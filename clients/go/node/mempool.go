package node

import (
	"bytes"
	"container/heap"
	"errors"
	"fmt"
	"math/bits"
	"sort"
	"sync"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

const maxMempoolTransactions = 300

type mempoolEntry struct {
	raw    []byte
	txid   [32]byte
	inputs []consensus.Outpoint
	fee    uint64
	weight uint64
	size   int
}

type Mempool struct {
	mu         sync.RWMutex
	chainState *ChainState
	blockStore *BlockStore
	chainID    [32]byte
	policy     MempoolConfig
	maxTxs     int
	txs        map[[32]byte]*mempoolEntry
	spenders   map[consensus.Outpoint][32]byte
	worstHeap  mempoolWorstHeap
	heapItems  map[[32]byte]*mempoolHeapItem
	heapSeqs   map[[32]byte]uint64
	nextHeapID uint64
}

type mempoolHeapItem struct {
	txid   [32]byte
	fee    uint64
	weight uint64
	size   int
	heapID uint64
	index  int
}

type mempoolPriority struct {
	fee    uint64
	size   int
	weight uint64
	txid   [32]byte
}

type mempoolWorstHeap []*mempoolHeapItem

func (h mempoolWorstHeap) Len() int { return len(h) }

func (h mempoolWorstHeap) Less(i, j int) bool {
	return compareHeapItemPriority(h[i], h[j]) < 0
}

func (h mempoolWorstHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].index = i
	h[j].index = j
}

func (h *mempoolWorstHeap) Push(x any) {
	item := x.(*mempoolHeapItem)
	item.index = len(*h)
	*h = append(*h, item)
}

func (h *mempoolWorstHeap) Pop() any {
	old := *h
	n := len(old)
	item := old[n-1]
	item.index = -1
	*h = old[:n-1]
	return item
}

type MempoolConfig struct {
	PolicyDaSurchargePerByte             uint64
	PolicyRejectNonCoinbaseAnchorOutputs bool
	PolicyRejectCoreExtPreActivation     bool
	PolicyMaxExtPayloadBytes             int
	CoreExtProfiles                      consensus.CoreExtProfileProvider
}

type RelayTxMetadata struct {
	Fee  uint64
	Size int
}

func NewMempool(chainState *ChainState, blockStore *BlockStore, chainID [32]byte) (*Mempool, error) {
	return NewMempoolWithConfig(chainState, blockStore, chainID, DefaultMempoolConfig())
}

func DefaultMempoolConfig() MempoolConfig {
	minerDefaults := DefaultMinerConfig()
	return MempoolConfig{
		PolicyDaSurchargePerByte:             minerDefaults.PolicyDaSurchargePerByte,
		PolicyRejectNonCoinbaseAnchorOutputs: minerDefaults.PolicyRejectNonCoinbaseAnchorOutputs,
		PolicyRejectCoreExtPreActivation:     minerDefaults.PolicyRejectCoreExtPreActivation,
	}
}

func NewMempoolWithConfig(chainState *ChainState, blockStore *BlockStore, chainID [32]byte, cfg MempoolConfig) (*Mempool, error) {
	if chainState == nil {
		return nil, errors.New("nil chainstate")
	}
	return &Mempool{
		chainState: chainState,
		blockStore: blockStore,
		chainID:    chainID,
		policy:     cfg,
		maxTxs:     maxMempoolTransactions,
		txs:        make(map[[32]byte]*mempoolEntry),
		spenders:   make(map[consensus.Outpoint][32]byte),
		worstHeap:  make(mempoolWorstHeap, 0, maxMempoolTransactions),
		heapItems:  make(map[[32]byte]*mempoolHeapItem),
		heapSeqs:   make(map[[32]byte]uint64),
	}, nil
}

func (m *Mempool) Len() int {
	if m == nil {
		return 0
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.txs)
}

func (m *Mempool) AddTx(txBytes []byte) error {
	if m == nil {
		return errors.New("nil mempool")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	checked, inputs, err := m.checkTransactionLocked(txBytes)
	if err != nil {
		return err
	}

	entry := newMempoolEntry(checked, inputs)
	if err := m.validateAdmissionLocked(entry); err != nil {
		return err
	}

	m.addEntryLocked(entry)
	return nil
}

func (m *Mempool) RelayMetadata(txBytes []byte) (RelayTxMetadata, error) {
	if m == nil {
		return RelayTxMetadata{}, errors.New("nil mempool")
	}
	m.mu.RLock()
	defer m.mu.RUnlock()

	checked, _, err := m.checkTransactionLocked(txBytes)
	if err != nil {
		return RelayTxMetadata{}, err
	}
	return RelayTxMetadata{
		Fee:  checked.Fee,
		Size: checked.SerializedSize,
	}, nil
}

func (m *Mempool) SelectTransactions(maxCount int, maxBytes int) [][]byte {
	if m == nil || maxCount <= 0 || maxBytes <= 0 {
		return nil
	}

	entries := m.snapshotEntries()
	sortMempoolEntries(entries)
	return pickEntries(entries, maxCount, maxBytes)
}

func (m *Mempool) EvictConfirmed(blockBytes []byte) error {
	return m.withParsedBlock(blockBytes, m.EvictConfirmedParsed)
}

func (m *Mempool) EvictConfirmedParsed(block *consensus.ParsedBlock) error {
	return m.withLockedParsedBlock(block, func(block *consensus.ParsedBlock) {
		for _, txid := range block.Txids {
			m.removeTxLocked(txid)
		}
	})
}

func (m *Mempool) RemoveConflicting(blockBytes []byte) error {
	return m.withParsedBlock(blockBytes, m.RemoveConflictingParsed)
}

func (m *Mempool) withParsedBlock(blockBytes []byte, fn func(*consensus.ParsedBlock) error) error {
	if m == nil {
		return errors.New("nil mempool")
	}
	block, err := consensus.ParseBlockBytes(blockBytes)
	if err != nil {
		return err
	}
	return fn(block)
}

func (m *Mempool) RemoveConflictingParsed(block *consensus.ParsedBlock) error {
	return m.withLockedParsedBlock(block, func(block *consensus.ParsedBlock) {
		for txid := range m.collectConflictsLocked(block) {
			m.removeTxLocked(txid)
		}
	})
}

func (m *Mempool) withLockedParsedBlock(block *consensus.ParsedBlock, fn func(*consensus.ParsedBlock)) error {
	if m == nil {
		return errors.New("nil mempool")
	}
	if block == nil {
		return errors.New("nil parsed block")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	fn(block)
	return nil
}

// checkTransactionLocked validates a transaction against the current chainstate.
// Caller MUST hold m.mu (read or write) to prevent TOCTOU races on m.chainState.
func (m *Mempool) checkTransactionLocked(txBytes []byte) (*consensus.CheckedTransaction, []consensus.Outpoint, error) {
	nextHeight, _, err := nextBlockContext(m.chainState)
	if err != nil {
		return nil, nil, err
	}

	blockMTP, err := m.nextBlockMTP(nextHeight)
	if err != nil {
		return nil, nil, err
	}
	checked, err := consensus.CheckTransaction(txBytes, m.chainState.Utxos, nextHeight, blockMTP, m.chainID)
	if err != nil {
		return nil, nil, err
	}
	if err := m.applyPolicyLocked(checked, nextHeight); err != nil {
		return nil, nil, err
	}
	inputs := make([]consensus.Outpoint, 0, len(checked.Tx.Inputs))
	for _, in := range checked.Tx.Inputs {
		inputs = append(inputs, consensus.Outpoint{Txid: in.PrevTxid, Vout: in.PrevVout})
	}
	return checked, inputs, nil
}

func (m *Mempool) applyPolicyLocked(checked *consensus.CheckedTransaction, nextHeight uint64) error {
	if checked == nil || checked.Tx == nil {
		return errors.New("nil checked transaction")
	}
	if m.policy.PolicyRejectNonCoinbaseAnchorOutputs {
		reject, reason, err := RejectNonCoinbaseAnchorOutputs(checked.Tx)
		if err != nil {
			return err
		}
		if reject {
			return errors.New(reason)
		}
	}
	reject, _, reason, err := RejectDaAnchorTxPolicy(checked.Tx, m.chainState.Utxos, m.policy.PolicyDaSurchargePerByte)
	if err != nil {
		return err
	}
	if reject {
		return errors.New(reason)
	}
	if m.policy.PolicyRejectCoreExtPreActivation {
		reject, reason, err := RejectCoreExtTxPreActivation(checked.Tx, m.chainState.Utxos, nextHeight, m.policy.CoreExtProfiles)
		if err != nil {
			return err
		}
		if reject {
			return errors.New(reason)
		}
	}
	if m.policy.PolicyMaxExtPayloadBytes > 0 {
		reject, reason, err := RejectCoreExtTxOversizedPayload(checked.Tx, m.policy.PolicyMaxExtPayloadBytes)
		if err != nil {
			return err
		}
		if reject {
			return errors.New(reason)
		}
	}
	return nil
}

func (m *Mempool) nextBlockMTP(nextHeight uint64) (uint64, error) {
	if m == nil || m.blockStore == nil || nextHeight == 0 {
		return 0, nil
	}
	prevTimestamps, err := prevTimestampsFromStore(m.blockStore, nextHeight)
	if err != nil {
		return 0, err
	}
	if len(prevTimestamps) == 0 {
		return 0, nil
	}
	return mtpMedian(nextHeight, prevTimestamps), nil
}

func (m *Mempool) removeTxLocked(txid [32]byte) {
	entry, ok := m.txs[txid]
	if !ok {
		return
	}
	if item, ok := m.heapItems[txid]; ok && item != nil && item.index >= 0 && item.index < len(m.worstHeap) && m.worstHeap[item.index] == item {
		heap.Remove(&m.worstHeap, item.index)
	}
	m.deleteEntryLocked(txid, entry)
}

func (m *Mempool) validateAdmissionLocked(entry *mempoolEntry) error {
	if entry == nil {
		return errors.New("nil mempool entry")
	}
	txid := entry.txid
	if _, exists := m.txs[txid]; exists {
		return fmt.Errorf("tx already in mempool")
	}
	for _, op := range entry.inputs {
		if existing, ok := m.spenders[op]; ok {
			return fmt.Errorf("mempool double-spend conflict with %x", existing)
		}
	}
	if len(m.txs) >= m.maxTxs {
		worstTxid, worstEntry, ok := m.peekWorstLocked()
		if !ok || compareEntryPriority(entry, worstEntry) <= 0 {
			return fmt.Errorf("mempool full")
		}
		m.popWorstLocked()
		m.removePoppedWorstLocked(worstTxid, worstEntry)
	}
	return nil
}

func newMempoolEntry(checked *consensus.CheckedTransaction, inputs []consensus.Outpoint) *mempoolEntry {
	return &mempoolEntry{
		raw:    append([]byte(nil), checked.Bytes...),
		txid:   checked.TxID,
		inputs: append([]consensus.Outpoint(nil), inputs...),
		fee:    checked.Fee,
		weight: checked.Weight,
		size:   checked.SerializedSize,
	}
}

func (m *Mempool) addEntryLocked(entry *mempoolEntry) {
	m.nextHeapID++
	heapID := m.nextHeapID
	m.txs[entry.txid] = entry
	m.heapSeqs[entry.txid] = heapID
	for _, op := range entry.inputs {
		m.spenders[op] = entry.txid
	}
	item := newHeapItem(entry.txid, entry, heapID)
	heap.Push(&m.worstHeap, item)
	m.heapItems[entry.txid] = item
}

func (m *Mempool) snapshotEntries() []*mempoolEntry {
	m.mu.RLock()
	defer m.mu.RUnlock()
	entries := make([]*mempoolEntry, 0, len(m.txs))
	for _, entry := range m.txs {
		entries = append(entries, entry)
	}
	return entries
}

func sortMempoolEntries(entries []*mempoolEntry) {
	sort.Slice(entries, func(i, j int) bool {
		if cmp := compareFeeRate(entries[i], entries[j]); cmp != 0 {
			return cmp > 0
		}
		if entries[i].fee != entries[j].fee {
			return entries[i].fee > entries[j].fee
		}
		if entries[i].weight != entries[j].weight {
			return entries[i].weight < entries[j].weight
		}
		return bytes.Compare(entries[i].txid[:], entries[j].txid[:]) < 0
	})
}

func pickEntries(entries []*mempoolEntry, maxCount int, maxBytes int) [][]byte {
	selected := make([][]byte, 0, len(entries))
	usedBytes := 0
	for _, entry := range entries {
		if len(selected) >= maxCount {
			break
		}
		if entry.size > maxBytes-usedBytes {
			continue
		}
		selected = append(selected, append([]byte(nil), entry.raw...))
		usedBytes += entry.size
	}
	return selected
}

func (m *Mempool) collectConflictsLocked(block *consensus.ParsedBlock) map[[32]byte]struct{} {
	conflicts := make(map[[32]byte]struct{})
	for i, tx := range block.Txs {
		if i == 0 || tx == nil {
			continue
		}
		for _, in := range tx.Inputs {
			if txid, ok := m.spenders[outpointFromInput(in)]; ok {
				conflicts[txid] = struct{}{}
			}
		}
	}
	return conflicts
}

func outpointFromInput(in consensus.TxInput) consensus.Outpoint {
	return consensus.Outpoint{Txid: in.PrevTxid, Vout: in.PrevVout}
}

func newHeapItem(txid [32]byte, entry *mempoolEntry, heapID uint64) *mempoolHeapItem {
	return &mempoolHeapItem{
		txid:   txid,
		fee:    entry.fee,
		weight: entry.weight,
		size:   entry.size,
		heapID: heapID,
	}
}

func (m *Mempool) seedWorstHeapLocked() {
	if len(m.heapItems) >= len(m.txs) {
		return
	}
	for txid, entry := range m.txs {
		if _, ok := m.heapItems[txid]; ok {
			continue
		}
		m.nextHeapID++
		heapID := m.nextHeapID
		m.heapSeqs[txid] = heapID
		item := newHeapItem(txid, entry, heapID)
		heap.Push(&m.worstHeap, item)
		m.heapItems[txid] = item
	}
}

func (m *Mempool) peekWorstLocked() ([32]byte, *mempoolEntry, bool) {
	m.seedWorstHeapLocked()
	for len(m.worstHeap) > 0 {
		item := m.worstHeap[0]
		entry := m.txs[item.txid]
		if entry == nil {
			heap.Pop(&m.worstHeap)
			delete(m.heapItems, item.txid)
			delete(m.heapSeqs, item.txid)
			continue
		}
		return item.txid, entry, true
	}
	return [32]byte{}, nil, false
}

func (m *Mempool) popWorstLocked() ([32]byte, *mempoolEntry, bool) {
	txid, entry, ok := m.peekWorstLocked()
	if !ok {
		return [32]byte{}, nil, false
	}
	heap.Pop(&m.worstHeap)
	delete(m.heapItems, txid)
	return txid, entry, true
}

func (m *Mempool) removePoppedWorstLocked(txid [32]byte, entry *mempoolEntry) {
	m.deleteEntryLocked(txid, entry)
}

func (m *Mempool) deleteEntryLocked(txid [32]byte, entry *mempoolEntry) {
	delete(m.txs, txid)
	delete(m.heapItems, txid)
	delete(m.heapSeqs, txid)
	if entry == nil {
		return
	}
	for _, op := range entry.inputs {
		delete(m.spenders, op)
	}
}

func compareEntryPriority(a *mempoolEntry, b *mempoolEntry) int {
	if a == nil || b == nil {
		return 0
	}
	return comparePriorityValues(priorityFromEntry(a), priorityFromEntry(b))
}

func compareHeapItemPriority(a *mempoolHeapItem, b *mempoolHeapItem) int {
	if a == nil || b == nil {
		return 0
	}
	return comparePriorityValues(priorityFromHeapItem(a), priorityFromHeapItem(b))
}

func priorityFromEntry(entry *mempoolEntry) mempoolPriority {
	return mempoolPriority{
		fee:    entry.fee,
		size:   entry.size,
		weight: entry.weight,
		txid:   entry.txid,
	}
}

func priorityFromHeapItem(item *mempoolHeapItem) mempoolPriority {
	return mempoolPriority{
		fee:    item.fee,
		size:   item.size,
		weight: item.weight,
		txid:   item.txid,
	}
}

func comparePriorityValues(a mempoolPriority, b mempoolPriority) int {
	cmp := compareFeeRateValues(a.fee, a.size, b.fee, b.size)
	if cmp != 0 {
		return cmp
	}
	if a.fee != b.fee {
		if a.fee > b.fee {
			return 1
		}
		return -1
	}
	if a.weight != b.weight {
		if a.weight < b.weight {
			return 1
		}
		return -1
	}
	switch cmp := bytes.Compare(a.txid[:], b.txid[:]); {
	case cmp < 0:
		return 1
	case cmp > 0:
		return -1
	default:
		return 0
	}
}

func compareFeeRate(a *mempoolEntry, b *mempoolEntry) int {
	if a == nil || b == nil {
		return 0
	}
	return compareFeeRateValues(a.fee, a.size, b.fee, b.size)
}

func compareFeeRateValues(feeA uint64, sizeA int, feeB uint64, sizeB int) int {
	if sizeA <= 0 || sizeB <= 0 {
		return 0
	}
	ahi, alo := bits.Mul64(feeA, uint64(sizeB))
	bhi, blo := bits.Mul64(feeB, uint64(sizeA))
	if ahi != bhi {
		if ahi > bhi {
			return 1
		}
		return -1
	}
	if alo != blo {
		if alo > blo {
			return 1
		}
		return -1
	}
	return 0
}

func prevTimestampsFromStore(store *BlockStore, nextHeight uint64) ([]uint64, error) {
	if store == nil || nextHeight == 0 {
		return nil, nil
	}
	k := uint64(11)
	if nextHeight < k {
		k = nextHeight
	}
	out := make([]uint64, 0, k)
	for i := uint64(0); i < k; i++ {
		height := nextHeight - 1 - i
		hash, ok, err := store.CanonicalHash(height)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, errors.New("missing canonical header for timestamp context")
		}
		headerBytes, err := store.GetHeaderByHash(hash)
		if err != nil {
			return nil, err
		}
		header, err := consensus.ParseBlockHeaderBytes(headerBytes)
		if err != nil {
			return nil, err
		}
		out = append(out, header.Timestamp)
	}
	return out, nil
}
