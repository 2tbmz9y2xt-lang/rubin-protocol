package node

import (
	"bytes"
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
	maxTxs     int
	txs        map[[32]byte]*mempoolEntry
	spenders   map[consensus.Outpoint][32]byte
}

func NewMempool(chainState *ChainState, blockStore *BlockStore, chainID [32]byte) (*Mempool, error) {
	if chainState == nil {
		return nil, errors.New("nil chainstate")
	}
	return &Mempool{
		chainState: chainState,
		blockStore: blockStore,
		chainID:    chainID,
		maxTxs:     maxMempoolTransactions,
		txs:        make(map[[32]byte]*mempoolEntry),
		spenders:   make(map[consensus.Outpoint][32]byte),
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
	checked, inputs, err := m.checkTransaction(txBytes)
	if err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if err := m.validateAdmissionLocked(checked.TxID, inputs); err != nil {
		return err
	}

	entry := newMempoolEntry(checked, inputs)
	m.addEntryLocked(entry)
	return nil
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
	if m == nil {
		return errors.New("nil mempool")
	}
	block, err := consensus.ParseBlockBytes(blockBytes)
	if err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	for _, txid := range block.Txids {
		m.removeTxLocked(txid)
	}
	return nil
}

func (m *Mempool) RemoveConflicting(blockBytes []byte) error {
	if m == nil {
		return errors.New("nil mempool")
	}
	block, err := consensus.ParseBlockBytes(blockBytes)
	if err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	for txid := range m.collectConflictsLocked(block) {
		m.removeTxLocked(txid)
	}
	return nil
}

func (m *Mempool) checkTransaction(txBytes []byte) (*consensus.CheckedTransaction, []consensus.Outpoint, error) {
	nextHeight, _, err := nextBlockContext(m.chainState)
	if err != nil {
		return nil, nil, err
	}

	blockMTP, err := m.nextBlockMTP(nextHeight)
	if err != nil {
		return nil, nil, err
	}
	checked, err := consensus.CheckTransaction(txBytes, copyUtxoSet(m.chainState.Utxos), nextHeight, blockMTP, m.chainID)
	if err != nil {
		return nil, nil, err
	}
	inputs := make([]consensus.Outpoint, 0, len(checked.Tx.Inputs))
	for _, in := range checked.Tx.Inputs {
		inputs = append(inputs, consensus.Outpoint{Txid: in.PrevTxid, Vout: in.PrevVout})
	}
	return checked, inputs, nil
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
	delete(m.txs, txid)
	for _, op := range entry.inputs {
		delete(m.spenders, op)
	}
}

func (m *Mempool) validateAdmissionLocked(txid [32]byte, inputs []consensus.Outpoint) error {
	if _, exists := m.txs[txid]; exists {
		return fmt.Errorf("tx already in mempool")
	}
	if len(m.txs) >= m.maxTxs {
		return fmt.Errorf("mempool full")
	}
	for _, op := range inputs {
		if existing, ok := m.spenders[op]; ok {
			return fmt.Errorf("mempool double-spend conflict with %x", existing)
		}
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
	m.txs[entry.txid] = entry
	for _, op := range entry.inputs {
		m.spenders[op] = entry.txid
	}
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

func compareFeeRate(a *mempoolEntry, b *mempoolEntry) int {
	if a == nil || b == nil || a.size <= 0 || b.size <= 0 {
		return 0
	}
	ahi, alo := bits.Mul64(a.fee, uint64(b.size))
	bhi, blo := bits.Mul64(b.fee, uint64(a.size))
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
