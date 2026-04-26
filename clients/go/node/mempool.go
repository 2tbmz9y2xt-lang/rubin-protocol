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

const (
	DefaultMempoolMaxTransactions = 300
	DefaultMempoolMaxBytes        = consensus.MAX_RELAY_MSG_BYTES
)

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
	maxBytes   int
	usedBytes  int
	txs        map[[32]byte]*mempoolEntry
	spenders   map[consensus.Outpoint][32]byte
}

type MempoolConfig struct {
	MaxTransactions                      int
	MaxBytes                             int
	PolicyDaSurchargePerByte             uint64
	PolicyRejectNonCoinbaseAnchorOutputs bool
	PolicyRejectCoreExtPreActivation     bool
	PolicyMaxExtPayloadBytes             int
	CoreExtProfiles                      consensus.CoreExtProfileProvider
	RotationProvider                     consensus.RotationProvider
	SuiteRegistry                        *consensus.SuiteRegistry
}

type RelayTxMetadata struct {
	Fee  uint64
	Size int
}

// TxAdmitErrorKind classifies mempool admission failures for deterministic
// HTTP status mapping. Mirrors Rust TxPoolAdmitErrorKind.
type TxAdmitErrorKind string

const (
	TxAdmitConflict    TxAdmitErrorKind = "conflict"
	TxAdmitRejected    TxAdmitErrorKind = "rejected"
	TxAdmitUnavailable TxAdmitErrorKind = "unavailable"
)

// TxAdmitError is a typed mempool admission error carrying a classification
// kind and a human-readable message.
type TxAdmitError struct {
	Kind    TxAdmitErrorKind
	Message string
}

func (e *TxAdmitError) Error() string { return e.Message }

func txAdmitConflict(msg string) *TxAdmitError {
	return &TxAdmitError{Kind: TxAdmitConflict, Message: msg}
}

func txAdmitRejected(msg string) *TxAdmitError {
	return &TxAdmitError{Kind: TxAdmitRejected, Message: msg}
}

func txAdmitUnavailable(msg string) *TxAdmitError {
	return &TxAdmitError{Kind: TxAdmitUnavailable, Message: msg}
}

func NewMempool(chainState *ChainState, blockStore *BlockStore, chainID [32]byte) (*Mempool, error) {
	return NewMempoolWithConfig(chainState, blockStore, chainID, DefaultMempoolConfig())
}

func DefaultMempoolConfig() MempoolConfig {
	minerDefaults := DefaultMinerConfig()
	return MempoolConfig{
		MaxTransactions:                      DefaultMempoolMaxTransactions,
		MaxBytes:                             DefaultMempoolMaxBytes,
		PolicyDaSurchargePerByte:             minerDefaults.PolicyDaSurchargePerByte,
		PolicyRejectNonCoinbaseAnchorOutputs: minerDefaults.PolicyRejectNonCoinbaseAnchorOutputs,
		PolicyRejectCoreExtPreActivation:     minerDefaults.PolicyRejectCoreExtPreActivation,
	}
}

func NewMempoolWithConfig(chainState *ChainState, blockStore *BlockStore, chainID [32]byte, cfg MempoolConfig) (*Mempool, error) {
	if chainState == nil {
		return nil, errors.New("nil chainstate")
	}
	cfg = normalizeMempoolConfig(cfg)
	return &Mempool{
		chainState: chainState,
		blockStore: blockStore,
		chainID:    chainID,
		policy:     cfg,
		maxTxs:     cfg.MaxTransactions,
		maxBytes:   cfg.MaxBytes,
		txs:        make(map[[32]byte]*mempoolEntry),
		spenders:   make(map[consensus.Outpoint][32]byte),
	}, nil
}

func normalizeMempoolConfig(cfg MempoolConfig) MempoolConfig {
	if cfg.MaxTransactions <= 0 {
		cfg.MaxTransactions = DefaultMempoolMaxTransactions
	}
	if cfg.MaxBytes <= 0 {
		cfg.MaxBytes = DefaultMempoolMaxBytes
	}
	return cfg
}

func (m *Mempool) Len() int {
	if m == nil {
		return 0
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.txs)
}

// AllTxIDs returns the txids of every transaction currently in the mempool.
// The slice ordering is not guaranteed to be stable between calls.
func (m *Mempool) AllTxIDs() [][32]byte {
	if m == nil {
		return nil
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	ids := make([][32]byte, 0, len(m.txs))
	for txid := range m.txs {
		ids = append(ids, txid)
	}
	return ids
}

// TxByID returns the raw transaction bytes of a mempool entry with the given
// txid. The returned slice is a defensive copy and safe for the caller to
// retain or mutate. Returns (nil, false) if no matching entry is present.
func (m *Mempool) TxByID(txid [32]byte) ([]byte, bool) {
	if m == nil {
		return nil, false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	entry, ok := m.txs[txid]
	if !ok {
		return nil, false
	}
	raw := make([]byte, len(entry.raw))
	copy(raw, entry.raw)
	return raw, true
}

// Contains reports whether a transaction with the given txid is currently
// present in the mempool.
func (m *Mempool) Contains(txid [32]byte) bool {
	if m == nil {
		return false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := m.txs[txid]
	return ok
}

func (m *Mempool) AddTx(txBytes []byte) error {
	if m == nil {
		return txAdmitUnavailable("nil mempool")
	}
	if m.chainState == nil {
		return txAdmitUnavailable("nil chainstate")
	}

	m.chainState.admissionMu.RLock()
	defer m.chainState.admissionMu.RUnlock()

	snapshot := m.chainState.admissionSnapshot()
	policy := m.policySnapshot()
	checked, inputs, err := m.checkTransactionWithSnapshot(txBytes, snapshot, policy)
	if err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	entry := newMempoolEntry(checked, inputs)
	if err := m.validateAdmissionLocked(entry); err != nil {
		return err
	}

	m.addEntryLocked(entry)
	return nil
}

func (m *Mempool) RelayMetadata(txBytes []byte) (RelayTxMetadata, error) {
	if m == nil {
		return RelayTxMetadata{}, txAdmitUnavailable("nil mempool")
	}
	if m.chainState == nil {
		return RelayTxMetadata{}, txAdmitUnavailable("nil chainstate")
	}
	tx, txid, wtxid, err := parseRelayMetadataTx(txBytes)
	if err != nil {
		return RelayTxMetadata{}, err
	}
	m.chainState.admissionMu.RLock()
	defer m.chainState.admissionMu.RUnlock()
	snapshot := m.chainState.admissionSnapshotForInputs(relayMetadataInputs(tx))
	policy := m.policySnapshot()
	checked, _, err := m.checkParsedTransactionWithSnapshot(txBytes, tx, txid, wtxid, snapshot, policy)
	if err != nil {
		return RelayTxMetadata{}, err
	}
	return RelayTxMetadata{
		Fee:  checked.Fee,
		Size: checked.SerializedSize,
	}, nil
}

func parseRelayMetadataTx(txBytes []byte) (*consensus.Tx, [32]byte, [32]byte, error) {
	tx, txid, wtxid, consumed, err := consensus.ParseTx(txBytes)
	if err != nil {
		return nil, [32]byte{}, [32]byte{}, txAdmitRejected(err.Error())
	}
	if consumed != len(txBytes) {
		return nil, [32]byte{}, [32]byte{}, txAdmitRejected("trailing bytes after canonical tx")
	}
	return tx, txid, wtxid, nil
}

func relayMetadataInputs(tx *consensus.Tx) []consensus.Outpoint {
	inputs := make([]consensus.Outpoint, 0, len(tx.Inputs))
	for _, in := range tx.Inputs {
		inputs = append(inputs, consensus.Outpoint{Txid: in.PrevTxid, Vout: in.PrevVout})
	}
	return inputs
}

func (m *Mempool) checkParsedTransactionWithSnapshot(
	txBytes []byte,
	tx *consensus.Tx,
	txid [32]byte,
	wtxid [32]byte,
	snapshot *chainStateAdmissionSnapshot,
	policy MempoolConfig,
) (*consensus.CheckedTransaction, []consensus.Outpoint, error) {
	if snapshot == nil {
		return nil, nil, txAdmitUnavailable("nil chainstate")
	}
	nextHeight, _, err := nextBlockContextFromFields(snapshot.hasTip, snapshot.height, snapshot.tipHash)
	if err != nil {
		return nil, nil, txAdmitUnavailable(err.Error())
	}

	blockMTP, err := m.nextBlockMTP(nextHeight)
	if err != nil {
		return nil, nil, txAdmitUnavailable(err.Error())
	}

	var policyUtxos map[consensus.Outpoint]consensus.UtxoEntry
	if policyNeedsInputSnapshot(policy) {
		policyUtxos, err = policyInputSnapshot(tx, snapshot.utxos)
		if err != nil {
			return nil, nil, txAdmitRejected(err.Error())
		}
	}

	checked, err := consensus.CheckParsedTransactionWithOwnedUtxoSetAndCoreExtProfilesAndSuiteContext(
		txBytes,
		tx,
		txid,
		wtxid,
		snapshot.utxos,
		nextHeight,
		blockMTP,
		m.chainID,
		policy.CoreExtProfiles,
		policy.RotationProvider,
		policy.SuiteRegistry,
	)
	if err != nil {
		return nil, nil, txAdmitRejected(err.Error())
	}
	if err := m.applyPolicyAgainstState(checked, nextHeight, policyUtxos, policy); err != nil {
		return nil, nil, txAdmitRejected(err.Error())
	}
	inputs := make([]consensus.Outpoint, 0, len(checked.Tx.Inputs))
	for _, in := range checked.Tx.Inputs {
		inputs = append(inputs, consensus.Outpoint{Txid: in.PrevTxid, Vout: in.PrevVout})
	}
	return checked, inputs, nil
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

// checkTransactionWithState validates a transaction against a consistent
// chainstate snapshot. Mempool bookkeeping lock ordering stays acyclic:
// chainstate snapshot first, then mempool mutex for admit/conflict checks.
func (m *Mempool) policySnapshot() MempoolConfig {
	if m == nil {
		return MempoolConfig{}
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.policy
}

// checkTransactionWithSnapshot validates a transaction against a consistent
// owned admission snapshot plus an immutable mempool policy snapshot.
func (m *Mempool) checkTransactionWithSnapshot(txBytes []byte, snapshot *chainStateAdmissionSnapshot, policy MempoolConfig) (*consensus.CheckedTransaction, []consensus.Outpoint, error) {
	if snapshot == nil {
		return nil, nil, txAdmitUnavailable("nil chainstate")
	}
	nextHeight, _, err := nextBlockContextFromFields(snapshot.hasTip, snapshot.height, snapshot.tipHash)
	if err != nil {
		return nil, nil, txAdmitUnavailable(err.Error())
	}

	blockMTP, err := m.nextBlockMTP(nextHeight)
	if err != nil {
		return nil, nil, txAdmitUnavailable(err.Error())
	}
	parsedTx, _, _, consumed, err := consensus.ParseTx(txBytes)
	if err != nil {
		return nil, nil, txAdmitRejected(err.Error())
	}
	if consumed != len(txBytes) {
		return nil, nil, txAdmitRejected("trailing bytes after canonical tx")
	}
	var policyUtxos map[consensus.Outpoint]consensus.UtxoEntry
	if policyNeedsInputSnapshot(policy) {
		policyUtxos, err = policyInputSnapshot(parsedTx, snapshot.utxos)
		if err != nil {
			return nil, nil, txAdmitRejected(err.Error())
		}
	}
	checked, err := consensus.CheckTransactionWithOwnedUtxoSetAndCoreExtProfilesAndSuiteContext(
		txBytes,
		snapshot.utxos,
		nextHeight,
		blockMTP,
		m.chainID,
		policy.CoreExtProfiles,
		policy.RotationProvider,
		policy.SuiteRegistry,
	)
	if err != nil {
		return nil, nil, txAdmitRejected(err.Error())
	}
	// Policy checks consume an immutable pre-validation snapshot of only the
	// transaction inputs they inspect, avoiding both live-state mutation and
	// whole-chainstate copying on mempool admission.
	if err := m.applyPolicyAgainstState(checked, nextHeight, policyUtxos, policy); err != nil {
		return nil, nil, txAdmitRejected(err.Error())
	}
	inputs := make([]consensus.Outpoint, 0, len(checked.Tx.Inputs))
	for _, in := range checked.Tx.Inputs {
		inputs = append(inputs, consensus.Outpoint{Txid: in.PrevTxid, Vout: in.PrevVout})
	}
	return checked, inputs, nil
}

func policyNeedsInputSnapshot(policy MempoolConfig) bool {
	return policy.PolicyDaSurchargePerByte > 0 || policy.PolicyRejectCoreExtPreActivation
}

func policyInputSnapshot(tx *consensus.Tx, utxos map[consensus.Outpoint]consensus.UtxoEntry) (map[consensus.Outpoint]consensus.UtxoEntry, error) {
	if tx == nil {
		return nil, errors.New("nil tx")
	}
	if utxos == nil {
		return nil, errors.New("nil utxo set")
	}
	inputs := make([]consensus.Outpoint, 0, len(tx.Inputs))
	for _, in := range tx.Inputs {
		inputs = append(inputs, consensus.Outpoint{Txid: in.PrevTxid, Vout: in.PrevVout})
	}
	out := copySelectedUtxoSet(utxos, inputs)
	for _, op := range inputs {
		if _, ok := out[op]; !ok {
			return nil, &consensus.TxError{Code: consensus.TX_ERR_MISSING_UTXO, Msg: "utxo not found"}
		}
	}
	return out, nil
}

func (m *Mempool) applyPolicyAgainstState(checked *consensus.CheckedTransaction, nextHeight uint64, utxos map[consensus.Outpoint]consensus.UtxoEntry, policy MempoolConfig) error {
	if checked == nil || checked.Tx == nil {
		return errors.New("nil checked transaction")
	}
	if policy.PolicyRejectNonCoinbaseAnchorOutputs {
		reject, reason, err := RejectNonCoinbaseAnchorOutputs(checked.Tx)
		if err != nil {
			return err
		}
		if reject {
			return errors.New(reason)
		}
	}
	reject, _, reason, err := RejectDaAnchorTxPolicy(checked.Tx, utxos, policy.PolicyDaSurchargePerByte)
	if err != nil {
		return err
	}
	if reject {
		return errors.New(reason)
	}
	if policy.PolicyRejectCoreExtPreActivation {
		reject, reason, err := RejectCoreExtTxPreActivation(checked.Tx, utxos, nextHeight, policy.CoreExtProfiles)
		if err != nil {
			return err
		}
		if reject {
			return errors.New(reason)
		}
	}
	if policy.PolicyMaxExtPayloadBytes > 0 {
		reject, reason, err := RejectCoreExtTxOversizedPayload(checked.Tx, policy.PolicyMaxExtPayloadBytes)
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
	m.deleteEntryLocked(txid, entry)
}

func (m *Mempool) validateAdmissionLocked(entry *mempoolEntry) error {
	if entry == nil {
		return txAdmitRejected("nil mempool entry")
	}
	if entry.size <= 0 {
		return txAdmitRejected("invalid mempool entry size")
	}
	txid := entry.txid
	if _, exists := m.txs[txid]; exists {
		return txAdmitConflict("tx already in mempool")
	}
	for _, op := range entry.inputs {
		if existing, ok := m.spenders[op]; ok {
			return txAdmitConflict(fmt.Sprintf("mempool double-spend conflict with %x", existing))
		}
	}
	if len(m.txs) >= m.maxTxs {
		return txAdmitUnavailable(fmt.Sprintf("mempool transaction count limit reached: current=%d max=%d", len(m.txs), m.maxTxs))
	}
	if entry.size > m.maxBytes || m.usedBytes > m.maxBytes-entry.size {
		return txAdmitUnavailable(fmt.Sprintf("mempool byte limit exceeded: current=%d tx=%d max=%d", m.usedBytes, entry.size, m.maxBytes))
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
	m.usedBytes += entry.size
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

func (m *Mempool) deleteEntryLocked(txid [32]byte, entry *mempoolEntry) {
	delete(m.txs, txid)
	if entry == nil {
		return
	}
	if entry.size > 0 {
		if m.usedBytes >= entry.size {
			m.usedBytes -= entry.size
		} else {
			m.usedBytes = 0
		}
	}
	for _, op := range entry.inputs {
		delete(m.spenders, op)
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
			return nil, fmt.Errorf("missing canonical hash at height %d for timestamp context (next_height=%d)", height, nextHeight)
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
