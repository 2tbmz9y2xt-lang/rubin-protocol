package node

import (
	"bytes"
	"errors"
	"fmt"
	"math/bits"
	"sort"
	"sync"
	"sync/atomic"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

const (
	DefaultMempoolMaxTransactions = 300
	DefaultMempoolMaxBytes        = consensus.MAX_RELAY_MSG_BYTES
	// DefaultMinMempoolFeePerWeight is the default minimum fee-per-weight ratio
	// (in satoshis per weight unit) required for mempool admission.
	// Transactions below this floor are rejected early before expensive signature
	// verification. This is a DoS protection mechanism.
	// Value: 1 satoshi per weight unit (conservative floor for spam prevention).
	DefaultMinMempoolFeePerWeight = 1
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
	mu                 sync.RWMutex
	chainState         *ChainState
	blockStore         *BlockStore
	chainID            [32]byte
	policy             MempoolConfig
	maxTxs             int
	maxBytes           int
	usedBytes          int
	minFeePerWeight    uint64 // minimum fee-per-weight for admission (0 = disabled)
	txs                map[[32]byte]*mempoolEntry
	spenders           map[consensus.Outpoint][32]byte
	// Admission counters are bumped exactly once for each AddTx call on a
	// non-nil Mempool that reaches the final outcome accounting path.
	// Nil-receiver calls return before that defer is registered and are
	// therefore intentionally excluded from these counters. Lock-free via
	// atomic.Uint64 — no impact on the admissionMu / mu ordering. Buckets
	// are the closed enum {accepted, conflict, rejected, unavailable};
	// any non-TxAdmitError reachable from AddTx falls into the rejected
	// bucket so no unbounded label class can grow from this surface. P2P
	// disconnect metrics are intentionally not tracked here; they are
	// scoped to issue #1307 because the disconnect boundary needs a
	// separate semantic audit (no double-count, normal shutdown is not a
	// peer fault).
	admitAccepted    atomic.Uint64
	admitConflict    atomic.Uint64
	admitRejected    atomic.Uint64
	admitUnavailable atomic.Uint64
}

// MempoolAdmissionCounts is the snapshot view of admission outcomes.
// Field order matches the /metrics rendering order in
// renderPrometheusMetrics so the textual output is stable across
// readings. Values are monotonic counts since process start; readers
// MUST treat them as Prometheus counters.
type MempoolAdmissionCounts struct {
	Accepted    uint64
	Conflict    uint64
	Rejected    uint64
	Unavailable uint64
}

type MempoolConfig struct {
	MaxTransactions                      int
	MaxBytes                             int
	MinFeePerWeight                      uint64 // minimum fee-per-weight (0 = disabled, default = 1)
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
		MinFeePerWeight:                      DefaultMinMempoolFeePerWeight,
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
		chainState:      chainState,
		blockStore:      blockStore,
		chainID:         chainID,
		policy:          cfg,
		maxTxs:          cfg.MaxTransactions,
		maxBytes:        cfg.MaxBytes,
		minFeePerWeight: cfg.MinFeePerWeight,
		txs:             make(map[[32]byte]*mempoolEntry),
		spenders:        make(map[consensus.Outpoint][32]byte),
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

// BytesUsed returns the total raw byte size of transactions currently
// resident in the mempool. Mirrors the existing usedBytes accounting
// already maintained on every AddTx / RemoveTx path. Returns 0 on a
// nil receiver so callers (e.g. /metrics rendering) can scrape
// unconditionally.
func (m *Mempool) BytesUsed() int {
	if m == nil {
		return 0
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.usedBytes
}

// AdmissionCounts returns a snapshot of the per-outcome admission
// counters bumped at the final return path of AddTx. Values are
// monotonic counts since process start. Returns a zero-valued struct
// on a nil receiver so callers (e.g. /metrics rendering) can scrape
// unconditionally. Field order matches the fixed metric rendering
// order in renderPrometheusMetrics.
func (m *Mempool) AdmissionCounts() MempoolAdmissionCounts {
	if m == nil {
		return MempoolAdmissionCounts{}
	}
	return MempoolAdmissionCounts{
		Accepted:    m.admitAccepted.Load(),
		Conflict:    m.admitConflict.Load(),
		Rejected:    m.admitRejected.Load(),
		Unavailable: m.admitUnavailable.Load(),
	}
}

// noteAdmissionResult bumps exactly one outcome counter based on the
// final error returned by AddTx. nil error → accepted; *TxAdmitError →
// matching kind bucket; any other (currently unreachable) error
// falls into the rejected bucket as a fail-closed default so this
// helper never silently swallows a metric and never invents a new
// label. AddTx wires this via named return + defer so every return
// path increments exactly one counter.
func (m *Mempool) noteAdmissionResult(err error) {
	if m == nil {
		return
	}
	if err == nil {
		m.admitAccepted.Add(1)
		return
	}
	var admitErr *TxAdmitError
	if errors.As(err, &admitErr) {
		switch admitErr.Kind {
		case TxAdmitConflict:
			m.admitConflict.Add(1)
		case TxAdmitRejected:
			m.admitRejected.Add(1)
		case TxAdmitUnavailable:
			m.admitUnavailable.Add(1)
		default:
			// Unknown TxAdmitErrorKind — bucket as rejected so we never
			// grow a new label silently.
			m.admitRejected.Add(1)
		}
		return
	}
	// Non-TxAdmitError reaching AddTx is currently unreachable per
	// audit, but bucket as rejected to keep the outcome closed.
	m.admitRejected.Add(1)
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

func (m *Mempool) AddTx(txBytes []byte) (retErr error) {
	if m == nil {
		return txAdmitUnavailable("nil mempool")
	}
	// Exactly one admission counter increment per non-nil-receiver call,
	// based on the final return value. Registered AFTER the nil-receiver
	// guard above so a nil mempool returns the typed unavailable error
	// without recording a counter — there is no mempool instance to own
	// the metric state.
	defer func() { m.noteAdmissionResult(retErr) }()
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

// cheapFeeFloorPrecheck performs a fast fee-floor check before expensive validation.
// This is a DoS protection mechanism that rejects obviously below-floor spam without
// invoking ML-DSA signature verification or full state processing.
//
// Returns nil if the transaction passes the cheap precheck or if the precheck cannot
// be soundly performed (e.g., missing UTXOs). Returns a TxAdmitError if the transaction
// is provably below the fee floor.
//
// This function MUST NOT mask earlier errors (malformed tx, missing inputs) that would
// be caught by full validation. It only rejects when fee/weight can be soundly computed
// and the ratio is below the configured minimum fee-per-weight.
func (m *Mempool) cheapFeeFloorPrecheck(tx *consensus.Tx, snapshot *chainStateAdmissionSnapshot) error {
	if tx == nil || snapshot == nil || m.minFeePerWeight == 0 {
		// Cannot perform precheck or fee floor disabled; let full validation handle it
		return nil
	}

	// Compute sum of input values. If any input is missing from UTXO set,
	// we cannot soundly compute fee, so skip precheck and let full validation
	// report TX_ERR_MISSING_UTXO.
	var sumInputs uint64
	for _, in := range tx.Inputs {
		op := consensus.Outpoint{Txid: in.PrevTxid, Vout: in.PrevVout}
		entry, ok := snapshot.utxos[op]
		if !ok {
			// Missing UTXO: cannot compute fee soundly. Skip precheck.
			// Full validation will report the proper error.
			return nil
		}
		// Check for overflow in sumInputs
		if sumInputs > ^uint64(0)-entry.Value {
			// Overflow in input sum: this is malformed and will be caught
			// by full validation. Skip precheck.
			return nil
		}
		sumInputs += entry.Value
	}

	// Compute sum of output values
	var sumOutputs uint64
	for _, out := range tx.Outputs {
		// Check for overflow in sumOutputs
		if sumOutputs > ^uint64(0)-out.Value {
			// Overflow in output sum: malformed, let full validation handle it
			return nil
		}
		sumOutputs += out.Value
	}

	// Check if sumInputs < sumOutputs (invalid transaction)
	if sumInputs < sumOutputs {
		// Invalid: outputs exceed inputs. This is a consensus error that
		// full validation will catch. Skip precheck.
		return nil
	}

	// Compute fee (safe because sumInputs >= sumOutputs)
	fee := sumInputs - sumOutputs

	// Compute weight cheaply using the public weight function.
	// This does NOT perform signature verification, just structural weight calculation.
	weight, _, _, err := consensus.TxWeightAndStats(tx)
	if err != nil {
		// Weight computation failed (malformed tx). Let full validation handle it.
		return nil
	}

	// Check fee-per-weight ratio against floor.
	// To avoid floating point: fee / weight >= minFeePerWeight
	// is equivalent to: fee >= minFeePerWeight * weight
	//
	// Check for overflow in multiplication
	if weight > 0 && m.minFeePerWeight > ^uint64(0)/weight {
		// Overflow in floor calculation: weight is extremely large.
		// This is likely malformed. Skip precheck.
		return nil
	}

	minFee := m.minFeePerWeight * weight

	if fee < minFee {
		// Transaction is provably below fee floor. Reject early.
		return txAdmitRejected(fmt.Sprintf(
			"transaction fee %d below minimum floor %d (fee-per-weight %d < %d)",
			fee, minFee, fee/max(weight, 1), MinMempoolFeePerWeight,
		))
	}

	// Passed cheap precheck
	return nil
}

// max returns the maximum of two uint64 values
func max(a, b uint64) uint64 {
	if a > b {
		return a
	}
	return b
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

	// RUB-165: Fast-reject spam with fee below floor BEFORE expensive signature verification.
	// This cheap precheck only rejects when fee/weight can be soundly computed from available
	// UTXO context. If inputs are missing or malformed, it returns nil and lets full validation
	// report the proper error.
	if err := m.cheapFeeFloorPrecheck(parsedTx, snapshot); err != nil {
		return nil, nil, err
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
