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
	DefaultMempoolMinFeeRate      = uint64(1)

	// DefaultMinDaFeeRate is the spec-side per-byte DA fee floor from
	// POLICY_MEMPOOL_ADMISSION_GENESIS.md Stage C (`min_da_fee_rate`).
	DefaultMinDaFeeRate = uint64(1)

	mempoolLowWaterNumerator   = 9
	mempoolLowWaterDenominator = 10
)

type mempoolTxSource string

const (
	mempoolTxSourceRemote mempoolTxSource = "remote"
	mempoolTxSourceLocal  mempoolTxSource = "local"
	mempoolTxSourceReorg  mempoolTxSource = "reorg"
)

type mempoolEntry struct {
	raw          []byte
	txid         [32]byte
	wtxid        [32]byte
	inputs       []consensus.Outpoint
	fee          uint64
	weight       uint64
	size         int
	admissionSeq uint64
	source       mempoolTxSource
}

type Mempool struct {
	mu                sync.RWMutex
	chainState        *ChainState
	blockStore        *BlockStore
	chainID           [32]byte
	policy            MempoolConfig
	maxTxs            int
	maxBytes          int
	lowWaterBytes     int
	usedBytes         int
	lastAdmissionSeq  uint64
	currentMinFeeRate uint64
	txs               map[[32]byte]*mempoolEntry
	wtxids            map[[32]byte][32]byte
	spenders          map[consensus.Outpoint][32]byte
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

	// evictedResidentTotal counts cumulative resident-entry capacity
	// evictions since process start. It is bumped exactly once per
	// already-admitted entry that is removed by capacity pressure
	// (the deleteEntryLocked loop in addEntryLocked after
	// validateCapacityAdmissionLocked classifies the candidate as
	// admitted-and-evicting). Candidate-worst rejection — where the
	// incoming candidate is rejected at capacity and no resident is
	// evicted — does not increment this counter; that path returns
	// txAdmitUnavailable before the deleteEntryLocked loop. Fee-floor
	// rejection of an incoming transaction never reaches this counter
	// either, because the fee-floor check happens before
	// validateCapacityAdmissionLocked. Confirmed-block removals via
	// EvictConfirmed/applyConnectedBlock are conflict resolution, not
	// policy capacity eviction, and also do not increment this counter.
	evictedResidentTotal atomic.Uint64
}

// MempoolStats is the snapshot view of standard mempool telemetry
// state. Field order matches the /metrics rendering order in
// renderPrometheusMetrics so the textual output is stable across
// readings. Reading a snapshot does not mutate any mempool state.
//
// Nil-receiver contract (matches CurrentMinFeeRateSnapshot
// convention): a nil *Mempool returns counters and sizes set to
// zero (TxCount, BytesUsed, MaxBytes, LowWaterBytes,
// EvictedResidentTotal) but MinFeeRate set to
// DefaultMempoolMinFeeRate. Callers do not need to special-case
// uninitialized mempool wiring; /metrics on an un-wired state
// renders the documented baseline floor instead of 0.
type MempoolStats struct {
	TxCount              int
	BytesUsed            int
	MaxBytes             int
	LowWaterBytes        int
	MinFeeRate           uint64
	EvictedResidentTotal uint64
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
	MaxTransactions          int
	MaxBytes                 int
	PolicyDaSurchargePerByte uint64
	// MinDaFeeRate is the spec-side per-byte DA fee floor
	// (POLICY_MEMPOOL_ADMISSION_GENESIS.md Stage C `min_da_fee_rate`,
	// default 1). NewMempoolWithConfig treats 0 as omitted and normalizes
	// it to DefaultMinDaFeeRate; callers cannot disable the spec floor
	// through the public mempool config. Direct policy-helper tests may
	// still pass 0 to isolate surcharge-only helper semantics.
	MinDaFeeRate                         uint64
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
		MinDaFeeRate:                         DefaultMinDaFeeRate,
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
		chainState:        chainState,
		blockStore:        blockStore,
		chainID:           chainID,
		policy:            cfg,
		maxTxs:            cfg.MaxTransactions,
		maxBytes:          cfg.MaxBytes,
		lowWaterBytes:     defaultMempoolLowWaterBytes(cfg.MaxBytes),
		currentMinFeeRate: DefaultMempoolMinFeeRate,
		txs:               make(map[[32]byte]*mempoolEntry),
		wtxids:            make(map[[32]byte][32]byte),
		spenders:          make(map[consensus.Outpoint][32]byte),
	}, nil
}

func normalizeMempoolConfig(cfg MempoolConfig) MempoolConfig {
	if cfg.MaxTransactions <= 0 {
		cfg.MaxTransactions = DefaultMempoolMaxTransactions
	}
	if cfg.MaxBytes <= 0 {
		cfg.MaxBytes = DefaultMempoolMaxBytes
	}
	if cfg.MinDaFeeRate == 0 {
		cfg.MinDaFeeRate = DefaultMinDaFeeRate
	}
	return cfg
}

func defaultMempoolLowWaterBytes(maxBytes int) int {
	if maxBytes <= 0 {
		return 0
	}
	lowWater := (maxBytes/mempoolLowWaterDenominator)*mempoolLowWaterNumerator +
		((maxBytes % mempoolLowWaterDenominator) * mempoolLowWaterNumerator / mempoolLowWaterDenominator)
	if lowWater == 0 {
		return 1
	}
	return lowWater
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

// Stats returns a current snapshot of standard mempool telemetry
// state for the /metrics renderer. The snapshot reads live struct
// fields under the read lock — values are NOT cached duplicates of
// MempoolConfig defaults — so max_bytes, low_water_bytes, and
// min_fee_rate reflect the rolling state including the post-eviction
// adjustments performed by raiseMinFeeRateAfterEvictionLocked and
// decayMinFeeRateAfterConnectedBlockLocked. EvictedResidentTotal is
// loaded INSIDE the read-lock window. Writers bump that counter
// under m.mu.Lock inside addEntryLocked's deleteEntryLocked loop,
// so the reader's m.mu.RLock pairs with the writer's m.mu.Lock and
// the atomic.Load observes the same critical section as the gauge
// fields read on the surrounding lines. Covered by
// TestMempoolStatsScrapePurity and the
// TestMempoolStatsResidentEvictionIncrementsExactlyOnce assertion
// chain in clients/go/node/mempool_test.go.
//
// Nil-safety follows the existing exported-accessor convention used
// by CurrentMinFeeRateSnapshot, BytesUsed, AdmissionCounts: a nil
// receiver returns counters/sizes 0, but MinFeeRate defaults to
// DefaultMempoolMinFeeRate. This keeps /metrics rendering on an
// uninitialized state agreeing with the rest of the Mempool API
// instead of advertising rubin_node_mempool_min_fee_rate = 0, which
// would disagree with CurrentMinFeeRateSnapshot's nil return and
// the documented baseline floor.
func (m *Mempool) Stats() MempoolStats {
	if m == nil {
		return MempoolStats{
			MinFeeRate: DefaultMempoolMinFeeRate,
		}
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return MempoolStats{
		TxCount:              len(m.txs),
		BytesUsed:            m.usedBytes,
		MaxBytes:             m.maxBytes,
		LowWaterBytes:        m.effectiveLowWaterBytesLocked(),
		MinFeeRate:           m.currentMinFeeRateLocked(),
		EvictedResidentTotal: m.evictedResidentTotal.Load(),
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
	return m.addTxWithSource(txBytes, mempoolTxSourceLocal)
}

// AddRemoteTx admits a transaction received from a peer while preserving the
// same validation and admission policy as AddTx. The source is metadata only.
func (m *Mempool) AddRemoteTx(txBytes []byte) (retErr error) {
	return m.addTxWithSource(txBytes, mempoolTxSourceRemote)
}

// AddReorgTx admits a transaction requeued from a disconnected canonical block
// while preserving the same validation and admission policy as AddTx.
func (m *Mempool) AddReorgTx(txBytes []byte) (retErr error) {
	return m.addTxWithSource(txBytes, mempoolTxSourceReorg)
}

// addTxWithSource validates and admits a transaction while recording the
// caller-declared origin in the mempool entry. Source provenance does not
// grant admission priority or bypass; invalid source values reject.
func (m *Mempool) addTxWithSource(txBytes []byte, source mempoolTxSource) (retErr error) {
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
	if !validMempoolTxSource(source) {
		return txAdmitRejected(fmt.Sprintf("invalid mempool tx source %q", source))
	}

	m.chainState.admissionMu.RLock()
	defer m.chainState.admissionMu.RUnlock()

	snapshot := m.chainState.admissionSnapshot()
	policy := m.policySnapshot()
	// Wave-6/8 (PR #1422): snap currentMinFeeRate ONCE so the cheap
	// precheck has a stable floor input for its accept/reject decision.
	// The locked path (validateFeeFloorLockedWithFloor below) then
	// enforces max(snappedFloor, live currentMinFeeRate) so the
	// admission decision is bidirectionally race-safe:
	//   - decay race: if decayMinFeeRateAfterConnectedBlockLocked fires
	//     between snap and lock, snappedFloor (higher) wins → spurious
	//     reject is the lesser evil, caller may retry (acceptable per
	//     Copilot wave-7 recommendation).
	//   - raise race: if raiseMinFeeRateAfterEvictionLocked fires
	//     between snap and lock, live currentMinFeeRate (higher) wins →
	//     tx correctly rejected against the current rolling floor;
	//     never admits below the live congestion-control level.
	// Wave-7's snap-once-pass-through fixed only the decay direction
	// and reopened the opposite race; wave-8 closes both.
	snappedFloor := m.CurrentMinFeeRateSnapshot()
	checked, inputs, err := m.checkTransactionWithSnapshot(txBytes, snapshot, policy, snappedFloor)
	if err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	entry := newMempoolEntry(checked, inputs, source)
	return m.addEntryLockedWithFloor(entry, snappedFloor)
}

func validMempoolTxSource(source mempoolTxSource) bool {
	switch source {
	case mempoolTxSourceRemote, mempoolTxSourceLocal, mempoolTxSourceReorg:
		return true
	default:
		return false
	}
}

// RelayMetadata returns the metadata a relay peer needs to forward the
// transaction (fee + serialized size). It runs full structural +
// chainstate validation via checkParsedTransactionWithSnapshot but
// intentionally DOES NOT enforce the rolling-relay-fee floor: the
// admit-path policy (see addTxWithSource at line 466 → addEntryLockedWithFloor
// at line 1028 → validateFeeFloorLockedWithFloor at :940-952) is the
// uniform owner of relay-floor classification (see applyPolicyAgainstState
// docstring at :753-768 for the matching admit-path rationale).
//
// Cross-client divergence (Hard Rule 2026-05-04 wave-20 thread #5):
// Rust `relay_metadata` (clients/rust/crates/rubin-node/src/txpool.rs:554)
// DOES enforce relay-floor inline via apply_post_consensus_policy_with_floor
// → validate_fee_floor. The Go relay path delegates floor enforcement to
// per-peer relay-policy + the admit-time check; the Rust relay path enforces
// inline at relay-time. This asymmetry is INTENTIONAL pending a future
// cross-client unification slice (RUB-NNN). Below-floor txs admitted via
// Go RelayMetadata that Rust RelayMetadata would `Unavailable`-reject is
// the documented expected delta — see the Rust pinning test
// `rub166_relay_metadata_below_floor_p2pk_still_returns_unavailable_matching_admit`.
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
	needs, err := policyNeedsInputSnapshotForTx(tx, policy)
	if err != nil {
		return nil, nil, txAdmitRejected(err.Error())
	}
	if needs {
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

func (m *Mempool) applyConnectedBlockParsed(block *consensus.ParsedBlock) error {
	return m.withLockedParsedBlock(block, func(block *consensus.ParsedBlock) {
		for _, txid := range block.Txids {
			m.removeTxLocked(txid)
		}
		for txid := range m.collectConflictsLocked(block) {
			m.removeTxLocked(txid)
		}
		m.decayMinFeeRateAfterConnectedBlockLocked()
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

// policyNeedsInputSnapshotForTx returns true if applying policy to the
// already-parsed transaction will read input UTXOs. The decision is
// tx-aware so admissions of non-DA transactions under the default
// config (`MinDaFeeRate=DefaultMinDaFeeRate=1`,
// `PolicyDaSurchargePerByte=0`, `PolicyRejectCoreExtPreActivation=false`)
// skip the per-tx map copy entirely.
//
// Trigger conditions:
//
//  1. `PolicyRejectCoreExtPreActivation` is on — the CORE_EXT classifier
//     reads input state for any candidate, so the snapshot is required
//     regardless of tx shape.
//  2. The DA path is exercisable AND the tx is DA-bearing
//     (`daBytes > 0`). `applyPolicyAgainstState` repeats the DA-bearing
//     check from the post-validation metadata before invoking
//     `RejectDaAnchorTxPolicy`, so non-DA tx never consume the snapshot or
//     enter the DA helper.
//
// A raw all-zero DA policy snapshot + non-CORE_EXT routing relies on
// `validateFeeFloorLocked` to enforce the rolling relay-fee floor; that
// path does not need a UTXO snapshot. Public NewMempoolWithConfig callers
// get DefaultMinDaFeeRate when MinDaFeeRate is left at zero.
//
// The function takes the parsed `*consensus.Tx` (not the post-validation
// `*CheckedTransaction`) on purpose: the caller must build the snapshot
// BEFORE invoking `CheckTransaction*WithOwnedUtxoSet`, which takes
// ownership of the supplied utxo map and removes spent inputs as it
// validates. The DA-bearing decision is a cheap structural predicate, not
// a full weight/stat walk; malformed tx kinds are still rejected by the
// later consensus validation path.
func policyNeedsInputSnapshotForTx(tx *consensus.Tx, policy MempoolConfig) (bool, error) {
	if policy.PolicyRejectCoreExtPreActivation {
		return true, nil
	}
	if policy.MinDaFeeRate == 0 && policy.PolicyDaSurchargePerByte == 0 {
		return false, nil
	}
	if tx == nil {
		return false, errors.New("nil transaction")
	}
	return tx.TxKind != 0x00 && len(tx.DaPayload) > 0, nil
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
	// Stage C DA fee policy: only enter the helper for DA-bearing tx when
	// the DA-side floor is configured (MinDaFeeRate > 0) or a per-byte
	// surcharge applies. Non-DA tx skip the helper entirely on the hot
	// admit path; their relay-floor handling remains in
	// validateFeeFloorLocked.
	//
	// The mempool admit path enforces the rolling relay-fee floor through
	// validateFeeFloorLocked (TxAdmitUnavailable — transient/retryable),
	// so this caller intentionally passes currentMempoolMinFeeRate=0 so
	// max(relay_fee_floor, da_required_fee) collapses to da_required_fee.
	// Without the zero override, a DA tx that pays the DA-side floor but
	// not the rolling relay floor would surface here as TxAdmitRejected
	// ("DA fee below Stage C floor ... relay_fee_floor=...") instead of
	// the symmetric TxAdmitUnavailable that non-DA tx receive from
	// validateFeeFloorLocked. With currentMin=0 the helper enforces only
	// the DA-specific terms and validateFeeFloorLocked owns relay-floor
	// classification uniformly for both DA and non-DA admissions.
	//
	// The miner caller (rejectCandidate) keeps using the live rolling
	// floor because it has no validateFeeFloorLocked equivalent — the
	// miner template needs to skip a tx whenever it fails any floor.
	if checked.DaBytes > 0 && (policy.MinDaFeeRate > 0 || policy.PolicyDaSurchargePerByte > 0) {
		reject, _, reason, err := RejectDaAnchorTxPolicy(
			checked.Tx,
			utxos,
			0,
			policy.MinDaFeeRate,
			policy.PolicyDaSurchargePerByte,
		)
		if err != nil {
			return txAdmitRejected(fmt.Sprintf("%s: %v", reason, err))
		}
		if reject {
			return txAdmitRejected(reason)
		}
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

func (m *Mempool) validateNonCapacityAdmissionLocked(entry *mempoolEntry) error {
	if err := validateBasicMempoolEntry(entry); err != nil {
		return err
	}
	if err := m.validateEntryIdentityLocked(entry); err != nil {
		return err
	}
	if err := validateMempoolEntrySource(entry.source); err != nil {
		return err
	}
	if err := m.validateEntryInputsLocked(entry); err != nil {
		return err
	}
	return m.validateAdmissionSeqLocked(entry)
}

func validateBasicMempoolEntry(entry *mempoolEntry) error {
	if entry == nil {
		return txAdmitRejected("nil mempool entry")
	}
	if entry.size <= 0 {
		return txAdmitRejected("invalid mempool entry size")
	}
	if entry.weight == 0 {
		return txAdmitRejected("invalid mempool entry weight")
	}
	return nil
}

func (m *Mempool) validateEntryIdentityLocked(entry *mempoolEntry) error {
	txid := entry.txid
	if txid == ([32]byte{}) {
		return txAdmitRejected("invalid mempool entry txid")
	}
	if _, exists := m.txs[txid]; exists {
		return txAdmitConflict("tx already in mempool")
	}
	wtxid := entry.wtxid
	if wtxid == ([32]byte{}) {
		wtxid = entry.txid
	}
	if existing, exists := m.wtxids[wtxid]; exists {
		return txAdmitConflict(fmt.Sprintf("mempool wtxid conflict with %x", existing))
	}
	return nil
}

func validateMempoolEntrySource(source mempoolTxSource) error {
	if source == "" {
		source = mempoolTxSourceLocal
	}
	if !validMempoolTxSource(source) {
		return txAdmitRejected(fmt.Sprintf("invalid mempool tx source %q", source))
	}
	return nil
}

func (m *Mempool) validateEntryInputsLocked(entry *mempoolEntry) error {
	for _, op := range entry.inputs {
		if existing, ok := m.spenders[op]; ok {
			return txAdmitConflict(fmt.Sprintf("mempool double-spend conflict with %x", existing))
		}
	}
	return nil
}

func (m *Mempool) validateAdmissionSeqLocked(entry *mempoolEntry) error {
	if entry.admissionSeq != 0 {
		for existingTxid, existing := range m.txs {
			if existing != nil && existing.admissionSeq == entry.admissionSeq {
				return txAdmitRejected(fmt.Sprintf("mempool admission sequence conflict with %x", existingTxid))
			}
		}
	}
	if m.lastAdmissionSeq == ^uint64(0) {
		return txAdmitUnavailable("mempool admission sequence exhausted")
	}
	return nil
}

// validateFeeFloorLocked enforces the rolling-relay-floor invariant
// using the live `m.currentMinFeeRate` value. Production callers
// SHOULD use `validateFeeFloorLockedWithFloor` to thread a snapped
// floor value through (see wave-6 race fix); this wrapper exists for
// test callers that drive the helper in isolation.
func (m *Mempool) validateFeeFloorLocked(entry *mempoolEntry) error {
	return m.validateFeeFloorLockedWithFloor(entry, m.currentMinFeeRateLocked())
}

// validateFeeFloorLockedWithFloor is the wave-8 race-safe entry point.
// `snappedFloor` is the floor value captured ONCE in `addTxWithSource`
// before the cheap precheck fired. The locked check enforces the
// MAXIMUM of (snappedFloor, live currentMinFeeRate) so newer higher
// floors always win.
//
// Bidirectional race protection:
//   - decay race (Copilot wave-5): if `decayMinFeeRateAfterConnectedBlockLocked`
//     fires between snap and lock, snappedFloor (higher) wins → tx
//     rejected here too. Caller may retry against the new lower
//     snapshot and admit — spurious reject is the lesser evil
//     (acceptable per Copilot's wave-7 recommendation).
//   - raise race (Codex + Copilot wave-7): if
//     `raiseMinFeeRateAfterEvictionLocked` fires between snap and
//     lock, live `currentMinFeeRate` (higher) wins → tx correctly
//     rejected against the current congestion-control policy. NEVER
//     admits a transaction below the current rolling floor.
//
// Wave-7 (snap-once-pass-through) closed the decay race in one
// direction but introduced the raise race in the opposite direction
// (both Codex PRRT_TRxc and Copilot PRRT_TYQt found this). Wave-8
// adds the locked re-read with max-of-(snap, live) per Copilot's
// explicit wave-7 fix recommendation.
func (m *Mempool) validateFeeFloorLockedWithFloor(entry *mempoolEntry, snappedFloor uint64) error {
	if entry == nil {
		return txAdmitRejected("nil mempool entry")
	}
	floor := snappedFloor
	if live := m.currentMinFeeRateLocked(); live > floor {
		floor = live
	}
	if feeRateBelowFloor(entry.fee, entry.weight, floor) {
		return txAdmitUnavailable(fmt.Sprintf("mempool fee below rolling minimum: fee=%d weight=%d min_fee_rate=%d", entry.fee, entry.weight, floor))
	}
	return nil
}

func newMempoolEntry(checked *consensus.CheckedTransaction, inputs []consensus.Outpoint, source mempoolTxSource) *mempoolEntry {
	return &mempoolEntry{
		raw:    append([]byte(nil), checked.Bytes...),
		txid:   checked.TxID,
		wtxid:  checked.WTxID,
		inputs: append([]consensus.Outpoint(nil), inputs...),
		fee:    checked.Fee,
		weight: checked.Weight,
		size:   checked.SerializedSize,
		source: source,
	}
}

func normalizeMempoolEntryDefaults(entry *mempoolEntry) {
	if entry == nil {
		return
	}
	if entry.source == "" {
		entry.source = mempoolTxSourceLocal
	}
	if entry.wtxid == ([32]byte{}) {
		entry.wtxid = entry.txid
	}
}

// addEntryLocked admits `entry` under `m.mu`, using the live
// `m.currentMinFeeRate` value for the fee-floor check. Production
// callers SHOULD use `addEntryLockedWithFloor` (see wave-6 race fix
// in addTxWithSource); this wrapper exists for test callers that
// drive the locked admission path in isolation and accept whatever
// floor is in effect at call time.
func (m *Mempool) addEntryLocked(entry *mempoolEntry) error {
	return m.addEntryLockedWithFloor(entry, m.currentMinFeeRateLocked())
}

// addEntryLockedWithFloor is the wave-6/8 race-safe entry point. The
// caller MUST pass the `snappedFloor` value that was captured ONCE
// before the cheap precheck fired (see addTxWithSource for rationale).
// The snapped floor is plumbed down to validateFeeFloorLockedWithFloor
// which enforces max(snappedFloor, live currentMinFeeRate) on the
// admission decision: the precheck owns the snap, the locked path
// owns the live re-read, and the strict-of-the-two wins. This blocks
// the raise race (Codex+Copilot wave-7) where
// raiseMinFeeRateAfterEvictionLocked could fire between snap and lock
// and a stale-lower snap would otherwise admit a transaction below
// the current rolling floor.
func (m *Mempool) addEntryLockedWithFloor(entry *mempoolEntry, snappedFloor uint64) error {
	normalizeMempoolEntryDefaults(entry)
	if err := m.validateNonCapacityAdmissionLocked(entry); err != nil {
		return err
	}
	evictedEntries, err := m.validateCapacityAdmissionLocked(entry, snappedFloor)
	if err != nil {
		return err
	}
	m.ensureMinFeeRateLocked()
	m.ensureIndexesLocked()
	for _, evicted := range evictedEntries {
		m.deleteEntryLocked(evicted.txid, evicted)
		// Bump the resident-eviction counter exactly once per
		// already-admitted entry that capacity pressure removes here.
		// Candidate-worst rejection returned txAdmitUnavailable above
		// without populating evictedEntries, so that path skips this
		// loop entirely. Fee-floor rejection returned earlier from
		// validateFeeFloorLocked and likewise never reaches here.
		m.evictedResidentTotal.Add(1)
	}
	m.assignAdmissionSeqLocked(entry)
	m.insertEntryIndexesLocked(entry)
	m.raiseMinFeeRateAfterEvictionLocked(evictedEntries)
	return nil
}

func (m *Mempool) validateCapacityAdmissionLocked(entry *mempoolEntry, snappedFloor uint64) ([]*mempoolEntry, error) {
	if err := m.validateFeeFloorLockedWithFloor(entry, snappedFloor); err != nil {
		return nil, err
	}
	evictedEntries, candidateEvicted, err := m.capacityEvictionPlanLocked(entry)
	if err != nil {
		return nil, err
	}
	if candidateEvicted {
		return nil, txAdmitUnavailable("mempool capacity candidate rejected by eviction ordering")
	}
	return evictedEntries, nil
}

func (m *Mempool) ensureIndexesLocked() {
	if m.txs == nil {
		m.txs = make(map[[32]byte]*mempoolEntry)
	}
	if m.wtxids == nil {
		m.wtxids = make(map[[32]byte][32]byte)
	}
	if m.spenders == nil {
		m.spenders = make(map[consensus.Outpoint][32]byte)
	}
}

func (m *Mempool) assignAdmissionSeqLocked(entry *mempoolEntry) {
	if entry.admissionSeq == 0 {
		m.lastAdmissionSeq++
		entry.admissionSeq = m.lastAdmissionSeq
	} else if entry.admissionSeq > m.lastAdmissionSeq {
		m.lastAdmissionSeq = entry.admissionSeq
	}
}

func (m *Mempool) insertEntryIndexesLocked(entry *mempoolEntry) {
	m.txs[entry.txid] = entry
	m.wtxids[entry.wtxid] = entry.txid
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
	if existing, ok := m.wtxids[entry.wtxid]; ok && existing == txid {
		delete(m.wtxids, entry.wtxid)
	}
}

type mempoolEvictionPlanEntry struct {
	entry     *mempoolEntry
	candidate bool
}

type mempoolCapacityState struct {
	maxBytes      uint64
	candidateSize uint64
	usedBytes     uint64
	targetBytes   uint64
	totalBytes    uint64
	totalCount    int
	countPressure bool
	bytePressure  bool
}

func (m *Mempool) capacityEvictionPlanLocked(candidate *mempoolEntry) ([]*mempoolEntry, bool, error) {
	if candidate == nil {
		return nil, false, txAdmitRejected("nil mempool entry")
	}
	state, err := m.capacityStateLocked(candidate)
	if err != nil {
		return nil, false, err
	}
	if !state.underPressure() {
		return nil, false, nil
	}
	planPool, err := m.evictionPlanPoolLocked(candidate)
	if err != nil {
		return nil, false, err
	}
	return dryRunCapacityEvictions(planPool, state, m.maxTxs)
}

func (m *Mempool) capacityStateLocked(candidate *mempoolEntry) (mempoolCapacityState, error) {
	maxBytes, err := nonNegativeMempoolIntToUint64("max_bytes", m.maxBytes)
	if err != nil {
		return mempoolCapacityState{}, err
	}
	if m.maxTxs <= 0 || maxBytes == 0 {
		return mempoolCapacityState{}, txAdmitUnavailable(fmt.Sprintf("invalid mempool capacity limits: max_txs=%d max_bytes=%d", m.maxTxs, m.maxBytes))
	}
	candidateSize, err := nonNegativeMempoolIntToUint64("candidate_size", candidate.size)
	if err != nil {
		return mempoolCapacityState{}, err
	}
	usedBytes, err := nonNegativeMempoolIntToUint64("used_bytes", m.usedBytes)
	if err != nil {
		return mempoolCapacityState{}, err
	}
	if candidateSize > maxBytes {
		return mempoolCapacityState{}, txAdmitUnavailable(fmt.Sprintf("mempool byte limit exceeded: current=%d tx=%d max=%d", m.usedBytes, candidate.size, m.maxBytes))
	}
	countPressure := len(m.txs) >= m.maxTxs
	bytePressure := usedBytes > maxBytes-candidateSize
	targetBytes := maxBytes
	if bytePressure {
		targetBytes = mempoolBytePressureTarget(uint64(m.effectiveLowWaterBytesLocked()), candidateSize) // #nosec G115 -- effectiveLowWaterBytesLocked returns 0 or a positive value derived from positive maxBytes.
	}
	return mempoolCapacityState{
		maxBytes:      maxBytes,
		candidateSize: candidateSize,
		usedBytes:     usedBytes,
		targetBytes:   targetBytes,
		totalBytes:    usedBytes + candidateSize,
		totalCount:    len(m.txs) + 1,
		countPressure: countPressure,
		bytePressure:  bytePressure,
	}, nil
}

func mempoolBytePressureTarget(lowWaterBytes uint64, candidateSize uint64) uint64 {
	if lowWaterBytes < candidateSize {
		return candidateSize
	}
	return lowWaterBytes
}

func (state mempoolCapacityState) underPressure() bool {
	return state.countPressure || state.bytePressure
}

func (m *Mempool) evictionPlanPoolLocked(candidate *mempoolEntry) ([]mempoolEvictionPlanEntry, error) {
	planPool := make([]mempoolEvictionPlanEntry, 0, len(m.txs)+1)
	admissionSeqs := make(map[uint64][32]byte, len(m.txs))
	for _, entry := range m.txs {
		if err := validateEvictionMetadata(entry); err != nil {
			return nil, err
		}
		if existing, exists := admissionSeqs[entry.admissionSeq]; exists {
			return nil, txAdmitRejected(fmt.Sprintf("duplicate mempool entry admission_seq %d existing=%x new=%x", entry.admissionSeq, existing, entry.txid))
		}
		admissionSeqs[entry.admissionSeq] = entry.txid
		planPool = append(planPool, mempoolEvictionPlanEntry{entry: entry})
	}
	planPool = append(planPool, mempoolEvictionPlanEntry{entry: candidate, candidate: true})
	return planPool, nil
}

func dryRunCapacityEvictions(planPool []mempoolEvictionPlanEntry, state mempoolCapacityState, maxTxs int) ([]*mempoolEntry, bool, error) {
	evictedEntries := make([]*mempoolEntry, 0)
	for state.exceedsEvictionTarget(maxTxs) && len(planPool) > 0 {
		worstIndex := worstEvictionPlanIndex(planPool)
		worst := planPool[worstIndex]
		if worst.candidate {
			return nil, true, nil
		}
		evictedEntries = append(evictedEntries, worst.entry)
		if err := state.applyDryRunEviction(worst.entry); err != nil {
			return nil, false, err
		}
		planPool = append(planPool[:worstIndex], planPool[worstIndex+1:]...)
	}
	if state.exceedsHardCapacity(maxTxs) {
		return nil, false, txAdmitUnavailable(fmt.Sprintf("mempool capacity remains exceeded after dry-run eviction: count=%d/%d bytes=%d/%d", state.totalCount, maxTxs, state.totalBytes, state.maxBytes))
	}
	return evictedEntries, false, nil
}

func (state mempoolCapacityState) exceedsEvictionTarget(maxTxs int) bool {
	return state.totalCount > maxTxs || state.totalBytes > state.targetBytes
}

func (state mempoolCapacityState) exceedsHardCapacity(maxTxs int) bool {
	return state.totalCount > maxTxs || state.totalBytes > state.maxBytes
}

func (state *mempoolCapacityState) applyDryRunEviction(entry *mempoolEntry) error {
	worstSize := uint64(entry.size) // #nosec G115 -- validateEvictionMetadata rejects non-positive entry sizes before this helper.
	if state.totalBytes < worstSize {
		return txAdmitUnavailable("mempool eviction byte accounting underflow")
	}
	state.totalBytes -= worstSize
	state.totalCount--
	return nil
}

func worstEvictionPlanIndex(planPool []mempoolEvictionPlanEntry) int {
	worstIndex := 0
	for i := 1; i < len(planPool); i++ {
		if evictionPlanEntryWorse(planPool[i], planPool[worstIndex]) {
			worstIndex = i
		}
	}
	return worstIndex
}

func nonNegativeMempoolIntToUint64(label string, value int) (uint64, error) {
	if value < 0 {
		return 0, txAdmitUnavailable(fmt.Sprintf("invalid mempool %s: %d", label, value))
	}
	return uint64(value), nil
}

func validateEvictionMetadata(entry *mempoolEntry) error {
	if entry == nil {
		return txAdmitRejected("nil mempool entry")
	}
	if entry.txid == ([32]byte{}) {
		return txAdmitRejected("invalid mempool entry txid")
	}
	if entry.size <= 0 {
		return txAdmitRejected("invalid mempool entry size")
	}
	if entry.weight == 0 {
		return txAdmitRejected("invalid mempool entry weight")
	}
	if entry.admissionSeq == 0 {
		return txAdmitRejected(fmt.Sprintf("invalid mempool entry admission_seq for txid %x", entry.txid))
	}
	return nil
}

func evictionPlanEntryWorse(a, b mempoolEvictionPlanEntry) bool {
	if a.entry == nil || b.entry == nil {
		return a.entry != nil && b.entry == nil
	}
	if cmp := compareMempoolEvictionPriority(a, b); cmp != 0 {
		return cmp < 0
	}
	return bytes.Compare(a.entry.txid[:], b.entry.txid[:]) > 0
}

func compareMempoolEvictionPriority(a, b mempoolEvictionPlanEntry) int {
	if a.entry == nil || b.entry == nil {
		return 0
	}
	if cmp := compareEvictionFeeRate(a.entry, b.entry); cmp != 0 {
		return cmp
	}
	if a.entry.fee != b.entry.fee {
		if a.entry.fee > b.entry.fee {
			return 1
		}
		return -1
	}
	aSeq := evictionAdmissionSeq(a)
	bSeq := evictionAdmissionSeq(b)
	if aSeq != bSeq {
		if aSeq > bSeq {
			return 1
		}
		return -1
	}
	return 0
}

func evictionAdmissionSeq(entry mempoolEvictionPlanEntry) uint64 {
	if entry.candidate {
		// Treat the candidate as oldest on exact fee ties so capacity pressure is no-RBF.
		return 0
	}
	if entry.entry == nil {
		return 0
	}
	return entry.entry.admissionSeq
}

func (m *Mempool) ensureMinFeeRateLocked() {
	if m.currentMinFeeRate < DefaultMempoolMinFeeRate {
		m.currentMinFeeRate = DefaultMempoolMinFeeRate
	}
}

func (m *Mempool) currentMinFeeRateLocked() uint64 {
	if m.currentMinFeeRate < DefaultMempoolMinFeeRate {
		return DefaultMempoolMinFeeRate
	}
	return m.currentMinFeeRate
}

// CurrentMinFeeRateSnapshot returns the rolling local floor without
// requiring the caller to already hold m.mu. It briefly takes a read
// lock so that race-free Stage C admission helpers (which run under a
// chainstate-side lock, not m.mu) can read the value safely.
//
// It is exported so that external callers (e.g. the miner template
// loop in cmd/rubin-node) can wire MinerConfig.CurrentMempoolMinFeeRateFn
// directly to it and keep the relay-fee half of the Stage C admission
// contract aligned with the rolling floor.
//
// Nil-safe like the other exported Mempool accessors (BytesUsed,
// AdmissionCounts, Contains): a nil receiver returns
// DefaultMempoolMinFeeRate so test-time wiring or fail-closed paths
// that never construct a Mempool see the documented baseline floor
// instead of a panic from m.mu.RLock().
func (m *Mempool) CurrentMinFeeRateSnapshot() uint64 {
	if m == nil {
		return DefaultMempoolMinFeeRate
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.currentMinFeeRateLocked()
}

// SetCurrentMinFeeRateForTest overrides the rolling local floor. Test-only:
// bypasses the admit-path eviction logic that normally raises the floor.
// cmd/rubin-node tests inject a distinctive sentinel through this setter so
// the live miner wiring tests bind on the exact value, instead of admitting
// any closure returning the documented baseline. Nil-safe like the other
// accessors.
func (m *Mempool) SetCurrentMinFeeRateForTest(floor uint64) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.currentMinFeeRate = floor
}

func (m *Mempool) effectiveLowWaterBytesLocked() int {
	if m.lowWaterBytes > 0 || m.maxBytes <= 0 {
		return m.lowWaterBytes
	}
	return defaultMempoolLowWaterBytes(m.maxBytes)
}

func feeRateBelowFloor(fee uint64, weight uint64, floor uint64) bool {
	if weight == 0 {
		return true
	}
	if floor < DefaultMempoolMinFeeRate {
		floor = DefaultMempoolMinFeeRate
	}
	hi, lo := bits.Mul64(weight, floor)
	if hi != 0 {
		return true
	}
	return fee < lo
}

func (m *Mempool) raiseMinFeeRateAfterEvictionLocked(evictedEntries []*mempoolEntry) {
	if len(evictedEntries) == 0 {
		return
	}
	m.ensureMinFeeRateLocked()
	var highestEvictedFloor uint64
	for _, entry := range evictedEntries {
		floor, ok := entryFloorRate(entry)
		if ok && floor > highestEvictedFloor {
			highestEvictedFloor = floor
		}
	}
	raised := saturatingAddMinRelayFeeStep(highestEvictedFloor)
	if raised > m.currentMinFeeRate {
		m.currentMinFeeRate = raised
	}
}

func (m *Mempool) decayMinFeeRateAfterConnectedBlockLocked() {
	m.ensureMinFeeRateLocked()
	if m.usedBytes >= m.effectiveLowWaterBytesLocked() {
		return
	}
	decayed := m.currentMinFeeRate / 2
	if decayed < DefaultMempoolMinFeeRate {
		decayed = DefaultMempoolMinFeeRate
	}
	m.currentMinFeeRate = decayed
}

func entryFloorRate(entry *mempoolEntry) (uint64, bool) {
	if entry == nil || entry.weight == 0 {
		return 0, false
	}
	return entry.fee / entry.weight, true
}

func saturatingAddMinRelayFeeStep(v uint64) uint64 {
	if v > ^uint64(0)-DefaultMempoolMinFeeRate {
		return ^uint64(0)
	}
	return v + DefaultMempoolMinFeeRate
}

func compareFeeRate(a *mempoolEntry, b *mempoolEntry) int {
	if a == nil || b == nil {
		return 0
	}
	return compareFeeRateWeightValues(a.fee, a.weight, b.fee, b.weight)
}

func compareEvictionFeeRate(a *mempoolEntry, b *mempoolEntry) int {
	// Eviction and miner selection intentionally share the fee/weight axis.
	return compareFeeRate(a, b)
}

func compareFeeRateWeightValues(feeA uint64, weightA uint64, feeB uint64, weightB uint64) int {
	if weightA == 0 || weightB == 0 {
		return 0
	}
	ahi, alo := bits.Mul64(feeA, weightB)
	bhi, blo := bits.Mul64(feeB, weightA)
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
