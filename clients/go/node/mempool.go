package node

import (
	"errors"
	"fmt"
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

// RelayMetadata returns the metadata a relay peer needs to forward the
// transaction (fee + serialized size). It runs full structural +
// chainstate validation via checkParsedTransactionWithSnapshot and then
// enforces the rolling-relay-fee floor read-only. Below-floor otherwise-valid
// txs return the same TxAdmitUnavailable class/message family as admit-path
// validateFeeFloorLockedWithFloor.
//
// RelayMetadata is not full mempool admission: it does not insert, does not
// record source/admission_seq, and does not check duplicate, conflict, or
// capacity state. Those remain owned by addTxWithSource/addEntryLockedWithFloor.
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
	snappedFloor := m.CurrentMinFeeRateSnapshot()
	checked, _, err := m.checkParsedTransactionWithSnapshot(txBytes, tx, txid, wtxid, snapshot, policy)
	if err != nil {
		return RelayTxMetadata{}, err
	}
	if err := m.validateRelayMetadataFeeFloor(checked, snappedFloor); err != nil {
		return RelayTxMetadata{}, err
	}
	return RelayTxMetadata{
		Fee:  checked.Fee,
		Size: checked.SerializedSize,
	}, nil
}

func (m *Mempool) checkParsedTransactionWithSnapshot(
	txBytes []byte,
	tx *consensus.Tx,
	txid [32]byte,
	wtxid [32]byte,
	snapshot *chainStateAdmissionSnapshot,
	policy MempoolConfig,
) (*consensus.CheckedTransaction, []consensus.Outpoint, error) {
	// Validate chain snapshot and extract next height
	nextHeight, err := validateChainSnapshot(snapshot)
	if err != nil {
		return nil, nil, err
	}

	// Get block MTP
	blockMTP, err := m.nextBlockMTP(nextHeight)
	if err != nil {
		return nil, nil, txAdmitUnavailable(err.Error())
	}

	// Prepare policy UTXOs if needed
	policyUtxos, err := preparePolicyUtxos(tx, policy, snapshot)
	if err != nil {
		return nil, nil, err
	}

	// Perform consensus validation
	checked, err := m.validateTransactionWithConsensus(txBytes, tx, txid, wtxid, snapshot, nextHeight, blockMTP, policy)
	if err != nil {
		return nil, nil, err
	}

	// Apply policy validation
	if err := m.applyPolicyAgainstState(checked, nextHeight, policyUtxos, policy); err != nil {
		return nil, nil, txAdmitRejected(err.Error())
	}

	// Extract inputs and return
	inputs := extractTxInputs(checked)
	return checked, inputs, nil
}

func (m *Mempool) applyPolicyAgainstState(checked *consensus.CheckedTransaction, nextHeight uint64, utxos map[consensus.Outpoint]consensus.UtxoEntry, policy MempoolConfig) error {
	if checked == nil || checked.Tx == nil {
		return errors.New("nil checked transaction")
	}
	// Apply non-coinbase anchor output policy
	if policy.PolicyRejectNonCoinbaseAnchorOutputs {
		reject, reason, err := RejectNonCoinbaseAnchorOutputs(checked.Tx)
		if err != nil {
			return err
		}
		if reject {
			return errors.New(reason)
		}
	}

	// Apply DA fee policy
	if err := applyPolicyAgainstStateDA(checked, policy, utxos); err != nil {
		return err
	}

	// Apply CoreExt policy
	if err := applyPolicyAgainstStateCoreExt(checked, utxos, nextHeight, policy); err != nil {
		return err
	}

	// Apply payload size policy
	if err := applyPolicyAgainstStatePayload(checked, policy); err != nil {
		return err
	}

	return nil
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
		timestamp, err := getBlockTimestamp(store, height, nextHeight)
		if err != nil {
			return nil, err
		}
		out = append(out, timestamp)
	}
	return out, nil
}

// getBlockTimestamp retrieves the timestamp from a block at the given height
func getBlockTimestamp(store *BlockStore, height, nextHeight uint64) (uint64, error) {
	hash, ok, err := store.CanonicalHash(height)
	if err != nil {
		return 0, err
	}
	if !ok {
		return 0, fmt.Errorf("missing canonical hash at height %d for timestamp context (next_height=%d)", height, nextHeight)
	}
	headerBytes, err := store.GetHeaderByHash(hash)
	if err != nil {
		return 0, err
	}
	header, err := consensus.ParseBlockHeaderBytes(headerBytes)
	if err != nil {
		return 0, err
	}
	return header.Timestamp, nil
}
