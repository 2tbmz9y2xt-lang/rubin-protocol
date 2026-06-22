package node

import (
	"errors"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

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
	MaxTransactions int
	MaxBytes        int
	// PolicyMaxDaBytesPerBlock caps the declared DA bytes of a DA_COMMIT
	// transaction admitted to mempool/relay policy. The value is derived from
	// DaCommitCore.ChunkCount * CHUNK_BYTES, not caller-supplied payload bytes.
	// A zero value is treated as omitted and normalized to the miner policy
	// default so partial configs do not accidentally disable the budget.
	PolicyMaxDaBytesPerBlock uint64
	PolicyDaSurchargePerByte uint64
	// MinDaFeeRate is the spec-side per-byte DA fee floor
	// (POLICY_MEMPOOL_ADMISSION_GENESIS.md Stage C `min_da_fee_rate`,
	// default 1). NewMempoolWithConfig treats 0 as omitted and normalizes
	// it to DefaultMinDaFeeRate; callers cannot disable the spec floor
	// through the public mempool config. Direct policy-helper tests may
	// still pass 0 to isolate surcharge-only helper semantics.
	MinDaFeeRate                         uint64
	PolicyRejectNonCoinbaseAnchorOutputs bool
	PolicyRejectSimplicityPreActivation  bool
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
		PolicyMaxDaBytesPerBlock:             minerDefaults.PolicyMaxDaBytesPerBlock,
		PolicyDaSurchargePerByte:             minerDefaults.PolicyDaSurchargePerByte,
		MinDaFeeRate:                         DefaultMinDaFeeRate,
		PolicyRejectNonCoinbaseAnchorOutputs: minerDefaults.PolicyRejectNonCoinbaseAnchorOutputs,
		PolicyRejectSimplicityPreActivation:  minerDefaults.PolicyRejectSimplicityPreActivation,
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
	if cfg.PolicyMaxDaBytesPerBlock == 0 {
		cfg.PolicyMaxDaBytesPerBlock = DefaultMinerConfig().PolicyMaxDaBytesPerBlock
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
