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

// AllTxIDs returns the txids of every transaction currently in the mempool.
// The slice ordering is not guaranteed to be stable between calls.
func (m *Mempool) AllTxIDs() [][32]byte {
	return m.txIDsLimit(0)
}

// TxIDsLimit returns at most limit txids from the current mempool snapshot.
// It returns nil when limit <= 0; use AllTxIDs for an unbounded snapshot.
// The slice ordering is not guaranteed to be stable between calls.
func (m *Mempool) TxIDsLimit(limit int) [][32]byte {
	if limit <= 0 {
		return nil
	}
	return m.txIDsLimit(limit)
}

func (m *Mempool) txIDsLimit(limit int) [][32]byte {
	if m == nil {
		return nil
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	capHint := len(m.txs)
	if limit > 0 && limit < capHint {
		capHint = limit
	}
	ids := make([][32]byte, 0, capHint)
	for txid := range m.txs {
		ids = append(ids, txid)
		if limit > 0 && len(ids) >= limit {
			break
		}
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
	policyUtxos, err := buildPolicyInputSnapshotIfNeeded(tx, snapshot, policy)
	if err != nil {
		return nil, nil, err
	}
	if policy.PolicyRejectSimplicityPreActivation {
		reject, reason, err := rejectCoreSimplicityPreActivation(tx, policyUtxos, nextHeight, policy.RotationProvider)
		if err != nil {
			return nil, nil, txAdmitRejected(err.Error())
		}
		if reject {
			return nil, nil, txAdmitRejected(reason)
		}
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
	if err := applyPolicyAgainstStateAnchor(checked, policy); err != nil {
		return err
	}

	// Apply DA fee policy
	if err := applyPolicyAgainstStateDA(checked, policy, utxos); err != nil {
		return err
	}

	// Apply Simplicity policy
	if err := applyPolicyAgainstStateSimplicity(checked, utxos, nextHeight, policy); err != nil {
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
