package node

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"slices"
	"time"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

// txErrCode extracts the consensus.TxError code string from err for
// telemetry and event labeling. It uses errors.As so that a wrapped
// *consensus.TxError (e.g. produced by fmt.Errorf("...: %w", inner)) is
// still classified correctly instead of falling through to "ERR". A nil
// error reports "OK"; any non-TxError reports "ERR".
func txErrCode(err error) string {
	if err == nil {
		return "OK"
	}
	var te *consensus.TxError
	if errors.As(err, &te) {
		return string(te.Code)
	}
	return "ERR"
}

// canonicalRowDescriptor is the ONLY per-row state a canonical transition plan
// keeps once staging and proof are done: the charged (height, hash) pair — 40
// bytes, exactly what canonicalPlanMetadataCharge bills for one row. No block or
// header bytes, no ParsedBlock, no BlockUndo, no UTXO delta and no transaction
// payload survive into it, so retained plan memory is bounded by the metadata
// charge instead of by transition depth.
type canonicalRowDescriptor struct {
	height uint64
	hash   [32]byte
}

// canonicalStagedRow is one new-suffix artifact set on its way to the store. It
// lives in the plan only until staging consumes and releases it, and is never
// part of the retained plan metadata.
type canonicalStagedRow struct {
	descriptor  canonicalRowDescriptor
	headerBytes []byte
	blockBytes  []byte
	undo        *BlockUndo
}

// canonicalTransitionPlan is the one bounded, recovery-ready plan every
// production canonical transition — direct connect, bootstrap, winning reorg,
// standalone disconnect — derives BEFORE it opens the admission fence, and the
// only state commitCanonicalTransition consumes.
type canonicalTransitionPlan struct {
	// oldSequence and newSequence are the complete ordered canonical-index
	// identities: position is height, and equality is length plus every row.
	// newSequence is unused by a compatibility engine with no BlockStore.
	oldSequence []string
	newSequence []string

	// disconnect is tip-down (h_max..h_min, the Section 11.1 requeue order) and
	// connect is ascending height. Together they are the charged row set.
	disconnect []canonicalRowDescriptor
	connect    []canonicalRowDescriptor

	// applied is A1: one row per newly canonical block, including a row whose ID
	// list is empty, IDs ascending by raw bytes, cross-block occurrences kept.
	applied []CanonicalAppliedBlock

	// checkpoint is the image at the highest (height, block_hash) row common to
	// both identities; final is C1. A standalone disconnect shares one image for
	// both, and a reorg holds exactly these two O(UTXO) images and never a third.
	checkpoint *ChainState
	final      *ChainState

	// priorTip is the exact live identity the plan was derived against. The
	// fence rechecks it before any M/O provider work runs.
	priorTip canonicalTipScalars

	// finalMTP is the median-time-past retained-record revalidation uses against
	// C1.
	finalMTP uint64

	// staged carries new-suffix payload to the store and is released by staging,
	// so the plan afterwards retains only charged metadata.
	staged []canonicalStagedRow
}

const (
	canonicalPlanMetadataBaseBytes = 48
	canonicalPlanMetadataRowBytes  = 40
	canonicalPlanMetadataIDBytes   = 32

	// canonicalPlanMetadataCapBytes is the 64 MiB production cap on the charge
	// below. The exact cap is accepted; every term is a multiple of 8, so the
	// smallest realizable overflow is cap+8.
	canonicalPlanMetadataCapBytes = uint64(67108864)
)

// canonicalPlanMetadataCap is the live cap on the production charge path. It is
// package-private and exists so a test can drive the REAL refusal with a small
// plan instead of a parallel copy of the rule; it is the only such override and
// there is no public, CLI, file or RPC knob.
var canonicalPlanMetadataCap = canonicalPlanMetadataCapBytes

// errCanonicalPlanMetadataCap refuses a plan whose charged metadata exceeds the
// cap. It fires BEFORE any artifact write, checkpoint replacement, owner
// generation advance or live mutation, so a refused plan changes nothing.
var errCanonicalPlanMetadataCap = errors.New("LOCAL_RESOURCE_UNAVAILABLE(canonical_plan_metadata)")

// canonicalPlanMetadataCharge bills exactly what the plan retains:
// 48 + 40*(disconnect_rows+connect_rows) + 32*sum(len(A1[row].CompleteDAIDs)).
// Every term is checked, so no count can wrap the total back under the cap.
func canonicalPlanMetadataCharge(disconnect, connect []canonicalRowDescriptor, applied []CanonicalAppliedBlock) (uint64, error) {
	rows := uint64(len(disconnect)) + uint64(len(connect))
	total, err := addCanonicalPlanBytes(canonicalPlanMetadataBaseBytes, canonicalPlanMetadataRowBytes, rows)
	if err != nil {
		return 0, err
	}
	ids := uint64(0)
	for i := range applied {
		if ids, err = addCanonicalPlanBytes(ids, 1, uint64(len(applied[i].CompleteDAIDs))); err != nil {
			return 0, err
		}
	}
	return addCanonicalPlanBytes(total, canonicalPlanMetadataIDBytes, ids)
}

// addCanonicalPlanBytes returns total+unit*count, refusing any overflow.
func addCanonicalPlanBytes(total, unit, count uint64) (uint64, error) {
	if count != 0 && unit > (math.MaxUint64-total)/count {
		return 0, errCanonicalPlanMetadataCap
	}
	return total + unit*count, nil
}

// checkCanonicalPlanMetadataBound is METADATA_BOUND: it runs after old identity
// and C1/A1 planning and BEFORE any artifact, checkpoint, generation or live
// work, so an over-cap plan is refused with nothing mutated.
func (p *canonicalTransitionPlan) checkCanonicalPlanMetadataBound() error {
	charge, err := canonicalPlanMetadataCharge(p.disconnect, p.connect, p.applied)
	if err != nil {
		return err
	}
	return canonicalPlanMetadataBoundError(charge)
}

// canonicalPlanMetadataBoundError is the cap comparison itself. The exact cap is
// accepted; every charge term is a multiple of 8, so the smallest realizable
// overflow is cap+8.
func canonicalPlanMetadataBoundError(charge uint64) error {
	if charge > canonicalPlanMetadataCap {
		return fmt.Errorf("%w: charge=%d cap=%d", errCanonicalPlanMetadataCap, charge, canonicalPlanMetadataCap)
	}
	return nil
}

// canonicalCommitTruth is the commit-truth class of one canonical transition.
// It is not a consensus result: OLD preserves the exact old image, NEW publishes
// the exact planned new image, and UNKNOWN publishes neither.
type canonicalCommitTruth uint8

const (
	canonicalTruthOld canonicalCommitTruth = iota
	canonicalTruthNew
	canonicalTruthUnknown
)

// errCanonicalCommitUnclassified stands in when a commit result carries a latching
// outcome with no cause, so a latch always has evidence.
var errCanonicalCommitUnclassified = errors.New("canonical index commit returned an unclassified result")

// classifyCanonicalCommit is the SOLE truth selector: it reads the commit result
// class and its sentinel cause and nothing else — never error text, a RAM digest,
// a live tip, a published summary, a callback or a reload heuristic.
//
// The mapping is closed:
//
//	COMMITTED                             -> NEW,     open
//	LOCAL_PERSISTENCE_ERROR(precommit)    -> OLD,     open
//	stale + errCanonicalIndexMoved        -> OLD,     open      (STALE_LOCAL_PLAN)
//	stale + errPreparedIndexSpent         -> OLD,     latched   (TERMINAL_LOCAL_INVARIANT)
//	empty class + noncanonical bytes/count-> OLD,     open      (LOCAL_RESOURCE_UNAVAILABLE)
//	empty class, any other cause          -> OLD,     latched
//	TERMINAL_PERSISTENCE(old)             -> OLD,     latched
//	TERMINAL_PERSISTENCE(new)             -> NEW,     latched
//	TERMINAL_PERSISTENCE(neither/unread.) -> UNKNOWN, latched
//
// Any other class value — including one this package does not define — is
// UNKNOWN and latched: an unrecognized class must never map to NEW and must
// never release admission.
func classifyCanonicalCommit(result canonicalCommitResult) (canonicalCommitTruth, bool, error) {
	switch result.class {
	case canonicalCommitted:
		return canonicalTruthNew, false, nil
	case canonicalCommitPrecommit:
		return canonicalTruthOld, false, result.err
	case canonicalCommitStale:
		if errors.Is(result.err, errCanonicalIndexMoved) {
			return canonicalTruthOld, false, result.err
		}
		return canonicalTruthOld, true, canonicalCommitCause(result.err)
	case canonicalCommitTerminalOld:
		return canonicalTruthOld, true, canonicalCommitCause(result.err)
	case canonicalCommitTerminalNew:
		return canonicalTruthNew, true, canonicalCommitCause(result.err)
	case canonicalCommitTerminalUnknown:
		return canonicalTruthUnknown, true, canonicalCommitCause(result.err)
	case "":
		if errors.Is(result.err, errNoncanonicalBytes) || errors.Is(result.err, errNoncanonicalCount) {
			return canonicalTruthOld, false, result.err
		}
		return canonicalTruthOld, true, canonicalCommitCause(result.err)
	default:
		return canonicalTruthUnknown, true, canonicalCommitCause(result.err)
	}
}

func canonicalCommitCause(err error) error {
	if err == nil {
		return errCanonicalCommitUnclassified
	}
	return err
}

// commitCanonicalTransition runs METADATA_BOUND, RECOVERY_PROOF, FENCE_AND_MO,
// ONE_COMMIT, CLASSIFY and FIXED_PUBLICATION for one already-planned transition,
// and is the only production path that commits a canonical-index image.
//
// It returns the commit truth plus the error the caller must surface. Only NEW
// authorizes the caller to expose A1, the summary, counters and requeue, and
// only an ordinary NEW (nil error) authorizes requeue.
func (s *SyncEngine) commitCanonicalTransition(plan *canonicalTransitionPlan, diag *diagnosticBatch) (canonicalCommitTruth, error) {
	if plan == nil || plan.final == nil || plan.checkpoint == nil {
		return canonicalTruthOld, errors.New("nil canonical transition plan image")
	}
	if err := plan.checkCanonicalPlanMetadataBound(); err != nil {
		return canonicalTruthOld, err
	}
	prepared, err := s.prepareCanonicalTransitionIndex(plan)
	if err != nil {
		return canonicalTruthOld, err
	}
	if err := s.proveCanonicalRecoverySet(plan); err != nil {
		return canonicalTruthOld, s.latchPreFenceCanonicalCorruption(err, diag)
	}
	return s.fenceAndCommitCanonicalTransition(plan, prepared, diag)
}

// canonicalStoreIntegrityError marks corruption or loss of a canonical artifact
// the active retention profile already requires to be present. Rubin's profile
// requires a complete header/block/undo set for EVERY canonical row, so a suffix
// row that does not strict-read is TERMINAL_STORE_INTEGRITY(canonical) and never
// a recoverable resource refusal.
type canonicalStoreIntegrityError struct{ cause error }

func (e *canonicalStoreIntegrityError) Error() string {
	return "TERMINAL_STORE_INTEGRITY(canonical): " + e.cause.Error()
}

func (e *canonicalStoreIntegrityError) Unwrap() error { return e.cause }

// latchPreFenceCanonicalCorruption installs the EXISTING terminal fail-closed
// latch for a canonical corruption found before the fence opened. It acquires
// the live admission guard BEFORE installing the fault and RETAINS it until
// restart, which is the latch itself; it publishes nothing, advances no owner
// generation and invents no second terminal mechanism. Every other precommit
// failure preserves OLD with admission open and returns unchanged.
func (s *SyncEngine) latchPreFenceCanonicalCorruption(cause error, diag *diagnosticBatch) error {
	var integrity *canonicalStoreIntegrityError
	if !errors.As(cause, &integrity) {
		return cause
	}
	s.chainState.admissionMu.Lock()
	s.latchTerminalFault(cause)
	s.reportTerminalTransition(diag, "terminal canonical store integrity", cause)
	return cause
}

// prepareCanonicalTransitionIndex builds the semantic prepared index OFF-LOCK,
// against the store's visible canonical identity. A compatibility engine with no
// BlockStore has no canonical index and prepares none: its truth comes from the
// chainstate save in saveNonpersistentFinalState.
func (s *SyncEngine) prepareCanonicalTransitionIndex(plan *canonicalTransitionPlan) (*preparedCanonicalIndex, error) {
	if s.blockStore == nil {
		return nil, nil
	}
	return prepareCanonicalIndex(s.blockStore.visibleIndexBytes(), plan.newSequence)
}

// proveCanonicalRecoverySet completes precommit recovery: it stages every
// required new-suffix artifact through the existing reservation path, strict-reads
// BOTH suffix proof sets through the same reader startup uses, and only then
// replaces the durable checkpoint and reads it back.
//
// Order is load-bearing. No failure here can destroy the last usable old
// snapshot: the checkpoint row is common to the old and planned-new identities,
// so a checkpoint that did land still replays either suffix.
func (s *SyncEngine) proveCanonicalRecoverySet(plan *canonicalTransitionPlan) error {
	if s.blockStore == nil {
		plan.staged = nil
		return nil
	}
	staged := plan.staged
	// Released before the proof reads, so the transition retains only charged
	// descriptors from here on.
	plan.staged = nil
	for i := range staged {
		if err := s.blockStore.StoreBlock(staged[i].descriptor.hash, staged[i].headerBytes, staged[i].blockBytes); err != nil {
			return err
		}
		if err := s.blockStore.PutUndo(staged[i].descriptor.hash, staged[i].undo); err != nil {
			return err
		}
	}
	for _, rows := range [][]canonicalRowDescriptor{plan.disconnect, plan.connect} {
		for _, row := range rows {
			if err := s.blockStore.proveCanonicalArtifacts(row.hash); err != nil {
				return &canonicalStoreIntegrityError{cause: err}
			}
		}
	}
	return s.replaceCanonicalCheckpoint(plan)
}

// replaceCanonicalCheckpoint atomically saves the common-ancestor image and
// integrity-reads it back, comparing has-tip, height, tip hash, already-generated,
// UTXO count and state digest. A configured-out chainstate path omits only this
// durable readiness proof; every other step of the state machine is unchanged.
func (s *SyncEngine) replaceCanonicalCheckpoint(plan *canonicalTransitionPlan) error {
	if s.cfg.ChainStatePath == "" {
		return nil
	}
	if err := plan.checkpoint.Save(s.cfg.ChainStatePath); err != nil {
		return err
	}
	loaded, err := LoadChainState(s.cfg.ChainStatePath)
	if err != nil {
		return err
	}
	if !sameCanonicalStateImage(loaded, plan.checkpoint) {
		return errors.New("canonical checkpoint readback does not match the common-ancestor image")
	}
	return nil
}

// sameCanonicalStateImage compares two chainstate images by the six values that
// identify a canonical snapshot: has-tip, height, tip hash, already-generated,
// UTXO count and state digest. It is shared by the checkpoint readback and by
// the no-BlockStore ambiguous-save readback, so both prove the same equality.
func sameCanonicalStateImage(got *ChainState, want *ChainState) bool {
	if got == nil || want == nil {
		return false
	}
	gotView, wantView := got.view(), want.view()
	if gotView != wantView {
		return false
	}
	return got.StateDigest() == want.StateDigest()
}

// fenceAndCommitCanonicalTransition holds ChainState.admissionMu exclusively from
// the owner generation advance through classification and the complete fixed
// publication, so releasing the component locks around the BlockStore commit
// cannot invalidate the live preflight.
func (s *SyncEngine) fenceAndCommitCanonicalTransition(plan *canonicalTransitionPlan, prepared *preparedCanonicalIndex, diag *diagnosticBatch) (canonicalCommitTruth, error) {
	tr, err := s.beginCanonicalTransition(diag)
	if err != nil {
		return canonicalTruthOld, err
	}
	mo, err := s.prepareCanonicalFenceImage(tr, plan)
	if err != nil {
		return canonicalTruthOld, tr.end(err)
	}
	truth, latched, cause := classifyCanonicalCommit(s.commitCanonicalIndexOnce(plan, prepared))
	tr.publishCanonicalTransition(plan, mo, truth, latched, cause)
	return truth, cause
}

// prepareCanonicalFenceImage rechecks freshness under the fence and then builds
// the complete standard/owner image against final C1, binds the prepared owner
// image's stable tip to C1, and runs the full live preflight under Mempool.mu
// then PendingOutpointOwner.mu. It publishes nothing: publication is a separate
// assignment that runs only after the commit selects NEW.
//
// A nil result means no mempool is bound to this engine, which is not an error.
func (s *SyncEngine) prepareCanonicalFenceImage(tr *canonicalTransition, plan *canonicalTransitionPlan) (*canonicalMempoolPlan, error) {
	if err := s.recheckCanonicalTransitionFreshness(tr, plan); err != nil {
		return nil, err
	}
	if tr.mempool == nil {
		return nil, nil
	}
	snapshot, err := snapshotMempool(tr.mempool)
	if err != nil {
		return nil, err
	}
	mo, err := prepareCanonicalMempoolPlan(tr.mempool, snapshot, plan.final, plan.finalMTP, len(plan.connect), s.cfg.ChainID)
	if err != nil {
		return nil, err
	}
	mo.pending.stableTip = pendingOutpointTipOf(plan.final)
	if err := validateCanonicalMempoolLiveImage(tr.mempool, mo.snapshot, mo.snapshotUsedBytes, mo.owner); err != nil {
		return nil, terminalCanonicalMempoolError(err)
	}
	return &mo, nil
}

// recheckCanonicalTransitionFreshness proves, under the admission fence, that the
// live ChainState identity and the complete visible canonical-index sequence are
// still exactly the ones the plan was derived against. mutationMu already
// serializes canonical mutation in-process, so both halves are defense in depth.
func (s *SyncEngine) recheckCanonicalTransitionFreshness(tr *canonicalTransition, plan *canonicalTransitionPlan) error {
	if chainTipScalarsOf(tr.chainState) != plan.priorTip {
		return errors.New("live chainstate tip moved during canonical apply")
	}
	if s.blockStore == nil {
		return nil
	}
	visible, err := decodeCanonicalIndexSequence(s.blockStore.visibleIndexBytes())
	if err != nil {
		return err
	}
	if !slices.Equal(visible, plan.oldSequence) {
		return errors.New("visible canonical index moved during canonical apply")
	}
	return nil
}

// commitCanonicalIndexOnce invokes the prepared canonical-index commit EXACTLY
// once. A compatibility engine with no BlockStore has no index to commit and
// takes the chainstate-save lane instead, which returns the same closed result
// classes so one classifier serves both.
func (s *SyncEngine) commitCanonicalIndexOnce(plan *canonicalTransitionPlan, prepared *preparedCanonicalIndex) canonicalCommitResult {
	commitStart := time.Now()
	defer func() { s.pvTelemetry.RecordCommitLatency(time.Since(commitStart)) }()
	if prepared != nil {
		return prepared.commit(s.blockStore)
	}
	return s.saveNonpersistentFinalState(plan)
}

// saveNonpersistentFinalState is the compatibility truth source for an engine
// with no BlockStore: without a canonical index the chainstate file itself is the
// durable identity, so C1 is saved here and its outcome selects truth. A proven
// pre-namespace failure crossed nothing and is OLD; an ambiguous failure takes
// exactly ONE strict load, which yields NEW only for the exact C1 image and
// UNKNOWN for every other image, including an unreadable one.
func (s *SyncEngine) saveNonpersistentFinalState(plan *canonicalTransitionPlan) canonicalCommitResult {
	if s.cfg.ChainStatePath == "" {
		return canonicalCommitResult{class: canonicalCommitted}
	}
	err := plan.final.Save(s.cfg.ChainStatePath)
	if err == nil {
		return canonicalCommitResult{class: canonicalCommitted}
	}
	if stage, tagged := atomicWriteStageOf(err); tagged && stage == atomicWriteBeforeNamespaceCommit {
		return canonicalCommitResult{class: canonicalCommitPrecommit, err: err}
	}
	loaded, loadErr := LoadChainState(s.cfg.ChainStatePath)
	if loadErr != nil {
		return canonicalCommitResult{class: canonicalCommitTerminalUnknown, err: errors.Join(err, loadErr)}
	}
	if !sameCanonicalStateImage(loaded, plan.final) {
		return canonicalCommitResult{class: canonicalCommitTerminalUnknown, err: err}
	}
	return canonicalCommitResult{class: canonicalCommitTerminalNew, err: err}
}

// publishCanonicalTransition is FIXED_PUBLICATION. NEW first assignment-publishes
// the prebuilt C1 under ChainState.mu and releases it, then takes Mempool.mu ->
// PendingOutpointOwner.mu and assignment-publishes M1/O1 with stable tip C1 and
// the owner transition state, then releases both. No component locks overlap and
// nothing here allocates, clones, does I/O, validates, invokes a callback or
// returns an error.
//
// A latched outcome keeps admission closed until restart: terminal NEW publishes
// the full image and still latches, terminal OLD and UNKNOWN publish nothing.
// Every open outcome clears the owner transition and reopens admission.
func (t *canonicalTransition) publishCanonicalTransition(plan *canonicalTransitionPlan, mo *canonicalMempoolPlan, truth canonicalCommitTruth, latched bool, cause error) {
	ownerClosed := false
	if truth == canonicalTruthNew {
		assignCanonicalChainState(t.chainState, plan.final)
		if mo != nil {
			t.mempool.publishCanonicalMempoolPlan(*mo, !latched)
			ownerClosed = !latched
		}
	}
	if latched {
		t.engine.latchTerminalFault(cause)
		t.engine.reportTerminalTransition(t.diag, canonicalTerminalReason(truth), cause)
		return
	}
	if !ownerClosed {
		t.owner.endTransitionAborted()
	}
	t.chainState.admissionMu.Unlock()
}

func canonicalTerminalReason(truth canonicalCommitTruth) string {
	switch truth {
	case canonicalTruthNew:
		return "terminal canonical persistence (new)"
	case canonicalTruthUnknown:
		return "terminal canonical persistence (neither_or_unreadable)"
	default:
		return "terminal canonical persistence (old)"
	}
}

// assignCanonicalChainState publishes the prebuilt final image by ASSIGNMENT
// under ChainState.mu only: no clone, no allocation, no validation and no error
// return. src is the transition's private final image and is discarded
// afterwards, so moving its maps is what keeps a reorg at exactly two O(UTXO)
// images. The transition owns the non-reentrant admissionMu, so ChainState's own
// replaceFrom wrapper must never be used here.
func assignCanonicalChainState(dst *ChainState, src *ChainState) {
	dst.mu.Lock()
	dst.Utxos = src.Utxos
	dst.Height = src.Height
	dst.AlreadyGenerated = src.AlreadyGenerated
	dst.TipHash = src.TipHash
	dst.HasTip = src.HasTip
	dst.Rotation = src.Rotation
	dst.Registry = src.Registry
	dst.mu.Unlock()
}

// requeueCanonicalDisconnectedRows runs the existing best-effort standard requeue
// over the rows this transition disconnected, tip-down, which is the Section 11.1
// h_max..h_min order. It RE-READS each row from the store rather than retaining
// its bytes: the rows are retained healthy noncanonical artifacts, and holding
// depth-proportional payload is exactly what the plan's resource bound forbids. A
// row that can no longer be read is skipped with a diagnostic — requeue is a
// downstream best-effort effect and cannot change commit truth.
func (s *SyncEngine) requeueCanonicalDisconnectedRows(rows []canonicalRowDescriptor, diag *diagnosticBatch) {
	if s.mempool == nil || s.blockStore == nil || len(rows) == 0 {
		return
	}
	parsed := make([]*consensus.ParsedBlock, 0, len(rows))
	for _, row := range rows {
		blockBytes, err := s.blockStore.GetBlockByHash(row.hash)
		if err != nil {
			s.diagnose(diag, "mempool: requeue-block %x: %v\n", row.hash, err)
			continue
		}
		pb, err := consensus.ParseBlockBytes(blockBytes)
		if err != nil {
			s.diagnose(diag, "mempool: requeue-block %x: %v\n", row.hash, err)
			continue
		}
		parsed = append(parsed, pb)
	}
	s.requeueParsedDisconnectedTransactions(parsed, diag)
}

// canonicalSequenceDescriptors turns a contiguous canonical-index range into
// charged descriptors. Rows are read from the identity itself, so a descriptor
// can never name a height the sequence does not hold.
func canonicalSequenceDescriptors(sequence []string, from, to uint64, tipDown bool) ([]canonicalRowDescriptor, error) {
	if to > uint64(len(sequence)) || from > to {
		return nil, fmt.Errorf("canonical descriptor range [%d,%d) is not inside a %d-row identity", from, to, len(sequence))
	}
	rows := make([]canonicalRowDescriptor, 0, to-from)
	for height := from; height < to; height++ {
		hash, err := parseHex32("canonical hash", sequence[height])
		if err != nil {
			return nil, err
		}
		rows = append(rows, canonicalRowDescriptor{height: height, hash: hash})
	}
	if tipDown {
		slices.Reverse(rows)
	}
	return rows, nil
}

// canonicalSequenceWithSuffix returns prefix rows [0,keep) of the old identity
// followed by the newly canonical hashes, which is the complete planned-new
// canonical identity.
//
// PRECONDITION: keep <= len(oldSequence). Every caller establishes it first —
// the direct path by refusing a candidate that does not extend the identity, the
// reorg and disconnect paths by building their descriptors through
// canonicalSequenceDescriptors, which bounds-checks the same range.
func canonicalSequenceWithSuffix(oldSequence []string, keep uint64, suffix [][32]byte) []string {
	next := make([]string, 0, keep+uint64(len(suffix)))
	next = append(next, oldSequence[:keep]...)
	for _, hash := range suffix {
		next = append(next, hex.EncodeToString(hash[:]))
	}
	return next
}

func (s *SyncEngine) recordAppliedBlock(height uint64, timestamp uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tipTimestamp = timestamp
	if height > s.bestKnownHeight {
		s.bestKnownHeight = height
	}
	s.lastReorgDepth = 0
}

func (s *SyncEngine) noteBlockApplyAccepted() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.blockApply.Accepted++
}

func (s *SyncEngine) noteBlockApplyAcceptedN(count uint64) {
	if s == nil || count == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.blockApply.Accepted += count
}

func (s *SyncEngine) noteBlockApplyRejected() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.blockApply.Rejected++
}

func (s *SyncEngine) noteBlockApplyOutcome(outcome blockApplyMetricOutcome) {
	switch outcome {
	case blockApplyMetricNone:
		return
	case blockApplyMetricAccepted:
		s.noteBlockApplyAccepted()
	case blockApplyMetricRejected:
		s.noteBlockApplyRejected()
	}
}

func (s *SyncEngine) noteReorg(depth uint64) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastReorgDepth = depth
	if depth > 0 {
		s.reorgCount++
	}
}

func (s *SyncEngine) currentCanonicalTip() (uint64, [32]byte, error) {
	height, tipHash, ok, err := s.blockStore.Tip()
	if err != nil {
		return 0, [32]byte{}, err
	}
	if !ok {
		return 0, [32]byte{}, errors.New("blockstore has no canonical tip")
	}
	return height, tipHash, nil
}
