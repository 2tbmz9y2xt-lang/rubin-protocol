package node

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
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
// payload survive into it, so the per-row retention is metadata, not payload.
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

	// includedDA is I: the EXACT set identities the newly canonical blocks
	// carry, in block/transaction order, derived from each already validated
	// ParsedBlock and its aligned txid/wtxid arrays. It is the inclusion half of
	// the D1 selection and is charged as bounded fixed-width metadata; no block
	// or transaction bytes are retained for it. A standalone disconnect makes
	// none, which is the empty list, not a skipped step.
	includedDA []canonicalDASetIdentity

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
	return "TERMINAL_STORE_INTEGRITY(canonical): " + canonicalCauseText(e.cause)
}

func (e *canonicalStoreIntegrityError) Unwrap() error { return e.cause }

// canonicalArtifactUnavailableError is MP641's
// LOCAL_RESOURCE_UNAVAILABLE(canonical_artifact_read): the local condition
// prevented obtaining a complete bound-satisfying value, and nothing was
// observed about the artifact itself. It preserves OLD with admission OPEN, so
// it deliberately does NOT satisfy errors.As for the integrity type — that is
// what keeps it out of the latch lane.
type canonicalArtifactUnavailableError struct{ cause error }

func (e *canonicalArtifactUnavailableError) Error() string {
	return "LOCAL_RESOURCE_UNAVAILABLE(canonical_artifact_read): " + canonicalCauseText(e.cause)
}

func (e *canonicalArtifactUnavailableError) Unwrap() error { return e.cause }

// canonicalCauseText renders a canonical failure cause without assuming it is
// non-nil. Both constructors are fed a non-nil cause today, but these Error
// methods run on a path that is already failing closed, and a formatter that
// panics there would replace a latch an operator can act on with a crash.
func canonicalCauseText(cause error) string {
	if cause == nil {
		return "unclassified cause"
	}
	return cause.Error()
}

// canonicalArtifactReadError turns one observation class into the error the
// recovery proof returns, so the class — never an error string — decides which
// lane the transition takes.
func canonicalArtifactReadError(class canonicalArtifactRead, err error) error {
	switch class {
	case canonicalArtifactValid:
		return nil
	case canonicalArtifactUnavailable:
		return &canonicalArtifactUnavailableError{cause: err}
	default:
		return &canonicalStoreIntegrityError{cause: err}
	}
}

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
// BOTH suffix proof sets, and only then replaces the durable checkpoint and reads
// it back.
//
// The MP641 read order is load-bearing and is the order below: the old/disconnect
// suffix TIP-DOWN first, then the planned-new/connect suffix ASCENDING, each row
// header then block then state-reversal artifact, stopping at the first non-valid
// observation. No failure here can destroy the last usable old snapshot: the
// checkpoint row is common to the old and planned-new identities, so a checkpoint
// that did land still replays either suffix.
//
// The two failure classes are NOT interchangeable. An artifact that could not be
// ACQUIRED — open, metadata or byte read failing before a complete bound-satisfying
// value or a definitive absence — is LOCAL_RESOURCE_UNAVAILABLE(canonical_artifact_read):
// OLD, admission open, nothing committed or published, and NO retry inside this
// attempt; a later independent apply may take the ordinary path once the local
// condition changes. Positive evidence — definitive absence, a proven over-bound
// representation, a clean EOF establishing an invalid one, or complete integrity
// evidence — is TERMINAL_STORE_INTEGRITY(canonical): OLD, latched.
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
			if err := canonicalArtifactReadError(s.blockStore.proveCanonicalArtifacts(row.hash)); err != nil {
				return err
			}
		}
	}
	return s.replaceCanonicalCheckpoint(plan)
}

// replaceCanonicalCheckpoint atomically writes the common-ancestor image through
// the one encode-and-write path and proves the durable bytes are EXACTLY the
// bytes it handed that path: one raw read with the same bound LoadChainState
// uses, then byte equality. It does not decode a third image and does not
// compute a state digest — the encoder is deterministic, so equal bytes is the
// stronger statement and the cheaper one. A configured-out chainstate path omits
// only this durable readiness proof; every other step is unchanged.
//
// The readback failure classes are MP641's, same as the suffix rows: a read that
// could not obtain the bytes is unavailability (OLD, open); a byte difference is
// complete evidence that the durable representation is not the one just written,
// so it is integrity evidence (OLD, latched). A write failure keeps its existing
// LOCAL_PERSISTENCE_ERROR(precommit) identity and preserves OLD with admission
// open.
//
// Cost, accepted for strictness: every canonical transition encodes and writes
// the FULL chainstate image and then raw-reads all of it back, so the durable
// work is O(UTXO) per transition rather than O(rows touched), and the readback
// transiently materializes a second copy of the envelope. That is the same
// accepted-cost trade requireCompleteCanonicalPrefix makes at startup, and it is
// load-bearing here: without the readback the transition would commit on the
// word of a write call, and a checkpoint that is not exactly the common image is
// what turns a later restart into a chain that cannot replay either suffix.
func (s *SyncEngine) replaceCanonicalCheckpoint(plan *canonicalTransitionPlan) error {
	if s.cfg.ChainStatePath == "" {
		return nil
	}
	want, err := plan.checkpoint.saveReturningEnvelope(s.cfg.ChainStatePath)
	if err != nil {
		return err
	}
	got, err := readFileByPath(s.cfg.ChainStatePath)
	if err != nil {
		return canonicalArtifactReadError(classifyCanonicalArtifactAcquisition(err), fmt.Errorf("canonical checkpoint readback: %w", err))
	}
	if !bytes.Equal(got, want) {
		return &canonicalStoreIntegrityError{cause: fmt.Errorf(
			"canonical checkpoint readback is %d bytes and first differs at offset %d, want the %d bytes just written",
			len(got), firstByteDifference(got, want), len(want),
		)}
	}
	return nil
}

// firstByteDifference reports the offset of the first differing byte, or the
// shorter length when one image is a prefix of the other. Equal length with
// different bytes is exactly the case a length comparison cannot name, and the
// offset localizes it without hashing or decoding either image.
func firstByteDifference(got, want []byte) int {
	for i := 0; i < len(got) && i < len(want); i++ {
		if got[i] != want[i] {
			return i
		}
	}
	return min(len(got), len(want))
}

// sameCanonicalStateImage compares two chainstate images by the six values that
// identify a canonical snapshot: has-tip, height, tip hash, already-generated,
// UTXO count and state digest.
//
// Its ONE caller is the no-BlockStore ambiguous-save readback. The checkpoint
// readback deliberately does NOT share it: the two readbacks prove different
// predicates. The checkpoint proves that the exact bytes handed to the encoder
// reached the file (bytes.Equal, no decode), which is the stronger and cheaper
// statement available when the wanted image is still in hand as bytes. This one
// proves that an image loaded back off disk after an AMBIGUOUS write IS the
// planned image; only a decoded comparison can answer that, because the bytes
// that landed were written by a call whose outcome is unknown.
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
	image, err := s.prepareCanonicalFenceImage(tr, plan)
	if err != nil {
		return canonicalTruthOld, tr.end(err)
	}
	truth, latched, cause := classifyCanonicalCommit(s.commitCanonicalIndexOnce(plan, prepared))
	// Built HERE, outside the publication corridor: the fault value and the
	// operator record are the corridor's only allocating work, and clause 8
	// allows it none. Non-nil means "latched" for the corridor.
	var fault *storagePersistenceFault
	var report string
	if latched {
		fault = &storagePersistenceFault{cause: cause}
		report = terminalTransitionRecord(canonicalLatchReason(truth, cause), cause)
	}
	tr.publishCanonicalTransition(plan, image, truth, fault, report)
	return truth, cause
}

// canonicalFenceImage is the complete new image one transition prepared under the
// admission fence and publishes by assignment if — and only if — the commit
// selects NEW. Both halves are optional in exactly one case each: an engine with
// no mempool bound has neither, which is not an error.
type canonicalFenceImage struct {
	mo *canonicalMempoolPlan
	da *preparedCanonicalDAImage
}

// prepareCanonicalFenceImage rechecks freshness under the fence and then builds
// the complete standard/owner image against final C1, binds the prepared owner
// image's stable tip to C1, and runs the full live preflight under Mempool.mu
// then PendingOutpointOwner.mu. Only then does it prepare the retained-DA image
// against the SAME captured C1 context. It publishes nothing: publication is a
// separate assignment that runs only after the commit selects NEW.
//
// The M/O half is deliberately FIRST and complete before the D half starts, so a
// transition violating both invariants at once reports the standard/owner error:
// the contract's error order is preparation order, and D preparation is not
// reached at all once M/O has failed.
//
// An empty image means no mempool is bound to this engine, which is not an
// error; a bound mempool always carries the retained-DA state installed with it.
//
// validateCanonicalMempoolLiveImage REPEATS the identical call the plan builder
// already makes inside canonicalMempoolPlanSnapshot, on the same snapshot, byte
// count and owner. The repeat is DELIBERATE and contract-ordered (FENCE_AND_MO):
// the first proof runs before the plan and the stable-tip binding exist, and the
// contract requires the full live preflight to run after stableTip is bound to
// C1, under Mempool.mu then PendingOutpointOwner.mu. A future reader must not
// "deduplicate" it: dropping the second call would leave the ordered proof
// unproven and only the earlier, pre-bind one standing.
//
// It is no longer the LAST step. D preparation retires the DA claims of its own
// removals from the SAME private O1 candidate, so the candidate the transition
// will publish is not final until that edit has run. The owner-index rebuild
// happens INSIDE that edit (dropCanonicalDAClaims rebuilds both index halves,
// and only when a claim was actually retired — a transition that removes
// nothing leaves the prepared index standing), and the closing record/claim
// binding preflight below runs unconditionally AFTER the D phase, over whatever
// candidate will be published. That closing binding proof is the one that
// speaks about what gets published. The live-image proof deliberately keeps its
// earlier position: it is a statement about the LIVE owner, which the D edit
// cannot move, and its position is what makes a transition violating both
// invariants at once report the standard/owner error.
func (s *SyncEngine) prepareCanonicalFenceImage(tr *canonicalTransition, plan *canonicalTransitionPlan) (canonicalFenceImage, error) {
	if err := s.recheckCanonicalTransitionFreshness(tr, plan); err != nil {
		return canonicalFenceImage{}, err
	}
	if tr.mempool == nil {
		return canonicalFenceImage{}, nil
	}
	snapshot, err := snapshotMempool(tr.mempool)
	if err != nil {
		return canonicalFenceImage{}, err
	}
	mo, err := prepareCanonicalMempoolPlan(tr.mempool, snapshot, plan.final, plan.finalMTP, len(plan.connect), s.cfg.ChainID)
	if err != nil {
		return canonicalFenceImage{}, err
	}
	mo.pending.stableTip = pendingOutpointTipOf(plan.final)
	if err := validateCanonicalMempoolLiveImage(tr.mempool, mo.snapshot, mo.snapshotUsedBytes, mo.owner); err != nil {
		return canonicalFenceImage{}, terminalCanonicalMempoolError(err)
	}
	da, err := prepareCanonicalDAImage(tr.daRelay, plan.includedDA, mo.chain, &mo)
	if err != nil {
		return canonicalFenceImage{}, err
	}
	if err := validateRestoredClaimBinding(mo.txs, mo.ownerIndex); err != nil {
		return canonicalFenceImage{}, terminalCanonicalMempoolError(err)
	}
	return canonicalFenceImage{mo: &mo, da: da}, nil
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
	// Commit latency now measures the ONE durable index commit (or the
	// no-BlockStore chainstate save) and is recorded on EVERY attempt, refusals
	// included. It no longer covers per-row artifact writes: staging happens
	// earlier, in the recovery-proof step.
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
// the owner transition state, then releases both, then takes DARelayState.mu and
// assignment-publishes the prepared D1. That is the contract's exact order —
// C1, M1/O1, D1 — and no component locks overlap. The PUBLICATION ASSIGNMENTS
// themselves allocate nothing, clone nothing, do no I/O, validate nothing,
// invoke no callback and cannot fail.
//
// D1 is published for EVERY truth NEW, latched or not: TERMINAL_PERSISTENCE(new)
// publishes the identical complete image and then latches. Truth OLD and truth
// UNKNOWN publish no D image at all, so the live retained-DA state stays exactly
// the one the transition read.
//
// The latched arm runs AFTER every assignment and is stores only: the fault and
// the operator record were BUILT BY THE CALLER before the corridor opened, so it
// allocates, formats and validates nothing. It does BLOCK — storeTerminalFault
// takes persistenceFaultMu then s.mu under this transition's admissionMu, which
// the clause allows and the outermost-admission lock order covers. It can
// un-publish nothing.
//
// t.diag is non-nil on every production path: the five batch-creating entries
// (BootstrapCanonicalGenesisIfEmpty, ApplyBlock, SetMempool, DisconnectTip,
// ApplyBlockWithReorg) allocate it before taking mutationMu. The nil check is a
// no-panic guard, not a live case — a nil batch would DROP the record, the
// corridor having no fallback — so TestCanonicalBlockRelayTerminalNew pins it.
//
// A latched outcome keeps admission closed until restart: terminal NEW publishes
// the full image and still latches, terminal OLD and UNKNOWN publish nothing.
// Every open outcome clears the owner transition and reopens admission.
func (t *canonicalTransition) publishCanonicalTransition(plan *canonicalTransitionPlan, image canonicalFenceImage, truth canonicalCommitTruth, fault *storagePersistenceFault, report string) {
	latched := fault != nil
	ownerClosed := false
	if truth == canonicalTruthNew {
		assignCanonicalChainState(t.chainState, plan.final)
		if image.mo != nil {
			t.mempool.publishCanonicalMempoolPlan(*image.mo, !latched)
			ownerClosed = !latched
		}
		image.da.publish()
	}
	if latched {
		t.engine.storeTerminalFault(fault)
		// Into the batch's terminal slot directly: diagnoseTerminal would FORMAT
		// here, and the caller already formatted this record before the corridor.
		if t.diag != nil {
			t.diag.terminal = report
		}
		return
	}
	if !ownerClosed {
		t.owner.endTransitionAborted()
	}
	t.chainState.admissionMu.Unlock()
}

// canonicalLatchReason names the CLASS that latched, from the classifier's own
// (truth, cause) pair and never from error text. An operator reading one stderr
// line must be able to tell a spent prepared index — a local invariant violation
// that says the process reused a prepared commit — from a durable persistence
// failure, because the two point at different things to investigate. The OLD
// default stays deliberately unspecific: the remaining latched-OLD classes are
// terminal-old persistence and an empty-class accounting failure, which carry no
// sentinel to separate them, and naming one of the two would be a guess. The
// verbatim cause follows in the same record either way.
func canonicalLatchReason(truth canonicalCommitTruth, cause error) string {
	switch {
	case truth == canonicalTruthNew:
		return "terminal canonical persistence (new)"
	case truth == canonicalTruthUnknown:
		return "terminal canonical persistence (neither_or_unreadable)"
	case errors.Is(cause, errPreparedIndexSpent):
		return "terminal local invariant (old)"
	default:
		return "terminal canonical transition (old)"
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
// its bytes: the rows are retained healthy noncanonical artifacts, so the
// transition itself never has to carry depth-proportional payload ACROSS the
// commit. Requeue is not free — it materializes each disconnected parse here,
// transiently, one row at a time — but that lives entirely after the transition
// released admission. A row that can no longer be read is skipped with a
// diagnostic: requeue is a downstream best-effort effect and cannot change
// commit truth.
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
// charged descriptors, tip-down — h_max..h_min, which is the Section 11.1
// requeue order and the order a disconnect suffix is walked in. Rows are read
// from the identity itself, so a descriptor can never name a height the sequence
// does not hold.
func canonicalSequenceDescriptors(sequence []string, from, to uint64) ([]canonicalRowDescriptor, error) {
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
	slices.Reverse(rows)
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
