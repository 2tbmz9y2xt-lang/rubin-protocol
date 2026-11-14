//go:build cgo && (darwin || linux) && (amd64 || arm64)

package consensus

import (
	"bytes"
	"crypto/sha3"
	"encoding/binary"
	"errors"
	"math"
	"reflect"
	"syscall"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/mdbx"
)

// The format-3 route of the dormant replay metadata writers (RUBIN_MEMPOOL_POLICY.md Sections 6.4.1.2, 6.4.1.3 and
// 6.4.1.8). No production caller. On a tree store each writer reads the TreeAuthorityV1 envelope; a plan it builds
// itself is one pair-only Batch whose meta key 2 row is the encoding of the planned envelope. The selected-side intent
// branch instead returns the clear planner's result, which on a tree Reader is always its ReadStorageAuthorityV1
// tree-Reader refusal with an empty ReadResource (RUB-1729 owns that branch). Inside this package replayTreeOperation
// is the only route from such a Batch to Store.UpdateTreeV1. A Batch PlanReplayWholeTargetConversionMDBX returns is
// submitted only that way: the plan callback that called the planner returns replayTreeOperation(Batch), whose
// Mutations and Consulted rows are the pair-only TreeOperationV1 of that same UpdateTreeV1 callback.

// replayTreeRefusal is the comparable identity of a direct EngineError with a nil Cause and nil TreeObservation.
type replayTreeRefusal struct {
	class      mdbx.EngineClass
	operation  string
	code       int
	diagnostic string
	reopen     bool
}

// replayTreeStoreRefusal is Store.Update's refusal of a tree store before its callback.
var replayTreeStoreRefusal = replayTreeRefusal{mdbx.EngineStateMismatch, "update", -30779, "tree store requires typed tree operation", false}

const (
	// replayTreePairBytes (P_PAIR) bounds the step-5 charge of the entry plan: one envelope literal of at most
	// mdbx.MaxMetadataBytes plus four 16-byte or binding target rows, five keys, four Consulted keys and the owned
	// arrays (the fit through the engine is TestReplayTreeEntryAccountFit).
	replayTreePairBytes uint64 = mdbx.MaxMetadataBytes + 4096
	// replayTreeOwnBytes (OWN) is the entry route's evidence charge: LANE_MAX less P_PAIR.
	replayTreeOwnBytes = mdbx.LaneMaxBytes - replayTreePairBytes
)

// OWN fits the legacy grant and covers the 148 minimum share; a violation does not compile.
const (
	_ = mdbx.MaxOperationDataBytes - replayTreeOwnBytes
	_ = replayTreeOwnBytes - replayRecoveryMin148Bytes
)

// replayTreeReaderRefusal is ReadStorageAuthorityV1's tree-Reader refusal; that refusal leaves the Reader active.
var replayTreeReaderRefusal = replayTreeRefusal{mdbx.EngineInvalidInput, "get", int(syscall.EINVAL), "tree Reader requires tree authority accessor", false}

// replayTreeRefused reports whether err itself (never a wrapped or joined error) is an EngineError whose fields all
// equal want, with Cause and TreeObservation nil.
func replayTreeRefused(err error, want replayTreeRefusal) bool {
	var e *mdbx.EngineError
	if !errors.As(err, &e) || e == nil || reflect.TypeOf(err) != reflect.TypeOf(e) || e.Cause != nil || e.TreeObservation != nil {
		return false
	}
	return replayTreeRefusal{e.Class, e.Operation, e.Code, e.Diagnostic, e.ReopenRequired} == want
}

// replayTreeEncode encodes a planned envelope. Every writer plans from a decoded legal envelope, and two Encode refusals
// stay reachable from one: a retained source intent (TreeAuthorityV1.SourceIntent) copied into a planned phase where it
// is illegal, and the metadata size limit, because DecodeTreeAuthorityV1 bounds no persisted slot error below
// MaxMetadataBytes, so a plan that adds descriptors to a decode-legal envelope near that limit (treeEntryBatch's
// GENESIS_REPLAY plan adds ReplayV1) can exceed it. The whole-target conversion replaces ReplayV1 and the progress by
// CleanupV1 and the pending profile and inserts at most the caller's InvalidBranchV1 tuple into an empty slot; a size
// refusal caused by that tuple is structural only, since the caller admits its error as exactly one Section 13 token.
// Every refusal maps to LOCAL_RESOURCE_UNAVAILABLE(storage_capacity).
func replayTreeEncode(envelope mdbx.TreeAuthorityV1) ([]byte, error) {
	encoded, err := envelope.Encode()
	if err != nil {
		return nil, &selectedSideFailure{result: selectedSideCapacity, cause: err}
	}
	return encoded, nil
}

// replayTreeOperation converts a writer's Batch into the pair-only operation (no primitive, proof, header slot or
// entry inventory). A Batch carrying any domain other than Mutations and Consulted is refused before admission.
func replayTreeOperation(b mdbx.Batch) (mdbx.TreeOperationV1, error) {
	if replayTreeNonPair(b) {
		return mdbx.TreeOperationV1{}, &selectedSideFailure{result: selectedSideInvariant, cause: errors.New("replay plan carries a non-pair domain")}
	}
	return mdbx.TreeOperationV1{Pair: mdbx.TreePairV1{Mutations: b.Mutations, Consulted: b.Consulted}}, nil
}

func replayTreeNonPair(b mdbx.Batch) bool {
	return b.Reverse || b.ContextConsulted != nil || len(b.LargeConsulted) != 0 || len(b.ObsoleteDeletes) != 0 || len(b.ObsoleteConsulted) != 0
}

// replayTreeIntent is PlanRecoveryIntentMDBX on a tree Reader. A read error (integrity, non-empty absence or a native
// failure, including inside the absence census) is returned with ReadResource empty; proved exact-empty absence is the
// empty plan; a selected side delegates to the baseline clear planner unchanged.
func replayTreeIntent(reader *mdbx.Reader) (ReplayRecoveryPlanV1, error) {
	envelope, present, err := reader.ReadTreeAuthorityV1()
	if err != nil || !present {
		return ReplayRecoveryPlanV1{}, err
	}
	switch {
	case !replayRecoveryIntentDomain(envelope.Authority):
		return ReplayRecoveryPlanV1{}, nil
	case envelope.Authority.SelectedSide != nil:
		return replayRecoveryIntentSide(reader)
	}
	return replayTreeIntentOnly(envelope)
}

// replayTreeIntentOnly is the one-mutation intent: RECOVERY_REQUIRED with pending = the active profile; the target lag,
// source kind and progress are none; every other envelope field is the read one. Consulted is empty.
func replayTreeIntentOnly(envelope mdbx.TreeAuthorityV1) (ReplayRecoveryPlanV1, error) {
	profile := envelope.Authority.ActiveProfile
	envelope.Authority.Lifecycle, envelope.Authority.PendingTargetProfile = mdbx.StorageLifecycleRecoveryRequiredV1, &profile
	envelope.TargetLagGenerationID, envelope.SourceKind, envelope.Progress = 0, mdbx.TreeSourceNoneV1, mdbx.TreeProgressV1{}
	literal, err := replayTreeEncode(envelope)
	if err != nil {
		return ReplayRecoveryPlanV1{}, err
	}
	return ReplayRecoveryPlanV1{Batch: replayRecoveryAuthorityBatch(literal, nil)}, nil
}

// replayTreeRecompute is RecomputeReplayTargetMDBX after its context and LANE_MAX gates on a tree Reader: a read error
// (integrity, non-empty absence or a native failure) is returned with ReadResource empty; proved exact-empty absence is
// NOT_APPLICABLE; otherwise recompute148 decides for the envelope's authority and the report carries the read envelope.
func (o *ReplayEntryOwnerV1) replayTreeRecompute(reader *mdbx.Reader, limit uint64) (ReplayRecomputationV1, error) {
	envelope, present, err := reader.ReadTreeAuthorityV1()
	switch {
	case err != nil:
		return ReplayRecomputationV1{}, err
	case !present:
		return ReplayRecomputationV1{Report: ReplayRecomputationNotApplicableV1}, nil
	}
	report, err := o.recompute148(reader, envelope.Authority, limit)
	report.envelope = envelope
	return report, err
}

// replayTreeConversion is the PLAN_CHANGE adapter of replayTreeWholeTarget: the conversion of a PLAN_CHANGE report's
// read REPLAY envelope with Consulted for the report's active tip. It adds no slot effect.
func replayTreeConversion(report ReplayRecomputationV1) (mdbx.Batch, error) {
	return replayTreeWholeTarget(report.envelope, report.activeTip)
}

// replayTreeWholeTarget is the common whole-target conversion of a fixed REPLAY target pair (RUBIN_MEMPOOL_POLICY.md
// Section 6.4.1.8 lines 5650-5659, Section 6.4.1.3 lines 1276-1286): PRUNE_GC/RECOVERY_REQUIRED, pending = the target
// profile, ReplayV1 none, CleanupV1 exactly the two target generations as ascending GENERATION spans, and the target
// lag, source kind and progress none; every other envelope field (active pair, next_generation_id, the
// InvalidBranchV1 slot and the retained source intent included) is the given one. It reads no cursor and allocates no
// generation. Consulted is the baseline observation set of activeTip. Precondition: envelope.Authority.Replay is
// non-nil (a REPLAY envelope read from the store); the caller establishes it before calling, and a nil Replay panics.
func replayTreeWholeTarget(envelope mdbx.TreeAuthorityV1, activeTip uint64) (mdbx.Batch, error) {
	a := &envelope.Authority
	target, lag, profile := a.Replay.TargetGenerationID, envelope.TargetLagGenerationID, a.Replay.TargetProfile
	a.Cleanup = &mdbx.CleanupV1{Spans: []mdbx.CleanupSpanV1{
		{Kind: mdbx.CleanupSpanGenerationV1, GenerationID: min(target, lag)},
		{Kind: mdbx.CleanupSpanGenerationV1, GenerationID: max(target, lag)},
	}}
	a.Phase, a.Lifecycle, a.PendingTargetProfile, a.Replay = mdbx.StoragePhasePruneGCV1, mdbx.StorageLifecycleRecoveryRequiredV1, &profile, nil
	envelope.TargetLagGenerationID, envelope.SourceKind, envelope.Progress = 0, mdbx.TreeSourceNoneV1, mdbx.TreeProgressV1{}
	literal, err := replayTreeEncode(envelope)
	if err != nil {
		return mdbx.Batch{}, err
	}
	return replayRecoveryAuthorityBatch(literal, replayEntryConsulted(a.ActiveGenerationID, activeTip)), nil
}

// ReplayTargetConversionCauseV1 is the qualified cause of a whole-target conversion. Exactly the three named values
// are admitted by PlanReplayWholeTargetConversionMDBX; every other value is local misuse.
type ReplayTargetConversionCauseV1 uint8

const (
	// ReplayTargetConversionTargetLocalV1 is a qualified target-local finding (Section 6.4.1.8 lines 6344-6384). It keeps
	// an empty slot empty and clears ReplayV1, so the caller passes it only with consistent authority and never while an
	// invalidity hand-off of the same replay is pending; the planner cannot detect a pending hand-off.
	ReplayTargetConversionTargetLocalV1 ReplayTargetConversionCauseV1 = 1
	// ReplayTargetConversionInvalidityV1 is a qualified replay invalidity after its hand-off (lines 6386-6408).
	ReplayTargetConversionInvalidityV1 ReplayTargetConversionCauseV1 = 2
	// ReplayTargetConversionRecoveryCoreV1 is a qualified recovery-core disposition (lines 6458-6496).
	ReplayTargetConversionRecoveryCoreV1 ReplayTargetConversionCauseV1 = 3
)

// ReplayTargetConversionInputV1 is the caller's qualified conversion input. Reader is the Reader the UpdateTreeV1
// callback received, in which the caller qualified Envelope, the complete envelope snapshot it qualified (fixed source, target
// IDs, RecoveryTargetV1, progress, retained intent and slot). ActiveTip is the active tip that qualification
// established, at most 4294967295; it selects only the Batch's Consulted rows: the canonical-v1 height keys of the
// active generation at heights 0 and 1, then tip and tip+1 when tip > 1, or 2 when tip = 1. The planner checks
// ActiveTip only against that bound, never against the active generation's height index on the Reader: that it is the
// established active tip is the caller's qualification. Invalidity is nil for TARGET_LOCAL and
// RECOVERY_CORE and, for REPLAY_INVALIDITY, the first-invalid tuple whose error the caller admitted as exactly one
// Section 13 token. The caller invokes REPLAY_INVALIDITY only after its hand-off promotion is NEW, and TARGET_LOCAL only
// with consistent authority and never while an invalidity hand-off of the same replay is pending. For RECOVERY_CORE a
// P NEW is no input: the caller holds the qualified durable proof with its independently retained source before the
// call and the planner reads neither. The input is a process precondition of the caller, not an authentication
// certificate: the caller owns source qualification, role/ownership controls, cause admission and the view guard held
// until UpdateTreeV1 returns. Source qualification includes two checks the envelope decoder does not make (it checks a
// GENESIS_REPLAY cursor only against the target tip height and the genesis/tip hashes): the cursor hash lies on the
// target header path, and the target tuple is self-consistent. The planner does not make them either. For an IMAGE
// source, the legal zero ReplayCursorV1 is not a GENESIS_REPLAY cursor and receives no cursor check; the complete
// source-qualified checkpoint or progress is established by the IMAGE caller, never inferred from the presence of
// opaque progress or retained-intent bytes, and an absent progress producer supplies no admission. For
// REPLAY_INVALIDITY, FirstInvalidHeight and FirstInvalidBlockHash on the target path, with the error token, are the
// caller's qualified first-invalid finding of the replay step, admitted through the caller's hand-off gate and
// writer-side token check; the planner checks that tuple only for its C10 shape (non-nil, nonempty error, height at most
// 4294967295), never its path membership or token. The caller never calls the planner after a failed qualification or a
// stale view guard.
type ReplayTargetConversionInputV1 struct {
	Reader     *mdbx.Reader
	Envelope   mdbx.TreeAuthorityV1
	ActiveTip  uint64
	Cause      ReplayTargetConversionCauseV1
	Invalidity *mdbx.InvalidBranchV1
}

// PlanReplayWholeTargetConversionMDBX plans the common whole-target conversion (RUBIN_MEMPOOL_POLICY.md Section 6.4.1.8
// lines 5644-5659) of the fixed REPLAY target pair inside the caller's UpdateTreeV1 plan callback on reader. The caller
// passes as reader, and as input.Reader, the Reader that callback received: the planner only compares the two and
// cannot detect another Reader, while UpdateTreeV1 checks only the planned keys and Consulted rows against its own
// snapshot. The caller submits the returned Batch only as replayTreeOperation(Batch) from that same callback. Because
// replayTreeOperation is unexported and is the only route from that Batch to UpdateTreeV1, the caller is code in
// package consensus; code in another package cannot follow this route and never submits the Batch through a
// TreeOperationV1 it builds itself. Cursor
// hash/path, target self-consistency and ActiveTip as the established active tip are caller-qualified
// (ReplayTargetConversionInputV1); the planner does not check them (ActiveTip only against 4294967295, never against
// the Reader's active height index) and is never called after a failed qualification or a stale view guard. IMAGE keeps its own legal zero
// ReplayCursorV1 and caller-qualified checkpoint, which the planner neither checks nor infers from payload presence. A
// REPLAY_INVALIDITY tuple is the caller's qualified first-invalid finding; the planner checks only its shape. In order:
// a nil reader is TERMINAL_LOCAL_INVARIANT(evidence); the envelope is reread and a read or decode error is returned
// unchanged; proved absence, an envelope outside REPLAY/RECOVERY_REQUIRED, input.Reader other than reader, or a reread
// envelope whose canonical encoding differs from that of input.Envelope (or an input.Envelope Encode refuses) is
// STALE_LOCAL_PLAN; a cause outside the three values, an Invalidity of the wrong nilness, an empty error, or an
// ActiveTip or first-invalid height above 4294967295 is TERMINAL_LOCAL_INVARIANT(evidence); a planned envelope Encode
// refuses is LOCAL_RESOURCE_UNAVAILABLE(storage_capacity), structural only under the caller's one-token precondition.
// Otherwise the result is one pair-only Batch of one meta key 2 mutation whose literal is the reread envelope with
// exactly these changes (Section 6.4.1.8 lines 5650-5659, Section 6.4.1.3 lines 1276-1286): phase PRUNE_GC, lifecycle
// RECOVERY_REQUIRED, PendingTargetProfile = ReplayV1.TargetProfile, ReplayV1 none, CleanupV1 exactly two GENERATION
// spans of the target CURRENT and target LAG IDs in ascending ID order, TargetLagGenerationID 0, SourceKind none and
// Progress empty. Every other envelope and authority field is unchanged, including the active CURRENT/LAG IDs, ActiveProfile, B/U, NextGenerationID,
// SelectedSide, DetachedSuffix and the retained SourceIntent; no generation is allocated. The InvalidBranchV1 slot is
// kept for TARGET_LOCAL and RECOVERY_CORE; for REPLAY_INVALIDITY the caller's tuple is written only into an empty slot
// and an existing slot is kept, identical or not (first wins, no refusal). The Batch's Consulted rows are exactly the
// active-tip rows stated on ReplayTargetConversionInputV1.ActiveTip. The envelope is encoded before return, so the Batch literal owns its bytes and a later change
// of the caller's tuple does not reach it. It allocates no generation, writes nothing, acquires and releases no guard
// and publishes nothing; every failure returns an empty Batch.
func PlanReplayWholeTargetConversionMDBX(reader *mdbx.Reader, input ReplayTargetConversionInputV1) (mdbx.Batch, error) {
	if reader == nil {
		return mdbx.Batch{}, replayTreeMisuse("whole-target conversion without a Reader")
	}
	envelope, present, err := reader.ReadTreeAuthorityV1()
	switch {
	case err != nil:
		return mdbx.Batch{}, err
	case !present || !replayTreeQualified(reader, envelope, input):
		return mdbx.Batch{}, &selectedSideFailure{result: replayEntryStale, cause: errors.New("whole-target conversion input is not the current envelope")}
	case !replayTreeConversionShape(input):
		return mdbx.Batch{}, replayTreeMisuse("whole-target conversion input outside its cause domain")
	}
	replayTreeSlotEffect(&envelope.Authority, input)
	return replayTreeWholeTarget(envelope, input.ActiveTip)
}

func replayTreeMisuse(message string) error {
	return &selectedSideFailure{result: selectedSideInvariant, cause: errors.New(message)}
}

// replayTreeQualified reports the R2/R6 binding: the reread envelope is the fixed REPLAY/RECOVERY_REQUIRED target, the
// input names this Reader, and both envelopes have the same canonical encoding (value equality; an input envelope
// Encode refuses is a mismatch). That reader is the UpdateTreeV1 callback's own only by the caller's precondition.
func replayTreeQualified(reader *mdbx.Reader, envelope mdbx.TreeAuthorityV1, input ReplayTargetConversionInputV1) bool {
	a := envelope.Authority
	if a.Phase != mdbx.StoragePhaseReplayV1 || a.Lifecycle != mdbx.StorageLifecycleRecoveryRequiredV1 || a.Replay == nil || input.Reader != reader {
		return false
	}
	current, err := envelope.Encode()
	if err != nil {
		return false
	}
	qualified, err := input.Envelope.Encode()
	return err == nil && bytes.Equal(current, qualified)
}

// replayTreeConversionShape reports the closed C10 input domain.
func replayTreeConversionShape(input ReplayTargetConversionInputV1) bool {
	if input.ActiveTip > math.MaxUint32 {
		return false
	}
	switch input.Cause {
	case ReplayTargetConversionTargetLocalV1, ReplayTargetConversionRecoveryCoreV1:
		return input.Invalidity == nil
	case ReplayTargetConversionInvalidityV1:
		return input.Invalidity != nil && len(input.Invalidity.ExactConsensusError) != 0 && input.Invalidity.FirstInvalidHeight <= math.MaxUint32
	}
	return false
}

// replayTreeSlotEffect is the first-wins slot effect: only REPLAY_INVALIDITY writes, and only into an empty slot. The
// written tuple shares the caller's error bytes until replayTreeWholeTarget encodes it within the same planner call.
func replayTreeSlotEffect(a *mdbx.StorageAuthorityV1, input ReplayTargetConversionInputV1) {
	if input.Cause != ReplayTargetConversionInvalidityV1 || a.ExcludedInvalidBranch != nil {
		return
	}
	slot := *input.Invalidity
	a.ExcludedInvalidBranch = &slot
}

// replayTreeSnapshotMismatch is the Diagnostic of UpdateTreeV1's write snapshot refusal (treeSnapshotMismatchV1).
const replayTreeSnapshotMismatch = "OLD/write snapshot mismatch"

// ProjectReplayWholeTargetConversionMDBX projects one UpdateTreeV1 attempt of a PlanReplayWholeTargetConversionMDBX
// Batch as its CLEANUP-origin outcome (RUBIN_MEMPOOL_POLICY.md Section 6.4.1.9 lines 7479-7499 and 7593-7598). Truth,
// Stage and Err are kept exactly, wrappers and causes included; Decision is empty and Replay nil. A possibly crossed
// commit with a nil Err is the normal outcome (CanonicalTruth from its truth, empty Result); with an Err it is
// TERMINAL_PERSISTENCE(new|old|neither_or_unreadable) with CanonicalTruth NEW, OLD or UNKNOWN. Any other nil Err is OLD
// with an empty Result. WRITE_STARTED_DEFINITELY_PRECOMMIT keeps an integrity or invariant cause, else
// LOCAL_PERSISTENCE_ERROR(precommit). An Err at OLD/PREWRITE that is exactly the operation reservation owner's capacity
// refusal (mdbx.IsOperationReservationCapacity), which any refused reservation charge returns, such as the engine's
// step-5 Pair charge, whether the account's ceiling, the owner's limit or the owner's aggregate refused it, is
// LOCAL_RESOURCE_UNAVAILABLE(storage_capacity). Otherwise the merged
// cause walk classifies each direct cause of Err by native storage class with no read-artifact override; a direct
// EngineStateMismatch cause is STALE_LOCAL_PLAN when every such cause is the write snapshot mismatch, else
// TERMINAL_LOCAL_INVARIANT(evidence). It never returns the detecting step's result. The caller retains the raw
// UpdateTreeV1 index and the native owner disposition, applies the terminal admission and latch gates in its own owner
// to this projected outcome (the projection applies neither), and keeps the earlier detecting result independently. A
// PREWRITE refusal keeps its raw Truth, including the retained terminal truth (OLD, NEW or UNKNOWN) with which
// UpdateTreeV1 refuses on a Store already latched terminal, and reports CanonicalTruth OLD, since this attempt wrote
// nothing (Section 6.4.1.9 line 7596); its Result follows the rules above. For RECOVERY_CORE (Section 6.4.1.8
// lines 6486-6489) a STALE_LOCAL_PLAN, definite abort or precommit OLD outcome preserves the complete replay image and
// durable proof for only the caller's freshly guarded disposition retry, NEW proves this one conversion, and UNKNOWN
// keeps the proof and the existing gates.
func ProjectReplayWholeTargetConversionMDBX(truth mdbx.CommitTruth, stage mdbx.UpdateStage, err error) ReplayEntryOutcomeV1 {
	out := ReplayEntryOutcomeV1{CanonicalTruth: "OLD", Truth: truth, Stage: stage, Err: err}
	switch {
	case stage == mdbx.UpdateStageCommitMayHaveCrossed:
		return replayEntryCrossed(out, &replayEntryCall{})
	case err == nil:
		return out
	case stage == mdbx.UpdateStageWriteStartedDefinitelyPrecommit:
		out.Result = replayEntryPrecommit(replayEntryCauses(err, &replayEntryCall{}))
		return out
	case replayTreeStepCapacity(out):
		out.Result = selectedSideCapacity
		return out
	}
	out.Result = replayEntryCauses(err, &replayEntryCall{planned: replayTreeSnapshotOnly(err)})
	return out
}

// replayTreeSnapshotOnly reports whether every direct EngineStateMismatch cause of err (the causes replayEntryPart
// classifies; a wrapped one is not inspected) is the write snapshot mismatch.
func replayTreeSnapshotOnly(err error) bool {
	for _, part := range genesisMDBXCauses(err) {
		var e *mdbx.EngineError
		if errors.As(part, &e) && reflect.TypeOf(part) == reflect.TypeOf(e) && e != nil && e.Class == mdbx.EngineStateMismatch && e.Diagnostic != replayTreeSnapshotMismatch {
			return false
		}
	}
	return true
}

// replayTreeStoreRefused reports the F1 discriminator: Store.Update's exact tree-store refusal at OLD/PREWRITE.
func replayTreeStoreRefused(out ReplayEntryOutcomeV1) bool {
	return out.Truth == mdbx.CommitTruthOld && out.Stage == mdbx.UpdateStagePrewrite && replayTreeRefused(out.Err, replayTreeStoreRefusal)
}

// treeEnter is the format-3 route of EnterReplayTargetMDBX after the baseline frame returned the tree-store refusal:
// one LaneOperation whose OWN evidence charge wraps one UpdateTreeV1 with lane OWN; on the owner's exact capacity
// refusal of OWN, one UpdateTreeV1 on the same account runs the denied gates. raw is set for any other charge error,
// which the caller returns with an empty CanonicalTruth. The caller runs the release and the projection.
func (c *replayEntryCall) treeEnter(store *mdbx.Store) (ReplayEntryOutcomeV1, bool) {
	out := ReplayEntryOutcomeV1{Truth: mdbx.CommitTruthOld, Stage: mdbx.UpdateStagePrewrite}
	c.lane = replayTreeOwnBytes
	err := c.reservations.WithOperation(mdbx.LaneOperation, func(account *mdbx.OperationAccount) error {
		c.account = account
		ran := false
		err := account.WithReservation(replayTreeOwnBytes, func() error {
			ran, c.denied = true, false
			out.Truth, out.Stage, _, out.Err = store.UpdateTreeV1(account, c.treePlan)
			return nil
		})
		if ran || err.Error() != selectedSideCapacityText {
			return err
		}
		c.denied = true
		out.Truth, out.Stage, _, out.Err = store.UpdateTreeV1(account, c.treePlan)
		return nil
	})
	if err != nil {
		out.Err = err
		return out, true
	}
	return out, false
}

// replayTreeCapacity classifies the format-3 route's engine step-5 Pair copy refused by the owner aggregate: an
// UpdateTreeV1 Err that is exactly the owner's capacity refusal at OLD/PREWRITE is
// LOCAL_RESOURCE_UNAVAILABLE(storage_capacity) (E9(b)); Err is kept. A format-2 outcome (no route account) is unchanged.
func replayTreeCapacity(out ReplayEntryOutcomeV1, call *replayEntryCall) ReplayEntryOutcomeV1 {
	if call.account != nil && replayTreeStepCapacity(out) {
		out.Result = selectedSideCapacity
	}
	return out
}

func replayTreeStepCapacity(out ReplayEntryOutcomeV1) bool {
	return out.Truth == mdbx.CommitTruthOld && out.Stage == mdbx.UpdateStagePrewrite && mdbx.IsOperationReservationCapacity(out.Err)
}

// treePlan is plan on a tree Reader converted to the pair-only operation.
func (c *replayEntryCall) treePlan(reader *mdbx.Reader) (mdbx.TreeOperationV1, error) {
	batch, err := c.treeBatch(reader)
	if err != nil {
		return mdbx.TreeOperationV1{}, err
	}
	return replayTreeOperation(batch)
}

// treeBatch is plan's sequence over the envelope: proved exact-empty absence is not eligible and writes nothing; a
// persisted REPLAY resumes; then the gates, the denied stop and the 148 qualification with sequence and plan.
func (c *replayEntryCall) treeBatch(reader *mdbx.Reader) (mdbx.Batch, error) {
	envelope, present, err := reader.ReadTreeAuthorityV1()
	switch {
	case err != nil:
		return mdbx.Batch{}, err
	case !present:
		return c.decide("", replayEntryNotEligible)
	case envelope.Authority.Phase == mdbx.StoragePhaseReplayV1:
		resumed := *envelope.Authority.Replay
		c.replay = &resumed
		return c.decide("", replayEntryResume)
	}
	source, decided, err := c.gates(reader, envelope.Authority)
	if err != nil || decided {
		return mdbx.Batch{}, err
	}
	if c.denied {
		return c.decide(selectedSideCapacity, "")
	}
	return c.treeQualified(reader, envelope, source)
}

// treeQualified is Q5, then sequence availability for two allocations, then the E plan.
func (c *replayEntryCall) treeQualified(reader *mdbx.Reader, envelope mdbx.TreeAuthorityV1, source byte) (mdbx.Batch, error) {
	target, tipHeight, err := c.qualify148(reader, envelope.Authority)
	if err != nil {
		return mdbx.Batch{}, err
	}
	if envelope.Authority.NextGenerationID > math.MaxUint64-2 {
		return c.decide(selectedSideInvariant, "")
	}
	return c.treeEntryBatch(reader, envelope, source, target, tipHeight)
}

// treeEntryBatch is the format-3 REPLAY_PROGRESS plan (GEN 1100-1112, REPLAY 4502-4521): target CURRENT n and target
// LAG n+1 from n = next_generation_id, next n+2, GENESIS_REPLAY with the cursor PRE_GENESIS, the envelope and both
// targets' zero counter and empty PRE_GENESIS FULL_HISTORY binding rows.
func (c *replayEntryCall) treeEntryBatch(reader *mdbx.Reader, envelope mdbx.TreeAuthorityV1, source byte, target mdbx.RecoveryTargetV1, tipHeight uint64) (mdbx.Batch, error) {
	a := &envelope.Authority
	root, err := c.treeTargetRoot(reader, a.ActiveGenerationID, target)
	if err != nil {
		return mdbx.Batch{}, err
	}
	profile := a.ActiveProfile
	if source == 'd' {
		profile = *a.PendingTargetProfile
	}
	n, active := a.NextGenerationID, a.ActiveGenerationID
	replay := mdbx.ReplayV1{TargetProfile: profile, TargetGenerationID: n, Target: target, Cursor: mdbx.ReplayCursorV1{Kind: mdbx.ReplayCursorPreGenesisV1}}
	a.Phase, a.Lifecycle, a.Replay, a.NextGenerationID, a.PendingTargetProfile = mdbx.StoragePhaseReplayV1, mdbx.StorageLifecycleRecoveryRequiredV1, &replay, n+2, nil
	envelope.TargetLagGenerationID, envelope.SourceKind, envelope.Progress = n+1, mdbx.TreeSourceGenesisReplayV1, mdbx.TreeProgressV1{}
	literal, err := replayTreeEncode(envelope)
	if err != nil {
		return mdbx.Batch{}, err
	}
	c.replay, c.planned, c.step = &replay, true, ""
	return mdbx.Batch{Mutations: replayTreeEntryRows(literal, root, n), Consulted: replayEntryConsulted(active, tipHeight)}, nil
}

// replayTreeEntryRows is the envelope row, then both targets' counter rows, then their binding rows ((rank, key) order).
func replayTreeEntryRows(literal, root []byte, n uint64) []mdbx.Mutation {
	meta := mdbx.TreeSchemaV1DBIs()[0]
	rows := []mdbx.Mutation{{DBI: meta, Key: []byte{0x02}, BeforePresent: true, AfterKind: mdbx.AfterLiteral, Literal: literal}}
	for _, tag := range []byte{0x10, 0x11} {
		value := root
		if tag == 0x10 {
			value = mdbx.LogicalCounterValue(0, 0)
		}
		for _, g := range []uint64{n, n + 1} {
			rows = append(rows, mdbx.Mutation{DBI: meta, Key: binary.BigEndian.AppendUint64([]byte{tag}, g), AfterKind: mdbx.AfterLiteral, Literal: value})
		}
	}
	return rows
}

// treeTargetRoot reads the active CURRENT binding for its DatabaseID and encodes the targets' empty binding (AUTH
// 1034-1062). A transient read failure carries the canonical-artifact read site; absence is integrity.
func (c *replayEntryCall) treeTargetRoot(reader *mdbx.Reader, active uint64, target mdbx.RecoveryTargetV1) ([]byte, error) {
	c.step = selectedSideCanonical
	binding, present, err := reader.ReadTreeRootBindingV1(active)
	if err != nil {
		return nil, err
	}
	c.step = ""
	if !present {
		return nil, &selectedSideFailure{result: selectedSideIntegrity, cause: errors.New("active CURRENT root binding absent")}
	}
	root := mdbx.RootBindingV1{
		DatabaseID: binding.DatabaseID, CommitmentVersion: 1, ChainID: target.ChainID, GenesisHash: target.GenesisHash,
		Endpoint: mdbx.TreeEndpointV1{Kind: mdbx.TreeEndpointPreGenesisV1}, RootDigest: sha3.Sum256([]byte(canonicalUTXOEmptyDomain)),
		Top: mdbx.TreeTopV1{Kind: mdbx.TreeTopEmptyV1}, Assurance: mdbx.TreeAssuranceV1{Kind: mdbx.TreeAssuranceFullHistoryV1},
	}
	encoded, err := root.Encode()
	if err != nil {
		return nil, &selectedSideFailure{result: selectedSideInvariant, cause: err}
	}
	return encoded, nil
}

// replayTreeDirectPlan is replayRecoveryDirect over Q5, sequence and the E plan with lane = limit, after directEntryGates'
// format-3 gates (minimum share M148); a decided outcome becomes its refusal.
func replayTreeDirectPlan(call *replayEntryCall, reader *mdbx.Reader, envelope mdbx.TreeAuthorityV1) (ReplayRecoveryPlanV1, error) {
	batch, err := call.treeQualified(reader, envelope, 'b')
	switch {
	case errors.Is(err, call.sentinel):
		return ReplayRecoveryPlanV1{}, replayRecoveryRefusal(call.result, "direct replay entry refused")
	case err != nil:
		return ReplayRecoveryPlanV1{ReadResource: call.step}, err
	}
	return ReplayRecoveryPlanV1{Batch: batch}, nil
}
