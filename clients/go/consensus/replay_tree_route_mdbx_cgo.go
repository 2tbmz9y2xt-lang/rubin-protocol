//go:build cgo && (darwin || linux) && (amd64 || arm64)

package consensus

import (
	"errors"
	"reflect"
	"syscall"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/mdbx"
)

// The format-3 route of the dormant replay metadata writers (RUBIN_MEMPOOL_POLICY.md Sections 6.4.1.2, 6.4.1.3 and
// 6.4.1.8). No production caller. On a tree store each writer reads the TreeAuthorityV1 envelope; a plan it builds
// itself is one pair-only Batch whose meta key 2 row is the encoding of the planned envelope. The selected-side intent
// branch instead returns the clear planner's result, which on a tree Reader is always its ReadStorageAuthorityV1
// tree-Reader refusal with an empty ReadResource (RUB-1729 owns that branch). replayTreeOperation is the only route
// from such a Batch to Store.UpdateTreeV1.

// replayTreeRefusal is the comparable identity of a direct EngineError with a nil Cause and nil TreeObservation.
type replayTreeRefusal struct {
	class      mdbx.EngineClass
	operation  string
	code       int
	diagnostic string
	reopen     bool
}

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

// replayTreeEncode encodes a planned envelope. Every writer plans a legal tree envelope from a decoded legal one, so
// the only reachable Encode refusal is the metadata size bound: LOCAL_RESOURCE_UNAVAILABLE(storage_capacity).
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

// replayTreeConversion is the whole-target conversion of a PLAN_CHANGE report's REPLAY envelope (GEN 1185-1188, REPLAY
// 4369-4384): PRUNE_GC/RECOVERY_REQUIRED, pending = the target profile, ReplayV1 none, CleanupV1 exactly the two
// target generations as ascending GENERATION spans, and the target lag, source kind and progress none; every other
// envelope field is the read one. It reads no cursor. Consulted is the baseline observation set of the active tip.
func replayTreeConversion(report ReplayRecomputationV1) (mdbx.Batch, error) {
	envelope := report.envelope
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
	return replayRecoveryAuthorityBatch(literal, replayEntryConsulted(a.ActiveGenerationID, report.activeTip)), nil
}
