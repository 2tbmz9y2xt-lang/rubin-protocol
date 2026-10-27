//go:build cgo && (darwin || linux) && (amd64 || arm64)

package consensus

import (
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
	switch {
	case err != nil:
		return nil, err
	case !present:
		return nil, &selectedSideFailure{result: selectedSideIntegrity, cause: errors.New("active CURRENT root binding absent")}
	}
	c.step = ""
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

// replayTreeDirect is PlanDirectReplayEntryMDBX on a tree Reader after its context and LANE_MAX gates: a read error is
// returned with ReadResource empty; proved exact-empty absence and any domain other than NONE/STABLE with no selected
// side is no plan; the minimum share is M148 (M); then the identity page and, for an H>0 identity, Q5, sequence and
// the E plan with lane = limit.
func (o *ReplayEntryOwnerV1) replayTreeDirect(reader *mdbx.Reader, limit uint64) (ReplayRecoveryPlanV1, func(), error) {
	envelope, present, err := reader.ReadTreeAuthorityV1()
	a := envelope.Authority
	switch {
	case err != nil || !present:
		return ReplayRecoveryPlanV1{}, nil, err
	case !replayTreeDirectDomain(a):
		return ReplayRecoveryPlanV1{}, nil, nil
	case limit < replayRecoveryMin148Bytes:
		return ReplayRecoveryPlanV1{}, nil, replayRecoveryRefusal(selectedSideCapacity, "replay entry share below the minimum")
	}
	identity, site, err := replayEntryIdentity(reader, a.ActiveGenerationID)
	if err != nil || identity != 2 {
		return ReplayRecoveryPlanV1{ReadResource: site}, nil, err
	}
	call := &replayEntryCall{owner: o, sentinel: errors.New("direct replay entry decision"), lane: limit}
	plan, err := replayTreeDirectPlan(call, reader, envelope)
	return plan, call.release, err
}

// replayTreeDirectDomain is NONE/STABLE with no selected side.
func replayTreeDirectDomain(a mdbx.StorageAuthorityV1) bool {
	return a.Phase == mdbx.StoragePhaseNoneV1 && a.Lifecycle == mdbx.StorageLifecycleStableV1 && a.SelectedSide == nil
}

// replayTreeDirectPlan is replayRecoveryDirect over Q5, sequence and the E plan; a decided outcome becomes its refusal.
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
