//go:build rubin_mdbx_fixture && cgo && (darwin || linux) && (amd64 || arm64)

package consensus

import (
	"errors"
	"fmt"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/mdbx"
)

// recoveryUpdateTuple is the raw Store.Update tuple of one owned callback.
type recoveryUpdateTuple struct {
	truth mdbx.CommitTruth
	stage mdbx.UpdateStage
	err   error
}

func recoveryArmed(t *testing.T, w *replayWorld, scenario mdbx.SelectedDamageScenario, rank uint8, key []byte, callback func(*mdbx.Reader) (mdbx.Batch, error)) (recoveryUpdateTuple, mdbx.SelectedDamageEvidence) {
	t.Helper()
	var out recoveryUpdateTuple
	evidence, err := mdbx.FixtureSelectedDamage(w.store, w.owner, scenario, rank, key, func() { out.truth, out.stage, out.err = w.store.Update(callback) })
	logicalMDBXAssert(t, err == nil, "fixture %d: %v", scenario, err)
	return out, evidence
}

// R62: a transient read of a target-only header is the raw EngineIO error with ReadResource recovery_artifact.
func TestReplayRecoveryFixtureTargetHeaderEIO(t *testing.T) {
	w, tg := recoveryWorld(t, nil)
	view := recoveryEmpty()
	var rep ReplayRecomputationV1
	var err error
	_, _ = recoveryArmed(t, w, mdbx.SelectedDamageGetEIO, 3, tg.hashes[5][:], func(r *mdbx.Reader) (mdbx.Batch, error) {
		rep, err = NewReplayEntryOwnerV1(view, w.genesis).RecomputeReplayTargetMDBX(r, mdbx.MaxOperationDataBytes)
		return mdbx.Batch{}, errRecoverySentinel
	})
	replayEngineClass(t, err, mdbx.EngineIO, "R62")
	logicalMDBXAssert(t, rep.ReadResource == replayEntryRecovery && recoveryClass(err, rep.ReadResource) == replayEntryRecovery && rep.Release == nil && len(view.versions) == 0, "R62: %+v", rep)
}

// result_boundary (every walk and target-stream read is recovery_artifact): a transient read of the active canonical
// row of a listed unsupplied tip shared with the target index, and a width-defective active row, each return the raw
// Reader error with ReadResource recovery_artifact, no report, no release and no ProtectV1.
func TestReplayRecoveryFixtureActiveReads(t *testing.T) {
	w, tg := recoveryWorld(t, nil)
	view := recoveryTips([][32]byte{tg.hashes[2]}, nil)
	var rep ReplayRecomputationV1
	var err error
	_, _ = recoveryArmed(t, w, mdbx.SelectedDamageGetEIO, 2, logicalMDBXMust(mdbx.HeightKey(1, 2)), func(r *mdbx.Reader) (mdbx.Batch, error) {
		rep, err = NewReplayEntryOwnerV1(view, w.genesis).RecomputeReplayTargetMDBX(r, mdbx.MaxOperationDataBytes)
		return mdbx.Batch{}, errRecoverySentinel
	})
	replayEngineClass(t, err, mdbx.EngineIO, "shared tip Get")
	logicalMDBXAssert(t, rep.Report == 0 && rep.Release == nil && rep.ReadResource == replayEntryRecovery && recoveryClass(err, rep.ReadResource) == replayEntryRecovery && len(view.versions) == 0,
		"shared tip Get: %+v", rep)
	w, _ = recoveryWorld(t, nil)
	logicalMDBXAssert(t, mdbx.FixtureSeedRawRow(w.store, 2, logicalMDBXMust(mdbx.HeightKey(1, 2)), make([]byte, 103)) == nil, "seed")
	view = recoveryEmpty()
	rep, _, err, uerr := w.recompute(view, mdbx.MaxOperationDataBytes, false)
	replayEngineClass(t, err, mdbx.EngineIntegrity, "active width")
	logicalMDBXAssert(t, rep.Report == 0 && rep.Release == nil && rep.ReadResource == replayEntryRecovery && recoveryClass(err, rep.ReadResource) == selectedSideIntegrity && len(view.versions) == 0,
		"active width: %+v", rep)
	replayConsumed(t, w.store, uerr, "active width")
}

// R56: a target index value of width 103 is the Reader's integrity error, never TARGET_LOCAL; the Store is consumed.
func TestReplayRecoveryFixtureTargetWidth(t *testing.T) {
	w, _ := recoveryWorld(t, nil)
	logicalMDBXAssert(t, mdbx.FixtureSeedRawRow(w.store, 2, logicalMDBXMust(mdbx.HeightKey(2, 4)), make([]byte, 103)) == nil, "R56 seed")
	view := recoveryEmpty()
	rep, _, err, uerr := w.recompute(view, mdbx.MaxOperationDataBytes, false)
	replayEngineClass(t, err, mdbx.EngineIntegrity, "R56")
	logicalMDBXAssert(t, rep.Report == 0 && rep.ReadResource == replayEntryRecovery && recoveryClass(err, rep.ReadResource) == selectedSideIntegrity && len(view.versions) == 0, "R56: %+v", rep)
	replayConsumed(t, w.store, uerr, "R56")
}

// R55: a RecoveryTargetV1 ChainID or GenesisHash other than the context's is the decided TERMINAL_STORE_INTEGRITY(canonical)
// with zero InventoryV1 calls and no index read: a width-defective target row is never reached and the Store stays usable.
func TestReplayRecoveryFixtureIdentityBeforeIndex(t *testing.T) {
	for _, c := range []struct {
		label string
		edit  func(*mdbx.RecoveryTargetV1)
	}{{"ChainID", func(r *mdbx.RecoveryTargetV1) { r.ChainID[0] ^= 1 }}, {"GenesisHash", func(r *mdbx.RecoveryTargetV1) { r.GenesisHash[0] ^= 1 }}} {
		w, _ := recoveryWorld(t, nil)
		w.setAuthority(func(a *mdbx.StorageAuthorityV1) { c.edit(&a.Replay.Target) })
		logicalMDBXAssert(t, mdbx.FixtureSeedRawRow(w.store, 2, logicalMDBXMust(mdbx.HeightKey(2, 4)), make([]byte, 103)) == nil, "R55 seed")
		view := recoveryEmpty()
		rep, _, err, uerr := w.recompute(view, mdbx.MaxOperationDataBytes, false)
		var decided *selectedSideFailure
		logicalMDBXAssert(t, errors.As(err, &decided) && decided.result == selectedSideIntegrity && rep.ReadResource == "" && rep.Report == 0 && view.calls == 0 && len(view.versions) == 0,
			"R55 %s: %+v %v", c.label, rep, err)
		logicalMDBXAssert(t, errors.Is(uerr, errRecoverySentinel), "R55 %s: the Update outcome %v", c.label, uerr)
		ran := false
		_, _, _ = w.store.Update(func(*mdbx.Reader) (mdbx.Batch, error) { ran = true; return mdbx.Batch{}, errRecoverySentinel })
		logicalMDBXAssert(t, ran, "R55 %s: Store not usable", c.label)
	}
}

// R44, R37: a width-defective g0 identity row after the capacity check is the Reader's integrity error with
// canonical_artifact_read; below the minimum share it is never read.
func TestReplayRecoveryFixtureIdentityWidth(t *testing.T) {
	for _, c := range []struct {
		limit  uint64
		result string
		read   string
	}{{mdbx.MaxOperationDataBytes, selectedSideIntegrity, selectedSideCanonical}, {replayRecoveryM - 1, selectedSideCapacity, ""}} {
		w := newReplayWorld(t, 5)
		logicalMDBXAssert(t, mdbx.FixtureSeedRawRow(w.store, 2, logicalMDBXMust(mdbx.HeightKey(1, 0)), make([]byte, 103)) == nil, "seed")
		view := recoveryEmpty()
		plan, release, err := recoveryDirect(w, view, c.limit, false)
		logicalMDBXAssert(t, err != nil && plan.ReadResource == c.read && recoveryClass(err, plan.ReadResource) == c.result && release == nil && view.calls == 0 && len(view.versions) == 0, "R44/R37 %d: %+v %v", c.limit, plan, err)
		if c.read == "" {
			ran := false
			_, _, _ = w.store.Update(func(*mdbx.Reader) (mdbx.Batch, error) { ran = true; return mdbx.Batch{}, errRecoverySentinel })
			logicalMDBXAssert(t, ran, "R37: Store not usable")
		}
	}
	logicalMDBXAssert(t, recoveryClass(&mdbx.EngineError{Class: mdbx.EngineIO}, selectedSideCanonical) == selectedSideCanonical, "R44 EngineIO class")
}

// R41b: a D2 width defect of an active canonical row above height 0 is the Reader's integrity error returned before
// the step is cleared, so it carries recovery_artifact (RE L613-616, L657-660); a defect at height 0 is R44's.
func TestReplayRecoveryFixtureDirectWalkWidth(t *testing.T) {
	w := newReplayWorld(t, 5)
	logicalMDBXAssert(t, mdbx.FixtureSeedRawRow(w.store, 2, logicalMDBXMust(mdbx.HeightKey(1, 3)), make([]byte, 103)) == nil, "seed")
	view := recoveryEmpty()
	plan, release, err := recoveryDirect(w, view, mdbx.MaxOperationDataBytes, false)
	replayEngineClass(t, err, mdbx.EngineIntegrity, "R41b D2")
	logicalMDBXAssert(t, plan.ReadResource == replayEntryRecovery && recoveryClass(err, plan.ReadResource) == selectedSideIntegrity && release == nil && len(view.versions) == 0 && len(plan.Batch.Mutations) == 0, "R41b D2: %+v %v", plan, err)
}

// recoveryCrossed asserts H23-H25 for one world builder and plan callback: the raw tuple with its *mdbx.CommitError and
// the persisted image after reopen, as TestReplayEntryFixtureCrossed asserts them for the entry.
func recoveryCrossed(t *testing.T, label string, build func(*testing.T) (*replayWorld, func(*mdbx.Reader) (mdbx.Batch, error)), scenarios []mdbx.SelectedDamageScenario) {
	for _, scenario := range scenarios {
		control, plan := build(t)
		_, _, err := control.store.Update(plan)
		logicalMDBXAssert(t, err == nil, "%s control commit: %v", label, err)
		post := control.image()
		w, plan := build(t)
		pre := w.image()
		out, evidence := recoveryArmed(t, w, scenario, 0, []byte{2}, plan)
		truth := map[mdbx.SelectedDamageScenario]mdbx.CommitTruth{mdbx.SelectedDamageCommitOld: mdbx.CommitTruthOld, mdbx.SelectedDamageCommitNew: mdbx.CommitTruthNew}[scenario]
		unreadable := scenario == mdbx.SelectedDamageCommitUnreadable
		if scenario == mdbx.SelectedDamageCommitUnreadable || scenario == mdbx.SelectedDamageCommitThird {
			truth = mdbx.CommitTruthUnknown
		}
		logicalMDBXAssert(t, out.stage == mdbx.UpdateStageCommitMayHaveCrossed && out.truth == truth && evidence.BeginWrite == 1 && evidence.Commits == 1, "%s %d: %+v %+v", label, scenario, out, evidence)
		replayCrossedErr(t, out.err, truth, unreadable)
		w.store = w.reopen()
		want := map[mdbx.SelectedDamageScenario][]mdbx.PrefixRow{mdbx.SelectedDamageCommitOld: pre, mdbx.SelectedDamageCommitNew: post, mdbx.SelectedDamageCommitUnreadable: post, mdbx.SelectedDamageCommitThird: replayThirdImage(post)}[scenario]
		replaySameImage(t, want, w.image(), fmt.Sprintf("%s %d persisted", label, scenario))
	}
}

func TestReplayRecoveryFixtureCrossed(t *testing.T) {
	all := []mdbx.SelectedDamageScenario{mdbx.SelectedDamageCommitOld, mdbx.SelectedDamageCommitNew, mdbx.SelectedDamageCommitUnreadable, mdbx.SelectedDamageCommitThird}
	recoveryCrossed(t, "H23", func(t *testing.T) (*replayWorld, func(*mdbx.Reader) (mdbx.Batch, error)) {
		w := newReplayWorld(t, 4)
		w.setAuthority(func(a *mdbx.StorageAuthorityV1) {
			a.Phase, a.B, a.U = mdbx.StoragePhasePruneGCV1, 10, 13_690
			a.Cleanup = &mdbx.CleanupV1{Spans: []mdbx.CleanupSpanV1{{Kind: mdbx.CleanupSpanBlocksV1, GenerationID: 1, FirstHeight: 1, LastHeight: 3, NextHeight: 2}}}
		})
		return w, func(r *mdbx.Reader) (mdbx.Batch, error) {
			plan, err := PlanRecoveryIntentMDBX(r)
			return plan.Batch, err
		}
	}, all)
	recoveryCrossed(t, "H24", func(t *testing.T) (*replayWorld, func(*mdbx.Reader) (mdbx.Batch, error)) {
		w := newReplayWorld(t, 5)
		headers, hashes := w.fork(3, 4, 0)
		view := &replayView{inv: replayComplete([][32]byte{hashes[3]}, headers)}
		w.watch = 2
		return w, func(r *mdbx.Reader) (mdbx.Batch, error) {
			plan, _, err := NewReplayEntryOwnerV1(view, w.genesis).PlanDirectReplayEntryMDBX(r, mdbx.MaxOperationDataBytes)
			return plan.Batch, err
		}
	}, all[:2])
	recoveryCrossed(t, "H25", func(t *testing.T) (*replayWorld, func(*mdbx.Reader) (mdbx.Batch, error)) {
		w, _ := recoveryWorld(t, nil)
		headers, hashes := w.fork(2, 7, 3)
		view := &replayView{inv: replayComplete([][32]byte{hashes[6]}, headers)}
		return w, func(r *mdbx.Reader) (mdbx.Batch, error) {
			rep, err := NewReplayEntryOwnerV1(view, w.genesis).RecomputeReplayTargetMDBX(r, mdbx.MaxOperationDataBytes)
			if err != nil || rep.Report != ReplayRecomputationPlanChangeV1 {
				return mdbx.Batch{}, errors.Join(err, errRecoverySentinel)
			}
			return PlanReplayTargetConversionMDBX(r, rep)
		}
	}, all[:2])
}

// R63, R34, R36: a malformed authority row is returned unchanged by every owned call; LANE_MAX + 1 refuses before reading it.
func TestReplayRecoveryMalformedAuthority(t *testing.T) {
	malformed := func() *replayWorld {
		w := newReplayWorld(t, 4)
		a := w.authority()
		encoded, err := a.Encode()
		a.NextGenerationID++
		bumped, err2 := a.Encode()
		logicalMDBXAssert(t, err == nil && err2 == nil && len(bumped) == len(encoded), "R63 seed: %v %v", err, err2)
		for i := range encoded { // next_generation_id := active_generation_id, rejected by ValidateStorageAuthorityV1 (validTop)
			if encoded[i] != bumped[i] {
				encoded[i] -= byte(a.NextGenerationID - 1 - uint64(a.ActiveGenerationID))
			}
		}
		_, derr := mdbx.DecodeStorageAuthorityV1(encoded)
		logicalMDBXAssert(t, derr != nil, "R63 premise: the literal is rejected")
		logicalMDBXAssert(t, mdbx.FixtureSeedRawRow(w.store, 0, []byte{2}, encoded) == nil, "R63 raw seed")
		return w
	}
	var want error
	_ = malformed().store.View(func(r *mdbx.Reader) error { _, want = r.ReadStorageAuthorityV1(); return nil })
	logicalMDBXAssert(t, want != nil, "R63 premise")
	same := func(err error) bool { return err != nil && err.Error() == want.Error() }
	view := recoveryEmpty()
	rep, _, err, _ := malformed().recompute(view, mdbx.MaxOperationDataBytes+1, false)
	logicalMDBXAssert(t, err != nil && recoveryClass(err, rep.ReadResource) == selectedSideInvariant && !same(err), "R34 (f): %v", err)
	plan, release, err := recoveryDirect(malformed(), view, mdbx.MaxOperationDataBytes+1, false)
	logicalMDBXAssert(t, err != nil && recoveryClass(err, plan.ReadResource) == selectedSideInvariant && !same(err) && release == nil, "R34 (h): %v", err)
	for _, call := range []string{"(f)", "(h)"} { // R36: the context check precedes the authority read
		w := malformed()
		w.genesis.ChainID = [32]byte{}
		if call == "(f)" {
			rep, _, err, _ = w.recompute(view, mdbx.MaxOperationDataBytes, false)
		} else {
			plan, release, err = recoveryDirect(w, view, mdbx.MaxOperationDataBytes, false)
			logicalMDBXAssert(t, release == nil && plan.ReadResource == "", "R36 %s: %+v", call, plan)
		}
		logicalMDBXAssert(t, err != nil && recoveryClass(err, "") == selectedSideInvariant && !same(err), "R36 %s: the authority was read first: %v", call, err)
	}
	rep, _, err, _ = malformed().recompute(view, mdbx.MaxOperationDataBytes, false)
	logicalMDBXAssert(t, same(err) && rep.ReadResource == "" && rep.Report == 0, "R63 (f): %+v %v", rep, err)
	plan, release, err = recoveryDirect(malformed(), view, mdbx.MaxOperationDataBytes, false)
	logicalMDBXAssert(t, same(err) && plan.ReadResource == "" && release == nil && len(plan.Batch.Mutations) == 0, "R63 (h): %+v %v", plan, err)
	var intent ReplayRecoveryPlanV1
	_, _, _ = malformed().store.Update(func(r *mdbx.Reader) (mdbx.Batch, error) {
		intent, err = PlanRecoveryIntentMDBX(r)
		return mdbx.Batch{}, errRecoverySentinel
	})
	logicalMDBXAssert(t, same(err) && intent.ReadResource == "" && len(intent.Batch.Mutations) == 0, "R63 (g): %+v %v", intent, err)
	logicalMDBXAssert(t, view.calls == 0 && len(view.versions) == 0, "R63 view calls %+v", view)
}

// R53: a target-only entry whose header row holds bytes hashing to another value is nonlocalizable (T4).
func TestReplayRecoveryFixtureTargetHeaderHash(t *testing.T) {
	w, tg := recoveryWorld(t, nil)
	logicalMDBXAssert(t, mdbx.FixtureSeedRawRow(w.store, 3, tg.hashes[5][:], tg.headers[4][:]) == nil, "R53 seed")
	recoveryIntegrity(t, w, recoveryEmpty(), "R53 header hashes elsewhere")
}

// R46: the intent with a selected side returns the clear planner's own error and ReadResource, with no Batch, for a
// transient read of a leaving header (each planner on its own world); the decided refusal is TestPlanRecoveryIntentSide.
func TestReplayRecoveryFixtureIntentSideRefusals(t *testing.T) {
	type got struct {
		err      error
		resource string
		batch    int
	}
	run := func(arm func(w *sideWorld, call func())) (got, got) {
		var clear, intent got
		w := newSideWorld(t, sideFullSpec)
		arm(w, func() {
			_, _, _ = w.store.Update(func(r *mdbx.Reader) (mdbx.Batch, error) {
				p, err := PlanSelectedSideClearMDBX(r)
				clear = got{err, p.ReadResource, len(p.Batch.Mutations)}
				return mdbx.Batch{}, errRecoverySentinel
			})
		})
		w = newSideWorld(t, sideFullSpec)
		arm(w, func() {
			_, _, _ = w.store.Update(func(r *mdbx.Reader) (mdbx.Batch, error) {
				p, err := PlanRecoveryIntentMDBX(r)
				intent = got{err, p.ReadResource, len(p.Batch.Mutations)}
				return mdbx.Batch{}, errRecoverySentinel
			})
		})
		return clear, intent
	}
	for _, c := range []struct {
		label string
		arm   func(w *sideWorld, call func())
	}{
		{"GetEIO on a leaving header", func(w *sideWorld, call func()) {
			hash := w.sideAt[3]
			_, err := mdbx.FixtureSelectedDamage(w.store, w.owner, mdbx.SelectedDamageGetEIO, 3, hash[:], call)
			logicalMDBXAssert(t, err == nil, "R46 fixture: %v", err)
		}},
	} {
		clear, intent := run(c.arm)
		logicalMDBXAssert(t, clear.err != nil && intent.err != nil && intent.err.Error() == clear.err.Error() && intent.resource == clear.resource && intent.batch == 0,
			"R46 %s: intent %+v clear %+v", c.label, intent, clear)
		logicalMDBXAssert(t, recoveryClass(intent.err, intent.resource) == recoveryClass(clear.err, clear.resource), "R46 %s class", c.label)
	}
}
