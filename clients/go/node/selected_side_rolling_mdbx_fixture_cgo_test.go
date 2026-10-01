//go:build rubin_mdbx_fixture && cgo && (darwin || linux) && (amd64 || arm64)

package node

import (
	"bytes"
	"errors"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/mdbx"
)

// armedPrepare invokes the real RP entrypoint exactly once under one armed native scenario; a site not reached as
// armed fails.
func (w *ssqWorld) armedPrepare(scenario mdbx.SelectedDamageScenario, rank uint8, key, raw []byte) (SelectedSideMutationOutcome, mdbx.SelectedDamageEvidence) {
	w.t.Helper()
	var out SelectedSideMutationOutcome
	calls := 0
	evidence, err := mdbx.FixtureSelectedDamage(w.store, w.owner, scenario, rank, key, func() {
		calls++
		out = w.prepareSide(raw, w.tipAt(2))
	})
	if err != nil || calls != 1 {
		w.t.Fatalf("scenario %d: %v (%+v)", scenario, err, evidence)
	}
	return out, evidence
}

// rollFixtureWorld is rollWorld with native row comparison.
func rollFixtureWorld(t *testing.T) (*ssqWorld, []byte) {
	t.Helper()
	w, raw := rollWorld(t)
	w.rawEqual = func(rank uint8, key, want []byte) (bool, error) {
		return mdbx.FixtureRawRowEqual(w.store, rank, key, want)
	}
	return w, raw
}

// rollLocatorWorld is rollFixtureWorld whose tip 1440 is a hash-bound block naming an absent unowned parent Z (its
// SideLink and descriptor are rewritten to it): qualification of the exact-tip child asks row 1439 by Z, a clean damage
// locator (2,1440,1439); the recheck of 1439 finds that row healthy and the single retry repeats the same locator.
func rollLocatorWorld(t *testing.T) (*ssqWorld, []byte) {
	t.Helper()
	w, _ := rollFixtureWorld(t)
	z := [32]byte{0x5a}
	w.headers[z] = w.headers[w.side[1_439]]
	tip := w.mined(z, 113)
	hash := ssqHash(tip)
	w.side[1_440] = hash
	a := w.tracked()
	side := *a.SelectedSide
	side.TipHash = hash
	a.SelectedSide = &side
	w.apply([]mdbx.Mutation{
		w.literal(3, bytes.Clone(hash[:]), tip[:consensus.BLOCK_HEADER_BYTES], false), w.literal(4, bytes.Clone(hash[:]), tip, false),
		w.literal(6, ssqMust(mdbx.HeightKey(2, 1_440)), mdbx.ChainValue(hash, z, ssqWork(1_441)), true), w.authorityMutation(a),
	})
	// The previous tip's header and body stay as unrelated preserved rows.
	delete(w.headers, z)
	return w, w.childAt(hash, w.ts(hash)+120, consensus.POW_LIMIT, nil)
}

// rollTipBodyAbsent removes the tip 1440 body: the exact-tip qualification reads it through its optional linking owner
// and stops at a positive-absence damage locator (2,1440,1440) before RP planning.
func rollTipBodyAbsent(t *testing.T) (*ssqWorld, []byte) {
	t.Helper()
	w, raw := rollFixtureWorld(t)
	tip := w.side[1_440]
	w.apply([]mdbx.Mutation{w.absentRow(4, bytes.Clone(tip[:]))})
	return w, raw
}

func TestSelectedSideRollingFixture(t *testing.T) {
	old, crossed := mdbx.CommitTruthOld, mdbx.UpdateStageCommitMayHaveCrossed
	t.Run("H8-lifetime", func(t *testing.T) {
		w, raw := rollFixtureWorld(t)
		prior := w.tracked()
		out, evidence := w.armedPrepare(mdbx.SelectedDamageProbeOnly, 0, nil, raw)
		retainWant(t, "probed RP", out, "", "", retainNA, mdbx.CommitTruthNew, crossed, true)
		if evidence.Probes == 0 || evidence.ProbeDenied != evidence.Probes || evidence.ProbeRan != 0 || evidence.BeginWrite != 1 || evidence.Commits != 1 || evidence.BeginRead != 0 {
			t.Fatalf("every native full-lane probe denied; grant released after return: %+v", evidence)
		}
		w.expectPrepared(prior)
		w.wantImage("probed RP image")
	})
	t.Run("H8a-delete", func(t *testing.T) {
		// RP's one definite delete is the unkept oldest header; DeleteEIO fails it before commit.
		w, raw := rollFixtureWorld(t)
		out, evidence := w.armedPrepare(mdbx.SelectedDamageDeleteEIO, 0, nil, raw)
		retainWant(t, "definite precommit write", out, retainPrecommit, "", "OLD", old, mdbx.UpdateStageWriteStartedDefinitelyPrecommit, false)
		ssqWantNative(t, "RP delete", out.Err, ssqNative{"update", mdbx.EngineIO, 5})
		if evidence.BeginWrite != 1 || evidence.Deletes != 1 || evidence.Commits != 0 || evidence.Faults != 1 {
			t.Fatalf("RP delete evidence %+v", evidence)
		}
		w.wantImage("precommit keeps OLD")
	})
	t.Run("R-n", func(t *testing.T) {
		// The optional oldest body read faults transiently: branch_data/OLD with the exact native cause, no plan or write.
		w, raw := rollFixtureWorld(t)
		out, evidence := w.armedPrepare(mdbx.SelectedDamageGetEIO, 4, w.sideKey(1), raw)
		retainWant(t, "oldest transient read branch_data", out, ssqBranch, "", "OLD", old, mdbx.UpdateStagePrewrite, false)
		ssqWantNative(t, "oldest body GetEIO", out.Err, ssqGetEIO)
		if evidence.BeginWrite != 0 || evidence.Commits != 0 {
			t.Fatalf("R-n evidence %+v", evidence)
		}
		w.wantImage("oldest transient read keeps OLD")
	})
	t.Run("R-n-owner", func(t *testing.T) {
		// The oldest row's required CanonicalOwnerV1 read (rank 7, active generation 1) faults transiently: it keeps
		// canonical_artifact_read at its fixed position, with no plan, write or commit and the grant released (operate).
		w, raw := rollFixtureWorld(t)
		out, evidence := w.armedPrepare(mdbx.SelectedDamageGetEIO, 7, ssqMust(mdbx.CanonicalOwnerKey(1, w.side[1])), raw)
		retainWant(t, "required owner transient read canonical_artifact_read", out, ssqCanonical, "", "OLD", old, mdbx.UpdateStagePrewrite, false)
		ssqWantNative(t, "oldest owner GetEIO", out.Err, ssqGetEIO)
		if evidence.BeginWrite != 0 || evidence.Commits != 0 {
			t.Fatalf("R-n-owner evidence %+v", evidence)
		}
		w.wantImage("required owner transient read keeps OLD")
	})
	t.Run("H6b-NEW", func(t *testing.T) {
		w, raw := rollFixtureWorld(t)
		prior := w.tracked()
		out, evidence := w.armedPrepare(mdbx.SelectedDamageCommitNew, 0, nil, raw)
		retainWant(t, "proved NEW/raw causes retained/NOT_APPLICABLE empty Result", out, "", "", retainNA, mdbx.CommitTruthNew, crossed, false)
		var commit *mdbx.CommitError
		if !errors.As(out.Err, &commit) || commit.Truth != mdbx.CommitTruthNew || evidence.Commits != 1 {
			t.Fatalf("equality NEW error %v (%+v)", out.Err, evidence)
		}
		ssqWantNative(t, "commit ENOSPC", commit.Cause, ssqNative{"update", mdbx.EngineCapacity, 28})
		w.expectPrepared(prior)
		w.wantImage("equality NEW Prepared image")
	})
	t.Run("H6b-OLD", func(t *testing.T) {
		w, raw := rollFixtureWorld(t)
		out, _ := w.armedPrepare(mdbx.SelectedDamageCommitOld, 0, nil, raw)
		retainWant(t, "equality OLD empty Result", out, "", "", retainNA, old, crossed, false)
		retainWantCommit(t, "equality OLD", out, false)
		w.wantImage("equality OLD full image")
	})
	for _, c := range []struct {
		name string
		scen mdbx.SelectedDamageScenario
		key  []byte
	}{{"H6a-RP", mdbx.SelectedDamageCommitUnreadable, []byte{2}}, {"H6a-RP-third", mdbx.SelectedDamageCommitThird, nil}} {
		t.Run(c.name, func(t *testing.T) {
			w, raw := rollFixtureWorld(t)
			out, _ := w.armedPrepare(c.scen, 0, c.key, raw)
			retainWant(t, "noncanonical/NOT_APPLICABLE with exact raw UNKNOWN", out, retainCleared, "", retainNA, mdbx.CommitTruthUnknown, crossed, false)
			retainWantCommit(t, c.name, out, c.key != nil)
		})
	}
	for _, c := range []struct {
		name  string
		scen  mdbx.SelectedDamageScenario
		truth mdbx.CommitTruth
	}{{"H6a-RP-positive-OLD", mdbx.SelectedDamageCommitOld, mdbx.CommitTruthOld}, {"H6a-RP-positive-NEW", mdbx.SelectedDamageCommitNew, mdbx.CommitTruthNew}, {"H6a-RP-positive-UNKNOWN", mdbx.SelectedDamageCommitThird, mdbx.CommitTruthUnknown}} {
		t.Run(c.name, func(t *testing.T) {
			// Positive oldest damage: the complete clear keeps its all-outcome noncanonical exception.
			w, raw := rollFixtureWorld(t)
			oldest := w.side[1]
			w.apply([]mdbx.Mutation{w.absentRow(4, bytes.Clone(oldest[:]))})
			out, evidence := w.armedPrepare(c.scen, 0, nil, raw)
			retainWant(t, "positive-damage clear keeps its all-outcome exception", out, retainCleared, "", retainNA, c.truth, crossed, false)
			if evidence.BeginWrite != 1 || evidence.Commits != 1 {
				t.Fatalf("positive clear write evidence %+v", evidence)
			}
			switch c.truth {
			case mdbx.CommitTruthOld:
				w.wantImage("crossed OLD full image")
			case mdbx.CommitTruthNew:
				w.wantCleared("crossed NEW complete clear image", 1, 1_440)
			}
		})
	}
	for _, c := range []struct {
		name string
		code int
		kind mdbx.EngineClass
		scen mdbx.SelectedDamageScenario
	}{{"H8a-begin-txnfull", -30_788, mdbx.EngineTransaction, mdbx.SelectedDamageBeginTxnFull}, {"H8a-begin-eio", 5, mdbx.EngineIO, mdbx.SelectedDamageBeginEIO}} {
		t.Run(c.name, func(t *testing.T) {
			w, raw := rollFixtureWorld(t)
			out, evidence := w.armedPrepare(c.scen, 0, nil, raw)
			retainWant(t, "no-callback native begin keeps empty fields", out, "", "", "", old, mdbx.UpdateStagePrewrite, false)
			ssqWantNative(t, c.name, out.Err, ssqNative{"update", c.kind, c.code})
			if evidence.BeginOld != 1 || evidence.OldGets != [8]uint64{} {
				t.Fatalf("begin evidence %+v", evidence)
			}
			w.wantImage("RP begin failure")
		})
	}
	t.Run("H8a-get-tip", func(t *testing.T) {
		w, raw := rollFixtureWorld(t)
		out, _ := w.armedPrepare(mdbx.SelectedDamageGetEIO, 2, ssqMust(mdbx.HeightKey(1, 2)), raw)
		retainWantRefusal(t, "tip read canonical_artifact_read", out, ssqCanonical, "")
		ssqWantNative(t, "tip GetEIO", out.Err, ssqGetEIO)
		w.wantImage("RP tip read fault")
	})
	t.Run("H8a-getabort-tip", func(t *testing.T) {
		w, raw := rollFixtureWorld(t)
		out, _ := w.armedPrepare(mdbx.SelectedDamageGetAbortEIO, 2, ssqMust(mdbx.HeightKey(1, 2)), raw)
		retainWantRefusal(t, "first typed result kept over abort IO", out, ssqCanonical, "")
		ssqWantNative(t, "tip Get+abort EIO", out.Err, ssqGetEIO, ssqAbortEIO)
		w.wantImage("RP tip read and abort fault")
	})
	t.Run("H8a-put", func(t *testing.T) {
		// RP's only put is the authority literal; PutEIO fails it before commit.
		w, raw := rollFixtureWorld(t)
		out, evidence := w.armedPrepare(mdbx.SelectedDamagePutEIO, 0, []byte{2}, raw)
		retainWant(t, "definite precommit write", out, retainPrecommit, "", "OLD", old, mdbx.UpdateStageWriteStartedDefinitelyPrecommit, false)
		ssqWantNative(t, "RP put", out.Err, ssqNative{"update", mdbx.EngineIO, 5})
		if evidence.BeginWrite != 1 || evidence.Commits != 0 || evidence.BeginRead != 0 {
			t.Fatalf("RP put evidence %+v", evidence)
		}
		w.wantImage("precommit keeps OLD")
	})
	t.Run("H8-cache", func(t *testing.T) {
		// A Prepare whose child K23-outranks the canonical tip decides ORDINARY through the no-write sentinel; abort EIO
		// consumes the Store and the next RP call returns the cached tuple with empty invocation fields.
		w := newRetainFixtureWorld(t, ssqSpec{tip: 10})
		raw := w.child(w.canonical[10], 11, nil)
		var first SelectedSideMutationOutcome
		if _, err := mdbx.FixtureSelectedDamage(w.store, w.owner, mdbx.SelectedDamageAbortEIO, 0, nil, func() { first = w.prepareSide(raw, w.tipAt(10)) }); err != nil {
			t.Fatalf("H8-cache fixture: %v", err)
		}
		retainWant(t, "joined abort IO storage_io/raw ordered join/CLOSED", first, retainStorageIO, "", "OLD", old, mdbx.UpdateStagePrewrite, false)
		ssqWantNative(t, "sentinel abort", first.Err, ssqAbortEIO)
		next := w.prepareSide(raw, w.tipAt(10))
		retainWant(t, "empty invocation fields/raw cached tuple", next, "", "", "", old, mdbx.UpdateStagePrewrite, false)
		// Mutual errors.Is over an acyclic error tree holds only for the identical error value.
		if next.Err == nil || !errors.Is(next.Err, first.Err) || !errors.Is(first.Err, next.Err) {
			t.Fatalf("empty invocation fields/raw cached tuple: error %v, want %v", next.Err, first.Err)
		}
		w.wantImage("cached next call persisted image")
	})
	t.Run("H12-capacity-abortIO", func(t *testing.T) {
		// The RP capacity refusal is a non-read sentinel exit: ReadResource is clear, so abort EIO maps storage_io, never
		// the linking body's branch_data class; no clean Result or Decision survives the joined cause.
		w := newRetainFixtureWorld(t, ssqSpec{tip: 2, work: retainHeavy(2)})
		blocks := w.retainSide(0, 1_440, 1_440, 1_441, false)
		raw := retainLarge(t, w.side[1_440], w.ts(w.side[1_440])+120, (437_205-len(blocks[1_440]))/2+1)
		var out SelectedSideMutationOutcome
		if _, err := mdbx.FixtureSelectedDamage(w.store, w.owner, mdbx.SelectedDamageAbortEIO, 0, nil, func() { out = w.prepareSide(raw, w.tipAt(2)) }); err != nil {
			t.Fatalf("H12 fixture: %v", err)
		}
		retainWant(t, "capacity sentinel abort storage_io", out, retainStorageIO, "", "OLD", old, mdbx.UpdateStagePrewrite, false)
		ssqWantNative(t, "capacity sentinel abort", out.Err, ssqAbortEIO)
	})
	t.Run("H12-optional-read-abortIO", func(t *testing.T) {
		// An actual failed optional oldest-body read keeps its branch_data class through projection; a Get+abort EIO
		// keeps that first typed class with the raw ordered join.
		w, raw := rollFixtureWorld(t)
		out, _ := w.armedPrepare(mdbx.SelectedDamageGetAbortEIO, 4, w.sideKey(1), raw)
		retainWant(t, "failed-read resource retained", out, ssqBranch, "", "OLD", old, mdbx.UpdateStagePrewrite, false)
		ssqWantNative(t, "oldest body Get+abort EIO", out.Err, ssqGetEIO, ssqAbortEIO)
		w.wantImage("RP failed read keeps OLD")
	})
	t.Run("H5", func(t *testing.T) {
		// Each relied-on RP observation is in the final union: a readback-only Get EIO on it turns the committed image
		// UNKNOWN. The tuple is asserted inside the callback before fixture bookkeeping.
		for _, c := range []struct {
			name string
			rank uint8
			key  func(w *ssqWorld, raw []byte) []byte
		}{
			{"candidate owner absence", 7, func(w *ssqWorld, raw []byte) []byte { return ssqMust(mdbx.CanonicalOwnerKey(1, ssqHash(raw))) }},
			{"absent next-height tip boundary", 2, func(*ssqWorld, []byte) []byte { return ssqMust(mdbx.HeightKey(1, 3)) }},
			{"oldest SideLink", 6, func(*ssqWorld, []byte) []byte { return ssqMust(mdbx.HeightKey(2, 1)) }},
			{"oldest owner NONE", 7, func(w *ssqWorld, _ []byte) []byte { return ssqMust(mdbx.CanonicalOwnerKey(1, w.side[1])) }},
			{"oldest body", 4, func(w *ssqWorld, _ []byte) []byte { return w.sideKey(1) }},
		} {
			w, raw := rollFixtureWorld(t)
			prior := w.tracked()
			evidence, err := mdbx.FixtureSelectedDamage(w.store, w.owner, mdbx.SelectedDamageCommitUnreadable, c.rank, c.key(w, raw), func() {
				out := w.prepareSide(raw, w.tipAt(2))
				var commit *mdbx.CommitError
				if out.Result != retainCleared || out.Decision != "" || out.CanonicalTruth != retainNA || out.Truth != mdbx.CommitTruthUnknown || out.Stage != crossed ||
					!errors.As(out.Err, &commit) || commit.Truth != mdbx.CommitTruthUnknown {
					t.Fatalf("required native OLD/Consulted observation captured and equality rejected: %s %+v", c.name, out)
				}
				ssqWantNative(t, c.name+": readback get EIO", commit.ReadbackCause, ssqNative{"update", mdbx.EngineIO, 5})
			})
			if err != nil || evidence.Commits != 1 || evidence.BeginWrite != 1 {
				t.Fatalf("%s: fixture site %v (%+v)", c.name, err, evidence)
			}
			w.expectPrepared(prior)
			w.wantImage(c.name + ": independently checked committed Prepared image")
		}
	})
	t.Run("H10-abortIO", func(t *testing.T) {
		w, raw := rollTipBodyAbsent(t)
		out, evidence := w.armedPrepare(mdbx.SelectedDamageAbortEIO, 0, nil, raw)
		retainWant(t, "storage_io/raw join/CLOSED/no recheck", out, retainStorageIO, "", "OLD", old, mdbx.UpdateStagePrewrite, false)
		var request *selectedSideDamageRequest
		if !errors.As(out.Err, &request) || *request != (selectedSideDamageRequest{Generation: 2, Tip: 1_440, Height: 1_440}) || evidence.BeginOld != 1 || evidence.BeginRead != 0 {
			t.Fatalf("locator abort %+v (%+v)", out, evidence)
		}
		w.wantImage("side kept without recheck")
	})
	for _, c := range []struct {
		name  string
		scen  mdbx.SelectedDamageScenario
		truth mdbx.CommitTruth
	}{{"H10-positive", mdbx.SelectedDamageCommitNew, mdbx.CommitTruthNew}, {"H10-positive-OLD", mdbx.SelectedDamageCommitOld, mdbx.CommitTruthOld}, {"H10-positive-UNKNOWN", mdbx.SelectedDamageCommitThird, mdbx.CommitTruthUnknown}} {
		t.Run(c.name, func(t *testing.T) {
			// The tip locator's recheck is a complete positive clear: its whole tuple terminates, never the locator's.
			w, raw := rollTipBodyAbsent(t)
			out, evidence := w.armedPrepare(c.scen, 0, nil, raw)
			retainWant(t, "complete recheck NEW/raw/error image tuple", out, retainCleared, "", retainNA, c.truth, crossed, false)
			if evidence.BeginOld != 1 || evidence.BeginWrite != 1 || evidence.Commits != 1 {
				t.Fatalf("recheck write evidence %+v", evidence)
			}
			switch c.truth {
			case mdbx.CommitTruthOld:
				w.wantImage("crossed OLD recheck image")
			case mdbx.CommitTruthNew:
				w.wantCleared("crossed NEW recheck image", 1, 1_440)
			}
		})
	}
	for _, name := range []string{"A10", "H10-second"} {
		t.Run(name, func(t *testing.T) {
			// Healthy recheck between released grants, then ONE fresh qualification whose second locator is typed
			// branch_data; no clear, no write and no nested operation.
			w, raw := rollLocatorWorld(t)
			out, evidence := w.armedPrepare(mdbx.SelectedDamageProbeOnly, 0, nil, raw)
			retainWantRefusal(t, "one retry/branch_data/operation counts", out, ssqBranch, "")
			var request *selectedSideDamageRequest
			if !errors.As(out.Err, &request) || *request != (selectedSideDamageRequest{Generation: 2, Tip: 1_440, Height: 1_439}) {
				t.Fatalf("second locator cause %v", out.Err)
			}
			if evidence.BeginOld != 1 || evidence.BeginRead != 2 || evidence.BeginWrite != 0 || evidence.Deletes != 0 || evidence.Commits != 0 || evidence.Faults != 0 ||
				evidence.OldAborts < 1 || evidence.OldAborts > 3 || evidence.Probes != 2+2*evidence.OldAborts || evidence.ProbeDenied != evidence.Probes || evidence.ProbeRan != 0 {
				t.Fatalf("recheck between released grants/no nested operation: %+v", evidence)
			}
			w.wantImage("bounded retry left the image unchanged")
		})
	}
	// H11-oldest / H11-planner: the nFit+1 refusal reads exactly one body natively (the linking tip body, L) and no
	// planner row; a planner run before the preflight would also read the oldest SideLink and body. The intended
	// assertion precedes fixture bookkeeping.
	for _, name := range []string{"H11-oldest", "H11-planner", "H11-link-length"} {
		t.Run(name, func(t *testing.T) {
			w := newRetainFixtureWorld(t, ssqSpec{tip: 2, work: retainHeavy(2)})
			blocks := w.retainSide(0, 1_440, 1_440, 1_441, false)
			raw := retainLarge(t, w.side[1_440], w.ts(w.side[1_440])+120, (437_205-len(blocks[1_440]))/2+1)
			w.absent = append(w.absent, ssqHash(raw))
			out, evidence := w.armedPrepare(mdbx.SelectedDamageProbeOnly, 0, nil, raw)
			retainWant(t, "conservative planner Q>G refused before planner allocation/read/Batch", out, retainCapacity, "", "OLD", old, mdbx.UpdateStagePrewrite, true)
			if evidence.OldGets[4] != 1 || evidence.BeginWrite != 0 || evidence.Commits != 0 {
				t.Fatalf("actual L resource bound/no second body read: %+v", evidence)
			}
			w.wantImage(name + " refusal image")
		})
	}
	t.Run("H6a-RP-incomplete", func(t *testing.T) {
		// Positively absent optional oldest body, then the complete transfer meets an absent required SideLink(2,first+1):
		// canonical integrity from that required read, OLD/Prewrite, no native write or commit, the damaged pre-state
		// unchanged and the grant released (operate). A flag-only change on this error path is not observable here.
		w, raw := rollFixtureWorld(t)
		bodyKey, linkKey := w.sideKey(1), ssqMust(mdbx.HeightKey(2, 2))
		w.apply([]mdbx.Mutation{w.absentRow(4, bodyKey), w.absentRow(6, linkKey)})
		out, evidence := w.armedPrepare(mdbx.SelectedDamageProbeOnly, 0, nil, raw)
		retainWantIntegrity(t, "incomplete plan/stronger error is not positive clear", out, "selected side link is absent")
		ssqWantNative(t, "incomplete plan raw cause", out.Err, ssqNative{"get", mdbx.EngineIntegrity, -30_793})
		if evidence.BeginOld != 1 || evidence.BeginWrite != 0 || evidence.Deletes != 0 || evidence.Commits != 0 {
			t.Fatalf("incomplete plan wrote: %+v", evidence)
		}
		w.wantImage("incomplete plan keeps the damaged OLD image")
		w.wantAbsent("oldest body still absent", 4, bodyKey)
		w.wantAbsent("first+1 link still absent", 6, linkKey)
	})
}
