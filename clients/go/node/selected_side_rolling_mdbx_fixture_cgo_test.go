//go:build rubin_mdbx_fixture && cgo && (darwin || linux) && (amd64 || arm64)

package node

import (
	"bytes"
	"errors"
	"testing"

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
}
