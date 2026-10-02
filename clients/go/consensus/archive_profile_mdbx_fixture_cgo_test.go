//go:build rubin_mdbx_fixture && cgo && (darwin || linux) && (amd64 || arm64)

package consensus

import (
	"errors"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/mdbx"
)

// armedProfile invokes the real PROFILE entrypoint exactly once under one armed native scenario.
func (w *sideWorld) armedProfile(t *testing.T, scenario mdbx.SelectedDamageScenario, rank uint8, key []byte) (selectedSideOutcome, mdbx.SelectedDamageEvidence) {
	t.Helper()
	var out selectedSideOutcome
	calls := 0
	evidence, err := mdbx.FixtureSelectedDamage(w.store, w.owner, scenario, rank, key, func() { calls++; out = w.profile() })
	logicalMDBXAssert(t, err == nil && calls == 1, "PROFILE scenario %d: %v (%+v)", scenario, err, evidence)
	return out, evidence
}

// profileWantNative requires every distinct EngineError in err, in order, to be exactly one of want.
func profileWantNative(t *testing.T, err error, label string, want ...mdbx.EngineClass) {
	t.Helper()
	var engines []*mdbx.EngineError
	for _, part := range genesisMDBXCauses(err) {
		var engine *mdbx.EngineError
		if errors.As(part, &engine) {
			engines = append(engines, engine)
		}
	}
	logicalMDBXAssert(t, len(engines) == len(want), "%s: native causes %v, want %v", label, err, want)
	for i, engine := range engines {
		logicalMDBXAssert(t, engine.Class == want[i], "%s: cause %d class %v, want %v", label, i, engine.Class, want[i])
	}
}

func TestArchiveSelectedSideFixture(t *testing.T) {
	crossed := mdbx.UpdateStageCommitMayHaveCrossed
	for _, c := range []struct {
		name, result, canonical string
		scen                    mdbx.SelectedDamageScenario
		truth                   mdbx.CommitTruth
		key                     []byte
	}{
		{"H6c", "TERMINAL_PERSISTENCE(old)", "OLD", mdbx.SelectedDamageCommitOld, mdbx.CommitTruthOld, nil},
		{"H6d", "TERMINAL_PERSISTENCE(new)", "NEW", mdbx.SelectedDamageCommitNew, mdbx.CommitTruthNew, nil},
		{"H6e-third", "TERMINAL_PERSISTENCE(neither_or_unreadable)", "UNKNOWN", mdbx.SelectedDamageCommitThird, mdbx.CommitTruthUnknown, nil},
		{"H6e-unreadable", "TERMINAL_PERSISTENCE(neither_or_unreadable)", "UNKNOWN", mdbx.SelectedDamageCommitUnreadable, mdbx.CommitTruthUnknown, []byte{2}},
	} {
		t.Run(c.name, func(t *testing.T) {
			w := rawSideWorld(t, sideFullSpec)
			out, evidence := w.armedProfile(t, c.scen, 0, c.key)
			sideWantOutcome(t, out, c.result, c.canonical, c.truth, crossed, c.name)
			var commit *mdbx.CommitError
			logicalMDBXAssert(t, errors.As(out.Err, &commit) && commit.Truth == c.truth && evidence.Commits == 1, "%s: raw commit error %v (%+v)", c.name, out.Err, evidence)
			switch c.truth {
			case mdbx.CommitTruthOld:
				w.wantImage(c.name+": exact old image", w.authority, false)
			case mdbx.CommitTruthNew:
				w.wantImage(c.name+": exact pending-ARCHIVE authority, still RECOVERY_REQUIRED", w.profileAuthority(), true)
			}
			sideWantReleased(t, w.owner, c.name)
		})
	}
	for _, height := range []uint64{0, 1} {
		t.Run("H5-tip-g"+string(rune('0'+height)), func(t *testing.T) {
			// The identity rows g0/g1 are relied-on Consulted rows: a readback fault on either turns the committed image
			// UNKNOWN; the tuple is checked before fixture bookkeeping, NEW image independently.
			w := rawSideWorld(t, sideFullSpec)
			out, evidence := w.armedProfile(t, mdbx.SelectedDamageCommitUnreadable, 2, logicalMDBXMust(mdbx.HeightKey(1, height)))
			sideWantOutcome(t, out, "TERMINAL_PERSISTENCE(neither_or_unreadable)", "UNKNOWN", mdbx.CommitTruthUnknown, crossed, "identity row captured")
			logicalMDBXAssert(t, evidence.Commits == 1, "identity row commit evidence %+v", evidence)
			w.wantImage("identity row committed NEW image", w.profileAuthority(), true)
		})
	}
	t.Run("begin-eio", func(t *testing.T) {
		w := rawSideWorld(t, sideFullSpec)
		out, evidence := w.armedProfile(t, mdbx.SelectedDamageBeginEIO, 0, nil)
		sideWantOutcome(t, out, "", "", mdbx.CommitTruthOld, mdbx.UpdateStagePrewrite, "no-callback begin keeps empty fields")
		profileWantNative(t, out.Err, "PROFILE begin", mdbx.EngineIO)
		logicalMDBXAssert(t, evidence.BeginOld == 1 && evidence.OldGets == [8]uint64{}, "begin evidence %+v", evidence)
		w.wantImage("begin failure image", w.authority, false)
	})
	for _, c := range []struct {
		name string
		scen mdbx.SelectedDamageScenario
		rank uint8
		key  []byte
	}{{"put", mdbx.SelectedDamagePutEIO, 0, []byte{2}}, {"delete", mdbx.SelectedDamageDeleteEIO, 0, nil}} {
		t.Run(c.name, func(t *testing.T) {
			w := rawSideWorld(t, sideFullSpec)
			out, evidence := w.armedProfile(t, c.scen, c.rank, c.key)
			sideWantOutcome(t, out, "LOCAL_PERSISTENCE_ERROR(precommit)", "OLD", mdbx.CommitTruthOld, mdbx.UpdateStageWriteStartedDefinitelyPrecommit, c.name)
			profileWantNative(t, out.Err, c.name, mdbx.EngineIO)
			logicalMDBXAssert(t, evidence.BeginWrite == 1 && evidence.Commits == 0, "%s evidence %+v", c.name, evidence)
			w.wantImage(c.name+": precommit keeps OLD", w.authority, false)
		})
	}
	t.Run("sentinel-abort-cache", func(t *testing.T) {
		// PROFILE_NOOP's sentinel plus abort EIO: storage_io with the raw abort cause, no clean decision; the consumed
		// Store answers the next call from its cached raw error with empty fields and no callback.
		w := rawSideWorld(t, sideFullSpec)
		w.setAuthority(func(a *mdbx.StorageAuthorityV1) { a.ActiveProfile = mdbx.StorageProfileArchiveV1 })
		first, _ := w.armedProfile(t, mdbx.SelectedDamageAbortEIO, 0, nil)
		sideWantOutcome(t, first, "LOCAL_RESOURCE_UNAVAILABLE(storage_io)", "OLD", mdbx.CommitTruthOld, mdbx.UpdateStagePrewrite, "joined abort IO storage_io")
		profileWantNative(t, first.Err, "sentinel abort", mdbx.EngineIO)
		next := w.profile()
		sideWantOutcome(t, next, "", "", mdbx.CommitTruthOld, mdbx.UpdateStagePrewrite, "cached next call empty fields")
		logicalMDBXAssert(t, errors.Is(next.Err, first.Err) && errors.Is(first.Err, next.Err), "cached raw error %v, want %v", next.Err, first.Err)
		sideWantReleased(t, w.owner, "cached next call")
		w.reopen()
		w.wantImage("abort keeps OLD after reopen", w.authority, false)
	})
	t.Run("wrong-leaf-abort", func(t *testing.T) {
		// The H>0 no-side API refusal plus abort EIO: the bound empty-result leaf is skipped and storage_io classifies
		// the abort; the raw error keeps both causes.
		w := rawSideWorld(t, sideFullSpec)
		w.setAuthority(func(a *mdbx.StorageAuthorityV1) { a.SelectedSide = nil })
		out, _ := w.armedProfile(t, mdbx.SelectedDamageAbortEIO, 0, nil)
		sideWantOutcome(t, out, "LOCAL_RESOURCE_UNAVAILABLE(storage_io)", "OLD", mdbx.CommitTruthOld, mdbx.UpdateStagePrewrite, "wrong leaf abort storage_io")
		profileWantNative(t, out.Err, "wrong leaf abort", mdbx.EngineStateMismatch, mdbx.EngineIO)
		w.reopen()
		w.wantImage("wrong leaf abort keeps OLD", w.authority, false)
	})
	t.Run("lifetime", func(t *testing.T) {
		w := rawSideWorld(t, sideFullSpec)
		out, evidence := w.armedProfile(t, mdbx.SelectedDamageProbeOnly, 0, nil)
		sideWantOutcome(t, out, "", "NEW", mdbx.CommitTruthNew, crossed, "probed PROFILE")
		logicalMDBXAssert(t, out.Err == nil && evidence.Probes > 0 && evidence.ProbeDenied == evidence.Probes && evidence.ProbeRan == 0 && evidence.Commits == 1,
			"every native full-lane probe denied; grant released after return: %+v", evidence)
		w.wantImage("probed PROFILE image", w.profileAuthority(), true)
	})
}
