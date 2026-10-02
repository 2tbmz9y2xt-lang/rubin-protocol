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
				w.wantConsumed(c.name, out.Err)
				w.reopen()
				w.wantImage(c.name+": exact old image", w.authority, false)
			case mdbx.CommitTruthNew:
				w.wantConsumed(c.name, out.Err)
				w.reopen()
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
			w.wantConsumed("identity row captured", out.Err)
			w.reopen()
			w.wantImage("identity row committed NEW image", w.profileAuthority(), true)
		})
	}
	t.Run("begin-eio", func(t *testing.T) {
		w := rawSideWorld(t, sideFullSpec)
		out, evidence := w.armedProfile(t, mdbx.SelectedDamageBeginEIO, 0, nil)
		sideWantOutcome(t, out, "", "", mdbx.CommitTruthOld, mdbx.UpdateStagePrewrite, "no-callback begin keeps empty fields")
		profileWantNative(t, out.Err, "PROFILE begin", mdbx.EngineIO)
		logicalMDBXAssert(t, evidence.BeginOld == 1 && evidence.OldGets == [8]uint64{}, "begin evidence %+v", evidence)
		w.wantConsumed("PROFILE begin", out.Err)
		w.reopen()
		w.wantImage("begin failure image", w.authority, false)
	})
	for _, c := range []struct {
		name string
		scen mdbx.SelectedDamageScenario
		rank uint8
		key  []byte
	}{{"put", mdbx.SelectedDamagePutEIO, 0, []byte{2}}, {"delete", mdbx.SelectedDamageDeleteEIO, 0, []byte{2}}} {
		t.Run(c.name, func(t *testing.T) {
			// put is the targeted authority literal put. delete is the existing fixture's untargeted fault at the first
			// BeforePresent native delete, which in the sorted plan is the authority (rank 0, key 02) overwrite delete,
			// before any leaving header; the armed rank/key name that same first site. Reached once, faulted once, no
			// commit or readback; raw update/IO/5; OLD image and released grant.
			w := rawSideWorld(t, sideFullSpec)
			out, evidence := w.armedProfile(t, c.scen, c.rank, c.key)
			sideWantOutcome(t, out, "LOCAL_PERSISTENCE_ERROR(precommit)", "OLD", mdbx.CommitTruthOld, mdbx.UpdateStageWriteStartedDefinitelyPrecommit, c.name)
			var engine *mdbx.EngineError
			logicalMDBXAssert(t, errors.As(out.Err, &engine) && engine.Operation == "update" && engine.Class == mdbx.EngineIO && engine.Code == 5, "%s: raw %v", c.name, out.Err)
			profileWantNative(t, out.Err, c.name, mdbx.EngineIO)
			logicalMDBXAssert(t, evidence.BeginWrite == 1 && evidence.Faults == 1 && evidence.Commits == 0 && evidence.BeginRead == 0 && (c.scen != mdbx.SelectedDamageDeleteEIO || evidence.Deletes == 1),
				"%s exact site evidence %+v", c.name, evidence)
			sideWantReleased(t, w.owner, c.name)
			w.wantConsumed(c.name, out.Err)
			w.reopen()
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
	// seed writes one malformed-width canonical index row at height h through the existing native seed; a tracked
	// canonical entry takes the seeded bytes, an untracked height becomes an exact extra row.
	seed := func(t *testing.T, w *sideWorld, h uint64, value []byte) {
		t.Helper()
		key := logicalMDBXMust(mdbx.HeightKey(1, h))
		logicalMDBXAssert(t, mdbx.FixtureSeedRawRow(w.store, 2, key, value) == nil, "seed index height %d", h)
		if _, tracked := w.entries[h]; tracked {
			w.entries[h] = value
			return
		}
		w.extra = append(w.extra, sideRawRow{rank: 2, key: key, value: value})
	}
	t.Run("R-o2-malformed-index", func(t *testing.T) {
		// Active ARCHIVE with a selected side and a malformed canonical index row 1: PROFILE_NOOP before any identity read.
		w := rawSideWorld(t, sideFullSpec)
		w.setAuthority(func(a *mdbx.StorageAuthorityV1) { a.ActiveProfile = mdbx.StorageProfileArchiveV1 })
		seed(t, w, 1, []byte{1, 2, 3})
		out := w.profile()
		sideWantOutcome(t, out, "PROFILE_NOOP", "OLD", mdbx.CommitTruthOld, mdbx.UpdateStagePrewrite, "noop before malformed index")
		logicalMDBXAssert(t, out.Err == nil, "noop kept an error: %v", out.Err)
		w.wantImage("noop image", w.authority, false)
	})
	for _, c := range []struct {
		name   string
		height uint64
	}{{"page-first-width", 0}, {"page-lookahead-width", 1}} {
		t.Run(c.name, func(t *testing.T) {
			// A malformed first row or lookahead row of the identity page is the Reader's recorded integrity failure.
			w := rawSideWorld(t, sideFullSpec)
			seed(t, w, c.height, []byte{1, 2, 3})
			out := w.profile()
			sideWantOutcome(t, out, "TERMINAL_STORE_INTEGRITY(canonical)", "OLD", mdbx.CommitTruthOld, mdbx.UpdateStagePrewrite, c.name)
			profileWantNative(t, out.Err, c.name, mdbx.EngineIntegrity)
			w.reopen()
			w.wantImage(c.name+": image after reopen", w.authority, false)
		})
	}
	t.Run("page-no-third-row", func(t *testing.T) {
		// A malformed third index row (height 2) is never observed by the one-row page: H>0 PROFILE still commits.
		w := rawSideWorld(t, sideWorldSpec{f: 1, tip: 4, rows: 3, canonicalTip: 1})
		seed(t, w, 2, []byte{1, 2, 3})
		out := w.profile()
		sideWantOutcome(t, out, "", "NEW", mdbx.CommitTruthNew, crossed, "third row unobserved")
		w.wantImage("third row unobserved image", w.profileAuthority(), true)
	})
	t.Run("get-authority-eio", func(t *testing.T) {
		// The strict authority Get faults: storage_io with the exact get EIO; the recorded failure consumes the Store and
		// the next call is its cached raw error with empty fields.
		w := rawSideWorld(t, sideFullSpec)
		first, evidence := w.armedProfile(t, mdbx.SelectedDamageGetEIO, 0, []byte{2})
		sideWantOutcome(t, first, "LOCAL_RESOURCE_UNAVAILABLE(storage_io)", "OLD", mdbx.CommitTruthOld, mdbx.UpdateStagePrewrite, "authority get EIO")
		profileWantNative(t, first.Err, "authority get EIO", mdbx.EngineIO)
		logicalMDBXAssert(t, evidence.BeginWrite == 0 && evidence.Commits == 0, "authority get evidence %+v", evidence)
		next := w.profile()
		sideWantOutcome(t, next, "", "", mdbx.CommitTruthOld, mdbx.UpdateStagePrewrite, "cached after recorded read failure")
		logicalMDBXAssert(t, errors.Is(next.Err, first.Err) && errors.Is(first.Err, next.Err), "cached raw error %v, want %v", next.Err, first.Err)
		sideWantReleased(t, w.owner, "cached after read failure")
		w.reopen()
		w.wantImage("authority get image", w.authority, false)
	})
	for _, c := range []struct {
		name  string
		scen  mdbx.SelectedDamageScenario
		kinds []mdbx.EngineClass
	}{{"get-link-eio", mdbx.SelectedDamageGetEIO, []mdbx.EngineClass{mdbx.EngineIO}}, {"getabort-link-eio", mdbx.SelectedDamageGetAbortEIO, []mdbx.EngineClass{mdbx.EngineIO, mdbx.EngineIO}}} {
		t.Run(c.name, func(t *testing.T) {
			// The clear planner's leaving SideLink(2,2) Get faults: its read class branch_data survives (and the first
			// typed result survives a following abort EIO); no write.
			w := rawSideWorld(t, sideFullSpec)
			out, evidence := w.armedProfile(t, c.scen, 6, logicalMDBXMust(mdbx.HeightKey(2, 2)))
			sideWantOutcome(t, out, "LOCAL_RESOURCE_UNAVAILABLE(branch_data)", "OLD", mdbx.CommitTruthOld, mdbx.UpdateStagePrewrite, c.name)
			profileWantNative(t, out.Err, c.name, c.kinds...)
			logicalMDBXAssert(t, evidence.BeginWrite == 0 && evidence.Commits == 0, "%s evidence %+v", c.name, evidence)
			w.reopen()
			w.wantImage(c.name+": image after reopen", w.authority, false)
		})
	}
	t.Run("A9-original-reopen-abortIO", func(t *testing.T) {
		// Same unverified original prestate plus abort EIO: the empty first API classification survives (not storage_io)
		// with the raw ordered InvalidInput then IO causes; the Store is consumed and the next call is the cached raw
		// error with empty fields; the untouched image is read after reopen; the grant is released.
		w := rawSideWorld(t, sideFullSpec)
		w.reopen()
		first, _ := w.armedProfile(t, mdbx.SelectedDamageAbortEIO, 0, nil)
		sideWantOutcome(t, first, "", "OLD", mdbx.CommitTruthOld, mdbx.UpdateStagePrewrite, "unverified owner kept over abort IO")
		profileWantNative(t, first.Err, "unverified owner abort", mdbx.EngineInvalidInput, mdbx.EngineIO)
		next := w.profile()
		sideWantOutcome(t, next, "", "", mdbx.CommitTruthOld, mdbx.UpdateStagePrewrite, "cached next call empty fields")
		logicalMDBXAssert(t, errors.Is(next.Err, first.Err) && errors.Is(first.Err, next.Err), "cached raw error %v, want %v", next.Err, first.Err)
		sideWantReleased(t, w.owner, "unverified owner abort")
		w.reopen()
		w.wantImage("untouched original image after reopen", w.authority, false)
	})
	// armedHeld invokes the real PROFILE once, under one armed scenario, while the full lane is already held, so the
	// capacity refusal takes the grant-free control-only Update.
	armedHeld := func(t *testing.T, w *sideWorld, scenario mdbx.SelectedDamageScenario, rank uint8, key []byte) (selectedSideOutcome, mdbx.SelectedDamageEvidence) {
		t.Helper()
		var out selectedSideOutcome
		calls := 0
		evidence, err := mdbx.FixtureSelectedDamage(w.store, w.owner, scenario, rank, key, func() {
			held := w.owner.WithReservation(mdbx.MaxOperationDataBytes, func() error { calls++; out = w.profile(); return nil })
			logicalMDBXAssert(t, held == nil, "held full lane: %v", held)
		})
		logicalMDBXAssert(t, err == nil && calls == 1, "held PROFILE scenario %d: %v (%+v)", scenario, err, evidence)
		return out, evidence
	}
	t.Run("R-l-control-reads", func(t *testing.T) {
		// The control-only Update reads the authority alone (one rank-0 Get), no index/side evidence, no write.
		w := rawSideWorld(t, sideFullSpec)
		out, evidence := armedHeld(t, w, mdbx.SelectedDamageProbeOnly, 0, nil)
		sideWantOutcome(t, out, "LOCAL_RESOURCE_UNAVAILABLE(storage_capacity)", "OLD", mdbx.CommitTruthOld, mdbx.UpdateStagePrewrite, "control-only capacity")
		logicalMDBXAssert(t, out.Err == nil && evidence.OldGets == [8]uint64{1} && evidence.BeginWrite == 0 && evidence.Commits == 0, "control-only reads %+v (%v)", evidence, out.Err)
		w.wantImage("control-only image", w.authority, false)
		sideWantReleased(t, w.owner, "control-only")
	})
	t.Run("R-l-control-begin-eio", func(t *testing.T) {
		w := rawSideWorld(t, sideFullSpec)
		out, _ := armedHeld(t, w, mdbx.SelectedDamageBeginEIO, 0, nil)
		sideWantOutcome(t, out, "", "", mdbx.CommitTruthOld, mdbx.UpdateStagePrewrite, "control begin failure empty fields")
		profileWantNative(t, out.Err, "control begin", mdbx.EngineIO)
		w.wantConsumed("control begin", out.Err)
		w.reopen()
		w.wantImage("control begin image", w.authority, false)
	})
	t.Run("R-l-control-authority-eio", func(t *testing.T) {
		// The control read's authority Get faults: its own storage_io classification (no capacity, no in-flight
		// artifact class), consumed Store, cached next call with empty fields.
		w := rawSideWorld(t, sideFullSpec)
		first, _ := armedHeld(t, w, mdbx.SelectedDamageGetEIO, 0, []byte{2})
		sideWantOutcome(t, first, "LOCAL_RESOURCE_UNAVAILABLE(storage_io)", "OLD", mdbx.CommitTruthOld, mdbx.UpdateStagePrewrite, "control authority get EIO")
		profileWantNative(t, first.Err, "control authority get EIO", mdbx.EngineIO)
		next := w.profile()
		sideWantOutcome(t, next, "", "", mdbx.CommitTruthOld, mdbx.UpdateStagePrewrite, "control cached next call")
		logicalMDBXAssert(t, errors.Is(next.Err, first.Err) && errors.Is(first.Err, next.Err), "cached raw error %v, want %v", next.Err, first.Err)
		w.reopen()
		w.wantImage("control authority get image", w.authority, false)
	})
	t.Run("R-l-control-abortIO", func(t *testing.T) {
		// The capacity sentinel plus abort EIO: storage_io (never storage_capacity) with the raw join, consumed Store,
		// cached next call with empty fields, OLD image after reopen, grant released.
		w := rawSideWorld(t, sideFullSpec)
		first, _ := armedHeld(t, w, mdbx.SelectedDamageAbortEIO, 0, nil)
		sideWantOutcome(t, first, "LOCAL_RESOURCE_UNAVAILABLE(storage_io)", "OLD", mdbx.CommitTruthOld, mdbx.UpdateStagePrewrite, "capacity sentinel abort storage_io")
		profileWantNative(t, first.Err, "capacity sentinel abort", mdbx.EngineIO)
		next := w.profile()
		sideWantOutcome(t, next, "", "", mdbx.CommitTruthOld, mdbx.UpdateStagePrewrite, "capacity abort cached next call")
		logicalMDBXAssert(t, errors.Is(next.Err, first.Err) && errors.Is(first.Err, next.Err), "cached raw error %v, want %v", next.Err, first.Err)
		sideWantReleased(t, w.owner, "capacity abort")
		w.reopen()
		w.wantImage("capacity abort image after reopen", w.authority, false)
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
