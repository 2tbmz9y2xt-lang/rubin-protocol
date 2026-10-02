//go:build cgo && (darwin || linux) && (amd64 || arm64)

package consensus

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/mdbx"
)

// setAuthority rewrites the committed authority through edit and tracks its exact new bytes.
func (w *sideWorld) setAuthority(edit func(*mdbx.StorageAuthorityV1)) {
	w.t.Helper()
	a, err := mdbx.DecodeStorageAuthorityV1(w.authority)
	logicalMDBXAssert(w.t, err == nil, "side world authority decode: %v", err)
	edit(&a)
	encoded, err := a.Encode()
	logicalMDBXAssert(w.t, err == nil, "side world authority encode: %v", err)
	w.authority = encoded
	w.apply(mdbx.Mutation{DBI: logicalMDBXDBIs[0], Key: []byte{2}, BeforePresent: true, AfterKind: mdbx.AfterLiteral, Literal: encoded})
}

// profileAuthority is the spec's cleared authority (no selected side, PRUNE_GC, SIDE(g,first,tip,first)) with the
// PROFILE effect: RECOVERY_REQUIRED and a pending ARCHIVE target; PRUNED stays active, B/U/generations/next unchanged.
func (w *sideWorld) profileAuthority() []byte {
	w.t.Helper()
	a, err := mdbx.DecodeStorageAuthorityV1(w.clearedAuthority())
	logicalMDBXAssert(w.t, err == nil, "cleared authority decode: %v", err)
	archive := mdbx.StorageProfileArchiveV1
	a.Lifecycle, a.PendingTargetProfile = mdbx.StorageLifecycleRecoveryRequiredV1, &archive
	encoded, err := a.Encode()
	logicalMDBXAssert(w.t, err == nil, "profile authority encode: %v", err)
	return encoded
}

func (w *sideWorld) profile() selectedSideOutcome {
	return SelectArchiveSelectedSideMDBX(w.store, w.owner)
}

// profileWantDecision requires an exact clean no-write decision: Result, OLD/Prewrite, nil Err, unchanged image and a
// released grant.
func profileWantDecision(t *testing.T, w *sideWorld, result, label string) {
	t.Helper()
	out := w.profile()
	sideWantOutcome(t, out, result, "OLD", mdbx.CommitTruthOld, mdbx.UpdateStagePrewrite, label)
	logicalMDBXAssert(t, out.Err == nil, "%s: decision kept an error: %v", label, out.Err)
	w.wantImage(label, w.authority, false)
	sideWantReleased(t, w.owner, label)
}

// profileWantLeaf requires another leaf's exact update API refusal: empty Result, OLD/Prewrite, the raw
// StateMismatch/update/MDBX_PROBLEM error with its literal diagnostic, unchanged image and a released grant.
func profileWantLeaf(t *testing.T, w *sideWorld, out selectedSideOutcome, diagnostic, label string) {
	t.Helper()
	sideWantOutcome(t, out, "", "OLD", mdbx.CommitTruthOld, mdbx.UpdateStagePrewrite, label)
	// Mutual errors.Is with the found EngineError holds only when the raw error is that exact direct refusal.
	var engine *mdbx.EngineError
	ok := errors.As(out.Err, &engine) && errors.Is(out.Err, engine) && errors.Is(engine, out.Err)
	logicalMDBXAssert(t, ok && engine.Class == mdbx.EngineStateMismatch && engine.Operation == "update" && engine.Code == -30_779 && engine.Diagnostic == diagnostic, "%s: error %v", label, out.Err)
	sideWantReleased(t, w.owner, label)
}

func TestArchiveSelectedSide(t *testing.T) {
	selected := func(t *testing.T, w *sideWorld, label string) {
		t.Helper()
		out := w.profile()
		sideWantOutcome(t, out, "", "NEW", mdbx.CommitTruthNew, mdbx.UpdateStageCommitMayHaveCrossed, label+": clean PROFILE NEW")
		logicalMDBXAssert(t, out.Err == nil, "%s: clean PROFILE kept an error: %v", label, out.Err)
		want := w.profileAuthority()
		w.wantImage(label+": pending ARCHIVE exact image", want, true)
		a, err := mdbx.DecodeStorageAuthorityV1(want)
		logicalMDBXAssert(t, err == nil && a.ActiveProfile == mdbx.StorageProfilePrunedV1 && a.NextGenerationID == w.nextID() && a.Replay == nil && a.ActiveGenerationID == 1,
			"%s: no target/id/next preserved: %+v (%v)", label, a, err)
		sideWantReleased(t, w.owner, label)
		w.reopen()
		w.wantImage(label+": persisted image after reopen", want, true)
		// A9: the next PROFILE on the reopened handle stops at RECOVERY_REQUIRED before any identity or owner read.
		next := w.profile()
		sideWantOutcome(t, next, "RECOVERY_REQUIRED", "OLD", mdbx.CommitTruthOld, mdbx.UpdateStagePrewrite, label+": next operation after reopen")
		logicalMDBXAssert(t, next.Err == nil, "%s: next operation kept an error: %v", label, next.Err)
		w.wantImage(label+": next operation leaves the image", want, true)
		sideWantReleased(t, w.owner, label+": next operation")
	}
	t.Run("A8a", func(t *testing.T) {
		// Published genesis plus canonical 1..500 (H500), side generation 4 rows 491..495 over F490, next 6:
		// SIDE(4,491,495,491), pending ARCHIVE, PRUNE_GC/RECOVERY_REQUIRED, PRUNED active, next 6, no replay; unkept side
		// headers deleted, side bodies/links and every canonical row (genesis undo/UTXO/counters included) kept.
		w := newSideWorld(t, sideWorldSpec{f: 490, tip: 495, rows: 5, canonicalTip: 500, generation: 4, next: 6, published: true})
		selected(t, w, "A8a")
		a, err := mdbx.DecodeStorageAuthorityV1(w.profileAuthority())
		span := mdbx.CleanupSpanV1{Kind: mdbx.CleanupSpanSideV1, GenerationID: 4, FirstHeight: 491, LastHeight: 495, NextHeight: 491}
		logicalMDBXAssert(t, err == nil && a.NextGenerationID == 6 && a.SelectedSide == nil && len(a.Cleanup.Spans) == 1 && a.Cleanup.Spans[0] == span && *a.PendingTargetProfile == mdbx.StorageProfileArchiveV1,
			"pending ARCHIVE exact image: %+v (%v)", a, err)
	})
	t.Run("A8a-kept", func(t *testing.T) {
		// Side row 2 names the canonical block at 2 (override): its header is canonically kept, the others deleted.
		w := newSideWorld(t, sideWorldSpec{f: 1, tip: 4, rows: 3, canonicalTip: 2, override: map[uint64]uint64{2: 2}})
		selected(t, w, "A8a-kept")
	})
	t.Run("A8b", func(t *testing.T) {
		// Cleaned one-slot 2..1440 (F0, C1440, count 1439): SIDE(2,2,1440,2), otherwise A8a.
		selected(t, newSideWorld(t, sideWorldSpec{f: 0, tip: 1_440, rows: 1_439, canonicalTip: 1}), "A8b")
	})
	t.Run("R-o1", func(t *testing.T) {
		// Prepared PRUNE_GC/STABLE H>0 (one-slot side with its SIDE(first-1)): LOCAL_BUSY, the Prepared image stays.
		profileWantDecision(t, newSideWorld(t, sideWorldSpec{f: 0, tip: 1_440, rows: 1_439, canonicalTip: 1, pendingSide: true}), "LOCAL_BUSY", "LOCAL_BUSY/exact Prepared image")
	})
	t.Run("R-o2", func(t *testing.T) {
		// Active ARCHIVE NONE/STABLE with a selected side: PROFILE_NOOP before any identity read.
		w := newSideWorld(t, sideFullSpec)
		w.setAuthority(func(a *mdbx.StorageAuthorityV1) { a.ActiveProfile = mdbx.StorageProfileArchiveV1 })
		profileWantDecision(t, w, "PROFILE_NOOP", "active ARCHIVE PROFILE_NOOP")
	})
	t.Run("R-o3", func(t *testing.T) {
		// Prepared PRUNE_GC/RECOVERY_REQUIRED with a pending ARCHIVE target, active PRUNED and active ARCHIVE (B/U 0): in
		// the ARCHIVE prestate both the non-STABLE and the active-ARCHIVE predicates hold, so RECOVERY_REQUIRED must be
		// checked before the PROFILE_NOOP.
		for _, active := range []mdbx.StorageProfileV1{mdbx.StorageProfilePrunedV1, mdbx.StorageProfileArchiveV1} {
			w := newSideWorld(t, sideWorldSpec{f: 0, tip: 1_440, rows: 1_439, canonicalTip: 1, pendingSide: true})
			w.setAuthority(func(a *mdbx.StorageAuthorityV1) {
				archive := mdbx.StorageProfileArchiveV1
				a.ActiveProfile, a.Lifecycle, a.PendingTargetProfile = active, mdbx.StorageLifecycleRecoveryRequiredV1, &archive
			})
			profileWantDecision(t, w, "RECOVERY_REQUIRED", "RECOVERY_REQUIRED precedes noop")
		}
	})
	t.Run("R-o4", func(t *testing.T) {
		// ORDINARY_APPLY/RECOVERY_REQUIRED: RECOVERY_REQUIRED, never recovery_artifact.
		w := newSideWorld(t, sideFullSpec)
		w.setAuthority(func(a *mdbx.StorageAuthorityV1) {
			oldPoint, newPoint := mdbx.AuthorityPointV1{Height: 5, BlockHash: [32]byte{0x51}}, mdbx.AuthorityPointV1{Height: 5, BlockHash: [32]byte{0x52}}
			a.Phase, a.Lifecycle, a.SelectedSide = mdbx.StoragePhaseOrdinaryApplyV1, mdbx.StorageLifecycleRecoveryRequiredV1, nil
			a.Ordinary = &mdbx.OrdinaryApplyV1{
				Stage: mdbx.OrdinaryStageDisconnectV1, Target: newPoint, OldSuffix: []mdbx.AuthorityPointV1{oldPoint}, NewSuffix: []mdbx.AuthorityPointV1{newPoint},
				CapturedSelectedSide: &mdbx.SelectedSideV1{GenerationID: 2, F: 4, TipHeight: 5, TipHash: newPoint.BlockHash, CumulativeChainwork: sideWorldWork(1), RowCount: 1, LogicalBytes: 1},
			}
		})
		profileWantDecision(t, w, "RECOVERY_REQUIRED", "profile RECOVERY_REQUIRED")
	})
	t.Run("R-domain-profile-h0", func(t *testing.T) {
		// H0 (canonical index row 0 only) under PRUNE_GC (obsolete g3, next 4): the wrong-leaf refusal, not LOCAL_BUSY.
		w := newSideWorld(t, sideWorldSpec{f: 0, tip: 1, rows: 1, canonicalTip: 0})
		w.setAuthority(func(a *mdbx.StorageAuthorityV1) {
			a.NextGenerationID, a.Phase = 4, mdbx.StoragePhasePruneGCV1
			a.Cleanup = &mdbx.CleanupV1{Spans: []mdbx.CleanupSpanV1{{Kind: mdbx.CleanupSpanGenerationV1, GenerationID: 3}}}
		})
		profileWantLeaf(t, w, w.profile(), "archive at or before genesis belongs to SelectArchiveProfileV1", "exact StateMismatch/empty Result/raw API error")
		w.wantImage("H0 wrong leaf image", w.authority, false)
	})
	t.Run("R-domain-profile-pregenesis", func(t *testing.T) {
		// A bootstrapped PRE_GENESIS store (no canonical row): the same wrong-leaf refusal.
		store, err := mdbx.Create(filepath.Join(t.TempDir(), "db"), sideWorldConfig)
		logicalMDBXAssert(t, err == nil, "create: %v", err)
		t.Cleanup(func() { _ = store.Close() })
		owner, err := mdbx.NewOperationReservationOwner(mdbx.MaxOperationDataBytes)
		logicalMDBXAssert(t, err == nil, "owner: %v", err)
		truth, _, err := store.BootstrapStorageV1(mdbx.StorageProfilePrunedV1, owner)
		logicalMDBXAssert(t, err == nil && truth == mdbx.CommitTruthNew, "bootstrap: %v/%v", truth, err)
		w := &sideWorld{t: t, store: store, owner: owner}
		profileWantLeaf(t, w, w.profile(), "archive at or before genesis belongs to SelectArchiveProfileV1", "PRE_GENESIS wrong leaf")
	})
	t.Run("R-domain-profile-noside", func(t *testing.T) {
		// H>0 NONE/STABLE without a selected side: the replay-entry leaf's exact refusal.
		w := newSideWorld(t, sideFullSpec)
		w.setAuthority(func(a *mdbx.StorageAuthorityV1) { a.SelectedSide = nil })
		profileWantLeaf(t, w, w.profile(), "archive without selected side belongs to replay entry", "H>0 no-side wrong leaf")
		w.wantImage("no-side wrong leaf image", w.authority, false)
	})
	t.Run("R-domain-profile-work", func(t *testing.T) {
		// A genesis index entry with zero work: canonical integrity from the identity page, before any later decision.
		w := newSideWorld(t, sideFullSpec)
		w.setEntry(0, [32]byte{}, [40]byte{})
		out := w.profile()
		sideWantCause(t, out, "invalid archive profile genesis work", "first-work integrity")
		w.wantImage("first-work integrity image", w.authority, false)
	})
	t.Run("R-domain-profile-height", func(t *testing.T) {
		// The genesis index entry removed: the page's first row is height 1, canonical integrity.
		w := newSideWorld(t, sideFullSpec)
		w.remove(2, logicalMDBXMust(mdbx.HeightKey(1, 0)))
		w.entries[0] = nil
		sideWantCause(t, w.profile(), "archive canonical index does not start at genesis", "first-height integrity")
		w.wantImage("first-height integrity image", w.authority, false)
	})
	t.Run("R-domain-profile-upper-work", func(t *testing.T) {
		// Genesis work with byte 3 = 2 (40-byte big-endian) is exactly 2^289, above the 2^288 domain: canonical integrity.
		w := newSideWorld(t, sideFullSpec)
		var work [40]byte
		work[3] = 2
		w.setEntry(0, [32]byte{}, work)
		sideWantCause(t, w.profile(), "invalid archive profile genesis work", "upper-work integrity")
		w.wantImage("upper-work integrity image", w.authority, false)
	})
	t.Run("A9-original-reopen", func(t *testing.T) {
		// The eligible NONE/STABLE PRUNED H>0 prestate reopened before the first public PROFILE (no verification): the
		// clear planner's leaving-row CanonicalOwner is the direct unclassified get EINVAL, empty Result, OLD/Prewrite,
		// no effect and a released grant.
		w := newSideWorld(t, sideFullSpec)
		w.reopen()
		out := w.profile()
		sideWantOutcome(t, out, "", "OLD", mdbx.CommitTruthOld, mdbx.UpdateStagePrewrite, "unverified owner on the original prestate")
		var engine *mdbx.EngineError
		logicalMDBXAssert(t, errors.As(out.Err, &engine) && errors.Is(out.Err, engine) && errors.Is(engine, out.Err) && engine.Class == mdbx.EngineInvalidInput &&
			engine.Operation == "get" && engine.Code == 22 && engine.Diagnostic == "canonical owner index is not verified", "unverified owner raw error %v", out.Err)
		w.wantImage("unverified owner leaves the original image", w.authority, false)
		sideWantReleased(t, w.owner, "unverified owner")
	})
	t.Run("R-domain-profile-max-work", func(t *testing.T) {
		// H0 whose genesis work is exactly 2^288 (byte 3 = 1), the inclusive domain maximum: the identity is legal H0 and
		// stops at the wrong-leaf refusal, not canonical integrity.
		w := newSideWorld(t, sideWorldSpec{f: 0, tip: 1, rows: 1, canonicalTip: 0})
		var work [40]byte
		work[3] = 1
		w.setEntry(0, [32]byte{}, work)
		profileWantLeaf(t, w, w.profile(), "archive at or before genesis belongs to SelectArchiveProfileV1", "max-work H0 wrong leaf")
		w.wantImage("max-work H0 image", w.authority, false)
	})
	t.Run("inputs", func(t *testing.T) {
		// A nil Store is the Store's direct nil-Store refusal before any grant with every owner: valid, nil, zero and a
		// valid owner whose full lane is already held.
		owner, err := mdbx.NewOperationReservationOwner(mdbx.MaxOperationDataBytes)
		logicalMDBXAssert(t, err == nil, "owner: %v", err)
		nilStore := func(o *mdbx.OperationReservationOwner, label string) {
			t.Helper()
			out := SelectArchiveSelectedSideMDBX(nil, o)
			sideWantOutcome(t, out, "", "", mdbx.CommitTruthOld, mdbx.UpdateStagePrewrite, label)
			sideWantEngine(t, out.Err, mdbx.EngineInvalidInput, "nil Store", label)
		}
		nilStore(owner, "nil Store, valid owner")
		nilStore(nil, "nil Store, nil owner")
		nilStore(&mdbx.OperationReservationOwner{}, "nil Store, zero owner")
		held := owner.WithReservation(mdbx.MaxOperationDataBytes, func() error { nilStore(owner, "nil Store, held owner"); return nil })
		logicalMDBXAssert(t, held == nil, "held full lane: %v", held)
		sideWantReleased(t, owner, "nil Store")
		// A valid Store with a nil or zero owner returns that owner's own input refusal, and with the full lane already held
		// the owner's exact capacity refusal; no Update, empty fields, image unchanged.
		w := newSideWorld(t, sideFullSpec)
		for _, o := range []*mdbx.OperationReservationOwner{nil, {}} {
			want := o.WithReservation(mdbx.MaxOperationDataBytes, func() error { return nil })
			out := SelectArchiveSelectedSideMDBX(w.store, o)
			sideWantOutcome(t, out, "", "", mdbx.CommitTruthOld, mdbx.UpdateStagePrewrite, "owner input refusal")
			logicalMDBXAssert(t, want != nil && out.Err != nil && out.Err.Error() == want.Error() && errors.Is(out.Err, want), "owner input refusal %v, want %v", out.Err, want)
		}
		var out selectedSideOutcome
		held = w.owner.WithReservation(mdbx.MaxOperationDataBytes, func() error { out = w.profile(); return nil })
		logicalMDBXAssert(t, held == nil, "held full lane: %v", held)
		sideWantOutcome(t, out, "", "", mdbx.CommitTruthOld, mdbx.UpdateStagePrewrite, "capacity refusal")
		logicalMDBXAssert(t, out.Err != nil && out.Err.Error() == selectedSideCapacityText, "capacity refusal %v", out.Err)
		w.wantImage("owner refusals leave the image", w.authority, false)
		sideWantReleased(t, w.owner, "owner refusals")
	})
}
