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

// profileAuthority is the spec's cleared authority (no selected side, PRUNE_GC, SIDE(2,first,tip,first)) with the
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
		logicalMDBXAssert(t, err == nil && a.ActiveProfile == mdbx.StorageProfilePrunedV1 && a.NextGenerationID == 3 && a.Replay == nil && a.ActiveGenerationID == 1,
			"%s: no target/id/next preserved: %+v (%v)", label, a, err)
		sideWantReleased(t, w.owner, label)
		w.reopen()
		w.wantImage(label+": persisted image after reopen", want, true)
	}
	t.Run("A8a", func(t *testing.T) {
		// NONE/STABLE PRUNED H500 with side 491..495 (F490): SIDE(2,491,495,491), pending ARCHIVE, PRUNE_GC/RECOVERY_REQUIRED;
		// unkept side headers deleted, bodies/links and every canonical row kept.
		selected(t, newSideWorld(t, sideWorldSpec{f: 490, tip: 495, rows: 5, canonicalTip: 500}), "A8a")
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
		// PRUNE_GC/RECOVERY_REQUIRED with a pending ARCHIVE target: RECOVERY_REQUIRED precedes any noop.
		w := newSideWorld(t, sideWorldSpec{f: 0, tip: 1_440, rows: 1_439, canonicalTip: 1, pendingSide: true})
		w.setAuthority(func(a *mdbx.StorageAuthorityV1) {
			archive := mdbx.StorageProfileArchiveV1
			a.Lifecycle, a.PendingTargetProfile = mdbx.StorageLifecycleRecoveryRequiredV1, &archive
		})
		profileWantDecision(t, w, "RECOVERY_REQUIRED", "RECOVERY_REQUIRED precedes noop")
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
	t.Run("inputs", func(t *testing.T) {
		owner, err := mdbx.NewOperationReservationOwner(mdbx.MaxOperationDataBytes)
		logicalMDBXAssert(t, err == nil, "owner: %v", err)
		out := SelectArchiveSelectedSideMDBX(nil, owner)
		sideWantOutcome(t, out, "", "", mdbx.CommitTruthOld, mdbx.UpdateStagePrewrite, "nil Store")
		sideWantEngine(t, out.Err, mdbx.EngineInvalidInput, "nil Store", "nil Store")
		sideWantReleased(t, owner, "nil Store")
	})
}
