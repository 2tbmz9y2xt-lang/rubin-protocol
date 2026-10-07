//go:build rubin_mdbx_fixture && cgo && (darwin || linux) && (amd64 || arm64)

package consensus

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/mdbx"
)

// replayArmed runs one entry under an armed selected-damage scenario and returns its outcome and evidence.
func replayArmed(t *testing.T, w *replayWorld, view HeaderCandidateViewV1, scenario mdbx.SelectedDamageScenario, rank uint8, key []byte) (ReplayEntryOutcomeV1, mdbx.SelectedDamageEvidence) {
	t.Helper()
	var out ReplayEntryOutcomeV1
	evidence, err := mdbx.FixtureSelectedDamage(w.store, w.owner, scenario, rank, key, func() { out = w.enter(view, w.genesis) })
	logicalMDBXAssert(t, err == nil, "fixture %d: %v", scenario, err)
	return out, evidence
}

// replayEngineClass asserts the raw Err is itself a *mdbx.EngineError of class (a wrapped or joined value fails).
func replayEngineClass(t *testing.T, err error, class mdbx.EngineClass, label string) {
	t.Helper()
	var e *mdbx.EngineError
	raw := fmt.Sprintf("%T", err) == "*mdbx.EngineError" && errors.As(err, &e) // As on the raw type yields err itself
	logicalMDBXAssert(t, raw && e.Class == class, "%s: raw class %T %v", label, err, err)
}

// replayConsumed asserts the Store is consumed: a further Update on the same handle runs no callback and returns the
// Store's terminal error, the entry's raw Err.
func replayConsumed(t *testing.T, store *mdbx.Store, raw error, label string) {
	t.Helper()
	ran := false
	_, stage, err := store.Update(func(*mdbx.Reader) (mdbx.Batch, error) { ran = true; return mdbx.Batch{}, errors.New("probe") })
	logicalMDBXAssert(t, !ran && stage == mdbx.UpdateStagePrewrite && replaySameErr(err, raw), "%s: Store not consumed: ran=%v %T %v", label, ran, err, err)
}

// replayLatched asserts the latch: the next entry on the same handle runs no callback and returns the cached Err.
func replayLatched(t *testing.T, w *replayWorld, raw error, label string) {
	t.Helper()
	view := &replayView{inv: replayComplete(nil, nil)}
	again := w.enter(view, w.genesis)
	logicalMDBXAssert(t, view.calls == 0 && len(view.versions) == 0 && replaySameErr(again.Err, raw), "%s: not latched: %+v calls %d", label, again, view.calls)
}

// replayEntryWorld is canonical 0..3 under pending PRUNED with one received tip at 4 (the eligible target).
func replayEntryWorld(t *testing.T) (*replayWorld, *replayView) {
	w := pendingWorld(t, 3)
	headers, hashes := w.fork(3, 1, 1)
	return w, &replayView{inv: replayComplete([][32]byte{hashes[0]}, headers)}
}

// R7, A32: exhaustion attempts no write transaction; a committed entry at H = 7 makes no mdbx_get on the canonical-owner
// DBI (OldGets[7] = 0).
func TestReplayEntryFixtureNoWrite(t *testing.T) {
	w, view := replayEntryWorld(t)
	w.setAuthority(func(a *mdbx.StorageAuthorityV1) { a.NextGenerationID = 1<<64 - 1 })
	image := w.image()
	out, evidence := replayArmed(t, w, view, mdbx.SelectedDamageProbeOnly, 0, nil)
	replayDecided(t, out, selectedSideInvariant, "", "R7")
	replaySameImage(t, image, w.image(), "R7")
	logicalMDBXAssert(t, evidence.BeginWrite == 0 && evidence.Commits == 0, "R7 evidence: %+v", evidence)
	// A32 at canonical H = 7 with one received tip at 8.
	w = pendingWorld(t, 7)
	headers, hashes := w.fork(7, 1, 1)
	view, before := &replayView{inv: replayComplete([][32]byte{hashes[0]}, headers)}, w.snapshot()
	out, evidence = replayArmed(t, w, view, mdbx.SelectedDamageProbeOnly, 0, nil)
	logicalMDBXAssert(t, evidence.OldGets[7] == 0 && evidence.Commits == 1, "A32 evidence: %+v %+v", out, evidence)
	replayCommitted(t, w, out, before, mdbx.StorageProfilePrunedV1, hashes[0], 8, 9)
}

// replayProbed runs a held entry under SelectedDamageProbeOnly and asserts no write transaction and no commit.
func replayProbed(t *testing.T, w *replayWorld, view HeaderCandidateViewV1, hold uint64, label string) ReplayEntryOutcomeV1 {
	t.Helper()
	var out ReplayEntryOutcomeV1
	image := w.image()
	evidence, err := mdbx.FixtureSelectedDamage(w.store, w.owner, mdbx.SelectedDamageProbeOnly, 0, nil, func() { out = w.held(view, w.genesis, hold) })
	logicalMDBXAssert(t, err == nil && evidence.BeginWrite == 0 && evidence.Commits == 0 && evidence.Faults == 0, "%s evidence: %v %+v", label, err, evidence)
	replaySameImage(t, image, w.image(), label)
	return out
}

// R42, R43, R44, R47 under SelectedDamageProbeOnly with a refused full-lane grant: the evidence shows no write
// transaction and no commit (R45 is TestReplayEntryFixtureIllegalReplay).
func TestReplayEntryFixtureControlEvidence(t *testing.T) {
	view := &replayView{inv: replayComplete(nil, nil)}
	w, entry := replayEntryWorld(t)
	logicalMDBXAssert(t, w.enter(entry, w.genesis).Truth == mdbx.CommitTruthNew, "R42 REPLAY")
	out := replayProbed(t, w, view, 1, "R42")
	replayDecided(t, out, "", replayEntryResume, "R42 resume")
	w = newReplayWorld(t, 3)
	w.setAuthority(func(a *mdbx.StorageAuthorityV1) {
		a.NextGenerationID, a.Phase, a.Cleanup = 3, mdbx.StoragePhasePruneGCV1, &mdbx.CleanupV1{Spans: []mdbx.CleanupSpanV1{{Kind: mdbx.CleanupSpanGenerationV1, GenerationID: 2}}}
		pruned := mdbx.StorageProfilePrunedV1
		a.Lifecycle, a.PendingTargetProfile = mdbx.StorageLifecycleRecoveryRequiredV1, &pruned
	})
	out = replayProbed(t, w, view, 1, "R43")
	replayDecided(t, out, "", replayEntryNotEligible, "R43 PRUNE_GC")
	w = newReplayWorld(t, -1)
	out = replayProbed(t, w, view, 1, "R44")
	replayDecided(t, out, "", replayEntryGenesisFirst, "R44 genesis first")
	out = replayProbed(t, w, view, mdbx.MaxOperationDataBytes, "R47")
	replayDecided(t, out, selectedSideCapacity, "", "R47 control charge refused")
	logicalMDBXAssert(t, view.calls == 0, "R42-R47 inventory calls %d", view.calls)
	// R6: exhausted sequence under a refused grant: the control-only Update runs (one OLD read transaction) and reads
	// no header row (rank 3).
	w = pendingWorld(t, 3)
	w.pending(mdbx.StorageProfilePrunedV1, 1<<64-1)
	image := w.image()
	evidence, err := mdbx.FixtureSelectedDamage(w.store, w.owner, mdbx.SelectedDamageProbeOnly, 0, nil, func() { out = w.held(view, w.genesis, 1) })
	replayDecided(t, out, selectedSideCapacity, "", "R6 exhausted, grant refused")
	replaySameImage(t, image, w.image(), "R6")
	logicalMDBXAssert(t, err == nil && evidence.BeginOld == 1 && evidence.OldGets[3] == 0 && evidence.BeginWrite == 0 && evidence.Commits == 0 && view.calls == 0, "R6 evidence: %v %+v", err, evidence)
	// Selectivity: the same world with the grant admitted walks the headers, so OldGets[3] = 0 above is live.
	w = pendingWorld(t, 3)
	w.pending(mdbx.StorageProfilePrunedV1, 1<<64-1)
	evidence, err = mdbx.FixtureSelectedDamage(w.store, w.owner, mdbx.SelectedDamageProbeOnly, 0, nil, func() { w.held(view, w.genesis, 0) })
	logicalMDBXAssert(t, err == nil && evidence.OldGets[3] > 0, "R6 control: granted run reads no header: %v %+v", err, evidence)
}

// R9: the write-transaction begin fails after a successful sequence check: storage_transaction, image unchanged.
func TestReplayEntryFixtureWriteBegin(t *testing.T) {
	w, view := replayEntryWorld(t)
	image := w.image()
	out, evidence := replayArmed(t, w, view, mdbx.SelectedDamageWriteBeginTxnFull, 0, nil)
	logicalMDBXAssert(t, out.Result == "LOCAL_RESOURCE_UNAVAILABLE(storage_transaction)" && out.Truth == mdbx.CommitTruthOld && out.Stage == mdbx.UpdateStagePrewrite &&
		out.CanonicalTruth == "OLD" && evidence.BeginWrite == 1 && evidence.Faults == 1 && evidence.Commits == 0, "R9: %+v %+v", out, evidence)
	replayEngineClass(t, out.Err, mdbx.EngineTransaction, "R9")
	replayConsumed(t, w.store, out.Err, "R9")
	w.store = w.reopen()
	replaySameImage(t, image, w.image(), "R9")
	replayNoLatch(t, w, "R9")
}

// R60: the Update's read-transaction begin fails before the callback (never-run cells).
func TestReplayEntryFixtureBegin(t *testing.T) {
	for _, c := range []struct {
		scenario mdbx.SelectedDamageScenario
		class    mdbx.EngineClass
		result   string
	}{{mdbx.SelectedDamageBeginEIO, mdbx.EngineIO, "LOCAL_RESOURCE_UNAVAILABLE(storage_io)"}, {mdbx.SelectedDamageBeginTxnFull, mdbx.EngineTransaction, "LOCAL_RESOURCE_UNAVAILABLE(storage_transaction)"}} {
		w, view := replayEntryWorld(t)
		image := w.image()
		out, evidence := replayArmed(t, w, view, c.scenario, 0, nil)
		logicalMDBXAssert(t, out.Result == c.result && out.Decision == "" && out.Replay == nil && out.CanonicalTruth == "OLD" && out.Truth == mdbx.CommitTruthOld &&
			out.Stage == mdbx.UpdateStagePrewrite && evidence.Faults == 1 && evidence.BeginOld == 1 && evidence.BeginWrite == 0 && view.calls == 0, "R60 %d: %+v %+v", c.scenario, out, evidence)
		replayEngineClass(t, out.Err, c.class, "R60")
		replayConsumed(t, w.store, out.Err, "R60")
		w.store = w.reopen()
		replaySameImage(t, image, w.image(), "R60")
		replayNoLatch(t, w, "R60")
	}
}

// R35: a transient canonical header read failure during the walk is recovery_artifact.
func TestReplayEntryFixtureHeaderEIO(t *testing.T) {
	w, view := replayEntryWorld(t)
	image := w.image()
	out, evidence := replayArmed(t, w, view, mdbx.SelectedDamageGetEIO, 3, w.hashes[2][:])
	logicalMDBXAssert(t, out.Result == replayEntryRecovery && out.CanonicalTruth == "OLD" && out.Truth == mdbx.CommitTruthOld && out.Stage == mdbx.UpdateStagePrewrite, "R35: %+v", out)
	// The fault is the walk's own header read in the old transaction; no write transaction begins.
	logicalMDBXAssert(t, evidence.Faults == 1 && evidence.BeginOld == 1 && evidence.OldGets[3] >= 1 && evidence.BeginWrite == 0 && evidence.Commits == 0, "R35 evidence: %+v", evidence)
	replayEngineClass(t, out.Err, mdbx.EngineIO, "R35")
	replayConsumed(t, w.store, out.Err, "R35")
	w.store = w.reopen()
	replaySameImage(t, image, w.image(), "R35 no target, cursor or exclusion change")
}

// H9, H12, H13, H14: possibly crossed entry commits classified by strict readback.
func TestReplayEntryFixtureCrossed(t *testing.T) {
	for _, c := range []struct {
		scenario mdbx.SelectedDamageScenario
		truth    mdbx.CommitTruth
		result   string
		canon    string
		faults   uint64
		image    string // persisted image after reopen: pre-image, committed image, or committed with authority 0x7f
	}{
		{mdbx.SelectedDamageCommitOld, mdbx.CommitTruthOld, "TERMINAL_PERSISTENCE(old)", "OLD", 1, "pre"},
		{mdbx.SelectedDamageCommitNew, mdbx.CommitTruthNew, "TERMINAL_PERSISTENCE(new)", "NEW", 1, "post"},
		{mdbx.SelectedDamageCommitUnreadable, mdbx.CommitTruthUnknown, "TERMINAL_PERSISTENCE(neither_or_unreadable)", "UNKNOWN", 2, "post"},
		{mdbx.SelectedDamageCommitThird, mdbx.CommitTruthUnknown, "TERMINAL_PERSISTENCE(neither_or_unreadable)", "UNKNOWN", 1, "third"},
	} {
		control, controlView := replayEntryWorld(t)
		logicalMDBXAssert(t, control.enter(controlView, control.genesis).Truth == mdbx.CommitTruthNew, "control commit")
		post := control.image()
		w, view := replayEntryWorld(t)
		pre := w.image()
		out, evidence := replayArmed(t, w, view, c.scenario, 0, []byte{2})
		// One write transaction, one commit and one readback transaction; the unreadable readback faults its read.
		logicalMDBXAssert(t, evidence.Faults == c.faults && evidence.BeginWrite == 1 && evidence.Commits == 1 && evidence.BeginRead == 1 &&
			(c.scenario != mdbx.SelectedDamageCommitUnreadable || evidence.ReadGets >= 1), "crossed %d evidence: %+v", c.scenario, evidence)
		logicalMDBXAssert(t, out.Stage == mdbx.UpdateStageCommitMayHaveCrossed && out.Truth == c.truth && out.Result == c.result && out.CanonicalTruth == c.canon && out.Err != nil &&
			(out.Replay != nil) == (c.truth == mdbx.CommitTruthNew), "crossed %d: %+v", c.scenario, out)
		replayCrossedErr(t, out.Err, c.truth, c.scenario == mdbx.SelectedDamageCommitUnreadable)
		if c.scenario == mdbx.SelectedDamageCommitOld {
			replayLatched(t, w, out.Err, "H9")
		}
		w.store = w.reopen()
		want := map[string][]mdbx.PrefixRow{"pre": pre, "post": post, "third": replayThirdImage(post)}[c.image]
		replaySameImage(t, want, w.image(), fmt.Sprintf("crossed %d persisted", c.scenario))
		if c.truth == mdbx.CommitTruthNew {
			// H12: the persisted authority is the planned REPLAY/RECOVERY_REQUIRED image.
			a := w.authority()
			logicalMDBXAssert(t, a.Phase == mdbx.StoragePhaseReplayV1 && a.Lifecycle == mdbx.StorageLifecycleRecoveryRequiredV1 && a.Replay != nil && *a.Replay == *out.Replay, "H12 persisted: %+v", a)
		}
	}
}

// replayCrossedErr asserts the raw crossed-commit Err: a *mdbx.CommitError with the outcome Truth, the commit's raw
// EngineCapacity Cause and a raw EngineIO ReadbackCause only when the readback is unreadable.
func replayCrossedErr(t *testing.T, err error, truth mdbx.CommitTruth, unreadable bool) {
	t.Helper()
	var ce *mdbx.CommitError
	logicalMDBXAssert(t, fmt.Sprintf("%T", err) == "*mdbx.CommitError" && errors.As(err, &ce) && ce.Truth == truth, "crossed raw Err %T %v", err, err)
	replayEngineClass(t, ce.Cause, mdbx.EngineCapacity, "crossed commit cause")
	if unreadable {
		replayEngineClass(t, ce.ReadbackCause, mdbx.EngineIO, "crossed readback cause")
		return
	}
	logicalMDBXAssert(t, ce.ReadbackCause == nil, "crossed readback cause %v", ce.ReadbackCause)
}

// replayThirdImage is the committed image with the authority row (meta key 02) replaced by the third value 0x7f.
func replayThirdImage(post []mdbx.PrefixRow) []mdbx.PrefixRow {
	third := make([]mdbx.PrefixRow, len(post))
	for i, row := range post {
		third[i] = row
		if bytes.Equal(row.Key, []byte{0, 2}) {
			third[i].Value = []byte{0x7f}
		}
	}
	return third
}

// R10: the consulted authority row drifts before the write begin: STALE_LOCAL_PLAN with the raw StateMismatch.
func TestReplayEntryFixtureSnapshotDrift(t *testing.T) {
	w, view := replayEntryWorld(t)
	image := w.image()
	var out ReplayEntryOutcomeV1
	drift, err := mdbx.FixtureWriteSnapshotDrift(w.store, 0, []byte{2}, func() { out = w.enter(view, w.genesis) })
	logicalMDBXAssert(t, err == nil && drift == 1 && out.Result == replayEntryStale && out.Truth == mdbx.CommitTruthOld && out.Stage == mdbx.UpdateStagePrewrite, "R10: %d %v %+v", drift, err, out)
	replayEngineClass(t, out.Err, mdbx.EngineStateMismatch, "R10")
	replayConsumed(t, w.store, out.Err, "R10")
	// The drifted authority row is the only change: every other image row is byte-identical.
	w.store = w.reopen()
	after := w.image()
	same := len(after) == len(image)
	for i := 0; same && i < len(image); i++ {
		changed := !bytes.Equal(image[i].Value, after[i].Value)
		same = bytes.Equal(image[i].Key, after[i].Key) && changed == bytes.Equal(image[i].Key, []byte{0, 2})
	}
	logicalMDBXAssert(t, same, "R10: the drifted row is not the only change")
}

// R17, H8, H15, H16: malformed authority rows take the integrity route before inventory (R23-R26 and R45 are
// TestReplayEntryFixtureIllegalReplay).
func TestReplayEntryFixtureAuthority(t *testing.T) {
	for _, c := range []struct {
		label string
		value func([]byte) []byte
	}{
		{"R17 version 2", func(v []byte) []byte { v[0] = 2; return v }},
		{"H8 empty", func([]byte) []byte { return []byte{} }},
		{"H15 short", func(v []byte) []byte { return v[:len(v)-1] }},
		{"H16 oversized", func(v []byte) []byte { return append(v, 0) }},
		{"H16 over MaxMetadataBytes", func(v []byte) []byte { return append(v, make([]byte, mdbx.MaxMetadataBytes+1-len(v))...) }},
	} {
		w, view := replayEntryWorld(t)
		a := w.authority()
		encoded, _ := a.Encode()
		image, value := w.image(), c.value(bytes.Clone(encoded))
		logicalMDBXAssert(t, mdbx.FixtureSeedRawRow(w.store, 0, []byte{2}, value) == nil, "%s: seed", c.label)
		out := w.enter(view, w.genesis)
		logicalMDBXAssert(t, out.Result == selectedSideIntegrity && out.CanonicalTruth == "OLD" && out.Truth == mdbx.CommitTruthOld && out.Stage == mdbx.UpdateStagePrewrite && view.calls == 0, "%s: %+v", c.label, out)
		replayEngineClass(t, out.Err, mdbx.EngineIntegrity, c.label)
		replayConsumed(t, w.store, out.Err, c.label)
		w.store = w.reopen()
		same, err := mdbx.FixtureRawRowEqual(w.store, 0, []byte{2}, value)
		logicalMDBXAssert(t, err == nil && same && mdbx.FixtureSeedRawRow(w.store, 0, []byte{2}, encoded) == nil, "%s: authority row changed: %v", c.label, err)
		replaySameImage(t, image, w.image(), c.label+" zero mutation")
	}
}

// Selectivity of image() for DBI 7: an owner-only raw overwrite of a generation-1 canonical-owner row changes it.
func TestReplayEntryFixtureImageOwner(t *testing.T) {
	w := newReplayWorld(t, 3)
	image := w.image()
	logicalMDBXAssert(t, mdbx.FixtureSeedRawRow(w.store, 7, logicalMDBXMust(mdbx.CanonicalOwnerKey(1, w.hashes[2])), mdbx.CanonicalOwnerValue(9)) == nil, "owner seed")
	logicalMDBXAssert(t, !replayImagesEqual(image, w.image()), "owner overwrite: image did not change")
}

// R59 and H30: the step-1 identity page refuses a first row above height 0, zero work, and a malformed row.
func TestReplayEntryFixtureIdentityPage(t *testing.T) {
	w := newReplayWorld(t, -1)
	for h := uint64(3); h <= 5; h++ { // active canonical index rows at heights 3..5, no height-0 row
		logicalMDBXAssert(t, mdbx.FixtureSeedRawRow(w.store, 2, logicalMDBXMust(mdbx.HeightKey(1, h)), mdbx.ChainValue([32]byte{byte(h)}, [32]byte{byte(h - 1)}, sideWorldWork(h+1))) == nil, "R59 seed %d", h)
	}
	view := &replayView{}
	r59 := replayIntegrityWith(t, w, replayIdentityOnly(), "R59 first row at 3")
	logicalMDBXAssert(t, r59.calls == 0, "R59 first row at 3 inventory: %d", r59.calls)
	w = newReplayWorld(t, -1)
	logicalMDBXAssert(t, mdbx.FixtureSeedRawRow(w.store, 2, logicalMDBXMust(mdbx.HeightKey(1, 0)), mdbx.ChainValue([32]byte{1}, [32]byte{}, [40]byte{})) == nil, "R59 zero seed")
	r59 = replayIntegrityWith(t, w, replayIdentityOnly(), "R59 zero work")
	logicalMDBXAssert(t, r59.calls == 0, "R59 zero work inventory: %d", r59.calls)
	// H30: after a successful identity-page read the returned read-site label is empty.
	err := newReplayWorld(t, 0).store.View(func(r *mdbx.Reader) error {
		identity, site, readErr := replayEntryIdentity(r, 1)
		logicalMDBXAssert(t, readErr == nil && site == "" && identity != 0, "H30 successful read: %d %q %v", identity, site, readErr)
		return nil
	})
	logicalMDBXAssert(t, err == nil, "H30 successful view: %v", err)
	// H30: a NONE/STABLE image (genesis committed) whose active index row at HeightKey(1,0) is rewritten to 103 bytes.
	var preSeed []mdbx.PrefixRow
	seeded := func(label string) *replayWorld {
		w := newReplayWorld(t, 0)
		preSeed = w.image()
		a := w.authority()
		logicalMDBXAssert(t, a.Phase == mdbx.StoragePhaseNoneV1 && a.Lifecycle == mdbx.StorageLifecycleStableV1, "%s premise: %+v", label, a)
		key := logicalMDBXMust(mdbx.HeightKey(1, 0))
		present, err := mdbx.FixtureRawRowEqual(w.store, 2, key, mdbx.ChainValue(w.genesis.GenesisHash, [32]byte{}, sideWorldWork(1)))
		logicalMDBXAssert(t, err == nil && present && mdbx.FixtureSeedRawRow(w.store, 2, key, make([]byte, 103)) == nil, "%s rewrite: %v", label, err)
		return w
	}
	w = seeded("H30 helper")
	err = w.store.View(func(r *mdbx.Reader) error {
		_, site, readErr := replayEntryIdentity(r, 1)
		replayEngineClass(t, readErr, mdbx.EngineIntegrity, "H30 helper")
		logicalMDBXAssert(t, site == selectedSideCanonical, "H30 site %q", site)
		return nil
	})
	replayEngineClass(t, err, mdbx.EngineIntegrity, "H30 view records the read failure")
	// The identity-page step records the label on the granted and on the control-only (denied) path.
	for _, denied := range []bool{false, true} {
		w = seeded("H30 step")
		call := &replayEntryCall{owner: NewReplayEntryOwnerV1(view, replayIdentityOnly()), reservations: w.owner, denied: denied}
		err = w.store.View(func(r *mdbx.Reader) error {
			_, readErr := call.identityCharged(r, 1)
			replayEngineClass(t, readErr, mdbx.EngineIntegrity, "H30 step")
			logicalMDBXAssert(t, call.step == selectedSideCanonical, "H30 step label denied=%v: %q", denied, call.step)
			return nil
		})
		replayEngineClass(t, err, mdbx.EngineIntegrity, "H30 step view")
	}
	// The granted path (hold 0) and the control-only path (full-lane grant refused, hold 1) on identically seeded Stores.
	for _, hold := range []uint64{0, 1} {
		w = seeded("H30 entry")
		authority, err := w.authority().Encode()
		logicalMDBXAssert(t, err == nil, "H30 authority: %v", err)
		out := w.held(view, replayIdentityOnly(), hold)
		logicalMDBXAssert(t, out.Result == selectedSideIntegrity && out.CanonicalTruth == "OLD" && out.Truth == mdbx.CommitTruthOld && out.Stage == mdbx.UpdateStagePrewrite && out.Decision == "" && out.Replay == nil && view.calls == 0, "H30 entry hold %d: %+v", hold, out)
		replayEngineClass(t, out.Err, mdbx.EngineIntegrity, "H30 entry")
		replayConsumed(t, w.store, out.Err, "H30 entry")
		// image() pages the malformed index row, so the persisted rows are compared directly: the rewritten row and the
		// authority row are byte-identical after reopen.
		w.store = w.reopen()
		row, err := mdbx.FixtureRawRowEqual(w.store, 2, logicalMDBXMust(mdbx.HeightKey(1, 0)), make([]byte, 103))
		same, err2 := mdbx.FixtureRawRowEqual(w.store, 0, []byte{2}, authority)
		logicalMDBXAssert(t, err == nil && err2 == nil && row && same, "H30 hold %d persisted rows: %v %v", hold, err, err2)
		// Restoring the original row value gives back the full pre-seed image: nothing else changed.
		original := mdbx.ChainValue(w.genesis.GenesisHash, [32]byte{}, sideWorldWork(1))
		logicalMDBXAssert(t, mdbx.FixtureSeedRawRow(w.store, 2, logicalMDBXMust(mdbx.HeightKey(1, 0)), original) == nil, "H30 restore")
		replaySameImage(t, preSeed, w.image(), "H30 full image")
	}
}

// R53 D5 (the seeded defect): the header row under the height-3 entry hash holds the 116 bytes of another header.
func TestReplayEntryFixtureHeaderHash(t *testing.T) {
	w := pendingWorld(t, 4)
	logicalMDBXAssert(t, mdbx.FixtureSeedRawRow(w.store, 3, w.hashes[3][:], w.headers[1][:]) == nil, "R53 seed")
	w.headers[3] = w.headers[1]
	replayIntegrity(t, w, "R53 D5")
}

// R51 D2: a 103-byte index value at height 4, and separately a 115-byte header row, are refused by the Reader itself:
// the raw EngineIntegrity Err is forwarded and the Store is consumed.
func TestReplayEntryFixtureRowWidth(t *testing.T) {
	for _, c := range []struct {
		label string
		rank  uint8
		key   func(*replayWorld) []byte
		width int
	}{
		{"R51 D2 entry 103", 2, func(*replayWorld) []byte { return logicalMDBXMust(mdbx.HeightKey(1, 4)) }, 103},
		{"R51 D2 header 115", 3, func(w *replayWorld) []byte { return w.hashes[4][:] }, 115},
	} {
		w := pendingWorld(t, 5)
		headers, hashes := w.fork(5, 1, 1)
		view, image := &replayView{inv: replayComplete([][32]byte{hashes[0]}, headers)}, w.image()
		i := slices.IndexFunc(image, func(r mdbx.PrefixRow) bool { return bytes.Equal(r.Key, append([]byte{c.rank}, c.key(w)...)) })
		logicalMDBXAssert(t, i > 0 && mdbx.FixtureSeedRawRow(w.store, c.rank, c.key(w), make([]byte, c.width)) == nil, "%s: seed", c.label)
		out := w.enter(view, w.genesis)
		logicalMDBXAssert(t, out.Result == selectedSideIntegrity && out.Decision == "" && out.CanonicalTruth == "OLD" && out.Truth == mdbx.CommitTruthOld && out.Stage == mdbx.UpdateStagePrewrite && out.Replay == nil, "%s: %+v", c.label, out)
		replayEngineClass(t, out.Err, mdbx.EngineIntegrity, c.label)
		replayConsumed(t, w.store, out.Err, c.label)
		calls := view.calls
		again := w.enter(view, w.genesis)
		logicalMDBXAssert(t, again.Result == selectedSideIntegrity && again.Truth == mdbx.CommitTruthOld && again.CanonicalTruth == "OLD" && view.calls == calls, "%s latched: %+v", c.label, again)
		w.store = w.reopen()
		same, err := mdbx.FixtureRawRowEqual(w.store, c.rank, c.key(w), make([]byte, c.width))
		logicalMDBXAssert(t, err == nil && same && mdbx.FixtureSeedRawRow(w.store, c.rank, c.key(w), image[i].Value) == nil, "%s: seeded row changed: %v", c.label, err)
		replaySameImage(t, image, w.image(), c.label)
	}
}

// H10: the OLD read transaction's abort fails (SelectedDamageAbortEIO) after the callback returned the sentinel. A
// Decision-only outcome (genesis first) gives storage_io and a decided recovery_artifact outcome (nil view) keeps its
// Result; both carry the raw joined Err, and the latched Store answers the next entry with no callback.
func TestReplayEntryFixtureAbortEIO(t *testing.T) {
	for _, c := range []struct {
		label  string
		depth  int
		nilV   bool
		result string
	}{
		{"H10 decision-only", -1, false, "LOCAL_RESOURCE_UNAVAILABLE(storage_io)"},
		{"H10 recovery_artifact", 3, true, replayEntryRecovery},
	} {
		var w *replayWorld
		if c.depth < 0 {
			w = newReplayWorld(t, c.depth)
		} else {
			w = pendingWorld(t, c.depth)
		}
		image := w.image()
		view := &replayView{inv: replayComplete(nil, nil)}
		var handle HeaderCandidateViewV1 = view
		if c.nilV {
			handle = nil
		}
		var out ReplayEntryOutcomeV1
		evidence, err := mdbx.FixtureSelectedDamage(w.store, w.owner, mdbx.SelectedDamageAbortEIO, 0, nil, func() {
			out = NewReplayEntryOwnerV1(handle, w.genesis).EnterReplayTargetMDBX(w.store, w.owner)
		})
		logicalMDBXAssert(t, err == nil && evidence.Faults == 1 && evidence.Commits == 0, "%s fixture: %v %+v", c.label, err, evidence)
		logicalMDBXAssert(t, out.Result == c.result && out.Decision == "" && out.CanonicalTruth == "OLD" && out.Truth == mdbx.CommitTruthOld &&
			out.Stage == mdbx.UpdateStagePrewrite && out.Replay == nil && len(genesisMDBXCauses(out.Err)) == 2, "%s: %+v", c.label, out)
		// The raw Err joins exactly two causes: the abort's raw EngineIO and this invocation's own sentinel, a plain
		// *errors.errorString leaf (identified by its type, never by its text).
		causes := genesisMDBXCauses(out.Err)
		engine, sentinel := 0, 0
		for _, cause := range causes {
			switch fmt.Sprintf("%T", cause) {
			case "*mdbx.EngineError":
				replayEngineClass(t, cause, mdbx.EngineIO, c.label+" abort cause")
				engine++
			case "*errors.errorString":
				sentinel++
			}
		}
		logicalMDBXAssert(t, fmt.Sprintf("%T", out.Err) == "*errors.joinError" && engine == 1 && sentinel == 1, "%s joined causes: %#v", c.label, causes)
		// Latched: a running callback would answer genesis first or commit the canonical tip at height 3, not this Err.
		again := w.enter(view, w.genesis)
		logicalMDBXAssert(t, again.Result == selectedSideInvariant && replaySameErr(again.Err, out.Err) && view.calls == 0, "%s next: %+v calls %d", c.label, again, view.calls)
		replayConsumed(t, w.store, out.Err, c.label+" next operation")
		w.store = w.reopen()
		replaySameImage(t, image, w.image(), c.label)
	}
}

// H11 header-read case: the zero-work index entry at height 2 is refused before its header read, which is armed to
// fail transiently (SelectedDamageGetEIO, rank 3, at that header hash): integrity through a consensus failure object.
func TestReplayEntryFixtureChainworkBeforeHeader(t *testing.T) {
	w0 := newReplayWorld(t, 0)
	headers, _ := replayChain(t, w0.genesis.GenesisHash, w0.lastTime, 3)
	w := defectWorld(t, headers[:3], replayValueAt(2, nil, [40]byte{}))
	image := w.image()
	var out ReplayEntryOutcomeV1
	view := &replayView{inv: replayComplete(nil, nil)}
	// The armed site is never reached (the fixture reports it), because the entry is refused before its header read.
	evidence, err := mdbx.FixtureSelectedDamage(w.store, w.owner, mdbx.SelectedDamageGetEIO, 3, w.hashes[2][:], func() { out = w.enter(view, w.genesis) })
	var failure *selectedSideFailure
	ok := fmt.Sprintf("%T", out.Err) == "*consensus.selectedSideFailure" && errors.As(out.Err, &failure) && failure.result == selectedSideIntegrity
	logicalMDBXAssert(t, ok && out.Result == selectedSideIntegrity && out.Decision == "" && out.CanonicalTruth == "OLD" && out.Truth == mdbx.CommitTruthOld && out.Stage == mdbx.UpdateStagePrewrite, "H11 header-read: %+v", out)
	replaySameImage(t, image, w.image(), "H11 header-read (Store open)")
	logicalMDBXAssert(t, err != nil && evidence.Faults == 0, "H11 header-read fixture: %v %+v", err, evidence)
}

// replayIllegalTail splices outer-option bytes after a legal REPLAY payload; Encode refuses illegal authorities, so the
// illegal rows are built from the legal encoding's bytes (its four trailing none-option tags are replaced).
func replayIllegalTail(t *testing.T, legal []byte, tail ...[]byte) []byte {
	t.Helper()
	logicalMDBXAssert(t, bytes.Equal(legal[len(legal)-4:], []byte{0, 0, 0, 0}), "legal REPLAY carries outer options")
	return bytes.Join(append([][]byte{legal[:len(legal)-4]}, tail...), nil)
}

// R23-R26, R45: an illegal persisted REPLAY authority (or version 2) takes the integrity route with zero mutation, with or
// without a refused full-lane grant.
func TestReplayEntryFixtureIllegalReplay(t *testing.T) {
	u16, u64 := func(n uint16) []byte { return binary.BigEndian.AppendUint16(nil, n) }, func(n uint64) []byte { return binary.BigEndian.AppendUint64(nil, n) }
	hash, work := bytes.Repeat([]byte{1}, 32), append(make([]byte, 39), 3)
	selected := bytes.Join([][]byte{u64(2), u64(1), u64(2), hash, work, u16(1), u64(1)}, nil)
	detached := bytes.Join([][]byte{u16(1), u64(1), hash, u64(1), u64(1), hash, u16(1), u64(1)}, nil)
	cleanup := append([]byte{1, byte(mdbx.CleanupSpanGenerationV1)}, u64(2)...)
	for _, c := range []struct {
		label string
		value func([]byte) []byte
	}{
		{"R23 pending profile", func(v []byte) []byte {
			return replayIllegalTail(t, v, []byte{1, byte(mdbx.StorageProfileArchiveV1), 0, 0, 0})
		}},
		{"R24 cleanup payload", func(v []byte) []byte { return replayIllegalTail(t, v, cleanup, []byte{0, 0, 0, 0}) }},
		{"R25 selected side", func(v []byte) []byte { return replayIllegalTail(t, v, []byte{0, 0, 1}, selected, []byte{0}) }},
		{"R26 detached suffix", func(v []byte) []byte { return replayIllegalTail(t, v, []byte{0, 0, 0, 1}, detached) }},
		{"R45 version 2", func(v []byte) []byte { v[0] = 2; return v }},
	} {
		t.Run(c.label, func(t *testing.T) {
			for _, hold := range []uint64{0, 1} {
				w, view := replayEntryWorld(t)
				logicalMDBXAssert(t, w.enter(view, w.genesis).Truth == mdbx.CommitTruthNew, "%s: enter REPLAY", c.label)
				legal, err := w.authority().Encode()
				logicalMDBXAssert(t, err == nil, "%s: encode %v", c.label, err)
				image, value := w.image(), c.value(bytes.Clone(legal))
				_, err = mdbx.DecodeStorageAuthorityV1(value)
				logicalMDBXAssert(t, err != nil && mdbx.FixtureSeedRawRow(w.store, 0, []byte{2}, value) == nil, "%s: seed must be an illegal row", c.label)
				view = &replayView{inv: view.inv}
				var out ReplayEntryOutcomeV1
				evidence, err := mdbx.FixtureSelectedDamage(w.store, w.owner, mdbx.SelectedDamageProbeOnly, 0, nil, func() { out = w.held(view, w.genesis, hold) })
				logicalMDBXAssert(t, err == nil && evidence.BeginWrite == 0 && evidence.Commits == 0 && evidence.Faults == 0, "%s/%d evidence: %v %+v", c.label, hold, err, evidence)
				logicalMDBXAssert(t, out.Result == selectedSideIntegrity && out.Decision == "" && out.Replay == nil && out.CanonicalTruth == "OLD" &&
					out.Truth == mdbx.CommitTruthOld && out.Stage == mdbx.UpdateStagePrewrite && view.calls == 0, "%s/%d: %+v", c.label, hold, out)
				replayEngineClass(t, out.Err, mdbx.EngineIntegrity, c.label)
				replayConsumed(t, w.store, out.Err, c.label)
				w.store = w.reopen()
				same, err := mdbx.FixtureRawRowEqual(w.store, 0, []byte{2}, value)
				logicalMDBXAssert(t, err == nil && same && mdbx.FixtureSeedRawRow(w.store, 0, []byte{2}, legal) == nil, "%s: authority row changed: %v", c.label, err)
				replaySameImage(t, image, w.image(), c.label)
			}
		})
	}
}

// R52 transient: the height-7 header row of the R52 world, present here, is transiently unreadable instead
// (SelectedDamageGetEIO, rank 3, at that hash): the R35 tuple.
func TestReplayEntryFixtureHeaderTransient(t *testing.T) {
	w0 := newReplayWorld(t, 0)
	headers, _ := replayChain(t, w0.genesis.GenesisHash, w0.lastTime, 8)
	w := defectWorld(t, headers, replayKeep)
	image := w.image()
	view := &replayView{inv: replayComplete(nil, nil)}
	out, evidence := replayArmed(t, w, view, mdbx.SelectedDamageGetEIO, 3, w.hashes[7][:])
	logicalMDBXAssert(t, out.Result == replayEntryRecovery && out.Decision == "" && out.CanonicalTruth == "OLD" && out.Truth == mdbx.CommitTruthOld &&
		out.Stage == mdbx.UpdateStagePrewrite && out.Replay == nil && evidence.Faults == 1 && evidence.BeginWrite == 0, "R52 transient: %+v %+v", out, evidence)
	replayEngineClass(t, out.Err, mdbx.EngineIO, "R52 transient")
	replayConsumed(t, w.store, out.Err, "R52 transient")
	w.store = w.reopen()
	replaySameImage(t, image, w.image(), "R52 transient")
}

// RUB-1571 X2 resource half: in the D10 world (published prefix tip at height 5) the height-8 header is transiently
// unreadable; the end of the prefix is then undetermined and the R35 tuple stands, never a commit of height 5.
func TestReplayEntryFixturePrefixTipTransient(t *testing.T) {
	w := defectWorld(t, replayD10Headers(t), replayKeep)
	image := w.image()
	out, evidence := replayArmed(t, w, &replayView{inv: replayComplete(nil, nil)}, mdbx.SelectedDamageGetEIO, 3, w.hashes[8][:])
	logicalMDBXAssert(t, out.Result == replayEntryRecovery && out.Decision == "" && out.CanonicalTruth == "OLD" && out.Truth == mdbx.CommitTruthOld &&
		out.Stage == mdbx.UpdateStagePrewrite && out.Replay == nil && evidence.Faults == 1 && evidence.BeginWrite == 0, "X2 transient: %+v %+v", out, evidence)
	replayEngineClass(t, out.Err, mdbx.EngineIO, "X2 transient")
	replayConsumed(t, w.store, out.Err, "X2 transient")
	w.store = w.reopen()
	replaySameImage(t, image, w.image(), "X2 transient")
}
