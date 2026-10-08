//go:build cgo && (darwin || linux) && (amd64 || arm64) && rubin_mdbx_fixture

package consensus

import (
	"bytes"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/mdbx"
)

// pathArmed runs one real producer invocation (pathWorld.call form) under an armed native scenario. A native fault
// consumes the Store, so the Update tuple is returned rather than asserted; the setup reads are counted in the evidence.
func (w *pathWorld) pathArmed(t *testing.T, p *replayPathOwner, supplied []byte, scenario mdbx.SelectedDamageScenario, rank uint8, key []byte) (replayPathOwn, error, mdbx.SelectedDamageEvidence) {
	t.Helper()
	var own replayPathOwn
	var err error
	evidence, ferr := mdbx.FixtureSelectedDamage(w.store, w.owner, scenario, rank, key, func() {
		_, _, _ = w.store.Update(func(r *mdbx.Reader) (mdbx.Batch, error) {
			a, rerr := r.ReadStorageAuthorityV1()
			logicalMDBXAssert(t, rerr == nil, "setup authority: %v", rerr)
			old := pathOldActive(t, r, uint64(a.ActiveGenerationID), w.active)
			if p == nil {
				return mdbx.Batch{}, errPathAbort
			}
			p.mu.Lock()
			defer p.mu.Unlock()
			defer p.finishLocked()
			own, err = p.ownLocked(r, a, old, w.genesis, supplied)
			return mdbx.Batch{}, errPathAbort
		})
	})
	logicalMDBXAssert(t, ferr == nil, "fixture %d: %v", scenario, ferr)
	logicalMDBXAssert(t, evidence.BeginWrite == 0 && evidence.Commits == 0 && evidence.Deletes == 0, "write evidence %+v", evidence)
	return own, err, evidence
}

// pathBaseline is the setup-only read count of one invocation: the same Update with no producer call.
func (w *pathWorld) pathBaseline(t *testing.T) mdbx.SelectedDamageEvidence {
	t.Helper()
	_, _, evidence := w.pathArmed(t, nil, nil, mdbx.SelectedDamageProbeOnly, 0, nil)
	return evidence
}

// pathGets asserts the PATH-owned index (rank 2) and header (rank 3) Gets beyond the setup baseline.
func pathGets(t *testing.T, evidence, base mdbx.SelectedDamageEvidence, index, headers uint64, label string) {
	t.Helper()
	gotIndex, gotHeaders := evidence.OldGets[2]-base.OldGets[2], evidence.OldGets[3]-base.OldGets[3]
	logicalMDBXAssert(t, gotIndex == index && gotHeaders == headers, "%s: PATH gets index %d headers %d, want %d %d", label, gotIndex, gotHeaders, index, headers)
}

func pathNative(t *testing.T, own replayPathOwn, err error, resource, label string) {
	t.Helper()
	replayEngineClass(t, err, mdbx.EngineIO, label)
	logicalMDBXAssert(t, own.resource == resource && !own.missing, "%s: own %+v", label, own)
}

func TestReplayPathMDBX(t *testing.T) {
	t.Run("ExactCapacity", testReplayPathFixtureExactCapacity)
	t.Run("GreatestAttachment", testReplayPathFixtureGreatestAttachment)
	t.Run("PreGenesis", testReplayPathFixturePreGenesis)
	t.Run("SameAttemptReuse", testReplayPathFixtureSameAttemptReuse)
	t.Run("RetainedReuse", testReplayPathFixtureRetainedReuse)
	t.Run("WalkFaultRetry", testReplayPathFixtureWalkFaultRetry)
	t.Run("FirstFaultSelectivity", testReplayPathFixtureFirstFaultSelectivity)
	t.Run("StoredPositive", testReplayPathFixtureStoredPositive)
}

// RC1: limit 32N-1 performs zero PATH Gets and no provider call; limit 32N reads the whole walk.
func testReplayPathFixtureExactCapacity(t *testing.T) {
	w := newPathWorld(t, 2, 2, 4)
	w.setReplay(mdbx.ReplayCursorAppliedV1, 2)
	base := w.pathBaseline(t)
	view := &pathView{}
	p := newReplayPathOwner(view, 32*4-1)
	_, err, evidence := w.pathArmed(t, p, nil, mdbx.SelectedDamageProbeOnly, 0, nil)
	pathWant(t, err, selectedSideCapacity, "32N-1")
	pathGets(t, evidence, base, 0, 0, "32N-1")
	logicalMDBXAssert(t, p.slot == nil && view.versions+view.protects+view.headerCalls == 0, "32N-1 provider/slot")
	p = newReplayPathOwner(view, 32*4)
	own, err, evidence := w.pathArmed(t, p, nil, mdbx.SelectedDamageProbeOnly, 0, nil)
	w.pathOK(t, own, err, 3, replayPathStored, "32N")
	pathGets(t, evidence, base, 0, 4, "32N")
	logicalMDBXAssert(t, len(p.slot.hashes) == 4, "32N slot")
}

// B27: index-before-header descent stops at the greatest attachment; a fault on the first eligible entry wins.
func testReplayPathFixtureGreatestAttachment(t *testing.T) {
	w := newPathWorld(t, 6, 2, 5)
	w.setReplay(mdbx.ReplayCursorAppliedV1, 1)
	base := w.pathBaseline(t)
	p := newReplayPathOwner(nil, pathLimit)
	own, err, evidence := w.pathArmed(t, p, nil, mdbx.SelectedDamageProbeOnly, 0, nil)
	w.pathOK(t, own, err, 2, replayPathStored, "attachment")
	// Entries 6..2 (7 is above the active tip); headers 7..3 and the own canonical header 2, none at the attachment walk.
	pathGets(t, evidence, base, 5, 6, "attachment")
	logicalMDBXAssert(t, p.slot.attached && p.slot.a == 2 && [32]byte(own.activeEntry[:32]) == w.hashes[2], "greatest attachment slot %+v", p.slot)
	p = newReplayPathOwner(nil, pathLimit)
	own, err, evidence = w.pathArmed(t, p, nil, mdbx.SelectedDamageGetEIO, 2, logicalMDBXMust(mdbx.HeightKey(1, 6)))
	pathNative(t, own, err, selectedSideCanonical, "entry 6 fault")
	logicalMDBXAssert(t, evidence.Faults == 1 && own.h == 6 && own.header == nil && p.slot == nil, "entry fault %+v", own)
	pathGets(t, evidence, base, 1, 1, "entry fault")
}

// B28: PRE_GENESIS performs zero index Gets and reads each header once (h0 reused).
func testReplayPathFixturePreGenesis(t *testing.T) {
	w := newPathWorld(t, -1, 0, 4)
	w.setReplay(mdbx.ReplayCursorPreGenesisV1, 0)
	base := w.pathBaseline(t)
	own, err, evidence := w.pathArmed(t, newReplayPathOwner(nil, pathLimit), nil, mdbx.SelectedDamageProbeOnly, 0, nil)
	w.pathOK(t, own, err, 0, replayPathStored, "pre-genesis")
	pathGets(t, evidence, base, 0, 5, "pre-genesis")
	a := newPathWorld(t, 3, 3, 4)
	a.setReplay(mdbx.ReplayCursorAppliedV1, 4)
	base = a.pathBaseline(t)
	_, err, evidence = a.pathArmed(t, newReplayPathOwner(nil, pathLimit), nil, mdbx.SelectedDamageProbeOnly, 0, nil)
	logicalMDBXAssert(t, err == nil, "above tip: %v", err)
	pathGets(t, evidence, base, 0, 3, "above active tip")
}

// B27/RC4: the walk's own-height header is the own source; the armed own-height key is reached exactly once.
func testReplayPathFixtureSameAttemptReuse(t *testing.T) {
	w := newPathWorld(t, 3, 3, 4)
	w.setReplay(mdbx.ReplayCursorAppliedV1, 4)
	base := w.pathBaseline(t)
	own, err, evidence := w.pathArmed(t, newReplayPathOwner(nil, pathLimit), nil, mdbx.SelectedDamageProbeOnly, 0, nil)
	w.pathOK(t, own, err, 5, replayPathStored, "same attempt")
	pathGets(t, evidence, base, 0, 3, "same attempt")
	g := newPathWorld(t, 6, 2, 5)
	g.setReplay(mdbx.ReplayCursorAppliedV1, 1)
	base = g.pathBaseline(t)
	own, err, evidence = g.pathArmed(t, newReplayPathOwner(nil, pathLimit), nil, mdbx.SelectedDamageProbeOnly, 0, nil)
	g.pathOK(t, own, err, 2, replayPathStored, "attachment entry reuse")
	pathGets(t, evidence, base, 5, 6, "attachment entry reuse")
}

// RC4: the second call reads only the own header: no descent, no index Get.
func testReplayPathFixtureRetainedReuse(t *testing.T) {
	w := newPathWorld(t, 2, 2, 4)
	w.setReplay(mdbx.ReplayCursorAppliedV1, 2)
	p := newReplayPathOwner(nil, pathLimit)
	_, err := w.call(t, p, nil, nil)
	logicalMDBXAssert(t, err == nil, "establish")
	slot := p.slot
	w.setReplay(mdbx.ReplayCursorAppliedV1, 3)
	base := w.pathBaseline(t)
	own, err, evidence := w.pathArmed(t, p, nil, mdbx.SelectedDamageProbeOnly, 0, nil)
	w.pathOK(t, own, err, 4, replayPathStored, "retained")
	pathGets(t, evidence, base, 0, 1, "retained")
	logicalMDBXAssert(t, p.slot == slot, "slot replaced")
}

// RC5: a native fault at the first, a middle and the own walk header publishes nothing; the retry repeats the walk.
func testReplayPathFixtureWalkFaultRetry(t *testing.T) {
	for _, k := range []uint64{6, 4, 3} {
		w := newPathWorld(t, 2, 2, 4)
		w.setReplay(mdbx.ReplayCursorAppliedV1, 2)
		base := w.pathBaseline(t)
		image := w.image()
		p := newReplayPathOwner(nil, pathLimit)
		own, err, evidence := w.pathArmed(t, p, nil, mdbx.SelectedDamageGetEIO, 3, bytes.Clone(w.hashes[k][:]))
		pathNative(t, own, err, replayEntryRecovery, "walk fault")
		logicalMDBXAssert(t, evidence.Faults == 1 && own.h == k && own.x == w.hashes[k] && own.header == nil && p.slot == nil && !p.discard(), "fault at %d: %+v", k, own)
		pathGets(t, evidence, base, 0, 6-k+1, "walk fault")
		w.store = w.reopen()
		replaySameImage(t, image, w.image(), "walk fault image")
		base = w.pathBaseline(t)
		own, err, evidence = w.pathArmed(t, p, nil, mdbx.SelectedDamageProbeOnly, 0, nil)
		w.pathOK(t, own, err, 3, replayPathStored, "retry")
		pathGets(t, evidence, base, 0, 4, "retry")
	}
}

// K8/K11: one armed fault ends the visit with its original native cause; no provider call, supply or missing identity.
func testReplayPathFixtureFirstFaultSelectivity(t *testing.T) {
	w := newPathWorld(t, 6, 2, 5, 5)
	w.setReplay(mdbx.ReplayCursorAppliedV1, 1)
	view := &pathView{}
	view.admit(w.headers[5])
	p := newReplayPathOwner(view, pathLimit)
	image := w.image()
	own, err, evidence := w.pathArmed(t, p, w.headers[5][:], mdbx.SelectedDamageGetEIO, 2, logicalMDBXMust(mdbx.HeightKey(1, 5)))
	pathNative(t, own, err, selectedSideCanonical, "entry fault before unavailable header")
	logicalMDBXAssert(t, evidence.Faults == 1 && own.h == 5 && view.headerCalls+view.protects == 0, "entry fault %+v", view)
	w.store = w.reopen()
	replaySameImage(t, image, w.image(), "entry fault image")
	s := newPathWorld(t, 2, 2, 4)
	s.setReplay(mdbx.ReplayCursorAppliedV1, 2)
	view = &pathView{}
	view.admit(s.headers[5])
	p = newReplayPathOwner(view, pathLimit)
	own, err, evidence = s.pathArmed(t, p, s.headers[5][:], mdbx.SelectedDamageGetEIO, 3, bytes.Clone(s.hashes[5][:]))
	pathNative(t, own, err, replayEntryRecovery, "stored ancestry fault")
	logicalMDBXAssert(t, evidence.Faults == 1 && own.h == 5 && own.header == nil && view.headerCalls+view.protects == 0 && p.slot == nil, "ancestry fault %+v", own)
}

// K1-K6 header subset: a present stored misnamed header is positive damage that good point and supplied bytes never hide.
func testReplayPathFixtureStoredPositive(t *testing.T) {
	w := newPathWorld(t, 2, 2, 3)
	w.setReplay(mdbx.ReplayCursorAppliedV1, 2)
	bad := bytes.Clone(w.headers[4][:])
	bad[115] ^= 1
	logicalMDBXAssert(t, mdbx.FixtureSeedRawRow(w.store, 3, w.hashes[4][:], bad) == nil, "seed misnamed header")
	view := &pathView{}
	view.admit(w.headers[4])
	p := newReplayPathOwner(view, pathLimit)
	own, err := w.call(t, p, w.headers[4][:], nil)
	pathWant(t, err, selectedSideIntegrity, "stored positive")
	logicalMDBXAssert(t, own.h == 4 && own.x == w.hashes[4] && bytes.Equal(own.header, bad) && own.headerSource == replayPathStored && !own.missing, "positive own %+v", own)
	logicalMDBXAssert(t, view.headerCalls+view.protects == 0 && p.slot == nil, "positive slot/provider")
}
