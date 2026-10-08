//go:build cgo && (darwin || linux) && (amd64 || arm64)

package consensus

import (
	"bytes"
	"encoding/binary"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/mdbx"
)

// pathView is a finite raw point provider: it records calls and never decides validity.
type pathView struct {
	headers     map[[32]byte][116]byte
	version     uint64
	churn       bool // the admitted membership changes between the first VersionV1 and ProtectV1
	nilRelease  bool
	panicWith   any
	entered     chan struct{}
	block       chan struct{}
	versions    int
	protects    int
	headerCalls int
	releases    int
	inUpdate    *bool // set by pathWorld.call: true while Store.Update has not returned
	inside      int   // releases run before Store.Update returned (before its OLD abort)
	owner       *replayPathOwner
	unclear     int // releases run while owner.release was still set
}

func (v *pathView) InventoryV1(uint64) HeaderCandidateInventoryV1 {
	panic("replay path called InventoryV1")
}

func (v *pathView) VersionV1() uint64 { v.versions++; return v.version }

func (v *pathView) ProtectV1(version uint64) (bool, func()) {
	v.protects++
	if v.churn {
		v.version++
	}
	if v.nilRelease {
		return version == v.version, nil
	}
	return version == v.version, func() {
		v.releases++
		if v.inUpdate != nil && *v.inUpdate {
			v.inside++
		}
		if v.owner != nil && v.owner.release != nil {
			v.unclear++
		}
	}
}

func (v *pathView) HeaderV1(hash [32]byte, dst *[116]byte) bool {
	v.headerCalls++
	if v.entered != nil {
		close(v.entered)
		<-v.block
	}
	if v.panicWith != nil {
		panic(v.panicWith)
	}
	h, ok := v.headers[hash]
	if ok {
		*dst = h
	}
	return ok
}

func (v *pathView) admit(header [116]byte) {
	if v.headers == nil {
		v.headers = map[[32]byte][116]byte{}
	}
	v.headers[mustHash(header)] = header
}

// pathWorld is an active canonical chain 0..active (active < 0: PRE_GENESIS) and a replay target that shares the
// active prefix 0..forkAt and continues with forkLen fork headers; target headers above the active chain are stored
// as header rows except at the heights in skip.
type pathWorld struct {
	*replayWorld
	active   int
	hashes   [][32]byte
	headers  [][116]byte
	inUpdate bool
	observe  func() // runs after Store.Update returned, before finishLocked
}

func newPathWorld(t *testing.T, active, forkAt, forkLen int, skip ...int) *pathWorld {
	t.Helper()
	return newPathWorldWith(t, pathSeed{active: active, forkAt: forkAt, forkLen: forkLen, skip: skip})
}

// pathSeed edits the seeded rows: canonical edits each active height's rows (defectWorld form).
type pathSeed struct {
	active, forkAt, forkLen int
	skip                    []int
	canonical               func(h uint64, rows []mdbx.Mutation) []mdbx.Mutation
}

func newPathWorldWith(t *testing.T, seed pathSeed) *pathWorld {
	t.Helper()
	w := &pathWorld{active: seed.active}
	if seed.canonical == nil {
		w.replayWorld = newReplayWorld(t, seed.active)
	} else {
		w.replayWorld = defectWorld(t, replayChainHeaders(t, seed.active), seed.canonical)
		w.setAuthority(func(a *mdbx.StorageAuthorityV1) {
			a.Lifecycle, a.PendingTargetProfile = mdbx.StorageLifecycleStableV1, nil
		})
	}
	base, at := w.genesis.GenesisHash, w.lastTime
	if seed.active >= 0 {
		base, at = w.replayWorld.hashes[seed.forkAt], binary.LittleEndian.Uint64(w.replayWorld.headers[seed.forkAt][68:76])+7
	}
	headers, hashes := replayChain(t, base, at, seed.forkLen)
	w.headers = append(append([][116]byte{}, w.replayWorld.headers[:seed.forkAt+1]...), headers...)
	w.hashes = append(append([][32]byte{}, w.replayWorld.hashes[:seed.forkAt+1]...), hashes...)
	var rows []mdbx.Mutation
	from := seed.forkAt + 1
	if seed.active < 0 {
		from = 0
	}
	for h := from; h < len(w.hashes); h++ {
		if !containsInt(seed.skip, h) {
			rows = append(rows, mdbx.Mutation{DBI: logicalMDBXDBIs[3], Key: bytes.Clone(w.hashes[h][:]), AfterKind: mdbx.AfterLiteral, Literal: bytes.Clone(w.headers[h][:])})
		}
	}
	if len(rows) > 0 {
		w.apply(rows...)
	}
	return w
}

// replayChainHeaders is the canonical chain 1..n over the published genesis as newReplayWorld seeds it.
func replayChainHeaders(t *testing.T, n int) [][116]byte {
	g := replayGenesis()
	headers, _ := replayChain(t, g.GenesisHash, binary.LittleEndian.Uint64(g.Published[68:76]), n)
	return headers
}

func containsInt(s []int, v int) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func (w *pathWorld) tip() uint64 { return uint64(len(w.hashes) - 1) }

// setReplay persists a legal REPLAY authority for the target with the given cursor.
func (w *pathWorld) setReplay(kind mdbx.ReplayCursorKindV1, h uint64) {
	w.setReplayEdit(kind, h, nil)
}

func (w *pathWorld) setReplayEdit(kind mdbx.ReplayCursorKindV1, h uint64, edit func(*mdbx.StorageAuthorityV1)) {
	tip, g := w.tip(), w.genesis
	w.setAuthority(func(a *mdbx.StorageAuthorityV1) {
		a.Lifecycle, a.Phase, a.PendingTargetProfile, a.NextGenerationID = mdbx.StorageLifecycleRecoveryRequiredV1, mdbx.StoragePhaseReplayV1, nil, 3
		a.Replay = &mdbx.ReplayV1{
			TargetProfile: mdbx.StorageProfilePrunedV1, TargetGenerationID: 2, Cursor: mdbx.ReplayCursorV1{Kind: kind},
			Target: mdbx.RecoveryTargetV1{ChainID: g.ChainID, GenesisHash: g.GenesisHash, TipHash: w.hashes[tip], TipHeight: tip, CumulativeChainwork: sideWorldWork(tip + 1)},
		}
		if kind == mdbx.ReplayCursorAppliedV1 {
			a.Replay.Cursor.Height, a.Replay.Cursor.BlockHash = h, w.hashes[h]
		}
		if edit != nil {
			edit(a)
		}
	})
}

// pathOldActive is the root-approved SAME-Reader endpoint setup: one PrefixPage row after H-1 (nil continuation for
// H = 0 or PRE_GENESIS), exhausted, with the point derived from the returned key and value.
func pathOldActive(t testing.TB, r *mdbx.Reader, generation uint64, tip int) *mdbx.AuthorityPointV1 {
	t.Helper()
	var prefix [8]byte
	binary.BigEndian.PutUint64(prefix[:], generation)
	var after []byte
	if tip > 0 {
		after = logicalMDBXMust(mdbx.HeightKey(generation, uint64(tip-1)))
	}
	page, err := r.PrefixPage(mdbx.SchemaV2DBIs()[2], prefix[:], after, 1, 120)
	logicalMDBXAssert(t, err == nil && page.Stop == mdbx.PrefixPageExhausted, "setup endpoint page: %v %v", page.Stop, err)
	if tip < 0 {
		logicalMDBXAssert(t, len(page.Rows) == 0, "setup PRE_GENESIS rows %d", len(page.Rows))
		return nil
	}
	logicalMDBXAssert(t, len(page.Rows) == 1 && len(page.Rows[0].Key) == 16 && len(page.Rows[0].Value) == 104, "setup endpoint row")
	row := page.Rows[0]
	h := binary.BigEndian.Uint64(row.Key[8:])
	logicalMDBXAssert(t, h == uint64(tip) && archiveSelectedSideWork(row.Value[64:104]), "setup endpoint height %d", h)
	return &mdbx.AuthorityPointV1{Height: h, BlockHash: [32]byte(row.Value[:32])}
}

var errPathAbort = errors.New("replay path test abort")

// call composes the real producer as its caller does: p.mu held over the whole invocation, the owner's full grant,
// one aborted Store.Update with authority and endpoint from the same Reader, inspect observing the borrowed facts in
// the callback, observe after Update returned (after its OLD abort), then finishLocked and the unlock.
func (w *pathWorld) call(t *testing.T, p *replayPathOwner, supplied []byte, inspect func(replayPathOwn, error)) (replayPathOwn, error) {
	t.Helper()
	var own replayPathOwn
	var err error
	if v, ok := p.view.(*pathView); ok && v != nil {
		v.inUpdate = &w.inUpdate
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	defer p.finishLocked()
	gerr := w.owner.WithReservation(mdbx.MaxOperationDataBytes, func() error {
		truth, uerr := w.update(t, func(r *mdbx.Reader) {
			a, rerr := r.ReadStorageAuthorityV1()
			logicalMDBXAssert(t, rerr == nil, "setup authority: %v", rerr)
			old := pathOldActive(t, r, uint64(a.ActiveGenerationID), w.active)
			own, err = p.ownLocked(r, a, old, w.genesis, supplied)
			if inspect != nil {
				inspect(own, err)
			}
		})
		logicalMDBXAssert(t, truth == mdbx.CommitTruthOld && errors.Is(uerr, errPathAbort), "update tuple %v %v", truth, uerr)
		return nil
	})
	logicalMDBXAssert(t, gerr == nil, "full grant: %v", gerr)
	if w.observe != nil {
		w.observe()
	}
	return own, err
}

// update runs one Store.Update whose callback aborts with errPathAbort; inUpdate is cleared only when Update's frame
// has exited, on return or on a re-raised panic.
func (w *pathWorld) update(t *testing.T, body func(*mdbx.Reader)) (mdbx.CommitTruth, error) {
	t.Helper()
	w.inUpdate = true
	defer func() { w.inUpdate = false }()
	truth, _, uerr := w.store.Update(func(r *mdbx.Reader) (mdbx.Batch, error) {
		body(r)
		return mdbx.Batch{}, errPathAbort
	})
	return truth, uerr
}

func pathResult(err error) string {
	var f *selectedSideFailure
	if errors.As(err, &f) {
		return f.result
	}
	return ""
}

func pathWant(t *testing.T, err error, result, label string) {
	t.Helper()
	logicalMDBXAssert(t, pathResult(err) == result, "%s: result %q err %v, want %q", label, pathResult(err), err, result)
}

// pathOK asserts a successful own read of height h with the target hash and the exact stored or acquired header.
func (w *pathWorld) pathOK(t *testing.T, own replayPathOwn, err error, h uint64, source replayPathHeaderSource, label string) {
	t.Helper()
	logicalMDBXAssert(t, err == nil, "%s: %v", label, err)
	logicalMDBXAssert(t, own.h == h && own.x == w.hashes[h] && own.headerSource == source && own.resource == "" && !own.missing, "%s: own %+v", label, own)
	logicalMDBXAssert(t, bytes.Equal(own.header, w.headers[h][:]), "%s: header bytes", label)
}

func pathZero(t *testing.T, own replayPathOwn, label string) {
	t.Helper()
	logicalMDBXAssert(t, own.h == 0 && own.x == [32]byte{} && own.header == nil && own.activeEntry == nil && own.headerSource == replayPathUnavailable && !own.missing && own.resource == "", "%s: own %+v", label, own)
}

const pathLimit = 1 << 20

func TestReplayPathMDBXV1(t *testing.T) {
	t.Run("Precondition", testReplayPathPrecondition)
	t.Run("GreatestAttachment", testReplayPathGreatestAttachment)
	t.Run("PreGenesis", testReplayPathPreGenesis)
	t.Run("BelowCursor", testReplayPathBelowCursor)
	t.Run("FinalHeightFresh", testReplayPathFinalHeightFresh)
	t.Run("OwnAtAttachment", testReplayPathOwnAtAttachment)
	t.Run("StoredPointSupplied", testReplayPathStoredPointSupplied)
	t.Run("MultiAcquisition", testReplayPathMultiAcquisition)
	t.Run("ChurnProtectFalse", testReplayPathChurnProtectFalse)
	t.Run("NilFacet", testReplayPathNilFacet)
	t.Run("ExactCapacity", testReplayPathExactCapacity)
	t.Run("RetainedReuse", testReplayPathRetainedReuse)
	t.Run("Discard", testReplayPathDiscard)
	t.Run("Restart", testReplayPathRestart)
	t.Run("GuardFinish", testReplayPathGuardFinish)
	t.Run("ForeignSlot", testReplayPathForeignSlot)
	t.Run("ActiveEntryDamage", testReplayPathActiveEntryDamage)
	t.Run("CanonicalHeaderDamage", testReplayPathCanonicalHeaderDamage)
	t.Run("AncestryMissing", testReplayPathAncestryMissing)
	t.Run("CursorGenesisTarget", testReplayPathCursorGenesisTarget)
	t.Run("ProducerReleaseMissing", testReplayPathProducerReleaseMissing)
	t.Run("IrrelevantCandidates", testReplayPathIrrelevantCandidates)
	t.Run("ProtectedPanic", testReplayPathProtectedPanic)
	t.Run("ConcurrentFinishDiscard", testReplayPathConcurrentFinishDiscard)
	t.Run("PositiveErrorBacking", testReplayPathPositiveErrorBacking)
	t.Run("BoundaryCases", testReplayPathBoundaryCases)
}

// Step 1: nil Replay, an authority failing pure validation and an APPLIED cursor at the tip refuse before any read.
func testReplayPathPrecondition(t *testing.T) {
	w := newPathWorld(t, 3, 1, 3)
	view := &pathView{}
	p := newReplayPathOwner(view, pathLimit)
	own, err := w.call(t, p, nil, nil)
	pathWant(t, err, selectedSideInvariant, "nil Replay")
	pathZero(t, own, "nil Replay")
	w.setReplay(mdbx.ReplayCursorAppliedV1, w.tip())
	image := w.image()
	own, err = pathCallNoPanic(t, w, p, "cursor at tip")
	pathWant(t, err, selectedSideInvariant, "cursor at tip")
	pathZero(t, own, "cursor at tip")
	replaySameImage(t, image, w.image(), "cursor at tip")
	// A cursor above the tip cannot be persisted, so it runs on the in-memory authority.
	a := w.authority()
	a.Replay.Cursor.Height = a.Replay.Target.TipHeight + 1
	logicalMDBXAssert(t, mdbx.ValidateStorageAuthorityV1(a) != nil, "hand-built authority validates")
	own, err = pathDirect(t, p, a, w.genesis, "cursor above tip")
	pathWant(t, err, selectedSideInvariant, "cursor above tip")
	pathZero(t, own, "cursor above tip")
	logicalMDBXAssert(t, p.slot == nil && view.versions+view.protects+view.headerCalls == 0, "precondition touched the slot or view")
}

// B27: target forks from active height 2; descending from tip 7 the first active match is 2 (heights 0..2 all match).
func testReplayPathGreatestAttachment(t *testing.T) {
	w := newPathWorld(t, 6, 2, 5)
	w.setReplay(mdbx.ReplayCursorAppliedV1, 1)
	view := &pathView{}
	p := newReplayPathOwner(view, pathLimit)
	image := w.image()
	own, err := w.call(t, p, nil, nil)
	w.pathOK(t, own, err, 2, replayPathStored, "greatest attachment")
	logicalMDBXAssert(t, [32]byte(own.activeEntry[:32]) == w.hashes[2] && len(own.activeEntry) == 104, "active entry source")
	s := p.slot
	logicalMDBXAssert(t, s != nil && s.attached && s.a == 2 && s.lo == 2 && len(s.hashes) == 6, "slot %+v", s)
	for k := uint64(3); k <= 7; k++ {
		logicalMDBXAssert(t, s.hashes[k-2] == w.hashes[k], "suffix hash at %d", k)
	}
	logicalMDBXAssert(t, view.versions+view.protects+view.headerCalls == 0, "provider touched")
	replaySameImage(t, image, w.image(), "greatest attachment")
}

// B28: PRE_GENESIS active and replay: the walk runs tip..0 over headers only and h0 is the target genesis.
func testReplayPathPreGenesis(t *testing.T) {
	w := newPathWorld(t, -1, 0, 4)
	w.setReplay(mdbx.ReplayCursorPreGenesisV1, 0)
	p := newReplayPathOwner(nil, pathLimit)
	own, err := w.call(t, p, nil, nil)
	w.pathOK(t, own, err, 0, replayPathStored, "pre-genesis")
	logicalMDBXAssert(t, own.activeEntry == nil && own.x == w.genesis.GenesisHash, "pre-genesis own")
	s := p.slot
	logicalMDBXAssert(t, s != nil && !s.attached && s.lo == 0 && len(s.hashes) == 5 && s.hashes[0] == w.genesis.GenesisHash && s.hashes[4] == w.hashes[4], "slot %+v", s)
}

// APPLIED cursor at 4 above the active tip 3: no attachment, the derived cursor hash matches.
func testReplayPathBelowCursor(t *testing.T) {
	w := newPathWorld(t, 3, 3, 4)
	w.setReplay(mdbx.ReplayCursorAppliedV1, 4)
	p := newReplayPathOwner(nil, pathLimit)
	own, err := w.call(t, p, nil, nil)
	w.pathOK(t, own, err, 5, replayPathStored, "below cursor")
	s := p.slot
	logicalMDBXAssert(t, !s.attached && s.lo == 5 && len(s.hashes) == 3 && s.hashes[0] == w.hashes[5], "slot %+v", s)
}

// B16: cursor tip-1 on a fresh owner establishes exactly the tip.
func testReplayPathFinalHeightFresh(t *testing.T) {
	w := newPathWorld(t, 3, 1, 4)
	w.setReplay(mdbx.ReplayCursorAppliedV1, w.tip()-1)
	p := newReplayPathOwner(nil, 32)
	own, err := w.call(t, p, nil, nil)
	w.pathOK(t, own, err, w.tip(), replayPathStored, "final height")
	logicalMDBXAssert(t, len(p.slot.hashes) == 1 && own.activeEntry == nil, "final slot")
}

// h <= a reads the active entry then its header; a later h above a reads the retained hash then the header.
func testReplayPathOwnAtAttachment(t *testing.T) {
	w := newPathWorld(t, 6, 2, 5)
	w.setReplay(mdbx.ReplayCursorAppliedV1, 0)
	p := newReplayPathOwner(nil, pathLimit)
	own, err := w.call(t, p, nil, nil)
	w.pathOK(t, own, err, 1, replayPathStored, "own below attachment")
	logicalMDBXAssert(t, p.slot.a == 2 && [32]byte(own.activeEntry[:32]) == w.hashes[1], "own entry")
	w.setReplay(mdbx.ReplayCursorAppliedV1, 2)
	own, err = w.call(t, p, nil, nil)
	w.pathOK(t, own, err, 3, replayPathStored, "own above attachment")
	logicalMDBXAssert(t, own.activeEntry == nil, "entry above attachment")
}

// B35: stored beats supplied and point; absence queries the point first; no point yields the supplied header.
func testReplayPathStoredPointSupplied(t *testing.T) {
	w := newPathWorld(t, 3, 3, 3, 5)
	w.setReplay(mdbx.ReplayCursorAppliedV1, 5)
	view := &pathView{version: 9}
	view.admit(w.headers[6])
	p := newReplayPathOwner(view, pathLimit)
	same := bytes.Clone(w.headers[6][:])
	own, err := w.call(t, p, same, nil)
	w.pathOK(t, own, err, 6, replayPathStored, "stored beats supplied")
	logicalMDBXAssert(t, &own.header[0] != &same[0] && view.headerCalls == 0 && view.protects == 0, "stored consulted the provider or supply")
	p.discard()
	w.setReplay(mdbx.ReplayCursorAppliedV1, 4)
	view.admit(w.headers[5])
	_, err = w.call(t, p, w.headers[6][:], func(own replayPathOwn, err error) {
		w.pathOK(t, own, err, 5, replayPathPoint, "point beats wrong supplied")
	})
	logicalMDBXAssert(t, err == nil && view.headerCalls == 1 && view.protects == 1 && view.releases == 1, "point calls %+v", view)
	p.discard()
	// Definitive stored absence queries the point before an exact supplied artifact that also binds x.
	sup, calls := bytes.Clone(w.headers[5][:]), view.headerCalls
	_, err = w.call(t, p, sup, func(own replayPathOwn, err error) {
		w.pathOK(t, own, err, 5, replayPathPoint, "point before binding supplied")
		logicalMDBXAssert(t, bytes.Equal(own.header, w.headers[5][:]) && &own.header[0] != &sup[0], "point bytes %x", own.header)
	})
	logicalMDBXAssert(t, err == nil && view.headerCalls == calls+1, "point before supplied calls %+v", view)
	p.discard()
	delete(view.headers, w.hashes[5])
	block := append(bytes.Clone(w.headers[5][:]), 0xAA)
	own, err = w.call(t, p, block, nil)
	w.pathOK(t, own, err, 5, replayPathSupplied, "supplied prefix")
	logicalMDBXAssert(t, &own.header[0] == &block[0] && cap(own.header) == 116, "supplied backing is not the caller prefix")
}

// B35: two absent ancestry headers are admitted one per failed attempt; the third attempt succeeds.
func testReplayPathMultiAcquisition(t *testing.T) {
	w := newPathWorld(t, 2, 2, 4, 4, 5)
	w.setReplay(mdbx.ReplayCursorAppliedV1, 3)
	view := &pathView{}
	p := newReplayPathOwner(view, pathLimit)
	image := w.image()
	for i, k := range []uint64{5, 4} {
		own, err := w.call(t, p, nil, nil)
		pathWant(t, err, replayEntryRecovery, "missing")
		logicalMDBXAssert(t, view.releases == i+1 && view.protects == i+1 && p.release == nil, "missing %d: releases %+v", k, view)
		logicalMDBXAssert(t, own.missing && own.missingHeight == k && own.missingHash == w.hashes[k] && own.resource == "", "missing %d: %+v", k, own)
		logicalMDBXAssert(t, p.slot == nil && !p.discard(), "partial slot after %d", k)
		view.admit(w.headers[k])
	}
	own, err := w.call(t, p, nil, func(own replayPathOwn, err error) { w.pathOK(t, own, err, 4, replayPathPoint, "acquired") })
	logicalMDBXAssert(t, err == nil && own.h == 4 && p.slot != nil && view.releases == 3 && view.protects == 3, "acquired walk %+v", view)
	logicalMDBXAssert(t, p.slot.lo == 4 && len(p.slot.hashes) == 3 && !p.slot.attached, "acquired slot %+v", p.slot)
	replaySameImage(t, image, w.image(), "multi acquisition")
}

// B40: Protect false with a release is supersession; points are read under the held current version.
func testReplayPathChurnProtectFalse(t *testing.T) {
	w := newPathWorld(t, 2, 2, 3, 3)
	w.setReplay(mdbx.ReplayCursorAppliedV1, 2)
	view := &pathView{churn: true, version: 4}
	view.admit(w.headers[3])
	p := newReplayPathOwner(view, pathLimit)
	_, err := w.call(t, p, nil, func(own replayPathOwn, err error) {
		w.pathOK(t, own, err, 3, replayPathPoint, "churn")
		logicalMDBXAssert(t, view.releases == 0, "released before the consumer")
	})
	logicalMDBXAssert(t, err == nil && view.protects == 1 && view.versions == 2 && view.releases == 1, "churn calls %+v", view)
}

// C33: a nil interface calls nothing; a typed-nil provider reaches its real method.
func testReplayPathNilFacet(t *testing.T) {
	w := newPathWorld(t, 2, 2, 3, 3)
	w.setReplay(mdbx.ReplayCursorAppliedV1, 2)
	p := newReplayPathOwner(nil, pathLimit)
	own, err := w.call(t, p, w.headers[3][:], nil)
	w.pathOK(t, own, err, 3, replayPathSupplied, "nil facet supplied")
	p.discard()
	own, err = w.call(t, p, nil, nil)
	pathWant(t, err, replayEntryRecovery, "nil facet missing")
	logicalMDBXAssert(t, own.missing && own.missingHeight == 3, "nil facet identity")
	var typed *pathView
	p = newReplayPathOwner(typed, pathLimit)
	func() {
		defer func() {
			_, isRuntime := recover().(interface{ RuntimeError() })
			logicalMDBXAssert(t, isRuntime, "typed nil did not reach its method")
		}()
		_, _ = w.call(t, p, nil, nil)
	}()
}

// RC1/RC2: limit 32N-1 refuses before any source, 32N succeeds with exactly N elements, zero refuses.
func testReplayPathExactCapacity(t *testing.T) {
	w := newPathWorld(t, 2, 2, 4, 3)
	w.setReplay(mdbx.ReplayCursorAppliedV1, 2)
	view := &pathView{}
	view.admit(w.headers[3])
	for _, limit := range []uint64{0, 32*4 - 1} {
		p := newReplayPathOwner(view, limit)
		own, err := w.call(t, p, nil, nil)
		pathWant(t, err, selectedSideCapacity, "capacity")
		pathZero(t, own, "capacity")
		logicalMDBXAssert(t, p.slot == nil && view.headerCalls+view.protects == 0, "capacity read a source")
	}
	p := newReplayPathOwner(view, 32*4)
	own, err := w.call(t, p, nil, nil)
	logicalMDBXAssert(t, err == nil && own.h == 3 && len(p.slot.hashes) == 4 && cap(p.slot.hashes) == 4, "exact limit: %v", err)
	n, ok := replayPathAdmit(0xffffffff, 0, 137438953471)
	logicalMDBXAssert(t, n == 1<<32 && !ok, "max refusal")
	n, ok = replayPathAdmit(0xffffffff, 0, 137438953472)
	logicalMDBXAssert(t, n == 1<<32 && ok, "max admission")
}

// RC4: successive calls reuse the slot; a deleted high header proves no re-walk, and a later refusal keeps the slot.
func testReplayPathRetainedReuse(t *testing.T) {
	w := newPathWorld(t, 2, 2, 4)
	w.setReplay(mdbx.ReplayCursorAppliedV1, 2)
	p := newReplayPathOwner(nil, pathLimit)
	_, err := w.call(t, p, nil, nil)
	logicalMDBXAssert(t, err == nil, "establish: %v", err)
	slot, first, hashes := p.slot, &p.slot.hashes[0], slices.Clone(p.slot.hashes)
	w.apply(mdbx.Mutation{DBI: logicalMDBXDBIs[3], Key: bytes.Clone(w.hashes[6][:]), BeforePresent: true, AfterKind: mdbx.AfterAbsent})
	w.apply(mdbx.Mutation{DBI: logicalMDBXDBIs[3], Key: bytes.Clone(w.hashes[5][:]), BeforePresent: true, AfterKind: mdbx.AfterAbsent})
	w.setReplay(mdbx.ReplayCursorAppliedV1, 3)
	own, err := w.call(t, p, nil, nil)
	w.pathOK(t, own, err, 4, replayPathStored, "retained")
	logicalMDBXAssert(t, p.slot == slot && &p.slot.hashes[0] == first && len(slot.hashes) == 4, "slot replaced")
	w.setReplay(mdbx.ReplayCursorAppliedV1, 4)
	own, err = w.call(t, p, nil, nil)
	pathWant(t, err, replayEntryRecovery, "retained refusal")
	logicalMDBXAssert(t, own.missing && own.missingHeight == 5 && p.slot == slot && slices.Equal(slot.hashes, hashes), "refusal cleared the slot")
	own, err = w.call(t, p, w.headers[5][:], nil)
	w.pathOK(t, own, err, 5, replayPathSupplied, "retry on the retained slot")
	logicalMDBXAssert(t, p.slot == slot && slices.Equal(slot.hashes, hashes) && slot.lo == 3, "retry changed the slot")
}

// RC7: locked discard is true once; concurrent unlocked discards serialize to exactly one true.
func testReplayPathDiscard(t *testing.T) {
	w := newPathWorld(t, 2, 2, 2)
	w.setReplay(mdbx.ReplayCursorAppliedV1, 2)
	p := newReplayPathOwner(nil, pathLimit)
	logicalMDBXAssert(t, !p.discard(), "empty discard")
	_, err := w.call(t, p, nil, nil)
	logicalMDBXAssert(t, err == nil, "establish: %v", err)
	p.mu.Lock()
	first, second := p.discardLocked(), p.discardLocked()
	p.mu.Unlock()
	logicalMDBXAssert(t, first && !second && p.slot == nil, "locked discard %v %v", first, second)
	_, _ = w.call(t, p, nil, nil)
	var wg sync.WaitGroup
	results := make(chan bool, 8)
	for range 8 {
		wg.Add(1)
		go func() { defer wg.Done(); results <- p.discard() }()
	}
	wg.Wait()
	close(results)
	trues := 0
	for r := range results {
		if r {
			trues++
		}
	}
	logicalMDBXAssert(t, trues == 1, "concurrent discards true %d", trues)
}

// B16/RC8: a fresh owner starts empty and re-establishes; the old owner keeps its slot.
func testReplayPathRestart(t *testing.T) {
	w := newPathWorld(t, 2, 2, 4)
	w.setReplay(mdbx.ReplayCursorAppliedV1, 2)
	old := newReplayPathOwner(nil, pathLimit)
	_, err := w.call(t, old, nil, nil)
	logicalMDBXAssert(t, err == nil, "establish")
	w.apply(mdbx.Mutation{DBI: logicalMDBXDBIs[3], Key: bytes.Clone(w.hashes[6][:]), BeforePresent: true, AfterKind: mdbx.AfterAbsent})
	fresh := newReplayPathOwner(nil, pathLimit)
	own, err := w.call(t, fresh, nil, nil)
	pathWant(t, err, replayEntryRecovery, "fresh owner re-walks")
	logicalMDBXAssert(t, own.missingHeight == 6 && fresh.slot == nil, "fresh missing %+v", own)
	_, err = w.call(t, old, nil, nil)
	logicalMDBXAssert(t, err == nil, "old owner re-walked: %v", err)
	old.discard()
	_, err = w.call(t, old, nil, nil)
	pathWant(t, err, replayEntryRecovery, "discarded owner re-walks")
}

// B40/K17: the guard is held from the first point through the consumer and released once by finishLocked.
func testReplayPathGuardFinish(t *testing.T) {
	w := newPathWorld(t, 2, 2, 2, 3)
	w.setReplay(mdbx.ReplayCursorAppliedV1, 2)
	view := &pathView{}
	view.admit(w.headers[3])
	p := newReplayPathOwner(view, pathLimit)
	view.owner = p
	observed := false
	w.observe = func() {
		observed = true
		logicalMDBXAssert(t, !w.inUpdate && view.releases == 0 && p.release != nil, "guard released before Update returned and the final observation")
	}
	_, err := w.call(t, p, nil, func(own replayPathOwn, err error) {
		logicalMDBXAssert(t, err == nil && view.releases == 0 && p.release != nil && bytes.Equal(own.header, w.headers[3][:]), "held source")
	})
	w.observe = nil
	logicalMDBXAssert(t, view.releases == 1 && view.unclear == 0, "release ran before finishLocked cleared it: %+v", view)
	logicalMDBXAssert(t, observed && err == nil && view.releases == 1 && view.inside == 0 && p.release == nil && p.slot != nil, "finish %+v", view)
	p.mu.Lock()
	p.finishLocked()
	p.mu.Unlock()
	logicalMDBXAssert(t, view.releases == 1, "second finish released again")
}

// RC9: each slot-key component differing refuses with storage_capacity before any source; the slot is unchanged.
func testReplayPathForeignSlot(t *testing.T) {
	w := newPathWorld(t, 2, 2, 3, 3)
	w.setReplay(mdbx.ReplayCursorAppliedV1, 2)
	view := &pathView{}
	view.admit(w.headers[3])
	p := newReplayPathOwner(view, pathLimit)
	_, err := w.call(t, p, nil, nil)
	logicalMDBXAssert(t, err == nil, "establish")
	slot, calls := p.slot, view.headerCalls
	key, hashes, lo, attached, a := slot.key, slices.Clone(slot.hashes), slot.lo, slot.attached, slot.a
	edits := map[string]func(*mdbx.StorageAuthorityV1){
		"generation": func(a *mdbx.StorageAuthorityV1) { a.NextGenerationID, a.Replay.TargetGenerationID = 4, 3 },
		"chainID":    func(a *mdbx.StorageAuthorityV1) { a.Replay.Target.ChainID[0] ^= 1 },
		"genesis":    func(a *mdbx.StorageAuthorityV1) { a.Replay.Target.GenesisHash[0] ^= 1 },
		"tipHash":    func(a *mdbx.StorageAuthorityV1) { a.Replay.Target.TipHash[0] ^= 1 },
		"tipHeight":  func(a *mdbx.StorageAuthorityV1) { a.Replay.Target.TipHeight++ },
		"chainwork":  func(a *mdbx.StorageAuthorityV1) { a.Replay.Target.CumulativeChainwork[39]++ },
	}
	for _, name := range []string{"generation", "chainID", "genesis", "tipHash", "tipHeight", "chainwork"} {
		w.setReplayEdit(mdbx.ReplayCursorAppliedV1, 2, edits[name])
		image := w.image()
		own, err := w.call(t, p, nil, nil)
		pathWant(t, err, selectedSideCapacity, name)
		pathZero(t, own, name)
		logicalMDBXAssert(t, p.slot == slot && view.headerCalls == calls, "%s: slot or source touched", name)
		logicalMDBXAssert(t, slot.key == key && slices.Equal(slot.hashes, hashes) && slot.lo == lo && slot.attached == attached && slot.a == a, "%s: slot contents changed", name)
		replaySameImage(t, image, w.image(), name)
	}
	w.setReplay(mdbx.ReplayCursorAppliedV1, 2)
	_, err = w.call(t, p, nil, nil)
	logicalMDBXAssert(t, err == nil && p.slot == slot, "original target after variants: %v", err)
	p.discard()
	w.setReplayEdit(mdbx.ReplayCursorAppliedV1, 2, edits["tipHash"])
	_, err = w.call(t, p, nil, nil)
	logicalMDBXAssert(t, pathResult(err) != selectedSideCapacity, "discard did not permit a new target: %v", err)
}

// C21/C23/C24: a required active entry absent or with illegal work is canonical integrity with no later header.
func testReplayPathActiveEntryDamage(t *testing.T) {
	for _, tc := range []struct {
		name   string
		absent bool
	}{{"absent", true}, {"work", false}} {
		edit := replayValueAt(4, nil, [40]byte{})
		if tc.absent {
			edit = func(h uint64, rows []mdbx.Mutation) []mdbx.Mutation {
				if h == 4 {
					return rows[:1]
				}
				return rows
			}
		}
		w := newPathWorldWith(t, pathSeed{active: 6, forkAt: 2, forkLen: 5, skip: []int{5}, canonical: edit})
		w.setReplay(mdbx.ReplayCursorAppliedV1, 1)
		view := &pathView{}
		view.admit(w.headers[5]) // the point at 5 acquires the guard before the damaged entry at 4
		p := newReplayPathOwner(view, pathLimit)
		own, err := w.call(t, p, nil, nil)
		pathWant(t, err, selectedSideIntegrity, tc.name)
		logicalMDBXAssert(t, own.h == 4 && own.x == w.hashes[4] && own.header == nil && own.resource == "" && !own.missing, "%s: own %+v", tc.name, own)
		logicalMDBXAssert(t, (own.activeEntry == nil) == tc.absent && p.slot == nil && view.headerCalls == 1, "%s: entry/slot", tc.name)
		logicalMDBXAssert(t, view.releases == 1 && p.release == nil, "%s: release %+v", tc.name, view)
	}
}

// C11/C12/C25: the h <= a canonical header absent or with a wrong parent is integrity, never acquisition.
func testReplayPathCanonicalHeaderDamage(t *testing.T) {
	absent := func(h uint64, rows []mdbx.Mutation) []mdbx.Mutation {
		if h == 1 {
			return rows[1:]
		}
		return rows
	}
	w := newPathWorldWith(t, pathSeed{active: 6, forkAt: 2, forkLen: 5, skip: []int{4}, canonical: absent})
	w.setReplay(mdbx.ReplayCursorAppliedV1, 0)
	view := &pathView{}
	view.admit(w.headers[1])
	view.admit(w.headers[4]) // the walk's point at 4 holds the guard when the own canonical header is absent
	p := newReplayPathOwner(view, pathLimit)
	own, err := w.call(t, p, w.headers[1][:], nil)
	pathWant(t, err, selectedSideIntegrity, "canonical header absent")
	logicalMDBXAssert(t, own.h == 1 && own.header == nil && !own.missing && view.headerCalls == 1 && p.slot != nil, "absent own %+v", own)
	logicalMDBXAssert(t, view.releases == 1 && p.release == nil, "absent own release %+v", view)
	var wrong [32]byte
	wrong[0] = 1
	w = newPathWorldWith(t, pathSeed{active: 6, forkAt: 2, forkLen: 5, canonical: replayValueAt(1, &wrong, sideWorldWork(2))})
	w.setReplay(mdbx.ReplayCursorAppliedV1, 0)
	p = newReplayPathOwner(nil, pathLimit)
	own, err = w.call(t, p, nil, nil)
	pathWant(t, err, selectedSideIntegrity, "canonical parent")
	logicalMDBXAssert(t, bytes.Equal(own.header, w.headers[1][:]) && own.headerSource == replayPathStored, "parent own %+v", own)
}

// C11/C12/C25/B35: absence with nothing binding is recovery_artifact with the exact HEADER identity and no slot.
func testReplayPathAncestryMissing(t *testing.T) {
	w := newPathWorld(t, 2, 2, 4, 5)
	w.setReplay(mdbx.ReplayCursorAppliedV1, 2)
	view := &pathView{}
	view.admit(w.headers[4]) // unrelated admitted header
	p := newReplayPathOwner(view, pathLimit)
	image := w.image()
	own, err := w.call(t, p, w.headers[3][:], nil)
	pathWant(t, err, replayEntryRecovery, "ancestry missing")
	logicalMDBXAssert(t, own.missing && own.missingHeight == 5 && own.missingHash == w.hashes[5] && own.h == 5 && own.header == nil, "missing %+v", own)
	logicalMDBXAssert(t, p.slot == nil && !p.discard() && view.headerCalls == 1, "missing slot")
	logicalMDBXAssert(t, view.releases == 1 && view.unclear == 0 && p.release == nil, "missing header release %+v", view)
	replaySameImage(t, image, w.image(), "ancestry missing")
}

// C21/C23/C24: a cursor element or target genesis contradiction is integrity before any slot.
func testReplayPathCursorGenesisTarget(t *testing.T) {
	w := newPathWorld(t, 2, 2, 4, 4)
	w.setReplayEdit(mdbx.ReplayCursorAppliedV1, 3, func(a *mdbx.StorageAuthorityV1) { a.Replay.Cursor.BlockHash[0] ^= 1 })
	view := &pathView{}
	view.admit(w.headers[4]) // the cursor element is derived from the point-sourced header at 4
	p := newReplayPathOwner(view, pathLimit)
	own, err := w.call(t, p, nil, nil)
	pathWant(t, err, selectedSideIntegrity, "cursor")
	logicalMDBXAssert(t, !own.missing && p.slot == nil && view.headerCalls == 1, "cursor own %+v", own)
	logicalMDBXAssert(t, view.releases == 1 && p.release == nil, "cursor release %+v", view)
	g := newPathWorld(t, -1, 0, 3)
	g.setReplay(mdbx.ReplayCursorPreGenesisV1, 0)
	g.genesis.GenesisHash[0] ^= 1
	view = &pathView{}
	p = newReplayPathOwner(view, pathLimit)
	own, err = g.call(t, p, nil, nil)
	pathWant(t, err, selectedSideIntegrity, "genesis context")
	logicalMDBXAssert(t, own.header == nil && p.slot == nil && view.versions == 0, "genesis own %+v", own)
	// A completed slot does not bypass the target/genesis contradiction.
	c := newPathWorld(t, 2, 2, 4)
	c.setReplay(mdbx.ReplayCursorAppliedV1, 2)
	p = newReplayPathOwner(nil, pathLimit)
	_, err = c.call(t, p, nil, nil)
	logicalMDBXAssert(t, err == nil && p.slot != nil, "genesis reuse establish: %v", err)
	slot, hashes := p.slot, append([][32]byte(nil), p.slot.hashes...)
	c.setReplay(mdbx.ReplayCursorAppliedV1, 3)
	c.genesis.ChainID[0] ^= 1
	own, err = c.call(t, p, nil, nil)
	pathWant(t, err, selectedSideIntegrity, "genesis context on slot reuse")
	pathZero(t, own, "genesis context on slot reuse")
	logicalMDBXAssert(t, p.slot == slot && slices.Equal(slot.hashes, hashes) && slot.lo == 3 && !slot.attached, "genesis reuse changed the slot")
}

// B40: a nil release is the evidence invariant; no HeaderV1 call follows.
func testReplayPathProducerReleaseMissing(t *testing.T) {
	for _, stale := range []bool{false, true} {
		w := newPathWorld(t, 2, 2, 2, 3)
		w.setReplay(mdbx.ReplayCursorAppliedV1, 2)
		view := &pathView{nilRelease: true, churn: stale}
		view.admit(w.headers[3])
		p := newReplayPathOwner(view, pathLimit)
		own, err := w.call(t, p, nil, nil)
		pathWant(t, err, selectedSideInvariant, "nil release")
		logicalMDBXAssert(t, view.headerCalls == 0 && view.protects == 1 && !own.missing && p.slot == nil, "nil release %+v", view)
	}
}

// K16: the provider's Inventory panics if called; required points still succeed.
func testReplayPathIrrelevantCandidates(t *testing.T) {
	w := newPathWorld(t, 2, 2, 3, 3, 4)
	w.setReplay(mdbx.ReplayCursorAppliedV1, 2)
	view := &pathView{}
	view.admit(w.headers[3])
	view.admit(w.headers[4])
	other, _ := replayChain(t, w.genesis.GenesisHash, 99, 2)
	view.admit(other[1])
	p := newReplayPathOwner(view, pathLimit)
	_, err := w.call(t, p, nil, func(own replayPathOwn, err error) { w.pathOK(t, own, err, 3, replayPathPoint, "irrelevant") })
	logicalMDBXAssert(t, err == nil && view.headerCalls == 2 && view.protects == 1, "points %+v", view)
}

// K17: a natural HeaderV1 panic keeps its payload, releases the acquired guard once and leaves no slot or row effect.
func testReplayPathProtectedPanic(t *testing.T) {
	w := newPathWorld(t, 2, 2, 2, 4)
	w.setReplay(mdbx.ReplayCursorAppliedV1, 2)
	payload := &struct{ id int }{7}
	view := &pathView{panicWith: payload}
	p := newReplayPathOwner(view, pathLimit)
	image := w.image()
	func() {
		defer func() {
			got := recover()
			logicalMDBXAssert(t, got == any(payload), "panic payload %v", got)
		}()
		_, _ = w.call(t, p, nil, nil)
	}()
	logicalMDBXAssert(t, view.releases == 1 && view.inside == 0 && p.release == nil && p.slot == nil, "panic cleanup: release before the OLD abort %+v", view)
	replaySameImage(t, image, w.image(), "panic")
}

// RC7 producer subset: a discard blocked on p.mu completes only after the held source's finish and unlock.
func testReplayPathConcurrentFinishDiscard(t *testing.T) {
	w := newPathWorld(t, 2, 2, 3, 4)
	w.setReplay(mdbx.ReplayCursorAppliedV1, 2)
	view := &pathView{}
	view.admit(w.headers[4])
	p := newReplayPathOwner(view, pathLimit)
	_, err := w.call(t, p, nil, nil)
	logicalMDBXAssert(t, err == nil, "establish")
	w.setReplay(mdbx.ReplayCursorAppliedV1, 3)
	view.releases = 0
	view.entered, view.block = make(chan struct{}), make(chan struct{})
	done := make(chan [2]int, 1) // discard result and the releases it observed after acquiring p.mu
	early := make(chan string, 1)
	go func() {
		defer close(view.block)
		select {
		case <-view.entered:
		case <-time.After(10 * time.Second):
			early <- "HeaderV1 not reached"
			return
		}
		go func() { ok := p.discard(); done <- [2]int{map[bool]int{true: 1}[ok], view.releases} }()
		select {
		case r := <-done:
			early <- "discard returned while the guard was held"
			done <- r
		case <-time.After(50 * time.Millisecond):
			early <- ""
		}
	}()
	_, err = w.call(t, p, nil, func(replayPathOwn, error) {
		select {
		case <-done:
			t.Error("discard returned before the last consumer")
		default:
		}
	})
	logicalMDBXAssert(t, <-early == "" && err == nil, "held discard: err %v", err)
	var r [2]int
	select {
	case r = <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("discard did not return after finish and unlock")
	}
	logicalMDBXAssert(t, r == [2]int{1, 1}, "discard %v", r)
	logicalMDBXAssert(t, !p.discard() && view.releases == 1, "double release or discard")
}

// C14/C26 boundary: a positive current-visit link error returns the original stored header and active-entry backing
// with the visit identity; the failed build publishes nothing.
func testReplayPathPositiveErrorBacking(t *testing.T) {
	var wrong [32]byte
	wrong[0] = 1
	w := newPathWorldWith(t, pathSeed{active: 6, forkAt: 2, forkLen: 5, canonical: replayValueAt(1, &wrong, sideWorldWork(2))})
	w.setReplay(mdbx.ReplayCursorAppliedV1, 0)
	p := newReplayPathOwner(nil, pathLimit)
	own, err := w.call(t, p, nil, nil)
	pathWant(t, err, selectedSideIntegrity, "positive backing")
	entry := mdbx.ChainValue(w.hashes[1], wrong, sideWorldWork(2))
	logicalMDBXAssert(t, own.h == 1 && own.x == w.hashes[1] && bytes.Equal(own.header, w.headers[1][:]) && bytes.Equal(own.activeEntry, entry), "positive own %+v", own)
	logicalMDBXAssert(t, own.headerSource == replayPathStored && own.resource == "" && !own.missing && p.slot.a == 2, "positive origin")
	// Own h <= a with damaged entry work: x names the entry's hash; the header is never read.
	w = newPathWorldWith(t, pathSeed{active: 6, forkAt: 2, forkLen: 5, canonical: replayValueAt(1, nil, [40]byte{})})
	w.setReplay(mdbx.ReplayCursorAppliedV1, 0)
	p = newReplayPathOwner(nil, pathLimit)
	own, err = w.call(t, p, nil, nil)
	pathWant(t, err, selectedSideIntegrity, "own entry work")
	logicalMDBXAssert(t, own.x == w.hashes[1], "own entry x %x", own.x)
	entry = mdbx.ChainValue(w.hashes[1], w.hashes[0], [40]byte{})
	logicalMDBXAssert(t, own.h == 1 && bytes.Equal(own.activeEntry, entry) && own.header == nil && own.headerSource == replayPathUnavailable, "own entry %+v", own)
	logicalMDBXAssert(t, own.resource == "" && !own.missing && p.slot.a == 2, "own entry origin")
}

// pathDirect runs ownLocked on an in-memory authority; a panic is reported as this assertion's failure.
func pathDirect(t *testing.T, p *replayPathOwner, a mdbx.StorageAuthorityV1, g PublishedGenesisContextV1, label string) (own replayPathOwn, err error) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("%s: producer panicked: %v", label, r)
		}
	}()
	p.mu.Lock()
	defer p.mu.Unlock()
	defer p.finishLocked()
	return p.ownLocked(nil, a, nil, g, nil)
}

// pathCallNoPanic is w.call with a producer panic reported as this assertion's failure.
func pathCallNoPanic(t *testing.T, w *pathWorld, p *replayPathOwner, label string) (replayPathOwn, error) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("%s: producer panicked: %v", label, r)
		}
	}()
	return w.call(t, p, nil, nil)
}

// Precondition refusal, foreign-target invariant, cursor/genesis proof on reuse and attachment, unbound point discarded.
func testReplayPathBoundaryCases(t *testing.T) {
	w := newPathWorld(t, 2, 2, 4)
	w.setReplay(mdbx.ReplayCursorAppliedV1, 2)
	view := &pathView{}
	p := newReplayPathOwner(view, pathLimit)
	// Precondition: below the tip, but invalid for another reason (STABLE lifecycle in REPLAY phase); it cannot be
	// persisted, so it and the foreign target below run on the in-memory authority.
	a := w.authority()
	a.Lifecycle = mdbx.StorageLifecycleStableV1
	logicalMDBXAssert(t, mdbx.ValidateStorageAuthorityV1(a) != nil && a.Replay.Cursor.Height < a.Replay.Target.TipHeight, "invalid setup")
	own, err := pathDirect(t, p, a, w.genesis, "invalid authority")
	pathWant(t, err, selectedSideInvariant, "invalid authority")
	pathZero(t, own, "invalid authority")
	w.setReplay(mdbx.ReplayCursorAppliedV1, w.tip())
	image := w.image()
	own, err = pathCallNoPanic(t, w, p, "cursor at tip")
	pathWant(t, err, selectedSideInvariant, "cursor at tip")
	pathZero(t, own, "cursor at tip")
	replaySameImage(t, image, w.image(), "cursor at tip")
	logicalMDBXAssert(t, p.slot == nil && view.versions+view.protects+view.headerCalls == 0, "precondition slot/view")
	w.setReplay(mdbx.ReplayCursorAppliedV1, 2)
	// Foreign target: a completed slot and a precondition-violating authority naming another target: invariant, not capacity.
	_, err = w.call(t, p, nil, nil)
	logicalMDBXAssert(t, err == nil, "foreign establish: %v", err)
	slot, hashes := p.slot, slices.Clone(p.slot.hashes)
	a.Replay.Target.TipHash[0] ^= 1
	_, err = pathDirect(t, p, a, w.genesis, "foreign target")
	pathWant(t, err, selectedSideInvariant, "foreign target")
	logicalMDBXAssert(t, p.slot == slot, "foreign slot changed")
	// Cursor proof on reuse: cursor advanced to 3 with a hash the own header 4 does not name.
	w.setReplayEdit(mdbx.ReplayCursorAppliedV1, 3, func(a *mdbx.StorageAuthorityV1) { a.Replay.Cursor.BlockHash[0] ^= 1 })
	_, err = w.call(t, p, nil, nil)
	pathWant(t, err, selectedSideIntegrity, "cursor reuse")
	logicalMDBXAssert(t, p.slot == slot && slices.Equal(slot.hashes, hashes) && slot.lo == 3, "cursor reuse slot")
	// Cursor proof when attached: a = 2, cursor 1 with a foreign hash, own h = 2 <= a.
	g := newPathWorld(t, 6, 2, 5)
	g.setReplay(mdbx.ReplayCursorAppliedV1, 0)
	q := newReplayPathOwner(nil, pathLimit)
	_, err = g.call(t, q, nil, nil)
	logicalMDBXAssert(t, err == nil && q.slot.a == 2, "cursor attached establish")
	g.setReplayEdit(mdbx.ReplayCursorAppliedV1, 1, func(a *mdbx.StorageAuthorityV1) { a.Replay.Cursor.BlockHash[0] ^= 1 })
	_, err = g.call(t, q, nil, nil)
	pathWant(t, err, selectedSideIntegrity, "cursor attached")
	logicalMDBXAssert(t, q.slot != nil, "cursor attached slot")
	// Attached slot below its establishment: established at cursor 1 (lo = a = 2), then cursor 0 (h = 1 < lo, h <= a) reads entry(1) then its header.
	g.setReplay(mdbx.ReplayCursorAppliedV1, 1)
	lv := &pathView{}
	l := newReplayPathOwner(lv, pathLimit)
	_, err = g.call(t, l, nil, nil)
	logicalMDBXAssert(t, err == nil && l.slot.lo == 2 && l.slot.attached && l.slot.a == 2, "below establishment setup %v %+v", err, l.slot)
	lslot, lhashes := l.slot, slices.Clone(l.slot.hashes)
	g.setReplay(mdbx.ReplayCursorAppliedV1, 0)
	own, err = g.call(t, l, nil, nil)
	g.pathOK(t, own, err, 1, replayPathStored, "attached below establishment")
	logicalMDBXAssert(t, len(own.activeEntry) == 104 && [32]byte(own.activeEntry[:32]) == g.hashes[1], "attached below establishment entry %x", own.activeEntry)
	logicalMDBXAssert(t, l.slot == lslot && slices.Equal(lslot.hashes, lhashes) && lslot.lo == 2 && lslot.attached && lslot.a == 2, "attached below establishment slot %+v", lslot)
	// Non-attached slot below its establishment: established at cursor 3 above the fork (lo = 4), then cursor 2 (h = 3 < lo): structural-only refusal.
	g.setReplay(mdbx.ReplayCursorAppliedV1, 3)
	nv := &pathView{}
	n := newReplayPathOwner(nv, pathLimit)
	_, err = g.call(t, n, nil, nil)
	logicalMDBXAssert(t, err == nil && n.slot.lo == 4 && !n.slot.attached, "non-attached setup %v %+v", err, n.slot)
	nslot, nkey, nhashes, na := n.slot, n.slot.key, slices.Clone(n.slot.hashes), n.slot.a
	g.setReplay(mdbx.ReplayCursorAppliedV1, 2)
	gimage, nview := g.image(), *nv
	own, err = g.call(t, n, nil, nil)
	pathWant(t, err, selectedSideInvariant, "non-attached below establishment")
	pathZero(t, own, "non-attached below establishment")
	logicalMDBXAssert(t, n.slot == nslot && nslot.key == nkey && slices.Equal(nslot.hashes, nhashes) && nslot.lo == 4 && !nslot.attached && nslot.a == na, "non-attached below establishment slot %+v", nslot)
	logicalMDBXAssert(t, nv.versions == nview.versions && nv.protects == nview.protects && nv.headerCalls == nview.headerCalls, "non-attached below establishment view %+v", nv)
	replaySameImage(t, gimage, g.image(), "non-attached below establishment")
	// Unbound point: the provider returns 116 bytes that do not bind x; they are discarded.
	m := newPathWorld(t, 2, 2, 3, 3)
	m.setReplay(mdbx.ReplayCursorAppliedV1, 2)
	bad := &pathView{headers: map[[32]byte][116]byte{m.hashes[3]: m.headers[4]}}
	r := newReplayPathOwner(bad, pathLimit)
	own, err = m.call(t, r, nil, nil)
	pathWant(t, err, replayEntryRecovery, "unbound point")
	logicalMDBXAssert(t, own.missing && own.missingHeight == 3 && own.header == nil && bad.headerCalls == 1, "unbound own %+v", own)
	logicalMDBXAssert(t, bad.releases == 1 && r.release == nil, "unbound release %+v", bad)
	// Unbound point bytes end the visit: a valid supplied artifact is not consulted after them (MP8F, step 4).
	own, err = m.call(t, r, m.headers[3][:], nil)
	pathWant(t, err, replayEntryRecovery, "unbound point with supplied")
	logicalMDBXAssert(t, own.missing && own.missingHeight == 3 && own.missingHash == m.hashes[3] && own.header == nil && own.headerSource == replayPathUnavailable && r.slot == nil, "supplied after unbound point %+v", own)
	logicalMDBXAssert(t, bad.releases == 2 && bad.protects == 2 && r.release == nil, "unbound second release %+v", bad)
	// Genesis proof below the cursor: PRE_GENESIS target whose height-0 ancestry is a foreign genesis header.
	f := newPathWorld(t, -1, 0, 0)
	fake, fakeHash := replayHeader(t, [32]byte{}, POW_LIMIT, 5)
	chain, hashes := replayChain(t, fakeHash, 5, 2)
	f.headers, f.hashes = append([][116]byte{fake}, chain...), append([][32]byte{fakeHash}, hashes...)
	var rows []mdbx.Mutation
	for i := range f.hashes {
		rows = append(rows, mdbx.Mutation{DBI: logicalMDBXDBIs[3], Key: bytes.Clone(f.hashes[i][:]), AfterKind: mdbx.AfterLiteral, Literal: bytes.Clone(f.headers[i][:])})
	}
	f.apply(rows...)
	f.setReplay(mdbx.ReplayCursorPreGenesisV1, 0)
	fp := newReplayPathOwner(nil, pathLimit)
	_, err = f.call(t, fp, nil, nil)
	pathWant(t, err, selectedSideIntegrity, "genesis below")
	logicalMDBXAssert(t, fp.slot == nil, "genesis below slot")
	// Genesis proof on the own header: attached PRE_GENESIS replay whose target genesis differs from the active height-0 entry.
	o := newPathWorld(t, 6, 2, 5, 4)
	o.genesis.GenesisHash[0] ^= 1
	o.setReplay(mdbx.ReplayCursorPreGenesisV1, 0)
	ov := &pathView{}
	ov.admit(o.headers[4]) // the walk's point at 4 holds the guard when the own genesis check fails
	op := newReplayPathOwner(ov, pathLimit)
	_, err = o.call(t, op, nil, nil)
	pathWant(t, err, selectedSideIntegrity, "own genesis")
	logicalMDBXAssert(t, op.slot != nil && op.slot.a == 2 && ov.headerCalls == 1, "own genesis slot")
	logicalMDBXAssert(t, ov.releases == 1 && op.release == nil, "own genesis release %+v", ov)
}
