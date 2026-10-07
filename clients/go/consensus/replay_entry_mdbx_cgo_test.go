//go:build cgo && (darwin || linux) && (amd64 || arm64)

package consensus

import (
	"bytes"
	"cmp"
	"encoding/binary"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"math/big"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
	"unsafe"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/mdbx"
)

// replayView is the test producer of HeaderCandidateViewV1.
type replayView struct {
	inv         HeaderCandidateInventoryV1
	calls       int
	limits      []uint64
	versions    []uint64
	stale       bool
	versioned   bool   // ProtectV1 reports current only for the producer's present inventory Version
	admit       func() // run by ProtectV1 first: the producer's admissions after the inventory
	nilRelease  bool
	releases    int
	early       int                             // releases run while the entry's full-lane grant was held (before its WithReservation returned)
	lane        *mdbx.OperationReservationOwner // when set, each release probes the full lane
	afterInvent func()
	distinct    bool     // each InventoryV1 call returns its own Version (100 + call number), recorded in issued
	issued      []uint64 // the Version each InventoryV1 call returned, in call order (distinct mode)
}

func (v *replayView) InventoryV1(limit uint64) HeaderCandidateInventoryV1 {
	v.calls++
	v.limits = append(v.limits, limit)
	if v.afterInvent != nil {
		v.afterInvent()
	}
	if v.distinct {
		inv := v.inv
		inv.Version = 100 + uint64(v.calls)
		v.issued = append(v.issued, inv.Version)
		return inv
	}
	return v.inv
}

func (v *replayView) ProtectV1(version uint64) (bool, func()) {
	v.versions = append(v.versions, version)
	if v.admit != nil {
		v.admit()
	}
	if v.nilRelease {
		return !v.stale, nil
	}
	if v.versioned {
		return version == v.inv.Version, v.release
	}
	return !v.stale, v.release
}

// release counts the call; with a lane it also records whether the entry still held its full-lane grant (a competing full
// grant is refused until the entry's WithReservation returns, which spans Store.Update and the rest of its callback).
func (v *replayView) release() {
	v.releases++
	if v.lane != nil && v.lane.WithReservation(mdbx.MaxOperationDataBytes, func() error { return nil }) != nil {
		v.early++
	}
}

// replayComplete returns a Complete inventory of the given tips and headers with exact Bytes.
func replayComplete(tips [][32]byte, headers [][116]byte) HeaderCandidateInventoryV1 {
	return HeaderCandidateInventoryV1{Status: HeaderCandidateCompleteV1, Version: 7, Tips: tips, Headers: headers, Bytes: 32*uint64(len(tips)) + 116*uint64(len(headers))}
}

// replayHeader builds one header over parent with the caller's target and timestamp and the first nonce that passes
// PowCheck under that target.
func replayHeader(t testing.TB, parent [32]byte, target [32]byte, timestamp uint64) ([116]byte, [32]byte) {
	t.Helper()
	var h [116]byte
	binary.LittleEndian.PutUint32(h[:4], 1)
	copy(h[4:36], parent[:])
	binary.LittleEndian.PutUint64(h[68:76], timestamp)
	copy(h[76:108], target[:])
	for nonce := uint64(0); ; nonce++ {
		binary.LittleEndian.PutUint64(h[108:116], nonce)
		if PowCheck(h[:], target) == nil {
			hash, _ := BlockHash(h[:])
			return h, hash
		}
	}
}

// replayChain extends a parent with n qualifying headers.
func replayChain(t testing.TB, parent [32]byte, timestamp uint64, n int) ([][116]byte, [][32]byte) {
	t.Helper()
	headers, hashes := make([][116]byte, n), make([][32]byte, n)
	for i := range n {
		timestamp += 2 * TARGET_BLOCK_INTERVAL // slow enough that a retarget keeps POW_LIMIT
		headers[i], hashes[i] = replayHeader(t, parent, POW_LIMIT, timestamp)
		parent = hashes[i]
	}
	return headers, hashes
}

// replayWorld is a bootstrapped store with an optional seeded canonical chain 0..tip of generation 1.
type replayWorld struct {
	t        testing.TB
	store    *mdbx.Store
	owner    *mdbx.OperationReservationOwner
	reopen   func() *mdbx.Store
	genesis  PublishedGenesisContextV1
	hashes   [][32]byte
	headers  [][116]byte
	lastTime uint64
	pre      []mdbx.PrefixRow // pre-entry image recorded by snapshot
	watch    uint64           // the pre-entry next_generation_id recorded by snapshot; image() reads its counter row
}

func replayGenesis() PublishedGenesisContextV1 {
	block, chainID, hash := genesisMDBXFixture()
	return PublishedGenesisContextV1{ChainID: chainID, GenesisHash: hash, Published: block}
}

func replayIdentityOnly() PublishedGenesisContextV1 {
	g := replayGenesis()
	g.Published = nil
	return g
}

// newReplayWorld seeds canonical heights 0..tip (tip < 0: PRE_GENESIS) through the published genesis owner and one
// literal plan per 1,000 heights of headers, ChainValue entries and paired owner rows (seeding_boundary).
func newReplayWorld(t testing.TB, tip int) *replayWorld {
	t.Helper()
	w := &replayWorld{t: t, genesis: replayGenesis()}
	path := filepath.Join(t.TempDir(), "db")
	cfg := mdbx.ConfigV1{Lower: 1 << 20, Now: 2 << 20, Upper: 256 << 20, Growth: 1 << 20, Shrink: 2 << 20, PageSize: 4096, MaxReaders: 492}
	var err error
	w.store, err = mdbx.Create(path, cfg)
	logicalMDBXAssert(t, err == nil, "replay store: %v", err)
	t.Cleanup(func() { _ = w.store.Close() })
	w.owner, err = mdbx.NewOperationReservationOwner(mdbx.MaxOperationDataBytes)
	logicalMDBXAssert(t, err == nil, "replay owner: %v", err)
	truth, _, err := w.store.BootstrapStorageV1(mdbx.StorageProfilePrunedV1, w.owner)
	logicalMDBXAssert(t, err == nil && truth == mdbx.CommitTruthNew, "replay bootstrap: %v", err)
	// reopen closes the handle (a consumed handle may refuse Close) and opens the same path.
	w.reopen = func() *mdbx.Store {
		_ = w.store.Close()
		store, err := mdbx.Open(path, cfg)
		logicalMDBXAssert(t, err == nil, "replay reopen: %v", err)
		t.Cleanup(func() { _ = store.Close() })
		return store
	}
	block := w.genesis.Published
	w.headers, w.hashes = [][116]byte{[116]byte(block[:116])}, [][32]byte{w.genesis.GenesisHash}
	w.lastTime = binary.LittleEndian.Uint64(block[68:76])
	if tip < 0 {
		return w
	}
	genesisMDBXReturned(t, genesisMDBXRun(w.store, w.owner), "ACCEPTED", 2, 3, "replay world genesis")
	headers, hashes := replayChain(t, w.genesis.GenesisHash, w.lastTime, tip)
	w.headers, w.hashes = append(w.headers, headers...), append(w.hashes, hashes...)
	if tip > 0 {
		w.lastTime += 2 * TARGET_BLOCK_INTERVAL * uint64(tip)
	}
	for from := 1; from <= tip; from += 1000 {
		w.apply(w.canonicalRows(from, min(from+999, tip))...)
	}
	return w
}

// canonicalRows is the seeded literal plan for heights from..to of generation 1 (work = height+1 under POW_LIMIT).
func (w *replayWorld) canonicalRows(from, to int) []mdbx.Mutation {
	var rows []mdbx.Mutation
	for h := from; h <= to; h++ {
		hash := w.hashes[h]
		rows = append(rows,
			mdbx.Mutation{DBI: logicalMDBXDBIs[3], Key: bytes.Clone(hash[:]), AfterKind: mdbx.AfterLiteral, Literal: bytes.Clone(w.headers[h][:])},
			mdbx.Mutation{DBI: logicalMDBXDBIs[2], Key: logicalMDBXMust(mdbx.HeightKey(1, uint64(h))), AfterKind: mdbx.AfterLiteral, Literal: mdbx.ChainValue(hash, w.hashes[h-1], sideWorldWork(uint64(h)+1))},
			mdbx.Mutation{DBI: logicalMDBXDBIs[7], Key: logicalMDBXMust(mdbx.CanonicalOwnerKey(1, hash)), AfterKind: mdbx.AfterLiteral, Literal: mdbx.CanonicalOwnerValue(uint64(h))})
	}
	return rows
}

func (w *replayWorld) apply(rows ...mdbx.Mutation) {
	w.t.Helper()
	slices.SortFunc(rows, func(a, b mdbx.Mutation) int {
		if a.DBI.Rank != b.DBI.Rank {
			return int(a.DBI.Rank) - int(b.DBI.Rank)
		}
		return bytes.Compare(a.Key, b.Key)
	})
	truth, _, err := w.store.Update(func(*mdbx.Reader) (mdbx.Batch, error) { return mdbx.Batch{Mutations: rows}, nil })
	logicalMDBXAssert(w.t, err == nil && truth == mdbx.CommitTruthNew, "replay world write: %v/%v", truth, err)
}

func (w *replayWorld) authority() mdbx.StorageAuthorityV1 {
	w.t.Helper()
	var a mdbx.StorageAuthorityV1
	err := w.store.View(func(r *mdbx.Reader) (err error) { a, err = r.ReadStorageAuthorityV1(); return err })
	logicalMDBXAssert(w.t, err == nil, "read authority: %v", err)
	return a
}

// snapshot records the pre-entry image for replayCommitted and returns the pre-entry authority.
func (w *replayWorld) snapshot() mdbx.StorageAuthorityV1 {
	a := w.authority()
	w.watch = uint64(a.NextGenerationID)
	w.pre = w.image()
	return a
}

// setAuthority writes an edited authority literal.
func (w *replayWorld) setAuthority(edit func(*mdbx.StorageAuthorityV1)) {
	w.t.Helper()
	a := w.authority()
	edit(&a)
	encoded, err := a.Encode()
	logicalMDBXAssert(w.t, err == nil && mdbx.ValidateStorageAuthorityV1(a) == nil, "seed authority: %v", err)
	w.apply(mdbx.Mutation{DBI: logicalMDBXDBIs[0], Key: []byte{2}, BeforePresent: true, AfterKind: mdbx.AfterLiteral, Literal: encoded})
}

// pending seeds NONE/RECOVERY_REQUIRED with a pending profile and the given next id.
func (w *replayWorld) pending(profile mdbx.StorageProfileV1, next uint64) {
	w.setAuthority(func(a *mdbx.StorageAuthorityV1) {
		a.Lifecycle, a.PendingTargetProfile, a.NextGenerationID = mdbx.StorageLifecycleRecoveryRequiredV1, &profile, next
	})
}

// replayImageGenerations bounds the generations image() reads row by row (index, owner and counter rows); a larger
// allocated id is read through w.watch (the A10 world), and the per-DBI entry counts cover every other row.
const replayImageGenerations = 16

// image is the entry count of each DBI (Store.Inspect, before the View) and, under one Reader, the authority, schema and
// counter metadata (counter ids 1..15 and w.watch), every seeded header row and every canonical-index (DBI 2) and
// canonical-owner (DBI 7) row of generations 1..15. Keys carry the DBI rank as a first byte; the count row has key 0xff.
func (w *replayWorld) image() []mdbx.PrefixRow {
	w.t.Helper()
	inspection, err := w.store.Inspect()
	logicalMDBXAssert(w.t, err == nil, "image inspect: %v", err)
	counts := []byte{}
	for _, d := range inspection.DBIs {
		counts = binary.BigEndian.AppendUint64(counts, d.Entries)
	}
	rows := []mdbx.PrefixRow{{Key: []byte{0xff}, Value: counts}}
	err = w.store.View(func(r *mdbx.Reader) error {
		keys := [][]byte{{0}, {1}, {2}}
		for id := uint64(1); id < replayImageGenerations; id++ {
			keys = append(keys, binary.BigEndian.AppendUint64([]byte{0x10}, id))
		}
		if w.watch >= replayImageGenerations {
			keys = append(keys, binary.BigEndian.AppendUint64([]byte{0x10}, w.watch))
		}
		for _, key := range keys {
			if err := replayImageGet(r, &rows, 0, key); err != nil {
				return err
			}
		}
		for _, hash := range w.hashes {
			if err := replayImageGet(r, &rows, 3, bytes.Clone(hash[:])); err != nil {
				return err
			}
		}
		for g := uint64(1); g < replayImageGenerations; g++ {
			for _, rank := range []uint8{2, 7} {
				if err := replayImagePrefix(r, &rows, rank, binary.BigEndian.AppendUint64(nil, g)); err != nil {
					return err
				}
			}
		}
		return nil
	})
	logicalMDBXAssert(w.t, err == nil, "image: %v", err)
	return rows
}

func replayImageGet(r *mdbx.Reader, rows *[]mdbx.PrefixRow, rank uint8, key []byte) error {
	value, present, err := r.Get(logicalMDBXDBIs[rank], key)
	if present {
		*rows = append(*rows, mdbx.PrefixRow{Key: append([]byte{rank}, key...), Value: value})
	}
	return err
}

// replayImagePrefix appends every row of one DBI under an 8-byte generation prefix, page by page.
func replayImagePrefix(r *mdbx.Reader, rows *[]mdbx.PrefixRow, rank uint8, prefix []byte) error {
	var after []byte
	for {
		page, err := r.PrefixPage(logicalMDBXDBIs[rank], prefix, after, mdbx.MaxPrefixPageRows, mdbx.MaxPrefixPageBytes)
		if err != nil {
			return err
		}
		for _, row := range page.Rows {
			*rows = append(*rows, mdbx.PrefixRow{Key: append([]byte{rank}, row.Key...), Value: row.Value})
			after = row.Key
		}
		if page.Stop == mdbx.PrefixPageExhausted {
			return nil
		}
	}
}

func replayImagesEqual(before, after []mdbx.PrefixRow) bool {
	ok := len(before) == len(after)
	for i := 0; ok && i < len(before); i++ {
		ok = bytes.Equal(before[i].Key, after[i].Key) && bytes.Equal(before[i].Value, after[i].Value)
	}
	return ok
}

func replaySameImage(t *testing.T, before, after []mdbx.PrefixRow, label string) {
	t.Helper()
	logicalMDBXAssert(t, replayImagesEqual(before, after), "%s: image changed", label)
}

// Selectivity of image(): index and owner rows of another generation and a header row outside w.hashes each change it
// (the owner-only overwrite is TestReplayEntryFixtureImageOwner).
func TestReplayEntryImageSelectivity(t *testing.T) {
	for label, rows := range map[string]func(w *replayWorld) []mdbx.Mutation{
		"generation 2 rows": func(w *replayWorld) []mdbx.Mutation {
			return []mdbx.Mutation{
				{DBI: logicalMDBXDBIs[2], Key: logicalMDBXMust(mdbx.HeightKey(2, 1)), AfterKind: mdbx.AfterLiteral, Literal: mdbx.ChainValue(w.hashes[1], w.hashes[0], sideWorldWork(2))},
				{DBI: logicalMDBXDBIs[7], Key: logicalMDBXMust(mdbx.CanonicalOwnerKey(2, w.hashes[1])), AfterKind: mdbx.AfterLiteral, Literal: mdbx.CanonicalOwnerValue(1)},
			}
		},
		"header outside w.hashes": func(w *replayWorld) []mdbx.Mutation {
			headers, hashes := replayChain(t, w.hashes[3], w.lastTime, 1)
			return []mdbx.Mutation{{DBI: logicalMDBXDBIs[3], Key: bytes.Clone(hashes[0][:]), AfterKind: mdbx.AfterLiteral, Literal: bytes.Clone(headers[0][:])}}
		},
	} {
		w := newReplayWorld(t, 3)
		image := w.image()
		w.apply(rows(w)...)
		logicalMDBXAssert(t, !replayImagesEqual(image, w.image()), "%s: image did not change", label)
	}
	// A value-only overwrite of generation-2 rows (entry counts unchanged) changes it through the row reads alone.
	w := newReplayWorld(t, 3)
	gen2 := func(work uint64) []mdbx.Mutation {
		return []mdbx.Mutation{
			{DBI: logicalMDBXDBIs[2], Key: logicalMDBXMust(mdbx.HeightKey(2, 1)), BeforePresent: work != 2, AfterKind: mdbx.AfterLiteral, Literal: mdbx.ChainValue(w.hashes[1], w.hashes[0], sideWorldWork(work))},
			{DBI: logicalMDBXDBIs[7], Key: logicalMDBXMust(mdbx.CanonicalOwnerKey(2, w.hashes[1])), BeforePresent: work != 2, AfterKind: mdbx.AfterLiteral, Literal: mdbx.CanonicalOwnerValue(1)},
		}
	}
	w.apply(gen2(2)...)
	image := w.image()
	w.apply(gen2(3)...)
	logicalMDBXAssert(t, !replayImagesEqual(image, w.image()), "generation 2 overwrite: image did not change")
}

func (w *replayWorld) enter(view HeaderCandidateViewV1, genesis PublishedGenesisContextV1) ReplayEntryOutcomeV1 {
	return NewReplayEntryOwnerV1(view, genesis).EnterReplayTargetMDBX(w.store, w.owner)
}

// replayDecided asserts a zero-mutation callback decision: raw (OLD, Prewrite), nil Err, CanonicalTruth OLD.
func replayDecided(t *testing.T, out ReplayEntryOutcomeV1, result, decision, label string) {
	t.Helper()
	logicalMDBXAssert(t, out.Result == result && out.Decision == decision && out.Err == nil && out.CanonicalTruth == "OLD" &&
		out.Truth == mdbx.CommitTruthOld && out.Stage == mdbx.UpdateStagePrewrite, "%s: %+v", label, out)
}

// replayHeldSame runs a held entry, asserts the decided tuple and that the persisted image is unchanged.
func replayHeldSame(t *testing.T, w *replayWorld, view HeaderCandidateViewV1, hold uint64, result, decision, label string) ReplayEntryOutcomeV1 {
	t.Helper()
	image := w.image()
	out := w.held(view, w.genesis, hold)
	replayDecided(t, out, result, decision, label)
	replaySameImage(t, image, w.image(), label)
	return out
}

// replayExpected is the contract plan (6) authority after a normal entry commit over before, its encoding and the
// target counter key.
func replayExpected(t *testing.T, w *replayWorld, before mdbx.StorageAuthorityV1, profile mdbx.StorageProfileV1, tip [32]byte, height uint64, work uint64) (mdbx.StorageAuthorityV1, []byte, []byte) {
	t.Helper()
	want := mdbx.ReplayV1{
		TargetProfile: profile, TargetGenerationID: before.NextGenerationID, Cursor: mdbx.ReplayCursorV1{Kind: mdbx.ReplayCursorPreGenesisV1},
		Target: mdbx.RecoveryTargetV1{ChainID: w.genesis.ChainID, GenesisHash: w.genesis.GenesisHash, TipHash: tip, TipHeight: height, CumulativeChainwork: sideWorldWork(work)},
	}
	expected := before
	expected.Phase, expected.Lifecycle, expected.PendingTargetProfile, expected.Replay = mdbx.StoragePhaseReplayV1, mdbx.StorageLifecycleRecoveryRequiredV1, nil, &want
	expected.NextGenerationID = before.NextGenerationID + 1
	encoded, err := expected.Encode()
	logicalMDBXAssert(t, err == nil && uint64(before.NextGenerationID) == w.watch, "expected image: %v (target id %d, watched %d)", err, before.NextGenerationID, w.watch)
	return expected, encoded, binary.BigEndian.AppendUint64([]byte{0x10}, uint64(before.NextGenerationID))
}

// replayCommitted asserts a normal NEW entry commit (Stage 3, nil Err, empty Result and Decision): the whole persisted
// authority equals the pre-entry authority with only the REPLAY fields changed, and the image differs from the
// pre-entry image (w.pre) only in the authority row, the new target counter row and the meta entry count (every
// canonical-index, canonical-owner and header row and every other DBI's entry count byte-identical).
func replayCommitted(t *testing.T, w *replayWorld, out ReplayEntryOutcomeV1, before mdbx.StorageAuthorityV1, profile mdbx.StorageProfileV1, tip [32]byte, height uint64, work uint64) {
	t.Helper()
	logicalMDBXAssert(t, out.Result == "" && out.Decision == "" && out.Err == nil && out.CanonicalTruth == "NEW" && out.Truth == mdbx.CommitTruthNew &&
		out.Stage == mdbx.UpdateStageCommitMayHaveCrossed, "commit: %+v", out)
	expected, encoded, counterKey := replayExpected(t, w, before, profile, tip, height, work)
	a := w.authority()
	logicalMDBXAssert(t, reflect.DeepEqual(a, expected) && out.Replay != nil && *out.Replay == *expected.Replay, "authority: %+v want %+v", a, expected)
	logicalMDBXAssert(t, w.pre != nil, "pre-image recorded")
	rows := map[string][]byte{}
	for _, row := range w.pre {
		rows[string(row.Key)] = row.Value
	}
	counts := bytes.Clone(rows[string([]byte{0xff})])
	if _, ok := rows[string(append([]byte{0}, counterKey...))]; !ok {
		binary.BigEndian.PutUint64(counts[:8], binary.BigEndian.Uint64(counts[:8])+1)
	}
	rows[string([]byte{0xff})], rows[string([]byte{0, 2})] = counts, encoded
	rows[string(append([]byte{0}, counterKey...))] = mdbx.LogicalCounterValue(0, 0)
	post := w.image()
	same := len(post) == len(rows)
	for _, row := range post {
		value, ok := rows[string(row.Key)]
		same = same && ok && bytes.Equal(value, row.Value)
	}
	logicalMDBXAssert(t, same, "mutation set: %d rows after, %d expected", len(post), len(rows))
}

func TestReplayEntryConstants(t *testing.T) {
	logicalMDBXAssert(t, replayEntryWalkBytes == 404_070 && replayEntryPlanBytes == 3_146_240 && replayEntryInventoryLimit == 71_815_566, "lane terms %d %d %d", replayEntryWalkBytes, replayEntryPlanBytes, replayEntryInventoryLimit)
}

// activate seeds canonical 0..len(w.hashes)-1 as generation g (index and owner rows) and makes g the active generation.
func (w *replayWorld) activate(g uint64) {
	w.t.Helper()
	var rows []mdbx.Mutation
	for h, hash := range w.hashes {
		var parent [32]byte
		if h > 0 {
			parent = w.hashes[h-1]
		}
		rows = append(rows,
			mdbx.Mutation{DBI: logicalMDBXDBIs[2], Key: logicalMDBXMust(mdbx.HeightKey(g, uint64(h))), AfterKind: mdbx.AfterLiteral, Literal: mdbx.ChainValue(hash, parent, sideWorldWork(uint64(h)+1))},
			mdbx.Mutation{DBI: logicalMDBXDBIs[7], Key: logicalMDBXMust(mdbx.CanonicalOwnerKey(g, hash)), AfterKind: mdbx.AfterLiteral, Literal: mdbx.CanonicalOwnerValue(uint64(h))})
	}
	w.apply(rows...)
	w.setAuthority(func(a *mdbx.StorageAuthorityV1) { a.ActiveGenerationID, a.NextGenerationID = g, g+1 })
}

// A2 (active 1, next 2) and A14 (active 4, next 7): pending PRUNED NONE/RECOVERY_REQUIRED over canonical 0..10 binds a
// received tip at 12 extending the canonical tip; A7 resumes a persisted REPLAY whose cursor is APPLIED(10, h10).
func TestReplayEntrySourceD(t *testing.T) {
	for _, c := range []struct{ active, next uint64 }{{1, 2}, {4, 7}} {
		w := newReplayWorld(t, 10)
		if c.active != 1 {
			w.activate(c.active)
		}
		w.pending(mdbx.StorageProfilePrunedV1, c.next)
		logicalMDBXAssert(t, uint64(w.authority().ActiveGenerationID) == c.active, "A14 premise: active %d", w.authority().ActiveGenerationID)
		before := w.snapshot()
		headers, hashes := replayChain(t, w.hashes[10], w.lastTime, 2)
		view := &replayView{inv: replayComplete([][32]byte{hashes[1]}, headers), lane: w.owner}
		out := w.enter(view, w.genesis)
		replayCommitted(t, w, out, before, mdbx.StorageProfilePrunedV1, hashes[1], 12, 13)
		logicalMDBXAssert(t, view.calls == 1 && view.releases == 1 && view.early == 0 && len(view.versions) == 1 && view.versions[0] == 7 && view.limits[0] == 71_815_566, "view: %+v", view)
		// A13: a fresh handle reads exactly the committed image.
		committed := w.image()
		w.store = w.reopen()
		image := w.image()
		replaySameImage(t, committed, image, "A13 reopened image")
		if c.next == 2 {
			// A7: the persisted REPLAY (target 2, next 3) has applied through height 10; a repeated request resumes it.
			w.setAuthority(func(a *mdbx.StorageAuthorityV1) {
				a.Replay.Cursor = mdbx.ReplayCursorV1{Kind: mdbx.ReplayCursorAppliedV1, Height: 10, BlockHash: w.hashes[10]}
			})
			a := w.authority()
			logicalMDBXAssert(t, a.Replay.TargetGenerationID == 2 && a.NextGenerationID == 3 && a.Replay.Cursor.Kind == mdbx.ReplayCursorAppliedV1, "A7 premise: %+v", a)
			image = w.image()
		}
		again := w.enter(view, w.genesis)
		replayDecided(t, again, "", replayEntryResume, "resume")
		logicalMDBXAssert(t, again.Replay != nil && *again.Replay == *w.authority().Replay, "resume replay: %+v", again.Replay)
		replaySameImage(t, image, w.image(), "resume")
	}
}

// A3: pending ARCHIVE with active PRUNED: target_profile ARCHIVE, active profile unchanged.
func TestReplayEntryPendingArchive(t *testing.T) {
	w := newReplayWorld(t, 3)
	w.pending(mdbx.StorageProfileArchiveV1, 2)
	w.setAuthority(func(a *mdbx.StorageAuthorityV1) { a.B, a.U = 5000, 5000+13680 }) // PRUNED requires U = B + 13,680.
	before := w.snapshot()
	logicalMDBXAssert(t, before.B == 5000 && before.ActiveProfile == mdbx.StorageProfilePrunedV1, "A3 premise: %+v", before)
	headers, hashes := replayChain(t, w.hashes[3], w.lastTime, 1)
	out := w.enter(&replayView{inv: replayComplete([][32]byte{hashes[0]}, headers)}, w.genesis)
	replayCommitted(t, w, out, before, mdbx.StorageProfileArchiveV1, hashes[0], 4, 5)
}

// A9: source (b) at NONE/STABLE/PRE_GENESIS with an identity-only context binds T@10 through the received anchor h0.
func TestReplayEntrySourceBIdentityOnly(t *testing.T) {
	w := newReplayWorld(t, -1)
	before := w.snapshot()
	headers, hashes := replayChain(t, w.genesis.GenesisHash, w.lastTime, 10)
	all := append([][116]byte{w.headers[0]}, headers...)
	out := w.enter(&replayView{inv: replayComplete([][32]byte{hashes[9]}, all)}, replayIdentityOnly())
	replayCommitted(t, w, out, before, mdbx.StorageProfilePrunedV1, hashes[9], 10, 11)
	// R22b-shaped: without h0 the identity-only request is incomplete evidence.
	w2 := newReplayWorld(t, -1)
	image := w2.image()
	out = w2.enter(&replayView{inv: replayComplete([][32]byte{hashes[9]}, headers)}, replayIdentityOnly())
	replayDecided(t, out, replayEntryRecovery, "", "no anchor")
	replaySameImage(t, image, w2.image(), "no anchor")
	// R22b: source (b), identity-only context, Incomplete inventory: the same tuple, NONE/STABLE/PRE_GENESIS, next 2 unchanged.
	w3 := newReplayWorld(t, -1)
	image = w3.image()
	incomplete := &replayView{inv: HeaderCandidateInventoryV1{Status: HeaderCandidateIncompleteV1}}
	replayDecided(t, w3.enter(incomplete, replayIdentityOnly()), replayEntryRecovery, "", "R22b incomplete")
	a := w3.authority()
	logicalMDBXAssert(t, incomplete.calls == 1 && a.Phase == mdbx.StoragePhaseNoneV1 && a.Lifecycle == mdbx.StorageLifecycleStableV1 && a.NextGenerationID == 2, "R22b: calls %d %+v", incomplete.calls, a)
	replaySameImage(t, image, w3.image(), "R22b")
}

// R19b: complete Published bytes at PRE_GENESIS: genesis first before any inventory, whether the producer's inventory
// would be Complete (with an eligible-shaped tip), Incomplete or CapacityRefused.
func TestReplayEntryGenesisFirst(t *testing.T) {
	w := newReplayWorld(t, -1)
	image := w.image()
	headers, hashes := replayChain(t, w.genesis.GenesisHash, w.lastTime, 2)
	for _, inv := range []HeaderCandidateInventoryV1{replayComplete([][32]byte{hashes[1]}, headers), {Status: HeaderCandidateIncompleteV1}, {Status: HeaderCandidateCapacityRefusedV1}} {
		view := &replayView{inv: inv}
		replayDecided(t, w.enter(view, w.genesis), "", replayEntryGenesisFirst, fmt.Sprintf("genesis first, status %d", inv.Status))
		logicalMDBXAssert(t, view.calls == 0, "inventory before genesis first: %d", view.calls)
		replaySameImage(t, image, w.image(), "genesis first")
	}
}

// R19: source (b) after genesis committed is not eligible.
func TestReplayEntryNotEligible(t *testing.T) {
	w := newReplayWorld(t, 0)
	image := w.image()
	view := &replayView{inv: replayComplete(nil, nil)}
	replayDecided(t, w.enter(view, replayIdentityOnly()), "", replayEntryNotEligible, "after genesis")
	logicalMDBXAssert(t, view.calls == 0, "inventory: %d", view.calls)
	replaySameImage(t, image, w.image(), "after genesis")
}

// R36/R37: a bad context refuses before any Store or reservation work: with a nil Store and with a live Store, and with a
// free, a nil and a fully held reservation owner (either of which would refuse first if it were consulted).
func TestReplayEntryContext(t *testing.T) {
	bad := replayGenesis()
	bad.Published = bytes.Clone(bad.Published)
	bad.Published[200] ^= 1 // outside the header: the ChainID commitment fails
	hashMismatch := replayGenesis()
	hashMismatch.GenesisHash[0] ^= 1 // BlockHash(Published[:116]) differs; ChainID still matches
	short := replayGenesis()
	short.Published = short.Published[:265]
	zero := replayGenesis()
	zero.ChainID = [32]byte{}
	zeroHash := replayGenesis()
	zeroHash.GenesisHash = [32]byte{}
	w := pendingWorld(t, 3)
	image := w.image()
	for _, c := range []struct {
		g    PublishedGenesisContextV1
		text string
	}{{bad, "published genesis context commitment mismatch"}, {hashMismatch, "published genesis context commitment mismatch"}, {short, "invalid published genesis context"}, {zero, "invalid published genesis context"}, {zeroHash, "invalid published genesis context"}} {
		for _, run := range []struct {
			store *mdbx.Store
			owner *mdbx.OperationReservationOwner
			hold  bool
		}{{nil, w.owner, false}, {w.store, w.owner, false}, {w.store, nil, false}, {w.store, w.owner, true}, {nil, nil, false}} {
			view := &replayView{}
			var out ReplayEntryOutcomeV1
			enter := func() error {
				out = NewReplayEntryOwnerV1(view, c.g).EnterReplayTargetMDBX(run.store, run.owner)
				return nil
			}
			if run.hold {
				logicalMDBXAssert(t, w.owner.WithReservation(mdbx.MaxOperationDataBytes, enter) == nil, "held lane")
			} else {
				_ = enter()
			}
			logicalMDBXAssert(t, out.Result == selectedSideInvariant && out.CanonicalTruth == "OLD" && out.Err != nil && out.Err.Error() == c.text && out.Decision == "" && out.Replay == nil &&
				out.Truth == mdbx.CommitTruthOld && out.Stage == mdbx.UpdateStagePrewrite && view.calls == 0, "context %q: %+v", c.text, out)
		}
		replaySameImage(t, image, w.image(), "R36/R37 zero mutation "+c.text)
		// No reservation is left held: the full lane is still grantable.
		logicalMDBXAssert(t, w.owner.WithReservation(mdbx.MaxOperationDataBytes, func() error { return nil }) == nil, "R36/R37 owner lane")
	}
	// Positive control: the same Store and owner then serve a valid context normally.
	headers, hashes := w.fork(3, 1, 1)
	before := w.snapshot()
	replayCommitted(t, w, w.enter(&replayView{inv: replayComplete([][32]byte{hashes[0]}, headers)}, w.genesis), before, mdbx.StorageProfilePrunedV1, hashes[0], 4, 5)
}

// fork builds n received headers on canonical height k; skew shifts the timestamps to vary the hashes.
func (w *replayWorld) fork(k, n int, skew uint64) ([][116]byte, [][32]byte) {
	w.t.Helper()
	return replayChain(w.t, w.hashes[k], binary.LittleEndian.Uint64(w.headers[k][68:76])+skew, n)
}

// pendingWorld is canonical 0..tip under pending PRUNED NONE/RECOVERY_REQUIRED with next = 3.
func pendingWorld(t testing.TB, tip int) *replayWorld {
	w := newReplayWorld(t, tip)
	w.pending(mdbx.StorageProfilePrunedV1, 3)
	return w
}

// replayRefused asserts a zero-mutation decided refusal with the pre-state image unchanged.
func replayRefused(t *testing.T, w *replayWorld, view *replayView, genesis PublishedGenesisContextV1, result, label string) {
	t.Helper()
	image := w.image()
	out := w.enter(view, genesis)
	replayDecided(t, out, result, "", label)
	logicalMDBXAssert(t, out.Replay == nil, "%s: ReplayV1 %+v", label, out.Replay)
	replaySameImage(t, image, w.image(), label)
}

// A5: equal chainwork: the lexicographically smaller tip hash is bound, whichever fork carries it (the skew pairs put
// the smaller tip on the first fork in some runs and on the second in others).
func TestReplayEntryTieSmallerHash(t *testing.T) {
	seen := map[int]bool{}
	for skew := uint64(2); skew <= 9; skew++ {
		w := pendingWorld(t, 5)
		before := w.snapshot()
		h1, t1 := w.fork(5, 3, 1)
		h2, t2 := w.fork(5, 3, skew)
		want, fork := t1[2], 1
		if bytes.Compare(t2[2][:], want[:]) < 0 {
			want, fork = t2[2], 2
		}
		seen[fork] = true
		view := &replayView{inv: replayComplete([][32]byte{t1[2], t2[2]}, append(h1, h2...))}
		replayCommitted(t, w, w.enter(view, w.genesis), before, mdbx.StorageProfilePrunedV1, want, 8, 9)
	}
	logicalMDBXAssert(t, seen[1] && seen[2], "A5: the smaller tip lay on one fork only: %v", seen)
}

// A6 and R4: a path containing the excluded hash is skipped; when every received path contains it, the N1 published
// prefix tip below the excluded canonical height is the target (RUB-1571: world w2 was recovery_artifact "all excluded"
// before MP 2544-2561 and now commits hashes[1], height 1, work 2); an excluded height 0 leaves no target.
func TestReplayEntryExclusion(t *testing.T) {
	w := pendingWorld(t, 5)
	long, longTips := w.fork(5, 4, 1)
	short, shortTips := w.fork(5, 2, 2)
	exclude := func(w *replayWorld, hash [32]byte) {
		w.setAuthority(func(a *mdbx.StorageAuthorityV1) {
			a.ExcludedInvalidBranch = &mdbx.InvalidBranchV1{FirstInvalidHeight: 7, FirstInvalidBlockHash: hash, ExactConsensusError: []byte("BLOCK_ERR_POW_INVALID")}
		})
	}
	exclude(w, longTips[1])
	before := w.snapshot()
	view := &replayView{inv: replayComplete([][32]byte{longTips[3], shortTips[1]}, append(long, short...))}
	replayCommitted(t, w, w.enter(view, w.genesis), before, mdbx.StorageProfilePrunedV1, shortTips[1], 7, 8)
	logicalMDBXAssert(t, w.authority().ExcludedInvalidBranch != nil, "exclusion dropped")
	w2 := pendingWorld(t, 5)
	exclude(w2, w2.hashes[2])
	before = w2.snapshot()
	view = &replayView{inv: replayComplete([][32]byte{longTips[3]}, long)}
	replayCommitted(t, w2, w2.enter(view, w2.genesis), before, mdbx.StorageProfilePrunedV1, w2.hashes[1], 1, 2)
	// R4 at a non-empty index: the excluded genesis hash at height 0 makes every path ineligible.
	w3 := pendingWorld(t, 5)
	logicalMDBXAssert(t, w3.hashes[0] == w3.genesis.GenesisHash, "R4 premise: canonical height 0 is the genesis hash")
	w3.setAuthority(func(a *mdbx.StorageAuthorityV1) {
		a.ExcludedInvalidBranch = &mdbx.InvalidBranchV1{FirstInvalidHeight: 0, FirstInvalidBlockHash: w3.genesis.GenesisHash, ExactConsensusError: []byte("BLOCK_ERR_POW_INVALID")}
	})
	view = &replayView{inv: replayComplete([][32]byte{longTips[3]}, long)}
	replayRefused(t, w3, view, w3.genesis, replayEntryRecovery, "R4 excluded genesis at height 0")
}

// R1, R2, R3/H19, H22, R58: no positive target, an empty set, a received gap, an unknown tip and an unattached
// header are recovery_artifact with zero mutation.
func TestReplayEntryIncompleteEvidence(t *testing.T) {
	w := pendingWorld(t, 0)
	replayRefused(t, w, &replayView{inv: replayComplete(nil, nil)}, w.genesis, replayEntryRecovery, "R1 height-zero only")
	w = pendingWorld(t, -1)
	replayRefused(t, w, &replayView{inv: replayComplete(nil, nil)}, w.genesis, replayEntryRecovery, "R2 empty set")
	w = pendingWorld(t, 4)
	headers, hashes := w.fork(4, 4, 1)
	gap := append([][116]byte{headers[0]}, headers[2:]...)
	t.Run("R3", func(t *testing.T) {
		w := pendingWorld(t, 4)
		replayRefused(t, w, &replayView{inv: replayComplete([][32]byte{hashes[3]}, gap)}, w.genesis, replayEntryRecovery, "R3 gap")
	})
	t.Run("H22", func(t *testing.T) {
		w := pendingWorld(t, 4)
		replayRefused(t, w, &replayView{inv: replayComplete([][32]byte{{0x55}}, headers)}, w.genesis, replayEntryRecovery, "H22 unknown tip")
	})
	t.Run("R58", func(t *testing.T) {
		w := pendingWorld(t, 4)
		foreign, foreignTips := replayChain(t, [32]byte{0x66}, 2_000_000_000, 2)
		view := &replayView{inv: replayComplete([][32]byte{foreignTips[1], hashes[3]}, append(foreign, headers...))}
		replayRefused(t, w, view, w.genesis, replayEntryRecovery, "R58 unattached")
	})
}

// R5, R7 shape, A10, R21: sequence exhaustion after qualification; no eligible target wins over exhaustion.
func TestReplayEntrySequence(t *testing.T) {
	w := newReplayWorld(t, 3)
	headers, hashes := w.fork(3, 1, 1)
	t.Run("R5", func(t *testing.T) {
		w := newReplayWorld(t, 3)
		w.pending(mdbx.StorageProfilePrunedV1, 1<<64-1)
		view := &replayView{inv: replayComplete([][32]byte{hashes[0]}, headers)}
		replayRefused(t, w, view, w.genesis, selectedSideInvariant, "R5 exhausted")
		logicalMDBXAssert(t, view.releases == 1, "R5 release: %d", view.releases)
	})
	t.Run("R21", func(t *testing.T) {
		w0 := newReplayWorld(t, 0)
		w0.pending(mdbx.StorageProfilePrunedV1, 1<<64-1)
		replayRefused(t, w0, &replayView{inv: replayComplete(nil, nil)}, w0.genesis, replayEntryRecovery, "R21 none eligible")
	})
	w.pending(mdbx.StorageProfilePrunedV1, 1<<64-2)
	before := w.snapshot()
	replayCommitted(t, w, w.enter(&replayView{inv: replayComplete([][32]byte{hashes[0]}, headers)}, w.genesis), before, mdbx.StorageProfilePrunedV1, hashes[0], 4, 5)
}

// R11, R40a-e, H20, H21, R11b: protection and view postconditions.
func TestReplayEntryViewContract(t *testing.T) {
	w := pendingWorld(t, 3)
	headers, hashes := w.fork(3, 1, 1)
	good := replayComplete([][32]byte{hashes[0]}, headers)
	// R11: after the inventory the producer admits a qualified H+1 header outranking T and advances its Version, so
	// ProtectV1 of the inventory's Version reports current=false.
	good.Version = 7
	stale := &replayView{inv: good, versioned: true, lane: w.owner}
	next, nextHash := replayChain(t, hashes[0], binary.LittleEndian.Uint64(headers[0][68:76]), 1)
	stale.admit = func() {
		stale.inv = replayComplete([][32]byte{nextHash[0]}, append(slices.Clone(headers), next...))
		stale.inv.Version = 8
	}
	replayRefused(t, w, stale, w.genesis, replayEntryStale, "R11 stale")
	logicalMDBXAssert(t, stale.releases == 1 && stale.early == 0 && slices.Equal(stale.versions, []uint64{7}), "R11 release: %d, while the entry's full-lane grant was held: %d, versions %v", stale.releases, stale.early, stale.versions)
	good.Version = 0
	nilRelease := &replayView{inv: good, nilRelease: true}
	replayRefused(t, w, nilRelease, w.genesis, selectedSideInvariant, "R40b nil release")
	off := good
	off.Bytes++
	replayRefused(t, w, &replayView{inv: off}, w.genesis, selectedSideInvariant, "R40a bytes")
	// R40a: an Incomplete inventory carrying one Tip (consistent Bytes) reaches the non-zero-payload refusal; the same
	// for CapacityRefused with a Tip and a Header. Status 9 with payload is refused too, by the unknown-status check or
	// the payload check alike, so that case does not isolate the payload refusal.
	one := HeaderCandidateInventoryV1{Status: HeaderCandidateIncompleteV1, Tips: [][32]byte{hashes[0]}, Bytes: 32}
	replayRefused(t, w, &replayView{inv: one}, w.genesis, selectedSideInvariant, "R40a incomplete with one tip")
	for _, status := range []HeaderCandidateStatusV1{HeaderCandidateCapacityRefusedV1, 9} {
		tipped := HeaderCandidateInventoryV1{Status: status, Tips: [][32]byte{hashes[0]}, Headers: headers[:1], Bytes: 32 + 116}
		replayRefused(t, w, &replayView{inv: tipped}, w.genesis, selectedSideInvariant, fmt.Sprintf("R40a status %d with payload", status))
	}
	// R40c: matching accounting above the limit (one tip, 619,100 headers, Bytes = limit + 66).
	over := HeaderCandidateInventoryV1{Status: HeaderCandidateCompleteV1, Tips: [][32]byte{hashes[0]}, Headers: make([][116]byte, 619_100)}
	over.Bytes = 32 + 116*uint64(len(over.Headers))
	logicalMDBXAssert(t, over.Bytes == replayEntryInventoryLimit+66, "R40c premise: %d limit %d", over.Bytes, uint64(replayEntryInventoryLimit))
	replayRefused(t, w, &replayView{inv: over}, w.genesis, selectedSideInvariant, "R40c above limit")
	// R40e: an out-of-range Status with empty Tips and Headers and Bytes 0 reaches the unknown-status refusal.
	unknown := HeaderCandidateInventoryV1{Status: 9}
	replayRefused(t, w, &replayView{inv: unknown}, w.genesis, selectedSideInvariant, "R40e status")
	capacity := &replayView{inv: HeaderCandidateInventoryV1{Status: HeaderCandidateCapacityRefusedV1}}
	replayRefused(t, w, capacity, w.genesis, selectedSideCapacity, "H20 capacity")
	logicalMDBXAssert(t, slices.Equal(capacity.limits, []uint64{71_815_566}), "H20 limit %v", capacity.limits)
	// R11b: after a restart (the path reopened) the producer reports the view not re-established.
	w.store = w.reopen()
	restarted := &replayView{inv: HeaderCandidateInventoryV1{Status: HeaderCandidateIncompleteV1}}
	replayRefused(t, w, restarted, w.genesis, replayEntryRecovery, "R11b incomplete after restart")
	logicalMDBXAssert(t, slices.Equal(restarted.limits, []uint64{71_815_566}) && len(restarted.versions) == 0, "R11b view %+v", restarted)
	image := w.image()
	replayDecided(t, NewReplayEntryOwnerV1(nil, w.genesis).EnterReplayTargetMDBX(w.store, w.owner), replayEntryRecovery, "", "H21 nil view")
	replaySameImage(t, image, w.image(), "H21")
	// R40d: one producer and one owner over two stores; the second inventory carries the lower Version, which is
	// passed through unchanged and never compared with the first.
	w2 := pendingWorld(t, 3)
	logicalMDBXAssert(t, w2.genesis.GenesisHash == w.genesis.GenesisHash, "R40d premise: one chain instance")
	shared := &replayView{inv: good}
	shared.afterInvent = func() { shared.inv.Version = []uint64{7, 1}[min(shared.calls, 2)-1] }
	owner := NewReplayEntryOwnerV1(shared, w.genesis)
	before := w.snapshot()
	replayCommitted(t, w, owner.EnterReplayTargetMDBX(w.store, w.owner), before, mdbx.StorageProfilePrunedV1, hashes[0], 4, 5)
	before = w2.snapshot()
	replayCommitted(t, w2, owner.EnterReplayTargetMDBX(w2.store, w2.owner), before, mdbx.StorageProfilePrunedV1, hashes[0], 4, 5)
	logicalMDBXAssert(t, slices.Equal(shared.versions, []uint64{7, 1}) && shared.calls == 2 && shared.releases == 2, "R40d versions %v calls %d releases %d", shared.versions, shared.calls, shared.releases)
}

// R61: a selected side at NONE/STABLE/PRE_GENESIS is not eligible.
func TestReplayEntrySelectedSidePreGenesis(t *testing.T) {
	w := newReplayWorld(t, -1)
	w.setAuthority(func(a *mdbx.StorageAuthorityV1) {
		a.NextGenerationID = 3
		a.SelectedSide = &mdbx.SelectedSideV1{GenerationID: 2, F: 1, TipHeight: 2, CumulativeChainwork: sideWorldWork(3), RowCount: 1, LogicalBytes: 1}
	})
	image := w.image()
	view := &replayView{inv: replayComplete(nil, nil)}
	replayDecided(t, w.enter(view, replayIdentityOnly()), "", replayEntryNotEligible, "R61")
	logicalMDBXAssert(t, view.calls == 0, "R61 inventory: %d", view.calls)
	replaySameImage(t, image, w.image(), "R61")
}

// seedRow is one canonical height of generation 1: header row, index entry and paired owner row.
func (w *replayWorld) seedRow(h uint64, header [116]byte, parent [32]byte, work [40]byte) []mdbx.Mutation {
	hash, _ := BlockHash(header[:])
	return []mdbx.Mutation{
		{DBI: logicalMDBXDBIs[3], Key: bytes.Clone(hash[:]), AfterKind: mdbx.AfterLiteral, Literal: bytes.Clone(header[:])},
		{DBI: logicalMDBXDBIs[2], Key: logicalMDBXMust(mdbx.HeightKey(1, h)), AfterKind: mdbx.AfterLiteral, Literal: mdbx.ChainValue(hash, parent, work)},
		{DBI: logicalMDBXDBIs[7], Key: logicalMDBXMust(mdbx.CanonicalOwnerKey(1, hash)), AfterKind: mdbx.AfterLiteral, Literal: mdbx.CanonicalOwnerValue(h)},
	}
}

// defectWorld seeds canonical 1..len(headers) over the published genesis with edit applied to each height's rows.
func defectWorld(t *testing.T, headers [][116]byte, edit func(h uint64, rows []mdbx.Mutation) []mdbx.Mutation) *replayWorld {
	w := newReplayWorld(t, 0)
	parent := w.genesis.GenesisHash
	var rows []mdbx.Mutation
	for i, header := range headers {
		h := uint64(i + 1)
		hash, _ := BlockHash(header[:])
		rows = append(rows, edit(h, w.seedRow(h, header, parent, sideWorldWork(h+1)))...)
		w.hashes, w.headers = append(w.hashes, hash), append(w.headers, header)
		parent = hash
	}
	w.apply(rows...)
	w.pending(mdbx.StorageProfilePrunedV1, 3)
	return w
}

func replayKeep(_ uint64, rows []mdbx.Mutation) []mdbx.Mutation { return rows }

// replayValueAt is a defectWorld edit of the index value at height at: work, and parent when non-nil.
func replayValueAt(at uint64, parent *[32]byte, work [40]byte) func(uint64, []mdbx.Mutation) []mdbx.Mutation {
	return func(h uint64, rows []mdbx.Mutation) []mdbx.Mutation {
		if h == at {
			p := [32]byte(rows[1].Literal[32:64])
			rows[1].Literal = mdbx.ChainValue([32]byte(rows[1].Literal[:32]), *cmp.Or(parent, &p), work)
		}
		return rows
	}
}

// replayIntegrity asserts a D-class canonical defect: TERMINAL_STORE_INTEGRITY(canonical) through a consensus failure
// object, zero mutation and the Store still open.
func replayIntegrity(t *testing.T, w *replayWorld, label string) *replayView {
	t.Helper()
	return replayIntegrityWith(t, w, w.genesis, label)
}

func replayIntegrityWith(t *testing.T, w *replayWorld, genesis PublishedGenesisContextV1, label string) *replayView {
	t.Helper()
	return replayIntegrityOn(t, w, genesis, &replayView{inv: replayComplete(nil, nil)}, label)
}

// replayIntegrityOn is replayIntegrityWith over a given view.
func replayIntegrityOn(t *testing.T, w *replayWorld, genesis PublishedGenesisContextV1, view *replayView, label string) *replayView {
	t.Helper()
	image := w.image()
	out := w.enter(view, genesis)
	var failure *selectedSideFailure
	ok := fmt.Sprintf("%T", out.Err) == "*consensus.selectedSideFailure" && errors.As(out.Err, &failure) && failure.result == selectedSideIntegrity
	logicalMDBXAssert(t, ok && out.Result == selectedSideIntegrity && out.Decision == "" && out.CanonicalTruth == "OLD" && out.Truth == mdbx.CommitTruthOld && out.Stage == mdbx.UpdateStagePrewrite, "%s: %+v", label, out)
	replaySameImage(t, image, w.image(), label+" (Store open)")
	return view
}

// Each row's seeded defect: R50 D1, R54 D6 (stored parent and header prev), R56 D8, R57 D9; the rows share one tuple,
// so a row names the seeded defect, not the check that refuses it.
func TestReplayEntryCanonicalDefects(t *testing.T) {
	w0 := newReplayWorld(t, 0)
	headers, _ := replayChain(t, w0.genesis.GenesisHash, w0.lastTime, 10)
	// R50: a received tip on canonical height 10 outranks it, so stitching alone has a result (the gap-free control
	// commits it); the D1 gap still refuses with no stitching or selection result.
	gap := defectWorld(t, headers, func(h uint64, rows []mdbx.Mutation) []mdbx.Mutation {
		if h == 5 {
			return rows[:1]
		}
		return rows
	})
	fh, fhash := gap.fork(10, 1, 1)
	r50 := replayIntegrityOn(t, gap, gap.genesis, &replayView{inv: replayComplete([][32]byte{fhash[0]}, fh)}, "R50 D1 gap")
	logicalMDBXAssert(t, gap.authority().Replay == nil, "R50: no target")
	control := defectWorld(t, headers, replayKeep)
	ch, chash := control.fork(10, 1, 1)
	logicalMDBXAssert(t, chash[0] == fhash[0] && control.enter(&replayView{inv: replayComplete([][32]byte{chash[0]}, ch)}, control.genesis).Truth == mdbx.CommitTruthNew &&
		control.authority().Replay != nil, "R50 control: stitching alone commits the tip (calls %d)", r50.calls)
	splice := replayValueAt(5, &[32]byte{0x77}, sideWorldWork(6))
	replayIntegrity(t, defectWorld(t, headers[:5], splice), "R54 D6 stored parent")
	zero := headers[1]
	copy(zero[76:108], make([]byte, 32))
	replayIntegrity(t, defectWorld(t, [][116]byte{headers[0], zero}, replayKeep), "R56 D8 zero target")
	replayIntegrity(t, defectWorld(t, headers, replayValueAt(10, nil, sideWorldWork(12))), "R57 D9 work off by one")
	moved := slices.Clone(headers[:5])
	moved[4], _ = replayHeader(t, [32]byte{0x77}, POW_LIMIT, binary.LittleEndian.Uint64(headers[4][68:76]))
	replayIntegrity(t, defectWorld(t, moved, replayKeep), "R54 D6 header prev")
	replayIntegrity(t, defectWorld(t, moved, splice), "R54 D6 consistent splice")
	g0 := func(parent [32]byte, work [40]byte) func(*replayWorld) []mdbx.Mutation {
		return func(w *replayWorld) []mdbx.Mutation { // the genesis index row rewritten with its owner row
			r := w.seedRow(0, w.headers[0], parent, work)[1:]
			r[0].BeforePresent, r[1].BeforePresent = true, true
			return r
		}
	}
	replayGenesisEdit(t, "R54 D6 genesis stored parent", g0([32]byte{1}, sideWorldWork(1)))
	replayGenesisEdit(t, "R57 D9 genesis work", g0([32]byte{}, sideWorldWork(2)))
	// The R54 and R57 height-0 control (the same rewrite with the published values commits) and A32 at H = 0.
	c := replayGenesisEdit(t, "", g0([32]byte{}, sideWorldWork(1))).Consulted
	logicalMDBXAssert(t, len(c) == 2 && bytes.Equal(c[0].Key, logicalMDBXMust(mdbx.HeightKey(1, 0))) && bytes.Equal(c[1].Key, logicalMDBXMust(mdbx.HeightKey(1, 1))), "A32 H=0: %v", c)
	replayGenesisEdit(t, "R50 D1 genesis absent", func(w *replayWorld) []mdbx.Mutation {
		first, _ := replayHeader(t, [32]byte{}, POW_LIMIT, w.lastTime+1)
		return append(w.seedRow(1, first, [32]byte{}, sideWorldWork(1)), mdbx.Mutation{DBI: logicalMDBXDBIs[2], Key: logicalMDBXMust(mdbx.HeightKey(1, 0)), BeforePresent: true, AfterKind: mdbx.AfterAbsent},
			mdbx.Mutation{DBI: logicalMDBXDBIs[7], Key: logicalMDBXMust(mdbx.CanonicalOwnerKey(1, w.genesis.GenesisHash)), BeforePresent: true, AfterKind: mdbx.AfterAbsent})
	})
}

// replayGenesisEdit applies rows over the published genesis alone under pending NONE/RECOVERY_REQUIRED with a received
// tip on it: a labeled call refuses as integrity, an unlabeled one commits NEW and returns its Batch.
func replayGenesisEdit(t *testing.T, label string, rows func(*replayWorld) []mdbx.Mutation) (batch mdbx.Batch) {
	w := newReplayWorld(t, 0)
	w.apply(rows(w)...)
	w.pending(mdbx.StorageProfilePrunedV1, 3)
	fh, fhash := w.fork(0, 1, 1)
	if view := (&replayView{inv: replayComplete([][32]byte{fhash[0]}, fh)}); label != "" {
		replayIntegrityOn(t, w, w.genesis, view, label)
	} else {
		batch, _ = replayCaptured(t, w, view, w.genesis)
	}
	return batch
}

// H11 D3 (the seeded defect): a stored canonical chainwork of zero or 2^288+1 is a canonical defect, never ineligibility.
func TestReplayEntryChainworkDomain(t *testing.T) {
	w0 := newReplayWorld(t, 0)
	headers, _ := replayChain(t, w0.genesis.GenesisHash, w0.lastTime, 3)
	replayIntegrity(t, defectWorld(t, headers[:3], replayValueAt(2, nil, [40]byte{})), "H11 D3 zero work")
	over := sideWorldWork(1)
	over[3] = 1
	replayIntegrity(t, defectWorld(t, headers[:3], replayValueAt(2, nil, over)), "H11 D3 2^288+1 work")
}

// R55 D7: canonical 0..3 of another genesis, consistent among themselves, under the published-genesis context.
func TestReplayEntryForeignCanonicalGenesis(t *testing.T) {
	w := newReplayWorld(t, 0)
	other, otherHash := replayHeader(t, [32]byte{}, POW_LIMIT, w.lastTime+1)
	headers, hashes := replayChain(t, otherHash, w.lastTime+1, 3)
	rows := append(w.seedRow(0, other, [32]byte{}, sideWorldWork(1)),
		mdbx.Mutation{DBI: logicalMDBXDBIs[7], Key: logicalMDBXMust(mdbx.CanonicalOwnerKey(1, w.genesis.GenesisHash)), BeforePresent: true, AfterKind: mdbx.AfterAbsent})
	rows[1].BeforePresent = true
	parent := otherHash
	for i, header := range headers {
		rows = append(rows, w.seedRow(uint64(i+1), header, parent, sideWorldWork(uint64(i)+2))...)
		parent = hashes[i]
	}
	w.apply(rows...)
	w.pending(mdbx.StorageProfilePrunedV1, 3)
	w.headers, w.hashes = append([][116]byte{w.headers[0], other}, headers...), append([][32]byte{w.hashes[0], otherHash}, hashes...)
	replayIntegrity(t, w, "R55 D7")
}

// A36 D10: canonical height 6 fails CAN22 while passing D1-D9; the canonical tip is ineligible, the walk continues,
// and a received tip at 7 forking at 4 is bound with computed(4) plus its own work.
func TestReplayEntryD10(t *testing.T) {
	headers := replayD10Headers(t)
	w := defectWorld(t, headers, replayKeep)
	before := w.snapshot()
	forked, tips := w.fork(4, 3, 7)
	out := w.enter(&replayView{inv: replayComplete([][32]byte{tips[2]}, forked)}, w.genesis)
	replayCommitted(t, w, out, before, mdbx.StorageProfilePrunedV1, tips[2], 7, 8)
	w = defectWorld(t, headers, replayKeep)
	forked, tips = w.fork(4, 3, 7)
	g := w.authority().ActiveGenerationID
	batch, _ := replayCaptured(t, w, &replayView{inv: replayComplete([][32]byte{tips[2]}, forked)}, w.genesis)
	want := [][]byte{logicalMDBXMust(mdbx.HeightKey(g, 0)), logicalMDBXMust(mdbx.HeightKey(g, 1)), logicalMDBXMust(mdbx.HeightKey(g, 10)), logicalMDBXMust(mdbx.HeightKey(g, 11))}
	got := make([][]byte, len(batch.Consulted))
	for i, row := range batch.Consulted {
		logicalMDBXAssert(t, row.DBI == logicalMDBXDBIs[2], "A36 consulted DBI %v", row.DBI)
		got[i] = row.Key
	}
	logicalMDBXAssert(t, slices.EqualFunc(got, want, bytes.Equal), "A36 consulted: %x", got)
	// The walk continues D1-D9 past the D10 height: a stored-work mismatch at height 8 is an integrity result.
	replayIntegrity(t, defectWorld(t, headers, replayValueAt(8, nil, sideWorldWork(10))), "A36 D9 at 8 past the D10 height")
}

// replayD10Headers is canonical 1..10 whose height 6 repeats an old timestamp (not above the median, CAN22 fails while
// D1-D9 pass), with 7..10 rebuilt on it.
func replayD10Headers(t *testing.T) [][116]byte {
	w0 := newReplayWorld(t, 0)
	headers, _ := replayChain(t, w0.genesis.GenesisHash, w0.lastTime, 10)
	ts := binary.LittleEndian.Uint64(headers[0][68:76])
	headers[5], _ = replayHeader(t, mustHash(headers[4]), POW_LIMIT, ts)
	rest, _ := replayChain(t, mustHash(headers[5]), binary.LittleEndian.Uint64(headers[4][68:76]), 4)
	copy(headers[6:], rest)
	return headers
}

// replayExclude seeds the exclusion slot with canonical height h of w.
func replayExclude(w *replayWorld, h uint64) {
	w.setAuthority(func(a *mdbx.StorageAuthorityV1) {
		a.ExcludedInvalidBranch = &mdbx.InvalidBranchV1{FirstInvalidHeight: h, FirstInvalidBlockHash: w.hashes[h], ExactConsensusError: []byte("BLOCK_ERR_POW_INVALID")}
	})
}

// replayPrefixCommits enters w over view and asserts the commit of canonical height h (work h+1 under POW_LIMIT).
func replayPrefixCommits(t *testing.T, w *replayWorld, view *replayView, h uint64) {
	t.Helper()
	before := w.snapshot()
	replayCommitted(t, w, w.enter(view, w.genesis), before, mdbx.StorageProfilePrunedV1, w.hashes[h], h, h+1)
}

// RUB-1571 E1, E2, E3, K2, X1 (MP 2544-2561): the D10 world's published tip 10 is ineligible from height 6, so the
// published prefix tip is canonical height 5 with work 6, a candidate whether or not it is inventoried.
func TestReplayEntryPrefixTipD10(t *testing.T) {
	headers := replayD10Headers(t)
	t.Run("E1 no received candidate", func(t *testing.T) {
		replayPrefixCommits(t, defectWorld(t, headers, replayKeep), &replayView{inv: replayComplete(nil, nil)}, 5)
	})
	t.Run("E1 every received candidate worse", func(t *testing.T) {
		w := defectWorld(t, headers, replayKeep)
		forked, tips := w.fork(2, 1, 7) // height 3, work 4 < 6
		replayPrefixCommits(t, w, &replayView{inv: replayComplete([][32]byte{tips[0]}, forked)}, 5)
	})
	// E2 (a received candidate with more chainwork is committed) is TestReplayEntryD10's first row, unchanged.
	t.Run("E3 equal chainwork", func(t *testing.T) {
		seen := map[bool]bool{}
		for skew := uint64(1); skew <= 200 && (!seen[true] || !seen[false]); skew++ {
			w := defectWorld(t, headers, replayKeep)
			forked, tips := w.fork(4, 1, skew) // height 5, work 6 == the prefix tip's
			want := w.hashes[5]
			received := bytes.Compare(tips[0][:], want[:]) < 0
			if received {
				want = tips[0]
			}
			seen[received] = true
			before := w.snapshot()
			out := w.enter(&replayView{inv: replayComplete([][32]byte{tips[0]}, forked)}, w.genesis)
			replayCommitted(t, w, out, before, mdbx.StorageProfilePrunedV1, want, 5, 6)
		}
		logicalMDBXAssert(t, seen[true] && seen[false], "E3: the smaller hash lay on one side only: %v", seen)
	})
	t.Run("K2 heavier ineligible branch", func(t *testing.T) {
		w := defectWorld(t, headers, replayKeep)
		quarter := [32]byte(new(big.Int).Rsh(new(big.Int).SetBytes(POW_LIMIT[:]), 2).FillBytes(make([]byte, 32)))
		bad, badHash := replayHeader(t, w.hashes[4], quarter, binary.LittleEndian.Uint64(w.headers[4][68:76])+2*TARGET_BLOCK_INTERVAL)
		child, childHash := replayHeader(t, badHash, quarter, binary.LittleEndian.Uint64(bad[68:76])+2*TARGET_BLOCK_INTERVAL)
		// Height 6 carries 4+4 work over computed(4) = 5: 13 > 6, but CAN15 expects POW_LIMIT at height 5.
		replayPrefixCommits(t, w, &replayView{inv: replayComplete([][32]byte{childHash}, [][116]byte{bad, child})}, 5)
	})
	t.Run("X1 exclusion above the D10 height", func(t *testing.T) {
		w := defectWorld(t, headers, replayKeep)
		replayExclude(w, 8)
		replayPrefixCommits(t, w, &replayView{inv: replayComplete(nil, nil)}, 5)
	})
	t.Run("X1 exclusion below the D10 height", func(t *testing.T) {
		w := defectWorld(t, headers, replayKeep)
		replayExclude(w, 3)
		replayPrefixCommits(t, w, &replayView{inv: replayComplete(nil, nil)}, 2)
	})
}

// RUB-1571 E5, E6, K1, X3 (MP 2544-2561): an excluded canonical hash ends the published prefix below it.
func TestReplayEntryPrefixTipExcluded(t *testing.T) {
	t.Run("E5 no other candidate", func(t *testing.T) {
		w := pendingWorld(t, 5)
		replayExclude(w, 3)
		replayPrefixCommits(t, w, &replayView{inv: replayComplete(nil, nil)}, 2)
	})
	for _, c := range []struct {
		label string
		tips  int
	}{{"E6 inventoried prefix tip", 1}, {"K1 prefix tip listed twice without a header", 2}} {
		t.Run(c.label, func(t *testing.T) {
			w := pendingWorld(t, 5)
			replayExclude(w, 3)
			tips := slices.Repeat([][32]byte{w.hashes[2]}, c.tips)
			replayPrefixCommits(t, w, &replayView{inv: replayComplete(tips, nil)}, 2)
		})
	}
	t.Run("X3 prefix ends at height 0", func(t *testing.T) {
		w := pendingWorld(t, 5)
		replayExclude(w, 1)
		// The fork from 5 is ineligible through its canonical ancestry (badFrom), not through its own hashes.
		forked, tips := w.fork(5, 2, 1)
		replayRefused(t, w, &replayView{inv: replayComplete([][32]byte{tips[1]}, forked)}, w.genesis, replayEntryRecovery, "X3")
	})
}

func mustHash(header [116]byte) [32]byte {
	hash, _ := BlockHash(header[:])
	return hash
}

// A35, A35b, A37, R4, R48, R49: source (d) at a pending PRE_GENESIS image anchors at the Fork F identity.
func TestReplayEntryForkFAnchor(t *testing.T) {
	base := newReplayWorld(t, -1)
	headers, hashes := replayChain(t, base.genesis.GenesisHash, base.lastTime, 10)
	withH0 := append([][116]byte{base.headers[0]}, headers...)
	for _, c := range []struct {
		label   string
		genesis PublishedGenesisContextV1
		headers [][116]byte
	}{{"A35 complete bytes", replayGenesis(), headers}, {"A35b identity-only with h0", replayIdentityOnly(), withH0}, {"A37 complete bytes with h0", replayGenesis(), withH0}} {
		t.Run(c.label, func(t *testing.T) {
			w := newReplayWorld(t, -1)
			w.pending(mdbx.StorageProfilePrunedV1, 3)
			before := w.snapshot()
			out := w.enter(&replayView{inv: replayComplete([][32]byte{hashes[9]}, c.headers)}, c.genesis)
			replayCommitted(t, w, out, before, mdbx.StorageProfilePrunedV1, hashes[9], 10, 11)
			own := newReplayWorld(t, -1)
			own.pending(mdbx.StorageProfilePrunedV1, 3)
			replayCapturedCommit(t, own, replayComplete([][32]byte{hashes[9]}, slices.Clone(c.headers)), c.genesis, hashes[9], 10, 11, true, 0, 1)
		})
	}
	t.Run("H22 anchor tip", func(t *testing.T) {
		// A listed GenesisHash tip is the established Fork F anchor identity (MP 2529-2535), never E1: the inventory
		// binds the height-9 tip exactly like the control that also supplies the genesis header.
		tips := [][32]byte{base.genesis.GenesisHash, hashes[8]}
		for _, supplied := range [][][116]byte{headers[:9], withH0[:10]} {
			w := newReplayWorld(t, -1)
			w.pending(mdbx.StorageProfilePrunedV1, 3)
			before := w.snapshot()
			out := w.enter(&replayView{inv: replayComplete(slices.Clone(tips), slices.Clone(supplied))}, replayGenesis())
			replayCommitted(t, w, out, before, mdbx.StorageProfilePrunedV1, hashes[8], 9, 10)
		}
	})
	t.Run("R48", func(t *testing.T) {
		w := newReplayWorld(t, -1)
		w.pending(mdbx.StorageProfilePrunedV1, 3)
		replayRefused(t, w, &replayView{inv: replayComplete([][32]byte{hashes[9]}, headers)}, replayIdentityOnly(), replayEntryRecovery, "R48 no anchor")
	})
	t.Run("R4 excluded anchor", func(t *testing.T) {
		w := newReplayWorld(t, -1)
		w.pending(mdbx.StorageProfilePrunedV1, 3)
		w.setAuthority(func(a *mdbx.StorageAuthorityV1) {
			a.ExcludedInvalidBranch = &mdbx.InvalidBranchV1{FirstInvalidHeight: 0, FirstInvalidBlockHash: w.genesis.GenesisHash, ExactConsensusError: []byte("BLOCK_ERR_POW_INVALID")}
		})
		replayRefused(t, w, &replayView{inv: replayComplete([][32]byte{hashes[9]}, withH0)}, w.genesis, replayEntryRecovery, "R4 excluded anchor")
	})
	t.Run("R49", func(t *testing.T) {
		w := newReplayWorld(t, -1)
		w.pending(mdbx.StorageProfilePrunedV1, 3)
		replayRefused(t, w, &replayView{inv: replayComplete(nil, nil)}, w.genesis, replayEntryRecovery, "R49 no positive tip")
	})
}

// A38, H28, H29, H25: supplied copies of canonical headers are E3 identities; duplicates and order do not matter.
func TestReplayEntryIdentities(t *testing.T) {
	run := func(tips [][32]byte, headers [][116]byte) (ReplayEntryOutcomeV1, mdbx.StorageAuthorityV1, *replayWorld) {
		w := pendingWorld(t, 10)
		before := w.snapshot()
		// The view hands Tips and Headers over (the consumer sorts and compacts Tips in place), so each run gets its own copy.
		return w.enter(&replayView{inv: replayComplete(slices.Clone(tips), slices.Clone(headers))}, w.genesis), before, w
	}
	probe := pendingWorld(t, 10)
	ext, extTips := probe.fork(10, 2, 1)
	out, before, w := run([][32]byte{extTips[1]}, ext)
	replayCommitted(t, w, out, before, mdbx.StorageProfilePrunedV1, extTips[1], 12, 13)
	copies := append([][116]byte{probe.headers[0], probe.headers[5]}, ext...)
	out, before, w = run([][32]byte{extTips[1]}, copies)
	replayCommitted(t, w, out, before, mdbx.StorageProfilePrunedV1, extTips[1], 12, 13)
	// A38 genesis-copy branch: Tips {T@12, B} with the copies plus a received branch from height 1 to B at 13 (chainwork
	// 14 above T's 13): B is bound, because the genesis copy is the canonical identity, never a foreign zero-parent root.
	branch, branchTips := probe.fork(0, 13, 1)
	out, before, w = run([][32]byte{extTips[1], branchTips[12]}, append(slices.Clone(copies), branch...))
	replayCommitted(t, w, out, before, mdbx.StorageProfilePrunedV1, branchTips[12], 13, 14)
	for _, headers := range [][][116]byte{ext, copies} {
		replayCapturedCommit(t, pendingWorld(t, 10), replayComplete([][32]byte{extTips[1]}, slices.Clone(headers)), probe.genesis, extTips[1], 12, 13, false, 0, 1, 10, 11)
	}
	t.Run("H28", func(t *testing.T) {
		// A received copy of canonical 8 is one identity: the tip at 9 on it is bound with computed(8) plus its own work.
		w := pendingWorld(t, 8)
		before := w.snapshot()
		nine, nineTips := w.fork(8, 1, 3)
		out := w.enter(&replayView{inv: replayComplete([][32]byte{nineTips[0]}, append([][116]byte{w.headers[8]}, nine...))}, w.genesis)
		replayCommitted(t, w, out, before, mdbx.StorageProfilePrunedV1, nineTips[0], 9, 10)
	})
	// H29 and H25: duplicated tips and headers and a received fork, in two orders.
	a, aTips := probe.fork(10, 3, 5)
	b, bTips := probe.fork(10, 3, 6)
	want := aTips[2]
	if bytes.Compare(bTips[2][:], want[:]) < 0 {
		want = bTips[2]
	}
	forward := append(append(append([][116]byte{}, a...), b...), a[1])
	reverse := slices.Clone(forward)
	slices.Reverse(reverse)
	// The canonical tip, not supplied as a header, is listed twice: without dedupe E1 would count it as missing twice.
	tipsForward := [][32]byte{bTips[2], probe.hashes[10], aTips[2], bTips[2], probe.hashes[10]}
	tipsReverse := slices.Clone(tipsForward)
	slices.Reverse(tipsReverse)
	for _, order := range [][][116]byte{forward, reverse} {
		for _, tips := range [][][32]byte{tipsForward, tipsReverse} {
			out, before, w = run(tips, order)
			replayCommitted(t, w, out, before, mdbx.StorageProfilePrunedV1, want, 13, 14)
		}
	}
	// H29: the other fork tip is a candidate too: with the smaller-hash tip excluded it is bound.
	other := aTips[2]
	if other == want {
		other = bTips[2]
	}
	w = pendingWorld(t, 10)
	w.setAuthority(func(a *mdbx.StorageAuthorityV1) {
		a.ExcludedInvalidBranch = &mdbx.InvalidBranchV1{FirstInvalidHeight: 13, FirstInvalidBlockHash: want, ExactConsensusError: []byte("BLOCK_ERR_POW_INVALID")}
	})
	before = w.snapshot()
	out = w.enter(&replayView{inv: replayComplete(slices.Clone(tipsForward), forward)}, w.genesis)
	replayCommitted(t, w, out, before, mdbx.StorageProfilePrunedV1, other, 13, 14)
}

// H5: a received zero-parent header that is not the genesis is an ineligible path, not missing evidence.
func TestReplayEntryForeignGenesis(t *testing.T) {
	w := pendingWorld(t, 4)
	before := w.snapshot()
	// The foreign chain (tip height 9, work 10) outweighs the extension (work 6): only its ineligibility makes it lose.
	foreign, foreignTips := replayChain(t, [32]byte{}, w.lastTime, 10) // timestamps valid on the canonical tip
	// Every path through the foreign root: the root itself as a tip, the chain tip, a heavier branch off foreign height
	// 4 (tip height 11, work 12) and a branch off the root (tip height 7, work 8); the chain tip and both branches
	// outweigh the extension (the root listed as a tip, height 0, is never eligible).
	// The +1 second skew makes each branch header differ from the foreign chain header at the same height.
	branch, branchTips := replayChain(t, foreignTips[4], w.lastTime+2*TARGET_BLOCK_INTERVAL*5+1, 7)
	rooted, rootedTips := replayChain(t, foreignTips[0], w.lastTime+2*TARGET_BLOCK_INTERVAL+1, 7)
	logicalMDBXAssert(t, branchTips[0] != foreignTips[5] && rootedTips[0] != foreignTips[1], "H5 branches must be distinct paths")
	ext, extTips := w.fork(4, 1, 1)
	tips := [][32]byte{foreignTips[0], foreignTips[9], branchTips[6], rootedTips[6], extTips[0]}
	view := &replayView{inv: replayComplete(tips, slices.Concat(foreign, branch, rooted, ext))}
	replayCommitted(t, w, w.enter(view, w.genesis), before, mdbx.StorageProfilePrunedV1, extTips[0], 5, 6)
	// At an empty active index the Fork F anchor exists; the foreign root (tip 9, work 10) is still not the anchor.
	w = newReplayWorld(t, -1)
	w.pending(mdbx.StorageProfilePrunedV1, 3)
	anchored, anchoredTips := replayChain(t, w.genesis.GenesisHash, w.lastTime, 3)
	foreign, foreignTips = replayChain(t, [32]byte{}, w.lastTime, 10)
	before, view = w.snapshot(), &replayView{inv: replayComplete([][32]byte{foreignTips[9], anchoredTips[2]}, slices.Concat(foreign, anchored))}
	replayCommitted(t, w, w.enter(view, w.genesis), before, mdbx.StorageProfilePrunedV1, anchoredTips[2], 3, 4)
}

// H3, H4, H4b: a zero target (it differs from the CAN15 expected target and WorkFromTarget refuses it; either check alone
// refuses it, the test shows the joint refusal; PowCheck runs on the expected target) and a timestamp equal to the newest-11 median (refused by CAN22) make the
// received path ineligible, and so does a timestamp above that median plus MAX_FUTURE_DRIFT (CAN22 step 4). The H3 header passes CAN22; the control, the same header with the expected target, is bound.
func TestReplayEntryReceivedPredicates(t *testing.T) {
	for _, zero := range []bool{true, false} {
		w := pendingWorld(t, 20)
		valid, validHash := replayHeader(t, w.hashes[20], POW_LIMIT, w.lastTime+2*TARGET_BLOCK_INTERVAL)
		zeroTarget := valid
		copy(zeroTarget[76:108], make([]byte, 32))
		median := binary.LittleEndian.Uint64(w.headers[15][68:76]) // newest 11 parents are 10..20; lower median is 15
		stale, staleHash := replayHeader(t, w.hashes[20], POW_LIMIT, median)
		tips, headers := [][32]byte{mustHash(zeroTarget), staleHash}, [][116]byte{zeroTarget, stale}
		tip, height, work := w.hashes[20], uint64(20), uint64(21)
		if !zero {
			tips[0], headers[0], tip, height, work = validHash, valid, validHash, 21, 22
		}
		before := w.snapshot()
		view := &replayView{inv: replayComplete(tips, headers)}
		replayCommitted(t, w, w.enter(view, w.genesis), before, mdbx.StorageProfilePrunedV1, tip, height, work)
	}
	for _, drift := range []uint64{MAX_FUTURE_DRIFT + 1, MAX_FUTURE_DRIFT} { // H4b: refused above median + drift, its control at it
		w := pendingWorld(t, 20)
		future, futureHash := replayHeader(t, w.hashes[20], POW_LIMIT, binary.LittleEndian.Uint64(w.headers[15][68:76])+drift)
		tip, height, before := w.hashes[20], uint64(20), w.snapshot()
		if drift == MAX_FUTURE_DRIFT {
			tip, height = futureHash, 21
		}
		replayCommitted(t, w, w.enter(&replayView{inv: replayComplete([][32]byte{futureHash}, [][116]byte{future})}, w.genesis), before, mdbx.StorageProfilePrunedV1, tip, height, height+1)
	}
}

// A30 capacity_boundary: the per-header derived charge D_h is the size of one replayNode and one replayKid.
func TestReplayEntryDerivedBytes(t *testing.T) {
	size := uint64(unsafe.Sizeof(replayNode{}) + unsafe.Sizeof(replayKid{}))
	logicalMDBXAssert(t, size == replayEntryDerivedBytes && replayEntryDerivedBytes == 128, "D_h: %d, charged %d", size, replayEntryDerivedBytes)
}

// replayNoLatch asserts no latch: the next entry with the full-lane grant admitted runs its callback and reaches
// InventoryV1.
func replayNoLatch(t *testing.T, w *replayWorld, label string) {
	t.Helper()
	view := &replayView{inv: replayComplete(nil, nil)}
	w.enter(view, w.genesis)
	logicalMDBXAssert(t, view.calls == 1, "%s: latched, inventory calls %d", label, view.calls)
}

// held runs the entry while the owner already holds hold bytes: any hold above zero refuses the full-lane grant (hold 0
// admits it); a hold of the whole lane also refuses the nested 512-byte control charge.
func (w *replayWorld) held(view HeaderCandidateViewV1, genesis PublishedGenesisContextV1, hold uint64) ReplayEntryOutcomeV1 {
	var out ReplayEntryOutcomeV1
	err := w.owner.WithReservation(hold, func() error { out = w.enter(view, genesis); return nil })
	logicalMDBXAssert(w.t, err == nil, "hold: %v", err)
	return out
}

// R6, R8, R42, R43, R44, R47: every step-1 gate wins over storage_capacity (R45 is TestReplayEntryFixtureIllegalReplay).
func TestReplayEntryControlPath(t *testing.T) {
	w := newReplayWorld(t, 3)
	w.pending(mdbx.StorageProfilePrunedV1, 1<<64-1)
	view := &replayView{inv: replayComplete(nil, nil)}
	replayHeldSame(t, w, view, 1, selectedSideCapacity, "", "R6 exhausted, grant refused")
	w = pendingWorld(t, 3)
	image := w.image()
	replayDecided(t, w.held(view, w.genesis, 1), selectedSideCapacity, "", "R8 grant refused")
	replaySameImage(t, image, w.image(), "R8")
	logicalMDBXAssert(t, view.calls == 0, "R6/R8 inventory: %d", view.calls)
	replayNoLatch(t, w, "R8 same handle")
	headers, hashes := w.fork(3, 1, 1)
	w.enter(&replayView{inv: replayComplete([][32]byte{hashes[0]}, headers)}, w.genesis)
	resumed := replayHeldSame(t, w, view, 1, "", replayEntryResume, "R42 resume")
	logicalMDBXAssert(t, resumed.Replay != nil && *resumed.Replay == *w.authority().Replay, "R42 replay")
	w = newReplayWorld(t, 3)
	w.setAuthority(func(a *mdbx.StorageAuthorityV1) {
		a.NextGenerationID, a.Phase, a.Cleanup = 3, mdbx.StoragePhasePruneGCV1, &mdbx.CleanupV1{Spans: []mdbx.CleanupSpanV1{{Kind: mdbx.CleanupSpanGenerationV1, GenerationID: 2}}}
		pruned := mdbx.StorageProfilePrunedV1 // RECOVERY_REQUIRED under PRUNE_GC carries a pending profile.
		a.Lifecycle, a.PendingTargetProfile = mdbx.StorageLifecycleRecoveryRequiredV1, &pruned
	})
	logicalMDBXAssert(t, w.authority().Lifecycle == mdbx.StorageLifecycleRecoveryRequiredV1 && w.authority().Phase == mdbx.StoragePhasePruneGCV1, "R12/R43 premise")
	image = w.image()
	replayDecided(t, w.held(view, w.genesis, 1), "", replayEntryNotEligible, "R43 PRUNE_GC")
	replaySameImage(t, image, w.image(), "R43")
	replayDecided(t, w.enter(view, w.genesis), "", replayEntryNotEligible, "R12 PRUNE_GC granted")
	replaySameImage(t, image, w.image(), "R12")
	w = newReplayWorld(t, -1)
	replayHeldSame(t, w, view, 1, "", replayEntryGenesisFirst, "R44 genesis first")
	replayHeldSame(t, w, view, mdbx.MaxOperationDataBytes, selectedSideCapacity, "", "R47 control charge refused")
	logicalMDBXAssert(t, view.calls == 0, "control inventory: %d", view.calls)
}

// H26 (end to end part): nil Store, nil reservation owner, nil Store with a valid owner and both nil.
func TestReplayEntryNilInputs(t *testing.T) {
	view := &replayView{}
	owner := NewReplayEntryOwnerV1(view, replayGenesis())
	_, _, nilStore := (*mdbx.Store)(nil).Update(func(*mdbx.Reader) (mdbx.Batch, error) { return mdbx.Batch{}, nil })
	nilOwner := (*mdbx.OperationReservationOwner)(nil).WithReservation(mdbx.MaxOperationDataBytes, func() error { return nil })
	logicalMDBXAssert(t, nilStore != nil && nilOwner != nil, "reference errors: %v %v", nilStore, nilOwner)
	raw := func(out ReplayEntryOutcomeV1, want error, label string) {
		t.Helper()
		logicalMDBXAssert(t, replaySameRaw(out.Err, want) && out.Result == "" && out.Decision == "" && out.CanonicalTruth == "" && out.Replay == nil && out.Truth == mdbx.CommitTruthOld && out.Stage == mdbx.UpdateStagePrewrite && view.calls == 0, "%s: %+v", label, out)
	}
	raw(owner.EnterReplayTargetMDBX(nil, nil), nilStore, "both nil")
	w := pendingWorld(t, 2)
	raw(owner.EnterReplayTargetMDBX(nil, w.owner), nilStore, "nil store, valid owner")
	image := w.image()
	raw(owner.EnterReplayTargetMDBX(w.store, nil), nilOwner, "nil owner")
	replaySameImage(t, image, w.image(), "nil owner leaves the Store open")
}

// replaySameRaw is raw-error identity for refusals that allocate a fresh error per call: equal EngineError values, else
// errors.Is both ways.
func replaySameRaw(got, want error) bool {
	var g, w *mdbx.EngineError
	if errors.As(got, &g) && errors.As(want, &w) {
		return fmt.Sprintf("%T", got) == fmt.Sprintf("%T", want) && g.Class == w.Class && g.Operation == w.Operation && g.Code == w.Code &&
			g.Diagnostic == w.Diagnostic && g.Cause == nil && w.Cause == nil && g.ReopenRequired == w.ReopenRequired
	}
	return errors.Is(got, want) && errors.Is(want, got)
}

// replaySameErr is raw-Err identity: the same dynamic type and pointer, so a wrapped Err fails it.
func replaySameErr(got, want error) bool {
	return fmt.Sprintf("%T %p", got, got) == fmt.Sprintf("%T %p", want, want)
}

// H26: the result_map projection over every (stage, class, read site) cell and input shape (H17 is a stage-1 cell).
func TestReplayEntryProjectionCorpus(t *testing.T) {
	classes := []mdbx.EngineClass{mdbx.EngineInvalidInput, mdbx.EngineIntegrity, mdbx.EngineCapacity, mdbx.EngineConcurrency, mdbx.EngineTransaction, mdbx.EngineIO, mdbx.EngineStateMismatch, mdbx.EngineLocalInvariant}
	eio := &mdbx.EngineError{Class: mdbx.EngineIO}
	stage1 := func(class mdbx.EngineClass, step string, planned bool) string {
		switch class {
		case mdbx.EngineIntegrity:
			return "TERMINAL_STORE_INTEGRITY(canonical)"
		case mdbx.EngineCapacity:
			return "LOCAL_RESOURCE_UNAVAILABLE(storage_capacity)"
		case mdbx.EngineConcurrency:
			return replayCorpusResource(step, "storage_concurrency")
		case mdbx.EngineTransaction:
			return replayCorpusResource(step, "storage_transaction")
		case mdbx.EngineIO:
			return replayCorpusResource(step, "storage_io")
		case mdbx.EngineStateMismatch:
			if planned {
				return "STALE_LOCAL_PLAN"
			}
		case mdbx.EngineInvalidInput, mdbx.EngineLocalInvariant:
		}
		return "TERMINAL_LOCAL_INVARIANT(evidence)"
	}
	for _, class := range classes {
		for _, step := range []string{"", replayEntryRecovery, selectedSideCanonical} {
			for _, planned := range []bool{false, true} {
				call := &replayEntryCall{sentinel: errors.New("s"), step: step, planned: planned}
				raw := &mdbx.EngineError{Class: class}
				out := replayEntryProject(ReplayEntryOutcomeV1{Truth: mdbx.CommitTruthOld, Stage: mdbx.UpdateStagePrewrite, Err: raw}, call)
				want := stage1(class, step, planned)
				logicalMDBXAssert(t, out.Result == want && replaySameErr(out.Err, raw) && out.CanonicalTruth == "OLD" && out.Decision == "" && out.Truth == mdbx.CommitTruthOld && out.Stage == mdbx.UpdateStagePrewrite && out.Replay == nil, "stage1/H17 %s/%q/%v: %+v want %s", class, step, planned, out, want)
				// Stage 2 bare and joined after EngineIO; the constructed invalid stage (shape error alone or joined) keeps invariant.
				for err, stage := range map[error]mdbx.UpdateStage{raw: mdbx.UpdateStageWriteStartedDefinitelyPrecommit, errors.Join(eio, raw): mdbx.UpdateStageWriteStartedDefinitelyPrecommit, &mdbx.EngineError{Class: mdbx.EngineLocalInvariant}: mdbx.UpdateStageInvalid, errors.Join(&mdbx.EngineError{Class: mdbx.EngineLocalInvariant}, raw): mdbx.UpdateStageInvalid} {
					want := map[mdbx.UpdateStage]string{mdbx.UpdateStageWriteStartedDefinitelyPrecommit: replayCorpusPrecommit(class), mdbx.UpdateStageInvalid: selectedSideInvariant}[stage]
					out = replayEntryProject(ReplayEntryOutcomeV1{Truth: mdbx.CommitTruthOld, Stage: stage, Err: err}, call)
					logicalMDBXAssert(t, out.Result == want && out.Decision == "" && replaySameErr(out.Err, err) && out.CanonicalTruth == "OLD" && out.Truth == mdbx.CommitTruthOld && out.Stage == stage && out.Replay == nil, "stage %d %s %v: %+v", stage, class, err, out)
				}
			}
		}
		// Third-leaf BS census site (G1): StateMismatch is the not eligible Decision with an empty Result and the raw Err.
		raw := &mdbx.EngineError{Class: class}
		out := replayEntryProject(ReplayEntryOutcomeV1{Truth: mdbx.CommitTruthOld, Stage: mdbx.UpdateStagePrewrite, Err: raw}, &replayEntryCall{sentinel: errors.New("s"), census: true})
		want, decision := stage1(class, "", false), ""
		if class == mdbx.EngineStateMismatch {
			want, decision = "", replayEntryNotEligible
		}
		logicalMDBXAssert(t, out.Result == want && out.Decision == decision && fmt.Sprintf("%p", out.Err) == fmt.Sprintf("%p", raw) && out.CanonicalTruth == "OLD" && out.Truth == mdbx.CommitTruthOld && out.Stage == mdbx.UpdateStagePrewrite && out.Replay == nil, "census %s: %+v", class, out)
		// Never run (busy, begin failure, a cached plain or CommitError Err of any latched truth): merged-walk Update-begin cells.
		for _, truth := range []mdbx.CommitTruth{mdbx.CommitTruthOld, mdbx.CommitTruthNew, mdbx.CommitTruthUnknown} {
			for raw, want := range map[error]string{&mdbx.EngineError{Class: class}: stage1(class, "", false), &mdbx.CommitError{Truth: truth, Cause: &mdbx.EngineError{Class: class}}: stage1(class, "", false), &mdbx.CommitError{Truth: truth, Cause: eio, ReadbackCause: &mdbx.EngineError{Class: mdbx.EngineIntegrity}}: selectedSideIntegrity} {
				out := replayEntryProject(ReplayEntryOutcomeV1{Truth: truth, Stage: mdbx.UpdateStagePrewrite, Err: raw}, &replayEntryCall{sentinel: errors.New("s")})
				logicalMDBXAssert(t, out.Result == want && out.Truth == truth && out.CanonicalTruth == "OLD" && out.Decision == "" && replaySameErr(out.Err, raw) && out.Stage == mdbx.UpdateStagePrewrite && out.Replay == nil, "never run %s/%d %v: %+v", class, truth, raw, out)
			}
		}
	}
	call := &replayEntryCall{sentinel: errors.New("s"), result: replayEntryRecovery}
	out := replayEntryProject(ReplayEntryOutcomeV1{Truth: mdbx.CommitTruthOld, Stage: mdbx.UpdateStagePrewrite, Err: call.sentinel}, call)
	logicalMDBXAssert(t, out.Result == replayEntryRecovery && out.Err == nil && out.Decision == "" && out.CanonicalTruth == "OLD" && out.Truth == mdbx.CommitTruthOld && out.Stage == mdbx.UpdateStagePrewrite && out.Replay == nil, "sentinel: %+v", out)
	// H26 joined causes: the own sentinel is skipped for an empty decided Result and classified as the decided Result
	// otherwise; an unclassified plain error joined with EngineIO is TERMINAL_LOCAL_INVARIANT(evidence).
	for _, c := range []struct {
		decided, want string
		own           bool
	}{{"", "LOCAL_RESOURCE_UNAVAILABLE(storage_io)", true}, {replayEntryRecovery, replayEntryRecovery, true}, {"", selectedSideInvariant, false}} {
		jc := &replayEntryCall{sentinel: errors.New("s"), result: c.decided, decision: replayEntryResume}
		first := error(errors.New("plain"))
		if c.own {
			first = jc.sentinel
		}
		joined := errors.Join(first, eio)
		out = replayEntryProject(ReplayEntryOutcomeV1{Truth: mdbx.CommitTruthOld, Stage: mdbx.UpdateStagePrewrite, Err: joined}, jc)
		logicalMDBXAssert(t, out.Result == c.want && out.Decision == "" && replaySameErr(out.Err, joined) && out.Replay == nil && out.CanonicalTruth == "OLD" && out.Truth == mdbx.CommitTruthOld && out.Stage == mdbx.UpdateStagePrewrite, "H26 joined %q own=%v: %+v", c.decided, c.own, out)
	}
	// H26 cause walk: an integrity or invariant cause wins over an EARLIER classified cause (EngineIO, or the own
	// sentinel classified as a decided recovery_artifact).
	for _, c := range []struct {
		label string
		late  error
		want  string
	}{
		{"engine integrity", &mdbx.EngineError{Class: mdbx.EngineIntegrity}, selectedSideIntegrity},
		{"engine invariant", &mdbx.EngineError{Class: mdbx.EngineLocalInvariant}, selectedSideInvariant},
		{"consensus defect", selectedSideDefect("late"), selectedSideIntegrity},
	} {
		for _, own := range []bool{false, true} {
			jc := &replayEntryCall{sentinel: errors.New("s"), result: replayEntryRecovery}
			first := error(eio)
			if own {
				first = jc.sentinel
			}
			joined := errors.Join(first, c.late)
			out = replayEntryProject(ReplayEntryOutcomeV1{Truth: mdbx.CommitTruthOld, Stage: mdbx.UpdateStagePrewrite, Err: joined}, jc)
			logicalMDBXAssert(t, out.Result == c.want && out.Decision == "" && replaySameErr(out.Err, joined) && out.CanonicalTruth == "OLD" && out.Truth == mdbx.CommitTruthOld && out.Stage == mdbx.UpdateStagePrewrite && out.Replay == nil, "H26 late %s own=%v: %+v", c.label, own, out)
		}
	}
	defectErr := selectedSideDefect("d")
	defect := replayEntryProject(ReplayEntryOutcomeV1{Truth: mdbx.CommitTruthOld, Stage: mdbx.UpdateStagePrewrite, Err: defectErr}, &replayEntryCall{sentinel: errors.New("s")})
	logicalMDBXAssert(t, defect.Result == selectedSideIntegrity && replaySameErr(defect.Err, defectErr) && defect.Decision == "" && defect.CanonicalTruth == "OLD" && defect.Truth == mdbx.CommitTruthOld && defect.Stage == mdbx.UpdateStagePrewrite && defect.Replay == nil, "defect: %+v", defect)
	// Stage 3: the Result follows the raw truth for every cause class (EngineError values per class).
	for truth, want := range map[mdbx.CommitTruth]string{mdbx.CommitTruthOld: "TERMINAL_PERSISTENCE(old)", mdbx.CommitTruthNew: "TERMINAL_PERSISTENCE(new)", mdbx.CommitTruthUnknown: "TERMINAL_PERSISTENCE(neither_or_unreadable)"} {
		for _, class := range classes {
			crossErr := &mdbx.CommitError{Truth: truth, Cause: &mdbx.EngineError{Class: class}}
			out = replayEntryProject(ReplayEntryOutcomeV1{Truth: truth, Stage: mdbx.UpdateStageCommitMayHaveCrossed, Err: crossErr}, &replayEntryCall{})
			logicalMDBXAssert(t, out.Result == want && replaySameErr(out.Err, crossErr) && out.Decision == "" && out.CanonicalTruth == map[mdbx.CommitTruth]string{mdbx.CommitTruthOld: "OLD", mdbx.CommitTruthNew: "NEW", mdbx.CommitTruthUnknown: "UNKNOWN"}[truth] && out.Truth == truth && out.Stage == mdbx.UpdateStageCommitMayHaveCrossed, "crossed %d/%s: %+v", truth, class, out)
		}
	}
	out = replayEntryProject(ReplayEntryOutcomeV1{Truth: mdbx.CommitTruthNew, Stage: mdbx.UpdateStageCommitMayHaveCrossed}, &replayEntryCall{})
	logicalMDBXAssert(t, out.Result == "" && out.Decision == "" && out.Err == nil && out.CanonicalTruth == "NEW" && out.Truth == mdbx.CommitTruthNew &&
		out.Stage == mdbx.UpdateStageCommitMayHaveCrossed && out.Replay == nil, "normal commit: %+v", out)
}

func replayCorpusResource(step, resource string) string {
	if step != "" {
		return step
	}
	return "LOCAL_RESOURCE_UNAVAILABLE(" + resource + ")"
}

func replayCorpusPrecommit(class mdbx.EngineClass) string {
	switch class {
	case mdbx.EngineIntegrity:
		return "TERMINAL_STORE_INTEGRITY(canonical)"
	case mdbx.EngineInvalidInput, mdbx.EngineStateMismatch, mdbx.EngineLocalInvariant:
		return "TERMINAL_LOCAL_INVARIANT(evidence)"
	case mdbx.EngineCapacity, mdbx.EngineConcurrency, mdbx.EngineTransaction, mdbx.EngineIO:
	}
	return "LOCAL_PERSISTENCE_ERROR(precommit)"
}

// H6, H7: the work and height domain predicates refuse 2^288+1 and 2^32 rather than truncating.
func TestReplayEntryDomains(t *testing.T) {
	limit := new(big.Int).Lsh(big.NewInt(1), 288)
	logicalMDBXAssert(t, replayEntryWorkOK(limit) && !replayEntryWorkOK(new(big.Int).Add(limit, big.NewInt(1))) && !replayEntryWorkOK(new(big.Int)), "work domain")
	logicalMDBXAssert(t, replayEntryHeightOK(0xffffffff) && !replayEntryHeightOK(0), "height domain")
	logicalMDBXAssert(t, !replayEntryHeightOK(1<<32) && !replayEntryHeightOK(1<<32+1), "H7: 2^32 and 2^32+1 are never truncated to u32")
}

// A32, A33, H14: the planned Batch mutates exactly meta 0x02 and meta 0x10||target and consults exactly the
// per-source identity rows; it carries no cleanup, canonical-index or owner mutation.
func TestReplayEntryPlanShape(t *testing.T) {
	keys := func(rows []mdbx.ConsultedRow) [][]byte {
		out := make([][]byte, len(rows))
		for i, row := range rows {
			logicalMDBXAssert(t, row.DBI == logicalMDBXDBIs[2], "consulted DBI %v", row.DBI)
			out[i] = row.Key
		}
		return out
	}
	want := func(heights ...uint64) [][]byte {
		out := make([][]byte, len(heights))
		for i, h := range heights {
			out[i] = logicalMDBXMust(mdbx.HeightKey(1, h))
		}
		return out
	}
	for tip, heights := range map[uint64][]uint64{0: {0, 1}, 1: {0, 1, 2}, 7: {0, 1, 7, 8}, 10: {0, 1, 10, 11}} {
		got := keys(replayEntryConsulted(1, tip))
		logicalMDBXAssert(t, slices.EqualFunc(got, want(heights...), bytes.Equal), "consulted at %d: %x", tip, got)
	}
	w := pendingWorld(t, 7)
	a := w.authority()
	call := &replayEntryCall{}
	batch, err := call.entryBatch(a, 'd', mdbx.RecoveryTargetV1{TipHeight: 8, CumulativeChainwork: sideWorldWork(9)}, 7)
	// H14: the plan writes exactly the authority row and the next counter, so no cleanup span or artifact row. A CleanupV1,
	// SelectedSide or DetachedSuffix in the planned REPLAY authority is illegal (authority.go validity), so entryBatch
	// refuses it and the plan fails here; the decoded plan cannot carry one, and the exclusion stays (A2, R4).
	logicalMDBXAssert(t, err == nil && len(batch.Mutations) == 2 && bytes.Equal(batch.Mutations[0].Key, []byte{2}) &&
		bytes.Equal(batch.Mutations[1].Key, binary.BigEndian.AppendUint64([]byte{0x10}, 3)) && batch.Mutations[1].BeforePresent == false, "plan: %+v %v", batch, err)
	logicalMDBXAssert(t, batch.Mutations[0].DBI == logicalMDBXDBIs[0] && batch.Mutations[1].DBI == logicalMDBXDBIs[0] &&
		slices.EqualFunc(keys(batch.Consulted), want(0, 1, 7, 8), bytes.Equal), "planned Batch DBIs and Consulted: %+v", batch)
}

// H27 (placement only; the timing is R11's): every occurrence of ProtectV1, qualifyAndPlan, plan, runRelease and release in
// replay_entry_mdbx_cgo.go (comments excluded) is classified by enclosing declaration, function-literal and block nesting,
// the innermost statement holding a call, and role (a go statement marks every occurrence in it), and the census equals the
// H27 placements exactly; the clear precedes the invocation, and the deferred (plain) runRelease precedes (follows) both
// Store.Update calls that take plan.
func TestReplayEntryProtectPlacement(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "replay_entry_mdbx_cgo.go", nil, 0)
	logicalMDBXAssert(t, err == nil, "parse: %v", err)
	got, pos := map[string]int{}, map[string]token.Pos{}
	var stack []ast.Node
	ast.Inspect(file, func(n ast.Node) bool {
		if n == nil {
			stack = stack[:len(stack)-1]
			return true
		}
		stack = append(stack, n)
		if id, ok := n.(*ast.Ident); ok && slices.Contains([]string{"ProtectV1", "qualifyAndPlan", "plan", "runRelease", "release"}, id.Name) {
			key := replayPlacement(stack)
			got[key], pos[key] = got[key]+1, max(pos[key], id.Pos())
		}
		return true
	})
	want := map[string]int{
		": field *ast.InterfaceType ProtectV1": 1, ": field *ast.FuncType release": 1, ": field *ast.StructType release": 1,
		"plan: decl plan": 1, "plan: call *ast.ReturnStmt qualifyAndPlan": 1, "qualifyAndPlan: decl qualifyAndPlan": 1,
		"qualifyAndPlan: call *ast.AssignStmt ProtectV1": 1, "qualifyAndPlan: := lhs ProtectV1[1] release": 1,
		"qualifyAndPlan: cmp == nil release": 1, "qualifyAndPlan: = lhs release release": 1, "qualifyAndPlan: = rhs release": 1,
		"EnterReplayTargetMDBX: literal arg store.Update plan": 1, "EnterReplayTargetMDBX: nested arg store.Update plan": 1,
		"EnterReplayTargetMDBX: call *ast.DeferStmt runRelease": 1, "EnterReplayTargetMDBX: call *ast.ExprStmt runRelease": 1,
		"runRelease: decl runRelease": 1, "runRelease: := lhs release release": 1, "runRelease: := rhs release": 1,
		"runRelease: cmp != nil release": 1, "runRelease: nested = lhs nil release": 1, "runRelease: nested call *ast.ExprStmt release": 1,
	}
	logicalMDBXAssert(t, reflect.DeepEqual(got, want), "placement census: %v", got)
	at := func(k string) token.Pos { return pos["EnterReplayTargetMDBX: "+k] }
	first, last := min(at("literal arg store.Update plan"), at("nested arg store.Update plan")), max(at("literal arg store.Update plan"), at("nested arg store.Update plan"))
	clear, invoke := pos["runRelease: nested = lhs nil release"], pos["runRelease: nested call *ast.ExprStmt release"]
	logicalMDBXAssert(t, clear > 0 && invoke > 0 && clear < invoke, "clear %d before invocation %d", clear, invoke)
	deferred, plain := at("call *ast.DeferStmt runRelease"), at("call *ast.ExprStmt runRelease")
	logicalMDBXAssert(t, deferred > 0 && first > 0 && deferred < first, "deferred runRelease %d before both Updates %d", deferred, first)
	logicalMDBXAssert(t, plain > 0 && first > 0 && last < plain, "plain runRelease %d after both Updates %d", plain, last)
}

// replayPlacement classifies the identifier on top of stack as "declaration: [go] [literal]... [nested] role name".
func replayPlacement(stack []ast.Node) string {
	id, i := stack[len(stack)-1].(*ast.Ident), len(stack)-2
	var at ast.Node = id
	if sel, ok := stack[i].(*ast.SelectorExpr); ok && sel.Sel == id {
		at, i = sel, i-1
	}
	role := fmt.Sprintf("other %T", stack[i])
	switch p := stack[i].(type) {
	case *ast.FuncDecl:
		role = "decl"
	case *ast.Field:
		role = fmt.Sprintf("field %T", stack[i-2])
	case *ast.CallExpr:
		role = replayCallRole(p, at, stack[:i])
	case *ast.AssignStmt:
		role = replayAssignRole(p, at)
	case *ast.BinaryExpr:
		role = "cmp " + p.Op.String() + " " + replayCalleeName(p.Y)
	}
	fn := ""
	if d, ok := stack[1].(*ast.FuncDecl); ok {
		fn = d.Name.Name
	}
	return fn + ": " + replayContext(stack[:i]) + role + " " + id.Name
}

// replayContext is "go " inside a go statement, "literal " per enclosing function literal, and "nested " when a block,
// case, or else-if lies between the occurrence and the body of its innermost function (an if/for/switch header is direct).
func replayContext(outer []ast.Node) string {
	gos, lits, body := "", "", 0
	for k, n := range outer {
		switch n.(type) {
		case *ast.GoStmt:
			gos = "go "
		case *ast.FuncLit:
			lits, body = lits+"literal ", k+1
		case *ast.FuncDecl:
			body = k + 1
		}
	}
	for k := body + 1; k < len(outer); k++ {
		if _, elseIf := outer[k-1].(*ast.IfStmt); replayBlock(outer[k]) || elseIf && outer[k-1].(*ast.IfStmt).Else == outer[k] {
			return gos + lits + "nested "
		}
	}
	return gos + lits
}

// replayBlock reports a statement list nested below a function body.
func replayBlock(n ast.Node) bool {
	switch n.(type) {
	case *ast.BlockStmt, *ast.CaseClause, *ast.CommClause:
		return true
	}
	return false
}

// replayCallRole is "arg <callee>" for at as an argument of p, else "call <innermost statement type>".
func replayCallRole(p *ast.CallExpr, at ast.Node, outer []ast.Node) string {
	if p.Fun != at {
		return "arg " + types.ExprString(p.Fun)
	}
	for k := len(outer) - 1; k >= 0; k-- {
		if stmt, ok := outer[k].(ast.Stmt); ok {
			return fmt.Sprintf("call %T", stmt)
		}
	}
	return "call"
}

// replayAssignRole is "<tok> lhs <value>" for a left-hand side (value[i] for a multi-value right-hand side) or "<tok> rhs".
func replayAssignRole(x *ast.AssignStmt, at ast.Node) string {
	for i, lhs := range x.Lhs {
		switch {
		case lhs != at:
		case len(x.Rhs) == len(x.Lhs):
			return x.Tok.String() + " lhs " + replayCalleeName(x.Rhs[i])
		default:
			return fmt.Sprintf("%s lhs %s[%d]", x.Tok, replayCalleeName(x.Rhs[0]), i)
		}
	}
	return x.Tok.String() + " rhs"
}

// replayCalleeName is the identifier or selected field an expression names, or the callee of a call expression.
func replayCalleeName(e ast.Expr) string {
	switch x := e.(type) {
	case *ast.CallExpr:
		return replayCalleeName(x.Fun)
	case *ast.SelectorExpr:
		return x.Sel.Name
	case *ast.Ident:
		return x.Name
	}
	return ""
}

// replaySeq is a header sequence from the published genesis with per-height timestamps and targets, so each new header
// takes its CAN15 expected target.
type replaySeq struct {
	headers [][116]byte
	hashes  [][32]byte
	times   []uint64
	targets [][32]byte
}

func newReplaySeq(w *replayWorld) *replaySeq {
	return &replaySeq{headers: [][116]byte{w.headers[0]}, hashes: [][32]byte{w.genesis.GenesisHash}, times: []uint64{w.lastTime}, targets: [][32]byte{POW_LIMIT}}
}

// clone copies the sequence up to and including height h.
func (s *replaySeq) clone(h int) *replaySeq {
	return &replaySeq{headers: slices.Clone(s.headers[:h+1]), hashes: slices.Clone(s.hashes[:h+1]), times: slices.Clone(s.times[:h+1]), targets: slices.Clone(s.targets[:h+1])}
}

// extend appends n headers spaced by spacing seconds; keep forces the parent target instead of the expected one.
func (s *replaySeq) extend(t *testing.T, n int, spacing uint64, keep bool) {
	t.Helper()
	for range n {
		h := uint64(len(s.headers))
		window := s.times[max(0, int(h)-int(WINDOW_SIZE)):]
		target, err := ReplayExpectedTargetV1(h, s.targets[h-1], window)
		logicalMDBXAssert(t, err == nil, "expected target at %d: %v", h, err)
		if keep {
			target = s.targets[h-1]
		}
		ts := s.times[h-1] + spacing
		header, hash := replayHeader(t, s.hashes[h-1], target, ts)
		s.headers, s.hashes, s.times, s.targets = append(s.headers, header), append(s.hashes, hash), append(s.times, ts), append(s.targets, target)
	}
}

// A4, H24, A29/H2: retarget-boundary qualification over received chains from an empty-genesis canonical index.
func TestReplayEntryRetarget(t *testing.T) {
	w := pendingWorld(t, 0)
	fast := newReplaySeq(w)
	fast.extend(t, int(WINDOW_SIZE)+19, 1, false) // heights 1..10099, the boundary at 10080 lowers the target
	slow := fast.clone(100)
	slow.extend(t, int(WINDOW_SIZE)-90, 2*TARGET_BLOCK_INTERVAL, false) // heights 101..10090, target stays POW_LIMIT
	logicalMDBXAssert(t, fast.targets[WINDOW_SIZE] != POW_LIMIT && slow.targets[WINDOW_SIZE] == POW_LIMIT, "schedule setup")
	headers := slices.Concat(fast.headers[1:], slow.headers[101:])
	fastTip, slowTip := fast.hashes[len(fast.hashes)-1], slow.hashes[len(slow.hashes)-1]
	before := w.snapshot()
	fastWork := new(big.Int).SetUint64(WINDOW_SIZE)
	for _, target := range fast.targets[WINDOW_SIZE:] {
		work, _ := WorkFromTarget(target)
		fastWork.Add(fastWork, work)
	}
	out := w.enter(&replayView{inv: replayComplete([][32]byte{slowTip, fastTip}, headers)}, w.genesis)
	replayCommitted(t, w, out, before, mdbx.StorageProfilePrunedV1, fastTip, uint64(len(fast.hashes)-1), fastWork.Uint64())
	// A4: a slow tip at 10120 (work 10121) is higher than the fast tip at 10099 (work 10160); the fast tip is bound.
	tall := slow.clone(len(slow.hashes) - 1)
	tall.extend(t, 30, 2*TARGET_BLOCK_INTERVAL, false)
	w4 := pendingWorld(t, 0)
	before = w4.snapshot()
	out = w4.enter(&replayView{inv: replayComplete([][32]byte{tall.hashes[len(tall.hashes)-1], fastTip}, slices.Concat(fast.headers[1:], tall.headers[101:]))}, w4.genesis)
	replayCommitted(t, w4, out, before, mdbx.StorageProfilePrunedV1, fastTip, uint64(len(fast.hashes)-1), fastWork.Uint64())
	// H24: the same fast chain (heights 1..10099, same spacing) whose boundary header keeps the parent target is
	// ineligible; the slow tip is bound. The eligible control above is that chain with the boundary carrying target_new.
	kept := fast.clone(int(WINDOW_SIZE) - 1)
	kept.extend(t, 20, 1, true) // tip 10099 would outrank the slow tip 10090 if eligible
	logicalMDBXAssert(t, len(kept.hashes) == len(fast.hashes) && kept.times[len(kept.times)-1] == fast.times[len(fast.times)-1], "H24 same chain shape")
	w2 := pendingWorld(t, 0)
	before = w2.snapshot()
	out = w2.enter(&replayView{inv: replayComplete([][32]byte{slowTip, kept.hashes[len(kept.hashes)-1]}, slices.Concat(kept.headers[1:], slow.headers[101:]))}, w2.genesis)
	replayCommitted(t, w2, out, before, mdbx.StorageProfilePrunedV1, slowTip, uint64(len(slow.hashes)-1), uint64(len(slow.hashes)))
	// A29/H2: the boundary header declares the expected POW_LIMIT/4 but its hash is not below it; the slow tip is bound.
	weak := fast.clone(int(WINDOW_SIZE) - 1)
	weak.appendFailingPow(t)
	weak.extend(t, 20, 1, false)
	w3 := pendingWorld(t, 0)
	before = w3.snapshot()
	out = w3.enter(&replayView{inv: replayComplete([][32]byte{slowTip, weak.hashes[len(weak.hashes)-1]}, slices.Concat(weak.headers[1:], slow.headers[101:]))}, w3.genesis)
	replayCommitted(t, w3, out, before, mdbx.StorageProfilePrunedV1, slowTip, uint64(len(slow.hashes)-1), uint64(len(slow.hashes)))
}

// appendFailingPow appends a header that carries its CAN15 expected target while its hash is not below that target
// (it is below POW_LIMIT, so only re-qualification under the expected target refuses it).
func (s *replaySeq) appendFailingPow(t *testing.T) {
	t.Helper()
	h := uint64(len(s.headers))
	target, err := ReplayExpectedTargetV1(h, s.targets[h-1], s.times[max(0, int(h)-int(WINDOW_SIZE)):])
	quarter := [32]byte(new(big.Int).Rsh(new(big.Int).SetBytes(POW_LIMIT[:]), 2).FillBytes(make([]byte, 32)))
	logicalMDBXAssert(t, err == nil && target == quarter, "expected target at %d is not POW_LIMIT/4: %x %v", h, target, err)
	header, _ := replayHeader(t, s.hashes[h-1], target, s.times[h-1]+1)
	for nonce := uint64(0); PowCheck(header[:], target) == nil; nonce++ {
		binary.LittleEndian.PutUint64(header[108:116], nonce)
	}
	logicalMDBXAssert(t, PowCheck(header[:], POW_LIMIT) == nil, "header must pass POW_LIMIT")
	hash, _ := BlockHash(header[:])
	s.headers, s.hashes, s.times, s.targets = append(s.headers, header), append(s.hashes, hash), append(s.times, s.times[h-1]+1), append(s.targets, target)
}

// R52 D4 (the seeded defect): the header row of canonical height 7 is definitively absent.
func TestReplayEntryHeaderDefects(t *testing.T) {
	w0 := newReplayWorld(t, 0)
	headers, _ := replayChain(t, w0.genesis.GenesisHash, w0.lastTime, 8)
	replayIntegrity(t, defectWorld(t, headers, func(h uint64, rows []mdbx.Mutation) []mdbx.Mutation {
		if h == 7 {
			return rows[1:]
		}
		return rows
	}), "R52 D4 absent header")
}

// R22: source (b), identity-only, a complete inventory whose only candidate is the header-only height-0 genesis.
func TestReplayEntryHeightZeroOnly(t *testing.T) {
	w := newReplayWorld(t, -1)
	view := &replayView{inv: replayComplete([][32]byte{w.genesis.GenesisHash}, [][116]byte{w.headers[0]})}
	replayRefused(t, w, view, replayIdentityOnly(), replayEntryRecovery, "R22")
	logicalMDBXAssert(t, w.authority().NextGenerationID == 2 && w.authority().Phase == mdbx.StoragePhaseNoneV1, "R22 authority")
}

// A30: the producer receives the one capacity_boundary limit at H = 100 and H = 20,000, and the source (d) entry commits
// at both heights with an empty inventory and at H = 20,000 with received headers filling the limit. The walk's canonical
// working memory not growing with H is a reviewed structural property; this test does not observe retention.
func TestReplayEntryStreaming(t *testing.T) {
	if testing.Short() {
		t.Skip("seeds a 20,000-height canonical chain")
	}
	for _, tip := range []int{100, 20_000} {
		w := pendingWorld(t, tip)
		before := w.snapshot()
		view := &replayView{inv: replayComplete(nil, nil)}
		out := w.enter(view, w.genesis)
		replayCommitted(t, w, out, before, mdbx.StorageProfilePrunedV1, w.hashes[tip], uint64(tip), uint64(tip)+1)
		logicalMDBXAssert(t, len(view.limits) == 1 && view.limits[0] == 71_815_566, "A30 limit at %d: %v", tip, view.limits)
	}
	// A30 limit part: one tip and as many received headers as fit the limit, extending canonical 20,000.
	const fill = (71_815_566 - 32) / 116
	w := pendingWorld(t, 20_000)
	headers, hashes := w.fork(20_000, fill, 0)
	view := &replayView{inv: replayComplete([][32]byte{hashes[fill-1]}, headers)}
	logicalMDBXAssert(t, view.inv.Bytes <= 71_815_566 && view.inv.Bytes+116 > 71_815_566, "A30 fill: %d", view.inv.Bytes)
	before := w.snapshot()
	out := w.enter(view, w.genesis)
	replayCommitted(t, w, out, before, mdbx.StorageProfilePrunedV1, hashes[fill-1], 20_000+fill, 20_001+fill)
}

// replayCaptured runs the production entry callback inside one real Store.Update and returns the Batch it handed to the
// Store, so Consulted is observed on the store path rather than on a hand-built plan, and the raw tuple projected
// through replayEntryProject.
func replayCaptured(t *testing.T, w *replayWorld, view HeaderCandidateViewV1, genesis PublishedGenesisContextV1) (mdbx.Batch, ReplayEntryOutcomeV1) {
	t.Helper()
	call := &replayEntryCall{owner: NewReplayEntryOwnerV1(view, genesis), reservations: w.owner, sentinel: errors.New("s")}
	var batch mdbx.Batch
	truth, stage, err := w.store.Update(func(r *mdbx.Reader) (mdbx.Batch, error) {
		b, err := call.plan(r)
		batch = b
		return b, err
	})
	call.runRelease()
	logicalMDBXAssert(t, truth == mdbx.CommitTruthNew && err == nil, "captured entry: %s %v", truth, err)
	return batch, replayEntryProject(ReplayEntryOutcomeV1{Truth: truth, Stage: stage, Err: err}, call)
}

// replayCapturedCommit commits the row's own request through replayCaptured on w and asserts the projected outcome
// and image (replayCommitted), Batch.Consulted exactly HeightKey(1, heights...) and, when absent, each consulted row
// absent before and after the commit.
func replayCapturedCommit(t *testing.T, w *replayWorld, inv HeaderCandidateInventoryV1, genesis PublishedGenesisContextV1, tip [32]byte, height, work uint64, absent bool, heights ...uint64) {
	t.Helper()
	want := make([][]byte, len(heights))
	for i, h := range heights {
		want[i] = logicalMDBXMust(mdbx.HeightKey(1, h))
	}
	present := func() bool {
		found := false
		err := w.store.View(func(r *mdbx.Reader) error {
			for _, key := range want {
				_, ok, err := r.Get(logicalMDBXDBIs[2], key)
				if err != nil {
					return err
				}
				found = found || ok
			}
			return nil
		})
		logicalMDBXAssert(t, err == nil, "consulted presence: %v", err)
		return found
	}
	logicalMDBXAssert(t, !absent || !present(), "consulted rows present before the commit")
	before := w.snapshot()
	view := &replayView{inv: inv}
	batch, out := replayCaptured(t, w, view, genesis)
	got := make([][]byte, len(batch.Consulted))
	for i, row := range batch.Consulted {
		logicalMDBXAssert(t, row.DBI == logicalMDBXDBIs[2], "own-commit consulted DBI %v", row.DBI)
		got[i] = row.Key
	}
	logicalMDBXAssert(t, slices.EqualFunc(got, want, bytes.Equal), "own-commit consulted: %x", got)
	logicalMDBXAssert(t, !absent || !present(), "consulted rows present after the commit")
	replayPlanMutations(t, w, batch.Mutations, before, tip, height, work)
	replayCommitted(t, w, out, before, mdbx.StorageProfilePrunedV1, tip, height, work)
}

// replayPlanMutations asserts the plan (6) mutation set exactly, in any order: the meta authority literal over the
// present row and the absent target counter row LogicalCounterValue(0,0), nothing else.
func replayPlanMutations(t *testing.T, w *replayWorld, got []mdbx.Mutation, before mdbx.StorageAuthorityV1, tip [32]byte, height, work uint64) {
	t.Helper()
	_, encoded, counterKey := replayExpected(t, w, before, mdbx.StorageProfilePrunedV1, tip, height, work)
	want := []mdbx.Mutation{
		{DBI: logicalMDBXDBIs[0], Key: []byte{2}, BeforePresent: true, AfterKind: mdbx.AfterLiteral, Literal: encoded},
		{DBI: logicalMDBXDBIs[0], Key: counterKey, AfterKind: mdbx.AfterLiteral, Literal: mdbx.LogicalCounterValue(0, 0)},
	}
	sorted := slices.Clone(got)
	slices.SortFunc(sorted, func(a, b mdbx.Mutation) int { return bytes.Compare(a.Key, b.Key) })
	logicalMDBXAssert(t, reflect.DeepEqual(sorted, want), "plan mutations: %+v want %+v", got, want)
}

// A32, A33: the committed entry's Batch.Consulted is the exact set; at PRE_GENESIS both consulted rows are absent.
func TestReplayEntryStoreConsulted(t *testing.T) {
	heights := func(g uint64, hs ...uint64) [][]byte {
		out := make([][]byte, len(hs))
		for i, h := range hs {
			out[i] = logicalMDBXMust(mdbx.HeightKey(g, h))
		}
		return out
	}
	keys := func(rows []mdbx.ConsultedRow) [][]byte {
		out := make([][]byte, len(rows))
		for i, row := range rows {
			logicalMDBXAssert(t, row.DBI == logicalMDBXDBIs[2], "consulted DBI %v", row.DBI)
			out[i] = row.Key
		}
		return out
	}
	w := pendingWorld(t, 7)
	g := w.authority().ActiveGenerationID
	tips, hashes := w.fork(7, 1, 1)
	before := w.snapshot()
	batch, out := replayCaptured(t, w, &replayView{inv: replayComplete([][32]byte{hashes[0]}, tips)}, w.genesis)
	logicalMDBXAssert(t, slices.EqualFunc(keys(batch.Consulted), heights(g, 0, 1, 7, 8), bytes.Equal), "A32 consulted: %x", keys(batch.Consulted))
	replayCommitted(t, w, out, before, mdbx.StorageProfilePrunedV1, hashes[0], 8, 9)
	w = newReplayWorld(t, -1)
	g = w.authority().ActiveGenerationID
	headers, hashes := replayChain(t, w.genesis.GenesisHash, w.lastTime, 2)
	before = w.snapshot()
	batch, out = replayCaptured(t, w, &replayView{inv: replayComplete([][32]byte{hashes[1]}, append([][116]byte{w.headers[0]}, headers...))}, replayIdentityOnly())
	replayCommitted(t, w, out, before, w.authority().ActiveProfile, hashes[1], 2, 3)
	logicalMDBXAssert(t, slices.EqualFunc(keys(batch.Consulted), heights(g, 0, 1), bytes.Equal), "A33 consulted: %x", keys(batch.Consulted))
	err := w.store.View(func(r *mdbx.Reader) error {
		for _, key := range heights(g, 0, 1) {
			_, present, err := r.Get(logicalMDBXDBIs[2], key)
			if err != nil || present {
				return fmt.Errorf("A33 row %x present=%v: %w", key, present, err)
			}
		}
		return nil
	})
	logicalMDBXAssert(t, err == nil, "A33: %v", err)
}

// H1: the owner method, the constructor, the view interface and the context struct take no target tuple, tip, subset,
// qualification flag, per-call genesis body or availability flag; the view and the published-genesis context are fixed
// at owner construction, so a later change of the caller's Published bytes does not reach the owner.
func TestReplayEntryExportedSignatures(t *testing.T) {
	owner := reflect.TypeFor[*ReplayEntryOwnerV1]()
	logicalMDBXAssert(t, owner.NumMethod() == 3 && owner.Method(0).Name == "EnterReplayTargetMDBX" && owner.Method(1).Name == "PlanDirectReplayEntryMDBX" && owner.Method(2).Name == "RecomputeReplayTargetMDBX" &&
		owner.Method(0).Type == reflect.TypeOf(func(*ReplayEntryOwnerV1, *mdbx.Store, *mdbx.OperationReservationOwner) ReplayEntryOutcomeV1 {
			return ReplayEntryOutcomeV1{}
		}),
		"owner methods: %d", owner.NumMethod())
	for i := range owner.Elem().NumField() {
		logicalMDBXAssert(t, !owner.Elem().Field(i).IsExported(), "exported owner field %s", owner.Elem().Field(i).Name)
	}
	logicalMDBXAssert(t, reflect.TypeOf(NewReplayEntryOwnerV1) == reflect.TypeOf(func(HeaderCandidateViewV1, PublishedGenesisContextV1) *ReplayEntryOwnerV1 { return nil }), "constructor signature")
	view := reflect.TypeFor[HeaderCandidateViewV1]()
	inventory, _ := view.MethodByName("InventoryV1")
	protect, _ := view.MethodByName("ProtectV1")
	logicalMDBXAssert(t, view.NumMethod() == 2 && inventory.Type == reflect.TypeOf(func(uint64) HeaderCandidateInventoryV1 { return HeaderCandidateInventoryV1{} }) &&
		protect.Type == reflect.TypeOf(func(uint64) (bool, func()) { return false, nil }), "view methods")
	genesis := reflect.TypeFor[PublishedGenesisContextV1]()
	names := make([]string, genesis.NumField())
	for i := range names {
		names[i] = genesis.Field(i).Name
	}
	logicalMDBXAssert(t, slices.Equal(names, []string{"ChainID", "GenesisHash", "Published"}), "genesis context fields: %v", names)
	w := newReplayWorld(t, -1)
	caller := replayGenesis()
	caller.Published = bytes.Clone(caller.Published)
	fixed := NewReplayEntryOwnerV1(&replayView{}, caller)
	caller.Published[200] ^= 1 // would fail the ChainID commitment if the owner aliased the caller's bytes
	image := w.image()
	replayDecided(t, fixed.EnterReplayTargetMDBX(w.store, w.owner), "", replayEntryGenesisFirst, "H1 caller bytes changed after construction")
	replaySameImage(t, image, w.image(), "H1")
}

// BenchmarkReplayEntryWalk measures the per-header walk (canonical rows with their D10 predicates, received-header
// qualify/attach); this pending (source d) world never reads the step-1 identity page: an R4-shaped entry over canonical 0..100 and a 50-header received
// branch, with canonical height 1 excluded so every path is ineligible and the published prefix tip is height 0 (no
// positive-height target); it ends recovery_artifact with zero mutation and the Store is unchanged across iterations.
// RUB-1571: the exclusion was height 2, which now commits the height-1 prefix tip (MP 2544-2561). A measurement with no threshold (coder-go section 3); the contract sets none.
func BenchmarkReplayEntryWalk(b *testing.B) {
	w := pendingWorld(b, 100)
	headers, hashes := w.fork(100, 50, 1)
	w.setAuthority(func(a *mdbx.StorageAuthorityV1) {
		a.ExcludedInvalidBranch = &mdbx.InvalidBranchV1{FirstInvalidHeight: 1, FirstInvalidBlockHash: w.hashes[1], ExactConsensusError: []byte("BLOCK_ERR_POW_INVALID")}
	})
	view := &replayView{inv: replayComplete([][32]byte{hashes[49]}, headers)}
	owner := NewReplayEntryOwnerV1(view, w.genesis)
	b.ReportAllocs()
	b.SetBytes(116 * (101 + 50))
	for b.Loop() {
		if out := owner.EnterReplayTargetMDBX(w.store, w.owner); out.Result != replayEntryRecovery {
			b.Fatalf("walk: %+v", out)
		}
	}
}
