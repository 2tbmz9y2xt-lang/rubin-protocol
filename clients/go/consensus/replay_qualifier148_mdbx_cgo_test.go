//go:build cgo && (darwin || linux) && (amd64 || arm64)

package consensus

import (
	"bytes"
	"crypto/sha3"
	"encoding/binary"
	"errors"
	"math"
	"math/big"
	"slices"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/mdbx"
)

// q148Half is a target that about half of all hashes meet, so a full-148 and a 116-prefix PoW verdict can differ.
var q148Half = [32]byte{0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

// q148Hash is the HDR block hash of a 148-byte header, SHA3-256 over all 148 bytes, computed by the test.
func q148Hash(raw []byte) [32]byte { return sha3.Sum256(raw) }

// q148Meets is the HDR PoW predicate: the hash as an unsigned big-endian integer is below target.
func q148Meets(raw []byte, target [32]byte) bool {
	hash := sha3.Sum256(raw)
	return bytes.Compare(hash[:], target[:]) < 0
}

// q148Header builds a 148-byte header (HDR offsets: parent 4:36, timestamp 68:76, target 76:108, utxo_root 108:140,
// nonce 140:148); the search counter goes into the nonce and utxo_root[0:8], so the 116-byte prefix varies too.
func q148Header(t *testing.T, parent, target [32]byte, timestamp uint64, accept func(raw []byte) bool) [148]byte {
	t.Helper()
	var h [148]byte
	binary.LittleEndian.PutUint32(h[:4], 1)
	copy(h[4:36], parent[:])
	binary.LittleEndian.PutUint64(h[68:76], timestamp)
	copy(h[76:108], target[:])
	for n := uint64(0); n < 1<<20; n++ {
		binary.LittleEndian.PutUint64(h[108:116], n)
		binary.LittleEndian.PutUint64(h[140:148], n)
		if accept(h[:]) {
			return h
		}
	}
	t.Fatal("no header found")
	return h
}

func q148Any([]byte) bool { return true }

// q148Defect asserts err is the selected-side integrity defect with exactly message.
func q148Defect(t *testing.T, err error, message, label string) {
	t.Helper()
	var failure *selectedSideFailure
	if !errors.As(err, &failure) || failure.result != selectedSideIntegrity || failure.cause.Error() != message {
		t.Fatalf("%s: got %v, want %s", label, err, message)
	}
}

func q148Qualifier(g PublishedGenesisContextV1, tips [][32]byte, headers ...[148]byte) *replayQualifier {
	return newReplayQualifier148(g, HeaderCandidateInventory148V1{Status: HeaderCandidateCompleteV1, Tips: tips, Headers: headers}, nil)
}

// TestReplayQualifier148Identity is Q1 and H1: identity is the hash of all 148 bytes, so a utxo_root-only difference
// gives two identities, each reached only through its own bytes; duplicate headers and tips collapse.
func TestReplayQualifier148Identity(t *testing.T) {
	a := q148Header(t, [32]byte{1}, POW_LIMIT, 100, q148Any)
	b := a
	b[139] ^= 1 // utxo_root only
	ha, hb := q148Hash(a[:]), q148Hash(b[:])
	if ha == hb {
		t.Fatal("fixture: utxo_root mutation did not change the hash")
	}
	q := q148Qualifier(replayGenesis(), [][32]byte{hb, ha, hb}, a, b, a)
	if len(q.nodes) != 2 || len(q.tips) != 2 {
		t.Fatalf("nodes %d tips %d, want 2 and 2", len(q.nodes), len(q.tips))
	}
	for _, c := range []struct {
		hash [32]byte
		raw  [148]byte
	}{{ha, a}, {hb, b}} {
		i := q.find(c.hash)
		if i < 0 || !bytes.Equal(q.header(i), c.raw[:]) || q.parentOf(i) != [32]byte{1} {
			t.Fatalf("identity %x not reached through its own bytes (node %d)", c.hash, i)
		}
	}
}

// TestReplayQualifier148PrefixAlias is H2: a 148 header whose first 116 bytes are a 116 header has no identity, anchor
// or qualification under the 116 hash of that prefix.
func TestReplayQualifier148PrefixAlias(t *testing.T) {
	p := q148Header(t, [32]byte{2}, POW_LIMIT, 100, q148Any)
	alias := q148Hash(p[:116])
	if _, err := ParseBlockHeaderBytes(p[:116]); err != nil {
		t.Fatalf("fixture: prefix is not a 116 header: %v", err)
	}
	g := replayIdentityOnly()
	g.GenesisHash = alias
	q := q148Qualifier(g, [][32]byte{alias}, p)
	if q.find(alias) >= 0 || q.find(q148Hash(p[:])) != 0 {
		t.Fatal("148 node is identified by its 116-byte prefix")
	}
	q.anchor()
	if q.count != 0 || q.nodes[0].flags != 0 {
		t.Fatalf("anchor taken from a 116-byte prefix identity: count %d flags %d", q.count, q.nodes[0].flags)
	}
}

// TestReplayQualifier148CanonicalIdentity is H4 with the width split of D5: the stored 148 bytes must hash, at 148, to
// the index hash; 116 bytes at width 148 and 148 bytes at width 116 are header-hash defects.
func TestReplayQualifier148CanonicalIdentity(t *testing.T) {
	gh := q148Header(t, [32]byte{}, POW_LIMIT, 100, q148Any)
	hash := q148Hash(gh[:])
	g := replayIdentityOnly()
	g.GenesisHash = hash
	q := q148Qualifier(g, nil)
	header, err := q.canonicalIdentity(0, hash, [32]byte{}, gh[:])
	if err != nil || header.Target != POW_LIMIT || header.Timestamp != 100 || header.PrevBlockHash != ([32]byte{}) {
		t.Fatalf("valid 148 genesis row: %+v %v", header, err)
	}
	wrong := hash
	wrong[31] ^= 1
	_, err = q.canonicalIdentity(0, wrong, [32]byte{}, gh[:])
	q148Defect(t, err, "replay canonical header hash mismatch", "index hash differs from the 148 hash")
	_, err = q.canonicalIdentity(0, q148Hash(gh[:116]), [32]byte{}, gh[:116])
	q148Defect(t, err, "replay canonical header hash mismatch", "116 bytes at width 148")
	q116 := newReplayQualifier(g, HeaderCandidateInventoryV1{Status: HeaderCandidateCompleteV1}, nil)
	_, err = q116.canonicalIdentity(0, hash, [32]byte{}, gh[:])
	q148Defect(t, err, "replay canonical header hash mismatch", "148 bytes at width 116")
}

// TestReplayQualifier148CanonicalPow is Q2 for D10 at height 0: the PoW verdict is over all 148 bytes, never the
// 116-byte prefix.
func TestReplayQualifier148CanonicalPow(t *testing.T) {
	q := q148Qualifier(replayIdentityOnly(), nil)
	for _, c := range []struct {
		label string
		want  bool
	}{{"148 meets, prefix does not", true}, {"prefix meets, 148 does not", false}} {
		raw := q148Header(t, [32]byte{}, q148Half, 100, func(raw []byte) bool {
			return q148Meets(raw, q148Half) == c.want && q148Meets(raw[:116], q148Half) != c.want
		})
		header, err := q.parse(raw[:])
		if err != nil || header.Target != q148Half {
			t.Fatalf("%s: parse %+v %v", c.label, header, err)
		}
		if got := q.canonicalOK(0, raw[:], header); got != c.want {
			t.Fatalf("%s: canonicalOK %v, want %v", c.label, got, c.want)
		}
	}
}

// TestReplayQualifier148Anchor is Q4: Published[:148] seeds height 0 with its target and timestamp when it passes PoW
// at 148; failing PoW makes the anchor ineligible; with Published nil the inventory header named GenesisHash anchors.
func TestReplayQualifier148Anchor(t *testing.T) {
	for _, c := range []struct {
		label     string
		pass      bool
		published bool
	}{{"published passes", true, true}, {"published fails PoW", false, true}, {"inventory anchor passes", true, false}} {
		gh := q148Header(t, [32]byte{}, q148Half, 1234, func(raw []byte) bool { return q148Meets(raw, q148Half) == c.pass })
		g := replayIdentityOnly()
		g.GenesisHash = q148Hash(gh[:])
		q := q148Qualifier(g, nil, gh)
		if c.published {
			g.Published = append(gh[:], make([]byte, 118)...) // 266 bytes meeting the Q4 precondition (the 148 context check is RUB-1627's)
			q = q148Qualifier(g, nil)
		}
		q.anchor()
		wantBad := uint64(math.MaxUint64)
		if !c.pass {
			wantBad = 0
		}
		if q.count != 1 || q.hash != g.GenesisHash || q.target != q148Half || q.ring[0] != 1234 || q.badFrom != wantBad {
			t.Fatalf("%s: count %d hash %x target %x ts %d badFrom %d", c.label, q.count, q.hash, q.target, q.ring[0], q.badFrom)
		}
		if !c.published && q.nodes[0].flags&(replayNodeE3|replayNodeReached) != replayNodeE3|replayNodeReached {
			t.Fatalf("%s: anchor node flags %d", c.label, q.nodes[0].flags)
		}
	}
}

// TestReplayQualifier116Unchanged is A8 at function level: the 116 qualifier identifies, parses and PoW-checks 116
// bytes, so the width-148 primitives (which refuse 116 bytes) are never on its path.
func TestReplayQualifier116Unchanged(t *testing.T) {
	h, _ := replayHeader(t, [32]byte{}, q148Half, 100)
	g := replayIdentityOnly()
	g.GenesisHash = q148Hash(h[:])
	q := newReplayQualifier(g, HeaderCandidateInventoryV1{Status: HeaderCandidateCompleteV1, Headers: [][116]byte{h}}, nil)
	if q.find(g.GenesisHash) != 0 {
		t.Fatal("116 node hash is not SHA3-256 of its 116 bytes")
	}
	header, err := q.canonicalIdentity(0, g.GenesisHash, [32]byte{}, h[:])
	if err != nil || !q.canonicalOK(0, h[:], header) {
		t.Fatalf("116 genesis row: %v", err)
	}
	q.anchor()
	if q.count != 1 || q.target != q148Half || q.badFrom != math.MaxUint64 {
		t.Fatalf("116 anchor: count %d target %x badFrom %d", q.count, q.target, q.badFrom)
	}
}

// q148View is the test producer of HeaderCandidateView148V1; it also implements HeaderCandidateViewV1 (the owner's
// view type) and records every call.
type q148View struct {
	inv        HeaderCandidateInventory148V1
	calls116   int
	limits     []uint64
	versions   []uint64
	stale      bool
	nilRelease bool
	releases   int
}

func (v *q148View) InventoryV1(uint64) HeaderCandidateInventoryV1 {
	v.calls116++
	return HeaderCandidateInventoryV1{}
}

func (v *q148View) Inventory148V1(limit uint64) HeaderCandidateInventory148V1 {
	v.limits = append(v.limits, limit)
	return v.inv
}

func (v *q148View) ProtectV1(version uint64) (bool, func()) {
	v.versions = append(v.versions, version)
	if v.nilRelease {
		return !v.stale, nil
	}
	return !v.stale, func() { v.releases++ }
}

// q148Complete is a Complete 148 inventory with Version 9 and exact Bytes (32 per tip, 148 per header).
func q148Complete(tips [][32]byte, headers [][148]byte) HeaderCandidateInventory148V1 {
	return HeaderCandidateInventory148V1{Status: HeaderCandidateCompleteV1, Version: 9, Tips: tips, Headers: headers, Bytes: 32*uint64(len(tips)) + 148*uint64(len(headers))}
}

// q148Seq is a 148-byte header sequence from its own genesis; each header takes its Section 15 expected target unless
// the caller overrides it.
type q148Seq struct {
	headers [][148]byte
	hashes  [][32]byte
	times   []uint64
	targets [][32]byte
}

func newQ148Seq(t *testing.T, target [32]byte, timestamp uint64) *q148Seq {
	g := q148Header(t, [32]byte{}, target, timestamp, func(raw []byte) bool { return q148Meets(raw, target) })
	return &q148Seq{headers: [][148]byte{g}, hashes: [][32]byte{q148Hash(g[:])}, times: []uint64{timestamp}, targets: [][32]byte{target}}
}

func (s *q148Seq) clone(h int) *q148Seq {
	return &q148Seq{headers: slices.Clone(s.headers[:h+1]), hashes: slices.Clone(s.hashes[:h+1]), times: slices.Clone(s.times[:h+1]), targets: slices.Clone(s.targets[:h+1])}
}

// push appends one header over the last with the given target and timestamp; meets selects the PoW verdict.
func (s *q148Seq) push(t *testing.T, target [32]byte, timestamp uint64, meets bool) {
	h := q148Header(t, s.hashes[len(s.hashes)-1], target, timestamp, func(raw []byte) bool { return q148Meets(raw, target) == meets })
	s.headers, s.hashes, s.times, s.targets = append(s.headers, h), append(s.hashes, q148Hash(h[:])), append(s.times, timestamp), append(s.targets, target)
}

// extend appends n headers spaced by spacing seconds; keep forces the parent target instead of the expected one.
func (s *q148Seq) extend(t *testing.T, n int, spacing uint64, keep bool) {
	t.Helper()
	for range n {
		h := uint64(len(s.headers))
		target, err := ReplayExpectedTargetV1(h, s.targets[h-1], s.times[max(0, int(h)-int(WINDOW_SIZE)):])
		if err != nil {
			t.Fatalf("expected target at %d: %v", h, err)
		}
		if keep {
			target = s.targets[h-1]
		}
		s.push(t, target, s.times[h-1]+spacing, true)
	}
}

func (s *q148Seq) tip() [32]byte { return s.hashes[len(s.hashes)-1] }

// work is the cumulative chainwork of heights 0..h as the 40-byte big-endian encoding.
func (s *q148Seq) work(t *testing.T, h int) [40]byte {
	sum := new(big.Int)
	for _, target := range s.targets[:h+1] {
		w, err := WorkFromTarget(target)
		if err != nil {
			t.Fatalf("work of %x: %v", target, err)
		}
		sum.Add(sum, w)
	}
	return [40]byte(sum.FillBytes(make([]byte, 40)))
}

// q148World is a format-3 store whose generation-1 canonical index holds heights 0..n of a 148-byte sequence.
type q148World struct {
	*btWorld
	g PublishedGenesisContextV1
}

func newQ148World(t *testing.T, s *q148Seq, n int, edit func(h int, rows []mdbx.Mutation) []mdbx.Mutation) *q148World {
	t.Helper()
	w := &q148World{btWorld: btNew(t), g: PublishedGenesisContextV1{ChainID: [32]byte{0xc1}, GenesisHash: s.hashes[0]}}
	var rows []mdbx.Mutation
	for h := 0; h <= n; h++ {
		parent := [32]byte{}
		if h > 0 {
			parent = s.hashes[h-1]
		}
		key, err := mdbx.HeightKey(1, uint64(h))
		if err != nil {
			t.Fatal(err)
		}
		row := []mdbx.Mutation{btMutation(3, bytes.Clone(s.hashes[h][:]), bytes.Clone(s.headers[h][:])), btMutation(2, key, mdbx.ChainValue(s.hashes[h], parent, s.work(t, h))), q148Owner(s.hashes[h], h)}
		if edit != nil {
			row = edit(h, row)
		}
		rows = append(rows, row...)
	}
	if n >= 0 {
		w.pair(t, rows...)
	}
	return w
}

// q148Owner is the canonical-owner row paired with a generation-1 index row (format-3 Pair pairing rule).
func q148Owner(hash [32]byte, h int) mdbx.Mutation {
	return btMutation(7, logicalMDBXMust(mdbx.CanonicalOwnerKey(1, hash)), mdbx.CanonicalOwnerValue(uint64(h)))
}

type q148Out struct {
	target mdbx.RecoveryTargetV1
	tip    uint64
	err    error
	call   *replayEntryCall
}

// qualify runs Q5 under one Reader of the format-3 store and then the caller's release handling.
func (w *q148World) qualify(t *testing.T, view HeaderCandidateViewV1, a mdbx.StorageAuthorityV1, lane uint64) q148Out {
	t.Helper()
	out := q148Out{call: &replayEntryCall{owner: NewReplayEntryOwnerV1(view, w.g), sentinel: errors.New("q148 decision"), lane: lane}}
	if err := w.s.View(func(r *mdbx.Reader) error {
		out.target, out.tip, out.err = out.call.qualify148(r, a)
		return nil
	}); err != nil {
		t.Fatalf("view: %v", err)
	}
	out.call.runRelease()
	return out
}

func q148Active() mdbx.StorageAuthorityV1 { return mdbx.StorageAuthorityV1{ActiveGenerationID: 1} }

// selected asserts a selection of tip at height with work, the walk tip height and exactly one ProtectV1 and release.
func (o q148Out) selected(t *testing.T, w *q148World, v *q148View, tip [32]byte, height uint64, work [40]byte, walkTip uint64, label string) {
	t.Helper()
	want := mdbx.RecoveryTargetV1{ChainID: w.g.ChainID, GenesisHash: w.g.GenesisHash, TipHash: tip, TipHeight: height, CumulativeChainwork: work}
	if o.err != nil || o.target != want || o.tip != walkTip || o.call.result != "" {
		t.Fatalf("%s: got %+v tip %d %q %v, want %+v tip %d", label, o.target, o.tip, o.call.result, o.err, want, walkTip)
	}
	if !slices.Equal(v.versions, []uint64{9}) || v.releases != 1 || v.calls116 != 0 {
		t.Fatalf("%s: ProtectV1 %v releases %d 116 calls %d", label, v.versions, v.releases, v.calls116)
	}
}

// decided asserts a decided outcome: zero target and tip height, the sentinel, result, and the ProtectV1 count.
func (o q148Out) decided(t *testing.T, result string, protects int, label string) {
	t.Helper()
	if !errors.Is(o.err, o.call.sentinel) || o.target != (mdbx.RecoveryTargetV1{}) || o.tip != 0 || o.call.result != result {
		t.Fatalf("%s: got %+v tip %d %q %v, want %q", label, o.target, o.tip, o.call.result, o.err, result)
	}
	if v, ok := o.call.owner.view.(*q148View); ok && len(v.versions) != protects {
		t.Fatalf("%s: ProtectV1 calls %d, want %d", label, len(v.versions), protects)
	}
}

// q148Slow is a canonical sequence 0..n spaced 2*TARGET_BLOCK_INTERVAL under POW_LIMIT.
func q148Slow(t *testing.T, n int) *q148Seq {
	s := newQ148Seq(t, POW_LIMIT, 1<<30)
	s.extend(t, n, 2*TARGET_BLOCK_INTERVAL, false)
	return s
}

// TestReplayQualifier148Select is A1 and Q3: on a format-3 Reader, a received 148 branch attached at k=2 below the
// canonical tip H=5 with greater chainwork is selected; the walk tip height is H; the 148 limit is requested.
func TestReplayQualifier148Select(t *testing.T) {
	s := q148Slow(t, 5)
	w := newQ148World(t, s, 5, nil)
	b := s.clone(2)
	b.extend(t, 5, 3*TARGET_BLOCK_INTERVAL, false) // heights 3..7
	v := &q148View{inv: q148Complete([][32]byte{b.tip()}, b.headers[3:])}
	out := w.qualify(t, v, q148Active(), 0)
	out.selected(t, w, v, b.tip(), 7, b.work(t, 7), 5, "A1")
	if !slices.Equal(v.limits, []uint64{replayInvLimit148(0)}) || replayInvLimit148(0) == replayInvLimit(0) {
		t.Fatalf("A1: limits %v, want the 148 full-lane limit %d", v.limits, replayInvLimit148(0))
	}
}

// TestReplayQualifier148Tie is A2: three tips of equal chainwork (the canonical tip and two received tips at its
// height); the lexicographically smallest hash is selected.
func TestReplayQualifier148Tie(t *testing.T) {
	s := q148Slow(t, 4)
	w := newQ148World(t, s, 4, nil)
	b1, b2 := s.clone(3), s.clone(3)
	b1.extend(t, 1, 3*TARGET_BLOCK_INTERVAL, false)
	b2.extend(t, 1, 4*TARGET_BLOCK_INTERVAL, false)
	tips := [][32]byte{s.tip(), b1.tip(), b2.tip()}
	smallest := slices.MinFunc(tips, replayHashCompare)
	v := &q148View{inv: q148Complete(tips[1:], [][148]byte{b1.headers[4], b2.headers[4]})}
	w.qualify(t, v, q148Active(), 0).selected(t, w, v, smallest, 4, s.work(t, 4), 4, "A2")
}

// TestReplayQualifier148PrefixTip is A3: canonical height 3 declares a target other than its expected one; the
// published prefix tip is height 2 and a heavier received branch descending from the bad header is ineligible.
func TestReplayQualifier148PrefixTip(t *testing.T) {
	s := q148Slow(t, 2)
	s.push(t, q148Half, s.times[2]+2*TARGET_BLOCK_INTERVAL, true)
	s.extend(t, 2, 2*TARGET_BLOCK_INTERVAL, true) // heights 4..5 keep the parent target
	w := newQ148World(t, s, 5, nil)
	b := s.clone(3)
	b.extend(t, 4, 2*TARGET_BLOCK_INTERVAL, false)
	v := &q148View{inv: q148Complete([][32]byte{b.tip()}, b.headers[4:])}
	w.qualify(t, v, q148Active(), 0).selected(t, w, v, s.hashes[2], 2, s.work(t, 2), 5, "A3")
}

// TestReplayQualifier148ForkF is A4 and A5: with an empty active index the anchor is Published[:148] (A4) or the
// inventory header named GenesisHash (A5), and the received branch from it is selected; the genesis header alone is
// reached but is no positive-height candidate.
func TestReplayQualifier148ForkF(t *testing.T) {
	s := newQ148Seq(t, POW_LIMIT, 1<<30)
	s.extend(t, 3, 2*TARGET_BLOCK_INTERVAL, false)
	w := newQ148World(t, s, -1, nil)
	w.g.Published = append(bytes.Clone(s.headers[0][:]), make([]byte, 118)...)
	v := &q148View{inv: q148Complete([][32]byte{s.tip()}, s.headers[1:])}
	w.qualify(t, v, q148Active(), 0).selected(t, w, v, s.tip(), 3, s.work(t, 3), 0, "A4")
	w.g.Published = nil
	v = &q148View{inv: q148Complete([][32]byte{s.tip()}, s.headers)}
	w.qualify(t, v, q148Active(), 0).selected(t, w, v, s.tip(), 3, s.work(t, 3), 0, "A5")
	v = &q148View{inv: q148Complete([][32]byte{s.hashes[0]}, s.headers[:1])}
	w.qualify(t, v, q148Active(), 0).decided(t, replayEntryRecovery, 0, "A5 genesis alone")
}

// TestReplayQualifier148Retarget is A6: canonical heights 0..100 and received 101..10099 spaced 1 second; the received
// header at 10080 is qualified against the target from the 10080 timestamps of heights 0..10079, canonical ring
// included. Its parent-target twin is ineligible and the canonical tip is selected.
func TestReplayQualifier148Retarget(t *testing.T) {
	s := q148Slow(t, 100)
	w := newQ148World(t, s, 100, nil)
	fast := s.clone(100)
	fast.extend(t, int(WINDOW_SIZE)+19-100, 1, false)
	quarter := [32]byte(new(big.Int).Rsh(new(big.Int).SetBytes(POW_LIMIT[:]), 2).FillBytes(make([]byte, 32)))
	if fast.targets[WINDOW_SIZE] != quarter || fast.targets[WINDOW_SIZE-1] != POW_LIMIT {
		t.Fatalf("schedule: boundary target %x", fast.targets[WINDOW_SIZE])
	}
	v := &q148View{inv: q148Complete([][32]byte{fast.tip()}, fast.headers[101:])}
	w.qualify(t, v, q148Active(), 0).selected(t, w, v, fast.tip(), uint64(len(fast.hashes)-1), fast.work(t, len(fast.hashes)-1), 100, "A6 boundary")
	kept := fast.clone(int(WINDOW_SIZE) - 1)
	kept.extend(t, 20, 1, true)
	v = &q148View{inv: q148Complete([][32]byte{kept.tip()}, kept.headers[101:])}
	w.qualify(t, v, q148Active(), 0).selected(t, w, v, s.tip(), 100, s.work(t, 100), 100, "A6 boundary keeps parent target")
}

// TestReplayQualifier148MTP is A6's timestamp floor: at heights 1, 11 and 12 the MTP is the median of the min(h,11)
// newest ancestors; a header at the MTP is ineligible and one second above it is selected.
func TestReplayQualifier148MTP(t *testing.T) {
	s := newQ148Seq(t, POW_LIMIT, 1<<30)
	s.extend(t, 11, 10, false)
	w := newQ148World(t, s, 0, nil)
	for _, h := range []int{1, 11, 12} {
		k := min(h, 11)
		window := slices.Clone(s.times[h-k : h])
		slices.Sort(window)
		mtp := window[k/2]
		for _, ts := range []uint64{mtp, mtp + 1} {
			b := s.clone(h - 1)
			b.push(t, POW_LIMIT, ts, true)
			v := &q148View{inv: q148Complete([][32]byte{b.tip()}, b.headers[1:])}
			out := w.qualify(t, v, q148Active(), 0)
			if ts == mtp {
				out.decided(t, replayEntryRecovery, 0, "A6 at MTP")
				continue
			}
			out.selected(t, w, v, b.tip(), uint64(h), b.work(t, h), 0, "A6 above MTP")
		}
	}
}

// TestReplayQualifier148InventoryRefusals is R1 and Q5's limit: each refused 148 inventory decides its result before
// the walk (the canonical index has a height gap the walk would report) and before ProtectV1; at a lane whose 148
// limit an inventory meets exactly it is accepted, and one lane byte less refuses it.
func TestReplayQualifier148InventoryRefusals(t *testing.T) {
	s := q148Slow(t, 2)
	gap := newQ148World(t, s, 2, func(h int, rows []mdbx.Mutation) []mdbx.Mutation {
		if h == 1 {
			return rows[:1]
		}
		return rows
	})
	for _, c := range []struct {
		inv    HeaderCandidateInventory148V1
		result string
	}{
		{HeaderCandidateInventory148V1{Status: HeaderCandidateIncompleteV1}, replayEntryRecovery},
		{HeaderCandidateInventory148V1{Status: HeaderCandidateCapacityRefusedV1}, selectedSideCapacity},
		{HeaderCandidateInventory148V1{Status: HeaderCandidateCompleteV1, Tips: [][32]byte{{1}}, Bytes: 31}, selectedSideInvariant},
		{HeaderCandidateInventory148V1{Status: HeaderCandidateCompleteV1, Headers: s.headers[1:2], Bytes: 116}, selectedSideInvariant},
	} {
		v := &q148View{inv: c.inv}
		gap.qualify(t, v, q148Active(), 0).decided(t, c.result, 0, "R1 "+c.result)
	}
	w := newQ148World(t, s, 2, nil)
	b := s.clone(1)
	b.extend(t, 2, 3*TARGET_BLOCK_INTERVAL, false)
	lane := replayRecoveryMin148Bytes
	for (replayInvLimit148(lane) < 32+148*2 || (replayInvLimit148(lane)-148*2)%32 != 0) || replayInvLimit148(lane-1) == replayInvLimit148(lane) {
		lane++
	}
	inv := q148Complete(slices.Repeat([][32]byte{b.tip()}, int((replayInvLimit148(lane)-148*2)/32)), b.headers[2:])
	if inv.Bytes != replayInvLimit148(lane) {
		t.Fatalf("fixture: Bytes %d, limit %d", inv.Bytes, replayInvLimit148(lane))
	}
	v := &q148View{inv: inv}
	w.qualify(t, v, q148Active(), lane).selected(t, w, v, b.tip(), 3, b.work(t, 3), 2, "R1 exact limit")
	v = &q148View{inv: inv}
	w.qualify(t, v, q148Active(), lane-1).decided(t, selectedSideInvariant, 0, "R1 one byte over")
}

// TestReplayQualifier148View is Q7 and R2: an owner view without the 148 interface (or none) is the absent view; a
// typed-nil 148 provider is returned as itself.
func TestReplayQualifier148View(t *testing.T) {
	s := q148Slow(t, 1)
	w := newQ148World(t, s, 1, nil)
	legacy := &replayView{inv: replayComplete(nil, nil)}
	w.qualify(t, legacy, q148Active(), 0).decided(t, replayEntryRecovery, 0, "R2 116-only view")
	if legacy.calls != 0 || len(legacy.versions) != 0 {
		t.Fatalf("R2: 116 view called: inventory %d protect %d", legacy.calls, len(legacy.versions))
	}
	w.qualify(t, nil, q148Active(), 0).decided(t, replayEntryRecovery, 0, "R2 nil view")
	var typed *q148View
	if got := NewReplayEntryOwnerV1(typed, w.g).view148(); got == nil || got.(*q148View) != nil {
		t.Fatalf("Q7: typed-nil provider not returned as itself: %#v", got)
	}
	v := &q148View{}
	if got := NewReplayEntryOwnerV1(v, w.g).view148(); got != HeaderCandidateView148V1(v) {
		t.Fatal("Q7: 148 view not returned")
	}
}

// TestReplayQualifier148CanonicalDefects is R3: each format-3 canonical-index defect returns the baseline
// selected-side defect, the first failing check winning; no ProtectV1.
func TestReplayQualifier148CanonicalDefects(t *testing.T) {
	s := q148Slow(t, 2)
	other := newQ148Seq(t, POW_LIMIT, 1<<30+1) // a different genesis
	// side is a height-2 header whose PrevBlockHash skips height 1.
	side := q148Header(t, s.hashes[0], s.targets[2], s.times[2], q148Any)
	sideHash := q148Hash(side[:])
	key := func(h uint64) []byte { k, _ := mdbx.HeightKey(1, h); return k }
	for _, c := range []struct {
		label, message string
		edit           func(h int, rows []mdbx.Mutation) []mdbx.Mutation
	}{
		{"gap", "replay canonical index height gap", func(h int, rows []mdbx.Mutation) []mdbx.Mutation {
			if h == 1 {
				return rows[:1]
			}
			return rows
		}},
		{"gap and work", "replay canonical index height gap", func(h int, rows []mdbx.Mutation) []mdbx.Mutation {
			if h == 1 {
				return rows[:1]
			}
			if h == 2 {
				rows[1] = btMutation(2, key(2), mdbx.ChainValue(s.hashes[2], s.hashes[1], [40]byte{}))
			}
			return rows
		}},
		{"work outside domain", "replay canonical index work outside domain", func(h int, rows []mdbx.Mutation) []mdbx.Mutation {
			if h == 1 {
				rows[1] = btMutation(2, key(1), mdbx.ChainValue(s.hashes[1], s.hashes[0], [40]byte{}))
			}
			return rows
		}},
		{"header absent", "replay canonical header absent", func(h int, rows []mdbx.Mutation) []mdbx.Mutation {
			if h == 2 {
				return rows[1:]
			}
			return rows
		}},
		{"stored parent differs from PrevBlockHash", "replay canonical header linkage mismatch", func(h int, rows []mdbx.Mutation) []mdbx.Mutation {
			if h == 2 {
				rows[1] = btMutation(2, key(2), mdbx.ChainValue(s.hashes[2], s.hashes[0], s.work(t, 2)))
			}
			return rows
		}},
		{"stored parent equals PrevBlockHash, differs from the previous entry", "replay canonical header linkage mismatch", func(h int, rows []mdbx.Mutation) []mdbx.Mutation {
			if h == 2 {
				return []mdbx.Mutation{btMutation(3, bytes.Clone(sideHash[:]), bytes.Clone(side[:])), btMutation(2, key(2), mdbx.ChainValue(sideHash, s.hashes[0], s.work(t, 2))), q148Owner(sideHash, 2)}
			}
			return rows
		}},
		{"genesis", "replay canonical genesis mismatch", func(h int, rows []mdbx.Mutation) []mdbx.Mutation {
			if h == 0 {
				return []mdbx.Mutation{btMutation(3, bytes.Clone(other.hashes[0][:]), bytes.Clone(other.headers[0][:])), btMutation(2, key(0), mdbx.ChainValue(other.hashes[0], [32]byte{}, other.work(t, 0))), q148Owner(other.hashes[0], 0)}
			}
			return nil
		}},
		{"chainwork", "replay canonical chainwork mismatch", func(h int, rows []mdbx.Mutation) []mdbx.Mutation {
			if h == 2 {
				rows[1] = btMutation(2, key(2), mdbx.ChainValue(s.hashes[2], s.hashes[1], s.work(t, 1)))
			}
			return rows
		}},
	} {
		w := newQ148World(t, s, 2, c.edit)
		v := &q148View{inv: q148Complete(nil, nil)}
		out := w.qualify(t, v, q148Active(), 0)
		q148Defect(t, out.err, c.message, "R3 "+c.label)
		if out.target != (mdbx.RecoveryTargetV1{}) || len(v.versions) != 0 {
			t.Fatalf("R3 %s: target %+v ProtectV1 %v", c.label, out.target, v.versions)
		}
	}
}

// TestReplayQualifier148ReceivedIneligible is R4 and R5: over a canonical genesis-only index (target q148Half) every
// received branch that fails its expected target, its 148 PoW, the MTP floor or the timestamp ceiling, is excluded,
// descends from such a header, is never reached, or is a listed tip with no header decides replayEntryRecovery.
func TestReplayQualifier148ReceivedIneligible(t *testing.T) {
	s := newQ148Seq(t, q148Half, 1<<30)
	w := newQ148World(t, s, 0, nil)
	t0 := s.times[0]
	branch := func(target [32]byte, ts uint64, meets bool) *q148Seq {
		b := s.clone(0)
		b.push(t, target, ts, meets)
		b.extend(t, 1, 10, false)
		return b
	}
	excludedBranch := branch(q148Half, t0+10, true)
	orphan := q148Header(t, [32]byte{9}, q148Half, t0+10, q148Any)
	for _, c := range []struct {
		label   string
		inv     HeaderCandidateInventory148V1
		exclude *[32]byte
	}{
		{"target", q148Complete([][32]byte{branch(POW_LIMIT, t0+10, true).tip()}, branch(POW_LIMIT, t0+10, true).headers[1:]), nil},
		{"pow", q148Complete([][32]byte{branch(q148Half, t0+10, false).tip()}, branch(q148Half, t0+10, false).headers[1:]), nil},
		{"mtp floor", q148Complete([][32]byte{branch(q148Half, t0, true).tip()}, branch(q148Half, t0, true).headers[1:]), nil},
		{"ceiling", q148Complete([][32]byte{branch(q148Half, t0+MAX_FUTURE_DRIFT+1, true).tip()}, branch(q148Half, t0+MAX_FUTURE_DRIFT+1, true).headers[1:]), nil},
		{"excluded descendant", q148Complete([][32]byte{excludedBranch.tip()}, excludedBranch.headers[1:]), &excludedBranch.hashes[1]},
		{"never reached", q148Complete([][32]byte{q148Hash(orphan[:])}, [][148]byte{orphan}), nil},
		{"tip without header", q148Complete([][32]byte{{7}}, nil), nil},
	} {
		a := q148Active()
		if c.exclude != nil {
			a.ExcludedInvalidBranch = &mdbx.InvalidBranchV1{FirstInvalidBlockHash: *c.exclude}
		}
		v := &q148View{inv: c.inv}
		w.qualify(t, v, a, 0).decided(t, replayEntryRecovery, 0, "R4/R5 "+c.label)
	}
	ok := branch(q148Half, t0+10, true)
	v := &q148View{inv: q148Complete([][32]byte{ok.tip()}, ok.headers[1:])}
	w.qualify(t, v, q148Active(), 0).selected(t, w, v, ok.tip(), 2, ok.work(t, 2), 0, "R4 control")
}

// TestReplayQualifier148AnchorIneligible is R6: a Fork F anchor that fails its 148 PoW, carries a zero target, or is
// excluded leaves no eligible descendant, so Q5 decides replayEntryRecovery.
func TestReplayQualifier148AnchorIneligible(t *testing.T) {
	for _, c := range []struct {
		label   string
		target  [32]byte
		meets   bool
		exclude bool
	}{{"pow", q148Half, false, false}, {"zero target", [32]byte{}, true, false}, {"excluded", POW_LIMIT, true, true}, {"control", POW_LIMIT, true, false}} {
		g := q148Header(t, [32]byte{}, c.target, 1<<30, func(raw []byte) bool { return c.target == [32]byte{} || q148Meets(raw, c.target) == c.meets })
		s := &q148Seq{headers: [][148]byte{g}, hashes: [][32]byte{q148Hash(g[:])}, times: []uint64{1 << 30}, targets: [][32]byte{c.target}}
		child := c.target
		if child == ([32]byte{}) {
			child = POW_LIMIT // the zero-target anchor's child cannot meet its parent target; it declares POW_LIMIT
		}
		s.push(t, child, 1<<30+10, true)
		w := newQ148World(t, s, -1, nil)
		w.g.Published = append(bytes.Clone(g[:]), make([]byte, 118)...)
		a := q148Active()
		if c.exclude {
			a.ExcludedInvalidBranch = &mdbx.InvalidBranchV1{FirstInvalidBlockHash: s.hashes[0]}
		}
		v := &q148View{inv: q148Complete([][32]byte{s.tip()}, s.headers[1:])}
		out := w.qualify(t, v, a, 0)
		if c.label == "control" {
			out.selected(t, w, v, s.tip(), 1, s.work(t, 1), 0, "R6 control")
			continue
		}
		out.decided(t, replayEntryRecovery, 0, "R6 "+c.label)
		if c.exclude {
			continue
		}
		q := q148Qualifier(w.g, nil) // the anchor's own ineligibility, apart from the child's target check
		q.anchor()
		if q.badFrom != 0 || q.work.Cmp(big.NewInt(1)) != 0 || q.target != c.target {
			t.Fatalf("R6 %s anchor: badFrom %d work %v target %x, want 0, 1, %x", c.label, q.badFrom, &q.work, q.target, c.target)
		}
	}
}

// TestReplayQualifier148Protect is R7: a nil release decides selectedSideInvariant with no stored release; a stale
// version decides replayEntryStale after storing the release, which the caller runs once.
func TestReplayQualifier148Protect(t *testing.T) {
	s := q148Slow(t, 2)
	w := newQ148World(t, s, 2, nil)
	v := &q148View{inv: q148Complete(nil, nil), nilRelease: true}
	out := w.qualify(t, v, q148Active(), 0)
	out.decided(t, selectedSideInvariant, 1, "R7 nil release")
	v = &q148View{inv: q148Complete(nil, nil), stale: true}
	out = w.qualify(t, v, q148Active(), 0)
	out.decided(t, replayEntryStale, 1, "R7 stale")
	if v.releases != 1 || out.call.release != nil || !slices.Equal(v.versions, []uint64{9}) {
		t.Fatalf("R7 stale: releases %d versions %v", v.releases, v.versions)
	}
}

// q148TargetRows is the generation-2 target index of heights 0..n of s with each header row; edit may change a height.
func q148TargetRows(t *testing.T, s *q148Seq, n int, edit func(h int, rows []mdbx.Mutation) []mdbx.Mutation) []mdbx.Mutation {
	t.Helper()
	var rows []mdbx.Mutation
	for h := 0; h <= n; h++ {
		parent := [32]byte{}
		if h > 0 {
			parent = s.hashes[h-1]
		}
		key, _ := mdbx.HeightKey(2, uint64(h))
		row := []mdbx.Mutation{btMutation(3, bytes.Clone(s.hashes[h][:]), bytes.Clone(s.headers[h][:])), btMutation(2, key, mdbx.ChainValue(s.hashes[h], parent, s.work(t, h))), q148Owner2(s.hashes[h], h)}
		if edit != nil {
			row = edit(h, row)
		}
		rows = append(rows, row...)
	}
	return rows
}

// q148Owner2 is the canonical-owner row paired with a generation-2 index row.
func q148Owner2(hash [32]byte, h int) mdbx.Mutation {
	return btMutation(7, logicalMDBXMust(mdbx.CanonicalOwnerKey(2, hash)), mdbx.CanonicalOwnerValue(uint64(h)))
}

// q148Replay is the REPLAY authority with the cursor APPLIED at the target tip c of s in generation 2.
func q148Replay(w *q148World, s *q148Seq, c int, t *testing.T) mdbx.StorageAuthorityV1 {
	a := q148Active()
	target := mdbx.RecoveryTargetV1{ChainID: w.g.ChainID, GenesisHash: w.g.GenesisHash, TipHash: s.hashes[c], TipHeight: uint64(c), CumulativeChainwork: s.work(t, c)}
	a.Phase, a.Replay = mdbx.StoragePhaseReplayV1, &mdbx.ReplayV1{TargetGenerationID: 2, Target: target, Cursor: mdbx.ReplayCursorV1{Kind: mdbx.ReplayCursorAppliedV1, Height: uint64(c), BlockHash: s.hashes[c]}}
	return a
}

// recompute runs Q6 under one Reader; reader reports whether the report carries that Reader.
func (w *q148World) recompute(t *testing.T, view HeaderCandidateViewV1, a mdbx.StorageAuthorityV1, limit uint64) (out ReplayRecomputationV1, reader bool, err error) {
	t.Helper()
	if verr := w.s.View(func(r *mdbx.Reader) error {
		out, err = NewReplayEntryOwnerV1(view, w.g).recompute148(r, a, limit)
		reader = out.reader == r
		return nil
	}); verr != nil {
		t.Fatalf("view: %v", verr)
	}
	return out, reader, err
}

// q148Recomputation builds the active index 0..2 of a slow sequence and a target index forked at 2 with tip T at
// height 4; active extends the active index beyond 2 (unlisted, so it is only the published comparand).
func q148Recomputation(t *testing.T, active int) (*q148World, *q148Seq, *q148Seq) {
	s := q148Slow(t, active)
	w := newQ148World(t, s, active, nil)
	tg := s.clone(2)
	tg.extend(t, 2, 3*TARGET_BLOCK_INTERVAL, false)
	w.pair(t, q148TargetRows(t, tg, 4, func(h int, rows []mdbx.Mutation) []mdbx.Mutation {
		if h <= min(active, 2) {
			return rows[1:] // the header row is already stored by the active index
		}
		return rows
	})...)
	return w, s, tg
}

// TestReplayQualifier148Recompute is A7: Q6 classifies the fresh 148 best tip against T and the published comparand
// and calls ProtectV1 once; Release, reader, authority and activeTip are carried in every class.
func TestReplayQualifier148Recompute(t *testing.T) {
	w, s, tg := q148Recomputation(t, 2)
	child := tg.clone(4)
	child.extend(t, 1, 3*TARGET_BLOCK_INTERVAL, false)
	heavy := s.clone(2)
	heavy.extend(t, 3, 4*TARGET_BLOCK_INTERVAL, false) // not T's headers (those are spaced 3 intervals)
	wd, _, tgd := q148Recomputation(t, 5)
	childD := tgd.clone(4)
	childD.extend(t, 1, 3*TARGET_BLOCK_INTERVAL, false)
	for _, c := range []struct {
		label  string
		w      *q148World
		tg     *q148Seq
		view   *q148View
		report ReplayRecomputationReportV1
		result string
		tip    uint64
	}{
		{"(a) T", w, tg, &q148View{inv: q148Complete(nil, nil)}, ReplayRecomputationActivationEligibleV1, "", 2},
		{"(b) descendant", w, tg, &q148View{inv: q148Complete([][32]byte{child.tip()}, child.headers[5:])}, ReplayRecomputationActivationEligibleV1, "", 2},
		{"(c) other branch", w, tg, &q148View{inv: q148Complete([][32]byte{heavy.tip()}, heavy.headers[3:])}, ReplayRecomputationPlanChangeV1, "", 2},
		{"(d) comparand outranks T", wd, tgd, &q148View{inv: q148Complete([][32]byte{childD.tip()}, childD.headers[5:])}, ReplayRecomputationPlanChangeV1, "", 5},
		{"STALE", w, tg, &q148View{inv: q148Complete(nil, nil), stale: true}, ReplayRecomputationStaleV1, replayEntryStale, 2},
	} {
		a := q148Replay(c.w, c.tg, 4, t)
		out, reader, err := c.w.recompute(t, c.view, a, mdbx.MaxOperationDataBytes)
		if err != nil || out.Report != c.report || out.Result != c.result || out.Release == nil || !reader || out.activeTip != c.tip || out.authority.Replay != a.Replay {
			t.Fatalf("A7 %s: %+v reader %v %v", c.label, out, reader, err)
		}
		out.Release()
		if !slices.Equal(c.view.versions, []uint64{9}) || c.view.releases != 1 || !slices.Equal(c.view.limits, []uint64{replayInvLimit148(mdbx.MaxOperationDataBytes)}) {
			t.Fatalf("A7 %s: ProtectV1 %v releases %d limits %v", c.label, c.view.versions, c.view.releases, c.view.limits)
		}
	}
}

// TestReplayQualifier148RecomputeRefusals is R8 with R1 and R2 for Q6: each refusal or defect as the baseline target
// stream classifies it, with no ProtectV1; the minimum-share refusal makes no inventory call.
func TestReplayQualifier148RecomputeRefusals(t *testing.T) {
	w, _, tg := q148Recomputation(t, 2)
	ok := func() *q148View { return &q148View{inv: q148Complete(nil, nil)} }
	other := q148Replay(w, tg, 4, t)
	other.Replay.Target.ChainID[0] ^= 1
	tipless := q148Replay(w, tg, 4, t)
	tipless.Replay.Target.TipHash[0] ^= 1
	off := q148Replay(w, tg, 4, t)
	off.Replay.Cursor.Height = 3
	for _, c := range []struct {
		label, result, defect string
		view                  HeaderCandidateViewV1
		a                     mdbx.StorageAuthorityV1
		limit                 uint64
		report                ReplayRecomputationReportV1
	}{
		{"domain", "", "", ok(), off, mdbx.MaxOperationDataBytes, ReplayRecomputationNotApplicableV1},
		{"identity", "", "replay target identity differs from the context", ok(), other, mdbx.MaxOperationDataBytes, 0},
		{"below M148", selectedSideCapacity, "", ok(), q148Replay(w, tg, 4, t), replayRecoveryMin148Bytes - 1, ReplayRecomputationRefusedV1},
		{"incomplete", replayEntryRecovery, "", &q148View{inv: HeaderCandidateInventory148V1{Status: HeaderCandidateIncompleteV1}}, q148Replay(w, tg, 4, t), mdbx.MaxOperationDataBytes, ReplayRecomputationRefusedV1},
		{"116-only view", replayEntryRecovery, "", &replayView{inv: replayComplete(nil, nil)}, q148Replay(w, tg, 4, t), mdbx.MaxOperationDataBytes, ReplayRecomputationRefusedV1},
		{"tip identity", "", "replay target index identity mismatch", ok(), tipless, mdbx.MaxOperationDataBytes, 0},
	} {
		out, _, err := w.recompute(t, c.view, c.a, c.limit)
		if c.defect != "" {
			q148Defect(t, err, c.defect, "R8 "+c.label)
		} else if err != nil || out.Report != c.report || out.Result != c.result {
			t.Fatalf("R8 %s: %+v %v", c.label, out, err)
		}
		if v, ok := c.view.(*q148View); ok && (len(v.versions) != 0 || c.label == "below M148" && len(v.limits) != 0) {
			t.Fatalf("R8 %s: ProtectV1 %v limits %v", c.label, v.versions, v.limits)
		}
	}
	bad := &q148View{inv: HeaderCandidateInventory148V1{Status: HeaderCandidateCompleteV1, Tips: [][32]byte{{1}}, Bytes: 31}}
	_, _, err := w.recompute(t, bad, q148Replay(w, tg, 4, t), mdbx.MaxOperationDataBytes)
	var failure *selectedSideFailure
	if !errors.As(err, &failure) || failure.result != selectedSideInvariant || len(bad.versions) != 0 {
		t.Fatalf("R1 invariant: %v", err)
	}
	out, _, err := w.recompute(t, ok(), q148Replay(w, tg, 4, t), replayRecoveryMin148Bytes)
	if err != nil || out.Report != ReplayRecomputationActivationEligibleV1 {
		t.Fatalf("R8 at M148: %+v %v", out, err)
	}
}

// TestReplayQualifier148RecomputeTargetRows is R8 over target-index rows: a row above the cursor, a wrong genesis
// identity and an absent header row are selected-side defects; a height gap is TARGET_LOCAL with its Evidence row.
func TestReplayQualifier148RecomputeTargetRows(t *testing.T) {
	other := newQ148Seq(t, POW_LIMIT, 1<<30+1)
	for _, c := range []struct {
		label, defect string
		local         uint64
		edit          func(s, tg *q148Seq) []mdbx.Mutation
	}{
		{"above cursor", "replay target index row above the cursor", 0, func(s, tg *q148Seq) []mdbx.Mutation {
			tg.extend(t, 1, 3*TARGET_BLOCK_INTERVAL, false)
			return q148TargetRows(t, tg, 5, nil)[3*5:]
		}},
		{"genesis", "replay target index identity mismatch", 0, func(s, tg *q148Seq) []mdbx.Mutation {
			key, _ := mdbx.HeightKey(2, 0)
			return []mdbx.Mutation{btMutation(2, key, mdbx.ChainValue(other.hashes[0], [32]byte{}, other.work(t, 0))), q148Owner2(other.hashes[0], 0)}
		}},
		{"header absent", "replay target header absent or misnamed", 0, nil},
		{"gap", "", 3, nil},
	} {
		s := q148Slow(t, 2)
		w := newQ148World(t, s, 2, nil)
		tg := s.clone(2)
		tg.extend(t, 2, 3*TARGET_BLOCK_INTERVAL, false)
		rows := q148TargetRows(t, tg, 4, func(h int, rows []mdbx.Mutation) []mdbx.Mutation {
			switch {
			case c.label == "gap" && h == 3, c.label == "genesis" && h == 0:
				return nil
			case h <= 2, c.label == "header absent" && h == 3:
				return rows[1:]
			}
			return rows
		})
		if c.edit != nil {
			rows = append(rows, c.edit(s, tg)...)
		}
		w.pair(t, rows...)
		v := &q148View{inv: q148Complete(nil, nil)}
		out, _, err := w.recompute(t, v, q148Replay(w, tg, 4, t), mdbx.MaxOperationDataBytes)
		key, _ := mdbx.HeightKey(2, c.local)
		switch {
		case c.defect != "":
			q148Defect(t, err, c.defect, "R8 "+c.label)
		case err != nil || out.Report != ReplayRecomputationTargetLocalV1 || out.Evidence.DBI != mdbx.SchemaV2DBIs()[2] || !bytes.Equal(out.Evidence.Key, key):
			t.Fatalf("R8 %s: %+v %v", c.label, out, err)
		}
		if len(v.versions) != 0 {
			t.Fatalf("R8 %s: ProtectV1 %v", c.label, v.versions)
		}
	}
}
