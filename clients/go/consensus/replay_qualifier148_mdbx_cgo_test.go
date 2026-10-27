//go:build cgo && (darwin || linux) && (amd64 || arm64)

package consensus

import (
	"bytes"
	"crypto/sha3"
	"encoding/binary"
	"errors"
	"math"
	"testing"
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
			g.Published = append(gh[:], make([]byte, 118)...) // 266 bytes, as the context check admits
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
