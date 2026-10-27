//go:build rubin_mdbx_fixture && cgo && (darwin || linux) && (amd64 || arm64)

package consensus

import (
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/mdbx"
)

// TestReplayQualifier148RecomputeMisnamedHeader is R8: a target header row of exactly 148 bytes that parses but does
// not hash to its key at 148 is the selected-side defect, with no ProtectV1. The row differs from its named header
// only in utxo_root, so every later check would pass on it; ordinary writes refuse such a row, so the fixture seeds it.
func TestReplayQualifier148RecomputeMisnamedHeader(t *testing.T) {
	w, _, tg := q148Recomputation(t, 2)
	twin := tg.headers[3]
	twin[139] ^= 1
	if q148Hash(twin[:]) == tg.hashes[3] {
		t.Fatal("fixture: utxo_root mutation did not change the hash")
	}
	if err := mdbx.FixtureSeedRawRow(w.s, 3, tg.hashes[3][:], twin[:]); err != nil {
		t.Fatalf("seed rank 3: %v", err)
	}
	v := &q148View{inv: q148Complete(nil, nil)}
	_, _, err := w.recompute(t, v, q148Replay(w, tg, 4, t), mdbx.MaxOperationDataBytes)
	q148Defect(t, err, "replay target header absent or misnamed", "R8 misnamed")
	if len(v.versions) != 0 {
		t.Fatalf("R8 misnamed: ProtectV1 %v", v.versions)
	}
}
