package consensus

import (
	"encoding/hex"
	"math/big"
	"testing"
)

func mustHex32(t *testing.T, hex32 string) [32]byte {
	t.Helper()
	b, err := hex.DecodeString(hex32)
	if err != nil || len(b) != 32 {
		t.Fatalf("bad hex32: %v len=%d", err, len(b))
	}
	var out [32]byte
	copy(out[:], b)
	return out
}

func TestWorkFromTarget_Vectors(t *testing.T) {
	ff := mustHex32(t, "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	w, err := WorkFromTarget(ff)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if w.Cmp(big.NewInt(1)) != 0 {
		t.Fatalf("want 1 got %s", w.Text(16))
	}

	half := mustHex32(t, "8000000000000000000000000000000000000000000000000000000000000000")
	w, err = WorkFromTarget(half)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if w.Cmp(big.NewInt(2)) != 0 {
		t.Fatalf("want 2 got %s", w.Text(16))
	}

	one := mustHex32(t, "0000000000000000000000000000000000000000000000000000000000000001")
	w, err = WorkFromTarget(one)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	want := new(big.Int).Lsh(big.NewInt(1), 256)
	if w.Cmp(want) != 0 {
		t.Fatalf("want 2^256 got %s", w.Text(16))
	}
}
