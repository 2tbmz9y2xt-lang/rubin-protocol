package consensus

import (
	"math/big"
	"testing"
)

func TestWorkFromTarget_RejectsInvalidTargets(t *testing.T) {
	_, err := WorkFromTarget([32]byte{})
	if err == nil {
		t.Fatalf("expected error for zero target")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_PARSE {
		t.Fatalf("code=%s, want %s", got, TX_ERR_PARSE)
	}
}

func TestWorkFromTarget_Deterministic(t *testing.T) {
	target := filledHash(0xff)
	w, err := WorkFromTarget(target)
	if err != nil {
		t.Fatalf("WorkFromTarget: %v", err)
	}
	if w.Sign() <= 0 {
		t.Fatalf("expected positive work")
	}

	two256 := new(big.Int).Lsh(big.NewInt(1), 256)
	want := new(big.Int).Div(two256, new(big.Int).SetBytes(target[:]))
	if w.Cmp(want) != 0 {
		t.Fatalf("work mismatch")
	}
}

func TestChainWorkFromTargets_Sums(t *testing.T) {
	t1 := filledHash(0xff)
	t2 := filledHash(0xfe)
	w1, _ := WorkFromTarget(t1)
	w2, _ := WorkFromTarget(t2)

	total, err := ChainWorkFromTargets([][32]byte{t1, t2})
	if err != nil {
		t.Fatalf("ChainWorkFromTargets: %v", err)
	}
	want := new(big.Int).Add(w1, w2)
	if total.Cmp(want) != 0 {
		t.Fatalf("sum mismatch")
	}
}
