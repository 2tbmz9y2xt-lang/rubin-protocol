package simplicity

import (
	"bytes"
	"testing"
)

func TestU64DataJets(t *testing.T) {
	for _, tc := range []struct {
		name     string
		got      U64JetResult
		want     uint64
		accepted bool
	}{
		{"add", EvaluateU64CheckedAddJet(2, 3), 5, true},
		{"add-overflow", EvaluateU64CheckedAddJet(^uint64(0), 1), 0, false},
		{"sub", EvaluateU64CheckedSubJet(5, 3), 2, true},
		{"sub-underflow", EvaluateU64CheckedSubJet(3, 5), 0, false},
		{"mul", EvaluateU64CheckedMulJet(7, 6), 42, true},
		{"mul-overflow", EvaluateU64CheckedMulJet(1<<63, 2), 0, false},
	} {
		if tc.got.Accepted != tc.accepted || tc.got.Value != tc.want || tc.got.Cost != 1 {
			t.Fatalf("%s = %+v, want accepted=%v value=%d cost=1", tc.name, tc.got, tc.accepted, tc.want)
		}
	}

	assertOrdering(t, "u64-lt", EvaluateU64CmpJet(1, 2), OrderingLT, 1)
	assertOrdering(t, "u64-eq", EvaluateU64CmpJet(2, 2), OrderingEQ, 1)
	assertOrdering(t, "u64-gt", EvaluateU64CmpJet(3, 2), OrderingGT, 1)
}

func TestU128DataJets(t *testing.T) {
	for _, tc := range []struct {
		name     string
		got      U128JetResult
		want     Uint128
		accepted bool
	}{
		{"add-carry", EvaluateU128CheckedAddJet(Uint128{Lo: ^uint64(0)}, Uint128{Lo: 1}), Uint128{Hi: 1}, true},
		{"add-overflow", EvaluateU128CheckedAddJet(Uint128{Hi: ^uint64(0), Lo: ^uint64(0)}, Uint128{Lo: 1}), Uint128{}, false},
		{"sub-borrow", EvaluateU128CheckedSubJet(Uint128{Hi: 1}, Uint128{Lo: 1}), Uint128{Lo: ^uint64(0)}, true},
		{"sub-underflow", EvaluateU128CheckedSubJet(Uint128{}, Uint128{Lo: 1}), Uint128{}, false},
	} {
		if tc.got.Accepted != tc.accepted || tc.got.Value != tc.want || tc.got.Cost != 1 {
			t.Fatalf("%s = %+v, want accepted=%v value=%+v cost=1", tc.name, tc.got, tc.accepted, tc.want)
		}
	}

	assertOrdering(t, "u128-hi-lt", EvaluateU128CmpJet(Uint128{Hi: 1}, Uint128{Hi: 2}), OrderingLT, 1)
	assertOrdering(t, "u128-eq", EvaluateU128CmpJet(Uint128{Hi: 2, Lo: 3}, Uint128{Hi: 2, Lo: 3}), OrderingEQ, 1)
	assertOrdering(t, "u128-lo-gt", EvaluateU128CmpJet(Uint128{Hi: 2, Lo: 4}, Uint128{Hi: 2, Lo: 3}), OrderingGT, 1)
}

func TestBytesDataJets(t *testing.T) {
	if got := EvaluateBytesEqJet(nil, []byte{}); !got.Value || got.Cost != 1 {
		t.Fatalf("bytes_eq empty = %+v, want true cost=1", got)
	}
	if got := EvaluateBytesEqJet(bytes.Repeat([]byte{0x11}, 33), bytes.Repeat([]byte{0x11}, 32)); got.Value || got.Cost != 3 {
		t.Fatalf("bytes_eq 33/32 = %+v, want false cost=3", got)
	}

	assertOrdering(t, "bytes-unsigned", EvaluateBytesCmpJet([]byte{0xff}, []byte{0x01}), OrderingGT, 2)
	assertOrdering(t, "bytes-prefix-shorter", EvaluateBytesCmpJet([]byte("ab"), []byte("abc")), OrderingLT, 2)
	assertOrdering(t, "bytes-prefix-longer", EvaluateBytesCmpJet([]byte("abc"), []byte("ab")), OrderingGT, 2)
	assertOrdering(t, "bytes-eq", EvaluateBytesCmpJet([]byte("abc"), []byte("abc")), OrderingEQ, 2)

	src := []byte("abcdef")
	if got := EvaluateBytesSliceJet(src, 2, 3); !got.Accepted || string(got.Bytes) != "cde" || got.Cost != 2 {
		t.Fatalf("bytes_slice = %+v, want accepted cde cost=2", got)
	} else {
		src[2] = 'X'
		if string(got.Bytes) != "cde" {
			t.Fatalf("bytes_slice returned aliased bytes %q", got.Bytes)
		}
	}
	if got := EvaluateBytesSliceJet(src, uint64(len(src)), 0); !got.Accepted || len(got.Bytes) != 0 || got.Cost != 1 {
		t.Fatalf("bytes_slice empty = %+v, want accepted empty cost=1", got)
	}
	if got := EvaluateBytesSliceJet(src, 5, 2); got.Accepted || got.Cost != 2 {
		t.Fatalf("bytes_slice out of range = %+v, want rejected cost=2", got)
	}
	if got := EvaluateBytesSliceJet(src, ^uint64(0), 1); got.Accepted || got.Cost != 2 {
		t.Fatalf("bytes_slice overflow = %+v, want rejected cost=2", got)
	}
	maxLength := ^uint64(0)
	expectedMaxCost := dataJetFlatCost + maxLength/bytesJetChunkLen
	if maxLength%bytesJetChunkLen != 0 {
		expectedMaxCost++
	}
	if got := EvaluateBytesSliceJet(nil, 0, maxLength); got.Accepted || got.Cost != expectedMaxCost {
		t.Fatalf("bytes_slice max len = %+v, want rejected cost=%d", got, expectedMaxCost)
	}
}

func assertOrdering(t *testing.T, name string, got OrderingJetResult, want Ordering, cost uint64) {
	t.Helper()
	if got.Ordering != want || got.Cost != cost {
		t.Fatalf("%s = %+v, want ordering=%d cost=%d", name, got, want, cost)
	}
}
