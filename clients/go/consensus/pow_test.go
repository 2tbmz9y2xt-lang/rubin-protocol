package consensus

import (
	"encoding/hex"
	"math/big"
	"testing"
)

func TestRetargetV1_IdentityAtExpectedWindow(t *testing.T) {
	targetOld := mustBytes32Hex(t, "0000000000000000000000000000000000000000000000000000000000001234")
	tExpected := uint64(TARGET_BLOCK_INTERVAL) * uint64(WINDOW_SIZE)

	got, err := RetargetV1(targetOld, 100, 100+tExpected)
	if err != nil {
		t.Fatalf("RetargetV1 error: %v", err)
	}
	if got != targetOld {
		t.Fatalf("target mismatch: got=%x want=%x", got, targetOld)
	}
}

func TestRetargetV1_LowerClamp(t *testing.T) {
	targetOld := mustBytes32Hex(t, "0000000000000000000000000000000000000000000000000000000000001000") // 4096

	got, err := RetargetV1(targetOld, 200, 200) // T_actual <= 0 => 1
	if err != nil {
		t.Fatalf("RetargetV1 error: %v", err)
	}

	want := mustBytes32Hex(t, "0000000000000000000000000000000000000000000000000000000000000400") // 1024
	if got != want {
		t.Fatalf("target mismatch: got=%x want=%x", got, want)
	}
}

func TestRetargetV1_UpperClamp(t *testing.T) {
	targetOld := mustBytes32Hex(t, "0000000000000000000000000000000000000000000000000000000000001000") // 4096
	tExpected := uint64(TARGET_BLOCK_INTERVAL) * uint64(WINDOW_SIZE)

	got, err := RetargetV1(targetOld, 0, 10*tExpected)
	if err != nil {
		t.Fatalf("RetargetV1 error: %v", err)
	}

	want := mustBytes32Hex(t, "0000000000000000000000000000000000000000000000000000000000004000") // 16384
	if got != want {
		t.Fatalf("target mismatch: got=%x want=%x", got, want)
	}
}

func TestPowCheck_StrictLess(t *testing.T) {
	header := make([]byte, BLOCK_HEADER_BYTES)
	header[0] = 1 // just to avoid all-zero input

	h, err := BlockHash(header)
	if err != nil {
		t.Fatalf("BlockHash error: %v", err)
	}

	// target == hash => invalid (strictly less required)
	if err := PowCheck(header, h); err == nil {
		t.Fatalf("expected pow invalid for target == hash")
	}

	// target = hash + 1 => valid (unless hash is max, which is practically impossible)
	bh := new(big.Int).SetBytes(h[:])
	bh.Add(bh, big.NewInt(1))
	target1, err := bigIntToBytes32(bh)
	if err != nil {
		t.Fatalf("bigIntToBytes32: %v", err)
	}
	if err := PowCheck(header, target1); err != nil {
		t.Fatalf("expected pow valid for target = hash+1, got err=%v", err)
	}
}

func mustBytes32Hex(t *testing.T, hex32 string) [32]byte {
	t.Helper()
	b, err := parseHex32(hex32)
	if err != nil {
		t.Fatalf("bad hex32: %v", err)
	}
	return b
}

func parseHex32(hex32 string) ([32]byte, error) {
	var out [32]byte
	b, err := hex.DecodeString(hex32)
	if err != nil {
		return out, err
	}
	if len(b) != 32 {
		return out, txerr(TX_ERR_PARSE, "bad bytes32 length")
	}
	copy(out[:], b)
	return out, nil
}
