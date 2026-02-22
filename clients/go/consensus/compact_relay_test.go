package consensus

import (
	"encoding/hex"
	"testing"
)

func TestSiphash24_ReferenceVectors(t *testing.T) {
	k0 := uint64(0x0706050403020100)
	k1 := uint64(0x0f0e0d0c0b0a0908)

	if got := siphash24([]byte{}, k0, k1); got != 0x726fdb47dd0e0e31 {
		t.Fatalf("len0 mismatch: got=%016x", got)
	}

	msg := make([]byte, 15)
	for i := 0; i < len(msg); i++ {
		msg[i] = byte(i)
	}
	if got := siphash24(msg, k0, k1); got != 0xa129ca6149be45e5 {
		t.Fatalf("len15 mismatch: got=%016x", got)
	}
}

func TestCompactShortID_Vector(t *testing.T) {
	wtxid, _ := hex.DecodeString("26ce78c5671f12911e3610831095305ed00a112b9ba59cddb87c694bb8b4e695")
	var id [32]byte
	copy(id[:], wtxid)

	got := CompactShortID(id, 0x0706050403020100, 0x0f0e0d0c0b0a0908)
	if hex.EncodeToString(got[:]) != "b50c6fb86b2f" {
		t.Fatalf("shortid mismatch: got=%s", hex.EncodeToString(got[:]))
	}
}
