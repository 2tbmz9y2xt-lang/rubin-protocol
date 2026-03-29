package consensus

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestSha3_256_EmptyInput(t *testing.T) {
	got := sha3_256(nil)
	// NIST FIPS 202: SHA3-256("") = a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a
	want, _ := hex.DecodeString("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a")
	if !bytes.Equal(got[:], want) {
		t.Fatalf("sha3_256(nil)=%x, want %x", got, want)
	}
}

func TestSha3_256_EmptySlice(t *testing.T) {
	got := sha3_256([]byte{})
	want := sha3_256(nil)
	if got != want {
		t.Fatalf("sha3_256([]byte{}) != sha3_256(nil)")
	}
}

func TestSha3_256_KnownVector(t *testing.T) {
	// SHA3-256("abc") = 3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532
	got := sha3_256([]byte("abc"))
	want, _ := hex.DecodeString("3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532")
	if !bytes.Equal(got[:], want) {
		t.Fatalf("sha3_256(abc)=%x, want %x", got, want)
	}
}

func TestSha3_256_OutputLength(t *testing.T) {
	got := sha3_256([]byte("test"))
	if len(got) != 32 {
		t.Fatalf("output length=%d, want 32", len(got))
	}
}

func TestSha3_256_Deterministic(t *testing.T) {
	input := []byte("deterministic check")
	a := sha3_256(input)
	b := sha3_256(input)
	if a != b {
		t.Fatalf("sha3_256 not deterministic: %x != %x", a, b)
	}
}

func TestSha3_256_DifferentInputsDifferentOutputs(t *testing.T) {
	a := sha3_256([]byte("input1"))
	b := sha3_256([]byte("input2"))
	if a == b {
		t.Fatalf("different inputs produced same hash")
	}
}

func TestSha3_256_SingleByte(t *testing.T) {
	got := sha3_256([]byte{0x00})
	// Must not be the empty-input hash
	empty := sha3_256(nil)
	if got == empty {
		t.Fatalf("single zero byte produced same hash as empty input")
	}
}

func TestSha3_256_LargeInput(t *testing.T) {
	input := make([]byte, 1<<16) // 64KB
	for i := range input {
		input[i] = byte(i)
	}
	got := sha3_256(input)
	// Just verify it doesn't panic and returns 32 bytes
	if len(got) != 32 {
		t.Fatalf("output length=%d", len(got))
	}
	// Verify determinism on large input
	got2 := sha3_256(input)
	if got != got2 {
		t.Fatal("large input not deterministic")
	}
}
