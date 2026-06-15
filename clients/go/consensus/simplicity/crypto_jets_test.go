package simplicity

import (
	"bytes"
	"crypto/sha3"
	"errors"
	"testing"
)

func TestSHA3256JetUsesNativeSHA3AndChargesByMessageLen(t *testing.T) {
	for _, msg := range [][]byte{
		nil,
		[]byte("abc"),
		bytes.Repeat([]byte{0xa5}, 65),
	} {
		got := EvaluateSHA3256Jet(msg)
		if got.Digest != sha3.Sum256(msg) {
			t.Fatalf("sha3_256(%x)=%x", msg, got.Digest)
		}
		if got.Cost != sha3256JetBaseCost+uint64(len(msg)) {
			t.Fatalf("sha3_256 cost=%d want %d", got.Cost, sha3256JetBaseCost+uint64(len(msg)))
		}
	}
}

func TestMLDSA87VerifyJetLengthMismatchIsProgramFalse(t *testing.T) {
	digest := sha3.Sum256(nil)
	called := false
	verifier := func([]byte, []byte, [32]byte) (bool, error) {
		called = true
		return true, nil
	}
	tests := []struct {
		name      string
		pubkey    []byte
		signature []byte
	}{
		{
			name:      "short pubkey",
			pubkey:    make([]byte, mldsa87PubkeyBytes-1),
			signature: make([]byte, mldsa87SigBytes),
		},
		{
			name:      "short signature",
			pubkey:    make([]byte, mldsa87PubkeyBytes),
			signature: make([]byte, mldsa87SigBytes-1),
		},
		{
			name:      "sighash byte is not stripped",
			pubkey:    make([]byte, mldsa87PubkeyBytes),
			signature: make([]byte, mldsa87SigBytes+1),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			called = false
			got, err := EvaluateMLDSA87VerifyJet(tt.pubkey, tt.signature, digest, verifier)
			if err != nil {
				t.Fatalf("mldsa87_verify: %v", err)
			}
			if called {
				t.Fatal("mldsa87_verify called verifier for length mismatch")
			}
			if got.Verified || got.Cost != mldsa87VerifyJetCost {
				t.Fatalf("mldsa87_verify=%+v want false flat cost %d", got, mldsa87VerifyJetCost)
			}
		})
	}
}

func TestMLDSA87VerifyJetRequiresVerifierForValidLengths(t *testing.T) {
	got, err := EvaluateMLDSA87VerifyJet(make([]byte, mldsa87PubkeyBytes), make([]byte, mldsa87SigBytes), [32]byte{}, nil)
	assertErrorCode(t, err, ErrJetDisallowed)
	if got.Verified || got.Cost != mldsa87VerifyJetCost {
		t.Fatalf("mldsa87_verify=%+v want false flat cost %d", got, mldsa87VerifyJetCost)
	}
}

func TestMLDSA87VerifyJetPropagatesVerifierError(t *testing.T) {
	sentinel := errors.New("verifier failed")
	got, err := EvaluateMLDSA87VerifyJet(
		make([]byte, mldsa87PubkeyBytes),
		make([]byte, mldsa87SigBytes),
		[32]byte{},
		func([]byte, []byte, [32]byte) (bool, error) {
			return false, sentinel
		},
	)
	if !errors.Is(err, sentinel) {
		t.Fatalf("mldsa87_verify error=%v want %v", err, sentinel)
	}
	if got.Verified || got.Cost != mldsa87VerifyJetCost {
		t.Fatalf("mldsa87_verify=%+v want false flat cost %d", got, mldsa87VerifyJetCost)
	}
}
