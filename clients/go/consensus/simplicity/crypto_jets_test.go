package simplicity

import (
	"bytes"
	"crypto/sha3"
	"encoding/json"
	"errors"
	"io"
	"os"
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

type sharedCryptoJetCorpus struct {
	ContractVersion int                   `json:"contract_version"`
	FixtureKind     string                `json:"fixture_kind"`
	Description     string                `json:"description"`
	Cases           []sharedCryptoJetCase `json:"cases"`
}

type sharedCryptoJetCase struct {
	ID                   string `json:"id"`
	Jet                  string `json:"jet"`
	MessageHex           string `json:"message_hex"`
	ExpectedDigestHex    string `json:"expected_digest_hex"`
	DigestHex            string `json:"digest_hex"`
	PubkeyLen            int    `json:"pubkey_len"`
	SignatureLen         int    `json:"signature_len"`
	VerifierResult       bool   `json:"verifier_result"`
	ExpectedVerified     bool   `json:"expected_verified"`
	ExpectedCost         uint64 `json:"expected_cost"`
	ExpectVerifierCalled bool   `json:"expect_verifier_called"`
	ExpectedError        string `json:"expected_error"`
}

func TestSharedCryptoJetsCorpus(t *testing.T) {
	var corpus sharedCryptoJetCorpus
	raw, err := os.ReadFile(repoPath(t, "conformance", "fixtures", "protocol", "simplicity_crypto_jets_corpus_v1.json"))
	if err != nil {
		t.Fatalf("read shared crypto jets corpus: %v", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&corpus); err != nil {
		t.Fatalf("parse shared crypto jets corpus: %v", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		t.Fatalf("shared crypto jets corpus has trailing data: %v", err)
	}
	if corpus.ContractVersion != 1 || corpus.FixtureKind != "simplicity_crypto_jets_corpus_v1" || len(corpus.Cases) == 0 {
		t.Fatalf("bad shared crypto jets corpus header: version=%d kind=%q cases=%d", corpus.ContractVersion, corpus.FixtureKind, len(corpus.Cases))
	}
	for _, tc := range corpus.Cases {
		t.Run(tc.ID, func(t *testing.T) {
			switch tc.Jet {
			case "sha3_256":
				got := EvaluateSHA3256Jet(hx(tc.MessageHex))
				if got.Digest != hex32(tc.ExpectedDigestHex) || got.Cost != tc.ExpectedCost {
					t.Fatalf("sha3_256=%x/%d want %s/%d", got.Digest, got.Cost, tc.ExpectedDigestHex, tc.ExpectedCost)
				}
			case "mldsa87_verify":
				digest := hex32(tc.DigestHex)
				called := false
				got, err := EvaluateMLDSA87VerifyJet(bytes.Repeat([]byte{0x11}, tc.PubkeyLen), bytes.Repeat([]byte{0x22}, tc.SignatureLen), digest, func(pubkey []byte, signature []byte, gotDigest [32]byte) (bool, error) {
					called = true
					if len(pubkey) != tc.PubkeyLen || len(signature) != tc.SignatureLen || gotDigest != digest {
						t.Fatalf("mldsa87_verify verifier input lengths/digest mismatch")
					}
					if tc.ExpectedError != "" {
						return false, &Error{Code: ErrorCode(tc.ExpectedError)}
					}
					return tc.VerifierResult, nil
				})
				if tc.ExpectedError != "" {
					assertErrorCode(t, err, ErrorCode(tc.ExpectedError))
				} else if err != nil {
					t.Fatalf("mldsa87_verify: %v", err)
				}
				if got.Verified != tc.ExpectedVerified || got.Cost != tc.ExpectedCost || called != tc.ExpectVerifierCalled {
					t.Fatalf("mldsa87_verify=%+v called=%v want verified=%v cost=%d called=%v", got, called, tc.ExpectedVerified, tc.ExpectedCost, tc.ExpectVerifierCalled)
				}
			default:
				t.Fatalf("unknown jet %q", tc.Jet)
			}
		})
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
