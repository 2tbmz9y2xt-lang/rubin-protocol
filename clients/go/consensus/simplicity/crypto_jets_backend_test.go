//go:build cgo

package simplicity_test

import (
	"crypto/sha3"
	"strings"
	"testing"

	consensus "github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus/simplicity"
)

func TestMLDSA87VerifyJetUsesNativeDigest32BackendAndFlatCost(t *testing.T) {
	kp, err := consensus.NewMLDSA87Keypair()
	if err != nil {
		if strings.Contains(err.Error(), "unsupported") {
			t.Skipf("ML-DSA backend unavailable in this OpenSSL build: %v", err)
		}
		t.Fatalf("NewMLDSA87Keypair: %v", err)
	}
	t.Cleanup(func() { kp.Close() })

	digest := sha3.Sum256([]byte("simplicity mldsa87_verify"))
	signature, err := kp.SignDigest32(digest)
	if err != nil {
		t.Fatalf("SignDigest32: %v", err)
	}

	got, err := simplicity.EvaluateMLDSA87VerifyJet(kp.PubkeyBytes(), signature, digest, consensus.VerifyMLDSA87Digest32)
	if err != nil {
		t.Fatalf("mldsa87_verify valid: %v", err)
	}
	if !got.Verified || got.Cost != 50_000 {
		t.Fatalf("valid mldsa87_verify=%+v want verified flat cost 50000", got)
	}

	digest[0] ^= 0xff
	got, err = simplicity.EvaluateMLDSA87VerifyJet(kp.PubkeyBytes(), signature, digest, consensus.VerifyMLDSA87Digest32)
	if err != nil {
		t.Fatalf("mldsa87_verify wrong digest: %v", err)
	}
	if got.Verified || got.Cost != 50_000 {
		t.Fatalf("wrong-digest mldsa87_verify=%+v want false flat cost 50000", got)
	}
}
