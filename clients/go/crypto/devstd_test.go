package crypto

import (
	"encoding/hex"
	"testing"
)

func TestDevStdSHA3_256_KnownVector(t *testing.T) {
	p := DevStdCryptoProvider{}
	sum, err := p.SHA3_256([]byte("abc"))
	if err != nil {
		t.Fatalf("SHA3_256 returned error: %v", err)
	}
	// SHA3-256("abc")
	const want = "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
	got := hex.EncodeToString(sum[:])
	if got != want {
		t.Fatalf("digest mismatch: got=%s want=%s", got, want)
	}
}

func TestDevStdVerifyAlwaysFalse(t *testing.T) {
	p := DevStdCryptoProvider{}
	var d [32]byte
	if p.VerifyMLDSA87(make([]byte, 2592), make([]byte, 4627), d) {
		t.Fatalf("VerifyMLDSA87 unexpectedly returned true")
	}
	if p.VerifySLHDSASHAKE_256f(make([]byte, 64), make([]byte, 1), d) {
		t.Fatalf("VerifySLHDSASHAKE_256f unexpectedly returned true")
	}
}

