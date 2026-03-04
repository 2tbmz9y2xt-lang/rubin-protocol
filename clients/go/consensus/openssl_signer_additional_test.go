//go:build cgo

package consensus

import (
	"strings"
	"testing"
)

func TestCStringTrim0(t *testing.T) {
	if got := cStringTrim0([]byte("abc\x00def")); got != "abc" {
		t.Fatalf("got=%q", got)
	}
	if got := cStringTrim0([]byte("abc")); got != "abc" {
		t.Fatalf("got=%q", got)
	}
}

func TestMLDSA87Keypair_PubkeyBytesIsCopyAndCloseIdempotent(t *testing.T) {
	kp := mustMLDSA87Keypair(t)

	p1 := kp.PubkeyBytes()
	if len(p1) != ML_DSA_87_PUBKEY_BYTES {
		t.Fatalf("pubkey len=%d", len(p1))
	}
	p1[0] ^= 0x01

	p2 := kp.PubkeyBytes()
	if p2[0] == p1[0] {
		t.Fatalf("expected PubkeyBytes to return a copy")
	}

	kp.Close()
	kp.Close()

	var nilKP *MLDSA87Keypair
	if got := nilKP.PubkeyBytes(); got != nil {
		t.Fatalf("expected nil for nil receiver")
	}
}

func TestMLDSA87Keypair_SignDigest32_NilKeypairErrors(t *testing.T) {
	var digest [32]byte

	var kp *MLDSA87Keypair
	if _, err := kp.SignDigest32(digest); err == nil {
		t.Fatalf("expected error")
	}
	kp = &MLDSA87Keypair{}
	if _, err := kp.SignDigest32(digest); err == nil {
		t.Fatalf("expected error")
	}
}

func TestNewOpenSSLRawKeypair_RejectsUnknownAlg(t *testing.T) {
	_, _, err := newOpenSSLRawKeypair("NO_SUCH_ALG", 1)
	if err == nil {
		t.Fatalf("expected error")
	}
}

func TestNewOpenSSLRawKeypair_PublicKeyBufferTooSmallErrors(t *testing.T) {
	_, _, err := newOpenSSLRawKeypair("ML-DSA-87", 1)
	if err == nil {
		t.Fatalf("expected error")
	}
}

func TestNewOpenSSLRawKeypair_PublicKeyLenMismatchErrors(t *testing.T) {
	_, _, err := newOpenSSLRawKeypair("ML-DSA-87", ML_DSA_87_PUBKEY_BYTES+1)
	if err == nil {
		t.Fatalf("expected error")
	}
}

func TestSignOpenSSLDigest32_ExactSigLenMismatchErrors(t *testing.T) {
	kp := mustMLDSA87Keypair(t)

	var digest [32]byte
	digest[0] = 0x01
	_, err := signOpenSSLDigest32(kp.pkey, digest, ML_DSA_87_SIG_BYTES, ML_DSA_87_SIG_BYTES-1)
	if err == nil {
		t.Fatalf("expected error")
	}
}

func TestSignOpenSSLDigest32_BufferTooSmallErrors(t *testing.T) {
	kp := mustMLDSA87Keypair(t)

	var digest [32]byte
	digest[0] = 0x02
	_, err := signOpenSSLDigest32(kp.pkey, digest, 1, 0)
	if err == nil {
		t.Fatalf("expected error")
	}
}

func TestNewOpenSSLRawKeypair_InvalidFIPSModeRejected(t *testing.T) {
	resetOpenSSLBootstrapStateForTests()
	t.Cleanup(resetOpenSSLBootstrapStateForTests)

	t.Setenv("RUBIN_OPENSSL_FIPS_MODE", "definitely-invalid")
	_, _, err := newOpenSSLRawKeypair("ML-DSA-87", ML_DSA_87_PUBKEY_BYTES)
	if err == nil {
		t.Fatalf("expected bootstrap mode error")
	}
	if !strings.Contains(err.Error(), "invalid RUBIN_OPENSSL_FIPS_MODE") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSignOpenSSLDigest32_InvalidFIPSModeRejected(t *testing.T) {
	resetOpenSSLBootstrapStateForTests()
	t.Cleanup(resetOpenSSLBootstrapStateForTests)

	t.Setenv("RUBIN_OPENSSL_FIPS_MODE", "definitely-invalid")
	var digest [32]byte
	_, err := signOpenSSLDigest32(nil, digest, ML_DSA_87_SIG_BYTES, 0)
	if err == nil {
		t.Fatalf("expected bootstrap mode error")
	}
	if !strings.Contains(err.Error(), "invalid RUBIN_OPENSSL_FIPS_MODE") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNewMLDSA87Keypair_InvalidFIPSModeRejected(t *testing.T) {
	resetOpenSSLBootstrapStateForTests()
	t.Cleanup(resetOpenSSLBootstrapStateForTests)

	t.Setenv("RUBIN_OPENSSL_FIPS_MODE", "definitely-invalid")
	_, err := NewMLDSA87Keypair()
	if err == nil {
		t.Fatalf("expected bootstrap mode error")
	}
	if !strings.Contains(err.Error(), "invalid RUBIN_OPENSSL_FIPS_MODE") {
		t.Fatalf("unexpected error: %v", err)
	}
}
