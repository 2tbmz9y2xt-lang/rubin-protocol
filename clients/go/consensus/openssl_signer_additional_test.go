//go:build cgo

package consensus

import (
	"strings"
	"testing"
)

func TestValidateOpenSSLAlgorithmRejectsUnknownAndLengthMismatch(t *testing.T) {
	if err := validateOpenSSLAlgorithm("NO_SUCH_ALG", 1, "keygen"); err == nil {
		t.Fatalf("expected unknown algorithm error")
	}
	if err := validateOpenSSLAlgorithm("ML-DSA-87", ML_DSA_87_PUBKEY_BYTES+1, "keygen"); err == nil {
		t.Fatalf("expected length mismatch error")
	}
}

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

func TestOpenSSLPublicKeyBytes_NilKeyErrors(t *testing.T) {
	if _, err := openSSLPublicKeyBytes(nil, ML_DSA_87_PUBKEY_BYTES); err == nil {
		t.Fatalf("expected error")
	}
	if _, err := openSSLPublicKeyBytesWithErrBuf(nil, ML_DSA_87_PUBKEY_BYTES, nil); err == nil {
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

func TestNewMLDSA87KeypairFromDER_EmptyInputRejected(t *testing.T) {
	if _, err := NewMLDSA87KeypairFromDER(nil); err == nil {
		t.Fatalf("expected error")
	}
}

func TestMLDSA87Keypair_PrivateKeyDER_NilKeypairErrors(t *testing.T) {
	var kp *MLDSA87Keypair
	if _, err := kp.PrivateKeyDER(); err == nil {
		t.Fatalf("expected nil keypair error")
	}

	kp = &MLDSA87Keypair{}
	if _, err := kp.PrivateKeyDER(); err == nil {
		t.Fatalf("expected nil keypair error")
	}
}

func TestMLDSA87Keypair_DERRoundTrip(t *testing.T) {
	kp := mustMLDSA87Keypair(t)

	der, err := kp.PrivateKeyDER()
	if err != nil {
		t.Fatalf("PrivateKeyDER: %v", err)
	}
	restored, err := NewMLDSA87KeypairFromDER(der)
	if err != nil {
		t.Fatalf("NewMLDSA87KeypairFromDER: %v", err)
	}
	t.Cleanup(restored.Close)

	if got, want := restored.PubkeyBytes(), kp.PubkeyBytes(); len(got) != len(want) || string(got) != string(want) {
		t.Fatalf("pubkey mismatch after DER roundtrip")
	}
}
