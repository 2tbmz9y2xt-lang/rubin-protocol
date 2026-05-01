//go:build cgo

package consensus

import (
	"math"
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

// TestOpenSSLPublicKeyBytes_NonPositivePubkeyLenErrors covers the
// package-local FFI guard added for Q-SEC-GO-OPENSSL-SIGNER-LIFETIME-GUARDS-01:
// a non-positive expectedPubkeyLen would otherwise panic at the
// unsafe.Pointer(&pubkey[0]) site after make([]byte, 0). A clean error
// is required before any C call or unsafe pointer use.
func TestOpenSSLPublicKeyBytes_NonPositivePubkeyLenErrors(t *testing.T) {
	kp := mustMLDSA87Keypair(t)

	for _, badLen := range []int{0, -1, -42} {
		_, err := openSSLPublicKeyBytesWithErrBuf(kp.pkey, badLen, nil)
		if err == nil {
			t.Fatalf("openSSLPublicKeyBytesWithErrBuf(non-nil pkey, %d, nil) returned nil error", badLen)
		}
		if !strings.Contains(err.Error(), "openssl pubkey length must be positive") {
			t.Fatalf("badLen=%d err=%q, want substring %q", badLen, err.Error(), "openssl pubkey length must be positive")
		}
	}
}

// TestSignOpenSSLDigest32_NilPKeyErrors covers the helper-level
// pre-C guard added for Q-SEC-GO-OPENSSL-SIGNER-LIFETIME-GUARDS-01.
// signOpenSSLDigest32 must reject a nil pkey before allocating the
// signature buffer or passing the pointer to C, so a direct caller
// outside MLDSA87Keypair.SignDigest32 fails closed.
func TestSignOpenSSLDigest32_NilPKeyErrors(t *testing.T) {
	var digest [32]byte
	digest[0] = 0x77

	_, err := signOpenSSLDigest32(nil, digest, ML_DSA_87_SIG_BYTES, ML_DSA_87_SIG_BYTES)
	if err == nil {
		t.Fatalf("signOpenSSLDigest32(nil pkey, ...) returned nil error")
	}
	if !strings.Contains(err.Error(), "nil openssl key") {
		t.Fatalf("err=%q, want substring %q", err.Error(), "nil openssl key")
	}
}

// TestSignOpenSSLDigest32_NonPositiveMaxSigBytesErrors covers the
// pre-C guard for maxSigBytes <= 0. Without the guard, make([]byte,
// 0) plus &signature[0] panics at the unsafe.Pointer site; make([]byte,
// -1) panics inside the runtime allocator. Both must surface as a
// clean error from the FFI boundary.
func TestSignOpenSSLDigest32_NonPositiveMaxSigBytesErrors(t *testing.T) {
	kp := mustMLDSA87Keypair(t)

	var digest [32]byte
	digest[0] = 0x33

	for _, badMax := range []int{0, -1, -1024} {
		_, err := signOpenSSLDigest32(kp.pkey, digest, badMax, 0)
		if err == nil {
			t.Fatalf("signOpenSSLDigest32(pkey, _, %d, 0) returned nil error", badMax)
		}
		if !strings.Contains(err.Error(), "openssl maxSigBytes must be positive") {
			t.Fatalf("badMax=%d err=%q, want substring %q", badMax, err.Error(), "openssl maxSigBytes must be positive")
		}
	}
}

// TestSignOpenSSLDigest32_ExactGreaterThanMaxErrors covers the
// pre-C guard for exactSigBytes > maxSigBytes. The C helper writes
// at most maxSigBytes, so any exactSigBytes greater than that can
// never be satisfied; rejecting before the C call avoids spending
// an OpenSSL signing operation on a request the caller cannot
// possibly accept.
func TestSignOpenSSLDigest32_ExactGreaterThanMaxErrors(t *testing.T) {
	kp := mustMLDSA87Keypair(t)

	var digest [32]byte
	digest[0] = 0x44

	_, err := signOpenSSLDigest32(kp.pkey, digest, ML_DSA_87_SIG_BYTES, ML_DSA_87_SIG_BYTES+1)
	if err == nil {
		t.Fatalf("signOpenSSLDigest32 returned nil error for exactSigBytes>maxSigBytes")
	}
	if !strings.Contains(err.Error(), "exceeds maxSigBytes") {
		t.Fatalf("err=%q, want substring %q", err.Error(), "exceeds maxSigBytes")
	}
}

// TestMLDSA87Keypair_SignDigest32_KeepsKeypairAliveAcrossCall covers
// the runtime.KeepAlive(k) added after signOpenSSLDigest32 returns:
// the keypair finalizer must not free k.pkey while the C call is in
// flight. We cannot directly observe finalizer timing in a unit test,
// but a successful sign+verify roundtrip on a freshly generated
// keypair proves the post-call KeepAlive is on the live path; if the
// pkey were freed mid-call the C side would crash or produce an
// invalid signature.
func TestMLDSA87Keypair_SignDigest32_KeepsKeypairAliveAcrossCall(t *testing.T) {
	kp := mustMLDSA87Keypair(t)

	var digest [32]byte
	digest[0] = 0x55

	sig, err := kp.SignDigest32(digest)
	if err != nil {
		t.Fatalf("SignDigest32: %v", err)
	}
	if len(sig) != ML_DSA_87_SIG_BYTES {
		t.Fatalf("sig len=%d, want %d", len(sig), ML_DSA_87_SIG_BYTES)
	}
	ok, vErr := opensslVerifySigOneShot("ML-DSA-87", kp.PubkeyBytes(), sig, digest[:])
	if vErr != nil {
		t.Fatalf("opensslVerifySigOneShot: %v", vErr)
	}
	if !ok {
		t.Fatalf("hedged production signature rejected by verifier under same pubkey")
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

func TestValidatePrivateKeyDERPostC_NilPointerErrors(t *testing.T) {
	err := validatePrivateKeyDERPostC(true, 1)
	if err == nil {
		t.Fatalf("expected error for nil DER pointer")
	}
	if !strings.Contains(err.Error(), "nil DER pointer") {
		t.Fatalf("missing nil-pointer marker in error: %v", err)
	}
}

func TestValidatePrivateKeyDERPostC_ZeroLengthErrors(t *testing.T) {
	err := validatePrivateKeyDERPostC(false, 0)
	if err == nil {
		t.Fatalf("expected error for zero DER length")
	}
	if !strings.Contains(err.Error(), "zero DER length") {
		t.Fatalf("missing zero-length marker in error: %v", err)
	}
}

func TestValidatePrivateKeyDERPostC_OverflowErrors(t *testing.T) {
	for _, derLen := range []uint64{
		uint64(math.MaxInt32) + 1,
		uint64(math.MaxInt32) + 1024,
		math.MaxUint64,
	} {
		err := validatePrivateKeyDERPostC(false, derLen)
		if err == nil {
			t.Fatalf("derLen=%d: expected overflow error", derLen)
		}
		if !strings.Contains(err.Error(), "exceeds C.int range") {
			t.Fatalf("derLen=%d: missing overflow marker in error: %v", derLen, err)
		}
	}
}

func TestValidatePrivateKeyDERPostC_AcceptsValidLengths(t *testing.T) {
	for _, derLen := range []uint64{1, 32, 4096, uint64(math.MaxInt32)} {
		if err := validatePrivateKeyDERPostC(false, derLen); err != nil {
			t.Fatalf("derLen=%d: unexpected error: %v", derLen, err)
		}
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
