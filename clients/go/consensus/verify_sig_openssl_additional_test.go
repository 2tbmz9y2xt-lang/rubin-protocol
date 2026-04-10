//go:build cgo

package consensus

import (
	"fmt"
	"testing"
)

func TestVerifySig_UnsupportedSuiteReturnsError(t *testing.T) {
	var d [32]byte
	_, err := verifySig(0xff, []byte{0x01}, []byte{0x02}, d)
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_SIG_ALG_INVALID {
		t.Fatalf("code=%s, want %s", got, TX_ERR_SIG_ALG_INVALID)
	}
}

func TestOpenSSLVerifySig_EmptyInputsReturnErrors(t *testing.T) {
	var d [32]byte
	_, err := opensslVerifySigOneShot("", []byte{0x01}, []byte{0x02}, d[:])
	if err == nil {
		t.Fatalf("expected error for empty alg")
	}
	_, err = opensslVerifySigOneShot("ML-DSA-87", nil, []byte{0x02}, d[:])
	if err == nil {
		t.Fatalf("expected error for empty pubkey")
	}
	_, err = opensslVerifySigOneShot("ML-DSA-87", []byte{0x01}, nil, d[:])
	if err == nil {
		t.Fatalf("expected error for empty signature")
	}
	_, err = opensslVerifySigOneShot("ML-DSA-87", []byte{0x01}, []byte{0x02}, nil)
	if err == nil {
		t.Fatalf("expected error for empty message")
	}
}

func TestOpenSSL_MLDSA87_VerifyWrongMessageReturnsFalse(t *testing.T) {
	kp := mustMLDSA87Keypair(t)

	var msg [32]byte
	msg[0] = 0x42
	sig, err := kp.SignDigest32(msg)
	if err != nil {
		t.Fatalf("SignDigest32: %v", err)
	}

	msg[0] ^= 0x01
	ok, err := verifySig(SUITE_ID_ML_DSA_87, kp.PubkeyBytes(), sig, msg)
	if err != nil {
		t.Fatalf("verifySig err: %v", err)
	}
	if ok {
		t.Fatalf("verifySig=true for wrong message")
	}
}

func TestOpenSSLVerifySig_UnknownAlgErrors(t *testing.T) {
	var d [32]byte
	ok, err := opensslVerifySigOneShot("NO_SUCH_ALG", []byte{0x01}, []byte{0x02}, d[:])
	if err == nil || ok {
		t.Fatalf("expected error for unknown alg")
	}
}

func TestVerifySig_OpenSSLBackendErrorMapsToSigInvalid(t *testing.T) {
	kp := mustMLDSA87Keypair(t)
	var digest [32]byte
	digest[0] = 0x5a

	sig, err := kp.SignDigest32(digest)
	if err != nil {
		t.Fatalf("SignDigest32: %v", err)
	}

	orig := opensslVerifySigOneShotFn
	opensslVerifySigOneShotFn = func(_ string, _ []byte, _ []byte, _ []byte) (bool, error) {
		return false, fmt.Errorf("forced backend failure")
	}
	defer func() { opensslVerifySigOneShotFn = orig }()

	_, verifyErr := verifySig(SUITE_ID_ML_DSA_87, kp.PubkeyBytes(), sig, digest)
	if verifyErr == nil {
		t.Fatalf("expected verifySig error")
	}
	if got := mustTxErrCode(t, verifyErr); got != TX_ERR_SIG_INVALID {
		t.Fatalf("code=%s, want %s", got, TX_ERR_SIG_INVALID)
	}
}

func TestDefaultRuntimeSuiteRegistry_CachesSharedInstance(t *testing.T) {
	first := defaultRuntimeSuiteRegistry()
	second := defaultRuntimeSuiteRegistry()
	if first == nil || second == nil {
		t.Fatalf("expected cached runtime registry")
	}
	if first != second {
		t.Fatalf("expected shared cached runtime registry instance")
	}
}

func TestDefaultRuntimeSuiteRegistry_IsCanonicalDefaultLiveManifest(t *testing.T) {
	reg := defaultRuntimeSuiteRegistry()
	if !reg.IsCanonicalDefaultLiveManifest() {
		t.Fatalf("default runtime registry must stay pinned to the canonical live ML-DSA-87 manifest")
	}
}
