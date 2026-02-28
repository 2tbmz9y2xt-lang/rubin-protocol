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

func TestOpenSSL_SLH_SignVerifyRoundtrip_OneShot(t *testing.T) {
	kp, err := NewSLHDSASHAKE256fKeypair()
	if err != nil {
		// Not every OpenSSL build enables SLH-DSA.
		t.Skipf("SLH-DSA backend unavailable: %v", err)
	}
	t.Cleanup(func() { kp.Close() })

	var msg [32]byte
	msg[0] = 0x24
	sig, err := kp.SignDigest32(msg)
	if err != nil {
		t.Fatalf("SignDigest32: %v", err)
	}

	ok, err := verifySig(SUITE_ID_SLH_DSA_SHAKE_256F, kp.PubkeyBytes(), sig, msg)
	if err != nil {
		t.Fatalf("verifySig err: %v", err)
	}
	if !ok {
		t.Fatalf("verifySig=false")
	}

	// Wrong message must fail signature verification deterministically.
	msg[0] ^= 0x01
	ok2, err := verifySig(SUITE_ID_SLH_DSA_SHAKE_256F, kp.PubkeyBytes(), sig, msg)
	if err != nil {
		t.Fatalf("verifySig err (wrong msg): %v", err)
	}
	if ok2 {
		t.Fatalf("verifySig=true for wrong message")
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
