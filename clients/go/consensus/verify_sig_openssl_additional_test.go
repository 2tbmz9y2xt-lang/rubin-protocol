//go:build cgo

package consensus

import "testing"

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
	_, err := opensslVerifySigMessage("", []byte{0x01}, []byte{0x02}, d[:])
	if err == nil {
		t.Fatalf("expected error for empty alg")
	}
	_, err = opensslVerifySigMessage("ML-DSA-87", nil, []byte{0x02}, d[:])
	if err == nil {
		t.Fatalf("expected error for empty pubkey")
	}
	_, err = opensslVerifySigMessage("ML-DSA-87", []byte{0x01}, nil, d[:])
	if err == nil {
		t.Fatalf("expected error for empty signature")
	}
	_, err = opensslVerifySigMessage("ML-DSA-87", []byte{0x01}, []byte{0x02}, nil)
	if err == nil {
		t.Fatalf("expected error for empty message")
	}

	_, err = opensslVerifySigDigestOneShot("", []byte{0x01}, []byte{0x02}, d[:])
	if err == nil {
		t.Fatalf("expected error for empty alg (oneshot)")
	}
	_, err = opensslVerifySigDigestOneShot("SLH-DSA-SHAKE-256f", nil, []byte{0x02}, d[:])
	if err == nil {
		t.Fatalf("expected error for empty pubkey (oneshot)")
	}
	_, err = opensslVerifySigDigestOneShot("SLH-DSA-SHAKE-256f", []byte{0x01}, nil, d[:])
	if err == nil {
		t.Fatalf("expected error for empty signature (oneshot)")
	}
	_, err = opensslVerifySigDigestOneShot("SLH-DSA-SHAKE-256f", []byte{0x01}, []byte{0x02}, nil)
	if err == nil {
		t.Fatalf("expected error for empty message (oneshot)")
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
	ok, err := opensslVerifySigMessage("NO_SUCH_ALG", []byte{0x01}, []byte{0x02}, d[:])
	if err == nil || ok {
		t.Fatalf("expected error for unknown alg")
	}
	ok, err = opensslVerifySigDigestOneShot("NO_SUCH_ALG", []byte{0x01}, []byte{0x02}, d[:])
	if err == nil || ok {
		t.Fatalf("expected error for unknown alg (oneshot)")
	}
}
