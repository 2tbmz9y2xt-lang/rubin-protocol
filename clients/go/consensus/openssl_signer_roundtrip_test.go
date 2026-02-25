package consensus

import "testing"

func TestOpenSSL_MLDSA87_SignVerifyRoundtrip(t *testing.T) {
	kp := mustMLDSA87Keypair(t)

	var msg [32]byte
	msg[0] = 0x42
	sig, err := kp.SignDigest32(msg)
	if err != nil {
		t.Fatalf("SignDigest32: %v", err)
	}

	ok, err := verifySig(SUITE_ID_ML_DSA_87, kp.PubkeyBytes(), sig, msg)
	if err != nil {
		t.Fatalf("verifySig err: %v", err)
	}
	if !ok {
		t.Fatalf("verifySig=false")
	}
}

func TestOpenSSL_VerifySig_RejectsWrongMLDSALengthsBeforeOpenSSL(t *testing.T) {
	var msg [32]byte
	ok, err := verifySig(SUITE_ID_ML_DSA_87, make([]byte, ML_DSA_87_PUBKEY_BYTES-1), make([]byte, ML_DSA_87_SIG_BYTES), msg)
	if err != nil {
		t.Fatalf("verifySig err: %v", err)
	}
	if ok {
		t.Fatalf("verifySig=true for invalid ML-DSA pubkey length")
	}
}

func TestOpenSSL_VerifySig_RejectsWrongSLHKeyLengthBeforeOpenSSL(t *testing.T) {
	var msg [32]byte
	ok, err := verifySig(SUITE_ID_SLH_DSA_SHAKE_256F, make([]byte, SLH_DSA_SHAKE_256F_PUBKEY_BYTES+1), []byte{0x01}, msg)
	if err != nil {
		t.Fatalf("verifySig err: %v", err)
	}
	if ok {
		t.Fatalf("verifySig=true for invalid SLH pubkey length")
	}
}
