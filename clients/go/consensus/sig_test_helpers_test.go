package consensus

import "testing"

func mustMLDSA87Keypair(t *testing.T) *MLDSA87Keypair {
	t.Helper()
	kp, err := NewMLDSA87Keypair()
	if err != nil {
		t.Fatalf("NewMLDSA87Keypair: %v", err)
	}
	t.Cleanup(func() { kp.Close() })
	return kp
}

func p2pkCovenantDataForPubkey(pub []byte) []byte {
	keyID := sha3_256(pub)
	b := make([]byte, MAX_P2PK_COVENANT_DATA)
	b[0] = SUITE_ID_ML_DSA_87
	copy(b[1:33], keyID[:])
	return b
}

func signP2PKInputWitness(t *testing.T, tx *Tx, inputIndex uint32, inputValue uint64, chainID [32]byte, kp *MLDSA87Keypair) WitnessItem {
	t.Helper()
	d, err := SighashV1Digest(tx, inputIndex, inputValue, chainID)
	if err != nil {
		t.Fatalf("SighashV1Digest: %v", err)
	}
	sig, err := kp.SignDigest32(d)
	if err != nil {
		t.Fatalf("SignDigest32: %v", err)
	}
	return WitnessItem{
		SuiteID:   SUITE_ID_ML_DSA_87,
		Pubkey:    kp.PubkeyBytes(),
		Signature: sig,
	}
}

