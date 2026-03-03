package consensus

import (
	"strings"
	"testing"
)

func mustMLDSA87Keypair(t *testing.T) *MLDSA87Keypair {
	t.Helper()
	kp, err := NewMLDSA87Keypair()
	if err != nil {
		if strings.Contains(err.Error(), "unsupported") {
			t.Skipf("ML-DSA backend unavailable in this OpenSSL build: %v", err)
		}
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
	d, err := SighashV1DigestWithType(tx, inputIndex, inputValue, chainID, SIGHASH_ALL)
	if err != nil {
		t.Fatalf("SighashV1DigestWithType: %v", err)
	}
	sig, err := kp.SignDigest32(d)
	if err != nil {
		t.Fatalf("SignDigest32: %v", err)
	}
	sig = append(sig, SIGHASH_ALL)
	return WitnessItem{
		SuiteID:   SUITE_ID_ML_DSA_87,
		Pubkey:    kp.PubkeyBytes(),
		Signature: sig,
	}
}

func testSighashContextTx() (*Tx, uint32, uint64, [32]byte) {
	var prev [32]byte
	prev[0] = 0x42
	var chainID [32]byte
	chainID[0] = 0x11
	return &Tx{
		Version: 1,
		TxKind:  0x00,
		TxNonce: 7,
		Inputs: []TxInput{{
			PrevTxid: prev,
			PrevVout: 0,
			Sequence: 0,
		}},
		Outputs: []TxOutput{{
			Value:        1,
			CovenantType: COV_TYPE_P2PK,
			CovenantData: validP2PKCovenantData(),
		}},
		Locktime: 0,
	}, 0, 1, chainID
}

func signDigestWithSighashType(t *testing.T, kp *MLDSA87Keypair, tx *Tx, inputIndex uint32, inputValue uint64, chainID [32]byte, sighashType uint8) []byte {
	t.Helper()
	digest, err := SighashV1DigestWithType(tx, inputIndex, inputValue, chainID, sighashType)
	if err != nil {
		t.Fatalf("SighashV1DigestWithType: %v", err)
	}
	sig, err := kp.SignDigest32(digest)
	if err != nil {
		t.Fatalf("SignDigest32: %v", err)
	}
	return append(sig, sighashType)
}
