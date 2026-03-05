package consensus

import "testing"

func stealthCovenantDataForKeyID(oneTimeKeyID [32]byte) []byte {
	cov := make([]byte, MAX_STEALTH_COVENANT_DATA)
	copy(cov[ML_KEM_1024_CT_BYTES:MAX_STEALTH_COVENANT_DATA], oneTimeKeyID[:])
	return cov
}

func TestParseStealthCovenantData_LengthChecks(t *testing.T) {
	_, err := ParseStealthCovenantData(nil)
	if err == nil {
		t.Fatalf("expected error for nil covenant_data")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_COVENANT_TYPE_INVALID {
		t.Fatalf("code=%s, want %s", got, TX_ERR_COVENANT_TYPE_INVALID)
	}

	_, err = ParseStealthCovenantData(make([]byte, MAX_STEALTH_COVENANT_DATA-1))
	if err == nil {
		t.Fatalf("expected error for non-canonical covenant_data length")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_COVENANT_TYPE_INVALID {
		t.Fatalf("code=%s, want %s", got, TX_ERR_COVENANT_TYPE_INVALID)
	}
}

func TestParseStealthCovenantData_Valid(t *testing.T) {
	var oneTimeKeyID [32]byte
	oneTimeKeyID[0] = 0xaa
	oneTimeKeyID[31] = 0x55

	cov, err := ParseStealthCovenantData(stealthCovenantDataForKeyID(oneTimeKeyID))
	if err != nil {
		t.Fatalf("ParseStealthCovenantData(valid): %v", err)
	}
	if len(cov.Ciphertext) != ML_KEM_1024_CT_BYTES {
		t.Fatalf("ciphertext_len=%d, want %d", len(cov.Ciphertext), ML_KEM_1024_CT_BYTES)
	}
	if cov.OneTimeKeyID != oneTimeKeyID {
		t.Fatalf("one_time_key_id mismatch")
	}
}

func TestValidateCoreStealthSpend_ErrorMapping(t *testing.T) {
	var chainID [32]byte
	var prev [32]byte
	prev[0] = 0x51

	kp := mustMLDSA87Keypair(t)
	txBytes := txWithOneInputOneOutput(prev, 0, 90, COV_TYPE_P2PK, p2pkCovenantDataForPubkey(kp.PubkeyBytes()))
	tx, _ := mustParseTxForUtxo(t, txBytes)
	validWitness := signP2PKInputWitness(t, tx, 0, 100, chainID, kp)
	entry := UtxoEntry{
		Value:        100,
		CovenantType: COV_TYPE_CORE_STEALTH,
		CovenantData: stealthCovenantDataForKeyID(sha3_256(validWitness.Pubkey)),
	}

	if err := validateCoreStealthSpend(entry, validWitness, tx, 0, 100, chainID, 200); err != nil {
		t.Fatalf("validateCoreStealthSpend(valid): %v", err)
	}

	badSuite := validWitness
	badSuite.SuiteID = 0x03
	err := validateCoreStealthSpend(entry, badSuite, tx, 0, 100, chainID, 200)
	if err == nil {
		t.Fatalf("expected suite rejection")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_SIG_ALG_INVALID {
		t.Fatalf("code=%s, want %s", got, TX_ERR_SIG_ALG_INVALID)
	}

	otherKP := mustMLDSA87Keypair(t)
	mismatchEntry := entry
	mismatchEntry.CovenantData = stealthCovenantDataForKeyID(sha3_256(otherKP.PubkeyBytes()))
	err = validateCoreStealthSpend(mismatchEntry, validWitness, tx, 0, 100, chainID, 200)
	if err == nil {
		t.Fatalf("expected key binding mismatch")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_SIG_INVALID {
		t.Fatalf("code=%s, want %s", got, TX_ERR_SIG_INVALID)
	}

	nonNative := validWitness
	nonNative.SuiteID = 0x02 // Formerly SLH-DSA; now treated as a non-native suite.
	err = validateCoreStealthSpend(entry, nonNative, tx, 0, 100, chainID, 0)
	if err == nil {
		t.Fatalf("expected non-native suite rejection")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_SIG_ALG_INVALID {
		t.Fatalf("code=%s, want %s", got, TX_ERR_SIG_ALG_INVALID)
	}
}
