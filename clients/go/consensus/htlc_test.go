package consensus

import "testing"

func encodeHTLCCovenantData(
	hash [32]byte,
	lockMode uint8,
	lockValue uint64,
	claimKeyID [32]byte,
	refundKeyID [32]byte,
) []byte {
	b := make([]byte, 0, MAX_HTLC_COVENANT_DATA)
	b = append(b, hash[:]...)
	b = append(b, lockMode)
	b = appendU64le(b, lockValue)
	b = append(b, claimKeyID[:]...)
	b = append(b, refundKeyID[:]...)
	return b
}

func encodeHTLCClaimPayload(preimage []byte) []byte {
	b := make([]byte, 0, 3+len(preimage))
	b = append(b, 0x00) // path_id = claim
	b = appendU16le(b, uint16(len(preimage)))
	b = append(b, preimage...)
	return b
}

func TestParseHTLCCovenantData_OK(t *testing.T) {
	preimage := []byte("rubin-htlc")
	hash := sha3_256(preimage)
	claimPub := make([]byte, SLH_DSA_SHAKE_256F_PUBKEY_BYTES)
	refundPub := make([]byte, SLH_DSA_SHAKE_256F_PUBKEY_BYTES)
	refundPub[0] = 0x01

	cov := encodeHTLCCovenantData(
		hash,
		LOCK_MODE_HEIGHT,
		123,
		sha3_256(claimPub),
		sha3_256(refundPub),
	)
	parsed, err := ParseHTLCCovenantData(cov)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if parsed.LockMode != LOCK_MODE_HEIGHT || parsed.LockValue != 123 {
		t.Fatalf("unexpected parsed lock fields")
	}
}

func TestParseHTLCCovenantData_InvalidLockMode(t *testing.T) {
	hash := sha3_256([]byte("x"))
	claim := sha3_256([]byte("claim"))
	refund := sha3_256([]byte("refund"))
	cov := encodeHTLCCovenantData(hash, 0x02, 1, claim, refund)
	err := ValidateTxCovenantsGenesis(&Tx{
		Outputs: []TxOutput{{Value: 1, CovenantType: COV_TYPE_HTLC, CovenantData: cov}},
	})
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_COVENANT_TYPE_INVALID {
		t.Fatalf("code=%s, want %s", got, TX_ERR_COVENANT_TYPE_INVALID)
	}
}

func TestValidateHTLCSpend_ClaimHashMismatch(t *testing.T) {
	claimPub := make([]byte, SLH_DSA_SHAKE_256F_PUBKEY_BYTES)
	refundPub := make([]byte, SLH_DSA_SHAKE_256F_PUBKEY_BYTES)
	refundPub[0] = 0x22
	claimKeyID := sha3_256(claimPub)
	refundKeyID := sha3_256(refundPub)

	cov := encodeHTLCCovenantData(
		sha3_256([]byte("different")),
		LOCK_MODE_HEIGHT,
		50,
		claimKeyID,
		refundKeyID,
	)
	entry := UtxoEntry{
		Value:        100,
		CovenantType: COV_TYPE_HTLC,
		CovenantData: cov,
	}

	path := WitnessItem{
		SuiteID:   SUITE_ID_SENTINEL,
		Pubkey:    claimKeyID[:],
		Signature: encodeHTLCClaimPayload([]byte("actual-preimage")),
	}
	sig := WitnessItem{
		SuiteID:   SUITE_ID_SLH_DSA_SHAKE_256F,
		Pubkey:    claimPub,
		Signature: []byte{0x01},
	}

	err := ValidateHTLCSpend(entry, path, sig, SLH_DSA_ACTIVATION_HEIGHT, 0)
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_SIG_INVALID {
		t.Fatalf("code=%s, want %s", got, TX_ERR_SIG_INVALID)
	}
}

func TestValidateHTLCSpend_RefundTimelockNotMet(t *testing.T) {
	claimPub := make([]byte, SLH_DSA_SHAKE_256F_PUBKEY_BYTES)
	refundPub := make([]byte, SLH_DSA_SHAKE_256F_PUBKEY_BYTES)
	refundPub[0] = 0x33
	claimKeyID := sha3_256(claimPub)
	refundKeyID := sha3_256(refundPub)

	cov := encodeHTLCCovenantData(
		sha3_256([]byte("x")),
		LOCK_MODE_HEIGHT,
		SLH_DSA_ACTIVATION_HEIGHT+100,
		claimKeyID,
		refundKeyID,
	)
	entry := UtxoEntry{
		Value:        100,
		CovenantType: COV_TYPE_HTLC,
		CovenantData: cov,
	}
	path := WitnessItem{
		SuiteID:   SUITE_ID_SENTINEL,
		Pubkey:    refundKeyID[:],
		Signature: []byte{0x01}, // path_id = refund
	}
	sig := WitnessItem{
		SuiteID:   SUITE_ID_SLH_DSA_SHAKE_256F,
		Pubkey:    refundPub,
		Signature: []byte{0x01},
	}

	err := ValidateHTLCSpend(entry, path, sig, SLH_DSA_ACTIVATION_HEIGHT, 0)
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_TIMELOCK_NOT_MET {
		t.Fatalf("code=%s, want %s", got, TX_ERR_TIMELOCK_NOT_MET)
	}
}

func TestApplyNonCoinbaseTxBasic_HTLCUnknownPath(t *testing.T) {
	var prev [32]byte
	prev[0] = 0xa1
	txBytes := txWithOneInputOneOutput(prev, 0, 90, COV_TYPE_P2PK, validP2PKCovenantData())
	tx, txid := mustParseTxForUtxo(t, txBytes)

	claimPub := make([]byte, SLH_DSA_SHAKE_256F_PUBKEY_BYTES)
	refundPub := make([]byte, SLH_DSA_SHAKE_256F_PUBKEY_BYTES)
	refundPub[0] = 0x44
	claimKeyID := sha3_256(claimPub)
	refundKeyID := sha3_256(refundPub)

	tx.Witness = []WitnessItem{
		// Unknown spend path for CORE_HTLC.
		{SuiteID: SUITE_ID_SENTINEL, Pubkey: claimKeyID[:], Signature: []byte{0x02}},
		// Signature item (shape is irrelevant because first item already fails).
		{SuiteID: SUITE_ID_SLH_DSA_SHAKE_256F, Pubkey: claimPub, Signature: []byte{0x01}},
	}

	utxos := map[Outpoint]UtxoEntry{
		{Txid: prev, Vout: 0}: {
			Value:        100,
			CovenantType: COV_TYPE_HTLC,
			CovenantData: encodeHTLCCovenantData(
				sha3_256([]byte("preimage")),
				LOCK_MODE_HEIGHT,
				10,
				claimKeyID,
				refundKeyID,
			),
		},
	}

	_, err := ApplyNonCoinbaseTxBasic(tx, txid, utxos, SLH_DSA_ACTIVATION_HEIGHT, 1000)
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_PARSE {
		t.Fatalf("code=%s, want %s", got, TX_ERR_PARSE)
	}
}
