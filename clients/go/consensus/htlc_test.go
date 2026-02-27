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

func makeSLHKeyMaterial(refundTag byte) ([]byte, []byte, [32]byte, [32]byte) {
	claimPub := make([]byte, SLH_DSA_SHAKE_256F_PUBKEY_BYTES)
	refundPub := make([]byte, SLH_DSA_SHAKE_256F_PUBKEY_BYTES)
	refundPub[0] = refundTag
	claimKeyID := sha3_256(claimPub)
	refundKeyID := sha3_256(refundPub)
	return claimPub, refundPub, claimKeyID, refundKeyID
}

func makeHTLCEntry(hash [32]byte, lockMode uint8, lockValue uint64, claimKeyID, refundKeyID [32]byte) UtxoEntry {
	return UtxoEntry{
		Value:        100,
		CovenantType: COV_TYPE_HTLC,
		CovenantData: encodeHTLCCovenantData(hash, lockMode, lockValue, claimKeyID, refundKeyID),
	}
}

func TestParseHTLCCovenantData_OK(t *testing.T) {
	preimage := []byte("rubin-htlc")
	hash := sha3_256(preimage)
	_, _, claimKeyID, refundKeyID := makeSLHKeyMaterial(0x01)
	cov := encodeHTLCCovenantData(hash, LOCK_MODE_HEIGHT, 123, claimKeyID, refundKeyID)
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
	}, 0)
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_COVENANT_TYPE_INVALID {
		t.Fatalf("code=%s, want %s", got, TX_ERR_COVENANT_TYPE_INVALID)
	}
}

func TestValidateHTLCSpend_ClaimHashMismatch(t *testing.T) {
	var digest [32]byte
	claimPub, _, claimKeyID, refundKeyID := makeSLHKeyMaterial(0x22)
	entry := makeHTLCEntry(sha3_256([]byte("different")), LOCK_MODE_HEIGHT, 50, claimKeyID, refundKeyID)

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

	err := ValidateHTLCSpend(entry, path, sig, digest, SLH_DSA_ACTIVATION_HEIGHT, 0)
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_SIG_INVALID {
		t.Fatalf("code=%s, want %s", got, TX_ERR_SIG_INVALID)
	}
}

func TestValidateHTLCSpend_RefundTimelockNotMet(t *testing.T) {
	var digest [32]byte
	_, refundPub, claimKeyID, refundKeyID := makeSLHKeyMaterial(0x33)
	entry := makeHTLCEntry(
		sha3_256([]byte("x")),
		LOCK_MODE_HEIGHT,
		SLH_DSA_ACTIVATION_HEIGHT+100,
		claimKeyID,
		refundKeyID,
	)
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

	err := ValidateHTLCSpend(entry, path, sig, digest, SLH_DSA_ACTIVATION_HEIGHT, 0)
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_TIMELOCK_NOT_MET {
		t.Fatalf("code=%s, want %s", got, TX_ERR_TIMELOCK_NOT_MET)
	}
}

func TestValidateHTLCSpend_RefundTimestampUsesMTP(t *testing.T) {
	var digest [32]byte
	digest[0] = 0x01
	claimKP := mustMLDSA87Keypair(t)
	refundKP := mustMLDSA87Keypair(t)
	claimPub := claimKP.PubkeyBytes()
	refundPub := refundKP.PubkeyBytes()
	claimKeyID := sha3_256(claimPub)
	refundKeyID := sha3_256(refundPub)

	entry := makeHTLCEntry(
		sha3_256([]byte("x")),
		LOCK_MODE_TIMESTAMP,
		2000,
		claimKeyID,
		refundKeyID,
	)
	path := WitnessItem{
		SuiteID:   SUITE_ID_SENTINEL,
		Pubkey:    refundKeyID[:],
		Signature: []byte{0x01},
	}
	refundSig, err := refundKP.SignDigest32(digest)
	if err != nil {
		t.Fatalf("SignDigest32: %v", err)
	}
	sig := WitnessItem{
		SuiteID:   SUITE_ID_ML_DSA_87,
		Pubkey:    refundPub,
		Signature: refundSig,
	}

	err = ValidateHTLCSpend(entry, path, sig, digest, SLH_DSA_ACTIVATION_HEIGHT, 1000)
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_TIMELOCK_NOT_MET {
		t.Fatalf("code=%s, want %s", got, TX_ERR_TIMELOCK_NOT_MET)
	}

	if err := ValidateHTLCSpend(entry, path, sig, digest, SLH_DSA_ACTIVATION_HEIGHT, 3000); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestApplyNonCoinbaseTxBasic_HTLCUnknownPath(t *testing.T) {
	var chainID [32]byte
	var prev [32]byte
	prev[0] = 0xa1
	txBytes := txWithOneInputOneOutput(prev, 0, 90, COV_TYPE_P2PK, validP2PKCovenantData())
	tx, txid := mustParseTxForUtxo(t, txBytes)

	claimPub, _, claimKeyID, refundKeyID := makeSLHKeyMaterial(0x44)

	tx.Witness = []WitnessItem{
		// Unknown spend path for CORE_HTLC.
		{SuiteID: SUITE_ID_SENTINEL, Pubkey: claimKeyID[:], Signature: []byte{0x02}},
		// Signature item (shape is irrelevant because first item already fails).
		{SuiteID: SUITE_ID_SLH_DSA_SHAKE_256F, Pubkey: claimPub, Signature: []byte{0x01}},
	}

	utxos := map[Outpoint]UtxoEntry{
		{Txid: prev, Vout: 0}: makeHTLCEntry(sha3_256([]byte("preimage")), LOCK_MODE_HEIGHT, 10, claimKeyID, refundKeyID),
	}

	_, err := ApplyNonCoinbaseTxBasic(tx, txid, utxos, SLH_DSA_ACTIVATION_HEIGHT, 1000, chainID)
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_PARSE {
		t.Fatalf("code=%s, want %s", got, TX_ERR_PARSE)
	}
}

func TestParseHTLCCovenantData_Nil(t *testing.T) {
	_, err := ParseHTLCCovenantData(nil)
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_COVENANT_TYPE_INVALID {
		t.Fatalf("code=%s, want %s", got, TX_ERR_COVENANT_TYPE_INVALID)
	}
}

func TestParseHTLCCovenantData_LengthMismatch(t *testing.T) {
	_, err := ParseHTLCCovenantData(make([]byte, MAX_HTLC_COVENANT_DATA-1))
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_COVENANT_TYPE_INVALID {
		t.Fatalf("code=%s, want %s", got, TX_ERR_COVENANT_TYPE_INVALID)
	}
}

func TestParseHTLCCovenantData_LockValueZero(t *testing.T) {
	hash := sha3_256([]byte("x"))
	claim := sha3_256([]byte("claim"))
	refund := sha3_256([]byte("refund"))
	cov := encodeHTLCCovenantData(hash, LOCK_MODE_HEIGHT, 0, claim, refund)

	_, err := ParseHTLCCovenantData(cov)
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_COVENANT_TYPE_INVALID {
		t.Fatalf("code=%s, want %s", got, TX_ERR_COVENANT_TYPE_INVALID)
	}
}

func TestParseHTLCCovenantData_ClaimRefundKeyIDMustDiffer(t *testing.T) {
	hash := sha3_256([]byte("x"))
	keyID := sha3_256([]byte("same"))
	cov := encodeHTLCCovenantData(hash, LOCK_MODE_HEIGHT, 1, keyID, keyID)

	_, err := ParseHTLCCovenantData(cov)
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_PARSE {
		t.Fatalf("code=%s, want %s", got, TX_ERR_PARSE)
	}
}

func TestValidateHTLCSpend_SelectorSuiteIDInvalid(t *testing.T) {
	var digest [32]byte
	claimPub, _, claimKeyID, refundKeyID := makeSLHKeyMaterial(0x55)
	entry := makeHTLCEntry(sha3_256([]byte("x")), LOCK_MODE_HEIGHT, 1, claimKeyID, refundKeyID)

	path := WitnessItem{
		SuiteID:   SUITE_ID_ML_DSA_87,
		Pubkey:    claimKeyID[:],
		Signature: []byte{0x00},
	}
	sig := WitnessItem{SuiteID: SUITE_ID_SLH_DSA_SHAKE_256F, Pubkey: claimPub, Signature: []byte{0x01}}

	err := ValidateHTLCSpend(entry, path, sig, digest, SLH_DSA_ACTIVATION_HEIGHT, 0)
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_PARSE {
		t.Fatalf("code=%s, want %s", got, TX_ERR_PARSE)
	}
}

func TestValidateHTLCSpend_SelectorKeyIDLenInvalid(t *testing.T) {
	var digest [32]byte
	claimPub, _, claimKeyID, refundKeyID := makeSLHKeyMaterial(0x56)
	entry := makeHTLCEntry(sha3_256([]byte("x")), LOCK_MODE_HEIGHT, 1, claimKeyID, refundKeyID)

	path := WitnessItem{
		SuiteID:   SUITE_ID_SENTINEL,
		Pubkey:    claimKeyID[:31],
		Signature: []byte{0x00},
	}
	sig := WitnessItem{SuiteID: SUITE_ID_SLH_DSA_SHAKE_256F, Pubkey: claimPub, Signature: []byte{0x01}}

	err := ValidateHTLCSpend(entry, path, sig, digest, SLH_DSA_ACTIVATION_HEIGHT, 0)
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_PARSE {
		t.Fatalf("code=%s, want %s", got, TX_ERR_PARSE)
	}
}

func TestValidateHTLCSpend_SelectorPayloadTooShort(t *testing.T) {
	var digest [32]byte
	claimPub, _, claimKeyID, refundKeyID := makeSLHKeyMaterial(0x57)
	entry := makeHTLCEntry(sha3_256([]byte("x")), LOCK_MODE_HEIGHT, 1, claimKeyID, refundKeyID)

	path := WitnessItem{
		SuiteID:   SUITE_ID_SENTINEL,
		Pubkey:    claimKeyID[:],
		Signature: nil,
	}
	sig := WitnessItem{SuiteID: SUITE_ID_SLH_DSA_SHAKE_256F, Pubkey: claimPub, Signature: []byte{0x01}}

	err := ValidateHTLCSpend(entry, path, sig, digest, SLH_DSA_ACTIVATION_HEIGHT, 0)
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_PARSE {
		t.Fatalf("code=%s, want %s", got, TX_ERR_PARSE)
	}
}

func TestValidateHTLCSpend_ClaimKeyIDMismatch(t *testing.T) {
	var digest [32]byte
	claimPub, _, claimKeyID, refundKeyID := makeSLHKeyMaterial(0x58)
	entry := makeHTLCEntry(sha3_256([]byte("x")), LOCK_MODE_HEIGHT, 1, claimKeyID, refundKeyID)

	var otherKeyID [32]byte
	otherKeyID[0] = 0xff
	path := WitnessItem{
		SuiteID:   SUITE_ID_SENTINEL,
		Pubkey:    otherKeyID[:],
		Signature: []byte{0x00, 0x00, 0x00}, // claim path + preimage_len=0 (won't be reached)
	}
	sig := WitnessItem{SuiteID: SUITE_ID_SLH_DSA_SHAKE_256F, Pubkey: claimPub, Signature: []byte{0x01}}

	err := ValidateHTLCSpend(entry, path, sig, digest, SLH_DSA_ACTIVATION_HEIGHT, 0)
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_SIG_INVALID {
		t.Fatalf("code=%s, want %s", got, TX_ERR_SIG_INVALID)
	}
}

func TestValidateHTLCSpend_ClaimPayloadTooShort(t *testing.T) {
	var digest [32]byte
	claimPub, _, claimKeyID, refundKeyID := makeSLHKeyMaterial(0x59)
	entry := makeHTLCEntry(sha3_256([]byte("x")), LOCK_MODE_HEIGHT, 1, claimKeyID, refundKeyID)

	path := WitnessItem{
		SuiteID:   SUITE_ID_SENTINEL,
		Pubkey:    claimKeyID[:],
		Signature: []byte{0x00, 0x01}, // too short for claim payload
	}
	sig := WitnessItem{SuiteID: SUITE_ID_SLH_DSA_SHAKE_256F, Pubkey: claimPub, Signature: []byte{0x01}}

	err := ValidateHTLCSpend(entry, path, sig, digest, SLH_DSA_ACTIVATION_HEIGHT, 0)
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_PARSE {
		t.Fatalf("code=%s, want %s", got, TX_ERR_PARSE)
	}
}

func TestValidateHTLCSpend_ClaimPreimageLenZero(t *testing.T) {
	var digest [32]byte
	claimPub, _, claimKeyID, refundKeyID := makeSLHKeyMaterial(0x5a)
	entry := makeHTLCEntry(sha3_256([]byte("x")), LOCK_MODE_HEIGHT, 1, claimKeyID, refundKeyID)

	path := WitnessItem{
		SuiteID:   SUITE_ID_SENTINEL,
		Pubkey:    claimKeyID[:],
		Signature: []byte{0x00, 0x00, 0x00}, // claim + preimage_len=0
	}
	sig := WitnessItem{SuiteID: SUITE_ID_SLH_DSA_SHAKE_256F, Pubkey: claimPub, Signature: []byte{0x01}}

	err := ValidateHTLCSpend(entry, path, sig, digest, SLH_DSA_ACTIVATION_HEIGHT, 0)
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_PARSE {
		t.Fatalf("code=%s, want %s", got, TX_ERR_PARSE)
	}
}

func TestValidateHTLCSpend_ClaimPreimageLenOverflow(t *testing.T) {
	var digest [32]byte
	claimPub, _, claimKeyID, refundKeyID := makeSLHKeyMaterial(0x5b)
	entry := makeHTLCEntry(sha3_256([]byte("x")), LOCK_MODE_HEIGHT, 1, claimKeyID, refundKeyID)

	tooBig := uint16(MAX_HTLC_PREIMAGE_BYTES + 1)
	path := WitnessItem{
		SuiteID: SUITE_ID_SENTINEL,
		Pubkey:  claimKeyID[:],
		Signature: []byte{
			0x00,
			byte(tooBig),
			byte(tooBig >> 8),
		},
	}
	sig := WitnessItem{SuiteID: SUITE_ID_SLH_DSA_SHAKE_256F, Pubkey: claimPub, Signature: []byte{0x01}}

	err := ValidateHTLCSpend(entry, path, sig, digest, SLH_DSA_ACTIVATION_HEIGHT, 0)
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_PARSE {
		t.Fatalf("code=%s, want %s", got, TX_ERR_PARSE)
	}
}

func TestValidateHTLCSpend_ClaimPayloadLenMismatch(t *testing.T) {
	var digest [32]byte
	claimPub, _, claimKeyID, refundKeyID := makeSLHKeyMaterial(0x5c)
	entry := makeHTLCEntry(sha3_256([]byte("x")), LOCK_MODE_HEIGHT, 1, claimKeyID, refundKeyID)

	// preimage_len=2 but only 1 byte provided.
	path := WitnessItem{
		SuiteID:   SUITE_ID_SENTINEL,
		Pubkey:    claimKeyID[:],
		Signature: []byte{0x00, 0x02, 0x00, 0xaa},
	}
	sig := WitnessItem{SuiteID: SUITE_ID_SLH_DSA_SHAKE_256F, Pubkey: claimPub, Signature: []byte{0x01}}

	err := ValidateHTLCSpend(entry, path, sig, digest, SLH_DSA_ACTIVATION_HEIGHT, 0)
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_PARSE {
		t.Fatalf("code=%s, want %s", got, TX_ERR_PARSE)
	}
}

func TestValidateHTLCSpend_RefundPayloadLenMismatch(t *testing.T) {
	var digest [32]byte
	claimPub, refundPub, claimKeyID, refundKeyID := makeSLHKeyMaterial(0x5d)
	entry := makeHTLCEntry(sha3_256([]byte("x")), LOCK_MODE_HEIGHT, 1, claimKeyID, refundKeyID)

	path := WitnessItem{
		SuiteID:   SUITE_ID_SENTINEL,
		Pubkey:    refundKeyID[:],
		Signature: []byte{0x01, 0x00},
	}
	sig := WitnessItem{SuiteID: SUITE_ID_SLH_DSA_SHAKE_256F, Pubkey: refundPub, Signature: []byte{0x01}}

	err := ValidateHTLCSpend(entry, path, sig, digest, SLH_DSA_ACTIVATION_HEIGHT, 0)
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_PARSE {
		t.Fatalf("code=%s, want %s", got, TX_ERR_PARSE)
	}

	_ = claimPub
}

func TestValidateHTLCSpend_RefundKeyIDMismatch(t *testing.T) {
	var digest [32]byte
	claimPub, refundPub, claimKeyID, refundKeyID := makeSLHKeyMaterial(0x5e)
	entry := makeHTLCEntry(sha3_256([]byte("x")), LOCK_MODE_HEIGHT, 1, claimKeyID, refundKeyID)

	var otherKeyID [32]byte
	otherKeyID[0] = 0xee
	path := WitnessItem{
		SuiteID:   SUITE_ID_SENTINEL,
		Pubkey:    otherKeyID[:],
		Signature: []byte{0x01},
	}
	sig := WitnessItem{SuiteID: SUITE_ID_SLH_DSA_SHAKE_256F, Pubkey: refundPub, Signature: []byte{0x01}}

	err := ValidateHTLCSpend(entry, path, sig, digest, SLH_DSA_ACTIVATION_HEIGHT, 0)
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_SIG_INVALID {
		t.Fatalf("code=%s, want %s", got, TX_ERR_SIG_INVALID)
	}

	_ = claimPub
	_ = refundKeyID
}

func TestValidateHTLCSpend_SigSuiteInvalid(t *testing.T) {
	var digest [32]byte
	claimPub, refundPub, claimKeyID, refundKeyID := makeSLHKeyMaterial(0x5f)
	entry := makeHTLCEntry(sha3_256([]byte("x")), LOCK_MODE_HEIGHT, 1, claimKeyID, refundKeyID)
	path := WitnessItem{SuiteID: SUITE_ID_SENTINEL, Pubkey: refundKeyID[:], Signature: []byte{0x01}}

	sig := WitnessItem{SuiteID: 0x09, Pubkey: claimPub, Signature: []byte{0x01}}
	err := ValidateHTLCSpend(entry, path, sig, digest, SLH_DSA_ACTIVATION_HEIGHT, 0)
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_SIG_ALG_INVALID {
		t.Fatalf("code=%s, want %s", got, TX_ERR_SIG_ALG_INVALID)
	}

	_ = refundPub
}

func TestValidateHTLCSpend_MLDSANonCanonicalWitnessItemLengths(t *testing.T) {
	var digest [32]byte
	claimPub, refundPub, claimKeyID, refundKeyID := makeSLHKeyMaterial(0x60)
	entry := makeHTLCEntry(sha3_256([]byte("x")), LOCK_MODE_HEIGHT, 1, claimKeyID, refundKeyID)
	path := WitnessItem{SuiteID: SUITE_ID_SENTINEL, Pubkey: refundKeyID[:], Signature: []byte{0x01}}

	sig := WitnessItem{SuiteID: SUITE_ID_ML_DSA_87, Pubkey: []byte{0x01}, Signature: []byte{0x02}}
	err := ValidateHTLCSpend(entry, path, sig, digest, SLH_DSA_ACTIVATION_HEIGHT, 0)
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_SIG_NONCANONICAL {
		t.Fatalf("code=%s, want %s", got, TX_ERR_SIG_NONCANONICAL)
	}

	_ = claimPub
	_ = refundPub
}

func TestValidateHTLCSpend_SLHInactiveAtHeight(t *testing.T) {
	var digest [32]byte
	claimPub, refundPub, claimKeyID, refundKeyID := makeSLHKeyMaterial(0x61)
	entry := makeHTLCEntry(sha3_256([]byte("x")), LOCK_MODE_HEIGHT, 1, claimKeyID, refundKeyID)
	path := WitnessItem{SuiteID: SUITE_ID_SENTINEL, Pubkey: refundKeyID[:], Signature: []byte{0x01}}

	sig := WitnessItem{SuiteID: SUITE_ID_SLH_DSA_SHAKE_256F, Pubkey: refundPub, Signature: []byte{0x01}}
	err := ValidateHTLCSpend(entry, path, sig, digest, SLH_DSA_ACTIVATION_HEIGHT-1, 0)
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_SIG_ALG_INVALID {
		t.Fatalf("code=%s, want %s", got, TX_ERR_SIG_ALG_INVALID)
	}

	_ = claimPub
}

func TestValidateHTLCSpend_SLHNonCanonicalWitnessItemLengths(t *testing.T) {
	var digest [32]byte
	claimPub, refundPub, claimKeyID, refundKeyID := makeSLHKeyMaterial(0x62)
	entry := makeHTLCEntry(sha3_256([]byte("x")), LOCK_MODE_HEIGHT, 1, claimKeyID, refundKeyID)
	path := WitnessItem{SuiteID: SUITE_ID_SENTINEL, Pubkey: refundKeyID[:], Signature: []byte{0x01}}

	sig := WitnessItem{SuiteID: SUITE_ID_SLH_DSA_SHAKE_256F, Pubkey: refundPub, Signature: nil}
	err := ValidateHTLCSpend(entry, path, sig, digest, SLH_DSA_ACTIVATION_HEIGHT, 0)
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_SIG_NONCANONICAL {
		t.Fatalf("code=%s, want %s", got, TX_ERR_SIG_NONCANONICAL)
	}

	_ = claimPub
}

func TestValidateHTLCSpend_SigKeyBindingMismatch(t *testing.T) {
	var digest [32]byte

	// Covenant binds to claimKP but signature pubkey is from otherKP.
	claimKP := mustMLDSA87Keypair(t)
	otherKP := mustMLDSA87Keypair(t)
	claimPub := claimKP.PubkeyBytes()
	otherPub := otherKP.PubkeyBytes()
	claimKeyID := sha3_256(claimPub)
	refundKeyID := sha3_256([]byte("refund"))

	entry := makeHTLCEntry(sha3_256([]byte("p")), LOCK_MODE_HEIGHT, 1, claimKeyID, refundKeyID)

	path := WitnessItem{
		SuiteID:   SUITE_ID_SENTINEL,
		Pubkey:    claimKeyID[:],
		Signature: encodeHTLCClaimPayload([]byte("p")),
	}
	sig := WitnessItem{
		SuiteID:   SUITE_ID_ML_DSA_87,
		Pubkey:    otherPub,
		Signature: make([]byte, ML_DSA_87_SIG_BYTES),
	}

	err := ValidateHTLCSpend(entry, path, sig, digest, 0, 0)
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_SIG_INVALID {
		t.Fatalf("code=%s, want %s", got, TX_ERR_SIG_INVALID)
	}
}

func TestValidateHTLCSpend_SignatureInvalid(t *testing.T) {
	var digest [32]byte
	digest[0] = 0x01

	claimKP := mustMLDSA87Keypair(t)
	claimPub := claimKP.PubkeyBytes()
	claimKeyID := sha3_256(claimPub)
	refundKeyID := sha3_256([]byte("refund"))

	preimage := []byte("rubin-htlc-claim")
	entry := makeHTLCEntry(sha3_256(preimage), LOCK_MODE_HEIGHT, 1, claimKeyID, refundKeyID)

	path := WitnessItem{
		SuiteID:   SUITE_ID_SENTINEL,
		Pubkey:    claimKeyID[:],
		Signature: encodeHTLCClaimPayload(preimage),
	}
	sig := WitnessItem{
		SuiteID:   SUITE_ID_ML_DSA_87,
		Pubkey:    claimPub,
		Signature: make([]byte, ML_DSA_87_SIG_BYTES), // wrong signature but correct length
	}

	err := ValidateHTLCSpend(entry, path, sig, digest, 0, 0)
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_SIG_INVALID {
		t.Fatalf("code=%s, want %s", got, TX_ERR_SIG_INVALID)
	}
}

func TestValidateHTLCSpend_ClaimOK(t *testing.T) {
	var digest [32]byte
	digest[0] = 0x99

	claimKP := mustMLDSA87Keypair(t)
	refundKP := mustMLDSA87Keypair(t)
	claimPub := claimKP.PubkeyBytes()
	refundPub := refundKP.PubkeyBytes()
	claimKeyID := sha3_256(claimPub)
	refundKeyID := sha3_256(refundPub)

	preimage := []byte("rubin-htlc-claim-ok")
	entry := makeHTLCEntry(sha3_256(preimage), LOCK_MODE_HEIGHT, 1, claimKeyID, refundKeyID)

	path := WitnessItem{
		SuiteID:   SUITE_ID_SENTINEL,
		Pubkey:    claimKeyID[:],
		Signature: encodeHTLCClaimPayload(preimage),
	}
	claimSig, err := claimKP.SignDigest32(digest)
	if err != nil {
		t.Fatalf("SignDigest32: %v", err)
	}
	sig := WitnessItem{
		SuiteID:   SUITE_ID_ML_DSA_87,
		Pubkey:    claimPub,
		Signature: claimSig,
	}

	if err := ValidateHTLCSpend(entry, path, sig, digest, 0, 0); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
