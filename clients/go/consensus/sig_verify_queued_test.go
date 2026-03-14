package consensus

import (
	"testing"
)

// ─────────────────────────────────────────────────────────────────────────────
// validateHTLCSpendQ tests
// ─────────────────────────────────────────────────────────────────────────────

func TestValidateHTLCSpendQ_ClaimOK(t *testing.T) {
	claimKP := mustMLDSA87Keypair(t)
	refundKP := mustMLDSA87Keypair(t)
	claimPub := claimKP.PubkeyBytes()
	refundPub := refundKP.PubkeyBytes()
	claimKeyID := sha3_256(claimPub)
	refundKeyID := sha3_256(refundPub)

	preimage := []byte("rubin-htlc-queued-ok")
	entry := makeHTLCEntry(sha3_256(preimage), LOCK_MODE_HEIGHT, 1, claimKeyID, refundKeyID)

	path := WitnessItem{
		SuiteID:   SUITE_ID_SENTINEL,
		Pubkey:    claimKeyID[:],
		Signature: encodeHTLCClaimPayload(preimage),
	}

	tx, inputIndex, inputValue, chainID := testSighashContextTx()
	cache, err := NewSighashV1PrehashCache(tx)
	if err != nil {
		t.Fatalf("cache: %v", err)
	}
	digest, err := SighashV1DigestWithCache(cache, inputIndex, inputValue, chainID, SIGHASH_ALL)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	claimSig, err := claimKP.SignDigest32(digest)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	claimSig = append(claimSig, SIGHASH_ALL)
	sig := WitnessItem{
		SuiteID:   SUITE_ID_ML_DSA_87,
		Pubkey:    claimPub,
		Signature: claimSig,
	}

	// Test with queue: should defer sig and return nil.
	q := NewSigCheckQueue(1)
	err = validateHTLCSpendQ(entry, path, sig, tx, inputIndex, inputValue, chainID, 0, 0, cache, q)
	if err != nil {
		t.Fatalf("queued HTLC claim: %v", err)
	}
	if q.Len() != 1 {
		t.Fatalf("expected 1 queued task, got %d", q.Len())
	}
	if err := q.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}

	// Test with nil queue: should verify inline.
	err = validateHTLCSpendQ(entry, path, sig, tx, inputIndex, inputValue, chainID, 0, 0, cache, nil)
	if err != nil {
		t.Fatalf("inline HTLC claim: %v", err)
	}
}

func TestValidateHTLCSpendQ_RefundOK(t *testing.T) {
	claimKP := mustMLDSA87Keypair(t)
	refundKP := mustMLDSA87Keypair(t)
	claimPub := claimKP.PubkeyBytes()
	refundPub := refundKP.PubkeyBytes()
	claimKeyID := sha3_256(claimPub)
	refundKeyID := sha3_256(refundPub)

	preimage := []byte("rubin-htlc-refund-q")
	entry := makeHTLCEntry(sha3_256(preimage), LOCK_MODE_HEIGHT, 10, claimKeyID, refundKeyID)

	path := WitnessItem{
		SuiteID:   SUITE_ID_SENTINEL,
		Pubkey:    refundKeyID[:],
		Signature: []byte{0x01}, // refund path
	}

	tx, inputIndex, inputValue, chainID := testSighashContextTx()
	cache, err := NewSighashV1PrehashCache(tx)
	if err != nil {
		t.Fatalf("cache: %v", err)
	}
	digest, err := SighashV1DigestWithCache(cache, inputIndex, inputValue, chainID, SIGHASH_ALL)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	refundSig, err := refundKP.SignDigest32(digest)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	refundSig = append(refundSig, SIGHASH_ALL)
	sig := WitnessItem{
		SuiteID:   SUITE_ID_ML_DSA_87,
		Pubkey:    refundPub,
		Signature: refundSig,
	}

	// blockHeight=10 meets lock_value=10
	q := NewSigCheckQueue(1)
	err = validateHTLCSpendQ(entry, path, sig, tx, inputIndex, inputValue, chainID, 10, 0, cache, q)
	if err != nil {
		t.Fatalf("queued HTLC refund: %v", err)
	}
	if err := q.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
}

func TestValidateHTLCSpendQ_TimelockNotMet(t *testing.T) {
	claimKP := mustMLDSA87Keypair(t)
	refundKP := mustMLDSA87Keypair(t)
	claimKeyID := sha3_256(claimKP.PubkeyBytes())
	refundKeyID := sha3_256(refundKP.PubkeyBytes())

	preimage := []byte("rubin-htlc-timelock")
	entry := makeHTLCEntry(sha3_256(preimage), LOCK_MODE_HEIGHT, 100, claimKeyID, refundKeyID)

	path := WitnessItem{
		SuiteID:   SUITE_ID_SENTINEL,
		Pubkey:    refundKeyID[:],
		Signature: []byte{0x01},
	}
	sig := WitnessItem{
		SuiteID:   SUITE_ID_ML_DSA_87,
		Pubkey:    refundKP.PubkeyBytes(),
		Signature: make([]byte, ML_DSA_87_SIG_BYTES+1),
	}

	tx, inputIndex, inputValue, chainID := testSighashContextTx()
	cache, _ := NewSighashV1PrehashCache(tx)

	// blockHeight=50 < lock_value=100
	q := NewSigCheckQueue(1)
	err := validateHTLCSpendQ(entry, path, sig, tx, inputIndex, inputValue, chainID, 50, 0, cache, q)
	if err == nil {
		t.Fatal("expected timelock error")
	}
	if !isTxErrCode(err, TX_ERR_TIMELOCK_NOT_MET) {
		t.Fatalf("expected TX_ERR_TIMELOCK_NOT_MET, got: %v", err)
	}
	// Queue should be empty (error returned before queueing).
	if q.Len() != 0 {
		t.Fatalf("expected empty queue, got %d", q.Len())
	}
}

func TestValidateHTLCSpendQ_PreImageMismatch(t *testing.T) {
	claimKP := mustMLDSA87Keypair(t)
	refundKP := mustMLDSA87Keypair(t)
	claimKeyID := sha3_256(claimKP.PubkeyBytes())
	refundKeyID := sha3_256(refundKP.PubkeyBytes())

	preimage := []byte("correct-preimage-htlc")
	wrongPreimage := []byte("wrong-preimage-match")
	entry := makeHTLCEntry(sha3_256(preimage), LOCK_MODE_HEIGHT, 1, claimKeyID, refundKeyID)

	path := WitnessItem{
		SuiteID:   SUITE_ID_SENTINEL,
		Pubkey:    claimKeyID[:],
		Signature: encodeHTLCClaimPayload(wrongPreimage),
	}
	sig := WitnessItem{
		SuiteID:   SUITE_ID_ML_DSA_87,
		Pubkey:    claimKP.PubkeyBytes(),
		Signature: make([]byte, ML_DSA_87_SIG_BYTES+1),
	}

	tx, inputIndex, inputValue, chainID := testSighashContextTx()
	cache, _ := NewSighashV1PrehashCache(tx)

	q := NewSigCheckQueue(1)
	err := validateHTLCSpendQ(entry, path, sig, tx, inputIndex, inputValue, chainID, 0, 0, cache, q)
	if err == nil {
		t.Fatal("expected preimage mismatch error")
	}
	if !isTxErrCode(err, TX_ERR_SIG_INVALID) {
		t.Fatalf("expected TX_ERR_SIG_INVALID, got: %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// validateThresholdSigSpendQ tests
// ─────────────────────────────────────────────────────────────────────────────

func TestValidateThresholdSigSpendQ_OneOfTwo(t *testing.T) {
	kp1 := mustMLDSA87Keypair(t)
	kp2 := mustMLDSA87Keypair(t)
	keyID1 := sha3_256(kp1.PubkeyBytes())
	keyID2 := sha3_256(kp2.PubkeyBytes())

	tx, inputIndex, inputValue, chainID := testSighashContextTx()
	cache, err := NewSighashV1PrehashCache(tx)
	if err != nil {
		t.Fatalf("cache: %v", err)
	}
	digest, err := SighashV1DigestWithCache(cache, inputIndex, inputValue, chainID, SIGHASH_ALL)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}

	sig1, err := kp1.SignDigest32(digest)
	if err != nil {
		t.Fatalf("sign1: %v", err)
	}
	sig1 = append(sig1, SIGHASH_ALL)

	keys := [][32]byte{keyID1, keyID2}
	ws := []WitnessItem{
		{SuiteID: SUITE_ID_ML_DSA_87, Pubkey: kp1.PubkeyBytes(), Signature: sig1},
		{SuiteID: SUITE_ID_SENTINEL, Pubkey: nil, Signature: nil}, // skip slot 2
	}

	q := NewSigCheckQueue(1)
	err = validateThresholdSigSpendQ(keys, 1, ws, tx, inputIndex, inputValue, chainID, 0, cache, q, "TEST-MULTISIG")
	if err != nil {
		t.Fatalf("threshold 1-of-2 queued: %v", err)
	}
	if q.Len() != 1 {
		t.Fatalf("expected 1 queued task, got %d", q.Len())
	}
	if err := q.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
}

func TestValidateThresholdSigSpendQ_ThresholdNotMet(t *testing.T) {
	kp1 := mustMLDSA87Keypair(t)
	kp2 := mustMLDSA87Keypair(t)
	keyID1 := sha3_256(kp1.PubkeyBytes())
	keyID2 := sha3_256(kp2.PubkeyBytes())

	tx, inputIndex, inputValue, chainID := testSighashContextTx()
	cache, _ := NewSighashV1PrehashCache(tx)

	keys := [][32]byte{keyID1, keyID2}
	ws := []WitnessItem{
		{SuiteID: SUITE_ID_SENTINEL, Pubkey: nil, Signature: nil},
		{SuiteID: SUITE_ID_SENTINEL, Pubkey: nil, Signature: nil},
	}

	q := NewSigCheckQueue(1)
	err := validateThresholdSigSpendQ(keys, 1, ws, tx, inputIndex, inputValue, chainID, 0, cache, q, "TEST-MULTISIG")
	if err == nil {
		t.Fatal("expected threshold not met error")
	}
	if !isTxErrCode(err, TX_ERR_SIG_INVALID) {
		t.Fatalf("expected TX_ERR_SIG_INVALID, got: %v", err)
	}
}

func TestValidateThresholdSigSpendQ_SlotMismatch(t *testing.T) {
	kp1 := mustMLDSA87Keypair(t)
	keyID1 := sha3_256(kp1.PubkeyBytes())

	tx, inputIndex, inputValue, chainID := testSighashContextTx()
	cache, _ := NewSighashV1PrehashCache(tx)

	keys := [][32]byte{keyID1}
	ws := []WitnessItem{
		{SuiteID: SUITE_ID_SENTINEL},
		{SuiteID: SUITE_ID_SENTINEL},
	}

	q := NewSigCheckQueue(1)
	err := validateThresholdSigSpendQ(keys, 1, ws, tx, inputIndex, inputValue, chainID, 0, cache, q, "TEST")
	if err == nil {
		t.Fatal("expected slot mismatch error")
	}
	if !isTxErrCode(err, TX_ERR_PARSE) {
		t.Fatalf("expected TX_ERR_PARSE, got: %v", err)
	}
}

func TestValidateThresholdSigSpendQ_InvalidSuiteID(t *testing.T) {
	kp1 := mustMLDSA87Keypair(t)
	keyID1 := sha3_256(kp1.PubkeyBytes())

	tx, inputIndex, inputValue, chainID := testSighashContextTx()
	cache, _ := NewSighashV1PrehashCache(tx)

	keys := [][32]byte{keyID1}
	ws := []WitnessItem{
		{SuiteID: 0xFF, Pubkey: kp1.PubkeyBytes(), Signature: make([]byte, 10)},
	}

	q := NewSigCheckQueue(1)
	err := validateThresholdSigSpendQ(keys, 1, ws, tx, inputIndex, inputValue, chainID, 0, cache, q, "TEST")
	if err == nil {
		t.Fatal("expected suite invalid error")
	}
	if !isTxErrCode(err, TX_ERR_SIG_ALG_INVALID) {
		t.Fatalf("expected TX_ERR_SIG_ALG_INVALID, got: %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// validateCoreStealthSpendQ tests
// ─────────────────────────────────────────────────────────────────────────────

func makeStealthCovenantData(keyID [32]byte) []byte {
	// Stealth covenant data = [ML_KEM_1024_CT_BYTES ciphertext][32 bytes one_time_key_id]
	data := make([]byte, MAX_STEALTH_COVENANT_DATA)
	// First ML_KEM_1024_CT_BYTES are ciphertext (zero-filled for test).
	// Last 32 bytes are one_time_key_id.
	copy(data[ML_KEM_1024_CT_BYTES:], keyID[:])
	return data
}

func TestValidateCoreStealthSpendQ_OK(t *testing.T) {
	kp := mustMLDSA87Keypair(t)
	keyID := sha3_256(kp.PubkeyBytes())

	entry := UtxoEntry{
		Value:        100,
		CovenantType: COV_TYPE_CORE_STEALTH,
		CovenantData: makeStealthCovenantData(keyID),
	}

	tx, inputIndex, inputValue, chainID := testSighashContextTx()
	cache, err := NewSighashV1PrehashCache(tx)
	if err != nil {
		t.Fatalf("cache: %v", err)
	}
	digest, err := SighashV1DigestWithCache(cache, inputIndex, inputValue, chainID, SIGHASH_ALL)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	sig, err := kp.SignDigest32(digest)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	sig = append(sig, SIGHASH_ALL)

	w := WitnessItem{
		SuiteID:   SUITE_ID_ML_DSA_87,
		Pubkey:    kp.PubkeyBytes(),
		Signature: sig,
	}

	q := NewSigCheckQueue(1)
	err = validateCoreStealthSpendQ(entry, w, tx, inputIndex, inputValue, chainID, 0, cache, q)
	if err != nil {
		t.Fatalf("queued stealth: %v", err)
	}
	if q.Len() != 1 {
		t.Fatalf("expected 1 queued task, got %d", q.Len())
	}
	if err := q.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
}

func TestValidateCoreStealthSpendQ_InvalidSuite(t *testing.T) {
	kp := mustMLDSA87Keypair(t)
	keyID := sha3_256(kp.PubkeyBytes())

	entry := UtxoEntry{
		Value:        100,
		CovenantType: COV_TYPE_CORE_STEALTH,
		CovenantData: makeStealthCovenantData(keyID),
	}

	tx, inputIndex, inputValue, chainID := testSighashContextTx()
	cache, _ := NewSighashV1PrehashCache(tx)

	w := WitnessItem{
		SuiteID:   0xFF, // invalid
		Pubkey:    kp.PubkeyBytes(),
		Signature: make([]byte, ML_DSA_87_SIG_BYTES+1),
	}

	q := NewSigCheckQueue(1)
	err := validateCoreStealthSpendQ(entry, w, tx, inputIndex, inputValue, chainID, 0, cache, q)
	if err == nil {
		t.Fatal("expected suite invalid error")
	}
	if !isTxErrCode(err, TX_ERR_SIG_ALG_INVALID) {
		t.Fatalf("expected TX_ERR_SIG_ALG_INVALID, got: %v", err)
	}
}

func TestValidateCoreStealthSpendQ_BadCovenantData(t *testing.T) {
	entry := UtxoEntry{
		Value:        100,
		CovenantType: COV_TYPE_CORE_STEALTH,
		CovenantData: []byte{0x01, 0x02}, // too short
	}

	tx, inputIndex, inputValue, chainID := testSighashContextTx()
	cache, _ := NewSighashV1PrehashCache(tx)

	w := WitnessItem{
		SuiteID:   SUITE_ID_ML_DSA_87,
		Pubkey:    make([]byte, ML_DSA_87_PUBKEY_BYTES),
		Signature: make([]byte, ML_DSA_87_SIG_BYTES+1),
	}

	q := NewSigCheckQueue(1)
	err := validateCoreStealthSpendQ(entry, w, tx, inputIndex, inputValue, chainID, 0, cache, q)
	if err == nil {
		t.Fatal("expected covenant parse error")
	}
}
