package consensus

import (
	"strings"
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
	err = validateHTLCSpendQ(entry, path, sig, tx, inputIndex, inputValue, chainID, 0, 0, cache, q, nil, nil)
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
	err = validateHTLCSpendQ(entry, path, sig, tx, inputIndex, inputValue, chainID, 0, 0, cache, nil, nil, nil)
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
	err = validateHTLCSpendQ(entry, path, sig, tx, inputIndex, inputValue, chainID, 10, 0, cache, q, nil, nil)
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
	err := validateHTLCSpendQ(entry, path, sig, tx, inputIndex, inputValue, chainID, 50, 0, cache, q, nil, nil)
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
	err := validateHTLCSpendQ(entry, path, sig, tx, inputIndex, inputValue, chainID, 0, 0, cache, q, nil, nil)
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
	err = validateThresholdSigSpendQ(keys, 1, ws, tx, inputIndex, inputValue, chainID, 0, cache, q, "TEST-MULTISIG", nil, nil)
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
	err := validateThresholdSigSpendQ(keys, 1, ws, tx, inputIndex, inputValue, chainID, 0, cache, q, "TEST-MULTISIG", nil, nil)
	if err == nil {
		t.Fatal("expected threshold not met error")
	}
	if !isTxErrCode(err, TX_ERR_SIG_INVALID) {
		t.Fatalf("expected TX_ERR_SIG_INVALID, got: %v", err)
	}
}

func TestValidateThresholdSigSpendQ_RollbackOnThresholdFailure(t *testing.T) {
	kp1 := mustMLDSA87Keypair(t)
	kp2 := mustMLDSA87Keypair(t)
	keyID1 := sha3_256(kp1.PubkeyBytes())
	keyID2 := sha3_256(kp2.PubkeyBytes())

	tx, inputIndex, inputValue, chainID := testSighashContextTx()
	cache, _ := NewSighashV1PrehashCache(tx)
	sig1 := signDigestWithSighashType(t, kp1, tx, inputIndex, inputValue, chainID, SIGHASH_ALL)

	keys := [][32]byte{keyID1, keyID2}
	ws := []WitnessItem{
		{SuiteID: SUITE_ID_ML_DSA_87, Pubkey: kp1.PubkeyBytes(), Signature: sig1},
		{SuiteID: SUITE_ID_SENTINEL, Pubkey: nil, Signature: nil},
	}

	q := NewSigCheckQueue(1)
	err := validateThresholdSigSpendQ(keys, 2, ws, tx, inputIndex, inputValue, chainID, 0, cache, q, "TEST-MULTISIG", nil, nil)
	if err == nil {
		t.Fatal("expected threshold not met error")
	}
	if !isTxErrCode(err, TX_ERR_SIG_INVALID) {
		t.Fatalf("expected TX_ERR_SIG_INVALID, got: %v", err)
	}
	if q.Len() != 0 {
		t.Fatalf("expected rollback to clear threshold task, got %d queued tasks", q.Len())
	}
}

func TestValidateThresholdSigSpendQ_RollbackPreservesExistingQueue(t *testing.T) {
	existingKP := mustMLDSA87Keypair(t)
	existingDigest := [32]byte{0xA5}
	existingSig, err := existingKP.SignDigest32(existingDigest)
	if err != nil {
		t.Fatalf("existing sign: %v", err)
	}

	q := NewSigCheckQueue(1)
	q.Push(SUITE_ID_ML_DSA_87, existingKP.PubkeyBytes(), existingSig, existingDigest, txerr(TX_ERR_SIG_INVALID, "existing invalid"))

	kp1 := mustMLDSA87Keypair(t)
	kp2 := mustMLDSA87Keypair(t)
	keyID1 := sha3_256(kp1.PubkeyBytes())
	keyID2 := sha3_256(kp2.PubkeyBytes())

	tx, inputIndex, inputValue, chainID := testSighashContextTx()
	cache, _ := NewSighashV1PrehashCache(tx)
	sig1 := signDigestWithSighashType(t, kp1, tx, inputIndex, inputValue, chainID, SIGHASH_ALL)

	keys := [][32]byte{keyID1, keyID2}
	ws := []WitnessItem{
		{SuiteID: SUITE_ID_ML_DSA_87, Pubkey: kp1.PubkeyBytes(), Signature: sig1},
		{SuiteID: SUITE_ID_SENTINEL, Pubkey: nil, Signature: nil},
	}

	err = validateThresholdSigSpendQ(keys, 2, ws, tx, inputIndex, inputValue, chainID, 0, cache, q, "TEST-MULTISIG", nil, nil)
	if err == nil {
		t.Fatal("expected threshold not met error")
	}
	if q.Len() != 1 {
		t.Fatalf("expected rollback to preserve prior task only, got %d queued tasks", q.Len())
	}
	if err := q.Flush(); err != nil {
		t.Fatalf("prior queued task should still flush: %v", err)
	}
}

func TestValidateThresholdSigSpendQ_RollbackOnLateThresholdErrors(t *testing.T) {
	kp1 := mustMLDSA87Keypair(t)
	kp2 := mustMLDSA87Keypair(t)
	keyID1 := sha3_256(kp1.PubkeyBytes())
	keyID2 := sha3_256(kp2.PubkeyBytes())

	tx, inputIndex, inputValue, chainID := testSighashContextTx()
	cache, _ := NewSighashV1PrehashCache(tx)
	sig1 := signDigestWithSighashType(t, kp1, tx, inputIndex, inputValue, chainID, SIGHASH_ALL)
	sig2 := signDigestWithSighashType(t, kp2, tx, inputIndex, inputValue, chainID, SIGHASH_ALL)
	invalidSighashSig := append([]byte(nil), sig2...)
	invalidSighashSig[len(invalidSighashSig)-1] = 0x00

	existingKP := mustMLDSA87Keypair(t)
	existingDigest := [32]byte{0xA6}
	existingSig, err := existingKP.SignDigest32(existingDigest)
	if err != nil {
		t.Fatalf("existing sign: %v", err)
	}

	validFirst := WitnessItem{SuiteID: SUITE_ID_ML_DSA_87, Pubkey: kp1.PubkeyBytes(), Signature: sig1}
	tests := []struct {
		name       string
		keys       [][32]byte
		second     WitnessItem
		wantErr    ErrorCode
		wantErrMsg string
	}{
		{
			name:       "sentinel_with_data",
			keys:       [][32]byte{keyID1, keyID2},
			second:     WitnessItem{SuiteID: SUITE_ID_SENTINEL, Pubkey: []byte{0x01}, Signature: nil},
			wantErr:    TX_ERR_PARSE,
			wantErrMsg: "SENTINEL witness must be keyless",
		},
		{
			name:       "invalid_suite",
			keys:       [][32]byte{keyID1, keyID2},
			second:     WitnessItem{SuiteID: 0xFE, Pubkey: kp2.PubkeyBytes(), Signature: sig2},
			wantErr:    TX_ERR_SIG_ALG_INVALID,
			wantErrMsg: "suite not in native spend set",
		},
		{
			name:       "noncanonical_lengths",
			keys:       [][32]byte{keyID1, keyID2},
			second:     WitnessItem{SuiteID: SUITE_ID_ML_DSA_87, Pubkey: kp2.PubkeyBytes(), Signature: sig2[:ML_DSA_87_SIG_BYTES]},
			wantErr:    TX_ERR_SIG_NONCANONICAL,
			wantErrMsg: "non-canonical witness item lengths",
		},
		{
			name:       "key_binding_mismatch",
			keys:       [][32]byte{keyID1, [32]byte{0xEE}},
			second:     WitnessItem{SuiteID: SUITE_ID_ML_DSA_87, Pubkey: kp2.PubkeyBytes(), Signature: sig2},
			wantErr:    TX_ERR_SIG_INVALID,
			wantErrMsg: "key binding mismatch",
		},
		{
			name:       "invalid_sighash_type",
			keys:       [][32]byte{keyID1, keyID2},
			second:     WitnessItem{SuiteID: SUITE_ID_ML_DSA_87, Pubkey: kp2.PubkeyBytes(), Signature: invalidSighashSig},
			wantErr:    TX_ERR_SIGHASH_TYPE_INVALID,
			wantErrMsg: "invalid sighash_type",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			q := NewSigCheckQueue(1)
			q.Push(SUITE_ID_ML_DSA_87, existingKP.PubkeyBytes(), existingSig, existingDigest, txerr(TX_ERR_SIG_INVALID, "existing invalid"))
			preLen := q.Len()

			err := validateThresholdSigSpendQ(tc.keys, 2, []WitnessItem{validFirst, tc.second}, tx, inputIndex, inputValue, chainID, 0, cache, q, "TEST-MULTISIG", nil, nil)
			if err == nil {
				t.Fatal("expected late threshold error")
			}
			if !isTxErrCode(err, tc.wantErr) {
				t.Fatalf("expected %s, got: %v", tc.wantErr, err)
			}
			if tc.wantErrMsg != "" && !strings.Contains(err.Error(), tc.wantErrMsg) {
				t.Fatalf("expected error containing %q, got: %v", tc.wantErrMsg, err)
			}
			if q.Len() != preLen {
				t.Fatalf("expected rollback to pre-call queue length %d, got %d", preLen, q.Len())
			}
			if err := q.Flush(); err != nil {
				t.Fatalf("pre-existing queued task should still flush: %v", err)
			}
		})
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
	err := validateThresholdSigSpendQ(keys, 1, ws, tx, inputIndex, inputValue, chainID, 0, cache, q, "TEST", nil, nil)
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
	err := validateThresholdSigSpendQ(keys, 1, ws, tx, inputIndex, inputValue, chainID, 0, cache, q, "TEST", nil, nil)
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
	err = validateCoreStealthSpendQ(entry, w, tx, inputIndex, inputValue, chainID, 0, cache, q, nil, nil)
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
	err := validateCoreStealthSpendQ(entry, w, tx, inputIndex, inputValue, chainID, 0, cache, q, nil, nil)
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
	err := validateCoreStealthSpendQ(entry, w, tx, inputIndex, inputValue, chainID, 0, cache, q, nil, nil)
	if err == nil {
		t.Fatal("expected covenant parse error")
	}
}

func TestValidateCoreStealthSpendQ_NonCanonicalLengths(t *testing.T) {
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
		SuiteID:   SUITE_ID_ML_DSA_87,
		Pubkey:    make([]byte, 10), // wrong length
		Signature: make([]byte, ML_DSA_87_SIG_BYTES+1),
	}

	q := NewSigCheckQueue(1)
	err := validateCoreStealthSpendQ(entry, w, tx, inputIndex, inputValue, chainID, 0, cache, q, nil, nil)
	if err == nil {
		t.Fatal("expected non-canonical error")
	}
	if !isTxErrCode(err, TX_ERR_SIG_NONCANONICAL) {
		t.Fatalf("expected TX_ERR_SIG_NONCANONICAL, got: %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// validateP2PKSpendQ error-path tests
// ─────────────────────────────────────────────────────────────────────────────

func TestValidateP2PKSpendQ_SuiteInvalid(t *testing.T) {
	kp := mustMLDSA87Keypair(t)
	entry := UtxoEntry{
		Value:        100,
		CovenantType: COV_TYPE_P2PK,
		CovenantData: p2pkCovenantDataForPubkey(kp.PubkeyBytes()),
	}

	tx, inputIndex, inputValue, chainID := testSighashContextTx()
	cache, _ := NewSighashV1PrehashCache(tx)

	w := WitnessItem{
		SuiteID:   0xFF, // not ML-DSA-87
		Pubkey:    kp.PubkeyBytes(),
		Signature: make([]byte, ML_DSA_87_SIG_BYTES+1),
	}

	q := NewSigCheckQueue(1)
	err := validateP2PKSpendQ(entry, w, tx, inputIndex, inputValue, chainID, 0, cache, q, nil, nil)
	if err == nil {
		t.Fatal("expected suite invalid error")
	}
	if !isTxErrCode(err, TX_ERR_SIG_ALG_INVALID) {
		t.Fatalf("expected TX_ERR_SIG_ALG_INVALID, got: %v", err)
	}
}

func TestValidateP2PKSpendQ_NonCanonicalLengths(t *testing.T) {
	kp := mustMLDSA87Keypair(t)
	entry := UtxoEntry{
		Value:        100,
		CovenantType: COV_TYPE_P2PK,
		CovenantData: p2pkCovenantDataForPubkey(kp.PubkeyBytes()),
	}

	tx, inputIndex, inputValue, chainID := testSighashContextTx()
	cache, _ := NewSighashV1PrehashCache(tx)

	w := WitnessItem{
		SuiteID:   SUITE_ID_ML_DSA_87,
		Pubkey:    make([]byte, 10), // wrong length
		Signature: make([]byte, ML_DSA_87_SIG_BYTES+1),
	}

	q := NewSigCheckQueue(1)
	err := validateP2PKSpendQ(entry, w, tx, inputIndex, inputValue, chainID, 0, cache, q, nil, nil)
	if err == nil {
		t.Fatal("expected non-canonical error")
	}
	if !isTxErrCode(err, TX_ERR_SIG_NONCANONICAL) {
		t.Fatalf("expected TX_ERR_SIG_NONCANONICAL, got: %v", err)
	}
}

func TestValidateP2PKSpendQ_CovenantDataInvalid(t *testing.T) {
	kp := mustMLDSA87Keypair(t)
	// Use ML-DSA-87 suite but wrong covenant_data (e.g. 0xFF suite byte).
	badCovData := make([]byte, MAX_P2PK_COVENANT_DATA)
	badCovData[0] = 0xFF // mismatched suite_id
	keyID := sha3_256(kp.PubkeyBytes())
	copy(badCovData[1:33], keyID[:])

	entry := UtxoEntry{
		Value:        100,
		CovenantType: COV_TYPE_P2PK,
		CovenantData: badCovData,
	}

	tx, inputIndex, inputValue, chainID := testSighashContextTx()
	cache, _ := NewSighashV1PrehashCache(tx)

	w := WitnessItem{
		SuiteID:   SUITE_ID_ML_DSA_87,
		Pubkey:    kp.PubkeyBytes(),
		Signature: make([]byte, ML_DSA_87_SIG_BYTES+1),
	}

	q := NewSigCheckQueue(1)
	err := validateP2PKSpendQ(entry, w, tx, inputIndex, inputValue, chainID, 0, cache, q, nil, nil)
	if err == nil {
		t.Fatal("expected covenant_data invalid error")
	}
	if !isTxErrCode(err, TX_ERR_COVENANT_TYPE_INVALID) {
		t.Fatalf("expected TX_ERR_COVENANT_TYPE_INVALID, got: %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// validateHTLCSpendQ additional error-path tests
// ─────────────────────────────────────────────────────────────────────────────

// htlcRefundKeyID returns a distinct refund key_id for HTLC tests that only need
// a valid entry (claim/refund must differ per ParseHTLCCovenantData).
func htlcRefundKeyID() [32]byte {
	var k [32]byte
	k[0] = 0xFE
	k[1] = 0xDC
	return k
}

func TestValidateHTLCSpendQ_SelectorSuiteInvalid(t *testing.T) {
	kp := mustMLDSA87Keypair(t)
	claimKeyID := sha3_256(kp.PubkeyBytes())

	entry := makeHTLCEntry(sha3_256([]byte("test-preimage-1234")), LOCK_MODE_HEIGHT, 1, claimKeyID, htlcRefundKeyID())

	tx, inputIndex, inputValue, chainID := testSighashContextTx()
	cache, _ := NewSighashV1PrehashCache(tx)

	path := WitnessItem{
		SuiteID:   SUITE_ID_ML_DSA_87, // wrong — should be SENTINEL
		Pubkey:    claimKeyID[:],
		Signature: encodeHTLCClaimPayload([]byte("test-preimage-1234")),
	}
	sig := WitnessItem{SuiteID: SUITE_ID_ML_DSA_87, Pubkey: make([]byte, ML_DSA_87_PUBKEY_BYTES), Signature: make([]byte, ML_DSA_87_SIG_BYTES+1)}

	q := NewSigCheckQueue(1)
	err := validateHTLCSpendQ(entry, path, sig, tx, inputIndex, inputValue, chainID, 0, 0, cache, q, nil, nil)
	if err == nil {
		t.Fatal("expected selector suite error")
	}
}

func TestValidateHTLCSpendQ_SelectorKeyIDLengthInvalid(t *testing.T) {
	kp := mustMLDSA87Keypair(t)
	claimKeyID := sha3_256(kp.PubkeyBytes())

	entry := makeHTLCEntry(sha3_256([]byte("test-preimage-1234")), LOCK_MODE_HEIGHT, 1, claimKeyID, htlcRefundKeyID())

	tx, inputIndex, inputValue, chainID := testSighashContextTx()
	cache, _ := NewSighashV1PrehashCache(tx)

	path := WitnessItem{
		SuiteID:   SUITE_ID_SENTINEL,
		Pubkey:    []byte{0x01, 0x02}, // wrong — must be 32 bytes
		Signature: encodeHTLCClaimPayload([]byte("test-preimage-1234")),
	}
	sig := WitnessItem{SuiteID: SUITE_ID_ML_DSA_87, Pubkey: make([]byte, ML_DSA_87_PUBKEY_BYTES), Signature: make([]byte, ML_DSA_87_SIG_BYTES+1)}

	q := NewSigCheckQueue(1)
	err := validateHTLCSpendQ(entry, path, sig, tx, inputIndex, inputValue, chainID, 0, 0, cache, q, nil, nil)
	if err == nil {
		t.Fatal("expected key_id length error")
	}
}

func TestValidateHTLCSpendQ_ClaimKeyIDMismatch(t *testing.T) {
	kp := mustMLDSA87Keypair(t)
	refundKP := mustMLDSA87Keypair(t)
	claimKeyID := sha3_256(kp.PubkeyBytes())
	refundKeyID := sha3_256(refundKP.PubkeyBytes())
	var wrongKeyID [32]byte
	wrongKeyID[0] = 0xFF

	entry := makeHTLCEntry(sha3_256([]byte("test-preimage-1234")), LOCK_MODE_HEIGHT, 1, claimKeyID, refundKeyID)

	tx, inputIndex, inputValue, chainID := testSighashContextTx()
	cache, _ := NewSighashV1PrehashCache(tx)

	path := WitnessItem{
		SuiteID:   SUITE_ID_SENTINEL,
		Pubkey:    wrongKeyID[:], // doesn't match claim_key_id
		Signature: encodeHTLCClaimPayload([]byte("test-preimage-1234")),
	}
	sig := WitnessItem{SuiteID: SUITE_ID_ML_DSA_87, Pubkey: make([]byte, ML_DSA_87_PUBKEY_BYTES), Signature: make([]byte, ML_DSA_87_SIG_BYTES+1)}

	q := NewSigCheckQueue(1)
	err := validateHTLCSpendQ(entry, path, sig, tx, inputIndex, inputValue, chainID, 0, 0, cache, q, nil, nil)
	if err == nil {
		t.Fatal("expected claim key_id mismatch error")
	}
	if !isTxErrCode(err, TX_ERR_SIG_INVALID) {
		t.Fatalf("expected TX_ERR_SIG_INVALID, got: %v", err)
	}
}

func TestValidateHTLCSpendQ_UnknownPath(t *testing.T) {
	kp := mustMLDSA87Keypair(t)
	claimKeyID := sha3_256(kp.PubkeyBytes())

	entry := makeHTLCEntry(sha3_256([]byte("test-preimage-1234")), LOCK_MODE_HEIGHT, 1, claimKeyID, htlcRefundKeyID())

	tx, inputIndex, inputValue, chainID := testSighashContextTx()
	cache, _ := NewSighashV1PrehashCache(tx)

	path := WitnessItem{
		SuiteID:   SUITE_ID_SENTINEL,
		Pubkey:    claimKeyID[:],
		Signature: []byte{0x42}, // unknown path ID
	}
	sig := WitnessItem{SuiteID: SUITE_ID_ML_DSA_87, Pubkey: make([]byte, ML_DSA_87_PUBKEY_BYTES), Signature: make([]byte, ML_DSA_87_SIG_BYTES+1)}

	q := NewSigCheckQueue(1)
	err := validateHTLCSpendQ(entry, path, sig, tx, inputIndex, inputValue, chainID, 0, 0, cache, q, nil, nil)
	if err == nil {
		t.Fatal("expected unknown path error")
	}
}

func TestValidateHTLCSpendQ_RefundKeyIDMismatch(t *testing.T) {
	kp := mustMLDSA87Keypair(t)
	claimKeyID := sha3_256(kp.PubkeyBytes())
	var refundKeyID, wrongRefundKey [32]byte
	refundKeyID[0] = 0xAA
	wrongRefundKey[0] = 0xBB

	entry := makeHTLCEntry(sha3_256([]byte("test-preimage-1234")), LOCK_MODE_HEIGHT, 10, claimKeyID, refundKeyID)

	tx, inputIndex, inputValue, chainID := testSighashContextTx()
	cache, _ := NewSighashV1PrehashCache(tx)

	path := WitnessItem{
		SuiteID:   SUITE_ID_SENTINEL,
		Pubkey:    wrongRefundKey[:], // doesn't match refund_key_id
		Signature: []byte{0x01},      // refund path
	}
	sig := WitnessItem{SuiteID: SUITE_ID_ML_DSA_87, Pubkey: make([]byte, ML_DSA_87_PUBKEY_BYTES), Signature: make([]byte, ML_DSA_87_SIG_BYTES+1)}

	q := NewSigCheckQueue(1)
	err := validateHTLCSpendQ(entry, path, sig, tx, inputIndex, inputValue, chainID, 10, 0, cache, q, nil, nil)
	if err == nil {
		t.Fatal("expected refund key_id mismatch error")
	}
	if !isTxErrCode(err, TX_ERR_SIG_INVALID) {
		t.Fatalf("expected TX_ERR_SIG_INVALID, got: %v", err)
	}
}

func TestValidateHTLCSpendQ_TimestampLockNotMet(t *testing.T) {
	kp := mustMLDSA87Keypair(t)
	refundKP := mustMLDSA87Keypair(t)
	claimKeyID := sha3_256(kp.PubkeyBytes())
	refundKeyID := sha3_256(refundKP.PubkeyBytes())

	entry := makeHTLCEntry(sha3_256([]byte("test-preimage-1234")), LOCK_MODE_TIMESTAMP, 100, claimKeyID, refundKeyID)

	tx, inputIndex, inputValue, chainID := testSighashContextTx()
	cache, _ := NewSighashV1PrehashCache(tx)

	path := WitnessItem{
		SuiteID:   SUITE_ID_SENTINEL,
		Pubkey:    refundKeyID[:],
		Signature: []byte{0x01}, // refund path
	}
	sig := WitnessItem{SuiteID: SUITE_ID_ML_DSA_87, Pubkey: refundKP.PubkeyBytes(), Signature: make([]byte, ML_DSA_87_SIG_BYTES+1)}

	q := NewSigCheckQueue(1)
	// blockHeight=200 (enough for height), blockMTP=50 (< lock_value=100)
	err := validateHTLCSpendQ(entry, path, sig, tx, inputIndex, inputValue, chainID, 200, 50, cache, q, nil, nil)
	if err == nil {
		t.Fatal("expected timestamp lock not met error")
	}
	if !isTxErrCode(err, TX_ERR_TIMELOCK_NOT_MET) {
		t.Fatalf("expected TX_ERR_TIMELOCK_NOT_MET, got: %v", err)
	}
}

func TestValidateHTLCSpendQ_SigSuiteInvalid(t *testing.T) {
	claimKP := mustMLDSA87Keypair(t)
	refundKP := mustMLDSA87Keypair(t)
	claimKeyID := sha3_256(claimKP.PubkeyBytes())
	refundKeyID := sha3_256(refundKP.PubkeyBytes())

	preimage := []byte("test-preimage-sig-s")
	entry := makeHTLCEntry(sha3_256(preimage), LOCK_MODE_HEIGHT, 1, claimKeyID, refundKeyID)

	tx, inputIndex, inputValue, chainID := testSighashContextTx()
	cache, _ := NewSighashV1PrehashCache(tx)

	path := WitnessItem{
		SuiteID:   SUITE_ID_SENTINEL,
		Pubkey:    claimKeyID[:],
		Signature: encodeHTLCClaimPayload(preimage),
	}
	sig := WitnessItem{
		SuiteID:   0xFF, // invalid suite
		Pubkey:    claimKP.PubkeyBytes(),
		Signature: make([]byte, ML_DSA_87_SIG_BYTES+1),
	}

	q := NewSigCheckQueue(1)
	err := validateHTLCSpendQ(entry, path, sig, tx, inputIndex, inputValue, chainID, 0, 0, cache, q, nil, nil)
	if err == nil {
		t.Fatal("expected sig suite invalid error")
	}
	if !isTxErrCode(err, TX_ERR_SIG_ALG_INVALID) {
		t.Fatalf("expected TX_ERR_SIG_ALG_INVALID, got: %v", err)
	}
}

func TestValidateHTLCSpendQ_SigKeyBindingMismatch(t *testing.T) {
	claimKP := mustMLDSA87Keypair(t)
	wrongKP := mustMLDSA87Keypair(t)
	refundKP := mustMLDSA87Keypair(t)
	claimKeyID := sha3_256(claimKP.PubkeyBytes())
	refundKeyID := sha3_256(refundKP.PubkeyBytes())

	preimage := []byte("test-preimage-bind1")
	entry := makeHTLCEntry(sha3_256(preimage), LOCK_MODE_HEIGHT, 1, claimKeyID, refundKeyID)

	tx, inputIndex, inputValue, chainID := testSighashContextTx()
	cache, _ := NewSighashV1PrehashCache(tx)

	path := WitnessItem{
		SuiteID:   SUITE_ID_SENTINEL,
		Pubkey:    claimKeyID[:],
		Signature: encodeHTLCClaimPayload(preimage),
	}
	sig := WitnessItem{
		SuiteID:   SUITE_ID_ML_DSA_87,
		Pubkey:    wrongKP.PubkeyBytes(), // sha3_256(wrongKP) != claimKeyID
		Signature: make([]byte, ML_DSA_87_SIG_BYTES+1),
	}

	q := NewSigCheckQueue(1)
	err := validateHTLCSpendQ(entry, path, sig, tx, inputIndex, inputValue, chainID, 0, 0, cache, q, nil, nil)
	if err == nil {
		t.Fatal("expected key binding mismatch error")
	}
	if !isTxErrCode(err, TX_ERR_SIG_INVALID) {
		t.Fatalf("expected TX_ERR_SIG_INVALID, got: %v", err)
	}
}

func TestValidateHTLCSpendQ_SigNonCanonicalLengths(t *testing.T) {
	claimKP := mustMLDSA87Keypair(t)
	refundKP := mustMLDSA87Keypair(t)
	claimKeyID := sha3_256(claimKP.PubkeyBytes())
	refundKeyID := sha3_256(refundKP.PubkeyBytes())

	preimage := []byte("test-preimage-noncl")
	entry := makeHTLCEntry(sha3_256(preimage), LOCK_MODE_HEIGHT, 1, claimKeyID, refundKeyID)

	tx, inputIndex, inputValue, chainID := testSighashContextTx()
	cache, _ := NewSighashV1PrehashCache(tx)

	path := WitnessItem{
		SuiteID:   SUITE_ID_SENTINEL,
		Pubkey:    claimKeyID[:],
		Signature: encodeHTLCClaimPayload(preimage),
	}
	sig := WitnessItem{
		SuiteID:   SUITE_ID_ML_DSA_87,
		Pubkey:    make([]byte, 10), // wrong length
		Signature: make([]byte, ML_DSA_87_SIG_BYTES+1),
	}

	q := NewSigCheckQueue(1)
	err := validateHTLCSpendQ(entry, path, sig, tx, inputIndex, inputValue, chainID, 0, 0, cache, q, nil, nil)
	if err == nil {
		t.Fatal("expected non-canonical lengths error")
	}
	if !isTxErrCode(err, TX_ERR_SIG_NONCANONICAL) {
		t.Fatalf("expected TX_ERR_SIG_NONCANONICAL, got: %v", err)
	}
}

func TestValidateHTLCSpendQ_ClaimPayloadTooShort(t *testing.T) {
	kp := mustMLDSA87Keypair(t)
	claimKeyID := sha3_256(kp.PubkeyBytes())

	entry := makeHTLCEntry(sha3_256([]byte("test-preimage-1234")), LOCK_MODE_HEIGHT, 1, claimKeyID, htlcRefundKeyID())

	tx, inputIndex, inputValue, chainID := testSighashContextTx()
	cache, _ := NewSighashV1PrehashCache(tx)

	path := WitnessItem{
		SuiteID:   SUITE_ID_SENTINEL,
		Pubkey:    claimKeyID[:],
		Signature: []byte{0x00, 0x10}, // claim path, but payload too short (missing preimage_len)
	}
	sig := WitnessItem{SuiteID: SUITE_ID_ML_DSA_87, Pubkey: make([]byte, ML_DSA_87_PUBKEY_BYTES), Signature: make([]byte, ML_DSA_87_SIG_BYTES+1)}

	q := NewSigCheckQueue(1)
	err := validateHTLCSpendQ(entry, path, sig, tx, inputIndex, inputValue, chainID, 0, 0, cache, q, nil, nil)
	if err == nil {
		t.Fatal("expected payload too short error")
	}
}

func TestValidateHTLCSpendQ_SelectorPayloadEmpty(t *testing.T) {
	kp := mustMLDSA87Keypair(t)
	claimKeyID := sha3_256(kp.PubkeyBytes())

	entry := makeHTLCEntry(sha3_256([]byte("test-preimage-1234")), LOCK_MODE_HEIGHT, 1, claimKeyID, htlcRefundKeyID())

	tx, inputIndex, inputValue, chainID := testSighashContextTx()
	cache, _ := NewSighashV1PrehashCache(tx)

	path := WitnessItem{
		SuiteID:   SUITE_ID_SENTINEL,
		Pubkey:    claimKeyID[:],
		Signature: nil, // empty payload
	}
	sig := WitnessItem{SuiteID: SUITE_ID_ML_DSA_87, Pubkey: make([]byte, ML_DSA_87_PUBKEY_BYTES), Signature: make([]byte, ML_DSA_87_SIG_BYTES+1)}

	q := NewSigCheckQueue(1)
	err := validateHTLCSpendQ(entry, path, sig, tx, inputIndex, inputValue, chainID, 0, 0, cache, q, nil, nil)
	if err == nil {
		t.Fatal("expected payload too short error")
	}
}

func TestValidateHTLCSpendQ_RefundPayloadLengthMismatch(t *testing.T) {
	kp := mustMLDSA87Keypair(t)
	refundKP := mustMLDSA87Keypair(t)
	claimKeyID := sha3_256(kp.PubkeyBytes())
	refundKeyID := sha3_256(refundKP.PubkeyBytes())

	entry := makeHTLCEntry(sha3_256([]byte("test-preimage-1234")), LOCK_MODE_HEIGHT, 10, claimKeyID, refundKeyID)

	tx, inputIndex, inputValue, chainID := testSighashContextTx()
	cache, _ := NewSighashV1PrehashCache(tx)

	path := WitnessItem{
		SuiteID:   SUITE_ID_SENTINEL,
		Pubkey:    refundKeyID[:],
		Signature: []byte{0x01, 0xFF}, // refund path but extra byte
	}
	sig := WitnessItem{SuiteID: SUITE_ID_ML_DSA_87, Pubkey: refundKP.PubkeyBytes(), Signature: make([]byte, ML_DSA_87_SIG_BYTES+1)}

	q := NewSigCheckQueue(1)
	err := validateHTLCSpendQ(entry, path, sig, tx, inputIndex, inputValue, chainID, 10, 0, cache, q, nil, nil)
	if err == nil {
		t.Fatal("expected refund payload length error")
	}
}

func TestValidateHTLCSpendQ_NilQueue_ClaimInvalidSig(t *testing.T) {
	claimKP := mustMLDSA87Keypair(t)
	claimKP2 := mustMLDSA87Keypair(t) // different keypair for wrong sig
	refundKP := mustMLDSA87Keypair(t)
	claimPub2 := claimKP2.PubkeyBytes()
	claimKeyID2 := sha3_256(claimPub2)
	refundKeyID := sha3_256(refundKP.PubkeyBytes())

	preimage := []byte("rubin-htlc-nil-q-claim")
	entry := makeHTLCEntry(sha3_256(preimage), LOCK_MODE_HEIGHT, 1, claimKeyID2, refundKeyID)

	path := WitnessItem{
		SuiteID:   SUITE_ID_SENTINEL,
		Pubkey:    claimKeyID2[:],
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
	// Sign with wrong key (claimKP, not claimKP2) → valid sig structure, wrong key.
	claimSig, err := claimKP.SignDigest32(digest)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	claimSig = append(claimSig, SIGHASH_ALL)
	sig := WitnessItem{
		SuiteID:   SUITE_ID_ML_DSA_87,
		Pubkey:    claimPub2, // matches claimKeyID2, but signed by claimKP
		Signature: claimSig,
	}

	// nil queue → inline verify → sig mismatch → TX_ERR_SIG_INVALID
	err = validateHTLCSpendQ(entry, path, sig, tx, inputIndex, inputValue, chainID, 0, 0, cache, nil, nil, nil)
	if err == nil {
		t.Fatalf("expected error for mismatched HTLC sig, got nil")
	}
	if !isTxErrCode(err, TX_ERR_SIG_INVALID) {
		t.Fatalf("expected TX_ERR_SIG_INVALID, got: %v", err)
	}
}

func TestValidateHTLCSpendQ_NilQueue_RefundOK(t *testing.T) {
	claimKP := mustMLDSA87Keypair(t)
	refundKP := mustMLDSA87Keypair(t)
	claimKeyID := sha3_256(claimKP.PubkeyBytes())
	refundPub := refundKP.PubkeyBytes()
	refundKeyID := sha3_256(refundPub)

	preimage := []byte("rubin-htlc-nil-q-refund")
	entry := makeHTLCEntry(sha3_256(preimage), LOCK_MODE_HEIGHT, 10, claimKeyID, refundKeyID)

	path := WitnessItem{
		SuiteID:   SUITE_ID_SENTINEL,
		Pubkey:    refundKeyID[:],
		Signature: []byte{0x01},
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

	// nil queue → inline verify → should pass
	err = validateHTLCSpendQ(entry, path, sig, tx, inputIndex, inputValue, chainID, 10, 0, cache, nil, nil, nil)
	if err != nil {
		t.Fatalf("inline HTLC refund: %v", err)
	}
}

func TestValidateThresholdSigSpendQ_NilQueue_ValidSig(t *testing.T) {
	kp := mustMLDSA87Keypair(t)
	keyID := sha3_256(kp.PubkeyBytes())

	tx, inputIndex, inputValue, chainID := testSighashContextTx()
	cache, _ := NewSighashV1PrehashCache(tx)
	digest, _ := SighashV1DigestWithCache(cache, inputIndex, inputValue, chainID, SIGHASH_ALL)
	sig, _ := kp.SignDigest32(digest)
	sig = append(sig, SIGHASH_ALL)

	keys := [][32]byte{keyID}
	ws := []WitnessItem{
		{SuiteID: SUITE_ID_ML_DSA_87, Pubkey: kp.PubkeyBytes(), Signature: sig},
	}

	// nil queue → inline verify
	err := validateThresholdSigSpendQ(keys, 1, ws, tx, inputIndex, inputValue, chainID, 0, cache, nil, "TEST", nil, nil)
	if err != nil {
		t.Fatalf("nil queue threshold verify: %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// validateThresholdSigSpendQ additional error-path tests
// ─────────────────────────────────────────────────────────────────────────────

func TestValidateThresholdSigSpendQ_SentinelWithData(t *testing.T) {
	kp := mustMLDSA87Keypair(t)
	keyID := sha3_256(kp.PubkeyBytes())

	tx, inputIndex, inputValue, chainID := testSighashContextTx()
	cache, _ := NewSighashV1PrehashCache(tx)

	keys := [][32]byte{keyID}
	ws := []WitnessItem{
		{SuiteID: SUITE_ID_SENTINEL, Pubkey: []byte{0x01}, Signature: nil}, // non-empty pubkey
	}

	q := NewSigCheckQueue(1)
	err := validateThresholdSigSpendQ(keys, 1, ws, tx, inputIndex, inputValue, chainID, 0, cache, q, "TEST", nil, nil)
	if err == nil {
		t.Fatal("expected SENTINEL with data error")
	}
	if !isTxErrCode(err, TX_ERR_PARSE) {
		t.Fatalf("expected TX_ERR_PARSE, got: %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// HTLC claim preimage length bounds tests (lines 172-177 of sig_verify_queued.go)
// ─────────────────────────────────────────────────────────────────────────────

func TestValidateHTLCSpendQ_ClaimPreimageTooShort(t *testing.T) {
	kp := mustMLDSA87Keypair(t)
	claimKeyID := sha3_256(kp.PubkeyBytes())

	// Preimage with 5 bytes (< MIN_HTLC_PREIMAGE_BYTES=16).
	shortPreimage := []byte("short")
	entry := makeHTLCEntry(sha3_256(shortPreimage), LOCK_MODE_HEIGHT, 1, claimKeyID, htlcRefundKeyID())

	tx, inputIndex, inputValue, chainID := testSighashContextTx()
	cache, _ := NewSighashV1PrehashCache(tx)

	path := WitnessItem{
		SuiteID:   SUITE_ID_SENTINEL,
		Pubkey:    claimKeyID[:],
		Signature: encodeHTLCClaimPayload(shortPreimage),
	}
	sig := WitnessItem{SuiteID: SUITE_ID_ML_DSA_87, Pubkey: make([]byte, ML_DSA_87_PUBKEY_BYTES), Signature: make([]byte, ML_DSA_87_SIG_BYTES+1)}

	q := NewSigCheckQueue(1)
	err := validateHTLCSpendQ(entry, path, sig, tx, inputIndex, inputValue, chainID, 0, 0, cache, q, nil, nil)
	if err == nil {
		t.Fatal("expected preimage too short error")
	}
	if !isTxErrCode(err, TX_ERR_PARSE) {
		t.Fatalf("expected TX_ERR_PARSE, got: %v", err)
	}
}

func TestValidateHTLCSpendQ_ClaimPreimageTooLong(t *testing.T) {
	kp := mustMLDSA87Keypair(t)
	claimKeyID := sha3_256(kp.PubkeyBytes())

	// Preimage with 257 bytes (> MAX_HTLC_PREIMAGE_BYTES=256).
	longPreimage := make([]byte, MAX_HTLC_PREIMAGE_BYTES+1)
	for i := range longPreimage {
		longPreimage[i] = byte(i)
	}
	entry := makeHTLCEntry(sha3_256(longPreimage), LOCK_MODE_HEIGHT, 1, claimKeyID, htlcRefundKeyID())

	tx, inputIndex, inputValue, chainID := testSighashContextTx()
	cache, _ := NewSighashV1PrehashCache(tx)

	path := WitnessItem{
		SuiteID:   SUITE_ID_SENTINEL,
		Pubkey:    claimKeyID[:],
		Signature: encodeHTLCClaimPayload(longPreimage),
	}
	sig := WitnessItem{SuiteID: SUITE_ID_ML_DSA_87, Pubkey: make([]byte, ML_DSA_87_PUBKEY_BYTES), Signature: make([]byte, ML_DSA_87_SIG_BYTES+1)}

	q := NewSigCheckQueue(1)
	err := validateHTLCSpendQ(entry, path, sig, tx, inputIndex, inputValue, chainID, 0, 0, cache, q, nil, nil)
	if err == nil {
		t.Fatal("expected preimage too long error")
	}
	if !isTxErrCode(err, TX_ERR_PARSE) {
		t.Fatalf("expected TX_ERR_PARSE, got: %v", err)
	}
}

func TestValidateHTLCSpendQ_ClaimPreimageLengthMismatch(t *testing.T) {
	kp := mustMLDSA87Keypair(t)
	claimKeyID := sha3_256(kp.PubkeyBytes())

	entry := makeHTLCEntry([32]byte{0x01}, LOCK_MODE_HEIGHT, 1, claimKeyID, htlcRefundKeyID())

	tx, inputIndex, inputValue, chainID := testSighashContextTx()
	cache, _ := NewSighashV1PrehashCache(tx)

	// Encode preLen=20 but only append 10 bytes of actual preimage data.
	payload := make([]byte, 0, 13)
	payload = append(payload, 0x00)                // claim path
	payload = AppendU16le(payload, 20)             // preLen=20
	payload = append(payload, make([]byte, 10)...) // only 10 bytes (mismatch)

	path := WitnessItem{
		SuiteID:   SUITE_ID_SENTINEL,
		Pubkey:    claimKeyID[:],
		Signature: payload,
	}
	sig := WitnessItem{SuiteID: SUITE_ID_ML_DSA_87, Pubkey: make([]byte, ML_DSA_87_PUBKEY_BYTES), Signature: make([]byte, ML_DSA_87_SIG_BYTES+1)}

	q := NewSigCheckQueue(1)
	err := validateHTLCSpendQ(entry, path, sig, tx, inputIndex, inputValue, chainID, 0, 0, cache, q, nil, nil)
	if err == nil {
		t.Fatal("expected claim payload length mismatch error")
	}
	if !isTxErrCode(err, TX_ERR_PARSE) {
		t.Fatalf("expected TX_ERR_PARSE, got: %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Nil-queue verifySig error paths (P2PK + HTLC)
// ─────────────────────────────────────────────────────────────────────────────

func TestVerifyMLDSAKeyAndSigQ_NilQueue_BadSuiteErr(t *testing.T) {
	// Call verifyMLDSAKeyAndSigQ with nil queue and a bad suite so that
	// verifySig returns err (not ok=false). Covers lines 44-46.
	tx, inputIndex, inputValue, chainID := testSighashContextTx()
	cache, _ := NewSighashV1PrehashCache(tx)
	digest, _ := SighashV1DigestWithCache(cache, inputIndex, inputValue, chainID, SIGHASH_ALL)

	_ = digest // avoid unused

	// verifyMLDSAKeyAndSigQ calls extractSigAndDigestWithCache then verifySig.
	// We feed bad suite through validateP2PKSpendQ with nil queue.
	// But validateP2PKSpendQ checks suite before reaching verifySig at line 29.
	// Instead, test via validateThresholdSigSpendQ with nil queue and a bad suite
	// that passes the ML-DSA-87 length check but has corrupt pubkey → verifySig err.
	// Actually, verifySig with SUITE_ID_ML_DSA_87 and corrupt pubkey returns (false, nil),
	// not err. To get err, need unknown suite — but that's caught earlier.
	// The nil-queue verifySig err path (lines 44-46) requires a suite that passes
	// earlier checks but fails in verifySig. This is UNREACHABLE_FROM_PUBLIC_SURFACE
	// because all invalid suites are caught before reaching verifySig.
	// Skip: unreachable via public API.
	t.Skip("verifySig err with nil queue is unreachable: all invalid suites caught earlier")
}

func TestValidateHTLCSpendQ_NilQueue_BadSuiteErr(t *testing.T) {
	// Same reasoning: lines 231-233 (nil-queue verifySig err in HTLC path).
	// verifySig only returns err for unknown suites, but suite check is at line 213.
	// UNREACHABLE_FROM_PUBLIC_SURFACE.
	t.Skip("HTLC nil-queue verifySig err is unreachable: suite checked at line 213")
}

func TestValidateThresholdSigSpendQ_NonCanonicalLengths(t *testing.T) {
	kp := mustMLDSA87Keypair(t)
	keyID := sha3_256(kp.PubkeyBytes())

	tx, inputIndex, inputValue, chainID := testSighashContextTx()
	cache, _ := NewSighashV1PrehashCache(tx)

	keys := [][32]byte{keyID}
	ws := []WitnessItem{
		{SuiteID: SUITE_ID_ML_DSA_87, Pubkey: make([]byte, 10), Signature: make([]byte, ML_DSA_87_SIG_BYTES+1)}, // wrong pubkey length
	}

	q := NewSigCheckQueue(1)
	err := validateThresholdSigSpendQ(keys, 1, ws, tx, inputIndex, inputValue, chainID, 0, cache, q, "TEST", nil, nil)
	if err == nil {
		t.Fatal("expected non-canonical lengths error")
	}
	if !isTxErrCode(err, TX_ERR_SIG_NONCANONICAL) {
		t.Fatalf("expected TX_ERR_SIG_NONCANONICAL, got: %v", err)
	}
}
