package consensus

import (
	"context"
	"strings"
	"testing"
)

// ─────────────────────────────────────────────────────────────────────────────
// ValidateTxLocal unit tests
// ─────────────────────────────────────────────────────────────────────────────

func TestValidateTxLocal_P2PK_Valid(t *testing.T) {
	kp := mustMLDSA87Keypair(t)
	covData := p2pkCovenantDataForPubkey(kp.PubkeyBytes())

	var prevTxid [32]byte
	prevTxid[0] = 0x42
	tx := &Tx{
		Version: 1,
		TxKind:  0x00,
		TxNonce: 1,
		Inputs:  []TxInput{{PrevTxid: prevTxid, PrevVout: 0, Sequence: 0}},
		Outputs: []TxOutput{{Value: 90, CovenantType: COV_TYPE_P2PK, CovenantData: covData}},
	}
	tx.Witness = []WitnessItem{signP2PKInputWitness(t, tx, 0, 100, [32]byte{}, kp)}

	sighashCache, err := NewSighashV1PrehashCache(tx)
	if err != nil {
		t.Fatalf("NewSighashV1PrehashCache: %v", err)
	}

	tvc := TxValidationContext{
		TxIndex: 1,
		Tx:      tx,
		ResolvedInputs: []UtxoEntry{{
			Value:        100,
			CovenantType: COV_TYPE_P2PK,
			CovenantData: append([]byte(nil), covData...),
		}},
		WitnessStart: 0,
		WitnessEnd:   1,
		SighashCache: sighashCache,
		Fee:          10,
	}

	result := ValidateTxLocal(tvc, [32]byte{}, 1, 0, nil, nil)
	if !result.Valid {
		t.Fatalf("expected valid, got err: %v", result.Err)
	}
	if result.Fee != 10 {
		t.Fatalf("expected fee=10, got %d", result.Fee)
	}
	if result.TxIndex != 1 {
		t.Fatalf("expected TxIndex=1, got %d", result.TxIndex)
	}
	if result.SigCount != 1 {
		t.Fatalf("expected SigCount=1, got %d", result.SigCount)
	}
}

func TestValidateTxLocal_P2PK_InvalidSig(t *testing.T) {
	kp := mustMLDSA87Keypair(t)
	kp2 := mustMLDSA87Keypair(t)
	covData := p2pkCovenantDataForPubkey(kp.PubkeyBytes())

	var prevTxid [32]byte
	prevTxid[0] = 0x42
	tx := &Tx{
		Version: 1,
		TxKind:  0x00,
		TxNonce: 1,
		Inputs:  []TxInput{{PrevTxid: prevTxid, PrevVout: 0, Sequence: 0}},
		Outputs: []TxOutput{{Value: 90, CovenantType: COV_TYPE_P2PK, CovenantData: covData}},
	}
	// Sign with wrong key — will fail key binding check.
	tx.Witness = []WitnessItem{signP2PKInputWitness(t, tx, 0, 100, [32]byte{}, kp2)}

	sighashCache, err := NewSighashV1PrehashCache(tx)
	if err != nil {
		t.Fatalf("NewSighashV1PrehashCache: %v", err)
	}

	tvc := TxValidationContext{
		TxIndex: 1,
		Tx:      tx,
		ResolvedInputs: []UtxoEntry{{
			Value:        100,
			CovenantType: COV_TYPE_P2PK,
			CovenantData: append([]byte(nil), covData...),
		}},
		WitnessStart: 0,
		WitnessEnd:   1,
		SighashCache: sighashCache,
		Fee:          10,
	}

	result := ValidateTxLocal(tvc, [32]byte{}, 1, 0, nil, nil)
	if result.Valid {
		t.Fatalf("expected invalid, got valid")
	}
	if result.Err == nil {
		t.Fatalf("expected error, got nil")
	}
}

func TestValidateTxLocal_NilTx(t *testing.T) {
	tvc := TxValidationContext{TxIndex: 1, Tx: nil}
	result := ValidateTxLocal(tvc, [32]byte{}, 1, 0, nil, nil)
	if result.Valid {
		t.Fatalf("expected invalid for nil tx")
	}
	if result.Err == nil {
		t.Fatalf("expected error for nil tx")
	}
}

func TestValidateTxLocal_WitnessUnderflow(t *testing.T) {
	kp := mustMLDSA87Keypair(t)
	covData := p2pkCovenantDataForPubkey(kp.PubkeyBytes())

	tx := &Tx{
		Version: 1,
		TxKind:  0x00,
		TxNonce: 1,
		Inputs:  []TxInput{{PrevVout: 0, Sequence: 0}},
		Outputs: []TxOutput{{Value: 90, CovenantType: COV_TYPE_P2PK, CovenantData: covData}},
		Witness: []WitnessItem{}, // empty — underflow
	}

	sighashCache, err := NewSighashV1PrehashCache(tx)
	if err != nil {
		t.Fatalf("NewSighashV1PrehashCache: %v", err)
	}

	tvc := TxValidationContext{
		TxIndex: 1,
		Tx:      tx,
		ResolvedInputs: []UtxoEntry{{
			Value:        100,
			CovenantType: COV_TYPE_P2PK,
			CovenantData: covData,
		}},
		WitnessStart: 0,
		WitnessEnd:   0, // no witness available
		SighashCache: sighashCache,
		Fee:          10,
	}

	result := ValidateTxLocal(tvc, [32]byte{}, 1, 0, nil, nil)
	if result.Valid {
		t.Fatalf("expected invalid for witness underflow")
	}
}

func TestValidateTxLocal_WitnessCountMismatch(t *testing.T) {
	kp := mustMLDSA87Keypair(t)
	covData := p2pkCovenantDataForPubkey(kp.PubkeyBytes())

	var prevTxid [32]byte
	prevTxid[0] = 0x42
	tx := &Tx{
		Version: 1,
		TxKind:  0x00,
		TxNonce: 1,
		Inputs:  []TxInput{{PrevTxid: prevTxid, PrevVout: 0, Sequence: 0}},
		Outputs: []TxOutput{{Value: 90, CovenantType: COV_TYPE_P2PK, CovenantData: covData}},
	}

	validWitness := signP2PKInputWitness(t, tx, 0, 100, [32]byte{}, kp)
	tx.Witness = []WitnessItem{validWitness, validWitness}

	sighashCache, err := NewSighashV1PrehashCache(tx)
	if err != nil {
		t.Fatalf("NewSighashV1PrehashCache: %v", err)
	}

	tvc := TxValidationContext{
		TxIndex: 1,
		Tx:      tx,
		ResolvedInputs: []UtxoEntry{{
			Value:        100,
			CovenantType: COV_TYPE_P2PK,
			CovenantData: covData,
		}},
		WitnessStart: 0,
		WitnessEnd:   1,
		SighashCache: sighashCache,
	}

	result := ValidateTxLocal(tvc, [32]byte{}, 1, 0, nil, nil)
	if result.Valid {
		t.Fatalf("expected invalid for witness count mismatch")
	}
	if !isTxErrCode(result.Err, TX_ERR_PARSE) {
		t.Fatalf("expected TX_ERR_PARSE, got: %v", result.Err)
	}
	if !strings.Contains(result.Err.Error(), "witness_count mismatch") {
		t.Fatalf("expected witness_count mismatch detail, got: %v", result.Err)
	}
}

func TestValidateTxLocal_WithSigCache(t *testing.T) {
	kp := mustMLDSA87Keypair(t)
	covData := p2pkCovenantDataForPubkey(kp.PubkeyBytes())

	var prevTxid [32]byte
	prevTxid[0] = 0x42
	tx := &Tx{
		Version: 1,
		TxKind:  0x00,
		TxNonce: 1,
		Inputs:  []TxInput{{PrevTxid: prevTxid, PrevVout: 0, Sequence: 0}},
		Outputs: []TxOutput{{Value: 90, CovenantType: COV_TYPE_P2PK, CovenantData: covData}},
	}
	tx.Witness = []WitnessItem{signP2PKInputWitness(t, tx, 0, 100, [32]byte{}, kp)}

	sighashCache, err := NewSighashV1PrehashCache(tx)
	if err != nil {
		t.Fatalf("NewSighashV1PrehashCache: %v", err)
	}

	entry := UtxoEntry{
		Value:        100,
		CovenantType: COV_TYPE_P2PK,
		CovenantData: append([]byte(nil), covData...),
	}

	sigCache := NewSigCache(100)
	tvc := TxValidationContext{
		TxIndex:        1,
		Tx:             tx,
		ResolvedInputs: []UtxoEntry{entry},
		WitnessStart:   0,
		WitnessEnd:     1,
		SighashCache:   sighashCache,
		Fee:            10,
	}

	// First call populates sig cache.
	result := ValidateTxLocal(tvc, [32]byte{}, 1, 0, nil, sigCache)
	if !result.Valid {
		t.Fatalf("first call: %v", result.Err)
	}
	if sigCache.Len() != 1 {
		t.Fatalf("expected 1 cached sig, got %d", sigCache.Len())
	}

	// Second call should hit cache.
	result2 := ValidateTxLocal(tvc, [32]byte{}, 1, 0, nil, sigCache)
	if !result2.Valid {
		t.Fatalf("second call (cached): %v", result2.Err)
	}
	if sigCache.Hits() < 1 {
		t.Fatalf("expected cache hit, got %d hits", sigCache.Hits())
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// RunTxValidationWorkers tests
// ─────────────────────────────────────────────────────────────────────────────

func TestRunTxValidationWorkers_Empty(t *testing.T) {
	results, err := RunTxValidationWorkers(
		context.Background(), 4, nil, [32]byte{}, 1, 0, nil, nil,
	)
	if err != nil {
		t.Fatalf("RunTxValidationWorkers: %v", err)
	}
	if len(results) != 0 {
		t.Fatalf("expected 0 results, got %d", len(results))
	}
}

func TestRunTxValidationWorkers_SingleValid(t *testing.T) {
	kp := mustMLDSA87Keypair(t)
	covData := p2pkCovenantDataForPubkey(kp.PubkeyBytes())

	var prevTxid [32]byte
	prevTxid[0] = 0x42
	tx := &Tx{
		Version: 1,
		TxKind:  0x00,
		TxNonce: 1,
		Inputs:  []TxInput{{PrevTxid: prevTxid, PrevVout: 0, Sequence: 0}},
		Outputs: []TxOutput{{Value: 90, CovenantType: COV_TYPE_P2PK, CovenantData: covData}},
	}
	tx.Witness = []WitnessItem{signP2PKInputWitness(t, tx, 0, 100, [32]byte{}, kp)}

	sighashCache, err := NewSighashV1PrehashCache(tx)
	if err != nil {
		t.Fatalf("NewSighashV1PrehashCache: %v", err)
	}

	txcs := []TxValidationContext{{
		TxIndex: 1,
		Tx:      tx,
		ResolvedInputs: []UtxoEntry{{
			Value:        100,
			CovenantType: COV_TYPE_P2PK,
			CovenantData: append([]byte(nil), covData...),
		}},
		WitnessStart: 0,
		WitnessEnd:   1,
		SighashCache: sighashCache,
		Fee:          10,
	}}

	results, err := RunTxValidationWorkers(
		context.Background(), 2, txcs, [32]byte{}, 1, 0, nil, nil,
	)
	if err != nil {
		t.Fatalf("RunTxValidationWorkers: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Err != nil {
		t.Fatalf("expected valid, got err: %v", results[0].Err)
	}
	if !results[0].Value.Valid {
		t.Fatalf("expected Valid=true")
	}
}

func TestRunTxValidationWorkers_MultipleWithOneInvalid(t *testing.T) {
	kp := mustMLDSA87Keypair(t)
	kp2 := mustMLDSA87Keypair(t)
	covData := p2pkCovenantDataForPubkey(kp.PubkeyBytes())

	makeTvc := func(idx int, validSig bool) TxValidationContext {
		var prevTxid [32]byte
		prevTxid[0] = byte(idx)
		tx := &Tx{
			Version: 1,
			TxKind:  0x00,
			TxNonce: 1,
			Inputs:  []TxInput{{PrevTxid: prevTxid, PrevVout: 0, Sequence: 0}},
			Outputs: []TxOutput{{Value: 90, CovenantType: COV_TYPE_P2PK, CovenantData: covData}},
		}
		signer := kp
		if !validSig {
			signer = kp2 // wrong key → key binding mismatch
		}
		tx.Witness = []WitnessItem{signP2PKInputWitness(t, tx, 0, 100, [32]byte{}, signer)}

		sighashCache, err := NewSighashV1PrehashCache(tx)
		if err != nil {
			t.Fatalf("NewSighashV1PrehashCache: %v", err)
		}

		return TxValidationContext{
			TxIndex: idx,
			Tx:      tx,
			ResolvedInputs: []UtxoEntry{{
				Value:        100,
				CovenantType: COV_TYPE_P2PK,
				CovenantData: append([]byte(nil), covData...),
			}},
			WitnessStart: 0,
			WitnessEnd:   1,
			SighashCache: sighashCache,
			Fee:          10,
		}
	}

	txcs := []TxValidationContext{
		makeTvc(1, true),
		makeTvc(2, false), // invalid
		makeTvc(3, true),
	}

	results, err := RunTxValidationWorkers(
		context.Background(), 2, txcs, [32]byte{}, 1, 0, nil, nil,
	)
	if err != nil {
		t.Fatalf("RunTxValidationWorkers: %v", err)
	}
	if len(results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(results))
	}

	// First should be valid.
	if results[0].Err != nil {
		t.Fatalf("tx[0] expected valid, got err: %v", results[0].Err)
	}

	// Second should be invalid.
	if results[1].Err == nil {
		t.Fatalf("tx[1] expected error, got nil")
	}

	// Third should be valid.
	if results[2].Err != nil {
		t.Fatalf("tx[2] expected valid, got err: %v", results[2].Err)
	}

	// FirstTxError should return the second tx error.
	firstErr := FirstTxError(results)
	if firstErr == nil {
		t.Fatalf("FirstTxError should return non-nil")
	}
}

func TestRunTxValidationWorkers_CancelledContext(t *testing.T) {
	kp := mustMLDSA87Keypair(t)
	covData := p2pkCovenantDataForPubkey(kp.PubkeyBytes())

	var prevTxid [32]byte
	prevTxid[0] = 0x42
	tx := &Tx{
		Version: 1,
		TxKind:  0x00,
		TxNonce: 1,
		Inputs:  []TxInput{{PrevTxid: prevTxid, PrevVout: 0, Sequence: 0}},
		Outputs: []TxOutput{{Value: 90, CovenantType: COV_TYPE_P2PK, CovenantData: covData}},
	}
	tx.Witness = []WitnessItem{signP2PKInputWitness(t, tx, 0, 100, [32]byte{}, kp)}

	sighashCache, err := NewSighashV1PrehashCache(tx)
	if err != nil {
		t.Fatalf("NewSighashV1PrehashCache: %v", err)
	}

	txcs := []TxValidationContext{{
		TxIndex: 1,
		Tx:      tx,
		ResolvedInputs: []UtxoEntry{{
			Value:        100,
			CovenantType: COV_TYPE_P2PK,
			CovenantData: append([]byte(nil), covData...),
		}},
		WitnessStart: 0,
		WitnessEnd:   1,
		SighashCache: sighashCache,
		Fee:          10,
	}}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled

	results, err := RunTxValidationWorkers(ctx, 2, txcs, [32]byte{}, 1, 0, nil, nil)
	if err != nil {
		t.Fatalf("RunTxValidationWorkers: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Err == nil {
		t.Fatalf("expected error from cancelled context")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// FirstTxError tests
// ─────────────────────────────────────────────────────────────────────────────

func TestFirstTxError_AllValid(t *testing.T) {
	results := []WorkerResult[TxValidationResult]{
		{Value: TxValidationResult{Valid: true}},
		{Value: TxValidationResult{Valid: true}},
	}
	if err := FirstTxError(results); err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
}

func TestFirstTxError_Nil(t *testing.T) {
	if err := FirstTxError(nil); err != nil {
		t.Fatalf("expected nil for nil results, got %v", err)
	}
}

func TestFirstTxError_PicksSmallestTxIndexEvenIfOutOfOrder(t *testing.T) {
	err3 := txerr(TX_ERR_PARSE, "tx3")
	err1 := txerr(TX_ERR_MISSING_UTXO, "tx1")

	results := []WorkerResult[TxValidationResult]{
		{Value: TxValidationResult{TxIndex: 3, Err: err3}, Err: err3},
		{Value: TxValidationResult{TxIndex: 2, Valid: true}, Err: nil},
		{Value: TxValidationResult{TxIndex: 1, Err: err1}, Err: err1},
	}

	got := FirstTxError(results)
	if got == nil {
		t.Fatal("expected error, got nil")
	}
	if got != err1 {
		t.Fatalf("expected smallest-index error (tx1), got %v", got)
	}
}

func TestFirstTxError_FallsBackWhenTxIndexMissingOrZero(t *testing.T) {
	errA := txerr(TX_ERR_PARSE, "missing index A")
	errB := txerr(TX_ERR_PARSE, "missing index B")

	// Both errors have TxIndex=0 (missing). Reducer must deterministically keep
	// the first such error encountered.
	results := []WorkerResult[TxValidationResult]{
		{Value: TxValidationResult{TxIndex: 0, Err: errA}, Err: errA},
		{Value: TxValidationResult{TxIndex: 0, Err: errB}, Err: errB},
	}

	got := FirstTxError(results)
	if got == nil {
		t.Fatal("expected error, got nil")
	}
	if got != errA {
		t.Fatalf("expected first missing-index error, got %v", got)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// validateInputSpendQ branch coverage
// ─────────────────────────────────────────────────────────────────────────────

func TestValidateInputSpendQ_DefaultCovType(t *testing.T) {
	// Unknown/unhandled covenant type should return nil (no spend checks).
	entry := UtxoEntry{
		CovenantType: 0xFFFF, // unknown type
		CovenantData: []byte{0x00},
	}
	err := validateInputSpendQ(entry, nil, &Tx{}, 0, 100, [32]byte{}, 1, 0, nil, nil, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("expected nil for unknown covenant type, got: %v", err)
	}
}

func TestValidateCoreExtSpendQ_InactiveProfile(t *testing.T) {
	// An explicit empty provider models pre-ACTIVE semantics without relying on nil.
	entry := UtxoEntry{
		CovenantType: COV_TYPE_CORE_EXT,
		CovenantData: makeCoreExtCovenantData(0x01),
	}
	w := WitnessItem{SuiteID: SUITE_ID_ML_DSA_87}
	err := validateCoreExtSpendQ(entry, w, &Tx{}, 0, 100, [32]byte{}, 1, nil, EmptyCoreExtProfileProvider(), nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("expected nil for inactive CORE_EXT, got: %v", err)
	}
}

func TestValidateCoreExtSpendQ_MissingProviderRejected(t *testing.T) {
	entry := UtxoEntry{
		CovenantType: COV_TYPE_CORE_EXT,
		CovenantData: makeCoreExtCovenantData(0x01),
	}
	w := WitnessItem{SuiteID: SUITE_ID_ML_DSA_87}
	err := validateCoreExtSpendQ(entry, w, &Tx{}, 0, 100, [32]byte{}, 1, nil, nil, nil, nil, nil, nil)
	if err == nil || err.Error() != "TX_ERR_COVENANT_TYPE_INVALID: CORE_EXT profile provider missing" {
		t.Fatalf("expected missing provider error, got %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// ValidateTxLocal — non-P2PK covenant types
// ─────────────────────────────────────────────────────────────────────────────

func TestValidateTxLocal_Multisig_Valid(t *testing.T) {
	kp := mustMLDSA87Keypair(t)
	keyID := sha3_256(kp.PubkeyBytes())
	covData := encodeMultisigCovenantData(1, [][32]byte{keyID})

	var prevTxid [32]byte
	prevTxid[0] = 0x11
	tx := &Tx{
		Version: 1,
		TxKind:  0x00,
		TxNonce: 1,
		Inputs:  []TxInput{{PrevTxid: prevTxid, PrevVout: 0, Sequence: 0}},
		Outputs: []TxOutput{{Value: 90, CovenantType: COV_TYPE_P2PK, CovenantData: p2pkCovenantDataForPubkey(kp.PubkeyBytes())}},
	}
	tx.Witness = []WitnessItem{signP2PKInputWitness(t, tx, 0, 100, [32]byte{}, kp)}

	sighashCache, err := NewSighashV1PrehashCache(tx)
	if err != nil {
		t.Fatalf("sighash cache: %v", err)
	}

	tvc := TxValidationContext{
		TxIndex: 1,
		Tx:      tx,
		ResolvedInputs: []UtxoEntry{{
			Value:        100,
			CovenantType: COV_TYPE_MULTISIG,
			CovenantData: covData,
		}},
		WitnessStart: 0,
		WitnessEnd:   1,
		SighashCache: sighashCache,
		Fee:          10,
	}

	result := ValidateTxLocal(tvc, [32]byte{}, 1, 0, nil, nil)
	if !result.Valid {
		t.Fatalf("multisig valid: %v", result.Err)
	}
}

func TestValidateTxLocal_HTLC_ClaimValid(t *testing.T) {
	kp := mustMLDSA87Keypair(t)
	claimKeyID := sha3_256(kp.PubkeyBytes())

	preimage := make([]byte, 32)
	preimage[0] = 0xAA
	hash := sha3_256(preimage)

	var refundKeyID [32]byte
	refundKeyID[0] = 0xBB

	covData := encodeHTLCCovenantData(hash, LOCK_MODE_HEIGHT, 100, claimKeyID, refundKeyID)

	var prevTxid [32]byte
	prevTxid[0] = 0x22
	tx := &Tx{
		Version: 1,
		TxKind:  0x00,
		TxNonce: 1,
		Inputs:  []TxInput{{PrevTxid: prevTxid, PrevVout: 0, Sequence: 0}},
		Outputs: []TxOutput{{Value: 90, CovenantType: COV_TYPE_P2PK, CovenantData: p2pkCovenantDataForPubkey(kp.PubkeyBytes())}},
	}

	// Build HTLC witness: path selector (claim) + signature.
	claimPayload := encodeHTLCClaimPayload(preimage)
	pathItem := WitnessItem{
		SuiteID:   SUITE_ID_SENTINEL,
		Pubkey:    claimKeyID[:],
		Signature: claimPayload,
	}
	tx.Witness = []WitnessItem{pathItem, signP2PKInputWitness(t, tx, 0, 100, [32]byte{}, kp)}

	sighashCache, err := NewSighashV1PrehashCache(tx)
	if err != nil {
		t.Fatalf("sighash cache: %v", err)
	}

	tvc := TxValidationContext{
		TxIndex: 1,
		Tx:      tx,
		ResolvedInputs: []UtxoEntry{{
			Value:        100,
			CovenantType: COV_TYPE_HTLC,
			CovenantData: covData,
		}},
		WitnessStart: 0,
		WitnessEnd:   2,
		SighashCache: sighashCache,
		Fee:          10,
	}

	result := ValidateTxLocal(tvc, [32]byte{}, 1, 0, nil, nil)
	if !result.Valid {
		t.Fatalf("HTLC claim valid: %v", result.Err)
	}
}

func TestValidateTxLocal_Vault_SigValid(t *testing.T) {
	kp := mustMLDSA87Keypair(t)
	vaultKeyID := sha3_256(kp.PubkeyBytes())
	var ownerLockID [32]byte
	ownerLockID[0] = 0xCC
	var whitelistH [32]byte
	whitelistH[0] = 0xDD

	covData := encodeVaultCovenantData(ownerLockID, 1, [][32]byte{vaultKeyID}, [][32]byte{whitelistH})

	var prevTxid [32]byte
	prevTxid[0] = 0x33
	tx := &Tx{
		Version: 1,
		TxKind:  0x00,
		TxNonce: 1,
		Inputs:  []TxInput{{PrevTxid: prevTxid, PrevVout: 0, Sequence: 0}},
		Outputs: []TxOutput{{Value: 90, CovenantType: COV_TYPE_P2PK, CovenantData: p2pkCovenantDataForPubkey(kp.PubkeyBytes())}},
	}
	tx.Witness = []WitnessItem{signP2PKInputWitness(t, tx, 0, 100, [32]byte{}, kp)}

	sighashCache, err := NewSighashV1PrehashCache(tx)
	if err != nil {
		t.Fatalf("sighash cache: %v", err)
	}

	tvc := TxValidationContext{
		TxIndex: 1,
		Tx:      tx,
		ResolvedInputs: []UtxoEntry{{
			Value:        100,
			CovenantType: COV_TYPE_VAULT,
			CovenantData: covData,
		}},
		WitnessStart: 0,
		WitnessEnd:   1,
		SighashCache: sighashCache,
		Fee:          10,
	}

	result := ValidateTxLocal(tvc, [32]byte{}, 1, 0, nil, nil)
	if !result.Valid {
		t.Fatalf("vault sig valid: %v", result.Err)
	}
}

func TestValidateTxLocal_Stealth_Valid(t *testing.T) {
	kp := mustMLDSA87Keypair(t)
	oneTimeKeyID := sha3_256(kp.PubkeyBytes())
	covData := stealthCovenantDataForKeyID(oneTimeKeyID)

	var prevTxid [32]byte
	prevTxid[0] = 0x44
	tx := &Tx{
		Version: 1,
		TxKind:  0x00,
		TxNonce: 1,
		Inputs:  []TxInput{{PrevTxid: prevTxid, PrevVout: 0, Sequence: 0}},
		Outputs: []TxOutput{{Value: 90, CovenantType: COV_TYPE_P2PK, CovenantData: p2pkCovenantDataForPubkey(kp.PubkeyBytes())}},
	}
	tx.Witness = []WitnessItem{signP2PKInputWitness(t, tx, 0, 100, [32]byte{}, kp)}

	sighashCache, err := NewSighashV1PrehashCache(tx)
	if err != nil {
		t.Fatalf("sighash cache: %v", err)
	}

	tvc := TxValidationContext{
		TxIndex: 1,
		Tx:      tx,
		ResolvedInputs: []UtxoEntry{{
			Value:        100,
			CovenantType: COV_TYPE_CORE_STEALTH,
			CovenantData: covData,
		}},
		WitnessStart: 0,
		WitnessEnd:   1,
		SighashCache: sighashCache,
		Fee:          10,
	}

	result := ValidateTxLocal(tvc, [32]byte{}, 1, 0, nil, nil)
	if !result.Valid {
		t.Fatalf("stealth valid: %v", result.Err)
	}
}

func TestValidateTxLocal_CoreExt_ActiveProfile(t *testing.T) {
	kp := mustMLDSA87Keypair(t)
	covData := makeCoreExtCovenantData(0x01)

	var prevTxid [32]byte
	prevTxid[0] = 0x55
	tx := &Tx{
		Version: 1,
		TxKind:  0x00,
		TxNonce: 1,
		Inputs:  []TxInput{{PrevTxid: prevTxid, PrevVout: 0, Sequence: 0}},
		Outputs: []TxOutput{{Value: 90, CovenantType: COV_TYPE_P2PK, CovenantData: p2pkCovenantDataForPubkey(kp.PubkeyBytes())}},
	}
	tx.Witness = []WitnessItem{signP2PKInputWitness(t, tx, 0, 100, [32]byte{}, kp)}

	sighashCache, err := NewSighashV1PrehashCache(tx)
	if err != nil {
		t.Fatalf("sighash cache: %v", err)
	}

	profiles := &testCoreExtProfileProvider{
		profile: CoreExtProfile{
			Active:        true,
			AllowedSuites: map[uint8]struct{}{SUITE_ID_ML_DSA_87: {}},
		},
		found: true,
	}

	tvc := TxValidationContext{
		TxIndex: 1,
		Tx:      tx,
		ResolvedInputs: []UtxoEntry{{
			Value:        100,
			CovenantType: COV_TYPE_CORE_EXT,
			CovenantData: covData,
		}},
		WitnessStart: 0,
		WitnessEnd:   1,
		SighashCache: sighashCache,
		Fee:          10,
	}

	result := ValidateTxLocal(tvc, [32]byte{}, 1, 0, profiles, nil)
	if !result.Valid {
		t.Fatalf("CORE_EXT active: %v", result.Err)
	}
}

func TestValidateTxLocal_CoreExtTxContextEnabledDispatchesNineParam(t *testing.T) {
	var prev [32]byte
	prev[0] = 0xb0

	txBytes := txWithOneInputOneOutputWithWitness(prev, 0, 90, COV_TYPE_CORE_EXT, coreExtCovenantData(7, nil), []WitnessItem{{
		SuiteID:   0x42,
		Pubkey:    []byte{0x01, 0x02, 0x03},
		Signature: []byte{0x04, 0x01},
	}})
	tx, _ := mustParseTxForUtxo(t, txBytes)
	sighashCache, err := NewSighashV1PrehashCache(tx)
	if err != nil {
		t.Fatalf("sighash cache: %v", err)
	}

	called := false
	profiles, err := NewStaticCoreExtProfileProvider([]CoreExtDeploymentProfile{{
		ExtID:            7,
		ActivationHeight: 0,
		TxContextEnabled: true,
		AllowedSuites:    map[uint8]struct{}{0x42: {}},
		VerifySigExtTxContextFn: func(
			extID uint16,
			suiteID uint8,
			pubkey []byte,
			signature []byte,
			digest32 [32]byte,
			extPayload []byte,
			ctxBase *TxContextBase,
			ctxContinuing *TxContextContinuing,
			selfInputValue uint64,
		) (bool, error) {
			called = true
			if extID != 7 || suiteID != 0x42 {
				t.Fatalf("extID/suiteID=%d/%d", extID, suiteID)
			}
			if string(extPayload) != string([]byte{0x99}) {
				t.Fatalf("extPayload=%x", extPayload)
			}
			if ctxBase == nil || ctxBase.TotalIn != (Uint128{Lo: 100, Hi: 0}) || ctxBase.TotalOut != (Uint128{Lo: 90, Hi: 0}) || ctxBase.Height != 1 {
				t.Fatalf("ctxBase=%+v", ctxBase)
			}
			if ctxContinuing == nil || ctxContinuing.ContinuingOutputCount != 1 || ctxContinuing.ContinuingOutputs[0].Value != 90 {
				t.Fatalf("ctxContinuing=%+v", ctxContinuing)
			}
			if ctxContinuing.ContinuingOutputs[0].ExtPayload == nil || len(ctxContinuing.ContinuingOutputs[0].ExtPayload) != 0 {
				t.Fatalf("continuing payload must be non-nil empty slice, got %#v", ctxContinuing.ContinuingOutputs[0].ExtPayload)
			}
			if selfInputValue != 100 {
				t.Fatalf("selfInputValue=%d", selfInputValue)
			}
			_ = pubkey
			_ = signature
			_ = digest32
			return true, nil
		},
		BindingDescriptor: []byte{0xa1},
		ExtPayloadSchema:  []byte{0xb2},
	}})
	if err != nil {
		t.Fatalf("NewStaticCoreExtProfileProvider: %v", err)
	}

	tvc := TxValidationContext{
		TxIndex: 1,
		Tx:      tx,
		ResolvedInputs: []UtxoEntry{{
			Value:        100,
			CovenantType: COV_TYPE_CORE_EXT,
			CovenantData: coreExtCovenantData(7, []byte{0x99}),
		}},
		WitnessStart: 0,
		WitnessEnd:   1,
		SighashCache: sighashCache,
		Fee:          10,
	}

	result := ValidateTxLocal(tvc, [32]byte{}, 1, 0, profiles, nil)
	if !result.Valid {
		t.Fatalf("txcontext-enabled CORE_EXT valid: %v", result.Err)
	}
	if !called {
		t.Fatalf("expected txcontext-enabled verifier to run")
	}
}

func TestValidateTxLocal_CoreExtTxContextMalformedOutputFailsBeforeVerifier(t *testing.T) {
	var prev [32]byte
	prev[0] = 0xb3

	txBytes := txWithOneInputOneOutputWithWitness(prev, 0, 90, COV_TYPE_CORE_EXT, []byte{0x01}, []WitnessItem{{
		SuiteID:   0x42,
		Pubkey:    []byte{0x01, 0x02, 0x03},
		Signature: []byte{0x04, 0x01},
	}})
	tx, _ := mustParseTxForUtxo(t, txBytes)
	sighashCache, err := NewSighashV1PrehashCache(tx)
	if err != nil {
		t.Fatalf("sighash cache: %v", err)
	}

	called := false
	profiles, err := NewStaticCoreExtProfileProvider([]CoreExtDeploymentProfile{{
		ExtID:            7,
		ActivationHeight: 0,
		TxContextEnabled: true,
		AllowedSuites:    map[uint8]struct{}{0x42: {}},
		VerifySigExtTxContextFn: func(uint16, uint8, []byte, []byte, [32]byte, []byte, *TxContextBase, *TxContextContinuing, uint64) (bool, error) {
			called = true
			return true, nil
		},
		BindingDescriptor: []byte{0xa1},
		ExtPayloadSchema:  []byte{0xb2},
	}})
	if err != nil {
		t.Fatalf("NewStaticCoreExtProfileProvider: %v", err)
	}

	tvc := TxValidationContext{
		TxIndex: 1,
		Tx:      tx,
		ResolvedInputs: []UtxoEntry{{
			Value:        100,
			CovenantType: COV_TYPE_CORE_EXT,
			CovenantData: coreExtCovenantData(7, []byte{0x99}),
		}},
		WitnessStart: 0,
		WitnessEnd:   1,
		SighashCache: sighashCache,
		Fee:          10,
	}

	result := ValidateTxLocal(tvc, [32]byte{}, 1, 0, profiles, nil)
	if result.Err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, result.Err); got != TX_ERR_COVENANT_TYPE_INVALID {
		t.Fatalf("code=%s want %s", got, TX_ERR_COVENANT_TYPE_INVALID)
	}
	if called {
		t.Fatalf("verifier must not run when txcontext output cache build fails")
	}
}

func TestValidateTxLocal_CoreExtTxContextTooManyContinuingOutputsFailsBeforeVerifier(t *testing.T) {
	var prev [32]byte
	prev[0] = 0xb4

	tx := &Tx{
		Version: 1,
		TxKind:  0x00,
		TxNonce: 1,
		Inputs:  []TxInput{{PrevTxid: prev, PrevVout: 0, Sequence: 0}},
		Outputs: []TxOutput{
			{Value: 30, CovenantType: COV_TYPE_CORE_EXT, CovenantData: coreExtCovenantData(7, nil)},
			{Value: 30, CovenantType: COV_TYPE_CORE_EXT, CovenantData: coreExtCovenantData(7, []byte{0x01})},
			{Value: 30, CovenantType: COV_TYPE_CORE_EXT, CovenantData: coreExtCovenantData(7, []byte{0x02})},
		},
		Witness: []WitnessItem{{
			SuiteID:   0x42,
			Pubkey:    []byte{0x01, 0x02, 0x03},
			Signature: []byte{0x04, 0x01},
		}},
	}
	sighashCache, err := NewSighashV1PrehashCache(tx)
	if err != nil {
		t.Fatalf("sighash cache: %v", err)
	}

	called := false
	profiles, err := NewStaticCoreExtProfileProvider([]CoreExtDeploymentProfile{{
		ExtID:            7,
		ActivationHeight: 0,
		TxContextEnabled: true,
		AllowedSuites:    map[uint8]struct{}{0x42: {}},
		VerifySigExtTxContextFn: func(uint16, uint8, []byte, []byte, [32]byte, []byte, *TxContextBase, *TxContextContinuing, uint64) (bool, error) {
			called = true
			return true, nil
		},
		BindingDescriptor: []byte{0xa1},
		ExtPayloadSchema:  []byte{0xb2},
	}})
	if err != nil {
		t.Fatalf("NewStaticCoreExtProfileProvider: %v", err)
	}

	tvc := TxValidationContext{
		TxIndex: 1,
		Tx:      tx,
		ResolvedInputs: []UtxoEntry{{
			Value:        100,
			CovenantType: COV_TYPE_CORE_EXT,
			CovenantData: coreExtCovenantData(7, []byte{0x99}),
		}},
		WitnessStart: 0,
		WitnessEnd:   1,
		SighashCache: sighashCache,
		Fee:          10,
	}

	result := ValidateTxLocal(tvc, [32]byte{}, 1, 0, profiles, nil)
	if result.Err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, result.Err); got != TX_ERR_COVENANT_TYPE_INVALID {
		t.Fatalf("code=%s want %s", got, TX_ERR_COVENANT_TYPE_INVALID)
	}
	if called {
		t.Fatalf("verifier must not run when txcontext build rejects excessive continuing outputs")
	}
}

func TestValidateInputSpendQ_P2PKWrongSlots(t *testing.T) {
	entry := UtxoEntry{
		CovenantType: COV_TYPE_P2PK,
		CovenantData: p2pkCovenantDataForPubkey(make([]byte, ML_DSA_87_PUBKEY_BYTES)),
	}
	err := validateInputSpendQ(entry, []WitnessItem{{}, {}}, &Tx{}, 0, 100, [32]byte{}, 1, 0, nil, nil, nil, nil, nil, nil)
	if err == nil {
		t.Fatalf("expected error for wrong slot count")
	}
}

func TestValidateInputSpendQ_HTLCWrongSlots(t *testing.T) {
	preimage := make([]byte, 32)
	hash := sha3_256(preimage)
	covData := encodeHTLCCovenantData(hash, LOCK_MODE_HEIGHT, 100, [32]byte{}, [32]byte{})
	entry := UtxoEntry{
		CovenantType: COV_TYPE_HTLC,
		CovenantData: covData,
	}
	// Only 1 witness item instead of 2.
	err := validateInputSpendQ(entry, []WitnessItem{{}}, &Tx{}, 0, 100, [32]byte{}, 1, 0, nil, nil, nil, nil, nil, nil)
	if err == nil {
		t.Fatalf("expected error for HTLC wrong slot count")
	}
}

func TestValidateInputSpendQ_CoreExtWrongSlots(t *testing.T) {
	entry := UtxoEntry{
		CovenantType: COV_TYPE_CORE_EXT,
		CovenantData: makeCoreExtCovenantData(0x01),
	}
	err := validateInputSpendQ(entry, []WitnessItem{{}, {}}, &Tx{}, 0, 100, [32]byte{}, 1, 0, nil, nil, nil, nil, nil, nil)
	if err == nil {
		t.Fatalf("expected error for CORE_EXT wrong slot count")
	}
}

func TestValidateInputSpendQ_StealthWrongSlots(t *testing.T) {
	covData := stealthCovenantDataForKeyID([32]byte{})
	entry := UtxoEntry{
		CovenantType: COV_TYPE_CORE_STEALTH,
		CovenantData: covData,
	}
	err := validateInputSpendQ(entry, []WitnessItem{{}, {}}, &Tx{}, 0, 100, [32]byte{}, 1, 0, nil, nil, nil, nil, nil, nil)
	if err == nil {
		t.Fatalf("expected error for CORE_STEALTH wrong slot count")
	}
}

func TestValidateCoreExtSpendQ_SentinelForbidden(t *testing.T) {
	entry := UtxoEntry{
		CovenantType: COV_TYPE_CORE_EXT,
		CovenantData: makeCoreExtCovenantData(0x01),
	}
	profiles := &testCoreExtProfileProvider{
		profile: CoreExtProfile{
			Active:        true,
			AllowedSuites: map[uint8]struct{}{SUITE_ID_SENTINEL: {}},
		},
		found: true,
	}
	w := WitnessItem{SuiteID: SUITE_ID_SENTINEL}
	err := validateCoreExtSpendQ(entry, w, &Tx{}, 0, 100, [32]byte{}, 1, nil, profiles, nil, nil, nil, nil)
	if err == nil {
		t.Fatalf("expected error for sentinel under active profile")
	}
}

func TestValidateCoreExtSpendQ_DisallowedSuite(t *testing.T) {
	entry := UtxoEntry{
		CovenantType: COV_TYPE_CORE_EXT,
		CovenantData: makeCoreExtCovenantData(0x01),
	}
	profiles := &testCoreExtProfileProvider{
		profile: CoreExtProfile{
			Active:        true,
			AllowedSuites: map[uint8]struct{}{}, // no suites allowed
		},
		found: true,
	}
	w := WitnessItem{SuiteID: SUITE_ID_ML_DSA_87}
	err := validateCoreExtSpendQ(entry, w, &Tx{}, 0, 100, [32]byte{}, 1, nil, profiles, nil, nil, nil, nil)
	if err == nil {
		t.Fatalf("expected error for disallowed suite")
	}
}

func TestValidateCoreExtSpendQ_ExternalVerifier(t *testing.T) {
	entry := UtxoEntry{
		CovenantType: COV_TYPE_CORE_EXT,
		CovenantData: makeCoreExtCovenantData(0x01),
	}
	called := false
	profiles := &testCoreExtProfileProvider{
		profile: CoreExtProfile{
			Active:        true,
			AllowedSuites: map[uint8]struct{}{0x42: {}},
			VerifySigExtFn: func(extID uint16, suiteID uint8, pubkey []byte, signature []byte, digest32 [32]byte, extPayload []byte) (bool, error) {
				called = true
				return true, nil
			},
		},
		found: true,
	}
	// Need a valid Tx for extractSigAndDigestWithCache.
	var prevTxid [32]byte
	prevTxid[0] = 0x66
	tx := &Tx{
		Version: 1,
		TxKind:  0x00,
		TxNonce: 1,
		Inputs:  []TxInput{{PrevTxid: prevTxid, PrevVout: 0, Sequence: 0}},
		Outputs: []TxOutput{{Value: 90, CovenantType: COV_TYPE_P2PK, CovenantData: make([]byte, MAX_P2PK_COVENANT_DATA)}},
	}

	sighashCache, cacheErr := NewSighashV1PrehashCache(tx)
	if cacheErr != nil {
		t.Fatalf("sighash: %v", cacheErr)
	}

	w := WitnessItem{
		SuiteID:   0x42,
		Pubkey:    make([]byte, 10),
		Signature: append(make([]byte, 100), SIGHASH_ALL),
	}
	err := validateCoreExtSpendQ(entry, w, tx, 0, 100, [32]byte{}, 1, sighashCache, profiles, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("external verifier: %v", err)
	}
	if !called {
		t.Fatalf("external verifier was not called")
	}
}

func TestValidateCoreExtSpendQ_ExternalVerifierRejects(t *testing.T) {
	entry := UtxoEntry{
		CovenantType: COV_TYPE_CORE_EXT,
		CovenantData: makeCoreExtCovenantData(0x01),
	}
	profiles := &testCoreExtProfileProvider{
		profile: CoreExtProfile{
			Active:        true,
			AllowedSuites: map[uint8]struct{}{0x42: {}},
			VerifySigExtFn: func(extID uint16, suiteID uint8, pubkey []byte, signature []byte, digest32 [32]byte, extPayload []byte) (bool, error) {
				return false, nil // rejected
			},
		},
		found: true,
	}
	var prevTxid [32]byte
	prevTxid[0] = 0x88
	tx := &Tx{
		Version: 1, TxKind: 0x00, TxNonce: 1,
		Inputs:  []TxInput{{PrevTxid: prevTxid, PrevVout: 0, Sequence: 0}},
		Outputs: []TxOutput{{Value: 90, CovenantType: COV_TYPE_P2PK, CovenantData: make([]byte, MAX_P2PK_COVENANT_DATA)}},
	}
	sighashCache, _ := NewSighashV1PrehashCache(tx)
	w := WitnessItem{
		SuiteID:   0x42,
		Pubkey:    make([]byte, 10),
		Signature: append(make([]byte, 100), SIGHASH_ALL),
	}
	err := validateCoreExtSpendQ(entry, w, tx, 0, 100, [32]byte{}, 1, sighashCache, profiles, nil, nil, nil, nil)
	if err == nil {
		t.Fatalf("expected error for rejected external verifier")
	}
}

func TestValidateCoreExtSpendQ_ExternalVerifierError(t *testing.T) {
	entry := UtxoEntry{
		CovenantType: COV_TYPE_CORE_EXT,
		CovenantData: makeCoreExtCovenantData(0x01),
	}
	profiles := &testCoreExtProfileProvider{
		profile: CoreExtProfile{
			Active:        true,
			AllowedSuites: map[uint8]struct{}{0x42: {}},
			VerifySigExtFn: func(extID uint16, suiteID uint8, pubkey []byte, signature []byte, digest32 [32]byte, extPayload []byte) (bool, error) {
				return false, txerr(TX_ERR_SIG_ALG_INVALID, "ext error")
			},
		},
		found: true,
	}
	var prevTxid [32]byte
	prevTxid[0] = 0x99
	tx := &Tx{
		Version: 1, TxKind: 0x00, TxNonce: 1,
		Inputs:  []TxInput{{PrevTxid: prevTxid, PrevVout: 0, Sequence: 0}},
		Outputs: []TxOutput{{Value: 90, CovenantType: COV_TYPE_P2PK, CovenantData: make([]byte, MAX_P2PK_COVENANT_DATA)}},
	}
	sighashCache, _ := NewSighashV1PrehashCache(tx)
	w := WitnessItem{
		SuiteID:   0x42,
		Pubkey:    make([]byte, 10),
		Signature: append(make([]byte, 100), SIGHASH_ALL),
	}
	err := validateCoreExtSpendQ(entry, w, tx, 0, 100, [32]byte{}, 1, sighashCache, profiles, nil, nil, nil, nil)
	if err == nil {
		t.Fatalf("expected error for ext verifier error")
	}
}

func TestValidateCoreExtSpendQ_MLDSA87_NonCanonical(t *testing.T) {
	entry := UtxoEntry{
		CovenantType: COV_TYPE_CORE_EXT,
		CovenantData: makeCoreExtCovenantData(0x01),
	}
	profiles := &testCoreExtProfileProvider{
		profile: CoreExtProfile{
			Active:        true,
			AllowedSuites: map[uint8]struct{}{SUITE_ID_ML_DSA_87: {}},
		},
		found: true,
	}
	w := WitnessItem{
		SuiteID:   SUITE_ID_ML_DSA_87,
		Pubkey:    make([]byte, 10), // wrong size
		Signature: make([]byte, 10), // wrong size
	}
	err := validateCoreExtSpendQ(entry, w, &Tx{}, 0, 100, [32]byte{}, 1, nil, profiles, nil, nil, nil, nil)
	if err == nil {
		t.Fatalf("expected error for non-canonical ML-DSA lengths")
	}
}

func TestValidateCoreExtSpendQ_NilQueue_MLDSA(t *testing.T) {
	// Test the sigQueue==nil fallback for ML-DSA-87 in CORE_EXT.
	kp := mustMLDSA87Keypair(t)
	entry := UtxoEntry{
		CovenantType: COV_TYPE_CORE_EXT,
		CovenantData: makeCoreExtCovenantData(0x01),
	}
	profiles := &testCoreExtProfileProvider{
		profile: CoreExtProfile{
			Active:        true,
			AllowedSuites: map[uint8]struct{}{SUITE_ID_ML_DSA_87: {}},
		},
		found: true,
	}

	var prevTxid [32]byte
	prevTxid[0] = 0xAA
	tx := &Tx{
		Version: 1, TxKind: 0x00, TxNonce: 1,
		Inputs:  []TxInput{{PrevTxid: prevTxid, PrevVout: 0, Sequence: 0}},
		Outputs: []TxOutput{{Value: 90, CovenantType: COV_TYPE_P2PK, CovenantData: p2pkCovenantDataForPubkey(kp.PubkeyBytes())}},
	}
	tx.Witness = []WitnessItem{signP2PKInputWitness(t, tx, 0, 100, [32]byte{}, kp)}
	sighashCache, _ := NewSighashV1PrehashCache(tx)

	// sigQueue=nil → inline verifySig
	err := validateCoreExtSpendQ(entry, tx.Witness[0], tx, 0, 100, [32]byte{}, 1, sighashCache, profiles, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("nil queue MLDSA: %v", err)
	}
}

func TestValidateCoreExtSpendQ_ProfileLookupError(t *testing.T) {
	entry := UtxoEntry{
		CovenantType: COV_TYPE_CORE_EXT,
		CovenantData: makeCoreExtCovenantData(0x01),
	}
	profiles := &testCoreExtProfileProvider{
		err: txerr(TX_ERR_COVENANT_TYPE_INVALID, "lookup fail"),
	}
	w := WitnessItem{SuiteID: SUITE_ID_ML_DSA_87}
	err := validateCoreExtSpendQ(entry, w, &Tx{}, 0, 100, [32]byte{}, 1, nil, profiles, nil, nil, nil, nil)
	if err == nil {
		t.Fatalf("expected error for profile lookup failure")
	}
}

func TestValidateCoreExtSpendQ_ExternalVerifierNil(t *testing.T) {
	entry := UtxoEntry{
		CovenantType: COV_TYPE_CORE_EXT,
		CovenantData: makeCoreExtCovenantData(0x01),
	}
	profiles := &testCoreExtProfileProvider{
		profile: CoreExtProfile{
			Active:        true,
			AllowedSuites: map[uint8]struct{}{0x42: {}},
			// No VerifySigExtFn → nil
		},
		found: true,
	}
	var prevTxid [32]byte
	prevTxid[0] = 0x77
	tx := &Tx{
		Version: 1,
		TxKind:  0x00,
		TxNonce: 1,
		Inputs:  []TxInput{{PrevTxid: prevTxid, PrevVout: 0, Sequence: 0}},
		Outputs: []TxOutput{{Value: 90, CovenantType: COV_TYPE_P2PK, CovenantData: make([]byte, MAX_P2PK_COVENANT_DATA)}},
	}
	sighashCache, _ := NewSighashV1PrehashCache(tx)

	w := WitnessItem{
		SuiteID:   0x42,
		Pubkey:    make([]byte, 10),
		Signature: append(make([]byte, 100), SIGHASH_ALL),
	}
	err := validateCoreExtSpendQ(entry, w, tx, 0, 100, [32]byte{}, 1, sighashCache, profiles, nil, nil, nil, nil)
	if err == nil {
		t.Fatalf("expected error for nil external verifier")
	}
}
