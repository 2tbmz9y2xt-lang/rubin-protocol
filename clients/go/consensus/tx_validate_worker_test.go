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

func TestValidateTxLocal_ResolvedInputCountMismatchUsesTxContextError(t *testing.T) {
	tx := &Tx{
		Version: TX_WIRE_VERSION,
		TxKind:  0x00,
		TxNonce: 1,
		Inputs:  []TxInput{{PrevVout: 0}},
	}

	result := ValidateTxLocal(TxValidationContext{TxIndex: 1, Tx: tx}, [32]byte{}, 1, 0, nil, nil)
	assertTxErrCodeMsg(t, result.Err, TX_ERR_PARSE, "txcontext resolved input count mismatch")
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

func TestValidateTxLocal_CoreSimplicitySpendRejected(t *testing.T) {
	var prevTxid [32]byte
	prevTxid[0] = 0x66
	tx := &Tx{
		Version: 1,
		TxKind:  0x00,
		TxNonce: 1,
		Inputs:  []TxInput{{PrevTxid: prevTxid, PrevVout: 0}},
		Outputs: []TxOutput{{Value: 90, CovenantType: COV_TYPE_P2PK, CovenantData: validP2PKCovenantData()}},
		Witness: dummyWitnesses(SIMPLICITY_WITNESS_SLOTS),
	}
	tvc := TxValidationContext{
		TxIndex: 1,
		Tx:      tx,
		ResolvedInputs: []UtxoEntry{{
			Value:        100,
			CovenantType: COV_TYPE_CORE_SIMPLICITY,
			CovenantData: encodeSimplicityCovenantData([32]byte{0x66}, nil),
		}},
		WitnessStart: 0,
		WitnessEnd:   SIMPLICITY_WITNESS_SLOTS,
		Fee:          10,
	}

	result := ValidateTxLocal(tvc, [32]byte{}, 1, 0, nil, nil)
	assertTxErrCodeMsg(t, result.Err, TX_ERR_COVENANT_TYPE_INVALID, "CORE_SIMPLICITY spend evaluation not enabled")
}

func TestValidateTxLocal_CoreSimplicityInputGroupCapDeferredBehindDisabledSpend(t *testing.T) {
	cmr := [32]byte{0x67}
	run := func(inputCount int, splitLast bool) TxValidationResult {
		t.Helper()
		outputs := []TxOutput{{Value: 1, CovenantType: COV_TYPE_P2PK, CovenantData: validP2PKCovenantData()}}
		tx := &Tx{
			Version: 1,
			TxKind:  0x00,
			TxNonce: 1,
			Inputs:  make([]TxInput, inputCount),
			Outputs: outputs,
			Witness: dummyWitnesses(inputCount * SIMPLICITY_WITNESS_SLOTS),
		}
		resolved := make([]UtxoEntry, inputCount)
		for i := range tx.Inputs {
			inputCMR := cmr
			if splitLast && i == len(tx.Inputs)-1 {
				inputCMR = [32]byte{0x68}
			}
			tx.Inputs[i] = TxInput{PrevTxid: hashWithPrefix(byte(0x70 + i)), PrevVout: 0}
			resolved[i] = UtxoEntry{
				Value:        1,
				CovenantType: COV_TYPE_CORE_SIMPLICITY,
				CovenantData: encodeSimplicityCovenantData(inputCMR, []byte{byte(i)}),
			}
		}
		sighashCache, err := NewSighashV1PrehashCache(tx)
		if err != nil {
			t.Fatalf("NewSighashV1PrehashCache: %v", err)
		}

		return ValidateTxLocal(TxValidationContext{
			TxIndex:        1,
			Tx:             tx,
			ResolvedInputs: resolved,
			WitnessStart:   0,
			WitnessEnd:     len(tx.Witness),
			SighashCache:   sighashCache,
			Fee:            uint64(inputCount - 1),
		}, [32]byte{}, 1, 0, nil, nil)
	}

	assertTxErrCodeMsg(t, run(SIMPLICITY_MAX_GROUP_INPUTS, false).Err, TX_ERR_COVENANT_TYPE_INVALID, "CORE_SIMPLICITY spend evaluation not enabled")
	assertTxErrCodeMsg(t, run(SIMPLICITY_MAX_GROUP_INPUTS+1, true).Err, TX_ERR_COVENANT_TYPE_INVALID, "CORE_SIMPLICITY spend evaluation not enabled")
	assertTxErrCodeMsg(t, run(SIMPLICITY_MAX_GROUP_INPUTS+1, false).Err, TX_ERR_COVENANT_TYPE_INVALID, "CORE_SIMPLICITY spend evaluation not enabled")
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
	cancel() // already canceled

	results, err := RunTxValidationWorkers(ctx, 2, txcs, [32]byte{}, 1, 0, nil, nil)
	if err != nil {
		t.Fatalf("RunTxValidationWorkers: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Err == nil {
		t.Fatalf("expected error from canceled context")
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

func validateTestInputSpendQ(entry UtxoEntry, assigned []WitnessItem, tx *Tx) error {
	check := txInputSpendCheck{
		entry:      entry,
		assigned:   assigned,
		tx:         tx,
		inputIndex: 0,
		inputValue: 100,
	}
	return validateInputSpendQ(check, txValidationWorkerEnv{blockHeight: 1})
}

func TestValidateInputSpendQ_DefaultCovType(t *testing.T) {
	// Unknown/unhandled covenant type should return nil (no spend checks).
	entry := UtxoEntry{
		CovenantType: 0xFFFF, // unknown type
		CovenantData: []byte{0x00},
	}
	err := validateTestInputSpendQ(entry, nil, &Tx{})
	if err != nil {
		t.Fatalf("expected nil for unknown covenant type, got: %v", err)
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

func TestValidateInputSpendQ_P2PKWrongSlots(t *testing.T) {
	entry := UtxoEntry{
		CovenantType: COV_TYPE_P2PK,
		CovenantData: p2pkCovenantDataForPubkey(make([]byte, ML_DSA_87_PUBKEY_BYTES)),
	}
	err := validateTestInputSpendQ(entry, []WitnessItem{{}, {}}, &Tx{})
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
	err := validateTestInputSpendQ(entry, []WitnessItem{{}}, &Tx{})
	if err == nil {
		t.Fatalf("expected error for HTLC wrong slot count")
	}
}

func TestValidateInputSpendQ_StealthWrongSlots(t *testing.T) {
	covData := stealthCovenantDataForKeyID([32]byte{})
	entry := UtxoEntry{
		CovenantType: COV_TYPE_CORE_STEALTH,
		CovenantData: covData,
	}
	err := validateTestInputSpendQ(entry, []WitnessItem{{}, {}}, &Tx{})
	if err == nil {
		t.Fatalf("expected error for CORE_STEALTH wrong slot count")
	}
}
