package consensus

import (
	"testing"
)

// ─────────────────────────────────────────────────────────────────────────────
// Test helpers for precompute tests
// ─────────────────────────────────────────────────────────────────────────────

// makeParsedBlockForPrecompute builds a minimal ParsedBlock with a coinbase
// and the given non-coinbase transactions. Txids are deterministic sha3 hashes.
func makeParsedBlockForPrecompute(coinbase *Tx, txs []*Tx) *ParsedBlock {
	allTxs := make([]*Tx, 0, 1+len(txs))
	allTxs = append(allTxs, coinbase)
	allTxs = append(allTxs, txs...)

	txids := make([][32]byte, len(allTxs))
	for i := range allTxs {
		// Deterministic txid: sha3(index byte).
		txids[i] = sha3_256([]byte{byte(i)})
	}

	return &ParsedBlock{
		Txs:   allTxs,
		Txids: txids,
	}
}

// makeSimpleCoinbase returns a minimal coinbase tx.
func makeSimpleCoinbase() *Tx {
	var zeroTxid [32]byte
	return &Tx{
		Version: 1,
		TxKind:  0x00,
		TxNonce: 0,
		Inputs: []TxInput{{
			PrevTxid: zeroTxid,
			PrevVout: 0xffff_ffff,
			Sequence: 0,
		}},
		Outputs: []TxOutput{{
			Value:        50_000_000,
			CovenantType: COV_TYPE_P2PK,
			CovenantData: validP2PKCovenantData(),
		}},
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// PrecomputeTxContexts: basic behavior
// ─────────────────────────────────────────────────────────────────────────────

func TestPrecomputeTxContexts_CoinbaseOnlyBlock(t *testing.T) {
	pb := makeParsedBlockForPrecompute(makeSimpleCoinbase(), nil)
	utxos := map[Outpoint]UtxoEntry{}

	results, err := PrecomputeTxContexts(pb, utxos, 100)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if results != nil {
		t.Fatalf("expected nil for coinbase-only block, got %d contexts", len(results))
	}
}

func TestPrecomputeTxContexts_NilBlock(t *testing.T) {
	_, err := PrecomputeTxContexts(nil, nil, 0)
	if err == nil {
		t.Fatal("expected error for nil block")
	}
}

func TestPrecomputeTxContexts_SingleP2PK(t *testing.T) {
	// Seed a P2PK UTXO in the snapshot.
	covData := validP2PKCovenantData()
	prevTxid := sha3_256([]byte("prev-tx-for-precompute"))
	op := Outpoint{Txid: prevTxid, Vout: 0}
	utxos := map[Outpoint]UtxoEntry{
		op: {
			Value:        1000,
			CovenantType: COV_TYPE_P2PK,
			CovenantData: covData,
		},
	}

	tx := &Tx{
		Version: 1,
		TxKind:  0x00,
		TxNonce: 1,
		Inputs: []TxInput{{
			PrevTxid: prevTxid,
			PrevVout: 0,
			Sequence: 0,
		}},
		Outputs: []TxOutput{{
			Value:        900,
			CovenantType: COV_TYPE_P2PK,
			CovenantData: covData,
		}},
		Witness: []WitnessItem{{
			SuiteID:   SUITE_ID_ML_DSA_87,
			Pubkey:    make([]byte, ML_DSA_87_PUBKEY_BYTES),
			Signature: make([]byte, ML_DSA_87_SIG_BYTES+1),
		}},
	}

	pb := makeParsedBlockForPrecompute(makeSimpleCoinbase(), []*Tx{tx})

	results, err := PrecomputeTxContexts(pb, utxos, 100)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 context, got %d", len(results))
	}

	ctx := results[0]

	// Verify TxIndex.
	if ctx.TxIndex != 1 {
		t.Errorf("TxIndex: got %d, want 1", ctx.TxIndex)
	}

	// Verify resolved inputs.
	if len(ctx.ResolvedInputs) != 1 {
		t.Fatalf("ResolvedInputs length: got %d, want 1", len(ctx.ResolvedInputs))
	}
	if ctx.ResolvedInputs[0].Value != 1000 {
		t.Errorf("ResolvedInputs[0].Value: got %d, want 1000", ctx.ResolvedInputs[0].Value)
	}

	// Verify witness boundaries: P2PK = 1 slot, cursor starts at 0.
	if ctx.WitnessStart != 0 {
		t.Errorf("WitnessStart: got %d, want 0", ctx.WitnessStart)
	}
	if ctx.WitnessEnd != 1 {
		t.Errorf("WitnessEnd: got %d, want 1", ctx.WitnessEnd)
	}

	// Verify fee.
	if ctx.Fee != 100 {
		t.Errorf("Fee: got %d, want 100", ctx.Fee)
	}

	// Verify sighash cache is non-nil.
	if ctx.SighashCache == nil {
		t.Error("SighashCache is nil")
	}

	// Verify input outpoints.
	if len(ctx.InputOutpoints) != 1 {
		t.Fatalf("InputOutpoints length: got %d, want 1", len(ctx.InputOutpoints))
	}
	if ctx.InputOutpoints[0] != op {
		t.Errorf("InputOutpoints[0]: got %v, want %v", ctx.InputOutpoints[0], op)
	}
}

func TestPrecomputeTxContexts_WitnessCursorParity(t *testing.T) {
	// Two transactions, each P2PK (1 witness slot each).
	// Sequential cursor model: tx0 gets [0,1), tx1 gets [1,2).
	covData := validP2PKCovenantData()
	prev0 := sha3_256([]byte("utxo-0"))
	prev1 := sha3_256([]byte("utxo-1"))

	utxos := map[Outpoint]UtxoEntry{
		{Txid: prev0, Vout: 0}: {Value: 500, CovenantType: COV_TYPE_P2PK, CovenantData: covData},
		{Txid: prev1, Vout: 0}: {Value: 500, CovenantType: COV_TYPE_P2PK, CovenantData: covData},
	}

	dummyWitness := WitnessItem{
		SuiteID:   SUITE_ID_ML_DSA_87,
		Pubkey:    make([]byte, ML_DSA_87_PUBKEY_BYTES),
		Signature: make([]byte, ML_DSA_87_SIG_BYTES+1),
	}

	tx0 := &Tx{
		Version: 1, TxKind: 0x00, TxNonce: 1,
		Inputs:  []TxInput{{PrevTxid: prev0, PrevVout: 0, Sequence: 0}},
		Outputs: []TxOutput{{Value: 400, CovenantType: COV_TYPE_P2PK, CovenantData: covData}},
		Witness: []WitnessItem{dummyWitness},
	}
	tx1 := &Tx{
		Version: 1, TxKind: 0x00, TxNonce: 2,
		Inputs:  []TxInput{{PrevTxid: prev1, PrevVout: 0, Sequence: 0}},
		Outputs: []TxOutput{{Value: 400, CovenantType: COV_TYPE_P2PK, CovenantData: covData}},
		Witness: []WitnessItem{dummyWitness},
	}

	pb := makeParsedBlockForPrecompute(makeSimpleCoinbase(), []*Tx{tx0, tx1})

	results, err := PrecomputeTxContexts(pb, utxos, 100)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 contexts, got %d", len(results))
	}

	// Witness cursor is per-tx (reset to 0 for each tx).
	// tx0: witness [0,1) within tx0.Witness
	if results[0].WitnessStart != 0 || results[0].WitnessEnd != 1 {
		t.Errorf("tx0 witness: got [%d,%d), want [0,1)", results[0].WitnessStart, results[0].WitnessEnd)
	}
	// tx1: witness [0,1) within tx1.Witness (cursor resets per tx)
	if results[1].WitnessStart != 0 || results[1].WitnessEnd != 1 {
		t.Errorf("tx1 witness: got [%d,%d), want [0,1)", results[1].WitnessStart, results[1].WitnessEnd)
	}

	// Verify fees.
	if results[0].Fee != 100 {
		t.Errorf("tx0 fee: got %d, want 100", results[0].Fee)
	}
	if results[1].Fee != 100 {
		t.Errorf("tx1 fee: got %d, want 100", results[1].Fee)
	}
}

func TestPrecomputeTxContexts_SameBlockParentChild(t *testing.T) {
	// tx0 creates an output, tx1 spends it (same block).
	covData := validP2PKCovenantData()
	prevTxid := sha3_256([]byte("genesis-utxo"))

	utxos := map[Outpoint]UtxoEntry{
		{Txid: prevTxid, Vout: 0}: {Value: 1000, CovenantType: COV_TYPE_P2PK, CovenantData: covData},
	}

	dummyWitness := WitnessItem{
		SuiteID:   SUITE_ID_ML_DSA_87,
		Pubkey:    make([]byte, ML_DSA_87_PUBKEY_BYTES),
		Signature: make([]byte, ML_DSA_87_SIG_BYTES+1),
	}

	tx0 := &Tx{
		Version: 1, TxKind: 0x00, TxNonce: 1,
		Inputs:  []TxInput{{PrevTxid: prevTxid, PrevVout: 0, Sequence: 0}},
		Outputs: []TxOutput{{Value: 900, CovenantType: COV_TYPE_P2PK, CovenantData: covData}},
		Witness: []WitnessItem{dummyWitness},
	}

	// tx1 spends tx0's output. The txid of tx0 in the ParsedBlock is
	// deterministic: sha3(byte(1)) since tx0 is at block index 1.
	tx0Txid := sha3_256([]byte{byte(1)})
	tx1 := &Tx{
		Version: 1, TxKind: 0x00, TxNonce: 2,
		Inputs:  []TxInput{{PrevTxid: tx0Txid, PrevVout: 0, Sequence: 0}},
		Outputs: []TxOutput{{Value: 800, CovenantType: COV_TYPE_P2PK, CovenantData: covData}},
		Witness: []WitnessItem{dummyWitness},
	}

	pb := makeParsedBlockForPrecompute(makeSimpleCoinbase(), []*Tx{tx0, tx1})

	results, err := PrecomputeTxContexts(pb, utxos, 100)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 contexts, got %d", len(results))
	}

	// tx1 resolved input should have value 900 (from tx0's output).
	if results[1].ResolvedInputs[0].Value != 900 {
		t.Errorf("tx1 resolved input value: got %d, want 900", results[1].ResolvedInputs[0].Value)
	}
	// tx1 fee: 900 - 800 = 100.
	if results[1].Fee != 100 {
		t.Errorf("tx1 fee: got %d, want 100", results[1].Fee)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// PrecomputeTxContexts: error paths
// ─────────────────────────────────────────────────────────────────────────────

func TestPrecomputeTxContexts_MissingUTXO(t *testing.T) {
	covData := validP2PKCovenantData()
	prevTxid := sha3_256([]byte("nonexistent"))

	tx := &Tx{
		Version: 1, TxKind: 0x00, TxNonce: 1,
		Inputs:  []TxInput{{PrevTxid: prevTxid, PrevVout: 0, Sequence: 0}},
		Outputs: []TxOutput{{Value: 100, CovenantType: COV_TYPE_P2PK, CovenantData: covData}},
		Witness: []WitnessItem{{SuiteID: SUITE_ID_ML_DSA_87, Pubkey: make([]byte, ML_DSA_87_PUBKEY_BYTES), Signature: make([]byte, ML_DSA_87_SIG_BYTES+1)}},
	}

	pb := makeParsedBlockForPrecompute(makeSimpleCoinbase(), []*Tx{tx})
	_, err := PrecomputeTxContexts(pb, map[Outpoint]UtxoEntry{}, 100)
	if err == nil {
		t.Fatal("expected error for missing UTXO")
	}
	if !isTxErrCode(err, TX_ERR_MISSING_UTXO) {
		t.Fatalf("expected TX_ERR_MISSING_UTXO, got: %v", err)
	}
}

func TestPrecomputeTxContexts_DuplicateInput(t *testing.T) {
	covData := validP2PKCovenantData()
	prevTxid := sha3_256([]byte("dup-input"))
	op := Outpoint{Txid: prevTxid, Vout: 0}
	utxos := map[Outpoint]UtxoEntry{
		op: {Value: 1000, CovenantType: COV_TYPE_P2PK, CovenantData: covData},
	}

	// Two inputs referencing the same outpoint.
	tx := &Tx{
		Version: 1, TxKind: 0x00, TxNonce: 1,
		Inputs: []TxInput{
			{PrevTxid: prevTxid, PrevVout: 0, Sequence: 0},
			{PrevTxid: prevTxid, PrevVout: 0, Sequence: 0},
		},
		Outputs: []TxOutput{{Value: 100, CovenantType: COV_TYPE_P2PK, CovenantData: covData}},
		Witness: []WitnessItem{
			{SuiteID: SUITE_ID_ML_DSA_87, Pubkey: make([]byte, ML_DSA_87_PUBKEY_BYTES), Signature: make([]byte, ML_DSA_87_SIG_BYTES+1)},
			{SuiteID: SUITE_ID_ML_DSA_87, Pubkey: make([]byte, ML_DSA_87_PUBKEY_BYTES), Signature: make([]byte, ML_DSA_87_SIG_BYTES+1)},
		},
	}

	pb := makeParsedBlockForPrecompute(makeSimpleCoinbase(), []*Tx{tx})
	_, err := PrecomputeTxContexts(pb, utxos, 100)
	if err == nil {
		t.Fatal("expected error for duplicate input")
	}
	if !isTxErrCode(err, TX_ERR_PARSE) {
		t.Fatalf("expected TX_ERR_PARSE, got: %v", err)
	}
}

func TestPrecomputeTxContexts_WitnessUnderflow(t *testing.T) {
	covData := validP2PKCovenantData()
	prevTxid := sha3_256([]byte("witness-underflow"))
	utxos := map[Outpoint]UtxoEntry{
		{Txid: prevTxid, Vout: 0}: {Value: 500, CovenantType: COV_TYPE_P2PK, CovenantData: covData},
	}

	// P2PK needs 1 witness slot, but we provide 0.
	tx := &Tx{
		Version: 1, TxKind: 0x00, TxNonce: 1,
		Inputs:  []TxInput{{PrevTxid: prevTxid, PrevVout: 0, Sequence: 0}},
		Outputs: []TxOutput{{Value: 400, CovenantType: COV_TYPE_P2PK, CovenantData: covData}},
		Witness: []WitnessItem{}, // empty!
	}

	pb := makeParsedBlockForPrecompute(makeSimpleCoinbase(), []*Tx{tx})
	_, err := PrecomputeTxContexts(pb, utxos, 100)
	if err == nil {
		t.Fatal("expected witness underflow error")
	}
	if !isTxErrCode(err, TX_ERR_PARSE) {
		t.Fatalf("expected TX_ERR_PARSE, got: %v", err)
	}
}

func TestPrecomputeTxContexts_OutputsExceedInputs(t *testing.T) {
	covData := validP2PKCovenantData()
	prevTxid := sha3_256([]byte("value-overflow"))
	utxos := map[Outpoint]UtxoEntry{
		{Txid: prevTxid, Vout: 0}: {Value: 100, CovenantType: COV_TYPE_P2PK, CovenantData: covData},
	}

	tx := &Tx{
		Version: 1, TxKind: 0x00, TxNonce: 1,
		Inputs:  []TxInput{{PrevTxid: prevTxid, PrevVout: 0, Sequence: 0}},
		Outputs: []TxOutput{{Value: 200, CovenantType: COV_TYPE_P2PK, CovenantData: covData}}, // > 100
		Witness: []WitnessItem{{SuiteID: SUITE_ID_ML_DSA_87, Pubkey: make([]byte, ML_DSA_87_PUBKEY_BYTES), Signature: make([]byte, ML_DSA_87_SIG_BYTES+1)}},
	}

	pb := makeParsedBlockForPrecompute(makeSimpleCoinbase(), []*Tx{tx})
	_, err := PrecomputeTxContexts(pb, utxos, 100)
	if err == nil {
		t.Fatal("expected value overflow error")
	}
	if !isTxErrCode(err, TX_ERR_VALUE_CONSERVATION) {
		t.Fatalf("expected TX_ERR_VALUE_CONSERVATION, got: %v", err)
	}
}

func TestPrecomputeTxContexts_NonSpendableCovenant(t *testing.T) {
	prevTxid := sha3_256([]byte("anchor-spend"))
	utxos := map[Outpoint]UtxoEntry{
		{Txid: prevTxid, Vout: 0}: {Value: 100, CovenantType: COV_TYPE_ANCHOR},
	}

	tx := &Tx{
		Version: 1, TxKind: 0x00, TxNonce: 1,
		Inputs:  []TxInput{{PrevTxid: prevTxid, PrevVout: 0, Sequence: 0}},
		Outputs: []TxOutput{{Value: 50, CovenantType: COV_TYPE_P2PK, CovenantData: validP2PKCovenantData()}},
		Witness: []WitnessItem{{SuiteID: SUITE_ID_ML_DSA_87, Pubkey: make([]byte, ML_DSA_87_PUBKEY_BYTES), Signature: make([]byte, ML_DSA_87_SIG_BYTES+1)}},
	}

	pb := makeParsedBlockForPrecompute(makeSimpleCoinbase(), []*Tx{tx})
	_, err := PrecomputeTxContexts(pb, utxos, 100)
	if err == nil {
		t.Fatal("expected error for non-spendable covenant")
	}
	if !isTxErrCode(err, TX_ERR_MISSING_UTXO) {
		t.Fatalf("expected TX_ERR_MISSING_UTXO, got: %v", err)
	}
}

func TestPrecomputeTxContexts_CoinbasePrevoutForbidden(t *testing.T) {
	var zeroTxid [32]byte
	utxos := map[Outpoint]UtxoEntry{}

	tx := &Tx{
		Version: 1, TxKind: 0x00, TxNonce: 1,
		Inputs:  []TxInput{{PrevTxid: zeroTxid, PrevVout: 0xffff_ffff, Sequence: 0}},
		Outputs: []TxOutput{{Value: 50, CovenantType: COV_TYPE_P2PK, CovenantData: validP2PKCovenantData()}},
		Witness: []WitnessItem{{SuiteID: SUITE_ID_ML_DSA_87, Pubkey: make([]byte, ML_DSA_87_PUBKEY_BYTES), Signature: make([]byte, ML_DSA_87_SIG_BYTES+1)}},
	}

	pb := makeParsedBlockForPrecompute(makeSimpleCoinbase(), []*Tx{tx})
	_, err := PrecomputeTxContexts(pb, utxos, 100)
	if err == nil {
		t.Fatal("expected error for coinbase prevout in non-coinbase")
	}
	if !isTxErrCode(err, TX_ERR_PARSE) {
		t.Fatalf("expected TX_ERR_PARSE, got: %v", err)
	}
}

func TestPrecomputeTxContexts_NilTx(t *testing.T) {
	pb := makeParsedBlockForPrecompute(makeSimpleCoinbase(), []*Tx{nil})
	_, err := PrecomputeTxContexts(pb, map[Outpoint]UtxoEntry{}, 100)
	if err == nil {
		t.Fatal("expected error for nil tx")
	}
}

func TestPrecomputeTxContexts_NoInputs(t *testing.T) {
	tx := &Tx{
		Version: 1, TxKind: 0x00, TxNonce: 1,
		Inputs:  []TxInput{},
		Outputs: []TxOutput{{Value: 50, CovenantType: COV_TYPE_P2PK, CovenantData: validP2PKCovenantData()}},
	}

	pb := makeParsedBlockForPrecompute(makeSimpleCoinbase(), []*Tx{tx})
	_, err := PrecomputeTxContexts(pb, map[Outpoint]UtxoEntry{}, 100)
	if err == nil {
		t.Fatal("expected error for tx with no inputs")
	}
}

func TestPrecomputeTxContexts_SnapshotNotMutated(t *testing.T) {
	// Verify that the original UTXO snapshot is not modified.
	covData := validP2PKCovenantData()
	prevTxid := sha3_256([]byte("snapshot-immutable"))
	op := Outpoint{Txid: prevTxid, Vout: 0}
	utxos := map[Outpoint]UtxoEntry{
		op: {Value: 1000, CovenantType: COV_TYPE_P2PK, CovenantData: covData},
	}

	tx := &Tx{
		Version: 1, TxKind: 0x00, TxNonce: 1,
		Inputs:  []TxInput{{PrevTxid: prevTxid, PrevVout: 0, Sequence: 0}},
		Outputs: []TxOutput{{Value: 900, CovenantType: COV_TYPE_P2PK, CovenantData: covData}},
		Witness: []WitnessItem{{SuiteID: SUITE_ID_ML_DSA_87, Pubkey: make([]byte, ML_DSA_87_PUBKEY_BYTES), Signature: make([]byte, ML_DSA_87_SIG_BYTES+1)}},
	}

	pb := makeParsedBlockForPrecompute(makeSimpleCoinbase(), []*Tx{tx})
	_, err := PrecomputeTxContexts(pb, utxos, 100)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Original snapshot must still have the UTXO.
	if _, ok := utxos[op]; !ok {
		t.Fatal("original UTXO snapshot was mutated: entry removed")
	}
	if len(utxos) != 1 {
		t.Fatalf("original UTXO snapshot was mutated: expected 1 entry, got %d", len(utxos))
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// HTLC witness slots parity (2 slots per HTLC input)
// ─────────────────────────────────────────────────────────────────────────────

func TestPrecomputeTxContexts_HTLCWitnessSlots(t *testing.T) {
	preimage := make([]byte, MIN_HTLC_PREIMAGE_BYTES)
	preimage[0] = 0xAA
	hash := sha3_256(preimage)

	var claimKeyID, refundKeyID [32]byte
	claimKeyID[0] = 0x01
	refundKeyID[0] = 0x02
	htlcCovData := encodeHTLCCovenantData(hash, LOCK_MODE_HEIGHT, 100, claimKeyID, refundKeyID)

	prevTxid := sha3_256([]byte("htlc-utxo"))
	utxos := map[Outpoint]UtxoEntry{
		{Txid: prevTxid, Vout: 0}: {Value: 500, CovenantType: COV_TYPE_HTLC, CovenantData: htlcCovData},
	}

	dummyWitness := WitnessItem{SuiteID: SUITE_ID_SENTINEL, Pubkey: make([]byte, 32), Signature: []byte{0x00}}
	dummySig := WitnessItem{SuiteID: SUITE_ID_ML_DSA_87, Pubkey: make([]byte, ML_DSA_87_PUBKEY_BYTES), Signature: make([]byte, ML_DSA_87_SIG_BYTES+1)}

	tx := &Tx{
		Version: 1, TxKind: 0x00, TxNonce: 1,
		Inputs:  []TxInput{{PrevTxid: prevTxid, PrevVout: 0, Sequence: 0}},
		Outputs: []TxOutput{{Value: 400, CovenantType: COV_TYPE_P2PK, CovenantData: validP2PKCovenantData()}},
		Witness: []WitnessItem{dummyWitness, dummySig}, // 2 slots for HTLC
	}

	pb := makeParsedBlockForPrecompute(makeSimpleCoinbase(), []*Tx{tx})
	results, err := PrecomputeTxContexts(pb, utxos, 100)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 context, got %d", len(results))
	}

	// HTLC = 2 witness slots.
	if results[0].WitnessStart != 0 || results[0].WitnessEnd != 2 {
		t.Errorf("HTLC witness: got [%d,%d), want [0,2)", results[0].WitnessStart, results[0].WitnessEnd)
	}
}
