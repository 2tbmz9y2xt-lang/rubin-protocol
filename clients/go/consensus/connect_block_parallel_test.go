package consensus

import (
	"math/big"
	"testing"
)

// TestConnectBlockParallelSigVerify_OK exercises the full parallel sig verify
// path with a block containing a single P2PK spend transaction. The result
// must match the sequential ConnectBlockBasicInMemoryAtHeight exactly.
func TestConnectBlockParallelSigVerify_OK(t *testing.T) {
	height := uint64(1)
	prev := hashWithPrefix(0x77)
	target := filledHash(0xff)

	kp := mustMLDSA87Keypair(t)
	covData := p2pkCovenantDataForPubkey(kp.PubkeyBytes())

	prevOut := Outpoint{Txid: prev, Vout: 0}
	spendTx := &Tx{
		Version:  1,
		TxKind:   0x00,
		TxNonce:  1,
		Inputs:   []TxInput{{PrevTxid: prev, PrevVout: 0, Sequence: 0}},
		Outputs:  []TxOutput{{Value: 90, CovenantType: COV_TYPE_P2PK, CovenantData: covData}},
		Locktime: 0,
	}
	spendTx.Witness = []WitnessItem{signP2PKInputWitness(t, spendTx, 0, 100, [32]byte{}, kp)}
	spendBytes := txBytesFromTx(t, spendTx)
	_, spendTxid, _, _, err := ParseTx(spendBytes)
	if err != nil {
		t.Fatalf("ParseTx(spend): %v", err)
	}

	// Create two identical states for sequential and parallel paths.
	makeState := func() *InMemoryChainState {
		return &InMemoryChainState{
			Utxos: map[Outpoint]UtxoEntry{
				prevOut: {
					Value:        100,
					CovenantType: COV_TYPE_P2PK,
					CovenantData: append([]byte(nil), covData...),
				},
			},
			AlreadyGenerated: new(big.Int),
		}
	}

	sumFees := uint64(10)
	subsidy := BlockSubsidyBig(height, makeState().AlreadyGenerated)
	coinbase := coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, height, subsidy+sumFees, spendBytes)
	cbTxid := testTxID(t, coinbase)

	root, err := MerkleRootTxids([][32]byte{cbTxid, spendTxid})
	if err != nil {
		t.Fatalf("MerkleRootTxids: %v", err)
	}
	block := buildBlockBytes(t, prev, root, target, 1, [][]byte{coinbase, spendBytes})

	// Sequential path.
	seqState := makeState()
	seqSummary, err := ConnectBlockBasicInMemoryAtHeight(block, &prev, &target, height, []uint64{0}, seqState, [32]byte{})
	if err != nil {
		t.Fatalf("Sequential: %v", err)
	}

	// Parallel path.
	parState := makeState()
	parSummary, err := ConnectBlockParallelSigVerify(block, &prev, &target, height, []uint64{0}, parState, [32]byte{}, 4)
	if err != nil {
		t.Fatalf("Parallel: %v", err)
	}

	// Results must match.
	if seqSummary.SumFees != parSummary.SumFees {
		t.Fatalf("SumFees mismatch: seq=%d, par=%d", seqSummary.SumFees, parSummary.SumFees)
	}
	if seqSummary.AlreadyGenerated != parSummary.AlreadyGenerated {
		t.Fatalf("AlreadyGenerated mismatch: seq=%d, par=%d", seqSummary.AlreadyGenerated, parSummary.AlreadyGenerated)
	}
	if seqSummary.AlreadyGeneratedN1 != parSummary.AlreadyGeneratedN1 {
		t.Fatalf("AlreadyGeneratedN1 mismatch: seq=%d, par=%d", seqSummary.AlreadyGeneratedN1, parSummary.AlreadyGeneratedN1)
	}
	if seqSummary.UtxoCount != parSummary.UtxoCount {
		t.Fatalf("UtxoCount mismatch: seq=%d, par=%d", seqSummary.UtxoCount, parSummary.UtxoCount)
	}

	// UTXO sets must match.
	if len(seqState.Utxos) != len(parState.Utxos) {
		t.Fatalf("UTXO set sizes differ: seq=%d, par=%d", len(seqState.Utxos), len(parState.Utxos))
	}
	for op, seqEntry := range seqState.Utxos {
		parEntry, ok := parState.Utxos[op]
		if !ok {
			t.Fatalf("UTXO %v missing from parallel result", op)
		}
		if seqEntry.Value != parEntry.Value || seqEntry.CovenantType != parEntry.CovenantType {
			t.Fatalf("UTXO %v mismatch: seq=(val=%d,cov=%d), par=(val=%d,cov=%d)",
				op, seqEntry.Value, seqEntry.CovenantType, parEntry.Value, parEntry.CovenantType)
		}
	}
}

// TestConnectBlockParallelSigVerify_NilState checks that nil state is rejected.
func TestConnectBlockParallelSigVerify_NilState(t *testing.T) {
	_, err := ConnectBlockParallelSigVerify(nil, nil, nil, 0, nil, nil, [32]byte{}, 1)
	if err == nil {
		t.Fatalf("expected error for nil state")
	}
}

// TestConnectBlockParallelSigVerify_MultipleP2PKInputs exercises parallel sig
// verify with a transaction that has multiple P2PK inputs, demonstrating
// per-block parallelism.
func TestConnectBlockParallelSigVerify_MultipleP2PKInputs(t *testing.T) {
	height := uint64(1)
	prev := hashWithPrefix(0x88)
	target := filledHash(0xff)

	kp := mustMLDSA87Keypair(t)
	covData := p2pkCovenantDataForPubkey(kp.PubkeyBytes())

	// Create 4 UTXOs from different "previous" txids.
	utxos := make(map[Outpoint]UtxoEntry, 4)
	var inputs []TxInput
	totalIn := uint64(0)
	for i := 0; i < 4; i++ {
		var txid [32]byte
		txid[0] = byte(i + 1)
		op := Outpoint{Txid: txid, Vout: 0}
		utxos[op] = UtxoEntry{
			Value:        100,
			CovenantType: COV_TYPE_P2PK,
			CovenantData: append([]byte(nil), covData...),
		}
		inputs = append(inputs, TxInput{PrevTxid: txid, PrevVout: 0, Sequence: 0})
		totalIn += 100
	}

	outputValue := totalIn - 10 // fee = 10
	spendTx := &Tx{
		Version:  1,
		TxKind:   0x00,
		TxNonce:  1,
		Inputs:   inputs,
		Outputs:  []TxOutput{{Value: outputValue, CovenantType: COV_TYPE_P2PK, CovenantData: covData}},
		Locktime: 0,
	}

	// Sign all 4 inputs.
	var witnesses []WitnessItem
	for i := range inputs {
		witnesses = append(witnesses, signP2PKInputWitness(t, spendTx, uint32(i), 100, [32]byte{}, kp))
	}
	spendTx.Witness = witnesses

	spendBytes := txBytesFromTx(t, spendTx)
	_, spendTxid, _, _, err := ParseTx(spendBytes)
	if err != nil {
		t.Fatalf("ParseTx(spend): %v", err)
	}

	makeState := func() *InMemoryChainState {
		u := make(map[Outpoint]UtxoEntry, len(utxos))
		for k, v := range utxos {
			u[k] = UtxoEntry{
				Value:        v.Value,
				CovenantType: v.CovenantType,
				CovenantData: append([]byte(nil), v.CovenantData...),
			}
		}
		return &InMemoryChainState{
			Utxos:            u,
			AlreadyGenerated: new(big.Int),
		}
	}

	subsidy := BlockSubsidyBig(height, makeState().AlreadyGenerated)
	coinbase := coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, height, subsidy+10, spendBytes)
	cbTxid := testTxID(t, coinbase)

	root, err := MerkleRootTxids([][32]byte{cbTxid, spendTxid})
	if err != nil {
		t.Fatalf("MerkleRootTxids: %v", err)
	}
	block := buildBlockBytes(t, prev, root, target, 1, [][]byte{coinbase, spendBytes})

	// Sequential path.
	seqState := makeState()
	seqSummary, err := ConnectBlockBasicInMemoryAtHeight(block, &prev, &target, height, []uint64{0}, seqState, [32]byte{})
	if err != nil {
		t.Fatalf("Sequential: %v", err)
	}

	// Parallel path.
	parState := makeState()
	parSummary, err := ConnectBlockParallelSigVerify(block, &prev, &target, height, []uint64{0}, parState, [32]byte{}, 2)
	if err != nil {
		t.Fatalf("Parallel: %v", err)
	}

	// Results must match.
	if seqSummary.SumFees != parSummary.SumFees {
		t.Fatalf("SumFees mismatch: seq=%d, par=%d", seqSummary.SumFees, parSummary.SumFees)
	}
	if seqSummary.UtxoCount != parSummary.UtxoCount {
		t.Fatalf("UtxoCount mismatch: seq=%d, par=%d", seqSummary.UtxoCount, parSummary.UtxoCount)
	}
}

// TestConnectBlockParallelSigVerify_InvalidSigRejects ensures that the
// parallel path correctly rejects blocks with invalid signatures.
func TestConnectBlockParallelSigVerify_InvalidSigRejects(t *testing.T) {
	height := uint64(1)
	prev := hashWithPrefix(0x99)
	target := filledHash(0xff)

	kp := mustMLDSA87Keypair(t)
	covData := p2pkCovenantDataForPubkey(kp.PubkeyBytes())

	prevOut := Outpoint{Txid: prev, Vout: 0}
	spendTx := &Tx{
		Version:  1,
		TxKind:   0x00,
		TxNonce:  1,
		Inputs:   []TxInput{{PrevTxid: prev, PrevVout: 0, Sequence: 0}},
		Outputs:  []TxOutput{{Value: 90, CovenantType: COV_TYPE_P2PK, CovenantData: covData}},
		Locktime: 0,
	}

	// Create a VALID witness first, then corrupt the signature.
	w := signP2PKInputWitness(t, spendTx, 0, 100, [32]byte{}, kp)
	// Corrupt the signature (flip a byte in the middle).
	if len(w.Signature) > 100 {
		w.Signature[100] ^= 0xFF
	}
	spendTx.Witness = []WitnessItem{w}

	spendBytes := txBytesFromTx(t, spendTx)
	_, spendTxid, _, _, err := ParseTx(spendBytes)
	if err != nil {
		t.Fatalf("ParseTx(spend): %v", err)
	}

	state := &InMemoryChainState{
		Utxos: map[Outpoint]UtxoEntry{
			prevOut: {
				Value:        100,
				CovenantType: COV_TYPE_P2PK,
				CovenantData: append([]byte(nil), covData...),
			},
		},
		AlreadyGenerated: new(big.Int),
	}

	sumFees := uint64(10)
	subsidy := BlockSubsidyBig(height, state.AlreadyGenerated)
	coinbase := coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, height, subsidy+sumFees, spendBytes)
	cbTxid := testTxID(t, coinbase)

	root, err := MerkleRootTxids([][32]byte{cbTxid, spendTxid})
	if err != nil {
		t.Fatalf("MerkleRootTxids: %v", err)
	}
	block := buildBlockBytes(t, prev, root, target, 1, [][]byte{coinbase, spendBytes})

	_, err = ConnectBlockParallelSigVerify(block, &prev, &target, height, []uint64{0}, state, [32]byte{}, 2)
	if err == nil {
		t.Fatalf("expected error for invalid signature, got nil")
	}
	// The error should be TX_ERR_SIG_INVALID.
	te, ok := err.(*TxError)
	if !ok {
		t.Fatalf("expected *TxError, got %T: %v", err, err)
	}
	if te.Code != TX_ERR_SIG_INVALID {
		t.Fatalf("expected TX_ERR_SIG_INVALID, got: %s", te.Code)
	}
}

// TestConnectBlockParallelSigVerify_CoinbaseOnly exercises a block with only
// a coinbase transaction (no sigs to verify, queue should be empty).
func TestConnectBlockParallelSigVerify_CoinbaseOnly(t *testing.T) {
	height := uint64(1)
	prev := hashWithPrefix(0xAA)
	target := filledHash(0xff)

	state := &InMemoryChainState{
		Utxos:            make(map[Outpoint]UtxoEntry),
		AlreadyGenerated: new(big.Int),
	}

	subsidy := BlockSubsidyBig(height, state.AlreadyGenerated)
	coinbase := coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, height, subsidy)
	cbTxid := testTxID(t, coinbase)

	root, err := MerkleRootTxids([][32]byte{cbTxid})
	if err != nil {
		t.Fatalf("MerkleRootTxids: %v", err)
	}
	block := buildBlockBytes(t, prev, root, target, 1, [][]byte{coinbase})

	summary, err := ConnectBlockParallelSigVerify(block, &prev, &target, height, []uint64{0}, state, [32]byte{}, 1)
	if err != nil {
		t.Fatalf("Parallel coinbase-only: %v", err)
	}
	if summary.SumFees != 0 {
		t.Fatalf("expected 0 fees, got %d", summary.SumFees)
	}
}

// TestApplyNonCoinbaseTxBasicWorkQ_MatchesSequential verifies that the queued
// variant of applyNonCoinbaseTxBasicWork produces identical results to the
// sequential variant for a simple P2PK transaction.
func TestApplyNonCoinbaseTxBasicWorkQ_MatchesSequential(t *testing.T) {
	kp := mustMLDSA87Keypair(t)
	covData := p2pkCovenantDataForPubkey(kp.PubkeyBytes())

	var prevTxid [32]byte
	prevTxid[0] = 0x42
	op := Outpoint{Txid: prevTxid, Vout: 0}
	utxo := UtxoEntry{
		Value:        500,
		CovenantType: COV_TYPE_P2PK,
		CovenantData: covData,
	}

	tx := &Tx{
		Version:  1,
		TxKind:   0x00,
		TxNonce:  1,
		Inputs:   []TxInput{{PrevTxid: prevTxid, PrevVout: 0, Sequence: 0}},
		Outputs:  []TxOutput{{Value: 490, CovenantType: COV_TYPE_P2PK, CovenantData: covData}},
		Locktime: 0,
	}
	tx.Witness = []WitnessItem{signP2PKInputWitness(t, tx, 0, 500, [32]byte{}, kp)}
	txBytes := txBytesFromTx(t, tx)
	_, txid, _, _, err := ParseTx(txBytes)
	if err != nil {
		t.Fatalf("ParseTx: %v", err)
	}

	// Sequential.
	seqUtxos := map[Outpoint]UtxoEntry{op: utxo}
	seqWork, seqSummary, err := ApplyNonCoinbaseTxBasicUpdateWithMTP(tx, txid, seqUtxos, 1, 0, 0, [32]byte{})
	if err != nil {
		t.Fatalf("Sequential: %v", err)
	}

	// Queued (parallel).
	parUtxos := map[Outpoint]UtxoEntry{op: utxo}
	q := NewSigCheckQueue(2)
	parWork, parFee, err := applyNonCoinbaseTxBasicWorkQ(tx, txid, parUtxos, 1, 0, [32]byte{}, nil, q)
	if err != nil {
		t.Fatalf("Queued pre-flush: %v", err)
	}
	if q.Len() != 1 {
		t.Fatalf("expected 1 queued sig, got %d", q.Len())
	}
	if err := q.Flush(); err != nil {
		t.Fatalf("Queued flush: %v", err)
	}

	// Compare.
	if seqSummary.Fee != parFee {
		t.Fatalf("Fee mismatch: seq=%d, par=%d", seqSummary.Fee, parFee)
	}
	if len(seqWork) != len(parWork) {
		t.Fatalf("UTXO set size mismatch: seq=%d, par=%d", len(seqWork), len(parWork))
	}
}

// TestApplyNonCoinbaseTxBasicWorkQ_MissingUTXO verifies pre-check error is
// returned before queue flush.
func TestApplyNonCoinbaseTxBasicWorkQ_MissingUTXO(t *testing.T) {
	kp := mustMLDSA87Keypair(t)
	covData := p2pkCovenantDataForPubkey(kp.PubkeyBytes())
	tx := &Tx{
		Version: 1,
		TxKind:  0x00,
		TxNonce: 1,
		Inputs:  []TxInput{{PrevTxid: [32]byte{0x01}, PrevVout: 0, Sequence: 0}},
		Outputs: []TxOutput{{Value: 1, CovenantType: COV_TYPE_P2PK, CovenantData: covData}},
		Witness: []WitnessItem{{SuiteID: SUITE_ID_ML_DSA_87, Pubkey: kp.PubkeyBytes(), Signature: make([]byte, ML_DSA_87_SIG_BYTES+1)}},
	}
	q := NewSigCheckQueue(1)
	_, _, err := applyNonCoinbaseTxBasicWorkQ(tx, [32]byte{}, make(map[Outpoint]UtxoEntry), 1, 0, [32]byte{}, nil, q)
	if err == nil {
		t.Fatalf("expected UTXO error")
	}
	te, ok := err.(*TxError)
	if !ok {
		t.Fatalf("expected *TxError, got %T", err)
	}
	if te.Code != TX_ERR_MISSING_UTXO {
		t.Fatalf("expected TX_ERR_MISSING_UTXO, got %s", te.Code)
	}
	// Queue should be empty (error before any sig task).
	if q.Len() != 0 {
		t.Fatalf("expected empty queue, got %d", q.Len())
	}
}
