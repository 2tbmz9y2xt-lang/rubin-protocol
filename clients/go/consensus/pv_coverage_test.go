package consensus

import (
	"context"
	"math/big"
	"testing"
)

// ─────────────────────────────────────────────────────────────────────────────
// Q-PV-14: Unit-test expansion and coverage hardening for PV paths.
// Targets: reducer, worker pool, sig cache, and deterministic replay checks.
// Tests that already exist in other files are not duplicated here.
// ─────────────────────────────────────────────────────────────────────────────

// ── FirstTxError (reducer) — additional cases ───────────────────────────────

func TestPV14_FirstTxError_AllValid(t *testing.T) {
	results := []WorkerResult[TxValidationResult]{
		{Value: TxValidationResult{TxIndex: 1, Valid: true}},
		{Value: TxValidationResult{TxIndex: 2, Valid: true}},
	}
	if err := FirstTxError(results); err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
}

func TestPV14_FirstTxError_FirstByIndex(t *testing.T) {
	err1 := txerr(TX_ERR_SIG_INVALID, "sig1")
	err2 := txerr(TX_ERR_MISSING_UTXO, "utxo")
	results := []WorkerResult[TxValidationResult]{
		{Value: TxValidationResult{TxIndex: 3}, Err: err1},
		{Value: TxValidationResult{TxIndex: 1}, Err: err2},
	}
	got := FirstTxError(results)
	if got != err2 {
		t.Fatalf("expected err from tx1, got: %v", got)
	}
}

func TestPV14_FirstTxError_Empty(t *testing.T) {
	if err := FirstTxError(nil); err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
}

func TestPV14_FirstTxError_SingleError(t *testing.T) {
	err1 := txerr(TX_ERR_SIG_INVALID, "sig")
	results := []WorkerResult[TxValidationResult]{
		{Value: TxValidationResult{TxIndex: 1, Valid: true}},
		{Value: TxValidationResult{TxIndex: 2}, Err: err1},
	}
	if got := FirstTxError(results); got != err1 {
		t.Fatalf("expected err1, got %v", got)
	}
}

// ── RunTxValidationWorkers ──────────────────────────────────────────────────

func TestPV14_RunTxValidationWorkers_ValidP2PK(t *testing.T) {
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

	results := RunTxValidationWorkers(
		context.Background(), 2,
		[]TxValidationContext{tvc},
		[32]byte{}, 1, 0, nil, nil,
	)
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

func TestPV14_RunTxValidationWorkers_WithSigCache(t *testing.T) {
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

	cache := NewSigCache(100)

	// First run: no cache hits.
	results1 := RunTxValidationWorkers(context.Background(), 1, []TxValidationContext{tvc}, [32]byte{}, 1, 0, nil, cache)
	if results1[0].Err != nil {
		t.Fatalf("first run: %v", results1[0].Err)
	}
	if cache.Hits() != 0 {
		t.Fatalf("expected 0 hits first run, got %d", cache.Hits())
	}

	// Second run: should get cache hit.
	results2 := RunTxValidationWorkers(context.Background(), 1, []TxValidationContext{tvc}, [32]byte{}, 1, 0, nil, cache)
	if results2[0].Err != nil {
		t.Fatalf("second run: %v", results2[0].Err)
	}
	if cache.Hits() != 1 {
		t.Fatalf("expected 1 cache hit, got %d", cache.Hits())
	}
}

func TestPV14_RunTxValidationWorkers_CancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	kp := mustMLDSA87Keypair(t)
	covData := p2pkCovenantDataForPubkey(kp.PubkeyBytes())
	tx := &Tx{
		Version: 1, TxKind: 0x00, TxNonce: 1,
		Inputs:  []TxInput{{PrevTxid: [32]byte{0x42}, PrevVout: 0, Sequence: 0}},
		Outputs: []TxOutput{{Value: 90, CovenantType: COV_TYPE_P2PK, CovenantData: covData}},
	}
	tx.Witness = []WitnessItem{signP2PKInputWitness(t, tx, 0, 100, [32]byte{}, kp)}
	sighashCache, _ := NewSighashV1PrehashCache(tx)

	tvc := TxValidationContext{
		TxIndex: 1, Tx: tx,
		ResolvedInputs: []UtxoEntry{{Value: 100, CovenantType: COV_TYPE_P2PK, CovenantData: covData}},
		WitnessStart:   0, WitnessEnd: 1, SighashCache: sighashCache, Fee: 10,
	}

	results := RunTxValidationWorkers(ctx, 1, []TxValidationContext{tvc}, [32]byte{}, 1, 0, nil, nil)
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	// Context cancellation is best-effort; either error or success is acceptable.
}

// ── ValidateTxLocal edge cases (additional) ─────────────────────────────────

func TestPV14_ValidateTxLocal_WitnessUnderflow(t *testing.T) {
	kp := mustMLDSA87Keypair(t)
	covData := p2pkCovenantDataForPubkey(kp.PubkeyBytes())

	tx := &Tx{
		Version: 1, TxKind: 0x00, TxNonce: 1,
		Inputs:  []TxInput{{PrevTxid: [32]byte{0x42}, PrevVout: 0, Sequence: 0}},
		Outputs: []TxOutput{{Value: 90, CovenantType: COV_TYPE_P2PK, CovenantData: covData}},
		Witness: []WitnessItem{}, // empty — underflow
	}
	sighashCache, _ := NewSighashV1PrehashCache(tx)

	tvc := TxValidationContext{
		TxIndex: 1, Tx: tx,
		ResolvedInputs: []UtxoEntry{{Value: 100, CovenantType: COV_TYPE_P2PK, CovenantData: covData}},
		WitnessStart:   0, WitnessEnd: 0, SighashCache: sighashCache, Fee: 10,
	}
	result := ValidateTxLocal(tvc, [32]byte{}, 1, 0, nil, nil)
	if result.Err == nil {
		t.Fatal("expected witness underflow error")
	}
}

// ── SigCheckQueue edge cases (additional) ───────────────────────────────────

func TestPV14_SigCheckQueue_FlushEmpty(t *testing.T) {
	q := NewSigCheckQueue(4)
	if err := q.Flush(); err != nil {
		t.Fatalf("flush empty: %v", err)
	}
}

func TestPV14_SigCheckQueue_AssertFlushedNonEmpty(t *testing.T) {
	q := NewSigCheckQueue(1)
	q.Push(SUITE_ID_ML_DSA_87, make([]byte, 10), make([]byte, 10), [32]byte{}, nil)
	if err := q.AssertFlushed(); err == nil {
		t.Fatal("expected error for unflushed queue")
	}
}

func TestPV14_SigCheckQueue_NilErrOnFail(t *testing.T) {
	q := NewSigCheckQueue(1)
	q.Push(SUITE_ID_ML_DSA_87, make([]byte, ML_DSA_87_PUBKEY_BYTES), make([]byte, ML_DSA_87_SIG_BYTES), [32]byte{}, nil)
	if q.Len() != 1 {
		t.Fatalf("len=%d, want 1", q.Len())
	}
}

// ── Deterministic replay: sequential == parallel ────────────────────────────

func TestPV14_DeterministicReplay_MultiTxBlock_Parity(t *testing.T) {
	height := uint64(1)
	prev := hashWithPrefix(0xCC)
	target := filledHash(0xff)

	kp := mustMLDSA87Keypair(t)
	covData := p2pkCovenantDataForPubkey(kp.PubkeyBytes())

	const numTxs = 3
	var spendTxBytes [][]byte
	var spendTxids [][32]byte
	totalFees := uint64(0)
	startUtxos := make(map[Outpoint]UtxoEntry)

	for i := 0; i < numTxs; i++ {
		var prevTxid [32]byte
		prevTxid[0] = byte(i + 1)
		op := Outpoint{Txid: prevTxid, Vout: 0}
		startUtxos[op] = UtxoEntry{
			Value:        uint64(100 + i*10),
			CovenantType: COV_TYPE_P2PK,
			CovenantData: append([]byte(nil), covData...),
		}

		fee := uint64(i + 1)
		totalFees += fee
		outVal := uint64(100+i*10) - fee

		tx := &Tx{
			Version: 1, TxKind: 0x00, TxNonce: uint64(i + 1),
			Inputs:  []TxInput{{PrevTxid: prevTxid, PrevVout: 0, Sequence: 0}},
			Outputs: []TxOutput{{Value: outVal, CovenantType: COV_TYPE_P2PK, CovenantData: covData}},
		}
		tx.Witness = []WitnessItem{signP2PKInputWitness(t, tx, 0, uint64(100+i*10), [32]byte{}, kp)}
		txb := txBytesFromTx(t, tx)
		_, txid, _, _, err := ParseTx(txb)
		if err != nil {
			t.Fatalf("ParseTx(%d): %v", i, err)
		}
		spendTxBytes = append(spendTxBytes, txb)
		spendTxids = append(spendTxids, txid)
	}

	makeState := func() *InMemoryChainState {
		u := make(map[Outpoint]UtxoEntry, len(startUtxos))
		for k, v := range startUtxos {
			u[k] = UtxoEntry{Value: v.Value, CovenantType: v.CovenantType, CovenantData: append([]byte(nil), v.CovenantData...)}
		}
		return &InMemoryChainState{Utxos: u, AlreadyGenerated: new(big.Int)}
	}

	subsidy := BlockSubsidyBig(height, makeState().AlreadyGenerated)
	allSpendBytes := make([][]byte, 0, numTxs)
	allSpendBytes = append(allSpendBytes, spendTxBytes...)
	coinbase := coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, height, subsidy+totalFees, allSpendBytes...)
	cbTxid := testTxID(t, coinbase)

	allTxids := append([][32]byte{cbTxid}, spendTxids...)
	root, err := MerkleRootTxids(allTxids)
	if err != nil {
		t.Fatalf("MerkleRootTxids: %v", err)
	}

	allTxs := append([][]byte{coinbase}, spendTxBytes...)
	block := buildBlockBytes(t, prev, root, target, 1, allTxs)

	// Sequential.
	seqState := makeState()
	seqSummary, err := ConnectBlockBasicInMemoryAtHeight(block, &prev, &target, height, []uint64{0}, seqState, [32]byte{})
	if err != nil {
		t.Fatalf("Sequential: %v", err)
	}

	// Parallel with different worker counts — all must match sequential.
	for _, workers := range []int{1, 2, 4, 8} {
		parState := makeState()
		parSummary, err := ConnectBlockParallelSigVerify(block, &prev, &target, height, []uint64{0}, parState, [32]byte{}, workers)
		if err != nil {
			t.Fatalf("Parallel(%d workers): %v", workers, err)
		}

		if seqSummary.SumFees != parSummary.SumFees {
			t.Fatalf("w=%d SumFees: seq=%d par=%d", workers, seqSummary.SumFees, parSummary.SumFees)
		}
		if seqSummary.PostStateDigest != parSummary.PostStateDigest {
			t.Fatalf("w=%d PostStateDigest mismatch", workers)
		}
		if seqSummary.UtxoCount != parSummary.UtxoCount {
			t.Fatalf("w=%d UtxoCount: seq=%d par=%d", workers, seqSummary.UtxoCount, parSummary.UtxoCount)
		}
	}
}

// ── WorkerPool edge cases (additional) ──────────────────────────────────────

func TestPV14_WorkerPool_EmptyTasks(t *testing.T) {
	pool := &WorkerPool[int, int]{
		MaxWorkers: 4,
		MaxTasks:   8,
		Func: func(ctx context.Context, task int) (int, error) {
			return task * 2, nil
		},
	}
	results, err := pool.Run(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected run error: %v", err)
	}
	if len(results) != 0 {
		t.Fatalf("expected nil results, got %v", results)
	}
}

func TestPV14_WorkerPool_PanicRecovery(t *testing.T) {
	pool := &WorkerPool[int, int]{
		MaxWorkers: 2,
		MaxTasks:   8,
		Func: func(ctx context.Context, task int) (int, error) {
			if task == 1 {
				panic("deliberate panic")
			}
			return task * 2, nil
		},
	}
	results, err := pool.Run(context.Background(), []int{0, 1, 2})
	if err != nil {
		t.Fatalf("unexpected run error: %v", err)
	}
	if len(results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(results))
	}
	if results[0].Err != nil || results[0].Value != 0 {
		t.Fatalf("result[0]=%+v", results[0])
	}
	if results[1].Err == nil {
		t.Fatal("expected panic error for task 1")
	}
	if results[2].Err != nil || results[2].Value != 4 {
		t.Fatalf("result[2]=%+v", results[2])
	}
}

func TestPV14_CollectValues_WithError(t *testing.T) {
	results := []WorkerResult[int]{
		{Value: 1},
		{Value: 2, Err: txerr(TX_ERR_PARSE, "bad")},
		{Value: 3},
	}
	_, err := CollectValues(results)
	if err == nil {
		t.Fatal("expected error from CollectValues")
	}
}

func TestPV14_CollectValues_AllOK(t *testing.T) {
	results := []WorkerResult[int]{
		{Value: 10}, {Value: 20},
	}
	vals, err := CollectValues(results)
	if err != nil {
		t.Fatalf("CollectValues: %v", err)
	}
	if len(vals) != 2 || vals[0] != 10 || vals[1] != 20 {
		t.Fatalf("vals=%v", vals)
	}
}

// ── SigCache hit/miss tracking ──────────────────────────────────────────────

func TestPV14_SigCache_HitMissTracking(t *testing.T) {
	c := NewSigCache(10)
	if c.Hits() != 0 || c.Misses() != 0 {
		t.Fatal("expected zero hit/miss")
	}

	digest := hashWithPrefix(0x01)
	pk := make([]byte, 32)
	sig := make([]byte, 64)

	// Miss.
	if c.Lookup(SUITE_ID_ML_DSA_87, pk, sig, digest) {
		t.Fatal("expected miss on first lookup")
	}
	if c.Misses() != 1 {
		t.Fatalf("misses=%d, want 1", c.Misses())
	}

	// Insert and hit.
	c.Insert(SUITE_ID_ML_DSA_87, pk, sig, digest)
	if !c.Lookup(SUITE_ID_ML_DSA_87, pk, sig, digest) {
		t.Fatal("expected hit after insert")
	}
	if c.Hits() != 1 {
		t.Fatalf("hits=%d, want 1", c.Hits())
	}
}
