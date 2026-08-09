package consensus

import (
	"math/big"
	"reflect"
	"strings"
	"testing"
)

func buildSupplyOnlyBlock(t *testing.T, height uint64, coinbaseValue uint64) ([]byte, [32]byte, [32]byte) {
	t.Helper()
	prev := hashWithPrefix(0xd1)
	target := filledHash(0xff)
	coinbase := coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, height, coinbaseValue)
	root, err := MerkleRootTxids([][32]byte{testTxID(t, coinbase)})
	if err != nil {
		t.Fatalf("MerkleRootTxids: %v", err)
	}
	return buildBlockBytes(t, prev, root, target, 1, [][]byte{coinbase}), prev, target
}

func connectSupplyPath(parallel bool, block []byte, prev, target *[32]byte, height uint64, state *InMemoryChainState) (*ConnectBlockBasicSummary, error) {
	if parallel {
		return ConnectBlockParallelSigVerify(block, prev, target, height, nil, state, [32]byte{}, 2)
	}
	return ConnectBlockBasicInMemoryAtHeight(block, prev, target, height, nil, state, [32]byte{})
}

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
		t.Fatalf("AlreadyGenerated mismatch: seq=%s, par=%s", seqSummary.AlreadyGenerated.String(), parSummary.AlreadyGenerated.String())
	}
	if seqSummary.AlreadyGeneratedN1 != parSummary.AlreadyGeneratedN1 {
		t.Fatalf("AlreadyGeneratedN1 mismatch: seq=%s, par=%s", seqSummary.AlreadyGeneratedN1.String(), parSummary.AlreadyGeneratedN1.String())
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

func TestConnectBlockSupplyPreflightWinsBeforeParseWithoutMutation(t *testing.T) {
	overU128 := new(big.Int).Lsh(big.NewInt(1), 128)
	for _, supply := range []struct {
		name  string
		value *big.Int
	}{
		{name: "negative", value: big.NewInt(-1)},
		{name: "above_u128", value: overU128},
	} {
		var firstError string
		for _, parallel := range []bool{false, true} {
			path := "sequential"
			if parallel {
				path = "parallel"
			}
			t.Run(path+"/"+supply.name, func(t *testing.T) {
				source := new(big.Int).Set(supply.value)
				utxos := map[Outpoint]UtxoEntry{{Txid: [32]byte{0x41}, Vout: 2}: {Value: 7, CovenantData: []byte{0xaa}}}
				state := &InMemoryChainState{Utxos: utxos, AlreadyGenerated: source}
				beforeUtxos := cloneUtxoSet(utxos)
				beforeSupply := new(big.Int).Set(source)

				summary, err := connectSupplyPath(parallel, []byte{0x00}, nil, nil, 1, state)
				if err == nil || summary != nil {
					t.Fatalf("expected supply preflight error, summary=%#v err=%v", summary, err)
				}
				if got := mustTxErrCode(t, err); got != BLOCK_ERR_PARSE || !strings.Contains(err.Error(), "already_generated") {
					t.Fatalf("error=%v, want already_generated %s", err, BLOCK_ERR_PARSE)
				}
				if firstError == "" {
					firstError = err.Error()
				} else if err.Error() != firstError {
					t.Fatalf("sequential/parallel preflight error mismatch: %q vs %q", firstError, err)
				}
				if state.AlreadyGenerated != source || source.Cmp(beforeSupply) != 0 {
					t.Fatalf("supply mutated or replaced: state=%p source=%p value=%s", state.AlreadyGenerated, source, source)
				}
				if !reflect.DeepEqual(state.Utxos, beforeUtxos) {
					t.Fatalf("UTXO state changed on preflight error")
				}
				probe := Outpoint{Txid: [32]byte{0x42}, Vout: 3}
				utxos[probe] = UtxoEntry{Value: 8}
				if _, ok := state.Utxos[probe]; !ok {
					t.Fatal("UTXO map was replaced on preflight error")
				}
			})
		}
	}
}

func TestConnectBlockSupplyCrossesU64ExactlyAndCopiesSource(t *testing.T) {
	const (
		height     = uint64(5_771_107)
		beforeText = "18446744073699181041"
		afterText  = "18446744073718206916"
	)
	before, ok := new(big.Int).SetString(beforeText, 10)
	if !ok {
		t.Fatal("parse crossing supply")
	}
	wantBefore, err := ParseUint128Decimal(beforeText)
	if err != nil {
		t.Fatalf("ParseUint128Decimal(before): %v", err)
	}
	wantAfter, err := ParseUint128Decimal(afterText)
	if err != nil {
		t.Fatalf("ParseUint128Decimal(after): %v", err)
	}
	block, prev, target := buildSupplyOnlyBlock(t, height, TAIL_EMISSION_PER_BLOCK)

	var first *ConnectBlockBasicSummary
	for _, parallel := range []bool{false, true} {
		path := "sequential"
		if parallel {
			path = "parallel"
		}
		t.Run(path, func(t *testing.T) {
			source := new(big.Int).Set(before)
			state := &InMemoryChainState{Utxos: map[Outpoint]UtxoEntry{}, AlreadyGenerated: source}
			summary, err := connectSupplyPath(parallel, block, &prev, &target, height, state)
			if err != nil {
				t.Fatalf("connect: %v", err)
			}
			if summary.AlreadyGenerated != wantBefore || summary.AlreadyGeneratedN1 != wantAfter {
				t.Fatalf("summary supply=%s -> %s", summary.AlreadyGenerated.String(), summary.AlreadyGeneratedN1.String())
			}
			if state.AlreadyGenerated == source || state.AlreadyGenerated.Cmp(wantAfter.Big()) != 0 {
				t.Fatalf("state did not retain an exact copied supply: %s", state.AlreadyGenerated)
			}
			source.SetUint64(1)
			if state.AlreadyGenerated.Cmp(wantAfter.Big()) != 0 || summary.AlreadyGenerated != wantBefore || summary.AlreadyGeneratedN1 != wantAfter {
				t.Fatal("source big.Int mutation leaked into retained state or summary")
			}
			if first == nil {
				copySummary := *summary
				first = &copySummary
				return
			}
			if *summary != *first {
				t.Fatalf("sequential/parallel supply divergence: %#v vs %#v", first, summary)
			}
		})
	}
}

func TestConnectBlockSupplyOverflowRunsAfterEarlierCoinbaseChecks(t *testing.T) {
	const height = uint64(5_771_107)
	maxSupply := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 128), big.NewInt(1))
	valid, prev, target := buildSupplyOnlyBlock(t, height, TAIL_EMISSION_PER_BLOCK)
	badCoinbase, _, _ := buildSupplyOnlyBlock(t, height, TAIL_EMISSION_PER_BLOCK+1)

	newState := func() (*InMemoryChainState, *big.Int, map[Outpoint]UtxoEntry, map[Outpoint]UtxoEntry) {
		source := new(big.Int).Set(maxSupply)
		utxos := map[Outpoint]UtxoEntry{{Txid: [32]byte{0x52}, Vout: 3}: {Value: 9, CovenantData: []byte{0xbb}}}
		return &InMemoryChainState{Utxos: utxos, AlreadyGenerated: source}, source, utxos, cloneUtxoSet(utxos)
	}
	assertUnchanged := func(t *testing.T, state *InMemoryChainState, source *big.Int, original, want map[Outpoint]UtxoEntry) {
		t.Helper()
		if state.AlreadyGenerated != source || source.Cmp(maxSupply) != 0 || !reflect.DeepEqual(state.Utxos, want) {
			t.Fatal("caller state changed on rejected block")
		}
		probe := Outpoint{Txid: [32]byte{0x53}, Vout: 4}
		original[probe] = UtxoEntry{Value: 10}
		if _, ok := state.Utxos[probe]; !ok {
			t.Fatal("UTXO map was replaced on rejected block")
		}
	}

	var firstEarlierError, firstOverflowError string
	for _, parallel := range []bool{false, true} {
		path := "sequential"
		if parallel {
			path = "parallel"
		}
		t.Run(path+"/earlier_coinbase_error", func(t *testing.T) {
			state, source, original, utxos := newState()
			summary, err := connectSupplyPath(parallel, badCoinbase, &prev, &target, height, state)
			if err == nil || summary != nil || mustTxErrCode(t, err) != BLOCK_ERR_SUBSIDY_EXCEEDED {
				t.Fatalf("got summary=%#v err=%v, want earlier subsidy error", summary, err)
			}
			if firstEarlierError == "" {
				firstEarlierError = err.Error()
			} else if err.Error() != firstEarlierError {
				t.Fatalf("sequential/parallel earlier error mismatch: %q vs %q", firstEarlierError, err)
			}
			assertUnchanged(t, state, source, original, utxos)
		})
		t.Run(path+"/checked_add_overflow", func(t *testing.T) {
			state, source, original, utxos := newState()
			summary, err := connectSupplyPath(parallel, valid, &prev, &target, height, state)
			if err == nil || summary != nil || mustTxErrCode(t, err) != BLOCK_ERR_PARSE || !strings.Contains(err.Error(), "already_generated overflow") {
				t.Fatalf("got summary=%#v err=%v, want checked-add overflow", summary, err)
			}
			if firstOverflowError == "" {
				firstOverflowError = err.Error()
			} else if err.Error() != firstOverflowError {
				t.Fatalf("sequential/parallel overflow mismatch: %q vs %q", firstOverflowError, err)
			}
			assertUnchanged(t, state, source, original, utxos)
		})
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
	if summary.SumFees.Cmp(Uint128FromU64(0)) != 0 {
		t.Fatalf("expected 0 fees, got %d", summary.SumFees)
	}
	if summary.PostStateDigest != UtxoSetHash(state.Utxos) {
		t.Fatal("post-state digest must match UTXO set")
	}
}

func TestPostStateDigest_SequentialParallelParity(t *testing.T) {
	height := uint64(1)
	prev := hashWithPrefix(0xAB)
	target := filledHash(0xff)

	// Shared initial state: one P2PK UTXO.
	kp := mustMLDSA87Keypair(t)
	prevTxid := hashWithPrefix(0x10)
	covData := p2pkCovenantDataForPubkey(kp.PubkeyBytes())
	op := Outpoint{Txid: prevTxid, Vout: 0}
	startUtxos := map[Outpoint]UtxoEntry{
		op: {
			Value:        1000,
			CovenantType: COV_TYPE_P2PK,
			CovenantData: append([]byte(nil), covData...),
		},
	}

	makeState := func() *InMemoryChainState {
		utxos := make(map[Outpoint]UtxoEntry, len(startUtxos))
		for k, v := range startUtxos {
			utxos[k] = v
		}
		return &InMemoryChainState{
			Utxos:            utxos,
			AlreadyGenerated: new(big.Int),
		}
	}

	// Spend tx (fee=10).
	spend := &Tx{
		Version: 1,
		TxKind:  0x00,
		TxNonce: 1,
		Inputs:  []TxInput{{PrevTxid: prevTxid, PrevVout: 0, Sequence: 0}},
		Outputs: []TxOutput{{Value: 990, CovenantType: COV_TYPE_P2PK, CovenantData: covData}},
	}
	spend.Witness = []WitnessItem{signP2PKInputWitness(t, spend, 0, 1000, [32]byte{}, kp)}
	spendBytes := txBytesFromTx(t, spend)
	_, spendTxid, _, _, err := ParseTx(spendBytes)
	if err != nil {
		t.Fatalf("ParseTx: %v", err)
	}

	// Coinbase value includes subsidy + fees.
	seqState := makeState()
	subsidy := BlockSubsidyBig(height, seqState.AlreadyGenerated)
	coinbase := coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, height, subsidy+10, spendBytes)
	cbTxid := testTxID(t, coinbase)

	root, err := MerkleRootTxids([][32]byte{cbTxid, spendTxid})
	if err != nil {
		t.Fatalf("MerkleRootTxids: %v", err)
	}
	block := buildBlockBytes(t, prev, root, target, 1, [][]byte{coinbase, spendBytes})

	seqSummary, err := ConnectBlockBasicInMemoryAtHeight(block, &prev, &target, height, []uint64{0}, seqState, [32]byte{})
	if err != nil {
		t.Fatalf("sequential connect: %v", err)
	}

	parState := makeState()
	parSummary, err := ConnectBlockParallelSigVerify(block, &prev, &target, height, []uint64{0}, parState, [32]byte{}, 2)
	if err != nil {
		t.Fatalf("parallel connect: %v", err)
	}

	if seqSummary.PostStateDigest != parSummary.PostStateDigest {
		t.Fatalf("post-state digest mismatch: seq=%x par=%x", seqSummary.PostStateDigest, parSummary.PostStateDigest)
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
	parWork, parFee, err := applyNonCoinbaseTxBasicWorkQ(tx, txid, parUtxos, 1, 0, [32]byte{}, q, nil, nil)
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
	_, _, err := applyNonCoinbaseTxBasicWorkQ(tx, [32]byte{}, make(map[Outpoint]UtxoEntry), 1, 0, [32]byte{}, q, nil, nil)
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
