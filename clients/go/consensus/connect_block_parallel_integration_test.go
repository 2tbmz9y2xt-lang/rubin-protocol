package consensus

import (
	"math/big"
	"testing"
)

// Integration parity suite (Q-PV-15): tests that sequential and parallel
// validation produce the same verdict, error code, first-invalid behavior,
// and post-state digest for valid, invalid, and mixed scenarios.
// See RUBIN_PARALLEL_VALIDATION_IMPLEMENTATION_PLAN.md §6 (determinism replay).

func TestIntegrationParity_ValidOnly(t *testing.T) {
	height := uint64(1)
	prev := hashWithPrefix(0x77)
	target := filledHash(0xff)

	kp := mustMLDSA87Keypair(t)
	covData := p2pkCovenantDataForPubkey(kp.PubkeyBytes())
	prevOut := Outpoint{Txid: prev, Vout: 0}

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

	seqState := makeState()
	subsidy := BlockSubsidyBig(height, seqState.AlreadyGenerated)
	coinbase := coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, height, subsidy+10, spendBytes)
	cbTxid := testTxID(t, coinbase)
	root, err := MerkleRootTxids([][32]byte{cbTxid, spendTxid})
	if err != nil {
		t.Fatalf("MerkleRootTxids: %v", err)
	}
	block := buildBlockBytes(t, prev, root, target, 1, [][]byte{coinbase, spendBytes})

	seqSummary, seqErr := ConnectBlockBasicInMemoryAtHeight(block, &prev, &target, height, []uint64{0}, seqState, [32]byte{})
	parState := makeState()
	parSummary, parErr := ConnectBlockParallelSigVerify(block, &prev, &target, height, []uint64{0}, parState, [32]byte{}, 4)

	if seqErr != nil {
		t.Fatalf("sequential: %v", seqErr)
	}
	if parErr != nil {
		t.Fatalf("parallel: %v", parErr)
	}
	if seqSummary.PostStateDigest != parSummary.PostStateDigest {
		t.Fatalf("post-state digest mismatch: seq=%x par=%x", seqSummary.PostStateDigest, parSummary.PostStateDigest)
	}
	if seqSummary.SumFees != parSummary.SumFees {
		t.Fatalf("SumFees mismatch: seq=%d par=%d", seqSummary.SumFees, parSummary.SumFees)
	}
	if seqSummary.UtxoCount != parSummary.UtxoCount {
		t.Fatalf("UtxoCount mismatch: seq=%d par=%d", seqSummary.UtxoCount, parSummary.UtxoCount)
	}
}

func TestIntegrationParity_InvalidOne(t *testing.T) {
	height := uint64(1)
	prev := hashWithPrefix(0x88)
	target := filledHash(0xff)

	kp := mustMLDSA87Keypair(t)
	covData := p2pkCovenantDataForPubkey(kp.PubkeyBytes())
	prevOut := Outpoint{Txid: prev, Vout: 0}

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

	spendTx := &Tx{
		Version:  1,
		TxKind:   0x00,
		TxNonce:  1,
		Inputs:   []TxInput{{PrevTxid: prev, PrevVout: 0, Sequence: 0}},
		Outputs:  []TxOutput{{Value: 90, CovenantType: COV_TYPE_P2PK, CovenantData: covData}},
		Locktime: 0,
	}
	// Valid structure, corrupt one byte so verify fails (TX_ERR_SIG_INVALID).
	w := signP2PKInputWitness(t, spendTx, 0, 100, [32]byte{}, kp)
	if len(w.Signature) > 100 {
		w.Signature[100] ^= 0xFF
	}
	spendTx.Witness = []WitnessItem{w}
	spendBytes := txBytesFromTx(t, spendTx)
	_, spendTxid, _, _, err := ParseTx(spendBytes)
	if err != nil {
		t.Fatalf("ParseTx: %v", err)
	}

	subsidy := BlockSubsidyBig(height, state.AlreadyGenerated)
	coinbase := coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, height, subsidy+10, spendBytes)
	cbTxid := testTxID(t, coinbase)
	root, err := MerkleRootTxids([][32]byte{cbTxid, spendTxid})
	if err != nil {
		t.Fatalf("MerkleRootTxids: %v", err)
	}
	block := buildBlockBytes(t, prev, root, target, 1, [][]byte{coinbase, spendBytes})

	seqState := &InMemoryChainState{
		Utxos:            copyUtxoMap(state.Utxos),
		AlreadyGenerated: new(big.Int).Set(state.AlreadyGenerated),
	}
	parState := &InMemoryChainState{
		Utxos:            copyUtxoMap(state.Utxos),
		AlreadyGenerated: new(big.Int).Set(state.AlreadyGenerated),
	}

	_, seqErr := ConnectBlockBasicInMemoryAtHeight(block, &prev, &target, height, []uint64{0}, seqState, [32]byte{})
	_, parErr := ConnectBlockParallelSigVerify(block, &prev, &target, height, []uint64{0}, parState, [32]byte{}, 2)

	if seqErr == nil {
		t.Fatal("sequential must reject invalid sig")
	}
	if parErr == nil {
		t.Fatal("parallel must reject invalid sig")
	}
	seqCode := txErrCode(seqErr)
	parCode := txErrCode(parErr)
	if seqCode != parCode {
		t.Fatalf("error code mismatch: seq=%s par=%s", seqCode, parCode)
	}
}

func TestIntegrationParity_Mixed(t *testing.T) {
	height := uint64(1)
	prev := hashWithPrefix(0x99)
	target := filledHash(0xff)

	kp := mustMLDSA87Keypair(t)
	covData := p2pkCovenantDataForPubkey(kp.PubkeyBytes())
	prevOut := Outpoint{Txid: prev, Vout: 0}

	makeState := func() *InMemoryChainState {
		return &InMemoryChainState{
			Utxos: map[Outpoint]UtxoEntry{
				prevOut: {
					Value:        200,
					CovenantType: COV_TYPE_P2PK,
					CovenantData: append([]byte(nil), covData...),
				},
			},
			AlreadyGenerated: new(big.Int),
		}
	}

	validSpend := &Tx{
		Version:  1,
		TxKind:   0x00,
		TxNonce:  1,
		Inputs:   []TxInput{{PrevTxid: prev, PrevVout: 0, Sequence: 0}},
		Outputs:  []TxOutput{{Value: 190, CovenantType: COV_TYPE_P2PK, CovenantData: covData}},
		Locktime: 0,
	}
	validSpend.Witness = []WitnessItem{signP2PKInputWitness(t, validSpend, 0, 200, [32]byte{}, kp)}
	validBytes := txBytesFromTx(t, validSpend)
	_, validTxid, _, _, err := ParseTx(validBytes)
	if err != nil {
		t.Fatalf("ParseTx(valid): %v", err)
	}

	invalidSpend := &Tx{
		Version:  1,
		TxKind:   0x00,
		TxNonce:  2,
		Inputs:   []TxInput{{PrevTxid: validTxid, PrevVout: 0, Sequence: 0}},
		Outputs:  []TxOutput{{Value: 180, CovenantType: COV_TYPE_P2PK, CovenantData: covData}},
		Locktime: 0,
	}
	invW := signP2PKInputWitness(t, invalidSpend, 0, 190, [32]byte{}, kp)
	if len(invW.Signature) > 100 {
		invW.Signature[100] ^= 0xFF
	}
	invalidSpend.Witness = []WitnessItem{invW}
	invalidBytes := txBytesFromTx(t, invalidSpend)
	_, invalidTxid, _, _, err := ParseTx(invalidBytes)
	if err != nil {
		t.Fatalf("ParseTx(invalid): %v", err)
	}

	seqState := makeState()
	subsidy := BlockSubsidyBig(height, seqState.AlreadyGenerated)
	coinbase := coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, height, subsidy+20, validBytes, invalidBytes)
	cbTxid := testTxID(t, coinbase)
	root, err := MerkleRootTxids([][32]byte{cbTxid, validTxid, invalidTxid})
	if err != nil {
		t.Fatalf("MerkleRootTxids: %v", err)
	}
	block := buildBlockBytes(t, prev, root, target, 1, [][]byte{coinbase, validBytes, invalidBytes})

	_, seqErr := ConnectBlockBasicInMemoryAtHeight(block, &prev, &target, height, []uint64{0}, seqState, [32]byte{})
	parState := makeState()
	_, parErr := ConnectBlockParallelSigVerify(block, &prev, &target, height, []uint64{0}, parState, [32]byte{}, 4)

	if seqErr == nil {
		t.Fatal("sequential must reject block with invalid second tx")
	}
	if parErr == nil {
		t.Fatal("parallel must reject block with invalid second tx")
	}
	seqCode := txErrCode(seqErr)
	parCode := txErrCode(parErr)
	if seqCode != parCode {
		t.Fatalf("error code mismatch: seq=%s par=%s", seqCode, parCode)
	}
}

func TestIntegrationParity_MultipleValidTxs(t *testing.T) {
	height := uint64(1)
	prev := hashWithPrefix(0xAA)
	target := filledHash(0xff)

	kp := mustMLDSA87Keypair(t)
	covData := p2pkCovenantDataForPubkey(kp.PubkeyBytes())
	prevOut := Outpoint{Txid: prev, Vout: 0}

	makeState := func() *InMemoryChainState {
		return &InMemoryChainState{
			Utxos: map[Outpoint]UtxoEntry{
				prevOut: {
					Value:        500,
					CovenantType: COV_TYPE_P2PK,
					CovenantData: append([]byte(nil), covData...),
				},
			},
			AlreadyGenerated: new(big.Int),
		}
	}

	txs := make([][]byte, 0, 4)
	txids := make([][32]byte, 0, 4)
	curVal := uint64(500)
	var prevTxid [32]byte
	copy(prevTxid[:], prev[:])
	sumFees := uint64(0)

	for i := 0; i < 3; i++ {
		outVal := curVal - 10
		spend := &Tx{
			Version:  1,
			TxKind:   0x00,
			TxNonce:  uint64(i + 1),
			Inputs:   []TxInput{{PrevTxid: prevTxid, PrevVout: 0, Sequence: 0}},
			Outputs:  []TxOutput{{Value: outVal, CovenantType: COV_TYPE_P2PK, CovenantData: covData}},
			Locktime: 0,
		}
		spend.Witness = []WitnessItem{signP2PKInputWitness(t, spend, 0, curVal, [32]byte{}, kp)}
		spendBytes := txBytesFromTx(t, spend)
		_, txid, _, _, err := ParseTx(spendBytes)
		if err != nil {
			t.Fatalf("ParseTx: %v", err)
		}
		txs = append(txs, spendBytes)
		txids = append(txids, txid)
		sumFees += 10
		curVal = outVal
		copy(prevTxid[:], txid[:])
	}

	seqState := makeState()
	subsidy := BlockSubsidyBig(height, seqState.AlreadyGenerated)
	coinbase := coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, height, subsidy+sumFees, txs...)
	cbTxid := testTxID(t, coinbase)
	allTxids := append([][32]byte{cbTxid}, txids...)
	root, err := MerkleRootTxids(allTxids)
	if err != nil {
		t.Fatalf("MerkleRootTxids: %v", err)
	}
	blockTxs := append([][]byte{coinbase}, txs...)
	block := buildBlockBytes(t, prev, root, target, 1, blockTxs)

	seqSummary, seqErr := ConnectBlockBasicInMemoryAtHeight(block, &prev, &target, height, []uint64{0}, seqState, [32]byte{})
	parState := makeState()
	parSummary, parErr := ConnectBlockParallelSigVerify(block, &prev, &target, height, []uint64{0}, parState, [32]byte{}, 8)

	if seqErr != nil {
		t.Fatalf("sequential: %v", seqErr)
	}
	if parErr != nil {
		t.Fatalf("parallel: %v", parErr)
	}
	if seqSummary.PostStateDigest != parSummary.PostStateDigest {
		t.Fatalf("post-state digest mismatch: seq=%x par=%x", seqSummary.PostStateDigest, parSummary.PostStateDigest)
	}
	if seqSummary.SumFees != parSummary.SumFees {
		t.Fatalf("SumFees mismatch: seq=%d par=%d", seqSummary.SumFees, parSummary.SumFees)
	}
}

func txErrCode(err error) string {
	if te, ok := err.(*TxError); ok {
		return string(te.Code)
	}
	return err.Error()
}
