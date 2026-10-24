package consensus

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
	"reflect"
	"testing"
)

func TestConnectBlock_Section16GlobalFamilyOrder(t *testing.T) {
	valid, utxos := section16SignedControl(t)
	prev, target := hashWithPrefix(0x77), filledHash(0xff)
	initial := &InMemoryChainState{Utxos: utxos, AlreadyGenerated: big.NewInt(123)}
	makeState := func() *InMemoryChainState {
		return &InMemoryChainState{Utxos: cloneUtxoSet(utxos), AlreadyGenerated: new(big.Int).Set(initial.AlreadyGenerated)}
	}
	block := func(txs ...*Tx) []byte {
		raw := make([][]byte, 0, len(txs)+1)
		for _, tx := range txs {
			raw = append(raw, txBytesFromTx(t, tx))
		}
		cb := coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 1, BlockSubsidyBig(1, initial.AlreadyGenerated)+10, raw...)
		raw = append([][]byte{cb}, raw...)
		ids := make([][32]byte, len(raw))
		for i := range raw {
			ids[i] = testTxID(t, raw[i])
		}
		root, err := MerkleRootTxids(ids)
		if err != nil {
			t.Fatal(err)
		}
		return buildBlockBytes(t, prev, root, target, 1, raw)
	}
	validBlock := block(valid)
	for _, parallel := range []bool{false, true} {
		connect := func(raw []byte, state *InMemoryChainState) (*ConnectBlockBasicSummary, error) {
			if parallel {
				return ConnectBlockParallelSigVerify(raw, &prev, &target, 1, []uint64{0}, state, [32]byte{}, 4)
			}
			return ConnectBlockBasicInMemoryAtHeight(raw, &prev, &target, 1, []uint64{0}, state, [32]byte{})
		}
		controlState := makeState()
		control, err := connect(validBlock, controlState)
		if err != nil || control.SumFees.Cmp(Uint128FromU64(10)) != 0 {
			t.Fatalf("valid connect control: %v", err)
		}
		bad := section16TestTx(2, []TxInput{{PrevTxid: hashWithPrefix(0x51), Sequence: 0x80000000}, {PrevVout: 0xffffffff}})
		for _, mode := range []string{"valid_then_structural", "earlier_output", "earlier_missing"} {
			first := section16SnapshotTx(valid)
			state := makeState()
			want, msg := TX_ERR_PARSE, "coinbase prevout encoding forbidden in non-coinbase"
			switch mode {
			case "earlier_output":
				first.Outputs = []TxOutput{{CovenantType: 0x0105}}
				want, msg = TX_ERR_COVENANT_TYPE_INVALID, "unknown covenant_type"
			case "earlier_missing":
				first.Inputs[0].PrevTxid = hashWithPrefix(0x69)
				want, msg = TX_ERR_MISSING_UTXO, "utxo not found"
			}
			summary, err := connect(block(first, bad), state)
			assertTxErrCodeMsg(t, err, want, msg)
			if summary != nil || !reflect.DeepEqual(state, initial) {
				t.Fatalf("%s parallel=%v: rejection published state or summary", mode, parallel)
			}
			if mode == "valid_then_structural" {
				got, err := connect(validBlock, state)
				if err != nil || !reflect.DeepEqual(got, control) || !reflect.DeepEqual(state, controlState) {
					t.Fatalf("rejected-then-valid connect differs from control: %v", err)
				}
			}
		}
	}
}

// Integration parity suite (Q-PV-15): tests that sequential and parallel
// validation produce the same verdict, error code, first-invalid behavior,
// and post-state digest for valid, invalid, and mixed scenarios.

func coinbaseWithWitnessCommitmentAndOutputsAtHeight(t *testing.T, height uint64, outputs []testOutput, nonCoinbaseTxs ...[]byte) []byte {
	t.Helper()
	wtxids := make([][32]byte, 1, 1+len(nonCoinbaseTxs))
	for _, txb := range nonCoinbaseTxs {
		_, _, wtxid, _, err := ParseTx(txb)
		if err != nil {
			t.Fatalf("ParseTx(non-coinbase): %v", err)
		}
		wtxids = append(wtxids, wtxid)
	}
	wroot, err := WitnessMerkleRootWtxids(wtxids)
	if err != nil {
		t.Fatalf("WitnessMerkleRootWtxids: %v", err)
	}
	commit := WitnessCommitmentHash(wroot)
	outputs = append(append([]testOutput(nil), outputs...), testOutput{value: 0, covenantType: COV_TYPE_ANCHOR, covenantData: commit[:]})
	return coinbaseTxWithOutputs(uint32(height), outputs)
}

func TestConnectBlock_ApplyCoinbaseBeforeNonCoinbase(t *testing.T) {
	height := uint64(10)
	coinbaseTxid := hashWithPrefix(0xa9)
	cov := validP2PKCovenantData()
	coinbase := &Tx{TxKind: 0, Outputs: []TxOutput{
		{Value: 1, CovenantType: COV_TYPE_P2PK, CovenantData: cov},
		{Value: 0, CovenantType: COV_TYPE_ANCHOR, CovenantData: []byte{0x01}},
	}}
	spend := &Tx{Version: 1, TxKind: 0, TxNonce: 1, Inputs: []TxInput{{PrevTxid: coinbaseTxid, PrevVout: 0, Sequence: 0}}, Outputs: []TxOutput{{Value: 1, CovenantType: COV_TYPE_P2PK, CovenantData: cov}}}
	pb := &ParsedBlock{Txs: []*Tx{coinbase, spend}, Txids: [][32]byte{coinbaseTxid, hashWithPrefix(0xaa)}}
	apply := func() error {
		_, _, err := applyInMemorySequentialConnect(pb, make(map[Outpoint]UtxoEntry), height, 0, connectBlockInMemoryValidationContext{})
		return err
	}

	if got := mustTxErrCode(t, apply()); got != TX_ERR_COINBASE_IMMATURE {
		t.Fatalf("spendable coinbase output code=%s, want %s", got, TX_ERR_COINBASE_IMMATURE)
	}
	spend.Inputs[0].PrevVout = 1
	if got := mustTxErrCode(t, apply()); got != TX_ERR_MISSING_UTXO {
		t.Fatalf("ANCHOR coinbase output code=%s, want %s", got, TX_ERR_MISSING_UTXO)
	}
	runConnectBlockFirstErrorCases(t, true)
}

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

func TestConnectBlock_TransactionIndexFirstErrorOrder(t *testing.T) {
	runConnectBlockFirstErrorCases(t, false)
}

func runConnectBlockFirstErrorCases(t *testing.T, rub1099 bool) {
	height, prev, target := uint64(1), hashWithPrefix(0x59), filledHash(0xff)
	state := func(cov []byte) *InMemoryChainState {
		utxos := make(map[Outpoint]UtxoEntry)
		for vout := uint32(0); vout < 3; vout++ {
			utxos[Outpoint{Txid: prev, Vout: vout}] = UtxoEntry{Value: 100, CovenantType: COV_TYPE_P2PK, CovenantData: append([]byte(nil), cov...)}
		}
		return &InMemoryChainState{Utxos: utxos, AlreadyGenerated: big.NewInt(123)}
	}
	spend := func(cov []byte, nonce uint64, vout uint32, value uint64) *Tx {
		return &Tx{Version: 1, TxKind: 0, TxNonce: nonce, Inputs: []TxInput{{PrevTxid: prev, PrevVout: vout, Sequence: 0}}, Outputs: []TxOutput{{Value: value, CovenantType: COV_TYPE_P2PK, CovenantData: cov}}}
	}
	missing := func(cov []byte, nonce uint64) []byte { return txBytesFromTx(t, spend(cov, nonce, 99, 90)) }
	invalid := func(cov []byte, nonce uint64, vout uint32) []byte {
		return txBytesFromTx(t, spend(cov, nonce, vout, 0))
	}
	noInputs := func(cov []byte, nonce uint64) []byte {
		return txBytesFromTx(t, &Tx{Version: 1, TxKind: 0, TxNonce: nonce, Outputs: []TxOutput{{Value: 1, CovenantType: COV_TYPE_P2PK, CovenantData: cov}}})
	}
	buildBlock := func(coinbase []byte, txs ...[]byte) []byte {
		ids := make([][32]byte, 1, len(txs)+1)
		ids[0] = testTxID(t, coinbase)
		for _, tx := range txs {
			ids = append(ids, testTxID(t, tx))
		}
		root, err := MerkleRootTxids(ids)
		if err != nil {
			t.Fatal(err)
		}
		return buildBlockBytes(t, prev, root, target, 1, append([][]byte{coinbase}, txs...))
	}
	block := func(coinbaseValue uint64, txs ...[]byte) []byte {
		return buildBlock(coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, height, coinbaseValue, txs...), txs...)
	}
	assertState := func(t *testing.T, got, want *InMemoryChainState) {
		t.Helper()
		if !reflect.DeepEqual(got.Utxos, want.Utxos) || got.AlreadyGenerated.Cmp(want.AlreadyGenerated) != 0 {
			t.Fatal("rejection changed initialized chainstate")
		}
	}
	var rotation RotationProvider
	if rub1099 {
		rotation = testRotationProvider{createSuiteID: SUITE_ID_ML_DSA_87, simplicityActiveHeight: height}
	}
	reject := func(t *testing.T, b []byte, want ErrorCode, cov []byte, wantMsg ...string) {
		t.Helper()
		seq, seqBefore := state(cov), state(cov)
		seqSummary, seqErr := ConnectBlockBasicInMemoryAtHeightAndSuiteContext(b, &prev, &target, height, []uint64{0}, seq, [32]byte{}, rotation, nil)
		if seqSummary != nil {
			t.Fatal("rejected sequential block published summary")
		}
		if got := mustTxErrCode(t, seqErr); got != want {
			t.Fatalf("sequential=%s, want %s", got, want)
		}
		var seqTxErr *TxError
		if len(wantMsg) != 0 && (!errors.As(seqErr, &seqTxErr) || seqTxErr == nil || seqTxErr.Msg != wantMsg[0]) {
			t.Fatalf("sequential error=%v, want message %q", seqErr, wantMsg[0])
		}
		assertState(t, seq, seqBefore)
		contexts := []bool{true}
		if !rub1099 {
			contexts = []bool{false, true}
		}
		for _, suiteContext := range contexts {
			par, parBefore := state(cov), state(cov)
			var parSummary *ConnectBlockBasicSummary
			var parErr error
			if suiteContext {
				parSummary, parErr = ConnectBlockParallelSigVerifyWithSuiteContext(b, &prev, &target, height, []uint64{0}, par, [32]byte{}, rotation, DefaultSuiteRegistry(), 2)
			} else {
				parSummary, parErr = ConnectBlockParallelSigVerify(b, &prev, &target, height, []uint64{0}, par, [32]byte{}, 2)
			}
			if parSummary != nil {
				t.Fatal("rejected parallel block published summary")
			}
			if got := mustTxErrCode(t, parErr); got != want {
				t.Fatalf("parallel=%s, want %s", got, want)
			}
			var parTxErr *TxError
			if len(wantMsg) != 0 && (!errors.As(parErr, &parTxErr) || parTxErr == nil || parTxErr.Msg != wantMsg[0]) {
				t.Fatalf("parallel error=%v, want message %q", parErr, wantMsg[0])
			}
			assertState(t, par, parBefore)
		}
	}
	subsidy := BlockSubsidyBig(height, big.NewInt(123))
	t.Run("precrypto", func(t *testing.T) {
		cov := validP2PKCovenantData()
		coinbaseLike := coinbaseTxWithOutputs(uint32(height), []testOutput{{value: 1, covenantType: COV_TYPE_P2PK, covenantData: cov}})
		cases := []struct {
			name  string
			value uint64
			txs   [][]byte
			want  ErrorCode
		}{
			{"missing_only", subsidy + 20, [][]byte{missing(cov, 1)}, TX_ERR_MISSING_UTXO},
			{"missing_before_invalid_output", subsidy + 20, [][]byte{missing(cov, 1), invalid(cov, 2, 1)}, TX_ERR_MISSING_UTXO},
			{"missing_before_coinbase_like", subsidy + 20, [][]byte{missing(cov, 1), coinbaseLike}, TX_ERR_MISSING_UTXO},
			{"missing_before_zero_nonce_empty", subsidy + 20, [][]byte{missing(cov, 1), noInputs(cov, 0)}, TX_ERR_MISSING_UTXO},
			{"missing_before_empty", subsidy + 20, [][]byte{missing(cov, 1), noInputs(cov, 2)}, TX_ERR_MISSING_UTXO},
			{"missing_before_replay", subsidy + 20, [][]byte{missing(cov, 1), missing(cov, 1)}, TX_ERR_MISSING_UTXO},
			{"structural_before_output", subsidy + 20, [][]byte{noInputs(cov, 3), invalid(cov, 4, 1)}, TX_ERR_PARSE},
			{"same_tx_output_before_missing", subsidy + 20, [][]byte{invalid(cov, 1, 99)}, TX_ERR_COVENANT_TYPE_INVALID},
			{"coinbase_before_later", 0, [][]byte{missing(cov, 1)}, TX_ERR_COVENANT_TYPE_INVALID},
			{"da_integrity_before_tx_semantics", subsidy, [][]byte{daCommitTxBytes(1, filled32(0x61), 1, filled32(0x62))}, BLOCK_ERR_DA_INCOMPLETE},
		}
		for i, tc := range cases {
			if rub1099 && i > 0 {
				break
			}
			t.Run(tc.name, func(t *testing.T) { reject(t, block(tc.value, tc.txs...), tc.want, cov) })
		}
		missingTx := missing(cov, 1)
		vaultCoinbase := coinbaseWithWitnessCommitmentAndVaultOutputAtHeight(t, height, 1, validVaultCovenantDataForP2PKOutput(), missingTx)
		t.Run("coinbase_vault_before_missing", func(t *testing.T) {
			reject(t, buildBlock(vaultCoinbase, missingTx), BLOCK_ERR_COINBASE_INVALID, cov)
		})
		if !rub1099 {
			return
		}
		daCoinbase := coinbaseWithWitnessCommitmentAndOutputsAtHeight(t, height, []testOutput{{value: 0, covenantType: COV_TYPE_DA_COMMIT, covenantData: make([]byte, 32)}})
		reject(t, buildBlock(daCoinbase), TX_ERR_COVENANT_TYPE_INVALID, cov)
		simplicityData := encodeSimplicityCovenantData([32]byte{0x5a}, nil)
		simplicityOutputs := make([]testOutput, 0, SIMPLICITY_MAX_GROUP_OUTPUTS+2)
		for i := 0; i <= SIMPLICITY_MAX_GROUP_OUTPUTS; i++ {
			simplicityOutputs = append(simplicityOutputs, testOutput{value: 1, covenantType: COV_TYPE_CORE_SIMPLICITY, covenantData: simplicityData})
		}
		capCoinbase := coinbaseWithWitnessCommitmentAndOutputsAtHeight(t, height, simplicityOutputs)
		reject(t, buildBlock(capCoinbase), TX_ERR_COVENANT_TYPE_INVALID, cov, "CORE_SIMPLICITY same-cmr output group exceeds limit")
		simplicityOutputs = append(simplicityOutputs, testOutput{value: 0, covenantType: COV_TYPE_P2PK, covenantData: cov})
		capThenInvalid := coinbaseWithWitnessCommitmentAndOutputsAtHeight(t, height, simplicityOutputs)
		reject(t, buildBlock(capThenInvalid), TX_ERR_COVENANT_TYPE_INVALID, cov, "CORE_P2PK value must be > 0")
		vaultOnly := coinbaseWithWitnessCommitmentAndVaultOutputAtHeight(t, height, 1, validVaultCovenantDataForP2PKOutput())
		t.Run("coinbase_vault_only", func(t *testing.T) {
			reject(t, buildBlock(vaultOnly), BLOCK_ERR_COINBASE_INVALID, cov)
		})
		emptyTx := noInputs(cov, 2)
		vaultBeforeEmpty := coinbaseWithWitnessCommitmentAndVaultOutputAtHeight(t, height, 1, validVaultCovenantDataForP2PKOutput(), emptyTx)
		t.Run("coinbase_vault_before_later_empty_input", func(t *testing.T) {
			reject(t, buildBlock(vaultBeforeEmpty, emptyTx), BLOCK_ERR_COINBASE_INVALID, cov)
		})
		invalidTx := invalid(cov, 1, 0)
		vaultThenInvalid := coinbaseWithWitnessCommitmentAndOutputsAtHeight(t, height, []testOutput{
			{value: 1, covenantType: COV_TYPE_VAULT, covenantData: validVaultCovenantDataForP2PKOutput()},
			{value: 0, covenantType: COV_TYPE_P2PK, covenantData: cov},
		}, invalidTx)
		t.Run("coinbase_vault_before_later_creation", func(t *testing.T) {
			reject(t, buildBlock(vaultThenInvalid, invalidTx), BLOCK_ERR_COINBASE_INVALID, cov)
		})
		creationOnly := coinbaseWithWitnessCommitmentAndOutputsAtHeight(t, height, []testOutput{
			{value: 1, covenantType: COV_TYPE_P2PK, covenantData: cov},
			{value: 0, covenantType: COV_TYPE_P2PK, covenantData: cov},
		})
		t.Run("coinbase_creation_only", func(t *testing.T) {
			reject(t, buildBlock(creationOnly), TX_ERR_COVENANT_TYPE_INVALID, cov)
		})
		creationThenVault := coinbaseWithWitnessCommitmentAndOutputsAtHeight(t, height, []testOutput{
			{value: 0, covenantType: COV_TYPE_P2PK, covenantData: cov},
			{value: 1, covenantType: COV_TYPE_VAULT, covenantData: validVaultCovenantDataForP2PKOutput()},
		}, missingTx)
		t.Run("coinbase_creation_before_vault", func(t *testing.T) {
			reject(t, buildBlock(creationThenVault, missingTx), TX_ERR_COVENANT_TYPE_INVALID, cov)
		})
		t.Run("coinbase_zero_value_vault_before_own_creation_error", func(t *testing.T) {
			zeroVault := coinbaseWithWitnessCommitmentAndVaultOutputAtHeight(t, height, 0, validVaultCovenantDataForP2PKOutput())
			reject(t, buildBlock(zeroVault), BLOCK_ERR_COINBASE_INVALID, cov)
		})
		vaultExceedingSubsidy := coinbaseWithWitnessCommitmentAndVaultOutputAtHeight(t, height, subsidy+1, validVaultCovenantDataForP2PKOutput())
		t.Run("coinbase_vault_before_subsidy", func(t *testing.T) {
			reject(t, buildBlock(vaultExceedingSubsidy), BLOCK_ERR_COINBASE_INVALID, cov)
		})
	})

	t.Run("signed", func(t *testing.T) {
		kp, err := NewMLDSA87Keypair()
		if err != nil {
			t.Fatalf("ML-DSA-87 backend required for RUB-659: %v", err)
		}
		t.Cleanup(func() { kp.Close() })
		cov := p2pkCovenantDataForPubkey(kp.PubkeyBytes())
		valid := func(nonce uint64, vout uint32, value uint64) []byte {
			tx := spend(cov, nonce, vout, value)
			tx.Witness = []WitnessItem{signP2PKInputWitness(t, tx, 0, 100, [32]byte{}, kp)}
			return txBytesFromTx(t, tx)
		}
		other := requiredOrderedKeypair(t)
		for _, variant := range []string{"suite", "key", "selector"} {
			for _, firstValid := range []bool{false, true} {
				t.Run(fmt.Sprintf("same_tx/%s/firstValid%v", variant, firstValid), func(t *testing.T) {
					tx := spend(cov, 1, 0, 190)
					tx.Inputs = append(tx.Inputs, TxInput{PrevTxid: prev, PrevVout: 1})
					chain := [32]byte{0x77}
					if firstValid {
						chain = [32]byte{}
					}
					tx.Witness = []WitnessItem{signP2PKInputWitness(t, tx, 0, 100, chain, kp), signP2PKInputWitness(t, tx, 1, 100, [32]byte{}, kp)}
					code, msg := ErrorCode("TX_ERR_SIG_INVALID"), "CORE_P2PK signature invalid"
					switch variant {
					case "suite":
						tx.Witness[1].SuiteID = 0xfe
						if firstValid {
							code, msg = "TX_ERR_SIG_ALG_INVALID", "CORE_P2PK suite not in native spend set"
						}
					case "key":
						tx.Witness[1].Pubkey = other.PubkeyBytes()
						if firstValid {
							msg = "CORE_P2PK key binding mismatch"
						}
					case "selector":
						tx.Witness[1].Signature[len(tx.Witness[1].Signature)-1] = 0x00
						if firstValid {
							code, msg = "TX_ERR_SIGHASH_TYPE_INVALID", "invalid sighash_type"
						}
					}
					reject(t, block(subsidy, txBytesFromTx(t, tx)), code, cov, msg)
				})
			}
		}
		t.Run("earlier transaction result during later threshold panic", func(t *testing.T) {
			key, otherKey := sha3_256(kp.PubkeyBytes()), sha3_256(other.PubkeyBytes())
			thresholdKP := kp
			if bytes.Compare(key[:], otherKey[:]) > 0 {
				key, otherKey, thresholdKP = otherKey, key, other
			}
			multi := encodeMultisigCovenantData(2, [][32]byte{key, otherKey})
			first := spend(cov, 1, 0, 90)
			first.Witness = []WitnessItem{signP2PKInputWitness(t, first, 0, 100, [32]byte{}, kp)}
			second := spend(cov, 2, 1, 90)
			second.Witness = []WitnessItem{signP2PKInputWitness(t, second, 0, 100, [32]byte{}, thresholdKP), {SuiteID: SUITE_ID_SENTINEL}}
			digest, err := SighashV1DigestWithType(first, 0, 100, [32]byte{}, SIGHASH_ALL)
			if err != nil {
				t.Fatal(err)
			}
			raw := block(subsidy, txBytesFromTx(t, first), txBytesFromTx(t, second))
			for _, disposition := range []string{"error", "panic", "success"} {
				t.Run(disposition, func(t *testing.T) {
					laterPanic, earlierPanic := &struct{ label string }{"later tx"}, &struct{ label string }{"earlier tx"}
					queueVerifierHook(t, func(_ string, _, _, msg []byte) (bool, error) {
						if bytes.Equal(msg, digest[:]) {
							if disposition == "panic" {
								panic(earlierPanic)
							}
							return disposition == "success", nil
						}
						panic(laterPanic)
					})
					initial := state(cov)
					initial.Utxos[Outpoint{Txid: prev, Vout: 1}] = UtxoEntry{Value: 100, CovenantType: COV_TYPE_MULTISIG, CovenantData: multi}
					before := &InMemoryChainState{Utxos: cloneUtxoSet(initial.Utxos), AlreadyGenerated: new(big.Int).Set(initial.AlreadyGenerated)}
					invoke := func() {
						summary, err := ConnectBlockParallelSigVerify(raw, &prev, &target, height, []uint64{0}, initial, [32]byte{}, 2)
						if disposition != "error" || summary != nil {
							t.Fatal("later block panic returned without earlier error or published summary")
						}
						assertTxErrCodeMsg(t, err, "TX_ERR_SIG_INVALID", "CORE_P2PK signature invalid")
					}
					if disposition == "error" {
						invoke()
					} else if disposition == "panic" {
						requireQueuePanic(t, earlierPanic, invoke)
					} else {
						requireQueuePanic(t, laterPanic, invoke)
					}
					assertState(t, initial, before)
				})
			}
		})

		for _, firstValid := range []bool{false, true} {
			first := spend(cov, 1, 0, 90)
			chainID := [32]byte{0x77}
			if firstValid {
				chainID = [32]byte{}
			}
			first.Witness = []WitnessItem{signP2PKInputWitness(t, first, 0, 100, chainID, kp)}
			firstRaw := txBytesFromTx(t, first)
			for _, later := range []struct {
				name string
				raw  []byte
				code ErrorCode
				msg  string
			}{
				{"missing", missing(cov, 2), "TX_ERR_MISSING_UTXO", "utxo not found"},
				{"nonce_zero", txBytesFromTx(t, spend(cov, 0, 1, 90)), "TX_ERR_TX_NONCE_INVALID", "tx_nonce must be >= 1 for non-coinbase"},
				{"replay", valid(1, 1, 90), "TX_ERR_NONCE_REPLAY", "duplicate tx_nonce in block"},
				{"invalid_output", invalid(cov, 2, 1), "TX_ERR_COVENANT_TYPE_INVALID", "CORE_P2PK value must be > 0"},
			} {
				name := fmt.Sprintf("retained_signature/%s/firstValid%v", later.name, firstValid)
				t.Run(name, func(t *testing.T) {
					code, msg := ErrorCode("TX_ERR_SIG_INVALID"), "CORE_P2PK signature invalid"
					if firstValid {
						code, msg = later.code, later.msg
					}
					reject(t, block(subsidy, firstRaw, later.raw), code, cov, msg)
				})
			}
			// A global linkage failure remains before all transaction signatures.
			t.Run(fmt.Sprintf("global_linkage/firstValid%v", firstValid), func(t *testing.T) {
				bad := block(subsidy, firstRaw)
				bad[4] ^= 1
				reject(t, bad, "BLOCK_ERR_LINKAGE_INVALID", cov, "prev_block_hash mismatch")
			})
			t.Run(fmt.Sprintf("global_parse/firstValid%v", firstValid), func(t *testing.T) {
				reject(t, append(block(subsidy, firstRaw), 0), "BLOCK_ERR_PARSE", cov, "trailing bytes after tx list")
			})
			t.Run(fmt.Sprintf("global_resource/firstValid%v", firstValid), func(t *testing.T) {
				filler := txWithNonceAndOutputs(3, repeatedAnchorOutputs(3, 50_000))
				reject(t, block(subsidy, firstRaw, filler), "BLOCK_ERR_ANCHOR_BYTES_EXCEEDED", cov, "anchor bytes exceeded")
			})
			t.Run(fmt.Sprintf("global_coinbase/firstValid%v", firstValid), func(t *testing.T) {
				coinbase := coinbaseWithWitnessCommitmentAndVaultOutputAtHeight(t, height, 1, validVaultCovenantDataForP2PKOutput(), firstRaw)
				reject(t, buildBlock(coinbase, firstRaw), "BLOCK_ERR_COINBASE_INVALID", cov, "coinbase must not create CORE_VAULT outputs")
			})
		}

		coinbaseLike := coinbaseTxWithOutputs(uint32(height), []testOutput{{value: 1, covenantType: COV_TYPE_P2PK, covenantData: cov}})
		cases := []struct {
			name string
			txs  [][]byte
			want ErrorCode
		}{
			{"later_invalid_output", [][]byte{valid(1, 0, 90), invalid(cov, 2, 1)}, TX_ERR_COVENANT_TYPE_INVALID},
			{"replay_before_output", [][]byte{valid(1, 0, 90), missing(cov, 1), invalid(cov, 2, 1)}, TX_ERR_NONCE_REPLAY},
			{"value_before_output", [][]byte{valid(1, 0, 101), invalid(cov, 2, 1)}, TX_ERR_VALUE_CONSERVATION},
			{"valid_before_coinbase_like", [][]byte{valid(1, 0, 90), coinbaseLike}, BLOCK_ERR_COINBASE_INVALID},
			{"valid_before_zero_nonce_empty", [][]byte{valid(1, 0, 90), noInputs(cov, 0)}, TX_ERR_TX_NONCE_INVALID},
			{"valid_before_empty", [][]byte{valid(1, 0, 90), noInputs(cov, 2)}, TX_ERR_PARSE},
			{"missing_valid_middle_invalid", [][]byte{missing(cov, 1), valid(2, 0, 90), invalid(cov, 3, 1)}, TX_ERR_MISSING_UTXO},
		}
		for _, tc := range cases {
			if rub1099 {
				break
			}
			t.Run(tc.name, func(t *testing.T) { reject(t, block(subsidy+20, tc.txs...), tc.want, cov) })
		}
		if rub1099 {
			replayFirst, replaySecond := valid(1, 0, 90), valid(1, 1, 90)
			vaultBeforeReplay := coinbaseWithWitnessCommitmentAndVaultOutputAtHeight(t, height, 1, validVaultCovenantDataForP2PKOutput(), replayFirst, replaySecond)
			t.Run("coinbase_vault_before_later_nonce_replay", func(t *testing.T) {
				reject(t, buildBlock(vaultBeforeReplay, replayFirst, replaySecond), BLOCK_ERR_COINBASE_INVALID, cov)
			})
		}
		firstRaw, secondRaw := valid(1, 0, 90), valid(2, 1, 90)
		validBlock := block(subsidy+20, firstRaw, secondRaw)
		seq, par := state(cov), state(cov)
		seqSummary, seqErr := ConnectBlockBasicInMemoryAtHeight(validBlock, &prev, &target, height, []uint64{0}, seq, [32]byte{})
		parSummary, parErr := ConnectBlockParallelSigVerify(validBlock, &prev, &target, height, []uint64{0}, par, [32]byte{}, 2)
		if seqErr != nil || parErr != nil || seqSummary.PostStateDigest != parSummary.PostStateDigest || !reflect.DeepEqual(seq, par) || seqSummary.SumFees != (Uint128{Lo: 20}) || parSummary.SumFees != (Uint128{Lo: 20}) || parSummary.SigTaskCount != 2 || parSummary.WorkerPanics != 0 {
			t.Fatalf("valid multi-tx parity failed: seq=%v par=%v", seqErr, parErr)
		}
		if par.AlreadyGenerated.Cmp(new(big.Int).SetUint64(123+subsidy)) != 0 || parSummary.AlreadyGenerated != (Uint128{Lo: 123}) || parSummary.AlreadyGeneratedN1 != (Uint128{Lo: 123 + subsidy}) || parSummary.UtxoCount != 4 {
			t.Fatalf("valid supply/summary: state=%s summary=%+v", par.AlreadyGenerated, parSummary)
		}
		coinbaseRaw := coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, height, subsidy+20, firstRaw, secondRaw)
		expected := map[Outpoint]UtxoEntry{
			{Txid: prev, Vout: 2}: {Value: 100, CovenantType: COV_TYPE_P2PK, CovenantData: cov},
		}
		expected[Outpoint{Txid: testTxID(t, firstRaw)}] = UtxoEntry{Value: 90, CovenantType: COV_TYPE_P2PK, CovenantData: cov, CreationHeight: height}
		expected[Outpoint{Txid: testTxID(t, secondRaw)}] = UtxoEntry{Value: 90, CovenantType: COV_TYPE_P2PK, CovenantData: cov, CreationHeight: height}
		expected[Outpoint{Txid: testTxID(t, coinbaseRaw)}] = UtxoEntry{Value: subsidy + 20, CovenantType: COV_TYPE_P2PK, CovenantData: validP2PKCovenantData(), CreationHeight: height, CreatedByCoinbase: true}
		if !reflect.DeepEqual(par.Utxos, expected) {
			t.Fatalf("valid exact UTXO result: got=%#v want=%#v", par.Utxos, expected)
		}
		t.Run("valid signatures before subsidy failure", func(t *testing.T) {
			reject(t, block(subsidy+21, firstRaw, secondRaw), "BLOCK_ERR_SUBSIDY_EXCEEDED", cov)
		})

	})
}

func TestConnectBlock_DA_CanonicalErrorOrderNoMutation(t *testing.T) {
	newState := func() *InMemoryChainState {
		return &InMemoryChainState{
			Utxos: map[Outpoint]UtxoEntry{
				{Txid: filled32(0xa0), Vout: 3}: {
					Value:             42,
					CovenantType:      COV_TYPE_P2PK,
					CovenantData:      []byte{0x51, 0x52},
					CreationHeight:    7,
					CreatedByCoinbase: true,
				},
			},
			AlreadyGenerated: big.NewInt(123),
		}
	}
	cloneState := func(s *InMemoryChainState) *InMemoryChainState {
		return &InMemoryChainState{Utxos: copyUtxoMap(s.Utxos), AlreadyGenerated: new(big.Int).Set(s.AlreadyGenerated)}
	}
	for _, tc := range canonicalDACases() {
		if tc.want == "" {
			continue
		}
		t.Run(tc.name, func(t *testing.T) {
			block, prev, target := buildDABlockBytes(t, tc.txs...)
			for _, workers := range []int{-1, 0, 1, 4} {
				state := newState()
				before := cloneState(state)
				var err error
				if workers < 0 {
					_, err = ConnectBlockBasicInMemoryAtHeight(block, &prev, &target, 1, []uint64{0}, state, [32]byte{})
				} else {
					_, err = ConnectBlockParallelSigVerify(block, &prev, &target, 1, []uint64{0}, state, [32]byte{}, workers)
				}
				if err == nil {
					t.Fatal("expected error")
				}
				if got := mustTxErrCode(t, err); got != tc.want {
					t.Fatalf("workers=%d code=%s, want %s", workers, got, tc.want)
				}
				if !reflect.DeepEqual(state.Utxos, before.Utxos) || state.AlreadyGenerated.Cmp(before.AlreadyGenerated) != 0 {
					t.Fatalf("workers=%d rejection changed initialized chainstate", workers)
				}
			}
		})
	}
}

func txErrCode(err error) string {
	if te, ok := err.(*TxError); ok {
		return string(te.Code)
	}
	return err.Error()
}
