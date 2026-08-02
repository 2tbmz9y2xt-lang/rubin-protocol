package consensus

import (
	"errors"
	"math/big"
	"reflect"
	"testing"
)

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
		return &InMemoryChainState{Utxos: utxos, AlreadyGenerated: new(big.Int)}
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
		_, seqErr := ConnectBlockBasicInMemoryAtHeightAndSuiteContext(b, &prev, &target, height, []uint64{0}, seq, [32]byte{}, rotation, nil)
		if got := mustTxErrCode(t, seqErr); got != want {
			t.Fatalf("sequential=%s, want %s", got, want)
		}
		var seqTxErr *TxError
		if len(wantMsg) != 0 && (!errors.As(seqErr, &seqTxErr) || seqTxErr == nil || seqTxErr.Msg != wantMsg[0]) {
			t.Fatalf("sequential error=%v, want message %q", seqErr, wantMsg[0])
		}
		assertState(t, seq, seqBefore)
		par, parBefore := state(cov), state(cov)
		_, parErr := ConnectBlockParallelSigVerifyWithSuiteContext(b, &prev, &target, height, []uint64{0}, par, [32]byte{}, rotation, nil, 2)
		if got := mustTxErrCode(t, parErr); got != want {
			t.Fatalf("parallel=%s, want %s", got, want)
		}
		var parTxErr *TxError
		if len(wantMsg) != 0 && (!errors.As(parErr, &parTxErr) || parTxErr == nil || parTxErr.Msg != wantMsg[0]) {
			t.Fatalf("parallel error=%v, want message %q", parErr, wantMsg[0])
		}
		assertState(t, par, parBefore)
	}
	subsidy := BlockSubsidyBig(height, new(big.Int))
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
		validBlock := block(subsidy+20, valid(1, 0, 90), valid(2, 1, 90))
		seq, par := state(cov), state(cov)
		seqSummary, seqErr := ConnectBlockBasicInMemoryAtHeight(validBlock, &prev, &target, height, []uint64{0}, seq, [32]byte{})
		parSummary, parErr := ConnectBlockParallelSigVerify(validBlock, &prev, &target, height, []uint64{0}, par, [32]byte{}, 2)
		if seqErr != nil || parErr != nil || seqSummary.PostStateDigest != parSummary.PostStateDigest || !reflect.DeepEqual(seq, par) {
			t.Fatalf("valid multi-tx parity failed: seq=%v par=%v", seqErr, parErr)
		}
	})
}

func txErrCode(err error) string {
	if te, ok := err.(*TxError); ok {
		return string(te.Code)
	}
	return err.Error()
}
