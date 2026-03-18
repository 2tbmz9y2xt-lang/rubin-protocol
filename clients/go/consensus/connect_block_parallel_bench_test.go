package consensus

import (
	"math/big"
	"runtime"
	"testing"
)

// BenchmarkConnectBlockParallelSigVerify_* measure ns/op for parallel block
// validation at different worker counts. Used for Q-PV-18 evidence and gates:
// 1-worker regression ≤5%; multi-worker (8/16) should show gain.
// Run with: go test -bench=BenchmarkConnectBlockParallelSigVerify -benchmem
// Evidence: run and capture JSON (env + ns/op per worker count) for merge gates.

func buildBlockForBench(b *testing.B, numTxs int) (block []byte, prev, target [32]byte, height uint64, initialState *InMemoryChainState) {
	b.Helper()
	prev = hashWithPrefix(0x77)
	target = filledHash(0xff)
	height = 1

	kp := mustMLDSA87KeypairB(b)
	covData := p2pkCovenantDataForPubkey(kp.PubkeyBytes())
	prevOut := Outpoint{Txid: prev, Vout: 0}

	initialState = &InMemoryChainState{
		Utxos: map[Outpoint]UtxoEntry{
			prevOut: {
				Value:        uint64(100 * numTxs),
				CovenantType: COV_TYPE_P2PK,
				CovenantData: append([]byte(nil), covData...),
			},
		},
		AlreadyGenerated: new(big.Int),
	}

	var txs [][]byte
	var txids [][32]byte
	curVal := uint64(100 * numTxs)
	prevTxid := prev
	sumFees := uint64(0)

	for i := 0; i < numTxs; i++ {
		outVal := curVal - 10
		spendTx := &Tx{
			Version:  1,
			TxKind:   0x00,
			TxNonce:  uint64(i + 1),
			Inputs:   []TxInput{{PrevTxid: prevTxid, PrevVout: 0, Sequence: 0}},
			Outputs:  []TxOutput{{Value: outVal, CovenantType: COV_TYPE_P2PK, CovenantData: covData}},
			Locktime: 0,
		}
		spendTx.Witness = []WitnessItem{signP2PKInputWitnessBench(b, spendTx, 0, curVal, kp)}
		spendBytes := txBytesFromTxBench(b, spendTx)
		_, txid, _, _, err := ParseTx(spendBytes)
		if err != nil {
			b.Fatalf("ParseTx: %v", err)
		}
		txs = append(txs, spendBytes)
		txids = append(txids, txid)
		sumFees += 10
		curVal = outVal
		prevTxid = txid
	}

	subsidy := BlockSubsidyBig(height, initialState.AlreadyGenerated)
	coinbase := coinbaseWithWitnessCommitmentAndP2PKValueAtHeightBench(b, height, subsidy+sumFees, txs...)
	cbTxid := testTxIDBench(b, coinbase)
	allTxids := append([][32]byte{cbTxid}, txids...)
	root, err := MerkleRootTxids(allTxids)
	if err != nil {
		b.Fatalf("MerkleRootTxids: %v", err)
	}
	blockTxs := append([][]byte{coinbase}, txs...)
	block = buildBlockBytesBench(b, prev, root, target, 1, blockTxs)
	return block, prev, target, height, initialState
}

func signP2PKInputWitnessBench(b *testing.B, tx *Tx, inputIndex uint32, inputValue uint64, kp *MLDSA87Keypair) WitnessItem {
	b.Helper()
	d, err := SighashV1DigestWithType(tx, inputIndex, inputValue, [32]byte{}, SIGHASH_ALL)
	if err != nil {
		b.Fatalf("SighashV1DigestWithType: %v", err)
	}
	sig, err := kp.SignDigest32(d)
	if err != nil {
		b.Fatalf("SignDigest32: %v", err)
	}
	sig = append(sig, SIGHASH_ALL)
	return WitnessItem{SuiteID: SUITE_ID_ML_DSA_87, Pubkey: kp.PubkeyBytes(), Signature: sig}
}

func txBytesFromTxBench(b *testing.B, tx *Tx) []byte {
	b.Helper()
	out, err := MarshalTx(tx)
	if err != nil {
		b.Fatalf("MarshalTx: %v", err)
	}
	return out
}

func coinbaseWithWitnessCommitmentAndP2PKValueAtHeightBench(b *testing.B, height uint64, value uint64, nonCoinbaseTxs ...[]byte) []byte {
	b.Helper()
	wtxids := make([][32]byte, 1, 1+len(nonCoinbaseTxs))
	for _, txb := range nonCoinbaseTxs {
		_, _, wtxid, _, err := ParseTx(txb)
		if err != nil {
			b.Fatalf("ParseTx: %v", err)
		}
		wtxids = append(wtxids, wtxid)
	}
	wroot, err := WitnessMerkleRootWtxids(wtxids)
	if err != nil {
		b.Fatalf("WitnessMerkleRootWtxids: %v", err)
	}
	commit := WitnessCommitmentHash(wroot)
	return coinbaseTxWithOutputs(uint32(height), []testOutput{
		{value: value, covenantType: COV_TYPE_P2PK, covenantData: validP2PKCovenantData()},
		{value: 0, covenantType: COV_TYPE_ANCHOR, covenantData: commit[:]},
	})
}

func testTxIDBench(b *testing.B, tx []byte) [32]byte {
	b.Helper()
	_, txid, _, _, err := ParseTx(tx)
	if err != nil {
		b.Fatalf("ParseTx: %v", err)
	}
	return txid
}

func buildBlockBytesBench(b *testing.B, prevHash [32]byte, merkleRoot [32]byte, target [32]byte, nonce uint64, txs [][]byte) []byte {
	b.Helper()
	if len(txs) == 0 {
		b.Fatalf("txs must not be empty")
	}
	header := make([]byte, 0, BLOCK_HEADER_BYTES)
	header = AppendU32le(header, 1)
	header = append(header, prevHash[:]...)
	header = append(header, merkleRoot[:]...)
	header = AppendU64le(header, 1)
	header = append(header, target[:]...)
	header = AppendU64le(header, nonce)
	if len(header) != BLOCK_HEADER_BYTES {
		b.Fatalf("header size=%d", len(header))
	}
	out := make([]byte, 0, len(header)+32)
	out = append(out, header...)
	out = AppendCompactSize(out, uint64(len(txs)))
	for _, tx := range txs {
		out = append(out, tx...)
	}
	return out
}

func BenchmarkConnectBlockParallelSigVerify_1Worker(b *testing.B) {
	block, prev, target, height, state := buildBlockForBench(b, 8)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		st := cloneStateB(b, state)
		_, err := ConnectBlockParallelSigVerify(block, &prev, &target, height, []uint64{0}, st, [32]byte{}, 1)
		if err != nil {
			b.Fatalf("ConnectBlockParallelSigVerify: %v", err)
		}
	}
}

func BenchmarkConnectBlockParallelSigVerify_8Workers(b *testing.B) {
	block, prev, target, height, state := buildBlockForBench(b, 8)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		st := cloneStateB(b, state)
		_, err := ConnectBlockParallelSigVerify(block, &prev, &target, height, []uint64{0}, st, [32]byte{}, 8)
		if err != nil {
			b.Fatalf("ConnectBlockParallelSigVerify: %v", err)
		}
	}
}

func BenchmarkConnectBlockParallelSigVerify_16Workers(b *testing.B) {
	block, prev, target, height, state := buildBlockForBench(b, 16)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		st := cloneStateB(b, state)
		_, err := ConnectBlockParallelSigVerify(block, &prev, &target, height, []uint64{0}, st, [32]byte{}, 16)
		if err != nil {
			b.Fatalf("ConnectBlockParallelSigVerify: %v", err)
		}
	}
}

func BenchmarkConnectBlockParallelSigVerify_GOMAXPROCS(b *testing.B) {
	workers := runtime.GOMAXPROCS(0) * 2
	if workers < 2 {
		workers = 2
	}
	block, prev, target, height, state := buildBlockForBench(b, 8)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		st := cloneStateB(b, state)
		_, err := ConnectBlockParallelSigVerify(block, &prev, &target, height, []uint64{0}, st, [32]byte{}, workers)
		if err != nil {
			b.Fatalf("ConnectBlockParallelSigVerify: %v", err)
		}
	}
}

func cloneStateB(b *testing.B, s *InMemoryChainState) *InMemoryChainState {
	utxos := make(map[Outpoint]UtxoEntry, len(s.Utxos))
	for k, v := range s.Utxos {
		utxos[k] = v
	}
	return &InMemoryChainState{
		Utxos:            utxos,
		AlreadyGenerated: new(big.Int).Set(s.AlreadyGenerated),
	}
}
