package node

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

func mustBenchmarkNodeMLDSA87Keypair(tb testing.TB) *consensus.MLDSA87Keypair {
	tb.Helper()
	kp, err := consensus.NewMLDSA87Keypair()
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unsupported") {
			tb.Skipf("ML-DSA backend unavailable: %v", err)
		}
		tb.Fatalf("NewMLDSA87Keypair: %v", err)
	}
	tb.Cleanup(func() { kp.Close() })
	return kp
}

func benchmarkSpendableChainState(fromAddress []byte, values []uint64) (*ChainState, []consensus.Outpoint) {
	st := NewChainState()
	st.HasTip = true
	st.Height = 100
	st.TipHash[0] = 0x11
	outpoints := make([]consensus.Outpoint, 0, len(values))
	for i, value := range values {
		var txid [32]byte
		txid[0] = byte(i + 1)
		txid[31] = byte(i + 9)
		op := consensus.Outpoint{Txid: txid, Vout: uint32(i)}
		st.Utxos[op] = consensus.UtxoEntry{
			Value:             value,
			CovenantType:      consensus.COV_TYPE_P2PK,
			CovenantData:      append([]byte(nil), fromAddress...),
			CreationHeight:    1,
			CreatedByCoinbase: true,
		}
		outpoints = append(outpoints, op)
	}
	return st, outpoints
}

func mustBenchmarkSignedTransferTx(
	tb testing.TB,
	utxos map[consensus.Outpoint]consensus.UtxoEntry,
	inputs []consensus.Outpoint,
	amount uint64,
	fee uint64,
	nonce uint64,
	signer *consensus.MLDSA87Keypair,
	changeAddress []byte,
	toAddress []byte,
) []byte {
	tb.Helper()
	txInputs := make([]consensus.TxInput, 0, len(inputs))
	var totalIn uint64
	for _, op := range inputs {
		entry, ok := utxos[op]
		if !ok {
			tb.Fatalf("missing utxo for %x:%d", op.Txid, op.Vout)
		}
		totalIn += entry.Value
		txInputs = append(txInputs, consensus.TxInput{
			PrevTxid: op.Txid,
			PrevVout: op.Vout,
			Sequence: 0,
		})
	}
	if totalIn < amount || totalIn-amount < fee {
		tb.Fatalf("insufficient inputs: total=%d amount=%d fee=%d", totalIn, amount, fee)
	}
	change := totalIn - amount - fee
	outputs := []consensus.TxOutput{{
		Value:        amount,
		CovenantType: consensus.COV_TYPE_P2PK,
		CovenantData: append([]byte(nil), toAddress...),
	}}
	if change > 0 {
		outputs = append(outputs, consensus.TxOutput{
			Value:        change,
			CovenantType: consensus.COV_TYPE_P2PK,
			CovenantData: append([]byte(nil), changeAddress...),
		})
	}
	tx := &consensus.Tx{
		Version:  1,
		TxKind:   0x00,
		TxNonce:  nonce,
		Inputs:   txInputs,
		Outputs:  outputs,
		Locktime: 0,
	}
	if err := consensus.SignTransaction(tx, utxos, devnetGenesisChainID, signer); err != nil {
		tb.Fatalf("SignTransaction: %v", err)
	}
	raw, err := consensus.MarshalTx(tx)
	if err != nil {
		tb.Fatalf("MarshalTx: %v", err)
	}
	return raw
}

func snapshotChainState(tb testing.TB, st *ChainState) *ChainState {
	tb.Helper()
	snapshot := cloneChainState(st)
	if snapshot == nil {
		tb.Fatal("snapshot must not be nil")
	}
	return snapshot
}

func assertChainStateUnchanged(tb testing.TB, before *ChainState, after *ChainState) {
	tb.Helper()
	if !reflect.DeepEqual(before, after) {
		tb.Fatalf("base chainstate mutated\nbefore=%#v\nafter=%#v", before, after)
	}
}

func benchmarkConnectBlockFixture(tb testing.TB) (*ChainState, []byte, []uint64) {
	tb.Helper()
	fromKey := mustBenchmarkNodeMLDSA87Keypair(tb)
	toKey := mustBenchmarkNodeMLDSA87Keypair(tb)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	toAddress := consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes())
	state, outpoints := benchmarkSpendableChainState(fromAddress, []uint64{100})
	txBytes := mustBenchmarkSignedTransferTx(
		tb,
		state.Utxos,
		[]consensus.Outpoint{outpoints[0]},
		90,
		1,
		1,
		fromKey,
		fromAddress,
		toAddress,
	)
	_, txid, wtxid, consumed, err := consensus.ParseTx(txBytes)
	if err != nil {
		tb.Fatalf("ParseTx: %v", err)
	}
	if consumed != len(txBytes) {
		tb.Fatalf("non-canonical tx fixture: consumed=%d len=%d", consumed, len(txBytes))
	}
	weight, err := canonicalTxWeight(txBytes, "fixture tx must be canonical")
	if err != nil {
		tb.Fatalf("canonicalTxWeight: %v", err)
	}
	parsed := []minedCandidate{{
		raw:    txBytes,
		txid:   txid,
		wtxid:  wtxid,
		weight: weight,
	}}
	witnessCommitment, err := buildWitnessCommitment(parsed)
	if err != nil {
		tb.Fatalf("buildWitnessCommitment: %v", err)
	}
	nextHeight := state.Height + 1
	coinbase, err := buildCoinbaseTx(nextHeight, state.AlreadyGenerated, defaultMineAddress(), witnessCommitment)
	if err != nil {
		tb.Fatalf("buildCoinbaseTx: %v", err)
	}
	_, coinbaseTxid, _, consumed, err := consensus.ParseTx(coinbase)
	if err != nil {
		tb.Fatalf("ParseTx(coinbase): %v", err)
	}
	if consumed != len(coinbase) {
		tb.Fatalf("non-canonical coinbase fixture: consumed=%d len=%d", consumed, len(coinbase))
	}
	txids := [][32]byte{coinbaseTxid, txid}
	merkleRoot, err := consensus.MerkleRootTxids(txids)
	if err != nil {
		tb.Fatalf("MerkleRootTxids: %v", err)
	}
	prevTimestamps := []uint64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}
	timestamp := chooseValidTimestamp(nextHeight, prevTimestamps, 12)
	headerPrefix := makeHeaderPrefix(state.TipHash, merkleRoot, timestamp, consensus.POW_LIMIT)
	headerBytes, _, err := mineHeaderNonce(context.Background(), headerPrefix, consensus.POW_LIMIT)
	if err != nil {
		tb.Fatalf("mineHeaderNonce: %v", err)
	}
	return state, assembleBlockBytes(headerBytes, coinbase, parsed), prevTimestamps
}

func TestMempoolAddTxPreservesBaseChainState(t *testing.T) {
	fromKey := mustBenchmarkNodeMLDSA87Keypair(t)
	toKey := mustBenchmarkNodeMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	toAddress := consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes())
	state, outpoints := benchmarkSpendableChainState(fromAddress, []uint64{100})
	before := snapshotChainState(t, state)
	mp, err := NewMempool(state, nil, devnetGenesisChainID)
	if err != nil {
		t.Fatalf("NewMempool: %v", err)
	}
	txBytes := mustBenchmarkSignedTransferTx(
		t,
		state.Utxos,
		[]consensus.Outpoint{outpoints[0]},
		90,
		1,
		1,
		fromKey,
		fromAddress,
		toAddress,
	)
	if err := mp.AddTx(txBytes); err != nil {
		t.Fatalf("AddTx: %v", err)
	}
	assertChainStateUnchanged(t, before, snapshotChainState(t, state))
}

func TestMempoolRelayMetadataPreservesBaseChainState(t *testing.T) {
	fromKey := mustBenchmarkNodeMLDSA87Keypair(t)
	toKey := mustBenchmarkNodeMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	toAddress := consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes())
	state, outpoints := benchmarkSpendableChainState(fromAddress, []uint64{100})
	before := snapshotChainState(t, state)
	mp, err := NewMempool(state, nil, devnetGenesisChainID)
	if err != nil {
		t.Fatalf("NewMempool: %v", err)
	}
	txBytes := mustBenchmarkSignedTransferTx(
		t,
		state.Utxos,
		[]consensus.Outpoint{outpoints[0]},
		90,
		3,
		5,
		fromKey,
		fromAddress,
		toAddress,
	)
	if _, err := mp.RelayMetadata(txBytes); err != nil {
		t.Fatalf("RelayMetadata: %v", err)
	}
	assertChainStateUnchanged(t, before, snapshotChainState(t, state))
}

func BenchmarkMempoolAddTx(b *testing.B) {
	fromKey := mustBenchmarkNodeMLDSA87Keypair(b)
	toKey := mustBenchmarkNodeMLDSA87Keypair(b)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	toAddress := consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes())
	state, outpoints := benchmarkSpendableChainState(fromAddress, []uint64{100})
	txBytes := mustBenchmarkSignedTransferTx(
		b,
		state.Utxos,
		[]consensus.Outpoint{outpoints[0]},
		90,
		1,
		1,
		fromKey,
		fromAddress,
		toAddress,
	)
	b.ReportAllocs()
	b.SetBytes(int64(len(txBytes)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		mp, err := NewMempool(state, nil, devnetGenesisChainID)
		if err != nil {
			b.Fatalf("NewMempool: %v", err)
		}
		b.StartTimer()
		if err := mp.AddTx(txBytes); err != nil {
			b.Fatalf("AddTx: %v", err)
		}
	}
}

func BenchmarkMempoolRelayMetadata(b *testing.B) {
	fromKey := mustBenchmarkNodeMLDSA87Keypair(b)
	toKey := mustBenchmarkNodeMLDSA87Keypair(b)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	toAddress := consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes())
	state, outpoints := benchmarkSpendableChainState(fromAddress, []uint64{100})
	mp, err := NewMempool(state, nil, devnetGenesisChainID)
	if err != nil {
		b.Fatalf("NewMempool: %v", err)
	}
	txBytes := mustBenchmarkSignedTransferTx(
		b,
		state.Utxos,
		[]consensus.Outpoint{outpoints[0]},
		90,
		3,
		5,
		fromKey,
		fromAddress,
		toAddress,
	)
	b.ReportAllocs()
	b.SetBytes(int64(len(txBytes)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := mp.RelayMetadata(txBytes); err != nil {
			b.Fatalf("RelayMetadata: %v", err)
		}
	}
}

func BenchmarkMinerBuildContext(b *testing.B) {
	fromKey := mustBenchmarkNodeMLDSA87Keypair(b)
	toKey := mustBenchmarkNodeMLDSA87Keypair(b)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	toAddress := consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes())
	state, outpoints := benchmarkSpendableChainState(fromAddress, []uint64{100})
	blockStore, err := OpenBlockStore(BlockStorePath(b.TempDir()))
	if err != nil {
		b.Fatalf("OpenBlockStore: %v", err)
	}
	syncEngine, err := NewSyncEngine(state, blockStore, DefaultSyncConfig(nil, [32]byte{}, ""))
	if err != nil {
		b.Fatalf("NewSyncEngine: %v", err)
	}
	miner, err := NewMiner(state, blockStore, syncEngine, DefaultMinerConfig())
	if err != nil {
		b.Fatalf("NewMiner: %v", err)
	}
	txBytes := mustBenchmarkSignedTransferTx(
		b,
		state.Utxos,
		[]consensus.Outpoint{outpoints[0]},
		90,
		1,
		1,
		fromKey,
		fromAddress,
		toAddress,
	)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := miner.buildContext([][]byte{txBytes}); err != nil {
			b.Fatalf("buildContext: %v", err)
		}
	}
}

func BenchmarkCloneChainState(b *testing.B) {
	fromKey := mustBenchmarkNodeMLDSA87Keypair(b)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	state, _ := benchmarkSpendableChainState(fromAddress, []uint64{
		100, 101, 102, 103, 104, 105, 106, 107,
		108, 109, 110, 111, 112, 113, 114, 115,
		116, 117, 118, 119, 120, 121, 122, 123,
		124, 125, 126, 127, 128, 129, 130, 131,
	})
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if clone := cloneChainState(state); clone == nil {
			b.Fatal("cloneChainState returned nil")
		}
	}
}

func BenchmarkCopyUtxoSet(b *testing.B) {
	fromKey := mustBenchmarkNodeMLDSA87Keypair(b)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	state, _ := benchmarkSpendableChainState(fromAddress, []uint64{
		100, 101, 102, 103, 104, 105, 106, 107,
		108, 109, 110, 111, 112, 113, 114, 115,
		116, 117, 118, 119, 120, 121, 122, 123,
		124, 125, 126, 127, 128, 129, 130, 131,
	})
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if cloned := copyUtxoSet(state.Utxos); len(cloned) != len(state.Utxos) {
			b.Fatalf("copyUtxoSet len=%d want=%d", len(cloned), len(state.Utxos))
		}
	}
}

func BenchmarkConnectBlockWithCoreExtProfilesAndSuiteContext(b *testing.B) {
	baseState, blockBytes, prevTimestamps := benchmarkConnectBlockFixture(b)
	b.ReportAllocs()
	b.SetBytes(int64(len(blockBytes)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		state := cloneChainState(baseState)
		b.StartTimer()
		if _, err := state.ConnectBlockWithCoreExtProfilesAndSuiteContext(
			blockBytes,
			nil,
			prevTimestamps,
			devnetGenesisChainID,
			consensus.EmptyCoreExtProfileProvider(),
			nil,
			nil,
		); err != nil {
			b.Fatalf("ConnectBlockWithCoreExtProfilesAndSuiteContext: %v", err)
		}
	}
}

func BenchmarkConnectBlockParallelSigsWithSuiteContext(b *testing.B) {
	baseState, blockBytes, prevTimestamps := benchmarkConnectBlockFixture(b)
	b.ReportAllocs()
	b.SetBytes(int64(len(blockBytes)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		state := cloneChainState(baseState)
		b.StartTimer()
		if _, err := state.ConnectBlockParallelSigsWithSuiteContext(
			blockBytes,
			nil,
			prevTimestamps,
			devnetGenesisChainID,
			consensus.EmptyCoreExtProfileProvider(),
			nil,
			nil,
			2,
		); err != nil {
			b.Fatalf("ConnectBlockParallelSigsWithSuiteContext: %v", err)
		}
	}
}
