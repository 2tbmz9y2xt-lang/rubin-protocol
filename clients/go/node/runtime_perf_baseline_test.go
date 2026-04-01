package node

import (
	"context"
	"fmt"
	"path/filepath"
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

func TestMempoolAddTxDaCommitPreservesBaseChainState(t *testing.T) {
	fromKey := mustBenchmarkNodeMLDSA87Keypair(t)
	toKey := mustBenchmarkNodeMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	toAddress := consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes())
	state, outpoints := benchmarkSpendableChainState(fromAddress, []uint64{100})
	before := snapshotChainState(t, state)
	mp, err := NewMempoolWithConfig(state, nil, devnetGenesisChainID, MempoolConfig{
		PolicyDaSurchargePerByte: 1,
	})
	if err != nil {
		t.Fatalf("NewMempoolWithConfig: %v", err)
	}
	txBytes := mustBuildSignedDaCommitTx(
		t,
		state.Utxos,
		outpoints[0],
		80,
		10,
		1,
		fromKey,
		toAddress,
		[]byte("0123456789"),
	)
	if err := mp.AddTx(txBytes); err != nil {
		t.Fatalf("AddTx(da): %v", err)
	}
	assertChainStateUnchanged(t, before, snapshotChainState(t, state))
}

func TestMempoolAddTxCoreExtPreservesBaseChainState(t *testing.T) {
	fromKey := mustBenchmarkNodeMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	state, outpoints := benchmarkSpendableChainState(fromAddress, []uint64{100})
	before := snapshotChainState(t, state)
	mp, err := NewMempoolWithConfig(state, nil, devnetGenesisChainID, MempoolConfig{
		PolicyRejectCoreExtPreActivation: true,
		CoreExtProfiles:                  testCoreExtProfiles{activeByExtID: map[uint16]bool{7: true}},
	})
	if err != nil {
		t.Fatalf("NewMempoolWithConfig: %v", err)
	}
	txBytes := mustBuildSignedCoreExtOutputTx(
		t,
		state.Utxos,
		outpoints[0],
		90,
		1,
		1,
		fromKey,
		fromAddress,
		7,
	)
	if err := mp.AddTx(txBytes); err != nil {
		t.Fatalf("AddTx(core_ext): %v", err)
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
		b.StopTimer()
		mp, err := NewMempool(state, nil, devnetGenesisChainID)
		if err != nil {
			b.Fatalf("NewMempool: %v", err)
		}
		b.StartTimer()
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

func benchmarkLargeChainState(tb testing.TB, count int) *ChainState {
	tb.Helper()
	fromAddress := testP2PKCovenantData(0x41)
	values := make([]uint64, count)
	for i := range values {
		values[i] = 100 + uint64(i)
	}
	state, _ := benchmarkSpendableChainState(fromAddress, values)
	state.HasTip = true
	state.Height = 100
	state.AlreadyGenerated = 50_000
	state.TipHash[0] = 0x44
	return state
}

func benchmarkRecoveryReplayFixture(tb testing.TB, blocks int) (*BlockStore, SyncConfig, *ChainState, *ChainState) {
	tb.Helper()
	dir := tb.TempDir()
	chainStatePath := ChainStatePath(dir)
	store, err := OpenBlockStore(BlockStorePath(dir))
	if err != nil {
		tb.Fatalf("OpenBlockStore: %v", err)
	}

	target := consensus.POW_LIMIT
	cfg := DefaultSyncConfig(&target, devnetGenesisChainID, chainStatePath)
	liveState := NewChainState()
	engine, err := NewSyncEngine(liveState, store, cfg)
	if err != nil {
		tb.Fatalf("NewSyncEngine: %v", err)
	}
	if _, err := engine.ApplyBlock(devnetGenesisBlockBytes, nil); err != nil {
		tb.Fatalf("ApplyBlock(genesis): %v", err)
	}
	genesisState := cloneChainState(liveState)

	genesisParsed, err := consensus.ParseBlockBytes(devnetGenesisBlockBytes)
	if err != nil {
		tb.Fatalf("ParseBlockBytes(genesis): %v", err)
	}

	prevHash := devnetGenesisBlockHash
	prevTimestamps := []uint64{genesisParsed.Header.Timestamp}
	now := genesisParsed.Header.Timestamp + 60
	for height := uint64(1); height <= uint64(blocks); height++ {
		subsidy := consensus.BlockSubsidy(height, liveState.AlreadyGenerated)
		timestamp := chooseValidTimestamp(height, prevTimestamps, now)
		block := benchmarkBuildSingleTxBlock(
			tb,
			prevHash,
			target,
			timestamp,
			benchmarkCoinbaseWithWitnessCommitmentAndP2PKValueAtHeight(tb, height, subsidy),
		)
		summary, err := engine.ApplyBlock(block, nil)
		if err != nil {
			tb.Fatalf("ApplyBlock(%d): %v", height, err)
		}
		prevHash = summary.BlockHash
		prevTimestamps = append(prevTimestamps, timestamp)
		if len(prevTimestamps) > 11 {
			prevTimestamps = append([]uint64(nil), prevTimestamps[len(prevTimestamps)-11:]...)
		}
		now = timestamp + 60
	}

	return store, cfg, genesisState, cloneChainState(liveState)
}

func benchmarkBuildSingleTxBlock(tb testing.TB, prevHash [32]byte, target [32]byte, timestamp uint64, tx []byte) []byte {
	tb.Helper()
	_, txid, _, _, err := consensus.ParseTx(tx)
	if err != nil {
		tb.Fatalf("parse tx: %v", err)
	}
	root, err := consensus.MerkleRootTxids([][32]byte{txid})
	if err != nil {
		tb.Fatalf("merkle root: %v", err)
	}
	header := make([]byte, 0, consensus.BLOCK_HEADER_BYTES)
	header = consensus.AppendU32le(header, 1)
	header = append(header, prevHash[:]...)
	header = append(header, root[:]...)
	header = consensus.AppendU64le(header, timestamp)
	header = append(header, target[:]...)
	header = consensus.AppendU64le(header, 7)

	block := make([]byte, 0, len(header)+len(tx)+4)
	block = append(block, header...)
	block = consensus.AppendCompactSize(block, 1)
	block = append(block, tx...)
	return block
}

func benchmarkCoinbaseWithWitnessCommitmentAndP2PKValueAtHeight(tb testing.TB, height uint64, value uint64) []byte {
	tb.Helper()
	wtxids := [][32]byte{{}}
	wroot, err := consensus.WitnessMerkleRootWtxids(wtxids)
	if err != nil {
		tb.Fatalf("witness merkle root: %v", err)
	}
	commitment := consensus.WitnessCommitmentHash(wroot)
	return coinbaseTxWithOutputs(uint32(height), []testOutput{
		{value: value, covenantType: consensus.COV_TYPE_P2PK, covenantData: testP2PKCovenantData(0x11)},
		{value: 0, covenantType: consensus.COV_TYPE_ANCHOR, covenantData: commitment[:]},
	})
}

func BenchmarkChainStateSave(b *testing.B) {
	for _, count := range []int{4096, 8192} {
		b.Run(fmt.Sprintf("utxos_%d", count), func(b *testing.B) {
			state := benchmarkLargeChainState(b, count)
			path := filepath.Join(b.TempDir(), chainStateFileName)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if err := state.Save(path); err != nil {
					b.Fatalf("Save: %v", err)
				}
			}
		})
	}
}

func BenchmarkChainStateLoad(b *testing.B) {
	for _, count := range []int{4096, 8192} {
		b.Run(fmt.Sprintf("utxos_%d", count), func(b *testing.B) {
			state := benchmarkLargeChainState(b, count)
			path := filepath.Join(b.TempDir(), chainStateFileName)
			if err := state.Save(path); err != nil {
				b.Fatalf("Save: %v", err)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				loaded, err := LoadChainState(path)
				if err != nil {
					b.Fatalf("LoadChainState: %v", err)
				}
				if loaded == nil || len(loaded.Utxos) != len(state.Utxos) {
					b.Fatalf("LoadChainState len=%d want=%d", len(loaded.Utxos), len(state.Utxos))
				}
			}
		})
	}
}

func BenchmarkReconcileChainState(b *testing.B) {
	store, cfg, genesisState, canonicalState := benchmarkRecoveryReplayFixture(b, 32)
	b.Run("noop_tip_32_blocks", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			b.StopTimer()
			state := cloneChainState(canonicalState)
			b.StartTimer()
			changed, err := ReconcileChainStateWithBlockStore(state, store, cfg)
			if err != nil {
				b.Fatalf("ReconcileChainStateWithBlockStore: %v", err)
			}
			if changed {
				b.Fatal("noop reconcile unexpectedly changed state")
			}
		}
	})
	b.Run("replay_32_blocks", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			b.StopTimer()
			state := cloneChainState(genesisState)
			b.StartTimer()
			changed, err := ReconcileChainStateWithBlockStore(state, store, cfg)
			if err != nil {
				b.Fatalf("ReconcileChainStateWithBlockStore: %v", err)
			}
			if !changed {
				b.Fatal("replay reconcile unexpectedly reported no change")
			}
		}
	})
}
