package node

import (
	"bytes"
	"crypto/sha3"
	"encoding/hex"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

func TestDefaultSyncConfigAndEngineInit_Defaults(t *testing.T) {
	st := NewChainState()
	var chainID [32]byte
	cfg := DefaultSyncConfig(nil, chainID, "x.json")
	if cfg.HeaderBatchLimit == 0 || cfg.IBDLagSeconds == 0 {
		t.Fatalf("expected non-zero defaults: %#v", cfg)
	}
	if cfg.IBDLagSeconds != defaultIBDLagSeconds {
		t.Fatalf("ibd_lag_seconds=%d, want %d", cfg.IBDLagSeconds, defaultIBDLagSeconds)
	}
	if cfg.ParallelValidationMode != "off" {
		t.Fatalf("parallel_validation_mode=%q, want off", cfg.ParallelValidationMode)
	}

	cfg.HeaderBatchLimit = 0
	cfg.IBDLagSeconds = 0
	engine, err := NewSyncEngine(st, nil, cfg)
	if err != nil {
		t.Fatalf("NewSyncEngine: %v", err)
	}
	if engine.cfg.HeaderBatchLimit != 512 {
		t.Fatalf("header_batch_limit=%d, want 512", engine.cfg.HeaderBatchLimit)
	}
	if engine.cfg.IBDLagSeconds != defaultIBDLagSeconds {
		t.Fatalf("ibd_lag_seconds=%d, want %d", engine.cfg.IBDLagSeconds, defaultIBDLagSeconds)
	}
}

func TestNewSyncEngine_ParallelValidationModeParse(t *testing.T) {
	st := NewChainState()
	cfg := DefaultSyncConfig(nil, [32]byte{}, "")
	cfg.ParallelValidationMode = "shadow"
	if _, err := NewSyncEngine(st, nil, cfg); err != nil {
		t.Fatalf("expected shadow mode ok: %v", err)
	}

	cfg.ParallelValidationMode = "on"
	if _, err := NewSyncEngine(st, nil, cfg); err != nil {
		t.Fatalf("expected on mode ok: %v", err)
	}

	cfg.ParallelValidationMode = "nope"
	if _, err := NewSyncEngine(st, nil, cfg); err == nil {
		t.Fatal("expected error for invalid mode")
	}
}

func TestPVShadowMismatch_SequentialTruthPreserved(t *testing.T) {
	target := consensus.POW_LIMIT
	cfg := DefaultSyncConfig(&target, devnetGenesisChainID, "")
	cfg.ParallelValidationMode = "shadow"
	cfg.PVShadowMaxSamples = 2

	signer := mustNodeMLDSA87Keypair(t)
	keyID := sha3.Sum256(signer.PubkeyBytes())
	fromAddr, err := ParseMineAddress(hex.EncodeToString(keyID[:]))
	if err != nil {
		t.Fatalf("ParseMineAddress: %v", err)
	}
	st, ops := testSpendableChainState(fromAddr, []uint64{100})

	engine, err := NewSyncEngine(st, nil, cfg)
	if err != nil {
		t.Fatalf("new sync engine: %v", err)
	}
	var stderr bytes.Buffer
	engine.SetStderr(&stderr)
	inOp := ops[0]

	// tx1: valid structure, but corrupt the signature so sequential path returns TX_ERR_SIG_INVALID.
	changeAddress := append([]byte(nil), fromAddr...)
	toAddress := append([]byte(nil), fromAddr...)
	tx1 := mustBuildSignedTransferTxForSyncTest(t, engine.chainState.Utxos, []consensus.Outpoint{inOp}, 1, 0, 1, signer, changeAddress, toAddress)
	parsed1, _, wtxid1, _, err := consensus.ParseTx(tx1)
	if err != nil {
		t.Fatalf("ParseTx(tx1): %v", err)
	}
	// Flip one byte in the first witness signature (P2PK => witness[0]).
	if len(parsed1.Witness) == 0 || len(parsed1.Witness[0].Signature) == 0 {
		t.Fatal("expected witness signature in tx1")
	}
	parsed1.Witness[0].Signature[0] ^= 0xFF
	tx1, err = consensus.MarshalTx(parsed1)
	if err != nil {
		t.Fatalf("MarshalTx(tx1): %v", err)
	}
	// Recompute wtxid after corruption (coinbase witness commitment must match).
	_, _, wtxid1, _, err = consensus.ParseTx(tx1)
	if err != nil {
		t.Fatalf("ParseTx(tx1 after corrupt): %v", err)
	}

	// tx2: missing UTXO, so parallel pre-check may return TX_ERR_MISSING_UTXO before flushing sigs.
	tx2obj := &consensus.Tx{
		Version:  1,
		TxKind:   0x00,
		TxNonce:  2,
		Inputs:   []consensus.TxInput{{PrevTxid: [32]byte{0x99}, PrevVout: 0, Sequence: 0}},
		Outputs:  []consensus.TxOutput{{Value: 1, CovenantType: consensus.COV_TYPE_P2PK, CovenantData: changeAddress}},
		Locktime: 0,
	}
	tx2, err := consensus.MarshalTx(tx2obj)
	if err != nil {
		t.Fatalf("MarshalTx(tx2): %v", err)
	}
	_, _, wtxid2, _, err := consensus.ParseTx(tx2)
	if err != nil {
		t.Fatalf("ParseTx(tx2): %v", err)
	}

	height := st.Height + 1
	subsidy := consensus.BlockSubsidy(height, st.AlreadyGenerated)
	coinbase := coinbaseWithWitnessCommitmentAndP2PKValueForWtxids(t, height, subsidy, [][32]byte{{}, wtxid1, wtxid2})
	block := buildMultiTxBlock(t, st.TipHash, target, 2, coinbase, tx1, tx2)

	_, err = engine.ApplyBlock(block, nil)
	if err == nil || !strings.Contains(err.Error(), string(consensus.TX_ERR_SIG_INVALID)) {
		t.Fatalf("expected sequential truth error %s, got %v", consensus.TX_ERR_SIG_INVALID, err)
	}

	mismatches, samples := engine.PVShadowStats()
	if mismatches == 0 || len(samples) == 0 {
		t.Fatalf("expected pv shadow mismatch recorded, got mismatches=%d samples=%v", mismatches, samples)
	}
	if !strings.Contains(stderr.String(), "pv_shadow: mismatch") {
		t.Fatalf("expected pv_shadow diagnostic on stderr, got: %q", stderr.String())
	}
}

func TestPVShadowStats_NilEngine(t *testing.T) {
	var nilEngine *SyncEngine
	m, s := nilEngine.PVShadowStats()
	if m != 0 || s != nil {
		t.Fatalf("expected zero stats for nil engine, got mismatches=%d samples=%v", m, s)
	}
}

func TestPVShadowMismatch_IsBounded(t *testing.T) {
	st := NewChainState()
	cfg := DefaultSyncConfig(nil, [32]byte{}, "")
	cfg.ParallelValidationMode = "shadow"
	cfg.PVShadowMaxSamples = 1
	engine, err := NewSyncEngine(st, nil, cfg)
	if err != nil {
		t.Fatalf("NewSyncEngine: %v", err)
	}

	engine.recordPVShadowMismatch("a")
	engine.recordPVShadowMismatch("b")
	m, samples := engine.PVShadowStats()
	if m != 2 {
		t.Fatalf("mismatches=%d, want 2", m)
	}
	if len(samples) != 1 || samples[0] != "a" {
		t.Fatalf("samples=%v, want [a]", samples)
	}
}

func TestPVShadow_NoMismatchOnValidBlock(t *testing.T) {
	target := consensus.POW_LIMIT
	cfg := DefaultSyncConfig(&target, devnetGenesisChainID, "")
	cfg.ParallelValidationMode = "shadow"
	cfg.PVShadowMaxSamples = 3

	signer := mustNodeMLDSA87Keypair(t)
	keyID := sha3.Sum256(signer.PubkeyBytes())
	fromAddr, err := ParseMineAddress(hex.EncodeToString(keyID[:]))
	if err != nil {
		t.Fatalf("ParseMineAddress: %v", err)
	}
	st, ops := testSpendableChainState(fromAddr, []uint64{100})
	engine, err := NewSyncEngine(st, nil, cfg)
	if err != nil {
		t.Fatalf("NewSyncEngine: %v", err)
	}
	var stderr bytes.Buffer
	engine.SetStderr(&stderr)

	height := st.Height + 1
	tx1 := mustBuildSignedTransferTxForSyncTest(t, st.Utxos, []consensus.Outpoint{ops[0]}, 1, 0, 1, signer, fromAddr, fromAddr)
	_, _, wtxid1, _, err := consensus.ParseTx(tx1)
	if err != nil {
		t.Fatalf("ParseTx(tx1): %v", err)
	}
	subsidy := consensus.BlockSubsidy(height, st.AlreadyGenerated)
	coinbase := coinbaseWithWitnessCommitmentAndP2PKValueForWtxids(t, height, subsidy, [][32]byte{{}, wtxid1})
	block := buildMultiTxBlock(t, st.TipHash, target, 2, coinbase, tx1)

	if _, err := engine.ApplyBlock(block, nil); err != nil {
		t.Fatalf("ApplyBlock(valid): %v", err)
	}
	m, samples := engine.PVShadowStats()
	if m != 0 || len(samples) != 0 {
		t.Fatalf("expected no mismatches on valid block, got mismatches=%d samples=%v stderr=%q", m, samples, stderr.String())
	}
}

func TestNewSyncEngine_NilChainState(t *testing.T) {
	_, err := NewSyncEngine(nil, nil, SyncConfig{})
	if err == nil {
		t.Fatalf("expected error")
	}
}

func TestNewSyncEngine_MainnetGuard(t *testing.T) {
	st := NewChainState()

	cfg := DefaultSyncConfig(nil, [32]byte{}, "")
	cfg.Network = "mainnet"
	if _, err := NewSyncEngine(st, nil, cfg); err == nil {
		t.Fatalf("expected error for mainnet without explicit expected_target")
	}

	allFF := consensus.POW_LIMIT
	cfg = DefaultSyncConfig(&allFF, [32]byte{}, "")
	cfg.Network = "mainnet"
	if _, err := NewSyncEngine(st, nil, cfg); err == nil {
		t.Fatalf("expected error for mainnet with devnet POW_LIMIT")
	}

	okTarget := consensus.POW_LIMIT
	okTarget[0] = 0x7f
	cfg = DefaultSyncConfig(&okTarget, [32]byte{}, "")
	cfg.Network = "mainnet"
	if _, err := NewSyncEngine(st, nil, cfg); err != nil {
		t.Fatalf("expected success for mainnet with explicit non-devnet target: %v", err)
	}
}

func TestSyncEngine_HeaderSyncRequest(t *testing.T) {
	st := NewChainState()
	engine, err := NewSyncEngine(st, nil, DefaultSyncConfig(nil, [32]byte{}, ""))
	if err != nil {
		t.Fatalf("NewSyncEngine: %v", err)
	}

	r := engine.HeaderSyncRequest()
	if r.HasFrom {
		t.Fatalf("expected HasFrom=false when no tip")
	}
	if r.Limit != engine.cfg.HeaderBatchLimit {
		t.Fatalf("limit=%d, want %d", r.Limit, engine.cfg.HeaderBatchLimit)
	}

	st.HasTip = true
	st.TipHash = mustHash32Hex(t, "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc")
	r = engine.HeaderSyncRequest()
	if !r.HasFrom || r.FromHash != st.TipHash {
		t.Fatalf("unexpected request: %#v", r)
	}
}

func TestSyncEngine_RecordBestKnownHeight(t *testing.T) {
	st := NewChainState()
	engine, err := NewSyncEngine(st, nil, DefaultSyncConfig(nil, [32]byte{}, ""))
	if err != nil {
		t.Fatalf("NewSyncEngine: %v", err)
	}
	if got := engine.BestKnownHeight(); got != 0 {
		t.Fatalf("best_known=%d, want 0", got)
	}

	engine.RecordBestKnownHeight(7)
	engine.RecordBestKnownHeight(6)
	engine.RecordBestKnownHeight(9)
	if got := engine.BestKnownHeight(); got != 9 {
		t.Fatalf("best_known=%d, want 9", got)
	}

	var nilEngine *SyncEngine
	nilEngine.RecordBestKnownHeight(10)
	if got := nilEngine.BestKnownHeight(); got != 0 {
		t.Fatalf("nil best_known=%d, want 0", got)
	}
}

func TestSyncEngine_IsInIBDEdgeCases(t *testing.T) {
	var nilEngine *SyncEngine
	if !nilEngine.IsInIBD(0) {
		t.Fatalf("expected IBD for nil engine")
	}

	st := NewChainState()
	engine, err := NewSyncEngine(st, nil, DefaultSyncConfig(nil, [32]byte{}, ""))
	if err != nil {
		t.Fatalf("NewSyncEngine: %v", err)
	}
	st.HasTip = true
	engine.tipTimestamp = 100
	engine.cfg.IBDLagSeconds = 10
	if !engine.IsInIBD(99) {
		t.Fatalf("expected IBD when now < tip timestamp")
	}
}

func TestSyncEngineIBDLogic(t *testing.T) {
	st := NewChainState()
	cfg := DefaultSyncConfig(nil, [32]byte{}, "")
	engine, err := NewSyncEngine(st, nil, cfg)
	if err != nil {
		t.Fatalf("new sync engine: %v", err)
	}
	if !engine.IsInIBD(1_000) {
		t.Fatalf("expected IBD when no tip")
	}

	st.HasTip = true
	st.Height = 10
	engine.tipTimestamp = 1_000
	engine.cfg.IBDLagSeconds = 100
	if !engine.IsInIBD(1_200) {
		t.Fatalf("expected IBD when lag exceeds threshold")
	}
	if engine.IsInIBD(1_050) {
		t.Fatalf("did not expect IBD when lag below threshold")
	}
}

func TestSyncEngineApplyBlockPersistsChainstateAndStore(t *testing.T) {
	dir := t.TempDir()
	chainStatePath := ChainStatePath(dir)
	store, err := OpenBlockStore(BlockStorePath(dir))
	if err != nil {
		t.Fatalf("open blockstore: %v", err)
	}
	st := NewChainState()
	target := consensus.POW_LIMIT
	engine, err := NewSyncEngine(st, store, DefaultSyncConfig(&target, devnetGenesisChainID, chainStatePath))
	if err != nil {
		t.Fatalf("new sync engine: %v", err)
	}

	if _, err := engine.ApplyBlock(devnetGenesisBlockBytes, nil); err != nil {
		t.Fatalf("apply genesis block: %v", err)
	}

	block1Coinbase := coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 1, 1)
	block1 := buildSingleTxBlock(t, devnetGenesisBlockHash, target, 2, block1Coinbase)

	summary, err := engine.ApplyBlock(block1, nil)
	if err != nil {
		t.Fatalf("apply block: %v", err)
	}
	if summary.BlockHeight != 1 {
		t.Fatalf("block height=%d, want 1", summary.BlockHeight)
	}
	if _, err := os.Stat(chainStatePath); err != nil {
		t.Fatalf("chainstate file not persisted: %v", err)
	}

	loaded, err := LoadChainState(chainStatePath)
	if err != nil {
		t.Fatalf("reload chainstate: %v", err)
	}
	if !loaded.HasTip || loaded.Height != 1 {
		t.Fatalf("unexpected persisted chainstate: has_tip=%v height=%d", loaded.HasTip, loaded.Height)
	}

	height, _, ok, err := store.Tip()
	if err != nil {
		t.Fatalf("blockstore tip: %v", err)
	}
	if !ok || height != 1 {
		t.Fatalf("unexpected blockstore tip: ok=%v height=%d", ok, height)
	}
}

func TestSyncEngineApplyBlockPutUndoFailureRollsBackCanonicalTip(t *testing.T) {
	dir := t.TempDir()
	chainStatePath := ChainStatePath(dir)
	store, err := OpenBlockStore(BlockStorePath(dir))
	if err != nil {
		t.Fatalf("open blockstore: %v", err)
	}
	st := NewChainState()
	target := consensus.POW_LIMIT
	engine, err := NewSyncEngine(st, store, DefaultSyncConfig(&target, devnetGenesisChainID, chainStatePath))
	if err != nil {
		t.Fatalf("new sync engine: %v", err)
	}

	prevWrite := writeFileAtomicFn
	t.Cleanup(func() { writeFileAtomicFn = prevWrite })
	undoPath := filepath.Join(store.undoDir, hex.EncodeToString(devnetGenesisBlockHash[:])+".json")
	writeFileAtomicFn = func(path string, data []byte, mode os.FileMode) error {
		if path == undoPath {
			return os.ErrPermission
		}
		return prevWrite(path, data, mode)
	}

	if _, err := engine.ApplyBlock(devnetGenesisBlockBytes, nil); err == nil {
		t.Fatalf("expected apply block failure when undo write fails")
	}
	if st.HasTip {
		t.Fatalf("chainstate tip should be rolled back")
	}
	if _, _, ok, err := store.Tip(); err != nil {
		t.Fatalf("blockstore tip: %v", err)
	} else if ok {
		t.Fatalf("blockstore canonical tip should be rolled back")
	}
	if _, err := os.Stat(undoPath); !os.IsNotExist(err) {
		t.Fatalf("undo file should not exist after rollback, err=%v", err)
	}
}

func TestChainStateDisconnectBlockRestoresSpentUTXOState(t *testing.T) {
	sourceKP, err := consensus.NewMLDSA87Keypair()
	if err != nil {
		t.Fatalf("NewMLDSA87Keypair(source): %v", err)
	}
	defer sourceKP.Close()

	destKP, err := consensus.NewMLDSA87Keypair()
	if err != nil {
		t.Fatalf("NewMLDSA87Keypair(dest): %v", err)
	}
	defer destKP.Close()

	sourceAddress := consensus.P2PKCovenantDataForPubkey(sourceKP.PubkeyBytes())
	destAddress := consensus.P2PKCovenantDataForPubkey(destKP.PubkeyBytes())

	st := NewChainState()
	st.HasTip = true
	st.Height = 100
	st.TipHash = mustHash32Hex(t, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	st.AlreadyGenerated = 123_456

	sourceOutpoint := consensus.Outpoint{
		Txid: mustHash32Hex(t, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
		Vout: 0,
	}
	st.Utxos[sourceOutpoint] = consensus.UtxoEntry{
		Value:             1_000,
		CovenantType:      consensus.COV_TYPE_P2PK,
		CovenantData:      append([]byte(nil), sourceAddress...),
		CreationHeight:    1,
		CreatedByCoinbase: true,
	}

	before, err := stateToDisk(st)
	if err != nil {
		t.Fatalf("stateToDisk before: %v", err)
	}
	prevState, err := chainStateFromDisk(before)
	if err != nil {
		t.Fatalf("chainStateFromDisk before: %v", err)
	}

	spendTx := mustBuildSignedTransferTxForSyncTest(
		t,
		st.Utxos,
		[]consensus.Outpoint{sourceOutpoint},
		700,
		50,
		1,
		sourceKP,
		sourceAddress,
		destAddress,
	)
	_, _, spendWTxID, _, err := consensus.ParseTx(spendTx)
	if err != nil {
		t.Fatalf("ParseTx(spend): %v", err)
	}
	subsidy := consensus.BlockSubsidy(101, st.AlreadyGenerated)
	coinbase := coinbaseWithWitnessCommitmentAndP2PKValueForWtxids(t, 101, subsidy+50, [][32]byte{{}, spendWTxID})
	target := consensus.POW_LIMIT
	block := buildMultiTxBlock(t, st.TipHash, target, 2, coinbase, spendTx)

	summary, err := st.ConnectBlock(block, &target, nil, devnetGenesisChainID)
	if err != nil {
		t.Fatalf("ConnectBlock: %v", err)
	}
	pb, err := consensus.ParseBlockBytes(block)
	if err != nil {
		t.Fatalf("ParseBlockBytes: %v", err)
	}
	undo, err := buildBlockUndo(prevState, pb, summary.BlockHeight)
	if err != nil {
		t.Fatalf("buildBlockUndo: %v", err)
	}

	disconnectSummary, err := st.DisconnectBlock(block, undo)
	if err != nil {
		t.Fatalf("DisconnectBlock: %v", err)
	}
	if !disconnectSummary.HasTip || disconnectSummary.NewHeight != 100 {
		t.Fatalf("unexpected disconnect summary: %+v", disconnectSummary)
	}

	after, err := stateToDisk(st)
	if err != nil {
		t.Fatalf("stateToDisk after: %v", err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("chainstate mismatch after disconnect")
	}
}

func TestSyncEngineDisconnectTipPersistsChainstateAndStore(t *testing.T) {
	dir := t.TempDir()
	chainStatePath := ChainStatePath(dir)
	store, err := OpenBlockStore(BlockStorePath(dir))
	if err != nil {
		t.Fatalf("open blockstore: %v", err)
	}
	st := NewChainState()
	target := consensus.POW_LIMIT
	engine, err := NewSyncEngine(st, store, DefaultSyncConfig(&target, devnetGenesisChainID, chainStatePath))
	if err != nil {
		t.Fatalf("new sync engine: %v", err)
	}

	if _, err := engine.ApplyBlock(devnetGenesisBlockBytes, nil); err != nil {
		t.Fatalf("apply genesis block: %v", err)
	}
	genesisBlock, err := consensus.ParseBlockBytes(devnetGenesisBlockBytes)
	if err != nil {
		t.Fatalf("ParseBlockBytes(genesis): %v", err)
	}

	block1Coinbase := coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 1, 1)
	block1 := buildSingleTxBlock(t, devnetGenesisBlockHash, target, 2, block1Coinbase)
	block1Parsed, err := consensus.ParseBlockBytes(block1)
	if err != nil {
		t.Fatalf("ParseBlockBytes(block1): %v", err)
	}
	block1Hash, err := consensus.BlockHash(block1Parsed.HeaderBytes)
	if err != nil {
		t.Fatalf("BlockHash(block1): %v", err)
	}
	if _, err := engine.ApplyBlock(block1, nil); err != nil {
		t.Fatalf("apply block1: %v", err)
	}

	summary, err := engine.DisconnectTip()
	if err != nil {
		t.Fatalf("DisconnectTip: %v", err)
	}
	if !summary.HasTip || summary.NewHeight != 0 || summary.NewTipHash != devnetGenesisBlockHash {
		t.Fatalf("unexpected disconnect summary: %+v", summary)
	}
	if engine.tipTimestamp != genesisBlock.Header.Timestamp {
		t.Fatalf("tip_timestamp=%d, want %d", engine.tipTimestamp, genesisBlock.Header.Timestamp)
	}

	loaded, err := LoadChainState(chainStatePath)
	if err != nil {
		t.Fatalf("LoadChainState: %v", err)
	}
	if !loaded.HasTip || loaded.Height != 0 || loaded.TipHash != devnetGenesisBlockHash {
		t.Fatalf("unexpected persisted chainstate: %+v", loaded)
	}

	tipHeight, tipHash, ok, err := store.Tip()
	if err != nil {
		t.Fatalf("store.Tip: %v", err)
	}
	if !ok || tipHeight != 0 || tipHash != devnetGenesisBlockHash {
		t.Fatalf("unexpected store tip after disconnect: ok=%v height=%d hash=%x", ok, tipHeight, tipHash)
	}
	if _, err := store.GetUndo(block1Hash); err != nil {
		t.Fatalf("GetUndo(block1): %v", err)
	}
}

func TestSyncEngineApplyBlockNoMutationOnFailure(t *testing.T) {
	dir := t.TempDir()
	chainStatePath := filepath.Join(dir, "chainstate.json")
	st := NewChainState()
	st.HasTip = true
	st.Height = 5
	st.TipHash = mustHash32Hex(t, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	st.AlreadyGenerated = 10
	st.Utxos[consensus.Outpoint{
		Txid: mustHash32Hex(t, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
		Vout: 0,
	}] = consensus.UtxoEntry{
		Value:             1,
		CovenantType:      consensus.COV_TYPE_P2PK,
		CovenantData:      testP2PKCovenantData(0x22),
		CreationHeight:    1,
		CreatedByCoinbase: false,
	}

	engine, err := NewSyncEngine(st, nil, DefaultSyncConfig(nil, [32]byte{}, chainStatePath))
	if err != nil {
		t.Fatalf("new sync engine: %v", err)
	}
	before, err := stateToDisk(st)
	if err != nil {
		t.Fatalf("stateToDisk before: %v", err)
	}

	if _, err := engine.ApplyBlock([]byte{0x01, 0x02}, nil); err == nil {
		t.Fatalf("expected apply error")
	}
	after, err := stateToDisk(st)
	if err != nil {
		t.Fatalf("stateToDisk after: %v", err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("chainstate mutated on failed apply")
	}
}

func TestSyncEngineApplyBlock_RollbackOnSaveFailure(t *testing.T) {
	dir := t.TempDir()
	badDir := filepath.Join(dir, "not-a-dir")
	if err := os.WriteFile(badDir, []byte("x"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	chainStatePath := filepath.Join(badDir, "chainstate.json")

	st := &ChainState{
		HasTip:  true,
		Height:  0,
		TipHash: devnetGenesisBlockHash,
		Utxos:   nil,
	}
	target := consensus.POW_LIMIT
	engine, err := NewSyncEngine(st, nil, DefaultSyncConfig(&target, devnetGenesisChainID, chainStatePath))
	if err != nil {
		t.Fatalf("NewSyncEngine: %v", err)
	}
	engine.tipTimestamp = 999
	engine.bestKnownHeight = 123

	before, err := stateToDisk(st)
	if err != nil {
		t.Fatalf("stateToDisk before: %v", err)
	}

	block1Coinbase := coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 1, 1)
	block := buildSingleTxBlock(t, st.TipHash, target, 2, block1Coinbase)

	if _, err := engine.ApplyBlock(block, nil); err == nil {
		t.Fatalf("expected apply error")
	}

	after, err := stateToDisk(st)
	if err != nil {
		t.Fatalf("stateToDisk after: %v", err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("chainstate mutated on rollback path")
	}
	if engine.tipTimestamp != 999 {
		t.Fatalf("tip_timestamp=%d, want 999", engine.tipTimestamp)
	}
	if engine.bestKnownHeight != 123 {
		t.Fatalf("best_known_height=%d, want 123", engine.bestKnownHeight)
	}
}

func TestRestoreChainState_NilDestination(t *testing.T) {
	if err := testRestoreChainState(nil, chainStateDisk{}); err == nil {
		t.Fatalf("expected error")
	}
}

func TestSyncEngineApplyBlockRejectsPostActivationCoreExtSpend(t *testing.T) {
	dir := t.TempDir()
	chainStatePath := ChainStatePath(dir)
	store, err := OpenBlockStore(BlockStorePath(dir))
	if err != nil {
		t.Fatalf("open blockstore: %v", err)
	}
	target := consensus.POW_LIMIT
	profiles, err := consensus.NewStaticCoreExtProfileProvider([]consensus.CoreExtDeploymentProfile{{
		ExtID:            1,
		ActivationHeight: 1,
		AllowedSuites:    map[uint8]struct{}{0x03: {}},
	}})
	if err != nil {
		t.Fatalf("NewStaticCoreExtProfileProvider: %v", err)
	}
	cfg := DefaultSyncConfig(&target, devnetGenesisChainID, chainStatePath)
	cfg.CoreExtProfiles = profiles
	engine, err := NewSyncEngine(NewChainState(), store, cfg)
	if err != nil {
		t.Fatalf("new sync engine: %v", err)
	}

	if _, err := engine.ApplyBlock(devnetGenesisBlockBytes, nil); err != nil {
		t.Fatalf("apply genesis block: %v", err)
	}

	engine.chainState.Utxos[consensus.Outpoint{Txid: [32]byte{0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee}, Vout: 0}] = consensus.UtxoEntry{
		Value:        100,
		CovenantType: consensus.COV_TYPE_CORE_EXT,
		CovenantData: coreExtCovenantData(1, nil),
	}

	spendTx := mustDecodeHexBytes(t, "0100000000010000000000000001eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee000000000000000000015a0000000000000000002101111111111111111111111111111111111111111111111111111111111111111100000000010300010100")
	_, _, spendWTxID, _, err := consensus.ParseTx(spendTx)
	if err != nil {
		t.Fatalf("ParseTx(spend): %v", err)
	}
	subsidy := consensus.BlockSubsidy(1, 0)
	coinbase := coinbaseWithWitnessCommitmentAndP2PKValueForWtxids(t, 1, subsidy, [][32]byte{{}, spendWTxID})
	block := buildMultiTxBlock(t, devnetGenesisBlockHash, target, 2, coinbase, spendTx)

	if _, err := engine.ApplyBlock(block, nil); err == nil || !strings.Contains(err.Error(), string(consensus.TX_ERR_SIG_ALG_INVALID)) {
		t.Fatalf("expected %s, got %v", consensus.TX_ERR_SIG_ALG_INVALID, err)
	}
}

func mustBuildSignedTransferTxForSyncTest(
	t *testing.T,
	utxos map[consensus.Outpoint]consensus.UtxoEntry,
	inputs []consensus.Outpoint,
	amount uint64,
	fee uint64,
	nonce uint64,
	signer *consensus.MLDSA87Keypair,
	changeAddress []byte,
	toAddress []byte,
) []byte {
	t.Helper()

	txInputs := make([]consensus.TxInput, 0, len(inputs))
	var totalIn uint64
	for _, op := range inputs {
		entry, ok := utxos[op]
		if !ok {
			t.Fatalf("missing utxo for %x:%d", op.Txid, op.Vout)
		}
		totalIn += entry.Value
		txInputs = append(txInputs, consensus.TxInput{
			PrevTxid: op.Txid,
			PrevVout: op.Vout,
			Sequence: 0,
		})
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
		t.Fatalf("SignTransaction: %v", err)
	}
	txBytes, err := consensus.MarshalTx(tx)
	if err != nil {
		t.Fatalf("MarshalTx: %v", err)
	}
	return txBytes
}

func buildMultiTxBlock(t *testing.T, prevHash [32]byte, target [32]byte, timestamp uint64, txs ...[]byte) []byte {
	t.Helper()
	txids := make([][32]byte, 0, len(txs))
	totalLen := consensus.BLOCK_HEADER_BYTES + 8
	for _, txBytes := range txs {
		_, txid, _, _, err := consensus.ParseTx(txBytes)
		if err != nil {
			t.Fatalf("ParseTx: %v", err)
		}
		txids = append(txids, txid)
		totalLen += len(txBytes)
	}
	root, err := consensus.MerkleRootTxids(txids)
	if err != nil {
		t.Fatalf("MerkleRootTxids: %v", err)
	}
	header := make([]byte, 0, consensus.BLOCK_HEADER_BYTES)
	header = consensus.AppendU32le(header, 1)
	header = append(header, prevHash[:]...)
	header = append(header, root[:]...)
	header = consensus.AppendU64le(header, timestamp)
	header = append(header, target[:]...)
	header = consensus.AppendU64le(header, 7)

	block := make([]byte, 0, totalLen)
	block = append(block, header...)
	block = consensus.AppendCompactSize(block, uint64(len(txs)))
	for _, txBytes := range txs {
		block = append(block, txBytes...)
	}
	return block
}

func coinbaseWithWitnessCommitmentAndP2PKValueForWtxids(t *testing.T, height uint64, value uint64, wtxids [][32]byte) []byte {
	t.Helper()
	wroot, err := consensus.WitnessMerkleRootWtxids(wtxids)
	if err != nil {
		t.Fatalf("WitnessMerkleRootWtxids: %v", err)
	}
	commitment := consensus.WitnessCommitmentHash(wroot)
	return coinbaseTxWithOutputs(uint32(height), []testOutput{
		{value: value, covenantType: consensus.COV_TYPE_P2PK, covenantData: testP2PKCovenantData(0x11)},
		{value: 0, covenantType: consensus.COV_TYPE_ANCHOR, covenantData: commitment[:]},
	})
}

func mustDecodeHexBytes(t *testing.T, raw string) []byte {
	t.Helper()
	out, err := hex.DecodeString(raw)
	if err != nil {
		t.Fatalf("DecodeString: %v", err)
	}
	return out
}

// TestSyncEngine_isInIBDUnchecked exercises the internal isInIBDUnchecked()
// method used to choose between sequential and parallel signature verification
// during block connection.
func TestSyncEngine_isInIBDUnchecked(t *testing.T) {
	t.Run("nil_engine", func(t *testing.T) {
		var nilEngine *SyncEngine
		if !nilEngine.isInIBDUnchecked() {
			t.Fatal("expected IBD for nil engine")
		}
	})

	t.Run("nil_chainstate", func(t *testing.T) {
		engine := &SyncEngine{}
		if !engine.isInIBDUnchecked() {
			t.Fatal("expected IBD when chainState is nil")
		}
	})

	t.Run("no_tip", func(t *testing.T) {
		st := NewChainState()
		engine, err := NewSyncEngine(st, nil, DefaultSyncConfig(nil, [32]byte{}, ""))
		if err != nil {
			t.Fatalf("NewSyncEngine: %v", err)
		}
		if !engine.isInIBDUnchecked() {
			t.Fatal("expected IBD when no tip")
		}
	})

	t.Run("zero_timestamp", func(t *testing.T) {
		st := NewChainState()
		st.HasTip = true
		engine, err := NewSyncEngine(st, nil, DefaultSyncConfig(nil, [32]byte{}, ""))
		if err != nil {
			t.Fatalf("NewSyncEngine: %v", err)
		}
		engine.tipTimestamp = 0
		if !engine.isInIBDUnchecked() {
			t.Fatal("expected IBD when tipTimestamp == 0")
		}
	})

	t.Run("tip_in_future", func(t *testing.T) {
		st := NewChainState()
		st.HasTip = true
		engine, err := NewSyncEngine(st, nil, DefaultSyncConfig(nil, [32]byte{}, ""))
		if err != nil {
			t.Fatalf("NewSyncEngine: %v", err)
		}
		// Set tip timestamp far in the future.
		engine.tipTimestamp = ^uint64(0)
		engine.cfg.IBDLagSeconds = 100
		if !engine.isInIBDUnchecked() {
			t.Fatal("expected IBD when tip timestamp is in future")
		}
	})

	t.Run("recent_tip_not_ibd", func(t *testing.T) {
		st := NewChainState()
		st.HasTip = true
		engine, err := NewSyncEngine(st, nil, DefaultSyncConfig(nil, [32]byte{}, ""))
		if err != nil {
			t.Fatalf("NewSyncEngine: %v", err)
		}
		// Tip is very recent (1 second ago).
		engine.tipTimestamp = uint64(time.Now().Unix()) - 1
		engine.cfg.IBDLagSeconds = 86400
		if engine.isInIBDUnchecked() {
			t.Fatal("did not expect IBD when tip is recent")
		}
	})

	t.Run("old_tip_is_ibd", func(t *testing.T) {
		st := NewChainState()
		st.HasTip = true
		engine, err := NewSyncEngine(st, nil, DefaultSyncConfig(nil, [32]byte{}, ""))
		if err != nil {
			t.Fatalf("NewSyncEngine: %v", err)
		}
		// Tip is very old.
		engine.tipTimestamp = 1000
		engine.cfg.IBDLagSeconds = 100
		if !engine.isInIBDUnchecked() {
			t.Fatal("expected IBD when tip is very old")
		}
	})
}
