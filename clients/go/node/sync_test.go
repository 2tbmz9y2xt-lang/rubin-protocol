package node

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"reflect"
	"testing"

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
	if err := restoreChainState(nil, chainStateDisk{}); err == nil {
		t.Fatalf("expected error")
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
