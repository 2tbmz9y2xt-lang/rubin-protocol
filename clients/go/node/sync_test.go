package node

import (
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
	engine, err := NewSyncEngine(st, store, DefaultSyncConfig(&target, [32]byte{}, chainStatePath))
	if err != nil {
		t.Fatalf("new sync engine: %v", err)
	}

	prev := mustHash32Hex(t, "1111111111111111111111111111111111111111111111111111111111111111")
	coinbase := coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 0, 1)
	block := buildSingleTxBlock(t, prev, target, 12345, coinbase)

	summary, err := engine.ApplyBlock(block, nil)
	if err != nil {
		t.Fatalf("apply block: %v", err)
	}
	if summary.BlockHeight != 0 {
		t.Fatalf("block height=%d, want 0", summary.BlockHeight)
	}
	if _, err := os.Stat(chainStatePath); err != nil {
		t.Fatalf("chainstate file not persisted: %v", err)
	}

	loaded, err := LoadChainState(chainStatePath)
	if err != nil {
		t.Fatalf("reload chainstate: %v", err)
	}
	if !loaded.HasTip || loaded.Height != 0 {
		t.Fatalf("unexpected persisted chainstate: has_tip=%v height=%d", loaded.HasTip, loaded.Height)
	}

	height, _, ok, err := store.Tip()
	if err != nil {
		t.Fatalf("blockstore tip: %v", err)
	}
	if !ok || height != 0 {
		t.Fatalf("unexpected blockstore tip: ok=%v height=%d", ok, height)
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

	st := NewChainState()
	target := consensus.POW_LIMIT
	engine, err := NewSyncEngine(st, nil, DefaultSyncConfig(&target, [32]byte{}, chainStatePath))
	if err != nil {
		t.Fatalf("NewSyncEngine: %v", err)
	}
	engine.tipTimestamp = 999
	engine.bestKnownHeight = 123

	before, err := stateToDisk(st)
	if err != nil {
		t.Fatalf("stateToDisk before: %v", err)
	}

	prev := mustHash32Hex(t, "1111111111111111111111111111111111111111111111111111111111111111")
	coinbase := coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 0, 1)
	block := buildSingleTxBlock(t, prev, target, 12345, coinbase)

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
