package node

import (
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

func TestCoverageResidual4_SyncHelperBranches(t *testing.T) {
	if got := normalizedNetworkName(""); got != "devnet" {
		t.Fatalf("normalizedNetworkName(empty)=%q", got)
	}
	if got := normalizedNetworkName(" DevNet "); got != "devnet" {
		t.Fatalf("normalizedNetworkName(trimmed)=%q", got)
	}
	if req := (&SyncEngine{chainState: NewChainState(), cfg: SyncConfig{HeaderBatchLimit: 7}}).HeaderSyncRequest(); req.HasFrom || req.Limit != 7 {
		t.Fatalf("HeaderSyncRequest(empty chainstate)=%+v", req)
	}
	if ts, err := testParentTipTimestamp(nil, 0, [32]byte{}); err != nil || ts != 0 {
		t.Fatalf("testParentTipTimestamp genesis=%d err=%v", ts, err)
	}
	if err := testValidateIncomingChainID(0, devnetGenesisChainID); err != nil {
		t.Fatalf("testValidateIncomingChainID(devnet genesis): %v", err)
	}
	if err := testValidateIncomingChainID(1, [32]byte{0x01}); err != nil {
		t.Fatalf("non-genesis chain_id should be ignored: %v", err)
	}
}

func TestCoverageResidual4_SyncRollbackAndPersistHelpers(t *testing.T) {
	engineWithNilState := &SyncEngine{}
	if err := engineWithNilState.rollbackApplyBlock(errors.New("boom"), syncRollbackState{}); err == nil {
		t.Fatalf("expected nil rollback failure")
	}

	engine := &SyncEngine{
		chainState: NewChainState(),
		cfg:        DefaultSyncConfig(nil, devnetGenesisChainID, ""),
	}
	if err := engine.persistAppliedBlock(&ChainStateConnectSummary{}, [32]byte{}, nil, nil, nil); err != nil {
		t.Fatalf("persistAppliedBlock without store/path: %v", err)
	}
	engine.recordAppliedBlock(3, 11)
	engine.recordAppliedBlock(2, 9)
	if engine.tipTimestamp != 9 {
		t.Fatalf("tipTimestamp=%d, want 9", engine.tipTimestamp)
	}
	if engine.bestKnownHeight != 3 {
		t.Fatalf("bestKnownHeight=%d, want 3", engine.bestKnownHeight)
	}
}

func TestCoverageResidual4_SyncStoreErrorBranches(t *testing.T) {
	dir := t.TempDir()
	store, err := OpenBlockStore(BlockStorePath(dir))
	if err != nil {
		t.Fatalf("OpenBlockStore: %v", err)
	}

	if _, err := testParentTipTimestamp(store, 1, [32]byte{0xaa}); err == nil {
		t.Fatalf("expected missing parent header error")
	}

	st := NewChainState()
	target := consensus.POW_LIMIT
	engine, err := NewSyncEngine(st, store, DefaultSyncConfig(&target, devnetGenesisChainID, ""))
	if err != nil {
		t.Fatalf("NewSyncEngine: %v", err)
	}
	if _, err := engine.DisconnectTip(); err == nil {
		t.Fatalf("expected empty blockstore disconnect rejection")
	}

	if _, err := engine.ApplyBlock(devnetGenesisBlockBytes, nil); err != nil {
		t.Fatalf("apply genesis block: %v", err)
	}
	st.Height++
	if _, err := engine.DisconnectTip(); err == nil {
		t.Fatalf("expected tip mismatch rejection")
	}
}

func TestCoverageResidual4_SyncAdditionalErrorBranches(t *testing.T) {
	dir := t.TempDir()
	store, err := OpenBlockStore(BlockStorePath(dir))
	if err != nil {
		t.Fatalf("OpenBlockStore: %v", err)
	}

	st := NewChainState()
	target := consensus.POW_LIMIT
	engine, err := NewSyncEngine(st, store, DefaultSyncConfig(&target, [32]byte{0x01}, filepath.Join(dir, "chainstate.json")))
	if err != nil {
		t.Fatalf("NewSyncEngine: %v", err)
	}
	if _, err := engine.ApplyBlock(devnetGenesisBlockBytes, nil); err == nil {
		t.Fatalf("expected genesis chain_id mismatch")
	}

	store.index.Canonical = []string{"not-hex"}
	if _, err := engine.captureRollbackState(); err == nil {
		t.Fatalf("expected malformed canonical index rejection")
	}

	store.index.Canonical = nil
	engine.cfg.ChainID = devnetGenesisChainID
	if _, err := engine.ApplyBlock(devnetGenesisBlockBytes, nil); err != nil {
		t.Fatalf("apply genesis block: %v", err)
	}
	undoPath := filepath.Join(store.undoDir, hex.EncodeToString(devnetGenesisBlockHash[:])+".json")
	if err := os.Remove(undoPath); err != nil {
		t.Fatalf("Remove(undo): %v", err)
	}
	if _, err := engine.DisconnectTip(); err == nil {
		t.Fatalf("expected missing undo rejection")
	}
}

func TestCoverageResidual4_ReorgAndBlockstoreHelpers(t *testing.T) {
	var nilEngine *SyncEngine
	nilEngine.SetMempool(nil)
	if got := nilEngine.LastReorgDepth(); got != 0 {
		t.Fatalf("LastReorgDepth(nil)=%d, want 0", got)
	}
	if got := nilEngine.ReorgCount(); got != 0 {
		t.Fatalf("ReorgCount(nil)=%d, want 0", got)
	}
	if got := cloneMempoolEntry(nil); len(got.raw) != 0 || len(got.inputs) != 0 || got.fee != 0 || got.weight != 0 || got.size != 0 {
		t.Fatalf("cloneMempoolEntry(nil)=%+v", got)
	}

	engine, store, target := newReorgTestEngine(t)
	if blocks, depth, err := engine.previewDisconnectCanonicalToAncestor(nil, 0); err != nil || blocks != nil || depth != 0 {
		t.Fatalf("previewDisconnectCanonicalToAncestor(nil)=(%v,%d,%v), want (nil,0,nil)", blocks, depth, err)
	}

	var nilStore *BlockStore
	if _, err := nilStore.ChainWork([32]byte{}); err == nil {
		t.Fatalf("expected nil blockstore ChainWork rejection")
	}
	if work, err := store.ChainWork([32]byte{}); err != nil || work.Sign() != 0 {
		t.Fatalf("ChainWork(zero)=(%v,%v), want zero,nil", work, err)
	}

	subsidy1 := consensus.BlockSubsidy(1, 0)
	block1 := buildSingleTxBlock(t, devnetGenesisBlockHash, target, 2, coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 1, subsidy1))
	parsed1, err := consensus.ParseBlockBytes(block1)
	if err != nil {
		t.Fatalf("ParseBlockBytes(block1): %v", err)
	}
	block1Hash, err := consensus.BlockHash(parsed1.HeaderBytes)
	if err != nil {
		t.Fatalf("BlockHash(block1): %v", err)
	}
	if err := store.StoreBlock(block1Hash, parsed1.HeaderBytes, block1); err != nil {
		t.Fatalf("StoreBlock(block1): %v", err)
	}
	headerPath := filepath.Join(store.headersDir, hex.EncodeToString(block1Hash[:])+".bin")
	cyclic := append([]byte(nil), parsed1.HeaderBytes...)
	copy(cyclic[4:36], block1Hash[:])
	if err := os.WriteFile(headerPath, cyclic, 0o600); err != nil {
		t.Fatalf("WriteFile(cyclic header): %v", err)
	}
	if _, err := store.ChainWork(block1Hash); err == nil {
		t.Fatalf("expected parent cycle rejection")
	}
}
