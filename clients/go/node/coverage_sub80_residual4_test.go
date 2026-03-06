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
	if got := headerSyncRequest(nil, 7); got.HasFrom || got.Limit != 7 {
		t.Fatalf("headerSyncRequest(nil)=%+v", got)
	}
	if ts, err := parentTipTimestamp(nil, 0, [32]byte{}); err != nil || ts != 0 {
		t.Fatalf("parentTipTimestamp genesis=%d err=%v", ts, err)
	}
	if err := validateIncomingChainID(0, devnetGenesisChainID); err != nil {
		t.Fatalf("validateIncomingChainID(devnet genesis): %v", err)
	}
	if err := validateIncomingChainID(1, [32]byte{0x01}); err != nil {
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

	if _, err := parentTipTimestamp(store, 1, [32]byte{0xaa}); err == nil {
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
