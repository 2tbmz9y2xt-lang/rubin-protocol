package node

import (
	"context"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

func TestMinerMineOneFromEmptyState(t *testing.T) {
	dir := t.TempDir()
	chainStatePath := ChainStatePath(dir)

	chainState := NewChainState()
	if err := chainState.Save(chainStatePath); err != nil {
		t.Fatalf("save chainstate: %v", err)
	}
	blockStore, err := OpenBlockStore(BlockStorePath(dir))
	if err != nil {
		t.Fatalf("open blockstore: %v", err)
	}
	syncEngine, err := NewSyncEngine(
		chainState,
		blockStore,
		DefaultSyncConfig(nil, [32]byte{}, chainStatePath),
	)
	if err != nil {
		t.Fatalf("new sync engine: %v", err)
	}
	cfg := DefaultMinerConfig()
	cfg.TimestampSource = func() uint64 { return 1_777_000_000 }
	miner, err := NewMiner(chainState, blockStore, syncEngine, cfg)
	if err != nil {
		t.Fatalf("new miner: %v", err)
	}

	mb, err := miner.MineOne(context.Background(), nil)
	if err != nil {
		t.Fatalf("mine one: %v", err)
	}
	if mb.Height != 0 {
		t.Fatalf("height=%d, want 0", mb.Height)
	}
	if mb.TxCount != 1 {
		t.Fatalf("tx_count=%d, want 1", mb.TxCount)
	}

	height, hash, ok, err := blockStore.Tip()
	if err != nil {
		t.Fatalf("blockstore tip: %v", err)
	}
	if !ok || height != 0 || hash != mb.Hash {
		t.Fatalf("unexpected tip: ok=%v height=%d hash=%x", ok, height, hash)
	}
	if !chainState.HasTip || chainState.Height != 0 {
		t.Fatalf("unexpected chainstate tip: has_tip=%v height=%d", chainState.HasTip, chainState.Height)
	}
}

func TestMinerMineNProducesTimestampProgression(t *testing.T) {
	dir := t.TempDir()
	chainStatePath := ChainStatePath(dir)

	chainState := NewChainState()
	blockStore, err := OpenBlockStore(BlockStorePath(dir))
	if err != nil {
		t.Fatalf("open blockstore: %v", err)
	}
	syncEngine, err := NewSyncEngine(
		chainState,
		blockStore,
		DefaultSyncConfig(nil, [32]byte{}, chainStatePath),
	)
	if err != nil {
		t.Fatalf("new sync engine: %v", err)
	}
	cfg := DefaultMinerConfig()
	cfg.TimestampSource = func() uint64 { return 1 } // forcing miner to use MTP+1 on heights > 0
	miner, err := NewMiner(chainState, blockStore, syncEngine, cfg)
	if err != nil {
		t.Fatalf("new miner: %v", err)
	}

	mined, err := miner.MineN(context.Background(), 3, nil)
	if err != nil {
		t.Fatalf("mine n: %v", err)
	}
	if len(mined) != 3 {
		t.Fatalf("mined=%d, want 3", len(mined))
	}
	if mined[0].Height != 0 || mined[1].Height != 1 || mined[2].Height != 2 {
		t.Fatalf("unexpected mined heights: %+v", mined)
	}
	if mined[1].Timestamp <= mined[0].Timestamp {
		t.Fatalf("expected timestamp progression, got %d <= %d", mined[1].Timestamp, mined[0].Timestamp)
	}
	if mined[2].Timestamp < mined[1].Timestamp {
		t.Fatalf("expected non-decreasing timestamp, got %d < %d", mined[2].Timestamp, mined[1].Timestamp)
	}
}

func TestBuildCoinbaseTxAnchorOnlyCanonical(t *testing.T) {
	var commitment [32]byte
	for i := range commitment {
		commitment[i] = byte(i + 1)
	}
	txBytes, err := buildCoinbaseTx(7, commitment)
	if err != nil {
		t.Fatalf("build coinbase tx: %v", err)
	}
	tx, _, _, consumed, err := consensus.ParseTx(txBytes)
	if err != nil {
		t.Fatalf("parse coinbase tx: %v", err)
	}
	if consumed != len(txBytes) {
		t.Fatalf("consumed=%d len=%d", consumed, len(txBytes))
	}
	if len(tx.Outputs) != 1 {
		t.Fatalf("outputs=%d, want 1", len(tx.Outputs))
	}
	out := tx.Outputs[0]
	if out.Value != 0 {
		t.Fatalf("anchor value=%d, want 0", out.Value)
	}
	if out.CovenantType != consensus.COV_TYPE_ANCHOR {
		t.Fatalf("anchor covenant type=%d", out.CovenantType)
	}
	if len(out.CovenantData) != 32 {
		t.Fatalf("anchor covenant_data_len=%d, want 32", len(out.CovenantData))
	}
	if tx.Locktime != 7 {
		t.Fatalf("coinbase locktime=%d, want 7", tx.Locktime)
	}
}
