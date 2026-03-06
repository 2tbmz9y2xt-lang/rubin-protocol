package node

import (
	"context"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

func setupBlockStoreForP2P(t *testing.T, blockCount int) (*BlockStore, *SyncEngine, *ChainState) {
	t.Helper()
	dir := t.TempDir()
	bs, err := OpenBlockStore(BlockStorePath(dir))
	if err != nil {
		t.Fatalf("OpenBlockStore: %v", err)
	}
	cs := NewChainState()
	target := consensus.POW_LIMIT
	syncCfg := DefaultSyncConfig(&target, DevnetGenesisChainID(), ChainStatePath(dir))
	se, err := NewSyncEngine(cs, bs, syncCfg)
	if err != nil {
		t.Fatalf("NewSyncEngine: %v", err)
	}

	// Apply genesis
	if blockCount > 0 {
		if _, err := se.ApplyBlock(DevnetGenesisBlockBytes(), nil); err != nil {
			t.Fatalf("ApplyBlock(genesis): %v", err)
		}
	}
	// Mine additional blocks
	for i := 1; i < blockCount; i++ {
		minerCfg := DefaultMinerConfig()
		ts := uint64(1_777_000_000 + i)
		minerCfg.TimestampSource = func() uint64 { return ts }
		miner, err := NewMiner(cs, bs, se, minerCfg)
		if err != nil {
			t.Fatalf("NewMiner: %v", err)
		}
		if _, err := miner.MineOne(context.Background(), nil); err != nil {
			t.Fatalf("MineOne(block %d): %v", i, err)
		}
	}
	return bs, se, cs
}

func TestFindCanonicalHeight_Found(t *testing.T) {
	bs, _, _ := setupBlockStoreForP2P(t, 3)

	tipHeight, tipHash, ok, err := bs.Tip()
	if err != nil || !ok {
		t.Fatalf("Tip: err=%v ok=%v", err, ok)
	}

	height, found, err := bs.FindCanonicalHeight(tipHash)
	if err != nil {
		t.Fatalf("FindCanonicalHeight: %v", err)
	}
	if !found {
		t.Fatal("expected to find tip hash in canonical chain")
	}
	if height != tipHeight {
		t.Fatalf("height=%d, want %d", height, tipHeight)
	}
}

func TestFindCanonicalHeight_NotFound(t *testing.T) {
	bs, _, _ := setupBlockStoreForP2P(t, 2)

	var unknown [32]byte
	unknown[0] = 0xFF
	_, found, err := bs.FindCanonicalHeight(unknown)
	if err != nil {
		t.Fatalf("FindCanonicalHeight: %v", err)
	}
	if found {
		t.Fatal("should not find unknown hash")
	}
}

func TestFindCanonicalHeight_NilBlockStore(t *testing.T) {
	var bs *BlockStore
	_, _, err := bs.FindCanonicalHeight([32]byte{})
	if err == nil {
		t.Fatal("expected error for nil blockstore")
	}
}

func TestLocatorHashes_WithBlocks(t *testing.T) {
	bs, _, _ := setupBlockStoreForP2P(t, 5)

	locators, err := bs.LocatorHashes(10)
	if err != nil {
		t.Fatalf("LocatorHashes: %v", err)
	}
	if len(locators) == 0 {
		t.Fatal("expected non-empty locators")
	}
	// First locator should be the tip
	tipHeight, tipHash, ok, err := bs.Tip()
	if err != nil || !ok {
		t.Fatalf("Tip: err=%v ok=%v", err, ok)
	}
	if locators[0] != tipHash {
		t.Fatalf("first locator should be tip hash at height %d", tipHeight)
	}
}

func TestLocatorHashes_DefaultLimit(t *testing.T) {
	bs, _, _ := setupBlockStoreForP2P(t, 2)

	locators, err := bs.LocatorHashes(0) // should default to 32
	if err != nil {
		t.Fatalf("LocatorHashes: %v", err)
	}
	if len(locators) == 0 {
		t.Fatal("expected non-empty locators")
	}
}

func TestLocatorHashes_NilBlockStore(t *testing.T) {
	var bs *BlockStore
	_, err := bs.LocatorHashes(10)
	if err == nil {
		t.Fatal("expected error for nil blockstore")
	}
}

func TestHashesAfterLocators_Full(t *testing.T) {
	bs, _, _ := setupBlockStoreForP2P(t, 5)

	// Get genesis hash as locator
	genesisHash, exists, err := bs.CanonicalHash(0)
	if err != nil || !exists {
		t.Fatalf("CanonicalHash(0): err=%v exists=%v", err, exists)
	}

	hashes, err := bs.HashesAfterLocators([][32]byte{genesisHash}, [32]byte{}, 100)
	if err != nil {
		t.Fatalf("HashesAfterLocators: %v", err)
	}
	// Should return hashes from height 1 onwards
	if len(hashes) == 0 {
		t.Fatal("expected non-empty hashes")
	}
	// First hash should be height 1
	h1, exists, err := bs.CanonicalHash(1)
	if err != nil || !exists {
		t.Fatalf("CanonicalHash(1): err=%v exists=%v", err, exists)
	}
	if hashes[0] != h1 {
		t.Fatalf("first hash should be height 1")
	}
}

func TestHashesAfterLocators_NoLocatorMatch(t *testing.T) {
	bs, _, _ := setupBlockStoreForP2P(t, 3)

	var unknown [32]byte
	unknown[0] = 0xFF
	hashes, err := bs.HashesAfterLocators([][32]byte{unknown}, [32]byte{}, 100)
	if err != nil {
		t.Fatalf("HashesAfterLocators: %v", err)
	}
	// When no locator matches, should start from height 0
	if len(hashes) == 0 {
		t.Fatal("expected hashes from height 0")
	}
}

func TestHashesAfterLocators_WithStopHash(t *testing.T) {
	bs, _, _ := setupBlockStoreForP2P(t, 5)

	genesisHash, _, _ := bs.CanonicalHash(0)
	stopHash, _, _ := bs.CanonicalHash(2)

	hashes, err := bs.HashesAfterLocators([][32]byte{genesisHash}, stopHash, 100)
	if err != nil {
		t.Fatalf("HashesAfterLocators: %v", err)
	}
	// Should stop at stopHash
	if len(hashes) == 0 {
		t.Fatal("expected non-empty hashes")
	}
	if hashes[len(hashes)-1] != stopHash {
		t.Fatal("last hash should be the stop hash")
	}
}

func TestHashesAfterLocators_WithLimit(t *testing.T) {
	bs, _, _ := setupBlockStoreForP2P(t, 5)

	genesisHash, _, _ := bs.CanonicalHash(0)
	hashes, err := bs.HashesAfterLocators([][32]byte{genesisHash}, [32]byte{}, 2)
	if err != nil {
		t.Fatalf("HashesAfterLocators: %v", err)
	}
	if len(hashes) != 2 {
		t.Fatalf("expected 2 hashes, got %d", len(hashes))
	}
}

func TestHashesAfterLocators_NilBlockStore(t *testing.T) {
	var bs *BlockStore
	_, err := bs.HashesAfterLocators(nil, [32]byte{}, 10)
	if err == nil {
		t.Fatal("expected error for nil blockstore")
	}
}

func TestHashesAfterLocators_EmptyLocators(t *testing.T) {
	bs, _, _ := setupBlockStoreForP2P(t, 3)

	hashes, err := bs.HashesAfterLocators(nil, [32]byte{}, 100)
	if err != nil {
		t.Fatalf("HashesAfterLocators: %v", err)
	}
	// Empty locators → start from 0
	if len(hashes) == 0 {
		t.Fatal("expected hashes")
	}
}
