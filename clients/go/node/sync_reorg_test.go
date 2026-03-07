package node

import (
	"reflect"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

func TestReorgTwoMiners(t *testing.T) {
	dir := t.TempDir()
	store, err := OpenBlockStore(BlockStorePath(dir))
	if err != nil {
		t.Fatalf("OpenBlockStore: %v", err)
	}
	target := consensus.POW_LIMIT
	engine, err := NewSyncEngine(NewChainState(), store, DefaultSyncConfig(&target, devnetGenesisChainID, ChainStatePath(dir)))
	if err != nil {
		t.Fatalf("NewSyncEngine: %v", err)
	}
	if _, err := engine.ApplyBlock(devnetGenesisBlockBytes, nil); err != nil {
		t.Fatalf("ApplyBlock(genesis): %v", err)
	}

	subsidy1 := consensus.BlockSubsidy(1, 0)
	blockA1 := buildSingleTxBlock(t, devnetGenesisBlockHash, target, 2, coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 1, subsidy1))
	summaryA1, err := engine.ApplyBlock(blockA1, nil)
	if err != nil {
		t.Fatalf("ApplyBlock(A1): %v", err)
	}
	if summaryA1.BlockHeight != 1 {
		t.Fatalf("A1 height=%d, want 1", summaryA1.BlockHeight)
	}

	blockB1 := buildSingleTxBlock(t, devnetGenesisBlockHash, target, 3, coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 1, subsidy1))
	summaryB1, err := engine.ApplyBlockWithReorg(blockB1, nil)
	if err != nil {
		t.Fatalf("ApplyBlockWithReorg(B1): %v", err)
	}
	if summaryB1.BlockHeight != 1 {
		t.Fatalf("B1 height=%d, want 1", summaryB1.BlockHeight)
	}
	if engine.chainState.Height != 1 || engine.chainState.TipHash != summaryA1.BlockHash {
		t.Fatalf("canonical tip changed before heavier branch")
	}

	subsidy2 := consensus.BlockSubsidy(2, subsidy1)
	blockB1Hash, err := consensus.BlockHash(blockHeaderBytes(t, blockB1))
	if err != nil {
		t.Fatalf("BlockHash(B1): %v", err)
	}
	blockB2 := buildSingleTxBlock(t, blockB1Hash, target, 4, coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 2, subsidy2))
	summaryB2, err := engine.ApplyBlockWithReorg(blockB2, nil)
	if err != nil {
		t.Fatalf("ApplyBlockWithReorg(B2): %v", err)
	}
	if summaryB2.BlockHeight != 2 {
		t.Fatalf("B2 height=%d, want 2", summaryB2.BlockHeight)
	}
	if depth := engine.LastReorgDepth(); depth != 1 {
		t.Fatalf("LastReorgDepth()=%d, want 1", depth)
	}
	if count := engine.ReorgCount(); count != 1 {
		t.Fatalf("ReorgCount()=%d, want 1", count)
	}

	b1CanonicalHash, ok, err := store.CanonicalHash(1)
	if err != nil || !ok {
		t.Fatalf("CanonicalHash(1): ok=%v err=%v", ok, err)
	}
	b2CanonicalHash, ok, err := store.CanonicalHash(2)
	if err != nil || !ok {
		t.Fatalf("CanonicalHash(2): ok=%v err=%v", ok, err)
	}
	if b1CanonicalHash != blockB1Hash {
		t.Fatalf("height 1 canonical hash=%x, want %x", b1CanonicalHash, blockB1Hash)
	}
	if b2CanonicalHash != summaryB2.BlockHash {
		t.Fatalf("height 2 canonical hash=%x, want %x", b2CanonicalHash, summaryB2.BlockHash)
	}
}

func TestDeepReorg10(t *testing.T) {
	dir := t.TempDir()
	store, err := OpenBlockStore(BlockStorePath(dir))
	if err != nil {
		t.Fatalf("OpenBlockStore: %v", err)
	}
	target := consensus.POW_LIMIT
	engine, err := NewSyncEngine(NewChainState(), store, DefaultSyncConfig(&target, devnetGenesisChainID, ChainStatePath(dir)))
	if err != nil {
		t.Fatalf("NewSyncEngine: %v", err)
	}
	if _, err := engine.ApplyBlock(devnetGenesisBlockBytes, nil); err != nil {
		t.Fatalf("ApplyBlock(genesis): %v", err)
	}

	mainPrev := devnetGenesisBlockHash
	mainAlreadyGenerated := uint64(0)
	for height := uint64(1); height <= 10; height++ {
		subsidy := consensus.BlockSubsidy(height, mainAlreadyGenerated)
		block := buildSingleTxBlock(t, mainPrev, target, height+1, coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, height, subsidy))
		summary, err := engine.ApplyBlock(block, nil)
		if err != nil {
			t.Fatalf("ApplyBlock(A%d): %v", height, err)
		}
		mainPrev = summary.BlockHash
		mainAlreadyGenerated += subsidy
	}

	sidePrev := devnetGenesisBlockHash
	sideAlreadyGenerated := uint64(0)
	sideBlocks := make([][]byte, 0, 11)
	for height := uint64(1); height <= 11; height++ {
		subsidy := consensus.BlockSubsidy(height, sideAlreadyGenerated)
		block := buildSingleTxBlock(t, sidePrev, target, 100+height, coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, height, subsidy))
		sideBlocks = append(sideBlocks, block)
		sidePrev, err = consensus.BlockHash(blockHeaderBytes(t, block))
		if err != nil {
			t.Fatalf("BlockHash(B%d): %v", height, err)
		}
		sideAlreadyGenerated += subsidy
	}
	for index, block := range sideBlocks {
		if _, err := engine.ApplyBlockWithReorg(block, nil); err != nil {
			t.Fatalf("ApplyBlockWithReorg(B%d): %v", index+1, err)
		}
	}
	if depth := engine.LastReorgDepth(); depth != 10 {
		t.Fatalf("LastReorgDepth()=%d, want 10", depth)
	}

	referenceStore, err := OpenBlockStore(BlockStorePath(t.TempDir()))
	if err != nil {
		t.Fatalf("OpenBlockStore(reference): %v", err)
	}
	referenceState := NewChainState()
	referenceEngine, err := NewSyncEngine(referenceState, referenceStore, DefaultSyncConfig(&target, devnetGenesisChainID, ""))
	if err != nil {
		t.Fatalf("NewSyncEngine(reference): %v", err)
	}
	if _, err := referenceEngine.ApplyBlock(devnetGenesisBlockBytes, nil); err != nil {
		t.Fatalf("ApplyBlock(reference genesis): %v", err)
	}
	for index, block := range sideBlocks {
		if _, err := referenceEngine.ApplyBlock(block, nil); err != nil {
			t.Fatalf("ApplyBlock(reference B%d): %v", index+1, err)
		}
	}

	gotDisk, err := stateToDisk(engine.chainState)
	if err != nil {
		t.Fatalf("stateToDisk(got): %v", err)
	}
	wantDisk, err := stateToDisk(referenceState)
	if err != nil {
		t.Fatalf("stateToDisk(want): %v", err)
	}
	if !reflect.DeepEqual(gotDisk, wantDisk) {
		t.Fatalf("reorged chainstate does not match canonical replay")
	}
}

func blockHeaderBytes(t *testing.T, blockBytes []byte) []byte {
	t.Helper()
	pb, err := consensus.ParseBlockBytes(blockBytes)
	if err != nil {
		t.Fatalf("ParseBlockBytes: %v", err)
	}
	return pb.HeaderBytes
}
