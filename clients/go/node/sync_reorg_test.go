package node

import (
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

func TestReorgTwoMiners(t *testing.T) {
	engine, store, target := newReorgTestEngine(t)

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
	if _, err := store.GetBlockByHash(summaryB1.BlockHash); err != nil {
		t.Fatalf("GetBlockByHash(B1): %v", err)
	}
	if work, err := store.ChainWork(summaryB1.BlockHash); err != nil {
		t.Fatalf("ChainWork(B1): %v", err)
	} else if work.Sign() <= 0 {
		t.Fatalf("ChainWork(B1)=%s, want positive", work)
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
	engine, _, target := newReorgTestEngine(t)

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
	var err error
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

func TestApplyBlockWithReorgRejectsMissingParent(t *testing.T) {
	engine, _, target := newReorgTestEngine(t)
	var missingParent [32]byte
	missingParent[0] = 0x42
	block := buildSingleTxBlock(t, missingParent, target, 77, coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 1, consensus.BlockSubsidy(1, 0)))
	if _, err := engine.ApplyBlockWithReorg(block, nil); !errors.Is(err, ErrParentNotFound) {
		t.Fatalf("ApplyBlockWithReorg(missing parent) err=%v, want ErrParentNotFound", err)
	}
}

func TestApplyBlockWithReorgRejectsInvalidNonHeavierSideBranch(t *testing.T) {
	engine, store, target := newReorgTestEngine(t)

	subsidy1 := consensus.BlockSubsidy(1, 0)
	blockA1 := buildSingleTxBlock(t, devnetGenesisBlockHash, target, 2, coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 1, subsidy1))
	summaryA1, err := engine.ApplyBlock(blockA1, nil)
	if err != nil {
		t.Fatalf("ApplyBlock(A1): %v", err)
	}

	blockB1 := buildSingleTxBlock(t, devnetGenesisBlockHash, target, 3, coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 1, subsidy1))
	invalidB1 := append([]byte(nil), blockB1...)
	invalidB1[4+32] ^= 0x01 // flip a merkle-root byte while keeping the block parseable
	invalidB1Hash, err := consensus.BlockHash(blockHeaderBytes(t, invalidB1))
	if err != nil {
		t.Fatalf("BlockHash(invalid B1): %v", err)
	}
	if _, err := engine.ApplyBlockWithReorg(invalidB1, nil); err == nil {
		t.Fatalf("expected invalid competing branch rejection")
	}

	if engine.chainState.Height != 1 || engine.chainState.TipHash != summaryA1.BlockHash {
		t.Fatalf("canonical tip changed after invalid competing branch")
	}
	if _, err := store.GetBlockByHash(invalidB1Hash); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("GetBlockByHash(invalid B1) err=%v, want not-exist", err)
	}
}

func TestApplyBlockWithReorgRollbackRestoresCanonicalIndexAndChainstateFile(t *testing.T) {
	dir := t.TempDir()
	chainStatePath := ChainStatePath(dir)
	store, err := OpenBlockStore(BlockStorePath(dir))
	if err != nil {
		t.Fatalf("OpenBlockStore: %v", err)
	}
	target := consensus.POW_LIMIT
	engine, err := NewSyncEngine(NewChainState(), store, DefaultSyncConfig(&target, devnetGenesisChainID, chainStatePath))
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
	beforeState, err := stateToDisk(engine.chainState)
	if err != nil {
		t.Fatalf("stateToDisk(before): %v", err)
	}

	sideB1 := buildSingleTxBlock(t, devnetGenesisBlockHash, target, 3, coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 1, subsidy1))
	sideB1Hash, err := consensus.BlockHash(blockHeaderBytes(t, sideB1))
	if err != nil {
		t.Fatalf("BlockHash(B1): %v", err)
	}
	if _, err := engine.ApplyBlockWithReorg(sideB1, nil); err != nil {
		t.Fatalf("ApplyBlockWithReorg(B1): %v", err)
	}

	subsidy2 := consensus.BlockSubsidy(2, subsidy1)
	sideB2 := buildSingleTxBlock(t, sideB1Hash, target, 4, coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 2, subsidy2))

	prevWrite := writeFileAtomicFn
	t.Cleanup(func() { writeFileAtomicFn = prevWrite })
	indexWriteCount := 0
	writeFileAtomicFn = func(path string, data []byte, mode os.FileMode) error {
		if path == store.indexPath {
			indexWriteCount++
			if indexWriteCount == 2 {
				return os.ErrPermission
			}
		}
		return prevWrite(path, data, mode)
	}

	if _, err := engine.ApplyBlockWithReorg(sideB2, nil); err == nil {
		t.Fatalf("expected reorg apply failure")
	}

	afterState, err := LoadChainState(chainStatePath)
	if err != nil {
		t.Fatalf("LoadChainState(after): %v", err)
	}
	wantState, err := chainStateFromDisk(beforeState)
	if err != nil {
		t.Fatalf("chainStateFromDisk(before): %v", err)
	}
	if !reflect.DeepEqual(afterState, wantState) {
		t.Fatalf("persisted chainstate not restored after rollback")
	}
	if engine.chainState.Height != 1 || engine.chainState.TipHash != summaryA1.BlockHash {
		t.Fatalf("in-memory chainstate not restored after rollback")
	}
	tipHeight, tipHash, ok, err := store.Tip()
	if err != nil {
		t.Fatalf("store.Tip: %v", err)
	}
	if !ok || tipHeight != 1 || tipHash != summaryA1.BlockHash {
		t.Fatalf("canonical tip after rollback: ok=%v height=%d hash=%x", ok, tipHeight, tipHash)
	}
	b1CanonicalHash, ok, err := store.CanonicalHash(1)
	if err != nil || !ok {
		t.Fatalf("CanonicalHash(1): ok=%v err=%v", ok, err)
	}
	if b1CanonicalHash != summaryA1.BlockHash {
		t.Fatalf("canonical height 1 hash=%x, want %x", b1CanonicalHash, summaryA1.BlockHash)
	}
}

func TestApplyBlockWithReorgRejectsInvalidHeavierBranchBeforeDisconnectingCanonicalTip(t *testing.T) {
	engine, store, target := newReorgTestEngine(t)

	subsidy1 := consensus.BlockSubsidy(1, 0)
	blockA1 := buildSingleTxBlock(t, devnetGenesisBlockHash, target, 2, coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 1, subsidy1))
	summaryA1, err := engine.ApplyBlock(blockA1, nil)
	if err != nil {
		t.Fatalf("ApplyBlock(A1): %v", err)
	}
	subsidy2 := consensus.BlockSubsidy(2, subsidy1)
	blockA2 := buildSingleTxBlock(t, summaryA1.BlockHash, target, 3, coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 2, subsidy2))
	summaryA2, err := engine.ApplyBlock(blockA2, nil)
	if err != nil {
		t.Fatalf("ApplyBlock(A2): %v", err)
	}

	blockB1 := buildSingleTxBlock(t, devnetGenesisBlockHash, target, 10, coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 1, subsidy1))
	if _, err := engine.ApplyBlockWithReorg(blockB1, nil); err != nil {
		t.Fatalf("ApplyBlockWithReorg(B1): %v", err)
	}
	blockB1Hash, err := consensus.BlockHash(blockHeaderBytes(t, blockB1))
	if err != nil {
		t.Fatalf("BlockHash(B1): %v", err)
	}
	blockB2 := buildSingleTxBlock(t, blockB1Hash, target, 11, coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 2, subsidy2))
	if _, err := engine.ApplyBlockWithReorg(blockB2, nil); err != nil {
		t.Fatalf("ApplyBlockWithReorg(B2): %v", err)
	}
	blockB2Hash, err := consensus.BlockHash(blockHeaderBytes(t, blockB2))
	if err != nil {
		t.Fatalf("BlockHash(B2): %v", err)
	}

	subsidy3 := consensus.BlockSubsidy(3, subsidy1+subsidy2)
	validB3 := buildSingleTxBlock(t, blockB2Hash, target, 12, coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 3, subsidy3))
	invalidB3 := append([]byte(nil), validB3...)
	invalidB3[len(invalidB3)-1] ^= 0x01

	prevWrite := writeFileAtomicFn
	t.Cleanup(func() { writeFileAtomicFn = prevWrite })
	chainStateWrites := 0
	indexWrites := 0
	writeFileAtomicFn = func(path string, data []byte, mode os.FileMode) error {
		switch path {
		case ChainStatePath(filepath.Dir(store.rootPath)):
			chainStateWrites++
		case store.indexPath:
			indexWrites++
		}
		return prevWrite(path, data, mode)
	}

	if _, err := engine.ApplyBlockWithReorg(invalidB3, nil); err == nil {
		t.Fatalf("expected invalid heavier branch rejection")
	}
	if chainStateWrites != 0 || indexWrites != 0 {
		t.Fatalf("invalid heavier branch rewrote state: chainstate=%d index=%d", chainStateWrites, indexWrites)
	}
	if engine.chainState.Height != summaryA2.BlockHeight || engine.chainState.TipHash != summaryA2.BlockHash {
		t.Fatalf("canonical tip changed after invalid heavier branch")
	}
	tipHeight, tipHash, ok, err := store.Tip()
	if err != nil {
		t.Fatalf("store.Tip: %v", err)
	}
	if !ok || tipHeight != summaryA2.BlockHeight || tipHash != summaryA2.BlockHash {
		t.Fatalf("store tip after invalid branch: ok=%v height=%d hash=%x", ok, tipHeight, tipHash)
	}
}

func TestCollectBranchToCanonicalPropagatesNonNotExistErrors(t *testing.T) {
	engine, store, target := newReorgTestEngine(t)

	subsidy1 := consensus.BlockSubsidy(1, 0)
	sideB1 := buildSingleTxBlock(t, devnetGenesisBlockHash, target, 3, coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 1, subsidy1))
	sideB1Parsed, err := consensus.ParseBlockBytes(sideB1)
	if err != nil {
		t.Fatalf("ParseBlockBytes(B1): %v", err)
	}
	sideB1Hash, err := consensus.BlockHash(sideB1Parsed.HeaderBytes)
	if err != nil {
		t.Fatalf("BlockHash(B1): %v", err)
	}
	if err := store.StoreBlock(sideB1Hash, sideB1Parsed.HeaderBytes, sideB1); err != nil {
		t.Fatalf("StoreBlock(B1): %v", err)
	}

	subsidy2 := consensus.BlockSubsidy(2, subsidy1)
	sideB2 := buildSingleTxBlock(t, sideB1Hash, target, 4, coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 2, subsidy2))
	sideB2Parsed, err := consensus.ParseBlockBytes(sideB2)
	if err != nil {
		t.Fatalf("ParseBlockBytes(B2): %v", err)
	}
	sideB2Hash, err := consensus.BlockHash(sideB2Parsed.HeaderBytes)
	if err != nil {
		t.Fatalf("BlockHash(B2): %v", err)
	}

	nonDir := filepath.Join(t.TempDir(), "blocks-file")
	if err := os.WriteFile(nonDir, []byte("x"), 0o600); err != nil {
		t.Fatalf("WriteFile(nonDir): %v", err)
	}
	store.blocksDir = nonDir

	if _, _, _, err := engine.collectBranchToCanonical(sideB2Hash, sideB2, sideB2Parsed); err == nil {
		t.Fatalf("expected storage error")
	} else if errors.Is(err, ErrParentNotFound) {
		t.Fatalf("expected non-not-found error, got %v", err)
	}
}

func TestApplyCanonicalParsedBlockHelperErrors(t *testing.T) {
	var nilEngine *SyncEngine
	if _, err := nilEngine.applyCanonicalParsedBlock(nil, nil, nil); err == nil {
		t.Fatalf("expected nil sync engine error")
	}

	engine, _, _ := newReorgTestEngine(t)
	if _, err := engine.applyCanonicalParsedBlock(nil, nil, nil); err == nil {
		t.Fatalf("expected nil parsed block error")
	}

	engine.cfg.ChainID = [32]byte{0x99}
	pb, err := consensus.ParseBlockBytes(devnetGenesisBlockBytes)
	if err != nil {
		t.Fatalf("ParseBlockBytes(genesis): %v", err)
	}
	if _, err := engine.applyCanonicalParsedBlock(pb, devnetGenesisBlockBytes, nil); err == nil {
		t.Fatalf("expected genesis chain_id mismatch")
	}
}

func TestRecordAppliedBlockAndNoteReorgHelpers(t *testing.T) {
	engine, _, _ := newReorgTestEngine(t)
	engine.noteReorg(3)
	if engine.LastReorgDepth() != 3 || engine.ReorgCount() == 0 {
		t.Fatalf("noteReorg did not record metrics")
	}
	engine.recordAppliedBlock(2, 1234)
	if depth := engine.LastReorgDepth(); depth != 0 {
		t.Fatalf("LastReorgDepth()=%d, want reset to 0", depth)
	}
	if engine.bestKnownHeight != 2 {
		t.Fatalf("bestKnownHeight=%d, want 2", engine.bestKnownHeight)
	}

	var nilEngine *SyncEngine
	nilEngine.noteReorg(1)
}

func TestApplyBlockWithReorgRequeuesDisconnectedTransactionsIntoMempool(t *testing.T) {
	engine, store, target := newReorgTestEngine(t)
	mempool, err := NewMempool(engine.chainState, store, devnetGenesisChainID)
	if err != nil {
		t.Fatalf("NewMempool: %v", err)
	}
	engine.SetMempool(mempool)

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

	prevHash := devnetGenesisBlockHash
	alreadyGenerated := uint64(0)
	var sourceOutpoint consensus.Outpoint
	for height := uint64(1); height <= 100; height++ {
		subsidy := consensus.BlockSubsidy(height, alreadyGenerated)
		coinbase := reorgTestCoinbaseForAddress(t, height, subsidy, sourceAddress)
		block := buildSingleTxBlock(t, prevHash, target, height+1, coinbase)
		summary, err := engine.ApplyBlock(block, nil)
		if err != nil {
			t.Fatalf("ApplyBlock(height=%d): %v", height, err)
		}
		if height == 1 {
			_, coinbaseTxid, _, _, err := consensus.ParseTx(coinbase)
			if err != nil {
				t.Fatalf("ParseTx(coinbase height1): %v", err)
			}
			sourceOutpoint = consensus.Outpoint{Txid: coinbaseTxid, Vout: 0}
		}
		prevHash = summary.BlockHash
		alreadyGenerated += subsidy
	}

	spendTx := mustBuildSignedTransferTxForSyncTest(
		t,
		engine.chainState.Utxos,
		[]consensus.Outpoint{sourceOutpoint},
		700,
		50,
		1,
		sourceKP,
		sourceAddress,
		destAddress,
	)
	_, spendTxid, spendWtxid, _, err := consensus.ParseTx(spendTx)
	if err != nil {
		t.Fatalf("ParseTx(spend): %v", err)
	}

	subsidyA101 := consensus.BlockSubsidy(101, alreadyGenerated)
	blockA101 := buildMultiTxBlock(
		t,
		prevHash,
		target,
		202,
		reorgTestCoinbaseForWtxids(t, 101, subsidyA101+50, sourceAddress, [][32]byte{{}, spendWtxid}),
		spendTx,
	)
	summaryA101, err := engine.ApplyBlock(blockA101, nil)
	if err != nil {
		t.Fatalf("ApplyBlock(A101): %v", err)
	}
	if got := mempool.Len(); got != 0 {
		t.Fatalf("mempool len after mining tx=%d, want 0", got)
	}

	subsidyB101 := consensus.BlockSubsidy(101, alreadyGenerated)
	blockB101 := buildSingleTxBlock(t, prevHash, target, 203, reorgTestCoinbaseForAddress(t, 101, subsidyB101, destAddress))
	if _, err := engine.ApplyBlockWithReorg(blockB101, nil); err != nil {
		t.Fatalf("ApplyBlockWithReorg(B101): %v", err)
	}
	blockB101Hash, err := consensus.BlockHash(blockHeaderBytes(t, blockB101))
	if err != nil {
		t.Fatalf("BlockHash(B101): %v", err)
	}

	subsidyB102 := consensus.BlockSubsidy(102, alreadyGenerated+subsidyB101)
	blockB102 := buildSingleTxBlock(t, blockB101Hash, target, 204, reorgTestCoinbaseForAddress(t, 102, subsidyB102, destAddress))
	if _, err := engine.ApplyBlockWithReorg(blockB102, nil); err != nil {
		t.Fatalf("ApplyBlockWithReorg(B102): %v", err)
	}

	if got := mempool.Len(); got != 1 {
		t.Fatalf("mempool len after reorg=%d, want 1", got)
	}
	if err := mempool.AddTx(spendTx); err == nil {
		t.Fatalf("expected spend tx to already be in mempool after reorg")
	}
	if _, exists := engine.chainState.Utxos[consensus.Outpoint{Txid: spendTxid, Vout: 0}]; exists {
		t.Fatalf("reorged chainstate should not retain old-branch spend output")
	}
	if engine.chainState.TipHash == summaryA101.BlockHash {
		t.Fatalf("tip hash still points to old branch")
	}
}

type countingRotationProvider struct {
	suiteID    uint8
	spendCalls int
}

func (p *countingRotationProvider) NativeCreateSuites(uint64) *consensus.NativeSuiteSet {
	return consensus.NewNativeSuiteSet(consensus.SUITE_ID_ML_DSA_87, p.suiteID)
}

func (p *countingRotationProvider) NativeSpendSuites(uint64) *consensus.NativeSuiteSet {
	p.spendCalls++
	return consensus.NewNativeSuiteSet(consensus.SUITE_ID_ML_DSA_87, p.suiteID)
}

func TestNativeSuitesCacheInvalidatedOnReorg(t *testing.T) {
	engine, store, target := newReorgTestEngine(t)
	sourceKPA := mustReorgMLDSA87Keypair(t)
	destKPA := mustReorgMLDSA87Keypair(t)
	sourceKPB := mustReorgMLDSA87Keypair(t)
	destKPB := mustReorgMLDSA87Keypair(t)

	sourceAddressA := consensus.P2PKCovenantDataForPubkey(sourceKPA.PubkeyBytes())
	destAddressA := consensus.P2PKCovenantDataForPubkey(destKPA.PubkeyBytes())
	sourceAddressB := consensus.P2PKCovenantDataForPubkey(sourceKPB.PubkeyBytes())
	destAddressB := consensus.P2PKCovenantDataForPubkey(destKPB.PubkeyBytes())
	sourceOutpointA := consensus.Outpoint{Txid: [32]byte{0x11}, Vout: 0}
	sourceOutpointB := consensus.Outpoint{Txid: [32]byte{0x22}, Vout: 0}
	utxos := map[consensus.Outpoint]consensus.UtxoEntry{
		sourceOutpointA: {
			Value:             750,
			CovenantType:      consensus.COV_TYPE_P2PK,
			CovenantData:      append([]byte(nil), sourceAddressA...),
			CreationHeight:    0,
			CreatedByCoinbase: false,
		},
		sourceOutpointB: {
			Value:             730,
			CovenantType:      consensus.COV_TYPE_P2PK,
			CovenantData:      append([]byte(nil), sourceAddressB...),
			CreationHeight:    0,
			CreatedByCoinbase: false,
		},
	}

	blockASpend := mustBuildSignedTransferTxForSyncTest(
		t,
		utxos,
		[]consensus.Outpoint{sourceOutpointA},
		680,
		50,
		1,
		sourceKPA,
		sourceAddressA,
		destAddressA,
	)
	blockBSpend := mustBuildSignedTransferTxForSyncTest(
		t,
		utxos,
		[]consensus.Outpoint{sourceOutpointB},
		665,
		50,
		2,
		sourceKPB,
		sourceAddressB,
		destAddressB,
	)

	const rotatedSuiteID = 0x42
	blockASpend = rewriteSyncTestWitnessSuiteID(t, blockASpend, rotatedSuiteID)
	blockBSpend = rewriteSyncTestWitnessSuiteID(t, blockBSpend, rotatedSuiteID)
	for _, op := range []consensus.Outpoint{sourceOutpointA, sourceOutpointB} {
		rotatedEntry := utxos[op]
		rotatedEntry.CovenantData = append([]byte(nil), rotatedEntry.CovenantData...)
		rotatedEntry.CovenantData[0] = rotatedSuiteID
		utxos[op] = rotatedEntry
	}

	rotation := &countingRotationProvider{suiteID: rotatedSuiteID}
	registry := reorgTestSuiteRegistry(rotatedSuiteID)
	engine.cfg.RotationProvider = rotation
	engine.cfg.SuiteRegistry = registry
	engine.chainState.Utxos = utxos

	mempool, err := NewMempoolWithConfig(engine.chainState, store, devnetGenesisChainID, MempoolConfig{
		RotationProvider: rotation,
		SuiteRegistry:    registry,
	})
	if err != nil {
		t.Fatalf("NewMempoolWithConfig: %v", err)
	}
	engine.SetMempool(mempool)

	_, _, blockASpendWtxid, _, err := consensus.ParseTx(blockASpend)
	if err != nil {
		t.Fatalf("ParseTx(blockASpend): %v", err)
	}
	subsidy1 := consensus.BlockSubsidy(1, 0)
	blockA1 := buildMultiTxBlock(
		t,
		devnetGenesisBlockHash,
		target,
		2,
		reorgTestCoinbaseForWtxids(t, 1, subsidy1+50, sourceAddressA, [][32]byte{{}, blockASpendWtxid}),
		blockASpend,
	)
	summaryA1, err := engine.ApplyBlock(blockA1, nil)
	if err != nil {
		t.Fatalf("ApplyBlock(A1): %v", err)
	}

	_, _, blockBSpendWtxid, _, err := consensus.ParseTx(blockBSpend)
	if err != nil {
		t.Fatalf("ParseTx(blockBSpend): %v", err)
	}
	blockB1 := buildMultiTxBlock(
		t,
		devnetGenesisBlockHash,
		target,
		3,
		reorgTestCoinbaseForWtxids(t, 1, subsidy1+50, destAddressB, [][32]byte{{}, blockBSpendWtxid}),
		blockBSpend,
	)
	if _, err := engine.ApplyBlockWithReorg(blockB1, nil); err != nil {
		t.Fatalf("ApplyBlockWithReorg(B1): %v", err)
	}
	blockB1Hash, err := consensus.BlockHash(blockHeaderBytes(t, blockB1))
	if err != nil {
		t.Fatalf("BlockHash(B1): %v", err)
	}

	subsidy2 := consensus.BlockSubsidy(2, subsidy1)
	blockB2 := buildSingleTxBlock(
		t,
		blockB1Hash,
		target,
		4,
		reorgTestCoinbaseForAddress(t, 2, subsidy2, destAddressB),
	)
	if _, err := engine.ApplyBlockWithReorg(blockB2, nil); err != nil {
		t.Fatalf("ApplyBlockWithReorg(B2): %v", err)
	}

	if got := mempool.Len(); got != 1 {
		t.Fatalf("mempool len after reorg=%d, want 1", got)
	}
	if rotation.spendCalls < 3 {
		t.Fatalf("NativeSpendSuites calls=%d, want >= 3 (canonical apply, preview replay, mempool requeue)", rotation.spendCalls)
	}
	if engine.chainState.TipHash == summaryA1.BlockHash {
		t.Fatalf("tip hash still points to old branch")
	}
}

func TestApplyBlockWithReorgRollbackRestoresMempoolAfterPersistFailure(t *testing.T) {
	engine, store, target := newReorgTestEngine(t)
	mempool, err := NewMempool(engine.chainState, store, devnetGenesisChainID)
	if err != nil {
		t.Fatalf("NewMempool: %v", err)
	}
	engine.SetMempool(mempool)

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

	prevHash := devnetGenesisBlockHash
	alreadyGenerated := uint64(0)
	var sourceOutpoint consensus.Outpoint
	for height := uint64(1); height <= 100; height++ {
		subsidy := consensus.BlockSubsidy(height, alreadyGenerated)
		coinbase := reorgTestCoinbaseForAddress(t, height, subsidy, sourceAddress)
		block := buildSingleTxBlock(t, prevHash, target, height+1, coinbase)
		summary, err := engine.ApplyBlock(block, nil)
		if err != nil {
			t.Fatalf("ApplyBlock(height=%d): %v", height, err)
		}
		if height == 1 {
			_, coinbaseTxid, _, _, err := consensus.ParseTx(coinbase)
			if err != nil {
				t.Fatalf("ParseTx(coinbase height1): %v", err)
			}
			sourceOutpoint = consensus.Outpoint{Txid: coinbaseTxid, Vout: 0}
		}
		prevHash = summary.BlockHash
		alreadyGenerated += subsidy
	}

	spendTx := mustBuildSignedTransferTxForSyncTest(
		t,
		engine.chainState.Utxos,
		[]consensus.Outpoint{sourceOutpoint},
		700,
		50,
		1,
		sourceKP,
		sourceAddress,
		destAddress,
	)
	_, _, spendWtxid, _, err := consensus.ParseTx(spendTx)
	if err != nil {
		t.Fatalf("ParseTx(spend): %v", err)
	}
	if err := mempool.AddTx(spendTx); err != nil {
		t.Fatalf("mempool.AddTx(spend): %v", err)
	}

	subsidyA101 := consensus.BlockSubsidy(101, alreadyGenerated)
	blockA101 := buildSingleTxBlock(t, prevHash, target, 202, reorgTestCoinbaseForAddress(t, 101, subsidyA101, sourceAddress))
	summaryA101, err := engine.ApplyBlock(blockA101, nil)
	if err != nil {
		t.Fatalf("ApplyBlock(A101): %v", err)
	}
	if got := mempool.Len(); got != 1 {
		t.Fatalf("mempool len after A101=%d, want 1", got)
	}

	subsidyB101 := consensus.BlockSubsidy(101, alreadyGenerated)
	blockB101 := buildMultiTxBlock(
		t,
		prevHash,
		target,
		203,
		reorgTestCoinbaseForWtxids(t, 101, subsidyB101+50, destAddress, [][32]byte{{}, spendWtxid}),
		spendTx,
	)
	if _, err := engine.ApplyBlockWithReorg(blockB101, nil); err != nil {
		t.Fatalf("ApplyBlockWithReorg(B101): %v", err)
	}
	blockB101Hash, err := consensus.BlockHash(blockHeaderBytes(t, blockB101))
	if err != nil {
		t.Fatalf("BlockHash(B101): %v", err)
	}

	subsidyB102 := consensus.BlockSubsidy(102, alreadyGenerated+subsidyB101)
	blockB102 := buildSingleTxBlock(t, blockB101Hash, target, 204, reorgTestCoinbaseForAddress(t, 102, subsidyB102, destAddress))

	prevWrite := writeFileAtomicFn
	t.Cleanup(func() { writeFileAtomicFn = prevWrite })
	indexWrites := 0
	writeFileAtomicFn = func(path string, data []byte, mode os.FileMode) error {
		if path == store.indexPath {
			indexWrites++
			if indexWrites == 3 {
				return os.ErrPermission
			}
		}
		return prevWrite(path, data, mode)
	}

	if _, err := engine.ApplyBlockWithReorg(blockB102, nil); err == nil {
		t.Fatalf("expected reorg persist failure")
	}
	if engine.chainState.Height != summaryA101.BlockHeight || engine.chainState.TipHash != summaryA101.BlockHash {
		t.Fatalf("chainstate tip changed after rollback: height=%d hash=%x", engine.chainState.Height, engine.chainState.TipHash)
	}
	if got := mempool.Len(); got != 1 {
		t.Fatalf("mempool len after rollback=%d, want 1", got)
	}
	if err := mempool.AddTx(spendTx); err == nil {
		t.Fatalf("expected spend tx to remain in mempool after rollback")
	}
}

func TestNonCoinbaseBlockTransactionsExtractsCanonicalTransactions(t *testing.T) {
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
	sourceOutpoint := consensus.Outpoint{
		Txid: mustHash32Hex(t, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
		Vout: 0,
	}
	utxos := map[consensus.Outpoint]consensus.UtxoEntry{
		sourceOutpoint: {
			Value:             1_000,
			CovenantType:      consensus.COV_TYPE_P2PK,
			CovenantData:      append([]byte(nil), sourceAddress...),
			CreationHeight:    1,
			CreatedByCoinbase: true,
		},
	}
	spendTx := mustBuildSignedTransferTxForSyncTest(
		t,
		utxos,
		[]consensus.Outpoint{sourceOutpoint},
		700,
		50,
		1,
		sourceKP,
		sourceAddress,
		destAddress,
	)
	_, _, spendWtxid, _, err := consensus.ParseTx(spendTx)
	if err != nil {
		t.Fatalf("ParseTx(spend): %v", err)
	}
	block := buildMultiTxBlock(
		t,
		devnetGenesisBlockHash,
		consensus.POW_LIMIT,
		2,
		reorgTestCoinbaseForWtxids(t, 101, consensus.BlockSubsidy(101, 0)+50, sourceAddress, [][32]byte{{}, spendWtxid}),
		spendTx,
	)

	txs, err := nonCoinbaseBlockTransactions(block)
	if err != nil {
		t.Fatalf("nonCoinbaseBlockTransactions: %v", err)
	}
	if len(txs) != 1 {
		t.Fatalf("len(non-coinbase txs)=%d, want 1", len(txs))
	}
	if !reflect.DeepEqual(txs[0], spendTx) {
		t.Fatalf("extracted tx bytes differ from original spend tx")
	}
}

func TestSyncReorgHelperCoveragePaths(t *testing.T) {
	engine, store, target := newReorgTestEngine(t)

	if got, err := testBlockStoreCanonicalCount(nil); err != nil || got != 0 {
		t.Fatalf("testBlockStoreCanonicalCount(nil)=(%d,%v), want (0,nil)", got, err)
	}
	if got, err := testBlockStoreCanonicalCount(store); err != nil || got != 1 {
		t.Fatalf("testBlockStoreCanonicalCount(genesis)=(%d,%v), want (1,nil)", got, err)
	}
	emptyDir := t.TempDir()
	emptyStore, err := OpenBlockStore(BlockStorePath(emptyDir))
	if err != nil {
		t.Fatalf("OpenBlockStore(empty): %v", err)
	}
	emptyEngine, err := NewSyncEngine(NewChainState(), emptyStore, DefaultSyncConfig(&target, devnetGenesisChainID, ChainStatePath(emptyDir)))
	if err != nil {
		t.Fatalf("NewSyncEngine(empty): %v", err)
	}
	if _, _, err := emptyEngine.currentCanonicalTip(); err == nil {
		t.Fatalf("expected currentCanonicalTip to reject empty canonical index")
	}

	subsidy1 := consensus.BlockSubsidy(1, 0)
	block1 := buildSingleTxBlock(t, devnetGenesisBlockHash, target, 2, coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 1, subsidy1))
	if _, err := engine.ApplyBlock(block1, nil); err != nil {
		t.Fatalf("ApplyBlock(block1): %v", err)
	}
	if got, err := testBlockStoreCanonicalCount(store); err != nil || got != 2 {
		t.Fatalf("testBlockStoreCanonicalCount(height=1)=(%d,%v), want (2,nil)", got, err)
	}
	if height, _, err := engine.currentCanonicalTip(); err != nil || height != 1 {
		t.Fatalf("currentCanonicalTip()=(%d,%v), want height=1", height, err)
	}
}

func TestApplyBlockWithReorgAdditionalErrorPaths(t *testing.T) {
	var nilEngine *SyncEngine
	if _, err := nilEngine.ApplyBlockWithReorg(nil, nil); err == nil {
		t.Fatalf("expected nil sync engine error")
	}

	target := consensus.POW_LIMIT
	engine := &SyncEngine{chainState: NewChainState()}
	block := buildSingleTxBlock(t, devnetGenesisBlockHash, target, 8, coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 1, consensus.BlockSubsidy(1, 0)))
	if _, err := engine.ApplyBlockWithReorg(block, nil); err == nil {
		t.Fatalf("expected missing blockstore error")
	}
}

func TestApplyBlockWithReorgKeepsLighterSideBranchOffCanonicalTip(t *testing.T) {
	engine, store, target := newReorgTestEngine(t)

	subsidy1 := consensus.BlockSubsidy(1, 0)
	blockA1 := buildSingleTxBlock(t, devnetGenesisBlockHash, target, 2, coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 1, subsidy1))
	summaryA1, err := engine.ApplyBlock(blockA1, nil)
	if err != nil {
		t.Fatalf("ApplyBlock(A1): %v", err)
	}

	subsidy2 := consensus.BlockSubsidy(2, subsidy1)
	blockA2 := buildSingleTxBlock(t, summaryA1.BlockHash, target, 3, coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 2, subsidy2))
	summaryA2, err := engine.ApplyBlock(blockA2, nil)
	if err != nil {
		t.Fatalf("ApplyBlock(A2): %v", err)
	}

	sideB1 := buildSingleTxBlock(t, devnetGenesisBlockHash, target, 4, coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 1, subsidy1))
	sideSummary, err := engine.ApplyBlockWithReorg(sideB1, nil)
	if err != nil {
		t.Fatalf("ApplyBlockWithReorg(B1): %v", err)
	}
	if sideSummary.BlockHeight != 1 {
		t.Fatalf("side branch synthetic height=%d, want 1", sideSummary.BlockHeight)
	}
	if engine.chainState.TipHash != summaryA2.BlockHash || engine.chainState.Height != 2 {
		t.Fatalf("canonical tip changed on lighter side branch")
	}
	sideHash, err := consensus.BlockHash(blockHeaderBytes(t, sideB1))
	if err != nil {
		t.Fatalf("BlockHash(B1): %v", err)
	}
	if _, err := store.GetBlockByHash(sideHash); err != nil {
		t.Fatalf("GetBlockByHash(B1): %v", err)
	}
}

func TestDisconnectTipErrorPaths(t *testing.T) {
	var nilEngine *SyncEngine
	if _, err := nilEngine.DisconnectTip(); err == nil {
		t.Fatalf("expected nil sync engine error")
	}

	engine := &SyncEngine{chainState: NewChainState()}
	if _, err := engine.DisconnectTip(); err == nil {
		t.Fatalf("expected missing blockstore error")
	}

	reorgEngine, store, target := newReorgTestEngine(t)
	subsidy1 := consensus.BlockSubsidy(1, 0)
	blockA1 := buildSingleTxBlock(t, devnetGenesisBlockHash, target, 2, coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 1, subsidy1))
	summaryA1, err := reorgEngine.ApplyBlock(blockA1, nil)
	if err != nil {
		t.Fatalf("ApplyBlock(A1): %v", err)
	}

	reorgEngine.chainState.TipHash = devnetGenesisBlockHash
	if _, err := reorgEngine.DisconnectTip(); err == nil {
		t.Fatalf("expected chainstate/blockstore mismatch error")
	}
	reorgEngine.chainState.TipHash = summaryA1.BlockHash

	hashHex := hex.EncodeToString(summaryA1.BlockHash[:])
	if err := os.Remove(filepath.Join(store.undoDir, hashHex+".json")); err != nil {
		t.Fatalf("Remove(undo): %v", err)
	}
	if _, err := reorgEngine.DisconnectTip(); err == nil {
		t.Fatalf("expected missing undo error")
	}
}

func TestSyncApplyHelperAdditionalBranches(t *testing.T) {
	if got, err := testBlockStoreCanonicalIndexSnapshot(nil); err != nil || got != nil {
		t.Fatalf("testBlockStoreCanonicalIndexSnapshot(nil)=(%v,%v), want (nil,nil)", got, err)
	}

	store := mustOpenBlockStore(t, filepath.Join(t.TempDir(), "blockstore"))
	store.index.Canonical = []string{"zz"}
	if _, err := testBlockStoreCanonicalIndexSnapshot(store); err == nil {
		t.Fatalf("expected invalid canonical snapshot error")
	}

	if err := testRestoreChainState(nil, chainStateDisk{}); err == nil {
		t.Fatalf("expected nil testRestoreChainState error")
	}

	if ts, err := testParentTipTimestamp(store, 0, [32]byte{}); err != nil || ts != 0 {
		t.Fatalf("testParentTipTimestamp(height0)=(%d,%v), want (0,nil)", ts, err)
	}

	engine, _, _ := newReorgTestEngine(t)
	engine.blockStore.index.Canonical = []string{"zz"}
	if _, err := engine.captureRollbackState(); err == nil {
		t.Fatalf("expected captureRollbackState canonical snapshot error")
	}

	engine, _, _ = newReorgTestEngine(t)
	cause := errors.New("boom")
	state, err := engine.captureRollbackState()
	if err != nil {
		t.Fatalf("captureRollbackState: %v", err)
	}
	if err := engine.rollbackApplyBlock(cause, state); !errors.Is(err, cause) {
		t.Fatalf("rollbackApplyBlock err=%v, want %v", err, cause)
	}

	engine.cfg.ChainID = [32]byte{}
	if err := testValidateIncomingChainID(0, devnetGenesisChainID); err != nil {
		t.Fatalf("testValidateIncomingChainID(devnet genesis): %v", err)
	}
	if err := testValidateIncomingChainID(1, [32]byte{0x01}); err != nil {
		t.Fatalf("testValidateIncomingChainID(non-genesis): %v", err)
	}
}

func reorgTestCoinbaseForAddress(t *testing.T, height uint64, value uint64, address []byte) []byte {
	t.Helper()
	return reorgTestCoinbaseForWtxids(t, height, value, address, [][32]byte{{}})
}

func mustReorgMLDSA87Keypair(t *testing.T) *consensus.MLDSA87Keypair {
	t.Helper()
	kp, err := consensus.NewMLDSA87Keypair()
	if err != nil {
		if strings.Contains(err.Error(), "unsupported") {
			t.Skipf("ML-DSA backend unavailable in this OpenSSL build: %v", err)
		}
		t.Fatalf("NewMLDSA87Keypair: %v", err)
	}
	t.Cleanup(func() { kp.Close() })
	return kp
}

func rewriteSyncTestWitnessSuiteID(t *testing.T, txBytes []byte, suiteID uint8) []byte {
	t.Helper()
	tx, _, _, consumed, err := consensus.ParseTx(txBytes)
	if err != nil {
		t.Fatalf("ParseTx(rewrite suite): %v", err)
	}
	if consumed != len(txBytes) {
		t.Fatalf("ParseTx(rewrite suite) consumed=%d, want %d", consumed, len(txBytes))
	}
	if len(tx.Witness) != 1 {
		t.Fatalf("rewrite suite expects single witness, got %d", len(tx.Witness))
	}
	tx.Witness[0].SuiteID = suiteID
	rewritten, err := consensus.MarshalTx(tx)
	if err != nil {
		t.Fatalf("MarshalTx(rewrite suite): %v", err)
	}
	return rewritten
}

func reorgTestSuiteRegistry(extraSuiteID uint8) *consensus.SuiteRegistry {
	return consensus.NewSuiteRegistryFromParams([]consensus.SuiteParams{
		{
			SuiteID:    consensus.SUITE_ID_ML_DSA_87,
			PubkeyLen:  consensus.ML_DSA_87_PUBKEY_BYTES,
			SigLen:     consensus.ML_DSA_87_SIG_BYTES,
			VerifyCost: consensus.VERIFY_COST_ML_DSA_87,
			AlgName:    "ML-DSA-87",
		},
		{
			SuiteID:    extraSuiteID,
			PubkeyLen:  consensus.ML_DSA_87_PUBKEY_BYTES,
			SigLen:     consensus.ML_DSA_87_SIG_BYTES,
			VerifyCost: consensus.VERIFY_COST_ML_DSA_87,
			AlgName:    "ML-DSA-87",
		},
	})
}

func reorgTestCoinbaseForWtxids(t *testing.T, height uint64, value uint64, address []byte, wtxids [][32]byte) []byte {
	t.Helper()
	wroot, err := consensus.WitnessMerkleRootWtxids(wtxids)
	if err != nil {
		t.Fatalf("WitnessMerkleRootWtxids: %v", err)
	}
	commitment := consensus.WitnessCommitmentHash(wroot)
	return coinbaseTxWithOutputs(uint32(height), []testOutput{
		{value: value, covenantType: consensus.COV_TYPE_P2PK, covenantData: append([]byte(nil), address...)},
		{value: 0, covenantType: consensus.COV_TYPE_ANCHOR, covenantData: commitment[:]},
	})
}

func newReorgTestEngine(t *testing.T) (*SyncEngine, *BlockStore, [32]byte) {
	t.Helper()
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
	return engine, store, target
}

func testValidateIncomingChainID(blockHeight uint64, chainID [32]byte) error {
	var zeroID [32]byte
	if blockHeight == 0 && chainID != zeroID && chainID != devnetGenesisChainID {
		return errors.New("genesis chain_id mismatch")
	}
	return nil
}

func testBlockStoreCanonicalCount(store *BlockStore) (uint64, error) {
	if store == nil {
		return 0, nil
	}
	height, _, ok, err := store.Tip()
	if err != nil {
		return 0, err
	}
	if !ok {
		return 0, nil
	}
	return height + 1, nil
}

func testBlockStoreCanonicalIndexSnapshot(store *BlockStore) ([]string, error) {
	if store == nil {
		return nil, nil
	}
	return store.CanonicalIndexSnapshot()
}

func testRestoreChainState(dst *ChainState, snapshot chainStateDisk) error {
	if dst == nil {
		return errors.New("nil chainstate destination")
	}
	recovered, err := chainStateFromDisk(snapshot)
	if err != nil {
		return err
	}
	dst.replaceFrom(recovered)
	return nil
}

func testParentTipTimestamp(store *BlockStore, tipHeight uint64, prevBlockHash [32]byte) (uint64, error) {
	if tipHeight == 0 {
		return 0, nil
	}
	parentHeaderBytes, err := store.GetHeaderByHash(prevBlockHash)
	if err != nil {
		return 0, err
	}
	parentHeader, err := consensus.ParseBlockHeaderBytes(parentHeaderBytes)
	if err != nil {
		return 0, err
	}
	return parentHeader.Timestamp, nil
}
