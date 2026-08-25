package node

import (
	"bytes"
	"crypto/sha3"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

// reorgTestTimestamp returns a valid MTP-passing timestamp for reorg test
// blocks.  Genesis timestamp is ~1772020800; adding n ensures each block
// stays monotonic and above MTP median.
func reorgTestTimestamp(n uint64) uint64 {
	genesisParsed, err := consensus.ParseBlockBytes(devnetGenesisBlockBytes)
	if err != nil {
		panic("ParseBlockBytes(genesis): " + err.Error())
	}
	return genesisParsed.Header.Timestamp + n
}

type corruptCanonicalOnCreateRotation struct {
	overwrite func()
	fires     int
}

func (p *corruptCanonicalOnCreateRotation) NativeCreateSuites(height uint64) *consensus.NativeSuiteSet {
	if p.fires == 0 {
		p.fires++
		p.overwrite()
	}
	return consensus.DefaultRotationProvider{}.NativeCreateSuites(height)
}

func (p *corruptCanonicalOnCreateRotation) NativeSpendSuites(height uint64) *consensus.NativeSuiteSet {
	return consensus.DefaultRotationProvider{}.NativeSpendSuites(height)
}

func TestReorgTwoMiners(t *testing.T) {
	engine, store, target := newReorgTestEngine(t)

	subsidy1 := consensus.BlockSubsidy(1, 0)
	blockA1 := buildSingleTxBlock(t, devnetGenesisBlockHash, target, reorgTestTimestamp(1), coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 1, subsidy1))
	summaryA1, err := engine.ApplyBlock(blockA1, nil)
	if err != nil {
		t.Fatalf("ApplyBlock(A1): %v", err)
	}
	if summaryA1.BlockHeight != 1 {
		t.Fatalf("A1 height=%d, want 1", summaryA1.BlockHeight)
	}

	blockB1 := buildSingleTxBlock(t, devnetGenesisBlockHash, target, reorgTestTimestamp(2), coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 1, subsidy1))
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
	beforeReorgCounts := engine.BlockApplyCounts()

	subsidy2 := consensus.BlockSubsidy(2, subsidy1)
	blockB1Hash, err := consensus.BlockHash(blockHeaderBytes(t, blockB1))
	if err != nil {
		t.Fatalf("BlockHash(B1): %v", err)
	}
	blockB2 := buildSingleTxBlock(t, blockB1Hash, target, reorgTestTimestamp(3), coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 2, subsidy2))
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
	if after := engine.BlockApplyCounts(); after.Accepted != beforeReorgCounts.Accepted+2 || after.Rejected != beforeReorgCounts.Rejected {
		t.Fatalf("BlockApplyCounts after successful reorg=%+v, want accepted=%d rejected=%d", after, beforeReorgCounts.Accepted+2, beforeReorgCounts.Rejected)
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
		block := buildSingleTxBlock(t, mainPrev, target, reorgTestTimestamp(height), coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, height, subsidy))
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
		block := buildSingleTxBlock(t, sidePrev, target, reorgTestTimestamp(100+height), coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, height, subsidy))
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

	referenceStore, err := CreateBlockStore(BlockStorePath(t.TempDir()))
	if err != nil {
		t.Fatalf("CreateBlockStore(reference): %v", err)
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

func requireConsensusTxErrCode(t *testing.T, err error, want consensus.ErrorCode) {
	t.Helper()
	var txErr *consensus.TxError
	if !errors.As(err, &txErr) {
		t.Fatalf("err=%T %v, want consensus.TxError code %s", err, err, want)
	}
	if txErr.Code != want {
		t.Fatalf("err code=%s, want %s", txErr.Code, want)
	}
}

func directTipMTPTestBlock(t *testing.T, engine *SyncEngine, target [32]byte, timestamp uint64) []byte {
	t.Helper()
	view := engine.chainState.view()
	height := view.height + 1
	subsidy := consensus.BlockSubsidyBig(height, view.alreadyGenerated.Big())
	return buildSingleTxBlock(t, view.tipHash, target, timestamp, coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, height, subsidy))
}

func applyDirectTipMTPTestBlock(t *testing.T, engine *SyncEngine, target [32]byte, timestamp uint64, callerContext []uint64) ([]byte, *ChainStateConnectSummary, error) {
	t.Helper()
	block := directTipMTPTestBlock(t, engine, target, timestamp)
	summary, err := engine.ApplyBlockWithReorg(block, callerContext)
	return block, summary, err
}

func extendDirectTipMTPTestChain(t *testing.T, engine *SyncEngine, target [32]byte, throughHeight uint64) {
	t.Helper()
	for engine.chainState.view().height < throughHeight {
		height := engine.chainState.view().height + 1
		if _, _, err := applyDirectTipMTPTestBlock(t, engine, target, reorgTestTimestamp(height), nil); err != nil {
			t.Fatalf("ApplyBlockWithReorg(height=%d): %v", height, err)
		}
	}
}

type directTipStateSnapshot struct {
	view      chainStateView
	memory    chainStateDisk
	persisted chainStateDisk
	canonical []string
	mempool   MempoolStats
}

func captureDirectTipState(t *testing.T, engine *SyncEngine, store *BlockStore) directTipStateSnapshot {
	t.Helper()
	memory, err := stateToDisk(engine.chainState)
	if err != nil {
		t.Fatalf("stateToDisk(memory): %v", err)
	}
	persistedState, err := LoadChainState(engine.cfg.ChainStatePath)
	if err != nil {
		t.Fatalf("LoadChainState: %v", err)
	}
	persisted, err := stateToDisk(persistedState)
	if err != nil {
		t.Fatalf("stateToDisk(persisted): %v", err)
	}
	canonical, err := store.CanonicalIndexSnapshot()
	if err != nil {
		t.Fatalf("CanonicalIndexSnapshot: %v", err)
	}
	var mempool MempoolStats
	if engine.mempool != nil {
		mempool = engine.mempool.Stats()
	}
	return directTipStateSnapshot{engine.chainState.view(), memory, persisted, canonical, mempool}
}

func requireDirectTipStateUnchanged(t *testing.T, engine *SyncEngine, store *BlockStore, before directTipStateSnapshot) {
	t.Helper()
	if after := captureDirectTipState(t, engine, store); !reflect.DeepEqual(after, before) {
		t.Fatalf("candidate changed state:\nbefore=%+v\nafter=%+v", before, after)
	}
}

func TestApplyBlockWithReorgDerivesDirectTipMTPWhenCallerContextNil(t *testing.T) {
	dir := t.TempDir()
	store := mustCreateBlockStore(t, BlockStorePath(dir))
	target := consensus.POW_LIMIT
	engine, err := NewSyncEngine(NewChainState(), store, DefaultSyncConfig(&target, devnetGenesisChainID, ChainStatePath(dir)))
	if err != nil {
		t.Fatalf("NewSyncEngine: %v", err)
	}
	if summary, err := engine.ApplyBlockWithReorg(devnetGenesisBlockBytes, nil); err != nil || summary.BlockHeight != 0 {
		t.Fatalf("ApplyBlockWithReorg(genesis)=(%v,%v), want height zero success", summary, err)
	}
	_, _, err = applyDirectTipMTPTestBlock(t, engine, target, reorgTestTimestamp(0), nil)
	requireConsensusTxErrCode(t, err, consensus.BLOCK_ERR_TIMESTAMP_OLD)
}

func TestApplyBlockWithReorgRejectsDirectTipTimestampAtOrBelowDerivedMTP(t *testing.T) {
	tests := []struct {
		name      string
		timestamp uint64
	}{{"at_mtp", reorgTestTimestamp(0)}, {"below_mtp", reorgTestTimestamp(0) - 1}}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			engine, _, target := newReorgTestEngine(t)
			_, _, err := applyDirectTipMTPTestBlock(t, engine, target, tc.timestamp, nil)
			requireConsensusTxErrCode(t, err, consensus.BLOCK_ERR_TIMESTAMP_OLD)
		})
	}
}

func TestApplyBlockWithReorgRejectsDirectTipTimestampAboveDerivedFutureBound(t *testing.T) {
	engine, _, target := newReorgTestEngine(t)
	_, _, err := applyDirectTipMTPTestBlock(t, engine, target, reorgTestTimestamp(0)+consensus.MAX_FUTURE_DRIFT+1, nil)
	requireConsensusTxErrCode(t, err, consensus.BLOCK_ERR_TIMESTAMP_FUTURE)
}

func TestApplyBlockWithReorgIgnoresForgedCallerTimestampContext(t *testing.T) {
	t.Run("false_low_cannot_bypass", func(t *testing.T) {
		engine, _, target := newReorgTestEngine(t)
		_, _, err := applyDirectTipMTPTestBlock(t, engine, target, reorgTestTimestamp(0), []uint64{reorgTestTimestamp(0) - 1})
		requireConsensusTxErrCode(t, err, consensus.BLOCK_ERR_TIMESTAMP_OLD)
	})
	t.Run("false_high_cannot_reject", func(t *testing.T) {
		engine, _, target := newReorgTestEngine(t)
		if _, summary, err := applyDirectTipMTPTestBlock(t, engine, target, reorgTestTimestamp(1), []uint64{reorgTestTimestamp(1)}); err != nil || summary.BlockHeight != 1 {
			t.Fatalf("ApplyBlockWithReorg(valid direct child)=(%v,%v), want height one success", summary, err)
		}
	})
}

func TestApplyBlockWithReorgTimestampFailureDoesNotMutateState(t *testing.T) {
	engine, store, target := newReorgTestEngine(t)
	mempool, err := NewMempool(engine.chainState, store, devnetGenesisChainID)
	if err != nil {
		t.Fatalf("NewMempool: %v", err)
	}
	engine.SetMempool(mempool)
	block := directTipMTPTestBlock(t, engine, target, reorgTestTimestamp(0))
	blockHash, err := consensus.BlockHash(blockHeaderBytes(t, block))
	if err != nil {
		t.Fatalf("BlockHash: %v", err)
	}
	beforeState := captureDirectTipState(t, engine, store)
	beforeCounts := engine.BlockApplyCounts()
	_, err = engine.ApplyBlockWithReorg(block, nil)
	requireConsensusTxErrCode(t, err, consensus.BLOCK_ERR_TIMESTAMP_OLD)
	requireDirectTipStateUnchanged(t, engine, store, beforeState)
	if got := engine.BlockApplyCounts(); got.Accepted != beforeCounts.Accepted || got.Rejected != beforeCounts.Rejected+1 {
		t.Fatalf("BlockApplyCounts=%+v, want accepted=%d rejected=%d", got, beforeCounts.Accepted, beforeCounts.Rejected+1)
	}
	if canonical, ok, err := store.CanonicalHash(0); err != nil || !ok || canonical != devnetGenesisBlockHash {
		t.Fatalf("CanonicalHash(0)=(%x,%v,%v), want genesis", canonical, ok, err)
	}
	if _, err := store.GetBlockByHash(blockHash); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("GetBlockByHash(rejected) err=%v, want not-exist", err)
	}
}

func TestApplyBlockWithReorgRejectsMissingDirectTipTimestampHistory(t *testing.T) {
	tests := []struct {
		name      string
		setup     func(*testing.T, *SyncEngine, *BlockStore)
		wantExact string
		wantCode  consensus.ErrorCode
	}{
		{"nil_blockstore", func(_ *testing.T, e *SyncEngine, _ *BlockStore) { e.blockStore = nil }, "missing blockstore for direct-tip timestamp context", ""},
		{"missing_hash", func(t *testing.T, _ *SyncEngine, s *BlockStore) {
			if err := s.TruncateCanonical(0); err != nil {
				t.Fatalf("TruncateCanonical: %v", err)
			}
		}, "missing canonical hash at height 0 for timestamp context (next_height=1)", ""},
		// RUB-655 ordering: target context precedes the MTP window, so a
		// missing selected-parent header is now the primitive's documented
		// ErrParentNotFound instead of the MTP read's raw os.ErrNotExist.
		// Rejected either way, and nothing is stored.
		{"missing_header", func(t *testing.T, _ *SyncEngine, s *BlockStore) {
			if err := os.Remove(filepath.Join(s.headersDir, hex.EncodeToString(devnetGenesisBlockHash[:])+".bin")); err != nil {
				t.Fatalf("Remove(header): %v", err)
			}
		}, ErrParentNotFound.Error(), ""},
		{"malformed_header", func(t *testing.T, _ *SyncEngine, s *BlockStore) {
			if err := os.WriteFile(filepath.Join(s.headersDir, hex.EncodeToString(devnetGenesisBlockHash[:])+".bin"), []byte{0}, 0o600); err != nil {
				t.Fatalf("WriteFile(header): %v", err)
			}
		}, "", consensus.TX_ERR_PARSE},
		{"height_overflow", func(_ *testing.T, e *SyncEngine, _ *BlockStore) {
			e.chainState.mu.Lock()
			e.chainState.Height = ^uint64(0)
			e.chainState.mu.Unlock()
		}, "height overflow", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			engine, store, target := newReorgTestEngine(t)
			block := directTipMTPTestBlock(t, engine, target, reorgTestTimestamp(1))
			blockHash, err := consensus.BlockHash(blockHeaderBytes(t, block))
			if err != nil {
				t.Fatalf("BlockHash: %v", err)
			}
			tc.setup(t, engine, store)
			beforeState := captureDirectTipState(t, engine, store)
			beforeCounts := engine.BlockApplyCounts()
			_, err = engine.ApplyBlockWithReorg(block, []uint64{reorgTestTimestamp(0)})
			switch {
			case tc.wantExact != "" && (err == nil || err.Error() != tc.wantExact):
				t.Fatalf("err=%v, want %q", err, tc.wantExact)
			case tc.wantCode != "":
				requireConsensusTxErrCode(t, err, tc.wantCode)
			}
			requireDirectTipStateUnchanged(t, engine, store, beforeState)
			if got := engine.BlockApplyCounts(); got != beforeCounts {
				t.Fatalf("BlockApplyCounts changed from %+v to %+v", beforeCounts, got)
			}
			if _, err := store.GetBlockByHash(blockHash); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("GetBlockByHash(rejected) err=%v, want not-exist", err)
			}
		})
	}
}

func TestApplyBlockWithReorgDirectTipMTPWindowBoundaries(t *testing.T) {
	tests := []struct {
		name       string
		nextHeight uint64
		mtpOffset  uint64
	}{{"height_10_window_10", 10, 4}, {"height_11_window_11", 11, 5}, {"height_12_slides_past_genesis", 12, 6}}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			engine, _, target := newReorgTestEngine(t)
			extendDirectTipMTPTestChain(t, engine, target, tc.nextHeight-1)
			_, _, err := applyDirectTipMTPTestBlock(t, engine, target, reorgTestTimestamp(tc.mtpOffset), nil)
			requireConsensusTxErrCode(t, err, consensus.BLOCK_ERR_TIMESTAMP_OLD)
		})
	}
}

func TestApplyBlockWithReorgRejectThenValidPreservesState(t *testing.T) {
	engine, store, target := newReorgTestEngine(t)
	beforeState := captureDirectTipState(t, engine, store)
	beforeCounts := engine.BlockApplyCounts()
	_, _, err := applyDirectTipMTPTestBlock(t, engine, target, reorgTestTimestamp(0), nil)
	requireConsensusTxErrCode(t, err, consensus.BLOCK_ERR_TIMESTAMP_OLD)
	requireDirectTipStateUnchanged(t, engine, store, beforeState)
	_, summary, err := applyDirectTipMTPTestBlock(t, engine, target, reorgTestTimestamp(1), nil)
	if err != nil || summary.BlockHeight != 1 || engine.chainState.view().tipHash != summary.BlockHash {
		t.Fatalf("ApplyBlockWithReorg(valid recovery)=(%v,%v), want canonical height one", summary, err)
	}
	if got := engine.BlockApplyCounts(); got.Accepted != beforeCounts.Accepted+1 || got.Rejected != beforeCounts.Rejected+1 {
		t.Fatalf("BlockApplyCounts=%+v, want accepted=%d rejected=%d", got, beforeCounts.Accepted+1, beforeCounts.Rejected+1)
	}
}

func TestApplyBlockWithReorgRejectsMissingParent(t *testing.T) {
	engine, _, target := newReorgTestEngine(t)
	before := engine.BlockApplyCounts()
	var missingParent [32]byte
	missingParent[0] = 0x42
	block := buildSingleTxBlock(t, missingParent, target, 77, coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 1, consensus.BlockSubsidy(1, 0)))
	if _, err := engine.ApplyBlockWithReorg(block, nil); !errors.Is(err, ErrParentNotFound) {
		t.Fatalf("ApplyBlockWithReorg(missing parent) err=%v, want ErrParentNotFound", err)
	}
	if after := engine.BlockApplyCounts(); after != before {
		t.Fatalf("missing-parent block changed BlockApplyCounts from %+v to %+v", before, after)
	}
}

func TestApplyBlockWithReorgRejectsInvalidNonHeavierSideBranch(t *testing.T) {
	engine, store, target := newReorgTestEngine(t)

	subsidy1 := consensus.BlockSubsidy(1, 0)
	blockA1 := buildSingleTxBlock(t, devnetGenesisBlockHash, target, reorgTestTimestamp(1), coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 1, subsidy1))
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
	beforeInvalidSide := engine.BlockApplyCounts()
	if _, err := engine.ApplyBlockWithReorg(invalidB1, nil); err == nil {
		t.Fatalf("expected invalid competing branch rejection")
	}
	if after := engine.BlockApplyCounts(); after != beforeInvalidSide {
		t.Fatalf("invalid non-canonical side branch changed BlockApplyCounts from %+v to %+v", beforeInvalidSide, after)
	}

	if engine.chainState.Height != 1 || engine.chainState.TipHash != summaryA1.BlockHash {
		t.Fatalf("canonical tip changed after invalid competing branch")
	}
	if _, err := store.GetBlockByHash(invalidB1Hash); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("GetBlockByHash(invalid B1) err=%v, want not-exist", err)
	}
}

func TestApplyBlockWithReorgRejectsSideBranchTimestampContextBeforeStore(t *testing.T) {
	engine, store, target := newReorgTestEngine(t)
	genesisParsed, err := consensus.ParseBlockBytes(devnetGenesisBlockBytes)
	if err != nil {
		t.Fatalf("ParseBlockBytes(genesis): %v", err)
	}

	subsidy1 := consensus.BlockSubsidy(1, 0)
	blockA1 := buildSingleTxBlock(t, devnetGenesisBlockHash, target, reorgTestTimestamp(1), coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 1, subsidy1))
	summaryA1, err := engine.ApplyBlock(blockA1, nil)
	if err != nil {
		t.Fatalf("ApplyBlock(A1): %v", err)
	}
	subsidy2 := consensus.BlockSubsidy(2, subsidy1)
	blockA2 := buildSingleTxBlock(t, summaryA1.BlockHash, target, reorgTestTimestamp(2), coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 2, subsidy2))
	summaryA2, err := engine.ApplyBlock(blockA2, nil)
	if err != nil {
		t.Fatalf("ApplyBlock(A2): %v", err)
	}

	tests := []struct {
		name      string
		timestamp uint64
		wantCode  consensus.ErrorCode
	}{
		{
			name:      "timestamp_old",
			timestamp: genesisParsed.Header.Timestamp,
			wantCode:  consensus.BLOCK_ERR_TIMESTAMP_OLD,
		},
		{
			name:      "timestamp_future",
			timestamp: genesisParsed.Header.Timestamp + consensus.MAX_FUTURE_DRIFT + 1,
			wantCode:  consensus.BLOCK_ERR_TIMESTAMP_FUTURE,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sideBlock := buildSingleTxBlock(t, devnetGenesisBlockHash, target, tc.timestamp, coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 1, subsidy1))
			sideHash, err := consensus.BlockHash(blockHeaderBytes(t, sideBlock))
			if err != nil {
				t.Fatalf("BlockHash(side): %v", err)
			}

			before := engine.BlockApplyCounts()
			summary, err := engine.ApplyBlockWithReorg(sideBlock, nil)
			if err == nil {
				t.Fatalf("expected timestamp-invalid side branch rejection")
			}
			if summary != nil {
				t.Fatalf("summary=%v, want nil for rejected side branch", summary)
			}
			requireConsensusTxErrCode(t, err, tc.wantCode)
			if after := engine.BlockApplyCounts(); after != before {
				t.Fatalf("timestamp-invalid side branch changed BlockApplyCounts from %+v to %+v", before, after)
			}
			if engine.chainState.Height != 2 || engine.chainState.TipHash != summaryA2.BlockHash {
				t.Fatalf("canonical tip changed after timestamp-invalid side branch")
			}
			if _, err := store.GetBlockByHash(sideHash); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("GetBlockByHash(timestamp-invalid side) err=%v, want not-exist", err)
			}
		})
	}
}

func TestApplyBlockWithReorgRollbackRestoresCanonicalIndexAndChainstateFile(t *testing.T) {
	dir := t.TempDir()
	chainStatePath := ChainStatePath(dir)
	store, err := CreateBlockStore(BlockStorePath(dir))
	if err != nil {
		t.Fatalf("CreateBlockStore: %v", err)
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
	blockA1 := buildSingleTxBlock(t, devnetGenesisBlockHash, target, reorgTestTimestamp(1), coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 1, subsidy1))
	summaryA1, err := engine.ApplyBlock(blockA1, nil)
	if err != nil {
		t.Fatalf("ApplyBlock(A1): %v", err)
	}
	beforeState, err := stateToDisk(engine.chainState)
	if err != nil {
		t.Fatalf("stateToDisk(before): %v", err)
	}

	sideB1 := buildSingleTxBlock(t, devnetGenesisBlockHash, target, reorgTestTimestamp(2), coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 1, subsidy1))
	sideB1Hash, err := consensus.BlockHash(blockHeaderBytes(t, sideB1))
	if err != nil {
		t.Fatalf("BlockHash(B1): %v", err)
	}
	if _, err := engine.ApplyBlockWithReorg(sideB1, nil); err != nil {
		t.Fatalf("ApplyBlockWithReorg(B1): %v", err)
	}

	subsidy2 := consensus.BlockSubsidy(2, subsidy1)
	sideB2 := buildSingleTxBlock(t, sideB1Hash, target, reorgTestTimestamp(3), coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 2, subsidy2))

	prevWrite := writeFileAtomicFn
	t.Cleanup(func() { writeFileAtomicFn = prevWrite })
	indexWriteCount := 0
	writeFileAtomicFn = func(path string, data []byte, mode os.FileMode) error {
		if path == store.indexPath {
			indexWriteCount++
			// One prepared commit per transition: this IS the reorg's write.
			if indexWriteCount == 1 {
				return newAtomicWriteError(atomicWriteBeforeNamespaceCommit, path, atomicWriteOverwrite, os.ErrPermission)
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
	if _, err := chainStateFromDisk(beforeState); err != nil {
		t.Fatalf("chainStateFromDisk(before): %v", err)
	}
	// The durable snapshot is the common-ancestor CHECKPOINT the precommit
	// recovery set replaced it with. That row belongs to BOTH identities, so the
	// refused reorg did not destroy the last usable old snapshot: replaying the
	// retained old suffix from it reproduces the exact preserved OLD image.
	if !afterState.HasTip || afterState.Height != 0 || afterState.TipHash != devnetGenesisBlockHash {
		t.Fatalf("persisted checkpoint=(%v,%d,%x), want the common ancestor", afterState.HasTip, afterState.Height, afterState.TipHash)
	}
	if changed, err := ReconcileChainStateWithBlockStore(afterState, store, engine.cfg); err != nil || !changed || afterState.Height != 1 || afterState.TipHash != summaryA1.BlockHash {
		t.Fatalf("checkpoint replay=(%d,%x) changed=%v err=%v, want the preserved OLD identity", afterState.Height, afterState.TipHash, changed, err)
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
	blockA1 := buildSingleTxBlock(t, devnetGenesisBlockHash, target, reorgTestTimestamp(1), coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 1, subsidy1))
	summaryA1, err := engine.ApplyBlock(blockA1, nil)
	if err != nil {
		t.Fatalf("ApplyBlock(A1): %v", err)
	}
	subsidy2 := consensus.BlockSubsidy(2, subsidy1)
	blockA2 := buildSingleTxBlock(t, summaryA1.BlockHash, target, reorgTestTimestamp(2), coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 2, subsidy2))
	summaryA2, err := engine.ApplyBlock(blockA2, nil)
	if err != nil {
		t.Fatalf("ApplyBlock(A2): %v", err)
	}

	blockB1 := buildSingleTxBlock(t, devnetGenesisBlockHash, target, reorgTestTimestamp(10), coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 1, subsidy1))
	if _, err := engine.ApplyBlockWithReorg(blockB1, nil); err != nil {
		t.Fatalf("ApplyBlockWithReorg(B1): %v", err)
	}
	blockB1Hash, err := consensus.BlockHash(blockHeaderBytes(t, blockB1))
	if err != nil {
		t.Fatalf("BlockHash(B1): %v", err)
	}
	blockB2 := buildSingleTxBlock(t, blockB1Hash, target, reorgTestTimestamp(11), coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 2, subsidy2))
	if _, err := engine.ApplyBlockWithReorg(blockB2, nil); err != nil {
		t.Fatalf("ApplyBlockWithReorg(B2): %v", err)
	}
	blockB2Hash, err := consensus.BlockHash(blockHeaderBytes(t, blockB2))
	if err != nil {
		t.Fatalf("BlockHash(B2): %v", err)
	}

	subsidy3 := consensus.BlockSubsidy(3, subsidy1+subsidy2)
	validB3 := buildSingleTxBlock(t, blockB2Hash, target, reorgTestTimestamp(12), coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 3, subsidy3))
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
	if _, err := nilEngine.applyCanonicalParsedBlock(nil, nil, nil, nil, nil); err == nil {
		t.Fatalf("expected nil sync engine error")
	}

	target := consensus.POW_LIMIT
	newEmptyEngine := func(t *testing.T, chainID [32]byte) *SyncEngine {
		t.Helper()
		dir := t.TempDir()
		store, err := CreateBlockStore(BlockStorePath(dir))
		if err != nil {
			t.Fatalf("CreateBlockStore: %v", err)
		}
		engine, err := NewSyncEngine(NewChainState(), store, DefaultSyncConfig(&target, chainID, ChainStatePath(dir)))
		if err != nil {
			t.Fatalf("NewSyncEngine: %v", err)
		}
		return engine
	}

	engine := newEmptyEngine(t, devnetGenesisChainID)
	if _, err := engine.applyCanonicalParsedBlock(nil, nil, nil, nil, nil); err == nil {
		t.Fatalf("expected nil parsed block error")
	}

	engine = newEmptyEngine(t, [32]byte{0x99})
	if _, err := engine.ApplyBlock(devnetGenesisBlockBytes, nil); err == nil {
		t.Fatalf("expected genesis chain_id mismatch")
	}
	if got := engine.BlockApplyCounts(); got.Accepted != 0 || got.Rejected != 1 {
		t.Fatalf("genesis chain_id mismatch BlockApplyCounts=%+v, want accepted=0 rejected=1", got)
	}

	engine = newEmptyEngine(t, devnetGenesisChainID)
	badGenesis := buildSingleTxBlock(t, [32]byte{}, target, reorgTestTimestamp(1), coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 0, 0))
	if _, err := engine.ApplyBlock(badGenesis, nil); err == nil {
		t.Fatalf("expected genesis_hash mismatch")
	}
	if got := engine.BlockApplyCounts(); got.Accepted != 0 || got.Rejected != 1 {
		t.Fatalf("genesis_hash mismatch BlockApplyCounts=%+v, want accepted=0 rejected=1", got)
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
		100_000,
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
		reorgTestCoinbaseForWtxids(t, 101, subsidyA101+100_000, sourceAddress, [][32]byte{{}, spendWtxid}),
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

func TestRequeueDisconnectedTransactionsUsesTipDownOrderAndContinuesAfterReject(t *testing.T) {
	fromKey := mustReorgMLDSA87Keypair(t)
	toKey := mustReorgMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	toAddress := consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes())
	st, outpoints := testSpendableChainState(fromAddress, []uint64{
		1_000_000,
		1_000_000,
		1_000_000,
		1_000_000,
	})
	mempool, err := NewMempool(st, nil, devnetGenesisChainID)
	if err != nil {
		t.Fatalf("NewMempool: %v", err)
	}
	var stderr bytes.Buffer
	engine := &SyncEngine{mempool: mempool, stderr: &stderr}

	txHighFirst := mustBuildSignedTransferTxForSyncTest(t, st.Utxos, []consensus.Outpoint{outpoints[0]}, 100_000, 200_000, 1, fromKey, fromAddress, toAddress)
	txRejectedDuplicate := mustBuildSignedTransferTxForSyncTest(t, st.Utxos, []consensus.Outpoint{outpoints[1]}, 100_000, 200_000, 2, fromKey, fromAddress, toAddress)
	txHighAfterReject := mustBuildSignedTransferTxForSyncTest(t, st.Utxos, []consensus.Outpoint{outpoints[2]}, 100_000, 200_000, 3, fromKey, fromAddress, toAddress)
	txLow := mustBuildSignedTransferTxForSyncTest(t, st.Utxos, []consensus.Outpoint{outpoints[3]}, 100_000, 200_000, 4, fromKey, fromAddress, toAddress)
	if err := mempool.AddTx(txRejectedDuplicate); err != nil {
		t.Fatalf("AddTx(duplicate setup): %v", err)
	}
	seqBeforeRequeue := mempool.lastAdmissionSeq

	_, _, highFirstWtxid, _, err := consensus.ParseTx(txHighFirst)
	if err != nil {
		t.Fatalf("ParseTx(txHighFirst): %v", err)
	}
	_, _, rejectedWtxid, _, err := consensus.ParseTx(txRejectedDuplicate)
	if err != nil {
		t.Fatalf("ParseTx(txRejectedDuplicate): %v", err)
	}
	_, _, highAfterWtxid, _, err := consensus.ParseTx(txHighAfterReject)
	if err != nil {
		t.Fatalf("ParseTx(txHighAfterReject): %v", err)
	}
	_, _, lowWtxid, _, err := consensus.ParseTx(txLow)
	if err != nil {
		t.Fatalf("ParseTx(txLow): %v", err)
	}

	blockHigh := buildMultiTxBlock(
		t,
		[32]byte{0xa1},
		consensus.POW_LIMIT,
		reorgTestTimestamp(202),
		reorgTestCoinbaseForWtxids(t, 202, consensus.BlockSubsidy(202, 0)+600_000, fromAddress, [][32]byte{{}, highFirstWtxid, rejectedWtxid, highAfterWtxid}),
		txHighFirst,
		txRejectedDuplicate,
		txHighAfterReject,
	)
	blockLow := buildMultiTxBlock(
		t,
		[32]byte{0xa0},
		consensus.POW_LIMIT,
		reorgTestTimestamp(201),
		reorgTestCoinbaseForWtxids(t, 201, consensus.BlockSubsidy(201, 0)+200_000, fromAddress, [][32]byte{{}, lowWtxid}),
		txLow,
	)

	highParsed, err := consensus.ParseBlockBytes(blockHigh)
	if err != nil {
		t.Fatalf("ParseBlockBytes(high): %v", err)
	}
	lowParsed, err := consensus.ParseBlockBytes(blockLow)
	if err != nil {
		t.Fatalf("ParseBlockBytes(low): %v", err)
	}
	engine.requeueParsedDisconnectedTransactions([]*consensus.ParsedBlock{highParsed, lowParsed}, nil)

	if !strings.Contains(stderr.String(), "mempool: requeue-tx:") {
		t.Fatalf("expected duplicate requeue rejection to be logged, got %q", stderr.String())
	}
	for _, tc := range []struct {
		name string
		tx   []byte
		seq  uint64
	}{
		{name: "high_first", tx: txHighFirst, seq: seqBeforeRequeue + 1},
		{name: "high_after_reject", tx: txHighAfterReject, seq: seqBeforeRequeue + 2},
		{name: "low", tx: txLow, seq: seqBeforeRequeue + 3},
	} {
		txid := txID(t, tc.tx)
		entry := mempool.txs[txid]
		if entry == nil {
			t.Fatalf("%s requeued tx %x missing", tc.name, txid)
		}
		if entry.source != mempoolTxSourceReorg {
			t.Fatalf("%s source=%q, want %q", tc.name, entry.source, mempoolTxSourceReorg)
		}
		if entry.admissionSeq != tc.seq {
			t.Fatalf("%s admissionSeq=%d, want %d", tc.name, entry.admissionSeq, tc.seq)
		}
	}
	duplicateEntry := mempool.txs[txID(t, txRejectedDuplicate)]
	if duplicateEntry == nil {
		t.Fatalf("duplicate setup tx missing after requeue")
	}
	if duplicateEntry.source != mempoolTxSourceLocal || duplicateEntry.admissionSeq != seqBeforeRequeue {
		t.Fatalf("duplicate setup entry changed source/seq: source=%q seq=%d", duplicateEntry.source, duplicateEntry.admissionSeq)
	}
}

func TestRequeueDisconnectedTransactionsUsesAdmissionFeeFloor(t *testing.T) {
	fromKey := mustReorgMLDSA87Keypair(t)
	toKey := mustReorgMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	toAddress := consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes())
	st, outpoints := testSpendableChainState(fromAddress, []uint64{1_000_000})
	mempool, err := NewMempool(st, nil, devnetGenesisChainID)
	if err != nil {
		t.Fatalf("NewMempool: %v", err)
	}
	mempool.currentMinFeeRate = 8
	var stderr bytes.Buffer
	engine := &SyncEngine{mempool: mempool, stderr: &stderr}

	txBelowFloor := mustBuildSignedTransferTxForSyncTest(t, st.Utxos, []consensus.Outpoint{outpoints[0]}, 100_000, 1, 1, fromKey, fromAddress, toAddress)
	_, _, belowFloorWtxid, _, err := consensus.ParseTx(txBelowFloor)
	if err != nil {
		t.Fatalf("ParseTx(txBelowFloor): %v", err)
	}
	block := buildMultiTxBlock(
		t,
		[32]byte{0xb0},
		consensus.POW_LIMIT,
		reorgTestTimestamp(203),
		reorgTestCoinbaseForWtxids(t, 203, consensus.BlockSubsidy(203, 0)+1, fromAddress, [][32]byte{{}, belowFloorWtxid}),
		txBelowFloor,
	)

	engine.requeueDisconnectedTransactions([][]byte{block})

	if !strings.Contains(stderr.String(), "mempool fee below rolling minimum") {
		t.Fatalf("expected rolling-floor rejection in stderr, got %q", stderr.String())
	}
	if got := mempool.Len(); got != 0 {
		t.Fatalf("mempool len after below-floor requeue=%d, want 0", got)
	}
	if mempool.Contains(txID(t, txBelowFloor)) {
		t.Fatalf("below-floor requeue tx entered mempool")
	}
	if mempool.lastAdmissionSeq != 0 {
		t.Fatalf("lastAdmissionSeq after below-floor requeue=%d, want 0", mempool.lastAdmissionSeq)
	}
	if got := mempool.currentMinFeeRate; got != 8 {
		t.Fatalf("currentMinFeeRate after below-floor requeue=%d, want 8", got)
	}
}

func TestApplyBlockDecaysMempoolFloorAfterConflictRemoval(t *testing.T) {
	engine, store, target := newReorgTestEngine(t)

	sourceKP := mustReorgMLDSA87Keypair(t)
	destKP := mustReorgMLDSA87Keypair(t)
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

	blockTx := mustBuildSignedTransferTxForSyncTest(
		t,
		engine.chainState.Utxos,
		[]consensus.Outpoint{sourceOutpoint},
		700,
		100_000,
		1,
		sourceKP,
		sourceAddress,
		destAddress,
	)
	conflictingTx := mustBuildSignedTransferTxForSyncTest(
		t,
		engine.chainState.Utxos,
		[]consensus.Outpoint{sourceOutpoint},
		690,
		100_000,
		2,
		sourceKP,
		sourceAddress,
		destAddress,
	)
	mempool, err := NewMempoolWithConfig(engine.chainState, store, devnetGenesisChainID, MempoolConfig{
		MaxTransactions: 10,
		MaxBytes:        len(conflictingTx),
	})
	if err != nil {
		t.Fatalf("NewMempoolWithConfig: %v", err)
	}
	engine.SetMempool(mempool)
	if err := mempool.AddTx(conflictingTx); err != nil {
		t.Fatalf("AddTx(conflicting): %v", err)
	}
	mempool.currentMinFeeRate = 8
	if mempool.usedBytes < mempool.effectiveLowWaterBytesLocked() {
		t.Fatalf("test setup usedBytes=%d below lowWater=%d before block apply", mempool.usedBytes, mempool.effectiveLowWaterBytesLocked())
	}

	_, _, blockWtxid, _, err := consensus.ParseTx(blockTx)
	if err != nil {
		t.Fatalf("ParseTx(blockTx): %v", err)
	}
	subsidy := consensus.BlockSubsidy(101, alreadyGenerated)
	block := buildMultiTxBlock(
		t,
		prevHash,
		target,
		202,
		reorgTestCoinbaseForWtxids(t, 101, subsidy+100_000, sourceAddress, [][32]byte{{}, blockWtxid}),
		blockTx,
	)
	if _, err := engine.ApplyBlock(block, nil); err != nil {
		t.Fatalf("ApplyBlock(conflicting connected block): %v", err)
	}
	if got := mempool.Len(); got != 0 {
		t.Fatalf("mempool len after conflict removal=%d, want 0", got)
	}
	if got := mempool.currentMinFeeRate; got != 4 {
		t.Fatalf("currentMinFeeRate after connected block conflict removal=%d, want 4", got)
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
			Value:             1_000_000,
			CovenantType:      consensus.COV_TYPE_P2PK,
			CovenantData:      append([]byte(nil), sourceAddressA...),
			CreationHeight:    0,
			CreatedByCoinbase: false,
		},
		sourceOutpointB: {
			Value:             1_000_000,
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
		100_000,
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
		100_000,
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
		reorgTestTimestamp(1),
		reorgTestCoinbaseForWtxids(t, 1, subsidy1+100_000, sourceAddressA, [][32]byte{{}, blockASpendWtxid}),
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
		reorgTestTimestamp(2),
		reorgTestCoinbaseForWtxids(t, 1, subsidy1+100_000, destAddressB, [][32]byte{{}, blockBSpendWtxid}),
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
		reorgTestTimestamp(3),
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
		100_000,
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
	subsidyB101 := consensus.BlockSubsidy(101, alreadyGenerated)
	blockB101 := buildMultiTxBlock(
		t,
		prevHash,
		target,
		203,
		reorgTestCoinbaseForWtxids(t, 101, subsidyB101+100_000, destAddress, [][32]byte{{}, spendWtxid}),
		spendTx,
	)
	blockA101, blockA101Hash, blockB101, blockB101Hash := orderedEqualWorkBlockVariants(t, blockA101, blockB101)
	summaryA101, err := engine.ApplyBlock(blockA101, nil)
	if err != nil {
		t.Fatalf("ApplyBlock(A101): %v", err)
	}
	if summaryA101.BlockHash != blockA101Hash {
		t.Fatalf("A101 hash=%x, want %x", summaryA101.BlockHash, blockA101Hash)
	}
	if got := mempool.Len(); got != 1 {
		t.Fatalf("mempool len after A101=%d, want 1", got)
	}

	if _, err := engine.ApplyBlockWithReorg(blockB101, nil); err != nil {
		t.Fatalf("ApplyBlockWithReorg(B101): %v", err)
	}
	if engine.chainState.TipHash != blockA101Hash {
		t.Fatalf("B101 equal-work side branch changed canonical tip to %x, want A101 %x", engine.chainState.TipHash, blockA101Hash)
	}

	subsidyB102 := consensus.BlockSubsidy(102, alreadyGenerated+subsidyB101)
	blockB102 := buildSingleTxBlock(t, blockB101Hash, target, 204, reorgTestCoinbaseForAddress(t, 102, subsidyB102, destAddress))

	beforeReorgCounts := engine.BlockApplyCounts()
	var duringFailedCommitCounts BlockApplyCounts
	observedFailedCommit := false
	prevWrite := writeFileAtomicFn
	t.Cleanup(func() { writeFileAtomicFn = prevWrite })
	indexWrites := 0
	writeFileAtomicFn = func(path string, data []byte, mode os.FileMode) error {
		if path == store.indexPath {
			indexWrites++
			if indexWrites == 1 {
				observedFailedCommit = true
				duringFailedCommitCounts = engine.BlockApplyCounts()
				return newAtomicWriteError(atomicWriteBeforeNamespaceCommit, path, atomicWriteOverwrite, os.ErrPermission)
			}
		}
		return prevWrite(path, data, mode)
	}

	if _, err := engine.ApplyBlockWithReorg(blockB102, nil); err == nil {
		t.Fatalf("expected reorg persist failure")
	}
	if !observedFailedCommit {
		t.Fatalf("expected forced index write failure to be observed")
	}
	if duringFailedCommitCounts != beforeReorgCounts {
		t.Fatalf("speculative reorg apply published BlockApplyCounts before rollback: got %+v want %+v", duringFailedCommitCounts, beforeReorgCounts)
	}
	if after := engine.BlockApplyCounts(); after != beforeReorgCounts {
		t.Fatalf("failed reorg changed BlockApplyCounts from %+v to %+v", beforeReorgCounts, after)
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
	emptyStore, err := CreateBlockStore(BlockStorePath(emptyDir))
	if err != nil {
		t.Fatalf("CreateBlockStore(empty): %v", err)
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
	switchBranch, height, err := engine.shouldSwitchToBranch(nil, devnetGenesisBlockHash, 0)
	if err == nil {
		t.Fatalf("shouldSwitchToBranch(empty branch) err=nil, want error")
	}
	if switchBranch || height != 0 {
		t.Fatalf("shouldSwitchToBranch(empty branch)=(%v,%d), want (false,0)", switchBranch, height)
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
	blockA1 := buildSingleTxBlock(t, devnetGenesisBlockHash, target, reorgTestTimestamp(1), coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 1, subsidy1))
	summaryA1, err := engine.ApplyBlock(blockA1, nil)
	if err != nil {
		t.Fatalf("ApplyBlock(A1): %v", err)
	}

	subsidy2 := consensus.BlockSubsidy(2, subsidy1)
	blockA2 := buildSingleTxBlock(t, summaryA1.BlockHash, target, reorgTestTimestamp(2), coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 2, subsidy2))
	summaryA2, err := engine.ApplyBlock(blockA2, nil)
	if err != nil {
		t.Fatalf("ApplyBlock(A2): %v", err)
	}

	sideB1 := buildSingleTxBlock(t, devnetGenesisBlockHash, target, reorgTestTimestamp(3), coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 1, subsidy1))
	beforeSide := engine.BlockApplyCounts()
	sideSummary, err := engine.ApplyBlockWithReorg(sideB1, nil)
	if err != nil {
		t.Fatalf("ApplyBlockWithReorg(B1): %v", err)
	}
	if after := engine.BlockApplyCounts(); after != beforeSide {
		t.Fatalf("lighter side branch changed BlockApplyCounts from %+v to %+v", beforeSide, after)
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

func TestApplyBlockWithReorgSwitchesToLowerTipOnEqualWork(t *testing.T) {
	engine, store, target := newReorgTestEngine(t)
	lowerBlock, lowerHash, higherBlock, higherHash := equalWorkCompetingHeightOneBlocks(t, target)

	higherSummary, err := engine.ApplyBlock(higherBlock, nil)
	if err != nil {
		t.Fatalf("ApplyBlock(higher): %v", err)
	}
	if higherSummary.BlockHash != higherHash {
		t.Fatalf("higher block hash=%x, want %x", higherSummary.BlockHash, higherHash)
	}

	before := engine.BlockApplyCounts()
	lowerSummary, err := engine.ApplyBlockWithReorg(lowerBlock, nil)
	if err != nil {
		t.Fatalf("ApplyBlockWithReorg(lower equal-work): %v", err)
	}
	if lowerSummary.BlockHash != lowerHash {
		t.Fatalf("lower summary hash=%x, want %x", lowerSummary.BlockHash, lowerHash)
	}
	if engine.chainState.Height != 1 || engine.chainState.TipHash != lowerHash {
		t.Fatalf("canonical tip=%d/%x, want 1/%x", engine.chainState.Height, engine.chainState.TipHash, lowerHash)
	}
	if depth := engine.LastReorgDepth(); depth != 1 {
		t.Fatalf("LastReorgDepth()=%d, want 1", depth)
	}
	if count := engine.ReorgCount(); count != 1 {
		t.Fatalf("ReorgCount()=%d, want 1", count)
	}
	if after := engine.BlockApplyCounts(); after.Accepted != before.Accepted+1 || after.Rejected != before.Rejected {
		t.Fatalf("equal-work reorg counts=%+v, want accepted=%d rejected=%d", after, before.Accepted+1, before.Rejected)
	}
	canonicalHash, ok, err := store.CanonicalHash(1)
	if err != nil || !ok {
		t.Fatalf("CanonicalHash(1): ok=%v err=%v", ok, err)
	}
	if canonicalHash != lowerHash {
		t.Fatalf("canonical height 1 hash=%x, want lower %x; higher was %x", canonicalHash, lowerHash, higherHash)
	}
}

func TestApplyBlockWithReorgKeepsLowerTipOnEqualWorkHigherSideBranch(t *testing.T) {
	engine, store, target := newReorgTestEngine(t)
	lowerBlock, lowerHash, higherBlock, higherHash := equalWorkCompetingHeightOneBlocks(t, target)

	lowerSummary, err := engine.ApplyBlock(lowerBlock, nil)
	if err != nil {
		t.Fatalf("ApplyBlock(lower): %v", err)
	}
	if lowerSummary.BlockHash != lowerHash {
		t.Fatalf("lower block hash=%x, want %x", lowerSummary.BlockHash, lowerHash)
	}

	before := engine.BlockApplyCounts()
	higherSummary, err := engine.ApplyBlockWithReorg(higherBlock, nil)
	if err != nil {
		t.Fatalf("ApplyBlockWithReorg(higher equal-work): %v", err)
	}
	if after := engine.BlockApplyCounts(); after != before {
		t.Fatalf("higher equal-work side branch changed BlockApplyCounts from %+v to %+v", before, after)
	}
	if higherSummary.BlockHeight != 1 || higherSummary.BlockHash != higherHash {
		t.Fatalf("higher side summary=%d/%x, want 1/%x", higherSummary.BlockHeight, higherSummary.BlockHash, higherHash)
	}
	if engine.chainState.Height != 1 || engine.chainState.TipHash != lowerHash {
		t.Fatalf("canonical tip=%d/%x, want 1/%x", engine.chainState.Height, engine.chainState.TipHash, lowerHash)
	}
	canonicalHash, ok, err := store.CanonicalHash(1)
	if err != nil || !ok {
		t.Fatalf("CanonicalHash(1): ok=%v err=%v", ok, err)
	}
	if canonicalHash != lowerHash {
		t.Fatalf("canonical height 1 hash=%x, want lower %x; higher was %x", canonicalHash, lowerHash, higherHash)
	}
	if _, err := store.GetBlockByHash(higherHash); err != nil {
		t.Fatalf("GetBlockByHash(higher side): %v", err)
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

	store := mustCreateBlockStore(t, filepath.Join(t.TempDir(), "blockstore"))
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
	if _, err := engine.canonicalIndexPreflight(); err == nil {
		t.Fatalf("expected canonicalIndexPreflight snapshot error")
	}

	engine, _, _ = newReorgTestEngine(t)
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

// TestSideBlockStoreFailureNeverLatches pins the LOCAL_STORE_ERROR(noncanonical)
// disposition: a side branch that loses fork choice touches no canonical state,
// so even an AMBIGUOUS post-namespace-commit write failure while storing it is
// NOT_APPLICABLE to canonical truth. It is returned, it latches nothing, and the
// engine keeps applying canonical blocks afterwards.
func TestSideBlockStoreFailureNeverLatches(t *testing.T) {
	engine, store, target := newReorgTestEngine(t)
	subsidy1 := consensus.BlockSubsidy(1, 0)
	blockA1 := buildSingleTxBlock(t, devnetGenesisBlockHash, target, reorgTestTimestamp(1), coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 1, subsidy1))
	a1, err := engine.ApplyBlock(blockA1, nil)
	if err != nil {
		t.Fatalf("ApplyBlock(A1): %v", err)
	}
	subsidy2 := consensus.BlockSubsidy(2, subsidy1)
	blockA2 := buildSingleTxBlock(t, a1.BlockHash, target, reorgTestTimestamp(2), coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 2, subsidy2))
	a2, err := engine.ApplyBlock(blockA2, nil)
	if err != nil {
		t.Fatalf("ApplyBlock(A2): %v", err)
	}

	// One block against a two-block canonical chain of identical targets: strictly
	// less work, so fork choice takes the store-side-block path deterministically
	// rather than through a tip-hash tiebreak.
	sideB1 := buildSingleTxBlock(t, devnetGenesisBlockHash, target, reorgTestTimestamp(3), coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 1, subsidy1))
	// The AMBIGUOUS class: the parent sync fails after the leaf may already be
	// durable, which is the failure a canonical commit would have to latch on.
	// One-shot, so the canonical apply at the end runs against a healthy store.
	failed := false
	withAtomicWriteOps(t, func(ops *atomicWriteOps) {
		syncParent := ops.syncParent
		ops.syncParent = func(parent string) error {
			if !failed && parent == store.blocksDir {
				failed = true
				return os.ErrPermission
			}
			return syncParent(parent)
		}
	})
	summary, err := engine.ApplyBlockWithReorg(sideB1, nil)
	if summary != nil || !failed || !errors.Is(err, os.ErrPermission) {
		t.Fatalf("summary=%+v failed=%v err=%v, want the side-block store failure", summary, failed, err)
	}
	if engine.persistenceFaulted() {
		t.Fatal("a noncanonical side-block store failure latched the engine")
	}
	if view := engine.chainState.view(); view.tipHash != a2.BlockHash {
		t.Fatalf("canonical tip=%x, want the untouched %x", view.tipHash, a2.BlockHash)
	}

	// The engine is still open for canonical business, which is what
	// NOT_APPLICABLE has to mean in practice.
	blockA3 := buildSingleTxBlock(t, a2.BlockHash, target, reorgTestTimestamp(4), coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 3, consensus.BlockSubsidy(3, subsidy1+subsidy2)))
	if _, err := engine.ApplyBlock(blockA3, nil); err != nil {
		t.Fatalf("ApplyBlock(A3) after a side-block store failure: %v", err)
	}
}

func newReorgTestEngine(t *testing.T) (*SyncEngine, *BlockStore, [32]byte) {
	t.Helper()
	dir := t.TempDir()
	store, err := CreateBlockStore(BlockStorePath(dir))
	if err != nil {
		t.Fatalf("CreateBlockStore: %v", err)
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

func equalWorkCompetingHeightOneBlocks(t *testing.T, target [32]byte) ([]byte, [32]byte, []byte, [32]byte) {
	t.Helper()
	subsidy := consensus.BlockSubsidy(1, 0)
	base := buildSingleTxBlock(
		t,
		devnetGenesisBlockHash,
		target,
		reorgTestTimestamp(1),
		coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 1, subsidy),
	)

	var firstBlock []byte
	var firstHash [32]byte
	for nonce := uint64(1); nonce <= 64; nonce++ {
		block := blockWithHeaderNonce(t, base, nonce)
		hash, err := consensus.BlockHash(blockHeaderBytes(t, block))
		if err != nil {
			t.Fatalf("BlockHash(nonce=%d): %v", nonce, err)
		}
		if firstBlock == nil {
			firstBlock = block
			firstHash = hash
			continue
		}
		if hash == firstHash {
			continue
		}
		if bytes.Compare(hash[:], firstHash[:]) < 0 {
			return block, hash, firstBlock, firstHash
		}
		return firstBlock, firstHash, block, hash
	}
	t.Fatalf("failed to build distinct equal-work competing blocks")
	return nil, [32]byte{}, nil, [32]byte{}
}

func blockWithHeaderNonce(t *testing.T, block []byte, nonce uint64) []byte {
	t.Helper()
	if len(block) < consensus.BLOCK_HEADER_BYTES {
		t.Fatalf("block length=%d, want at least header length %d", len(block), consensus.BLOCK_HEADER_BYTES)
	}
	out := append([]byte(nil), block...)
	binary.LittleEndian.PutUint64(out[consensus.BLOCK_HEADER_BYTES-8:consensus.BLOCK_HEADER_BYTES], nonce)
	return out
}

func orderedEqualWorkBlockVariants(t *testing.T, lowerBase []byte, higherBase []byte) ([]byte, [32]byte, []byte, [32]byte) {
	t.Helper()
	for lowerNonce := uint64(1); lowerNonce <= 64; lowerNonce++ {
		lowerBlock := blockWithHeaderNonce(t, lowerBase, lowerNonce)
		lowerHash, err := consensus.BlockHash(blockHeaderBytes(t, lowerBlock))
		if err != nil {
			t.Fatalf("BlockHash(lower nonce=%d): %v", lowerNonce, err)
		}
		for higherNonce := uint64(1); higherNonce <= 64; higherNonce++ {
			higherBlock := blockWithHeaderNonce(t, higherBase, higherNonce)
			higherHash, err := consensus.BlockHash(blockHeaderBytes(t, higherBlock))
			if err != nil {
				t.Fatalf("BlockHash(higher nonce=%d): %v", higherNonce, err)
			}
			if bytes.Compare(lowerHash[:], higherHash[:]) < 0 {
				return lowerBlock, lowerHash, higherBlock, higherHash
			}
		}
	}
	t.Fatalf("failed to order equal-work block variants by tip hash")
	return nil, [32]byte{}, nil, [32]byte{}
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

func TestAdvancePrevTimestampsSliding(t *testing.T) {
	// Empty input → single entry.
	got := advancePrevTimestamps(nil, 100)
	if len(got) != 1 || got[0] != 100 {
		t.Fatalf("empty: got %v, want [100]", got)
	}
	// Partial window (5 entries) → prepend, len=6.
	prev := []uint64{90, 80, 70, 60, 50}
	got = advancePrevTimestamps(prev, 100)
	if len(got) != 6 || got[0] != 100 || got[5] != 50 {
		t.Fatalf("partial: got %v, want [100 90 80 70 60 50]", got)
	}
	// Full window (11 entries) → prepend, truncate, len=11.
	full := make([]uint64, 11)
	for i := range full {
		full[i] = uint64(110 - i*10)
	}
	got = advancePrevTimestamps(full, 200)
	if len(got) != 11 || got[0] != 200 || got[10] != 20 {
		t.Fatalf("full: got %v, want [200 110 100 ... 20]", got)
	}
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

func TestCanonicalAppliedBlocksOnDirectApply(t *testing.T) {
	engine, _, target := newReorgTestEngine(t)

	subsidy := consensus.BlockSubsidy(1, 0)
	blockBytes := buildSingleTxBlock(t, devnetGenesisBlockHash, target, reorgTestTimestamp(1), coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 1, subsidy))

	summary, err := engine.ApplyBlock(blockBytes, nil)
	if err != nil {
		t.Fatalf("ApplyBlock: %v", err)
	}
	if summary.BlockHeight != 1 {
		t.Fatalf("height=%d, want 1", summary.BlockHeight)
	}

	blocks := summary.CanonicalAppliedBlocks
	if len(blocks) != 1 {
		t.Fatalf("CanonicalAppliedBlocks len=%d, want 1", len(blocks))
	}
	if blocks[0].Hash != summary.BlockHash {
		t.Fatalf("CanonicalAppliedBlocks[0].Hash=%x, want BlockHash=%x", blocks[0].Hash, summary.BlockHash)
	}
	if len(blocks[0].CompleteDAIDs) != 0 {
		t.Fatalf("CompleteDAIDs=%x for a block with no DA transactions, want none", blocks[0].CompleteDAIDs)
	}
}

// TestCanonicalAppliedBlockCarriesNoBlockBytes pins the bound itself: the
// canonical-applied record is fixed-width by construction, so a reorg summary
// cannot retain N x MAX_BLOCK_BYTES of block bytes no matter how deep the reorg.
// A byte-slice field of any name reintroduces that growth, so the shape — not
// one field name — is what is asserted.
func TestCanonicalAppliedBlockCarriesNoBlockBytes(t *testing.T) {
	typ := reflect.TypeOf(CanonicalAppliedBlock{})
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		if field.Type.Kind() == reflect.Slice && field.Type.Elem().Kind() == reflect.Uint8 {
			t.Fatalf("CanonicalAppliedBlock.%s is a raw byte slice; the record must stay bounded", field.Name)
		}
	}
	if typ.NumField() != 2 {
		t.Fatalf("CanonicalAppliedBlock has %d fields, want exactly Hash and CompleteDAIDs", typ.NumField())
	}
}

// TestCanonicalAppliedBlocksOnDirectApplyReportsCompleteDASets is the
// exact-IDs row: a block that really is applied to the canonical tip reports the
// da_id of every complete DA set it carries, in ascending order, and nothing
// else. Both sets here are complete because consensus rejects a block carrying
// an incomplete one (BLOCK_ERR_DA_INCOMPLETE) — the incomplete-set report
// corners are pinned against the extraction core in node/p2p.
func TestCanonicalAppliedBlocksOnDirectApplyReportsCompleteDASets(t *testing.T) {
	fixture := newCanonicalDATestFixture(t)
	// Declared out of ascending order on the wire so a map-iteration or
	// insertion-order report cannot pass by luck.
	secondID := [32]byte{0xd2}
	firstID := [32]byte{0xd1}

	blockBytes := fixture.blockWithDASets(
		t,
		daSetSpec{daID: secondID, payloads: [][]byte{[]byte("second-0")}},
		daSetSpec{daID: firstID, payloads: [][]byte{[]byte("first-0"), []byte("first-1")}},
	)

	summary, err := fixture.engine.ApplyBlock(blockBytes, nil)
	if err != nil {
		t.Fatalf("ApplyBlock(DA block): %v", err)
	}
	blocks := summary.CanonicalAppliedBlocks
	if len(blocks) != 1 {
		t.Fatalf("CanonicalAppliedBlocks len=%d, want 1", len(blocks))
	}
	if blocks[0].Hash != summary.BlockHash {
		t.Fatalf("CanonicalAppliedBlocks[0].Hash=%x, want BlockHash=%x", blocks[0].Hash, summary.BlockHash)
	}
	want := [][32]byte{firstID, secondID}
	if !reflect.DeepEqual(blocks[0].CompleteDAIDs, want) {
		t.Fatalf("CompleteDAIDs=%x, want %x in ascending order", blocks[0].CompleteDAIDs, want)
	}
}

func TestCanonicalAppliedBlocksOnSideBranch(t *testing.T) {
	engine, _, target := newReorgTestEngine(t)

	subsidy := consensus.BlockSubsidy(1, 0)
	blockA := buildSingleTxBlock(t, devnetGenesisBlockHash, target, reorgTestTimestamp(1), coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 1, subsidy))
	if _, err := engine.ApplyBlock(blockA, nil); err != nil {
		t.Fatalf("ApplyBlock(A): %v", err)
	}

	blockB := buildSingleTxBlock(t, devnetGenesisBlockHash, target, reorgTestTimestamp(2), coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 1, subsidy))
	summary, err := engine.ApplyBlockWithReorg(blockB, nil)
	if err != nil {
		t.Fatalf("ApplyBlockWithReorg(B): %v", err)
	}

	if summary.CanonicalAppliedBlocks != nil {
		t.Fatalf("CanonicalAppliedBlocks len=%d, want nil (side branch, no canonical blocks)", len(summary.CanonicalAppliedBlocks))
	}
	// Side block B must NOT switch the canonical tip: A stays canonical at
	// height 1. Assert unconditionally against A's hash so a wrong switch to B
	// fails the test instead of being masked by a guard on B's own hash.
	aHash, err := consensus.BlockHash(blockHeaderBytes(t, blockA))
	if err != nil {
		t.Fatalf("BlockHash(A): %v", err)
	}
	if engine.chainState.Height != 1 {
		t.Fatalf("canonical height=%d after side branch B, want 1", engine.chainState.Height)
	}
	if engine.chainState.TipHash != aHash {
		t.Fatalf("canonical tip=%x after side branch B, want A=%x", engine.chainState.TipHash, aHash)
	}
}

func TestCanonicalAppliedBlocksOnReorg(t *testing.T) {
	target := consensus.POW_LIMIT
	// Build a 2-block chain B that will outwork the 1-block canonical chain A.
	subsidy1 := consensus.BlockSubsidy(1, 0)
	blockA1 := buildSingleTxBlock(t, devnetGenesisBlockHash, target, reorgTestTimestamp(1), coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 1, subsidy1))
	blockB1 := buildSingleTxBlock(t, devnetGenesisBlockHash, target, reorgTestTimestamp(2), coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 1, subsidy1))

	b1Hash, err := consensus.BlockHash(blockHeaderBytes(t, blockB1))
	if err != nil {
		t.Fatalf("BlockHash(B1): %v", err)
	}

	subsidy2 := consensus.BlockSubsidy(2, subsidy1)
	blockB2 := buildSingleTxBlock(t, b1Hash, target, reorgTestTimestamp(3), coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 2, subsidy2))
	engine, store, _ := newReorgTestEngine(t)

	// Apply A1 as canonical (1-block chain)
	if _, err := engine.ApplyBlock(blockA1, nil); err != nil {
		t.Fatalf("ApplyBlock(A1): %v", err)
	}

	// Store B1 in blockstore so branch collection can find it
	if err := store.StoreBlock(b1Hash, blockHeaderBytes(t, blockB1), blockB1); err != nil {
		t.Fatalf("StoreBlock(B1): %v", err)
	}

	// Apply B2 as reorg trigger — B1->B2 is a 2-block branch with more total work
	summary, err := engine.ApplyBlockWithReorg(blockB2, nil)
	if err != nil {
		t.Fatalf("ApplyBlockWithReorg(B2): %v", err)
	}

	canonBlocks := summary.CanonicalAppliedBlocks
	if len(canonBlocks) != 2 {
		t.Fatalf("CanonicalAppliedBlocks len=%d, want 2 (B1 + B2 reorg)", len(canonBlocks))
	}
	// B1 comes first in canonical order (height 1)
	if canonBlocks[0].Hash != b1Hash {
		t.Fatalf("CanonicalAppliedBlocks[0].Hash=%x, want B1=%x", canonBlocks[0].Hash, b1Hash)
	}
	// B2 is second (height 2)
	if canonBlocks[1].Hash != summary.BlockHash {
		t.Fatalf("CanonicalAppliedBlocks[1].Hash=%x, want B2=%x", canonBlocks[1].Hash, summary.BlockHash)
	}
	for i, item := range canonBlocks {
		if len(item.CompleteDAIDs) != 0 {
			t.Fatalf("CanonicalAppliedBlocks[%d].CompleteDAIDs=%x for a coinbase-only block, want none", i, item.CompleteDAIDs)
		}
	}
}

// TestCanonicalAppliedBlocksOnReorgAttributesDASetsPerBlock is the per-block
// attribution row: after a reorg each newly-canonical block reports ITS OWN
// complete DA sets, in canonical order. A single accumulated set, or a
// last-block-wins report, would leave the other block's relay records pinned
// forever.
func TestCanonicalAppliedBlocksOnReorgAttributesDASetsPerBlock(t *testing.T) {
	fixture := newCanonicalDATestFixture(t)
	idA1 := [32]byte{0xa1}
	idB1 := [32]byte{0xb1}
	idB2 := [32]byte{0xb2}

	// Canonical chain A: one block carrying its own DA set.
	blockA1 := fixture.blockWithDASets(t, daSetSpec{daID: idA1, payloads: [][]byte{[]byte("a1")}})
	if _, err := fixture.engine.ApplyBlock(blockA1, nil); err != nil {
		t.Fatalf("ApplyBlock(A1): %v", err)
	}

	// Competing branch B1 -> B2, each with a distinct DA set, out-working A.
	forkFixture := fixture.forkFrom(t)
	blockB1 := forkFixture.blockWithDASets(t, daSetSpec{daID: idB1, payloads: [][]byte{[]byte("b1")}})
	b1Parsed, b1Hash := mustParseReorgBlockForTest(t, blockB1)
	if err := fixture.store.StoreBlock(b1Hash, b1Parsed.HeaderBytes, blockB1); err != nil {
		t.Fatalf("StoreBlock(B1): %v", err)
	}
	// blockWithDASets already advanced the fork to build on B1.
	blockB2 := forkFixture.blockWithDASets(t, daSetSpec{daID: idB2, payloads: [][]byte{[]byte("b2")}})

	summary, err := fixture.engine.ApplyBlockWithReorg(blockB2, nil)
	if err != nil {
		t.Fatalf("ApplyBlockWithReorg(B2): %v", err)
	}
	canonBlocks := summary.CanonicalAppliedBlocks
	if len(canonBlocks) != 2 {
		t.Fatalf("CanonicalAppliedBlocks len=%d, want 2 (B1 + B2)", len(canonBlocks))
	}
	if canonBlocks[0].Hash != b1Hash || canonBlocks[1].Hash != summary.BlockHash {
		t.Fatalf("canonical order = %x, %x; want B1=%x then B2=%x",
			canonBlocks[0].Hash, canonBlocks[1].Hash, b1Hash, summary.BlockHash)
	}
	if !reflect.DeepEqual(canonBlocks[0].CompleteDAIDs, [][32]byte{idB1}) {
		t.Fatalf("B1 CompleteDAIDs=%x, want %x", canonBlocks[0].CompleteDAIDs, [][32]byte{idB1})
	}
	if !reflect.DeepEqual(canonBlocks[1].CompleteDAIDs, [][32]byte{idB2}) {
		t.Fatalf("B2 CompleteDAIDs=%x, want %x", canonBlocks[1].CompleteDAIDs, [][32]byte{idB2})
	}
}

func TestCanonicalAppliedBlocksOnDirectApplyWithReorg(t *testing.T) {
	engine, _, target := newReorgTestEngine(t)

	subsidy := consensus.BlockSubsidy(1, 0)
	blockBytes := buildSingleTxBlock(t, devnetGenesisBlockHash, target, reorgTestTimestamp(1), coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 1, subsidy))

	// ApplyBlockWithReorg for a direct tip child also goes through applyCanonicalParsedBlock
	summary, err := engine.ApplyBlockWithReorg(blockBytes, nil)
	if err != nil {
		t.Fatalf("ApplyBlockWithReorg(direct): %v", err)
	}

	blocks := summary.CanonicalAppliedBlocks
	if len(blocks) != 1 {
		t.Fatalf("CanonicalAppliedBlocks len=%d, want 1 (direct apply via ApplyBlockWithReorg)", len(blocks))
	}
	if blocks[0].Hash != summary.BlockHash {
		t.Fatalf("CanonicalAppliedBlocks[0].Hash=%x, want BlockHash=%x", blocks[0].Hash, summary.BlockHash)
	}
}

// daSetSpec describes one complete DA set for a fixture block: one commit
// declaring len(payloads) chunks, plus one chunk transaction per payload.
type daSetSpec struct {
	daID     [32]byte
	payloads [][]byte
}

// canonicalDATestFixture mines a matured canonical chain and then builds blocks
// that really carry complete DA sets. Nothing cheaper reaches the canonical
// apply path: DA transactions are non-coinbase, so they need spendable inputs
// and valid ML-DSA-87 signatures, and coinbase outputs only become spendable
// after consensus.COINBASE_MATURITY blocks.
type canonicalDATestFixture struct {
	engine           *SyncEngine
	store            *BlockStore
	keypair          *consensus.MLDSA87Keypair
	address          []byte
	spendable        []consensus.Outpoint
	cursor           *int // shared across forks so two branches never reuse an input
	target           [32]byte
	prevHash         [32]byte
	height           uint64
	alreadyGenerated uint64
	timestampSeed    uint64
	nextNonce        uint64
}

// daFixtureSpendableOutputs is how many independently spendable P2PK outputs the
// height-1 coinbase pays to the fixture key. Only outputs created at height 1
// are mature at the first post-maturity block, so every DA input a test needs
// has to come from that one coinbase.
const daFixtureSpendableOutputs = 8

func newCanonicalDATestFixture(t *testing.T) *canonicalDATestFixture {
	t.Helper()
	engine, store, target := newReorgTestEngine(t)
	keypair := mustReorgMLDSA87Keypair(t)
	cursor := 0
	fixture := &canonicalDATestFixture{
		engine:        engine,
		store:         store,
		keypair:       keypair,
		address:       consensus.P2PKCovenantDataForPubkey(keypair.PubkeyBytes()),
		cursor:        &cursor,
		target:        target,
		prevHash:      devnetGenesisBlockHash,
		timestampSeed: 1,
		nextNonce:     1,
	}
	for height := uint64(1); height <= consensus.COINBASE_MATURITY; height++ {
		fixture.mineMaturityBlock(t, height)
	}
	fixture.height = consensus.COINBASE_MATURITY + 1
	return fixture
}

func (f *canonicalDATestFixture) mineMaturityBlock(t *testing.T, height uint64) {
	t.Helper()
	subsidy := consensus.BlockSubsidy(height, f.alreadyGenerated)
	coinbase := f.maturityCoinbase(t, height, subsidy)
	block := buildSingleTxBlock(t, f.prevHash, f.target, reorgTestTimestamp(height), coinbase)
	summary, err := f.engine.ApplyBlock(block, nil)
	if err != nil {
		t.Fatalf("ApplyBlock(maturity height=%d): %v", height, err)
	}
	if height == 1 {
		_, txid, _, _, err := consensus.ParseTx(coinbase)
		if err != nil {
			t.Fatalf("ParseTx(height-1 coinbase): %v", err)
		}
		for vout := 0; vout < daFixtureSpendableOutputs; vout++ {
			f.spendable = append(f.spendable, consensus.Outpoint{Txid: txid, Vout: uint32(vout)})
		}
	}
	f.prevHash = summary.BlockHash
	f.alreadyGenerated += subsidy
	f.timestampSeed = height + 1
}

// maturityCoinbase pays the full subsidy to the fixture key. At height 1 it
// splits the subsidy across daFixtureSpendableOutputs outputs so later DA
// transactions have independent inputs; the total is exactly the subsidy, which
// keeps the fixture's own already-generated tracking exact.
func (f *canonicalDATestFixture) maturityCoinbase(t *testing.T, height uint64, subsidy uint64) []byte {
	t.Helper()
	if height != 1 {
		return reorgTestCoinbaseForAddress(t, height, subsidy, f.address)
	}
	share := subsidy / daFixtureSpendableOutputs
	outputs := make([]testOutput, 0, daFixtureSpendableOutputs+1)
	for i := 0; i < daFixtureSpendableOutputs; i++ {
		value := share
		if i == 0 {
			value = subsidy - share*(daFixtureSpendableOutputs-1)
		}
		outputs = append(outputs, testOutput{
			value:        value,
			covenantType: consensus.COV_TYPE_P2PK,
			covenantData: append([]byte(nil), f.address...),
		})
	}
	wroot, err := consensus.WitnessMerkleRootWtxids([][32]byte{{}})
	if err != nil {
		t.Fatalf("WitnessMerkleRootWtxids(height 1): %v", err)
	}
	commitment := consensus.WitnessCommitmentHash(wroot)
	outputs = append(outputs, testOutput{
		value:        0,
		covenantType: consensus.COV_TYPE_ANCHOR,
		covenantData: commitment[:],
	})
	return coinbaseTxWithOutputs(uint32(height), outputs)
}

// forkFrom snapshots the fixture so a competing branch can be built from the
// same parent. The spend cursor is shared, so branch blocks never claim an input
// another branch already used.
func (f *canonicalDATestFixture) forkFrom(t *testing.T) *canonicalDATestFixture {
	t.Helper()
	fork := *f
	fork.timestampSeed = f.timestampSeed + 1000
	return &fork
}

// blockWithDASets builds (does NOT apply) the next block of this branch carrying
// every specified DA set, and advances the fixture as if it became the tip.
func (f *canonicalDATestFixture) blockWithDASets(t *testing.T, specs ...daSetSpec) []byte {
	t.Helper()
	daTxs := make([][]byte, 0, len(specs)*2)
	var sumFees uint64
	for _, spec := range specs {
		txs, fees := f.daSetTxs(t, spec)
		daTxs = append(daTxs, txs...)
		sumFees += fees
	}
	wtxids := make([][32]byte, 0, len(daTxs)+1)
	wtxids = append(wtxids, [32]byte{})
	for _, txBytes := range daTxs {
		_, _, wtxid, _, err := consensus.ParseTx(txBytes)
		if err != nil {
			t.Fatalf("ParseTx(DA tx): %v", err)
		}
		wtxids = append(wtxids, wtxid)
	}
	subsidy := consensus.BlockSubsidy(f.height, f.alreadyGenerated)
	coinbase := reorgTestCoinbaseForWtxids(t, f.height, subsidy+sumFees, f.address, wtxids)
	block := buildMultiTxBlock(t, f.prevHash, f.target, reorgTestTimestamp(f.timestampSeed), append([][]byte{coinbase}, daTxs...)...)

	f.prevHash = mustBlockHashForTest(t, block)
	f.height++
	f.alreadyGenerated += subsidy
	f.timestampSeed++
	return block
}

func (f *canonicalDATestFixture) daSetTxs(t *testing.T, spec daSetSpec) ([][]byte, uint64) {
	t.Helper()
	hasher := sha3.New256()
	for _, payload := range spec.payloads {
		if _, err := hasher.Write(payload); err != nil {
			t.Fatalf("hash DA payload: %v", err)
		}
	}
	var commitment [32]byte
	copy(commitment[:], hasher.Sum(nil))

	commitInput, commitFee := f.nextSpendableInput(t)
	commitTx := &consensus.Tx{
		Version: 1,
		TxKind:  0x01,
		TxNonce: f.takeNonce(),
		Inputs:  []consensus.TxInput{commitInput},
		Outputs: []consensus.TxOutput{{
			Value:        0,
			CovenantType: consensus.COV_TYPE_DA_COMMIT,
			CovenantData: append([]byte(nil), commitment[:]...),
		}},
		DaCommitCore: &consensus.DaCommitCore{
			DaID:        spec.daID,
			ChunkCount:  uint16(len(spec.payloads)),
			BatchNumber: 1,
		},
	}
	txs := [][]byte{f.signAndMarshal(t, commitTx)}
	fees := commitFee
	for index, payload := range spec.payloads {
		chunkInput, chunkFee := f.nextSpendableInput(t)
		chunkHash := sha3.Sum256(payload)
		chunkTx := &consensus.Tx{
			Version: 1,
			TxKind:  0x02,
			TxNonce: f.takeNonce(),
			Inputs:  []consensus.TxInput{chunkInput},
			DaChunkCore: &consensus.DaChunkCore{
				DaID:       spec.daID,
				ChunkIndex: uint16(index),
				ChunkHash:  chunkHash,
			},
			DaPayload: append([]byte(nil), payload...),
		}
		txs = append(txs, f.signAndMarshal(t, chunkTx))
		fees += chunkFee
	}
	return txs, fees
}

// nextSpendableInput claims the next unused matured coinbase output. Its whole
// value becomes fee, since DA transactions here create no spendable outputs.
func (f *canonicalDATestFixture) nextSpendableInput(t *testing.T) (consensus.TxInput, uint64) {
	t.Helper()
	if *f.cursor >= len(f.spendable) {
		t.Fatalf("fixture ran out of spendable outputs (have %d)", len(f.spendable))
	}
	outpoint := f.spendable[*f.cursor]
	*f.cursor++
	entry, ok := f.engine.chainState.Utxos[outpoint]
	if !ok {
		t.Fatalf("spendable outpoint %x:%d is not in the UTXO set", outpoint.Txid, outpoint.Vout)
	}
	return consensus.TxInput{PrevTxid: outpoint.Txid, PrevVout: outpoint.Vout}, entry.Value
}

func (f *canonicalDATestFixture) takeNonce() uint64 {
	f.nextNonce++
	return f.nextNonce
}

func (f *canonicalDATestFixture) signAndMarshal(t *testing.T, tx *consensus.Tx) []byte {
	t.Helper()
	if err := consensus.SignTransaction(tx, f.engine.chainState.Utxos, devnetGenesisChainID, f.keypair); err != nil {
		t.Fatalf("SignTransaction(DA tx): %v", err)
	}
	raw, err := consensus.MarshalTx(tx)
	if err != nil {
		t.Fatalf("MarshalTx(DA tx): %v", err)
	}
	return raw
}

func mustBlockHashForTest(t *testing.T, blockBytes []byte) [32]byte {
	t.Helper()
	hash, err := consensus.BlockHash(blockHeaderBytes(t, blockBytes))
	if err != nil {
		t.Fatalf("BlockHash: %v", err)
	}
	return hash
}

func mustParseReorgBlockForTest(t *testing.T, blockBytes []byte) (*consensus.ParsedBlock, [32]byte) {
	t.Helper()
	parsed, err := consensus.ParseBlockBytes(blockBytes)
	if err != nil {
		t.Fatalf("ParseBlockBytes: %v", err)
	}
	hash, err := consensus.BlockHash(parsed.HeaderBytes)
	if err != nil {
		t.Fatalf("BlockHash: %v", err)
	}
	return parsed, hash
}

// writeRawStoreBlockFile plants arbitrary bytes at the block-store path a given
// hash resolves to. BlockStore.GetBlockByHash is a plain file read, so this is
// exactly what a corrupt datadir — or anything with write access to it — hands
// the branch walk.
func writeRawStoreBlockFile(t *testing.T, store *BlockStore, hash [32]byte, blockBytes []byte) {
	t.Helper()
	path := filepath.Join(store.blocksDir, hex.EncodeToString(hash[:])+".bin")
	if err := os.WriteFile(path, blockBytes, 0o600); err != nil {
		t.Fatalf("plant store block %x: %v", hash, err)
	}
}

func corruptStoredMerkleBody(t *testing.T, blockBytes []byte) []byte {
	t.Helper()
	corrupt := append([]byte(nil), blockBytes...)
	if len(corrupt) < 3 {
		t.Fatal("test block too short to change coinbase locktime")
	}
	// Mutating coinbase locktime keeps parsing/header identity but breaks Merkle.
	corrupt[len(corrupt)-3] ^= 0x01
	pb, err := consensus.ParseBlockBytes(corrupt)
	if err != nil {
		t.Fatalf("ParseBlockBytes(corrupt merkle body): %v", err)
	}
	requireConsensusTxErrCode(t, consensus.ValidateStoredBlockCommitments(pb), consensus.BLOCK_ERR_MERKLE_INVALID)
	return corrupt
}

func storedWitnessCommitmentTestBlock(t *testing.T, prevHash, target [32]byte, height, timestamp uint64) []byte {
	t.Helper()
	spend := &consensus.Tx{
		Version:  1,
		TxKind:   0x00,
		TxNonce:  1,
		Inputs:   []consensus.TxInput{{PrevTxid: [32]byte{0x91}, PrevVout: 0, Sequence: 0}},
		Outputs:  []consensus.TxOutput{{Value: 1, CovenantType: consensus.COV_TYPE_P2PK, CovenantData: testP2PKCovenantData(0x77)}},
		Locktime: 0,
		Witness:  []consensus.WitnessItem{{SuiteID: 0x7e, Pubkey: []byte{0x01}, Signature: []byte{0x02}}},
	}
	spendBytes, err := consensus.MarshalTx(spend)
	if err != nil {
		t.Fatalf("MarshalTx(spend): %v", err)
	}
	_, _, spendWtxid, _, err := consensus.ParseTx(spendBytes)
	if err != nil {
		t.Fatalf("ParseTx(spend): %v", err)
	}
	coinbase := coinbaseWithWitnessCommitmentAndP2PKValueForWtxids(
		t,
		height,
		consensus.BlockSubsidy(height, 0),
		[][32]byte{{}, spendWtxid},
	)
	return buildMultiTxBlock(t, prevHash, target, timestamp, coinbase, spendBytes)
}

func corruptStoredWitnessOnly(t *testing.T, blockBytes []byte) []byte {
	t.Helper()
	pb, err := consensus.ParseBlockBytes(blockBytes)
	if err != nil {
		t.Fatalf("ParseBlockBytes(source): %v", err)
	}
	if len(pb.Txs) < 2 || len(pb.Txs[1].Witness) == 0 || len(pb.Txs[1].Witness[0].Signature) == 0 {
		t.Fatal("test block has no mutable non-coinbase witness")
	}
	pb.Txs[1].Witness[0].Signature[0] ^= 0x01

	corrupt := append([]byte(nil), pb.HeaderBytes...)
	corrupt = consensus.AppendCompactSize(corrupt, uint64(len(pb.Txs)))
	for _, tx := range pb.Txs {
		txBytes, err := consensus.MarshalTx(tx)
		if err != nil {
			t.Fatalf("MarshalTx(rebuild): %v", err)
		}
		corrupt = append(corrupt, txBytes...)
	}
	parsed, err := consensus.ParseBlockBytes(corrupt)
	if err != nil {
		t.Fatalf("ParseBlockBytes(corrupt witness): %v", err)
	}
	root, err := consensus.MerkleRootTxids(parsed.Txids)
	if err != nil {
		t.Fatalf("MerkleRootTxids(corrupt witness): %v", err)
	}
	if root != parsed.Header.MerkleRoot {
		t.Fatal("witness-only corruption changed the txid Merkle root")
	}
	requireConsensusTxErrCode(t, consensus.ValidateStoredBlockCommitments(parsed), consensus.BLOCK_ERR_WITNESS_COMMITMENT)
	return corrupt
}

// assertBranchStoreCorruption pins the failure class of a corrupt-store branch
// walk: a local-corruption error, distinct from ErrParentNotFound, and NOT a
// *consensus.TxError. That last property is what keeps a peer from being
// ban-scored for our own bad datadir — node/p2p classifies apply failures with
// exactly this predicate (handlers_block.go isConsensusApplyBlockError).
func assertBranchStoreCorruption(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("corrupt store walk returned nil error")
	}
	// Checked FIRST because it is the consequential one: errors.As unwraps, so
	// any *consensus.TxError anywhere in the chain — including a %w-wrapped
	// cause — makes node/p2p bumpBan(100) the peer that relayed a well-formed
	// block, for a defect that is entirely ours.
	var txErr *consensus.TxError
	if errors.As(err, &txErr) {
		t.Fatalf("corruption error %v is a consensus.TxError; the relaying peer would be ban-scored for our corrupt store", err)
	}
	if !errors.Is(err, errBranchStoreCorrupt) {
		t.Fatalf("error %v is not errBranchStoreCorrupt", err)
	}
	if errors.Is(err, ErrParentNotFound) {
		t.Fatalf("corruption error %v must not be ErrParentNotFound", err)
	}
}

// TestCollectBranchToCanonicalRejectsCorruptStoreAncestry drives the branch walk
// against a block store whose files lie. None of these shapes is
// self-consistent — a stored block that really hashed to a name it also points
// back to would need a hash preimage — which is exactly what a corrupt or
// hostile datadir produces and what a plain file read cannot detect.
//
// Each case plants store content and returns the parent hash a candidate should
// name. The prior defect differs by shape, and all three kinds converge on one
// verdict here:
//
//   - self-referencing store file, two-file store cycle: the walk did not
//     terminate — it appended stored bytes forever.
//   - ancestor bytes hashing to another value: the walk terminated but TRUSTED
//     the substituted block as a branch ancestor.
//   - ancestor file present but unparseable, truncated mid-block: the walk
//     terminated and trusted nothing — ParseBlockBytes failed and its error was
//     returned immediately. The defect was the CLASS of that error: a raw
//     *consensus.TxError, which node/p2p reads as a consensus fault and
//     ban-scores the relaying peer 100 for our own corrupt datadir.
//
// All five must now fail as local corruption: typed, terminating, and never a
// *consensus.TxError.
func TestCollectBranchToCanonicalRejectsCorruptStoreAncestry(t *testing.T) {
	subsidy := consensus.BlockSubsidy(1, 0)
	cases := []struct {
		name  string
		plant func(t *testing.T, store *BlockStore, target [32]byte) [32]byte
	}{{
		// One file claiming itself as its own parent: the walk used to append
		// the same block bytes on every pass, forever.
		name: "self-referencing store file",
		plant: func(t *testing.T, store *BlockStore, target [32]byte) [32]byte {
			selfHash := [32]byte{0x5e, 0x1f}
			block := buildSingleTxBlock(t, selfHash, target, reorgTestTimestamp(60), coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 1, subsidy))
			writeRawStoreBlockFile(t, store, selfHash, block)
			return selfHash
		},
	}, {
		// The same class one hop wider: two files pointing at each other.
		name: "two-file store cycle",
		plant: func(t *testing.T, store *BlockStore, target [32]byte) [32]byte {
			hashX := [32]byte{0xc0, 0x01}
			hashY := [32]byte{0xc0, 0x02}
			writeRawStoreBlockFile(t, store, hashX,
				buildSingleTxBlock(t, hashY, target, reorgTestTimestamp(70), coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 1, subsidy)))
			writeRawStoreBlockFile(t, store, hashY,
				buildSingleTxBlock(t, hashX, target, reorgTestTimestamp(71), coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 1, subsidy)))
			return hashX
		},
	}, {
		// Present but unparseable: bytes that cannot even yield a header
		// certainly are not the block that was asked for. The raw parse failure
		// is a *consensus.TxError, so leaking it would have node/p2p ban-score
		// the relaying peer 100 for our own corrupt datadir.
		name: "ancestor file present but unparseable",
		plant: func(t *testing.T, store *BlockStore, target [32]byte) [32]byte {
			garbageHash := [32]byte{0x9a, 0x11}
			writeRawStoreBlockFile(t, store, garbageHash, []byte{0x01, 0x02, 0x03})
			return garbageHash
		},
	}, {
		// Truncated: a real block cut short mid-encoding.
		name: "ancestor file truncated mid-block",
		plant: func(t *testing.T, store *BlockStore, target [32]byte) [32]byte {
			truncatedHash := [32]byte{0x9a, 0x22}
			full := buildSingleTxBlock(t, devnetGenesisBlockHash, target, reorgTestTimestamp(75), coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 1, subsidy))
			writeRawStoreBlockFile(t, store, truncatedHash, full[:len(full)/2])
			return truncatedHash
		},
	}, {
		name: "ancestor file with trailing bytes",
		plant: func(t *testing.T, store *BlockStore, target [32]byte) [32]byte {
			trailingHash := [32]byte{0x9a, 0x33}
			full := buildSingleTxBlock(t, devnetGenesisBlockHash, target, reorgTestTimestamp(76), coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 1, subsidy))
			writeRawStoreBlockFile(t, store, trailingHash, append(full, 0x00))
			return trailingHash
		},
	}, {
		// Substitution: a real, well-formed block stored under someone else's
		// hash. A plain file read cannot tell the difference.
		name: "ancestor bytes hashing to another value",
		plant: func(t *testing.T, store *BlockStore, target [32]byte) [32]byte {
			claimedHash := [32]byte{0xbe, 0xef}
			writeRawStoreBlockFile(t, store, claimedHash,
				buildSingleTxBlock(t, devnetGenesisBlockHash, target, reorgTestTimestamp(80), coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 1, subsidy)))
			return claimedHash
		},
	}}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			engine, store, target := newReorgTestEngine(t)
			parentHash := tc.plant(t, store, target)
			candidate := buildSingleTxBlock(t, parentHash, target, reorgTestTimestamp(90), coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 1, subsidy))
			parsed, candidateHash := mustParseReorgBlockForTest(t, candidate)

			_, _, _, err := engine.collectBranchToCanonical(candidateHash, candidate, parsed)
			assertBranchStoreCorruption(t, err)
		})
	}
}

func TestCollectBranchToCanonicalRejectsStoredCommitmentCorruptionAtEveryDepth(t *testing.T) {
	corruptions := []struct {
		name    string
		block   func(t *testing.T, target [32]byte) []byte
		corrupt func(t *testing.T, blockBytes []byte) []byte
	}{
		{
			name: "txid Merkle body substitution",
			block: func(t *testing.T, target [32]byte) []byte {
				return buildSingleTxBlock(t, devnetGenesisBlockHash, target, reorgTestTimestamp(101), coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 1, consensus.BlockSubsidy(1, 0)))
			},
			corrupt: corruptStoredMerkleBody,
		},
		{
			name: "witness-only substitution",
			block: func(t *testing.T, target [32]byte) []byte {
				return storedWitnessCommitmentTestBlock(t, devnetGenesisBlockHash, target, 1, reorgTestTimestamp(102))
			},
			corrupt: corruptStoredWitnessOnly,
		},
	}

	for _, corruption := range corruptions {
		for _, depth := range []struct {
			name string
			mid  bool
		}{
			{name: "branch root"},
			{name: "branch middle", mid: true},
		} {
			t.Run(corruption.name+"/"+depth.name, func(t *testing.T) {
				engine, store, target := newReorgTestEngine(t)
				validB1 := corruption.block(t, target)
				_, b1Hash := mustParseReorgBlockForTest(t, validB1)
				writeRawStoreBlockFile(t, store, b1Hash, corruption.corrupt(t, validB1))

				parentHash := b1Hash
				candidateHeight := uint64(2)
				if depth.mid {
					b2 := buildSingleTxBlock(t, b1Hash, target, reorgTestTimestamp(103), coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 2, consensus.BlockSubsidy(2, consensus.BlockSubsidy(1, 0))))
					b2Parsed, b2Hash := mustParseReorgBlockForTest(t, b2)
					if err := store.StoreBlock(b2Hash, b2Parsed.HeaderBytes, b2); err != nil {
						t.Fatalf("StoreBlock(B2): %v", err)
					}
					parentHash = b2Hash
					candidateHeight = 3
				}
				candidate := buildSingleTxBlock(t, parentHash, target, reorgTestTimestamp(104), coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, candidateHeight, consensus.BlockSubsidy(candidateHeight, 0)))
				parsed, candidateHash := mustParseReorgBlockForTest(t, candidate)

				_, _, _, err := engine.collectBranchToCanonical(candidateHash, candidate, parsed)
				assertBranchStoreCorruption(t, err)
			})
		}
	}
}

func TestApplyBlockWithReorgRejectsCorruptLosingStoredBranchBeforeForkChoice(t *testing.T) {
	engine, store, target := newReorgTestEngine(t)
	prevHash := devnetGenesisBlockHash
	alreadyGenerated := uint64(0)
	for height := uint64(1); height <= 3; height++ {
		subsidy := consensus.BlockSubsidy(height, alreadyGenerated)
		block := buildSingleTxBlock(t, prevHash, target, reorgTestTimestamp(height), coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, height, subsidy))
		summary, err := engine.ApplyBlock(block, nil)
		if err != nil {
			t.Fatalf("ApplyBlock(A%d): %v", height, err)
		}
		prevHash = summary.BlockHash
		alreadyGenerated += subsidy
	}
	mempool, err := NewMempool(engine.chainState, store, devnetGenesisChainID)
	if err != nil {
		t.Fatalf("NewMempool: %v", err)
	}
	engine.SetMempool(mempool)
	beforeState, err := stateToDisk(engine.chainState)
	if err != nil {
		t.Fatalf("stateToDisk(before): %v", err)
	}
	beforeIndex, err := store.CanonicalIndexSnapshot()
	if err != nil {
		t.Fatalf("CanonicalIndexSnapshot(before): %v", err)
	}
	beforeCounts := engine.BlockApplyCounts()
	beforeMempoolLen := mempool.Len()

	subsidy1 := consensus.BlockSubsidy(1, 0)
	validB1 := buildSingleTxBlock(t, devnetGenesisBlockHash, target, reorgTestTimestamp(201), coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 1, subsidy1))
	_, b1Hash := mustParseReorgBlockForTest(t, validB1)
	writeRawStoreBlockFile(t, store, b1Hash, corruptStoredMerkleBody(t, validB1))
	b2 := buildSingleTxBlock(t, b1Hash, target, reorgTestTimestamp(202), coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 2, consensus.BlockSubsidy(2, subsidy1)))
	_, b2Hash := mustParseReorgBlockForTest(t, b2)

	// A healthy two-block branch loses to the current three-block canonical tip.
	// Collection must still reject its corrupt stored ancestor before fork choice.
	_, err = engine.ApplyBlockWithReorg(b2, nil)
	assertBranchStoreCorruption(t, err)
	if got, err := stateToDisk(engine.chainState); err != nil || !reflect.DeepEqual(got, beforeState) {
		t.Fatalf("chainstate after corrupt losing branch: state=%+v err=%v", got, err)
	}
	if got, err := store.CanonicalIndexSnapshot(); err != nil || !reflect.DeepEqual(got, beforeIndex) {
		t.Fatalf("canonical index after corrupt losing branch: index=%v err=%v", got, err)
	}
	if got := engine.BlockApplyCounts(); got != beforeCounts {
		t.Fatalf("BlockApplyCounts=%+v, want %+v", got, beforeCounts)
	}
	if got := mempool.Len(); got != beforeMempoolLen {
		t.Fatalf("mempool len=%d, want %d", got, beforeMempoolLen)
	}
	if _, err := store.GetBlockByHash(b2Hash); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("candidate B2 stored despite local failure: %v", err)
	}
}

// TestCollectBranchToCanonicalKeepsParentNotFoundForAbsentAncestor pins that
// hardening did not reclassify the ordinary case: an ancestor that simply is not
// stored stays ErrParentNotFound, which is what drives orphan retention.
func TestCollectBranchToCanonicalKeepsParentNotFoundForAbsentAncestor(t *testing.T) {
	engine, _, target := newReorgTestEngine(t)

	subsidy := consensus.BlockSubsidy(1, 0)
	candidate := buildSingleTxBlock(t, [32]byte{0xab, 0x5e, 0x17}, target, reorgTestTimestamp(90), coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 1, subsidy))
	parsed, candidateHash := mustParseReorgBlockForTest(t, candidate)

	_, _, _, err := engine.collectBranchToCanonical(candidateHash, candidate, parsed)
	if !errors.Is(err, ErrParentNotFound) {
		t.Fatalf("absent ancestor error=%v, want ErrParentNotFound", err)
	}
	if errors.Is(err, errBranchStoreCorrupt) {
		t.Fatalf("absent ancestor reported as store corruption: %v", err)
	}
	if _, err := engine.ApplyBlockWithReorg(candidate, nil); !errors.Is(err, ErrParentNotFound) {
		t.Fatalf("ApplyBlockWithReorg(orphan) error=%v, want ErrParentNotFound", err)
	}
}

// TestCollectBranchToCanonicalAcceptsHonestMultiBlockBranch is the
// no-false-positive row: verification must pass on honest stored ancestry, and
// the branch must still collect in canonical order and reorg the chain.
func TestCollectBranchToCanonicalAcceptsHonestMultiBlockBranch(t *testing.T) {
	engine, store, target := newReorgTestEngine(t)

	subsidy1 := consensus.BlockSubsidy(1, 0)
	blockA1 := buildSingleTxBlock(t, devnetGenesisBlockHash, target, reorgTestTimestamp(1), coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 1, subsidy1))
	if _, err := engine.ApplyBlock(blockA1, nil); err != nil {
		t.Fatalf("ApplyBlock(A1): %v", err)
	}

	blockB1 := buildSingleTxBlock(t, devnetGenesisBlockHash, target, reorgTestTimestamp(2), coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 1, subsidy1))
	b1Parsed, b1Hash := mustParseReorgBlockForTest(t, blockB1)
	if err := store.StoreBlock(b1Hash, b1Parsed.HeaderBytes, blockB1); err != nil {
		t.Fatalf("StoreBlock(B1): %v", err)
	}
	subsidy2 := consensus.BlockSubsidy(2, subsidy1)
	blockB2 := buildSingleTxBlock(t, b1Hash, target, reorgTestTimestamp(3), coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 2, subsidy2))
	b2Parsed, b2Hash := mustParseReorgBlockForTest(t, blockB2)

	branch, ancestorHash, ancestorHeight, err := engine.collectBranchToCanonical(b2Hash, blockB2, b2Parsed)
	if err != nil {
		t.Fatalf("collectBranchToCanonical(honest branch): %v", err)
	}
	if len(branch) != 2 || branch[0].hash != b1Hash || branch[1].hash != b2Hash {
		t.Fatalf("branch=%d blocks, want B1=%x then B2=%x", len(branch), b1Hash, b2Hash)
	}
	if ancestorHash != devnetGenesisBlockHash || ancestorHeight != 0 {
		t.Fatalf("common ancestor=%x at height %d, want genesis at 0", ancestorHash, ancestorHeight)
	}

	summary, err := engine.ApplyBlockWithReorg(blockB2, nil)
	if err != nil {
		t.Fatalf("ApplyBlockWithReorg(honest branch): %v", err)
	}
	if engine.chainState.TipHash != b2Hash || engine.chainState.Height != 2 {
		t.Fatalf("tip=%x height=%d after honest reorg, want %x at 2", engine.chainState.TipHash, engine.chainState.Height, b2Hash)
	}
	if len(summary.CanonicalAppliedBlocks) != 2 {
		t.Fatalf("CanonicalAppliedBlocks len=%d after honest reorg, want 2", len(summary.CanonicalAppliedBlocks))
	}
}

// TestApplyBlockWithReorgReportsNoCanonicalBlocksWhenBranchApplyFails is the
// rollback row: a heavier branch whose later block is invalid must leave the
// canonical chain untouched AND return no summary, so the DA-consume hook that
// runs on accepted blocks has nothing to consume.
func TestApplyBlockWithReorgReportsNoCanonicalBlocksWhenBranchApplyFails(t *testing.T) {
	engine, store, target := newReorgTestEngine(t)

	subsidy1 := consensus.BlockSubsidy(1, 0)
	blockA1 := buildSingleTxBlock(t, devnetGenesisBlockHash, target, reorgTestTimestamp(1), coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 1, subsidy1))
	summaryA1, err := engine.ApplyBlock(blockA1, nil)
	if err != nil {
		t.Fatalf("ApplyBlock(A1): %v", err)
	}

	blockB1 := buildSingleTxBlock(t, devnetGenesisBlockHash, target, reorgTestTimestamp(10), coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 1, subsidy1))
	b1Parsed, b1Hash := mustParseReorgBlockForTest(t, blockB1)
	if err := store.StoreBlock(b1Hash, b1Parsed.HeaderBytes, blockB1); err != nil {
		t.Fatalf("StoreBlock(B1): %v", err)
	}
	subsidy2 := consensus.BlockSubsidy(2, subsidy1)
	validB2 := buildSingleTxBlock(t, b1Hash, target, reorgTestTimestamp(11), coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 2, subsidy2))
	// Over-claiming coinbase: the branch out-works the canonical chain, so fork
	// choice selects it, and the second row then fails to apply.
	invalidB2 := buildSingleTxBlock(t, b1Hash, target, reorgTestTimestamp(11), coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 2, subsidy2+1))
	if bytes.Equal(validB2, invalidB2) {
		t.Fatal("invalid B2 fixture is identical to the valid one")
	}

	summary, err := engine.ApplyBlockWithReorg(invalidB2, nil)
	if err == nil {
		t.Fatal("invalid heavier branch was applied")
	}
	if summary != nil {
		t.Fatalf("failed reorg returned summary %+v; a canonical-applied report would consume DA sets for a branch that never landed", summary)
	}
	if engine.chainState.Height != 1 || engine.chainState.TipHash != summaryA1.BlockHash {
		t.Fatalf("canonical tip=%x height=%d after failed reorg, want A1=%x at 1", engine.chainState.TipHash, engine.chainState.Height, summaryA1.BlockHash)
	}
}

// completeDASetTxsForCount returns the transactions of exactly count complete DA
// sets (one commit declaring one chunk, plus that chunk).
func completeDASetTxsForCount(count int) []*consensus.Tx {
	txs := make([]*consensus.Tx, 0, count*2)
	for i := 0; i < count; i++ {
		daID := [32]byte{byte(i), byte(i >> 8)}
		txs = append(
			txs,
			&consensus.Tx{TxKind: 0x01, DaCommitCore: &consensus.DaCommitCore{DaID: daID, ChunkCount: 1}},
			&consensus.Tx{TxKind: 0x02, DaChunkCore: &consensus.DaChunkCore{DaID: daID, ChunkIndex: 0}},
		)
	}
	return txs
}

// TestApplyCanonicalParsedBlockRollsBackWhenCanonicalReportFails pins the
// disposition of a failure in the canonical-applied report, which happens AFTER
// ConnectBlock has already mutated chain state. Returning the error without
// rolling back would leave the in-memory tip advanced to a block that was never
// persisted and never reported — a chain state diverged from the block store,
// created by a path that returned an error.
//
// The failure is injected the only way it is reachable: applyCanonicalParsedBlockTracked
// takes the parsed block and the raw bytes as independent parameters, so the
// connect can be fed a real valid block while extraction is fed a tx list
// carrying more complete DA sets than consensus can ever accept. On the
// production path both come from one parse and this branch is unreachable, which
// is exactly why it needs pinning rather than trust.
func TestApplyCanonicalParsedBlockRollsBackWhenCanonicalReportFails(t *testing.T) {
	engine, store, target := newReorgTestEngine(t)
	mempool, err := NewMempool(engine.chainState, store, devnetGenesisChainID)
	if err != nil {
		t.Fatalf("NewMempool: %v", err)
	}
	engine.SetMempool(mempool)

	before := engine.chainState.view()
	beforeMempoolLen := mempool.Len()
	beforeTipHeight, beforeTipHash, beforeTipOK, err := store.Tip()
	if err != nil {
		t.Fatalf("store.Tip(before): %v", err)
	}
	beforeIndex, err := store.CanonicalIndexSnapshot()
	if err != nil {
		t.Fatalf("CanonicalIndexSnapshot(before): %v", err)
	}

	subsidy := consensus.BlockSubsidy(1, 0)
	blockBytes := buildSingleTxBlock(t, devnetGenesisBlockHash, target, reorgTestTimestamp(1), coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 1, subsidy))
	parsed, _ := mustParseReorgBlockForTest(t, blockBytes)
	overloaded := &consensus.ParsedBlock{
		HeaderBytes: parsed.HeaderBytes,
		Header:      parsed.Header,
		Txs:         completeDASetTxsForCount(consensus.MAX_DA_BATCHES_PER_BLOCK + 1),
	}

	summary, outcome, err := engine.applyCanonicalParsedBlockTracked(overloaded, blockBytes, nil, nil, nil)
	if err == nil {
		t.Fatal("over-cap canonical-applied report was accepted")
	}
	if summary != nil {
		t.Fatalf("failed report returned summary %+v, want nil", summary)
	}
	if outcome != blockApplyMetricNone {
		t.Fatalf("outcome=%v, want blockApplyMetricNone (the block was neither accepted nor consensus-rejected)", outcome)
	}

	if after := engine.chainState.view(); after != before {
		t.Fatalf("chain state not rolled back: after=%+v, before=%+v", after, before)
	}
	tipHeight, tipHash, tipOK, err := store.Tip()
	if err != nil {
		t.Fatalf("store.Tip(after): %v", err)
	}
	if tipOK != beforeTipOK || tipHeight != beforeTipHeight || tipHash != beforeTipHash {
		t.Fatalf("store tip moved: ok=%v height=%d hash=%x, want ok=%v height=%d hash=%x",
			tipOK, tipHeight, tipHash, beforeTipOK, beforeTipHeight, beforeTipHash)
	}
	afterIndex, err := store.CanonicalIndexSnapshot()
	if err != nil {
		t.Fatalf("CanonicalIndexSnapshot(after): %v", err)
	}
	if !reflect.DeepEqual(afterIndex, beforeIndex) {
		t.Fatalf("canonical index changed: after=%v, before=%v", afterIndex, beforeIndex)
	}
	if got := mempool.Len(); got != beforeMempoolLen {
		t.Fatalf("mempool len=%d, want %d", got, beforeMempoolLen)
	}
}

// --- complete-DA-set extraction core -----------------------------------------
//
// These rows live in package node because the extraction core does. Go
// attributes statement coverage to the package under test, so exercising
// CompleteDASetIDsFromParsedBlock from package p2p left the core reading as
// dead code in node's profile. node/p2p keeps only the rows whose subject is
// p2p behavior — the bytes entry, the canonical-applied iteration, and the
// bytes-vs-parsed equivalence row, which is precisely about the two entry
// points agreeing and therefore has to sit on the p2p side.

func daExtractionTestID(seed byte) (out [32]byte) {
	out[0] = seed
	return out
}

// daExtractionBlockBytes encodes a real block carrying txs, so a row exercises
// the same parse-then-extract path ConsumeAcceptedBlockDASets takes rather than
// only the in-memory core.
func daExtractionBlockBytes(t *testing.T, daTxs ...[]byte) []byte {
	t.Helper()
	txs := make([][]byte, 0, len(daTxs)+1)
	txs = append(txs, coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 1, consensus.BlockSubsidy(1, 0)))
	txs = append(txs, daTxs...)
	return buildMultiTxBlock(t, devnetGenesisBlockHash, consensus.POW_LIMIT, reorgTestTimestamp(1), txs...)
}

func daExtractionCommitTxBytes(t *testing.T, daID [32]byte, nonce uint64, payloads ...[]byte) []byte {
	t.Helper()
	hasher := sha3.New256()
	for _, payload := range payloads {
		if _, err := hasher.Write(payload); err != nil {
			t.Fatalf("hash DA payload: %v", err)
		}
	}
	return mustMarshalTxForNodeTest(t, &consensus.Tx{
		Version: 1,
		TxKind:  0x01,
		TxNonce: nonce,
		Outputs: []consensus.TxOutput{{
			Value:        0,
			CovenantType: consensus.COV_TYPE_DA_COMMIT,
			CovenantData: hasher.Sum(nil),
		}},
		DaCommitCore: &consensus.DaCommitCore{DaID: daID, ChunkCount: uint16(len(payloads))},
	})
}

func daExtractionChunkTxBytes(t *testing.T, daID [32]byte, index uint16, nonce uint64, payload []byte) []byte {
	t.Helper()
	chunkHash := sha3.Sum256(payload)
	return mustMarshalTxForNodeTest(t, &consensus.Tx{
		Version:     1,
		TxKind:      0x02,
		TxNonce:     nonce,
		DaChunkCore: &consensus.DaChunkCore{DaID: daID, ChunkIndex: index, ChunkHash: chunkHash},
		DaPayload:   append([]byte(nil), payload...),
	})
}

// mustParseCompleteDASetIDs runs the extraction core over real block bytes:
// parse first, exactly as ConsumeAcceptedBlockDASets does, so these rows pin the
// behavior of the encoded-block entry and not only of the core.
func mustParseCompleteDASetIDs(t *testing.T, blockBytes []byte) [][32]byte {
	t.Helper()
	parsed, err := consensus.ParseBlockBytes(blockBytes)
	if err != nil {
		t.Fatalf("ParseBlockBytes: %v", err)
	}
	ids, err := CompleteDASetIDsFromParsedBlock(parsed)
	if err != nil {
		t.Fatalf("CompleteDASetIDsFromParsedBlock: %v", err)
	}
	return ids
}

// daSetTxObjects returns the tx objects of one DA set: a single commit declaring
// chunkCount, plus one chunk per index in present. Building objects rather than
// wire bytes keeps the high-cardinality rows (128 sets) cheap; the encoded path
// is covered by the mustParseCompleteDASetIDs rows.
func daSetTxObjects(daID [32]byte, chunkCount uint16, present []uint16) []*consensus.Tx {
	txs := []*consensus.Tx{{
		TxKind:       0x01,
		DaCommitCore: &consensus.DaCommitCore{DaID: daID, ChunkCount: chunkCount},
	}}
	for _, index := range present {
		txs = append(txs, &consensus.Tx{
			TxKind:      0x02,
			DaChunkCore: &consensus.DaChunkCore{DaID: daID, ChunkIndex: index},
		})
	}
	return txs
}

func TestCompleteDASetIDsFromParsedBlockNoDA(t *testing.T) {
	block := daExtractionBlockBytes(t)

	if got := mustParseCompleteDASetIDs(t, block); len(got) != 0 {
		t.Fatalf("got %d DA ids, want none", len(got))
	}
}

func TestCompleteDASetIDsFromParsedBlockSingle(t *testing.T) {
	daID := daExtractionTestID(0x41)
	payload := []byte("payload")
	block := daExtractionBlockBytes(
		t,
		daExtractionCommitTxBytes(t, daID, 1, payload),
		daExtractionChunkTxBytes(t, daID, 0, 2, payload),
	)

	got := mustParseCompleteDASetIDs(t, block)
	if !reflect.DeepEqual(got, [][32]byte{daID}) {
		t.Fatalf("got %x, want %x", got, [][32]byte{daID})
	}
}

func TestCompleteDASetIDsFromParsedBlockSorted(t *testing.T) {
	low := daExtractionTestID(0x01)
	mid := daExtractionTestID(0x7f)
	high := daExtractionTestID(0xf0)
	lowPayload, midPayload, highPayload := []byte("low"), []byte("mid"), []byte("high")
	block := daExtractionBlockBytes(
		t,
		daExtractionCommitTxBytes(t, high, 1, highPayload),
		daExtractionChunkTxBytes(t, high, 0, 2, highPayload),
		daExtractionCommitTxBytes(t, low, 3, lowPayload),
		daExtractionChunkTxBytes(t, low, 0, 4, lowPayload),
		daExtractionCommitTxBytes(t, mid, 7, midPayload),
		daExtractionChunkTxBytes(t, mid, 0, 8, midPayload),
	)

	got := mustParseCompleteDASetIDs(t, block)
	want := [][32]byte{low, mid, high}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %x, want %x", got, want)
	}
}

func TestCompleteDASetIDsFromParsedBlockNilBlock(t *testing.T) {
	if _, err := CompleteDASetIDsFromParsedBlock(nil); err == nil {
		t.Fatal("nil parsed block returned nil error")
	}
}

// TestCompleteDASetIDsFromParsedBlockAtBatchBoundary pins the exact
// MAX_DA_BATCHES_PER_BLOCK boundary: a block carrying the maximum number of
// complete sets reports every one of them, ascending, and does not trip the
// defensive cap.
func TestCompleteDASetIDsFromParsedBlockAtBatchBoundary(t *testing.T) {
	var txs []*consensus.Tx
	want := make([][32]byte, 0, consensus.MAX_DA_BATCHES_PER_BLOCK)
	for i := 0; i < consensus.MAX_DA_BATCHES_PER_BLOCK; i++ {
		daID := daExtractionTestID(byte(i))
		want = append(want, daID)
		txs = append(txs, daSetTxObjects(daID, 1, []uint16{0})...)
	}

	got, err := CompleteDASetIDsFromParsedBlock(&consensus.ParsedBlock{Txs: txs})
	if err != nil {
		t.Fatalf("CompleteDASetIDsFromParsedBlock: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %d ids, want the %d ascending boundary ids", len(got), len(want))
	}
}

// TestCompleteDASetIDsFromParsedBlockBoundaryWithOneIncomplete pins that
// completeness is decided per set even at the boundary: 128 commits with one set
// missing a chunk yields exactly the other 127 and never the incomplete id.
func TestCompleteDASetIDsFromParsedBlockBoundaryWithOneIncomplete(t *testing.T) {
	incomplete := daExtractionTestID(byte(consensus.MAX_DA_BATCHES_PER_BLOCK - 1))
	var txs []*consensus.Tx
	want := make([][32]byte, 0, consensus.MAX_DA_BATCHES_PER_BLOCK-1)
	for i := 0; i < consensus.MAX_DA_BATCHES_PER_BLOCK; i++ {
		daID := daExtractionTestID(byte(i))
		if daID == incomplete {
			// Declares two chunks, carries only index 0.
			txs = append(txs, daSetTxObjects(daID, 2, []uint16{0})...)
			continue
		}
		want = append(want, daID)
		txs = append(txs, daSetTxObjects(daID, 1, []uint16{0})...)
	}

	got, err := CompleteDASetIDsFromParsedBlock(&consensus.ParsedBlock{Txs: txs})
	if err != nil {
		t.Fatalf("CompleteDASetIDsFromParsedBlock: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %d ids, want %d complete ids without %x", len(got), len(want), incomplete)
	}
}

// TestCompleteDASetIDsFromParsedBlockOverBatchCap pins the defensive cap: a
// block that would report more complete sets than consensus can ever accept is
// an error, never a silently truncated list. Consensus rejects such a block
// first (BLOCK_ERR_DA_BATCH_EXCEEDED), so this branch is unreachable from the
// canonical-apply path and exists only so an unvalidated caller cannot under-report.
func TestCompleteDASetIDsFromParsedBlockOverBatchCap(t *testing.T) {
	var txs []*consensus.Tx
	for i := 0; i <= consensus.MAX_DA_BATCHES_PER_BLOCK; i++ {
		daID := [32]byte{byte(i), byte(i >> 8)}
		txs = append(txs, daSetTxObjects(daID, 1, []uint16{0})...)
	}

	if _, err := CompleteDASetIDsFromParsedBlock(&consensus.ParsedBlock{Txs: txs}); err == nil {
		t.Fatal("over-cap complete DA set count returned nil error")
	}
}

func TestCompleteDASetIDsFromParsedBlockIncompleteShapes(t *testing.T) {
	daID := daExtractionTestID(0x71)
	cases := []struct {
		name string
		txs  []*consensus.Tx
	}{
		{"duplicate commit", append(daSetTxObjects(daID, 1, []uint16{0}), &consensus.Tx{
			TxKind:       0x01,
			DaCommitCore: &consensus.DaCommitCore{DaID: daID, ChunkCount: 1},
		})},
		{"zero chunk count", daSetTxObjects(daID, 0, nil)},
		{"chunk count mismatch", daSetTxObjects(daID, 2, []uint16{0})},
		{"chunk index gap", daSetTxObjects(daID, 2, []uint16{0, 2})},
		{"chunk count over max", daSetTxObjects(daID, uint16(consensus.MAX_DA_CHUNK_COUNT)+1, []uint16{0})},
		{"chunks without commit", daSetTxObjects(daID, 1, []uint16{0})[1:]},
		{"commit without DA core", []*consensus.Tx{{TxKind: 0x01}}},
		{"chunk without DA core", append(daSetTxObjects(daID, 1, nil), &consensus.Tx{TxKind: 0x02})},
		{"nil transaction beside an incomplete set", append(daSetTxObjects(daID, 2, []uint16{0}), nil)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := CompleteDASetIDsFromParsedBlock(&consensus.ParsedBlock{Txs: tc.txs})
			if err != nil {
				t.Fatalf("CompleteDASetIDsFromParsedBlock: %v", err)
			}
			for _, id := range got {
				if id == daID {
					t.Fatalf("%s reported %x as a complete DA set", tc.name, daID)
				}
			}
		})
	}
}

// An over-bound ancestor block is local store corruption while retaining its
// typed size cause for callers that need the operational diagnosis.
func TestLoadVerifiedBranchAncestorOverBoundBlockIsLocalCorruption(t *testing.T) {
	dir := t.TempDir()
	store := mustCreateBlockStore(t, BlockStorePath(dir))
	target := consensus.POW_LIMIT
	engine, err := NewSyncEngine(NewChainState(), store, DefaultSyncConfig(&target, devnetGenesisChainID, ChainStatePath(dir)))
	if err != nil {
		t.Fatalf("NewSyncEngine: %v", err)
	}
	hash := [32]byte{0: 0x11}
	blockPath := filepath.Join(BlockStorePath(dir), "blocks", hex.EncodeToString(hash[:])+".bin")
	createSparseFile(t, blockPath, blockFileMaxBytes+1)
	_, _, err = engine.loadVerifiedBranchAncestor(hash)
	if !errors.Is(err, errBranchStoreCorrupt) || !errors.Is(err, errStoreFileTooLarge) || errors.Is(err, ErrParentNotFound) {
		t.Fatalf("want local corruption with typed size cause, got %v", err)
	}
	var txErr *consensus.TxError
	if errors.As(err, &txErr) {
		t.Fatalf("over-bound ancestor must not be peer-attributable: %v", err)
	}
}

func TestLoadVerifiedStoredBlockReadFailuresAreLocalCorruption(t *testing.T) {
	t.Run("missing file", func(t *testing.T) {
		engine, _, _ := newReorgTestEngine(t)
		hash := [32]byte{0x71}
		_, err := engine.loadVerifiedStoredBlock(hash)
		assertBranchStoreCorruption(t, err)
		if !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("missing stored block must retain os.ErrNotExist: %v", err)
		}
		_, _, err = engine.loadVerifiedBranchAncestor(hash)
		if !errors.Is(err, ErrParentNotFound) || errors.Is(err, errBranchStoreCorrupt) {
			t.Fatalf("missing side ancestor=%v, want ErrParentNotFound only", err)
		}
	})

	t.Run("wrong kind", func(t *testing.T) {
		engine, store, _ := newReorgTestEngine(t)
		hash := [32]byte{0x72}
		path := filepath.Join(store.blocksDir, hex.EncodeToString(hash[:])+".bin")
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatalf("Mkdir(block path): %v", err)
		}
		_, err := engine.loadVerifiedStoredBlock(hash)
		assertBranchStoreCorruption(t, err)
		var pathErr *fs.PathError
		if !errors.As(err, &pathErr) {
			t.Fatalf("wrong-kind read must retain a path error: %v", err)
		}
		_, _, err = engine.loadVerifiedBranchAncestor(hash)
		assertBranchStoreCorruption(t, err)
	})
}

// TestApplyBlockWithReorgPendingOutpointUsesOneGenerationForTheWholeBranch
// proves the preferred-branch row: the whole winning branch runs inside EXACTLY
// one canonical transition, so exactly one generation is consumed no matter how
// many rows move; one final-C1 M/O plan removes the included record and claim,
// and the owner's stable tip becomes the branch tip.
func TestApplyBlockWithReorgPendingOutpointUsesOneGenerationForTheWholeBranch(t *testing.T) {
	f := newPendingOutpointSyncFixture(t)
	forkHash, forkHeight, forkGenerated := f.tipHash, f.tipHeight, f.alreadyGenerated
	spend := f.spend(t, 700, 1)

	subsidyA101 := consensus.BlockSubsidy(forkHeight+1, forkGenerated)
	blockA101 := buildSingleTxBlock(t, forkHash, f.target, 202, reorgTestCoinbaseForAddress(t, forkHeight+1, subsidyA101, f.sourceAddress))
	summaryA101, err := f.engine.ApplyBlock(blockA101, nil)
	if err != nil {
		t.Fatalf("ApplyBlock(A101): %v", err)
	}
	if err := f.mempool.AddTx(spend); err != nil {
		t.Fatalf("AddTx(spend): %v", err)
	}
	beforeReorg := mustAdmissionContext(t, f.owner, "before the reorg")
	if beforeReorg.StableTip.Hash != summaryA101.BlockHash {
		t.Fatalf("stable tip before reorg=%+v, want A101 %x", beforeReorg.StableTip, summaryA101.BlockHash)
	}

	// B101 includes the spend and B102 extends it, so the B branch outweighs A
	// and the reorg disconnects one block while connecting two.
	blockB101 := f.blockIncluding(t, forkHash, forkHeight+1, forkGenerated, 203, spend)
	b101Parsed, b101Hash := mustParseReorgBlockForTest(t, blockB101)
	if err := f.store.StoreBlock(b101Hash, b101Parsed.HeaderBytes, blockB101); err != nil {
		t.Fatalf("StoreBlock(B101): %v", err)
	}
	subsidyB101 := consensus.BlockSubsidy(forkHeight+1, forkGenerated)
	subsidyB102 := consensus.BlockSubsidy(forkHeight+2, forkGenerated+subsidyB101)
	blockB102 := buildSingleTxBlock(t, b101Hash, f.target, 204, reorgTestCoinbaseForAddress(t, forkHeight+2, subsidyB102, f.destAddress))
	summaryB102, err := f.engine.ApplyBlockWithReorg(blockB102, nil)
	if err != nil {
		t.Fatalf("ApplyBlockWithReorg(B102): %v", err)
	}

	afterReorg := mustAdmissionContext(t, f.owner, "after the reorg")
	if afterReorg.Generation != beforeReorg.Generation+1 {
		t.Fatalf("generation after reorg=%d, want exactly one advance from %d for the whole branch", afterReorg.Generation, beforeReorg.Generation)
	}
	if afterReorg.StableTip.Hash != summaryB102.BlockHash || afterReorg.StableTip.Height != summaryB102.BlockHeight {
		t.Fatalf("stable tip after reorg=%+v, want B102 (%d,%x)", afterReorg.StableTip, summaryB102.BlockHeight, summaryB102.BlockHash)
	}
	if got := f.mempool.Len(); got != 0 {
		t.Fatalf("mempool len after reorg=%d, want 0 after final-C1 planning", got)
	}
	outpoints, claims, highWater := ownerClaimCount(f.owner)
	if outpoints != 0 || claims != 0 {
		t.Fatalf("owner still holds outpoints=%d claims=%d after the reorg", outpoints, claims)
	}
	if highWater != 1 {
		t.Fatalf("token high-water=%d after the reorg, want the consumed sequence retained", highWater)
	}
}

// TestApplyBlockWithReorgPendingOutpointRestoresExactTokensOnFailure proves the
// abort row: a reorg that fails after prepared rows restores the record, its
// exact token and its finalized claim, leaves the owner's stable tip untouched,
// and still retains the advanced generation high-water so the failed transition
// can never reproduce an earlier admission context.
func TestApplyBlockWithReorgPendingOutpointRestoresExactTokensOnFailure(t *testing.T) {
	f := newPendingOutpointSyncFixture(t)
	forkHash, forkHeight, forkGenerated := f.tipHash, f.tipHeight, f.alreadyGenerated
	spend := f.spend(t, 700, 1)
	if err := f.mempool.AddTx(spend); err != nil {
		t.Fatalf("AddTx(spend): %v", err)
	}
	spendID := txID(t, spend)
	f.mempool.mu.Lock()
	residentToken := f.mempool.txs[spendID].token
	f.mempool.mu.Unlock()

	subsidyA101 := consensus.BlockSubsidy(forkHeight+1, forkGenerated)
	blockA101 := buildSingleTxBlock(t, forkHash, f.target, 202, reorgTestCoinbaseForAddress(t, forkHeight+1, subsidyA101, f.sourceAddress))
	summaryA101, err := f.engine.ApplyBlock(blockA101, nil)
	if err != nil {
		t.Fatalf("ApplyBlock(A101): %v", err)
	}
	beforeReorg := mustAdmissionContext(t, f.owner, "before the failed reorg")

	// This branch omits the spend: final-C1 retains the record, and failure restores it.
	blockB101 := buildSingleTxBlock(t, forkHash, f.target, 203, reorgTestCoinbaseForAddress(t, forkHeight+1, subsidyA101, f.destAddress))
	b101Parsed, b101Hash := mustParseReorgBlockForTest(t, blockB101)
	if err := f.store.StoreBlock(b101Hash, b101Parsed.HeaderBytes, blockB101); err != nil {
		t.Fatalf("StoreBlock(B101): %v", err)
	}
	blockB102 := f.blockIncluding(t, b101Hash, forkHeight+2, forkGenerated+subsidyA101, 204, spend)

	prevWrite := writeFileAtomicFn
	t.Cleanup(func() { writeFileAtomicFn = prevWrite })
	indexWrites, injected := 0, false
	writeFileAtomicFn = func(path string, data []byte, mode os.FileMode) error {
		if path == f.store.indexPath {
			indexWrites++
			if indexWrites == 1 {
				injected = true
				return newAtomicWriteError(atomicWriteBeforeNamespaceCommit, path, atomicWriteOverwrite, os.ErrPermission)
			}
		}
		return prevWrite(path, data, mode)
	}
	if _, err := f.engine.ApplyBlockWithReorg(blockB102, nil); err == nil {
		t.Fatal("expected the injected reorg persistence failure")
	}
	if !injected {
		t.Fatal("the injected canonical-index write failure never fired")
	}

	if f.engine.chainState.TipHash != summaryA101.BlockHash {
		t.Fatalf("chainstate tip=%x after the failed reorg, want A101 %x", f.engine.chainState.TipHash, summaryA101.BlockHash)
	}
	entry, claim := residentClaim(t, f.mempool, spendID)
	if entry.token != residentToken {
		t.Fatalf("restored token seq=%d, want the exact pre-reorg seq %d", entry.token.seq, residentToken.seq)
	}
	if claim == nil || !claim.finalized || claim.txid != spendID {
		t.Fatalf("restored claim=%+v, want the exact finalized claim", claim)
	}
	if got, ok := f.owner.txidForOutpoint(f.sourceOutpoint); !ok || got != spendID {
		t.Fatalf("restored index row=(%x,%v), want %x", got, ok, spendID)
	}
	afterReorg := mustAdmissionContext(t, f.owner, "after the failed reorg")
	if afterReorg.StableTip != beforeReorg.StableTip {
		t.Fatalf("stable tip after the failed reorg=%+v, want %+v unchanged", afterReorg.StableTip, beforeReorg.StableTip)
	}
	if afterReorg.Generation != beforeReorg.Generation+1 {
		t.Fatalf("generation after the failed reorg=%d, want the advanced high-water %d", afterReorg.Generation, beforeReorg.Generation+1)
	}
}

// storedSideBranch builds and stores a side branch of depth blocks on top of
// prevHash, oldest-first, the shape collectBranchToCanonical hands preparation.
func (f *pendingOutpointSyncFixture) storedSideBranch(t *testing.T, prevHash [32]byte, height, alreadyGenerated uint64, depth int) []reorgBranchBlock {
	t.Helper()
	branch := make([]reorgBranchBlock, 0, depth)
	for i := 0; i < depth; i++ {
		blockHeight := height + uint64(i)
		subsidy := consensus.BlockSubsidy(blockHeight, alreadyGenerated)
		coinbase := reorgTestCoinbaseForAddress(t, blockHeight, subsidy, f.destAddress)
		blockBytes := buildSingleTxBlock(t, prevHash, f.target, 300+blockHeight, coinbase)
		parsed, hash := mustParseReorgBlockForTest(t, blockBytes)
		if err := f.store.StoreBlock(hash, parsed.HeaderBytes, blockBytes); err != nil {
			t.Fatalf("StoreBlock(side height %d): %v", blockHeight, err)
		}
		branch = append(branch, reorgBranchBlock{hash: hash, blockBytes: blockBytes, parsed: parsed, header: parsed.Header})
		prevHash, alreadyGenerated = hash, alreadyGenerated+subsidy
	}
	return branch
}

// applyForkBlock applies one canonical block on the fixture tip, so the side
// branch below has a canonical block to disconnect.
func (f *pendingOutpointSyncFixture) applyForkBlock(t *testing.T) *ChainStateConnectSummary {
	t.Helper()
	subsidy := consensus.BlockSubsidy(f.tipHeight+1, f.alreadyGenerated)
	coinbase := reorgTestCoinbaseForAddress(t, f.tipHeight+1, subsidy, f.sourceAddress)
	summary, err := f.engine.ApplyBlock(buildSingleTxBlock(t, f.tipHash, f.target, 202, coinbase), nil)
	if err != nil {
		t.Fatalf("ApplyBlock(fork block): %v", err)
	}
	return summary
}

// extendCanonical applies count blocks on the fixture tip through the production
// apply path and advances the fixture's own tip cursor with them.
func (f *pendingOutpointSyncFixture) extendCanonical(t *testing.T, count int, baseTimestamp uint64) {
	t.Helper()
	for i := 0; i < count; i++ {
		height := f.tipHeight + 1
		subsidy := consensus.BlockSubsidy(height, f.alreadyGenerated)
		coinbase := reorgTestCoinbaseForAddress(t, height, subsidy, f.sourceAddress)
		summary, err := f.engine.ApplyBlock(buildSingleTxBlock(t, f.tipHash, f.target, baseTimestamp+uint64(i), coinbase), nil)
		if err != nil {
			t.Fatalf("ApplyBlock(canonical height %d): %v", height, err)
		}
		f.tipHash, f.tipHeight, f.alreadyGenerated = summary.BlockHash, height, f.alreadyGenerated+subsidy
	}
}

// consensusInvalidTipOn returns one block on prevHash whose timestamp is at or
// below the canonical MTP, so ConnectBlock rejects it on consensus. It is NOT
// stored: it arrives through ApplyBlockWithReorg exactly as a peer's block would.
func (f *pendingOutpointSyncFixture) consensusInvalidTipOn(t *testing.T, prevHash [32]byte, height, alreadyGenerated uint64) []byte {
	t.Helper()
	coinbase := reorgTestCoinbaseForAddress(t, height, consensus.BlockSubsidy(height, alreadyGenerated), f.destAddress)
	return buildSingleTxBlock(t, prevHash, f.target, 1, coinbase)
}

// TestPreferredBranchConsensusRejectionCountsExactlyOnce pins the canonical
// block-apply accounting of the preferred-branch path: exactly one rejected
// outcome for a consensus rejection anywhere in the SELECTED winning branch, and
// zero for everything that is not a consensus verdict on a selected candidate.
//
// The rejection is recorded during preparation because that is where the branch
// path runs ConnectBlock at all; the commit half revalidates nothing. Rows that
// prepared successfully before the failing one count neither accepted nor
// rejected: the branch never opened a transition, so it never published.
func TestPreferredBranchConsensusRejectionCountsExactlyOnce(t *testing.T) {
	f := newPendingOutpointSyncFixture(t)
	forkHash, forkHeight, forkGenerated := f.tipHash, f.tipHeight, f.alreadyGenerated
	f.extendCanonical(t, 1, 202)

	assertCounts := func(t *testing.T, before BlockApplyCounts, wantRejectedDelta uint64, what string) {
		t.Helper()
		want := BlockApplyCounts{Accepted: before.Accepted, Rejected: before.Rejected + wantRejectedDelta}
		if got := f.engine.BlockApplyCounts(); got != want {
			t.Fatalf("%s: block-apply counts=%+v, want %+v", what, got, want)
		}
	}

	t.Run("selected winning branch consensus rejection", func(t *testing.T) {
		// A two-block stored prefix plus an invalid tip outweighs the one-block
		// canonical extension, so fork choice SELECTS this branch and preparation
		// reaches its third row after the first two prepared successfully.
		branch := f.storedSideBranch(t, forkHash, forkHeight+1, forkGenerated, 2)
		generated := forkGenerated
		for i := 0; i < 2; i++ {
			generated += consensus.BlockSubsidy(forkHeight+1+uint64(i), generated)
		}
		invalidTip := f.consensusInvalidTipOn(t, branch[1].hash, forkHeight+3, generated)

		before := f.engine.BlockApplyCounts()
		canonicalBefore := f.engine.chainState.view()
		_, err := f.engine.ApplyBlockWithReorg(invalidTip, nil)
		var txErr *consensus.TxError
		if !errors.As(err, &txErr) {
			t.Fatalf("err=%v, want a consensus rejection of the selected branch tip", err)
		}
		assertCounts(t, before, 1, "selected-branch consensus rejection")
		if live := f.engine.chainState.view(); live != canonicalBefore {
			t.Fatalf("canonical state moved to %+v although the branch never published, want %+v", live, canonicalBefore)
		}
	})

	t.Run("orphan candidate counts nothing", func(t *testing.T) {
		before := f.engine.BlockApplyCounts()
		orphan := f.consensusInvalidTipOn(t, [32]byte{0xab}, f.tipHeight+1, f.alreadyGenerated)
		if _, err := f.engine.ApplyBlockWithReorg(orphan, nil); !errors.Is(err, ErrParentNotFound) {
			t.Fatalf("err=%v, want ErrParentNotFound", err)
		}
		assertCounts(t, before, 0, "orphan / missing parent")
	})

	t.Run("rejected side-chain store counts nothing", func(t *testing.T) {
		// One more canonical block puts the chain two ahead of the fork, so a
		// single side block is strictly lower work and takes the side-chain
		// storage path instead of being selected. Its consensus rejection there
		// is not a canonical apply outcome.
		f.extendCanonical(t, 1, 203)
		before := f.engine.BlockApplyCounts()
		sideInvalid := f.consensusInvalidTipOn(t, forkHash, forkHeight+1, forkGenerated)
		var txErr *consensus.TxError
		if _, err := f.engine.ApplyBlockWithReorg(sideInvalid, nil); !errors.As(err, &txErr) {
			t.Fatalf("err=%v, want the side-chain candidate's consensus rejection", err)
		}
		assertCounts(t, before, 0, "rejected side-chain storage")
	})
}

// TestCanonicalCutoverRetainsOnlyChargedRowMetadata pins the plan's retention
// shape: after staging and validation the transition keeps ONLY charged
// (height, hash) descriptors and A1 IDs. No block or header bytes, no
// ParsedBlock, no BlockUndo, no UTXO delta and no transaction payload survive,
// and a reorg holds exactly two O(UTXO) ChainState images — the immutable common
// checkpoint and the rolling image that becomes final C1 — never a third.
func TestCanonicalCutoverRetainsOnlyChargedRowMetadata(t *testing.T) {
	descriptor := reflect.TypeOf(canonicalRowDescriptor{})
	for i := 0; i < descriptor.NumField(); i++ {
		switch descriptor.Field(i).Type.Kind() {
		case reflect.Uint64, reflect.Array:
		default:
			t.Fatalf("canonicalRowDescriptor.%s is %v: a charged row is (height, hash) only", descriptor.Field(i).Name, descriptor.Field(i).Type)
		}
	}
	if got := unsafe.Sizeof(canonicalRowDescriptor{}); got != canonicalPlanMetadataRowBytes {
		t.Fatalf("canonicalRowDescriptor size=%d, want the charged %d bytes", got, canonicalPlanMetadataRowBytes)
	}
	chainStatePtr := reflect.TypeOf((*ChainState)(nil))
	prepared := reflect.TypeOf(preparedBranchBlock{})
	for i := 0; i < prepared.NumField(); i++ {
		field := prepared.Field(i)
		if field.Type == chainStatePtr || field.Type.Kind() == reflect.Map {
			t.Fatalf("preparedBranchBlock.%s is %v: a prepared row must retain no chainstate and no map", field.Name, field.Type)
		}
	}

	f := newPendingOutpointSyncFixture(t)
	forkHash, forkHeight, forkGenerated := f.tipHash, f.tipHeight, f.alreadyGenerated
	summaryA := f.applyForkBlock(t)
	liveUtxos, liveUtxoHash := len(f.engine.chainState.Utxos), f.engine.chainState.UtxoSetHash()

	branch := f.storedSideBranch(t, forkHash, forkHeight+1, forkGenerated, 2)
	canonicalIndex, err := f.engine.canonicalIndexPreflight()
	if err != nil {
		t.Fatalf("canonicalIndexPreflight: %v", err)
	}
	plan, summary, reorgDepth, _, err := f.engine.planPreferredBranch(canonicalIndex, branch, forkHeight)
	if err != nil {
		t.Fatalf("planPreferredBranch: %v", err)
	}
	if len(plan.connect) != 2 || len(plan.disconnect) != 1 || reorgDepth != 1 || summary == nil {
		t.Fatalf("connect=%d disconnect=%d depth=%d, want 2/1/1", len(plan.connect), len(plan.disconnect), reorgDepth)
	}
	if plan.checkpoint == plan.final || plan.checkpoint.Height != forkHeight || plan.checkpoint.TipHash != forkHash {
		t.Fatalf("checkpoint=(%d,%x) shared_with_final=%v, want the immutable common ancestor", plan.checkpoint.Height, plan.checkpoint.TipHash, plan.checkpoint == plan.final)
	}
	if plan.final.Height != forkHeight+2 || plan.final.TipHash != branch[1].hash {
		t.Fatalf("final C1=(%d,%x), want the branch tip", plan.final.Height, plan.final.TipHash)
	}
	if plan.disconnect[0] != (canonicalRowDescriptor{height: forkHeight + 1, hash: summaryA.BlockHash}) {
		t.Fatalf("disconnect row=%+v, want the old tip", plan.disconnect[0])
	}
	for i, row := range plan.connect {
		if row != (canonicalRowDescriptor{height: forkHeight + 1 + uint64(i), hash: branch[i].hash}) {
			t.Fatalf("connect row %d=%+v, want ascending branch rows", i, row)
		}
	}
	if len(plan.applied) != len(plan.connect) {
		t.Fatalf("A1 rows=%d, want one per newly canonical block", len(plan.applied))
	}
	if len(plan.staged) != 2 {
		t.Fatalf("staged rows=%d before staging, want the new suffix", len(plan.staged))
	}

	// Staging consumes and releases the payload; nothing depth-proportional
	// survives into the transition.
	if err := f.engine.proveCanonicalRecoverySet(plan); err != nil {
		t.Fatalf("proveCanonicalRecoverySet: %v", err)
	}
	if plan.staged != nil {
		t.Fatalf("staged payload survived staging: %d rows", len(plan.staged))
	}
	charge, err := canonicalPlanMetadataCharge(plan.disconnect, plan.connect, plan.applied)
	if err != nil || charge != canonicalPlanMetadataBaseBytes+3*canonicalPlanMetadataRowBytes {
		t.Fatalf("charge=%d err=%v, want the exact base plus three rows", charge, err)
	}
	if len(plan.connect) >= liveUtxos {
		t.Fatalf("retained rows=%d against a %d-entry live set, want compact metadata", len(plan.connect), liveUtxos)
	}

	// Planning and staging touch no live canonical state.
	if f.engine.chainState.TipHash != summaryA.BlockHash || f.engine.chainState.UtxoSetHash() != liveUtxoHash {
		t.Fatalf("planning mutated the live chainstate: tip=%x", f.engine.chainState.TipHash)
	}
	if storeHeight, storeHash, ok, err := f.store.Tip(); err != nil || !ok || storeHash != summaryA.BlockHash || storeHeight != summaryA.BlockHeight {
		t.Fatalf("planning moved the blockstore tip to (%d,%x,ok=%v,err=%v)", storeHeight, storeHash, ok, err)
	}
}

// TestCanonicalCutoverWinningReorgOneCommit pins the winning-reorg row: one
// final private C1, EXACTLY ONE canonical-index write however many rows the
// branch has, no intermediate public tip at that write, and a deterministic
// requeue that runs only after the transition reopened admission. The refused
// first attempt proves an OLD/open commit leaves the exact old image, and the
// disconnects afterwards prove the staged per-row undo is real.
func TestCanonicalCutoverWinningReorgOneCommit(t *testing.T) {
	f := newPendingOutpointSyncFixture(t)
	forkHash, forkHeight, forkGenerated := f.tipHash, f.tipHeight, f.alreadyGenerated
	forkUtxoHash := f.engine.chainState.UtxoSetHash()
	summaryA := f.applyForkBlock(t)
	beforeReorgUtxoHash := f.engine.chainState.UtxoSetHash()
	branch := f.storedSideBranch(t, forkHash, forkHeight+1, forkGenerated, 2)
	candidate := branch[len(branch)-1]

	type indexObservation struct {
		height uint64
		hash   [32]byte
	}
	prevWrite := writeFileAtomicFn
	t.Cleanup(func() { writeFileAtomicFn = prevWrite })
	observed, failWrite, injected := []indexObservation{}, true, false
	writeFileAtomicFn = func(path string, data []byte, mode os.FileMode) error {
		if path == f.store.indexPath {
			view := f.engine.chainState.view()
			observed = append(observed, indexObservation{height: view.height, hash: view.tipHash})
			if failWrite {
				injected = true
				// A PROVEN pre-namespace refusal: nothing crossed the commit
				// point, so the class is precommit and the truth is OLD/open.
				return newAtomicWriteError(atomicWriteBeforeNamespaceCommit, path, atomicWriteOverwrite, os.ErrPermission)
			}
		}
		return prevWrite(path, data, mode)
	}

	if _, err := f.engine.ApplyBlockWithReorg(candidate.blockBytes, nil); err == nil || !injected {
		t.Fatalf("expected the injected commit failure (err=%v injected=%v)", err, injected)
	}
	if len(observed) != 1 {
		t.Fatalf("canonical index writes=%d on a refused two-row reorg, want exactly 1", len(observed))
	}
	if f.engine.persistenceFaulted() {
		t.Fatal("a proven pre-namespace commit refusal latched the engine")
	}
	if f.engine.chainState.TipHash != summaryA.BlockHash || f.engine.chainState.Height != summaryA.BlockHeight {
		t.Fatalf("chainstate tip=(%d,%x) after the refused reorg, want A (%d,%x)",
			f.engine.chainState.Height, f.engine.chainState.TipHash, summaryA.BlockHeight, summaryA.BlockHash)
	}
	if got := f.engine.chainState.UtxoSetHash(); got != beforeReorgUtxoHash {
		t.Fatalf("utxo set hash=%x after the refused reorg, want the exact pre-reorg set %x", got, beforeReorgUtxoHash)
	}

	failWrite, observed = false, nil
	summaryB, err := f.engine.ApplyBlockWithReorg(candidate.blockBytes, nil)
	if err != nil {
		t.Fatalf("ApplyBlockWithReorg(retry): %v", err)
	}
	if summaryB.BlockHash != candidate.hash || summaryB.BlockHeight != forkHeight+2 {
		t.Fatalf("reorg summary=(%d,%x), want the branch tip (%d,%x)", summaryB.BlockHeight, summaryB.BlockHash, forkHeight+2, candidate.hash)
	}
	if len(observed) != 1 {
		t.Fatalf("canonical index writes=%d for a two-row reorg, want exactly 1", len(observed))
	}
	// The single commit happens with the OLD image still public: no reader can
	// observe an intermediate tip, because publication follows classification.
	if observed[0] != (indexObservation{height: summaryA.BlockHeight, hash: summaryA.BlockHash}) {
		t.Fatalf("live chainstate at the commit=(%d,%x), want the old tip (%d,%x)", observed[0].height, observed[0].hash, summaryA.BlockHeight, summaryA.BlockHash)
	}
	if len(summaryB.CanonicalAppliedBlocks) != 2 {
		t.Fatalf("A1 rows=%d, want one per newly canonical block", len(summaryB.CanonicalAppliedBlocks))
	}

	for i := range branch {
		if _, err := f.engine.DisconnectTip(); err != nil {
			t.Fatalf("DisconnectTip(%d): %v", i, err)
		}
	}
	view := f.engine.chainState.view()
	if view.height != forkHeight || view.tipHash != forkHash || view.alreadyGenerated != consensus.Uint128FromU64(forkGenerated) {
		t.Fatalf("chainstate after disconnecting the branch=(%d,%x,generated=%d), want the fork point (%d,%x,%d)",
			view.height, view.tipHash, view.alreadyGenerated, forkHeight, forkHash, forkGenerated)
	}
	if got := f.engine.chainState.UtxoSetHash(); got != forkUtxoHash {
		t.Fatalf("utxo set hash after disconnecting the branch=%x, want the fork-point set %x", got, forkUtxoHash)
	}
}

// TestCanonicalCutoverWinningReorgTerminalNewRequeuesNothing pins the
// TERMINAL_PERSISTENCE(new) row of Section 11.1: the transition publishes its
// complete NEW image and summary and returns the terminal error, but invokes
// ZERO requeue owners — the disconnected transaction does not reappear. The
// guard is also a liveness requirement: admission stays latched, so a requeue
// attempt would block on the retained guard instead of returning.
func TestCanonicalCutoverWinningReorgTerminalNewRequeuesNothing(t *testing.T) {
	f := newPendingOutpointSyncFixture(t)
	forkHash, forkHeight, forkGenerated := f.tipHash, f.tipHeight, f.alreadyGenerated
	spend := f.spend(t, 700, 3)
	spendID := txID(t, spend)
	blockA := f.blockIncluding(t, forkHash, forkHeight+1, forkGenerated, 205, spend)
	if _, err := f.engine.ApplyBlock(blockA, nil); err != nil {
		t.Fatalf("ApplyBlock(A with the spend): %v", err)
	}
	if f.mempool.Contains(spendID) {
		t.Fatal("the spend must be canonical, not resident, before the reorg")
	}
	branch := f.storedSideBranch(t, forkHash, forkHeight+1, forkGenerated, 2)
	candidate := branch[len(branch)-1]

	prevWrite := writeFileAtomicFn
	t.Cleanup(func() { writeFileAtomicFn = prevWrite })
	injected := false
	writeFileAtomicFn = func(path string, data []byte, mode os.FileMode) error {
		if path == f.store.indexPath && !injected {
			injected = true
			// The write really lands, then the lane reports an AMBIGUOUS
			// failure: the strict readback proves the planned-new identity.
			if err := prevWrite(path, data, mode); err != nil {
				return err
			}
			return newAtomicWriteError(atomicWriteAfterNamespaceCommit, path, atomicWriteOverwrite, os.ErrPermission)
		}
		return prevWrite(path, data, mode)
	}

	type result struct {
		summary *ChainStateConnectSummary
		err     error
	}
	done := make(chan result, 1)
	go func() {
		summary, err := f.engine.ApplyBlockWithReorg(candidate.blockBytes, nil)
		done <- result{summary, err}
	}()
	var got result
	select {
	case got = <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("terminal NEW invoked a requeue owner and blocked on the retained admission guard")
	}
	if !injected || got.err == nil || got.summary == nil || len(got.summary.CanonicalAppliedBlocks) != 2 {
		t.Fatalf("injected=%v summary=%+v err=%v, want the published NEW image with a terminal error", injected, got.summary, got.err)
	}
	if !f.engine.persistenceFaulted() {
		t.Fatal("terminal NEW did not latch the engine")
	}
	if f.mempool.Contains(spendID) {
		t.Fatal("terminal NEW invoked a standard requeue owner")
	}
	if f.engine.chainState.view().tipHash != candidate.hash {
		t.Fatalf("terminal NEW published tip=%x, want the branch tip %x", f.engine.chainState.view().tipHash, candidate.hash)
	}
}

// TestPreferredReorgCorruptUndoLeavesStateUnchanged pins RUB-1132 step 7 on the
// preferred-branch path. The corrupt record belongs to the CANONICAL block the
// reorg would have to disconnect, so the failure happens inside
// preparePreferredBranch's preview — before beginCanonicalTransition — and the
// canonical tip, chainstate, index, mempool and apply counters must all be
// exactly as they were. The tail restores the record and drives the same reorg
// to success, so a mistake that made this path reject everything could not pass.
// Rust twin: `preferred_reorg_corrupt_undo_leaves_state_unchanged`.
func TestPreferredReorgCorruptUndoLeavesStateUnchanged(t *testing.T) {
	engine, store, target := newReorgTestEngine(t)
	subsidy1 := consensus.BlockSubsidy(1, 0)
	canonical := buildSingleTxBlock(t, devnetGenesisBlockHash, target, reorgTestTimestamp(1),
		coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 1, subsidy1))
	canonicalSummary, err := engine.ApplyBlock(canonical, nil)
	if err != nil {
		t.Fatalf("ApplyBlock(canonical A1): %v", err)
	}

	sideB1 := buildSingleTxBlock(t, devnetGenesisBlockHash, target, reorgTestTimestamp(2),
		coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 1, subsidy1))
	if _, err := engine.ApplyBlockWithReorg(sideB1, nil); err != nil {
		t.Fatalf("ApplyBlockWithReorg(B1): %v", err)
	}
	_, b1Hash := mustParseReorgBlockForTest(t, sideB1)
	sideB2 := buildSingleTxBlock(t, b1Hash, target, reorgTestTimestamp(3),
		coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 2, consensus.BlockSubsidy(2, subsidy1)))

	mempool, err := NewMempool(engine.chainState, store, devnetGenesisChainID)
	if err != nil {
		t.Fatalf("NewMempool: %v", err)
	}
	engine.SetMempool(mempool)

	beforeState, err := stateToDisk(engine.chainState)
	if err != nil {
		t.Fatalf("stateToDisk(before): %v", err)
	}
	beforeIndex, err := store.CanonicalIndexSnapshot()
	if err != nil {
		t.Fatalf("CanonicalIndexSnapshot(before): %v", err)
	}
	beforeCounts := engine.BlockApplyCounts()
	beforeMempoolLen := mempool.Len()
	beforeReorgCount := engine.ReorgCount()
	beforeSnapshot, err := os.ReadFile(engine.cfg.ChainStatePath)
	if err != nil {
		t.Fatalf("read chainstate snapshot: %v", err)
	}

	corrupt, original := corruptStoredUndoChecksum(t, store, canonicalSummary.BlockHash)

	_, err = engine.ApplyBlockWithReorg(sideB2, nil)
	if err == nil {
		t.Fatal("preferred-branch reorg consumed a checksum-broken undo record")
	}
	if !errors.Is(err, ErrUndoIntegrity) {
		t.Fatalf("err = %v, want errors.Is ErrUndoIntegrity", err)
	}
	if err.Error() != "UNDO_INTEGRITY: checksum mismatch" {
		t.Fatalf("message = %q, want exactly %q", err.Error(), "UNDO_INTEGRITY: checksum mismatch")
	}
	// Our own corrupt file must not be charged to the peer that relayed B2:
	// node/p2p bumpBan(100) fires on any *consensus.TxError in the chain.
	var txErr *consensus.TxError
	if errors.As(err, &txErr) {
		t.Fatalf("local corruption surfaced as consensus.TxError: %v", err)
	}

	if got, err := stateToDisk(engine.chainState); err != nil || !reflect.DeepEqual(got, beforeState) {
		t.Fatalf("chainstate mutated by refused reorg: state=%+v err=%v", got, err)
	}
	if got, err := store.CanonicalIndexSnapshot(); err != nil || !reflect.DeepEqual(got, beforeIndex) {
		t.Fatalf("canonical index mutated by refused reorg: index=%v err=%v", got, err)
	}
	if engine.chainState.TipHash != canonicalSummary.BlockHash || engine.chainState.Height != 1 {
		t.Fatalf("canonical tip moved to (%d,%x), want (1,%x)",
			engine.chainState.Height, engine.chainState.TipHash, canonicalSummary.BlockHash)
	}
	if got := engine.BlockApplyCounts(); got != beforeCounts {
		t.Fatalf("BlockApplyCounts=%+v, want %+v", got, beforeCounts)
	}
	if got := mempool.Len(); got != beforeMempoolLen {
		t.Fatalf("mempool len=%d, want %d", got, beforeMempoolLen)
	}
	if got := engine.ReorgCount(); got != beforeReorgCount {
		t.Fatalf("ReorgCount=%d, want %d", got, beforeReorgCount)
	}
	if got, err := os.ReadFile(engine.cfg.ChainStatePath); err != nil || !bytes.Equal(got, beforeSnapshot) {
		t.Fatalf("persisted chainstate rewritten by a refused reorg (err=%v)", err)
	}
	undoPath := filepath.Join(store.undoDir, hex.EncodeToString(canonicalSummary.BlockHash[:])+".json")
	if got, err := os.ReadFile(undoPath); err != nil || !bytes.Equal(got, corrupt) {
		t.Fatalf("refused reorg rewrote the undo record (err=%v)", err)
	}

	// Positive control: the very same reorg must succeed once the record is
	// valid again, so the rejection above is attributable to the corruption.
	restoreStoredUndo(t, store, canonicalSummary.BlockHash, original)
	summaryB2, err := engine.ApplyBlockWithReorg(sideB2, nil)
	if err != nil {
		t.Fatalf("ApplyBlockWithReorg(B2) after restore: %v", err)
	}
	if summaryB2.BlockHeight != 2 || engine.chainState.Height != 2 {
		t.Fatalf("restored reorg height=%d state height=%d, want 2", summaryB2.BlockHeight, engine.chainState.Height)
	}
	if got := engine.ReorgCount(); got != beforeReorgCount+1 {
		t.Fatalf("ReorgCount after restored reorg=%d, want %d", got, beforeReorgCount+1)
	}
}

func TestPreferredReorgPreservesWideSupplyAndFailsAtomicallyOnCorruptUndo(t *testing.T) {
	engine, store, target := newReorgTestEngine(t)
	wide := consensus.Uint128{Hi: 1, Lo: 17}
	engine.chainState.AlreadyGenerated = wide
	if err := engine.chainState.Save(engine.cfg.ChainStatePath); err != nil {
		t.Fatalf("Save(wide genesis): %v", err)
	}
	subsidy := consensus.BlockSubsidyBig(1, wide.Big())
	base := buildSingleTxBlock(t, devnetGenesisBlockHash, target, reorgTestTimestamp(1),
		coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 1, subsidy))
	first := blockWithHeaderNonce(t, base, 1)
	second := blockWithHeaderNonce(t, base, 2)
	_, firstHash := mustParseReorgBlockForTest(t, first)
	_, secondHash := mustParseReorgBlockForTest(t, second)
	canonical, canonicalHash, side, sideHash := first, firstHash, second, secondHash
	if bytes.Compare(firstHash[:], secondHash[:]) > 0 {
		canonical, canonicalHash, side, sideHash = second, secondHash, first, firstHash
	}
	canonicalSummary, err := engine.ApplyBlock(canonical, nil)
	if err != nil {
		t.Fatalf("ApplyBlock(canonical): %v", err)
	}
	if canonicalSummary.BlockHash != canonicalHash {
		t.Fatal("canonical hash mismatch")
	}
	if _, err := engine.ApplyBlockWithReorg(side, nil); err != nil {
		t.Fatalf("ApplyBlockWithReorg(side height 1): %v", err)
	}
	side2 := buildSingleTxBlock(t, sideHash, target, reorgTestTimestamp(2),
		coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 2, subsidy))

	beforeState, err := stateToDisk(engine.chainState)
	if err != nil {
		t.Fatalf("stateToDisk(before): %v", err)
	}
	beforeIndex, err := store.CanonicalIndexSnapshot()
	if err != nil {
		t.Fatalf("CanonicalIndexSnapshot(before): %v", err)
	}
	beforeSnapshot, err := os.ReadFile(engine.cfg.ChainStatePath)
	if err != nil {
		t.Fatalf("ReadFile(chainstate before): %v", err)
	}
	corrupt, original := corruptStoredUndoChecksum(t, store, canonicalHash)
	if _, err := engine.ApplyBlockWithReorg(side2, nil); !errors.Is(err, ErrUndoIntegrity) {
		t.Fatalf("corrupt-undo reorg err=%v, want UNDO_INTEGRITY", err)
	}
	if got, err := stateToDisk(engine.chainState); err != nil || !reflect.DeepEqual(got, beforeState) {
		t.Fatalf("chainstate changed on corrupt undo: state=%+v err=%v", got, err)
	}
	if got, err := store.CanonicalIndexSnapshot(); err != nil || !reflect.DeepEqual(got, beforeIndex) {
		t.Fatalf("canonical index changed on corrupt undo: index=%v err=%v", got, err)
	}
	afterSnapshot, err := os.ReadFile(engine.cfg.ChainStatePath)
	if err != nil || !bytes.Equal(afterSnapshot, beforeSnapshot) {
		t.Fatalf("chainstate bytes changed on corrupt undo: err=%v", err)
	}
	undoPath := filepath.Join(store.undoDir, hex.EncodeToString(canonicalHash[:])+".json")
	if afterUndo, err := os.ReadFile(undoPath); err != nil || !bytes.Equal(afterUndo, corrupt) {
		t.Fatalf("corrupt undo was rewritten: err=%v", err)
	}
	if err := os.WriteFile(undoPath, original, 0o600); err != nil {
		t.Fatalf("restore undo: %v", err)
	}

	reorgSummary, err := engine.ApplyBlockWithReorg(side2, nil)
	if err != nil {
		t.Fatalf("ApplyBlockWithReorg(valid): %v", err)
	}
	wantFinal, ok := wide.CheckedAdd(consensus.Uint128FromU64(2 * subsidy))
	if !ok || reorgSummary.AlreadyGeneratedN1 != wantFinal || engine.chainState.AlreadyGenerated != wantFinal {
		t.Fatalf("reorg supply summary=%s state=%s, want %s", reorgSummary.AlreadyGeneratedN1.String(), engine.chainState.AlreadyGenerated.String(), wantFinal.String())
	}
	firstDisconnect, err := engine.DisconnectTip()
	if err != nil {
		t.Fatalf("DisconnectTip(side2): %v", err)
	}
	wantSide1, ok := wide.CheckedAdd(consensus.Uint128FromU64(subsidy))
	if !ok {
		t.Fatal("test setup overflowed u128")
	}
	if firstDisconnect.AlreadyGenerated != wantSide1 {
		t.Fatalf("first disconnect supply=%s, want %s", firstDisconnect.AlreadyGenerated.String(), wantSide1.String())
	}
	secondDisconnect, err := engine.DisconnectTip()
	if err != nil {
		t.Fatalf("DisconnectTip(side1): %v", err)
	}
	if secondDisconnect.AlreadyGenerated != wide || engine.chainState.AlreadyGenerated != wide {
		t.Fatalf("second disconnect supply summary=%s state=%s, want %s", secondDisconnect.AlreadyGenerated.String(), engine.chainState.AlreadyGenerated.String(), wide.String())
	}
}

// TestWinningReorgHoldsTwoImagesUnderPVShadow pins resource_bounds on the path
// PV could break it: with the shadow active the winning-reorg preparation still
// retains only the common checkpoint and the rolling image that becomes C1. The
// shadow pre-state was the one third-image producer here (its run cloned a
// fourth), so "no branch row validated" is exactly "no third image".
func TestWinningReorgHoldsTwoImagesUnderPVShadow(t *testing.T) {
	engine, _, target := newReorgTestEngine(t)
	engine.pvMode = pvModeShadow
	subsidy1 := consensus.BlockSubsidy(1, 0)
	blockA1 := buildSingleTxBlock(t, devnetGenesisBlockHash, target, reorgTestTimestamp(1), coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 1, subsidy1))
	if _, err := engine.ApplyBlockWithReorg(blockA1, nil); err != nil {
		t.Fatalf("ApplyBlockWithReorg(A1): %v", err)
	}
	if !engine.pvShadowActive() {
		t.Fatal("fixture is not shadow-active: the row would prove nothing")
	}
	sideB1 := buildSingleTxBlock(t, devnetGenesisBlockHash, target, reorgTestTimestamp(2), coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 1, subsidy1))
	sideB1Hash, err := consensus.BlockHash(blockHeaderBytes(t, sideB1))
	if err != nil {
		t.Fatalf("BlockHash(B1): %v", err)
	}
	a1Hash := engine.chainState.view().tipHash
	if _, err := engine.ApplyBlockWithReorg(sideB1, nil); err != nil {
		t.Fatalf("ApplyBlockWithReorg(B1): %v", err)
	}
	// B1 must be STORED, not connected: if a tie-break made it the tip, B2 would
	// take the DIRECT path and the row below would prove nothing.
	if tip := engine.chainState.view().tipHash; tip != a1Hash {
		t.Fatalf("side B1 became the tip (%x): this fixture no longer exercises a reorg", tip)
	}
	before := engine.pvTelemetry.Snapshot()
	sideB2 := buildSingleTxBlock(t, sideB1Hash, target, reorgTestTimestamp(3), coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 2, consensus.BlockSubsidy(2, subsidy1)))
	if _, err := engine.ApplyBlockWithReorg(sideB2, nil); err != nil {
		t.Fatalf("ApplyBlockWithReorg(B2, winning): %v", err)
	}
	after := engine.pvTelemetry.Snapshot()
	if depth := engine.LastReorgDepth(); depth != 1 {
		t.Fatalf("LastReorgDepth()=%d, want the depth-1 reorg this row measures", depth)
	}
	if after.BlocksValidated != before.BlocksValidated {
		t.Fatalf("winning reorg ran %d PV shadow validations: each one clones a third full image", after.BlocksValidated-before.BlocksValidated)
	}
	if after.BlocksSkipped == before.BlocksSkipped {
		t.Fatal("winning reorg recorded no PV-skipped row: the accounting no longer covers the branch")
	}
}
