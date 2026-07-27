package node

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
	"os"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

type reorgBranchBlock struct {
	hash       [32]byte
	blockBytes []byte
	parsed     *consensus.ParsedBlock
	header     consensus.BlockHeader
}

func (s *SyncEngine) ApplyBlockWithReorg(blockBytes []byte, prevTimestamps []uint64) (*ChainStateConnectSummary, error) {
	if s == nil || s.chainState == nil {
		return nil, errors.New("sync engine is not initialized")
	}
	pb, blockHash, err := parseReorgBlock(blockBytes)
	if err != nil {
		return nil, err
	}

	if summary, handled, err := s.applyDirectBlockIfPossible(pb, blockBytes, prevTimestamps); handled {
		return summary, err
	}
	branch, commonAncestorHeight, switchToBranch, candidateHeight, err := s.evaluateSideBranch(blockHash, blockBytes, pb)
	if err != nil {
		return nil, err
	}
	if !switchToBranch {
		return s.storeSideBlockAndSummary(branch, commonAncestorHeight, candidateHeight)
	}
	return s.applyPreferredBranch(branch, commonAncestorHeight)
}

func parseReorgBlock(blockBytes []byte) (*consensus.ParsedBlock, [32]byte, error) {
	pb, err := consensus.ParseBlockBytes(blockBytes)
	if err != nil {
		return nil, [32]byte{}, err
	}
	blockHash, err := consensus.BlockHash(pb.HeaderBytes)
	if err != nil {
		return nil, [32]byte{}, err
	}
	return pb, blockHash, nil
}

func (s *SyncEngine) evaluateSideBranch(
	blockHash [32]byte,
	blockBytes []byte,
	pb *consensus.ParsedBlock,
) ([]reorgBranchBlock, uint64, bool, uint64, error) {
	if s.blockStore == nil {
		return nil, 0, false, 0, &consensus.TxError{Code: consensus.BLOCK_ERR_LINKAGE_INVALID, Msg: "missing blockstore for side-chain block"}
	}
	branch, commonAncestorHash, commonAncestorHeight, err := s.collectBranchToCanonical(blockHash, blockBytes, pb)
	if err != nil {
		return nil, 0, false, 0, err
	}
	switchToBranch, candidateHeight, err := s.shouldSwitchToBranch(branch, commonAncestorHash, commonAncestorHeight)
	if err != nil {
		return nil, 0, false, 0, err
	}
	return branch, commonAncestorHeight, switchToBranch, candidateHeight, nil
}

func (s *SyncEngine) storeSideBlockAndSummary(branch []reorgBranchBlock, commonAncestorHeight uint64, candidateHeight uint64) (*ChainStateConnectSummary, error) {
	if len(branch) == 0 {
		return nil, errors.New("empty side branch")
	}
	candidate := branch[len(branch)-1]
	// Target context BEFORE the MTP window, so a target-context failure
	// short-circuits without reading MTP state. Selected parent = the
	// candidate's PrevBlockHash, already resolved against stored ancestry by
	// collectBranchToCanonical; height = the caller-owned candidateHeight.
	targetCtx, err := s.targetContextForCandidate(candidate.header.PrevBlockHash, candidateHeight)
	if err != nil {
		return nil, err
	}
	prevTimestamps, err := sideBranchPrevTimestamps(s.blockStore, branch, commonAncestorHeight)
	if err != nil {
		return nil, err
	}
	// Full validation still precedes StoreBlock, so an invalid side-branch
	// target contributes nothing to stored state or to fork choice.
	if _, err := consensus.ValidateBlockBasicWithContextAtHeightAndRotation(candidate.blockBytes, &candidate.header.PrevBlockHash, targetCtx.expected, candidateHeight, prevTimestamps, s.cfg.ChainID, s.cfg.RotationProvider); err != nil {
		return nil, err
	}
	if err := s.blockStore.StoreBlock(candidate.hash, candidate.parsed.HeaderBytes, candidate.blockBytes); err != nil {
		return nil, err
	}
	return s.syntheticSideChainSummary(candidateHeight, candidate.hash), nil
}

func sideBranchPrevTimestamps(store *BlockStore, branch []reorgBranchBlock, commonAncestorHeight uint64) ([]uint64, error) {
	if len(branch) == 0 {
		return nil, errors.New("empty side branch")
	}
	if store == nil {
		return nil, errors.New("missing blockstore for side branch timestamp context")
	}
	prevTimestamps, err := prevTimestampsFromStore(store, commonAncestorHeight+1)
	if err != nil {
		return nil, err
	}
	for _, item := range branch[:len(branch)-1] {
		prevTimestamps = advancePrevTimestamps(prevTimestamps, item.header.Timestamp)
	}
	return prevTimestamps, nil
}

func (s *SyncEngine) applyDirectBlockIfPossible(
	pb *consensus.ParsedBlock,
	blockBytes []byte,
	prevTimestamps []uint64,
) (*ChainStateConnectSummary, bool, error) {
	var zero [32]byte
	view := s.chainState.view()
	switch {
	case !view.hasTip:
		if pb.Header.PrevBlockHash != zero {
			return nil, true, ErrParentNotFound
		}
		summary, err := s.applyCanonicalParsedBlock(pb, blockBytes, prevTimestamps, nil)
		return summary, true, err
	case pb.Header.PrevBlockHash == view.tipHash:
		summary, err := s.applyDirectTipBlock(pb, blockBytes, view)
		return summary, true, err
	default:
		return nil, false, nil
	}
}

// applyDirectTipBlock applies a candidate whose parent is the canonical tip.
// Acquisition order is target-then-MTP: the target context must precede the
// RUB-647 canonical MTP window so a target-context failure short-circuits
// before any MTP state is read. The height-0 genesis branch never reaches here.
func (s *SyncEngine) applyDirectTipBlock(pb *consensus.ParsedBlock, blockBytes []byte, view chainStateView) (*ChainStateConnectSummary, error) {
	nextHeight, _, err := nextBlockContextFromFields(view.hasTip, view.height, view.tipHash)
	if err != nil {
		return nil, err
	}
	if s.blockStore == nil {
		return nil, errors.New("missing blockstore for direct-tip timestamp context")
	}
	targetCtx, err := s.targetContextForCandidate(view.tipHash, nextHeight)
	if err != nil {
		return nil, err
	}
	canonicalPrevTimestamps, err := prevTimestampsFromStore(s.blockStore, nextHeight)
	if err != nil {
		return nil, err
	}
	return s.applyCanonicalParsedBlock(pb, blockBytes, canonicalPrevTimestamps, targetCtx)
}

func (s *SyncEngine) shouldSwitchToBranch(
	branch []reorgBranchBlock,
	commonAncestorHash [32]byte,
	commonAncestorHeight uint64,
) (bool, uint64, error) {
	if len(branch) == 0 {
		return false, commonAncestorHeight, errors.New("empty side branch")
	}
	_, currentTipHash, err := s.currentCanonicalTip()
	if err != nil {
		return false, 0, err
	}

	currentWork, err := s.blockStore.ChainWork(currentTipHash)
	if err != nil {
		return false, 0, err
	}
	ancestorWork, err := s.blockStore.ChainWork(commonAncestorHash)
	if err != nil {
		return false, 0, err
	}
	branchTargets := make([][32]byte, 0, len(branch))
	for _, item := range branch {
		branchTargets = append(branchTargets, item.header.Target)
	}
	branchWork, err := consensus.ChainWorkFromTargets(branchTargets)
	if err != nil {
		return false, 0, err
	}
	candidateWork := new(big.Int).Add(new(big.Int).Set(ancestorWork), branchWork)
	candidateHeight := commonAncestorHeight + uint64(len(branch))
	switch candidateWork.Cmp(currentWork) {
	case 1:
		return true, candidateHeight, nil
	case -1:
		return false, candidateHeight, nil
	default:
		candidateTipHash := branch[len(branch)-1].hash
		return bytes.Compare(candidateTipHash[:], currentTipHash[:]) < 0, candidateHeight, nil
	}
}

// applyPreferredBranch applies the candidate branch selected by fork choice:
// greater ChainWork, or equal ChainWork with a lexicographically lower tip hash.
func (s *SyncEngine) applyPreferredBranch(
	branch []reorgBranchBlock,
	commonAncestorHeight uint64,
) (*ChainStateConnectSummary, error) {
	rollbackState, err := s.captureRollbackState()
	if err != nil {
		return nil, err
	}
	disconnectedBlocks, reorgDepth, err := s.preparePreferredBranch(branch, commonAncestorHeight, rollbackState)
	if err != nil {
		return nil, err
	}
	if _, _, err := s.disconnectCanonicalToAncestor(commonAncestorHeight); err != nil {
		return nil, s.rollbackApplyBlock(err, rollbackState)
	}

	var summary *ChainStateConnectSummary
	var pendingAccepted uint64
	var canonicalBlocks []CanonicalAppliedBlock
	for i, item := range branch {
		var outcome blockApplyMetricOutcome
		summary, outcome, err = s.applyBranchBlock(item, commonAncestorHeight+1+uint64(i))
		if err != nil {
			return nil, s.rollbackBranchBlockApply(err, rollbackState, outcome)
		}
		if outcome == blockApplyMetricAccepted {
			pendingAccepted++
		}
		if summary != nil && len(summary.CanonicalAppliedBlocks) > 0 {
			canonicalBlocks = append(canonicalBlocks, summary.CanonicalAppliedBlocks[0])
		}
	}
	s.requeueDisconnectedTransactions(disconnectedBlocks)
	s.noteBlockApplyAcceptedN(pendingAccepted)
	s.noteReorg(reorgDepth)
	if summary != nil {
		summary.CanonicalAppliedBlocks = canonicalBlocks
	}
	return summary, nil
}

// applyBranchBlock commits one row of the preferred branch at its caller-owned
// height. Both context windows are re-derived per iteration: the canonical
// index moved when the previous row committed, and a branch can cross a
// retarget boundary (the target half of the B.9 / issue #1166 argument). Target
// context first, so a target-context failure short-circuits before the MTP
// window is read.
func (s *SyncEngine) applyBranchBlock(item reorgBranchBlock, nextHeight uint64) (*ChainStateConnectSummary, blockApplyMetricOutcome, error) {
	targetCtx, err := s.targetContextForCandidate(item.header.PrevBlockHash, nextHeight)
	if err != nil {
		return nil, blockApplyMetricNone, err
	}
	freshTs, err := prevTimestampsFromStore(s.blockStore, nextHeight)
	if err != nil {
		return nil, blockApplyMetricNone, err
	}
	return s.applyCanonicalParsedBlockTracked(item.parsed, item.blockBytes, freshTs, targetCtx)
}

func (s *SyncEngine) rollbackBranchBlockApply(
	err error,
	rollbackState syncRollbackState,
	outcome blockApplyMetricOutcome,
) error {
	rollbackErr := s.rollbackApplyBlock(err, rollbackState)
	if outcome == blockApplyMetricRejected {
		s.noteBlockApplyRejected()
	}
	return rollbackErr
}

func (s *SyncEngine) preparePreferredBranch(
	branch []reorgBranchBlock,
	commonAncestorHeight uint64,
	rollbackState syncRollbackState,
) ([][]byte, uint64, error) {
	previewState := cloneChainState(rollbackState.chainState)
	if previewState == nil {
		return nil, 0, errors.New("nil preview chainstate")
	}
	var err error
	disconnectedBlocks, reorgDepth, err := s.previewDisconnectCanonicalToAncestor(previewState, commonAncestorHeight)
	if err != nil {
		return nil, 0, err
	}
	// Build a sliding MTP window: start from pre-fork timestamps, advance
	// after each block.  The blockstore index is NOT updated during preview,
	// so per-block advancement uses a sliding window instead of
	// re-deriving from the store each iteration (B.9 fix).
	slidingTs, err := prevTimestampsFromStore(s.blockStore, commonAncestorHeight+1)
	if err != nil {
		return nil, 0, err
	}
	for i, item := range branch {
		// Per-row derivation: a branch can cross a retarget boundary. Unlike
		// the MTP window this needs no sliding workaround — it reads headers
		// by hash and never consults the canonical index, and every ancestor
		// it needs is already stored (collectBranchToCanonical fetched
		// branch[0..len-2] from the store; the common ancestor is canonical).
		targetCtx, targetErr := s.targetContextForCandidate(item.header.PrevBlockHash, commonAncestorHeight+1+uint64(i))
		if targetErr != nil {
			return nil, 0, targetErr
		}
		if _, err := previewState.ConnectBlockWithSuiteContext(
			item.blockBytes,
			targetCtx.expected,
			slidingTs,
			s.cfg.ChainID,
			s.cfg.RotationProvider,
			s.cfg.SuiteRegistry,
		); err != nil {
			return nil, 0, err
		}
		slidingTs = advancePrevTimestamps(slidingTs, item.header.Timestamp)
	}
	return disconnectedBlocks, reorgDepth, nil
}

// advancePrevTimestamps prepends newTs to prev and keeps at most 11 entries,
// sliding the MTP window forward by one block.
func advancePrevTimestamps(prev []uint64, newTs uint64) []uint64 {
	const maxWindow = 11
	out := make([]uint64, 0, maxWindow)
	out = append(out, newTs)
	for _, ts := range prev {
		if len(out) >= maxWindow {
			break
		}
		out = append(out, ts)
	}
	return out
}

func (s *SyncEngine) collectBranchToCanonical(
	blockHash [32]byte,
	blockBytes []byte,
	pb *consensus.ParsedBlock,
) ([]reorgBranchBlock, [32]byte, uint64, error) {
	branch := []reorgBranchBlock{{
		hash:       blockHash,
		blockBytes: append([]byte(nil), blockBytes...),
		parsed:     pb,
		header:     pb.Header,
	}}
	parentHash := pb.Header.PrevBlockHash
	for {
		height, found, err := s.blockStore.FindCanonicalHeight(parentHash)
		if err != nil {
			return nil, [32]byte{}, 0, err
		}
		if found {
			reverseBranchBlocks(branch)
			return branch, parentHash, height, nil
		}
		parentBlockBytes, err := s.blockStore.GetBlockByHash(parentHash)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil, [32]byte{}, 0, ErrParentNotFound
			}
			return nil, [32]byte{}, 0, err
		}
		parentParsed, err := consensus.ParseBlockBytes(parentBlockBytes)
		if err != nil {
			return nil, [32]byte{}, 0, err
		}
		branch = append(branch, reorgBranchBlock{
			hash:       parentHash,
			blockBytes: parentBlockBytes,
			parsed:     parentParsed,
			header:     parentParsed.Header,
		})
		parentHash = parentParsed.Header.PrevBlockHash
	}
}

func (s *SyncEngine) syntheticSideChainSummary(height uint64, blockHash [32]byte) *ChainStateConnectSummary {
	utxoCount := uint64(0)
	alreadyGenerated := uint64(0)
	if s != nil && s.chainState != nil {
		view := s.chainState.view()
		utxoCount = uint64(view.utxoCount) //nolint:gosec // G115: view.utxoCount is non-negative by chainstate invariant
		alreadyGenerated = view.alreadyGenerated
	}
	return &ChainStateConnectSummary{
		BlockHeight:        height,
		BlockHash:          blockHash,
		AlreadyGenerated:   alreadyGenerated,
		AlreadyGeneratedN1: alreadyGenerated,
		UtxoCount:          utxoCount,
	}
}

func (s *SyncEngine) requeueDisconnectedTransactions(disconnectedBlocks [][]byte) {
	if s == nil || s.mempool == nil || len(disconnectedBlocks) == 0 {
		return
	}
	// Disconnect helpers append blocks tip-down, matching h_max -> h_min requeue order.
	for blockIndex := 0; blockIndex < len(disconnectedBlocks); blockIndex++ {
		txs, err := nonCoinbaseBlockTransactions(disconnectedBlocks[blockIndex])
		if err != nil {
			continue
		}
		for _, txBytes := range txs {
			if err := s.mempool.AddReorgTx(txBytes); err != nil {
				_, _ = fmt.Fprintf(s.stderr, "mempool: requeue-tx: %v\n", err)
			}
		}
	}
}

func nonCoinbaseBlockTransactions(blockBytes []byte) ([][]byte, error) {
	pb, err := consensus.ParseBlockBytes(blockBytes)
	if err != nil {
		return nil, err
	}
	if len(pb.Txs) <= 1 {
		return nil, nil
	}
	txs := make([][]byte, 0, len(pb.Txs)-1)
	for txIndex := 1; txIndex < len(pb.Txs); txIndex++ {
		txBytes, err := consensus.MarshalTx(pb.Txs[txIndex])
		if err != nil {
			return nil, err
		}
		txs = append(txs, txBytes)
	}
	return txs, nil
}

func reverseBranchBlocks(branch []reorgBranchBlock) {
	for left, right := 0, len(branch)-1; left < right; left, right = left+1, right-1 {
		branch[left], branch[right] = branch[right], branch[left]
	}
}
