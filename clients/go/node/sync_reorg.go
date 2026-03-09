package node

import (
	"errors"
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
	pb, err := consensus.ParseBlockBytes(blockBytes)
	if err != nil {
		return nil, err
	}
	blockHash, err := consensus.BlockHash(pb.HeaderBytes)
	if err != nil {
		return nil, err
	}

	if summary, handled, err := s.applyDirectBlockIfPossible(pb, blockBytes, prevTimestamps); handled {
		return summary, err
	}
	if s.blockStore == nil {
		return nil, &consensus.TxError{Code: consensus.BLOCK_ERR_LINKAGE_INVALID, Msg: "missing blockstore for side-chain block"}
	}

	branch, commonAncestorHash, commonAncestorHeight, err := s.collectBranchToCanonical(blockHash, blockBytes, pb)
	if err != nil {
		return nil, err
	}
	switchToBranch, candidateHeight, err := s.shouldSwitchToBranch(branch, commonAncestorHash, commonAncestorHeight)
	if err != nil {
		return nil, err
	}
	if !switchToBranch {
		if _, err := consensus.ValidateBlockBasicWithContextAtHeight(blockBytes, &pb.Header.PrevBlockHash, s.cfg.ExpectedTarget, candidateHeight, prevTimestamps); err != nil {
			return nil, err
		}
		if err := s.blockStore.StoreBlock(blockHash, pb.HeaderBytes, blockBytes); err != nil {
			return nil, err
		}
		return s.syntheticSideChainSummary(candidateHeight, blockHash), nil
	}
	return s.applyHeavierBranch(branch, commonAncestorHeight, prevTimestamps)
}

func (s *SyncEngine) applyDirectBlockIfPossible(
	pb *consensus.ParsedBlock,
	blockBytes []byte,
	prevTimestamps []uint64,
) (*ChainStateConnectSummary, bool, error) {
	var zero [32]byte
	switch {
	case !s.chainState.HasTip:
		if pb.Header.PrevBlockHash != zero {
			return nil, true, ErrParentNotFound
		}
		summary, err := s.applyCanonicalParsedBlock(pb, blockBytes, prevTimestamps)
		return summary, true, err
	case pb.Header.PrevBlockHash == s.chainState.TipHash:
		summary, err := s.applyCanonicalParsedBlock(pb, blockBytes, prevTimestamps)
		return summary, true, err
	default:
		return nil, false, nil
	}
}

func (s *SyncEngine) shouldSwitchToBranch(
	branch []reorgBranchBlock,
	commonAncestorHash [32]byte,
	commonAncestorHeight uint64,
) (bool, uint64, error) {
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
	return candidateWork.Cmp(currentWork) > 0, candidateHeight, nil
}

func (s *SyncEngine) applyHeavierBranch(
	branch []reorgBranchBlock,
	commonAncestorHeight uint64,
	prevTimestamps []uint64,
) (*ChainStateConnectSummary, error) {
	rollbackState, err := s.captureRollbackState()
	if err != nil {
		return nil, err
	}
	disconnectedBlocks, reorgDepth, err := s.prepareHeavierBranch(branch, commonAncestorHeight, prevTimestamps, rollbackState)
	if err != nil {
		return nil, err
	}
	if _, _, err := s.disconnectCanonicalToAncestor(commonAncestorHeight); err != nil {
		return nil, s.rollbackApplyBlock(err, rollbackState)
	}

	var summary *ChainStateConnectSummary
	for _, item := range branch {
		summary, err = s.applyCanonicalParsedBlock(item.parsed, item.blockBytes, prevTimestamps)
		if err != nil {
			return nil, s.rollbackApplyBlock(err, rollbackState)
		}
	}
	s.requeueDisconnectedTransactions(disconnectedBlocks)
	s.noteReorg(reorgDepth)
	return summary, nil
}

func (s *SyncEngine) prepareHeavierBranch(
	branch []reorgBranchBlock,
	commonAncestorHeight uint64,
	prevTimestamps []uint64,
	rollbackState syncRollbackState,
) ([][]byte, uint64, error) {
	previewState, err := chainStateFromDisk(rollbackState.chainState)
	if err != nil {
		return nil, 0, err
	}
	disconnectedBlocks, reorgDepth, err := s.previewDisconnectCanonicalToAncestor(previewState, commonAncestorHeight)
	if err != nil {
		return nil, 0, err
	}
	for _, item := range branch {
		if _, err := previewState.ConnectBlockWithCoreExtProfiles(
			item.blockBytes,
			s.cfg.ExpectedTarget,
			prevTimestamps,
			s.cfg.ChainID,
			s.cfg.CoreExtProfiles,
		); err != nil {
			return nil, 0, err
		}
	}
	return disconnectedBlocks, reorgDepth, nil
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
		utxoCount = uint64(len(s.chainState.Utxos))
		alreadyGenerated = s.chainState.AlreadyGenerated
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
	for blockIndex := len(disconnectedBlocks) - 1; blockIndex >= 0; blockIndex-- {
		txs, err := nonCoinbaseBlockTransactions(disconnectedBlocks[blockIndex])
		if err != nil {
			continue
		}
		for _, txBytes := range txs {
			_ = s.mempool.AddTx(txBytes)
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
