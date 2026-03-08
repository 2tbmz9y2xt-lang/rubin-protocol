package node

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
		if _, err := previewState.ConnectBlock(item.blockBytes, s.cfg.ExpectedTarget, prevTimestamps, s.cfg.ChainID); err != nil {
			return nil, 0, err
		}
	}
	return disconnectedBlocks, reorgDepth, nil
}

func (s *SyncEngine) previewDisconnectCanonicalToAncestor(previewState *ChainState, commonAncestorHeight uint64) ([][]byte, uint64, error) {
	if previewState == nil {
		return nil, 0, nil
	}
	currentTipHeight := previewState.Height
	reorgDepth := currentTipHeight - commonAncestorHeight
	disconnectedBlocks := make([][]byte, 0, reorgDepth)
	for currentTipHeight > commonAncestorHeight {
		tipHash := previewState.TipHash
		blockBytes, err := s.blockStore.GetBlockByHash(tipHash)
		if err != nil {
			return nil, 0, err
		}
		undo, err := s.blockStore.GetUndo(tipHash)
		if err != nil {
			return nil, 0, err
		}
		if _, err := previewState.DisconnectBlock(blockBytes, undo); err != nil {
			return nil, 0, err
		}
		disconnectedBlocks = append(disconnectedBlocks, append([]byte(nil), blockBytes...))
		currentTipHeight--
	}
	return disconnectedBlocks, reorgDepth, nil
}
