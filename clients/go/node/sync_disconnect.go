package node

import (
	"errors"
)

func (s *SyncEngine) DisconnectTip() (*ChainStateDisconnectSummary, error) {
	if s == nil || s.chainState == nil {
		return nil, errors.New("sync engine is not initialized")
	}
	if s.blockStore == nil {
		return nil, errors.New("sync engine has no blockstore")
	}

	tipHeight, tipHash, err := s.currentCanonicalTip()
	if err != nil {
		return nil, err
	}
	view := s.chainState.view()
	if !view.hasTip || view.height != tipHeight || view.tipHash != tipHash {
		return nil, errors.New("chainstate tip does not match blockstore tip")
	}

	pb, blockBytes, undo, err := s.fetchDisconnectBlockAndUndo(tipHash)
	if err != nil {
		return nil, err
	}

	rollbackState, err := s.captureRollbackState()
	if err != nil {
		return nil, err
	}
	newTipTimestamp, err := s.getParentTimestamp(tipHeight, pb.Header.PrevBlockHash)
	if err != nil {
		return nil, err
	}

	summary, err := s.chainState.DisconnectBlock(blockBytes, undo)
	if err != nil {
		return nil, err
	}
	if err := s.finalizeDisconnectState(rollbackState, newTipTimestamp); err != nil {
		return nil, err
	}
	return summary, nil
}

func (s *SyncEngine) disconnectCanonicalToAncestor(commonAncestorHeight uint64) ([][]byte, uint64, error) {
	currentTipHeight, _, err := s.currentCanonicalTip()
	if err != nil {
		return nil, 0, err
	}
	reorgDepth := currentTipHeight - commonAncestorHeight
	disconnectedBlocks := make([][]byte, 0, reorgDepth)
	for currentTipHeight > commonAncestorHeight {
		_, tipHash, err := s.currentCanonicalTip()
		if err != nil {
			return nil, 0, err
		}
		disconnectedBlockBytes, err := s.blockStore.GetBlockByHash(tipHash)
		if err != nil {
			return nil, 0, err
		}
		disconnectedBlocks = append(disconnectedBlocks, append([]byte(nil), disconnectedBlockBytes...))
		if _, err := s.DisconnectTip(); err != nil {
			return nil, 0, err
		}
		currentTipHeight--
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
