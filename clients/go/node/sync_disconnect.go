package node

import (
	"errors"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
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

// fetchDisconnectBlockAndUndo fetches block bytes, undo data, and parses the block.
func (s *SyncEngine) fetchDisconnectBlockAndUndo(tipHash [32]byte) (*consensus.ParsedBlock, []byte, *BlockUndo, error) {
	blockBytes, err := s.blockStore.GetBlockByHash(tipHash)
	if err != nil {
		return nil, nil, nil, err
	}
	undo, err := s.blockStore.GetUndo(tipHash)
	if err != nil {
		return nil, nil, nil, err
	}
	pb, err := consensus.ParseBlockBytes(blockBytes)
	if err != nil {
		return nil, nil, nil, err
	}
	return pb, blockBytes, undo, nil
}

// getParentTimestamp returns the timestamp of the parent block, or 0 at height 0.
func (s *SyncEngine) getParentTimestamp(tipHeight uint64, prevBlockHash [32]byte) (uint64, error) {
	if tipHeight == 0 {
		return 0, nil
	}
	parentHeaderBytes, err := s.blockStore.GetHeaderByHash(prevBlockHash)
	if err != nil {
		return 0, err
	}
	parentHeader, err := consensus.ParseBlockHeaderBytes(parentHeaderBytes)
	if err != nil {
		return 0, err
	}
	return parentHeader.Timestamp, nil
}

// finalizeDisconnectState updates chain state after disconnect.
func (s *SyncEngine) finalizeDisconnectState(rollbackState syncRollbackState, newTipTimestamp uint64) error {
	if err := s.blockStore.TruncateCanonical(uint64(len(rollbackState.canonicalIndex)) - 1); err != nil {
		return s.rollbackApplyBlock(err, rollbackState)
	}
	if s.cfg.ChainStatePath != "" {
		if err := s.chainState.Save(s.cfg.ChainStatePath); err != nil {
			return s.rollbackApplyBlock(err, rollbackState)
		}
	}
	s.mu.Lock()
	s.tipTimestamp = newTipTimestamp
	s.bestKnownHeight = rollbackState.bestKnownHeight
	s.mu.Unlock()
	return nil
}
