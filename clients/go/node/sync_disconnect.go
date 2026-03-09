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
	if !s.chainState.HasTip || s.chainState.Height != tipHeight || s.chainState.TipHash != tipHash {
		return nil, errors.New("chainstate tip does not match blockstore tip")
	}

	blockBytes, err := s.blockStore.GetBlockByHash(tipHash)
	if err != nil {
		return nil, err
	}
	undo, err := s.blockStore.GetUndo(tipHash)
	if err != nil {
		return nil, err
	}
	pb, err := consensus.ParseBlockBytes(blockBytes)
	if err != nil {
		return nil, err
	}

	rollbackState, err := s.captureRollbackState()
	if err != nil {
		return nil, err
	}
	newTipTimestamp := uint64(0)
	if tipHeight > 0 {
		parentHeaderBytes, err := s.blockStore.GetHeaderByHash(pb.Header.PrevBlockHash)
		if err != nil {
			return nil, err
		}
		parentHeader, err := consensus.ParseBlockHeaderBytes(parentHeaderBytes)
		if err != nil {
			return nil, err
		}
		newTipTimestamp = parentHeader.Timestamp
	}

	summary, err := s.chainState.DisconnectBlock(blockBytes, undo)
	if err != nil {
		return nil, err
	}
	if err := s.blockStore.TruncateCanonical(uint64(len(rollbackState.canonicalIndex)) - 1); err != nil {
		return nil, s.rollbackApplyBlock(err, rollbackState)
	}
	if s.cfg.ChainStatePath != "" {
		if err := s.chainState.Save(s.cfg.ChainStatePath); err != nil {
			return nil, s.rollbackApplyBlock(err, rollbackState)
		}
	}

	s.mu.Lock()
	s.tipTimestamp = newTipTimestamp
	s.bestKnownHeight = rollbackState.bestKnownHeight
	s.mu.Unlock()
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
