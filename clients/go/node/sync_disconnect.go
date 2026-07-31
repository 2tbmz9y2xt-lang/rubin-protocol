package node

import (
	"errors"
)

type disconnectTipContext struct {
	storedBlock     verifiedStoredBlock
	undo            *BlockUndo
	rollbackState   syncRollbackState
	newTipTimestamp uint64
}

func (s *SyncEngine) DisconnectTip() (*ChainStateDisconnectSummary, error) {
	if s == nil {
		return nil, errors.New("sync engine is not initialized")
	}
	s.mutationMu.Lock()
	defer s.mutationMu.Unlock()
	return s.disconnectTip()
}

func (s *SyncEngine) disconnectTip() (*ChainStateDisconnectSummary, error) {
	ctx, err := s.prepareDisconnectTip()
	if err != nil {
		return nil, err
	}
	return s.disconnectPreparedTip(ctx)
}

func (s *SyncEngine) disconnectPreparedTip(ctx disconnectTipContext) (*ChainStateDisconnectSummary, error) {
	summary, err := s.chainState.disconnectVerifiedStoredBlock(ctx.storedBlock, ctx.undo)
	if err != nil {
		return nil, err
	}
	if err := s.finalizeDisconnectState(ctx.rollbackState, ctx.newTipTimestamp); err != nil {
		return nil, err
	}
	return summary, nil
}

func (s *SyncEngine) prepareDisconnectTip() (disconnectTipContext, error) {
	if err := s.validateDisconnectTipReady(); err != nil {
		return disconnectTipContext{}, err
	}
	tipHeight, tipHash, err := s.currentDisconnectTip()
	if err != nil {
		return disconnectTipContext{}, err
	}
	storedBlock, undo, err := s.fetchDisconnectBlockAndUndo(tipHash)
	if err != nil {
		return disconnectTipContext{}, err
	}
	return s.prepareDisconnectTipContext(tipHeight, tipHash, storedBlock, undo)
}

func (s *SyncEngine) prepareDisconnectTipFromVerified(storedBlock verifiedStoredBlock) (disconnectTipContext, error) {
	if err := s.validateDisconnectTipReady(); err != nil {
		return disconnectTipContext{}, err
	}
	tipHeight, tipHash, err := s.currentDisconnectTip()
	if err != nil {
		return disconnectTipContext{}, err
	}
	undo, err := s.blockStore.GetUndo(tipHash)
	if err != nil {
		return disconnectTipContext{}, err
	}
	return s.prepareDisconnectTipContext(tipHeight, tipHash, storedBlock, undo)
}

func (s *SyncEngine) currentDisconnectTip() (uint64, [32]byte, error) {
	tipHeight, tipHash, err := s.currentCanonicalTip()
	if err != nil {
		return 0, [32]byte{}, err
	}
	view := s.chainState.view()
	gotTip := struct {
		hasTip bool
		height uint64
		hash   [32]byte
	}{hasTip: view.hasTip, height: view.height, hash: view.tipHash}
	wantTip := struct {
		hasTip bool
		height uint64
		hash   [32]byte
	}{hasTip: true, height: tipHeight, hash: tipHash}
	if gotTip != wantTip {
		return 0, [32]byte{}, errors.New("chainstate tip does not match blockstore tip")
	}
	return tipHeight, tipHash, nil
}

func (s *SyncEngine) prepareDisconnectTipContext(tipHeight uint64, tipHash [32]byte, storedBlock verifiedStoredBlock, undo *BlockUndo) (disconnectTipContext, error) {
	if storedBlock.lookupHash != tipHash {
		return disconnectTipContext{}, errors.New("disconnect block is not current canonical tip")
	}
	if storedBlock.parsed == nil {
		return disconnectTipContext{}, errors.New("nil verified stored block")
	}
	rollbackState, err := s.captureRollbackState()
	if err != nil {
		return disconnectTipContext{}, err
	}
	newTipTimestamp, err := s.getParentTimestamp(tipHeight, storedBlock.parsed.Header.PrevBlockHash)
	if err != nil {
		return disconnectTipContext{}, err
	}
	return disconnectTipContext{
		storedBlock:     storedBlock,
		undo:            undo,
		rollbackState:   rollbackState,
		newTipTimestamp: newTipTimestamp,
	}, nil
}

func (s *SyncEngine) validateDisconnectTipReady() error {
	if err := s.mutationAllowed(); err != nil {
		return err
	}
	if s.blockStore == nil {
		return errors.New("sync engine has no blockstore")
	}
	return nil
}

func (s *SyncEngine) disconnectCanonicalToAncestor(commonAncestorHeight uint64, preparedBlocks []verifiedStoredBlock) error {
	if err := s.validatePreparedDisconnectBlocks(commonAncestorHeight, preparedBlocks); err != nil {
		return err
	}
	for _, storedBlock := range preparedBlocks {
		ctx, err := s.prepareDisconnectTipFromVerified(storedBlock)
		if err != nil {
			return err
		}
		if _, err := s.disconnectPreparedTip(ctx); err != nil {
			return err
		}
	}
	return nil
}

func (s *SyncEngine) validatePreparedDisconnectBlocks(commonAncestorHeight uint64, preparedBlocks []verifiedStoredBlock) error {
	if err := s.validateDisconnectTipReady(); err != nil {
		return err
	}
	currentTipHeight, _, err := s.currentCanonicalTip()
	if err != nil {
		return err
	}
	if commonAncestorHeight > currentTipHeight {
		return errors.New("common ancestor is above canonical tip")
	}
	if uint64(len(preparedBlocks)) != currentTipHeight-commonAncestorHeight {
		return errors.New("prepared disconnect block count mismatch")
	}
	for index, storedBlock := range preparedBlocks {
		if err := s.validatePreparedDisconnectBlock(storedBlock, currentTipHeight-uint64(index)); err != nil {
			return err
		}
	}
	return nil
}

func (s *SyncEngine) validatePreparedDisconnectBlock(storedBlock verifiedStoredBlock, canonicalHeight uint64) error {
	if storedBlock.parsed == nil {
		return errors.New("invalid prepared disconnect block")
	}
	if len(storedBlock.parsed.Txs) != len(storedBlock.parsed.Txids) {
		return errors.New("invalid prepared disconnect block")
	}
	expectedHash, ok, err := s.blockStore.CanonicalHash(canonicalHeight)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("prepared disconnect block is not canonical")
	}
	if storedBlock.lookupHash != expectedHash {
		return errors.New("prepared disconnect block is not canonical")
	}
	return nil
}

func (s *SyncEngine) previewDisconnectCanonicalToAncestor(previewState *ChainState, commonAncestorHeight uint64) ([]verifiedStoredBlock, uint64, error) {
	if previewState == nil {
		return nil, 0, nil
	}
	currentTipHeight := previewState.Height
	reorgDepth := currentTipHeight - commonAncestorHeight
	disconnectedBlocks := make([]verifiedStoredBlock, 0, reorgDepth)
	tipHash := previewState.TipHash
	for height := currentTipHeight; height > commonAncestorHeight; height-- {
		storedBlock, err := s.loadVerifiedStoredBlock(tipHash)
		if err != nil {
			return nil, 0, err
		}
		disconnectedBlocks = append(disconnectedBlocks, storedBlock)
		tipHash = storedBlock.parsed.Header.PrevBlockHash
	}
	for _, storedBlock := range disconnectedBlocks {
		undo, err := s.blockStore.GetUndo(storedBlock.lookupHash)
		if err != nil {
			return nil, 0, err
		}
		if _, err := previewState.disconnectVerifiedStoredBlock(storedBlock, undo); err != nil {
			return nil, 0, err
		}
	}
	return disconnectedBlocks, reorgDepth, nil
}

func (s *SyncEngine) fetchDisconnectBlockAndUndo(tipHash [32]byte) (verifiedStoredBlock, *BlockUndo, error) {
	storedBlock, err := s.loadVerifiedStoredBlock(tipHash)
	if err != nil {
		return verifiedStoredBlock{}, nil, err
	}
	undo, err := s.blockStore.GetUndo(tipHash)
	return storedBlock, undo, err
}

// getParentTimestamp returns the timestamp of the parent block, or 0 at height 0.
func (s *SyncEngine) getParentTimestamp(tipHeight uint64, prevBlockHash [32]byte) (uint64, error) {
	if tipHeight == 0 {
		return 0, nil
	}
	parentHeader, err := s.blockStore.chainWorkHeader(prevBlockHash)
	return parentHeader.Timestamp, err
}

// finalizeDisconnectState updates chain state after disconnect.
func (s *SyncEngine) finalizeDisconnectState(rollbackState syncRollbackState, newTipTimestamp uint64) error {
	if err := s.blockStore.TruncateCanonical(uint64(len(rollbackState.canonicalIndex)) - 1); err != nil {
		if isAtomicWritePostCommit(err) {
			return s.handlePersistenceError(err, true, false)
		}
		return s.rollbackApplyBlock(err, rollbackState)
	}
	if s.cfg.ChainStatePath != "" {
		if err := s.chainState.Save(s.cfg.ChainStatePath); err != nil {
			if isAtomicWritePostCommit(err) {
				return s.handlePersistenceError(err, false, true)
			}
			return s.rollbackApplyBlock(err, rollbackState)
		}
	}
	s.mu.Lock()
	s.tipTimestamp = newTipTimestamp
	s.bestKnownHeight = rollbackState.bestKnownHeight
	s.mu.Unlock()
	return nil
}
