package node

import (
	"errors"
)

type disconnectTipContext struct {
	storedBlock verifiedStoredBlock
	undo        *BlockUndo
	finalState  *ChainState
	mempoolMTP  uint64
	// tipHeight is the canonical height of the block being disconnected, read
	// fresh per block. The canonical index must be truncated relative to the
	// CURRENT tip: a preferred-branch reorg disconnects several blocks inside
	// ONE transition, so a length taken from the shared rollback snapshot would
	// truncate every iteration back to the same original height.
	tipHeight       uint64
	newTipTimestamp uint64
}

type disconnectPreFinalizeError struct{ cause error }

func (e *disconnectPreFinalizeError) Error() string { return e.cause.Error() }

func (e *disconnectPreFinalizeError) Unwrap() error { return e.cause }

func unwrapDisconnectPreFinalizeError(err error) error {
	var early *disconnectPreFinalizeError
	if errors.As(err, &early) {
		return early.cause
	}
	return err
}

func (s *SyncEngine) DisconnectTip() (*ChainStateDisconnectSummary, error) {
	if s == nil {
		return nil, errors.New("sync engine is not initialized")
	}
	diag := &diagnosticBatch{}
	defer s.flushDiagnostics(diag)
	s.mutationMu.Lock()
	defer s.mutationMu.Unlock()
	return s.disconnectTip(diag)
}

// disconnectTip runs one guarded final-C1 M/O plan with no requeue.
func (s *SyncEngine) disconnectTip(diag *diagnosticBatch) (*ChainStateDisconnectSummary, error) {
	canonicalIndex, err := s.canonicalIndexPreflight()
	if err != nil {
		return nil, err
	}
	ctx, err := s.prepareDisconnectTip()
	if err != nil {
		return nil, err
	}
	tr, err := s.beginCanonicalTransition(canonicalIndex, diag)
	if err != nil {
		return nil, err
	}
	if err := s.prepareAndPublishCanonicalMempoolPlan(tr, ctx.finalState, ctx.mempoolMTP, 0); err != nil {
		if endErr := tr.end(err); endErr != nil {
			return nil, endErr
		}
		return nil, err
	}
	summary, err := s.disconnectPreparedTip(ctx, tr.rollback)
	var early *disconnectPreFinalizeError
	if errors.As(err, &early) {
		err = s.rollbackApplyBlock(early.cause, tr.rollback)
	}
	if endErr := tr.end(err); endErr != nil {
		return nil, endErr
	}
	return summary, nil
}

// disconnectPreparedTip disconnects one prepared tip under the caller's already
// open canonical transition. It takes that transition's rollback state by value
// rather than the transition itself: nothing else here is transition-scoped, and
// a value cannot be nil-dereferenced on the validity path.
func (s *SyncEngine) disconnectPreparedTip(ctx disconnectTipContext, rollback syncRollbackState) (*ChainStateDisconnectSummary, error) {
	summary, err := s.disconnectVerifiedUnderTransition(ctx.storedBlock, ctx.undo)
	if err != nil {
		return nil, &disconnectPreFinalizeError{cause: err}
	}
	if err := s.finalizeDisconnectState(rollback, ctx.tipHeight, ctx.newTipTimestamp); err != nil {
		return nil, err
	}
	return summary, nil
}

// disconnectVerifiedUnderTransition mirrors ChainState.disconnectVerifiedStoredBlock
// without its admissionMu acquisition. The canonical transition already owns
// that lock and sync.RWMutex is not reentrant, so calling the public wrapper
// from under the guard would self-deadlock. Validation order and the shared
// already-validated locked mutation primitive are unchanged.
func (s *SyncEngine) disconnectVerifiedUnderTransition(storedBlock verifiedStoredBlock, undo *BlockUndo) (*ChainStateDisconnectSummary, error) {
	state := s.chainState
	if state == nil {
		return nil, errors.New("nil chainstate")
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if !state.HasTip {
		return nil, errors.New("chainstate has no tip")
	}
	if undo == nil {
		return nil, errors.New("nil block undo")
	}
	pb, err := validateVerifiedDisconnectStoredBlock(storedBlock, undo, state.TipHash, state.Height)
	if err != nil {
		return nil, err
	}
	return state.disconnectParsedBlockLocked(pb, storedBlock.lookupHash, undo)
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
	ctx, err := s.prepareDisconnectTipContext(tipHeight, tipHash, storedBlock, undo)
	if err != nil {
		return disconnectTipContext{}, err
	}
	return s.prepareMempoolDisconnectContext(ctx)
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
	newTipTimestamp, err := s.getParentTimestamp(tipHeight, storedBlock.parsed.Header.PrevBlockHash)
	if err != nil {
		return disconnectTipContext{}, err
	}
	return disconnectTipContext{
		storedBlock:     storedBlock,
		undo:            undo,
		tipHeight:       tipHeight,
		newTipTimestamp: newTipTimestamp,
	}, nil
}

func (s *SyncEngine) prepareMempoolDisconnectContext(ctx disconnectTipContext) (disconnectTipContext, error) {
	finalState := cloneChainState(s.chainState)
	if finalState == nil {
		return disconnectTipContext{}, errors.New("nil final disconnect chainstate")
	}
	if _, err := finalState.disconnectVerifiedStoredBlock(ctx.storedBlock, ctx.undo); err != nil {
		return disconnectTipContext{}, err
	}
	nextHeight, _, err := nextBlockContext(finalState)
	if err != nil {
		return disconnectTipContext{}, err
	}
	prevTimestamps, err := prevTimestampsFromStore(s.blockStore, nextHeight)
	if err != nil {
		return disconnectTipContext{}, err
	}
	ctx.finalState = finalState
	if nextHeight != 0 {
		ctx.mempoolMTP = mtpMedian(nextHeight, prevTimestamps)
	}
	return ctx, nil
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

func (s *SyncEngine) disconnectCanonicalToAncestor(commonAncestorHeight uint64, preparedBlocks []verifiedStoredBlock, rollback syncRollbackState) error {
	if err := s.validatePreparedDisconnectBlocks(commonAncestorHeight, preparedBlocks); err != nil {
		return err
	}
	for _, storedBlock := range preparedBlocks {
		ctx, err := s.prepareDisconnectTipFromVerified(storedBlock)
		if err != nil {
			return err
		}
		if _, err := s.disconnectPreparedTip(ctx, rollback); err != nil {
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
func (s *SyncEngine) finalizeDisconnectState(rollbackState syncRollbackState, disconnectedHeight uint64, newTipTimestamp uint64) error {
	if err := s.blockStore.TruncateCanonical(disconnectedHeight); err != nil {
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
