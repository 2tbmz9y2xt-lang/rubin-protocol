package node

import (
	"encoding/hex"
	"errors"
	"fmt"
)

type disconnectTipContext struct {
	storedBlock verifiedStoredBlock
	undo        *BlockUndo
	finalState  *ChainState
	summary     *ChainStateDisconnectSummary
	mempoolMTP  uint64
	// tipHeight is the canonical height of the block being disconnected.
	tipHeight       uint64
	newTipTimestamp uint64
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

// disconnectTip runs one standalone disconnect through the shared driver. Its
// plan has an EMPTY A1 — no block becomes canonical, so there is no
// connected-block fee decay event — an empty new suffix, and one disconnect
// descriptor. The post-disconnect image is both final C1 and the common
// checkpoint, so the path holds exactly one private image.
//
// A summary is returned WITH an error only for TERMINAL_PERSISTENCE(new).
func (s *SyncEngine) disconnectTip(diag *diagnosticBatch) (*ChainStateDisconnectSummary, error) {
	canonicalIndex, err := s.canonicalIndexPreflight()
	if err != nil {
		return nil, err
	}
	priorTip := chainTipScalarsOf(s.chainState)
	ctx, err := s.prepareDisconnectTip()
	if err != nil {
		return nil, err
	}
	disconnect, err := canonicalSequenceDescriptors(canonicalIndex, ctx.tipHeight, ctx.tipHeight+1, true)
	if err != nil {
		return nil, err
	}
	plan := &canonicalTransitionPlan{
		oldSequence: canonicalIndex,
		newSequence: canonicalSequenceWithSuffix(canonicalIndex, ctx.tipHeight, nil),
		disconnect:  disconnect,
		checkpoint:  ctx.finalState,
		final:       ctx.finalState,
		priorTip:    priorTip,
		finalMTP:    ctx.mempoolMTP,
	}
	truth, err := s.commitCanonicalTransition(plan, diag)
	if truth != canonicalTruthNew {
		return nil, err
	}
	s.mu.Lock()
	s.tipTimestamp = ctx.newTipTimestamp
	s.mu.Unlock()
	return ctx.summary, err
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

// prepareMempoolDisconnectContext builds the post-disconnect image on a PRIVATE
// clone and keeps that image's own summary: the live chainstate is never
// disconnected in place, it receives the finished image by assignment after the
// index commit selects NEW.
func (s *SyncEngine) prepareMempoolDisconnectContext(ctx disconnectTipContext) (disconnectTipContext, error) {
	finalState := cloneChainState(s.chainState)
	if finalState == nil {
		return disconnectTipContext{}, errors.New("nil final disconnect chainstate")
	}
	summary, err := finalState.disconnectVerifiedStoredBlock(ctx.storedBlock, ctx.undo)
	if err != nil {
		return disconnectTipContext{}, err
	}
	ctx.summary = summary
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

// previewDisconnectCanonicalToAncestor rolls previewState back to the common
// ancestor, leaving it holding the immutable common-checkpoint image. It walks
// the ancestry from the preview tip and CROSS-CHECKS every walked block against
// the canonical identity's row at that height, so a walked hash the identity
// does not name at that exact height is refused before any artifact is staged.
func (s *SyncEngine) previewDisconnectCanonicalToAncestor(previewState *ChainState, canonicalIndex []string, commonAncestorHeight uint64) (uint64, error) {
	if previewState == nil {
		return 0, nil
	}
	currentTipHeight := previewState.Height
	if currentTipHeight >= uint64(len(canonicalIndex)) || commonAncestorHeight > currentTipHeight {
		return 0, errors.New("preview tip is not inside the canonical identity")
	}
	reorgDepth := currentTipHeight - commonAncestorHeight
	disconnectedBlocks := make([]verifiedStoredBlock, 0, reorgDepth)
	tipHash := previewState.TipHash
	for height := currentTipHeight; height > commonAncestorHeight; height-- {
		if canonicalIndex[height] != hex.EncodeToString(tipHash[:]) {
			return 0, fmt.Errorf("disconnect row %x is not canonical at height %d", tipHash, height)
		}
		storedBlock, err := s.loadVerifiedStoredBlock(tipHash)
		if err != nil {
			return 0, err
		}
		disconnectedBlocks = append(disconnectedBlocks, storedBlock)
		tipHash = storedBlock.parsed.Header.PrevBlockHash
	}
	for _, storedBlock := range disconnectedBlocks {
		undo, err := s.blockStore.GetUndo(storedBlock.lookupHash)
		if err != nil {
			return 0, err
		}
		if _, err := previewState.disconnectVerifiedStoredBlock(storedBlock, undo); err != nil {
			return 0, err
		}
	}
	return reorgDepth, nil
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
