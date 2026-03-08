package node

import (
	"errors"
	"fmt"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

type syncRollbackState struct {
	chainState      chainStateDisk
	canonicalIndex  []string
	tipTimestamp    uint64
	bestKnownHeight uint64
	lastReorgDepth  uint64
	reorgCount      uint64
}

func (s *SyncEngine) captureRollbackState() (syncRollbackState, error) {
	snapshot, err := stateToDisk(s.chainState)
	if err != nil {
		return syncRollbackState{}, err
	}
	canonicalIndex, err := blockStoreCanonicalIndexSnapshot(s.blockStore)
	if err != nil {
		return syncRollbackState{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return syncRollbackState{
		chainState:      snapshot,
		canonicalIndex:  canonicalIndex,
		tipTimestamp:    s.tipTimestamp,
		bestKnownHeight: s.bestKnownHeight,
		lastReorgDepth:  s.lastReorgDepth,
		reorgCount:      s.reorgCount,
	}, nil
}

func (s *SyncEngine) rollbackApplyBlock(cause error, state syncRollbackState) error {
	restoreErr := restoreChainState(s.chainState, state.chainState)
	if s.blockStore != nil {
		if bsErr := s.blockStore.RestoreCanonicalIndex(state.canonicalIndex); bsErr != nil && restoreErr == nil {
			restoreErr = bsErr
		}
	}
	if restoreErr == nil && s.cfg.ChainStatePath != "" {
		if saveErr := s.chainState.Save(s.cfg.ChainStatePath); saveErr != nil {
			restoreErr = saveErr
		}
	}
	s.mu.Lock()
	s.tipTimestamp = state.tipTimestamp
	s.bestKnownHeight = state.bestKnownHeight
	s.lastReorgDepth = state.lastReorgDepth
	s.reorgCount = state.reorgCount
	s.mu.Unlock()
	if restoreErr != nil {
		return fmt.Errorf("%w (rollback failed: %v)", cause, restoreErr)
	}
	return cause
}

func (s *SyncEngine) applyCanonicalParsedBlock(
	pb *consensus.ParsedBlock,
	blockBytes []byte,
	prevTimestamps []uint64,
) (*ChainStateConnectSummary, error) {
	if s == nil || s.chainState == nil {
		return nil, errors.New("sync engine is not initialized")
	}
	if pb == nil {
		return nil, errors.New("nil parsed block")
	}
	blockHeight, _, err := nextBlockContext(s.chainState)
	if err != nil {
		return nil, err
	}
	if err := validateIncomingChainID(blockHeight, s.cfg.ChainID); err != nil {
		return nil, err
	}
	blockHash, err := consensus.BlockHash(pb.HeaderBytes)
	if err != nil {
		return nil, err
	}

	rollbackState, err := s.captureRollbackState()
	if err != nil {
		return nil, err
	}
	prevState, err := chainStateFromDisk(rollbackState.chainState)
	if err != nil {
		return nil, err
	}
	summary, err := s.chainState.ConnectBlock(blockBytes, s.cfg.ExpectedTarget, prevTimestamps, s.cfg.ChainID)
	if err != nil {
		return nil, err
	}
	if err := s.persistAppliedBlock(summary, blockHash, pb, blockBytes, prevState); err != nil {
		return nil, s.rollbackApplyBlock(err, rollbackState)
	}

	s.recordAppliedBlock(summary.BlockHeight, pb.Header.Timestamp)
	if s.mempool != nil {
		_ = s.mempool.EvictConfirmed(blockBytes)
		_ = s.mempool.RemoveConflicting(blockBytes)
	}
	return summary, nil
}

func (s *SyncEngine) persistAppliedBlock(summary *ChainStateConnectSummary, blockHash [32]byte, pb *consensus.ParsedBlock, blockBytes []byte, prevState *ChainState) error {
	if s.blockStore != nil {
		undo, err := buildBlockUndo(prevState, pb, summary.BlockHeight)
		if err != nil {
			return err
		}
		if err := s.blockStore.PutBlock(summary.BlockHeight, blockHash, pb.HeaderBytes, blockBytes); err != nil {
			return err
		}
		if err := s.blockStore.PutUndo(blockHash, undo); err != nil {
			return err
		}
	}
	if s.cfg.ChainStatePath != "" {
		if err := s.chainState.Save(s.cfg.ChainStatePath); err != nil {
			return err
		}
	}
	return nil
}

func (s *SyncEngine) recordAppliedBlock(height uint64, timestamp uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tipTimestamp = timestamp
	if height > s.bestKnownHeight {
		s.bestKnownHeight = height
	}
	s.lastReorgDepth = 0
}

func (s *SyncEngine) noteReorg(depth uint64) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastReorgDepth = depth
	if depth > 0 {
		s.reorgCount++
	}
}

func validateIncomingChainID(blockHeight uint64, chainID [32]byte) error {
	var zeroID [32]byte
	if blockHeight == 0 && chainID != zeroID {
		if chainID != devnetGenesisChainID {
			return errors.New("genesis chain_id mismatch")
		}
	}
	return nil
}

func restoreChainState(dst *ChainState, snapshot chainStateDisk) error {
	if dst == nil {
		return errors.New("nil chainstate destination")
	}
	recovered, err := chainStateFromDisk(snapshot)
	if err != nil {
		return err
	}
	*dst = *recovered
	return nil
}

func blockStoreCanonicalCount(store *BlockStore) (uint64, error) {
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

func blockStoreCanonicalIndexSnapshot(store *BlockStore) ([]string, error) {
	if store == nil {
		return nil, nil
	}
	return store.CanonicalIndexSnapshot()
}

func parentTipTimestamp(store *BlockStore, tipHeight uint64, prevBlockHash [32]byte) (uint64, error) {
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
