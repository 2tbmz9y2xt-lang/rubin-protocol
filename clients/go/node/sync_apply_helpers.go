package node

import (
	"errors"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

// txErrCode extracts the consensus.TxError code string from err for
// telemetry and event labeling. It uses errors.As so that a wrapped
// *consensus.TxError (e.g. produced by fmt.Errorf("...: %w", inner)) is
// still classified correctly instead of falling through to "ERR". A nil
// error reports "OK"; any non-TxError reports "ERR".
func txErrCode(err error) string {
	if err == nil {
		return "OK"
	}
	var te *consensus.TxError
	if errors.As(err, &te) {
		return string(te.Code)
	}
	return "ERR"
}

func (s *SyncEngine) persistAppliedBlock(summary *ChainStateConnectSummary, blockHash [32]byte, pb *consensus.ParsedBlock, blockBytes []byte, prevState *ChainState) error {
	if s.blockStore != nil {
		undo, err := buildBlockUndo(prevState, pb, summary.BlockHeight)
		if err != nil {
			return err
		}
		if err := s.blockStore.CommitCanonicalBlock(summary.BlockHeight, blockHash, pb.HeaderBytes, blockBytes, undo); err != nil {
			return err
		}
	}
	if s.cfg.ChainStatePath != "" && (s.blockStore == nil || shouldPersistChainStateSnapshot(s.chainState, summary)) {
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

func (s *SyncEngine) noteBlockApplyAccepted() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.blockApply.Accepted++
}

func (s *SyncEngine) noteBlockApplyAcceptedN(count uint64) {
	if s == nil || count == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.blockApply.Accepted += count
}

func (s *SyncEngine) noteBlockApplyRejected() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.blockApply.Rejected++
}

func (s *SyncEngine) noteBlockApplyOutcome(outcome blockApplyMetricOutcome) {
	switch outcome {
	case blockApplyMetricNone:
		return
	case blockApplyMetricAccepted:
		s.noteBlockApplyAccepted()
	case blockApplyMetricRejected:
		s.noteBlockApplyRejected()
	}
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

func (s *SyncEngine) currentCanonicalTip() (uint64, [32]byte, error) {
	height, tipHash, ok, err := s.blockStore.Tip()
	if err != nil {
		return 0, [32]byte{}, err
	}
	if !ok {
		return 0, [32]byte{}, errors.New("blockstore has no canonical tip")
	}
	return height, tipHash, nil
}
