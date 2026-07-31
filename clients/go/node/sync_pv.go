package node

import (
	"errors"
	"fmt"
	"time"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

// validateGenesisIdentity checks genesis block identity at height 0.
func (s *SyncEngine) validateGenesisIdentity(blockHeight uint64, blockHash [32]byte) (blockApplyMetricOutcome, error) {
	var zeroID [32]byte
	if blockHeight == 0 && s.cfg.ChainID != zeroID && s.cfg.ChainID != devnetGenesisChainID {
		return blockApplyMetricRejected, &consensus.TxError{
			Code: consensus.BLOCK_ERR_LINKAGE_INVALID,
			Msg:  "genesis chain_id mismatch",
		}
	}
	if blockHeight == 0 && s.cfg.ChainID == devnetGenesisChainID && blockHash != devnetGenesisBlockHash {
		return blockApplyMetricRejected, &consensus.TxError{
			Code: consensus.BLOCK_ERR_LINKAGE_INVALID,
			Msg:  "genesis_hash mismatch",
		}
	}
	return blockApplyMetricNone, nil
}

// runPVShadowOnError runs parallel validation when sequential connect failed.
//
// The shadow run MUST observe the same expected target as the sequential
// connect that produced seqErr — ctx.expectedTarget, never the static
// SyncConfig.ExpectedTarget, or PV reports a fabricated seq/par divergence at
// every retarget boundary.
func (s *SyncEngine) runPVShadowOnError(blockBytes []byte, prevTimestamps []uint64, ctx canonicalBlockApplyContext, seqErr error) {
	blockHeight := ctx.blockHeight
	s.pvTelemetry.RecordBlockValidated()
	validateStart := time.Now()
	shadowState := cloneChainState(ctx.prevState)
	_, parErr := shadowState.ConnectBlockParallelSigsWithSuiteContext(
		blockBytes,
		ctx.expectedTarget, prevTimestamps, s.cfg.ChainID,
		s.cfg.RotationProvider, s.cfg.SuiteRegistry, 0,
	)
	s.pvTelemetry.RecordValidateLatency(time.Since(validateStart))
	seqCode, parCode := txErrCode(seqErr), txErrCode(parErr)
	if seqCode != parCode {
		s.recordPVShadowMismatch(fmt.Sprintf("pv_shadow mismatch(height=%d): seq_err=%s par_err=%s", blockHeight, seqCode, parCode))
		_, _ = fmt.Fprintf(s.stderr, "pv_shadow: mismatch height=%d seq_err=%s par_err=%s\n", blockHeight, seqCode, parCode)
		if parErr == nil {
			s.pvTelemetry.RecordMismatchVerdict()
		} else {
			s.pvTelemetry.RecordMismatchError()
		}
	}
}

// runPVShadowOnSuccess runs parallel validation when sequential connect succeeded.
//
// Same contract as runPVShadowOnError: binds to ctx.expectedTarget.
func (s *SyncEngine) runPVShadowOnSuccess(blockBytes []byte, prevTimestamps []uint64, ctx canonicalBlockApplyContext, seqSummary *ChainStateConnectSummary) {
	blockHeight := ctx.blockHeight
	s.pvTelemetry.RecordBlockValidated()
	validateStart := time.Now()
	shadowState := cloneChainState(ctx.prevState)
	parSummary, parErr := shadowState.ConnectBlockParallelSigsWithSuiteContext(
		blockBytes,
		ctx.expectedTarget, prevTimestamps, s.cfg.ChainID,
		s.cfg.RotationProvider, s.cfg.SuiteRegistry, 0,
	)
	s.pvTelemetry.RecordValidateLatency(time.Since(validateStart))
	if parSummary != nil {
		s.pvTelemetry.RecordWorkerTasks(parSummary.SigTaskCount)
		for i := uint64(0); i < parSummary.WorkerPanics; i++ {
			s.pvTelemetry.RecordWorkerPanic()
		}
	}
	if parErr != nil {
		s.recordPVShadowMismatch(fmt.Sprintf("pv_shadow mismatch(height=%d): seq_ok par_err=%s", blockHeight, txErrCode(parErr)))
		_, _ = fmt.Fprintf(s.stderr, "pv_shadow: mismatch height=%d seq_ok par_err=%s\n", blockHeight, txErrCode(parErr))
		s.pvTelemetry.RecordMismatchVerdict()
	} else if parSummary.PostStateDigest != seqSummary.PostStateDigest {
		s.recordPVShadowMismatch(fmt.Sprintf("pv_shadow mismatch(height=%d): post_state_digest", blockHeight))
		_, _ = fmt.Fprintf(s.stderr, "pv_shadow: mismatch height=%d post_state_digest\n", blockHeight)
		s.pvTelemetry.RecordMismatchState()
	}
}

// runPVShadowIfActive runs the appropriate PV shadow validation.
func (s *SyncEngine) runPVShadowIfActive(blockBytes []byte, prevTimestamps []uint64, ctx canonicalBlockApplyContext, seqErr error, seqSummary *ChainStateConnectSummary) {
	pvActive := (s.pvMode == pvModeShadow || s.pvMode == pvModeOn) && s.isInIBDUnchecked()
	if !pvActive {
		s.pvTelemetry.RecordBlockSkipped()
		return
	}
	if seqErr != nil {
		s.runPVShadowOnError(blockBytes, prevTimestamps, ctx, seqErr)
	} else {
		s.runPVShadowOnSuccess(blockBytes, prevTimestamps, ctx, seqSummary)
	}
}

// finalizeAppliedBlock commits persistence, records metrics, and updates mempool.
func (s *SyncEngine) finalizeAppliedBlock(summary *ChainStateConnectSummary, blockHash [32]byte, pb *consensus.ParsedBlock, blockBytes []byte, prevState *ChainState, rollbackState syncRollbackState) error {
	commitStart := time.Now()
	if err := s.persistAppliedBlock(summary, blockHash, pb, blockBytes, prevState); err != nil {
		if isAtomicWritePostCommit(err) {
			var atomicErr *atomicWriteError
			errors.As(err, &atomicErr)
			if s.blockStore != nil && atomicErr.destination == s.blockStore.indexPath {
				return s.handlePersistenceError(err, true, false)
			}
			if atomicErr.destination == s.cfg.ChainStatePath {
				return s.handlePersistenceError(err, false, true)
			}
			fault := s.handlePersistenceError(err, false, false)
			s.chainState.replaceFrom(rollbackState.chainState)
			return fault
		}
		return s.rollbackApplyBlock(err, rollbackState)
	}
	s.pvTelemetry.RecordCommitLatency(time.Since(commitStart))
	s.recordAppliedBlock(summary.BlockHeight, pb.Header.Timestamp)
	if s.mempool != nil {
		if err := s.mempool.applyConnectedBlockParsed(pb); err != nil {
			_, _ = fmt.Fprintf(s.stderr, "mempool: apply-connected-block: %v\n", err)
		}
	}
	return nil
}
