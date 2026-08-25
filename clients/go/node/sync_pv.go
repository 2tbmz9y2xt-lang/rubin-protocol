package node

import (
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
		s.diagnose(ctx.diag, "pv_shadow: mismatch height=%d seq_err=%s par_err=%s\n", blockHeight, seqCode, parCode)
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
		s.diagnose(ctx.diag, "pv_shadow: mismatch height=%d seq_ok par_err=%s\n", blockHeight, txErrCode(parErr))
		s.pvTelemetry.RecordMismatchVerdict()
	} else if parSummary.PostStateDigest != seqSummary.PostStateDigest {
		s.recordPVShadowMismatch(fmt.Sprintf("pv_shadow mismatch(height=%d): post_state_digest", blockHeight))
		s.diagnose(ctx.diag, "pv_shadow: mismatch height=%d post_state_digest\n", blockHeight)
		s.pvTelemetry.RecordMismatchState()
	}
}

// pvShadowActive reports whether a shadow run would happen right now.
func (s *SyncEngine) pvShadowActive() bool {
	return (s.pvMode == pvModeShadow || s.pvMode == pvModeOn) && s.isInIBDUnchecked()
}

// pvShadowPreState clones state ONLY when a shadow run will actually consume it.
// The preferred-branch preparation rolls one private state forward in place, so
// it has no per-row pre-image to hand the shadow unless one is taken here. A nil
// result keeps that clone off the default path and lets the caller decide once
// rather than re-evaluate a time-dependent predicate after the connect.
func (s *SyncEngine) pvShadowPreState(state *ChainState) *ChainState {
	if !s.pvShadowActive() {
		return nil
	}
	return cloneChainState(state)
}

// runPVShadow runs the shadow for a caller that already decided it is active.
func (s *SyncEngine) runPVShadow(blockBytes []byte, prevTimestamps []uint64, ctx canonicalBlockApplyContext, seqErr error, seqSummary *ChainStateConnectSummary) {
	if seqErr != nil {
		s.runPVShadowOnError(blockBytes, prevTimestamps, ctx, seqErr)
		return
	}
	s.runPVShadowOnSuccess(blockBytes, prevTimestamps, ctx, seqSummary)
}

// runPVShadowIfActive runs the appropriate PV shadow validation.
func (s *SyncEngine) runPVShadowIfActive(blockBytes []byte, prevTimestamps []uint64, ctx canonicalBlockApplyContext, seqErr error, seqSummary *ChainStateConnectSummary) {
	if !s.pvShadowActive() {
		s.pvTelemetry.RecordBlockSkipped()
		return
	}
	s.runPVShadow(blockBytes, prevTimestamps, ctx, seqErr, seqSummary)
}
