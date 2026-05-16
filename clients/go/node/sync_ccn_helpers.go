package node

import (
	"fmt"
	"time"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

// validateGenesisIdentity checks genesis block identity at height 0.
// Returns blockApplyMetricRejected + TxError on mismatch, or blockApplyMetricNone + nil when ok.
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
func (s *SyncEngine) runPVShadowOnError(blockBytes []byte, prevTimestamps []uint64, prevState *ChainState, blockHeight uint64, seqErr error) {
	s.pvTelemetry.RecordBlockValidated()
	validateStart := time.Now()
	shadowState := cloneChainState(prevState)
	_, parErr := shadowState.ConnectBlockParallelSigsWithSuiteContext(
		blockBytes,
		s.cfg.ExpectedTarget, prevTimestamps, s.cfg.ChainID,
		s.cfg.CoreExtProfiles, s.cfg.RotationProvider, s.cfg.SuiteRegistry, 0,
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
func (s *SyncEngine) runPVShadowOnSuccess(blockBytes []byte, prevTimestamps []uint64, prevState *ChainState, blockHeight uint64, seqSummary *ChainStateConnectSummary) {
	s.pvTelemetry.RecordBlockValidated()
	validateStart := time.Now()
	shadowState := cloneChainState(prevState)
	parSummary, parErr := shadowState.ConnectBlockParallelSigsWithSuiteContext(
		blockBytes,
		s.cfg.ExpectedTarget, prevTimestamps, s.cfg.ChainID,
		s.cfg.CoreExtProfiles, s.cfg.RotationProvider, s.cfg.SuiteRegistry, 0,
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
func (s *SyncEngine) runPVShadowIfActive(blockBytes []byte, prevTimestamps []uint64, prevState *ChainState, blockHeight uint64, seqErr error, seqSummary *ChainStateConnectSummary) {
	pvActive := (s.pvMode == pvModeShadow || s.pvMode == pvModeOn) && s.isInIBDUnchecked()
	if !pvActive {
		s.pvTelemetry.RecordBlockSkipped()
		return
	}
	if seqErr != nil {
		s.runPVShadowOnError(blockBytes, prevTimestamps, prevState, blockHeight, seqErr)
	} else {
		s.runPVShadowOnSuccess(blockBytes, prevTimestamps, prevState, blockHeight, seqSummary)
	}
}

// finalizeAppliedBlock commits persistence, records metrics, and updates mempool.
func (s *SyncEngine) finalizeAppliedBlock(summary *ChainStateConnectSummary, blockHash [32]byte, pb *consensus.ParsedBlock, blockBytes []byte, prevState *ChainState, rollbackState syncRollbackState) error {
	commitStart := time.Now()
	if err := s.persistAppliedBlock(summary, blockHash, pb, blockBytes, prevState); err != nil {
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

// buildMempoolRestoreMaps builds txid/wtxid/spender/admission maps from snapshot entries.
func buildMempoolRestoreMaps(snapshotEntries []mempoolEntry, maxTxs int, maxBytes int) (
	txs map[[32]byte]*mempoolEntry,
	wtxids map[[32]byte][32]byte,
	spenders map[consensus.Outpoint][32]byte,
	maxAdmissionSeq uint64,
	usedBytes int,
	err error,
) {
	txs = make(map[[32]byte]*mempoolEntry, len(snapshotEntries))
	wtxids = make(map[[32]byte][32]byte, len(snapshotEntries))
	spenders = make(map[consensus.Outpoint][32]byte)
	admissionSeqs := make(map[uint64][32]byte, len(snapshotEntries))
	for _, item := range snapshotEntries {
		entry := cloneMempoolEntry(&item)
		if _, exists := txs[entry.txid]; exists {
			return nil, nil, nil, 0, 0, fmt.Errorf("duplicate mempool snapshot txid %x", entry.txid)
		}
		if existing, exists := wtxids[entry.wtxid]; exists {
			return nil, nil, nil, 0, 0, fmt.Errorf("duplicate mempool snapshot wtxid %x existing=%x new=%x", entry.wtxid, existing, entry.txid)
		}
		if err := validateMempoolSnapshotEntry(entry); err != nil {
			return nil, nil, nil, 0, 0, err
		}
		if existing, exists := admissionSeqs[entry.admissionSeq]; exists {
			return nil, nil, nil, 0, 0, fmt.Errorf("duplicate mempool snapshot admission_seq %d existing=%x new=%x", entry.admissionSeq, existing, entry.txid)
		}
		if len(txs) >= maxTxs {
			return nil, nil, nil, 0, 0, fmt.Errorf("mempool snapshot exceeds transaction cap: count=%d max=%d", len(txs)+1, maxTxs)
		}
		if entry.size > maxBytes || usedBytes > maxBytes-entry.size {
			return nil, nil, nil, 0, 0, fmt.Errorf("mempool snapshot exceeds byte cap: used=%d entry=%d max=%d", usedBytes, entry.size, maxBytes)
		}
		for _, op := range entry.inputs {
			if existing, exists := spenders[op]; exists {
				return nil, nil, nil, 0, 0, fmt.Errorf("duplicate mempool snapshot spender txid=%x vout=%d existing=%x new=%x", op.Txid, op.Vout, existing, entry.txid)
			}
			spenders[op] = entry.txid
		}
		entryCopy := entry
		txs[entryCopy.txid] = &entryCopy
		wtxids[entryCopy.wtxid] = entryCopy.txid
		admissionSeqs[entryCopy.admissionSeq] = entryCopy.txid
		usedBytes += entryCopy.size
		if entryCopy.admissionSeq > maxAdmissionSeq {
			maxAdmissionSeq = entryCopy.admissionSeq
		}
	}
	return
}

// validateMempoolEntryParsed parses raw tx bytes inside a mempool entry and validates consistency.
func validateMempoolEntryParsed(entry mempoolEntry) error {
	tx, txid, wtxid, consumed, err := consensus.ParseTx(entry.raw)
	if err != nil {
		return fmt.Errorf("invalid mempool snapshot entry raw for txid %x: %w", entry.txid, err)
	}
	if consumed != len(entry.raw) {
		return fmt.Errorf("mempool snapshot entry has trailing bytes for txid %x: consumed=%d raw_len=%d", entry.txid, consumed, len(entry.raw))
	}
	if txid != entry.txid {
		return fmt.Errorf("mempool snapshot entry txid mismatch: entry=%x raw=%x", entry.txid, txid)
	}
	if wtxid != entry.wtxid {
		return fmt.Errorf("mempool snapshot entry wtxid mismatch: entry=%x raw=%x", entry.wtxid, wtxid)
	}
	weight, _, _, err := consensus.TxWeightAndStats(tx)
	if err != nil {
		return fmt.Errorf("invalid mempool snapshot entry weight for txid %x: %w", entry.txid, err)
	}
	if entry.weight != weight {
		return fmt.Errorf("mempool snapshot entry weight mismatch: entry=%d computed=%d txid=%x", entry.weight, weight, entry.txid)
	}
	if entry.admissionSeq == 0 {
		return fmt.Errorf("invalid mempool snapshot entry admission_seq for txid %x: seq=0", entry.txid)
	}
	if !validMempoolTxSource(entry.source) {
		return fmt.Errorf("invalid mempool snapshot entry source for txid %x: source=%q", entry.txid, entry.source)
	}
	if len(entry.inputs) != len(tx.Inputs) {
		return fmt.Errorf("mempool snapshot entry input count mismatch for txid %x: entry=%d tx=%d", entry.txid, len(entry.inputs), len(tx.Inputs))
	}
	for i, in := range tx.Inputs {
		want := consensus.Outpoint{Txid: in.PrevTxid, Vout: in.PrevVout}
		if entry.inputs[i] != want {
			return fmt.Errorf("mempool snapshot entry input mismatch for txid %x at index=%d", entry.txid, i)
		}
	}
	return nil
}
