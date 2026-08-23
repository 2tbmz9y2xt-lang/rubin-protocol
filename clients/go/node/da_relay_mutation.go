package node

import (
	"bytes"
	"crypto/sha3"
	"sort"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

func (s *DARelayState) releasePeerQuotaKey(key string) error {
	if s == nil {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.orphanBytesByPeerQuotaKey[key] == 0 {
		return nil
	}
	return s.releasePeerQuotaKeyLocked(key)
}

func (s *DARelayState) releasePeerQuotaKeyLocked(key string) error {
	for _, daID := range s.sortedIncompleteDAIDsLocked() {
		if err := s.releasePeerQuotaKeyRecordLocked(key, s.sets[daID]); err != nil {
			return err
		}
	}
	return nil
}

func (s *DARelayState) releasePeerQuotaKeyRecordLocked(key string, record daRelaySetRecord) error {
	updated, changed, err := record.withoutPeerQuotaKey(key)
	if err != nil {
		return err
	}
	if !changed {
		return nil
	}
	if updated.emptyIncomplete() {
		return s.removeDASetRecordLocked(record)
	}
	return s.applyDASetRecordLocked(updated)
}

func (s *DARelayState) sortedIncompleteDAIDsLocked() [][32]byte {
	var daIDs [][32]byte
	for daID := range s.orphanBytesByDAID {
		record, ok := s.sets[daID]
		if !ok || record.state == daRelayStateCompleteSet {
			continue
		}
		daIDs = append(daIDs, daID)
	}
	sort.Slice(daIDs, func(i, j int) bool {
		return bytes.Compare(daIDs[i][:], daIDs[j][:]) < 0
	})
	return daIDs
}

func (s *DARelayState) addDACommit(peerQuotaKey string, commit daRelayCommit) error {
	if err := validateDACommit(commit); err != nil {
		return err
	}

	txBytesOwned := false
	for {
		_, retry, err := s.addDACommitAttempt(peerQuotaKey, &commit, &txBytesOwned)
		if err != nil {
			return err
		}
		if retry {
			continue
		}
		return nil
	}
}

func validateDACommit(commit daRelayCommit) error {
	if commit.chunkCount == 0 || uint64(commit.chunkCount) > consensus.MAX_DA_CHUNK_COUNT {
		return errDARelayChunkCountInvalid
	}
	if commit.wireBytes == 0 {
		return errDARelayWireBytesInvalid
	}
	return nil
}

func (s *DARelayState) addDACommitAttempt(peerQuotaKey string, commit *daRelayCommit, txBytesOwned *bool) (daRelaySetRecord, bool, error) {
	record, snapshot, complete, err := s.stageDACommitForCompletion(peerQuotaKey, commit, txBytesOwned)
	if err != nil || !complete {
		return record, false, err
	}
	return s.resolveDACommitCompletion(peerQuotaKey, commit, txBytesOwned, snapshot)
}

func (s *DARelayState) stageDACommitForCompletion(peerQuotaKey string, commit *daRelayCommit, txBytesOwned *bool) (daRelaySetRecord, daRelayCompletionSnapshot, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	record, ownedNow, err := s.stageDACommitRecordLocked(peerQuotaKey, *commit, *txBytesOwned)
	if err != nil {
		return daRelaySetRecord{}, daRelayCompletionSnapshot{}, false, err
	}
	updateDACommitTxBytes(commit, txBytesOwned, record, ownedNow)
	snapshot, complete := record.completionSnapshot()
	if complete {
		return record, snapshot, true, nil
	}
	if err := record.recomputeOrphanTotals(); err != nil {
		return daRelaySetRecord{}, daRelayCompletionSnapshot{}, false, err
	}
	if err := s.applyDASetRecordLocked(record); err != nil {
		return daRelaySetRecord{}, daRelayCompletionSnapshot{}, false, err
	}
	return record, snapshot, false, nil
}

func updateDACommitTxBytes(commit *daRelayCommit, txBytesOwned *bool, record daRelaySetRecord, ownedNow bool) {
	if !*txBytesOwned && ownedNow {
		commit.txBytes = record.commit.txBytes
		*txBytesOwned = true
	}
}

func (s *DARelayState) resolveDACommitCompletion(peerQuotaKey string, commit *daRelayCommit, txBytesOwned *bool, snapshot daRelayCompletionSnapshot) (daRelaySetRecord, bool, error) {
	payloadBytes, payloadCommitment := snapshot.payloadCommitment()
	if payloadCommitment == snapshot.payloadCommitmentExpected {
		return s.completeDACommitSnapshot(peerQuotaKey, commit, txBytesOwned, snapshot, payloadBytes)
	}
	// Commit metadata is the first-seen authority for duplicate handling;
	// orphan chunks are provisional until they match that commit.
	return s.rejectDACommitPayloadMismatch(peerQuotaKey, *commit, *txBytesOwned, snapshot)
}

func (s *DARelayState) rejectDACommitPayloadMismatch(peerQuotaKey string, commit daRelayCommit, txBytesOwned bool, snapshot daRelayCompletionSnapshot) (daRelaySetRecord, bool, error) {
	applied, err := s.stageCommitDroppingMatchingCompletionChunks(peerQuotaKey, commit, txBytesOwned, snapshot)
	if err != nil {
		return daRelaySetRecord{}, false, err
	}
	if !applied {
		return daRelaySetRecord{}, true, nil
	}
	return daRelaySetRecord{}, false, errDARelayPayloadCommitmentMismatch
}

func (s *DARelayState) completeDACommitSnapshot(peerQuotaKey string, commit *daRelayCommit, txBytesOwned *bool, snapshot daRelayCompletionSnapshot, payloadBytes uint64) (daRelaySetRecord, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	record, ownedNow, err := s.stageDACommitRecordLocked(peerQuotaKey, *commit, *txBytesOwned)
	if err != nil {
		return daRelaySetRecord{}, false, err
	}
	updateDACommitTxBytes(commit, txBytesOwned, record, ownedNow)
	if !snapshot.matchesRecord(record) {
		return daRelaySetRecord{}, true, nil
	}
	record.markComplete(payloadBytes)
	if err := record.recomputeOrphanTotals(); err != nil {
		return daRelaySetRecord{}, false, err
	}
	if err := s.checkDASetRecordCapsLocked(record); err != nil {
		return daRelaySetRecord{}, false, err
	}
	if !*txBytesOwned {
		record.cloneRetainedTxBytes()
		commit.txBytes = record.commit.txBytes
		*txBytesOwned = true
	}
	if err := s.applyDASetRecordLocked(record); err != nil {
		return daRelaySetRecord{}, false, err
	}
	return record, false, nil
}

func (s *DARelayState) addDAChunk(peerQuotaKey string, chunk daRelayChunk) error {
	payload, err := s.prepareDAChunk(chunk)
	if err != nil {
		return err
	}

	txBytesOwned := false
	for {
		_, retry, err := s.addDAChunkAttempt(peerQuotaKey, &chunk, payload, &txBytesOwned)
		if err != nil {
			return err
		}
		if retry {
			continue
		}
		return nil
	}
}

func (s *DARelayState) prepareDAChunk(chunk daRelayChunk) ([]byte, error) {
	if err := validateDAChunk(chunk); err != nil {
		return nil, err
	}
	if err := s.validateDAChunkInsert(chunk); err != nil {
		return nil, err
	}
	if !chunk.hashChecked && sha3.Sum256(chunk.payload) != chunk.chunkHash {
		return nil, errDARelayChunkHashMismatch
	}
	return cloneBytes(chunk.payload), nil
}

func (s *DARelayState) validateDAChunkInsert(chunk daRelayChunk) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sets[chunk.daID].validateChunkInsert(chunk.chunkIndex)
}

func (s *DARelayState) addDAChunkAttempt(peerQuotaKey string, chunk *daRelayChunk, payload []byte, txBytesOwned *bool) (daRelaySetRecord, bool, error) {
	record, snapshot, complete, err := s.stageDAChunkForCompletion(peerQuotaKey, chunk, payload, txBytesOwned)
	if err != nil || !complete {
		return record, false, err
	}
	return s.resolveDAChunkCompletion(peerQuotaKey, chunk, payload, txBytesOwned, snapshot)
}

func (s *DARelayState) stageDAChunkForCompletion(peerQuotaKey string, chunk *daRelayChunk, payload []byte, txBytesOwned *bool) (daRelaySetRecord, daRelayCompletionSnapshot, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	record, ownedNow, err := s.stageDAChunkRecordLocked(peerQuotaKey, *chunk, payload, *txBytesOwned)
	if err != nil {
		return daRelaySetRecord{}, daRelayCompletionSnapshot{}, false, err
	}
	updateDAChunkTxBytes(chunk, txBytesOwned, record, ownedNow)
	snapshot, complete := record.completionSnapshot()
	if complete {
		return record, snapshot, true, nil
	}
	if err := record.recomputeOrphanTotals(); err != nil {
		return daRelaySetRecord{}, daRelayCompletionSnapshot{}, false, err
	}
	if err := s.applyDASetRecordLocked(record); err != nil {
		return daRelaySetRecord{}, daRelayCompletionSnapshot{}, false, err
	}
	return record, snapshot, false, nil
}

func updateDAChunkTxBytes(chunk *daRelayChunk, txBytesOwned *bool, record daRelaySetRecord, ownedNow bool) {
	if !*txBytesOwned && ownedNow {
		chunk.txBytes = record.chunks[chunk.chunkIndex].txBytes
		*txBytesOwned = true
	}
}

func (s *DARelayState) resolveDAChunkCompletion(peerQuotaKey string, chunk *daRelayChunk, payload []byte, txBytesOwned *bool, snapshot daRelayCompletionSnapshot) (daRelaySetRecord, bool, error) {
	payloadBytes, payloadCommitment := snapshot.payloadCommitment()
	if payloadCommitment == snapshot.payloadCommitmentExpected {
		return s.completeDAChunkSnapshot(peerQuotaKey, chunk, payload, txBytesOwned, snapshot, payloadBytes)
	}
	return s.rejectDAChunkPayloadMismatch(snapshot)
}

func (s *DARelayState) rejectDAChunkPayloadMismatch(snapshot daRelayCompletionSnapshot) (daRelaySetRecord, bool, error) {
	retry, err := s.markMatchingCompletionChunksReplaceable(snapshot)
	if err != nil {
		return daRelaySetRecord{}, false, err
	}
	if retry {
		return daRelaySetRecord{}, true, nil
	}
	return daRelaySetRecord{}, false, errDARelayPayloadCommitmentMismatch
}

func (s *DARelayState) completeDAChunkSnapshot(peerQuotaKey string, chunk *daRelayChunk, payload []byte, txBytesOwned *bool, snapshot daRelayCompletionSnapshot, payloadBytes uint64) (daRelaySetRecord, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	record, ownedNow, err := s.stageDAChunkRecordLocked(peerQuotaKey, *chunk, payload, *txBytesOwned)
	if err != nil {
		return daRelaySetRecord{}, false, err
	}
	updateDAChunkTxBytes(chunk, txBytesOwned, record, ownedNow)
	if !snapshot.matchesRecord(record) {
		return daRelaySetRecord{}, true, nil
	}
	record.markComplete(payloadBytes)
	if err := record.recomputeOrphanTotals(); err != nil {
		return daRelaySetRecord{}, false, err
	}
	if err := s.checkDASetRecordCapsLocked(record); err != nil {
		return daRelaySetRecord{}, false, err
	}
	if !*txBytesOwned {
		record.cloneRetainedTxBytes()
		chunk.txBytes = record.chunks[chunk.chunkIndex].txBytes
		*txBytesOwned = true
	}
	if err := s.applyDASetRecordLocked(record); err != nil {
		return daRelaySetRecord{}, false, err
	}
	return record, false, nil
}

// txBytesOwned is only true for retrying a txBytes slice cloned by an earlier
// successful staging call; first admission still clones after duplicate checks.
func (s *DARelayState) stageDACommitRecordLocked(peerQuotaKey string, commit daRelayCommit, txBytesOwned bool) (daRelaySetRecord, bool, error) {
	record, stagedCommit, err := s.stageDACommitMetadataLocked(peerQuotaKey, commit)
	if err != nil {
		return daRelaySetRecord{}, false, err
	}
	return s.cloneStagedDACommitTxBytesLocked(record, stagedCommit, txBytesOwned)
}

func (s *DARelayState) stageDACommitMetadataLocked(peerQuotaKey string, commit daRelayCommit) (daRelaySetRecord, daRelayCommit, error) {
	record := s.sets[commit.daID].cloneForStateMutation()
	record.ensureMaps()
	if record.commit.chunkCount != 0 {
		return daRelaySetRecord{}, daRelayCommit{}, errDARelayDuplicateCommit
	}
	commit.peerQuotaKey = peerQuotaKey
	record.daID = commit.daID
	record.commit = commit
	record.pruneChunksOutsideCommit()
	record.state = daRelayStateStagedCommit
	record.ttlBlocksRemaining = s.caps.orphanTTLBlocks
	if err := s.assignFirstSeenReceivedTimeLocked(&record); err != nil {
		return daRelaySetRecord{}, daRelayCommit{}, err
	}
	return record, commit, nil
}

func (s *DARelayState) cloneStagedDACommitTxBytesLocked(record daRelaySetRecord, commit daRelayCommit, txBytesOwned bool) (daRelaySetRecord, bool, error) {
	if txBytesOwned || len(commit.txBytes) == 0 {
		return record, true, nil
	}
	if record.completeByShape() {
		return record, false, nil
	}
	if err := record.recomputeOrphanTotals(); err != nil {
		return daRelaySetRecord{}, false, err
	}
	if err := s.checkDASetRecordCapsLocked(record); err != nil {
		return daRelaySetRecord{}, false, err
	}
	commit.txBytes = cloneBytes(commit.txBytes)
	record.commit = commit
	return record, true, nil
}

// txBytesOwned follows the same ownership contract as stageDACommitRecordLocked.
func (s *DARelayState) stageDAChunkRecordLocked(peerQuotaKey string, chunk daRelayChunk, payload []byte, txBytesOwned bool) (daRelaySetRecord, bool, error) {
	record, stagedChunk, err := s.stageDAChunkMetadataLocked(peerQuotaKey, chunk, payload)
	if err != nil {
		return daRelaySetRecord{}, false, err
	}
	return s.cloneStagedDAChunkTxBytesLocked(record, stagedChunk, txBytesOwned)
}

func (s *DARelayState) stageDAChunkMetadataLocked(peerQuotaKey string, chunk daRelayChunk, payload []byte) (daRelaySetRecord, daRelayChunk, error) {
	record := s.sets[chunk.daID].cloneForStateMutation()
	record.ensureMaps()
	if err := record.validateChunkInsert(chunk.chunkIndex); err != nil {
		return daRelaySetRecord{}, daRelayChunk{}, err
	}
	chunk.peerQuotaKey = peerQuotaKey
	record.daID = chunk.daID
	if record.commit.chunkCount == 0 {
		record.state = daRelayStateOrphanChunks
		record.ttlBlocksRemaining = s.caps.orphanTTLBlocks
	}
	chunk.payload = payload
	record.chunks[chunk.chunkIndex] = chunk
	delete(record.replaceableChunks, chunk.chunkIndex)
	if err := s.assignFirstSeenReceivedTimeLocked(&record); err != nil {
		return daRelaySetRecord{}, daRelayChunk{}, err
	}
	return record, chunk, nil
}

func (s *DARelayState) cloneStagedDAChunkTxBytesLocked(record daRelaySetRecord, chunk daRelayChunk, txBytesOwned bool) (daRelaySetRecord, bool, error) {
	if txBytesOwned || len(chunk.txBytes) == 0 {
		return record, true, nil
	}
	if record.completeByShape() {
		return record, false, nil
	}
	if err := record.recomputeOrphanTotals(); err != nil {
		return daRelaySetRecord{}, false, err
	}
	if err := s.checkDASetRecordCapsLocked(record); err != nil {
		return daRelaySetRecord{}, false, err
	}
	chunk.txBytes = cloneBytes(chunk.txBytes)
	record.chunks[chunk.chunkIndex] = chunk
	return record, true, nil
}

func validateDAChunk(chunk daRelayChunk) error {
	if uint64(chunk.chunkIndex) >= consensus.MAX_DA_CHUNK_COUNT {
		return errDARelayChunkIndexOutOfRange
	}
	payloadLen := len(chunk.payload)
	if payloadLen == 0 || uint64(payloadLen) > consensus.CHUNK_BYTES {
		return errDARelayChunkPayloadSizeInvalid
	}
	if chunk.wireBytes == 0 || chunk.wireBytes < uint64(payloadLen) {
		return errDARelayWireBytesInvalid
	}
	return nil
}

func (s *DARelayState) applyDASetRecordLocked(record daRelaySetRecord) error {
	oldRecord := s.sets[record.daID]
	orphanBytes, peerBytes, daBytes, commitBytes, err := s.projectOrphanAccountingDeltaLocked(oldRecord, record)
	if err != nil {
		return err
	}
	pinnedBytes, err := s.projectPinnedPayloadDeltaLocked(oldRecord, record)
	if err != nil {
		return err
	}
	s.sets[record.daID] = record
	s.orphanBytes = orphanBytes
	s.applyProjectedPeerBytes(peerBytes)
	s.applyProjectedDAIDBytes(record.daID, daBytes)
	s.orphanCommitOverheadBytes = commitBytes
	s.pinnedPayloadBytes = pinnedBytes
	if record.receivedTime > s.nextReceivedTime {
		s.nextReceivedTime = record.receivedTime
	}
	return nil
}

func (s *DARelayState) checkDASetRecordCapsLocked(record daRelaySetRecord) error {
	oldRecord := s.sets[record.daID]
	if _, _, _, _, err := s.projectOrphanAccountingDeltaLocked(oldRecord, record); err != nil {
		return err
	}
	_, err := s.projectPinnedPayloadDeltaLocked(oldRecord, record)
	return err
}

func (s *DARelayState) removeDASetRecordLocked(record daRelaySetRecord) error {
	emptyRecord := daRelaySetRecord{daID: record.daID}
	orphanBytes, peerBytes, daBytes, commitBytes, err := s.projectOrphanAccountingDeltaLocked(record, emptyRecord)
	if err != nil {
		return err
	}
	pinnedBytes, err := s.projectPinnedPayloadDeltaLocked(record, emptyRecord)
	if err != nil {
		return err
	}
	delete(s.sets, record.daID)
	s.orphanBytes = orphanBytes
	s.applyProjectedPeerBytes(peerBytes)
	s.applyProjectedDAIDBytes(record.daID, daBytes)
	s.orphanCommitOverheadBytes = commitBytes
	s.pinnedPayloadBytes = pinnedBytes
	s.prefetch.releaseSet(record.daID)
	return nil
}

func (s *DARelayState) projectOrphanAccountingDeltaLocked(oldRecord, newRecord daRelaySetRecord) (uint64, map[string]uint64, uint64, uint64, error) {
	oldAccounting, err := oldRecord.orphanAccounting()
	if err != nil {
		return 0, nil, 0, 0, err
	}
	newAccounting, err := newRecord.orphanAccounting()
	if err != nil {
		return 0, nil, 0, 0, err
	}
	orphanBytes, err := checkedApplyUint64DeltaCap(s.orphanBytes, oldAccounting.orphanBytes, newAccounting.orphanBytes, s.caps.orphanPoolBytes, errDARelayOrphanPoolCapExceeded)
	if err != nil {
		return 0, nil, 0, 0, err
	}
	daBytes, err := checkedApplyUint64DeltaCap(s.orphanBytesByDAID[newRecord.daID], oldAccounting.orphanBytes, newAccounting.orphanBytes, s.caps.orphanPoolPerDAIDBytes, errDARelayOrphanDAIDCapExceeded)
	if err != nil {
		return 0, nil, 0, 0, err
	}
	commitBytes, err := checkedApplyUint64DeltaCap(s.orphanCommitOverheadBytes, oldAccounting.commitBytes, newAccounting.commitBytes, s.caps.orphanCommitOverheadBytes, errDARelayOrphanCommitCapExceeded)
	if err != nil {
		return 0, nil, 0, 0, err
	}
	peerBytes, err := s.projectPeerAccountingDeltaLocked(oldAccounting.peerBytes, newAccounting.peerBytes)
	if err != nil {
		return 0, nil, 0, 0, err
	}
	return orphanBytes, peerBytes, daBytes, commitBytes, nil
}

func (s *DARelayState) projectPinnedPayloadDeltaLocked(oldRecord, newRecord daRelaySetRecord) (uint64, error) {
	pinnedBytes, err := checkedApplyUint64Delta(s.pinnedPayloadBytes, oldRecord.pinnedPayloadAccountingBytes(), newRecord.pinnedPayloadAccountingBytes())
	if err != nil {
		return 0, err
	}
	if pinnedBytes > s.caps.pinnedPayloadBytes {
		return 0, errDARelayPinnedPayloadCapExceeded
	}
	return pinnedBytes, nil
}

func (s *DARelayState) projectPeerAccountingDeltaLocked(oldPeerBytes, newPeerBytes map[string]uint64) (map[string]uint64, error) {
	projected := map[string]uint64{}
	for key, oldBytes := range oldPeerBytes {
		value, err := checkedApplyUint64Delta(s.orphanBytesByPeerQuotaKey[key], oldBytes, newPeerBytes[key])
		if err != nil {
			return nil, err
		}
		if value > s.caps.orphanPoolPerPeerBytes {
			return nil, errDARelayOrphanPeerCapExceeded
		}
		projected[key] = value
	}
	for key, newBytes := range newPeerBytes {
		if _, seen := oldPeerBytes[key]; seen {
			continue
		}
		value, err := checkedApplyUint64Delta(s.orphanBytesByPeerQuotaKey[key], 0, newBytes)
		if err != nil {
			return nil, err
		}
		if value > s.caps.orphanPoolPerPeerBytes {
			return nil, errDARelayOrphanPeerCapExceeded
		}
		projected[key] = value
	}
	return projected, nil
}

func (s *DARelayState) applyProjectedPeerBytes(projected map[string]uint64) {
	for key, bytes := range projected {
		if bytes == 0 {
			delete(s.orphanBytesByPeerQuotaKey, key)
			continue
		}
		s.orphanBytesByPeerQuotaKey[key] = bytes
	}
}

func (s *DARelayState) applyProjectedDAIDBytes(daID [32]byte, bytes uint64) {
	if bytes == 0 {
		delete(s.orphanBytesByDAID, daID)
		return
	}
	s.orphanBytesByDAID[daID] = bytes
}
