package node

import (
	"bytes"
	"crypto/sha3"
	"maps"
	"slices"
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
	projected := s.cloneForAtomicBatchLocked()
	if err := projected.releasePeerQuotaKeyLocked(key); err != nil {
		return err
	}
	s.publishAtomicBatchLocked(projected)
	return nil
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
	peerBytes, err := s.projectPeerAccountingDeltaLocked(oldAccounting.peerBytes, newAccounting.peerBytes, s.caps.orphanPoolPerPeerBytes)
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

func (s *DARelayState) projectPeerAccountingDeltaLocked(oldPeerBytes, newPeerBytes map[string]uint64, capBytes uint64) (map[string]uint64, error) {
	projected := map[string]uint64{}
	for key, oldBytes := range oldPeerBytes {
		value, err := checkedApplyUint64Delta(s.orphanBytesByPeerQuotaKey[key], oldBytes, newPeerBytes[key])
		if err != nil {
			return nil, err
		}
		if value > capBytes {
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
		if value > capBytes {
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

// daRelayRecordPlacement holds ABSOLUTE counter values, not deltas.
type daRelayRecordPlacement struct {
	daID        [32]byte
	record      daRelaySetRecord
	remove      bool
	retire      []daRelayLocatorRow
	install     []daRelayLocatorRow
	orphanBytes uint64
	peerBytes   map[string]uint64
	daBytes     uint64
	commitBytes uint64
}

// projectDARecordImageLocked is the FALLIBLE half: it owns EVERY check and mutates
// nothing on any path, so a refused image leaves live state byte-identical. A
// doubly-violating image selects by STAGE: incompatible live record, stale image,
// unusable candidate, locator row, global/per-DA/commit/peer accounting, then
// exhausted revision space (RUBIN_COMPACT_BLOCKS.md 18.2, 18.3). Within the peer arm,
// map order can select the first sentinel when keys violate different checks (overflow or peer cap).
func (s *DARelayState) projectDARecordImageLocked(image daRelayRecordImage) (daRelayRecordPlacement, error) {
	live, err := s.checkDARecordImageBaselineLocked(image)
	if err != nil {
		return daRelayRecordPlacement{}, err
	}
	return s.projectDARecordImageLiveLocked(image, live, s.caps)
}

func (s *DARelayState) projectDARecordImageLiveLocked(image daRelayRecordImage, live daRelaySetRecord, caps daRelayCaps) (daRelayRecordPlacement, error) {
	retire, install, err := s.checkDARecordImageLocatorsLocked(image, live)
	if err != nil {
		return daRelayRecordPlacement{}, err
	}
	placement, err := s.projectDARecordImageCountersLocked(image, live, caps)
	if err != nil {
		return daRelayRecordPlacement{}, err
	}
	placement.retire, placement.install = retire, install
	if !image.remove {
		revision, revisionErr := checkedAddUint64(s.records, 1)
		if revisionErr != nil {
			return daRelayRecordPlacement{}, revisionErr
		}
		placement.record = image.next.cloneOwnerReady()
		placement.record.revision = revision
	}
	return placement, nil
}

// checkDARecordImageBaselineLocked takes residency from the s.sets lookup alone, never
// from the record. Absent means revision 0 and baseline 0, so one comparison does both.
func (s *DARelayState) checkDARecordImageBaselineLocked(image daRelayRecordImage) (daRelaySetRecord, error) {
	live, resident := s.sets[image.daID]
	if resident && (live.revision == 0 || len(live.locatorRows()) == 0 || live.checkOwnerReadyRecord() != nil) {
		return daRelaySetRecord{}, errDARelayImageIncompatible
	}
	if resident != image.present || live.revision != image.baseline {
		return daRelaySetRecord{}, errDARelayRecordStale
	}
	if image.admission {
		return live, checkStagedDANonReplayRecord(image, live, s.caps.orphanTTLBlocks)
	}
	return live, checkStagedOwnerReadyRecord(image, live)
}

// checkStagedOwnerReadyRecord makes image.next the placement's AUTHORITY: it names
// its own da_id, holds the candidate at the named slot field for field and every
// other live slot byte-identically. Reading only the parallel descriptor would leave
// the record installDASetRecordLocked actually publishes unchecked.
func checkStagedOwnerReadyRecord(image daRelayRecordImage, live daRelaySetRecord) error {
	rows := image.next.locatorRows()
	// Removal requires zero retained member/locator rows; non-removal requires rows.
	// The record is not installed, but residual chunk entries still reach accounting below.
	if image.remove != (len(rows) == 0) {
		return errDARelayMemberIncomplete
	}
	if image.remove {
		return nil
	}
	if image.next.daID != image.daID {
		return errDARelayImageIncompatible
	}
	if err := image.member.validate(); err != nil {
		return err
	}
	if err := checkOwnerReadySlotFree(live, image.member.locator); err != nil {
		return err
	}
	if err := image.next.checkOwnerReadyRecord(); err != nil {
		return err
	}
	if err := checkStagedCandidateSlot(image.next, rows, image.member); err != nil {
		return err
	}
	return checkPreservedOwnerReadySlots(live, image.next, image.member.locator)
}

func checkStagedDANonReplayRecord(image daRelayRecordImage, live daRelaySetRecord, ttl uint64) error {
	if image.remove {
		return errDARelayImageIncompatible
	}
	if err := image.member.validate(); err != nil {
		return err
	}
	slotErr := checkOwnerReadySlotFree(live, image.member.locator)
	if image.member.locator.kind == daRelayLocatorChunk {
		slotErr = live.validateChunkInsert(image.member.locator.chunkIndex)
	}
	if slotErr != nil {
		return slotErr
	}
	if err := image.next.checkDANonReplayShape(); err != nil {
		return err
	}
	if err := checkDANonReplayRecordFields(image, live, ttl); err != nil {
		return err
	}
	if image.member.locator.kind == daRelayLocatorCommit {
		return checkDANonReplayCommitSlot(image, live)
	}
	return checkDANonReplayChunkSlot(image, live)
}

func checkDANonReplayRecordFields(image daRelayRecordImage, live daRelaySetRecord, ttl uint64) error {
	next := image.next
	if err := checkStagedCandidateSlot(next, next.locatorRows(), image.member); err != nil {
		return err
	}
	type fixed struct{ revision, receivedTime, payloadBytes, wireBytes uint64 }
	if (fixed{next.revision, next.receivedTime, next.payloadBytes, next.wireBytes}) !=
		(fixed{live.revision, live.receivedTime, live.payloadBytes, live.wireBytes}) || !maps.Equal(next.replaceableChunks, live.replaceableChunks) {
		return errDARelayImageIncompatible
	}
	wantState, wantTTL := live.state, live.ttlBlocksRemaining
	if image.member.locator.kind == daRelayLocatorCommit {
		wantState, wantTTL = daRelayStateStagedCommit, ttl
	}
	if !image.present && image.member.locator.kind == daRelayLocatorChunk {
		wantState, wantTTL = daRelayStateOrphanChunks, ttl
	}
	if [2]uint64{uint64(next.state), next.ttlBlocksRemaining} != [2]uint64{uint64(wantState), wantTTL} {
		return errDARelayImageIncompatible
	}
	return nil
}

func checkDANonReplayCommitSlot(image daRelayRecordImage, live daRelaySetRecord) error {
	if image.admissionChunkCount == 0 || uint64(image.admissionChunkCount) > consensus.MAX_DA_CHUNK_COUNT {
		return errDARelayImageIncompatible
	}
	commit := image.next.commit
	type residual struct {
		commitment, chunkHash [32]byte
		chunkCount            uint16
		quotaKey              string
		wireBytes             uint64
	}
	if (residual{commit.payloadCommitment, image.admissionChunkHash, commit.chunkCount, commit.peerQuotaKey, commit.wireBytes}) !=
		(residual{commitment: image.admissionPayloadCommitment, chunkCount: image.admissionChunkCount}) {
		return errDARelayImageIncompatible
	}
	return checkDANonReplayCommitChunks(live, image.next, image.admissionChunkCount)
}

func checkDANonReplayChunkSlot(image daRelayRecordImage, live daRelaySetRecord) error {
	chunk := image.next.chunks[image.member.locator.chunkIndex]
	type residual struct {
		commitment, chunkHash [32]byte
		chunkCount            uint16
		quotaKey              string
		wireBytes             uint64
		hashChecked           bool
	}
	if (residual{image.admissionPayloadCommitment, chunk.chunkHash, image.admissionChunkCount, chunk.peerQuotaKey, chunk.wireBytes, chunk.hashChecked}) !=
		(residual{chunkHash: image.admissionChunkHash}) {
		return errDARelayImageIncompatible
	}
	if !sameOwnerReadyCommit(live.commit, image.next.commit) {
		return errDARelayImageIncompatible
	}
	return checkDANonReplayChunkAddition(live, image.next, image.member.locator.chunkIndex)
}

func checkDANonReplayCommitChunks(live, next daRelaySetRecord, count uint16) error {
	kept := 0
	for index, chunk := range live.chunks {
		staged, present := next.chunks[index]
		if index >= count {
			if present {
				return errDARelayImageIncompatible
			}
			continue
		}
		kept++
		if !present || !sameOwnerReadyChunk(chunk, staged) {
			return errDARelayImageIncompatible
		}
	}
	if len(next.chunks) != kept {
		return errDARelayImageIncompatible
	}
	return nil
}

func checkDANonReplayChunkAddition(live, next daRelaySetRecord, target uint16) error {
	if len(next.chunks) != len(live.chunks)+1 {
		return errDARelayImageIncompatible
	}
	for index, chunk := range next.chunks {
		if index != target && !sameOwnerReadyChunk(live.chunks[index], chunk) {
			return errDARelayImageIncompatible
		}
	}
	return nil
}

func checkDANonReplayVictims(image daRelayRecordImage, live daRelaySetRecord, victims []DAAdmissionVictim) error {
	next := 0
	for _, index := range sortedRetainedDAChunkIndexes(live) {
		if _, preserved := image.next.chunks[index]; preserved {
			continue
		}
		if next == len(victims) {
			return errDARelayImageIncompatible
		}
		member, victim := live.chunks[index].member, victims[next]
		if member == nil || [2]any{victim.TxID, victim.Token} != [2]any{member.txid, member.token} || !slices.Equal(victim.Inputs, member.inputs) {
			return errDARelayImageIncompatible
		}
		next++
	}
	if next != len(victims) {
		return errDARelayImageIncompatible
	}
	return nil
}

// checkStagedCandidateSlot binds the ONE slot image.member.locator names to the
// descriptor across every field the descriptor carries. The locator ROW settles
// da_id, kind, index and txid together, because locatorRows derives each of them
// from the staged record itself; the remaining fields are compared one by one.
func checkStagedCandidateSlot(next daRelaySetRecord, rows []daRelayLocatorRow, candidate daRelayOwnerReadyMember) error {
	staged, txBytes, payload := next.commit.member, next.commit.txBytes, []byte(nil)
	if candidate.locator.kind == daRelayLocatorChunk {
		chunk := next.chunks[candidate.locator.chunkIndex]
		staged, txBytes, payload = chunk.member, chunk.txBytes, chunk.payload
	}
	if staged == nil {
		return errDARelayMemberIncomplete
	}
	if !slices.Contains(rows, daRelayLocatorRow{txid: candidate.member.txid, locator: candidate.locator}) ||
		!sameOwnerReadyMember(staged, &candidate.member) ||
		!bytes.Equal(txBytes, candidate.txBytes) ||
		!bytes.Equal(payload, candidate.payload) {
		return errDARelayImageIncompatible
	}
	return nil
}

// checkPreservedOwnerReadySlots and its three helpers prove every live slot AND the
// record's own five fields survive BYTE-IDENTICALLY. A locator row carries only txid and
// position, so a swapped fee, token, provenance, payload commitment or cached legacy key
// passes it unseen. da_id and wireBytes are pinned above and revision is REMINTED whatever
// the image carries, so the five complete the record. checkOwnerReadyRecord admits BOTH
// OrphanChunks and StagedCommit, so only the state equality stops a resident image
// switching between them; the other four move no counter at INSTALL, but the installed
// record LIVES in s.sets, where missingChunkIndexes and validateChunkInsert read
// replaceableChunks and the TTL sweep decrements ttlBlocksRemaining. Staging copies all five.
func checkPreservedOwnerReadySlots(live, next daRelaySetRecord, target daRelayLocator) error {
	if !samePreservedRecordFields(live, next) {
		return errDARelayImageIncompatible
	}
	if err := checkPreservedCommitSlot(live, next, target); err != nil {
		return err
	}
	return checkPreservedChunkSlots(live, next, target)
}

func samePreservedRecordFields(live, next daRelaySetRecord) bool {
	return live.state == next.state && live.payloadBytes == next.payloadBytes &&
		live.receivedTime == next.receivedTime &&
		live.ttlBlocksRemaining == next.ttlBlocksRemaining &&
		(live.replaceableChunks == nil) == (next.replaceableChunks == nil) &&
		maps.Equal(live.replaceableChunks, next.replaceableChunks)
}

// A chunk target must leave the whole commit alone, and the chunk it freshly stages may
// carry none of the three legacy fields this kernel never assigns. A commit candidate owns
// da_id, member and txBytes and wireBytes is pinned, so the residual three complete the seven.
func checkPreservedCommitSlot(live, next daRelaySetRecord, target daRelayLocator) error {
	if target.kind != daRelayLocatorChunk {
		type residual struct {
			commitment [32]byte
			quotaKey   string
			chunkCount uint16
		}
		a := residual{live.commit.payloadCommitment, live.commit.peerQuotaKey, live.commit.chunkCount}
		if a != (residual{next.commit.payloadCommitment, next.commit.peerQuotaKey, next.commit.chunkCount}) {
			return errDARelayImageIncompatible
		}
		return nil
	}
	if fresh := next.chunks[target.chunkIndex]; fresh.chunkHash != ([32]byte{}) || fresh.peerQuotaKey != "" || fresh.hashChecked {
		return errDARelayImageIncompatible
	}
	if !sameOwnerReadyCommit(live.commit, next.commit) {
		return errDARelayImageIncompatible
	}
	return nil
}

// checkOwnerReadySlotFree already proved the target slot free in live, so exactly one
// chunk may appear under a chunk target and none under a commit target; in neither may a
// live one be dropped. The walk is map-ordered but yields ONE error identity, so order-immune.
func checkPreservedChunkSlots(live, next daRelaySetRecord, target daRelayLocator) error {
	staged := len(live.chunks)
	if target.kind == daRelayLocatorChunk {
		staged++
	}
	if len(next.chunks) != staged {
		return errDARelayImageIncompatible
	}
	for index, chunk := range next.chunks {
		if target.kind == daRelayLocatorChunk && index == target.chunkIndex {
			continue
		}
		if !sameOwnerReadyChunk(live.chunks[index], chunk) {
			return errDARelayImageIncompatible
		}
	}
	return nil
}

// The three comparisons below name EVERY field of their type: none is comparable with
// ==, and a field left out is one an edited image may change unseen.
func sameOwnerReadyCommit(a, b daRelayCommit) bool {
	return a.daID == b.daID && a.payloadCommitment == b.payloadCommitment &&
		a.peerQuotaKey == b.peerQuotaKey && a.chunkCount == b.chunkCount &&
		a.wireBytes == b.wireBytes && bytes.Equal(a.txBytes, b.txBytes) &&
		sameOwnerReadyMember(a.member, b.member)
}

func sameOwnerReadyChunk(a, b daRelayChunk) bool {
	return [2][32]byte{a.daID, a.chunkHash} == [2][32]byte{b.daID, b.chunkHash} &&
		a.peerQuotaKey == b.peerQuotaKey && a.chunkIndex == b.chunkIndex &&
		a.wireBytes == b.wireBytes && a.hashChecked == b.hashChecked &&
		bytes.Equal(a.payload, b.payload) && bytes.Equal(a.txBytes, b.txBytes) &&
		sameOwnerReadyMember(a.member, b.member)
}

func sameOwnerReadyMember(a, b *daRelayMemberIdentity) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.txid == b.txid && a.wtxid == b.wtxid && a.fee == b.fee &&
		a.token == b.token && a.provenance == b.provenance &&
		slices.Equal(a.inputs, b.inputs)
}

// checkDARecordImageLocatorsLocked proves the txid index and the retained image are one
// bijection (Section 18.3). A nil index is refused: the installer does not construct missing state.
func (s *DARelayState) checkDARecordImageLocatorsLocked(image daRelayRecordImage, live daRelaySetRecord) ([]daRelayLocatorRow, []daRelayLocatorRow, error) {
	if s.locators == nil {
		return nil, nil, errDARelayImageIncompatible
	}
	retire := live.locatorRows()
	install := image.next.locatorRows()
	if err := s.checkRetiredLocatorRowsLocked(image.daID, retire); err != nil {
		return nil, nil, err
	}
	return retire, install, s.checkDAInstallLocatorRowsLocked(image.daID, install)
}

// checkOwnerReadySlotFree is FIRST-SEEN over the ONE slot image.member.locator names:
// staging overwrites it, so without this a second member would evict the retained one and
// move its charge to the new provenance. Both arms are stricter than the legacy guard; the
// chunk-count range arm is RUB-1273's, not here.
func checkOwnerReadySlotFree(live daRelaySetRecord, locator daRelayLocator) error {
	if locator.kind == daRelayLocatorCommit {
		if live.commit.member != nil {
			return errDARelayDuplicateCommit
		}
		return nil
	}
	if _, occupied := live.chunks[locator.chunkIndex]; occupied {
		return errDARelayDuplicateChunk
	}
	return nil
}

func (s *DARelayState) checkRetiredLocatorRowsLocked(daID [32]byte, retire []daRelayLocatorRow) error {
	retired := make(map[[32]byte]bool, len(retire))
	for _, row := range retire {
		if s.locators[row.txid] != row.locator {
			return errDARelayLocatorMismatch
		}
		retired[row.txid] = true
	}
	for txid, locator := range s.locators {
		if locator.daID == daID && !retired[txid] {
			return errDARelayLocatorMismatch
		}
	}
	return nil
}

func (s *DARelayState) checkDAInstallLocatorRowsLocked(daID [32]byte, install []daRelayLocatorRow) error {
	claimed := make(map[[32]byte]bool, len(install))
	// Every row names daID: locatorRows stamps image.next.daID, and every installer pins
	// next.daID == image.daID — checkStagedOwnerReadyRecord and checkOwnerReadyRemovalSurvivor
	// directly, the admission installer checkStagedDANonReplayRecord transitively, through
	// checkStagedCandidateSlot's row membership over the image.member.locator that
	// stageDAOwnerReadyMember (da_relay_record.go) made image.daID.
	for _, row := range install {
		if claimed[row.txid] {
			return errDARelayLocatorMismatch
		}
		if other, indexed := s.locators[row.txid]; indexed && other.daID != daID {
			return errDARelayLocatorMismatch
		}
		claimed[row.txid] = true
	}
	return nil
}

func (s *DARelayState) projectDARecordImageCountersLocked(image daRelayRecordImage, live daRelaySetRecord, caps daRelayCaps) (daRelayRecordPlacement, error) {
	oldAccounting, err := live.ownerReadyAccounting()
	if err != nil {
		return daRelayRecordPlacement{}, err
	}
	newAccounting, err := image.next.ownerReadyAccounting()
	if err != nil {
		return daRelayRecordPlacement{}, err
	}
	placement := daRelayRecordPlacement{daID: image.daID, remove: image.remove}
	if placement.orphanBytes, err = checkedApplyUint64DeltaCap(s.orphanBytes, oldAccounting.orphanBytes, newAccounting.orphanBytes, caps.orphanPoolBytes, errDARelayOrphanPoolCapExceeded); err != nil {
		return daRelayRecordPlacement{}, err
	}
	if placement.daBytes, err = checkedApplyUint64DeltaCap(s.orphanBytesByDAID[image.daID], oldAccounting.orphanBytes, newAccounting.orphanBytes, caps.orphanPoolPerDAIDBytes, errDARelayOrphanDAIDCapExceeded); err != nil {
		return daRelayRecordPlacement{}, err
	}
	if placement.commitBytes, err = checkedApplyUint64DeltaCap(s.orphanCommitOverheadBytes, oldAccounting.commitBytes, newAccounting.commitBytes, caps.orphanCommitOverheadBytes, errDARelayOrphanCommitCapExceeded); err != nil {
		return daRelayRecordPlacement{}, err
	}
	placement.peerBytes, err = s.projectPeerAccountingDeltaLocked(oldAccounting.peerBytes, newAccounting.peerBytes, caps.orphanPoolPerPeerBytes)
	return placement, err
}

// installDASetRecordLocked PERFORMS NO VALIDATION: every check ran in
// projectDARecordImageLocked, so a caller may run it after an owner reserve.
//
// PRECONDITION, the caller's to keep: a placement is SINGLE-USE — ONE projection, ONE
// installation, one continuous hold. Two placements projected before either installs
// carry the same minted revision; nothing here detects that, by design.
//
// Three steps the sibling installers take are skipped: the pinned-payload counter prices only a
// COMPLETE_SET, a state the projector refuses, so it stays 0-to-0; RUB-1287 checks the admission
// sequence and revision high-water; and every remove: true caller releases the removed record's
// prefetch reservation itself.
func (s *DARelayState) installDASetRecordLocked(placement daRelayRecordPlacement) {
	for _, row := range placement.retire {
		delete(s.locators, row.txid)
	}
	if placement.remove {
		delete(s.sets, placement.daID)
	} else {
		s.sets[placement.daID] = placement.record
		s.records = placement.record.revision
	}
	for _, row := range placement.install {
		s.locators[row.txid] = row.locator
	}
	s.orphanBytes = placement.orphanBytes
	s.applyProjectedPeerBytes(placement.peerBytes)
	s.applyProjectedDAIDBytes(placement.daID, placement.daBytes)
	s.orphanCommitOverheadBytes = placement.commitBytes
}

// releaseOwnerReadyPeerQuota is the DORMANT owner-aware PEER quota cleanup selector
// (RUBIN_COMPACT_BLOCKS.md 18.1, Section 5 State B). It matches retained members on typed
// provenance, never the cached peerQuotaKey and never orphanBytesByPeerQuotaKey. Postconditions:
// a matching commit survives iff a LOCAL or DETACHED_REORG member is retained, keeping its
// accounting charge and its owner claim; an unblocked whole-record removal also carries every
// non-matching PEER member; State B never downgrades to State A
// (releaseOwnerReadyPeerRecordLocked); an empty quota identity selects nothing. It returns
// commitOwnerReadyRemoval's error classes unwrapped. This entrypoint has zero non-test callers
// until issue 678.
func (s *DARelayState) releaseOwnerReadyPeerQuota(quotaIdentity string) error {
	return s.commitOwnerReadyRemoval(func(clone *DARelayState) ([]DAAdmissionVictim, error) {
		return ownerReadyPeerRemovalVictims(clone, quotaIdentity)
	})
}

// advanceOwnerReadyTTL is the DORMANT owner-aware TTL tick selector: each incomplete
// owner-ready record with ttl greater than one decrements once and mints one fresh
// revision, ttl one expires as a whole-record removal with no revision, and a resident
// ttl of zero fails closed before any arithmetic. It returns commitOwnerReadyRemoval's error
// classes unwrapped. This entrypoint has zero non-test callers until issue 678.
func (s *DARelayState) advanceOwnerReadyTTL() error {
	return s.commitOwnerReadyRemoval(ownerReadyTTLTickVictims)
}

// commitOwnerReadyRemoval runs one owner-atomic incomplete-record removal batch. It clones
// the retained image under the existing admission fence and DARelayState.mu, lets
// selectVictims derive every exact per-record transition and the bound-owner victim tokens on
// that clone, and then binds the relay. TWO of the three arms mirror BeginDARemoval
// (da_admission.go): a nil chainState and a nil pending-outpoint owner are its exact refusals. The
// third does not — BeginDARemoval refuses a nil mempool as well, while here a nil mempool publishes
// the DA image as the whole change. The ground is REACH, not existence: s.mempool is the relay's
// only path to pendingOutpoints, so an unbound relay reaches no claim domain, and the arm keeps the
// unfenced behavior lockAdmissionFence already gives it (da_relay_state.go). It does NOT say that
// no claim domain exists — the paired row builds a live owner this relay cannot see and asserts it
// untouched. Where a domain IS reachable but unusable, a nil chainState, the arm refuses instead,
// because publishing there would strand claims the relay can see. Any other relay publishes under
// its claim domain, a batch that releases no member taking the same arm as one that does. Any
// error before publication leaves both complete images unchanged.
//
// ERROR CLASSES a caller receives, for RUB-678's removal_error_class_taxonomy to sort into latch
// and transient. The callees define the set — every sentinel any of them can return is a possible
// value — and both groups below classify all of it, so a dead family is named, not omitted.
// REACHABLE: errDARelayImageIncompatible (candidate gate, stored scalars, survivor baseline,
// retained binding, live claim), errDARelayArithmeticOverflow (revision or accounting),
// *canonicalDATerminalError (retained parse/bind, map-key, locator bijection, accounting closure)
// and *TxAdmitError (nil chainstate, nil owner, victim refusal).
// STATICALLY PRESENT AND DEAD: errDARelayLocatorMismatch — the preflight's bijection already pins
// every row of every candidate; errDARelayRecordStale — the whole-record arm mints its image from
// the same s.sets read checkDARecordImageBaselineLocked repeats; the four orphan cap sentinels —
// ownerReadyRemovalCaps lifts every cap they guard to the uint64 maximum; and
// checkOwnerReadyRecord's own family (errDARelayMemberIncomplete, errDARelayChunkIndexOutOfRange,
// errDARelayChunkPayloadSizeInvalid, errDAProvenanceInvalid) — only checkOwnerReadyRemovalSurvivor
// propagates it, over a byte-identical submultiset of a record the candidate gate already passed
// through that same predicate.
// Postcondition: this path only RETURNS them; it reads and sets no latch of its own.
//
// FENCE OWNERSHIP for the issue-678 wiring: this body takes lockAdmissionFence ITSELF, where every
// merged sibling takes it in the exported wrapper. sync.RWMutex is not reentrant, so the wrapper that
// swaps to this path must DROP its own deferred fence and keep the nil-receiver arm
// ReleasePeerQuotaKey pins today (da_relay_state.go).
func (s *DARelayState) commitOwnerReadyRemoval(selectVictims func(*DARelayState) ([]DAAdmissionVictim, error)) error {
	release := s.lockAdmissionFence()
	defer release()
	s.mu.Lock()
	defer s.mu.Unlock()

	clone := s.cloneForAtomicBatchLocked()
	victims, err := selectVictims(clone)
	if err != nil {
		return err
	}
	if s.mempool == nil {
		s.publishAtomicBatchLocked(clone) // truly unbound: the DA image is the whole change
		return nil
	}
	if s.mempool.chainState == nil {
		return txAdmitUnavailable("nil chainstate")
	}
	owner := s.mempool.pendingOutpoints
	if owner == nil {
		return txAdmitUnavailable("nil pending-outpoint owner")
	}
	return s.commitOwnerReadyRemovalClaimsLocked(owner, clone, victims)
}

// commitOwnerReadyRemovalClaimsLocked validates the victim batch and the retained image's owner
// binding and, only on success, publishes the DA image and drops every victim claim under one
// owner-lock hold. An empty batch takes the same route, so a member-preserving decrement is
// proven owner-bound before it republishes. Nothing fallible runs after the DA publish, so a
// record and its claim cannot become observably separated.
//
// The binding proof's clone-only half is materialized BEFORE the hold, as the owner's lock contract
// requires of every caller (pending_outpoint_owner.go) and as BeginCommit does with
// prepareDAAdmissionVictims (da_admission.go); its error is carried past the victim preflight and
// the live claim walk, so the first refusal stays the one the single-span proof returned.
// Postcondition: nothing between owner.mu.Lock() and owner.mu.Unlock() allocates, on ANY path.
// The hold is released EXPLICITLY, never by defer, and the victim refusal is mapped AFTER that
// release: the shape both BeginCommit bodies use on their refusal path (da_admission.go). Here
// EVERY return releases, which is where the parity stops — a BeginCommit hands a live hold to
// its DACommit on success, and this body owns the whole hold.
// The refusal descriptor is DECLARED above the lock for the same reason: &failure escapes, so
// its heap cell is taken off-lock. No deferred unlock guards this body, so a return added under
// the hold leaks owner.mu; the statement-order guard in da_relay_owner_test.go reddens on that.
func (s *DARelayState) commitOwnerReadyRemovalClaimsLocked(owner *PendingOutpointOwner, clone *DARelayState, victims []DAAdmissionVictim) error {
	var batch []DAAdmissionVictim
	if len(victims) != 0 {
		var err error
		if batch, err = prepareDAAdmissionVictims(victims, [32]byte{}); err != nil {
			return txAdmitFromPendingOutpointError(err)
		}
	}
	members, bindErr := ownerReadyRetainedBindingMembers(clone, owner, batch)
	var failure PendingOutpointError
	var failed bool
	owner.mu.Lock()
	if failure, failed = owner.validateDAAdmissionVictimsLocked(batch, PendingOutpointToken{}); failed {
		owner.mu.Unlock()
		return txAdmitFromPendingOutpointError(&failure)
	}
	if err := checkOwnerReadyMemberClaimsLocked(owner, members); err != nil {
		owner.mu.Unlock()
		return err
	}
	if bindErr != nil {
		owner.mu.Unlock()
		return bindErr
	}
	s.publishAtomicBatchLocked(clone)
	for _, victim := range batch {
		owner.dropClaimLocked(victim.Token)
	}
	owner.mu.Unlock()
	return nil
}

// ownerReadyRetainedBindingMembers is the clone-only half of the proof that the clone is publishable
// under owner: every retained member carries a nonzero token owned by owner (checkDANonReplayTokens,
// a pointer and sequence compare that reads no owner map), no token appears twice anywhere in the
// image, and no token in batch still belongs to a member the clone RETAINS. It reads nothing behind
// owner.mu, so the caller runs it before the hold and every allocation of the proof happens here.
//
// It returns the members whose live claim the single-span proof had already checked when it stopped:
// the prefix the record walk had reached when it refused, the whole image otherwise. The da_id walk
// ascends and within a record the order is locatorRows order, so one image still yields one error,
// and checking those members under the hold before returning this error yields the exact error the
// unsplit proof returned.
//
// The closing batch-versus-retained comparison is a fail-closed backstop the alias row executes:
// the preflight's bijection (canonicalDARecordLocatorsIndexed) keys by txid and cannot see a
// token two members share, so that image lands here as errDARelayImageIncompatible. The live
// claim proof returns that sentinel first under the hold, so deleting this arm reddens no row.
func ownerReadyRetainedBindingMembers(clone *DARelayState, owner *PendingOutpointOwner, batch []DAAdmissionVictim) ([]*daRelayMemberIdentity, error) {
	image := make([]*daRelayMemberIdentity, 0, len(clone.locators))
	retained := make(map[PendingOutpointToken]struct{}, len(clone.locators))
	for _, daID := range clone.sortedRetainedDAIDsLocked() {
		members, err := ownerReadyRecordMembers(clone.sets[daID], owner, retained)
		image = append(image, members...)
		if err != nil {
			return image, err
		}
	}
	for _, victim := range batch {
		if _, held := retained[victim.Token]; held {
			return image, errDARelayImageIncompatible
		}
	}
	return image, nil
}

// ownerReadyRecordMembers proves one record's clone-only binding and adds its members' tokens to
// seen, refusing a memberless occupied slot or the first token seen twice. It returns the members
// the caller must still bind to a live claim, and on the aliased-token refusal only the prefix
// before the offending member, whose claims the unsplit proof had already checked.
func ownerReadyRecordMembers(record daRelaySetRecord, owner *PendingOutpointOwner, seen map[PendingOutpointToken]struct{}) ([]*daRelayMemberIdentity, error) {
	if err := record.checkDANonReplayTokens(owner); err != nil {
		return nil, err
	}
	members, err := canonicalDARetainedMemberIdentities(record)
	if err != nil {
		return nil, err
	}
	for i, member := range members {
		if _, alias := seen[member.token]; alias {
			return members[:i], errDARelayImageIncompatible
		}
		seen[member.token] = struct{}{}
	}
	return members, nil
}

// checkOwnerReadyMemberClaimsLocked is the live half: every prepared member must resolve a LIVE
// owner claim that describes it — DA domain, txid, ordered inputs and finalized — through
// canonicalDAClaimBindsMember, the canonical builder's own phase-5 predicate (sync_da_relay.go),
// over the owner's byToken index. That index is the single input the proof cannot read off-lock,
// which is why this half alone runs under the owner mutex. It allocates nothing.
func checkOwnerReadyMemberClaimsLocked(owner *PendingOutpointOwner, members []*daRelayMemberIdentity) error {
	for _, member := range members {
		claim := owner.byToken[member.token]
		if claim == nil || !canonicalDAClaimBindsMember(*claim, member) {
			return errDARelayImageIncompatible
		}
	}
	return nil
}

// ownerReadyRemovalCandidatesLocked returns the owner-ready da_ids the PEER and TTL selectors
// consider, ascending, after a fail-closed whole-image preflight. Records — never the cached
// orphanBytesByDAID total — are the selection authority (R4). Every retained record is a candidate:
// checkOwnerReadyRetainedRecordLocked refuses a whole image carrying a COMPLETE_SET, so no record
// reaching the preflight is one, and A5's "State C is never selected" holds trivially.
// COMPLETE_SET is only the named case: that same per-record gate makes ANY resident non-owner-ready
// record terminal for the WHOLE image on BOTH selectors until it leaves. A legacy-staged record is
// the reachable instance — zero revision, no locator rows, and a chunk carrying nonzero wireBytes
// with a nil member identity (the last two refused by checkOwnerReadyChunk) — so a relay still
// holding legacy bytes can neither tick nor release. RUB-678 owns that ordering before it wires
// either selector beside the still-exported legacy writers.
//
// The per-candidate shape gate is checkDANonReplayShape, the predicate
// validateCanonicalDARetainedSnapshot applies to every retained record — not the weaker
// checkOwnerReadyRecord it wraps. The TTL and receivedTime bounds it does not read are applied by
// ownerReadyRemovalGateFails, and the preflight is unconditional.
//
// The preflight IS canonicalDARetainedImageClosed (sync_da_relay_validate.go), the canonical
// builder's own phase-3 closure, CALLED over the whole retained set rather than restated: the
// COMPLETE_SET refusal above leaves every record reaching it incomplete, which is what lets that
// closure's state-agnostic ownerReadyAccounting bill each one exactly. Postcondition inherited
// with the call: the first defect is RECORD-major in ascending da_id, so one record's locator
// bijection and its accounting are both decided before the next record is read.
//
// Cost, under BOTH the admission fence and DARelayState.mu, per peer release and per TTL tick.
// The preflight walks every retained record's bytes once through consensus.ParseTx, plus one
// SHA3-256 and one payload equality per incomplete chunk and one re-scan of each commit's outputs,
// on top of the shallow image clone. Selection walks each SURVIVING record's bytes three times
// more: cloneOwnerReady in dropOwnerReadyChunksLocked, checkOwnerReadyRemovalSurvivor's
// byte-equality of that clone against its source (a tautology on the TTL arm), and a second
// cloneOwnerReady in projectDARecordImageLiveLocked — redundant for THIS caller, whose image.next
// is already private, and kept because that projector is shared with admission, where it is not.
// So a tick decrementing every record walks the retained bytes four times per record where the
// legacy tick copied none of them; the whole-record arm pays the preflight walk alone. Selection
// also runs checkRetiredLocatorRowsLocked over ALL of s.locators per projected record, so that
// tick is O(records x locators) against the legacy O(records). RUB-678 owns measuring both before
// any live caller (removal_preflight_reparse_bound, removal_batch_scan_bound, M_LOCATOR_SCAN); no
// cache, memo or skip-if-unchanged shortcut guards them, deliberately.
func (s *DARelayState) ownerReadyRemovalCandidatesLocked() ([][32]byte, error) {
	candidates := s.sortedRetainedDAIDsLocked()
	for _, daID := range candidates {
		if err := checkOwnerReadyRetainedRecordLocked(s.sets[daID]); err != nil {
			return nil, err
		}
	}
	if err := canonicalDARetainedImageClosed(s, candidates); err != nil {
		return nil, err
	}
	return candidates, nil
}

// checkOwnerReadyRetainedRecordLocked refuses a retained COMPLETE_SET outright, and applies to
// every other retained record the stored-scalar gate plus bindRetainedRecord, phase 2 of the
// canonical retained validator, which re-validates the retained BYTES no stored scalar can prove.
//
// RUB-1275 coverage_disposition, "R1 for a resident COMPLETE_SET": this path validates no State C
// shape, so one retained COMPLETE_SET makes the whole image terminal for both selectors. Issue 1118
// owns owner-ready COMPLETE_SET support and the State C validation it would then need.
//
// The state refusal is STATED here, not inherited. ownerReadyRemovalGateFails reaches the same
// verdict today only through checkOwnerReadyRecord's two-state allowlist (da_relay_owner.go), which
// is what issue 1118 must widen to admit a COMPLETE_SET; without this disjunct that widening would
// make State C selectable here silently. No in-package test can redden the disjunct alone.
func checkOwnerReadyRetainedRecordLocked(record daRelaySetRecord) error {
	if record.state == daRelayStateCompleteSet || record.ownerReadyRemovalGateFails() {
		return errDARelayImageIncompatible
	}
	return (&canonicalDARetainedImage{}).bindRetainedRecord(record)
}

// ownerReadyRemovalGateFails reports whether the record's revision, receivedTime,
// ttlBlocksRemaining, locator rows, or checkDANonReplayShape fails the STORED-SCALAR half of the
// per-candidate removal gate, whose retained-bytes half is bindRetainedRecord; the caller fails the
// whole image with errDARelayImageIncompatible on a true result.
func (r daRelaySetRecord) ownerReadyRemovalGateFails() bool {
	return r.revision == 0 || r.receivedTime == 0 || r.ttlBlocksRemaining == 0 || len(r.locatorRows()) == 0 || r.checkDANonReplayShape() != nil
}

func ownerReadyPeerRemovalVictims(clone *DARelayState, quotaIdentity string) ([]DAAdmissionVictim, error) {
	candidates, err := clone.ownerReadyRemovalCandidatesLocked()
	if err != nil {
		return nil, err
	}
	// A1's empty-key rule selects nothing, but only BELOW the preflight: an early return above it
	// would launder a malformed image into a silent success.
	if quotaIdentity == "" {
		return nil, nil
	}
	var victims []DAAdmissionVictim
	for _, daID := range candidates {
		removed, err := clone.releaseOwnerReadyPeerRecordLocked(daID, quotaIdentity)
		if err != nil {
			return nil, err
		}
		victims = append(victims, removed...)
	}
	return victims, nil
}

func ownerReadyTTLTickVictims(clone *DARelayState) ([]DAAdmissionVictim, error) {
	candidates, err := clone.ownerReadyRemovalCandidatesLocked()
	if err != nil {
		return nil, err
	}
	var victims []DAAdmissionVictim
	for _, daID := range candidates {
		removed, err := clone.tickOwnerReadyTTLRecordLocked(daID)
		if err != nil {
			return nil, err
		}
		victims = append(victims, removed...)
	}
	return victims, nil
}

// releaseOwnerReadyPeerRecordLocked applies the PEER rule to one record on the clone. The
// commit arm quantifies over the retained members' PROVENANCE KIND, never over the released
// quota identity: the kind set is closed at PEER, LOCAL and DETACHED_REORG, and exactly a
// LOCAL or a DETACHED_REORG member leaves a matching commit retained. A PEER member of
// ANOTHER quota identity does not protect it and goes with the record, so this arm can
// release members the caller never named (RUBIN_COMPACT_BLOCKS.md Section 5, State B).
// Otherwise only the independently eligible matching chunks are dropped and the state never
// downgrades. A record every member of which matches is removed whole even with no commit
// slot, the arm a chunk-only record needs: dropping its last chunk would stage a memberless
// record checkOwnerReadyRemovalSurvivor refuses.
//
// Legacy dropCommitForPeerQuotaKey (da_relay_record.go) drops a matching commit ALONE and lets
// the record fall back to OrphanChunks; that arm cannot reach an owner-ready record at all.
func (s *DARelayState) releaseOwnerReadyPeerRecordLocked(daID [32]byte, quotaIdentity string) ([]DAAdmissionVictim, error) {
	record := s.sets[daID]
	matchCommit, matchChunks, memberCount, nonPeerChunk := ownerReadyPeerMatches(record, quotaIdentity)
	matchCount := len(matchChunks)
	if matchCommit {
		matchCount++
	}
	switch {
	case matchCount == 0:
		return nil, nil
	case (matchCommit && !nonPeerChunk) || matchCount == memberCount:
		return s.removeOwnerReadyWholeRecordLocked(record)
	case len(matchChunks) == 0:
		return nil, nil
	default:
		return s.dropOwnerReadyChunksLocked(record, matchChunks, 0)
	}
}

// ownerReadyPeerMatches reports the matching commit, the ascending matching chunk indexes, the
// total retained member count and whether any retained CHUNK carries a provenance kind other
// than PEER, walking chunks in sorted order so map iteration cannot change the selection. A
// memberless chunk slot counts as protective, which no reachable image carries and which is the
// fail-closed direction anyway.
func ownerReadyPeerMatches(record daRelaySetRecord, quotaIdentity string) (matchCommit bool, matchChunks []uint16, memberCount int, nonPeerChunk bool) {
	matchCommit, memberCount = ownerReadyMemberMatchesPeer(record.commit.member, quotaIdentity), len(record.chunks)
	if record.commit.member != nil {
		memberCount++
	}
	for _, index := range sortedRetainedDAChunkIndexes(record) {
		member := record.chunks[index].member
		switch {
		case ownerReadyMemberMatchesPeer(member, quotaIdentity):
			matchChunks = append(matchChunks, index)
		case member == nil || member.provenance.kind != daProvenancePeer:
			nonPeerChunk = true
		}
	}
	return matchCommit, matchChunks, memberCount, nonPeerChunk
}

func (s *DARelayState) tickOwnerReadyTTLRecordLocked(daID [32]byte) ([]DAAdmissionVictim, error) {
	record := s.sets[daID]
	if record.ttlBlocksRemaining == 1 {
		return s.removeOwnerReadyWholeRecordLocked(record)
	}
	return s.dropOwnerReadyChunksLocked(record, nil, 1)
}

// ownerReadyRemovalCaps is s.caps with the four orphan-domain caps lifted to the uint64 maximum.
// checkedApplyUint64DeltaCap compares a post-delta TOTAL against the limit, so without the
// lift a counter still above its cap after this removal's own decrease would abort the whole
// all-or-nothing batch. Growth stays impossible: a whole removal stages an empty record, and
// a survivor is proven a member-wise byte-identical subset before this cap set is used.
func (s *DARelayState) ownerReadyRemovalCaps() daRelayCaps {
	caps := s.caps
	caps.orphanPoolBytes, caps.orphanPoolPerDAIDBytes = ^uint64(0), ^uint64(0)
	caps.orphanPoolPerPeerBytes, caps.orphanCommitOverheadBytes = ^uint64(0), ^uint64(0)
	return caps
}

// removeOwnerReadyWholeRecordLocked removes one whole owner-ready incomplete record — every
// member with its locator, accounting contribution, prefetch reservation and shared-owner
// claim — through the merged record-image projector, and returns each retired member as a
// bound-owner victim in locator order. It splits projectDARecordImageLocked's two steps to
// project uncapped, exactly as the canonical removal builder does.
//
// checkDANonReplayVictims cannot pair this arm's batch: it walks chunks alone, and here the whole
// record departs COMMIT FIRST. Nothing else pairs it either — the batch and the departure set are
// both ownerReadyRecordVictims' single derivation — so the equivalent comparison is against
// locatorRows, the record's other member enumerator, in the same commit-then-chunks-ascending
// order. An omitted victim would leave a departed member's finalized DA claim live; an extra or
// reordered one fails the same count-and-txid comparison. It sits BELOW the baseline guard, whose
// checkOwnerReadyRecord is what makes the victim walk's non-nil member precondition safe, so no
// input's first error moves. Fail-closed backstop, like the drop arm's: nothing reddens it today.
func (s *DARelayState) removeOwnerReadyWholeRecordLocked(record daRelaySetRecord) ([]DAAdmissionVictim, error) {
	image := stageDAOwnerReadyRemoval(record, true)
	live, err := s.checkDARecordImageBaselineLocked(image)
	if err != nil {
		return nil, err
	}
	victims, rows := ownerReadyRecordVictims(record), record.locatorRows()
	if len(victims) != len(rows) {
		return nil, errDARelayImageIncompatible
	}
	for i, row := range rows {
		if victims[i].TxID != row.txid {
			return nil, errDARelayImageIncompatible
		}
	}
	placement, err := s.projectDARecordImageLiveLocked(image, live, s.ownerReadyRemovalCaps())
	if err != nil {
		return nil, err
	}
	s.installDASetRecordLocked(placement)
	s.prefetch.releaseSet(record.daID)
	return victims, nil
}

// dropOwnerReadyChunksLocked keeps one owner-ready record and drops the named chunks,
// releasing their locators, accounting and claims and minting one fresh revision. ttlDelta
// decrements the record TTL once (the TTL selector passes 1; the PEER selector passes 0).
// The commit and every unnamed member stay byte-identical and the record state never changes.
//
// PRECONDITION: ttlDelta is strictly below the record's resident TTL, so the unsigned
// subtraction below neither wraps nor lands on zero. ownerReadyRemovalGateFails refuses a
// resident TTL of zero before either selector runs, which is what makes a delta of 1 safe.
//
// checkDANonReplayVictims — the admission path's own pairing — proves the batch is exactly the
// departed chunks, in sortedRetainedDAChunkIndexes order, txid/token/inputs equal, so no chunk can
// leave the survivor while its finalized DA claim stays live. It is a fail-closed backstop: the
// one loop below appends a victim per deleted index, so no reachable input reddens it today.
func (s *DARelayState) dropOwnerReadyChunksLocked(record daRelaySetRecord, dropIndexes []uint16, ttlDelta uint64) ([]DAAdmissionVictim, error) {
	survivor := record.cloneOwnerReady()
	survivor.ttlBlocksRemaining -= ttlDelta
	var victims []DAAdmissionVictim
	for _, index := range dropIndexes {
		victims = append(victims, ownerReadyMemberVictim(record.chunks[index].member))
		delete(survivor.chunks, index)
	}
	if err := checkOwnerReadyRemovalBaseline(record, survivor); err != nil {
		return nil, err
	}
	image := daRelayRecordImage{daID: record.daID, present: true, baseline: record.revision, next: survivor}
	if err := checkDANonReplayVictims(image, record, victims); err != nil {
		return nil, err
	}
	placement, err := s.projectDARecordImageLiveLocked(image, record, s.ownerReadyRemovalCaps())
	if err != nil {
		return nil, err
	}
	s.installDASetRecordLocked(placement)
	return victims, nil
}

// checkOwnerReadyRemovalBaseline re-checks the live record's own shape as a fail-closed backstop —
// the candidate gate already refuses all three disjuncts before either selector runs — and then
// proves next a byte-identical submultiset of it, so no member, token, provenance, commit slot or
// locator can change unseen. It does not test the caller's baseline: the caller reads live out of
// s.sets and mints image.baseline from that same record, unlike checkDARecordImageBaselineLocked,
// which establishes residency from its own lookup.
func checkOwnerReadyRemovalBaseline(live, next daRelaySetRecord) error {
	if live.revision == 0 || live.checkOwnerReadyRecord() != nil || len(live.locatorRows()) == 0 {
		return errDARelayImageIncompatible
	}
	return checkOwnerReadyRemovalSurvivor(live, next)
}

// checkOwnerReadyRemovalSurvivor proves the survivor is the live record minus the dropped
// members: it pins daID, state, receivedTime, payloadBytes, wireBytes, the whole commit and
// every surviving chunk byte-identical, lets ttlBlocksRemaining only decrease and never to
// zero, and leaves revision to the projector's remint. replaceableChunks is the one live field it
// does not pin, unlike its admission-side twin samePreservedRecordFields: the candidate gate
// refuses a non-nil one and cloneOwnerReady carries that nil into the survivor.
func checkOwnerReadyRemovalSurvivor(live, next daRelaySetRecord) error {
	type fixed struct {
		daID                                  [32]byte
		state                                 daRelaySetState
		receivedTime, payloadBytes, wireBytes uint64
	}
	if (fixed{next.daID, next.state, next.receivedTime, next.payloadBytes, next.wireBytes}) !=
		(fixed{live.daID, live.state, live.receivedTime, live.payloadBytes, live.wireBytes}) {
		return errDARelayImageIncompatible
	}
	if next.ttlBlocksRemaining == 0 || next.ttlBlocksRemaining > live.ttlBlocksRemaining {
		return errDARelayImageIncompatible
	}
	if err := next.checkOwnerReadyRecord(); err != nil {
		return err
	}
	if len(next.locatorRows()) == 0 || !sameOwnerReadyCommit(live.commit, next.commit) {
		return errDARelayImageIncompatible
	}
	return checkOwnerReadySurvivingChunks(live, next)
}

// checkOwnerReadySurvivingChunks proves every chunk the survivor keeps is byte-identical to
// the live chunk at that index, so a removal drops members but never rewrites a survivor.
// The walk is map-ordered but yields one error identity, so it is order-immune.
func checkOwnerReadySurvivingChunks(live, next daRelaySetRecord) error {
	for index, chunk := range next.chunks {
		liveChunk, present := live.chunks[index]
		if !present || !sameOwnerReadyChunk(liveChunk, chunk) {
			return errDARelayImageIncompatible
		}
	}
	return nil
}

func ownerReadyMemberMatchesPeer(member *daRelayMemberIdentity, quotaIdentity string) bool {
	return member != nil && member.provenance.kind == daProvenancePeer && member.provenance.quotaIdentity == quotaIdentity
}

// ownerReadyMemberVictim copies one retained member's claim descriptor; the input slice is
// cloned so no victim aliases live record state before publication.
//
// PRECONDITION shared by both arms: member is non-nil. dropOwnerReadyChunksLocked reads a
// member only for the indexes ownerReadyPeerMatches accepted, and that predicate starts at
// member != nil (the TTL selector passes no indexes at all); ownerReadyRecordVictims proves
// its own two arms.
func ownerReadyMemberVictim(member *daRelayMemberIdentity) DAAdmissionVictim {
	return DAAdmissionVictim{TxID: member.txid, Token: member.token, Inputs: slices.Clone(member.inputs)}
}

// ownerReadyRecordVictims lists every retained member of one record as a bound-owner victim,
// commit first then chunks ascending, matching locatorRows order.
//
// PRECONDITION: checkOwnerReadyCommitSlot ACCEPTS a legitimately-empty commit slot (a chunk-only
// OrphanChunks record carries no commit member), so the commit read below is nil-safe only
// because of its own explicit guard. Every retained chunk member is non-nil because
// checkOwnerReadyChunk -> member.validate() refuses a memberless chunk slot.
func ownerReadyRecordVictims(record daRelaySetRecord) []DAAdmissionVictim {
	victims := make([]DAAdmissionVictim, 0, 1+len(record.chunks))
	if record.commit.member != nil {
		victims = append(victims, ownerReadyMemberVictim(record.commit.member))
	}
	for _, index := range sortedRetainedDAChunkIndexes(record) {
		victims = append(victims, ownerReadyMemberVictim(record.chunks[index].member))
	}
	return victims
}
