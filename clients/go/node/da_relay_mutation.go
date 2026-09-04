package node

import (
	"bytes"
	"crypto/sha3"
	"fmt"
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
	// Every row names daID: checkStagedOwnerReadyRecord pinned next.daID, and a removal installs none.
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
// Three steps the sibling installers take are skipped. The pinned-payload counter is
// neither projected nor restored: it prices only a COMPLETE_SET, a state the projector
// refuses, so 0-to-0; RUB-1287 checks admission sequence/revision high-water, and every
// remove: true caller — removeOwnerReadyWholeRecordLocked below and buildCanonicalDAOwnerCandidates
// (sync_da_relay.go) — releases the removed record's prefetch reservation itself.
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

// releaseOwnerReadyPeerQuota is the DORMANT owner-aware PEER quota cleanup selector. It
// MATCHES retained members on typed provenance — peer with the requested quota identity,
// never the cached legacy peerQuotaKey and never orphanBytesByPeerQuotaKey as selection
// authority (RUBIN_COMPACT_BLOCKS.md 18.1; the map is still a legitimate accounting side
// effect of a successful install) — and can REMOVE less than it matches, over one
// owner-atomic incomplete-record removal batch: matching chunks are dropped, but a matching
// commit goes only with a whole-record removal, so any non-matching member — a LOCAL, a
// DETACHED_REORG or a PEER of a different quota identity — leaves that commit retained WITH
// its accounting charge and its owner claim until the record is removed whole, by TTL expiry
// or by a later release matching every remaining member. State B never downgrades to State A
// (see releaseOwnerReadyPeerRecordLocked below for the exact per-record rule). An empty quota
// identity selects nothing. This entrypoint has zero non-test callers until issue 678.
func (s *DARelayState) releaseOwnerReadyPeerQuota(quotaIdentity string) error {
	return s.commitOwnerReadyRemoval(func(clone *DARelayState) ([]DAAdmissionVictim, error) {
		return ownerReadyPeerRemovalVictims(clone, quotaIdentity)
	})
}

// advanceOwnerReadyTTL is the DORMANT owner-aware TTL tick selector: each incomplete
// owner-ready record with ttl greater than one decrements once and mints one fresh
// revision, ttl one expires as a whole-record removal with no revision, and a resident
// ttl of zero fails closed before any arithmetic. This entrypoint has zero non-test
// callers until issue 678.
func (s *DARelayState) advanceOwnerReadyTTL() error {
	return s.commitOwnerReadyRemoval(ownerReadyTTLTickVictims)
}

// commitOwnerReadyRemoval runs one owner-atomic incomplete-record removal batch. It clones
// the retained image under the existing admission fence and DARelayState.mu, lets
// selectVictims derive every exact per-record transition and the bound-owner victim tokens
// on that clone, then validates the full victim batch and publishes the DA image and owner
// commit through non-fallible operations. An unbound test-only relay has no claim domain,
// so its DA image is the whole change; any error before publication leaves both complete
// images unchanged.
func (s *DARelayState) commitOwnerReadyRemoval(selectVictims func(*DARelayState) ([]DAAdmissionVictim, error)) error {
	if s == nil {
		return nil
	}
	release := s.lockAdmissionFence()
	defer release()
	s.mu.Lock()
	defer s.mu.Unlock()

	clone := s.cloneForAtomicBatchLocked()
	victims, err := selectVictims(clone)
	if err != nil {
		return err
	}
	// A pure TTL decrement releases no member, so it never reaches the owner on any
	// relay: the DA image is the whole change.
	if len(victims) == 0 {
		s.publishAtomicBatchLocked(clone)
		return nil
	}
	owner := s.ownerReadyRemovalOwner()
	if owner != nil {
		return s.commitOwnerReadyRemovalClaimsLocked(owner, clone, victims)
	}
	// owner == nil with victims to drop. A truly unbound test-only relay (mempool or
	// chainState nil) has no claim domain and publishes the DA image alone; a BOUND
	// relay whose pending-outpoint owner is nil must never publish a victim-removing
	// image without dropping claims, so it fails closed — mirroring BeginDARemoval's
	// nil pending-outpoint owner refusal (da_admission.go).
	if s.mempool != nil && s.mempool.chainState != nil {
		return txAdmitUnavailable("nil pending-outpoint owner")
	}
	s.publishAtomicBatchLocked(clone)
	return nil
}

// commitOwnerReadyRemovalClaimsLocked validates the batch — shape, disjointness, owner — and only
// on success, publishes the DA image and drops every victim claim under one owner-lock hold.
// It mirrors DACommit's removal commit inline rather than wiring the dormant DARemoval guard,
// which issue 678 owns: nothing fallible runs after the DA publish, so a record and its claim
// cannot become observably separated.
func (s *DARelayState) commitOwnerReadyRemovalClaimsLocked(owner *PendingOutpointOwner, clone *DARelayState, victims []DAAdmissionVictim) error {
	batch, err := prepareDAAdmissionVictims(victims, [32]byte{})
	if err != nil {
		return txAdmitFromPendingOutpointError(err)
	}
	if err := checkOwnerReadyVictimsReleaseRetainedLocked(clone, batch); err != nil {
		return err
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if failure, failed := owner.validateDAAdmissionVictimsLocked(batch, PendingOutpointToken{}); failed {
		return txAdmitFromPendingOutpointError(&failure)
	}
	s.publishAtomicBatchLocked(clone)
	for _, victim := range batch {
		owner.dropClaimLocked(victim.Token)
	}
	return nil
}

// checkOwnerReadyVictimsReleaseRetainedLocked proves the batch is disjoint from the image about
// to be published: no dropped token still belongs to a member the clone RETAINS. The candidate
// gate runs checkDANonReplayShape, which never reads the owner domain; this path never reaches
// checkDANonReplayTokens, the canonical retained path's owner-domain validator; and
// prepareDAAdmissionVictims refuses only a duplicate WITHIN the batch. So a malformed image
// carrying one token on two members would publish a survivor whose claim was dropped — a
// retained member with no claim. The surviving set is derived from the clone's own records, not
// from the victim list, so map order cannot change the single sentinel this returns.
func checkOwnerReadyVictimsReleaseRetainedLocked(clone *DARelayState, batch []DAAdmissionVictim) error {
	retained := make(map[PendingOutpointToken]struct{}, len(clone.locators))
	for _, record := range clone.sets {
		if record.commit.member != nil {
			retained[record.commit.member.token] = struct{}{}
		}
		for _, chunk := range record.chunks {
			if chunk.member != nil {
				retained[chunk.member.token] = struct{}{}
			}
		}
	}
	for _, victim := range batch {
		if _, held := retained[victim.Token]; held {
			return errDARelayImageIncompatible
		}
	}
	return nil
}

// ownerReadyRemovalOwner returns the shared-owner claim domain only for a fully bound relay.
// The mempool+chainState check mirrors the fence lockAdmissionFence takes, but the actual
// claim domain is a superset of that guard: the returned owner is s.mempool.pendingOutpoints,
// which can itself be nil. A nil return splits two cases in commitOwnerReadyRemoval: a truly
// unbound relay (mempool or chainState nil) publishes the DA image alone, but a bound relay
// whose pending-outpoint owner is nil fails closed rather than orphaning victim claims.
func (s *DARelayState) ownerReadyRemovalOwner() *PendingOutpointOwner {
	if s.mempool == nil || s.mempool.chainState == nil {
		return nil
	}
	return s.mempool.pendingOutpoints
}

// ownerReadyRemovalCandidatesLocked returns the incomplete owner-ready da_ids the
// PEER and TTL selectors consider, ascending, after a fail-closed whole-image
// preflight. Records — never the cached orphanBytesByDAID total — are the selection
// authority (R4): the candidates come from s.sets, so a resident record whose cache
// entry was deleted is no longer silently skipped, and the preflight then fails the
// batch closed, without repair, on any derived-versus-live accounting mismatch or
// non-bijective locator image (R1/R4). A COMPLETE_SET is out of scope (State C):
// never a candidate and left byte-identical (A5).
//
// The per-candidate shape gate is checkDANonReplayShape, the SAME predicate the
// canonical retained-image validator applies to every retained record
// (validateCanonicalDARetainedSnapshot, via checkDANonReplayPrior), not the weaker
// checkOwnerReadyRecord it wraps: it adds the record's payloadBytes/replaceableChunks
// residual, the state-vs-commit-slot coupling and, per chunk, the legacy
// peerQuotaKey/hashChecked residual and the index bound. The accounting arm below sees
// none of them — an incomplete record pins no payload, so pinnedPayloadAccountingBytes
// never reads payloadBytes, and ownerReadyAccounting keys peer bytes on typed
// provenance, never on the legacy chunk field. So a malformed record is terminal here,
// before any selection, decrement or publication.
//
// checkDANonReplayShape reads neither ttlBlocksRemaining nor receivedTime, so the gate
// applies both bounds itself, the way checkDANonReplayPrior applies them to every record on
// the canonical retained path — one condition over da_id, revision, receivedTime and TTL.
// Admission stamps caps.orphanTTLBlocks, which newDARelayState refuses to construct as zero,
// and stamps receivedTime from a monotonic counter it first increments, so neither field is
// legitimately zero: a resident incomplete record carrying a zero in either is terminal here
// whether or not a selector would have touched it.
//
// The preflight runs UNCONDITIONALLY — for an all-incomplete image and for a MIXED
// image (a State C record coexisting with incomplete records) alike. It cannot reuse
// canonicalDARetainedImageClosed wholesale: that closure compares pinnedPayloadBytes
// and assumes s.locators holds exactly the passed records' rows, both false once a
// State C record is present, since a completed set pins its payload (out of this
// dormant removal's scope) yet still owns locator rows. See
// checkOwnerReadyRemovalImageClosedLocked for the mixed-safe composition.
func (s *DARelayState) ownerReadyRemovalCandidatesLocked() ([][32]byte, error) {
	retained := s.sortedRetainedDAIDsLocked()
	candidates := make([][32]byte, 0, len(retained))
	for _, daID := range retained {
		record := s.sets[daID]
		if record.state == daRelayStateCompleteSet {
			continue
		}
		if record.revision == 0 || record.receivedTime == 0 || record.ttlBlocksRemaining == 0 || len(record.locatorRows()) == 0 || record.checkDANonReplayShape() != nil {
			return nil, errDARelayImageIncompatible
		}
		candidates = append(candidates, daID)
	}
	if err := s.checkOwnerReadyRemovalImageClosedLocked(retained, candidates); err != nil {
		return nil, err
	}
	return candidates, nil
}

// checkOwnerReadyRemovalImageClosedLocked is the removal path's whole-image preflight
// (R1/R4), the mixed-safe analog of canonicalDARetainedImageClosed that the removal
// path cannot reuse directly (see ownerReadyRemovalCandidatesLocked). It composes the
// same per-record helpers so there is no second validator framework:
//   - a locator bijection over EVERY retained record (incomplete AND State C, because
//     s.locators holds a row for each of their members) equal to len(s.locators);
//   - the orphan-domain accounting derived over the INCOMPLETE candidates only,
//     compared to the live orphan-domain totals and entry counts, EXCLUDING
//     pinnedPayloadBytes, which a completed set owns and this removal never touches.
//
// Any corruption — a stray locator row, a stray orphan-domain entry, a map-key/da_id
// mismatch or a malformed record — fails closed before selection or publication. This
// is the orphan-domain and locator-bijection integrity gate only, not a general
// image-integrity check: a COMPLETE_SET record's own revision, receivedTime and
// payloadBytes are out of scope and never read here, since State C stays
// byte-identical (A5) and this dormant removal is never selected against it.
func (s *DARelayState) checkOwnerReadyRemovalImageClosedLocked(retained, candidates [][32]byte) error {
	if err := canonicalDARetainedImageRequiredMaps(s); err != nil {
		return err
	}
	indexed := make(map[[32]byte]bool, len(s.locators))
	for _, daID := range retained {
		record := s.sets[daID]
		if record.daID != daID {
			return terminalCanonicalDAError(fmt.Errorf("retained DA record stored under da_id %x carries da_id %x", daID, record.daID))
		}
		if err := canonicalDARecordLocatorsIndexed(s, record, indexed); err != nil {
			return err
		}
	}
	if len(indexed) != len(s.locators) {
		return terminalCanonicalDAError(fmt.Errorf("retained DA locator index holds %d rows against %d retained members", len(s.locators), len(indexed)))
	}
	return s.checkOwnerReadyRemovalOrphanDomainLocked(candidates)
}

// checkOwnerReadyRemovalOrphanDomainLocked verifies the live orphan-domain accounting
// is exactly what the incomplete candidates imply (R4), failing closed on any
// mismatch. pinnedPayloadBytes is deliberately excluded: it belongs to State C, which
// this dormant removal leaves byte-identical (A5), so the candidate-derived total
// (always zero — an incomplete record pins nothing) is aligned to the live pinned pool
// before the shared checkAgainstLocked compares every other, orphan-domain, field.
func (s *DARelayState) checkOwnerReadyRemovalOrphanDomainLocked(candidates [][32]byte) error {
	totals := retainedDAAccountingTotals{peerBytes: map[string]uint64{}}
	for _, daID := range candidates {
		if err := canonicalDARecordAccounted(s, s.sets[daID], &totals); err != nil {
			return err
		}
	}
	totals.pinnedBytes = s.pinnedPayloadBytes
	if err := totals.checkAgainstLocked(s); err != nil {
		return terminalCanonicalDAError(err)
	}
	return nil
}

func ownerReadyPeerRemovalVictims(clone *DARelayState, quotaIdentity string) ([]DAAdmissionVictim, error) {
	candidates, err := clone.ownerReadyRemovalCandidatesLocked()
	if err != nil {
		return nil, err
	}
	// A1's empty-key rule selects nothing, but only AFTER the whole-image preflight: an
	// early return above it would launder a malformed image into a silent success. The
	// TTL selector below has no early return at all, so the preflight is unconditional
	// on both entrypoints.
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

// releaseOwnerReadyPeerRecordLocked applies the PEER rule to one record on the clone. A
// record whose every member matches is a whole-record removal; otherwise any non-matching
// member protects the commit (RUBIN_COMPACT_BLOCKS.md 5), so only the independently
// eligible matching chunks are dropped and the state never downgrades.
func (s *DARelayState) releaseOwnerReadyPeerRecordLocked(daID [32]byte, quotaIdentity string) ([]DAAdmissionVictim, error) {
	record := s.sets[daID]
	matchCommit, matchChunks, memberCount := ownerReadyPeerMatches(record, quotaIdentity)
	matchCount := len(matchChunks)
	if matchCommit {
		matchCount++
	}
	switch {
	case matchCount == 0:
		return nil, nil
	case matchCount == memberCount:
		return s.removeOwnerReadyWholeRecordLocked(record)
	case len(matchChunks) == 0:
		return nil, nil
	default:
		return s.dropOwnerReadyChunksLocked(record, matchChunks, 0)
	}
}

// ownerReadyPeerMatches reports the matching commit, the ascending matching chunk indexes
// and the total retained member count for one record, walking chunks in sorted order so
// map iteration cannot change the selection.
func ownerReadyPeerMatches(record daRelaySetRecord, quotaIdentity string) (bool, []uint16, int) {
	memberCount := len(record.chunks)
	if record.commit.member != nil {
		memberCount++
	}
	var matchChunks []uint16
	for _, index := range sortedRetainedDAChunkIndexes(record) {
		if ownerReadyMemberMatchesPeer(record.chunks[index].member, quotaIdentity) {
			matchChunks = append(matchChunks, index)
		}
	}
	return ownerReadyMemberMatchesPeer(record.commit.member, quotaIdentity), matchChunks, memberCount
}

func (s *DARelayState) tickOwnerReadyTTLRecordLocked(daID [32]byte) ([]DAAdmissionVictim, error) {
	record := s.sets[daID]
	switch record.ttlBlocksRemaining {
	case 0:
		return nil, errDARelayImageIncompatible
	case 1:
		return s.removeOwnerReadyWholeRecordLocked(record)
	default:
		return s.dropOwnerReadyChunksLocked(record, nil, 1)
	}
}

// ownerReadyRemovalCaps is s.caps with the four orphan-domain caps lifted to the uint64
// maximum, as buildCanonicalDAOwnerCandidates (sync_da_relay.go) and
// projectDANonReplayAdmissionLocked (da_relay_owner.go) also pass them to the projector.
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
func (s *DARelayState) removeOwnerReadyWholeRecordLocked(record daRelaySetRecord) ([]DAAdmissionVictim, error) {
	image := stageDAOwnerReadyRemoval(record, true)
	live, err := s.checkDARecordImageBaselineLocked(image)
	if err != nil {
		return nil, err
	}
	placement, err := s.projectDARecordImageLiveLocked(image, live, s.ownerReadyRemovalCaps())
	if err != nil {
		return nil, err
	}
	s.installDASetRecordLocked(placement)
	s.prefetch.releaseSet(record.daID)
	return ownerReadyRecordVictims(record), nil
}

// dropOwnerReadyChunksLocked keeps one owner-ready record and drops the named chunks,
// releasing their locators, accounting and claims and minting one fresh revision. ttlDelta
// decrements the record TTL once (the TTL selector passes 1; the PEER selector passes 0);
// the caller guarantees ttlDelta is below the resident TTL. The commit and every unnamed
// member stay byte-identical and the record state never changes.
//
// Backstop: a record already at ttl 0 reaches neither selector, because
// ownerReadyRemovalCandidatesLocked refuses it. Were one to arrive on the PEER path, where
// ttlDelta is always 0, projectOwnerReadyRemovalLocked's checkOwnerReadyRemovalSurvivor still
// rejects next.ttlBlocksRemaining == 0 and aborts this whole all-or-nothing batch rather than
// installing a stalled record.
func (s *DARelayState) dropOwnerReadyChunksLocked(record daRelaySetRecord, dropIndexes []uint16, ttlDelta uint64) ([]DAAdmissionVictim, error) {
	survivor := record.cloneOwnerReady()
	survivor.ttlBlocksRemaining -= ttlDelta
	var victims []DAAdmissionVictim
	for _, index := range dropIndexes {
		victims = append(victims, ownerReadyMemberVictim(record.chunks[index].member))
		delete(survivor.chunks, index)
	}
	image := daRelayRecordImage{daID: record.daID, present: true, baseline: record.revision, next: survivor}
	placement, err := s.projectOwnerReadyRemovalLocked(image, record)
	if err != nil {
		return nil, err
	}
	s.installDASetRecordLocked(placement)
	return victims, nil
}

// projectOwnerReadyRemovalLocked validates one surviving-record image against the live
// record and projects the placement, reusing projectDARecordImageLiveLocked for the exact
// locator and accounting delta and the fresh revision. It is the removal analog of
// checkDARecordImageBaselineLocked's staging arm: the surviving record is a byte-identical
// submultiset of the live members with the state preserved, so no member, token,
// provenance, commit slot or locator can change unseen.
func (s *DARelayState) projectOwnerReadyRemovalLocked(image daRelayRecordImage, live daRelaySetRecord) (daRelayRecordPlacement, error) {
	if err := checkOwnerReadyRemovalBaseline(image, live); err != nil {
		return daRelayRecordPlacement{}, err
	}
	return s.projectDARecordImageLiveLocked(image, live, s.ownerReadyRemovalCaps())
}

func checkOwnerReadyRemovalBaseline(image daRelayRecordImage, live daRelaySetRecord) error {
	if live.revision == 0 || live.checkOwnerReadyRecord() != nil || len(live.locatorRows()) == 0 {
		return errDARelayImageIncompatible
	}
	if live.revision != image.baseline {
		return errDARelayRecordStale
	}
	return checkOwnerReadyRemovalSurvivor(live, image.next)
}

// checkOwnerReadyRemovalSurvivor proves the survivor is the live record minus the dropped
// members: it pins daID, state, receivedTime, payloadBytes, wireBytes, the whole commit and
// every surviving chunk byte-identical, lets ttlBlocksRemaining only decrease and never to
// zero, and leaves revision to the projector's remint. replaceableChunks is the one live field
// it does not pin, unlike its admission-side twin samePreservedRecordFields:
// ownerReadyRemovalCandidatesLocked's checkDANonReplayShape already refuses a non-nil
// replaceableChunks on every record that reaches this path, and cloneOwnerReady carries that
// nil into the survivor, so no reachable image could kill such a pin.
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
// member != nil (the TTL selector passes no indexes at all); ownerReadyRecordVictims (below)
// proves its own commit and chunk arms. A nil guard here would be unreachable, so there is none.
func ownerReadyMemberVictim(member *daRelayMemberIdentity) DAAdmissionVictim {
	return DAAdmissionVictim{TxID: member.txid, Token: member.token, Inputs: slices.Clone(member.inputs)}
}

// ownerReadyRecordVictims lists every retained member of one record as a bound-owner victim,
// commit first then chunks ascending, matching locatorRows order.
//
// PRECONDITION: reachable only after projectDARecordImageLocked -> checkOwnerReadyRecord.
// checkOwnerReadyCommitSlot ACCEPTS a legitimately-empty commit slot (a chunk-only
// OrphanChunks record carries no commit member), so it is NOT a memberless-commit refuser:
// the commit read below is nil-safe only because of its explicit record.commit.member != nil
// guard. Every retained chunk member is non-nil because checkOwnerReadyChunk ->
// member.validate() refuses a memberless chunk slot.
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
