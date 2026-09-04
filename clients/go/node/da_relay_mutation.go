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
	// Every row names daID: locatorRows stamps image.next.daID, and every installer pins
	// next.daID == image.daID (checkStagedOwnerReadyRecord, checkOwnerReadyRemovalSurvivor).
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
// (releaseOwnerReadyPeerRecordLocked); an empty quota identity selects nothing. This entrypoint
// has zero non-test callers until issue 678.
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
// selectVictims derive every exact per-record transition and the bound-owner victim tokens on
// that clone, and publishes it through the arm the relay's claim domain selects — a batch that
// releases no member taking the same arm as one that does. Any error before publication leaves
// both complete images unchanged.
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
	if s.mempool == nil || s.mempool.chainState == nil {
		s.publishAtomicBatchLocked(clone) // truly unbound: the DA image is the whole change
		return nil
	}
	owner := s.mempool.pendingOutpoints
	if owner == nil { // bound but no claim domain: BeginDARemoval's exact refusal, whatever the batch releases
		return txAdmitUnavailable("nil pending-outpoint owner")
	}
	return s.commitOwnerReadyRemovalClaimsLocked(owner, clone, victims)
}

// commitOwnerReadyRemovalClaimsLocked validates the victim batch and the retained image's owner
// binding and, only on success, publishes the DA image and drops every victim claim under one
// owner-lock hold. An empty batch takes the same route, so a member-preserving decrement is
// proven owner-bound before it republishes. Nothing fallible runs after the DA publish, so a
// record and its claim cannot become observably separated.
func (s *DARelayState) commitOwnerReadyRemovalClaimsLocked(owner *PendingOutpointOwner, clone *DARelayState, victims []DAAdmissionVictim) error {
	var batch []DAAdmissionVictim
	if len(victims) != 0 {
		var err error
		if batch, err = prepareDAAdmissionVictims(victims, [32]byte{}); err != nil {
			return txAdmitFromPendingOutpointError(err)
		}
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if failure, failed := owner.validateDAAdmissionVictimsLocked(batch, PendingOutpointToken{}); failed {
		return txAdmitFromPendingOutpointError(&failure)
	}
	if err := checkOwnerReadyRetainedBindingLocked(clone, owner, batch); err != nil {
		return err
	}
	s.publishAtomicBatchLocked(clone)
	for _, victim := range batch {
		owner.dropClaimLocked(victim.Token)
	}
	return nil
}

// checkOwnerReadyRetainedBindingLocked proves the clone is publishable under owner: every
// retained member of every record — incomplete and COMPLETE_SET alike — is bound to owner and to
// a live claim that describes it, no token appears twice anywhere in the image, and no token in
// batch still belongs to a member the clone RETAINS. The da_id walk ascends, so one image yields
// one error.
//
// The closing batch-versus-retained comparison is a fail-closed backstop: the preflight's locator
// bijection already makes an aliased token unreachable, so no test executes that arm.
func checkOwnerReadyRetainedBindingLocked(clone *DARelayState, owner *PendingOutpointOwner, batch []DAAdmissionVictim) error {
	retained := make(map[PendingOutpointToken]struct{}, len(clone.locators))
	for _, daID := range clone.sortedRetainedDAIDsLocked() {
		if err := checkOwnerReadyRecordBinding(clone.sets[daID], owner, retained); err != nil {
			return err
		}
	}
	for _, victim := range batch {
		if _, held := retained[victim.Token]; held {
			return errDARelayImageIncompatible
		}
	}
	return nil
}

// checkOwnerReadyRecordBinding proves one record's owner binding and adds its members' tokens to
// seen, refusing the first token seen twice or a memberless occupied slot. EVERY member — a
// COMPLETE_SET's included — must carry a nonzero token owned by owner (checkDANonReplayTokens,
// the token check checkDANonReplayPrior applies canonically) AND resolve a LIVE owner claim that
// describes it: DA domain, txid, ordered inputs and finalized, through canonicalDAClaimBindsMember,
// the canonical builder's own phase-5 predicate (sync_da_relay.go), over the owner's LIVE byToken
// index — which is why the proof lives under the owner mutex here and not in the preflight.
func checkOwnerReadyRecordBinding(record daRelaySetRecord, owner *PendingOutpointOwner, seen map[PendingOutpointToken]struct{}) error {
	if err := record.checkDANonReplayTokens(owner); err != nil {
		return err
	}
	members, err := canonicalDARetainedMemberIdentities(record)
	if err != nil {
		return err
	}
	for _, member := range members {
		claim := owner.byToken[member.token]
		if _, alias := seen[member.token]; alias || claim == nil || !canonicalDAClaimBindsMember(*claim, member) {
			return errDARelayImageIncompatible
		}
		seen[member.token] = struct{}{}
	}
	return nil
}

// ownerReadyRemovalCandidatesLocked returns the incomplete owner-ready da_ids the PEER and TTL
// selectors consider, ascending, after a fail-closed whole-image preflight. Records — never the
// cached orphanBytesByDAID total — are the selection authority (R4). A COMPLETE_SET is never a
// candidate and stays byte-identical (A5), but every retained record, State C included, is
// validated here, since either selector publishes a clone that carries it (R1).
//
// The per-candidate shape gate is checkDANonReplayShape, the predicate
// validateCanonicalDARetainedSnapshot applies to every retained record — not the weaker
// checkOwnerReadyRecord it wraps. The TTL and receivedTime bounds it does not read are applied by
// ownerReadyRemovalGateFails, and the preflight is unconditional and mixed-safe; see
// checkOwnerReadyRemovalImageClosedLocked.
//
// Cost, under BOTH the admission fence and DARelayState.mu, per peer release and per TTL tick:
// O(retained bytes) of consensus.ParseTx over every retained record, plus one SHA3-256 per
// incomplete chunk payload and one re-scan of each commit's outputs, on top of the image clone.
// Selection then adds checkRetiredLocatorRowsLocked, which walks ALL of s.locators per projected
// record, so a tick touching every record is O(records x locators) against the legacy O(records).
// RUB-678 owns measuring that (removal_batch_scan_bound, M_LOCATOR_SCAN) before any live caller;
// no cache, memo or skip-if-unchanged shortcut guards it, deliberately.
func (s *DARelayState) ownerReadyRemovalCandidatesLocked() ([][32]byte, error) {
	retained := s.sortedRetainedDAIDsLocked()
	candidates := make([][32]byte, 0, len(retained))
	for _, daID := range retained {
		record := s.sets[daID]
		if err := s.checkOwnerReadyRetainedRecordLocked(record); err != nil {
			return nil, err
		}
		if record.state != daRelayStateCompleteSet {
			candidates = append(candidates, daID)
		}
	}
	if err := s.checkOwnerReadyRemovalImageClosedLocked(retained, candidates); err != nil {
		return nil, err
	}
	return candidates, nil
}

// checkOwnerReadyRetainedRecordLocked applies the stored-scalar gate the record's own state implies
// and then re-validates the retained BYTES no stored scalar can prove. An incomplete record takes
// bindRetainedRecord, phase 2 of the canonical retained validator; a COMPLETE_SET takes
// checkOwnerReadyCompleteSetBytes, that phase minus the clauses a completed set cannot satisfy.
func (s *DARelayState) checkOwnerReadyRetainedRecordLocked(record daRelaySetRecord) error {
	if record.state == daRelayStateCompleteSet {
		if record.ownerReadyCompleteSetGateFails(s) {
			return errDARelayImageIncompatible
		}
		return record.checkOwnerReadyCompleteSetBytes()
	}
	if record.ownerReadyRemovalGateFails() {
		return errDARelayImageIncompatible
	}
	return (&canonicalDARetainedImage{}).bindRetainedRecord(record)
}

// checkOwnerReadyCompleteSetBytes re-parses every retained member of a COMPLETE_SET record to full
// consumption and role-checks it against the record's own claims (canonicalRetainedDASetIdentity),
// then binds the commit member to the identity, inputs and payload commitment its slot stores
// (canonicalDARetainedBinding). Both walks emit the commit first and the caller's gate proves a
// commit member beside a nonzero chunk_count, so index 0 is that commit.
//
// bindRetainedRecord itself cannot be called here: markComplete (da_relay_record.go) nulls every
// chunk payload when a set completes, and canonicalDAChunkCacheBound hashes that payload, so the
// chunk arm of the binding calls every legitimate complete set terminal. A chunk's stored identity
// and inputs are the one pairing this path leaves to the admission replay validator
// (da_relay_owner.go, validateRetained).
func (r daRelaySetRecord) checkOwnerReadyCompleteSetBytes() error {
	_, parsed, err := canonicalRetainedDASetIdentity(r)
	if err != nil {
		return canonicalDARecordTerminal(err, r.daID)
	}
	stored, err := canonicalDARetainedMemberIdentities(r)
	if err != nil {
		return err
	}
	if len(parsed) == 0 || len(parsed) != len(stored) {
		return errDARelayImageIncompatible
	}
	return canonicalDARetainedBinding(r, canonicalDARetainedMember{parsed: parsed[0], stored: stored[0], daID: r.daID})
}

// ownerReadyRemovalGateFails reports whether the record's revision, receivedTime, ttlBlocksRemaining, locator rows, or checkDANonReplayShape fails the STORED-SCALAR half of the per-candidate removal gate, whose retained-bytes half is bindRetainedRecord; the caller fails the whole image with errDARelayImageIncompatible on a true result.
func (r daRelaySetRecord) ownerReadyRemovalGateFails() bool {
	return r.revision == 0 || r.receivedTime == 0 || r.ttlBlocksRemaining == 0 || len(r.locatorRows()) == 0 || r.checkDANonReplayShape() != nil
}

// ownerReadyCompleteSetGateFails reports whether a COMPLETE_SET record fails the member shape its
// own state implies: a commit member plus exactly one member per declared chunk, at least one
// chunk, each a valid identity. The caller fails the whole image with errDARelayImageIncompatible
// on a true result. Its own state's scalars, and the two stored high-waters s carries, are then
// bound by ownerReadyCompleteSetShapeFails below.
func (r daRelaySetRecord) ownerReadyCompleteSetGateFails(s *DARelayState) bool {
	members, err := canonicalDARetainedMemberIdentities(r)
	if err != nil || r.commit.member == nil || r.commit.chunkCount == 0 || len(members) != 1+int(r.commit.chunkCount) {
		return true
	}
	for _, member := range members {
		if member.validate() != nil {
			return true
		}
	}
	return r.ownerReadyCompleteSetShapeFails(s)
}

// ownerReadyCompleteSetShapeFails reports whether a COMPLETE_SET record contradicts the scalars
// and slot residuals its own state implies. Every bound mirrors daAdmissionObservation's
// validateHeader/validateCommitRole/validateStagedCommit/validateChunkRole (da_relay_owner.go),
// read off the record observeDAAdmission copies them from. Drift is pinned by
// TestOwnerReadyCompleteSetMirrorTracksItsSiblings; the canonical retained validator refuses a
// State C record outright.
//
// wireBytes is bounded below by the LARGEST retained member's byte length, over the set {commit,
// every retained chunk}: validateHeader bounds it against whichever member observeDAAdmission is
// replaying, and every retained member is replayable, so the bound must hold for the maximum.
// The map walk that takes that maximum, and the boolean-valued residual walk below, are both
// order-immune.
//
// The chunk-index bound is the one predicate with no sibling helper, though not a new invariant:
// validateStagedCommit refuses the same out-of-range index for an admission candidate. With the
// caller's member count already proving one member per declared chunk and map keys distinct by
// construction, an in-range walk yields exactly [0, chunk_count).
//
// The two STORED HIGH-WATER bounds come from a different sibling, canonicalDARecordAccounted
// (sync_da_relay_validate.go), which applies them to EVERY retained record while this path bills
// only the incomplete candidates through it. They are restated rather than called because that
// sibling also bills state-agnostic accounting a COMPLETE_SET's live counters do not hold. s is
// read for those two counters alone.
func (r daRelaySetRecord) ownerReadyCompleteSetShapeFails(s *DARelayState) bool {
	largest := len(r.commit.txBytes)
	for _, chunk := range r.chunks {
		largest = max(largest, len(chunk.txBytes))
	}
	if slices.Contains([]bool{
		r.revision == 0,
		r.revision > s.records,
		r.receivedTime == 0,
		r.receivedTime > s.nextReceivedTime,
		r.ttlBlocksRemaining != 0,
		r.payloadBytes == 0,
		r.wireBytes <= uint64(largest),
		r.replaceableChunks != nil,
		uint64(r.commit.chunkCount) > consensus.MAX_DA_CHUNK_COUNT,
		r.commit.daID != r.daID,
		len(r.commit.txBytes) == 0,
		r.commit.wireBytes != 0,
		r.commit.peerQuotaKey != "",
	}, true) {
		return true
	}
	type chunkResidual struct {
		daID        [32]byte
		index       uint16
		quotaKey    string
		wireBytes   uint64
		hashChecked bool
	}
	for index, chunk := range r.chunks {
		if index >= r.commit.chunkCount ||
			(chunkResidual{chunk.daID, chunk.chunkIndex, chunk.peerQuotaKey, chunk.wireBytes, chunk.hashChecked}) != (chunkResidual{daID: r.daID, index: index}) {
			return true
		}
	}
	return false
}

// checkOwnerReadyRemovalImageClosedLocked is the removal path's whole-image preflight (R1/R4),
// composing the same per-record helpers as canonicalDARetainedImageClosed rather than a second
// validator framework:
//   - a locator bijection over EVERY retained record (incomplete AND State C, because
//     s.locators holds a row for each of their members) equal to len(s.locators);
//   - the orphan-domain accounting derived over the INCOMPLETE candidates only, and
//     the pinned-payload total derived over EVERY retained record, compared to the
//     live totals and entry counts.
//
// This is the accounting and locator-bijection integrity gate alone: a COMPLETE_SET record enters
// it through its locator rows and its pinned payload only, and its own scalars are bound by the
// candidate walk's State C gate instead.
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
	return s.checkOwnerReadyRemovalOrphanDomainLocked(retained, candidates)
}

// checkOwnerReadyRemovalOrphanDomainLocked derives every field checkAgainstLocked compares
// and exempts none of them, so any derived-versus-live accounting mismatch is terminal (R4).
// The two walks bill different domains over different record sets, which is the whole reason
// this preflight cannot reuse canonicalDARetainedImageClosed wholesale:
//   - the orphan-domain terms over the incomplete CANDIDATES, through
//     canonicalDARecordAccounted, whose state-agnostic ownerReadyAccounting would charge a
//     State C record's members that the live orphan counters do not hold;
//   - the pinned-payload term over EVERY retained record, through
//     pinnedPayloadAccountingBytes, the same accessor the live writers bill with, which is
//     zero in every state but COMPLETE_SET and therefore adds nothing for a candidate.
func (s *DARelayState) checkOwnerReadyRemovalOrphanDomainLocked(retained, candidates [][32]byte) error {
	totals := retainedDAAccountingTotals{peerBytes: map[string]uint64{}}
	for _, daID := range candidates {
		if err := canonicalDARecordAccounted(s, s.sets[daID], &totals); err != nil {
			return err
		}
	}
	for _, daID := range retained {
		if err := totals.add(daRelayRecordAccounting{}, s.sets[daID].pinnedPayloadAccountingBytes()); err != nil {
			return terminalCanonicalDAError(err)
		}
	}
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
// decrements the record TTL once (the TTL selector passes 1; the PEER selector passes 0).
// The commit and every unnamed member stay byte-identical and the record state never changes.
//
// PRECONDITION: ttlDelta is strictly below the record's resident TTL, so the unsigned
// subtraction below neither wraps nor lands on zero. ownerReadyRemovalGateFails refuses a
// resident TTL of zero before either selector runs, which is what makes a delta of 1 safe.
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
