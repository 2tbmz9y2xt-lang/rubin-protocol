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

// projectDARecordImageLocked is the FALLIBLE half: it owns EVERY check and
// mutates nothing on any path, so a refused image leaves live state
// byte-identical. A doubly-violating image selects by STAGE, in this order:
// incompatible live record, stale image, unusable candidate, locator row,
// accounting, exhausted revision space (RUBIN_COMPACT_BLOCKS.md 18.2, 18.3).
// The four pool arms hold that order too, but the per-peer arm walks a map: which
// violating key is reported, and so which identity surfaces, is unordered. The live
// counters and the revision high-water are re-read here: they are shared state.
func (s *DARelayState) projectDARecordImageLocked(image daRelayRecordImage) (daRelayRecordPlacement, error) {
	live, err := s.checkDARecordImageBaselineLocked(image)
	if err != nil {
		return daRelayRecordPlacement{}, err
	}
	retire, install, err := s.checkDARecordImageLocatorsLocked(image, live)
	if err != nil {
		return daRelayRecordPlacement{}, err
	}
	placement, err := s.projectDARecordImageCountersLocked(image, live)
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

// checkDARecordImageBaselineLocked takes residency from the s.sets lookup alone,
// never from the record's contents. An absent record has revision 0 and a
// non-resident staging baseline 0, so one comparison covers both arms.
func (s *DARelayState) checkDARecordImageBaselineLocked(image daRelayRecordImage) (daRelaySetRecord, error) {
	live, resident := s.sets[image.daID]
	if resident && (live.revision == 0 || live.checkOwnerReadyRecord() != nil) {
		return daRelaySetRecord{}, errDARelayImageIncompatible
	}
	if resident != image.present || live.revision != image.baseline {
		return daRelaySetRecord{}, errDARelayRecordStale
	}
	return live, checkStagedOwnerReadyRecord(image, live)
}

// checkStagedOwnerReadyRecord makes image.next the placement's AUTHORITY: a removal
// carries an EMPTY next, a non-removal a non-empty one naming its own da_id, holding
// the candidate at the named slot field for field and every other live slot
// byte-identically. Reading only the parallel descriptor would leave the record
// installDASetRecordLocked actually publishes unchecked.
func checkStagedOwnerReadyRecord(image daRelayRecordImage, live daRelaySetRecord) error {
	rows := image.next.locatorRows()
	if image.remove {
		if len(rows) != 0 {
			return errDARelayMemberIncomplete
		}
		return nil
	}
	if len(rows) == 0 {
		return errDARelayMemberIncomplete
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

// checkStagedCandidateSlot binds the ONE slot image.member.locator names to the
// descriptor across every field the descriptor carries. The locator ROW settles
// da_id, kind, index and txid together, because locatorRows derives each of them
// from the staged record itself; the remaining fields are compared one by one, so
// no valid-but-different value reaches the installer.
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

// checkPreservedOwnerReadySlots proves every live slot survives BYTE-IDENTICALLY.
// Locator rows cannot: a row carries txid and position, so a swapped fee, token,
// provenance, payload commitment or cached legacy key passes it unseen. Both
// directions are covered — checkOwnerReadySlotFree already proved the target slot
// is free in live, so exactly one chunk may appear and none may be dropped. The
// chunk walk is map-ordered and every violation yields ONE error identity, so
// iteration order cannot change the outcome. Every remaining record field is
// accounted for: da_id, state and wireBytes are pinned by the checks above,
// revision is REMINTED by projectDARecordImageLocked whatever the image carries,
// and the four below are compared against the live pre-state. That they move no
// counter at INSTALL time is no argument for leaving them free: the installed
// record then LIVES in s.sets, where missingChunkIndexes and validateChunkInsert
// read replaceableChunks and the TTL sweep decrements ttlBlocksRemaining. Staging
// copies all four out of the pre-state, so a legitimate image already agrees.
func checkPreservedOwnerReadySlots(live, next daRelaySetRecord, target daRelayLocator) error {
	if live.payloadBytes != next.payloadBytes || live.receivedTime != next.receivedTime ||
		live.ttlBlocksRemaining != next.ttlBlocksRemaining ||
		!maps.Equal(live.replaceableChunks, next.replaceableChunks) {
		return errDARelayImageIncompatible
	}
	staged := len(live.chunks)
	if target.kind == daRelayLocatorChunk {
		staged++
		// The kernel assigns none of these three, and the target slot was free, so
		// a staged one carrying any of them did not come from this kernel.
		if fresh := next.chunks[target.chunkIndex]; fresh.chunkHash != ([32]byte{}) || fresh.peerQuotaKey != "" || fresh.hashChecked {
			return errDARelayImageIncompatible
		}
		if !sameOwnerReadyCommit(live.commit, next.commit) {
			return errDARelayImageIncompatible
		}
	} else if live.commit.payloadCommitment != next.commit.payloadCommitment ||
		live.commit.peerQuotaKey != next.commit.peerQuotaKey ||
		live.commit.chunkCount != next.commit.chunkCount {
		// A commit candidate owns only da_id, member and txBytes, and
		// checkOwnerReadyCommitSlot pins wireBytes to zero, so these three
		// complete the seven-field slot.
		return errDARelayImageIncompatible
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

// The three comparisons below name EVERY field of their type: none of the three is
// comparable with ==, and a field left out is a field an edited image may change
// unseen.
func sameOwnerReadyCommit(a, b daRelayCommit) bool {
	return a.daID == b.daID && a.payloadCommitment == b.payloadCommitment &&
		a.peerQuotaKey == b.peerQuotaKey && a.chunkCount == b.chunkCount &&
		a.wireBytes == b.wireBytes && bytes.Equal(a.txBytes, b.txBytes) &&
		sameOwnerReadyMember(a.member, b.member)
}

func sameOwnerReadyChunk(a, b daRelayChunk) bool {
	return a.daID == b.daID && a.chunkHash == b.chunkHash &&
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

// checkDARecordImageLocatorsLocked proves the txid index and the retained image
// are one bijection (Section 18.3). A nil index is refused rather than allocated,
// since installDASetRecordLocked may not allocate the index itself.
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

// checkOwnerReadySlotFree is FIRST-SEEN over the ONE slot image.member.locator
// names: staging overwrites it, so without this a second member would evict the
// retained one and move its charge to the new provenance. Both arms are stricter
// than the legacy guard; the chunk-count range arm is RUB-1273's, not here.
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

func (s *DARelayState) projectDARecordImageCountersLocked(image daRelayRecordImage, live daRelaySetRecord) (daRelayRecordPlacement, error) {
	oldAccounting, err := live.ownerReadyAccounting()
	if err != nil {
		return daRelayRecordPlacement{}, err
	}
	newAccounting, err := image.next.ownerReadyAccounting()
	if err != nil {
		return daRelayRecordPlacement{}, err
	}
	placement := daRelayRecordPlacement{daID: image.daID, remove: image.remove}
	if placement.orphanBytes, err = checkedApplyUint64DeltaCap(s.orphanBytes, oldAccounting.orphanBytes, newAccounting.orphanBytes, s.caps.orphanPoolBytes, errDARelayOrphanPoolCapExceeded); err != nil {
		return daRelayRecordPlacement{}, err
	}
	if placement.daBytes, err = checkedApplyUint64DeltaCap(s.orphanBytesByDAID[image.daID], oldAccounting.orphanBytes, newAccounting.orphanBytes, s.caps.orphanPoolPerDAIDBytes, errDARelayOrphanDAIDCapExceeded); err != nil {
		return daRelayRecordPlacement{}, err
	}
	if placement.commitBytes, err = checkedApplyUint64DeltaCap(s.orphanCommitOverheadBytes, oldAccounting.commitBytes, newAccounting.commitBytes, s.caps.orphanCommitOverheadBytes, errDARelayOrphanCommitCapExceeded); err != nil {
		return daRelayRecordPlacement{}, err
	}
	placement.peerBytes, err = s.projectPeerAccountingDeltaLocked(oldAccounting.peerBytes, newAccounting.peerBytes)
	return placement, err
}

// installDASetRecordLocked PERFORMS NO VALIDATION: every check ran in
// projectDARecordImageLocked, which is what lets a caller run it after an owner
// reserve with no fallible step in between.
//
// PRECONDITION, the caller's to keep: a placement is SINGLE-USE — ONE projection,
// ONE installation, one continuous hold, with the placement THIS image's own
// projection returned. Two placements projected before either installs carry the
// same minted revision; nothing here detects that, by design.
//
// Three steps the sibling installers take are skipped. The pinned-payload counter
// is neither projected nor restored: it prices only a COMPLETE_SET, a state the
// projector refuses, so its delta is 0-to-0. No received-time high-water advances
// (RUB-1273's), and a removal releases no prefetch reservation (RUB-1275's).
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
