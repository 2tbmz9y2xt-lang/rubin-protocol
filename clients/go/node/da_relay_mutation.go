package node

import (
	"bytes"
	"crypto/sha3"
	"sort"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

// releasePeerQuotaKeyLocked runs Section 18.3 peer teardown for one peer quota
// identity over the PROJECTED image and returns the exact member claims the
// teardown removes. It publishes nothing: the caller couples this projection and
// the victim batch inside one DACommit so record, locator and claim move
// together or not at all.
func (s *DARelayState) releasePeerQuotaKeyLocked(key string) ([]DAAdmissionVictim, error) {
	var victims []DAAdmissionVictim
	for _, daID := range s.sortedIncompleteDAIDsLocked() {
		removed, err := s.releasePeerQuotaKeyRecordLocked(key, s.sets[daID])
		if err != nil {
			return nil, err
		}
		victims = appendDAMemberVictims(victims, removed)
	}
	return victims, nil
}

func (s *DARelayState) releasePeerQuotaKeyRecordLocked(key string, record daRelaySetRecord) ([]daRelayMemberIdentity, error) {
	updated, removed, err := record.peerCleanupPlan(key)
	if err != nil {
		return nil, err
	}
	if len(removed) == 0 {
		return nil, nil
	}
	if updated.emptyIncomplete() {
		return removed, s.removeDASetRecordLocked(record)
	}
	return removed, s.applyDASetRecordLocked(updated)
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

// addDACommit stages one commit into the live image under DARelayState.mu, with
// no owner claim. It is the package-private accounting/cap entry the retained
// schema's own tests drive; every PRODUCTION admission goes through AdmitDA,
// which stages the same member through stageDACommitLocked with its exact
// identity and token.
func (s *DARelayState) addDACommit(peerQuotaKey string, commit daRelayCommit) error {
	commit.peerQuotaKey = peerQuotaKey
	s.mu.Lock()
	defer s.mu.Unlock()
	projected := s.cloneForAtomicBatchLocked()
	if _, err := projected.stageDACommitLocked(commit); err != nil {
		return err
	}
	s.publishAtomicBatchLocked(projected)
	return nil
}

// addDAChunk is addDACommit's chunk half and carries the same contract.
func (s *DARelayState) addDAChunk(peerQuotaKey string, chunk daRelayChunk) error {
	chunk.peerQuotaKey = peerQuotaKey
	payload, err := prepareDAChunkPayload(chunk)
	if err != nil {
		return err
	}
	chunk.payload = payload
	s.mu.Lock()
	defer s.mu.Unlock()
	projected := s.cloneForAtomicBatchLocked()
	if _, err := projected.stageDAChunkLocked(chunk); err != nil {
		return err
	}
	s.publishAtomicBatchLocked(projected)
	return nil
}

// stageDACommitLocked installs one commit into the PROJECTED image and reports
// the members the staging dropped, so the caller can turn them into exact victim
// claims. The receiver is the private projection, never live state.
func (s *DARelayState) stageDACommitLocked(commit daRelayCommit) ([]daRelayMemberIdentity, error) {
	if err := validateDACommit(commit); err != nil {
		return nil, err
	}
	record := s.sets[commit.daID].cloneForStateMutation()
	record.ensureMaps()
	if record.commit.chunkCount != 0 {
		return nil, errDARelayDuplicateCommit
	}
	commit.txBytes = cloneBytes(commit.txBytes)
	record.daID = commit.daID
	record.commit = commit
	dropped := record.pruneChunksOutsideCommit()
	record.state = daRelayStateStagedCommit
	record.ttlBlocksRemaining = s.caps.orphanTTLBlocks
	if err := s.advanceAcceptedSequenceLocked(&record); err != nil {
		return nil, err
	}
	completion, err := s.finishStagedDARecordLocked(&record, true)
	if err != nil {
		return nil, err
	}
	return append(dropped, completion...), nil
}

// stageDAChunkLocked installs one chunk into the PROJECTED image. A chunk that
// completes the set with a payload commitment its commit does not confirm is
// REJECTED whole (Section 5.2 chunk-last mismatch): the projection is discarded
// by the caller, so the existing State B record and every claim it owns survive
// byte-identical.
func (s *DARelayState) stageDAChunkLocked(chunk daRelayChunk) ([]daRelayMemberIdentity, error) {
	if err := validateDAChunk(chunk); err != nil {
		return nil, err
	}
	record := s.sets[chunk.daID].cloneForStateMutation()
	record.ensureMaps()
	if err := record.validateChunkInsert(chunk.chunkIndex); err != nil {
		return nil, err
	}
	chunk.txBytes = cloneBytes(chunk.txBytes)
	record.daID = chunk.daID
	if record.commit.chunkCount == 0 {
		record.state = daRelayStateOrphanChunks
		record.ttlBlocksRemaining = s.caps.orphanTTLBlocks
	}
	record.chunks[chunk.chunkIndex] = chunk
	if err := s.advanceAcceptedSequenceLocked(&record); err != nil {
		return nil, err
	}
	return s.finishStagedDARecordLocked(&record, false)
}

// finishStagedDARecordLocked resolves completion for one staged record and
// applies it to the projection.
//
// commitArrival selects Section 5.2's two DIFFERENT mismatch outcomes, and the
// asymmetry is deliberate: the FIRST-SEEN COMMIT is the record's authority, so a
// commit that arrives last and disagrees with the retained chunks keeps its own
// State B record and removes those chunks with their exact claims, while a CHUNK
// that arrives last and disagrees is simply not retained and changes nothing.
func (s *DARelayState) finishStagedDARecordLocked(record *daRelaySetRecord, commitArrival bool) ([]daRelayMemberIdentity, error) {
	var dropped []daRelayMemberIdentity
	if snapshot, complete := record.completionSnapshot(); complete {
		payloadBytes, commitment := snapshot.payloadCommitment()
		switch {
		case commitment == snapshot.payloadCommitmentExpected:
			record.markComplete(payloadBytes)
		case commitArrival:
			dropped = record.dropAllChunks()
		default:
			return nil, errDARelayPayloadCommitmentMismatch
		}
	}
	if err := record.recomputeOrphanTotals(); err != nil {
		return nil, err
	}
	return dropped, s.applyDASetRecordLocked(*record)
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

// prepareDAChunkPayload validates one chunk's context-free shape and returns the
// owned payload copy staging retains.
func prepareDAChunkPayload(chunk daRelayChunk) ([]byte, error) {
	if err := validateDAChunk(chunk); err != nil {
		return nil, err
	}
	if !chunk.hashChecked && sha3.Sum256(chunk.payload) != chunk.chunkHash {
		return nil, errDARelayChunkHashMismatch
	}
	return cloneBytes(chunk.payload), nil
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

// applyDASetRecordLocked installs one record and its locator rows together.
// Every projected accounting value is computed and cap-checked BEFORE the first
// write, so a refused record leaves the image byte-identical.
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
	s.replaceLocatorsLocked(oldRecord, record)
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
	s.replaceLocatorsLocked(record, emptyRecord)
	s.orphanBytes = orphanBytes
	s.applyProjectedPeerBytes(peerBytes)
	s.applyProjectedDAIDBytes(record.daID, daBytes)
	s.orphanCommitOverheadBytes = commitBytes
	s.pinnedPayloadBytes = pinnedBytes
	s.prefetch.releaseSet(record.daID)
	return nil
}

// replaceLocatorsLocked retires the old record's txid rows and installs the new
// one's. It is called by the ONLY two writers of s.sets, which is what keeps the
// locator index and the record image one bijection: a row can be neither
// orphaned by a removal nor duplicated by a restage.
func (s *DARelayState) replaceLocatorsLocked(oldRecord, newRecord daRelaySetRecord) {
	if s.locators == nil {
		s.locators = map[[32]byte]daRelayLocator{}
	}
	for txid, locator := range oldRecord.locators() {
		if s.locators[txid] == locator {
			delete(s.locators, txid)
		}
	}
	for txid, locator := range newRecord.locators() {
		s.locators[txid] = locator
	}
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
