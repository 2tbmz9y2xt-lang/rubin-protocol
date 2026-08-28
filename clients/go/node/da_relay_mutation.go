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
		if victims, err = s.appendDAMemberVictims(victims, removed); err != nil {
			return nil, err
		}
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
// which plans the same member outside the final lock and installs it under it.
func (s *DARelayState) addDACommit(peerQuotaKey string, commit daRelayCommit) error {
	commit.provenance = stagingDAProvenance(commit.provenance, peerQuotaKey)
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
	chunk.provenance = stagingDAProvenance(chunk.provenance, peerQuotaKey)
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

// stagingDAProvenance is the two staging entries' provenance rule. A member's OWN
// provenance is the single authority and is never overwritten; the quota-key
// shorthand names a PEER source only for a member that carries none, so these
// entries produce the same one-field member shape AdmitDA does.
func stagingDAProvenance(current DAProvenance, quotaKey string) DAProvenance {
	if current.kind != daProvenanceInvalid || quotaKey == "" {
		return current
	}
	return DAProvenance{kind: daProvenancePeer, peerIdentity: quotaKey, quotaIdentity: quotaKey}
}

// daRelayStagedMember is ONE member's staging result: the complete new record
// value and the members the staging dropped, so a caller can turn those into
// exact victim claims. It is produced by a PURE function of the current record,
// the caps and the member — no sequence value, no state-level accounting and no
// image.
type daRelayStagedMember struct {
	record  daRelaySetRecord
	dropped []daRelayMemberIdentity
}

func (c daRelayCaps) stageDAMember(current daRelaySetRecord, member daRelayAdmissionMember) (daRelayStagedMember, error) {
	if member.locator.kind == daRelayLocatorCommit {
		return c.stageDACommit(current, member.commit)
	}
	return c.stageDAChunk(current, member.chunk)
}

// stageDACommit builds the record one commit produces from current.
func (c daRelayCaps) stageDACommit(current daRelaySetRecord, commit daRelayCommit) (daRelayStagedMember, error) {
	if err := validateDACommit(commit); err != nil {
		return daRelayStagedMember{}, err
	}
	record := current.cloneForStateMutation()
	record.ensureMaps()
	if record.commit.chunkCount != 0 {
		return daRelayStagedMember{}, errDARelayDuplicateCommit
	}
	commit.txBytes = cloneBytes(commit.txBytes)
	record.daID = commit.daID
	record.commit = commit
	dropped := record.pruneChunksOutsideCommit()
	record.state = daRelayStateStagedCommit
	record.ttlBlocksRemaining = c.orphanTTLBlocks
	completion, err := finishStagedDARecord(&record, true)
	if err != nil {
		return daRelayStagedMember{}, err
	}
	return daRelayStagedMember{record: record, dropped: append(dropped, completion...)}, nil
}

// stageDAChunk is stageDACommit's chunk half. A chunk that completes the set
// with a payload commitment its commit does not confirm is REJECTED whole
// (Section 5.2 chunk-last mismatch): the staged record is discarded by the
// caller, so the existing State B record and every claim it owns survive
// byte-identical.
func (c daRelayCaps) stageDAChunk(current daRelaySetRecord, chunk daRelayChunk) (daRelayStagedMember, error) {
	if err := validateDAChunk(chunk); err != nil {
		return daRelayStagedMember{}, err
	}
	record := current.cloneForStateMutation()
	record.ensureMaps()
	if err := record.validateChunkInsert(chunk.chunkIndex); err != nil {
		return daRelayStagedMember{}, err
	}
	// The payload-hash check runs AFTER the shape and duplicate/index checks, the
	// order the retained schema has always refused in: a duplicate index is a
	// property of the record, a bad hash a property of the candidate.
	if !chunk.hashChecked && sha3.Sum256(chunk.payload) != chunk.chunkHash {
		return daRelayStagedMember{}, errDARelayChunkHashMismatch
	}
	chunk.txBytes = cloneBytes(chunk.txBytes)
	record.daID = chunk.daID
	if record.commit.chunkCount == 0 {
		record.state = daRelayStateOrphanChunks
		record.ttlBlocksRemaining = c.orphanTTLBlocks
	}
	record.chunks[chunk.chunkIndex] = chunk
	dropped, err := finishStagedDARecord(&record, false)
	if err != nil {
		return daRelayStagedMember{}, err
	}
	return daRelayStagedMember{record: record, dropped: dropped}, nil
}

// stageDACommitLocked and stageDAChunkLocked are the IMAGE-level staging entries
// the package-private accounting helpers drive: the pure staging above, then the
// accepted-sequence value, then installation into the image the receiver holds.
// AdmitDA deliberately does NOT use them — it plans the pure half outside the
// final DA lock and installs under it.
func (s *DARelayState) stageDACommitLocked(commit daRelayCommit) ([]daRelayMemberIdentity, error) {
	staged, err := s.caps.stageDACommit(s.sets[commit.daID], commit)
	if err != nil {
		return nil, err
	}
	return staged.dropped, s.applyStagedDAMemberLocked(staged.record)
}

func (s *DARelayState) stageDAChunkLocked(chunk daRelayChunk) ([]daRelayMemberIdentity, error) {
	staged, err := s.caps.stageDAChunk(s.sets[chunk.daID], chunk)
	if err != nil {
		return nil, err
	}
	return staged.dropped, s.applyStagedDAMemberLocked(staged.record)
}

func (s *DARelayState) applyStagedDAMemberLocked(record daRelaySetRecord) error {
	if err := s.advanceAcceptedSequenceLocked(&record); err != nil {
		return err
	}
	return s.applyDASetRecordLocked(record)
}

// finishStagedDARecord resolves completion for one staged record. It is pure:
// it installs nothing and reads no image.
//
// commitArrival selects Section 5.2's two DIFFERENT mismatch outcomes, and the
// asymmetry is deliberate: the FIRST-SEEN COMMIT is the record's authority, so a
// commit that arrives last and disagrees with the retained chunks keeps its own
// State B record and removes those chunks with their exact claims, while a CHUNK
// that arrives last and disagrees is simply not retained and changes nothing.
func finishStagedDARecord(record *daRelaySetRecord, commitArrival bool) ([]daRelayMemberIdentity, error) {
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
	return dropped, record.recomputeOrphanTotals()
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

// prepareDAChunkPayload validates one chunk's context-free SHAPE and returns the
// owned payload copy staging retains. The payload-hash check belongs to staging,
// which runs it after the record's own duplicate/index refusals.
func prepareDAChunkPayload(chunk daRelayChunk) ([]byte, error) {
	if err := validateDAChunk(chunk); err != nil {
		return nil, err
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

// daRelayRecordImage is everything about ONE record transition that is a PURE
// function of the two record values: the accounting and pinned payload each side
// implies, and the exact locator rows the old one retires and the new one
// installs. DERIVING it walks both records and builds four maps; APPLYING it is
// arithmetic and assignment.
//
// The split exists so the admission path can derive the image while PLANNING and
// leave the lock window with nothing to walk, build or decide
// (RUBIN_COMPACT_BLOCKS.md Section 5.1: all allocation, locator, record and
// accounting planning precedes the final DA lock).
type daRelayRecordImage struct {
	oldAccounting daRelayRecordAccounting
	newAccounting daRelayRecordAccounting
	oldPinned     uint64
	newPinned     uint64
	retire        map[[32]byte]daRelayLocator
	install       map[[32]byte]daRelayLocator
}

func daRelayRecordImageOf(oldRecord, newRecord daRelaySetRecord) (daRelayRecordImage, error) {
	oldAccounting, err := oldRecord.orphanAccounting()
	if err != nil {
		return daRelayRecordImage{}, err
	}
	newAccounting, err := newRecord.orphanAccounting()
	if err != nil {
		return daRelayRecordImage{}, err
	}
	return daRelayRecordImage{
		oldAccounting: oldAccounting,
		newAccounting: newAccounting,
		oldPinned:     oldRecord.pinnedPayloadAccountingBytes(),
		newPinned:     newRecord.pinnedPayloadAccountingBytes(),
		retire:        oldRecord.locators(),
		install:       newRecord.locators(),
	}, nil
}

// daRelayRecordPlacement is one record's fully computed, cap-checked placement:
// the locator rows to retire and install, the record revision to stamp, and the
// new ABSOLUTE value of every counter the record touches.
type daRelayRecordPlacement struct {
	retire      map[[32]byte]daRelayLocator
	install     map[[32]byte]daRelayLocator
	revision    uint64
	orphanBytes uint64
	peerBytes   map[string]uint64
	daBytes     uint64
	commitBytes uint64
	pinnedBytes uint64
}

// applyDASetRecordLocked installs one record and its locator rows together.
// Every projected accounting value is computed and cap-checked BEFORE the first
// write, so a refused record leaves the image byte-identical.
func (s *DARelayState) applyDASetRecordLocked(record daRelaySetRecord) error {
	placement, err := s.projectDASetRecordLocked(record)
	if err != nil {
		return err
	}
	s.installDASetRecordLocked(record, placement)
	return nil
}

// projectDASetRecordLocked is the FALLIBLE half for a caller that has NOT already
// derived the record image: it derives it here and projects it. The admission
// path deliberately does not use it — it carries the image in its plan.
func (s *DARelayState) projectDASetRecordLocked(record daRelaySetRecord) (daRelayRecordPlacement, error) {
	image, err := daRelayRecordImageOf(s.sets[record.daID], record)
	if err != nil {
		return daRelayRecordPlacement{}, err
	}
	return s.projectDARecordImageLocked(record.daID, image)
}

// projectDARecordImageLocked cap-checks one already-derived record image against
// the LIVE counters and mints the record revision. It is checked arithmetic over
// values the image carries, and it mutates nothing.
//
// The live counters and the revision high-water are deliberately NOT part of the
// image: they are shared by every record, so re-deriving them here is what lets a
// concurrent admission of a DIFFERENT record neither invalidate this projection
// nor be lost to it. A REMOVAL shares this projection and so also refuses at the
// exhausted revision ceiling, though it consumes no revision — fail-closed is the
// posture a state whose record-identity source is exhausted should take.
func (s *DARelayState) projectDARecordImageLocked(daID [32]byte, image daRelayRecordImage) (daRelayRecordPlacement, error) {
	orphanBytes, peerBytes, daBytes, commitBytes, err := s.projectOrphanAccountingDeltaLocked(daID, image)
	if err != nil {
		return daRelayRecordPlacement{}, err
	}
	pinnedBytes, err := s.projectPinnedPayloadDeltaLocked(image)
	if err != nil {
		return daRelayRecordPlacement{}, err
	}
	revision, err := s.nextRecordRevisionLocked()
	if err != nil {
		return daRelayRecordPlacement{}, err
	}
	return daRelayRecordPlacement{
		retire:      image.retire,
		install:     image.install,
		revision:    revision,
		orphanBytes: orphanBytes,
		peerBytes:   peerBytes,
		daBytes:     daBytes,
		commitBytes: commitBytes,
		pinnedBytes: pinnedBytes,
	}, nil
}

// installDASetRecordLocked is the NON-FALLIBLE half: assignment only. Nothing
// here walks a record, builds a map, derives a value or can fail — the placement
// carries every one of those already — which is what lets the admission path run
// it AFTER the owner reserve. It must be called with the placement projected for
// THIS record, under the same lock hold.
func (s *DARelayState) installDASetRecordLocked(record daRelaySetRecord, placement daRelayRecordPlacement) {
	s.stampRecordLocked(&record, placement.revision)
	s.sets[record.daID] = record
	s.replaceLocatorsLocked(placement)
	s.orphanBytes = placement.orphanBytes
	s.applyProjectedPeerBytes(placement.peerBytes)
	s.applyProjectedDAIDBytes(record.daID, placement.daBytes)
	s.orphanCommitOverheadBytes = placement.commitBytes
	s.pinnedPayloadBytes = placement.pinnedBytes
	if record.receivedTime > s.nextReceivedTime {
		s.nextReceivedTime = record.receivedTime
	}
}

func (s *DARelayState) removeDASetRecordLocked(record daRelaySetRecord) error {
	image, err := daRelayRecordImageOf(record, daRelaySetRecord{daID: record.daID})
	if err != nil {
		return err
	}
	placement, err := s.projectDARecordImageLocked(record.daID, image)
	if err != nil {
		return err
	}
	delete(s.sets, record.daID)
	s.replaceLocatorsLocked(placement)
	s.orphanBytes = placement.orphanBytes
	s.applyProjectedPeerBytes(placement.peerBytes)
	s.applyProjectedDAIDBytes(record.daID, placement.daBytes)
	s.orphanCommitOverheadBytes = placement.commitBytes
	s.pinnedPayloadBytes = placement.pinnedBytes
	s.prefetch.releaseSet(record.daID)
	return nil
}

// replaceLocatorsLocked retires the rows the placement's image named for the old
// record and installs the ones it named for the new. It is called by the only two
// writers that change record MEMBERSHIP (installMemberTokenLocked and the TTL
// decrement also assign s.sets, but never add or remove a member), which is what
// keeps the locator index and the record image one bijection: a row can be
// neither orphaned by a removal nor duplicated by a restage.
func (s *DARelayState) replaceLocatorsLocked(placement daRelayRecordPlacement) {
	if s.locators == nil {
		s.locators = map[[32]byte]daRelayLocator{}
	}
	for txid, locator := range placement.retire {
		if s.locators[txid] == locator {
			delete(s.locators, txid)
		}
	}
	for txid, locator := range placement.install {
		s.locators[txid] = locator
	}
	// A ZERO txid is not an identity and must never be locatable: it is the shape
	// the package-private staging entry produces for a member with no admission
	// snapshot, and indexing it would make LookupRetainedTx resolve the zero txid
	// to whichever record wrote last.
	delete(s.locators, [32]byte{})
}

func (s *DARelayState) projectOrphanAccountingDeltaLocked(daID [32]byte, image daRelayRecordImage) (uint64, map[string]uint64, uint64, uint64, error) {
	oldAccounting, newAccounting := image.oldAccounting, image.newAccounting
	orphanBytes, err := checkedApplyUint64DeltaCap(s.orphanBytes, oldAccounting.orphanBytes, newAccounting.orphanBytes, s.caps.orphanPoolBytes, errDARelayOrphanPoolCapExceeded)
	if err != nil {
		return 0, nil, 0, 0, err
	}
	daBytes, err := checkedApplyUint64DeltaCap(s.orphanBytesByDAID[daID], oldAccounting.orphanBytes, newAccounting.orphanBytes, s.caps.orphanPoolPerDAIDBytes, errDARelayOrphanDAIDCapExceeded)
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

func (s *DARelayState) projectPinnedPayloadDeltaLocked(image daRelayRecordImage) (uint64, error) {
	pinnedBytes, err := checkedApplyUint64Delta(s.pinnedPayloadBytes, image.oldPinned, image.newPinned)
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
