package p2p

import (
	"bytes"
	"crypto/sha3"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

const (
	daOrphanPoolSizeBytes           uint64 = 64 << 20
	daOrphanPoolPerPeerMaxBytes     uint64 = 4 << 20
	daOrphanPoolPerDAIDMaxBytes     uint64 = 8 << 20
	daOrphanCommitOverheadMaxBytes  uint64 = 8 << 20
	daOrphanTTLBlocks               uint64 = 3
	daMempoolPinnedPayloadMaxBytes  uint64 = 96_000_000
	daCompleteSetRecordFootprint    uint64 = 256
	daCompleteSetChunkFootprint     uint64 = 128
	daPrefetchPerPeerBytesPerSecond uint64 = 4_000_000
	daPrefetchGlobalBytesPerSecond  uint64 = 32_000_000
	daPrefetchMaxConcurrentSets            = 8
	daPrefetchRequestTTL                   = time.Second
)

type daRelaySetState uint8

const (
	daRelayStateOrphanChunks daRelaySetState = iota
	daRelayStateStagedCommit
	daRelayStateCompleteSet
)

type daRelayCaps struct {
	orphanPoolBytes           uint64
	orphanPoolPerPeerBytes    uint64
	orphanPoolPerDAIDBytes    uint64
	orphanCommitOverheadBytes uint64
	orphanTTLBlocks           uint64
	pinnedPayloadBytes        uint64
}

func defaultDARelayCaps() daRelayCaps {
	return daRelayCaps{
		orphanPoolBytes:           daOrphanPoolSizeBytes,
		orphanPoolPerPeerBytes:    daOrphanPoolPerPeerMaxBytes,
		orphanPoolPerDAIDBytes:    daOrphanPoolPerDAIDMaxBytes,
		orphanCommitOverheadBytes: daOrphanCommitOverheadMaxBytes,
		orphanTTLBlocks:           daOrphanTTLBlocks,
		pinnedPayloadBytes:        daMempoolPinnedPayloadMaxBytes,
	}
}

func (c daRelayCaps) validate() error {
	if err := c.validatePositiveCaps(); err != nil {
		return err
	}
	return c.validateRelativeCaps()
}

func (c daRelayCaps) validatePositiveCaps() error {
	checks := []struct {
		value   uint64
		message string
	}{
		{value: c.orphanPoolBytes, message: "da orphan pool cap is zero"},
		{value: c.orphanPoolPerPeerBytes, message: "da orphan pool per-peer cap is zero"},
		{value: c.orphanPoolPerDAIDBytes, message: "da orphan pool per-da_id cap is zero"},
		{value: c.orphanCommitOverheadBytes, message: "da orphan commit overhead cap is zero"},
		{value: c.orphanTTLBlocks, message: "da orphan ttl is zero"},
		{value: c.pinnedPayloadBytes, message: "da pinned payload cap is zero"},
	}
	for _, check := range checks {
		if check.value == 0 {
			return errors.New(check.message)
		}
	}
	return nil
}

func (c daRelayCaps) validateRelativeCaps() error {
	checks := []struct {
		value   uint64
		limit   uint64
		message string
	}{
		{value: c.orphanPoolPerPeerBytes, limit: c.orphanPoolBytes, message: "da orphan pool per-peer cap exceeds global cap"},
		{value: c.orphanPoolPerDAIDBytes, limit: c.orphanPoolBytes, message: "da orphan pool per-da_id cap exceeds global cap"},
		{value: c.orphanCommitOverheadBytes, limit: c.orphanPoolBytes, message: "da orphan commit overhead cap exceeds global cap"},
	}
	for _, check := range checks {
		if check.value > check.limit {
			return errors.New(check.message)
		}
	}
	return nil
}

type daRelaySetRecord struct {
	daID               [32]byte
	state              daRelaySetState
	receivedTime       uint64
	payloadBytes       uint64
	wireBytes          uint64
	ttlBlocksRemaining uint64
	commit             daRelayCommit
	chunks             map[uint16]daRelayChunk
	replaceableChunks  map[uint16]bool
}

type daRelayEvictionAccounting struct {
	daID         [32]byte
	payloadBytes uint64
	wireBytes    uint64
	receivedTime uint64
}

type daRelayExpiredSet struct {
	daID               [32]byte
	state              daRelaySetState
	commitPeerQuotaKey string
	receivedTime       uint64
}

type daRelayPrefetchState struct {
	indexes map[[32]byte]map[uint16]string
	expires map[[32]byte]time.Time
}

type daRelayPrefetchPlan struct {
	daID    [32]byte
	peerKey string
	indexes []uint16
}

type daRelayCommit struct {
	daID              [32]byte
	payloadCommitment [32]byte
	peerQuotaKey      string
	chunkCount        uint16
	wireBytes         uint64
}

type daRelayChunk struct {
	daID         [32]byte
	chunkHash    [32]byte
	peerQuotaKey string
	chunkIndex   uint16
	payload      []byte
	wireBytes    uint64
}

type daRelayCompletionSnapshot struct {
	daID                      [32]byte
	payloadCommitmentExpected [32]byte
	chunkCount                uint16
	chunks                    []daRelayCompletionChunkSnapshot
}

type daRelayCompletionChunkSnapshot struct {
	chunkHash  [32]byte
	chunkIndex uint16
	payload    []byte
}

var (
	errDARelayDuplicateCommit           = errors.New("duplicate da commit")
	errDARelayDuplicateChunk            = errors.New("duplicate da chunk")
	errDARelayChunkCountInvalid         = errors.New("da commit chunk count invalid")
	errDARelayChunkIndexOutOfRange      = errors.New("da chunk index out of range")
	errDARelayChunkIndexOutsideCommit   = errors.New("da chunk index outside commit")
	errDARelayOrphanPoolCapExceeded     = errors.New("da orphan pool cap exceeded")
	errDARelayOrphanPeerCapExceeded     = errors.New("da orphan pool per-peer cap exceeded")
	errDARelayOrphanDAIDCapExceeded     = errors.New("da orphan pool per-da_id cap exceeded")
	errDARelayOrphanCommitCapExceeded   = errors.New("da orphan commit overhead cap exceeded")
	errDARelayChunkHashMismatch         = errors.New("da chunk hash mismatch")
	errDARelayChunkPayloadSizeInvalid   = errors.New("da chunk payload size invalid")
	errDARelayPayloadCommitmentMismatch = errors.New("da payload commitment mismatch")
	errDARelayWireBytesInvalid          = errors.New("da relay wire bytes invalid")
	errDARelayPinnedPayloadCapExceeded  = errors.New("da pinned payload cap exceeded")
	errDARelayArithmeticOverflow        = errors.New("da relay arithmetic overflow")
)

type daRelayRecordAccounting struct {
	orphanBytes uint64
	commitBytes uint64
	peerBytes   map[string]uint64
}

type daRelayState struct {
	mu                        sync.Mutex
	caps                      daRelayCaps
	prefetch                  daRelayPrefetchState
	nextReceivedTime          uint64
	orphanBytes               uint64
	orphanBytesByPeerQuotaKey map[string]uint64
	orphanBytesByDAID         map[[32]byte]uint64
	orphanCommitOverheadBytes uint64
	pinnedPayloadBytes        uint64
	sets                      map[[32]byte]daRelaySetRecord
}

func newDARelayState(caps daRelayCaps) (*daRelayState, error) {
	if err := caps.validate(); err != nil {
		return nil, err
	}
	return &daRelayState{
		caps:                      caps,
		orphanBytesByPeerQuotaKey: map[string]uint64{},
		orphanBytesByDAID:         map[[32]byte]uint64{},
		sets:                      make(map[[32]byte]daRelaySetRecord),
	}, nil
}

func (s *daRelayState) nextMonotonicReceivedTime() (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	receivedTime, err := s.nextReceivedTimeLocked()
	if err != nil {
		return 0, err
	}
	s.nextReceivedTime = receivedTime
	return receivedTime, nil
}

func (s *daRelayState) nextReceivedTimeLocked() (uint64, error) {
	return checkedAddUint64(s.nextReceivedTime, 1)
}

func (s *daRelayState) assignFirstSeenReceivedTimeLocked(record *daRelaySetRecord) error {
	if record.receivedTime != 0 {
		return nil
	}
	receivedTime, err := s.nextReceivedTimeLocked()
	if err != nil {
		return err
	}
	record.receivedTime = receivedTime
	return nil
}

func (s *daRelayState) setOrphanBytesForPeer(peerAddr string, bytes uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := peerQuotaKey(peerAddr)
	if bytes == 0 {
		delete(s.orphanBytesByPeerQuotaKey, key)
		return
	}
	s.orphanBytesByPeerQuotaKey[key] = bytes
}

func (s *daRelayState) orphanBytesForPeer(peerAddr string) uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.orphanBytesByPeerQuotaKey[peerQuotaKey(peerAddr)]
}

func (s *daRelayState) setOrphanBytesForDAID(daID [32]byte, bytes uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if bytes == 0 {
		delete(s.orphanBytesByDAID, daID)
		return
	}
	s.orphanBytesByDAID[daID] = bytes
}

func (s *daRelayState) orphanBytesForDAID(daID [32]byte) uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.orphanBytesByDAID[daID]
}

func (s *daRelayState) advanceOrphanTTL() ([]daRelayExpiredSet, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var expired []daRelayExpiredSet
	for _, daID := range s.sortedIncompleteDAIDsLocked() {
		record := s.sets[daID]
		if record.ttlBlocksRemaining > 1 {
			record.ttlBlocksRemaining--
			s.sets[daID] = record
			continue
		}
		if err := s.removeDASetRecordLocked(record); err != nil {
			return nil, err
		}
		expired = append(expired, daRelayExpiredSet{
			daID:               record.daID,
			state:              record.state,
			commitPeerQuotaKey: record.commit.peerQuotaKey,
			receivedTime:       record.receivedTime,
		})
	}
	return expired, nil
}

func (s *daRelayState) releasePeerQuotaKey(key string) error {
	if s == nil {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.orphanBytesByPeerQuotaKey[key] == 0 {
		return nil
	}

	for _, daID := range s.sortedIncompleteDAIDsLocked() {
		record := s.sets[daID]
		updated, changed, err := record.withoutPeerQuotaKey(key)
		if err != nil {
			return err
		}
		if !changed {
			continue
		}
		if updated.emptyIncomplete() {
			if err := s.removeDASetRecordLocked(record); err != nil {
				return err
			}
			continue
		}
		if err := s.applyDASetRecordLocked(updated); err != nil {
			return err
		}
	}
	return nil
}

func (s *daRelayState) sortedIncompleteDAIDsLocked() [][32]byte {
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

func (s *daRelayState) addDACommit(peerAddr string, commit daRelayCommit) (daRelaySetRecord, error) {
	if commit.chunkCount == 0 || uint64(commit.chunkCount) > consensus.MAX_DA_CHUNK_COUNT {
		return daRelaySetRecord{}, errDARelayChunkCountInvalid
	}
	if commit.wireBytes == 0 {
		return daRelaySetRecord{}, errDARelayWireBytesInvalid
	}

	for {
		s.mu.Lock()
		record, err := s.stageDACommitRecordLocked(peerAddr, commit)
		if err != nil {
			s.mu.Unlock()
			return daRelaySetRecord{}, err
		}
		snapshot, complete := record.completionSnapshot()
		if !complete {
			if err := record.recomputeOrphanTotals(); err != nil {
				s.mu.Unlock()
				return daRelaySetRecord{}, err
			}
			if err := s.applyDASetRecordLocked(record); err != nil {
				s.mu.Unlock()
				return daRelaySetRecord{}, err
			}
			s.mu.Unlock()
			return record.clone(), nil
		}
		s.mu.Unlock()

		payloadBytes, payloadCommitment := snapshot.payloadCommitment()
		if payloadCommitment != snapshot.payloadCommitmentExpected {
			// Commit metadata is the first-seen authority for duplicate handling;
			// orphan chunks are provisional until they match that commit.
			applied, err := s.stageCommitDroppingMatchingCompletionChunks(peerAddr, commit, snapshot)
			if err != nil {
				return daRelaySetRecord{}, err
			}
			if !applied {
				continue
			}
			return daRelaySetRecord{}, errDARelayPayloadCommitmentMismatch
		}

		s.mu.Lock()
		record, err = s.stageDACommitRecordLocked(peerAddr, commit)
		if err != nil {
			s.mu.Unlock()
			return daRelaySetRecord{}, err
		}
		if !snapshot.matchesRecord(record) {
			s.mu.Unlock()
			continue
		}
		record.markComplete(payloadBytes)
		if err := record.recomputeOrphanTotals(); err != nil {
			s.mu.Unlock()
			return daRelaySetRecord{}, err
		}
		if err := s.applyDASetRecordLocked(record); err != nil {
			s.mu.Unlock()
			return daRelaySetRecord{}, err
		}
		s.mu.Unlock()
		return record.clone(), nil
	}
}

func (s *daRelayState) addDAChunk(peerAddr string, chunk daRelayChunk) (daRelaySetRecord, error) {
	if err := validateDAChunk(chunk); err != nil {
		return daRelaySetRecord{}, err
	}

	s.mu.Lock()
	record := s.sets[chunk.daID]
	if err := record.validateChunkInsert(chunk.chunkIndex); err != nil {
		s.mu.Unlock()
		return daRelaySetRecord{}, err
	}
	s.mu.Unlock()

	if sha3.Sum256(chunk.payload) != chunk.chunkHash {
		return daRelaySetRecord{}, errDARelayChunkHashMismatch
	}
	payload := cloneBytes(chunk.payload)

	for {
		s.mu.Lock()
		record, err := s.stageDAChunkRecordLocked(peerAddr, chunk, payload)
		if err != nil {
			s.mu.Unlock()
			return daRelaySetRecord{}, err
		}
		snapshot, complete := record.completionSnapshot()
		if !complete {
			if err := record.recomputeOrphanTotals(); err != nil {
				s.mu.Unlock()
				return daRelaySetRecord{}, err
			}
			if err := s.applyDASetRecordLocked(record); err != nil {
				s.mu.Unlock()
				return daRelaySetRecord{}, err
			}
			s.mu.Unlock()
			return record.clone(), nil
		}
		s.mu.Unlock()

		payloadBytes, payloadCommitment := snapshot.payloadCommitment()
		if payloadCommitment != snapshot.payloadCommitmentExpected {
			retry, err := s.markMatchingCompletionChunksReplaceable(snapshot)
			if err != nil {
				return daRelaySetRecord{}, err
			}
			if retry {
				continue
			}
			return daRelaySetRecord{}, errDARelayPayloadCommitmentMismatch
		}

		s.mu.Lock()
		record, err = s.stageDAChunkRecordLocked(peerAddr, chunk, payload)
		if err != nil {
			s.mu.Unlock()
			return daRelaySetRecord{}, err
		}
		if !snapshot.matchesRecord(record) {
			s.mu.Unlock()
			continue
		}
		record.markComplete(payloadBytes)
		if err := record.recomputeOrphanTotals(); err != nil {
			s.mu.Unlock()
			return daRelaySetRecord{}, err
		}
		if err := s.applyDASetRecordLocked(record); err != nil {
			s.mu.Unlock()
			return daRelaySetRecord{}, err
		}
		s.mu.Unlock()
		return record.clone(), nil
	}
}

func (s *daRelayState) stageDACommitRecordLocked(peerAddr string, commit daRelayCommit) (daRelaySetRecord, error) {
	record := s.sets[commit.daID].cloneForStateMutation()
	record.ensureMaps()
	if record.commit.chunkCount != 0 {
		return daRelaySetRecord{}, errDARelayDuplicateCommit
	}
	c := commit
	c.peerQuotaKey = peerQuotaKey(peerAddr)
	record.daID = c.daID
	record.commit = c
	record.pruneChunksOutsideCommit()
	record.state = daRelayStateStagedCommit
	record.ttlBlocksRemaining = s.caps.orphanTTLBlocks
	if err := s.assignFirstSeenReceivedTimeLocked(&record); err != nil {
		return daRelaySetRecord{}, err
	}
	return record, nil
}

func (s *daRelayState) stageDAChunkRecordLocked(peerAddr string, chunk daRelayChunk, payload []byte) (daRelaySetRecord, error) {
	record := s.sets[chunk.daID].cloneForStateMutation()
	record.ensureMaps()
	if err := record.validateChunkInsert(chunk.chunkIndex); err != nil {
		return daRelaySetRecord{}, err
	}
	chunk.peerQuotaKey = peerQuotaKey(peerAddr)
	record.daID = chunk.daID
	if record.commit.chunkCount == 0 {
		record.state = daRelayStateOrphanChunks
		record.ttlBlocksRemaining = s.caps.orphanTTLBlocks
	}
	chunk.payload = payload
	record.chunks[chunk.chunkIndex] = chunk
	delete(record.replaceableChunks, chunk.chunkIndex)
	if err := s.assignFirstSeenReceivedTimeLocked(&record); err != nil {
		return daRelaySetRecord{}, err
	}
	return record, nil
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

func (s *daRelayState) applyDASetRecordLocked(record daRelaySetRecord) error {
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

func (s *daRelayState) removeDASetRecordLocked(record daRelaySetRecord) error {
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
	return nil
}

func (s *daRelayState) projectOrphanAccountingDeltaLocked(oldRecord, newRecord daRelaySetRecord) (uint64, map[string]uint64, uint64, uint64, error) {
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

func (s *daRelayState) projectPinnedPayloadDeltaLocked(oldRecord, newRecord daRelaySetRecord) (uint64, error) {
	oldPinnedBytes, err := oldRecord.pinnedPayloadAccountingBytes()
	if err != nil {
		return 0, err
	}
	newPinnedBytes, err := newRecord.pinnedPayloadAccountingBytes()
	if err != nil {
		return 0, err
	}
	pinnedBytes, err := checkedApplyUint64Delta(s.pinnedPayloadBytes, oldPinnedBytes, newPinnedBytes)
	if err != nil {
		return 0, err
	}
	if pinnedBytes > s.caps.pinnedPayloadBytes {
		return 0, errDARelayPinnedPayloadCapExceeded
	}
	return pinnedBytes, nil
}

func (s *daRelayState) projectPeerAccountingDeltaLocked(oldPeerBytes, newPeerBytes map[string]uint64) (map[string]uint64, error) {
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

func (s *daRelayState) applyProjectedPeerBytes(projected map[string]uint64) {
	for key, bytes := range projected {
		if bytes == 0 {
			delete(s.orphanBytesByPeerQuotaKey, key)
			continue
		}
		s.orphanBytesByPeerQuotaKey[key] = bytes
	}
}

func (s *daRelayState) applyProjectedDAIDBytes(daID [32]byte, bytes uint64) {
	if bytes == 0 {
		delete(s.orphanBytesByDAID, daID)
		return
	}
	s.orphanBytesByDAID[daID] = bytes
}

func (r daRelaySetRecord) missingChunkIndexes() []uint16 {
	if r.commit.chunkCount == 0 || r.state == daRelayStateCompleteSet {
		return nil
	}
	var missing []uint16
	for i := uint16(0); i < r.commit.chunkCount; i++ {
		_, ok := r.chunks[i]
		if !ok || r.replaceableChunks[i] {
			missing = append(missing, i)
		}
	}
	return missing
}

func (r daRelaySetRecord) evictionAccounting() (daRelayEvictionAccounting, bool) {
	if r.state != daRelayStateCompleteSet || r.payloadBytes == 0 || r.wireBytes == 0 || r.receivedTime == 0 {
		return daRelayEvictionAccounting{}, false
	}
	return daRelayEvictionAccounting{
		daID:         r.daID,
		payloadBytes: r.payloadBytes,
		wireBytes:    r.wireBytes,
		receivedTime: r.receivedTime,
	}, true
}

func (r daRelaySetRecord) clone() daRelaySetRecord {
	return r.cloneWithPayloads(true)
}

func (r daRelaySetRecord) cloneForStateMutation() daRelaySetRecord {
	return r.cloneWithPayloads(false)
}

func (r daRelaySetRecord) cloneWithPayloads(copyPayloads bool) daRelaySetRecord {
	out := r
	if r.chunks != nil {
		out.chunks = make(map[uint16]daRelayChunk, len(r.chunks))
		for index, chunk := range r.chunks {
			if copyPayloads {
				chunk.payload = cloneBytes(chunk.payload)
			}
			out.chunks[index] = chunk
		}
	}
	if r.replaceableChunks != nil {
		out.replaceableChunks = make(map[uint16]bool, len(r.replaceableChunks))
		for index, replaceable := range r.replaceableChunks {
			out.replaceableChunks[index] = replaceable
		}
	}
	return out
}

func (r *daRelaySetRecord) ensureMaps() {
	if r.chunks == nil {
		r.chunks = map[uint16]daRelayChunk{}
	}
}

func (r *daRelaySetRecord) pruneChunksOutsideCommit() {
	for index := range r.chunks {
		if index >= r.commit.chunkCount {
			delete(r.chunks, index)
			delete(r.replaceableChunks, index)
		}
	}
}

func (r daRelaySetRecord) withoutPeerQuotaKey(key string) (daRelaySetRecord, bool, error) {
	if r.state == daRelayStateCompleteSet || r.wireBytes == 0 {
		return r, false, nil
	}

	out := r.cloneForStateMutation()
	changed := out.dropCommitForPeerQuotaKey(key)
	if out.dropChunksForPeerQuotaKey(key) {
		changed = true
	}
	if !changed {
		return r, false, nil
	}
	out.payloadBytes = 0
	if out.commit.chunkCount == 0 {
		out.state = daRelayStateOrphanChunks
		out.replaceableChunks = nil
	}
	if out.emptyIncomplete() {
		out.wireBytes = 0
		return out, true, nil
	}
	if err := out.recomputeOrphanTotals(); err != nil {
		return daRelaySetRecord{}, false, err
	}
	return out, true, nil
}

func (r *daRelaySetRecord) dropCommitForPeerQuotaKey(key string) bool {
	if r.commit.wireBytes == 0 || r.commit.peerQuotaKey != key {
		return false
	}
	r.commit = daRelayCommit{}
	r.replaceableChunks = nil
	return true
}

func (r *daRelaySetRecord) dropChunksForPeerQuotaKey(key string) bool {
	changed := false
	for index, chunk := range r.chunks {
		if chunk.wireBytes == 0 || chunk.peerQuotaKey != key {
			continue
		}
		delete(r.chunks, index)
		delete(r.replaceableChunks, index)
		changed = true
	}
	return changed
}

func (r daRelaySetRecord) emptyIncomplete() bool {
	return r.state != daRelayStateCompleteSet && r.commit.chunkCount == 0 && len(r.chunks) == 0
}

func (r daRelaySetRecord) validateChunkInsert(chunkIndex uint16) error {
	if _, exists := r.chunks[chunkIndex]; exists {
		if r.replaceableChunks[chunkIndex] {
			return nil
		}
		return errDARelayDuplicateChunk
	}
	if r.commit.chunkCount != 0 && chunkIndex >= r.commit.chunkCount {
		return errDARelayChunkIndexOutsideCommit
	}
	return nil
}

func (r daRelaySetRecord) completionSnapshot() (daRelayCompletionSnapshot, bool) {
	if r.commit.chunkCount == 0 || r.state == daRelayStateCompleteSet || len(r.missingChunkIndexes()) != 0 {
		return daRelayCompletionSnapshot{}, false
	}
	snapshot := daRelayCompletionSnapshot{
		daID:                      r.daID,
		payloadCommitmentExpected: r.commit.payloadCommitment,
		chunkCount:                r.commit.chunkCount,
		chunks:                    make([]daRelayCompletionChunkSnapshot, 0, r.commit.chunkCount),
	}
	for i := uint16(0); i < r.commit.chunkCount; i++ {
		chunk, ok := r.chunks[i]
		if !ok {
			return daRelayCompletionSnapshot{}, false
		}
		snapshot.chunks = append(snapshot.chunks, daRelayCompletionChunkSnapshot{
			chunkHash:  chunk.chunkHash,
			chunkIndex: i,
			payload:    chunk.payload,
		})
	}
	return snapshot, true
}

func (s daRelayCompletionSnapshot) payloadCommitment() (uint64, [32]byte) {
	hasher := sha3.New256()
	var payloadBytes uint64
	for _, chunk := range s.chunks {
		payloadBytes += uint64(len(chunk.payload))
		_, _ = hasher.Write(chunk.payload)
	}
	var payloadCommitment [32]byte
	copy(payloadCommitment[:], hasher.Sum(nil))
	return payloadBytes, payloadCommitment
}

func (s *daRelayState) stageCommitDroppingMatchingCompletionChunks(peerAddr string, commit daRelayCommit, snapshot daRelayCompletionSnapshot) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	record, err := s.stageDACommitRecordLocked(peerAddr, commit)
	if err != nil {
		return false, err
	}
	if !snapshot.matchesRecord(record) {
		return false, nil
	}
	indexesToDrop, ok := record.matchingCompletionChunkIndexes(snapshot)
	if !ok {
		return false, nil
	}
	record.dropChunks(indexesToDrop)
	record.payloadBytes = 0
	record.state = daRelayStateStagedCommit
	if err := record.recomputeOrphanTotals(); err != nil {
		return false, err
	}
	if err := s.applyDASetRecordLocked(record); err != nil {
		return false, err
	}
	return true, nil
}

func (s *daRelayState) markMatchingCompletionChunksReplaceable(snapshot daRelayCompletionSnapshot) (retry bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	record := s.sets[snapshot.daID].cloneForStateMutation()
	if record.state == daRelayStateCompleteSet || record.commit.chunkCount != snapshot.chunkCount || record.commit.payloadCommitment != snapshot.payloadCommitmentExpected {
		return true, nil
	}
	indexes, ok := record.matchingCompletionChunkIndexes(snapshot)
	if !ok {
		return false, nil
	}
	if len(indexes) != len(snapshot.chunks) {
		return false, nil
	}
	record.markChunksReplaceable(indexes)
	if err := s.applyDASetRecordLocked(record); err != nil {
		return false, err
	}
	return false, nil
}

func (r daRelaySetRecord) matchingCompletionChunkIndexes(snapshot daRelayCompletionSnapshot) ([]uint16, bool) {
	indexes := make([]uint16, 0, len(snapshot.chunks))
	for _, snapshotChunk := range snapshot.chunks {
		chunk, ok := r.chunks[snapshotChunk.chunkIndex]
		if !ok {
			continue
		}
		if chunk.chunkHash != snapshotChunk.chunkHash || len(chunk.payload) != len(snapshotChunk.payload) {
			return nil, false
		}
		indexes = append(indexes, snapshotChunk.chunkIndex)
	}
	return indexes, true
}

func (r *daRelaySetRecord) dropChunks(indexes []uint16) {
	for _, index := range indexes {
		delete(r.chunks, index)
		delete(r.replaceableChunks, index)
	}
}

func (r *daRelaySetRecord) markChunksReplaceable(indexes []uint16) {
	if r.replaceableChunks == nil {
		r.replaceableChunks = map[uint16]bool{}
	}
	for _, index := range indexes {
		r.replaceableChunks[index] = true
	}
}

func (s daRelayCompletionSnapshot) matchesRecord(r daRelaySetRecord) bool {
	current, ok := r.completionSnapshot()
	if !ok {
		return false
	}
	return s.matchesHeader(current) && completionChunksMatch(s.chunks, current.chunks)
}

func (s daRelayCompletionSnapshot) matchesHeader(current daRelayCompletionSnapshot) bool {
	return current.daID == s.daID &&
		current.payloadCommitmentExpected == s.payloadCommitmentExpected &&
		current.chunkCount == s.chunkCount
}

func completionChunksMatch(expected, current []daRelayCompletionChunkSnapshot) bool {
	if len(current) != len(expected) {
		return false
	}
	for i := range expected {
		if !completionChunkMatches(expected[i], current[i]) {
			return false
		}
	}
	return true
}

func completionChunkMatches(expected, current daRelayCompletionChunkSnapshot) bool {
	return current.chunkIndex == expected.chunkIndex &&
		current.chunkHash == expected.chunkHash &&
		len(current.payload) == len(expected.payload)
}

func (r *daRelaySetRecord) markComplete(payloadBytes uint64) {
	r.payloadBytes = payloadBytes
	r.state = daRelayStateCompleteSet
	r.ttlBlocksRemaining = 0
	r.replaceableChunks = nil
}

func (r *daRelaySetRecord) recomputeOrphanTotals() error {
	r.wireBytes = r.commit.wireBytes
	for _, chunk := range r.chunks {
		var err error
		r.wireBytes, err = checkedAddUint64(r.wireBytes, chunk.wireBytes)
		if err != nil {
			return err
		}
	}
	return nil
}

func (r daRelaySetRecord) pinnedPayloadAccountingBytes() (uint64, error) {
	if r.state != daRelayStateCompleteSet || r.payloadBytes == 0 {
		return 0, nil
	}
	footprint := r.wireBytes
	if footprint == 0 {
		footprint = r.payloadBytes
	}
	var err error
	footprint, err = checkedAddUint64(footprint, daCompleteSetRecordFootprint)
	if err != nil {
		return 0, err
	}
	chunkFootprint := uint64(r.commit.chunkCount) * daCompleteSetChunkFootprint
	footprint, err = checkedAddUint64(footprint, chunkFootprint)
	if err != nil {
		return 0, err
	}
	return footprint, nil
}

func (r daRelaySetRecord) orphanAccounting() (daRelayRecordAccounting, error) {
	if r.state == daRelayStateCompleteSet || r.wireBytes == 0 {
		return daRelayRecordAccounting{}, nil
	}
	accounting := daRelayRecordAccounting{peerBytes: map[string]uint64{}}
	accounting.orphanBytes = r.wireBytes
	accounting.commitBytes = r.commit.wireBytes
	if err := addPeerAccounting(accounting.peerBytes, r.commit.peerQuotaKey, r.commit.wireBytes); err != nil {
		return daRelayRecordAccounting{}, err
	}
	for _, chunk := range r.chunks {
		if err := addPeerAccounting(accounting.peerBytes, chunk.peerQuotaKey, chunk.wireBytes); err != nil {
			return daRelayRecordAccounting{}, err
		}
	}
	return accounting, nil
}

func addPeerAccounting(peerBytes map[string]uint64, key string, bytes uint64) error {
	if bytes == 0 {
		return nil
	}
	var err error
	peerBytes[key], err = checkedAddUint64(peerBytes[key], bytes)
	return err
}

func checkedApplyUint64DeltaCap(current, remove, add, limit uint64, capErr error) (uint64, error) {
	value, err := checkedApplyUint64Delta(current, remove, add)
	if err != nil {
		return 0, err
	}
	if value > limit {
		return 0, capErr
	}
	return value, nil
}

func checkedApplyUint64Delta(current uint64, remove uint64, add uint64) (uint64, error) {
	if current < remove {
		return 0, errDARelayArithmeticOverflow
	}
	return checkedAddUint64(current-remove, add)
}

func checkedAddUint64(a uint64, b uint64) (uint64, error) {
	if ^uint64(0)-a < b {
		return 0, errDARelayArithmeticOverflow
	}
	return a + b, nil
}

func cloneBytes(in []byte) []byte {
	if len(in) == 0 {
		return nil
	}
	return append([]byte(nil), in...)
}

func (s *Service) scheduleDAPrefetch(peerAddr string, record daRelaySetRecord) {
	if !s.canScheduleDAPrefetch() {
		return
	}
	peersByKey, keys := s.daPrefetchPeers(peerAddr)
	plans, diagnostic := s.daRelay.planDAPrefetch(record, keys, s.cfg.Now())
	reportDAPrefetchDiagnostic(peersByKey, keys, diagnostic)
	for _, plan := range plans {
		s.sendDAPrefetchPlan(peersByKey, plan)
	}
}

func (s *Service) canScheduleDAPrefetch() bool {
	if s == nil {
		return false
	}
	return s.daRelay != nil
}

func (s *Service) daPrefetchPeers(peerAddr string) (map[string]*peer, []string) {
	s.peersMu.RLock()
	defer s.peersMu.RUnlock()
	peers, keys := s.allDAPrefetchPeersLocked()
	if peerAddr == "" {
		return peers, keys
	}
	return peers, preferDAPrefetchPeer(keys, s.preferredDAPrefetchPeerKeyLocked(peerAddr))
}

func (s *Service) preferredDAPrefetchPeerKeyLocked(peerAddr string) string {
	current := s.peers[peerAddr]
	if !acceptsDAPrefetch(current) {
		return ""
	}
	key := peerQuotaKey(current.addr())
	if key == "" {
		return ""
	}
	return key
}

func (s *Service) allDAPrefetchPeersLocked() (map[string]*peer, []string) {
	peers := map[string]*peer{}
	for _, current := range s.peers {
		if !acceptsDAPrefetch(current) {
			continue
		}
		if key := peerQuotaKey(current.addr()); key != "" {
			peers[key] = current
		}
	}
	keys := make([]string, 0, len(peers))
	for key := range peers {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return peers, keys
}

func preferDAPrefetchPeer(keys []string, preferred string) []string {
	if preferred == "" || len(keys) < 2 {
		return keys
	}
	ordered := make([]string, 0, len(keys))
	for _, key := range keys {
		if key == preferred {
			ordered = append(ordered, key)
			break
		}
	}
	if len(ordered) == 0 {
		return keys
	}
	for _, key := range keys {
		if key != preferred {
			ordered = append(ordered, key)
		}
	}
	return ordered
}

func acceptsDAPrefetch(current *peer) bool {
	if current == nil {
		return false
	}
	return current.acceptsCompactBlocks()
}

func reportDAPrefetchDiagnostic(peersByKey map[string]*peer, keys []string, diagnostic string) {
	if diagnostic == "" || len(keys) == 0 {
		return
	}
	peersByKey[keys[0]].setLastError(diagnostic)
}

func (s *Service) sendDAPrefetchPlan(peersByKey map[string]*peer, plan daRelayPrefetchPlan) {
	current := peersByKey[plan.peerKey]
	if current == nil {
		s.daRelay.releaseDAPrefetchPlan(plan)
		return
	}
	payload, err := encodeDAPrefetchPlanPayload(plan)
	if err == nil {
		err = current.send(messageGetDAChunk, payload)
	}
	if err != nil {
		current.setLastError(fmt.Sprintf("da prefetch send failed: %v", err))
		s.daRelay.releaseDAPrefetchPlan(plan)
	}
}

func encodeDAPrefetchPlanPayload(plan daRelayPrefetchPlan) ([]byte, error) {
	return encodeGetDAChunkPayload(getDAChunkPayload{Version: daChunkRequestVersion, DAID: plan.daID, Indexes: plan.indexes})
}

func (s *daRelayState) planDAPrefetch(record daRelaySetRecord, peerKeys []string, now time.Time) ([]daRelayPrefetchPlan, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prefetch.ensureMaps()
	s.prefetch.releaseExpired(now)
	current, ok := s.sets[record.daID]
	if !ok {
		s.prefetch.releaseSet(record.daID)
		return nil, ""
	}
	record = current
	missing := record.missingChunkIndexes()
	if len(missing) == 0 {
		s.prefetch.releaseSet(record.daID)
		return nil, ""
	}
	s.prefetch.releaseFulfilled(record.daID, missing)
	if len(peerKeys) == 0 {
		return nil, ""
	}
	set, diagnostic := s.prefetch.planSet(record.daID)
	if diagnostic != "" {
		return nil, diagnostic
	}
	plansByPeer, diagnostic := s.prefetch.reserveMissing(record.daID, missing, peerKeys, set, now)
	return buildDAPrefetchPlans(record.daID, peerKeys, plansByPeer), diagnostic
}

func (p *daRelayPrefetchState) ensureMaps() {
	if p.indexes == nil {
		p.indexes = map[[32]byte]map[uint16]string{}
		p.expires = map[[32]byte]time.Time{}
	}
}

func (p *daRelayPrefetchState) releaseExpired(now time.Time) {
	for daID, expiresAt := range p.expires {
		if !expiresAt.IsZero() && !now.Before(expiresAt) {
			p.releaseSet(daID)
		}
	}
}

func (p *daRelayPrefetchState) planSet(daID [32]byte) (map[uint16]string, string) {
	set := p.indexes[daID]
	if set != nil {
		return set, ""
	}
	if len(p.indexes) >= daPrefetchMaxConcurrentSets {
		return nil, "da prefetch global set cap exceeded"
	}
	return map[uint16]string{}, ""
}

func (p *daRelayPrefetchState) releaseFulfilled(daID [32]byte, missing []uint16) {
	set := p.indexes[daID]
	if len(set) == 0 {
		return
	}
	missingSet := map[uint16]bool{}
	for _, chunkIndex := range missing {
		missingSet[chunkIndex] = true
	}
	for chunkIndex := range set {
		if !missingSet[chunkIndex] {
			delete(set, chunkIndex)
		}
	}
	if len(set) == 0 {
		p.releaseSet(daID)
	}
}

func (p *daRelayPrefetchState) reserveMissing(daID [32]byte, missing []uint16, peerKeys []string, set map[uint16]string, now time.Time) (map[string][]uint16, string) {
	globalBytes, peerBytes := p.bytesInFlight()
	plansByPeer := map[string][]uint16{}
	peerIndex := 0
	for _, chunkIndex := range missing {
		if _, inFlight := set[chunkIndex]; inFlight {
			continue
		}
		peerKey, ok, reason := nextDAPrefetchPeer(peerKeys, peerBytes, globalBytes, &peerIndex)
		if !ok {
			p.expirePlanned(daID, plansByPeer, now)
			return plansByPeer, reason
		}
		p.indexes[daID] = set
		set[chunkIndex] = peerKey
		globalBytes += consensus.CHUNK_BYTES
		peerBytes[peerKey] += consensus.CHUNK_BYTES
		plansByPeer[peerKey] = append(plansByPeer[peerKey], chunkIndex)
	}
	p.expirePlanned(daID, plansByPeer, now)
	return plansByPeer, ""
}

func (p *daRelayPrefetchState) expirePlanned(daID [32]byte, plansByPeer map[string][]uint16, now time.Time) {
	if len(plansByPeer) != 0 {
		p.expires[daID] = now.Add(daPrefetchRequestTTL)
	}
}

func nextDAPrefetchPeer(peerKeys []string, peerBytes map[string]uint64, globalBytes uint64, peerIndex *int) (string, bool, string) {
	if len(peerKeys) == 0 {
		return "", false, ""
	}
	if globalBytes+consensus.CHUNK_BYTES > daPrefetchGlobalBytesPerSecond {
		return "", false, "da prefetch global byte cap exceeded"
	}
	for checked := 0; checked < len(peerKeys); checked++ {
		idx := (*peerIndex + checked) % len(peerKeys)
		key := peerKeys[idx]
		if peerBytes[key]+consensus.CHUNK_BYTES <= daPrefetchPerPeerBytesPerSecond {
			*peerIndex = idx + 1
			return key, true, ""
		}
	}
	return "", false, "da prefetch per-peer byte cap exceeded"
}

func buildDAPrefetchPlans(daID [32]byte, peerKeys []string, plansByPeer map[string][]uint16) []daRelayPrefetchPlan {
	plans := make([]daRelayPrefetchPlan, 0, len(plansByPeer))
	for _, peerKey := range peerKeys {
		if indexes := plansByPeer[peerKey]; len(indexes) != 0 {
			plans = append(plans, daRelayPrefetchPlan{daID: daID, peerKey: peerKey, indexes: indexes})
		}
	}
	return plans
}

func (s *daRelayState) releaseDAPrefetchPlan(plan daRelayPrefetchPlan) {
	s.mu.Lock()
	defer s.mu.Unlock()
	set := s.prefetch.indexes[plan.daID]
	for _, index := range plan.indexes {
		if set[index] == plan.peerKey {
			delete(set, index)
		}
	}
	if len(set) == 0 {
		s.prefetch.releaseSet(plan.daID)
	}
}

func (p *daRelayPrefetchState) releaseSet(daID [32]byte) {
	delete(p.indexes, daID)
	delete(p.expires, daID)
}

func (p *daRelayPrefetchState) bytesInFlight() (uint64, map[string]uint64) {
	peerBytes := map[string]uint64{}
	var globalBytes uint64
	for _, indexes := range p.indexes {
		for _, peerKey := range indexes {
			globalBytes += consensus.CHUNK_BYTES
			peerBytes[peerKey] += consensus.CHUNK_BYTES
		}
	}
	return globalBytes, peerBytes
}
