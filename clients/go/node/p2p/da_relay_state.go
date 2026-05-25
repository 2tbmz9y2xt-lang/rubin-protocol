package p2p

import (
	"crypto/sha3"
	"errors"
	"sync"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

const (
	daOrphanPoolSizeBytes          uint64 = 64 << 20
	daOrphanPoolPerPeerMaxBytes    uint64 = 4 << 20
	daOrphanPoolPerDAIDMaxBytes    uint64 = 8 << 20
	daOrphanCommitOverheadMaxBytes uint64 = 8 << 20
	daOrphanTTLBlocks              uint64 = 3
	daMempoolPinnedPayloadMaxBytes uint64 = 96_000_000
	daCompleteSetRecordFootprint   uint64 = 256
	daCompleteSetChunkFootprint    uint64 = 128
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
	totalFee           uint64
	ttlBlocksRemaining uint64
	commit             daRelayCommit
	chunks             map[uint16]daRelayChunk
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

func (s *daRelayState) nextMonotonicReceivedTime() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.nextReceivedTime++
	return s.nextReceivedTime
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

func (s *daRelayState) addDACommit(peerAddr string, commit daRelayCommit) (daRelaySetRecord, error) {
	if commit.chunkCount == 0 || uint64(commit.chunkCount) > consensus.MAX_DA_CHUNK_COUNT {
		return daRelaySetRecord{}, errDARelayChunkCountInvalid
	}
	if commit.wireBytes == 0 {
		return daRelaySetRecord{}, errDARelayWireBytesInvalid
	}

	s.mu.Lock()

	record := s.sets[commit.daID].cloneForStateMutation()
	record.ensureMaps()
	if record.commit.chunkCount != 0 {
		s.mu.Unlock()
		return daRelaySetRecord{}, errDARelayDuplicateCommit
	}
	c := commit
	c.peerQuotaKey = peerQuotaKey(peerAddr)
	record.daID = c.daID
	record.commit = c
	record.pruneChunksOutsideCommit()
	record.state = daRelayStateStagedCommit
	record.ttlBlocksRemaining = s.caps.orphanTTLBlocks
	record.receivedTime = s.nextReceivedTime + 1
	if err := record.tryComplete(false); err != nil {
		s.mu.Unlock()
		return daRelaySetRecord{}, err
	}
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

func (s *daRelayState) addDAChunk(peerAddr string, chunk daRelayChunk) (daRelaySetRecord, error) {
	if uint64(chunk.chunkIndex) >= consensus.MAX_DA_CHUNK_COUNT {
		return daRelaySetRecord{}, errDARelayChunkIndexOutOfRange
	}
	payloadLen := len(chunk.payload)
	if payloadLen == 0 || uint64(payloadLen) > consensus.CHUNK_BYTES {
		return daRelaySetRecord{}, errDARelayChunkPayloadSizeInvalid
	}
	if chunk.wireBytes == 0 || chunk.wireBytes < uint64(payloadLen) {
		return daRelaySetRecord{}, errDARelayWireBytesInvalid
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

	s.mu.Lock()

	record = s.sets[chunk.daID].cloneForStateMutation()
	record.ensureMaps()
	if err := record.validateChunkInsert(chunk.chunkIndex); err != nil {
		s.mu.Unlock()
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
	record.receivedTime = s.nextReceivedTime + 1
	if err := record.tryComplete(false); err != nil {
		s.mu.Unlock()
		return daRelaySetRecord{}, err
	}
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
	s.nextReceivedTime = record.receivedTime
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
	orphanBytes, err := checkedApplyUint64Delta(s.orphanBytes, oldAccounting.orphanBytes, newAccounting.orphanBytes)
	if err != nil {
		return 0, nil, 0, 0, err
	}
	if orphanBytes > s.caps.orphanPoolBytes {
		return 0, nil, 0, 0, errDARelayOrphanPoolCapExceeded
	}
	daBytes, err := checkedApplyUint64Delta(s.orphanBytesByDAID[newRecord.daID], oldAccounting.orphanBytes, newAccounting.orphanBytes)
	if err != nil {
		return 0, nil, 0, 0, err
	}
	if daBytes > s.caps.orphanPoolPerDAIDBytes {
		return 0, nil, 0, 0, errDARelayOrphanDAIDCapExceeded
	}
	commitBytes, err := checkedApplyUint64Delta(s.orphanCommitOverheadBytes, oldAccounting.commitBytes, newAccounting.commitBytes)
	if err != nil {
		return 0, nil, 0, 0, err
	}
	if commitBytes > s.caps.orphanCommitOverheadBytes {
		return 0, nil, 0, 0, errDARelayOrphanCommitCapExceeded
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
	missing := make([]uint16, 0)
	for i := uint16(0); i < r.commit.chunkCount; i++ {
		if _, ok := r.chunks[i]; !ok {
			missing = append(missing, i)
		}
	}
	return missing
}

func (r daRelaySetRecord) clone() daRelaySetRecord {
	return r.cloneWithPayloads(true)
}

func (r daRelaySetRecord) cloneForStateMutation() daRelaySetRecord {
	return r.cloneWithPayloads(false)
}

func (r daRelaySetRecord) cloneWithPayloads(copyPayloads bool) daRelaySetRecord {
	out := r
	if r.chunks == nil {
		return out
	}
	out.chunks = make(map[uint16]daRelayChunk, len(r.chunks))
	for index, chunk := range r.chunks {
		if copyPayloads {
			chunk.payload = cloneBytes(chunk.payload)
		}
		out.chunks[index] = chunk
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
		}
	}
}

func (r daRelaySetRecord) validateChunkInsert(chunkIndex uint16) error {
	if _, exists := r.chunks[chunkIndex]; exists {
		return errDARelayDuplicateChunk
	}
	if r.commit.chunkCount != 0 && chunkIndex >= r.commit.chunkCount {
		return errDARelayChunkIndexOutsideCommit
	}
	return nil
}

func (r *daRelaySetRecord) tryComplete(dropChunksOnCommitMismatch bool) error {
	if r.commit.chunkCount == 0 || len(r.missingChunkIndexes()) != 0 {
		r.payloadBytes = 0
		return nil
	}

	hasher := sha3.New256()
	var payloadBytes uint64
	for i := uint16(0); i < r.commit.chunkCount; i++ {
		chunk := r.chunks[i]
		var err error
		payloadBytes, err = checkedAddUint64(payloadBytes, uint64(len(chunk.payload)))
		if err != nil {
			return err
		}
		_, _ = hasher.Write(chunk.payload)
	}
	var payloadCommitment [32]byte
	copy(payloadCommitment[:], hasher.Sum(nil))
	if payloadCommitment != r.commit.payloadCommitment {
		if !dropChunksOnCommitMismatch {
			r.payloadBytes = 0
			r.state = daRelayStateStagedCommit
			return errDARelayPayloadCommitmentMismatch
		}
		for i := uint16(0); i < r.commit.chunkCount; i++ {
			delete(r.chunks, i)
		}
		r.payloadBytes = 0
		r.state = daRelayStateStagedCommit
		return nil
	}
	r.payloadBytes = payloadBytes
	r.state = daRelayStateCompleteSet
	r.ttlBlocksRemaining = 0
	return nil
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
	accounting := daRelayRecordAccounting{peerBytes: map[string]uint64{}}
	if r.state == daRelayStateCompleteSet || r.wireBytes == 0 {
		return accounting, nil
	}
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
	if key == "" || bytes == 0 {
		return nil
	}
	var err error
	peerBytes[key], err = checkedAddUint64(peerBytes[key], bytes)
	return err
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
