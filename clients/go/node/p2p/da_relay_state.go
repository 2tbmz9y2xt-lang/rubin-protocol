package p2p

import (
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
)

type daRelaySetState uint8

const (
	daRelayStateOrphanChunks daRelaySetState = iota
	daRelayStateStagedCommit
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
	daID         [32]byte
	peerQuotaKey string
	chunkCount   uint16
	wireBytes    uint64
}

type daRelayChunk struct {
	daID         [32]byte
	peerQuotaKey string
	chunkIndex   uint16
	wireBytes    uint64
}

var (
	errDARelayDuplicateCommit         = errors.New("duplicate da commit")
	errDARelayDuplicateChunk          = errors.New("duplicate da chunk")
	errDARelayChunkCountInvalid       = errors.New("da commit chunk count invalid")
	errDARelayChunkIndexOutOfRange    = errors.New("da chunk index out of range")
	errDARelayChunkIndexOutsideCommit = errors.New("da chunk index outside commit")
	errDARelayOrphanPoolCapExceeded   = errors.New("da orphan pool cap exceeded")
	errDARelayOrphanPeerCapExceeded   = errors.New("da orphan pool per-peer cap exceeded")
	errDARelayOrphanDAIDCapExceeded   = errors.New("da orphan pool per-da_id cap exceeded")
	errDARelayOrphanCommitCapExceeded = errors.New("da orphan commit overhead cap exceeded")
	errDARelayWireBytesInvalid        = errors.New("da relay wire bytes invalid")
	errDARelayArithmeticOverflow      = errors.New("da relay arithmetic overflow")
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

func (s *daRelayState) nextReceivedTimeLocked() (uint64, error) {
	return checkedAddUint64(s.nextReceivedTime, 1)
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
	defer s.mu.Unlock()

	record := s.sets[commit.daID].clone()
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
	if err := s.prepareDASetRecordLocked(&record); err != nil {
		return daRelaySetRecord{}, err
	}
	if err := s.applyDASetRecordLocked(record); err != nil {
		return daRelaySetRecord{}, err
	}
	return record.clone(), nil
}

func (s *daRelayState) addDAChunk(peerAddr string, chunk daRelayChunk) (daRelaySetRecord, error) {
	if err := validateDAChunk(chunk); err != nil {
		return daRelaySetRecord{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	record := s.sets[chunk.daID].clone()
	record.ensureMaps()
	if _, exists := record.chunks[chunk.chunkIndex]; exists {
		return daRelaySetRecord{}, errDARelayDuplicateChunk
	}
	if record.commit.chunkCount != 0 && chunk.chunkIndex >= record.commit.chunkCount {
		return daRelaySetRecord{}, errDARelayChunkIndexOutsideCommit
	}
	chunk.peerQuotaKey = peerQuotaKey(peerAddr)
	record.daID = chunk.daID
	if record.commit.chunkCount == 0 {
		record.state = daRelayStateOrphanChunks
		record.ttlBlocksRemaining = s.caps.orphanTTLBlocks
	}
	record.chunks[chunk.chunkIndex] = chunk
	if err := s.prepareDASetRecordLocked(&record); err != nil {
		return daRelaySetRecord{}, err
	}
	if err := s.applyDASetRecordLocked(record); err != nil {
		return daRelaySetRecord{}, err
	}
	return record.clone(), nil
}

func validateDAChunk(chunk daRelayChunk) error {
	if uint64(chunk.chunkIndex) >= consensus.MAX_DA_CHUNK_COUNT {
		return errDARelayChunkIndexOutOfRange
	}
	if chunk.wireBytes == 0 {
		return errDARelayWireBytesInvalid
	}
	return nil
}

func (s *daRelayState) prepareDASetRecordLocked(record *daRelaySetRecord) error {
	receivedTime, err := s.nextReceivedTimeLocked()
	if err != nil {
		return err
	}
	record.receivedTime = receivedTime
	return record.recomputeOrphanTotals()
}

func (s *daRelayState) applyDASetRecordLocked(record daRelaySetRecord) error {
	oldRecord := s.sets[record.daID]
	orphanBytes, peerBytes, daBytes, commitBytes, err := s.projectOrphanAccountingDeltaLocked(oldRecord, record)
	if err != nil {
		return err
	}
	s.sets[record.daID] = record
	s.orphanBytes = orphanBytes
	s.applyProjectedPeerBytes(peerBytes)
	s.applyProjectedDAIDBytes(record.daID, daBytes)
	s.orphanCommitOverheadBytes = commitBytes
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
	if r.commit.chunkCount == 0 {
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
	out := r
	if r.chunks == nil {
		return out
	}
	out.chunks = make(map[uint16]daRelayChunk, len(r.chunks))
	for index, chunk := range r.chunks {
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

func (r daRelaySetRecord) orphanAccounting() (daRelayRecordAccounting, error) {
	accounting := daRelayRecordAccounting{peerBytes: map[string]uint64{}}
	if r.wireBytes == 0 {
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
