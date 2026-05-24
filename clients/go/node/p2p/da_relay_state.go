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
	commit                    daRelayCommit
	chunks                    map[uint16]daRelayChunk
	orphanBytesByPeerQuotaKey map[string]uint64
	daID                      [32]byte
	state                     daRelaySetState
	receivedTime              uint64
	ttlBlocksRemaining        uint64
	payloadBytes              uint64
	wireBytes                 uint64
	totalFee                  uint64
}

type daRelayCommit struct {
	daID              [32]byte
	payloadCommitment [32]byte
	peerQuotaKey      string
	chunkCount        uint16
	wireBytes         uint64
}

type daRelayChunk struct {
	payload      []byte
	daID         [32]byte
	chunkHash    [32]byte
	peerQuotaKey string
	chunkIndex   uint16
	wireBytes    uint64
}

var (
	errDARelayDuplicateCommit           = errors.New("duplicate da commit")
	errDARelayDuplicateChunk            = errors.New("duplicate da chunk")
	errDARelayChunkHashMismatch         = errors.New("da chunk hash mismatch")
	errDARelayChunkIndexOutOfRange      = errors.New("da chunk index out of range")
	errDARelayChunkIndexOutsideCommit   = errors.New("da chunk index outside commit")
	errDARelayPayloadCommitmentMismatch = errors.New("da payload commitment mismatch")
	errDARelayPayloadBytesOverflow      = errors.New("da relay payload bytes overflow")
	errDARelayWireBytesOverflow         = errors.New("da relay wire bytes overflow")
)

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
		return daRelaySetRecord{}, errDARelayChunkIndexOutOfRange
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	record := s.sets[commit.daID].clone()
	if record.commit.chunkCount != 0 {
		return daRelaySetRecord{}, errDARelayDuplicateCommit
	}
	record.daID = commit.daID
	commit.peerQuotaKey = peerQuotaKey(peerAddr)
	record.commit = commit
	record.pruneChunksOutsideCommit()
	record.state = daRelayStateStagedCommit
	record.ttlBlocksRemaining = s.caps.orphanTTLBlocks
	s.nextReceivedTime++
	record.receivedTime = s.nextReceivedTime
	if err := record.recomputeTotals(); err != nil {
		return daRelaySetRecord{}, err
	}
	if err := record.maybeComplete(); err != nil {
		return daRelaySetRecord{}, err
	}

	s.applyDASetRecordLocked(record)
	return record.clone(), nil
}

func (s *daRelayState) addDAChunk(peerAddr string, chunk daRelayChunk) (daRelaySetRecord, error) {
	if uint64(chunk.chunkIndex) >= consensus.MAX_DA_CHUNK_COUNT {
		return daRelaySetRecord{}, errDARelayChunkIndexOutOfRange
	}
	if sha3.Sum256(chunk.payload) != chunk.chunkHash {
		return daRelaySetRecord{}, errDARelayChunkHashMismatch
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	record := s.sets[chunk.daID].clone()
	if _, exists := record.chunks[chunk.chunkIndex]; exists {
		return daRelaySetRecord{}, errDARelayDuplicateChunk
	}
	if record.commit.chunkCount != 0 && chunk.chunkIndex >= record.commit.chunkCount {
		return daRelaySetRecord{}, errDARelayChunkIndexOutsideCommit
	}
	record.daID = chunk.daID
	if record.commit.chunkCount == 0 {
		record.state = daRelayStateOrphanChunks
		record.ttlBlocksRemaining = s.caps.orphanTTLBlocks
	}
	s.nextReceivedTime++
	record.receivedTime = s.nextReceivedTime
	chunk.peerQuotaKey = peerQuotaKey(peerAddr)
	record.chunks[chunk.chunkIndex] = chunk.clone()
	if err := record.recomputeTotals(); err != nil {
		return daRelaySetRecord{}, err
	}
	if err := record.maybeComplete(); err != nil {
		return daRelaySetRecord{}, err
	}

	s.applyDASetRecordLocked(record)
	return record.clone(), nil
}

func (s *daRelayState) applyDASetRecordLocked(record daRelaySetRecord) {
	old := s.sets[record.daID]
	s.subtractOrphanAccountingLocked(old.wireBytes, old.orphanBytesByPeerQuotaKey, record.daID)
	if record.state == daRelayStateCompleteSet {
		s.pinnedPayloadBytes += record.payloadBytes
	} else {
		s.addOrphanAccountingLocked(record)
	}
	s.sets[record.daID] = record.clone()
}

func (s *daRelayState) addOrphanAccountingLocked(record daRelaySetRecord) {
	if record.wireBytes == 0 {
		return
	}
	s.orphanBytes += record.wireBytes
	for key, bytes := range record.orphanBytesByPeerQuotaKey {
		if key != "" && bytes != 0 {
			s.orphanBytesByPeerQuotaKey[key] += bytes
		}
	}
	s.orphanBytesByDAID[record.daID] += record.wireBytes
}

func (s *daRelayState) subtractOrphanAccountingLocked(bytes uint64, peerBytes map[string]uint64, daID [32]byte) {
	if bytes == 0 {
		return
	}
	if s.orphanBytes >= bytes {
		s.orphanBytes -= bytes
	} else {
		s.orphanBytes = 0
	}
	delete(s.orphanBytesByDAID, daID)
	for key, remove := range peerBytes {
		value := s.orphanBytesByPeerQuotaKey[key]
		if value <= remove {
			delete(s.orphanBytesByPeerQuotaKey, key)
			continue
		}
		s.orphanBytesByPeerQuotaKey[key] = value - remove
	}
}

func (r daRelaySetRecord) clone() daRelaySetRecord {
	out := r
	if r.chunks == nil {
		out.chunks = make(map[uint16]daRelayChunk)
	} else {
		out.chunks = make(map[uint16]daRelayChunk, len(r.chunks))
		for index, chunk := range r.chunks {
			out.chunks[index] = chunk.clone()
		}
	}
	if r.orphanBytesByPeerQuotaKey == nil {
		out.orphanBytesByPeerQuotaKey = make(map[string]uint64)
	} else {
		out.orphanBytesByPeerQuotaKey = make(map[string]uint64, len(r.orphanBytesByPeerQuotaKey))
		for key, bytes := range r.orphanBytesByPeerQuotaKey {
			out.orphanBytesByPeerQuotaKey[key] = bytes
		}
	}
	return out
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

func (r *daRelaySetRecord) pruneChunksOutsideCommit() {
	for index := range r.chunks {
		if index >= r.commit.chunkCount {
			delete(r.chunks, index)
		}
	}
}

func (r *daRelaySetRecord) recomputeTotals() error {
	r.payloadBytes = 0
	r.wireBytes = r.commit.wireBytes
	r.totalFee = 0
	r.orphanBytesByPeerQuotaKey = make(map[string]uint64)
	if r.commit.peerQuotaKey != "" && r.commit.wireBytes != 0 {
		r.orphanBytesByPeerQuotaKey[r.commit.peerQuotaKey] += r.commit.wireBytes
	}
	for _, chunk := range r.chunks {
		var err error
		if r.payloadBytes, err = checkedAddUint64(r.payloadBytes, uint64(len(chunk.payload)), errDARelayPayloadBytesOverflow); err != nil {
			return err
		}
		if r.wireBytes, err = checkedAddUint64(r.wireBytes, chunk.wireBytes, errDARelayWireBytesOverflow); err != nil {
			return err
		}
		if chunk.peerQuotaKey != "" && chunk.wireBytes != 0 {
			r.orphanBytesByPeerQuotaKey[chunk.peerQuotaKey] += chunk.wireBytes
		}
	}
	return nil
}

func (r *daRelaySetRecord) maybeComplete() error {
	if r.commit.chunkCount == 0 {
		return nil
	}
	missing := r.missingChunkIndexes()
	if len(missing) != 0 {
		r.state = daRelayStateStagedCommit
		return nil
	}
	if r.payloadCommitment() != r.commit.payloadCommitment {
		r.state = daRelayStateStagedCommit
		return errDARelayPayloadCommitmentMismatch
	}
	r.state = daRelayStateCompleteSet
	r.ttlBlocksRemaining = 0
	return nil
}

func (r daRelaySetRecord) payloadCommitment() [32]byte {
	hasher := sha3.New256()
	for i := uint16(0); i < r.commit.chunkCount; i++ {
		chunk := r.chunks[i]
		_, _ = hasher.Write(chunk.payload)
	}
	var out [32]byte
	copy(out[:], hasher.Sum(nil))
	return out
}

func (c daRelayChunk) clone() daRelayChunk {
	out := c
	out.payload = append([]byte(nil), c.payload...)
	return out
}

func checkedAddUint64(a uint64, b uint64, err error) (uint64, error) {
	if ^uint64(0)-a < b {
		return 0, err
	}
	return a + b, nil
}
