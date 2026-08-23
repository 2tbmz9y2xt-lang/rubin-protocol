package node

import (
	"crypto/sha3"
	"errors"
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

// DARelayPrefetchPlan is one caller-owned request reservation.
type DARelayPrefetchPlan struct {
	DAID    [32]byte
	PeerKey string
	Indexes []uint16
}

// DARelayCommit is the retained commit metadata supplied by P2P after peer
// quota normalization.
type DARelayCommit struct {
	DAID              [32]byte
	PayloadCommitment [32]byte
	ChunkCount        uint16
	WireBytes         uint64
	TxBytes           []byte
}

// DARelayChunk is one retained chunk supplied by P2P after peer quota
// normalization.
type DARelayChunk struct {
	DAID        [32]byte
	ChunkHash   [32]byte
	ChunkIndex  uint16
	Payload     []byte
	WireBytes   uint64
	TxBytes     []byte
	HashChecked bool
}

type daRelayCommit struct {
	daID              [32]byte
	payloadCommitment [32]byte
	peerQuotaKey      string
	chunkCount        uint16
	wireBytes         uint64
	txBytes           []byte
}

type daRelayChunk struct {
	daID         [32]byte
	chunkHash    [32]byte
	peerQuotaKey string
	chunkIndex   uint16
	payload      []byte
	wireBytes    uint64
	txBytes      []byte
	hashChecked  bool
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
	ErrDARelayChunkHashMismatch         = errors.New("da chunk hash mismatch")
	errDARelayChunkPayloadSizeInvalid   = errors.New("da chunk payload size invalid")
	ErrDARelayPayloadCommitmentMismatch = errors.New("da payload commitment mismatch")
	errDARelayWireBytesInvalid          = errors.New("da relay wire bytes invalid")
	errDARelayPinnedPayloadCapExceeded  = errors.New("da pinned payload cap exceeded")
	errDARelayArithmeticOverflow        = errors.New("da relay arithmetic overflow")
)

var (
	errDARelayChunkHashMismatch         = ErrDARelayChunkHashMismatch
	errDARelayPayloadCommitmentMismatch = ErrDARelayPayloadCommitmentMismatch
)

type daRelayRecordAccounting struct {
	orphanBytes uint64
	commitBytes uint64
	peerBytes   map[string]uint64
}

type DARelayState struct {
	mu                        sync.Mutex
	mempool                   *Mempool
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

func newDARelayState(mempool *Mempool, caps daRelayCaps) (*DARelayState, error) {
	if err := caps.validate(); err != nil {
		return nil, err
	}
	return &DARelayState{
		mempool:                   mempool,
		caps:                      caps,
		orphanBytesByPeerQuotaKey: map[string]uint64{},
		orphanBytesByDAID:         map[[32]byte]uint64{},
		sets:                      make(map[[32]byte]daRelaySetRecord),
	}, nil
}

// StageCommit retains one commit whose peer quota key was normalized by P2P.
func (s *DARelayState) StageCommit(peerQuotaKey string, commit DARelayCommit) error {
	return s.addDACommit(peerQuotaKey, daRelayCommit{
		daID:              commit.DAID,
		payloadCommitment: commit.PayloadCommitment,
		chunkCount:        commit.ChunkCount,
		wireBytes:         commit.WireBytes,
		txBytes:           commit.TxBytes,
	})
}

// StageChunk retains one chunk whose peer quota key was normalized by P2P.
func (s *DARelayState) StageChunk(peerQuotaKey string, chunk DARelayChunk) error {
	return s.addDAChunk(peerQuotaKey, daRelayChunk{
		daID:        chunk.DAID,
		chunkHash:   chunk.ChunkHash,
		chunkIndex:  chunk.ChunkIndex,
		payload:     chunk.Payload,
		wireBytes:   chunk.WireBytes,
		txBytes:     chunk.TxBytes,
		hashChecked: chunk.HashChecked,
	})
}

// ValidateDARelayChunk validates one unretained chunk before relay admission.
func ValidateDARelayChunk(chunk DARelayChunk) error {
	internal := daRelayChunk{
		daID:        chunk.DAID,
		chunkHash:   chunk.ChunkHash,
		chunkIndex:  chunk.ChunkIndex,
		payload:     chunk.Payload,
		wireBytes:   chunk.WireBytes,
		hashChecked: chunk.HashChecked,
	}
	if err := validateDAChunk(internal); err != nil {
		return err
	}
	if !internal.hashChecked && sha3.Sum256(internal.payload) != internal.chunkHash {
		return ErrDARelayChunkHashMismatch
	}
	return nil
}

// AdvanceOrphanTTL advances the retained incomplete-set TTL once.
func (s *DARelayState) AdvanceOrphanTTL() error {
	_, err := s.advanceOrphanTTL()
	return err
}

// ReleasePeerQuotaKey releases incomplete retained data owned by key.
func (s *DARelayState) ReleasePeerQuotaKey(key string) error {
	return s.releasePeerQuotaKey(key)
}

// ConsumeCompleteSet releases one retained complete set.
func (s *DARelayState) ConsumeCompleteSet(daID [32]byte) (bool, error) {
	return s.consumeCompleteSet(daID)
}

// PlanPrefetch reserves missing chunks for the supplied normalized peer keys.
func (s *DARelayState) PlanPrefetch(daID [32]byte, peerKeys []string, now time.Time) ([]DARelayPrefetchPlan, string) {
	plans, diagnostic := s.planDAPrefetch(daRelaySetRecord{daID: daID}, peerKeys, now)
	out := make([]DARelayPrefetchPlan, len(plans))
	for i, plan := range plans {
		out[i] = DARelayPrefetchPlan{DAID: plan.daID, PeerKey: plan.peerKey, Indexes: plan.indexes}
	}
	return out, diagnostic
}

// ReleasePrefetchPlan releases one previously reserved prefetch plan.
func (s *DARelayState) ReleasePrefetchPlan(plan DARelayPrefetchPlan) {
	s.releaseDAPrefetchPlan(daRelayPrefetchPlan{daID: plan.DAID, peerKey: plan.PeerKey, indexes: plan.Indexes})
}

func (s *DARelayState) setOrphanBytesForPeerQuotaKey(key string, bytes uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if bytes == 0 {
		delete(s.orphanBytesByPeerQuotaKey, key)
		return
	}
	s.orphanBytesByPeerQuotaKey[key] = bytes
}

func (s *DARelayState) orphanBytesForPeerQuotaKey(key string) uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.orphanBytesByPeerQuotaKey[key]
}

func (s *DARelayState) setOrphanBytesForDAID(daID [32]byte, bytes uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if bytes == 0 {
		delete(s.orphanBytesByDAID, daID)
		return
	}
	s.orphanBytesByDAID[daID] = bytes
}

func (s *DARelayState) orphanBytesForDAID(daID [32]byte) uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.orphanBytesByDAID[daID]
}

func (s *DARelayState) consumeCompleteSet(daID [32]byte) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	record, ok := s.sets[daID]
	if !ok || record.state != daRelayStateCompleteSet {
		return false, nil
	}
	if err := s.removeDASetRecordLocked(record); err != nil {
		return false, err
	}
	return true, nil
}

func (s *DARelayState) advanceOrphanTTL() ([]daRelayExpiredSet, error) {
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

func (s *DARelayState) planDAPrefetch(record daRelaySetRecord, peerKeys []string, now time.Time) ([]daRelayPrefetchPlan, string) {
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

func (s *DARelayState) releaseDAPrefetchPlan(plan daRelayPrefetchPlan) {
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
