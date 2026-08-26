package node

import (
	"crypto/sha3"
	"errors"
	"maps"
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
//
// TxBytes MUST be the EXACT canonical serialization of the tx_kind 0x01
// transaction this record is the commit of — the bytes Section 5.2 admission
// validated, fully consuming, with DaCommitCore.DaID == DAID and
// DaCommitCore.ChunkCount == ChunkCount. Staging does NOT check it, and the
// transition's re-parse detects only STRUCTURAL violations: bytes that do not
// parse, trailing bytes, or a kind/da_id/chunk_count contradiction are
// TERMINAL_LOCAL_INVARIANT(evidence) there — the node latches and publishes
// nothing. A WELL-FORMED substitute transaction carrying matching metadata is
// silently adopted as this record's exact identity instead: nothing binds these
// bytes to the payload commitment or to the transaction admission actually saw.
type DARelayCommit struct {
	DAID              [32]byte
	PayloadCommitment [32]byte
	ChunkCount        uint16
	WireBytes         uint64
	TxBytes           []byte
}

// DARelayChunk is one retained chunk supplied by P2P after peer quota
// normalization.
//
// TxBytes carries the same MUST as DARelayCommit.TxBytes, for the tx_kind 0x02
// transaction at this exact ChunkIndex.
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

// lockAdmissionFence takes the bound ChainState admission READ guard for the
// duration of one complete exported retained-DA mutation and returns its
// release, so the idiomatic call is `defer s.lockAdmissionFence()()` as the
// first statement of the wrapper.
//
// It is what makes an ordinary retained-DA writer unable to interleave with a
// canonical transition: the transition holds the same guard EXCLUSIVELY and
// CONTINUOUSLY from D preparation through D publication, so a writer either
// completed before the transition took it or starts after publication released
// it. There is no third schedule and therefore no lost update against the
// prepared image (RUBIN_MEMPOOL_POLICY.md Section 6.4.1).
//
// Lock order is peerQuotaLock (when a P2P caller holds one) then this guard then
// DARelayState.mu, and nothing under this guard re-enters it: the wrappers are
// the only entry points, they never nest, and the canonical transition reaches
// prepare/publish with the WRITE guard already held and so never calls one.
//
// An UNBOUND relay — no mempool, or a mempool with no chainstate, which is the
// test-only construction — has no admission guard to take and keeps its existing
// unfenced behavior rather than inventing one. The nil RECEIVER arm is load
// bearing too: ReleasePeerQuotaKey is a pinned nil-safe surface, so the fence
// must reach that body instead of dereferencing on the way in.
//
// A LATCHED engine parks a writer here until restart, by design: the terminal
// fail-closed latch retains admissionMu exclusively, and standard admission
// already parks its leased P2P workers the same way (mempool.go, "BLOCKS
// INDEFINITELY, by design"). Returning instead would mutate retained state the
// transition proved it cannot reason about.
//
// Forward note: RUB-678/RUB-680's owner-guarded paths REPLACE this fence for the
// writers they take over and must never nest inside it — BeginDAAdmission holds
// admissionMu.R for its guard's whole life and sync.RWMutex is not reentrant.
func (s *DARelayState) lockAdmissionFence() func() {
	if s == nil || s.mempool == nil || s.mempool.chainState == nil {
		return unfencedDARelayMutation
	}
	fence := &s.mempool.chainState.admissionMu
	fence.RLock()
	return fence.RUnlock
}

// unfencedDARelayMutation is the release for an unbound relay: it exists as a
// package-level func so the unbound path allocates no closure per mutation.
func unfencedDARelayMutation() {}

// StageCommit retains one commit whose peer quota key was normalized by P2P.
// The complete mutation runs under the admission read fence. commit.TxBytes is
// the caller's obligation, stated on DARelayCommit and unchecked here.
func (s *DARelayState) StageCommit(peerQuotaKey string, commit DARelayCommit) error {
	defer s.lockAdmissionFence()()
	return s.addDACommit(peerQuotaKey, daRelayCommit{
		daID:              commit.DAID,
		payloadCommitment: commit.PayloadCommitment,
		chunkCount:        commit.ChunkCount,
		wireBytes:         commit.WireBytes,
		txBytes:           commit.TxBytes,
	})
}

// StageChunk retains one chunk whose peer quota key was normalized by P2P.
// The complete mutation runs under the admission read fence. chunk.TxBytes is
// the caller's obligation, stated on DARelayChunk and unchecked here.
func (s *DARelayState) StageChunk(peerQuotaKey string, chunk DARelayChunk) error {
	defer s.lockAdmissionFence()()
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
// The complete mutation runs under the admission read fence.
func (s *DARelayState) AdvanceOrphanTTL() error {
	defer s.lockAdmissionFence()()
	_, err := s.advanceOrphanTTL()
	return err
}

// ReleasePeerQuotaKey releases incomplete retained data owned by key.
// The complete mutation runs under the admission read fence, taken INSIDE the
// caller's per-key peer quota lock.
func (s *DARelayState) ReleasePeerQuotaKey(key string) error {
	defer s.lockAdmissionFence()()
	return s.releasePeerQuotaKey(key)
}

// PlanPrefetch reserves missing chunks for the supplied normalized peer keys.
// The complete reservation runs under the admission read fence.
func (s *DARelayState) PlanPrefetch(daID [32]byte, peerKeys []string, now time.Time) ([]DARelayPrefetchPlan, string) {
	defer s.lockAdmissionFence()()
	plans, diagnostic := s.planDAPrefetch(daRelaySetRecord{daID: daID}, peerKeys, now)
	out := make([]DARelayPrefetchPlan, len(plans))
	for i, plan := range plans {
		out[i] = DARelayPrefetchPlan{DAID: plan.daID, PeerKey: plan.peerKey, Indexes: plan.indexes}
	}
	return out, diagnostic
}

// ReleasePrefetchPlan releases one previously reserved prefetch plan.
// The complete release runs under the admission read fence.
func (s *DARelayState) ReleasePrefetchPlan(plan DARelayPrefetchPlan) {
	defer s.lockAdmissionFence()()
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

func (s *DARelayState) advanceOrphanTTL() ([]daRelayExpiredSet, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	projected := s.cloneForAtomicBatchLocked()
	expired, err := projected.advanceOrphanTTLLocked()
	if err != nil {
		return nil, err
	}
	s.publishAtomicBatchLocked(projected)
	return expired, nil
}

func (s *DARelayState) advanceOrphanTTLLocked() ([]daRelayExpiredSet, error) {
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

func (s *DARelayState) cloneForAtomicBatchLocked() *DARelayState {
	prefetchIndexes := maps.Clone(s.prefetch.indexes)
	for daID, indexes := range prefetchIndexes {
		prefetchIndexes[daID] = maps.Clone(indexes)
	}
	return &DARelayState{
		mempool:                   s.mempool,
		caps:                      s.caps,
		prefetch:                  daRelayPrefetchState{indexes: prefetchIndexes, expires: maps.Clone(s.prefetch.expires)},
		nextReceivedTime:          s.nextReceivedTime,
		orphanBytes:               s.orphanBytes,
		orphanBytesByPeerQuotaKey: maps.Clone(s.orphanBytesByPeerQuotaKey),
		orphanBytesByDAID:         maps.Clone(s.orphanBytesByDAID),
		orphanCommitOverheadBytes: s.orphanCommitOverheadBytes,
		pinnedPayloadBytes:        s.pinnedPayloadBytes,
		sets:                      maps.Clone(s.sets),
	}
}

func (s *DARelayState) publishAtomicBatchLocked(projected *DARelayState) {
	s.prefetch = projected.prefetch
	s.nextReceivedTime = projected.nextReceivedTime
	s.orphanBytes = projected.orphanBytes
	s.orphanBytesByPeerQuotaKey = projected.orphanBytesByPeerQuotaKey
	s.orphanBytesByDAID = projected.orphanBytesByDAID
	s.orphanCommitOverheadBytes = projected.orphanCommitOverheadBytes
	s.pinnedPayloadBytes = projected.pinnedPayloadBytes
	s.sets = projected.sets
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
