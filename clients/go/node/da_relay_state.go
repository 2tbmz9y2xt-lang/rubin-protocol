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
	daID  [32]byte
	state daRelaySetState
	// revision is this record's IDENTITY, not a statistic: every writer that
	// installs a record value stamps it from the state's monotone counter, so two
	// record values are the same record state exactly when their revisions agree.
	// It is what lets an admission plan built OUTSIDE the final DA lock prove,
	// under that lock, that the record it planned against has not moved. An ABSENT
	// record reads as the zero value, and no record a writer installs carries
	// revision 0, so present and absent are never confused.
	revision           uint64
	receivedTime       uint64
	payloadBytes       uint64
	wireBytes          uint64
	ttlBlocksRemaining uint64
	commit             daRelayCommit
	chunks             map[uint16]daRelayChunk
}

type daRelayEvictionAccounting struct {
	daID         [32]byte
	payloadBytes uint64
	wireBytes    uint64
	receivedTime uint64
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

// DARelayChunk is one UNRETAINED chunk's context-free shape, the sole input of
// ValidateDARelayChunk. It carries no retained transaction bytes and no owner
// identity: since RUB-678 the only way to retain a DA member is AdmitDA, which
// derives every retained field from the DAAdmissionSnapshot of a fully validated
// transaction rather than from a caller-supplied struct.
//
// Compatibility, construction dimension — deliberate break: RUB-678 REMOVED the
// exported TxBytes field, so a keyed composite literal naming TxBytes and any
// unkeyed literal built for the old shape no longer compile. Migration: drop the
// field — retained bytes now come only from the admission's own snapshot, and
// this type validates shape, never retention.
type DARelayChunk struct {
	DAID        [32]byte
	ChunkHash   [32]byte
	ChunkIndex  uint16
	Payload     []byte
	WireBytes   uint64
	HashChecked bool
}

// daRelayMemberIdentity is the owner-coupled half of ONE retained DA member: the
// exact admission identity DAAdmissionSnapshot carried, the provenance that
// admitted it, and the exact finalized PendingOutpointToken its DA claim was
// issued under. token is the JOIN KEY to PendingOutpointOwner — the owner has no
// txid index — so every removal path names a claim through this field and never
// by outpoint.
//
// A ZERO token means the member carries no owner claim. That is reachable only
// for a relay with no bound owner (the unbound test construction) and for the
// package-private staging helpers the accounting tests drive; a member of a BOUND
// relay that reaches canonical planning with a zero token is a missing claim and
// takes the terminal lane there.
type daRelayMemberIdentity struct {
	txid          [32]byte
	wtxid         [32]byte
	fee           consensus.Uint128
	retainedBytes uint64
	inputs        []consensus.Outpoint
	token         PendingOutpointToken
	provenance    DAProvenance
}

type daRelayCommit struct {
	daRelayMemberIdentity
	daID              [32]byte
	payloadCommitment [32]byte
	peerQuotaKey      string
	chunkCount        uint16
	wireBytes         uint64
	txBytes           []byte
}

type daRelayChunk struct {
	daRelayMemberIdentity
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
	// locators is the txid -> exact member locator index. It is maintained by
	// applyDASetRecordLocked and removeDASetRecordLocked ONLY, so it cannot drift
	// from s.sets without one of those two writers, and it is the sole txid
	// authority: no second raw-byte or record store exists.
	locators map[[32]byte]daRelayLocator
	// records is the monotone source of daRelaySetRecord.revision. It is carried
	// through cloneForAtomicBatchLocked and publishAtomicBatchLocked so a stamp
	// minted on a projection stays unique once that projection is published, and
	// it is deliberately not part of the observable image.
	records uint64
}

// daRelayLocatorKind names which member slot of a record a locator addresses.
// The zero value is not a kind, so a zero locator can never resolve.
type daRelayLocatorKind uint8

const (
	daRelayLocatorCommit daRelayLocatorKind = iota + 1
	daRelayLocatorChunk
)

// daRelayLocator is one retained member's exact address inside the retained
// image: its record, its role, and — for a chunk — its exact index.
type daRelayLocator struct {
	daID       [32]byte
	kind       daRelayLocatorKind
	chunkIndex uint16
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
		locators:                  make(map[[32]byte]daRelayLocator),
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
// An UNBOUND relay — a nil receiver, no mempool, or a mempool with no
// chainstate, which is the test-only construction — has no admission guard to
// take and keeps its existing unfenced behavior rather than inventing one. The
// nil-receiver condition is one arm of that same unbound family, not a
// nil-safety promise for the prefetch entries, which dereference the receiver
// immediately after the fence.
//
// A LATCHED engine parks a writer here until restart, by design: the terminal
// fail-closed latch retains admissionMu exclusively, and standard admission
// already parks its leased P2P workers the same way (mempool.go, "BLOCKS
// INDEFINITELY, by design"). Returning instead would mutate retained state the
// transition proved it cannot reason about.
//
// Its ONLY remaining writers are PlanPrefetch and ReleasePrefetchPlan, which
// mutate request RESERVATIONS and never a retained record or an owner claim.
// RUB-678 moved every retained-DA writer — AdmitDA, ReleasePeerQuotaKey and
// AdvanceOrphanTTL — onto the owner-guarded acquisition lifecycle in
// da_admission.go (acquireDAAdmissionHold for admission, BeginDARemoval for
// removal), which takes admissionMu.R itself for the guard's whole life. Those
// paths must never nest inside this fence: sync.RWMutex is not reentrant.
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

// advanceOrphanTTLLocked runs the TTL walk over the PROJECTED image: every
// incomplete record either loses one TTL block or is removed WHOLE together with
// every member claim it owns. It runs on a private clone, so it publishes
// nothing; the caller collects the victim claims and publishes both halves under
// one owner hold.
func (s *DARelayState) advanceOrphanTTLLocked() ([]DAAdmissionVictim, error) {
	var victims []DAAdmissionVictim
	for _, daID := range s.sortedIncompleteDAIDsLocked() {
		record := s.sets[daID]
		if record.ttlBlocksRemaining > 1 {
			record.ttlBlocksRemaining--
			s.stampRecordLocked(&record)
			s.sets[daID] = record
			continue
		}
		selected, err := s.appendDAMemberVictims(victims, record.members())
		if err != nil {
			return nil, err
		}
		victims = selected
		if err := s.removeDASetRecordLocked(record); err != nil {
			return nil, err
		}
	}
	return victims, nil
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
		locators:                  maps.Clone(s.locators),
		records:                   s.records,
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
	s.locators = projected.locators
	// The stamp source only ever ADVANCES. Every publisher currently holds this
	// mutex from its clone through this call, so the projection's value cannot be
	// behind — taking the maximum makes revision uniqueness independent of that
	// argument rather than conditional on it.
	s.records = max(s.records, projected.records)
}

// stampRecordLocked gives one record value a fresh identity. Every writer that
// installs a record — installDASetRecordLocked and the TTL decrement — calls it,
// so no two record states of one da_id ever share a revision and a removed
// da_id's next record never reuses its predecessor's.
func (s *DARelayState) stampRecordLocked(record *daRelaySetRecord) {
	s.records++
	record.revision = s.records
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
