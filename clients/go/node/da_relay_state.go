package node

import (
	"crypto/sha3"
	"errors"
	"iter"
	"maps"
	"sync"
	"sync/atomic"
	"time"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

const (
	daOrphanPoolSizeBytes           uint64 = 64 << 20
	daOrphanPoolPerPeerMaxBytes     uint64 = 4 << 20
	daOrphanPoolPerDAIDMaxBytes     uint64 = 8 << 20
	daOrphanCommitOverheadMaxBytes  uint64 = 8 << 20
	daStagedSharedMaxBytes          uint64 = 536870912
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
	stagedBytes               uint64
	orphanPoolBytes           uint64
	orphanPoolPerPeerBytes    uint64
	orphanPoolPerDAIDBytes    uint64
	orphanCommitOverheadBytes uint64
	orphanTTLBlocks           uint64
	pinnedPayloadBytes        uint64
}

func defaultDARelayCaps() daRelayCaps {
	return daRelayCaps{
		stagedBytes:               daStagedSharedMaxBytes,
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
	// revision is minted by the owner-ready projector and installed with its SINGLE-USE
	// placement under one uninterrupted lock hold. A LEGACY writer creates a record
	// presenting 0 and may keep a stamped record's stamp; RUB-1275 owns the TTL decrement.
	// Go-private: never serialized, never public, never a normative protocol field.
	revision           uint64
	receivedTime       uint64
	payloadBytes       uint64
	wireBytes          uint64
	ttlBlocksRemaining uint64
	completeIntrinsic  daCompleteCapacitySet
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

// DARelayChunk is the unretained chunk descriptor ValidateDARelayChunk checks before
// local relay admission; retained members are admitted by AdmitDA from exact bytes.
type DARelayChunk struct {
	DAID        [32]byte
	ChunkHash   [32]byte
	ChunkIndex  uint16
	Payload     []byte
	WireBytes   uint64
	HashChecked bool
}

type daRelayCommit struct {
	daID              [32]byte
	payloadCommitment [32]byte
	peerQuotaKey      string
	member            *daRelayMemberIdentity
	chunkCount        uint16
	wireBytes         uint64
	txBytes           []byte
}

type daRelayChunk struct {
	daID         [32]byte
	chunkHash    [32]byte
	peerQuotaKey string
	member       *daRelayMemberIdentity
	chunkIndex   uint16
	payload      []byte
	wireBytes    uint64
	txBytes      []byte
	hashChecked  bool
}

// daRelayMemberIdentity is the owner-ready half of ONE retained DA member. Every field
// arrives EXPLICITLY from the caller: nothing is parsed, hashed, reconstructed or
// narrowed, and inputs keep canonical order verbatim (RUBIN_COMPACT_BLOCKS.md 18.1,
// RUBIN_MEMPOOL_POLICY.md 6.4). A commit or chunk holds it BY POINTER: one word unowned.
type daRelayMemberIdentity struct {
	txid       [32]byte
	wtxid      [32]byte
	fee        consensus.Uint128
	inputs     []consensus.Outpoint
	token      PendingOutpointToken
	provenance daProvenance
}

type daRelayLocatorKind uint8

const (
	daRelayLocatorCommit daRelayLocatorKind = iota + 1
	daRelayLocatorChunk
)

type daRelayLocator struct {
	daID       [32]byte
	kind       daRelayLocatorKind
	chunkIndex uint16
}

type daRelayLocatorRow struct {
	txid    [32]byte
	locator daRelayLocator
	present bool
	links   [2]daRelayRelationLink
	keys    [2]daRelayRelationKey
}

// Literal rows own admitted identities; legacy record values retain immutable
// byte/member backing but cannot change the identity copied into a member row.
type daRelayMemberRow struct {
	slot        daRelayLocator
	txid, wtxid [32]byte
	member      *daRelayMemberIdentity
	commit      daRelayCommit
	chunk       daRelayChunk
	links       [3]daRelayRelationLink
	keys        [3]daRelayRelationKey
}

type daRelayRecordRow struct {
	key     [32]byte
	value   daRelaySetRecord
	present bool
	members []*daRelayMemberRow
}

type daRelayRelationKey struct {
	dimension uint8
	id        [32]byte
	slot      daRelayLocator
}

type daRelayRelationBucket struct {
	count uint64
	head  *daRelayRelationLink
}

type daRelayRelationLink struct {
	previous, next *daRelayRelationLink
	bucket         *daRelayRelationBucket
	member         *daRelayMemberRow
	locator        *daRelayLocatorRow
}

type daRelayRelations struct {
	sets         map[[32]byte]*daRelayRecordRow
	locators     map[[32]byte]*daRelayLocatorRow
	buckets      map[daRelayRelationKey]*daRelayRelationBucket
	setCount     int
	locatorCount int
}

// Preparation reserves physical capacity, never logical membership. Publication
// only changes existing pointer slots and fixed incidence links under s.mu.
type daRelayRelationPublication struct {
	oldRecords, newRecords   []*daRelayRecordRow
	oldLocators, newLocators []*daRelayLocatorRow
	keys                     []daRelayRelationKey
	locatorIndexes           map[[32]byte]int
}

func newDARelayRelations() daRelayRelations {
	return daRelayRelations{
		sets:     make(map[[32]byte]*daRelayRecordRow),
		locators: make(map[[32]byte]*daRelayLocatorRow),
		buckets:  make(map[daRelayRelationKey]*daRelayRelationBucket),
	}
}

func (r *daRelayRelations) record(key [32]byte) (daRelaySetRecord, bool) {
	row := r.sets[key]
	if row == nil || !row.present {
		return daRelaySetRecord{}, false
	}
	return row.value, true
}

func (r *daRelayRelations) recordValue(key [32]byte) daRelaySetRecord {
	value, _ := r.record(key)
	return value
}

func (r *daRelayRelations) locator(key [32]byte) (daRelayLocator, bool) {
	row := r.locators[key]
	if row == nil || !row.present {
		return daRelayLocator{}, false
	}
	return row.locator, true
}

func (r *daRelayRelations) locatorValue(key [32]byte) daRelayLocator {
	value, _ := r.locator(key)
	return value
}

func (r *daRelayRelations) records() iter.Seq2[[32]byte, daRelaySetRecord] {
	return func(yield func([32]byte, daRelaySetRecord) bool) {
		for key, row := range r.sets {
			if row.present && !yield(key, row.value) {
				return
			}
		}
	}
}

func (r *daRelayRelations) locatorRows() iter.Seq2[[32]byte, daRelayLocator] {
	return func(yield func([32]byte, daRelayLocator) bool) {
		for key, row := range r.locators {
			if row.present && !yield(key, row.locator) {
				return
			}
		}
	}
}

func (r *daRelayRelations) prepareBucket(p *daRelayRelationPublication, key daRelayRelationKey) *daRelayRelationBucket {
	bucket := r.buckets[key]
	if bucket == nil {
		bucket = &daRelayRelationBucket{}
		r.buckets[key] = bucket
	}
	p.keys = append(p.keys, key)
	return bucket
}

func (r *daRelayRelations) prepareMember(p *daRelayRelationPublication, row *daRelayMemberRow) {
	if row.member == nil {
		return
	}
	row.keys = [3]daRelayRelationKey{{dimension: 1, id: row.txid}, {dimension: 2, id: row.wtxid}, {dimension: 3, slot: row.slot}}
	for i, key := range row.keys {
		row.links[i] = daRelayRelationLink{bucket: r.prepareBucket(p, key), member: row}
	}
}

func (r *daRelayRelations) prepareRecord(p *daRelayRelationPublication, key [32]byte, value daRelaySetRecord, present bool) {
	old := r.sets[key]
	if old == nil {
		old = &daRelayRecordRow{key: key}
		r.sets[key] = old
	}
	row := &daRelayRecordRow{key: key, value: value, present: present}
	for _, member := range old.members {
		p.keys = append(p.keys, member.keys[:]...)
	}
	if present {
		row.members = r.prepareRecordMembers(p, key, value)
	}
	p.oldRecords = append(p.oldRecords, old)
	p.newRecords = append(p.newRecords, row)
}

func (r *daRelayRelations) prepareRecordMembers(p *daRelayRelationPublication, key [32]byte, value daRelaySetRecord) []*daRelayMemberRow {
	rows := make([]*daRelayMemberRow, 0, len(value.chunks)+1)
	if value.commit.member != nil {
		row := &daRelayMemberRow{slot: daRelayLocator{daID: key, kind: daRelayLocatorCommit}, member: value.commit.member, commit: value.commit}
		row.txid, row.wtxid = row.member.txid, row.member.wtxid
		r.prepareMember(p, row)
		rows = append(rows, row)
	}
	for index, chunk := range value.chunks {
		row := &daRelayMemberRow{slot: daRelayLocator{daID: key, kind: daRelayLocatorChunk, chunkIndex: index}, member: chunk.member, chunk: chunk}
		if row.member != nil {
			row.txid, row.wtxid = row.member.txid, row.member.wtxid
		}
		r.prepareMember(p, row)
		rows = append(rows, row)
	}
	return rows
}

func daRelayAliasSlot(slot daRelayLocator) daRelayLocator {
	if slot.kind == daRelayLocatorCommit {
		slot.chunkIndex = 0
	}
	return slot
}

func (r *daRelayRelations) prepareLocator(p *daRelayRelationPublication, value daRelayLocatorRow, present bool) {
	old := r.locators[value.txid]
	if old == nil {
		old = &daRelayLocatorRow{txid: value.txid}
		r.locators[value.txid] = old
	}
	row := &daRelayLocatorRow{txid: value.txid, locator: value.locator, present: present}
	if present {
		row.keys = [2]daRelayRelationKey{{dimension: 4, id: row.txid}, {dimension: 5, slot: daRelayAliasSlot(row.locator)}}
		for i, key := range row.keys {
			row.links[i] = daRelayRelationLink{bucket: r.prepareBucket(p, key), locator: row}
		}
	}
	if p.locatorIndexes == nil {
		p.locatorIndexes = make(map[[32]byte]int)
	}
	if index, found := p.locatorIndexes[row.txid]; found {
		p.newLocators[index] = row
		return
	}
	p.locatorIndexes[row.txid] = len(p.newLocators)
	p.keys = append(p.keys, old.keys[:]...)
	p.oldLocators = append(p.oldLocators, old)
	p.newLocators = append(p.newLocators, row)
}

func (link *daRelayRelationLink) attach() {
	if link.bucket == nil {
		return
	}
	link.next = link.bucket.head
	if link.next != nil {
		link.next.previous = link
	}
	link.bucket.head = link
	link.bucket.count++
}

func (link *daRelayRelationLink) detach() {
	if link.bucket == nil {
		return
	}
	if link.previous != nil {
		link.previous.next = link.next
	} else {
		link.bucket.head = link.next
	}
	if link.next != nil {
		link.next.previous = link.previous
	}
	link.bucket.count--
	link.previous, link.next = nil, nil
}

func (r *daRelayRelations) publishRecords(p *daRelayRelationPublication) {
	for _, row := range p.oldRecords {
		if row.present {
			r.setCount--
			for _, member := range row.members {
				for i := range member.links {
					member.links[i].detach()
				}
			}
		}
	}
	for _, row := range p.newRecords {
		r.publishRecord(row)
	}
}

func (r *daRelayRelations) publishRecord(row *daRelayRecordRow) {
	r.sets[row.key] = row
	if row.present {
		r.setCount++
		for _, member := range row.members {
			for i := range member.links {
				member.links[i].attach()
			}
		}
	}
}

func (r *daRelayRelations) publishLocators(p *daRelayRelationPublication) {
	for _, row := range p.oldLocators {
		if row.present {
			r.locatorCount--
			for i := range row.links {
				row.links[i].detach()
			}
		}
	}
	for _, row := range p.newLocators {
		r.locators[row.txid] = row
		if row.present {
			r.locatorCount++
			for i := range row.links {
				row.links[i].attach()
			}
		}
	}
}

func (r *daRelayRelations) publish(p *daRelayRelationPublication) {
	r.publishRecords(p)
	r.publishLocators(p)
	r.discard(p)
}

func (r *daRelayRelations) discard(p *daRelayRelationPublication) {
	for _, row := range p.newRecords {
		if !r.sets[row.key].present {
			delete(r.sets, row.key)
		}
	}
	for _, row := range p.newLocators {
		if !r.locators[row.txid].present {
			delete(r.locators, row.txid)
		}
	}
	for _, key := range p.keys {
		if bucket := r.buckets[key]; bucket != nil && bucket.count == 0 {
			delete(r.buckets, key)
		}
	}
}

func (r *daRelayRelations) putRecord(key [32]byte, value daRelaySetRecord) {
	p := &daRelayRelationPublication{}
	r.prepareRecord(p, key, value, true)
	r.publish(p)
}

func (r *daRelayRelations) removeRecord(key [32]byte) {
	p := &daRelayRelationPublication{}
	r.prepareRecord(p, key, daRelaySetRecord{}, false)
	r.publish(p)
}

func (r *daRelayRelations) putLocator(key [32]byte, value daRelayLocator) {
	p := &daRelayRelationPublication{}
	r.prepareLocator(p, daRelayLocatorRow{txid: key, locator: value}, true)
	r.publish(p)
}

func (r *daRelayRelations) removeLocator(key [32]byte) {
	p := &daRelayRelationPublication{}
	r.prepareLocator(p, daRelayLocatorRow{txid: key}, false)
	r.publish(p)
}

func (r *daRelayRelations) scalarRecord(key [32]byte, value daRelaySetRecord) {
	r.sets[key].value = value
}

func (r *daRelayRelations) clone() daRelayRelations {
	out := newDARelayRelations()
	for key, row := range r.sets {
		if row.present {
			out.cloneRecord(key, row)
		}
	}
	for key, value := range r.locatorRows() {
		out.putLocator(key, value)
	}
	if r.sets == nil {
		out.sets = nil
	}
	if r.locators == nil {
		out.locators = nil
	}
	return out
}

func (r *daRelayRelations) cloneRecord(key [32]byte, source *daRelayRecordRow) {
	p := &daRelayRelationPublication{}
	row := &daRelayRecordRow{key: key, value: source.value, present: true}
	row.members = make([]*daRelayMemberRow, 0, len(source.members))
	for _, member := range source.members {
		copy := *member
		copy.links = [3]daRelayRelationLink{}
		r.prepareMember(p, &copy)
		row.members = append(row.members, &copy)
	}
	r.sets[key] = row
	p.newRecords = append(p.newRecords, row)
	r.publish(p)
}

func (r *daRelayRelations) member(slot daRelayLocator) *daRelayMemberRow {
	bucket := r.buckets[daRelayRelationKey{dimension: 3, slot: slot}]
	if bucket == nil || bucket.count != 1 || bucket.head == nil {
		return nil
	}
	return bucket.head.member
}

func (r *daRelayRelations) soleMember(key daRelayRelationKey, member *daRelayMemberRow) bool {
	bucket := r.buckets[key]
	if member == nil {
		return bucket == nil || bucket.count == 0
	}
	return bucket != nil && bucket.count == 1 && bucket.head != nil && bucket.head.member == member
}

func (r *daRelayRelations) soleLocator(key daRelayRelationKey, locator *daRelayLocatorRow) bool {
	bucket := r.buckets[key]
	return bucket != nil && bucket.count == 1 && bucket.head != nil && bucket.head.locator == locator
}

func (r *daRelayRelations) memberBound(row *daRelayMemberRow) bool {
	if !compactDAMemberIdentityValid(row) || !r.memberIncidencesBound(row) {
		return false
	}
	return r.memberLocatorBound(row)
}

func compactDAMemberIdentityValid(row *daRelayMemberRow) bool {
	if row == nil || row.member == nil {
		return false
	}
	return row.txid != ([32]byte{}) && row.wtxid != ([32]byte{}) && row.txid == row.member.txid && row.wtxid == row.member.wtxid
}

func (r *daRelayRelations) memberIncidencesBound(row *daRelayMemberRow) bool {
	for _, key := range row.keys {
		if !r.soleMember(key, row) {
			return false
		}
	}
	return true
}

func (r *daRelayRelations) memberLocatorBound(row *daRelayMemberRow) bool {
	locator := r.locators[row.txid]
	if locator == nil || !locator.present || locator.locator != row.slot {
		return false
	}
	return r.soleLocator(daRelayRelationKey{dimension: 4, id: row.txid}, locator) && r.soleLocator(daRelayRelationKey{dimension: 5, slot: row.slot}, locator)
}

func (r *daRelayRelations) observedBound(identity CompactCandidateIdentity, row *daRelayMemberRow) bool {
	if row == nil {
		return r.soleMember(daRelayRelationKey{dimension: 1, id: identity.TxID}, nil) && r.soleMember(daRelayRelationKey{dimension: 2, id: identity.WTxID}, nil)
	}
	if !r.memberBound(row) || row.txid != identity.TxID {
		return false
	}
	witness := row
	if row.wtxid != identity.WTxID {
		witness = nil
	}
	return r.soleMember(daRelayRelationKey{dimension: 2, id: identity.WTxID}, witness)
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
	errDAProvenanceInvalid              = errors.New("invalid da provenance")
	errDARelayMemberIncomplete          = errors.New("da relay member is not owner-ready")
	errDARelayImageIncompatible         = errors.New("da relay retained image is not owner-ready")
	errDARelayRecordStale               = errors.New("da relay record image is stale")
	errDARelayLocatorMismatch           = errors.New("da relay locator mismatch")
)

var (
	errDARelayChunkHashMismatch         = ErrDARelayChunkHashMismatch
	errDARelayPayloadCommitmentMismatch = ErrDARelayPayloadCommitmentMismatch
)

type daRelayRecordAccounting struct {
	stagedBytes   uint64
	completeBytes uint64
	completeCount uint64
	orphanBytes   uint64
	commitBytes   uint64
	peerBytes     map[string]uint64
}

type DARelayState struct {
	mu sync.Mutex
	// rejectCache is owner-lifetime policy state. Atomic retained-state images
	// deliberately omit it, and publication leaves the live instance untouched.
	rejectCache               daRejectCache
	mempool                   *Mempool
	caps                      daRelayCaps
	prefetch                  daRelayPrefetchState
	nextReceivedTime          uint64
	stagedBytes               uint64
	completeBytes             uint64
	completeCount             uint64
	orphanBytes               uint64
	orphanBytesByPeerQuotaKey map[string]uint64
	orphanBytesByDAID         map[[32]byte]uint64
	orphanCommitOverheadBytes uint64
	pinnedPayloadBytes        uint64
	relations                 daRelayRelations
	// records is the process-local high-water of all issued revisions, including
	// deleted records. Single-use placement under one uninterrupted lock preserves it.
	records uint64
	// admitObserver receives every AdmitDA outcome on a non-nil receiver after
	// the outcome is final, with no DA relay or owner mutex held; a panicking
	// call has no outcome and is not observed. It must not call AdmitDA. Nil at
	// construction; retained-state images never copy it.
	admitObserver atomic.Pointer[func(daAdmitCall)]
	// completeHook, when set by package tests, runs once at each reached stage
	// of one completing admission: daCompletePlanned with only the admission
	// hold held, daCompleteEffects with s.mu held and the owner mutex not held.
	// At daCompleteEffects it must not take s.mu, call AdmitDA or call
	// DAObserverReadStateImage; it may read and mutate DA relay fields directly
	// and may take the owner mutex. Nil at construction; retained-state images
	// never copy it.
	completeHook func(daCompleteStage, *daCompleteCommitPlan)
}

// daAdmitCall is one AdmitDA invocation exactly as it returned.
type daAdmitCall struct {
	provenance DAProvenance
	result     DAAdmissionResult
	err        error
}

type daCompleteStage uint8

const (
	daCompletePlanned daCompleteStage = iota + 1
	daCompleteEffects
)

func newDARelayState(mempool *Mempool, caps daRelayCaps) (*DARelayState, error) {
	if err := caps.validate(); err != nil {
		return nil, err
	}
	return &DARelayState{
		mempool:                   mempool,
		caps:                      caps,
		orphanBytesByPeerQuotaKey: map[string]uint64{},
		orphanBytesByDAID:         map[[32]byte]uint64{},
		relations:                 newDARelayRelations(),
	}, nil
}

// lockAdmissionFence takes the bound ChainState admission READ guard for the
// duration of one complete retained-DA mutation. It returns the release or a
// terminal-refusal error before the entry reaches retained state.
//
// It is what makes an ordinary retained-DA writer unable to interleave with a
// canonical transition: the transition holds the same guard EXCLUSIVELY and
// CONTINUOUSLY from D preparation through D publication, so a writer either
// completed before the transition took it or starts after publication released
// it. There is no third schedule and therefore no lost update against the
// prepared image (RUBIN_MEMPOOL_POLICY.md Section 6.4.1).
//
// Lock order is peerQuotaLock (when a P2P caller holds one) then this guard then
// DARelayState.mu. sync.RWMutex is not reentrant, so nothing under this guard
// re-enters it and each entry takes it exactly once; the canonical transition
// reaches prepare/publish with the WRITE guard already held and never calls one.
//
// An UNBOUND relay — no mempool, or a mempool with no chainstate, which is the
// test-only construction — has no admission guard to take and keeps its existing
// unfenced behavior rather than inventing one. The nil RECEIVER arm only keeps this
// function itself from dereferencing s: no fenced body is nil-safe (each takes s.mu
// next), so nil handling belongs to the exported wrappers — ReleasePeerQuotaKey
// returns early, AdvanceOrphanTTL promises nothing.
//
// A latched engine returns unavailable before retained state is accessed. The
// terminal writer remains held, so the closed image cannot be reopened.
func (s *DARelayState) lockAdmissionFence() (func(), error) {
	if s == nil || s.mempool == nil || s.mempool.chainState == nil {
		return unfencedDARelayMutation, nil
	}
	fence := &s.mempool.chainState.admissionMu
	if !fence.RLockUnlessTerminal() {
		return unfencedDARelayMutation, txAdmitUnavailable("pending-outpoint owner admission context unavailable")
	}
	return fence.RUnlock, nil
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

// AdvanceOrphanTTL runs the owner-aware TTL tick once, all-or-nothing: each incomplete owner-ready
// record with ttl above one decrements once and mints one fresh revision; ttl one expires whole
// (members, locator rows, accounting, prefetch reservation and, on a bound relay, finalized owner
// claims) with no revision; valid C is a validated zero-TTL no-op, while zero A/B TTL fails. It returns
// commitOwnerReadyRemoval's error classes unwrapped; that body owns the fence; a nil receiver is not promised.
func (s *DARelayState) AdvanceOrphanTTL() error {
	return s.advanceOwnerReadyTTL()
}

// ReleasePeerQuotaKey releases the retained members whose finalized PEER provenance carries key
// (typed match, never the cached quota key): a matching commit survives iff a LOCAL or DETACHED_REORG
// chunk is retained, keeping its charge and owner claim; an unblocked whole removal also carries the
// record's non-matching PEER members; an empty key selects nothing after the same preflight; a nil
// receiver returns nil. Valid C is validated but never selected. It takes no quota lock and returns
// commitOwnerReadyRemoval's error classes unwrapped, and that body owns the fence.
func (s *DARelayState) ReleasePeerQuotaKey(key string) error {
	if s == nil {
		return nil
	}
	return s.releaseOwnerReadyPeerQuota(key)
}

// PlanPrefetch reserves missing chunks for the supplied normalized peer keys.
// The complete reservation runs under the admission read fence.
func (s *DARelayState) PlanPrefetch(daID [32]byte, peerKeys []string, now time.Time) ([]DARelayPrefetchPlan, string) {
	release, err := s.lockAdmissionFence()
	if err != nil {
		return nil, err.Error()
	}
	defer release()
	plans, diagnostic := s.planDAPrefetch(daRelaySetRecord{daID: daID}, peerKeys, now)
	out := make([]DARelayPrefetchPlan, len(plans))
	for i, plan := range plans {
		out[i] = DARelayPrefetchPlan{DAID: plan.daID, PeerKey: plan.peerKey, Indexes: plan.indexes}
	}
	return out, diagnostic
}

// ReleasePrefetchPlan releases one previously reserved prefetch plan under the
// admission read fence. Terminal refusal leaves the reservation frozen until
// restart.
func (s *DARelayState) ReleasePrefetchPlan(plan DARelayPrefetchPlan) {
	release, err := s.lockAdmissionFence()
	if err != nil {
		return
	}
	defer release()
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
		record := s.relations.recordValue(daID)
		if record.ttlBlocksRemaining > 1 {
			record.ttlBlocksRemaining--
			s.relations.scalarRecord(daID, record)
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
		stagedBytes:               s.stagedBytes,
		completeBytes:             s.completeBytes,
		completeCount:             s.completeCount,
		orphanBytes:               s.orphanBytes,
		orphanBytesByPeerQuotaKey: maps.Clone(s.orphanBytesByPeerQuotaKey),
		orphanBytesByDAID:         maps.Clone(s.orphanBytesByDAID),
		orphanCommitOverheadBytes: s.orphanCommitOverheadBytes,
		pinnedPayloadBytes:        s.pinnedPayloadBytes,
		relations:                 s.relations.clone(),
		records:                   s.records,
	}
}

func (s *DARelayState) publishAtomicBatchLocked(projected *DARelayState) {
	s.prefetch = projected.prefetch
	s.nextReceivedTime = projected.nextReceivedTime
	s.stagedBytes = projected.stagedBytes
	s.completeBytes = projected.completeBytes
	s.completeCount = projected.completeCount
	s.orphanBytes = projected.orphanBytes
	s.orphanBytesByPeerQuotaKey = projected.orphanBytesByPeerQuotaKey
	s.orphanBytesByDAID = projected.orphanBytesByDAID
	s.orphanCommitOverheadBytes = projected.orphanCommitOverheadBytes
	s.pinnedPayloadBytes = projected.pinnedPayloadBytes
	s.relations = projected.relations
	// Zero on any legacy state, so this pair is the identity. Only the canonical
	// transition releases s.mu before this assignment; its admission WRITE fence
	// closes that window. The legacy callers hold s.mu through clone and publish.
	s.records = projected.records
}

func (s *DARelayState) planDAPrefetch(record daRelaySetRecord, peerKeys []string, now time.Time) ([]daRelayPrefetchPlan, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prefetch.ensureMaps()
	s.prefetch.releaseExpired(now)
	current, ok := s.relations.record(record.daID)
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
