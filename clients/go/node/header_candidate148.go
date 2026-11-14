package node

import (
	"bytes"
	"errors"
	"math"
	"math/big"
	"math/bits"
	"slices"
	"sync"
	"sync/atomic"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

// Dormant finite admitted received-header owner over raw 148-byte headers (RUBIN_MEMPOOL_POLICY.md Section 6.4.1.8,
// RUBIN_COMPACT_BLOCKS.md Sections 7.1.1 and 7.2). No production caller. Every non-OK outcome is a local refusal and
// establishes no candidate invalidity.

// ErrHeaderCandidateConfig148V1 is the only constructor refusal: a zero or maximum limit field, or incarnation zero.
var ErrHeaderCandidateConfig148V1 = errors.New("header candidate 148: invalid configuration")

// HeaderCandidateLimits148V1 are the finite local ceilings captured at construction (RUB-1550 api_contract,
// first_refusal_order). MaxTips, MaxHeaders and MaxRetainedBytes are the row 12 ceilings over the post-transition
// received set; one record is charged 252 bytes (148 raw, 32 hash, 32 parent, 8 height, 32 provenance) plus the
// minimal big-endian byte length of its Work. MaxTransitionHeaders bounds only len(Additions)+len(Retired) (EstablishV1:
// len(records)) at row 5, MaxSnapshotBytes bounds only Inventory148V1 Bytes, and MaxLeases bounds only the outstanding
// leases of AcquireDependencyV1.
type HeaderCandidateLimits148V1 struct {
	MaxTips              uint64
	MaxHeaders           uint64
	MaxRetainedBytes     uint64
	MaxTransitionHeaders uint64
	MaxSnapshotBytes     uint64
	MaxLeases            uint64
}

// HeaderCandidateRecord148V1 is one already-qualified publication. Provenance is an opaque nonzero producer tag.
// External states that Parent is a durable active-canonical or accepted-target header; it is not record identity.
type HeaderCandidateRecord148V1 struct {
	Raw        [148]byte
	Hash       [32]byte
	Parent     [32]byte
	Height     uint64
	Work       *big.Int
	Provenance [32]byte
	External   bool
}

// HeaderCandidateTransition148V1 is one producer update. NewSource zero means unchanged. Additions and Retired list
// every parent before its child; Retired is the exact canonical-promoted received prefix.
type HeaderCandidateTransition148V1 struct {
	ExpectedVersion uint64
	ExpectedSource  [32]byte
	NewSource       [32]byte
	Additions       []HeaderCandidateRecord148V1
	Retired         [][32]byte
}

// HeaderCandidateOutcome148V1 is the owner result. The numeric order is the contract's declaration order, not the
// evaluation order: EstablishV1, PrepareV1 and AcquireDependencyV1 follow the first-refusal table, Missing and
// AlreadyEstablished are evaluated where that table places them, and Consumed precedes Closed on a handle call.
type HeaderCandidateOutcome148V1 uint8

// Owner outcomes.
const (
	HeaderCandidateOK148V1 HeaderCandidateOutcome148V1 = iota
	HeaderCandidateClosed148V1
	HeaderCandidateUnknownSource148V1
	HeaderCandidateNotEstablished148V1
	HeaderCandidateBusy148V1
	HeaderCandidateInvalid148V1
	HeaderCandidateStale148V1
	HeaderCandidateConflict148V1
	HeaderCandidateMissingParent148V1
	HeaderCandidateNoCoverage148V1
	HeaderCandidateProtected148V1
	HeaderCandidateVersionExhausted148V1
	HeaderCandidateCapacity148V1
	HeaderCandidateMissing148V1
	HeaderCandidateAlreadyEstablished148V1
	HeaderCandidateConsumed148V1
)

// HeaderCandidatePublication148V1 is the receipt of an applied publication (RUB-1550 D7). Added and Retired are
// independent of owner state. Added lists the hashes of the Additions not received before the operation, in input
// order. Retired lists the transition's Retired in its order, then each chosen capacity reclaim in choice order: the
// victim tip first, then its exclusive ancestry downward. A candidate whose reclaim holds a leased hash, a received
// ancestor of a leased hash, or a hash of this transition's Additions is skipped whole and never listed. A
// Changed-false receipt keeps the version and has both empty.
type HeaderCandidatePublication148V1 struct {
	Changed bool
	Version uint64
	Added   [][32]byte
	Retired [][32]byte
}

type hcEntry struct {
	rec    HeaderCandidateRecord148V1
	charge uint64
}

type hcPlan struct {
	adds    []HeaderCandidateRecord148V1
	prov    []HeaderCandidateRecord148V1
	retired [][32]byte
	source  [32]byte
	changed bool
	added   [][32]byte
}

// HeaderCandidateOwner148V1 is the process-local owner. All state is guarded by mu; version is also published
// atomically for VersionV1. No method performs storage I/O or runs caller code while holding mu.
type HeaderCandidateOwner148V1 struct {
	limits      HeaderCandidateLimits148V1
	incarnation uint64
	mu          sync.Mutex
	cond        sync.Cond
	version     atomic.Uint64
	established bool
	latched     bool
	closed      bool
	source      [32]byte
	recs        map[[32]byte]*hcEntry
	kids        map[[32]byte]uint64
	tips        uint64
	guards      uint64
	prepared    *HeaderCandidatePrepared148V1
	leased      map[[32]byte]uint64
	leases      uint64
}

// HeaderCandidatePrepared148V1 is the single outstanding prepared transition; its first handle call consumes it.
type HeaderCandidatePrepared148V1 struct {
	owner    *HeaderCandidateOwner148V1
	plan     hcPlan
	consumed bool
}

// HeaderCandidateLease148V1 pins one hash and every received ancestor against retirement until released.
type HeaderCandidateLease148V1 struct {
	owner    *HeaderCandidateOwner148V1
	hash     [32]byte
	released bool
}

// NewHeaderCandidateOwner148V1 returns a not-established owner at version 1, or ErrHeaderCandidateConfig148V1.
func NewHeaderCandidateOwner148V1(limits HeaderCandidateLimits148V1, incarnation uint64) (*HeaderCandidateOwner148V1, error) {
	if incarnation == 0 || !hcLimitsValid(limits) {
		return nil, ErrHeaderCandidateConfig148V1
	}
	o := &HeaderCandidateOwner148V1{
		limits: limits, incarnation: incarnation,
		recs: map[[32]byte]*hcEntry{}, kids: map[[32]byte]uint64{}, leased: map[[32]byte]uint64{},
	}
	o.cond.L = &o.mu
	o.version.Store(1)
	return o, nil
}

func hcLimitsValid(l HeaderCandidateLimits148V1) bool {
	for _, v := range [...]uint64{l.MaxTips, l.MaxHeaders, l.MaxRetainedBytes, l.MaxTransitionHeaders, l.MaxSnapshotBytes, l.MaxLeases} {
		if v == 0 || v == math.MaxUint64 {
			return false
		}
	}
	return true
}

// IncarnationV1 returns the constructor incarnation.
func (o *HeaderCandidateOwner148V1) IncarnationV1() uint64 { return o.incarnation }

// VersionV1 is a race-safe scalar read; it never waits.
func (o *HeaderCandidateOwner148V1) VersionV1() uint64 { return o.version.Load() }

// CloseV1 destroys the owner without waiting for guards (RUB-1550 api_contract CloseV1). Afterwards Inventory148V1 is
// Incomplete, ProtectV1 returns current false with a non-nil release, mutators return Closed, Header148V1 returns false,
// LookupV1 returns the zero record and false, and VersionV1 keeps the version current at close. A waiting EstablishV1,
// PublishV1 or UnknownV1 is woken and returns Closed with no effect and no receipt; a later guard release applies nothing.
func (o *HeaderCandidateOwner148V1) CloseV1() {
	o.mu.Lock()
	o.closed = true
	o.cond.Broadcast()
	o.mu.Unlock()
}

// ProtectV1 takes a shared guard; it holds mu only briefly and never waits for another guard or for a publication that
// waits for guards. current is true exactly when the owner is established, not latched, not closed and version is
// current. The release is non-nil on every return and a second call of one release is a no-op. Every guard, whatever
// its current value, holds back EstablishV1, UnknownV1 and a state-changing PublishV1 until its release runs; a
// Changed-false PublishV1 does not wait.
func (o *HeaderCandidateOwner148V1) ProtectV1(version uint64) (bool, func()) {
	o.mu.Lock()
	o.guards++
	current := o.established && !o.latched && !o.closed && version == o.version.Load()
	o.mu.Unlock()
	released := false
	return current, func() {
		o.mu.Lock()
		if !released {
			released = true
			o.guards--
			if o.guards == 0 {
				o.cond.Broadcast()
			}
		}
		o.mu.Unlock()
	}
}

// Header148V1 writes the admitted raw bytes of hash into dst and returns true. On an absent hash or after CloseV1 it
// returns false and dst is unspecified. dst is never retained or written after return. It is callable under a held guard.
func (o *HeaderCandidateOwner148V1) Header148V1(hash [32]byte, dst *[148]byte) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	e := o.lookup(hash)
	if e == nil {
		return false
	}
	*dst = e.rec.Raw
	return true
}

// LookupV1 returns an independent copy of the admitted record, with the External stored at first admission.
func (o *HeaderCandidateOwner148V1) LookupV1(hash [32]byte) (HeaderCandidateRecord148V1, bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	e := o.lookup(hash)
	if e == nil {
		return HeaderCandidateRecord148V1{}, false
	}
	r := e.rec
	r.Work = new(big.Int).Set(e.rec.Work)
	return r, true
}

func (o *HeaderCandidateOwner148V1) lookup(hash [32]byte) *hcEntry {
	if o.closed {
		return nil
	}
	return o.recs[hash]
}

// gate evaluates first-refusal rows 1-3; wantEstablished is false only for EstablishV1.
func (o *HeaderCandidateOwner148V1) gate(wantEstablished bool) HeaderCandidateOutcome148V1 {
	switch {
	case o.closed:
		return HeaderCandidateClosed148V1
	case o.latched:
		return HeaderCandidateUnknownSource148V1
	case wantEstablished && !o.established:
		return HeaderCandidateNotEstablished148V1
	case !wantEstablished && o.established:
		return HeaderCandidateAlreadyEstablished148V1
	}
	return HeaderCandidateOK148V1
}

// EstablishV1 is the once-per-owner complete startup source join; it performs no replacement. It evaluates rows 1-3, 5,
// 7, 8, 11 and 12 of the first-refusal order with records read as Additions, waits for guards under the PublishV1 rule,
// and on OK advances the version by exactly one with Changed true and Retired empty. Every non-OK return carries the
// zero publication and changes no owner state: an owner that was not established stays so, with an unchanged version.
func (o *HeaderCandidateOwner148V1) EstablishV1(source [32]byte, records []HeaderCandidateRecord148V1) (HeaderCandidatePublication148V1, HeaderCandidateOutcome148V1) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if out := o.gate(false); out != HeaderCandidateOK148V1 {
		return HeaderCandidatePublication148V1{}, out
	}
	if hcTooLong(o.limits.MaxTransitionHeaders, uint64(len(records)), 0) || source == ([32]byte{}) {
		return HeaderCandidatePublication148V1{}, HeaderCandidateInvalid148V1
	}
	t := HeaderCandidateTransition148V1{NewSource: source, Additions: records}
	plan, out := o.planTransition(t, true)
	if out != HeaderCandidateOK148V1 {
		return HeaderCandidatePublication148V1{}, out
	}
	if out := o.waitGuards(); out != HeaderCandidateOK148V1 {
		return HeaderCandidatePublication148V1{}, out
	}
	// Rows 1-3 again: the owner may have been closed, latched or established while this call waited.
	if out := o.gate(false); out != HeaderCandidateOK148V1 {
		return HeaderCandidatePublication148V1{}, out
	}
	o.established = true
	return o.apply(&plan), HeaderCandidateOK148V1
}

// PrepareV1 validates and reserves the whole transition without changing membership or version; it does not wait for
// guards. It returns the first true row of the RUB-1550 first_refusal_order: Closed, UnknownSource, NotEstablished,
// Busy, Invalid, Stale, Conflict, MissingParent, NoCoverage, Protected, VersionExhausted, Capacity. Before Capacity it
// runs the D5 replacement walk: when a new qualified tip exists, unprotected tips strictly outranked by the weakest new
// tip are chosen weakest first with their exclusive ancestry until every row 12 ceiling fits; a candidate whose reclaim
// holds a leased hash, a received ancestor of a leased hash, or a hash of this transition's Additions is skipped whole.
// At most one prepared transition exists per owner. Every non-OK return carries a nil handle.
func (o *HeaderCandidateOwner148V1) PrepareV1(t HeaderCandidateTransition148V1) (*HeaderCandidatePrepared148V1, HeaderCandidateOutcome148V1) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if out := o.gate(true); out != HeaderCandidateOK148V1 {
		return nil, out
	}
	if o.prepared != nil {
		return nil, HeaderCandidateBusy148V1
	}
	if hcTooLong(o.limits.MaxTransitionHeaders, uint64(len(t.Additions)), uint64(len(t.Retired))) {
		return nil, HeaderCandidateInvalid148V1
	}
	plan, out := o.planTransition(t, false)
	if out != HeaderCandidateOK148V1 {
		return nil, out
	}
	h := &HeaderCandidatePrepared148V1{owner: o, plan: plan}
	o.prepared = h
	return h, HeaderCandidateOK148V1
}

// hcTooLong is the row 5 length check, before any proportional allocation.
func hcTooLong(limit, a, r uint64) bool {
	return a > limit || r > limit-a
}

// waitGuards waits, with mu held on entry and exit, until no guard is held or the owner is closed.
func (o *HeaderCandidateOwner148V1) waitGuards() HeaderCandidateOutcome148V1 {
	for o.guards > 0 && !o.closed {
		o.cond.Wait()
	}
	if o.closed {
		return HeaderCandidateClosed148V1
	}
	return HeaderCandidateOK148V1
}

// PublishV1 applies additions, retirements, charges and source atomically. A state-changing transition waits until no
// guard is held and advances the version by one; a Changed-false transition does not wait and keeps the version. A
// second call of any handle method returns Consumed; otherwise a destroyed owner returns Closed (also when CloseV1 wakes
// the wait). Every non-OK return carries the zero publication and applies nothing.
func (h *HeaderCandidatePrepared148V1) PublishV1() (HeaderCandidatePublication148V1, HeaderCandidateOutcome148V1) {
	o := h.owner
	o.mu.Lock()
	defer o.mu.Unlock()
	if out := h.consume(); out != HeaderCandidateOK148V1 {
		return HeaderCandidatePublication148V1{}, out
	}
	if h.plan.changed {
		if out := o.waitGuards(); out != HeaderCandidateOK148V1 {
			return HeaderCandidatePublication148V1{}, out
		}
	}
	o.prepared = nil
	return o.apply(&h.plan), HeaderCandidateOK148V1
}

// AbortV1 is a known abort: the reservation is released and membership, charges and version are unchanged. It returns
// OK on a first call to an open owner, Consumed on a later handle call, otherwise Closed.
func (h *HeaderCandidatePrepared148V1) AbortV1() HeaderCandidateOutcome148V1 {
	o := h.owner
	o.mu.Lock()
	defer o.mu.Unlock()
	if out := h.consume(); out != HeaderCandidateOK148V1 {
		return out
	}
	o.prepared = nil
	return HeaderCandidateOK148V1
}

// UnknownV1 is an unknown native outcome. It always waits until no guard is held, applies no addition or retirement,
// keeps the slot occupied, advances the version when representable and latches the owner: later Inventory148V1 is
// Incomplete, ProtectV1 returns current false with a non-nil release, and EstablishV1, PrepareV1 and
// AcquireDependencyV1 return UnknownSource until a new incarnation. Reads answer the unchanged membership. It returns OK
// on a first call to an open owner, Consumed on a later handle call, otherwise Closed (also when CloseV1 wakes the wait).
func (h *HeaderCandidatePrepared148V1) UnknownV1() HeaderCandidateOutcome148V1 {
	o := h.owner
	o.mu.Lock()
	defer o.mu.Unlock()
	if out := h.consume(); out != HeaderCandidateOK148V1 {
		return out
	}
	if out := o.waitGuards(); out != HeaderCandidateOK148V1 {
		return out
	}
	o.latched = true
	if v := o.version.Load(); v != math.MaxUint64 {
		o.version.Store(v + 1)
	}
	return HeaderCandidateOK148V1
}

// consume marks the handle used; mu is held.
func (h *HeaderCandidatePrepared148V1) consume() HeaderCandidateOutcome148V1 {
	if h.consumed {
		return HeaderCandidateConsumed148V1
	}
	h.consumed = true
	if h.owner.closed {
		return HeaderCandidateClosed148V1
	}
	return HeaderCandidateOK148V1
}

// AcquireDependencyV1 pins hash and every received ancestor against every retirement; a version advance does not revoke
// the lease. It evaluates rows 1-3, then Missing (hash absent), Protected (hash or an ancestor in the outstanding planned
// removal, capacity victims included) and Capacity (MaxLeases reached). Every non-OK return carries a nil lease.
func (o *HeaderCandidateOwner148V1) AcquireDependencyV1(hash [32]byte) (*HeaderCandidateLease148V1, HeaderCandidateOutcome148V1) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if out := o.gate(true); out != HeaderCandidateOK148V1 {
		return nil, out
	}
	if o.recs[hash] == nil {
		return nil, HeaderCandidateMissing148V1
	}
	if o.plannedRemovalHits(hash) {
		return nil, HeaderCandidateProtected148V1
	}
	if o.leases >= o.limits.MaxLeases {
		return nil, HeaderCandidateCapacity148V1
	}
	o.leased[hash]++
	o.leases++
	return &HeaderCandidateLease148V1{owner: o, hash: hash}, HeaderCandidateOK148V1
}

// plannedRemovalHits reports whether hash or a received ancestor is in the outstanding planned removal (D6).
func (o *HeaderCandidateOwner148V1) plannedRemovalHits(hash [32]byte) bool {
	if o.prepared == nil || len(o.prepared.plan.retired) == 0 {
		return false
	}
	removal := make(map[[32]byte]struct{}, len(o.prepared.plan.retired))
	for _, r := range o.prepared.plan.retired {
		removal[r] = struct{}{}
	}
	for e := o.recs[hash]; e != nil; e = o.recs[e.rec.Parent] {
		if _, ok := removal[e.rec.Hash]; ok {
			return true
		}
	}
	return false
}

// ReleaseV1 releases the lease once; later calls and calls after CloseV1 are no-ops.
func (l *HeaderCandidateLease148V1) ReleaseV1() {
	o := l.owner
	o.mu.Lock()
	defer o.mu.Unlock()
	if l.released || o.closed {
		return
	}
	l.released = true
	o.leases--
	if o.leased[l.hash]--; o.leased[l.hash] == 0 {
		delete(o.leased, l.hash)
	}
}

// protectedSet is every leased hash and its received ancestors in current membership.
func (o *HeaderCandidateOwner148V1) protectedSet() map[[32]byte]struct{} {
	p := map[[32]byte]struct{}{}
	for h := range o.leased {
		for e := o.recs[h]; e != nil; e = o.recs[e.rec.Parent] {
			if _, seen := p[e.rec.Hash]; seen {
				break
			}
			p[e.rec.Hash] = struct{}{}
		}
	}
	return p
}

// apply commits a validated plan and returns an independent receipt; mu is held.
func (o *HeaderCandidateOwner148V1) apply(p *hcPlan) HeaderCandidatePublication148V1 {
	if !p.changed {
		return HeaderCandidatePublication148V1{Version: o.version.Load(), Added: [][32]byte{}, Retired: [][32]byte{}}
	}
	for i := range p.adds {
		o.insert(p.adds[i])
	}
	for i := range p.prov {
		o.recs[p.prov[i].Hash].rec.Provenance = p.prov[i].Provenance
	}
	for _, h := range p.retired {
		o.remove(h)
	}
	o.source = p.source
	v := o.version.Load() + 1
	o.version.Store(v)
	return HeaderCandidatePublication148V1{Changed: true, Version: v, Added: slices.Clone(p.added), Retired: slices.Clone(p.retired)}
}

func (o *HeaderCandidateOwner148V1) insert(r HeaderCandidateRecord148V1) {
	if o.kids[r.Hash] == 0 {
		o.tips++
	}
	if parent := o.recs[r.Parent]; parent != nil && o.kids[r.Parent] == 0 {
		o.tips--
	}
	o.kids[r.Parent]++
	o.recs[r.Hash] = &hcEntry{rec: r, charge: hcCharge(r.Work)}
}

func (o *HeaderCandidateOwner148V1) remove(h [32]byte) {
	e := o.recs[h]
	if o.kids[h] == 0 {
		o.tips--
	}
	p := e.rec.Parent
	if o.kids[p]--; o.kids[p] == 0 {
		delete(o.kids, p)
		if o.recs[p] != nil {
			o.tips++
		}
	}
	delete(o.recs, h)
}

// hcCharge is 148 raw + 32 hash + 32 parent + 8 height + 32 provenance + the minimal big-endian Work length.
// It reads BitLen, so charging allocates nothing.
func hcCharge(w *big.Int) uint64 {
	n := w.BitLen()
	if n <= 0 {
		return 252
	}
	return 252 + (uint64(n)+7)/8
}

func hcAddSat(a, b uint64) uint64 {
	s, c := bits.Add64(a, b, 0)
	if c != 0 {
		return math.MaxUint64
	}
	return s
}

// hcOutranks reports whether a strictly outranks b: greater Work, then the bytewise smaller hash.
func hcOutranks(aw *big.Int, ah [32]byte, bw *big.Int, bh [32]byte) bool {
	if c := aw.Cmp(bw); c != 0 {
		return c > 0
	}
	return bytes.Compare(ah[:], bh[:]) < 0
}

// hcTx is one transition under validation; mu is held for its whole life.
type hcTx struct {
	o      *HeaderCandidateOwner148V1
	t      HeaderCandidateTransition148V1
	est    bool
	addIdx map[[32]byte]int
	retIdx map[[32]byte]int
}

// planTransition evaluates first-refusal rows 5-12 (row 5 length already checked) and returns the reservation.
func (o *HeaderCandidateOwner148V1) planTransition(t HeaderCandidateTransition148V1, est bool) (hcPlan, HeaderCandidateOutcome148V1) {
	x := &hcTx{o: o, t: t, est: est}
	for _, step := range [...]func() HeaderCandidateOutcome148V1{x.shape, x.stale, x.conflicts, x.parents, x.coverage, x.protected} {
		if out := step(); out != HeaderCandidateOK148V1 {
			return hcPlan{}, out
		}
	}
	p := x.build()
	if p.changed && o.version.Load() == math.MaxUint64 {
		return hcPlan{}, HeaderCandidateVersionExhausted148V1
	}
	victims, ok := x.capacity()
	if !ok {
		return hcPlan{}, HeaderCandidateCapacity148V1
	}
	p.retired = append(p.retired, victims...)
	// Work is copied only after row 12 accepted the plan, so the caller's value cannot reach owner state.
	for i := range p.adds {
		p.adds[i].Work = new(big.Int).Set(p.adds[i].Work)
	}
	return p, HeaderCandidateOK148V1
}

// hcRecordValid is the per-record part of row 5.
func hcRecordValid(r *HeaderCandidateRecord148V1) bool {
	hdr, err := consensus.ParseInitial148HeaderBytes(r.Raw[:])
	if err != nil {
		return false
	}
	h, err := consensus.Initial148BlockHash(r.Raw[:])
	if err != nil || h != r.Hash {
		return false
	}
	return hdr.PrevBlockHash == r.Parent && r.Work != nil && r.Work.Sign() > 0 && r.Provenance != [32]byte{}
}

// shape is row 5 after the length check: record shape, duplicates, overlap and parent-before-child order.
func (x *hcTx) shape() HeaderCandidateOutcome148V1 {
	adds := x.t.Additions
	for i := range adds {
		if !hcRecordValid(&adds[i]) {
			return HeaderCandidateInvalid148V1
		}
	}
	x.addIdx = make(map[[32]byte]int, len(adds))
	for i := range adds {
		if _, dup := x.addIdx[adds[i].Hash]; dup {
			return HeaderCandidateInvalid148V1
		}
		x.addIdx[adds[i].Hash] = i
	}
	if !x.indexRetired() || !x.ordered() {
		return HeaderCandidateInvalid148V1
	}
	return HeaderCandidateOK148V1
}

func (x *hcTx) indexRetired() bool {
	x.retIdx = make(map[[32]byte]int, len(x.t.Retired))
	for i, r := range x.t.Retired {
		_, dup := x.retIdx[r]
		_, both := x.addIdx[r]
		if dup || both {
			return false
		}
		x.retIdx[r] = i
	}
	return true
}

// ordered reports parent-before-child order inside Additions and inside Retired (Retired parents from membership).
func (x *hcTx) ordered() bool {
	for i := range x.t.Additions {
		if j, ok := x.addIdx[x.t.Additions[i].Parent]; ok && j >= i {
			return false
		}
	}
	for i, r := range x.t.Retired {
		e := x.o.recs[r]
		if e == nil {
			continue
		}
		if j, ok := x.retIdx[e.rec.Parent]; ok && j >= i {
			return false
		}
	}
	return true
}

// stale is row 6; EstablishV1 has no expectation.
func (x *hcTx) stale() HeaderCandidateOutcome148V1 {
	if !x.est && (x.t.ExpectedVersion != x.o.version.Load() || x.t.ExpectedSource != x.o.source) {
		return HeaderCandidateStale148V1
	}
	return HeaderCandidateOK148V1
}

// conflicts is row 7 over the working set (D8, D9).
func (x *hcTx) conflicts() HeaderCandidateOutcome148V1 {
	for i := range x.t.Additions {
		a := &x.t.Additions[i]
		if e := x.o.recs[a.Hash]; e != nil {
			if e.rec.Height != a.Height || e.rec.Work.Cmp(a.Work) != 0 {
				return HeaderCandidateConflict148V1
			}
			continue
		}
		if ph, ok := x.workingHeight(a.Parent, i); ok && (a.Height == 0 || ph != a.Height-1) {
			return HeaderCandidateConflict148V1
		}
	}
	return HeaderCandidateOK148V1
}

// workingHeight resolves a parent in current membership or among the Additions listed before index i.
func (x *hcTx) workingHeight(p [32]byte, i int) (uint64, bool) {
	if e := x.o.recs[p]; e != nil {
		return e.rec.Height, true
	}
	if j, ok := x.addIdx[p]; ok && j < i {
		return x.t.Additions[j].Height, true
	}
	return 0, false
}

func (x *hcTx) inWorking(h [32]byte) bool {
	if x.o.recs[h] != nil {
		return true
	}
	_, ok := x.addIdx[h]
	return ok
}

// parents is row 8 over the post-transition set, for additions not currently admitted.
func (x *hcTx) parents() HeaderCandidateOutcome148V1 {
	for i := range x.t.Additions {
		a := &x.t.Additions[i]
		if x.o.recs[a.Hash] != nil || a.External {
			continue
		}
		if _, retired := x.retIdx[a.Parent]; retired || !x.inWorking(a.Parent) {
			return HeaderCandidateMissingParent148V1
		}
	}
	return HeaderCandidateOK148V1
}

// coverage is row 9: every Retired hash is admitted and its Parent is gone after the earlier Retired entries.
func (x *hcTx) coverage() HeaderCandidateOutcome148V1 {
	for i, r := range x.t.Retired {
		e := x.o.recs[r]
		if e == nil {
			return HeaderCandidateNoCoverage148V1
		}
		j, earlier := x.retIdx[e.rec.Parent]
		if x.inWorking(e.rec.Parent) && (!earlier || j >= i) {
			return HeaderCandidateNoCoverage148V1
		}
	}
	return HeaderCandidateOK148V1
}

// protected is row 10.
func (x *hcTx) protected() HeaderCandidateOutcome148V1 {
	if len(x.t.Retired) == 0 || len(x.o.leased) == 0 {
		return HeaderCandidateOK148V1
	}
	ps := x.o.protectedSet()
	for _, r := range x.t.Retired {
		if _, ok := ps[r]; ok {
			return HeaderCandidateProtected148V1
		}
	}
	return HeaderCandidateOK148V1
}

// build classifies each addition as new, provenance update or identical duplicate and fixes the receipt order (D7).
func (x *hcTx) build() hcPlan {
	o := x.o
	p := hcPlan{source: o.source, retired: append([][32]byte{}, x.t.Retired...), added: [][32]byte{}}
	for i := range x.t.Additions {
		a := x.t.Additions[i]
		e := o.recs[a.Hash]
		switch {
		case e == nil:
			p.adds = append(p.adds, a)
			p.added = append(p.added, a.Hash)
		case e.rec.Provenance != a.Provenance:
			p.prov = append(p.prov, a)
		}
	}
	sourceChange := x.t.NewSource != [32]byte{} && x.t.NewSource != o.source
	if sourceChange {
		p.source = x.t.NewSource
	}
	p.changed = x.est || sourceChange || len(p.adds)+len(p.prov)+len(p.retired) > 0
	return p
}

// hcPost is the post-transition received set used by row 12.
type hcPost struct {
	nodes   map[[32]byte]*hcEntry
	kids    map[[32]byte]uint64
	tips    uint64
	headers uint64
	bytes   uint64
}

func (x *hcTx) post() *hcPost {
	s := &hcPost{nodes: make(map[[32]byte]*hcEntry, len(x.o.recs)+len(x.t.Additions)), kids: map[[32]byte]uint64{}}
	for h, e := range x.o.recs {
		if _, gone := x.retIdx[h]; !gone {
			s.nodes[h] = e
		}
	}
	for i := range x.t.Additions {
		a := &x.t.Additions[i]
		if s.nodes[a.Hash] == nil && x.o.recs[a.Hash] == nil {
			s.nodes[a.Hash] = &hcEntry{rec: *a, charge: hcCharge(a.Work)}
		}
	}
	s.tally()
	return s
}

// tally derives children, tips, headers and saturating bytes of the post-transition set.
func (s *hcPost) tally() {
	for _, e := range s.nodes {
		s.kids[e.rec.Parent]++
		s.bytes = hcAddSat(s.bytes, e.charge)
	}
	for h := range s.nodes {
		if s.kids[h] == 0 {
			s.tips++
		}
	}
	s.headers = uint64(len(s.nodes))
}

func (o *HeaderCandidateOwner148V1) fits(s *hcPost) bool {
	return s.tips <= o.limits.MaxTips && s.headers <= o.limits.MaxHeaders && s.bytes <= o.limits.MaxRetainedBytes
}

// capacity is row 12 with the D5 replacement walk; it returns the chosen reclaims in choice order.
func (x *hcTx) capacity() ([][32]byte, bool) {
	s := x.post()
	if x.o.fits(s) {
		return nil, true
	}
	if x.est {
		return nil, false
	}
	fresh, old := x.splitTips(s)
	if len(fresh) == 0 {
		return nil, false
	}
	comp := fresh[0]
	protected := x.o.protectedSet()
	var victims [][32]byte
	for _, c := range old {
		if !hcOutranks(comp.rec.Work, comp.rec.Hash, c.rec.Work, c.rec.Hash) {
			return nil, false
		}
		reclaim := s.exclusive(c)
		if x.blocked(reclaim, protected) {
			continue
		}
		s.drop(reclaim)
		victims = append(victims, reclaim...)
		if x.o.fits(s) {
			return victims, true
		}
	}
	return nil, false
}

// splitTips returns the new qualified tips and the other tips, each weakest first (equal Work: larger hash first).
func (x *hcTx) splitTips(s *hcPost) (fresh, old []*hcEntry) {
	for h, e := range s.nodes {
		if s.kids[h] != 0 {
			continue
		}
		if x.o.recs[h] == nil {
			fresh = append(fresh, e)
		} else {
			old = append(old, e)
		}
	}
	slices.SortFunc(fresh, hcWeakFirst)
	slices.SortFunc(old, hcWeakFirst)
	return fresh, old
}

func hcWeakFirst(a, b *hcEntry) int {
	if a.rec.Hash == b.rec.Hash {
		return 0
	}
	if hcOutranks(b.rec.Work, b.rec.Hash, a.rec.Work, a.rec.Hash) {
		return -1
	}
	return 1
}

// exclusive is the tip plus every ancestor that would lie on no surviving tip's path, tip first then downward.
func (s *hcPost) exclusive(tip *hcEntry) [][32]byte {
	out := [][32]byte{tip.rec.Hash}
	for cur := tip; ; {
		p := s.nodes[cur.rec.Parent]
		if p == nil || s.kids[cur.rec.Parent] != 1 {
			return out
		}
		out = append(out, p.rec.Hash)
		cur = p
	}
}

func (x *hcTx) blocked(reclaim [][32]byte, protected map[[32]byte]struct{}) bool {
	for _, h := range reclaim {
		_, p := protected[h]
		_, a := x.addIdx[h]
		if p || a {
			return true
		}
	}
	return false
}

// drop removes one chosen reclaim. Only its lowest header's parent can lose a child; when that parent is in the set it
// keeps another child. A saturated byte sum stays saturated, so it never decrements into a false fit.
func (s *hcPost) drop(reclaim [][32]byte) {
	for _, h := range reclaim {
		if s.bytes != math.MaxUint64 {
			s.bytes -= s.nodes[h].charge
		}
	}
	s.kids[s.nodes[reclaim[len(reclaim)-1]].rec.Parent]--
	for _, h := range reclaim {
		delete(s.nodes, h)
	}
	s.tips--
	s.headers -= uint64(len(reclaim))
}

// hcInventoryBytes is 32*tips + 148*headers with checked arithmetic.
func hcInventoryBytes(tips, headers uint64) (uint64, bool) {
	th, tl := bits.Mul64(tips, 32)
	hh, hl := bits.Mul64(headers, 148)
	sum, c := bits.Add64(tl, hl, 0)
	return sum, th == 0 && hh == 0 && c == 0
}

// copyInventory copies every tip hash and raw header into the two charged arrays only, each sorted in place so the
// output never depends on map iteration; mu is held.
func (o *HeaderCandidateOwner148V1) copyInventory() ([][32]byte, [][148]byte) {
	tips := make([][32]byte, 0, o.tips)
	headers := make([][148]byte, 0, len(o.recs))
	for h, e := range o.recs {
		if o.kids[h] == 0 {
			tips = append(tips, h)
		}
		headers = append(headers, e.rec.Raw)
	}
	slices.SortFunc(tips, func(a, b [32]byte) int { return bytes.Compare(a[:], b[:]) })
	slices.SortFunc(headers, func(a, b [148]byte) int { return bytes.Compare(a[:], b[:]) })
	return tips, headers
}
