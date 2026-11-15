package node

import (
	"errors"
	"math"
	"slices"
)

// ErrPendingBodyConfig148V1 rejects nonfinite or empty custody ceilings.
var ErrPendingBodyConfig148V1 = errors.New("pending body 148: invalid configuration")

// PendingBodyLimits148V1 captures local logical ceilings and a monotonic lifetime.
type PendingBodyLimits148V1 struct {
	MaxCandidates, MaxBytes, MaxDependencies, MaxLifetime uint64
}

// PendingBodyOutcome148V1 reports custody only, without validity or dispatch authority.
type PendingBodyOutcome148V1 uint8

const (
	PendingBodyOK148V1 PendingBodyOutcome148V1 = iota
	PendingBodyUnavailable148V1
	PendingBodyInvalid148V1
	PendingBodyStale148V1
	PendingBodyCapacity148V1
	PendingBodyDuplicate148V1
	PendingBodyAbsent148V1
	PendingBodyConsumed148V1
)

// PendingBodyDecision148V1 preserves a lifecycle refusal from the attached C1 owner.
type PendingBodyDecision148V1 struct {
	Outcome          PendingBodyOutcome148V1
	CandidateOutcome HeaderCandidateOutcome148V1
}

// PendingBodyRelease148V1 is the closed terminal-disposal domain, never peer fault.
type PendingBodyRelease148V1 uint8

const (
	PendingBodyReleaseCapacity148V1 PendingBodyRelease148V1 = iota + 1
	PendingBodyReleaseExpired148V1
	PendingBodyReleaseCancelled148V1
	PendingBodyReleaseSourceLost148V1
	PendingBodyReleaseInvalidParentOrBody148V1
	PendingBodyReleaseShutdown148V1
)

// PendingBodyCompletion148V1 identifies producer-qualified weak provenance only.
type PendingBodyCompletion148V1 uint8

const (
	PendingBodyLocalComplete148V1 PendingBodyCompletion148V1 = iota + 1
	PendingBodyAssociatedResponse148V1
)

// PendingBodyWeak148V1 is an opaque, fixed-size producer capability, not a score.
// Its separately authorized producer supplies one shared provenance payload.
type PendingBodyWeak148V1 struct {
	origin           uint64
	hash, provenance [32]byte
	completion       PendingBodyCompletion148V1
	ended, consumed  bool
}

// PendingBodyKey148V1 separates independent acquisition lifetimes for the same hash.
type PendingBodyKey148V1 struct {
	Origin uint64
	Hash   [32]byte
}

// PendingBodyBundle148V1 moves exclusive producer-owned storage and genuine pins.
// Success consumes every field; refusal leaves every field and resource untouched.
// RetainedBytes includes all retained aliases and is at least cap(Body).
type PendingBodyBundle148V1 struct {
	Body                     []byte
	RetainedBytes, Origin    uint64
	Hash, Parent, Provenance [32]byte
	View                     HeaderContextView148V1
	Dependencies             []*HeaderContextLease148V1
	Weak                     *PendingBodyWeak148V1
}

// PendingBodyRequest148V1 is an opaque record-bound once-only move request.
type PendingBodyRequest148V1 struct {
	owner    *HeaderCandidateOwner148V1
	record   *pendingBodyRecord148
	consumed bool
}

type pendingBodyRecord148 struct {
	bundle   PendingBodyBundle148V1
	charge   uint64
	deadline uint64
	request  *PendingBodyRequest148V1
	next     *pendingBodyRecord148
}

type pendingBodyState148 struct {
	limits              PendingBodyLimits148V1
	records             map[PendingBodyKey148V1]*pendingBodyRecord148
	bytes, dependencies uint64
}

// NewHeaderCandidateBodyCustody148V1 attaches dormant custody to the same C1/C2 host.
// C1 and C2 configuration errors retain their existing identity and precedence.
func NewHeaderCandidateBodyCustody148V1(cl HeaderCandidateLimits148V1, xl HeaderContextLimits148V1, bl PendingBodyLimits148V1, incarnation uint64, network, genesis [32]byte) (*HeaderCandidateOwner148V1, error) {
	o, err := NewHeaderCandidateContext148V1(cl, xl, incarnation, network, genesis)
	if err != nil {
		return nil, err
	}
	if !pendingBodyLimitsValid(bl) {
		return nil, ErrPendingBodyConfig148V1
	}
	o.pendingBody = &pendingBodyState148{limits: bl, records: map[PendingBodyKey148V1]*pendingBodyRecord148{}}
	return o, nil
}

// pendingBodyLimitsValid accepts only positive captured finite limits.
func pendingBodyLimitsValid(l PendingBodyLimits148V1) bool {
	for _, n := range [...]uint64{l.MaxCandidates, l.MaxBytes, l.MaxDependencies, l.MaxLifetime} {
		if n == 0 || n == math.MaxUint64 {
			return false
		}
	}
	return true
}

// pendingBodyDecision constructs a pure local outcome with CandidateOK.
func pendingBodyDecision(out PendingBodyOutcome148V1) PendingBodyDecision148V1 {
	return PendingBodyDecision148V1{Outcome: out}
}

// pendingBodyGate runs lifecycle checks before touching caller input; mu is held.
func (o *HeaderCandidateOwner148V1) pendingBodyGate() PendingBodyDecision148V1 {
	if out := o.gate(true); out != HeaderCandidateOK148V1 {
		return PendingBodyDecision148V1{Outcome: PendingBodyUnavailable148V1, CandidateOutcome: out}
	}
	if o.pendingBody == nil {
		return pendingBodyDecision(PendingBodyUnavailable148V1)
	}
	return PendingBodyDecision148V1{}
}

// pendingBodyShape checks fixed fields before dependency work or freshness; mu is held.
func (o *HeaderCandidateOwner148V1) pendingBodyShape(b *PendingBodyBundle148V1) bool {
	if b == nil || len(b.Body) == 0 {
		return false
	}
	if b.RetainedBytes < uint64(cap(b.Body)) || !pendingBodyKeyValid(PendingBodyKey148V1{b.Origin, b.Hash}) {
		return false
	}
	return b.Provenance != ([32]byte{}) && o.pendingBodyViewShape(b.View) && pendingBodyWeakValid(b)
}

// pendingBodyViewShape distinguishes malformed source identity from stale identity.
func (o *HeaderCandidateOwner148V1) pendingBodyViewShape(v HeaderContextView148V1) bool {
	return hctxViewShape(v) && v.Network == o.context.network && v.Genesis == o.context.genesis
}

// pendingBodyWeakValid admits nil or one exact live completion payload, never credit.
func pendingBodyWeakValid(b *PendingBodyBundle148V1) bool {
	w := b.Weak
	if w == nil {
		return true
	}
	if w.ended || w.consumed || w.origin != b.Origin {
		return false
	}
	if w.hash != b.Hash || w.provenance != b.Provenance {
		return false
	}
	return w.completion == PendingBodyLocalComplete148V1 || w.completion == PendingBodyAssociatedResponse148V1
}

// pendingBodyKeyValid admits only an actual origin and selected hash.
func pendingBodyKeyValid(key PendingBodyKey148V1) bool {
	return key.Origin != 0 && key.Hash != ([32]byte{})
}

// pendingBodyHandles validates bounded genuine handles without acquiring or copying; mu is held.
func (o *HeaderCandidateOwner148V1) pendingBodyHandles(b *PendingBodyBundle148V1) bool {
	selected := false
	for i, l := range b.Dependencies {
		if !o.pendingBodyHandleLive(l) {
			return false
		}
		if slices.Contains(b.Dependencies[:i], l) {
			return false
		}
		selected = selected || l.hash == b.Hash
	}
	return selected
}

// pendingBodyHandleLive checks the genuine C2 handle's owner and release disposition.
func (o *HeaderCandidateOwner148V1) pendingBodyHandleLive(l *HeaderContextLease148V1) bool {
	return l != nil && l.owner == o && !l.released
}

// pendingBodyCurrent separates stale views, absent evidence and conflicting identity; mu is held.
func (o *HeaderCandidateOwner148V1) pendingBodyCurrent(b *PendingBodyBundle148V1) PendingBodyDecision148V1 {
	v := b.View
	if v.Incarnation != o.incarnation || v.Version != o.version.Load() || v.Source != o.source {
		return pendingBodyDecision(PendingBodyStale148V1)
	}
	r, ok := o.context.records[b.Hash]
	if !ok {
		return pendingBodyDecision(PendingBodyUnavailable148V1)
	}
	if r.View != v {
		return pendingBodyDecision(PendingBodyStale148V1)
	}
	if !pendingBodyIdentity(r, b) {
		return pendingBodyDecision(PendingBodyInvalid148V1)
	}
	return PendingBodyDecision148V1{}
}

// pendingBodyIdentity compares the cached body's exact selected provenance.
func pendingBodyIdentity(r HeaderContextRecord148V1, b *PendingBodyBundle148V1) bool {
	return r.Hash == b.Hash && r.Parent == b.Parent && r.Provenance == b.Provenance
}

// pendingBodyInput runs the ordered, nonmutating intake checks; mu is held.
func (o *HeaderCandidateOwner148V1) pendingBodyInput(b *PendingBodyBundle148V1) PendingBodyDecision148V1 {
	if d := o.pendingBodyGate(); d.Outcome != PendingBodyOK148V1 {
		return d
	}
	if !o.pendingBodyShape(b) {
		return pendingBodyDecision(PendingBodyInvalid148V1)
	}
	if uint64(len(b.Dependencies)) > o.pendingBody.limits.MaxDependencies {
		return pendingBodyDecision(PendingBodyCapacity148V1)
	}
	if !o.pendingBodyHandles(b) {
		return pendingBodyDecision(PendingBodyInvalid148V1)
	}
	return o.pendingBodyCurrent(b)
}

// pendingBodyFits computes all logical charges and the fixed deadline before allocation.
func (s *pendingBodyState148) pendingBodyFits(b *PendingBodyBundle148V1, now uint64) (uint64, uint64, bool) {
	n := uint64(len(b.Dependencies))
	meta := hctxSum(256, hctxMul(8, n))
	charge := hctxSum(b.RetainedBytes, meta)
	if uint64(len(s.records)) >= s.limits.MaxCandidates || hctxSum(s.bytes, charge) > s.limits.MaxBytes {
		return 0, 0, false
	}
	if hctxSum(s.dependencies, n) > s.limits.MaxDependencies || now > math.MaxUint64-s.limits.MaxLifetime {
		return 0, 0, false
	}
	return charge, now + s.limits.MaxLifetime, true
}

// RetainPendingBodyV1 moves an exclusive qualified bundle only after every refusal check.
// The producer protects source authority through this call and must abandon aliases on OK.
func (o *HeaderCandidateOwner148V1) RetainPendingBodyV1(b *PendingBodyBundle148V1, now uint64) PendingBodyDecision148V1 {
	for {
		o.mu.Lock()
		d := o.pendingBodyInput(b)
		if d.Outcome != PendingBodyOK148V1 {
			o.mu.Unlock()
			return d
		}
		key := PendingBodyKey148V1{b.Origin, b.Hash}
		if old := o.expirePendingBody(key, now); old != nil {
			o.mu.Unlock()
			drainPendingBodies(old)
			continue
		}
		d = o.publishPendingBody(key, b, now)
		o.mu.Unlock()
		return d
	}
}

// publishPendingBody checks duplicate before quotas and commits the single ownership move.
func (o *HeaderCandidateOwner148V1) publishPendingBody(key PendingBodyKey148V1, b *PendingBodyBundle148V1, now uint64) PendingBodyDecision148V1 {
	s := o.pendingBody
	if s.records[key] != nil {
		return pendingBodyDecision(PendingBodyDuplicate148V1)
	}
	charge, deadline, fits := s.pendingBodyFits(b, now)
	if !fits {
		return pendingBodyDecision(PendingBodyCapacity148V1)
	}
	s.records[key] = &pendingBodyRecord148{bundle: *b, charge: charge, deadline: deadline}
	s.bytes += charge
	s.dependencies += uint64(len(b.Dependencies))
	*b = PendingBodyBundle148V1{}
	return PendingBodyDecision148V1{}
}

// detachPendingBody removes all live custody references and consumes its request; mu is held.
func (o *HeaderCandidateOwner148V1) detachPendingBody(key PendingBodyKey148V1) *pendingBodyRecord148 {
	s := o.pendingBody
	r := s.records[key]
	delete(s.records, key)
	s.bytes -= r.charge
	s.dependencies -= uint64(len(r.bundle.Dependencies))
	if r.request != nil {
		r.request.consumed = true
		r.request = nil
	}
	return r
}

// expirePendingBody detaches only the matching expired key without touching incoming resources.
func (o *HeaderCandidateOwner148V1) expirePendingBody(key PendingBodyKey148V1, now uint64) *pendingBodyRecord148 {
	if r := o.pendingBody.records[key]; r != nil && now >= r.deadline {
		return o.detachPendingBody(key)
	}
	return nil
}

// drainPendingBodies releases genuine C2/C1 handles only outside the shared mutex.
func drainPendingBodies(r *pendingBodyRecord148) {
	for r != nil {
		for _, l := range r.bundle.Dependencies {
			l.ReleaseV1()
		}
		if w := r.bundle.Weak; w != nil {
			w.ended = true
		}
		r.bundle = PendingBodyBundle148V1{}
		next := r.next
		r.next = nil
		r = next
	}
}

// PendingBodyRetainedV1 observes only live custody, with matching expiry cleanup.
func (o *HeaderCandidateOwner148V1) PendingBodyRetainedV1(key PendingBodyKey148V1, now uint64) bool {
	o.mu.Lock()
	if o.closed || o.pendingBody == nil {
		o.mu.Unlock()
		return false
	}
	expired := o.expirePendingBody(key, now)
	present := o.pendingBody.records[key] != nil
	o.mu.Unlock()
	drainPendingBodies(expired)
	return present
}

// RequestPendingBodyV1 emits at most one opaque request for the current live record.
func (o *HeaderCandidateOwner148V1) RequestPendingBodyV1(key *PendingBodyKey148V1, now uint64) (*PendingBodyRequest148V1, PendingBodyDecision148V1) {
	o.mu.Lock()
	if d := o.pendingBodyGate(); d.Outcome != PendingBodyOK148V1 {
		o.mu.Unlock()
		return nil, d
	}
	if key == nil || !pendingBodyKeyValid(*key) {
		o.mu.Unlock()
		return nil, pendingBodyDecision(PendingBodyInvalid148V1)
	}
	expired := o.expirePendingBody(*key, now)
	request, d := o.requestPendingBody(*key)
	o.mu.Unlock()
	drainPendingBodies(expired)
	return request, d
}

// requestPendingBody coalesces requests without refreshing the captured deadline; mu is held.
func (o *HeaderCandidateOwner148V1) requestPendingBody(key PendingBodyKey148V1) (*PendingBodyRequest148V1, PendingBodyDecision148V1) {
	r := o.pendingBody.records[key]
	if r == nil {
		return nil, pendingBodyDecision(PendingBodyAbsent148V1)
	}
	if r.request != nil {
		return nil, PendingBodyDecision148V1{}
	}
	r.request = &PendingBodyRequest148V1{owner: o, record: r}
	return r.request, PendingBodyDecision148V1{}
}

// pendingBodyRequest checks token provenance before any current record is touched; mu is held.
func (o *HeaderCandidateOwner148V1) pendingBodyRequest(q *PendingBodyRequest148V1) PendingBodyDecision148V1 {
	if q == nil || q.owner != o || q.record == nil {
		return pendingBodyDecision(PendingBodyInvalid148V1)
	}
	if q.consumed {
		return pendingBodyDecision(PendingBodyConsumed148V1)
	}
	if q.record.request != q {
		return pendingBodyDecision(PendingBodyInvalid148V1)
	}
	return PendingBodyDecision148V1{}
}

// TakePendingBodyV1 returns the exact owned bundle once, without releasing its handles.
// The receiver must separately acquire dispatch and freshly qualify ordinary admission.
func (o *HeaderCandidateOwner148V1) TakePendingBodyV1(q *PendingBodyRequest148V1, now uint64) (*PendingBodyBundle148V1, PendingBodyDecision148V1) {
	o.mu.Lock()
	if d := o.pendingBodyGate(); d.Outcome != PendingBodyOK148V1 {
		o.mu.Unlock()
		return nil, d
	}
	if d := o.pendingBodyRequest(q); d.Outcome != PendingBodyOK148V1 {
		o.mu.Unlock()
		return nil, d
	}
	key := PendingBodyKey148V1{q.record.bundle.Origin, q.record.bundle.Hash}
	if expired := o.expirePendingBody(key, now); expired != nil {
		o.mu.Unlock()
		drainPendingBodies(expired)
		return nil, pendingBodyDecision(PendingBodyAbsent148V1)
	}
	r := o.detachPendingBody(key)
	b := r.bundle
	r.bundle = PendingBodyBundle148V1{}
	o.mu.Unlock()
	return &b, PendingBodyDecision148V1{}
}

// ReleasePendingBodyV1 terminally disposes accepted custody, even under a source latch.
func (o *HeaderCandidateOwner148V1) ReleasePendingBodyV1(key PendingBodyKey148V1, cause PendingBodyRelease148V1) PendingBodyDecision148V1 {
	if cause < PendingBodyReleaseCapacity148V1 || cause > PendingBodyReleaseShutdown148V1 {
		return pendingBodyDecision(PendingBodyInvalid148V1)
	}
	o.mu.Lock()
	if o.pendingBody == nil || o.pendingBody.records[key] == nil {
		o.mu.Unlock()
		return pendingBodyDecision(PendingBodyAbsent148V1)
	}
	r := o.detachPendingBody(key)
	o.mu.Unlock()
	drainPendingBodies(r)
	return PendingBodyDecision148V1{}
}

// ExpirePendingBodiesV1 visits only finite owned records and drains after unlocking.
func (o *HeaderCandidateOwner148V1) ExpirePendingBodiesV1(now uint64) {
	o.mu.Lock()
	var expired *pendingBodyRecord148
	if s := o.pendingBody; s != nil {
		for key := range s.records {
			if r := o.expirePendingBody(key, now); r != nil {
				r.next, expired = expired, r
			}
		}
	}
	o.mu.Unlock()
	drainPendingBodies(expired)
}

// closePendingBodies detaches the finite owner under mu; Close drains after unlocking.
func (o *HeaderCandidateOwner148V1) closePendingBodies() *pendingBodyRecord148 {
	var detached *pendingBodyRecord148
	if s := o.pendingBody; s != nil {
		for key := range s.records {
			r := o.detachPendingBody(key)
			r.next, detached = detached, r
		}
	}
	return detached
}
