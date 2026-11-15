package node

import (
	"bytes"
	"errors"
	"math"
	"math/big"
	"slices"
	"unsafe"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

// ErrHeaderContextConfig148V1 rejects an invalid dormant context configuration.
var ErrHeaderContextConfig148V1 = errors.New("header context 148: invalid configuration")

// HeaderContextLimits148V1 captures the logical resource ceilings of RUB-1817.
type HeaderContextLimits148V1 struct {
	MaxRecords, MaxBytes, MaxReads, MaxReadBytes, MaxReadWork uint64
	MaxScratchBytes, MaxSuffix, MaxWorkBytes                  uint64
}

// HeaderContextView148V1 binds both candidate and separately protected source truth.
type HeaderContextView148V1 struct {
	Incarnation, Version                uint64
	Source, Authority, Network, Genesis [32]byte
}

// HeaderContextRecord148V1 is independent immutable evidence after handoff.
type HeaderContextRecord148V1 struct {
	Raw                                       [148]byte
	Hash, Parent                              [32]byte
	Height                                    uint64
	Work                                      *big.Int
	Provenance                                [32]byte
	View                                      HeaderContextView148V1
	RawTimestamps                             [11]uint64
	RawCount                                  uint8
	EpochStart, EpochCount, FirstRawTimestamp uint64
	LastClampedTimestamp                      *big.Int
	CurrentTarget                             [32]byte
}

// HeaderContextTip148V1 is the source's exact committed tip, not a received tip.
type HeaderContextTip148V1 struct {
	Height                uint64
	Hash                  [32]byte
	Work                  *big.Int
	Provenance, Authority [32]byte
}

// HeaderContextAnchorKind148V1 identifies the source's positive anchor premise.
type HeaderContextAnchorKind148V1 uint8

const (
	HeaderContextAdmitted148V1 HeaderContextAnchorKind148V1 = iota + 1
	HeaderContextCanonical148V1
	HeaderContextAcceptedTarget148V1
)

// HeaderContextAnchor148V1 supplies exact qualified facts, including actual work.
type HeaderContextAnchor148V1 struct {
	Kind       HeaderContextAnchorKind148V1
	Raw        [148]byte
	Hash       [32]byte
	Height     uint64
	Work       *big.Int
	Provenance [32]byte
}

// HeaderContextCold148V1 is either positive absence or one bounded ancestry plan.
type HeaderContextCold148V1 struct {
	Missing bool
	Anchor  HeaderContextAnchor148V1
	Suffix  uint64
}

// HeaderContextInput148V1 selects exactly one warm proof or cold plan.
type HeaderContextInput148V1 struct {
	View       HeaderContextView148V1
	Raw        [148]byte
	Tip        HeaderContextTip148V1
	WarmParent *HeaderContextAnchor148V1
	ColdParent *HeaderContextCold148V1
	Source     HeaderContextSource148V1
}

// HeaderContextSource148V1 is acquired/protected by its producer through terminal use.
// Methods are bounded, retain no destination and run outside candidate locks/guards.
type HeaderContextSource148V1 interface {
	CurrentV1() (bool, error)
	Header148V1(hash [32]byte, dst *[148]byte) (HeaderContextRead148V1, error)
}

// HeaderContextRead148V1 is the closed point-observation domain; absence is a plan.
type HeaderContextRead148V1 uint8

const (
	HeaderContextPresent148V1 HeaderContextRead148V1 = iota
	HeaderContextReadUnavailable148V1
	HeaderContextReadStale148V1
	HeaderContextReadInconsistent148V1
)

// HeaderContextOutcome148V1 distinguishes local refusal from incoming mismatch.
type HeaderContextOutcome148V1 uint8

const (
	HeaderContextOK148V1 HeaderContextOutcome148V1 = iota
	HeaderContextMissing148V1
	HeaderContextUnavailable148V1
	HeaderContextStale148V1
	HeaderContextInconsistent148V1
	HeaderContextCapacity148V1
	HeaderContextIncomingMismatch148V1
	HeaderContextNoneligible148V1
	HeaderContextConsumed148V1
)

// HeaderContextMismatch148V1 attributes only an incoming child's failed check.
type HeaderContextMismatch148V1 uint8

const (
	HeaderContextNone148V1 HeaderContextMismatch148V1 = iota
	HeaderContextTargetRange148V1
	HeaderContextPoW148V1
	HeaderContextLinkage148V1
	HeaderContextTarget148V1
	HeaderContextTimestampOld148V1
	HeaderContextTimestampFuture148V1
)

// HeaderContextDecision148V1 preserves the actual C1 refusal and first source error.
type HeaderContextDecision148V1 struct {
	Outcome          HeaderContextOutcome148V1
	Mismatch         HeaderContextMismatch148V1
	CandidateOutcome HeaderCandidateOutcome148V1
	Cause            error
}

type hctxState struct {
	limits           HeaderContextLimits148V1
	network, genesis [32]byte
	records          map[[32]byte]HeaderContextRecord148V1
	bytes, scratch   uint64
	active           *hctxReservation
}

type hctxReservation struct {
	owner   *HeaderCandidateOwner148V1
	record  HeaderContextRecord148V1
	source  HeaderContextSource148V1
	victims [][32]byte
	scratch uint64
	done    bool
	view    HeaderContextView148V1
}

// HeaderContextPrepared148V1 owns the exact C1 plan and its C2 reservation.
type HeaderContextPrepared148V1 struct {
	candidate   *HeaderCandidatePrepared148V1
	reservation *hctxReservation
	view        HeaderContextView148V1
	consumed    bool
}

// NewHeaderCandidateContext148V1 attaches context state to the ordinary C1 owner.
func NewHeaderCandidateContext148V1(cl HeaderCandidateLimits148V1, l HeaderContextLimits148V1, incarnation uint64, network, genesis [32]byte) (*HeaderCandidateOwner148V1, error) {
	o, err := NewHeaderCandidateOwner148V1(cl, incarnation)
	if err != nil {
		return nil, err
	}
	if !hctxLimitsValid(l) || network == ([32]byte{}) || genesis == ([32]byte{}) {
		return nil, ErrHeaderContextConfig148V1
	}
	o.context = &hctxState{
		limits: l, network: network, genesis: genesis, bytes: 512,
		records: map[[32]byte]HeaderContextRecord148V1{},
	}
	return o, nil
}

// hctxLimitsValid admits only captured finite ceilings, including fixed state.
func hctxLimitsValid(l HeaderContextLimits148V1) bool {
	for _, n := range [...]uint64{l.MaxRecords, l.MaxBytes, l.MaxReads, l.MaxReadBytes, l.MaxReadWork, l.MaxScratchBytes, l.MaxSuffix, l.MaxWorkBytes} {
		if n == 0 || n == math.MaxUint64 {
			return false
		}
	}
	return l.MaxBytes >= 512
}

// hctxDecision constructs a local result without inventing a C1 outcome.
func hctxDecision(out HeaderContextOutcome148V1) HeaderContextDecision148V1 {
	return HeaderContextDecision148V1{Outcome: out}
}

// hctxCandidate preserves the exact reason returned by a real C1 operation.
func hctxCandidate(out HeaderCandidateOutcome148V1) HeaderContextDecision148V1 {
	d := HeaderContextDecision148V1{CandidateOutcome: out}
	switch out {
	case HeaderCandidateOK148V1:
		d.Outcome = HeaderContextOK148V1
	case HeaderCandidateStale148V1:
		d.Outcome = HeaderContextStale148V1
	case HeaderCandidateInvalid148V1, HeaderCandidateConflict148V1, HeaderCandidateMissingParent148V1, HeaderCandidateNoCoverage148V1, HeaderCandidateMissing148V1:
		d.Outcome = HeaderContextInconsistent148V1
	case HeaderCandidateCapacity148V1, HeaderCandidateProtected148V1, HeaderCandidateVersionExhausted148V1, HeaderCandidateBusy148V1:
		d.Outcome = HeaderContextCapacity148V1
	case HeaderCandidateConsumed148V1:
		d.Outcome = HeaderContextConsumed148V1
	default:
		d.Outcome = HeaderContextUnavailable148V1
	}
	return d
}

// contextGate checks C1 authority before interpreting caller metadata; mu is held.
func (o *HeaderCandidateOwner148V1) contextGate() HeaderContextDecision148V1 {
	if out := o.gate(true); out != HeaderCandidateOK148V1 {
		return hctxCandidate(out)
	}
	if o.context == nil {
		return hctxDecision(HeaderContextUnavailable148V1)
	}
	return HeaderContextDecision148V1{}
}

// contextView separates malformed identity from a stale candidate binding; mu is held.
func (o *HeaderCandidateOwner148V1) contextView(v HeaderContextView148V1) HeaderContextDecision148V1 {
	if !hctxViewShape(v) {
		return hctxDecision(HeaderContextInconsistent148V1)
	}
	if v.Network != o.context.network || v.Genesis != o.context.genesis {
		return hctxDecision(HeaderContextInconsistent148V1)
	}
	if v.Incarnation != o.incarnation || v.Version != o.version.Load() || v.Source != o.source {
		return hctxDecision(HeaderContextStale148V1)
	}
	return HeaderContextDecision148V1{}
}

// hctxViewShape rejects absent identities independently of their current binding.
func hctxViewShape(v HeaderContextView148V1) bool {
	return v.Incarnation != 0 && v.Version != 0 && v.Source != ([32]byte{}) && v.Authority != ([32]byte{})
}

// startContext reserves the singleton after shape then freshness; no source call runs here.
func (o *HeaderCandidateOwner148V1) startContext(v HeaderContextView148V1, shape HeaderContextDecision148V1) (*hctxReservation, HeaderContextDecision148V1) {
	o.mu.Lock()
	defer o.mu.Unlock()
	for _, d := range [...]HeaderContextDecision148V1{o.contextGate(), shape} {
		if d.Outcome != HeaderContextOK148V1 {
			return nil, d
		}
	}
	if d := o.contextView(v); d.Outcome != HeaderContextOK148V1 {
		return nil, d
	}
	if o.context.active != nil {
		return nil, hctxDecision(HeaderContextCapacity148V1)
	}
	r := &hctxReservation{owner: o, view: v}
	o.context.active = r
	return r, HeaderContextDecision148V1{}
}

// currentContext rechecks both identities around the callback and retains the first cause.
func (o *HeaderCandidateOwner148V1) currentContext(v HeaderContextView148V1, source HeaderContextSource148V1, cause error) HeaderContextDecision148V1 {
	d := o.checkContext(v)
	if d.Outcome != HeaderContextOK148V1 {
		d.Cause = cause
		return d
	}
	if source == nil {
		d.Outcome, d.Cause = HeaderContextUnavailable148V1, cause
		return d
	}
	current, err := source.CurrentV1()
	if cause == nil {
		cause = err
	}
	d = o.checkContext(v)
	d.Cause = cause
	if d.Outcome != HeaderContextOK148V1 {
		return d
	}
	if !current {
		d.Outcome = HeaderContextStale148V1
		return d
	}
	if err != nil {
		d.Outcome = HeaderContextUnavailable148V1
	}
	return d
}

// checkContext is the short locked identity observation, without allocation or guards.
func (o *HeaderCandidateOwner148V1) checkContext(v HeaderContextView148V1) HeaderContextDecision148V1 {
	o.mu.Lock()
	defer o.mu.Unlock()
	if d := o.contextGate(); d.Outcome != HeaderContextOK148V1 {
		return d
	}
	return o.contextView(v)
}

// hctxWidth inspects an already shape-checked integer without copying it.
func hctxWidth(n *big.Int) uint64 {
	bits := n.BitLen()
	if bits <= 0 {
		return 0
	}
	return (uint64(bits) + 7) / 8
}

// hctxCharge is the exact logical record payload Q, excluding its 64-byte index.
func hctxCharge(r HeaderContextRecord148V1) uint64 {
	return 541 + hctxWidth(r.Work) + hctxWidth(r.LastClampedTimestamp)
}

// hctxSum fails closed on an overflowing resource expression.
func hctxSum(ns ...uint64) uint64 {
	var n uint64
	for _, v := range ns {
		n = hcAddSat(n, v)
	}
	return n
}

// hctxMul fails closed before proportional allocation.
func hctxMul(a, b uint64) uint64 {
	if b != 0 && a > math.MaxUint64/b {
		return math.MaxUint64
	}
	return a * b
}

// reserveContext applies the agreed S and prospective cache formulas before copying.
func (r *hctxReservation) reserveContext(hash [32]byte, n, a uint64) HeaderContextDecision148V1 {
	o := r.owner
	o.mu.Lock()
	defer o.mu.Unlock()
	s := o.context
	if d := o.contextGate(); d.Outcome != HeaderContextOK148V1 {
		return d
	}
	if d := o.contextView(r.view); d.Outcome != HeaderContextOK148V1 {
		return d
	}
	if r.done {
		return hctxDecision(HeaderContextUnavailable148V1)
	}
	l := s.limits
	scratch := hctxScratch(l.MaxWorkBytes, n, a, uint64(len(s.records)))
	if !hctxPlanFits(l, o.limits.MaxTransitionHeaders, n, a, scratch, s.scratch) {
		return hctxDecision(HeaderContextCapacity148V1)
	}
	s.scratch += scratch
	r.scratch = scratch
	return r.reserveContextVictims(hash)
}

// hctxPlanFits validates finite counts and aggregate scratch before any charge/allocation.
func hctxPlanFits(l HeaderContextLimits148V1, maxAdditions, n, a, scratch, used uint64) bool {
	return n <= min(l.MaxReads, l.MaxReadWork, uint64(math.MaxInt)/148) && hctxMul(148, n) <= l.MaxReadBytes && a <= min(maxAdditions, uint64(math.MaxInt)/uint64(unsafe.Sizeof(HeaderCandidateRecord148V1{}))) && scratch <= l.MaxScratchBytes && used <= l.MaxScratchBytes-scratch
}

// hctxScratch evaluates exactly S with saturating failure, before any proportional allocation.
func hctxScratch(m, n, a, records uint64) uint64 {
	q := hctxSum(550, m)
	u := hctxSum(max(m, 41), 1)
	return hctxSum(1024, hctxMul(148, n), hctxMul(a, hctxSum(317, m)), hctxMul(3, q), hctxMul(2, m), hctxMul(16, hctxSum(u, 64)), hctxMul(64, records))
}

// reserveContextVictims fixes ascending exclusions within reserved 64*R scratch; mu is held.
func (r *hctxReservation) reserveContextVictims(hash [32]byte) HeaderContextDecision148V1 {
	s := r.owner.context
	l := s.limits
	count, total := uint64(len(s.records))+1, hctxSum(s.bytes, 550, l.MaxWorkBytes, 64)
	if _, ok := s.records[hash]; ok {
		count--
		total = s.bytes
	}
	if total == math.MaxUint64 {
		return hctxDecision(HeaderContextCapacity148V1)
	}
	keys := hctxVictimKeys(s, hash)
	for _, h := range keys {
		if hctxCacheFits(count, total, l) {
			break
		}
		count--
		total -= hctxCharge(s.records[h]) + 64
		r.victims = append(r.victims, h)
	}
	if !hctxCacheFits(count, total, l) {
		return hctxDecision(HeaderContextCapacity148V1)
	}
	return HeaderContextDecision148V1{}
}

// hctxVictimKeys filters and orders only eligible victims within the invocation's index reservation.
func hctxVictimKeys(s *hctxState, replacement [32]byte) [][32]byte {
	keys := make([][32]byte, 0, len(s.records))
	for h := range s.records {
		if h != replacement {
			keys = append(keys, h)
		}
	}
	slices.SortFunc(keys, func(a, b [32]byte) int { return bytes.Compare(a[:], b[:]) })
	return keys
}

// hctxCacheFits applies both prospective retained ceilings to one planned state.
func hctxCacheFits(count, total uint64, l HeaderContextLimits148V1) bool {
	return count <= l.MaxRecords && total <= l.MaxBytes
}

// finishContext releases only the matching invocation; mu is held, including C1 hooks.
func (o *HeaderCandidateOwner148V1) finishContext(r *hctxReservation) {
	if r == nil || r.done {
		return
	}
	r.done = true
	s := o.context
	s.scratch -= r.scratch
	if s.active == r {
		s.active = nil
	}
	r.victims = nil
	r.record = HeaderContextRecord148V1{}
	r.source = nil
}

// releaseContext is the unlocked invocation cleanup used by deferred refusal paths.
func (r *hctxReservation) releaseContext() {
	r.owner.mu.Lock()
	r.owner.finishContext(r)
	r.owner.mu.Unlock()
}

// closeContext discards derived trust and charges; late plan cleanup is harmless.
func (o *HeaderCandidateOwner148V1) closeContext() {
	if s := o.context; s != nil {
		if s.active != nil {
			o.finishContext(s.active)
		}
		clear(s.records)
		s.bytes, s.scratch = 512, 0
	}
}

// dropContext removes derived evidence and never touches C1 membership.
func (o *HeaderCandidateOwner148V1) dropContext(hash [32]byte) {
	s := o.context
	if old, ok := s.records[hash]; ok {
		s.bytes -= hctxCharge(old) + 64
		delete(s.records, hash)
	}
}

// applyContext promotes prevalidated owned data before C1 publishes its version; mu is held.
func (o *HeaderCandidateOwner148V1) applyContext(p *hcPlan) {
	s := o.context
	if s == nil {
		return
	}
	o.reconcileContext(p)
	r := p.context
	if r == nil || r.done {
		return
	}
	for _, h := range r.victims {
		o.dropContext(h)
	}
	if old, ok := s.records[r.record.Hash]; ok {
		s.bytes -= hctxCharge(old) + 64
	}
	v := o.version.Load()
	if p.changed {
		v++
	}
	r.record.View.Version = v
	s.records[r.record.Hash] = r.record
	s.bytes += hctxCharge(r.record) + 64
	o.finishContext(r)
}

// reconcileContext consumes only actual C1 provenance/retirement effects; mu is held.
func (o *HeaderCandidateOwner148V1) reconcileContext(p *hcPlan) {
	s := o.context
	for _, a := range p.prov {
		if r, ok := s.records[a.Hash]; ok {
			r.Provenance = a.Provenance
			s.records[a.Hash] = r
		}
	}
	for _, h := range p.retired {
		o.dropContext(h)
	}
}

// hctxClone creates the two independent mutable integers within reserved scratch.
func hctxClone(r HeaderContextRecord148V1) HeaderContextRecord148V1 {
	r.Work = new(big.Int).Set(r.Work)
	r.LastClampedTimestamp = new(big.Int).Set(r.LastClampedTimestamp)
	return r
}

// LookupContextV1 returns only exact current-view evidence under its L output reservation.
// The caller retains source protection and rechecks it through use of the copy.
func (o *HeaderCandidateOwner148V1) LookupContextV1(v HeaderContextView148V1, hash [32]byte) (HeaderContextRecord148V1, HeaderContextDecision148V1) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if d := o.contextGate(); d.Outcome != HeaderContextOK148V1 {
		return HeaderContextRecord148V1{}, d
	}
	if d := o.contextView(v); d.Outcome != HeaderContextOK148V1 {
		return HeaderContextRecord148V1{}, d
	}
	s := o.context
	r, ok := s.records[hash]
	if !ok {
		return HeaderContextRecord148V1{}, hctxDecision(HeaderContextUnavailable148V1)
	}
	if r.View != v {
		return HeaderContextRecord148V1{}, hctxDecision(HeaderContextStale148V1)
	}
	l := 256 + hctxCharge(r)
	if l > s.limits.MaxScratchBytes || s.scratch > s.limits.MaxScratchBytes-l {
		return HeaderContextRecord148V1{}, hctxDecision(HeaderContextCapacity148V1)
	}
	s.scratch += l
	out := hctxClone(r)
	s.scratch -= l
	return out, HeaderContextDecision148V1{}
}

// hctxFixed consumes the serialized target with unchanged fixed-width primitives.
func hctxFixed(raw [148]byte) (consensus.Initial148Header, [32]byte, HeaderContextMismatch148V1) {
	h, _ := consensus.ParseInitial148HeaderBytes(raw[:])
	hash, _ := consensus.Initial148BlockHash(raw[:])
	if h.Target == ([32]byte{}) || bytes.Compare(h.Target[:], consensus.POW_LIMIT[:]) > 0 {
		return h, hash, HeaderContextTargetRange148V1
	}
	if consensus.Initial148PowCheck(raw[:], h.Target) != nil {
		return h, hash, HeaderContextPoW148V1
	}
	return h, hash, HeaderContextNone148V1
}

// hctxAnchorShape inspects proof shape and bounded Work without a proportional copy.
func hctxAnchorShape(a HeaderContextAnchor148V1, m uint64) HeaderContextDecision148V1 {
	if a.Kind < HeaderContextAdmitted148V1 || a.Kind > HeaderContextAcceptedTarget148V1 || a.Work == nil || a.Provenance == ([32]byte{}) {
		return hctxDecision(HeaderContextInconsistent148V1)
	}
	if a.Work.Sign() <= 0 {
		return hctxDecision(HeaderContextInconsistent148V1)
	}
	if hctxWidth(a.Work) > m {
		return hctxDecision(HeaderContextCapacity148V1)
	}
	if !hctxAnchorFixed(a) {
		return hctxDecision(HeaderContextInconsistent148V1)
	}
	return HeaderContextDecision148V1{}
}

// hctxAnchorFixed keeps a local proof's fixed-byte binding separate from incoming mismatch.
func hctxAnchorFixed(a HeaderContextAnchor148V1) bool {
	_, hash, bad := hctxFixed(a.Raw)
	return hash == a.Hash && bad == HeaderContextNone148V1
}

// anchorContext verifies the source's membership/External premise under the C1 guard.
func (o *HeaderCandidateOwner148V1) anchorContext(a HeaderContextAnchor148V1) HeaderContextDecision148V1 {
	o.mu.Lock()
	defer o.mu.Unlock()
	e := o.recs[a.Hash]
	if e == nil {
		if a.Kind == HeaderContextAdmitted148V1 {
			return hctxDecision(HeaderContextInconsistent148V1)
		}
		return HeaderContextDecision148V1{}
	}
	r := e.rec
	if a.Kind != HeaderContextAdmitted148V1 || a.Raw != r.Raw || a.Height != r.Height || a.Provenance != r.Provenance || a.Work.Cmp(r.Work) != 0 {
		return hctxDecision(HeaderContextInconsistent148V1)
	}
	return HeaderContextDecision148V1{}
}

// hctxGenesis derives the first record, including a valid exactly zero clamp.
func hctxGenesis(v HeaderContextView148V1, raw [148]byte, prov [32]byte) HeaderContextRecord148V1 {
	h, hash, _ := hctxFixed(raw)
	w, _ := consensus.WorkFromTarget(h.Target)
	return HeaderContextRecord148V1{
		Raw: raw, Hash: hash, Parent: h.PrevBlockHash, Work: w, Provenance: prov, View: v,
		RawTimestamps: [11]uint64{h.Timestamp}, RawCount: 1, EpochCount: 1,
		FirstRawTimestamp: h.Timestamp, LastClampedTimestamp: new(big.Int).SetUint64(h.Timestamp), CurrentTarget: h.Target,
	}
}

// SeedGenesisContextV1 caches published genesis evidence under retained source protection without admitting a header.
func (o *HeaderCandidateOwner148V1) SeedGenesisContextV1(v HeaderContextView148V1, raw [148]byte, prov [32]byte, source HeaderContextSource148V1) HeaderContextDecision148V1 {
	hash, shape := hctxSeedShape(v, raw, prov)
	r, d := o.startContext(v, shape)
	if r == nil {
		return d
	}
	defer r.releaseContext()
	if d = o.currentContext(v, source, nil); d.Outcome != HeaderContextOK148V1 {
		return d
	}
	if d = r.reserveContext(hash, 0, 0); d.Outcome != HeaderContextOK148V1 {
		return d
	}
	rec := hctxGenesis(v, raw, prov)
	if hctxWidth(rec.Work) > o.context.limits.MaxWorkBytes {
		return hctxDecision(HeaderContextCapacity148V1)
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if d = o.contextGate(); d.Outcome != HeaderContextOK148V1 {
		return d
	}
	if d = o.contextView(v); d.Outcome != HeaderContextOK148V1 {
		return d
	}
	if d = o.matchSeedContext(v, rec); d.Outcome != HeaderContextOK148V1 {
		return d
	}
	r.record = rec
	o.applyContext(&hcPlan{context: r})
	return HeaderContextDecision148V1{}
}

// hctxSeedShape treats published genesis failures as local evidence inconsistency.
func hctxSeedShape(v HeaderContextView148V1, raw [148]byte, prov [32]byte) ([32]byte, HeaderContextDecision148V1) {
	_, hash, bad := hctxFixed(raw)
	if hash != v.Genesis || bad != HeaderContextNone148V1 || prov == ([32]byte{}) {
		return hash, hctxDecision(HeaderContextInconsistent148V1)
	}
	return hash, HeaderContextDecision148V1{}
}

// matchSeedContext makes repeat seeding an exact no-op, never an implicit rebind; mu is held.
func (o *HeaderCandidateOwner148V1) matchSeedContext(v HeaderContextView148V1, rec HeaderContextRecord148V1) HeaderContextDecision148V1 {
	old, ok := o.context.records[rec.Hash]
	if !ok {
		return HeaderContextDecision148V1{}
	}
	if old.View != v {
		return hctxDecision(HeaderContextStale148V1)
	}
	if old.Raw != rec.Raw || old.Provenance != rec.Provenance || old.Work.Cmp(rec.Work) != 0 {
		return hctxDecision(HeaderContextInconsistent148V1)
	}
	return HeaderContextDecision148V1{}
}

// RebindContextV1 preserves all immutable fields and refreshes only View/Provenance after fresh source qualification.
// The old stored producer tag may differ from the proof's new nonzero tag.
func (o *HeaderCandidateOwner148V1) RebindContextV1(v HeaderContextView148V1, proof HeaderContextAnchor148V1, source HeaderContextSource148V1) (HeaderContextRecord148V1, HeaderContextDecision148V1) {
	o.mu.Lock()
	m := uint64(0)
	if o.context != nil {
		m = o.context.limits.MaxWorkBytes
	}
	o.mu.Unlock()
	r, d := o.startContext(v, hctxAnchorShape(proof, m))
	if r == nil {
		return HeaderContextRecord148V1{}, d
	}
	defer r.releaseContext()
	o.mu.Lock()
	_, present := o.context.records[proof.Hash]
	o.mu.Unlock()
	if !present {
		return HeaderContextRecord148V1{}, hctxDecision(HeaderContextUnavailable148V1)
	}
	if d = o.currentContext(v, source, nil); d.Outcome != HeaderContextOK148V1 {
		return HeaderContextRecord148V1{}, d
	}
	if d = r.reserveContext(proof.Hash, 0, 0); d.Outcome != HeaderContextOK148V1 {
		return HeaderContextRecord148V1{}, d
	}
	_, release := o.ProtectV1(v.Version)
	defer release()
	if d = o.checkContext(v); d.Outcome != HeaderContextOK148V1 {
		return HeaderContextRecord148V1{}, d
	}
	if d = o.anchorContext(proof); d.Outcome != HeaderContextOK148V1 {
		return HeaderContextRecord148V1{}, d
	}
	return o.rebindRetainedContext(v, proof, r)
}

// rebindRetainedContext changes only the explicitly refreshable fields under the same mutex.
func (o *HeaderCandidateOwner148V1) rebindRetainedContext(v HeaderContextView148V1, proof HeaderContextAnchor148V1, r *hctxReservation) (HeaderContextRecord148V1, HeaderContextDecision148V1) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if d := o.contextGate(); d.Outcome != HeaderContextOK148V1 {
		return HeaderContextRecord148V1{}, d
	}
	old, ok := o.context.records[proof.Hash]
	if !ok {
		return HeaderContextRecord148V1{}, hctxDecision(HeaderContextUnavailable148V1)
	}
	if !hctxSameOrigin(old.View, v) || !hctxRecordFacts(old, proof.Raw, proof.Height, proof.Work) {
		return HeaderContextRecord148V1{}, hctxDecision(HeaderContextInconsistent148V1)
	}
	r.record = hctxClone(old)
	r.record.View, r.record.Provenance = v, proof.Provenance
	output := hctxClone(r.record)
	o.applyContext(&hcPlan{context: r})
	return output, HeaderContextDecision148V1{}
}

// hctxSameOrigin forbids carrying derived trust into another configured incarnation.
func hctxSameOrigin(a, b HeaderContextView148V1) bool {
	return a.Incarnation == b.Incarnation && a.Network == b.Network && a.Genesis == b.Genesis
}

// inputContextShape closes request payloads before stale-view classification.
func (o *HeaderCandidateOwner148V1) inputContextShape(in HeaderContextInput148V1) HeaderContextDecision148V1 {
	o.mu.Lock()
	defer o.mu.Unlock()
	if d := o.contextGate(); d.Outcome != HeaderContextOK148V1 {
		return d
	}
	l := o.context.limits
	if d := hctxTipShape(in.Tip, in.View.Authority, l.MaxWorkBytes); d.Outcome != HeaderContextOK148V1 {
		return d
	}
	if in.WarmParent != nil && in.ColdParent != nil {
		return hctxDecision(HeaderContextInconsistent148V1)
	}
	if in.WarmParent != nil {
		if in.WarmParent.Height == math.MaxUint64 {
			return hctxDecision(HeaderContextCapacity148V1)
		}
		return hctxParentProofShape(in.Tip, *in.WarmParent, l.MaxWorkBytes)
	}
	if in.ColdParent == nil {
		return hctxDecision(HeaderContextUnavailable148V1)
	}
	return hctxColdShape(in.Tip, *in.ColdParent, l)
}

// hctxTipShape validates only the source-supplied comparand, without copying it.
func hctxTipShape(t HeaderContextTip148V1, authority [32]byte, m uint64) HeaderContextDecision148V1 {
	if t.Work == nil || t.Provenance == ([32]byte{}) || t.Authority != authority {
		return hctxDecision(HeaderContextInconsistent148V1)
	}
	if t.Work.Sign() <= 0 {
		return hctxDecision(HeaderContextInconsistent148V1)
	}
	if hctxWidth(t.Work) > m {
		return hctxDecision(HeaderContextCapacity148V1)
	}
	return HeaderContextDecision148V1{}
}

// hctxColdShape closes positive/absence payloads and the successor planning domain.
func hctxColdShape(tip HeaderContextTip148V1, c HeaderContextCold148V1, l HeaderContextLimits148V1) HeaderContextDecision148V1 {
	if c.Missing {
		if c.Suffix != 0 || c.Anchor != (HeaderContextAnchor148V1{}) {
			return hctxDecision(HeaderContextInconsistent148V1)
		}
		return HeaderContextDecision148V1{}
	}
	if d := hctxParentProofShape(tip, c.Anchor, l.MaxWorkBytes); d.Outcome != HeaderContextOK148V1 {
		return d
	}
	if c.Suffix > l.MaxSuffix || c.Anchor.Height >= math.MaxUint64-c.Suffix {
		return hctxDecision(HeaderContextCapacity148V1)
	}
	return HeaderContextDecision148V1{}
}

// hctxParentProofShape closes same-hash contradictions before interpreting a stale view.
func hctxParentProofShape(tip HeaderContextTip148V1, a HeaderContextAnchor148V1, m uint64) HeaderContextDecision148V1 {
	if d := hctxAnchorShape(a, m); d.Outcome != HeaderContextOK148V1 {
		return d
	}
	if !hctxTipAgrees(tip, a.Hash, a.Height, a.Work) {
		return hctxDecision(HeaderContextInconsistent148V1)
	}
	return HeaderContextDecision148V1{}
}

// hctxTipAgrees forbids assigning two heights or cumulative work values to one hash.
func hctxTipAgrees(tip HeaderContextTip148V1, hash [32]byte, height uint64, work *big.Int) bool {
	return tip.Hash != hash || (tip.Height == height && tip.Work.Cmp(work) == 0)
}

// hctxMismatch returns the exact child classification with no incidental cause.
func hctxMismatch(bad HeaderContextMismatch148V1) HeaderContextDecision148V1 {
	if bad == HeaderContextNone148V1 {
		return HeaderContextDecision148V1{}
	}
	return HeaderContextDecision148V1{Outcome: HeaderContextIncomingMismatch148V1, Mismatch: bad}
}

// hctxClamp keeps the epoch chain exact even above MaxUint64.
func hctxClamp(prev *big.Int, raw uint64) *big.Int {
	lo := new(big.Int).Add(prev, big.NewInt(1))
	hi := new(big.Int).Add(prev, big.NewInt(1200))
	v := new(big.Int).SetUint64(raw)
	if v.Cmp(lo) < 0 {
		return lo
	}
	if v.Cmp(hi) > 0 {
		return hi
	}
	return v
}

// hctxExpectedTarget projects only a checked completed epoch into unchanged RetargetV1.
func hctxExpectedTarget(p HeaderContextRecord148V1) ([32]byte, bool) {
	if p.EpochCount != 10080 {
		return p.CurrentTarget, true
	}
	delta := new(big.Int).Sub(p.LastClampedTimestamp, new(big.Int).SetUint64(p.FirstRawTimestamp))
	if !delta.IsUint64() || delta.Uint64() < 10079 || delta.Uint64() > 12094800 {
		return [32]byte{}, false
	}
	t, err := consensus.RetargetV1(p.CurrentTarget, 0, delta.Uint64())
	return t, err == nil
}

// hctxTimestamp evaluates raw lower median before the exact wide ceiling.
func hctxTimestamp(p HeaderContextRecord148V1, timestamp uint64) HeaderContextMismatch148V1 {
	values := p.RawTimestamps
	slices.Sort(values[:p.RawCount])
	median := values[(p.RawCount-1)/2]
	if timestamp <= median {
		return HeaderContextTimestampOld148V1
	}
	ceiling := new(big.Int).Add(new(big.Int).SetUint64(median), big.NewInt(7200))
	if new(big.Int).SetUint64(timestamp).Cmp(ceiling) > 0 {
		return HeaderContextTimestampFuture148V1
	}
	return HeaderContextNone148V1
}

// hctxExtend qualifies one child and derives its complete independent snapshot.
func hctxExtend(p HeaderContextRecord148V1, raw [148]byte, prov [32]byte, m uint64) (HeaderContextRecord148V1, HeaderContextDecision148V1) {
	h, hash, bad := hctxFixed(raw)
	if bad != HeaderContextNone148V1 {
		return HeaderContextRecord148V1{}, hctxMismatch(bad)
	}
	if p.Height == math.MaxUint64 {
		return HeaderContextRecord148V1{}, hctxDecision(HeaderContextCapacity148V1)
	}
	if d := hctxRelative(p, h); d.Outcome != HeaderContextOK148V1 {
		return HeaderContextRecord148V1{}, d
	}
	w, _ := consensus.WorkFromTarget(h.Target)
	w.Add(w, p.Work)
	if hctxWidth(w) > m {
		return HeaderContextRecord148V1{}, hctxDecision(HeaderContextCapacity148V1)
	}
	r := HeaderContextRecord148V1{
		Raw: raw, Hash: hash, Parent: p.Hash, Height: p.Height + 1, Work: w, Provenance: prov, View: p.View,
		RawCount: min(11, p.RawCount+1), EpochStart: p.EpochStart, EpochCount: p.EpochCount + 1,
		FirstRawTimestamp: p.FirstRawTimestamp, LastClampedTimestamp: hctxClamp(p.LastClampedTimestamp, h.Timestamp), CurrentTarget: h.Target,
	}
	copy(r.RawTimestamps[1:], p.RawTimestamps[:10])
	r.RawTimestamps[0] = h.Timestamp
	if r.Height%10080 == 0 {
		r.EpochStart, r.EpochCount, r.FirstRawTimestamp = r.Height, 1, h.Timestamp
		r.LastClampedTimestamp = new(big.Int).SetUint64(h.Timestamp)
	}
	return r, HeaderContextDecision148V1{}
}

// hctxRelative preserves linkage, target, raw floor, then wide-ceiling refusal order.
func hctxRelative(p HeaderContextRecord148V1, h consensus.Initial148Header) HeaderContextDecision148V1 {
	if h.PrevBlockHash != p.Hash {
		return hctxMismatch(HeaderContextLinkage148V1)
	}
	target, ok := hctxExpectedTarget(p)
	if !ok {
		return hctxDecision(HeaderContextInconsistent148V1)
	}
	if h.Target != target {
		return hctxMismatch(HeaderContextTarget148V1)
	}
	return hctxMismatch(hctxTimestamp(p, h.Timestamp))
}

// hctxParentValid protects arithmetic against malformed retained/imported summaries.
func hctxParentValid(p HeaderContextRecord148V1) bool {
	if p.Work == nil || p.LastClampedTimestamp == nil {
		return false
	}
	if p.Work.Sign() <= 0 || p.LastClampedTimestamp.Sign() < 0 {
		return false
	}
	return hctxRecordRaw(p) && hctxHistory(p) && hctxSummary(p)
}

// hctxRecordRaw binds retained scalar facts to their immutable header bytes.
func hctxRecordRaw(p HeaderContextRecord148V1) bool {
	h, hash, bad := hctxFixed(p.Raw)
	return bad == HeaderContextNone148V1 && hash == p.Hash && h.PrevBlockHash == p.Parent && h.Target == p.CurrentTarget && h.Timestamp == p.RawTimestamps[0]
}

// hctxHistory validates the exact raw-history length and zero unused suffix.
func hctxHistory(p HeaderContextRecord148V1) bool {
	if uint64(p.RawCount) != min(uint64(11), hcAddSat(p.Height, 1)) {
		return false
	}
	for _, v := range p.RawTimestamps[p.RawCount:] {
		if v != 0 {
			return false
		}
	}
	return true
}

// hctxSummary validates partial/completed epoch growth without narrowing its absolute clamp.
func hctxSummary(p HeaderContextRecord148V1) bool {
	if p.EpochStart != p.Height/10080*10080 || p.EpochCount != p.Height-p.EpochStart+1 {
		return false
	}
	delta := new(big.Int).Sub(p.LastClampedTimestamp, new(big.Int).SetUint64(p.FirstRawTimestamp))
	return delta.IsUint64() && delta.Uint64() >= p.EpochCount-1 && delta.Uint64() <= (p.EpochCount-1)*1200
}

// checkWarmContext resolves cache absence and freshness before admission without copying Work.
func (o *HeaderCandidateOwner148V1) checkWarmContext(v HeaderContextView148V1, hash [32]byte) HeaderContextDecision148V1 {
	_, release := o.ProtectV1(v.Version)
	defer release()
	o.mu.Lock()
	defer o.mu.Unlock()
	if d := o.contextGate(); d.Outcome != HeaderContextOK148V1 {
		return d
	}
	if d := o.contextView(v); d.Outcome != HeaderContextOK148V1 {
		return d
	}
	p, ok := o.context.records[hash]
	if !ok {
		return hctxDecision(HeaderContextUnavailable148V1)
	}
	if p.View != v {
		return hctxDecision(HeaderContextStale148V1)
	}
	return HeaderContextDecision148V1{}
}

// warmContext consumes only exact cached evidence plus the positive current proof.
func (o *HeaderCandidateOwner148V1) warmContext(v HeaderContextView148V1, a HeaderContextAnchor148V1) (HeaderContextRecord148V1, HeaderContextDecision148V1) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if d := o.contextGate(); d.Outcome != HeaderContextOK148V1 {
		return HeaderContextRecord148V1{}, d
	}
	p, ok := o.context.records[a.Hash]
	if !ok {
		return HeaderContextRecord148V1{}, hctxDecision(HeaderContextUnavailable148V1)
	}
	if p.View != v {
		return HeaderContextRecord148V1{}, hctxDecision(HeaderContextStale148V1)
	}
	if !hctxParentValid(p) || p.Provenance != a.Provenance || !hctxRecordFacts(p, a.Raw, a.Height, a.Work) {
		return HeaderContextRecord148V1{}, hctxDecision(HeaderContextInconsistent148V1)
	}
	return hctxClone(p), HeaderContextDecision148V1{}
}

// hctxRecordFacts compares the immutable ancestry/work facts shared by proof and duplicate joins.
func hctxRecordFacts(r HeaderContextRecord148V1, raw [148]byte, height uint64, work *big.Int) bool {
	return r.Raw == raw && r.Height == height && r.Work.Cmp(work) == 0
}

// hctxPublication projects a qualified context without inferring External from cache.
func hctxPublication(r HeaderContextRecord148V1, external bool) HeaderCandidateRecord148V1 {
	return HeaderCandidateRecord148V1{Raw: r.Raw, Hash: r.Hash, Parent: r.Parent, Height: r.Height, Work: r.Work, Provenance: r.Provenance, External: external}
}

// readContext performs exactly one bounded observation and postread freshness check.
func (o *HeaderCandidateOwner148V1) readContext(in HeaderContextInput148V1, hash [32]byte, dst *[148]byte) HeaderContextDecision148V1 {
	if d := o.currentContext(in.View, in.Source, nil); d.Outcome != HeaderContextOK148V1 {
		return d
	}
	status, err := in.Source.Header148V1(hash, dst)
	d := o.currentContext(in.View, in.Source, err)
	if d.Outcome != HeaderContextOK148V1 {
		return d
	}
	if err != nil {
		d.Outcome = HeaderContextUnavailable148V1
		return d
	}
	switch status {
	case HeaderContextPresent148V1:
		return d
	case HeaderContextReadUnavailable148V1:
		d.Outcome = HeaderContextUnavailable148V1
	case HeaderContextReadStale148V1:
		d.Outcome = HeaderContextStale148V1
	default:
		d.Outcome = HeaderContextInconsistent148V1
	}
	return d
}

// coldContext materializes the one backward hash chain into its pre-reserved raw array.
func (o *HeaderCandidateOwner148V1) coldContext(in HeaderContextInput148V1, n uint64) ([][148]byte, HeaderContextDecision148V1) {
	raws := make([][148]byte, n)
	h, _ := consensus.ParseInitial148HeaderBytes(in.Raw[:])
	want := h.PrevBlockHash
	for i := len(raws) - 1; i >= 0; i-- {
		if d := o.readContext(in, want, &raws[i]); d.Outcome != HeaderContextOK148V1 {
			return nil, d
		}
		parsed, ok := hctxColdRaw(in, n, uint64(i), raws[i], want)
		if !ok {
			return nil, hctxDecision(HeaderContextInconsistent148V1)
		}
		want = parsed.PrevBlockHash
	}
	return raws, HeaderContextDecision148V1{}
}

// hctxColdRaw identifies every fixed-byte contradiction at its first backward observation.
func hctxColdRaw(in HeaderContextInput148V1, n, i uint64, raw [148]byte, want [32]byte) (consensus.Initial148Header, bool) {
	h, hash, bad := hctxFixed(raw)
	if hash != want || bad != HeaderContextNone148V1 {
		return h, false
	}
	if i == n-in.ColdParent.Suffix-1 && raw != in.ColdParent.Anchor.Raw {
		return h, false
	}
	if in.ColdParent.Anchor.Height < 10080 && (hash == in.View.Genesis) != (i == 0) {
		return h, false
	}
	return h, true
}

// coldAnchor reconstructs the qualified prefix's raw history and exact epoch clamp.
func hctxColdAnchor(in HeaderContextInput148V1, raws [][148]byte) (HeaderContextRecord148V1, HeaderContextDecision148V1) {
	a := in.ColdParent.Anchor
	e := a.Height / 10080 * 10080
	lead := min(uint64(10), e)
	idx := lead + a.Height - e
	// coldContext already checked the exact anchor and configured genesis at their read positions.
	r := hctxGenesis(in.View, raws[lead], a.Provenance)
	if a.Height == 0 && r.Work.Cmp(a.Work) != 0 {
		return HeaderContextRecord148V1{}, hctxDecision(HeaderContextInconsistent148V1)
	}
	for i := lead + 1; i <= idx; i++ {
		h, _, _ := hctxFixed(raws[i])
		if h.Target != r.CurrentTarget {
			return HeaderContextRecord148V1{}, hctxDecision(HeaderContextInconsistent148V1)
		}
		r.LastClampedTimestamp = hctxClamp(r.LastClampedTimestamp, h.Timestamp)
	}
	h, _, _ := hctxFixed(a.Raw)
	r.Raw, r.Hash, r.Parent, r.Height = a.Raw, a.Hash, h.PrevBlockHash, a.Height
	r.Work = new(big.Int).Set(a.Work)
	r.EpochStart, r.EpochCount = e, a.Height-e+1
	r.RawCount = uint8(min(uint64(11), hcAddSat(a.Height, 1)))
	clear(r.RawTimestamps[:])
	for j := uint8(0); j < r.RawCount; j++ {
		item, _ := consensus.ParseInitial148HeaderBytes(raws[idx-uint64(j)][:])
		r.RawTimestamps[j] = item.Timestamp
	}
	return r, HeaderContextDecision148V1{}
}

// suffixContext independently qualifies local suffix facts and builds parent-first C1 input.
func (o *HeaderCandidateOwner148V1) suffixContext(in HeaderContextInput148V1, raws [][148]byte, p HeaderContextRecord148V1) (HeaderContextRecord148V1, []HeaderCandidateRecord148V1, HeaderContextDecision148V1) {
	adds := make([]HeaderCandidateRecord148V1, 0, in.ColdParent.Suffix+1)
	start := uint64(len(raws)) - in.ColdParent.Suffix
	external := in.ColdParent.Anchor.Kind != HeaderContextAdmitted148V1
	for i := start; i < uint64(len(raws)); i++ {
		next, d := hctxExtend(p, raws[i], in.ColdParent.Anchor.Provenance, o.context.limits.MaxWorkBytes)
		if d.Outcome != HeaderContextOK148V1 {
			if d.Outcome == HeaderContextIncomingMismatch148V1 {
				d = hctxDecision(HeaderContextInconsistent148V1)
			}
			return HeaderContextRecord148V1{}, nil, d
		}
		o.mu.Lock()
		old := o.recs[next.Hash]
		o.mu.Unlock()
		if old != nil {
			if !hctxAdmittedFacts(old.rec, next) {
				return HeaderContextRecord148V1{}, nil, hctxDecision(HeaderContextInconsistent148V1)
			}
		} else {
			adds = append(adds, hctxPublication(next, external))
		}
		external = false
		p = next
	}
	return p, adds, HeaderContextDecision148V1{}
}

// hctxAdmittedFacts forbids omitting a suffix addition on conflicting current C1 evidence.
func hctxAdmittedFacts(a HeaderCandidateRecord148V1, b HeaderContextRecord148V1) bool {
	return a.Raw == b.Raw && a.Height == b.Height && a.Work.Cmp(b.Work) == 0
}

// PrepareContextV1 qualifies immutable evidence under retained source protection and attaches it to the real C1 plan.
func (o *HeaderCandidateOwner148V1) PrepareContextV1(in HeaderContextInput148V1) (*HeaderContextPrepared148V1, HeaderContextDecision148V1) {
	r, d := o.startContext(in.View, o.inputContextShape(in))
	if r == nil {
		return nil, d
	}
	transferred := false
	defer func() {
		if !transferred {
			r.releaseContext()
		}
	}()
	_, hash, bad := hctxFixed(in.Raw)
	if bad != HeaderContextNone148V1 {
		return nil, hctxMismatch(bad)
	}
	if d = o.currentContext(in.View, in.Source, nil); d.Outcome != HeaderContextOK148V1 {
		return nil, d
	}
	if in.ColdParent != nil && in.ColdParent.Missing {
		return nil, hctxDecision(HeaderContextMissing148V1)
	}
	in, proof, raws, d := r.prepareContextEvidence(in, hash)
	if d.Outcome != HeaderContextOK148V1 {
		return nil, d
	}
	handle, d := o.prepareContextPlan(in, proof, raws, r)
	transferred = handle != nil
	return handle, d
}

// prepareContextEvidence reserves before cloning inputs and performing the sole cold pass.
func (r *hctxReservation) prepareContextEvidence(in HeaderContextInput148V1, hash [32]byte) (HeaderContextInput148V1, HeaderContextAnchor148V1, [][148]byte, HeaderContextDecision148V1) {
	o := r.owner
	if in.WarmParent != nil {
		if d := o.checkWarmContext(in.View, in.WarmParent.Hash); d.Outcome != HeaderContextOK148V1 {
			return in, HeaderContextAnchor148V1{}, nil, d
		}
	}
	var proof HeaderContextAnchor148V1
	n, a := uint64(0), uint64(1)
	if c := in.ColdParent; c != nil {
		e := c.Anchor.Height / 10080 * 10080
		n = hctxSum(c.Anchor.Height-e, 1, c.Suffix, min(uint64(10), e))
		a = hctxSum(c.Suffix, 1)
	}
	if d := r.reserveContext(hash, n, a); d.Outcome != HeaderContextOK148V1 {
		return in, proof, nil, d
	}
	// Snapshot caller-owned integers after the aggregate reservation, before callbacks.
	in.Tip.Work = new(big.Int).Set(in.Tip.Work)
	if in.WarmParent != nil {
		proof = *in.WarmParent
	} else {
		proof = in.ColdParent.Anchor
	}
	proof.Work = new(big.Int).Set(proof.Work)
	var raws [][148]byte
	var d HeaderContextDecision148V1
	if in.ColdParent != nil {
		plan := *in.ColdParent
		plan.Anchor = proof
		in.ColdParent = &plan
		raws, d = o.coldContext(in, n)
		if d.Outcome != HeaderContextOK148V1 {
			return in, proof, nil, d
		}
	}
	return in, proof, raws, HeaderContextDecision148V1{}
}

// prepareContextPlan holds the C1 view only for pure qualification and actual C1 preparation.
func (o *HeaderCandidateOwner148V1) prepareContextPlan(in HeaderContextInput148V1, proof HeaderContextAnchor148V1, raws [][148]byte, r *hctxReservation) (*HeaderContextPrepared148V1, HeaderContextDecision148V1) {
	_, release := o.ProtectV1(in.View.Version)
	defer release()
	if d := o.checkContext(in.View); d.Outcome != HeaderContextOK148V1 {
		return nil, d
	}
	if d := o.anchorContext(proof); d.Outcome != HeaderContextOK148V1 {
		return nil, d
	}
	child, adds, d := o.prepareContextChild(in, proof, raws)
	if d.Outcome != HeaderContextOK148V1 {
		return nil, d
	}
	return r.attachContext(in, child, adds)
}

// prepareContextChild qualifies/ranks the final record and forms its exact C1 additions.
func (o *HeaderCandidateOwner148V1) prepareContextChild(in HeaderContextInput148V1, proof HeaderContextAnchor148V1, raws [][148]byte) (HeaderContextRecord148V1, []HeaderCandidateRecord148V1, HeaderContextDecision148V1) {
	parent, adds, d := o.prepareParentContext(in, proof, raws)
	if d.Outcome != HeaderContextOK148V1 {
		return HeaderContextRecord148V1{}, nil, d
	}
	child, d := hctxExtend(parent, in.Raw, proof.Provenance, o.context.limits.MaxWorkBytes)
	if d.Outcome != HeaderContextOK148V1 {
		return HeaderContextRecord148V1{}, nil, d
	}
	if d = o.rankContextChild(in.Tip, child); d.Outcome != HeaderContextOK148V1 {
		return HeaderContextRecord148V1{}, nil, d
	}
	external := len(adds) == 0 && proof.Kind != HeaderContextAdmitted148V1 && child.Parent == proof.Hash
	adds = append(adds, hctxPublication(child, external))
	return child, adds, HeaderContextDecision148V1{}
}

// rankContextChild checks representable eligibility and exact duplicate facts before C1 Prepare.
func (o *HeaderCandidateOwner148V1) rankContextChild(tip HeaderContextTip148V1, child HeaderContextRecord148V1) HeaderContextDecision148V1 {
	if !hctxTipAgrees(tip, child.Hash, child.Height, child.Work) {
		return hctxDecision(HeaderContextInconsistent148V1)
	}
	if tip.Height > math.MaxUint64-2 {
		return hctxDecision(HeaderContextCapacity148V1)
	}
	if child.Height > tip.Height+2 || !hcOutranks(child.Work, child.Hash, tip.Work, tip.Hash) {
		return hctxDecision(HeaderContextNoneligible148V1)
	}
	o.mu.Lock()
	old, exists := o.context.records[child.Hash]
	o.mu.Unlock()
	if exists && !hctxRecordFacts(old, child.Raw, child.Height, child.Work) {
		return hctxDecision(HeaderContextInconsistent148V1)
	}
	return HeaderContextDecision148V1{}
}

// attachContext joins an accepted real C1 handle with its still-owned C2 reservation.
func (r *hctxReservation) attachContext(in HeaderContextInput148V1, child HeaderContextRecord148V1, adds []HeaderCandidateRecord148V1) (*HeaderContextPrepared148V1, HeaderContextDecision148V1) {
	o := r.owner
	candidate, out := o.PrepareV1(HeaderCandidateTransition148V1{ExpectedVersion: in.View.Version, ExpectedSource: in.View.Source, Additions: adds})
	if out != HeaderCandidateOK148V1 {
		return nil, hctxCandidate(out)
	}
	o.mu.Lock()
	d := o.contextGate()
	if d.Outcome == HeaderContextOK148V1 {
		d = r.attachContextLocked(candidate, child, in.Source)
	}
	o.mu.Unlock()
	if d.Outcome != HeaderContextOK148V1 {
		if out = candidate.AbortV1(); out != HeaderCandidateOK148V1 {
			return nil, hctxCandidate(out)
		}
		return nil, d
	}
	return &HeaderContextPrepared148V1{candidate: candidate, reservation: r, view: in.View}, HeaderContextDecision148V1{}
}

// attachContextLocked owns the attachment only while both reservations remain live; mu is held.
func (r *hctxReservation) attachContextLocked(candidate *HeaderCandidatePrepared148V1, child HeaderContextRecord148V1, source HeaderContextSource148V1) HeaderContextDecision148V1 {
	if r.done || r.owner.context.active != r || candidate.consumed {
		return hctxDecision(HeaderContextUnavailable148V1)
	}
	r.record = child
	r.source = source
	candidate.plan.context = r
	return HeaderContextDecision148V1{}
}

// prepareParentContext joins warm or cold evidence without a second source pass.
func (o *HeaderCandidateOwner148V1) prepareParentContext(in HeaderContextInput148V1, proof HeaderContextAnchor148V1, raws [][148]byte) (HeaderContextRecord148V1, []HeaderCandidateRecord148V1, HeaderContextDecision148V1) {
	if in.WarmParent != nil {
		p, d := o.warmContext(in.View, proof)
		return p, make([]HeaderCandidateRecord148V1, 0, 1), d
	}
	p, d := hctxColdAnchor(in, raws)
	if d.Outcome != HeaderContextOK148V1 {
		return HeaderContextRecord148V1{}, nil, d
	}
	return o.suffixContext(in, raws, p)
}

// terminalContext consumes the wrapper before Closed or callbacks; mu is held briefly.
func (h *HeaderContextPrepared148V1) terminalContext() HeaderContextDecision148V1 {
	o := h.reservation.owner
	o.mu.Lock()
	defer o.mu.Unlock()
	if h.consumed || h.candidate.consumed {
		return hctxDecision(HeaderContextConsumed148V1)
	}
	h.consumed = true
	return o.contextGate()
}

// PublishV1 aborts the attached C1 plan on every refusal/panic before actual publication.
func (h *HeaderContextPrepared148V1) PublishV1() (HeaderContextRecord148V1, HeaderCandidatePublication148V1, HeaderContextDecision148V1) {
	d := h.terminalContext()
	if d.Outcome == HeaderContextConsumed148V1 {
		return HeaderContextRecord148V1{}, HeaderCandidatePublication148V1{}, d
	}
	defer h.candidate.AbortV1()
	if d.Outcome != HeaderContextOK148V1 {
		return HeaderContextRecord148V1{}, HeaderCandidatePublication148V1{}, d
	}
	o := h.reservation.owner
	o.mu.Lock()
	source := h.reservation.source
	o.mu.Unlock()
	if d = o.currentContext(h.view, source, nil); d.Outcome != HeaderContextOK148V1 {
		return HeaderContextRecord148V1{}, HeaderCandidatePublication148V1{}, d
	}
	// Current ran without a guard; only owned identity is observed under this fresh guard.
	_, release := o.ProtectV1(h.view.Version)
	d = o.checkContext(h.view)
	release()
	if d.Outcome != HeaderContextOK148V1 {
		return HeaderContextRecord148V1{}, HeaderCandidatePublication148V1{}, d
	}
	output, d := h.snapshotContextOutput()
	if d.Outcome != HeaderContextOK148V1 {
		return HeaderContextRecord148V1{}, HeaderCandidatePublication148V1{}, d
	}
	pub, out := h.candidate.PublishV1()
	if out != HeaderCandidateOK148V1 {
		return HeaderContextRecord148V1{}, HeaderCandidatePublication148V1{}, hctxCandidate(out)
	}
	output.View.Version = pub.Version
	return output, pub, HeaderContextDecision148V1{}
}

// snapshotContextOutput clones within pre-reserved S and synchronizes against direct terminal/Close cleanup.
func (h *HeaderContextPrepared148V1) snapshotContextOutput() (HeaderContextRecord148V1, HeaderContextDecision148V1) {
	o := h.reservation.owner
	o.mu.Lock()
	defer o.mu.Unlock()
	if d := o.contextGate(); d.Outcome != HeaderContextOK148V1 {
		return HeaderContextRecord148V1{}, d
	}
	if h.reservation.done {
		return HeaderContextRecord148V1{}, HeaderContextDecision148V1{}
	}
	return hctxClone(h.reservation.record), HeaderContextDecision148V1{}
}

// AbortV1 consumes both handles and releases all invocation charges once.
func (h *HeaderContextPrepared148V1) AbortV1() HeaderContextDecision148V1 {
	d := h.terminalContext()
	if d.Outcome == HeaderContextConsumed148V1 {
		return d
	}
	return hctxCandidate(h.candidate.AbortV1())
}
