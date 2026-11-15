package node

import (
	"fmt"
	"math"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

type pbFixture struct {
	o *HeaderCandidateOwner148V1
	p HeaderContextRecord148V1
	s *cxSource
}

func pbLimits() PendingBodyLimits148V1 {
	return PendingBodyLimits148V1{MaxCandidates: 4, MaxBytes: 4096, MaxDependencies: 8, MaxLifetime: 10}
}

// pbNew uses the real constructor, genesis qualification and context publication.
func pbNew(t *testing.T, limits PendingBodyLimits148V1) pbFixture {
	t.Helper()
	raw := cxMine([32]byte{}, 0, cxTarget(255))
	o, err := NewHeaderCandidateBodyCustody148V1(hcLim(), cxLimits(), limits, 7, [32]byte{91}, cxHash(raw))
	cxEqual(t, "body constructor", err, nil)
	hcEstablish(t, o)
	v := HeaderContextView148V1{Incarnation: 7, Version: 2, Source: [32]byte{1}, Authority: [32]byte{8}, Network: [32]byte{91}, Genesis: cxHash(raw)}
	s := &cxSource{raws: map[[32]byte][148]byte{cxHash(raw): raw}}
	parent := cxSeed(t, o, v, raw, s)
	p, _ := cxPublish(t, o, cxInput(v, cxMine(parent.Hash, 1, cxTarget(255)), cxProof(parent, HeaderContextCanonical148V1), s))
	t.Cleanup(func() {
		if !o.mu.TryLock() {
			t.Error("pending owner cleanup: shared mutex retained")
			return
		}
		o.mu.Unlock()
		o.CloseV1()
	})
	return pbFixture{o, p, s}
}

func pbPin(t *testing.T, f pbFixture) *HeaderContextLease148V1 {
	t.Helper()
	l, d := f.o.PinContextV1(f.p.View, f.p.Hash)
	cxDecision(t, "real pending pin", d, 0, 0, 0, nil)
	if l == nil {
		t.Fatal("real pending pin missing")
	}
	return l
}

// pbBundle supplies producer qualification only; C3 must perform all observed moves.
func pbBundle(t *testing.T, f pbFixture, origin uint64, kind uint8) *PendingBodyBundle148V1 {
	t.Helper()
	b := &PendingBodyBundle148V1{Body: make([]byte, 3, 8), RetainedBytes: 8, Origin: origin, Hash: f.p.Hash, Parent: f.p.Parent, Provenance: f.p.Provenance, View: f.p.View, Dependencies: []*HeaderContextLease148V1{pbPin(t, f)}}
	copy(b.Body, []byte{11, 22, 33})
	if kind != 0 {
		b.Weak = &PendingBodyWeak148V1{origin: origin, hash: b.Hash, provenance: b.Provenance, completion: PendingBodyCompletion148V1(kind)}
	}
	return b
}

func pbKey(b *PendingBodyBundle148V1) PendingBodyKey148V1 {
	return PendingBodyKey148V1{Origin: b.Origin, Hash: b.Hash}
}

func pbDecision(t *testing.T, label string, d PendingBodyDecision148V1, outcome, candidate uint8) {
	t.Helper()
	want := PendingBodyDecision148V1{Outcome: PendingBodyOutcome148V1(outcome), CandidateOutcome: HeaderCandidateOutcome148V1(candidate)}
	if d != want {
		t.Fatalf("%s: got %+v want %+v", label, d, want)
	}
}

// pbBundleImage captures storage identities, all bytes/fields and actual handle states.
func pbBundleImage(b *PendingBodyBundle148V1) string {
	if b == nil {
		return "nil"
	}
	image := fmt.Sprintf("%p/%x/%#v/deps=%p/weak=%p:%#v", b.Body, b.Body[:cap(b.Body)], *b, b.Dependencies, b.Weak, b.Weak)
	for _, l := range b.Dependencies {
		image += fmt.Sprintf("/pin=%p:%#v", l, l)
		if l != nil {
			image += fmt.Sprintf("/c1=%p:%#v", l.candidate, l.candidate)
		}
	}
	return image
}

// pbImage covers C1/C2 and every live custody record, counter, token and payload.
func pbImage(o *HeaderCandidateOwner148V1) string {
	image := fmt.Sprintf("C1=%#v", hcInnerOf(o))
	if o.context != nil {
		image += "/C2=" + cxState(o)
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	s := o.pendingBody
	if s == nil {
		return image + "/C3=nil"
	}
	image += fmt.Sprintf("/C3=%#v/%d/%d", s.limits, s.bytes, s.dependencies)
	var records []string
	for key, r := range s.records {
		records = append(records, fmt.Sprintf("%#v/%p/%d/%d/request=%p:%#v/next=%p/%s", key, r, r.charge, r.deadline, r.request, r.request, r.next, pbBundleImage(&r.bundle)))
	}
	slices.Sort(records)
	return image + "/" + strings.Join(records, ";")
}

func pbRefuse(t *testing.T, label string, o *HeaderCandidateOwner148V1, b *PendingBodyBundle148V1, now uint64, outcome, candidate uint8) {
	t.Helper()
	defer func() {
		if failure := recover(); failure != nil {
			t.Fatalf("%s: refusal panicked: %v", label, failure)
		}
	}()
	owner, producer := pbImage(o), pbBundleImage(b)
	pbDecision(t, label, o.RetainPendingBodyV1(b, now), outcome, candidate)
	cxEqual(t, label+" owner changed", pbImage(o), owner)
	cxEqual(t, label+" refused producer lease changed", pbBundleImage(b), producer)
}

func pbReleaseProducer(b *PendingBodyBundle148V1) {
	for _, l := range b.Dependencies {
		if l != nil && l.owner != nil {
			l.ReleaseV1()
		}
	}
}

func pbEmpty(t *testing.T, o *HeaderCandidateOwner148V1, label string) {
	t.Helper()
	o.mu.Lock()
	defer o.mu.Unlock()
	cxEqual(t, label+" terminal owner retained state", [3]uint64{uint64(len(o.pendingBody.records)), o.pendingBody.bytes, o.pendingBody.dependencies}, [3]uint64{})
}

func pbMoved(t *testing.T, got *PendingBodyBundle148V1, original PendingBodyBundle148V1) {
	t.Helper()
	if got == nil {
		t.Fatal("moved bundle missing")
	}
	if &got.Body[0] != &original.Body[0] {
		t.Fatal("pending body backing changed")
	}
	if &got.Dependencies[0] != &original.Dependencies[0] || got.Weak != original.Weak {
		t.Fatal("weak capability owner or provenance changed")
	}
	cxEqual(t, "exact moved bundle", *got, original)
}

func TestPendingBody148Configuration(t *testing.T) {
	for _, field := range []string{"MaxCandidates", "MaxBytes", "MaxDependencies", "MaxLifetime"} {
		for _, value := range []uint64{0, math.MaxUint64} {
			t.Run(fmt.Sprintf("%s-%d", field, value), func(t *testing.T) {
				l := pbLimits()
				reflect.ValueOf(&l).Elem().FieldByName(field).SetUint(value)
				o, err := NewHeaderCandidateBodyCustody148V1(hcLim(), cxLimits(), l, 7, [32]byte{91}, [32]byte{92})
				cxEqual(t, "invalid captured body limits owner", o, (*HeaderCandidateOwner148V1)(nil))
				cxEqual(t, "invalid captured body limits error", err, ErrPendingBodyConfig148V1)
			})
		}
	}
	for _, prior := range []string{"C1", "C2"} {
		cl, xl := hcLim(), cxLimits()
		want := ErrHeaderContextConfig148V1
		if prior == "C1" {
			cl.MaxLeases = 0
			want = ErrHeaderCandidateConfig148V1
		} else {
			xl.MaxPins = 0
		}
		o, err := NewHeaderCandidateBodyCustody148V1(cl, xl, PendingBodyLimits148V1{}, 7, [32]byte{91}, [32]byte{92})
		cxEqual(t, prior+" config precedence owner", o, (*HeaderCandidateOwner148V1)(nil))
		cxEqual(t, prior+" config precedence error", err, want)
	}
	for _, l := range []PendingBodyLimits148V1{{1, 1, 1, 1}, {9, 9999, 17, 71}} {
		o, err := NewHeaderCandidateBodyCustody148V1(hcLim(), cxLimits(), l, 7, [32]byte{91}, [32]byte{92})
		cxEqual(t, "nondefault constructor", err, nil)
		cxEqual(t, "limits captured exactly", o.pendingBody.limits, l)
		o.CloseV1()
	}
}

func TestPendingBody148Move(t *testing.T) {
	for _, kind := range []uint8{0, 1, 2} {
		t.Run(fmt.Sprintf("completion-%d", kind), func(t *testing.T) {
			f := pbNew(t, pbLimits())
			baseline := cxState(f.o)
			b := pbBundle(t, f, 91, kind)
			original, key, pin := *b, pbKey(b), b.Dependencies[0]
			c1 := hcInnerOf(f.o)
			contextBefore := cxState(f.o)
			pbDecision(t, "valid weak shape refused", f.o.RetainPendingBodyV1(b, 100), 0, 0)
			cxEqual(t, "producer still owns transferred bundle", *b, PendingBodyBundle148V1{})
			cxEqual(t, "C1 unchanged by custody", hcInnerOf(f.o), c1)
			cxEqual(t, "C2 unchanged by custody", cxState(f.o), contextBefore)
			cxEqual(t, "exact retained accounting", [5]uint64{f.o.pendingBody.bytes, f.o.pendingBody.dependencies, f.o.context.bytes, f.o.context.pins, f.o.leases}, [5]uint64{272, 1, 1853, 1, 1})
			cxEqual(t, "presence is custody", f.o.PendingBodyRetainedV1(key, 109), true)
			req, d := f.o.RequestPendingBodyV1(&key, 101)
			pbDecision(t, "pending request tuple", d, 0, 0)
			if req == nil {
				t.Fatal("first request missing")
			}
			requested := pbImage(f.o)
			repeated, d := f.o.RequestPendingBodyV1(&key, 109)
			pbDecision(t, "pending request tuple", d, 0, 0)
			cxEqual(t, "pending request tuple repeated token", repeated, (*PendingBodyRequest148V1)(nil))
			cxEqual(t, "request refreshed ownership", pbImage(f.o), requested)
			out, d := f.o.TakePendingBodyV1(req, 109)
			pbDecision(t, "take", d, 0, 0)
			pbMoved(t, out, original)
			pbEmpty(t, f.o, "take")
			if pin.released || pin.candidate.released || f.o.context.pins != 1 || f.o.leases != 1 {
				t.Fatal("handoff released receiving dependency")
			}
			owner, receiver := pbImage(f.o), pbBundleImage(out)
			again, d := f.o.TakePendingBodyV1(req, 109)
			pbDecision(t, "pending request tuple replay", d, 7, 0)
			cxEqual(t, "replay returned bundle", again, (*PendingBodyBundle148V1)(nil))
			cxEqual(t, "replay owner", pbImage(f.o), owner)
			cxEqual(t, "replay receiver", pbBundleImage(out), receiver)
			pbReleaseProducer(out)
			cxEqual(t, "receiver last-owner release", cxState(f.o), baseline)
			if out.Weak != nil && (out.Weak.ended || out.Weak.consumed) {
				t.Fatal("handoff ended weak capability")
			}
		})
	}
}

func TestPendingBody148Retirement(t *testing.T) {
	f := pbNew(t, pbLimits())
	ancestor := f.p
	f.p, _ = cxPublish(t, f.o, cxInput(ancestor.View, cxMine(ancestor.Hash, 2, cxTarget(255)), cxProof(ancestor, HeaderContextAdmitted148V1), f.s))
	b := pbBundle(t, f, 1, 1)
	key, pin := pbKey(b), b.Dependencies[0]
	pbDecision(t, "retain ancestry", f.o.RetainPendingBodyV1(b, 1), 0, 0)
	before := pbImage(f.o)
	h, out := f.o.PrepareV1(hcTr(f.o, nil, ancestor.Hash, f.p.Hash))
	cxEqual(t, "real ancestor retirement protected", uint8(out), uint8(10))
	cxEqual(t, "protected no plan", h, (*HeaderCandidatePrepared148V1)(nil))
	cxEqual(t, "protected complete image", pbImage(f.o), before)
	pbDecision(t, "terminal ancestry release", f.o.ReleasePendingBodyV1(key, PendingBodyReleaseCancelled148V1), 0, 0)
	if !pin.released || !pin.candidate.released || f.o.context.pins != 0 || f.o.leases != 0 {
		t.Fatal("released dependency still protects ancestor")
	}
	pub, out := hcPublish(t, f.o, hcTr(f.o, nil, ancestor.Hash, f.p.Hash))
	cxEqual(t, "released dependency still protects ancestor", uint8(out), uint8(0))
	cxEqual(t, "actual retired ancestors", pub.Retired, [][32]byte{ancestor.Hash, f.p.Hash})
	cxEqual(t, "post-retirement real resources", [3]uint64{f.o.context.bytes, f.o.context.pins, f.o.leases}, [3]uint64{1118, 0, 0})
}

type pbBadShape struct {
	name string
	edit func(*PendingBodyBundle148V1) *PendingBodyBundle148V1
}

func pbShapeRows() []pbBadShape {
	return []pbBadShape{
		{"nil-bundle", func(b *PendingBodyBundle148V1) *PendingBodyBundle148V1 { return nil }},
		{"nil-body", func(b *PendingBodyBundle148V1) *PendingBodyBundle148V1 { b.Body = nil; return b }},
		{"empty-body", func(b *PendingBodyBundle148V1) *PendingBodyBundle148V1 { b.Body = b.Body[:0]; return b }},
		{"zero-charge", func(b *PendingBodyBundle148V1) *PendingBodyBundle148V1 { b.RetainedBytes = 0; return b }},
		{"below-cap", func(b *PendingBodyBundle148V1) *PendingBodyBundle148V1 { b.RetainedBytes = 7; return b }},
		{"zero-origin", func(b *PendingBodyBundle148V1) *PendingBodyBundle148V1 { b.Origin = 0; b.Weak.origin = 0; return b }},
		{"zero-hash", func(b *PendingBodyBundle148V1) *PendingBodyBundle148V1 { b.Hash = [32]byte{}; b.Weak.hash = b.Hash; return b }},
		{"zero-provenance", func(b *PendingBodyBundle148V1) *PendingBodyBundle148V1 { b.Provenance = [32]byte{}; b.Weak.provenance = b.Provenance; return b }},
		{"zero-incarnation", func(b *PendingBodyBundle148V1) *PendingBodyBundle148V1 { b.View.Incarnation = 0; return b }},
		{"zero-version", func(b *PendingBodyBundle148V1) *PendingBodyBundle148V1 { b.View.Version = 0; return b }},
		{"zero-source", func(b *PendingBodyBundle148V1) *PendingBodyBundle148V1 { b.View.Source = [32]byte{}; return b }},
		{"zero-authority", func(b *PendingBodyBundle148V1) *PendingBodyBundle148V1 { b.View.Authority = [32]byte{}; return b }},
		{"zero-network", func(b *PendingBodyBundle148V1) *PendingBodyBundle148V1 { b.View.Network = [32]byte{}; return b }},
		{"wrong-network", func(b *PendingBodyBundle148V1) *PendingBodyBundle148V1 { b.View.Network = [32]byte{92}; return b }},
		{"zero-genesis", func(b *PendingBodyBundle148V1) *PendingBodyBundle148V1 { b.View.Genesis = [32]byte{}; return b }},
		{"wrong-genesis", func(b *PendingBodyBundle148V1) *PendingBodyBundle148V1 { b.View.Genesis = [32]byte{93}; return b }},
	}
}

func TestPendingBody148Shapes(t *testing.T) {
	for _, row := range pbShapeRows() {
		for _, overBound := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s-overBound-%v", row.name, overBound), func(t *testing.T) {
				f := pbNew(t, pbLimits())
				b := pbBundle(t, f, 1, 1)
				original := *b
				if overBound {
					b.Dependencies = make([]*HeaderContextLease148V1, 9)
				}
				bad := row.edit(b)
				pbRefuse(t, "pending shape tuple/"+row.name, f.o, bad, 100, 2, 0)
				pbReleaseProducer(&original)
				good := pbBundle(t, f, 2, 0)
				pbDecision(t, "shape refusal next operation", f.o.RetainPendingBodyV1(good, 100), 0, 0)
			})
		}
	}
}

func TestPendingBody148WeakShapes(t *testing.T) {
	rows := []struct {
		name string
		edit func(*PendingBodyWeak148V1)
	}{
		{"zero-kind", func(w *PendingBodyWeak148V1) { w.completion = 0 }},
		{"unknown-kind", func(w *PendingBodyWeak148V1) { w.completion = 3 }},
		{"ended", func(w *PendingBodyWeak148V1) { w.ended = true }},
		{"consumed", func(w *PendingBodyWeak148V1) { w.consumed = true }},
		{"wrong-origin", func(w *PendingBodyWeak148V1) { w.origin++ }},
		{"wrong-hash", func(w *PendingBodyWeak148V1) { w.hash = [32]byte{98} }},
		{"wrong-provenance", func(w *PendingBodyWeak148V1) { w.provenance = [32]byte{99} }},
	}
	for _, row := range rows {
		for _, overBound := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s-overBound-%v", row.name, overBound), func(t *testing.T) {
				f := pbNew(t, pbLimits())
				b := pbBundle(t, f, 1, 1)
				pins := b.Dependencies
				if overBound {
					b.Dependencies = make([]*HeaderContextLease148V1, 9)
				}
				w := *b.Weak
				row.edit(b.Weak)
				pbRefuse(t, "pending weak payload tuple/"+row.name, f.o, b, 100, 2, 0)
				*b.Weak = w
				b.Dependencies = pins
				pbDecision(t, "weak refusal next operation", f.o.RetainPendingBodyV1(b, 100), 0, 0)
			})
		}
	}
}

func TestPendingBody148Bounds(t *testing.T) {
	rows := []struct {
		name string
		limits PendingBodyLimits148V1
		pins int
		charge, now uint64
		prefill bool
		outcome uint8
	}{
		{"count-exact", PendingBodyLimits148V1{1, 4096, 8, 10}, 1, 8, 100, false, 0},
		{"count-over", PendingBodyLimits148V1{1, 4096, 8, 10}, 1, 8, 100, true, 4},
		{"bytes-exact", PendingBodyLimits148V1{4, 272, 8, 10}, 1, 8, 100, false, 0},
		{"bytes-over", PendingBodyLimits148V1{4, 271, 8, 10}, 1, 8, 100, false, 4},
		{"aggregate-bytes-exact", PendingBodyLimits148V1{4, 544, 8, 10}, 1, 8, 100, true, 0},
		{"aggregate-bytes-over", PendingBodyLimits148V1{4, 543, 8, 10}, 1, 8, 100, true, 4},
		{"dependencies-exact", PendingBodyLimits148V1{4, 4096, 2, 10}, 2, 8, 100, false, 0},
		{"dependencies-over", PendingBodyLimits148V1{4, 4096, 1, 10}, 2, 8, 100, false, 4},
		{"aggregate-dependencies-exact", PendingBodyLimits148V1{4, 4096, 2, 10}, 1, 8, 100, true, 0},
		{"aggregate-dependencies-over", PendingBodyLimits148V1{4, 4096, 1, 10}, 1, 8, 100, true, 4},
		{"body-charge-equal-cap", pbLimits(), 1, 8, 100, false, 0},
		{"body-charge-above-cap", pbLimits(), 1, 9, 100, false, 0},
		{"metadata-sum-exact-max", PendingBodyLimits148V1{4, math.MaxUint64 - 1, 8, 10}, 1, math.MaxUint64 - 264, 100, false, 4},
		{"metadata-sum-overflow", PendingBodyLimits148V1{4, math.MaxUint64 - 1, 8, 10}, 1, math.MaxUint64 - 263, 100, false, 4},
		{"body-charge-max", pbLimits(), 1, math.MaxUint64, 100, false, 4},
		{"deadline-exact-max", pbLimits(), 1, 8, math.MaxUint64 - 10, false, 0},
		{"deadline-overflow", pbLimits(), 1, 8, math.MaxUint64 - 9, false, 4},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			f := pbNew(t, row.limits)
			if row.prefill {
				pbDecision(t, "prefill", f.o.RetainPendingBodyV1(pbBundle(t, f, 1, 1), row.now), 0, 0)
			}
			b := pbBundle(t, f, 2, 2)
			for len(b.Dependencies) < row.pins {
				b.Dependencies = append(b.Dependencies, pbPin(t, f))
			}
			b.RetainedBytes = row.charge
			if row.outcome != 0 {
				pbRefuse(t, "pending overflow changed owner/"+row.name, f.o, b, row.now, row.outcome, 0)
				pbReleaseProducer(b)
				return
			}
			key, original := pbKey(b), *b
			pbDecision(t, "pending exact fit/"+row.name, f.o.RetainPendingBodyV1(b, row.now), 0, 0)
			r := f.o.pendingBody.records[key]
			cxEqual(t, "literal metadata charge", r.charge, row.charge+256+8*uint64(row.pins))
			cxEqual(t, "captured deadline", r.deadline, row.now+10)
			pbMoved(t, &r.bundle, original)
			if r.deadline == math.MaxUint64 {
				cxEqual(t, "maximum deadline minus one", f.o.PendingBodyRetainedV1(key, math.MaxUint64-1), true)
				cxEqual(t, "maximum deadline equality expires", f.o.PendingBodyRetainedV1(key, math.MaxUint64), false)
			}
		})
	}
	// Two logical retained charges overflow their shared total with only two real pins.
	f := pbNew(t, PendingBodyLimits148V1{4, math.MaxUint64 - 1, 8, 10})
	first := pbBundle(t, f, 1, 1)
	first.RetainedBytes = math.MaxUint64 - 1000
	pbDecision(t, "large finite logical charge", f.o.RetainPendingBodyV1(first, 100), 0, 0)
	second := pbBundle(t, f, 2, 2)
	second.RetainedBytes = 1000
	pbRefuse(t, "pending overflow changed owner/aggregate-bytes", f.o, second, 100, 4, 0)
	pbReleaseProducer(second)
}

func TestPendingBody148Dependencies(t *testing.T) {
	for _, kind := range []string{"nil", "foreign", "released", "repeated", "missing-selected", "zero", "over-limit-invalid"} {
		t.Run(kind, func(t *testing.T) {
			limits := pbLimits()
			limits.MaxDependencies = 2
			f, foreign := pbNew(t, limits), pbNew(t, pbLimits())
			b := pbBundle(t, f, 1, 1)
			original := *b
			var extra *HeaderContextLease148V1
			want := uint8(2)
			switch kind {
			case "nil":
				b.Dependencies = []*HeaderContextLease148V1{nil}
			case "foreign":
				extra = pbPin(t, foreign)
				b.Dependencies = []*HeaderContextLease148V1{extra}
			case "released":
				b.Dependencies[0].ReleaseV1()
			case "repeated":
				b.Dependencies = append(b.Dependencies, b.Dependencies[0])
			case "missing-selected":
				v := f.p.View
				genesis := f.o.context.records[v.Genesis]
				_, d := f.o.RebindContextV1(v, *cxProof(genesis, HeaderContextCanonical148V1), f.s)
				cxDecision(t, "current parent evidence", d, 0, 0, 0, nil)
				extra, d = f.o.PinContextV1(v, v.Genesis)
				cxDecision(t, "real parent pin", d, 0, 0, 0, nil)
				b.Dependencies = []*HeaderContextLease148V1{extra}
			case "zero":
				b.Dependencies = nil
			case "over-limit-invalid":
				b.Dependencies = []*HeaderContextLease148V1{nil, nil, nil}
				want = 4
			}
			foreignBefore := pbImage(foreign.o)
			label := "pending dependency tuple/"+kind
			if kind == "over-limit-invalid" {
				label = "dependency bound preceded payload incorrectly"
			}
			pbRefuse(t, label, f.o, b, 100, want, 0)
			cxEqual(t, "foreign real owner changed", pbImage(foreign.o), foreignBefore)
			pbReleaseProducer(&original)
			if extra != nil {
				extra.ReleaseV1()
			}
			pbDecision(t, "dependency refusal next operation", f.o.RetainPendingBodyV1(pbBundle(t, f, 2, 0), 100), 0, 0)
		})
	}
}

// pbAdvance changes source authority by an actual C1 publication while retaining leases.
func pbAdvance(t *testing.T, f pbFixture, source bool) HeaderContextView148V1 {
	t.Helper()
	tr := hcTr(f.o, nil)
	if source {
		tr.NewSource = [32]byte{2}
	} else {
		tr.Additions = []HeaderCandidateRecord148V1{hcExt(hcMk(t, [32]byte{50}, 20, 30, 51))}
	}
	pub, out := hcPublish(t, f.o, tr)
	cxEqual(t, "actual authority advance", uint8(out), uint8(0))
	v := f.p.View
	v.Version = pub.Version
	if source {
		v.Source = [32]byte{2}
	}
	return v
}

func TestPendingBody148CurrentContext(t *testing.T) {
	for _, kind := range []string{"incarnation", "version", "source", "stored-view", "parent", "provenance"} {
		t.Run(kind, func(t *testing.T) {
			f := pbNew(t, pbLimits())
			b := pbBundle(t, f, 1, 1)
			want := uint8(3)
			switch kind {
			case "incarnation":
				b.View.Incarnation++
			case "version":
				pbAdvance(t, f, false)
			case "source":
				fresh := pbAdvance(t, f, true)
				b.View.Version = fresh.Version
			case "stored-view":
				b.View = pbAdvance(t, f, false)
			case "parent":
				b.Parent = [32]byte{99}
				want = 2
			case "provenance":
				record, _ := f.o.LookupV1(b.Hash)
				record.Provenance = [32]byte{10}
				_, out := hcPublish(t, f.o, hcTr(f.o, []HeaderCandidateRecord148V1{record}))
				cxEqual(t, "real provenance update", uint8(out), uint8(0))
				b.View.Version = f.o.VersionV1()
				_, d := f.o.RebindContextV1(b.View, *cxProof(f.o.context.records[b.Hash], HeaderContextAdmitted148V1), f.s)
				cxDecision(t, "current provenance rebind", d, 0, 0, 0, nil)
				want = 2
			}
			pbRefuse(t, "pending context tuple/"+kind, f.o, b, 100, want, 0)
			pbReleaseProducer(b)
		})
	}
}

func TestPendingBody148Terminal(t *testing.T) {
	for _, cause := range []uint8{1, 2, 3, 4, 5, 6} {
		for _, kind := range []uint8{1, 2} {
			t.Run(fmt.Sprintf("cause-%d-kind-%d", cause, kind), func(t *testing.T) {
				f := pbNew(t, pbLimits())
				baseline := cxState(f.o)
				b := pbBundle(t, f, 1, kind)
				b.Dependencies = append(b.Dependencies, pbPin(t, f))
				key, weak, pins := pbKey(b), b.Weak, slices.Clone(b.Dependencies)
				pbDecision(t, "retain terminal", f.o.RetainPendingBodyV1(b, 100), 0, 0)
				req, d := f.o.RequestPendingBodyV1(&key, 100)
				pbDecision(t, "terminal request", d, 0, 0)
				pbDecision(t, "terminal release", f.o.ReleasePendingBodyV1(key, PendingBodyRelease148V1(cause)), 0, 0)
				pbEmpty(t, f.o, "release")
				cxEqual(t, "released exact real accounting", cxState(f.o), baseline)
				for _, pin := range pins {
					if !pin.released || !pin.candidate.released {
						t.Fatal("released dependency still protects ancestor")
					}
				}
				if !weak.ended || weak.consumed {
					t.Fatal("released weak capability still live")
					}
				before := pbImage(f.o)
				pbDecision(t, "repeated terminal release", f.o.ReleasePendingBodyV1(key, PendingBodyRelease148V1(cause)), 6, 0)
				cxEqual(t, "repeat release changed owner", pbImage(f.o), before)
				out, d := f.o.TakePendingBodyV1(req, 100)
				pbDecision(t, "pending request tuple after release", d, 7, 0)
				cxEqual(t, "released token returned bundle", out, (*PendingBodyBundle148V1)(nil))
				pbDecision(t, "terminal next retain", f.o.RetainPendingBodyV1(pbBundle(t, f, 1, 0), 101), 0, 0)
			})
		}
	}
}

func TestPendingBody148Expiry(t *testing.T) {
	for _, accessor := range []string{"presence", "request", "take", "explicit", "retain"} {
		t.Run(accessor, func(t *testing.T) {
			f := pbNew(t, pbLimits())
			b := pbBundle(t, f, 1, 1)
			key, weak, pin := pbKey(b), b.Weak, b.Dependencies[0]
			pbDecision(t, "retain expiry", f.o.RetainPendingBodyV1(b, 100), 0, 0)
			req, d := f.o.RequestPendingBodyV1(&key, 109)
			pbDecision(t, "expiry request", d, 0, 0)
			duplicate := pbBundle(t, f, 1, 2)
			pbRefuse(t, "duplicate does not extend lifetime", f.o, duplicate, 109, 5, 0)
			pbReleaseProducer(duplicate)
			cxEqual(t, "deadline minus one retains", f.o.PendingBodyRetainedV1(key, 109), true)
			switch accessor {
			case "presence":
				cxEqual(t, "deadline equality retained body", f.o.PendingBodyRetainedV1(key, 110), false)
			case "request":
				q, result := f.o.RequestPendingBodyV1(&key, 110)
				pbDecision(t, "request extended lifetime", result, 6, 0)
				cxEqual(t, "expired request emitted token", q, (*PendingBodyRequest148V1)(nil))
			case "take":
				out, result := f.o.TakePendingBodyV1(req, 110)
				pbDecision(t, "deadline equality retained body", result, 6, 0)
				cxEqual(t, "expired take returned body", out, (*PendingBodyBundle148V1)(nil))
			case "explicit":
				f.o.ExpirePendingBodiesV1(109)
				cxEqual(t, "explicit minus one retains", f.o.PendingBodyRetainedV1(key, 109), true)
				f.o.ExpirePendingBodiesV1(110)
			case "retain":
				fresh := pbBundle(t, f, 1, 2)
				pbDecision(t, "expired same-key replacement", f.o.RetainPendingBodyV1(fresh, 110), 0, 0)
				cxEqual(t, "replacement deadline", f.o.pendingBody.records[key].deadline, uint64(120))
				pbDecision(t, "replacement cleanup", f.o.ReleasePendingBodyV1(key, 3), 0, 0)
			}
			pbEmpty(t, f.o, "expiry")
			if !weak.ended || !pin.released || !pin.candidate.released {
				t.Fatal("expiry did not end real owner")
			}
			cxEqual(t, "expiry actual restored bytes", [3]uint64{f.o.context.bytes, f.o.context.pins, f.o.leases}, [3]uint64{1725, 0, 0})
			out, d := f.o.TakePendingBodyV1(req, 111)
			pbDecision(t, "pending request tuple expired emitted token", d, 7, 0)
			cxEqual(t, "expired token bundle", out, (*PendingBodyBundle148V1)(nil))
			cxEqual(t, "later remains absent", f.o.PendingBodyRetainedV1(key, 111), false)
			q, d := f.o.RequestPendingBodyV1(&key, 111)
			pbDecision(t, "pending request tuple expired key", d, 6, 0)
			cxEqual(t, "expired key token", q, (*PendingBodyRequest148V1)(nil))
		})
	}
}

func TestPendingBody148DuplicateDomain(t *testing.T) {
	f := pbNew(t, PendingBodyLimits148V1{2, 544, 2, 10})
	first, independent := pbBundle(t, f, 1, 1), pbBundle(t, f, 2, 2)
	key, otherKey := pbKey(first), pbKey(independent)
	firstWeak, otherWeak := first.Weak, independent.Weak
	pbDecision(t, "first origin", f.o.RetainPendingBodyV1(first, 100), 0, 0)
	pbDecision(t, "independent origin refused or replaced", f.o.RetainPendingBodyV1(independent, 100), 0, 0)
	duplicate := pbBundle(t, f, 1, 2)
	pbRefuse(t, "pending first-result tuple/duplicate-before-remaining-quota", f.o, duplicate, 100, 5, 0)
	pbReleaseProducer(duplicate)
	cxEqual(t, "two exact independent owners", [5]uint64{uint64(len(f.o.pendingBody.records)), f.o.pendingBody.bytes, f.o.pendingBody.dependencies, f.o.context.pins, f.o.leases}, [5]uint64{2, 544, 2, 2, 2})
	otherBefore := pbBundleImage(&f.o.pendingBody.records[otherKey].bundle)
	pbDecision(t, "release one origin", f.o.ReleasePendingBodyV1(key, 3), 0, 0)
	cxEqual(t, "independent-origin survival", pbBundleImage(&f.o.pendingBody.records[otherKey].bundle), otherBefore)
	if !firstWeak.ended || otherWeak.ended || otherWeak.consumed {
		t.Fatal("weak capability owner or provenance changed")
	}
	cxEqual(t, "independent charges survive", [4]uint64{f.o.pendingBody.bytes, f.o.pendingBody.dependencies, f.o.context.pins, f.o.leases}, [4]uint64{272, 1, 1, 1})
	// A newly qualified different hash may progress; old retained pins are not freshness.
	f.p, _ = cxPublish(t, f.o, cxInput(f.p.View, cxMine(f.p.Hash, 2, cxTarget(255)), cxProof(f.p, HeaderContextAdmitted148V1), f.s))
	newBody := pbBundle(t, f, 1, 1)
	pbDecision(t, "different hash progresses", f.o.RetainPendingBodyV1(newBody, 100), 0, 0)
	cxEqual(t, "different hashes coexist", len(f.o.pendingBody.records), 2)
}

func TestPendingBody148Replacement(t *testing.T) {
	f := pbNew(t, pbLimits())
	first, other := pbBundle(t, f, 1, 1), pbBundle(t, f, 2, 2)
	key, otherKey := pbKey(first), pbKey(other)
	pbDecision(t, "replacement first", f.o.RetainPendingBodyV1(first, 100), 0, 0)
	pbDecision(t, "replacement sibling", f.o.RetainPendingBodyV1(other, 100), 0, 0)
	old, d := f.o.RequestPendingBodyV1(&key, 100)
	pbDecision(t, "old record request", d, 0, 0)
	pbDecision(t, "old record release", f.o.ReleasePendingBodyV1(key, 3), 0, 0)
	replacement := pbBundle(t, f, 1, 2)
	replacement.Body[0] = 77
	newWeak := replacement.Weak
	pbDecision(t, "same-key replacement", f.o.RetainPendingBodyV1(replacement, 101), 0, 0)
	before := pbImage(f.o)
	out, d := f.o.TakePendingBodyV1(old, 102)
	pbDecision(t, "pending request tuple replaced record", d, 7, 0)
	cxEqual(t, "stale request took replacement body", out, (*PendingBodyBundle148V1)(nil))
	cxEqual(t, "stale request changed replacement", pbImage(f.o), before)
	cxEqual(t, "same-hash sibling retained", f.o.PendingBodyRetainedV1(otherKey, 102), true)
	q, d := f.o.RequestPendingBodyV1(&key, 102)
	pbDecision(t, "replacement request", d, 0, 0)
	out, d = f.o.TakePendingBodyV1(q, 102)
	pbDecision(t, "replacement take", d, 0, 0)
	cxEqual(t, "replacement buffer selected", out.Body[0], byte(77))
	cxEqual(t, "replacement capability exact", out.Weak == newWeak, true)
	pbReleaseProducer(out)
}

func TestPendingBody148RequestDomain(t *testing.T) {
	for _, input := range []string{"nil-key", "zero-key", "zero-origin", "zero-hash", "missing-key", "nil-token", "zero-token", "foreign-token", "unknown-cause-live", "zero-cause-live", "unknown-cause-absent", "zero-cause-absent"} {
		t.Run(input, func(t *testing.T) {
			defer func() {
				if failure := recover(); failure != nil {
					t.Fatalf("pending request tuple/%s: request panicked: %v", input, failure)
				}
			}()
			f, other := pbNew(t, pbLimits()), pbNew(t, pbLimits())
			b, foreign := pbBundle(t, f, 1, 1), pbBundle(t, other, 1, 2)
			key, foreignKey := pbKey(b), pbKey(foreign)
			pbDecision(t, "request live prerequisite", f.o.RetainPendingBodyV1(b, 100), 0, 0)
			pbDecision(t, "foreign live prerequisite", other.o.RetainPendingBodyV1(foreign, 100), 0, 0)
			foreignToken, d := other.o.RequestPendingBodyV1(&foreignKey, 100)
			pbDecision(t, "foreign request", d, 0, 0)
			owner, foreignOwner := pbImage(f.o), pbImage(other.o)
			var token *PendingBodyRequest148V1
			var bundle *PendingBodyBundle148V1
			want := uint8(2)
			switch input {
			case "nil-key":
				token, d = f.o.RequestPendingBodyV1(nil, 100)
			case "zero-key":
				token, d = f.o.RequestPendingBodyV1(&PendingBodyKey148V1{}, 100)
			case "zero-origin":
				token, d = f.o.RequestPendingBodyV1(&PendingBodyKey148V1{Hash: key.Hash}, 100)
			case "zero-hash":
				token, d = f.o.RequestPendingBodyV1(&PendingBodyKey148V1{Origin: key.Origin}, 100)
			case "missing-key":
				missing := PendingBodyKey148V1{Origin: 99, Hash: key.Hash}
				token, d = f.o.RequestPendingBodyV1(&missing, 100)
				want = 6
			case "nil-token":
				bundle, d = f.o.TakePendingBodyV1(nil, 100)
			case "zero-token":
				bundle, d = f.o.TakePendingBodyV1(&PendingBodyRequest148V1{}, 100)
			case "foreign-token":
				bundle, d = f.o.TakePendingBodyV1(foreignToken, 100)
			default:
				cause := PendingBodyRelease148V1(7)
				if strings.HasPrefix(input, "zero-") {
					cause = 0
				}
				if strings.HasSuffix(input, "absent") {
					key.Origin = 99
				}
				d = f.o.ReleasePendingBodyV1(key, cause)
			}
			pbDecision(t, "pending request tuple/"+input, d, want, 0)
			cxEqual(t, "invalid request returned token", token, (*PendingBodyRequest148V1)(nil))
			cxEqual(t, "invalid request returned bundle", bundle, (*PendingBodyBundle148V1)(nil))
			cxEqual(t, "invalid request actual owner image", pbImage(f.o), owner)
			cxEqual(t, "invalid request foreign owner image", pbImage(other.o), foreignOwner)
			q, result := f.o.RequestPendingBodyV1(&PendingBodyKey148V1{Origin: 1, Hash: f.p.Hash}, 100)
			pbDecision(t, "request refusal next operation", result, 0, 0)
			if q == nil {
				t.Fatal("request refusal poisoned next operation")
			}
		})
	}
}

func pbLatch(t *testing.T, f pbFixture) {
	t.Helper()
	h := hcPrepOK(t, f.o, hcTr(f.o, nil))
	cxEqual(t, "actual unknown source latch", uint8(h.UnknownV1()), uint8(0))
}

func TestPendingBody148Lifecycle(t *testing.T) {
	for _, state := range []string{"Closed", "UnknownSource", "NotEstablished", "C1-only", "C2-only"} {
		t.Run(state, func(t *testing.T) {
			f := pbNew(t, pbLimits())
			b := pbBundle(t, f, 1, 1)
			key := pbKey(b)
			pbDecision(t, "lifecycle retain prerequisite", f.o.RetainPendingBodyV1(b, 100), 0, 0)
			q, d := f.o.RequestPendingBodyV1(&key, 100)
			pbDecision(t, "lifecycle token prerequisite", d, 0, 0)
			o, candidate := f.o, uint8(0)
			switch state {
			case "Closed":
				o.CloseV1()
				candidate = 1
			case "UnknownSource":
				pbLatch(t, f)
				candidate = 2
			case "NotEstablished":
				var err error
				o, err = NewHeaderCandidateBodyCustody148V1(hcLim(), cxLimits(), pbLimits(), 7, [32]byte{91}, [32]byte{92})
				cxEqual(t, "unestablished constructor", err, nil)
				candidate = 3
			case "C1-only":
				o = hcNew(t, hcLim())
				hcEstablish(t, o)
			case "C2-only":
				var err error
				o, err = NewHeaderCandidateContext148V1(hcLim(), cxLimits(), 7, [32]byte{91}, [32]byte{92})
				cxEqual(t, "C2-only constructor", err, nil)
				hcEstablish(t, o)
			}
			before := pbImage(o)
			pbRefuse(t, "pending lifecycle tuple/retain/"+state, o, nil, 100, 1, candidate)
			request, d := o.RequestPendingBodyV1(nil, 100)
			pbDecision(t, "pending lifecycle tuple/request/"+state, d, 1, candidate)
			cxEqual(t, "lifecycle token", request, (*PendingBodyRequest148V1)(nil))
			bundle, d := o.TakePendingBodyV1(q, 100)
			pbDecision(t, "pending lifecycle tuple/take/"+state, d, 1, candidate)
			cxEqual(t, "lifecycle bundle", bundle, (*PendingBodyBundle148V1)(nil))
			cxEqual(t, "lifecycle unchanged owner", pbImage(o), before)
			if state == "UnknownSource" {
				pbDecision(t, "source latch blocked owned cleanup", o.ReleasePendingBodyV1(key, 4), 0, 0)
				cxEqual(t, "source latch exact release", [3]uint64{o.context.bytes, o.context.pins, o.leases}, [3]uint64{1725, 0, 0})
			}
			if state == "Closed" || state == "C1-only" || state == "C2-only" {
				cxEqual(t, "closed or unattached presence", o.PendingBodyRetainedV1(key, 100), false)
			}
			o.CloseV1()
		})
	}
}

type pbOperationResult struct {
	bundle *PendingBodyBundle148V1
	d PendingBodyDecision148V1
}

// pbOrdered runs real operations in both channel-selected linearization orders.
// The timer only bounds completion; it never decides which operation wins.
func pbOrdered(t *testing.T, first, second func() pbOperationResult) (pbOperationResult, pbOperationResult) {
	t.Helper()
	start, firstDone := make(chan struct{}), make(chan struct{})
	one, two := make(chan pbOperationResult, 1), make(chan pbOperationResult, 1)
	go func() { <-start; one <- first(); close(firstDone) }()
	go func() { <-firstDone; two <- second() }()
	close(start)
	var a, b pbOperationResult
	select {
	case a = <-one:
	case <-time.After(5 * time.Second):
		t.Fatal("close did not release ownership: first operation did not complete")
	}
	select {
	case b = <-two:
	case <-time.After(5 * time.Second):
		t.Fatal("close did not release ownership: second operation did not complete")
	}
	return a, b
}

func TestPendingBody148TerminalOrders(t *testing.T) {
	for _, terminal := range []string{"Expire", "Cancel", "SourceLost"} {
		for _, takeFirst := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s-takeFirst-%v", terminal, takeFirst), func(t *testing.T) {
				f := pbNew(t, pbLimits())
				b := pbBundle(t, f, 1, 1)
				key, original := pbKey(b), *b
				pbDecision(t, "race prerequisite", f.o.RetainPendingBodyV1(b, 100), 0, 0)
				q, d := f.o.RequestPendingBodyV1(&key, 100)
				pbDecision(t, "race request", d, 0, 0)
				take := func() pbOperationResult { bundle, result := f.o.TakePendingBodyV1(q, 109); return pbOperationResult{bundle, result} }
				dispose := func() pbOperationResult {
					if terminal == "Expire" {
						f.o.ExpirePendingBodiesV1(110)
						return pbOperationResult{}
					}
					cause := PendingBodyRelease148V1(3)
					if terminal == "SourceLost" {
						cause = 4
					}
					return pbOperationResult{d: f.o.ReleasePendingBodyV1(key, cause)}
				}
				first, second := dispose, take
				if takeFirst {
					first, second = take, dispose
				}
				a, z := pbOrdered(t, first, second)
				pbEmpty(t, f.o, "terminal orders")
				if takeFirst {
					pbDecision(t, "take winner", a.d, 0, 0)
					pbMoved(t, a.bundle, original)
					if original.Dependencies[0].released || original.Weak.ended {
						t.Fatal("handoff released receiving dependency")
					}
					if terminal != "Expire" {
						pbDecision(t, "terminal loser", z.d, 6, 0)
					}
					pbReleaseProducer(a.bundle)
				} else {
					pbDecision(t, "terminal winner", a.d, 0, 0)
					pbDecision(t, "take loser", z.d, 7, 0)
					cxEqual(t, "terminal no second bundle", z.bundle, (*PendingBodyBundle148V1)(nil))
					if !original.Dependencies[0].released || !original.Weak.ended {
						t.Fatal("terminal winner did not release actual owner")
					}
				}
				cxEqual(t, "terminal race exact real resources", [3]uint64{f.o.context.bytes, f.o.context.pins, f.o.leases}, [3]uint64{1725, 0, 0})
			})
		}
	}
}

func TestPendingBody148CloseOrders(t *testing.T) {
	for _, operation := range []string{"retain", "request", "take", "release"} {
		for _, closeFirst := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s-closeFirst-%v", operation, closeFirst), func(t *testing.T) {
				f := pbNew(t, pbLimits())
				b := pbBundle(t, f, 1, 1)
				key, original := pbKey(b), *b
				var q *PendingBodyRequest148V1
				if operation != "retain" {
					pbDecision(t, "close owned prerequisite", f.o.RetainPendingBodyV1(b, 100), 0, 0)
					if operation == "take" {
						var d PendingBodyDecision148V1
						q, d = f.o.RequestPendingBodyV1(&key, 100)
						pbDecision(t, "close request prerequisite", d, 0, 0)
					}
				}
				act := func() pbOperationResult {
					switch operation {
					case "retain":
						return pbOperationResult{d: f.o.RetainPendingBodyV1(b, 100)}
					case "request":
						var d PendingBodyDecision148V1
						q, d = f.o.RequestPendingBodyV1(&key, 100)
						return pbOperationResult{d: d}
					case "take":
						bundle, d := f.o.TakePendingBodyV1(q, 100)
						return pbOperationResult{bundle, d}
					default:
						return pbOperationResult{d: f.o.ReleasePendingBodyV1(key, 3)}
					}
				}
				closeOwner := func() pbOperationResult { f.o.CloseV1(); return pbOperationResult{} }
				first, second := act, closeOwner
				if closeFirst {
					first, second = closeOwner, act
				}
				a, z := pbOrdered(t, first, second)
				result := a
				if closeFirst {
					result = z
				}
				outcome, candidate := uint8(0), uint8(0)
				if closeFirst {
					outcome, candidate = 1, 1
					if operation == "release" {
						outcome, candidate = 6, 0
					}
				}
				pbDecision(t, "close operation tuple", result.d, outcome, candidate)
				if operation == "request" {
					if closeFirst && q != nil {
						t.Fatal("closed request published a token")
					}
					if !closeFirst && (q == nil || !q.consumed) {
						t.Fatal("Close did not consume the emitted request")
					}
				}
				pbEmpty(t, f.o, "closed custody retained state")
				cxEqual(t, "close actual C2 clear semantics", [3]uint64{f.o.context.bytes, f.o.context.pins, uint64(len(f.o.context.pinned))}, [3]uint64{512, 0, 0})
				if operation == "take" && !closeFirst {
					pbMoved(t, result.bundle, original)
					cxEqual(t, "Close released receiving pin", original.Dependencies[0].released, false)
					pbReleaseProducer(result.bundle)
				} else if operation == "retain" && closeFirst {
					cxEqual(t, "Close refusal moved producer", pbBundleImage(b), pbBundleImage(&original))
					pbReleaseProducer(b)
				} else if !original.Dependencies[0].released || !original.Weak.ended {
					t.Fatal("close did not release ownership")
				}
				wantHistorical := uint64(1)
				if operation == "release" && !closeFirst {
					wantHistorical = 0
				}
				cxEqual(t, "closed historical C1 count", f.o.leases, wantHistorical)
				before := pbImage(f.o)
				f.o.CloseV1()
				pbDecision(t, "post-Close late release", f.o.ReleasePendingBodyV1(key, 6), 6, 0)
				f.o.ExpirePendingBodiesV1(999)
				cxEqual(t, "Close/late cleanup repeated", pbImage(f.o), before)
			})
		}
	}
}

func TestPendingBody148FirstResult(t *testing.T) {
	rows := []struct {
		name string
		outcome uint8
	}{
		{"fixed-before-dependency-excess", 2},
		{"weak-before-dependency-excess", 2},
		{"fixed-before-stale", 2},
		{"weak-before-stale", 2},
		{"in-bound-invalid-handle-before-stale", 2},
		{"dependency-excess-before-invalid-element", 4},
		{"stale-current-before-duplicate", 3},
		{"stale-stored-before-duplicate", 3},
		{"stale-current-before-count", 3},
		{"stale-current-before-bytes", 3},
		{"stale-current-before-dependencies", 3},
		{"stale-stored-before-count", 3},
		{"stale-stored-before-bytes", 3},
		{"stale-stored-before-dependencies", 3},
		{"identity-conflict-before-count", 2},
		{"identity-conflict-before-bytes", 2},
		{"identity-conflict-before-dependencies", 2},
		{"provenance-conflict-before-count", 2},
		{"provenance-conflict-before-bytes", 2},
		{"provenance-conflict-before-dependencies", 2},
		{"duplicate-before-count", 5},
		{"duplicate-before-bytes", 5},
		{"duplicate-before-dependencies", 5},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			l := pbLimits()
			if strings.HasSuffix(row.name, "count") {
				l.MaxCandidates = 1
			}
			if strings.HasSuffix(row.name, "bytes") {
				l.MaxBytes = 272
			}
			if strings.HasSuffix(row.name, "dependencies") {
				l.MaxDependencies = 1
			}
			f := pbNew(t, l)
			first := pbBundle(t, f, 1, 1)
			pbDecision(t, "order live record", f.o.RetainPendingBodyV1(first, 100), 0, 0)
			origin := uint64(2)
			if strings.Contains(row.name, "duplicate") {
				origin = 1
			}
			b := pbBundle(t, f, origin, 2)
			originalPins := slices.Clone(b.Dependencies)
			switch {
			case strings.HasPrefix(row.name, "fixed-"):
				b.Body = nil
			case strings.HasPrefix(row.name, "weak-"):
				b.Weak.completion = 0
			case strings.HasPrefix(row.name, "in-bound-"):
				b.Dependencies = []*HeaderContextLease148V1{nil}
			case strings.HasPrefix(row.name, "dependency-excess-"):
				b.Dependencies = make([]*HeaderContextLease148V1, 9)
			case strings.HasPrefix(row.name, "stale-current-"):
				pbAdvance(t, f, false)
			case strings.HasPrefix(row.name, "stale-stored-"):
				b.View = pbAdvance(t, f, false)
			case strings.HasPrefix(row.name, "identity-conflict-"):
				b.Parent = [32]byte{99}
			case strings.HasPrefix(row.name, "provenance-conflict-"):
				b.Provenance = [32]byte{99}
				b.Weak.provenance = b.Provenance
			}
			if strings.HasSuffix(row.name, "dependency-excess") {
				b.Dependencies = make([]*HeaderContextLease148V1, 9)
			}
			if strings.HasSuffix(row.name, "stale") {
				pbAdvance(t, f, false)
			}
			pbRefuse(t, "pending first-result tuple/"+row.name, f.o, b, 100, row.outcome, 0)
			for _, pin := range originalPins {
				if pin.released || pin.candidate.released {
					t.Fatal("ordered refusal released incoming real pin")
				}
				pin.ReleaseV1()
			}
		})
	}
}

func TestPendingBody148ExternalContextAndLifetime(t *testing.T) {
	l := PendingBodyLimits148V1{3, 1000, 3, 7}
	f := pbNew(t, l)
	genesis := f.o.context.records[f.p.View.Genesis]
	var d HeaderContextDecision148V1
	f.p, d = f.o.RebindContextV1(f.p.View, *cxProof(genesis, HeaderContextCanonical148V1), f.s)
	cxDecision(t, "actual external selected context", d, 0, 0, 0, nil)
	b := pbBundle(t, f, 17, 0)
	cxEqual(t, "valid zero parent", b.Parent, [32]byte{})
	cxEqual(t, "external selected pin does not invent C1", b.Dependencies[0].candidate, (*HeaderCandidateLease148V1)(nil))
	key := pbKey(b)
	l.MaxLifetime = 999
	pbDecision(t, "nondefault external custody", f.o.RetainPendingBodyV1(b, 0), 0, 0)
	cxEqual(t, "captured nondefault lifetime", f.o.pendingBody.records[key].deadline, uint64(7))
	cxEqual(t, "nondefault before deadline", f.o.PendingBodyRetainedV1(key, 6), true)
	cxEqual(t, "nondefault deadline equality", f.o.PendingBodyRetainedV1(key, 7), false)
	pbEmpty(t, f.o, "nondefault external expiry")
	cxEqual(t, "external expiry resource tuple", [2]uint64{f.o.context.pins, f.o.leases}, [2]uint64{})
}

func TestPendingBody148RefusalRetirement(t *testing.T) {
	f := pbNew(t, PendingBodyLimits148V1{1, 271, 1, 10})
	b := pbBundle(t, f, 1, 1)
	pbRefuse(t, "capacity producer preservation", f.o, b, 100, 4, 0)
	_, out := f.o.PrepareV1(hcTr(f.o, nil, f.p.Hash))
	cxEqual(t, "refused producer lease changed retirement", uint8(out), uint8(10))
	pbReleaseProducer(b)
	pub, out := hcPublish(t, f.o, hcTr(f.o, nil, f.p.Hash))
	cxEqual(t, "producer cleanup permits real retirement", uint8(out), uint8(0))
	cxEqual(t, "producer retired exact header", pub.Retired, [][32]byte{f.p.Hash})
	pbEmpty(t, f.o, "refused custody remained empty")
}

func TestPendingBody148MultipleTerminalRecords(t *testing.T) {
	for _, terminal := range []string{"Close", "UnknownExpiry"} {
		t.Run(terminal, func(t *testing.T) {
			f := pbNew(t, pbLimits())
			var pins []*HeaderContextLease148V1
			var weak []*PendingBodyWeak148V1
			for origin := uint64(1); origin <= 2; origin++ {
				b := pbBundle(t, f, origin, uint8(origin))
				pins, weak = append(pins, b.Dependencies[0]), append(weak, b.Weak)
				key := pbKey(b)
				pbDecision(t, "multiple retain", f.o.RetainPendingBodyV1(b, 100), 0, 0)
				q, d := f.o.RequestPendingBodyV1(&key, 100)
				pbDecision(t, "multiple request", d, 0, 0)
				if q == nil {
					t.Fatal("multiple request missing")
				}
			}
			if terminal == "Close" {
				pbOrdered(t, func() pbOperationResult { f.o.CloseV1(); return pbOperationResult{} }, func() pbOperationResult { return pbOperationResult{} })
			} else {
				pbLatch(t, f)
				f.o.ExpirePendingBodiesV1(110)
			}
			pbEmpty(t, f.o, "multiple terminal")
			for i, pin := range pins {
				if !pin.released || !weak[i].ended {
					t.Fatal("terminal did not drain every detached record")
				}
			}
			want := [3]uint64{1725, 0, 0}
			if terminal == "Close" {
				want = [3]uint64{512, 0, 2}
			}
			cxEqual(t, "multiple exact terminal accounting", [3]uint64{f.o.context.bytes, f.o.context.pins, f.o.leases}, want)
		})
	}
}
