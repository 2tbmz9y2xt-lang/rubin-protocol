package node

import (
	"bytes"
	"errors"
	"math"
	"math/big"
	"slices"
	"testing"
	"time"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

var (
	hcSrc1  = [32]byte{1}
	hcSrc2  = [32]byte{2}
	hcProvA = [32]byte{9}
	hcProvB = [32]byte{10}
	hcRoot  = [32]byte{0xEE}
)

func hcLim() HeaderCandidateLimits148V1 {
	return HeaderCandidateLimits148V1{MaxTips: 8, MaxHeaders: 16, MaxRetainedBytes: 1 << 20, MaxTransitionHeaders: 8, MaxSnapshotBytes: 1 << 20, MaxLeases: 8}
}

// hcMk builds a literal qualified record; the hash is derived only to construct the input.
func hcMk(t testing.TB, parent [32]byte, height uint64, work int64, nonce uint64) HeaderCandidateRecord148V1 {
	return hcMkW(t, parent, height, big.NewInt(work), nonce)
}

func hcMkW(t testing.TB, parent [32]byte, height uint64, work *big.Int, nonce uint64) HeaderCandidateRecord148V1 {
	t.Helper()
	raw := consensus.EncodeInitial148Header(consensus.Initial148Header{Version: 1, PrevBlockHash: parent, Timestamp: height, Nonce: nonce})
	h, err := consensus.Initial148BlockHash(raw[:])
	if err != nil {
		t.Fatal(err)
	}
	return HeaderCandidateRecord148V1{Raw: raw, Hash: h, Parent: parent, Height: height, Work: work, Provenance: hcProvA}
}

func hcExt(r HeaderCandidateRecord148V1) HeaderCandidateRecord148V1 { r.External = true; return r }

func hcNew(t testing.TB, lim HeaderCandidateLimits148V1) *HeaderCandidateOwner148V1 {
	t.Helper()
	o, err := NewHeaderCandidateOwner148V1(lim, 7)
	if err != nil {
		t.Fatal(err)
	}
	return o
}

func hcEstablish(t testing.TB, o *HeaderCandidateOwner148V1, recs ...HeaderCandidateRecord148V1) {
	t.Helper()
	if _, out := o.EstablishV1(hcSrc1, recs); out != HeaderCandidateOK148V1 {
		t.Fatalf("establish: %d", out)
	}
}

func hcTr(o *HeaderCandidateOwner148V1, adds []HeaderCandidateRecord148V1, ret ...[32]byte) HeaderCandidateTransition148V1 {
	return HeaderCandidateTransition148V1{ExpectedVersion: o.VersionV1(), ExpectedSource: o.source, Additions: adds, Retired: ret}
}

func hcPublish(t testing.TB, o *HeaderCandidateOwner148V1, tr HeaderCandidateTransition148V1) (HeaderCandidatePublication148V1, HeaderCandidateOutcome148V1) {
	t.Helper()
	h, out := o.PrepareV1(tr)
	if out != HeaderCandidateOK148V1 {
		if h != nil {
			t.Fatal("non-OK prepare returned a handle")
		}
		return HeaderCandidatePublication148V1{}, out
	}
	return h.PublishV1()
}

func hcHashes(rs ...HeaderCandidateRecord148V1) [][32]byte {
	out := make([][32]byte, 0, len(rs))
	for _, r := range rs {
		out = append(out, r.Hash)
	}
	return out
}

// hcEqual compares two hash lists element by element and by length.
func hcEqual(t testing.TB, what string, got, want [][32]byte) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s: len %d want %d", what, len(got), len(want))
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("%s[%d] mismatch", what, i)
		}
	}
}

func hcPresent(o *HeaderCandidateOwner148V1, rs ...HeaderCandidateRecord148V1) []bool {
	out := make([]bool, len(rs))
	for i, r := range rs {
		_, out[i] = o.LookupV1(r.Hash)
	}
	return out
}

type hcSnap struct {
	version uint64
	present []bool
	bytes   uint64
	tips    uint64
	leases  uint64
}

func hcTake(o *HeaderCandidateOwner148V1, rs ...HeaderCandidateRecord148V1) hcSnap {
	o.mu.Lock()
	b, tp, l := o.bytes, o.tips, o.leases
	o.mu.Unlock()
	return hcSnap{o.VersionV1(), hcPresent(o, rs...), b, tp, l}
}

func (s hcSnap) same(u hcSnap) bool {
	return s.version == u.version && slices.Equal(s.present, u.present) && s.bytes == u.bytes && s.tips == u.tips && s.leases == u.leases
}

// hcBase is R0 (External, height 10) <- R1 (height 11), established under hcSrc1.
func hcBase(t testing.TB, lim HeaderCandidateLimits148V1) (*HeaderCandidateOwner148V1, HeaderCandidateRecord148V1, HeaderCandidateRecord148V1) {
	o := hcNew(t, lim)
	r0 := hcExt(hcMk(t, hcRoot, 10, 100, 1))
	r1 := hcMk(t, r0.Hash, 11, 110, 2)
	hcEstablish(t, o, r0, r1)
	return o, r0, r1
}

func TestHeaderCandidate148Classification(t *testing.T) {
	type tc struct {
		name string
		want HeaderCandidateOutcome148V1
		run  func(t *testing.T, o *HeaderCandidateOwner148V1, r0, r1 HeaderCandidateRecord148V1) (HeaderCandidateOutcome148V1, func())
	}
	prep := func(o *HeaderCandidateOwner148V1, tr HeaderCandidateTransition148V1) HeaderCandidateOutcome148V1 {
		h, out := o.PrepareV1(tr)
		if (h == nil) != (out != HeaderCandidateOK148V1) {
			t.Fatalf("handle/outcome mismatch %d", out)
		}
		return out
	}
	latch := func(t *testing.T, o *HeaderCandidateOwner148V1) {
		h, _ := o.PrepareV1(hcTr(o, nil))
		if h.UnknownV1() != HeaderCandidateOK148V1 {
			t.Fatal("unknown")
		}
	}
	lease := func(t *testing.T, o *HeaderCandidateOwner148V1, h [32]byte) {
		if _, out := o.AcquireDependencyV1(h); out != HeaderCandidateOK148V1 {
			t.Fatalf("lease %d", out)
		}
	}
	child := func(t *testing.T, r HeaderCandidateRecord148V1, n uint64) HeaderCandidateRecord148V1 {
		return hcMk(t, r.Hash, r.Height+1, r.Work.Int64()+1, n)
	}
	bad := func(t *testing.T, r1 HeaderCandidateRecord148V1, mut func(*HeaderCandidateRecord148V1)) HeaderCandidateRecord148V1 {
		c := child(t, r1, 50)
		mut(&c)
		return c
	}
	cases := []tc{
		{"row1 closed", HeaderCandidateClosed148V1, func(t *testing.T, o *HeaderCandidateOwner148V1, _, r1 HeaderCandidateRecord148V1) (HeaderCandidateOutcome148V1, func()) {
			o.CloseV1()
			return prep(o, hcTr(o, []HeaderCandidateRecord148V1{child(t, r1, 3)})), nil
		}},
		{"rows1+2 closed wins over latch", HeaderCandidateClosed148V1, func(t *testing.T, o *HeaderCandidateOwner148V1, _, r1 HeaderCandidateRecord148V1) (HeaderCandidateOutcome148V1, func()) {
			latch(t, o)
			o.CloseV1()
			_, out := o.AcquireDependencyV1(r1.Hash)
			return out, nil
		}},
		{"row2 unknown source", HeaderCandidateUnknownSource148V1, func(t *testing.T, o *HeaderCandidateOwner148V1, _, r1 HeaderCandidateRecord148V1) (HeaderCandidateOutcome148V1, func()) {
			latch(t, o)
			_, out := o.AcquireDependencyV1(r1.Hash)
			return out, nil
		}},
		{"rows2+3 latch wins over already established", HeaderCandidateUnknownSource148V1, func(t *testing.T, o *HeaderCandidateOwner148V1, _, _ HeaderCandidateRecord148V1) (HeaderCandidateOutcome148V1, func()) {
			latch(t, o)
			_, out := o.EstablishV1(hcSrc1, nil)
			return out, nil
		}},
		{"row3 already established", HeaderCandidateAlreadyEstablished148V1, func(t *testing.T, o *HeaderCandidateOwner148V1, _, _ HeaderCandidateRecord148V1) (HeaderCandidateOutcome148V1, func()) {
			_, out := o.EstablishV1(hcSrc2, nil)
			return out, nil
		}},
		{"rows3+5 already established wins over invalid", HeaderCandidateAlreadyEstablished148V1, func(t *testing.T, o *HeaderCandidateOwner148V1, _, _ HeaderCandidateRecord148V1) (HeaderCandidateOutcome148V1, func()) {
			_, out := o.EstablishV1([32]byte{}, nil)
			return out, nil
		}},
		{"row4 busy", HeaderCandidateBusy148V1, func(t *testing.T, o *HeaderCandidateOwner148V1, _, r1 HeaderCandidateRecord148V1) (HeaderCandidateOutcome148V1, func()) {
			h, _ := o.PrepareV1(hcTr(o, nil))
			return prep(o, hcTr(o, []HeaderCandidateRecord148V1{child(t, r1, 3)})), func() { h.AbortV1() }
		}},
		{"rows4+5 busy wins over invalid", HeaderCandidateBusy148V1, func(t *testing.T, o *HeaderCandidateOwner148V1, _, r1 HeaderCandidateRecord148V1) (HeaderCandidateOutcome148V1, func()) {
			h, _ := o.PrepareV1(hcTr(o, nil))
			return prep(o, hcTr(o, []HeaderCandidateRecord148V1{bad(t, r1, func(r *HeaderCandidateRecord148V1) { r.Work = nil })})), func() { h.AbortV1() }
		}},
		{"row5 bad hash", HeaderCandidateInvalid148V1, func(t *testing.T, o *HeaderCandidateOwner148V1, _, r1 HeaderCandidateRecord148V1) (HeaderCandidateOutcome148V1, func()) {
			return prep(o, hcTr(o, []HeaderCandidateRecord148V1{bad(t, r1, func(r *HeaderCandidateRecord148V1) { r.Hash[0] ^= 1 })})), nil
		}},
		{"row5 parent mismatch", HeaderCandidateInvalid148V1, func(t *testing.T, o *HeaderCandidateOwner148V1, r0, r1 HeaderCandidateRecord148V1) (HeaderCandidateOutcome148V1, func()) {
			return prep(o, hcTr(o, []HeaderCandidateRecord148V1{bad(t, r1, func(r *HeaderCandidateRecord148V1) { r.Parent = r0.Hash })})), nil
		}},
		{"row5 nonpositive work", HeaderCandidateInvalid148V1, func(t *testing.T, o *HeaderCandidateOwner148V1, _, r1 HeaderCandidateRecord148V1) (HeaderCandidateOutcome148V1, func()) {
			return prep(o, hcTr(o, []HeaderCandidateRecord148V1{bad(t, r1, func(r *HeaderCandidateRecord148V1) { r.Work = big.NewInt(0) })})), nil
		}},
		{"row5 zero provenance", HeaderCandidateInvalid148V1, func(t *testing.T, o *HeaderCandidateOwner148V1, _, r1 HeaderCandidateRecord148V1) (HeaderCandidateOutcome148V1, func()) {
			return prep(o, hcTr(o, []HeaderCandidateRecord148V1{bad(t, r1, func(r *HeaderCandidateRecord148V1) { r.Provenance = [32]byte{} })})), nil
		}},
		{"row5 duplicate addition", HeaderCandidateInvalid148V1, func(t *testing.T, o *HeaderCandidateOwner148V1, _, r1 HeaderCandidateRecord148V1) (HeaderCandidateOutcome148V1, func()) {
			c := child(t, r1, 3)
			return prep(o, hcTr(o, []HeaderCandidateRecord148V1{c, c})), nil
		}},
		{"row5 duplicate retired", HeaderCandidateInvalid148V1, func(t *testing.T, o *HeaderCandidateOwner148V1, r0, _ HeaderCandidateRecord148V1) (HeaderCandidateOutcome148V1, func()) {
			return prep(o, hcTr(o, nil, r0.Hash, r0.Hash)), nil
		}},
		{"row5 hash in both", HeaderCandidateInvalid148V1, func(t *testing.T, o *HeaderCandidateOwner148V1, r0, _ HeaderCandidateRecord148V1) (HeaderCandidateOutcome148V1, func()) {
			return prep(o, hcTr(o, []HeaderCandidateRecord148V1{r0}, r0.Hash)), nil
		}},
		{"row5 addition parent after child", HeaderCandidateInvalid148V1, func(t *testing.T, o *HeaderCandidateOwner148V1, _, r1 HeaderCandidateRecord148V1) (HeaderCandidateOutcome148V1, func()) {
			a := child(t, r1, 3)
			return prep(o, hcTr(o, []HeaderCandidateRecord148V1{child(t, a, 4), a})), nil
		}},
		{"row5 retired parent after child", HeaderCandidateInvalid148V1, func(t *testing.T, o *HeaderCandidateOwner148V1, r0, r1 HeaderCandidateRecord148V1) (HeaderCandidateOutcome148V1, func()) {
			return prep(o, hcTr(o, nil, r1.Hash, r0.Hash)), nil
		}},
		{"row5 too long", HeaderCandidateInvalid148V1, func(t *testing.T, o *HeaderCandidateOwner148V1, r0, r1 HeaderCandidateRecord148V1) (HeaderCandidateOutcome148V1, func()) {
			return prep(o, hcTr(o, make([]HeaderCandidateRecord148V1, 8), r0.Hash)), nil
		}},
		{"row5 establish zero source", HeaderCandidateInvalid148V1, func(t *testing.T, _ *HeaderCandidateOwner148V1, _, _ HeaderCandidateRecord148V1) (HeaderCandidateOutcome148V1, func()) {
			_, out := hcNew(t, hcLim()).EstablishV1([32]byte{}, nil)
			return out, nil
		}},
		{"rows5+6 invalid wins over stale", HeaderCandidateInvalid148V1, func(t *testing.T, o *HeaderCandidateOwner148V1, _, r1 HeaderCandidateRecord148V1) (HeaderCandidateOutcome148V1, func()) {
			tr := hcTr(o, []HeaderCandidateRecord148V1{bad(t, r1, func(r *HeaderCandidateRecord148V1) { r.Work = nil })})
			tr.ExpectedVersion++
			return prep(o, tr), nil
		}},
		{"row6 stale version", HeaderCandidateStale148V1, func(t *testing.T, o *HeaderCandidateOwner148V1, _, r1 HeaderCandidateRecord148V1) (HeaderCandidateOutcome148V1, func()) {
			tr := hcTr(o, []HeaderCandidateRecord148V1{child(t, r1, 3)})
			tr.ExpectedVersion++
			return prep(o, tr), nil
		}},
		{"row6 stale source", HeaderCandidateStale148V1, func(t *testing.T, o *HeaderCandidateOwner148V1, _, r1 HeaderCandidateRecord148V1) (HeaderCandidateOutcome148V1, func()) {
			tr := hcTr(o, []HeaderCandidateRecord148V1{child(t, r1, 3)})
			tr.ExpectedSource = hcSrc2
			return prep(o, tr), nil
		}},
		{"rows6+7 stale wins over conflict", HeaderCandidateStale148V1, func(t *testing.T, o *HeaderCandidateOwner148V1, _, r1 HeaderCandidateRecord148V1) (HeaderCandidateOutcome148V1, func()) {
			c := r1
			c.Work = big.NewInt(999)
			tr := hcTr(o, []HeaderCandidateRecord148V1{c})
			tr.ExpectedSource = hcSrc2
			return prep(o, tr), nil
		}},
		{"row7 same hash different work", HeaderCandidateConflict148V1, func(t *testing.T, o *HeaderCandidateOwner148V1, _, r1 HeaderCandidateRecord148V1) (HeaderCandidateOutcome148V1, func()) {
			c := r1
			c.Work = big.NewInt(999)
			return prep(o, hcTr(o, []HeaderCandidateRecord148V1{c})), nil
		}},
		{"row7 same hash different height", HeaderCandidateConflict148V1, func(t *testing.T, o *HeaderCandidateOwner148V1, _, r1 HeaderCandidateRecord148V1) (HeaderCandidateOutcome148V1, func()) {
			c := r1
			c.Height++
			return prep(o, hcTr(o, []HeaderCandidateRecord148V1{c})), nil
		}},
		{"row7 parent height", HeaderCandidateConflict148V1, func(t *testing.T, o *HeaderCandidateOwner148V1, _, r1 HeaderCandidateRecord148V1) (HeaderCandidateOutcome148V1, func()) {
			return prep(o, hcTr(o, []HeaderCandidateRecord148V1{hcMk(t, r1.Hash, r1.Height+2, 200, 3)})), nil
		}},
		{"row7 height zero under present parent", HeaderCandidateConflict148V1, func(t *testing.T, o *HeaderCandidateOwner148V1, _, r1 HeaderCandidateRecord148V1) (HeaderCandidateOutcome148V1, func()) {
			return prep(o, hcTr(o, []HeaderCandidateRecord148V1{hcMk(t, r1.Hash, 0, 200, 3)})), nil
		}},
		{"rows7+8 conflict wins over missing parent", HeaderCandidateConflict148V1, func(t *testing.T, o *HeaderCandidateOwner148V1, _, r1 HeaderCandidateRecord148V1) (HeaderCandidateOutcome148V1, func()) {
			orphan := hcMk(t, [32]byte{0x55}, 5, 50, 3)
			return prep(o, hcTr(o, []HeaderCandidateRecord148V1{orphan, hcMk(t, r1.Hash, r1.Height+2, 200, 4)})), nil
		}},
		{"row8 missing parent", HeaderCandidateMissingParent148V1, func(t *testing.T, o *HeaderCandidateOwner148V1, _, _ HeaderCandidateRecord148V1) (HeaderCandidateOutcome148V1, func()) {
			return prep(o, hcTr(o, []HeaderCandidateRecord148V1{hcMk(t, [32]byte{0x55}, 5, 50, 3)})), nil
		}},
		{"row8 parent retired by the same transition", HeaderCandidateMissingParent148V1, func(t *testing.T, o *HeaderCandidateOwner148V1, r0, _ HeaderCandidateRecord148V1) (HeaderCandidateOutcome148V1, func()) {
			return prep(o, hcTr(o, []HeaderCandidateRecord148V1{hcMk(t, r0.Hash, 11, 120, 3)}, r0.Hash)), nil
		}},
		{"rows8+9 missing parent wins over no coverage", HeaderCandidateMissingParent148V1, func(t *testing.T, o *HeaderCandidateOwner148V1, _, _ HeaderCandidateRecord148V1) (HeaderCandidateOutcome148V1, func()) {
			return prep(o, hcTr(o, []HeaderCandidateRecord148V1{hcMk(t, [32]byte{0x55}, 5, 50, 3)}, [32]byte{0x66})), nil
		}},
		{"row9 retired absent", HeaderCandidateNoCoverage148V1, func(t *testing.T, o *HeaderCandidateOwner148V1, _, _ HeaderCandidateRecord148V1) (HeaderCandidateOutcome148V1, func()) {
			return prep(o, hcTr(o, nil, [32]byte{0x66})), nil
		}},
		{"row9 retired parent still present", HeaderCandidateNoCoverage148V1, func(t *testing.T, o *HeaderCandidateOwner148V1, _, r1 HeaderCandidateRecord148V1) (HeaderCandidateOutcome148V1, func()) {
			return prep(o, hcTr(o, nil, r1.Hash)), nil
		}},
		{"rows9+10 no coverage wins over protected", HeaderCandidateNoCoverage148V1, func(t *testing.T, o *HeaderCandidateOwner148V1, _, r1 HeaderCandidateRecord148V1) (HeaderCandidateOutcome148V1, func()) {
			lease(t, o, r1.Hash)
			return prep(o, hcTr(o, nil, r1.Hash)), nil
		}},
		{"row10 retired leased ancestor", HeaderCandidateProtected148V1, func(t *testing.T, o *HeaderCandidateOwner148V1, r0, r1 HeaderCandidateRecord148V1) (HeaderCandidateOutcome148V1, func()) {
			lease(t, o, r1.Hash)
			return prep(o, hcTr(o, nil, r0.Hash)), nil
		}},
		{"row10 retired leased hash", HeaderCandidateProtected148V1, func(t *testing.T, o *HeaderCandidateOwner148V1, r0, _ HeaderCandidateRecord148V1) (HeaderCandidateOutcome148V1, func()) {
			lease(t, o, r0.Hash)
			return prep(o, hcTr(o, nil, r0.Hash)), nil
		}},
		{"rows10+11 protected wins over exhausted", HeaderCandidateProtected148V1, func(t *testing.T, o *HeaderCandidateOwner148V1, r0, r1 HeaderCandidateRecord148V1) (HeaderCandidateOutcome148V1, func()) {
			lease(t, o, r1.Hash)
			o.version.Store(math.MaxUint64)
			return prep(o, hcTr(o, nil, r0.Hash)), nil
		}},
		{"row11 exhausted", HeaderCandidateVersionExhausted148V1, func(t *testing.T, o *HeaderCandidateOwner148V1, _, r1 HeaderCandidateRecord148V1) (HeaderCandidateOutcome148V1, func()) {
			o.version.Store(math.MaxUint64)
			return prep(o, hcTr(o, []HeaderCandidateRecord148V1{child(t, r1, 3)})), nil
		}},
		{"rows11+12 exhausted wins over capacity", HeaderCandidateVersionExhausted148V1, func(t *testing.T, o *HeaderCandidateOwner148V1, _, r1 HeaderCandidateRecord148V1) (HeaderCandidateOutcome148V1, func()) {
			o.version.Store(math.MaxUint64)
			o.limits.MaxHeaders = 2
			return prep(o, hcTr(o, []HeaderCandidateRecord148V1{child(t, r1, 3)})), nil
		}},
		{"row12 capacity", HeaderCandidateCapacity148V1, func(t *testing.T, o *HeaderCandidateOwner148V1, _, r1 HeaderCandidateRecord148V1) (HeaderCandidateOutcome148V1, func()) {
			o.limits.MaxHeaders = 2
			return prep(o, hcTr(o, []HeaderCandidateRecord148V1{child(t, r1, 3)})), nil
		}},
		{"row3 not established prepare", HeaderCandidateNotEstablished148V1, func(t *testing.T, _ *HeaderCandidateOwner148V1, _, _ HeaderCandidateRecord148V1) (HeaderCandidateOutcome148V1, func()) {
			o := hcNew(t, hcLim())
			return prep(o, HeaderCandidateTransition148V1{ExpectedVersion: 1}), nil
		}},
		{"row3 not established lease", HeaderCandidateNotEstablished148V1, func(t *testing.T, _ *HeaderCandidateOwner148V1, _, r1 HeaderCandidateRecord148V1) (HeaderCandidateOutcome148V1, func()) {
			_, out := hcNew(t, hcLim()).AcquireDependencyV1(r1.Hash)
			return out, nil
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			o, r0, r1 := hcBase(t, hcLim())
			before := hcTake(o, r0, r1)
			got, cleanup := c.run(t, o, r0, r1)
			if got != c.want {
				t.Fatalf("outcome %d want %d", got, c.want)
			}
			// The refusal leaves membership, charges and tips as established; the version moved only by the
			// case's own setup (UnknownV1 latch or a forced maximum).
			after := hcTake(o, r0, r1)
			if !o.closed && (!slices.Equal(after.present, before.present) || after.bytes != before.bytes || after.tips != before.tips) {
				t.Fatalf("refusal changed state: %+v -> %+v", before, after)
			}
			if v := after.version; v != before.version && v != before.version+1 && v != math.MaxUint64 {
				t.Fatalf("version %d from %d", v, before.version)
			}
			if cleanup != nil {
				cleanup()
			}
		})
	}
}

func TestHeaderCandidate148Constructor(t *testing.T) {
	fields := []func(*HeaderCandidateLimits148V1) *uint64{
		func(l *HeaderCandidateLimits148V1) *uint64 { return &l.MaxTips },
		func(l *HeaderCandidateLimits148V1) *uint64 { return &l.MaxHeaders },
		func(l *HeaderCandidateLimits148V1) *uint64 { return &l.MaxRetainedBytes },
		func(l *HeaderCandidateLimits148V1) *uint64 { return &l.MaxTransitionHeaders },
		func(l *HeaderCandidateLimits148V1) *uint64 { return &l.MaxSnapshotBytes },
		func(l *HeaderCandidateLimits148V1) *uint64 { return &l.MaxLeases },
	}
	for i, f := range fields {
		for _, v := range []uint64{0, math.MaxUint64} {
			l := hcLim()
			*f(&l) = v
			if o, err := NewHeaderCandidateOwner148V1(l, 1); o != nil || !errors.Is(err, ErrHeaderCandidateConfig148V1) {
				t.Fatalf("field %d value %d accepted", i, v)
			}
		}
		l := hcLim()
		*f(&l) = math.MaxUint64 - 1
		if _, err := NewHeaderCandidateOwner148V1(l, 1); err != nil {
			t.Fatalf("field %d max-1 refused", i)
		}
	}
	if o, err := NewHeaderCandidateOwner148V1(hcLim(), 0); o != nil || !errors.Is(err, ErrHeaderCandidateConfig148V1) {
		t.Fatal("incarnation zero accepted")
	}
	o := hcNew(t, hcLim())
	if o.IncarnationV1() != 7 || o.VersionV1() != 1 {
		t.Fatal("new owner identity")
	}
	cur, rel := o.ProtectV1(1)
	if cur || rel == nil {
		t.Fatal("not-established owner protected current")
	}
	rel()
}

func TestHeaderCandidate148Limits(t *testing.T) {
	// Base: tips 1, headers 2 (works 100 and 110, one byte each). A sibling of R1 with work 65536 (three bytes) makes
	// tips 2, headers 3, bytes 3*252+1+1+3.
	for _, c := range []struct {
		name string
		set  func(*HeaderCandidateLimits148V1, uint64)
		fit  uint64
	}{
		{"tips", func(l *HeaderCandidateLimits148V1, v uint64) { l.MaxTips = v }, 2},
		{"headers", func(l *HeaderCandidateLimits148V1, v uint64) { l.MaxHeaders = v }, 3},
		{"bytes", func(l *HeaderCandidateLimits148V1, v uint64) { l.MaxRetainedBytes = v }, 3*252 + 1 + 1 + 3},
	} {
		for _, short := range []bool{false, true} {
			o, r0, r1 := hcBase(t, hcLim())
			v := c.fit
			if short {
				v--
			}
			c.set(&o.limits, v)
			// The lease leaves no lawful replacement victim, so one unit short is a plain capacity refusal.
			if _, out := o.AcquireDependencyV1(r1.Hash); out != HeaderCandidateOK148V1 {
				t.Fatal("lease")
			}
			sib := hcMk(t, r0.Hash, 11, 65536, 30)
			_, out := hcPublish(t, o, hcTr(o, []HeaderCandidateRecord148V1{sib}))
			want := HeaderCandidateOK148V1
			if short {
				want = HeaderCandidateCapacity148V1
			}
			if out != want {
				t.Fatalf("%s short=%v: %d", c.name, short, out)
			}
		}
	}
	o, _, r1 := hcBase(t, hcLim())
	o.limits.MaxTransitionHeaders = 2
	a := hcMk(t, r1.Hash, 12, 120, 31)
	b := hcMk(t, a.Hash, 13, 130, 32)
	c := hcMk(t, b.Hash, 14, 140, 33)
	if _, out := o.PrepareV1(hcTr(o, []HeaderCandidateRecord148V1{a, b, c})); out != HeaderCandidateInvalid148V1 {
		t.Fatalf("over transition: %d", out)
	}
	h, out := o.PrepareV1(hcTr(o, []HeaderCandidateRecord148V1{a, b}))
	if out != HeaderCandidateOK148V1 {
		t.Fatalf("exact transition: %d", out)
	}
	if h.AbortV1() != HeaderCandidateOK148V1 {
		t.Fatal("abort")
	}
	l := hcLim()
	l.MaxTransitionHeaders = 2
	e := hcNew(t, l)
	r0 := hcExt(hcMk(t, hcRoot, 10, 100, 1))
	e1 := hcMk(t, r0.Hash, 11, 110, 2)
	if _, out := e.EstablishV1(hcSrc1, []HeaderCandidateRecord148V1{r0, e1, hcMk(t, e1.Hash, 12, 120, 3)}); out != HeaderCandidateInvalid148V1 || e.established || e.VersionV1() != 1 {
		t.Fatalf("over establish: %d", out)
	}
	if _, out := e.EstablishV1(hcSrc1, []HeaderCandidateRecord148V1{r0, e1}); out != HeaderCandidateOK148V1 || e.VersionV1() != 2 {
		t.Fatalf("exact establish: %d", out)
	}
	o.limits.MaxLeases = 2
	for i := 0; i < 2; i++ {
		if _, out := o.AcquireDependencyV1(r1.Hash); out != HeaderCandidateOK148V1 {
			t.Fatalf("lease %d: %d", i, out)
		}
	}
	if l, out := o.AcquireDependencyV1(r1.Hash); out != HeaderCandidateCapacity148V1 || l != nil {
		t.Fatalf("lease over: %d", out)
	}
}

func TestHeaderCandidate148Receipts(t *testing.T) {
	o, r0, r1 := hcBase(t, hcLim())
	v := o.VersionV1()
	cur, rel := o.ProtectV1(v)
	if !cur {
		t.Fatal("not current")
	}
	rel()
	rel()
	upd := r1
	upd.Provenance = hcProvB
	rec, out := hcPublish(t, o, hcTr(o, []HeaderCandidateRecord148V1{upd}))
	if out != HeaderCandidateOK148V1 || !rec.Changed || rec.Version != v+1 || o.VersionV1() != v+1 {
		t.Fatalf("provenance update: %d %+v", out, rec)
	}
	hcEqual(t, "prov added", rec.Added, nil)
	hcEqual(t, "prov retired", rec.Retired, nil)
	cur, rel = o.ProtectV1(v)
	if cur {
		t.Fatal("prior version still current")
	}
	rel()
	if got, _ := o.LookupV1(r1.Hash); got.Provenance != hcProvB {
		t.Fatal("provenance not applied")
	}
	n := hcMk(t, r1.Hash, 12, 120, 40)
	rec, _ = hcPublish(t, o, hcTr(o, []HeaderCandidateRecord148V1{upd, n}))
	hcEqual(t, "D,N added", rec.Added, hcHashes(n))
	n1 := hcMk(t, n.Hash, 13, 130, 41)
	n2 := hcMk(t, n1.Hash, 14, 140, 42)
	rec, _ = hcPublish(t, o, hcTr(o, []HeaderCandidateRecord148V1{n1, upd, n2}))
	hcEqual(t, "N1,D,N2 added", rec.Added, hcHashes(n1, n2))
	v = o.VersionV1()
	rec, out = hcPublish(t, o, hcTr(o, []HeaderCandidateRecord148V1{n}))
	if out != HeaderCandidateOK148V1 || rec.Changed || rec.Version != v || o.VersionV1() != v || len(rec.Added) != 0 || len(rec.Retired) != 0 {
		t.Fatalf("duplicate: %+v", rec)
	}
	tr := hcTr(o, nil, r0.Hash)
	tr.NewSource = hcSrc2
	rec, out = hcPublish(t, o, tr)
	if out != HeaderCandidateOK148V1 || !rec.Changed || rec.Version != v+1 || o.source != hcSrc2 {
		t.Fatalf("retire+source: %d %+v", out, rec)
	}
	hcEqual(t, "retired", rec.Retired, hcHashes(r0))
	if _, ok := o.LookupV1(r0.Hash); ok {
		t.Fatal("retired still present")
	}
	if _, ok := o.LookupV1(r1.Hash); !ok {
		t.Fatal("surviving lowest-received header lost")
	}
}

// hcCapFixture: R0 <- S <- {A(5), B(6)}, R0 <- I <- A2(4), R0 <- K(50).
func hcCapFixture(t testing.TB, lim HeaderCandidateLimits148V1) (*HeaderCandidateOwner148V1, map[string]HeaderCandidateRecord148V1) {
	o := hcNew(t, hcLim())
	r := map[string]HeaderCandidateRecord148V1{}
	r["R0"] = hcExt(hcMk(t, hcRoot, 10, 10, 1))
	r["S"] = hcMk(t, r["R0"].Hash, 11, 11, 2)
	r["A"] = hcMk(t, r["S"].Hash, 12, 5, 3)
	r["B"] = hcMk(t, r["S"].Hash, 12, 6, 4)
	r["I"] = hcMk(t, r["R0"].Hash, 11, 11, 5)
	r["A2"] = hcMk(t, r["I"].Hash, 12, 4, 6)
	r["K"] = hcMk(t, r["R0"].Hash, 11, 50, 7)
	hcEstablish(t, o, r["R0"], r["S"], r["A"], r["B"], r["I"], r["A2"], r["K"])
	o.limits = lim
	return o, r
}

func TestHeaderCandidate148Capacity(t *testing.T) {
	lim := hcLim()
	lim.MaxHeaders = 7
	ext := func(t *testing.T, o *HeaderCandidateOwner148V1, r map[string]HeaderCandidateRecord148V1, want ...[32]byte) {
		t.Helper()
		n := hcMk(t, r["K"].Hash, 12, 60, 8)
		rec, out := hcPublish(t, o, hcTr(o, []HeaderCandidateRecord148V1{n}))
		if out != HeaderCandidateOK148V1 {
			t.Fatalf("%d", out)
		}
		hcEqual(t, "added", rec.Added, hcHashes(n))
		hcEqual(t, "retired", rec.Retired, want)
		for _, h := range want {
			if _, ok := o.LookupV1(h); ok {
				t.Fatal("victim still present")
			}
		}
	}
	t.Run("weakest victim with exclusive ancestry", func(t *testing.T) {
		o, r := hcCapFixture(t, lim)
		ext(t, o, r, r["A2"].Hash, r["I"].Hash)
		if p := hcPresent(o, r["S"], r["A"], r["B"], r["R0"]); slices.Contains(p, false) {
			t.Fatal("surviving path lost")
		}
	})
	t.Run("leased interior skips whole candidate", func(t *testing.T) {
		o, r := hcCapFixture(t, lim)
		if _, out := o.AcquireDependencyV1(r["I"].Hash); out != HeaderCandidateOK148V1 {
			t.Fatal("lease")
		}
		ext(t, o, r, r["A"].Hash)
	})
	t.Run("leased tip skipped then two victims share an ancestor", func(t *testing.T) {
		l := lim
		l.MaxHeaders = 5
		o, r := hcCapFixture(t, l)
		if _, out := o.AcquireDependencyV1(r["A2"].Hash); out != HeaderCandidateOK148V1 {
			t.Fatal("lease")
		}
		ext(t, o, r, r["A"].Hash, r["B"].Hash, r["S"].Hash)
	})
	t.Run("stops at first fit", func(t *testing.T) {
		l := lim
		l.MaxHeaders = 16
		l.MaxTips = 4
		o, r := hcCapFixture(t, l)
		n := hcMk(t, r["R0"].Hash, 11, 60, 8)
		rec, out := hcPublish(t, o, hcTr(o, []HeaderCandidateRecord148V1{n}))
		if out != HeaderCandidateOK148V1 {
			t.Fatalf("%d", out)
		}
		hcEqual(t, "retired", rec.Retired, hcHashes(r["A2"], r["I"]))
	})
	t.Run("weak new tip refuses", func(t *testing.T) {
		o, r := hcCapFixture(t, lim)
		before := hcTake(o, r["A"], r["A2"], r["I"])
		w := hcMk(t, r["K"].Hash, 12, 1, 8)
		z := hcMk(t, r["K"].Hash, 12, 100, 9)
		if _, out := hcPublish(t, o, hcTr(o, []HeaderCandidateRecord148V1{w, z})); out != HeaderCandidateCapacity148V1 {
			t.Fatalf("%d", out)
		}
		if !before.same(hcTake(o, r["A"], r["A2"], r["I"])) {
			t.Fatal("refusal changed state")
		}
	})
	t.Run("all protected refuses", func(t *testing.T) {
		o, r := hcCapFixture(t, lim)
		for _, k := range []string{"A", "B", "A2"} {
			if _, out := o.AcquireDependencyV1(r[k].Hash); out != HeaderCandidateOK148V1 {
				t.Fatal("lease")
			}
		}
		before := hcTake(o, r["A"], r["A2"], r["I"])
		if _, out := hcPublish(t, o, hcTr(o, []HeaderCandidateRecord148V1{hcMk(t, r["K"].Hash, 12, 60, 8)})); out != HeaderCandidateCapacity148V1 {
			t.Fatalf("%d", out)
		}
		if !before.same(hcTake(o, r["A"], r["A2"], r["I"])) {
			t.Fatal("refusal changed state")
		}
	})
	t.Run("no new qualified tip refuses", func(t *testing.T) {
		o := hcNew(t, hcLim())
		p := hcExt(hcMk(t, [32]byte{0x44}, 9, 9, 98))
		c := hcExt(hcMk(t, p.Hash, 10, 10, 97))
		hcEstablish(t, o, c)
		o.limits.MaxHeaders = 1
		if _, out := hcPublish(t, o, hcTr(o, []HeaderCandidateRecord148V1{p})); out != HeaderCandidateCapacity148V1 {
			t.Fatalf("%d", out)
		}
	})
	t.Run("duplicate at capacity is a no-op", func(t *testing.T) {
		o, r := hcCapFixture(t, lim)
		v := o.VersionV1()
		rec, out := hcPublish(t, o, hcTr(o, []HeaderCandidateRecord148V1{r["A"]}))
		if out != HeaderCandidateOK148V1 || rec.Changed || o.VersionV1() != v {
			t.Fatalf("%d %+v", out, rec)
		}
	})
}

// TestHeaderCandidate148Order covers X4: equal-work opposite hash order, work wider than 256 bits and identical
// victim order across 64 fresh owners.
func TestHeaderCandidate148Order(t *testing.T) {
	wide := new(big.Int).Lsh(big.NewInt(1), 300)
	root := hcExt(hcMk(t, hcRoot, 10, 10, 1))
	t1 := hcMkW(t, root.Hash, 11, wide, 2)
	t2 := hcMkW(t, root.Hash, 11, wide, 3)
	larger, smaller := t1, t2
	if bytes.Compare(t1.Hash[:], t2.Hash[:]) < 0 {
		larger, smaller = t2, t1
	}
	strong := hcMkW(t, root.Hash, 11, new(big.Int).Add(wide, big.NewInt(1)), 4)
	for i := 0; i < 64; i++ {
		lim := hcLim()
		lim.MaxTips = 2
		o := hcNew(t, lim)
		hcEstablish(t, o, root, t1, t2)
		rec, out := hcPublish(t, o, hcTr(o, []HeaderCandidateRecord148V1{strong}))
		if out != HeaderCandidateOK148V1 {
			t.Fatalf("owner %d: %d", i, out)
		}
		hcEqual(t, "retired", rec.Retired, hcHashes(larger))
		if _, ok := o.LookupV1(smaller.Hash); !ok {
			t.Fatal("smaller-hash tip retired")
		}
		if o.bytes != 253+2*290 {
			t.Fatalf("bytes %d", o.bytes)
		}
	}
}

// TestHeaderCandidate148Canonical covers V5: promotions for more blocks than MaxHeaders retire covered prefixes.
func TestHeaderCandidate148Canonical(t *testing.T) {
	lim := hcLim()
	lim.MaxHeaders = 3
	o := hcNew(t, lim)
	prev := hcExt(hcMk(t, hcRoot, 10, 10, 1))
	tip := hcMk(t, prev.Hash, 11, 11, 2)
	hcEstablish(t, o, prev, tip)
	for i := uint64(0); i < 3*lim.MaxHeaders; i++ {
		next := hcMk(t, tip.Hash, tip.Height+1, tip.Work.Int64()+1, 100+i)
		rec, out := hcPublish(t, o, hcTr(o, []HeaderCandidateRecord148V1{next}, prev.Hash))
		if out != HeaderCandidateOK148V1 {
			t.Fatalf("step %d: %d", i, out)
		}
		hcEqual(t, "retired", rec.Retired, hcHashes(prev))
		prev, tip = tip, next
		if p := hcPresent(o, prev, tip); slices.Contains(p, false) || o.tips != 1 || len(o.recs) != 2 {
			t.Fatalf("step %d lost the surviving path", i)
		}
	}
}

// TestHeaderCandidate148WorkingSets covers the V8 D8 and D9 inputs and V7.
func TestHeaderCandidate148WorkingSets(t *testing.T) {
	// D8: current {R}, R's Parent P not received.
	p := hcExt(hcMk(t, hcRoot, 9, 9, 1))
	r := hcExt(hcMk(t, p.Hash, 10, 10, 2))
	newR := func() *HeaderCandidateOwner148V1 {
		o := hcNew(t, hcLim())
		hcEstablish(t, o, r)
		return o
	}
	o := newR()
	y := hcExt(hcMk(t, r.Hash, r.Height+2, 30, 3))
	if _, out := hcPublish(t, o, hcTr(o, []HeaderCandidateRecord148V1{y}, r.Hash)); out != HeaderCandidateConflict148V1 {
		t.Fatalf("D8 conflict: %d", out)
	}
	y = hcExt(hcMk(t, r.Hash, r.Height+1, 30, 3))
	if _, out := hcPublish(t, o, hcTr(o, []HeaderCandidateRecord148V1{y}, r.Hash)); out != HeaderCandidateOK148V1 {
		t.Fatalf("D8 ok: %d", out)
	}
	o = newR()
	if _, out := hcPublish(t, o, hcTr(o, []HeaderCandidateRecord148V1{p}, r.Hash)); out != HeaderCandidateNoCoverage148V1 {
		t.Fatalf("D8 no coverage: %d", out)
	}
	// D9: P and H admitted, P retired by a covered publication; H re-added identical with External false.
	o = hcNew(t, hcLim())
	h := hcMk(t, p.Hash, 10, 10, 4)
	hcEstablish(t, o, p, h)
	if _, out := hcPublish(t, o, hcTr(o, nil, p.Hash)); out != HeaderCandidateOK148V1 {
		t.Fatalf("retire P: %d", out)
	}
	v := o.VersionV1()
	rec, out := hcPublish(t, o, hcTr(o, []HeaderCandidateRecord148V1{h}))
	if out != HeaderCandidateOK148V1 || rec.Changed || o.VersionV1() != v {
		t.Fatalf("D9 identical: %d %+v", out, rec)
	}
	if got, _ := o.LookupV1(h.Hash); got.External {
		t.Fatal("External recomputed")
	}
	k := hcMk(t, h.Hash, 11, 11, 5)
	rec, out = hcPublish(t, o, hcTr(o, []HeaderCandidateRecord148V1{h, k}))
	if out != HeaderCandidateOK148V1 || !rec.Changed || rec.Version != v+1 {
		t.Fatalf("D9 with child: %d", out)
	}
	hcEqual(t, "D9 added", rec.Added, hcHashes(k))
	// V7: before anchor loss the producer re-adds the required suffix in one transition, or gets Capacity first.
	o = hcNew(t, hcLim())
	hcEstablish(t, o, hcExt(h))
	if _, out := hcPublish(t, o, hcTr(o, []HeaderCandidateRecord148V1{p})); out != HeaderCandidateOK148V1 {
		t.Fatalf("V7 re-add: %d", out)
	}
	o.limits.MaxHeaders = 2
	o2 := hcNew(t, hcLim())
	hcEstablish(t, o2, hcExt(h))
	o2.limits.MaxHeaders = 1
	if _, out := hcPublish(t, o2, hcTr(o2, []HeaderCandidateRecord148V1{p})); out != HeaderCandidateCapacity148V1 {
		t.Fatalf("V7 capacity: %d", out)
	}
	if _, ok := o2.LookupV1(h.Hash); !ok {
		t.Fatal("V7 dropped the surviving branch")
	}
}

// TestHeaderCandidate148Leases covers X2, D6 and V3.
func TestHeaderCandidate148Leases(t *testing.T) {
	o, r0, r1 := hcBase(t, hcLim())
	if _, out := o.AcquireDependencyV1([32]byte{0x77}); out != HeaderCandidateMissing148V1 {
		t.Fatal("missing")
	}
	h, out := o.PrepareV1(hcTr(o, nil, r0.Hash))
	if out != HeaderCandidateOK148V1 {
		t.Fatalf("prepare: %d", out)
	}
	for _, x := range [][32]byte{r0.Hash, r1.Hash} {
		if l, out := o.AcquireDependencyV1(x); out != HeaderCandidateProtected148V1 || l != nil {
			t.Fatalf("lease on planned removal: %d", out)
		}
	}
	if h.AbortV1() != HeaderCandidateOK148V1 {
		t.Fatal("abort")
	}
	l, out := o.AcquireDependencyV1(r1.Hash)
	if out != HeaderCandidateOK148V1 {
		t.Fatalf("lease after abort: %d", out)
	}
	v := o.VersionV1()
	var dst [148]byte
	if !o.Header148V1(r0.Hash, &dst) || dst != r0.Raw || o.VersionV1() != v {
		t.Fatal("V3 read changed version")
	}
	if _, out := hcPublish(t, o, hcTr(o, nil, r0.Hash)); out != HeaderCandidateProtected148V1 {
		t.Fatalf("leased path retired: %d", out)
	}
	l.ReleaseV1()
	l.ReleaseV1()
	if o.leases != 0 || o.VersionV1() != v {
		t.Fatal("release changed state")
	}
	h, _ = o.PrepareV1(hcTr(o, nil, r0.Hash))
	if _, out := o.AcquireDependencyV1(r1.Hash); out != HeaderCandidateProtected148V1 {
		t.Fatal("surviving tip over planned Retired")
	}
	if _, out := h.PublishV1(); out != HeaderCandidateOK148V1 {
		t.Fatal("publish")
	}
	if _, out := o.AcquireDependencyV1(r1.Hash); out != HeaderCandidateOK148V1 {
		t.Fatal("lease after publish")
	}
	// A lease survives a version advance.
	n := hcMk(t, r1.Hash, 12, 120, 9)
	if _, out := hcPublish(t, o, hcTr(o, []HeaderCandidateRecord148V1{n})); out != HeaderCandidateOK148V1 || o.leases != 1 {
		t.Fatal("lease lost on version advance")
	}
}

// TestHeaderCandidate148Aliasing covers R2 for points and LookupV1 and R3 zero allocation on over-length input.
func TestHeaderCandidate148Aliasing(t *testing.T) {
	o, r0, r1 := hcBase(t, hcLim())
	var dst [148]byte
	if !o.Header148V1(r1.Hash, &dst) {
		t.Fatal("present")
	}
	kept := dst
	if _, out := hcPublish(t, o, hcTr(o, []HeaderCandidateRecord148V1{hcMk(t, r1.Hash, 12, 120, 9)}, r0.Hash)); out != HeaderCandidateOK148V1 {
		t.Fatal("publish")
	}
	if dst != kept {
		t.Fatal("dst written after return")
	}
	dst[0] ^= 1
	var again [148]byte
	if !o.Header148V1(r1.Hash, &again) || again != r1.Raw {
		t.Fatal("dst aliased provider state")
	}
	if o.Header148V1(r0.Hash, &again) {
		t.Fatal("retired header present")
	}
	got, _ := o.LookupV1(r1.Hash)
	got.Work.SetInt64(1)
	if got2, _ := o.LookupV1(r1.Hash); got2.Work.Cmp(r1.Work) != 0 {
		t.Fatal("LookupV1 Work aliased")
	}
	// R3: a transition longer than MaxTransitionHeaders allocates nothing. The input also holds a duplicate and a
	// parent-after-child order so a set check placed before the length check would allocate.
	c := hcMk(t, r1.Hash, 12, 120, 9)
	long := hcTr(o, []HeaderCandidateRecord148V1{hcMk(t, c.Hash, 13, 130, 10), c, c, c, c, c, c, c, c})
	if a := testing.AllocsPerRun(50, func() {
		if h, out := o.PrepareV1(long); out != HeaderCandidateInvalid148V1 || h != nil {
			t.Fatal("over-length accepted")
		}
	}); a != 0 {
		t.Fatalf("allocs %v", a)
	}
}

func hcWithin(t *testing.T, what string, f func()) {
	t.Helper()
	done := make(chan struct{})
	go func() { f(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("%s did not return", what)
	}
}

func hcBlocked(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
		t.Fatal("returned while a guard was held")
	case <-time.After(50 * time.Millisecond):
	}
}

// TestHeaderCandidate148Faults covers X1, X5, V10, R4 and R5.
func TestHeaderCandidate148Faults(t *testing.T) {
	t.Run("abort then publish", func(t *testing.T) {
		o, r0, r1 := hcBase(t, hcLim())
		n := hcMk(t, r1.Hash, 12, 120, 9)
		tr := hcTr(o, []HeaderCandidateRecord148V1{n})
		before := hcTake(o, r0, r1, n)
		h, _ := o.PrepareV1(tr)
		if h.AbortV1() != HeaderCandidateOK148V1 || !before.same(hcTake(o, r0, r1, n)) {
			t.Fatal("abort changed state")
		}
		for _, c := range []HeaderCandidateOutcome148V1{h.AbortV1(), h.UnknownV1()} {
			if c != HeaderCandidateConsumed148V1 {
				t.Fatal("second handle call")
			}
		}
		if _, out := h.PublishV1(); out != HeaderCandidateConsumed148V1 || !before.same(hcTake(o, r0, r1, n)) {
			t.Fatal("consumed publish")
		}
		h, _ = o.PrepareV1(tr)
		if _, out := h.PublishV1(); out != HeaderCandidateOK148V1 || !hcPresent(o, n)[0] {
			t.Fatal("publish")
		}
		after := hcTake(o, r0, r1, n)
		if _, out := h.PublishV1(); out != HeaderCandidateConsumed148V1 || !after.same(hcTake(o, r0, r1, n)) {
			t.Fatal("second publish")
		}
	})
	t.Run("stale guard holds publication", func(t *testing.T) {
		o, _, r1 := hcBase(t, hcLim())
		v := o.VersionV1()
		if _, out := hcPublish(t, o, hcTr(o, []HeaderCandidateRecord148V1{hcMk(t, r1.Hash, 12, 120, 9)})); out != HeaderCandidateOK148V1 {
			t.Fatal("publish")
		}
		cur, rel := o.ProtectV1(v)
		if cur {
			t.Fatal("stale guard current")
		}
		h, _ := o.PrepareV1(hcTr(o, []HeaderCandidateRecord148V1{hcMk(t, r1.Hash, 12, 121, 10)}))
		done := make(chan struct{})
		go func() { h.PublishV1(); close(done) }()
		hcBlocked(t, done)
		// R5: shared reads and guards return while the publication waits.
		hcWithin(t, "reads under waiting publish", func() {
			c2, r2 := o.ProtectV1(o.VersionV1())
			var dst [148]byte
			o.Header148V1(r1.Hash, &dst)
			o.LookupV1(r1.Hash)
			if l, out := o.AcquireDependencyV1(r1.Hash); out == HeaderCandidateOK148V1 {
				l.ReleaseV1()
			}
			_ = c2
			r2()
		})
		rel()
		rel()
		hcWithin(t, "publish after release", func() { <-done })
		// The second release was a no-op: a later state-changing publication still proceeds.
		hcWithin(t, "publish after double release", func() {
			if _, out := hcPublish(t, o, hcTr(o, []HeaderCandidateRecord148V1{hcMk(t, r1.Hash, 12, 122, 11)})); out != HeaderCandidateOK148V1 {
				t.Errorf("later publish: %d", out)
			}
		})
	})
	t.Run("unknown latch", func(t *testing.T) {
		o, r0, r1 := hcBase(t, hcLim())
		n := hcMk(t, r1.Hash, 12, 120, 9)
		h, _ := o.PrepareV1(hcTr(o, []HeaderCandidateRecord148V1{n}, r0.Hash))
		v := o.VersionV1()
		if h.UnknownV1() != HeaderCandidateOK148V1 || o.VersionV1() != v+1 {
			t.Fatal("unknown")
		}
		if p := hcPresent(o, r0, r1, n); !p[0] || !p[1] || p[2] {
			t.Fatal("unknown applied membership")
		}
		if cur, rel := o.ProtectV1(o.VersionV1()); cur || rel == nil {
			t.Fatal("latched protect current")
		} else {
			rel()
		}
		if _, out := o.PrepareV1(hcTr(o, nil)); out != HeaderCandidateUnknownSource148V1 {
			t.Fatal("prepare after latch")
		}
		if _, out := o.EstablishV1(hcSrc1, nil); out != HeaderCandidateUnknownSource148V1 {
			t.Fatal("establish after latch")
		}
		if _, out := o.AcquireDependencyV1(r1.Hash); out != HeaderCandidateUnknownSource148V1 {
			t.Fatal("lease after latch")
		}
		if h.UnknownV1() != HeaderCandidateConsumed148V1 {
			t.Fatal("second unknown")
		}
	})
	t.Run("unknown waits for guard on changed-false and at maximum version", func(t *testing.T) {
		for _, max := range []bool{false, true} {
			o, _, _ := hcBase(t, hcLim())
			if max {
				o.version.Store(math.MaxUint64)
			}
			h, out := o.PrepareV1(hcTr(o, nil))
			if out != HeaderCandidateOK148V1 || h.plan.changed {
				t.Fatalf("prepare changed-false: %d", out)
			}
			v := o.VersionV1()
			cur, rel := o.ProtectV1(v)
			if !cur {
				t.Fatal("guard not current")
			}
			done := make(chan HeaderCandidateOutcome148V1, 1)
			go func() { done <- h.UnknownV1() }()
			time.Sleep(50 * time.Millisecond)
			if o.VersionV1() != v || o.latched {
				t.Fatal("unknown applied under guard")
			}
			rel()
			if <-done != HeaderCandidateOK148V1 || !o.latched {
				t.Fatal("unknown after release")
			}
			want := v + 1
			if max {
				want = math.MaxUint64
			}
			if o.VersionV1() != want {
				t.Fatalf("version %d", o.VersionV1())
			}
		}
	})
	t.Run("close wakes blocked calls", func(t *testing.T) {
		for _, kind := range []string{"publish", "unknown", "establish"} {
			o, r0, r1 := hcBase(t, hcLim())
			var h *HeaderCandidatePrepared148V1
			if kind == "establish" {
				o = hcNew(t, hcLim())
			} else {
				h, _ = o.PrepareV1(hcTr(o, []HeaderCandidateRecord148V1{hcMk(t, r1.Hash, 12, 120, 9)}))
			}
			v := o.VersionV1()
			_, rel := o.ProtectV1(v)
			done := make(chan HeaderCandidateOutcome148V1, 1)
			go func() {
				switch kind {
				case "publish":
					_, out := h.PublishV1()
					done <- out
				case "unknown":
					done <- h.UnknownV1()
				default:
					_, out := o.EstablishV1(hcSrc1, []HeaderCandidateRecord148V1{r0})
					done <- out
				}
			}()
			time.Sleep(50 * time.Millisecond)
			o.CloseV1()
			select {
			case out := <-done:
				if out != HeaderCandidateClosed148V1 {
					t.Fatalf("%s: %d", kind, out)
				}
			case <-time.After(5 * time.Second):
				t.Fatalf("%s not woken", kind)
			}
			if h != nil {
				if _, out := h.PublishV1(); out != HeaderCandidateConsumed148V1 {
					t.Fatal("handle not consumed")
				}
			}
			rel()
			if o.VersionV1() != v || o.latched || (kind == "establish" && o.established) {
				t.Fatalf("%s applied after close", kind)
			}
		}
	})
	t.Run("close with handle guard and lease outstanding", func(t *testing.T) {
		o, r0, r1 := hcBase(t, hcLim())
		l, _ := o.AcquireDependencyV1(r1.Hash)
		h, _ := o.PrepareV1(hcTr(o, nil))
		_, rel := o.ProtectV1(o.VersionV1())
		v := o.VersionV1()
		o.CloseV1()
		if cur, rel2 := o.ProtectV1(v); cur || rel2 == nil {
			t.Fatal("closed protect current")
		} else {
			rel2()
		}
		rel()
		l.ReleaseV1()
		if h.AbortV1() != HeaderCandidateClosed148V1 || h.AbortV1() != HeaderCandidateConsumed148V1 {
			t.Fatal("closed handle")
		}
		var dst [148]byte
		if o.Header148V1(r0.Hash, &dst) || o.VersionV1() != v {
			t.Fatal("closed reads")
		}
		if got, ok := o.LookupV1(r0.Hash); ok || got.Work != nil {
			t.Fatal("closed lookup")
		}
		for _, out := range []HeaderCandidateOutcome148V1{
			func() HeaderCandidateOutcome148V1 { _, o2 := o.PrepareV1(hcTr(o, nil)); return o2 }(),
			func() HeaderCandidateOutcome148V1 { _, o2 := o.EstablishV1(hcSrc1, nil); return o2 }(),
			func() HeaderCandidateOutcome148V1 { _, o2 := o.AcquireDependencyV1(r1.Hash); return o2 }(),
		} {
			if out != HeaderCandidateClosed148V1 {
				t.Fatalf("mutator after close: %d", out)
			}
		}
	})
	t.Run("concurrent establish", func(t *testing.T) {
		o := hcNew(t, hcLim())
		r0 := hcExt(hcMk(t, hcRoot, 10, 100, 1))
		_, rel := o.ProtectV1(1)
		res := make(chan HeaderCandidateOutcome148V1, 2)
		for i := 0; i < 2; i++ {
			go func() { _, out := o.EstablishV1(hcSrc1, []HeaderCandidateRecord148V1{r0}); res <- out }()
		}
		time.Sleep(50 * time.Millisecond)
		rel()
		a, b := <-res, <-res
		okFirst := a == HeaderCandidateOK148V1 && b == HeaderCandidateAlreadyEstablished148V1
		okSecond := b == HeaderCandidateOK148V1 && a == HeaderCandidateAlreadyEstablished148V1
		if (!okFirst && !okSecond) || o.VersionV1() != 2 {
			t.Fatalf("concurrent establish %d %d", a, b)
		}
	})
}

// TestHeaderCandidate148Race covers E6 under go test -race: concurrent publishers, guards, leases and readers.
func TestHeaderCandidate148Race(t *testing.T) {
	o, _, r1 := hcBase(t, hcLim())
	stop := make(chan struct{})
	doneReaders := make(chan struct{}, 3)
	for i := 0; i < 3; i++ {
		go func() {
			defer func() { doneReaders <- struct{}{} }()
			for {
				select {
				case <-stop:
					return
				default:
				}
				_, rel := o.ProtectV1(o.VersionV1())
				var dst [148]byte
				o.Header148V1(r1.Hash, &dst)
				o.LookupV1(r1.Hash)
				if l, out := o.AcquireDependencyV1(r1.Hash); out == HeaderCandidateOK148V1 {
					l.ReleaseV1()
				}
				rel()
			}
		}()
	}
	parent := r1
	for i := uint64(0); i < 12; i++ {
		n := hcMk(t, parent.Hash, parent.Height+1, parent.Work.Int64()+1, 1000+i)
		var out HeaderCandidateOutcome148V1
		for out = HeaderCandidateStale148V1; out == HeaderCandidateStale148V1; {
			_, out = hcPublish(t, o, hcTr(o, []HeaderCandidateRecord148V1{n}))
		}
		if out != HeaderCandidateOK148V1 {
			t.Fatalf("publish %d: %d", i, out)
		}
		parent = n
	}
	close(stop)
	for i := 0; i < 3; i++ {
		<-doneReaders
	}
}
