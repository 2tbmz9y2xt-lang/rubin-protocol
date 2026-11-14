package node

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"math/big"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
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

// hcHeaders is hcLim with MaxHeaders n, fixed at construction as production fixes it.
func hcHeaders(n uint64) HeaderCandidateLimits148V1 {
	l := hcLim()
	l.MaxHeaders = n
	return l
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
	o.mu.Lock()
	src := o.source
	o.mu.Unlock()
	return HeaderCandidateTransition148V1{ExpectedVersion: o.VersionV1(), ExpectedSource: src, Additions: adds, Retired: ret}
}

func hcPublish(t testing.TB, o *HeaderCandidateOwner148V1, tr HeaderCandidateTransition148V1) (HeaderCandidatePublication148V1, HeaderCandidateOutcome148V1) {
	t.Helper()
	before := hcInnerOf(o)
	h, out := o.PrepareV1(tr)
	if out != HeaderCandidateOK148V1 {
		if h != nil || hcInnerOf(o) != before {
			t.Fatal("non-OK prepare returned a handle or changed state")
		}
		return HeaderCandidatePublication148V1{}, out
	}
	// Bounded: a guard left counted by a faulty release fails here instead of hanging the test goroutine.
	var pub HeaderCandidatePublication148V1
	done := make(chan struct{})
	go func() { pub, out = h.PublishV1(); close(done) }()
	select {
	case <-done:
		return pub, out
	case <-time.After(5 * time.Second):
		t.Fatal("PublishV1 did not return")
		return HeaderCandidatePublication148V1{}, HeaderCandidateClosed148V1
	}
}

// hcReads renders VersionV1 and, for each record, every LookupV1 field and the Header148V1 result, so a V3 trigger can
// be compared before and after on the same owner.
func hcReads(o *HeaderCandidateOwner148V1, rs ...HeaderCandidateRecord148V1) string {
	var b strings.Builder
	fmt.Fprintf(&b, "v%d", o.VersionV1())
	for _, r := range rs {
		got, ok := o.LookupV1(r.Hash)
		var dst [148]byte
		hok := o.Header148V1(r.Hash, &dst)
		fmt.Fprintf(&b, "|%v %x %x %x %d %s %x %v %v %x", ok, got.Raw, got.Hash, got.Parent, got.Height, got.Work, got.Provenance, got.External, hok, dst)
	}
	return b.String()
}

// hcGuard takes a guard and fails before any cleanup registration when the release is nil.
func hcGuard(t testing.TB, o *HeaderCandidateOwner148V1, v uint64) (bool, func()) {
	t.Helper()
	cur, rel := o.ProtectV1(v)
	if rel == nil {
		t.Fatal("ProtectV1 returned a nil release")
	}
	return cur, rel
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
	b, tp, l := hcRecsBytes(o.recs), o.tips, o.leases
	o.mu.Unlock()
	return hcSnap{o.VersionV1(), hcPresent(o, rs...), b, tp, l}
}

func (s hcSnap) same(u hcSnap) bool {
	return s.version == u.version && slices.Equal(s.present, u.present) && s.bytes == u.bytes && s.tips == u.tips && s.leases == u.leases
}

// hcRecsBytes is the retained charge of a membership from the contract formula, 252 plus the minimal big-endian Work
// length per record, derived independently of the provider's own charge.
func hcRecsBytes(m map[[32]byte]*hcEntry) uint64 {
	var n uint64
	for _, e := range m {
		n += 252 + uint64((e.rec.Work.BitLen()+7)/8)
	}
	return n
}

func hcHeldBytes(o *HeaderCandidateOwner148V1) uint64 {
	o.mu.Lock()
	defer o.mu.Unlock()
	return hcRecsBytes(o.recs)
}

// hcBase is R0 (External, height 10) <- R1 (height 11), established under hcSrc1.
func hcBase(t testing.TB, lim HeaderCandidateLimits148V1) (*HeaderCandidateOwner148V1, HeaderCandidateRecord148V1, HeaderCandidateRecord148V1) {
	o := hcNew(t, lim)
	r0 := hcExt(hcMk(t, hcRoot, 10, 100, 1))
	r1 := hcMk(t, r0.Hash, 11, 110, 2)
	hcEstablish(t, o, r0, r1)
	return o, r0, r1
}

// hcInner is the complete comparable owner state a refusal must leave unchanged: scalars and counters, every stored
// record field with its charge, child counts, per-hash lease counts, guards and the prepared slot.
type hcInner struct {
	version, tips, leases, guards uint64
	headers                       int
	members, kids, leased         string
	established, latched, closed  bool
	source                        [32]byte
	prepared                      *HeaderCandidatePrepared148V1
}

func hcInnerOf(o *HeaderCandidateOwner148V1) hcInner {
	o.mu.Lock()
	defer o.mu.Unlock()
	recs := make([]string, 0, len(o.recs))
	for h, e := range o.recs {
		r := e.rec
		recs = append(recs, fmt.Sprintf("%x|%x|%x|%d|%s|%x|%v|%d", h, r.Raw, r.Parent, r.Height, r.Work, r.Provenance, r.External, e.charge))
	}
	slices.Sort(recs)
	return hcInner{o.version.Load(), o.tips, o.leases, o.guards, len(o.recs), strings.Join(recs, ","), hcCounts(o.kids), hcCounts(o.leased), o.established, o.latched, o.closed, o.source, o.prepared}
}

func hcCounts(m map[[32]byte]uint64) string {
	s := make([]string, 0, len(m))
	for h, n := range m {
		s = append(s, fmt.Sprintf("%x=%d", h, n))
	}
	slices.Sort(s)
	return strings.Join(s, ",")
}

// hcPrepOK and hcLeaseOK are for calls whose result the test then uses: any non-OK outcome fails at the call.
func hcPrepOK(t testing.TB, o *HeaderCandidateOwner148V1, tr HeaderCandidateTransition148V1) *HeaderCandidatePrepared148V1 {
	t.Helper()
	h, out := o.PrepareV1(tr)
	if out != HeaderCandidateOK148V1 || h == nil {
		t.Fatalf("prepare: %d", out)
	}
	return h
}

func hcLeaseOK(t testing.TB, o *HeaderCandidateOwner148V1, hash [32]byte) *HeaderCandidateLease148V1 {
	t.Helper()
	l, out := o.AcquireDependencyV1(hash)
	if out != HeaderCandidateOK148V1 || l == nil {
		t.Fatalf("lease: %d", out)
	}
	return l
}

// Each refused call goes through one of these wrappers: it snapshots the owner right before the call and asserts
// that the refusal returned the zero value of its other result and changed no owner state, version included.
func hcPrep(t *testing.T, o *HeaderCandidateOwner148V1, tr HeaderCandidateTransition148V1) HeaderCandidateOutcome148V1 {
	t.Helper()
	before := hcInnerOf(o)
	h, out := o.PrepareV1(tr)
	if out != HeaderCandidateOK148V1 && (h != nil || hcInnerOf(o) != before) {
		t.Fatalf("refused PrepareV1 %d returned a handle or changed state", out)
	}
	return out
}

func hcAcq(t *testing.T, o *HeaderCandidateOwner148V1, hash [32]byte) HeaderCandidateOutcome148V1 {
	t.Helper()
	before := hcInnerOf(o)
	l, out := o.AcquireDependencyV1(hash)
	if out != HeaderCandidateOK148V1 && (l != nil || hcInnerOf(o) != before) {
		t.Fatalf("refused AcquireDependencyV1 %d returned a lease or changed state", out)
	}
	return out
}

func hcEst(t *testing.T, o *HeaderCandidateOwner148V1, source [32]byte, recs []HeaderCandidateRecord148V1) HeaderCandidateOutcome148V1 {
	t.Helper()
	before := hcInnerOf(o)
	p, out := o.EstablishV1(source, recs)
	zero := !p.Changed && p.Version == 0 && p.Added == nil && p.Retired == nil
	if out != HeaderCandidateOK148V1 && (!zero || hcInnerOf(o) != before) {
		t.Fatalf("refused EstablishV1 %d returned %+v or changed state", out, p)
	}
	return out
}

func TestHeaderCandidate148Classification(t *testing.T) {
	type tc struct {
		name string
		want HeaderCandidateOutcome148V1
		run  func(t *testing.T, o *HeaderCandidateOwner148V1, r0, r1 HeaderCandidateRecord148V1) (HeaderCandidateOutcome148V1, func())
	}
	prep, acq := hcPrep, hcAcq
	est := func(t *testing.T, o *HeaderCandidateOwner148V1, source [32]byte) HeaderCandidateOutcome148V1 {
		return hcEst(t, o, source, nil)
	}
	latch := func(t *testing.T, o *HeaderCandidateOwner148V1) {
		if hcPrepOK(t, o, hcTr(o, nil)).UnknownV1() != HeaderCandidateOK148V1 {
			t.Fatal("unknown")
		}
	}
	lease := func(t *testing.T, o *HeaderCandidateOwner148V1, h [32]byte) { hcLeaseOK(t, o, h) }
	estRecs := func(t *testing.T, recs ...HeaderCandidateRecord148V1) HeaderCandidateOutcome148V1 {
		return hcEst(t, hcNew(t, hcHeaders(2)), hcSrc1, recs)
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
			return prep(t, o, hcTr(o, []HeaderCandidateRecord148V1{child(t, r1, 3)})), nil
		}},
		{"rows1+2 closed wins over latch", HeaderCandidateClosed148V1, func(t *testing.T, o *HeaderCandidateOwner148V1, _, r1 HeaderCandidateRecord148V1) (HeaderCandidateOutcome148V1, func()) {
			latch(t, o)
			o.CloseV1()
			return acq(t, o, r1.Hash), nil
		}},
		{"row2 unknown source", HeaderCandidateUnknownSource148V1, func(t *testing.T, o *HeaderCandidateOwner148V1, _, r1 HeaderCandidateRecord148V1) (HeaderCandidateOutcome148V1, func()) {
			latch(t, o)
			return acq(t, o, r1.Hash), nil
		}},
		{"rows2+3 latch wins over already established", HeaderCandidateUnknownSource148V1, func(t *testing.T, o *HeaderCandidateOwner148V1, _, _ HeaderCandidateRecord148V1) (HeaderCandidateOutcome148V1, func()) {
			latch(t, o)
			return est(t, o, hcSrc1), nil
		}},
		{"row3 already established", HeaderCandidateAlreadyEstablished148V1, func(t *testing.T, o *HeaderCandidateOwner148V1, _, _ HeaderCandidateRecord148V1) (HeaderCandidateOutcome148V1, func()) {
			return est(t, o, hcSrc2), nil
		}},
		{"rows3+5 already established wins over invalid", HeaderCandidateAlreadyEstablished148V1, func(t *testing.T, o *HeaderCandidateOwner148V1, _, _ HeaderCandidateRecord148V1) (HeaderCandidateOutcome148V1, func()) {
			return est(t, o, [32]byte{}), nil
		}},
		{"row4 busy", HeaderCandidateBusy148V1, func(t *testing.T, o *HeaderCandidateOwner148V1, _, r1 HeaderCandidateRecord148V1) (HeaderCandidateOutcome148V1, func()) {
			h := hcPrepOK(t, o, hcTr(o, nil))
			return prep(t, o, hcTr(o, []HeaderCandidateRecord148V1{child(t, r1, 3)})), func() { h.AbortV1() }
		}},
		{"rows4+5 busy wins over invalid", HeaderCandidateBusy148V1, func(t *testing.T, o *HeaderCandidateOwner148V1, _, r1 HeaderCandidateRecord148V1) (HeaderCandidateOutcome148V1, func()) {
			h := hcPrepOK(t, o, hcTr(o, nil))
			return prep(t, o, hcTr(o, []HeaderCandidateRecord148V1{bad(t, r1, func(r *HeaderCandidateRecord148V1) { r.Work = nil })})), func() { h.AbortV1() }
		}},
		{"row5 bad hash", HeaderCandidateInvalid148V1, func(t *testing.T, o *HeaderCandidateOwner148V1, _, r1 HeaderCandidateRecord148V1) (HeaderCandidateOutcome148V1, func()) {
			return prep(t, o, hcTr(o, []HeaderCandidateRecord148V1{bad(t, r1, func(r *HeaderCandidateRecord148V1) { r.Hash[0] ^= 1 })})), nil
		}},
		{"row5 parent mismatch", HeaderCandidateInvalid148V1, func(t *testing.T, o *HeaderCandidateOwner148V1, r0, r1 HeaderCandidateRecord148V1) (HeaderCandidateOutcome148V1, func()) {
			return prep(t, o, hcTr(o, []HeaderCandidateRecord148V1{bad(t, r1, func(r *HeaderCandidateRecord148V1) { r.Parent = r0.Hash })})), nil
		}},
		{"row5 nonpositive work", HeaderCandidateInvalid148V1, func(t *testing.T, o *HeaderCandidateOwner148V1, _, r1 HeaderCandidateRecord148V1) (HeaderCandidateOutcome148V1, func()) {
			return prep(t, o, hcTr(o, []HeaderCandidateRecord148V1{bad(t, r1, func(r *HeaderCandidateRecord148V1) { r.Work = big.NewInt(0) })})), nil
		}},
		{"row5 negative work", HeaderCandidateInvalid148V1, func(t *testing.T, o *HeaderCandidateOwner148V1, _, r1 HeaderCandidateRecord148V1) (HeaderCandidateOutcome148V1, func()) {
			return prep(t, o, hcTr(o, []HeaderCandidateRecord148V1{bad(t, r1, func(r *HeaderCandidateRecord148V1) { r.Work = big.NewInt(-1) })})), nil
		}},
		{"row5 zero provenance", HeaderCandidateInvalid148V1, func(t *testing.T, o *HeaderCandidateOwner148V1, _, r1 HeaderCandidateRecord148V1) (HeaderCandidateOutcome148V1, func()) {
			return prep(t, o, hcTr(o, []HeaderCandidateRecord148V1{bad(t, r1, func(r *HeaderCandidateRecord148V1) { r.Provenance = [32]byte{} })})), nil
		}},
		{"row5 duplicate addition", HeaderCandidateInvalid148V1, func(t *testing.T, o *HeaderCandidateOwner148V1, _, r1 HeaderCandidateRecord148V1) (HeaderCandidateOutcome148V1, func()) {
			c := child(t, r1, 3)
			return prep(t, o, hcTr(o, []HeaderCandidateRecord148V1{c, c})), nil
		}},
		{"row5 duplicate retired", HeaderCandidateInvalid148V1, func(t *testing.T, o *HeaderCandidateOwner148V1, r0, _ HeaderCandidateRecord148V1) (HeaderCandidateOutcome148V1, func()) {
			return prep(t, o, hcTr(o, nil, r0.Hash, r0.Hash)), nil
		}},
		{"row5 hash in both", HeaderCandidateInvalid148V1, func(t *testing.T, o *HeaderCandidateOwner148V1, r0, _ HeaderCandidateRecord148V1) (HeaderCandidateOutcome148V1, func()) {
			return prep(t, o, hcTr(o, []HeaderCandidateRecord148V1{r0}, r0.Hash)), nil
		}},
		{"row5 addition parent after child", HeaderCandidateInvalid148V1, func(t *testing.T, o *HeaderCandidateOwner148V1, _, r1 HeaderCandidateRecord148V1) (HeaderCandidateOutcome148V1, func()) {
			a := child(t, r1, 3)
			return prep(t, o, hcTr(o, []HeaderCandidateRecord148V1{child(t, a, 4), a})), nil
		}},
		{"row5 retired parent after child", HeaderCandidateInvalid148V1, func(t *testing.T, o *HeaderCandidateOwner148V1, r0, r1 HeaderCandidateRecord148V1) (HeaderCandidateOutcome148V1, func()) {
			return prep(t, o, hcTr(o, nil, r1.Hash, r0.Hash)), nil
		}},
		{"row5 too long", HeaderCandidateInvalid148V1, func(t *testing.T, o *HeaderCandidateOwner148V1, r0, r1 HeaderCandidateRecord148V1) (HeaderCandidateOutcome148V1, func()) {
			// Eight otherwise valid additions plus one Retired exceed MaxTransitionHeaders 8.
			return prep(t, o, hcTr(o, hcChain(t, r1, 8), r0.Hash)), nil
		}},
		{"row5 establish zero source", HeaderCandidateInvalid148V1, func(t *testing.T, _ *HeaderCandidateOwner148V1, _, _ HeaderCandidateRecord148V1) (HeaderCandidateOutcome148V1, func()) {
			return est(t, hcNew(t, hcLim()), [32]byte{}), nil
		}},
		{"rows5+6 invalid wins over stale", HeaderCandidateInvalid148V1, func(t *testing.T, o *HeaderCandidateOwner148V1, _, r1 HeaderCandidateRecord148V1) (HeaderCandidateOutcome148V1, func()) {
			tr := hcTr(o, []HeaderCandidateRecord148V1{bad(t, r1, func(r *HeaderCandidateRecord148V1) { r.Work = nil })})
			tr.ExpectedVersion++
			return prep(t, o, tr), nil
		}},
		{"row6 stale version", HeaderCandidateStale148V1, func(t *testing.T, o *HeaderCandidateOwner148V1, _, r1 HeaderCandidateRecord148V1) (HeaderCandidateOutcome148V1, func()) {
			tr := hcTr(o, []HeaderCandidateRecord148V1{child(t, r1, 3)})
			tr.ExpectedVersion++
			return prep(t, o, tr), nil
		}},
		{"row6 stale source", HeaderCandidateStale148V1, func(t *testing.T, o *HeaderCandidateOwner148V1, _, r1 HeaderCandidateRecord148V1) (HeaderCandidateOutcome148V1, func()) {
			tr := hcTr(o, []HeaderCandidateRecord148V1{child(t, r1, 3)})
			tr.ExpectedSource = hcSrc2
			return prep(t, o, tr), nil
		}},
		{"rows6+7 stale wins over conflict", HeaderCandidateStale148V1, func(t *testing.T, o *HeaderCandidateOwner148V1, _, r1 HeaderCandidateRecord148V1) (HeaderCandidateOutcome148V1, func()) {
			c := r1
			c.Work = big.NewInt(999)
			tr := hcTr(o, []HeaderCandidateRecord148V1{c})
			tr.ExpectedSource = hcSrc2
			return prep(t, o, tr), nil
		}},
		{"row7 same hash different work", HeaderCandidateConflict148V1, func(t *testing.T, o *HeaderCandidateOwner148V1, _, r1 HeaderCandidateRecord148V1) (HeaderCandidateOutcome148V1, func()) {
			c := r1
			c.Work = big.NewInt(999)
			return prep(t, o, hcTr(o, []HeaderCandidateRecord148V1{c})), nil
		}},
		{"row7 same hash different height", HeaderCandidateConflict148V1, func(t *testing.T, o *HeaderCandidateOwner148V1, _, r1 HeaderCandidateRecord148V1) (HeaderCandidateOutcome148V1, func()) {
			c := r1
			c.Height++
			return prep(t, o, hcTr(o, []HeaderCandidateRecord148V1{c})), nil
		}},
		{"row7 parent height", HeaderCandidateConflict148V1, func(t *testing.T, o *HeaderCandidateOwner148V1, _, r1 HeaderCandidateRecord148V1) (HeaderCandidateOutcome148V1, func()) {
			return prep(t, o, hcTr(o, []HeaderCandidateRecord148V1{hcMk(t, r1.Hash, r1.Height+2, 200, 3)})), nil
		}},
		{"row7 height zero under present parent", HeaderCandidateConflict148V1, func(t *testing.T, o *HeaderCandidateOwner148V1, _, r1 HeaderCandidateRecord148V1) (HeaderCandidateOutcome148V1, func()) {
			return prep(t, o, hcTr(o, []HeaderCandidateRecord148V1{hcMk(t, r1.Hash, 0, 200, 3)})), nil
		}},
		{"rows7+8 conflict wins over missing parent", HeaderCandidateConflict148V1, func(t *testing.T, o *HeaderCandidateOwner148V1, _, r1 HeaderCandidateRecord148V1) (HeaderCandidateOutcome148V1, func()) {
			orphan := hcMk(t, [32]byte{0x55}, 5, 50, 3)
			return prep(t, o, hcTr(o, []HeaderCandidateRecord148V1{orphan, hcMk(t, r1.Hash, r1.Height+2, 200, 4)})), nil
		}},
		{"row8 missing parent", HeaderCandidateMissingParent148V1, func(t *testing.T, o *HeaderCandidateOwner148V1, _, _ HeaderCandidateRecord148V1) (HeaderCandidateOutcome148V1, func()) {
			return prep(t, o, hcTr(o, []HeaderCandidateRecord148V1{hcMk(t, [32]byte{0x55}, 5, 50, 3)})), nil
		}},
		{"row8 parent retired by the same transition", HeaderCandidateMissingParent148V1, func(t *testing.T, o *HeaderCandidateOwner148V1, r0, _ HeaderCandidateRecord148V1) (HeaderCandidateOutcome148V1, func()) {
			return prep(t, o, hcTr(o, []HeaderCandidateRecord148V1{hcMk(t, r0.Hash, 11, 120, 3)}, r0.Hash)), nil
		}},
		{"rows8+9 missing parent wins over no coverage", HeaderCandidateMissingParent148V1, func(t *testing.T, o *HeaderCandidateOwner148V1, _, _ HeaderCandidateRecord148V1) (HeaderCandidateOutcome148V1, func()) {
			return prep(t, o, hcTr(o, []HeaderCandidateRecord148V1{hcMk(t, [32]byte{0x55}, 5, 50, 3)}, [32]byte{0x66})), nil
		}},
		{"row9 retired absent", HeaderCandidateNoCoverage148V1, func(t *testing.T, o *HeaderCandidateOwner148V1, _, _ HeaderCandidateRecord148V1) (HeaderCandidateOutcome148V1, func()) {
			return prep(t, o, hcTr(o, nil, [32]byte{0x66})), nil
		}},
		{"row9 retired parent still present", HeaderCandidateNoCoverage148V1, func(t *testing.T, o *HeaderCandidateOwner148V1, _, r1 HeaderCandidateRecord148V1) (HeaderCandidateOutcome148V1, func()) {
			return prep(t, o, hcTr(o, nil, r1.Hash)), nil
		}},
		{"rows9+10 no coverage wins over protected", HeaderCandidateNoCoverage148V1, func(t *testing.T, o *HeaderCandidateOwner148V1, _, r1 HeaderCandidateRecord148V1) (HeaderCandidateOutcome148V1, func()) {
			lease(t, o, r1.Hash)
			return prep(t, o, hcTr(o, nil, r1.Hash)), nil
		}},
		{"row10 retired leased ancestor", HeaderCandidateProtected148V1, func(t *testing.T, o *HeaderCandidateOwner148V1, r0, r1 HeaderCandidateRecord148V1) (HeaderCandidateOutcome148V1, func()) {
			lease(t, o, r1.Hash)
			return prep(t, o, hcTr(o, nil, r0.Hash)), nil
		}},
		{"row10 retired leased hash", HeaderCandidateProtected148V1, func(t *testing.T, o *HeaderCandidateOwner148V1, r0, _ HeaderCandidateRecord148V1) (HeaderCandidateOutcome148V1, func()) {
			lease(t, o, r0.Hash)
			return prep(t, o, hcTr(o, nil, r0.Hash)), nil
		}},
		{"rows10+11 protected wins over exhausted", HeaderCandidateProtected148V1, func(t *testing.T, o *HeaderCandidateOwner148V1, r0, r1 HeaderCandidateRecord148V1) (HeaderCandidateOutcome148V1, func()) {
			lease(t, o, r1.Hash)
			o.version.Store(math.MaxUint64)
			return prep(t, o, hcTr(o, nil, r0.Hash)), nil
		}},
		{"row11 exhausted", HeaderCandidateVersionExhausted148V1, func(t *testing.T, o *HeaderCandidateOwner148V1, _, r1 HeaderCandidateRecord148V1) (HeaderCandidateOutcome148V1, func()) {
			o.version.Store(math.MaxUint64)
			return prep(t, o, hcTr(o, []HeaderCandidateRecord148V1{child(t, r1, 3)})), nil
		}},
		{"rows11+12 exhausted wins over capacity", HeaderCandidateVersionExhausted148V1, func(t *testing.T, _ *HeaderCandidateOwner148V1, _, _ HeaderCandidateRecord148V1) (HeaderCandidateOutcome148V1, func()) {
			o, _, r1 := hcBase(t, hcHeaders(2))
			o.version.Store(math.MaxUint64)
			return prep(t, o, hcTr(o, []HeaderCandidateRecord148V1{child(t, r1, 3)})), nil
		}},
		{"row12 capacity", HeaderCandidateCapacity148V1, func(t *testing.T, _ *HeaderCandidateOwner148V1, _, _ HeaderCandidateRecord148V1) (HeaderCandidateOutcome148V1, func()) {
			o, _, r1 := hcBase(t, hcHeaders(2))
			return prep(t, o, hcTr(o, []HeaderCandidateRecord148V1{child(t, r1, 3)})), nil
		}},
		{"row7 establish parent height", HeaderCandidateConflict148V1, func(t *testing.T, _ *HeaderCandidateOwner148V1, r0, _ HeaderCandidateRecord148V1) (HeaderCandidateOutcome148V1, func()) {
			return estRecs(t, r0, hcMk(t, r0.Hash, r0.Height+2, 200, 3)), nil
		}},
		{"row8 establish missing parent", HeaderCandidateMissingParent148V1, func(t *testing.T, _ *HeaderCandidateOwner148V1, _, _ HeaderCandidateRecord148V1) (HeaderCandidateOutcome148V1, func()) {
			return estRecs(t, hcMk(t, [32]byte{0x55}, 5, 50, 3)), nil
		}},
		{"row12 establish capacity", HeaderCandidateCapacity148V1, func(t *testing.T, _ *HeaderCandidateOwner148V1, r0, r1 HeaderCandidateRecord148V1) (HeaderCandidateOutcome148V1, func()) {
			return estRecs(t, r0, r1, child(t, r1, 3)), nil
		}},
		{"row3 not established prepare", HeaderCandidateNotEstablished148V1, func(t *testing.T, _ *HeaderCandidateOwner148V1, _, _ HeaderCandidateRecord148V1) (HeaderCandidateOutcome148V1, func()) {
			o := hcNew(t, hcLim())
			return prep(t, o, HeaderCandidateTransition148V1{ExpectedVersion: 1}), nil
		}},
		{"row3 not established lease", HeaderCandidateNotEstablished148V1, func(t *testing.T, _ *HeaderCandidateOwner148V1, _, r1 HeaderCandidateRecord148V1) (HeaderCandidateOutcome148V1, func()) {
			return acq(t, hcNew(t, hcLim()), r1.Hash), nil
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			o, r0, r1 := hcBase(t, hcLim())
			got, cleanup := c.run(t, o, r0, r1)
			if got != c.want {
				t.Fatalf("outcome %d want %d", got, c.want)
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
	cur, rel := hcGuard(t, o, 1)
	t.Cleanup(rel)
	if cur {
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
			v := c.fit
			if short {
				v--
			}
			l := hcLim()
			c.set(&l, v)
			o, r0, r1 := hcBase(t, l)
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
	// V9 MaxRetainedBytes through PrepareV1, a Work one byte wider: the limit is the contract charge, 252 plus the
	// minimal big-endian Work length, for R0 (work 100, one byte), R1 (110, one byte) and a sibling of R1 whose Work
	// 65536 = 0x010000 is three bytes. The same sibling with Work 1<<24 = 0x01000000 is four bytes and one byte over.
	for _, wide := range []bool{false, true} {
		l := hcLim()
		l.MaxRetainedBytes = (252 + 1) + (252 + 1) + (252 + 3)
		o, r0, r1 := hcBase(t, l)
		hcLeaseOK(t, o, r1.Hash)
		work, want := big.NewInt(65536), HeaderCandidateOK148V1
		if wide {
			work, want = big.NewInt(1<<24), HeaderCandidateCapacity148V1
		}
		if out := hcPrep(t, o, hcTr(o, []HeaderCandidateRecord148V1{hcMkW(t, r0.Hash, 11, work, 30)})); out != want {
			t.Fatalf("work wide=%v: %d", wide, out)
		}
	}
	ol := hcLim()
	ol.MaxTransitionHeaders = 2
	ol.MaxLeases = 2
	o, _, r1 := hcBase(t, ol)
	a := hcMk(t, r1.Hash, 12, 120, 31)
	b := hcMk(t, a.Hash, 13, 130, 32)
	c := hcMk(t, b.Hash, 14, 140, 33)
	if out := hcPrep(t, o, hcTr(o, []HeaderCandidateRecord148V1{a, b, c})); out != HeaderCandidateInvalid148V1 {
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
	if out := hcEst(t, e, hcSrc1, []HeaderCandidateRecord148V1{r0, e1, hcMk(t, e1.Hash, 12, 120, 3)}); out != HeaderCandidateInvalid148V1 || e.established || e.VersionV1() != 1 {
		t.Fatalf("over establish: %d", out)
	}
	if _, out := e.EstablishV1(hcSrc1, []HeaderCandidateRecord148V1{r0, e1}); out != HeaderCandidateOK148V1 || e.VersionV1() != 2 {
		t.Fatalf("exact establish: %d", out)
	}
	for i := 0; i < 2; i++ {
		if _, out := o.AcquireDependencyV1(r1.Hash); out != HeaderCandidateOK148V1 {
			t.Fatalf("lease %d: %d", i, out)
		}
	}
	if out := hcAcq(t, o, r1.Hash); out != HeaderCandidateCapacity148V1 {
		t.Fatalf("lease over: %d", out)
	}
}

func TestHeaderCandidate148Receipts(t *testing.T) {
	// D7 EstablishV1: Changed true, Version 2, Added the records' hashes in input order, Retired empty.
	o := hcNew(t, hcLim())
	e0 := hcExt(hcMk(t, hcRoot, 10, 100, 1))
	e1 := hcMk(t, e0.Hash, 11, 110, 2)
	e2 := hcExt(hcMk(t, [32]byte{0x55}, 10, 100, 3))
	pub, out := o.EstablishV1(hcSrc1, []HeaderCandidateRecord148V1{e2, e0, e1})
	if out != HeaderCandidateOK148V1 || !pub.Changed || pub.Version != 2 || len(pub.Retired) != 0 {
		t.Fatalf("establish receipt: %d %+v", out, pub)
	}
	hcEqual(t, "establish added", pub.Added, [][32]byte{e2.Hash, e0.Hash, e1.Hash})
	// V2/R4 Retired-only publication: Changed true, Version v+1, Retired exactly [R0], R0 gone, prior version stale.
	o, r0, r1 := hcBase(t, hcLim())
	v := o.VersionV1()
	pub, out = hcPublish(t, o, hcTr(o, nil, r0.Hash))
	if out != HeaderCandidateOK148V1 || !pub.Changed || pub.Version != v+1 || o.VersionV1() != v+1 || len(pub.Added) != 0 {
		t.Fatalf("retired-only receipt: %d %+v", out, pub)
	}
	hcEqual(t, "retired-only retired", pub.Retired, [][32]byte{r0.Hash})
	if _, ok := o.LookupV1(r0.Hash); ok {
		t.Fatal("retired-only: R0 still present")
	}
	cur, rel := hcGuard(t, o, v)
	rel()
	if cur {
		t.Fatal("retired-only: prior version still current")
	}
	o, r0, r1 = hcBase(t, hcLim())
	v = o.VersionV1()
	cur, rel = hcGuard(t, o, v)
	t.Cleanup(rel)
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
	cur, rel = hcGuard(t, o, v)
	t.Cleanup(rel)
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
	// D7 source-only: Changed true, a new Version, Added and Retired empty; NewSource equal to the current source is a no-op.
	tr := hcTr(o, nil)
	tr.NewSource = hcSrc2
	rec, out = hcPublish(t, o, tr)
	if out != HeaderCandidateOK148V1 || !rec.Changed || rec.Version != v+1 || o.VersionV1() != v+1 || o.source != hcSrc2 {
		t.Fatalf("source only: %d %+v", out, rec)
	}
	hcEqual(t, "source-only added", rec.Added, nil)
	hcEqual(t, "source-only retired", rec.Retired, nil)
	tr = hcTr(o, nil)
	tr.NewSource = hcSrc2
	rec, out = hcPublish(t, o, tr)
	if out != HeaderCandidateOK148V1 || rec.Changed || rec.Version != v+1 || o.VersionV1() != v+1 {
		t.Fatalf("same source: %d %+v", out, rec)
	}
	tr = hcTr(o, nil, r0.Hash)
	tr.NewSource = hcSrc1
	rec, out = hcPublish(t, o, tr)
	if out != HeaderCandidateOK148V1 || !rec.Changed || rec.Version != v+2 || o.source != hcSrc1 || len(rec.Added) != 0 {
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
	o := hcNew(t, lim)
	r := map[string]HeaderCandidateRecord148V1{}
	r["R0"] = hcExt(hcMk(t, hcRoot, 10, 10, 1))
	r["S"] = hcMk(t, r["R0"].Hash, 11, 11, 2)
	r["A"] = hcMk(t, r["S"].Hash, 12, 5, 3)
	r["B"] = hcMk(t, r["S"].Hash, 12, 6, 4)
	r["I"] = hcMk(t, r["R0"].Hash, 11, 11, 5)
	r["A2"] = hcMk(t, r["I"].Hash, 12, 4, 6)
	r["K"] = hcMk(t, r["R0"].Hash, 11, 50, 7)
	hcEstablish(t, o, r["R0"], r["S"], r["A"], r["B"], r["I"], r["A2"], r["K"])
	return o, r
}

func TestHeaderCandidate148Capacity(t *testing.T) {
	lim := hcLim()
	lim.MaxHeaders = 7
	ext := func(t *testing.T, o *HeaderCandidateOwner148V1, r map[string]HeaderCandidateRecord148V1, want ...[32]byte) {
		t.Helper()
		n := hcMk(t, r["K"].Hash, 12, 60, 8)
		rec, out := hcPublish(t, o, hcTr(o, []HeaderCandidateRecord148V1{n}))
		if out != HeaderCandidateOK148V1 || !rec.Changed || rec.Version != 3 {
			t.Fatalf("%d %+v", out, rec)
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
		o, r := hcCapFixture(t, lim)
		if _, out := o.AcquireDependencyV1(r["A2"].Hash); out != HeaderCandidateOK148V1 {
			t.Fatal("lease")
		}
		// Three additions over a full owner need three removals: A, then B together with S, which is B's exclusive
		// ancestor once A is chosen; S is never a tip.
		n := hcChain(t, r["K"], 3)
		rec, out := hcPublish(t, o, hcTr(o, n))
		if out != HeaderCandidateOK148V1 || !rec.Changed || rec.Version != 3 {
			t.Fatalf("%d %+v", out, rec)
		}
		hcEqual(t, "added", rec.Added, hcHashes(n...))
		hcEqual(t, "retired", rec.Retired, hcHashes(r["A"], r["B"], r["S"]))
		if p := hcPresent(o, r["A"], r["B"], r["S"]); p[0] || p[1] || p[2] {
			t.Fatal("victim still present")
		}
	})
	t.Run("candidate holding an addition is skipped whole", func(t *testing.T) {
		// Post set: fixture plus N over MaxHeaders 7. A2 (work 4) is the weakest candidate but its reclaim [A2, I]
		// holds A2, an identical duplicate in Additions, so it is skipped; A (work 5) with reclaim [A] is chosen.
		o, r := hcCapFixture(t, lim)
		n := hcMk(t, r["K"].Hash, 12, 60, 8)
		rec, out := hcPublish(t, o, hcTr(o, []HeaderCandidateRecord148V1{r["A2"], n}))
		if out != HeaderCandidateOK148V1 || !rec.Changed || rec.Version != 3 {
			t.Fatalf("%d %+v", out, rec)
		}
		hcEqual(t, "added", rec.Added, [][32]byte{n.Hash})
		hcEqual(t, "retired", rec.Retired, [][32]byte{r["A"].Hash})
		if p := hcPresent(o, r["A2"], r["I"]); !p[0] || !p[1] {
			t.Fatal("skipped candidate lost")
		}
	})
	t.Run("stops at first fit", func(t *testing.T) {
		l := lim
		l.MaxHeaders = 16
		l.MaxTips = 4
		o, r := hcCapFixture(t, l)
		n := hcMk(t, r["R0"].Hash, 11, 60, 8)
		rec, out := hcPublish(t, o, hcTr(o, []HeaderCandidateRecord148V1{n}))
		if out != HeaderCandidateOK148V1 || !rec.Changed || rec.Version != 3 {
			t.Fatalf("%d %+v", out, rec)
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
		o := hcNew(t, hcHeaders(1))
		p := hcExt(hcMk(t, [32]byte{0x44}, 9, 9, 98))
		c := hcExt(hcMk(t, p.Hash, 10, 10, 97))
		hcEstablish(t, o, c)
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

// TestHeaderCandidate148Reorg covers X3: a source replacement over shared ancestors with pending-body (A) and target
// (K) dependencies meets unavailable, stale and capacity refusals that preserve membership, leases, source and version;
// the next valid sibling operation is then legal.
func TestHeaderCandidate148Reorg(t *testing.T) {
	lim := hcLim()
	lim.MaxHeaders = 7
	o, r := hcCapFixture(t, lim)
	for _, k := range []string{"A", "K"} {
		if _, out := o.AcquireDependencyV1(r[k].Hash); out != HeaderCandidateOK148V1 {
			t.Fatalf("lease %s: %d", k, out)
		}
	}
	all := []HeaderCandidateRecord148V1{r["R0"], r["S"], r["A"], r["B"], r["I"], r["A2"], r["K"]}
	unchanged := func(what string, want HeaderCandidateOutcome148V1, tr HeaderCandidateTransition148V1) {
		t.Helper()
		before := hcTake(o, all...)
		if out := hcPrep(t, o, tr); out != want {
			t.Fatalf("%s: %d want %d", what, out, want)
		}
		if !before.same(hcTake(o, all...)) || o.source != hcSrc1 || o.leases != 2 || o.prepared != nil {
			t.Fatalf("%s changed ownership", what)
		}
	}
	strong := hcMk(t, r["K"].Hash, 12, 60, 8)
	valid := hcTr(o, []HeaderCandidateRecord148V1{strong})
	valid.NewSource = hcSrc2
	// Unavailable: the reorg would retire the shared ancestor R0 below both leased paths.
	gone := hcTr(o, []HeaderCandidateRecord148V1{strong}, r["R0"].Hash)
	gone.NewSource = hcSrc2
	unchanged("retire shared leased ancestor", HeaderCandidateProtected148V1, gone)
	// Stale: the otherwise valid replacement names another source.
	stale := valid
	stale.ExpectedSource = hcSrc2
	unchanged("stale source", HeaderCandidateStale148V1, stale)
	// Capacity: a weak replacement tip outranks no unprotected candidate.
	weak := hcTr(o, []HeaderCandidateRecord148V1{hcMk(t, r["K"].Hash, 12, 1, 9)})
	weak.NewSource = hcSrc2
	unchanged("weak replacement", HeaderCandidateCapacity148V1, weak)
	// The next valid sibling operation is legal and keeps both dependencies.
	v := o.VersionV1()
	rec, out := hcPublish(t, o, valid)
	if out != HeaderCandidateOK148V1 || rec.Version != v+1 || o.source != hcSrc2 || o.leases != 2 {
		t.Fatalf("valid replacement: %d %+v", out, rec)
	}
	hcEqual(t, "retired", rec.Retired, hcHashes(r["A2"], r["I"]))
	if p := hcPresent(o, r["R0"], r["S"], r["A"], r["K"], strong); slices.Contains(p, false) {
		t.Fatal("dependency path lost")
	}
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
		if b := hcHeldBytes(o); b != 253+2*290 {
			t.Fatalf("bytes %d", b)
		}
	}
	// Multi-victim order: with A2 leased, three additions over a full owner retire exactly [A, B, S] on every one of
	// 64 fresh owners.
	_, r := hcCapFixture(t, hcHeaders(7))
	n := hcChain(t, r["K"], 3)
	want := hcHashes(r["A"], r["B"], r["S"])
	for i := 0; i < 64; i++ {
		o, _ := hcCapFixture(t, hcHeaders(7))
		if _, out := o.AcquireDependencyV1(r["A2"].Hash); out != HeaderCandidateOK148V1 {
			t.Fatalf("owner %d lease: %d", i, out)
		}
		rec, out := hcPublish(t, o, hcTr(o, n))
		if out != HeaderCandidateOK148V1 {
			t.Fatalf("owner %d: %d", i, out)
		}
		hcEqual(t, "multi-victim retired", rec.Retired, want)
	}
}

// TestHeaderCandidate148Canonical covers V5: promotions for more blocks than MaxHeaders retire covered prefixes.
func TestHeaderCandidate148Canonical(t *testing.T) {
	lim := hcLim()
	lim.MaxHeaders = 3
	o := hcNew(t, lim)
	prev := hcExt(hcMk(t, hcRoot, 10, 10, 1))
	tip := hcMk(t, prev.Hash, 11, 11, 2)
	// Z is a dependency on another attached branch; its lease is held through every promotion.
	z := hcExt(hcMk(t, [32]byte{0x5A}, 10, 10, 3))
	hcEstablish(t, o, prev, tip, z)
	if _, out := o.AcquireDependencyV1(z.Hash); out != HeaderCandidateOK148V1 {
		t.Fatalf("lease Z: %d", out)
	}
	for i := uint64(0); i < 3*lim.MaxHeaders; i++ {
		next := hcMk(t, tip.Hash, tip.Height+1, tip.Work.Int64()+1, 100+i)
		rec, out := hcPublish(t, o, hcTr(o, []HeaderCandidateRecord148V1{next}, prev.Hash))
		if out != HeaderCandidateOK148V1 {
			t.Fatalf("step %d: %d", i, out)
		}
		hcEqual(t, "retired", rec.Retired, hcHashes(prev))
		prev, tip = tip, next
		var dst [148]byte
		for _, r := range []HeaderCandidateRecord148V1{prev, tip, z} {
			if !o.Header148V1(r.Hash, &dst) || dst != r.Raw {
				t.Fatalf("step %d lost an admitted header", i)
			}
		}
		if o.tips != 2 || len(o.recs) != 3 || o.leases != 1 {
			t.Fatalf("step %d: tips %d headers %d leases %d", i, o.tips, len(o.recs), o.leases)
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
	if _, ok := o.LookupV1(p.Hash); ok {
		t.Fatal("retire P: P still present")
	}
	v := o.VersionV1()
	rec, out := hcPublish(t, o, hcTr(o, []HeaderCandidateRecord148V1{h}))
	if out != HeaderCandidateOK148V1 || rec.Changed || o.VersionV1() != v {
		t.Fatalf("D9 identical: %d %+v", out, rec)
	}
	// D9: External is neither consulted nor stored on a same-hash addition, for a duplicate and a provenance update.
	hExt := hcExt(h)
	if rec, out := hcPublish(t, o, hcTr(o, []HeaderCandidateRecord148V1{hExt})); out != HeaderCandidateOK148V1 || rec.Changed {
		t.Fatalf("D9 External-only duplicate: %d %+v", out, rec)
	}
	if got, _ := o.LookupV1(h.Hash); got.External {
		t.Fatal("duplicate stored External")
	}
	hExt.Provenance = hcProvB
	if rec, out := hcPublish(t, o, hcTr(o, []HeaderCandidateRecord148V1{hExt})); out != HeaderCandidateOK148V1 || !rec.Changed {
		t.Fatalf("D9 provenance update: %d %+v", out, rec)
	}
	if got, _ := o.LookupV1(h.Hash); got.External || got.Provenance != hcProvB {
		t.Fatalf("provenance update stored External=%v provenance=%v", got.External, got.Provenance == hcProvB)
	}
	// D9: Additions [H exactly as stored, K a new child of H] has the outcome and effect of Additions [K], compared
	// with a second owner brought to the same pre-state on the full inner state and the receipt.
	hStored := h
	hStored.Provenance = hcProvB
	o2 := hcNew(t, hcLim())
	hcEstablish(t, o2, p, h)
	for _, tr := range []HeaderCandidateTransition148V1{hcTr(o2, nil, p.Hash), {Additions: []HeaderCandidateRecord148V1{hStored}}} {
		tr.ExpectedVersion, tr.ExpectedSource = o2.VersionV1(), hcSrc1
		if _, out := hcPublish(t, o2, tr); out != HeaderCandidateOK148V1 {
			t.Fatalf("D9 second owner pre-state: %d", out)
		}
	}
	if hcInnerOf(o) != hcInnerOf(o2) {
		t.Fatal("D9 pre-states differ")
	}
	v = o.VersionV1()
	k := hcMk(t, h.Hash, 11, 11, 5)
	rec, out = hcPublish(t, o, hcTr(o, []HeaderCandidateRecord148V1{hStored, k}))
	rec2, out2 := hcPublish(t, o2, hcTr(o2, []HeaderCandidateRecord148V1{k}))
	if out != HeaderCandidateOK148V1 || out2 != out || !rec.Changed || rec2.Changed != rec.Changed || rec.Version != v+1 || rec2.Version != rec.Version {
		t.Fatalf("D9 with child: %d %+v, alone: %d %+v", out, rec, out2, rec2)
	}
	hcEqual(t, "D9 added", rec.Added, rec2.Added)
	hcEqual(t, "D9 retired", rec.Retired, rec2.Retired)
	hcEqual(t, "D9 added literal", rec.Added, hcHashes(k))
	if hcInnerOf(o) != hcInnerOf(o2) {
		t.Fatal("D9 effect differs from Additions [K]")
	}
	// D9: P retired, then re-added External with a Height inconsistent with its admitted child H (row 7 compares an
	// addition only with its own parent); H re-added identical is never refused for its parent's height.
	o = hcNew(t, hcLim())
	hcEstablish(t, o, p, h)
	if _, out := hcPublish(t, o, hcTr(o, nil, p.Hash)); out != HeaderCandidateOK148V1 {
		t.Fatalf("retire P: %d", out)
	}
	pFar := p
	pFar.Height = h.Height + 5
	if _, out := hcPublish(t, o, hcTr(o, []HeaderCandidateRecord148V1{pFar})); out != HeaderCandidateOK148V1 {
		t.Fatalf("re-add P at an inconsistent height: %d", out)
	}
	v = o.VersionV1()
	rec, out = hcPublish(t, o, hcTr(o, []HeaderCandidateRecord148V1{h}))
	if out != HeaderCandidateOK148V1 || rec.Changed || rec.Version != v || o.VersionV1() != v {
		t.Fatalf("D9 same hash under an inconsistent parent height: %d %+v", out, rec)
	}
	// V7: before anchor loss the producer re-adds the required suffix in one transition, or gets Capacity first.
	o = hcNew(t, hcLim())
	hcEstablish(t, o, hcExt(h))
	if _, out := hcPublish(t, o, hcTr(o, []HeaderCandidateRecord148V1{p})); out != HeaderCandidateOK148V1 {
		t.Fatalf("V7 re-add: %d", out)
	}
	o2 = hcNew(t, hcHeaders(1))
	hcEstablish(t, o2, hcExt(h))
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
	if out := hcAcq(t, o, [32]byte{0x77}); out != HeaderCandidateMissing148V1 {
		t.Fatal("missing")
	}
	h, out := o.PrepareV1(hcTr(o, nil, r0.Hash))
	if out != HeaderCandidateOK148V1 {
		t.Fatalf("prepare: %d", out)
	}
	for _, x := range [][32]byte{r0.Hash, r1.Hash} {
		if out := hcAcq(t, o, x); out != HeaderCandidateProtected148V1 {
			t.Fatalf("lease on planned removal: %d", out)
		}
	}
	if h.AbortV1() != HeaderCandidateOK148V1 {
		t.Fatal("abort")
	}
	pre := hcReads(o, r0, r1)
	l, out := o.AcquireDependencyV1(r1.Hash)
	if out != HeaderCandidateOK148V1 {
		t.Fatalf("lease after abort: %d", out)
	}
	if hcReads(o, r0, r1) != pre {
		t.Fatal("V3 lease acquire changed VersionV1, LookupV1 or Header148V1")
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
	if o.leases != 0 || hcReads(o, r0, r1) != pre {
		t.Fatal("V3 lease release changed state, VersionV1, LookupV1 or Header148V1")
	}
	h = hcPrepOK(t, o, hcTr(o, nil, r0.Hash))
	if out := hcAcq(t, o, r1.Hash); out != HeaderCandidateProtected148V1 {
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
	// D6 over capacity victims: the outstanding replacement plans to retire tip A2 and its exclusive ancestor I.
	lim := hcLim()
	lim.MaxHeaders = 7
	c, r := hcCapFixture(t, lim)
	h, out = c.PrepareV1(hcTr(c, []HeaderCandidateRecord148V1{hcMk(t, r["K"].Hash, 12, 60, 8)}))
	if out != HeaderCandidateOK148V1 {
		t.Fatalf("replacement prepare: %d", out)
	}
	for _, k := range []string{"A2", "I"} {
		if out := hcAcq(t, c, r[k].Hash); out != HeaderCandidateProtected148V1 {
			t.Fatalf("lease on capacity victim %s: %d", k, out)
		}
	}
	if h.AbortV1() != HeaderCandidateOK148V1 {
		t.Fatal("abort")
	}
	for _, k := range []string{"A2", "I"} {
		if _, out := c.AcquireDependencyV1(r[k].Hash); out != HeaderCandidateOK148V1 {
			t.Fatalf("lease after abort %s: %d", k, out)
		}
	}
	// Order Missing, Protected, Capacity with MaxLeases reached: an absent hash is Missing, a planned victim Protected.
	lim.MaxLeases = 1
	f, r := hcCapFixture(t, lim)
	hcLeaseOK(t, f, r["K"].Hash)
	h = hcPrepOK(t, f, hcTr(f, []HeaderCandidateRecord148V1{hcMk(t, r["K"].Hash, 12, 60, 8)}))
	t.Cleanup(func() { h.AbortV1() })
	for _, c := range []struct {
		hash [32]byte
		want HeaderCandidateOutcome148V1
	}{{[32]byte{0x77}, HeaderCandidateMissing148V1}, {r["A2"].Hash, HeaderCandidateProtected148V1}, {r["B"].Hash, HeaderCandidateCapacity148V1}} {
		if out := hcAcq(t, f, c.hash); out != c.want {
			t.Fatalf("full leases: %d want %d", out, c.want)
		}
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
	// The caller's addition Work mutated after PublishV1 does not reach the stored record.
	add := hcMk(t, r1.Hash, 12, 140, 11)
	if _, out := hcPublish(t, o, hcTr(o, []HeaderCandidateRecord148V1{add})); out != HeaderCandidateOK148V1 {
		t.Fatal("publish addition")
	}
	add.Work.SetInt64(7)
	if stored, ok := o.LookupV1(add.Hash); !ok || stored.Work.Cmp(big.NewInt(140)) != 0 {
		t.Fatal("addition Work aliased")
	}
	// R3: a transition longer than MaxTransitionHeaders allocates nothing. The input also holds a duplicate and a
	// parent-after-child order so a set check placed before the length check would allocate.
	c := hcMk(t, r1.Hash, 12, 120, 9)
	long := hcTr(o, []HeaderCandidateRecord148V1{hcMk(t, c.Hash, 13, 130, 10), c, c, c, c, c, c, c, c})
	if out := hcPrep(t, o, long); out != HeaderCandidateInvalid148V1 {
		t.Fatal("over-length accepted")
	}
	if a := testing.AllocsPerRun(50, func() {
		if h, out := o.PrepareV1(long); out != HeaderCandidateInvalid148V1 || h != nil {
			t.Fatal("over-length accepted")
		}
	}); a != 0 {
		t.Fatalf("allocs %v", a)
	}
	// R3 Retired term: Additions within the limit, Additions plus Retired over it.
	overRetired := hcTr(o, hcChain(t, r1, 4), [32]byte{0x61}, [32]byte{0x62}, [32]byte{0x63}, [32]byte{0x64}, [32]byte{0x65})
	if out := hcPrep(t, o, overRetired); out != HeaderCandidateInvalid148V1 {
		t.Fatalf("over-length Retired: %d", out)
	}
	if a := testing.AllocsPerRun(50, func() {
		if h, out := o.PrepareV1(overRetired); out != HeaderCandidateInvalid148V1 || h != nil {
			t.Fatalf("over-length Retired: %d", out)
		}
	}); a != 0 {
		t.Fatalf("Retired allocs %v", a)
	}
	// R3/M24 on EstablishV1: records longer than MaxTransitionHeaders are Invalid at row 5 on a fresh owner with no
	// allocation, no establishment and an unchanged version.
	fresh := hcNew(t, hcLim())
	if a := testing.AllocsPerRun(50, func() {
		if p, out := fresh.EstablishV1(hcSrc1, long.Additions); out != HeaderCandidateInvalid148V1 || p.Changed || p.Version != 0 || p.Added != nil || p.Retired != nil {
			t.Fatalf("over-length establish: %d", out)
		}
	}); a != 0 {
		t.Fatalf("establish allocs %v", a)
	}
	if fresh.established || fresh.VersionV1() != 1 {
		t.Fatal("over-length establish changed state")
	}
	// Charge is 252 plus the minimal big-endian Work length (zero for zero), computed without allocating.
	wide := new(big.Int).Lsh(big.NewInt(1), 300)
	for _, c := range []struct {
		w    *big.Int
		want uint64
	}{{big.NewInt(0), 252}, {big.NewInt(255), 253}, {big.NewInt(256), 254}, {wide, 252 + 38}} {
		if got := hcCharge(c.w); got != c.want {
			t.Fatalf("charge %s: %d want %d", c.w, got, c.want)
		}
	}
	if a := testing.AllocsPerRun(50, func() { _ = hcCharge(wide) }); a != 0 {
		t.Fatalf("charge allocs %v", a)
	}
}

// hcChain returns n valid records, each the child of the previous one, starting under parent.
func hcChain(t testing.TB, parent HeaderCandidateRecord148V1, n int) []HeaderCandidateRecord148V1 {
	out := make([]HeaderCandidateRecord148V1, 0, n)
	for i := 0; i < n; i++ {
		parent = hcMk(t, parent.Hash, parent.Height+1, parent.Work.Int64()+1, uint64(500+i))
		out = append(out, parent)
	}
	return out
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
	t.Run("changed-false publish does not wait for a guard", func(t *testing.T) {
		o, r0, _ := hcBase(t, hcLim())
		v := o.VersionV1()
		cur, rel := hcGuard(t, o, v)
		t.Cleanup(rel)
		if !cur {
			t.Fatal("not current")
		}
		h := hcPrepOK(t, o, hcTr(o, []HeaderCandidateRecord148V1{r0}))
		var pub HeaderCandidatePublication148V1
		var out HeaderCandidateOutcome148V1
		hcWithin(t, "Changed-false PublishV1 under a held guard", func() { pub, out = h.PublishV1() })
		if out != HeaderCandidateOK148V1 || pub.Changed || pub.Version != v || o.VersionV1() != v || hcInnerOf(o).guards != 1 {
			t.Fatalf("changed-false publish: %d %+v", out, pub)
		}
		rel()
	})
	t.Run("abort then publish", func(t *testing.T) {
		o, r0, r1 := hcBase(t, hcLim())
		n := hcMk(t, r1.Hash, 12, 120, 9)
		tr := hcTr(o, []HeaderCandidateRecord148V1{n})
		before, reads, inner := hcTake(o, r0, r1, n), hcReads(o, r0, r1, n), hcInnerOf(o)
		h := hcPrepOK(t, o, tr)
		if h.AbortV1() != HeaderCandidateOK148V1 || !before.same(hcTake(o, r0, r1, n)) || hcReads(o, r0, r1, n) != reads || hcInnerOf(o) != inner {
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
		h = hcPrepOK(t, o, tr)
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
		cur, rel := hcGuard(t, o, v)
		// A failing assertion must not leave blocked goroutines behind: release the guard and wake every waiter.
		t.Cleanup(func() { rel(); o.CloseV1() })
		if cur {
			t.Fatal("stale guard current")
		}
		guarded := hcMk(t, r1.Hash, 12, 121, 10)
		h := hcPrepOK(t, o, hcTr(o, []HeaderCandidateRecord148V1{guarded}))
		vPrep := o.VersionV1()
		var gpub HeaderCandidatePublication148V1
		var gout HeaderCandidateOutcome148V1
		done := make(chan struct{})
		go func() { gpub, gout = h.PublishV1(); close(done) }()
		hcBlocked(t, done)
		// R5: shared reads and guards return while the publication waits, and answer the unchanged state.
		var c2, hdrOK, lookOK bool
		var dst [148]byte
		var got HeaderCandidateRecord148V1
		var lout HeaderCandidateOutcome148V1
		hcWithin(t, "reads under waiting publish", func() {
			var r2 func()
			c2, r2 = o.ProtectV1(o.VersionV1())
			hdrOK = o.Header148V1(r1.Hash, &dst)
			got, lookOK = o.LookupV1(r1.Hash)
			var l *HeaderCandidateLease148V1
			if l, lout = o.AcquireDependencyV1(r1.Hash); lout == HeaderCandidateOK148V1 {
				l.ReleaseV1()
			}
			r2()
		})
		if !c2 || !hdrOK || dst != r1.Raw || !lookOK || got.Hash != r1.Hash || got.Height != r1.Height || got.Work.Cmp(r1.Work) != 0 || lout != HeaderCandidateOK148V1 {
			t.Fatalf("reads under waiting publish: current %v header %v lookup %v lease %d", c2, hdrOK, lookOK, lout)
		}
		rel()
		hcWithin(t, "publish after release", func() { <-done })
		if gout != HeaderCandidateOK148V1 || !gpub.Changed || gpub.Version != vPrep+1 || o.VersionV1() != vPrep+1 {
			t.Fatalf("guarded publish: %d %+v", gout, gpub)
		}
		hcEqual(t, "guarded added", gpub.Added, hcHashes(guarded))
		hcEqual(t, "guarded retired", gpub.Retired, nil)
		// X1: the second call of the same release is a no-op, so a later state-changing publication still proceeds.
		rel()
		later := hcPrepOK(t, o, hcTr(o, []HeaderCandidateRecord148V1{hcMk(t, r1.Hash, 12, 122, 11)}))
		var out HeaderCandidateOutcome148V1
		hcWithin(t, "publish after double release", func() { _, out = later.PublishV1() })
		if out != HeaderCandidateOK148V1 {
			t.Fatalf("later publish: %d", out)
		}
	})
	t.Run("unknown latch", func(t *testing.T) {
		o, r0, r1 := hcBase(t, hcLim())
		lease := hcLeaseOK(t, o, r1.Hash)
		n := hcMk(t, r1.Hash, 12, 120, 9)
		h := hcPrepOK(t, o, hcTr(o, []HeaderCandidateRecord148V1{n}))
		v := o.VersionV1()
		if h.UnknownV1() != HeaderCandidateOK148V1 || o.VersionV1() != v+1 {
			t.Fatal("unknown")
		}
		// X5 reads after the latch answer the unchanged membership; a lease still releases normally.
		var dst [148]byte
		if !o.Header148V1(r0.Hash, &dst) || dst != r0.Raw || o.Header148V1(n.Hash, &dst) || o.IncarnationV1() != 7 {
			t.Fatal("reads after latch")
		}
		lease.ReleaseV1()
		if o.leases != 0 {
			t.Fatal("lease release after latch")
		}
		if p := hcPresent(o, r0, r1, n); !p[0] || !p[1] || p[2] {
			t.Fatal("unknown applied membership")
		}
		cur, rel := o.ProtectV1(o.VersionV1())
		if rel == nil {
			t.Fatal("latched protect returned a nil release")
		}
		t.Cleanup(rel)
		if cur {
			t.Fatal("latched protect current")
		}
		if out := hcPrep(t, o, hcTr(o, nil)); out != HeaderCandidateUnknownSource148V1 {
			t.Fatal("prepare after latch")
		}
		if out := hcEst(t, o, hcSrc1, nil); out != HeaderCandidateUnknownSource148V1 {
			t.Fatal("establish after latch")
		}
		if out := hcAcq(t, o, r1.Hash); out != HeaderCandidateUnknownSource148V1 {
			t.Fatal("lease after latch")
		}
		// The latched guard is still held: a second handle call must return Consumed without waiting for it.
		var second HeaderCandidateOutcome148V1
		hcWithin(t, "second unknown under a held guard", func() { second = h.UnknownV1() })
		if second != HeaderCandidateConsumed148V1 {
			t.Fatal("second unknown")
		}
	})
	t.Run("unknown latch keeps planned removal", func(t *testing.T) {
		// R0 is a lawful Retired (its parent is not received, R1 survives); N is a planned addition.
		o, r0, r1 := hcBase(t, hcLim())
		n := hcMk(t, r1.Hash, 12, 120, 9)
		h := hcPrepOK(t, o, hcTr(o, []HeaderCandidateRecord148V1{n}, r0.Hash))
		v := o.VersionV1()
		before := hcInnerOf(o)
		cur, rel := hcGuard(t, o, v)
		t.Cleanup(func() { rel(); o.CloseV1() })
		if !cur {
			t.Fatal("guard not current")
		}
		done := make(chan HeaderCandidateOutcome148V1, 1)
		go func() { done <- h.UnknownV1() }()
		select {
		case <-done:
			t.Fatal("UnknownV1 returned while a guard was held")
		case <-time.After(50 * time.Millisecond):
		}
		rel()
		var got HeaderCandidateOutcome148V1
		hcWithin(t, "unknown after release", func() { got = <-done })
		if got != HeaderCandidateOK148V1 {
			t.Fatalf("unknown: %d", got)
		}
		var dst [148]byte
		if p := hcPresent(o, r0, r1, n); !p[0] || !p[1] || p[2] || !o.Header148V1(r0.Hash, &dst) || dst != r0.Raw {
			t.Fatalf("latch applied the prepared transition: present %v", p)
		}
		// Only the latch and one version step differ; membership, charges, leases and the occupied slot are unchanged.
		before.version, before.latched = v+1, true
		if after := hcInnerOf(o); after != before || o.VersionV1() != v+1 {
			t.Fatalf("latch state: %+v", after)
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
			cur, rel := hcGuard(t, o, v)
			t.Cleanup(func() { rel(); o.CloseV1() })
			if !cur {
				t.Fatal("guard not current")
			}
			done := make(chan HeaderCandidateOutcome148V1, 1)
			go func() { done <- h.UnknownV1() }()
			time.Sleep(50 * time.Millisecond)
			if o.VersionV1() != v || hcInnerOf(o).latched {
				t.Fatal("unknown applied under guard")
			}
			rel()
			var got HeaderCandidateOutcome148V1
			hcWithin(t, "unknown after release", func() { got = <-done })
			if got != HeaderCandidateOK148V1 || !hcInnerOf(o).latched {
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
				h = hcPrepOK(t, o, hcTr(o, []HeaderCandidateRecord148V1{hcMk(t, r1.Hash, 12, 120, 9)}))
			}
			v := o.VersionV1()
			_, rel := hcGuard(t, o, v)
			t.Cleanup(rel)
			type res struct {
				pub HeaderCandidatePublication148V1
				out HeaderCandidateOutcome148V1
			}
			done := make(chan res, 1)
			go func() {
				switch kind {
				case "publish":
					p, out := h.PublishV1()
					done <- res{p, out}
				case "unknown":
					done <- res{out: h.UnknownV1()}
				default:
					p, out := o.EstablishV1(hcSrc1, []HeaderCandidateRecord148V1{r0})
					done <- res{p, out}
				}
			}()
			select {
			case <-done:
				t.Fatalf("%s returned while a guard was held", kind)
			case <-time.After(50 * time.Millisecond):
			}
			o.CloseV1()
			select {
			case r := <-done:
				zero := !r.pub.Changed && r.pub.Version == 0 && r.pub.Added == nil && r.pub.Retired == nil
				if r.out != HeaderCandidateClosed148V1 || !zero {
					t.Fatalf("%s: %d %+v", kind, r.out, r.pub)
				}
			case <-time.After(5 * time.Second):
				t.Fatalf("%s not woken", kind)
			}
			if h != nil {
				var out HeaderCandidateOutcome148V1
				hcWithin(t, "consumed publish under a held guard", func() { _, out = h.PublishV1() })
				if out != HeaderCandidateConsumed148V1 {
					t.Fatal("handle not consumed")
				}
			}
			rel()
			if in := hcInnerOf(o); o.VersionV1() != v || in.latched || (kind == "establish" && in.established) {
				t.Fatalf("%s applied after close", kind)
			}
		}
	})
	t.Run("close with handle guard and lease outstanding", func(t *testing.T) {
		o, r0, r1 := hcBase(t, hcLim())
		l := hcLeaseOK(t, o, r1.Hash)
		h := hcPrepOK(t, o, hcTr(o, nil))
		_, rel := hcGuard(t, o, o.VersionV1())
		t.Cleanup(rel)
		v := o.VersionV1()
		o.CloseV1()
		// ProtectV1 never waits, also with a guard and a prepared handle outstanding at close.
		var cur bool
		var rel2 func()
		hcWithin(t, "protect after close", func() { cur, rel2 = o.ProtectV1(v) })
		if cur || rel2 == nil {
			t.Fatal("closed protect current")
		}
		rel2()
		rel()
		closedState := hcInnerOf(o)
		l.ReleaseV1()
		if hcInnerOf(o) != closedState || o.leases != 1 {
			t.Fatal("lease release after close changed state")
		}
		if h.AbortV1() != HeaderCandidateClosed148V1 || h.AbortV1() != HeaderCandidateConsumed148V1 {
			t.Fatal("closed handle")
		}
		var dst [148]byte
		if o.Header148V1(r0.Hash, &dst) || o.VersionV1() != v {
			t.Fatal("closed reads")
		}
		if got, ok := o.LookupV1(r0.Hash); ok || got.Work != nil || o.IncarnationV1() != 7 {
			t.Fatal("closed lookup or incarnation")
		}
		for _, out := range []HeaderCandidateOutcome148V1{hcPrep(t, o, hcTr(o, nil)), hcEst(t, o, hcSrc1, nil), hcAcq(t, o, r1.Hash)} {
			if out != HeaderCandidateClosed148V1 {
				t.Fatalf("mutator after close: %d", out)
			}
		}
	})
	t.Run("concurrent establish", func(t *testing.T) {
		o := hcNew(t, hcLim())
		r0 := hcExt(hcMk(t, hcRoot, 10, 100, 1))
		_, rel := hcGuard(t, o, 1)
		t.Cleanup(func() { rel(); o.CloseV1() })
		type res struct {
			pub HeaderCandidatePublication148V1
			out HeaderCandidateOutcome148V1
		}
		ch := make(chan res, 2)
		for i := 0; i < 2; i++ {
			go func() { p, out := o.EstablishV1(hcSrc1, []HeaderCandidateRecord148V1{r0}); ch <- res{p, out} }()
		}
		time.Sleep(50 * time.Millisecond)
		rel()
		var a, b res
		hcWithin(t, "concurrent establish", func() { a, b = <-ch, <-ch })
		if b.out == HeaderCandidateOK148V1 {
			a, b = b, a
		}
		refusedZero := !b.pub.Changed && b.pub.Version == 0 && b.pub.Added == nil && b.pub.Retired == nil
		if a.out != HeaderCandidateOK148V1 || a.pub.Version != 2 || b.out != HeaderCandidateAlreadyEstablished148V1 || !refusedZero || o.VersionV1() != 2 {
			t.Fatalf("concurrent establish %d %+v / %d %+v", a.out, a.pub, b.out, b.pub)
		}
	})
}

// TestHeaderCandidate148Race covers E6 under go test -race: a canonical-promotion publisher retires the prefix of a
// chain while readers lease every chain hash, a provenance publisher races it (both tolerating Busy, Stale and
// Protected), and readers take guards and point reads. Every record is built before any goroutine starts. Afterwards
// each publisher reached its target, no successful lease ever named a removed hash, and the retired prefix is gone.
func TestHeaderCandidate148Race(t *testing.T) {
	const target = 6
	o := hcNew(t, hcLim())
	t.Cleanup(o.CloseV1)
	c0 := hcExt(hcMk(t, hcRoot, 10, 100, 1))
	chain := append([]HeaderCandidateRecord148V1{c0}, hcChain(t, c0, target+1)...)
	z := hcExt(hcMk(t, [32]byte{0x5A}, 10, 10, 3))
	hcEstablish(t, o, chain[0], chain[1], z)
	provs := make([]HeaderCandidateRecord148V1, target)
	for i := range provs {
		provs[i] = z
		provs[i].Provenance = [32]byte{byte(i) + 1, 7}
	}
	var dangling atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go hcRaceRead(&wg, o, z.Hash, hcHashes(chain...), &dangling)
	}
	var oks [2]int
	publish := func(id int, tr func(k int) HeaderCandidateTransition148V1) {
		defer wg.Done()
		for n := 0; oks[id] < target && n < 100000; n++ {
			h, out := o.PrepareV1(tr(oks[id]))
			switch out {
			case HeaderCandidateOK148V1:
				if _, out := h.PublishV1(); out == HeaderCandidateOK148V1 {
					oks[id]++
				}
			case HeaderCandidateBusy148V1, HeaderCandidateStale148V1, HeaderCandidateProtected148V1:
			default:
				t.Errorf("publisher %d: %d", id, out)
				return
			}
		}
	}
	wg.Add(2)
	go publish(0, func(k int) HeaderCandidateTransition148V1 {
		return hcTr(o, []HeaderCandidateRecord148V1{chain[k+2]}, chain[k].Hash)
	})
	go publish(1, func(k int) HeaderCandidateTransition148V1 { return hcTr(o, []HeaderCandidateRecord148V1{provs[k]}) })
	hcWithin(t, "concurrent publishers and readers", wg.Wait)
	if oks != [2]int{target, target} || dangling.Load() != 0 || o.leases != 0 {
		t.Fatalf("publishers %v dangling leases %d outstanding %d", oks, dangling.Load(), o.leases)
	}
	for i, r := range chain {
		if _, ok := o.LookupV1(r.Hash); ok != (i >= target) {
			t.Fatalf("chain[%d] present %v", i, ok)
		}
	}
	hcRaceCapacity(t, target)
}

// hcRaceRead takes guards and point reads and leases every pool hash in turn; a successful lease whose hash is then
// absent counts as dangling.
func hcRaceRead(wg *sync.WaitGroup, o *HeaderCandidateOwner148V1, probe [32]byte, pool [][32]byte, dangling *atomic.Int64) {
	defer wg.Done()
	for j := 0; j < 200; j++ {
		_, rel := o.ProtectV1(o.VersionV1())
		var dst [148]byte
		o.Header148V1(probe, &dst)
		rel()
		h := pool[j%len(pool)]
		if l, out := o.AcquireDependencyV1(h); out == HeaderCandidateOK148V1 {
			if _, ok := o.LookupV1(h); !ok {
				dangling.Add(1)
			}
			l.ReleaseV1()
		}
	}
}

// hcRaceCapacity covers X2 and E6 for capacity replacement: on a full owner (MaxHeaders 7) a publisher adds ever
// stronger tips, so the publications retire weaker unprotected tips with their exclusive ancestry (at least one header
// per addition in total, since the owner starts full), while readers lease the candidate tips and the interior headers. No successful lease may dangle.
func hcRaceCapacity(t *testing.T, target int) {
	c, r := hcCapFixture(t, hcHeaders(7))
	t.Cleanup(c.CloseV1)
	strong := make([]HeaderCandidateRecord148V1, target)
	for i := range strong {
		strong[i] = hcMk(t, r["R0"].Hash, 11, int64(100+i), uint64(100+i))
	}
	pool := hcHashes(strong...)
	for _, k := range []string{"R0", "S", "A", "B", "I", "A2", "K"} {
		pool = append(pool, r[k].Hash)
	}
	var dangling atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go hcRaceRead(&wg, c, r["R0"].Hash, pool, &dangling)
	}
	replaced, retired := 0, 0
	wg.Add(1)
	go func() {
		defer wg.Done()
		for n := 0; replaced < target && n < 100000; n++ {
			h, out := c.PrepareV1(hcTr(c, []HeaderCandidateRecord148V1{strong[replaced]}))
			if out == HeaderCandidateCapacity148V1 {
				continue
			}
			if out != HeaderCandidateOK148V1 {
				t.Errorf("capacity publisher: %d", out)
				return
			}
			p, out := h.PublishV1()
			if out != HeaderCandidateOK148V1 {
				t.Errorf("replacement publish: %d", out)
				return
			}
			replaced, retired = replaced+1, retired+len(p.Retired)
		}
	}()
	hcWithin(t, "capacity replacement with readers", wg.Wait)
	if replaced != target || retired < target || dangling.Load() != 0 || c.leases != 0 || hcInnerOf(c).headers > 7 {
		t.Fatalf("replaced %d retired %d dangling %d leases %d", replaced, retired, dangling.Load(), c.leases)
	}
	if _, ok := c.LookupV1(strong[target-1].Hash); !ok {
		t.Fatal("strongest tip absent")
	}
}
