//go:build cgo && (darwin || linux) && (amd64 || arm64)

package node

import (
	"math"
	"testing"
	"time"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

func hcRefused(t *testing.T, what string, inv consensus.HeaderCandidateInventory148V1, status consensus.HeaderCandidateStatusV1, version uint64) {
	t.Helper()
	if inv.Status != status || inv.Version != version || inv.Tips != nil || inv.Headers != nil || inv.Bytes != 0 {
		t.Fatalf("%s: %+v", what, inv)
	}
}

// TestHeaderCandidate148Inventory covers V1, V4, R1, R2 for arrays and the inventory side of X5.
func TestHeaderCandidate148Inventory(t *testing.T) {
	o := hcNew(t, hcLim())
	hcRefused(t, "new owner", o.Inventory148V1(1<<20), consensus.HeaderCandidateIncompleteV1, 1)
	a := hcExt(hcMk(t, hcRoot, 10, 10, 1))
	b := hcMk(t, a.Hash, 11, 11, 2)
	c := hcMk(t, a.Hash, 11, 12, 3)
	hcEstablish(t, o, a, b, c)
	inv := o.Inventory148V1(508)
	if inv.Status != consensus.HeaderCandidateCompleteV1 || inv.Version != 2 || inv.Bytes != 508 || len(inv.Tips) != 2 || len(inv.Headers) != 3 {
		t.Fatalf("exact fit: %+v", inv)
	}
	wantTips := map[[32]byte]bool{b.Hash: true, c.Hash: true}
	for _, h := range inv.Tips {
		if !wantTips[h] {
			t.Fatal("unexpected tip")
		}
		delete(wantTips, h)
	}
	wantRaw := map[[148]byte]bool{a.Raw: true, b.Raw: true, c.Raw: true}
	for _, r := range inv.Headers {
		if !wantRaw[r] {
			t.Fatal("unexpected header")
		}
		delete(wantRaw, r)
	}
	if len(wantTips)+len(wantRaw) != 0 {
		t.Fatal("missing tip or header")
	}
	pre := hcReads(o, a, b, c)
	hcRefused(t, "one short", o.Inventory148V1(507), consensus.HeaderCandidateCapacityRefusedV1, 2)
	if hcReads(o, a, b, c) != pre {
		t.Fatal("V3 CapacityRefused inventory changed VersionV1, LookupV1 or Header148V1")
	}
	ceiling := func(n uint64) *HeaderCandidateOwner148V1 {
		l := hcLim()
		l.MaxSnapshotBytes = n
		s := hcNew(t, l)
		hcEstablish(t, s, a, b, c)
		return s
	}
	short := ceiling(507)
	pre = hcReads(short, a, b, c)
	hcRefused(t, "snapshot ceiling", short.Inventory148V1(1<<20), consensus.HeaderCandidateCapacityRefusedV1, 2)
	if hcReads(short, a, b, c) != pre {
		t.Fatal("V3 snapshot-ceiling refusal changed VersionV1, LookupV1 or Header148V1")
	}
	o = ceiling(508)
	inv = o.Inventory148V1(1 << 20)
	if inv.Status != consensus.HeaderCandidateCompleteV1 {
		t.Fatal("snapshot exact fit")
	}
	inv.Tips[0][0] ^= 1
	inv.Headers[0][0] ^= 1
	var dst [148]byte
	if !o.Header148V1(a.Hash, &dst) || dst != a.Raw || !o.Header148V1(b.Hash, &dst) || dst != b.Raw || !o.Header148V1(c.Hash, &dst) || dst != c.Raw {
		t.Fatal("caller mutation reached provider")
	}
	again := o.Inventory148V1(1 << 20)
	if again.Tips[0] == inv.Tips[0] || again.Headers[0] == inv.Headers[0] {
		t.Fatal("arrays alias")
	}
	if o.VersionV1() != 2 {
		t.Fatal("V3 inventory changed version")
	}
	empty := hcNew(t, hcLim())
	if _, out := empty.EstablishV1(hcSrc1, nil); out != HeaderCandidateOK148V1 {
		t.Fatal("empty establish")
	}
	if e := empty.Inventory148V1(1 << 20); e.Status != consensus.HeaderCandidateCompleteV1 || len(e.Tips)+len(e.Headers) != 0 || e.Bytes != 0 {
		t.Fatalf("established empty: %+v", e)
	}
	fresh := hcNew(t, hcLim())
	hcRefused(t, "new incarnation", fresh.Inventory148V1(1<<20), consensus.HeaderCandidateIncompleteV1, 1)
	if hcPrepOK(t, o, hcTr(o, nil)).UnknownV1() != HeaderCandidateOK148V1 {
		t.Fatal("unknown")
	}
	hcRefused(t, "latched", o.Inventory148V1(1<<20), consensus.HeaderCandidateIncompleteV1, 3)
	empty.CloseV1()
	hcRefused(t, "closed", empty.Inventory148V1(1<<20), consensus.HeaderCandidateIncompleteV1, 2)
}

// TestHeaderCandidate148InventoryUnderBlockedUnknown covers X5: while UnknownV1 waits on a current guard the
// inventory stays the complete pre-latch view, also at the maximum version; after the release it is Incomplete. Below
// the maximum the prepared transition adds N and retires R0, and neither is applied by the latch.
func TestHeaderCandidate148InventoryUnderBlockedUnknown(t *testing.T) {
	for _, max := range []bool{false, true} {
		o, r0, r1 := hcBase(t, hcLim())
		tr := hcTr(o, []HeaderCandidateRecord148V1{hcMk(t, r1.Hash, 12, 120, 9)}, r0.Hash)
		if max {
			o.version.Store(math.MaxUint64)
			tr = hcTr(o, nil)
		}
		h := hcPrepOK(t, o, tr)
		v := o.VersionV1()
		cur, rel := hcGuard(t, o, v)
		t.Cleanup(func() { rel(); o.CloseV1() })
		if !cur {
			t.Fatal("guard not current")
		}
		done := make(chan HeaderCandidateOutcome148V1, 1)
		go func() { done <- h.UnknownV1() }()
		time.Sleep(50 * time.Millisecond)
		// Tips {R1}, headers {R0, R1}: 32 + 2*148.
		inv := o.Inventory148V1(1 << 20)
		if inv.Version != v {
			t.Fatalf("inventory under blocked UnknownV1 max=%v: %+v", max, inv)
		}
		hcInvExact(t, "inventory under blocked UnknownV1", inv, []HeaderCandidateRecord148V1{r1}, []HeaderCandidateRecord148V1{r0, r1}, 328)
		rel()
		var out HeaderCandidateOutcome148V1
		hcWithin(t, "unknown after release", func() { out = <-done })
		if out != HeaderCandidateOK148V1 {
			t.Fatalf("unknown: %d", out)
		}
		want := v + 1
		if max {
			want = math.MaxUint64
		}
		hcRefused(t, "after latch", o.Inventory148V1(1<<20), consensus.HeaderCandidateIncompleteV1, want)
	}
}

// TestHeaderCandidate148InventoryThenPublish covers X1 through the inventory read path: a publication between
// Inventory148V1 and ProtectV1(inv.Version) gives current false with a non-nil release, whose two calls hold nothing back.
func TestHeaderCandidate148InventoryThenPublish(t *testing.T) {
	o, _, r1 := hcBase(t, hcLim())
	inv := o.Inventory148V1(1 << 20)
	if inv.Status != consensus.HeaderCandidateCompleteV1 {
		t.Fatalf("inventory: %+v", inv)
	}
	if _, out := hcPublish(t, o, hcTr(o, []HeaderCandidateRecord148V1{hcMk(t, r1.Hash, 12, 120, 9)})); out != HeaderCandidateOK148V1 {
		t.Fatalf("publish: %d", out)
	}
	cur, rel := hcGuard(t, o, inv.Version)
	if cur {
		t.Fatal("ProtectV1 of the pre-publication inventory version is current")
	}
	rel()
	rel()
	if _, out := hcPublish(t, o, hcTr(o, []HeaderCandidateRecord148V1{hcMk(t, r1.Hash, 12, 121, 10)})); out != HeaderCandidateOK148V1 {
		t.Fatalf("publish after release: %d", out)
	}
}

// hcInvExact asserts a Complete inventory holding exactly the given tips and headers, with Bytes from the literal counts.
func hcInvExact(t *testing.T, what string, inv consensus.HeaderCandidateInventory148V1, tips, headers []HeaderCandidateRecord148V1, bytes uint64) {
	t.Helper()
	if inv.Status != consensus.HeaderCandidateCompleteV1 || inv.Bytes != bytes || len(inv.Tips) != len(tips) || len(inv.Headers) != len(headers) {
		t.Fatalf("%s: status %d bytes %d tips %d headers %d", what, inv.Status, inv.Bytes, len(inv.Tips), len(inv.Headers))
	}
	gotTips := map[[32]byte]bool{}
	for _, h := range inv.Tips {
		gotTips[h] = true
	}
	gotRaw := map[[148]byte]bool{}
	for _, r := range inv.Headers {
		gotRaw[r] = true
	}
	for _, r := range tips {
		if !gotTips[r.Hash] {
			t.Fatalf("%s: tip missing", what)
		}
	}
	for _, r := range headers {
		if !gotRaw[r.Raw] {
			t.Fatalf("%s: header missing", what)
		}
	}
}

// TestHeaderCandidate148InventoryAfterRemoval covers V5, V6 and R1 for the tip and header counters: the inventory after
// canonical promotions and after a capacity replacement that retires a tip and its exclusive ancestor.
func TestHeaderCandidate148InventoryAfterRemoval(t *testing.T) {
	lim := hcLim()
	lim.MaxHeaders = 3
	o := hcNew(t, lim)
	prev := hcExt(hcMk(t, hcRoot, 10, 10, 1))
	tip := hcMk(t, prev.Hash, 11, 11, 2)
	z := hcExt(hcMk(t, [32]byte{0x5A}, 10, 10, 3))
	hcEstablish(t, o, prev, tip, z)
	for i := uint64(0); i < 4; i++ {
		next := hcMk(t, tip.Hash, tip.Height+1, tip.Work.Int64()+1, 100+i)
		if _, out := hcPublish(t, o, hcTr(o, []HeaderCandidateRecord148V1{next}, prev.Hash)); out != HeaderCandidateOK148V1 {
			t.Fatalf("promotion %d: %d", i, out)
		}
		prev, tip = tip, next
	}
	// Tips {tip, Z}, headers {prev, tip, Z}: 2*32 + 3*148.
	hcInvExact(t, "after promotions", o.Inventory148V1(1<<20), []HeaderCandidateRecord148V1{tip, z}, []HeaderCandidateRecord148V1{prev, tip, z}, 508)
	cl := hcLim()
	cl.MaxHeaders = 7
	c, r := hcCapFixture(t, cl)
	n := hcMk(t, r["K"].Hash, 12, 60, 8)
	if _, out := hcPublish(t, c, hcTr(c, []HeaderCandidateRecord148V1{n})); out != HeaderCandidateOK148V1 {
		t.Fatalf("replacement: %d", out)
	}
	// A2 and its exclusive ancestor I are retired: tips {A, B, N}, headers {R0, S, A, B, K, N}: 3*32 + 6*148.
	headers := []HeaderCandidateRecord148V1{r["R0"], r["S"], r["A"], r["B"], r["K"], n}
	hcInvExact(t, "after replacement", c.Inventory148V1(1<<20), []HeaderCandidateRecord148V1{r["A"], r["B"], n}, headers, 984)
}
