//go:build cgo && (darwin || linux) && (amd64 || arm64)

package node

import (
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
	hcRefused(t, "one short", o.Inventory148V1(507), consensus.HeaderCandidateCapacityRefusedV1, 2)
	ceiling := func(n uint64) *HeaderCandidateOwner148V1 {
		l := hcLim()
		l.MaxSnapshotBytes = n
		s := hcNew(t, l)
		hcEstablish(t, s, a, b, c)
		return s
	}
	hcRefused(t, "snapshot ceiling", ceiling(507).Inventory148V1(1<<20), consensus.HeaderCandidateCapacityRefusedV1, 2)
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
	h, _ := o.PrepareV1(hcTr(o, nil))
	if h.UnknownV1() != HeaderCandidateOK148V1 {
		t.Fatal("unknown")
	}
	hcRefused(t, "latched", o.Inventory148V1(1<<20), consensus.HeaderCandidateIncompleteV1, 3)
	empty.CloseV1()
	hcRefused(t, "closed", empty.Inventory148V1(1<<20), consensus.HeaderCandidateIncompleteV1, 2)
}

// TestHeaderCandidate148InventoryUnderBlockedUnknown covers X5: while UnknownV1 waits on a current guard the
// inventory stays the complete pre-latch view; after the release it is Incomplete.
func TestHeaderCandidate148InventoryUnderBlockedUnknown(t *testing.T) {
	o, _, _ := hcBase(t, hcLim())
	h, _ := o.PrepareV1(hcTr(o, nil))
	v := o.VersionV1()
	cur, rel := o.ProtectV1(v)
	t.Cleanup(func() { rel(); o.CloseV1() })
	if !cur {
		t.Fatal("guard not current")
	}
	done := make(chan HeaderCandidateOutcome148V1, 1)
	go func() { done <- h.UnknownV1() }()
	time.Sleep(50 * time.Millisecond)
	if inv := o.Inventory148V1(1 << 20); inv.Status != consensus.HeaderCandidateCompleteV1 || inv.Version != v || len(inv.Headers) != 2 {
		t.Fatalf("inventory under blocked UnknownV1: %+v", inv)
	}
	rel()
	var out HeaderCandidateOutcome148V1
	hcWithin(t, "unknown after release", func() { out = <-done })
	if out != HeaderCandidateOK148V1 {
		t.Fatalf("unknown: %d", out)
	}
	hcRefused(t, "after latch", o.Inventory148V1(1<<20), consensus.HeaderCandidateIncompleteV1, v+1)
}
