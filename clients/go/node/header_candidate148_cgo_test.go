//go:build cgo && (darwin || linux) && (amd64 || arm64)

package node

import (
	"testing"

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
	o.limits.MaxSnapshotBytes = 507
	hcRefused(t, "snapshot ceiling", o.Inventory148V1(1<<20), consensus.HeaderCandidateCapacityRefusedV1, 2)
	o.limits.MaxSnapshotBytes = 508
	inv = o.Inventory148V1(1 << 20)
	if inv.Status != consensus.HeaderCandidateCompleteV1 {
		t.Fatal("snapshot exact fit")
	}
	inv.Tips[0][0] ^= 1
	inv.Headers[0][0] ^= 1
	var dst [148]byte
	if !o.Header148V1(a.Hash, &dst) || dst != a.Raw || !o.Header148V1(b.Hash, &dst) || dst != b.Raw {
		t.Fatal("caller mutation reached provider")
	}
	again := o.Inventory148V1(1 << 20)
	if again.Tips[0] == inv.Tips[0] && again.Headers[0] == inv.Headers[0] {
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
