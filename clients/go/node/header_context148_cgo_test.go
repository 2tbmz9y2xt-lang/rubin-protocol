//go:build cgo && (darwin || linux) && (amd64 || arm64)

package node

import (
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

func TestHeaderContext148InventoryComposition(t *testing.T) {
	o, p, source := cxWarm(t, []uint64{0, 1})
	var view consensus.ReplayHeaderCandidateView148V1 = o
	before := view.Inventory148V1(180)
	cxEqual(t, "inventory before", before, consensus.HeaderCandidateInventory148V1{Status: consensus.HeaderCandidateCompleteV1, Version: 3, Tips: [][32]byte{p.Hash}, Headers: [][148]byte{p.Raw}, Bytes: 180})
	raw := cxMine(p.Hash, 2, cxTarget(255))
	h, d := o.PrepareContextV1(cxInput(p.View, raw, cxProof(p, HeaderContextAdmitted148V1), source))
	cxDecision(t, "inventory prepare", d, 0, 0, 0, nil)
	cxEqual(t, "prepared inventory unchanged", view.Inventory148V1(180), before)
	r, pub, d := h.PublishV1()
	cxDecision(t, "inventory publish", d, 0, 0, 0, nil)
	inv := view.Inventory148V1(328)
	if inv.Status != consensus.HeaderCandidateCompleteV1 || inv.Version != pub.Version || inv.Bytes != 328 || len(inv.Headers) != 2 {
		t.Fatalf("complete inventory %+v", inv)
	}
	cxEqual(t, "inventory tips", inv.Tips, [][32]byte{r.Hash})
	if !((inv.Headers[0] == p.Raw && inv.Headers[1] == r.Raw) || (inv.Headers[1] == p.Raw && inv.Headers[0] == r.Raw)) {
		t.Fatal("inventory must include both admitted raw headers")
	}
	current, release := view.ProtectV1(inv.Version)
	if !current {
		t.Fatal("inventory guard stale")
	}
	context, d := o.LookupContextV1(r.View, r.Hash)
	cxDecision(t, "inventory/context guarded join", d, 0, 0, 0, nil)
	cxEqual(t, "context same version", context, r)
	var dst [148]byte
	if !view.Header148V1(r.Hash, &dst) || dst != r.Raw {
		t.Fatal("point facet changed")
	}
	release()
	inv.Headers[0][0] ^= 1
	inv.Tips[0][0] ^= 1
	if !view.Header148V1(r.Hash, &dst) || dst != r.Raw {
		t.Fatal("inventory output aliases C1")
	}
	refused := view.Inventory148V1(327)
	cxEqual(t, "inventory exact finite refusal", refused, consensus.HeaderCandidateInventory148V1{Status: consensus.HeaderCandidateCapacityRefusedV1, Version: pub.Version})
}
