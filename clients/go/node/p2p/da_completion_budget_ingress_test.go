package p2p

import (
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/node"
)

// The completion-budget decline reaches PEER ingress as the existing
// UNAVAILABLE admission error; the unchanged mapping applies no ban step,
// score change or returned disconnect error.
func TestDACompletionBudgetIngressDeclineIsPeerNeutral(t *testing.T) {
	h := newTestHarness(t, 1, "127.0.0.1:0", nil)
	p := daRelayTestPeer(h, "127.0.0.1:19121", "127.0.0.1:19121")
	before := effectsOf(p)
	err := &node.TxAdmitError{Kind: node.TxAdmitUnavailable, Message: "DA completion work budget unavailable"}
	for i := 0; i < 3; i++ {
		if got := p.penalizeDAAdmissionError(err); got != nil || effectsOf(p) != before {
			t.Fatalf("decline %d changed peer effects: returned=%v before=%+v after=%+v", i, got, before, effectsOf(p))
		}
	}
}
