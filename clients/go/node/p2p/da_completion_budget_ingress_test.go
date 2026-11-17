package p2p

import (
	"errors"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/node"
)

// The completion-budget decline is built as
// selectRelayDisposition(txAdmitUnavailable(...), RelayAdmissionUnavailable).
// Package p2p cannot seed the private budget, so a real AdmitDA error of that
// same constructor pair (the nil-mempool refusal of a zero DARelayState) drives
// the actual PEER ingress: no ban step, score change or returned disconnect
// error, and no prefetch attempt. The disposition is unexported outside the
// observer build, so only Kind and message are matched here.
func TestDACompletionBudgetIngressDeclineIsPeerNeutral(t *testing.T) {
	h := newTestHarness(t, 1, "127.0.0.1:0", nil)
	h.service.daRelay = &node.DARelayState{}
	p := daRelayTestPeer(h, "127.0.0.1:19121", "127.0.0.1:19121")
	_, _, provenance, ok := p.remoteDAProvenance()
	if !ok {
		t.Fatal("PEER provenance unavailable")
	}
	_, err := h.service.daRelay.AdmitDA([]byte{1}, provenance)
	var admitErr *node.TxAdmitError
	if !errors.As(err, &admitErr) || admitErr.Kind != node.TxAdmitUnavailable || admitErr.Message != "nil mempool" {
		t.Fatalf("AdmitDA err=%v, want the UNAVAILABLE nil-mempool refusal", err)
	}
	calls := nowCalls(h)
	before := effectsOf(p)
	for i := 0; i < 3; i++ {
		if got := p.handleRelayDATx([]byte{1}); got != nil || effectsOf(p) != before || calls.Load() != 0 {
			t.Fatalf("decline %d: returned=%v effects %+v -> %+v prefetch attempts=%d", i, got, before, effectsOf(p), calls.Load())
		}
	}
	// Control: the oracle counts a scheduler attempt in this harness.
	h.service.scheduleDAPrefetch(p, [32]byte{1})
	if calls.Load() != 1 {
		t.Fatalf("prefetch oracle saw %d attempts, want 1", calls.Load())
	}
}
