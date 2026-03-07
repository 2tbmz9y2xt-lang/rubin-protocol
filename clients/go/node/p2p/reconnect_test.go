package p2p

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/node"
)

func TestAutoReconnect(t *testing.T) {
	restore := overrideReconnectTiming(50*time.Millisecond, 50*time.Millisecond, 400*time.Millisecond)
	defer restore()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	h := newTestHarness(t, 1, "127.0.0.1:0", []string{listener.Addr().String()})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := h.service.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer h.service.Close()

	accepted := make(chan struct{}, 2)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			accepted <- struct{}{}
			_ = conn.Close()
		}
		conn, err = listener.Accept()
		if err != nil {
			return
		}
		accepted <- struct{}{}
		_ = completeRemoteHandshake(conn, node.DefaultPeerRuntimeConfig("devnet", 8), testVersionPayload(node.DevnetGenesisChainID(), node.DevnetGenesisBlockHash(), "remote", 1))
		time.Sleep(250 * time.Millisecond)
		_ = conn.Close()
	}()

	waitFor(t, 5*time.Second, func() bool {
		return len(accepted) >= 2 && h.peerManager.Count() == 1
	})
	if snap := h.service.reconnectSnapshot(listener.Addr().String()); snap.failures != 0 {
		t.Fatalf("failures=%d, want reset to 0", snap.failures)
	}
}

func TestReconnectBackoff(t *testing.T) {
	restore := overrideReconnectTiming(50*time.Millisecond, 50*time.Millisecond, 400*time.Millisecond)
	defer restore()

	currentTime := time.Unix(1_777_000_000, 0)
	h := newTestHarness(t, 0, "127.0.0.1:0", nil)
	h.service.cfg.Now = func() time.Time { return currentTime }

	addr := "127.0.0.1:19001"
	h.service.recordDialFailure(addr)
	first := h.service.reconnectSnapshot(addr)
	if got := first.nextRetry.Sub(currentTime); got != 50*time.Millisecond {
		t.Fatalf("first backoff=%s, want 50ms", got)
	}

	currentTime = currentTime.Add(50 * time.Millisecond)
	h.service.recordDialFailure(addr)
	second := h.service.reconnectSnapshot(addr)
	if got := second.nextRetry.Sub(currentTime); got != 100*time.Millisecond {
		t.Fatalf("second backoff=%s, want 100ms", got)
	}

	currentTime = currentTime.Add(100 * time.Millisecond)
	h.service.recordDialFailure(addr)
	third := h.service.reconnectSnapshot(addr)
	if got := third.nextRetry.Sub(currentTime); got != 200*time.Millisecond {
		t.Fatalf("third backoff=%s, want 200ms", got)
	}
}

func overrideReconnectTiming(loopInterval, baseDelay, maxDelay time.Duration) func() {
	prevLoop := reconnectLoopInterval
	prevBase := reconnectBaseDelay
	prevMax := reconnectMaxDelay
	reconnectLoopInterval = loopInterval
	reconnectBaseDelay = baseDelay
	reconnectMaxDelay = maxDelay
	return func() {
		reconnectLoopInterval = prevLoop
		reconnectBaseDelay = prevBase
		reconnectMaxDelay = prevMax
	}
}
