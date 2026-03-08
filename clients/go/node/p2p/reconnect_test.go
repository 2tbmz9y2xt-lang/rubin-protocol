package p2p

import (
	"context"
	"net"
	"slices"
	"sync/atomic"
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

func TestReconnectHelpers(t *testing.T) {
	restore := overrideReconnectTiming(50*time.Millisecond, 50*time.Millisecond, 200*time.Millisecond)
	defer restore()

	currentTime := time.Unix(1_777_000_100, 0)
	h := newTestHarness(t, 0, "127.0.0.1:0", []string{" 127.0.0.1:19001 ", "127.0.0.1:19001"})
	h.service.cfg.Now = func() time.Time { return currentTime }

	if got := h.service.outboundAddrsSnapshot(); !slices.Equal(got, []string{"127.0.0.1:19001"}) {
		t.Fatalf("outboundAddrsSnapshot=%v", got)
	}

	h.service.ensureOutboundAddr("127.0.0.1:19002")
	h.service.ensureOutboundAddr("127.0.0.1:19002")
	if got := h.service.outboundAddrsSnapshot(); !slices.Equal(got, []string{"127.0.0.1:19001", "127.0.0.1:19002"}) {
		t.Fatalf("ensureOutboundAddr snapshot=%v", got)
	}

	if h.service.isReconnectDue("", currentTime) {
		t.Fatalf("empty addr must not be due")
	}
	h.service.scheduleReconnect("127.0.0.1:19002")
	if !h.service.isReconnectDue("127.0.0.1:19002", currentTime.Add(50*time.Millisecond)) {
		t.Fatalf("addr should become due after scheduled backoff")
	}
	h.service.resetReconnect("127.0.0.1:19002")
	if snap := h.service.reconnectSnapshot("127.0.0.1:19002"); snap.failures != 0 || !snap.nextRetry.IsZero() {
		t.Fatalf("reset snapshot=%+v", snap)
	}
}

func TestReconnectBackoffCapsAtMax(t *testing.T) {
	restore := overrideReconnectTiming(50*time.Millisecond, 50*time.Millisecond, 200*time.Millisecond)
	defer restore()

	if got := reconnectBackoff(10); got != 200*time.Millisecond {
		t.Fatalf("reconnectBackoff(10)=%s, want 200ms", got)
	}
	if got := reconnectBackoff(-1); got != 50*time.Millisecond {
		t.Fatalf("reconnectBackoff(-1)=%s, want 50ms", got)
	}
}

func TestDialPeerFailureRecordsReconnect(t *testing.T) {
	restore := overrideReconnectTiming(50*time.Millisecond, 50*time.Millisecond, 200*time.Millisecond)
	defer restore()

	currentTime := time.Unix(1_777_000_200, 0)
	h := newTestHarness(t, 0, "127.0.0.1:0", nil)
	h.service.cfg.Now = func() time.Time { return currentTime }
	h.service.ctx = context.Background()
	h.service.loopWG.Add(1)
	h.service.dialPeer("127.0.0.1:1")

	snap := h.service.reconnectSnapshot("127.0.0.1:1")
	if snap.failures != 1 {
		t.Fatalf("failures=%d, want 1", snap.failures)
	}
	if got := snap.nextRetry.Sub(currentTime); got != 50*time.Millisecond {
		t.Fatalf("nextRetry delta=%s, want 50ms", got)
	}
}

func TestReconnectDuePeersSkipsConnectedAndNotDue(t *testing.T) {
	restore := overrideReconnectTiming(50*time.Millisecond, 50*time.Millisecond, 200*time.Millisecond)
	defer restore()

	currentTime := time.Unix(1_777_000_250, 0)
	h := newTestHarness(t, 0, "127.0.0.1:0", []string{" peer-a ", "peer-b"})
	h.service.cfg.Now = func() time.Time { return currentTime }

	h.service.peers["peer-a"] = &peer{service: h.service, state: node.PeerState{Addr: "peer-a"}}
	h.service.scheduleNextReconnectAttempt("peer-b", currentTime.Add(100*time.Millisecond))
	before := h.service.reconnectSnapshot("peer-b")
	h.service.reconnectDuePeers()
	after := h.service.reconnectSnapshot("peer-b")
	if after != before {
		t.Fatalf("unexpected reconnect state mutation for not-due peer: before=%+v after=%+v", before, after)
	}
}

func TestReconnectDuePeersDialsDuePeer(t *testing.T) {
	restore := overrideReconnectTiming(50*time.Millisecond, 50*time.Millisecond, 200*time.Millisecond)
	defer restore()

	currentTime := time.Unix(1_777_000_275, 0)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	var accepted atomic.Int32
	acceptedDone := make(chan struct{})
	go func() {
		defer close(acceptedDone)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		accepted.Add(1)
		defer conn.Close()
		time.Sleep(150 * time.Millisecond)
	}()

	h := newTestHarness(t, 0, "127.0.0.1:0", []string{listener.Addr().String()})
	h.service.cfg.Now = func() time.Time { return currentTime }
	h.service.ctx = context.Background()
	h.service.scheduleReconnect(listener.Addr().String())
	currentTime = currentTime.Add(50 * time.Millisecond)

	h.service.reconnectDuePeers()
	<-acceptedDone
	if got := accepted.Load(); got != 1 {
		t.Fatalf("accepted=%d, want 1", got)
	}
}

func TestReconnectNilAndEmptyHelpers(t *testing.T) {
	var svc *Service
	svc.reconnectDuePeers()
	if got := svc.reconnectSnapshot("addr"); got != (reconnectEntry{}) {
		t.Fatalf("reconnectSnapshot(nil)=%+v", got)
	}
	if got := svc.isConnected("addr"); got {
		t.Fatalf("isConnected(nil)=true, want false")
	}
	if ok := svc.withReconnectEntry("", func(*reconnectEntry) {}); ok {
		t.Fatalf("withReconnectEntry(empty) unexpectedly succeeded")
	}
	if got := normalizeReconnectAddr("  "); got != "" {
		t.Fatalf("normalizeReconnectAddr(blank)=%q, want empty", got)
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
