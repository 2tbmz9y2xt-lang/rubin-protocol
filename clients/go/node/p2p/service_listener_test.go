package p2p

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"
)

func TestNextAcceptErrorBackoff(t *testing.T) {
	cases := []struct {
		name    string
		current time.Duration
		want    time.Duration
	}{
		{"zero resets to init", 0, acceptErrorBackoffInit},
		{"negative resets to init", -1 * time.Millisecond, acceptErrorBackoffInit},
		{"init doubles to 200ms", acceptErrorBackoffInit, 200 * time.Millisecond},
		{"200ms doubles to 400ms", 200 * time.Millisecond, 400 * time.Millisecond},
		{"400ms doubles to 800ms", 400 * time.Millisecond, 800 * time.Millisecond},
		{"800ms doubles to 1600ms", 800 * time.Millisecond, 1600 * time.Millisecond},
		{"1600ms doubles to 3200ms", 1600 * time.Millisecond, 3200 * time.Millisecond},
		{"3200ms clamps to cap", 3200 * time.Millisecond, acceptErrorBackoffCap},
		{"cap stays at cap", acceptErrorBackoffCap, acceptErrorBackoffCap},
		{"overshoot clamps to cap", 10 * time.Second, acceptErrorBackoffCap},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got := nextAcceptErrorBackoff(tc.current)
			if got != tc.want {
				t.Fatalf("nextAcceptErrorBackoff(%s)=%s want %s", tc.current, got, tc.want)
			}
		})
	}
}

func TestIsAcceptLoopTerminalCtxCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	someErr := errors.New("temporary accept failure")
	if !isAcceptLoopTerminal(ctx, someErr) {
		t.Fatalf("cancelled ctx should make error terminal")
	}
}

func TestIsAcceptLoopTerminalErrClosed(t *testing.T) {
	// Plain net.ErrClosed returned by a closed listener.
	if !isAcceptLoopTerminal(context.Background(), net.ErrClosed) {
		t.Fatalf("net.ErrClosed should be terminal with live ctx")
	}
	// Wrapped net.ErrClosed (e.g. OpError wrapping) still unwraps to terminal.
	wrapped := fmt.Errorf("accept: %w", net.ErrClosed)
	if !isAcceptLoopTerminal(context.Background(), wrapped) {
		t.Fatalf("wrapped net.ErrClosed should be terminal")
	}
}

func TestIsAcceptLoopTerminalNonTerminal(t *testing.T) {
	if isAcceptLoopTerminal(context.Background(), errors.New("EMFILE")) {
		t.Fatalf("random error with live ctx should not be terminal")
	}
	// Nil context with a transient error is also non-terminal — Start() sets
	// s.ctx before acceptLoop runs, but the helper must tolerate a nil ctx.
	if isAcceptLoopTerminal(nil, errors.New("transient")) {
		t.Fatalf("nil ctx with transient error should not be terminal")
	}
}

func TestSleepOrStopZeroDuration(t *testing.T) {
	s := &Service{}
	if !s.sleepOrStop(0) {
		t.Fatalf("sleepOrStop(0) must return true")
	}
	if !s.sleepOrStop(-1 * time.Second) {
		t.Fatalf("sleepOrStop(-1s) must return true")
	}
}

func TestSleepOrStopCancelledCtx(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s := &Service{ctx: ctx}
	start := time.Now()
	if s.sleepOrStop(5 * time.Second) {
		t.Fatalf("sleepOrStop with cancelled ctx must return false")
	}
	if elapsed := time.Since(start); elapsed >= 1*time.Second {
		t.Fatalf("sleepOrStop should return promptly on cancelled ctx, elapsed=%s", elapsed)
	}
}

func TestSleepOrStopLiveCtxElapses(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := &Service{ctx: ctx}
	start := time.Now()
	if !s.sleepOrStop(5 * time.Millisecond) {
		t.Fatalf("sleepOrStop(5ms) with live ctx must return true")
	}
	if elapsed := time.Since(start); elapsed < 5*time.Millisecond {
		t.Fatalf("sleepOrStop(5ms) returned too early: %s", elapsed)
	}
}

func TestSleepOrStopNilReceiver(t *testing.T) {
	var s *Service
	if !s.sleepOrStop(0) {
		t.Fatalf("sleepOrStop on nil service with d=0 must return true")
	}
	// Non-zero duration on nil receiver falls back to plain time.Sleep; use a
	// short duration to keep the test fast but still exercise the branch.
	start := time.Now()
	if !s.sleepOrStop(2 * time.Millisecond) {
		t.Fatalf("sleepOrStop(2ms) on nil service must return true")
	}
	if elapsed := time.Since(start); elapsed < 2*time.Millisecond {
		t.Fatalf("sleepOrStop(2ms) on nil service returned too early: %s", elapsed)
	}
}

// Service lifecycle tests: the single-use contract. Start must refuse to
// restart a Service whose closed flag is set, Close must set the flag, and
// Addr must fall back to the configured bind address once the Service is
// closed (the stale listener reference is no longer a valid endpoint).

func TestService_StartAfterClose_ReturnsAlreadyClosed(t *testing.T) {
	// Simulate the post-Close state directly: the closed flag is set. Start
	// must reject the restart with "service already closed" before touching
	// net.Listen, so no real bind is needed.
	s := &Service{closed: true}
	err := s.Start(context.Background())
	if err == nil {
		t.Fatalf("Start() on closed Service must return error, got nil")
	}
	if err.Error() != "service already closed" {
		t.Fatalf("Start() on closed Service: err=%q want %q", err.Error(), "service already closed")
	}
}

func TestService_StartAlreadyStarted_ReturnsAlreadyStarted(t *testing.T) {
	// A live listener (closed=false) should still produce the original
	// "service already started" error to preserve the previous contract for
	// this distinct case.
	ln, lerr := net.Listen("tcp", "127.0.0.1:0")
	if lerr != nil {
		t.Fatalf("net.Listen: %v", lerr)
	}
	defer func() { _ = ln.Close() }()
	s := &Service{listener: ln}
	err := s.Start(context.Background())
	if err == nil {
		t.Fatalf("Start() on running Service must return error, got nil")
	}
	if err.Error() != "service already started" {
		t.Fatalf("Start() on running Service: err=%q want %q", err.Error(), "service already started")
	}
}

func TestService_StartNilReceiver(t *testing.T) {
	var s *Service
	err := s.Start(context.Background())
	if err == nil || err.Error() != "nil service" {
		t.Fatalf("Start() on nil receiver: err=%v want %q", err, "nil service")
	}
}

func TestService_CloseSetsClosedFlag(t *testing.T) {
	// Zero-value Service has no goroutines, no listener, no cancel — Close
	// completes immediately and must leave closed=true so a subsequent Start
	// is rejected. This isolates the flag transition from the full shutdown
	// path that requires a running accept loop.
	s := &Service{}
	if err := s.Close(); err != nil {
		t.Fatalf("Close() on zero-value Service: %v", err)
	}
	s.peersMu.RLock()
	closed := s.closed
	s.peersMu.RUnlock()
	if !closed {
		t.Fatalf("Close() did not set closed=true")
	}
	// Verify the flag transition blocks Start.
	if err := s.Start(context.Background()); err == nil || err.Error() != "service already closed" {
		t.Fatalf("Start() after Close(): err=%v want %q", err, "service already closed")
	}
}

func TestService_CloseNilReceiverIsNoOp(t *testing.T) {
	var s *Service
	if err := s.Close(); err != nil {
		t.Fatalf("Close() on nil receiver: %v", err)
	}
}

func TestService_AddrReturnsCachedBoundAddrWhenRunning(t *testing.T) {
	cfg := ServiceConfig{BindAddr: "ignored:9999"}
	// Simulate a successful Start that cached the resolved listener
	// endpoint in boundAddr. Addr must prefer the cached value over the
	// configured bind address so the caller sees the concrete port.
	s := &Service{cfg: cfg, boundAddr: "127.0.0.1:43219"}
	if got, want := s.Addr(), "127.0.0.1:43219"; got != want {
		t.Fatalf("Addr() running: %q want %q", got, want)
	}
}

func TestService_AddrReturnsCachedBoundAddrAfterClose(t *testing.T) {
	// Post-Close: the listener net.Listener itself has been closed and
	// may be nil'd by a future cleanup, but boundAddr cache is retained
	// from Start. Addr must still return the resolved concrete port — not
	// the raw configured bind address — so log/metric tags stay stable
	// across the whole lifecycle. This is the LOW fix from #1131 codex
	// exec review: wildcard / ":0" binds used to lose the resolved port
	// once the Service flipped to closed=true.
	cfg := ServiceConfig{BindAddr: ":0"}
	s := &Service{cfg: cfg, boundAddr: "127.0.0.1:43219", closed: true}
	if got, want := s.Addr(), "127.0.0.1:43219"; got != want {
		t.Fatalf("Addr() after Close: %q want %q", got, want)
	}
}

func TestService_AddrNoBoundAddrFallsBackToConfigBindAddr(t *testing.T) {
	// Pre-Start (or after a failed Start that never published the
	// listener): boundAddr is the zero value. Addr must fall back to the
	// configured bind address.
	cfg := ServiceConfig{BindAddr: "pending:2222"}
	s := &Service{cfg: cfg}
	if got, want := s.Addr(), "pending:2222"; got != want {
		t.Fatalf("Addr() pre-Start: %q want %q", got, want)
	}
}

func TestService_AddrNilReceiverReturnsEmpty(t *testing.T) {
	var s *Service
	if got := s.Addr(); got != "" {
		t.Fatalf("Addr() on nil receiver: %q want %q", got, "")
	}
}
