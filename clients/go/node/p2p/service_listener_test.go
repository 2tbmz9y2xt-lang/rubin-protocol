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
