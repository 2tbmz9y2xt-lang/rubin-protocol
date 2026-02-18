//go:build wolfcrypt_dylib

package crypto

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

// TestHSMMonitor_NormalToReadOnly verifies that 3 consecutive failures
// cause a NORMAL→READ_ONLY transition.
func TestHSMMonitor_NormalToReadOnly(t *testing.T) {
	var calls atomic.Int32
	check := func() error {
		calls.Add(1)
		return errors.New("hsm unavailable")
	}

	cfg := HSMConfig{
		HealthInterval:  1 * time.Millisecond,
		FailThreshold:   3,
		FailoverTimeout: 0, // disabled so we don't reach FAILED in this test
	}

	mon := NewHSMMonitor(cfg, check, nil)
	if mon.State() != HSMStateNormal {
		t.Fatal("expected initial state NORMAL")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	go mon.Run(ctx)

	// Wait until fail_count reaches threshold
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if mon.State() == HSMStateReadOnly {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	if mon.State() != HSMStateReadOnly {
		t.Fatalf("expected READ_ONLY after %d failures, got %s", cfg.FailThreshold, mon.State())
	}
	if mon.CanSign() {
		t.Error("CanSign must be false in READ_ONLY state")
	}
}

// TestHSMMonitor_Recovery verifies NORMAL→READ_ONLY→NORMAL recovery.
func TestHSMMonitor_Recovery(t *testing.T) {
	var fail atomic.Bool
	fail.Store(true)

	check := func() error {
		if fail.Load() {
			return errors.New("hsm unavailable")
		}
		return nil
	}

	cfg := HSMConfig{
		HealthInterval:  2 * time.Millisecond,
		FailThreshold:   3,
		FailoverTimeout: 0,
	}

	mon := NewHSMMonitor(cfg, check, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	go mon.Run(ctx)

	// Wait for READ_ONLY
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if mon.State() == HSMStateReadOnly {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if mon.State() != HSMStateReadOnly {
		t.Fatal("did not reach READ_ONLY")
	}

	// Restore HSM
	fail.Store(false)

	// Wait for NORMAL
	deadline = time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if mon.State() == HSMStateNormal {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if mon.State() != HSMStateNormal {
		t.Fatalf("expected recovery to NORMAL, got %s", mon.State())
	}
	if !mon.CanSign() {
		t.Error("CanSign must be true in NORMAL state")
	}
}

// TestHSMMonitor_FailoverTimeout verifies READ_ONLY→FAILED after timeout.
func TestHSMMonitor_FailoverTimeout(t *testing.T) {
	failedCalled := make(chan struct{}, 1)

	check := func() error { return errors.New("hsm unavailable") }
	onFailed := func() { failedCalled <- struct{}{} }

	cfg := HSMConfig{
		HealthInterval:  2 * time.Millisecond,
		FailThreshold:   2,
		FailoverTimeout: 20 * time.Millisecond,
	}

	mon := NewHSMMonitor(cfg, check, onFailed)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	go mon.Run(ctx)

	select {
	case <-failedCalled:
		// good
	case <-time.After(1 * time.Second):
		t.Fatal("onFailed was not called within timeout")
	}

	if mon.State() != HSMStateFailed {
		t.Fatalf("expected FAILED state, got %s", mon.State())
	}
}

// TestHSMMonitor_CanSign verifies CanSign semantics across states.
func TestHSMMonitor_CanSign(t *testing.T) {
	mon := &HSMMonitor{}
	mon.state.Store(int32(HSMStateNormal))
	if !mon.CanSign() {
		t.Error("NORMAL: CanSign must be true")
	}
	mon.state.Store(int32(HSMStateReadOnly))
	if mon.CanSign() {
		t.Error("READ_ONLY: CanSign must be false")
	}
	mon.state.Store(int32(HSMStateFailed))
	if mon.CanSign() {
		t.Error("FAILED: CanSign must be false")
	}
}
