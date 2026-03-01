package consensus

import "testing"

func TestFeatureBits_SingleStepNoDoubleTransition(t *testing.T) {
	d := FeatureBitDeployment{
		Name:          "X",
		Bit:           0,
		StartHeight:   0,
		TimeoutHeight: SIGNAL_WINDOW * 10,
	}

	// Window 0 signals above threshold; at boundary 0 we still must only enter STARTED.
	counts := make([]uint32, 2)
	counts[0] = SIGNAL_THRESHOLD

	ev0, err := FeatureBitStateAtHeightFromWindowCounts(d, 0, counts[:0])
	if err != nil {
		t.Fatalf("ev0: %v", err)
	}
	if ev0.State != FEATUREBIT_STARTED {
		t.Fatalf("expected STARTED at h=0 boundary; got %s", ev0.State)
	}

	ev1, err := FeatureBitStateAtHeightFromWindowCounts(d, SIGNAL_WINDOW, counts[:1])
	if err != nil {
		t.Fatalf("ev1: %v", err)
	}
	if ev1.State != FEATUREBIT_LOCKED_IN {
		t.Fatalf("expected LOCKED_IN at h=W; got %s", ev1.State)
	}
}

func TestFeatureBits_LockInWinsOverTimeout(t *testing.T) {
	d := FeatureBitDeployment{
		Name:          "X",
		Bit:           0,
		StartHeight:   0,
		TimeoutHeight: SIGNAL_WINDOW, // timeout at first boundary after STARTED
	}
	counts := []uint32{SIGNAL_THRESHOLD}

	ev, err := FeatureBitStateAtHeightFromWindowCounts(d, SIGNAL_WINDOW, counts)
	if err != nil {
		t.Fatalf("eval: %v", err)
	}
	if ev.State != FEATUREBIT_LOCKED_IN {
		t.Fatalf("expected LOCKED_IN (lock-in wins), got %s", ev.State)
	}
}

func TestFeatureBits_TimeoutToFailed(t *testing.T) {
	d := FeatureBitDeployment{
		Name:          "X",
		Bit:           0,
		StartHeight:   0,
		TimeoutHeight: SIGNAL_WINDOW,
	}
	counts := []uint32{0}

	ev, err := FeatureBitStateAtHeightFromWindowCounts(d, SIGNAL_WINDOW, counts)
	if err != nil {
		t.Fatalf("eval: %v", err)
	}
	if ev.State != FEATUREBIT_FAILED {
		t.Fatalf("expected FAILED, got %s", ev.State)
	}
}

func TestFeatureBits_LockedInToActiveAfterOneWindow(t *testing.T) {
	d := FeatureBitDeployment{
		Name:          "X",
		Bit:           0,
		StartHeight:   0,
		TimeoutHeight: SIGNAL_WINDOW * 10,
	}
	counts := []uint32{SIGNAL_THRESHOLD, 0}

	evLocked, err := FeatureBitStateAtHeightFromWindowCounts(d, SIGNAL_WINDOW, counts[:1])
	if err != nil {
		t.Fatalf("locked: %v", err)
	}
	if evLocked.State != FEATUREBIT_LOCKED_IN {
		t.Fatalf("expected LOCKED_IN, got %s", evLocked.State)
	}

	evActive, err := FeatureBitStateAtHeightFromWindowCounts(d, 2*SIGNAL_WINDOW, counts[:2])
	if err != nil {
		t.Fatalf("active: %v", err)
	}
	if evActive.State != FEATUREBIT_ACTIVE {
		t.Fatalf("expected ACTIVE, got %s", evActive.State)
	}
}

func TestFeatureBits_StateBetweenBoundaries(t *testing.T) {
	d := FeatureBitDeployment{
		Name:          "X",
		Bit:           0,
		StartHeight:   0,
		TimeoutHeight: SIGNAL_WINDOW * 10,
	}
	counts := []uint32{0, 0}

	ev, err := FeatureBitStateAtHeightFromWindowCounts(d, SIGNAL_WINDOW+123, counts[:1])
	if err != nil {
		t.Fatalf("eval: %v", err)
	}
	if ev.BoundaryHeight != SIGNAL_WINDOW {
		t.Fatalf("expected boundary height W, got %d", ev.BoundaryHeight)
	}
	if ev.State != FEATUREBIT_STARTED {
		t.Fatalf("expected STARTED, got %s", ev.State)
	}
}

func TestFeatureBits_BitRange(t *testing.T) {
	d := FeatureBitDeployment{
		Name:          "X",
		Bit:           32,
		StartHeight:   0,
		TimeoutHeight: 1,
	}
	_, err := FeatureBitStateAtHeightFromWindowCounts(d, 0, nil)
	if err == nil {
		t.Fatalf("expected error")
	}
}
