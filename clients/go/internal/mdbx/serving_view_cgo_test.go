//go:build cgo && (darwin || linux) && (amd64 || arm64)

package mdbx

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"
)

// TestServingViewV1 owns synchronous serving admission, actual native cleanup,
// priority and external-span behavior. Peer/Service integration belongs to 1672.
func TestServingViewV1(t *testing.T) {
	for _, test := range []struct {
		name string
		run  func(*testing.T)
	}{
		{"A1", servingQualifiedV1}, {"A2", servingLastUseV1},
		{"A3", servingExpiryV1}, {"A4", servingPriorityV1},
		{"A5", servingNewerPriorityV1}, {"A6", servingOwnedCopyV1},
		{"A7", servingSpanV1}, {"A8", servingOptionalV1},
		{"R1", servingAdmissionV1}, {"R2", servingNoReadV1},
		{"R3", servingInputOrderV1}, {"R4", servingEscapeV1},
		{"R5", servingEarlierResultV1}, {"H1", servingUnwindV1},
		{"H2", servingReplacementV1}, {"H3", servingOwnedCopyFailureV1},
	} {
		t.Run(test.name, test.run)
	}
}

// servingSetupV1 uses a real format-2 native Store and the existing reservation owner.
func servingSetupV1(t *testing.T) (*Store, *ServingViewOwnerV1, *OperationReservationOwner) {
	t.Helper()
	s, err := Create(filepath.Join(t.TempDir(), "db"), environmentConfig())
	mustEnvironment(t, err)
	t.Cleanup(func() { _ = s.Close() })
	o, err := NewServingViewOwnerV1(time.Hour)
	mustEnvironment(t, err)
	return s, o, reservationOwner(t, 805306368)
}

// servingCallV1 keeps the authentic LaneOperation open through actual View cleanup.
func servingCallV1(t *testing.T, o *ServingViewOwnerV1, s *Store, reservations *OperationReservationOwner, use func(*Reader, *ServingEpochV1, *OperationAccount) error) (out ServingViewOutcomeV1, err error) {
	t.Helper()
	err = reservations.WithOperation(LaneOperation, func(a *OperationAccount) error {
		out, err = o.WithViewV1(context.Background(), s, a, func(r *Reader, e *ServingEpochV1) error { return use(r, e, a) })
		return err
	})
	return out, err
}

// servingWantOutcomeV1 pins the public finite disposition independently of production constants.
func servingWantOutcomeV1(t *testing.T, out ServingViewOutcomeV1, end uint8, ended bool) {
	t.Helper()
	if uint8(out.ReadEndV1()) != end || out.EligibilityEndedV1() != ended {
		t.Fatalf("read end/eligibility = %d/%v, want %d/%v", out.ReadEndV1(), out.EligibilityEndedV1(), end, ended)
	}
}

// servingWantBusyV1 checks all fields of the fixed refusal tuple.
func servingWantBusyV1(t *testing.T, err error, operation string) {
	t.Helper()
	e := requireEnvironmentError(t, err, EngineClass("Concurrency"), engineOperation(operation), -30778, "store operation in progress")
	if e.Cause != nil || e.ReopenRequired || e.TreeObservation != nil {
		t.Fatalf("busy payload drifted: %+v", e)
	}
}

// servingWantInputV1 checks the independent fixed local input tuple.
func servingWantInputV1(t *testing.T, err error, operation string) {
	t.Helper()
	e := requireEnvironmentError(t, err, EngineClass("InvalidInput"), engineOperation(operation), 22, "invalid serving view input")
	if e.Cause != nil || e.ReopenRequired || e.TreeObservation != nil {
		t.Fatalf("input payload drifted: %+v", e)
	}
}

// servingRefusedV1 proves no callback, read or reservation effect on admission refusal.
func servingRefusedV1(t *testing.T, o *ServingViewOwnerV1, s *Store, reservations *OperationReservationOwner) {
	t.Helper()
	before := reservationLive(reservations)
	out, err := servingCallV1(t, o, s, reservations, func(*Reader, *ServingEpochV1, *OperationAccount) error {
		t.Fatal("refused serving callback executed")
		return nil
	})
	servingWantBusyV1(t, err, "view")
	servingWantOutcomeV1(t, out, 0, false)
	if reservationLive(reservations) != before {
		t.Fatal("refusal changed live reservations")
	}
}

// servingQualifiedV1 qualifies actual same-Reader APPLIED/current and STABLE/LAG roles.
func servingQualifiedV1(t *testing.T) {
	for _, lifetime := range []time.Duration{time.Hour, time.Duration(math.MaxInt64)} {
		t.Run(lifetime.String(), func(t *testing.T) { servingQualifiedLifetimeV1(t, lifetime) })
	}
}

// servingQualifiedLifetimeV1 keeps qualification and refused requests on the original clock.
func servingQualifiedLifetimeV1(t *testing.T, lifetime time.Duration) {
	s, _, reservations := tsNew(t)
	current := treeRoleBuildV1(t, 1, treeRoleAppliedV1)
	current.seedV1(t, s, reservations, false)
	treeRoleAssuredV1(t, s, reservations, 2, nil)
	o, err := NewServingViewOwnerV1(lifetime)
	mustEnvironment(t, err)
	var previous *ServingEpochV1
	for range 2 {
		out, callErr := servingCallV1(t, o, s, reservations, func(r *Reader, e *ServingEpochV1, a *OperationAccount) error {
			mustEnvironment(t, e.CheckV1())
			opened := e.opened
			authority, found, authorityErr := r.ReadTreeAuthorityV1()
			mustEnvironment(t, authorityErr)
			if !found || authority.Authority.ActiveGenerationID != 1 || authority.LagGenerationID != 2 {
				t.Fatal("actual selected source authority changed")
			}
			early, qualified, _ := treeRoleFullChainV1(t, r, a, authority)
			if early.HealthyOn(r) || !qualified.HealthyOn(r) || e == previous || r.databaseID != ([32]byte{7}) || r.format != 3 {
				t.Fatal("same-snapshot qualification/epoch identity")
			}
			if e.opened != opened || o.lifetime != lifetime {
				t.Fatal("qualification renewed the original opening/lifetime")
			}
			servingRefusedV1(t, o, s, reservations)
			if o.lifetime != lifetime || e.opened != opened {
				t.Fatal("second request renewed the occupied original epoch")
			}
			o.mu.Lock()
			atBoundary := e.endedV1(lifetime)
			o.mu.Unlock()
			if atBoundary {
				t.Fatal("original lifetime equality refused an admitted unit")
			}
			previous = e
			return e.CheckV1()
		})
		mustEnvironment(t, callErr)
		servingWantOutcomeV1(t, out, 1, false)
		servingWantInputV1(t, previous.CheckV1(), "view")
	}
}

// servingLastUseV1 crosses ordinary application results with actual clean native closure.
func servingLastUseV1(t *testing.T) {
	var typed *nilPointerError
	direct := errors.New("application result")
	for _, app := range []error{nil, direct, typed, fmt.Errorf("wrapped application: %w", direct)} {
		t.Run(fmt.Sprintf("%T/%v", app, app), func(t *testing.T) {
			s, o, reservations := servingSetupV1(t)
			var reader *Reader
			out, err := servingCallV1(t, o, s, reservations, func(r *Reader, e *ServingEpochV1, a *OperationAccount) error {
				reader = r
				return a.WithReservation(7, func() error {
					if reservationLive(reservations) != 7 || !r.usable() || r.txn == nil {
						t.Fatal("native/account ownership released before last use")
					}
					_, found, getErr := r.Get(readDBIsLiteral()[0], []byte{0})
					mustEnvironment(t, getErr)
					if !found {
						t.Fatal("real schema row missing")
					}
					mustEnvironment(t, e.CheckV1())
					return app
				})
			})
			if !sameError(err, app) || reader.usable() || reader.active.Load() || reservationLive(reservations) != 0 || s.state != storeOPEN || s.txn != nil {
				t.Fatalf("last-use/result/actual close = %v/%v/%s", err, app, s.state)
			}
			servingWantOutcomeV1(t, out, 1, false)
			next, nextErr := servingCallV1(t, o, s, reservations, func(*Reader, *ServingEpochV1, *OperationAccount) error { return nil })
			mustEnvironment(t, nextErr)
			servingWantOutcomeV1(t, next, 1, false)
		})
	}
}

// servingExpiryV1 observes equality through the pure decision and a genuinely
// expired native-backed callback through channels; the timer supplies no verdict.
func servingExpiryV1(t *testing.T) {
	s, _, reservations := servingSetupV1(t)
	o, err := NewServingViewOwnerV1(30 * time.Millisecond)
	mustEnvironment(t, err)
	entered, release, done := make(chan *ServingEpochV1, 1), make(chan struct{}), make(chan struct{})
	releaseView := sync.OnceFunc(func() { close(release) })
	defer func() {
		releaseView()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("expired callback cleanup did not finish")
		}
	}()
	var out ServingViewOutcomeV1
	var result error
	go func() {
		defer close(done)
		out, result = servingCallV1(t, o, s, reservations, func(r *Reader, e *ServingEpochV1, a *OperationAccount) error {
			return a.WithReservation(13, func() error {
				entered <- e
				select {
				case <-release:
				case <-time.After(5 * time.Second):
					t.Error("expired callback was never released")
					return nil
				}
				if time.Since(e.opened) <= o.lifetime || !r.usable() || r.txn == nil || reservationLive(reservations) != 13 {
					t.Error("expired view lost actual source/account ownership")
				}
				servingWantBusyV1(t, e.CheckV1(), "view")
				o.mu.Lock()
				occupied := o.current == e
				o.mu.Unlock()
				if !occupied || !r.usable() || r.txn == nil || reservationLive(reservations) != 13 {
					t.Error("expired Check released the occupied native/account owner")
				}
				_, found, readErr := r.Get(readDBIsLiteral()[0], []byte{0})
				if readErr != nil || !found {
					t.Error("logical expiry forcibly expired the real Reader")
				}
				return nil
			})
		})
	}()
	var e *ServingEpochV1
	select {
	case e = <-entered:
	case <-done:
		t.Fatalf("snapshot callback never entered: %v", result)
	case <-time.After(5 * time.Second):
		t.Fatal("snapshot callback admission did not finish")
	}
	o.mu.Lock()
	if e.endedV1(o.lifetime) || !e.endedV1(o.lifetime+time.Nanosecond) {
		t.Error("deadline equality/strictly-later decision")
	}
	o.mu.Unlock()
	timer := time.NewTimer(o.lifetime - time.Since(e.opened) + time.Millisecond)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-time.After(5 * time.Second):
		t.Fatal("original finite deadline did not arrive")
	}
	servingRefusedV1(t, o, s, reservations)
	o.mu.Lock()
	occupied := o.current == e
	o.mu.Unlock()
	if reservationLive(reservations) != 13 || !occupied {
		t.Error("expiry released the occupied borrow")
	}
	releaseView()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("expired callback actual cleanup did not finish")
	}
	mustEnvironment(t, result)
	servingWantOutcomeV1(t, out, 1, true)
	if reservationLive(reservations) != 0 || o.current != nil {
		t.Fatal("actual cleanup retained a consumed borrow")
	}
}

// servingPriorityV1 covers all three published optional native entry owners.
func servingPriorityV1(t *testing.T) {
	for _, route := range []string{"update", "tree", "close"} {
		t.Run(route, func(t *testing.T) { servingPriorityRouteV1(t, route) })
	}
	t.Run("first binding", servingFirstBindingV1)
}

// servingFirstBindingV1 tests the contention effect with an actual nil observation
// before public binding. Direct source review binds all three native adapters to
// this effect; the narrow public preemption window is not scheduled by this test.
func servingFirstBindingV1(t *testing.T) {
	s, o, reservations := servingSetupV1(t)
	initial := s.requestServingCloseV1()
	if initial != nil {
		t.Fatal("unbound Store unexpectedly supplied a serving identity")
	}
	var pending *servingMutationV1
	out, err := servingCallV1(t, o, s, reservations, func(r *Reader, e *ServingEpochV1, _ *OperationAccount) error {
		if s.servingOwner.Load() != o || !r.usable() || r.txn == nil {
			t.Fatal("first binding did not open an actual native epoch")
		}
		if s.operations.TryLock() {
			s.operations.Unlock()
			t.Fatal("native Reader did not retain the operation lock")
		}
		s.contendedServingCloseV1(initial)
		if o.priority == nil {
			t.Fatal("nil initial observation lost first-bound contention priority")
		}
		older := o.priority
		pending = s.requestServingCloseV1()
		s.contendedServingCloseV1(older)
		if o.priority != pending {
			t.Fatal("already-marked contention replaced a newer pending identity")
		}
		servingWantBusyV1(t, e.CheckV1(), "view")
		return nil
	})
	mustEnvironment(t, err)
	servingWantOutcomeV1(t, out, 1, true)
	if o.current != nil || o.priority != pending {
		t.Fatal("actual old-view close lost the first-bound pending priority")
	}
	servingRefusedV1(t, o, s, reservations)
	servingRefusedV1(t, o, s, reservations)
	servingNativeRetryV1(t, "update", s, nil)
	if o.priority != nil {
		t.Fatal("actual retry failed to clear first-bound priority")
	}
	_, err = servingCallV1(t, o, s, reservations, func(*Reader, *ServingEpochV1, *OperationAccount) error { return nil })
	mustEnvironment(t, err)
}

// servingNativeBusyV1 pins original contention tuples and zero callback effects.
func servingNativeBusyV1(t *testing.T, route string, s *Store, a *OperationAccount) {
	t.Helper()
	called := 0
	switch route {
	case "update":
		truth, stage, err := s.Update(func(*Reader) (Batch, error) {
			called++
			return Batch{}, nil
		})
		if truth != 1 || stage != 1 {
			t.Fatalf("Update tuple %d/%d", truth, stage)
		}
		servingWantBusyV1(t, err, "update")
	case "tree":
		truth, stage, index, err := s.UpdateTreeV1(a, func(*Reader) (TreeOperationV1, error) {
			called++
			return TreeOperationV1{}, nil
		})
		if truth != 1 || stage != 1 || index != -1 {
			t.Fatalf("tree tuple %d/%d/%d", truth, stage, index)
		}
		servingWantBusyV1(t, err, "update")
	case "close":
		servingWantBusyV1(t, s.Close(), "close")
	}
	if called != 0 {
		t.Fatal("native contention invoked callback")
	}
}

// servingNativeRetryV1 reaches the original lock and an actual native callback or Close.
func servingNativeRetryV1(t *testing.T, route string, s *Store, a *OperationAccount) {
	t.Helper()
	app := errors.New("retry application")
	called := 0
	switch route {
	case "update":
		truth, stage, err := s.Update(func(*Reader) (Batch, error) {
			called++
			return Batch{}, app
		})
		if truth != 1 || stage != 1 || !sameError(err, app) {
			t.Fatalf("retry Update %d/%d/%v", truth, stage, err)
		}
	case "tree":
		truth, stage, index, err := s.UpdateTreeV1(a, func(*Reader) (TreeOperationV1, error) {
			called++
			return TreeOperationV1{}, app
		})
		if truth != 1 || stage != 1 || index != -1 || !sameError(err, app) {
			t.Fatalf("retry tree %d/%d/%d/%v", truth, stage, index, err)
		}
	case "close":
		mustEnvironment(t, s.Close())
		if s.state != storeCLOSED || s.env != nil || s.txn != nil {
			t.Fatal("Close retry did not actually consume")
		}
		return
	}
	if called != 1 {
		t.Fatal("priority introduced a native callback refusal")
	}
}

// servingPriorityRouteV1 proves contention leaves a mark through old-view cleanup.
func servingPriorityRouteV1(t *testing.T, route string) {
	s, o, reservations := servingSetupV1(t)
	if route == "tree" {
		s, _, reservations = tsNew(t)
	}
	out, err := servingCallV1(t, o, s, reservations, func(r *Reader, e *ServingEpochV1, a *OperationAccount) error {
		servingNativeBusyV1(t, route, s, a)
		servingWantBusyV1(t, e.CheckV1(), "view")
		if !r.usable() || r.txn == nil {
			t.Fatal("optional closure forced native read close")
		}
		servingRefusedV1(t, o, s, reservations)
		return nil
	})
	mustEnvironment(t, err)
	servingWantOutcomeV1(t, out, 1, true)
	servingRefusedV1(t, o, s, reservations)
	servingRefusedV1(t, o, s, reservations)
	mustEnvironment(t, reservations.WithOperation(LaneOperation, func(a *OperationAccount) error {
		servingNativeRetryV1(t, route, s, a)
		return nil
	}))
	if o.priority != nil {
		t.Fatal("matching actual retry failed to clear priority")
	}
	if route != "close" {
		_, err = servingCallV1(t, o, s, reservations, func(*Reader, *ServingEpochV1, *OperationAccount) error { return nil })
		mustEnvironment(t, err)
	}
}

// servingNewerPriorityV1 forces a newer contender before an older callback ends.
func servingNewerPriorityV1(t *testing.T) {
	s, o, reservations := servingSetupV1(t)
	_, err := servingCallV1(t, o, s, reservations, func(*Reader, *ServingEpochV1, *OperationAccount) error { return nil })
	mustEnvironment(t, err)
	app := errors.New("older callback")
	var newer *servingMutationV1
	truth, stage, result := s.Update(func(*Reader) (Batch, error) {
		older := o.priority
		servingNativeBusyV1(t, "update", s, nil)
		newer = o.priority
		if newer == nil || newer == older {
			t.Fatal("attempt identities joined")
		}
		return Batch{}, app
	})
	if truth != 1 || stage != 1 || !sameError(result, app) || o.priority != newer {
		t.Fatal("older completion cleared the newer pending identity")
	}
	servingRefusedV1(t, o, s, reservations)
	servingNativeRetryV1(t, "update", s, nil)
	_, err = servingCallV1(t, o, s, reservations, func(*Reader, *ServingEpochV1, *OperationAccount) error { return nil })
	mustEnvironment(t, err)
}

// servingOwnedCopyV1 checks the local ownership boundary; no peer or Service is simulated.
func servingOwnedCopyV1(t *testing.T) {
	s, o, reservations := servingSetupV1(t)
	network := reservationOwner(t, 805306368)
	mustEnvironment(t, network.WithReservation(4, func() error {
		var owned []byte
		out, err := servingCallV1(t, o, s, reservations, func(r *Reader, e *ServingEpochV1, _ *OperationAccount) error {
			mustEnvironment(t, e.CheckV1())
			value, found, getErr := r.Get(readDBIsLiteral()[0], []byte{0})
			if getErr != nil || !found {
				t.Fatal("schema copy failed")
			}
			owned = bytes.Clone(value)
			return e.CheckV1()
		})
		mustEnvironment(t, err)
		servingWantOutcomeV1(t, out, 1, false)
		mustEnvironment(t, s.Close())
		if !bytes.Equal(owned, []byte{0, 0, 0, 2}) || reservationLive(network) != 4 || reservationLive(reservations) != 0 {
			t.Fatal("source close changed independently owned copy/charge")
		}
		return nil
	}))
	if reservationLive(network) != 0 {
		t.Fatal("network owner's own last use did not release")
	}
}

// servingSpanV1 exercises public exclusion across a nested native adapter and its unwind.
func servingSpanV1(t *testing.T) {
	for _, mode := range []string{"nil", "error", "typed nil", "wrapped", "panic", "goexit"} {
		t.Run(mode, func(t *testing.T) { servingSpanUnwindV1(t, mode) })
	}
	t.Run("second span and newer mark", servingSpanContenderV1)
	t.Run("old view must actually end", servingSpanOldViewV1)
	t.Run("original operation contention retains priority", servingSpanOperationV1)
}

// servingSpanOperationV1 keeps priority after an actual preflight lock refusal.
func servingSpanOperationV1(t *testing.T) {
	s, o, reservations := servingSetupV1(t)
	s.operations.Lock()
	err := o.WithQuiescenceV1(context.Background(), s, func() error {
		t.Error("preflight contention executed effect")
		return nil
	})
	s.operations.Unlock()
	servingWantBusyV1(t, err, "update")
	servingRefusedV1(t, o, s, reservations)
	mustEnvironment(t, o.WithQuiescenceV1(context.Background(), s, func() error { return nil }))
	if o.priority != nil || o.span != nil {
		t.Fatal("actual preflight retry did not complete its exclusion")
	}
}

// servingModeV1 uses an independent callback result for each unwind shape.
func servingModeV1(mode string, app error) error {
	switch mode {
	case "error", "typed nil", "wrapped":
		return app
	case "panic":
		panic(app)
	case "goexit":
		runtime.Goexit()
	}
	return nil
}

// servingSpanUnwindV1 pauses at the public effect boundary without retaining a lock.
func servingSpanUnwindV1(t *testing.T, mode string) {
	s, o, reservations := servingSetupV1(t)
	var app error = errors.New("outer effect result")
	if mode == "typed nil" {
		var typed *nilPointerError
		app = typed
	}
	if mode == "wrapped" {
		app = fmt.Errorf("external wrapper: %w", app)
	}
	var result error
	var panicked any
	var returned bool
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer func() { panicked = recover() }()
		result = o.WithQuiescenceV1(context.Background(), s, func() error {
			servingRefusedV1(t, o, s, reservations)
			servingNativeRetryV1(t, "update", s, nil)
			servingRefusedV1(t, o, s, reservations)
			if o.span == nil {
				t.Error("nested native return ended outer span")
			}
			return servingModeV1(mode, app)
		})
		returned = true
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("external span callback/cleanup did not finish")
	}
	servingWantUnwindV1(t, mode, result, panicked, returned, app)
	if o.span != nil || o.priority != nil {
		t.Fatal("outer synchronous cleanup left its span")
	}
	_, err := servingCallV1(t, o, s, reservations, func(*Reader, *ServingEpochV1, *OperationAccount) error { return nil })
	mustEnvironment(t, err)
}

// servingWantUnwindV1 distinguishes exact errors, panic identity and Goexit continuation.
func servingWantUnwindV1(t *testing.T, mode string, result error, panicked any, returned bool, app error) {
	t.Helper()
	switch mode {
	case "nil":
		if !returned || result != nil || panicked != nil {
			t.Fatal("nil callback changed")
		}
	case "error", "typed nil", "wrapped":
		if !returned || !sameError(result, app) || panicked != nil {
			t.Fatal("callback error identity changed")
		}
	case "panic":
		if returned || panicked != app {
			t.Fatal("callback panic identity/continuation changed")
		}
	case "goexit":
		if returned || panicked != nil {
			t.Fatal("Goexit became a normal result or panic")
		}
	}
}

// servingSpanContenderV1 makes a second span's pending identity outlive the older span.
func servingSpanContenderV1(t *testing.T) {
	s, o, reservations := servingSetupV1(t)
	var newer *servingMutationV1
	err := o.WithQuiescenceV1(context.Background(), s, func() error {
		before := o.span
		got := o.WithQuiescenceV1(context.Background(), s, func() error {
			t.Fatal("second span callback ran")
			return nil
		})
		servingWantBusyV1(t, got, "update")
		newer = o.priority
		if o.span != before || newer == before {
			t.Fatal("second span joined or replaced the first")
		}
		return nil
	})
	mustEnvironment(t, err)
	if o.span != nil || o.priority != newer {
		t.Fatal("older span cleared a newer mark")
	}
	servingRefusedV1(t, o, s, reservations)
	mustEnvironment(t, o.WithQuiescenceV1(context.Background(), s, func() error { return nil }))
	_, err = servingCallV1(t, o, s, reservations, func(*Reader, *ServingEpochV1, *OperationAccount) error { return nil })
	mustEnvironment(t, err)
}

// servingSpanOldViewV1 proves required refusal cannot execute before real read closure.
func servingSpanOldViewV1(t *testing.T) {
	s, o, reservations := servingSetupV1(t)
	_, err := servingCallV1(t, o, s, reservations, func(r *Reader, e *ServingEpochV1, _ *OperationAccount) error {
		got := o.WithQuiescenceV1(context.Background(), s, func() error {
			t.Fatal("effect before native close")
			return nil
		})
		servingWantBusyV1(t, got, "update")
		if !r.usable() || r.txn == nil {
			t.Fatal("required refusal pretended to close the native Reader")
		}
		return nil
	})
	mustEnvironment(t, err)
	mustEnvironment(t, o.WithQuiescenceV1(context.Background(), s, func() error {
		if o.current != nil {
			t.Fatal("effect reached before consumed old borrow")
		}
		servingRefusedV1(t, o, s, reservations)
		return nil
	}))
}

// servingOptionalV1 crosses original native state/format with owner exclusion flags.
func servingOptionalV1(t *testing.T) {
	for _, route := range []string{"update", "tree", "close"} {
		for _, state := range []string{"active", "expired", "priority", "span"} {
			t.Run(route+"/"+state, func(t *testing.T) { servingOptionalRouteV1(t, route, state) })
		}
	}
	t.Run("format refusals unchanged", servingFormatV1)
	t.Run("static inputs precede marking", servingNativeInputsV1)
}

// servingNativeInputsV1 protects the existing entry-order rows while a real
// serving epoch is active, with independent native input diagnostics.
func servingNativeInputsV1(t *testing.T) {
	s, o, reservations := servingSetupV1(t)
	_, err := servingCallV1(t, o, s, reservations, func(_ *Reader, e *ServingEpochV1, _ *OperationAccount) error {
		truth, stage, result := s.Update(nil)
		if truth != 1 || stage != 1 {
			t.Fatal("nil Update callback tuple")
		}
		treeNativeError(t, result, engineOperation("update"), EngineClass("InvalidInput"), 22, "nil Update callback", nil)
		truth, stage, index, result := s.UpdateTreeV1(nil, nil)
		if truth != 1 || stage != 1 || index != -1 {
			t.Fatal("nil tree callback tuple")
		}
		treeNativeError(t, result, engineOperation("update"), EngineClass("InvalidInput"), 22, "nil UpdateTreeV1 callback", nil)
		use := func(*Reader) (TreeOperationV1, error) {
			t.Fatal("invalid account executed native callback")
			return TreeOperationV1{}, nil
		}
		for _, row := range []struct {
			account *OperationAccount
			text    string
		}{{nil, "nil operation account"}, {&OperationAccount{}, "closed operation account"}} {
			truth, stage, index, result = s.UpdateTreeV1(row.account, use)
			if truth != 1 || stage != 1 || index != -1 {
				t.Fatal("tree static account tuple")
			}
			treeNativeError(t, result, engineOperation("update"), EngineClass("InvalidInput"), 22, row.text, nil)
		}
		if o.priority != nil || e.closing {
			t.Fatal("refused static input changed serving priority")
		}
		return e.CheckV1()
	})
	mustEnvironment(t, err)
}

// servingOptionalRouteV1 demonstrates closure adds neither wait nor refusal.
func servingOptionalRouteV1(t *testing.T, route, state string) {
	s, o, reservations := servingSetupV1(t)
	if route == "tree" {
		s, _, reservations = tsNew(t)
	}
	if state == "expired" {
		var err error
		o, err = NewServingViewOwnerV1(30 * time.Millisecond)
		mustEnvironment(t, err)
	}
	if state == "span" {
		mustEnvironment(t, o.WithQuiescenceV1(context.Background(), s, func() error {
			mustEnvironment(t, reservations.WithOperation(LaneOperation, func(a *OperationAccount) error {
				servingNativeRetryV1(t, route, s, a)
				return nil
			}))
			if o.span == nil {
				t.Fatal("native completion cleared external span")
			}
			return nil
		}))
		return
	}
	out, err := servingCallV1(t, o, s, reservations, func(r *Reader, e *ServingEpochV1, a *OperationAccount) error {
		if state == "expired" {
			timer := time.NewTimer(o.lifetime - time.Since(e.opened) + time.Millisecond)
			defer timer.Stop()
			select {
			case <-timer.C:
			case <-time.After(5 * time.Second):
				t.Fatal("optional native row did not reach its finite deadline")
			}
			if time.Since(e.opened) <= o.lifetime {
				t.Fatal("expired row did not reach expiry")
			}
			servingWantBusyV1(t, e.CheckV1(), "view")
		}
		servingNativeBusyV1(t, route, s, a)
		if state == "priority" {
			servingNativeBusyV1(t, route, s, a)
		}
		if !r.usable() {
			t.Fatal("optional native closure expired Reader")
		}
		return nil
	})
	mustEnvironment(t, err)
	servingWantOutcomeV1(t, out, 1, true)
	mustEnvironment(t, reservations.WithOperation(LaneOperation, func(a *OperationAccount) error {
		servingNativeRetryV1(t, route, s, a)
		return nil
	}))
}

// servingFormatV1 preserves native format refusal before a callback is inspected.
func servingFormatV1(t *testing.T) {
	tree, _, reservations := tsNew(t)
	_, owner, _ := servingSetupV1(t)
	_, err := servingCallV1(t, owner, tree, reservations, func(*Reader, *ServingEpochV1, *OperationAccount) error { return nil })
	mustEnvironment(t, err)
	mustEnvironment(t, owner.WithQuiescenceV1(context.Background(), tree, func() error {
		truth, stage, got := tree.Update(func(*Reader) (Batch, error) {
			t.Fatal("serving flag enabled format3 legacy callback")
			return Batch{}, nil
		})
		if truth != 1 || stage != 1 {
			t.Fatal("format3 refusal changed under span")
		}
		treeNativeError(t, got, engineOperation("update"), EngineClass("StateMismatch"), -30779, "tree store requires typed tree operation", nil)
		return nil
	}))
	s, o, reservations := servingSetupV1(t)
	mustEnvironment(t, reservations.WithOperation(LaneOperation, func(a *OperationAccount) error {
		return o.WithQuiescenceV1(context.Background(), s, func() error {
			truth, stage, index, got := s.UpdateTreeV1(a, func(*Reader) (TreeOperationV1, error) {
				t.Fatal("span enabled legacy tree callback")
				return TreeOperationV1{}, nil
			})
			if truth != 1 || stage != 1 || index != -1 {
				t.Fatal("legacy tree format refusal changed")
			}
			treeNativeError(t, got, engineOperation("update"), EngineClass("StateMismatch"), -30779, "typed tree operation requires tree store", nil)
			return nil
		})
	}))
}

// servingAdmissionV1 proves owner/store binding and one occupied source epoch.
func servingAdmissionV1(t *testing.T) {
	s, o, reservations := servingSetupV1(t)
	foreign, err := NewServingViewOwnerV1(time.Hour)
	mustEnvironment(t, err)
	_, err = servingCallV1(t, o, s, reservations, func(*Reader, *ServingEpochV1, *OperationAccount) error { return nil })
	mustEnvironment(t, err)
	out, err := servingCallV1(t, foreign, s, reservations, func(*Reader, *ServingEpochV1, *OperationAccount) error {
		t.Fatal("foreign Store owner admitted")
		return nil
	})
	servingWantInputV1(t, err, "view")
	servingWantOutcomeV1(t, out, 0, false)
	servingWantInputV1(t, foreign.WithQuiescenceV1(context.Background(), s, func() error {
		t.Fatal("foreign span admitted")
		return nil
	}), "update")
	if s.servingOwner.Load() != o || foreign.current != nil || foreign.priority != nil {
		t.Fatal("foreign attempt rebound or marked Store")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	mustEnvironment(t, reservations.WithOperation(LaneOperation, func(a *OperationAccount) error {
		_, err := foreign.WithViewV1(ctx, s, a, func(*Reader, *ServingEpochV1) error {
			t.Fatal("cancelled foreign callback ran")
			return nil
		})
		servingWantInputV1(t, err, "view")
		servingWantInputV1(t, foreign.WithQuiescenceV1(ctx, s, func() error {
			t.Fatal("cancelled foreign span ran")
			return nil
		}), "update")
		return nil
	}))
}

// servingNoReadV1 distinguishes pre-acquisition refusal and terminal native state.
func servingNoReadV1(t *testing.T) {
	s, o, reservations := servingSetupV1(t)
	s.operations.Lock()
	out, err := servingCallV1(t, o, s, reservations, func(*Reader, *ServingEpochV1, *OperationAccount) error {
		t.Fatal("locked Store opened read")
		return nil
	})
	s.operations.Unlock()
	servingWantBusyV1(t, err, "view")
	servingWantOutcomeV1(t, out, 0, false)
	if o.current != nil {
		t.Fatal("NO_READ retained a fictitious native borrow")
	}
	mustEnvironment(t, s.Close())
	out, err = servingCallV1(t, o, s, reservations, func(*Reader, *ServingEpochV1, *OperationAccount) error {
		t.Fatal("closed source qualified")
		return nil
	})
	requireEnvironmentError(t, err, EngineClass("InvalidInput"), engineOperation("view"), 22, "Store is closed")
	servingWantOutcomeV1(t, out, 0, false)
	err = o.WithQuiescenceV1(context.Background(), s, func() error {
		t.Fatal("closed Store granted effect permission")
		return nil
	})
	requireEnvironmentError(t, err, EngineClass("InvalidInput"), engineOperation("update"), 22, "Store is closed")
}

// servingInputOrderV1 keeps static/account/binding/cancellation precedence and no early R_MIN gate.
func servingInputOrderV1(t *testing.T) {
	for _, lifetime := range []time.Duration{-1, 0} {
		o, err := NewServingViewOwnerV1(lifetime)
		servingWantInputV1(t, err, "view")
		if o != nil {
			t.Fatal("invalid lifetime constructed owner")
		}
	}
	for _, lifetime := range []time.Duration{1, time.Duration(math.MaxInt64)} {
		o, err := NewServingViewOwnerV1(lifetime)
		mustEnvironment(t, err)
		if o.lifetime != lifetime {
			t.Fatal("finite positive lifetime was clamped")
		}
	}
	s, o, reservations := servingSetupV1(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	callback := func(*Reader, *ServingEpochV1) error {
		t.Fatal("invalid input callback")
		return nil
	}
	mustEnvironment(t, reservations.WithOperation(LaneOperation, func(a *OperationAccount) error {
		for _, row := range []struct {
			owner *ServingViewOwnerV1
			store *Store
			ctx   context.Context
			use   func(*Reader, *ServingEpochV1) error
		}{
			{nil, nil, nil, nil}, {&ServingViewOwnerV1{}, s, ctx, callback},
			{o, nil, ctx, callback}, {o, s, nil, callback}, {o, s, ctx, nil},
		} {
			out, err := row.owner.WithViewV1(row.ctx, row.store, nil, row.use)
			servingWantInputV1(t, err, "view")
			servingWantOutcomeV1(t, out, 0, false)
		}
		out, err := o.WithViewV1(ctx, s, a, callback)
		if !sameError(err, context.Canceled) {
			t.Fatal("cancelled context result changed")
		}
		servingWantOutcomeV1(t, out, 0, false)
		return nil
	}))
	servingBadAccountsV1(t, o, s, ctx, callback)
	servingSpanInputsV1(t, o, s, ctx)
	low := reservationOwner(t, 805306367)
	called := 0
	out, err := servingCallV1(t, o, s, low, func(_ *Reader, _ *ServingEpochV1, a *OperationAccount) error {
		called++
		return a.WithReservation(1, func() error {
			t.Fatal("below-floor charge admitted")
			return nil
		})
	})
	if called != 1 || !sameError(err, errOperationReservationCapacity) || reservationLive(low) != 0 {
		t.Fatal("new early R_MIN gate or changed reservation refusal")
	}
	servingWantOutcomeV1(t, out, 1, false)
}

// servingBadAccountsV1 refuses every invalid account before already-cancelled context.
func servingBadAccountsV1(t *testing.T, o *ServingViewOwnerV1, s *Store, ctx context.Context, callback func(*Reader, *ServingEpochV1) error) {
	t.Helper()
	reservations := reservationOwner(t, 805306368)
	var closed *OperationAccount
	mustEnvironment(t, reservations.WithOperation(LaneOperation, func(a *OperationAccount) error {
		closed = a
		return nil
	}))
	accounts := []*OperationAccount{nil, {}, closed}
	mustEnvironment(t, reservations.WithOperation(TreeOperation, func(tree *OperationAccount) error {
		for _, a := range append(accounts, tree) {
			out, err := o.WithViewV1(ctx, s, a, callback)
			if !sameError(err, errOperationReservationInput) {
				t.Fatalf("account error = %v", err)
			}
			servingWantOutcomeV1(t, out, 0, false)
		}
		return nil
	}))
}

// servingSpanInputsV1 checks all span static rows before cancellation or marking.
func servingSpanInputsV1(t *testing.T, o *ServingViewOwnerV1, s *Store, ctx context.Context) {
	t.Helper()
	use := func() error {
		t.Fatal("refused span callback ran")
		return nil
	}
	for _, row := range []struct {
		owner *ServingViewOwnerV1
		store *Store
		ctx   context.Context
		use   func() error
	}{
		{nil, nil, nil, nil}, {&ServingViewOwnerV1{}, s, ctx, use},
		{o, nil, ctx, use}, {o, s, nil, use}, {o, s, ctx, nil},
	} {
		servingWantInputV1(t, row.owner.WithQuiescenceV1(row.ctx, row.store, row.use), "update")
	}
	if err := o.WithQuiescenceV1(ctx, s, use); !sameError(err, context.Canceled) || o.span != nil || o.priority != nil {
		t.Fatal("cancelled no-effect span changed context or retained mark")
	}
}

// servingEscapeV1 rejects zero, copied and escaped epochs and actual expired Readers.
func servingEscapeV1(t *testing.T) {
	s, o, reservations := servingSetupV1(t)
	var absent *ServingEpochV1
	servingWantInputV1(t, absent.CheckV1(), "view")
	servingWantInputV1(t, (&ServingEpochV1{}).CheckV1(), "view")
	var reader *Reader
	var epoch *ServingEpochV1
	_, err := servingCallV1(t, o, s, reservations, func(r *Reader, e *ServingEpochV1, _ *OperationAccount) error {
		reader, epoch = r, e
		copied := *e
		servingWantInputV1(t, copied.CheckV1(), "view")
		servingRefusedV1(t, o, s, reservations)
		return nil
	})
	mustEnvironment(t, err)
	servingWantInputV1(t, epoch.CheckV1(), "view")
	_, found, err := reader.Get(readDBIsLiteral()[0], []byte{0})
	requireEnvironmentError(t, err, EngineClass("InvalidInput"), engineOperation("get"), 22, "Reader is not active")
	if found || reader.active.Load() {
		t.Fatal("escaped Reader expiration drifted")
	}
}

// servingEarlierResultV1 preserves established application truth across late cancellation/closure.
func servingEarlierResultV1(t *testing.T) {
	s, o, reservations := servingSetupV1(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	app := errors.New("earlier source result")
	mustEnvironment(t, reservations.WithOperation(LaneOperation, func(a *OperationAccount) error {
		out, err := o.WithViewV1(ctx, s, a, func(r *Reader, e *ServingEpochV1) error {
			servingNativeBusyV1(t, "update", s, a)
			if ctx.Err() != nil {
				t.Fatal("owner cancelled caller context")
			}
			cancel()
			if !sameError(e.CheckV1(), context.Canceled) || !r.usable() {
				t.Fatal("request cancellation lost reached precedence or expired Reader")
			}
			return app
		})
		if !sameError(err, app) {
			t.Fatal("later eligibility/cancellation replaced earlier result")
		}
		servingWantOutcomeV1(t, out, 1, true)
		return nil
	}))
	servingNativeRetryV1(t, "update", s, nil)
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	mustEnvironment(t, reservations.WithOperation(LaneOperation, func(a *OperationAccount) error {
		out, err := o.WithViewV1(ctx2, s, a, func(*Reader, *ServingEpochV1) error {
			cancel2()
			return app
		})
		if !sameError(err, app) {
			t.Fatal("request-only cancellation replaced result")
		}
		servingWantOutcomeV1(t, out, 1, false)
		return nil
	}))
}

// servingUnwindV1 observes clean panic and Goexit with actual Reader/account cleanup.
func servingUnwindV1(t *testing.T) {
	for _, mode := range []string{"nil", "error", "panic", "goexit"} {
		t.Run(mode, func(t *testing.T) {
			s, o, reservations := servingSetupV1(t)
			app := errors.New("view callback result")
			var reader *Reader
			var epoch *ServingEpochV1
			var result error
			var panicked any
			var returned bool
			done := make(chan struct{})
			go func() {
				defer close(done)
				defer func() { panicked = recover() }()
				_, result = servingCallV1(t, o, s, reservations, func(r *Reader, e *ServingEpochV1, a *OperationAccount) error {
					reader, epoch = r, e
					return a.WithReservation(17, func() error {
						if reservationLive(reservations) != 17 || !r.usable() {
							t.Error("early last-use release")
						}
						return servingModeV1(mode, app)
					})
				})
				returned = true
			}()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("view callback/cleanup did not finish")
			}
			servingWantUnwindV1(t, mode, result, panicked, returned, app)
			if reader == nil || reader.usable() || reader.active.Load() || !epoch.finished || o.current != nil || s.state != storeOPEN || s.txn != nil || reservationLive(reservations) != 0 {
				t.Fatal("clean unwind left native/account/borrow resources")
			}
			_, err := servingCallV1(t, o, s, reservations, func(*Reader, *ServingEpochV1, *OperationAccount) error { return nil })
			mustEnvironment(t, err)
		})
	}
}

// servingReplacementV1 prevents a replacement Store from inheriting an old epoch.
func servingReplacementV1(t *testing.T) {
	s, o, reservations := servingSetupV1(t)
	replacement, _, otherReservations := servingSetupV1(t)
	var old *ServingEpochV1
	var oldReader *Reader
	var result error
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	releaseView := sync.OnceFunc(func() { close(release) })
	defer func() {
		releaseView()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("source replacement callback cleanup did not finish")
		}
	}()
	go func() {
		defer close(done)
		_, result = servingCallV1(t, o, s, reservations, func(r *Reader, e *ServingEpochV1, _ *OperationAccount) error {
			old, oldReader = e, r
			close(entered)
			select {
			case <-release:
			case <-time.After(5 * time.Second):
				t.Error("source replacement never released old view")
			}
			return nil
		})
	}()
	select {
	case <-entered:
	case <-done:
		t.Fatalf("old source callback never entered: %v", result)
	case <-time.After(5 * time.Second):
		t.Fatal("old source admission did not finish")
	}
	servingRefusedV1(t, o, replacement, otherReservations)
	servingNativeBusyV1(t, "update", s, nil)
	servingWantBusyV1(t, old.CheckV1(), "view")
	releaseView()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("old source actual cleanup did not finish")
	}
	mustEnvironment(t, result)
	servingRefusedV1(t, o, replacement, otherReservations)
	mustEnvironment(t, o.WithQuiescenceV1(context.Background(), s, func() error {
		if oldReader.usable() || s.txn != nil {
			t.Fatal("replacement effect preceded actual native close")
		}
		servingRefusedV1(t, o, replacement, otherReservations)
		return nil
	}))
	_, err := servingCallV1(t, o, replacement, otherReservations, func(_ *Reader, e *ServingEpochV1, _ *OperationAccount) error {
		if e == old || e.store != replacement || old.store != s {
			t.Fatal("replacement inherited old source identity")
		}
		servingWantInputV1(t, old.CheckV1(), "view")
		return e.CheckV1()
	})
	mustEnvironment(t, err)
}

// servingOwnedCopyFailureV1 preserves completed independent bytes when the later
// source callback fails; response/Service semantics require RUB-1672 integration.
func servingOwnedCopyFailureV1(t *testing.T) {
	s, o, reservations := servingSetupV1(t)
	network := reservationOwner(t, 805306368)
	app := errors.New("later source failure")
	mustEnvironment(t, network.WithReservation(4, func() error {
		var owned []byte
		_, err := servingCallV1(t, o, s, reservations, func(r *Reader, e *ServingEpochV1, _ *OperationAccount) error {
			value, _, getErr := r.Get(readDBIsLiteral()[0], []byte{0})
			mustEnvironment(t, getErr)
			owned = bytes.Clone(value)
			mustEnvironment(t, e.CheckV1())
			return app
		})
		if !sameError(err, app) || !bytes.Equal(owned, []byte{0, 0, 0, 2}) || reservationLive(network) != 4 {
			t.Fatal("source failure retargeted or released independent output")
		}
		return nil
	}))
}
