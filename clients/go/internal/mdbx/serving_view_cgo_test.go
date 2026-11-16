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
		{"A1", servingQualifiedV1},
		{"A2", servingLastUseV1},
		{"A3", servingExpiryV1},
		{"A4", servingPriorityV1},
		{"A5", servingNewerPriorityV1},
		{"A6", servingOwnedCopyV1},
		{"A7", servingSpanV1},
		{"A8", servingOptionalV1},
		{"R1", servingAdmissionV1},
		{"R2", servingNoReadV1},
		{"R3", servingInputOrderV1},
		{"R4", servingEscapeV1},
		{"R5", servingEarlierResultV1},
		{"H1", servingUnwindV1},
		{"H2", servingReplacementV1},
		{"H3", servingOwnedCopyFailureV1},
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

// servingFirstBindingV1 exercises actual holders that began before owner binding.
func servingFirstBindingV1(t *testing.T) {
	for _, route := range []string{"view", "update", "tree"} {
		for _, late := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/late=%v", route, late), func(t *testing.T) {
				servingNativeWakeV1(t, route, late)
			})
		}
	}
}

// servingWaitContextV1 schedules a public wait without supplying its result.
type servingWaitContextV1 struct {
	context.Context
	waiting chan struct{}
	resume  chan struct{}
	signal  sync.Once
	release func()
}

// Done pauses before the wait select, making a preceding completion observable.
func (c *servingWaitContextV1) Done() <-chan struct{} {
	c.signal.Do(func() { close(c.waiting) })
	<-c.resume
	return c.Context.Done()
}

// servingRequiredV1 starts one bounded invocation and releases every gate on failure.
func servingRequiredV1(t *testing.T, o *ServingViewOwnerV1, s *Store, use func() error) (*servingWaitContextV1, <-chan error, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	c := &servingWaitContextV1{Context: ctx, waiting: make(chan struct{}), resume: make(chan struct{})}
	c.release = sync.OnceFunc(func() { close(c.resume) })
	result, done := make(chan error, 1), make(chan struct{})
	go func() {
		defer close(done)
		result <- o.WithQuiescenceV1(c, s, use)
	}()
	t.Cleanup(func() {
		cancel()
		c.release()
		servingSignalV1(t, done, "required invocation cleanup did not finish")
	})
	return c, result, cancel
}

// servingWaitingV1 rejects old immediate-busy behavior at the actual return boundary.
func servingWaitingV1(t *testing.T, c *servingWaitContextV1, result <-chan error) {
	t.Helper()
	select {
	case err := <-result:
		t.Fatalf("required invocation returned before actual closure: %v", err)
	case <-c.waiting:
	case <-time.After(5 * time.Second):
		t.Fatal("required invocation did not reach cancellation wait")
	}
}

// servingResultV1 bounds a missing wake without treating time as a successful result.
func servingResultV1(t *testing.T, result <-chan error, message string) error {
	t.Helper()
	select {
	case err := <-result:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal(message)
		return nil
	}
}

// servingSignalV1 waits for an actual callback/completion synchronization event.
func servingSignalV1(t *testing.T, event <-chan struct{}, message string) {
	t.Helper()
	select {
	case <-event:
	case <-time.After(5 * time.Second):
		t.Fatal(message)
	}
}

// servingFreshV1 proves invocation retirement by a new public healthy serving call.
func servingFreshV1(t *testing.T, o *ServingViewOwnerV1, s *Store, reservations *OperationReservationOwner, message string) {
	t.Helper()
	out, err := servingCallV1(t, o, s, reservations, func(*Reader, *ServingEpochV1, *OperationAccount) error { return nil })
	if err != nil {
		t.Fatalf("%s: %v", message, err)
	}
	servingWantOutcomeV1(t, out, 1, false)
}

// servingNativeHolderV1 pauses a real callback under its original native lock.
func servingNativeHolderV1(t *testing.T, route string, s *Store, reservations *OperationReservationOwner) (func(), <-chan error) {
	t.Helper()
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	open := sync.OnceFunc(func() { close(release) })
	app := errors.New("holder application result")
	result := make(chan error, 1)
	use := func(*Reader) error { close(entered); <-release; return app }
	go func() {
		defer close(done)
		err := servingNativeHoldCallV1(route, s, reservations, use)
		if !sameError(err, app) {
			err = fmt.Errorf("native holder result changed: %w", err)
		} else {
			err = nil
		}
		result <- err
	}()
	t.Cleanup(func() { open(); servingSignalV1(t, done, "native holder cleanup did not finish") })
	servingSignalV1(t, entered, "native holder did not enter")
	return open, result
}

// servingNativeHoldCallV1 retains each native entry's real callback/error tuple.
func servingNativeHoldCallV1(route string, s *Store, reservations *OperationReservationOwner, use func(*Reader) error) error {
	if route == "view" {
		return s.View(use)
	}
	if route == "update" {
		truth, stage, err := s.Update(func(r *Reader) (Batch, error) { return Batch{}, use(r) })
		if truth != 1 || stage != 1 {
			return fmt.Errorf("holder Update tuple %d/%d", truth, stage)
		}
		return err
	}
	return reservations.WithOperation(LaneOperation, func(a *OperationAccount) error {
		truth, stage, index, err := s.UpdateTreeV1(a, func(r *Reader) (TreeOperationV1, error) { return TreeOperationV1{}, use(r) })
		if truth != 1 || stage != 1 || index != -1 {
			return fmt.Errorf("holder Tree tuple %d/%d/%d", truth, stage, index)
		}
		return err
	})
}

// servingNativeWakeV1 completes the actual holder before the captured wait selects.
func servingNativeWakeV1(t *testing.T, route string, late bool) {
	s, o, reservations := servingSetupV1(t)
	if route == "tree" {
		s, _, reservations = tsNew(t)
	}
	if !late {
		servingFreshV1(t, o, s, reservations, "initial binding failed")
	}
	open, holder := servingNativeHolderV1(t, route, s, reservations)
	called := 0
	c, result, _ := servingRequiredV1(t, o, s, func() error { called++; return nil })
	servingWaitingV1(t, c, result)
	servingRefusedV1(t, o, s, reservations)
	open()
	mustEnvironment(t, servingResultV1(t, holder, "native holder cleanup did not finish"))
	c.release()
	message := "native completion did not wake required invocation"
	if late {
		message = "late-bound completion did not wake required invocation"
	}
	mustEnvironment(t, servingResultV1(t, result, message))
	if called != 1 {
		t.Fatal("completion notification was lost or callback replayed")
	}
	servingFreshV1(t, o, s, reservations, "resolved invocation retained priority")
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

// servingPriorityRouteV1 proves optional busy retires without a phantom retry.
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
	servingFreshV1(t, o, s, reservations, "optional invocation left priority after actual close")
	mustEnvironment(t, reservations.WithOperation(LaneOperation, func(a *OperationAccount) error {
		servingNativeRetryV1(t, route, s, a)
		return nil
	}))
}

// servingNewerPriorityV1 preserves each live caller in both completion/cancel orders.
func servingNewerPriorityV1(t *testing.T) {
	for _, first := range []int{0, 1} {
		for _, canceled := range []bool{false, true} {
			t.Run(fmt.Sprintf("first%d/cancel=%v", first, canceled), func(t *testing.T) {
				servingPendingOrderV1(t, first, canceled)
			})
		}
	}
}

// servingEpochHolderV1 pauses the actual finite serving Reader until released.
func servingEpochHolderV1(t *testing.T, o *ServingViewOwnerV1, s *Store, reservations *OperationReservationOwner) (func(), <-chan error) {
	t.Helper()
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	open := sync.OnceFunc(func() { close(release) })
	result := make(chan error, 1)
	go func() {
		defer close(done)
		_, err := servingCallV1(t, o, s, reservations, func(*Reader, *ServingEpochV1, *OperationAccount) error {
			close(entered)
			<-release
			return nil
		})
		result <- err
	}()
	t.Cleanup(func() { open(); servingSignalV1(t, done, "serving holder cleanup did not finish") })
	servingSignalV1(t, entered, "serving holder did not enter")
	return open, result
}

// servingPendingOrderV1 holds the second real caller before admission after the first returns.
func servingPendingOrderV1(t *testing.T, first int, canceled bool) {
	s, o, reservations := servingSetupV1(t)
	open, view := servingEpochHolderV1(t, o, s, reservations)
	calls := [2]int{}
	contexts := [2]*servingWaitContextV1{}
	results := [2]<-chan error{}
	cancels := [2]context.CancelFunc{}
	for i := range 2 {
		contexts[i], results[i], cancels[i] = servingRequiredV1(t, o, s, func() error { calls[i]++; return nil })
		servingWaitingV1(t, contexts[i], results[i])
	}
	if canceled {
		cancels[first]()
		contexts[first].release()
	} else {
		open()
		mustEnvironment(t, servingResultV1(t, view, "old native cleanup did not finish"))
		contexts[first].release()
	}
	err := servingResultV1(t, results[first], "first invocation did not resolve")
	servingWantResolutionV1(t, err, calls[first], canceled)
	if canceled {
		servingRefusedV1(t, o, s, reservations)
		open()
		mustEnvironment(t, servingResultV1(t, view, "old native cleanup did not finish"))
	}
	out, got := servingCallV1(t, o, s, reservations, func(*Reader, *ServingEpochV1, *OperationAccount) error { return nil })
	if got == nil {
		t.Fatal("completed mutation admitted view past live waiter")
	}
	servingWantBusyV1(t, got, "view")
	servingWantOutcomeV1(t, out, 0, false)
	second := 1 - first
	contexts[second].release()
	mustEnvironment(t, servingResultV1(t, results[second], "second live invocation did not resolve"))
	if calls[second] != 1 {
		t.Fatal("remaining caller lost callback or replayed it")
	}
	servingFreshV1(t, o, s, reservations, "resolved invocation retained priority")
}

// servingWantResolutionV1 pins waiting cancellation and one admitted callback separately.
func servingWantResolutionV1(t *testing.T, err error, called int, canceled bool) {
	t.Helper()
	want, count := error(nil), 1
	if canceled {
		want, count = context.Canceled, 0
	}
	if !sameError(err, want) || called != count {
		t.Fatal("cancellation replaced established result or replayed callback")
	}
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
	t.Run("second span and canceled effect cleanup", servingSpanContenderV1)
	t.Run("old view must actually end", servingSpanOldViewV1)
	t.Run("native wait and cancellation", servingSpanOperationV1)
}

// servingSpanOperationV1 checks cancellation against real native preflight contention.
func servingSpanOperationV1(t *testing.T) {
	for _, route := range []string{"view", "update", "tree", "closed"} {
		t.Run(route, func(t *testing.T) { servingNativeCancelV1(t, route) })
	}
	t.Run("canceled entry states", servingCanceledEntriesV1)
}

// servingNativeCancelV1 makes cancellation and completion ready before wait resumption.
func servingNativeCancelV1(t *testing.T, route string) {
	s, o, reservations := servingSetupV1(t)
	if route == "tree" {
		s, _, reservations = tsNew(t)
	}
	holderRoute := route
	if route == "closed" {
		holderRoute = "view"
	}
	open, holder := servingNativeHolderV1(t, holderRoute, s, reservations)
	called := 0
	c, result, cancel := servingRequiredV1(t, o, s, func() error { called++; return nil })
	servingWaitingV1(t, c, result)
	cancel()
	open()
	mustEnvironment(t, servingResultV1(t, holder, "native holder did not finish"))
	if route == "closed" {
		mustEnvironment(t, s.Close())
	}
	c.release()
	got := servingResultV1(t, result, "native completion did not wake required invocation")
	servingWantResolutionV1(t, got, called, true)
	if route == "closed" {
		return
	}
	servingFreshV1(t, o, s, reservations, "resolved invocation retained priority")
}

// servingCanceledEntriesV1 rejects canceled calls without ending an existing epoch.
func servingCanceledEntriesV1(t *testing.T) {
	s, o, reservations := servingSetupV1(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	refused := func() {
		called := 0
		err := o.WithQuiescenceV1(ctx, s, func() error { called++; return nil })
		if !sameError(err, context.Canceled) || called != 0 {
			t.Fatal("canceled entry changed context or called effect")
		}
	}
	refused()
	out, err := servingCallV1(t, o, s, reservations, func(_ *Reader, e *ServingEpochV1, _ *OperationAccount) error {
		refused()
		if e.CheckV1() != nil {
			t.Fatal("canceled entry changed old eligibility or retained priority")
		}
		return nil
	})
	mustEnvironment(t, err)
	servingWantOutcomeV1(t, out, 1, false)
	mustEnvironment(t, o.WithQuiescenceV1(context.Background(), s, func() error { refused(); return nil }))
	servingFreshV1(t, o, s, reservations, "canceled entry changed old eligibility or retained priority")
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
	app := errors.New("outer effect result")
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
	called := 0
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer func() { panicked = recover() }()
		result = o.WithQuiescenceV1(context.Background(), s, func() error {
			called++
			if called != 1 {
				t.Error("cancellation replaced established result or replayed callback")
				return app
			}
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
	servingSignalV1(t, done, "external span callback/cleanup did not finish")
	if called != 1 {
		t.Fatal("cancellation replaced established result or replayed callback")
	}
	servingWantUnwindV1(t, mode, result, panicked, returned, app)
	if o.span != nil || s.state != storeOPEN || s.txn != nil {
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
		recovered, ok := panicked.(error)
		if returned || !ok || !sameError(recovered, app) {
			t.Fatal("callback panic identity/continuation changed")
		}
	case "goexit":
		if returned || panicked != nil {
			t.Fatal("Goexit became a normal result or panic")
		}
	}
}

// servingSpanContenderV1 keeps the outer effect and its cleanup despite cancellation.
func servingSpanContenderV1(t *testing.T) {
	s, o, reservations := servingSetupV1(t)
	entered, cleanup := make(chan struct{}), make(chan struct{})
	release := sync.OnceFunc(func() { close(cleanup) })
	t.Cleanup(release)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result, done := make(chan error, 1), make(chan struct{})
	app := errors.New("outer established result")
	called := 0
	go func() {
		defer close(done)
		result <- o.WithQuiescenceV1(ctx, s, func() error {
			called++
			if called != 1 {
				t.Error("cancellation replaced established result or replayed callback")
				return app
			}
			defer func() { close(entered); <-cleanup }()
			cancel()
			servingNativeRetryV1(t, "update", s, nil)
			return app
		})
	}()
	t.Cleanup(func() { release(); servingSignalV1(t, done, "active callback cleanup stranded") })
	servingSignalV1(t, entered, "outer cleanup did not start")
	out, err := servingCallV1(t, o, s, reservations, func(*Reader, *ServingEpochV1, *OperationAccount) error { return nil })
	if err == nil {
		t.Fatal("active effect cleanup admitted a serving view")
	}
	servingWantBusyV1(t, err, "view")
	servingWantOutcomeV1(t, out, 0, false)
	c, second, cancelSecond := servingRequiredV1(t, o, s, func() error { return nil })
	servingWaitingV1(t, c, second)
	cancelSecond()
	c.release()
	if !sameError(servingResultV1(t, second, "waiting cancellation did not return"), context.Canceled) {
		t.Fatal("waiting cancellation did not preserve its context")
	}
	servingRefusedV1(t, o, s, reservations)
	release()
	if !sameError(servingResultV1(t, result, "active cleanup did not return"), app) || called != 1 {
		t.Fatal("cancellation replaced established result or replayed callback")
	}
	servingFreshV1(t, o, s, reservations, "resolved invocation retained priority")
}

// servingSpanOldViewV1 waits for the actual Reader/borrow cleanup before effects.
func servingSpanOldViewV1(t *testing.T) {
	s, o, reservations := servingSetupV1(t)
	entered, release := make(chan struct{}), make(chan struct{})
	open := sync.OnceFunc(func() { close(release) })
	view, done := make(chan error, 1), make(chan struct{})
	var reader *Reader
	var epoch *ServingEpochV1
	go func() {
		defer close(done)
		_, err := servingCallV1(t, o, s, reservations, func(r *Reader, e *ServingEpochV1, a *OperationAccount) error {
			reader, epoch = r, e
			return a.WithReservation(17, func() error { close(entered); <-release; return nil })
		})
		view <- err
	}()
	t.Cleanup(func() { open(); servingSignalV1(t, done, "serving callback cleanup stranded") })
	servingSignalV1(t, entered, "serving callback did not enter")
	called := 0
	c, result, _ := servingRequiredV1(t, o, s, func() error {
		called++
		if reader.usable() || s.txn != nil || reservationLive(reservations) != 0 {
			t.Error("effect before actual Reader/account close")
		}
		servingRefusedV1(t, o, s, reservations)
		return nil
	})
	servingWaitingV1(t, c, result)
	servingWantBusyV1(t, epoch.CheckV1(), "view")
	if !reader.usable() || reservationLive(reservations) != 17 {
		t.Fatal("waiting required invocation forced old native/account close")
	}
	servingRefusedV1(t, o, s, reservations)
	open()
	mustEnvironment(t, servingResultV1(t, view, "serving cleanup did not finish"))
	c.release()
	mustEnvironment(t, servingResultV1(t, result, "completion notification was lost"))
	if called != 1 {
		t.Fatal("actual close failed to admit effect once")
	}
	servingFreshV1(t, o, s, reservations, "resolved invocation retained priority")
}

// servingOptionalV1 crosses original native state/format with owner exclusion flags.
func servingOptionalV1(t *testing.T) {
	for _, route := range []string{"update", "tree", "close"} {
		for _, state := range []string{"active", "expired", "priority", "span"} {
			t.Run(route+"/"+state, func(t *testing.T) { servingOptionalRouteV1(t, route, state) })
		}
		t.Run(route+"/pending native admitted", func(t *testing.T) { servingOptionalPendingRouteV1(t, route) })
	}
	t.Run("format refusals unchanged", servingFormatV1)
	t.Run("static inputs precede marking", servingNativeInputsV1)
}

// servingOptionalPendingRouteV1 admits the original native callback while another scope waits.
func servingOptionalPendingRouteV1(t *testing.T, route string) {
	s, o, reservations := servingSetupV1(t)
	if route == "tree" {
		s, _, reservations = tsNew(t)
	}
	open, view := servingEpochHolderV1(t, o, s, reservations)
	called := 0
	c, result, _ := servingRequiredV1(t, o, s, func() error { called++; return nil })
	servingWaitingV1(t, c, result)
	open()
	mustEnvironment(t, servingResultV1(t, view, "old epoch cleanup did not finish"))
	servingRefusedV1(t, o, s, reservations)
	mustEnvironment(t, reservations.WithOperation(LaneOperation, func(a *OperationAccount) error {
		servingNativeRetryV1(t, route, s, a)
		return nil
	}))
	servingRefusedV1(t, o, s, reservations)
	c.release()
	err := servingResultV1(t, result, "native completion did not wake required invocation")
	if route == "close" {
		requireEnvironmentError(t, err, EngineClass("InvalidInput"), engineOperation("update"), 22, "Store is closed")
		if called != 0 {
			t.Fatal("consumed terminal Store admitted required effect")
		}
		return
	}
	servingWantResolutionV1(t, err, called, false)
	servingFreshV1(t, o, s, reservations, "resolved invocation retained priority")
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
		if e.closing {
			t.Fatal("refused static input changed serving priority")
		}
		return e.CheckV1()
	})
	mustEnvironment(t, err)
	servingFreshV1(t, o, s, reservations, "static input retained priority")
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
			servingOptionalPendingV1(t, o, s, route, a)
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

// servingOptionalPendingV1 preserves a real required caller across optional busy.
func servingOptionalPendingV1(t *testing.T, o *ServingViewOwnerV1, s *Store, route string, a *OperationAccount) {
	t.Helper()
	c, result, cancel := servingRequiredV1(t, o, s, func() error {
		t.Error("pending optional row entered before actual close")
		return nil
	})
	servingWaitingV1(t, c, result)
	servingNativeBusyV1(t, route, s, a)
	cancel()
	c.release()
	if !sameError(servingResultV1(t, result, "pending optional row cancellation stranded"), context.Canceled) {
		t.Fatal("optional native invocation altered pending caller")
	}
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
	if s.servingOwner.Load() != o || foreign.current != nil {
		t.Fatal("foreign attempt rebound or marked Store")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	mustEnvironment(t, reservations.WithOperation(LaneOperation, func(a *OperationAccount) error {
		_, err := foreign.WithViewV1(ctx, s, a, func(*Reader, *ServingEpochV1) error {
			t.Fatal("canceled foreign callback ran")
			return nil
		})
		servingWantInputV1(t, err, "view")
		servingWantInputV1(t, foreign.WithQuiescenceV1(ctx, s, func() error {
			t.Fatal("canceled foreign span ran")
			return nil
		}), "update")
		return nil
	}))
	fresh, _, freshReservations := servingSetupV1(t)
	servingFreshV1(t, foreign, fresh, freshReservations, "foreign input retained priority")
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
	spanCallback := func() error {
		t.Fatal("refused span callback ran")
		return nil
	}
	for _, row := range []struct {
		owner *ServingViewOwnerV1
		store *Store
		ctx   context.Context
		view  func(*Reader, *ServingEpochV1) error
		span  func() error
	}{
		{nil, nil, nil, nil, nil},
		{&ServingViewOwnerV1{}, s, ctx, callback, spanCallback},
		{&ServingViewOwnerV1{self: o, lifetime: time.Hour}, s, ctx, callback, spanCallback},
		{o, nil, ctx, callback, spanCallback},
		{o, s, nil, callback, spanCallback},
		{o, s, ctx, nil, nil},
	} {
		out, err := row.owner.WithViewV1(row.ctx, row.store, nil, row.view)
		servingWantInputV1(t, err, "view")
		servingWantOutcomeV1(t, out, 0, false)
		servingWantInputV1(t, row.owner.WithQuiescenceV1(row.ctx, row.store, row.span), "update")
	}
	mustEnvironment(t, reservations.WithOperation(LaneOperation, func(a *OperationAccount) error {
		out, err := o.WithViewV1(ctx, s, a, callback)
		if !sameError(err, context.Canceled) {
			t.Fatal("canceled context result changed")
		}
		servingWantOutcomeV1(t, out, 0, false)
		return nil
	}))
	servingBadAccountsV1(t, o, s, ctx, callback)
	if err := o.WithQuiescenceV1(ctx, s, spanCallback); !sameError(err, context.Canceled) || o.span != nil {
		t.Fatal("canceled no-effect span changed context or retained mark")
	}
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

// servingBadAccountsV1 refuses every invalid account before already-canceled context.
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
				t.Fatal("owner canceled caller context")
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
	servingFreshV1(t, o, replacement, otherReservations, "optional invocation left priority after actual close")
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
