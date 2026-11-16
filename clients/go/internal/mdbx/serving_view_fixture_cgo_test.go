//go:build rubin_mdbx_fixture && cgo && (darwin || linux) && (amd64 || arm64)

package mdbx

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

// TestServingViewFixtureV1 crosses callback outcomes with actual existing native
// consumed/retained transports. It supplies no source-health or native-close flag.
func TestServingViewFixtureV1(t *testing.T) {
	for _, mode := range []uint32{0, 9, 10} {
		for _, app := range []string{"nil", "error", "typed nil", "wrapped", "panic", "goexit"} {
			t.Run(fmt.Sprintf("H1/abort%d/%s", mode, app), func(t *testing.T) { servingFixtureProductV1(t, mode, app) })
		}
	}
	for _, mode := range []uint32{0, 9, 10, 11} {
		for _, app := range []string{"ignored", "returned", "wrapped", "panic", "goexit"} {
			t.Run(fmt.Sprintf("H1/read/abort%d/%s", mode, app), func(t *testing.T) { servingFixtureReadV1(t, mode, app) })
		}
	}
	t.Run("R2/begin nil", servingFixtureBeginV1)
	t.Run("R2/non-nil failed-begin projection", servingFixtureBeginRetainedV1)
	t.Run("R2/required retained span", servingFixtureRetainedSpanV1)
	t.Run("A8/terminal native tuples", servingFixtureTerminalEntriesV1)
	t.Run("A7/external native cleanup", servingFixtureSpanNativeV1)
	for _, site := range []uint32{4, 5} {
		for _, late := range []bool{false, true} {
			t.Run(fmt.Sprintf("A7/inspect/site%d/late=%v", site, late), func(t *testing.T) {
				servingFixtureInspectWakeV1(t, site, late)
			})
		}
	}
}

// servingFixtureCallbackV1 preserves each independent error's identity.
func servingFixtureCallbackV1(kind string, app error) error {
	if kind == "typed nil" {
		var typed *nilPointerError
		return typed
	}
	if kind == "wrapped" {
		return fmt.Errorf("callback wrapper: %w", app)
	}
	return servingModeV1(kind, app)
}

// servingFixtureProductV1 observes native cleanup even when WithView never returns.
func servingFixtureProductV1(t *testing.T, mode uint32, kind string) {
	s, o, reservations := servingSetupV1(t)
	app := errors.New("callback primary")
	var callback, result error
	var reader *Reader
	var epoch *ServingEpochV1
	var out ServingViewOutcomeV1
	var panicked any
	var returned bool
	var evidence fixtureLargeEvidence
	var fixtureErr error
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer func() { panicked = recover() }()
		run := func() {
			out, result = servingCallV1(t, o, s, reservations, func(r *Reader, e *ServingEpochV1, a *OperationAccount) error {
				reader, epoch = r, e
				return a.WithReservation(23, func() error {
					if reservationLive(reservations) != 23 || !r.usable() {
						t.Error("native/account owner released before callback last use")
					}
					callback = servingFixtureCallbackV1(kind, app)
					return callback
				})
			})
		}
		if mode == 0 {
			run()
		} else {
			evidence, fixtureErr = fixtureLargeFault(s, mode, 0, []byte{0}, run)
		}
		returned = true
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("native disposition callback/cleanup did not finish")
	}
	mustEnvironment(t, fixtureErr)
	if returned && mode != 0 && evidence.aborts != 1 {
		t.Fatalf("fault not reached exactly once: %+v", evidence)
	}
	if reader == nil || reader.usable() || reader.active.Load() || epoch == nil || !epoch.finished || reservationLive(reservations) != 0 {
		t.Fatal("unwind leaked live Reader/account")
	}
	if kind == "panic" || kind == "goexit" {
		servingWantUnwindV1(t, kind, result, panicked, returned, app)
	} else if !returned || panicked != nil {
		t.Fatal("ordinary callback stopped returning")
	}
	servingFixtureDispositionV1(t, s, o, reservations, mode)
	if returned {
		end := uint8(1)
		if mode == 9 {
			end = 2
		}
		if mode == 10 {
			end = 3
		}
		servingWantOutcomeV1(t, out, end, false)
		servingFixtureErrorV1(t, mode, result, callback)
	} else if mode != 0 {
		servingFixtureErrorV1(t, mode, s.terminal, nil)
	}
	if mode != 0 {
		mustEnvironment(t, fixtureLargeRelease(s))
	}
}

// servingFixtureErrorV1 pins primary/native ordering, including a typed nil callback.
func servingFixtureErrorV1(t *testing.T, mode uint32, result, primary error) {
	t.Helper()
	switch mode {
	case 0:
		if !sameError(result, primary) {
			t.Fatal("clean callback result identity changed")
		}
	case 9:
		abort := result
		if primary != nil {
			parts, ok := result.(interface{ Unwrap() []error })
			if !ok || len(parts.Unwrap()) != 2 || !sameError(parts.Unwrap()[0], primary) {
				t.Fatal("application/abort order or identity changed")
			}
			abort = parts.Unwrap()[1]
		}
		e := requireEnvironmentError(t, abort, EngineClass("IO"), engineOperation("abort"), 5, "error 5")
		if e.Cause != nil || e.ReopenRequired || e.TreeObservation != nil {
			t.Fatal("consumed abort payload changed")
		}
	case 10:
		e := requireEnvironmentError(t, result, EngineClass("LocalInvariant"), engineOperation("abort"), -30416, pinnedNegativeDiagnostics[-30416])
		if !sameError(e.Cause, primary) || !e.ReopenRequired || e.TreeObservation != nil {
			t.Fatal("retained abort cause or payload changed")
		}
	}
}

// servingFixtureDispositionV1 checks actual resource shape and the next public call.
func servingFixtureDispositionV1(t *testing.T, s *Store, o *ServingViewOwnerV1, reservations *OperationReservationOwner, mode uint32) {
	t.Helper()
	switch mode {
	case 0:
		if s.state != storeOPEN || s.txn != nil || s.env == nil || o.current != nil {
			t.Fatal("clean unwind poisoned or retained native ownership")
		}
		_, err := servingCallV1(t, o, s, reservations, func(*Reader, *ServingEpochV1, *OperationAccount) error { return nil })
		mustEnvironment(t, err)
	case 9:
		if s.state != storeCLOSED || s.txn != nil || s.env != nil || s.writer != nil || o.current != nil || s.terminal == nil {
			t.Fatal("consumed terminal native shape")
		}
		out, err := servingCallV1(t, o, s, reservations, func(*Reader, *ServingEpochV1, *OperationAccount) error {
			t.Fatal("consumed terminal callback")
			return nil
		})
		if !sameError(err, s.terminal) {
			t.Fatal("terminal next-call cause changed")
		}
		servingWantOutcomeV1(t, out, 0, false)
	case 10:
		if s.state != storePOISONEDTHREAD || s.txn == nil || s.env == nil || s.writer == nil || o.current == nil || s.terminal == nil {
			t.Fatal("retained native pointer/borrow/cause lost")
		}
		servingRefusedV1(t, o, s, reservations)
		got := o.WithQuiescenceV1(context.Background(), s, func() error {
			t.Fatal("retained read granted transition")
			return nil
		})
		servingWantBusyV1(t, got, "update")
		if s.txn == nil {
			t.Fatal("logical closure consumed retained native pointer")
		}
	}
}

// servingFixtureReadV1 crosses ignored/returned/wrapped infrastructure with actual abort outcomes.
func servingFixtureReadV1(t *testing.T, mode uint32, kind string) {
	s, o, reservations := servingSetupV1(t)
	var recorded, result, callback error
	var out ServingViewOutcomeV1
	var reader *Reader
	var returned bool
	var panicked any
	app := errors.New("read unwind")
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer func() { panicked = recover() }()
		run := func() {
			_, err := FixtureSelectedDamage(s, reservations, SelectedDamageGetEIO, 0, []byte{0}, func() {
				out, result = servingCallV1(t, o, s, reservations, func(r *Reader, _ *ServingEpochV1, _ *OperationAccount) error {
					reader = r
					_, _, recorded = r.Get(readDBIsLiteral()[0], []byte{0})
					if recorded == nil {
						t.Error("real read fault not reached")
						return errors.New("read fixture did not reach its native fault")
					}
					switch kind {
					case "returned":
						callback = recorded
					case "wrapped":
						callback = fmt.Errorf("read wrapper: %w", recorded)
					case "panic", "goexit":
						return servingModeV1(kind, app)
					}
					return callback
				})
			})
			mustEnvironment(t, err)
		}
		if mode == 0 {
			run()
		} else {
			_, err := fixtureLargeFault(s, mode, 0, []byte{0}, run)
			mustEnvironment(t, err)
		}
		returned = true
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("native read callback/cleanup did not finish")
	}
	if reader == nil || reader.usable() || !sameError(reader.failure, recorded) || reservationLive(reservations) != 0 {
		t.Fatal("recorded native read/callback cleanup")
	}
	if kind == "panic" || kind == "goexit" {
		servingWantUnwindV1(t, kind, result, panicked, returned, app)
	} else if !returned || panicked != nil {
		t.Fatal("ordinary infrastructure callback stopped returning")
	}
	if mode == 10 {
		if s.txn != reader.txn || s.state != storePOISONEDTHREAD || o.current == nil {
			t.Fatal("read failure lost retained actual pointer/epoch")
		}
		servingRefusedV1(t, o, s, reservations)
	} else if mode == 11 {
		if s.state != storeCLOSEBLOCKED || s.txn != nil || s.env == nil || o.current != nil {
			t.Fatal("consumed read with retained environment was treated as healthy")
		}
	} else if s.state != storeCLOSED || s.txn != nil || s.env != nil || o.current != nil {
		t.Fatal("read infrastructure did not actually consume environment")
	}
	if returned {
		end := uint8(2)
		if mode == 10 {
			end = 3
		}
		servingWantOutcomeV1(t, out, end, false)
		primary := servingFixtureReadPrimaryV1(t, kind, callback, recorded, result, mode)
		if mode == 9 || mode == 10 {
			servingFixtureErrorV1(t, mode, result, primary)
		}
		if !sameError(s.terminal, result) {
			t.Fatal("actual native terminal identity differed from returned result")
		}
	} else {
		primary := servingFixtureReadPrimaryV1(t, "ignored", nil, recorded, s.terminal, mode)
		if mode == 9 || mode == 10 {
			servingFixtureErrorV1(t, mode, s.terminal, primary)
		}
	}
	if mode != 10 {
		servingFixtureRequiredTerminalV1(t, s, o)
	}
	if mode == 10 || mode == 11 {
		mustEnvironment(t, fixtureLargeRelease(s))
	}
}

// servingFixtureRequiredTerminalV1 distinguishes acquired state errors from lock contention.
func servingFixtureRequiredTerminalV1(t *testing.T, s *Store, o *ServingViewOwnerV1) {
	t.Helper()
	terminal := s.terminal
	c, result, _ := servingRequiredV1(t, o, s, func() error {
		t.Error("terminal native state admitted callback")
		return nil
	})
	select {
	case got := <-result:
		if !sameError(got, terminal) {
			t.Fatal("acquired native state error identity changed")
		}
	case <-c.waiting:
		t.Fatal("acquired native state error was retried as lock contention")
	case <-time.After(5 * time.Second):
		t.Fatal("acquired native state error did not return")
	}
}

// servingFixtureReadPrimaryV1 independently checks readPrimary's exact composition.
func servingFixtureReadPrimaryV1(t *testing.T, kind string, callback, recorded, result error, mode uint32) error {
	t.Helper()
	primary := result
	if mode == 10 {
		primary = requireEngineError(t, result, EngineClass("LocalInvariant"), engineOperation("abort"), -30416).Cause
	}
	if mode == 9 {
		parts, ok := result.(interface{ Unwrap() []error })
		if !ok || len(parts.Unwrap()) != 2 {
			t.Fatal("native read/abort error shape")
		}
		primary = parts.Unwrap()[0]
	}
	if mode == 11 {
		e := requireEngineError(t, result, EngineClass("Concurrency"), engineOperation("close"), -30778)
		if e.ReopenRequired || e.TreeObservation != nil {
			t.Fatal("retained environment close tuple")
		}
		primary = e.Cause
	}
	if kind == "wrapped" {
		parts, ok := primary.(interface{ Unwrap() []error })
		if !ok || len(parts.Unwrap()) != 2 || !sameError(parts.Unwrap()[0], callback) || !sameError(parts.Unwrap()[1], recorded) {
			t.Fatal("wrapped callback and recorded infrastructure lost ordered identities")
		}
	} else if !sameError(primary, recorded) {
		t.Fatal("ignored/returned infrastructure was duplicated or replaced")
	}
	return primary
}

// servingFixtureBeginV1 proves a failed native begin with nil transaction is NO_READ,
// even though its actual existing owner consumes the terminal environment.
func servingFixtureBeginV1(t *testing.T) {
	s, o, reservations := servingSetupV1(t)
	var out ServingViewOutcomeV1
	var result error
	evidence, err := FixtureSelectedDamage(s, reservations, SelectedDamageBeginEIO, 0, []byte{0}, func() {
		out, result = servingCallV1(t, o, s, reservations, func(*Reader, *ServingEpochV1, *OperationAccount) error {
			t.Fatal("failed begin invoked callback")
			return nil
		})
	})
	mustEnvironment(t, err)
	if evidence.BeginOld != 1 || evidence.OldAborts != 0 || evidence.Faults != 1 || s.env != nil || s.txn != nil || s.state != storeCLOSED || o.current != nil {
		t.Fatal("failed-begin actual native shape")
	}
	servingWantOutcomeV1(t, out, 0, false)
	requireEnvironmentError(t, result, EngineClass("IO"), engineOperation("view"), 5, "error 5")
	if !sameError(s.terminal, result) {
		t.Fatal("failed begin terminal cause identity")
	}
}

// servingFixtureBeginRetainedV1 checks the defensive failed-begin/non-nil shape
// against an actual retained native handle. Existing C transports never produce
// that malformed begin pair; no C wrapper or fixture behavior is added here.
func servingFixtureBeginRetainedV1(t *testing.T) {
	s, _, _ := servingSetupV1(t)
	_, err := fixtureLargeFault(s, 10, 0, []byte{0}, func() {
		_ = s.View(func(*Reader) error { return nil })
	})
	mustEnvironment(t, err)
	txn := s.txn
	if txn == nil {
		t.Fatal("missing real retained transaction")
	}
	primary := nativePointerResultError(operationView, "mdbx_txn_begin returned invalid result shape", 5, true)
	var out ServingViewOutcomeV1
	s.operations.Lock()
	result := s.failedReadBegin(txn, primary)
	s.observeServingReadV1(&out, true)
	s.operations.Unlock()
	servingWantOutcomeV1(t, out, 3, false)
	if s.txn != txn || s.state != storePOISONEDTHREAD || !sameError(result, primary) || !sameError(s.terminal, primary) {
		t.Fatal("non-nil failed begin became NO_READ or lost native pointer/cause")
	}
	mustEnvironment(t, fixtureLargeRelease(s))
}

// servingFixtureRetainedSpanV1 proves required refusal retains a real abort pointer/cause.
func servingFixtureRetainedSpanV1(t *testing.T) {
	s, o, reservations := servingSetupV1(t)
	var out ServingViewOutcomeV1
	var result error
	_, err := fixtureLargeFault(s, 10, 0, []byte{0}, func() {
		out, result = servingCallV1(t, o, s, reservations, func(*Reader, *ServingEpochV1, *OperationAccount) error { return nil })
	})
	mustEnvironment(t, err)
	servingWantOutcomeV1(t, out, 3, false)
	txn, terminal := s.txn, s.terminal
	if txn == nil || !sameError(result, terminal) {
		t.Fatal("retained setup missing actual pointer/cause")
	}
	t.Cleanup(func() { _ = fixtureLargeRelease(s) })
	c, requiredResult, _ := servingRequiredV1(t, o, s, func() error {
		t.Fatal("retained native read allowed required effect")
		return nil
	})
	var got error
	select {
	case got = <-requiredResult:
	case <-c.waiting:
		t.Fatal("retained completion did not refuse")
	case <-time.After(5 * time.Second):
		t.Fatal("retained completion did not refuse")
	}
	servingWantBusyV1(t, got, "update")
	if s.txn != txn || !sameError(s.terminal, terminal) || s.state != storePOISONEDTHREAD {
		t.Fatal("required refusal altered retained truth")
	}
	servingRefusedV1(t, o, s, reservations)
	mustEnvironment(t, fixtureLargeRelease(s))
}

// servingFixtureInspectWakeV1 pauses actual native OLD abort before/after consumption.
func servingFixtureInspectWakeV1(t *testing.T, site uint32, late bool) {
	s, o, reservations := servingSetupV1(t)
	if !late {
		servingFreshV1(t, o, s, reservations, "initial binding failed")
	}
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	open := sync.OnceFunc(func() { close(release) })
	holder := make(chan error, 1)
	go func() {
		defer close(done)
		var result error
		_, err := FixturePairReadObservation(s, func(at uint32) {
			if at == site {
				close(entered)
				<-release
			}
		}, func() { _, result = s.Inspect() })
		if err == nil {
			err = result
		}
		holder <- err
	}()
	t.Cleanup(func() { open(); servingSignalV1(t, done, "Inspect cleanup stranded") })
	servingSignalV1(t, entered, "Inspect actual abort site not reached")
	called := 0
	c, result, _ := servingRequiredV1(t, o, s, func() error { called++; return nil })
	servingWaitingV1(t, c, result)
	open()
	mustEnvironment(t, servingResultV1(t, holder, "Inspect actual cleanup did not finish"))
	c.release()
	message := "native completion did not wake required invocation"
	if late {
		message = "late-bound completion did not wake required invocation"
	}
	mustEnvironment(t, servingResultV1(t, result, message))
	if called != 1 || s.txn != nil || s.state != storeOPEN {
		t.Fatal("Inspect completion changed callback/native state")
	}
	servingFreshV1(t, o, s, reservations, "resolved invocation retained priority")
}

// servingFixtureTerminalEntriesV1 shows optional closure adds no error over actual native state.
func servingFixtureTerminalEntriesV1(t *testing.T) {
	for _, mode := range []uint32{9, 10} {
		t.Run(fmt.Sprint(mode), func(t *testing.T) {
			s, o, reservations := servingSetupV1(t)
			_, err := fixtureLargeFault(s, mode, 0, []byte{0}, func() {
				_, _ = servingCallV1(t, o, s, reservations, func(*Reader, *ServingEpochV1, *OperationAccount) error { return nil })
			})
			mustEnvironment(t, err)
			terminal := s.terminal
			truth, stage, result := s.Update(func(*Reader) (Batch, error) {
				t.Fatal("terminal Update callback")
				return Batch{}, nil
			})
			if truth != 1 || stage != 1 || !sameError(result, terminal) {
				t.Fatal("serving mark replaced original terminal Update tuple")
			}
			mustEnvironment(t, reservations.WithOperation(LaneOperation, func(a *OperationAccount) error {
				truth, stage, index, result := s.UpdateTreeV1(a, func(*Reader) (TreeOperationV1, error) {
					t.Fatal("terminal tree callback")
					return TreeOperationV1{}, nil
				})
				if truth != 1 || stage != 1 || index != -1 || !sameError(result, terminal) {
					t.Fatal("serving mark replaced terminal tree tuple")
				}
				return nil
			}))
			if !sameError(s.Close(), terminal) {
				t.Fatal("serving mark replaced original terminal Close")
			}
			if mode == 10 {
				mustEnvironment(t, fixtureLargeRelease(s))
			}
		})
	}
}

// servingFixtureSpanNativeV1 keeps raw external outcome independent of nested native failure.
func servingFixtureSpanNativeV1(t *testing.T) {
	for _, mode := range []uint32{9, 10} {
		for _, kind := range []string{"nil", "error", "typed nil", "wrapped", "panic", "goexit"} {
			t.Run(fmt.Sprintf("%d/%s", mode, kind), func(t *testing.T) {
				s, o, reservations := servingSetupV1(t)
				app := errors.New("external raw result")
				if kind == "typed nil" {
					var typed *nilPointerError
					app = typed
				}
				if kind == "wrapped" {
					app = fmt.Errorf("external raw wrapper: %w", app)
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
						_, err := fixtureLargeFault(s, mode, 0, []byte{0}, func() {
							_ = s.View(func(*Reader) error { return nil })
						})
						mustEnvironment(t, err)
						servingRefusedV1(t, o, s, reservations)
						return servingModeV1(kind, app)
					})
					returned = true
				}()
				servingSignalV1(t, done, "external native callback/cleanup did not finish")
				if called != 1 {
					t.Fatal("cancellation replaced established result or replayed callback")
				}
				servingWantUnwindV1(t, kind, result, panicked, returned, app)
				if o.span != nil || s.terminal == nil || (mode == 10) != (s.txn != nil) {
					t.Fatal("external unwind altered actual nested native truth")
				}
				mustEnvironment(t, fixtureLargeRelease(s))
			})
		}
	}
}
