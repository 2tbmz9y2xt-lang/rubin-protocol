package mdbx

import (
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"runtime"
	"slices"
	"sync"
	"testing"
)

const (
	textReservationLimit    = "invalid storage operation reservation limit"
	textReservationInput    = "invalid storage operation reservation input"
	textReservationCapacity = "storage operation reservation capacity unavailable"
)

type reservationRow struct {
	label string
	run   func(t *testing.T, label string)
}

func runRows(t *testing.T, rows []reservationRow) {
	t.Helper()
	for _, row := range rows {
		t.Run(row.label, func(t *testing.T) { row.run(t, row.label) })
	}
}

func newOwner(t *testing.T, limit uint64) *OperationReservationOwner {
	t.Helper()
	owner, err := NewOperationReservationOwner(limit)
	if err != nil || owner == nil {
		t.Fatalf("%s: owner(%d): %v %v", t.Name(), limit, owner, err)
	}
	return owner
}

func wantSentinel(t *testing.T, label string, got, want error, text string) {
	t.Helper()
	if got != want || got.Error() != text { //nolint:errorlint // Exact sentinel identity is the contract.
		t.Fatalf("%s: err=%v, want %q", label, got, text)
	}
}

// admitted reports whether owner admits bytes through one counted callback; a refusal is
// the capacity sentinel and runs no callback.
func admitted(t *testing.T, label string, owner *OperationReservationOwner, bytes uint64) bool {
	t.Helper()
	calls := 0
	err := owner.WithReservation(bytes, func() error { calls++; return nil })
	if err == nil && calls == 1 {
		return true
	}
	wantSentinel(t, label, err, errOperationReservationCapacity, textReservationCapacity)
	if calls != 0 {
		t.Fatalf("%s: refused bytes %d ran the callback %d times", label, bytes, calls)
	}
	return false
}

func mustAdmit(t *testing.T, label string, owner *OperationReservationOwner, bytes uint64) {
	t.Helper()
	if !admitted(t, label, owner, bytes) {
		t.Fatalf("%s: bytes %d refused", label, bytes)
	}
}

func mustRefuse(t *testing.T, label string, owner *OperationReservationOwner, bytes uint64) {
	t.Helper()
	if admitted(t, label, owner, bytes) {
		t.Fatalf("%s: bytes %d admitted", label, bytes)
	}
}

// nested admits each weight in order and runs inner while all of them are live.
func nested(t *testing.T, label string, owner *OperationReservationOwner, weights []uint64, inner func()) {
	t.Helper()
	if len(weights) == 0 {
		inner()
		return
	}
	calls := 0
	err := owner.WithReservation(weights[0], func() error {
		calls++
		nested(t, label, owner, weights[1:], inner)
		return nil
	})
	if err != nil || calls != 1 {
		t.Fatalf("%s: weight %d err=%v calls=%d", label, weights[0], err, calls)
	}
}

func mustReserve(t *testing.T, label string, owner *OperationReservationOwner, bytes uint64) operationReservationToken {
	t.Helper()
	token, err := owner.reserve(bytes)
	if err != nil || token.grant == nil {
		t.Fatalf("%s: reserve(%d): %+v %v", label, bytes, token, err)
	}
	return token
}

func liveOf(owner *OperationReservationOwner) uint64 {
	owner.state.mu.Lock()
	defer owner.state.mu.Unlock()
	return owner.state.live
}

func TestOperationReservationOwnerConfiguration(t *testing.T) {
	runRows(t, []reservationRow{
		{"configuration oracle literal", func(t *testing.T, label string) {
			if MaxOperationDataBytes != 154611151 {
				t.Fatalf("%s: MaxOperationDataBytes=%d", label, MaxOperationDataBytes)
			}
		}},
		{"configuration exact minimum", func(t *testing.T, label string) {
			owner, err := NewOperationReservationOwner(154611151)
			if err != nil || owner == nil {
				t.Fatalf("%s: %v %v", label, owner, err)
			}
			mustAdmit(t, label, owner, 154611151)
		}},
		{"configuration below minimum", func(t *testing.T, label string) {
			for _, limit := range []uint64{154611150, 0} {
				owner, err := NewOperationReservationOwner(limit)
				if owner != nil {
					t.Fatalf("%s: limit %d returned owner %v", label, limit, owner)
				}
				wantSentinel(t, label, err, errOperationReservationLimit, textReservationLimit)
			}
		}},
		{"configuration maximum", func(t *testing.T, label string) {
			mustAdmit(t, label, newOwner(t, 18446744073709551615), 154611151)
		}},
	})
}

func TestOperationReservationOwnerBounds(t *testing.T) {
	full := []uint64{154611151, 154611151, 1}
	runRows(t, []reservationRow{
		{"bounds zero bytes", func(t *testing.T, label string) { mustAdmit(t, label, newOwner(t, 154611151), 0) }},
		{"bounds one byte", func(t *testing.T, label string) { mustAdmit(t, label, newOwner(t, 154611151), 1) }},
		{"bounds per-operation exact", func(t *testing.T, label string) {
			mustAdmit(t, label, newOwner(t, 309222303), 154611151)
		}},
		{"bounds aggregate exact", func(t *testing.T, label string) {
			inner := 0
			nested(t, label, newOwner(t, 309222303), full, func() { inner++ })
			if inner != 1 {
				t.Fatalf("%s: inner=%d", label, inner)
			}
		}},
		{"bounds per-operation one-over", func(t *testing.T, label string) {
			owner := newOwner(t, 309222303)
			for _, bytes := range []uint64{154611152, 18446744073709551615} {
				mustRefuse(t, label, owner, bytes)
			}
			nested(t, label, owner, full, func() {})
		}},
		{"bounds aggregate one-over", func(t *testing.T, label string) {
			owner := newOwner(t, 309222303)
			nested(t, label, owner, full, func() { mustRefuse(t, label, owner, 1) })
		}},
		{"bounds aggregate reuse after release", func(t *testing.T, label string) {
			owner := newOwner(t, 309222303)
			nested(t, label, owner, full[:2], func() {
				nested(t, label, owner, full[2:], func() {})
				mustAdmit(t, label, owner, 1)
			})
			nested(t, label, owner, full, func() {})
		}},
		{"bounds overflow witness", func(t *testing.T, label string) {
			owner := newOwner(t, 18446744073709551615)
			// The sum 18446744073709551614+2 has no public construction, so the live counter
			// is injected under the owner mutex and restored afterwards.
			owner.state.mu.Lock()
			owner.state.live = 18446744073709551614
			owner.state.mu.Unlock()
			mustAdmit(t, label, owner, 1)
			mustRefuse(t, label, owner, 2)
			owner.state.mu.Lock()
			owner.state.live = 0
			owner.state.mu.Unlock()
			mustAdmit(t, label, owner, 154611151)
		}},
	})
}

func TestOperationReservationOwnerOrder(t *testing.T) {
	invalid := func(owner *OperationReservationOwner) func(t *testing.T, label string) {
		return func(t *testing.T, label string) {
			calls := 0
			err := owner.WithReservation(1, func() error { calls++; return nil })
			wantSentinel(t, label, err, errOperationReservationInput, textReservationInput)
			if calls != 0 {
				t.Fatalf("%s: callback ran %d times", label, calls)
			}
		}
	}
	runRows(t, []reservationRow{
		{"order nil owner", invalid(nil)},
		{"order zero-value owner", invalid(&OperationReservationOwner{})},
		{"order nil callback before capacity", func(t *testing.T, label string) {
			owner := newOwner(t, 154611151)
			for _, bytes := range []uint64{154611152, 1} {
				wantSentinel(t, label, owner.WithReservation(bytes, nil), errOperationReservationInput, textReservationInput)
			}
			mustAdmit(t, label, owner, 154611151)
		}},
		{"order live charged during callback", func(t *testing.T, label string) {
			owner := newOwner(t, 154611151)
			nested(t, label, owner, []uint64{100}, func() {
				mustAdmit(t, label, owner, 154611051)
				mustRefuse(t, label, owner, 154611052)
			})
		}},
		{"order no callback on refusal", func(t *testing.T, label string) {
			owner := newOwner(t, 154611151)
			mustRefuse(t, label, owner, 154611152)
			nested(t, label, owner, []uint64{154611151}, func() { mustRefuse(t, label, owner, 1) })
			mustAdmit(t, label, owner, 154611151)
		}},
	})
}

// panicCycle runs a panicking full-capacity callback and reports the recovered value,
// whether the full capacity was admitted again inside the recovering frame, and the
// callback count.
func panicCycle(t *testing.T, label string, value any) (recovered any, restored bool, calls int) {
	t.Helper()
	owner := newOwner(t, 154611151)
	defer func() {
		recovered = recover()
		restored = admitted(t, label, owner, 154611151)
	}()
	_ = owner.WithReservation(154611151, func() error { calls++; panic(value) })
	return recovered, restored, calls
}

func TestOperationReservationOwnerLifecycle(t *testing.T) {
	direct := errors.New("direct")
	wrapped := fmt.Errorf("wrapped: %w", direct)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	exit := func(want error, exit func() error) func(t *testing.T, label string) {
		return func(t *testing.T, label string) {
			owner, calls := newOwner(t, 154611151), 0
			got := owner.WithReservation(154611151, func() error { calls++; return exit() })
			if got != want || calls != 1 { //nolint:errorlint // Exact callback error identity is the contract.
				t.Fatalf("%s: err=%v calls=%d", label, got, calls)
			}
			mustAdmit(t, label, owner, 154611151)
		}
	}
	runRows(t, []reservationRow{
		{"lifecycle nil error", exit(nil, func() error { return nil })},
		{"lifecycle direct error", exit(direct, func() error { return direct })},
		{"lifecycle wrapped error", exit(wrapped, func() error { return wrapped })},
		{"lifecycle canceled", exit(context.Canceled, func() error { cancel(); return ctx.Err() })},
		{"lifecycle deadline", exit(context.DeadlineExceeded, func() error { return context.DeadlineExceeded })},
		{"lifecycle panic identity", func(t *testing.T, label string) {
			value := &struct{ id int }{1}
			recovered, _, calls := panicCycle(t, label, value)
			if recovered != value || calls != 1 {
				t.Fatalf("%s: recovered=%v calls=%d", label, recovered, calls)
			}
		}},
		{"lifecycle live restored before panic", func(t *testing.T, label string) {
			if _, restored, _ := panicCycle(t, label, "value"); !restored {
				t.Fatalf("%s: capacity still charged at recovery", label)
			}
		}},
	})
}

// goexitCycle reserves the full capacity in a child goroutine whose callback calls
// runtime.Goexit and reports whether WithReservation returned and how often the
// callback ran.
func goexitCycle(owner *OperationReservationOwner) (returned bool, calls int) {
	var wg sync.WaitGroup
	wg.Go(func() {
		_ = owner.WithReservation(154611151, func() error { calls++; runtime.Goexit(); return nil })
		returned = true
	})
	wg.Wait()
	return returned, calls
}

func TestOperationReservationOwnerGoexit(t *testing.T) {
	owner := newOwner(t, 154611151)
	if returned, calls := goexitCycle(owner); returned || calls != 1 {
		t.Fatalf("goexit child terminated: returned=%v calls=%d", returned, calls)
	}
	mustAdmit(t, "goexit live restored", owner, 154611151)
	if returned, calls := goexitCycle(owner); returned || calls != 1 {
		t.Fatalf("goexit capacity reusable: returned=%v calls=%d", returned, calls)
	}
	mustAdmit(t, "goexit capacity reusable", owner, 154611151)
}

func TestOperationReservationOwnerIdentity(t *testing.T) {
	runRows(t, []reservationRow{
		{"identity duplicate release", func(t *testing.T, label string) {
			owner := newOwner(t, 154611151)
			token := mustReserve(t, label, owner, 100)
			mustReserve(t, label, owner, 100)
			if !owner.release(token) || liveOf(owner) != 100 {
				t.Fatalf("%s: first release left live=%d", label, liveOf(owner))
			}
			if owner.release(token) || liveOf(owner) != 100 {
				t.Fatalf("%s: second release left live=%d", label, liveOf(owner))
			}
		}},
		{"identity copied token after release", func(t *testing.T, label string) {
			owner := newOwner(t, 154611151)
			token := mustReserve(t, label, owner, 100)
			mustReserve(t, label, owner, 100)
			dup := token
			if !owner.release(token) || owner.release(dup) || liveOf(owner) != 100 {
				t.Fatalf("%s: live=%d", label, liveOf(owner))
			}
		}},
		{"identity foreign owner", func(t *testing.T, label string) {
			a, b := newOwner(t, 154611151), newOwner(t, 154611151)
			token := mustReserve(t, label, a, 100)
			mustReserve(t, label, b, 100)
			if b.release(token) || liveOf(a) != 100 || liveOf(b) != 100 {
				t.Fatalf("%s: a=%d b=%d", label, liveOf(a), liveOf(b))
			}
			if !a.release(token) || liveOf(a) != 0 {
				t.Fatalf("%s: origin release left a=%d", label, liveOf(a))
			}
		}},
		{"identity older owner", func(t *testing.T, label string) {
			older := newOwner(t, 154611151)
			token := mustReserve(t, label, older, 100)
			newer := newOwner(t, 154611151)
			mustAdmit(t, label, newer, 154611151)
			mustReserve(t, label, newer, 100)
			if newer.release(token) || liveOf(newer) != 100 || liveOf(older) != 100 {
				t.Fatalf("%s: newer=%d older=%d", label, liveOf(newer), liveOf(older))
			}
		}},
		{"identity zero token", func(t *testing.T, label string) {
			owner := newOwner(t, 154611151)
			mustReserve(t, label, owner, 100)
			if owner.release(operationReservationToken{}) || liveOf(owner) != 100 {
				t.Fatalf("%s: live=%d", label, liveOf(owner))
			}
		}},
		{"identity nil grant token", func(t *testing.T, label string) {
			owner := newOwner(t, 154611151)
			token := mustReserve(t, label, owner, 100)
			if owner.release(operationReservationToken{origin: token.origin}) || liveOf(owner) != 100 {
				t.Fatalf("%s: live=%d", label, liveOf(owner))
			}
		}},
		{"identity zero-byte token releases once", func(t *testing.T, label string) {
			owner := newOwner(t, 154611151)
			token := mustReserve(t, label, owner, 0)
			if !owner.release(token) || owner.release(token) || liveOf(owner) != 0 {
				t.Fatalf("%s: live=%d", label, liveOf(owner))
			}
		}},
		{"identity owner copy shares aggregate", func(t *testing.T, label string) {
			owner := newOwner(t, 154611151)
			dup := *owner
			nested(t, label, owner, []uint64{154611151}, func() { mustRefuse(t, label, &dup, 1) })
			mustAdmit(t, label, &dup, 154611151)
			token := mustReserve(t, label, &dup, 100)
			if !owner.release(token) || liveOf(owner) != 0 {
				t.Fatalf("%s: live=%d", label, liveOf(owner))
			}
		}},
	})
}

func TestOperationReservationOwnerConcurrent(t *testing.T) {
	owner := newOwner(t, 154611151)
	start, unblock, outcomes := make(chan struct{}), make(chan struct{}), make(chan error, 16)
	for range 8 {
		go func() {
			<-start
			outcomes <- owner.WithReservation(154611151, func() error { outcomes <- nil; <-unblock; return nil })
		}()
	}
	close(start)
	entered := 0
	for range 8 {
		if err := <-outcomes; err == nil {
			entered++
		} else {
			wantSentinel(t, "concurrent refusals are capacity", err, errOperationReservationCapacity, textReservationCapacity)
		}
	}
	if entered != 1 {
		t.Fatalf("concurrent single admission: entered=%d", entered)
	}
	close(unblock)
	if err := <-outcomes; err != nil {
		t.Fatalf("concurrent single admission: admitted result %v", err)
	}
	mustAdmit(t, "concurrent single admission", owner, 154611151)
}

func TestOperationReservationOwnerSurface(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "operation_reservation.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var imports, exports []string
	for _, spec := range file.Imports {
		imports = append(imports, spec.Path.Value)
	}
	exported := func(name string) {
		if ast.IsExported(name) {
			exports = append(exports, name)
		}
	}
	for _, decl := range file.Decls {
		switch decl := decl.(type) {
		case *ast.FuncDecl:
			exported(decl.Name.Name)
		case *ast.GenDecl:
			for _, spec := range decl.Specs {
				switch spec := spec.(type) {
				case *ast.TypeSpec:
					exported(spec.Name.Name)
				case *ast.ValueSpec:
					for _, name := range spec.Names {
						exported(name.Name)
					}
				}
			}
		}
	}
	slices.Sort(exports)
	if !slices.Equal(imports, []string{`"errors"`, `"sync"`}) {
		t.Fatalf("surface imports: %v", imports)
	}
	if !slices.Equal(exports, []string{"MaxOperationDataBytes", "NewOperationReservationOwner", "OperationReservationOwner", "WithReservation"}) {
		t.Fatalf("surface exports: %v", exports)
	}
}
