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
	"strconv"
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

func reservationRows(t *testing.T, rows []reservationRow) {
	t.Helper()
	for _, row := range rows {
		t.Run(row.label, func(t *testing.T) { row.run(t, row.label) })
	}
}

func reservationOwner(t *testing.T, limit uint64) *OperationReservationOwner {
	t.Helper()
	owner, err := NewOperationReservationOwner(limit)
	if err != nil || owner == nil {
		t.Fatalf("%s: owner(%d): %v %v", t.Name(), limit, owner, err)
	}
	return owner
}

func wantReservationSentinel(t *testing.T, label string, got, want error, text string) {
	t.Helper()
	if got != want || got.Error() != text { //nolint:errorlint // Exact sentinel identity is the contract.
		t.Fatalf("%s: err=%v, want %q", label, got, text)
	}
}

// reservationAdmitted reports whether owner admits bytes through one counted callback; a refusal runs none.
func reservationAdmitted(t *testing.T, label string, owner *OperationReservationOwner, bytes uint64) bool {
	t.Helper()
	calls := 0
	err := owner.WithReservation(bytes, func() error { calls++; return nil })
	if err == nil {
		if calls != 1 {
			t.Fatalf("%s: admitted bytes %d ran the callback %d times", label, bytes, calls)
		}
		return true
	}
	wantReservationSentinel(t, label, err, errOperationReservationCapacity, textReservationCapacity)
	if calls != 0 {
		t.Fatalf("%s: refused bytes %d ran the callback %d times", label, bytes, calls)
	}
	return false
}

func reservationMustAdmit(t *testing.T, label string, owner *OperationReservationOwner, bytes uint64) {
	t.Helper()
	if !reservationAdmitted(t, label, owner, bytes) {
		t.Fatalf("%s: bytes %d refused", label, bytes)
	}
}

// reservationMustRefuse requires a refusal that leaves the live counter unchanged.
func reservationMustRefuse(t *testing.T, label string, owner *OperationReservationOwner, bytes uint64) {
	t.Helper()
	before := reservationLive(owner)
	if reservationAdmitted(t, label, owner, bytes) {
		t.Fatalf("%s: bytes %d admitted", label, bytes)
	}
	if after := reservationLive(owner); after != before {
		t.Fatalf("%s: refusal of bytes %d changed live %d to %d", label, bytes, before, after)
	}
}

// reservationNested admits each weight in order and runs inner while all of them are live.
func reservationNested(t *testing.T, label string, owner *OperationReservationOwner, weights []uint64, inner func()) {
	t.Helper()
	if len(weights) == 0 {
		inner()
		return
	}
	calls := 0
	err := owner.WithReservation(weights[0], func() error {
		calls++
		reservationNested(t, label, owner, weights[1:], inner)
		return nil
	})
	if err != nil || calls != 1 {
		t.Fatalf("%s: weight %d err=%v calls=%d", label, weights[0], err, calls)
	}
}

func reservationReserve(t *testing.T, label string, owner *OperationReservationOwner, bytes uint64) operationReservationToken {
	t.Helper()
	token, err := owner.shared.reserve(bytes)
	if err != nil || token.grant == nil {
		t.Fatalf("%s: reserve(%d): %+v %v", label, bytes, token, err)
	}
	return token
}

func reservationLive(owner *OperationReservationOwner) uint64 {
	owner.shared.mu.Lock()
	defer owner.shared.mu.Unlock()
	return owner.shared.live
}

// reservationInjectLive overwrites the live counter under the owner mutex.
func reservationInjectLive(owner *OperationReservationOwner, live uint64) {
	owner.shared.mu.Lock()
	defer owner.shared.mu.Unlock()
	owner.shared.live = live
}

func TestOperationReservationOwnerConfiguration(t *testing.T) {
	reservationRows(t, []reservationRow{
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
			reservationMustAdmit(t, label, owner, 154611151)
		}},
		{"configuration below minimum", func(t *testing.T, label string) {
			for _, limit := range []uint64{154611150, 0} {
				owner, err := NewOperationReservationOwner(limit)
				if owner != nil {
					t.Fatalf("%s: limit %d returned owner %v", label, limit, owner)
				}
				wantReservationSentinel(t, label, err, errOperationReservationLimit, textReservationLimit)
			}
		}},
		{"configuration maximum", func(t *testing.T, label string) {
			reservationMustAdmit(t, label, reservationOwner(t, 18446744073709551615), 154611151)
		}},
	})
}

func TestOperationReservationOwnerBounds(t *testing.T) {
	full := []uint64{154611151, 154611151, 1}
	reservationRows(t, []reservationRow{
		{"bounds zero bytes", func(t *testing.T, label string) { reservationMustAdmit(t, label, reservationOwner(t, 154611151), 0) }},
		{"bounds one byte", func(t *testing.T, label string) { reservationMustAdmit(t, label, reservationOwner(t, 154611151), 1) }},
		{"bounds per-operation exact", func(t *testing.T, label string) {
			reservationMustAdmit(t, label, reservationOwner(t, 309222303), 154611151)
		}},
		{"bounds aggregate exact", func(t *testing.T, label string) {
			inner := 0
			reservationNested(t, label, reservationOwner(t, 309222303), full, func() { inner++ })
			if inner != 1 {
				t.Fatalf("%s: inner=%d", label, inner)
			}
		}},
		{"bounds per-operation one-over", func(t *testing.T, label string) {
			owner := reservationOwner(t, 309222303)
			for _, bytes := range []uint64{154611152, 18446744073709551615} {
				reservationMustRefuse(t, label, owner, bytes)
			}
			reservationNested(t, label, owner, full, func() {})
		}},
		{"bounds aggregate one-over", func(t *testing.T, label string) {
			owner := reservationOwner(t, 309222303)
			reservationNested(t, label, owner, full, func() { reservationMustRefuse(t, label, owner, 1) })
		}},
		{"bounds aggregate reuse after release", func(t *testing.T, label string) {
			owner := reservationOwner(t, 309222303)
			reservationNested(t, label, owner, full[:2], func() {
				reservationNested(t, label, owner, full[2:], func() {})
				reservationMustAdmit(t, label, owner, 1)
			})
			reservationNested(t, label, owner, full, func() {})
		}},
		{"bounds overflow witness", func(t *testing.T, label string) {
			owner := reservationOwner(t, 18446744073709551615)
			// The sum 18446744073709551614+2 has no public construction, so the live counter
			// is injected under the owner mutex and restored afterwards.
			reservationInjectLive(owner, 18446744073709551614)
			reservationMustAdmit(t, label, owner, 1)
			reservationMustRefuse(t, label, owner, 2)
			reservationInjectLive(owner, 0)
			reservationMustAdmit(t, label, owner, 154611151)
		}},
		{"bounds live above limit", func(t *testing.T, label string) {
			owner := reservationOwner(t, 154611151)
			reservationInjectLive(owner, 154611152)
			reservationMustRefuse(t, label, owner, 0)
			reservationInjectLive(owner, 0)
			reservationMustAdmit(t, label, owner, 154611151)
		}},
	})
}

func TestOperationReservationOwnerOrder(t *testing.T) {
	invalid := func(owner *OperationReservationOwner) func(t *testing.T, label string) {
		return func(t *testing.T, label string) {
			calls := 0
			err := owner.WithReservation(1, func() error { calls++; return nil })
			wantReservationSentinel(t, label, err, errOperationReservationInput, textReservationInput)
			if calls != 0 {
				t.Fatalf("%s: callback ran %d times", label, calls)
			}
		}
	}
	reservationRows(t, []reservationRow{
		{"order nil owner", invalid(nil)},
		{"order zero-value owner", invalid(&OperationReservationOwner{})},
		{"order nil callback before capacity", func(t *testing.T, label string) {
			owner := reservationOwner(t, 154611151)
			for _, bytes := range []uint64{154611152, 1} {
				wantReservationSentinel(t, label, owner.WithReservation(bytes, nil), errOperationReservationInput, textReservationInput)
			}
			reservationMustAdmit(t, label, owner, 154611151)
		}},
		{"order live charged during callback", func(t *testing.T, label string) {
			owner := reservationOwner(t, 154611151)
			reservationNested(t, label, owner, []uint64{100}, func() {
				reservationMustAdmit(t, label, owner, 154611051)
				reservationMustRefuse(t, label, owner, 154611052)
			})
		}},
		{"order no callback on refusal", func(t *testing.T, label string) {
			owner := reservationOwner(t, 154611151)
			reservationMustRefuse(t, label, owner, 154611152)
			reservationNested(t, label, owner, []uint64{154611151}, func() { reservationMustRefuse(t, label, owner, 1) })
			reservationMustAdmit(t, label, owner, 154611151)
		}},
	})
}

// reservationPanicCycle observes one panicking full-capacity callback from the frame that recovers it.
func reservationPanicCycle(t *testing.T, label string, value any) (recovered any, restored bool, calls int) {
	t.Helper()
	owner := reservationOwner(t, 154611151)
	defer func() {
		recovered = recover()
		restored = reservationAdmitted(t, label, owner, 154611151)
	}()
	_ = owner.WithReservation(154611151, func() error { calls++; panic(value) })
	return recovered, restored, calls
}

func TestOperationReservationOwnerLifecycle(t *testing.T) {
	direct := errors.New("direct")
	wrapped := fmt.Errorf("wrapped: %w", direct)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	exit := func(want error, exit func(owner *OperationReservationOwner) error) func(t *testing.T, label string) {
		return func(t *testing.T, label string) {
			owner, calls := reservationOwner(t, 154611151), 0
			state := owner.shared
			got := owner.WithReservation(154611151, func() error { calls++; return exit(owner) })
			if got != want || calls != 1 { //nolint:errorlint // Exact callback error identity is the contract.
				t.Fatalf("%s: err=%v calls=%d", label, got, calls)
			}
			reservationMustAdmit(t, label, &OperationReservationOwner{shared: state}, 154611151)
		}
	}
	reservationRows(t, []reservationRow{
		{"lifecycle nil error", exit(nil, func(*OperationReservationOwner) error { return nil })},
		{"lifecycle direct error", exit(direct, func(*OperationReservationOwner) error { return direct })},
		{"lifecycle wrapped error", exit(wrapped, func(*OperationReservationOwner) error { return wrapped })},
		{"lifecycle canceled", exit(context.Canceled, func(*OperationReservationOwner) error { cancel(); return ctx.Err() })},
		{"lifecycle deadline", exit(context.DeadlineExceeded, func(*OperationReservationOwner) error { return context.DeadlineExceeded })},
		{"lifecycle panic identity", func(t *testing.T, label string) {
			value := &struct{ id int }{1}
			recovered, _, calls := reservationPanicCycle(t, label, value)
			if recovered != value || calls != 1 {
				t.Fatalf("%s: recovered=%v calls=%d", label, recovered, calls)
			}
		}},
		{"lifecycle live restored before panic", func(t *testing.T, label string) {
			if _, restored, _ := reservationPanicCycle(t, label, "value"); !restored {
				t.Fatalf("%s: capacity still charged at recovery", label)
			}
		}},
		{"lifecycle owner overwritten during callback", exit(nil, func(owner *OperationReservationOwner) error { *owner = OperationReservationOwner{}; return nil })},
	})
}

// reservationGoexitCycle observes one full-capacity callback that calls runtime.Goexit in a child goroutine.
func reservationGoexitCycle(owner *OperationReservationOwner) (returned bool, calls int) {
	var wg sync.WaitGroup
	wg.Go(func() {
		_ = owner.WithReservation(154611151, func() error { calls++; runtime.Goexit(); return nil })
		returned = true
	})
	wg.Wait()
	return returned, calls
}

func TestOperationReservationOwnerGoexit(t *testing.T) {
	owner := reservationOwner(t, 154611151)
	for _, labels := range [][2]string{{"goexit child terminated", "goexit live restored"}, {"goexit capacity reusable", "goexit capacity reusable"}} {
		if returned, calls := reservationGoexitCycle(owner); returned || calls != 1 {
			t.Fatalf("%s: returned=%v calls=%d", labels[0], returned, calls)
		}
		reservationMustAdmit(t, labels[1], owner, 154611151)
	}
}

func TestOperationReservationOwnerIdentity(t *testing.T) {
	reservationRows(t, []reservationRow{
		{"identity duplicate release", func(t *testing.T, label string) {
			owner := reservationOwner(t, 154611151)
			token := reservationReserve(t, label, owner, 100)
			reservationReserve(t, label, owner, 100)
			if !owner.shared.release(token) || reservationLive(owner) != 100 {
				t.Fatalf("%s: first release left live=%d", label, reservationLive(owner))
			}
			if owner.shared.release(token) || reservationLive(owner) != 100 {
				t.Fatalf("%s: second release left live=%d", label, reservationLive(owner))
			}
		}},
		{"identity copied token after release", func(t *testing.T, label string) {
			owner := reservationOwner(t, 154611151)
			token := reservationReserve(t, label, owner, 100)
			reservationReserve(t, label, owner, 100)
			dup := token
			if !owner.shared.release(token) || owner.shared.release(dup) || reservationLive(owner) != 100 {
				t.Fatalf("%s: live=%d", label, reservationLive(owner))
			}
		}},
		{"identity foreign owner", func(t *testing.T, label string) {
			a, b := reservationOwner(t, 154611151), reservationOwner(t, 154611151)
			token := reservationReserve(t, label, a, 100)
			reservationReserve(t, label, b, 100)
			if b.shared.release(token) || reservationLive(a) != 100 || reservationLive(b) != 100 {
				t.Fatalf("%s: a=%d b=%d", label, reservationLive(a), reservationLive(b))
			}
			if !a.shared.release(token) || reservationLive(a) != 0 {
				t.Fatalf("%s: origin release left a=%d", label, reservationLive(a))
			}
		}},
		{"identity older owner", func(t *testing.T, label string) {
			older := reservationOwner(t, 154611151)
			token := reservationReserve(t, label, older, 100)
			newer := reservationOwner(t, 154611151)
			reservationMustAdmit(t, label, newer, 154611151)
			reservationReserve(t, label, newer, 100)
			if newer.shared.release(token) || reservationLive(newer) != 100 || reservationLive(older) != 100 {
				t.Fatalf("%s: newer=%d older=%d", label, reservationLive(newer), reservationLive(older))
			}
		}},
		{"identity zero token", func(t *testing.T, label string) {
			owner := reservationOwner(t, 154611151)
			reservationReserve(t, label, owner, 100)
			if owner.shared.release(operationReservationToken{}) || reservationLive(owner) != 100 {
				t.Fatalf("%s: live=%d", label, reservationLive(owner))
			}
		}},
		{"identity nil grant token", func(t *testing.T, label string) {
			owner := reservationOwner(t, 154611151)
			token := reservationReserve(t, label, owner, 100)
			if owner.shared.release(operationReservationToken{origin: token.origin}) || reservationLive(owner) != 100 {
				t.Fatalf("%s: live=%d", label, reservationLive(owner))
			}
		}},
		{"identity zero-byte token releases once", func(t *testing.T, label string) {
			owner := reservationOwner(t, 154611151)
			token := reservationReserve(t, label, owner, 0)
			if !owner.shared.release(token) || owner.shared.release(token) || reservationLive(owner) != 0 {
				t.Fatalf("%s: live=%d", label, reservationLive(owner))
			}
		}},
		{"identity owner copy shares aggregate", func(t *testing.T, label string) {
			owner := reservationOwner(t, 154611151)
			dup := *owner
			reservationNested(t, label, owner, []uint64{154611151}, func() { reservationMustRefuse(t, label, &dup, 1) })
			reservationMustAdmit(t, label, &dup, 154611151)
			token := reservationReserve(t, label, &dup, 100)
			if !owner.shared.release(token) || reservationLive(owner) != 0 {
				t.Fatalf("%s: live=%d", label, reservationLive(owner))
			}
		}},
		{"identity oversized token", func(t *testing.T, label string) {
			owner := reservationOwner(t, 154611151)
			token := reservationReserve(t, label, owner, 100)
			reservationInjectLive(owner, 50)
			if owner.shared.release(token) || reservationLive(owner) != 50 {
				t.Fatalf("%s: live=%d", label, reservationLive(owner))
			}
			reservationInjectLive(owner, 0)
		}},
	})
}

// reservationPartialWeights holds three concurrent reservations summing to the limit, probes one more byte, then releases.
func reservationPartialWeights(t *testing.T) {
	t.Helper()
	owner := reservationOwner(t, 309222303)
	hold, results := make(chan struct{}), make(chan error, 6)
	unhold := sync.OnceFunc(func() { close(hold) })
	defer unhold()
	coexist := func() {
		for range 3 {
			if err := <-results; err != nil {
				t.Fatalf("concurrent partial weights coexist: %v", err)
			}
		}
	}
	for _, weight := range []uint64{154611151, 154611151, 1} {
		go func() {
			results <- owner.WithReservation(weight, func() error { results <- nil; <-hold; return nil })
		}()
	}
	coexist()
	reservationMustRefuse(t, "concurrent partial weights exhaust", owner, 1)
	unhold()
	coexist()
	reservationNested(t, "concurrent partial weights reusable", owner, []uint64{154611151, 154611151, 1}, func() {})
}

func TestOperationReservationOwnerConcurrent(t *testing.T) {
	owner := reservationOwner(t, 154611151)
	dup := *owner
	handles := [2]*OperationReservationOwner{owner, &dup}
	start, unblock, outcomes := make(chan struct{}), make(chan struct{}), make(chan error, 16)
	unblockOnce := sync.OnceFunc(func() { close(unblock) })
	defer unblockOnce()
	for i := range 8 {
		go func() {
			<-start
			outcomes <- handles[i%2].WithReservation(154611151, func() error { outcomes <- nil; <-unblock; return nil })
		}()
	}
	close(start)
	entered := 0
	for range 8 {
		if err := <-outcomes; err == nil {
			entered++
		} else {
			wantReservationSentinel(t, "concurrent refusals are capacity", err, errOperationReservationCapacity, textReservationCapacity)
		}
	}
	if live := reservationLive(owner); entered != 1 || live != 154611151 {
		t.Fatalf("concurrent single admission: entered=%d live=%d", entered, live)
	}
	unblockOnce()
	if err := <-outcomes; err != nil {
		t.Fatalf("concurrent single admission: admitted result %v", err)
	}
	reservationMustAdmit(t, "concurrent single admission", owner, 154611151)
	reservationPartialWeights(t)
}

// reservationCensus is the parsed surface of one package file: imports, sorted exported
// top-level and method names, exported struct field names, storage identifiers and the
// MaxPrefixPageBytes literal.
type reservationCensus struct {
	imports, exports, fields, storage []string
	sibling                           string
}

func reservationParse(t *testing.T, name string) reservationCensus {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), name, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	forbidden := []string{"Store", "Reader", "ConfigV1", "Batch", "Mutation", "updateBudget", "DBI"}
	exported := func(names []string, idents ...*ast.Ident) []string {
		for _, ident := range idents {
			if ident != nil && ast.IsExported(ident.Name) {
				names = append(names, ident.Name)
			}
		}
		return names
	}
	var c reservationCensus
	for name := range file.Scope.Objects {
		c.exports = exported(c.exports, ast.NewIdent(name))
	}
	ast.Inspect(file, func(node ast.Node) bool {
		switch node := node.(type) {
		case *ast.ImportSpec:
			c.imports = append(c.imports, node.Path.Value)
		case *ast.FuncDecl:
			if node.Recv != nil {
				c.exports = exported(c.exports, node.Name)
			}
		case *ast.ValueSpec:
			if len(node.Values) == 1 && node.Names[0].Name == "MaxPrefixPageBytes" {
				if lit, ok := node.Values[0].(*ast.BasicLit); ok {
					c.sibling = lit.Value
				}
			}
		case *ast.StructType:
			for _, field := range node.Fields.List {
				names := field.Names
				if len(names) == 0 { // An embedded field carries every identifier of its type expression.
					ast.Inspect(field.Type, func(n ast.Node) bool { ident, _ := n.(*ast.Ident); names = append(names, ident); return true })
				}
				c.fields = exported(c.fields, names...)
			}
		case *ast.Ident:
			if slices.Contains(forbidden, node.Name) {
				c.storage = append(c.storage, node.Name)
			}
		}
		return true
	})
	slices.Sort(c.exports)
	return c
}

func TestOperationReservationOwnerSurface(t *testing.T) {
	bound, err := strconv.ParseUint(reservationParse(t, "mdbx_cgo.go").sibling, 0, 64)
	if err != nil || bound != 154611151 {
		t.Fatalf("surface sibling bound: MaxPrefixPageBytes=%d %v", bound, err)
	}
	if bound != MaxOperationDataBytes {
		t.Fatalf("surface sibling bound: MaxPrefixPageBytes=%d MaxOperationDataBytes=%d", bound, MaxOperationDataBytes)
	}
	own := reservationParse(t, "operation_reservation.go")
	if !slices.Equal(own.imports, []string{`"errors"`, `"sync"`}) {
		t.Fatalf("surface imports: %v", own.imports)
	}
	if !slices.Equal(own.exports, []string{"MaxOperationDataBytes", "NewOperationReservationOwner", "OperationReservationOwner", "WithReservation"}) {
		t.Fatalf("surface exports: %v", own.exports)
	}
	if len(own.fields) != 0 {
		t.Fatalf("surface opaque fields: %v", own.fields)
	}
	if len(own.storage) != 0 {
		t.Fatalf("surface no storage identifiers: %v", own.storage)
	}
}
