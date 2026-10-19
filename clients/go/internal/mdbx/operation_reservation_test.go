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
	textReservationInput    = "invalid storage operation reservation input"
	textReservationCapacity = "storage operation reservation capacity unavailable"
)

type reservationRow struct {
	label string
	run   func(t *testing.T, label string)
}

func TestOperationReservationCapacityIdentity(t *testing.T) {
	for _, row := range []struct {
		name string
		err  error
		want bool
	}{
		{"direct", errOperationReservationCapacity, true},
		{"nil", nil, false},
		{"input", errOperationReservationInput, false},
		{"wrapped", fmt.Errorf("wrapped: %w", errOperationReservationCapacity), false},
		{"joined", errors.Join(errOperationReservationCapacity), false},
		{"same text", errors.New("storage operation reservation capacity unavailable"), false},
	} {
		t.Run(row.name, func(t *testing.T) {
			if got := IsOperationReservationCapacity(row.err); got != row.want {
				t.Fatalf("capacity identity=%v, want %v", got, row.want)
			}
		})
	}
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

// Spec literals (RUBIN_COMPACT_BLOCKS §10): LANE_MAX, TREE_LANE_MAX and R_MIN = R_DEFAULT.
const (
	specLaneMax     uint64 = 154611183
	specTreeLaneMax uint64 = 402653184
	specRMin        uint64 = 805306368
)

// reservationFill holds bytes on owner, in legacy charges of at most LANE_MAX, until t's cleanup.
func reservationFill(t *testing.T, owner *OperationReservationOwner, bytes uint64) {
	t.Helper()
	hold, entered := make(chan struct{}), make(chan error)
	var wg sync.WaitGroup
	t.Cleanup(func() { close(hold); wg.Wait() })
	for bytes > 0 {
		chunk := min(bytes, specLaneMax)
		bytes -= chunk
		wg.Go(func() {
			if err := owner.WithReservation(chunk, func() error { entered <- nil; <-hold; return nil }); err != nil {
				entered <- err
			}
		})
		if err := <-entered; err != nil {
			t.Fatalf("%s: reservation filler %d: %v", t.Name(), chunk, err)
		}
	}
}

// reservationFilled returns an R_MIN owner whose free remainder is exactly remaining for t's lifetime.
func reservationFilled(t *testing.T, remaining uint64) *OperationReservationOwner {
	t.Helper()
	owner := reservationOwner(t, specRMin)
	reservationFill(t, owner, specRMin-remaining)
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
	token, err := owner.shared.reserve(nil, bytes)
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
		{"A6 legacy budget literal", func(t *testing.T, label string) {
			if MaxOperationDataBytes != 154611151 {
				t.Fatalf("%s: MaxOperationDataBytes=%d", label, MaxOperationDataBytes)
			}
		}},
		{"A1 constructor admits every limit", func(t *testing.T, label string) {
			for _, limit := range []uint64{0, 1, 154611151, 805306367, 805306368, 18446744073709551615} {
				t.Run(fmt.Sprintf("A1 constructor limit %d", limit), func(t *testing.T) {
					owner, err := NewOperationReservationOwner(limit)
					if err != nil || owner == nil || owner.shared.limit != limit || reservationLive(owner) != 0 {
						t.Fatalf("%s: limit %d: %v %v", label, limit, owner, err)
					}
				})
			}
		}},
		{"A1 R_MIN admits legacy", func(t *testing.T, label string) {
			owner := reservationOwner(t, specRMin)
			reservationMustAdmit(t, label, owner, 0)
			reservationMustAdmit(t, label, owner, specLaneMax)
		}},
		{"A1 maximum admits tree", func(t *testing.T, label string) {
			accountRun(t, label, reservationOwner(t, 18446744073709551615), TreeOperation, func(a *OperationAccount) {
				accountMustAdmit(t, label, a, specTreeLaneMax, func() {})
			})
		}},
	})
}

func TestOperationReservationOwnerBounds(t *testing.T) {
	full := []uint64{154611151, 154611151, 1}
	reservationRows(t, []reservationRow{
		{"bounds zero bytes", func(t *testing.T, label string) { reservationMustAdmit(t, label, reservationFilled(t, 154611151), 0) }},
		{"bounds one byte", func(t *testing.T, label string) { reservationMustAdmit(t, label, reservationFilled(t, 154611151), 1) }},
		{"bounds per-operation exact", func(t *testing.T, label string) {
			reservationMustAdmit(t, label, reservationFilled(t, 309222303), 154611151)
		}},
		{"bounds aggregate exact", func(t *testing.T, label string) {
			inner := 0
			reservationNested(t, label, reservationFilled(t, 309222303), full, func() { inner++ })
			if inner != 1 {
				t.Fatalf("%s: inner=%d", label, inner)
			}
		}},
		{"bounds per-operation one-over", func(t *testing.T, label string) {
			owner := reservationFilled(t, 309222303)
			for _, bytes := range []uint64{154611184, 18446744073709551615} {
				reservationMustRefuse(t, label, owner, bytes)
			}
			reservationNested(t, label, owner, full, func() {})
		}},
		{"bounds aggregate one-over", func(t *testing.T, label string) {
			owner := reservationFilled(t, 309222303)
			reservationNested(t, label, owner, full, func() { reservationMustRefuse(t, label, owner, 1) })
		}},
		{"bounds aggregate reuse after release", func(t *testing.T, label string) {
			owner := reservationFilled(t, 309222303)
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
			owner := reservationOwner(t, specRMin)
			reservationInjectLive(owner, 805306369)
			reservationMustRefuse(t, label, owner, 0)
			reservationInjectLive(owner, 0)
			reservationMustAdmit(t, label, owner, 154611151)
		}},
		{"R3 live at limit", func(t *testing.T, label string) {
			owner := reservationOwner(t, specRMin)
			reservationInjectLive(owner, 805306368)
			reservationMustRefuse(t, label, owner, 1)
			accountRun(t, label, owner, TreeOperation, func(a *OperationAccount) { accountMustRefuse(t, label, a, 1) })
			reservationInjectLive(owner, 805306363)
			reservationMustRefuse(t, label, owner, 6)
			accountRun(t, label, owner, TreeOperation, func(a *OperationAccount) {
				accountMustRefuse(t, label, a, 6)
				accountMustAdmit(t, label, a, 5, func() {})
			})
			reservationInjectLive(owner, 0)
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
			owner := reservationFilled(t, 154611151)
			for _, bytes := range []uint64{154611152, 1} {
				wantReservationSentinel(t, label, owner.WithReservation(bytes, nil), errOperationReservationInput, textReservationInput)
			}
			reservationMustAdmit(t, label, owner, 154611151)
		}},
		{"order live charged during callback", func(t *testing.T, label string) {
			owner := reservationFilled(t, 154611151)
			reservationNested(t, label, owner, []uint64{100}, func() {
				reservationMustAdmit(t, label, owner, 154611051)
				reservationMustRefuse(t, label, owner, 154611052)
			})
		}},
		{"order no callback on refusal", func(t *testing.T, label string) {
			owner := reservationFilled(t, 154611151)
			reservationMustRefuse(t, label, owner, 154611152)
			reservationNested(t, label, owner, []uint64{154611151}, func() { reservationMustRefuse(t, label, owner, 1) })
			reservationMustAdmit(t, label, owner, 154611151)
		}},
	})
}

// reservationPanicCycle observes one panicking full-capacity callback from the frame that recovers it.
func reservationPanicCycle(t *testing.T, label string, value any) (recovered any, restored bool, calls int) {
	t.Helper()
	owner := reservationFilled(t, 154611151)
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
			owner, calls := reservationFilled(t, 154611151), 0
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
	owner := reservationFilled(t, 154611151)
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
			owner := reservationOwner(t, specRMin)
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
			owner := reservationOwner(t, specRMin)
			token := reservationReserve(t, label, owner, 100)
			reservationReserve(t, label, owner, 100)
			dup := token
			if !owner.shared.release(token) || owner.shared.release(dup) || reservationLive(owner) != 100 {
				t.Fatalf("%s: live=%d", label, reservationLive(owner))
			}
		}},
		{"identity foreign owner", func(t *testing.T, label string) {
			a, b := reservationOwner(t, specRMin), reservationOwner(t, specRMin)
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
			older := reservationOwner(t, specRMin)
			token := reservationReserve(t, label, older, 100)
			newer := reservationOwner(t, specRMin)
			reservationMustAdmit(t, label, newer, 154611151)
			reservationReserve(t, label, newer, 100)
			if newer.shared.release(token) || reservationLive(newer) != 100 || reservationLive(older) != 100 {
				t.Fatalf("%s: newer=%d older=%d", label, reservationLive(newer), reservationLive(older))
			}
		}},
		{"identity zero token", func(t *testing.T, label string) {
			owner := reservationOwner(t, specRMin)
			reservationReserve(t, label, owner, 100)
			if owner.shared.release(operationReservationToken{}) || reservationLive(owner) != 100 {
				t.Fatalf("%s: live=%d", label, reservationLive(owner))
			}
		}},
		{"identity nil grant token", func(t *testing.T, label string) {
			owner := reservationOwner(t, specRMin)
			token := reservationReserve(t, label, owner, 100)
			if owner.shared.release(operationReservationToken{origin: token.origin}) || reservationLive(owner) != 100 {
				t.Fatalf("%s: live=%d", label, reservationLive(owner))
			}
		}},
		{"identity zero-byte token releases once", func(t *testing.T, label string) {
			owner := reservationOwner(t, specRMin)
			token := reservationReserve(t, label, owner, 0)
			if !owner.shared.release(token) || owner.shared.release(token) || reservationLive(owner) != 0 {
				t.Fatalf("%s: live=%d", label, reservationLive(owner))
			}
		}},
		{"identity owner copy shares aggregate", func(t *testing.T, label string) {
			owner := reservationFilled(t, 154611151)
			dup := *owner
			reservationNested(t, label, owner, []uint64{154611151}, func() { reservationMustRefuse(t, label, &dup, 1) })
			reservationMustAdmit(t, label, &dup, 154611151)
			token := reservationReserve(t, label, &dup, 100)
			if !owner.shared.release(token) || reservationLive(owner) != 650695217 {
				t.Fatalf("%s: live=%d", label, reservationLive(owner))
			}
		}},
		{"identity oversized token", func(t *testing.T, label string) {
			owner := reservationOwner(t, specRMin)
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
	owner := reservationFilled(t, 309222303)
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
	owner := reservationFilled(t, 154611151)
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
	if live := reservationLive(owner); entered != 1 || live != 650695217+154611151 {
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
// MaxPrefixPageBytes value expression.
type reservationCensus struct {
	imports, exports, fields, storage []string
	sibling                           ast.Expr
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
				c.sibling = node.Values[0]
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
	// The cgo-only MaxPrefixPageBytes is bound to this identifier by the cgo build; its value is the alias target's.
	sibling := reservationParse(t, "mdbx_cgo.go").sibling
	if alias, ok := sibling.(*ast.Ident); !ok || alias.Name != "MaxOperationDataBytes" || MaxOperationDataBytes != 154611151 {
		t.Fatalf("surface sibling alias: MaxPrefixPageBytes=%T %+v MaxOperationDataBytes=%d, want the identifier MaxOperationDataBytes = 154611151", sibling, sibling, MaxOperationDataBytes)
	}
	own := reservationParse(t, "operation_reservation.go")
	if !slices.Equal(own.imports, []string{`"errors"`, `"sync"`}) {
		t.Fatalf("surface imports: %v", own.imports)
	}
	if !slices.Equal(own.exports, []string{"IsOperationReservationCapacity", "LaneMaxBytes", "LaneOperation", "MaxOperationDataBytes", "MinReservationLimit", "NewOperationReservationOwner", "OperationAccount", "OperationKind", "OperationReservationOwner", "TreeLaneMaxBytes", "TreeOperation", "WithOperation", "WithReservation", "WithReservation"}) {
		t.Fatalf("surface exports: %v", own.exports)
	}
	if len(own.fields) != 0 {
		t.Fatalf("surface opaque fields: %v", own.fields)
	}
	if len(own.storage) != 0 {
		t.Fatalf("surface no storage identifiers: %v", own.storage)
	}
}

// accountRun opens kind on owner and runs body with its account; WithOperation must return nil after one callback.
func accountRun(t *testing.T, label string, owner *OperationReservationOwner, kind OperationKind, body func(*OperationAccount)) {
	t.Helper()
	calls := 0
	if err := owner.WithOperation(kind, func(a *OperationAccount) error { calls++; body(a); return nil }); err != nil || calls != 1 {
		t.Fatalf("%s: WithOperation(%d) err=%v calls=%d", label, kind, err, calls)
	}
}

func accountHeld(a *OperationAccount) uint64 {
	a.shared.origin.mu.Lock()
	defer a.shared.origin.mu.Unlock()
	return a.shared.held
}

// accountCharge charges bytes on a, running inner while held, and reports admission; a refusal must be the
// capacity singleton with no callback and no held or live change.
func accountCharge(t *testing.T, label string, a *OperationAccount, bytes uint64, inner func()) bool {
	t.Helper()
	held, live, calls := accountHeld(a), reservationLive(&OperationReservationOwner{a.shared.origin}), 0
	err := a.WithReservation(bytes, func() error { calls++; inner(); return nil })
	if err == nil {
		if after := reservationLive(&OperationReservationOwner{a.shared.origin}); calls != 1 || accountHeld(a) != held || after != live {
			t.Fatalf("%s: admitted bytes %d calls=%d held=%d (want %d) live=%d (want %d)", label, bytes, calls, accountHeld(a), held, after, live)
		}
		return true
	}
	wantReservationSentinel(t, label, err, errOperationReservationCapacity, textReservationCapacity)
	if after := reservationLive(&OperationReservationOwner{a.shared.origin}); calls != 0 || accountHeld(a) != held || after != live {
		t.Fatalf("%s: refused bytes %d calls=%d held=%d (want %d) live=%d (want %d)", label, bytes, calls, accountHeld(a), held, after, live)
	}
	return false
}

func accountMustAdmit(t *testing.T, label string, a *OperationAccount, bytes uint64, inner func()) {
	t.Helper()
	if !accountCharge(t, label, a, bytes, inner) {
		t.Fatalf("%s: account bytes %d refused", label, bytes)
	}
}

func accountMustRefuse(t *testing.T, label string, a *OperationAccount, bytes uint64) {
	t.Helper()
	if accountCharge(t, label, a, bytes, func() {}) {
		t.Fatalf("%s: account bytes %d admitted", label, bytes)
	}
}

// accountInput requires the input refusal from a charge on a, with no callback and no live change on owner.
func accountInput(t *testing.T, label string, owner *OperationReservationOwner, a *OperationAccount, bytes uint64, callback func() error) {
	t.Helper()
	before := reservationLive(owner)
	wantReservationSentinel(t, label, a.WithReservation(bytes, callback), errOperationReservationInput, textReservationInput)
	if after := reservationLive(owner); after != before {
		t.Fatalf("%s: input refusal changed live %d to %d", label, before, after)
	}
}

func TestOperationReservationFloor(t *testing.T) {
	sentinel := errors.New("A7 sentinel")
	for _, limit := range []uint64{0, 805306367} {
		owner := reservationOwner(t, limit)
		t.Run(fmt.Sprintf("R1 below R_MIN %d", limit), func(t *testing.T) {
			for range 100 {
				for _, bytes := range []uint64{0, 1} {
					reservationMustRefuse(t, "R1 legacy", owner, bytes)
					for _, kind := range []OperationKind{LaneOperation, TreeOperation} {
						accountRun(t, "R1 account", owner, kind, func(a *OperationAccount) { accountMustRefuse(t, "R1 account", a, bytes) })
					}
				}
			}
			var wg sync.WaitGroup
			for range 8 {
				wg.Go(func() {
					if err := owner.WithReservation(1, func() error { return nil }); err != errOperationReservationCapacity { //nolint:errorlint // Exact sentinel identity is the contract.
						t.Errorf("R1 concurrent: %v", err)
					}
				})
			}
			wg.Wait()
			if live := reservationLive(owner); live != 0 {
				t.Fatalf("R1 live=%d", live)
			}
		})
		t.Run(fmt.Sprintf("A7 WithOperation is not a capacity check %d", limit), func(t *testing.T) {
			for _, kind := range []OperationKind{LaneOperation, TreeOperation} {
				for _, want := range []error{nil, sentinel} {
					calls := 0
					got := owner.WithOperation(kind, func(a *OperationAccount) error {
						calls++
						accountMustRefuse(t, "A7 inner charge", a, 0)
						return want
					})
					if got != want || calls != 1 { //nolint:errorlint // Exact callback error identity is the contract.
						t.Fatalf("A7 kind %d: err=%v calls=%d", kind, got, calls)
					}
				}
			}
		})
	}
}

func TestOperationReservationCeilings(t *testing.T) {
	t.Run("A2 lane ceiling", func(t *testing.T) {
		owner := reservationOwner(t, specRMin)
		accountRun(t, "A2", owner, LaneOperation, func(a *OperationAccount) {
			accountMustAdmit(t, "A2 single", a, specLaneMax, func() {})
			accountMustAdmit(t, "A2 nested zero", a, specLaneMax, func() { accountMustAdmit(t, "A2 nested zero", a, 0, func() {}) })
		})
		reservationMustAdmit(t, "A2 legacy", owner, specLaneMax)
		if live := reservationLive(owner); live != 0 {
			t.Fatalf("A2 live=%d", live)
		}
	})
	t.Run("A3 tree ceiling", func(t *testing.T) {
		owner := reservationOwner(t, specRMin)
		accountRun(t, "A3", owner, TreeOperation, func(a *OperationAccount) {
			accountMustAdmit(t, "A3 single", a, specTreeLaneMax, func() {})
			accountMustAdmit(t, "A3 nested", a, 200000000, func() {
				accountMustAdmit(t, "A3 nested sum", a, 202653184, func() {
					if held := accountHeld(a); held != 402653184 {
						t.Fatalf("A3 held=%d", held)
					}
				})
				accountMustAdmit(t, "A3 reuse after inner release", a, 202653184, func() {})
				accountMustRefuse(t, "A3 no reset while held", a, 202653185)
			})
		})
	})
	for _, limit := range []uint64{805306368, 18446744073709551615} {
		t.Run(fmt.Sprintf("R2 ceiling plus one %d", limit), func(t *testing.T) {
			owner := reservationOwner(t, limit)
			for _, bytes := range []uint64{154611184, 18446744073709551615} {
				reservationMustRefuse(t, "R2 legacy", owner, bytes)
				accountRun(t, "R2 lane", owner, LaneOperation, func(a *OperationAccount) { accountMustRefuse(t, "R2 lane", a, bytes) })
			}
			for _, bytes := range []uint64{402653185, 18446744073709551615} {
				accountRun(t, "R2 tree", owner, TreeOperation, func(a *OperationAccount) { accountMustRefuse(t, "R2 tree", a, bytes) })
			}
			nested := func(kind OperationKind, outer, inner uint64) {
				t.Run(fmt.Sprintf("R2 nested kind %d %d then %d", kind, outer, inner), func(t *testing.T) {
					accountRun(t, "R2 nested", owner, kind, func(a *OperationAccount) {
						accountMustAdmit(t, "R2 nested outer", a, outer, func() { accountMustRefuse(t, "R2 nested inner", a, inner) })
					})
				})
			}
			nested(LaneOperation, 154611183, 1)
			nested(TreeOperation, 300000000, 200000000)
			if live := reservationLive(owner); live != 0 {
				t.Fatalf("R2 outer not released once: live=%d", live)
			}
		})
	}
}

// accountHold charges bytes on a from a new goroutine and returns once admitted; closing the returned channel
// releases it and done reports its return.
func accountHold(t *testing.T, a *OperationAccount, bytes uint64) (release chan struct{}, done chan error) {
	t.Helper()
	release, done, entered := make(chan struct{}), make(chan error, 1), make(chan struct{})
	go func() { done <- a.WithReservation(bytes, func() error { close(entered); <-release; return nil }) }()
	select {
	case <-entered:
	case err := <-done:
		t.Fatalf("hold %d refused: %v", bytes, err)
	}
	return release, done
}

// operationHold opens kind on owner in a new goroutine and charges bytes on it until release is closed; done
// reports WithOperation's return.
func operationHold(t *testing.T, owner *OperationReservationOwner, kind OperationKind, bytes uint64) (release chan struct{}, done chan error) {
	t.Helper()
	release, done, entered := make(chan struct{}), make(chan error, 1), make(chan struct{})
	go func() {
		done <- owner.WithOperation(kind, func(a *OperationAccount) error {
			return a.WithReservation(bytes, func() error { close(entered); <-release; return nil })
		})
	}()
	select {
	case <-entered:
	case err := <-done:
		t.Fatalf("operation hold %d refused: %v", bytes, err)
	}
	return release, done
}

func TestOperationReservationAggregate(t *testing.T) {
	owner := reservationOwner(t, specRMin)
	dup := *owner
	r1, d1 := operationHold(t, owner, TreeOperation, 402653184)
	r2, d2 := operationHold(t, &dup, TreeOperation, 402653184)
	if live := reservationLive(owner); live != 805306368 {
		t.Fatalf("A4 live=%d", live)
	}
	reservationMustRefuse(t, "A4 legacy third", owner, 1)
	reservationMustRefuse(t, "A4 copy third", &dup, 1)
	accountRun(t, "A4 lane third", owner, LaneOperation, func(a *OperationAccount) { accountMustRefuse(t, "A4 lane third", a, 1) })
	close(r1)
	if err := <-d1; err != nil {
		t.Fatalf("A4 first: %v", err)
	}
	reservationMustAdmit(t, "A4 after release", owner, 1)
	close(r2)
	if err := <-d2; err != nil {
		t.Fatalf("A4 second: %v", err)
	}
}

func TestOperationAccountErrorIdentity(t *testing.T) {
	owner := reservationOwner(t, specRMin)
	sentinel := &struct{ error }{errors.New("A5 sentinel")}
	for _, want := range []error{nil, sentinel} {
		var inner error
		got := owner.WithOperation(TreeOperation, func(a *OperationAccount) error {
			inner = a.WithReservation(1, func() error { return want })
			return inner
		})
		if got != want || inner != want || !errors.Is(got, want) { //nolint:errorlint // Exact callback error identity is the contract.
			t.Fatalf("A5: got=%v inner=%v want=%v", got, inner, want)
		}
	}
}

func TestOperationAccountInput(t *testing.T) {
	owner := reservationOwner(t, specRMin)
	run := func(label string, o *OperationReservationOwner, kind OperationKind, withCallback bool) {
		calls := 0
		callback := func(*OperationAccount) error { calls++; return nil }
		if !withCallback {
			callback = nil
		}
		wantReservationSentinel(t, label, o.WithOperation(kind, callback), errOperationReservationInput, textReservationInput)
		if calls != 0 {
			t.Fatalf("%s: callback ran %d times", label, calls)
		}
	}
	for _, kind := range []OperationKind{0, 3, 255} {
		run(fmt.Sprintf("R4 kind %d", kind), owner, kind, true)
	}
	run("R4 nil owner", nil, TreeOperation, true)
	run("R4 zero-value owner", &OperationReservationOwner{}, TreeOperation, true)
	run("R4 zero-value owner below floor irrelevant", &OperationReservationOwner{}, LaneOperation, true)
	run("R4 nil callback", owner, TreeOperation, false)
	ran := func() error { t.Fatal("R4 refused charge ran its callback"); return nil }
	var retained *OperationAccount
	accountRun(t, "R4 retain", owner, TreeOperation, func(a *OperationAccount) {
		retained = a
		accountInput(t, "R4 nil callback", owner, a, 1, nil)
		accountInput(t, "R4 nil callback over ceiling", owner, a, 402653185, nil)
	})
	accountInput(t, "R4 nil account", owner, (*OperationAccount)(nil), 1, ran)
	accountInput(t, "R4 zero-value account", owner, new(OperationAccount), 0, ran)
	accountInput(t, "R4 closed account", owner, retained, 1, ran)
	accountInput(t, "R4 closed account over ceiling", owner, retained, 18446744073709551615, ran)
	accountInput(t, "R4 closed account below floor", reservationOwner(t, 0), retained, 0, ran)
	if held := accountHeld(retained); held != 0 {
		t.Fatalf("R4 closed held=%d", held)
	}
}

// accountReleaseOrder holds two charges on one open tree account, probes one more byte, then releases them in order.
func accountReleaseOrder(t *testing.T, label string, reverse bool) {
	owner := reservationOwner(t, specRMin)
	accountRun(t, label, owner, TreeOperation, func(a *OperationAccount) {
		r1, d1 := accountHold(t, a, 200000000)
		r2, d2 := accountHold(t, a, 202653184)
		if held, live := accountHeld(a), reservationLive(owner); held != 402653184 || live != 402653184 {
			t.Fatalf("%s: held=%d live=%d", label, held, live)
		}
		accountMustRefuse(t, label, a, 1)
		first, second := [2]chan struct{}{r1, r2}, [2]chan error{d1, d2}
		if reverse {
			first, second = [2]chan struct{}{r2, r1}, [2]chan error{d2, d1}
		}
		for i := range 2 {
			close(first[i])
			if err := <-second[i]; err != nil {
				t.Fatalf("%s: release %d: %v", label, i, err)
			}
		}
		if held, live := accountHeld(a), reservationLive(owner); held != 0 || live != 0 {
			t.Fatalf("%s: final held=%d live=%d", label, held, live)
		}
	})
}

func TestOperationAccountShared(t *testing.T) {
	accountReleaseOrder(t, "A8 opposite order", true)
	accountReleaseOrder(t, "A8 admission order", false)
}

func TestOperationReservationLaneConcurrency(t *testing.T) {
	owner := reservationOwner(t, specRMin)
	release, results := make(chan struct{}), make(chan error, 24)
	unhold := sync.OnceFunc(func() { close(release) })
	defer unhold()
	var wg sync.WaitGroup
	for range 12 {
		wg.Go(func() {
			results <- owner.WithOperation(LaneOperation, func(a *OperationAccount) error {
				return a.WithReservation(specLaneMax, func() error { results <- nil; <-release; return nil })
			})
		})
	}
	admitted := 0
	for range 12 {
		if err := <-results; err == nil {
			admitted++
		} else {
			wantReservationSentinel(t, "H1 refusal", err, errOperationReservationCapacity, textReservationCapacity)
		}
	}
	if live := reservationLive(owner); admitted != 5 || live != 773055915 {
		t.Fatalf("H1: admitted=%d live=%d", admitted, live)
	}
	unhold()
	wg.Wait()
	for range 5 {
		if err := <-results; err != nil {
			t.Fatalf("H1 admitted result: %v", err)
		}
	}
	if live := reservationLive(owner); live != 0 {
		t.Fatalf("H1 final live=%d", live)
	}
}

// accountNestedExit charges 300000000 then a nested 100000000 whose callback runs exit, from a new goroutine.
func accountNestedExit(owner *OperationReservationOwner, exit func()) (recovered any, returned bool) {
	var wg sync.WaitGroup
	wg.Go(func() {
		defer func() { recovered = recover() }()
		_ = owner.WithOperation(TreeOperation, func(a *OperationAccount) error {
			return a.WithReservation(300000000, func() error {
				return a.WithReservation(100000000, func() error { exit(); return nil })
			})
		})
		returned = true
	})
	wg.Wait()
	return recovered, returned
}

func TestOperationAccountExit(t *testing.T) {
	owner := reservationOwner(t, specRMin)
	value := &struct{ id int }{2}
	if recovered, returned := accountNestedExit(owner, func() { panic(value) }); recovered != value || returned {
		t.Fatalf("H2 panic: recovered=%v returned=%v", recovered, returned)
	}
	if live := reservationLive(owner); live != 0 {
		t.Fatalf("H2 panic live=%d", live)
	}
	if recovered, returned := accountNestedExit(owner, runtime.Goexit); recovered != nil || returned {
		t.Fatalf("H2 Goexit: recovered=%v returned=%v", recovered, returned)
	}
	if live := reservationLive(owner); live != 0 {
		t.Fatalf("H2 Goexit live=%d", live)
	}
	reservationNested(t, "H2 restored", owner, []uint64{specLaneMax, specLaneMax, specLaneMax, specLaneMax, specLaneMax}, func() {})
}

func TestOperationAccountOutlived(t *testing.T) {
	owner := reservationOwner(t, specRMin)
	var retained *OperationAccount
	var release chan struct{}
	var done chan error
	accountRun(t, "H4 open", owner, TreeOperation, func(a *OperationAccount) {
		retained = a
		release, done = accountHold(t, a, 100000000)
	})
	accountInput(t, "H4 closed charge", owner, retained, 1, func() error { t.Fatal("H4 closed charge ran"); return nil })
	if live, held := reservationLive(owner), accountHeld(retained); live != 100000000 || held != 100000000 {
		t.Fatalf("H4 held after close: live=%d held=%d", live, held)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatalf("H4 held charge: %v", err)
	}
	if live, held := reservationLive(owner), accountHeld(retained); live != 0 || held != 0 {
		t.Fatalf("H4 released once: live=%d held=%d", live, held)
	}
	r1, d1 := operationHold(t, owner, TreeOperation, 402653184)
	r2, d2 := operationHold(t, owner, TreeOperation, 402653184)
	close(r1)
	close(r2)
	if err1, err2 := <-d1, <-d2; err1 != nil || err2 != nil || reservationLive(owner) != 0 {
		t.Fatalf("H4 pair: %v %v live=%d", err1, err2, reservationLive(owner))
	}
}

func BenchmarkOperationReservationOwnerWithReservation(b *testing.B) {
	owner, _ := NewOperationReservationOwner(805306368)
	callback := func() error { return nil }
	b.ReportAllocs()
	for b.Loop() {
		_ = owner.WithReservation(154611151, callback)
	}
}

func BenchmarkOperationAccountWithReservation(b *testing.B) {
	owner, _ := NewOperationReservationOwner(805306368)
	callback := func() error { return nil }
	b.ReportAllocs()
	_ = owner.WithOperation(TreeOperation, func(a *OperationAccount) error {
		for b.Loop() {
			_ = a.WithReservation(402653184, callback)
		}
		return nil
	})
}
