//go:build cgo && (darwin || linux) && (amd64 || arm64)

package mdbx

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	treeCallChildEnvV1   = "RUBIN_TREE_CALL_CHILD_ROW"
	treeCallCreatorV1    = "mdbx.runTreeLockedV1 in goroutine"
	treeCallResultMarker = "RUBIN_TREE_CALL_RESULT_OK"
	treeCallParkMarker   = "RUBIN_TREE_CALL_PARKED"
	treeCallPreMarker    = "RUBIN_TREE_CALL_PRECALL"
	treeCallDelivered    = "RUBIN_TREE_CALL_DELIVERED"
)

// treeCallNilPanicValue is a nil panic value the nilness analyzer cannot fold to a constant.
var treeCallNilPanicValue any

func treeCallGoroutineRecords() []string {
	buf := make([]byte, 1<<16)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			return strings.Split(string(buf[:n]), "\n\n")
		}
		buf = make([]byte, 2*len(buf))
	}
}

func treeCallWorkerCount() int {
	count := 0
	for _, record := range treeCallGoroutineRecords() {
		if strings.Contains(record, treeCallCreatorV1) {
			count++
		}
	}
	return count
}

func treeCallParkedWorker() bool {
	for _, record := range treeCallGoroutineRecords() {
		header, _, _ := strings.Cut(record, "\n")
		if strings.Contains(header, "[select (no cases)") && strings.Contains(header, ", locked to thread") && strings.Contains(record, treeCallCreatorV1) {
			return true
		}
	}
	return false
}

func treeCallPoll(condition func() bool) bool {
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return true
		}
		time.Sleep(time.Millisecond)
	}
	return condition()
}

func treeCallWorkersGone() bool { return treeCallWorkerCount() == 0 }

// treeCallChild re-executes the test binary for one child row (pattern of mdbx_cgo_test.go:2530-2541).
func treeCallChild(t *testing.T, row string, env ...string) (string, error) {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestTreeCallV1ChildRows$/^"+row+"$", "-test.count=1", "-test.v")
	cmd.Env = append(append(os.Environ(), treeCallChildEnvV1+"="+row), env...)
	output, err := cmd.CombinedOutput()
	return string(output), err
}

func TestTreeCallV1Return(t *testing.T) {
	calls, flag := 0, false
	unwind, err := treeCallV1(func() error { calls++; flag = true; return nil })
	if err != nil || unwind != (treeUnwindV1{}) || !flag || calls != 1 {
		t.Fatalf("normal return = (%v, %+v), flag %v, calls %d", err, unwind, flag, calls)
	}
	if !treeCallResumeReturns(unwind) {
		t.Fatal("statement after resumeV1 on kind 0 did not run")
	}
}

func treeCallResumeReturns(u treeUnwindV1) bool {
	u.resumeV1()
	return true
}

func TestTreeCallV1ErrorIdentity(t *testing.T) {
	sentinel, a, b := errors.New("provider"), errors.New("a"), errors.New("b")
	joined := errors.Join(a, b)
	var typedNil *CommitError
	for _, row := range []struct {
		name string
		want error
	}{{"sentinel", sentinel}, {"typed-nil", typedNil}, {"capacity", errOperationReservationCapacity}, {"joined", joined}} {
		t.Run(row.name, func(t *testing.T) {
			unwind, err := treeCallV1(func() error { return row.want })
			if any(err) != any(row.want) || unwind.kind != 0 || unwind.value != nil {
				t.Fatalf("got (%v, %+v), want identity of %v", err, unwind, row.want)
			}
		})
	}
	_, err := treeCallV1(func() error { return typedNil })
	var commitErr *CommitError
	if err == nil || !errors.As(err, &commitErr) || commitErr != nil {
		t.Fatalf("typed-nil error became %#v", err)
	}
	_, err = treeCallV1(func() error { return errOperationReservationCapacity })
	if !IsOperationReservationCapacity(err) {
		t.Fatalf("capacity singleton lost: %v", err)
	}
}

func treeCallRecoverResume(u treeUnwindV1) (recovered any, returned bool) {
	defer func() { recovered = recover() }()
	u.resumeV1()
	return nil, true
}

func TestTreeCallV1PanicAtCallSite(t *testing.T) {
	v := new(struct{ n int })
	unwind, err := treeCallV1(func() error { panic(v) })
	if err != nil || unwind.kind != 1 || unwind.value != v {
		t.Fatalf("panic = (%v, %+v), want (nil, kind 1, %p)", err, unwind, v)
	}
	if recovered, returned := treeCallRecoverResume(unwind); returned || recovered != v {
		t.Fatalf("resumeV1 recovered %v (returned %v), want %p", recovered, returned, v)
	}
}

func TestTreeCallV1ErrorPanicValue(t *testing.T) {
	e := errors.New("panic value")
	unwind, err := treeCallV1(func() error { panic(e) })
	if err != nil || unwind.kind != 1 || unwind.value != any(e) {
		t.Fatalf("error panic = (%v, %+v), want (nil, kind 1, %v)", err, unwind, e)
	}
}

func TestTreeCallV1NilCall(t *testing.T) {
	unwind, err := treeCallV1(nil)
	var runtimeErr runtime.Error
	valueErr, isErr := unwind.value.(error)
	if err != nil || unwind.kind != 1 || !isErr || !errors.As(valueErr, &runtimeErr) {
		t.Fatalf("nil call = (%v, %+v), want (nil, kind 1, runtime.Error)", err, unwind)
	}
	if recovered, returned := treeCallRecoverResume(unwind); returned || recovered != unwind.value {
		t.Fatalf("nil call resume recovered %v (returned %v)", recovered, returned)
	}
}

func TestTreeCallV1PanicNilDefault(t *testing.T) {
	unwind, err := treeCallV1(func() error { panic(treeCallNilPanicValue) })
	panicNil, ok := unwind.value.(*runtime.PanicNilError)
	if err != nil || unwind.kind != 1 || !ok || panicNil == nil {
		t.Fatalf("panic(nil) = (%v, %+v), want kind 1 with *runtime.PanicNilError", err, unwind)
	}
	if recovered, returned := treeCallRecoverResume(unwind); returned || recovered != any(panicNil) {
		t.Fatalf("panic(nil) resume recovered %v (returned %v)", recovered, returned)
	}
}

func TestTreeCallV1LockedDelivery(t *testing.T) {
	v, o := new(struct{ n int }), errors.New("locked outcome")
	calls := 0
	outcome, unwind := runTreeLockedV1(func(out *transactionOutcome) treeUnwindV1 {
		calls++
		u, _ := treeCallV1(func() error { panic(v) })
		*out = transactionOutcome{err: o}
		return u
	})
	if any(outcome.err) != any(o) || outcome.poisoned || unwind.kind != 1 || unwind.value != v || calls != 1 {
		t.Fatalf("locked panic delivery = (%+v, %+v), calls %d", outcome, unwind, calls)
	}
	if recovered, returned := treeCallRecoverResume(unwind); returned || recovered != v {
		t.Fatalf("caller resume recovered %v (returned %v)", recovered, returned)
	}
}

func TestTreeCallV1NormalDeliveryThreadLaw(t *testing.T) {
	o := errors.New("normal outcome")
	outcome, unwind := runTreeLockedV1(func(out *transactionOutcome) treeUnwindV1 {
		*out = transactionOutcome{err: o}
		return treeUnwindV1{}
	})
	if outcome != (transactionOutcome{err: o}) || unwind != (treeUnwindV1{}) {
		t.Fatalf("normal delivery = (%+v, %+v)", outcome, unwind)
	}
	if !treeCallPoll(treeCallWorkersGone) {
		t.Fatalf("worker frame remained after non-poisoned delivery: %d", treeCallWorkerCount())
	}
}

func TestTreeCallV1GoexitResume(t *testing.T) {
	var mu sync.Mutex
	done, after := make(chan struct{}), make(chan struct{}, 1)
	mu.Lock()
	go func() {
		defer close(done)
		defer mu.Unlock()
		treeUnwindV1{kind: 2}.resumeV1()
		after <- struct{}{}
	}()
	<-done
	if len(after) != 0 || !mu.TryLock() {
		t.Fatalf("Goexit resume ran post-resume code (%d) or kept the mutex", len(after))
	}
}

type treeGoexitMarkers struct{ afterCall, afterInnerExit, afterOpExit bool }

func treeGoexitOp(o1, o2 error, poisoned, viaCall bool, markers *treeGoexitMarkers) func(*transactionOutcome) treeUnwindV1 {
	return func(out *transactionOutcome) treeUnwindV1 {
		*out = transactionOutcome{err: o1}
		defer func() { *out = transactionOutcome{err: o2, poisoned: poisoned} }()
		if viaCall {
			u, _ := treeCallV1(func() error {
				runtime.Goexit()
				markers.afterInnerExit = true
				return nil
			})
			markers.afterCall = true
			return u
		}
		runtime.Goexit()
		markers.afterOpExit = true
		return treeUnwindV1{}
	}
}

func TestTreeCallV1GoexitDelivery(t *testing.T) {
	for _, viaCall := range []bool{true, false} {
		t.Run(fmt.Sprintf("viaCall=%v", viaCall), func(t *testing.T) {
			o1, o2 := errors.New("before cleanup"), errors.New("cleanup")
			var markers treeGoexitMarkers
			outcome, unwind := runTreeLockedV1(treeGoexitOp(o1, o2, false, viaCall, &markers))
			if any(outcome.err) != any(o2) || outcome.poisoned || unwind != (treeUnwindV1{kind: 2}) {
				t.Fatalf("Goexit delivery = (%+v, %+v), want (%v, kind 2)", outcome, unwind, o2)
			}
			if markers != (treeGoexitMarkers{}) {
				t.Fatalf("post-Goexit statements ran: %+v", markers)
			}
			if !treeCallPoll(treeCallWorkersGone) {
				t.Fatalf("worker frame remained after Goexit delivery: %d", treeCallWorkerCount())
			}
		})
	}
}

func TestTreeCallV1ProviderPanicDuringGoexit(t *testing.T) {
	v, o1, o2 := new(struct{ n int }), errors.New("before cleanup"), errors.New("cleanup")
	var afterExit, afterCall bool
	outcome, unwind := runTreeLockedV1(func(out *transactionOutcome) treeUnwindV1 {
		defer func() { *out = transactionOutcome{err: o2} }()
		*out = transactionOutcome{err: o1}
		u, _ := treeCallV1(func() error {
			defer func() { panic(v) }()
			runtime.Goexit()
			afterExit = true
			return nil
		})
		afterCall = true
		return u
	})
	if any(outcome.err) != any(o2) || outcome.poisoned || unwind != (treeUnwindV1{kind: 2}) {
		t.Fatalf("provider panic during Goexit = (%+v, %+v), want (%v, kind 2, value nil)", outcome, unwind, o2)
	}
	if afterExit || afterCall {
		t.Fatalf("post-Goexit statements ran: afterExit %v afterCall %v", afterExit, afterCall)
	}
	if !treeCallPoll(treeCallWorkersGone) {
		t.Fatalf("worker frame remained after Goexit delivery: %d", treeCallWorkerCount())
	}
}

type treeConcurrentRow struct {
	sentinel error
	value    *struct{ n int }
	mode     int
}

func (row treeConcurrentRow) op(out *transactionOutcome) treeUnwindV1 {
	switch row.mode {
	case 0:
		*out = transactionOutcome{err: row.sentinel}
		return treeUnwindV1{}
	case 1:
		u, _ := treeCallV1(func() error { panic(row.value) })
		*out = transactionOutcome{err: row.sentinel}
		return u
	}
	defer func() { *out = transactionOutcome{err: row.sentinel} }()
	runtime.Goexit()
	return treeUnwindV1{}
}

func (row treeConcurrentRow) check(outcome transactionOutcome, unwind treeUnwindV1) error {
	wantValue := any(nil)
	if row.mode == 1 {
		wantValue = row.value
	}
	if outcome != (transactionOutcome{err: row.sentinel}) || unwind.kind != uint8(row.mode) || unwind.value != wantValue {
		return fmt.Errorf("mode %d got (%+v, %+v)", row.mode, outcome, unwind)
	}
	return nil
}

func TestTreeCallV1ConcurrentCallers(t *testing.T) {
	errs := make(chan error, 8)
	var wg sync.WaitGroup
	for i := range 8 {
		row := treeConcurrentRow{sentinel: fmt.Errorf("caller %d", i), value: new(struct{ n int }), mode: i % 3}
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- row.check(runTreeLockedV1(row.op))
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestTreeCallV1NextOperationAfterGoexit(t *testing.T) {
	var operations sync.Mutex
	done := make(chan struct{})
	go func() {
		defer close(done)
		operations.Lock()
		defer operations.Unlock()
		var markers treeGoexitMarkers
		_, unwind := runTreeLockedV1(treeGoexitOp(errors.New("o1"), errors.New("o2"), false, true, &markers))
		unwind.resumeV1()
	}()
	<-done
	if !operations.TryLock() {
		t.Fatal("operation mutex left held after Goexit resume")
	}
	operations.Unlock()
	operations.Lock()
	defer operations.Unlock()
	o := errors.New("next")
	outcome, unwind := runTreeLockedV1(func(out *transactionOutcome) treeUnwindV1 { *out = transactionOutcome{err: o}; return treeUnwindV1{} })
	if any(outcome.err) != any(o) || unwind != (treeUnwindV1{}) {
		t.Fatalf("next operation = (%+v, %+v)", outcome, unwind)
	}
}

func treeCallFuncDecl(t *testing.T, name string) *ast.FuncDecl {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), "tree_call_cgo.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, declaration := range file.Decls {
		if fn, ok := declaration.(*ast.FuncDecl); ok && fn.Name.Name == name {
			return fn
		}
	}
	t.Fatalf("%s not declared", name)
	return nil
}

func treeCallSends(node ast.Node) []*ast.SendStmt {
	var sends []*ast.SendStmt
	ast.Inspect(node, func(n ast.Node) bool {
		if send, ok := n.(*ast.SendStmt); ok {
			sends = append(sends, send)
		}
		return true
	})
	return sends
}

func treeCallIsUnlock(call *ast.CallExpr) bool {
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || selector.Sel.Name != "UnlockOSThread" {
		return false
	}
	pkg, ok := selector.X.(*ast.Ident)
	return ok && pkg.Name == "runtime"
}

func treeCallUnlocks(node ast.Node) []*ast.CallExpr {
	var calls []*ast.CallExpr
	ast.Inspect(node, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok && treeCallIsUnlock(call) {
			calls = append(calls, call)
		}
		return true
	})
	return calls
}

func treeCallDeferLiterals(node ast.Node) []*ast.FuncLit {
	var literals []*ast.FuncLit
	ast.Inspect(node, func(n ast.Node) bool {
		if deferred, ok := n.(*ast.DeferStmt); ok {
			if literal, ok := deferred.Call.Fun.(*ast.FuncLit); ok {
				literals = append(literals, literal)
			}
		}
		return true
	})
	return literals
}

// treeCallGuardedUnlock reports whether unlock is the sole body statement of an if over !<x>.poisoned.
func treeCallGuardedUnlock(scope ast.Node, unlock *ast.CallExpr) (token.Pos, bool) {
	var at token.Pos
	ast.Inspect(scope, func(n ast.Node) bool {
		branch, ok := n.(*ast.IfStmt)
		if !ok || len(branch.Body.List) != 1 {
			return true
		}
		stmt, isExpr := branch.Body.List[0].(*ast.ExprStmt)
		not, isNot := branch.Cond.(*ast.UnaryExpr)
		if !isExpr || stmt.X != unlock || !isNot || not.Op != token.NOT {
			return true
		}
		if selector, ok := not.X.(*ast.SelectorExpr); ok && selector.Sel.Name == "poisoned" {
			at = branch.Pos()
		}
		return true
	})
	return at, at.IsValid()
}

func TestTreeCallV1DeliverySourceShape(t *testing.T) {
	fn := treeCallFuncDecl(t, "runTreeLockedV1")
	sends, unlocks := treeCallSends(fn), treeCallUnlocks(fn)
	if len(sends) != 1 || len(unlocks) != 1 {
		t.Fatalf("runTreeLockedV1 has %d sends and %d UnlockOSThread calls, want 1 and 1", len(sends), len(unlocks))
	}
	for _, literal := range treeCallDeferLiterals(fn) {
		inner, innerUnlocks := treeCallSends(literal), treeCallUnlocks(literal)
		if len(inner) != 1 || len(innerUnlocks) != 1 || inner[0] != sends[0] {
			continue
		}
		if at, ok := treeCallGuardedUnlock(literal, unlocks[0]); ok && at < sends[0].Pos() {
			return
		}
	}
	t.Fatal("delivery send and guarded UnlockOSThread are not in one deferred function literal in the runLocked form")
}

func treeCallChildPoisonedNormal() {
	o := errors.New("poisoned normal")
	outcome, unwind := runTreeLockedV1(func(out *transactionOutcome) treeUnwindV1 {
		*out = transactionOutcome{err: o, poisoned: true}
		return treeUnwindV1{}
	})
	if outcome == (transactionOutcome{err: o, poisoned: true}) && unwind == (treeUnwindV1{}) {
		fmt.Println(treeCallResultMarker)
	}
	if treeCallPoll(treeCallParkedWorker) {
		fmt.Println(treeCallParkMarker)
	}
}

func treeCallChildPoisonedGoexit() {
	o2 := errors.New("poisoned cleanup")
	var markers treeGoexitMarkers
	outcome, unwind := runTreeLockedV1(treeGoexitOp(errors.New("o1"), o2, true, false, &markers))
	if outcome == (transactionOutcome{err: o2, poisoned: true}) && unwind == (treeUnwindV1{kind: 2}) {
		fmt.Println(treeCallResultMarker)
	}
	if treeCallPoll(treeCallParkedWorker) {
		fmt.Println(treeCallParkMarker)
	}
}

const treeCallHeldText = "rubin tree held engine defect"

// treeCallHeldPanic is an engine panic value whose Error method holds the crash until the caller signals receipt or
// the A5 bound elapses; the first wait is shared by every later Error call.
type treeCallHeldPanic struct {
	receipt chan struct{}
	once    sync.Once
}

func newTreeCallHeldPanic() *treeCallHeldPanic {
	return &treeCallHeldPanic{receipt: make(chan struct{})}
}

func (p *treeCallHeldPanic) Error() string {
	p.once.Do(func() {
		select {
		case <-p.receipt:
		case <-time.After(10 * time.Second):
		}
	})
	return treeCallHeldText
}

func treeCallRunHeld(held *treeCallHeldPanic, op func(*transactionOutcome) treeUnwindV1) {
	fmt.Println(treeCallPreMarker)
	runTreeLockedV1(op)
	fmt.Println(treeCallDelivered)
	close(held.receipt)
}

func treeCallChildEnginePanic() {
	held := newTreeCallHeldPanic()
	treeCallRunHeld(held, func(*transactionOutcome) treeUnwindV1 { panic(held) })
}

func treeCallChildGoexitEnginePanic(viaCall bool) func() {
	return func() {
		held := newTreeCallHeldPanic()
		treeCallRunHeld(held, func(out *transactionOutcome) treeUnwindV1 {
			*out = transactionOutcome{err: errors.New("o1")}
			defer func() { panic(held) }()
			if viaCall {
				u, _ := treeCallV1(func() error {
					runtime.Goexit()
					return nil
				})
				return u
			}
			runtime.Goexit()
			return treeUnwindV1{}
		})
	}
}

func treeCallChildNilOp() {
	fmt.Println(treeCallPreMarker)
	runTreeLockedV1(nil)
	fmt.Println(treeCallDelivered)
}

func treeCallChildOpPanicNil() {
	fmt.Println(treeCallPreMarker)
	runTreeLockedV1(func(*transactionOutcome) treeUnwindV1 { panic(treeCallNilPanicValue) })
	fmt.Println(treeCallDelivered)
}

func treeCallChildCallPanicNil() {
	unwind, _ := treeCallV1(func() error { panic(treeCallNilPanicValue) })
	if unwind.kind == 1 && unwind.value == nil {
		fmt.Println(treeCallResultMarker)
	}
	unwind.resumeV1()
}

type treeCallChildRow struct {
	name      string
	body      func()
	env       []string
	crash     bool
	wantTexts []string
	forbidden string
}

func treeCallChildRows() []treeCallChildRow {
	panicNil := []string{"GODEBUG=panicnil=1"}
	return []treeCallChildRow{
		{"A5b", treeCallChildPoisonedNormal, nil, false, []string{treeCallResultMarker, treeCallParkMarker}, ""},
		{"A9", treeCallChildPoisonedGoexit, nil, false, []string{treeCallResultMarker, treeCallParkMarker}, ""},
		{"R1", treeCallChildEnginePanic, nil, true, []string{treeCallPreMarker, "panic:", treeCallHeldText}, treeCallDelivered},
		{"R4a", treeCallChildGoexitEnginePanic(false), nil, true, []string{treeCallPreMarker, "panic:", treeCallHeldText}, treeCallDelivered},
		{"R4b", treeCallChildGoexitEnginePanic(true), nil, true, []string{treeCallPreMarker, "panic:", treeCallHeldText}, treeCallDelivered},
		{"R3", treeCallChildNilOp, nil, true, []string{treeCallPreMarker, "panic: runtime error"}, treeCallDelivered},
		{"H1", treeCallChildCallPanicNil, panicNil, true, []string{treeCallResultMarker, "panic: nil"}, ""},
		{"H4", treeCallChildOpPanicNil, panicNil, true, []string{treeCallPreMarker, "panic: nil"}, treeCallDelivered},
	}
}

func (row treeCallChildRow) verify(output string, runErr error) error {
	if crashed := runErr != nil; crashed != row.crash {
		return fmt.Errorf("child exit error %w, want crash %v", runErr, row.crash)
	}
	for _, text := range row.wantTexts {
		if !strings.Contains(output, text) {
			return fmt.Errorf("child output lacks %q", text)
		}
	}
	if row.forbidden != "" && strings.Contains(output, row.forbidden) {
		return fmt.Errorf("child output contains %q", row.forbidden)
	}
	return nil
}

func TestTreeCallV1ChildRows(t *testing.T) {
	for _, row := range treeCallChildRows() {
		t.Run(row.name, func(t *testing.T) {
			if os.Getenv(treeCallChildEnvV1) == row.name {
				row.body()
				return
			}
			output, runErr := treeCallChild(t, row.name, row.env...)
			if err := row.verify(output, runErr); err != nil {
				t.Fatalf("%v\n%s", err, output)
			}
		})
	}
}
