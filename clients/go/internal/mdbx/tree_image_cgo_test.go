//go:build cgo && (darwin || linux) && (amd64 || arm64)

package mdbx

import (
	"bytes"
	"errors"
	"reflect"
	"runtime"
	"testing"
	"time"
)

// tiOutcome is how one UpdateImageV1 call ended: returned with r, or unwound with the
// recovered panic value (nil for Goexit). The rest is observed on the caller's account a
// inside WithOperation, holding hold bytes (0 or 1), after the call returns or unwinds:
// original and account are *a before and after the call, before and after the state that
// original names, live the live sum, and reuse and reuseLive the result and live sum of a
// further one-byte a.WithReservation. inside holds the live sum read at the start of each
// planner call, and allocated the bytes the call allocated when it returned. wantZero marks
// a planner that zeroes *a.
type tiOutcome struct {
	r                 tsResult
	live              uint64
	returned          bool
	recovered         any
	original, account OperationAccount
	before, after     operationAccountState
	reuse             error
	reuseLive         uint64
	wantZero          bool
	hold              uint64
	inside            []uint64
	allocated         uint64
}

// tiPlanner counts calls and keeps the last Reader. From its second call on it
// reads meta key 0x02 through the kept Reader and meta keys 0x00 and 0x02
// through the live Reader before it calls outcome. replays counts the Replay
// calls of the publication that outcome returns. want02 and want02Present are the meta key
// 0x02 value and presence that the live Reader of a repeated call must read.
type tiPlanner struct {
	calls          int
	replays        *int
	kept           *Reader
	expiredValue   []byte
	expiredPresent bool
	expired        error
	live           []byte
	liveErr        error
	live02         []byte
	live02Present  bool
	live02Err      error
	want02         []byte
	want02Present  bool
	outcome        func(*Reader) (TreeImagePublicationV1, error)
}

func (p *tiPlanner) imagePlan(r *Reader) (TreeImagePublicationV1, error) {
	p.calls++
	if p.kept != nil {
		p.expiredValue, p.expiredPresent, p.expired = p.kept.Get(TreeSchemaV1DBIs()[0], []byte{2})
		p.live, _, p.liveErr = r.Get(TreeSchemaV1DBIs()[0], []byte{0})
		p.live02, p.live02Present, p.live02Err = r.Get(TreeSchemaV1DBIs()[0], []byte{2})
	}
	p.kept = r
	return p.outcome(r)
}

func tiInvoke(s *Store, a *OperationAccount, planner func(*Reader) (TreeImagePublicationV1, error)) tsResult {
	var r tsResult
	r.truth, r.stage, r.index, r.err = s.UpdateImageV1(a, planner)
	return r
}

// tiCall runs one UpdateImageV1 on a fresh goroutine inside WithOperation(kind) while the
// caller holds hold bytes (0 or 1) on the account.
func tiCall(s *Store, o *OperationReservationOwner, kind OperationKind, hold uint64, planner func(*Reader) (TreeImagePublicationV1, error)) tiOutcome {
	return tiCallAccount(s, o, kind, hold, func(*OperationAccount) func(*Reader) (TreeImagePublicationV1, error) { return planner })
}

// tiCallAccount is tiCall with the planner that bind returns for the account WithOperation
// passes.
func tiCallAccount(s *Store, o *OperationReservationOwner, kind OperationKind, hold uint64, bind func(*OperationAccount) func(*Reader) (TreeImagePublicationV1, error)) tiOutcome {
	out := tiOutcome{hold: hold}
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer func() { out.recovered = recover() }()
		_ = o.WithOperation(kind, func(a *OperationAccount) error {
			if hold == 0 {
				tiObserve(s, o, a, bind, &out)
				return nil
			}
			return a.WithReservation(hold, func() error { tiObserve(s, o, a, bind, &out); return nil })
		})
	}()
	<-done
	return out
}

// tiObserve runs one UpdateImageV1 on a and records the account observations into out.
func tiObserve(s *Store, o *OperationReservationOwner, a *OperationAccount, bind func(*OperationAccount) func(*Reader) (TreeImagePublicationV1, error), out *tiOutcome) {
	out.original, out.before = *a, *a.shared
	defer func() {
		out.account, out.after, out.live = *a, *out.original.shared, reservationLive(o)
		out.reuse = a.WithReservation(1, func() error { out.reuseLive = reservationLive(o); return nil })
	}()
	planner := bind(a)
	if planner != nil {
		inner := planner
		planner = func(r *Reader) (TreeImagePublicationV1, error) {
			out.inside = append(out.inside, reservationLive(o))
			return inner(r)
		}
	}
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	out.r = tiInvoke(s, a, planner)
	runtime.ReadMemStats(&after)
	out.returned, out.allocated = true, after.TotalAlloc-before.TotalAlloc
}

// tiPublication is Tag 1, RecordLimit 6, the tsEntry meta key 0x02 envelope and
// a Replay that counts its calls into replays.
func tiPublication(t *testing.T, replays *int) TreeImagePublicationV1 {
	t.Helper()
	replay := func(*Reader, func(TreeImageRecordV1) error) error { *replays++; return nil }
	return TreeImagePublicationV1{Tag: 1, Authority: tsEntry(t).Pair.Mutations[0].Literal, RecordLimit: 6, Replay: replay}
}

// tiCounted returns a planner that counts its calls into calls and returns the tiPublication
// publication with its Replay counting into replays.
func tiCounted(t *testing.T, calls, replays *int) func(*Reader) (TreeImagePublicationV1, error) {
	t.Helper()
	publication := tiPublication(t, replays)
	return func(*Reader) (TreeImagePublicationV1, error) { *calls++; return publication, nil }
}

func tiInvalidBatch(t *testing.T, err error) {
	t.Helper()
	treeNativeError(t, err, operationUpdate, "InvalidInput", 22, "invalid Update Batch", nil)
}

// tiReturned requires a returned (1, 1, -1) call with tiAccountKept and returns its error.
func tiReturned(t *testing.T, out tiOutcome) error {
	t.Helper()
	return tiReturnedAt(t, out, 1)
}

// tiReturnedAt is tiReturned for (truth, 1, -1).
func tiReturnedAt(t *testing.T, out tiOutcome, truth CommitTruth) error {
	t.Helper()
	if !out.returned || out.recovered != nil {
		t.Fatalf("UpdateImageV1 returned %v recovered %v", out.returned, out.recovered)
	}
	out.r.tuple(t, truth, 1, -1)
	tiAccountKept(t, out)
	return out.r.err
}

// tiAccountKept requires the caller's account state before the call to hold exactly the
// caller's hold (zero for a fresh account), the live sum at the start of each planner call and
// after the call equal to that hold, that state unchanged by the call, and the caller's account value either unchanged with a further one-byte
// WithReservation admitted at live sum hold+1, or, for wantZero, the zero value refused as
// invalid input.
func tiAccountKept(t *testing.T, out tiOutcome) {
	t.Helper()
	if out.before.held != out.hold || out.before.everPositive != (out.hold != 0) || out.before.closed {
		t.Fatalf("account before the call %+v, want caller hold %d", out.before, out.hold)
	}
	for _, live := range out.inside {
		if live != out.hold {
			t.Fatalf("live sum inside the planner %d, want %d", live, out.hold)
		}
	}
	if out.live != out.hold || out.after != out.before {
		t.Fatalf("live sum %d, want %d; account before %+v after %+v", out.live, out.hold, out.before, out.after)
	}
	if out.wantZero {
		if out.account != (OperationAccount{}) || any(out.reuse) != any(errOperationReservationInput) || out.reuseLive != 0 {
			t.Fatalf("zeroed account %+v reuse returned %v with live sum %d", out.account, out.reuse, out.reuseLive)
		}
		return
	}
	if out.account != out.original || out.reuse != nil || out.reuseLive != out.hold+1 {
		t.Fatalf("account %+v, want %+v; reuse returned %v with live sum %d", out.account, out.original, out.reuse, out.reuseLive)
	}
}

// tiMeta02 reads meta key 0x02 through a View.
func tiMeta02(t *testing.T, s *Store) ([]byte, bool) {
	t.Helper()
	var value []byte
	var present bool
	calls := 0
	mustEnvironment(t, s.View(func(r *Reader) error {
		var err error
		calls++
		value, present, err = r.Get(TreeSchemaV1DBIs()[0], []byte{2})
		return err
	}))
	if calls != 1 {
		t.Fatalf("View ran its callback %d times, want 1", calls)
	}
	return value, present
}

// tiOpenNext requires the Store OPEN, repeats the call with the same planner under caller hold
// hold and check, then requires the Store OPEN, the planner reads of the repeated call and its
// Reader expired, then a View that runs view when non-nil followed by viewed when non-nil, and
// last an UpdateTreeV1 that returns its callback error once.
func tiOpenNext(t *testing.T, s *Store, o *OperationReservationOwner, kind OperationKind, hold uint64, p *tiPlanner, check func(tiOutcome), view func(*Reader), viewed func()) {
	t.Helper()
	tiRequireOpen(t, s)
	calls := p.calls
	check(tiCallAccount(s, o, kind, hold, func(*OperationAccount) func(*Reader) (TreeImagePublicationV1, error) { return p.imagePlan }))
	tiRequireOpen(t, s)
	if p.calls != calls+1 || *p.replays != 0 {
		t.Fatalf("repeated planner calls %d, want %d, Replay calls %d", p.calls, calls+1, *p.replays)
	}
	if p.expiredValue != nil || p.expiredPresent {
		t.Fatalf("kept Reader returned %x present %v", p.expiredValue, p.expiredPresent)
	}
	treeNativeError(t, p.expired, operationGet, "InvalidInput", 22, "Reader is not active", nil)
	if p.liveErr != nil || !bytes.Equal(p.live, TreeSchemaVersionValue()) {
		t.Fatalf("live Reader meta key 0x00 = %x, %v", p.live, p.liveErr)
	}
	if p.live02Err != nil || p.live02Present != p.want02Present || !bytes.Equal(p.live02, p.want02) {
		t.Fatalf("meta key 0x02 in the repeated call %x present %v error %v", p.live02, p.live02Present, p.live02Err)
	}
	tsExpiredReader(t, p.kept)
	viewCalls := 0
	mustEnvironment(t, s.View(func(r *Reader) error {
		viewCalls++
		if view != nil {
			view(r)
		}
		return nil
	}))
	if viewCalls != 1 {
		t.Fatalf("View ran %d callbacks, want 1", viewCalls)
	}
	tiRequireOpen(t, s)
	if viewed != nil {
		viewed()
	}
	app, treeCalls := errors.New("tree callback error"), 0
	var r tsResult
	mustEnvironment(t, o.WithOperation(LaneOperation, func(a *OperationAccount) error {
		r = tsInvoke(s, a, func(*Reader) (TreeOperationV1, error) { treeCalls++; return TreeOperationV1{}, app })
		return nil
	}))
	r.tuple(t, 1, 1, -1)
	if any(r.err) != any(app) || treeCalls != 1 {
		t.Fatalf("UpdateTreeV1 on the OPEN Store returned %v with %d callback calls", r.err, treeCalls)
	}
}

// tiRequireOpen requires the Store OPEN with no terminal.
func tiRequireOpen(t *testing.T, s *Store) {
	t.Helper()
	if s.state != storeOPEN || s.terminal != nil {
		t.Fatalf("Store %s terminal %v, want OPEN", s.state, s.terminal)
	}
}

// tiTerminal requires, in this order and each observed before the next call, UpdateImageV1 under
// caller hold hold, UpdateTreeV1, View and Close to return terminal (the two updates at
// (truth, 1, -1), UpdateImageV1 with the caller's account kept), and after each of them the Store
// state, terminal, terminal truth, transaction and environment it had before, with every error in
// terminal's tree unchanged; then zero callback calls and live sum 0.
func tiTerminal(t *testing.T, s *Store, o *OperationReservationOwner, hold uint64, truth CommitTruth, terminal error) {
	t.Helper()
	if terminal == nil {
		t.Fatal("terminal Store check called with a nil terminal")
	}
	calls := 0
	state, txn, env, values := s.state, s.txn, s.env, tiErrorTree(terminal, nil)
	same := func(call string) {
		t.Helper()
		if s.state != state || any(s.terminal) != any(terminal) || s.terminalTruth != truth || s.txn != txn || s.env != env || !tiSameTree(values, tiErrorTree(terminal, nil)) {
			t.Fatalf("terminal %s left %s terminal %v truth %d, want %s with the same transaction, environment and terminal values", call, s.state, s.terminal, s.terminalTruth, state)
		}
	}
	same("Store")
	image := tiCall(s, o, LaneOperation, hold, func(*Reader) (TreeImagePublicationV1, error) { calls++; return TreeImagePublicationV1{}, nil })
	same("UpdateImageV1")
	if err := tiReturnedAt(t, image, truth); any(err) != any(terminal) || calls != 0 {
		t.Fatalf("terminal UpdateImageV1 returned %v with %d planner calls, want %v", err, calls, terminal)
	}
	var tree tsResult
	mustEnvironment(t, o.WithOperation(LaneOperation, func(a *OperationAccount) error {
		tree = tsInvoke(s, a, func(*Reader) (TreeOperationV1, error) { calls++; return TreeOperationV1{}, nil })
		return nil
	}))
	same("UpdateTreeV1")
	tree.tuple(t, truth, 1, -1)
	if any(tree.err) != any(terminal) || calls != 0 {
		t.Fatalf("terminal UpdateTreeV1 returned %v with %d callback calls, want %v", tree.err, calls, terminal)
	}
	if err := s.View(func(*Reader) error { calls++; return nil }); any(err) != any(terminal) || calls != 0 {
		t.Fatalf("terminal View returned %v with %d callback calls", err, calls)
	}
	same("View")
	if err := s.Close(); any(err) != any(terminal) {
		t.Fatalf("terminal Close returned %v", err)
	}
	same("Close")
	if reservationLive(o) != 0 {
		t.Fatalf("terminal Store live %d", reservationLive(o))
	}
}

// tiErrorTree appends err, and for a pointer to a comparable struct a copy of the struct, then
// the same for the ReadbackCause of a *CommitError and for each error that err unwraps to, depth
// first. It reads only the dynamic type of each node, so a nil pointer err is appended and none
// of its methods is called.
func tiErrorTree(err error, out []any) []any {
	if err == nil {
		return out
	}
	out = append(out, err)
	v := reflect.ValueOf(err)
	if v.Kind() == reflect.Pointer && v.IsNil() {
		return out
	}
	out = tiErrorValue(v, out)
	if c, ok := any(err).(*CommitError); ok {
		out = tiErrorTree(c.ReadbackCause, out)
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		for _, inner := range joined.Unwrap() {
			out = tiErrorTree(inner, out)
		}
		return out
	}
	return tiErrorTree(errors.Unwrap(err), out)
}

// tiErrorValue appends a copy of the struct that v points to when that struct is comparable.
func tiErrorValue(v reflect.Value, out []any) []any {
	if v.Kind() == reflect.Pointer && v.Elem().Kind() == reflect.Struct && v.Elem().Comparable() {
		return append(out, v.Elem().Interface())
	}
	return out
}

// tiSameTree reports whether two tiErrorTree results hold equal elements in the same order.
func tiSameTree(a, b []any) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// tiNextAdmission runs the tiPublication publication on s once under caller hold hold and requires
// "invalid Update Batch" at (1, 1, -1) with live sum 0, one planner call, no Replay call, the
// Store OPEN and the planner's Reader expired.
func tiNextAdmission(t *testing.T, s *Store, o *OperationReservationOwner, hold uint64) {
	t.Helper()
	replays := 0
	publication := tiPublication(t, &replays)
	p := &tiPlanner{replays: &replays, outcome: func(*Reader) (TreeImagePublicationV1, error) { return publication, nil }}
	tiInvalidBatch(t, tiReturned(t, tiCall(s, o, LaneOperation, hold, p.imagePlan)))
	if p.calls != 1 || replays != 0 || reservationLive(o) != 0 {
		t.Fatalf("next admission planner %d replay %d live %d", p.calls, replays, reservationLive(o))
	}
	tiRequireOpen(t, s)
	tsExpiredReader(t, p.kept)
}

func TestTreeImageAdmissionV1(t *testing.T) {
	for _, present := range []bool{false, true} {
		name := "exact-empty Store with absent meta key 0x02 returns invalid Update Batch with the Store OPEN"
		if present {
			name = "decodable meta key 0x02 returns invalid Update Batch with the Store OPEN"
		}
		t.Run(name, func(t *testing.T) { tiAdmissionRead(t, present) })
	}
	for _, name := range []string{"nil", "closed", "zero"} {
		t.Run(name+" operation account refuses before the Store operation owner", func(t *testing.T) { tiAdmissionAccount(t, name) })
	}
	t.Run("nil Store refuses before the planner and account checks", func(t *testing.T) {
		o := reservationOwner(t, MinReservationLimit)
		calls, replays := 0, 0
		planner := tiCounted(t, &calls, &replays)
		var s *Store
		for _, call := range []func() error{
			func() error { return tiReturned(t, tiCall(s, o, LaneOperation, 1, planner)) },
			func() error { return tiReturned(t, tiCall(s, o, LaneOperation, 0, planner)) },
			func() error { return tiNilAll(t, s) },
		} {
			treeNativeError(t, call(), operationUpdate, "InvalidInput", 22, "nil Store", nil)
			if calls != 0 || replays != 0 || reservationLive(o) != 0 {
				t.Fatalf("nil Store planner %d Replay %d live %d", calls, replays, reservationLive(o))
			}
		}
	})
	for _, account := range []bool{true, false} {
		name := "nil planner with an open account refuses as nil UpdateImageV1 callback"
		if !account {
			name = "nil planner refuses before the nil account check"
		}
		t.Run(name, func(t *testing.T) { tiAdmissionNilPlanner(t, account) })
	}
	for _, name := range []string{"busy", "closed", "format2", "consumed"} {
		t.Run(name+" Store refusal", func(t *testing.T) { tiAdmissionStore(t, name) })
	}
}

func tiAdmissionRead(t *testing.T, present bool) {
	for _, hold := range []uint64{1, 0} {
		tiAdmissionReadHold(t, present, hold)
	}
}

// tiAdmissionReadHold runs the successful-read refusal under caller hold hold on a fresh Store,
// then the next public calls.
func tiAdmissionReadHold(t *testing.T, present bool, hold uint64) {
	s, _, _ := treeNativeStore(t)
	o := reservationOwner(t, MinReservationLimit)
	if present {
		s, _, o = prunedTreeSeed(t, prunedTreeEnvelope(StorageProfileArchiveV1, StoragePhaseNoneV1, StorageLifecycleStableV1, 0))
	}
	beforeValue, beforePresent := tiMeta02(t, s)
	if beforePresent != present {
		t.Fatalf("seeded meta key 0x02 present %v", beforePresent)
	}
	replays := 0
	publication := tiPublication(t, &replays)
	p := &tiPlanner{replays: &replays, want02: beforeValue, want02Present: beforePresent, outcome: func(*Reader) (TreeImagePublicationV1, error) { return publication, nil }}
	check := func(out tiOutcome) { tiInvalidBatch(t, tiReturned(t, out)) }
	check(tiCall(s, o, LaneOperation, hold, p.imagePlan))
	if p.calls != 1 || replays != 0 {
		t.Fatalf("planner %d replay %d", p.calls, replays)
	}
	tiRequireOpen(t, s)
	tsExpiredReader(t, p.kept)
	var afterValue []byte
	var afterPresent bool
	afterErr := errors.New("View did not read meta key 0x02")
	tiOpenNext(t, s, o, LaneOperation, hold, p, check, func(r *Reader) {
		afterValue, afterPresent, afterErr = r.Get(TreeSchemaV1DBIs()[0], []byte{2})
	}, func() {
		if afterErr != nil || afterPresent != beforePresent || !bytes.Equal(afterValue, beforeValue) {
			t.Fatalf("meta key 0x02 after the calls %x present %v error %v", afterValue, afterPresent, afterErr)
		}
	})
}

func tiAdmissionAccount(t *testing.T, name string) {
	s, _, _ := treeNativeStore(t)
	o := reservationOwner(t, MinReservationLimit)
	var account *OperationAccount
	diagnostic := "closed operation account"
	switch name {
	case "nil":
		diagnostic = "nil operation account"
	case "closed":
		mustEnvironment(t, o.WithOperation(LaneOperation, func(a *OperationAccount) error { account = a; return nil }))
	case "zero":
		account = &OperationAccount{}
	}
	for _, hold := range []uint64{1, 0} {
		tiAccountRefusal(t, s, o, account, diagnostic)
		tiNextAdmission(t, s, o, hold)
	}
}

// tiAccountRefusal runs UpdateImageV1 with account while the Store operation owner is held and
// requires the diagnostic refusal at (1, 1, -1), no planner or Replay call, live sum 0, the Store
// OPEN and account and its state unchanged, with a one-byte WithReservation on it refused.
func tiAccountRefusal(t *testing.T, s *Store, o *OperationReservationOwner, account *OperationAccount, diagnostic string) {
	t.Helper()
	value, state := tiAccountSnapshot(account)
	calls, replays := 0, 0
	var r tsResult
	tiHeld(t, s, func() { r = tiInvoke(s, account, tiCounted(t, &calls, &replays)) })
	r.tuple(t, 1, 1, -1)
	treeNativeError(t, r.err, operationUpdate, "InvalidInput", 22, diagnostic, nil)
	if calls != 0 || replays != 0 || reservationLive(o) != 0 {
		t.Fatalf("account refusal planner %d Replay %d live %d", calls, replays, reservationLive(o))
	}
	tiRequireOpen(t, s)
	if gotValue, gotState := tiAccountSnapshot(account); gotValue != value || gotState != state {
		t.Fatalf("refused account %+v state %+v, want %+v state %+v", gotValue, gotState, value, state)
	}
	ran := false
	if err := account.WithReservation(1, func() error { ran = true; return nil }); any(err) != any(errOperationReservationInput) || ran || reservationLive(o) != 0 {
		t.Fatalf("refused account WithReservation returned %v ran %v live %d", err, ran, reservationLive(o))
	}
}

// tiHeld runs call on a fresh goroutine while s.operations is held and waits for it at most
// five seconds. A call still running then fails the test after the owner is released and the
// call has finished.
func tiHeld(t *testing.T, s *Store, call func()) {
	t.Helper()
	done := make(chan struct{})
	s.operations.Lock()
	go func() {
		defer close(done)
		call()
	}()
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	returned := true
	select {
	case <-done:
	case <-timer.C:
		returned = false
	}
	s.operations.Unlock()
	<-done
	if !returned {
		t.Fatal("UpdateImageV1 did not return within five seconds while the Store operation owner was held")
	}
}

// tiAccountSnapshot copies the value of a and of the state it names (zero values when absent).
func tiAccountSnapshot(a *OperationAccount) (OperationAccount, operationAccountState) {
	if a == nil {
		return OperationAccount{}, operationAccountState{}
	}
	if a.shared == nil {
		return *a, operationAccountState{}
	}
	return *a, *a.shared
}

func tiAdmissionNilPlanner(t *testing.T, account bool) {
	s, _, _ := treeNativeStore(t)
	o := reservationOwner(t, MinReservationLimit)
	for _, hold := range []uint64{1, 0} {
		var err error
		if account {
			err = tiReturned(t, tiCall(s, o, LaneOperation, hold, nil))
		} else {
			err = tiNilAll(t, s)
		}
		treeNativeError(t, err, operationUpdate, "InvalidInput", 22, "nil UpdateImageV1 callback", nil)
		if reservationLive(o) != 0 {
			t.Fatalf("nil planner refusal live %d", reservationLive(o))
		}
		tiRequireOpen(t, s)
		tiNextAdmission(t, s, o, hold)
	}
}

// tiNilAll runs UpdateImageV1(nil, nil) on s and requires (1, 1, -1).
func tiNilAll(t *testing.T, s *Store) error {
	t.Helper()
	r := tiInvoke(s, nil, nil)
	r.tuple(t, 1, 1, -1)
	return r.err
}

func tiAdmissionStore(t *testing.T, name string) {
	s, _, _ := treeNativeStore(t)
	o := reservationOwner(t, MinReservationLimit)
	var terminal error
	switch name {
	case "format2":
		s = newUpdateStore(t)
		t.Cleanup(func() { _ = s.Close() })
	case "consumed":
		_, terminal = s.consume(nativeError(operationUpdate, 5))
		s.latchUpdateTerminalTruth()
		if terminal == nil {
			t.Fatal("consume returned no terminal")
		}
	case "closed":
		mustEnvironment(t, s.Close())
	}
	state, truth, values := s.state, s.terminalTruth, tiErrorTree(terminal, nil)
	calls, replays := 0, 0
	planner := tiCounted(t, &calls, &replays)
	refuse := func(hold uint64) {
		t.Helper()
		var out tiOutcome
		call := func() { out = tiCall(s, o, LaneOperation, hold, planner) }
		if name == "busy" {
			tiHeld(t, s, call)
		} else {
			call()
		}
		tiStoreRefusal(t, name, tiReturned(t, out), terminal)
		if calls != 0 || replays != 0 || reservationLive(o) != 0 || s.state != state || any(s.terminal) != any(terminal) || s.terminalTruth != truth || !tiSameTree(values, tiErrorTree(terminal, nil)) {
			t.Fatalf("Store refusal planner %d Replay %d live %d state %s terminal %v truth %d", calls, replays, reservationLive(o), s.state, s.terminal, s.terminalTruth)
		}
	}
	for _, hold := range []uint64{1, 0} {
		refuse(hold)
		switch name {
		case "busy":
			tiNextAdmission(t, s, o, hold)
		case "format2":
			viewCalls := 0
			mustEnvironment(t, s.View(func(*Reader) error { viewCalls++; return nil }))
			if viewCalls != 1 {
				t.Fatalf("format 2 View ran its callback %d times, want 1", viewCalls)
			}
			refuse(hold)
		case "closed":
			refuse(hold)
		case "consumed":
			tiTerminal(t, s, o, hold, 1, terminal)
		}
	}
}

// tiStoreRefusal checks the refusal of the named Store; a consumed Store returns terminal, the
// error consume returned.
func tiStoreRefusal(t *testing.T, name string, err, terminal error) {
	t.Helper()
	switch name {
	case "busy":
		treeNativeError(t, err, operationUpdate, "Concurrency", -30778, "store operation in progress", nil)
	case "format2":
		treeNativeError(t, err, operationUpdate, "StateMismatch", -30779, "typed tree operation requires tree store", nil)
	case "closed":
		treeNativeError(t, err, operationUpdate, "InvalidInput", 22, "Store is closed", nil)
	case "consumed":
		if any(err) != any(terminal) {
			t.Fatalf("consumed Store returned %v, want the terminal %v", err, terminal)
		}
	}
}
