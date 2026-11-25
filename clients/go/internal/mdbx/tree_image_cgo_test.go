//go:build cgo && (darwin || linux) && (amd64 || arm64)

package mdbx

import (
	"bytes"
	"errors"
	"testing"
)

// tiOutcome is how one UpdateImageV1 call ended: returned with r, or unwound
// with the recovered panic value (nil for Goexit). The rest is observed on the
// caller's own account value a inside WithOperation, after the call returns or
// while it unwinds: original and account are *a before and after the call,
// before and after the state that original names, live the live sum, and reuse
// and reuseLive the result and live sum of a one-byte a.WithReservation.
// wantZero is set by a row whose planner replaces *a with the zero value.
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
}

// tiPlanner counts calls and keeps the last Reader. From its second call on it
// reads meta key 0x02 through the kept Reader and meta key 0x00 through the
// live Reader before it calls outcome. replays counts the Replay calls of the
// publication that outcome returns.
type tiPlanner struct {
	calls          int
	replays        *int
	kept           *Reader
	expiredValue   []byte
	expiredPresent bool
	expired        error
	live           []byte
	liveErr        error
	outcome        func(*Reader) (TreeImagePublicationV1, error)
}

func (p *tiPlanner) imagePlan(r *Reader) (TreeImagePublicationV1, error) {
	p.calls++
	if p.kept != nil {
		p.expiredValue, p.expiredPresent, p.expired = p.kept.Get(TreeSchemaV1DBIs()[0], []byte{2})
		p.live, _, p.liveErr = r.Get(TreeSchemaV1DBIs()[0], []byte{0})
	}
	p.kept = r
	return p.outcome(r)
}

func tiInvoke(s *Store, a *OperationAccount, planner func(*Reader) (TreeImagePublicationV1, error)) tsResult {
	var r tsResult
	r.truth, r.stage, r.index, r.err = s.UpdateImageV1(a, planner)
	return r
}

// tiCall runs one UpdateImageV1 on a fresh goroutine inside WithOperation(kind).
func tiCall(s *Store, o *OperationReservationOwner, kind OperationKind, planner func(*Reader) (TreeImagePublicationV1, error)) tiOutcome {
	return tiCallAccount(s, o, kind, func(*OperationAccount) func(*Reader) (TreeImagePublicationV1, error) { return planner })
}

// tiCallAccount is tiCall with the planner that bind returns for the account WithOperation passes.
func tiCallAccount(s *Store, o *OperationReservationOwner, kind OperationKind, bind func(*OperationAccount) func(*Reader) (TreeImagePublicationV1, error)) tiOutcome {
	var out tiOutcome
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer func() { out.recovered = recover() }()
		_ = o.WithOperation(kind, func(a *OperationAccount) error {
			out.original, out.before = *a, *a.shared
			defer func() {
				out.account, out.after, out.live = *a, *out.original.shared, reservationLive(o)
				out.reuse = a.WithReservation(1, func() error { out.reuseLive = reservationLive(o); return nil })
			}()
			out.r = tiInvoke(s, a, bind(a))
			out.returned = true
			return nil
		})
	}()
	<-done
	return out
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
	if !out.returned || out.recovered != nil {
		t.Fatalf("UpdateImageV1 returned %v recovered %v", out.returned, out.recovered)
	}
	out.r.tuple(t, 1, 1, -1)
	tiAccountKept(t, out)
	return out.r.err
}

// tiAccountKept requires live sum 0 after the call, the state of the caller's account unchanged
// by the call, and the caller's account value either unchanged with a one-byte WithReservation
// admitted at live sum 1, or, for wantZero, the zero value refused as invalid input.
func tiAccountKept(t *testing.T, out tiOutcome) {
	t.Helper()
	if out.live != 0 || out.after != out.before || out.before.held != 0 || out.before.everPositive || out.before.closed {
		t.Fatalf("live sum %d, account before %+v after %+v", out.live, out.before, out.after)
	}
	if out.wantZero {
		if out.account != (OperationAccount{}) || any(out.reuse) != any(errOperationReservationInput) || out.reuseLive != 0 {
			t.Fatalf("zeroed account %+v reuse returned %v with live sum %d", out.account, out.reuse, out.reuseLive)
		}
		return
	}
	if out.account != out.original || out.reuse != nil || out.reuseLive != 1 {
		t.Fatalf("account %+v, want %+v; reuse returned %v with live sum %d", out.account, out.original, out.reuse, out.reuseLive)
	}
}

// tiMeta02 reads meta key 0x02 through a View.
func tiMeta02(t *testing.T, s *Store) ([]byte, bool) {
	t.Helper()
	var value []byte
	var present bool
	mustEnvironment(t, s.View(func(r *Reader) error {
		var err error
		value, present, err = r.Get(TreeSchemaV1DBIs()[0], []byte{2})
		return err
	}))
	return value, present
}

// tiOpenNext requires the Store OPEN, repeats the call with the same planner
// under check, then requires a View that runs view when non-nil and an
// UpdateTreeV1 that returns its callback error once.
func tiOpenNext(t *testing.T, s *Store, o *OperationReservationOwner, kind OperationKind, p *tiPlanner, check func(tiOutcome), view func(*Reader)) {
	t.Helper()
	if s.state != storeOPEN || s.terminal != nil {
		t.Fatalf("Store %s terminal %v, want OPEN", s.state, s.terminal)
	}
	calls := p.calls
	check(tiCall(s, o, kind, p.imagePlan))
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
	mustEnvironment(t, s.View(func(r *Reader) error {
		if view != nil {
			view(r)
		}
		return nil
	}))
	app, treeCalls := errors.New("tree callback error"), 0
	mustEnvironment(t, o.WithOperation(LaneOperation, func(a *OperationAccount) error {
		r := tsInvoke(s, a, func(*Reader) (TreeOperationV1, error) { treeCalls++; return TreeOperationV1{}, app })
		r.tuple(t, 1, 1, -1)
		if any(r.err) != any(app) || treeCalls != 1 {
			t.Fatalf("UpdateTreeV1 on the OPEN Store returned %v with %d callback calls", r.err, treeCalls)
		}
		return nil
	}))
}

// tiTerminal requires UpdateImageV1 and UpdateTreeV1 to return (truth, 1, -1, terminal), View
// and Close to return terminal, zero callback calls and live sum 0, and after these four
// calls the Store state, terminal, terminal truth, transaction and environment it had before.
func tiTerminal(t *testing.T, s *Store, o *OperationReservationOwner, truth CommitTruth, terminal error) {
	t.Helper()
	calls := 0
	state, txn, env := s.state, s.txn, s.env
	same := func(call string) {
		if s.state != state || any(s.terminal) != any(terminal) || s.terminalTruth != truth || s.txn != txn || s.env != env {
			t.Fatalf("terminal %s left %s terminal %v truth %d, want %s with the same transaction and environment", call, s.state, s.terminal, s.terminalTruth, state)
		}
	}
	same("Store")
	mustEnvironment(t, o.WithOperation(LaneOperation, func(a *OperationAccount) error {
		image := tiInvoke(s, a, func(*Reader) (TreeImagePublicationV1, error) { calls++; return TreeImagePublicationV1{}, nil })
		same("UpdateImageV1")
		tree := tsInvoke(s, a, func(*Reader) (TreeOperationV1, error) { calls++; return TreeOperationV1{}, nil })
		same("UpdateTreeV1")
		for _, r := range []tsResult{image, tree} {
			r.tuple(t, truth, 1, -1)
			if any(r.err) != any(terminal) {
				t.Fatalf("terminal Store returned %v, want %v", r.err, terminal)
			}
		}
		return nil
	}))
	if err := s.View(func(*Reader) error { calls++; return nil }); any(err) != any(terminal) {
		t.Fatalf("terminal View returned %v", err)
	}
	same("View")
	if err := s.Close(); any(err) != any(terminal) {
		t.Fatalf("terminal Close returned %v", err)
	}
	same("Close")
	if calls != 0 || reservationLive(o) != 0 {
		t.Fatalf("terminal Store ran %d callbacks, live %d", calls, reservationLive(o))
	}
}

// tiNextAdmission runs the tiPublication publication on s and requires "invalid Update Batch"
// at (1, 1, -1) with live sum 0, one planner call, no Replay call and the Store OPEN.
func tiNextAdmission(t *testing.T, s *Store, o *OperationReservationOwner) {
	t.Helper()
	replays := 0
	publication := tiPublication(t, &replays)
	p := &tiPlanner{replays: &replays, outcome: func(*Reader) (TreeImagePublicationV1, error) { return publication, nil }}
	tiInvalidBatch(t, tiReturned(t, tiCall(s, o, LaneOperation, p.imagePlan)))
	if p.calls != 1 || replays != 0 || s.state != storeOPEN {
		t.Fatalf("next admission planner %d replay %d state %s", p.calls, replays, s.state)
	}
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
		mustEnvironment(t, o.WithOperation(LaneOperation, func(a *OperationAccount) error {
			var s *Store
			for _, r := range []tsResult{tiInvoke(s, a, planner), tiInvoke(s, nil, nil)} {
				r.tuple(t, 1, 1, -1)
				treeNativeError(t, r.err, operationUpdate, "InvalidInput", 22, "nil Store", nil)
			}
			return nil
		}))
		if calls != 0 || replays != 0 || reservationLive(o) != 0 {
			t.Fatalf("nil Store planner %d Replay %d live %d", calls, replays, reservationLive(o))
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
	p := &tiPlanner{replays: &replays, outcome: func(*Reader) (TreeImagePublicationV1, error) { return publication, nil }}
	check := func(out tiOutcome) { tiInvalidBatch(t, tiReturned(t, out)) }
	check(tiCall(s, o, LaneOperation, p.imagePlan))
	if p.calls != 1 || replays != 0 || s.state != storeOPEN {
		t.Fatalf("planner %d replay %d state %s", p.calls, replays, s.state)
	}
	var afterValue []byte
	var afterPresent bool
	afterErr := errors.New("View did not read meta key 0x02")
	tiOpenNext(t, s, o, LaneOperation, p, check, func(r *Reader) {
		afterValue, afterPresent, afterErr = r.Get(TreeSchemaV1DBIs()[0], []byte{2})
	})
	if afterErr != nil || afterPresent != beforePresent || !bytes.Equal(afterValue, beforeValue) {
		t.Fatalf("meta key 0x02 after the calls %x present %v error %v", afterValue, afterPresent, afterErr)
	}
	tsExpiredReader(t, p.kept)
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
	calls, replays := 0, 0
	s.operations.Lock()
	r := tiInvoke(s, account, tiCounted(t, &calls, &replays))
	s.operations.Unlock()
	r.tuple(t, 1, 1, -1)
	treeNativeError(t, r.err, operationUpdate, "InvalidInput", 22, diagnostic, nil)
	if calls != 0 || replays != 0 || reservationLive(o) != 0 || s.state != storeOPEN || s.terminal != nil {
		t.Fatalf("account refusal planner %d Replay %d live %d state %s terminal %v", calls, replays, reservationLive(o), s.state, s.terminal)
	}
	tiNextAdmission(t, s, o)
}

func tiAdmissionNilPlanner(t *testing.T, account bool) {
	s, _, _ := treeNativeStore(t)
	o := reservationOwner(t, MinReservationLimit)
	mustEnvironment(t, o.WithOperation(LaneOperation, func(a *OperationAccount) error {
		if !account {
			a = nil
		}
		r := tiInvoke(s, a, nil)
		r.tuple(t, 1, 1, -1)
		treeNativeError(t, r.err, operationUpdate, "InvalidInput", 22, "nil UpdateImageV1 callback", nil)
		return nil
	}))
	if reservationLive(o) != 0 || s.state != storeOPEN || s.terminal != nil {
		t.Fatalf("nil planner refusal live %d state %s terminal %v", reservationLive(o), s.state, s.terminal)
	}
	tiNextAdmission(t, s, o)
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
	state := s.state
	calls, replays := 0, 0
	planner := tiCounted(t, &calls, &replays)
	refuse := func() {
		mustEnvironment(t, o.WithOperation(LaneOperation, func(a *OperationAccount) error {
			if name == "busy" {
				s.operations.Lock()
				defer s.operations.Unlock()
			}
			r := tiInvoke(s, a, planner)
			r.tuple(t, 1, 1, -1)
			tiStoreRefusal(t, name, r.err, terminal)
			return nil
		}))
		if calls != 0 || replays != 0 || reservationLive(o) != 0 || s.state != state || any(s.terminal) != any(terminal) {
			t.Fatalf("Store refusal planner %d Replay %d live %d state %s terminal %v", calls, replays, reservationLive(o), s.state, s.terminal)
		}
	}
	refuse()
	switch name {
	case "busy":
		tiNextAdmission(t, s, o)
	case "format2":
		mustEnvironment(t, s.View(func(*Reader) error { return nil }))
		refuse()
	case "closed":
		refuse()
	case "consumed":
		tiTerminal(t, s, o, 1, terminal)
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
