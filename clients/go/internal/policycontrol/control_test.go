package policycontrol

import (
	"bytes"
	"errors"
	"reflect"
	"slices"
	"sort"
	"testing"
)

func diag(hash byte, height uint64, errText string) Diagnosis {
	return Diagnosis{Height: height, Hash: fill32(hash), Error: []byte(errText), Source: []byte("own-current-replay"), Trigger: []byte("L/T")}
}

func admission(dest string) Admission {
	return Admission{Old: []byte("OLD"), Destination: []byte(dest), Source: SourceGenesisReplay, Profile: ProfileV1, Ownership: []byte("h1-owner")}
}

// failWith faults exactly the named stages with err.
func failWith(err error, stages ...stage) func(stage) error {
	return func(st stage) error {
		if slices.Contains(stages, st) {
			return err
		}
		return nil
	}
}

func failAt(stages ...stage) func(stage) error { return failWith(errors.New("injected"), stages...) }

// wantTruth checks the Truth of a (Result, error) call.
func wantTruth(t *testing.T, want Truth) func(Result, error) {
	return func(r Result, err error) {
		t.Helper()
		if r.Truth != want {
			t.Fatalf("truth %v (%v), want %v", r.Truth, err, want)
		}
	}
}

// wantErr checks the trailing error of a call.
func wantErr(t *testing.T, target error) func(...any) {
	return func(v ...any) {
		t.Helper()
		if err, _ := v[len(v)-1].(error); !errors.Is(err, target) {
			t.Fatalf("error %v, want %v", err, target)
		}
	}
}

// controlCommit runs one control transaction with stage and returns its result.
func controlCommit(t *testing.T, s *Store, stageFn func(tx *Tx) error) (Result, error) {
	t.Helper()
	tx := mustBegin(t, s)
	tx.AdmitOwner(OwnerH1, []byte("h1-intent"))
	tx.Operation(ClassControl, 1)
	if err := stageFn(tx); err != nil {
		r, _ := tx.Abort()
		return r, err
	}
	return tx.Commit()
}

func mustControl(t *testing.T, s *Store, stageFn func(tx *Tx) error) {
	t.Helper()
	r, err := controlCommit(t, s, stageFn)
	if err != nil || r.Truth != NEW {
		t.Fatalf("control commit %v: %v", r.Truth, err)
	}
}

func observe(d Diagnosis) func(tx *Tx) error {
	return func(tx *Tx) error { _, err := tx.ObserveIncident(d); return err }
}

func latchedAttemptedState() *state {
	st := ownerlessState(testIdentity(1), 40)
	st.ctl = control{sequence: 30, initialSync: true, hasAttempt: true}
	return st
}

// A11, H6: first OBSERVED is one control commit that preserves both booleans and allocates nothing; height u32max is accepted, above refused.
func TestFirstObserved(t *testing.T) {
	dir, s := seedStore(t, latchedAttemptedState())
	before := fileBytes(t, dir)
	r, err := controlCommit(t, s, observe(diag(1, MaxIncidentHeight+1, "e")))
	if !errors.Is(err, ErrRefused) || r.Truth != OLD || !bytes.Equal(fileBytes(t, dir), before) {
		t.Fatalf("height above u32max: %v", err)
	}
	mustControl(t, s, observe(diag(1, MaxIncidentHeight, "e")))
	v := mustView(t, s)
	want := &Incident{Diagnosis: diag(1, MaxIncidentHeight, "e"), State: StateObserved}
	if !reflect.DeepEqual(v.Incident, want) || !v.InitialSyncCompleted || !v.HasAttempt || v.ControlSequence != 41 {
		t.Fatalf("view %+v", v)
	}
	if rows, _ := s.Membership(); len(rows) != 0 {
		t.Fatal("OBSERVED allocated rows")
	}
}

// A12, X10, X9: SAME incident is a no-op that never resets attempted; contradictions and second incidents are refused with P unchanged.
func TestSameIncidentAndContradiction(t *testing.T) {
	dir, s := seedStore(t, ownerlessState(testIdentity(1), 40))
	mustControl(t, s, observe(diag(1, 100, "e")))
	mustControl(t, s, func(tx *Tx) error { return tx.ConsumeIntent(admission("D1")) })
	before := fileBytes(t, dir)
	same := diag(1, 100, "e")
	same.Source = []byte("other-source")
	tx := mustBegin(t, s)
	got, err := tx.ObserveIncident(same)
	if err != nil || got.State != StateIntent || !got.Attempted || !bytes.Equal(got.Diagnosis.Source, []byte("own-current-replay")) {
		t.Fatalf("same incident: %+v %v", got, err)
	}
	mustCommit(t, tx, OLD, 42)
	for _, d := range map[string]Diagnosis{"other height": diag(1, 101, "e"), "other error": diag(1, 100, "x")} {
		tx := mustBegin(t, s)
		wantErr(t, ErrContradiction)(tx.ObserveIncident(d))
		mustCommit(t, tx, OLD, 42)
	}
	for name, fn := range map[string]func(tx *Tx) error{
		"second incident":        observe(diag(2, 100, "e")),
		"replace INTENT":         func(tx *Tx) error { return tx.ReplaceObserved(diag(2, 100, "e")) },
		"consume over INTENT":    func(tx *Tx) error { return tx.ConsumeIntent(admission("D2")) },
		"empty destination":      func(tx *Tx) error { return tx.ConsumeIntent(admission("")) },
		"destination equals OLD": func(tx *Tx) error { return tx.ConsumeIntent(admission("OLD")) },
		"source not genesis":     func(tx *Tx) error { a := admission("D2"); a.Source = 2; return tx.ConsumeIntent(a) },
		"empty diagnosis error":  func(tx *Tx) error { _, err := tx.ObserveIncident(diag(1, 100, "")); return err },
	} {
		if r, err := controlCommit(t, s, fn); !errors.Is(err, ErrRefused) || r.Truth != OLD {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if !bytes.Equal(fileBytes(t, dir), before) {
		t.Fatal("refusals changed P")
	}
}

// A13, X9: only OBSERVED attempted=false is replaced, atomically, keeping both booleans; replacement OLD keeps the old OBSERVED.
func TestObservedReplacement(t *testing.T) {
	_, s := seedStore(t, latchedAttemptedState())
	mustControl(t, s, observe(diag(1, 100, "e")))
	s.fault = failAt(stageRename)
	wantTruth(t, OLD)(controlCommit(t, s, func(tx *Tx) error { return tx.ReplaceObserved(diag(2, 200, "f")) }))
	if v := mustView(t, s); v.Incident.Diagnosis.Hash != fill32(1) {
		t.Fatal("OLD replacement lost the old OBSERVED")
	}
	s.fault = nil
	if r, err := controlCommit(t, s, func(tx *Tx) error { return tx.ReplaceObserved(diag(1, 300, "g")) }); !errors.Is(err, ErrRefused) || r.Truth != OLD {
		t.Fatalf("same-hash replacement: %v", err)
	}
	mustControl(t, s, func(tx *Tx) error { return tx.ReplaceObserved(diag(2, 200, "f")) })
	v := mustView(t, s)
	if !reflect.DeepEqual(v.Incident, &Incident{Diagnosis: diag(2, 200, "f"), State: StateObserved}) || !v.InitialSyncCompleted || !v.HasAttempt {
		t.Fatalf("replacement view %+v", v)
	}
	mustControl(t, s, func(tx *Tx) error { return tx.ConsumeIntent(admission("D1")) })
	mustControl(t, s, func(tx *Tx) error { return tx.AutoBlock() })
	wantErr(t, ErrRefused)(controlCommit(t, s, func(tx *Tx) error { return tx.ReplaceObserved(diag(3, 1, "h")) }))
}

// X9: an OBSERVED record with attempted=true is neither replaced nor consumed.
func TestAttemptedObservedIsNotReplaced(t *testing.T) {
	st := latchedAttemptedState()
	st.ctl.incident = &Incident{Diagnosis: diag(1, 100, "e"), Attempted: true, State: StateObserved}
	dir, s := seedStore(t, st)
	before := fileBytes(t, dir)
	for name, fn := range map[string]func(tx *Tx) error{
		"replace": func(tx *Tx) error { return tx.ReplaceObserved(diag(2, 200, "f")) },
		"consume": func(tx *Tx) error { return tx.ConsumeIntent(admission("D1")) },
	} {
		if r, err := controlCommit(t, s, fn); !errors.Is(err, ErrRefused) || r.Truth != OLD || !bytes.Equal(fileBytes(t, dir), before) {
			t.Fatalf("%s attempted OBSERVED: %v", name, err)
		}
	}
}

// A14, A15: intent consumption, AUTO_BLOCKED, manual re-intent and SUCCESS removal keep diagnosis and has_attempt; OLD keeps INTENT for handoff retry only.
func TestIntentAndTerminalTransitions(t *testing.T) {
	_, s := seedStore(t, ownerlessState(testIdentity(1), 40))
	mustControl(t, s, observe(diag(1, 100, "e")))
	for _, fn := range map[string]func(tx *Tx) error{
		"auto-block OBSERVED": func(tx *Tx) error { return tx.AutoBlock() },
		"remove OBSERVED":     func(tx *Tx) error { return tx.RemoveOnSuccess() },
	} {
		wantErr(t, ErrRefused)(controlCommit(t, s, fn))
	}
	r, err := controlCommit(t, s, func(tx *Tx) error { return tx.ConsumeIntent(admission("D1")) })
	if wantResult(t, r, NEW, 42); err != nil {
		t.Fatal(err)
	}
	v := mustView(t, s)
	a := admission("D1")
	if v.Incident.State != StateIntent || !v.Incident.Attempted || !v.HasAttempt || !reflect.DeepEqual(v.Incident.Admission, &a) {
		t.Fatalf("INTENT view %+v", v.Incident)
	}
	s.fault = failAt(stageWrite)
	if r, _ := controlCommit(t, s, func(tx *Tx) error { return tx.AutoBlock() }); r.Truth != OLD || mustView(t, s).Incident.State != StateIntent {
		t.Fatal("handoff OLD did not keep INTENT")
	}
	s.fault = nil
	wantErr(t, ErrRefused)(controlCommit(t, s, func(tx *Tx) error { return tx.ConsumeIntent(admission("D9")) }))
	mustControl(t, s, func(tx *Tx) error { return tx.AutoBlock() })
	blocked := mustView(t, s).Incident
	if blocked.State != StateAutoBlocked || blocked.Diagnosis.Hash != fill32(1) || !reflect.DeepEqual(blocked.Admission, &a) || !mustView(t, s).HasAttempt {
		t.Fatalf("AUTO_BLOCKED %+v", blocked)
	}
	wantErr(t, ErrRefused)(controlCommit(t, s, func(tx *Tx) error { return tx.ConsumeIntent(admission("D1")) }))
	mustControl(t, s, func(tx *Tx) error { return tx.ConsumeIntent(admission("D2")) })
	if in := mustView(t, s).Incident; in.State != StateIntent || !in.Attempted || in.Diagnosis.Hash != fill32(1) || string(in.Admission.Destination) != "D2" {
		t.Fatalf("manual INTENT %+v", in)
	}
	mustControl(t, s, func(tx *Tx) error { return tx.RemoveOnSuccess() })
	if v := mustView(t, s); v.Incident != nil || !v.HasAttempt {
		t.Fatalf("SUCCESS view %+v", v)
	}
}

// A20: a P-INTENT transaction whose guard advanced is STALE_LOCAL_PLAN with the predecessor unchanged; fresh qualification commits n+1.
func TestIntentGuardQualification(t *testing.T) {
	dir, s := seedStore(t, ownerlessState(testIdentity(1), 40))
	mustControl(t, s, observe(diag(1, 100, "e")))
	before := fileBytes(t, dir)
	g := &Guard{}
	tx := mustBegin(t, s)
	tx.AdmitOwner(OwnerH1, []byte("i"))
	tx.Operation(ClassControl, 1)
	tx.Require(g.Qualify())
	must(t, tx.ConsumeIntent(admission("D1")))
	g.Advance()
	r, err := tx.Commit()
	if wantResult(t, r, OLD, 41); !errors.Is(err, ErrStaleLocalPlan) || !bytes.Equal(fileBytes(t, dir), before) {
		t.Fatalf("stale intent: %v", err)
	}
	mustControl(t, s, func(tx *Tx) error { tx.Require(g.Qualify()); return tx.ConsumeIntent(admission("D1")) })
	if v := mustView(t, s); v.Sequence != 42 || v.Incident.State != StateIntent {
		t.Fatalf("fresh intent %+v", v)
	}
}

func stableProof(g *Guard) LatchProof { return LatchProof{PredicateTrue: true, Basis: g.Qualify()} }

func wantLatch(t *testing.T, s *Store, want LatchStatus) {
	t.Helper()
	if got := s.Latch(); got != want {
		t.Fatalf("latch %+v, want %+v", got, want)
	}
}

// A9, X11: false predicate writes nothing and retains; stale basis retains; OLD clears; NEW latches durably and nothing clears it afterwards.
func TestLatchPersistence(t *testing.T) {
	id := testIdentity(1)
	dir, s := seedStore(t, ownerlessState(id, 40))
	g := &Guard{}
	before := fileBytes(t, dir)
	if r, err := s.PersistLatch(stableProof(g)); r.Truth != OLD || !errors.Is(err, ErrNoRequest) {
		t.Fatalf("no request: %v %v", r.Truth, err)
	}
	s.RequestLatch()
	s.RequestLatch()
	if r, err := s.PersistLatch(LatchProof{Basis: g.Qualify()}); r.Truth != OLD || err != nil {
		t.Fatalf("false predicate: %v", err)
	}
	stale := stableProof(g)
	g.Advance()
	if r, err := s.PersistLatch(stale); r.Truth != OLD || !errors.Is(err, ErrStaleLocalPlan) {
		t.Fatalf("stale basis: %v", err)
	}
	if !bytes.Equal(fileBytes(t, dir), before) {
		t.Fatal("unpersisted latch wrote")
	}
	wantLatch(t, s, LatchStatus{Requested: true})
	if g := s.Gate(); g.AutomaticH1 {
		t.Fatal("automatic H1 permitted before the latch")
	}
	s.fault = failAt(stageFileSync)
	wantTruth(t, OLD)(s.PersistLatch(stableProof(g)))
	wantLatch(t, s, LatchStatus{})
	s.fault = nil
	s.RequestLatch()
	r, err := s.PersistLatch(stableProof(g))
	if wantResult(t, r, NEW, 41); err != nil {
		t.Fatal(err)
	}
	wantLatch(t, s, LatchStatus{Durable: true})
	if v := mustView(t, s); v.Receipt.Owner.Kind != OwnerlessControl || v.ControlSequence != 41 {
		t.Fatalf("latch receipt %+v", v.Receipt)
	}
	if g := s.Gate(); !g.AutomaticH1 {
		t.Fatal("durable latch did not permit automatic H1 at the P gate")
	}
	mustControl(t, s, observe(diag(1, 100, "e")))
	mustControl(t, s, func(tx *Tx) error { return tx.ConsumeIntent(admission("D1")) })
	mustControl(t, s, func(tx *Tx) error { return tx.AutoBlock() })
	s.RequestLatch()
	wantLatch(t, s, LatchStatus{Durable: true})
	must(t, s.Close())
	wantLatch(t, mustOpen(t, dir, id), LatchStatus{Durable: true})
	if r, err := s.PersistLatch(stableProof(g)); r != (Result{}) || !errors.Is(err, ErrClosed) {
		t.Fatalf("closed store: %v %v", r, err)
	}
}

// A10, H5: requests during UNKNOWN start no persistence; readback true consumes them, readback false retains an intervening one; restart drops the RAM request; unrelated commits keep it.
func TestLatchRequestLifetime(t *testing.T) {
	id := testIdentity(1)
	g := &Guard{}

	// Unrelated UNKNOWN: request and OBSERVED start no persistence or writer.
	dir, s := seedStore(t, ownerlessState(id, 40))
	s.RequestLatch()
	mustCommit(t, controlTx(t, s, "x"), NEW, 41)
	wantLatch(t, s, LatchStatus{Requested: true})
	s.fault = failAt(stageAck)
	wantTruth(t, UNKNOWN)(controlTx(t, s, "y").Commit())
	s.fault = nil
	before := fileBytes(t, dir)
	s.RequestLatch()
	if r, err := s.PersistLatch(stableProof(g)); r != (Result{}) || !errors.Is(err, ErrBusy) {
		t.Fatalf("persistence during UNKNOWN: %v %v", r.Truth, err)
	}
	wantErr(t, ErrBusy)(s.Begin())
	if !bytes.Equal(fileBytes(t, dir), before) {
		t.Fatal("UNKNOWN readback wrote")
	}
	wantTruth(t, NEW)(s.Recover())
	wantLatch(t, s, LatchStatus{Requested: true})

	// Latch UNKNOWN, intervening request, readback true: consumed, no second write.
	s.fault = failAt(stageAck)
	wantTruth(t, UNKNOWN)(s.PersistLatch(stableProof(g)))
	s.fault = nil
	wantLatch(t, s, LatchStatus{PendingPersistence: true})
	s.RequestLatch()
	wantLatch(t, s, LatchStatus{Requested: true, PendingPersistence: true})
	if r, _ := s.Recover(); r.Truth != NEW || mustView(t, s).Sequence != 43 {
		t.Fatalf("latch readback %v", r.Truth)
	}
	wantLatch(t, s, LatchStatus{Durable: true})

	// Latch UNKNOWN with readback false: an intervening request is retained for fresh qualification; without one, none remains.
	for _, intervening := range []bool{true, false} {
		dir, s := seedStore(t, ownerlessState(id, 40))
		s.RequestLatch()
		s.fault = failAt(stageAck, stageRename)
		wantTruth(t, UNKNOWN)(s.PersistLatch(stableProof(g)))
		s.fault = nil
		if intervening {
			s.RequestLatch()
		}
		wantTruth(t, OLD)(s.Recover())
		wantLatch(t, s, LatchStatus{Requested: intervening})
		if !intervening {
			continue
		}
		wantTruth(t, OLD)(s.PersistLatch(LatchProof{Basis: g.Qualify()}))
		mustCommit(t, controlTx(t, s, "z"), NEW, 41)
		wantLatch(t, s, LatchStatus{Requested: true})
		must(t, s.Close())
		wantLatch(t, mustOpen(t, dir, id), LatchStatus{})
	}

	// Restart before readback: RAM request lost, durable readback true enables.
	dir, s = seedStore(t, ownerlessState(id, 40))
	s.RequestLatch()
	s.fault = failAt(stageAck)
	wantTruth(t, UNKNOWN)(s.PersistLatch(stableProof(g)))
	s.RequestLatch()
	must(t, s.Close())
	wantLatch(t, mustOpen(t, dir, id), LatchStatus{Durable: true})
}

// X11, X13: API census. No exported path sets the latch outside PersistLatch's P transaction or clears it, and no exported operation resets or recreates P; the result type carries only P truth.
func TestAPICensus(t *testing.T) {
	methods := func(v any) []string {
		typ := reflect.TypeOf(v)
		var out []string
		for i := 0; i < typ.NumMethod(); i++ {
			out = append(out, typ.Method(i).Name)
		}
		sort.Strings(out)
		return out
	}
	want := map[string][]string{
		"Store":  {"Begin", "Close", "Gate", "Latch", "Membership", "PersistLatch", "Recover", "RequestLatch", "View"},
		"Tx":     {"Abort", "AdmitOwner", "AutoBlock", "Batch", "Commit", "ConsumeIntent", "DeleteRow", "ObserveIncident", "Operation", "Ownerless", "PutRow", "RemoveOnSuccess", "ReplaceObserved", "Require", "RetainOwner"},
		"Result": {"Sequence"},
	}
	got := map[string][]string{"Store": methods(&Store{}), "Tx": methods(&Tx{}), "Result": methods(Result{})}
	for name := range want {
		if !reflect.DeepEqual(got[name], want[name]) {
			t.Fatalf("%s methods %v, want %v", name, got[name], want[name])
		}
	}
	rt := reflect.TypeOf(Result{})
	if rt.NumField() != 2 || rt.Field(0).Name != "Truth" || rt.Field(1).IsExported() {
		t.Fatal("Result carries more than P truth")
	}
	gt := reflect.TypeOf(Gate{})
	for i := 0; i < gt.NumField(); i++ {
		if gt.Field(i).Type.Kind() != reflect.Bool {
			t.Fatal("Gate carries more than refusal bits")
		}
	}
}

// A9: a latch transaction found empty (already durably true) still consumes the request.
func TestEmptyLatchCommitConsumesRequest(t *testing.T) {
	_, s := seedStore(t, ownerlessState(testIdentity(1), 40))
	tx := mustBegin(t, s)
	tx.latch, s.latchRequested = true, true
	if r, err := tx.Commit(); err != nil || r.Truth != OLD || s.latchRequested {
		t.Fatalf("%v %v requested=%t", r, err, s.latchRequested)
	}
}

// X9: a transaction carries one incident change; every other change is refused, the staged state stays and commits alone.
func TestOneIncidentChangePerTransaction(t *testing.T) {
	type op = func(tx *Tx) error
	replace := func(h byte) op { return func(tx *Tx) error { return tx.ReplaceObserved(diag(h, 200, "f")) } }
	consume := func(dest string) op { return func(tx *Tx) error { return tx.ConsumeIntent(admission(dest)) } }
	block, remove := op(func(tx *Tx) error { return tx.AutoBlock() }), op(func(tx *Tx) error { return tx.RemoveOnSuccess() })
	committed := observe(diag(1, 100, "e"))
	// ops[0] is the staged change; every later op must be refused.
	for name, tc := range map[string]struct{ prior, ops []op }{
		"first OBSERVED": {nil, []op{committed, replace(2), consume("D1"), observe(diag(2, 100, "e"))}},
		"replacement":    {[]op{committed}, []op{replace(2), replace(3), consume("D1"), committed}},
		"intent":         {[]op{committed}, []op{consume("D1"), block, remove, consume("D2")}},
		"auto-block":     {[]op{committed, consume("D1")}, []op{block, consume("D2"), remove}},
		"removal":        {[]op{committed, consume("D1")}, []op{remove, observe(diag(2, 100, "e")), committed}},
	} {
		_, s := seedStore(t, ownerlessState(testIdentity(1), 40))
		for _, fn := range tc.prior {
			mustControl(t, s, fn)
		}
		tx := controlTx(t, s, "x")
		must(t, tc.ops[0](tx))
		staged := incidentBytes(tx.ctl.incident)
		for i, fn := range tc.ops[1:] {
			if err := fn(tx); !errors.Is(err, ErrRefused) || !bytes.Equal(incidentBytes(tx.ctl.incident), staged) {
				t.Fatalf("%s: second change %d: %v", name, i, err)
			}
		}
		r, err := tx.Commit()
		if r.Truth != NEW || err != nil || !bytes.Equal(incidentBytes(s.st.ctl.incident), staged) {
			t.Fatalf("%s: commit %v %v", name, r.Truth, err)
		}
	}
	// A12, X10: a record request compares with the staged incident ahead of the committed one.
	_, s := seedStore(t, ownerlessState(testIdentity(1), 40))
	mustControl(t, s, observe(diag(1, 100, "e")))
	tx := mustBegin(t, s)
	must(t, tx.ReplaceObserved(diag(2, 200, "f")))
	if got, err := tx.ObserveIncident(diag(2, 200, "f")); err != nil || got.Diagnosis.Hash != fill32(2) {
		t.Fatalf("staged no-op: %+v %v", got, err)
	}
	wantErr(t, ErrContradiction)(tx.ObserveIncident(diag(2, 201, "f")))
}

// A10: a request recorded while a latch attempt crosses survives its OLD or UNKNOWN; a durable NEW consumes it; a request from an earlier crossing marks nothing.
func TestLatchRequestDuringCrossing(t *testing.T) {
	g := &Guard{}
	requestDuring := func(s *Store, faults ...stage) func(stage) error {
		fail := failAt(faults...)
		return func(st stage) error {
			if st == stageCreate {
				s.RequestLatch()
			}
			return fail(st)
		}
	}
	want := map[Truth]LatchStatus{OLD: {Requested: true}, UNKNOWN: {Requested: true, PendingPersistence: true}, NEW: {Durable: true}}
	for truth, faults := range map[Truth][]stage{OLD: {stageWrite}, UNKNOWN: {stageAck}, NEW: nil} {
		_, s := seedStore(t, ownerlessState(testIdentity(1), 40))
		s.RequestLatch()
		s.fault = requestDuring(s, faults...)
		wantTruth(t, truth)(s.PersistLatch(stableProof(g)))
		wantLatch(t, s, want[truth])
	}
	_, s := seedStore(t, ownerlessState(testIdentity(1), 40))
	s.fault = requestDuring(s)
	mustCommit(t, controlTx(t, s, "x"), NEW, 41)
	s.fault = failAt(stageWrite)
	wantTruth(t, OLD)(s.PersistLatch(stableProof(g)))
	wantLatch(t, s, LatchStatus{})
}

// A10: Close discards the RAM request, and a closed store records none.
func TestCloseDiscardsLatchRequest(t *testing.T) {
	_, s := seedStore(t, ownerlessState(testIdentity(1), 40))
	s.RequestLatch()
	must(t, s.Close())
	wantLatch(t, s, LatchStatus{})
	s.RequestLatch()
	wantLatch(t, s, LatchStatus{})
}
