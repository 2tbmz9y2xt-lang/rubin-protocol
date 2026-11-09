package policycontrol

import (
	"bytes"
	"errors"
	"reflect"
	"sort"
	"testing"
)

func diag(hash byte, height uint64, errText string) Diagnosis {
	return Diagnosis{Height: height, Hash: fill32(hash), Error: []byte(errText), Source: []byte("own-current-replay"), Trigger: []byte("L/T")}
}

func admission(dest string) Admission {
	return Admission{Old: []byte("OLD"), Destination: []byte(dest), Source: SourceGenesisReplay, Profile: ProfileV1, Ownership: []byte("h1-owner")}
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

// A11, H6: first OBSERVED is one control commit that preserves both
// booleans and allocates nothing; height u32max is accepted, above refused.
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

// A12, X10, X9: SAME incident is a no-op that never resets attempted;
// contradictions and second incidents are refused with P unchanged.
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
	for name, d := range map[string]Diagnosis{"other height": diag(1, 101, "e"), "other error": diag(1, 100, "x")} {
		tx := mustBegin(t, s)
		if _, err := tx.ObserveIncident(d); !errors.Is(err, ErrContradiction) {
			t.Fatalf("%s: %v", name, err)
		}
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

// A13, X9: only OBSERVED attempted=false is replaced, atomically, keeping
// both booleans; replacement OLD keeps the old OBSERVED.
func TestObservedReplacement(t *testing.T) {
	_, s := seedStore(t, latchedAttemptedState())
	mustControl(t, s, observe(diag(1, 100, "e")))
	s.fault = func(st stage) error {
		if st == stageRename {
			return errors.New("injected")
		}
		return nil
	}
	if r, _ := controlCommit(t, s, func(tx *Tx) error { return tx.ReplaceObserved(diag(2, 200, "f")) }); r.Truth != OLD {
		t.Fatalf("replacement precommit failure %v", r.Truth)
	}
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
	if _, err := controlCommit(t, s, func(tx *Tx) error { return tx.ReplaceObserved(diag(3, 1, "h")) }); !errors.Is(err, ErrRefused) {
		t.Fatalf("AUTO_BLOCKED replaced: %v", err)
	}
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

// A14, A15: intent consumption, AUTO_BLOCKED, manual re-intent and SUCCESS
// removal keep diagnosis and has_attempt; OLD keeps INTENT for handoff retry only.
func TestIntentAndTerminalTransitions(t *testing.T) {
	_, s := seedStore(t, ownerlessState(testIdentity(1), 40))
	mustControl(t, s, observe(diag(1, 100, "e")))
	for name, fn := range map[string]func(tx *Tx) error{
		"auto-block OBSERVED": func(tx *Tx) error { return tx.AutoBlock() },
		"remove OBSERVED":     func(tx *Tx) error { return tx.RemoveOnSuccess() },
	} {
		if _, err := controlCommit(t, s, fn); !errors.Is(err, ErrRefused) {
			t.Fatalf("%s: %v", name, err)
		}
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
	s.fault = func(st stage) error {
		if st == stageWrite {
			return errors.New("injected")
		}
		return nil
	}
	if r, _ := controlCommit(t, s, func(tx *Tx) error { return tx.AutoBlock() }); r.Truth != OLD || mustView(t, s).Incident.State != StateIntent {
		t.Fatal("handoff OLD did not keep INTENT")
	}
	s.fault = nil
	if _, err := controlCommit(t, s, func(tx *Tx) error { return tx.ConsumeIntent(admission("D9")) }); !errors.Is(err, ErrRefused) {
		t.Fatalf("OLD allowed a new intent: %v", err)
	}
	mustControl(t, s, func(tx *Tx) error { return tx.AutoBlock() })
	blocked := mustView(t, s).Incident
	if blocked.State != StateAutoBlocked || blocked.Diagnosis.Hash != fill32(1) || !reflect.DeepEqual(blocked.Admission, &a) || !mustView(t, s).HasAttempt {
		t.Fatalf("AUTO_BLOCKED %+v", blocked)
	}
	if _, err := controlCommit(t, s, func(tx *Tx) error { return tx.ConsumeIntent(admission("D1")) }); !errors.Is(err, ErrRefused) {
		t.Fatalf("manual intent reused destination: %v", err)
	}
	mustControl(t, s, func(tx *Tx) error { return tx.ConsumeIntent(admission("D2")) })
	if in := mustView(t, s).Incident; in.State != StateIntent || !in.Attempted || in.Diagnosis.Hash != fill32(1) || string(in.Admission.Destination) != "D2" {
		t.Fatalf("manual INTENT %+v", in)
	}
	mustControl(t, s, func(tx *Tx) error { return tx.RemoveOnSuccess() })
	if v := mustView(t, s); v.Incident != nil || !v.HasAttempt {
		t.Fatalf("SUCCESS view %+v", v)
	}
}

// A20: a P-INTENT transaction whose guard advanced is STALE_LOCAL_PLAN with
// the predecessor unchanged; fresh qualification commits n+1.
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

// A9, X11: false predicate writes nothing and retains; stale basis retains;
// OLD clears; NEW latches durably and nothing clears it afterwards.
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
	s.fault = func(st stage) error {
		if st == stageFileSync {
			return errors.New("injected")
		}
		return nil
	}
	if r, _ := s.PersistLatch(stableProof(g)); r.Truth != OLD {
		t.Fatalf("injected OLD: %v", r.Truth)
	}
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

// A10, H5: requests during UNKNOWN start no persistence; readback true
// consumes them, readback false retains an intervening one; restart drops
// the RAM request; unrelated commits keep it.
func TestLatchRequestLifetime(t *testing.T) {
	id := testIdentity(1)
	ackLost := func(also stage) func(stage) error {
		return func(st stage) error {
			if st == stageAck || st == also {
				return errors.New("injected")
			}
			return nil
		}
	}
	g := &Guard{}

	// Unrelated UNKNOWN: request and OBSERVED start no persistence or writer.
	dir, s := seedStore(t, ownerlessState(id, 40))
	s.RequestLatch()
	mustCommit(t, controlTx(t, s, "x"), NEW, 41)
	wantLatch(t, s, LatchStatus{Requested: true})
	s.fault = ackLost(0)
	if r, _ := controlTx(t, s, "y").Commit(); r.Truth != UNKNOWN {
		t.Fatal("expected UNKNOWN")
	}
	s.fault = nil
	before := fileBytes(t, dir)
	s.RequestLatch()
	if r, err := s.PersistLatch(stableProof(g)); r != (Result{}) || !errors.Is(err, ErrBusy) {
		t.Fatalf("persistence during UNKNOWN: %v %v", r.Truth, err)
	}
	if _, err := s.Begin(); !errors.Is(err, ErrBusy) {
		t.Fatal("OBSERVED writer started during UNKNOWN")
	}
	if !bytes.Equal(fileBytes(t, dir), before) {
		t.Fatal("UNKNOWN readback wrote")
	}
	if r, _ := s.Recover(); r.Truth != NEW {
		t.Fatalf("recover %v", r.Truth)
	}
	wantLatch(t, s, LatchStatus{Requested: true})

	// Latch UNKNOWN, intervening request, readback true: consumed, no second write.
	s.fault = ackLost(0)
	if r, _ := s.PersistLatch(stableProof(g)); r.Truth != UNKNOWN {
		t.Fatal("expected latch UNKNOWN")
	}
	s.fault = nil
	wantLatch(t, s, LatchStatus{PendingPersistence: true})
	s.RequestLatch()
	wantLatch(t, s, LatchStatus{Requested: true, PendingPersistence: true})
	if r, _ := s.Recover(); r.Truth != NEW || mustView(t, s).Sequence != 43 {
		t.Fatalf("latch readback %v", r.Truth)
	}
	wantLatch(t, s, LatchStatus{Durable: true})

	// Latch UNKNOWN with readback false: an intervening request is retained
	// for fresh qualification; without one, none remains.
	for _, intervening := range []bool{true, false} {
		dir, s := seedStore(t, ownerlessState(id, 40))
		s.RequestLatch()
		s.fault = ackLost(stageRename)
		if r, _ := s.PersistLatch(stableProof(g)); r.Truth != UNKNOWN {
			t.Fatal("expected latch UNKNOWN")
		}
		s.fault = nil
		if intervening {
			s.RequestLatch()
		}
		if r, _ := s.Recover(); r.Truth != OLD {
			t.Fatalf("readback %v", r.Truth)
		}
		wantLatch(t, s, LatchStatus{Requested: intervening})
		if !intervening {
			continue
		}
		if r, _ := s.PersistLatch(LatchProof{Basis: g.Qualify()}); r.Truth != OLD {
			t.Fatal("false predicate wrote")
		}
		mustCommit(t, controlTx(t, s, "z"), NEW, 41)
		wantLatch(t, s, LatchStatus{Requested: true})
		must(t, s.Close())
		wantLatch(t, mustOpen(t, dir, id), LatchStatus{})
	}

	// Restart before readback: RAM request lost, durable readback true enables.
	dir, s = seedStore(t, ownerlessState(id, 40))
	s.RequestLatch()
	s.fault = ackLost(0)
	if r, _ := s.PersistLatch(stableProof(g)); r.Truth != UNKNOWN {
		t.Fatal("expected latch UNKNOWN")
	}
	s.RequestLatch()
	must(t, s.Close())
	wantLatch(t, mustOpen(t, dir, id), LatchStatus{Durable: true})
}

// X11, X13: API census. No exported path sets the latch outside PersistLatch's
// P transaction or clears it, and no exported operation resets or recreates
// P; the result type carries only P truth.
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
