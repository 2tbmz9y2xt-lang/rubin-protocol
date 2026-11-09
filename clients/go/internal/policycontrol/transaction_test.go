package policycontrol

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// ownerlessState is a valid state at seq whose last commit was ownerless control.
func ownerlessState(id Identity, seq uint64) *state {
	return &state{id: id, seq: seq, rows: map[string]Row{}, receipt: &Receipt{Predecessor: seq - 1, Successor: seq, Operation: operationID(id, seq), Owner: Owner{Kind: OwnerlessControl, Epoch: seq}, Class: ClassControl}}
}

func seedStore(t *testing.T, st *state) (string, *Store) {
	t.Helper()
	dir := storeDir(t)
	must(t, os.WriteFile(filepath.Join(dir, controlFile), encode(st), 0o600))
	return dir, mustOpen(t, dir, st.id)
}

func mustBegin(t *testing.T, s *Store) *Tx {
	t.Helper()
	tx, err := s.Begin()
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	return tx
}

func wantResult(t *testing.T, r Result, truth Truth, seq uint64) {
	t.Helper()
	got, ok := r.Sequence()
	if r.Truth != truth || (truth == UNKNOWN) == ok || (ok && got != seq) {
		t.Fatalf("result %v seq %d/%v, want %v seq %d", r.Truth, got, ok, truth, seq)
	}
}

func put(t *testing.T, tx *Tx, kind RowKind, key, payload string) {
	t.Helper()
	if err := tx.PutRow(kind, []byte(key), []byte(payload)); err != nil {
		t.Fatalf("PutRow: %v", err)
	}
}

// controlTx stages one ownerless control row change.
func controlTx(t *testing.T, s *Store, key string) *Tx {
	t.Helper()
	tx := mustBegin(t, s)
	tx.Ownerless()
	tx.Operation(ClassControl, 0)
	put(t, tx, KindAudit, key, "v")
	return tx
}

func mustCommit(t *testing.T, tx *Tx, truth Truth, seq uint64) {
	t.Helper()
	r, err := tx.Commit()
	if truth == NEW && err != nil {
		t.Fatalf("Commit: %v", err)
	}
	wantResult(t, r, truth, seq)
}

func noScratch(t *testing.T, dir string) {
	t.Helper()
	if _, err := os.Lstat(filepath.Join(dir, scratchFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("scratch left behind: %v", err)
	}
}

// A2: ownerless control 40 -> 41 is NEW with epoch 41, no cursors, no second read.
func TestOwnerlessControlCommit(t *testing.T) {
	_, s := seedStore(t, ownerlessState(testIdentity(1), 40))
	reads := 0
	s.fault = func(st stage) error {
		if st == stageRead {
			reads++
		}
		return nil
	}
	mustCommit(t, controlTx(t, s, "a"), NEW, 41)
	if reads != 0 {
		t.Fatalf("commit performed %d reads", reads)
	}
	r := mustView(t, s).Receipt
	want := Owner{Kind: OwnerlessControl, Epoch: 41}
	if r.Predecessor != 40 || r.Successor != 41 || !reflect.DeepEqual(r.Owner, want) || r.Cursors != nil || r.Class != ClassControl {
		t.Fatalf("receipt %+v", r)
	}
}

func batchTx(t *testing.T, s *Store, before, after uint64, prefix string) *Tx {
	t.Helper()
	tx := mustBegin(t, s)
	tx.RetainOwner(Owner{Kind: OwnerH1, Epoch: 10, Intent: []byte("intent_10")})
	tx.Operation(ClassReconciliationBatch, 7)
	tx.Batch(before, after)
	for i := before; i < after; i++ {
		put(t, tx, KindAudit, fmt.Sprintf("%s%04d", prefix, i), "row")
	}
	return tx
}

// A3: a 128-row batch commits all rows, cursors and the H1 receipt together.
func TestBatchCommitWithCursor(t *testing.T) {
	_, s := seedStore(t, ownerlessState(testIdentity(1), 40))
	mustCommit(t, batchTx(t, s, 0, 128, "b"), NEW, 41)
	r := mustView(t, s).Receipt
	if !reflect.DeepEqual(r.Owner, Owner{Kind: OwnerH1, Epoch: 10, Intent: []byte("intent_10")}) || r.Ordinal != 7 ||
		!reflect.DeepEqual(r.Cursors, &Cursors{Before: 0, After: 128}) {
		t.Fatalf("receipt %+v", r)
	}
	rows, err := s.Membership()
	if err != nil || len(rows) != 128 {
		t.Fatalf("membership %d err %v", len(rows), err)
	}
	for _, row := range rows {
		if row.Sequence != 41 {
			t.Fatalf("row %q committed at %d", row.Key, row.Sequence)
		}
	}
}

// A4, H6: admission gets epoch n+1; continuation, handoff and ending keep the original epoch and intent; nothing re-epochs an owned descriptor.
func TestOwnerEpochRules(t *testing.T) {
	id := testIdentity(1)
	for name, c := range map[string]struct {
		set  func(tx *Tx)
		want Owner
	}{
		"admission":    {func(tx *Tx) { tx.AdmitOwner(OwnerH1, []byte("i")) }, Owner{OwnerH1, 150, []byte("i")}},
		"continuation": {func(tx *Tx) { tx.RetainOwner(Owner{OwnerH1, 100, []byte("i")}) }, Owner{OwnerH1, 100, []byte("i")}},
		"handoff":      {func(tx *Tx) { tx.RetainOwner(Owner{OwnerOrdinaryRestoration, 100, []byte("m")}) }, Owner{OwnerOrdinaryRestoration, 100, []byte("m")}},
		"ending at n":  {func(tx *Tx) { tx.RetainOwner(Owner{OwnerGenericManual, 149, []byte("m")}) }, Owner{OwnerGenericManual, 149, []byte("m")}},
	} {
		_, s := seedStore(t, ownerlessState(id, 149))
		tx := mustBegin(t, s)
		c.set(tx)
		tx.Operation(ClassControl, 0)
		put(t, tx, KindAudit, "a", "v")
		mustCommit(t, tx, NEW, 150)
		if got := mustView(t, s).Receipt.Owner; !reflect.DeepEqual(got, c.want) {
			t.Fatalf("%s: owner %+v, want %+v", name, got, c.want)
		}
	}
	for name, set := range map[string]func(tx *Tx){
		"re-epoch retained owner": func(tx *Tx) { tx.RetainOwner(Owner{OwnerH1, 150, []byte("i")}) },
		"retained epoch zero":     func(tx *Tx) { tx.RetainOwner(Owner{OwnerH1, 0, []byte("i")}) },
		"retained empty intent":   func(tx *Tx) { tx.RetainOwner(Owner{OwnerH1, 100, nil}) },
		"admit ownerless":         func(tx *Tx) { tx.AdmitOwner(OwnerlessControl, nil) },
		"unknown owner":           func(tx *Tx) { tx.AdmitOwner(7, []byte("i")) },
		"undeclared owner":        func(tx *Tx) {},
		"unknown class":           func(tx *Tx) { tx.Ownerless(); tx.Operation(8, 0) },
		"undeclared class":        func(tx *Tx) { tx.Ownerless(); tx.Operation(0, 0) },
		"batch without cursors":   func(tx *Tx) { tx.Ownerless(); tx.Operation(ClassReconciliationBatch, 0) },
		"cursors without batch":   func(tx *Tx) { tx.Ownerless(); tx.Operation(ClassCapture, 0); tx.Batch(0, 0) },
		"compound ordinal":        func(tx *Tx) { tx.Ownerless(); tx.Operation(ClassCompoundControl, 1) },
	} {
		dir, s := seedStore(t, ownerlessState(id, 149))
		before := fileBytes(t, dir)
		tx := mustBegin(t, s)
		tx.Operation(ClassControl, 0)
		set(tx)
		put(t, tx, KindAudit, "a", "v")
		r, err := tx.Commit()
		if wantResult(t, r, OLD, 149); !errors.Is(err, ErrRefused) || !bytes.Equal(fileBytes(t, dir), before) {
			t.Fatalf("%s: err %v or bytes changed", name, err)
		}
	}
	// H6: cursor 0 present is distinct from absent.
	_, s := seedStore(t, ownerlessState(id, 149))
	tx := mustBegin(t, s)
	tx.Ownerless()
	tx.Operation(ClassCompoundControl, 0)
	tx.Batch(0, 0)
	put(t, tx, KindAudit, "a", "v")
	mustCommit(t, tx, NEW, 150)
	if c := mustView(t, s).Receipt.Cursors; c == nil || *c != (Cursors{}) {
		t.Fatalf("zero cursors lost: %v", c)
	}
}

// A5, A6: pure reads and empty or identical commits change nothing; abort is OLD.
func TestPureReadsEmptyCommitAndAbort(t *testing.T) {
	dir, s := seedStore(t, ownerlessState(testIdentity(1), 40))
	mustCommit(t, controlTx(t, s, "a"), NEW, 41)
	before := fileBytes(t, dir)
	mustView(t, s)
	_ = s.Gate()
	if _, err := s.Membership(); err != nil {
		t.Fatal(err)
	}
	// Empty and identical-payload commits declare a valid owner and operation, so OLD comes from the empty-change-set path, not from an unrelated refusal.
	for _, identical := range []bool{false, true} {
		tx := mustBegin(t, s)
		tx.Ownerless()
		tx.Operation(ClassControl, 0)
		if identical {
			put(t, tx, KindAudit, "a", "v")
		}
		r, err := tx.Commit()
		if wantResult(t, r, OLD, 41); err != nil || !bytes.Equal(fileBytes(t, dir), before) {
			t.Fatalf("empty commit (identical %t): %v", identical, err)
		}
	}
	tx := controlTx(t, s, "b")
	r, err := tx.Abort()
	if wantResult(t, r, OLD, 41); err != nil {
		t.Fatal(err)
	}
	if r, err := tx.Commit(); r != (Result{}) || !errors.Is(err, ErrFinished) {
		t.Fatalf("commit after abort: %v %v", r.Truth, err)
	}
	if !bytes.Equal(fileBytes(t, dir), before) || mustView(t, s).Sequence != 41 {
		t.Fatal("pure operations changed P")
	}
	noScratch(t, dir)
}

// A7, A8: a lost acknowledgement freezes P until Recover reads back NEW or OLD.
func TestLostAcknowledgementRecovery(t *testing.T) {
	for _, tc := range []struct {
		name    string
		failAt  stage
		truth   Truth
		seq     uint64
		members int
	}{{"durable", 0, NEW, 41, 128}, {"aborted before commit", stageRename, OLD, 40, 0}} {
		dir, s := seedStore(t, ownerlessState(testIdentity(1), 40))
		old := fileBytes(t, dir)
		s.fault = failAt(tc.failAt, stageAck)
		r, err := batchTx(t, s, 0, 128, "b").Commit()
		if wantResult(t, r, UNKNOWN, 0); !errors.Is(err, ErrUnresolved) {
			t.Fatalf("%s: %v", tc.name, err)
		}
		s.fault = nil
		wantErr(t, ErrBusy)(s.Begin())
		if g := s.Gate(); g != (Gate{}) {
			t.Fatalf("%s: gate %+v", tc.name, g)
		}
		wantErr(t, ErrBusy)(s.View())
		wantErr(t, ErrBusy)(s.Membership())
		r, err = s.Recover()
		if wantResult(t, r, tc.truth, tc.seq); err != nil {
			t.Fatalf("%s: recover %v", tc.name, err)
		}
		v := mustView(t, s)
		rows, _ := s.Membership()
		if v.Sequence != tc.seq || len(rows) != tc.members || (tc.truth == NEW && v.Receipt.Cursors.After != 128) {
			t.Fatalf("%s: view %+v rows %d", tc.name, v, len(rows))
		}
		if tc.truth == OLD && !bytes.Equal(fileBytes(t, dir), old) {
			t.Fatalf("%s: OLD changed bytes", tc.name)
		}
		noScratch(t, dir)
		mustCommit(t, controlTx(t, s, "next"), NEW, tc.seq+1)
	}
}

// X6: every readback other than the exact predecessor or successor is UNKNOWN.
func TestRecoveryReadbackDisagreement(t *testing.T) {
	id := testIdentity(1)
	for name, tamper := range map[string]func(next *state){
		"other profile":           func(n *state) { n.id.Profile = 2 },
		"operation identity of n": func(n *state) { n.receipt.Operation = operationID(n.id, 40) },
		"missing affected row":    func(n *state) { delete(n.rows, rowID(KindAudit, []byte("b0000"))) },
		"wrong owner epoch":       func(n *state) { n.receipt.Owner.Epoch = 11 },
		"cursor without batch":    func(n *state) { n.receipt.Class = ClassControl },
		"unknown class":           func(n *state) { n.receipt.Class = 9 },
		"unknown owner kind":      func(n *state) { n.receipt.Owner.Kind = 9 },
		"another sequence":        func(n *state) { *n = *ownerlessState(id, 42) },
		"zero cursor substitute":  func(n *state) { n.receipt.Cursors = &Cursors{} },
	} {
		dir, s := seedStore(t, ownerlessState(id, 40))
		s.fault = failAt(stageAck)
		wantTruth(t, UNKNOWN)(batchTx(t, s, 0, 128, "b").Commit())
		s.fault = nil
		next := *s.pending.next
		next.receipt = func() *Receipt { r := *next.receipt; return &r }()
		next.rows = map[string]Row{}
		for k, v := range s.pending.next.rows {
			next.rows[k] = v
		}
		tamper(&next)
		must(t, os.WriteFile(filepath.Join(dir, controlFile), encode(&next), 0o600))
		r, err := s.Recover()
		if wantResult(t, r, UNKNOWN, 0); err == nil {
			t.Fatalf("%s: no error", name)
		}
		wantErr(t, ErrBusy)(s.Begin())
	}
}

// X7, X8: a failed post-rename synchronization or a retained crossing handle stays UNKNOWN; Recover neither synchronizes nor reads again.
func TestUnestablishedDurabilityStaysUnknown(t *testing.T) {
	for name, fault := range map[string]error{"directory sync failed": errors.New("EIO"), "handle retained": errInjectedCrash} {
		dir, s := seedStore(t, ownerlessState(testIdentity(1), 40))
		s.fault = failWith(fault, stageDirSync)
		r, err := controlTx(t, s, "a").Commit()
		if wantResult(t, r, UNKNOWN, 0); err == nil {
			t.Fatalf("%s: no error", name)
		}
		if b := fileBytes(t, dir); !bytes.Equal(b, s.pending.new) {
			t.Fatalf("%s: successor bytes not visible", name)
		}
		var calls []stage
		s.fault = func(st stage) error { calls = append(calls, st); return nil }
		for i := 0; i < 3; i++ {
			if r, err := s.Recover(); r.Truth != UNKNOWN || !errors.Is(err, ErrUnresolved) {
				t.Fatalf("%s: recover %v %v", name, r.Truth, err)
			}
		}
		if len(calls) != 0 {
			t.Fatalf("%s: recover performed %v", name, calls)
		}
		if g := s.Gate(); g != (Gate{}) {
			t.Fatalf("%s: gate %+v", name, g)
		}
		must(t, s.Close())
		if errors.Is(fault, errInjectedCrash) {
			// Process loss with no observed sync failure: reopen performs the first synchronization.
			if v := mustView(t, mustOpen(t, dir, testIdentity(1))); v.Sequence != 41 {
				t.Fatalf("%s: reopen saw %d", name, v.Sequence)
			}
			continue
		}
		// An observed failure is never resolved by a later synchronization, reopen or Create.
		for i := 0; i < 2; i++ {
			if s, err := Open(dir, testIdentity(1)); s != nil || !errors.Is(err, ErrUnresolved) {
				t.Fatalf("%s: reopen after failed sync: %v", name, err)
			}
		}
		if s, err := Create(dir, testIdentity(1), NewInstallationProof{Identity: testIdentity(1)}); s != nil || !errors.Is(err, ErrRefused) {
			t.Fatalf("%s: create over unresolved store: %v", name, err)
		}
	}
	dir := storeDir(t)
	h := productionHooks
	h.fault = failAt(stageDirSync)
	if s, err := start(dir, testIdentity(1), &NewInstallationProof{Identity: testIdentity(1)}, h); s != nil || err == nil {
		t.Fatalf("create with failed sync: %v", err)
	}
	if s, err := Open(dir, testIdentity(1)); s != nil || !errors.Is(err, ErrUnresolved) {
		t.Fatalf("open after create sync failure: %v", err)
	}
}

// X3, H6: max-1 -> max commits; a mutation at max refuses before effects.
func TestSequenceBoundary(t *testing.T) {
	dir, s := seedStore(t, ownerlessState(testIdentity(1), math.MaxUint64-1))
	mustCommit(t, controlTx(t, s, "a"), NEW, math.MaxUint64)
	if v := mustView(t, s); v.Receipt.Owner.Epoch != math.MaxUint64 {
		t.Fatalf("epoch %d", v.Receipt.Owner.Epoch)
	}
	before := fileBytes(t, dir)
	r, err := controlTx(t, s, "b").Commit()
	if wantResult(t, r, OLD, math.MaxUint64); !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "sequence exhausted") || !bytes.Equal(fileBytes(t, dir), before) {
		t.Fatalf("exhausted sequence: %v", err)
	}
	noScratch(t, dir)
}

// X5: a failure at any pre-rename stage, including a partial scratch write, aborts everything: OLD with durable bytes identical.
func TestPrecommitFailureIsOld(t *testing.T) {
	for _, at := range []stage{stageCreate, stageWrite, stageFileSync, stageRename} {
		dir, s := seedStore(t, ownerlessState(testIdentity(1), 40))
		before := fileBytes(t, dir)
		s.fault = func(st stage) error {
			if st != at {
				return nil
			}
			if st == stageWrite {
				_ = os.WriteFile(filepath.Join(dir, scratchFile), []byte("partial"), 0o600)
			}
			return errors.New("injected")
		}
		r, err := batchTx(t, s, 0, 128, "b").Commit()
		if wantResult(t, r, OLD, 40); err == nil || !bytes.Equal(fileBytes(t, dir), before) {
			t.Fatalf("stage %d: err %v or bytes changed", at, err)
		}
		noScratch(t, dir)
		if rows, _ := s.Membership(); len(rows) != 0 {
			t.Fatalf("stage %d: rows survived", at)
		}
		s.fault = nil
		mustCommit(t, controlTx(t, s, "a"), NEW, 41)
	}
}

// A18, X4: Begin, Gate, View, Recover and Close never wait on a crossing; a second writer gets the immediate concurrency result.
func TestNoWaiterDuringCrossing(t *testing.T) {
	_, s := seedStore(t, ownerlessState(testIdentity(1), 40))
	tx := controlTx(t, s, "a")
	wantErr(t, ErrBusy)(s.Begin())
	if g := s.Gate(); g != (Gate{}) {
		t.Fatalf("held gate %+v", g)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	s.fault = func(st stage) error {
		if st == stageFileSync {
			close(entered)
			<-release
		}
		return nil
	}
	done := make(chan Result)
	go func() { r, _ := tx.Commit(); done <- r }()
	<-entered
	start := time.Now()
	_, beginErr := s.Begin()
	_, viewErr := s.View()
	_, recErr := s.Recover()
	closeErr := s.Close()
	abortRes, abortErr := tx.Abort()
	againRes, againErr := tx.Commit()
	if abortRes != (Result{}) || !errors.Is(abortErr, ErrFinished) || againRes != (Result{}) || !errors.Is(againErr, ErrFinished) {
		t.Fatalf("in-flight Tx accepted Abort or a second Commit: %v/%v %v/%v", abortRes, abortErr, againRes, againErr)
	}
	g := s.Gate()
	if time.Since(start) > time.Second || !errors.Is(beginErr, ErrBusy) || !errors.Is(viewErr, ErrBusy) ||
		!errors.Is(recErr, ErrBusy) || !errors.Is(closeErr, ErrBusy) || g != (Gate{}) {
		t.Fatalf("crossing waited or allowed: %v %v %v %v %+v", beginErr, viewErr, recErr, closeErr, g)
	}
	close(release)
	wantResult(t, <-done, NEW, 41)
	if g := s.Gate(); !g.DependentEffects || !g.LatchUse || g.AutomaticH1 {
		t.Fatalf("resolved gate %+v", g)
	}
}

// A19: restart continues the committed batch with its next cursor; an uncommitted batch keeps the preceding cursor; nothing is replayed.
func TestRestartContinuation(t *testing.T) {
	id := testIdentity(1)
	dir, s := seedStore(t, ownerlessState(id, 40))
	mustCommit(t, batchTx(t, s, 0, 128, "b"), NEW, 41)
	s.fault = failWith(errInjectedCrash, stageRename)
	wantTruth(t, UNKNOWN)(batchTx(t, s, 128, 256, "b").Commit())
	must(t, s.Close())
	s = mustOpen(t, dir, id)
	v := mustView(t, s)
	rows, _ := s.Membership()
	if v.Sequence != 41 || *v.Receipt.Cursors != (Cursors{0, 128}) || len(rows) != 128 {
		t.Fatalf("reopened at %d cursors %+v rows %d", v.Sequence, v.Receipt.Cursors, len(rows))
	}
	mustCommit(t, batchTx(t, s, 128, 256, "b"), NEW, 42)
	must(t, s.Close())
	s = mustOpen(t, dir, id)
	v = mustView(t, s)
	rows, _ = s.Membership()
	if v.Sequence != 42 || *v.Receipt.Cursors != (Cursors{128, 256}) || len(rows) != 256 {
		t.Fatalf("continued at %d cursors %+v rows %d", v.Sequence, v.Receipt.Cursors, len(rows))
	}
}

// A20: a guard advanced after qualification is STALE_LOCAL_PLAN with OLD retained; guards stay held through the crossing; fresh qualification commits.
func TestGuardQualification(t *testing.T) {
	dir, s := seedStore(t, ownerlessState(testIdentity(1), 40))
	before := fileBytes(t, dir)
	g := &Guard{}
	tx := controlTx(t, s, "a")
	tx.Require(g.Qualify())
	g.Advance()
	r, err := tx.Commit()
	if wantResult(t, r, OLD, 40); !errors.Is(err, ErrStaleLocalPlan) || !bytes.Equal(fileBytes(t, dir), before) {
		t.Fatalf("stale guard: %v", err)
	}
	if v := mustView(t, s); v.Sequence != 40 || v.Receipt.Successor != 40 {
		t.Fatalf("predecessor changed: %+v", v)
	}
	tx = controlTx(t, s, "a")
	q := g.Qualify()
	tx.Require(q)
	tx.Require(q)
	heldDuringCrossing := false
	s.fault = func(st stage) error {
		if st == stageDirSync {
			if heldDuringCrossing = !g.mu.TryLock(); !heldDuringCrossing {
				g.mu.Unlock()
			}
		}
		return nil
	}
	mustCommit(t, tx, NEW, 41)
	if !heldDuringCrossing {
		t.Fatal("guard was not protected through the crossing")
	}
	tx = controlTx(t, s, "b")
	tx.Require(Qualified{})
	if r, err := tx.Commit(); r.Truth != OLD || !errors.Is(err, ErrRefused) {
		t.Fatalf("zero guard: %v %v", r.Truth, err)
	}
}

func TestUnreadableReadbackStaysUnknown(t *testing.T) {
	_, s := seedStore(t, ownerlessState(testIdentity(1), 40))
	s.fault = func(st stage) error {
		return map[bool]error{true: errors.New("EIO")}[st == stageAck || st == stageRead]
	}
	_, _ = controlTx(t, s, "a").Commit()
	_, _ = s.Recover()
	s.fault = nil
	if r, err := s.Recover(); r.Truth != UNKNOWN || !errors.Is(err, ErrUnresolved) {
		t.Fatalf("second Recover: %v %v", r, err)
	}
}
