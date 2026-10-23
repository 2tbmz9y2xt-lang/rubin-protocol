//go:build cgo && (darwin || linux) && (amd64 || arm64)

package mdbx

import (
	"errors"
	"math"
	"path/filepath"
	"testing"
)

// mbView returns the binding of one fresh active View Reader.
func mbView(t *testing.T, s *Store) MutationBindingV1 {
	t.Helper()
	var binding MutationBindingV1
	mustEnvironment(t, s.View(func(r *Reader) error {
		var err error
		binding, err = r.MutationBindingV1()
		return err
	}))
	return binding
}

// mbEpoch reads the same-package attempt epoch; expected values in callers are contract literals.
func mbEpoch(t *testing.T, s *Store, want uint64, marker string) {
	t.Helper()
	if s.lineageEpoch != want {
		t.Fatalf("%s: epoch=%d, want %d", marker, s.lineageEpoch, want)
	}
}

func mbCommit(t *testing.T, s *Store, id uint64, marker string) {
	t.Helper()
	consultedRequireCommit(t, s, marker, Batch{Mutations: []Mutation{consultedCounter(t, id)}})
}

// mbReuse requires EqualForReuse to give want in both directions.
func mbReuse(t *testing.T, a, b MutationBindingV1, want bool, marker string) {
	t.Helper()
	if a.EqualForReuse(b) != want || b.EqualForReuse(a) != want {
		t.Fatalf("%s: EqualForReuse=%v, want %v (%+v vs %+v)", marker, a.EqualForReuse(b), want, a, b)
	}
}

func mbSuccessor(t *testing.T, b MutationBindingV1) MutationBindingV1 {
	t.Helper()
	next, ok := b.AfterOneCommitAttemptV1()
	if !ok {
		t.Fatalf("no successor for %+v", b)
	}
	return next
}

func TestMutationBindingSameStoreV1(t *testing.T) {
	s, _, _ := consultedStore(t)
	first, second := mbView(t, s), mbView(t, s)
	mbReuse(t, first, second, true, "N1 repeated View")
	mbReuse(t, first, first, true, "N1 self")
	var updateBinding MutationBindingV1
	refusal := errors.New("N4 refusal")
	truth, stage, err := s.Update(func(r *Reader) (Batch, error) {
		var getErr error
		updateBinding, getErr = r.MutationBindingV1()
		mustEnvironment(t, getErr)
		return Batch{}, refusal
	})
	if truth != CommitTruthOld || stage != UpdateStagePrewrite || !errors.Is(err, refusal) {
		t.Fatalf("N4 callback refusal tuple: %s/%d/%v", truth, stage, err)
	}
	mbReuse(t, first, updateBinding, true, "N1 Update Reader")
	mbEpoch(t, s, 0, "N4 no attempt")
	mbReuse(t, first, mbView(t, s), true, "N4 binding after refusal")
	mbCommit(t, s, 7, "N4 later legal Update")
	mbEpoch(t, s, 1, "N4 later legal Update")
}

func TestMutationBindingAdvanceV1(t *testing.T) {
	s, _, _ := consultedStore(t)
	mbEpoch(t, s, 0, "N2 construction")
	old := mbView(t, s)
	mbCommit(t, s, 7, "N2 commit")
	mbEpoch(t, s, 1, "N2 one attempt")
	fresh := mbView(t, s)
	mbReuse(t, fresh, mbSuccessor(t, old), true, "N2 successor")
	mbReuse(t, fresh, old, false, "N2 stale")
	twice := mbSuccessor(t, mbSuccessor(t, old))
	mbReuse(t, fresh, twice, false, "N9 epoch+2")
	mbCommit(t, s, 8, "N9 second commit")
	mbEpoch(t, s, 2, "N9 second attempt")
	mbReuse(t, mbView(t, s), mbSuccessor(t, old), false, "N9 stale successor")
	mbReuse(t, mbView(t, s), twice, true, "N9 two attempts")
}

func TestMutationBindingPublicEntriesV1(t *testing.T) {
	t.Run("N3 bootstrap then archive", func(t *testing.T) {
		s, _, _ := consultedStore(t)
		before := mbView(t, s)
		truth, stage, err := s.BootstrapStorageV1(1, bootstrapOwner(t))
		if truth != CommitTruthNew || stage != UpdateStageCommitMayHaveCrossed || err != nil {
			t.Fatalf("bootstrap: %s/%d/%v", truth, stage, err)
		}
		mbEpoch(t, s, 1, "N3 bootstrap")
		owner := bootstrapOwner(t)
		out := s.SelectArchiveProfileV1(owner)
		if out.Truth != CommitTruthNew || out.Err != nil {
			t.Fatalf("archive: %+v", out)
		}
		prunedReleased(t, owner)
		mbEpoch(t, s, 2, "N3 archive")
		after := mbView(t, s)
		mbReuse(t, after, before, false, "N3 pre-first binding")
		mbReuse(t, after, mbSuccessor(t, before), false, "N3 pre-first successor")
		mbReuse(t, after, mbSuccessor(t, mbSuccessor(t, before)), true, "N3 two attempts")
		prunedDecision(t, s.SelectArchiveProfileV1(owner), "PROFILE_NOOP", "N3 noop")
		mbEpoch(t, s, 2, "N3 noop decision")
	})
	t.Run("N5 cleanup side", func(t *testing.T) {
		a := sideAuthority(5, 9)
		var rows []Mutation
		for h := uint64(5); h <= 9; h++ {
			_, _, pair := sideRows(2, h)
			rows = append(rows, pair...)
		}
		s, _ := sideStore(t, a, rows...)
		mbEpoch(t, s, 1, "N5 side seed")
		sideRun(t, s, CommitTruthNew)
		mbEpoch(t, s, 2, "N5 side")
	})
	t.Run("N5 cleanup BU", func(t *testing.T) {
		s, _, _, _ := cleanupTestStore(t, cleanupAuthority(CleanupSpanBlocksV1, 0, false), 0, 0)
		before := s.lineageEpoch
		truth, stage, err := s.CleanupBUV1(bootstrapOwner(t))
		if truth != CommitTruthNew || stage != UpdateStageCommitMayHaveCrossed || err != nil {
			t.Fatalf("cleanup BU: %s/%d/%v", truth, stage, err)
		}
		mbEpoch(t, s, before+1, "N5 cleanup BU")
	})
	t.Run("N5 pruned", func(t *testing.T) {
		s, _, _, _ := prunedStore(t, modelBase(2, 0, 0), nil, modelWork(false))
		mbEpoch(t, s, 1, "N5 pruned seed")
		owner := bootstrapOwner(t)
		out := s.SelectPrunedProfileV1(true, nil, owner)
		if out.Truth != CommitTruthNew || out.Err != nil {
			t.Fatalf("pruned: %+v", out)
		}
		prunedReleased(t, owner)
		mbEpoch(t, s, 2, "N5 pruned")
	})
}

// N6 changes the process-global identity counter: never t.Parallel.
func TestMutationBindingExhaustionV1(t *testing.T) {
	saved := storeLineageLast.Load()
	t.Cleanup(func() { storeLineageLast.Store(saved) })
	storeLineageLast.Store(math.MaxUint64 - 1)
	last, _, _ := consultedStore(t)
	if last.lineageID != math.MaxUint64 {
		t.Fatalf("N6 last identity=%d", last.lineageID)
	}
	lastBinding := mbView(t, last)
	mbReuse(t, lastBinding, lastBinding, true, "N6 maximum identity")
	exhausted, _, _ := consultedStore(t)
	if exhausted.lineageID == last.lineageID || storeLineageLast.Load() != math.MaxUint64 {
		t.Fatalf("N6 identity reused or wrapped: %d %d", exhausted.lineageID, storeLineageLast.Load())
	}
	binding := mbView(t, exhausted)
	mbReuse(t, binding, binding, false, "N6 non-cacheable instance")
	if _, ok := binding.AfterOneCommitAttemptV1(); ok {
		t.Fatal("N6 non-cacheable successor")
	}
	storeLineageLast.Store(saved)

	s, _, _ := consultedStore(t)
	s.lineageEpoch = math.MaxUint64 - 1
	before := mbView(t, s)
	mbCommit(t, s, 7, "N6 reach maximum")
	mbEpoch(t, s, math.MaxUint64, "N6 reach maximum")
	atMax := mbView(t, s)
	mbReuse(t, atMax, mbSuccessor(t, before), true, "N6 maximum stays reusable")
	if next, ok := atMax.AfterOneCommitAttemptV1(); ok || next != (MutationBindingV1{}) {
		t.Fatal("N6 successor beyond maximum")
	}
	mbCommit(t, s, 8, "N6 exhausting attempt")
	mbEpoch(t, s, math.MaxUint64, "N6 no wrap")
	if !s.lineageExhausted {
		t.Fatal("N6 exhaustion not recorded")
	}
	after := mbView(t, s)
	mbReuse(t, after, after, false, "N6 exhausted instance")
	mbReuse(t, after, atMax, false, "N6 exhausted versus maximum")
	consultedRequireImage(t, s, readDBIsLiteral()[0], consultedCounter(t, 8).Key, consultedCounter(t, 8).Literal, true, "N6 image")
}

func TestMutationBindingInstancesV1(t *testing.T) {
	path, cfg := filepath.Join(t.TempDir(), "db"), environmentConfig()
	first, err := Create(path, cfg)
	mustEnvironment(t, err)
	closed := mbView(t, first)
	mustEnvironment(t, first.Close())
	reopened, err := Open(path, cfg)
	reopened = consultedTrack(t, reopened, err)
	mbEpoch(t, reopened, 0, "N7 reopen")
	again := mbView(t, reopened)
	mbReuse(t, again, closed, false, "N7 Close then Open")
	other, _, _ := consultedStore(t)
	foreign := mbView(t, other)
	mbReuse(t, again, foreign, false, "N7 equal epochs")
	mbCommit(t, other, 7, "N7 foreign commit")
	mbReuse(t, mbView(t, other), mbSuccessor(t, again), false, "N9 foreign successor")
	mbReuse(t, mbView(t, reopened), again, true, "N9 foreign commit leaves this instance")
}

func mbInactive(t *testing.T, r *Reader, marker string) {
	t.Helper()
	binding, err := r.MutationBindingV1()
	if binding != (MutationBindingV1{}) {
		t.Fatalf("%s: binding=%+v", marker, binding)
	}
	if engine := requireEnvironmentError(t, err, EngineInvalidInput, operationGet, codeEINVAL, "Reader is not active"); engine.Cause != nil {
		t.Fatalf("%s: cause=%v", marker, engine.Cause)
	}
}

func TestMutationBindingInactiveV1(t *testing.T) {
	s, _, _ := consultedStore(t)
	var zero MutationBindingV1
	mbReuse(t, zero, zero, false, "N8 zero")
	mbReuse(t, zero, mbView(t, s), false, "N8 zero versus active")
	if _, ok := zero.AfterOneCommitAttemptV1(); ok {
		t.Fatal("N8 zero successor")
	}
	mbInactive(t, nil, "N8 nil Reader")
	var escaped, copied *Reader
	mustEnvironment(t, s.View(func(r *Reader) error {
		escaped = r
		copied = &Reader{self: r.self, txn: r.txn, dbis: r.dbis, format: r.format, lineageID: r.lineageID, lineageEpoch: r.lineageEpoch, lineageReusable: r.lineageReusable}
		copied.active.Store(true)
		mbInactive(t, copied, "N8 copied Reader")
		return nil
	}))
	mbInactive(t, escaped, "N8 expired View Reader")
	var escapedUpdate *Reader
	_, _, _ = s.Update(func(r *Reader) (Batch, error) {
		escapedUpdate = r
		return Batch{}, errors.New("stop")
	})
	mbInactive(t, escapedUpdate, "N13 expired Update Reader")
	mbEpoch(t, s, 0, "N8 inactive Readers")
}

func TestMutationBindingOverlapV1(t *testing.T) {
	s, _, _ := consultedStore(t)
	before := mbView(t, s)
	mustEnvironment(t, s.View(func(*Reader) error {
		truth, stage, err := s.Update(func(*Reader) (Batch, error) { return Batch{}, nil })
		if truth != CommitTruthOld || stage != UpdateStagePrewrite {
			t.Fatalf("N13 overlapping Update: %s/%d", truth, stage)
		}
		requireEnvironmentError(t, err, EngineConcurrency, operationUpdate, codeBusy, "store operation in progress")
		requireEnvironmentError(t, s.View(func(*Reader) error { return nil }), EngineConcurrency, operationView, codeBusy, "store operation in progress")
		mustEnvironment(t, reservationOwner(t, 805_306_368).WithOperation(TreeOperation, func(a *OperationAccount) error {
			r := tsInvoke(s, a, func(*Reader) (TreeOperationV1, error) { return TreeOperationV1{}, nil })
			r.tuple(t, CommitTruthOld, UpdateStagePrewrite, -1)
			requireEnvironmentError(t, r.err, EngineConcurrency, operationUpdate, codeBusy, "store operation in progress")
			return nil
		}))
		return nil
	}))
	mbEpoch(t, s, 0, "N13 denied overlap")
	mbReuse(t, mbView(t, s), before, true, "N13 binding after overlap")
}
