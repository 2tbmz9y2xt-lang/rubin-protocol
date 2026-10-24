//go:build cgo && (darwin || linux) && (amd64 || arm64) && rubin_mdbx_fixture

package mdbx

import (
	"errors"
	"fmt"
	"runtime"
	"testing"
)

// mbArmedUpdate runs one counter Update under scenario and returns the public tuple and native evidence.
func mbArmedUpdate(t *testing.T, s *Store, scenario SelectedDamageScenario) (CommitTruth, UpdateStage, error, SelectedDamageEvidence) {
	t.Helper()
	encoded, encodeErr := modelBase(1, 0, 0).Encode()
	mustEnvironment(t, encodeErr)
	row := Mutation{DBI: readDBIsLiteral()[0], Key: []byte{2}, AfterKind: AfterLiteral, Literal: encoded}
	var truth CommitTruth
	var stage UpdateStage
	var err error
	evidence, armErr := FixtureSelectedDamage(s, bootstrapOwner(t), scenario, 0, row.Key, func() {
		truth, stage, err = s.Update(func(*Reader) (Batch, error) { return Batch{Mutations: []Mutation{row}}, nil })
	})
	mustEnvironment(t, armErr)
	return truth, stage, err, evidence
}

func TestMutationBindingCrossedUpdateV1(t *testing.T) {
	for _, row := range []struct {
		scenario SelectedDamageScenario
		truth    CommitTruth
	}{
		{SelectedDamageCommitOld, CommitTruthOld},
		{SelectedDamageCommitNew, CommitTruthNew},
		{SelectedDamageCommitUnreadable, CommitTruthUnknown},
		{SelectedDamageCommitThird, CommitTruthUnknown},
	} {
		t.Run(fmt.Sprint(row.scenario), func(t *testing.T) {
			s, _, _ := consultedStore(t)
			mbEpoch(t, s, 0, "N10 construction")
			truth, stage, err, evidence := mbArmedUpdate(t, s, row.scenario)
			if truth != row.truth || stage != UpdateStageCommitMayHaveCrossed || err == nil || evidence.Commits != 1 {
				t.Fatalf("N10 crossed tuple: %s/%d/%v %+v", truth, stage, err, evidence)
			}
			mbEpoch(t, s, 1, "N10 one attempt")
			if s.state != storeCLOSED || s.terminal != err || s.terminalTruth != row.truth {
				t.Fatalf("N10 consumption: %s %v %s", s.state, s.terminal, s.terminalTruth)
			}
			again, nextStage, next := s.Update(func(*Reader) (Batch, error) { return Batch{}, nil })
			if again != row.truth || nextStage != UpdateStagePrewrite || next != err {
				t.Fatalf("N10 next operation: %s/%d/%v", again, nextStage, next)
			}
			mbEpoch(t, s, 1, "N10 refused next operation")
		})
	}
}

func TestMutationBindingNonAttemptFailureV1(t *testing.T) {
	for _, scenario := range []SelectedDamageScenario{SelectedDamagePutEIO, SelectedDamageWriteBeginTxnFull} {
		t.Run(fmt.Sprint(scenario), func(t *testing.T) {
			s, _, _ := consultedStore(t)
			truth, stage, err, evidence := mbArmedUpdate(t, s, scenario)
			if truth != CommitTruthOld || err == nil || evidence.Commits != 0 || stage == UpdateStageCommitMayHaveCrossed {
				t.Fatalf("N12 definite non-attempt failure: %s/%d/%v %+v", truth, stage, err, evidence)
			}
			mbEpoch(t, s, 0, "N12 definite non-attempt failure")
		})
	}
}

// N11 projects outcomes that differ only in commitAttempted through the single advance site.
func TestMutationBindingAttemptFlagV1(t *testing.T) {
	cause := errors.New("N11 cause")
	for _, stage := range []UpdateStage{UpdateStageWriteStartedDefinitelyPrecommit, UpdateStagePrewrite} {
		for _, attempted := range []bool{false, true} {
			t.Run(fmt.Sprintf("stage%d-attempted%v", stage, attempted), func(t *testing.T) {
				s, _, _ := consultedStore(t)
				outcome := updateNativeConsumed(CommitTruthOld, attempted, cause, nil, stage)
				truth, gotStage, err := s.applyUpdateOutcome(outcome, nil, nil, false)
				if truth != CommitTruthOld || gotStage != stage || !errors.Is(err, cause) {
					t.Fatalf("N11 projection: %s/%d/%v", truth, gotStage, err)
				}
				want := uint64(0)
				if attempted {
					want = 1
				}
				mbEpoch(t, s, want, "N11 definite OLD")
			})
		}
	}
}

func TestMutationBindingCallbackOutcomesV1(t *testing.T) {
	t.Run("panic", func(t *testing.T) {
		s, _, _ := consultedStore(t)
		value := new(int)
		var got any
		func() {
			defer func() { got = recover() }()
			_, _, _ = s.Update(func(*Reader) (Batch, error) { panic(value) })
		}()
		if got != value {
			t.Fatalf("N12 panic identity: %v", got)
		}
		mbEpoch(t, s, 0, "N12 panic")
		mbCommit(t, s, 7, "N12 after panic")
		mbEpoch(t, s, 1, "N12 after panic")
	})
	t.Run("goexit", func(t *testing.T) {
		s, _, _ := consultedStore(t)
		done := make(chan struct{})
		go func() {
			defer close(done)
			_, _, _ = s.Update(func(*Reader) (Batch, error) { runtime.Goexit(); return Batch{}, nil })
		}()
		<-done
		mbEpoch(t, s, 0, "N12 goexit")
		mbCommit(t, s, 7, "N12 after goexit")
		mbEpoch(t, s, 1, "N12 after goexit")
	})
	t.Run("invalid batch then commit", func(t *testing.T) {
		s, _, _ := consultedStore(t)
		truth, stage, err := s.Update(func(*Reader) (Batch, error) { return Batch{}, nil })
		if truth != CommitTruthOld || stage != UpdateStagePrewrite {
			t.Fatalf("N12 invalid empty batch: %s/%d/%v", truth, stage, err)
		}
		requireEnvironmentError(t, err, EngineInvalidInput, operationUpdate, codeEINVAL, "invalid Update Batch")
		mbEpoch(t, s, 0, "N12 invalid batch")
		mbCommit(t, s, 7, "N12 infrastructure success")
		mbEpoch(t, s, 1, "N12 infrastructure success")
	})
}

// mbTreeBindings records the provider Reader bindings at the writer (1) and readback (2) positions.
func mbTreeBindings(t *testing.T, p *tsfProvider, got *[3]MutationBindingV1) {
	p.before = func(pos TreePositionV1, r *Reader, _ *TreeDeltaSinkV1) error {
		binding, err := r.MutationBindingV1()
		if err != nil {
			t.Errorf("provider Reader binding: %v", err)
		}
		got[pos] = binding
		return nil
	}
}

func TestMutationBindingTreeCompoundV1(t *testing.T) {
	for _, crossed := range []bool{false, true} {
		t.Run(fmt.Sprintf("crossed%v", crossed), func(t *testing.T) {
			s := tsfNew(t)
			mbEpoch(t, s.s, 3, "N14 tsfNew setup")
			pre := mbView(t, s.s)
			var got [3]MutationBindingV1
			mbTreeBindings(t, s.p[1], &got)
			var r tsResult
			if crossed {
				r = s.crossed(t)
			} else {
				r = s.run(t)
			}
			r.tuple(t, 2, 3, -1)
			mbEpoch(t, s.s, 4, "N14 one attempt for several primitives")
			mbReuse(t, got[1], pre, true, "N15 writer-position Reader")
			if !crossed {
				mustEnvironment(t, r.err)
				mbReuse(t, mbView(t, s.s), mbSuccessor(t, pre), true, "N14 successor")
				return
			}
			tcCrossedCause(t, r.err, 2, nil)
			mbReuse(t, got[2], pre, true, "N15 readback-position Reader carries the pre-attempt binding")
		})
	}
}

func TestMutationBindingTreeNoAttemptV1(t *testing.T) {
	t.Run("ORIGINAL OLD begin", func(t *testing.T) {
		s, _, _ := treeNativeStore(t)
		o := reservationOwner(t, 805_306_368)
		op := tsOperation(t, tsSource(func(TreePositionV1, *Reader, *TreeDeltaSinkV1) error { return nil }))
		var r tsResult
		evidence, err := FixtureSelectedDamage(s, o, SelectedDamageBeginEIO, 0, []byte{0}, func() {
			_ = o.WithOperation(TreeOperation, func(a *OperationAccount) error {
				r = tsInvoke(s, a, func(*Reader) (TreeOperationV1, error) { return op, nil })
				return nil
			})
		})
		mustEnvironment(t, err)
		r.tuple(t, 1, 1, -1)
		if evidence.BeginOld != 1 || evidence.Commits != 0 {
			t.Fatalf("N15 begin evidence %+v", evidence)
		}
		mbEpoch(t, s, 0, "N15 ORIGINAL OLD begin failure")
	})
	t.Run("write begin", func(t *testing.T) {
		s := tsfNew(t)
		before := s.s.lineageEpoch
		var r tsResult
		evidence, err := FixtureSelectedDamage(s.s, s.o, SelectedDamageWriteBeginTxnFull, 0, []byte{0}, func() { r = s.run(t) })
		mustEnvironment(t, err)
		if r.err == nil || r.stage == UpdateStageCommitMayHaveCrossed || evidence.Commits != 0 {
			t.Fatalf("N15 write begin %+v %+v", r, evidence)
		}
		mbEpoch(t, s.s, before, "N15 write-begin failure")
	})
	t.Run("source drift", func(t *testing.T) {
		s := tsfNew(t)
		before := s.s.lineageEpoch
		var r tsResult
		count, err := FixtureWriteSnapshotDrift(s.s, 4, append([]byte(nil), s.op.Primitives[2].Block[:]...), func() { r = s.run(t) })
		mustEnvironment(t, err)
		if count != 1 {
			t.Fatal("N15 drift site not reached")
		}
		r.tuple(t, 1, 2, 2)
		mbEpoch(t, s.s, before, "N15 source drift")
	})
	t.Run("source error", func(t *testing.T) {
		s := tsfNew(t)
		before := s.s.lineageEpoch
		marker := errors.New("N15 source")
		s.p[1].before = func(pos TreePositionV1, _ *Reader, _ *TreeDeltaSinkV1) error { return marker }
		r := s.run(t)
		if !errors.Is(r.err, marker) || r.stage == UpdateStageCommitMayHaveCrossed {
			t.Fatalf("N15 source error %+v", r)
		}
		mbEpoch(t, s.s, before, "N15 source error")
	})
}

func TestMutationBindingTreeUnwindV1(t *testing.T) {
	for _, variant := range []string{"clean", "sink"} {
		t.Run("writer panic "+variant, func(t *testing.T) {
			s := tsfNew(t)
			before := s.s.lineageEpoch
			value := new(int)
			s.p[1].before = func(pos TreePositionV1, _ *Reader, sink *TreeDeltaSinkV1) error {
				if variant == "sink" {
					_ = sink.BeginV1(TreeBlockV1{TxCount: 1, EventCount: 1})
				}
				panic(value)
			}
			var got any
			func() { defer func() { got = recover() }(); s.run(t) }()
			if got != value {
				t.Fatalf("N16 writer panic identity %v", got)
			}
			mbEpoch(t, s.s, before, "N16 writer-position panic")
		})
	}
	t.Run("writer goexit", func(t *testing.T) {
		s := tsfNew(t)
		before := s.s.lineageEpoch
		s.p[1].before = func(TreePositionV1, *Reader, *TreeDeltaSinkV1) error { runtime.Goexit(); return nil }
		done := make(chan struct{})
		go func() {
			defer close(done)
			_ = s.o.WithOperation(TreeOperation, func(a *OperationAccount) error {
				_ = tsInvoke(s.s, a, func(*Reader) (TreeOperationV1, error) { return s.op, nil })
				return nil
			})
		}()
		<-done
		mbEpoch(t, s.s, before, "N16 writer-position goexit")
	})
	t.Run("readback panic after crossed commit", func(t *testing.T) {
		s := tsfNew(t)
		before := s.s.lineageEpoch
		value := new(int)
		s.p[1].before = func(pos TreePositionV1, _ *Reader, _ *TreeDeltaSinkV1) error {
			if pos == 2 {
				panic(value)
			}
			return nil
		}
		var got any
		func() { defer func() { got = recover() }(); s.crossed(t) }()
		if got != value {
			t.Fatalf("N16 readback panic identity %v", got)
		}
		mbEpoch(t, s.s, before+1, "N16 readback-position unwind")
	})
	t.Run("readback error", func(t *testing.T) {
		s := tsfNew(t)
		before := s.s.lineageEpoch
		marker := errors.New("N15 readback provider")
		s.p[1].before = func(pos TreePositionV1, _ *Reader, _ *TreeDeltaSinkV1) error {
			if pos == 2 {
				return marker
			}
			return nil
		}
		r := s.crossed(t)
		if r.stage != UpdateStageCommitMayHaveCrossed || r.err == nil {
			t.Fatalf("N15 readback error %+v", r)
		}
		mbEpoch(t, s.s, before+1, "N15 readback result")
	})
}

// N12 retained cleanup failure: the existing wrong-thread lifecycle fixture with a retained OLD cleanup, crossed
// with and without a real native attempt; the epoch follows commitAttempted only.
func TestMutationBindingRetainedCleanupV1(t *testing.T) {
	for _, attempted := range []bool{false, true} {
		t.Run(fmt.Sprintf("attempted%v", attempted), func(t *testing.T) {
			s := newUpdateStore(t)
			native, release, err := fixtureUpdateWrongThread(s)
			mustEnvironment(t, err)
			defer func() { _ = release() }()
			token := updateRetained(native)
			cleanup := nativeError(operationAbort, codeThreadMismatch)
			native = updateNativeRetainedWrite(false, nativeError(operationUpdate, codeENOSPC), nil, token, UpdateStagePrewrite)
			if attempted {
				native = updateNativeConsumed(CommitTruthNew, true, nil, nil, UpdateStageCommitMayHaveCrossed)
			}
			before := s.lineageEpoch
			truth, stage, terminal := s.applyUpdateOutcome(native, token, cleanup, attempted)
			if truth != native.truth || stage != native.stage || terminal == nil || s.state != storePOISONEDTHREAD || s.txn != token {
				t.Fatalf("N12 retained cleanup projection: %s/%d/%v %s", truth, stage, terminal, s.state)
			}
			want := before
			if attempted {
				want++
			}
			mbEpoch(t, s, want, "N12 retained cleanup failure")
		})
	}
}

// mbTcWriterUnwind arms the writer-position provider of the tcNew scene with the existing tcFail variant and unwind.
func mbTcWriterUnwind(t *testing.T, s *tcScene, variant string, goexit bool, v *int) {
	f := treeIntegrity(operationGet, nil)
	s.prims[1].custom = func(old *Reader, rec *treeRecorderV1) error {
		if variant != "sink" {
			mustEnvironment(t, s.prims[1].stream(rec))
		}
		tcFail(t, variant, f, old, rec)
		if goexit {
			runtime.Goexit()
		}
		panic(v)
	}
}

// mbTcUnwindPath pins which projection the unwind took: clean -> treeUnwoundV1 (nil primary, OPEN); recorded and
// sink -> applyUpdateOutcome with a non-nil primary and commitAttempted=false (CLOSED), per updateTreeLockedV1.
func mbTcUnwindPath(t *testing.T, s *tcScene, r tcResult, variant string, before uint64) {
	t.Helper()
	if r.unwind.kind == 0 || r.stage != UpdateStageWriteStartedDefinitelyPrecommit {
		t.Errorf("N16 %s: unwind %d stage %d", variant, r.unwind.kind, r.stage)
	}
	clean := variant == "clean"
	if clean != (r.err == nil) || clean != (s.store.state == storeOPEN) || !clean && s.store.state != storeCLOSED {
		t.Errorf("N16 %s path: err %v state %s", variant, r.err, s.store.state)
	}
	if s.store.lineageEpoch != before {
		t.Errorf("N16 %s writer-position unwind: epoch=%d, want %d", variant, s.store.lineageEpoch, before)
	}
}

func TestMutationBindingTreeComposeUnwindV1(t *testing.T) {
	for _, variant := range []string{"clean", "recorded", "sink"} {
		t.Run("panic "+variant, func(t *testing.T) {
			s := tcNew(t, 3)
			before := s.store.lineageEpoch
			v := new(int)
			mbTcWriterUnwind(t, s, variant, false, v)
			var r tcResult
			func() { defer func() { _ = recover() }(); r = s.run(nil) }()
			mbTcUnwindPath(t, s, r, variant, before)
			func() {
				defer func() {
					if got := recover(); got != v {
						t.Fatalf("N16 resumed %v", got)
					}
				}()
				r.unwind.resumeV1()
			}()
			s.settled(t)
		})
		t.Run("goexit "+variant, func(t *testing.T) {
			s := tcNew(t, 3)
			before := s.store.lineageEpoch
			mbTcWriterUnwind(t, s, variant, true, nil)
			s.goexitRun(t, func(r tcResult) { mbTcUnwindPath(t, s, r, variant, before) })
			s.settled(t)
		})
	}
}
