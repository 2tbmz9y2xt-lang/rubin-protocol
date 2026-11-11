//go:build cgo && (darwin || linux) && (amd64 || arm64)

package consensus

import (
	"errors"
	"math"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/mdbx"
)

type retainedCapacitySourceV1 struct{}

func (retainedCapacitySourceV1) TreeDeltaV1(mdbx.TreePositionV1, *mdbx.Reader, *mdbx.TreeDeltaSinkV1) error {
	return nil
}

// retainedCapacityStructuralV1 installs D1 report-domain inputs on an owned
// prepared attempt: CURRENT S56,N1,J2 plus E 625 (LAG 32, headers 296,
// bodies 241, undo 56) gives pre 1005; E adds header 148 and body 122.
func retainedCapacityStructuralV1(a *RetainedAccountingV1) *DirectRetainedProofV1 {
	p := &DirectRetainedProofV1{}
	*p = DirectRetainedProofV1{owner: a, self: p, prepared: true, pre: 1005, add: 148 + 122}
	p.roles[0] = retainedRoleV1{generation: 1, s: 56, n: 1, j: 2}
	p.binding, _ = (&mdbx.Reader{}).MutationBindingV1()
	a.active = p
	return p
}

func retainedCapacityReportV1() *mdbx.TreeDeltaReportV1 {
	return &mdbx.TreeDeltaReportV1{
		Current: mdbx.TreeRoleDeltaV1{Present: true, Generation: 1, BytesBefore: 56, CountBefore: 1, BytesAfter: 112, CountAfter: 2, IndexAdded: 1},
		Undo:    []mdbx.TreeUndoChargeV1{{}},
	}
}

func TestRetainedCapacityMDBX(t *testing.T) {
	t.Run("D1_D25_structural_post_and_R_boundary", func(t *testing.T) {
		for _, tc := range []struct {
			lRet uint64
			ok   bool
		}{{1073743437, true}, {1073743436, false}} {
			a := NewRetainedAccountingV1(NewLimitsV1(1073741824, tc.lRet))
			p := retainedCapacityStructuralV1(a)
			err := p.Proof(retainedCapacityReportV1())
			if (err == nil) != tc.ok || p.accepted != tc.ok {
				t.Fatalf("lRet %d: err=%v accepted=%v", tc.lRet, err, p.accepted)
			}
			if tc.ok && p.post != 1613 {
				t.Fatalf("post=%d want 1613", p.post)
			}
			var failure *RetainedProofFailureV1
			if !tc.ok && (!errors.As(err, &failure) || failure.Resource != "storage_capacity") {
				t.Fatalf("one-below refusal=%v", err)
			}
		}
	})
	t.Run("D4_LRet_below_R_and_maximal_R", func(t *testing.T) {
		for _, limits := range []LimitsV1{NewLimitsV1(10, 5), NewLimitsV1(math.MaxUint64, math.MaxUint64)} {
			p := retainedCapacityStructuralV1(NewRetainedAccountingV1(limits))
			if err := p.Proof(retainedCapacityReportV1()); !errors.Is(err, errRetainedProofCapacity) || p.accepted {
				t.Fatalf("limits %v: %v", limits, err)
			}
		}
	})
	t.Run("D25_report_shapes", retainedCapacityReportShapesV1)
	t.Run("D25_undo_effects", retainedCapacityUndoEffectsV1)
	t.Run("D8_initial_controls", retainedCapacityInitialControlsV1)
	t.Run("D8_op_only_refusals_keep_token", retainedCapacityOpOnlyV1)
	t.Run("D14_D18_apply_matrix", retainedCapacityApplyMatrixV1)
}

func retainedCapacityReportShapesV1(t *testing.T) {
	mutate := []func(*mdbx.TreeDeltaReportV1){
		func(r *mdbx.TreeDeltaReportV1) { r.Lag.Present = true },
		func(r *mdbx.TreeDeltaReportV1) { r.Lag.BytesAfter = 1 },
		func(r *mdbx.TreeDeltaReportV1) { r.Lag.Generation = 2 },
		func(r *mdbx.TreeDeltaReportV1) { r.Undo = nil },
		func(r *mdbx.TreeDeltaReportV1) { r.Undo = append(r.Undo, mdbx.TreeUndoChargeV1{}) },
		func(r *mdbx.TreeDeltaReportV1) { r.Current.Present = false },
		func(r *mdbx.TreeDeltaReportV1) { r.Current.Generation = 2 },
		func(r *mdbx.TreeDeltaReportV1) { r.Current.BytesBefore = 57 },
		func(r *mdbx.TreeDeltaReportV1) { r.Current.CountBefore = 2 },
		func(r *mdbx.TreeDeltaReportV1) { r.Undo[0] = mdbx.TreeUndoChargeV1{Effect: 4} },
		func(r *mdbx.TreeDeltaReportV1) { r.Undo[0] = mdbx.TreeUndoChargeV1{Bytes: 1} },
		func(r *mdbx.TreeDeltaReportV1) { r.Undo[0] = mdbx.TreeUndoChargeV1{Effect: 1, Bytes: 56} },
		func(r *mdbx.TreeDeltaReportV1) { r.Undo[0] = mdbx.TreeUndoChargeV1{Effect: 1, Entries: 1, Bytes: 55} },
		func(r *mdbx.TreeDeltaReportV1) {
			r.Undo[0] = mdbx.TreeUndoChargeV1{Effect: 2, Entries: 1, Bytes: 65597}
		},
		func(r *mdbx.TreeDeltaReportV1) {
			r.Undo[0] = mdbx.TreeUndoChargeV1{Effect: 3, Entries: 414635, Bytes: 56 * 414635}
		},
	}
	for i, m := range mutate {
		p := retainedCapacityStructuralV1(NewRetainedAccountingV1(NewLimitsV1(0, math.MaxUint64)))
		r := retainedCapacityReportV1()
		m(r)
		if err := p.Proof(r); !errors.Is(err, errRetainedReportAPIV1) || p.accepted || !p.entered {
			t.Fatalf("shape %d: %v accepted=%v", i, err, p.accepted)
		}
	}
	p := retainedCapacityStructuralV1(NewRetainedAccountingV1(NewLimitsV1(0, math.MaxUint64)))
	if err := p.Proof(nil); !errors.Is(err, errRetainedReportAPIV1) {
		t.Fatalf("nil report: %v", err)
	}
	if err := p.Proof(retainedCapacityReportV1()); !errors.Is(err, errRetainedProofAPIV1) {
		t.Fatalf("second entry: %v", err)
	}
	unprepared := retainedCapacityStructuralV1(NewRetainedAccountingV1(NewLimitsV1(0, math.MaxUint64)))
	unprepared.prepared = false
	if err := unprepared.Proof(retainedCapacityReportV1()); !errors.Is(err, errRetainedProofAPIV1) || unprepared.entered {
		t.Fatalf("unprepared: %v", err)
	}
	copied := *retainedCapacityStructuralV1(NewRetainedAccountingV1(NewLimitsV1(0, math.MaxUint64)))
	if err := copied.Proof(retainedCapacityReportV1()); !errors.Is(err, errRetainedProofAPIV1) {
		t.Fatalf("copied: %v", err)
	}
}

func retainedCapacityUndoEffectsV1(t *testing.T) {
	for _, tc := range []struct {
		name              string
		oldOwned, postOwn bool
		oldCharge         uint64
		undo              mdbx.TreeUndoChargeV1
		want              uint64
	}{
		{"none_acquire", false, true, 80, mdbx.TreeUndoChargeV1{}, 1613 + 80},
		{"none_release", true, false, 80, mdbx.TreeUndoChargeV1{}, 1613 - 80},
		{"none_keep", true, true, 80, mdbx.TreeUndoChargeV1{}, 1613},
		{"written", false, true, 0, mdbx.TreeUndoChargeV1{Effect: 1, Entries: 1, Bytes: 89}, 1613 + 89},
		{"kept_once", true, true, 89, mdbx.TreeUndoChargeV1{Effect: 2, Entries: 1, Bytes: 89}, 1613},
		{"deleted", true, true, 89, mdbx.TreeUndoChargeV1{Effect: 3, Entries: 1, Bytes: 89}, 1613 - 89},
	} {
		p := retainedCapacityStructuralV1(NewRetainedAccountingV1(NewLimitsV1(0, math.MaxUint64)))
		p.undo = retainedUndoProjectionV1{oldCharge: tc.oldCharge, oldOwned: tc.oldOwned, postOwned: tc.postOwn}
		r := retainedCapacityReportV1()
		r.Undo[0] = tc.undo
		if err := p.Proof(r); err != nil || p.post != tc.want {
			t.Fatalf("%s: err=%v post=%d want %d", tc.name, err, p.post, tc.want)
		}
	}
	p := retainedCapacityStructuralV1(NewRetainedAccountingV1(NewLimitsV1(0, math.MaxUint64)))
	p.remove = p.pre
	if err := p.Proof(retainedCapacityReportV1()); !errors.Is(err, errRetainedProofCapacity) {
		t.Fatalf("underflow: %v", err)
	}
	p = retainedCapacityStructuralV1(NewRetainedAccountingV1(NewLimitsV1(0, math.MaxUint64)))
	p.add = math.MaxUint64
	if err := p.Proof(retainedCapacityReportV1()); !errors.Is(err, errRetainedProofCapacity) {
		t.Fatalf("overflow: %v", err)
	}
}

func retainedCapacityDirectOpV1() *mdbx.TreeOperationV1 {
	block := [32]byte{7}
	return &mdbx.TreeOperationV1{Primitives: []mdbx.TreePrimitiveV1{{
		Direction: mdbx.TreeForwardV1, Kind: mdbx.TreeKindDirectApplyV1, Generation: 1, Block: block, Undo: mdbx.UndoWriteOrReuseV1,
		Source:   retainedCapacitySourceV1{},
		Coverage: &mdbx.TreeSourceCoverageV1{Generation: 1, Block: block, HeaderBytes: 148, BodyKind: 2},
	}}}
}

func retainedCapacityCachedV1() *RetainedAccountingV1 {
	a := NewRetainedAccountingV1(DefaultLimitsV1())
	a.exactRet, a.valid, a.complete = 77, true, [2]retainedCompleteV1{{1, true}, {2, false}}
	return a
}

func retainedCapacityInitialControlsV1(t *testing.T) {
	reader, account := &mdbx.Reader{}, &mdbx.OperationAccount{}
	lag := func(op *mdbx.TreeOperationV1) { op.Primitives[0].Kind = mdbx.TreeKindLagForwardV1 }
	companion := func(op *mdbx.TreeOperationV1) {
		op.Primitives = append(op.Primitives, op.Primitives[0])
		op.Primitives[1].Kind, op.Primitives[1].Generation = mdbx.TreeKindLagForwardV1, 2
	}
	reverse := func(op *mdbx.TreeOperationV1) {
		companion(op)
		op.Primitives[1].Kind = mdbx.TreeKindLagReverseV1
	}
	zero := func(op *mdbx.TreeOperationV1) { op.Primitives = nil }
	proof := func(op *mdbx.TreeOperationV1) { op.Proof = func(*mdbx.TreeDeltaReportV1) error { return nil } }
	inventory := func(op *mdbx.TreeOperationV1) { op.Pair.EntryInventory = &mdbx.EntryInventoryV1{} }
	for i, m := range []func(*mdbx.TreeOperationV1){lag, companion, reverse, zero, proof, inventory} {
		a, op, dst := retainedCapacityCachedV1(), retainedCapacityDirectOpV1(), &DirectRetainedProofV1{}
		m(op)
		before := *a
		if err := a.PlanDirectMDBX(dst, reader, account, op); !errors.Is(err, errRetainedPlanAPIV1) {
			t.Fatalf("control %d: %v", i, err)
		}
		if *a != before || *dst != (DirectRetainedProofV1{}) {
			t.Fatalf("control %d changed owner or token", i)
		}
		if err := a.ApplyDirectMDBX(dst, mdbx.CommitTruthOld, mdbx.UpdateStagePrewrite, -1, errors.New("refused"), true); !errors.Is(err, errRetainedApplyAPIV1) || a.valid {
			t.Fatalf("control %d apply: %v valid=%v", i, err, a.valid)
		}
	}
	a, op := retainedCapacityCachedV1(), retainedCapacityDirectOpV1()
	for i, call := range []func() error{
		func() error { return a.PlanDirectMDBX(nil, reader, account, op) },
		func() error { return a.PlanDirectMDBX(&DirectRetainedProofV1{}, nil, account, op) },
		func() error { return a.PlanDirectMDBX(&DirectRetainedProofV1{}, reader, nil, op) },
		func() error { return a.PlanDirectMDBX(&DirectRetainedProofV1{}, reader, account, nil) },
		func() error { return a.PlanDirectMDBX(&DirectRetainedProofV1{applied: true}, reader, account, op) },
		func() error {
			return (*RetainedAccountingV1)(nil).PlanDirectMDBX(&DirectRetainedProofV1{}, reader, account, op)
		},
	} {
		if err := call(); !errors.Is(err, errRetainedPlanAPIV1) || !a.valid || a.active != nil {
			t.Fatalf("nil control %d: %v", i, err)
		}
	}
	active := &DirectRetainedProofV1{}
	a.active = active
	if err := a.PlanDirectMDBX(&DirectRetainedProofV1{}, reader, account, op); !errors.Is(err, errRetainedPlanAPIV1) || a.active != active {
		t.Fatalf("active owner: %v", err)
	}
}

func retainedCapacityOpOnlyV1(t *testing.T) {
	reader, account := &mdbx.Reader{}, &mdbx.OperationAccount{}
	for i, m := range []func(*mdbx.TreeOperationV1){
		func(op *mdbx.TreeOperationV1) { op.Primitives[0].Source = nil },
		func(op *mdbx.TreeOperationV1) { op.Primitives[0].Coverage = nil },
		func(op *mdbx.TreeOperationV1) { op.Primitives[0].Kind = mdbx.TreeKindConnectV1 },
		func(op *mdbx.TreeOperationV1) { op.Primitives[0].Coverage.HeaderBytes = 116 },
		func(op *mdbx.TreeOperationV1) { op.Primitives[0].Coverage.CurrentBody = []byte{1} },
		func(op *mdbx.TreeOperationV1) { op.Primitives[0].Coverage.BodyKind = 3 },
		func(op *mdbx.TreeOperationV1) { op.HeaderSlot = &mdbx.TreeHeaderSlotV1{Hash: [32]byte{8}} },
		func(op *mdbx.TreeOperationV1) {
			op.HeaderSlot = &mdbx.TreeHeaderSlotV1{Hash: op.Primitives[0].Block}
			op.Primitives[0].Coverage.Block = [32]byte{9}
		},
		func(op *mdbx.TreeOperationV1) {
			op.HeaderSlot = &mdbx.TreeHeaderSlotV1{Hash: op.Primitives[0].Block}
			op.Primitives[0].Coverage.BodyKind, op.Primitives[0].Coverage.CurrentBody = 1, []byte{1}
		},
	} {
		a, op, dst := retainedCapacityCachedV1(), retainedCapacityDirectOpV1(), &DirectRetainedProofV1{}
		m(op)
		if err := a.PlanDirectMDBX(dst, reader, account, op); !errors.Is(err, errRetainedShapeAPIV1) {
			t.Fatalf("op-only %d: %v", i, err)
		}
		if a.active != dst || dst.self != dst || dst.prepared || !a.valid {
			t.Fatalf("op-only %d lost the active token", i)
		}
		if err := dst.Proof(retainedCapacityReportV1()); !errors.Is(err, errRetainedProofAPIV1) {
			t.Fatalf("op-only %d proof: %v", i, err)
		}
	}
}

func retainedCapacityApplyMatrixV1(t *testing.T) {
	boom := errors.New("native")
	accepted := func(a *RetainedAccountingV1) *DirectRetainedProofV1 {
		p := retainedCapacityStructuralV1(a)
		if err := p.Proof(retainedCapacityReportV1()); err != nil {
			t.Fatal(err)
		}
		return p
	}
	for i, tc := range []struct {
		truth     mdbx.CommitTruth
		stage     mdbx.UpdateStage
		index     int
		err       error
		clean     bool
		wantErr   error
		wantValid bool
	}{
		{mdbx.CommitTruthNew, mdbx.UpdateStageCommitMayHaveCrossed, -1, boom, false, nil, false},
		{mdbx.CommitTruthNew, mdbx.UpdateStageCommitMayHaveCrossed, 0, nil, false, errRetainedApplyAPIV1, false},
		{mdbx.CommitTruthOld, mdbx.UpdateStagePrewrite, -1, nil, false, errRetainedApplyAPIV1, false},
		{mdbx.CommitTruthUnknown, mdbx.UpdateStageCommitMayHaveCrossed, -1, boom, false, nil, false},
		{mdbx.CommitTruthOld, mdbx.UpdateStagePrewrite, -1, boom, true, nil, false},
		{0, mdbx.UpdateStagePrewrite, -1, boom, false, errRetainedApplyAPIV1, false},
		{mdbx.CommitTruthOld, 0, -1, boom, false, errRetainedApplyAPIV1, false},
		{mdbx.CommitTruthOld, mdbx.UpdateStagePrewrite, 1, boom, false, errRetainedApplyAPIV1, false},
		{mdbx.CommitTruthOld, mdbx.UpdateStagePrewrite, -2, boom, false, errRetainedApplyAPIV1, false},
	} {
		a := retainedCapacityCachedV1()
		p := accepted(a)
		if err := a.ApplyDirectMDBX(p, tc.truth, tc.stage, tc.index, tc.err, tc.clean); !errors.Is(err, tc.wantErr) || a.valid != tc.wantValid {
			t.Fatalf("row %d: err=%v valid=%v", i, err, a.valid)
		}
	}
	// A non-reusable binding never yields a cached successor.
	a := retainedCapacityCachedV1()
	p := accepted(a)
	if err := a.ApplyDirectMDBX(p, mdbx.CommitTruthNew, mdbx.UpdateStageCommitMayHaveCrossed, -1, nil, false); err != nil || a.valid || a.active != nil {
		t.Fatalf("non-reusable success: %v valid=%v", err, a.valid)
	}
	if err := a.ApplyDirectMDBX(p, mdbx.CommitTruthNew, mdbx.UpdateStageCommitMayHaveCrossed, -1, nil, false); !errors.Is(err, errRetainedApplyAPIV1) {
		t.Fatalf("used token: %v", err)
	}
	// An unprepared refused attempt is consumed; a clean refusal keeps a matching completed pre.
	a = retainedCapacityCachedV1()
	dst := &DirectRetainedProofV1{}
	op := retainedCapacityDirectOpV1()
	op.Primitives[0].Source = nil
	_ = a.PlanDirectMDBX(dst, &mdbx.Reader{}, &mdbx.OperationAccount{}, op)
	if err := a.ApplyDirectMDBX(dst, mdbx.CommitTruthOld, mdbx.UpdateStagePrewrite, -1, boom, true); err != nil || a.active != nil || !dst.applied {
		t.Fatalf("unprepared apply: %v", err)
	}
}

// retainedCapacityPlanV1 runs one Plan inside an actual operation account and
// View Reader; budget is the extra grant the caller holds around Plan.
func retainedCapacityPlanV1(t *testing.T, w *btWorld, a *RetainedAccountingV1, dst *DirectRetainedProofV1, op *mdbx.TreeOperationV1, budget uint64) error {
	t.Helper()
	var result error
	err := w.owner.WithOperation(mdbx.TreeOperation, func(account *mdbx.OperationAccount) error {
		return account.WithReservation(budget, func() error {
			return w.s.View(func(reader *mdbx.Reader) error {
				result = a.PlanDirectMDBX(dst, reader, account, op)
				return nil
			})
		})
	})
	logicalMDBXAssert(t, err == nil, "plan account owner: %v", err)
	btReservationsReleased(t, w.owner)
	return result
}

// retainedCapacityBoundOpV1 binds the direct op to the fixture's actual
// CURRENT role through the producer: origin DatabaseID and next height j.
func retainedCapacityBoundOpV1(t *testing.T, w *btWorld) *mdbx.TreeOperationV1 {
	t.Helper()
	op := retainedCapacityDirectOpV1()
	err := w.owner.WithOperation(mdbx.TreeOperation, func(account *mdbx.OperationAccount) error {
		return account.WithReservation(retainedPlanFrameV1, func() error {
			return w.s.View(func(reader *mdbx.Reader) error {
				var read retainedReadV1
				if err := prepareRetainedReadV1(&read, reader, account, nil); err != nil {
					return err
				}
				if err := readRetainedRolesV1(&read); err != nil {
					return err
				}
				op.Primitives[0].Coverage.DatabaseID, op.Primitives[0].Height = read.origin.database, read.roles[0].j
				op.Primitives[0].Coverage.Height = read.roles[0].j
				return nil
			})
		})
	})
	logicalMDBXAssert(t, err == nil, "bind op: %v", err)
	return op
}

func TestRetainedCapacityMDBXPlanPre(t *testing.T) {
	w, _, _ := riGenesis(t)
	cold, err := riRead(t, w, nil)
	logicalMDBXAssert(t, err == nil && cold.exactRet != 0, "cold reference: %v", err)
	a := NewRetainedAccountingV1(DefaultLimitsV1())
	run := func() *DirectRetainedProofV1 {
		dst := &DirectRetainedProofV1{}
		if err := retainedCapacityPlanV1(t, w, a, dst, retainedCapacityBoundOpV1(t, w), 8192); !errors.Is(err, errRetainedPendingV1) {
			t.Fatalf("plan: %v", err)
		}
		if a.active != dst || dst.prepared || dst.entered {
			t.Fatalf("refused plan lost its active unprepared token")
		}
		if err := a.ApplyDirectMDBX(dst, mdbx.CommitTruthOld, mdbx.UpdateStagePrewrite, -1, errRetainedPendingV1, true); err != nil {
			t.Fatalf("clean refusal apply: %v", err)
		}
		return dst
	}
	first := run()
	if first.undo.block != first.op.Primitives[0].Block || first.undo.oldCharge != 0 {
		t.Fatalf("absent OLD family projection: %+v", first.undo)
	}
	if first.pre != cold.exactRet || !a.valid || a.exactRet != cold.exactRet || first.roles[0].generation == 0 {
		t.Fatalf("cold pre %d cache %d/%v want %d", first.pre, a.exactRet, a.valid, cold.exactRet)
	}
	// D3: a matching binding reuses the cached quantity with fresh roles and no cold visit.
	a.exactRet = cold.exactRet + 7
	if warm := run(); warm.pre != cold.exactRet+7 || warm.roles != first.roles {
		t.Fatalf("warm pre %d roles %v", warm.pre, warm.roles)
	}
	// A cache under another binding is never reused.
	a.binding = mdbx.MutationBindingV1{}
	if again := run(); again.pre != cold.exactRet || a.exactRet != cold.exactRet {
		t.Fatalf("nonmatching binding reused cache: %d", again.pre)
	}
}

func TestRetainedCapacityMDBXPlanOrder(t *testing.T) {
	w, _, _ := riGenesis(t)
	denied := uint64(402653184 - retainedPlanFrameV1 + 1)
	// D8/T1: the op-only refusal precedes the temporary frame; the frame itself is cost-1 denied.
	a, dst, op := NewRetainedAccountingV1(DefaultLimitsV1()), &DirectRetainedProofV1{}, retainedCapacityDirectOpV1()
	op.Primitives[0].Source = nil
	if err := retainedCapacityPlanV1(t, w, a, dst, op, denied); !errors.Is(err, errRetainedShapeAPIV1) || a.valid || a.active != dst {
		t.Fatalf("op-only under denied frame: %v", err)
	}
	a, dst = NewRetainedAccountingV1(DefaultLimitsV1()), &DirectRetainedProofV1{}
	err := retainedCapacityPlanV1(t, w, a, dst, retainedCapacityDirectOpV1(), denied)
	if !mdbx.IsOperationReservationCapacity(err) || a.valid || dst.pre != 0 || dst.roles != ([2]retainedRoleV1{}) {
		t.Fatalf("denied frame: %v pre=%d", err, dst.pre)
	}
	// Relation refusals run after the initializer and before roles or cold work.
	op = retainedCapacityDirectOpV1()
	op.Primitives[0].Generation, op.Primitives[0].Coverage.Generation = 9, 9
	a, dst = NewRetainedAccountingV1(DefaultLimitsV1()), &DirectRetainedProofV1{}
	if err := retainedCapacityPlanV1(t, w, a, dst, op, 8192); !errors.Is(err, errRetainedShapeAPIV1) || a.valid || dst.roles != ([2]retainedRoleV1{}) || a.active != dst {
		t.Fatalf("relation: %v", err)
	}
	// D8: the role relations run after the cold quantity entry, which stores
	// its completed pre tuple first; the clean witness then preserves it.
	for name, mutate := range map[string]func(*mdbx.TreeOperationV1){
		"database": func(op *mdbx.TreeOperationV1) { op.Primitives[0].Coverage.DatabaseID[0] ^= 1 },
		"height": func(op *mdbx.TreeOperationV1) {
			op.Primitives[0].Height++
			op.Primitives[0].Coverage.Height++
		},
	} {
		a, dst = NewRetainedAccountingV1(DefaultLimitsV1()), &DirectRetainedProofV1{}
		op = retainedCapacityBoundOpV1(t, w)
		mutate(op)
		err := retainedCapacityPlanV1(t, w, a, dst, op, 8192)
		if !errors.Is(err, errRetainedShapeAPIV1) || !a.valid || dst.pre == 0 || dst.roles[0].generation == 0 || a.active != dst || dst.prepared {
			t.Fatalf("%s relation: %v valid=%v pre=%d", name, err, a.valid, dst.pre)
		}
		if err := a.ApplyDirectMDBX(dst, mdbx.CommitTruthOld, mdbx.UpdateStagePrewrite, -1, err, true); err != nil || !a.valid {
			t.Fatalf("%s clean witness lost completed pre: %v", name, err)
		}
	}
}
