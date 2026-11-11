//go:build cgo && (darwin || linux) && (amd64 || arm64)

package consensus

import (
	"crypto/sha3"
	"errors"
	"math"
	"runtime"
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
	// T8: the exact success tuple without this attempt's accepted Proof is the
	// recognized missing/foreign proof row: applied, invalidated, nil.
	a = retainedCapacityCachedV1()
	p = retainedCapacityStructuralV1(a)
	if err := a.ApplyDirectMDBX(p, mdbx.CommitTruthNew, mdbx.UpdateStageCommitMayHaveCrossed, -1, nil, false); err != nil || a.valid || a.active != nil || !p.applied {
		t.Fatalf("missing proof row: %v valid=%v", err, a.valid)
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
	x, parent := retainedCapacityChildV1(t, w)
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
				op.Primitives[0].Block, op.Primitives[0].Coverage.Block = x, x
				op.Primitives[0].Coverage.DatabaseID, op.Primitives[0].Height = read.origin.database, read.roles[0].j
				op.Primitives[0].Coverage.Height = read.roles[0].j
				op.Pair.Mutations = retainedCapacityIndexV1(read.roles[0].generation, read.roles[0].j, x, parent)
				return nil
			})
		})
	})
	logicalMDBXAssert(t, err == nil, "bind op: %v", err)
	return op
}

// retainedCapacityChildV1 is a healthy child of the stored genesis whose
// 298-byte body is stored, unowned, under its identity x (BodyKind 2 source).
func retainedCapacityChildV1(t *testing.T, w *btWorld) ([32]byte, [32]byte) {
	t.Helper()
	genesis := sha3.Sum256(initial148BlockGenesis(t)[:148])
	child := initial148BlockFrame(t, [][]byte{initial148BlockGenesisTx(t)}, func(h *initial148BlockHead) { h.parent = genesis })
	x := sha3.Sum256(child[:148])
	present := false
	err := w.s.View(func(reader *mdbx.Reader) error {
		var err error
		_, present, err = reader.Get(mdbx.TreeSchemaV1DBIs()[4], x[:])
		return err
	})
	logicalMDBXAssert(t, err == nil && ValidateInitial148BlockBodyCommitments(child) == nil, "child body: %v", err)
	if !present {
		w.pair(t, btMutation(4, x[:], child))
	}
	return x, genesis
}

// retainedCapacityIndexV1 is x's planned CURRENT canonical index and owner
// insert, the only Pair source of x's planned canonical identity.
func retainedCapacityIndexV1(g, h uint64, x, parent [32]byte) []mdbx.Mutation {
	index, _ := mdbx.HeightKey(g, h)
	owner, _ := mdbx.CanonicalOwnerKey(g, x)
	height := make([]byte, 8)
	height[7] = byte(h)
	return []mdbx.Mutation{
		{DBI: mdbx.TreeSchemaV1DBIs()[2], Key: index, AfterKind: mdbx.AfterLiteral, Literal: mdbx.ChainValue(x, parent, [40]byte{})},
		{DBI: mdbx.TreeSchemaV1DBIs()[7], Key: owner, AfterKind: mdbx.AfterLiteral, Literal: height},
	}
}

func TestRetainedCapacityMDBXPlanPre(t *testing.T) {
	w, _, _ := riGenesis(t)
	cold, err := riRead(t, w, nil)
	logicalMDBXAssert(t, err == nil && cold.exactRet != 0, "cold reference: %v", err)
	a := NewRetainedAccountingV1(DefaultLimitsV1())
	run := func() *DirectRetainedProofV1 {
		dst := &DirectRetainedProofV1{}
		if err := retainedCapacityPlanV1(t, w, a, dst, retainedCapacityBoundOpV1(t, w), 8192); err != nil {
			t.Fatalf("plan: %v", err)
		}
		// x is unowned before: canonical header +148, its stored 298-byte
		// body becomes canonically owned, family unowned before and owned after.
		if a.active != dst || !dst.prepared || dst.entered || dst.add != 148+298 || dst.remove != 0 || dst.undo.oldOwned || !dst.undo.postOwned {
			t.Fatalf("prepared finite capture: %+v", dst)
		}
		if err := a.ApplyDirectMDBX(dst, mdbx.CommitTruthOld, mdbx.UpdateStagePrewrite, -1, errors.New("callback"), true); err != nil {
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

func TestRetainedCapacityMDBXFinite(t *testing.T) {
	w, _, _ := riGenesis(t)
	plan := func(mutate func(*mdbx.TreeOperationV1)) (*RetainedAccountingV1, *DirectRetainedProofV1, error) {
		a, dst, op := NewRetainedAccountingV1(DefaultLimitsV1()), &DirectRetainedProofV1{}, retainedCapacityBoundOpV1(t, w)
		mutate(op)
		return a, dst, retainedCapacityPlanV1(t, w, a, dst, op, 8192)
	}
	staged := mdbx.Mutation{DBI: mdbx.TreeSchemaV1DBIs()[6], Key: []byte{1}, AfterKind: mdbx.AfterLiteral, Literal: []byte{1}}
	for name, mutate := range map[string]func(*mdbx.TreeOperationV1){
		"no_index_insert": func(op *mdbx.TreeOperationV1) { op.Pair.Mutations = op.Pair.Mutations[1:] },
		"index_names_other": func(op *mdbx.TreeOperationV1) {
			op.Pair.Mutations[0].Literal = mdbx.ChainValue([32]byte{9}, [32]byte{}, [40]byte{})
		},
		"unknown_namespace": func(op *mdbx.TreeOperationV1) { op.Pair.Mutations = append(op.Pair.Mutations, staged) },
		"slot_with_pair_header": func(op *mdbx.TreeOperationV1) {
			x := op.Primitives[0].Block
			op.HeaderSlot = &mdbx.TreeHeaderSlotV1{Hash: x}
			op.Pair.Mutations = append(op.Pair.Mutations, mdbx.Mutation{DBI: mdbx.TreeSchemaV1DBIs()[3], Key: x[:], AfterKind: mdbx.AfterLiteral, Literal: make([]byte, 148)})
		},
		"stored_body_literal": func(op *mdbx.TreeOperationV1) {
			x := op.Primitives[0].Block
			op.Pair.Mutations = append(op.Pair.Mutations, mdbx.Mutation{DBI: mdbx.TreeSchemaV1DBIs()[4], Key: x[:], AfterKind: mdbx.AfterLiteral, Literal: make([]byte, 298)})
		},
	} {
		a, dst, err := plan(mutate)
		if !errors.Is(err, errRetainedFiniteAPIV1) || a.active != dst || dst.prepared || dst.pre == 0 {
			t.Fatalf("%s: %v prepared=%v", name, err, dst.prepared)
		}
	}
	// T5: a fresh nil-slot header insert of an absent x adds the canonical
	// 148 once, not 296; a qualified slot also adds 148 once.
	for name, mutate := range map[string]func(*mdbx.TreeOperationV1){
		"nil_slot_insert": func(op *mdbx.TreeOperationV1) {
			x := op.Primitives[0].Block
			op.Pair.Mutations = append(op.Pair.Mutations, mdbx.Mutation{DBI: mdbx.TreeSchemaV1DBIs()[3], Key: x[:], AfterKind: mdbx.AfterLiteral, Literal: make([]byte, 148)})
		},
		"qualified_slot": func(op *mdbx.TreeOperationV1) {
			op.HeaderSlot = &mdbx.TreeHeaderSlotV1{Hash: op.Primitives[0].Block}
		},
	} {
		_, dst, err := plan(mutate)
		if err != nil || !dst.prepared || dst.add != 148+298 || dst.remove != 0 {
			t.Fatalf("%s: %v add=%d remove=%d", name, err, dst.add, dst.remove)
		}
	}
	// A BodyKind 1 current body literal is owned after at its exact length.
	_, dst, err := plan(func(op *mdbx.TreeOperationV1) {
		c := op.Primitives[0].Coverage
		c.BodyKind, c.CurrentBody = 1, make([]byte, 298)
		x := op.Primitives[0].Block
		op.Pair.Mutations = append(op.Pair.Mutations, mdbx.Mutation{DBI: mdbx.TreeSchemaV1DBIs()[4], Key: x[:], AfterKind: mdbx.AfterLiteral, Literal: c.CurrentBody})
	})
	if err != nil || !dst.prepared || dst.add != 148+298 {
		t.Fatalf("current body: %v add=%d", err, dst.add)
	}
	// The prepared finite capture reduces an actual-shaped report exactly:
	// CURRENT +S56,N+1 (Tree +170 or +68 from N0), J+1, header 148, family.
	_, dst, err = plan(func(*mdbx.TreeOperationV1) {})
	logicalMDBXAssert(t, err == nil && dst.prepared, "plan: %v", err)
	r := dst.roles[0]
	report := &mdbx.TreeDeltaReportV1{
		Current: mdbx.TreeRoleDeltaV1{Present: true, Generation: r.generation, BytesBefore: r.s, CountBefore: r.n, BytesAfter: r.s + 56, CountAfter: r.n + 1, IndexAdded: 1},
		Undo:    []mdbx.TreeUndoChargeV1{{Effect: mdbx.TreeUndoFamilyWrittenV1, Entries: 1, Bytes: 56}},
	}
	oldTree, _ := RetainedTreeChargeV1(r.n)
	newTree, _ := RetainedTreeChargeV1(r.n + 1)
	if err := dst.Proof(report); err != nil || dst.post != dst.pre+56+newTree-oldTree+RetainedIndexChargeV1+148+298+56 {
		t.Fatalf("proof: %v post=%d pre=%d", err, dst.post, dst.pre)
	}
}

// T11: x's planned canonical identity comes from the Pair insert; the OLD
// Reader reports x as not owned, so reading it would lose the planned bits.
func TestRetainedCapacityMDBXPlannedX(t *testing.T) {
	w, _, _ := riGenesis(t)
	op := retainedCapacityBoundOpV1(t, w)
	err := w.s.View(func(reader *mdbx.Reader) error {
		o, err := reader.CanonicalOwnerV1(op.Primitives[0].Generation, op.Primitives[0].Block)
		logicalMDBXAssert(t, err == nil && !o.Owned, "x OLD owner: %v %+v", err, o)
		return nil
	})
	logicalMDBXAssert(t, err == nil, "view: %v", err)
	a, dst := NewRetainedAccountingV1(DefaultLimitsV1()), &DirectRetainedProofV1{}
	if err := retainedCapacityPlanV1(t, w, a, dst, op, 8192); err != nil || !dst.undo.postOwned || dst.undo.oldOwned || dst.add != 148+298 {
		t.Fatalf("planned x: %v %+v add=%d", err, dst.undo, dst.add)
	}
}

// T12: the exchange restores OLD on return, error, panic and Goexit.
func TestRetainedCapacityMDBXExchange(t *testing.T) {
	var read retainedReadV1
	read.authority.Authority.U = 1
	f := retainedFiniteV1{read: &read}
	f.planned.Authority.U = 2
	inside := uint64(0)
	use := func() error { inside = read.authority.Authority.U; return errRetainedFiniteAPIV1 }
	if err := f.exchangeV1(use); err != errRetainedFiniteAPIV1 || inside != 2 || read.authority.Authority.U != 1 || f.planned.Authority.U != 2 {
		t.Fatalf("error exit: %v inside=%d old=%d planned=%d", err, inside, read.authority.Authority.U, f.planned.Authority.U)
	}
	func() {
		defer func() { _ = recover() }()
		_ = f.exchangeV1(func() error { panic("probe") })
	}()
	if read.authority.Authority.U != 1 || f.planned.Authority.U != 2 {
		t.Fatalf("panic exit: old=%d planned=%d", read.authority.Authority.U, f.planned.Authority.U)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = f.exchangeV1(func() error { runtime.Goexit(); return nil })
	}()
	<-done
	if read.authority.Authority.U != 1 || f.planned.Authority.U != 2 {
		t.Fatalf("Goexit exit: old=%d planned=%d", read.authority.Authority.U, f.planned.Authority.U)
	}
}

// T14: the optional plan admits only unchanged descriptors or the W/L
// transfer (side cleared, detached unchanged, one appended SIDE span owing
// exactly L); x outside the side range needs no read (the nil Reader would
// panic on one).
func TestRetainedCapacityMDBXOptionalPlan(t *testing.T) {
	side := &mdbx.SelectedSideV1{GenerationID: 3, TipHeight: 6, RowCount: 2}
	pending := mdbx.CleanupSpanV1{Kind: mdbx.CleanupSpanSideV1, GenerationID: 3, FirstHeight: 1, NextHeight: 2, LastHeight: 3}
	l := mdbx.CleanupSpanV1{Kind: mdbx.CleanupSpanSideV1, GenerationID: 3, FirstHeight: 5, NextHeight: 5, LastHeight: 6}
	detached := &mdbx.DetachedSuffixV1{EntryCount: 1, Entries: []mdbx.DetachedSuffixEntryV1{{Height: 2}}}
	op := &mdbx.TreeOperationV1{Primitives: []mdbx.TreePrimitiveV1{{Height: 9}}}
	for name, c := range map[string]struct {
		oldSide, plannedSide *mdbx.SelectedSideV1
		plannedDetached      *mdbx.DetachedSuffixV1
		planned              []mdbx.CleanupSpanV1
		transfer, ok         bool
	}{
		"unchanged":        {side, &mdbx.SelectedSideV1{GenerationID: 3, TipHeight: 6, RowCount: 2}, detached, []mdbx.CleanupSpanV1{pending}, false, true},
		"none":             {nil, nil, detached, []mdbx.CleanupSpanV1{pending}, false, true},
		"transfer":         {side, nil, detached, []mdbx.CleanupSpanV1{pending, l}, true, true},
		"side_changed":     {side, &mdbx.SelectedSideV1{GenerationID: 3, TipHeight: 7, RowCount: 3}, detached, []mdbx.CleanupSpanV1{pending}, false, false},
		"side_created":     {nil, side, detached, []mdbx.CleanupSpanV1{pending}, false, false},
		"detached_changed": {side, side, &mdbx.DetachedSuffixV1{EntryCount: 1, Entries: []mdbx.DetachedSuffixEntryV1{{Height: 3}}}, []mdbx.CleanupSpanV1{pending}, false, false},
		"span_added":       {side, side, detached, []mdbx.CleanupSpanV1{pending, l}, false, false},
		"l_missing":        {side, nil, detached, []mdbx.CleanupSpanV1{pending}, true, false},
		"l_wider":          {side, nil, detached, []mdbx.CleanupSpanV1{pending, {Kind: mdbx.CleanupSpanSideV1, GenerationID: 3, FirstHeight: 4, NextHeight: 4, LastHeight: 6}}, true, false},
		"pending_drained":  {side, nil, detached, []mdbx.CleanupSpanV1{{Kind: mdbx.CleanupSpanSideV1, GenerationID: 3, FirstHeight: 1, NextHeight: 3, LastHeight: 3}, l}, true, false},
	} {
		var read retainedReadV1
		read.authority.Authority.SelectedSide, read.authority.Authority.DetachedSuffix = c.oldSide, detached
		read.authority.Authority.Cleanup = &mdbx.CleanupV1{Spans: []mdbx.CleanupSpanV1{pending}}
		f := retainedFiniteV1{read: &read, op: op}
		f.planned.Authority.SelectedSide, f.planned.Authority.DetachedSuffix = c.plannedSide, c.plannedDetached
		f.planned.Authority.Cleanup = &mdbx.CleanupV1{Spans: c.planned}
		transfer, err := f.optionalPlanV1()
		if (err == nil) != c.ok || err != nil && !errors.Is(err, errRetainedFiniteAPIV1) || c.ok && transfer != c.transfer {
			t.Fatalf("%s: transfer=%v err=%v", name, transfer, err)
		}
	}
}

// The promise transfer admits only the exact UNDO span of a U increase.
func TestRetainedCapacityMDBXPromise(t *testing.T) {
	var read retainedReadV1
	read.roles[0].generation = 1
	read.authority.Authority.U = 10
	f := retainedFiniteV1{read: &read}
	undo := func(first, next, last uint64) mdbx.CleanupSpanV1 {
		return mdbx.CleanupSpanV1{Kind: mdbx.CleanupSpanUndoV1, GenerationID: 1, FirstHeight: first, NextHeight: next, LastHeight: last}
	}
	for name, c := range map[string]struct {
		old, planned []mdbx.CleanupSpanV1
		u            uint64
		ok           bool
	}{
		"unchanged":   {nil, nil, 10, true},
		"created":     {nil, []mdbx.CleanupSpanV1{undo(10, 10, 11)}, 12, true},
		"extended":    {[]mdbx.CleanupSpanV1{undo(4, 5, 9)}, []mdbx.CleanupSpanV1{undo(4, 5, 11)}, 12, true},
		"no_span":     {nil, nil, 12, false},
		"wider":       {nil, []mdbx.CleanupSpanV1{undo(9, 9, 11)}, 12, false},
		"regressed":   {nil, nil, 9, false},
		"gap_extend":  {[]mdbx.CleanupSpanV1{undo(4, 5, 8)}, []mdbx.CleanupSpanV1{undo(4, 5, 11)}, 12, false},
		"drained_old": {[]mdbx.CleanupSpanV1{undo(4, 5, 9)}, []mdbx.CleanupSpanV1{undo(4, 6, 9)}, 10, false},
	} {
		read.authority.Authority.Cleanup = &mdbx.CleanupV1{Spans: c.old}
		f.planned.Authority = read.authority.Authority
		f.planned.Authority.U = c.u
		f.planned.Authority.Cleanup = &mdbx.CleanupV1{Spans: c.planned}
		ok := f.spansV1(mdbx.CleanupSpanUndoV1) && c.u >= read.authority.Authority.U
		if ok != c.ok {
			t.Fatalf("%s: %v", name, ok)
		}
	}
}

// W/L transfer (MP 3018-3058): the planned authority clears the selected
// side and appends the SIDE span owing L={y}. y's selected header 148 leaves
// E, its body transfers to SIDE (0), and x adds 148+298. Deleting y's body
// while SIDE still owes it is an unsupported effect.
func TestRetainedCapacityMDBXLeavingSide(t *testing.T) {
	w, _, genesis := riGenesis(t)
	y := initial148BlockFrame(t, [][]byte{initial148BlockGenesisTx(t)}, func(h *initial148BlockHead) { h.parent, h.timestamp = genesis, blockStepsMedian+2 })
	yh := sha3.Sum256(y[:148])
	key, _ := mdbx.HeightKey(3, 5)
	w.pair(t, btMutation(3, yh[:], y[:148]), btMutation(4, yh[:], y), btMutation(6, key, mdbx.ChainValue(yh, genesis, [40]byte{39: 1})))
	riAuthority(t, w, func(a *mdbx.TreeAuthorityV1) {
		a.Authority.SelectedSide = &mdbx.SelectedSideV1{GenerationID: 3, F: 4, TipHeight: 5, TipHash: yh, RowCount: 1, LogicalBytes: uint64(len(y)), CumulativeChainwork: [40]byte{39: 1}}
	})
	op := retainedCapacityBoundOpV1(t, w)
	var planned []byte
	err := w.s.View(func(reader *mdbx.Reader) error {
		a, _, err := reader.ReadTreeAuthorityV1()
		if err != nil {
			return err
		}
		a.Authority.SelectedSide = nil
		if a.Authority.Cleanup == nil {
			a.Authority.Phase, a.Authority.Cleanup = mdbx.StoragePhasePruneGCV1, &mdbx.CleanupV1{}
		}
		a.Authority.Cleanup.Spans = append(a.Authority.Cleanup.Spans, mdbx.CleanupSpanV1{Kind: mdbx.CleanupSpanSideV1, GenerationID: 3, FirstHeight: 5, NextHeight: 5, LastHeight: 5})
		planned, err = a.Encode()
		return err
	})
	logicalMDBXAssert(t, err == nil, "planned authority: %v", err)
	meta := btMutation(0, []byte{2}, planned)
	meta.BeforePresent = true
	del := func(rank int) mdbx.Mutation {
		return mdbx.Mutation{DBI: mdbx.TreeSchemaV1DBIs()[rank], Key: yh[:], BeforePresent: true, AfterKind: mdbx.AfterAbsent}
	}
	base := op.Pair.Mutations
	op.Pair.Mutations = append([]mdbx.Mutation{meta}, base...)
	a, dst := NewRetainedAccountingV1(DefaultLimitsV1()), &DirectRetainedProofV1{}
	if err := retainedCapacityPlanV1(t, w, a, dst, op, 8192); err != nil || !dst.prepared || dst.add != 148+298 || dst.remove != 148 {
		t.Fatalf("leaving side: %v add=%d remove=%d", err, dst.add, dst.remove)
	}
	op = retainedCapacityBoundOpV1(t, w)
	op.Pair.Mutations = append([]mdbx.Mutation{meta}, append(op.Pair.Mutations, del(4))...)
	a, dst = NewRetainedAccountingV1(DefaultLimitsV1()), &DirectRetainedProofV1{}
	if err := retainedCapacityPlanV1(t, w, a, dst, op, 8192); !errors.Is(err, errRetainedFiniteAPIV1) || dst.prepared || a.active != dst {
		t.Fatalf("owed body deletion: %v", err)
	}
	// Keeping y owned while deleting its body is an unsupported effect.
	op2 := retainedCapacityBoundOpV1(t, w)
	op2.Pair.Mutations = append(op2.Pair.Mutations, del(4))
	a, dst = NewRetainedAccountingV1(DefaultLimitsV1()), &DirectRetainedProofV1{}
	if err := retainedCapacityPlanV1(t, w, a, dst, op2, 8192); !errors.Is(err, errRetainedFiniteAPIV1) || dst.prepared || a.active != dst {
		t.Fatalf("owned deletion: %v", err)
	}
}
