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
	// T2: Apply on the fresh destination a nil-Reader Plan refused is the
	// not-active local API failure and invalidates the cache.
	fresh := &DirectRetainedProofV1{}
	if err := a.PlanDirectMDBX(fresh, nil, account, op); !errors.Is(err, errRetainedPlanAPIV1) || !a.valid {
		t.Fatalf("nil Reader: %v", err)
	}
	if err := a.ApplyDirectMDBX(fresh, mdbx.CommitTruthOld, mdbx.UpdateStagePrewrite, -1, errors.New("refused"), true); !errors.Is(err, errRetainedApplyAPIV1) || a.valid || fresh.applied {
		t.Fatalf("nil Reader apply: %v valid=%v", err, a.valid)
	}
	a = retainedCapacityCachedV1()
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
		"bodykind1_nil_slot_insert": func(op *mdbx.TreeOperationV1) {
			c, x := op.Primitives[0].Coverage, op.Primitives[0].Block
			c.BodyKind, c.CurrentBody = 1, make([]byte, 298)
			op.Pair.Mutations = append(op.Pair.Mutations,
				mdbx.Mutation{DBI: mdbx.TreeSchemaV1DBIs()[3], Key: x[:], AfterKind: mdbx.AfterLiteral, Literal: make([]byte, 148)},
				mdbx.Mutation{DBI: mdbx.TreeSchemaV1DBIs()[4], Key: x[:], AfterKind: mdbx.AfterLiteral, Literal: c.CurrentBody})
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
	if err := f.exchangeV1(use); !errors.Is(err, errRetainedFiniteAPIV1) || inside != 2 || read.authority.Authority.U != 1 || f.planned.Authority.U != 2 {
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
// exactly L); a planned SIDE span outside the OLD key set (span_added,
// l_wider, pending_drained) is refused by this construction before any
// exchanged read: x outside the side range needs no read (the nil Reader
// would panic on one). fresh rows hold no OLD SIDE span, since a decodable
// authority holds at most one (validSpanOrder).
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
		transfer, ok, fresh  bool
	}{
		"unchanged":        {side, &mdbx.SelectedSideV1{GenerationID: 3, TipHeight: 6, RowCount: 2}, detached, []mdbx.CleanupSpanV1{pending}, false, true, false},
		"none":             {nil, nil, detached, []mdbx.CleanupSpanV1{pending}, false, true, false},
		"transfer":         {side, nil, detached, []mdbx.CleanupSpanV1{l}, true, true, true},
		"side_changed":     {side, &mdbx.SelectedSideV1{GenerationID: 3, TipHeight: 7, RowCount: 3}, detached, []mdbx.CleanupSpanV1{pending}, false, false, false},
		"side_created":     {nil, side, detached, []mdbx.CleanupSpanV1{pending}, false, false, false},
		"detached_changed": {side, side, &mdbx.DetachedSuffixV1{EntryCount: 1, Entries: []mdbx.DetachedSuffixEntryV1{{Height: 3}}}, []mdbx.CleanupSpanV1{pending}, false, false, false},
		"span_added":       {side, side, detached, []mdbx.CleanupSpanV1{pending, l}, false, false, false},
		"l_missing":        {side, nil, detached, nil, true, false, true},
		"l_wider":          {side, nil, detached, []mdbx.CleanupSpanV1{{Kind: mdbx.CleanupSpanSideV1, GenerationID: 3, FirstHeight: 4, NextHeight: 4, LastHeight: 6}}, true, false, true},
		"pending_drained":  {side, nil, detached, []mdbx.CleanupSpanV1{{Kind: mdbx.CleanupSpanSideV1, GenerationID: 3, FirstHeight: 1, NextHeight: 3, LastHeight: 3}, l}, true, false, false},
	} {
		var read retainedReadV1
		read.authority.Authority.SelectedSide, read.authority.Authority.DetachedSuffix = c.oldSide, detached
		read.authority.Authority.Cleanup = &mdbx.CleanupV1{Spans: []mdbx.CleanupSpanV1{pending}}
		if c.fresh {
			read.authority.Authority.Cleanup = &mdbx.CleanupV1{}
		}
		f := retainedFiniteV1{read: &read, op: op}
		f.planned.Authority.SelectedSide, f.planned.Authority.DetachedSuffix = c.plannedSide, c.plannedDetached
		f.planned.Authority.Cleanup = &mdbx.CleanupV1{Spans: c.planned}
		transfer, err := f.optionalPlanV1()
		if (err == nil) != c.ok || err != nil && !errors.Is(err, errRetainedFiniteAPIV1) || c.ok && transfer != c.transfer {
			t.Fatalf("%s: transfer=%v err=%v", name, transfer, err)
		}
	}
}

// D2/D15/D17 rolling merge: from the rolling-prepared OLD shape (MP
// 1422-1426: one-slot side [f,tip], pending SIDE(g,f-1,f-1,f-1)) the W/L
// transfer with W empty merges L into that span, SIDE(g,f-1,tip,f-1), and
// every other SIDE descriptor is refused (MP 2539-2541). "witness" is the
// RUB-1594 A1 tuple: H_old=F=0, rows 2..1440, SIDE(7,1,1,1), candidate at 1.
// Both rows are legal direct pre-states: H_old=F, candidate at F+1 below f,
// so W is empty with no read. A second planned
// SIDE span is shown refused here although DecodeTreeAuthorityV1 refuses it
// before the consumer. "w_row" is the span restV1 builds for a W row at
// index 0 (L=[f+1,tip]); beside the pending SIDE retainedExtendedV1 refuses
// every plan.
// Consumer-branch cases: this OLD shape is produced natively only by RUB-1508.
func TestRetainedCapacityMDBXRollingMerge(t *testing.T) {
	span := func(g mdbx.GenerationIDV1, first, last, next uint64) mdbx.CleanupSpanV1 {
		return mdbx.CleanupSpanV1{Kind: mdbx.CleanupSpanSideV1, GenerationID: g, FirstHeight: first, LastHeight: last, NextHeight: next}
	}
	for _, geo := range []struct {
		g          mdbx.GenerationIDV1
		F, tip, op uint64
	}{{7, 0, 1440, 1}, {9, 5, 1500, 6}} {
		side := &mdbx.SelectedSideV1{GenerationID: geo.g, F: geo.F, TipHeight: geo.tip, RowCount: 1439}
		f, g, tip := geo.tip-1438, geo.g, geo.tip
		for name, c := range map[string]struct {
			planned []mdbx.CleanupSpanV1
			ok      bool
		}{
			"witness":       {[]mdbx.CleanupSpanV1{span(g, f-1, tip, f-1)}, true},
			"first_moved":   {[]mdbx.CleanupSpanV1{span(g, f, tip, f)}, false},
			"next_moved":    {[]mdbx.CleanupSpanV1{span(g, f-1, tip, f)}, false},
			"last_wider":    {[]mdbx.CleanupSpanV1{span(g, f-1, tip+1, f-1)}, false},
			"last_narrower": {[]mdbx.CleanupSpanV1{span(g, f-1, tip-1, f-1)}, false},
			"second_span":   {[]mdbx.CleanupSpanV1{span(g, f-1, f-1, f-1), span(g, f, tip, f)}, false},
			"not_merged":    {[]mdbx.CleanupSpanV1{span(g, f-1, f-1, f-1)}, false},
			"other_gen":     {[]mdbx.CleanupSpanV1{span(g+1, f-1, tip, f-1)}, false},
		} {
			var read retainedReadV1
			read.authority.Authority.SelectedSide = side
			read.authority.Authority.Cleanup = &mdbx.CleanupV1{Spans: []mdbx.CleanupSpanV1{span(g, f-1, f-1, f-1)}}
			fin := retainedFiniteV1{read: &read, op: &mdbx.TreeOperationV1{Primitives: []mdbx.TreePrimitiveV1{{Height: geo.op}}}}
			fin.planned.Authority.Cleanup = &mdbx.CleanupV1{Spans: c.planned}
			transfer, err := fin.optionalPlanV1()
			if (err == nil) != c.ok || err != nil && !errors.Is(err, errRetainedFiniteAPIV1) || c.ok && !transfer {
				t.Fatalf("g%d %s: transfer=%v err=%v", g, name, transfer, err)
			}
			w := span(g, f+1, tip, f+1)
			if retainedExtendedV1(read.authority.Authority, fin.planned.Authority, w, 1, retainedCountV1(fin.planned.Authority, mdbx.CleanupSpanSideV1)) {
				t.Fatalf("g%d %s w_row admitted", g, name)
			}
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

// retainedCapacityObsoleteV1 stores x's healthy header under an obsolete
// generation 5 with an empty or a paired index/reverse image naming x at 1.
func retainedCapacityObsoleteV1(t *testing.T, w *btWorld, member bool) {
	t.Helper()
	genesis := sha3.Sum256(initial148BlockGenesis(t)[:148])
	child := initial148BlockFrame(t, [][]byte{initial148BlockGenesisTx(t)}, func(h *initial148BlockHead) { h.parent = genesis })
	x := sha3.Sum256(child[:148])
	rows := []mdbx.Mutation{btMutation(3, x[:], child[:148])}
	if member {
		index, _ := mdbx.HeightKey(5, 1)
		owner, _ := mdbx.CanonicalOwnerKey(5, x)
		rows = append(rows, btMutation(2, index, mdbx.ChainValue(x, genesis, [40]byte{39: 1})), btMutation(7, owner, []byte{7: 1}))
	}
	w.pair(t, rows...)
	riAuthority(t, w, func(a *mdbx.TreeAuthorityV1) {
		a.Authority.NextGenerationID = max(a.Authority.NextGenerationID, 6)
		a.Authority.Phase, a.Authority.Cleanup = mdbx.StoragePhasePruneGCV1, &mdbx.CleanupV1{Spans: []mdbx.CleanupSpanV1{{Kind: mdbx.CleanupSpanGenerationV1, GenerationID: 5}}}
	})
}

// D10/D28 under a TRUE fact: an x projected by an obsolete generation
// through a positive own forward and a healthy matching-parent header
// transfers to canonical: its header leaves E (-148) as the canonical term
// adds 148, its body and undo stay owned. A negative membership under the
// TRUE fact excludes x: its stored body is added and its header (owned by
// nobody in OLD) is not removed. The FALSE-fact rows are tagged fixtures.
func TestRetainedCapacityMDBXObsoleteX(t *testing.T) {
	for name, c := range map[string]struct {
		member      bool
		add, remove uint64
	}{
		"positive_true": {true, 148, 148},
		"negative_true": {false, 148 + 298, 0},
	} {
		w, _, _ := riGenesis(t)
		retainedCapacityChildV1(t, w)
		retainedCapacityObsoleteV1(t, w, c.member)
		op := retainedCapacityBoundOpV1(t, w)
		a, dst := NewRetainedAccountingV1(DefaultLimitsV1()), &DirectRetainedProofV1{}
		err := retainedCapacityPlanV1(t, w, a, dst, op, 8192)
		if err != nil || !dst.prepared || dst.add != c.add || dst.remove != c.remove || dst.undo.oldOwned != c.member || !dst.undo.postOwned || dst.complete[0] != (retainedCompleteV1{5, true}) {
			t.Fatalf("%s: %v add=%d remove=%d undo=%+v complete=%+v", name, err, dst.add, dst.remove, dst.undo, dst.complete)
		}
	}
}

// retainedCapacityTwinsV1 plans op twice through one owner: the first Plan is
// cold and its clean callback refusal keeps the completed pre tuple, the
// second is warm. A third owner plans the same op cold for comparison.
func retainedCapacityTwinsV1(t *testing.T, w *btWorld, op func() *mdbx.TreeOperationV1) (cold, warm *DirectRetainedProofV1) {
	t.Helper()
	a := NewRetainedAccountingV1(DefaultLimitsV1())
	first := &DirectRetainedProofV1{}
	err := retainedCapacityPlanV1(t, w, a, first, op(), 8192)
	logicalMDBXAssert(t, err == nil && first.prepared, "cold plan: %v", err)
	err = a.ApplyDirectMDBX(first, mdbx.CommitTruthOld, mdbx.UpdateStagePrewrite, -1, errors.New("callback"), true)
	logicalMDBXAssert(t, err == nil && a.valid, "clean refusal: %v", err)
	a.exactRet++
	warm = &DirectRetainedProofV1{}
	err = retainedCapacityPlanV1(t, w, a, warm, op(), 8192)
	logicalMDBXAssert(t, err == nil && warm.prepared && warm.pre == first.pre+1, "warm plan: %v pre=%d", err, warm.pre)
	warm.pre--
	cold = &DirectRetainedProofV1{}
	err = retainedCapacityPlanV1(t, w, NewRetainedAccountingV1(DefaultLimitsV1()), cold, op(), 8192)
	logicalMDBXAssert(t, err == nil && cold.prepared, "second cold plan: %v", err)
	return cold, warm
}

// retainedCapacityAgreeV1 requires identical finite captures and identical
// accepted proofs over one actual-shaped report.
func retainedCapacityAgreeV1(t *testing.T, cold, warm *DirectRetainedProofV1) {
	t.Helper()
	same := cold.pre == warm.pre && cold.add == warm.add && cold.remove == warm.remove
	if !same || cold.undo != warm.undo || cold.roles != warm.roles || cold.complete != warm.complete {
		t.Fatalf("warm/cold capture: %+v / %+v", cold, warm)
	}
	r := cold.roles[0]
	for _, p := range []*DirectRetainedProofV1{cold, warm} {
		report := &mdbx.TreeDeltaReportV1{
			Current: mdbx.TreeRoleDeltaV1{Present: true, Generation: r.generation, BytesBefore: r.s, CountBefore: r.n, BytesAfter: r.s + 56, CountAfter: r.n + 1, IndexAdded: 1},
			Undo:    []mdbx.TreeUndoChargeV1{{Effect: mdbx.TreeUndoFamilyWrittenV1, Entries: 1, Bytes: 56}},
		}
		if err := p.Proof(report); err != nil || !p.accepted {
			t.Fatalf("proof: %v", err)
		}
	}
	if cold.post != warm.post {
		t.Fatalf("warm post %d cold post %d", warm.post, cold.post)
	}
}

// retainedCapacitySelectedV1 stores raw's header and a SideLink naming it at
// (3,h) and installs a one-row selected side of generation 3 at tip h.
func retainedCapacitySelectedV1(t *testing.T, w *btWorld, raw []byte, h uint64) [32]byte {
	t.Helper()
	hash := sha3.Sum256(raw[:148])
	key, _ := mdbx.HeightKey(3, h)
	w.pair(t, btMutation(3, hash[:], raw[:148]), btMutation(4, hash[:], raw), btMutation(6, key, mdbx.ChainValue(hash, [32]byte(raw[4:36]), [40]byte{39: 1})))
	riAuthority(t, w, func(a *mdbx.TreeAuthorityV1) {
		a.Authority.SelectedSide = &mdbx.SelectedSideV1{GenerationID: 3, F: h - 1, TipHeight: h, TipHash: hash, RowCount: 1, LogicalBytes: uint64(len(raw)), CumulativeChainwork: [40]byte{39: 1}}
	})
	return hash
}

// retainedCapacityClearSideV1 prepends the planned authority that clears the
// selected side, appending SIDE(3,first,last,first) when first<=last.
func retainedCapacityClearSideV1(t *testing.T, w *btWorld, op *mdbx.TreeOperationV1, first, last uint64) {
	t.Helper()
	var planned []byte
	err := w.s.View(func(reader *mdbx.Reader) error {
		a, _, err := reader.ReadTreeAuthorityV1()
		if err != nil {
			return err
		}
		a.Authority.SelectedSide = nil
		if first <= last {
			if a.Authority.Cleanup == nil {
				a.Authority.Phase, a.Authority.Cleanup = mdbx.StoragePhasePruneGCV1, &mdbx.CleanupV1{}
			}
			a.Authority.Cleanup.Spans = append(a.Authority.Cleanup.Spans, mdbx.CleanupSpanV1{Kind: mdbx.CleanupSpanSideV1, GenerationID: 3, FirstHeight: first, NextHeight: first, LastHeight: last})
		}
		planned, err = a.Encode()
		return err
	})
	logicalMDBXAssert(t, err == nil, "planned authority: %v", err)
	meta := btMutation(0, []byte{2}, planned)
	meta.BeforePresent = true
	op.Pair.Mutations = append([]mdbx.Mutation{meta}, op.Pair.Mutations...)
}

// T4 (D2): x is the selected-side W row at the first side height. A nil-slot
// W promotion passes lateHeader nil; x's selected header 148 leaves E as the
// canonical term adds 148 (delta-header(x)=0), its selected body stays owned
// (0) and its absent undo family becomes owned.
func TestRetainedCapacityMDBXWPromotion(t *testing.T) {
	w, _, genesis := riGenesis(t)
	child := initial148BlockFrame(t, [][]byte{initial148BlockGenesisTx(t)}, func(h *initial148BlockHead) { h.parent = genesis })
	x := retainedCapacitySelectedV1(t, w, child, 1)
	op := retainedCapacityBoundOpV1(t, w)
	logicalMDBXAssert(t, op.Primitives[0].Block == x && op.Primitives[0].Height == 1 && op.HeaderSlot == nil, "W op")
	retainedCapacityClearSideV1(t, w, op, 1, 0)
	a, dst := NewRetainedAccountingV1(DefaultLimitsV1()), &DirectRetainedProofV1{}
	if err := retainedCapacityPlanV1(t, w, a, dst, op, 8192); err != nil || !dst.prepared || dst.add != 148 || dst.remove != 148 || dst.undo.oldOwned || !dst.undo.postOwned {
		t.Fatalf("W promotion: %v add=%d remove=%d undo=%+v", err, dst.add, dst.remove, dst.undo)
	}
}

// T10 (D15/D3/D13): one W/L-transfer op gives identical finite captures and
// identical accepted proofs on the warm and the cold path.
func TestRetainedCapacityMDBXTransferWarmCold(t *testing.T) {
	w, _, genesis := riGenesis(t)
	y := initial148BlockFrame(t, [][]byte{initial148BlockGenesisTx(t)}, func(h *initial148BlockHead) { h.parent, h.timestamp = genesis, blockStepsMedian+2 })
	retainedCapacitySelectedV1(t, w, y, 5)
	cold, warm := retainedCapacityTwinsV1(t, w, func() *mdbx.TreeOperationV1 {
		op := retainedCapacityBoundOpV1(t, w)
		retainedCapacityClearSideV1(t, w, op, 5, 5)
		return op
	})
	if cold.add != 148+298 || cold.remove != 148 {
		t.Fatalf("transfer capture add=%d remove=%d", cold.add, cold.remove)
	}
	retainedCapacityAgreeV1(t, cold, warm)
}

// D28: with x owned by an obsolete projection under a TRUE fact the warm and
// cold final quantities agree; cached facts whose generations disagree with
// the fresh OLD spans, or a cache under another binding, are never reused.
func TestRetainedCapacityMDBXObsoleteWarmCold(t *testing.T) {
	w, _, _ := riGenesis(t)
	retainedCapacityChildV1(t, w)
	retainedCapacityObsoleteV1(t, w, true)
	op := func() *mdbx.TreeOperationV1 { return retainedCapacityBoundOpV1(t, w) }
	cold, warm := retainedCapacityTwinsV1(t, w, op)
	if cold.complete[0] != (retainedCompleteV1{5, true}) || cold.add != 148 || cold.remove != 148 {
		t.Fatalf("obsolete capture: %+v", cold)
	}
	retainedCapacityAgreeV1(t, cold, warm)
	for name, stale := range map[string]func(*RetainedAccountingV1){
		"facts":   func(a *RetainedAccountingV1) { a.complete[0].generation = 4 },
		"binding": func(a *RetainedAccountingV1) { a.binding = mdbx.MutationBindingV1{} },
	} {
		a := NewRetainedAccountingV1(DefaultLimitsV1())
		dst := &DirectRetainedProofV1{}
		logicalMDBXAssert(t, retainedCapacityPlanV1(t, w, a, dst, op(), 8192) == nil, "%s seed", name)
		logicalMDBXAssert(t, a.ApplyDirectMDBX(dst, mdbx.CommitTruthOld, mdbx.UpdateStagePrewrite, -1, errors.New("callback"), true) == nil && a.valid, "%s keep", name)
		a.exactRet++
		stale(a)
		dst = &DirectRetainedProofV1{}
		if err := retainedCapacityPlanV1(t, w, a, dst, op(), 8192); err != nil || dst.pre != cold.pre || a.exactRet != cold.pre || a.complete != cold.complete {
			t.Fatalf("%s outlived: %v pre=%d cache=%d facts=%+v", name, err, dst.pre, a.exactRet, a.complete)
		}
	}
}

// T6 (D8): a cold-path role-relation refusal stores the completed pre tuple
// first; the clean witness keeps it, so the next same-binding Plan makes no
// cold call (it returns the marked cache); without the witness it makes one.
func TestRetainedCapacityMDBXRoleRefusalWitness(t *testing.T) {
	w, _, _ := riGenesis(t)
	for _, clean := range []bool{true, false} {
		a, dst := NewRetainedAccountingV1(DefaultLimitsV1()), &DirectRetainedProofV1{}
		op := retainedCapacityBoundOpV1(t, w)
		op.Primitives[0].Coverage.DatabaseID[0] ^= 1
		err := retainedCapacityPlanV1(t, w, a, dst, op, 8192)
		logicalMDBXAssert(t, errors.Is(err, errRetainedShapeAPIV1) && a.valid && !dst.prepared, "role refusal: %v", err)
		cold := a.exactRet
		a.exactRet++
		logicalMDBXAssert(t, a.ApplyDirectMDBX(dst, mdbx.CommitTruthOld, mdbx.UpdateStagePrewrite, -1, err, clean) == nil, "apply")
		next := &DirectRetainedProofV1{}
		err = retainedCapacityPlanV1(t, w, a, next, retainedCapacityBoundOpV1(t, w), 8192)
		want := cold
		if clean {
			want = cold + 1
		}
		if err != nil || next.pre != want {
			t.Fatalf("clean=%v: %v pre=%d want %d", clean, err, next.pre, want)
		}
	}
}

// T7 (D8): the endpoint relation over the producer's actual j: a PreGenesis
// CURRENT role has j=0 and an Applied one at height 0 has j=1.
func TestRetainedCapacityMDBXEndpointRelation(t *testing.T) {
	empty, _, _ := riGenesis(t)
	for _, c := range []struct {
		w    *btWorld
		kind mdbx.TreeEndpointKindV1
		j    uint64
	}{{riNew(t), mdbx.TreeEndpointPreGenesisV1, 0}, {empty, mdbx.TreeEndpointAppliedV1, 1}} {
		err := riContext(t, c.w, nil, func(read *retainedReadV1) error {
			if err := readRetainedRolesV1(read); err != nil {
				return err
			}
			logicalMDBXAssert(t, read.endpoints[0].Kind == c.kind && read.roles[0].j == c.j, "role %+v j=%d", read.endpoints[0], read.roles[0].j)
			op := retainedCapacityDirectOpV1()
			op.Primitives[0].Coverage.DatabaseID = read.origin.database
			for _, h := range []uint64{c.j, c.j + 1} {
				op.Primitives[0].Height = h
				if err := retainedRoleRelationV1(read, op); (err == nil) != (h == c.j) {
					t.Fatalf("j=%d height %d: %v", c.j, h, err)
				}
			}
			return nil
		})
		logicalMDBXAssert(t, err == nil, "context: %v", err)
	}
}

// T8 (D14/D18): under an actual reusable binding the exact success tuple
// still invalidates for an attempt that is !prepared, !entered or !accepted.
func TestRetainedCapacityMDBXReusableUnaccepted(t *testing.T) {
	w, _, _ := riGenesis(t)
	for name, c := range map[string]struct {
		mutate func(*mdbx.TreeOperationV1)
		report bool
	}{
		"unprepared": {func(op *mdbx.TreeOperationV1) { op.Primitives[0].Coverage.DatabaseID[0] ^= 1 }, false},
		"unentered":  {func(*mdbx.TreeOperationV1) {}, false},
		"unaccepted": {func(*mdbx.TreeOperationV1) {}, true},
	} {
		a, dst, op := NewRetainedAccountingV1(DefaultLimitsV1()), &DirectRetainedProofV1{}, retainedCapacityBoundOpV1(t, w)
		c.mutate(op)
		_ = retainedCapacityPlanV1(t, w, a, dst, op, 8192)
		if _, ok := dst.binding.AfterOneCommitAttemptV1(); !ok || !a.valid {
			t.Fatalf("%s: binding not reusable", name)
		}
		if c.report && !errors.Is(dst.Proof(&mdbx.TreeDeltaReportV1{}), errRetainedReportAPIV1) {
			t.Fatalf("%s: report accepted", name)
		}
		if err := a.ApplyDirectMDBX(dst, mdbx.CommitTruthNew, mdbx.UpdateStageCommitMayHaveCrossed, -1, nil, false); err != nil || a.valid || dst.accepted {
			t.Fatalf("%s: %v valid=%v", name, err, a.valid)
		}
	}
}

// D15/D17: L_body comes from the actual published LAG endpoint p, not b(H):
// p4320 keeps L_body 4321 (560 bodies below B 4881), p3600 keeps 3601; a
// direct op preserves p and admits no BLOCKS span change.
func TestRetainedCapacityMDBXBodyWindow(t *testing.T) {
	for _, p := range []uint64{4320, 3600} {
		var read retainedReadV1
		read.authority.Authority = mdbx.StorageAuthorityV1{ActiveProfile: mdbx.StorageProfilePrunedV1, B: 4881, U: 19000}
		read.endpoints[1] = mdbx.TreeEndpointV1{Kind: mdbx.TreeEndpointAppliedV1, Height: p}
		below, at := read.keepV1(retainedArtifactV1{height: p}), read.keepV1(retainedArtifactV1{height: p + 1})
		if read.bodyFirstV1() != p+1 || below.bits&2 != 0 || at.bits&2 == 0 || at.bits&4 != 0 {
			t.Fatalf("p%d: L_body %d below %b at %b", p, read.bodyFirstV1(), below.bits, at.bits)
		}
	}
	var read retainedReadV1
	read.roles[0].generation = 1
	read.authority.Authority = mdbx.StorageAuthorityV1{ActiveProfile: mdbx.StorageProfilePrunedV1, B: 4881, U: 20000, Cleanup: &mdbx.CleanupV1{}}
	read.endpoints[1] = mdbx.TreeEndpointV1{Kind: mdbx.TreeEndpointAppliedV1, Height: 4320}
	op := retainedCapacityDirectOpV1()
	op.Primitives[0].Endpoint = mdbx.TreeEndpointV1{Kind: mdbx.TreeEndpointAppliedV1, Height: 20160}
	op.Pair.Mutations = []mdbx.Mutation{btMutation(0, []byte{2}, nil)}
	f := retainedFiniteV1{read: &read, op: op, planned: read.authority}
	blocks := mdbx.CleanupSpanV1{Kind: mdbx.CleanupSpanBlocksV1, GenerationID: 1, FirstHeight: 4321, NextHeight: 4321, LastHeight: 4880}
	for name, c := range map[string]struct {
		spans []mdbx.CleanupSpanV1
		b     uint64
		ok    bool
	}{"unchanged": {nil, 4881, true}, "blocks_span": {[]mdbx.CleanupSpanV1{blocks}, 4881, false}, "b_moved": {nil, 4882, false}} {
		f.planned.Authority.Cleanup, f.planned.Authority.B = &mdbx.CleanupV1{Spans: c.spans}, c.b
		if _, err := f.promiseV1(); (err == nil) != c.ok {
			t.Fatalf("%s: %v", name, err)
		}
	}
	f.planned.Authority.Cleanup, f.planned.Authority.B = &mdbx.CleanupV1{}, 4881
	logicalMDBXAssert(t, f.read.bodyFirstV1() == 4321, "L_body after promise")
}

// Span-order residual: a decodable authority holds at most one SIDE span
// (validSpanOrder: strictly increasing kinds), so a planned SIDE span never
// sorts beside a second one. The rolling-prepared OLD shape (MP 1422-1426)
// encodes, and appending L beside its pending span does not.
func TestRetainedCapacityMDBXSideOrder(t *testing.T) {
	w, _, _ := riGenesis(t)
	err := w.s.View(func(reader *mdbx.Reader) error {
		a, _, err := reader.ReadTreeAuthorityV1()
		if err != nil {
			return err
		}
		side := func(first, last uint64) mdbx.CleanupSpanV1 {
			return mdbx.CleanupSpanV1{Kind: mdbx.CleanupSpanSideV1, GenerationID: 3, FirstHeight: first, NextHeight: first, LastHeight: last}
		}
		a.Authority.Phase = mdbx.StoragePhasePruneGCV1
		a.Authority.SelectedSide = &mdbx.SelectedSideV1{GenerationID: 3, F: 1, TipHeight: 1441, RowCount: 1439, LogicalBytes: 1439, CumulativeChainwork: [40]byte{39: 1}}
		a.Authority.Cleanup = &mdbx.CleanupV1{Spans: []mdbx.CleanupSpanV1{side(2, 2)}}
		_, rolling := a.Encode()
		a.Authority.SelectedSide = nil
		a.Authority.Cleanup.Spans = []mdbx.CleanupSpanV1{side(2, 2), side(3, 1441)}
		_, two := a.Encode()
		a.Authority.Cleanup.Spans = []mdbx.CleanupSpanV1{side(3, 1441)}
		_, one := a.Encode()
		logicalMDBXAssert(t, rolling == nil && two != nil && one == nil, "rolling=%v two=%v one=%v", rolling, two, one)
		return nil
	})
	logicalMDBXAssert(t, err == nil, "view: %v", err)
}
