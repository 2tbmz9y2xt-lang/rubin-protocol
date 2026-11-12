//go:build cgo && (darwin || linux) && (amd64 || arm64)

package consensus

import (
	"crypto/sha3"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"runtime"
	"strings"
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
	a.active = p
	return p
}

func retainedCapacityReportV1() *mdbx.TreeDeltaReportV1 {
	return &mdbx.TreeDeltaReportV1{
		Current: mdbx.TreeRoleDeltaV1{Present: true, Generation: 1, BytesBefore: 56, CountBefore: 1, BytesAfter: 112, CountAfter: 2, IndexAdded: 1},
		Undo:    []mdbx.TreeUndoChargeV1{{}},
	}
}

// retainedCapacityGrowV1 is p's actual-shaped report of one new CURRENT entry (S+56, N+1, J+1) with the sole undo record u.
func retainedCapacityGrowV1(p *DirectRetainedProofV1, u mdbx.TreeUndoChargeV1) *mdbx.TreeDeltaReportV1 {
	r := p.roles[0]
	return &mdbx.TreeDeltaReportV1{Current: mdbx.TreeRoleDeltaV1{Present: true, Generation: r.generation, BytesBefore: r.s, CountBefore: r.n, BytesAfter: r.s + 56, CountAfter: r.n + 1, IndexAdded: 1}, Undo: []mdbx.TreeUndoChargeV1{u}}
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
	t.Run("D2_D23_equal_digest_roles_distinct", retainedCapacityEqualDigestV1)
}

// D2/D23 "equal digest roles distinct": in the actual empty pair both role bindings carry the same
// empty RootDigest (riEmptyRole); the roles stay two (generations 1 and 2, fresh 32*2), each owning
// its empty Tree(0)=32 (TREE root32), so Ret(pre) is 64, not one shared 32. A Proof over two equal
// role terms replaces only CURRENT and keeps the LAG term (D1 1613).
func retainedCapacityEqualDigestV1(t *testing.T) {
	w := riNew(t)
	err := riContext(t, w, nil, func(read *retainedReadV1) error {
		if err := readRetainedRolesV1(read); err != nil {
			return err
		}
		if read.roles[0] != (retainedRoleV1{generation: 1}) || read.roles[1] != (retainedRoleV1{generation: 2}) {
			return fmt.Errorf("roles %+v", read.roles)
		}
		return nil
	})
	logicalMDBXAssert(t, err == nil, "two roles: %v", err)
	pre, err := riRead(t, w, nil)
	logicalMDBXAssert(t, err == nil && pre.exactRet == 64, "equal-digest pre %d: %v", pre.exactRet, err)
	p := retainedCapacityStructuralV1(NewRetainedAccountingV1(DefaultLimitsV1()))
	p.roles[1] = retainedRoleV1{generation: 2, s: 56, n: 1, j: 2}
	logicalMDBXAssert(t, p.Proof(retainedCapacityReportV1()) == nil && p.post == 1613, "equal role terms post %d", p.post)
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
	p.remove = p.pre + 1<<20 // wraps past every later add: only the subtract check refuses
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
		if err := a.ApplyDirectMDBX(dst, mdbx.CommitTruthOld, mdbx.UpdateStagePrewrite, -1, errors.New("refused"), true); !errors.Is(err, errRetainedApplyAPIV1) || !retainedCapacityClearedV1(a) {
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
	if err := a.ApplyDirectMDBX(fresh, mdbx.CommitTruthOld, mdbx.UpdateStagePrewrite, -1, errors.New("refused"), true); !errors.Is(err, errRetainedApplyAPIV1) || !retainedCapacityClearedV1(a) || fresh.applied {
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
		func(op *mdbx.TreeOperationV1) { op.Primitives[0].Undo = 0 },
		func(op *mdbx.TreeOperationV1) { op.Primitives[0].Undo = 7 },
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
	definiteOld := &mdbx.EngineError{Class: mdbx.EngineTransaction, Operation: "update", Code: -1}
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
		// Outside the native failure union (mdbx_cgo.go updateNativeOutcome.valid; a
		// primitive index is a precommit writer abort, tree_compose_cgo.go abortV1).
		{mdbx.CommitTruthNew, mdbx.UpdateStagePrewrite, 0, boom, false, errRetainedApplyAPIV1, false},
		{mdbx.CommitTruthUnknown, mdbx.UpdateStageWriteStartedDefinitelyPrecommit, -1, boom, false, errRetainedApplyAPIV1, false},
		{mdbx.CommitTruthOld, mdbx.UpdateStageCommitMayHaveCrossed, 0, boom, false, errRetainedApplyAPIV1, false},
		{mdbx.CommitTruthOld, mdbx.UpdateStageWriteStartedDefinitelyPrecommit, 0, boom, false, nil, false},
		// Definite attempted OLD: updateNativeCommit maps RESULT_TRUE/PANIC/EPERM/...
		// to OLD with the commit EngineError at the section's reached stage
		// (internal/mdbx/mdbx_cgo.go:2135-2140, tree_truth_cgo.go:523), which is
		// WriteStarted once a Pair row was put (mdbx_cgo.go:1881,1901); index -1.
		{mdbx.CommitTruthOld, mdbx.UpdateStageWriteStartedDefinitelyPrecommit, -1, definiteOld, false, nil, false},
		{mdbx.CommitTruthOld, mdbx.UpdateStageWriteStartedDefinitelyPrecommit, -1, definiteOld, true, nil, false},
	} {
		a := retainedCapacityCachedV1()
		p := accepted(a)
		if err := a.ApplyDirectMDBX(p, tc.truth, tc.stage, tc.index, tc.err, tc.clean); !errors.Is(err, tc.wantErr) || a.valid != tc.wantValid || a.exactRet != 0 || a.active != nil {
			t.Fatalf("row %d: err=%v valid=%v", i, err, a.valid)
		}
	}
	// A non-reusable binding never yields a cached successor.
	a := retainedCapacityCachedV1()
	p := accepted(a)
	if err := a.ApplyDirectMDBX(p, mdbx.CommitTruthNew, mdbx.UpdateStageCommitMayHaveCrossed, -1, nil, false); err != nil || !retainedCapacityClearedV1(a) || a.active != nil {
		t.Fatalf("non-reusable success: %v valid=%v", err, a.valid)
	}
	if err := a.ApplyDirectMDBX(p, mdbx.CommitTruthNew, mdbx.UpdateStageCommitMayHaveCrossed, -1, nil, false); !errors.Is(err, errRetainedApplyAPIV1) || !retainedCapacityClearedV1(a) {
		t.Fatalf("used token: %v", err)
	}
	// T8: the exact success tuple without this attempt's accepted Proof is the
	// recognized missing/foreign proof row: applied, invalidated, nil.
	a = retainedCapacityCachedV1()
	p = retainedCapacityStructuralV1(a)
	if err := a.ApplyDirectMDBX(p, mdbx.CommitTruthNew, mdbx.UpdateStageCommitMayHaveCrossed, -1, nil, false); err != nil || !retainedCapacityClearedV1(a) || a.active != nil || !p.applied {
		t.Fatalf("missing proof row: %v valid=%v", err, a.valid)
	}
	// An unprepared op-only refusal is consumed; it has no completed pre of its own, so the clean witness clears the cache (D8).
	a = retainedCapacityCachedV1()
	dst := &DirectRetainedProofV1{}
	op := retainedCapacityDirectOpV1()
	op.Primitives[0].Source = nil
	logicalMDBXAssert(t, errors.Is(a.PlanDirectMDBX(dst, &mdbx.Reader{}, &mdbx.OperationAccount{}, op), errRetainedShapeAPIV1), "nil Source plan")
	if err := a.ApplyDirectMDBX(dst, mdbx.CommitTruthOld, mdbx.UpdateStagePrewrite, -1, boom, true); err != nil || a.active != nil || !dst.applied || !retainedCapacityClearedV1(a) {
		t.Fatalf("unprepared apply: %v", err)
	}
}

// retainedCapacityClearedV1 reports the invalidated cache: no valid flag, Ret, binding or facts.
func retainedCapacityClearedV1(a *RetainedAccountingV1) bool {
	return !a.valid && a.exactRet == 0 && a.binding == (mdbx.MutationBindingV1{}) && a.complete == [2]retainedCompleteV1{}
}

// retainedCapacityPlanV1 sorts op's Pair into the (rank, key) order native admission requires (tree_stream_cgo.go:18-19)
// and runs one Plan inside an actual operation account and View Reader; budget is the extra grant the caller holds around Plan.
func retainedCapacityPlanV1(t *testing.T, w *btWorld, a *RetainedAccountingV1, dst *DirectRetainedProofV1, op *mdbx.TreeOperationV1, budget uint64) (result error) {
	t.Helper()
	btSort(op.Pair.Mutations)
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

// retainedCapacityIndexV1 is x's planned CURRENT canonical index and owner insert, the only Pair source of x's planned canonical
// identity; W_h=h+1 is the MP 2817 work (genesis 1, 1 per all-ff target) only when x is h above genesis; Plan never reads it.
func retainedCapacityIndexV1(g, h uint64, x, parent [32]byte) []mdbx.Mutation {
	index, _ := mdbx.HeightKey(g, h)
	owner, _ := mdbx.CanonicalOwnerKey(g, x)
	height := make([]byte, 8)
	height[7] = byte(h)
	return []mdbx.Mutation{
		{DBI: mdbx.TreeSchemaV1DBIs()[2], Key: index, AfterKind: mdbx.AfterLiteral, Literal: mdbx.ChainValue(x, parent, [40]byte{38: byte((h + 1) >> 8), 39: byte(h + 1)})},
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
	// T11: x's planned canonical identity comes from the Pair insert; the OLD
	// Reader reports x as not owned, so reading it would lose the planned bits.
	err = w.s.View(func(reader *mdbx.Reader) error {
		o, err := reader.CanonicalOwnerV1(first.op.Primitives[0].Generation, first.op.Primitives[0].Block)
		logicalMDBXAssert(t, err == nil && !o.Owned, "x OLD owner: %v %+v", err, o)
		return nil
	})
	logicalMDBXAssert(t, err == nil, "view: %v", err)
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
}

func TestRetainedCapacityMDBXPlanOrder(t *testing.T) {
	w, _, _ := riGenesis(t)
	denied := uint64(402653184 - retainedPlanFrameV1 + 1)
	// D8/T1: op-only refusals (nil Source, Undo 0, a stored BodyKind 2 x body literal) precede the cost-1 denied frame.
	a, dst, op := (*RetainedAccountingV1)(nil), (*DirectRetainedProofV1)(nil), retainedCapacityBoundOpV1(t, w)
	literal := mdbx.Mutation{DBI: mdbx.TreeSchemaV1DBIs()[4], Key: op.Primitives[0].Block[:], AfterKind: mdbx.AfterLiteral, Literal: make([]byte, 298)}
	for name, mutate := range map[string]func(*mdbx.TreeOperationV1){
		"nil_source":          func(op *mdbx.TreeOperationV1) { op.Primitives[0].Source = nil },
		"undo_0":              func(op *mdbx.TreeOperationV1) { op.Primitives[0].Undo = 0 },
		"stored_body_literal": func(op *mdbx.TreeOperationV1) { op.Pair.Mutations = append(op.Pair.Mutations, literal) },
	} {
		a, dst, op = NewRetainedAccountingV1(DefaultLimitsV1()), &DirectRetainedProofV1{}, retainedCapacityBoundOpV1(t, w)
		mutate(op)
		if err := retainedCapacityPlanV1(t, w, a, dst, op, denied); !errors.Is(err, errRetainedShapeAPIV1) || a.valid || a.active != dst || dst.roles != ([2]retainedRoleV1{}) {
			t.Fatalf("%s op-only under denied frame: %v", name, err)
		}
	}
	a, dst = NewRetainedAccountingV1(DefaultLimitsV1()), &DirectRetainedProofV1{}
	err := retainedCapacityPlanV1(t, w, a, dst, retainedCapacityDirectOpV1(), denied)
	if !mdbx.IsOperationReservationCapacity(err) || a.valid || dst.pre != 0 || dst.roles != ([2]retainedRoleV1{}) {
		t.Fatalf("denied frame: %v pre=%d", err, dst.pre)
	}
	// D12 exact/cost-1: a relation refusal runs inside the frame after the
	// initializer and before roles or cold work, so with lane 402653184 minus the
	// 4480400 frame held it is the result (frame admitted); one byte less denies the frame first.
	for _, c := range []struct {
		held  uint64
		admit bool
	}{{402653184 - 4480400, true}, {402653184 - 4480400 + 1, false}} {
		op = retainedCapacityBoundOpV1(t, w)
		op.Primitives[0].Generation, op.Primitives[0].Coverage.Generation = 9, 9
		a, dst = NewRetainedAccountingV1(DefaultLimitsV1()), &DirectRetainedProofV1{}
		err = retainedCapacityPlanV1(t, w, a, dst, op, c.held)
		if errors.Is(err, errRetainedShapeAPIV1) != c.admit || mdbx.IsOperationReservationCapacity(err) == c.admit || a.valid || a.active != dst || dst.roles != ([2]retainedRoleV1{}) {
			t.Fatalf("held %d: %v", c.held, err)
		}
	}
	// D8/T6: the role relations run after the cold quantity entry, which stores its completed pre first; the clean witness
	// keeps it, so the next same-binding Plan makes no cold call (it returns the +1 mark); without the witness it makes one.
	for _, c := range []struct {
		name   string
		clean  bool
		mutate func(*mdbx.TreeOperationV1)
	}{
		{"database unclean", false, func(op *mdbx.TreeOperationV1) { op.Primitives[0].Coverage.DatabaseID[0] ^= 1 }},
		{"height", true, func(op *mdbx.TreeOperationV1) {
			op.Primitives[0].Height++
			op.Primitives[0].Coverage.Height++
		}},
		{"database", true, func(op *mdbx.TreeOperationV1) { op.Primitives[0].Coverage.DatabaseID[0] ^= 1 }},
	} {
		a, dst, op = NewRetainedAccountingV1(DefaultLimitsV1()), &DirectRetainedProofV1{}, retainedCapacityBoundOpV1(t, w)
		c.mutate(op)
		err := retainedCapacityPlanV1(t, w, a, dst, op, 8192)
		if !errors.Is(err, errRetainedShapeAPIV1) || !a.valid || dst.pre == 0 || dst.roles[0].generation == 0 || a.active != dst || dst.prepared {
			t.Fatalf("%s relation: %v valid=%v pre=%d", c.name, err, a.valid, dst.pre)
		}
		cold := a.exactRet
		a.exactRet++
		if err := a.ApplyDirectMDBX(dst, mdbx.CommitTruthOld, mdbx.UpdateStagePrewrite, -1, err, c.clean); err != nil || a.valid != c.clean || !c.clean && !retainedCapacityClearedV1(a) {
			t.Fatalf("%s clean witness lost completed pre: %v", c.name, err)
		}
		want, dst := cold, &DirectRetainedProofV1{}
		if c.clean {
			want = cold + 1
		}
		if err := retainedCapacityPlanV1(t, w, a, dst, retainedCapacityBoundOpV1(t, w), 8192); err != nil || dst.pre != want {
			t.Fatalf("%s: %v pre=%d want %d", c.name, err, dst.pre, want)
		}
		logicalMDBXAssert(t, a.ApplyDirectMDBX(dst, mdbx.CommitTruthOld, mdbx.UpdateStagePrewrite, -1, errRetainedShapeAPIV1, true) == nil, "release")
	}
	// D8: a clean refusal raised before this attempt's pre tuple has no completed pre of its own, so it clears the
	// same-binding pre the last row kept (marked +1); the next Plan's pre is the cold value, not the mark.
	want, op, dst := a.exactRet-1, retainedCapacityBoundOpV1(t, w), &DirectRetainedProofV1{}
	op.Primitives[0].Generation, op.Primitives[0].Coverage.Generation = 9, 9
	err = retainedCapacityPlanV1(t, w, a, dst, op, 8192)
	logicalMDBXAssert(t, errors.Is(err, errRetainedShapeAPIV1) && a.valid && dst.pre == 0, "relation refusal over a cached pre: %v", err)
	if err := a.ApplyDirectMDBX(dst, mdbx.CommitTruthOld, mdbx.UpdateStagePrewrite, -1, err, true); err != nil || !retainedCapacityClearedV1(a) {
		t.Fatalf("clean refusal before the pre tuple kept the cache: %v ret=%d valid=%v", err, a.exactRet, a.valid)
	}
	dst = &DirectRetainedProofV1{}
	if err := retainedCapacityPlanV1(t, w, a, dst, retainedCapacityBoundOpV1(t, w), 8192); err != nil || dst.pre != want || a.exactRet != want {
		t.Fatalf("next plan after the cleared cache: %v pre=%d want %d", err, dst.pre, want)
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
	g, one, x := binary.BigEndian.AppendUint64(nil, 1), []byte{1}, retainedCapacityBoundOpV1(t, w).Primitives[0].Block
	row := func(m mdbx.Mutation) func(*mdbx.TreeOperationV1) {
		return func(op *mdbx.TreeOperationV1) { op.Pair.Mutations = append(op.Pair.Mutations, m) }
	}
	node, err := mdbx.TreeNodeKey(1, mdbx.TreeNodeIDV1{Kind: mdbx.TreeNodeLeafV1, Depth: 288})
	logicalMDBXAssert(t, err == nil, "tree node key: %v", err)
	for name, mutate := range map[string]func(*mdbx.TreeOperationV1){
		"no_index_insert":   func(op *mdbx.TreeOperationV1) { op.Pair.Mutations = op.Pair.Mutations[1:] },
		"index_names_other": func(op *mdbx.TreeOperationV1) { op.Pair.Mutations[0].Literal[0] ^= 1 },
		"unknown_namespace": func(op *mdbx.TreeOperationV1) { op.Pair.Mutations = append(op.Pair.Mutations, staged) },
		"slot_with_pair_header": func(op *mdbx.TreeOperationV1) {
			x := op.Primitives[0].Block
			op.HeaderSlot = &mdbx.TreeHeaderSlotV1{Hash: x}
			op.Pair.Mutations = append(op.Pair.Mutations, mdbx.Mutation{DBI: mdbx.TreeSchemaV1DBIs()[3], Key: x[:], AfterKind: mdbx.AfterLiteral, Literal: make([]byte, 148)})
		},
		// A Pair state, x-keyed undo, tree-node, counter or root meta row of the CURRENT generation g=1: native
		// admission refuses each for every covered direct op (internal/mdbx/tree_stream_cgo.go:582-584, 655-691).
		"state_row":     row(btMutation(1, append(g, make([]byte, 36)...), one)),
		"undo_row":      row(btMutation(5, append(x[:], 0, 0, 0, 1), one)),
		"tree_node_row": row(btMutation(8, node, one)),
		"counter_meta":  row(btMutation(0, append([]byte{0x10}, g...), one)),
		"root_meta":     row(btMutation(0, append([]byte{0x11}, g...), one)),
	} {
		a, dst, err := plan(mutate)
		if !errors.Is(err, errRetainedFiniteAPIV1) || a.active != dst || dst.prepared || dst.pre == 0 || !a.valid {
			t.Fatalf("%s: %v prepared=%v", name, err, dst.prepared)
		}
		// Each refusal follows the pre tuple, so the clean witness keeps the completed pre.
		if err := a.ApplyDirectMDBX(dst, mdbx.CommitTruthOld, mdbx.UpdateStagePrewrite, -1, err, true); err != nil || !a.valid || a.exactRet != dst.pre {
			t.Fatalf("%s: clean witness lost the completed pre: %v", name, err)
		}
	}
	// T5: a fresh nil-slot header insert of an absent x adds the canonical
	// 148 once, not 296; a qualified slot also adds 148 once.
	for name, mutate := range map[string]func(*mdbx.TreeOperationV1){
		"nil_slot_insert": func(op *mdbx.TreeOperationV1) {
			x := op.Primitives[0].Block
			op.Pair.Mutations = append(op.Pair.Mutations, mdbx.Mutation{DBI: mdbx.TreeSchemaV1DBIs()[3], Key: x[:], AfterKind: mdbx.AfterLiteral, Literal: make([]byte, 148)})
		},
		"qualified_slot": func(op *mdbx.TreeOperationV1) { op.HeaderSlot = &mdbx.TreeHeaderSlotV1{Hash: op.Primitives[0].Block} },
		// A BodyKind 1 current body literal is owned after at its exact length.
		"current_body": func(op *mdbx.TreeOperationV1) {
			c, x := op.Primitives[0].Coverage, op.Primitives[0].Block
			c.BodyKind, c.CurrentBody = 1, make([]byte, 298)
			op.Pair.Mutations = append(op.Pair.Mutations, mdbx.Mutation{DBI: mdbx.TreeSchemaV1DBIs()[4], Key: x[:], AfterKind: mdbx.AfterLiteral, Literal: c.CurrentBody})
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
	// The prepared finite capture reduces an actual-shaped report exactly:
	// CURRENT +S56,N+1 (Tree +170 or +68 from N0), J+1, header 148, family.
	_, dst, err := plan(func(*mdbx.TreeOperationV1) {})
	logicalMDBXAssert(t, err == nil && dst.prepared, "plan: %v", err)
	r, report := dst.roles[0], retainedCapacityGrowV1(dst, mdbx.TreeUndoChargeV1{Effect: mdbx.TreeUndoFamilyWrittenV1, Entries: 1, Bytes: 56})
	oldTree, _ := RetainedTreeChargeV1(r.n)
	newTree, _ := RetainedTreeChargeV1(r.n + 1)
	if err := dst.Proof(report); err != nil || dst.post != dst.pre+56+newTree-oldTree+RetainedIndexChargeV1+148+298+56 {
		t.Fatalf("proof: %v post=%d pre=%d", err, dst.post, dst.pre)
	}
	retainedCapacityKeptSideV1(t, w)
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
	func() { defer func() { _ = recover() }(); _ = f.exchangeV1(func() error { panic("probe") }) }()
	if read.authority.Authority.U != 1 || f.planned.Authority.U != 2 {
		t.Fatalf("panic exit: old=%d planned=%d", read.authority.Authority.U, f.planned.Authority.U)
	}
	done := make(chan struct{})
	go func() { defer close(done); _ = f.exchangeV1(func() error { runtime.Goexit(); return nil }) }()
	<-done
	if read.authority.Authority.U != 1 || f.planned.Authority.U != 2 {
		t.Fatalf("Goexit exit: old=%d planned=%d", read.authority.Authority.U, f.planned.Authority.U)
	}
}

// T14: the optional plan admits only unchanged descriptors or the W/L transfer (side cleared,
// detached unchanged, one appended SIDE span owing exactly L); a planned SIDE span outside the OLD
// key set (span_added, l_wider, pending_drained) is refused by this construction before any
// exchanged read: x outside the side range needs no read (the nil Reader would panic on one). fresh
// rows hold no OLD SIDE span, since a decodable authority holds at most one (validSpanOrder).
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

// D2/D15/D17 rolling merge: from the rolling-prepared OLD shape (MP 1422-1426: one-slot side
// [f,tip], pending SIDE(g,f-1,f-1,f-1)) the W/L transfer with W empty merges L into that span,
// SIDE(g,f-1,tip,f-1), and every other SIDE descriptor is refused (MP 2539-2541). "witness" is the
// RUB-1594 A1 tuple: H_old=F=0, rows 2..1440, SIDE(7,1,1,1), candidate at 1. Both rows are legal
// direct pre-states: H_old=F, candidate at F+1 below f, so W is empty with no read. A second
// planned SIDE span is shown refused here although DecodeTreeAuthorityV1 refuses it before the
// consumer. "w_row" is the span restV1 builds for a W row at index 0 (L=[f+1,tip]); beside the
// pending SIDE retainedExtendedV1 refuses every plan. Consumer-branch cases: this OLD shape is
// produced natively only by RUB-1508.
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

// The promise transfer admits only the exact UNDO span of a U increase. Each OLD and planned authority is NONE/STABLE
// without spans or PRUNE_GC/STABLE with them (MP 1844) and decodes; gap_extend's OLD, whose last UNDO span ends below
// U0-1 (MP 1327-1328), is the structural-only rejected case the decoder still accepts.
func TestRetainedCapacityMDBXPromise(t *testing.T) {
	var read retainedReadV1
	read.roles[0].generation = 1
	read.authority.Authority = mdbx.StorageAuthorityV1{Version: mdbx.StorageAuthorityVersionV1, ActiveProfile: mdbx.StorageProfilePrunedV1, U: 10, ActiveGenerationID: 1, NextGenerationID: 2, Lifecycle: mdbx.StorageLifecycleStableV1}
	f := retainedFiniteV1{read: &read, op: &mdbx.TreeOperationV1{Pair: mdbx.TreePairV1{Mutations: []mdbx.Mutation{btMutation(0, []byte{2}, nil)}}}}
	undo := func(first, next, last uint64) mdbx.CleanupSpanV1 {
		return mdbx.CleanupSpanV1{Kind: mdbx.CleanupSpanUndoV1, GenerationID: 1, FirstHeight: first, NextHeight: next, LastHeight: last}
	}
	for name, c := range map[string]struct {
		old, planned []mdbx.CleanupSpanV1
		u            uint64
		ok           bool
	}{
		"unchanged": {nil, nil, 10, true},
		"created":   {nil, []mdbx.CleanupSpanV1{undo(10, 10, 11)}, 12, true},
		"extended":  {[]mdbx.CleanupSpanV1{undo(4, 5, 9)}, []mdbx.CleanupSpanV1{undo(4, 5, 11)}, 12, true},
		"no_span":   {nil, nil, 12, false},
		"wider":     {nil, []mdbx.CleanupSpanV1{undo(9, 9, 11)}, 12, false},
		"regressed": {nil, nil, 9, false},
		// UNDO(1,4,9,5)->(1,4,8,5) with U 10->9 passes spansV1; only the nonregressing U (MP 1288-1290) refuses it.
		"u_regressed_span": {[]mdbx.CleanupSpanV1{undo(4, 5, 9)}, []mdbx.CleanupSpanV1{undo(4, 5, 8)}, 9, false},
		"gap_extend":       {[]mdbx.CleanupSpanV1{undo(4, 5, 8)}, []mdbx.CleanupSpanV1{undo(4, 5, 11)}, 12, false},
		"drained_old":      {[]mdbx.CleanupSpanV1{undo(4, 5, 9)}, []mdbx.CleanupSpanV1{undo(4, 6, 9)}, 10, false},
	} {
		retainedCapacitySpansV1(&read.authority.Authority, c.old)
		f.planned.Authority = read.authority.Authority
		f.planned.Authority.U = c.u
		retainedCapacitySpansV1(&f.planned.Authority, c.planned)
		if mdbx.ValidateStorageAuthorityV1(read.authority.Authority) != nil || mdbx.ValidateStorageAuthorityV1(f.planned.Authority) != nil {
			t.Fatalf("%s: authority must decode", name)
		}
		if _, err := f.promiseV1(); (err == nil) != c.ok {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

// retainedCapacitySpansV1 sets NONE without spans, otherwise PRUNE_GC with them (MP 1844).
func retainedCapacitySpansV1(a *mdbx.StorageAuthorityV1, spans []mdbx.CleanupSpanV1) {
	a.Phase, a.Cleanup = mdbx.StoragePhaseNoneV1, nil
	if len(spans) != 0 {
		a.Phase, a.Cleanup = mdbx.StoragePhasePruneGCV1, &mdbx.CleanupV1{Spans: spans}
	}
}

// W/L transfer (MP 3018-3037): side F=0=H_old holds x@1 (MP 2984-2986) and its child y@2 (298 bytes each). The op publishes
// x at 1 on the route of MP 3723-3726 (a longer descendant chain applied one D=0,C=1 commit or one bounded phase at a time; y
// as the winner is C=2 ORDINARY_APPLY, MP 3736-3740): W={x}, L={y}, side cleared, SIDE(3,2,2,2) owing L, SideLink (3,1) and y's
// unowned header deleted (MP 2550-2557): x's header delta 0, y's 148 leaves E, its body and link stay owed; a Pair that keeps that
// header leaves the same E (no owner keeps it after the transfer, MP 3169). Deleting L's link or y's body is refused.
// On the lawful-retention OLD (healthy y@1, x's sibling, MP 3047-3058) a W-less SideLink (3,1) deletion (side cleared, with or without SIDE) and y's owned body deletion are refused; the side is kept.
func TestRetainedCapacityMDBXLeavingSide(t *testing.T) {
	wl, leave := retainedCapacityWLSideV1(t)
	// G7 (D15, MP 1717, 2550-2557): in wo obsolete generation 5 also projects y; deleting y's header ends that projection in the
	// planned image, so y's header leaves E with its projection-owned (here absent) undo family while SIDE keeps its body.
	wo, leaveO := retainedCapacityWLSideV1(t)
	retainedCapacityObsoleteYV1(t, wo, [32]byte(leaveO.Key), 2)
	w, _, genesis := riGenesis(t)
	kept := retainedCapacitySelectedV1(t, w, initial148BlockFrame(t, [][]byte{initial148BlockGenesisTx(t)}, func(h *initial148BlockHead) { h.parent, h.timestamp = genesis, blockStepsMedian+2 }), 1)
	for name, c := range map[string]struct {
		w  *btWorld
		op *mdbx.TreeOperationV1
		m  []mdbx.Mutation
	}{
		"accepted":                {wl, retainedCapacityWLOpV1(t, wl, 2, 2, leave), nil},
		"accepted, header kept":   {wl, retainedCapacityWLOpV1(t, wl, 2, 2), nil},
		"accepted, G7 obsolete y": {wo, retainedCapacityWLOpV1(t, wo, 2, 2, leaveO), nil},
		"link deletion without W": {w, retainedCapacityWLOpV1(t, w, 1, 1), nil},
		"non-W row as W":          {w, retainedCapacityWLOpV1(t, w, 1, 0), nil},
		"L link deletion":         {wl, retainedCapacityWLOpV1(t, wl, 2, 2, leave), []mdbx.Mutation{retainedCapacityLinkDeleteV1(3, 2)}},
		"owed body deletion":      {wl, retainedCapacityWLOpV1(t, wl, 2, 2, leave), []mdbx.Mutation{{DBI: mdbx.TreeSchemaV1DBIs()[4], Key: leave.Key, BeforePresent: true, AfterKind: mdbx.AfterAbsent}}},
		"owned deletion":          {w, retainedCapacityBoundOpV1(t, w), []mdbx.Mutation{{DBI: mdbx.TreeSchemaV1DBIs()[4], Key: kept[:], BeforePresent: true, AfterKind: mdbx.AfterAbsent}}},
	} {
		c.op.Pair.Mutations = append(c.op.Pair.Mutations, c.m...)
		a, dst := NewRetainedAccountingV1(DefaultLimitsV1()), &DirectRetainedProofV1{}
		err := retainedCapacityPlanV1(t, c.w, a, dst, c.op, 8192)
		accepted := strings.HasPrefix(name, "accepted")
		logicalMDBXAssert(t, !accepted || err == nil && dst.prepared && dst.add == 148 && dst.remove == 148+148 && (c.w != wo || dst.complete[0] == (retainedCompleteV1{5, true})), "%s: %v add=%d remove=%d complete=%+v", name, err, dst.add, dst.remove, dst.complete)
		logicalMDBXAssert(t, accepted || errors.Is(err, errRetainedFiniteAPIV1) && !dst.prepared && a.active == dst, "%s: %v", name, err)
	}
	retainedCapacityKeptSideV1(t, w)
}

// retainedCapacityObsoleteYV1 makes obsolete generation 5 project y, x's child, at h under a TRUE fact: its own forward
// and reverse name y with parent x at h, and y's healthy header is stored.
func retainedCapacityObsoleteYV1(t *testing.T, w *btWorld, y [32]byte, h uint64) {
	t.Helper()
	x, _ := retainedCapacityChildV1(t, w)
	index, _ := mdbx.HeightKey(5, h)
	owner, _ := mdbx.CanonicalOwnerKey(5, y)
	w.pair(t, btMutation(2, index, mdbx.ChainValue(y, x, [40]byte{39: 3})), btMutation(7, owner, []byte{7: byte(h)}))
	riAuthority(t, w, func(a *mdbx.TreeAuthorityV1) {
		a.Authority.NextGenerationID = max(a.Authority.NextGenerationID, 6)
		a.Authority.Phase, a.Authority.Cleanup = mdbx.StoragePhasePruneGCV1, &mdbx.CleanupV1{Spans: []mdbx.CleanupSpanV1{{Kind: mdbx.CleanupSpanGenerationV1, GenerationID: 5}}}
	})
}

// retainedCapacityWLSideV1 installs the side F=0, rows x@1 and its child y@2; returns y's leaving header deletion (MP 2550-2557).
func retainedCapacityWLSideV1(t *testing.T) (*btWorld, mdbx.Mutation) {
	t.Helper()
	w, _, genesis := riGenesis(t)
	child := initial148BlockFrame(t, [][]byte{initial148BlockGenesisTx(t)}, func(h *initial148BlockHead) { h.parent = genesis })
	x := retainedCapacitySelectedV1(t, w, child, 1)
	y := retainedCapacitySelectedV1(t, w, initial148BlockFrame(t, [][]byte{initial148BlockGenesisTx(t)}, func(h *initial148BlockHead) { h.parent, h.timestamp = x, blockStepsMedian+2 }), 2)
	riAuthority(t, w, func(a *mdbx.TreeAuthorityV1) {
		a.Authority.SelectedSide.F, a.Authority.SelectedSide.RowCount, a.Authority.SelectedSide.LogicalBytes = 0, 2, 2*uint64(len(child))
	})
	return w, mdbx.Mutation{DBI: mdbx.TreeSchemaV1DBIs()[3], Key: y[:], BeforePresent: true, AfterKind: mdbx.AfterAbsent}
}

// retainedCapacityWLOpV1 publishes x at 1: side cleared, SIDE(3,f,l,f) if f<=l, SideLink (3,1) deleted, then m.
func retainedCapacityWLOpV1(t *testing.T, w *btWorld, f, l uint64, m ...mdbx.Mutation) *mdbx.TreeOperationV1 {
	op := retainedCapacityBoundOpV1(t, w)
	retainedCapacityClearSideV1(t, w, op, f, l)
	op.Pair.Mutations = append(append(op.Pair.Mutations, retainedCapacityLinkDeleteV1(3, 1)), m...)
	return op
}

// retainedCapacityKeptSideV1: a changed planned authority (U+1) that keeps
// OLD's selected side, or OLD without a side, admits no SideLink deletion at x's
// height; links stay byte-identical (MP 1483-1485). The bare op proves.
func retainedCapacityKeptSideV1(t *testing.T, w *btWorld) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("kept side: panic %v, want local API refusal", r)
		}
	}()
	for _, link := range []bool{false, true} {
		op := retainedCapacityBoundOpV1(t, w)
		if link {
			op.Pair.Mutations = append(op.Pair.Mutations, retainedCapacityLinkDeleteV1(3, op.Primitives[0].Height))
		}
		retainedCapacityMetaV1(t, w, op, func(a *mdbx.StorageAuthorityV1) {
			if a.Cleanup == nil {
				a.Phase, a.Cleanup = mdbx.StoragePhasePruneGCV1, &mdbx.CleanupV1{}
			}
			a.Cleanup.Spans = append(a.Cleanup.Spans, mdbx.CleanupSpanV1{Kind: mdbx.CleanupSpanUndoV1, GenerationID: a.ActiveGenerationID, FirstHeight: a.U, NextHeight: a.U, LastHeight: a.U})
			a.U++
		})
		a, dst := NewRetainedAccountingV1(DefaultLimitsV1()), &DirectRetainedProofV1{}
		if err := retainedCapacityPlanV1(t, w, a, dst, op, 8192); errors.Is(err, errRetainedFiniteAPIV1) != link || dst.prepared == link || a.active != dst {
			t.Fatalf("kept side, link=%v: %v prepared=%v", link, err, dst.prepared)
		}
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
		rows = append(rows, btMutation(2, index, mdbx.ChainValue(x, genesis, [40]byte{39: 2})), btMutation(7, owner, []byte{7: 1}))
	}
	w.pair(t, rows...)
	riAuthority(t, w, func(a *mdbx.TreeAuthorityV1) {
		a.Authority.NextGenerationID = max(a.Authority.NextGenerationID, 6)
		a.Authority.Phase, a.Authority.Cleanup = mdbx.StoragePhasePruneGCV1, &mdbx.CleanupV1{Spans: []mdbx.CleanupSpanV1{{Kind: mdbx.CleanupSpanGenerationV1, GenerationID: 5}}}
	})
}

// D10/D28 under a TRUE fact: a negative membership excludes x: its stored body is added and its
// header (owned by nobody in OLD) is not removed. The positive row is ObsoleteWarmCold's capture;
// the FALSE-fact rows are tagged fixtures.
func TestRetainedCapacityMDBXObsoleteX(t *testing.T) {
	w, _, _ := riGenesis(t)
	retainedCapacityChildV1(t, w)
	retainedCapacityObsoleteV1(t, w, false)
	a, dst := NewRetainedAccountingV1(DefaultLimitsV1()), &DirectRetainedProofV1{}
	err := retainedCapacityPlanV1(t, w, a, dst, retainedCapacityBoundOpV1(t, w), 8192)
	if err != nil || !dst.prepared || dst.add != 148+298 || dst.remove != 0 || dst.undo.oldOwned || !dst.undo.postOwned || dst.complete[0] != (retainedCompleteV1{5, true}) {
		t.Fatalf("negative_true: %v add=%d remove=%d undo=%+v complete=%+v", err, dst.add, dst.remove, dst.undo, dst.complete)
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
	for _, p := range []*DirectRetainedProofV1{cold, warm} {
		if err := p.Proof(retainedCapacityGrowV1(p, mdbx.TreeUndoChargeV1{Effect: mdbx.TreeUndoFamilyWrittenV1, Entries: 1, Bytes: 56})); err != nil || !p.accepted {
			t.Fatalf("proof: %v", err)
		}
	}
	if cold.post != warm.post {
		t.Fatalf("warm post %d cold post %d", warm.post, cold.post)
	}
}

// retainedCapacitySelectedV1 stores raw's header, body and a SideLink naming it at (3,h) and installs a one-row selected side
// 3 at tip h, both with W_h=h+1: the MP 1462-1464, 2817 work (genesis 1, 1 per all-ff target) only when raw is h above genesis.
func retainedCapacitySelectedV1(t *testing.T, w *btWorld, raw []byte, h uint64) [32]byte {
	t.Helper()
	hash := sha3.Sum256(raw[:148])
	key, _ := mdbx.HeightKey(3, h)
	w.pair(t, btMutation(3, hash[:], raw[:148]), btMutation(4, hash[:], raw), btMutation(6, key, mdbx.ChainValue(hash, [32]byte(raw[4:36]), [40]byte{38: byte((h + 1) >> 8), 39: byte(h + 1)})))
	riAuthority(t, w, func(a *mdbx.TreeAuthorityV1) {
		a.Authority.SelectedSide = &mdbx.SelectedSideV1{GenerationID: 3, F: h - 1, TipHeight: h, TipHash: hash, RowCount: 1, LogicalBytes: uint64(len(raw)), CumulativeChainwork: [40]byte{38: byte((h + 1) >> 8), 39: byte(h + 1)}}
	})
	return hash
}

// retainedCapacityClearSideV1 prepends the planned authority that clears the
// selected side, appending SIDE(3,first,last,first) when first<=last.
func retainedCapacityClearSideV1(t *testing.T, w *btWorld, op *mdbx.TreeOperationV1, first, last uint64) {
	t.Helper()
	retainedCapacityMetaV1(t, w, op, func(a *mdbx.StorageAuthorityV1) {
		a.SelectedSide = nil
		if first <= last {
			if a.Cleanup == nil {
				a.Phase, a.Cleanup = mdbx.StoragePhasePruneGCV1, &mdbx.CleanupV1{}
			}
			a.Cleanup.Spans = append(a.Cleanup.Spans, mdbx.CleanupSpanV1{Kind: mdbx.CleanupSpanSideV1, GenerationID: 3, FirstHeight: first, NextHeight: first, LastHeight: last})
		}
	})
}

// retainedCapacityMetaV1 prepends the planned authority edit makes of OLD.
func retainedCapacityMetaV1(t *testing.T, w *btWorld, op *mdbx.TreeOperationV1, edit func(*mdbx.StorageAuthorityV1)) {
	t.Helper()
	var planned []byte
	err := w.s.View(func(reader *mdbx.Reader) error {
		a, _, err := reader.ReadTreeAuthorityV1()
		if err != nil {
			return err
		}
		edit(&a.Authority)
		planned, err = a.Encode()
		return err
	})
	logicalMDBXAssert(t, err == nil, "planned authority: %v", err)
	meta := btMutation(0, []byte{2}, planned)
	meta.BeforePresent = true
	op.Pair.Mutations = append([]mdbx.Mutation{meta}, op.Pair.Mutations...)
}

// T4 (D2): x is the selected-side W row at the first side height. A nil-slot W promotion passes
// lateHeader nil; x's selected header 148 leaves E as the canonical term adds 148
// (delta-header(x)=0), its selected body stays owned (0) and its absent undo family becomes owned.
// The publication deletes the W SideLink (3,1); without that deletion the Pair is refused.
func TestRetainedCapacityMDBXWPromotion(t *testing.T) {
	w, _, genesis := riGenesis(t)
	child := initial148BlockFrame(t, [][]byte{initial148BlockGenesisTx(t)}, func(h *initial148BlockHead) { h.parent = genesis })
	x := retainedCapacitySelectedV1(t, w, child, 1)
	op := retainedCapacityBoundOpV1(t, w)
	logicalMDBXAssert(t, op.Primitives[0].Block == x && op.Primitives[0].Height == 1 && op.HeaderSlot == nil, "W op")
	retainedCapacityClearSideV1(t, w, op, 1, 0)
	bare, link := op.Pair.Mutations, retainedCapacityLinkDeleteV1(3, 1)
	op.Pair.Mutations = append(append([]mdbx.Mutation(nil), bare...), link)
	a, dst := NewRetainedAccountingV1(DefaultLimitsV1()), &DirectRetainedProofV1{}
	if err := retainedCapacityPlanV1(t, w, a, dst, op, 8192); err != nil || !dst.prepared || dst.add != 148 || dst.remove != 148 || dst.undo.oldOwned || !dst.undo.postOwned {
		t.Fatalf("W promotion: %v add=%d remove=%d undo=%+v", err, dst.add, dst.remove, dst.undo)
	}
	// Only a present-before deletion of SideLink(3,1) is the W publication
	// (MP 2559-2561); an overwrite, a before-absent or unknown-kind effect or
	// another key is refused (MP 1473-1474).
	overwrite, absent, unknown := link, link, link
	overwrite.AfterKind, overwrite.Literal = mdbx.AfterLiteral, mdbx.ChainValue(x, genesis, [40]byte{39: 2})
	absent.BeforePresent, unknown.AfterKind = false, 0
	stray := [][]mdbx.Mutation{bare, append(retainedCapacityBoundOpV1(t, w).Pair.Mutations, link)}
	for _, m := range []mdbx.Mutation{retainedCapacityLinkDeleteV1(3, 2), retainedCapacityLinkDeleteV1(2, 1), overwrite, absent, unknown} {
		stray = append(stray, append(bare[:len(bare):len(bare)], m))
	}
	for i, m := range stray {
		op.Pair.Mutations, a, dst = m, NewRetainedAccountingV1(DefaultLimitsV1()), &DirectRetainedProofV1{}
		if err := retainedCapacityPlanV1(t, w, a, dst, op, 8192); !errors.Is(err, errRetainedFiniteAPIV1) || dst.prepared || a.active != dst {
			t.Fatalf("SideLink row %d: %v", i, err)
		}
	}
	// D8 order: a BodyKind 1 write of x whose body the selected side owns is refused only after x's header settlement. The
	// cache models a pre completed before x's selected header was lost; x's header charge then returns selected_damage first.
	w.pair(t, mdbx.Mutation{DBI: mdbx.TreeSchemaV1DBIs()[3], Key: x[:], BeforePresent: true, AfterKind: mdbx.AfterAbsent})
	op = retainedCapacityBoundOpV1(t, w)
	op.Primitives[0].Coverage.BodyKind, op.Primitives[0].Coverage.CurrentBody = 1, child
	retainedCapacityClearSideV1(t, w, op, 1, 0)
	op.Pair.Mutations = append(op.Pair.Mutations, link)
	a, dst = NewRetainedAccountingV1(DefaultLimitsV1()), &DirectRetainedProofV1{}
	logicalMDBXAssert(t, retainedCapacityPlanV1(t, w, a, dst, op, 8192) != nil && a.ApplyDirectMDBX(dst, mdbx.CommitTruthOld, mdbx.UpdateStagePrewrite, -1, errRetainedShapeAPIV1, false) == nil, "cold plan")
	a.binding, a.exactRet, a.valid, dst = dst.binding, 1077, true, &DirectRetainedProofV1{}
	err := retainedCapacityPlanV1(t, w, a, dst, op, 8192)
	var failure *RetainedProofFailureV1
	if !errors.As(err, &failure) || failure.Resource != "selected_damage" || failure.Damage.Artifact != "header" || failure.Damage.Hash != x || dst.pre != 1077 || dst.prepared || a.active != dst {
		t.Fatalf("redundant write over a lost selected header: %T %v pre=%d", err, err, dst.pre)
	}
	if err := a.ApplyDirectMDBX(dst, mdbx.CommitTruthOld, mdbx.UpdateStagePrewrite, -1, err, true); err != nil || !a.valid || a.exactRet != 1077 {
		t.Fatalf("clean witness lost the completed pre: %v", err)
	}
}

func retainedCapacityLinkDeleteV1(g, h uint64) mdbx.Mutation {
	key, _ := mdbx.HeightKey(g, h)
	return mdbx.Mutation{DBI: mdbx.TreeSchemaV1DBIs()[6], Key: key, BeforePresent: true, AfterKind: mdbx.AfterAbsent}
}

// D28/T10: with x owned by an obsolete projection under a TRUE fact the warm and
// cold final quantities agree; cached facts whose generations disagree with
// the fresh OLD spans, or a cache under another binding, are never reused.
func TestRetainedCapacityMDBXObsoleteWarmCold(t *testing.T) {
	w, _, _ := riGenesis(t)
	retainedCapacityChildV1(t, w)
	retainedCapacityObsoleteV1(t, w, true)
	op := func() *mdbx.TreeOperationV1 { return retainedCapacityBoundOpV1(t, w) }
	cold, warm := retainedCapacityTwinsV1(t, w, op)
	// D10/D28 TRUE positive: x's own forward and healthy matching-parent header transfer it to
	// canonical: its header leaves E (-148) as the canonical term adds 148, body and undo stay owned.
	if cold.complete[0] != (retainedCompleteV1{5, true}) || cold.add != 148 || cold.remove != 148 || !cold.undo.oldOwned || !cold.undo.postOwned {
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
	// T10 (D15/D3/D13): one W/L-transfer op gives identical finite captures and accepted proofs warm and cold.
	wl, leave := retainedCapacityWLSideV1(t)
	cold, warm = retainedCapacityTwinsV1(t, wl, func() *mdbx.TreeOperationV1 { return retainedCapacityWLOpV1(t, wl, 2, 2, leave) })
	logicalMDBXAssert(t, cold.add == 148 && cold.remove == 148+148, "transfer capture add=%d remove=%d", cold.add, cold.remove)
	retainedCapacityAgreeV1(t, cold, warm)
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
		err := retainedCapacityPlanV1(t, w, a, dst, op, 8192)
		if _, ok := dst.binding.AfterOneCommitAttemptV1(); !ok || !a.valid || (name == "unprepared") != errors.Is(err, errRetainedShapeAPIV1) || name != "unprepared" && err != nil {
			t.Fatalf("%s: binding not reusable", name)
		}
		if c.report && !errors.Is(dst.Proof(&mdbx.TreeDeltaReportV1{}), errRetainedReportAPIV1) {
			t.Fatalf("%s: report accepted", name)
		}
		if err := a.ApplyDirectMDBX(dst, mdbx.CommitTruthNew, mdbx.UpdateStageCommitMayHaveCrossed, -1, nil, false); err != nil || !retainedCapacityClearedV1(a) || dst.accepted {
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
		read.authority.Authority = mdbx.StorageAuthorityV1{ActiveProfile: mdbx.StorageProfilePrunedV1, B: 4881, U: 4881 + 13680}
		read.endpoints[1] = mdbx.TreeEndpointV1{Kind: mdbx.TreeEndpointAppliedV1, Height: p}
		below, at := read.keepV1(retainedArtifactV1{height: p}), read.keepV1(retainedArtifactV1{height: p + 1})
		if read.bodyFirstV1() != p+1 || below.bits&2 != 0 || at.bits&2 == 0 || at.bits&4 != 0 {
			t.Fatalf("p%d: L_body %d below %b at %b", p, read.bodyFirstV1(), below.bits, at.bits)
		}
	}
	// CB 1.2 PRUNED promises: tip 20159 has (B,U)=(5040,18720), tip 20160 (5041,18721).
	old := mdbx.StorageAuthorityV1{Version: mdbx.StorageAuthorityVersionV1, ActiveProfile: mdbx.StorageProfilePrunedV1, B: 5040, U: 18720, ActiveGenerationID: 1, NextGenerationID: 2, Phase: mdbx.StoragePhaseNoneV1, Lifecycle: mdbx.StorageLifecycleStableV1}
	var read retainedReadV1
	read.roles[0].generation = 1
	read.authority.Authority = old
	read.endpoints[1] = mdbx.TreeEndpointV1{Kind: mdbx.TreeEndpointAppliedV1, Height: 4320}
	op := retainedCapacityDirectOpV1()
	op.Primitives[0].Endpoint = mdbx.TreeEndpointV1{Kind: mdbx.TreeEndpointAppliedV1, Height: 20160}
	op.Pair.Mutations = []mdbx.Mutation{btMutation(0, []byte{2}, nil)}
	f := retainedFiniteV1{read: &read, op: op}
	span := func(k mdbx.CleanupSpanKindV1, first, last uint64) []mdbx.CleanupSpanV1 {
		return []mdbx.CleanupSpanV1{{Kind: k, GenerationID: 1, FirstHeight: first, NextHeight: first, LastHeight: last}}
	}
	excluded := &mdbx.InvalidBranchV1{FirstInvalidHeight: 9, ExactConsensusError: []byte{1}}
	for name, c := range map[string]struct {
		spans    []mdbx.CleanupSpanV1
		b, u     uint64
		excluded *mdbx.InvalidBranchV1
		ok       bool
	}{
		"unchanged": {nil, 5040, 18720, nil, true}, "blocks_span": {span(mdbx.CleanupSpanBlocksV1, 4321, 4880), 5040, 18720, nil, false},
		"b_moved": {span(mdbx.CleanupSpanUndoV1, 18720, 18720), 5041, 18721, nil, true}, "b_regressed": {nil, 5039, 18719, nil, false},
		"excluded_set": {nil, 5040, 18720, excluded, false},
	} {
		f.planned.Authority = old
		f.planned.Authority.B, f.planned.Authority.U, f.planned.Authority.ExcludedInvalidBranch = c.b, c.u, c.excluded
		if c.spans != nil {
			f.planned.Authority.Phase, f.planned.Authority.Cleanup = mdbx.StoragePhasePruneGCV1, &mdbx.CleanupV1{Spans: c.spans}
		}
		logicalMDBXAssert(t, mdbx.ValidateStorageAuthorityV1(f.planned.Authority) == nil, "%s: planned authority must decode", name)
		if _, err := f.promiseV1(); (err == nil) != c.ok {
			t.Fatalf("%s: %v", name, err)
		}
	}
	read.authority.Authority.ExcludedInvalidBranch, f.planned.Authority = excluded, old
	f.planned.Authority.ExcludedInvalidBranch = &mdbx.InvalidBranchV1{FirstInvalidHeight: 9, ExactConsensusError: []byte{1}}
	_, err := f.promiseV1()
	logicalMDBXAssert(t, err == nil, "identical excluded tuple: %v", err)
	f.planned.Authority.ExcludedInvalidBranch.ExactConsensusError = []byte{2}
	_, err = f.promiseV1()
	logicalMDBXAssert(t, errors.Is(err, errRetainedFiniteAPIV1), "changed excluded tuple: %v", err)
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
		a.Authority.SelectedSide = &mdbx.SelectedSideV1{GenerationID: 3, F: 1, TipHeight: 1441, RowCount: 1439, LogicalBytes: 1439, CumulativeChainwork: [40]byte{38: 5, 39: 0xa2}}
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

// D5/D19/D20: the producer's first source result is forwarded unchanged by Plan. A selected row
// (3,1) under the live side F=0 stores a body whose anchor pair fails the complete binding (the
// producer's riBindingDefects anchor-pair row, re-parented to genesis). The cold quantity entry
// returns selected_damage carrying generation/height/hash, Artifact body and the original *TxError
// cause; Plan does no finite work, keeps the active unprepared token and caches no partial pre;
// Apply under a clean witness still invalidates (no completed pre to keep).
func TestRetainedCapacityMDBXSourceForward(t *testing.T) {
	w, _, genesis := riGenesis(t)
	commit := initial148BlockWitnessCommit(t)
	pairTx := coinbaseTxWithOutputs(0, []testOutput{bindingAnchor(commit[:], 0), bindingAnchor(make([]byte, 32), 0)})
	pair := initial148BlockFrame(t, [][]byte{pairTx}, func(h *initial148BlockHead) { h.parent = genesis })
	hash := sha3.Sum256(pair[:148])
	key, _ := mdbx.HeightKey(3, 1)
	w.pair(t, btMutation(3, hash[:], pair[:148]), btMutation(4, hash[:], pair), btMutation(6, key, mdbx.ChainValue(hash, genesis, [40]byte{39: 2})))
	riAuthority(t, w, func(a *mdbx.TreeAuthorityV1) {
		a.Authority.SelectedSide = &mdbx.SelectedSideV1{GenerationID: 3, F: 0, TipHeight: 1, TipHash: hash, RowCount: 1, LogicalBytes: uint64(len(pair)), CumulativeChainwork: [40]byte{39: 2}}
	})
	a, dst := NewRetainedAccountingV1(DefaultLimitsV1()), &DirectRetainedProofV1{}
	err := retainedCapacityPlanV1(t, w, a, dst, retainedCapacityBoundOpV1(t, w), 8192)
	var failure *RetainedProofFailureV1
	if !errors.As(err, &failure) || failure.Resource != "selected_damage" || failure.Damage == nil {
		t.Fatalf("forwarded result: %T %v", err, err)
	}
	d := failure.Damage
	cause, ok := any(d.Cause).(*TxError)
	if d.Generation != 3 || d.Height != 1 || d.Hash != hash || d.Artifact != "body" || !ok || cause.Code != BLOCK_ERR_WITNESS_COMMITMENT || cause.Msg != bindingWitnessMsg || any(failure.Cause) != any(d.Cause) {
		t.Fatalf("damage %+v cause %v", d, d.Cause)
	}
	if dst.prepared || a.active != dst || dst.pre != 0 || dst.add != 0 || dst.remove != 0 || a.valid {
		t.Fatalf("after forward: prepared=%v pre=%d add=%d valid=%v", dst.prepared, dst.pre, dst.add, a.valid)
	}
	if err := a.ApplyDirectMDBX(dst, mdbx.CommitTruthOld, mdbx.UpdateStagePrewrite, -1, err, true); err != nil || !retainedCapacityClearedV1(a) || a.active != nil || !dst.applied {
		t.Fatalf("apply forwarded refusal: %v valid=%v", err, a.valid)
	}
}

// D12: Proof allocates nothing on acceptance and on every refusal class, and
// each refusal is one preinitialized error value (the same identity on every
// call, no factory or formatter). Each measured call gets its own prebuilt
// owner/proof/report, since a token is single-entry.
func TestRetainedCapacityMDBXProofNoAlloc(t *testing.T) {
	const runs = 50
	for _, tc := range []struct {
		name   string
		lRet   uint64
		edit   func(*DirectRetainedProofV1, *mdbx.TreeDeltaReportV1)
		want   error
		accept bool
	}{
		{"accept", 1073743437, nil, nil, true},
		{"capacity", 1073743436, nil, errRetainedProofCapacity, false},
		{"report_shape", 1073743437, func(_ *DirectRetainedProofV1, r *mdbx.TreeDeltaReportV1) { r.Undo = nil }, errRetainedReportAPIV1, false},
		{"lag_present", 1073743437, func(_ *DirectRetainedProofV1, r *mdbx.TreeDeltaReportV1) { r.Lag.Present = true }, errRetainedReportAPIV1, false},
		{"used_token", 1073743437, func(p *DirectRetainedProofV1, _ *mdbx.TreeDeltaReportV1) { p.entered = true }, errRetainedProofAPIV1, false},
	} {
		proofs := make([]*DirectRetainedProofV1, runs+1)
		reports := make([]*mdbx.TreeDeltaReportV1, runs+1)
		for i := range proofs {
			proofs[i], reports[i] = retainedCapacityStructuralV1(NewRetainedAccountingV1(NewLimitsV1(1073741824, tc.lRet))), retainedCapacityReportV1()
			if tc.edit != nil {
				tc.edit(proofs[i], reports[i])
			}
		}
		next := 0
		allocs := testing.AllocsPerRun(runs, func() {
			if err := proofs[next].Proof(reports[next]); !retainedCapacitySameErrV1(err, tc.want) {
				t.Fatalf("%s call %d: %v", tc.name, next, err)
			}
			next++
		})
		if allocs != 0 || next != runs+1 || proofs[runs].accepted != tc.accept {
			t.Fatalf("%s: allocs=%v calls=%d accepted=%v", tc.name, allocs, next, proofs[runs].accepted)
		}
	}
}

// retainedCapacitySameErrV1 is identity of the preinitialized error value
// (D12): errors.Is would also admit a wrapper, which Proof must not build.
func retainedCapacitySameErrV1(got, want error) bool {
	return any(got) == any(want)
}

// The obsolete projection classifies a header read error by OLD's canonical
// header duty, as the producer's projectedV1 does: canonical_artifact_read
// when OLD canonically owns the header, otherwise branch_data.
func TestRetainedCapacityMDBXObsoleteHeaderSource(t *testing.T) {
	f := retainedFiniteV1{read: &retainedReadV1{reader: &mdbx.Reader{}}}
	for required, want := range map[uint8]string{1: "canonical_artifact_read", 0: "branch_data"} {
		var got *RetainedProofFailureV1
		_, err := f.obsoleteV1(retainedArtifactV1{required: required})
		logicalMDBXAssert(t, errors.As(err, &got) && got.Resource == want, "required %d: %v", required, err)
	}
}
