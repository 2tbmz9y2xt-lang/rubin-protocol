//go:build rubin_mdbx_fixture && cgo && (darwin || linux) && (amd64 || arm64)

package consensus

import (
	"bytes"
	"crypto/sha3"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"runtime"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/mdbx"
)

func TestRetainedCapacityMDBXCommitOutcomes(t *testing.T) {
	// Two native 20-byte entries charge 36+20 each; the 33-byte manifest key is
	// not an entry. The producer's "113" family (one 21-byte entry) is its
	// actual whole-family charge 113 (retained_image_mdbx_fixture_cgo_test.go
	// rifUndo/whole-family), read once into the sole projection.
	for variant, want := range map[string]uint64{"": 2 * (36 + 20), "113": 113} {
		t.Run("D6_D25_undo_projection_reads_actual_family"+variant, func(t *testing.T) {
			w, _, _ := riGenesis(t)
			op := retainedCapacityBoundOpV1(t, w)
			rifFamily(t, w, op.Primitives[0].Block, op.Primitives[0].Height, 2, variant)
			a, dst := NewRetainedAccountingV1(DefaultLimitsV1()), &DirectRetainedProofV1{}
			if err := retainedCapacityPlanV1(t, w, a, dst, op, 8192); err != nil || !dst.prepared {
				t.Fatalf("plan: %v", err)
			}
			if dst.undo.block != op.Primitives[0].Block || dst.undo.oldCharge != want {
				t.Fatalf("family projection %+v add=%d", dst.undo, dst.add)
			}
			// The UndoWriteOrReuse op over x's present family is reported Kept with its two entries (tree_delta.go
			// familyEffectV1 Refer): x's family is acquired once (S+56, Tree 100->270, J+112, header 148, body 298, family).
			logicalMDBXAssert(t, dst.Proof(retainedCapacityGrowV1(dst, mdbx.TreeUndoChargeV1{Effect: mdbx.TreeUndoFamilyKeptV1, Entries: 2, Bytes: want})) == nil && dst.post == dst.pre+784+want, "post %d pre %d", dst.post, dst.pre)
		})
	}
	// D10/D28 under a FALSE fact: a raw index row (5,2) without reverse
	// leaves generation 5 incomplete. A positive own forward with a healthy
	// matching-parent header still transfers x; a negative membership is
	// branch_data with no post and the active unprepared token kept.
	for name, member := range map[string]bool{"D10_positive_false": true, "D10_negative_false": false} {
		t.Run(name, func(t *testing.T) {
			w, _, _ := riGenesis(t)
			x, _ := retainedCapacityChildV1(t, w)
			retainedCapacityObsoleteV1(t, w, member)
			rifForward(t, w, 5, 2, [32]byte{9}, x)
			op := retainedCapacityBoundOpV1(t, w)
			a, dst := NewRetainedAccountingV1(DefaultLimitsV1()), &DirectRetainedProofV1{}
			err := retainedCapacityPlanV1(t, w, a, dst, op, 8192)
			if dst.complete[0] != (retainedCompleteV1{5, false}) {
				t.Fatalf("fact %+v", dst.complete)
			}
			if member {
				if err != nil || !dst.prepared || dst.add != 148 || dst.remove != 148 || !dst.undo.oldOwned {
					t.Fatalf("positive: %v add=%d remove=%d undo=%+v", err, dst.add, dst.remove, dst.undo)
				}
				return
			}
			var failure *RetainedProofFailureV1
			if !errors.As(err, &failure) || failure.Resource != "branch_data" || dst.prepared || a.active != dst || dst.add != 0 {
				t.Fatalf("negative: %v prepared=%v", err, dst.prepared)
			}
		})
	}
	t.Run("D4_D23_native_commit_and_companion", retainedCapacityNativeCommitV1)
	t.Run("T18_w_row_beside_pending_side", retainedCapacityWBesidePendingV1)
	t.Run("D4_native_frame_R_boundaries", retainedCapacityNativeBoundsV1)
	t.Run("T19_rolling_merge_full_plan_proof", retainedCapacityRollingMergeV1)
	t.Run("G7_D15_obsolete_leaving_header_family", func(t *testing.T) {
		w, leave := retainedCapacityWLSideV1(t)
		retainedCapacityObsoleteYV1(t, w, [32]byte(leave.Key))
		rifFamily(t, w, [32]byte(leave.Key), 2, 2, "")
		a, dst := NewRetainedAccountingV1(DefaultLimitsV1()), &DirectRetainedProofV1{}
		err := retainedCapacityPlanV1(t, w, a, dst, retainedCapacityWLOpV1(t, w, 2, 2, leave), 8192)
		// y's header 148 and its projection-only family 2*(36+20) leave E beside x's W header 148.
		logicalMDBXAssert(t, err == nil && dst.prepared && dst.add == 148 && dst.remove == 296+2*(36+20), "plan: %v add=%d remove=%d", err, dst.add, dst.remove)
		logicalMDBXAssert(t, dst.Proof(retainedCapacityGrowV1(dst, mdbx.TreeUndoChargeV1{Effect: mdbx.TreeUndoFamilyWrittenV1, Entries: 1, Bytes: 56})) == nil && dst.accepted, "proof")
	})
	t.Run("D3_D14_D18_native_callback_refusal_witness_warm_no_cold_row", retainedCapacityCallbackRefusalV1)
	t.Run("D14_native_fault_tuples", retainedCapacityFaultTuplesV1)
	t.Run("D14_native_unwinds", retainedCapacityUnwindsV1)
	t.Run("D5_D20_D27_H1_canonical_absence_first", retainedCapacityAbsentFirstV1)
	t.Run("D21_D22_optional_absent_and_malformed", retainedCapacityOptionalV1)
	t.Run("D26_external_drain", retainedCapacityDrainV1)
	t.Run("D24_completed_key_first_result", retainedCapacityCompletedKeyV1)
	t.Run("D28_D14_native_qualified_header_slot", retainedCapacityHeaderSlotV1)
	t.Run("D3_D13_reopen_reconstructs", retainedCapacityReopenV1)
	t.Run("D16_planned_aggregate_1440", retainedCapacityAggregateV1)
	t.Run("D3_warm_ARCHIVE16385_no_cold_row", retainedCapacityWarmArchiveV1)
	t.Run("D12_exact_admission_success_restores", retainedCapacityExactAdmitV1)
	t.Run("D14_clean_witness_tuple_conjuncts", retainedCapacityWitnessTupleV1)
}

// retainedCapacityWarmCacheV1 installs the producer's completed cold pre
// (binding, Ret, facts) as the cache, marked by +7.
func retainedCapacityWarmCacheV1(t *testing.T, w *btWorld, a *RetainedAccountingV1) uint64 {
	t.Helper()
	pre, err := riRead(t, w, nil)
	logicalMDBXAssert(t, err == nil, "cold pre: %v", err)
	a.binding, a.exactRet, a.complete, a.valid = pre.binding, pre.exactRet+7, pre.complete, true
	return pre.exactRet
}

// D3 on the producer's ARCHIVE 16385-height store (riArchive, scalar
// 9143051): the warm Plan uses the cached value and never reaches the
// genesis body, a row only the cold visit reads (arm unreached).
func retainedCapacityWarmArchiveV1(t *testing.T) {
	w := riChain(t, 16385)
	riAuthority(t, w, func(a *mdbx.TreeAuthorityV1) { a.Authority.ActiveProfile, a.Authority.U = 2, 16385 })
	op := retainedCapacityBoundOpV1(t, w)
	a := NewRetainedAccountingV1(DefaultLimitsV1())
	cold := retainedCapacityWarmCacheV1(t, w, a)
	logicalMDBXAssert(t, cold == 9143051, "ARCHIVE scalar %d", cold)
	genesis := sha3.Sum256(initial148BlockGenesis(t)[:148])
	dst := &DirectRetainedProofV1{}
	evidence, harness := mdbx.FixtureSelectedDamage(w.s, w.owner, mdbx.SelectedDamageGetEIO, 4, genesis[:], func() {
		logicalMDBXAssert(t, retainedCapacityPlanV1(t, w, a, dst, op, 8192) == nil, "warm ARCHIVE plan")
	})
	logicalMDBXAssert(t, harness != nil && evidence.Faults == 0 && dst.pre == 9143051+7, "warm ARCHIVE: %+v/%v pre=%d", evidence, harness, dst.pre)
}

// D12 exact/cost-1 with a successful warm Plan: the caller holds lane 402653184 minus the temporary
// frame 4480400 and the shared body frame 136463310 (resource_boundary); Plan succeeds, both are
// free again when Plan returns (the same grant fits beside the held cost) and the returned proof
// stays callable. One byte more held is denied.
func retainedCapacityExactAdmitV1(t *testing.T) {
	const exactHeld = 402653184 - 4480400 - 136463310
	for _, held := range []uint64{exactHeld, exactHeld + 1} {
		w, _, _ := riGenesis(t)
		op := retainedCapacityBoundOpV1(t, w)
		a, dst := NewRetainedAccountingV1(DefaultLimitsV1()), &DirectRetainedProofV1{}
		retainedCapacityWarmCacheV1(t, w, a)
		var plan, again error
		err := w.owner.WithOperation(mdbx.TreeOperation, func(account *mdbx.OperationAccount) error {
			return account.WithReservation(held, func() error {
				err := w.s.View(func(r *mdbx.Reader) error { plan = a.PlanDirectMDBX(dst, r, account, op); return nil })
				again = account.WithReservation(4480400+136463310, func() error { return nil })
				return err
			})
		})
		btReservationsReleased(t, w.owner)
		exact := held == exactHeld
		if err != nil || (plan == nil) != exact || dst.prepared != exact || (again == nil) != exact {
			t.Fatalf("held %d: plan=%v again=%v prepared=%v", held, plan, again, dst.prepared)
		}
		if exact {
			logicalMDBXAssert(t, dst.Proof(retainedCapacityGrowV1(dst, mdbx.TreeUndoChargeV1{})) == nil && dst.accepted, "proof after Plan returned")
		}
	}
}

// Clean witness: a completed pre survives a clean callback refusal only on
// OLD/Prewrite/-1; changing exactly one literal (NEW, WriteStarted, index 0)
// with everything else equal retires it; NEW before the commit, outside the
// native failure union, is also the local API failure.
func retainedCapacityWitnessTupleV1(t *testing.T) {
	for _, c := range []struct {
		truth mdbx.CommitTruth
		stage mdbx.UpdateStage
		index int
		keep  bool
	}{
		{mdbx.CommitTruthOld, mdbx.UpdateStagePrewrite, -1, true},
		{mdbx.CommitTruthNew, mdbx.UpdateStagePrewrite, -1, false},
		{mdbx.CommitTruthOld, mdbx.UpdateStageWriteStartedDefinitelyPrecommit, -1, false},
		{mdbx.CommitTruthOld, mdbx.UpdateStagePrewrite, 0, false},
	} {
		w, child, x := retainedCapacitySideFrameV1(t)
		a, dst := NewRetainedAccountingV1(DefaultLimitsV1()), &DirectRetainedProofV1{}
		refuse := errors.New("callback refusal")
		res := retainedCapacityShapedV1(t, w, a, dst, child, x, false, false, func(*mdbx.Reader, *mdbx.TreeOperationV1) error { return refuse })
		logicalMDBXAssert(t, a.valid && a.exactRet == 1077 && !dst.entered, "completed pre")
		if err := a.ApplyDirectMDBX(dst, c.truth, c.stage, c.index, res.err, true); errors.Is(err, errRetainedApplyAPIV1) != (c.truth == mdbx.CommitTruthNew) || a.valid != c.keep || a.active != nil {
			t.Fatalf("%+v: %v valid=%v", c, err, a.valid)
		}
	}
}

// D16: a planned authority whose detached count field says 1441 (> the
// selected/detached/SIDE aggregate 1440, authority_decode.go count16) is
// refused by the single planned decode before any finite work or extra
// grant; the unchanged planned bytes (control) prove.
func retainedCapacityAggregateV1(t *testing.T) {
	for _, over := range []bool{false, true} {
		w, _, _, y, encoded := retainedCapacityOptionalFrameV1(t, 298)
		at := bytes.Index(encoded, append(binary.BigEndian.AppendUint64([]byte{0, 1}, 1), y[:]...))
		logicalMDBXAssert(t, at > 0, "detached count field")
		planned := bytes.Clone(encoded)
		if over {
			binary.BigEndian.PutUint16(planned[at:], 1441)
		}
		op := retainedCapacityBoundOpV1(t, w)
		meta := btMutation(0, []byte{2}, planned)
		meta.BeforePresent = true
		op.Pair.Mutations = append([]mdbx.Mutation{meta}, op.Pair.Mutations...)
		a, dst := NewRetainedAccountingV1(DefaultLimitsV1()), &DirectRetainedProofV1{}
		err := retainedCapacityPlanV1(t, w, a, dst, op, 8192)
		refused := errors.Is(err, errRetainedShapeAPIV1) && dst.pre == 0 && dst.roles == [2]retainedRoleV1{}
		if over != refused || over == (err == nil) || dst.prepared == over || a.active != dst {
			t.Fatalf("over=%v: %v prepared=%v", over, err, dst.prepared)
		}
	}
}

// D3/D13 "reopen": a kept pre (marked 1077+7) does not survive a reopen of
// the same store; the next Plan reconstructs the fresh 1077 once and proves
// 1596.
func retainedCapacityReopenV1(t *testing.T) {
	w, child, x := retainedCapacitySideFrameV1(t)
	a, dst := NewRetainedAccountingV1(DefaultLimitsV1()), &DirectRetainedProofV1{}
	res := retainedCapacityShapedV1(t, w, a, dst, child, x, false, false, func(*mdbx.Reader, *mdbx.TreeOperationV1) error { return errors.New("refuse") })
	logicalMDBXAssert(t, a.ApplyDirectMDBX(dst, res.truth, res.stage, res.index, res.err, true) == nil && a.valid, "kept pre")
	a.exactRet = 1077 + 7
	w.reopen(t)
	verr, _ := w.s.StartupVerifyCanonicalV1(func(r *mdbx.Reader) (mdbx.StartupCanonicalCompletionV1, error) {
		return mdbx.StartupCanonicalActiveAndReplayCompleteV1, retainedCapacityLagReadV1(r)
	})
	logicalMDBXAssert(t, verr == nil, "reopen qualification: %v", verr)
	next := &DirectRetainedProofV1{}
	res = retainedCapacityCommitV1(t, w, a, next, child, x, false)
	res.want(t, 2, 3, -1)
	logicalMDBXAssert(t, res.err == nil && next.pre == 1077 && next.post == 1596, "after reopen: %v pre=%d", res.err, next.pre)
}

// D28 through actual UpdateTreeV1 on the recipe SIDE frame: the qualified HeaderSlot of the bound
// child x (Pair without a header-x row) contributes 0 to the pre 1077 and +148 once to the post
// 1596 (native_fixture_recipe); the slot inserts x and a fresh enumeration agrees. D14 "Proof nil
// then HeaderSlot error": a different stored row x makes the native slot refuse after an accepted
// Proof with StateMismatch -30779 "tree header slot differs" (RUB-1750, tree_stream_cgo.go:117-127)
// at OLD/Prewrite/-1 with no write; Apply returns nil and invalidates.
func retainedCapacityHeaderSlotV1(t *testing.T) {
	for _, differ := range []bool{false, true} {
		w, child, x := retainedCapacitySideFrameV1(t)
		other := bytes.Clone(child[:148])
		other[147] ^= 1
		if differ {
			rifSeed(t, w, 3, x[:], other)
		}
		a, dst := NewRetainedAccountingV1(DefaultLimitsV1()), &DirectRetainedProofV1{}
		res := retainedCapacityShapedV1(t, w, a, dst, child, x, false, true, func(_ *mdbx.Reader, op *mdbx.TreeOperationV1) error { op.Proof = dst.Proof; return nil })
		if dst.pre != 1077 || !dst.accepted || dst.post != 1596 {
			t.Fatalf("differ=%v slot proof: pre=%d post=%d accepted=%v", differ, dst.pre, dst.post, dst.accepted)
		}
		if !differ {
			res.want(t, 2, 3, -1)
			logicalMDBXAssert(t, res.err == nil && a.ApplyDirectMDBX(dst, res.truth, res.stage, res.index, res.err, false) == nil && a.valid && a.exactRet == 1596, "slot commit: %v", res.err)
			equal, err := mdbx.FixtureRawRowEqual(w.s, 3, x[:], child[:148])
			cold, cerr := riRead(t, w, nil)
			logicalMDBXAssert(t, err == nil && equal && cerr == nil && cold.exactRet == 1596, "slot insert %v/%v, fresh %d", equal, err, cold.exactRet)
			continue
		}
		res.want(t, 1, 1, -1)
		var engine *mdbx.EngineError
		if !errors.As(res.err, &engine) || engine.Class != mdbx.EngineStateMismatch || engine.Code != -30779 || engine.Diagnostic != "tree header slot differs" {
			t.Fatalf("slot refusal %T %v", res.err, res.err)
		}
		if err := a.ApplyDirectMDBX(dst, res.truth, res.stage, res.index, res.err, false); err != nil || a.valid || a.active != nil || !dst.applied {
			t.Fatalf("slot refusal apply: %v valid=%v", err, a.valid)
		}
		// The slot refusal takes the consuming route; the row is read after reopen.
		_, closed := mdbx.FixtureRawRowEqual(w.s, 3, x[:], other)
		w.reopen(t)
		equal, err := mdbx.FixtureRawRowEqual(w.s, 3, x[:], other)
		logicalMDBXAssert(t, closed != nil && err == nil && equal, "row x after refusal: closed=%v %v", closed, err)
	}
	// D28 "no stored header x through initializer/finite/shared probes": a one-shot Get EIO armed on headers-v1 x. The slot
	// op proves 1596 with no Plan read of x, and the native slot read after Proof meets the fault (OLD/Prewrite/-1, EIO); the
	// nil-slot op's Pair inserts x, so Plan's ordinary route reads it first: that EIO, no Proof (selectivity control).
	for _, slot := range []bool{true, false} {
		w, child, x := retainedCapacitySideFrameV1(t)
		a, dst := NewRetainedAccountingV1(DefaultLimitsV1()), &DirectRetainedProofV1{}
		var res btResult
		evidence, harness := mdbx.FixtureSelectedDamage(w.s, w.owner, mdbx.SelectedDamageGetEIO, 3, x[:], func() {
			res = retainedCapacityShapedV1(t, w, a, dst, child, x, false, slot, func(_ *mdbx.Reader, op *mdbx.TreeOperationV1) error { op.Proof = dst.Proof; return nil })
		})
		var engine *mdbx.EngineError
		read := harness == nil && evidence.Faults == 1 && res.truth == 1 && res.stage == 1 && res.index == -1 && errors.As(res.err, &engine) && engine.Class == mdbx.EngineIO
		if !read || dst.pre != 1077 || dst.accepted != slot || dst.prepared != slot || evidence.BeginWrite != map[bool]uint64{true: 1}[slot] || slot && dst.post != 1596 {
			t.Fatalf("slot=%v header x read: %+v/%v %v accepted=%v post=%d", slot, evidence, harness, res.err, dst.accepted, dst.post)
		}
	}
	// D28/direct-shape: a BodyKind 1 literal of x whose body is SIDE-owned before is a redundant write, refused.
	w, child, x := retainedCapacitySideFrameV1(t)
	op := retainedCapacityBoundOpV1(t, w)
	p := &op.Primitives[0]
	p.Block, p.Coverage.Block, p.Coverage.BodyKind, p.Coverage.CurrentBody = x, x, 1, child
	op.Pair.Mutations = append(retainedCapacityIndexV1(1, 1, x, [32]byte(child[4:36])), btMutation(4, x[:], child))
	a, dst := NewRetainedAccountingV1(DefaultLimitsV1()), &DirectRetainedProofV1{}
	err := retainedCapacityPlanV1(t, w, a, dst, op, 8192)
	logicalMDBXAssert(t, errors.Is(err, errRetainedFiniteAPIV1) && dst.pre == 1077 && !dst.prepared && a.active == dst, "redundant SIDE body literal: %v pre=%d", err, dst.pre)
}

// T18 (rejected_cases): a W row beside the rolling-prepared pending SIDE. The stored selected side of generation 3 has one
// row at 5 (F 4, f 5) whose SideLink names x; the OLD authority in this read carries the pending SIDE(3,4,4,4) (MP 1422-1426).
// The shape is structural-only (MP 2984-2986, 3047-3056, 1408-1411), and so is x's stored work 6: x is genesis's child
// (MP 2817 work 2); the read checks only 0<W<=2^288. restV1 reads the actual SideLink through optionalAtV1, finds x as W,
// and the L merge is refused; the same read with a non-W block admits the merge SIDE(3,4,5,4) (selectivity control).
func retainedCapacityWBesidePendingV1(t *testing.T) {
	w, _, genesis := riGenesis(t)
	raw := initial148BlockFrame(t, [][]byte{initial148BlockGenesisTx(t)}, func(h *initial148BlockHead) { h.parent = genesis })
	x := retainedCapacitySelectedV1(t, w, raw, 5)
	span := func(first, last uint64) mdbx.CleanupSpanV1 {
		return mdbx.CleanupSpanV1{Kind: mdbx.CleanupSpanSideV1, GenerationID: 3, FirstHeight: first, NextHeight: 4, LastHeight: last}
	}
	for name, c := range map[string]struct {
		block [32]byte
		ok    bool
	}{"w_row": {x, false}, "no_w": {[32]byte{1}, true}} {
		err := riContext(t, w, nil, func(read *retainedReadV1) error {
			old := read.authority
			defer func() { read.authority = old }()
			read.authority.Authority.Cleanup = &mdbx.CleanupV1{Spans: []mdbx.CleanupSpanV1{span(4, 4)}}
			fin := retainedFiniteV1{read: read, op: &mdbx.TreeOperationV1{Primitives: []mdbx.TreePrimitiveV1{{Height: 5, Block: c.block}}}}
			fin.planned.Authority.Cleanup = &mdbx.CleanupV1{Spans: []mdbx.CleanupSpanV1{span(4, 5)}}
			transfer, err := fin.optionalPlanV1()
			if (err == nil) != c.ok || err != nil && !errors.Is(err, errRetainedFiniteAPIV1) || transfer != c.ok {
				t.Fatalf("%s: transfer=%v err=%v", name, transfer, err)
			}
			return nil
		})
		logicalMDBXAssert(t, err == nil, "%s context: %v", name, err)
	}
}

// retainedCapacityNativeChildV1 is the recipe child of genesis: the genesis
// tx with one P2PK key-hash byte changed, so it creates a second 89-byte
// entry; its 298-byte body is stored unowned under x (BodyKind 2 source).
func retainedCapacityNativeChildV1(t *testing.T, w *btWorld, parent [32]byte, flip byte) ([]byte, [32]byte) {
	t.Helper()
	tx := initial148BlockGenesisTx(t)
	at := bytes.Index(tx, []byte{0x84, 0x48, 0xb9, 0x1b, 0x88, 0xd1, 0xa6, 0xfb})
	logicalMDBXAssert(t, at > 0, "genesis P2PK key hash")
	tx[at] ^= flip
	child := initial148BlockFrame(t, [][]byte{tx}, func(h *initial148BlockHead) { h.parent, h.timestamp = parent, h.timestamp+uint64(flip)-1 })
	x := sha3.Sum256(child[:148])
	logicalMDBXAssert(t, len(child) == 298 && ValidateInitial148BlockBodyCommitments(child) == nil, "child body")
	w.pair(t, btMutation(4, x[:], child))
	return child, x
}

func retainedCapacityRolesV1(t *testing.T, w *btWorld) ([2]retainedRoleV1, [2]mdbx.TreeEndpointV1) {
	t.Helper()
	var roles [2]retainedRoleV1
	var ends [2]mdbx.TreeEndpointV1
	err := riContext(t, w, nil, func(read *retainedReadV1) error {
		err := readRetainedRolesV1(read)
		roles, ends = read.roles, read.endpoints
		return err
	})
	logicalMDBXAssert(t, err == nil, "roles: %v", err)
	return roles, ends
}

// retainedCapacityCommitV1 plans inside the actual UpdateTreeV1 callback,
// installs op.Proof and returns the raw native tuple; lag adds a natively
// admissible LagForward companion at j=1.
func retainedCapacityCommitV1(t *testing.T, w *btWorld, a *RetainedAccountingV1, dst *DirectRetainedProofV1, child []byte, x [32]byte, lag bool) btResult {
	t.Helper()
	return retainedCapacityShapedV1(t, w, a, dst, child, x, lag, false, func(_ *mdbx.Reader, op *mdbx.TreeOperationV1) error { op.Proof = dst.Proof; return nil })
}

// retainedCapacityShapedV1 builds the bound op at height 1 for a child of
// genesis, else 2 (no store read); slot replaces the Pair's header insert of x
// with the qualified HeaderSlot{x, child[:148]}.
func retainedCapacityShapedV1(t *testing.T, w *btWorld, a *RetainedAccountingV1, dst *DirectRetainedProofV1, child []byte, x [32]byte, lag, slot bool, finish func(*mdbx.Reader, *mdbx.TreeOperationV1) error) btResult {
	t.Helper()
	var result btResult
	h := uint64(1)
	if [32]byte(child[4:36]) != sha3.Sum256(initial148BlockGenesis(t)[:148]) {
		h = 2
	}
	err := w.owner.WithOperation(mdbx.TreeOperation, func(account *mdbx.OperationAccount) error {
		return account.WithReservation(2<<20, func() error {
			result.truth, result.stage, result.index, result.err = w.s.UpdateTreeV1(account, func(r *mdbx.Reader) (mdbx.TreeOperationV1, error) {
				req := btRequest(child, h)
				req.BodyKind, req.Raw, req.Kind = 2, nil, mdbx.TreeKindDirectApplyV1
				req.Endpoint.CumulativeChainwork = [40]byte{39: byte(h + 1)}
				source := new(blockTreeSourceV1)
				effect, err := prepareBlockTreeEffectV1(source, r, account, req)
				if err != nil {
					return mdbx.TreeOperationV1{}, err
				}
				op := mdbx.TreeOperationV1{Primitives: []mdbx.TreePrimitiveV1{effect.Primitive}}
				if lag {
					companion := effect.Primitive
					companion.Kind, companion.Generation = mdbx.TreeKindLagForwardV1, 2
					op.Primitives = append(op.Primitives, companion)
				}
				op.Pair.Mutations = append([]mdbx.Mutation{}, effect.Index[:]...)
				if slot {
					op.HeaderSlot = &mdbx.TreeHeaderSlotV1{Hash: x, Header: [148]byte(child[:148])}
				} else {
					op.Pair.Mutations = append(op.Pair.Mutations, btMutation(3, bytes.Clone(x[:]), bytes.Clone(child[:148])))
				}
				btSort(op.Pair.Mutations)
				if err := a.PlanDirectMDBX(dst, r, account, &op); err != nil {
					return mdbx.TreeOperationV1{}, err
				}
				if err := finish(r, &op); err != nil {
					return mdbx.TreeOperationV1{}, err
				}
				return op, nil
			})
			return nil
		})
	})
	logicalMDBXAssert(t, err == nil, "commit account: %v", err)
	btReservationsReleased(t, w.owner)
	return result
}

// D4/D23 through actual UpdateTreeV1 (native_fixture_recipe): pre 779 is the recipe's setup value
// without SIDE (CURRENT 89+100+112, LAG 32, header 148, genesis body 298); post 1596 (CURRENT
// 178+270+224, LAG 32, headers 296, bodies 596). The LAG role is untouched; a LagForward companion
// is refused by Plan before any work and the next Plan reconstructs once.
func retainedCapacityNativeCommitV1(t *testing.T) {
	w, _, genesis := riGenesis(t)
	child, x := retainedCapacityNativeChildV1(t, w, genesis, 1)
	// Seed the later D3/D13 op's unowned body now, so building it is no commit.
	retainedCapacityChildV1(t, w)
	rolesBefore, endsBefore := retainedCapacityRolesV1(t, w)
	a := NewRetainedAccountingV1(DefaultLimitsV1())
	retainedCapacityLagEmptyV1(t, w)
	retainedCapacityCompanionV1(t, w, a, child, x)
	// The one-CURRENT op: cold pre 779, Proof accepts post 1596, NEW/nil commit.
	dst := &DirectRetainedProofV1{}
	res := retainedCapacityCommitV1(t, w, a, dst, child, x, false)
	res.want(t, 2, 3, -1)
	if res.err != nil || dst.pre != 779 || !dst.accepted || dst.post != 1596 {
		t.Fatalf("direct commit: %v pre=%d post=%d accepted=%v", res.err, dst.pre, dst.post, dst.accepted)
	}
	if err := a.ApplyDirectMDBX(dst, res.truth, res.stage, res.index, res.err, false); err != nil || !dst.applied || a.active != nil {
		t.Fatalf("apply success: %v", err)
	}
	logicalMDBXAssert(t, a.valid && a.exactRet == 1596, "cached successor %d/%v", a.exactRet, a.valid)
	cold, err := riRead(t, w, nil)
	logicalMDBXAssert(t, err == nil && cold.exactRet == 1596, "fresh post enumeration %d: %v", cold.exactRet, err)
	retainedCapacityReuseV1(t, w, a)
	retainedCapacityLagKeptV1(t, w, rolesBefore, endsBefore)
}

// retainedCapacityCompanionV1: the [CURRENT, LagForward] op is the invalid
// initial count/kind control: no token, no native write (OLD/Prewrite/-1),
// and Apply of that tuple is the not-active failure that invalidates.
func retainedCapacityCompanionV1(t *testing.T, w *btWorld, a *RetainedAccountingV1, child []byte, x [32]byte) {
	t.Helper()
	refused := &DirectRetainedProofV1{}
	res := retainedCapacityCommitV1(t, w, a, refused, child, x, true)
	res.want(t, 1, 1, -1)
	if !retainedCapacitySameErrV1(res.err, errRetainedPlanAPIV1) || a.active != nil || refused.owner != nil || refused.entered || refused.pre != 0 || refused.roles != ([2]retainedRoleV1{}) {
		t.Fatalf("companion: %v active=%v", res.err, a.active)
	}
	if err := a.ApplyDirectMDBX(refused, res.truth, res.stage, res.index, res.err, true); !errors.Is(err, errRetainedApplyAPIV1) || a.valid {
		t.Fatalf("companion apply: %v", err)
	}
}

// retainedCapacityLagEmptyV1: the LAG generation 2 root binding, counter
// bytes and both canonical index keysets equal the seeded empty role, and its
// state-map (utxo-v1) and tree-node-v1 keysets are empty.
func retainedCapacityLagEmptyV1(t *testing.T, w *btWorld) {
	t.Helper()
	err := w.s.View(retainedCapacityLagReadV1)
	logicalMDBXAssert(t, err == nil, "LAG role bytes: %v", err)
}

func retainedCapacityLagReadV1(r *mdbx.Reader) error {
	if err := riEmptyRole(r, 2); err != nil {
		return err
	}
	for _, rank := range []uint8{1, 8} {
		if n, err := retainedCapacityRowsV1(r, rank, 2); err != nil || n != 0 {
			return fmt.Errorf("LAG rank%d rows %d: %w", rank, n, err)
		}
	}
	return nil
}

// retainedCapacityRowsV1 counts the generation-g prefix rows of one rank.
func retainedCapacityRowsV1(r *mdbx.Reader, rank uint8, g uint64) (int, error) {
	page, err := r.PrefixPage(mdbx.TreeSchemaV1DBIs()[rank], binary.BigEndian.AppendUint64(nil, g), nil, 64, 1<<20)
	return len(page.Rows), err
}

func retainedCapacityReuseV1(t *testing.T, w *btWorld, a *RetainedAccountingV1) {
	t.Helper()
	// D3: the successor binding is reused with no cold visit (a marked cache
	// value is observed); D13: an intervening native commit of another kind
	// advances the epoch and the next Plan reconstructs once.
	a.exactRet = 1596 + 7
	warm := &DirectRetainedProofV1{}
	err := retainedCapacityPlanV1(t, w, a, warm, retainedCapacityBoundOpV1(t, w), 8192)
	logicalMDBXAssert(t, err == nil && warm.prepared && warm.pre == 1596+7 && a.valid, "warm successor pre %d", warm.pre)
	logicalMDBXAssert(t, a.ApplyDirectMDBX(warm, mdbx.CommitTruthOld, mdbx.UpdateStagePrewrite, -1, errors.New("callback"), true) == nil, "warm apply")
	a.exactRet = 1596 + 7
	riAuthority(t, w, func(*mdbx.TreeAuthorityV1) {}) // an intervening Pair-only native commit
	next := &DirectRetainedProofV1{}
	err = retainedCapacityPlanV1(t, w, a, next, retainedCapacityBoundOpV1(t, w), 8192)
	logicalMDBXAssert(t, err == nil && next.prepared, "reconstruction plan: %v", err)
	fresh, err := riRead(t, w, nil)
	logicalMDBXAssert(t, err == nil && next.pre == fresh.exactRet && next.pre != 1596+7, "reconstruction pre %d fresh %d", next.pre, fresh.exactRet)
}

// retainedCapacityLagKeptV1: the persisted LAG role and endpoint read back
// unchanged after the commit and after reopen; CURRENT went 89/1 -> 178/2.
func retainedCapacityLagKeptV1(t *testing.T, w *btWorld, rolesBefore [2]retainedRoleV1, endsBefore [2]mdbx.TreeEndpointV1) {
	t.Helper()
	retainedCapacityLagEmptyV1(t, w)
	rolesAfter, endsAfter := retainedCapacityRolesV1(t, w)
	// After reopen the test qualifies the committed pair itself (the startup
	// owner is outside this issue); the LAG role must read back unchanged.
	w.reopen(t)
	verr, cached := w.s.StartupVerifyCanonicalV1(func(r *mdbx.Reader) (mdbx.StartupCanonicalCompletionV1, error) {
		return mdbx.StartupCanonicalActiveAndReplayCompleteV1, retainedCapacityLagReadV1(r)
	})
	logicalMDBXAssert(t, verr == nil && !cached, "reopen qualification: %v/%v", verr, cached)
	if rolesReopen, endsReopen := retainedCapacityRolesV1(t, w); rolesReopen != rolesAfter || endsReopen != endsAfter {
		t.Fatalf("reopen roles %+v/%+v differ from %+v/%+v", rolesReopen, endsReopen, rolesAfter, endsAfter)
	}
	if rolesAfter[1] != rolesBefore[1] || endsAfter[1] != endsBefore[1] {
		t.Fatalf("LAG changed: %+v/%+v -> %+v/%+v", rolesBefore[1], endsBefore[1], rolesAfter[1], endsAfter[1])
	}
	err := w.s.View(func(r *mdbx.Reader) error {
		state, err := retainedCapacityRowsV1(r, 1, 1)
		nodes, nerr := retainedCapacityRowsV1(r, 8, 1)
		if err != nil || nerr != nil || state != 2 || nodes == 0 {
			return fmt.Errorf("CURRENT state %d nodes %d: %w %w", state, nodes, err, nerr)
		}
		return nil
	})
	logicalMDBXAssert(t, err == nil, "CURRENT rows (selectivity control): %v", err)
	if rolesBefore[0].s != 89 || rolesBefore[0].n != 1 || rolesAfter[0].s != 178 || rolesAfter[0].n != 2 || rolesAfter[0].generation != rolesBefore[0].generation {
		t.Fatalf("CURRENT %+v -> %+v", rolesBefore[0], rolesAfter[0])
	}
}

// T19 (D2/D15/D17): the rolling-prepared OLD shape of the RUB-1594 A1 witness: H_old=F=0, live
// one-slot selected side [2,1440] (1439 rows, f 2 >= F+2, MP 1408-1411) and pending SIDE(3,1,1,1)
// owing the candidate x at f-1 (MP 1422-1426). The direct op at 1 has W empty and merges L=[2,1440]
// into SIDE(3,1,1440,1) with first and next kept (MP 2539-2541, DIRECT 3800-3805), and the full
// Plan/Proof path accepts it. x's header is the canonical +148; each of the 1439 L headers leaves the selected
// owner (SIDE body only) and is deleted in the Pair (MP 2550-2557), so remove is 148*1439; bodies stay owned. SIDE(3,2,1440,2)
// and SIDE(3,1,1440,2) are refused.
func retainedCapacityRollingMergeV1(t *testing.T) {
	for name, c := range map[string]struct {
		first, next uint64
		ok          bool
	}{"merge": {1, 1, true}, "first_moved": {2, 2, false}, "next_moved": {1, 2, false}} {
		t.Run(name, func(t *testing.T) {
			w, x, leave := retainedCapacityRollingV1(t)
			op := retainedCapacityBoundOpV1(t, w)
			logicalMDBXAssert(t, op.Primitives[0].Block == x && op.Primitives[0].Height == 1, "candidate op")
			retainedCapacityMergeAuthorityV1(t, w, op, c.first, c.next)
			op.Pair.Mutations = append(op.Pair.Mutations, leave...)
			a, dst := NewRetainedAccountingV1(DefaultLimitsV1()), &DirectRetainedProofV1{}
			err := retainedCapacityPlanV1(t, w, a, dst, op, 8192)
			if !c.ok {
				if !errors.Is(err, errRetainedFiniteAPIV1) || dst.prepared || a.active != dst {
					t.Fatalf("refusal: %v prepared=%v", err, dst.prepared)
				}
				return
			}
			if err != nil || !dst.prepared || dst.add != 148 || dst.remove != 148*1439 {
				t.Fatalf("merge plan: %v add=%d remove=%d", err, dst.add, dst.remove)
			}
			if err := dst.Proof(retainedCapacityGrowV1(dst, mdbx.TreeUndoChargeV1{Effect: mdbx.TreeUndoFamilyWrittenV1, Entries: 1, Bytes: 56})); err != nil || !dst.accepted {
				t.Fatalf("merge proof: %v", err)
			}
		})
	}
}

// retainedCapacityRollingV1 stores the candidate x's body and SideLink (3,1), the 1439 chained selected rows 2..1440
// (W_h=h+1, MP 1462-1464, 2817) and the OLD authority; it returns the L header deletions the merge owes (MP 2550-2557).
func retainedCapacityRollingV1(t *testing.T) (*btWorld, [32]byte, []mdbx.Mutation) {
	t.Helper()
	w, _, genesis := riGenesis(t)
	x, _ := retainedCapacityChildV1(t, w)
	link, _ := mdbx.HeightKey(3, 1)
	rows := []mdbx.Mutation{btMutation(6, link, mdbx.ChainValue(x, genesis, [40]byte{39: 2}))}
	parent, tip, leave := x, [32]byte{}, []mdbx.Mutation(nil)
	for h := uint64(2); h <= 1440; h++ {
		y := initial148BlockFrame(t, [][]byte{initial148BlockGenesisTx(t)}, func(b *initial148BlockHead) { b.parent, b.timestamp = parent, blockStepsMedian+h })
		tip = sha3.Sum256(y[:148])
		key, _ := mdbx.HeightKey(3, h)
		id := bytes.Clone(tip[:])
		rows = append(rows, btMutation(3, id, y[:148]), btMutation(4, id, y), btMutation(6, key, mdbx.ChainValue(tip, parent, [40]byte{38: byte((h + 1) >> 8), 39: byte(h + 1)})))
		leave = append(leave, mdbx.Mutation{DBI: mdbx.TreeSchemaV1DBIs()[3], Key: id, BeforePresent: true, AfterKind: mdbx.AfterAbsent})
		parent = tip
	}
	for len(rows) > 0 {
		n := min(len(rows), 1024)
		w.pair(t, rows[:n]...)
		rows = rows[n:]
	}
	riAuthority(t, w, func(a *mdbx.TreeAuthorityV1) {
		a.Authority.Phase = mdbx.StoragePhasePruneGCV1
		a.Authority.SelectedSide = &mdbx.SelectedSideV1{GenerationID: 3, F: 0, TipHeight: 1440, TipHash: tip, RowCount: 1439, LogicalBytes: 1439 * 298, CumulativeChainwork: [40]byte{38: 5, 39: 0xa1}}
		a.Authority.Cleanup = &mdbx.CleanupV1{Spans: []mdbx.CleanupSpanV1{{Kind: mdbx.CleanupSpanSideV1, GenerationID: 3, FirstHeight: 1, NextHeight: 1, LastHeight: 1}}}
	})
	return w, x, leave
}

// retainedCapacityMergeAuthorityV1 prepends the planned authority: side
// cleared, SIDE(3,first,1440,next).
func retainedCapacityMergeAuthorityV1(t *testing.T, w *btWorld, op *mdbx.TreeOperationV1, first, next uint64) {
	t.Helper()
	retainedCapacityMetaV1(t, w, op, func(a *mdbx.StorageAuthorityV1) {
		a.SelectedSide = nil
		a.Cleanup.Spans = []mdbx.CleanupSpanV1{{Kind: mdbx.CleanupSpanSideV1, GenerationID: 3, FirstHeight: first, NextHeight: next, LastHeight: 1440}}
	})
}

// D4 on the recipe frame: x's 298-byte body is SIDE-owned before (SIDE(3,1,1,1) with its SideLink),
// so pre is 1077 (CURRENT 301, LAG 32, header 148, bodies 596) and post 1596. Each refusal is the
// actual Proof error inside UpdateTreeV1: OLD/Prewrite/-1 with that error and no write, so the next
// attempt sees the same frame; the exact fit then commits.
func retainedCapacityNativeBoundsV1(t *testing.T) {
	for i, limits := range []LimitsV1{
		NewLimitsV1(805306368, 805307963), NewLimitsV1(1073741824, 1073743419),
		NewLimitsV1(805306368, 1000), NewLimitsV1(math.MaxUint64, math.MaxUint64),
	} {
		// A Proof error takes the native consuming route, so each case owns a frame.
		w, child, x := retainedCapacitySideFrameV1(t)
		a, dst := NewRetainedAccountingV1(limits), &DirectRetainedProofV1{}
		res := retainedCapacityCommitV1(t, w, a, dst, child, x, false)
		res.want(t, 1, 1, -1)
		var failure *RetainedProofFailureV1
		if !errors.As(res.err, &failure) || failure.Resource != "storage_capacity" || dst.pre != 1077 || !dst.entered || dst.accepted {
			t.Fatalf("refusal %d: %v pre=%d entered=%v", i, res.err, dst.pre, dst.entered)
		}
		logicalMDBXAssert(t, a.ApplyDirectMDBX(dst, res.truth, res.stage, res.index, res.err, false) == nil && !a.valid, "refusal %d apply", i)
	}
	for _, limits := range []LimitsV1{NewLimitsV1(805306368, 805307964), NewLimitsV1(1073741824, 1073743420)} {
		w, child, x := retainedCapacitySideFrameV1(t)
		a, dst := NewRetainedAccountingV1(limits), &DirectRetainedProofV1{}
		res := retainedCapacityCommitV1(t, w, a, dst, child, x, false)
		res.want(t, 2, 3, -1)
		logicalMDBXAssert(t, res.err == nil && dst.pre == 1077 && dst.post == 1596, "fit R%d: %v", limits.R(), res.err)
	}
}

func retainedCapacitySideFrameV1(t *testing.T) (*btWorld, []byte, [32]byte) {
	t.Helper()
	w, _, genesis := riGenesis(t)
	child, x := retainedCapacityNativeChildV1(t, w, genesis, 1)
	link, _ := mdbx.HeightKey(3, 1)
	w.pair(t, btMutation(6, link, mdbx.ChainValue(x, genesis, [40]byte{39: 2})))
	riAuthority(t, w, func(a *mdbx.TreeAuthorityV1) {
		a.Authority.Phase = mdbx.StoragePhasePruneGCV1
		a.Authority.Cleanup = &mdbx.CleanupV1{Spans: []mdbx.CleanupSpanV1{{Kind: mdbx.CleanupSpanSideV1, GenerationID: 3, FirstHeight: 1, NextHeight: 1, LastHeight: 1}}}
	})
	return w, child, x
}

// D14/D18 rows "callback E, no Reader failure, clean abort; completed pre" and "false/absent clean
// witness": Plan completes inside the actual UpdateTreeV1 callback, then the callback refuses with
// E. The raw tuple is OLD/Prewrite/-1/E with no write. Under the trusted clean witness Apply
// consumes the token and keeps the completed cold pre 1077 (the next Plan reads a marked cached
// value: no cold visit); without it the cache is gone. D3 "ZERO cold scanner calls": that next Plan
// commits while a Get EIO is armed on the required genesis body, a row only the cold visit reads
// (selectivity control: the same arm is the cold first result in D5_D20_D27_H1_canonical_absence_first).
// The arm is never reached.
func retainedCapacityCallbackRefusalV1(t *testing.T) {
	refuse := errors.New("callback refusal")
	for _, clean := range []bool{true, false} {
		w, child, x := retainedCapacitySideFrameV1(t)
		a, dst := NewRetainedAccountingV1(DefaultLimitsV1()), &DirectRetainedProofV1{}
		res := retainedCapacityShapedV1(t, w, a, dst, child, x, false, false, func(*mdbx.Reader, *mdbx.TreeOperationV1) error { return refuse })
		res.want(t, 1, 1, -1)
		if !retainedCapacitySameErrV1(res.err, refuse) || !dst.prepared || dst.entered || dst.pre != 1077 || a.active != dst || !a.valid {
			t.Fatalf("clean=%v refusal: %v prepared=%v entered=%v pre=%d", clean, res.err, dst.prepared, dst.entered, dst.pre)
		}
		if err := a.ApplyDirectMDBX(dst, res.truth, res.stage, res.index, res.err, clean); err != nil || a.active != nil || !dst.applied || a.valid != clean {
			t.Fatalf("clean=%v apply: %v valid=%v", clean, err, a.valid)
		}
		if !clean {
			logicalMDBXAssert(t, a.exactRet == 0, "invalidated cache keeps %d", a.exactRet)
			continue
		}
		logicalMDBXAssert(t, a.exactRet == 1077, "kept pre %d", a.exactRet)
		a.exactRet = 1077 + 7
		next, genesis := &DirectRetainedProofV1{}, sha3.Sum256(initial148BlockGenesis(t)[:148])
		evidence, harness := mdbx.FixtureSelectedDamage(w.s, w.owner, mdbx.SelectedDamageGetEIO, 4, genesis[:], func() {
			res = retainedCapacityCommitV1(t, w, a, next, child, x, false)
		})
		res.want(t, 2, 3, -1)
		if harness == nil || evidence.Faults != 0 || res.err != nil || next.pre != 1077+7 || next.post != 1596+7 {
			t.Fatalf("reuse after clean refusal: %+v/%v %v pre=%d post=%d", evidence, harness, res.err, next.pre, next.post)
		}
	}
}

// D14 rows "callback nil/E/wrappedE with ReaderF", "Proof nil then write error or commit crossed
// error", "equality OLD/NEW with error, UNKNOWN" and "any cleanup failure" under one armed native
// scenario each. The commit hook returns ENOSPC, so commit_old is the readback equality OLD, not
// the definite attempted OLD (that tuple is pinned in the unit apply matrix). Every tuple is the
// raw native one; Apply consumes the token, returns nil, keeps no successor and retires the cache.
// A Reader or cleanup failure never carries the clean witness (false is passed), so a completed pre
// is lost.
func retainedCapacityFaultTuplesV1(t *testing.T) {
	refuse, absent := errors.New("callback refusal"), make([]byte, 32)
	read := func(ret int) func(*mdbx.Reader, *mdbx.TreeOperationV1) error {
		return func(r *mdbx.Reader, _ *mdbx.TreeOperationV1) error {
			_, _, f := r.Get(mdbx.TreeSchemaV1DBIs()[3], absent)
			return []error{nil, refuse, fmt.Errorf("wrapped: %w", f), f}[ret]
		}
	}
	install := func(*mdbx.Reader, *mdbx.TreeOperationV1) error { return nil }
	for _, c := range []struct {
		name               string
		scen               mdbx.SelectedDamageScenario
		rank               uint8
		key                []byte
		finish             func(*mdbx.Reader, *mdbx.TreeOperationV1) error
		truth, stage, errs int // errs: native causes in order (1 engine, 2 E+F join, 3 wrapped+F join)
	}{
		{"D14_4_nil_readerF", mdbx.SelectedDamageGetEIO, 3, absent, read(0), 1, 1, 1},
		{"D14_5_E_readerF", mdbx.SelectedDamageGetEIO, 3, absent, read(1), 1, 1, 2},
		{"D14_5_wrappedE_readerF", mdbx.SelectedDamageGetEIO, 3, absent, read(2), 1, 1, 3},
		{"D14_5_identical_readerF", mdbx.SelectedDamageGetEIO, 3, absent, read(3), 1, 1, 1},
		{"D14_12_abortEIO_after_E", mdbx.SelectedDamageAbortEIO, 0, nil, func(*mdbx.Reader, *mdbx.TreeOperationV1) error { return refuse }, 1, 1, 2},
		{"D14_9_write_error", mdbx.SelectedDamagePutEIO, 3, nil, install, 1, 2, 1},
		{"D14_9_commit_new", mdbx.SelectedDamageCommitNew, 0, nil, install, 2, 3, 0},
		{"D14_10_commit_old", mdbx.SelectedDamageCommitOld, 0, nil, install, 1, 3, 0},
		// The third writer's meta-02 byte is not a row this readback consults: equality NEW with error.
		{"D14_10_commit_third_equality_new", mdbx.SelectedDamageCommitThird, 0, nil, install, 2, 3, 0},
		{"D14_10_commit_unreadable", mdbx.SelectedDamageCommitUnreadable, 3, nil, install, 3, 3, 0},
	} {
		t.Run(c.name, func(t *testing.T) {
			w, child, x := retainedCapacitySideFrameV1(t)
			a, dst := NewRetainedAccountingV1(DefaultLimitsV1()), &DirectRetainedProofV1{}
			var res btResult
			key := c.key
			if c.rank == 3 && c.key == nil {
				key = x[:] // the Pair's header insert of x and its readback
			}
			evidence, err := mdbx.FixtureSelectedDamage(w.s, w.owner, c.scen, c.rank, key, func() {
				res = retainedCapacityShapedV1(t, w, a, dst, child, x, false, false, func(r *mdbx.Reader, op *mdbx.TreeOperationV1) error { op.Proof = dst.Proof; return c.finish(r, op) })
			})
			faults := uint64(1) // the commit fault plus the readback get fault for Unreadable
			if c.scen == mdbx.SelectedDamageCommitUnreadable {
				faults = 2
			}
			logicalMDBXAssert(t, err == nil && evidence.Faults == faults, "site %+v: %v", evidence, err)
			res.want(t, uint8(c.truth), uint8(c.stage), -1)
			retainedCapacityCausesV1(t, res.err, c.errs, refuse)
			proved := c.stage > 1
			if !dst.prepared || dst.entered != proved || dst.accepted != proved || a.active != dst || !a.valid || a.exactRet != 1077 {
				t.Fatalf("before apply: entered=%v accepted=%v valid=%v ret=%d", dst.entered, dst.accepted, a.valid, a.exactRet)
			}
			if err := a.ApplyDirectMDBX(dst, res.truth, res.stage, res.index, res.err, false); err != nil || a.active != nil || !dst.applied || a.valid || a.exactRet != 0 || a.binding != (mdbx.MutationBindingV1{}) {
				t.Fatalf("apply: %v valid=%v ret=%d", err, a.valid, a.exactRet)
			}
		})
	}
}

// retainedCapacityCausesV1 pins the raw error shape: 0 a CommitError, 1 one
// direct EngineError, 2 the join [E, F], 3 the join [wrapped F, F].
func retainedCapacityCausesV1(t *testing.T, err error, shape int, refuse error) {
	t.Helper()
	var engine *mdbx.EngineError
	var commit *mdbx.CommitError
	joined, isJoin := err.(interface{ Unwrap() []error })
	switch shape {
	case 0:
		logicalMDBXAssert(t, errors.As(err, &commit), "commit error %T %v", err, err)
	case 1:
		logicalMDBXAssert(t, errors.As(err, &engine) && retainedCapacitySameErrV1(err, engine), "direct engine error %T %v", err, err)
	default:
		parts := []error{}
		if isJoin {
			parts = joined.Unwrap()
		}
		first := len(parts) == 2 && (shape == 2 && retainedCapacitySameErrV1(parts[0], refuse) || shape == 3 && errors.As(parts[0], &engine) && !retainedCapacitySameErrV1(parts[0], engine))
		logicalMDBXAssert(t, first && errors.As(parts[1], &engine) && engine.Class == mdbx.EngineIO, "join order %v", err)
	}
}

// D14 rows "callback panic or Goexit" and "Proof panic/Goexit" (the Proof accepts the post 1596
// first): the native writer-position unwind resumes the exact panic value after clean cleanup with
// no write, the active token stays until the caller retires it with InvalidateV1, no post is cached
// and the Store stays OPEN for the next cold attempt.
func retainedCapacityUnwindsV1(t *testing.T) {
	type sentinel struct{}
	for _, c := range []struct {
		name  string
		proof bool
		end   func()
		want  any
	}{
		{"callback_panic", false, func() { panic("callback") }, "callback"},
		{"callback_goexit", false, runtime.Goexit, nil},
		{"proof_panic", true, func() { panic(sentinel{}) }, sentinel{}},
		{"proof_goexit", true, runtime.Goexit, nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			w, child, x := retainedCapacitySideFrameV1(t)
			a, dst := NewRetainedAccountingV1(DefaultLimitsV1()), &DirectRetainedProofV1{}
			returned, done := false, make(chan any)
			var proofErr error
			go func() {
				defer func() { done <- recover() }()
				retainedCapacityShapedV1(t, w, a, dst, child, x, false, false, func(_ *mdbx.Reader, op *mdbx.TreeOperationV1) error {
					if !c.proof {
						c.end()
					}
					op.Proof = func(r *mdbx.TreeDeltaReportV1) error { proofErr = dst.Proof(r); c.end(); return nil }
					return nil
				})
				returned = true
			}()
			got := <-done
			if returned || proofErr != nil || got != c.want || !dst.prepared || dst.entered != c.proof || dst.accepted != c.proof || c.proof && dst.post != 1596 || a.active != dst {
				t.Fatalf("unwind %v returned=%v entered=%v accepted=%v", got, returned, dst.entered, dst.accepted)
			}
			btReservationsReleased(t, w.owner)
			a.InvalidateV1()
			logicalMDBXAssert(t, a.active == nil && !a.valid && a.exactRet == 0, "invalidate after unwind")
			pre, err := riRead(t, w, nil)
			logicalMDBXAssert(t, err == nil && pre.exactRet == 1077, "no write after unwind: %d %v", pre.exactRet, err)
			next := &DirectRetainedProofV1{}
			res := retainedCapacityCommitV1(t, w, a, next, child, x, false)
			res.want(t, 2, 3, -1)
			logicalMDBXAssert(t, res.err == nil && next.pre == 1077 && next.post == 1596, "store OPEN after unwind: %v", res.err)
		})
	}
}

// retainedCapacityForwardedV1 checks a producer first result forwarded by
// Plan inside UpdateTreeV1: OLD/Prewrite/-1, no Proof entry, no finite work,
// the unprepared token kept and no cache; Apply under the clean witness
// still invalidates (no completed pre exists).
func retainedCapacityForwardedV1(t *testing.T, a *RetainedAccountingV1, dst *DirectRetainedProofV1, res btResult) {
	t.Helper()
	res.want(t, 1, 1, -1)
	if dst.prepared || dst.entered || a.active != dst || a.valid || dst.pre != 0 || dst.add != 0 || dst.remove != 0 {
		t.Fatalf("forwarded first result: prepared=%v entered=%v valid=%v pre=%d", dst.prepared, dst.entered, a.valid, dst.pre)
	}
	if err := a.ApplyDirectMDBX(dst, res.truth, res.stage, res.index, res.err, true); err != nil || a.valid || a.active != nil || !dst.applied {
		t.Fatalf("apply forwarded: %v valid=%v", err, a.valid)
	}
}

// D5/D20/D27/H1 (the producer's rifSources body-absent-before-SIDE at this consumer): the required
// genesis body is absent and the healthy SIDE-owned body y (not the subject, whose source read
// precedes Plan) is armed with a Get EIO. The first result is the typed StoreIntegrity absence with
// a non-native cause and the SIDE row is never read (arm unreached); no row is repaired or drained.
// With the genesis body present (selectivity control) the same arm fires and the SIDE transient is
// the first result.
func retainedCapacityAbsentFirstV1(t *testing.T) {
	genesis := sha3.Sum256(initial148BlockGenesis(t)[:148])
	for _, absent := range []bool{true, false} {
		w, child, x, y, _ := retainedCapacityOptionalFrameV1(t, 298)
		if absent {
			logicalMDBXAssert(t, mdbx.FixtureStartupDeleteRow(w.s, 4, genesis[:]) == nil, "delete required body")
		}
		a, dst := NewRetainedAccountingV1(DefaultLimitsV1()), &DirectRetainedProofV1{}
		var res btResult
		evidence, harness := mdbx.FixtureSelectedDamage(w.s, w.owner, mdbx.SelectedDamageGetEIO, 4, y[:], func() {
			res = retainedCapacityCommitV1(t, w, a, dst, child, x, false)
		})
		var integrity *logicalStateFailure
		var engine *mdbx.EngineError
		if !absent {
			logicalMDBXAssert(t, harness == nil && evidence.Faults == 1 && errors.As(res.err, &engine) && engine.Class == mdbx.EngineIO, "SIDE transient control: %+v/%v %v", evidence, harness, res.err)
			retainedCapacityForwardedV1(t, a, dst, res)
			continue
		}
		logicalMDBXAssert(t, harness != nil && evidence.Faults == 0, "SIDE row was read: %+v/%v", evidence, harness)
		if !errors.As(res.err, &integrity) || integrity.kind != logicalStateFailureStoreIntegrity || integrity.cause == nil || errors.As(integrity.cause, &engine) {
			t.Fatalf("first integrity result: %T %v", res.err, res.err)
		}
		retainedCapacityForwardedV1(t, a, dst, res)
		for key, want := range map[[32]byte][]byte{genesis: nil, x: child, y: retainedCapacityOptionalRawV1(t)} {
			equal, err := mdbx.FixtureRawRowEqual(w.s, 4, key[:], want)
			logicalMDBXAssert(t, err == nil && equal, "body %x changed: %v", key[:4], err)
		}
		logicalMDBXAssert(t, w.s.View(func(*mdbx.Reader) error { return nil }) == nil, "store not OPEN")
	}
	// D5 transient-before-positive: a Get EIO on the required genesis body is
	// the producer's canonical_artifact_read with that native cause.
	w, child, x, _, _ := retainedCapacityOptionalFrameV1(t, 298)
	a, dst := NewRetainedAccountingV1(DefaultLimitsV1()), &DirectRetainedProofV1{}
	var res btResult
	evidence, harness := mdbx.FixtureSelectedDamage(w.s, w.owner, mdbx.SelectedDamageGetEIO, 4, genesis[:], func() {
		res = retainedCapacityCommitV1(t, w, a, dst, child, x, false)
	})
	var engine *mdbx.EngineError
	failure := riResource(t, res.err, "canonical_artifact_read")
	logicalMDBXAssert(t, harness == nil && evidence.Faults == 1 && errors.As(failure.Cause, &engine) && engine.Class == mdbx.EngineIO, "required transient: %+v/%v %v", evidence, harness, res.err)
	retainedCapacityForwardedV1(t, a, dst, res)
}

func retainedCapacityOptionalRawV1(t *testing.T) []byte {
	genesis := sha3.Sum256(initial148BlockGenesis(t)[:148])
	return initial148BlockFrame(t, [][]byte{initial148BlockGenesisTx(t)}, func(h *initial148BlockHead) { h.parent, h.timestamp = genesis, blockStepsMedian+5 })
}

// retainedCapacityOptionalFrameV1 commits the recipe child x1 at 1 and returns its child x at 2
// (unowned body, a third 89-byte entry) beside a detached entry (1,y) on y, x1's sibling under
// genesis (the reorg genesis->y to genesis->x1: F=0, H_new=1>F, MP 3039-3044, 3736). The SIDE(4,1,1,1)
// whose SideLink names the same y mirrors the merged producer recipe riOptional "detached+SIDE"
// (retained_image_mdbx_cgo_test.go:447). y's header is stored; its body is absent (bodyLen 0),
// malformed (149) or healthy (298).
func retainedCapacityOptionalFrameV1(t *testing.T, bodyLen int) (*btWorld, []byte, [32]byte, [32]byte, []byte) {
	t.Helper()
	w, _, genesis := riGenesis(t)
	child1, x1 := retainedCapacityNativeChildV1(t, w, genesis, 1)
	retainedCapacityCommitV1(t, w, NewRetainedAccountingV1(DefaultLimitsV1()), &DirectRetainedProofV1{}, child1, x1, false).want(t, 2, 3, -1)
	child, x := retainedCapacityNativeChildV1(t, w, x1, 2)
	raw := retainedCapacityOptionalRawV1(t)
	y := sha3.Sum256(raw[:148])
	link, _ := mdbx.HeightKey(4, 1)
	rows := []mdbx.Mutation{btMutation(3, y[:], raw[:148]), btMutation(6, link, mdbx.ChainValue(y, genesis, [40]byte{39: 2}))}
	if bodyLen != 0 {
		rows = append(rows, btMutation(4, y[:], raw[:bodyLen]))
	}
	w.pair(t, rows...)
	encoded := riAuthority(t, w, func(a *mdbx.TreeAuthorityV1) {
		a.Authority.Phase = mdbx.StoragePhasePruneGCV1
		a.Authority.Cleanup = &mdbx.CleanupV1{Spans: []mdbx.CleanupSpanV1{{Kind: mdbx.CleanupSpanGenerationV1, GenerationID: 3}, {Kind: mdbx.CleanupSpanSideV1, GenerationID: 4, FirstHeight: 1, NextHeight: 1, LastHeight: 1}}}
		a.Authority.DetachedSuffix = &mdbx.DetachedSuffixV1{Entries: []mdbx.DetachedSuffixEntryV1{{Height: 1, Hash: y, BlockBytesLen: 298}}, Cursor: mdbx.AuthorityPointV1{Height: 1, BlockHash: y}, EntryCount: 1, LogicalBytes: 298}
	})
	return w, child, x, y, encoded
}

// D21: the absent optional body counts 0 under SIDE and detached, the detached header 148
// (riOptional detached+SIDE header-only): cold pre = recipe post-x1 1596 + 148 = 1744; x adds a
// third 89-byte entry, CURRENT 672 -> 267+Tree(3) 440+J 336 = 1043 (+371), header 148, body 298:
// post 1744+817=2561. NEW/nil commit, successor cached, and the authority bytes are unchanged. D22: the same
// frame with a present malformed body refuses storage_capacity first.
func retainedCapacityOptionalV1(t *testing.T) {
	for _, malformed := range []bool{false, true} {
		w, child, x, _, encoded := retainedCapacityOptionalFrameV1(t, map[bool]int{false: 0, true: 149}[malformed])
		a, dst := NewRetainedAccountingV1(DefaultLimitsV1()), &DirectRetainedProofV1{}
		res := retainedCapacityCommitV1(t, w, a, dst, child, x, false)
		if malformed {
			failure := riResource(t, res.err, "storage_capacity")
			logicalMDBXAssert(t, failure.Damage == nil, "capacity carries damage")
			retainedCapacityForwardedV1(t, a, dst, res)
			continue
		}
		res.want(t, 2, 3, -1)
		if res.err != nil || dst.pre != 1744 || !dst.accepted || dst.post != 2561 {
			t.Fatalf("optional absent commit: %v pre=%d post=%d", res.err, dst.pre, dst.post)
		}
		logicalMDBXAssert(t, a.ApplyDirectMDBX(dst, res.truth, res.stage, res.index, res.err, false) == nil && a.valid && a.exactRet == 2561, "successor %d", a.exactRet)
		cold, err := riRead(t, w, nil)
		logicalMDBXAssert(t, err == nil && cold.exactRet == 2561, "fresh post %d: %v", cold.exactRet, err)
		w.read(t, 0, []byte{2}, encoded)
	}
}

// D26: a clean callback refusal keeps the completed pre 1077 and the helper drains nothing (the
// stored image is still 1077 with its SIDE). A separate external commit then drains the SIDE
// descriptor; the next Plan sees a non-reusable binding and reconstructs the fresh pre 779 (x
// unowned), not the cached 1077, and proves post 1596.
func retainedCapacityDrainV1(t *testing.T) {
	w, child, x := retainedCapacitySideFrameV1(t)
	a, dst := NewRetainedAccountingV1(DefaultLimitsV1()), &DirectRetainedProofV1{}
	refuse := errors.New("callback refusal")
	res := retainedCapacityShapedV1(t, w, a, dst, child, x, false, false, func(*mdbx.Reader, *mdbx.TreeOperationV1) error { return refuse })
	logicalMDBXAssert(t, a.ApplyDirectMDBX(dst, res.truth, res.stage, res.index, res.err, true) == nil && a.valid && a.exactRet == 1077, "kept pre %d", a.exactRet)
	still, err := riRead(t, w, nil)
	logicalMDBXAssert(t, err == nil && still.exactRet == 1077, "helper drained: %d %v", still.exactRet, err)
	riAuthority(t, w, func(auth *mdbx.TreeAuthorityV1) {
		auth.Authority.Phase, auth.Authority.Cleanup = mdbx.StoragePhaseNoneV1, nil
	})
	fresh, err := riRead(t, w, nil)
	logicalMDBXAssert(t, err == nil && fresh.exactRet == 779, "drained image %d: %v", fresh.exactRet, err)
	next := &DirectRetainedProofV1{}
	res = retainedCapacityCommitV1(t, w, a, next, child, x, false)
	res.want(t, 2, 3, -1)
	logicalMDBXAssert(t, res.err == nil && next.pre == 779 && next.post == 1596, "reconstruction after drain: %v pre=%d post=%d", res.err, next.pre, next.post)
}

// D24: the producer's completed malformed node key (rifKinds malformed-key: the bare obsolete
// generation-3 prefix in tree-node-v1, on the D21 frame that alone commits) is its first result
// inside the actual UpdateTreeV1 callback: storage_capacity forwarded with no Proof, no post and no
// cache advance, and no native write.
func retainedCapacityCompletedKeyV1(t *testing.T) {
	w, child, x, _, _ := retainedCapacityOptionalFrameV1(t, 0)
	rifSeed(t, w, 8, binary.BigEndian.AppendUint64(nil, 3), []byte{1})
	a, dst := NewRetainedAccountingV1(DefaultLimitsV1()), &DirectRetainedProofV1{}
	res := retainedCapacityCommitV1(t, w, a, dst, child, x, false)
	riResource(t, res.err, "storage_capacity")
	retainedCapacityForwardedV1(t, a, dst, res)
	equal, err := mdbx.FixtureRawRowEqual(w.s, 3, x[:], nil)
	logicalMDBXAssert(t, err == nil && equal, "native write after refusal: %v", err)
}
