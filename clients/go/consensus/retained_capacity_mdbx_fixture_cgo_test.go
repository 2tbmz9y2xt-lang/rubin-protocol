//go:build rubin_mdbx_fixture && cgo && (darwin || linux) && (amd64 || arm64)

package consensus

import (
	"bytes"
	"crypto/sha3"
	"errors"
	"math"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/mdbx"
)

func TestRetainedCapacityMDBXCommitOutcomes(t *testing.T) {
	t.Run("D6_D25_undo_projection_reads_actual_family", func(t *testing.T) {
		w, _, _ := riGenesis(t)
		op := retainedCapacityBoundOpV1(t, w)
		// Two native 20-byte entries charge 36+20 each; the 33-byte manifest key is not an entry.
		rifFamily(t, w, op.Primitives[0].Block, op.Primitives[0].Height, 2, "")
		a, dst := NewRetainedAccountingV1(DefaultLimitsV1()), &DirectRetainedProofV1{}
		if err := retainedCapacityPlanV1(t, w, a, dst, op, 8192); err != nil || !dst.prepared {
			t.Fatalf("plan: %v", err)
		}
		if dst.undo.block != op.Primitives[0].Block || dst.undo.oldCharge != 2*(36+20) {
			t.Fatalf("family projection %+v", dst.undo)
		}
	})
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
}

// T18 (rejected_cases): a W row beside the rolling-prepared pending SIDE.
// The stored selected side of generation 3 has one row at 5 (F 4, f 5) whose
// SideLink names x; the OLD authority in this read carries the pending
// SIDE(3,4,4,4) structurally (MP 1422-1426; the shape is structural-only, MP
// 2984-2986, 3047-3056, 1408-1411). restV1 reads the actual SideLink through
// optionalAtV1, finds x as W, and the L merge is refused; the same read with
// a non-W block admits the merge SIDE(3,4,5,4) (selectivity control).
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
func retainedCapacityNativeChildV1(t *testing.T, w *btWorld, genesis [32]byte) ([]byte, [32]byte) {
	t.Helper()
	tx := initial148BlockGenesisTx(t)
	at := bytes.Index(tx, []byte{0x84, 0x48, 0xb9, 0x1b, 0x88, 0xd1, 0xa6, 0xfb})
	logicalMDBXAssert(t, at > 0, "genesis P2PK key hash")
	tx[at] ^= 1
	child := initial148BlockFrame(t, [][]byte{tx}, func(h *initial148BlockHead) { h.parent = genesis })
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
	var result btResult
	err := w.owner.WithOperation(mdbx.TreeOperation, func(account *mdbx.OperationAccount) error {
		return account.WithReservation(2<<20, func() error {
			result.truth, result.stage, result.index, result.err = w.s.UpdateTreeV1(account, func(r *mdbx.Reader) (mdbx.TreeOperationV1, error) {
				req := btRequest(child, 1)
				req.BodyKind, req.Raw, req.Kind = 2, nil, mdbx.TreeKindDirectApplyV1
				req.Endpoint.CumulativeChainwork = [40]byte{39: 2}
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
				op.Pair.Mutations = append(append([]mdbx.Mutation{}, effect.Index[:]...), btMutation(3, bytes.Clone(x[:]), bytes.Clone(child[:148])))
				btSort(op.Pair.Mutations)
				if err := a.PlanDirectMDBX(dst, r, account, &op); err != nil {
					return mdbx.TreeOperationV1{}, err
				}
				op.Proof = dst.Proof
				return op, nil
			})
			return nil
		})
	})
	logicalMDBXAssert(t, err == nil, "commit account: %v", err)
	btReservationsReleased(t, w.owner)
	return result
}

// D4/D23 through actual UpdateTreeV1 (native_fixture_recipe): pre 779 is the
// recipe's setup value without SIDE (CURRENT 89+100+112, LAG 32, header 148,
// genesis body 298); post 1596 (CURRENT 178+270+224, LAG 32, headers 296,
// bodies 596). The LAG role is untouched; a LagForward companion is refused by
// Plan before any work and the next Plan reconstructs once.
func retainedCapacityNativeCommitV1(t *testing.T) {
	w, _, genesis := riGenesis(t)
	child, x := retainedCapacityNativeChildV1(t, w, genesis)
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
	if res.err != errRetainedPlanAPIV1 || a.active != nil || refused.owner != nil || refused.entered || refused.pre != 0 || refused.roles != ([2]retainedRoleV1{}) {
		t.Fatalf("companion: %v active=%v", res.err, a.active)
	}
	if err := a.ApplyDirectMDBX(refused, res.truth, res.stage, res.index, res.err, true); !errors.Is(err, errRetainedApplyAPIV1) || a.valid {
		t.Fatalf("companion apply: %v", err)
	}
}

// retainedCapacityLagEmptyV1: the LAG generation 2 root binding, counter
// bytes and both canonical index keysets equal the seeded empty role.
func retainedCapacityLagEmptyV1(t *testing.T, w *btWorld) {
	t.Helper()
	err := w.s.View(func(r *mdbx.Reader) error { return riEmptyRole(r, 2) })
	logicalMDBXAssert(t, err == nil, "LAG role bytes: %v", err)
}

func retainedCapacityReuseV1(t *testing.T, w *btWorld, a *RetainedAccountingV1) {
	t.Helper()
	// D3: the successor binding is reused with no cold visit (a marked cache
	// value is observed); D13: an intervening native commit of another kind
	// advances the epoch and the next Plan reconstructs once.
	a.exactRet = 1596 + 7
	warm := &DirectRetainedProofV1{}
	_ = retainedCapacityPlanV1(t, w, a, warm, retainedCapacityBoundOpV1(t, w), 8192)
	logicalMDBXAssert(t, warm.pre == 1596+7 && a.valid, "warm successor pre %d", warm.pre)
	logicalMDBXAssert(t, a.ApplyDirectMDBX(warm, mdbx.CommitTruthOld, mdbx.UpdateStagePrewrite, -1, errors.New("callback"), true) == nil, "warm apply")
	a.exactRet = 1596 + 7
	riAuthority(t, w, func(*mdbx.TreeAuthorityV1) {}) // an intervening Pair-only native commit
	next := &DirectRetainedProofV1{}
	_ = retainedCapacityPlanV1(t, w, a, next, retainedCapacityBoundOpV1(t, w), 8192)
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
	verr, _ := w.s.StartupVerifyCanonicalV1(func(*mdbx.Reader) (mdbx.StartupCanonicalCompletionV1, error) {
		return mdbx.StartupCanonicalActiveAndReplayCompleteV1, nil
	})
	logicalMDBXAssert(t, verr == nil, "reopen qualification: %v", verr)
	retainedCapacityLagEmptyV1(t, w)
	if rolesReopen, endsReopen := retainedCapacityRolesV1(t, w); rolesReopen != rolesAfter || endsReopen != endsAfter {
		t.Fatalf("reopen roles %+v/%+v differ from %+v/%+v", rolesReopen, endsReopen, rolesAfter, endsAfter)
	}
	if rolesAfter[1] != rolesBefore[1] || endsAfter[1] != endsBefore[1] {
		t.Fatalf("LAG changed: %+v/%+v -> %+v/%+v", rolesBefore[1], endsBefore[1], rolesAfter[1], endsAfter[1])
	}
	if rolesBefore[0].s != 89 || rolesBefore[0].n != 1 || rolesAfter[0].s != 178 || rolesAfter[0].n != 2 || rolesAfter[0].generation != rolesBefore[0].generation {
		t.Fatalf("CURRENT %+v -> %+v", rolesBefore[0], rolesAfter[0])
	}
}

// T19 (D2/D15/D17): the rolling-prepared OLD shape of the RUB-1594 A1
// witness: H_old=F=0, live one-slot selected side [2,1440] (1439 rows, f 2
// >= F+2, MP 1408-1411) and pending SIDE(3,1,1,1) owing the candidate x at
// f-1 (MP 1422-1426). The direct op at 1 has W empty and merges L=[2,1440]
// into SIDE(3,1,1440,1) with first and next kept (MP 2539-2541, DIRECT
// 3800-3805), and the full Plan/Proof path accepts it. x's header is the
// canonical +148; each of the 1439 L headers leaves the selected owner
// (SIDE body only), so remove is 148*1439; bodies stay owned. SIDE(3,2,1440,2)
// and SIDE(3,1,1440,2) are refused.
func retainedCapacityRollingMergeV1(t *testing.T) {
	for name, c := range map[string]struct {
		first, next uint64
		ok          bool
	}{"merge": {1, 1, true}, "first_moved": {2, 2, false}, "next_moved": {1, 2, false}} {
		t.Run(name, func(t *testing.T) {
			w, x := retainedCapacityRollingV1(t)
			op := retainedCapacityBoundOpV1(t, w)
			logicalMDBXAssert(t, op.Primitives[0].Block == x && op.Primitives[0].Height == 1, "candidate op")
			retainedCapacityMergeAuthorityV1(t, w, op, c.first, c.next)
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
			r := dst.roles[0]
			report := &mdbx.TreeDeltaReportV1{
				Current: mdbx.TreeRoleDeltaV1{Present: true, Generation: r.generation, BytesBefore: r.s, CountBefore: r.n, BytesAfter: r.s + 56, CountAfter: r.n + 1, IndexAdded: 1},
				Undo:    []mdbx.TreeUndoChargeV1{{Effect: mdbx.TreeUndoFamilyWrittenV1, Entries: 1, Bytes: 56}},
			}
			if err := dst.Proof(report); err != nil || !dst.accepted {
				t.Fatalf("merge proof: %v", err)
			}
		})
	}
}

// retainedCapacityRollingV1 stores the candidate x's body and SideLink (3,1)
// and the 1439 chained selected rows 2..1440, then the OLD authority.
func retainedCapacityRollingV1(t *testing.T) (*btWorld, [32]byte) {
	t.Helper()
	w, _, genesis := riGenesis(t)
	x, _ := retainedCapacityChildV1(t, w)
	link, _ := mdbx.HeightKey(3, 1)
	rows := []mdbx.Mutation{btMutation(6, link, mdbx.ChainValue(x, genesis, [40]byte{39: 1}))}
	parent, tip := x, [32]byte{}
	for h := uint64(2); h <= 1440; h++ {
		y := initial148BlockFrame(t, [][]byte{initial148BlockGenesisTx(t)}, func(b *initial148BlockHead) { b.parent, b.timestamp = parent, blockStepsMedian+h })
		tip = sha3.Sum256(y[:148])
		key, _ := mdbx.HeightKey(3, h)
		id := bytes.Clone(tip[:])
		rows = append(rows, btMutation(3, id, y[:148]), btMutation(4, id, y), btMutation(6, key, mdbx.ChainValue(tip, parent, [40]byte{39: 1})))
		parent = tip
	}
	for len(rows) > 0 {
		n := min(len(rows), 1024)
		w.pair(t, rows[:n]...)
		rows = rows[n:]
	}
	riAuthority(t, w, func(a *mdbx.TreeAuthorityV1) {
		a.Authority.Phase = mdbx.StoragePhasePruneGCV1
		a.Authority.SelectedSide = &mdbx.SelectedSideV1{GenerationID: 3, F: 0, TipHeight: 1440, TipHash: tip, RowCount: 1439, LogicalBytes: 1439 * 298, CumulativeChainwork: [40]byte{39: 1}}
		a.Authority.Cleanup = &mdbx.CleanupV1{Spans: []mdbx.CleanupSpanV1{{Kind: mdbx.CleanupSpanSideV1, GenerationID: 3, FirstHeight: 1, NextHeight: 1, LastHeight: 1}}}
	})
	return w, x
}

// retainedCapacityMergeAuthorityV1 prepends the planned authority: side
// cleared, SIDE(3,first,1440,next).
func retainedCapacityMergeAuthorityV1(t *testing.T, w *btWorld, op *mdbx.TreeOperationV1, first, next uint64) {
	t.Helper()
	var auth mdbx.TreeAuthorityV1
	err := w.s.View(func(reader *mdbx.Reader) error {
		var err error
		auth, _, err = reader.ReadTreeAuthorityV1()
		return err
	})
	logicalMDBXAssert(t, err == nil, "authority: %v", err)
	auth.Authority.SelectedSide = nil
	auth.Authority.Cleanup.Spans = []mdbx.CleanupSpanV1{{Kind: mdbx.CleanupSpanSideV1, GenerationID: 3, FirstHeight: first, NextHeight: next, LastHeight: 1440}}
	encoded, err := auth.Encode()
	logicalMDBXAssert(t, err == nil, "planned encode: %v", err)
	meta := btMutation(0, []byte{2}, encoded)
	meta.BeforePresent = true
	op.Pair.Mutations = append([]mdbx.Mutation{meta}, op.Pair.Mutations...)
}

// D4 on the recipe frame: x's 298-byte body is SIDE-owned before
// (SIDE(3,1,1,1) with its SideLink), so pre is 1077 (CURRENT 301, LAG 32,
// header 148, bodies 596) and post 1596. Each refusal is the actual Proof
// error inside UpdateTreeV1: OLD/Prewrite/-1 with that error and no write,
// so the next attempt sees the same frame; the exact fit then commits.
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
	child, x := retainedCapacityNativeChildV1(t, w, genesis)
	link, _ := mdbx.HeightKey(3, 1)
	w.pair(t, btMutation(6, link, mdbx.ChainValue(x, genesis, [40]byte{39: 1})))
	riAuthority(t, w, func(a *mdbx.TreeAuthorityV1) {
		a.Authority.Phase = mdbx.StoragePhasePruneGCV1
		a.Authority.Cleanup = &mdbx.CleanupV1{Spans: []mdbx.CleanupSpanV1{{Kind: mdbx.CleanupSpanSideV1, GenerationID: 3, FirstHeight: 1, NextHeight: 1, LastHeight: 1}}}
	})
	return w, child, x
}
