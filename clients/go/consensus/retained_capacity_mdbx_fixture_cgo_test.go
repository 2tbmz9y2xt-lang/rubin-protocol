//go:build rubin_mdbx_fixture && cgo && (darwin || linux) && (amd64 || arm64)

package consensus

import (
	"bytes"
	"crypto/sha3"
	"errors"
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
	rolesBefore, endsBefore := retainedCapacityRolesV1(t, w)
	a := NewRetainedAccountingV1(DefaultLimitsV1())
	// The companion op: count/kind refusal, no token, no native write.
	refused := &DirectRetainedProofV1{}
	res := retainedCapacityCommitV1(t, w, a, refused, child, x, true)
	res.want(t, 1, 1, -1)
	if !errors.Is(res.err, errRetainedShapeAPIV1) && !errors.Is(res.err, errRetainedPlanAPIV1) || a.active != nil || refused.owner != nil || refused.entered {
		t.Fatalf("companion: %v active=%v", res.err, a.active)
	}
	if err := a.ApplyDirectMDBX(refused, res.truth, res.stage, res.index, res.err, true); !errors.Is(err, errRetainedApplyAPIV1) || a.valid {
		t.Fatalf("companion apply: %v", err)
	}
	// The one-CURRENT op: cold pre 779, Proof accepts post 1596, NEW/nil commit.
	dst := &DirectRetainedProofV1{}
	res = retainedCapacityCommitV1(t, w, a, dst, child, x, false)
	res.want(t, 2, 3, -1)
	if res.err != nil || dst.pre != 779 || !dst.accepted || dst.post != 1596 {
		t.Fatalf("direct commit: %v pre=%d post=%d accepted=%v", res.err, dst.pre, dst.post, dst.accepted)
	}
	// D4 boundary from the native post: default R 805306368 needs LRet 805307964.
	if 805306368+dst.post != 805307964 {
		t.Fatalf("R boundary %d", dst.post)
	}
	if err := a.ApplyDirectMDBX(dst, res.truth, res.stage, res.index, res.err, false); err != nil || !dst.applied || a.active != nil {
		t.Fatalf("apply success: %v", err)
	}
	logicalMDBXAssert(t, !a.valid || a.exactRet == 1596, "cached successor %d", a.exactRet)
	cold, err := riRead(t, w, nil)
	logicalMDBXAssert(t, err == nil && cold.exactRet == 1596, "fresh post enumeration %d: %v", cold.exactRet, err)
	rolesAfter, endsAfter := retainedCapacityRolesV1(t, w)
	// After reopen the test qualifies the committed pair itself (the startup
	// owner is outside this issue); the LAG role must read back unchanged.
	w.reopen(t)
	verr, _ := w.s.StartupVerifyCanonicalV1(func(*mdbx.Reader) (mdbx.StartupCanonicalCompletionV1, error) {
		return mdbx.StartupCanonicalActiveAndReplayCompleteV1, nil
	})
	logicalMDBXAssert(t, verr == nil, "reopen qualification: %v", verr)
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
