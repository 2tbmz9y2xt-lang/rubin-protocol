//go:build rubin_mdbx_fixture && cgo && (darwin || linux) && (amd64 || arm64)

package consensus

import (
	"errors"
	"testing"
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
}
