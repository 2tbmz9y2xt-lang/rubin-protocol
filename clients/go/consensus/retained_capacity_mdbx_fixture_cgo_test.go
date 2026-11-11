//go:build rubin_mdbx_fixture && cgo && (darwin || linux) && (amd64 || arm64)

package consensus

import "testing"

func TestRetainedCapacityMDBXCommitOutcomes(t *testing.T) {
	t.Run("D6_D25_undo_projection_reads_actual_family", func(t *testing.T) {
		w, _, _ := riGenesis(t)
		op := retainedCapacityBoundOpV1(t, w)
		// Two native 20-byte entries charge 36+20 each; the 33-byte manifest key is not an entry.
		rifFamily(t, w, op.Primitives[0].Block, op.Primitives[0].Height, 2, "")
		a, dst := NewRetainedAccountingV1(DefaultLimitsV1()), &DirectRetainedProofV1{}
		if err := retainedCapacityPlanV1(t, w, a, dst, op, 8192); err != errRetainedPendingV1 {
			t.Fatalf("plan: %v", err)
		}
		if dst.undo.block != op.Primitives[0].Block || dst.undo.oldCharge != 2*(36+20) {
			t.Fatalf("family projection %+v", dst.undo)
		}
	})
}
