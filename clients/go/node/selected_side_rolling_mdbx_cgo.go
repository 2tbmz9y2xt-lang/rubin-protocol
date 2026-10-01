//go:build cgo && (darwin || linux) && (amd64 || arm64)

package node

import (
	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/mdbx"
)

// Dormant selected-side rolling preparation RP (RUBIN_MEMPOOL_POLICY.md Sections 6.4.1.3, 6.4.1.5 and 6.4.1.9,
// RUBIN_COMPACT_BLOCKS.md Section 10.2). PrepareSelectedSideRollingMDBX has no production caller. It shares Retain's
// attempts, grant, Update, recheck/retry and raw tuple rules; its only write moves the oldest row of a full 1440-row side
// into SIDE(g,first,first,first) through the consensus rolling planner, and the incoming candidate is never stored.

const (
	// selectedRetainRoll is Proll, the rolling planner's whole charge: Pclear plus the oldest body's Go copy and native
	// OLD image (2M) and its commitment workspace (two 1024-element Tx input/output/witness arrays and two 64-level
	// frontiers of 32-byte nodes): 144720634.
	selectedRetainRoll uint64 = selectedRetainClear + 2*mdbx.MaxBlockBytes + 2*1024*(64+40+56) + 2*64*32
	// selectedRetainRollOutside is RP's Eoutside beside Proll: the merged union backing array and its Update clone (64
	// bytes per identity and key, twice), the candidate-owner/expected-tip allowance and fixed bookkeeping. The
	// qualifier's own authority and Consulted rows are inside the workspace term.
	selectedRetainRollOutside uint64 = 2*selectedQualIdentities*64 + selectedRetainOwnerTip + 131_072
)

// PrepareSelectedSideRollingMDBX prepares the rolling of a full 1440-row selected side for one raw exact-tip child under
// an untrusted expected canonical tip locator. A healthy oldest row leaves into SIDE(g,first,first,first) with count
// 1439; positive oldest damage is the complete clear instead. It returns the terminating attempt's whole tuple, like
// RetainSelectedSideMDBX.
func PrepareSelectedSideRollingMDBX(store *mdbx.Store, reservations *mdbx.OperationReservationOwner, raw []byte, expectedTip *mdbx.AuthorityPointV1) SelectedSideMutationOutcome {
	return selectedRetainRun(store, reservations, raw, expectedTip, selectedPrepareMode)
}

// prepare is RP's admission tail: only an exact-tip child of a full 1440-row side (which excludes a pending SIDE and a
// detached suffix) is prepared; anything else is typed branch_data with no automatic append. The conservative preflight
// 2n+L+W+Eoutside+Proll <= G precedes every planner read and allocation; L is the checked linking body's length.
func (r *selectedRetention) prepare(parent selectedQualParent) (mdbx.Batch, error) {
	switch {
	case r.side == nil || !parent.selected || r.side.RowCount != 1440:
		return mdbx.Batch{}, selectedQualFailure(selectedQualBranch, "selected side rolling preparation needs an exact-tip child of a full side")
	case !selectedRetainRollFits(uint64(len(r.attempt.raw)), r.attempt.linking):
		return mdbx.Batch{}, r.attempt.decide(selectedRetainCapacity, "", "OLD")
	}
	plan, err := consensus.PlanSelectedSideRollingMDBX(r.reader)
	if err != nil {
		r.attempt.resource = plan.ReadResource
		return mdbx.Batch{}, err
	}
	r.attempt.positive = plan.PositiveDamageClear
	plan.Batch.Consulted = selectedRetainUnion(append(r.consulted, plan.Batch.Consulted...), plan.Batch.Mutations)
	return plan.Batch, nil
}

// selectedRetainRollFits is the checked RP preflight; n <= M and L <= M, so the sum cannot wrap.
func selectedRetainRollFits(n, l uint64) bool {
	return 2*n+l+selectedRetainWorkspace+selectedRetainRollOutside+selectedRetainRoll <= mdbx.MaxOperationDataBytes
}
