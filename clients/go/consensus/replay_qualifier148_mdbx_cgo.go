//go:build cgo && (darwin || linux) && (amd64 || arm64)

package consensus

import "github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/mdbx"

// Dormant format-3 replay target qualification over raw 148-byte headers (RUBIN_MEMPOOL_POLICY.md Section 6.4.1.8).
// No production caller.

// view148 is the owner's view as HeaderCandidateView148V1 when its dynamic value implements that interface, else nil
// (the absent view of replayEntryInventory148). A non-nil interface holding a typed-nil provider follows its methods.
func (o *ReplayEntryOwnerV1) view148() HeaderCandidateView148V1 {
	view, _ := o.view.(HeaderCandidateView148V1)
	return view
}

// qualify148 is the inventory, walk, selection and protection prefix of qualifyAndPlan on a format-3 Reader at width
// 148: the inventory of view148 at replayInvLimit148(c.lane), the active canonical-index walk of a.ActiveGenerationID
// with c.step, selectTarget (empty or refused selection: replayEntryRecovery), then ProtectV1 once on the same view
// with the inventory Version (nil release: selectedSideInvariant; a non-nil release is stored in c.release before the
// current check; not current: replayEntryStale). It returns the target and the walk's tip height. A decided outcome
// returns a zero target, tip height 0 and c.decide's sentinel with c.result set; a read failure returns the Reader's
// error with c.step naming its site. Precondition: c.lane is zero or at least replayRecoveryMin148Bytes. It performs
// no authority read, sequence check, plan or write.
func (c *replayEntryCall) qualify148(reader *mdbx.Reader, a mdbx.StorageAuthorityV1) (mdbx.RecoveryTargetV1, uint64, error) {
	view := c.owner.view148()
	inv, result := replayEntryInventory148(view, replayInvLimit148(c.lane))
	if result != "" {
		return c.decided148(result)
	}
	q := newReplayQualifier148(c.owner.genesis, inv, a.ExcludedInvalidBranch)
	tipHeight, err := q.walk(reader, a.ActiveGenerationID, &c.step)
	if err != nil {
		return mdbx.RecoveryTargetV1{}, 0, err
	}
	target, ok, result := q.selectTarget()
	if result != "" || !ok {
		return c.decided148(replayEntryRecovery)
	}
	current, release := view.ProtectV1(inv.Version)
	if release == nil {
		return c.decided148(selectedSideInvariant)
	}
	c.release = release
	if !current {
		return c.decided148(replayEntryStale)
	}
	return target, tipHeight, nil
}

// decided148 is c.decide with qualify148's zero target and tip height.
func (c *replayEntryCall) decided148(result string) (mdbx.RecoveryTargetV1, uint64, error) {
	_, err := c.decide(result, "")
	return mdbx.RecoveryTargetV1{}, 0, err
}
