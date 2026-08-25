package node

import (
	"fmt"
	"sort"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

// beginTransition opens exactly one canonical transition and advances the
// generation high-water. Reserve and Finalize are unavailable until the
// transition commits its stable tip or aborts. A nil owner means no pool is
// bound to the engine and is a no-op, not an error.
func (o *PendingOutpointOwner) beginTransition() (uint64, error) {
	if o == nil {
		return 0, nil
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.inTransition {
		return 0, pendingOutpointUnavailable("pending-outpoint owner transition already active")
	}
	if o.generation == ^uint64(0) {
		return 0, pendingOutpointUnavailable("pending-outpoint generation exhausted")
	}
	o.generation++
	o.inTransition = true
	return o.generation, nil
}

// commitStableTip publishes the transition's stable tip and reopens admission.
//
// It has NO production caller: a canonical transition publishes its owner image
// — stable tip included — by assignment inside publishCanonicalMempoolPlan,
// under the same owner hold as M1/O1, because nothing after the canonical-index
// commit may return an error. It survives as the direct owner-level primitive
// the owner's own tests drive.
func (o *PendingOutpointOwner) commitStableTip(tip PendingOutpointTip) error {
	if o == nil {
		return nil
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if !o.inTransition {
		return pendingOutpointInternal("pending-outpoint stable tip commit without an active transition")
	}
	o.stableTip = tip
	o.inTransition = false
	return nil
}

// endTransitionAborted reopens admission for a transition that published
// NOTHING, which is the only shape an abort takes now: the live image was never
// replaced, so there is nothing to restore and this only clears the transition
// flag. The stable tip keeps its pre-transition value; token and generation
// high-waters stay advanced so no sequence is ever reused.
func (o *PendingOutpointOwner) endTransitionAborted() {
	if o == nil {
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	o.inTransition = false
}

// pendingOutpointSnapshot is the exact same-owner image a canonical transition
// snapshots under the admission fence and rebuilds its published O1 from.
type pendingOutpointSnapshot struct {
	claims              []pendingOutpointClaim
	stableTip           PendingOutpointTip
	tokenHighWater      uint64
	generationHighWater uint64
}

func (o *PendingOutpointOwner) snapshot() pendingOutpointSnapshot {
	if o == nil {
		return pendingOutpointSnapshot{}
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	claims := make([]pendingOutpointClaim, 0, len(o.byToken))
	for _, claim := range o.byToken {
		copied := *claim
		copied.inputs = append([]consensus.Outpoint(nil), claim.inputs...)
		claims = append(claims, copied)
	}
	// Sequence order, never map order: the snapshot is compared and restored
	// verbatim, so its contents must not depend on map iteration.
	sort.Slice(claims, func(i, j int) bool { return claims[i].token.seq < claims[j].token.seq })
	return pendingOutpointSnapshot{
		claims:              claims,
		stableTip:           o.stableTip,
		tokenHighWater:      o.tokenHighWater,
		generationHighWater: o.generation,
	}
}

// checkSnapshotClaim proves one snapshot claim is this owner's and well formed:
// an owned nonzero sequence at or below the snapshot high-water, a valid domain,
// a nonzero txid, and a nonempty input set. It reads no index and mutates
// nothing.
func (o *PendingOutpointOwner) checkSnapshotClaim(claim pendingOutpointClaim, tokenHighWater uint64) error {
	if claim.token.owner != o || claim.token.seq == 0 || claim.token.seq > tokenHighWater {
		return pendingOutpointInternal("foreign pending-outpoint token in snapshot")
	}
	if !claim.domain.valid() || claim.txid == ([32]byte{}) || len(claim.inputs) == 0 {
		return pendingOutpointInternal(fmt.Sprintf("malformed pending-outpoint claim in snapshot for %x", claim.txid))
	}
	return nil
}

// buildRestoreLocked builds both candidate indexes from snap and publishes
// NEITHER. The caller cross-checks them against the records it is about to
// install and only then calls publishRestoreLocked, so owner image and records
// become visible together or not at all. The caller holds o.mu.
//
// It has NO production caller: the canonical plan builder constructs its owner
// candidate with buildCanonicalOwnerIndex instead, which builds the same two
// indexes off-lock while the plan is still refusable. This survives as the
// owner-level primitive its own tests drive.
func (o *PendingOutpointOwner) buildRestoreLocked(snap pendingOutpointSnapshot) (pendingOutpointIndex, error) {
	byOutpoint := make(map[consensus.Outpoint]pendingOutpointRow, len(snap.claims))
	byToken := make(map[PendingOutpointToken]*pendingOutpointClaim, len(snap.claims))
	for i := range snap.claims {
		claim := snap.claims[i]
		if err := o.checkSnapshotClaim(claim, snap.tokenHighWater); err != nil {
			return pendingOutpointIndex{}, err
		}
		if _, dup := byToken[claim.token]; dup {
			return pendingOutpointIndex{}, pendingOutpointInternal("duplicate pending-outpoint token in snapshot")
		}
		for _, op := range claim.inputs {
			if _, dup := byOutpoint[op]; dup {
				return pendingOutpointIndex{}, pendingOutpointInternal(fmt.Sprintf("duplicate pending-outpoint in snapshot txid=%x vout=%d", op.Txid, op.Vout))
			}
			byOutpoint[op] = pendingOutpointRow{token: claim.token, txid: claim.txid}
		}
		restored := claim
		restored.inputs = append([]consensus.Outpoint(nil), claim.inputs...)
		byToken[claim.token] = &restored
	}
	return pendingOutpointIndex{
		owner:          o,
		byOutpoint:     byOutpoint,
		byToken:        byToken,
		tokenHighWater: snap.tokenHighWater,
	}, nil
}

// publishRestoreLocked installs an already-built, already-cross-checked candidate
// index. It cannot fail, so no error-capable step remains once the owner image is
// visible. High-waters never regress — the larger of current and snapshot wins —
// so an aborted transition cannot hand out a sequence twice. Caller holds o.mu.
//
// It does NOT close the transition: inTransition is cleared by the caller inside
// the same o.mu hold, and only for an ordinary COMMITTED outcome —
// TERMINAL_PERSISTENCE(new) publishes this identical image and deliberately
// keeps the transition and admission latched.
func (o *PendingOutpointOwner) publishRestoreLocked(snap pendingOutpointSnapshot, candidate pendingOutpointIndex) {
	o.byOutpoint = candidate.byOutpoint
	o.byToken = candidate.byToken
	if snap.tokenHighWater > o.tokenHighWater {
		o.tokenHighWater = snap.tokenHighWater
	}
	if snap.generationHighWater > o.generation {
		o.generation = snap.generationHighWater
	}
	o.stableTip = snap.stableTip
}
