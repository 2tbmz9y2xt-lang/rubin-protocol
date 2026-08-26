package node

import (
	"errors"
	"fmt"
	"math"
)

const (
	canonicalPlanMetadataBaseBytes = 48
	canonicalPlanMetadataRowBytes  = 40
	canonicalPlanMetadataIDBytes   = 32

	// canonicalPlanDAIdentityBytes is one privately retained included identity's
	// fixed cost: da_id, the commit's txid and wtxid, and its aligned
	// chunk-count metadata. canonicalPlanDAChunkIdentityBytes is one chunk
	// identity: the u16 index plus txid and wtxid, rounded to the charge's
	// 8-byte unit. Both are multiples of 8, so they preserve the property the
	// cap comparison below relies on.
	canonicalPlanDAIdentityBytes      = 104
	canonicalPlanDAChunkIdentityBytes = 72

	// canonicalPlanMetadataCapBytes is the 64 MiB production cap on the charge
	// below. The exact cap is accepted; every term is a multiple of 8, so the
	// smallest realizable overflow is cap+8.
	canonicalPlanMetadataCapBytes = uint64(67108864)
)

// canonicalPlanMetadataCap is the live cap on the production charge path. It is
// package-private and exists so a test can drive the REAL refusal with a small
// plan instead of a parallel copy of the rule; it is the only such override and
// there is no public, CLI, file or RPC knob.
var canonicalPlanMetadataCap = canonicalPlanMetadataCapBytes

// errCanonicalPlanMetadataCap refuses a plan whose charged metadata exceeds the
// cap. It fires BEFORE any artifact write, checkpoint replacement, owner
// generation advance or live mutation, so a refused plan changes nothing.
var errCanonicalPlanMetadataCap = errors.New("LOCAL_RESOURCE_UNAVAILABLE(canonical_plan_metadata)")

// canonicalPlanMetadataCharge bills the plan's row metadata:
// 48 + 40*(disconnect_rows+connect_rows) + 32*sum(len(A1[row].CompleteDAIDs))
// + 104*len(I) + 72*sum(len(I[i].chunks)).
// Every term is checked, so no count can wrap the total back under the cap.
//
// It bills THAT and nothing else. The two private O(UTXO) ChainState images and
// the O(height) old/new canonical sequences the plan also holds are normed
// separately by the contract's resource_bounds, so this cap is not a bound on
// the plan's total memory. The prepared retained-DA image is likewise outside it:
// it clones maps and shares retained payload, and the DA byte and count caps
// already bound what it can point at.
func canonicalPlanMetadataCharge(disconnect, connect []canonicalRowDescriptor, applied []CanonicalAppliedBlock, includedDA []canonicalDASetIdentity) (uint64, error) {
	rows := uint64(len(disconnect)) + uint64(len(connect))
	total, err := addCanonicalPlanBytes(canonicalPlanMetadataBaseBytes, canonicalPlanMetadataRowBytes, rows)
	if err != nil {
		return 0, err
	}
	ids := uint64(0)
	for i := range applied {
		if ids, err = addCanonicalPlanBytes(ids, 1, uint64(len(applied[i].CompleteDAIDs))); err != nil {
			return 0, err
		}
	}
	if total, err = addCanonicalPlanBytes(total, canonicalPlanMetadataIDBytes, ids); err != nil {
		return 0, err
	}
	chunks := uint64(0)
	for i := range includedDA {
		if chunks, err = addCanonicalPlanBytes(chunks, 1, uint64(len(includedDA[i].chunks))); err != nil {
			return 0, err
		}
	}
	if total, err = addCanonicalPlanBytes(total, canonicalPlanDAIdentityBytes, uint64(len(includedDA))); err != nil {
		return 0, err
	}
	return addCanonicalPlanBytes(total, canonicalPlanDAChunkIdentityBytes, chunks)
}

// addCanonicalPlanBytes returns total+unit*count, refusing any overflow.
func addCanonicalPlanBytes(total, unit, count uint64) (uint64, error) {
	if count != 0 && unit > (math.MaxUint64-total)/count {
		return 0, errCanonicalPlanMetadataCap
	}
	return total + unit*count, nil
}

// checkCanonicalPlanMetadataBound is METADATA_BOUND: it runs after old identity
// and C1/A1 planning and BEFORE any artifact, checkpoint, generation or live
// work, so an over-cap plan is refused with nothing mutated.
func (p *canonicalTransitionPlan) checkCanonicalPlanMetadataBound() error {
	charge, err := canonicalPlanMetadataCharge(p.disconnect, p.connect, p.applied, p.includedDA)
	if err != nil {
		return err
	}
	return canonicalPlanMetadataBoundError(charge)
}

// canonicalPlanMetadataBoundError is the cap comparison itself. The exact cap is
// accepted; every charge term is a multiple of 8, so the smallest realizable
// overflow is cap+8.
func canonicalPlanMetadataBoundError(charge uint64) error {
	if charge > canonicalPlanMetadataCap {
		return fmt.Errorf("%w: charge=%d cap=%d", errCanonicalPlanMetadataCap, charge, canonicalPlanMetadataCap)
	}
	return nil
}
