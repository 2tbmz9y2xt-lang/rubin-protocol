//go:build cgo && (darwin || linux) && (amd64 || arm64)

package consensus

import "github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/mdbx"

// Dormant fixed-148 header-candidate facets of the replay entry, path and recovery lanes (RUBIN_COMPACT_BLOCKS.md
// Section 7.1.1, RUBIN_MEMPOOL_POLICY.md Section 6.4.1.8). No production caller.

const (
	// replayEntryWalk148Bytes is replayEntryWalkBytes with two raw 148-byte headers.
	replayEntryWalk148Bytes uint64 = 2*8*WINDOW_SIZE + 2*8*11 + uint64(replayEntryPageRows)*(16+104+48) + 78 + 2*148 + 2*32 + 8*40
	// replayEntryInventory148Limit is the largest accepted 148 inventory Bytes of the full lane.
	replayEntryInventory148Limit = (mdbx.MaxOperationDataBytes - replayEntryIdentityBytes - replayEntryWalk148Bytes - replayEntryPlanBytes) * 148 / (148 + replayEntryDerivedBytes)
	// replayRecoveryMin148Bytes is M148, the identity, walk and plan terms of the 148 lane.
	replayRecoveryMin148Bytes = replayEntryIdentityBytes + replayEntryWalk148Bytes + replayEntryPlanBytes
)

// Compiles only if LANE_MAX >= identity + walk148 + plan + limit148 + D_h * floor(limit148/148) (its most headers).
const _ = mdbx.MaxOperationDataBytes - (replayEntryIdentityBytes + replayEntryWalk148Bytes + replayEntryPlanBytes + replayEntryInventory148Limit + replayEntryInventory148Limit/148*replayEntryDerivedBytes)

// HeaderCandidateInventory148V1 is one finite inventory over raw 148-byte headers. Complete: Tips holds every admitted
// received candidate tip hash and Headers every received header on each tip's path down to the lowest received
// ancestor, as raw 148-byte headers in no relied-on order, with Bytes = 32*len(Tips) + 148*len(Headers) <= limit. A
// path's lowest header attaches to a durable canonical parent of the active generation (empty active index: the Fork F
// anchor) or, for the pre-activation recomputation, to an accepted target-generation entry at a height at or below the
// cursor; otherwise the evidence is incomplete. An inventory above limit is CapacityRefused, never a truncated Complete.
// Incomplete and CapacityRefused carry empty Tips and Headers and Bytes 0. Version identifies the admitted-candidate
// set: it advances on every admitted-membership change and producer update, never on derived cache eviction, and is
// opaque to the consumer.
type HeaderCandidateInventory148V1 struct {
	Status  HeaderCandidateStatusV1
	Version uint64
	Tips    [][32]byte
	Headers [][148]byte
	Bytes   uint64
}

// HeaderCandidateView148V1 is the process-local, versioned, never-persisted 148-byte candidate view
// (RUBIN_MEMPOOL_POLICY.md Section 6.4.1.8). Inventory148V1 returns Complete, Incomplete or CapacityRefused. ProtectV1
// acquires the producer guard and returns whether version is still current and a non-nil release that the caller runs
// exactly once. Inventory148V1 hands the returned Tips and Headers to the caller: the producer neither retains nor
// modifies them after it returns, so the caller may reorder and deduplicate them in place and read them without the
// producer guard.
type HeaderCandidateView148V1 interface {
	Inventory148V1(limit uint64) HeaderCandidateInventory148V1
	ProtectV1(version uint64) (current bool, release func())
}

// ReplayHeaderCandidateView148V1 is ReplayHeaderCandidateViewV1 over 148-byte headers. VersionV1 is a race-safe scalar
// read with no enumeration, copy or allocation. Header148V1 writes exactly the 148 raw admitted bytes named by hash into
// dst and returns true when present; it does not retain dst or write it after returning, gives no validity result, and
// dst content is meaningless on false. Both methods are callable while the caller holds the ProtectV1 guard. A nil
// optional interface is normal absence and calls no method; a nonnil interface holding a typed-nil provider follows its
// actual method, error and panic behavior, without reflection filtering.
type ReplayHeaderCandidateView148V1 interface {
	HeaderCandidateView148V1
	VersionV1() uint64
	Header148V1(hash [32]byte, dst *[148]byte) bool
}

// replayEntryInventory148 is replayEntryInventory over the 148 inventory; the inventory is returned unchanged.
func replayEntryInventory148(view HeaderCandidateView148V1, limit uint64) (HeaderCandidateInventory148V1, string) {
	if view == nil {
		return HeaderCandidateInventory148V1{}, replayEntryRecovery
	}
	inv := view.Inventory148V1(limit)
	if inv.Bytes != 32*uint64(len(inv.Tips))+148*uint64(len(inv.Headers)) || inv.Bytes > limit {
		return inv, selectedSideInvariant
	}
	switch {
	case inv.Status == HeaderCandidateCompleteV1:
		return inv, ""
	case inv.Bytes != 0:
		return inv, selectedSideInvariant
	case inv.Status == HeaderCandidateIncompleteV1:
		return inv, replayEntryRecovery
	case inv.Status == HeaderCandidateCapacityRefusedV1:
		return inv, selectedSideCapacity
	}
	return inv, selectedSideInvariant
}

// replayInvLimit148 is floor((lane - M148) * 148 / (148 + D_h)) for M148 <= lane <= LANE_MAX; zero is the full lane.
func replayInvLimit148(lane uint64) uint64 {
	if lane == 0 {
		lane = mdbx.MaxOperationDataBytes
	}
	return (lane - replayRecoveryMin148Bytes) * 148 / (148 + replayEntryDerivedBytes)
}

// replayHeaderBind148 is structural parse and hash binding only, never PoW, target, timestamp, ancestry or validity;
// raw is read only during the call. The header is not relied on when the result is false.
func replayHeaderBind148(raw []byte, hash [32]byte) (Initial148Header, bool) {
	header, err := ParseInitial148HeaderBytes(raw)
	if err != nil {
		return header, false
	}
	got, err := Initial148BlockHash(raw)
	return header, err == nil && got == hash
}
