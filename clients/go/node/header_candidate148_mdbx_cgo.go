//go:build cgo && (darwin || linux) && (amd64 || arm64)

package node

import "github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"

var _ consensus.ReplayHeaderCandidateView148V1 = (*HeaderCandidateOwner148V1)(nil)

// Inventory148V1 returns every admitted tip and received header at the current version, CapacityRefused above the
// smaller of limit and MaxSnapshotBytes, or Incomplete when not established, latched or closed. Arrays are the caller's.
func (o *HeaderCandidateOwner148V1) Inventory148V1(limit uint64) consensus.HeaderCandidateInventory148V1 {
	o.mu.Lock()
	defer o.mu.Unlock()
	inv := consensus.HeaderCandidateInventory148V1{Status: consensus.HeaderCandidateIncompleteV1, Version: o.version.Load()}
	if !o.established || o.latched || o.closed {
		return inv
	}
	size, ok := hcInventoryBytes(o.tips, uint64(len(o.recs)))
	if !ok || size > min(limit, o.limits.MaxSnapshotBytes) {
		inv.Status = consensus.HeaderCandidateCapacityRefusedV1
		return inv
	}
	inv.Status, inv.Bytes = consensus.HeaderCandidateCompleteV1, size
	inv.Tips, inv.Headers = o.copyInventory()
	return inv
}
