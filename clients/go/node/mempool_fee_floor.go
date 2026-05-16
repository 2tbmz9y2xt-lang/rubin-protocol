package node

import (
	"fmt"
	"math/bits"
)

// validateFeeFloorLocked enforces the rolling-relay-floor invariant
// using the live `m.currentMinFeeRate` value. Production callers
// SHOULD use `validateFeeFloorLockedWithFloor` to thread a snapped
// floor value through (see wave-6 race fix); this wrapper exists for
// test callers that drive the helper in isolation.
func (m *Mempool) validateFeeFloorLocked(entry *mempoolEntry) error {
	return m.validateFeeFloorLockedWithFloor(entry, m.currentMinFeeRateLocked())
}

// validateFeeFloorLockedWithFloor is the wave-8 race-safe entry point.
// `snappedFloor` is the floor value captured ONCE in `addTxWithSource`
// before the cheap precheck fired. The locked check enforces the
// MAXIMUM of (snappedFloor, live currentMinFeeRate) so newer higher
// floors always win.
//
// Bidirectional race protection:
//   - decay race (Copilot wave-5): if `decayMinFeeRateAfterConnectedBlockLocked`
//     fires between snap and lock, snappedFloor (higher) wins → tx
//     rejected here too. Caller may retry against the new lower
//     snapshot and admit — spurious reject is the lesser evil
//     (acceptable per Copilot's wave-7 recommendation).
//   - raise race (Codex + Copilot wave-7): if
//     `raiseMinFeeRateAfterEvictionLocked` fires between snap and
//     lock, live `currentMinFeeRate` (higher) wins → tx correctly
//     rejected against the current congestion-control policy. NEVER
//     admits a transaction below the current rolling floor.
//
// A prior snap-once pass-through closed the decay race in one direction but
// introduced the raise race in the opposite direction. The locked re-read with
// max-of-(snap, live) closes both sides.
func (m *Mempool) validateFeeFloorLockedWithFloor(entry *mempoolEntry, snappedFloor uint64) error {
	if entry == nil {
		return txAdmitRejected("nil mempool entry")
	}
	floor := snappedFloor
	if live := m.currentMinFeeRateLocked(); live > floor {
		floor = live
	}
	if feeRateBelowFloor(entry.fee, entry.weight, floor) {
		return txAdmitUnavailable(fmt.Sprintf("mempool fee below rolling minimum: fee=%d weight=%d min_fee_rate=%d", entry.fee, entry.weight, floor))
	}
	return nil
}

func (m *Mempool) ensureMinFeeRateLocked() {
	if m.currentMinFeeRate < DefaultMempoolMinFeeRate {
		m.currentMinFeeRate = DefaultMempoolMinFeeRate
	}
}

func (m *Mempool) currentMinFeeRateLocked() uint64 {
	if m.currentMinFeeRate < DefaultMempoolMinFeeRate {
		return DefaultMempoolMinFeeRate
	}
	return m.currentMinFeeRate
}

// CurrentMinFeeRateSnapshot returns the rolling local floor without
// requiring the caller to already hold m.mu. It briefly takes a read
// lock so that race-free Stage C admission helpers (which run under a
// chainstate-side lock, not m.mu) can read the value safely.
//
// It is exported so that external callers (e.g. the miner template
// loop in cmd/rubin-node) can wire MinerConfig.CurrentMempoolMinFeeRateFn
// directly to it and keep the relay-fee half of the Stage C admission
// contract aligned with the rolling floor.
//
// Nil-safe like the other exported Mempool accessors (BytesUsed,
// AdmissionCounts, Contains): a nil receiver returns
// DefaultMempoolMinFeeRate so test-time wiring or fail-closed paths
// that never construct a Mempool see the documented baseline floor
// instead of a panic from m.mu.RLock().
func (m *Mempool) CurrentMinFeeRateSnapshot() uint64 {
	if m == nil {
		return DefaultMempoolMinFeeRate
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.currentMinFeeRateLocked()
}

// SetCurrentMinFeeRateForTest overrides the rolling local floor. Test-only:
// bypasses the admit-path eviction logic that normally raises the floor.
// cmd/rubin-node tests inject a distinctive sentinel through this setter so
// the live miner wiring tests bind on the exact value, instead of admitting
// any closure returning the documented baseline. Nil-safe like the other
// accessors.
func (m *Mempool) SetCurrentMinFeeRateForTest(floor uint64) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.currentMinFeeRate = floor
}

func (m *Mempool) effectiveLowWaterBytesLocked() int {
	if m.lowWaterBytes > 0 || m.maxBytes <= 0 {
		return m.lowWaterBytes
	}
	return defaultMempoolLowWaterBytes(m.maxBytes)
}

func feeRateBelowFloor(fee uint64, weight uint64, floor uint64) bool {
	if weight == 0 {
		return true
	}
	if floor < DefaultMempoolMinFeeRate {
		floor = DefaultMempoolMinFeeRate
	}
	hi, lo := bits.Mul64(weight, floor)
	if hi != 0 {
		return true
	}
	return fee < lo
}

func (m *Mempool) raiseMinFeeRateAfterEvictionLocked(evictedEntries []*mempoolEntry) {
	if len(evictedEntries) == 0 {
		return
	}
	m.ensureMinFeeRateLocked()
	var highestEvictedFloor uint64
	for _, entry := range evictedEntries {
		floor, ok := entryFloorRate(entry)
		if ok && floor > highestEvictedFloor {
			highestEvictedFloor = floor
		}
	}
	raised := saturatingAddMinRelayFeeStep(highestEvictedFloor)
	if raised > m.currentMinFeeRate {
		m.currentMinFeeRate = raised
	}
}

func (m *Mempool) decayMinFeeRateAfterConnectedBlockLocked() {
	m.ensureMinFeeRateLocked()
	if m.usedBytes >= m.effectiveLowWaterBytesLocked() {
		return
	}
	decayed := m.currentMinFeeRate / 2
	if decayed < DefaultMempoolMinFeeRate {
		decayed = DefaultMempoolMinFeeRate
	}
	m.currentMinFeeRate = decayed
}

func entryFloorRate(entry *mempoolEntry) (uint64, bool) {
	if entry == nil || entry.weight == 0 {
		return 0, false
	}
	return entry.fee / entry.weight, true
}

func saturatingAddMinRelayFeeStep(v uint64) uint64 {
	if v > ^uint64(0)-DefaultMempoolMinFeeRate {
		return ^uint64(0)
	}
	return v + DefaultMempoolMinFeeRate
}
