package node

import (
	"bytes"
	"fmt"
)

func defaultMempoolLowWaterBytes(maxBytes int) int {
	if maxBytes <= 0 {
		return 0
	}
	lowWater := (maxBytes/mempoolLowWaterDenominator)*mempoolLowWaterNumerator +
		((maxBytes % mempoolLowWaterDenominator) * mempoolLowWaterNumerator / mempoolLowWaterDenominator)
	if lowWater == 0 {
		return 1
	}
	return lowWater
}

type mempoolEvictionPlanEntry struct {
	entry     *mempoolEntry
	candidate bool
}

type mempoolCapacityState struct {
	maxBytes      uint64
	candidateSize uint64
	usedBytes     uint64
	targetBytes   uint64
	totalBytes    uint64
	totalCount    int
	countPressure bool
	bytePressure  bool
}

func (m *Mempool) validateCapacityAdmissionLocked(entry *mempoolEntry, snappedFloor uint64) ([]*mempoolEntry, error) {
	if err := m.validateFeeFloorLockedWithFloor(entry, snappedFloor); err != nil {
		return nil, err
	}
	evictedEntries, candidateEvicted, err := m.capacityEvictionPlanLocked(entry)
	if err != nil {
		return nil, err
	}
	if candidateEvicted {
		return nil, txAdmitUnavailable("mempool capacity candidate rejected by eviction ordering")
	}
	return evictedEntries, nil
}

func (m *Mempool) capacityEvictionPlanLocked(candidate *mempoolEntry) ([]*mempoolEntry, bool, error) {
	if candidate == nil {
		return nil, false, txAdmitRejected("nil mempool entry")
	}
	state, err := m.capacityStateLocked(candidate)
	if err != nil {
		return nil, false, err
	}
	if !state.underPressure() {
		return nil, false, nil
	}
	planPool, err := m.evictionPlanPoolLocked(candidate)
	if err != nil {
		return nil, false, err
	}
	return dryRunCapacityEvictions(planPool, state, m.maxTxs)
}

func (m *Mempool) capacityStateLocked(candidate *mempoolEntry) (mempoolCapacityState, error) {
	maxBytes, err := nonNegativeMempoolIntToUint64("max_bytes", m.maxBytes)
	if err != nil {
		return mempoolCapacityState{}, err
	}
	if m.maxTxs <= 0 || maxBytes == 0 {
		return mempoolCapacityState{}, txAdmitUnavailable(fmt.Sprintf("invalid mempool capacity limits: max_txs=%d max_bytes=%d", m.maxTxs, m.maxBytes))
	}
	candidateSize, err := nonNegativeMempoolIntToUint64("candidate_size", candidate.size)
	if err != nil {
		return mempoolCapacityState{}, err
	}
	usedBytes, err := nonNegativeMempoolIntToUint64("used_bytes", m.usedBytes)
	if err != nil {
		return mempoolCapacityState{}, err
	}
	if candidateSize > maxBytes {
		return mempoolCapacityState{}, txAdmitUnavailable(fmt.Sprintf("mempool byte limit exceeded: current=%d tx=%d max=%d", m.usedBytes, candidate.size, m.maxBytes))
	}
	countPressure := len(m.txs) >= m.maxTxs
	bytePressure := usedBytes > maxBytes-candidateSize
	targetBytes := maxBytes
	if bytePressure {
		targetBytes = mempoolBytePressureTarget(uint64(m.effectiveLowWaterBytesLocked()), candidateSize) // #nosec G115 -- effectiveLowWaterBytesLocked returns 0 or a positive value derived from positive maxBytes.
	}
	return mempoolCapacityState{
		maxBytes:      maxBytes,
		candidateSize: candidateSize,
		usedBytes:     usedBytes,
		targetBytes:   targetBytes,
		totalBytes:    usedBytes + candidateSize,
		totalCount:    len(m.txs) + 1,
		countPressure: countPressure,
		bytePressure:  bytePressure,
	}, nil
}

func mempoolBytePressureTarget(lowWaterBytes uint64, candidateSize uint64) uint64 {
	if lowWaterBytes < candidateSize {
		return candidateSize
	}
	return lowWaterBytes
}

func (state mempoolCapacityState) underPressure() bool {
	return state.countPressure || state.bytePressure
}

func (m *Mempool) evictionPlanPoolLocked(candidate *mempoolEntry) ([]mempoolEvictionPlanEntry, error) {
	planPool := make([]mempoolEvictionPlanEntry, 0, len(m.txs)+1)
	admissionSeqs := make(map[uint64][32]byte, len(m.txs))
	for _, entry := range m.txs {
		if err := validateEvictionMetadata(entry); err != nil {
			return nil, err
		}
		if existing, exists := admissionSeqs[entry.admissionSeq]; exists {
			return nil, txAdmitRejected(fmt.Sprintf("duplicate mempool entry admission_seq %d existing=%x new=%x", entry.admissionSeq, existing, entry.txid))
		}
		admissionSeqs[entry.admissionSeq] = entry.txid
		planPool = append(planPool, mempoolEvictionPlanEntry{entry: entry})
	}
	planPool = append(planPool, mempoolEvictionPlanEntry{entry: candidate, candidate: true})
	return planPool, nil
}

func dryRunCapacityEvictions(planPool []mempoolEvictionPlanEntry, state mempoolCapacityState, maxTxs int) ([]*mempoolEntry, bool, error) {
	evictedEntries := make([]*mempoolEntry, 0)
	for state.exceedsEvictionTarget(maxTxs) && len(planPool) > 0 {
		worstIndex := worstEvictionPlanIndex(planPool)
		worst := planPool[worstIndex]
		if worst.candidate {
			return nil, true, nil
		}
		evictedEntries = append(evictedEntries, worst.entry)
		if err := state.applyDryRunEviction(worst.entry); err != nil {
			return nil, false, err
		}
		planPool = append(planPool[:worstIndex], planPool[worstIndex+1:]...)
	}
	if state.exceedsHardCapacity(maxTxs) {
		return nil, false, txAdmitUnavailable(fmt.Sprintf("mempool capacity remains exceeded after dry-run eviction: count=%d/%d bytes=%d/%d", state.totalCount, maxTxs, state.totalBytes, state.maxBytes))
	}
	return evictedEntries, false, nil
}

func (state mempoolCapacityState) exceedsEvictionTarget(maxTxs int) bool {
	return state.totalCount > maxTxs || state.totalBytes > state.targetBytes
}

func (state mempoolCapacityState) exceedsHardCapacity(maxTxs int) bool {
	return state.totalCount > maxTxs || state.totalBytes > state.maxBytes
}

func (state *mempoolCapacityState) applyDryRunEviction(entry *mempoolEntry) error {
	worstSize := uint64(entry.size) // #nosec G115 -- validateEvictionMetadata rejects non-positive entry sizes before this helper.
	if state.totalBytes < worstSize {
		return txAdmitUnavailable("mempool eviction byte accounting underflow")
	}
	state.totalBytes -= worstSize
	state.totalCount--
	return nil
}

func worstEvictionPlanIndex(planPool []mempoolEvictionPlanEntry) int {
	worstIndex := 0
	for i := 1; i < len(planPool); i++ {
		if evictionPlanEntryWorse(planPool[i], planPool[worstIndex]) {
			worstIndex = i
		}
	}
	return worstIndex
}

func nonNegativeMempoolIntToUint64(label string, value int) (uint64, error) {
	if value < 0 {
		return 0, txAdmitUnavailable(fmt.Sprintf("invalid mempool %s: %d", label, value))
	}
	return uint64(value), nil
}

func validateEvictionMetadata(entry *mempoolEntry) error {
	if entry == nil {
		return txAdmitRejected("nil mempool entry")
	}
	if entry.txid == ([32]byte{}) {
		return txAdmitRejected("invalid mempool entry txid")
	}
	if entry.size <= 0 {
		return txAdmitRejected("invalid mempool entry size")
	}
	if entry.weight == 0 {
		return txAdmitRejected("invalid mempool entry weight")
	}
	if entry.admissionSeq == 0 {
		return txAdmitRejected(fmt.Sprintf("invalid mempool entry admission_seq for txid %x", entry.txid))
	}
	return nil
}

func evictionPlanEntryWorse(a, b mempoolEvictionPlanEntry) bool {
	if a.entry == nil || b.entry == nil {
		return a.entry != nil && b.entry == nil
	}
	if cmp := compareMempoolEvictionPriority(a, b); cmp != 0 {
		return cmp < 0
	}
	return bytes.Compare(a.entry.txid[:], b.entry.txid[:]) > 0
}

func compareMempoolEvictionPriority(a, b mempoolEvictionPlanEntry) int {
	if a.entry == nil || b.entry == nil {
		return 0
	}
	if cmp := compareEvictionFeeRate(a.entry, b.entry); cmp != 0 {
		return cmp
	}
	if a.entry.fee != b.entry.fee {
		if a.entry.fee > b.entry.fee {
			return 1
		}
		return -1
	}
	aSeq := evictionAdmissionSeq(a)
	bSeq := evictionAdmissionSeq(b)
	if aSeq != bSeq {
		if aSeq > bSeq {
			return 1
		}
		return -1
	}
	return 0
}

func evictionAdmissionSeq(entry mempoolEvictionPlanEntry) uint64 {
	if entry.candidate {
		// Treat the candidate as oldest on exact fee ties so capacity pressure is no-RBF.
		return 0
	}
	if entry.entry == nil {
		return 0
	}
	return entry.entry.admissionSeq
}
