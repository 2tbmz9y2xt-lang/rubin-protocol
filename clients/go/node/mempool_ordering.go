package node

import (
	"bytes"
	"sort"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

func (m *Mempool) SelectTransactions(maxCount int, maxBytes int) [][]byte {
	if m == nil || maxCount <= 0 || maxBytes <= 0 {
		return nil
	}

	entries := m.snapshotEntries()
	sortMempoolEntries(entries)
	return pickEntries(entries, maxCount, maxBytes)
}

func (m *Mempool) snapshotEntries() []*mempoolEntry {
	m.mu.RLock()
	defer m.mu.RUnlock()
	entries := make([]*mempoolEntry, 0, len(m.txs))
	for _, entry := range m.txs {
		entries = append(entries, entry)
	}
	return entries
}

func sortMempoolEntries(entries []*mempoolEntry) {
	sort.Slice(entries, func(i, j int) bool {
		if cmp := compareFeeRate(entries[i], entries[j]); cmp != 0 {
			return cmp > 0
		}
		if cmp := entries[i].fee.Cmp(entries[j].fee); cmp != 0 {
			return cmp > 0
		}
		if entries[i].weight != entries[j].weight {
			return entries[i].weight < entries[j].weight
		}
		return bytes.Compare(entries[i].txid[:], entries[j].txid[:]) < 0
	})
}

func pickEntries(entries []*mempoolEntry, maxCount int, maxBytes int) [][]byte {
	selected := make([][]byte, 0, len(entries))
	usedBytes := 0
	for _, entry := range entries {
		if len(selected) >= maxCount {
			break
		}
		if entry.size > maxBytes-usedBytes {
			continue
		}
		selected = append(selected, append([]byte(nil), entry.raw...))
		usedBytes += entry.size
	}
	return selected
}

func compareFeeRate(a *mempoolEntry, b *mempoolEntry) int {
	if a == nil || b == nil {
		return 0
	}
	return compareFeeRateWeightValues(a.fee, a.weight, b.fee, b.weight)
}

func compareEvictionFeeRate(a *mempoolEntry, b *mempoolEntry) int {
	// Eviction and miner selection intentionally share the fee/weight axis.
	return compareFeeRate(a, b)
}

// compareFeeRateWeightValues compares feeA/weightA against feeB/weightB by
// exact cross-multiplication. The u128 fee by u64 weight product needs up to
// 192 bits and consensus.CompareFeeRate retains every one of them, so two
// entries whose significant product bits exceed bit 127 still order exactly.
func compareFeeRateWeightValues(feeA consensus.Uint128, weightA uint64, feeB consensus.Uint128, weightB uint64) int {
	return consensus.CompareFeeRate(feeA, weightA, feeB, weightB)
}
