package node

import (
	"bytes"
	"sort"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

type mempoolSnapshot struct {
	entries []mempoolEntry
}

func snapshotMempool(m *Mempool) (mempoolSnapshot, error) {
	if m == nil {
		return mempoolSnapshot{}, nil
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	entries := make([]mempoolEntry, 0, len(m.txs))
	for _, entry := range m.txs {
		entries = append(entries, cloneMempoolEntry(entry))
	}
	sort.Slice(entries, func(i, j int) bool {
		return bytes.Compare(entries[i].txid[:], entries[j].txid[:]) < 0
	})
	return mempoolSnapshot{entries: entries}, nil
}

func restoreMempoolSnapshot(m *Mempool, snapshot mempoolSnapshot) error {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.txs = make(map[[32]byte]*mempoolEntry, len(snapshot.entries))
	m.spenders = make(map[consensus.Outpoint][32]byte)
	for _, item := range snapshot.entries {
		entry := cloneMempoolEntry(&item)
		m.txs[entry.txid] = &entry
		for _, op := range entry.inputs {
			m.spenders[op] = entry.txid
		}
	}
	return nil
}

func cloneMempoolEntry(entry *mempoolEntry) mempoolEntry {
	if entry == nil {
		return mempoolEntry{}
	}
	return mempoolEntry{
		raw:    append([]byte(nil), entry.raw...),
		txid:   entry.txid,
		inputs: append([]consensus.Outpoint(nil), entry.inputs...),
		fee:    entry.fee,
		weight: entry.weight,
		size:   entry.size,
	}
}
