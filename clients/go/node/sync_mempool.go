package node

import (
	"bytes"
	"fmt"
	"sort"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

type mempoolSnapshot struct {
	entries           []mempoolEntry
	lastAdmissionSeq  uint64
	currentMinFeeRate uint64
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
	currentMinFeeRate := m.currentMinFeeRate
	if currentMinFeeRate < DefaultMempoolMinFeeRate {
		currentMinFeeRate = DefaultMempoolMinFeeRate
	}
	return mempoolSnapshot{entries: entries, lastAdmissionSeq: m.lastAdmissionSeq, currentMinFeeRate: currentMinFeeRate}, nil
}

func restoreMempoolSnapshot(m *Mempool, snapshot mempoolSnapshot) error {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.maxTxs <= 0 || m.maxBytes <= 0 {
		return fmt.Errorf("invalid mempool snapshot restore limits: max_txs=%d max_bytes=%d", m.maxTxs, m.maxBytes)
	}
	txs, wtxids, spenders, maxAdmissionSeq, usedBytes, err := buildMempoolRestoreMaps(snapshot.entries, m.maxTxs, m.maxBytes)
	if err != nil {
		return err
	}
	if snapshot.lastAdmissionSeq < maxAdmissionSeq {
		return fmt.Errorf("mempool snapshot admission high-watermark below restored max: last=%d max=%d", snapshot.lastAdmissionSeq, maxAdmissionSeq)
	}
	m.txs = txs
	m.wtxids = wtxids
	m.spenders = spenders
	m.usedBytes = usedBytes
	m.lastAdmissionSeq = snapshot.lastAdmissionSeq
	m.currentMinFeeRate = snapshot.currentMinFeeRate
	m.ensureMinFeeRateLocked()
	return nil
}

func validateMempoolSnapshotEntry(entry mempoolEntry) error {
	if entry.size <= 0 {
		return fmt.Errorf("invalid mempool snapshot entry size for txid %x: size=%d raw_len=%d", entry.txid, entry.size, len(entry.raw))
	}
	if entry.weight == 0 {
		return fmt.Errorf("invalid mempool snapshot entry weight for txid %x: weight=0", entry.txid)
	}
	if entry.size != len(entry.raw) {
		return fmt.Errorf("mempool snapshot entry size mismatch for txid %x: size=%d raw_len=%d", entry.txid, entry.size, len(entry.raw))
	}
	return validateMempoolEntryParsed(entry)
}

func cloneMempoolEntry(entry *mempoolEntry) mempoolEntry {
	if entry == nil {
		return mempoolEntry{}
	}
	return mempoolEntry{
		raw:          append([]byte(nil), entry.raw...),
		txid:         entry.txid,
		wtxid:        entry.wtxid,
		inputs:       append([]consensus.Outpoint(nil), entry.inputs...),
		fee:          entry.fee,
		weight:       entry.weight,
		size:         entry.size,
		admissionSeq: entry.admissionSeq,
		source:       entry.source,
	}
}
