package node

import (
	"bytes"
	"fmt"
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
	maxTxs := m.maxTxs
	maxBytes := m.maxBytes
	if maxTxs <= 0 || maxBytes <= 0 {
		return fmt.Errorf("invalid mempool snapshot restore limits: max_txs=%d max_bytes=%d", maxTxs, maxBytes)
	}
	txs := make(map[[32]byte]*mempoolEntry, len(snapshot.entries))
	wtxids := make(map[[32]byte][32]byte, len(snapshot.entries))
	spenders := make(map[consensus.Outpoint][32]byte)
	usedBytes := 0
	var nextAdmissionSeq uint64
	for _, item := range snapshot.entries {
		entry := cloneMempoolEntry(&item)
		if err := validateMempoolSnapshotEntry(entry); err != nil {
			return err
		}
		if _, exists := txs[entry.txid]; exists {
			return fmt.Errorf("duplicate mempool snapshot txid %x", entry.txid)
		}
		if existing, exists := wtxids[entry.wtxid]; exists {
			return fmt.Errorf("duplicate mempool snapshot wtxid %x existing=%x new=%x", entry.wtxid, existing, entry.txid)
		}
		if len(txs) >= maxTxs {
			return fmt.Errorf("mempool snapshot exceeds transaction cap: count=%d max=%d", len(txs)+1, maxTxs)
		}
		if entry.size > maxBytes || usedBytes > maxBytes-entry.size {
			return fmt.Errorf("mempool snapshot exceeds byte cap: used=%d entry=%d max=%d", usedBytes, entry.size, maxBytes)
		}
		for _, op := range entry.inputs {
			if existing, exists := spenders[op]; exists {
				return fmt.Errorf("duplicate mempool snapshot spender txid=%x vout=%d existing=%x new=%x", op.Txid, op.Vout, existing, entry.txid)
			}
			spenders[op] = entry.txid
		}
		entryCopy := entry
		txs[entryCopy.txid] = &entryCopy
		wtxids[entryCopy.wtxid] = entryCopy.txid
		usedBytes += entryCopy.size
		if entryCopy.admissionSeq > nextAdmissionSeq {
			nextAdmissionSeq = entryCopy.admissionSeq
		}
	}
	m.txs = txs
	m.wtxids = wtxids
	m.spenders = spenders
	m.usedBytes = usedBytes
	m.nextAdmissionSeq = nextAdmissionSeq
	return nil
}

func validateMempoolSnapshotEntry(entry mempoolEntry) error {
	if entry.size <= 0 {
		return fmt.Errorf("invalid mempool snapshot entry size for txid %x: size=%d raw_len=%d", entry.txid, entry.size, len(entry.raw))
	}
	if entry.size != len(entry.raw) {
		return fmt.Errorf("mempool snapshot entry size mismatch for txid %x: size=%d raw_len=%d", entry.txid, entry.size, len(entry.raw))
	}
	tx, txid, wtxid, consumed, err := consensus.ParseTx(entry.raw)
	if err != nil {
		return fmt.Errorf("invalid mempool snapshot entry raw for txid %x: %w", entry.txid, err)
	}
	if consumed != len(entry.raw) {
		return fmt.Errorf("mempool snapshot entry has trailing bytes for txid %x: consumed=%d raw_len=%d", entry.txid, consumed, len(entry.raw))
	}
	if txid != entry.txid {
		return fmt.Errorf("mempool snapshot entry txid mismatch: entry=%x raw=%x", entry.txid, txid)
	}
	if wtxid != entry.wtxid {
		return fmt.Errorf("mempool snapshot entry wtxid mismatch: entry=%x raw=%x", entry.wtxid, wtxid)
	}
	if entry.admissionSeq == 0 {
		return fmt.Errorf("invalid mempool snapshot entry admission_seq for txid %x: seq=0", entry.txid)
	}
	if !validMempoolTxSource(entry.source) {
		return fmt.Errorf("invalid mempool snapshot entry source for txid %x: source=%q", entry.txid, entry.source)
	}
	if len(entry.inputs) != len(tx.Inputs) {
		return fmt.Errorf("mempool snapshot entry input count mismatch for txid %x: entry=%d tx=%d", entry.txid, len(entry.inputs), len(tx.Inputs))
	}
	for i, in := range tx.Inputs {
		want := consensus.Outpoint{Txid: in.PrevTxid, Vout: in.PrevVout}
		if entry.inputs[i] != want {
			return fmt.Errorf("mempool snapshot entry input mismatch for txid %x at index=%d", entry.txid, i)
		}
	}
	return nil
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
