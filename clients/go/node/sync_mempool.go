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

type mempoolRestoreMaps struct {
	txs             map[[32]byte]*mempoolEntry
	wtxids          map[[32]byte][32]byte
	spenders        map[consensus.Outpoint][32]byte
	admissionSeqs   map[uint64][32]byte
	maxAdmissionSeq uint64
	usedBytes       int
}

func newMempoolRestoreMaps(capacity int) mempoolRestoreMaps {
	return mempoolRestoreMaps{
		txs:           make(map[[32]byte]*mempoolEntry, capacity),
		wtxids:        make(map[[32]byte][32]byte, capacity),
		spenders:      make(map[consensus.Outpoint][32]byte),
		admissionSeqs: make(map[uint64][32]byte, capacity),
	}
}

// buildMempoolRestoreMaps builds txid/wtxid/spender/admission maps from snapshot entries.
func buildMempoolRestoreMaps(snapshotEntries []mempoolEntry, maxTxs int, maxBytes int) (
	txs map[[32]byte]*mempoolEntry,
	wtxids map[[32]byte][32]byte,
	spenders map[consensus.Outpoint][32]byte,
	maxAdmissionSeq uint64,
	usedBytes int,
	err error,
) {
	restored := newMempoolRestoreMaps(len(snapshotEntries))
	for _, item := range snapshotEntries {
		entry := cloneMempoolEntry(&item)
		if err := restored.add(entry, maxTxs, maxBytes); err != nil {
			return nil, nil, nil, 0, 0, err
		}
	}
	return restored.txs, restored.wtxids, restored.spenders, restored.maxAdmissionSeq, restored.usedBytes, nil
}

func (restored *mempoolRestoreMaps) add(entry mempoolEntry, maxTxs int, maxBytes int) error {
	if err := restored.validateUniqueIDs(entry); err != nil {
		return err
	}
	if err := validateMempoolSnapshotEntry(entry); err != nil {
		return err
	}
	if err := restored.validateAdmissionSeq(entry); err != nil {
		return err
	}
	if err := restored.validateCapacity(entry, maxTxs, maxBytes); err != nil {
		return err
	}
	if err := restored.addSpenders(entry); err != nil {
		return err
	}
	restored.store(entry)
	return nil
}

func (restored *mempoolRestoreMaps) validateUniqueIDs(entry mempoolEntry) error {
	if _, exists := restored.txs[entry.txid]; exists {
		return fmt.Errorf("duplicate mempool snapshot txid %x", entry.txid)
	}
	if existing, exists := restored.wtxids[entry.wtxid]; exists {
		return fmt.Errorf("duplicate mempool snapshot wtxid %x existing=%x new=%x", entry.wtxid, existing, entry.txid)
	}
	return nil
}

func (restored *mempoolRestoreMaps) validateAdmissionSeq(entry mempoolEntry) error {
	if existing, exists := restored.admissionSeqs[entry.admissionSeq]; exists {
		return fmt.Errorf("duplicate mempool snapshot admission_seq %d existing=%x new=%x", entry.admissionSeq, existing, entry.txid)
	}
	return nil
}

func (restored *mempoolRestoreMaps) validateCapacity(entry mempoolEntry, maxTxs int, maxBytes int) error {
	if len(restored.txs) >= maxTxs {
		return fmt.Errorf("mempool snapshot exceeds transaction cap: count=%d max=%d", len(restored.txs)+1, maxTxs)
	}
	if entry.size > maxBytes || restored.usedBytes > maxBytes-entry.size {
		return fmt.Errorf("mempool snapshot exceeds byte cap: used=%d entry=%d max=%d", restored.usedBytes, entry.size, maxBytes)
	}
	return nil
}

func (restored *mempoolRestoreMaps) addSpenders(entry mempoolEntry) error {
	for _, op := range entry.inputs {
		if existing, exists := restored.spenders[op]; exists {
			return fmt.Errorf("duplicate mempool snapshot spender txid=%x vout=%d existing=%x new=%x", op.Txid, op.Vout, existing, entry.txid)
		}
		restored.spenders[op] = entry.txid
	}
	return nil
}

func (restored *mempoolRestoreMaps) store(entry mempoolEntry) {
	entryCopy := entry
	restored.txs[entryCopy.txid] = &entryCopy
	restored.wtxids[entryCopy.wtxid] = entryCopy.txid
	restored.admissionSeqs[entryCopy.admissionSeq] = entryCopy.txid
	restored.usedBytes += entryCopy.size
	if entryCopy.admissionSeq > restored.maxAdmissionSeq {
		restored.maxAdmissionSeq = entryCopy.admissionSeq
	}
}

// validateMempoolEntryParsed parses raw tx bytes inside a mempool entry and validates consistency.
func validateMempoolEntryParsed(entry mempoolEntry) error {
	tx, err := parseMempoolEntryRaw(entry)
	if err != nil {
		return err
	}
	if err := validateMempoolEntryMetadata(entry, tx); err != nil {
		return err
	}
	return validateMempoolEntryInputs(entry, tx)
}

func parseMempoolEntryRaw(entry mempoolEntry) (*consensus.Tx, error) {
	tx, txid, wtxid, consumed, err := consensus.ParseTx(entry.raw)
	if err != nil {
		return nil, fmt.Errorf("invalid mempool snapshot entry raw for txid %x: %w", entry.txid, err)
	}
	if consumed != len(entry.raw) {
		return nil, fmt.Errorf("mempool snapshot entry has trailing bytes for txid %x: consumed=%d raw_len=%d", entry.txid, consumed, len(entry.raw))
	}
	if txid != entry.txid {
		return nil, fmt.Errorf("mempool snapshot entry txid mismatch: entry=%x raw=%x", entry.txid, txid)
	}
	if wtxid != entry.wtxid {
		return nil, fmt.Errorf("mempool snapshot entry wtxid mismatch: entry=%x raw=%x", entry.wtxid, wtxid)
	}
	return tx, nil
}

func validateMempoolEntryMetadata(entry mempoolEntry, tx *consensus.Tx) error {
	weight, _, _, err := consensus.TxWeightAndStats(tx)
	if err != nil {
		return fmt.Errorf("invalid mempool snapshot entry weight for txid %x: %w", entry.txid, err)
	}
	if entry.weight != weight {
		return fmt.Errorf("mempool snapshot entry weight mismatch: entry=%d computed=%d txid=%x", entry.weight, weight, entry.txid)
	}
	if entry.admissionSeq == 0 {
		return fmt.Errorf("invalid mempool snapshot entry admission_seq for txid %x: seq=0", entry.txid)
	}
	if !validMempoolTxSource(entry.source) {
		return fmt.Errorf("invalid mempool snapshot entry source for txid %x: source=%q", entry.txid, entry.source)
	}
	return nil
}

func validateMempoolEntryInputs(entry mempoolEntry, tx *consensus.Tx) error {
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
