package node

import (
	"bytes"
	"fmt"
	"sort"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

type mempoolSnapshot struct {
	entries []mempoolEntry
	// pending is the same-owner pending-outpoint image captured with the
	// entries: every live claim, the stable tip, and both high-waters.
	pending           pendingOutpointSnapshot
	lastAdmissionSeq  uint64
	currentMinFeeRate uint64
}

// snapshotMempool captures the exact rollback image: cloned entries with their
// exact tokens plus the owner's claims, stable tip and high-waters. Lock order
// is Mempool.mu then owner.mu.
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
	return mempoolSnapshot{
		entries:           entries,
		pending:           m.pendingOutpoints.snapshot(),
		lastAdmissionSeq:  m.lastAdmissionSeq,
		currentMinFeeRate: currentMinFeeRate,
	}, nil
}

// restoreMempoolSnapshot rebuilds the records and the owner claims of the SAME
// owner from snapshot. It builds every temporary map first, cross-checks each
// record against its exact finalized standard claim in both directions, and
// only then publishes all maps or none. Token and generation high-waters are
// retained at their advanced values, so an aborted transition can never hand
// out a sequence twice.
func restoreMempoolSnapshot(m *Mempool, snapshot mempoolSnapshot) error {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.maxTxs <= 0 || m.maxBytes <= 0 {
		return fmt.Errorf("invalid mempool snapshot restore limits: max_txs=%d max_bytes=%d", m.maxTxs, m.maxBytes)
	}
	txs, wtxids, maxAdmissionSeq, usedBytes, err := buildMempoolRestoreMaps(snapshot.entries, m.maxTxs, m.maxBytes)
	if err != nil {
		return err
	}
	if snapshot.lastAdmissionSeq < maxAdmissionSeq {
		return fmt.Errorf("mempool snapshot admission high-watermark below restored max: last=%d max=%d", snapshot.lastAdmissionSeq, maxAdmissionSeq)
	}
	owner := m.pendingOutpointOwnerLocked()
	owner.mu.Lock()
	defer owner.mu.Unlock()
	candidate, err := owner.buildRestoreLocked(snapshot.pending)
	if err != nil {
		return err
	}
	if err := validateRestoredClaimBinding(txs, candidate); err != nil {
		return err
	}
	// Everything fallible is done. Both locks are held, so the owner image and
	// the records below become visible to any reader as one step.
	owner.publishRestoreLocked(snapshot.pending, candidate)
	m.txs = txs
	m.wtxids = wtxids
	m.usedBytes = usedBytes
	m.lastAdmissionSeq = snapshot.lastAdmissionSeq
	m.currentMinFeeRate = snapshot.currentMinFeeRate
	m.ensureMinFeeRateLocked()
	return nil
}

// validateRestoredClaimBinding proves the bijection between the records about to
// be installed and the CANDIDATE finalized standard claims that would be
// published alongside them: every record with inputs holds exactly one finalized
// standard claim carrying its exact token, txid, domain and ordered inputs, and
// no finalized standard claim is left without a record. Both sides are still
// unpublished, so a rejection leaves live owner and records untouched.
func validateRestoredClaimBinding(txs map[[32]byte]*mempoolEntry, candidate pendingOutpointIndex) error {
	finalized := 0
	for _, claim := range candidate.byToken {
		if claim.domain == PendingOutpointStandardMempool && claim.finalized {
			finalized++
		}
	}
	claimed := 0
	for _, entry := range txs {
		if err := candidate.validateEntryClaim(entry.txid, entry.inputs, entry.token, true); err != nil {
			return err
		}
		if len(entry.inputs) > 0 {
			claimed++
		}
	}
	if claimed != finalized {
		return pendingOutpointInternal(fmt.Sprintf("mempool snapshot claim count mismatch: records=%d finalized_claims=%d", claimed, finalized))
	}
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
		token:        entry.token,
		fee:          entry.fee,
		weight:       entry.weight,
		size:         entry.size,
		admissionSeq: entry.admissionSeq,
		source:       entry.source,
	}
}

// buildMempoolRestoreMaps builds txid/wtxid/admission maps from snapshot
// entries. Outpoint uniqueness is no longer checked here: the owner's
// restoreLocked rejects a duplicate outpoint across claims, and
// validateRestoredClaimBinding then binds every record to its exact claim.
func buildMempoolRestoreMaps(snapshotEntries []mempoolEntry, maxTxs int, maxBytes int) (
	txs map[[32]byte]*mempoolEntry,
	wtxids map[[32]byte][32]byte,
	maxAdmissionSeq uint64,
	usedBytes int,
	err error,
) {
	txs = make(map[[32]byte]*mempoolEntry, len(snapshotEntries))
	wtxids = make(map[[32]byte][32]byte, len(snapshotEntries))
	admissionSeqs := make(map[uint64][32]byte, len(snapshotEntries))
	for _, item := range snapshotEntries {
		entry := cloneMempoolEntry(&item)
		if err := validateMempoolRestoreEntry(entry, txs, wtxids, admissionSeqs, len(txs), usedBytes, maxTxs, maxBytes); err != nil {
			return nil, nil, 0, 0, err
		}
		entryCopy := entry
		txs[entryCopy.txid] = &entryCopy
		wtxids[entryCopy.wtxid] = entryCopy.txid
		admissionSeqs[entryCopy.admissionSeq] = entryCopy.txid
		usedBytes += entryCopy.size
		if entryCopy.admissionSeq > maxAdmissionSeq {
			maxAdmissionSeq = entryCopy.admissionSeq
		}
	}
	return
}

func validateMempoolRestoreEntry(
	entry mempoolEntry,
	txs map[[32]byte]*mempoolEntry,
	wtxids map[[32]byte][32]byte,
	admissionSeqs map[uint64][32]byte,
	txCount int,
	usedBytes int,
	maxTxs int,
	maxBytes int,
) error {
	if _, exists := txs[entry.txid]; exists {
		return fmt.Errorf("duplicate mempool snapshot txid %x", entry.txid)
	}
	if existing, exists := wtxids[entry.wtxid]; exists {
		return fmt.Errorf("duplicate mempool snapshot wtxid %x existing=%x new=%x", entry.wtxid, existing, entry.txid)
	}
	if err := validateMempoolSnapshotEntry(entry); err != nil {
		return err
	}
	if existing, exists := admissionSeqs[entry.admissionSeq]; exists {
		return fmt.Errorf("duplicate mempool snapshot admission_seq %d existing=%x new=%x", entry.admissionSeq, existing, entry.txid)
	}
	if txCount >= maxTxs {
		return fmt.Errorf("mempool snapshot exceeds transaction cap: count=%d max=%d", txCount+1, maxTxs)
	}
	if entry.size > maxBytes || usedBytes > maxBytes-entry.size {
		return fmt.Errorf("mempool snapshot exceeds byte cap: used=%d entry=%d max=%d", usedBytes, entry.size, maxBytes)
	}
	return nil
}

// validateMempoolEntryParsed parses raw tx bytes inside a mempool entry and validates consistency.
func validateMempoolEntryParsed(entry mempoolEntry) error {
	tx, err := parseMempoolEntryRaw(entry)
	if err != nil {
		return err
	}
	return validateMempoolEntryParsedTx(entry, tx)
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

func validateMempoolEntryParsedTx(entry mempoolEntry, tx *consensus.Tx) error {
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
