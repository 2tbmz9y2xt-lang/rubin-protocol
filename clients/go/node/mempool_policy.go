package node

import (
	"errors"
	"fmt"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

func validMempoolTxSource(source mempoolTxSource) bool {
	switch source {
	case mempoolTxSourceRemote, mempoolTxSourceLocal, mempoolTxSourceReorg:
		return true
	default:
		return false
	}
}

func (m *Mempool) validateRelayMetadataFeeFloor(checked *consensus.CheckedTransaction, snappedFloor uint64) error {
	if checked == nil {
		return txAdmitRejected("nil checked transaction")
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.validateFeeFloorLockedWithFloor(&mempoolEntry{
		fee:    checked.Fee,
		weight: checked.Weight,
		size:   checked.SerializedSize,
	}, snappedFloor)
}

func parseRelayMetadataTx(txBytes []byte) (*consensus.Tx, [32]byte, [32]byte, error) {
	tx, txid, wtxid, consumed, err := consensus.ParseTx(txBytes)
	if err != nil {
		return nil, [32]byte{}, [32]byte{}, txAdmitRejected(err.Error())
	}
	if consumed != len(txBytes) {
		return nil, [32]byte{}, [32]byte{}, txAdmitRejected("trailing bytes after canonical tx")
	}
	return tx, txid, wtxid, nil
}

func relayMetadataInputs(tx *consensus.Tx) []consensus.Outpoint {
	inputs := make([]consensus.Outpoint, 0, len(tx.Inputs))
	for _, in := range tx.Inputs {
		inputs = append(inputs, consensus.Outpoint{Txid: in.PrevTxid, Vout: in.PrevVout})
	}
	return inputs
}

func (m *Mempool) EvictConfirmed(blockBytes []byte) error {
	return m.withParsedBlock(blockBytes, m.EvictConfirmedParsed)
}

func (m *Mempool) EvictConfirmedParsed(block *consensus.ParsedBlock) error {
	return m.withLockedParsedBlock(block, func(block *consensus.ParsedBlock) {
		for _, txid := range block.Txids {
			m.removeTxLocked(txid)
		}
	})
}

func (m *Mempool) applyConnectedBlockParsed(block *consensus.ParsedBlock) error {
	return m.withLockedParsedBlock(block, func(block *consensus.ParsedBlock) {
		for _, txid := range block.Txids {
			m.removeTxLocked(txid)
		}
		for txid := range m.collectConflictsLocked(block) {
			m.removeTxLocked(txid)
		}
		m.decayMinFeeRateAfterConnectedBlockLocked()
	})
}

func (m *Mempool) RemoveConflicting(blockBytes []byte) error {
	return m.withParsedBlock(blockBytes, m.RemoveConflictingParsed)
}

func (m *Mempool) withParsedBlock(blockBytes []byte, fn func(*consensus.ParsedBlock) error) error {
	if m == nil {
		return errors.New("nil mempool")
	}
	block, err := consensus.ParseBlockBytes(blockBytes)
	if err != nil {
		return err
	}
	return fn(block)
}

func (m *Mempool) RemoveConflictingParsed(block *consensus.ParsedBlock) error {
	return m.withLockedParsedBlock(block, func(block *consensus.ParsedBlock) {
		for txid := range m.collectConflictsLocked(block) {
			m.removeTxLocked(txid)
		}
	})
}

func (m *Mempool) withLockedParsedBlock(block *consensus.ParsedBlock, fn func(*consensus.ParsedBlock)) error {
	if m == nil {
		return errors.New("nil mempool")
	}
	if block == nil {
		return errors.New("nil parsed block")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	fn(block)
	return nil
}

// policySnapshot returns the current mempool policy under the mempool read lock.
func (m *Mempool) policySnapshot() MempoolConfig {
	if m == nil {
		return MempoolConfig{}
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.policy
}

// policyNeedsInputSnapshotForTx returns true if applying policy to the
// already-parsed transaction will read input UTXOs. The decision is
// tx-aware so admissions of non-DA transactions under the default
// config (`MinDaFeeRate=DefaultMinDaFeeRate=1`,
// `PolicyDaSurchargePerByte=0`, `PolicyRejectCoreExtPreActivation=false`)
// skip the per-tx map copy entirely.
//
// Trigger conditions:
//
//  1. `PolicyRejectCoreExtPreActivation` is on — the pre-activation classifier
//     reads input state for CORE_EXT and CORE_SIMPLICITY candidates, so the snapshot is required
//     regardless of tx shape.
//  2. The DA path is exercisable AND the tx is DA-bearing
//     (`daBytes > 0`). `applyPolicyAgainstState` repeats the DA-bearing
//     check from the post-validation metadata before invoking
//     `RejectDaAnchorTxPolicy`, so non-DA tx never consume the snapshot or
//     enter the DA helper.
//
// A raw all-zero DA policy snapshot + non-CORE_EXT routing relies on
// `validateFeeFloorLocked` to enforce the rolling relay-fee floor; that
// path does not need a UTXO snapshot. Public NewMempoolWithConfig callers
// get DefaultMinDaFeeRate when MinDaFeeRate is left at zero.
//
// The function takes the parsed `*consensus.Tx` (not the post-validation
// `*CheckedTransaction`) on purpose: the caller must build the snapshot
// BEFORE invoking `CheckTransaction*WithOwnedUtxoSet`, which takes
// ownership of the supplied utxo map and removes spent inputs as it
// validates. The DA-bearing decision is a cheap structural predicate, not
// a full weight/stat walk; malformed tx kinds are still rejected by the
// later consensus validation path.
func policyNeedsInputSnapshotForTx(tx *consensus.Tx, policy MempoolConfig) (bool, error) {
	if policy.PolicyRejectCoreExtPreActivation {
		return true, nil
	}
	if policy.MinDaFeeRate == 0 && policy.PolicyDaSurchargePerByte == 0 {
		return false, nil
	}
	if tx == nil {
		return false, errors.New("nil transaction")
	}
	return tx.TxKind != 0x00 && len(tx.DaPayload) > 0, nil
}

func policyInputSnapshot(tx *consensus.Tx, utxos map[consensus.Outpoint]consensus.UtxoEntry) (map[consensus.Outpoint]consensus.UtxoEntry, error) {
	if tx == nil {
		return nil, errors.New("nil tx")
	}
	if utxos == nil {
		return nil, errors.New("nil utxo set")
	}
	inputs := make([]consensus.Outpoint, 0, len(tx.Inputs))
	for _, in := range tx.Inputs {
		inputs = append(inputs, consensus.Outpoint{Txid: in.PrevTxid, Vout: in.PrevVout})
	}
	out := copySelectedUtxoSet(utxos, inputs)
	for _, op := range inputs {
		if _, ok := out[op]; !ok {
			return nil, &consensus.TxError{Code: consensus.TX_ERR_MISSING_UTXO, Msg: "utxo not found"}
		}
	}
	return out, nil
}

func (m *Mempool) removeTxLocked(txid [32]byte) {
	entry, ok := m.txs[txid]
	if !ok {
		return
	}
	m.deleteEntryLocked(txid, entry)
}

func (m *Mempool) validateNonCapacityAdmissionLocked(entry *mempoolEntry) error {
	if err := validateBasicMempoolEntry(entry); err != nil {
		return err
	}
	if err := m.validateEntryIdentityLocked(entry); err != nil {
		return err
	}
	if err := validateMempoolEntrySource(entry.source); err != nil {
		return err
	}
	if err := m.validateEntryInputsLocked(entry); err != nil {
		return err
	}
	return m.validateAdmissionSeqLocked(entry)
}

func validateBasicMempoolEntry(entry *mempoolEntry) error {
	if entry == nil {
		return txAdmitRejected("nil mempool entry")
	}
	if entry.size <= 0 {
		return txAdmitRejected("invalid mempool entry size")
	}
	if entry.weight == 0 {
		return txAdmitRejected("invalid mempool entry weight")
	}
	return nil
}

func (m *Mempool) validateEntryIdentityLocked(entry *mempoolEntry) error {
	txid := entry.txid
	if txid == ([32]byte{}) {
		return txAdmitRejected("invalid mempool entry txid")
	}
	if _, exists := m.txs[txid]; exists {
		return txAdmitConflict("tx already in mempool")
	}
	wtxid := entry.wtxid
	if wtxid == ([32]byte{}) {
		wtxid = entry.txid
	}
	if existing, exists := m.wtxids[wtxid]; exists {
		return txAdmitConflict(fmt.Sprintf("mempool wtxid conflict with %x", existing))
	}
	return nil
}

func validateMempoolEntrySource(source mempoolTxSource) error {
	if source == "" {
		source = mempoolTxSourceLocal
	}
	if !validMempoolTxSource(source) {
		return txAdmitRejected(fmt.Sprintf("invalid mempool tx source %q", source))
	}
	return nil
}

func (m *Mempool) validateEntryInputsLocked(entry *mempoolEntry) error {
	for _, op := range entry.inputs {
		if existing, ok := m.spenders[op]; ok {
			return txAdmitConflict(fmt.Sprintf("mempool double-spend conflict with %x", existing))
		}
	}
	return nil
}

func (m *Mempool) validateAdmissionSeqLocked(entry *mempoolEntry) error {
	if entry.admissionSeq != 0 {
		for existingTxid, existing := range m.txs {
			if existing != nil && existing.admissionSeq == entry.admissionSeq {
				return txAdmitRejected(fmt.Sprintf("mempool admission sequence conflict with %x", existingTxid))
			}
		}
	}
	if m.lastAdmissionSeq == ^uint64(0) {
		return txAdmitUnavailable("mempool admission sequence exhausted")
	}
	return nil
}

func newMempoolEntry(checked *consensus.CheckedTransaction, inputs []consensus.Outpoint, source mempoolTxSource) *mempoolEntry {
	return &mempoolEntry{
		raw:    append([]byte(nil), checked.Bytes...),
		txid:   checked.TxID,
		wtxid:  checked.WTxID,
		inputs: append([]consensus.Outpoint(nil), inputs...),
		fee:    checked.Fee,
		weight: checked.Weight,
		size:   checked.SerializedSize,
		source: source,
	}
}

func normalizeMempoolEntryDefaults(entry *mempoolEntry) {
	if entry == nil {
		return
	}
	if entry.source == "" {
		entry.source = mempoolTxSourceLocal
	}
	if entry.wtxid == ([32]byte{}) {
		entry.wtxid = entry.txid
	}
}

// addEntryLocked admits `entry` under `m.mu`, using the live
// `m.currentMinFeeRate` value for the fee-floor check. Production
// callers SHOULD use `addEntryLockedWithFloor` (see wave-6 race fix
// in addTxWithSource); this wrapper exists for test callers that
// drive the locked admission path in isolation and accept whatever
// floor is in effect at call time.
func (m *Mempool) addEntryLocked(entry *mempoolEntry) error {
	return m.addEntryLockedWithFloor(entry, m.currentMinFeeRateLocked())
}

// addEntryLockedWithFloor is the wave-6/8 race-safe entry point. The
// caller MUST pass the `snappedFloor` value that was captured ONCE
// before the cheap precheck fired (see addTxWithSource for rationale).
// The snapped floor is plumbed down to validateFeeFloorLockedWithFloor
// which enforces max(snappedFloor, live currentMinFeeRate) on the
// admission decision: the precheck owns the snap, the locked path
// owns the live re-read, and the strict-of-the-two wins. This blocks
// the raise race (Codex+Copilot wave-7) where
// raiseMinFeeRateAfterEvictionLocked could fire between snap and lock
// and a stale-lower snap would otherwise admit a transaction below
// the current rolling floor.
func (m *Mempool) addEntryLockedWithFloor(entry *mempoolEntry, snappedFloor uint64) error {
	normalizeMempoolEntryDefaults(entry)
	if err := m.validateNonCapacityAdmissionLocked(entry); err != nil {
		return err
	}
	evictedEntries, err := m.validateCapacityAdmissionLocked(entry, snappedFloor)
	if err != nil {
		return err
	}
	m.ensureMinFeeRateLocked()
	m.ensureIndexesLocked()
	for _, evicted := range evictedEntries {
		m.deleteEntryLocked(evicted.txid, evicted)
		// Bump the resident-eviction counter exactly once per
		// already-admitted entry that capacity pressure removes here.
		// Candidate-worst rejection returned txAdmitUnavailable above
		// without populating evictedEntries, so that path skips this
		// loop entirely. Fee-floor rejection returned earlier from
		// validateFeeFloorLocked and likewise never reaches here.
		m.evictedResidentTotal.Add(1)
	}
	m.assignAdmissionSeqLocked(entry)
	m.insertEntryIndexesLocked(entry)
	m.raiseMinFeeRateAfterEvictionLocked(evictedEntries)
	return nil
}

func (m *Mempool) ensureIndexesLocked() {
	if m.txs == nil {
		m.txs = make(map[[32]byte]*mempoolEntry)
	}
	if m.wtxids == nil {
		m.wtxids = make(map[[32]byte][32]byte)
	}
	if m.spenders == nil {
		m.spenders = make(map[consensus.Outpoint][32]byte)
	}
}

func (m *Mempool) assignAdmissionSeqLocked(entry *mempoolEntry) {
	if entry.admissionSeq == 0 {
		m.lastAdmissionSeq++
		entry.admissionSeq = m.lastAdmissionSeq
	} else if entry.admissionSeq > m.lastAdmissionSeq {
		m.lastAdmissionSeq = entry.admissionSeq
	}
}

func (m *Mempool) insertEntryIndexesLocked(entry *mempoolEntry) {
	m.txs[entry.txid] = entry
	m.wtxids[entry.wtxid] = entry.txid
	m.usedBytes += entry.size
	for _, op := range entry.inputs {
		m.spenders[op] = entry.txid
	}
}

func (m *Mempool) collectConflictsLocked(block *consensus.ParsedBlock) map[[32]byte]struct{} {
	conflicts := make(map[[32]byte]struct{})
	for i, tx := range block.Txs {
		if i == 0 || tx == nil {
			continue
		}
		for _, in := range tx.Inputs {
			if txid, ok := m.spenders[outpointFromInput(in)]; ok {
				conflicts[txid] = struct{}{}
			}
		}
	}
	return conflicts
}

func outpointFromInput(in consensus.TxInput) consensus.Outpoint {
	return consensus.Outpoint{Txid: in.PrevTxid, Vout: in.PrevVout}
}

func (m *Mempool) deleteEntryLocked(txid [32]byte, entry *mempoolEntry) {
	delete(m.txs, txid)
	if entry == nil {
		return
	}
	if entry.size > 0 {
		if m.usedBytes >= entry.size {
			m.usedBytes -= entry.size
		} else {
			m.usedBytes = 0
		}
	}
	for _, op := range entry.inputs {
		delete(m.spenders, op)
	}
	if existing, ok := m.wtxids[entry.wtxid]; ok && existing == txid {
		delete(m.wtxids, entry.wtxid)
	}
}
