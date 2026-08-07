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
	return m.withLockedParsedBlock(block, func(block *consensus.ParsedBlock) error {
		return m.commitStandardDeltaLocked(standardMempoolDelta{
			removals: m.blockTerminalEntriesLocked(nil, make(map[[32]byte]struct{}), block, false),
		})
	})
}

func (m *Mempool) applyConnectedBlockParsed(block *consensus.ParsedBlock) error {
	return m.applyConnectedBlocksParsed([]*consensus.ParsedBlock{block})
}

// applyConnectedBlocksParsed removes every standard entry the given canonical
// blocks include or conflict with, in ONE standard-domain commit, and releases
// each removed entry's exact token with it. A preferred-branch reorg pre-cleans
// the whole winning branch through this single call instead of running a
// per-block cleanup inside the transition.
func (m *Mempool) applyConnectedBlocksParsed(blocks []*consensus.ParsedBlock) error {
	if m == nil {
		return errors.New("nil mempool")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var removals []*mempoolEntry
	seen := make(map[[32]byte]struct{})
	for _, block := range blocks {
		if block == nil {
			return errors.New("nil parsed block")
		}
		removals = m.blockTerminalEntriesLocked(removals, seen, block, true)
	}
	if err := m.commitStandardDeltaLocked(standardMempoolDelta{removals: removals}); err != nil {
		return err
	}
	for range blocks {
		m.decayMinFeeRateAfterConnectedBlockLocked()
	}
	return nil
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
	return m.withLockedParsedBlock(block, func(block *consensus.ParsedBlock) error {
		return m.commitStandardDeltaLocked(standardMempoolDelta{
			removals: m.blockConflictEntriesLocked(nil, make(map[[32]byte]struct{}), block),
		})
	})
}

func (m *Mempool) withLockedParsedBlock(block *consensus.ParsedBlock, fn func(*consensus.ParsedBlock) error) error {
	if m == nil {
		return errors.New("nil mempool")
	}
	if block == nil {
		return errors.New("nil parsed block")
	}
	// A PUBLIC terminal removal takes the same ChainState admission read guard
	// standard admission takes, then Mempool.mu, then owner.mu. Without it a
	// terminal removal could delete a record and its claim inside a canonical
	// transition's snapshot/restore window, and an abort would then resurrect
	// an entry the caller was told had been removed.
	//
	// The unexported connected-block cleanup (applyConnectedBlocksParsed)
	// deliberately does NOT route through here: it runs under the transition's
	// own admissionMu.Lock, and sync.RWMutex is not reentrant.
	//
	// Like standard admission, that RLock BLOCKS INDEFINITELY by design in the
	// fail-closed terminal state described on canonicalTransition.end.
	if m.chainState != nil {
		m.chainState.admissionMu.RLock()
		defer m.chainState.admissionMu.RUnlock()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return fn(block)
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
// already-parsed transaction will read input UTXOs.
func policyNeedsInputSnapshotForTx(tx *consensus.Tx, policy MempoolConfig) (bool, error) {
	if tx == nil {
		return false, errors.New("nil transaction")
	}
	if len(tx.Inputs) > 0 || policy.PolicyRejectSimplicityPreActivation {
		return true, nil
	}
	if policy.MinDaFeeRate == 0 && policy.PolicyDaSurchargePerByte == 0 {
		return false, nil
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

// removeTxLocked terminates one resident entry by txid through the same typed
// standard delta the admission and capacity paths use, so its record and its
// claim cannot become observably separated.
//
// It has no production caller: every live terminal path already builds a bounded
// multi-entry delta directly. It survives as the single-entry form the package's
// own tests drive, and routes through the delta so they exercise the real rule.
func (m *Mempool) removeTxLocked(txid [32]byte) error {
	entry, ok := m.txs[txid]
	if !ok {
		return nil
	}
	return m.commitStandardDeltaLocked(standardMempoolDelta{removals: []*mempoolEntry{entry}})
}

// validateNonCapacityAdmissionLocked runs the non-capacity admission chain with
// no relay observer. It is the unprobed form the package's own locked-path tests
// drive; production admission uses validateNonCapacityAdmissionLockedProbed.
func (m *Mempool) validateNonCapacityAdmissionLocked(entry *mempoolEntry) error {
	return m.validateNonCapacityAdmissionLockedProbed(entry, nil)
}

// validateNonCapacityAdmissionLockedProbed is the one implementation. The probe
// reaches the owner seam, where a caller-supplied expected admission context is
// validated, and the post-decision release seam, which records a cleanup fault
// on it; every check, its order and its error are unchanged.
func (m *Mempool) validateNonCapacityAdmissionLockedProbed(entry *mempoolEntry, probe *relayAdmissionProbe) error {
	if err := validateBasicMempoolEntry(entry); err != nil {
		return err
	}
	if err := m.validateEntryIdentityLocked(entry); err != nil {
		return err
	}
	if err := validateMempoolEntrySource(entry.source); err != nil {
		return err
	}
	if err := m.reserveEntryInputsLocked(entry, probe); err != nil {
		return err
	}
	if err := m.validateAdmissionSeqLocked(entry); err != nil {
		return m.releaseCandidateLocked(entry, err, probe)
	}
	return nil
}

// validateBasicMempoolEntry checks the record shape a completed consensus
// validation always produces. Every failure here is an impossible invariant of
// the live admission path, never a property of the candidate bytes.
func validateBasicMempoolEntry(entry *mempoolEntry) error {
	if entry == nil {
		return selectRelayDisposition(txAdmitRejected("nil mempool entry"), RelayAdmissionInternal)
	}
	if entry.size <= 0 {
		return selectRelayDisposition(txAdmitRejected("invalid mempool entry size"), RelayAdmissionInternal)
	}
	if entry.weight == 0 {
		return selectRelayDisposition(txAdmitRejected("invalid mempool entry weight"), RelayAdmissionInternal)
	}
	return nil
}

// validateEntryIdentityLocked is the resident-duplicate slot. Both duplicate
// branches keep the existing TxAdmitConflict kind for compatibility, which is
// exactly why a relay consumer must read the disposition instead: the same
// public kind also carries the pending-outpoint double-spend conflict.
func (m *Mempool) validateEntryIdentityLocked(entry *mempoolEntry) error {
	txid := entry.txid
	if txid == ([32]byte{}) {
		return selectRelayDisposition(txAdmitRejected("invalid mempool entry txid"), RelayAdmissionInternal)
	}
	if _, exists := m.txs[txid]; exists {
		return selectRelayDisposition(txAdmitConflict("tx already in mempool"), RelayAdmissionDuplicate)
	}
	wtxid := entry.wtxid
	if wtxid == ([32]byte{}) {
		wtxid = entry.txid
	}
	if existing, exists := m.wtxids[wtxid]; exists {
		return selectRelayDisposition(txAdmitConflict(fmt.Sprintf("mempool wtxid conflict with %x", existing)), RelayAdmissionDuplicate)
	}
	return nil
}

func validateMempoolEntrySource(source mempoolTxSource) error {
	if source == "" {
		source = mempoolTxSourceLocal
	}
	if !validMempoolTxSource(source) {
		// The entry points pin the source constant; a record can only carry an
		// invalid one through an impossible invariant.
		return selectRelayDisposition(txAdmitRejected(fmt.Sprintf("invalid mempool tx source %q", source)), RelayAdmissionInternal)
	}
	return nil
}

// reserveEntryInputsLocked occupies the conflict slot that validateEntryInputsLocked
// used to hold. It reads ONE exact owner admission context, requires that
// context's stable tip to equal the ChainState tip the caller's admission read
// guard is pinning, and claims every input of the candidate against that exact
// tip/generation pair, recording the issued token on the entry. Passing the
// whole observed context — not just a tip — is what makes a stale reader lose:
// Reserve refuses a generation the owner has already left behind.
//
// An owner conflict maps to the existing TxAdmitConflict double-spend family; an
// active transition, an expected-tip or expected-generation mismatch, an
// exhausted sequence space and any owner-internal failure all map to
// TxAdmitUnavailable, so no new public TxAdmit kind appears here. A candidate
// with no inputs claims nothing and takes no token, exactly as the replaced loop
// was a no-op over an empty input slice.
//
// This slot is ALSO the seam at which a relay caller's supplied expected
// admission context is validated: the supplied context replaces the observed one
// as Reserve's binding, so the owner's own availability check refuses a stale
// tip or a superseded generation before it scans for a conflict and before it
// consumes a sequence. A nil probe or a nil expected context leaves the baseline
// binding, and therefore the baseline behavior, untouched.
func (m *Mempool) reserveEntryInputsLocked(entry *mempoolEntry, probe *relayAdmissionProbe) error {
	if len(entry.inputs) == 0 {
		// Pure read of the already-bound owner: the lazy owner constructor is
		// deliberately NOT called here, because classifying must never mutate.
		return probe.checkExpectedContext(m.pendingOutpoints, pendingOutpointTipOf(m.chainState))
	}
	owner := m.pendingOutpointOwnerLocked()
	admission, ok := owner.AdmissionContext()
	if !ok {
		return selectRelayDisposition(txAdmitUnavailable("pending-outpoint owner admission context unavailable"), RelayAdmissionUnavailable)
	}
	if admission.StableTip != pendingOutpointTipOf(m.chainState) {
		return selectRelayDisposition(txAdmitUnavailable("pending-outpoint owner tip does not match the guarded chainstate tip"), RelayAdmissionUnavailable)
	}
	requested := admission
	if probe != nil && probe.hasExpected {
		requested = probe.expected
	}
	token, err := owner.Reserve(requested, PendingOutpointStandardMempool, entry.txid, entry.inputs)
	if err != nil {
		return selectRelayDisposition(txAdmitFromPendingOutpointError(err), relayDispositionForOwnerError(err))
	}
	entry.token = token
	return nil
}

// releaseCandidateLocked releases a reservation the conflict slot issued for a
// candidate that a LATER admission check rejected, and returns cause unchanged
// so the public error order is preserved. The issued sequence stays consumed;
// high-waters never decrease.
//
// Release cannot fail for a claim this call just installed, so every failure it
// can report — a nil owner, a token this owner never issued, a by-outpoint row
// that disagrees with the token — is owner-accounting corruption. Reporting it
// in place of cause would rewrite the contractual admission error, so cause is
// still returned byte-identically; the fault is recorded on the relay probe
// instead, which publishes it as the fail-closed INTERNAL disposition the
// already-tagged cause can no longer carry (selectRelayDisposition is
// first-selection-wins and the deciding branch tagged cause before this ran).
//
// probe is nil on the legacy AddTx / AddRemoteTx / AddReorgTx path, where
// noteCleanupFailure is a no-op and the behavior is exactly as before.
func (m *Mempool) releaseCandidateLocked(entry *mempoolEntry, cause error, probe *relayAdmissionProbe) error {
	var zero PendingOutpointToken
	if entry == nil || entry.token == zero {
		return cause
	}
	probe.noteCleanupFailure(m.pendingOutpoints.Release(entry.token))
	// The token is zeroed unconditionally, exactly as before: the entry is
	// discarded on every path that reaches here, and a failed release leaves no
	// claim this record may keep pointing at.
	entry.token = zero
	return cause
}

func (m *Mempool) validateAdmissionSeqLocked(entry *mempoolEntry) error {
	if entry.admissionSeq != 0 {
		for existingTxid, existing := range m.txs {
			if existing != nil && existing.admissionSeq == entry.admissionSeq {
				return selectRelayDisposition(txAdmitRejected(fmt.Sprintf("mempool admission sequence conflict with %x", existingTxid)), RelayAdmissionAdmissionSequence)
			}
		}
	}
	if m.lastAdmissionSeq == ^uint64(0) {
		return selectRelayDisposition(txAdmitUnavailable("mempool admission sequence exhausted"), RelayAdmissionAdmissionSequence)
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
	return m.addEntryLockedProbed(entry, snappedFloor, nil)
}

// addEntryLockedProbed is the one implementation of the locked admission path.
// The probe reaches the owner seam inside the non-capacity chain and the
// post-decision release seam; it changes no check, no order, no error and no
// mutation.
func (m *Mempool) addEntryLockedProbed(entry *mempoolEntry, snappedFloor uint64, probe *relayAdmissionProbe) error {
	normalizeMempoolEntryDefaults(entry)
	if err := m.validateNonCapacityAdmissionLockedProbed(entry, probe); err != nil {
		return err
	}
	evictedEntries, err := m.validateCapacityAdmissionLocked(entry, snappedFloor)
	if err != nil {
		return m.releaseCandidateLocked(entry, err, probe)
	}
	m.ensureMinFeeRateLocked()
	// One typed delta: every exact victim token is released and the candidate
	// record plus its token finalization are installed together. A failure here
	// publishes no entry and exactly releases the candidate reservation.
	//
	// The commit validated its whole delta before writing anything, and the
	// live admission path reaches it holding the ChainState admission read
	// guard plus m.mu, so no transition, generation move or concurrent removal
	// is possible: every remaining failure is an accounting or claim
	// inconsistency, which is an impossible invariant.
	if err := m.commitStandardDeltaLocked(standardMempoolDelta{candidate: entry, removals: evictedEntries}); err != nil {
		return m.releaseCandidateLocked(entry, selectRelayDisposition(err, RelayAdmissionInternal), probe)
	}
	for range evictedEntries {
		// Bump the resident-eviction counter exactly once per
		// already-admitted entry that capacity pressure removed in the
		// commit above. Candidate-worst rejection returned
		// txAdmitUnavailable earlier without populating evictedEntries,
		// and fee-floor rejection returned from validateFeeFloorLocked
		// before that, so neither path reaches this loop.
		m.evictedResidentTotal.Add(1)
	}
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
}

// pendingOutpointOwnerLocked returns the single owner, creating it on first use
// for a bare Mempool value exactly as ensureIndexesLocked creates the txid and
// wtxid indexes — and as it used to create the spenders index this owner
// replaces. NewMempoolWithConfig always installs the owner eagerly from the
// bound ChainState stable tip, so no production path takes the lazy branch and
// no second owner can exist for one mempool.
func (m *Mempool) pendingOutpointOwnerLocked() *PendingOutpointOwner {
	if m.pendingOutpoints == nil {
		m.pendingOutpoints = newPendingOutpointOwner(pendingOutpointTipOf(m.chainState))
	}
	return m.pendingOutpoints
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
}

// blockTerminalEntriesLocked appends the resident entries a canonical block
// terminates: first the entries it includes by txid, then — when conflicts is
// true — the entries whose claimed outpoints the block's non-coinbase inputs
// spend. Order follows block order and then input order, and seen deduplicates
// across blocks, so the resulting delta is deterministic and never lists the
// same record twice.
func (m *Mempool) blockTerminalEntriesLocked(out []*mempoolEntry, seen map[[32]byte]struct{}, block *consensus.ParsedBlock, conflicts bool) []*mempoolEntry {
	for _, txid := range block.Txids {
		out = m.appendResidentEntryLocked(out, seen, txid)
	}
	if !conflicts {
		return out
	}
	return m.blockConflictEntriesLocked(out, seen, block)
}

func (m *Mempool) blockConflictEntriesLocked(out []*mempoolEntry, seen map[[32]byte]struct{}, block *consensus.ParsedBlock) []*mempoolEntry {
	for i, tx := range block.Txs {
		if i == 0 || tx == nil {
			continue
		}
		for _, in := range tx.Inputs {
			if txid, ok := m.pendingOutpoints.txidForOutpoint(outpointFromInput(in)); ok {
				out = m.appendResidentEntryLocked(out, seen, txid)
			}
		}
	}
	return out
}

func (m *Mempool) appendResidentEntryLocked(out []*mempoolEntry, seen map[[32]byte]struct{}, txid [32]byte) []*mempoolEntry {
	if _, done := seen[txid]; done {
		return out
	}
	entry, ok := m.txs[txid]
	if !ok {
		return out
	}
	seen[txid] = struct{}{}
	return append(out, entry)
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
	if existing, ok := m.wtxids[entry.wtxid]; ok && existing == txid {
		delete(m.wtxids, entry.wtxid)
	}
}
