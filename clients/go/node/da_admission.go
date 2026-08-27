//nolint:forbidigo // Contract-required lifecycle misuse fails fast.
package node

import (
	"crypto/sha3"
	"fmt"
	"sync/atomic"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

// DAAdmissionSnapshot is a defensive copy of a fully validated DA transaction.
type DAAdmissionSnapshot struct {
	TxID          [32]byte
	WTxID         [32]byte
	TxBytes       []byte
	Fee           consensus.Uint128
	RetainedBytes uint64
	Inputs        []consensus.Outpoint
}

// DAAdmissionVictim identifies one finalized DA claim to remove at commit.
type DAAdmissionVictim struct {
	TxID   [32]byte
	Inputs []consensus.Outpoint
	Token  PendingOutpointToken
}

const (
	daAdmissionOpen uint32 = iota
	daAdmissionAttempting
	daAdmissionLive
	daAdmissionFinishing
	daAdmissionResolved
	daAdmissionClosed
	daAdmissionMaxVictims = 65_536 * (1 + consensus.MAX_DA_CHUNK_COUNT)
)

type daAdmissionGuard struct {
	chainState *ChainState
	owner      *PendingOutpointOwner
	state      atomic.Uint32
}

// DAAdmission is a one-shot, chainstate-guarded DA candidate admission.
//
// tx is the admission's OWN canonical consumption of snapshot.TxBytes — the
// exact *consensus.Tx the single ParseTx of this candidate produced, carried
// here so no later stage re-parses the same bytes (RUB-678 R9: one raw
// acquisition, one full canonical consumption per admission).
type DAAdmission struct {
	self     *DAAdmission
	guard    *daAdmissionGuard
	tx       *consensus.Tx
	snapshot DAAdmissionSnapshot
	context  PendingOutpointAdmissionContext
}

// DARemoval is a one-shot, chainstate-guarded finalized-DA removal.
type DARemoval struct {
	self  *DARemoval
	guard *daAdmissionGuard
}

// DACommit owns a prepared owner lock; copied, foreign, and repeated terminal calls fail fast without a second unlock.
type DACommit struct {
	self      *DACommit
	guard     *daAdmissionGuard
	candidate PendingOutpointToken
	victims   []DAAdmissionVictim
}

// BeginDAAdmission validates raw DA bytes and retains the admission guard until Close.
//
// Order: the message bound and the full canonical parse run BEFORE any guard —
// a parse failure terminates with its own result and no ChainState or owner
// observation occurs — and then the shared acquireDAAdmissionHold lifecycle
// obtains the stable guard and the complete owner context BEFORE candidate
// validation, so guard/context unavailability or instability selects
// UNAVAILABLE ahead of every later candidate check
// (RUBIN_COMPACT_BLOCKS.md Section 5.1 duplicate-handling order).
func (m *Mempool) BeginDAAdmission(raw []byte) (*DAAdmission, error) {
	owned, tx, txid, wtxid, inputs, err := m.parseDAAdmissionCandidate(raw)
	if err != nil {
		return nil, err
	}
	hold, err := m.acquireDAAdmissionHold()
	if err != nil {
		return nil, err
	}
	defer hold.releaseIfHeld()
	return hold.validateDACandidate(owned, tx, txid, wtxid, inputs)
}

// parseDAAdmissionCandidate is the guardless pre-stage shared by
// BeginDAAdmission and AdmitDA: receiver availability, the message bound and
// the full canonical parse with structural identity derivation.
func (m *Mempool) parseDAAdmissionCandidate(raw []byte) (owned []byte, tx *consensus.Tx, txid, wtxid [32]byte, inputs []consensus.Outpoint, err error) {
	if m == nil {
		err = selectRelayDisposition(txAdmitUnavailable("nil mempool"), RelayAdmissionUnavailable)
		return
	}
	if m.chainState == nil {
		err = selectRelayDisposition(txAdmitUnavailable("nil chainstate"), RelayAdmissionUnavailable)
		return
	}
	if m.pendingOutpoints == nil {
		err = selectRelayDisposition(txAdmitUnavailable("nil pending-outpoint owner"), RelayAdmissionUnavailable)
		return
	}
	return parseDAAdmission(raw)
}

func parseDAAdmission(raw []byte) (owned []byte, tx *consensus.Tx, txid, wtxid [32]byte, inputs []consensus.Outpoint, err error) {
	if len(raw) == 0 {
		err = txAdmitRejected("empty DA transaction")
		return
	}
	if len(raw) > consensus.MAX_RELAY_MSG_BYTES {
		err = txAdmitRejected(fmt.Sprintf("tx payload exceeds MAX_RELAY_MSG_BYTES: %d > %d", len(raw), consensus.MAX_RELAY_MSG_BYTES))
		return
	}
	owned = append([]byte(nil), raw...)
	tx, txid, wtxid, err = parseRelayMetadataTx(owned)
	if err != nil {
		return
	}
	if !isDAAdmissionTx(tx) {
		err = txAdmitRejected("transaction is not a DA commit or DA chunk")
		return
	}
	inputs = relayMetadataInputs(tx)
	if len(inputs) == 0 || len(inputs) > consensus.MAX_TX_INPUTS {
		err = txAdmitRejected("DA transaction must have 1..MAX_TX_INPUTS inputs")
		return
	}
	if !matchingDAChunkPayloadHash(tx) {
		err = txAdmitRejected("DA chunk payload hash mismatch")
	}
	return
}

func matchingDAChunkPayloadHash(tx *consensus.Tx) bool {
	return tx.TxKind != 0x02 || sha3.Sum256(tx.DaPayload) == tx.DaChunkCore.ChunkHash
}

// daAdmissionHold is the ONE factored stable-guard/context acquisition
// BeginDAAdmission and AdmitDA share, and this file is its sole
// ChainState.admissionMu.R acquisition site on the admission path. It takes the
// guard exactly once, reads the complete owner admission context under it, and
// proves the context's stable tip equals the guarded chainstate tip — so every
// decision made while the hold lives runs against one stable
// {tip, generation} identity. Absence, mismatch or instability of that context
// (an active or latched transition, an exhausted generation, a tip the owner
// has not committed) selects the existing UNAVAILABLE disposition before any DA
// observation or candidate validation.
//
// The hold is single-goroutine and linear: it ends in exactly one of the
// deferred releaseIfHeld (the guard is unlocked here) or validateDACandidate
// success (the guard transfers into the returned DAAdmission, whose Close
// unlocks it). sync.RWMutex is not reentrant, so nothing running under a hold
// may acquire the guard again.
type daAdmissionHold struct {
	mempool *Mempool
	owner   *PendingOutpointOwner
	context PendingOutpointAdmissionContext
	held    bool
}

// acquireDAAdmissionHold requires a parseDAAdmissionCandidate-first caller:
// that pre-stage proved the receiver, chainstate and owner non-nil, and
// nothing else may reach this dereference of them.
func (m *Mempool) acquireDAAdmissionHold() (*daAdmissionHold, error) {
	m.chainState.admissionMu.RLock()
	admission, ok := m.pendingOutpoints.AdmissionContext()
	if !ok {
		m.chainState.admissionMu.RUnlock()
		return nil, selectRelayDisposition(txAdmitUnavailable("pending-outpoint owner admission context unavailable"), RelayAdmissionUnavailable)
	}
	if admission.StableTip != pendingOutpointTipOf(m.chainState) {
		m.chainState.admissionMu.RUnlock()
		return nil, selectRelayDisposition(txAdmitUnavailable("pending-outpoint owner tip does not match the guarded chainstate tip"), RelayAdmissionUnavailable)
	}
	return &daAdmissionHold{mempool: m, owner: m.pendingOutpoints, context: admission, held: true}, nil
}

// releaseIfHeld releases the hold unless the guard already transferred into a
// DAAdmission. Deferred right after acquisition, it makes the guard's release
// exactly-once on EVERY unwind — error and panic alike — without ever
// double-releasing after a successful transfer.
func (h *daAdmissionHold) releaseIfHeld() {
	if h == nil || !h.held {
		return
	}
	h.held = false
	h.mempool.chainState.admissionMu.RUnlock()
}

// validateDACandidate runs the existing full candidate validation under the
// held guard and, on success, transfers the guard into the returned DAAdmission
// (Close then releases it). On failure the hold stays held and the caller
// releases it, so an error changes no lock state.
func (h *daAdmissionHold) validateDACandidate(owned []byte, tx *consensus.Tx, txid, wtxid [32]byte, inputs []consensus.Outpoint) (*DAAdmission, error) {
	if h == nil || !h.held {
		panic("DA admission hold is not held")
	}
	m := h.mempool
	snapshot := m.chainState.admissionSnapshotForInputs(inputs)
	policy := m.policySnapshot()
	checked, _, err := m.checkParsedTransactionWithSnapshot(owned, tx, txid, wtxid, snapshot, policy)
	if err != nil {
		return nil, err
	}
	// checked.Tx IS the tx argument and checked.Bytes IS a copy of owned, so the
	// carried transaction, the retained bytes and the identity below are all the
	// product of ONE consensus.ParseTx(owned) and cannot contradict each other:
	// that is what replaces the renderer's former re-parse of the snapshot.
	a := &DAAdmission{
		guard: &daAdmissionGuard{chainState: m.chainState, owner: h.owner},
		tx:    checked.Tx,
		snapshot: DAAdmissionSnapshot{
			TxID:          checked.TxID,
			WTxID:         checked.WTxID,
			TxBytes:       checked.Bytes,
			Fee:           checked.Fee,
			RetainedBytes: uint64(len(checked.Bytes)),
			Inputs:        inputs,
		},
		context: h.context,
	}
	a.self = a
	h.held = false
	return a, nil
}

func isDAAdmissionTx(tx *consensus.Tx) bool {
	return tx != nil && (tx.TxKind == 0x01 && tx.DaCommitCore != nil && tx.DaChunkCore == nil || tx.TxKind == 0x02 && tx.DaChunkCore != nil && tx.DaCommitCore == nil)
}

// Snapshot returns independent copies while the admission remains open.
func (a *DAAdmission) Snapshot() DAAdmissionSnapshot {
	a.mustLiveValue()
	g := a.guard
	if g.state.Load() != daAdmissionOpen {
		panic("DA admission snapshot is not available")
	}
	return DAAdmissionSnapshot{
		TxID:          a.snapshot.TxID,
		WTxID:         a.snapshot.WTxID,
		TxBytes:       append([]byte(nil), a.snapshot.TxBytes...),
		Fee:           a.snapshot.Fee,
		RetainedBytes: a.snapshot.RetainedBytes,
		Inputs:        append([]consensus.Outpoint(nil), a.snapshot.Inputs...),
	}
}

// parsedTx returns the admission's OWN canonical consumption of the candidate,
// under exactly the Snapshot lifecycle guard: it is the transaction ParseTx
// produced from the very bytes Snapshot returns, so a consumer reading the two
// together never parses this candidate a second time. The parse AUTHORITY stays
// inside the owner: no caller may supply one.
func (a *DAAdmission) parsedTx() *consensus.Tx {
	a.mustLiveValue()
	if a.guard.state.Load() != daAdmissionOpen {
		panic("DA admission snapshot is not available")
	}
	return a.tx
}

// BeginCommit is one-shot; its successful input-bearing candidate has a nonzero token.
func (a *DAAdmission) BeginCommit(victims []DAAdmissionVictim) (*DACommit, error) {
	a.mustLiveValue()
	g := a.guard
	if !g.state.CompareAndSwap(daAdmissionOpen, daAdmissionAttempting) {
		panic("DA admission is not available for BeginCommit")
	}
	defer g.state.CompareAndSwap(daAdmissionAttempting, daAdmissionResolved)
	if len(a.snapshot.Inputs) > consensus.MAX_TX_INPUTS {
		return nil, txAdmitFromPendingOutpointError(pendingOutpointInternal("invalid DA candidate input count"))
	}
	if err := validatePendingOutpointRequest(PendingOutpointDA, a.snapshot.TxID, a.snapshot.Inputs); err != nil {
		return nil, txAdmitFromPendingOutpointError(err)
	}
	candidate := &pendingOutpointClaim{domain: PendingOutpointDA, txid: a.snapshot.TxID, inputs: append([]consensus.Outpoint(nil), a.snapshot.Inputs...)}
	batch, err := prepareDAAdmissionVictims(victims, a.snapshot.TxID)
	if err != nil {
		return nil, txAdmitFromPendingOutpointError(err)
	}
	commit := &DACommit{guard: g, victims: batch}
	commit.self = commit
	g.owner.mu.Lock()
	token, failure, failed := g.owner.reserveDAAdmissionLocked(a.context, candidate)
	if !failed {
		failure, failed = g.owner.validateDAAdmissionVictimsLocked(batch, token)
	}
	if failed {
		if token != (PendingOutpointToken{}) {
			g.owner.dropClaimLocked(token)
		}
		g.owner.mu.Unlock()
		return nil, txAdmitFromPendingOutpointError(&failure)
	}
	commit.candidate = token
	g.state.Store(daAdmissionLive)
	return commit, nil
}

func prepareDAAdmissionVictims(victims []DAAdmissionVictim, candidate [32]byte) ([]DAAdmissionVictim, error) {
	if candidate == ([32]byte{}) && len(victims) == 0 {
		return nil, pendingOutpointInternal("empty DA victim batch")
	}
	if len(victims) > daAdmissionMaxVictims {
		return nil, pendingOutpointInternal("DA victim batch exceeds bound")
	}
	batch := make([]DAAdmissionVictim, len(victims))
	seenTxID := make(map[[32]byte]struct{}, len(victims))
	seenToken := make(map[PendingOutpointToken]struct{}, len(victims))
	for i, victim := range victims {
		if err := validateDAAdmissionVictimShape(victim, candidate); err != nil {
			return nil, err
		}
		if _, duplicate := seenTxID[victim.TxID]; duplicate {
			return nil, pendingOutpointInternal("duplicate DA victim txid")
		}
		if _, duplicate := seenToken[victim.Token]; duplicate {
			return nil, pendingOutpointInternal("duplicate DA victim token")
		}
		batch[i] = DAAdmissionVictim{TxID: victim.TxID, Token: victim.Token, Inputs: append([]consensus.Outpoint(nil), victim.Inputs...)}
		seenTxID[victim.TxID] = struct{}{}
		seenToken[victim.Token] = struct{}{}
	}
	return batch, nil
}

func validateDAAdmissionVictimShape(victim DAAdmissionVictim, candidate [32]byte) error {
	if victim.TxID == ([32]byte{}) || victim.Token == (PendingOutpointToken{}) {
		return pendingOutpointInternal("zero DA victim txid or token")
	}
	if len(victim.Inputs) == 0 || len(victim.Inputs) > consensus.MAX_TX_INPUTS {
		return pendingOutpointInternal("invalid DA victim input count")
	}
	if err := validatePendingOutpointRequest(PendingOutpointDA, victim.TxID, victim.Inputs); err != nil {
		return err
	}
	if candidate != ([32]byte{}) && victim.TxID == candidate {
		return pendingOutpointInternal("DA candidate is also a victim")
	}
	return nil
}

// Close releases the admission guard after a failed attempt or terminal commit;
// a copied, live, or repeated Close fails fast without a second unlock.
func (a *DAAdmission) Close() { a.mustLiveValue(); a.guard.close() }

func (a *DAAdmission) mustLiveValue() {
	if a == nil || a.self != a || a.guard == nil {
		panic("invalid DAAdmission")
	}
}

// BeginDARemoval starts a candidate-free DA removal guarded until Close.
func (m *Mempool) BeginDARemoval() (*DARemoval, error) {
	if m == nil {
		return nil, txAdmitUnavailable("nil mempool")
	}
	if m.chainState == nil {
		return nil, txAdmitUnavailable("nil chainstate")
	}
	if m.pendingOutpoints == nil {
		return nil, txAdmitUnavailable("nil pending-outpoint owner")
	}
	m.chainState.admissionMu.RLock()
	r := &DARemoval{guard: &daAdmissionGuard{chainState: m.chainState, owner: m.pendingOutpoints}}
	r.self = r
	return r, nil
}

// BeginCommit is one-shot; a successful removal commit always has a zero token.
func (r *DARemoval) BeginCommit(victims []DAAdmissionVictim) (*DACommit, error) {
	r.mustLiveValue()
	g := r.guard
	if !g.state.CompareAndSwap(daAdmissionOpen, daAdmissionAttempting) {
		panic("DA removal is not available for BeginCommit")
	}
	defer g.state.CompareAndSwap(daAdmissionAttempting, daAdmissionResolved)
	batch, err := prepareDAAdmissionVictims(victims, [32]byte{})
	if err != nil {
		return nil, txAdmitFromPendingOutpointError(err)
	}
	commit := &DACommit{guard: g, victims: batch}
	commit.self = commit
	g.owner.mu.Lock()
	failure, failed := g.owner.validateDAAdmissionVictimsLocked(batch, PendingOutpointToken{})
	if failed {
		g.owner.mu.Unlock()
		return nil, txAdmitFromPendingOutpointError(&failure)
	}
	g.state.Store(daAdmissionLive)
	return commit, nil
}

// Close releases the removal guard after a failed attempt or terminal commit; copied, live, and repeated calls fail fast without a second unlock.
func (r *DARemoval) Close() { r.mustLiveValue(); r.guard.close() }

func (r *DARemoval) mustLiveValue() {
	if r == nil || r.self != r || r.guard == nil {
		panic("invalid DARemoval")
	}
}

func (g *daAdmissionGuard) close() {
	state := g.state.Load()
	if (state != daAdmissionOpen && state != daAdmissionResolved) || !g.state.CompareAndSwap(state, daAdmissionClosed) {
		panic("DA admission guard is not closable")
	}
	g.chainState.admissionMu.RUnlock()
}

// CandidateToken returns the nonzero admission token or the zero removal token while live.
func (g *DACommit) CandidateToken() PendingOutpointToken {
	g.mustValue()
	if g.guard.state.Load() != daAdmissionLive {
		panic("DACommit is not live")
	}
	return g.candidate
}

// Commit finalizes the candidate and removes prepared victims exactly once.
func (g *DACommit) Commit() { g.finish(true) }

// Abort releases an unfinalized candidate and preserves prepared victims exactly once.
func (g *DACommit) Abort() { g.finish(false) }

func (g *DACommit) finish(finalize bool) {
	g.mustValue()
	if g.guard.state.Load() != daAdmissionLive || !g.guard.state.CompareAndSwap(daAdmissionLive, daAdmissionFinishing) {
		panic("DACommit is not live")
	}
	owner := g.guard.owner
	if g.candidate != (PendingOutpointToken{}) {
		if finalize {
			owner.byToken[g.candidate].finalized = true
		} else {
			owner.dropClaimLocked(g.candidate)
		}
	}
	if finalize {
		for _, victim := range g.victims {
			owner.dropClaimLocked(victim.Token)
		}
	}
	owner.mu.Unlock()
	g.guard.state.Store(daAdmissionResolved)
}

func (g *DACommit) mustValue() {
	if g == nil || g.self != g || g.guard == nil || g.guard.owner == nil {
		panic("invalid DACommit")
	}
}
