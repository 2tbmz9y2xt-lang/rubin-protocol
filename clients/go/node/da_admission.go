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
type DAAdmission struct {
	self     *DAAdmission
	guard    *daAdmissionGuard
	snapshot DAAdmissionSnapshot
	tx       *consensus.Tx
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
func (m *Mempool) BeginDAAdmission(raw []byte) (*DAAdmission, error) {
	if m == nil {
		return nil, txAdmitUnavailable("nil mempool")
	}
	if m.chainState == nil {
		return nil, txAdmitUnavailable("nil chainstate")
	}
	owner := m.pendingOutpoints
	if owner == nil {
		return nil, txAdmitUnavailable("nil pending-outpoint owner")
	}
	owned, tx, txid, wtxid, inputs, err := parseDAAdmission(raw)
	if err != nil {
		return nil, err
	}
	return m.beginDAAdmissionGuarded(owner, owned, tx, txid, wtxid, inputs)
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

func (m *Mempool) beginDAAdmissionGuarded(owner *PendingOutpointOwner, owned []byte, tx *consensus.Tx, txid, wtxid [32]byte, inputs []consensus.Outpoint) (*DAAdmission, error) {
	m.chainState.admissionMu.RLock()
	locked := true
	defer func() {
		if locked {
			m.chainState.admissionMu.RUnlock()
		}
	}()
	snapshot := m.chainState.admissionSnapshotForInputs(inputs)
	policy := m.policySnapshot()
	checked, _, err := m.checkParsedTransactionWithSnapshot(owned, tx, txid, wtxid, snapshot, policy)
	if err != nil {
		return nil, err
	}
	admission, ok := owner.AdmissionContext()
	if !ok {
		return nil, txAdmitUnavailable("pending-outpoint owner admission context unavailable")
	}
	if admission.StableTip != (PendingOutpointTip{HasTip: snapshot.hasTip, Height: snapshot.height, Hash: snapshot.tipHash}) {
		return nil, txAdmitUnavailable("pending-outpoint owner tip does not match the guarded chainstate tip")
	}
	a := &DAAdmission{
		guard: &daAdmissionGuard{chainState: m.chainState, owner: owner},
		snapshot: DAAdmissionSnapshot{
			TxID:          checked.TxID,
			WTxID:         checked.WTxID,
			TxBytes:       owned,
			Fee:           checked.Fee,
			RetainedBytes: uint64(len(checked.Bytes)),
			Inputs:        inputs,
		},
		tx:      tx,
		context: admission,
	}
	a.self = a
	locked = false
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
