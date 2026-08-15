package node

import (
	"errors"
	"fmt"
	"sync"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

// PendingOutpointDomain names the pool that owns a pending-outpoint claim.
// StandardMempool and DA share one owner through distinct domains.
type PendingOutpointDomain uint8

const (
	// PendingOutpointStandardMempool is the standard Mempool admission domain.
	PendingOutpointStandardMempool PendingOutpointDomain = 1
	// PendingOutpointDA is the data-availability domain.
	PendingOutpointDA PendingOutpointDomain = 2
)

func (d PendingOutpointDomain) valid() bool {
	return d == PendingOutpointStandardMempool || d == PendingOutpointDA
}

// PendingOutpointTip is the stable canonical tip a reservation is bound to.
// A reservation whose expected tip differs from the owner's committed stable
// tip is unavailable, never a conflict.
type PendingOutpointTip struct {
	HasTip bool
	Height uint64
	Hash   [32]byte
}

func pendingOutpointTipOf(s *ChainState) PendingOutpointTip {
	view := s.view()
	return PendingOutpointTip{HasTip: view.hasTip, Height: view.height, Hash: view.tipHash}
}

// PendingOutpointAdmissionContext is one linearizable read of the owner's
// admission-visible state: the exact stable canonical tip reservations are
// currently bound to, and the monotonic transition generation that tip belongs
// to.
//
// Generation is the cache-validity term. The initial stable context and every
// begun canonical transition have DISTINCT generations, and neither a commit
// nor an abort ever decreases or reuses the generation high-water, so an
// A->B->A reorg and a failed transition both produce a generation no earlier
// context ever carried. A downstream policy cache may therefore treat an
// unchanged generation, and only that, as "nothing observable moved".
type PendingOutpointAdmissionContext struct {
	StableTip  PendingOutpointTip
	Generation uint64
}

// PendingOutpointToken identifies exactly one reservation. It is comparable and
// opaque outside package node: it carries the issuing owner's identity and a
// nonzero monotonic sequence, has no exported constructor, and is never
// serialized. A token from a previous process, or from any other owner, is
// foreign to this owner by construction.
type PendingOutpointToken struct {
	owner *PendingOutpointOwner
	seq   uint64
}

// PendingOutpointErrorKind classifies pending-outpoint failures.
type PendingOutpointErrorKind uint8

const (
	// PendingOutpointConflict reports an outpoint already claimed by another
	// live reservation. Evidence names the first conflicting outpoint in the
	// supplied input order, its index, and the claiming txid.
	PendingOutpointConflict PendingOutpointErrorKind = iota + 1
	// PendingOutpointUnavailable reports a temporarily closed owner: an active
	// canonical transition, an expected-tip mismatch, a stale generation, or an
	// exhausted sequence space.
	PendingOutpointUnavailable
	// PendingOutpointInternal reports a malformed request or an owner-state
	// inconsistency. It never publishes domain state.
	PendingOutpointInternal
)

// PendingOutpointError is the typed owner error. Conflict evidence fields are
// meaningful only for PendingOutpointConflict.
type PendingOutpointError struct {
	Kind         PendingOutpointErrorKind
	Msg          string
	Outpoint     consensus.Outpoint
	InputIndex   int
	ExistingTxid [32]byte
}

func (e *PendingOutpointError) Error() string { return e.Msg }

func pendingOutpointInternal(msg string) *PendingOutpointError {
	return &PendingOutpointError{Kind: PendingOutpointInternal, Msg: msg}
}

func pendingOutpointUnavailable(msg string) *PendingOutpointError {
	return &PendingOutpointError{Kind: PendingOutpointUnavailable, Msg: msg}
}

// pendingOutpointClaim is one live reservation. inputs keeps the exact caller
// order so a release compare-deletes precisely the rows it installed.
type pendingOutpointClaim struct {
	token      PendingOutpointToken
	domain     PendingOutpointDomain
	txid       [32]byte
	inputs     []consensus.Outpoint
	generation uint64
	finalized  bool
}

// pendingOutpointRow is the by-outpoint index row. It carries the exact owner
// identity and token sequence, so a stale release can never delete a newer
// claim that happens to cover the same outpoint.
type pendingOutpointRow struct {
	token PendingOutpointToken
	txid  [32]byte
}

// PendingOutpointOwner is the single authority over outpoints claimed by
// in-flight and resident pool candidates.
//
// Lock contract: standard callers use ChainState.admissionMu -> Mempool.mu ->
// owner. DA callers hold the continuous ChainState admission guard and a
// downstream DA state lock before owner; this primitive never takes that lock.
// Callers materialize buffers and scratch before owner; only bounded owner-map
// bucket growth may occur while publishing one prepared candidate claim.
type PendingOutpointOwner struct {
	mu             sync.Mutex
	byOutpoint     map[consensus.Outpoint]pendingOutpointRow
	byToken        map[PendingOutpointToken]*pendingOutpointClaim
	tokenHighWater uint64
	generation     uint64
	inTransition   bool
	stableTip      PendingOutpointTip
}

func newPendingOutpointOwner(tip PendingOutpointTip) *PendingOutpointOwner {
	return &PendingOutpointOwner{
		byOutpoint: make(map[consensus.Outpoint]pendingOutpointRow),
		byToken:    make(map[PendingOutpointToken]*pendingOutpointClaim),
		stableTip:  tip,
	}
}

// validatePendingOutpointRequest checks a reservation request in isolation:
// domain, txid, and the input set. It reads no owner state, acquires no lock,
// and mutates nothing, so a malformed request is rejected as internal before the
// owner mutex is taken and can consume no sequence.
func validatePendingOutpointRequest(
	domain PendingOutpointDomain,
	txid [32]byte,
	orderedInputs []consensus.Outpoint,
) error {
	if !domain.valid() {
		return pendingOutpointInternal(fmt.Sprintf("invalid pending-outpoint domain %d", uint8(domain)))
	}
	if txid == ([32]byte{}) {
		return pendingOutpointInternal("zero pending-outpoint txid")
	}
	if len(orderedInputs) == 0 {
		return pendingOutpointInternal("empty pending-outpoint input set")
	}
	seen := make(map[consensus.Outpoint]struct{}, len(orderedInputs))
	for _, op := range orderedInputs {
		if _, dup := seen[op]; dup {
			return pendingOutpointInternal(fmt.Sprintf("duplicate pending-outpoint input txid=%x vout=%d", op.Txid, op.Vout))
		}
		seen[op] = struct{}{}
	}
	return nil
}

// checkReserveAvailableLocked reports whether the owner can issue a reservation
// bound to the COMPLETE context the caller observed. The checks run in exactly
// this order — active transition, exact stable tip, exact generation, sequence
// space — each failure is unavailable rather than a conflict, and it only reads
// owner state under the caller's o.mu.
//
// The generation term is what a tip comparison alone cannot express: after an
// A->B->A reorg, or an aborted transition, the stable tip compares equal to a
// context cached BEFORE that transition while everything derived under it is
// stale. Generation never decreases or repeats, so an older expected generation
// loses here, before the conflict scan and before any sequence is consumed.
func (o *PendingOutpointOwner) checkReserveAvailableLocked(expected PendingOutpointAdmissionContext) error {
	if o.inTransition {
		return pendingOutpointUnavailable("pending-outpoint owner transition in progress")
	}
	if expected.StableTip != o.stableTip {
		return pendingOutpointUnavailable("pending-outpoint expected tip mismatch")
	}
	if expected.Generation != o.generation {
		return pendingOutpointUnavailable("pending-outpoint expected generation mismatch")
	}
	if o.tokenHighWater == ^uint64(0) {
		return pendingOutpointUnavailable("pending-outpoint token sequence exhausted")
	}
	return nil
}

// checkNoConflictLocked reports the FIRST outpoint of orderedInputs already held
// by a live claim, in the supplied canonical input order. It only reads the
// by-outpoint index under the caller's o.mu and mutates nothing, so a conflict
// leaves no partial claim behind.
func (o *PendingOutpointOwner) checkNoConflictLocked(orderedInputs []consensus.Outpoint) error {
	for index, op := range orderedInputs {
		if row, taken := o.byOutpoint[op]; taken {
			return &PendingOutpointError{
				Kind:         PendingOutpointConflict,
				Msg:          fmt.Sprintf("mempool double-spend conflict with %x", row.txid),
				Outpoint:     op,
				InputIndex:   index,
				ExistingTxid: row.txid,
			}
		}
	}
	return nil
}

// reserveDAAdmissionLocked reserves a prepared input-bearing DA candidate. The
// caller holds o.mu; caller buffers and scratch were materialized before it.
// Only bounded Go map bucket growth may occur while publishing the prepared rows.
func (o *PendingOutpointOwner) reserveDAAdmissionLocked(
	expected PendingOutpointAdmissionContext,
	claim *pendingOutpointClaim,
) (PendingOutpointToken, PendingOutpointError, bool) {
	var zero PendingOutpointToken
	if o.inTransition {
		return zero, PendingOutpointError{Kind: PendingOutpointUnavailable, Msg: "pending-outpoint owner transition in progress"}, true
	}
	if expected.StableTip != o.stableTip {
		return zero, PendingOutpointError{Kind: PendingOutpointUnavailable, Msg: "pending-outpoint expected tip mismatch"}, true
	}
	if expected.Generation != o.generation {
		return zero, PendingOutpointError{Kind: PendingOutpointUnavailable, Msg: "pending-outpoint expected generation mismatch"}, true
	}
	if o.tokenHighWater == ^uint64(0) {
		return zero, PendingOutpointError{Kind: PendingOutpointUnavailable, Msg: "pending-outpoint token sequence exhausted"}, true
	}
	for index, op := range claim.inputs {
		if row, taken := o.byOutpoint[op]; taken {
			return zero, PendingOutpointError{Kind: PendingOutpointConflict, Outpoint: op, InputIndex: index, ExistingTxid: row.txid}, true
		}
	}
	o.tokenHighWater++
	token := PendingOutpointToken{owner: o, seq: o.tokenHighWater}
	claim.token = token
	claim.generation = o.generation
	o.byToken[token] = claim
	for _, op := range claim.inputs {
		o.byOutpoint[op] = pendingOutpointRow{token: token, txid: claim.txid}
	}
	return token, PendingOutpointError{}, false
}

// validateDAAdmissionVictimsLocked checks already-copied, shape-valid victim
// descriptors without allocating. The candidate is never a removable victim.
func (o *PendingOutpointOwner) validateDAAdmissionVictimsLocked(
	victims []DAAdmissionVictim,
	candidateToken PendingOutpointToken,
) (PendingOutpointError, bool) {
	available := len(o.byToken)
	if candidateToken != (PendingOutpointToken{}) {
		available--
	}
	if len(victims) > available {
		return PendingOutpointError{Kind: PendingOutpointInternal, Msg: "DA victim batch exceeds live claim population"}, true
	}
	for _, victim := range victims {
		if victim.Token == candidateToken {
			return PendingOutpointError{Kind: PendingOutpointInternal, Msg: "DA candidate token is also a victim"}, true
		}
		if victim.Token.owner != o || victim.Token.seq == 0 || victim.Token.seq > o.tokenHighWater {
			return PendingOutpointError{Kind: PendingOutpointInternal, Msg: "invalid DA victim token"}, true
		}
		claim := o.byToken[victim.Token]
		if claim == nil || claim.domain != PendingOutpointDA || claim.txid != victim.TxID || !claim.finalized {
			return PendingOutpointError{Kind: PendingOutpointInternal, Msg: "DA victim claim mismatch"}, true
		}
		if len(claim.inputs) != len(victim.Inputs) {
			return PendingOutpointError{Kind: PendingOutpointInternal, Msg: "DA victim input mismatch"}, true
		}
		for j, input := range victim.Inputs {
			if claim.inputs[j] != input || o.byOutpoint[input] != (pendingOutpointRow{token: victim.Token, txid: victim.TxID}) {
				return PendingOutpointError{Kind: PendingOutpointInternal, Msg: "DA victim input mismatch"}, true
			}
		}
	}
	return PendingOutpointError{}, false
}

// Reserve claims every outpoint in orderedInputs for txid in domain, bound to
// the COMPLETE admission context the caller observed — stable tip AND
// generation, deliberately not a tip alone, so a caller that decided anything
// under an older generation loses instead of reserving against state it never
// saw. It validates the request (owner, domain, txid, input set) before it looks
// at availability or conflicts, so a malformed request is an internal error that
// mutates nothing and consumes no sequence. Availability failures — active
// transition, expected-tip mismatch, expected-generation mismatch, sequence
// exhaustion — and the first conflict in canonical input order likewise mutate
// nothing: every check is a pure read that completes before the first write
// below. On success exactly one sequence is consumed and the complete reserved
// claim is installed.
func (o *PendingOutpointOwner) Reserve(
	expectedContext PendingOutpointAdmissionContext,
	domain PendingOutpointDomain,
	txid [32]byte,
	orderedInputs []consensus.Outpoint,
) (PendingOutpointToken, error) {
	var zero PendingOutpointToken
	if o == nil {
		return zero, pendingOutpointInternal("nil pending-outpoint owner")
	}
	if err := validatePendingOutpointRequest(domain, txid, orderedInputs); err != nil {
		return zero, err
	}

	o.mu.Lock()
	defer o.mu.Unlock()
	if err := o.checkReserveAvailableLocked(expectedContext); err != nil {
		return zero, err
	}
	if err := o.checkNoConflictLocked(orderedInputs); err != nil {
		return zero, err
	}
	o.tokenHighWater++
	token := PendingOutpointToken{owner: o, seq: o.tokenHighWater}
	o.byToken[token] = &pendingOutpointClaim{
		token:      token,
		domain:     domain,
		txid:       txid,
		inputs:     append([]consensus.Outpoint(nil), orderedInputs...),
		generation: o.generation,
	}
	for _, op := range orderedInputs {
		o.byOutpoint[op] = pendingOutpointRow{token: token, txid: txid}
	}
	return token, nil
}

// AdmissionContext reports the current stable tip and generation, read under
// ONE owner-lock acquisition so the pair is always internally consistent. It
// mutates nothing.
//
// It returns false — never a stale or partial context — when the owner is nil,
// when a canonical transition is active (including the terminal fail-closed
// state a latched post-commit persistence fault leaves behind), or when the
// generation space is exhausted so no further transition could ever be
// distinguished. A reader racing a transition begin therefore observes either
// the prior stable context or unavailability, never a stable context paired
// with an active transition.
//
// This is the ONLY downstream policy-generation seam on the owner: it adds no
// generic TxPool method, no cache, no callback, no notification hook and no DA
// behavior.
func (o *PendingOutpointOwner) AdmissionContext() (PendingOutpointAdmissionContext, bool) {
	if o == nil {
		return PendingOutpointAdmissionContext{}, false
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.admissionContextLocked()
}

// admissionContextLocked is AdmissionContext's body for a caller that already
// holds o.mu: the binding recheck compares the context and installs the pointer
// without releasing the owner mutex in between.
func (o *PendingOutpointOwner) admissionContextLocked() (PendingOutpointAdmissionContext, bool) {
	if o.inTransition || o.generation == ^uint64(0) {
		return PendingOutpointAdmissionContext{}, false
	}
	return PendingOutpointAdmissionContext{StableTip: o.stableTip, Generation: o.generation}, true
}

// checkNoClaimsLocked proves the owner holds no live claim in either index. The
// caller holds o.mu.
func (o *PendingOutpointOwner) checkNoClaimsLocked() error {
	if len(o.byOutpoint) != 0 || len(o.byToken) != 0 {
		return pendingOutpointInternal(fmt.Sprintf("pending-outpoint owner holds %d outpoint and %d token claims", len(o.byOutpoint), len(o.byToken)))
	}
	return nil
}

// Finalize publishes a reserved claim of the current generation. An exact retry
// of an already-finalized current-generation token succeeds without a second
// mutation. Finalization during a transition, after a release, or from an older
// generation is unavailable and publishes nothing; an invalid or foreign token
// identity is internal.
func (o *PendingOutpointOwner) Finalize(token PendingOutpointToken) error {
	if o == nil {
		return pendingOutpointInternal("nil pending-outpoint owner")
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	claim, err := o.claimForTokenLocked(token)
	if err != nil {
		return err
	}
	if o.inTransition {
		return pendingOutpointUnavailable("pending-outpoint owner transition in progress")
	}
	if claim == nil {
		return pendingOutpointUnavailable("pending-outpoint token is no longer live")
	}
	if claim.generation != o.generation {
		return pendingOutpointUnavailable("pending-outpoint token belongs to an older generation")
	}
	if claim.finalized {
		return nil
	}
	claim.finalized = true
	return nil
}

// Release drops a claim and every by-outpoint row it installed, or drops none.
// It is generation-independent and remains valid during a transition. An exact
// retry after the claim is already gone succeeds and leaves no tombstone. A
// zero token, a foreign owner, a sequence above the high-water mark, or a
// partially matching live index is internal and changes nothing.
func (o *PendingOutpointOwner) Release(token PendingOutpointToken) error {
	if o == nil {
		return pendingOutpointInternal("nil pending-outpoint owner")
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	claim, err := o.claimForTokenLocked(token)
	if err != nil || claim == nil {
		return err
	}
	for _, op := range claim.inputs {
		if row, ok := o.byOutpoint[op]; !ok || row.token != token {
			return pendingOutpointInternal(fmt.Sprintf("pending-outpoint index mismatch for txid=%x vout=%d", op.Txid, op.Vout))
		}
	}
	o.dropClaimLocked(token)
	return nil
}

// pendingOutpointIndex is one by-outpoint / by-token index pair plus the token
// high-water it was built under. The owner's LIVE pair and a not-yet-published
// restore candidate are both read through it, so one binding rule serves both
// and a restore is proven consistent BEFORE anything becomes visible.
type pendingOutpointIndex struct {
	owner          *PendingOutpointOwner
	byOutpoint     map[consensus.Outpoint]pendingOutpointRow
	byToken        map[PendingOutpointToken]*pendingOutpointClaim
	tokenHighWater uint64
}

// indexLocked views the owner's live indexes. The caller holds o.mu.
func (o *PendingOutpointOwner) indexLocked() pendingOutpointIndex {
	return pendingOutpointIndex{
		owner:          o,
		byOutpoint:     o.byOutpoint,
		byToken:        o.byToken,
		tokenHighWater: o.tokenHighWater,
	}
}

// claimForToken resolves an owner-issued token. It reports an internal error for
// an identity this owner never issued, and (nil, nil) for a valid past sequence
// that no longer has a live claim.
func (ix pendingOutpointIndex) claimForToken(token PendingOutpointToken) (*pendingOutpointClaim, error) {
	if token.owner != ix.owner || token.seq == 0 {
		return nil, pendingOutpointInternal("zero or foreign pending-outpoint token")
	}
	if token.seq > ix.tokenHighWater {
		return nil, pendingOutpointInternal("pending-outpoint token sequence above high-water")
	}
	return ix.byToken[token], nil
}

func (o *PendingOutpointOwner) claimForTokenLocked(token PendingOutpointToken) (*pendingOutpointClaim, error) {
	return o.indexLocked().claimForToken(token)
}

// dropClaimLocked deletes an already-validated claim. It cannot fail, so a
// commit that validated its whole delta first has no error-capable step left.
func (o *PendingOutpointOwner) dropClaimLocked(token PendingOutpointToken) {
	claim := o.byToken[token]
	if claim == nil {
		return
	}
	for _, op := range claim.inputs {
		if row, ok := o.byOutpoint[op]; ok && row.token == token {
			delete(o.byOutpoint, op)
		}
	}
	delete(o.byToken, token)
}

// checkInputLessEntryToken proves that an input-less record carries the zero
// token, the only shape an entry with no claim may have. It reads no index and
// mutates nothing.
func checkInputLessEntryToken(txid [32]byte, token PendingOutpointToken) error {
	if token != (PendingOutpointToken{}) {
		return pendingOutpointInternal(fmt.Sprintf("pending-outpoint token on input-less entry %x", txid))
	}
	return nil
}

// checkClaimInputs proves that claim covers exactly inputs, in the same order,
// and that every one of those outpoints is indexed back to the same token. It
// only reads the index and mutates nothing.
func (ix pendingOutpointIndex) checkClaimInputs(
	txid [32]byte,
	inputs []consensus.Outpoint,
	claim *pendingOutpointClaim,
	token PendingOutpointToken,
) error {
	if len(claim.inputs) != len(inputs) {
		return pendingOutpointInternal(fmt.Sprintf("pending-outpoint claim input count mismatch for entry %x", txid))
	}
	for i, op := range inputs {
		row, ok := ix.byOutpoint[op]
		if claim.inputs[i] != op || !ok || row.token != token {
			return pendingOutpointInternal(fmt.Sprintf("pending-outpoint claim input mismatch for entry %x at index %d", txid, i))
		}
	}
	return nil
}

// validateEntryClaim proves that a pool record and its claim agree exactly: same
// owner, sequence, domain, txid, ordered inputs, index rows and phase. An
// input-less record carries no claim and MUST carry no token. It only reads the
// index and mutates nothing.
func (ix pendingOutpointIndex) validateEntryClaim(
	txid [32]byte,
	inputs []consensus.Outpoint,
	token PendingOutpointToken,
	wantFinalized bool,
) error {
	if len(inputs) == 0 {
		return checkInputLessEntryToken(txid, token)
	}
	claim, err := ix.claimForToken(token)
	if err != nil {
		return err
	}
	if claim == nil {
		return pendingOutpointInternal(fmt.Sprintf("no live pending-outpoint claim for entry %x", txid))
	}
	if claim.domain != PendingOutpointStandardMempool || claim.txid != txid || claim.finalized != wantFinalized {
		return pendingOutpointInternal(fmt.Sprintf("pending-outpoint claim mismatch for entry %x", txid))
	}
	return ix.checkClaimInputs(txid, inputs, claim, token)
}

func (o *PendingOutpointOwner) validateEntryClaimLocked(
	txid [32]byte,
	inputs []consensus.Outpoint,
	token PendingOutpointToken,
	wantFinalized bool,
) error {
	return o.indexLocked().validateEntryClaim(txid, inputs, token, wantFinalized)
}

// txidForOutpoint reports the txid currently claiming op, if any.
func (o *PendingOutpointOwner) txidForOutpoint(op consensus.Outpoint) ([32]byte, bool) {
	if o == nil {
		return [32]byte{}, false
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	row, ok := o.byOutpoint[op]
	return row.txid, ok
}

// standardMempoolDelta is the fully precomputed standard-domain change one
// commit applies: at most one candidate entry plus a bounded exact list of
// victim or terminal entries. Every entry carries its own exact token.
type standardMempoolDelta struct {
	candidate *mempoolEntry
	removals  []*mempoolEntry
}

// commitStandardDeltaLocked applies delta to the standard Mempool records and
// to the owner's claims together. The caller holds Mempool.mu.
//
// Everything fallible runs first: map allocation, record residency, and each
// entry's exact claim. Once mutation begins under the owner mutex there is no
// parse, validation, cryptography, I/O, wait, re-entry, callback, new lock, or
// error-capable step left, so a record and its claim cannot become observably
// separated. An exact idempotent retry performs no second domain mutation
// because a removal that is no longer resident fails validation before any
// write.
func (m *Mempool) commitStandardDeltaLocked(delta standardMempoolDelta) error {
	if m == nil {
		return txAdmitUnavailable("nil mempool")
	}
	m.ensureIndexesLocked()
	owner := m.pendingOutpointOwnerLocked()
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if err := m.validateStandardDeltaLocked(delta, owner); err != nil {
		return err
	}
	for _, entry := range delta.removals {
		m.deleteEntryLocked(entry.txid, entry)
		owner.dropClaimLocked(entry.token)
	}
	if delta.candidate != nil {
		m.assignAdmissionSeqLocked(delta.candidate)
		m.insertEntryIndexesLocked(delta.candidate)
		if claim := owner.byToken[delta.candidate.token]; claim != nil {
			claim.finalized = true
		}
	}
	return nil
}

// validateStandardRemovalsLocked proves every removal is a distinct resident
// record whose exact finalized claim still matches it, recording each removed
// txid in removed so the candidate cannot collide with one. It mutates neither
// the Mempool nor the owner — removed is the caller's own accumulator, passed in
// rather than returned so this function's complexity stays measurable by the
// Codacy-parity gate, whose Go parser truncates a `struct{}` return type. The
// caller holds Mempool.mu then owner.mu.
func (m *Mempool) validateStandardRemovalsLocked(
	removals []*mempoolEntry,
	removed map[[32]byte]struct{},
	owner *PendingOutpointOwner,
) error {
	for _, entry := range removals {
		if entry == nil {
			return txAdmitUnavailable("nil standard mempool terminal entry")
		}
		if _, dup := removed[entry.txid]; dup {
			return txAdmitUnavailable(fmt.Sprintf("duplicate standard mempool terminal entry %x", entry.txid))
		}
		removed[entry.txid] = struct{}{}
		if resident, ok := m.txs[entry.txid]; !ok || resident != entry {
			return txAdmitUnavailable(fmt.Sprintf("standard mempool terminal entry %x is not resident", entry.txid))
		}
		if err := owner.validateEntryClaimLocked(entry.txid, entry.inputs, entry.token, true); err != nil {
			return txAdmitFromPendingOutpointError(err)
		}
	}
	return nil
}

// validateStandardCandidateLocked proves the candidate is not also being
// removed, that the owner is not mid-transition, and that its exact reserved
// claim belongs to the current generation. It only reads the owner indexes and
// mutates nothing; the caller holds Mempool.mu then owner.mu.
func validateStandardCandidateLocked(
	candidate *mempoolEntry,
	removed map[[32]byte]struct{},
	owner *PendingOutpointOwner,
) error {
	if _, dup := removed[candidate.txid]; dup {
		return txAdmitUnavailable(fmt.Sprintf("candidate %x is also a terminal entry", candidate.txid))
	}
	if owner.inTransition {
		return txAdmitUnavailable("pending-outpoint owner transition in progress")
	}
	if err := owner.validateEntryClaimLocked(candidate.txid, candidate.inputs, candidate.token, false); err != nil {
		return txAdmitFromPendingOutpointError(err)
	}
	if claim := owner.byToken[candidate.token]; claim != nil && claim.generation != owner.generation {
		return txAdmitUnavailable("pending-outpoint token belongs to an older generation")
	}
	return nil
}

// validateStandardDeltaLocked runs the delta's complete removals-then-candidate
// checking chain. It mutates neither the Mempool nor the owner, so it runs to
// completion before commitStandardDeltaLocked writes anything.
func (m *Mempool) validateStandardDeltaLocked(delta standardMempoolDelta, owner *PendingOutpointOwner) error {
	removed := make(map[[32]byte]struct{}, len(delta.removals))
	if err := m.validateStandardRemovalsLocked(delta.removals, removed, owner); err != nil {
		return err
	}
	if delta.candidate == nil {
		return nil
	}
	return validateStandardCandidateLocked(delta.candidate, removed, owner)
}

// txAdmitFromPendingOutpointError maps owner failures onto the existing public
// admission kinds. A conflict keeps the existing mempool double-spend message
// family; unavailable and internal both surface as TxAdmitUnavailable, so no
// new public TxAdmit kind is introduced.
func txAdmitFromPendingOutpointError(err error) error {
	var ownerErr *PendingOutpointError
	if !errors.As(err, &ownerErr) {
		return txAdmitUnavailable(err.Error())
	}
	if ownerErr.Kind == PendingOutpointConflict {
		if ownerErr.Msg == "" {
			ownerErr.Msg = fmt.Sprintf("mempool double-spend conflict with %x", ownerErr.ExistingTxid)
		}
		return txAdmitConflict(ownerErr.Msg)
	}
	return txAdmitUnavailable(ownerErr.Msg)
}
