package node

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

// Seam: the owner-coupled retained-DA surface. Every retained DA member, its
// txid locator and its exact finalized PendingOutpointOwner DA claim are ONE
// bijection, and this file owns the three writers that may change it — remote or
// direct admission, peer teardown, and TTL expiry — plus the read-only retained
// lookup RUB-1169 consumes.

// daProvenanceKind is the CLOSED provenance set. Its zero value is not a member,
// so a DAProvenance{} literal is invalid by construction and there is no fourth
// arm to reach: the default arm of every switch below refuses.
type daProvenanceKind uint8

const (
	daProvenanceInvalid daProvenanceKind = iota
	daProvenancePeer
	daProvenanceLocal
	daProvenanceDetachedReorg
)

// DAProvenance is the opaque source of one DA admission. Its ZERO VALUE IS
// INVALID and AdmitDA refuses it before any owner or state work, so a caller
// cannot admit without naming a source.
//
// Only a PEER carries identities, and it carries BOTH: peerIdentity is the
// scoring subject and quotaIdentity is the per-peer accounting and teardown key.
// LOCAL and DETACHED_REORG are PEERLESS and DISTINCT — they never consume, test
// or acquire a peer quota (RUBIN_MEMPOOL_POLICY.md Section 11.1) and they are
// never selected by peer teardown.
//
// Identity emptiness is the ONLY identity check: a nonempty string of spaces is
// a valid identity here, exactly as it is everywhere else the peer address and
// quota key are carried, because this type is not the place that decides what a
// peer address may look like.
type DAProvenance struct {
	kind          daProvenanceKind
	peerIdentity  string
	quotaIdentity string
}

// NewPeerDAProvenance builds PEER provenance. It errors unless BOTH identities
// are nonempty, so a peer-sourced admission can never be charged to an anonymous
// quota or scored against an anonymous peer.
func NewPeerDAProvenance(peerIdentity, quotaIdentity string) (DAProvenance, error) {
	if peerIdentity == "" || quotaIdentity == "" {
		return DAProvenance{}, errors.New("peer DA provenance requires a nonempty peer identity and quota identity")
	}
	return DAProvenance{kind: daProvenancePeer, peerIdentity: peerIdentity, quotaIdentity: quotaIdentity}, nil
}

// LocalDAProvenance is the peerless local-submission source.
func LocalDAProvenance() DAProvenance { return DAProvenance{kind: daProvenanceLocal} }

// DetachedReorgDAProvenance is the peerless detached-requeue source.
func DetachedReorgDAProvenance() DAProvenance {
	return DAProvenance{kind: daProvenanceDetachedReorg}
}

// quotaKey is the per-peer accounting key this provenance is charged under. A
// peerless source has NO key, which is what keeps it out of every per-peer
// counter and out of peer teardown.
func (p DAProvenance) quotaKey() string {
	if p.kind == daProvenancePeer {
		return p.quotaIdentity
	}
	return ""
}

// validate refuses the zero value, any value outside the closed set, a PEER with
// an empty identity, and a peerless value carrying an identity — the last of
// which only a forged struct literal can produce. It reads no state.
func (p DAProvenance) validate() error {
	switch p.kind {
	case daProvenancePeer:
		if p.peerIdentity == "" || p.quotaIdentity == "" {
			return txAdmitRejected("peer DA provenance carries an empty identity")
		}
		return nil
	case daProvenanceLocal, daProvenanceDetachedReorg:
		if p.peerIdentity != "" || p.quotaIdentity != "" {
			return txAdmitRejected("peerless DA provenance carries a peer identity")
		}
		return nil
	default:
		return txAdmitRejected("invalid DA provenance")
	}
}

// DAAdmissionDisposition is the closed, NONZERO result class of one AdmitDA
// call. There is no third value and no zero value.
type DAAdmissionDisposition uint8

const (
	// DAAdmissionRetained means the EXACT member is resident after the call.
	DAAdmissionRetained DAAdmissionDisposition = 1
	// DAAdmissionDuplicate is a REJECTED no-mutation result: the member, or
	// the commit slot its record targets, is already occupied, so nothing was
	// reserved, nothing was removed, and no accepted-sequence value was
	// consumed.
	DAAdmissionDuplicate DAAdmissionDisposition = 2
)

// DAAdmissionResult reports which set the admission concerned and how it ended.
//
// SameDAIDCommitConflict is true ONLY when Disposition is DAAdmissionDuplicate
// and a FULLY VALIDATED DA_COMMIT_TX with a DIFFERENT txid competed with the
// retained first-seen commit for the same da_id (decided before any owner
// reserve). It is false for an exact replay, for a same-txid nonexact
// candidate, for every chunk and for every nonduplicate result. P2P applies the
// existing negative peer effect only from this bool AND PEER provenance — never
// from tx kind, error text or DUPLICATE alone
// (RUBIN_COMPACT_BLOCKS.md Section 5.1).
type DAAdmissionResult struct {
	DAID                   [32]byte
	Disposition            DAAdmissionDisposition
	SameDAIDCommitConflict bool
}

// DARetainedTxSnapshot is one retained DA member's caller-owned observation.
type DARetainedTxSnapshot struct {
	TxID    [32]byte
	WTxID   [32]byte
	TxBytes []byte
}

// daRelayAdmissionMember is one fully validated DA transaction rendered as the
// retained member it will become: its exact locator plus exactly one populated
// member slot.
type daRelayAdmissionMember struct {
	locator daRelayLocator
	commit  daRelayCommit
	chunk   daRelayChunk
}

// AdmitDA is the ONE owner-coupled entry that retains a DA member, for every
// provenance. It returns RETAINED with the member resident, or DUPLICATE having
// changed nothing at all.
//
// Order, and it is the whole safety argument
// (RUBIN_COMPACT_BLOCKS.md Section 5.1 duplicate-handling total order):
//
//  1. provenance is validated first, so an invalid source never reaches the
//     owner, the admission guard or any state;
//  2. the message bound and the full canonical parse derive txid, wtxid, kind
//     and DA identity BEFORE any guard — a failure there owns the result and no
//     ChainState or DA observation occurs;
//  3. acquireDAAdmissionHold is the SOLE ChainState.admissionMu.R acquisition
//     on this path (shared with BeginDAAdmission, factored in da_admission.go).
//     It obtains the stable guard AND the complete owner context first; guard,
//     context or owner unavailability and an unstable tip select the existing
//     UNAVAILABLE before any DA lock. The guard stays held for the whole call —
//     sync.RWMutex is not reentrant and nothing below may take it again;
//  4. under that held guard, exactly ONE DARelayState.mu window copies exactly
//     ONE raw retained observation for the candidate txid; the DA lock is
//     released BEFORE any retained parsing or validation, and the verdict is
//     never derived from state the copy did not observe. The copy is the
//     shortcut's only retained byte store; there is no second lookup, retry,
//     repair or fallback;
//  5. a located observation is integrity-validated OFF-lock, still under the
//     guard — invalid copied evidence selects the existing INTERNAL at this
//     originating site — and only then is exact (txid, wtxid, raw) equality
//     decided: an integrity-valid exact replay returns peer-neutral DUPLICATE
//     with zero ordinary validation, owner work, mutation, sequence or
//     publication — requested and unsolicited alike;
//  6. only ABSENT and retained-nonexact evidence continue, under the SAME
//     guard, through the existing signature, consensus, current-chain, fee and
//     candidate-integrity order (validateDACandidate) — a same-txid INVALID
//     candidate keeps its owning validation error and is never a duplicate;
//  7. every allocation, provenance, locator, record, accounting and victim
//     decision is PLANNED BEFORE the final DA lock, on a PRIVATE copy of the one
//     record this member joins, taken in its own DARelayState.mu window; nothing
//     that decides the new record is left to run inside the final lock. The one
//     thing the plan cannot carry is the projection of its accounting against the
//     LIVE counters, which are shared by every record and are therefore re-read
//     under the final lock — before the owner reserve, and before any mutation;
//  8. the FINAL DA lock performs only the recheck — duplicate/first-seen, then
//     the plan's currency, which is what makes every off-lock decision above
//     authoritative — and then DAAdmission.BeginCommit with the exact victim
//     descriptors, acquiring PendingOutpointOwner.mu LAST and holding it into
//     the returned DACommit, so the token write, the complete D publication by
//     assignment and Commit all run inside one owner hold with no fallible step
//     between them. A VALID same-txid nonexact candidate returns peer-neutral
//     DUPLICATE here, and a fully validated different-txid same-da_id commit
//     returns DUPLICATE with SameDAIDCommitConflict, both before any reserve.
//
// A failure before the publication in step 8 leaves D, the locator index and
// the owner byte-identical, and every exit — error, panic unwind of a fallible
// step, or duplicate — releases the admission guard exactly once (the deferred
// Close, or the deferred hold release that stands down after the transfer).
// There is deliberately NO Abort call: after BeginCommit succeeds the remaining
// work is a token assignment into an already-present map slot and the record,
// locator and counter assignments of installDASetRecordLocked; none of those can
// fail or panic, so no schedule exists that acquires a candidate token and then
// declines to finalize it.
//
// AdmitDA is SYNCHRONOUS by contract: it performs no network action, waits on
// no external event and returns only when the admission has been decided. It
// does BLOCK on locks — the admission read guard it holds for its whole
// duration (indefinitely against a latched engine, the documented A12
// residual), the DA lock and, inside BeginCommit, the owner lock.
func (s *DARelayState) AdmitDA(txBytes []byte, provenance DAProvenance) (DAAdmissionResult, error) {
	if err := s.checkAdmitDABound(); err != nil {
		return DAAdmissionResult{}, err
	}
	if err := provenance.validate(); err != nil {
		return DAAdmissionResult{}, err
	}
	owned, tx, txid, wtxid, inputs, err := s.mempool.parseDAAdmissionCandidate(txBytes)
	if err != nil {
		return DAAdmissionResult{}, err
	}
	hold, err := s.mempool.acquireDAAdmissionHold()
	if err != nil {
		return DAAdmissionResult{}, err
	}
	defer hold.releaseIfHeld()
	if result, done, err := s.classifyRetainedReplay(owned, txid, wtxid); done {
		return result, err
	}
	admission, err := hold.validateDACandidate(owned, tx, txid, wtxid, inputs)
	if err != nil {
		return DAAdmissionResult{}, err
	}
	defer admission.Close()
	member, err := daRelayAdmissionMemberOf(admission, provenance)
	if err != nil {
		return DAAdmissionResult{}, err
	}
	return s.commitDAAdmission(admission, member)
}

// checkAdmitDABound is AdmitDA's call-shape refusal ahead of step 1: an unbound
// relay state or one without a mempool selects the existing UNAVAILABLE before
// provenance, parse, guard or any state work.
func (s *DARelayState) checkAdmitDABound() error {
	if s == nil {
		return selectRelayDisposition(txAdmitUnavailable("no DA relay state bound"), RelayAdmissionUnavailable)
	}
	if s.mempool == nil {
		return selectRelayDisposition(txAdmitUnavailable("no mempool bound to the DA relay state"), RelayAdmissionUnavailable)
	}
	return nil
}

// classifyRetainedReplay is steps 4-5 of AdmitDA: one guarded raw observation,
// then OFF-lock over the copy — integrity validation first (invalid located
// evidence selects the existing INTERNAL, agreeing with LookupRetainedTx over
// the same state), exact (txid, wtxid, raw) equality second (peer-neutral
// DUPLICATE). ABSENT and integrity-valid nonexact evidence return done=false:
// the observation is discarded and the ordinary order resumes.
func (s *DARelayState) classifyRetainedReplay(owned []byte, txid, wtxid [32]byte) (DAAdmissionResult, bool, error) {
	observation := func() daRetainedObservation {
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.observeRetainedTxLocked(txid)
	}()
	if !observation.located {
		return DAAdmissionResult{}, false, nil
	}
	if _, err := observation.validate(txid); err != nil {
		return DAAdmissionResult{}, true, selectRelayDisposition(txAdmitUnavailable("invalid copied retained DA evidence: "+err.Error()), RelayAdmissionInternal)
	}
	if observation.member.txid == txid && observation.member.wtxid == wtxid && bytes.Equal(observation.raw, owned) {
		return DAAdmissionResult{DAID: observation.locator.daID, Disposition: DAAdmissionDuplicate}, true, nil
	}
	return DAAdmissionResult{}, false, nil
}

// daRelayAdmissionPlan is ONE complete admission decision, made outside the
// final DA lock: the whole new record value, the exact victim descriptors the
// staging drop implies, and the staging refusal if there was one.
//
// baseline is the REVISION of the record the plan was built against — the only
// live input the plan freezes, since bounds and the accepted sequence are
// rechecked against live values under the final lock. That lock proves the
// baseline still current before anything is applied, so a decision reached
// off-lock is never applied to a record it did not observe, and two admissions
// of DIFFERENT records never invalidate one another.
// image is the record transition the staging implies, derived HERE from the two
// frozen record values: the accounting each side contributes and the exact
// locator rows to retire and install. Carrying it is what leaves the corridor
// after the owner reserve with nothing to walk or allocate.
type daRelayAdmissionPlan struct {
	baseline uint64
	staged   daRelayStagedMember
	image    daRelayRecordImage
	victims  []DAAdmissionVictim
	stageErr error
}

// commitDAAdmission is AdmitDA's steps 7-8. PLANNING (step 7) runs OUTSIDE the
// final DA lock and APPLICATION (step 8) inside it.
func (s *DARelayState) commitDAAdmission(admission *DAAdmission, member daRelayAdmissionMember) (DAAdmissionResult, error) {
	plan, err := s.planDAAdmission(member)
	if err != nil {
		return DAAdmissionResult{}, err
	}
	return s.applyDAAdmissionPlan(admission, member, plan)
}

// planDAAdmission is step 7: one DARelayState.mu window copies the record this
// member belongs to, and every allocation, locator, record and victim decision
// is then made OFF-lock on that private copy. It publishes nothing, touches no
// live field and reaches no owner.
//
// Its own error return is reserved for a defect of the RETAINED record the plan
// walked — a member that owes a claim and carries no token — which is fail-closed
// and not a property of the candidate. A refusal of the CANDIDATE is carried in
// stageErr and classified under the final lock, where the plan is known current.
func (s *DARelayState) planDAAdmission(member daRelayAdmissionMember) (daRelayAdmissionPlan, error) {
	current := func() daRelaySetRecord {
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.sets[member.locator.daID]
	}()
	plan := daRelayAdmissionPlan{baseline: current.revision}
	staged, err := s.caps.stageDAMember(current, member)
	if err != nil {
		plan.stageErr = err
		return plan, nil
	}
	plan.staged = staged
	if plan.image, err = daRelayRecordImageOf(current, staged.record); err != nil {
		return plan, err
	}
	plan.victims, err = s.appendDAMemberVictims(nil, staged.dropped)
	return plan, err
}

// applyDAAdmissionPlan is step 8, and the whole final DA lock. It rechecks, in
// the contract's own order, duplicate/first-seen against the LIVE locator index,
// the LIVE record the plan was built against, the accepted SEQUENCE and the
// accounting BOUNDS, and only then reaches the owner. Nothing here parses, walks
// the retained set or decides what the new record is: that is the plan.
//
// The recheck is total over what the plan actually froze. The staged record is a
// pure function of ONE live input — the record itself — so its revision IS the
// plan/live agreement; the two values the plan did NOT freeze, the accounting
// counters and the sequence high-water, are re-derived here, which is why a
// concurrent admission of a DIFFERENT record neither invalidates this plan nor
// is lost to it. A raced change to THIS record is REFUSED with the existing
// transient UNAVAILABLE and every image byte-identical.
//
// Order is the safety argument: everything fallible — the rechecks, the bound
// projection and the owner reserve — runs before the FIRST live write, and what
// follows is assignment into present keys.
//
// The candidate arriving here is FULLY VALIDATED, so the two duplicate arms are
// Section 5.1's post-validation classes, both decided before any owner reserve
// and both discarding the plan: a live locator row for the candidate txid (an
// exact replay that raced a concurrent admission lands here) is peer-neutral
// DUPLICATE, and a commit staging refusal whose staged commit txid is PROVEN
// here to differ from the candidate's is DUPLICATE with SameDAIDCommitConflict.
func (s *DARelayState) applyDAAdmissionPlan(admission *DAAdmission, member daRelayAdmissionMember, plan daRelayAdmissionPlan) (DAAdmissionResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if result, done, err := s.recheckDAAdmissionPlanLocked(member, plan); done {
		return result, err
	}
	return s.installDAAdmissionPlanLocked(admission, member, plan)
}

// recheckDAAdmissionPlanLocked is the duplicate/first-seen and plan-currency
// half. done=true means the admission is decided here: a peer-neutral DUPLICATE,
// the conflict-bearing DUPLICATE, the transient stale-plan refusal, or the
// candidate refusal the plan carried.
func (s *DARelayState) recheckDAAdmissionPlanLocked(member daRelayAdmissionMember, plan daRelayAdmissionPlan) (DAAdmissionResult, bool, error) {
	result := DAAdmissionResult{DAID: member.locator.daID}
	if _, duplicate := s.locators[member.identity().txid]; duplicate {
		result.Disposition = DAAdmissionDuplicate
		return result, true, nil
	}
	if s.sets[member.locator.daID].revision != plan.baseline {
		return DAAdmissionResult{}, true, selectRelayDisposition(txAdmitUnavailable("retained DA record moved while this admission was planned"), RelayAdmissionUnavailable)
	}
	if plan.stageErr == nil {
		return DAAdmissionResult{}, false, nil
	}
	if errors.Is(plan.stageErr, errDARelayDuplicateCommit) && member.locator.kind == daRelayLocatorCommit {
		result.Disposition = DAAdmissionDuplicate
		// The arm's "different txid" claim is proven against the LIVE record under
		// this lock: a corrupt state that lost the locator row while the SAME
		// commit stays staged is a plain peer-neutral duplicate, not the conflict.
		result.SameDAIDCommitConflict = s.sets[member.locator.daID].commit.txid != member.identity().txid
		return result, true, nil
	}
	return DAAdmissionResult{}, true, plan.stageErr
}

// installDAAdmissionPlanLocked is the sequence and bounds recheck, the owner
// reserve, and then the writes. Everything fallible precedes the FIRST of them.
func (s *DARelayState) installDAAdmissionPlanLocked(admission *DAAdmission, member daRelayAdmissionMember, plan daRelayAdmissionPlan) (DAAdmissionResult, error) {
	record := plan.staged.record
	// The accepted-sequence RECHECK, in advanceAcceptedSequenceLocked's own
	// semantics but without its write: one value per accepted member, the record
	// keeps its FIRST member's stamp, and an exhausted space fails closed here
	// with the high-water untouched.
	sequence, err := checkedAddUint64(s.nextReceivedTime, 1)
	if err != nil {
		return DAAdmissionResult{}, err
	}
	if record.receivedTime == 0 {
		record.receivedTime = sequence
	}
	// The plan's image, not a fresh derivation: the recheck above proved the live
	// record still IS the one the image was derived from, and neither the token
	// write nor the sequence stamp changes a locator row or an accounting value.
	placement, err := s.projectDARecordImageLocked(member.locator.daID, plan.image)
	if err != nil {
		return DAAdmissionResult{}, err
	}
	commit, err := admission.BeginCommit(plan.victims)
	if err != nil {
		return DAAdmissionResult{}, err
	}
	record.installMemberToken(member.locator, commit.CandidateToken())
	s.nextReceivedTime = sequence
	s.installDASetRecordLocked(record, placement)
	commit.Commit()
	return DAAdmissionResult{DAID: member.locator.daID, Disposition: DAAdmissionRetained}, nil
}

// installMemberToken writes the finalized candidate token into the member slot
// staging already created: assignment into present keys, no allocation, no
// failure. Aliasing invariant: the receiver is the PLAN's own record and its
// chunks map is the fresh copy the pure staging's cloneForStateMutation made —
// never the live image's — so the write cannot reach live state before
// installDASetRecordLocked.
func (r *daRelaySetRecord) installMemberToken(locator daRelayLocator, token PendingOutpointToken) {
	if locator.kind == daRelayLocatorCommit {
		r.commit.token = token
		return
	}
	chunk := r.chunks[locator.chunkIndex]
	chunk.token = token
	r.chunks[locator.chunkIndex] = chunk
}

func (m daRelayAdmissionMember) identity() daRelayMemberIdentity {
	if m.locator.kind == daRelayLocatorCommit {
		return m.commit.daRelayMemberIdentity
	}
	return m.chunk.daRelayMemberIdentity
}

// daRelayAdmissionMemberOf renders one OWNER-ISSUED admission as the retained
// member it becomes. Every retained field except the token and the locator comes
// from the admission of the transaction actually validated — its bytes, txid,
// wtxid, fee, retained size and ordered inputs — so nothing a caller supplied
// can become part of a retained member.
//
// It CONSUMES the admission's own canonical parse and never re-parses the
// bytes: this candidate is parsed exactly once per admission (R9). The
// self-consistency the former re-parse asserted is structural instead — the
// admission builds tx, TxBytes, TxID, WTxID and RetainedBytes from ONE
// consensus.ParseTx of one byte string (validateDACandidate) — and a caller may
// not supply a transaction, because the parse authority stays inside the owner.
func daRelayAdmissionMemberOf(admission *DAAdmission, provenance DAProvenance) (daRelayAdmissionMember, error) {
	snapshot, tx := admission.Snapshot(), admission.parsedTx()
	identity := daRelayMemberIdentity{
		txid:          snapshot.TxID,
		wtxid:         snapshot.WTxID,
		fee:           snapshot.Fee,
		retainedBytes: snapshot.RetainedBytes,
		inputs:        snapshot.Inputs,
		provenance:    provenance,
	}
	if tx.TxKind == 0x01 {
		return daRelayAdmissionCommitOf(tx, identity, snapshot.TxBytes)
	}
	return daRelayAdmissionChunkOf(tx, identity, snapshot.TxBytes)
}

func daRelayAdmissionCommitOf(tx *consensus.Tx, identity daRelayMemberIdentity, raw []byte) (daRelayAdmissionMember, error) {
	commitment, ok := daCommitPayloadCommitment(tx)
	if !ok {
		return daRelayAdmissionMember{}, txAdmitRejected("DA commit does not carry exactly one 32-byte payload commitment output")
	}
	return daRelayAdmissionMember{
		locator: daRelayLocator{daID: tx.DaCommitCore.DaID, kind: daRelayLocatorCommit},
		commit: daRelayCommit{
			daRelayMemberIdentity: identity,
			daID:                  tx.DaCommitCore.DaID,
			payloadCommitment:     commitment,
			peerQuotaKey:          identity.provenance.quotaKey(),
			chunkCount:            tx.DaCommitCore.ChunkCount,
			wireBytes:             identity.retainedBytes,
			txBytes:               raw,
		},
	}, nil
}

func daRelayAdmissionChunkOf(tx *consensus.Tx, identity daRelayMemberIdentity, raw []byte) (daRelayAdmissionMember, error) {
	chunk := daRelayChunk{
		daRelayMemberIdentity: identity,
		daID:                  tx.DaChunkCore.DaID,
		chunkHash:             tx.DaChunkCore.ChunkHash,
		peerQuotaKey:          identity.provenance.quotaKey(),
		chunkIndex:            tx.DaChunkCore.ChunkIndex,
		payload:               tx.DaPayload,
		wireBytes:             identity.retainedBytes,
		txBytes:               raw,
		// parseDAAdmission already proved sha3-256(DaPayload) == ChunkHash for
		// exactly these bytes; rehashing here would be a second authority on the
		// same fact.
		hashChecked: true,
	}
	payload, err := prepareDAChunkPayload(chunk)
	if err != nil {
		return daRelayAdmissionMember{}, err
	}
	chunk.payload = payload
	return daRelayAdmissionMember{
		locator: daRelayLocator{daID: chunk.daID, kind: daRelayLocatorChunk, chunkIndex: chunk.chunkIndex},
		chunk:   chunk,
	}, nil
}

// daCommitPayloadCommitment reads the single COV_TYPE_DA_COMMIT output that
// carries the set's payload commitment. Exactly one such 32-byte output must be
// present; zero, several, or a wrong-width one is not a usable commit.
func daCommitPayloadCommitment(tx *consensus.Tx) ([32]byte, bool) {
	var commitment [32]byte
	count := 0
	for _, output := range tx.Outputs {
		if output.CovenantType != consensus.COV_TYPE_DA_COMMIT {
			continue
		}
		if len(output.CovenantData) != len(commitment) {
			return [32]byte{}, false
		}
		count++
		copy(commitment[:], output.CovenantData)
	}
	return commitment, count == 1
}

// appendDAMemberVictims turns removed members into exact owner victim
// descriptors, naming every claim by its exact token and never by outpoint.
//
// A ZERO token means the member owns NO claim, and whether that is possible is a
// property of the RELAY: an UNBOUND relay has no owner, beginRetainedDARemoval
// returns no guard and no claim can exist, so the member is legitimately skipped.
// On a BOUND relay every retained member holds its finalized claim, so a zero
// token is missing token evidence for a claim that DOES exist and removing the
// record around it would orphan that claim. It fails closed, before publication.
func (s *DARelayState) appendDAMemberVictims(victims []DAAdmissionVictim, members []daRelayMemberIdentity) ([]DAAdmissionVictim, error) {
	for _, member := range members {
		if member.token == (PendingOutpointToken{}) {
			if s.ownerBound() {
				return nil, fmt.Errorf("retained DA member %x of a bound relay carries no owner token", member.txid)
			}
			continue
		}
		victims = append(victims, DAAdmissionVictim{TxID: member.txid, Inputs: member.inputs, Token: member.token})
	}
	return victims, nil
}

// AdvanceOrphanTTL advances the retained incomplete-set TTL once, removing every
// set whose last block expired together with all of its member claims.
func (s *DARelayState) AdvanceOrphanTTL() error {
	if s == nil {
		return nil
	}
	return s.commitRetainedDARemoval((*DARelayState).advanceOrphanTTLLocked)
}

// ReleasePeerQuotaKey releases the incomplete retained data owned by one peer
// quota identity. The caller holds that key's per-key peer quota lock, which
// stays OUTERMOST; the admission guard and DARelayState.mu are taken inside it.
//
// The zero-victim scan is advisory and fully RELEASES DARelayState.mu before the
// removal guard is begun: holding it across BeginDARemoval would invert the
// canonical transition's admissionMu-then-DARelayState.mu order.
func (s *DARelayState) ReleasePeerQuotaKey(key string) error {
	if s == nil || !s.hasPeerQuotaBytes(key) {
		return nil
	}
	return s.commitRetainedDARemoval(func(projected *DARelayState) ([]DAAdmissionVictim, error) {
		return projected.releasePeerQuotaKeyLocked(key)
	})
}

func (s *DARelayState) hasPeerQuotaBytes(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.orphanBytesByPeerQuotaKey[key] != 0
}

// commitRetainedDARemoval is the shared owner-atomic removal sequence: one
// removal guard (the sole admissionMu.R acquisition), then DARelayState.mu, the
// complete projection, then the owner LAST inside BeginCommit; publication and
// Commit are non-fallible in that one owner hold. A removal that selects NO
// claim never calls BeginCommit — an empty victim batch with no candidate is a
// malformed owner request — and publishes its ownerless projection alone (a TTL
// decrement is exactly such a change).
func (s *DARelayState) commitRetainedDARemoval(plan func(*DARelayState) ([]DAAdmissionVictim, error)) error {
	removal, err := s.beginRetainedDARemoval()
	if err != nil {
		return err
	}
	if removal != nil {
		defer removal.Close()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	projected := s.cloneForAtomicBatchLocked()
	victims, err := plan(projected)
	if err != nil {
		return err
	}
	if removal == nil || len(victims) == 0 {
		s.publishAtomicBatchLocked(projected)
		return nil
	}
	commit, err := removal.BeginCommit(victims)
	if err != nil {
		return err
	}
	s.publishAtomicBatchLocked(projected)
	commit.Commit()
	return nil
}

// ownerBound reports whether this relay is coupled to a pending-outpoint owner.
// It is the ONE boundness predicate: the removal guard and the victim assembly
// must agree about whether a claim can exist at all, and a projection carries
// the same mempool pointer as the image it was cloned from.
func (s *DARelayState) ownerBound() bool {
	return s.mempool != nil && s.mempool.chainState != nil && s.mempool.pendingOutpoints != nil
}

// beginRetainedDARemoval returns the removal guard, or (nil, nil) for an UNBOUND
// relay — no mempool, no chainstate, or no owner, which is the test-only
// construction lockAdmissionFence documents. An unbound relay has no owner to
// couple to and therefore no claim to remove.
func (s *DARelayState) beginRetainedDARemoval() (*DARemoval, error) {
	if !s.ownerBound() {
		return nil, nil
	}
	return s.mempool.BeginDARemoval()
}

// daRetainedObservation is ONE atomic raw acquisition for one candidate txid,
// copied in a single DARelayState.mu window. It is the shared raw-observation
// shape of the two retained-evidence consumers — read-only LookupRetainedTx and
// AdmitDA's duplicate-classification shortcut, which decides an admission
// VERDICT. Both run the same off-lock validator over the copy BEFORE any
// consumer-specific decision, so the two cannot disagree about what
// "integrity-valid retained member" means, and neither holds the DA lock across
// parsing or validation (RUBIN_COMPACT_BLOCKS.md Sections 5.1 and 17.5).
//
// raw is a defensive copy taken under the lock: it is the observation's only
// retained byte store, it cannot alias the live image, and no consumer re-reads
// live state after the window closes.
type daRetainedObservation struct {
	located          bool
	locator          daRelayLocator
	recordPresent    bool
	recordDAID       [32]byte
	recordState      daRelaySetState
	commitChunkCount uint16
	memberPresent    bool
	member           daRelayMemberIdentity
	raw              []byte
}

// observeRetainedTxLocked copies the complete evidence for txid: locator
// presence, record presence, identity and STATE, the located member's identity,
// and the exact retained raw bytes. It validates nothing — validation is the
// off-lock half — and copies nothing twice.
func (s *DARelayState) observeRetainedTxLocked(txid [32]byte) daRetainedObservation {
	locator, located := s.locators[txid]
	if !located {
		return daRetainedObservation{}
	}
	observation := daRetainedObservation{located: true, locator: locator}
	record, ok := s.sets[locator.daID]
	if !ok {
		return observation
	}
	observation.recordPresent = true
	observation.recordDAID = record.daID
	observation.recordState = record.state
	observation.commitChunkCount = record.commit.chunkCount
	member, raw, ok := retainedDAMemberAt(record, locator)
	if !ok {
		return observation
	}
	observation.memberPresent = true
	observation.member = member
	observation.raw = cloneBytes(raw)
	return observation
}

// validate is the shared off-lock retained-evidence validator: it proves the
// copied bytes still ARE the located member — a canonical FULL-CONSUMPTION
// parse, the exact indexed txid and stored admission-time wtxid, and the DA
// role, da_id and index the locator claims. Every failure is a PLAIN error:
// this is a read-only path and its INTERNAL never carries the
// canonical-transition terminal type (the role checks it reuses wrap one, so
// their failures are re-rendered as plain text here). It reruns NO consensus,
// fee, capacity or policy check and repairs nothing.
func (o daRetainedObservation) validate(txid [32]byte) (DARetainedTxSnapshot, error) {
	if err := o.checkLocatedCoherence(txid); err != nil {
		return DARetainedTxSnapshot{}, err
	}
	tx, parsedTxID, parsedWTxID, consumed, err := consensus.ParseTx(o.raw)
	if err != nil {
		return DARetainedTxSnapshot{}, fmt.Errorf("retained DA member %x does not canonically parse: %w", o.member.txid, err)
	}
	if consumed != len(o.raw) || parsedTxID != o.member.txid || parsedWTxID != o.member.wtxid {
		return DARetainedTxSnapshot{}, fmt.Errorf("retained DA member %x contradicts its retained bytes", o.member.txid)
	}
	if err := o.checkRole(tx); err != nil {
		return DARetainedTxSnapshot{}, err
	}
	return DARetainedTxSnapshot{TxID: o.member.txid, WTxID: o.member.wtxid, TxBytes: o.raw}, nil
}

// checkLocatedCoherence is validate's coherence phase over the located copy: the
// locator's own shape, then its resolution inside the copy to its own record and
// member, then the member's retained bytes, then the record's shape.
func (o daRetainedObservation) checkLocatedCoherence(txid [32]byte) error {
	if err := o.checkLocatorShape(txid); err != nil {
		return err
	}
	if !o.recordPresent || o.recordDAID != o.locator.daID {
		return fmt.Errorf("retained DA locator for %x names absent record %x", txid, o.locator.daID)
	}
	if !o.memberPresent || o.member.txid != txid {
		return fmt.Errorf("retained DA locator for %x does not resolve to its own member", txid)
	}
	if len(o.raw) == 0 {
		return fmt.Errorf("retained DA member %x has no retained transaction bytes", o.member.txid)
	}
	return o.checkRecordShape(txid)
}

// checkLocatorShape refuses a locator that is not a member of the CLOSED kind
// set, and a commit locator carrying a chunk index — a contradiction, since a
// record holds exactly one commit slot and it has no index. Both take the
// located-inconsistency lane; neither may ever be read as "some chunk".
func (o daRetainedObservation) checkLocatorShape(txid [32]byte) error {
	switch o.locator.kind {
	case daRelayLocatorCommit:
		if o.locator.chunkIndex != 0 {
			return fmt.Errorf("retained DA commit locator for %x carries chunk index %d", txid, o.locator.chunkIndex)
		}
	case daRelayLocatorChunk:
	default:
		return fmt.Errorf("retained DA locator for %x names member kind %d", txid, o.locator.kind)
	}
	return nil
}

// checkRecordShape refuses a record whose STATE is not a member of the closed
// set at all, and then one whose state contradicts its own membership:
// ORPHAN_CHUNKS is exactly the state that holds no commit, so a State A record
// carrying one — or a staged/complete record carrying none — is corrupt, and a
// replay against it is not an "integrity-valid exact retained replay".
//
// The membership refusal is not implied by the pairwise one: an out-of-set state
// is not ORPHAN_CHUNKS, so one carrying a commit satisfies the pair and would
// otherwise answer OWNED_DA, and DUPLICATE to an exact replay.
func (o daRetainedObservation) checkRecordShape(txid [32]byte) error {
	if !o.recordState.valid() {
		return fmt.Errorf("retained DA record for %x holds state %d outside the closed set", txid, o.recordState)
	}
	if (o.recordState == daRelayStateOrphanChunks) != (o.commitChunkCount == 0) {
		return fmt.Errorf("retained DA record for %x is state %d with chunk_count %d", txid, o.recordState, o.commitChunkCount)
	}
	return nil
}

// checkRole applies the locator's role/identity claims to the parsed copy. It
// reuses the canonical transition's own role checkers over a record view built
// from the copied fields, then strips their transition-terminal carrier: the
// CHECK is one shared authority, the ERROR CLASS is the caller's.
func (o daRetainedObservation) checkRole(tx *consensus.Tx) error {
	var err error
	switch o.locator.kind {
	case daRelayLocatorCommit:
		err = checkRetainedDACommitRole(tx, daRelaySetRecord{daID: o.recordDAID, commit: daRelayCommit{chunkCount: o.commitChunkCount}})
	case daRelayLocatorChunk:
		err = checkRetainedDAChunkRole(tx, o.recordDAID, o.locator.chunkIndex)
	default:
		// checkLocatorShape already refused this kind; the arm exists so the
		// closed set has no silent fallthrough if the two ever drift.
		return fmt.Errorf("retained DA member %x names member kind %d", o.member.txid, o.locator.kind)
	}
	var terminal *canonicalDATerminalError
	if errors.As(err, &terminal) {
		return errors.New(terminal.detail)
	}
	return err
}

// LookupRetainedTx is the READ-ONLY retained-DA observation RUB-1169 consumes.
// It is tri-state and never repairs:
//
//	(snapshot, true,  nil)     OWNED_DA  — the exact retained member
//	(zero,     false, nil)     ABSENT_DA — no locator for this txid
//	(zero,     false, non-nil) INTERNAL  — a located member that contradicts itself
//
// A DANGLING or CONTRADICTORY locator is INTERNAL, deliberately never absence: a
// txid the index claims to hold and cannot produce is a retained-state invariant
// violation, and reporting it as "not retained" would let the caller announce
// around it. The INTERNAL error is a plain error, never the canonical-transition
// terminal type: a lookup cannot fabricate a canonical-transition terminal. The
// returned TxBytes are the observation's defensive copy, so a caller that
// mutates them cannot reach the retained image.
//
// It holds DARelayState.mu only for the copy, reruns NO consensus or policy
// check and performs no network action.
func (s *DARelayState) LookupRetainedTx(txid [32]byte) (DARetainedTxSnapshot, bool, error) {
	if s == nil {
		return DARetainedTxSnapshot{}, false, nil
	}
	observation := func() daRetainedObservation {
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.observeRetainedTxLocked(txid)
	}()
	if !observation.located {
		return DARetainedTxSnapshot{}, false, nil
	}
	snapshot, err := observation.validate(txid)
	if err != nil {
		return DARetainedTxSnapshot{}, false, err
	}
	return snapshot, true, nil
}

// retainedDAMemberAt resolves one locator to its member identity and exact
// retained bytes inside record. The kind switch is EXACT over the closed set: a
// locator outside it resolves to nothing rather than defaulting to a chunk slot,
// so a corrupt index can never make LookupRetainedTx answer owned=true.
func retainedDAMemberAt(record daRelaySetRecord, locator daRelayLocator) (daRelayMemberIdentity, []byte, bool) {
	switch locator.kind {
	case daRelayLocatorCommit:
		if record.commit.chunkCount == 0 || locator.chunkIndex != 0 {
			return daRelayMemberIdentity{}, nil, false
		}
		return record.commit.daRelayMemberIdentity, record.commit.txBytes, true
	case daRelayLocatorChunk:
		chunk, ok := record.chunks[locator.chunkIndex]
		if !ok {
			return daRelayMemberIdentity{}, nil, false
		}
		return chunk.daRelayMemberIdentity, chunk.txBytes, true
	default:
		return daRelayMemberIdentity{}, nil, false
	}
}
