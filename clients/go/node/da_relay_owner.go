package node

import (
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
	// DAAdmissionDuplicate is a REJECTED no-mutation result: the member was
	// already retained, so nothing reserved, nothing was removed, and no
	// accepted-sequence value was consumed.
	DAAdmissionDuplicate DAAdmissionDisposition = 2
)

// DAAdmissionResult reports which set the admission concerned and how it ended.
type DAAdmissionResult struct {
	DAID        [32]byte
	Disposition DAAdmissionDisposition
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
// Order, and it is the whole safety argument:
//
//  1. provenance is validated first, so an invalid source never reaches the
//     owner, the admission guard or any state;
//  2. BeginDAAdmission is the SOLE ChainState.admissionMu.R acquisition on this
//     path — it holds that guard for its whole life, sync.RWMutex is not
//     reentrant, and nothing below may take it again;
//  3. every allocation, parse, provenance, locator, record, accounting and
//     sequence decision happens BEFORE the owner is touched, on a PRIVATE clone
//     of the retained image;
//  4. DAAdmission.BeginCommit acquires PendingOutpointOwner.mu LAST and holds it
//     into the returned DACommit, so the token write, the complete D publication
//     and Commit all run inside one owner hold with no fallible step between
//     them.
//
// A failure before step 4 leaves D, the locator index and the owner
// byte-identical. There is deliberately NO Abort call: after BeginCommit
// succeeds the remaining work is a token assignment into an already-present map
// slot and two pointer publications, none of which can fail, so no schedule
// exists that acquires a candidate token and then declines to finalize it.
//
// AdmitDA is SYNCHRONOUS by contract: it performs no network action and never
// waits, because it holds the admission read guard for its whole duration.
func (s *DARelayState) AdmitDA(txBytes []byte, provenance DAProvenance) (DAAdmissionResult, error) {
	if s == nil || s.mempool == nil {
		return DAAdmissionResult{}, txAdmitUnavailable("no DA relay state bound")
	}
	if err := provenance.validate(); err != nil {
		return DAAdmissionResult{}, err
	}
	admission, err := s.mempool.BeginDAAdmission(txBytes)
	if err != nil {
		return DAAdmissionResult{}, err
	}
	defer admission.Close()
	member, err := daRelayAdmissionMemberOf(admission.Snapshot(), provenance)
	if err != nil {
		return DAAdmissionResult{}, err
	}
	return s.commitDAAdmission(admission, member)
}

// commitDAAdmission is AdmitDA's final DA lock. It rechecks the duplicate
// against the LIVE locator index, projects the complete new image, and only then
// reaches the owner.
func (s *DARelayState) commitDAAdmission(admission *DAAdmission, member daRelayAdmissionMember) (DAAdmissionResult, error) {
	result := DAAdmissionResult{DAID: member.locator.daID}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, duplicate := s.locators[member.identity().txid]; duplicate {
		result.Disposition = DAAdmissionDuplicate
		return result, nil
	}
	projected := s.cloneForAtomicBatchLocked()
	dropped, err := projected.stageDAMemberLocked(member)
	if err != nil {
		return DAAdmissionResult{}, err
	}
	commit, err := admission.BeginCommit(appendDAMemberVictims(nil, dropped))
	if err != nil {
		return DAAdmissionResult{}, err
	}
	projected.installMemberTokenLocked(member.locator, commit.CandidateToken())
	s.publishAtomicBatchLocked(projected)
	commit.Commit()
	result.Disposition = DAAdmissionRetained
	return result, nil
}

func (s *DARelayState) stageDAMemberLocked(member daRelayAdmissionMember) ([]daRelayMemberIdentity, error) {
	if member.locator.kind == daRelayLocatorCommit {
		return s.stageDACommitLocked(member.commit)
	}
	return s.stageDAChunkLocked(member.chunk)
}

// installMemberTokenLocked writes the finalized candidate token into the member
// slot staging already created. The record and the chunk map entry both exist,
// so this is assignment into present keys: no allocation, no failure.
func (s *DARelayState) installMemberTokenLocked(locator daRelayLocator, token PendingOutpointToken) {
	record := s.sets[locator.daID]
	if locator.kind == daRelayLocatorCommit {
		record.commit.token = token
	} else {
		chunk := record.chunks[locator.chunkIndex]
		chunk.token = token
		record.chunks[locator.chunkIndex] = chunk
	}
	s.sets[locator.daID] = record
}

func (m daRelayAdmissionMember) identity() daRelayMemberIdentity {
	if m.locator.kind == daRelayLocatorCommit {
		return m.commit.daRelayMemberIdentity
	}
	return m.chunk.daRelayMemberIdentity
}

// daRelayAdmissionMemberOf renders one DAAdmissionSnapshot as the retained
// member it becomes. Every retained field except the token and the locator comes
// from the snapshot of the transaction admission actually validated — the bytes,
// txid, wtxid, fee, retained size and ordered inputs — so nothing a caller
// supplied can become part of a retained member.
func daRelayAdmissionMemberOf(snapshot DAAdmissionSnapshot, provenance DAProvenance) (daRelayAdmissionMember, error) {
	tx, txid, wtxid, err := parseRelayMetadataTx(snapshot.TxBytes)
	if err != nil {
		return daRelayAdmissionMember{}, err
	}
	if txid != snapshot.TxID || wtxid != snapshot.WTxID || snapshot.RetainedBytes != uint64(len(snapshot.TxBytes)) {
		return daRelayAdmissionMember{}, txAdmitUnavailable("DA admission snapshot contradicts its own retained bytes")
	}
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
// descriptors. A member with a ZERO token owns no claim — the unbound-relay and
// package-private staging construction — and contributes no victim; nothing here
// ever names a claim by outpoint.
func appendDAMemberVictims(victims []DAAdmissionVictim, members []daRelayMemberIdentity) []DAAdmissionVictim {
	for _, member := range members {
		if member.token == (PendingOutpointToken{}) {
			continue
		}
		victims = append(victims, DAAdmissionVictim{TxID: member.txid, Inputs: member.inputs, Token: member.token})
	}
	return victims
}

// AdvanceOrphanTTL advances the retained incomplete-set TTL once, removing every
// set whose last block expired together with all of its member claims.
func (s *DARelayState) AdvanceOrphanTTL() error {
	if s == nil {
		return nil
	}
	return s.commitRetainedDARemoval(func(projected *DARelayState) ([]DAAdmissionVictim, error) {
		_, victims, err := projected.advanceOrphanTTLLocked()
		return victims, err
	})
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
// removal guard (the sole admissionMu.R acquisition), then DARelayState.mu, then
// the complete projection, then the owner LAST inside BeginCommit. Publication
// and Commit are non-fallible and run in that one owner hold.
//
// A removal that selects NO claim never calls BeginCommit — an empty victim
// batch with no candidate is a malformed owner request — and publishes its
// projection alone. That projection can still differ from the live image (a TTL
// decrement is exactly such a change) and it touches no owner claim, so nothing
// is left uncoupled.
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

// beginRetainedDARemoval returns the removal guard, or (nil, nil) for an UNBOUND
// relay — no mempool, no chainstate, or no owner, which is the test-only
// construction lockAdmissionFence documents. An unbound relay has no owner to
// couple to and therefore no claim to remove.
func (s *DARelayState) beginRetainedDARemoval() (*DARemoval, error) {
	if s.mempool == nil || s.mempool.chainState == nil || s.mempool.pendingOutpoints == nil {
		return nil, nil
	}
	return s.mempool.BeginDARemoval()
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
// around it. The returned TxBytes are a defensive copy, so a caller that mutates
// them cannot reach the retained image.
//
// It reruns NO consensus or policy check and performs no network action: the
// bytes were validated by the admission that retained them, and this proves only
// that the retained member still IS that member.
func (s *DARelayState) LookupRetainedTx(txid [32]byte) (DARetainedTxSnapshot, bool, error) {
	if s == nil {
		return DARetainedTxSnapshot{}, false, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lookupRetainedTxLocked(txid)
}

func (s *DARelayState) lookupRetainedTxLocked(txid [32]byte) (DARetainedTxSnapshot, bool, error) {
	locator, located := s.locators[txid]
	if !located {
		return DARetainedTxSnapshot{}, false, nil
	}
	record, ok := s.sets[locator.daID]
	if !ok || record.daID != locator.daID {
		return DARetainedTxSnapshot{}, false, fmt.Errorf("retained DA locator for %x names absent record %x", txid, locator.daID)
	}
	member, raw, ok := retainedDAMemberAt(record, locator)
	if !ok || member.txid != txid {
		return DARetainedTxSnapshot{}, false, fmt.Errorf("retained DA locator for %x does not resolve to its own member", txid)
	}
	if err := checkRetainedDAMemberIdentity(record, locator, member, raw); err != nil {
		return DARetainedTxSnapshot{}, false, err
	}
	return DARetainedTxSnapshot{TxID: member.txid, WTxID: member.wtxid, TxBytes: cloneBytes(raw)}, true, nil
}

// retainedDAMemberAt resolves one locator to its member identity and exact
// retained bytes inside record.
func retainedDAMemberAt(record daRelaySetRecord, locator daRelayLocator) (daRelayMemberIdentity, []byte, bool) {
	if locator.kind == daRelayLocatorCommit {
		if record.commit.chunkCount == 0 {
			return daRelayMemberIdentity{}, nil, false
		}
		return record.commit.daRelayMemberIdentity, record.commit.txBytes, true
	}
	chunk, ok := record.chunks[locator.chunkIndex]
	if !ok {
		return daRelayMemberIdentity{}, nil, false
	}
	return chunk.daRelayMemberIdentity, chunk.txBytes, true
}

// checkRetainedDAMemberIdentity proves the retained bytes still ARE this member:
// a canonical FULL-CONSUMPTION parse, the exact txid and wtxid the member
// recorded, and the DA role and index the locator claims.
func checkRetainedDAMemberIdentity(record daRelaySetRecord, locator daRelayLocator, member daRelayMemberIdentity, raw []byte) error {
	if len(raw) == 0 {
		return fmt.Errorf("retained DA member %x has no retained transaction bytes", member.txid)
	}
	tx, txid, wtxid, consumed, err := consensus.ParseTx(raw)
	if err != nil {
		return fmt.Errorf("retained DA member %x does not canonically parse: %w", member.txid, err)
	}
	if consumed != len(raw) || txid != member.txid || wtxid != member.wtxid {
		return fmt.Errorf("retained DA member %x contradicts its retained bytes", member.txid)
	}
	if locator.kind == daRelayLocatorCommit {
		return checkRetainedDACommitRole(tx, record)
	}
	return checkRetainedDAChunkRole(tx, record.daID, locator.chunkIndex)
}
