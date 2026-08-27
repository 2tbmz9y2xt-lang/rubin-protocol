package node

import (
	"bytes"
	"fmt"
	"maps"
	"slices"
	"sort"
)

// canonicalDATerminalError is Section 6.4.1's TERMINAL_LOCAL_INVARIANT(evidence)
// for retained DA state: a missing or corrupt selected member, a retained field
// that contradicts its own record, or a checked arithmetic failure while
// projecting the new image. It preserves OLD, publishes nothing, and keeps
// mutation admission latched, exactly like the standard/owner terminal class it
// sits beside — and it is deliberately a DISTINCT type so the operator record
// names retained DA rather than the standard mempool.
type canonicalDATerminalError struct{ detail string }

func (e *canonicalDATerminalError) Error() string {
	return "canonical retained-DA invariant: " + e.detail
}

func terminalCanonicalDAError(err error) error {
	return &canonicalDATerminalError{detail: err.Error()}
}

// preparedCanonicalDAImage is the complete D1 image, projected under the
// transition's admission write fence and published later by assignment only.
//
// It clones the relay's metadata and maps through the existing
// cloneForAtomicBatchLocked idiom and SHARES every surviving record's immutable
// retained TxBytes and payload bytes: the projection only deletes map entries, so
// no retained payload is duplicated and the image is O(records), not O(bytes).
type preparedCanonicalDAImage struct {
	relay     *DARelayState
	projected *DARelayState
}

// canonicalDAClaimProjection is the O1 half of D preparation: the exact DA claim
// tokens the selected removals retire. It names TOKENS, never outpoints, because
// the token is the only identity that survives an ABA reuse of the same outpoint
// by a later claim.
type canonicalDAClaimProjection struct {
	dropped map[PendingOutpointToken]struct{}
}

// prepareCanonicalDAImage derives D1: the retained DA image with every record
// removed that either has a member which is not final_chain_valid against C1, or
// whose exact set identity occurs in the newly canonical inclusion list. The two
// causes form ONE record union, so a record matched by both is removed once.
//
// It runs under the transition's ChainState admission WRITE fence, so the live
// image it reads cannot move before publication; of the LIVE state it takes only
// DARelayState.mu and never the admission guard itself, which is neither
// reentrant nor available to it. Member validation additionally RLocks the
// PRIVATE final image's ChainState.mu through admissionSnapshotForInputs — that
// clone is transition-owned and its mutex never becomes the live one.
//
// Everything fallible happens HERE: parsing, validation, every checked
// accounting projection, and the whole-image accounting sweep that follows the
// removals (checkRetainedDAAccountingLocked). Publication is assignment only.
//
// Cost, accepted deliberately: every retained member is validated against C1 on
// every canonical transition, including the later members of a record already
// destined for removal. That is what makes "D1 is independently derived from
// full validation of every retained member" a statement about the code rather
// than about the common case. The shared caches absorb exactly the SIGNATURE
// verification and the per-height rotation observation; the canonical RE-PARSE
// of every member's bytes and the rest of its consensus check are paid again on
// every transition. A cap on retained members is RUB-1118's, not this slice's.
//
// The third phase is the CLAIM phase, and it runs against the SAME live image
// and the SAME private O1 candidate the M/O half prepared: every live DA member
// must correspond to exactly one finalized DA claim in that candidate, no DA
// claim may be left over, and the claims of the selected removals are then
// retired from the candidate. Any extra, missing, duplicate, foreign,
// unfinalized, wrong-domain, txid-, input-, token-, locator- or
// record-mismatched claim is TERMINAL_LOCAL_INVARIANT here, BEFORE the durable
// commit, so OLD and every live image stay exactly as they were and admission
// stays latched.
//
// It NEVER calls BeginDARemoval: that guard takes admissionMu.R and the
// transition already holds the same lock exclusively. It adds no callback and no
// second owner publisher — publishCanonicalMempoolPlan remains the ONLY O1
// publisher, and the claim retirement is an edit of the candidate it will
// publish.
func prepareCanonicalDAImage(relay *DARelayState, included []canonicalDASetIdentity, chain canonicalFinalChainContext, mo *canonicalMempoolPlan) (*preparedCanonicalDAImage, error) {
	if relay == nil {
		return nil, nil //nolint:nilnil // nil image, nil error = engine with no retained-DA state bound; publish() documents the nil no-op
	}
	relay.mu.Lock()
	defer relay.mu.Unlock()
	removals, err := relay.canonicalDARemovalsLocked(included, chain)
	if err != nil {
		return nil, err
	}
	projection, err := relay.canonicalDAClaimProjectionLocked(removals, mo)
	if err != nil {
		return nil, err
	}
	projected := relay.cloneForAtomicBatchLocked()
	for _, record := range removals {
		// ...Locked names the clone's own invariant, not a second lock: projected
		// is single-owner private state until publish.
		if err := projected.removeDASetRecordLocked(record); err != nil {
			return nil, terminalCanonicalDAError(err)
		}
	}
	if err := projected.checkRetainedDAAccountingLocked(); err != nil {
		return nil, err
	}
	mo.dropCanonicalDAClaims(projection)
	return &preparedCanonicalDAImage{relay: relay, projected: projected}, nil
}

// canonicalDAClaimProjectionLocked proves the retained-member/DA-claim bijection
// over the WHOLE live image and returns the tokens the removals retire. It
// mutates nothing: the caller applies the projection only after every removal
// has been projected without error.
//
// The quantifier is over the members PRESENT in each record, never over a
// record's DECLARED chunk range: an incomplete record legitimately holds a sparse
// member set, and demanding a claim for a member that was never admitted would
// latch a healthy node.
//
// The skip arm covers BOTH ownerless shapes — a nil mo (no standard/owner image
// was prepared at all) and a mo whose owner is nil (an engine that never bound a
// pending-outpoint owner): either way there is no claim domain to bind to and
// the phase is skipped rather than inventing one.
//
// bound is deliberately unhinted: its population is not derivable from any map length in hand.
func (s *DARelayState) canonicalDAClaimProjectionLocked(removals []daRelaySetRecord, mo *canonicalMempoolPlan) (canonicalDAClaimProjection, error) {
	if mo == nil || mo.owner == nil {
		return canonicalDAClaimProjection{}, nil
	}
	bound := make(map[PendingOutpointToken]struct{})
	for _, daID := range s.sortedRetainedDAIDsLocked() {
		for _, member := range s.sets[daID].members() {
			if err := checkCanonicalDAMemberClaim(daID, member, mo.ownerIndex, bound); err != nil {
				return canonicalDAClaimProjection{}, terminalCanonicalDAError(err)
			}
			bound[member.token] = struct{}{}
		}
	}
	if err := checkNoOrphanCanonicalDAClaims(mo.ownerIndex, bound); err != nil {
		return canonicalDAClaimProjection{}, terminalCanonicalDAError(err)
	}
	projection := canonicalDAClaimProjection{dropped: make(map[PendingOutpointToken]struct{})}
	for _, record := range removals {
		for _, member := range record.members() {
			projection.dropped[member.token] = struct{}{}
		}
	}
	return projection, nil
}

// checkCanonicalDAMemberClaim binds ONE retained member to EXACTLY ONE finalized
// DA claim of the candidate owner image: same token identity, DA domain,
// finalized phase, exact txid, exact ordered inputs, and a by-outpoint row for
// every one of those inputs naming the same token and txid. A token already
// bound to an earlier member is a duplicate and fails here.
func checkCanonicalDAMemberClaim(daID [32]byte, member daRelayMemberIdentity, index pendingOutpointIndex, bound map[PendingOutpointToken]struct{}) error {
	if _, duplicate := bound[member.token]; duplicate {
		return fmt.Errorf("retained DA member %x of set %x shares its owner claim with another member", member.txid, daID)
	}
	claim, err := index.claimForToken(member.token)
	if err != nil {
		return fmt.Errorf("retained DA member %x of set %x: %w", member.txid, daID, err)
	}
	if claim == nil {
		return fmt.Errorf("retained DA member %x of set %x has no live owner claim", member.txid, daID)
	}
	if claim.domain != PendingOutpointDA || claim.txid != member.txid || !claim.finalized {
		return fmt.Errorf("retained DA member %x of set %x holds a claim that is not its own finalized DA claim", member.txid, daID)
	}
	if err := index.checkClaimInputs(member.txid, member.inputs, claim, member.token); err != nil {
		return err
	}
	// checkClaimInputs binds each row by TOKEN, which is the standard domain's
	// question. A retained DA member additionally owns the row's TXID: a row that
	// carries this member's token under another transaction's identity is a
	// record-mismatched claim, and nothing else on this path would refuse it.
	for _, input := range member.inputs {
		if row := index.byOutpoint[input]; row.txid != member.txid {
			return fmt.Errorf("retained DA member %x of set %x holds an owner row naming %x", member.txid, daID, row.txid)
		}
	}
	return nil
}

// checkNoOrphanCanonicalDAClaims refuses a DA claim the retained image does not
// account for. The standard domain is deliberately untouched: it is
// validateRestoredClaimBinding's subject, not this phase's.
//
// The map is walked in full and the LOWEST token sequence is named, never the
// first key the runtime happens to hand out, so the same corrupt image yields the
// same evidence string on every run.
func checkNoOrphanCanonicalDAClaims(index pendingOutpointIndex, bound map[PendingOutpointToken]struct{}) error {
	var orphan *pendingOutpointClaim
	for token, claim := range index.byToken {
		if claim.domain != PendingOutpointDA {
			continue
		}
		if _, ok := bound[token]; ok {
			continue
		}
		if orphan == nil || token.seq < orphan.token.seq {
			orphan = claim
		}
	}
	if orphan == nil {
		return nil
	}
	return fmt.Errorf("owner holds DA claim for %x with no retained DA member", orphan.txid)
}

// dropCanonicalDAClaims retires the projected DA claims from the plan's PRIVATE
// O1 candidate. It edits BOTH halves the candidate publishes — the ordered claim
// list AND the rebuilt by-token/by-outpoint index pair — because
// publishRestoreLocked installs the MAPS: editing the list alone would retire
// nothing observable. The surviving claims are carried through UNCHANGED, same
// token, same generation, same phase, and the list keeps its raw order, which the
// live preflight consumes.
//
// It runs on the candidate only. The LIVE owner is not touched here and
// dropClaimLocked — which mutates live maps — is deliberately never used on this
// path.
func (p *canonicalMempoolPlan) dropCanonicalDAClaims(projection canonicalDAClaimProjection) {
	if p == nil || len(projection.dropped) == 0 {
		return
	}
	claims := make([]pendingOutpointClaim, 0, len(p.pending.claims))
	for _, claim := range p.pending.claims {
		if _, drop := projection.dropped[claim.token]; drop {
			continue
		}
		claims = append(claims, claim)
	}
	p.pending.claims = claims
	p.ownerIndex = buildCanonicalOwnerIndex(p.owner, p.pending)
}

// checkRetainedDAAccountingLocked is R3's accounting-invariant sweep over the
// WHOLE projected image, not only over the records the projection removed: the
// removal path checks its own arithmetic, but the clone copies every SURVIVING
// record's stored counters verbatim, so only this can catch one that contradicts
// the records it summarizes. It runs before the image is returned and therefore
// before anything is published.
//
// Independence is at the AGGREGATION layer only: the sweep deliberately reuses
// record.orphanAccounting and pinnedPayloadAccountingBytes — the same per-record
// billing the writers use — so the two cannot disagree about what a record
// contributes, only about whether the counters the writers carried forward still
// equal the sum over the surviving records. Any such disagreement is the finding,
// and the sweep never repairs, only refuses. The walk is by ascending raw da_id
// and every accumulation is checked, so the same corrupt image yields the same
// evidence string on every run and on every pointer width.
func (s *DARelayState) checkRetainedDAAccountingLocked() error {
	totals, err := s.recomputeRetainedDAAccountingLocked()
	if err != nil {
		return terminalCanonicalDAError(err)
	}
	if err := totals.checkAgainstLocked(s); err != nil {
		return terminalCanonicalDAError(err)
	}
	return nil
}

// retainedDAAccountingTotals is what the surviving records THEMSELVES imply for
// every RECOMPUTABLE stored aggregate: the five counters compared below —
// orphanBytes, orphanCommitOverheadBytes, pinnedPayloadBytes, and the per-peer
// and per-da_id maps — plus the map-key/record-da_id agreement checked in the
// walk. DARelayState.nextReceivedTime is stored by the same writers and is
// deliberately NOT here: it is a monotone high-water mark that removal never
// lowers, so it is not derivable from the surviving records at all.
//
// daIDEntries is a COUNT, not a rebuilt map: each per-da_id value is compared
// inside the walk where its da_id is already in hand, leaving only EXTRA stored
// entries to catch afterwards.
type retainedDAAccountingTotals struct {
	orphanBytes uint64
	commitBytes uint64
	pinnedBytes uint64
	peerBytes   map[string]uint64
	daIDEntries int
}

// recomputeRetainedDAAccountingLocked derives the totals from retained_tx(R) via
// the SAME per-record accounting the mutation path bills with, so the sweep and
// the writers cannot disagree about what a record contributes — only about what
// the counters say it contributed.
func (s *DARelayState) recomputeRetainedDAAccountingLocked() (retainedDAAccountingTotals, error) {
	totals := retainedDAAccountingTotals{peerBytes: map[string]uint64{}}
	for _, daID := range s.sortedRetainedDAIDsLocked() {
		record := s.sets[daID]
		if record.daID != daID {
			return totals, fmt.Errorf("retained DA record stored under da_id %x carries da_id %x", daID, record.daID)
		}
		accounting, err := record.orphanAccounting()
		if err != nil {
			return totals, err
		}
		if stored := s.orphanBytesByDAID[daID]; stored != accounting.orphanBytes {
			return totals, fmt.Errorf("per-da_id orphan bytes for %x: record implies %d, state holds %d", daID, accounting.orphanBytes, stored)
		}
		if accounting.orphanBytes != 0 {
			totals.daIDEntries++
		}
		if err := totals.add(accounting, record.pinnedPayloadAccountingBytes()); err != nil {
			return totals, err
		}
	}
	return totals, nil
}

// add accumulates one record with checked arithmetic. The per-peer map is walked
// in map order deliberately: every failure it can raise is the SHARED
// errDARelayArithmeticOverflow sentinel, which carries no key, so no evidence
// string depends on iteration order.
func (t *retainedDAAccountingTotals) add(accounting daRelayRecordAccounting, pinned uint64) error {
	var err error
	if t.orphanBytes, err = checkedAddUint64(t.orphanBytes, accounting.orphanBytes); err != nil {
		return err
	}
	if t.commitBytes, err = checkedAddUint64(t.commitBytes, accounting.commitBytes); err != nil {
		return err
	}
	if t.pinnedBytes, err = checkedAddUint64(t.pinnedBytes, pinned); err != nil {
		return err
	}
	for key, bytes := range accounting.peerBytes {
		if err := addPeerAccounting(t.peerBytes, key, bytes); err != nil {
			return err
		}
	}
	return nil
}

func (t retainedDAAccountingTotals) checkAgainstLocked(s *DARelayState) error {
	switch {
	case t.orphanBytes != s.orphanBytes:
		return fmt.Errorf("orphan pool bytes: records imply %d, state holds %d", t.orphanBytes, s.orphanBytes)
	case t.commitBytes != s.orphanCommitOverheadBytes:
		return fmt.Errorf("orphan commit overhead bytes: records imply %d, state holds %d", t.commitBytes, s.orphanCommitOverheadBytes)
	case t.pinnedBytes != s.pinnedPayloadBytes:
		return fmt.Errorf("pinned payload bytes: records imply %d, state holds %d", t.pinnedBytes, s.pinnedPayloadBytes)
	case t.daIDEntries != len(s.orphanBytesByDAID):
		return fmt.Errorf("per-da_id orphan bytes: records imply %d entries, state holds %d", t.daIDEntries, len(s.orphanBytesByDAID))
	}
	return t.checkPeerBytesLocked(s)
}

// checkPeerBytesLocked compares the per-peer counters key by key in ascending
// key order, so the named key is the same on every run. A key the records do not
// imply at all is caught by the entry count: neither map may hold a zero value —
// every writer deletes an emptied key — so equal counts plus equal values on
// every implied key is total equality.
func (t retainedDAAccountingTotals) checkPeerBytesLocked(s *DARelayState) error {
	for _, key := range slices.Sorted(maps.Keys(t.peerBytes)) {
		if stored := s.orphanBytesByPeerQuotaKey[key]; stored != t.peerBytes[key] {
			return fmt.Errorf("per-peer orphan bytes for %q: records imply %d, state holds %d", key, t.peerBytes[key], stored)
		}
	}
	if len(t.peerBytes) != len(s.orphanBytesByPeerQuotaKey) {
		return fmt.Errorf("per-peer orphan bytes: records imply %d entries, state holds %d", len(t.peerBytes), len(s.orphanBytesByPeerQuotaKey))
	}
	return nil
}

// publish is the D1 half of FIXED_PUBLICATION: it takes DARelayState.mu and
// assignment-publishes the already prepared image. It allocates nothing, clones
// nothing, validates nothing, performs no I/O, invokes no callback and cannot
// fail — every one of those already ran inside prepareCanonicalDAImage, under the
// same admission write fence that is still held, so the live image cannot have
// moved since. A nil image is an engine with no retained-DA state bound and
// publishes nothing.
func (i *preparedCanonicalDAImage) publish() {
	if i == nil {
		return
	}
	i.relay.mu.Lock()
	i.relay.publishAtomicBatchLocked(i.projected)
	i.relay.mu.Unlock()
}

// canonicalDARemovalsLocked selects the records D1 removes, scanning records by
// ascending raw da_id and, within a record, its members in exact-identity order
// — commit first, then chunks in ascending index.
//
// Each record is walked TWICE, in ordered phases, never interleaved: phase 1
// (canonicalRetainedDASetIdentity) parses and role-checks EVERY member, phase 2
// (canonicalRetainedDAMembersFinalChainValid) validates every member against C1.
// Precedence follows the loop nesting: the FIRST record in ascending da_id order
// that reports an error wins, and inside that one record phase 1 outranks phase
// 2 — so a LATER member's parse/role terminal outranks an EARLIER member's
// validation-phase failure of any kind, a canonical precommit plan abort
// included, only within the SAME record. A member that merely fails chain
// validation is a planned removal, not an error.
func (s *DARelayState) canonicalDARemovalsLocked(included []canonicalDASetIdentity, chain canonicalFinalChainContext) ([]daRelaySetRecord, error) {
	inclusion := make(map[[32]byte][]canonicalDASetIdentity, len(included))
	for i := range included {
		inclusion[included[i].daID] = append(inclusion[included[i].daID], included[i])
	}
	var removals []daRelaySetRecord
	for _, daID := range s.sortedRetainedDAIDsLocked() {
		record := s.sets[daID]
		identity, members, err := canonicalRetainedDASetIdentity(record)
		if err != nil {
			return nil, err
		}
		valid, err := canonicalRetainedDAMembersFinalChainValid(members, chain)
		if err != nil {
			return nil, err
		}
		if valid && !canonicalDASetIdentityIncluded(inclusion[daID], identity) {
			continue
		}
		removals = append(removals, record)
	}
	return removals, nil
}

// sortedRetainedDAIDsLocked orders EVERY retained record by ascending raw da_id,
// so no scan, error selection or removal ordering depends on map iteration order.
func (s *DARelayState) sortedRetainedDAIDsLocked() [][32]byte {
	daIDs := make([][32]byte, 0, len(s.sets))
	for daID := range s.sets {
		daIDs = append(daIDs, daID)
	}
	sort.Slice(daIDs, func(i, j int) bool {
		return bytes.Compare(daIDs[i][:], daIDs[j][:]) < 0
	})
	return daIDs
}

func canonicalDASetIdentityIncluded(candidates []canonicalDASetIdentity, identity canonicalDASetIdentity) bool {
	for i := range candidates {
		if canonicalDASetIdentityEqual(candidates[i], identity) {
			return true
		}
	}
	return false
}
