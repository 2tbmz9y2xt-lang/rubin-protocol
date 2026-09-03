package node

import (
	"bytes"
	"errors"
	"fmt"
	"maps"
	"slices"
	"sort"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
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
func prepareCanonicalDAImage(relay *DARelayState, included []canonicalDASetIdentity, chain canonicalFinalChainContext) (*preparedCanonicalDAImage, error) {
	if relay == nil {
		return nil, nil //nolint:nilnil // nil image, nil error = engine with no retained-DA state bound; publish() documents the nil no-op
	}
	relay.mu.Lock()
	defer relay.mu.Unlock()
	removals, err := relay.canonicalDARemovalsLocked(included, chain)
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
	return &preparedCanonicalDAImage{relay: relay, projected: projected}, nil
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
// evidence string on every run and on every pointer width. It bills the LEGACY
// image (orphanAccounting: cached peerQuotaKey, wireBytes fallback); an
// owner-ready image is closed by canonicalDARetainedImageClosed instead.
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

// preparedCanonicalDAOwnerCandidates is ONE matched pair of private candidates:
// D1, the retained-DA image the transition would publish, and O1, the owner
// image keeping the DA claims D1's surviving members hold plus every standard claim
// verbatim, its indexes rebuilt from it. Neither half is publishable alone, and
// neither shares a mutable container with an input or with its sibling.
type preparedCanonicalDAOwnerCandidates struct {
	retained   *DARelayState
	pending    pendingOutpointSnapshot
	ownerIndex pendingOutpointIndex
}

// prepareCanonicalDAOwnerCandidates derives the matched D1/O1 pair from ONE
// caller-owned owner-ready retained snapshot, ONE owner snapshot, the same
// transition's canonical inclusion identities and its captured final-chain
// context: both halves, or exactly one ordered error and neither half; a nil
// snapshot, owner or final chain is terminal before phase 1.
//
// Both inputs are CALLER-OWNED and stable for the call: this takes no live
// transition, relay or owner lock, rereads nothing, publishes nothing and
// mutates neither input nor anything reachable from one. The one lock it takes
// transitively is the supplied chain.final's ChainState.mu, RLocked per member
// by admissionSnapshotForInputs, so the caller must supply a private clone or
// never hold that mutex exclusively across this call. It owns only the image it
// builds; the supplied context's rotation memo and signature cache absorb the
// per-height rotation observation and signature verification, as the live D
// preparation above states. Retained bytes and stored members are borrowed
// read-only and cannot escape.
//
// RUBIN_MEMPOOL_POLICY.md Section 6.4.1 says what each phase validates or derives;
// the PHASE-MAJOR walk is this builder's own rule — every record clears one phase
// before any enters the next: (1-3) structure, identity binding, accounting and
// locator closure; (4) the final chain and the exact stored fee, unioned with the
// exact-inclusion removals; (5) the member/finalized-DA-claim bijection; (6) the
// pair and its closing D/O proof. The first defect in ascending raw da_id, commit
// first then ascending chunk index, is the sole result — phase 5's claim-shape
// sub-phase excepted, which reports the first defect in the owner snapshot's own
// claim order (ascending token sequence, as snapshot() renders it) — with the class
// carried verbatim: keep=false is an EXCLUSION that removes a record, a canonical
// precommit plan abort is returned unchanged, a terminal stays the retained-DA
// terminal class — unlike the record-major live prepareCanonicalDAImage, which this
// builder never consults.
//
// Cost, accepted deliberately: the dominant term is the COPY, not the walks —
// cloneOwnerReady deep-copies every survivor (commit txBytes, each chunk's
// txBytes and payload), so the call is O(surviving retained bytes), ~2x them
// while the input and D1 coexist, bounded by the orphan-pool cap admission bills
// those same bytes against; the live preparedCanonicalDAImage SHARES that backing
// instead, and copying is what keeps a mutation of D1 out of the caller's
// snapshot. Each removal reproves the whole locator index through the shared
// owner-atomic projector, O(locators) per removal and O(removals × locators) over
// the call, and the inclusion scan is O(records × included), included bounded by
// MAX_DA_BATCHES_PER_BLOCK. A real block identity matches no owner-ready resident
// until COMPLETE_SET joins that domain (issue 1118); RUB-678 owns the live call
// site, and there is none today — and it must first move P2P ingest onto the
// owner-ready admission path, since the path behind StageCommit/StageChunk mints
// no revision and leaves a completed set in COMPLETE_SET, and phase 1 refuses the
// WHOLE snapshot on the first resident that is not owner-ready; scoping phase 1
// per record is the alternative.
func prepareCanonicalDAOwnerCandidates(
	retained *DARelayState,
	owner *PendingOutpointOwner,
	pending pendingOutpointSnapshot,
	included []canonicalDASetIdentity,
	chain canonicalFinalChainContext,
) (preparedCanonicalDAOwnerCandidates, error) {
	var zero preparedCanonicalDAOwnerCandidates
	if retained == nil {
		return zero, terminalCanonicalDAError(errors.New("no retained DA snapshot"))
	}
	if owner == nil {
		return zero, terminalCanonicalDAError(errors.New("no pending-outpoint owner"))
	}
	if chain.final == nil {
		return zero, terminalCanonicalDAError(errors.New("no final-chain context"))
	}
	image, err := validateCanonicalDARetainedSnapshot(retained, owner)
	if err != nil {
		return zero, err
	}
	removed, err := canonicalDAOwnerRemovals(image, included, chain)
	if err != nil {
		return zero, err
	}
	if err := validateCanonicalDAOwnerClaims(owner, pending, image); err != nil {
		return zero, err
	}
	return buildCanonicalDAOwnerCandidates(retained, owner, pending, image, removed)
}

// canonicalDAOwnerRemovals is phase 4: EVERY member of EVERY record is judged
// against the supplied final-chain context before any owner work, so an earlier
// member's ordinary invalidity never hides a later member's terminal or plan
// abort. The stored fee is bound after the shared validator returns, so a policy-half
// error (plan abort or terminal) outranks a fee mismatch on the same member and an
// exclusion does not. A record is removed if any member is not final_chain_valid OR
// its exact identity is included: one union.
func canonicalDAOwnerRemovals(image canonicalDARetainedImage, included []canonicalDASetIdentity, chain canonicalFinalChainContext) (map[[32]byte]bool, error) {
	removed := make(map[[32]byte]bool, len(image.identities))
	for _, member := range image.members {
		checked, keep, err := canonicalRetainedDACheckedMember(member.parsed, chain)
		if err != nil {
			return nil, canonicalDARecordTerminal(retaggedCanonicalDATerminal(err, member.parsed.label), member.daID)
		}
		if err := canonicalDAMemberFeeBound(member, checked, keep); err != nil {
			return nil, err
		}
		if !keep {
			removed[member.daID] = true
		}
	}
	for i := range image.identities {
		if canonicalDASetIdentityIncluded(included, image.identities[i]) {
			removed[image.identities[i].daID] = true
		}
	}
	return removed, nil
}

// canonicalDARecordTerminal names the record a member-labeled terminal belongs to.
func canonicalDARecordTerminal(err error, daID [32]byte) error {
	var terminal *canonicalDATerminalError
	if !errors.As(err, &terminal) {
		return err
	}
	return &canonicalDATerminalError{detail: fmt.Sprintf("retained DA record %x: %s", daID, terminal.detail)}
}

// validateCanonicalDAOwnerClaims is phase 5: every claim of the one owner snapshot
// is shape-valid for this owner under its own high-waters and claims its outpoints
// alone, then the members and the FINALIZED DA claims are proven one bijection:
// every member resolves its own exclusive claim, no claim outside the standard
// domain is left unbound, and a standard claim is never bound, removed or reordered.
func validateCanonicalDAOwnerClaims(owner *PendingOutpointOwner, pending pendingOutpointSnapshot, image canonicalDARetainedImage) error {
	bound, err := canonicalDAOwnerBoundClaims(owner, pending, image)
	if err != nil {
		return err
	}
	for i := range pending.claims {
		if pending.claims[i].domain != PendingOutpointStandardMempool && !bound[pending.claims[i].token] {
			return terminalCanonicalDAError(fmt.Errorf("DA claim for %x binds no retained member", pending.claims[i].txid))
		}
	}
	return nil
}

// canonicalDAOwnerBoundClaims resolves one claim per retained member in the
// image's own order and reports the tokens it bound; an unheld token, a token
// an earlier member bound, and a claim not describing its member are terminal.
func canonicalDAOwnerBoundClaims(owner *PendingOutpointOwner, pending pendingOutpointSnapshot, image canonicalDARetainedImage) (map[PendingOutpointToken]bool, error) {
	byToken, err := canonicalDAOwnerClaimsByToken(owner, pending)
	if err != nil {
		return nil, err
	}
	bound := make(map[PendingOutpointToken]bool, len(byToken))
	for _, member := range image.members {
		claim, held := byToken[member.stored.token]
		if !held {
			return nil, terminalCanonicalDAError(fmt.Errorf("retained DA %s of %x holds no owner claim", member.parsed.label, member.daID))
		}
		if bound[member.stored.token] {
			return nil, terminalCanonicalDAError(fmt.Errorf("retained DA %s of %x shares its token with an earlier retained member", member.parsed.label, member.daID))
		}
		if !canonicalDAClaimBindsMember(claim, member.stored) {
			return nil, terminalCanonicalDAError(fmt.Errorf("retained DA %s of %x is not described by its claim", member.parsed.label, member.daID))
		}
		bound[member.stored.token] = true
	}
	return bound, nil
}

// canonicalDAOwnerClaimsByToken indexes the snapshot's claims by token in the
// snapshot's own claim order, shape-checking every claim of every domain on the
// way: a token carried twice, a malformed claim and an outpoint claimed twice are
// terminal before any member is resolved. The owner's buildRestoreLocked builds
// the same index, but its contract is a held owner mutex this builder never
// takes, it omits the generation bound validateCanonicalMempoolClaimShape adds,
// and it reports the owner's internal class, not the retained-DA terminal one.
func canonicalDAOwnerClaimsByToken(owner *PendingOutpointOwner, pending pendingOutpointSnapshot) (map[PendingOutpointToken]pendingOutpointClaim, error) {
	byToken := make(map[PendingOutpointToken]pendingOutpointClaim, len(pending.claims))
	byOutpoint := make(map[consensus.Outpoint]bool, len(pending.claims))
	for _, claim := range pending.claims {
		if _, duplicate := byToken[claim.token]; duplicate {
			return nil, terminalCanonicalDAError(fmt.Errorf("owner snapshot carries one token twice for %x", claim.txid))
		}
		if err := validateCanonicalMempoolClaimShape(owner, claim, pending); err != nil {
			return nil, terminalCanonicalDAError(fmt.Errorf("owner claim for %x: %w", claim.txid, err))
		}
		for _, input := range claim.inputs {
			if byOutpoint[input] {
				return nil, terminalCanonicalDAError(fmt.Errorf("owner snapshot claims outpoint txid=%x vout=%d twice, last for %x", input.Txid, input.Vout, claim.txid))
			}
			byOutpoint[input] = true
		}
		byToken[claim.token] = claim
	}
	return byToken, nil
}

// canonicalDAClaimBindsMember is the exact claim-to-member rule the phase-5
// bijection and the closing proof share: DA domain, txid, ordered inputs, finalized.
func canonicalDAClaimBindsMember(claim pendingOutpointClaim, member *daRelayMemberIdentity) bool {
	return claim.domain == PendingOutpointDA && claim.txid == member.txid &&
		claim.finalized && slices.Equal(claim.inputs, member.inputs)
}

// buildCanonicalDAOwnerCandidates is phase 6: the pair is projected, every
// survivor preserved exactly, the owner indexes rebuilt from O1 alone, and the
// pair returned only after the closing bijection proof. Removal goes through the
// shared owner-atomic projector — retiring record, locator rows and accounting
// together — with every admission cap lifted as the owner-ready admission lifts
// them, since a shrinking projection cannot raise a counter. Only the per-peer
// lift can decide a call: that admission enforces the global and commit-overhead
// caps for a State B record at apply time and a removal zeroes its own per-da_id
// counter, so those three lifts are unreachable defense in depth, while a State B
// peer may legitimately sit above the per-peer cap. Prefetch reservations are
// released after it; survivors are deep-copied so no input container reaches D1.
func buildCanonicalDAOwnerCandidates(
	retained *DARelayState,
	owner *PendingOutpointOwner,
	pending pendingOutpointSnapshot,
	image canonicalDARetainedImage,
	removed map[[32]byte]bool,
) (preparedCanonicalDAOwnerCandidates, error) {
	var zero preparedCanonicalDAOwnerCandidates
	// ...Locked: the private projection's own invariant (see prepareCanonicalDAImage).
	projected := retained.cloneForAtomicBatchLocked()
	uncapped := projected.caps
	uncapped.orphanPoolBytes, uncapped.orphanPoolPerDAIDBytes, uncapped.orphanPoolPerPeerBytes, uncapped.orphanCommitOverheadBytes = ^uint64(0), ^uint64(0), ^uint64(0), ^uint64(0)
	for i := range image.identities {
		daID := image.identities[i].daID
		if !removed[daID] {
			projected.sets[daID] = retained.sets[daID].cloneOwnerReady()
			continue
		}
		removal := stageDAOwnerReadyRemoval(retained.sets[daID], true)
		live, err := projected.checkDARecordImageBaselineLocked(removal)
		var placement daRelayRecordPlacement
		if err == nil {
			placement, err = projected.projectDARecordImageLiveLocked(removal, live, uncapped)
		}
		if err != nil {
			return zero, terminalCanonicalDAError(fmt.Errorf("retained DA record %x removal: %w", daID, err))
		}
		projected.installDASetRecordLocked(placement)
		projected.prefetch.releaseSet(daID)
	}
	candidates := preparedCanonicalDAOwnerCandidates{retained: projected, pending: canonicalDAOwnerPending(pending, image, removed)}
	candidates.ownerIndex = buildCanonicalOwnerIndex(owner, candidates.pending)
	if err := canonicalDAOwnerPairClosed(candidates, image, removed); err != nil {
		return zero, err
	}
	return candidates, nil
}

// canonicalDAOwnerPending is O1: the supplied owner image minus the finalized claim
// of every removed member, in original order, every surviving claim — DA and
// standard alike — with its own copied input slice, tip and high-waters verbatim.
func canonicalDAOwnerPending(pending pendingOutpointSnapshot, image canonicalDARetainedImage, removed map[[32]byte]bool) pendingOutpointSnapshot {
	dropped := make(map[PendingOutpointToken]bool, len(image.members))
	for i := range image.members {
		if removed[image.members[i].daID] {
			dropped[image.members[i].stored.token] = true
		}
	}
	out := pending
	out.claims = make([]pendingOutpointClaim, 0, len(pending.claims))
	for _, claim := range pending.claims {
		if dropped[claim.token] {
			continue
		}
		claim.inputs = slices.Clone(claim.inputs)
		out.claims = append(out.claims, claim)
	}
	return out
}

// canonicalDAOwnerPairClosed is the closing proof: every surviving member still
// resolves its own finalized claim and outpoint rows through the REBUILT index,
// O1 carries no DA claim beyond those members, that index holds exactly one row
// per claimed input, and D1 satisfies the closure its input snapshot passed.
func canonicalDAOwnerPairClosed(candidates preparedCanonicalDAOwnerCandidates, image canonicalDARetainedImage, removed map[[32]byte]bool) error {
	survivors := 0
	for i := range image.members {
		if removed[image.members[i].daID] {
			continue
		}
		survivors++
		if err := canonicalDAOwnerSurvivingClaim(candidates.ownerIndex, image.members[i]); err != nil {
			return err
		}
	}
	if daClaims := canonicalDAOwnerDomainClaims(candidates.pending); daClaims != survivors {
		return terminalCanonicalDAError(fmt.Errorf("owner candidate holds %d DA claims against %d surviving retained members", daClaims, survivors))
	}
	if claimedInputs := canonicalDAOwnerClaimedInputs(candidates.pending); claimedInputs != len(candidates.ownerIndex.byOutpoint) {
		return terminalCanonicalDAError(fmt.Errorf("owner candidate indexes %d outpoint rows against %d claimed inputs", len(candidates.ownerIndex.byOutpoint), claimedInputs))
	}
	return canonicalDARetainedImageClosed(candidates.retained, candidates.retained.sortedRetainedDAIDsLocked())
}

func canonicalDAOwnerSurvivingClaim(index pendingOutpointIndex, member canonicalDARetainedMember) error {
	claim, err := index.claimForToken(member.stored.token)
	if err != nil {
		return terminalCanonicalDAError(fmt.Errorf("surviving retained DA %s of %x: %w", member.parsed.label, member.daID, err))
	}
	if claim == nil || !canonicalDAClaimBindsMember(*claim, member.stored) {
		return terminalCanonicalDAError(fmt.Errorf("surviving retained DA %s of %x lost its owner claim", member.parsed.label, member.daID))
	}
	for _, input := range member.stored.inputs {
		if index.byOutpoint[input] != (pendingOutpointRow{token: member.stored.token, txid: member.stored.txid}) {
			return terminalCanonicalDAError(fmt.Errorf("surviving retained DA %s of %x lost an owner outpoint row", member.parsed.label, member.daID))
		}
	}
	return nil
}

func canonicalDAOwnerDomainClaims(pending pendingOutpointSnapshot) int {
	claims := 0
	for i := range pending.claims {
		if pending.claims[i].domain == PendingOutpointDA {
			claims++
		}
	}
	return claims
}

func canonicalDAOwnerClaimedInputs(pending pendingOutpointSnapshot) (inputs int) {
	for _, claim := range pending.claims {
		inputs += len(claim.inputs)
	}
	return inputs
}
