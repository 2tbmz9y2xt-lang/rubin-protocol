package node

// Seam: one RETAINED record's members — the canonical re-parse of their exact
// retained bytes, the role/index checks against the record's own claims, and
// their final-chain validation against C1.

import (
	"crypto/sha3"
	"errors"
	"fmt"
	"slices"
	"sort"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

// canonicalRetainedDAMember is one retained member's canonical parse, kept with
// the identity it produced so the validator checks exactly the bytes the identity
// was derived from and nothing is parsed twice.
type canonicalRetainedDAMember struct {
	tx    *consensus.Tx
	raw   []byte
	ids   consensus.ParsedTxIDs
	label string
}

// canonicalRetainedDASetIdentity derives one retained record's exact set identity
// from retained_tx(R): a canonical full-consumption parse of each member's exact
// retained TxBytes, checked against the DA role and index the record itself
// claims for that member. Members are walked commit first, then chunks in
// strictly ascending index.
//
// A member with no retained bytes, a member whose bytes do not fully consume as a
// canonical transaction, and a member whose parse contradicts its record are all
// missing-or-corrupt selected state and take the terminal lane.
func canonicalRetainedDASetIdentity(record daRelaySetRecord) (canonicalDASetIdentity, []canonicalRetainedDAMember, error) {
	identity := canonicalDASetIdentity{daID: record.daID}
	members := make([]canonicalRetainedDAMember, 0, 1+len(record.chunks))
	if record.commit.chunkCount != 0 {
		member, err := parseRetainedDAMember(record.commit.txBytes, "commit")
		if err != nil {
			return canonicalDASetIdentity{}, nil, err
		}
		if err := checkRetainedDACommitRole(member.tx, record); err != nil {
			return canonicalDASetIdentity{}, nil, err
		}
		identity.commit = canonicalDATxIdentity{txid: member.ids.TxID, wtxid: member.ids.WTxID}
		members = append(members, member)
	}
	for _, index := range sortedRetainedDAChunkIndexes(record) {
		member, err := parseRetainedDAMember(record.chunks[index].txBytes, fmt.Sprintf("chunk %d", index))
		if err != nil {
			return canonicalDASetIdentity{}, nil, err
		}
		if err := checkRetainedDAChunkRole(member.tx, record.daID, index); err != nil {
			return canonicalDASetIdentity{}, nil, err
		}
		identity.chunks = append(identity.chunks, canonicalDAChunkIdentity{
			canonicalDATxIdentity: canonicalDATxIdentity{txid: member.ids.TxID, wtxid: member.ids.WTxID},
			index:                 index,
		})
		members = append(members, member)
	}
	return identity, members, nil
}

// sortedRetainedDAChunkIndexes orders a record's retained chunk indexes
// ascending. A record may legitimately hold a sparse set of indexes while it is
// still incomplete, so the walk is over the indexes actually present, never over
// the declared range.
func sortedRetainedDAChunkIndexes(record daRelaySetRecord) []uint16 {
	indexes := make([]uint16, 0, len(record.chunks))
	for index := range record.chunks {
		indexes = append(indexes, index)
	}
	sort.Slice(indexes, func(i, j int) bool { return indexes[i] < indexes[j] })
	return indexes
}

func parseRetainedDAMember(txBytes []byte, label string) (canonicalRetainedDAMember, error) {
	if len(txBytes) == 0 {
		return canonicalRetainedDAMember{}, terminalCanonicalDAError(fmt.Errorf("retained DA %s has no retained transaction bytes", label))
	}
	tx, txid, wtxid, consumed, err := consensus.ParseTx(txBytes)
	if err != nil {
		return canonicalRetainedDAMember{}, terminalCanonicalDAError(fmt.Errorf("retained DA %s does not canonically parse: %w", label, err))
	}
	if consumed != len(txBytes) {
		return canonicalRetainedDAMember{}, terminalCanonicalDAError(fmt.Errorf("retained DA %s has trailing bytes: consumed=%d retained=%d", label, consumed, len(txBytes)))
	}
	return canonicalRetainedDAMember{
		tx:    tx,
		raw:   txBytes,
		ids:   consensus.ParsedTxIDs{TxID: txid, WTxID: wtxid},
		label: label,
	}, nil
}

func checkRetainedDACommitRole(tx *consensus.Tx, record daRelaySetRecord) error {
	if tx.TxKind != 0x01 || tx.DaCommitCore == nil {
		return terminalCanonicalDAError(fmt.Errorf("retained DA commit for %x is tx_kind 0x%02x", record.daID, tx.TxKind))
	}
	if tx.DaCommitCore.DaID != record.daID {
		return terminalCanonicalDAError(fmt.Errorf("retained DA commit for %x carries da_id %x", record.daID, tx.DaCommitCore.DaID))
	}
	if tx.DaCommitCore.ChunkCount != record.commit.chunkCount {
		return terminalCanonicalDAError(fmt.Errorf("retained DA commit for %x declares chunk_count %d, record holds %d", record.daID, tx.DaCommitCore.ChunkCount, record.commit.chunkCount))
	}
	return nil
}

func checkRetainedDAChunkRole(tx *consensus.Tx, daID [32]byte, index uint16) error {
	if tx.TxKind != 0x02 || tx.DaChunkCore == nil {
		return terminalCanonicalDAError(fmt.Errorf("retained DA chunk %d for %x is tx_kind 0x%02x", index, daID, tx.TxKind))
	}
	if tx.DaChunkCore.DaID != daID {
		return terminalCanonicalDAError(fmt.Errorf("retained DA chunk %d for %x carries da_id %x", index, daID, tx.DaChunkCore.DaID))
	}
	if tx.DaChunkCore.ChunkIndex != index {
		return terminalCanonicalDAError(fmt.Errorf("retained DA chunk for %x is stored at index %d and declares %d", daID, index, tx.DaChunkCore.ChunkIndex))
	}
	return nil
}

// canonicalRetainedDAMembersFinalChainValid reports whether EVERY member of one
// record is final_chain_valid against C1. It does not stop at the first invalid
// member: a later member's error evidence — an unusable chainstate view, a
// canonical precommit plan abort — must not be hidden by an earlier member's
// ordinary invalidity, and only a complete pass proves the "every member"
// quantifier the removal rule is written in. Corrupt bytes cannot appear here:
// the parse phase already returned for the whole record.
func canonicalRetainedDAMembersFinalChainValid(members []canonicalRetainedDAMember, chain canonicalFinalChainContext) (bool, error) {
	valid := true
	for i := range members {
		keep, err := canonicalRetainedDAMemberFinalChainValid(members[i], chain)
		if err != nil {
			return false, err
		}
		if !keep {
			valid = false
		}
	}
	return valid, nil
}

// canonicalRetainedDAMemberFinalChainValid runs the SAME chain-dependent
// validator M1 runs, against the SAME captured C1 context — confirmed UTXO view,
// next height, MTP, chain id, suite registry, rotation-cache view and signature
// cache. It deliberately reruns no pool-local duplicate, fee-floor, capacity,
// admission-sequence or owner-conflict check, and it never consults M1
// membership: a retained member evicted from the standard mempool for a local
// capacity reason is still chain-valid and its record stays.
func canonicalRetainedDAMemberFinalChainValid(member canonicalRetainedDAMember, chain canonicalFinalChainContext) (bool, error) {
	keep, err := canonicalRetainedDAMemberChainValid(member, chain)
	return keep, retaggedCanonicalDATerminal(err, member.label)
}

// retaggedCanonicalDATerminal relabels a TERMINAL_LOCAL_INVARIANT the SHARED M/O
// validator raised while judging a RETAINED DA member, so the operator record
// names the subsystem that actually latched. Only the label moves; the class
// stays terminal (isCanonicalTransitionTerminalError accepts both).
//
// A canonical precommit PLAN error is deliberately NOT retagged: EPD-6 requires D
// to return the SAME plan error M does, and it is not a retained-state invariant.
//
// It has NO reachable producer today. On this path the shared validator's only
// terminal sites are canonicalMempoolChainPolicyValid's nil-tx guard, which a
// parsed member cannot trip, and its policyInputSnapshot refusal, which the
// consensus check's own keep=false already precedes on the same input set. The
// relabel is insurance for that SHARED helper as RUB-678 extends it, and its unit
// row proves the mechanism, not a live path.
func retaggedCanonicalDATerminal(err error, label string) error {
	var mo *canonicalMOTerminalError
	if !errors.As(err, &mo) {
		return err
	}
	return terminalCanonicalDAError(fmt.Errorf("retained DA %s: %s", label, mo.detail))
}

func canonicalRetainedDAMemberChainValid(member canonicalRetainedDAMember, chain canonicalFinalChainContext) (bool, error) {
	_, keep, err := canonicalRetainedDACheckedMember(member, chain)
	return keep, err
}

// canonicalRetainedDACheckedMember is the one chain-dependent body both retained
// DA preparations run: the D image discards the CheckedTransaction, the paired
// D1/O1 builder binds its fee. The shared validator's keep/error classification
// is layered with nothing: an exclusion is keep=false, nil error; a plan abort is as is.
func canonicalRetainedDACheckedMember(member canonicalRetainedDAMember, chain canonicalFinalChainContext) (*consensus.CheckedTransaction, bool, error) {
	snapshot := chain.final.admissionSnapshotForInputs(relayMetadataInputs(member.tx))
	if snapshot == nil {
		return nil, false, terminalCanonicalDAError(fmt.Errorf("no final chainstate view for retained DA %s", member.label))
	}
	// The checker CONSUMES the owned map it is handed (one delete per spent
	// input), so it gets a throwaway copy of the already-narrowed snapshot and the
	// policy half below reads the pristine one — the same split the M side makes in
	// canonicalMempoolEntryFinalValid.
	checked, keep, err := canonicalCheckedAgainstFinalChain(member.raw, member.tx, member.ids, copyUtxoSet(snapshot.utxos), chain)
	if err != nil || !keep {
		return nil, false, err
	}
	keep, err = canonicalMempoolChainPolicyValid(member.tx, snapshot.utxos, chain)
	return checked, keep, err
}

// canonicalDARetainedMember pairs ONE retained slot's stored owner-ready
// identity with the canonical parse of the exact bytes that slot retains, so
// every later phase reads one proven binding and no member is parsed twice.
type canonicalDARetainedMember struct {
	parsed canonicalRetainedDAMember
	stored *daRelayMemberIdentity
	daID   [32]byte
}

// canonicalDARetainedRecord is one validated record's da_id and exact set identity.
type canonicalDARetainedRecord struct {
	daID     [32]byte
	identity canonicalDASetIdentity
}

// canonicalDARetainedImage is what phases 1-3 prove about ONE caller-owned
// owner-ready snapshot: records in ascending raw da_id and members as that walk
// flattened, commit first then ascending chunk index, so every later phase
// inherits the order. It borrows stored members and retained bytes READ-ONLY
// for one synchronous builder call and never reaches the builder's caller.
type canonicalDARetainedImage struct {
	records []canonicalDARetainedRecord
	members []canonicalDARetainedMember
}

// validateCanonicalDARetainedSnapshot is the intrinsic structure, identity,
// accounting and locator phase of prepareCanonicalDAOwnerCandidates, its only
// caller: it reads the caller-owned snapshot, acquires no lock, rereads nothing
// and mutates nothing reachable from it; a nil snapshot or a nil owner is
// terminal before any record is read. The walk is PHASE-MAJOR
// (RUBIN_MEMPOOL_POLICY.md Section 6.4.1 order): every record passes structure
// before any is parsed, and every record is parsed and bound before the
// image-wide closure runs. Phase 2 is two sub-phases per record — every member
// parsed and role-checked, commit first then ascending chunk index, before any
// member of that record is bound in the same order — so a chunk's parse defect
// outranks the commit's binding defect. Within one phase the first defect in
// ascending raw da_id, then in that sub-phase order, is the sole result; every
// defect is the retained-DA terminal class.
func validateCanonicalDARetainedSnapshot(retained *DARelayState, owner *PendingOutpointOwner) (canonicalDARetainedImage, error) {
	var image canonicalDARetainedImage
	if retained == nil {
		return image, terminalCanonicalDAError(errors.New("no retained DA snapshot"))
	}
	if owner == nil {
		return image, terminalCanonicalDAError(errors.New("no pending-outpoint owner"))
	}
	// ...Locked: the caller-owned snapshot's own invariant (see prepareCanonicalDAImage).
	daIDs := retained.sortedRetainedDAIDsLocked()
	for _, daID := range daIDs {
		if err := canonicalDARetainedStructure(retained.sets[daID], daID, owner); err != nil {
			return canonicalDARetainedImage{}, err
		}
	}
	for _, daID := range daIDs {
		if err := image.bindRetainedRecord(retained.sets[daID]); err != nil {
			return canonicalDARetainedImage{}, err
		}
	}
	if err := canonicalDARetainedImageClosed(retained, daIDs); err != nil {
		return canonicalDARetainedImage{}, err
	}
	return image, nil
}

// canonicalDARetainedStructure is phase 1 for one record: the owner-ready
// completeness the admission projector requires of a resident it moves — shape,
// state domain, residual fields and owner token, composed by checkDANonReplayPrior
// and restated nowhere — plus its memberless-record refusal.
func canonicalDARetainedStructure(record daRelaySetRecord, daID [32]byte, owner *PendingOutpointOwner) error {
	if err := record.checkDANonReplayPrior(daID, owner); err != nil {
		return terminalCanonicalDAError(fmt.Errorf("retained DA record %x is not owner-ready: %w", daID, err))
	}
	if len(record.locatorRows()) == 0 {
		return terminalCanonicalDAError(fmt.Errorf("retained DA record %x retains no member", daID))
	}
	return nil
}

// bindRetainedRecord is phase 2 for one record: ALL its members' exact retained
// bytes are parsed once with full consumption and role-checked against the
// record's own claims, and only then is each member, in that same order, bound
// to every stored scalar the parse can prove. Every defect names the record.
func (i *canonicalDARetainedImage) bindRetainedRecord(record daRelaySetRecord) error {
	identity, parsed, err := canonicalRetainedDASetIdentity(record)
	if err != nil {
		return canonicalDARecordTerminal(err, record.daID)
	}
	stored := canonicalDARetainedMemberIdentities(record)
	if len(stored) != len(parsed) {
		return terminalCanonicalDAError(fmt.Errorf("retained DA record %x retains %d members against %d parsed", record.daID, len(stored), len(parsed)))
	}
	for j := range parsed {
		member := canonicalDARetainedMember{parsed: parsed[j], stored: stored[j], daID: record.daID}
		if err := canonicalDARetainedBinding(record, member); err != nil {
			return err
		}
		i.members = append(i.members, member)
	}
	i.records = append(i.records, canonicalDARetainedRecord{daID: record.daID, identity: identity})
	return nil
}

// canonicalDARetainedMemberIdentities lists the stored member of every OCCUPIED
// slot in locatorRows order — the order canonicalRetainedDASetIdentity parses
// in — so the caller's length comparison proves the pairing by position.
func canonicalDARetainedMemberIdentities(record daRelaySetRecord) []*daRelayMemberIdentity {
	stored := make([]*daRelayMemberIdentity, 0, 1+len(record.chunks))
	if record.commit.member != nil {
		stored = append(stored, record.commit.member)
	}
	for _, index := range sortedRetainedDAChunkIndexes(record) {
		stored = append(stored, record.chunks[index].member)
	}
	return stored
}

// canonicalDARetainedBinding binds one parsed member to the scalars its slot
// stores: the identity pair, the ordered input set, and the payload cache its
// role carries; typed provenance is stored shape, refused in phase 1.
func canonicalDARetainedBinding(record daRelaySetRecord, m canonicalDARetainedMember) error {
	type identity struct{ txid, wtxid [32]byte }
	if (identity{m.stored.txid, m.stored.wtxid}) != (identity{m.parsed.ids.TxID, m.parsed.ids.WTxID}) ||
		!slices.Equal(relayMetadataInputs(m.parsed.tx), m.stored.inputs) {
		return terminalCanonicalDAError(fmt.Errorf("retained DA %s for %x contradicts its parsed identity", m.parsed.label, m.daID))
	}
	if m.parsed.tx.TxKind == 0x01 {
		return canonicalDACommitCacheBound(record.commit, m)
	}
	return canonicalDAChunkCacheBound(record.chunks[m.parsed.tx.DaChunkCore.ChunkIndex], m)
}

// canonicalDACommitCacheBound keeps the helper's refusal (no single usable
// payload-commitment output) distinct from a stored commitment it contradicts.
func canonicalDACommitCacheBound(commit daRelayCommit, m canonicalDARetainedMember) error {
	commitment, err := daAdmissionPayloadCommitment(m.parsed.tx)
	if err != nil {
		return terminalCanonicalDAError(fmt.Errorf("retained DA %s for %x carries no usable payload-commitment output: %w", m.parsed.label, m.daID, err))
	}
	if commitment != commit.payloadCommitment {
		return terminalCanonicalDAError(fmt.Errorf("retained DA %s for %x contradicts its payload commitment", m.parsed.label, m.daID))
	}
	return nil
}

// canonicalDAChunkCacheBound proves the stored chunk hash is both the one the
// chunk's retained bytes declare and the hash of the retained payload; an
// owner-ready chunk carries no hashChecked latch, so the hash is recomputed.
func canonicalDAChunkCacheBound(chunk daRelayChunk, m canonicalDARetainedMember) error {
	if chunk.chunkHash != m.parsed.tx.DaChunkCore.ChunkHash || sha3.Sum256(chunk.payload) != chunk.chunkHash {
		return terminalCanonicalDAError(fmt.Errorf("retained DA %s for %x contradicts its payload hash", m.parsed.label, m.daID))
	}
	return nil
}

// canonicalDARetainedImageClosed is phase 3 over ONE whole image: every record
// sits under its own da_id, the txid locator index and the retained members are
// one bijection, and every recomputable stored aggregate equals what the records
// imply (RUBIN_COMPACT_BLOCKS.md Sections 18.1 and 18.3), billed with
// ownerReadyAccounting exactly as the owner-ready projector bills. It never
// repairs a disagreement, never recomputes the monotone high-waters records and
// nextReceivedTime, and serves the input snapshot and the projected D1 alike.
func canonicalDARetainedImageClosed(s *DARelayState, daIDs [][32]byte) error {
	if s.locators == nil {
		return terminalCanonicalDAError(errors.New("retained DA image carries no locator index"))
	}
	indexed := make(map[[32]byte]bool, len(s.locators))
	totals := retainedDAAccountingTotals{peerBytes: map[string]uint64{}}
	for _, daID := range daIDs {
		record := s.sets[daID]
		if record.daID != daID {
			return terminalCanonicalDAError(fmt.Errorf("retained DA record stored under da_id %x carries da_id %x", daID, record.daID))
		}
		if err := canonicalDARecordLocatorsIndexed(s, record, indexed); err != nil {
			return err
		}
		if err := canonicalDARecordAccounted(s, record, &totals); err != nil {
			return err
		}
	}
	if len(indexed) != len(s.locators) {
		return terminalCanonicalDAError(fmt.Errorf("retained DA locator index holds %d rows against %d retained members", len(s.locators), len(indexed)))
	}
	if err := totals.checkAgainstLocked(s); err != nil {
		return terminalCanonicalDAError(err)
	}
	return nil
}

// canonicalDARecordLocatorsIndexed proves every row this record implies is
// indexed at exactly that locator and no txid is claimed twice; the caller's
// row count then catches a locator no record implies, absent da_id included.
func canonicalDARecordLocatorsIndexed(s *DARelayState, record daRelaySetRecord, indexed map[[32]byte]bool) error {
	for _, row := range record.locatorRows() {
		if s.locators[row.txid] != row.locator || indexed[row.txid] {
			return terminalCanonicalDAError(fmt.Errorf("retained DA record %x is not the sole locator of txid %x", record.daID, row.txid))
		}
		indexed[row.txid] = true
	}
	return nil
}

// canonicalDARecordAccounted adds one record to the recomputed totals and
// compares its per-da_id counter, leaving extra stored entries to the caller.
func canonicalDARecordAccounted(s *DARelayState, record daRelaySetRecord, totals *retainedDAAccountingTotals) error {
	accounting, err := record.ownerReadyAccounting()
	if err != nil {
		return terminalCanonicalDAError(fmt.Errorf("retained DA record %x accounting: %w", record.daID, err))
	}
	if stored := s.orphanBytesByDAID[record.daID]; stored != accounting.orphanBytes {
		return terminalCanonicalDAError(fmt.Errorf("per-da_id orphan bytes for %x: record implies %d, state holds %d", record.daID, accounting.orphanBytes, stored))
	}
	if accounting.orphanBytes != 0 {
		totals.daIDEntries++
	}
	if err := totals.add(accounting, record.pinnedPayloadAccountingBytes()); err != nil {
		return terminalCanonicalDAError(err)
	}
	return nil
}

// canonicalDAMemberFeeBound proves one retained member's stored Uint128 fee is
// the fee the SUPPLIED final-chain context derives for its exact bytes — no
// narrowing, no other-domain substitute (RUBIN_COMPACT_BLOCKS.md Section 18.1).
// The caller binds every consensus-checked member, policy-excluded or not.
func canonicalDAMemberFeeBound(m canonicalDARetainedMember, checked *consensus.CheckedTransaction) error {
	if checked.Fee != m.stored.fee {
		return terminalCanonicalDAError(fmt.Errorf("retained DA %s of %x stores fee %+v against final-chain fee %+v", m.parsed.label, m.daID, m.stored.fee, checked.Fee))
	}
	return nil
}
