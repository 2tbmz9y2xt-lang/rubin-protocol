package node

import (
	"bytes"
	"errors"
	"fmt"
	"sort"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

// canonicalDATxIdentity is one DA transaction's exact identity.
//
// RUBIN_L1_CANONICAL.md Section 8.3 gives the two halves different jobs: txid
// binds the consensus core and outpoint identity, wtxid = SHA3-256(TxBytes)
// binds the exact witness and payload bytes. Both are part of the identity, so a
// resident carrying the same txid with a different wtxid is NOT the transaction a
// block included and is never selected by inclusion cleanup.
type canonicalDATxIdentity struct {
	txid  [32]byte
	wtxid [32]byte
}

// canonicalDAChunkIdentity is one chunk member's identity at its declared index.
type canonicalDAChunkIdentity struct {
	canonicalDATxIdentity
	index uint16
}

// canonicalDASetIdentity is one exact DA set identity as
// RUBIN_MEMPOOL_POLICY.md Section 6.4.1 defines it: the set's da_id, its commit's
// (txid, wtxid), and its chunks' (chunk_index, txid, wtxid) in strictly ascending
// index.
//
// Equality is total over all three parts (canonicalDASetIdentityEqual). A
// reusable da_id, or the same commit txid under a different wtxid, is a DIFFERENT
// identity and its resident stays: only an exact match is an inclusion removal.
type canonicalDASetIdentity struct {
	daID   [32]byte
	commit canonicalDATxIdentity
	chunks []canonicalDAChunkIdentity
}

// canonicalDASetIdentityEqual is the exact-match rule. len is compared first so
// an incomplete resident — which has fewer chunk members than any complete set a
// block can carry — can never match by accident.
func canonicalDASetIdentityEqual(left, right canonicalDASetIdentity) bool {
	if left.daID != right.daID || left.commit != right.commit || len(left.chunks) != len(right.chunks) {
		return false
	}
	for i := range left.chunks {
		if left.chunks[i] != right.chunks[i] {
			return false
		}
	}
	return true
}

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

// canonicalDASetIdentitiesFromParsedBlock derives I for ONE newly canonical
// block, in block transaction order, from the block's ALREADY VALIDATED parse and
// its aligned txid/wtxid arrays. It never reads A1, never re-parses summary bytes
// and never derives an identity from a da_id alone.
//
// Which da_ids are complete is decided by the EXISTING blockDASetTally rule that
// A1 itself uses, driven here through the same recordBlockDATx accumulator, so I
// and A1 cannot disagree about completeness. A1's own cardinality bound
// (MAX_DA_BATCHES_PER_BLOCK, enforced in CompleteDASetIDsFromParsedBlock) covers
// this list too: both callers derive A1 for the same block first, so an over-cap
// block is refused before this runs and no second bound is introduced here.
//
// Order is first-member block position, which is the subsection's "newly
// canonical block/transaction order" for a set spanning several rows.
func canonicalDASetIdentitiesFromParsedBlock(pb *consensus.ParsedBlock) ([]canonicalDASetIdentity, error) {
	if pb == nil {
		return nil, errors.New("nil parsed block")
	}
	if len(pb.Txids) != len(pb.Txs) || len(pb.Wtxids) != len(pb.Txs) {
		return nil, fmt.Errorf("parsed block identity arrays are not aligned with its %d transactions: txids=%d wtxids=%d", len(pb.Txs), len(pb.Txids), len(pb.Wtxids))
	}
	tallies := make(map[[32]byte]blockDASetTally)
	members := make(map[[32]byte]*canonicalDASetMembers)
	order := make([][32]byte, 0)
	for i, tx := range pb.Txs {
		recordBlockDATx(tallies, tx)
		daID, ok := canonicalDAMemberSetID(tx)
		if !ok {
			continue
		}
		member := members[daID]
		if member == nil {
			member = &canonicalDASetMembers{chunks: make(map[uint16]canonicalDATxIdentity)}
			members[daID] = member
			order = append(order, daID)
		}
		member.record(tx, canonicalDATxIdentity{txid: pb.Txids[i], wtxid: pb.Wtxids[i]})
	}
	identities := make([]canonicalDASetIdentity, 0, len(order))
	for _, daID := range order {
		tally := tallies[daID]
		if !tally.complete() {
			continue
		}
		identity, err := members[daID].identity(daID, tally.chunkCount)
		if err != nil {
			return nil, err
		}
		identities = append(identities, identity)
	}
	return identities, nil
}

// canonicalDASetMembers accumulates one block's members for one da_id. It keeps
// the FIRST occurrence of each role/index; a second commit or a duplicate chunk
// index makes the tally incomplete, so such a set contributes no identity at all.
type canonicalDASetMembers struct {
	commit    canonicalDATxIdentity
	hasCommit bool
	chunks    map[uint16]canonicalDATxIdentity
}

func (m *canonicalDASetMembers) record(tx *consensus.Tx, identity canonicalDATxIdentity) {
	if tx.TxKind == 0x01 {
		if !m.hasCommit {
			m.commit, m.hasCommit = identity, true
		}
		return
	}
	if _, seen := m.chunks[tx.DaChunkCore.ChunkIndex]; !seen {
		m.chunks[tx.DaChunkCore.ChunkIndex] = identity
	}
}

// identity renders the accumulated members in strictly ascending chunk index.
// The caller has already established completeness, so a missing index here is an
// internal inconsistency and is reported rather than silently shortening the set.
func (m *canonicalDASetMembers) identity(daID [32]byte, chunkCount uint16) (canonicalDASetIdentity, error) {
	identity := canonicalDASetIdentity{daID: daID, commit: m.commit, chunks: make([]canonicalDAChunkIdentity, 0, chunkCount)}
	for index := uint16(0); index < chunkCount; index++ {
		chunk, ok := m.chunks[index]
		if !ok {
			return canonicalDASetIdentity{}, fmt.Errorf("complete DA set %x is missing chunk index %d", daID, index)
		}
		identity.chunks = append(identity.chunks, canonicalDAChunkIdentity{canonicalDATxIdentity: chunk, index: index})
	}
	return identity, nil
}

// canonicalDAMemberSetID reports the da_id a transaction is a DA member of,
// under the same role guards recordBlockDATx applies.
func canonicalDAMemberSetID(tx *consensus.Tx) ([32]byte, bool) {
	switch {
	case tx == nil:
		return [32]byte{}, false
	case tx.TxKind == 0x01 && tx.DaCommitCore != nil:
		return tx.DaCommitCore.DaID, true
	case tx.TxKind == 0x02 && tx.DaChunkCore != nil:
		return tx.DaChunkCore.DaID, true
	default:
		return [32]byte{}, false
	}
}

// canonicalRetainedDAMember is one retained member's canonical parse, kept with
// the identity it produced so the validator checks exactly the bytes the identity
// was derived from and nothing is parsed twice.
type canonicalRetainedDAMember struct {
	tx    *consensus.Tx
	raw   []byte
	ids   consensus.ParsedTxIDs
	label string
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
// image it reads cannot move before publication; it takes only DARelayState.mu
// and never the admission guard itself, which is neither reentrant nor available
// to it.
//
// Everything fallible happens HERE: parsing, validation and every checked
// accounting projection. Publication is assignment only.
//
// Cost, accepted deliberately: every retained member is validated against C1 on
// every canonical transition, including the later members of a record already
// destined for removal. That is what makes "D1 is independently derived from
// full validation of every retained member" a statement about the code rather
// than about the common case; the shared rotation cache and signature cache from
// the M1 preparation absorb the repeated work.
func prepareCanonicalDAImage(relay *DARelayState, included []canonicalDASetIdentity, chain canonicalFinalChainContext) (*preparedCanonicalDAImage, error) {
	if relay == nil {
		return nil, nil
	}
	relay.mu.Lock()
	defer relay.mu.Unlock()
	removals, err := relay.canonicalDARemovalsLocked(included, chain)
	if err != nil {
		return nil, err
	}
	projected := relay.cloneForAtomicBatchLocked()
	for _, record := range removals {
		if err := projected.removeDASetRecordLocked(record); err != nil {
			return nil, terminalCanonicalDAError(err)
		}
	}
	return &preparedCanonicalDAImage{relay: relay, projected: projected}, nil
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

// canonicalDARemovalsLocked selects the records D1 removes, scanning in the
// contract's deterministic order: records by ascending raw da_id, and within a
// record its members in exact-identity order — commit first, then chunks in
// ascending index. The FIRST terminal member error in that order wins; a member
// that merely fails chain validation is a planned removal, not an error, and
// never suppresses a later member's terminal evidence.
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
		return terminalCanonicalDAError(fmt.Errorf("retained DA commit for %x is tx_kind %#02x", record.daID, tx.TxKind))
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
		return terminalCanonicalDAError(fmt.Errorf("retained DA chunk %d for %x is tx_kind %#02x", index, daID, tx.TxKind))
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
// member: a later member's terminal evidence — corrupt bytes, an unusable
// chainstate view — must not be hidden by an earlier member's ordinary
// invalidity, and only a complete pass proves the "every member" quantifier the
// removal rule is written in.
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
	snapshot := chain.final.admissionSnapshotForInputs(relayMetadataInputs(member.tx))
	if snapshot == nil {
		return false, terminalCanonicalDAError(fmt.Errorf("no final chainstate view for retained DA %s", member.label))
	}
	if _, keep, err := canonicalCheckedAgainstFinalChain(member.raw, member.tx, member.ids, snapshot.utxos, chain); err != nil || !keep {
		return false, err
	}
	return canonicalMempoolChainPolicyValid(member.tx, snapshot.utxos, chain)
}
