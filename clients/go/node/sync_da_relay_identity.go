package node

// Seam: the exact DA set IDENTITY — its types, its equality rule, and its
// derivation from one newly canonical block's already validated parse. Nothing
// here reads retained state.

import (
	"errors"
	"fmt"

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
	return canonicalCompleteDASetIdentities(order, tallies, members)
}

// canonicalCompleteDASetIdentities renders every COMPLETE set's identity in the
// accumulator's recorded order, never in either map's iteration order.
func canonicalCompleteDASetIdentities(order [][32]byte, tallies map[[32]byte]blockDASetTally, members map[[32]byte]*canonicalDASetMembers) ([]canonicalDASetIdentity, error) {
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

// canonicalDASetMembers accumulates one block's members for one da_id, keeping
// the FIRST occurrence of each role/index exactly as the shared tally does: a
// second COMMIT makes the tally incomplete so the set contributes no identity,
// while a duplicate chunk INDEX would be deduplicated by both (each is keyed by
// index) rather than making it incomplete — and cannot occur anyway: consensus
// rejects such a block upstream (BLOCK_ERR_DA_INCOMPLETE).
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
