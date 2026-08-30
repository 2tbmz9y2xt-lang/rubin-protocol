package node

import "github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"

type daProvenanceKind uint8

const (
	daProvenanceInvalid daProvenanceKind = iota
	daProvenancePeer
	daProvenanceLocal
	daProvenanceDetachedReorg
)

type daProvenance struct {
	kind          daProvenanceKind
	peerIdentity  string
	quotaIdentity string
}

// quotaKey is the ONLY source of the per-peer accounting key: derived on every use,
// never stored beside the provenance, so no member can present one source with
// another's charge. Only PEER is charged per peer; the empty key is never a bucket.
func (p daProvenance) quotaKey() string {
	if p.kind == daProvenancePeer {
		return p.quotaIdentity
	}
	return ""
}

func (p daProvenance) validate() error {
	switch p.kind {
	case daProvenancePeer:
		if p.peerIdentity == "" || p.quotaIdentity == "" {
			return errDAProvenanceInvalid
		}
		return nil
	case daProvenanceLocal, daProvenanceDetachedReorg:
		if p.peerIdentity != "" || p.quotaIdentity != "" {
			return errDAProvenanceInvalid
		}
		return nil
	default:
		return errDAProvenanceInvalid
	}
}

// validate runs only where a member is required, so nil — the empty-slot marker — is refused
// here; a commit slot's emptiness is that pointer, a chunk slot's its map key. Token and fee
// are deliberately NOT checked: a zero token precedes the owner reserve.
func (m *daRelayMemberIdentity) validate() error {
	if m == nil {
		return errDARelayMemberIncomplete
	}
	if m.txid == ([32]byte{}) || m.wtxid == ([32]byte{}) {
		return errDARelayMemberIncomplete
	}
	if len(m.inputs) == 0 || len(m.inputs) > consensus.MAX_TX_INPUTS {
		return errDARelayMemberIncomplete
	}
	return m.provenance.validate()
}

type daRelayOwnerReadyMember struct {
	locator daRelayLocator
	member  daRelayMemberIdentity
	txBytes []byte
	payload []byte
}

type daRelayAdmissionCandidate struct {
	member            daRelayOwnerReadyMember
	payloadCommitment [32]byte
	chunkCount        uint16
	chunkHash         [32]byte
}

func (a *DAAdmission) renderDARelayAdmissionCandidate(provenance daProvenance) (daRelayAdmissionCandidate, error) {
	var zero daRelayAdmissionCandidate
	snapshot := a.Snapshot()
	if err := provenance.validate(); err != nil {
		return zero, err
	}
	if a.tx == nil {
		return zero, errDARelayMemberIncomplete
	}
	candidate := daRelayAdmissionCandidate{member: daRelayOwnerReadyMember{
		member: daRelayMemberIdentity{
			txid:       snapshot.TxID,
			wtxid:      snapshot.WTxID,
			fee:        snapshot.Fee,
			inputs:     snapshot.Inputs,
			provenance: provenance,
		},
		txBytes: snapshot.TxBytes,
	}}
	switch a.tx.TxKind {
	case 0x01:
		return renderDACommitAdmissionCandidate(candidate, a.tx)
	case 0x02:
		return renderDAChunkAdmissionCandidate(candidate, a.tx)
	default:
		return zero, errDARelayMemberIncomplete
	}
}

func renderDACommitAdmissionCandidate(candidate daRelayAdmissionCandidate, tx *consensus.Tx) (daRelayAdmissionCandidate, error) {
	var zero daRelayAdmissionCandidate
	if tx.DaCommitCore == nil || tx.DaChunkCore != nil {
		return zero, errDARelayMemberIncomplete
	}
	if tx.DaCommitCore.ChunkCount == 0 || uint64(tx.DaCommitCore.ChunkCount) > consensus.MAX_DA_CHUNK_COUNT {
		return zero, errDARelayChunkCountInvalid
	}
	commitment, err := daAdmissionPayloadCommitment(tx)
	if err != nil {
		return zero, err
	}
	candidate.member.locator = daRelayLocator{daID: tx.DaCommitCore.DaID, kind: daRelayLocatorCommit}
	candidate.payloadCommitment = commitment
	candidate.chunkCount = tx.DaCommitCore.ChunkCount
	if err := candidate.validate(); err != nil {
		return zero, err
	}
	return candidate, nil
}

func renderDAChunkAdmissionCandidate(candidate daRelayAdmissionCandidate, tx *consensus.Tx) (daRelayAdmissionCandidate, error) {
	var zero daRelayAdmissionCandidate
	if tx.DaChunkCore == nil || tx.DaCommitCore != nil {
		return zero, errDARelayMemberIncomplete
	}
	if err := checkOwnerReadyChunkIndex(tx.DaChunkCore.ChunkIndex); err != nil {
		return zero, err
	}
	if err := checkOwnerReadyPayload(tx.DaPayload); err != nil {
		return zero, err
	}
	candidate.member.locator = daRelayLocator{daID: tx.DaChunkCore.DaID, kind: daRelayLocatorChunk, chunkIndex: tx.DaChunkCore.ChunkIndex}
	candidate.member.payload = append([]byte(nil), tx.DaPayload...)
	candidate.chunkHash = tx.DaChunkCore.ChunkHash
	if err := candidate.validate(); err != nil {
		return zero, err
	}
	return candidate, nil
}

func (c daRelayAdmissionCandidate) validate() error {
	if err := c.member.validate(); err != nil {
		return err
	}
	if c.member.member.token != (PendingOutpointToken{}) {
		return errDARelayMemberIncomplete
	}
	if c.member.locator.kind == daRelayLocatorCommit {
		return c.validateCommit()
	}
	return c.validateChunk()
}

func (c daRelayAdmissionCandidate) validateCommit() error {
	if c.chunkHash != ([32]byte{}) {
		return errDARelayMemberIncomplete
	}
	if c.chunkCount == 0 || uint64(c.chunkCount) > consensus.MAX_DA_CHUNK_COUNT {
		return errDARelayChunkCountInvalid
	}
	return nil
}

func (c daRelayAdmissionCandidate) validateChunk() error {
	if c.payloadCommitment != ([32]byte{}) || c.chunkCount != 0 {
		return errDARelayMemberIncomplete
	}
	return nil
}

func daAdmissionPayloadCommitment(tx *consensus.Tx) ([32]byte, error) {
	var commitment [32]byte
	found := false
	for _, output := range tx.Outputs {
		if output.CovenantType != consensus.COV_TYPE_DA_COMMIT {
			continue
		}
		if found || len(output.CovenantData) != len(commitment) {
			return [32]byte{}, errDARelayMemberIncomplete
		}
		copy(commitment[:], output.CovenantData)
		found = true
	}
	if !found {
		return [32]byte{}, errDARelayMemberIncomplete
	}
	return commitment, nil
}

// A commit locator must carry chunk index 0, or two locators for one slot would
// compare unequal. Every absolute bound below has ONE definition, shared with the
// record path that installDASetRecordLocked publishes. The descriptor carries neither the DECLARED
// chunk count nor wire_bytes, so this slice binds neither; the admission candidate keeps
// role-specific metadata separately, while legacy wireBytes remains zero.
func (m daRelayOwnerReadyMember) validate() error {
	switch m.locator.kind {
	case daRelayLocatorCommit:
		if m.locator.chunkIndex != 0 || len(m.payload) != 0 {
			return errDARelayMemberIncomplete
		}
	case daRelayLocatorChunk:
		if err := checkOwnerReadyChunkIndex(m.locator.chunkIndex); err != nil {
			return err
		}
		if err := checkOwnerReadyPayload(m.payload); err != nil {
			return err
		}
	default:
		return errDARelayMemberIncomplete
	}
	if err := checkOwnerReadyRetainedBytes(m.txBytes); err != nil {
		return err
	}
	return m.member.validate()
}

func checkOwnerReadyChunkIndex(chunkIndex uint16) error {
	if uint64(chunkIndex) >= consensus.MAX_DA_CHUNK_COUNT {
		return errDARelayChunkIndexOutOfRange
	}
	return nil
}

func checkOwnerReadyPayload(payload []byte) error {
	if len(payload) == 0 {
		return errDARelayMemberIncomplete
	}
	if uint64(len(payload)) > consensus.CHUNK_BYTES {
		return errDARelayChunkPayloadSizeInvalid
	}
	return nil
}

func checkOwnerReadyRetainedBytes(txBytes []byte) error {
	if len(txBytes) == 0 || len(txBytes) > consensus.MAX_RELAY_MSG_BYTES {
		return errDARelayMemberIncomplete
	}
	return nil
}

// checkOwnerReadyRecord reads no revision, so one check serves both the resident
// pre-state and the staged record. It reads the values installDASetRecordLocked
// publishes, so a record edited after staging is refused on the descriptor's terms.
//
// Legacy wireBytes is pinned to zero at all three levels — record, commit and
// chunk — which is the INVERSE of the legacy validators, which refuse a zero. That
// is the point: withoutPeerQuotaKey returns early on a zero record wireBytes, and
// its commit and chunk arms on a zero of their own, so no owner-ready image can
// reactivate that path. Owner-ready legacy wireBytes remains zero in every
// successor slice; separate role-specific accounting authority does not
// reactivate the legacy path.
func (r daRelaySetRecord) checkOwnerReadyRecord() error {
	// Only these two states have a charge formula here; the COMPLETE_SET domain
	// was not assigned to this slice.
	if r.state != daRelayStateOrphanChunks && r.state != daRelayStateStagedCommit {
		return errDARelayImageIncompatible
	}
	if r.wireBytes != 0 {
		return errDARelayImageIncompatible
	}
	if err := r.checkOwnerReadyCommitSlot(); err != nil {
		return err
	}
	for _, index := range sortedRetainedDAChunkIndexes(r) {
		if err := r.checkOwnerReadyChunk(index); err != nil {
			return err
		}
	}
	return nil
}

func (r daRelaySetRecord) checkOwnerReadyCommitSlot() error {
	if r.commit.wireBytes != 0 {
		return errDARelayImageIncompatible
	}
	if r.commit.member == nil {
		if r.commit.chunkCount != 0 || len(r.commit.txBytes) != 0 {
			return errDARelayMemberIncomplete
		}
		return nil
	}
	if r.commit.daID != r.daID {
		return errDARelayMemberIncomplete
	}
	if err := checkOwnerReadyRetainedBytes(r.commit.txBytes); err != nil {
		return err
	}
	return r.commit.member.validate()
}

func (r daRelaySetRecord) checkOwnerReadyChunk(index uint16) error {
	chunk := r.chunks[index]
	if chunk.chunkIndex != index || chunk.daID != r.daID {
		return errDARelayMemberIncomplete
	}
	if chunk.wireBytes != 0 {
		return errDARelayImageIncompatible
	}
	if err := checkOwnerReadyChunkIndex(index); err != nil {
		return err
	}
	if err := checkOwnerReadyPayload(chunk.payload); err != nil {
		return err
	}
	if err := checkOwnerReadyRetainedBytes(chunk.txBytes); err != nil {
		return err
	}
	return chunk.member.validate()
}
