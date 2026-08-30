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

// A commit locator must carry chunk index 0, or two locators for one slot would
// compare unequal. Every absolute bound below has ONE definition, shared with the
// record path that installDASetRecordLocked publishes. The descriptor carries neither the DECLARED
// chunk count nor wire_bytes, so this validator binds neither; the record path
// pins wire_bytes to zero and only PRESERVES a chunk count it never ranges —
// RUB-1273 owns the layer that assigns either.
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
// reactivate that path. RUB-1273 owns the layer that assigns a nonzero one.
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
