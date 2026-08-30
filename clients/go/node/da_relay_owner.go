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
// another's charge. The EMPTY key is a shared bucket, charged and capped like any.
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

// validate runs only where a member is required, so nil — the empty-slot marker — is
// refused here; a commit slot's emptiness is that pointer, a chunk slot's its map key.
// Token and fee are deliberately NOT checked: a zero token precedes the owner reserve.
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
// compare unequal. The bounds here are the package's absolute ones; the DECLARED
// chunk count and wire_bytes reach no check — RUB-1273 owns the layer that assigns.
func (m daRelayOwnerReadyMember) validate() error {
	switch m.locator.kind {
	case daRelayLocatorCommit:
		if m.locator.chunkIndex != 0 || len(m.payload) != 0 {
			return errDARelayMemberIncomplete
		}
	case daRelayLocatorChunk:
		if uint64(m.locator.chunkIndex) >= consensus.MAX_DA_CHUNK_COUNT {
			return errDARelayChunkIndexOutOfRange
		}
		if len(m.payload) == 0 {
			return errDARelayMemberIncomplete
		}
		if uint64(len(m.payload)) > consensus.CHUNK_BYTES {
			return errDARelayChunkPayloadSizeInvalid
		}
	default:
		return errDARelayMemberIncomplete
	}
	if len(m.txBytes) == 0 || len(m.txBytes) > consensus.MAX_RELAY_MSG_BYTES {
		return errDARelayMemberIncomplete
	}
	return m.member.validate()
}

// checkOwnerReadyRecord reads no revision, so one check serves both the resident
// pre-state and the staged record, whatever stamp each has.
func (r daRelaySetRecord) checkOwnerReadyRecord() error {
	// Only these two states have a charge formula here; the COMPLETE_SET domain
	// was not assigned to this slice.
	if r.state != daRelayStateOrphanChunks && r.state != daRelayStateStagedCommit {
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
	if r.commit.member == nil {
		if r.commit.chunkCount != 0 || len(r.commit.txBytes) != 0 {
			return errDARelayMemberIncomplete
		}
		return nil
	}
	if r.commit.daID != r.daID || len(r.commit.txBytes) == 0 {
		return errDARelayMemberIncomplete
	}
	return r.commit.member.validate()
}

func (r daRelaySetRecord) checkOwnerReadyChunk(index uint16) error {
	chunk := r.chunks[index]
	if chunk.chunkIndex != index || chunk.daID != r.daID {
		return errDARelayMemberIncomplete
	}
	if len(chunk.txBytes) == 0 || len(chunk.payload) == 0 {
		return errDARelayMemberIncomplete
	}
	return chunk.member.validate()
}
