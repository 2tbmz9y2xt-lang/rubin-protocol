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

// quotaKey is the ONLY source of the per-peer accounting key: derived on every
// use, never stored beside the provenance, so no member can present one source
// with another's charge, and the legacy peerQuotaKey is never an input. A
// peerless source, and every kind outside the closed set, derives the EMPTY key —
// a shared per-peer bucket, not an exemption: addPeerAccounting charges "" like
// any other key, under the same cap. A malformed PEER may still derive its own
// quota string; validate refuses it before any accounting.
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

// validate runs only where a member is required, so nil — the empty-slot marker —
// is refused here rather than read as an empty slot; the slot tests decide
// emptiness from the pointer. Token and fee are deliberately NOT checked: a zero
// token is permitted before the owner reserve.
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
// compare unequal. A chunk index at or above MAX_DA_CHUNK_COUNT and a payload
// above CHUNK_BYTES are refused on the package's absolute bounds; the commit's
// DECLARED chunk count stays admission's. wire_bytes and chunk_count go
// unchecked: this kernel assigns neither, and RUB-1273 owns the layer that does.
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
	if len(m.txBytes) == 0 {
		return errDARelayMemberIncomplete
	}
	return m.member.validate()
}

// checkOwnerReadyRecord proves one record internally COHERENT, not merely that
// its members individually validate. Shared by the pre-state and the staged
// record, so it carries no revision check — a staged record is unstamped.
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

// checkOwnerReadyCommitSlot treats a NON-nil member as occupancy, so legacy
// metadata carrying none is refused rather than read as empty, and a member
// present but incomplete is refused by validate rather than mistaken for absent.
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

// checkOwnerReadyChunk refuses a chunk whose map key is not its own index. The
// absolute index and payload bounds are daRelayOwnerReadyMember.validate's, not
// this record-level check's.
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
