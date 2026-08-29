package node

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

// A zero txid is the "slot is empty" marker. Token and fee are deliberately NOT
// checked: a zero token is permitted before the owner reserve.
func (m daRelayMemberIdentity) validate() error {
	if m.txid == ([32]byte{}) || m.wtxid == ([32]byte{}) {
		return errDARelayMemberIncomplete
	}
	if len(m.inputs) == 0 {
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
// compare unequal. The chunk index is NOT range-checked against the commit's
// declared chunk count: that bound belongs to admission.
func (m daRelayOwnerReadyMember) validate() error {
	switch m.locator.kind {
	case daRelayLocatorCommit:
		if m.locator.chunkIndex != 0 || len(m.payload) != 0 {
			return errDARelayMemberIncomplete
		}
	case daRelayLocatorChunk:
		if len(m.payload) == 0 {
			return errDARelayMemberIncomplete
		}
	default:
		return errDARelayMemberIncomplete
	}
	if len(m.txBytes) == 0 {
		return errDARelayMemberIncomplete
	}
	return m.member.validate()
}

// validateOwnerReady refuses a RESIDENT record this kernel could not have
// produced, mapping every incoherence to one image-class error. A legacy record
// carries revision 0, so it is INCOMPATIBLE input — never an absent one, which
// the projector decides from the s.sets lookup alone.
func (r daRelaySetRecord) validateOwnerReady() error {
	if r.revision == 0 || r.checkOwnerReadyRecord() != nil {
		return errDARelayImageIncompatible
	}
	return nil
}

// ownerReadyState covers only the states this kernel's charge formula is defined
// for; Section 18.1 gives COMPLETE_SET a domain this slice was not assigned.
func (r daRelaySetRecord) ownerReadyState() bool {
	return r.state == daRelayStateOrphanChunks || r.state == daRelayStateStagedCommit
}

// checkOwnerReadyRecord proves one record internally COHERENT, not merely that
// its members individually validate. Shared by the pre-state and the staged
// record, so it carries no revision check — a staged record is unstamped.
func (r daRelaySetRecord) checkOwnerReadyRecord() error {
	if !r.ownerReadyState() {
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

// checkOwnerReadyCommitSlot treats a nonzero txid as occupancy, so legacy
// metadata without one is refused rather than read as empty.
func (r daRelaySetRecord) checkOwnerReadyCommitSlot() error {
	if r.commit.member.txid == ([32]byte{}) {
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

// checkOwnerReadyChunk refuses a chunk whose map key is not its own index.
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
