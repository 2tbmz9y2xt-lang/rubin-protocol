package p2p

import (
	"errors"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/node"
)

// admitRelayDATx is the Service's single seam onto the owner-coupled DA
// admission. It derives NOTHING from the wire beyond the exact transaction
// bytes: the da_id, role, chunk index, payload commitment, fee and ordered
// inputs a retained member carries all come from the admission's own snapshot of
// the transaction it validated.
//
// Prefetch scheduling is POST-admission and cannot remap the result: it only
// requests still-missing chunks for the set the admission concerned. It follows
// a STATE CHANGE, never a bare success: a DUPLICATE changed no record, so its
// set is missing exactly what it was already missing and any outstanding
// reservation still covers it. Scheduling on one would re-reserve those indexes
// and, once the earlier reservation expired, emit a fresh getdachunk — an
// observable effect the exact-replay path may not have
// (RUBIN_COMPACT_BLOCKS.md Section 5.1).
func (s *Service) admitRelayDATx(peerAddr string, txBytes []byte, tx *consensus.Tx, provenance node.DAProvenance) (node.DAAdmissionResult, error) {
	if s == nil || s.daRelay == nil {
		return node.DAAdmissionResult{}, errors.New("no DA relay state bound")
	}
	daID, ok := relayDASetID(tx)
	if !ok {
		return node.DAAdmissionResult{}, errors.New("transaction is not a DA commit or DA chunk")
	}
	result, err := s.daRelay.AdmitDA(txBytes, provenance)
	if err != nil {
		// A chunk-last payload-commitment mismatch retains nothing, so the set is
		// still missing exactly the chunks it was missing: re-request them.
		if errors.Is(err, node.ErrDARelayPayloadCommitmentMismatch) {
			s.scheduleDAPrefetch(peerAddr, daID)
		}
		return node.DAAdmissionResult{}, err
	}
	if result.Disposition == node.DAAdmissionRetained {
		s.scheduleDAPrefetch(peerAddr, daID)
	}
	return result, nil
}

func relayDASetID(tx *consensus.Tx) ([32]byte, bool) {
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

func validateRelayDATxForAdmission(txBytes []byte, tx *consensus.Tx) error {
	if tx == nil || tx.TxKind != 0x02 || tx.DaChunkCore == nil {
		return nil
	}
	return node.ValidateDARelayChunk(node.DARelayChunk{
		DAID:       tx.DaChunkCore.DaID,
		ChunkHash:  tx.DaChunkCore.ChunkHash,
		ChunkIndex: tx.DaChunkCore.ChunkIndex,
		Payload:    tx.DaPayload,
		WireBytes:  uint64(len(txBytes)),
	})
}
