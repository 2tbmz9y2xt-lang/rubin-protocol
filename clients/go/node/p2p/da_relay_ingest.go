package p2p

import (
	"errors"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/node"
)

func (s *Service) stageRelayDATx(peerAddr string, txBytes []byte, tx *consensus.Tx, hashChecked ...bool) error {
	if s == nil || s.daRelay == nil || tx == nil {
		return nil
	}
	wireBytes := uint64(len(txBytes))
	checked := len(hashChecked) != 0 && hashChecked[0]
	switch tx.TxKind {
	case 0x01:
		return s.stageRelayDACommitTx(peerAddr, txBytes, wireBytes, tx)
	case 0x02:
		return s.stageRelayDAChunkTx(peerAddr, txBytes, wireBytes, tx, checked)
	default:
		return nil
	}
}

func (s *Service) stageRelayDACommitTx(peerAddr string, txBytes []byte, wireBytes uint64, tx *consensus.Tx) error {
	if tx.DaCommitCore == nil {
		return nil
	}
	commitment, ok := daRelayCommitPayloadCommitment(tx)
	if !ok {
		return nil
	}
	err := s.daRelay.StageCommit(peerQuotaKey(peerAddr), node.DARelayCommit{
		DAID:              tx.DaCommitCore.DaID,
		PayloadCommitment: commitment,
		ChunkCount:        tx.DaCommitCore.ChunkCount,
		WireBytes:         wireBytes,
		TxBytes:           txBytes,
	})
	return s.finishDAPrefetch(peerAddr, tx.DaCommitCore.DaID, err)
}

func (s *Service) stageRelayDAChunkTx(peerAddr string, txBytes []byte, wireBytes uint64, tx *consensus.Tx, hashChecked bool) error {
	if tx.DaChunkCore == nil {
		return nil
	}
	err := s.daRelay.StageChunk(peerQuotaKey(peerAddr), node.DARelayChunk{
		DAID:        tx.DaChunkCore.DaID,
		ChunkHash:   tx.DaChunkCore.ChunkHash,
		ChunkIndex:  tx.DaChunkCore.ChunkIndex,
		Payload:     tx.DaPayload,
		WireBytes:   wireBytes,
		TxBytes:     txBytes,
		HashChecked: hashChecked,
	})
	return s.finishDAPrefetch(peerAddr, tx.DaChunkCore.DaID, err)
}

func (s *Service) finishDAPrefetch(peerAddr string, daID [32]byte, err error) error {
	if err == nil {
		s.scheduleDAPrefetch(peerAddr, daID)
		return nil
	}
	if errors.Is(err, node.ErrDARelayPayloadCommitmentMismatch) {
		s.scheduleDAPrefetchSnapshot(peerAddr, daID)
	}
	return err
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

func (s *Service) scheduleDAPrefetchSnapshot(peerAddr string, daID [32]byte) {
	s.scheduleDAPrefetch(peerAddr, daID)
}

func daRelayCommitPayloadCommitment(tx *consensus.Tx) ([32]byte, bool) {
	var commitment [32]byte
	count := 0
	for _, output := range tx.Outputs {
		if output.CovenantType != consensus.COV_TYPE_DA_COMMIT {
			continue
		}
		if len(output.CovenantData) != len(commitment) {
			return [32]byte{}, false
		}
		count++
		copy(commitment[:], output.CovenantData)
	}
	return commitment, count == 1
}
