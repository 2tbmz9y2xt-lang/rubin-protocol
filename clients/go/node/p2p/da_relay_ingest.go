package p2p

import "github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"

func (s *Service) stageRelayDATx(peerAddr string, txBytes []byte, tx *consensus.Tx) error {
	if s == nil || s.daRelay == nil || tx == nil {
		return nil
	}
	wireBytes := uint64(len(txBytes))
	switch tx.TxKind {
	case 0x01:
		return s.stageRelayDACommitTx(peerAddr, wireBytes, tx)
	case 0x02:
		return s.stageRelayDAChunkTx(peerAddr, wireBytes, tx)
	default:
		return nil
	}
}

func (s *Service) stageRelayDACommitTx(peerAddr string, wireBytes uint64, tx *consensus.Tx) error {
	if tx.DaCommitCore == nil {
		return nil
	}
	commitment, ok := daRelayCommitPayloadCommitment(tx)
	if !ok {
		return nil
	}
	_, err := s.daRelay.addDACommit(peerAddr, daRelayCommit{
		daID:              tx.DaCommitCore.DaID,
		payloadCommitment: commitment,
		chunkCount:        tx.DaCommitCore.ChunkCount,
		wireBytes:         wireBytes,
	})
	return err
}

func (s *Service) stageRelayDAChunkTx(peerAddr string, wireBytes uint64, tx *consensus.Tx) error {
	if tx.DaChunkCore == nil {
		return nil
	}
	_, err := s.daRelay.addDAChunk(peerAddr, daRelayChunk{
		daID:       tx.DaChunkCore.DaID,
		chunkHash:  tx.DaChunkCore.ChunkHash,
		chunkIndex: tx.DaChunkCore.ChunkIndex,
		payload:    tx.DaPayload,
		wireBytes:  wireBytes,
	})
	return err
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
