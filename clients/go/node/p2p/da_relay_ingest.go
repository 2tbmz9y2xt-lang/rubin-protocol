package p2p

import (
	"crypto/sha3"
	"errors"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

func (s *Service) stageRelayDATx(peerAddr string, txBytes []byte, tx *consensus.Tx) error {
	if s == nil || s.daRelay == nil || tx == nil {
		return nil
	}
	wireBytes := uint64(len(txBytes))
	switch tx.TxKind {
	case 0x01:
		return s.stageRelayDACommitTx(peerAddr, txBytes, wireBytes, tx)
	case 0x02:
		return s.stageRelayDAChunkTx(peerAddr, txBytes, wireBytes, tx)
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
	record, err := s.daRelay.addDACommit(peerAddr, daRelayCommit{
		daID:              tx.DaCommitCore.DaID,
		payloadCommitment: commitment,
		chunkCount:        tx.DaCommitCore.ChunkCount,
		wireBytes:         wireBytes,
		txBytes:           txBytes,
	})
	return s.finishDAPrefetch(peerAddr, tx.DaCommitCore.DaID, record, err)
}

func (s *Service) stageRelayDAChunkTx(peerAddr string, txBytes []byte, wireBytes uint64, tx *consensus.Tx) error {
	if tx.DaChunkCore == nil {
		return nil
	}
	record, err := s.daRelay.addDAChunk(peerAddr, daRelayChunk{
		daID:       tx.DaChunkCore.DaID,
		chunkHash:  tx.DaChunkCore.ChunkHash,
		chunkIndex: tx.DaChunkCore.ChunkIndex,
		payload:    tx.DaPayload,
		wireBytes:  wireBytes,
		txBytes:    txBytes,
	})
	return s.finishDAPrefetch(peerAddr, tx.DaChunkCore.DaID, record, err)
}

func (s *Service) finishDAPrefetch(peerAddr string, daID [32]byte, record daRelaySetRecord, err error) error {
	if err == nil {
		s.scheduleDAPrefetch(peerAddr, record)
		return nil
	}
	if errors.Is(err, errDARelayPayloadCommitmentMismatch) {
		s.scheduleDAPrefetchSnapshot(peerAddr, daID)
	}
	return err
}

func validateRelayDATxForAdmission(txBytes []byte, tx *consensus.Tx) error {
	if tx == nil || tx.TxKind != 0x02 || tx.DaChunkCore == nil {
		return nil
	}
	chunk := daRelayChunk{
		daID:       tx.DaChunkCore.DaID,
		chunkHash:  tx.DaChunkCore.ChunkHash,
		chunkIndex: tx.DaChunkCore.ChunkIndex,
		payload:    tx.DaPayload,
		wireBytes:  uint64(len(txBytes)),
	}
	if err := validateDAChunk(chunk); err != nil {
		return err
	}
	if sha3.Sum256(tx.DaPayload) != tx.DaChunkCore.ChunkHash {
		return errDARelayChunkHashMismatch
	}
	return nil
}

func (s *Service) scheduleDAPrefetchSnapshot(peerAddr string, daID [32]byte) {
	s.scheduleDAPrefetch(peerAddr, daRelaySetRecord{daID: daID})
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
