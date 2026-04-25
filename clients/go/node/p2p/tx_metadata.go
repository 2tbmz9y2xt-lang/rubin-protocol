package p2p

import (
	"errors"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/node"
)

// CanonicalMempoolRelayMetadata is the lightweight metadata provider for
// CanonicalMempoolTxPool. Callers parse txBytes before metadata lookup; full
// policy/admission validation happens once in node.Mempool.AddTx via TxPool.Put.
func CanonicalMempoolRelayMetadata(txBytes []byte) (node.RelayTxMetadata, error) {
	return node.RelayTxMetadata{Size: len(txBytes)}, nil
}

func (s *Service) relayTxMetadata(txBytes []byte) (node.RelayTxMetadata, error) {
	if s == nil {
		return node.RelayTxMetadata{}, errors.New("nil service")
	}
	if _, ok := s.cfg.TxPool.(*CanonicalMempoolTxPool); ok {
		return CanonicalMempoolRelayMetadata(txBytes)
	}
	if s.cfg.TxMetadataFunc == nil {
		return node.RelayTxMetadata{}, errors.New("nil tx metadata func")
	}
	return s.cfg.TxMetadataFunc(txBytes)
}
