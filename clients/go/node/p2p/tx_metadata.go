package p2p

import (
	"errors"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/node"
)

func (s *Service) relayTxMetadata(txBytes []byte) (node.RelayTxMetadata, error) {
	if s == nil {
		return node.RelayTxMetadata{}, errors.New("nil service")
	}
	if s.cfg.TxMetadataFunc == nil {
		return node.RelayTxMetadata{}, errors.New("nil tx metadata func")
	}
	return s.cfg.TxMetadataFunc(txBytes)
}
