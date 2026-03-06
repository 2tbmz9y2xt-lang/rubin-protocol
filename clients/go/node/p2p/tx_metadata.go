package p2p

import "github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/node"

func (s *Service) relayTxMetadata(txBytes []byte) (node.RelayTxMetadata, error) {
	if s != nil && s.cfg.TxMetadataFunc != nil {
		return s.cfg.TxMetadataFunc(txBytes)
	}
	return node.RelayTxMetadata{
		Fee:  0,
		Size: len(txBytes),
	}, nil
}
