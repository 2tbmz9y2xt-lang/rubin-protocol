package p2p

import (
	"errors"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

func (p *peer) handleTx(txBytes []byte) error {
	txid, err := canonicalTxID(txBytes)
	if err != nil {
		if p.bumpBan(10, err.Error()) {
			return err
		}
		return nil
	}
	if !p.service.cfg.TxPool.Put(txid, txBytes) {
		return nil
	}
	if p.service.txSeen.Add(txid) {
		_ = p.service.broadcastInventory(p, []InventoryVector{{Type: MSG_TX, Hash: txid}})
	}
	return nil
}

func canonicalTxID(txBytes []byte) ([32]byte, error) {
	_, txid, _, consumed, err := consensus.ParseTx(txBytes)
	if err != nil {
		return [32]byte{}, err
	}
	if consumed != len(txBytes) {
		return [32]byte{}, errors.New("non-canonical tx bytes")
	}
	return txid, nil
}
