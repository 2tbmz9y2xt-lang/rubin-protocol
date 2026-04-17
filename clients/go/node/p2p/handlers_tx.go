package p2p

import (
	"errors"
	"fmt"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

func (p *peer) handleTx(txBytes []byte) error {
	// Defense-in-depth oversize guard (parity with Rust
	// clients/rust/crates/rubin-node/src/tx_relay.rs:290-296).
	// Envelope-level reader already caps tx payload at MAX_BLOCK_BYTES via
	// postHandshakePayloadCap in wire.go, but an explicit MAX_RELAY_MSG_BYTES
	// check here fails closed if that upstream cap regresses and keeps ban-score
	// parity with Rust's malformed-input policy.
	if len(txBytes) > consensus.MAX_RELAY_MSG_BYTES {
		reason := fmt.Sprintf("tx payload exceeds MAX_RELAY_MSG_BYTES: %d > %d", len(txBytes), consensus.MAX_RELAY_MSG_BYTES)
		if p.bumpBan(10, reason) {
			return errors.New(reason)
		}
		return nil
	}
	txid, err := canonicalTxID(txBytes)
	if err != nil {
		if p.bumpBan(10, err.Error()) {
			return err
		}
		return nil
	}
	// Mark as seen BEFORE pool admission so that pool-full rejections still
	// suppress future getdata requests (prevents inv/getdata churn at capacity).
	isNew := p.service.txSeen.Add(txid)
	if !isNew {
		return nil
	}
	meta, err := p.service.relayTxMetadata(txBytes)
	if err != nil {
		return nil
	}
	if !p.service.cfg.TxPool.Put(txid, txBytes, meta.Fee, meta.Size) {
		return nil
	}
	_ = p.service.broadcastInventory(p, []InventoryVector{{Type: MSG_TX, Hash: txid}})
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
