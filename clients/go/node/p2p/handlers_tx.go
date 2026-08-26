package p2p

import (
	"errors"
	"fmt"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/node"
)

// handleTx is the remote TX entry. Its order is lifecycle and envelope bounds,
// then the canonical full-consumption parse, then tx_kind dispatch.
//
// A DA transaction (tx_kind 0x01 or 0x02) EXITS at that dispatch, before the
// seen-set, before relay-pool admission, before the metadata producer and before
// any MSG_TX announcement: remote DA has no standard residency and creates no
// standard state at all. The standard 0x00 path below is unchanged.
func (p *peer) handleTx(txBytes []byte) error {
	// Defense-in-depth oversize guard (parity with Rust
	// `tx_relay::handle_received_tx` oversize guard, surfaced as
	// `RelayTxOutcome::Oversized`). Envelope-level reader already caps tx
	// payload at MAX_BLOCK_BYTES via postHandshakePayloadCap in wire.go,
	// but an explicit MAX_RELAY_MSG_BYTES check here fails closed if that
	// upstream cap regresses and keeps ban-score parity with Rust's
	// malformed-input policy.
	if len(txBytes) > consensus.MAX_RELAY_MSG_BYTES {
		reason := fmt.Sprintf("tx payload exceeds MAX_RELAY_MSG_BYTES: %d > %d", len(txBytes), consensus.MAX_RELAY_MSG_BYTES)
		if p.bumpBan(10, reason) {
			return errors.New(reason)
		}
		return nil
	}
	tx, txid, err := parseCanonicalTx(txBytes)
	if err != nil {
		if p.bumpBan(10, err.Error()) {
			return err
		}
		return nil
	}
	if tx.TxKind == 0x01 || tx.TxKind == 0x02 {
		return p.handleRelayDATx(txBytes, tx)
	}
	if p.service.txSeen.Has(txid) {
		return nil
	}
	// Mark as seen BEFORE pool admission so that pool-full rejections still
	// suppress future getdata requests (prevents inv/getdata churn at capacity).
	if !p.service.txSeen.Add(txid) {
		return nil
	}
	if _, _, err := p.service.ensureRelayTxAdmitted(txid, txBytes, tx, true); err != nil {
		// Keep admission and metadata rejections peer-neutral for Go/Rust relay
		// parity: local policy/runtime state can reject a structurally valid tx,
		// and Rust surfaces the same branch as non-banworthy MetadataRejected.
		return nil //nolint:nilerr
	}
	_ = p.service.broadcastInventory(p, []InventoryVector{{Type: MSG_TX, Hash: txid}})
	return nil
}

// handleRelayDATx is the remote DA arm. The context-free shape and payload-hash
// check keeps its existing peer consequence, and PEER provenance is built from
// this peer's own address and its normalized quota key, so scoring and quota
// teardown name exactly one subject.
//
// A DUPLICATE COMMIT carries the existing negative peer effect
// (RUBIN_COMPACT_BLOCKS.md Section 5.1): a peer re-announcing a commit the node
// already retains is the case that adjustment exists for. A duplicate CHUNK is
// peer-neutral — chunks legitimately race between peers. Every other admission
// failure stays peer-neutral for the same Go/Rust relay-parity reason the
// standard path gives.
func (p *peer) handleRelayDATx(txBytes []byte, tx *consensus.Tx) error {
	if err := validateRelayDATxForAdmission(txBytes, tx); err != nil {
		if p.bumpBan(10, err.Error()) {
			return err
		}
		return nil
	}
	provenance, err := node.NewPeerDAProvenance(p.addr(), peerQuotaKey(p.addr()))
	if err != nil {
		return err
	}
	result, err := p.service.admitRelayDATx(p.addr(), txBytes, tx, provenance)
	if err != nil {
		return nil //nolint:nilerr // admission rejections are peer-neutral, exactly as on the standard path
	}
	if result.Disposition == node.DAAdmissionDuplicate && tx.TxKind == 0x01 {
		reason := fmt.Sprintf("duplicate da commit %x", result.DAID)
		if p.bumpBan(10, reason) {
			return errors.New(reason)
		}
	}
	return nil
}

func canonicalTxID(txBytes []byte) ([32]byte, error) {
	_, txid, err := parseCanonicalTx(txBytes)
	return txid, err
}

func parseCanonicalTx(txBytes []byte) (*consensus.Tx, [32]byte, error) {
	tx, txid, _, consumed, err := consensus.ParseTx(txBytes)
	if err != nil {
		return nil, [32]byte{}, err
	}
	if consumed != len(txBytes) {
		return nil, [32]byte{}, errors.New("non-canonical tx bytes")
	}
	return tx, txid, nil
}
