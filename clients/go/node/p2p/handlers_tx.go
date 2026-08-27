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
	// Mark as seen BEFORE pool admission so that pool-full rejections still
	// suppress future getdata requests (prevents inv/getdata churn at capacity).
	// Add is the one seen-set authority: it reports false for an already-seen
	// txid, so no separate Has pre-check exists.
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
// The ONLY negative peer effect on this arm is the existing +10 for
// SameDAIDCommitConflict — a FULLY VALIDATED different-txid DA_COMMIT_TX
// competing with the retained same-da_id first-seen commit, reported by the
// admission's own bool AND applied here only because this arm's provenance is
// PEER. The effect is never derived from tx kind, from error text or from
// DUPLICATE alone (RUBIN_COMPACT_BLOCKS.md Section 5.1): an exact retained
// commit or chunk replay — requested or unsolicited — and a valid same-txid
// nonexact candidate are peer-neutral DUPLICATE, and every admission failure
// stays peer-neutral for the same Go/Rust relay-parity reason the standard
// path gives.
//
// The address is read ONCE and both identities are derived from that one value,
// so scoring and quota accounting can never name two different subjects. A
// REGISTERED peer cannot carry an empty address — the handshake binds it from
// the connection (handshake.go:46) and registerPeer already keyed this peer's
// quota lock by it (service_peer_lifecycle.go:79) — but the arm is TOTAL
// regardless: an addressless peer can be neither scored nor quota-charged, so
// retaining for it would break the per-peer accounting invariant. It is refused
// and the read loop drops the connection (peer_runtime.go:249) instead, with
// nothing retained and no score moved.
func (p *peer) handleRelayDATx(txBytes []byte, tx *consensus.Tx) error {
	if err := validateRelayDATxForAdmission(txBytes, tx); err != nil {
		if p.bumpBan(10, err.Error()) {
			return err
		}
		return nil
	}
	addr := p.addr()
	provenance, err := node.NewPeerDAProvenance(addr, peerQuotaKey(addr))
	if err != nil {
		return err
	}
	result, err := p.service.admitRelayDATx(addr, txBytes, tx, provenance)
	if err != nil {
		return nil //nolint:nilerr // admission rejections are peer-neutral, exactly as on the standard path
	}
	if result.SameDAIDCommitConflict {
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
