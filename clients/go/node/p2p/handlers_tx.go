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
// standard state at all. The standard 0x00 path in handleStandardTx is
// unchanged.
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
	return p.handleStandardTx(txBytes, tx, txid)
}

// handleStandardTx is the remote standard arm (tx_kind 0x00): the seen-set,
// relay-pool admission and the MSG_TX announcement, reached only after
// handleTx's dispatch.
func (p *peer) handleStandardTx(txBytes []byte, tx *consensus.Tx, txid [32]byte) error {
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

// handleRelayDATx is the remote DA arm: the context-free shape and payload-hash
// check keeps its existing peer consequence, and PEER provenance is built from
// this peer's own address and its normalized quota key.
//
// The ONLY negative peer effect the ADMISSION contributes is the existing +10,
// applied from its SameDAIDCommitConflict bool AND this arm's PEER provenance —
// never from tx kind, error text or DUPLICATE alone (RUBIN_COMPACT_BLOCKS.md
// Section 5.1); every other outcome is peer-neutral, as on the standard path.
//
// The address is read ONCE and both identities derive from that one value, so
// scoring and quota accounting name one subject. A REGISTERED peer cannot carry
// an empty address — the handshake binds it (handshake.go:46) and registerPeer
// keys the quota lock by it (service_peer_lifecycle.go:79) — but the arm is TOTAL
// regardless: an addressless peer is refused and the read loop drops the
// connection (peer_runtime.go:249), with nothing retained and no score moved.
//
// On a live engine the whole admission runs under THIS quota identity's key lock,
// the one registration and teardown take (service_peer_lifecycle.go:80, :103,
// :141), so an admission and the teardown of one quota key serialize while two
// different keys still progress independently. It is the OUTERMOST lock of the
// admission order — key, then the read guard, then DARelayState.mu, then the
// owner — the order every existing holder of this key already takes, so no
// schedule inverts, and the defer releases it on every exit.
//
// The key is skipped on an ALREADY-LATCHED engine, the same best-effort check
// releaseDAQuotaIfInactiveLocked makes and NOT a lock order: acquireDAAdmissionHold
// waits on a fence a terminal transition never releases (beginCanonicalTransition
// write-locks admissionMu at sync.go:925 and the terminal arm of
// canonicalTransition.end latches at sync.go:955 without unlocking it), so taking
// the key across that wait would park unregisterPeer for it. TerminalFaulted() is
// read OUTSIDE the state it judges, so a latch landing after this check still
// parks this call WITH the key, and peer teardown for that key parks with it: the
// A12/F13 residual, admitted until restart or process termination.
func (p *peer) handleRelayDATx(txBytes []byte, tx *consensus.Tx) error {
	if err := validateRelayDATxForAdmission(txBytes, tx); err != nil {
		if p.bumpBan(10, err.Error()) {
			return err
		}
		return nil
	}
	addr := p.addr()
	quotaKey := peerQuotaKey(addr)
	provenance, err := node.NewPeerDAProvenance(addr, quotaKey)
	if err != nil {
		return err
	}
	if !p.service.cfg.SyncEngine.TerminalFaulted() {
		defer p.service.lockPeerQuotaKey(quotaKey)()
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
