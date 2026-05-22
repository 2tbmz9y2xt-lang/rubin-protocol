package p2p

import (
	"encoding/binary"
	"errors"
	"time"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

const compactOutstandingRequestTTL = 15 * time.Second

type compactModeSnapshot struct {
	Mode    uint8
	Version uint64
}

type peerCompactRelayState struct {
	remoteMode  compactModeSnapshot
	outstanding *compactOutstandingRequest
}

type compactOutstandingRequest struct {
	BlockHash          [32]byte
	Header             [consensus.BLOCK_HEADER_BYTES]byte
	MissingIndexes     []uint64
	MissingShortIDs    []compactShortID
	Transactions       [][]byte
	Nonce1             uint64
	Nonce2             uint64
	BlockTxnPayloadCap uint32
	ExpiresAt          time.Time
}

func (p *peer) handleSendCmpct(payload []byte) error {
	msg, err := parseSendCmpctRuntimePayload(payload)
	if err != nil {
		return err
	}
	p.setRemoteCompactMode(compactModeSnapshot{Mode: msg.Mode, Version: msg.Version})
	return nil
}

func parseSendCmpctRuntimePayload(payload []byte) (sendCmpctPayload, error) {
	if len(payload) != sendCmpctPayloadBytes {
		return sendCmpctPayload{}, errors.New("sendcmpct payload width mismatch")
	}
	out := sendCmpctPayload{Mode: payload[0], Version: binary.LittleEndian.Uint64(payload[1:])}
	if out.Version != compactRelayVersion {
		return sendCmpctPayload{}, errors.New("unsupported compact relay version")
	}
	if out.Mode > 2 {
		return sendCmpctPayload{}, errors.New("unsupported compact relay mode")
	}
	return out, nil
}

func (p *peer) setRemoteCompactMode(mode compactModeSnapshot) {
	p.compactMu.Lock()
	p.compact.remoteMode = mode
	p.compactMu.Unlock()
}

func (p *peer) remoteCompactMode() compactModeSnapshot {
	p.compactMu.Lock()
	defer p.compactMu.Unlock()
	return p.compact.remoteMode
}

func (p *peer) setCompactOutstandingRequest(req compactOutstandingRequest) {
	stored := cloneCompactOutstandingRequest(req)
	p.compactMu.Lock()
	p.compact.outstanding = &stored
	p.compactMu.Unlock()
}

func (p *peer) activateCompactOutstandingRequest(req compactOutstandingRequest) {
	req.ExpiresAt = p.service.cfg.Now().Add(compactOutstandingRequestTTL)
	p.setCompactOutstandingRequest(req)
}

func (p *peer) sendCompactOutstandingRequest(req compactOutstandingRequest) error {
	payload, err := encodeGetBlockTxnPayload(getBlockTxnPayload{
		BlockHash: req.BlockHash,
		Indexes:   req.MissingIndexes,
	})
	if err != nil {
		return err
	}
	if err := p.send(messageGetBlockTxn, payload); err != nil {
		return err
	}
	p.activateCompactOutstandingRequest(req)
	return nil
}

func (p *peer) compactOutstandingRequestSnapshot() (compactOutstandingRequest, bool) {
	p.compactMu.Lock()
	if p.compact.outstanding == nil {
		p.compactMu.Unlock()
		return compactOutstandingRequest{}, false
	}
	if p.compactOutstandingRequestExpiredLocked() {
		p.compact.outstanding = nil
		p.compactMu.Unlock()
		return compactOutstandingRequest{}, false
	}
	// Stored outstanding requests are immutable; keep large tx-byte cloning outside compactMu.
	req := *p.compact.outstanding
	p.compactMu.Unlock()
	return cloneCompactOutstandingRequest(req), true
}

func (p *peer) compactOutstandingBlockHash() ([32]byte, bool) {
	p.compactMu.Lock()
	defer p.compactMu.Unlock()
	if p.compact.outstanding == nil {
		return [32]byte{}, false
	}
	if p.compactOutstandingRequestExpiredLocked() {
		p.compact.outstanding = nil
		return [32]byte{}, false
	}
	return p.compact.outstanding.BlockHash, true
}

func (p *peer) popCompactOutstandingRequest() (compactOutstandingRequest, bool) {
	p.compactMu.Lock()
	if p.compact.outstanding == nil {
		p.compactMu.Unlock()
		return compactOutstandingRequest{}, false
	}
	if p.compactOutstandingRequestExpiredLocked() {
		p.compact.outstanding = nil
		p.compactMu.Unlock()
		return compactOutstandingRequest{}, false
	}
	// Stored outstanding requests are immutable; keep large tx-byte cloning outside compactMu.
	req := *p.compact.outstanding
	p.compact.outstanding = nil
	p.compactMu.Unlock()
	return cloneCompactOutstandingRequest(req), true
}

func (p *peer) clearCompactOutstandingRequestForBlock(blockHash [32]byte) {
	p.compactMu.Lock()
	if p.compact.outstanding != nil && p.compact.outstanding.BlockHash == blockHash {
		p.compact.outstanding = nil
	}
	p.compactMu.Unlock()
}

func (p *peer) clearCompactOutstandingRequest() {
	p.compactMu.Lock()
	p.compact.outstanding = nil
	p.compactMu.Unlock()
}

func (p *peer) compactOutstandingRequestExpiredLocked() bool {
	if p.compact.outstanding == nil || p.compact.outstanding.ExpiresAt.IsZero() {
		return false
	}
	return !p.service.cfg.Now().Before(p.compact.outstanding.ExpiresAt)
}

func cloneCompactOutstandingRequest(req compactOutstandingRequest) compactOutstandingRequest {
	req.MissingIndexes = append([]uint64(nil), req.MissingIndexes...)
	req.MissingShortIDs = append([]compactShortID(nil), req.MissingShortIDs...)
	req.Transactions = cloneCompactTransactions(req.Transactions)
	return req
}

func (p *peer) blockTxnPayloadCap() uint32 {
	p.compactMu.Lock()
	defer p.compactMu.Unlock()
	if p.compact.outstanding == nil {
		return 0
	}
	if p.compactOutstandingRequestExpiredLocked() {
		p.compact.outstanding = nil
		return 0
	}
	if maxCap := compactRelayPayloadCap(messageBlockTxn); p.compact.outstanding.BlockTxnPayloadCap > maxCap {
		return maxCap
	}
	return p.compact.outstanding.BlockTxnPayloadCap
}
