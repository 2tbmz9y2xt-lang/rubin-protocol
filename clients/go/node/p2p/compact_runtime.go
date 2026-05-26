package p2p

import (
	"context"
	"encoding/binary"
	"errors"
	"time"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

const (
	compactOutstandingRequestTTL = 15 * time.Second
	compactAnnouncedBlockLimit   = 16
)

type compactModeSnapshot struct {
	Mode    uint8
	Version uint64
}

type peerCompactRelayState struct {
	remoteMode  compactModeSnapshot
	outstanding *compactOutstandingRequest
	announced   []compactBlockAnnouncement
}

type compactBlockAnnouncement struct {
	blockHash [32]byte
	sent      bool
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

func (p *peer) advertiseLocalCompactMode() error {
	payload := consensus.AppendU64le([]byte{0}, compactRelayVersion)
	return p.send(messageSendCmpct, payload)
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

func (*peer) handleGetDAChunk(payload []byte) error {
	_, err := decodeGetDAChunkPayload(payload)
	return err
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

func compactAnnouncementHashForSentMessage(command string, payload []byte) ([32]byte, bool) {
	var zero [32]byte
	if command != messageCmpctBlock {
		return zero, false
	}
	header, ok := cmpctBlockHeaderValidationCandidate(payload)
	if !ok {
		return zero, false
	}
	blockHash, _ := consensus.BlockHash(header[:]) // fixed-size header slice cannot hit the length error path
	return blockHash, true
}

func (p *peer) markCompactBlockAnnounced(blockHash [32]byte) {
	p.compactMu.Lock()
	defer p.compactMu.Unlock()
	p.appendCompactBlockAnnouncementLocked(blockHash, true)
	p.trimCompactBlockAnnouncementsLocked()
}

func (p *peer) beginCompactBlockAnnouncementSend(blockHash [32]byte) {
	p.compactMu.Lock()
	defer p.compactMu.Unlock()
	p.appendCompactBlockAnnouncementLocked(blockHash, false)
}

func (p *peer) finishCompactBlockAnnouncementSend(blockHash [32]byte, sendErr error) {
	p.compactMu.Lock()
	defer p.compactMu.Unlock()
	if sendErr != nil {
		p.removeCompactBlockAnnouncementBySentLocked(blockHash, false)
		return
	}
	p.publishCompactBlockAnnouncementLocked(blockHash)
	p.trimCompactBlockAnnouncementsLocked()
}

func (p *peer) appendCompactBlockAnnouncementLocked(blockHash [32]byte, sent bool) {
	p.compact.announced = append(p.compact.announced, compactBlockAnnouncement{blockHash: blockHash, sent: sent})
}

func (p *peer) publishCompactBlockAnnouncementLocked(blockHash [32]byte) {
	for idx := len(p.compact.announced) - 1; idx >= 0; idx-- {
		if p.compact.announced[idx].blockHash == blockHash {
			p.compact.announced[idx].sent = true
			return
		}
	}
}

func (p *peer) trimCompactBlockAnnouncementsLocked() {
	for len(p.compact.announced) > compactAnnouncedBlockLimit {
		copy(p.compact.announced, p.compact.announced[1:])
		p.compact.announced[len(p.compact.announced)-1] = compactBlockAnnouncement{}
		p.compact.announced = p.compact.announced[:len(p.compact.announced)-1]
	}
}

func (p *peer) consumeCompactBlockAnnouncement(blockHash [32]byte) bool {
	p.compactMu.Lock()
	defer p.compactMu.Unlock()
	return p.removeCompactBlockAnnouncementLocked(blockHash)
}

func (p *peer) removeCompactBlockAnnouncementLocked(blockHash [32]byte) bool {
	return p.removeCompactBlockAnnouncementBySentLocked(blockHash, true)
}

func (p *peer) removeCompactBlockAnnouncementBySentLocked(blockHash [32]byte, sent bool) bool {
	for idx := len(p.compact.announced) - 1; idx >= 0; idx-- {
		if p.compact.announced[idx].blockHash != blockHash || p.compact.announced[idx].sent != sent {
			continue
		}
		copy(p.compact.announced[idx:], p.compact.announced[idx+1:])
		p.compact.announced[len(p.compact.announced)-1] = compactBlockAnnouncement{}
		p.compact.announced = p.compact.announced[:len(p.compact.announced)-1]
		return true
	}
	return false
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
		p.compactMu.Unlock()
		return compactOutstandingRequest{}, false
	}
	// Stored outstanding requests are immutable; keep large tx-byte cloning outside compactMu.
	req := *p.compact.outstanding
	p.compact.outstanding = nil
	p.compactMu.Unlock()
	return cloneCompactOutstandingRequest(req), true
}

func (p *peer) popExpiredCompactOutstandingBlockHashAndPayloadCap() ([32]byte, uint32, bool) {
	p.compactMu.Lock()
	defer p.compactMu.Unlock()
	if p.compact.outstanding == nil || !p.compactOutstandingRequestExpiredLocked() {
		return [32]byte{}, 0, false
	}
	blockHash := p.compact.outstanding.BlockHash
	blockTxnPayloadCap := p.compact.outstanding.BlockTxnPayloadCap
	p.compact.outstanding = nil
	return blockHash, blockTxnPayloadCap, true
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
		return 0
	}
	cap := p.compact.outstanding.BlockTxnPayloadCap
	if maxCap := compactRelayPayloadCap(messageBlockTxn); cap > maxCap {
		cap = maxCap
	}
	return cap
}

func (p *peer) handleExpiredCompactOutstanding(ctx context.Context) (bool, error) {
	if peerRunContextDone(ctx) {
		return false, nil
	}
	blockHash, _, ok := p.popExpiredCompactOutstandingBlockHashAndPayloadCap()
	if !ok {
		return false, nil
	}
	if peerRunContextDone(ctx) {
		return false, nil
	}
	body := append([]byte{MSG_BLOCK}, blockHash[:]...)
	return true, p.send(messageGetData, body)
}

func (p *peer) compactOutstandingExpiry() (time.Time, bool) {
	p.compactMu.Lock()
	defer p.compactMu.Unlock()
	if p.compact.outstanding == nil || p.compact.outstanding.ExpiresAt.IsZero() {
		return time.Time{}, false
	}
	return p.compact.outstanding.ExpiresAt, true
}
