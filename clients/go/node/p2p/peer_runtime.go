package p2p

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/node"
)

type postHandshakeUnknownCommandError struct {
	command string
}

func (e postHandshakeUnknownCommandError) Error() string {
	return fmt.Sprintf("unknown message type: %s", e.command)
}

func (e postHandshakeUnknownCommandError) peerReason() string {
	return fmt.Sprintf("unknown command: %s", e.command)
}

type blockTxnStaleBodyError struct{}

func (e blockTxnStaleBodyError) Error() string {
	return "stale blocktxn response has body"
}

func (p *peer) run(ctx context.Context) error {
	for {
		if peerRunContextDone(ctx) {
			return nil
		}
		if err := p.setReadDeadline(); err != nil {
			return err
		}
		frame, err := p.readPostHandshakeFrame()
		if err != nil {
			if shouldIgnoreReadError(err) {
				continue
			}
			return normalizeReadError(err)
		}
		if err := p.handleMessage(frame); err != nil {
			return err
		}
	}
}

const blockTxnHashPayloadBytes = 32

func (p *peer) readPostHandshakeFrame() (message, error) {
	var frame message
	header, err := readFrameHeader(
		p.conn,
		networkMagic(p.service.cfg.PeerRuntimeConfig.Network),
		p.service.cfg.PeerRuntimeConfig.MaxMessageSize,
	)
	if err != nil {
		return frame, err
	}
	if header.Command == messageBlockTxn && p.acceptsBlockTxnResponses() {
		return p.readBlockTxnFrame(header)
	}
	limit := p.postHandshakePayloadCap()
	if header.Size > limit(header.Command) {
		return frame, commandPayloadCapError{command: header.Command}
	}
	payload, err := readPayloadWithChecksum(p.conn, header.Size, header.Checksum)
	if err != nil {
		return frame, err
	}
	return message{Command: header.Command, Payload: payload}, nil
}

func (p *peer) readBlockTxnFrame(header frameHeader) (message, error) {
	cap := p.blockTxnPayloadCap()
	if cap == 0 {
		return p.readUnexpectedBlockTxnFrame(header)
	}
	if header.Size > cap {
		if stale, err := p.readOversizedBlockTxnStaleHash(header); err != nil || stale {
			return message{}, err
		}
		return message{}, commandPayloadCapError{command: header.Command}
	}
	if header.Size > blockTxnHashPayloadBytes {
		return p.readMatchedBlockTxnFrame(header)
	}
	return p.readFullCommandFramePayload(header)
}

func (p *peer) readOversizedBlockTxnStaleHash(header frameHeader) (bool, error) {
	if header.Size <= blockTxnHashPayloadBytes {
		return false, nil
	}
	var responseHash [32]byte
	n, err := io.ReadFull(p.conn, responseHash[:])
	if err != nil {
		return false, payloadReadError(header.Size, 0, n, err)
	}
	blockHash, ok := p.compactOutstandingBlockHash()
	if !ok || responseHash != blockHash {
		return true, errors.New("stale blocktxn response has body")
	}
	return false, nil
}

func (p *peer) readUnexpectedBlockTxnFrame(header frameHeader) (message, error) {
	if header.Size > blockTxnHashPayloadBytes {
		return message{}, commandPayloadCapError{command: header.Command}
	}
	return p.readFullCommandFramePayload(header)
}

func (p *peer) readFullCommandFramePayload(header frameHeader) (message, error) {
	payload, err := readPayloadWithChecksum(p.conn, header.Size, header.Checksum)
	if err != nil {
		return message{}, err
	}
	return message{Command: header.Command, Payload: payload}, nil
}

func (p *peer) readMatchedBlockTxnFrame(header frameHeader) (message, error) {
	prefix, err := readPayloadPrefix(p.conn, header.Size, blockTxnHashPayloadBytes)
	if err != nil {
		return message{}, err
	}
	if !p.blockTxnPrefixMatchesOutstanding(prefix) {
		return message{}, blockTxnStaleBodyError{}
	}
	payload, err := readPayloadWithChecksum(io.MultiReader(bytes.NewReader(prefix), p.conn), header.Size, header.Checksum)
	if err != nil {
		return message{}, err
	}
	return message{Command: header.Command, Payload: payload}, nil
}

func (p *peer) blockTxnPrefixMatchesOutstanding(prefix []byte) bool {
	if len(prefix) < blockTxnHashPayloadBytes {
		return false
	}
	var responseHash [32]byte
	copy(responseHash[:], prefix[:blockTxnHashPayloadBytes])
	blockHash, ok := p.compactOutstandingBlockHash()
	return ok && responseHash == blockHash
}

func (p *peer) postHandshakePayloadCap() payloadLimitFn {
	base := postHandshakePayloadCap(p.service.cfg.LocatorLimit, p.service.cfg.SyncConfig.HeaderBatchLimit)
	return func(command string) uint32 {
		switch command {
		case messageCmpctBlock:
			if p.acceptsCompactBlocks() {
				return compactRelayPayloadCap(command)
			}
			return 0
		case messageBlockTxn:
			if !p.compactReceiveEnabled() {
				return 0
			}
			if cap := p.blockTxnPayloadCap(); cap != 0 {
				return cap
			}
			if p.acceptsCompactBlocks() {
				return blockTxnHashPayloadBytes
			}
			return 0
		case messageGetBlockTxn:
			return 0
		default:
			return base(command)
		}
	}
}

func (p *peer) compactReceiveEnabled() bool {
	return p != nil && p.service != nil && p.service.cfg.EnableCompactReceive
}

func (p *peer) acceptsCompactBlocks() bool {
	if !p.compactReceiveEnabled() {
		return false
	}
	mode := p.remoteCompactMode()
	return mode.Version == compactRelayVersion && mode.Mode != 0
}

func (p *peer) acceptsBlockTxnResponses() bool {
	if !p.compactReceiveEnabled() {
		return false
	}
	return p.acceptsCompactBlocks() || p.blockTxnPayloadCap() != 0
}

func peerRunContextDone(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	select {
	case <-ctx.Done():
		return true
	default:
		return false
	}
}

func (p *peer) setReadDeadline() error {
	deadline := p.service.cfg.PeerRuntimeConfig.ReadDeadline
	if deadline <= 0 {
		return nil
	}
	return p.conn.SetReadDeadline(time.Now().Add(deadline))
}

func shouldIgnoreReadError(err error) bool {
	return !isPartialFrameTimeout(err) && isReadTimeout(err)
}

func normalizeReadError(err error) error {
	switch {
	case errors.Is(err, io.EOF), errors.Is(err, net.ErrClosed):
		return nil
	default:
		return err
	}
}

func (p *peer) handleMessage(frame message) error {
	switch frame.Command {
	case messageInv, messageGetData, messageBlock, messageTx, messageGetBlk, messageCmpctBlock, messageBlockTxn:
		return p.handleRelayMessage(frame)
	case messageSendCmpct:
		return p.handleSendCmpct(frame.Payload)
	case messageGetAddr, messageAddr:
		return p.handleAddressMessage(frame)
	case messagePing, messagePong, messageHeaders:
		return nil
	case messageVersion:
		return errors.New("invalid version message after handshake")
	case messageVerAck:
		return errors.New("invalid verack after handshake")
	default:
		return postHandshakeUnknownCommandError{command: frame.Command}
	}
}

func (p *peer) handleRelayMessage(frame message) error {
	switch frame.Command {
	case messageInv, messageGetData:
		return p.handleInventoryRelayMessage(frame)
	case messageBlock, messageTx, messageGetBlk, messageCmpctBlock, messageBlockTxn:
		return p.handleObjectRelayMessage(frame)
	default:
		return postHandshakeUnknownCommandError{command: frame.Command}
	}
}

func (p *peer) handleInventoryRelayMessage(frame message) error {
	switch frame.Command {
	case messageInv:
		return p.handleInv(frame.Payload)
	case messageGetData:
		return p.handleGetData(frame.Payload)
	default:
		return postHandshakeUnknownCommandError{command: frame.Command}
	}
}

func (p *peer) handleObjectRelayMessage(frame message) error {
	switch frame.Command {
	case messageBlock:
		return p.handleBlock(frame.Payload)
	case messageTx:
		return p.handleTx(frame.Payload)
	case messageGetBlk:
		return p.handleGetBlocks(frame.Payload)
	case messageCmpctBlock:
		if !p.acceptsCompactBlocks() {
			return postHandshakeUnknownCommandError{command: frame.Command}
		}
		return p.handleCmpctBlock(frame.Payload)
	case messageBlockTxn:
		if !p.acceptsBlockTxnResponses() {
			return postHandshakeUnknownCommandError{command: frame.Command}
		}
		return p.handleBlockTxn(frame.Payload)
	default:
		return postHandshakeUnknownCommandError{command: frame.Command}
	}
}

func isCompactRelayObjectCommand(command string) bool {
	switch command {
	case messageCmpctBlock, messageGetBlockTxn, messageBlockTxn:
		return true
	default:
		return false
	}
}

func (p *peer) handleAddressMessage(frame message) error {
	switch frame.Command {
	case messageGetAddr:
		return p.handleGetAddr(frame.Payload)
	case messageAddr:
		return p.handleAddr(frame.Payload)
	default:
		return postHandshakeUnknownCommandError{command: frame.Command}
	}
}

func unknownCommandPolicyReason(err error) (string, bool) {
	var unknownErr postHandshakeUnknownCommandError
	if errors.As(err, &unknownErr) {
		return unknownErr.peerReason(), true
	}
	return "", false
}

func (p *peer) send(command string, payload []byte) error {
	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	if deadline := p.service.cfg.PeerRuntimeConfig.WriteDeadline; deadline > 0 {
		if err := p.conn.SetWriteDeadline(time.Now().Add(deadline)); err != nil {
			return err
		}
	}
	return writeFrame(p.conn, networkMagic(p.service.cfg.PeerRuntimeConfig.Network), message{Command: command, Payload: payload}, p.service.cfg.PeerRuntimeConfig.MaxMessageSize)
}

func (p *peer) addr() string {
	p.stateMu.Lock()
	defer p.stateMu.Unlock()
	return p.state.Addr
}

func (p *peer) snapshotState() node.PeerState {
	p.stateMu.Lock()
	defer p.stateMu.Unlock()
	return p.state
}

func (p *peer) setLastError(reason string) {
	p.stateMu.Lock()
	p.state.LastError = reason
	state := p.state
	p.stateMu.Unlock()
	_ = p.service.cfg.PeerManager.UpsertPeer(&state)
}

func (p *peer) applyPostHandshakeDisconnectError(err error) {
	if err == nil {
		return
	}
	if p.applyBlockTxnStaleBodyDisconnect(err) {
		return
	}
	if p.applyBlockTxnCapDisconnect(err) {
		return
	}
	if reason, ok := unknownCommandPolicyReason(err); ok {
		p.setLastError(reason)
		return
	}
	if reason, ok := payloadCapDiagnosticReason(err); ok {
		p.setLastError(reason)
		return
	}
	p.setLastError(err.Error())
}

func (p *peer) applyBlockTxnStaleBodyDisconnect(err error) bool {
	var staleErr blockTxnStaleBodyError
	if !errors.As(err, &staleErr) {
		return false
	}
	p.setLastError(staleErr.Error())
	return true
}

func (p *peer) applyBlockTxnCapDisconnect(err error) bool {
	var commandCapErr commandPayloadCapError
	if errors.As(err, &commandCapErr) && commandCapErr.command == messageBlockTxn {
		if p.blockTxnPayloadCap() == 0 {
			p.setLastError("unexpected blocktxn")
			return true
		}
		p.clearCompactOutstandingRequest()
		p.bumpBan(10, "blocktxn payload exceeds outstanding cap")
		return true
	}
	var messageCapErr inboundMessagePayloadCapError
	if errors.As(err, &messageCapErr) && messageCapErr.command == messageBlockTxn {
		if p.blockTxnPayloadCap() == 0 {
			p.setLastError("unexpected blocktxn")
			return true
		}
		p.setLastError("message exceeds cap: blocktxn")
		return true
	}
	return false
}

func payloadCapDiagnosticReason(err error) (string, bool) {
	command, ok := capErrorCommand(err)
	if !ok || command == "" {
		return "", false
	}
	return fmt.Sprintf("%s: %s", err.Error(), command), true
}

func capErrorCommand(err error) (string, bool) {
	var commandCapErr commandPayloadCapError
	if errors.As(err, &commandCapErr) {
		return commandCapErr.command, true
	}
	var messageCapErr inboundMessagePayloadCapError
	if errors.As(err, &messageCapErr) {
		return messageCapErr.command, true
	}
	return "", false
}

func (p *peer) bumpBan(delta int, reason string) bool {
	p.stateMu.Lock()
	p.state.BanScore += delta
	p.state.LastError = reason
	state := p.state
	p.stateMu.Unlock()
	_ = p.service.cfg.PeerManager.UpsertPeer(&state)
	return state.BanScore >= p.service.cfg.PeerRuntimeConfig.BanThreshold
}
