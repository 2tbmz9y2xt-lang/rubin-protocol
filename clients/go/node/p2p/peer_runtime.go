package p2p

import (
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

func (p *peer) run(ctx context.Context) error {
	for {
		if peerRunContextDone(ctx) {
			return nil
		}
		if err := p.setReadDeadline(); err != nil {
			return err
		}
		frame, err := readFrameWithPayloadLimit(
			p.conn,
			networkMagic(p.service.cfg.PeerRuntimeConfig.Network),
			p.service.cfg.PeerRuntimeConfig.MaxMessageSize,
			p.postHandshakePayloadCap(),
		)
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

func (p *peer) postHandshakePayloadCap() payloadLimitFn {
	base := postHandshakePayloadCap(p.service.cfg.LocatorLimit, p.service.cfg.SyncConfig.HeaderBatchLimit)
	return func(command string) uint32 {
		if command == messageGetBlockTxn {
			return 0
		}
		if isCompactRelayObjectCommand(command) && !p.compactRelayEnabled() {
			return 0
		}
		if command == messageBlockTxn {
			return p.blockTxnPayloadCap()
		}
		return base(command)
	}
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
	if isCompactRelayObjectCommand(frame.Command) && !p.compactRelayEnabled() {
		return errors.New("compact relay not negotiated")
	}
	switch frame.Command {
	case messageBlock:
		return p.handleBlock(frame.Payload)
	case messageTx:
		return p.handleTx(frame.Payload)
	case messageGetBlk:
		return p.handleGetBlocks(frame.Payload)
	case messageCmpctBlock:
		return p.handleCmpctBlock(frame.Payload)
	case messageBlockTxn:
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

func (p *peer) compactRelayEnabled() bool {
	mode := p.remoteCompactMode()
	return mode.Version == compactRelayVersion && mode.Mode > 0
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
	if reason, ok := unknownCommandPolicyReason(err); ok {
		p.setLastError(reason)
		return
	}
	p.setLastError(err.Error())
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
