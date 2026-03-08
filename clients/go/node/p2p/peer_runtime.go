package p2p

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/node"
)

func (p *peer) run(ctx context.Context) error {
	for {
		if ctx != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
			}
		}
		if deadline := p.service.cfg.PeerRuntimeConfig.ReadDeadline; deadline > 0 {
			if err := p.conn.SetReadDeadline(time.Now().Add(deadline)); err != nil {
				return err
			}
		}
		frame, err := readFrameWithPayloadLimit(
			p.conn,
			networkMagic(p.service.cfg.PeerRuntimeConfig.Network),
			p.service.cfg.PeerRuntimeConfig.MaxMessageSize,
			postHandshakePayloadCap(p.service.cfg.LocatorLimit, p.service.cfg.SyncConfig.HeaderBatchLimit),
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

func shouldIgnoreReadError(err error) bool {
	var netErr net.Error
	return errors.Is(err, os.ErrDeadlineExceeded) || (errors.As(err, &netErr) && netErr.Timeout())
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
	case messageInv:
		return p.handleInv(frame.Payload)
	case messageGetData:
		return p.handleGetData(frame.Payload)
	case messageBlock:
		return p.handleBlock(frame.Payload)
	case messageTx:
		return p.handleTx(frame.Payload)
	case messageGetBlk:
		return p.handleGetBlocks(frame.Payload)
	case messageGetAddr:
		return p.handleGetAddr(frame.Payload)
	case messageAddr:
		return p.handleAddr(frame.Payload)
	case messagePing, messagePong, messageHeaders:
		return nil
	case messageVersion:
		return errors.New("invalid version message after handshake")
	case messageVerAck:
		return errors.New("invalid verack after handshake")
	default:
		return fmt.Errorf("unknown message type: %s", frame.Command)
	}
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

func (p *peer) bumpBan(delta int, reason string) bool {
	p.stateMu.Lock()
	p.state.BanScore += delta
	p.state.LastError = reason
	state := p.state
	p.stateMu.Unlock()
	_ = p.service.cfg.PeerManager.UpsertPeer(&state)
	return state.BanScore >= p.service.cfg.PeerRuntimeConfig.BanThreshold
}
