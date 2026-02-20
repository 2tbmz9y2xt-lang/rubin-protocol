package p2p

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"rubin.dev/node/consensus"
	"rubin.dev/node/crypto"
)

type PeerRole int

const (
	PeerRoleUnknown PeerRole = iota
	PeerRoleInbound
	PeerRoleOutbound
)

type PeerHandler interface {
	// OnHeaders is called for unsolicited `headers` messages.
	OnHeaders(peer *Peer, headers []consensus.BlockHeader) error
	// OnInv is called for `inv` messages.
	OnInv(peer *Peer, vecs []InvVector) error
	// OnGetData is called for `getdata` messages.
	OnGetData(peer *Peer, vecs []InvVector) error
	// OnNotFound is called for `notfound` messages.
	OnNotFound(peer *Peer, vecs []InvVector) error
	// OnGetHeaders is called for `getheaders`. The handler returns headers to send.
	OnGetHeaders(peer *Peer, req *GetHeadersPayload) ([]consensus.BlockHeader, error)
	// OnBlock is called for `block` messages (raw canonical BlockBytes).
	OnBlock(peer *Peer, blockBytes []byte) error
	// OnTx is called for `tx` messages (raw canonical TxBytes including witness).
	OnTx(peer *Peer, txBytes []byte) error
}

type PeerConfig struct {
	Magic        uint32
	LocalChainID [32]byte

	Crypto crypto.CryptoProvider

	OurVersion VersionPayload

	// IdleTimeout, if non-zero, sets a read deadline per message to avoid stuck connections.
	IdleTimeout time.Duration
}

type Peer struct {
	Conn   net.Conn
	Role   PeerRole
	Config PeerConfig

	PeerVersion VersionPayload

	Ban BanScore
}

func NewPeer(conn net.Conn, role PeerRole, cfg PeerConfig) (*Peer, error) {
	if conn == nil {
		return nil, fmt.Errorf("p2p: peer: nil conn")
	}
	if cfg.Crypto == nil {
		return nil, fmt.Errorf("p2p: peer: nil crypto provider")
	}
	return &Peer{Conn: conn, Role: role, Config: cfg}, nil
}

func (p *Peer) Handshake() error {
	res, err := Handshake(p.Conn, p.Config.Crypto, p.Config.Magic, p.Config.OurVersion, p.Config.LocalChainID)
	if err != nil {
		return err
	}
	p.PeerVersion = res.PeerVersion
	return nil
}

func (p *Peer) Send(command string, payload []byte) error {
	return WriteMessage(p.Conn, p.Config.Crypto, p.Config.Magic, command, payload)
}

func (p *Peer) Run(ctx context.Context, h PeerHandler) error {
	if h == nil {
		return fmt.Errorf("p2p: peer: nil handler")
	}
	if err := p.Handshake(); err != nil {
		return err
	}

	// Ensure ctx cancellation unblocks ReadMessage (which is a blocking read on Conn).
	// Closing the conn is the simplest deterministic way to stop the loop.
	if ctx != nil {
		done := make(chan struct{})
		go func() {
			select {
			case <-ctx.Done():
				_ = p.Conn.Close()
			case <-done:
			}
		}()
		defer close(done)
	}

	for {
		if ctx != nil {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}
		}

		if p.Config.IdleTimeout > 0 {
			_ = p.Conn.SetReadDeadline(time.Now().Add(p.Config.IdleTimeout))
		}
		msg, rerr := ReadMessage(p.Conn, p.Config.Crypto, p.Config.Magic)
		if rerr != nil {
			now := time.Now()
			p.Ban.Add(now, rerr.BanScoreDelta)
			if p.Ban.ShouldBan(now) {
				return fmt.Errorf("p2p: peer: banned (score=%d): %w", p.Ban.Score(now), rerr.Err)
			}
			if rerr.Disconnect {
				return rerr
			}
			// Drop malformed message, keep connection.
			continue
		}

		now := time.Now()
		if p.Ban.ShouldThrottle(now) {
			time.Sleep(ThrottleDelay)
		}

		switch msg.Command {
		case CmdPing:
			pp, err := DecodePingPayload(msg.Payload)
			if err != nil {
				p.Ban.Add(now, 10)
				continue
			}
			pong, err := EncodePongPayload(PongPayload{Nonce: pp.Nonce})
			if err != nil {
				return err
			}
			if err := p.Send(CmdPong, pong); err != nil {
				return err
			}
		case CmdPong:
			// Higher layers can track RTT; we ignore for now.
			continue
		case CmdGetHeaders:
			req, err := DecodeGetHeadersPayload(msg.Payload)
			if err != nil {
				p.Ban.Add(now, 10)
				continue
			}
			headers, err := h.OnGetHeaders(p, req)
			if err != nil {
				// Treat handler errors as local; don't penalize peer.
				continue
			}
			payload, err := EncodeHeadersPayload(headers)
			if err != nil {
				continue
			}
			_ = p.Send(CmdHeaders, payload)
		case CmdHeaders:
			headers, err := DecodeHeadersPayload(msg.Payload)
			if err != nil {
				p.Ban.Add(now, 10)
				continue
			}
			if err := h.OnHeaders(p, headers); err != nil {
				// Policy: invalid header-chain data is treated as "invalid block" (+100),
				// except for future timestamps which should be deferred without immediate ban.
				switch {
				case errors.Is(err, ErrHeaderTimestampFuture):
					// No ban; caller may retry later.
				case errors.Is(err, ErrHeaderLinkageInvalid),
					errors.Is(err, ErrHeaderPOWInvalid),
					errors.Is(err, ErrHeaderTargetInvalid),
					errors.Is(err, ErrHeaderTimestampOld):
					p.Ban.Add(now, 100)
				default:
					p.Ban.Add(now, 10)
				}
				if p.Ban.ShouldBan(now) {
					return fmt.Errorf("p2p: peer: invalid headers (banned): %w", err)
				}
				continue
			}
		case CmdInv:
			vecs, err := DecodeInvPayload(msg.Payload)
			if err != nil {
				p.Ban.Add(now, 10)
				continue
			}
			if err := h.OnInv(p, vecs); err != nil {
				// Invalid tx is +5 per spec table, invalid block is +100; the handler decides.
				p.Ban.Add(now, 5)
			}
		case CmdGetData:
			vecs, err := DecodeInvPayload(msg.Payload)
			if err != nil {
				p.Ban.Add(now, 10)
				continue
			}
			if err := h.OnGetData(p, vecs); err != nil {
				p.Ban.Add(now, 2)
			}
		case CmdNotFound:
			vecs, err := DecodeInvPayload(msg.Payload)
			if err != nil {
				p.Ban.Add(now, 10)
				continue
			}
			_ = h.OnNotFound(p, vecs)
		case CmdBlock:
			if err := h.OnBlock(p, msg.Payload); err != nil {
				p.Ban.Add(now, 100)
				if p.Ban.ShouldBan(now) {
					return fmt.Errorf("p2p: peer: invalid block (banned): %w", err)
				}
			}
		case CmdTx:
			if err := h.OnTx(p, msg.Payload); err != nil {
				p.Ban.Add(now, 5)
			}
		default:
			// Unknown command: ignore, no ban-score.
			continue
		}
	}
}
