package node

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

const (
	defaultReadDeadline  = 15 * time.Second
	defaultWriteDeadline = 15 * time.Second
	defaultBanThreshold  = 100
)

type WireMessage struct {
	Command string          `json:"command"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

type VersionPayloadV1 struct {
	ProtocolVersion   uint32 `json:"protocol_version"`
	Network           string `json:"network"`
	NodeID            string `json:"node_id"`
	UserAgent         string `json:"user_agent"`
	StartHeight       uint64 `json:"start_height"`
	Timestamp         uint64 `json:"timestamp"`
	TxRelay           bool   `json:"tx_relay"`
	PrunedBelowHeight uint64 `json:"pruned_below_height"`
	DaMempoolSize     uint64 `json:"da_mempool_size"`
}

type PeerRuntimeConfig struct {
	MaxPeers      int
	ReadDeadline  time.Duration
	WriteDeadline time.Duration
	BanThreshold  int
	Network       string
}

type PeerState struct {
	Addr              string
	HandshakeComplete bool
	VersionReceived   bool
	VerackReceived    bool
	BanScore          int
	LastError         string
	RemoteVersion     VersionPayloadV1
}

type PeerSession struct {
	conn   net.Conn
	mu     sync.RWMutex
	peer   PeerState
	cfg    PeerRuntimeConfig
	reader *bufio.Reader
	writer *bufio.Writer
}

type PeerManager struct {
	cfg   PeerRuntimeConfig
	mu    sync.RWMutex
	peers map[string]*PeerState
}

func DefaultPeerRuntimeConfig(network string, maxPeers int) PeerRuntimeConfig {
	if maxPeers <= 0 {
		maxPeers = 64
	}
	return PeerRuntimeConfig{
		MaxPeers:      maxPeers,
		ReadDeadline:  defaultReadDeadline,
		WriteDeadline: defaultWriteDeadline,
		BanThreshold:  defaultBanThreshold,
		Network:       network,
	}
}

func NewPeerManager(cfg PeerRuntimeConfig) *PeerManager {
	if cfg.MaxPeers <= 0 {
		cfg.MaxPeers = 64
	}
	if cfg.ReadDeadline <= 0 {
		cfg.ReadDeadline = defaultReadDeadline
	}
	if cfg.WriteDeadline <= 0 {
		cfg.WriteDeadline = defaultWriteDeadline
	}
	if cfg.BanThreshold <= 0 {
		cfg.BanThreshold = defaultBanThreshold
	}
	return &PeerManager{
		cfg:   cfg,
		peers: make(map[string]*PeerState),
	}
}

func (pm *PeerManager) AddPeer(state *PeerState) error {
	if pm == nil {
		return errors.New("nil peer manager")
	}
	if state == nil {
		return errors.New("nil peer state")
	}
	pm.mu.Lock()
	defer pm.mu.Unlock()
	if len(pm.peers) >= pm.cfg.MaxPeers {
		return errors.New("max peers reached")
	}
	pm.peers[state.Addr] = clonePeerState(state)
	return nil
}

func (pm *PeerManager) RemovePeer(addr string) {
	if pm == nil {
		return
	}
	pm.mu.Lock()
	defer pm.mu.Unlock()
	delete(pm.peers, addr)
}

func (pm *PeerManager) Snapshot() []PeerState {
	if pm == nil {
		return nil
	}
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	out := make([]PeerState, 0, len(pm.peers))
	for _, p := range pm.peers {
		out = append(out, *clonePeerState(p))
	}
	return out
}

func PerformVersionHandshake(
	ctx context.Context,
	conn net.Conn,
	cfg PeerRuntimeConfig,
	local VersionPayloadV1,
) (*PeerState, error) {
	if conn == nil {
		return nil, errors.New("nil connection")
	}
	if cfg.ReadDeadline <= 0 {
		cfg.ReadDeadline = defaultReadDeadline
	}
	if cfg.WriteDeadline <= 0 {
		cfg.WriteDeadline = defaultWriteDeadline
	}
	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)
	session := &PeerSession{
		conn:   conn,
		cfg:    cfg,
		reader: reader,
		writer: writer,
		peer: PeerState{
			Addr: conn.RemoteAddr().String(),
		},
	}
	done := make(chan struct{})
	defer close(done)
	if ctx != nil {
		go func() {
			select {
			case <-ctx.Done():
				_ = conn.SetReadDeadline(time.Now())
				_ = conn.SetWriteDeadline(time.Now())
			case <-done:
			}
		}()
	}

	versionPayload, err := json.Marshal(local)
	if err != nil {
		return nil, err
	}
	if err := session.writeMessage(WireMessage{Command: "version", Payload: versionPayload}); err != nil {
		return nil, err
	}

	sentVerack := false
	for {
		if ctx != nil {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			default:
			}
		}
		msg, err := session.readMessage()
		if err != nil {
			var netErr net.Error
			if ctx != nil && errors.Is(ctx.Err(), context.Canceled) {
				return nil, ctx.Err()
			}
			if ctx != nil && errors.Is(ctx.Err(), context.DeadlineExceeded) {
				return nil, ctx.Err()
			}
			if errors.As(err, &netErr) && netErr.Timeout() && ctx != nil {
				if ctxErr := ctx.Err(); ctxErr != nil {
					return nil, ctxErr
				}
			}
			return nil, err
		}
		switch msg.Command {
		case "version":
			var remote VersionPayloadV1
			if err := json.Unmarshal(msg.Payload, &remote); err != nil {
				return nil, err
			}
			if err := validateRemoteVersion(cfg.Network, remote); err != nil {
				return nil, err
			}
			session.mu.Lock()
			session.peer.VersionReceived = true
			session.peer.RemoteVersion = remote
			session.mu.Unlock()
			if !sentVerack {
				if err := session.writeMessage(WireMessage{Command: "verack"}); err != nil {
					return nil, err
				}
				sentVerack = true
			}
		case "verack":
			session.mu.Lock()
			session.peer.VerackReceived = true
			session.mu.Unlock()
		default:
			session.bumpBan(10, "unexpected pre-handshake command")
			if session.banScore() >= cfg.BanThreshold {
				return nil, errors.New("peer banned during handshake")
			}
		}
		session.mu.Lock()
		completed := session.peer.VersionReceived && session.peer.VerackReceived && sentVerack
		if completed {
			session.peer.HandshakeComplete = true
		}
		result := clonePeerState(&session.peer)
		session.mu.Unlock()
		if completed {
			return result, nil
		}
	}
}

func NewPeerSession(conn net.Conn, cfg PeerRuntimeConfig, initial PeerState) *PeerSession {
	if cfg.ReadDeadline <= 0 {
		cfg.ReadDeadline = defaultReadDeadline
	}
	if cfg.WriteDeadline <= 0 {
		cfg.WriteDeadline = defaultWriteDeadline
	}
	if cfg.BanThreshold <= 0 {
		cfg.BanThreshold = defaultBanThreshold
	}
	return &PeerSession{
		conn:   conn,
		cfg:    cfg,
		peer:   initial,
		reader: bufio.NewReader(conn),
		writer: bufio.NewWriter(conn),
	}
}

func (ps *PeerSession) Run(ctx context.Context) error {
	if ps == nil || ps.conn == nil {
		return errors.New("nil peer session")
	}
	for {
		if ctx != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
			}
		}
		msg, err := ps.readMessage()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				continue
			}
			return err
		}
		switch msg.Command {
		case "ping":
			if err := ps.writeMessage(WireMessage{Command: "pong"}); err != nil {
				return err
			}
		case "tx", "block", "headers":
			// accepted runtime commands (stub)
		default:
			ps.bumpBan(1, fmt.Sprintf("unknown command: %s", msg.Command))
			if ps.banScore() >= ps.cfg.BanThreshold {
				return errors.New("peer banned")
			}
		}
	}
}

func (ps *PeerSession) State() PeerState {
	if ps == nil {
		return PeerState{}
	}
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	return *clonePeerState(&ps.peer)
}

func (ps *PeerSession) readMessage() (WireMessage, error) {
	var msg WireMessage
	if ps.cfg.ReadDeadline > 0 {
		if err := ps.conn.SetReadDeadline(time.Now().Add(ps.cfg.ReadDeadline)); err != nil {
			return msg, err
		}
	}
	line, err := ps.reader.ReadBytes('\n')
	if err != nil {
		return msg, err
	}
	if err := json.Unmarshal(line, &msg); err != nil {
		return msg, err
	}
	return msg, nil
}

func (ps *PeerSession) writeMessage(msg WireMessage) error {
	if ps.cfg.WriteDeadline > 0 {
		if err := ps.conn.SetWriteDeadline(time.Now().Add(ps.cfg.WriteDeadline)); err != nil {
			return err
		}
	}
	raw, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	if _, err := ps.writer.Write(raw); err != nil {
		return err
	}
	return ps.writer.Flush()
}

func (ps *PeerSession) bumpBan(delta int, reason string) {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	ps.peer.BanScore += delta
	ps.peer.LastError = reason
}

func (ps *PeerSession) banScore() int {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	return ps.peer.BanScore
}

func validateRemoteVersion(expectedNetwork string, remote VersionPayloadV1) error {
	if remote.ProtocolVersion == 0 {
		return errors.New("invalid protocol_version")
	}
	if expectedNetwork != "" && remote.Network != expectedNetwork {
		return fmt.Errorf("network mismatch: got %q", remote.Network)
	}
	if remote.NodeID == "" {
		return errors.New("empty node_id")
	}
	return nil
}

func clonePeerState(in *PeerState) *PeerState {
	if in == nil {
		return nil
	}
	out := *in
	return &out
}
