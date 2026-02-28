package node

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha3"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

const (
	defaultReadDeadline  = 15 * time.Second
	defaultWriteDeadline = 15 * time.Second
	defaultBanThreshold  = 100
	wireHeaderSize       = 24
	wireCommandSize      = 12
)

type WireMessage struct {
	Command string
	Payload []byte
}

type VersionPayloadV1 struct {
	ProtocolVersion   uint32
	TxRelay           bool
	PrunedBelowHeight uint64
	DaMempoolSize     uint32
}

type PeerRuntimeConfig struct {
	Network       string
	MaxPeers      int
	ReadDeadline  time.Duration
	WriteDeadline time.Duration
	BanThreshold  int
}

type PeerState struct {
	Addr              string
	LastError         string
	RemoteVersion     VersionPayloadV1
	BanScore          int
	HandshakeComplete bool
	VersionReceived   bool
	VerackReceived    bool
}

type PeerSession struct {
	conn   net.Conn
	reader *bufio.Reader
	writer *bufio.Writer
	cfg    PeerRuntimeConfig
	peer   PeerState
	mu     sync.RWMutex
}

type PeerManager struct {
	peers map[string]*PeerState
	cfg   PeerRuntimeConfig
	mu    sync.RWMutex
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

	versionPayload := marshalVersionPayloadV1(local)
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
			remote, err := unmarshalVersionPayloadV1(msg.Payload)
			if err != nil {
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
			if !protocolVersionsCompatible(local.ProtocolVersion, remote.ProtocolVersion) {
				return nil, fmt.Errorf(
					"protocol_version mismatch: local=%d remote=%d",
					local.ProtocolVersion,
					remote.ProtocolVersion,
				)
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

	header := make([]byte, wireHeaderSize)
	if _, err := io.ReadFull(ps.reader, header); err != nil {
		return msg, err
	}
	expectedMagic := networkMagic(ps.cfg.Network)
	if !bytes.Equal(header[0:4], expectedMagic[:]) {
		return msg, errors.New("invalid envelope magic")
	}

	command, err := decodeWireCommand(header[4 : 4+wireCommandSize])
	if err != nil {
		return msg, err
	}
	payloadLen := binary.LittleEndian.Uint32(header[16:20])
	if uint64(payloadLen) > consensus.MAX_RELAY_MSG_BYTES {
		return msg, fmt.Errorf("relay payload exceeds cap: %d", payloadLen)
	}
	payload := make([]byte, int(payloadLen))
	if payloadLen > 0 {
		if _, err := io.ReadFull(ps.reader, payload); err != nil {
			return msg, err
		}
	}
	checksum := wireChecksum(payload)
	if !bytes.Equal(header[20:24], checksum[:]) {
		return msg, errors.New("invalid envelope checksum")
	}
	msg.Command = command
	msg.Payload = payload
	return msg, nil
}

func (ps *PeerSession) writeMessage(msg WireMessage) error {
	if ps.cfg.WriteDeadline > 0 {
		if err := ps.conn.SetWriteDeadline(time.Now().Add(ps.cfg.WriteDeadline)); err != nil {
			return err
		}
	}
	if uint64(len(msg.Payload)) > consensus.MAX_RELAY_MSG_BYTES {
		return fmt.Errorf("relay payload exceeds cap: %d", len(msg.Payload))
	}
	header, err := buildEnvelopeHeader(networkMagic(ps.cfg.Network), msg.Command, msg.Payload)
	if err != nil {
		return err
	}
	if _, err := ps.writer.Write(header); err != nil {
		return err
	}
	if len(msg.Payload) > 0 {
		if _, err := ps.writer.Write(msg.Payload); err != nil {
			return err
		}
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

func validateRemoteVersion(_ string, remote VersionPayloadV1) error {
	if remote.ProtocolVersion == 0 {
		return errors.New("invalid protocol_version")
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

func protocolVersionsCompatible(local, remote uint32) bool {
	if local == remote {
		return true
	}
	if local > remote {
		return local-remote <= 1
	}
	return remote-local <= 1
}

func marshalVersionPayloadV1(v VersionPayloadV1) []byte {
	payload := make([]byte, 17)
	binary.LittleEndian.PutUint32(payload[0:4], v.ProtocolVersion)
	if v.TxRelay {
		payload[4] = 1
	}
	binary.LittleEndian.PutUint64(payload[5:13], v.PrunedBelowHeight)
	binary.LittleEndian.PutUint32(payload[13:17], v.DaMempoolSize)
	return payload
}

func unmarshalVersionPayloadV1(payload []byte) (VersionPayloadV1, error) {
	var out VersionPayloadV1
	switch {
	case len(payload) < 13:
		return out, errors.New("version payload too short")
	case len(payload) < 17:
		out.ProtocolVersion = binary.LittleEndian.Uint32(payload[0:4])
		out.TxRelay = payload[4] == 1
		out.PrunedBelowHeight = binary.LittleEndian.Uint64(payload[5:13])
		out.DaMempoolSize = 0 // legacy layout
		return out, nil
	default:
		out.ProtocolVersion = binary.LittleEndian.Uint32(payload[0:4])
		out.TxRelay = payload[4] == 1
		out.PrunedBelowHeight = binary.LittleEndian.Uint64(payload[5:13])
		out.DaMempoolSize = binary.LittleEndian.Uint32(payload[13:17])
		return out, nil
	}
}

func buildEnvelopeHeader(magic [4]byte, command string, payload []byte) ([]byte, error) {
	commandBytes, err := encodeWireCommand(command)
	if err != nil {
		return nil, err
	}
	header := make([]byte, wireHeaderSize)
	copy(header[0:4], magic[:])
	copy(header[4:16], commandBytes[:])
	binary.LittleEndian.PutUint32(header[16:20], uint32(len(payload)))
	sum := wireChecksum(payload)
	copy(header[20:24], sum[:])
	return header, nil
}

func wireChecksum(payload []byte) [4]byte {
	hash := sha3.Sum256(payload)
	var out [4]byte
	copy(out[:], hash[:4])
	return out
}

func encodeWireCommand(command string) ([wireCommandSize]byte, error) {
	var out [wireCommandSize]byte
	if len(command) == 0 || len(command) > wireCommandSize {
		return out, errors.New("invalid command length")
	}
	for index := 0; index < len(command); index++ {
		ch := command[index]
		if ch < 0x21 || ch > 0x7e {
			return out, errors.New("command is not ASCII printable")
		}
		out[index] = ch
	}
	return out, nil
}

func decodeWireCommand(raw []byte) (string, error) {
	if len(raw) != wireCommandSize {
		return "", errors.New("invalid command width")
	}
	end := wireCommandSize
	for index := 0; index < wireCommandSize; index++ {
		if raw[index] == 0 {
			end = index
			break
		}
	}
	for index := end; index < wireCommandSize; index++ {
		if raw[index] != 0 {
			return "", errors.New("invalid NUL padding in command")
		}
	}
	command := string(raw[:end])
	if len(command) == 0 {
		return "", errors.New("empty command")
	}
	_, size := utf8.DecodeRuneInString(command)
	if size == 0 {
		return "", errors.New("invalid command")
	}
	for index := 0; index < len(command); index++ {
		ch := command[index]
		if ch < 0x21 || ch > 0x7e {
			return "", errors.New("command is not ASCII printable")
		}
	}
	return command, nil
}

func networkMagic(network string) [4]byte {
	switch network {
	case "mainnet":
		return [4]byte{0x52, 0x42, 0x4d, 0x4e} // RBMN
	case "testnet":
		return [4]byte{0x52, 0x42, 0x54, 0x4e} // RBTN
	case "devnet", "":
		return [4]byte{0x52, 0x42, 0x44, 0x56} // RBDV
	default:
		return [4]byte{0x52, 0x42, 0x4f, 0x50} // RBOP
	}
}
