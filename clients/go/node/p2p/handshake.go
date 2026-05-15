package p2p

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/node"
)

type handshakeProgress struct {
	sentVerAck      bool
	versionReceived bool
	verAckReceived  bool
}

func (h handshakeProgress) complete() bool {
	return h.versionReceived && h.sentVerAck && h.verAckReceived
}

func performHandshake(
	ctx context.Context,
	conn net.Conn,
	cfg node.PeerRuntimeConfig,
	local node.VersionPayloadV1,
	expectedChainID [32]byte,
	expectedGenesisHash [32]byte,
) (node.PeerState, error) {
	cfg = mergePeerRuntimeConfig(cfg)
	magic := networkMagic(cfg.Network)

	state := node.PeerState{
		Addr: conn.RemoteAddr().String(),
	}
	deadline := handshakeDeadline(ctx, cfg.HandshakeTimeout)
	if err := conn.SetDeadline(deadline); err != nil {
		return state, err
	}
	defer func() {
		_ = conn.SetDeadline(time.Time{})
	}()

	done := make(chan struct{})
	defer close(done)
	if ctx != nil {
		go interruptHandshakeOnContextCancel(ctx, conn, done)
	}

	payload, err := encodeVersionPayload(local)
	if err != nil {
		return state, err
	}
	if err := writeFrame(conn, magic, message{Command: messageVersion, Payload: payload}, cfg.MaxMessageSize); err != nil {
		return state, err
	}
	progress := handshakeProgress{}
	if err := progress.run(conn, magic, cfg, local, expectedChainID, expectedGenesisHash, &state); err != nil {
		return state, err
	}
	state.HandshakeComplete = true
	return state, nil
}

func (h *handshakeProgress) run(
	conn net.Conn,
	magic [4]byte,
	cfg node.PeerRuntimeConfig,
	local node.VersionPayloadV1,
	expectedChainID [32]byte,
	expectedGenesisHash [32]byte,
	state *node.PeerState,
) error {
	for !h.complete() {
		frame, err := readFrameWithPayloadLimit(conn, magic, cfg.MaxMessageSize, preHandshakePayloadCap)
		if err != nil {
			return err
		}
		if err := h.handleFrame(conn, magic, cfg.MaxMessageSize, frame, local, expectedChainID, expectedGenesisHash, cfg.BanThreshold, state); err != nil {
			return err
		}
	}
	return nil
}

func (h *handshakeProgress) handleFrame(
	conn net.Conn,
	magic [4]byte,
	maxMessageSize uint32,
	frame message,
	local node.VersionPayloadV1,
	expectedChainID [32]byte,
	expectedGenesisHash [32]byte,
	banThreshold int,
	state *node.PeerState,
) error {
	switch frame.Command {
	case messageVersion:
		return h.handleVersionFrame(conn, magic, maxMessageSize, frame.Payload, local, expectedChainID, expectedGenesisHash, banThreshold, state)
	case messageVerAck:
		h.verAckReceived = true
		return nil
	default:
		state.BanScore = banThreshold
		state.LastError = "unexpected pre-handshake command"
		return errors.New("unexpected pre-handshake command")
	}
}

func (h *handshakeProgress) handleVersionFrame(
	conn net.Conn,
	magic [4]byte,
	maxMessageSize uint32,
	payload []byte,
	local node.VersionPayloadV1,
	expectedChainID [32]byte,
	expectedGenesisHash [32]byte,
	banThreshold int,
	state *node.PeerState,
) error {
	remote, err := decodeVersionPayload(payload)
	if err != nil {
		state.LastError = err.Error()
		return err
	}
	state.RemoteVersion = remote
	if err := validateRemoteVersion(remote, local.ProtocolVersion, expectedChainID, expectedGenesisHash, banThreshold, state); err != nil {
		return err
	}
	h.versionReceived = true
	if h.sentVerAck {
		return nil
	}
	if err := writeFrame(conn, magic, message{Command: messageVerAck}, maxMessageSize); err != nil {
		return err
	}
	h.sentVerAck = true
	return nil
}

func preHandshakePayloadCap(command string) uint32 {
	switch command {
	case messageVersion:
		return versionPayloadBytes
	case messageVerAck:
		return 0
	case messageGetAddr:
		return 0
	case messageAddr:
		return 0
	default:
		return 0
	}
}

func handshakeDeadline(ctx context.Context, timeout time.Duration) time.Time {
	deadline := time.Now().Add(timeout)
	if ctx == nil {
		return deadline
	}
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		return ctxDeadline
	}
	return deadline
}

func interruptHandshakeOnContextCancel(ctx context.Context, conn net.Conn, done <-chan struct{}) {
	select {
	case <-ctx.Done():
		_ = conn.SetDeadline(time.Now())
	case <-done:
	}
}

// maxProtocolVersion is the absolute upper bound for a remote peer's
// claimed protocol_version, mirroring the Rust client's MAX_PROTOCOL_VERSION
// in clients/rust/crates/rubin-node/src/p2p_runtime.rs. A version above this
// bound is rejected by validateRemoteVersion regardless of local/remote
// adjacency so absurd claims from a malicious or misconfigured peer cannot
// slip past the pairwise compatibility window.
const maxProtocolVersion uint32 = 1024

func validateRemoteVersion(
	remote node.VersionPayloadV1,
	localProtocolVersion uint32,
	expectedChainID [32]byte,
	expectedGenesisHash [32]byte,
	banThreshold int,
	state *node.PeerState,
) error {
	switch {
	case remote.ProtocolVersion == 0:
		state.LastError = "invalid protocol_version"
		return errors.New("invalid protocol_version")
	case remote.ProtocolVersion > maxProtocolVersion:
		state.LastError = fmt.Sprintf("protocol_version %d exceeds max %d", remote.ProtocolVersion, maxProtocolVersion)
		return fmt.Errorf("protocol_version %d exceeds max %d", remote.ProtocolVersion, maxProtocolVersion)
	case !protocolVersionsCompatible(localProtocolVersion, remote.ProtocolVersion):
		state.LastError = fmt.Sprintf("protocol_version mismatch: local=%d remote=%d", localProtocolVersion, remote.ProtocolVersion)
		return fmt.Errorf("protocol_version mismatch: local=%d remote=%d", localProtocolVersion, remote.ProtocolVersion)
	case remote.ChainID != expectedChainID:
		state.BanScore = banThreshold
		state.LastError = "chain_id mismatch"
		return errors.New("chain_id mismatch")
	case remote.GenesisHash != expectedGenesisHash:
		state.BanScore = banThreshold
		state.LastError = "genesis_hash mismatch"
		return errors.New("genesis_hash mismatch")
	default:
		return nil
	}
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

func normalizeDuration(current, fallback time.Duration) time.Duration {
	if current > 0 {
		return current
	}
	return fallback
}

func mergePeerRuntimeConfig(cfg node.PeerRuntimeConfig) node.PeerRuntimeConfig {
	defaults := node.DefaultPeerRuntimeConfig(cfg.Network, cfg.MaxPeers)
	if cfg.Network == "" {
		cfg.Network = defaults.Network
	}
	if cfg.MaxPeers <= 0 {
		cfg.MaxPeers = defaults.MaxPeers
	}
	cfg.ReadDeadline = normalizeDuration(cfg.ReadDeadline, defaults.ReadDeadline)
	cfg.WriteDeadline = normalizeDuration(cfg.WriteDeadline, defaults.WriteDeadline)
	cfg.HandshakeTimeout = normalizeDuration(cfg.HandshakeTimeout, defaults.HandshakeTimeout)
	if cfg.BanThreshold <= 0 {
		cfg.BanThreshold = defaults.BanThreshold
	}
	if cfg.MaxMessageSize == 0 {
		cfg.MaxMessageSize = defaults.MaxMessageSize
	}
	return cfg
}
