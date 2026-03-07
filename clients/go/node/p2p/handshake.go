package p2p

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/node"
)

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
	sentVerAck := false
	versionReceived := false
	verAckReceived := false
	for {
		frame, err := readFrameWithPayloadLimit(conn, magic, cfg.MaxMessageSize, preHandshakePayloadCap)
		if err != nil {
			return state, err
		}
		switch frame.Command {
		case messageVersion:
			remote, err := decodeVersionPayload(frame.Payload)
			if err != nil {
				state.LastError = err.Error()
				return state, err
			}
			state.RemoteVersion = remote
			if err := validateRemoteVersion(remote, local.ProtocolVersion, expectedChainID, expectedGenesisHash, cfg.BanThreshold, &state); err != nil {
				return state, err
			}
			versionReceived = true
			if !sentVerAck {
				if err := writeFrame(conn, magic, message{Command: messageVerAck}, cfg.MaxMessageSize); err != nil {
					return state, err
				}
				sentVerAck = true
			}
		case messageVerAck:
			verAckReceived = true
		default:
			state.BanScore = cfg.BanThreshold
			state.LastError = "unexpected pre-handshake command"
			return state, errors.New("unexpected pre-handshake command")
		}
		if versionReceived && sentVerAck && verAckReceived {
			state.HandshakeComplete = true
			return state, nil
		}
	}
}

func preHandshakePayloadCap(command string) uint32 {
	switch command {
	case messageVersion:
		return versionPayloadBytes
	case messageVerAck:
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
