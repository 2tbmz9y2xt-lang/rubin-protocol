package node

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"testing"
	"time"
)

func TestPerformVersionHandshakeOK(t *testing.T) {
	local, remote := net.Pipe()
	defer local.Close()
	defer remote.Close()

	cfg := DefaultPeerRuntimeConfig("devnet", 8)
	cfg.ReadDeadline = 2 * time.Second
	cfg.WriteDeadline = 2 * time.Second

	errCh := make(chan error, 1)
	go func() {
		errCh <- scriptedRemoteHandshake(remote, VersionPayloadV1{
			ProtocolVersion:   1,
			Network:           "devnet",
			NodeID:            "remote-1",
			UserAgent:         "rubin-node/remote",
			StartHeight:       7,
			Timestamp:         10,
			TxRelay:           true,
			PrunedBelowHeight: 0,
			DaMempoolSize:     1024,
		})
	}()

	state, err := PerformVersionHandshake(context.Background(), local, cfg, VersionPayloadV1{
		ProtocolVersion:   1,
		Network:           "devnet",
		NodeID:            "local-1",
		UserAgent:         "rubin-node/local",
		StartHeight:       5,
		Timestamp:         9,
		TxRelay:           true,
		PrunedBelowHeight: 0,
		DaMempoolSize:     2048,
	})
	if err != nil {
		t.Fatalf("handshake failed: %v", err)
	}
	if !state.HandshakeComplete || !state.VersionReceived || !state.VerackReceived {
		t.Fatalf("handshake state incomplete: %+v", state)
	}
	if state.RemoteVersion.NodeID != "remote-1" {
		t.Fatalf("unexpected remote node_id: %s", state.RemoteVersion.NodeID)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("remote script failed: %v", err)
	}
}

func TestPerformVersionHandshakeRejectsNetworkMismatch(t *testing.T) {
	local, remote := net.Pipe()
	defer local.Close()
	defer remote.Close()

	cfg := DefaultPeerRuntimeConfig("devnet", 8)
	cfg.ReadDeadline = 2 * time.Second
	cfg.WriteDeadline = 2 * time.Second

	go func() {
		_ = scriptedRemoteHandshake(remote, VersionPayloadV1{
			ProtocolVersion:   1,
			Network:           "testnet",
			NodeID:            "remote-mismatch",
			UserAgent:         "rubin-node/remote",
			StartHeight:       0,
			Timestamp:         0,
			TxRelay:           true,
			PrunedBelowHeight: 0,
			DaMempoolSize:     0,
		})
	}()

	_, err := PerformVersionHandshake(context.Background(), local, cfg, VersionPayloadV1{
		ProtocolVersion: 1,
		Network:         "devnet",
		NodeID:          "local-1",
	})
	if err == nil {
		t.Fatalf("expected handshake error")
	}
}

func TestPeerSessionRunPingPongAndBan(t *testing.T) {
	local, remote := net.Pipe()
	defer local.Close()
	defer remote.Close()

	cfg := DefaultPeerRuntimeConfig("devnet", 8)
	cfg.ReadDeadline = 2 * time.Second
	cfg.WriteDeadline = 2 * time.Second
	cfg.BanThreshold = 1
	session := NewPeerSession(local, cfg, PeerState{
		Addr:              "pipe",
		HandshakeComplete: true,
		VersionReceived:   true,
		VerackReceived:    true,
	})

	runErr := make(chan error, 1)
	go func() {
		runErr <- session.Run(context.Background())
	}()
	remoteReader := bufio.NewReader(remote)

	if err := writeWireMessage(remote, WireMessage{Command: "ping"}); err != nil {
		t.Fatalf("write ping: %v", err)
	}
	msg, err := readWireMessage(remoteReader)
	if err != nil {
		t.Fatalf("read pong: %v", err)
	}
	if msg.Command != "pong" {
		t.Fatalf("expected pong, got %q", msg.Command)
	}

	if err := writeWireMessage(remote, WireMessage{Command: "unknown"}); err != nil {
		t.Fatalf("write unknown: %v", err)
	}
	select {
	case err := <-runErr:
		if err == nil {
			t.Fatalf("expected peer ban error")
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("session did not exit after ban")
	}

	st := session.State()
	if st.BanScore < 1 {
		t.Fatalf("ban score not incremented: %d", st.BanScore)
	}
}

func TestPeerManagerMaxPeers(t *testing.T) {
	pm := NewPeerManager(DefaultPeerRuntimeConfig("devnet", 1))
	if err := pm.AddPeer(&PeerState{Addr: "a"}); err != nil {
		t.Fatalf("add first peer: %v", err)
	}
	if err := pm.AddPeer(&PeerState{Addr: "b"}); err == nil {
		t.Fatalf("expected max peers error")
	}
}

func scriptedRemoteHandshake(conn net.Conn, payload VersionPayloadV1) error {
	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)

	first, err := reader.ReadBytes('\n')
	if err != nil {
		return err
	}
	var m WireMessage
	if err := json.Unmarshal(first, &m); err != nil {
		return err
	}
	if m.Command != "version" {
		return errors.New("expected version from local peer")
	}

	versionPayload, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	out, err := json.Marshal(WireMessage{Command: "version", Payload: versionPayload})
	if err != nil {
		return err
	}
	if _, err := writer.Write(append(out, '\n')); err != nil {
		return err
	}
	if err := writer.Flush(); err != nil {
		return err
	}

	second, err := reader.ReadBytes('\n')
	if err != nil {
		return err
	}
	var m2 WireMessage
	if err := json.Unmarshal(second, &m2); err != nil {
		return err
	}
	if m2.Command != "verack" {
		return errors.New("expected verack from local peer")
	}

	verack, err := json.Marshal(WireMessage{Command: "verack"})
	if err != nil {
		return err
	}
	if _, err := writer.Write(append(verack, '\n')); err != nil {
		return err
	}
	return writer.Flush()
}

func writeWireMessage(conn net.Conn, msg WireMessage) error {
	raw, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	if _, err := conn.Write(append(raw, '\n')); err != nil {
		return err
	}
	return nil
}

func readWireMessage(reader *bufio.Reader) (WireMessage, error) {
	var out WireMessage
	line, err := reader.ReadBytes('\n')
	if err != nil {
		return out, err
	}
	err = json.Unmarshal(line, &out)
	return out, err
}
