package node

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

type staticAddr string

func (a staticAddr) Network() string { return "test" }
func (a staticAddr) String() string  { return string(a) }

type timeoutError struct{}

func (e timeoutError) Error() string   { return "timeout" }
func (e timeoutError) Timeout() bool   { return true }
func (e timeoutError) Temporary() bool { return true }

type scriptedConn struct {
	writeErr         error
	setReadDeadErr   error
	setWriteDeadErr  error
	remoteAddrString string
	readErrs         []error
}

func (c *scriptedConn) Read(_ []byte) (int, error) {
	if len(c.readErrs) == 0 {
		return 0, io.EOF
	}
	err := c.readErrs[0]
	c.readErrs = c.readErrs[1:]
	return 0, err
}

func (c *scriptedConn) Write(p []byte) (int, error) {
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	return len(p), nil
}

func (c *scriptedConn) Close() error                       { return nil }
func (c *scriptedConn) LocalAddr() net.Addr                { return staticAddr("local") }
func (c *scriptedConn) RemoteAddr() net.Addr               { return staticAddr(c.remoteAddrString) }
func (c *scriptedConn) SetDeadline(_ time.Time) error      { return nil }
func (c *scriptedConn) SetReadDeadline(_ time.Time) error  { return c.setReadDeadErr }
func (c *scriptedConn) SetWriteDeadline(_ time.Time) error { return c.setWriteDeadErr }

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

func TestDefaultPeerRuntimeConfig_ClampMaxPeers(t *testing.T) {
	cfg := DefaultPeerRuntimeConfig("devnet", 0)
	if cfg.MaxPeers != 64 {
		t.Fatalf("max_peers=%d, want 64", cfg.MaxPeers)
	}
	if cfg.ReadDeadline != defaultReadDeadline || cfg.WriteDeadline != defaultWriteDeadline || cfg.BanThreshold != defaultBanThreshold {
		t.Fatalf("unexpected defaults: %#v", cfg)
	}
}

func TestNewPeerManager_DefaultsApplied(t *testing.T) {
	pm := NewPeerManager(PeerRuntimeConfig{Network: "devnet"})
	if pm.cfg.MaxPeers != 64 {
		t.Fatalf("max_peers=%d, want 64", pm.cfg.MaxPeers)
	}
	if pm.cfg.ReadDeadline != defaultReadDeadline || pm.cfg.WriteDeadline != defaultWriteDeadline || pm.cfg.BanThreshold != defaultBanThreshold {
		t.Fatalf("unexpected defaults: %#v", pm.cfg)
	}
}

func TestPeerManager_AddPeerNilCases(t *testing.T) {
	var pm *PeerManager
	if err := pm.AddPeer(&PeerState{Addr: "x"}); err == nil {
		t.Fatalf("expected error for nil pm")
	}

	pm = NewPeerManager(DefaultPeerRuntimeConfig("devnet", 1))
	if err := pm.AddPeer(nil); err == nil {
		t.Fatalf("expected error for nil peer")
	}
}

func TestPeerManager_SnapshotClones(t *testing.T) {
	pm := NewPeerManager(DefaultPeerRuntimeConfig("devnet", 8))
	st := &PeerState{Addr: "a", BanScore: 7, LastError: "x"}
	if err := pm.AddPeer(st); err != nil {
		t.Fatalf("AddPeer: %v", err)
	}
	st.BanScore = 999
	snap := pm.Snapshot()
	if len(snap) != 1 {
		t.Fatalf("snapshot len=%d, want 1", len(snap))
	}
	if snap[0].BanScore != 7 {
		t.Fatalf("snapshot ban_score=%d, want 7", snap[0].BanScore)
	}
}

func TestPeerManager_RemovePeer(t *testing.T) {
	pm := NewPeerManager(DefaultPeerRuntimeConfig("devnet", 8))
	if err := pm.AddPeer(&PeerState{Addr: "a"}); err != nil {
		t.Fatalf("AddPeer: %v", err)
	}
	pm.RemovePeer("a")
	if got := pm.Snapshot(); len(got) != 0 {
		t.Fatalf("snapshot len=%d, want 0", len(got))
	}

	var nilPM *PeerManager
	nilPM.RemovePeer("a")
}

func TestValidateRemoteVersion_Errors(t *testing.T) {
	if err := validateRemoteVersion("devnet", VersionPayloadV1{}); err == nil {
		t.Fatalf("expected error")
	}
	if err := validateRemoteVersion("devnet", VersionPayloadV1{ProtocolVersion: 1, Network: "testnet", NodeID: "x"}); err == nil {
		t.Fatalf("expected network mismatch")
	}
	if err := validateRemoteVersion("", VersionPayloadV1{ProtocolVersion: 1, Network: "x", NodeID: ""}); err == nil {
		t.Fatalf("expected empty node_id error")
	}
}

func TestPerformVersionHandshake_NilConn(t *testing.T) {
	_, err := PerformVersionHandshake(context.Background(), nil, PeerRuntimeConfig{}, VersionPayloadV1{})
	if err == nil {
		t.Fatalf("expected error")
	}
}

func TestPerformVersionHandshake_BansOnUnexpectedPreHandshakeCommand(t *testing.T) {
	local, remote := net.Pipe()
	defer local.Close()
	defer remote.Close()

	cfg := DefaultPeerRuntimeConfig("devnet", 8)
	cfg.ReadDeadline = 2 * time.Second
	cfg.WriteDeadline = 2 * time.Second
	cfg.BanThreshold = 10

	go func() {
		reader := bufio.NewReader(remote)
		_, _ = reader.ReadBytes('\n') // local version
		_ = writeWireMessage(remote, WireMessage{Command: "ping"})
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

func TestPeerSession_readMessage_SetReadDeadlineError(t *testing.T) {
	c := &scriptedConn{
		setReadDeadErr:   errors.New("nope"),
		remoteAddrString: "x",
	}
	ps := NewPeerSession(c, DefaultPeerRuntimeConfig("devnet", 1), PeerState{Addr: "x"})
	if _, err := ps.readMessage(); err == nil {
		t.Fatalf("expected error")
	}
}

func TestPeerSession_writeMessage_SetWriteDeadlineError(t *testing.T) {
	c := &scriptedConn{
		setWriteDeadErr:  errors.New("nope"),
		remoteAddrString: "x",
	}
	ps := NewPeerSession(c, DefaultPeerRuntimeConfig("devnet", 1), PeerState{Addr: "x"})
	if err := ps.writeMessage(WireMessage{Command: "ping"}); err == nil {
		t.Fatalf("expected error")
	}
}

func TestNewPeerSession_DefaultsApplied(t *testing.T) {
	local, remote := net.Pipe()
	defer local.Close()
	defer remote.Close()

	cfg := PeerRuntimeConfig{
		MaxPeers:      1,
		ReadDeadline:  0,
		WriteDeadline: 0,
		BanThreshold:  0,
		Network:       "devnet",
	}
	ps := NewPeerSession(local, cfg, PeerState{Addr: "pipe"})
	if ps.cfg.ReadDeadline != defaultReadDeadline {
		t.Fatalf("read_deadline=%s, want %s", ps.cfg.ReadDeadline, defaultReadDeadline)
	}
	if ps.cfg.WriteDeadline != defaultWriteDeadline {
		t.Fatalf("write_deadline=%s, want %s", ps.cfg.WriteDeadline, defaultWriteDeadline)
	}
	if ps.cfg.BanThreshold != defaultBanThreshold {
		t.Fatalf("ban_threshold=%d, want %d", ps.cfg.BanThreshold, defaultBanThreshold)
	}
}

func TestPeerSession_Run_TimeoutThenEOF(t *testing.T) {
	c := &scriptedConn{
		readErrs:         []error{timeoutError{}, io.EOF},
		remoteAddrString: "x",
	}
	cfg := DefaultPeerRuntimeConfig("devnet", 1)
	cfg.ReadDeadline = 1 * time.Millisecond
	cfg.WriteDeadline = 1 * time.Millisecond
	ps := NewPeerSession(c, cfg, PeerState{Addr: "x", HandshakeComplete: true})
	if err := ps.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
}

func TestClonePeerState_Nil(t *testing.T) {
	if clonePeerState(nil) != nil {
		t.Fatalf("expected nil")
	}
}
