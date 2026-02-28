package node

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
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
		errCh <- scriptedRemoteHandshake(remote, cfg.Network, VersionPayloadV1{
			ProtocolVersion:   1,
			TxRelay:           true,
			PrunedBelowHeight: 7,
			DaMempoolSize:     1024,
		})
	}()

	state, err := PerformVersionHandshake(context.Background(), local, cfg, VersionPayloadV1{
		ProtocolVersion:   1,
		TxRelay:           true,
		PrunedBelowHeight: 5,
		DaMempoolSize:     2048,
	})
	if err != nil {
		t.Fatalf("handshake failed: %v", err)
	}
	if !state.HandshakeComplete || !state.VersionReceived || !state.VerackReceived {
		t.Fatalf("handshake state incomplete: %+v", state)
	}
	if state.RemoteVersion.DaMempoolSize != 1024 {
		t.Fatalf("unexpected remote da_mempool_size: %d", state.RemoteVersion.DaMempoolSize)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("remote script failed: %v", err)
	}
}

func TestPerformVersionHandshakeRejectsProtocolGap(t *testing.T) {
	local, remote := net.Pipe()
	defer local.Close()
	defer remote.Close()

	cfg := DefaultPeerRuntimeConfig("devnet", 8)
	cfg.ReadDeadline = 2 * time.Second
	cfg.WriteDeadline = 2 * time.Second

	go func() {
		_ = scriptedRemoteHandshake(remote, cfg.Network, VersionPayloadV1{
			ProtocolVersion:   3,
			TxRelay:           true,
			PrunedBelowHeight: 0,
			DaMempoolSize:     0,
		})
	}()

	_, err := PerformVersionHandshake(context.Background(), local, cfg, VersionPayloadV1{
		ProtocolVersion: 1,
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

	if err := writeWireMessage(remote, cfg.Network, WireMessage{Command: "ping"}); err != nil {
		t.Fatalf("write ping: %v", err)
	}
	msg, err := readWireMessage(remoteReader, cfg.Network)
	if err != nil {
		t.Fatalf("read pong: %v", err)
	}
	if msg.Command != "pong" {
		t.Fatalf("expected pong, got %q", msg.Command)
	}

	if err := writeWireMessage(remote, cfg.Network, WireMessage{Command: "unknown"}); err != nil {
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

func scriptedRemoteHandshake(conn net.Conn, network string, payload VersionPayloadV1) error {
	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)

	first, err := readWireMessage(reader, network)
	if err != nil {
		return err
	}
	if first.Command != "version" {
		return errors.New("expected version from local peer")
	}

	if err := writeWireMessageBuffered(writer, network, WireMessage{
		Command: "version",
		Payload: marshalVersionPayloadV1(payload),
	}); err != nil {
		return err
	}
	if err := writer.Flush(); err != nil {
		return err
	}

	second, err := readWireMessage(reader, network)
	if err != nil {
		return err
	}
	if second.Command != "verack" {
		return errors.New("expected verack from local peer")
	}

	if err := writeWireMessageBuffered(writer, network, WireMessage{Command: "verack"}); err != nil {
		return err
	}
	return writer.Flush()
}

func writeWireMessage(conn net.Conn, network string, msg WireMessage) error {
	writer := bufio.NewWriter(conn)
	if err := writeWireMessageBuffered(writer, network, msg); err != nil {
		return err
	}
	return writer.Flush()
}

func writeWireMessageBuffered(writer *bufio.Writer, network string, msg WireMessage) error {
	header, err := buildEnvelopeHeader(networkMagic(network), msg.Command, msg.Payload)
	if err != nil {
		return err
	}
	if _, err := writer.Write(header); err != nil {
		return err
	}
	if len(msg.Payload) > 0 {
		if _, err := writer.Write(msg.Payload); err != nil {
			return err
		}
	}
	return nil
}

func readWireMessage(reader *bufio.Reader, network string) (WireMessage, error) {
	var out WireMessage
	header := make([]byte, wireHeaderSize)
	if _, err := io.ReadFull(reader, header); err != nil {
		return out, err
	}
	expectedMagic := networkMagic(network)
	if !bytes.Equal(header[:4], expectedMagic[:]) {
		return out, errors.New("invalid magic")
	}
	command, err := decodeWireCommand(header[4:16])
	if err != nil {
		return out, err
	}
	payloadLen := binary.LittleEndian.Uint32(header[16:20])
	if uint64(payloadLen) > consensus.MAX_RELAY_MSG_BYTES {
		return out, errors.New("payload too large")
	}
	payload := make([]byte, int(payloadLen))
	if payloadLen > 0 {
		if _, err := io.ReadFull(reader, payload); err != nil {
			return out, err
		}
	}
	sum := wireChecksum(payload)
	if !bytes.Equal(header[20:24], sum[:]) {
		return out, errors.New("invalid checksum")
	}
	out.Command = command
	out.Payload = payload
	return out, nil
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
	if err := validateRemoteVersion("", VersionPayloadV1{ProtocolVersion: 1}); err != nil {
		t.Fatalf("unexpected error: %v", err)
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
		_, _ = readWireMessage(reader, cfg.Network) // local version
		_ = writeWireMessage(remote, cfg.Network, WireMessage{Command: "ping"})
	}()

	_, err := PerformVersionHandshake(context.Background(), local, cfg, VersionPayloadV1{
		ProtocolVersion: 1,
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

func TestPeerSession_readMessage_InvalidChecksum(t *testing.T) {
	local, remote := net.Pipe()
	defer local.Close()
	defer remote.Close()

	ps := NewPeerSession(local, DefaultPeerRuntimeConfig("devnet", 1), PeerState{Addr: "pipe"})
	done := make(chan error, 1)
	go func() {
		payload := []byte{0x01, 0x02}
		header, err := buildEnvelopeHeader(networkMagic("devnet"), "ping", payload)
		if err != nil {
			done <- err
			return
		}
		header[20] ^= 0xff
		_, err = remote.Write(append(header, payload...))
		done <- err
	}()
	if _, err := ps.readMessage(); err == nil {
		t.Fatalf("expected checksum error")
	}
	if err := <-done; err != nil {
		t.Fatalf("writer error: %v", err)
	}
}

func TestPeerSession_readMessage_RejectsOversizePayload(t *testing.T) {
	local, remote := net.Pipe()
	defer local.Close()
	defer remote.Close()

	ps := NewPeerSession(local, DefaultPeerRuntimeConfig("devnet", 1), PeerState{Addr: "pipe"})
	done := make(chan error, 1)
	go func() {
		header := make([]byte, wireHeaderSize)
		magic := networkMagic("devnet")
		copy(header[:4], magic[:])
		cmd, err := encodeWireCommand("ping")
		if err != nil {
			done <- err
			return
		}
		copy(header[4:16], cmd[:])
		binary.LittleEndian.PutUint32(header[16:20], uint32(consensus.MAX_RELAY_MSG_BYTES+1))
		copy(header[20:24], []byte{1, 2, 3, 4})
		_, err = remote.Write(header)
		done <- err
	}()
	if _, err := ps.readMessage(); err == nil {
		t.Fatalf("expected oversize error")
	}
	if err := <-done; err != nil {
		t.Fatalf("writer error: %v", err)
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

func TestPeerSession_writeMessage_RejectsOversizePayload(t *testing.T) {
	c := &scriptedConn{
		remoteAddrString: "x",
	}
	ps := NewPeerSession(c, DefaultPeerRuntimeConfig("devnet", 1), PeerState{Addr: "x"})
	oversized := make([]byte, int(consensus.MAX_RELAY_MSG_BYTES)+1)
	if err := ps.writeMessage(WireMessage{Command: "ping", Payload: oversized}); err == nil {
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

func TestVersionPayloadMarshalRoundTripAndLegacy(t *testing.T) {
	in := VersionPayloadV1{
		ProtocolVersion:   7,
		TxRelay:           true,
		PrunedBelowHeight: 44,
		DaMempoolSize:     55,
	}
	payload := marshalVersionPayloadV1(in)
	out, err := unmarshalVersionPayloadV1(payload)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out != in {
		t.Fatalf("roundtrip mismatch: %+v vs %+v", out, in)
	}

	legacy := payload[:13]
	legacyOut, err := unmarshalVersionPayloadV1(legacy)
	if err != nil {
		t.Fatalf("legacy unmarshal: %v", err)
	}
	if legacyOut.DaMempoolSize != 0 || legacyOut.ProtocolVersion != in.ProtocolVersion {
		t.Fatalf("legacy decode mismatch: %+v", legacyOut)
	}

	extended := append(payload, []byte{1, 2, 3}...)
	extendedOut, err := unmarshalVersionPayloadV1(extended)
	if err != nil {
		t.Fatalf("extended unmarshal: %v", err)
	}
	if extendedOut != in {
		t.Fatalf("extended decode mismatch: %+v vs %+v", extendedOut, in)
	}
}

func TestEnvelopeCommandCodecValidation(t *testing.T) {
	if _, err := encodeWireCommand(""); err == nil {
		t.Fatalf("expected empty command error")
	}
	if _, err := encodeWireCommand("toolong-command"); err == nil {
		t.Fatalf("expected too-long command error")
	}
	if _, err := encodeWireCommand("pi\nng"); err == nil {
		t.Fatalf("expected non-printable error")
	}
	cmd, err := encodeWireCommand("ping")
	if err != nil {
		t.Fatalf("encode command: %v", err)
	}
	decoded, err := decodeWireCommand(cmd[:])
	if err != nil {
		t.Fatalf("decode command: %v", err)
	}
	if decoded != "ping" {
		t.Fatalf("decoded=%q, want ping", decoded)
	}
	bad := cmd
	bad[5] = 0x01
	if _, err := decodeWireCommand(bad[:]); err == nil {
		t.Fatalf("expected bad padding error")
	}
}
