package p2p

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/node"
)

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

type scriptedRead struct {
	data []byte
	err  error
}

type scriptedConn struct {
	reads []scriptedRead
	bytes.Buffer
}

func (c *scriptedConn) Read(p []byte) (int, error) {
	if len(c.reads) == 0 {
		return 0, io.EOF
	}
	current := &c.reads[0]
	if len(current.data) > 0 {
		n := copy(p, current.data)
		current.data = current.data[n:]
		if len(current.data) > 0 {
			return n, nil
		}
		err := current.err
		c.reads = c.reads[1:]
		return n, err
	}
	err := current.err
	c.reads = c.reads[1:]
	return 0, err
}

func (c *scriptedConn) Write(p []byte) (int, error) { return c.Buffer.Write(p) }
func (c *scriptedConn) Close() error                { return nil }
func (c *scriptedConn) LocalAddr() net.Addr         { return stubAddr("local") }
func (c *scriptedConn) RemoteAddr() net.Addr        { return stubAddr("remote") }
func (c *scriptedConn) SetDeadline(time.Time) error { return nil }
func (c *scriptedConn) SetReadDeadline(time.Time) error {
	return nil
}
func (c *scriptedConn) SetWriteDeadline(time.Time) error { return nil }

func TestShouldIgnoreAndNormalizeReadError(t *testing.T) {
	if !shouldIgnoreReadError(os.ErrDeadlineExceeded) {
		t.Fatalf("expected os.ErrDeadlineExceeded to be ignored")
	}
	if !shouldIgnoreReadError(timeoutErr{}) {
		t.Fatalf("expected timeout net.Error to be ignored")
	}
	partialTimeout := partialFrameTimeoutError{part: "header", read: 1, want: wireHeaderSize, err: timeoutErr{}}
	if shouldIgnoreReadError(partialTimeout) {
		t.Fatalf("partial frame timeout must disconnect instead of being ignored")
	}
	if shouldIgnoreReadError(io.EOF) {
		t.Fatalf("expected EOF to not be ignored")
	}

	if err := normalizeReadError(io.EOF); err != nil {
		t.Fatalf("EOF should normalize to nil, got %v", err)
	}
	if err := normalizeReadError(net.ErrClosed); err != nil {
		t.Fatalf("net.ErrClosed should normalize to nil, got %v", err)
	}
	boom := errors.New("boom")
	if err := normalizeReadError(boom); !errors.Is(err, boom) {
		t.Fatalf("normalizeReadError changed error: %v", err)
	}
}

func TestRunDisconnectsOnPartialHeaderTimeoutBeforeFakeFrame(t *testing.T) {
	p := newPeerRuntimeTestPeer(t)
	p.service.cfg.PeerRuntimeConfig.ReadDeadline = time.Millisecond

	staleHeaderPrefix := mustPeerRuntimeFrameBytes(t, p, message{Command: messagePing})[:8]
	fakeValidFrame := mustPeerRuntimeFrameBytes(t, p, message{Command: messagePing})
	p.conn = &scriptedConn{reads: []scriptedRead{
		{data: staleHeaderPrefix},
		{err: timeoutErr{}},
		{data: fakeValidFrame},
	}}

	err := p.run(context.Background())
	if err == nil {
		t.Fatalf("partial header timeout was ignored and allowed a later fake frame parse")
	}
	var partial partialFrameTimeoutError
	if !errors.As(err, &partial) {
		t.Fatalf("err=%v, want partialFrameTimeoutError", err)
	}
	if partial.part != "header" || partial.read != len(staleHeaderPrefix) || partial.want != wireHeaderSize {
		t.Fatalf("partial timeout=%+v, want header %d/%d", partial, len(staleHeaderPrefix), wireHeaderSize)
	}
}

func TestRunDisconnectsOnPayloadTimeoutBeforeFakeFrame(t *testing.T) {
	for _, tc := range []struct {
		name        string
		prefixBytes int
	}{
		{name: "timeout before first payload byte", prefixBytes: 0},
		{name: "timeout after one payload byte", prefixBytes: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := newPeerRuntimeTestPeer(t)
			p.service.cfg.PeerRuntimeConfig.ReadDeadline = time.Millisecond

			payload := []byte{0xaa, 0xbb}
			firstFrame := mustPeerRuntimeFrameBytes(t, p, message{Command: messageTx, Payload: payload})
			fakeValidFrame := mustPeerRuntimeFrameBytes(t, p, message{Command: messagePing})
			reads := []scriptedRead{{data: firstFrame[:wireHeaderSize]}}
			if tc.prefixBytes > 0 {
				reads = append(reads, scriptedRead{data: payload[:tc.prefixBytes]})
			}
			reads = append(reads,
				scriptedRead{err: timeoutErr{}},
				scriptedRead{data: fakeValidFrame},
			)
			p.conn = &scriptedConn{reads: reads}

			err := p.run(context.Background())
			if err == nil {
				t.Fatalf("partial payload timeout was ignored and allowed a later fake frame parse")
			}
			var partial partialFrameTimeoutError
			if !errors.As(err, &partial) {
				t.Fatalf("err=%v, want partialFrameTimeoutError", err)
			}
			wantRead := wireHeaderSize + tc.prefixBytes
			if partial.part != "payload" || partial.read != wantRead || partial.want != wireHeaderSize+len(payload) {
				t.Fatalf("partial timeout=%+v, want payload %d/%d", partial, wantRead, wireHeaderSize+len(payload))
			}
		})
	}
}

func TestRunKeepsIdleTimeoutAndCompleteFrameValid(t *testing.T) {
	p := newPeerRuntimeTestPeer(t)
	p.service.cfg.PeerRuntimeConfig.ReadDeadline = time.Millisecond
	p.conn = &scriptedConn{reads: []scriptedRead{
		{err: timeoutErr{}},
		{data: mustPeerRuntimeFrameBytes(t, p, message{Command: messagePing})},
		{err: io.EOF},
	}}

	if err := p.run(context.Background()); err != nil {
		t.Fatalf("idle timeout followed by a complete valid frame should remain valid, got %v", err)
	}
}

func TestHandleMessageRejectsInvalidKinds(t *testing.T) {
	p := newPeerRuntimeTestPeer(t)
	if err := p.handleMessage(message{Command: messageVersion}); err == nil || !strings.Contains(err.Error(), "invalid version message") {
		t.Fatalf("expected version rejection, got %v", err)
	}
	if err := p.handleMessage(message{Command: "unknown"}); err == nil || !strings.Contains(err.Error(), "unknown message type") {
		t.Fatalf("expected unknown-kind rejection, got %v", err)
	}
}

func TestMissingInventoryAndNeedsInventory(t *testing.T) {
	p := newPeerRuntimeTestPeer(t)
	var seenBlock [32]byte
	seenBlock[0] = 0x01
	p.service.blockSeen.Add(seenBlock)

	var unknownBlock [32]byte
	unknownBlock[0] = 0x02
	var unseenTx [32]byte
	unseenTx[0] = 0x03
	var pooledTx [32]byte
	pooledTx[0] = 0x04
	p.service.cfg.TxPool.Put(pooledTx, []byte{0x01}, 1, 1)

	items := []InventoryVector{
		{Type: MSG_BLOCK, Hash: seenBlock},
		{Type: MSG_BLOCK, Hash: unknownBlock},
		{Type: MSG_TX, Hash: unseenTx},
		{Type: MSG_TX, Hash: pooledTx},
		{Type: 99, Hash: [32]byte{0x05}},
	}
	requests, err := p.missingInventory(items)
	if err != nil {
		t.Fatalf("missingInventory: %v", err)
	}
	if len(requests) != 2 {
		t.Fatalf("requests=%v, want 2 items", requests)
	}
	if requests[0].Hash != unknownBlock || requests[1].Hash != unseenTx {
		t.Fatalf("unexpected requests order/content: %v", requests)
	}
}

func TestCanonicalTxIDAcceptsCanonicalAndRejectsTrailingBytes(t *testing.T) {
	txBytes := mustMarshalPeerRuntimeTx(t, &consensus.Tx{
		Version:   1,
		TxKind:    0x00,
		TxNonce:   7,
		Inputs:    nil,
		Outputs:   nil,
		Locktime:  0,
		Witness:   nil,
		DaPayload: nil,
	})

	txid, err := canonicalTxID(txBytes)
	if err != nil {
		t.Fatalf("canonicalTxID: %v", err)
	}
	_, parsedTxID, _, consumed, err := consensus.ParseTx(txBytes)
	if err != nil {
		t.Fatalf("ParseTx: %v", err)
	}
	if consumed != len(txBytes) {
		t.Fatalf("consumed=%d len=%d", consumed, len(txBytes))
	}
	if txid != parsedTxID {
		t.Fatalf("txid mismatch")
	}

	_, err = canonicalTxID(append(append([]byte(nil), txBytes...), 0x00))
	if err == nil || !strings.Contains(err.Error(), "non-canonical tx bytes") {
		t.Fatalf("expected non-canonical error, got %v", err)
	}
}

func TestSetLastErrorAndBumpBanPersistState(t *testing.T) {
	p := newPeerRuntimeTestPeer(t)
	p.setLastError("read failed")
	snap := p.snapshotState()
	if snap.LastError != "read failed" {
		t.Fatalf("last_error=%q, want read failed", snap.LastError)
	}

	if p.bumpBan(50, "warn") {
		t.Fatalf("unexpected ban threshold reached")
	}
	if !p.bumpBan(60, "fatal") {
		t.Fatalf("expected ban threshold reached")
	}
	snap = p.snapshotState()
	if snap.BanScore != 110 {
		t.Fatalf("ban_score=%d, want 110", snap.BanScore)
	}
	if snap.LastError != "fatal" {
		t.Fatalf("last_error=%q, want fatal", snap.LastError)
	}
	pmState := p.service.cfg.PeerManager.Snapshot()
	if len(pmState) != 1 || pmState[0].BanScore != 110 {
		t.Fatalf("peer manager snapshot=%v, want single updated peer", pmState)
	}
}

func TestApplyPostHandshakeDisconnectErrorUnknownCommandNoBan(t *testing.T) {
	p := newPeerRuntimeTestPeer(t)
	err := postHandshakeUnknownCommandError{command: "weird"}
	reason, ok := unknownCommandPolicyReason(err)
	if !ok {
		t.Fatalf("unknown command policy reason not detected")
	}
	if reason != "unknown command: weird" {
		t.Fatalf("reason=%q, want unknown command: weird", reason)
	}
	p.applyPostHandshakeDisconnectError(err)
	snap := p.snapshotState()
	if snap.BanScore != 0 {
		t.Fatalf("ban_score=%d, want 0 for unknown post-handshake command", snap.BanScore)
	}
	if snap.LastError != "unknown command: weird" {
		t.Fatalf("last_error=%q, want unknown command: weird", snap.LastError)
	}

	unknownReason, unknownOK := unknownCommandPolicyReason(errors.New("plain runtime error"))
	if unknownOK || unknownReason != "" {
		t.Fatalf("plain error reason=%q ok=%v, want empty/false", unknownReason, unknownOK)
	}
}

func TestApplyPostHandshakeDisconnectErrorNilAndGenericFallback(t *testing.T) {
	p := newPeerRuntimeTestPeer(t)
	p.setLastError("keep")
	before := p.snapshotState()
	p.applyPostHandshakeDisconnectError(nil)
	after := p.snapshotState()
	if after.LastError != before.LastError || after.BanScore != before.BanScore {
		t.Fatalf("nil disconnect error mutated state: before=%+v after=%+v", before, after)
	}

	p.applyPostHandshakeDisconnectError(errors.New("plain runtime error"))
	snap := p.snapshotState()
	if snap.LastError != "plain runtime error" {
		t.Fatalf("last_error=%q, want plain runtime error", snap.LastError)
	}
	if snap.BanScore != 0 {
		t.Fatalf("ban_score=%d, want 0 for generic runtime error mapping", snap.BanScore)
	}
}

func TestRunUnknownCommandDisconnectWithoutBan(t *testing.T) {
	p := newPeerRuntimeTestPeer(t)
	local, remote := net.Pipe()
	defer local.Close()
	defer remote.Close()
	p.conn = local
	p.service.cfg.PeerRuntimeConfig.ReadDeadline = 0
	p.service.cfg.PeerRuntimeConfig.WriteDeadline = 0

	writeErrCh := make(chan error, 1)
	go func() {
		writeErrCh <- writeFrame(
			remote,
			networkMagic(p.service.cfg.PeerRuntimeConfig.Network),
			message{Command: "weird"},
			p.service.cfg.PeerRuntimeConfig.MaxMessageSize,
		)
	}()

	err := p.run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "unknown message type: weird") {
		t.Fatalf("expected unknown-command disconnect error, got %v", err)
	}
	if writeErr := <-writeErrCh; writeErr != nil {
		t.Fatalf("writeFrame(unknown): %v", writeErr)
	}

	reason, ok := unknownCommandPolicyReason(err)
	if !ok || reason != "unknown command: weird" {
		t.Fatalf("reason=%q ok=%v, want unknown command policy reason", reason, ok)
	}

	p.applyPostHandshakeDisconnectError(err)
	snap := p.snapshotState()
	if snap.BanScore != 0 {
		t.Fatalf("ban_score=%d, want 0 for unknown command disconnect", snap.BanScore)
	}
	if snap.LastError != "unknown command: weird" {
		t.Fatalf("last_error=%q, want unknown command: weird", snap.LastError)
	}
}

func TestSendAndRunContextCancellation(t *testing.T) {
	p := newPeerRuntimeTestPeer(t)
	local, remote := net.Pipe()
	defer local.Close()
	defer remote.Close()
	p.conn = local
	p.service.cfg.PeerRuntimeConfig.ReadDeadline = 0
	p.service.cfg.PeerRuntimeConfig.WriteDeadline = 0

	errCh := make(chan error, 1)
	go func() {
		msg, err := readFrame(remote, networkMagic(p.service.cfg.PeerRuntimeConfig.Network), p.service.cfg.PeerRuntimeConfig.MaxMessageSize)
		if err != nil {
			errCh <- err
			return
		}
		if msg.Command != messageTx || !bytes.Equal(msg.Payload, []byte{0xaa, 0xbb}) {
			errCh <- errors.New("unexpected frame")
			return
		}
		errCh <- nil
	}()

	if err := p.send(messageTx, []byte{0xaa, 0xbb}); err != nil {
		t.Fatalf("send: %v", err)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("remote read: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := p.run(ctx); err != nil {
		t.Fatalf("run(ctx canceled): %v", err)
	}
}

func newPeerRuntimeTestPeer(t *testing.T) *peer {
	t.Helper()
	dir := t.TempDir()
	chainState := node.NewChainState()
	blockStore, err := node.OpenBlockStore(node.BlockStorePath(dir))
	if err != nil {
		t.Fatalf("OpenBlockStore: %v", err)
	}
	syncEngine, err := node.NewSyncEngine(
		chainState,
		blockStore,
		node.DefaultSyncConfig(nil, node.DevnetGenesisChainID(), node.ChainStatePath(dir)),
	)
	if err != nil {
		t.Fatalf("NewSyncEngine: %v", err)
	}
	cfg := ServiceConfig{
		BindAddr:          "127.0.0.1:0",
		GenesisHash:       node.DevnetGenesisBlockHash(),
		PeerManager:       node.NewPeerManager(node.DefaultPeerRuntimeConfig("devnet", 8)),
		SyncConfig:        node.DefaultSyncConfig(nil, node.DevnetGenesisChainID(), node.ChainStatePath(dir)),
		SyncEngine:        syncEngine,
		BlockStore:        blockStore,
		TxPool:            NewMemoryTxPool(),
		TxMetadataFunc:    testHarnessDefaultTxMetadata,
		PeerRuntimeConfig: node.DefaultPeerRuntimeConfig("devnet", 8),
		Now:               time.Now,
	}
	svc, err := NewService(cfg)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	pr := &peer{
		service: svc,
		state: node.PeerState{
			Addr: "peer-test",
			RemoteVersion: node.VersionPayloadV1{
				BestHeight: 0,
			},
		},
	}
	if err := svc.cfg.PeerManager.AddPeer(&pr.state); err != nil {
		t.Fatalf("AddPeer: %v", err)
	}
	return pr
}

func mustMarshalPeerRuntimeTx(t *testing.T, tx *consensus.Tx) []byte {
	t.Helper()
	b, err := consensus.MarshalTx(tx)
	if err != nil {
		t.Fatalf("MarshalTx: %v", err)
	}
	return b
}

func mustPeerRuntimeFrameBytes(t *testing.T, p *peer, frame message) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := writeFrame(
		&buf,
		networkMagic(p.service.cfg.PeerRuntimeConfig.Network),
		frame,
		p.service.cfg.PeerRuntimeConfig.MaxMessageSize,
	); err != nil {
		t.Fatalf("writeFrame(%q): %v", frame.Command, err)
	}
	return buf.Bytes()
}

// TestPeerLifecycleExitsCounter_SingleRemovalIncrementsOnce registers
// one peer manually, calls unregisterPeer once.
// Proof assertion: PeerLifecycleExits() == 1 after the call AND
// the peer key is gone from s.peers.
func TestPeerLifecycleExitsCounter_SingleRemovalIncrementsOnce(t *testing.T) {
	h := newTestHarness(t, 0, "127.0.0.1:0", nil)
	p := &peer{service: h.service, state: node.PeerState{Addr: "peer-A"}}
	h.service.peers[p.addr()] = p
	if got := h.service.PeerLifecycleExits(); got != 0 {
		t.Fatalf("baseline counter=%d want 0", got)
	}
	h.service.unregisterPeer(p)
	if got := h.service.PeerLifecycleExits(); got != 1 {
		t.Fatalf("counter=%d want 1 after one unregister", got)
	}
	if _, still := h.service.peers[p.addr()]; still {
		t.Fatalf("peer still registered after unregister")
	}
}

// TestPeerLifecycleExitsCounter_RepeatedUnregisterDoesNotDoubleCount
// pins the dedupe contract: cleanup retries on an already-removed
// peer must not bump the counter again.
// Proof assertion: PeerLifecycleExits() == 1 after the second
// unregisterPeer call (the first bumped to 1, the second is a no-op).
func TestPeerLifecycleExitsCounter_RepeatedUnregisterDoesNotDoubleCount(t *testing.T) {
	h := newTestHarness(t, 0, "127.0.0.1:0", nil)
	p := &peer{service: h.service, state: node.PeerState{Addr: "peer-B"}}
	h.service.peers[p.addr()] = p
	h.service.unregisterPeer(p)
	first := h.service.PeerLifecycleExits()
	h.service.unregisterPeer(p)
	if got := h.service.PeerLifecycleExits(); got != first {
		t.Fatalf("counter=%d want %d after repeat unregister (no second bump)", got, first)
	}
	if first != 1 {
		t.Fatalf("first unregister bumped counter to %d, want 1", first)
	}
}

// TestPeerLifecycleExitsCounter_AliasEntriesCountAsOneExit registers
// a peer twice into s.peers under two distinct keys, mirroring
// registerPeer's canonical-addr-plus-remoteAddr-alias path.
// Proof assertion: PeerLifecycleExits() == 1 after one
// unregisterPeer call AND len(s.peers) == 0; the alias entries
// collapse into a single exit increment.
func TestPeerLifecycleExitsCounter_AliasEntriesCountAsOneExit(t *testing.T) {
	h := newTestHarness(t, 0, "127.0.0.1:0", nil)
	p := &peer{service: h.service, state: node.PeerState{Addr: "peer-C"}}
	h.service.peers[p.addr()] = p
	h.service.peers["peer-C-alias"] = p
	if len(h.service.peers) != 2 {
		t.Fatalf("setup peers=%d want 2", len(h.service.peers))
	}
	h.service.unregisterPeer(p)
	if got := h.service.PeerLifecycleExits(); got != 1 {
		t.Fatalf("counter=%d want 1 (alias entries collapse into one exit)", got)
	}
	if len(h.service.peers) != 0 {
		t.Fatalf("peers map=%d after alias unregister, want 0", len(h.service.peers))
	}
}

// TestPeerLifecycleExitsCounter_UnknownPeerNoBump constructs a peer
// that was never registered and calls unregisterPeer on it.
// Proof assertion: PeerLifecycleExits() == 0 because
// unregisterPeer's `remove` flag stays false when the peer has no
// entry in s.peers, so the increment branch is skipped.
func TestPeerLifecycleExitsCounter_UnknownPeerNoBump(t *testing.T) {
	h := newTestHarness(t, 0, "127.0.0.1:0", nil)
	stranger := &peer{service: h.service, state: node.PeerState{Addr: "peer-stranger"}}
	h.service.unregisterPeer(stranger)
	if got := h.service.PeerLifecycleExits(); got != 0 {
		t.Fatalf("counter=%d want 0 for unregister on never-registered peer", got)
	}
}

// TestPeerLifecycleExitsCounter_NilReceiverReturnsZero pins the
// nil-receiver contract on the public accessor.
// Proof assertion: ((*Service)(nil)).PeerLifecycleExits() == 0
// without panic.
func TestPeerLifecycleExitsCounter_NilReceiverReturnsZero(t *testing.T) {
	var s *Service
	if got := s.PeerLifecycleExits(); got != 0 {
		t.Fatalf("nil receiver counter=%d want 0", got)
	}
}

// TestPeerLifecycleExitsCounter_TwoPeersExitsTotalsTwo registers two
// distinct peers and unregisters both.
// Proof assertion: PeerLifecycleExits() == 2; the increment is
// per-peer, not per-call or per-map-entry.
func TestPeerLifecycleExitsCounter_TwoPeersExitsTotalsTwo(t *testing.T) {
	h := newTestHarness(t, 0, "127.0.0.1:0", nil)
	p1 := &peer{service: h.service, state: node.PeerState{Addr: "peer-1"}}
	p2 := &peer{service: h.service, state: node.PeerState{Addr: "peer-2"}}
	h.service.peers[p1.addr()] = p1
	h.service.peers[p2.addr()] = p2
	h.service.unregisterPeer(p1)
	h.service.unregisterPeer(p2)
	if got := h.service.PeerLifecycleExits(); got != 2 {
		t.Fatalf("counter=%d want 2 after two distinct peer exits", got)
	}
}
