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

type clock struct{ now time.Time }

func (c *clock) Now() time.Time          { return c.now }
func (c *clock) advance(d time.Duration) { c.now = c.now.Add(d) }

type expiryWakeConn struct {
	scriptedConn
	readCount int
	onRead    func(int)
}

func (c *expiryWakeConn) Read(p []byte) (int, error) {
	c.readCount++
	if c.onRead != nil {
		c.onRead(c.readCount)
	}
	return c.scriptedConn.Read(p)
}

func (c *expiryWakeConn) expireOnRead(ck *clock, readCount int) {
	c.onRead = func(n int) {
		if n == readCount {
			ck.advance(compactOutstandingRequestTTL + time.Second)
		}
	}
}

func setupCompactFallbackPeer(t *testing.T) (*peer, *clock) {
	p := newPeerRuntimeTestPeer(t)
	p.service.cfg.EnableCompactReceive = true
	p.setRemoteCompactMode(compactModeSnapshot{Mode: 1, Version: compactRelayVersion})
	ck := &clock{now: time.Now()}
	p.service.cfg.Now = func() time.Time { return ck.now }
	p.activateCompactOutstandingRequest(compactOutstandingTestRequest([32]byte{0x11}))
	return p, ck
}

func requireFirstGetDataBlock(t *testing.T, p *peer, written []byte, wantHash [32]byte) {
	frame, err := readFrameHeader(bytes.NewReader(written), networkMagic(p.service.cfg.PeerRuntimeConfig.Network), p.service.cfg.PeerRuntimeConfig.MaxMessageSize)
	if err != nil || frame.Command != messageGetData {
		t.Fatalf("first write command=%q err=%v, want %q", frame.Command, err, messageGetData)
	}
	payloadEnd := wireHeaderSize + int(frame.Size)
	if len(written) < payloadEnd {
		t.Fatalf("first write length=%d, want at least %d", len(written), payloadEnd)
	}
	payload := written[wireHeaderSize:payloadEnd]
	items, err := decodeInventoryVectors(payload)
	if err != nil {
		t.Fatalf("decode fallback getdata: %v", err)
	}
	if len(items) != 1 || items[0].Type != MSG_BLOCK || items[0].Hash != wantHash {
		t.Fatalf("fallback inventory=%+v, want MSG_BLOCK %x", items, wantHash)
	}
}

func requireBlockTxnStaleBodyError(t *testing.T, err error) {
	t.Helper()
	var staleErr blockTxnStaleBodyError
	if !errors.As(err, &staleErr) {
		t.Fatalf("err=%T %v, want blockTxnStaleBodyError", err, err)
	}
}

func runExpiredLateBlockTxnFrame(t *testing.T, req compactOutstandingRequest, payload []byte, tail ...message) (*peer, *scriptedConn, error) {
	t.Helper()
	p, ck := setupCompactFallbackPeer(t)
	p.activateCompactOutstandingRequest(req)
	ck.advance(compactOutstandingRequestTTL + time.Second)
	reads := []scriptedRead{{data: mustPeerRuntimeFrameBytes(t, p, message{Command: messageBlockTxn, Payload: payload})}}
	for _, frame := range tail {
		reads = append(reads, scriptedRead{data: mustPeerRuntimeFrameBytes(t, p, frame)})
	}
	conn := &scriptedConn{reads: reads}
	p.conn = conn
	return p, conn, p.run(context.Background())
}

type scriptedRead struct {
	data []byte
	err  error
}

type scriptedConn struct {
	reads []scriptedRead
	bytes.Buffer
	writeCount      int
	writeHook       func(int)
	writeErr        error
	writeErrAt      int
	readDeadlineErr error
	readDeadlines   []time.Time
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

func (c *scriptedConn) Write(p []byte) (int, error) {
	n, err := c.Buffer.Write(p)
	c.writeCount++
	if c.writeHook != nil {
		c.writeHook(c.writeCount)
	}
	if c.writeErr != nil && (c.writeErrAt == 0 || c.writeCount == c.writeErrAt) {
		return n, c.writeErr
	}
	return n, err
}
func (c *scriptedConn) Close() error                { return nil }
func (c *scriptedConn) LocalAddr() net.Addr         { return stubAddr("local") }
func (c *scriptedConn) RemoteAddr() net.Addr        { return stubAddr("remote") }
func (c *scriptedConn) SetDeadline(time.Time) error { return nil }
func (c *scriptedConn) SetReadDeadline(t time.Time) error {
	c.readDeadlines = append(c.readDeadlines, t)
	return c.readDeadlineErr
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

func TestCompactObjectCapsStayClosedUntilReceiveEnabled(t *testing.T) {
	p := newPeerRuntimeTestPeer(t)
	limiter := p.postHandshakePayloadCap()
	for _, command := range []string{messageCmpctBlock, messageGetBlockTxn, messageBlockTxn, messageGetDAChunk} {
		if got := limiter(command); got != 0 {
			t.Fatalf("pre-negotiation %s cap=%d, want 0", command, got)
		}
	}

	p.setRemoteCompactMode(compactModeSnapshot{Mode: 1, Version: compactRelayVersion})
	limiter = p.postHandshakePayloadCap()
	p.setCompactOutstandingRequest(compactOutstandingRequest{BlockTxnPayloadCap: compactRelayPayloadCap(messageBlockTxn) + 1})
	for _, command := range []string{messageCmpctBlock, messageGetBlockTxn, messageBlockTxn, messageGetDAChunk} {
		if got := limiter(command); got != 0 {
			t.Fatalf("negotiated %s cap=%d, want 0 while compact receive is disabled", command, got)
		}
	}
}

func TestCompactObjectCapsOpenOnlyForEnabledNegotiatedReceive(t *testing.T) {
	p := newPeerRuntimeTestPeer(t)
	p.service.cfg.EnableCompactReceive = true
	limiter := p.postHandshakePayloadCap()
	for _, command := range []string{messageCmpctBlock, messageGetBlockTxn, messageBlockTxn, messageGetDAChunk} {
		if got := limiter(command); got != 0 {
			t.Fatalf("pre-negotiation %s cap=%d, want 0", command, got)
		}
	}

	p.setRemoteCompactMode(compactModeSnapshot{Mode: 1, Version: compactRelayVersion})
	if got := limiter(messageCmpctBlock); got != uint32(consensus.MAX_RELAY_MSG_BYTES) {
		t.Fatalf("negotiated cmpctblock cap=%d, want %d", got, consensus.MAX_RELAY_MSG_BYTES)
	}
	if got, want := limiter(messageGetBlockTxn), compactRelayPayloadCap(messageGetBlockTxn); got != want {
		t.Fatalf("inbound getblocktxn cap=%d, want %d", got, want)
	}
	if got, want := limiter(messageGetDAChunk), getDAChunkPayloadCap(); got != want {
		t.Fatalf("inbound getdachunk cap=%d, want %d", got, want)
	}
	if got := limiter(messageBlockTxn); got != blockTxnHashPayloadBytes {
		t.Fatalf("blocktxn cap without outstanding=%d, want hash-only cap %d", got, blockTxnHashPayloadBytes)
	}
	p.setCompactOutstandingRequest(compactOutstandingRequest{BlockTxnPayloadCap: 64})
	if got := limiter(messageBlockTxn); got != 64 {
		t.Fatalf("blocktxn cap with outstanding=%d, want 64", got)
	}
	p.setRemoteCompactMode(compactModeSnapshot{Mode: 0, Version: compactRelayVersion})
	if got := limiter(messageCmpctBlock); got != 0 {
		t.Fatalf("disabled cmpctblock cap=%d, want 0", got)
	}
	if got := limiter(messageGetBlockTxn); got != 0 {
		t.Fatalf("disabled getblocktxn cap=%d, want 0", got)
	}
	if got := limiter(messageGetDAChunk); got != 0 {
		t.Fatalf("disabled getdachunk cap=%d, want 0", got)
	}
	if got := limiter(messageBlockTxn); got != 64 {
		t.Fatalf("disabled-mode blocktxn cap with outstanding=%d, want 64", got)
	}
}

func TestBlockTxnPayloadCapIsOutstandingBounded(t *testing.T) {
	p := newPeerRuntimeTestPeer(t)
	if got := p.blockTxnPayloadCap(); got != 0 {
		t.Fatalf("blocktxn cap without outstanding=%d, want 0", got)
	}

	tx := minimalBlockTxnTestTxBytes(81)
	req := compactOutstandingRequest{MissingIndexes: []uint64{1}, MissingShortIDs: []compactShortID{{0x01}}, Transactions: [][]byte{tx}, BlockTxnPayloadCap: 64}
	p.setCompactOutstandingRequest(req)
	req.MissingIndexes[0], req.MissingShortIDs[0], req.Transactions[0][0] = 9, compactShortID{0x02}, 0xff
	if snap, ok := p.compactOutstandingRequestSnapshot(); !ok || snap.BlockTxnPayloadCap != 64 {
		t.Fatalf("snapshot cap=%+v ok=%v, want 64", snap, ok)
	} else if snap.MissingIndexes[0] != 1 || snap.MissingShortIDs[0] != (compactShortID{0x01}) || snap.Transactions[0][0] == 0xff {
		t.Fatalf("snapshot aliases original request: %+v", snap)
	} else {
		snap.MissingIndexes[0], snap.Transactions[0][0] = 7, 0xee
	}
	if got := p.blockTxnPayloadCap(); got != 64 {
		t.Fatalf("blocktxn bounded cap=%d, want 64", got)
	}
	if snap, ok := p.compactOutstandingRequestSnapshot(); !ok || snap.MissingIndexes[0] != 1 || snap.Transactions[0][0] == 0xee {
		t.Fatalf("snapshot aliases previous snapshot: %+v ok=%v", snap, ok)
	}

	p.setCompactOutstandingRequest(compactOutstandingRequest{BlockTxnPayloadCap: compactRelayPayloadCap(messageBlockTxn) + 1})
	if got := p.blockTxnPayloadCap(); got != compactRelayPayloadCap(messageBlockTxn) {
		t.Fatalf("blocktxn oversized cap=%d, want max %d", got, compactRelayPayloadCap(messageBlockTxn))
	}
	if popped, ok := p.popCompactOutstandingRequest(); !ok || popped.BlockTxnPayloadCap != compactRelayPayloadCap(messageBlockTxn)+1 {
		t.Fatalf("popped cap=%+v ok=%v, want oversized request", popped, ok)
	}
	if got := p.blockTxnPayloadCap(); got != 0 {
		t.Fatalf("blocktxn cap after pop=%d, want 0", got)
	}
}

func TestCompactOutstandingRequestUsesDedicatedTTL(t *testing.T) {
	p := newPeerRuntimeTestPeer(t)
	now := time.Unix(1000, 0)
	p.service.cfg.Now = func() time.Time { return now }
	p.service.cfg.PeerRuntimeConfig.ReadDeadline = 0
	p.activateCompactOutstandingRequest(compactOutstandingTestRequest([32]byte{0x11}))
	if got := p.blockTxnPayloadCap(); got != 64 {
		t.Fatalf("disabled-deadline blocktxn cap=%d, want 64", got)
	}
	now = now.Add(compactOutstandingRequestTTL - time.Nanosecond)
	if got := p.blockTxnPayloadCap(); got != 64 {
		t.Fatalf("pre-expiry blocktxn cap=%d, want 64", got)
	}
	now = now.Add(time.Nanosecond)
	if got := p.blockTxnPayloadCap(); got != 0 {
		t.Fatalf("expired blocktxn cap=%d, want 0", got)
	}
	if gotHash, gotCap, ok := p.popExpiredCompactOutstandingBlockHashAndPayloadCap(); !ok || gotHash != ([32]byte{0x11}) || gotCap != 64 {
		t.Fatalf("expired pop hash=%x cap=%d ok=%v, want hash 0x11 cap 64", gotHash, gotCap, ok)
	}
}

func TestCompactOutstandingRequestActivatesAfterSuccessfulSend(t *testing.T) {
	p := newPeerRuntimeTestPeer(t)
	p.conn = &scriptedConn{}
	p.service.cfg.PeerRuntimeConfig.MaxMessageSize = 1
	req := compactOutstandingTestRequest([32]byte{0x22})
	if err := p.sendCompactOutstandingRequest(req); err == nil {
		t.Fatal("oversized getblocktxn send should fail")
	}
	if _, ok := p.compactOutstandingRequestSnapshot(); ok {
		t.Fatal("failed getblocktxn send left active outstanding request")
	}

	p = newPeerRuntimeTestPeer(t)
	p.conn = &scriptedConn{}
	if err := p.sendCompactOutstandingRequest(req); err != nil {
		t.Fatalf("sendCompactOutstandingRequest: %v", err)
	}
	if snap, ok := p.compactOutstandingRequestSnapshot(); !ok || snap.BlockHash != req.BlockHash {
		t.Fatalf("outstanding=%+v ok=%v, want sent request", snap, ok)
	}
	frame, err := readFrame(bytes.NewReader(p.conn.(*scriptedConn).Buffer.Bytes()), networkMagic(p.service.cfg.PeerRuntimeConfig.Network), p.service.cfg.PeerRuntimeConfig.MaxMessageSize)
	if err != nil {
		t.Fatalf("read sent frame: %v", err)
	}
	if frame.Command != messageGetBlockTxn {
		t.Fatalf("sent command=%q, want %q", frame.Command, messageGetBlockTxn)
	}
}

func TestCompactOutstandingRequestDoesNotActivateOnEncodeError(t *testing.T) {
	p := newPeerRuntimeTestPeer(t)
	p.conn = &scriptedConn{}
	req := compactOutstandingTestRequest([32]byte{0x44})
	req.MissingIndexes = []uint64{maxCompactRelayIndexValue + 1}
	if err := p.sendCompactOutstandingRequest(req); err == nil || !strings.Contains(err.Error(), "compact relay index out of range") {
		t.Fatalf("sendCompactOutstandingRequest err=%v, want compact relay index out of range", err)
	}
	if _, ok := p.compactOutstandingRequestSnapshot(); ok {
		t.Fatal("encode failure left active outstanding request")
	}
	if got := p.conn.(*scriptedConn).Len(); got != 0 {
		t.Fatalf("encode failure wrote %d bytes, want 0", got)
	}
}

func TestExpiredCompactOutstandingAccessorsPreserveStateForFallbackPop(t *testing.T) {
	p := newPeerRuntimeTestPeer(t)
	now := time.Unix(1000, 0)
	p.service.cfg.Now = func() time.Time { return now }
	req := compactOutstandingTestRequest([32]byte{0x55})

	p.activateCompactOutstandingRequest(req)
	now = now.Add(compactOutstandingRequestTTL)
	if snap, ok := p.compactOutstandingRequestSnapshot(); ok {
		t.Fatalf("snapshot=%+v ok=%v, want expired request hidden", snap, ok)
	}
	if snap, ok := p.popCompactOutstandingRequest(); ok {
		t.Fatalf("pop=%+v ok=%v, want expired request hidden", snap, ok)
	}
	gotHash, gotCap, ok := p.popExpiredCompactOutstandingBlockHashAndPayloadCap()
	if !ok || gotHash != req.BlockHash || gotCap != req.BlockTxnPayloadCap {
		t.Fatalf("fallback pop hash=%x cap=%d ok=%v, want hash %x cap %d", gotHash, gotCap, ok, req.BlockHash, req.BlockTxnPayloadCap)
	}
}

func TestPopCompactOutstandingRequestKeepsSnapshotAcrossExpiryRace(t *testing.T) {
	p := newPeerRuntimeTestPeer(t)
	start := time.Unix(1000, 0)
	current := start
	p.service.cfg.Now = func() time.Time { return current }
	blockHash := [32]byte{0x33}
	p.activateCompactOutstandingRequest(compactOutstandingTestRequest(blockHash))

	current = start.Add(compactOutstandingRequestTTL - time.Nanosecond)
	calls := 0
	p.service.cfg.Now = func() time.Time {
		calls++
		if calls == 1 {
			return current
		}
		return current.Add(time.Second)
	}
	snap, ok := p.popCompactOutstandingRequest()
	if !ok || snap.BlockHash != blockHash {
		t.Fatalf("pop snapshot=%+v ok=%v, want matching request", snap, ok)
	}
	if _, still := p.compactOutstandingRequestSnapshot(); still {
		t.Fatal("popped outstanding request still active")
	}
}

func TestFullBlockClearsMatchingCompactOutstanding(t *testing.T) {
	p := newPeerRuntimeTestPeer(t)
	_, blockHash, err := parseRelayedBlock(node.DevnetGenesisBlockBytes())
	if err != nil {
		t.Fatalf("parse genesis block: %v", err)
	}
	p.activateCompactOutstandingRequest(compactOutstandingTestRequest(blockHash))
	if err := p.handleBlock(node.DevnetGenesisBlockBytes()); err != nil {
		t.Fatalf("handleBlock(genesis): %v", err)
	}
	if _, ok := p.compactOutstandingRequestSnapshot(); ok {
		t.Fatal("full-block accept did not clear matching compact outstanding request")
	}
}

func TestAlreadyHaveFullBlockClearsMatchingCompactOutstanding(t *testing.T) {
	h := newTestHarness(t, 1, "127.0.0.1:0", nil)
	p := testPeerForService(h.service, "remote", 0)
	_, blockHash, err := parseRelayedBlock(node.DevnetGenesisBlockBytes())
	if err != nil {
		t.Fatalf("parse genesis block: %v", err)
	}
	ck := &clock{now: time.Now()}
	p.service.cfg.Now = ck.Now
	p.activateCompactOutstandingRequest(compactOutstandingTestRequest(blockHash))
	conn := &expiryWakeConn{scriptedConn: scriptedConn{reads: []scriptedRead{
		{data: mustPeerRuntimeFrameBytes(t, p, message{Command: messageBlock, Payload: node.DevnetGenesisBlockBytes()})},
		{err: io.EOF},
	}}}
	conn.expireOnRead(ck, 1)
	p.conn = conn

	requireNoCompactErr(t, p.run(context.Background()), "run existing full block")
	if _, ok := p.compactOutstandingRequestSnapshot(); ok {
		t.Fatal("already-have full block did not clear matching compact outstanding request")
	}
	if written := conn.Bytes(); len(written) != 0 {
		t.Fatalf("existing full block wrote duplicate fallback bytes: %d", len(written))
	}
}

func TestHasBlockErrorFullBlockClearsMatchingCompactOutstanding(t *testing.T) {
	h := newTestHarness(t, 1, "127.0.0.1:0", nil)
	p := testPeerForService(h.service, "remote", 0)
	_, blockHash, err := parseRelayedBlock(node.DevnetGenesisBlockBytes())
	if err != nil {
		t.Fatalf("parse genesis block: %v", err)
	}
	p.activateCompactOutstandingRequest(compactOutstandingTestRequest(blockHash))
	p.service.cfg.BlockStore = nil
	if _, err := p.processRelayedBlock(node.DevnetGenesisBlockBytes()); err == nil {
		t.Fatal("processRelayedBlock with nil blockstore unexpectedly succeeded")
	}
	if _, ok := p.compactOutstandingRequestSnapshot(); ok {
		t.Fatal("has-block error full block did not clear matching compact outstanding request")
	}
}

func TestOrphanFullBlockClearsMatchingCompactOutstanding(t *testing.T) {
	source := newTestHarness(t, 3, "127.0.0.1:0", nil)
	sink := newTestHarness(t, 0, "127.0.0.1:0", nil)
	blockHash, blockBytes := testHarnessBlockAtHeight(t, source, 2)
	p := testPeerForService(sink.service, "remote", 2)
	p.activateCompactOutstandingRequest(compactOutstandingTestRequest(blockHash))
	summary, err := p.processRelayedBlock(blockBytes)
	if err != nil {
		t.Fatalf("processRelayedBlock(orphan): %v", err)
	}
	if summary != nil {
		t.Fatalf("summary=%v, want nil for retained orphan", summary)
	}
	if _, ok := p.compactOutstandingRequestSnapshot(); ok {
		t.Fatal("retained full-block orphan did not clear matching compact outstanding request")
	}
}

func TestApplyErrorFullBlockClearsMatchingCompactOutstanding(t *testing.T) {
	source := newTestHarness(t, 2, "127.0.0.1:0", nil)
	sink := newTestHarness(t, 1, "127.0.0.1:0", nil)
	_, blockBytes := testHarnessBlockAtHeight(t, source, 1)
	corrupted := append([]byte(nil), blockBytes...)
	for i := 36; i < 68; i++ {
		corrupted[i] = 0xff
	}
	_, blockHash, err := parseRelayedBlock(corrupted)
	if err != nil {
		t.Fatalf("parse corrupted block: %v", err)
	}
	p := testPeerForService(sink.service, "remote", 1)
	p.activateCompactOutstandingRequest(compactOutstandingTestRequest(blockHash))
	if _, err := p.processRelayedBlock(corrupted); err == nil {
		t.Fatal("processRelayedBlock(corrupted) unexpectedly succeeded")
	}
	if _, ok := p.compactOutstandingRequestSnapshot(); ok {
		t.Fatal("apply-error full block did not clear matching compact outstanding request")
	}
}

func compactOutstandingTestRequest(blockHash [32]byte) compactOutstandingRequest {
	return compactOutstandingRequest{
		BlockHash:          blockHash,
		MissingIndexes:     []uint64{0},
		MissingShortIDs:    []compactShortID{{0x01}},
		Transactions:       [][]byte{nil},
		BlockTxnPayloadCap: 64,
	}
}

func TestRunDoesNotBanUnexpectedBlockTxnCommandCap(t *testing.T) {
	p := newPeerRuntimeTestPeer(t)
	p.conn = &scriptedConn{reads: []scriptedRead{{
		data: mustPeerRuntimeFrameBytes(t, p, message{Command: messageBlockTxn, Payload: make([]byte, 33)}),
	}}}
	err := p.run(context.Background())
	if err == nil || err.Error() != "message exceeds command cap" {
		t.Fatalf("run err=%v, want command cap error", err)
	}
	p.applyPostHandshakeDisconnectError(err)
	state := p.snapshotState()
	if state.BanScore != 0 || !strings.Contains(state.LastError, "unexpected blocktxn") {
		t.Fatalf("state=%+v, want unexpected blocktxn diagnostic without ban", state)
	}
}

func TestRunIgnoresUnexpectedBlockTxnAfterCompactNegotiation(t *testing.T) {
	p := newPeerRuntimeTestPeer(t)
	p.service.cfg.EnableCompactReceive = true
	p.setRemoteCompactMode(compactModeSnapshot{Mode: 1, Version: compactRelayVersion})
	p.conn = &scriptedConn{reads: []scriptedRead{{
		data: mustPeerRuntimeFrameBytes(t, p, message{Command: messageBlockTxn, Payload: make([]byte, blockTxnHashPayloadBytes)}),
	}}}
	if err := p.run(context.Background()); err != nil {
		t.Fatalf("run unexpected blocktxn: %v", err)
	}
	state := p.snapshotState()
	if state.BanScore != 0 || !strings.Contains(state.LastError, "ignored unexpected blocktxn") {
		t.Fatalf("state=%+v, want ignored unexpected blocktxn without ban", state)
	}
}

func TestRunCapsUnexpectedBlockTxnBodyAfterCompactNegotiation(t *testing.T) {
	p := newPeerRuntimeTestPeer(t)
	p.service.cfg.EnableCompactReceive = true
	p.setRemoteCompactMode(compactModeSnapshot{Mode: 1, Version: compactRelayVersion})
	p.conn = &scriptedConn{reads: []scriptedRead{{
		data: mustPeerRuntimeFrameBytes(t, p, message{Command: messageBlockTxn, Payload: make([]byte, blockTxnHashPayloadBytes+1)}),
	}}}
	err := p.run(context.Background())
	if err == nil || err.Error() != "message exceeds command cap" {
		t.Fatalf("run err=%v, want command cap error", err)
	}
	p.applyPostHandshakeDisconnectError(err)
	state := p.snapshotState()
	if state.BanScore != 0 || !strings.Contains(state.LastError, "unexpected blocktxn") {
		t.Fatalf("state=%+v, want unexpected blocktxn diagnostic without ban", state)
	}
}

func TestRunPropagatesUnexpectedBlockTxnChecksumFailure(t *testing.T) {
	p := newPeerRuntimeTestPeer(t)
	p.service.cfg.EnableCompactReceive = true
	p.setRemoteCompactMode(compactModeSnapshot{Mode: 1, Version: compactRelayVersion})
	payload := make([]byte, blockTxnHashPayloadBytes)
	header, err := buildEnvelopeHeader(networkMagic(p.service.cfg.PeerRuntimeConfig.Network), messageBlockTxn, payload)
	if err != nil {
		t.Fatalf("buildEnvelopeHeader: %v", err)
	}
	header[20] ^= 0xff
	p.conn = &scriptedConn{reads: []scriptedRead{{
		data: append(header[:], payload...),
	}}}
	err = p.run(context.Background())
	if err == nil || err.Error() != "invalid envelope checksum" {
		t.Fatalf("run err=%v, want invalid envelope checksum", err)
	}
}

func TestRunDoesNotBanUnexpectedBlockTxnMessageCap(t *testing.T) {
	p := newPeerRuntimeTestPeer(t)
	p.service.cfg.PeerRuntimeConfig.MaxMessageSize = 1
	header, err := buildEnvelopeHeader(
		networkMagic(p.service.cfg.PeerRuntimeConfig.Network),
		messageBlockTxn,
		[]byte{0x01, 0x02},
	)
	if err != nil {
		t.Fatalf("buildEnvelopeHeader: %v", err)
	}
	p.conn = &scriptedConn{reads: []scriptedRead{{data: header[:]}}}

	err = p.run(context.Background())
	if err == nil || err.Error() != "message exceeds cap" {
		t.Fatalf("run err=%v, want message cap error", err)
	}
	p.applyPostHandshakeDisconnectError(err)
	state := p.snapshotState()
	if state.BanScore != 0 || !strings.Contains(state.LastError, "unexpected blocktxn") {
		t.Fatalf("state=%+v, want unexpected blocktxn diagnostic without ban", state)
	}
}

func TestRunDoesNotClearActiveBlockTxnOnGlobalMessageCap(t *testing.T) {
	p := newPeerRuntimeTestPeer(t)
	p.service.cfg.EnableCompactReceive = true
	p.service.cfg.PeerRuntimeConfig.MaxMessageSize = 1
	blockHash := [32]byte{0x62}
	p.setRemoteCompactMode(compactModeSnapshot{Mode: 1, Version: compactRelayVersion})
	p.setCompactOutstandingRequest(compactOutstandingTestRequest(blockHash))
	header, err := buildEnvelopeHeader(
		networkMagic(p.service.cfg.PeerRuntimeConfig.Network),
		messageBlockTxn,
		append(blockHash[:], 0x01),
	)
	if err != nil {
		t.Fatalf("buildEnvelopeHeader: %v", err)
	}
	p.conn = &scriptedConn{reads: []scriptedRead{{data: header[:]}}}

	err = p.run(context.Background())
	if err == nil || err.Error() != "message exceeds cap" {
		t.Fatalf("run err=%v, want message cap error", err)
	}
	p.applyPostHandshakeDisconnectError(err)
	state := p.snapshotState()
	if state.BanScore != 0 || !strings.Contains(state.LastError, "message exceeds cap: blocktxn") {
		t.Fatalf("state=%+v, want global cap disconnect without ban", state)
	}
	if p.blockTxnPayloadCap() == 0 {
		t.Fatal("global cap disconnect cleared unclassified active outstanding request")
	}
}

func TestRunBansShortOverCapBlockTxn(t *testing.T) {
	p := newPeerRuntimeTestPeer(t)
	p.service.cfg.EnableCompactReceive = true
	blockHash := [32]byte{0x65}
	p.setRemoteCompactMode(compactModeSnapshot{Mode: 1, Version: compactRelayVersion})
	p.setCompactOutstandingRequest(compactOutstandingRequest{BlockHash: blockHash, BlockTxnPayloadCap: 16})
	payload := blockHash[:17]
	p.conn = &scriptedConn{reads: []scriptedRead{{
		data: mustPeerRuntimeFrameBytes(t, p, message{Command: messageBlockTxn, Payload: payload}),
	}}}
	err := p.run(context.Background())
	if err == nil || err.Error() != "message exceeds command cap" {
		t.Fatalf("run err=%v, want command cap error", err)
	}
	p.applyPostHandshakeDisconnectError(err)
	state := p.snapshotState()
	if state.BanScore == 0 || !strings.Contains(state.LastError, "blocktxn payload exceeds outstanding cap") {
		t.Fatalf("state=%+v, want outstanding cap ban", state)
	}
	if p.blockTxnPayloadCap() != 0 {
		t.Fatal("short over-cap blocktxn left outstanding request")
	}
}

func TestRunRejectsOversizedBlockTxnBeforeChecksum(t *testing.T) {
	p := newPeerRuntimeTestPeer(t)
	p.service.cfg.EnableCompactReceive = true
	blockHash := [32]byte{0x64}
	p.setRemoteCompactMode(compactModeSnapshot{Mode: 1, Version: compactRelayVersion})
	p.setCompactOutstandingRequest(compactOutstandingTestRequest(blockHash))
	payload := append(blockHash[:], make([]byte, 33)...)
	header, err := buildEnvelopeHeader(networkMagic(p.service.cfg.PeerRuntimeConfig.Network), messageBlockTxn, payload)
	if err != nil {
		t.Fatalf("buildEnvelopeHeader: %v", err)
	}
	header[20] ^= 0xff
	p.conn = &scriptedConn{reads: []scriptedRead{{
		data: append(header[:], payload...),
	}}}
	err = p.run(context.Background())
	if err == nil || err.Error() != "message exceeds command cap" {
		t.Fatalf("run err=%v, want command cap error", err)
	}
}

func TestRunDisconnectsOversizedStaleBlockTxnWithoutBan(t *testing.T) {
	p := newPeerRuntimeTestPeer(t)
	p.service.cfg.EnableCompactReceive = true
	activeHash := [32]byte{0x66}
	staleHash := [32]byte{0x77}
	p.setRemoteCompactMode(compactModeSnapshot{Mode: 1, Version: compactRelayVersion})
	p.setCompactOutstandingRequest(compactOutstandingTestRequest(activeHash))
	payload := append(staleHash[:], make([]byte, 33)...)
	p.conn = &scriptedConn{reads: []scriptedRead{{
		data: mustPeerRuntimeFrameBytes(t, p, message{Command: messageBlockTxn, Payload: payload}),
	}}}
	err := p.run(context.Background())
	requireBlockTxnStaleBodyError(t, err)
	p.applyPostHandshakeDisconnectError(err)
	state := p.snapshotState()
	if state.BanScore != 0 || !strings.Contains(state.LastError, "stale blocktxn response has body") {
		t.Fatalf("state=%+v, want stale body disconnect without ban", state)
	}
	if p.blockTxnPayloadCap() == 0 {
		t.Fatal("oversized stale blocktxn cleared active outstanding request")
	}
}

func TestRunDisconnectsStaleBlockTxnBodyWithoutBan(t *testing.T) {
	p := newPeerRuntimeTestPeer(t)
	p.service.cfg.EnableCompactReceive = true
	activeHash := [32]byte{0x68}
	staleHash := [32]byte{0x78}
	p.setRemoteCompactMode(compactModeSnapshot{Mode: 1, Version: compactRelayVersion})
	p.setCompactOutstandingRequest(compactOutstandingTestRequest(activeHash))
	payload := append(staleHash[:], 0x01)
	p.conn = &scriptedConn{reads: []scriptedRead{{
		data: mustPeerRuntimeFrameBytes(t, p, message{Command: messageBlockTxn, Payload: payload}),
	}}}
	err := p.run(context.Background())
	requireBlockTxnStaleBodyError(t, err)
	p.applyPostHandshakeDisconnectError(err)
	state := p.snapshotState()
	if state.BanScore != 0 || !strings.Contains(state.LastError, "stale blocktxn response has body") {
		t.Fatalf("state=%+v, want stale body disconnect without ban", state)
	}
	if p.blockTxnPayloadCap() == 0 {
		t.Fatal("stale body disconnect cleared active outstanding request")
	}
}

func TestRunRejectsStaleBlockTxnBodyBeforeChecksum(t *testing.T) {
	p := newPeerRuntimeTestPeer(t)
	p.service.cfg.EnableCompactReceive = true
	activeHash := [32]byte{0x66}
	staleHash := [32]byte{0x77}
	p.setRemoteCompactMode(compactModeSnapshot{Mode: 1, Version: compactRelayVersion})
	p.setCompactOutstandingRequest(compactOutstandingRequest{BlockHash: activeHash, BlockTxnPayloadCap: 128})
	payload := append(staleHash[:], make([]byte, 33)...)
	header, err := buildEnvelopeHeader(networkMagic(p.service.cfg.PeerRuntimeConfig.Network), messageBlockTxn, payload)
	if err != nil {
		t.Fatalf("buildEnvelopeHeader: %v", err)
	}
	header[20] ^= 0xff
	p.conn = &scriptedConn{reads: []scriptedRead{{data: append(header[:], payload...)}}}
	err = p.run(context.Background())
	requireBlockTxnStaleBodyError(t, err)
	p.applyPostHandshakeDisconnectError(err)
	state := p.snapshotState()
	if state.BanScore != 0 || !strings.Contains(state.LastError, "stale blocktxn response has body") {
		t.Fatalf("state=%+v, want stale body disconnect without ban", state)
	}
	if p.blockTxnPayloadCap() == 0 {
		t.Fatal("stale body before checksum cleared active outstanding request")
	}
}

func TestRunPropagatesBlockTxnPrefixReadFailure(t *testing.T) {
	p := newPeerRuntimeTestPeer(t)
	p.service.cfg.EnableCompactReceive = true
	blockHash := [32]byte{0x69}
	p.setRemoteCompactMode(compactModeSnapshot{Mode: 1, Version: compactRelayVersion})
	p.setCompactOutstandingRequest(compactOutstandingRequest{BlockHash: blockHash, BlockTxnPayloadCap: 128})
	payload := append(blockHash[:], make([]byte, 33)...)
	header, err := buildEnvelopeHeader(networkMagic(p.service.cfg.PeerRuntimeConfig.Network), messageBlockTxn, payload)
	if err != nil {
		t.Fatalf("buildEnvelopeHeader: %v", err)
	}
	p.conn = &scriptedConn{reads: []scriptedRead{{data: header[:]}}}
	err = p.run(context.Background())
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("run err=%v, want prefix short-read error", err)
	}
}

func TestBlockTxnPrefixWithoutOutstandingDoesNotMatch(t *testing.T) {
	p := newPeerRuntimeTestPeer(t)
	blockHash := [32]byte{0x6a}
	prefix := append([]byte(nil), blockHash[:]...)
	if p.blockTxnPrefixMatchesOutstanding(prefix) {
		t.Fatal("blocktxn prefix matched without outstanding request")
	}
	if p.blockTxnPrefixMatchesOutstanding(prefix[:blockTxnHashPayloadBytes-1]) {
		t.Fatal("short blocktxn prefix matched outstanding request")
	}
}

func TestRunPropagatesMatchedBlockTxnChecksumFailure(t *testing.T) {
	p := newPeerRuntimeTestPeer(t)
	p.service.cfg.EnableCompactReceive = true
	blockHash := [32]byte{0x67}
	p.setRemoteCompactMode(compactModeSnapshot{Mode: 1, Version: compactRelayVersion})
	p.setCompactOutstandingRequest(compactOutstandingRequest{BlockHash: blockHash, BlockTxnPayloadCap: 128})
	payload := append(blockHash[:], make([]byte, 33)...)
	header, err := buildEnvelopeHeader(networkMagic(p.service.cfg.PeerRuntimeConfig.Network), messageBlockTxn, payload)
	if err != nil {
		t.Fatalf("buildEnvelopeHeader: %v", err)
	}
	header[20] ^= 0xff
	p.conn = &scriptedConn{reads: []scriptedRead{{data: append(header[:], payload...)}}}
	err = p.run(context.Background())
	if err == nil || err.Error() != "invalid envelope checksum" {
		t.Fatalf("run err=%v, want invalid envelope checksum", err)
	}
}

func TestApplyBlockTxnCapDisconnectBansActiveCommandCap(t *testing.T) {
	p := newPeerRuntimeTestPeer(t)
	p.setCompactOutstandingRequest(compactOutstandingTestRequest([32]byte{0x63}))
	p.applyPostHandshakeDisconnectError(commandPayloadCapError{command: messageBlockTxn})
	state := p.snapshotState()
	if state.BanScore == 0 || !strings.Contains(state.LastError, "blocktxn payload exceeds outstanding cap") {
		t.Fatalf("state=%+v, want active command cap ban", state)
	}
	if p.blockTxnPayloadCap() != 0 {
		t.Fatal("active command cap error left outstanding request")
	}
}

func TestRunBansActiveBlockTxnCapOverflow(t *testing.T) {
	p := newPeerRuntimeTestPeer(t)
	p.service.cfg.EnableCompactReceive = true
	blockHash := [32]byte{0x66}
	p.setRemoteCompactMode(compactModeSnapshot{Mode: 1, Version: compactRelayVersion})
	p.setCompactOutstandingRequest(compactOutstandingTestRequest(blockHash))
	payload := append(blockHash[:], make([]byte, 33)...)
	p.conn = &scriptedConn{reads: []scriptedRead{{
		data: mustPeerRuntimeFrameBytes(t, p, message{Command: messageBlockTxn, Payload: payload}),
	}}}
	err := p.run(context.Background())
	if err == nil || err.Error() != "message exceeds command cap" {
		t.Fatalf("run err=%v, want command cap error", err)
	}
	p.applyPostHandshakeDisconnectError(err)
	state := p.snapshotState()
	if state.BanScore == 0 || !strings.Contains(state.LastError, "blocktxn payload exceeds outstanding cap") {
		t.Fatalf("state=%+v, want active blocktxn cap overflow ban", state)
	}
	if p.blockTxnPayloadCap() != 0 {
		t.Fatal("active blocktxn cap overflow left dynamic blocktxn cap open")
	}
}

func TestRunFallsBackAndClearsExpiredCompactOutstandingOnIdleTimeout(t *testing.T) {
	p, ck := setupCompactFallbackPeer(t)
	conn := &expiryWakeConn{scriptedConn: scriptedConn{reads: []scriptedRead{{err: timeoutErr{}}, {err: io.EOF}}}}
	conn.expireOnRead(ck, 1)
	p.conn = conn

	requireNoCompactErr(t, p.run(context.Background()), "run idle compact fallback")
	requireFirstGetDataBlock(t, p, conn.Bytes(), [32]byte{0x11})
	p, ck = setupCompactFallbackPeer(t)
	ck.advance(compactOutstandingRequestTTL + time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	p.conn = &scriptedConn{}
	if err := p.run(ctx); err != nil {
		t.Fatal(err)
	}
	if p.conn.(*scriptedConn).Len() != 0 {
		t.Fatal("canceled run wrote compact fallback")
	}
	p, ck = setupCompactFallbackPeer(t)
	ctx, cancel = context.WithCancel(context.Background())
	p.service.cfg.Now = func() time.Time { cancel(); return ck.now.Add(compactOutstandingRequestTTL + time.Second) }
	p.conn = &scriptedConn{}
	if sent, err := p.handleExpiredCompactOutstanding(ctx); sent || err != nil || p.conn.(*scriptedConn).Len() != 0 {
		t.Fatalf("cancel-after-pop sent=%v err=%v bytes=%d", sent, err, p.conn.(*scriptedConn).Len())
	}
}

func TestRunDrainsLateBlockTxnBodyAfterExpiryFallback(t *testing.T) {
	blockHash := [32]byte{0x11}
	req := compactOutstandingTestRequest(blockHash)
	payload := append(blockHash[:], 0x01)
	p, conn, err := runExpiredLateBlockTxnFrame(t, req, payload, message{Command: messageVersion})
	state := p.snapshotState()
	if err == nil || !strings.Contains(err.Error(), "invalid version message after handshake") || state.BanScore != 0 || !strings.Contains(state.LastError, "ignored late blocktxn response") {
		t.Fatalf("run err=%v state=%+v, want next frame after drained late blocktxn with diagnostic", err, state)
	}
	requireFirstGetDataBlock(t, p, conn.Bytes(), blockHash)
	p, ck := setupCompactFallbackPeer(t)
	frameBytes := mustPeerRuntimeFrameBytes(t, p, message{Command: messageHeaders, Payload: []byte{0x01}})
	lateFrame := mustPeerRuntimeFrameBytes(t, p, message{Command: messageBlockTxn, Payload: payload})
	wakeConn := &expiryWakeConn{scriptedConn: scriptedConn{reads: []scriptedRead{
		{data: frameBytes[:wireHeaderSize]}, {err: timeoutErr{}}, {data: frameBytes[wireHeaderSize:]}, {data: lateFrame}, {data: mustPeerRuntimeFrameBytes(t, p, message{Command: messageVersion})},
	}}}
	wakeConn.expireOnRead(ck, 2)
	p.conn = wakeConn
	if err := p.run(context.Background()); err == nil || !strings.Contains(err.Error(), "invalid version message after handshake") {
		t.Fatalf("payload-expiry run err=%v, want next frame after drained late blocktxn", err)
	}
}

func TestRunCapsLateBlockTxnBodyAfterExpiryFallbackByOutstandingRequest(t *testing.T) {
	blockHash := [32]byte{0x12}
	req := compactOutstandingTestRequest(blockHash)
	req.BlockTxnPayloadCap = blockTxnHashPayloadBytes
	p, conn, err := runExpiredLateBlockTxnFrame(t, req, append(blockHash[:], 0x01))
	if err == nil || err.Error() != "message exceeds command cap" {
		t.Fatalf("run err=%v, want expired outstanding cap error", err)
	}
	requireFirstGetDataBlock(t, p, conn.Bytes(), blockHash)
}

func TestRunResetsReadDeadlineBeforeLateBlockTxnDrainAfterExpiryFallback(t *testing.T) {
	blockHash := [32]byte{0x13}
	req := compactOutstandingTestRequest(blockHash)
	beforeRun := time.Now()
	p, conn, err := runExpiredLateBlockTxnFrame(t, req, append(blockHash[:], 0x01), message{Command: messageVersion})
	if err == nil || !strings.Contains(err.Error(), "invalid version message after handshake") {
		t.Fatalf("run err=%v, want next frame after late blocktxn drain", err)
	}
	requireFirstGetDataBlock(t, p, conn.Bytes(), blockHash)
	if len(conn.readDeadlines) == 0 || !conn.readDeadlines[0].After(beforeRun.Add(p.service.cfg.PeerRuntimeConfig.ReadDeadline/2)) {
		t.Fatalf("read deadlines=%v, want reset normal deadline after expired compact wake", conn.readDeadlines)
	}
}

func TestRunKeepsActiveCompactDeadlineWithStaleLateBlockTxnContext(t *testing.T) {
	p, ck := setupCompactFallbackPeer(t)
	ck.advance(compactOutstandingRequestTTL + time.Second)
	p.service.cfg.PeerRuntimeConfig.ReadDeadline = time.Hour
	conn := &scriptedConn{
		reads:     []scriptedRead{{data: mustPeerRuntimeFrameBytes(t, p, message{Command: messageVersion})}},
		writeHook: func(int) { p.activateCompactOutstandingRequest(compactOutstandingTestRequest([32]byte{0x23})) },
	}
	p.conn = conn

	if err := p.run(context.Background()); err == nil {
		t.Fatal("run succeeded, want post-handshake version stop")
	}
	if len(conn.readDeadlines) == 0 || conn.readDeadlines[0].After(time.Now().Add(time.Minute)) {
		t.Fatalf("read deadlines=%v, want active compact expiry before normal read deadline", conn.readDeadlines)
	}
}

func TestRunRejectsShortLateBlockTxnAfterExpiryFallback(t *testing.T) {
	blockHash := [32]byte{0x14}
	req := compactOutstandingTestRequest(blockHash)
	p, conn, err := runExpiredLateBlockTxnFrame(t, req, blockHash[:blockTxnHashPayloadBytes-1])
	if err == nil || !strings.Contains(err.Error(), "blocktxn payload missing block hash") {
		t.Fatalf("run err=%v, want short late blocktxn rejection", err)
	}
	requireFirstGetDataBlock(t, p, conn.Bytes(), blockHash)
}

func TestRunRejectsWrongHashLateBlockTxnBodyAfterExpiryFallback(t *testing.T) {
	blockHash := [32]byte{0x15}
	staleHash := [32]byte{0x25}
	req := compactOutstandingTestRequest(blockHash)
	p, conn, err := runExpiredLateBlockTxnFrame(t, req, append(staleHash[:], 0x01))
	requireBlockTxnStaleBodyError(t, err)
	requireFirstGetDataBlock(t, p, conn.Bytes(), blockHash)
}

func TestReadLateBlockTxnKeepsActiveResponseAndThenIgnoresLateContext(t *testing.T) {
	oldHash, activeHash := [32]byte{0x15}, [32]byte{0x35}
	activePayload := append(activeHash[:], bytes.Repeat([]byte{0x01}, 33)...)
	oldPayload := append(oldHash[:], 0x01)
	p := setupLateBlockTxnReadPeer(t, compactOutstandingRequest{BlockHash: activeHash, BlockTxnPayloadCap: 128}, activePayload, oldPayload)
	lateCtx := &compactOutstandingRequest{BlockHash: oldHash, BlockTxnPayloadCap: 64}

	frame, lateCtx, err := p.readPostHandshakeFrame(context.Background(), time.Now(), lateCtx)
	if err != nil {
		t.Fatalf("read late blocktxn with active response: %v", err)
	}
	if lateCtx == nil {
		t.Fatal("active response cleared stale late blocktxn context")
	}
	if frame.Command != messageBlockTxn || !bytes.Equal(frame.Payload, activePayload) {
		t.Fatalf("frame=%+v, want active blocktxn payload", frame)
	}
	_, lateCtx, err = p.readPostHandshakeFrame(context.Background(), time.Now(), lateCtx)
	if !errors.Is(err, errLateBlockTxnIgnored) || lateCtx != nil {
		t.Fatalf("stale late read err=%v lateCtx=%+v, want ignored late blocktxn and cleared context", err, lateCtx)
	}
}

func TestReadLateBlockTxnActiveCapErrorPreservesLateContext(t *testing.T) {
	oldHash, activeHash := [32]byte{0x15}, [32]byte{0x35}
	activePayload := append(activeHash[:], bytes.Repeat([]byte{0x01}, 33)...)
	p := setupLateBlockTxnReadPeer(t, compactOutstandingRequest{BlockHash: activeHash, BlockTxnPayloadCap: 64}, activePayload)

	_, lateCtx, err := p.readPostHandshakeFrame(context.Background(), time.Now(), &compactOutstandingRequest{BlockHash: oldHash, BlockTxnPayloadCap: 128})
	if err == nil || err.Error() != "message exceeds command cap" || lateCtx == nil {
		t.Fatalf("active cap err=%v lateCtx=%+v, want cap error preserving late context", err, lateCtx)
	}
}

func TestReadLateBlockTxnStaleBodyDoesNotBanActiveOutstanding(t *testing.T) {
	oldHash, activeHash := [32]byte{0x15}, [32]byte{0x35}
	stalePayload := append(oldHash[:], bytes.Repeat([]byte{0x02}, 33)...)
	p := setupLateBlockTxnReadPeer(t, compactOutstandingTestRequest(activeHash), stalePayload)

	_, _, err := p.readPostHandshakeFrame(context.Background(), time.Now(), &compactOutstandingRequest{BlockHash: oldHash, BlockTxnPayloadCap: blockTxnHashPayloadBytes})
	requireBlockTxnStaleBodyError(t, err)
	p.applyPostHandshakeDisconnectError(err)
	if state := p.snapshotState(); state.BanScore != 0 || p.blockTxnPayloadCap() == 0 {
		t.Fatalf("state=%+v activeCap=%d, want stale late cap not active ban/clear", state, p.blockTxnPayloadCap())
	}
}

func setupLateBlockTxnReadPeer(t *testing.T, active compactOutstandingRequest, payloads ...[]byte) *peer {
	t.Helper()
	p := newPeerRuntimeTestPeer(t)
	p.setCompactOutstandingRequest(active)
	reads := make([]scriptedRead, 0, len(payloads))
	for _, payload := range payloads {
		frame := message{Command: messageBlockTxn, Payload: payload}
		reads = append(reads, scriptedRead{data: mustPeerRuntimeFrameBytes(t, p, frame)})
	}
	p.conn = &scriptedConn{reads: reads}
	return p
}

func TestRunIgnoresHashOnlyStaleLateBlockTxnAfterExpiryFallback(t *testing.T) {
	blockHash := [32]byte{0x16}
	staleHash := [32]byte{0x26}
	req := compactOutstandingTestRequest(blockHash)
	p, conn, err := runExpiredLateBlockTxnFrame(t, req, staleHash[:])
	if err != nil {
		t.Fatalf("run hash-only stale late blocktxn: %v", err)
	}
	requireFirstGetDataBlock(t, p, conn.Bytes(), blockHash)
	if state := p.snapshotState(); state.BanScore != 0 || !strings.Contains(state.LastError, "ignored stale blocktxn response") {
		t.Fatalf("state=%+v, want ignored stale late blocktxn without ban", state)
	}
}

func TestRunRejectsBadChecksumLateBlockTxnAfterExpiryFallback(t *testing.T) {
	blockHash := [32]byte{0x17}
	staleHash := [32]byte{0x27}
	requireBadChecksumLateBlockTxn(t, blockHash, append(staleHash[:], 0x01))
}

func TestRunRejectsBadChecksumShortLateBlockTxnAfterExpiryFallback(t *testing.T) {
	blockHash := [32]byte{0x18}
	requireBadChecksumLateBlockTxn(t, blockHash, blockHash[:blockTxnHashPayloadBytes-1])
}

func TestRunRejectsBadChecksumHashOnlyStaleLateBlockTxnAfterExpiryFallback(t *testing.T) {
	blockHash := [32]byte{0x19}
	staleHash := [32]byte{0x29}
	requireBadChecksumLateBlockTxn(t, blockHash, staleHash[:])
}

func requireBadChecksumLateBlockTxn(t *testing.T, blockHash [32]byte, payload []byte) {
	t.Helper()
	p, ck := setupCompactFallbackPeer(t)
	p.activateCompactOutstandingRequest(compactOutstandingTestRequest(blockHash))
	ck.advance(compactOutstandingRequestTTL + time.Second)
	raw := mustPeerRuntimeFrameBytes(t, p, message{Command: messageBlockTxn, Payload: payload})
	raw[20] ^= 0xff
	p.conn = &scriptedConn{reads: []scriptedRead{{data: raw}}}
	err := p.run(context.Background())
	if err == nil || err.Error() != "invalid envelope checksum" {
		t.Fatalf("payload len=%d err=%v, want checksum failure before semantic classification", len(payload), err)
	}
}

func TestRunDoesNotSendExpiredCompactFallbackAfterContextCancelDuringBlockTxn(t *testing.T) {
	p, ck := setupCompactFallbackPeer(t)
	ck.advance(compactOutstandingRequestTTL + time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	p.conn = &scriptedConn{reads: []scriptedRead{{
		data: mustPeerRuntimeFrameBytes(t, p, message{Command: messageBlockTxn, Payload: make([]byte, blockTxnHashPayloadBytes)}),
	}}}

	if err := p.run(ctx); err != nil {
		t.Fatalf("canceled run err=%v", err)
	}
	if p.conn.(*scriptedConn).Len() != 0 {
		t.Fatal("canceled blocktxn run wrote compact fallback")
	}
}

func TestRunKeepsStartedHeaderAliveAcrossCompactExpiry(t *testing.T) {
	p, ck := setupCompactFallbackPeer(t)
	p.service.cfg.PeerRuntimeConfig.ReadDeadline = 0
	frameBytes := mustPeerRuntimeFrameBytes(t, p, message{Command: messagePing})
	stopFrame := mustPeerRuntimeFrameBytes(t, p, message{Command: messageVersion})
	conn := &expiryWakeConn{scriptedConn: scriptedConn{reads: []scriptedRead{
		{data: frameBytes[:1]}, {err: timeoutErr{}}, {data: frameBytes[1:]}, {data: stopFrame},
	}}}
	conn.expireOnRead(ck, 2)
	p.conn = conn
	if err := p.run(context.Background()); err == nil || err.Error() != "invalid version message after handshake" {
		t.Fatalf("run err=%v, want post-handshake version stop", err)
	}
	requireFirstGetDataBlock(t, p, conn.Bytes(), [32]byte{0x11})
}

func TestRunReturnsCompactFallbackWakeErrors(t *testing.T) {
	deadlineErr := errors.New("deadline failed")
	p := newPeerRuntimeTestPeer(t)
	p.conn = &scriptedConn{readDeadlineErr: deadlineErr}
	if err := p.run(context.Background()); !errors.Is(err, deadlineErr) {
		t.Fatalf("run deadline err=%v", err)
	}

	for _, frame := range []message{{Command: messagePing}, {Command: messageAddr}} {
		p, ck := setupCompactFallbackPeer(t)
		writeErr := errors.New("fallback write failed")
		conn := &expiryWakeConn{scriptedConn: scriptedConn{reads: []scriptedRead{{data: mustPeerRuntimeFrameBytes(t, p, frame)}}, writeErr: writeErr}}
		conn.expireOnRead(ck, 1)
		p.conn = conn
		if err := p.run(context.Background()); !errors.Is(err, writeErr) {
			t.Fatalf("%s run err=%v", frame.Command, err)
		}
	}

	p, ck := setupCompactFallbackPeer(t)
	ck.advance(compactOutstandingRequestTTL + time.Second)
	writeErr := errors.New("fallback direct write failed")
	p.conn = &scriptedConn{reads: []scriptedRead{{err: timeoutErr{}}}, writeErr: writeErr}
	_, err := (&compactFallbackReader{peer: p, ctx: context.Background(), frameStart: time.Now()}).Read(make([]byte, 1))
	if !errors.Is(err, writeErr) {
		t.Fatalf("reader err=%v", err)
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
			reads = append(
				reads,
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

func TestHandleGetDAChunkRequiresCompactReceiveAndDecodesPayload(t *testing.T) {
	var daID [32]byte
	daID[0] = 0x37
	payload, err := encodeGetDAChunkPayload(getDAChunkPayload{
		Version: daChunkRequestVersion,
		DAID:    daID,
		Indexes: []uint16{0, 2},
	})
	if err != nil {
		t.Fatalf("encodeGetDAChunkPayload: %v", err)
	}

	p := newPeerRuntimeTestPeer(t)
	err = p.handleMessage(message{Command: messageGetDAChunk, Payload: payload})
	var unknown postHandshakeUnknownCommandError
	if !errors.As(err, &unknown) || unknown.command != messageGetDAChunk {
		t.Fatalf("closed getdachunk err=%v, want unknown command", err)
	}

	p.service.cfg.EnableCompactReceive = true
	p.setRemoteCompactMode(compactModeSnapshot{Mode: 1, Version: compactRelayVersion})
	if err := p.handleMessage(message{Command: messageGetDAChunk, Payload: payload}); err != nil {
		t.Fatalf("valid getdachunk: %v", err)
	}
	if err := p.handleMessage(message{Command: messageGetDAChunk, Payload: payload[:1]}); err == nil || !strings.Contains(err.Error(), "getdachunk payload missing") {
		t.Fatalf("malformed getdachunk err=%v, want decode rejection", err)
	}
}

func TestHandleObjectRelayMessageKeepsCompactObjectsClosed(t *testing.T) {
	p := newPeerRuntimeTestPeer(t)
	for _, command := range []string{messageCmpctBlock, messageGetBlockTxn, messageBlockTxn} {
		err := p.handleObjectRelayMessage(message{Command: command})
		var unknown postHandshakeUnknownCommandError
		if !errors.As(err, &unknown) || unknown.command != command {
			t.Fatalf("%s err=%v, want unknown command while compact receive is closed", command, err)
		}
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

func TestApplyPostHandshakeDisconnectErrorCommandCapRecordsCommand(t *testing.T) {
	p := newPeerRuntimeTestPeer(t)
	err := commandPayloadCapError{command: messagePing}
	if err.Error() != "message exceeds command cap" {
		t.Fatalf("error=%q, want public command cap error unchanged", err.Error())
	}

	p.applyPostHandshakeDisconnectError(err)
	snap := p.snapshotState()
	if snap.LastError != "message exceeds command cap: ping" {
		t.Fatalf("last_error=%q, want command diagnostic", snap.LastError)
	}
	if snap.BanScore != 0 {
		t.Fatalf("ban_score=%d, want 0 for non-blocktxn command cap", snap.BanScore)
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
