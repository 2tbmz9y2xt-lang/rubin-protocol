package p2p

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

// ────────────────────────────────────────────────────────────
// Helpers for compact-fallback runtime tests
// ────────────────────────────────────────────────────────────

// clock is a controllable clock for compact fallback expiry tests.
type clock struct {
	now time.Time
}

func (c *clock) Now() time.Time { return c.now }

func (c *clock) advance(d time.Duration) {
	c.now = c.now.Add(d)
}

// deadlineConn records the last deadline set via SetReadDeadline.
type deadlineConn struct {
	scriptedConn
	lastReadDeadline time.Time
}

func (c *deadlineConn) SetReadDeadline(t time.Time) error {
	c.lastReadDeadline = t
	return nil
}

// setupCompactFallbackPeer creates a peer with compact receive enabled,
// high-bandwidth mode negotiated, and a compact outstanding request
// whose expiry is expressed in injectable clock time.
func setupCompactFallbackPeer(t *testing.T) (*peer, *clock) {
	t.Helper()
	p := newPeerRuntimeTestPeer(t)
	p.service.cfg.EnableCompactReceive = true
	p.setRemoteCompactMode(compactModeSnapshot{Mode: 1, Version: compactRelayVersion})

	ck := &clock{now: time.Now()}
	p.service.cfg.Now = ck.Now

	tx := minimalBlockTxnTestTxBytes(0)
	req := compactOutstandingRequest{
		BlockHash:          [32]byte{0x11},
		Header:             [consensus.BLOCK_HEADER_BYTES]byte{},
		MissingIndexes:     []uint64{0},
		MissingShortIDs:    []compactShortID{{0x01}},
		Transactions:       [][]byte{tx},
		Nonce1:             0,
		Nonce2:             0,
		BlockTxnPayloadCap: compactRelayPayloadCap(messageBlockTxn),
		ExpiresAt:          ck.now.Add(compactOutstandingRequestTTL),
	}
	p.setCompactOutstandingRequest(req)
	t.Cleanup(func() { p.clearCompactOutstandingRequest() })
	return p, ck
}

// ────────────────────────────────────────────────────────────
// 1. Idle expiry: no traffic → fallback emitted.
// ────────────────────────────────────────────────────────────
func TestRunFallsBackAndClearsExpiredCompactOutstandingOnIdleTimeout(t *testing.T) {
	p, ck := setupCompactFallbackPeer(t)
	// Advance the clock past the TTL so the request is expired on next check.
	ck.advance(compactOutstandingRequestTTL + time.Second)

	// First read times out, second ends the loop.
	p.conn = &scriptedConn{
		reads: []scriptedRead{
			{err: timeoutErr{}},
			{err: io.EOF},
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	_ = p.run(ctx)

	written := p.conn.(*scriptedConn).Bytes()
	if len(written) == 0 {
		t.Fatalf("expected fallback getdata(MSG_BLOCK) to be written")
	}
	// Decode the first frame header.
	frame, err := readFrameHeader(bytes.NewReader(written), networkMagic(p.service.cfg.PeerRuntimeConfig.Network), p.service.cfg.PeerRuntimeConfig.MaxMessageSize)
	if err != nil {
		t.Fatalf("readFrameHeader: %v", err)
	}
	cmd := strings.TrimRight(string(frame.Command[:]), "\x00")
	if cmd != messageGetData {
		t.Fatalf("expected getdata command, got %q", cmd)
	}
	// Verify payload contains MSG_BLOCK inventory vector for the expected hash.
	invs, err := decodeInventoryVectors(written[wireHeaderSize:])
	if err != nil {
		t.Fatalf("decodeInventoryVectors: %v", err)
	}
	if len(invs) != 1 || invs[0].Type != MSG_BLOCK {
		t.Fatalf("expected single MSG_BLOCK inv, got %v", invs)
	}
	if invs[0].Hash != [32]byte{0x11} {
		t.Fatalf("expected block hash 0x11, got %x", invs[0].Hash)
	}
}

// ────────────────────────────────────────────────────────────
// 2. Benign frame after expiry: fallback dispatched first.
// ────────────────────────────────────────────────────────────
func TestRunFallsBackForExpiredCompactOutstandingBeforeBenignFrame(t *testing.T) {
	p, ck := setupCompactFallbackPeer(t)
	ck.advance(compactOutstandingRequestTTL + time.Second)

	pingPayload := mustPeerRuntimeFrameBytes(t, p, message{Command: messagePing})
	p.conn = &scriptedConn{
		reads: []scriptedRead{
			{data: pingPayload},
			{err: io.EOF},
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	_ = p.run(ctx)

	written := p.conn.(*scriptedConn).Bytes()
	if len(written) == 0 {
		t.Fatalf("expected at least one write (fallback)")
	}
	frame, err := readFrameHeader(bytes.NewReader(written), networkMagic(p.service.cfg.PeerRuntimeConfig.Network), p.service.cfg.PeerRuntimeConfig.MaxMessageSize)
	if err != nil {
		t.Fatalf("readFrameHeader: %v", err)
	}
	cmd := strings.TrimRight(string(frame.Command[:]), "\x00")
	if cmd != messageGetData {
		t.Fatalf("first write command=%q, want getdata", cmd)
	}
}

// ────────────────────────────────────────────────────────────
// 3. setReadDeadline uses earlier of ReadDeadline and compact expiry.
// ────────────────────────────────────────────────────────────
func TestSetReadDeadlineUsesCompactOutstandingExpiry(t *testing.T) {
	p, ck := setupCompactFallbackPeer(t)
	// Set a very long read deadline so compact expiry is the tie-breaker.
	p.service.cfg.PeerRuntimeConfig.ReadDeadline = 10 * time.Minute
	// The compact request expires in ~15s from now.
	expected := ck.now.Add(compactOutstandingRequestTTL)

	dc := &deadlineConn{}
	p.conn = dc
	if err := p.setReadDeadline(); err != nil {
		t.Fatalf("setReadDeadline: %v", err)
	}
	got := dc.lastReadDeadline
	if got.IsZero() {
		t.Fatalf("deadline was not set")
	}
	diff := got.Sub(expected)
	if diff < -100*time.Millisecond || diff > 100*time.Millisecond {
		t.Fatalf("deadline=%v, want ~%v (diff=%v)", got, expected, diff)
	}
}

// ────────────────────────────────────────────────────────────
// 4. Deadline cleared when no generic deadline and no compact request.
// ────────────────────────────────────────────────────────────
func TestSetReadDeadlineClearsExpiredCompactDeadlineWhenNoGenericDeadline(t *testing.T) {
	p, ck := setupCompactFallbackPeer(t)
	p.service.cfg.PeerRuntimeConfig.ReadDeadline = 0 // no generic deadline
	// Compact request is alive. setReadDeadline should use its expiry.
	dc := &deadlineConn{}
	p.conn = dc
	if err := p.setReadDeadline(); err != nil {
		t.Fatalf("setReadDeadline: %v", err)
	}
	if dc.lastReadDeadline.IsZero() {
		t.Fatalf("expected non-zero deadline from compact expiry")
	}

	// Expire the compact request.
	ck.advance(compactOutstandingRequestTTL + time.Second)
	if err := p.setReadDeadline(); err != nil {
		t.Fatalf("setReadDeadline: %v", err)
	}
	if !dc.lastReadDeadline.IsZero() {
		t.Fatalf("expected zero deadline after compact expiry, got %v", dc.lastReadDeadline)
	}
}

// ────────────────────────────────────────────────────────────
// 5. Context cancellation prevents fallback emission.
// ────────────────────────────────────────────────────────────
func TestRunDoesNotSendExpiredCompactFallbackAfterContextCancel(t *testing.T) {
	p, ck := setupCompactFallbackPeer(t)
	ck.advance(compactOutstandingRequestTTL + time.Second)

	p.conn = &scriptedConn{
		reads: []scriptedRead{{err: io.EOF}},
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before entering run
	_ = p.run(ctx)

	written := p.conn.(*scriptedConn).Bytes()
	if len(written) != 0 {
		t.Fatalf("expected no writes after context cancellation, got %d bytes", len(written))
	}
}
