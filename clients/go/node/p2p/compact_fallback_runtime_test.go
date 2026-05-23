package p2p

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/node"
)

type clock struct{ now time.Time }

func (c *clock) Now() time.Time          { return c.now }
func (c *clock) advance(d time.Duration) { c.now = c.now.Add(d) }

type expiryWakeConn struct {
	scriptedConn
	lastReadDeadline time.Time
	readCount        int
	onRead           func(int)
}

func (c *expiryWakeConn) Read(p []byte) (int, error) {
	c.readCount++
	if c.onRead != nil {
		c.onRead(c.readCount)
	}
	return c.scriptedConn.Read(p)
}
func (c *expiryWakeConn) SetReadDeadline(t time.Time) error { c.lastReadDeadline = t; return nil }
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

func requireFirstWrittenCommand(t *testing.T, p *peer, written []byte, want string) {
	frame, err := readFrameHeader(bytes.NewReader(written), networkMagic(p.service.cfg.PeerRuntimeConfig.Network), p.service.cfg.PeerRuntimeConfig.MaxMessageSize)
	if err != nil {
		t.Fatalf("readFrameHeader: %v", err)
	}
	if cmd := strings.TrimRight(string(frame.Command[:]), "\x00"); cmd != want {
		t.Fatalf("first write command=%q, want %q", cmd, want)
	}
}

func TestRunReturnsExpiredCompactFallbackSendError(t *testing.T) {
	p, ck := setupCompactFallbackPeer(t)
	ck.advance(compactOutstandingRequestTTL + time.Second)
	p.conn = &scriptedConn{writeErr: io.ErrClosedPipe}
	if err := p.run(context.Background()); err == nil || err.Error() != io.ErrClosedPipe.Error() {
		t.Fatalf("run err=%v, want closed pipe", err)
	}
}

func TestHandleExpiredCompactOutstandingHonorsCancelAfterPop(t *testing.T) {
	p, ck := setupCompactFallbackPeer(t)
	ctx, cancel := context.WithCancel(context.Background())
	ck.advance(compactOutstandingRequestTTL + time.Second)
	p.service.cfg.Now = func() time.Time { cancel(); return ck.now }
	p.conn = &scriptedConn{}
	if sent, err := p.handleExpiredCompactOutstanding(ctx); sent || err != nil {
		t.Fatalf("sent=%v err=%v, want canceled no-op", sent, err)
	}
	if written := p.conn.(*scriptedConn).Bytes(); len(written) != 0 {
		t.Fatalf("canceled fallback wrote %d bytes", len(written))
	}
}

func TestRunFallsBackAndClearsExpiredCompactOutstandingOnIdleTimeout(t *testing.T) {
	p, ck := setupCompactFallbackPeer(t)
	conn := &expiryWakeConn{scriptedConn: scriptedConn{reads: []scriptedRead{{err: timeoutErr{}}, {err: io.EOF}}}}
	conn.expireOnRead(ck, 1)
	p.conn = conn

	requireNoCompactErr(t, p.run(context.Background()), "run idle compact fallback")
	requireFirstWrittenCommand(t, p, conn.Bytes(), messageGetData)
}

func TestRunFallsBackForExpiredCompactOutstandingBeforeBenignFrame(t *testing.T) {
	header, _, txs := compactPartsFromBlockBytes(t, node.DevnetGenesisBlockBytes())
	cmpctPayload := mustEncodeCmpctBlockPayload(t, cmpctBlockPayload{Header: header, Prefilled: []prefilledTxn{{Index: 0, Tx: txs[0]}}})
	matchingBlockTxnPayload := append([]byte{0x11}, make([]byte, 32)...)
	staleBlockTxnPayload := append([]byte{0x22}, make([]byte, 64)...)
	for _, tc := range []struct {
		name        string
		msg         message
		split       bool
		advanceRead int
		wantErr     string
	}{
		{name: "cmpctblock", msg: message{Command: messageCmpctBlock, Payload: cmpctPayload}, advanceRead: 1},
		{name: "blocktxn_matching_body_header_crosses_expiry", msg: message{Command: messageBlockTxn, Payload: matchingBlockTxnPayload}, split: true, advanceRead: 1},
		{name: "blocktxn_stale_body_crosses_expiry", msg: message{Command: messageBlockTxn, Payload: staleBlockTxnPayload}, split: true, advanceRead: 2, wantErr: "stale blocktxn response has body"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, ck := setupCompactFallbackPeer(t)
			if tc.split {
				p.service.cfg.PeerRuntimeConfig.ReadDeadline = 0
			}
			frameBytes := mustPeerRuntimeFrameBytes(t, p, tc.msg)
			reads := []scriptedRead{{data: frameBytes}, {err: io.EOF}}
			if tc.split {
				reads = []scriptedRead{{data: frameBytes[:wireHeaderSize]}, {data: frameBytes[wireHeaderSize:]}, {err: io.EOF}}
			}
			conn := &expiryWakeConn{scriptedConn: scriptedConn{reads: reads}}
			conn.expireOnRead(ck, tc.advanceRead)
			p.conn = conn
			err := p.run(context.Background())
			if tc.wantErr == "" {
				requireNoCompactErr(t, err, "run compact fallback")
			} else if err == nil || err.Error() != tc.wantErr {
				t.Fatalf("run err=%v, want %q", err, tc.wantErr)
			}
			if tc.wantErr != "" {
				if written := conn.Bytes(); len(written) != 0 {
					t.Fatalf("terminal read error wrote %d fallback bytes", len(written))
				}
				return
			}
			requireFirstWrittenCommand(t, p, conn.Bytes(), messageGetData)
		})
	}
}

func TestSetReadDeadlineUsesCompactOutstandingExpiry(t *testing.T) {
	p, ck := setupCompactFallbackPeer(t)
	p.service.cfg.PeerRuntimeConfig.ReadDeadline = 10 * time.Minute
	dc := &expiryWakeConn{}
	p.conn = dc
	if err := p.setReadDeadlineAt(ck.now, true); err != nil {
		t.Fatalf("setReadDeadline: %v", err)
	}
	if diff := dc.lastReadDeadline.Sub(ck.now.Add(compactOutstandingRequestTTL)); diff < -100*time.Millisecond || diff > 100*time.Millisecond {
		t.Fatalf("deadline=%v, want compact expiry near %v", dc.lastReadDeadline, ck.now.Add(compactOutstandingRequestTTL))
	}
	if err := p.setReadDeadlineAt(ck.now, false); err != nil || dc.lastReadDeadline.Before(ck.now.Add(time.Minute)) {
		t.Fatalf("generic deadline=%v err=%v, want compact expiry removed", dc.lastReadDeadline, err)
	}

	p.service.cfg.PeerRuntimeConfig.ReadDeadline = 0
	if err := p.setPostHeaderReadDeadline(ck.now); err != nil || dc.lastReadDeadline.IsZero() || dc.lastReadDeadline.After(ck.now.Add(compactOutstandingRequestTTL)) {
		t.Fatalf("post-header deadline=%v err=%v, want bounded payload read", dc.lastReadDeadline, err)
	}
	ck.advance(compactOutstandingRequestTTL + time.Second)
	if _, err := p.handleExpiredCompactOutstanding(context.Background()); err != nil {
		t.Fatalf("handleExpiredCompactOutstanding: %v", err)
	}
	if err := p.setReadDeadline(); err != nil {
		t.Fatalf("setReadDeadline after expiry: %v", err)
	}
	if !dc.lastReadDeadline.IsZero() {
		t.Fatalf("deadline=%v, want cleared deadline", dc.lastReadDeadline)
	}
}
