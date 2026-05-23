package p2p

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"
)

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

func requireFirstWrittenCommand(t *testing.T, p *peer, written []byte, want string) {
	frame, err := readFrameHeader(bytes.NewReader(written), networkMagic(p.service.cfg.PeerRuntimeConfig.Network), p.service.cfg.PeerRuntimeConfig.MaxMessageSize)
	if err != nil {
		t.Fatalf("readFrameHeader: %v", err)
	}
	if frame.Command != want {
		t.Fatalf("first write command=%q, want %q", frame.Command, want)
	}
}

func TestRunFallsBackAndClearsExpiredCompactOutstandingOnIdleTimeout(t *testing.T) {
	p, ck := setupCompactFallbackPeer(t)
	conn := &expiryWakeConn{scriptedConn: scriptedConn{reads: []scriptedRead{{err: timeoutErr{}}, {err: io.EOF}}}}
	conn.expireOnRead(ck, 1)
	p.conn = conn

	requireNoCompactErr(t, p.run(context.Background()), "run idle compact fallback")
	requireFirstWrittenCommand(t, p, conn.Bytes(), messageGetData)
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
}

func TestRunKeepsStartedHeaderAliveAcrossCompactExpiry(t *testing.T) {
	p, _ := setupCompactFallbackPeer(t)
	p.service.cfg.Now = time.Now
	p.service.cfg.PeerRuntimeConfig.ReadDeadline = 0
	p.compactMu.Lock()
	p.compact.outstanding.ExpiresAt = time.Now().Add(25 * time.Millisecond)
	p.compactMu.Unlock()
	local, remote := net.Pipe()
	defer local.Close()
	defer remote.Close()
	p.conn = local
	frameBytes := mustPeerRuntimeFrameBytes(t, p, message{Command: messagePing})
	stopFrame := mustPeerRuntimeFrameBytes(t, p, message{Command: messageVersion})
	runDone := make(chan error, 1)
	go func() {
		runDone <- p.run(context.Background())
	}()
	if _, err := remote.Write(frameBytes[:1]); err != nil {
		t.Fatal(err)
	}
	time.Sleep(60 * time.Millisecond)
	if err := remote.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := remote.Write(frameBytes[1:]); err != nil {
		t.Fatal(err)
	}
	frame, err := readFrame(remote, networkMagic(p.service.cfg.PeerRuntimeConfig.Network), p.service.cfg.PeerRuntimeConfig.MaxMessageSize)
	if err != nil {
		t.Fatal(err)
	}
	if frame.Command != messageGetData {
		t.Fatal("fallback command mismatch")
	}
	if _, err := remote.Write(stopFrame); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-runDone:
		if err == nil || err.Error() != "invalid version message after handshake" {
			t.Fatalf("run err=%v, want post-handshake version stop", err)
		}
	case <-time.After(time.Second):
		t.Fatal("run did not consume stop frame")
	}
}

func TestRunFallsBackForExpiredCompactOutstandingBeforeBenignFrame(t *testing.T) {
	matchingBlockTxnPayload := append([]byte{0x11}, make([]byte, 32)...)
	staleBlockTxnPayload := append([]byte{0x22}, make([]byte, 64)...)
	for _, tc := range []struct {
		name        string
		msg         message
		advanceRead int
		wantErr     string
	}{
		{name: "blocktxn_matching_body_header_crosses_expiry", msg: message{Command: messageBlockTxn, Payload: matchingBlockTxnPayload}, advanceRead: 1, wantErr: "message exceeds command cap"},
		{name: "blocktxn_stale_body_crosses_expiry", msg: message{Command: messageBlockTxn, Payload: staleBlockTxnPayload}, advanceRead: 2, wantErr: "stale blocktxn response has body"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, ck := setupCompactFallbackPeer(t)
			p.service.cfg.PeerRuntimeConfig.ReadDeadline = 0
			frameBytes := mustPeerRuntimeFrameBytes(t, p, tc.msg)
			reads := []scriptedRead{{data: frameBytes[:wireHeaderSize]}, {data: frameBytes[wireHeaderSize:]}, {err: io.EOF}}
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
