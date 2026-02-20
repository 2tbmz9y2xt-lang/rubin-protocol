package p2p

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"rubin.dev/node/consensus"
	"rubin.dev/node/crypto"
)

type testHandler struct {
	headersCalled atomic.Int32
}

func (h *testHandler) OnHeaders(_ *Peer, _ []consensus.BlockHeader) error {
	h.headersCalled.Add(1)
	return nil
}
func (h *testHandler) OnInv(_ *Peer, _ []InvVector) error      { return nil }
func (h *testHandler) OnGetData(_ *Peer, _ []InvVector) error  { return nil }
func (h *testHandler) OnNotFound(_ *Peer, _ []InvVector) error { return nil }
func (h *testHandler) OnGetHeaders(_ *Peer, _ *GetHeadersPayload) ([]consensus.BlockHeader, error) {
	return []consensus.BlockHeader{{Version: 1, Timestamp: 2}}, nil
}
func (h *testHandler) OnBlock(_ *Peer, _ []byte) error { return nil }
func (h *testHandler) OnTx(_ *Peer, _ []byte) error    { return nil }

func TestPeerPingPongLoopback(t *testing.T) {
	var cp crypto.DevStdCryptoProvider
	magic := uint32(0x0B110907)
	var chainID [32]byte
	chainID[0] = 9

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	serverErr := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer c.Close()

		p, err := NewPeer(c, PeerRoleInbound, PeerConfig{Magic: magic, LocalChainID: chainID, Crypto: cp})
		if err != nil {
			serverErr <- err
			return
		}
		th := &testHandler{}
		// Stop after a short time; we only care that ping is handled without error.
		go func() { time.Sleep(300 * time.Millisecond); cancel() }()
		serverErr <- p.Run(ctx, th)
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	client, err := NewPeer(conn, PeerRoleOutbound, PeerConfig{Magic: magic, LocalChainID: chainID, Crypto: cp})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Handshake(); err != nil {
		t.Fatal(err)
	}
	ping, _ := EncodePingPayload(PingPayload{Nonce: 123})
	if err := client.Send(CmdPing, ping); err != nil {
		t.Fatal(err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	msg, rerr := ReadMessage(conn, cp, magic)
	if rerr != nil {
		t.Fatal(rerr)
	}
	if msg.Command != CmdPong {
		t.Fatalf("expected pong, got %q", msg.Command)
	}
	pp, err := DecodePongPayload(msg.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if pp.Nonce != 123 {
		t.Fatalf("expected nonce 123, got %d", pp.Nonce)
	}

	// Drain server completion.
	_ = <-serverErr
}
