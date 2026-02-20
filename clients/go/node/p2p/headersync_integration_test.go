package p2p

import (
	"fmt"
	"net"
	"testing"
	"time"

	"rubin.dev/node/consensus"
	"rubin.dev/node/crypto"
)

func TestGetHeadersHeadersExchangeLoopback(t *testing.T) {
	var p crypto.DevStdCryptoProvider
	magic := uint32(0x0B110907)
	var chainID [32]byte
	chainID[0] = 9

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	serverErr := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer c.Close()

		_, err = Handshake(c, p, magic, VersionPayload{}, chainID)
		if err != nil {
			serverErr <- err
			return
		}

		msg, rerr := ReadMessage(c, p, magic)
		if rerr != nil {
			serverErr <- rerr
			return
		}
		if msg.Command != CmdGetHeaders {
			serverErr <- fmt.Errorf("expected getheaders, got %q", msg.Command)
			return
		}
		gh, err := DecodeGetHeadersPayload(msg.Payload)
		if err != nil {
			serverErr <- err
			return
		}
		if gh.Version != ProtocolVersionV1 {
			serverErr <- fmt.Errorf("expected version %d got %d", ProtocolVersionV1, gh.Version)
			return
		}

		h1 := consensus.BlockHeader{Version: 1, Timestamp: 2}
		h2 := consensus.BlockHeader{Version: 3, Timestamp: 4, Nonce: 5}
		hb, err := EncodeHeadersPayload([]consensus.BlockHeader{h1, h2})
		if err != nil {
			serverErr <- err
			return
		}
		serverErr <- WriteMessage(c, p, magic, CmdHeaders, hb)
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	if _, err := Handshake(conn, p, magic, VersionPayload{}, chainID); err != nil {
		t.Fatal(err)
	}

	ghp := GetHeadersPayload{
		Version:      ProtocolVersionV1,
		BlockLocator: [][32]byte{{1}},
	}
	ghb, err := EncodeGetHeadersPayload(ghp)
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteMessage(conn, p, magic, CmdGetHeaders, ghb); err != nil {
		t.Fatal(err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	msg, rerr := ReadMessage(conn, p, magic)
	if rerr != nil {
		t.Fatal(rerr)
	}
	if msg.Command != CmdHeaders {
		t.Fatalf("expected headers, got %q", msg.Command)
	}
	got, err := DecodeHeadersPayload(msg.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Version != 1 || got[1].Nonce != 5 {
		t.Fatalf("unexpected headers: %+v", got)
	}

	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
}
