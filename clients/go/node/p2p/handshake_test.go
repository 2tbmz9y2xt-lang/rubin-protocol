package p2p

import (
	"encoding/hex"
	"fmt"
	"net"
	"testing"
	"time"

	"rubin.dev/node/crypto"
)

func TestHandshakeRoundTripTCP(t *testing.T) {
	p := crypto.DevStdCryptoProvider{}
	magic := uint32(0x11223344)

	var chainID [32]byte
	chainID[0] = 0xaa
	chainID[31] = 0xbb

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
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
		res, err := Handshake(c, p, magic, VersionPayload{
			Timestamp:   uint64(time.Now().Unix()),
			Nonce:       2,
			UserAgent:   "S",
			StartHeight: 11,
			Relay:       false,
		}, chainID)
		if err != nil {
			serverErr <- err
			return
		}
		if !res.Ready {
			serverErr <- fmt.Errorf("server not ready")
			return
		}
		serverErr <- nil
	}()

	clientConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer clientConn.Close()

	res, err := Handshake(clientConn, p, magic, VersionPayload{
		Timestamp:   uint64(time.Now().Unix()),
		Nonce:       1,
		UserAgent:   "C",
		StartHeight: 10,
		Relay:       true,
	}, chainID)
	if err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	if !res.Ready {
		t.Fatalf("client not ready")
	}
	if err := <-serverErr; err != nil {
		t.Fatalf("server handshake: %v", err)
	}
}

func TestChainIDMismatchSendsReject(t *testing.T) {
	p := crypto.DevStdCryptoProvider{}
	magic := uint32(0x11223344)

	var chainA [32]byte
	var chainB [32]byte
	chainA[0] = 0x01
	chainB[0] = 0x02

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	// Server runs handshake expecting chainB; client sends a version with chainA.
	done := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			done <- err
			return
		}
		defer c.Close()
		_, err = Handshake(c, p, magic, VersionPayload{
			Timestamp:   1,
			Nonce:       2,
			UserAgent:   "S",
			StartHeight: 0,
			Relay:       false,
		}, chainB)
		done <- err
	}()

	clientConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer clientConn.Close()

	// Client writes a single version message with wrong chain_id and reads server reject.
	vp := VersionPayload{
		ProtocolVersion: ProtocolVersionV1,
		ChainID:         chainA,
		PeerServices:    0,
		Timestamp:       1,
		Nonce:           1,
		UserAgent:       "C",
		StartHeight:     0,
		Relay:           false,
	}
	payload, err := EncodeVersionPayload(vp)
	if err != nil {
		t.Fatalf("encode version: %v", err)
	}
	if err := WriteMessage(clientConn, p, magic, CmdVersion, payload); err != nil {
		t.Fatalf("write version: %v", err)
	}

	// Server is allowed (and recommended) to send its own version promptly after connect,
	// even if it will later reject the peer's version due to chain_id mismatch.
	msg, rerr := ReadMessage(clientConn, p, magic)
	if rerr != nil {
		t.Fatalf("read first msg: %v", rerr)
	}
	if msg.Command == CmdVersion {
		// ok, ignore
	} else if msg.Command == CmdReject {
		// Some implementations might reject before sending their own version; accept.
	} else {
		t.Fatalf("expected version or reject, got %q", msg.Command)
	}

	if msg.Command != CmdReject {
		msg, rerr = ReadMessage(clientConn, p, magic)
		if rerr != nil {
			t.Fatalf("read reject: %v", rerr)
		}
	}
	if msg.Command != CmdReject {
		t.Fatalf("expected reject, got %q", msg.Command)
	}

	rp, err := DecodeRejectPayload(msg.Payload)
	if err != nil {
		t.Fatalf("decode reject: %v (payload=%s)", err, hex.EncodeToString(msg.Payload))
	}
	if rp.Message != CmdVersion || rp.Code != RejectInvalid {
		t.Fatalf("unexpected reject: message=%q code=%x", rp.Message, rp.Code)
	}

	_ = <-done
}
