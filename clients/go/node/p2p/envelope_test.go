package p2p

import (
	"bytes"
	"encoding/hex"
	"io"
	"testing"

	"rubin.dev/node/crypto"
)

type chunkReader struct {
	b     []byte
	step  int
	index int
}

func (r *chunkReader) Read(p []byte) (int, error) {
	if r.index >= len(r.b) {
		return 0, io.EOF
	}
	n := r.step
	if n <= 0 {
		n = 1
	}
	if r.index+n > len(r.b) {
		n = len(r.b) - r.index
	}
	if n > len(p) {
		n = len(p)
	}
	copy(p[:n], r.b[r.index:r.index+n])
	r.index += n
	return n, nil
}

func TestEmptyPayloadChecksumIsNotZero(t *testing.T) {
	p := crypto.DevStdCryptoProvider{}
	c4, err := checksum4(p, nil)
	if err != nil {
		t.Fatalf("checksum: %v", err)
	}
	got := hex.EncodeToString(c4[:])
	// From spec/RUBIN_L1_P2P_PROTOCOL_v1.1.md §1.1.
	if got != "a7ffc6f8" {
		t.Fatalf("expected a7ffc6f8, got %s", got)
	}
}

func TestWriteReadRoundTripPartialReads(t *testing.T) {
	p := crypto.DevStdCryptoProvider{}
	var buf bytes.Buffer
	magic := uint32(0x11223344)

	payload := []byte("hello")
	if err := WriteMessage(&buf, p, magic, "version", payload); err != nil {
		t.Fatalf("WriteMessage: %v", err)
	}

	r := &chunkReader{b: buf.Bytes(), step: 1}
	msg, rerr := ReadMessage(r, p, magic)
	if rerr != nil {
		t.Fatalf("ReadMessage: %v", rerr)
	}
	if msg.Command != "version" {
		t.Fatalf("command mismatch: %q", msg.Command)
	}
	if !bytes.Equal(msg.Payload, payload) {
		t.Fatalf("payload mismatch: %x != %x", msg.Payload, payload)
	}
}

func TestMagicMismatchDisconnectNoBan(t *testing.T) {
	p := crypto.DevStdCryptoProvider{}
	var buf bytes.Buffer
	if err := WriteMessage(&buf, p, 0x01020304, "verack", nil); err != nil {
		t.Fatalf("WriteMessage: %v", err)
	}
	msg, rerr := ReadMessage(bytes.NewReader(buf.Bytes()), p, 0x0a0b0c0d)
	if msg != nil || rerr == nil {
		t.Fatalf("expected error")
	}
	if !rerr.Disconnect || rerr.BanScoreDelta != 0 {
		t.Fatalf("expected disconnect w/0 ban, got disconnect=%v ban=%d", rerr.Disconnect, rerr.BanScoreDelta)
	}
}

func TestOversizeDisconnectImmediate(t *testing.T) {
	p := crypto.DevStdCryptoProvider{}
	magic := uint32(0x11223344)
	cmd12, err := encodeCommand("inv")
	if err != nil {
		t.Fatalf("encodeCommand: %v", err)
	}

	var hdr [TransportPrefixBytes]byte
	// magic (be)
	hdr[0] = 0x11
	hdr[1] = 0x22
	hdr[2] = 0x33
	hdr[3] = 0x44
	copy(hdr[4:16], cmd12[:])
	// payload_length (le) := MaxRelayMsgBytes + 1
	oversize := uint32(MaxRelayMsgBytes + 1)
	hdr[16] = byte(oversize)
	hdr[17] = byte(oversize >> 8)
	hdr[18] = byte(oversize >> 16)
	hdr[19] = byte(oversize >> 24)
	// checksum arbitrary
	copy(hdr[20:24], []byte{1, 2, 3, 4})

	msg, rerr := ReadMessage(bytes.NewReader(hdr[:]), p, magic)
	if msg != nil || rerr == nil {
		t.Fatalf("expected error")
	}
	if !rerr.Disconnect {
		t.Fatalf("expected disconnect on oversize")
	}
}

func TestChecksumMismatchBan10NoDisconnect(t *testing.T) {
	p := crypto.DevStdCryptoProvider{}
	magic := uint32(0x11223344)
	cmd12, err := encodeCommand("ping")
	if err != nil {
		t.Fatalf("encodeCommand: %v", err)
	}
	payload := []byte{0, 1, 2, 3}

	var hdr [TransportPrefixBytes]byte
	hdr[0] = 0x11
	hdr[1] = 0x22
	hdr[2] = 0x33
	hdr[3] = 0x44
	copy(hdr[4:16], cmd12[:])
	// payload_length (le)
	hdr[16] = byte(len(payload))
	// checksum intentionally wrong
	copy(hdr[20:24], []byte{9, 9, 9, 9})

	wire := append(hdr[:], payload...)
	msg, rerr := ReadMessage(bytes.NewReader(wire), p, magic)
	if msg != nil || rerr == nil {
		t.Fatalf("expected error")
	}
	if rerr.Disconnect || rerr.BanScoreDelta != 10 {
		t.Fatalf("expected no disconnect +10 ban, got disconnect=%v ban=%d", rerr.Disconnect, rerr.BanScoreDelta)
	}
}
