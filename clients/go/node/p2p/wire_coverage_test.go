package p2p

import (
	"bytes"
	"testing"
)

// ---------------------------------------------------------------------------
// networkMagic — uncovered switch arms
// ---------------------------------------------------------------------------

func TestNetworkMagic_Testnet(t *testing.T) {
	got := networkMagic("testnet")
	want := [4]byte{'R', 'B', 'T', 'N'}
	if got != want {
		t.Fatalf("testnet magic=%v, want %v", got, want)
	}
}

func TestNetworkMagic_Default(t *testing.T) {
	got := networkMagic("unknown-net")
	want := [4]byte{'R', 'B', 'O', 'P'}
	if got != want {
		t.Fatalf("default magic=%v, want %v", got, want)
	}
}

func TestNetworkMagic_NormalizesKnownNetworkNames(t *testing.T) {
	got := networkMagic(" MAINNET ")
	want := [4]byte{'R', 'B', 'M', 'N'}
	if got != want {
		t.Fatalf("normalized mainnet magic=%v, want %v", got, want)
	}
}

// ---------------------------------------------------------------------------
// decodeWireCommand — uncovered error branches
// ---------------------------------------------------------------------------

func TestDecodeWireCommand_InvalidWidth(t *testing.T) {
	_, err := decodeWireCommand([]byte{0x41, 0x42}) // len != wireCommandSize
	if err == nil || err.Error() != "invalid command width" {
		t.Fatalf("expected 'invalid command width', got %v", err)
	}
}

func TestDecodeWireCommand_EmptyCommand(t *testing.T) {
	// 12 zero bytes → first byte is NUL → end=0 → "empty command"
	raw := make([]byte, wireCommandSize)
	_, err := decodeWireCommand(raw)
	if err == nil || err.Error() != "empty command" {
		t.Fatalf("expected 'empty command', got %v", err)
	}
}

func TestDecodeWireCommand_InvalidNULPadding(t *testing.T) {
	// "tx\x00\x00\x00\x00\x00\x00\x00\x00\x00\x42" — non-zero after NUL
	raw := make([]byte, wireCommandSize)
	raw[0] = 't'
	raw[1] = 'x'
	raw[11] = 0x42 // non-zero trailing byte
	_, err := decodeWireCommand(raw)
	if err == nil || err.Error() != "invalid NUL padding in command" {
		t.Fatalf("expected 'invalid NUL padding in command', got %v", err)
	}
}

func TestDecodeWireCommand_NonASCIIPrintable(t *testing.T) {
	// Control character (0x01) in command portion → "command is not ASCII printable"
	raw := make([]byte, wireCommandSize)
	raw[0] = 0x01 // non-printable
	raw[1] = 'x'
	_, err := decodeWireCommand(raw)
	if err == nil || err.Error() != "command is not ASCII printable" {
		t.Fatalf("expected 'command is not ASCII printable', got %v", err)
	}
}

// ---------------------------------------------------------------------------
// encodeWireCommand — uncovered error branch
// ---------------------------------------------------------------------------

func TestEncodeWireCommand_NonASCIIPrintable(t *testing.T) {
	_, err := encodeWireCommand("ab\x01cd")
	if err == nil || err.Error() != "command is not ASCII printable" {
		t.Fatalf("expected 'command is not ASCII printable', got %v", err)
	}
}

// ---------------------------------------------------------------------------
// readFrameHeader — decodeWireCommand error propagation (line 110)
// ---------------------------------------------------------------------------

func TestReadFrameHeader_BadCommandInHeader(t *testing.T) {
	// Construct a valid 24-byte header with bad command bytes (all zero).
	magic := networkMagic("devnet")
	var raw [wireHeaderSize]byte
	copy(raw[0:4], magic[:])
	// raw[4:16] all zero → decodeWireCommand → "empty command"
	// raw[16:20] = size 0
	// raw[20:24] = checksum (irrelevant, won't reach)

	_, err := readFrameHeader(bytes.NewReader(raw[:]), magic, 1024)
	if err == nil || err.Error() != "empty command" {
		t.Fatalf("expected 'empty command', got %v", err)
	}
}

// ---------------------------------------------------------------------------
// decodeGetBlocksPayload — width mismatch (line 365)
// ---------------------------------------------------------------------------

func TestDecodeGetBlocksPayload_WidthMismatch(t *testing.T) {
	// count=1 → needs 2 + 32 + 32 = 66 bytes, but provide 2 + 32 + 10
	payload := make([]byte, 44)
	payload[0] = 0x00
	payload[1] = 0x01 // count = 1 (big-endian)
	_, err := decodeGetBlocksPayload(payload)
	if err == nil || err.Error() != "getblocks payload width mismatch" {
		t.Fatalf("expected 'getblocks payload width mismatch', got %v", err)
	}
}

// ---------------------------------------------------------------------------
// decodeAddrPayload — trailing bytes (line 421)
// ---------------------------------------------------------------------------

func TestDecodeAddrPayload_TrailingBytes(t *testing.T) {
	// Encode 1 addr, then append an extra byte so len != needed
	addrs, err := encodeAddrPayload([]string{"[::1]:8333"})
	if err != nil {
		t.Fatalf("encodeAddrPayload: %v", err)
	}
	addrs = append(addrs, 0xff) // trailing
	_, err = decodeAddrPayload(addrs)
	if err == nil || err.Error() != "addr payload width mismatch" {
		t.Fatalf("expected 'addr payload width mismatch', got %v", err)
	}
}

// ---------------------------------------------------------------------------
// decodeAddrCount — DecodeCompactSize error (line 439)
// ---------------------------------------------------------------------------

func TestDecodeAddrCount_CompactSizeError(t *testing.T) {
	// CompactSize 0xfd needs 3 bytes, only provide 1 → error
	_, _, err := decodeAddrCount([]byte{0xfd})
	if err == nil {
		t.Fatal("expected DecodeCompactSize error")
	}
}
