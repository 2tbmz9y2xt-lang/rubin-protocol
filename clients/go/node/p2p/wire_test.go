package p2p

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/node"
)

func TestReadWriteFrameRoundtrip(t *testing.T) {
	msg := message{Command: messageInv, Payload: []byte{0x01, 0x02, 0x03}}
	magic := networkMagic("devnet")

	var buf bytes.Buffer
	if err := writeFrame(&buf, magic, msg, 1024*1024); err != nil {
		t.Fatalf("writeFrame: %v", err)
	}

	got, err := readFrame(&buf, magic, 1024*1024)
	if err != nil {
		t.Fatalf("readFrame: %v", err)
	}
	if got.Command != msg.Command {
		t.Fatalf("command mismatch: %q vs %q", got.Command, msg.Command)
	}
	if !bytes.Equal(got.Payload, msg.Payload) {
		t.Fatalf("payload mismatch")
	}
}

func TestReadFrameRejectsInvalidMagic(t *testing.T) {
	msg := message{Command: messageInv, Payload: []byte{0x01}}
	var buf bytes.Buffer
	if err := writeFrame(&buf, networkMagic("mainnet"), msg, 1024); err != nil {
		t.Fatalf("writeFrame: %v", err)
	}
	if _, err := readFrame(&buf, networkMagic("devnet"), 1024); err == nil || err.Error() != "invalid envelope magic" {
		t.Fatalf("expected invalid envelope magic, got %v", err)
	}
}

func TestReadFrameRejectsChecksumMismatch(t *testing.T) {
	msg := message{Command: messageInv, Payload: []byte{0x01, 0x02}}
	var buf bytes.Buffer
	if err := writeFrame(&buf, networkMagic("devnet"), msg, 1024); err != nil {
		t.Fatalf("writeFrame: %v", err)
	}
	raw := buf.Bytes()
	raw[len(raw)-1] ^= 0xff
	if _, err := readFrame(bytes.NewReader(raw), networkMagic("devnet"), 1024); err == nil || err.Error() != "invalid envelope checksum" {
		t.Fatalf("expected invalid envelope checksum, got %v", err)
	}
}

func TestReadFrameMessageTooLarge(t *testing.T) {
	header, err := buildEnvelopeHeader(networkMagic("devnet"), messageTx, make([]byte, 2048))
	if err != nil {
		t.Fatalf("buildEnvelopeHeader: %v", err)
	}
	buf := bytes.NewBuffer(header[:])
	buf.Write(make([]byte, 2048))
	_, err = readFrame(buf, networkMagic("devnet"), 1024)
	if err == nil || err.Error() != "message exceeds cap" {
		t.Fatalf("expected cap error, got %v", err)
	}
}

func TestReadFrameShortBody(t *testing.T) {
	header, err := buildEnvelopeHeader(networkMagic("devnet"), messageTx, []byte{0x01, 0x02})
	if err != nil {
		t.Fatalf("buildEnvelopeHeader: %v", err)
	}
	buf := bytes.NewBuffer(header[:])
	buf.WriteByte(0x01)
	_, err = readFrame(buf, networkMagic("devnet"), 1024)
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("expected short body error, got %v", err)
	}
}

func TestReadFrameWithPayloadLimitRejectsOversizeVersionBeforePayloadRead(t *testing.T) {
	header, err := buildEnvelopeHeader(networkMagic("devnet"), messageVersion, make([]byte, versionPayloadBytes+1))
	if err != nil {
		t.Fatalf("buildEnvelopeHeader: %v", err)
	}
	reader := io.MultiReader(
		bytes.NewReader(header[:]),
		&failingReader{err: errors.New("payload should not be read")},
	)
	_, err = readFrameWithPayloadLimit(reader, networkMagic("devnet"), 1024*1024, preHandshakePayloadCap)
	if err == nil || err.Error() != "message exceeds command cap" {
		t.Fatalf("expected command cap error, got %v", err)
	}
}

func TestWriteFrameErrors(t *testing.T) {
	t.Run("cap exceeded", func(t *testing.T) {
		err := writeFrame(io.Discard, networkMagic("devnet"), message{Command: messageInv, Payload: []byte{1, 2}}, 1)
		if err == nil {
			t.Fatal("expected cap error")
		}
	})

	t.Run("invalid command", func(t *testing.T) {
		err := writeFrame(io.Discard, networkMagic("devnet"), message{Command: "", Payload: []byte{1}}, 1024)
		if err == nil {
			t.Fatal("expected invalid command error")
		}
	})

	t.Run("header write fails", func(t *testing.T) {
		err := writeFrame(&failingWriter{failOnWrite: 1}, networkMagic("devnet"), message{Command: messageInv, Payload: []byte{1}}, 1024)
		if !errors.Is(err, errWriterFailed) {
			t.Fatalf("expected writer error, got %v", err)
		}
	})

	t.Run("payload write fails", func(t *testing.T) {
		err := writeFrame(&failingWriter{failOnWrite: 2}, networkMagic("devnet"), message{Command: messageInv, Payload: []byte{1}}, 1024)
		if !errors.Is(err, errWriterFailed) {
			t.Fatalf("expected writer error, got %v", err)
		}
	})
}

type failingReader struct {
	err error
}

func (r *failingReader) Read(_ []byte) (int, error) {
	return 0, r.err
}

func TestEncodeDecodeVersionPayload(t *testing.T) {
	var chainID [32]byte
	var genesis [32]byte
	chainID[0] = 0x11
	genesis[0] = 0x22
	in := node.VersionPayloadV1{
		ProtocolVersion:   ProtocolVersion,
		TxRelay:           true,
		PrunedBelowHeight: 7,
		DaMempoolSize:     512,
		ChainID:           chainID,
		GenesisHash:       genesis,
		BestHeight:        123,
	}
	encoded, err := encodeVersionPayload(in)
	if err != nil {
		t.Fatalf("encodeVersionPayload: %v", err)
	}
	if len(encoded) != versionPayloadBytes {
		t.Fatalf("payload bytes=%d, want %d", len(encoded), versionPayloadBytes)
	}
	out, err := decodeVersionPayload(encoded)
	if err != nil {
		t.Fatalf("decodeVersionPayload: %v", err)
	}
	if out != in {
		t.Fatalf("roundtrip mismatch: %#v vs %#v", out, in)
	}
}

func TestDecodeVersionPayloadErrors(t *testing.T) {
	t.Run("too short", func(t *testing.T) {
		_, err := decodeVersionPayload([]byte{0x01, 0x02})
		if err == nil || err.Error() != "version payload too short" {
			t.Fatalf("expected short payload error, got %v", err)
		}
	})

	t.Run("trailing bytes", func(t *testing.T) {
		payload, err := encodeVersionPayload(node.VersionPayloadV1{ProtocolVersion: ProtocolVersion})
		if err != nil {
			t.Fatalf("encodeVersionPayload: %v", err)
		}
		payload = append(payload, 0xff)
		_, err = decodeVersionPayload(payload)
		if err == nil || err.Error() != "trailing bytes in version payload" {
			t.Fatalf("expected trailing bytes error, got %v", err)
		}
	})
}

func TestEncodeDecodeInventoryVectors(t *testing.T) {
	vecs := []InventoryVector{
		{Type: MSG_BLOCK, Hash: [32]byte{0x01}},
		{Type: MSG_TX, Hash: [32]byte{0x02}},
	}

	encoded, err := encodeInventoryVectors(vecs)
	if err != nil {
		t.Fatalf("encodeInventoryVectors: %v", err)
	}
	decoded, err := decodeInventoryVectors(encoded)
	if err != nil {
		t.Fatalf("decodeInventoryVectors: %v", err)
	}
	if len(decoded) != len(vecs) {
		t.Fatalf("length mismatch: %d vs %d", len(decoded), len(vecs))
	}
	for i := range vecs {
		if decoded[i].Type != vecs[i].Type || decoded[i].Hash != vecs[i].Hash {
			t.Fatalf("vector %d mismatch", i)
		}
	}
}

func TestInventoryVectorEdgeCases(t *testing.T) {
	encoded, err := encodeInventoryVectors(nil)
	if err != nil {
		t.Fatalf("encodeInventoryVectors(nil): %v", err)
	}
	if len(encoded) != 0 {
		t.Fatalf("expected empty encoding, got %d bytes", len(encoded))
	}

	decoded, err := decodeInventoryVectors(nil)
	if err != nil {
		t.Fatalf("decodeInventoryVectors(nil): %v", err)
	}
	if decoded != nil {
		t.Fatalf("expected nil decoded slice, got %#v", decoded)
	}

	if _, err := encodeInventoryVectors([]InventoryVector{{Type: 0x7f}}); err == nil {
		t.Fatal("expected unsupported type error on encode")
	}

	payload := make([]byte, inventoryVectorSize)
	payload[0] = 0x7f
	if _, err := decodeInventoryVectors(payload); err == nil {
		t.Fatal("expected unsupported type error on decode")
	}
}

func TestDecodeInventoryVectorsInvalidLen(t *testing.T) {
	_, err := decodeInventoryVectors([]byte{0x01, 0x02})
	if err == nil {
		t.Fatal("expected error for invalid length")
	}
}

func TestEncodeDecodeGetBlocksPayload(t *testing.T) {
	p := GetBlocksPayload{
		LocatorHashes: [][32]byte{{0xaa}, {0xbb}},
		StopHash:      [32]byte{0xcc},
	}
	encoded, err := encodeGetBlocksPayload(p)
	if err != nil {
		t.Fatalf("encodeGetBlocksPayload: %v", err)
	}
	decoded, err := decodeGetBlocksPayload(encoded)
	if err != nil {
		t.Fatalf("decodeGetBlocksPayload: %v", err)
	}
	if len(decoded.LocatorHashes) != 2 {
		t.Fatalf("locator count mismatch: %d", len(decoded.LocatorHashes))
	}
	if decoded.StopHash != p.StopHash {
		t.Fatal("stop hash mismatch")
	}
}

func TestBuildEnvelopeHeaderEncodesLittleEndianLength(t *testing.T) {
	header, err := buildEnvelopeHeader(networkMagic("devnet"), messageBlock, []byte{0x01, 0x02, 0x03})
	if err != nil {
		t.Fatalf("buildEnvelopeHeader: %v", err)
	}
	if binary.LittleEndian.Uint32(header[16:20]) != 3 {
		t.Fatalf("payload_len=%d, want 3", binary.LittleEndian.Uint32(header[16:20]))
	}
}

var errWriterFailed = errors.New("writer failed")

type failingWriter struct {
	failOnWrite int
	writes      int
}

func (w *failingWriter) Write(p []byte) (int, error) {
	w.writes++
	if w.writes == w.failOnWrite {
		return 0, errWriterFailed
	}
	return len(p), nil
}
