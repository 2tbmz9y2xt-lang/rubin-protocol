package p2p

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"strings"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/node"
)

func TestReadWriteFrame_Roundtrip(t *testing.T) {
	msg := message{Kind: messageInv, Payload: []byte{0x01, 0x02, 0x03}}

	var buf bytes.Buffer
	if err := writeFrame(&buf, msg, 1024*1024); err != nil {
		t.Fatalf("writeFrame: %v", err)
	}

	got, err := readFrame(&buf, 1024*1024)
	if err != nil {
		t.Fatalf("readFrame: %v", err)
	}
	if got.Kind != msg.Kind {
		t.Fatalf("kind mismatch: %d vs %d", got.Kind, msg.Kind)
	}
	if !bytes.Equal(got.Payload, msg.Payload) {
		t.Fatalf("payload mismatch")
	}
}

func TestReadFrame_EmptyMessage(t *testing.T) {
	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, uint32(0))
	_, err := readFrame(&buf, 1024)
	if err == nil {
		t.Fatal("expected error for empty message")
	}
}

func TestReadFrame_MessageTooLarge(t *testing.T) {
	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, uint32(2048))
	buf.Write(make([]byte, 2048))
	_, err := readFrame(&buf, 1024) // max 1024
	if err == nil {
		t.Fatal("expected error for oversized message")
	}
}

func TestEncodeDecodeInventoryVectors(t *testing.T) {
	vecs := []InventoryVector{
		{Type: MSG_BLOCK, Hash: [32]byte{0x01}},
		{Type: MSG_TX, Hash: [32]byte{0x02}},
	}

	encoded, encErr := encodeInventoryVectors(vecs)
	if encErr != nil {
		t.Fatalf("encodeInventoryVectors: %v", encErr)
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

func TestDecodeInventoryVectors_InvalidLen(t *testing.T) {
	// Not a multiple of inventoryVectorSize
	_, err := decodeInventoryVectors([]byte{0x01, 0x02})
	if err == nil {
		t.Fatal("expected error for invalid length")
	}
}

func TestEncodeDecodeGetBlocksPayload(t *testing.T) {
	p := GetBlocksPayload{
		LocatorHashes: [][32]byte{{0xAA}, {0xBB}},
		StopHash:      [32]byte{0xCC},
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

func TestReadFrame_ShortBody(t *testing.T) {
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.BigEndian, uint32(3)); err != nil {
		t.Fatalf("write length: %v", err)
	}
	if _, err := buf.Write([]byte{messageTx, 0x01}); err != nil {
		t.Fatalf("write body: %v", err)
	}
	_, err := readFrame(&buf, 1024)
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("expected short body error, got %v", err)
	}
}

func TestWriteFrame_EmptyPayloadAllowed(t *testing.T) {
	var buf bytes.Buffer
	msg := message{Kind: messageTx}
	if err := writeFrame(&buf, msg, 1024); err != nil {
		t.Fatalf("writeFrame: %v", err)
	}
	got, err := readFrame(&buf, 1024)
	if err != nil {
		t.Fatalf("readFrame: %v", err)
	}
	if got.Kind != msg.Kind || len(got.Payload) != 0 {
		t.Fatalf("unexpected frame: %#v", got)
	}
}

func TestWriteFrame_Errors(t *testing.T) {
	t.Run("cap exceeded", func(t *testing.T) {
		err := writeFrame(io.Discard, message{Kind: messageInv, Payload: []byte{1, 2}}, 2)
		if err == nil {
			t.Fatal("expected cap error")
		}
	})

	t.Run("length write fails", func(t *testing.T) {
		err := writeFrame(&failingWriter{failOnWrite: 1}, message{Kind: messageInv, Payload: []byte{1}}, 1024)
		if !errors.Is(err, errWriterFailed) {
			t.Fatalf("expected writer error, got %v", err)
		}
	})

	t.Run("kind write fails", func(t *testing.T) {
		err := writeFrame(&failingWriter{failOnWrite: 2}, message{Kind: messageInv, Payload: []byte{1}}, 1024)
		if !errors.Is(err, errWriterFailed) {
			t.Fatalf("expected writer error, got %v", err)
		}
	})

	t.Run("payload write fails", func(t *testing.T) {
		err := writeFrame(&failingWriter{failOnWrite: 3}, message{Kind: messageInv, Payload: []byte{1}}, 1024)
		if !errors.Is(err, errWriterFailed) {
			t.Fatalf("expected writer error, got %v", err)
		}
	})
}

func TestEncodeDecodeVersionPayload(t *testing.T) {
	var chainID [32]byte
	var genesis [32]byte
	chainID[0] = 0x11
	genesis[0] = 0x22
	in := node.VersionPayloadV1{
		Magic:           ProtocolMagic,
		ProtocolVersion: ProtocolVersion,
		ChainID:         chainID,
		GenesisHash:     genesis,
		UserAgent:       "rubin-go/test",
		BestHeight:      123,
	}
	encoded, err := encodeVersionPayload(in)
	if err != nil {
		t.Fatalf("encodeVersionPayload: %v", err)
	}
	out, err := decodeVersionPayload(encoded)
	if err != nil {
		t.Fatalf("decodeVersionPayload: %v", err)
	}
	if out != in {
		t.Fatalf("roundtrip mismatch: %#v vs %#v", out, in)
	}
}

func TestEncodeVersionPayload_UserAgentTooLong(t *testing.T) {
	_, err := encodeVersionPayload(node.VersionPayloadV1{
		UserAgent: strings.Repeat("a", math.MaxUint16+1),
	})
	if err == nil {
		t.Fatal("expected user agent length error")
	}
}

func TestEncodeVersionPayloadTo_WriteErrors(t *testing.T) {
	base := node.VersionPayloadV1{
		Magic:           ProtocolMagic,
		ProtocolVersion: ProtocolVersion,
		UserAgent:       "ua",
		BestHeight:      7,
	}
	for _, failOn := range []int{1, 2, 3, 4, 5, 6, 7} {
		err := encodeVersionPayloadTo(&failingWriter{failOnWrite: failOn}, base)
		if !errors.Is(err, errWriterFailed) {
			t.Fatalf("failOnWrite=%d: expected writer error, got %v", failOn, err)
		}
	}
}

func TestDecodeVersionPayload_Errors(t *testing.T) {
	t.Run("too short", func(t *testing.T) {
		_, err := decodeVersionPayload([]byte{0x01, 0x02})
		if err == nil {
			t.Fatal("expected short payload error")
		}
	})

	t.Run("trailing bytes", func(t *testing.T) {
		payload, err := encodeVersionPayload(node.VersionPayloadV1{
			Magic:           ProtocolMagic,
			ProtocolVersion: ProtocolVersion,
			UserAgent:       "ua",
		})
		if err != nil {
			t.Fatalf("encodeVersionPayload: %v", err)
		}
		payload = append(payload, 0xFF)
		_, err = decodeVersionPayload(payload)
		if err == nil {
			t.Fatal("expected trailing bytes error")
		}
	})
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

	if _, err := encodeInventoryVectors([]InventoryVector{{Type: 0x7F}}); err == nil {
		t.Fatal("expected unsupported type error on encode")
	}

	payload := make([]byte, inventoryVectorSize)
	payload[0] = 0x7F
	if _, err := decodeInventoryVectors(payload); err == nil {
		t.Fatal("expected unsupported type error on decode")
	}
}

func TestGetBlocksPayload_Errors(t *testing.T) {
	locators := make([][32]byte, math.MaxUint16+1)
	if _, err := encodeGetBlocksPayload(GetBlocksPayload{LocatorHashes: locators}); err == nil {
		t.Fatal("expected locator overflow error")
	}

	if _, err := decodeGetBlocksPayload([]byte{0x00, 0x01}); err == nil {
		t.Fatal("expected short payload error")
	}

	if _, err := decodeGetBlocksPayload(make([]byte, 2+31)); err == nil {
		t.Fatal("expected width mismatch error")
	}
}

func TestEncodeGetBlocksPayloadTo_WriteErrors(t *testing.T) {
	req := GetBlocksPayload{
		LocatorHashes: [][32]byte{{0xAA}, {0xBB}},
		StopHash:      [32]byte{0xCC},
	}
	for _, failOn := range []int{1, 2, 3, 4} {
		err := encodeGetBlocksPayloadTo(&failingWriter{failOnWrite: failOn}, req)
		if !errors.Is(err, errWriterFailed) {
			t.Fatalf("failOnWrite=%d: expected writer error, got %v", failOn, err)
		}
	}
}

var errWriterFailed = errors.New("writer failed")

type failingWriter struct {
	writes      int
	failOnWrite int
}

func (w *failingWriter) Write(p []byte) (int, error) {
	w.writes++
	if w.writes == w.failOnWrite {
		return 0, errWriterFailed
	}
	return len(p), nil
}
