package p2p

import (
	"bytes"
	"encoding/binary"
	"testing"
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
