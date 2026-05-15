package p2p

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
)

func encodeInventoryVectors(items []InventoryVector) ([]byte, error) {
	if len(items) == 0 {
		return []byte{}, nil
	}
	out := make([]byte, 0, len(items)*inventoryVectorSize)
	for _, item := range items {
		if item.Type != MSG_BLOCK && item.Type != MSG_TX {
			return nil, fmt.Errorf("unsupported inventory type: %d", item.Type)
		}
		out = append(out, item.Type)
		out = append(out, item.Hash[:]...)
	}
	return out, nil
}

func decodeInventoryVectors(payload []byte) ([]InventoryVector, error) {
	if len(payload) == 0 {
		return nil, nil
	}
	if len(payload)%inventoryVectorSize != 0 {
		return nil, errors.New("inventory payload width mismatch")
	}
	if len(payload)/inventoryVectorSize > maxInventoryVectors {
		return nil, errors.New("inventory count exceeds limit")
	}
	out := make([]InventoryVector, 0, len(payload)/inventoryVectorSize)
	for offset := 0; offset < len(payload); offset += inventoryVectorSize {
		itemType := payload[offset]
		if itemType != MSG_BLOCK && itemType != MSG_TX {
			return nil, fmt.Errorf("unsupported inventory type: %d", itemType)
		}
		var hash [32]byte
		copy(hash[:], payload[offset+1:offset+inventoryVectorSize])
		out = append(out, InventoryVector{Type: itemType, Hash: hash})
	}
	return out, nil
}

func encodeGetBlocksPayload(req GetBlocksPayload) ([]byte, error) {
	if len(req.LocatorHashes) > math.MaxUint16 {
		return nil, fmt.Errorf("too many locator hashes: %d", len(req.LocatorHashes))
	}
	return encodePayload(func(w io.Writer) error {
		return encodeGetBlocksPayloadTo(w, req)
	})
}

func encodeGetBlocksPayloadTo(w io.Writer, req GetBlocksPayload) error {
	if err := binary.Write(w, binary.BigEndian, uint16(len(req.LocatorHashes))); err != nil { // #nosec G115 -- len(req.LocatorHashes) is checked against math.MaxUint16 in encodeGetBlocksPayload.
		return err
	}
	for _, locator := range req.LocatorHashes {
		if _, err := w.Write(locator[:]); err != nil {
			return err
		}
	}
	if _, err := w.Write(req.StopHash[:]); err != nil {
		return err
	}
	return nil
}

func decodeGetBlocksPayload(payload []byte) (GetBlocksPayload, error) {
	var out GetBlocksPayload
	if len(payload) < 2+32 {
		return out, errors.New("getblocks payload too short")
	}
	count := binary.BigEndian.Uint16(payload[:2])
	want := 2 + int(count)*32 + 32
	if len(payload) != want {
		return out, errors.New("getblocks payload width mismatch")
	}
	offset := 2
	out.LocatorHashes = make([][32]byte, 0, int(count))
	for i := 0; i < int(count); i++ {
		var locator [32]byte
		copy(locator[:], payload[offset:offset+32])
		out.LocatorHashes = append(out.LocatorHashes, locator)
		offset += 32
	}
	copy(out.StopHash[:], payload[offset:offset+32])
	return out, nil
}
