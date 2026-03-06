package p2p

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/node"
)

const (
	ProtocolMagic   uint32 = 0x52554249
	ProtocolVersion uint32 = 1

	messageVersion byte = 0x01
	messageInv     byte = 0x02
	messageGetData byte = 0x03
	messageBlock   byte = 0x04
	messageTx      byte = 0x05
	messageGetBlk  byte = 0x06

	MSG_BLOCK byte = 0x01
	MSG_TX    byte = 0x02

	inventoryVectorSize = 33
)

type message struct {
	Kind    byte
	Payload []byte
}

type InventoryVector struct {
	Type byte
	Hash [32]byte
}

type GetBlocksPayload struct {
	LocatorHashes [][32]byte
	StopHash      [32]byte
}

func readFrame(r io.Reader, maxMessageSize uint32) (message, error) {
	var frame message
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return frame, err
	}
	size := binary.BigEndian.Uint32(lenBuf[:])
	if size == 0 {
		return frame, errors.New("empty message")
	}
	if size > maxMessageSize {
		return frame, fmt.Errorf("message exceeds cap: %d", size)
	}

	body := make([]byte, int(size))
	if _, err := io.ReadFull(r, body); err != nil {
		return frame, err
	}
	frame.Kind = body[0]
	frame.Payload = append([]byte(nil), body[1:]...)
	return frame, nil
}

func writeFrame(w io.Writer, frame message, maxMessageSize uint32) error {
	bodyLen := 1 + len(frame.Payload)
	if bodyLen <= 0 {
		return errors.New("empty message")
	}
	if bodyLen > math.MaxUint32 || uint32(bodyLen) > maxMessageSize {
		return fmt.Errorf("message exceeds cap: %d", bodyLen)
	}

	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(bodyLen))
	if _, err := w.Write(lenBuf[:]); err != nil {
		return err
	}
	if _, err := w.Write([]byte{frame.Kind}); err != nil {
		return err
	}
	if len(frame.Payload) == 0 {
		return nil
	}
	_, err := w.Write(frame.Payload)
	return err
}

func encodeVersionPayload(v node.VersionPayloadV1) ([]byte, error) {
	if len(v.UserAgent) > math.MaxUint16 {
		return nil, fmt.Errorf("user_agent too long: %d", len(v.UserAgent))
	}

	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.BigEndian, v.Magic); err != nil {
		return nil, err
	}
	if err := binary.Write(&buf, binary.BigEndian, v.ProtocolVersion); err != nil {
		return nil, err
	}
	if _, err := buf.Write(v.ChainID[:]); err != nil {
		return nil, err
	}
	if _, err := buf.Write(v.GenesisHash[:]); err != nil {
		return nil, err
	}
	if err := binary.Write(&buf, binary.BigEndian, uint16(len(v.UserAgent))); err != nil {
		return nil, err
	}
	if _, err := buf.WriteString(v.UserAgent); err != nil {
		return nil, err
	}
	if err := binary.Write(&buf, binary.BigEndian, v.BestHeight); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func decodeVersionPayload(payload []byte) (node.VersionPayloadV1, error) {
	var out node.VersionPayloadV1
	reader := bytes.NewReader(payload)
	if err := binary.Read(reader, binary.BigEndian, &out.Magic); err != nil {
		return out, errors.New("version payload too short")
	}
	if err := binary.Read(reader, binary.BigEndian, &out.ProtocolVersion); err != nil {
		return out, errors.New("version payload too short")
	}
	if _, err := io.ReadFull(reader, out.ChainID[:]); err != nil {
		return out, errors.New("version payload too short")
	}
	if _, err := io.ReadFull(reader, out.GenesisHash[:]); err != nil {
		return out, errors.New("version payload too short")
	}
	var userAgentLen uint16
	if err := binary.Read(reader, binary.BigEndian, &userAgentLen); err != nil {
		return out, errors.New("version payload too short")
	}
	userAgent := make([]byte, int(userAgentLen))
	if _, err := io.ReadFull(reader, userAgent); err != nil {
		return out, errors.New("version payload too short")
	}
	out.UserAgent = string(userAgent)
	if err := binary.Read(reader, binary.BigEndian, &out.BestHeight); err != nil {
		return out, errors.New("version payload too short")
	}
	if reader.Len() != 0 {
		return out, errors.New("trailing bytes in version payload")
	}
	return out, nil
}

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
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.BigEndian, uint16(len(req.LocatorHashes))); err != nil {
		return nil, err
	}
	for _, locator := range req.LocatorHashes {
		if _, err := buf.Write(locator[:]); err != nil {
			return nil, err
		}
	}
	if _, err := buf.Write(req.StopHash[:]); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
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
