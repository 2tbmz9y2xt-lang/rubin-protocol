package p2p

import (
	"bytes"
	"crypto/sha3"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"strconv"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/node"
)

const (
	ProtocolVersion uint32 = 1

	messageVersion = "version"
	messageVerAck  = "verack"
	messageInv     = "inv"
	messageGetData = "getdata"
	messageBlock   = "block"
	messageTx      = "tx"
	messageGetBlk  = "getblocks"
	messageGetAddr = "getaddr"
	messageAddr    = "addr"
	messagePing    = "ping"
	messagePong    = "pong"
	messageHeaders = "headers"

	MSG_BLOCK byte = 0x01
	MSG_TX    byte = 0x02

	inventoryVectorSize     = 33
	addrPayloadEntrySize    = 18
	wireHeaderSize          = 24
	wireCommandSize         = 12
	versionPayloadBaseBytes = 17
	versionPayloadBytes     = versionPayloadBaseBytes + 32 + 32 + 8
	maxAddrPayloadEntries   = maxKnownAddrs
	maxInventoryVectors     = 4096
	maxCompactSizeBytes     = 9
	streamReadChunkBytes    = 32 * 1024
)

type message struct {
	Command string
	Payload []byte
}

type payloadLimitFn func(command string) uint32

type frameHeader struct {
	Command  string
	Size     uint32
	Checksum [4]byte
}

type InventoryVector struct {
	Type byte
	Hash [32]byte
}

type GetBlocksPayload struct {
	LocatorHashes [][32]byte
	StopHash      [32]byte
}

func readFrame(r io.Reader, expectedMagic [4]byte, maxMessageSize uint32) (message, error) {
	return readFrameWithPayloadLimit(r, expectedMagic, maxMessageSize, nil)
}

func readFrameWithPayloadLimit(r io.Reader, expectedMagic [4]byte, maxMessageSize uint32, limit payloadLimitFn) (message, error) {
	var frame message
	header, err := readFrameHeader(r, expectedMagic, maxMessageSize)
	if err != nil {
		return frame, err
	}
	if limit != nil {
		if header.Size > limit(header.Command) {
			return frame, errors.New("message exceeds command cap")
		}
	}
	payload, err := readPayloadWithChecksum(r, header.Size, header.Checksum)
	if err != nil {
		return frame, err
	}
	frame.Command = header.Command
	frame.Payload = payload
	return frame, nil
}

func readPayloadWithChecksum(r io.Reader, size uint32, wantChecksum [4]byte) ([]byte, error) {
	if size == 0 {
		if wantChecksum != wireChecksum(nil) {
			return nil, errors.New("invalid envelope checksum")
		}
		return make([]byte, 0), nil
	}

	hasher := sha3.New256()
	initialCap := int(size)
	if initialCap > streamReadChunkBytes {
		initialCap = streamReadChunkBytes
	}
	payload := make([]byte, 0, initialCap)
	remaining := int(size)
	for remaining > 0 {
		chunkLen := remaining
		if chunkLen > streamReadChunkBytes {
			chunkLen = streamReadChunkBytes
		}
		chunk := make([]byte, chunkLen)
		if _, err := io.ReadFull(r, chunk); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return nil, io.ErrUnexpectedEOF
			}
			return nil, err
		}
		if _, err := hasher.Write(chunk); err != nil {
			return nil, err
		}
		payload = append(payload, chunk...)
		remaining -= chunkLen
	}

	sum := hasher.Sum(nil)
	if !bytes.Equal(wantChecksum[:], sum[:4]) {
		return nil, errors.New("invalid envelope checksum")
	}

	return payload, nil
}

func readFrameHeader(r io.Reader, expectedMagic [4]byte, maxMessageSize uint32) (frameHeader, error) {
	var header frameHeader
	var raw [wireHeaderSize]byte
	if _, err := io.ReadFull(r, raw[:]); err != nil {
		return header, err
	}
	if !bytes.Equal(raw[0:4], expectedMagic[:]) {
		return header, errors.New("invalid envelope magic")
	}
	command, err := decodeWireCommand(raw[4 : 4+wireCommandSize])
	if err != nil {
		return header, err
	}
	size := binary.LittleEndian.Uint32(raw[16:20])
	if size > maxMessageSize {
		return header, errors.New("message exceeds cap")
	}
	header.Command = command
	header.Size = size
	copy(header.Checksum[:], raw[20:24])
	return header, nil
}

func writeFrame(w io.Writer, magic [4]byte, frame message, maxMessageSize uint32) error {
	if uint64(len(frame.Payload)) > uint64(maxMessageSize) {
		return errors.New("message exceeds cap")
	}
	header, err := buildEnvelopeHeader(magic, frame.Command, frame.Payload)
	if err != nil {
		return err
	}
	if _, err := w.Write(header[:]); err != nil {
		return err
	}
	if len(frame.Payload) == 0 {
		return nil
	}
	_, err = w.Write(frame.Payload)
	return err
}

func encodeVersionPayload(v node.VersionPayloadV1) ([]byte, error) {
	return encodePayload(func(w io.Writer) error {
		return encodeVersionPayloadTo(w, v)
	})
}

func encodeVersionPayloadTo(w io.Writer, v node.VersionPayloadV1) error {
	if err := binary.Write(w, binary.LittleEndian, v.ProtocolVersion); err != nil {
		return err
	}
	txRelay := byte(0)
	if v.TxRelay {
		txRelay = 1
	}
	if _, err := w.Write([]byte{txRelay}); err != nil {
		return err
	}
	if err := binary.Write(w, binary.LittleEndian, v.PrunedBelowHeight); err != nil {
		return err
	}
	if err := binary.Write(w, binary.LittleEndian, v.DaMempoolSize); err != nil {
		return err
	}
	if _, err := w.Write(v.ChainID[:]); err != nil {
		return err
	}
	if _, err := w.Write(v.GenesisHash[:]); err != nil {
		return err
	}
	if err := binary.Write(w, binary.LittleEndian, v.BestHeight); err != nil {
		return err
	}
	return nil
}

func decodeVersionPayload(payload []byte) (node.VersionPayloadV1, error) {
	var out node.VersionPayloadV1
	if len(payload) != versionPayloadBytes {
		if len(payload) < versionPayloadBytes {
			return out, errors.New("version payload too short")
		}
		return out, errors.New("trailing bytes in version payload")
	}
	reader := bytes.NewReader(payload)
	if err := binary.Read(reader, binary.LittleEndian, &out.ProtocolVersion); err != nil {
		return out, errors.New("version payload too short")
	}
	var txRelay [1]byte
	if _, err := io.ReadFull(reader, txRelay[:]); err != nil {
		return out, errors.New("version payload too short")
	}
	out.TxRelay = txRelay[0] == 1
	if err := binary.Read(reader, binary.LittleEndian, &out.PrunedBelowHeight); err != nil {
		return out, errors.New("version payload too short")
	}
	if err := binary.Read(reader, binary.LittleEndian, &out.DaMempoolSize); err != nil {
		return out, errors.New("version payload too short")
	}
	if _, err := io.ReadFull(reader, out.ChainID[:]); err != nil {
		return out, errors.New("version payload too short")
	}
	if _, err := io.ReadFull(reader, out.GenesisHash[:]); err != nil {
		return out, errors.New("version payload too short")
	}
	if err := binary.Read(reader, binary.LittleEndian, &out.BestHeight); err != nil {
		return out, errors.New("version payload too short")
	}
	if reader.Len() != 0 {
		return out, errors.New("trailing bytes in version payload")
	}
	return out, nil
}

func buildEnvelopeHeader(magic [4]byte, command string, payload []byte) ([wireHeaderSize]byte, error) {
	var header [wireHeaderSize]byte
	commandBytes, err := encodeWireCommand(command)
	if err != nil {
		return header, err
	}
	header[0], header[1], header[2], header[3] = magic[0], magic[1], magic[2], magic[3]
	copy(header[4:16], commandBytes[:])
	if len(payload) > math.MaxUint32 {
		return header, errors.New("payload length overflow")
	}
	binary.LittleEndian.PutUint32(header[16:20], uint32(len(payload))) // #nosec G115 -- len(payload) is checked against math.MaxUint32 above.
	checksum := wireChecksum(payload)
	copy(header[20:24], checksum[:])
	return header, nil
}

func wireChecksum(payload []byte) [4]byte {
	sum := sha3.Sum256(payload)
	return [4]byte{sum[0], sum[1], sum[2], sum[3]}
}

func encodeWireCommand(command string) ([wireCommandSize]byte, error) {
	var out [wireCommandSize]byte
	if len(command) == 0 || len(command) > wireCommandSize {
		return out, errors.New("invalid command length")
	}
	for i := 0; i < len(command); i++ {
		ch := command[i]
		if ch < 0x21 || ch > 0x7e {
			return out, errors.New("command is not ASCII printable")
		}
		out[i] = ch
	}
	return out, nil
}

func decodeWireCommand(raw []byte) (string, error) {
	if len(raw) != wireCommandSize {
		return "", errors.New("invalid command width")
	}
	end := wireCommandSize
	for i, ch := range raw {
		if ch == 0 {
			end = i
			break
		}
	}
	if end == 0 {
		return "", errors.New("empty command")
	}
	for _, ch := range raw[end:] {
		if ch != 0 {
			return "", errors.New("invalid NUL padding in command")
		}
	}
	for _, ch := range raw[:end] {
		if ch < 0x21 || ch > 0x7e {
			return "", errors.New("command is not ASCII printable")
		}
	}
	return string(raw[:end]), nil
}

func networkMagic(network string) [4]byte {
	network, ok := node.CanonicalNetworkName(network)
	if !ok {
		// Low-level wire helpers still keep a fixed isolation fallback for custom or
		// private transports, but the node config/runtime surface rejects those names
		// before startup. Any normalized name outside {mainnet,testnet,devnet} falls
		// through to the shared non-standard magic below.
	}
	switch network {
	case "mainnet":
		return [4]byte{'R', 'B', 'M', 'N'}
	case "testnet":
		return [4]byte{'R', 'B', 'T', 'N'}
	case "devnet":
		return [4]byte{'R', 'B', 'D', 'V'}
	default:
		return [4]byte{'R', 'B', 'O', 'P'}
	}
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

func encodePayload(encode func(io.Writer) error) ([]byte, error) {
	var buf bytes.Buffer
	if err := encode(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
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

func encodeAddrPayload(addrs []string) ([]byte, error) {
	var buf bytes.Buffer
	buf.Write(consensus.EncodeCompactSize(uint64(len(addrs))))
	for _, addr := range addrs {
		host, portStr, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		ip := net.ParseIP(host)
		if ip == nil {
			return nil, fmt.Errorf("invalid addr host: %s", host)
		}
		port, err := strconv.ParseUint(portStr, 10, 16)
		if err != nil || port == 0 {
			return nil, fmt.Errorf("invalid addr port: %s", portStr)
		}
		ip = ip.To16()
		if ip == nil {
			return nil, fmt.Errorf("invalid addr ip width: %s", host)
		}
		buf.Write(ip)
		var portBytes [2]byte
		binary.BigEndian.PutUint16(portBytes[:], uint16(port))
		buf.Write(portBytes[:])
	}
	return buf.Bytes(), nil
}

func decodeAddrPayload(payload []byte) ([]string, error) {
	if len(payload) == 0 {
		return nil, nil
	}
	count, consumed, err := decodeAddrCount(payload)
	if err != nil {
		return nil, err
	}
	remaining := len(payload) - consumed
	if remaining < 0 || count > uint64(remaining/addrPayloadEntrySize) {
		return nil, errors.New("addr payload width mismatch")
	}
	needed := consumed + int(count)*addrPayloadEntrySize // #nosec G115 -- count is bounded by remaining/addrPayloadEntrySize above.
	if len(payload) != needed {
		return nil, errors.New("addr payload width mismatch")
	}
	out := make([]string, 0, int(count)) // #nosec G115 -- count is bounded by remaining/addrPayloadEntrySize above.
	offset := consumed
	for i := uint64(0); i < count; i++ {
		addr, nextOffset, err := decodeAddrPayloadEntry(payload, offset)
		if err != nil {
			return nil, err
		}
		offset = nextOffset
		out = append(out, addr)
	}
	return out, nil
}

func decodeAddrCount(payload []byte) (uint64, int, error) {
	count, consumed, err := consensus.DecodeCompactSize(payload)
	if err != nil {
		return 0, 0, err
	}
	maxInt := int(^uint(0) >> 1)
	if count > uint64(maxInt) {
		return 0, 0, errors.New("addr count overflow")
	}
	if count > maxAddrPayloadEntries {
		return 0, 0, errors.New("addr count exceeds limit")
	}
	return count, consumed, nil
}

func decodeAddrPayloadEntry(payload []byte, offset int) (string, int, error) {
	ip := net.IP(payload[offset : offset+16])
	offset += 16
	port := binary.BigEndian.Uint16(payload[offset : offset+2])
	offset += 2
	addr := normalizeNetAddr(net.JoinHostPort(ip.String(), strconv.FormatUint(uint64(port), 10)))
	if addr == "" {
		return "", 0, errors.New("invalid addr payload entry")
	}
	return addr, offset, nil
}

func inventoryPayloadCap() uint32 {
	return uint32(maxInventoryVectors * inventoryVectorSize)
}

func addrPayloadCap() uint32 {
	return uint32(maxCompactSizeBytes + maxAddrPayloadEntries*addrPayloadEntrySize)
}

func getBlocksPayloadCap(locatorLimit int) uint32 {
	if locatorLimit <= 0 {
		locatorLimit = defaultLocatorLimit
	}
	return uint32(2 + locatorLimit*32 + 32)
}

func headersPayloadCap(headerBatchLimit uint64) uint32 {
	if headerBatchLimit == 0 {
		headerBatchLimit = 512
	}
	return uint32(headerBatchLimit * consensus.BLOCK_HEADER_BYTES)
}

func postHandshakePayloadCap(locatorLimit int, headerBatchLimit uint64) payloadLimitFn {
	return func(command string) uint32 {
		switch command {
		case messageVersion:
			return versionPayloadBytes
		case messageVerAck, messageGetAddr, messagePing, messagePong:
			return 0
		case messageInv, messageGetData:
			return inventoryPayloadCap()
		case messageAddr:
			return addrPayloadCap()
		case messageGetBlk:
			return getBlocksPayloadCap(locatorLimit)
		case messageHeaders:
			return headersPayloadCap(headerBatchLimit)
		case messageBlock, messageTx:
			return uint32(consensus.MAX_BLOCK_BYTES)
		default:
			return 0
		}
	}
}
