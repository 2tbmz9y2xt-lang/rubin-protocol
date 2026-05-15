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
	"os"

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

type partialFrameTimeoutError struct {
	part string
	read int
	want int
	err  error
}

func (e partialFrameTimeoutError) Error() string {
	return fmt.Sprintf("%s timeout after partial frame read: %d/%d bytes", e.part, e.read, e.want)
}

func (e partialFrameTimeoutError) Unwrap() error {
	return e.err
}

func isPartialFrameTimeout(err error) bool {
	var partial partialFrameTimeoutError
	return errors.As(err, &partial)
}

func isReadTimeout(err error) bool {
	var netErr net.Error
	return errors.Is(err, os.ErrDeadlineExceeded) || (errors.As(err, &netErr) && netErr.Timeout())
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
		n, err := io.ReadFull(r, chunk)
		if err != nil {
			read := wireHeaderSize + len(payload) + n
			if isReadTimeout(err) {
				return nil, partialFrameTimeoutError{part: "payload", read: read, want: wireHeaderSize + int(size), err: err}
			}
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
	n, err := io.ReadFull(r, raw[:])
	if err != nil {
		if isReadTimeout(err) && n > 0 {
			return header, partialFrameTimeoutError{part: "header", read: n, want: wireHeaderSize, err: err}
		}
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
	network, _ = node.CanonicalNetworkName(network)
	// Low-level wire helpers keep a fixed isolation fallback for unknown or
	// custom/private transport names. Validated config flows typically reject
	// unknown names earlier, but runtime normalization is not the rejection point.
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

func encodePayload(encode func(io.Writer) error) ([]byte, error) {
	var buf bytes.Buffer
	if err := encode(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
