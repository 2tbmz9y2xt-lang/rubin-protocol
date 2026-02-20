package p2p

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"unicode"

	"rubin.dev/node/crypto"
)

const (
	// TransportPrefixBytes is the fixed header length for every P2P message.
	TransportPrefixBytes = 24
	CommandBytes         = 12

	// MaxRelayMsgBytes is the maximum permitted payload length.
	// Spec: spec/RUBIN_L1_P2P_PROTOCOL_v1.1.md §1.2.
	MaxRelayMsgBytes = 8_388_608
)

type Message struct {
	Magic   uint32
	Command string
	Payload []byte
}

// ReadError conveys how the caller should treat a malformed P2P message.
// This is a policy surface for P2P; it must remain stable and testable.
type ReadError struct {
	Err           error
	BanScoreDelta int  // +10 checksum/parse errors, +20 truncation, etc.
	Disconnect    bool // true for magic mismatch / oversize / truncation
}

func (e *ReadError) Error() string {
	if e == nil || e.Err == nil {
		return ""
	}
	return e.Err.Error()
}

func checksum4(p crypto.CryptoProvider, payload []byte) ([4]byte, error) {
	d, err := p.SHA3_256(payload)
	if err != nil {
		return [4]byte{}, err
	}
	var out [4]byte
	copy(out[:], d[:4])
	return out, nil
}

func encodeCommand(cmd string) ([CommandBytes]byte, error) {
	var out [CommandBytes]byte
	if cmd == "" {
		return out, fmt.Errorf("p2p: empty command")
	}
	if len(cmd) > CommandBytes {
		return out, fmt.Errorf("p2p: command too long")
	}
	for i := 0; i < len(cmd); i++ {
		c := cmd[i]
		// Command is ASCII; reject control chars and non-ASCII.
		if c >= 0x80 || c == 0x00 || !unicode.IsPrint(rune(c)) {
			return out, fmt.Errorf("p2p: command contains non-printable ASCII")
		}
		out[i] = c
	}
	// Remaining bytes are already zero (right padding).
	return out, nil
}

func decodeCommand(b [CommandBytes]byte) (string, error) {
	// Find first NUL; after that all bytes must be NUL (right padding).
	n := CommandBytes
	for i := 0; i < CommandBytes; i++ {
		if b[i] == 0x00 {
			n = i
			break
		}
	}
	for i := n; i < CommandBytes; i++ {
		if b[i] != 0x00 {
			return "", fmt.Errorf("p2p: command not NUL-right-padded")
		}
	}
	cmd := string(b[:n])
	if cmd == "" {
		return "", fmt.Errorf("p2p: empty command")
	}
	for i := 0; i < len(cmd); i++ {
		c := cmd[i]
		if c >= 0x80 || c == 0x00 || !unicode.IsPrint(rune(c)) {
			return "", fmt.Errorf("p2p: command contains non-printable ASCII")
		}
	}
	return cmd, nil
}

// WriteMessage writes a single P2P message to w.
func WriteMessage(w io.Writer, p crypto.CryptoProvider, magic uint32, command string, payload []byte) error {
	if p == nil {
		return fmt.Errorf("p2p: nil crypto provider")
	}
	cmd12, err := encodeCommand(command)
	if err != nil {
		return err
	}
	if uint64(len(payload)) > MaxRelayMsgBytes {
		return fmt.Errorf("p2p: payload too large")
	}
	c4, err := checksum4(p, payload)
	if err != nil {
		return err
	}

	var hdr [TransportPrefixBytes]byte
	binary.BigEndian.PutUint32(hdr[0:4], magic)
	copy(hdr[4:16], cmd12[:])
	binary.LittleEndian.PutUint32(hdr[16:20], uint32(len(payload)))
	copy(hdr[20:24], c4[:])

	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	if len(payload) == 0 {
		return nil
	}
	_, err = w.Write(payload)
	return err
}

// ReadMessage reads exactly one P2P message from r. It handles partial reads.
//
// Semantics (spec/RUBIN_L1_P2P_PROTOCOL_v1.1.md §1):
// - magic mismatch => disconnect, not ban-worthy
// - oversize payload_length => disconnect immediately
// - checksum mismatch => drop message (+10 ban), do not disconnect
// - truncation / length mismatch => disconnect (+20 ban)
func ReadMessage(r io.Reader, p crypto.CryptoProvider, expectedMagic uint32) (*Message, *ReadError) {
	if p == nil {
		return nil, &ReadError{Err: fmt.Errorf("p2p: nil crypto provider"), BanScoreDelta: 0, Disconnect: true}
	}

	var hdr [TransportPrefixBytes]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		// EOF while reading prefix: treat as disconnect without ban (connection died).
		return nil, &ReadError{Err: err, BanScoreDelta: 0, Disconnect: true}
	}

	magic := binary.BigEndian.Uint32(hdr[0:4])
	if magic != expectedMagic {
		return nil, &ReadError{Err: fmt.Errorf("p2p: magic mismatch"), BanScoreDelta: 0, Disconnect: true}
	}

	var cmdBytes [CommandBytes]byte
	copy(cmdBytes[:], hdr[4:16])
	cmd, err := decodeCommand(cmdBytes)
	if err != nil {
		return nil, &ReadError{Err: err, BanScoreDelta: 10, Disconnect: false}
	}

	payloadLen := binary.LittleEndian.Uint32(hdr[16:20])
	if payloadLen > MaxRelayMsgBytes {
		// Do not attempt to read attacker-controlled payload length.
		return nil, &ReadError{Err: fmt.Errorf("p2p: payload_length exceeds MAX_RELAY_MSG_BYTES"), BanScoreDelta: 0, Disconnect: true}
	}

	var expectedC4 [4]byte
	copy(expectedC4[:], hdr[20:24])

	payload := make([]byte, int(payloadLen))
	if payloadLen > 0 {
		if _, err := io.ReadFull(r, payload); err != nil {
			// Declared length but stream ended.
			return nil, &ReadError{Err: err, BanScoreDelta: 20, Disconnect: true}
		}
	}

	computedC4, err := checksum4(p, payload)
	if err != nil {
		return nil, &ReadError{Err: err, BanScoreDelta: 0, Disconnect: true}
	}
	if !bytes.Equal(expectedC4[:], computedC4[:]) {
		return nil, &ReadError{Err: fmt.Errorf("p2p: checksum mismatch"), BanScoreDelta: 10, Disconnect: false}
	}

	return &Message{Magic: magic, Command: cmd, Payload: payload}, nil
}

