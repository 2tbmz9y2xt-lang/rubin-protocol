package p2p

import (
	"encoding/binary"
	"fmt"
	"unicode/utf8"
)

const (
	ProtocolVersionV1 = 1
	MaxUserAgentBytes = 256
)

type VersionPayload struct {
	ProtocolVersion uint32
	ChainID         [32]byte
	PeerServices    uint64
	Timestamp       uint64
	Nonce           uint64
	UserAgent       string
	StartHeight     uint32
	Relay           bool
}

func EncodeVersionPayload(v VersionPayload) ([]byte, error) {
	if v.ProtocolVersion != ProtocolVersionV1 {
		return nil, fmt.Errorf("p2p: version: unsupported protocol_version")
	}
	if len(v.UserAgent) > MaxUserAgentBytes {
		return nil, fmt.Errorf("p2p: version: user_agent too long")
	}
	if !utf8.ValidString(v.UserAgent) {
		return nil, fmt.Errorf("p2p: version: user_agent must be UTF-8")
	}

	out := make([]byte, 0, 4+32+8+8+8+9+len(v.UserAgent)+4+1)
	var tmp8 [8]byte
	var tmp4 [4]byte

	binary.LittleEndian.PutUint32(tmp4[:], v.ProtocolVersion)
	out = append(out, tmp4[:]...)
	out = append(out, v.ChainID[:]...)
	binary.LittleEndian.PutUint64(tmp8[:], v.PeerServices)
	out = append(out, tmp8[:]...)
	binary.LittleEndian.PutUint64(tmp8[:], v.Timestamp)
	out = append(out, tmp8[:]...)
	binary.LittleEndian.PutUint64(tmp8[:], v.Nonce)
	out = append(out, tmp8[:]...)

	out = append(out, encodeCompactSize(uint64(len(v.UserAgent)))...)
	out = append(out, []byte(v.UserAgent)...)

	binary.LittleEndian.PutUint32(tmp4[:], v.StartHeight)
	out = append(out, tmp4[:]...)

	if v.Relay {
		out = append(out, 1)
	} else {
		out = append(out, 0)
	}

	return out, nil
}

func DecodeVersionPayload(b []byte) (*VersionPayload, error) {
	if len(b) < 4+32+8+8+8+4+1 {
		return nil, fmt.Errorf("p2p: version: truncated")
	}
	off := 0
	proto := binary.LittleEndian.Uint32(b[off : off+4])
	off += 4
	var chainID [32]byte
	copy(chainID[:], b[off:off+32])
	off += 32
	peerServices := binary.LittleEndian.Uint64(b[off : off+8])
	off += 8
	timestamp := binary.LittleEndian.Uint64(b[off : off+8])
	off += 8
	nonce := binary.LittleEndian.Uint64(b[off : off+8])
	off += 8

	uaLenU64, used, err := readCompactSize(b[off:])
	if err != nil {
		return nil, err
	}
	off += used
	if uaLenU64 > MaxUserAgentBytes {
		return nil, fmt.Errorf("p2p: version: user_agent_len exceeds MAX_USER_AGENT_BYTES")
	}
	uaLen := int(uaLenU64)
	if len(b) < off+uaLen+4+1 {
		return nil, fmt.Errorf("p2p: version: truncated user_agent")
	}
	uaBytes := b[off : off+uaLen]
	off += uaLen
	if !utf8.Valid(uaBytes) {
		return nil, fmt.Errorf("p2p: version: user_agent must be UTF-8")
	}
	startHeight := binary.LittleEndian.Uint32(b[off : off+4])
	off += 4
	relayByte := b[off]
	off++
	if relayByte != 0 && relayByte != 1 {
		return nil, fmt.Errorf("p2p: version: relay must be 0 or 1")
	}
	if off != len(b) {
		return nil, fmt.Errorf("p2p: version: trailing bytes")
	}

	return &VersionPayload{
		ProtocolVersion: proto,
		ChainID:         chainID,
		PeerServices:    peerServices,
		Timestamp:       timestamp,
		Nonce:           nonce,
		UserAgent:       string(uaBytes),
		StartHeight:     startHeight,
		Relay:           relayByte == 1,
	}, nil
}
