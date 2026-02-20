package p2p

import (
	"encoding/binary"
	"fmt"
)

type PingPayload struct {
	Nonce uint64
}

func EncodePingPayload(p PingPayload) ([]byte, error) {
	var out [8]byte
	binary.LittleEndian.PutUint64(out[:], p.Nonce)
	return out[:], nil
}

func DecodePingPayload(b []byte) (*PingPayload, error) {
	if len(b) != 8 {
		return nil, fmt.Errorf("p2p: ping: invalid payload length")
	}
	return &PingPayload{Nonce: binary.LittleEndian.Uint64(b)}, nil
}

type PongPayload struct {
	Nonce uint64
}

func EncodePongPayload(p PongPayload) ([]byte, error) {
	return EncodePingPayload(PingPayload{Nonce: p.Nonce})
}

func DecodePongPayload(b []byte) (*PongPayload, error) {
	pp, err := DecodePingPayload(b)
	if err != nil {
		return nil, fmt.Errorf("p2p: pong: %w", err)
	}
	return &PongPayload{Nonce: pp.Nonce}, nil
}
