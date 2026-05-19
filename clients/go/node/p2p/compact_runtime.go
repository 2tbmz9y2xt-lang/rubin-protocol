package p2p

import (
	"encoding/binary"
	"errors"
)

type compactModeSnapshot struct {
	Mode    uint8
	Version uint64
}

type peerCompactRelayState struct {
	remoteMode compactModeSnapshot
}

func (p *peer) handleSendCmpct(payload []byte) error {
	msg, err := parseSendCmpctRuntimePayload(payload)
	if err != nil {
		return err
	}
	p.setRemoteCompactMode(compactModeSnapshot{Mode: msg.Mode, Version: msg.Version})
	return nil
}

func parseSendCmpctRuntimePayload(payload []byte) (sendCmpctPayload, error) {
	if len(payload) != sendCmpctPayloadBytes {
		return sendCmpctPayload{}, errors.New("sendcmpct payload width mismatch")
	}
	out := sendCmpctPayload{Mode: payload[0], Version: binary.LittleEndian.Uint64(payload[1:])}
	if out.Version != compactRelayVersion {
		return sendCmpctPayload{}, errors.New("unsupported compact relay version")
	}
	if out.Mode > 2 {
		return sendCmpctPayload{}, errors.New("unsupported compact relay mode")
	}
	return out, nil
}

func (p *peer) setRemoteCompactMode(mode compactModeSnapshot) {
	p.compactMu.Lock()
	p.compact.remoteMode = mode
	p.compactMu.Unlock()
}

func (p *peer) remoteCompactMode() compactModeSnapshot {
	p.compactMu.Lock()
	defer p.compactMu.Unlock()
	return p.compact.remoteMode
}
