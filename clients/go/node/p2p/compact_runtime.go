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
	localMode  compactModeSnapshot
	remoteMode compactModeSnapshot
}

func (p *peer) handleSendCmpct(payload []byte) error {
	msg, err := parseSendCmpctRuntimePayload(payload)
	if err != nil {
		return err
	}
	if msg.Version != compactRelayVersion {
		p.setRemoteCompactMode(compactModeSnapshot{Mode: 0, Version: msg.Version})
		return nil
	}
	p.setRemoteCompactMode(compactModeSnapshot{Mode: msg.Mode, Version: msg.Version})
	return nil
}

func parseSendCmpctRuntimePayload(payload []byte) (sendCmpctPayload, error) {
	if len(payload) != sendCmpctPayloadBytes {
		return sendCmpctPayload{}, errors.New("sendcmpct payload width mismatch")
	}
	out := sendCmpctPayload{Mode: payload[0], Version: binary.LittleEndian.Uint64(payload[1:])}
	if out.Version == compactRelayVersion && out.Mode > 2 {
		return sendCmpctPayload{}, errors.New("unsupported compact relay mode")
	}
	return out, nil
}

func (s *Service) advertiseCompactRelayMode(p *peer) error {
	if p == nil || !s.compactRelayReady() || !s.canAdvertiseCompactRelay(p) {
		return nil
	}
	return p.sendLocalCompactMode(0)
}

func (s *Service) compactRelayReady() bool {
	if s == nil || s.cfg.CompactRelayMode == 0 || s.cfg.Now == nil || s.cfg.SyncEngine == nil {
		return false
	}
	now := s.cfg.Now().Unix()
	if now < 0 {
		return false
	}
	return !s.cfg.SyncEngine.IsInIBD(uint64(now)) // #nosec G115 -- negative Unix times are rejected above.
}

func (s *Service) canAdvertiseCompactRelay(p *peer) bool {
	return s.cfg.CompactRelayPeerOK != nil && s.cfg.CompactRelayPeerOK(p.snapshotState())
}

func (p *peer) sendLocalCompactMode(mode uint8) error {
	current := p.localCompactMode()
	if current.Mode == mode && current.Version == compactRelayVersion {
		return nil
	}
	payload, err := encodeSendCmpctPayload(sendCmpctPayload{Mode: mode, Version: compactRelayVersion})
	if err != nil {
		return err
	}
	if err := p.send(messageSendCmpct, payload); err != nil {
		return err
	}
	p.setLocalCompactMode(compactModeSnapshot{Mode: mode, Version: compactRelayVersion})
	return nil
}

func (p *peer) setRemoteCompactMode(mode compactModeSnapshot) {
	p.compactMu.Lock()
	p.compact.remoteMode = mode
	p.compactMu.Unlock()
}

func (p *peer) setLocalCompactMode(mode compactModeSnapshot) {
	p.compactMu.Lock()
	p.compact.localMode = mode
	p.compactMu.Unlock()
}

func (p *peer) localCompactMode() compactModeSnapshot {
	p.compactMu.Lock()
	defer p.compactMu.Unlock()
	return p.compact.localMode
}

func (p *peer) remoteCompactMode() compactModeSnapshot {
	p.compactMu.Lock()
	defer p.compactMu.Unlock()
	return p.compact.remoteMode
}
