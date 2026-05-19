package p2p

import (
	"encoding/binary"
	"errors"
)

const (
	maxHighBandwidthCompactPeers = 3
	defaultCompactPeerScore      = 50
	compactModeOneScore          = 40
	compactModeTwoScore          = 75
)

type compactModeSnapshot struct {
	Mode    uint8
	Version uint64
}

type peerCompactRelayState struct {
	localMode  compactModeSnapshot
	remoteMode compactModeSnapshot
	score      int
	scoreSet   bool
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
	if out.Mode > 2 {
		return sendCmpctPayload{}, errors.New("unsupported compact relay mode")
	}
	return out, nil
}

func (s *Service) advertiseCompactRelayMode(p *peer) error {
	if p == nil || !s.compactRelayReady() {
		return nil
	}
	s.compactMu.Lock()
	defer s.compactMu.Unlock()

	mode := desiredCompactMode(s.cfg.CompactRelayMode, p.compactScore())
	if mode == 2 && p.localCompactMode().Mode != 2 && s.localCompactModeCount(2) >= maxHighBandwidthCompactPeers {
		mode = 1
	}
	return p.sendLocalCompactMode(mode)
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

func (s *Service) localCompactModeCount(mode uint8) int {
	s.peersMu.RLock()
	defer s.peersMu.RUnlock()
	seen := make(map[*peer]struct{}, len(s.peers))
	count := 0
	for _, p := range s.peers {
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		if p.localCompactMode().Mode == mode {
			count++
		}
	}
	return count
}

func desiredCompactMode(configured uint8, score int) uint8 {
	if configured == 0 || score < compactModeOneScore {
		return 0
	}
	if configured >= 2 && score >= compactModeTwoScore {
		return 2
	}
	return 1
}

func (p *peer) sendLocalCompactMode(mode uint8) error {
	if p.localCompactMode().Mode == mode {
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

func (p *peer) setCompactQualityScore(score int) {
	p.compactMu.Lock()
	p.compact.score = score
	p.compact.scoreSet = true
	p.compactMu.Unlock()
}

func (p *peer) compactScore() int {
	p.compactMu.Lock()
	defer p.compactMu.Unlock()
	if !p.compact.scoreSet {
		return defaultCompactPeerScore
	}
	return p.compact.score
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
