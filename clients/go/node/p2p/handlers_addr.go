package p2p

func (p *peer) handleGetAddr(payload []byte) error {
	if len(payload) != 0 {
		return nil
	}
	addrs := p.service.discoverableAddrs(maxAddrAdvertise)
	encoded, err := encodeAddrPayload(addrs)
	if err != nil {
		return err
	}
	return p.send(messageAddr, encoded)
}

func (p *peer) handleAddr(payload []byte) error {
	addrs, err := decodeAddrPayload(payload)
	if err != nil {
		return err
	}
	p.service.addrMgr.AddAddrs(addrs)
	p.service.connectDiscoveredAddrs(addrs)
	return nil
}

func (s *Service) discoverableAddrs(max int) []string {
	if s == nil {
		return nil
	}
	candidates := s.addrMgr.GetAddrs(maxKnownAddrs)
	banned := s.bannedPeerSet()
	connected := s.connectedPeerSet()
	self := normalizeNetAddr(s.Addr())
	out := make([]string, 0, max)
	for _, addr := range candidates {
		if addr == "" || addr == self {
			continue
		}
		if _, ok := connected[addr]; ok {
			continue
		}
		if _, ok := banned[addr]; ok {
			continue
		}
		out = append(out, addr)
		if max > 0 && len(out) >= max {
			break
		}
	}
	return out
}

func (s *Service) connectDiscoveredAddrs(addrs []string) {
	if s == nil {
		return
	}
	for _, addr := range addrs {
		addr = normalizeNetAddr(addr)
		if addr == "" || s.isConnected(addr) || s.connectedPeerCount() >= s.cfg.PeerRuntimeConfig.MaxPeers {
			continue
		}
		s.addrMgr.MarkAttempted(addr)
		s.loopWG.Add(1)
		go s.dialPeer(addr)
	}
}

func (s *Service) connectedPeerCount() int {
	if s == nil {
		return 0
	}
	s.peersMu.RLock()
	defer s.peersMu.RUnlock()
	return len(s.peers)
}

func (s *Service) connectedPeerSet() map[string]struct{} {
	s.peersMu.RLock()
	defer s.peersMu.RUnlock()
	out := make(map[string]struct{}, len(s.peers))
	for addr := range s.peers {
		out[normalizeNetAddr(addr)] = struct{}{}
	}
	return out
}

func (s *Service) bannedPeerSet() map[string]struct{} {
	out := make(map[string]struct{})
	if s == nil || s.cfg.PeerManager == nil {
		return out
	}
	for _, state := range s.cfg.PeerManager.Snapshot() {
		if state.BanScore >= s.cfg.PeerRuntimeConfig.BanThreshold {
			out[normalizeNetAddr(state.Addr)] = struct{}{}
		}
	}
	return out
}
