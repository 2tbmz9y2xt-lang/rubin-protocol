package p2p

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
		if !shouldAdvertiseAddr(addr, self, connected, banned) {
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
	limit := s.cfg.PeerRuntimeConfig.MaxPeers
	for _, addr := range normalizePeerAddrs(addrs) {
		if s.isConnected(addr) {
			continue
		}
		if !s.tryTrackDiscoveredDial(addr, limit) {
			continue
		}
		s.addrMgr.MarkAttempted(addr)
		s.loopWG.Add(1)
		go s.dialPeer(addr)
	}
}

func (s *Service) inFlightDialCount() int {
	if s == nil {
		return 0
	}
	s.dialMu.Lock()
	defer s.dialMu.Unlock()
	return len(s.inFlightDial)
}

func shouldAdvertiseAddr(addr string, self string, connected map[string]struct{}, banned map[string]struct{}) bool {
	if addr == "" || addr == self {
		return false
	}
	if _, ok := connected[addr]; ok {
		return false
	}
	if _, ok := banned[addr]; ok {
		return false
	}
	return true
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
