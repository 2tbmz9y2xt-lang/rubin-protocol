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
	for _, addr := range normalizePeerAddrs(addrs) {
		if !s.shouldDialDiscoveredAddr(addr) {
			continue
		}
		s.addrMgr.MarkAttempted(addr)
		if !s.startDiscoveredDial(addr) {
			if s.discoveredDialBudget() == 0 {
				return
			}
		}
	}
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

func (s *Service) shouldDialDiscoveredAddr(addr string) bool {
	if s == nil || addr == "" {
		return false
	}
	return !s.isConnected(addr) && !s.isDialing(addr)
}

func (s *Service) discoveredDialBudget() int {
	if s == nil {
		return 0
	}
	available := s.cfg.PeerRuntimeConfig.MaxPeers - s.connectedPeerCount() - s.pendingDialCount()
	if available <= 0 {
		return 0
	}
	if available > maxDiscoveredDialFanout {
		return maxDiscoveredDialFanout
	}
	return available
}

func (s *Service) startDiscoveredDial(addr string) bool {
	addr, ok := s.reserveDiscoveredDial(addr)
	if !ok {
		return false
	}
	s.loopWG.Add(1)
	go s.dialPeer(addr)
	return true
}

func (s *Service) reserveDiscoveredDial(addr string) (string, bool) {
	addr, ok := s.normalizedDialAddr(addr)
	if !ok {
		return "", false
	}
	s.peersMu.RLock()
	_, connected := s.peers[addr]
	connectedCount := len(s.peers)
	s.peersMu.RUnlock()
	if connected {
		return "", false
	}

	s.dialingMu.Lock()
	defer s.dialingMu.Unlock()
	if _, exists := s.dialing[addr]; exists {
		return "", false
	}
	available := s.cfg.PeerRuntimeConfig.MaxPeers - connectedCount - len(s.dialing)
	if available <= 0 || len(s.dialing) >= maxDiscoveredDialFanout {
		return "", false
	}
	s.dialing[addr] = struct{}{}
	return addr, true
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
