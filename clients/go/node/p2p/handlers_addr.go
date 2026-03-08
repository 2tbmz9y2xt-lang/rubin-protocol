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
	budget := s.discoveredDialBudget()
	for _, addr := range normalizePeerAddrs(addrs) {
		if budget == 0 {
			return
		}
		if !s.shouldDialDiscoveredAddr(addr) {
			continue
		}
		s.addrMgr.MarkAttempted(addr)
		if s.startOutboundDial(addr) {
			budget--
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
