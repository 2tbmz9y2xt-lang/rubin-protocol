package p2p

import (
	"net"
	"net/netip"
	"strings"
)

var discoveredAddrSpecialUsePrefixes = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("2001:db8::/32"),
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
	limit := s.cfg.PeerRuntimeConfig.MaxPeers
	for _, addr := range normalizePeerAddrs(addrs) {
		if !shouldDialDiscoveredAddr(addr, s.cfg.PeerRuntimeConfig.Network) {
			continue
		}
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

func shouldDialDiscoveredAddr(addr string, network string) bool {
	if addr == "" {
		return false
	}
	if normalizedDiscoveryNetwork(network) == "devnet" {
		return true
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return isDialableDiscoveredIP(ip)
}

func normalizedDiscoveryNetwork(network string) string {
	network = strings.ToLower(strings.TrimSpace(network))
	if network == "" {
		return "devnet"
	}
	return network
}

func isDialableDiscoveredIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() {
		return false
	}
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	addr = addr.Unmap()
	if !addr.IsValid() || !addr.IsGlobalUnicast() {
		return false
	}
	for _, prefix := range discoveredAddrSpecialUsePrefixes {
		if prefix.Contains(addr) {
			return false
		}
	}
	return true
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
