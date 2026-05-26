package p2p

import (
	"net"
	"slices"
	"strings"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/node"
)

func (s *Service) runConn(conn net.Conn, ownsHandshakeSlot bool) {
	defer s.loopWG.Done()
	if ownsHandshakeSlot {
		defer s.releaseHandshakeSlot()
	}
	_ = s.handleConn(conn, "")
}

func (s *Service) handleConn(conn net.Conn, outboundAddr string) error {
	defer func() {
		if conn != nil {
			_ = conn.Close()
		}
	}()

	localVersion, err := s.localVersion()
	if err != nil {
		return err
	}
	state, err := performHandshake(
		s.ctx,
		conn,
		s.cfg.PeerRuntimeConfig,
		localVersion,
		s.cfg.SyncConfig.ChainID,
		s.cfg.GenesisHash,
	)
	if err != nil {
		return err
	}

	current := &peer{
		conn:    conn,
		service: s,
		state:   state,
	}
	current.state.Addr = peerAddressKey(outboundAddr, current.state.Addr)
	if err := s.registerPeer(current); err != nil {
		return err
	}
	defer s.unregisterPeer(current)

	s.cfg.SyncEngine.RecordBestKnownHeight(state.RemoteVersion.BestHeight)
	if err := s.sendPostHandshakeAnnouncements(current); err != nil {
		return err
	}
	if err := current.run(s.ctx); err != nil && s.ctx.Err() == nil {
		current.applyPostHandshakeDisconnectError(err)
		return err
	}
	return nil
}

func (s *Service) sendPostHandshakeAnnouncements(current *peer) error {
	if err := current.advertiseLocalCompactMode(); err != nil {
		current.setLastError(err.Error())
		return err
	}
	if err := s.requestBlocksIfBehind(current); err != nil {
		current.setLastError(err.Error())
		return err
	}
	if err := current.send(messageGetAddr, nil); err != nil {
		current.setLastError(err.Error())
	}
	return nil
}

func (s *Service) registerPeer(p *peer) error {
	unlockQuota := s.lockPeerQuotaKey(peerQuotaKey(p.addr()))
	defer unlockQuota()
	if err := s.cfg.PeerManager.AddPeer(&p.state); err != nil {
		return err
	}
	s.peersMu.Lock()
	s.peers[p.addr()] = p
	if p.conn != nil {
		if alias := normalizeNetAddr(p.conn.RemoteAddr().String()); alias != "" && alias != p.addr() {
			s.peers[alias] = p
		}
	}
	s.peersMu.Unlock()
	s.resetReconnect(p.addr())
	return nil
}

func (s *Service) unregisterPeer(p *peer) {
	if s == nil || p == nil {
		return
	}
	addr := p.addr()
	quotaKey := peerQuotaKey(addr)
	unlockQuota := s.lockPeerQuotaKey(quotaKey)
	defer unlockQuota()
	remove := s.removePeerEntries(p)
	if remove {
		s.cfg.PeerManager.RemovePeer(addr)
		if err := s.releaseDAQuotaIfInactiveLocked(quotaKey); err != nil {
			p.setLastError(err.Error())
		}
	}
	if remove {
		// Lifecycle-exit counter increments here, exactly once per
		// unregisterPeer call that actually deleted peer entries from
		// the s.peers map. Repeat calls on the same already-removed
		// peer leave remove==false above and do not reach this line,
		// so cleanup retries cannot double-count. atomic.Uint64.Add is
		// safe to call without peersMu (the lock has been released
		// above) because the counter is independent of peer-map state.
		s.peerLifecycleExits.Add(1)
	}
	if remove && s.isOutboundAddr(addr) {
		s.scheduleReconnect(addr)
	}
}

func (s *Service) removePeerEntries(p *peer) bool {
	s.peersMu.Lock()
	defer s.peersMu.Unlock()
	remove := false
	for key, current := range s.peers {
		if current == p {
			delete(s.peers, key)
			remove = true
		}
	}
	return remove
}

func (s *Service) releaseDAQuotaIfInactive(quotaKey string) error {
	unlockQuota := s.lockPeerQuotaKey(quotaKey)
	defer unlockQuota()
	return s.releaseDAQuotaIfInactiveLocked(quotaKey)
}

func (s *Service) releaseDAQuotaIfInactiveLocked(quotaKey string) error {
	if s.daRelay == nil {
		return nil
	}
	s.peersMu.RLock()
	active := s.hasActivePeerQuotaKeyLocked(quotaKey)
	s.peersMu.RUnlock()
	if active {
		return nil
	}
	return s.daRelay.releasePeerQuotaKey(quotaKey)
}

func (s *Service) lockPeerQuotaKey(quotaKey string) func() {
	s.peerQuotaLocksMu.Lock()
	if s.peerQuotaLocks == nil {
		s.peerQuotaLocks = make(map[string]*peerQuotaLock)
	}
	quotaLock := s.peerQuotaLocks[quotaKey]
	if quotaLock == nil {
		quotaLock = &peerQuotaLock{}
		s.peerQuotaLocks[quotaKey] = quotaLock
	}
	quotaLock.refs++
	s.peerQuotaLocksMu.Unlock()

	quotaLock.mu.Lock()
	return func() {
		quotaLock.mu.Unlock()
		s.peerQuotaLocksMu.Lock()
		quotaLock.refs--
		if quotaLock.refs == 0 {
			delete(s.peerQuotaLocks, quotaKey)
		}
		s.peerQuotaLocksMu.Unlock()
	}
}

func (s *Service) hasActivePeerQuotaKeyLocked(quotaKey string) bool {
	for _, current := range s.peers {
		if current != nil && peerQuotaKey(current.addr()) == quotaKey {
			return true
		}
	}
	return false
}

// PeerLifecycleExits returns the monotonic count of peer lifecycle
// exits observed by this Service since construction. The counter is
// incremented inside unregisterPeer at the single canonical removal
// boundary; see the field comment on Service.peerLifecycleExits for
// the dedupe contract. Pure atomic.Load — safe to call concurrently
// with unregisterPeer and from /metrics rendering. Returns 0 on a
// nil receiver so scrape callers can read unconditionally.
func (s *Service) PeerLifecycleExits() uint64 {
	if s == nil {
		return 0
	}
	return s.peerLifecycleExits.Load()
}

func peerAddressKey(outboundAddr string, runtimeAddr string) string {
	if addr := normalizeReconnectAddr(outboundAddr); addr != "" {
		return addr
	}
	return normalizeReconnectAddr(runtimeAddr)
}

func (s *Service) localVersion() (node.VersionPayloadV1, error) {
	bestHeight, _, ok, err := s.cfg.BlockStore.Tip()
	if err != nil {
		return node.VersionPayloadV1{}, err
	}
	if !ok {
		bestHeight = 0
	}
	return node.VersionPayloadV1{
		ProtocolVersion:   ProtocolVersion,
		TxRelay:           true,
		PrunedBelowHeight: 0,
		DaMempoolSize:     0,
		ChainID:           s.cfg.SyncConfig.ChainID,
		GenesisHash:       s.cfg.GenesisHash,
		BestHeight:        bestHeight,
		UserAgent:         s.cfg.UserAgent,
	}, nil
}

func (s *Service) isOutboundAddr(addr string) bool {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return false
	}
	s.reconnectMu.Lock()
	defer s.reconnectMu.Unlock()
	return slices.Contains(s.outboundAddrs, addr)
}
