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

	var remote net.Addr
	if conn != nil {
		remote = conn.RemoteAddr()
	}
	daQuotaIdentity, _ := daQuotaIdentityForEndpoint(remote)
	current := &peer{
		conn:            conn,
		service:         s,
		state:           state,
		qualityScore:    qualityScoreInitial,
		qualityHeight:   s.cfg.SyncEngine.LocalTipHeight(),
		daQuotaIdentity: daQuotaIdentity,
	}
	current.state.Addr = peerAddressKey(outboundAddr, current.state.Addr)
	if err := s.registerPeer(current); err != nil {
		return err
	}
	defer current.releaseCompactOutstandingLease() // runs after finishBlockRetry: a released charge wakes retry slots waiting on the budget
	defer s.unregisterPeer(current)
	defer current.finishBlockRetry() // runs first: the retry waiter is joined before unregistration

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
	if quotaKey := p.daQuotaIdentity; quotaKey != "" {
		unlockQuota := s.lockPeerQuotaKey(quotaKey)
		defer unlockQuota()
	}
	addr := p.addr()
	// One peersMu section admits p to the PeerManager and, only on success, makes it the owner of
	// its logical address (the newest registration replaces an older one) and installs its alias
	// unless that key is another connection's logical address.
	s.peersMu.Lock()
	if err := s.cfg.PeerManager.AddPeer(&p.state); err != nil {
		s.peersMu.Unlock()
		return err
	}
	s.peerRegistrations++
	p.registrationOrder = s.peerRegistrations
	if s.livePeers == nil {
		s.livePeers = make(map[*peer]struct{})
	}
	s.livePeers[p] = struct{}{}
	s.peers[addr] = p
	if p.conn != nil {
		if alias := normalizeNetAddr(p.conn.RemoteAddr().String()); alias != "" && alias != addr {
			if holder := s.peers[alias]; holder == nil || holder.addr() != alias {
				s.peers[alias] = p
			}
		}
	}
	s.peersMu.Unlock()
	s.resetReconnect(addr)
	return nil
}

func (s *Service) unregisterPeer(p *peer) {
	if s == nil || p == nil {
		return
	}
	addr := p.addr()
	// An empty daQuotaIdentity (no IP endpoint) never owned DA quota: no key lock, no lock row, no
	// DA cleanup; ordinary removal still happens exactly once.
	quotaKey := p.daQuotaIdentity
	if quotaKey != "" {
		unlockQuota := s.lockPeerQuotaKey(quotaKey)
		defer unlockQuota()
	}
	remove := s.removePeerEntries(p, addr)
	if remove {
		if err := s.releaseDAQuotaIfInactiveLocked(quotaKey); err != nil {
			p.setLastError(err.Error())
		}
	}
	if remove {
		// Lifecycle-exit counter increments here, exactly once per
		// exiting live connection (removePeerEntries ended its
		// liveness). Repeat calls on the same already-removed
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

// livePeersLocked returns the live connections (R5): the registered set together with any
// connection still referenced by Service.peers (fixtures that insert there directly; in
// production the two coincide). The caller holds peersMu.
func (s *Service) livePeersLocked() map[*peer]struct{} {
	live := make(map[*peer]struct{}, len(s.livePeers)+len(s.peers))
	for current := range s.livePeers {
		live[current] = struct{}{}
	}
	for _, current := range s.peers {
		if current != nil {
			live[current] = struct{}{}
		}
	}
	return live
}

// removePeerEntries ends p's liveness and, in the same peersMu section, deletes its Service.peers
// entries and applies its PeerManager effect for its logical address addr; it reports whether p
// was live, so a connection's exit takes effect exactly once. Only the logical owner has a
// PeerManager effect: it hands addr to the live connection with the same logical address and
// the highest registration order (publishing its current state), or removes addr when none is
// left; a replaced connection's exit leaves the PeerManager untouched.
func (s *Service) removePeerEntries(p *peer, addr string) bool {
	s.peersMu.Lock()
	defer s.peersMu.Unlock()
	_, live := s.livePeersLocked()[p]
	owner := s.peers[addr] == p
	for key, current := range s.peers {
		if current == p {
			delete(s.peers, key)
		}
	}
	delete(s.livePeers, p)
	if !owner {
		return live
	}
	var successor *peer
	for current := range s.livePeersLocked() {
		if current.addr() == addr && (successor == nil || current.registrationOrder > successor.registrationOrder) {
			successor = current
		}
	}
	if successor == nil {
		s.cfg.PeerManager.RemovePeer(addr)
		return live
	}
	s.peers[addr] = successor
	state := successor.snapshotState()
	_ = s.cfg.PeerManager.UpsertPeer(&state)
	return live
}

// publishPeerStateIfOwner publishes p's current state to the PeerManager only while p is the
// logical owner of its address; the owner check and the state snapshot are taken under peersMu in
// the same step as the UpsertPeer, so a replaced or removed connection never overwrites or
// recreates another connection's entry and a handover is not followed by an older snapshot taken
// before it.
func (s *Service) publishPeerStateIfOwner(p *peer) {
	s.peersMu.RLock()
	defer s.peersMu.RUnlock()
	if state := p.snapshotState(); s.peers[state.Addr] == p {
		_ = s.cfg.PeerManager.UpsertPeer(&state)
	}
}

func (s *Service) releaseDAQuotaIfInactive(quotaKey string) error {
	if quotaKey == "" {
		return nil
	}
	unlockQuota := s.lockPeerQuotaKey(quotaKey)
	defer unlockQuota()
	return s.releaseDAQuotaIfInactiveLocked(quotaKey)
}

// releaseDAQuotaIfInactiveLocked releases the retained incomplete DA data owned
// by quotaKey once no live peer still holds that key, under the caller's per-key
// peer quota lock. An empty quotaKey is no DA quota identity and is refused with no
// node call.
//
// The release is best-effort cleanup, so an already-latched engine skips it. If
// a latch lands after this check, the shared admission fence returns unavailable
// before retained-state access; an ordinary transition still serializes the
// cleanup. TerminalFaulted() is nil-safe by its own
// documented contract, and no constructed Service reaches this gate with a
// nil engine: validateServiceConfig rejects a nil SyncEngine.
func (s *Service) releaseDAQuotaIfInactiveLocked(quotaKey string) error {
	if quotaKey == "" || s.daRelay == nil {
		return nil
	}
	s.peersMu.RLock()
	active := s.hasActivePeerQuotaKeyLocked(quotaKey)
	s.peersMu.RUnlock()
	if active || s.cfg.SyncEngine.TerminalFaulted() {
		return nil
	}
	return s.daRelay.ReleasePeerQuotaKey(quotaKey)
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
	for current := range s.livePeersLocked() {
		if current.daQuotaIdentity == quotaKey {
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
	daMempoolSize, err := s.cfg.SyncEngine.EffectiveDAMempoolSize()
	if err != nil {
		return node.VersionPayloadV1{}, err
	}
	return node.VersionPayloadV1{
		ProtocolVersion:   ProtocolVersion,
		TxRelay:           true,
		PrunedBelowHeight: 0,
		DaMempoolSize:     daMempoolSize,
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
