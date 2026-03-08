package p2p

import (
	"net"
	"slices"
	"strings"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/node"
)

func (s *Service) runConn(conn net.Conn) {
	defer s.loopWG.Done()
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
	if err := s.requestBlocksIfBehind(current); err != nil {
		current.setLastError(err.Error())
		return err
	}
	if err := current.send(messageGetAddr, nil); err != nil {
		current.setLastError(err.Error())
	}
	if err := current.run(s.ctx); err != nil && s.ctx.Err() == nil {
		current.setLastError(err.Error())
		return err
	}
	return nil
}

func (s *Service) registerPeer(p *peer) error {
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
	remove := false
	s.peersMu.Lock()
	for key, current := range s.peers {
		if current != p {
			continue
		}
		delete(s.peers, key)
		remove = true
	}
	s.peersMu.Unlock()
	if remove {
		s.cfg.PeerManager.RemovePeer(addr)
	}
	if remove && s.isOutboundAddr(addr) {
		s.scheduleReconnect(addr)
	}
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
