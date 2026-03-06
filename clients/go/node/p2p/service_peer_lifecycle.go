package p2p

import (
	"net"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/node"
)

func (s *Service) runConn(conn net.Conn) {
	defer s.loopWG.Done()
	s.handleConn(conn)
}

func (s *Service) handleConn(conn net.Conn) {
	defer func() {
		if conn != nil {
			_ = conn.Close()
		}
	}()

	localVersion, err := s.localVersion()
	if err != nil {
		return
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
		return
	}

	current := &peer{
		conn:    conn,
		service: s,
		state:   state,
	}
	if err := s.registerPeer(current); err != nil {
		return
	}
	defer s.unregisterPeer(current.addr())

	s.cfg.SyncEngine.RecordBestKnownHeight(state.RemoteVersion.BestHeight)
	if err := s.requestBlocksIfBehind(current); err != nil {
		current.setLastError(err.Error())
		return
	}
	if err := current.run(s.ctx); err != nil && s.ctx.Err() == nil {
		current.setLastError(err.Error())
		return
	}
}

func (s *Service) registerPeer(p *peer) error {
	if err := s.cfg.PeerManager.AddPeer(&p.state); err != nil {
		return err
	}
	s.peersMu.Lock()
	defer s.peersMu.Unlock()
	s.peers[p.addr()] = p
	return nil
}

func (s *Service) unregisterPeer(addr string) {
	s.peersMu.Lock()
	delete(s.peers, addr)
	s.peersMu.Unlock()
	s.cfg.PeerManager.RemovePeer(addr)
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
		Magic:           ProtocolMagic,
		ProtocolVersion: ProtocolVersion,
		ChainID:         s.cfg.SyncConfig.ChainID,
		GenesisHash:     s.cfg.GenesisHash,
		UserAgent:       s.cfg.UserAgent,
		BestHeight:      bestHeight,
	}, nil
}
