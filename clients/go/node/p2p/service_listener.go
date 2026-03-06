package p2p

import (
	"context"
	"errors"
	"net"
	"strings"
)

func (s *Service) Start(ctx context.Context) error {
	if s == nil {
		return errors.New("nil service")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if s.listener != nil {
		return errors.New("service already started")
	}
	listener, err := net.Listen("tcp", s.cfg.BindAddr)
	if err != nil {
		return err
	}
	s.listener = listener
	s.ctx, s.cancel = context.WithCancel(ctx)

	go s.acceptLoop()
	for _, peerAddr := range s.cfg.BootstrapPeers {
		peerAddr = strings.TrimSpace(peerAddr)
		if peerAddr == "" {
			continue
		}
		go s.dialPeer(peerAddr)
	}
	return nil
}

func (s *Service) Close() error {
	if s == nil {
		return nil
	}
	if s.cancel != nil {
		s.cancel()
	}
	if s.listener != nil {
		_ = s.listener.Close()
	}
	s.peersMu.RLock()
	peers := make([]*peer, 0, len(s.peers))
	for _, current := range s.peers {
		peers = append(peers, current)
	}
	s.peersMu.RUnlock()
	for _, current := range peers {
		_ = current.conn.Close()
	}
	return nil
}

func (s *Service) Addr() string {
	if s == nil {
		return ""
	}
	if s.listener != nil {
		return s.listener.Addr().String()
	}
	return s.cfg.BindAddr
}

func (s *Service) acceptLoop() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			if s.ctx != nil && s.ctx.Err() != nil {
				return
			}
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		go s.handleConn(conn)
	}
}

func (s *Service) dialPeer(addr string) {
	dialer := &net.Dialer{Timeout: s.cfg.PeerRuntimeConfig.HandshakeTimeout}
	conn, err := dialer.DialContext(s.ctx, "tcp", addr)
	if err != nil {
		return
	}
	s.handleConn(conn)
}
