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

	s.loopWG.Add(1)
	go s.acceptLoop()
	s.loopWG.Add(1)
	go s.reconnectLoop(s.ctx)
	for _, peerAddr := range s.outboundAddrs {
		peerAddr = strings.TrimSpace(peerAddr)
		if peerAddr == "" {
			continue
		}
		s.startOutboundDial(peerAddr)
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
	s.loopWG.Wait()
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
	defer s.loopWG.Done()
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
		s.loopWG.Add(1)
		go s.runConn(conn)
	}
}

func (s *Service) dialPeer(addr string) {
	defer s.loopWG.Done()
	defer s.finishDial(addr)
	if s == nil {
		return
	}
	ctx := s.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	dialer := &net.Dialer{Timeout: s.cfg.PeerRuntimeConfig.HandshakeTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		s.recordDialFailure(addr)
		return
	}
	if err := s.handleConn(conn, addr); err != nil && s.ctx != nil && s.ctx.Err() == nil {
		s.recordDialFailure(addr)
	}
}

func (s *Service) startOutboundDial(addr string) bool {
	addr, ok := s.normalizedDialAddr(addr)
	if !ok || s.isConnected(addr) || !s.beginDial(addr) {
		return false
	}
	s.loopWG.Add(1)
	go s.dialPeer(addr)
	return true
}

func (s *Service) beginDial(addr string) bool {
	return s.withTrackedDialAddr(addr, func(addr string) bool {
		if _, exists := s.dialing[addr]; exists {
			return false
		}
		s.dialing[addr] = struct{}{}
		return true
	})
}

func (s *Service) finishDial(addr string) {
	addr, ok := s.normalizedDialAddr(addr)
	if !ok {
		return
	}
	s.dialingMu.Lock()
	delete(s.dialing, addr)
	s.dialingMu.Unlock()
}

func (s *Service) isDialing(addr string) bool {
	return s.withTrackedDialAddr(addr, func(addr string) bool {
		_, exists := s.dialing[addr]
		return exists
	})
}

func (s *Service) normalizedDialAddr(addr string) (string, bool) {
	if s == nil {
		return "", false
	}
	addr = normalizeDialTarget(addr)
	if addr == "" {
		return "", false
	}
	return addr, true
}

func (s *Service) withDialingState(addr string, fn func() bool) bool {
	s.dialingMu.Lock()
	defer s.dialingMu.Unlock()
	return fn()
}

func (s *Service) withTrackedDialAddr(addr string, fn func(string) bool) bool {
	addr, ok := s.normalizedDialAddr(addr)
	if !ok {
		return false
	}
	return s.withDialingState(addr, func() bool {
		return fn(addr)
	})
}

func (s *Service) pendingDialCount() int {
	if s == nil {
		return 0
	}
	s.dialingMu.Lock()
	defer s.dialingMu.Unlock()
	return len(s.dialing)
}
