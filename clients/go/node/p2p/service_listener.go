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
		s.startDialPeer(peerAddr)
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
		if !s.tryAcquireHandshakeSlot() {
			_ = conn.Close()
			continue
		}
		s.loopWG.Add(1)
		go s.runConn(conn, true)
	}
}

func (s *Service) dialPeer(addr string) {
	defer s.loopWG.Done()
	defer s.finishDialPeer(addr)
	if s == nil {
		return
	}
	dialer := &net.Dialer{Timeout: s.cfg.PeerRuntimeConfig.HandshakeTimeout}
	conn, err := dialer.DialContext(s.ctx, "tcp", addr)
	if err != nil {
		s.recordDialFailure(addr)
		return
	}
	if !s.tryAcquireHandshakeSlot() {
		_ = conn.Close()
		s.recordDialFailure(addr)
		return
	}
	defer s.releaseHandshakeSlot()
	if err := s.handleConn(conn, addr); err != nil && s.ctx != nil && s.ctx.Err() == nil {
		s.recordDialFailure(addr)
	}
}

func (s *Service) startDialPeer(addr string) bool {
	if !s.trackDialPeer(addr) {
		return false
	}
	s.loopWG.Add(1)
	go s.dialPeer(addr)
	return true
}

func (s *Service) trackDialPeer(addr string) bool {
	return s.trackDial(addr, 0)
}

func (s *Service) tryTrackDiscoveredDial(addr string, limit int) bool {
	return s.trackDial(addr, limit)
}

// trackDial is the shared implementation for trackDialPeer and
// tryTrackDiscoveredDial.  When limit > 0 the total of connected peers
// plus in-flight dials is checked against limit before allowing the dial.
func (s *Service) trackDial(addr string, limit int) bool {
	if s == nil {
		return false
	}
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return false
	}
	s.dialMu.Lock()
	defer s.dialMu.Unlock()
	if _, exists := s.inFlightDial[addr]; exists {
		return false
	}
	if limit > 0 && s.connectedPeerCount()+len(s.inFlightDial) >= limit {
		return false
	}
	s.inFlightDial[addr] = struct{}{}
	return true
}

func (s *Service) finishDialPeer(addr string) {
	if s == nil {
		return
	}
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return
	}
	s.dialMu.Lock()
	delete(s.inFlightDial, addr)
	s.dialMu.Unlock()
}

func (s *Service) tryAcquireHandshakeSlot() bool {
	if s == nil || s.handshakeSlots == nil {
		return true
	}
	select {
	case s.handshakeSlots <- struct{}{}:
		return true
	default:
		return false
	}
}

func (s *Service) releaseHandshakeSlot() {
	if s == nil || s.handshakeSlots == nil {
		return
	}
	select {
	case <-s.handshakeSlots:
	default:
	}
}
