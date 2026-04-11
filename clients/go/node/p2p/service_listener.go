package p2p

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

// Non-terminal Accept errors (e.g. EMFILE on transient file-descriptor
// exhaustion) are retried with an exponential backoff capped at
// acceptErrorBackoffCap. The constants mirror rubin-node Rust
// ACCEPT_ERROR_BACKOFF_INIT / ACCEPT_ERROR_BACKOFF_CAP for cross-client
// behavioural parity; see
// clients/rust/crates/rubin-node/src/p2p_service.rs.
const (
	acceptErrorBackoffInit = 100 * time.Millisecond
	acceptErrorBackoffCap  = 5 * time.Second
)

// nextAcceptErrorBackoff doubles current, capped at acceptErrorBackoffCap.
// A non-positive current resets to acceptErrorBackoffInit. The helper is
// pure so tests can exhaustively verify the progression without touching a
// real listener.
func nextAcceptErrorBackoff(current time.Duration) time.Duration {
	if current <= 0 {
		return acceptErrorBackoffInit
	}
	next := current * 2
	if next > acceptErrorBackoffCap {
		return acceptErrorBackoffCap
	}
	return next
}

// isAcceptLoopTerminal reports whether an Accept error should exit the
// accept loop. Terminal conditions are: the service context has been
// cancelled (Close path), or the listener has been closed.
func isAcceptLoopTerminal(ctx context.Context, err error) bool {
	if ctx != nil && ctx.Err() != nil {
		return true
	}
	if errors.Is(err, net.ErrClosed) {
		return true
	}
	return false
}

func (s *Service) Start(ctx context.Context) error {
	if s == nil {
		return errors.New("nil service")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	s.peersMu.RLock()
	started := s.listener != nil
	s.peersMu.RUnlock()
	if started {
		return errors.New("service already started")
	}
	listener, err := net.Listen("tcp", s.cfg.BindAddr)
	if err != nil {
		return err
	}
	s.peersMu.Lock()
	s.listener = listener
	s.peersMu.Unlock()
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
	s.peersMu.RLock()
	ln := s.listener
	s.peersMu.RUnlock()
	if ln != nil {
		return ln.Addr().String()
	}
	return s.cfg.BindAddr
}

func (s *Service) acceptLoop() {
	defer s.loopWG.Done()
	errorBackoff := acceptErrorBackoffInit
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			if isAcceptLoopTerminal(s.ctx, err) {
				return
			}
			// Non-terminal Accept error (e.g. EMFILE, ENFILE, transient
			// socket failure). Log a diagnostic, sleep with the current
			// backoff, then double it for the next occurrence (capped at
			// acceptErrorBackoffCap). Mirrors rubin-node Rust
			// run_accept_loop; prevents a hot-loop that previously would
			// spin on a bare `continue` and drown the process.
			fmt.Fprintf(os.Stderr,
				"p2p: accept error on %s: %v (sleeping %s before retry)\n",
				s.cfg.BindAddr, err, errorBackoff)
			if !s.sleepOrStop(errorBackoff) {
				return
			}
			errorBackoff = nextAcceptErrorBackoff(errorBackoff)
			continue
		}
		errorBackoff = acceptErrorBackoffInit
		if !s.tryAcquireHandshakeSlot() {
			_ = conn.Close()
			continue
		}
		s.loopWG.Add(1)
		go s.runConn(conn, true)
	}
}

// sleepOrStop sleeps for d unless the service context is cancelled first.
// Returns true if the full sleep elapsed, false if cancellation unblocked
// the sleep (callers treat false as "exit the loop"). A non-positive d or
// nil receiver/context falls back to the obvious no-op or unconditional
// time.Sleep respectively so callers never need to branch themselves.
func (s *Service) sleepOrStop(d time.Duration) bool {
	if d <= 0 {
		return true
	}
	if s == nil || s.ctx == nil {
		time.Sleep(d)
		return true
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-s.ctx.Done():
		return false
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
