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
// behavioral parity; see
// clients/rust/crates/rubin-node/src/p2p_service.rs.
const (
	acceptErrorBackoffInit = 100 * time.Millisecond
	acceptErrorBackoffCap  = 5 * time.Second
)

// serviceStartPostListenHook is a test-only hook. When non-nil, Start invokes
// it after net.Listen succeeds and before the authoritative closed/started
// re-check under peersMu. Tests must install it only in single-threaded
// scenarios and restore it before returning.
var serviceStartPostListenHook func(*Service, net.Listener)

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
// canceled (Close path), or the listener has been closed.
func isAcceptLoopTerminal(ctx context.Context, err error) bool {
	if ctx != nil && ctx.Err() != nil {
		return true
	}
	if errors.Is(err, net.ErrClosed) {
		return true
	}
	return false
}

// Start begins accepting inbound P2P connections and launches the accept /
// reconnect goroutines. A Service instance is single-use: after Close has
// returned, Start must NOT be called again on the same Service — it will
// return "service already closed" rather than silently creating a second
// listener or reviving the shut-down goroutines. Construct a fresh Service
// for a fresh lifecycle.
//
// Lifecycle transitions (dormant → running → closed) are linearized under
// peersMu. The entry check, startWG registration, and the post-net.Listen
// authoritative publish all take the write lock; Close takes the same
// lock to transition closed. This gives two invariants: (1) startWG.Add
// only happens when closed=false, so Close's startWG.Wait cannot race
// a concurrent Add (which would panic sync.WaitGroup), and (2) an
// observed successful Start return implies the Service is running — if
// a concurrent Close ran between net.Listen and the re-check, the
// freshly created listener is closed and Start returns the dormant
// error instead of publishing.
func (s *Service) Start(ctx context.Context) error {
	if s == nil {
		return errors.New("nil service")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	// Register this Start invocation with startWG atomically with the
	// dormant/started check, under the same peersMu that guards closed.
	// This is critical for sync.WaitGroup correctness: Go panics with
	// "Add called concurrently with Wait" if Add transitions the counter
	// from 0 while Wait is running. Close sets s.closed=true under peersMu
	// and then calls startWG.Wait. By taking the write lock here and
	// reading s.closed before calling Add, we guarantee that once Close
	// has published closed=true, no subsequent Start can Add — it will
	// observe closed=true and return without touching startWG.
	s.peersMu.Lock()
	if s.closed {
		s.peersMu.Unlock()
		return errors.New("service already closed")
	}
	if s.listener != nil {
		s.peersMu.Unlock()
		return errors.New("service already started")
	}
	s.startWG.Add(1)
	s.peersMu.Unlock()
	defer s.startWG.Done()

	listener, err := net.Listen("tcp", s.cfg.BindAddr)
	if err != nil {
		return err
	}
	if hook := serviceStartPostListenHook; hook != nil {
		hook(s, listener)
	}

	// Authoritative transition. Re-check closed/started under the write
	// lock so that a concurrent Close that ran while net.Listen was still
	// executing is linearized ahead of the listener publish: if Close won
	// the race, drop the freshly created listener and surface the same
	// dormant error as the fast path. loopWG.Add runs under the lock and
	// BEFORE the goroutines are spawned so a concurrent Close's
	// loopWG.Wait sees the counter even if scheduling delays acceptLoop
	// or reconnectLoop past the unlock.
	newCtx, cancel := context.WithCancel(ctx)
	s.peersMu.Lock()
	if s.closed {
		s.peersMu.Unlock()
		cancel()
		_ = listener.Close()
		return errors.New("service already closed")
	}
	if s.listener != nil {
		s.peersMu.Unlock()
		cancel()
		_ = listener.Close()
		return errors.New("service already started")
	}
	s.listener = listener
	s.boundAddr = listener.Addr().String()
	s.ctx = newCtx
	s.cancel = cancel
	s.loopWG.Add(2)
	s.peersMu.Unlock()

	go s.acceptLoop()
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

// Close cancels the service context, closes the listener, tears down every
// tracked peer connection, waits for all background goroutines to exit, and
// marks the Service as closed. The Service is dormant after Close returns:
// any subsequent Start call will return "service already closed". Close is
// idempotent on a nil receiver. The boundAddr cache is retained so that
// post-close Addr() calls still surface the last resolved listener address
// for diagnostics/metrics.
//
// Close guarantees that no bound listener remains after it returns, even
// under a concurrent Start race. It does so by first marking the Service
// closed and then waiting on startWG: an in-progress Start that has already
// returned from net.Listen but not yet published into s.listener will
// observe the closed flag in its write-lock re-check and close the freshly
// created listener on its own before returning. Close's subsequent
// startWG.Wait blocks until that cleanup is done, so the listener snapshot
// below always reflects final state — either a published listener that
// Close itself closes, or nil if Start aborted and cleaned up.
func (s *Service) Close() error {
	if s == nil {
		return nil
	}
	// Phase 1: publish the closed flag so any in-progress Start observes
	// it on its write-lock re-check and aborts with "service already
	// closed", closing its local listener before returning.
	s.peersMu.Lock()
	s.closed = true
	s.peersMu.Unlock()

	// Phase 2: wait for every in-progress Start to return. After this
	// wait, s.listener is in its final state — either published by a
	// Start call that won the race and returned nil, or still nil
	// because every Start either failed the fast-path check or aborted
	// in the write-lock re-check and cleaned up its own local listener.
	s.startWG.Wait()

	// Phase 3: snapshot cancel + listener and drive the rest of the
	// shutdown sequence. The snapshot is stable because no Start is in
	// flight anymore, and any future Start will return "service already
	// closed" immediately without touching either field.
	s.peersMu.Lock()
	cancel := s.cancel
	listener := s.listener
	s.peersMu.Unlock()

	if cancel != nil {
		cancel()
	}
	if listener != nil {
		_ = listener.Close()
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

// Addr returns the effective bound address of the Service. While Start has
// successfully published a listener (whether the Service is still running
// or has since been Close'd), Addr returns the cached boundAddr captured at
// listener publish time — this preserves the resolved concrete port for
// wildcard/ephemeral binds such as ":0" even after the listener has been
// closed and becomes a valid log/metric tag across the whole lifecycle.
// Before Start (or if Start failed before publishing), Addr falls back to
// the configured ServiceConfig.BindAddr. Callers must not dial or Accept
// on the returned address after Close.
func (s *Service) Addr() string {
	if s == nil {
		return ""
	}
	s.peersMu.RLock()
	bound := s.boundAddr
	s.peersMu.RUnlock()
	if bound != "" {
		return bound
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
			//
			// Use s.Addr() instead of s.cfg.BindAddr so wildcard /
			// ephemeral binds (":0") surface the concrete resolved port
			// from the cached boundAddr, keeping the log diagnostic
			// consistent with what Addr reports elsewhere.
			fmt.Fprintf(os.Stderr,
				"p2p: accept error on %s: %v (sleeping %s before retry)\n",
				s.Addr(), err, errorBackoff)
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

// sleepOrStop sleeps for d unless the service context is canceled first.
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
