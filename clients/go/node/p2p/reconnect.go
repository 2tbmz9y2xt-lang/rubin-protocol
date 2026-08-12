package p2p

import (
	"context"
	"slices"
	"strings"
	"time"
)

var (
	reconnectLoopInterval = 5 * time.Second
	reconnectBaseDelay    = 5 * time.Second
	reconnectMaxDelay     = 5 * time.Minute
)

type reconnectEntry struct {
	failures  int
	nextRetry time.Time
}

func (s *Service) reconnectLoop(ctx context.Context) {
	defer s.loopWG.Done()
	ticker := time.NewTicker(reconnectLoopInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.reconnectDuePeers()
		}
	}
}

func (s *Service) reconnectDuePeers() {
	if s == nil {
		return
	}
	for _, addr := range s.outboundAddrsSnapshot() {
		if s.isConnected(addr) {
			continue
		}
		// Exact reconnect order: the worker lease precedes the clock producer and
		// the read-only due check, the in-flight reservation precedes the backoff
		// advance, and only a fully reserved attempt advances reconnectState and
		// spawns the dial that inherits the lease. A Close loss, a not-due entry
		// or a duplicate reservation leaves reconnectState exactly as it found it,
		// adds no reservation and releases the lease exactly once.
		if !s.acquireWork() {
			return
		}
		now := s.cfg.Now()
		if !s.isReconnectDue(addr, now) {
			s.releaseWork()
			continue
		}
		if !s.trackDialPeer(addr) {
			s.releaseWork()
			continue
		}
		s.scheduleNextReconnectAttempt(addr, now)
		go s.dialPeer(addr)
	}
}

func (s *Service) outboundAddrsSnapshot() []string {
	s.reconnectMu.Lock()
	defer s.reconnectMu.Unlock()
	return append([]string(nil), s.outboundAddrs...)
}

func (s *Service) ensureOutboundAddr(addr string) {
	if s == nil {
		return
	}
	addr = normalizeReconnectAddr(addr)
	if addr == "" {
		return
	}
	s.reconnectMu.Lock()
	defer s.reconnectMu.Unlock()
	if slices.Contains(s.outboundAddrs, addr) {
		return
	}
	s.outboundAddrs = append(s.outboundAddrs, addr)
}

func (s *Service) resetReconnect(addr string) {
	if s == nil {
		return
	}
	s.reconnectMu.Lock()
	defer s.reconnectMu.Unlock()
	addr = normalizeReconnectAddr(addr)
	if addr == "" {
		return
	}
	delete(s.reconnectState, addr)
}

func (s *Service) recordDialFailure(addr string) {
	s.withReconnectEntry(addr, func(entry *reconnectEntry) {
		entry.nextRetry = s.cfg.Now().Add(reconnectBackoff(entry.failures))
		entry.failures++
	})
}

func (s *Service) scheduleReconnect(addr string) {
	s.withReconnectEntry(addr, func(entry *reconnectEntry) {
		entry.nextRetry = s.cfg.Now().Add(reconnectBackoff(entry.failures))
	})
}

func (s *Service) scheduleNextReconnectAttempt(addr string, now time.Time) {
	s.withReconnectEntry(addr, func(entry *reconnectEntry) {
		entry.nextRetry = now.Add(reconnectBackoff(entry.failures))
	})
}

// isReconnectDue reports whether addr may be dialed again at now. It is a
// read-only peek over reconnectSnapshot: an address with no entry is due (zero
// nextRetry) but MUST NOT gain one here, so a reconnect rejected after this
// check leaves reconnectState exactly as it found it.
func (s *Service) isReconnectDue(addr string, now time.Time) bool {
	if s == nil || normalizeReconnectAddr(addr) == "" {
		return false
	}
	return !s.reconnectSnapshot(addr).nextRetry.After(now)
}

func (s *Service) reconnectSnapshot(addr string) reconnectEntry {
	if s == nil {
		return reconnectEntry{}
	}
	s.reconnectMu.Lock()
	defer s.reconnectMu.Unlock()
	addr = normalizeReconnectAddr(addr)
	if addr == "" {
		return reconnectEntry{}
	}
	entry := s.reconnectState[addr]
	if entry == nil {
		return reconnectEntry{}
	}
	return *entry
}

func reconnectBackoff(failures int) time.Duration {
	if failures < 0 {
		failures = 0
	}
	delay := reconnectBaseDelay
	for i := 0; i < failures; i++ {
		if delay >= reconnectMaxDelay {
			return reconnectMaxDelay
		}
		next := delay * 2
		if next < delay || next > reconnectMaxDelay {
			return reconnectMaxDelay
		}
		delay = next
	}
	if delay > reconnectMaxDelay {
		return reconnectMaxDelay
	}
	return delay
}

func (s *Service) withReconnectEntry(addr string, fn func(*reconnectEntry)) bool {
	if s == nil {
		return false
	}
	addr = normalizeReconnectAddr(addr)
	if addr == "" {
		return false
	}
	s.reconnectMu.Lock()
	defer s.reconnectMu.Unlock()
	entry := s.reconnectState[addr]
	if entry == nil {
		entry = &reconnectEntry{}
		s.reconnectState[addr] = entry
	}
	fn(entry)
	return true
}

func (s *Service) isConnected(addr string) bool {
	if s == nil {
		return false
	}
	s.peersMu.RLock()
	defer s.peersMu.RUnlock()
	_, ok := s.peers[addr]
	return ok
}

func normalizeReconnectAddr(addr string) string {
	addr = strings.TrimSpace(addr)
	return addr
}
