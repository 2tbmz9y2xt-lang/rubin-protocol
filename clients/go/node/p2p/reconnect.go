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
	now := s.cfg.Now()
	for _, addr := range s.outboundAddrsSnapshot() {
		if s.isConnected(addr) {
			continue
		}
		if !s.isReconnectDue(addr, now) {
			continue
		}
		if s.startOutboundDial(addr) {
			s.scheduleNextReconnectAttempt(addr, now)
		}
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

func (s *Service) isReconnectDue(addr string, now time.Time) bool {
	due := false
	ok := s.withReconnectEntry(addr, func(entry *reconnectEntry) {
		due = !entry.nextRetry.After(now)
	})
	return ok && due
}

func (s *Service) reconnectSnapshot(addr string) reconnectEntry {
	entry, ok := s.reconnectEntryFor(addr)
	if !ok || entry == nil {
		return reconnectEntry{}
	}
	return *entry
}

func (s *Service) reconnectEntryFor(addr string) (*reconnectEntry, bool) {
	var entry *reconnectEntry
	ok := s.withNormalizedReconnectAddr(addr, func(addr string) {
		s.reconnectMu.Lock()
		defer s.reconnectMu.Unlock()
		entry = s.lookupReconnectEntry(addr)
	})
	if !ok {
		return nil, false
	}
	return entry, entry != nil
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
	return s.withNormalizedReconnectAddr(addr, func(addr string) {
		s.reconnectMu.Lock()
		defer s.reconnectMu.Unlock()
		entry := s.lookupReconnectEntry(addr)
		if entry == nil {
			entry = s.insertReconnectEntry(addr)
		}
		fn(entry)
	})
}

func (s *Service) isConnected(addr string) bool {
	connected := false
	ok := s.withNormalizedReconnectAddr(addr, func(addr string) {
		s.peersMu.RLock()
		defer s.peersMu.RUnlock()
		_, connected = s.peers[addr]
	})
	return ok && connected
}

func normalizeReconnectAddr(addr string) string {
	normalized, ok := normalizedReconnectAddr(addr)
	if !ok {
		return ""
	}
	return normalized
}

func (s *Service) lookupReconnectEntry(addr string) *reconnectEntry {
	return s.reconnectState[addr]
}

func (s *Service) insertReconnectEntry(addr string) *reconnectEntry {
	entry := &reconnectEntry{}
	s.reconnectState[addr] = entry
	return entry
}

func (s *Service) withNormalizedReconnectAddr(addr string, fn func(string)) bool {
	addr, ok := normalizedReconnectAddr(addr)
	if !ok || s == nil {
		return false
	}
	fn(addr)
	return true
}

func normalizedReconnectAddr(addr string) (string, bool) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return "", false
	}
	if normalized := normalizeDialTarget(addr); normalized != "" {
		return normalized, true
	}
	return addr, true
}
