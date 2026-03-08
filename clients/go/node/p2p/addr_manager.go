package p2p

import (
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	maxKnownAddrs    = 1000
	maxAddrAdvertise = 25
)

type addrEntry struct {
	addr     string
	lastSeen time.Time
	attempts int
}

type addrManager struct {
	mu    sync.Mutex
	addrs map[string]addrEntry
	now   func() time.Time
}

func newAddrManager(now func() time.Time) *addrManager {
	if now == nil {
		now = time.Now
	}
	return &addrManager{
		addrs: make(map[string]addrEntry),
		now:   now,
	}
}

func (m *addrManager) AddAddrs(addrs []string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	for _, addr := range addrs {
		addr = normalizeNetAddr(addr)
		if addr == "" {
			continue
		}
		entry := m.addrs[addr]
		entry.addr = addr
		entry.lastSeen = now
		m.addrs[addr] = entry
	}
	m.evictLocked()
}

func (m *addrManager) GetAddrs(max int) []string {
	if m == nil || max == 0 {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if max < 0 || max > len(m.addrs) {
		max = len(m.addrs)
	}
	if max == 0 {
		return nil
	}
	entries := make([]addrEntry, 0, len(m.addrs))
	for _, entry := range m.addrs {
		entries = append(entries, entry)
	}
	sort.Slice(entries, func(i, j int) bool {
		if !entries[i].lastSeen.Equal(entries[j].lastSeen) {
			return entries[i].lastSeen.After(entries[j].lastSeen)
		}
		return entries[i].addr < entries[j].addr
	})
	out := make([]string, 0, max)
	for _, entry := range entries[:max] {
		out = append(out, entry.addr)
	}
	return out
}

func (m *addrManager) MarkAttempted(addr string) {
	if m == nil {
		return
	}
	addr = normalizeNetAddr(addr)
	if addr == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	entry := m.addrs[addr]
	entry.addr = addr
	entry.attempts++
	m.addrs[addr] = entry
}

func (m *addrManager) Len() int {
	if m == nil {
		return 0
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.addrs)
}

func (m *addrManager) evictLocked() {
	for len(m.addrs) > maxKnownAddrs {
		var oldest addrEntry
		first := true
		for _, entry := range m.addrs {
			if first || entry.lastSeen.Before(oldest.lastSeen) || (entry.lastSeen.Equal(oldest.lastSeen) && entry.addr < oldest.addr) {
				oldest = entry
				first = false
			}
		}
		if first {
			return
		}
		delete(m.addrs, oldest.addr)
	}
}

func normalizeNetAddr(raw string) string {
	return normalizeIPPort(raw, false)
}

func normalizeDialTarget(raw string) string {
	return normalizeIPPort(raw, true)
}

func normalizeIPPort(raw string, allowHostname bool) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	host, portStr, err := net.SplitHostPort(raw)
	if err != nil {
		return ""
	}
	host = strings.Trim(host, "[]")
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil || port == 0 {
		return ""
	}
	host = normalizeEndpointHost(host, allowHostname)
	if host == "" {
		return ""
	}
	return net.JoinHostPort(host, strconv.FormatUint(port, 10))
}

func normalizeEndpointHost(host string, allowHostname bool) string {
	if ip := net.ParseIP(host); ip != nil {
		return ip.String()
	}
	if !allowHostname || host == "" || strings.ContainsAny(host, " \t\r\n/") {
		return ""
	}
	return strings.ToLower(host)
}
