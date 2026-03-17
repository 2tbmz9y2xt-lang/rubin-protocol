package consensus

import (
	"encoding/binary"
	"sync"
	"sync/atomic"
)

// SigCache is a bounded, thread-safe, positive-only signature verification
// cache. It stores only successful verification results (valid=true, err=nil).
//
// Design rationale:
//   - Positive-only: caching negative results would allow cache-poisoning attacks
//     where an attacker causes valid signatures to be rejected.
//   - Bounded: the cache has a fixed maximum capacity. When full, new entries are
//     silently dropped (no eviction). This is simpler than LRU and still correct:
//     the cache is a pure performance optimization.
//   - Thread-safe: concurrent reads and writes are safe via RWMutex.
//   - Canonical key: SHA3-256(suiteID || len(pubkey) || pubkey || len(sig) || sig || digest).
//     Length-prefixing prevents ambiguity between different (pubkey, sig) splits.
type SigCache struct {
	mu       sync.RWMutex
	entries  map[[32]byte]struct{}
	capacity int
	hits     atomic.Uint64
	misses   atomic.Uint64
}

// NewSigCache creates a bounded positive-only signature cache.
// Capacity must be > 0; values <= 0 are clamped to 1.
func NewSigCache(capacity int) *SigCache {
	if capacity <= 0 {
		capacity = 1
	}
	return &SigCache{
		entries:  make(map[[32]byte]struct{}, capacity),
		capacity: capacity,
	}
}

// sigCacheKey computes the canonical cache key for a verification tuple.
// The key is SHA3-256(suiteID || le32(len(pubkey)) || pubkey || le32(len(sig)) || sig || digest).
func sigCacheKey(suiteID uint8, pubkey, sig []byte, digest [32]byte) [32]byte {
	// Pre-allocate: 1 + 4 + len(pubkey) + 4 + len(sig) + 32
	buf := make([]byte, 0, 1+4+len(pubkey)+4+len(sig)+32)
	buf = append(buf, suiteID)
	var lenBuf [4]byte
	binary.LittleEndian.PutUint32(lenBuf[:], uint32(len(pubkey)))
	buf = append(buf, lenBuf[:]...)
	buf = append(buf, pubkey...)
	binary.LittleEndian.PutUint32(lenBuf[:], uint32(len(sig)))
	buf = append(buf, lenBuf[:]...)
	buf = append(buf, sig...)
	buf = append(buf, digest[:]...)
	return sha3_256(buf)
}

// Lookup checks if a (suiteID, pubkey, sig, digest) tuple has been previously
// verified as valid. Returns true if found in cache (positive hit).
func (c *SigCache) Lookup(suiteID uint8, pubkey, sig []byte, digest [32]byte) bool {
	if c == nil {
		return false
	}
	key := sigCacheKey(suiteID, pubkey, sig, digest)
	c.mu.RLock()
	_, ok := c.entries[key]
	c.mu.RUnlock()
	if ok {
		c.hits.Add(1)
	} else {
		c.misses.Add(1)
	}
	return ok
}

// Insert records a positive verification result. If the cache is at capacity,
// the entry is silently dropped (no eviction).
func (c *SigCache) Insert(suiteID uint8, pubkey, sig []byte, digest [32]byte) {
	if c == nil {
		return
	}
	key := sigCacheKey(suiteID, pubkey, sig, digest)
	c.mu.Lock()
	if len(c.entries) < c.capacity {
		c.entries[key] = struct{}{}
	}
	c.mu.Unlock()
}

// Len returns the number of cached entries.
func (c *SigCache) Len() int {
	if c == nil {
		return 0
	}
	c.mu.RLock()
	n := len(c.entries)
	c.mu.RUnlock()
	return n
}

// Hits returns the number of cache hits.
func (c *SigCache) Hits() uint64 {
	if c == nil {
		return 0
	}
	return c.hits.Load()
}

// Misses returns the number of cache misses.
func (c *SigCache) Misses() uint64 {
	if c == nil {
		return 0
	}
	return c.misses.Load()
}

// Reset clears all cached entries and resets counters.
func (c *SigCache) Reset() {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.entries = make(map[[32]byte]struct{}, c.capacity)
	c.hits.Store(0)
	c.misses.Store(0)
	c.mu.Unlock()
}
