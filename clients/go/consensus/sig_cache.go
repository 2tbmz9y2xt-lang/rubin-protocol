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
//   - Bounded: the cache has a fixed maximum capacity. At saturation it evicts in
//     deterministic insertion-order FIFO, so a newly verified tuple always enters
//     and the oldest inserted tuple leaves. A lookup hit never refreshes an
//     entry's position: eviction order depends only on insertion order, never on
//     access order, so it cannot be steered by lookup traffic.
//   - Thread-safe: concurrent reads and writes are safe via RWMutex.
//   - Canonical key: see sigCacheKey / sigCacheBoundKey. Two key domains that can
//     never collide: the legacy suite-only domain (0x00) and the binding-inclusive
//     domain (0x01) used by live validation.
//
// The cache is a pure performance optimization: an entry may only ever let a
// caller skip a backend verification call that already returned valid=true for
// the exact same key components. It never carries transaction validity, an
// admission result, or any failure.
type SigCache struct {
	mu      sync.RWMutex
	entries map[[32]byte]struct{}
	// order is an insertion-order ring of exactly capacity slots. order[next]
	// holds the oldest live key whenever the cache is full, which makes
	// eviction deterministic FIFO without tracking access.
	order    [][32]byte
	next     int
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
		order:    make([][32]byte, capacity),
		capacity: capacity,
	}
}

// Cache-key domains. The first preimage byte separates the legacy suite-only
// key space from the binding-inclusive key space, so an entry inserted through
// one API can never be found through the other.
const (
	sigCacheKeyDomainLegacy uint8 = 0x00
	sigCacheKeyDomainBound  uint8 = 0x01
)

// appendSigCacheLenPrefixed appends le64(len(b)) || b.
func appendSigCacheLenPrefixed(buf []byte, b []byte) []byte {
	var lenBuf [8]byte
	binary.LittleEndian.PutUint64(lenBuf[:], uint64(len(b)))
	buf = append(buf, lenBuf[:]...)
	return append(buf, b...)
}

// appendSigCacheInt appends an int as le64 two's complement. It is injective on
// every pointer width because the value is widened to int64 before the cast, so
// a 32-bit and a 64-bit build encode the same value identically.
func appendSigCacheInt(buf []byte, v int) []byte {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], uint64(int64(v)))
	return append(buf, b[:]...)
}

// sigCacheKey computes the legacy suite-only cache key for a verification tuple:
// SHA3-256(0x00 || suiteID || le64(len(pubkey)) || pubkey || le64(len(sig)) || sig || digest).
//
// This key does NOT identify the resolved verifier binding and must not be used
// by any live validation path; it is retained for the in-package SigCheckQueue
// fast path and focused tests. Live validation uses sigCacheBoundKey.
func sigCacheKey(suiteID uint8, pubkey, sig []byte, digest [32]byte) [32]byte {
	buf := make([]byte, 0, 2+8+len(pubkey)+8+len(sig)+32)
	buf = append(buf, sigCacheKeyDomainLegacy, suiteID)
	buf = appendSigCacheLenPrefixed(buf, pubkey)
	buf = appendSigCacheLenPrefixed(buf, sig)
	buf = append(buf, digest[:]...)
	return sha3_256(buf)
}

// sigCacheBoundKey computes the binding-inclusive cache key:
// SHA3-256(0x01 || suiteID || le64(len(bindingID)) || bindingID ||
//
//	le64(len(pubkey)) || pubkey || le64(len(sig)) || sig || digest).
//
// Injectivity: the preimage is self-delimiting. Byte 0 is the domain, byte 1 is
// the suite ID, every variable-length component is preceded by its exact 8-byte
// little-endian length, and the fixed 32-byte digest terminates the buffer.
// A preimage can therefore be parsed back into exactly one component tuple
// left-to-right, so two DIFFERENT (bindingID, suiteID, pubkey, sig, digest)
// tuples can never produce the same preimage — in particular two different
// resolved verifier bindings can never serialize into the same key, and no
// re-split of the pubkey/signature byte boundary can alias another tuple.
// Key equality therefore implies component equality under SHA3-256 collision
// resistance. bindingID must itself be an injective encoding of the resolved
// binding (see sigCacheVerifierBindingIdentity).
func sigCacheBoundKey(bindingID []byte, suiteID uint8, pubkey, sig []byte, digest [32]byte) [32]byte {
	buf := make([]byte, 0, 2+8+len(bindingID)+8+len(pubkey)+8+len(sig)+32)
	buf = append(buf, sigCacheKeyDomainBound, suiteID)
	buf = appendSigCacheLenPrefixed(buf, bindingID)
	buf = appendSigCacheLenPrefixed(buf, pubkey)
	buf = appendSigCacheLenPrefixed(buf, sig)
	buf = append(buf, digest[:]...)
	return sha3_256(buf)
}

// Lookup checks if a (suiteID, pubkey, sig, digest) tuple has been previously
// verified as valid under the legacy suite-only key domain. Returns true if
// found in cache (positive hit). Live validation must use lookupBound.
func (c *SigCache) Lookup(suiteID uint8, pubkey, sig []byte, digest [32]byte) bool {
	if c == nil {
		return false
	}
	return c.lookupKey(sigCacheKey(suiteID, pubkey, sig, digest))
}

// Insert records a positive verification result under the legacy suite-only key
// domain. Live validation must use insertBound.
func (c *SigCache) Insert(suiteID uint8, pubkey, sig []byte, digest [32]byte) {
	if c == nil {
		return
	}
	c.insertKey(sigCacheKey(suiteID, pubkey, sig, digest))
}

// lookupBound reports whether the exact tuple was already verified successfully
// under this resolved verifier binding identity.
func (c *SigCache) lookupBound(bindingID []byte, suiteID uint8, pubkey, sig []byte, digest [32]byte) bool {
	if c == nil {
		return false
	}
	return c.lookupKey(sigCacheBoundKey(bindingID, suiteID, pubkey, sig, digest))
}

// insertBound records a successful backend verification under this resolved
// verifier binding identity. Callers must only reach it after the backend
// returned valid=true with a nil error.
func (c *SigCache) insertBound(bindingID []byte, suiteID uint8, pubkey, sig []byte, digest [32]byte) {
	if c == nil {
		return
	}
	c.insertKey(sigCacheBoundKey(bindingID, suiteID, pubkey, sig, digest))
}

func (c *SigCache) lookupKey(key [32]byte) bool {
	c.mu.RLock()
	_, ok := c.entries[key]
	// Counter bump stays under RLock: Reset zeroes the counters under the write
	// lock, so no add can land after a completed Reset.
	if ok {
		c.hits.Add(1)
	} else {
		c.misses.Add(1)
	}
	c.mu.RUnlock()
	return ok
}

// insertKey stores key, evicting the oldest inserted key first when the cache is
// at capacity. Re-inserting a key already present is a no-op: it neither
// duplicates a ring slot nor refreshes the key's eviction position.
func (c *SigCache) insertKey(key [32]byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	// A zero-value SigCache was not built by NewSigCache: it has no map and no
	// ring. Stay a no-op instead of panicking on a nil-map write or a modulo by
	// zero — this type is exported and a caller may declare one.
	if c.capacity <= 0 || len(c.order) != c.capacity || c.entries == nil {
		return
	}
	if _, ok := c.entries[key]; ok {
		return
	}
	if len(c.entries) >= c.capacity {
		delete(c.entries, c.order[c.next])
	}
	c.order[c.next] = key
	c.next = (c.next + 1) % c.capacity
	c.entries[key] = struct{}{}
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

// Reset clears all cached entries, the insertion order, and the counters. It is
// exact and concurrency-safe; it is not a policy-generation signal.
func (c *SigCache) Reset() {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.entries = make(map[[32]byte]struct{}, c.capacity)
	c.order = make([][32]byte, c.capacity)
	c.next = 0
	c.hits.Store(0)
	c.misses.Store(0)
	c.mu.Unlock()
}
