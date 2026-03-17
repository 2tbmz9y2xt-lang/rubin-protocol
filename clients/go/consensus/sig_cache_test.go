package consensus

import (
	"sync"
	"testing"
)

// ─────────────────────────────────────────────────────────────────────────────
// SigCache unit tests
// ─────────────────────────────────────────────────────────────────────────────

func TestSigCache_BasicInsertLookup(t *testing.T) {
	c := NewSigCache(100)
	kp := mustMLDSA87Keypair(t)

	var digest [32]byte
	digest[0] = 0x42
	sig, err := kp.SignDigest32(digest)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	pk := kp.PubkeyBytes()

	// Before insert: miss.
	if c.Lookup(SUITE_ID_ML_DSA_87, pk, sig, digest) {
		t.Fatalf("expected miss before insert")
	}
	if c.Hits() != 0 || c.Misses() != 1 {
		t.Fatalf("expected 0 hits / 1 miss, got %d / %d", c.Hits(), c.Misses())
	}

	// Insert and lookup: hit.
	c.Insert(SUITE_ID_ML_DSA_87, pk, sig, digest)
	if !c.Lookup(SUITE_ID_ML_DSA_87, pk, sig, digest) {
		t.Fatalf("expected hit after insert")
	}
	if c.Hits() != 1 || c.Misses() != 1 {
		t.Fatalf("expected 1 hit / 1 miss, got %d / %d", c.Hits(), c.Misses())
	}
	if c.Len() != 1 {
		t.Fatalf("expected len=1, got %d", c.Len())
	}
}

func TestSigCache_BoundedCapacity(t *testing.T) {
	c := NewSigCache(2) // capacity = 2
	kp := mustMLDSA87Keypair(t)

	// Pre-generate signatures (ML-DSA is randomized — must reuse same sig bytes).
	type entry struct {
		sig    []byte
		digest [32]byte
	}
	entries := make([]entry, 3)
	for i := range entries {
		entries[i].digest[0] = byte(i)
		var err error
		entries[i].sig, err = kp.SignDigest32(entries[i].digest)
		if err != nil {
			t.Fatalf("sign %d: %v", i, err)
		}
		c.Insert(SUITE_ID_ML_DSA_87, kp.PubkeyBytes(), entries[i].sig, entries[i].digest)
	}

	if c.Len() != 2 {
		t.Fatalf("expected len=2 (bounded), got %d", c.Len())
	}

	// First two should be present.
	for i := 0; i < 2; i++ {
		if !c.Lookup(SUITE_ID_ML_DSA_87, kp.PubkeyBytes(), entries[i].sig, entries[i].digest) {
			t.Fatalf("entry %d should be in cache", i)
		}
	}

	// Third should be absent (dropped due to capacity).
	if c.Lookup(SUITE_ID_ML_DSA_87, kp.PubkeyBytes(), entries[2].sig, entries[2].digest) {
		t.Fatalf("entry 2 should have been dropped (capacity=2)")
	}
}

func TestSigCache_NilSafe(t *testing.T) {
	var c *SigCache
	// All methods must be nil-safe (no panic).
	if c.Lookup(0, nil, nil, [32]byte{}) {
		t.Fatalf("nil cache lookup should return false")
	}
	c.Insert(0, nil, nil, [32]byte{})
	if c.Len() != 0 {
		t.Fatalf("nil cache len should be 0")
	}
	if c.Hits() != 0 || c.Misses() != 0 {
		t.Fatalf("nil cache counters should be 0")
	}
	c.Reset() // should not panic
}

func TestSigCache_Reset(t *testing.T) {
	c := NewSigCache(10)
	kp := mustMLDSA87Keypair(t)

	var d [32]byte
	sig, _ := kp.SignDigest32(d)
	c.Insert(SUITE_ID_ML_DSA_87, kp.PubkeyBytes(), sig, d)
	c.Lookup(SUITE_ID_ML_DSA_87, kp.PubkeyBytes(), sig, d) // hit

	if c.Len() != 1 || c.Hits() != 1 {
		t.Fatalf("pre-reset: expected len=1, hits=1")
	}

	c.Reset()
	if c.Len() != 0 || c.Hits() != 0 || c.Misses() != 0 {
		t.Fatalf("post-reset: expected all zeros, got len=%d hits=%d misses=%d",
			c.Len(), c.Hits(), c.Misses())
	}

	// Lookup after reset: miss.
	if c.Lookup(SUITE_ID_ML_DSA_87, kp.PubkeyBytes(), sig, d) {
		t.Fatalf("expected miss after reset")
	}
}

func TestSigCache_DifferentDigest_NoCrossHit(t *testing.T) {
	c := NewSigCache(100)
	kp := mustMLDSA87Keypair(t)

	var d1 [32]byte
	d1[0] = 0x01
	sig1, _ := kp.SignDigest32(d1)

	c.Insert(SUITE_ID_ML_DSA_87, kp.PubkeyBytes(), sig1, d1)

	// Same sig but different digest → must not hit.
	var d2 [32]byte
	d2[0] = 0x02
	if c.Lookup(SUITE_ID_ML_DSA_87, kp.PubkeyBytes(), sig1, d2) {
		t.Fatalf("different digest should not produce cache hit")
	}
}

func TestSigCache_CanonicalKeyDeterminism(t *testing.T) {
	// Same inputs → same key.
	pk := []byte{1, 2, 3}
	sig := []byte{4, 5, 6}
	var d [32]byte
	d[0] = 0xFF

	k1 := sigCacheKey(0x01, pk, sig, d)
	k2 := sigCacheKey(0x01, pk, sig, d)
	if k1 != k2 {
		t.Fatalf("same inputs should produce same cache key")
	}

	// Different suiteID → different key.
	k3 := sigCacheKey(0x02, pk, sig, d)
	if k1 == k3 {
		t.Fatalf("different suiteID should produce different cache key")
	}
}

func TestSigCache_CapacityClampZero(t *testing.T) {
	c := NewSigCache(0) // should clamp to 1
	if c.capacity != 1 {
		t.Fatalf("expected capacity=1, got %d", c.capacity)
	}
	c2 := NewSigCache(-5) // should clamp to 1
	if c2.capacity != 1 {
		t.Fatalf("expected capacity=1, got %d", c2.capacity)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// SigCheckQueue + SigCache integration
// ─────────────────────────────────────────────────────────────────────────────

func TestSigCheckQueue_WithCache_SingleHit(t *testing.T) {
	kp := mustMLDSA87Keypair(t)
	cache := NewSigCache(100)

	var d [32]byte
	d[0] = 0x42
	sig, err := kp.SignDigest32(d)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	pk := kp.PubkeyBytes()

	// Pre-populate cache with valid result.
	cache.Insert(SUITE_ID_ML_DSA_87, pk, sig, d)

	// Flush with cache → should skip verifySig (cache hit).
	q := NewSigCheckQueue(1).WithCache(cache)
	q.Push(SUITE_ID_ML_DSA_87, pk, sig, d, txerr(TX_ERR_SIG_INVALID, "test"))
	if err := q.Flush(); err != nil {
		t.Fatalf("cache hit should pass: %v", err)
	}
	if cache.Hits() != 1 {
		t.Fatalf("expected 1 cache hit, got %d", cache.Hits())
	}
}

func TestSigCheckQueue_WithCache_MultiHit(t *testing.T) {
	kp := mustMLDSA87Keypair(t)
	cache := NewSigCache(100)

	// Pre-generate signatures (ML-DSA is randomized).
	const n = 4
	type entry struct {
		sig    []byte
		digest [32]byte
	}
	entries := make([]entry, n)
	for i := range entries {
		entries[i].digest[0] = byte(i)
		var err error
		entries[i].sig, err = kp.SignDigest32(entries[i].digest)
		if err != nil {
			t.Fatalf("sign %d: %v", i, err)
		}
	}

	// First flush: populate cache (no hits).
	q1 := NewSigCheckQueue(2).WithCache(cache)
	for _, e := range entries {
		q1.Push(SUITE_ID_ML_DSA_87, kp.PubkeyBytes(), e.sig, e.digest, txerr(TX_ERR_SIG_INVALID, "first"))
	}
	if err := q1.Flush(); err != nil {
		t.Fatalf("first flush: %v", err)
	}
	if cache.Len() != n {
		t.Fatalf("expected %d cached entries, got %d", n, cache.Len())
	}

	// Second flush with same tuples: all hits.
	q2 := NewSigCheckQueue(2).WithCache(cache)
	for _, e := range entries {
		q2.Push(SUITE_ID_ML_DSA_87, kp.PubkeyBytes(), e.sig, e.digest, txerr(TX_ERR_SIG_INVALID, "second"))
	}
	if err := q2.Flush(); err != nil {
		t.Fatalf("second flush (all cached): %v", err)
	}
	if cache.Hits() != n {
		t.Fatalf("expected %d cache hits on second flush, got %d", n, cache.Hits())
	}
}

func TestSigCheckQueue_WithCache_InvalidNotCached(t *testing.T) {
	kp := mustMLDSA87Keypair(t)
	cache := NewSigCache(100)

	var d [32]byte
	d[0] = 0x42
	sig, err := kp.SignDigest32(d)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	badD := d
	badD[0] ^= 0xFF // corrupt

	q := NewSigCheckQueue(1).WithCache(cache)
	q.Push(SUITE_ID_ML_DSA_87, kp.PubkeyBytes(), sig, badD, txerr(TX_ERR_SIG_INVALID, "invalid"))
	err = q.Flush()
	if err == nil {
		t.Fatalf("expected error for invalid sig")
	}
	// Cache should remain empty — negative results are NOT cached.
	if cache.Len() != 0 {
		t.Fatalf("invalid sig should not be cached, got len=%d", cache.Len())
	}
}

func TestSigCheckQueue_WithCache_NilCacheStillWorks(t *testing.T) {
	kp := mustMLDSA87Keypair(t)

	var d [32]byte
	sig, _ := kp.SignDigest32(d)

	// WithCache(nil) should behave like no cache.
	q := NewSigCheckQueue(1).WithCache(nil)
	q.Push(SUITE_ID_ML_DSA_87, kp.PubkeyBytes(), sig, d, txerr(TX_ERR_SIG_INVALID, "test"))
	if err := q.Flush(); err != nil {
		t.Fatalf("nil cache flush: %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Concurrent cache safety
// ─────────────────────────────────────────────────────────────────────────────

func TestSigCache_ConcurrentInsertLookup(t *testing.T) {
	c := NewSigCache(1000)
	kp := mustMLDSA87Keypair(t)

	const goroutines = 8
	const perGoroutine = 10
	var wg sync.WaitGroup

	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(gid int) {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				var d [32]byte
				d[0] = byte(gid)
				d[1] = byte(i)
				sig, err := kp.SignDigest32(d)
				if err != nil {
					t.Errorf("goroutine %d sign %d: %v", gid, i, err)
					return
				}
				c.Insert(SUITE_ID_ML_DSA_87, kp.PubkeyBytes(), sig, d)
				c.Lookup(SUITE_ID_ML_DSA_87, kp.PubkeyBytes(), sig, d)
			}
		}(g)
	}
	wg.Wait()

	if c.Len() != goroutines*perGoroutine {
		t.Fatalf("expected %d entries, got %d", goroutines*perGoroutine, c.Len())
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Benchmark: cache hit vs verify
// ─────────────────────────────────────────────────────────────────────────────

func BenchmarkSigCache_Lookup(b *testing.B) {
	c := NewSigCache(1000)
	kp := mustMLDSA87KeypairB(b)

	var d [32]byte
	d[0] = 0xAA
	sig, err := kp.SignDigest32(d)
	if err != nil {
		b.Fatalf("sign: %v", err)
	}
	c.Insert(SUITE_ID_ML_DSA_87, kp.PubkeyBytes(), sig, d)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Lookup(SUITE_ID_ML_DSA_87, kp.PubkeyBytes(), sig, d)
	}
}

func BenchmarkSigCheckQueue_WithCache(b *testing.B) {
	kp := mustMLDSA87KeypairB(b)
	cache := NewSigCache(1000)

	// Pre-populate cache.
	const n = 16
	type task struct {
		sig    []byte
		digest [32]byte
	}
	tasks := make([]task, n)
	for i := range tasks {
		tasks[i].digest[0] = byte(i)
		var err error
		tasks[i].sig, err = kp.SignDigest32(tasks[i].digest)
		if err != nil {
			b.Fatalf("sign %d: %v", i, err)
		}
		cache.Insert(SUITE_ID_ML_DSA_87, kp.PubkeyBytes(), tasks[i].sig, tasks[i].digest)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		q := NewSigCheckQueue(0).WithCache(cache)
		for _, t := range tasks {
			q.Push(SUITE_ID_ML_DSA_87, kp.PubkeyBytes(), t.sig, t.digest, txerr(TX_ERR_SIG_INVALID, "bench"))
		}
		if err := q.Flush(); err != nil {
			b.Fatalf("flush: %v", err)
		}
	}
}
