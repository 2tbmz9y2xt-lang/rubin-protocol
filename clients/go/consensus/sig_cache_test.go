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

	// FIFO at saturation: the OLDEST insertion left, the newest entered.
	if c.Lookup(SUITE_ID_ML_DSA_87, kp.PubkeyBytes(), entries[0].sig, entries[0].digest) {
		t.Fatalf("entry 0 should have been evicted (oldest insertion, capacity=2)")
	}
	for i := 1; i < 3; i++ {
		if !c.Lookup(SUITE_ID_ML_DSA_87, kp.PubkeyBytes(), entries[i].sig, entries[i].digest) {
			t.Fatalf("entry %d should be in cache", i)
		}
	}
}

// syntheticSigCacheTuple builds distinct, cheap (pubkey, sig, digest) bytes for
// cache-mechanics tests that do not need a real signature.
func syntheticSigCacheTuple(seed byte) (pubkey, sig []byte, digest [32]byte) {
	pubkey = []byte{0xa0, seed}
	sig = []byte{0x50, seed}
	digest[0] = seed
	return pubkey, sig, digest
}

// TestSigCache_FIFOEvictsOldestAndHitsDoNotRefreshOrder pins the deterministic
// insertion-order FIFO contract: at saturation the oldest INSERTION is evicted
// so a newly verified tuple always enters, and a lookup hit never moves an
// entry's eviction position (which would make eviction access-order/LRU and let
// lookup traffic steer it).
func TestSigCache_FIFOEvictsOldestAndHitsDoNotRefreshOrder(t *testing.T) {
	c := NewSigCache(2)
	pkA, sigA, dA := syntheticSigCacheTuple(0xa1)
	pkB, sigB, dB := syntheticSigCacheTuple(0xb2)
	pkC, sigC, dC := syntheticSigCacheTuple(0xc3)

	c.Insert(SUITE_ID_ML_DSA_87, pkA, sigA, dA)
	c.Insert(SUITE_ID_ML_DSA_87, pkB, sigB, dB)

	// Hit A repeatedly, then re-insert it: neither may refresh its position.
	for i := 0; i < 3; i++ {
		if !c.Lookup(SUITE_ID_ML_DSA_87, pkA, sigA, dA) {
			t.Fatalf("A must be cached before saturation")
		}
	}
	c.Insert(SUITE_ID_ML_DSA_87, pkA, sigA, dA)
	if c.Len() != 2 {
		t.Fatalf("re-insert of a present key changed len: got %d, want 2", c.Len())
	}

	c.Insert(SUITE_ID_ML_DSA_87, pkC, sigC, dC)
	if c.Len() != 2 {
		t.Fatalf("len=%d after saturating insert, want 2", c.Len())
	}
	if c.Lookup(SUITE_ID_ML_DSA_87, pkA, sigA, dA) {
		t.Fatal("A (oldest insertion) must be evicted despite its lookup hits")
	}
	if !c.Lookup(SUITE_ID_ML_DSA_87, pkB, sigB, dB) {
		t.Fatal("B must survive: it was inserted after A")
	}
	if !c.Lookup(SUITE_ID_ML_DSA_87, pkC, sigC, dC) {
		t.Fatal("C (newly verified) must be admitted at saturation")
	}

	// Next insert evicts B, the new oldest — the ring keeps advancing.
	pkD, sigD, dD := syntheticSigCacheTuple(0xd4)
	c.Insert(SUITE_ID_ML_DSA_87, pkD, sigD, dD)
	if c.Lookup(SUITE_ID_ML_DSA_87, pkB, sigB, dB) {
		t.Fatal("B must be evicted next")
	}
	if !c.Lookup(SUITE_ID_ML_DSA_87, pkC, sigC, dC) || !c.Lookup(SUITE_ID_ML_DSA_87, pkD, sigD, dD) {
		t.Fatal("C and D must both be resident after the second eviction")
	}
}

// TestSigCache_BoundKeyIsInjectiveAndDomainSeparated falsifies a cache key that
// drops the resolved-binding component or that lets two different component
// tuples alias each other. Every row below differs in exactly one component and
// must therefore produce a different key.
func TestSigCache_BoundKeyIsInjectiveAndDomainSeparated(t *testing.T) {
	base := struct {
		bindingID []byte
		suiteID   uint8
		pubkey    []byte
		sig       []byte
		digest    [32]byte
	}{
		bindingID: []byte("binding-v1"),
		suiteID:   SUITE_ID_ML_DSA_87,
		pubkey:    []byte{0x01, 0x02, 0x03},
		sig:       []byte{0x04, 0x05},
		digest:    [32]byte{0xff},
	}
	want := sigCacheBoundKey(base.bindingID, base.suiteID, base.pubkey, base.sig, base.digest)
	if got := sigCacheBoundKey(base.bindingID, base.suiteID, base.pubkey, base.sig, base.digest); got != want {
		t.Fatal("same components must produce the same key")
	}

	otherDigest := base.digest
	otherDigest[31] = 0x01
	cases := []struct {
		name string
		key  [32]byte
	}{
		{"different_binding_identity", sigCacheBoundKey([]byte("binding-v2"), base.suiteID, base.pubkey, base.sig, base.digest)},
		{"binding_identity_absent", sigCacheBoundKey(nil, base.suiteID, base.pubkey, base.sig, base.digest)},
		{"different_suite_id", sigCacheBoundKey(base.bindingID, 0x02, base.pubkey, base.sig, base.digest)},
		{"different_pubkey", sigCacheBoundKey(base.bindingID, base.suiteID, []byte{0x01, 0x02, 0x04}, base.sig, base.digest)},
		{"different_signature", sigCacheBoundKey(base.bindingID, base.suiteID, base.pubkey, []byte{0x04, 0x06}, base.digest)},
		{"different_digest", sigCacheBoundKey(base.bindingID, base.suiteID, base.pubkey, base.sig, otherDigest)},
		// Re-split of the same concatenated bytes across the field boundary.
		{"pubkey_signature_resplit", sigCacheBoundKey(base.bindingID, base.suiteID, []byte{0x01, 0x02}, []byte{0x03, 0x04, 0x05}, base.digest)},
		// A binding-inclusive key can never equal a legacy suite-only key.
		{"legacy_domain", sigCacheKey(base.suiteID, base.pubkey, base.sig, base.digest)},
	}
	for _, tc := range cases {
		if tc.key == want {
			t.Fatalf("%s: key collides with the base tuple key", tc.name)
		}
	}
}

// TestSigCache_ConcurrentInsertLookupEvictReset drives insert, lookup, FIFO
// eviction, and Reset from concurrent goroutines under -race. The invariant is
// that the cache never exceeds capacity and never panics; residency is
// deliberately not asserted because Reset races with insertion by design.
func TestSigCache_ConcurrentInsertLookupEvictReset(t *testing.T) {
	const capacity = 8
	c := NewSigCache(capacity)

	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(gid int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				pk, sig, d := syntheticSigCacheTuple(byte(gid*8 + i%8))
				d[1] = byte(i)
				c.Insert(SUITE_ID_ML_DSA_87, pk, sig, d)
				c.lookupBound([]byte("binding"), SUITE_ID_ML_DSA_87, pk, sig, d)
				c.insertBound([]byte("binding"), SUITE_ID_ML_DSA_87, pk, sig, d)
				c.Lookup(SUITE_ID_ML_DSA_87, pk, sig, d)
				if n := c.Len(); n > capacity {
					t.Errorf("cache len=%d exceeds capacity %d", n, capacity)
					return
				}
				if gid == 0 && i%50 == 0 {
					c.Reset()
				}
			}
		}(g)
	}
	wg.Wait()
	if n := c.Len(); n > capacity {
		t.Fatalf("final cache len=%d exceeds capacity %d", n, capacity)
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

func TestSigCache_ZeroValueIsANoOp(t *testing.T) {
	var c SigCache // not built by NewSigCache: no map, no ring
	pk, sig, d := syntheticSigCacheTuple(0x01)
	c.Insert(SUITE_ID_ML_DSA_87, pk, sig, d)
	c.insertBound([]byte("binding"), SUITE_ID_ML_DSA_87, pk, sig, d)
	if c.Lookup(SUITE_ID_ML_DSA_87, pk, sig, d) || c.lookupBound([]byte("binding"), SUITE_ID_ML_DSA_87, pk, sig, d) {
		t.Fatal("zero-value cache must never report a hit")
	}
	if c.Len() != 0 {
		t.Fatalf("zero-value cache len=%d, want 0", c.Len())
	}
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
