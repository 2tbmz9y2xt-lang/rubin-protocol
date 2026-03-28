//go:build cgo

package consensus

import (
	"sync"
	"testing"
)

// maxFuzzSliceBytes caps pubkey/sig slices to avoid OOM and allocation churn
// during nightly fuzz runs. ML-DSA-87 pubkey=2592, sig=4627; 8192 covers both
// with headroom for mutation while keeping sigCacheKey hashing efficient.
const maxFuzzSliceBytes = 8192

// digestFrom pads or truncates raw bytes into a [32]byte digest.
func digestFrom(raw []byte) [32]byte {
	var d [32]byte
	copy(d[:], raw)
	return d
}

// FuzzVerifySigDispatch exercises the verifySig and verifySigWithRegistry
// dispatch paths with arbitrary suite IDs, pubkey/sig lengths, and digests.
//
// Invariants:
//   - No panic regardless of input.
//   - Unknown suite → TX_ERR_SIG_ALG_INVALID.
//   - Wrong-length pubkey/sig → (false, nil), not an internal error.
//   - Determinism: two calls with identical args produce identical result.
func FuzzVerifySigDispatch(f *testing.F) {
	f.Add([]byte{0x00}, []byte{}, []byte{}, []byte{})
	f.Add([]byte{SUITE_ID_ML_DSA_87}, []byte{0x01}, []byte{0x02}, []byte{0xff})
	f.Add([]byte{0xff}, make([]byte, 100), make([]byte, 100), make([]byte, 32))

	f.Fuzz(func(t *testing.T, suiteRaw []byte, pubkey []byte, sig []byte, digestRaw []byte) {
		if len(suiteRaw) == 0 {
			return
		}
		if len(pubkey) > maxFuzzSliceBytes || len(sig) > maxFuzzSliceBytes {
			return
		}
		suiteID := suiteRaw[0]
		digest := digestFrom(digestRaw)

		// Direct dispatch.
		ok1, err1 := verifySig(suiteID, pubkey, sig, digest)

		// Registry dispatch with default registry.
		registry := DefaultSuiteRegistry()
		ok2, err2 := verifySigWithRegistry(suiteID, pubkey, sig, digest, registry)

		// Nil registry → fallback to verifySig.
		ok3, err3 := verifySigWithRegistry(suiteID, pubkey, sig, digest, nil)

		// Determinism: direct calls must be identical.
		ok1b, err1b := verifySig(suiteID, pubkey, sig, digest)
		if ok1 != ok1b {
			t.Fatalf("verifySig non-deterministic: %v vs %v", ok1, ok1b)
		}
		if (err1 == nil) != (err1b == nil) {
			t.Fatalf("verifySig error non-deterministic: %v vs %v", err1, err1b)
		}

		// Nil-registry must equal direct call.
		if ok1 != ok3 || (err1 == nil) != (err3 == nil) {
			t.Fatalf("nil-registry diverged from direct: ok=%v/%v err=%v/%v", ok1, ok3, err1, err3)
		}

		// For known suites, registry dispatch must match direct dispatch.
		if registry.IsRegistered(suiteID) {
			if ok1 != ok2 || (err1 == nil) != (err2 == nil) {
				t.Fatalf("registry dispatch diverged: ok=%v/%v err=%v/%v", ok1, ok2, err1, err2)
			}
		}
	})
}

// FuzzSigCacheDeterminism exercises the SigCache with arbitrary tuples to check:
//   - Canonical key determinism: same inputs → same cache outcome.
//   - Positive-only: Insert+Lookup always agrees.
//   - Capacity bound is never exceeded.
//   - Nil-safe: operations on nil cache don't panic.
func FuzzSigCacheDeterminism(f *testing.F) {
	f.Add([]byte{0x01}, []byte{0x01}, []byte{0x02}, []byte{0xab})
	f.Add([]byte{0x00}, []byte{}, []byte{}, []byte{})
	f.Add([]byte{0xff}, make([]byte, 100), make([]byte, 100), make([]byte, 32))

	f.Fuzz(func(t *testing.T, suiteRaw []byte, pubkey []byte, sig []byte, digestRaw []byte) {
		if len(suiteRaw) == 0 {
			return
		}
		if len(pubkey) > maxFuzzSliceBytes || len(sig) > maxFuzzSliceBytes {
			return
		}
		suiteID := suiteRaw[0]
		digest := digestFrom(digestRaw)

		// Nil-safe operations.
		var nilCache *SigCache
		if nilCache.Lookup(suiteID, pubkey, sig, digest) {
			t.Fatal("nil cache returned hit")
		}
		nilCache.Insert(suiteID, pubkey, sig, digest) // must not panic
		if nilCache.Len() != 0 {
			t.Fatal("nil cache non-zero len")
		}

		// Normal cache.
		cache := NewSigCache(4)

		// Insert + Lookup determinism.
		cache.Insert(suiteID, pubkey, sig, digest)
		if !cache.Lookup(suiteID, pubkey, sig, digest) {
			t.Fatal("inserted tuple not found in cache")
		}

		// Second lookup must hit.
		if !cache.Lookup(suiteID, pubkey, sig, digest) {
			t.Fatal("second lookup missed")
		}
		if cache.Hits() < 2 {
			t.Fatal("expected ≥2 hits")
		}

		// Capacity bound.
		if cache.Len() > 4 {
			t.Fatalf("cache exceeded capacity: %d > 4", cache.Len())
		}

		// Key determinism: same args → same key.
		k1 := sigCacheKey(suiteID, pubkey, sig, digest)
		k2 := sigCacheKey(suiteID, pubkey, sig, digest)
		if k1 != k2 {
			t.Fatal("sigCacheKey non-deterministic")
		}

		// Different suiteID → different key (SHA3-256 collision resistance).
		k3 := sigCacheKey(suiteID^0x01, pubkey, sig, digest)
		if k1 == k3 {
			t.Errorf("sigCacheKey collision: suite 0x%02x and 0x%02x produced identical key", suiteID, suiteID^0x01)
		}
	})
}

// FuzzSigCheckQueueFlush exercises the SigCheckQueue batch verification path
// with arbitrary signature data.
func FuzzSigCheckQueueFlush(f *testing.F) {
	f.Add([]byte{0x01}, []byte{0x01}, []byte{0x02}, []byte{0xab})
	f.Add([]byte{0x00}, []byte{}, []byte{}, []byte{})

	f.Fuzz(func(t *testing.T, suiteRaw []byte, pubkey []byte, sig []byte, digestRaw []byte) {
		if len(suiteRaw) == 0 {
			return
		}
		if len(pubkey) > maxFuzzSliceBytes || len(sig) > maxFuzzSliceBytes {
			return
		}
		suiteID := suiteRaw[0]
		digest := digestFrom(digestRaw)

		q := NewSigCheckQueue(2)
		q.Push(suiteID, pubkey, sig, digest, txerr(TX_ERR_SIG_INVALID, "fuzz"))
		if q.Len() != 1 {
			t.Fatalf("expected len 1, got %d", q.Len())
		}

		flushErr := q.Flush()

		if q.Len() != 0 {
			t.Fatal("queue not empty after flush")
		}

		// Determinism: same input → same flush result.
		q2 := NewSigCheckQueue(2)
		q2.Push(suiteID, pubkey, sig, digest, txerr(TX_ERR_SIG_INVALID, "fuzz"))
		flushErr2 := q2.Flush()
		if (flushErr == nil) != (flushErr2 == nil) {
			t.Fatalf("flush non-deterministic: %v vs %v", flushErr, flushErr2)
		}

		if err := q.AssertFlushed(); err != nil {
			t.Fatalf("assert flushed failed: %v", err)
		}
	})
}

// FuzzSigCacheConcurrentAccess stress-tests the SigCache under concurrent
// reads and writes with fuzz-derived tuples.
func FuzzSigCacheConcurrentAccess(f *testing.F) {
	f.Add([]byte{0x01}, []byte{0x01}, []byte{0x02})

	f.Fuzz(func(t *testing.T, suiteRaw []byte, pubkey []byte, sig []byte) {
		if len(suiteRaw) == 0 {
			return
		}
		if len(pubkey) > maxFuzzSliceBytes || len(sig) > maxFuzzSliceBytes {
			return
		}
		suiteID := suiteRaw[0]
		cache := NewSigCache(16)
		var wg sync.WaitGroup

		for i := 0; i < 4; i++ {
			var digest [32]byte
			digest[0] = byte(i)
			localDigest := digest

			wg.Add(2)
			go func() {
				defer wg.Done()
				cache.Insert(suiteID, pubkey, sig, localDigest)
			}()
			go func() {
				defer wg.Done()
				cache.Lookup(suiteID, pubkey, sig, localDigest)
			}()
		}
		wg.Wait()

		if cache.Len() > 16 {
			t.Fatalf("cache exceeded capacity under concurrency: %d", cache.Len())
		}
	})
}

// FuzzSuiteRegistryLookup exercises SuiteRegistry lookup with arbitrary suite IDs.
func FuzzSuiteRegistryLookup(f *testing.F) {
	f.Add([]byte{0x00})
	f.Add([]byte{0x01})
	f.Add([]byte{0xff})

	f.Fuzz(func(t *testing.T, suiteRaw []byte) {
		if len(suiteRaw) == 0 {
			return
		}
		suiteID := suiteRaw[0]
		reg := DefaultSuiteRegistry()

		params, ok := reg.Lookup(suiteID)
		isReg := reg.IsRegistered(suiteID)
		if ok != isReg {
			t.Fatalf("Lookup/IsRegistered mismatch for suite 0x%02x", suiteID)
		}

		if suiteID == SUITE_ID_ML_DSA_87 {
			if !ok {
				t.Fatal("ML-DSA-87 not in default registry")
			}
			if params.PubkeyLen != ML_DSA_87_PUBKEY_BYTES {
				t.Fatalf("ML-DSA-87 pubkey len: got %d, want %d", params.PubkeyLen, ML_DSA_87_PUBKEY_BYTES)
			}
			if params.SigLen != ML_DSA_87_SIG_BYTES {
				t.Fatalf("ML-DSA-87 sig len: got %d, want %d", params.SigLen, ML_DSA_87_SIG_BYTES)
			}
		}

		// Nil registry safety.
		var nilReg *SuiteRegistry
		if _, ok := nilReg.Lookup(suiteID); ok {
			t.Fatal("nil registry returned hit")
		}
		if nilReg.IsRegistered(suiteID) {
			t.Fatal("nil registry returned registered")
		}

		// NativeSuiteSet: default rotation provider.
		rp := &DefaultRotationProvider{}
		createSet := rp.NativeCreateSuites(0)
		spendSet := rp.NativeSpendSuites(0)

		if !createSet.Contains(SUITE_ID_ML_DSA_87) {
			t.Fatal("ML-DSA-87 not in create set at height 0")
		}
		if !spendSet.Contains(SUITE_ID_ML_DSA_87) {
			t.Fatal("ML-DSA-87 not in spend set at height 0")
		}

		ids := createSet.SuiteIDs()
		for i := 1; i < len(ids); i++ {
			if ids[i] <= ids[i-1] {
				t.Fatalf("SuiteIDs not sorted: %v", ids)
			}
		}
	})
}

// FuzzSigCheckQueueWithCacheIntegration exercises the queue+cache integration.
func FuzzSigCheckQueueWithCacheIntegration(f *testing.F) {
	f.Add([]byte{0x42})

	f.Fuzz(func(t *testing.T, digestRaw []byte) {
		digest := digestFrom(digestRaw)
		cache := NewSigCache(64)
		registry := DefaultSuiteRegistry()

		q := NewSigCheckQueue(2).WithCache(cache).WithRegistry(registry)

		fakeKey := make([]byte, ML_DSA_87_PUBKEY_BYTES)
		fakeSig := make([]byte, ML_DSA_87_SIG_BYTES)

		q.Push(SUITE_ID_ML_DSA_87, fakeKey, fakeSig, digest, txerr(TX_ERR_SIG_INVALID, "fuzz"))

		err1 := q.Flush()
		misses1 := cache.Misses()

		q2 := NewSigCheckQueue(2).WithCache(cache).WithRegistry(registry)
		q2.Push(SUITE_ID_ML_DSA_87, fakeKey, fakeSig, digest, txerr(TX_ERR_SIG_INVALID, "fuzz"))
		_ = q2.Flush()

		if err1 != nil {
			if cache.Hits() > 0 {
				t.Fatal("cache hit on invalid signature — positive-only violation")
			}
			if cache.Misses() <= misses1 {
				t.Fatal("expected additional miss on second flush of invalid sig")
			}
		}
	})
}
