package p2p

import (
	"sync"
	"testing"
)

func TestMemoryTxPool_PutAndGet(t *testing.T) {
	pool := NewMemoryTxPool()
	var txid1 [32]byte
	txid1[0] = 0x01
	raw := []byte{0xAA, 0xBB}

	if !pool.Put(txid1, raw, 5, len(raw)) {
		t.Fatal("first Put should return true (new)")
	}
	if pool.Put(txid1, raw, 5, len(raw)) {
		t.Fatal("second Put should return false (overwrite)")
	}

	got, ok := pool.Get(txid1)
	if !ok {
		t.Fatal("Get should return true for existing txid")
	}
	if len(got) != 2 || got[0] != 0xAA || got[1] != 0xBB {
		t.Fatalf("unexpected data: %x", got)
	}
	// Verify defensive copy: modifying returned slice doesn't alter pool
	got[0] = 0xFF
	got2, _ := pool.Get(txid1)
	if got2[0] != 0xAA {
		t.Fatal("Get must return a defensive copy")
	}
}

func TestMemoryTxPool_Has(t *testing.T) {
	pool := NewMemoryTxPool()
	var txid1, txid2 [32]byte
	txid1[0] = 0x01
	txid2[0] = 0x02

	pool.Put(txid1, []byte{0x01}, 1, 1)

	if !pool.Has(txid1) {
		t.Fatal("Has should return true for known txid")
	}
	if pool.Has(txid2) {
		t.Fatal("Has should return false for unknown txid")
	}
}

func TestMemoryTxPool_GetMissing(t *testing.T) {
	pool := NewMemoryTxPool()
	var txid [32]byte
	txid[0] = 0x99

	raw, ok := pool.Get(txid)
	if ok {
		t.Fatal("Get should return false for missing txid")
	}
	if raw != nil {
		t.Fatal("raw should be nil for missing txid")
	}
}

func TestMemoryTxPool_NilReceiver(t *testing.T) {
	var pool *MemoryTxPool

	if pool.Put([32]byte{}, []byte{0x01}, 1, 1) {
		t.Fatal("nil pool Put should return false")
	}
	if pool.Has([32]byte{}) {
		t.Fatal("nil pool Has should return false")
	}
	raw, ok := pool.Get([32]byte{})
	if ok || raw != nil {
		t.Fatal("nil pool Get should return nil, false")
	}
}

func TestCanonicalMempoolTxPoolNilSafe(t *testing.T) {
	var nilPool *CanonicalMempoolTxPool
	var txid [32]byte
	if raw, ok := nilPool.Get(txid); ok || raw != nil {
		t.Fatalf("nil adapter Get=(%x,%v), want nil,false", raw, ok)
	}
	if nilPool.Has(txid) {
		t.Fatal("nil adapter Has should return false")
	}
	if nilPool.Put(txid, []byte{0x01}, 1, 1) {
		t.Fatal("nil adapter Put should return false")
	}

	emptyAdapter := NewCanonicalMempoolTxPool(nil)
	if raw, ok := emptyAdapter.Get(txid); ok || raw != nil {
		t.Fatalf("nil-backed adapter Get=(%x,%v), want nil,false", raw, ok)
	}
	if emptyAdapter.Has(txid) {
		t.Fatal("nil-backed adapter Has should return false")
	}
	if emptyAdapter.Put(txid, []byte{0x01}, 1, 1) {
		t.Fatal("nil-backed adapter Put should return false")
	}
}

func TestMemoryTxPool_ConcurrentSafe(t *testing.T) {
	pool := NewMemoryTxPool()
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			var txid [32]byte
			txid[0] = byte(idx)
			pool.Put(txid, []byte{byte(idx)}, uint64(idx+1), 1)
			pool.Has(txid)
			pool.Get(txid)
		}(i)
	}
	wg.Wait()
}

func TestMemoryTxPoolEvictsWorstFeeRate(t *testing.T) {
	pool := NewMemoryTxPoolWithLimit(2)
	var low [32]byte
	low[0] = 0x10
	var mid [32]byte
	mid[0] = 0x20
	var high [32]byte
	high[0] = 0x30

	if !pool.Put(low, []byte{0x01}, 1, 4) {
		t.Fatal("low Put should succeed")
	}
	if !pool.Put(mid, []byte{0x02}, 2, 4) {
		t.Fatal("mid Put should succeed")
	}
	if !pool.Put(high, []byte{0x03}, 9, 4) {
		t.Fatal("high Put should evict the lowest feerate entry")
	}
	if pool.Has(low) {
		t.Fatal("lowest feerate tx should be evicted")
	}
	if !pool.Has(mid) || !pool.Has(high) {
		t.Fatal("higher priority entries should remain")
	}
}

func TestMemoryTxPoolRejectsWorseCandidateWhenFull(t *testing.T) {
	pool := NewMemoryTxPoolWithLimit(2)
	var a [32]byte
	a[0] = 0x01
	var b [32]byte
	b[0] = 0x02
	var candidate [32]byte
	candidate[0] = 0x03

	if !pool.Put(a, []byte{0x01}, 10, 2) {
		t.Fatal("first Put should succeed")
	}
	if !pool.Put(b, []byte{0x02}, 8, 2) {
		t.Fatal("second Put should succeed")
	}
	if pool.Put(candidate, []byte{0x03}, 1, 4) {
		t.Fatal("worse feerate candidate should be rejected")
	}
	if !pool.Has(a) || !pool.Has(b) {
		t.Fatal("existing entries should remain after rejecting worse candidate")
	}
}

func TestMemoryTxPoolPutFallsBackToRawLength(t *testing.T) {
	pool := NewMemoryTxPool()
	var txid [32]byte
	txid[0] = 0x44
	raw := []byte{0xAA, 0xBB, 0xCC}
	if !pool.Put(txid, raw, 5, 0) {
		t.Fatal("Put with size=0 should fall back to len(raw)")
	}
	if !pool.Has(txid) {
		t.Fatal("pool should contain tx admitted via size fallback")
	}
}

func TestCompareRelayPriorityTieBreakers(t *testing.T) {
	var low [32]byte
	low[31] = 0x10
	var high [32]byte
	high[31] = 0x20
	if got := compareRelayPriority(5, 2, low, 4, 2, high); got <= 0 {
		t.Fatalf("higher feerate should win, got %d", got)
	}
	if got := compareRelayPriority(6, 3, low, 4, 2, high); got <= 0 {
		t.Fatalf("higher absolute fee should win on equal feerate, got %d", got)
	}
	if got := compareRelayPriority(4, 2, low, 4, 2, high); got <= 0 {
		t.Fatalf("lower txid should win final tie-break, got %d", got)
	}
	if got := compareRelayFeeRate(0, 0, 1, 1); got != 0 {
		t.Fatalf("invalid sizes should compare equal, got %d", got)
	}
}
