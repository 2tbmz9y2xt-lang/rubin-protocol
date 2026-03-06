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

	if !pool.Put(txid1, raw) {
		t.Fatal("first Put should return true (new)")
	}
	if pool.Put(txid1, raw) {
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

	pool.Put(txid1, []byte{0x01})

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

	if pool.Put([32]byte{}, []byte{0x01}) {
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

func TestMemoryTxPool_ConcurrentSafe(t *testing.T) {
	pool := NewMemoryTxPool()
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			var txid [32]byte
			txid[0] = byte(idx)
			pool.Put(txid, []byte{byte(idx)})
			pool.Has(txid)
			pool.Get(txid)
		}(i)
	}
	wg.Wait()
}
