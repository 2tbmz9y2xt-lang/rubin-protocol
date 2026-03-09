package p2p

import (
	"sync"
	"testing"
)

func TestBoundedHashSet_AddAndHas(t *testing.T) {
	s := newBoundedHashSet(100)

	var h1, h2 [32]byte
	h1[0] = 0x01
	h2[0] = 0x02

	// First add returns true.
	if !s.Add(h1) {
		t.Fatal("first Add should return true")
	}
	// Duplicate returns false.
	if s.Add(h1) {
		t.Fatal("duplicate Add should return false")
	}
	if !s.Has(h1) {
		t.Fatal("Has should return true for added hash")
	}
	if s.Has(h2) {
		t.Fatal("Has should return false for unknown hash")
	}
	if s.Len() != 1 {
		t.Fatalf("Len should be 1, got %d", s.Len())
	}
}

func TestBoundedHashSet_ConcurrentSafe(t *testing.T) {
	s := newBoundedHashSet(200)
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			var h [32]byte
			h[0] = byte(idx)
			s.Add(h)
			s.Has(h)
		}(i)
	}
	wg.Wait()
}

func TestBoundedHashSet_EvictsOldest(t *testing.T) {
	const cap = 5
	s := newBoundedHashSet(cap)

	hashes := make([][32]byte, cap+3)
	for i := range hashes {
		hashes[i][0] = byte(i + 1)
	}

	// Fill to capacity.
	for i := 0; i < cap; i++ {
		if !s.Add(hashes[i]) {
			t.Fatalf("Add(%d) should succeed", i)
		}
	}
	if s.Len() != cap {
		t.Fatalf("expected Len=%d, got %d", cap, s.Len())
	}

	// All entries present.
	for i := 0; i < cap; i++ {
		if !s.Has(hashes[i]) {
			t.Fatalf("hash %d should be present before eviction", i)
		}
	}

	// Add one more — oldest (index 0) should be evicted.
	if !s.Add(hashes[cap]) {
		t.Fatal("Add beyond capacity should succeed (evicts oldest)")
	}
	if s.Len() != cap {
		t.Fatalf("Len should remain %d after eviction, got %d", cap, s.Len())
	}
	if s.Has(hashes[0]) {
		t.Fatal("oldest hash (index 0) should have been evicted")
	}
	if !s.Has(hashes[cap]) {
		t.Fatal("newly added hash should be present")
	}
	// Entries 1..cap-1 should still be present.
	for i := 1; i < cap; i++ {
		if !s.Has(hashes[i]) {
			t.Fatalf("hash %d should still be present", i)
		}
	}

	// Add two more — evict indices 1 and 2.
	if !s.Add(hashes[cap+1]) {
		t.Fatal("Add should succeed")
	}
	if !s.Add(hashes[cap+2]) {
		t.Fatal("Add should succeed")
	}
	if s.Has(hashes[1]) {
		t.Fatal("hash 1 should have been evicted")
	}
	if s.Has(hashes[2]) {
		t.Fatal("hash 2 should have been evicted")
	}
	if s.Len() != cap {
		t.Fatalf("Len should be %d, got %d", cap, s.Len())
	}
}

func TestBoundedHashSet_DuplicateAfterEviction(t *testing.T) {
	const cap = 3
	s := newBoundedHashSet(cap)

	var a, b, c, d [32]byte
	a[0] = 0x0A
	b[0] = 0x0B
	c[0] = 0x0C
	d[0] = 0x0D

	s.Add(a) // ring: [A, _, _]
	s.Add(b) // ring: [A, B, _]
	s.Add(c) // ring: [A, B, C]  — full
	s.Add(d) // ring: [D, B, C]  — A evicted

	// A was evicted, re-adding should succeed.
	if !s.Add(a) {
		t.Fatal("re-adding evicted hash should return true")
	}
	if !s.Has(a) {
		t.Fatal("re-added hash should be present")
	}
	// B was evicted to make room for A.
	if s.Has(b) {
		t.Fatal("hash B should have been evicted when A was re-added")
	}
	if s.Len() != cap {
		t.Fatalf("Len should be %d, got %d", cap, s.Len())
	}
}

func TestBoundedHashSet_ZeroCapacityUsesDefault(t *testing.T) {
	s := newBoundedHashSet(0)
	if s.cap != defaultTxSeenCapacity {
		t.Fatalf("cap(0) should default to %d, got %d", defaultTxSeenCapacity, s.cap)
	}
	neg := newBoundedHashSet(-5)
	if neg.cap != defaultTxSeenCapacity {
		t.Fatalf("cap(-5) should default to %d, got %d", defaultTxSeenCapacity, neg.cap)
	}
}

func TestBoundedHashSet_CapacityOne(t *testing.T) {
	s := newBoundedHashSet(1)
	var a, b [32]byte
	a[0] = 0x01
	b[0] = 0x02

	if !s.Add(a) {
		t.Fatal("Add A should succeed")
	}
	if s.Len() != 1 {
		t.Fatalf("expected Len=1, got %d", s.Len())
	}
	if !s.Add(b) {
		t.Fatal("Add B should succeed (evicts A)")
	}
	if s.Has(a) {
		t.Fatal("A should be evicted")
	}
	if !s.Has(b) {
		t.Fatal("B should be present")
	}
	if s.Len() != 1 {
		t.Fatalf("expected Len=1 after eviction, got %d", s.Len())
	}
}

func TestBoundedHashSet_RemoveExistingAndNonExistent(t *testing.T) {
	s := newBoundedHashSet(10)
	var h1, h2 [32]byte
	h1[0] = 0x01
	h2[0] = 0x02

	s.Add(h1)

	// Remove existing entry.
	if !s.Remove(h1) {
		t.Fatal("Remove existing hash must return true")
	}
	if s.Has(h1) {
		t.Fatal("removed hash must not be present")
	}
	// Remove non-existent entry.
	if s.Remove(h2) {
		t.Fatal("Remove non-existent hash must return false")
	}
	if s.Len() != 0 {
		t.Fatalf("Len()=%d, want 0", s.Len())
	}
}
