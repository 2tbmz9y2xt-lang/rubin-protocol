package p2p

import (
	"sync"
	"testing"
)

func TestHashSet_AddAndHas(t *testing.T) {
	s := newHashSet()

	var h1, h2 [32]byte
	h1[0] = 0x01
	h2[0] = 0x02

	// First add returns true
	if !s.Add(h1) {
		t.Fatal("first Add should return true")
	}
	// Duplicate returns false
	if s.Add(h1) {
		t.Fatal("duplicate Add should return false")
	}
	if !s.Has(h1) {
		t.Fatal("Has should return true for added hash")
	}
	if s.Has(h2) {
		t.Fatal("Has should return false for unknown hash")
	}
}

func TestHashSet_ConcurrentSafe(t *testing.T) {
	s := newHashSet()
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
