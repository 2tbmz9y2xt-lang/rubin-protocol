package p2p

import "testing"

func TestOrphanEviction(t *testing.T) {
	pool := newOrphanPool(500)
	var sharedParent [32]byte
	sharedParent[31] = 0x99
	var oldestHash [32]byte
	oldestHash[31] = 1
	for i := 0; i < 501; i++ {
		var blockHash [32]byte
		blockHash[30] = byte((i + 1) >> 8)
		blockHash[31] = byte(i + 1)
		if !pool.Add(blockHash, sharedParent, []byte{byte(i)}) {
			t.Fatalf("Add(%d) unexpectedly rejected", i)
		}
	}
	if got := pool.Len(); got != 500 {
		t.Fatalf("Len()=%d, want 500", got)
	}
	children := pool.TakeChildren(sharedParent)
	if len(children) != 500 {
		t.Fatalf("children=%d, want 500", len(children))
	}
	for _, child := range children {
		if child.blockHash == oldestHash {
			t.Fatalf("oldest orphan was not evicted")
		}
	}
}
