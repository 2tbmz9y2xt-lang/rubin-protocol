package p2p

import "testing"

func TestOrphanPoolDefaultLimitAndDedup(t *testing.T) {
	pool := newOrphanPool(0)
	if pool.limit != 500 {
		t.Fatalf("limit=%d, want 500", pool.limit)
	}
	if pool.byteLimit != defaultOrphanByteLimit {
		t.Fatalf("byteLimit=%d, want %d", pool.byteLimit, defaultOrphanByteLimit)
	}
	var parent [32]byte
	parent[31] = 0x55
	var blockHash [32]byte
	blockHash[31] = 0x77
	if added, _ := pool.Add(blockHash, parent, []byte{0x01, 0x02}); !added {
		t.Fatalf("expected first add to succeed")
	}
	if added, _ := pool.Add(blockHash, parent, []byte{0x03}); added {
		t.Fatalf("expected duplicate add to be rejected")
	}
	children := pool.TakeChildren(parent)
	if len(children) != 1 {
		t.Fatalf("children=%d, want 1", len(children))
	}
	if got := pool.Len(); got != 0 {
		t.Fatalf("Len()=%d, want 0", got)
	}
	if got := len(pool.fifo); got != 0 {
		t.Fatalf("fifo_len=%d, want 0", got)
	}
	if got := pool.totalBytes; got != 0 {
		t.Fatalf("totalBytes=%d, want 0", got)
	}
}

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
		if added, _ := pool.Add(blockHash, sharedParent, []byte{byte(i)}); !added {
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

func TestOrphanPoolNilReceiverAdd(t *testing.T) {
	var pool *orphanPool
	added, evicted := pool.Add([32]byte{1}, [32]byte{2}, []byte{0x01})
	if added {
		t.Fatalf("nil receiver Add must return false")
	}
	if evicted != nil {
		t.Fatalf("nil receiver Add must return nil evicted")
	}
	if pool.Len() != 0 {
		t.Fatalf("nil receiver Len must return 0")
	}
}

func TestOrphanPoolEvictedHashesReturned(t *testing.T) {
	pool := newOrphanPool(2)
	var parent [32]byte
	parent[31] = 0xAA
	var h1, h2, h3 [32]byte
	h1[31] = 0x01
	h2[31] = 0x02
	h3[31] = 0x03

	if added, evicted := pool.Add(h1, parent, []byte{1}); !added || len(evicted) != 0 {
		t.Fatalf("first add: added=%v evicted=%d", added, len(evicted))
	}
	if added, evicted := pool.Add(h2, parent, []byte{2}); !added || len(evicted) != 0 {
		t.Fatalf("second add: added=%v evicted=%d", added, len(evicted))
	}
	added, evicted := pool.Add(h3, parent, []byte{3})
	if !added {
		t.Fatalf("third add must succeed")
	}
	if len(evicted) != 1 || evicted[0] != h1 {
		t.Fatalf("expected h1 evicted, got %v", evicted)
	}
}

func TestOrphanPoolRejectsOversizedBlocksAndCapsBytes(t *testing.T) {
	pool := newOrphanPool(500)
	pool.byteLimit = 8

	var parent [32]byte
	parent[31] = 0x01
	var first [32]byte
	first[31] = 0x02
	var second [32]byte
	second[31] = 0x03

	if added, _ := pool.Add(first, parent, make([]byte, 9)); added {
		t.Fatalf("expected oversized orphan rejection")
	}
	if added, _ := pool.Add(first, parent, []byte{1, 2, 3, 4, 5}); !added {
		t.Fatalf("expected first orphan add")
	}
	if added, _ := pool.Add(second, parent, []byte{6, 7, 8, 9, 10}); !added {
		t.Fatalf("expected second orphan add")
	}
	if got := pool.Len(); got != 1 {
		t.Fatalf("Len()=%d, want 1 after byte-budget eviction", got)
	}
	children := pool.TakeChildren(parent)
	if len(children) != 1 || children[0].blockHash != second {
		t.Fatalf("children=%v, want only newest surviving orphan", children)
	}
	if got := pool.totalBytes; got != 0 {
		t.Fatalf("totalBytes=%d, want 0 after draining pool", got)
	}
}
