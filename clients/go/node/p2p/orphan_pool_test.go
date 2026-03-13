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
	if added, _ := pool.Add(blockHash, parent, []byte{0x01, 0x02}, "peer-a"); !added {
		t.Fatalf("expected first add to succeed")
	}
	if added, _ := pool.Add(blockHash, parent, []byte{0x03}, "peer-a"); added {
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
		if added, _ := pool.Add(blockHash, sharedParent, []byte{byte(i)}, ""); !added {
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
	added, evicted := pool.Add([32]byte{1}, [32]byte{2}, []byte{0x01}, "")
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

	if added, evicted := pool.Add(h1, parent, []byte{1}, "peer-c"); !added || len(evicted) != 0 {
		t.Fatalf("first add: added=%v evicted=%d", added, len(evicted))
	}
	if added, evicted := pool.Add(h2, parent, []byte{2}, "peer-c"); !added || len(evicted) != 0 {
		t.Fatalf("second add: added=%v evicted=%d", added, len(evicted))
	}
	added, evicted := pool.Add(h3, parent, []byte{3}, "peer-c")
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

	if added, _ := pool.Add(first, parent, make([]byte, 9), "peer-d"); added {
		t.Fatalf("expected oversized orphan rejection")
	}
	if added, _ := pool.Add(first, parent, []byte{1, 2, 3, 4, 5}, "peer-d"); !added {
		t.Fatalf("expected first orphan add")
	}
	if added, _ := pool.Add(second, parent, []byte{6, 7, 8, 9, 10}, "peer-d"); !added {
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

func TestOrphanPoolPerPeerQuota(t *testing.T) {
	pool := newOrphanPool(500)
	pool.perPeerLimit = 3

	var parent [32]byte
	parent[31] = 0xBB

	// Peer "attacker" submits 3 orphans — all accepted.
	for i := 0; i < 3; i++ {
		var h [32]byte
		h[31] = byte(i + 1)
		added, _ := pool.Add(h, parent, []byte{byte(i)}, "attacker")
		if !added {
			t.Fatalf("add %d: expected accepted", i)
		}
	}
	// 4th from same peer is rejected.
	var h4 [32]byte
	h4[31] = 0x04
	if added, _ := pool.Add(h4, parent, []byte{0x04}, "attacker"); added {
		t.Fatalf("expected per-peer quota rejection")
	}
	// Different peer can still add.
	var h5 [32]byte
	h5[31] = 0x05
	if added, _ := pool.Add(h5, parent, []byte{0x05}, "honest"); !added {
		t.Fatalf("honest peer should not be blocked by attacker quota")
	}
	// Empty peer (e.g. resolveOrphans internal) is never throttled.
	var h6 [32]byte
	h6[31] = 0x06
	if added, _ := pool.Add(h6, parent, []byte{0x06}, ""); !added {
		t.Fatalf("empty peer should bypass quota")
	}
}

func TestOrphanPoolPeerCounterDecrementsOnEvictAndTake(t *testing.T) {
	pool := newOrphanPool(2)

	var parent [32]byte
	parent[31] = 0xCC
	var h1, h2, h3 [32]byte
	h1[31] = 0x01
	h2[31] = 0x02
	h3[31] = 0x03

	pool.Add(h1, parent, []byte{1}, "peerX")
	pool.Add(h2, parent, []byte{2}, "peerX")
	// h3 triggers eviction of h1 → peerX count should drop from 2 back to 2 (add h3, evict h1).
	pool.Add(h3, parent, []byte{3}, "peerX")

	pool.mu.Lock()
	cnt := pool.peerOrphanCnt["peerX"]
	pool.mu.Unlock()
	if cnt != 2 {
		t.Fatalf("peerOrphanCnt[peerX]=%d, want 2 after eviction", cnt)
	}

	// TakeChildren drains all → counter should be 0 (cleaned up).
	pool.TakeChildren(parent)
	pool.mu.Lock()
	_, exists := pool.peerOrphanCnt["peerX"]
	pool.mu.Unlock()
	if exists {
		t.Fatalf("peerOrphanCnt[peerX] should be cleaned up after TakeChildren")
	}
}

// TestOrphanPoolEvictionCleansUpPeerCounterToZero verifies that when a peer's
// only orphan is evicted, the peerOrphanCnt entry is fully deleted (not left
// at 0), covering the evictOldest cleanup path.
func TestOrphanPoolEvictionCleansUpPeerCounterToZero(t *testing.T) {
	pool := newOrphanPool(1) // limit=1, so second add evicts first
	var parent [32]byte
	parent[31] = 0xDD

	var h1, h2 [32]byte
	h1[31] = 0x01
	h2[31] = 0x02

	// Add one orphan from "solo-peer".
	pool.Add(h1, parent, []byte{1}, "solo-peer")
	// Add another from different peer → evicts h1 → solo-peer count drops to 0.
	pool.Add(h2, parent, []byte{2}, "other-peer")

	pool.mu.Lock()
	_, soloExists := pool.peerOrphanCnt["solo-peer"]
	otherCnt := pool.peerOrphanCnt["other-peer"]
	pool.mu.Unlock()

	if soloExists {
		t.Fatalf("peerOrphanCnt[solo-peer] should be deleted after eviction")
	}
	if otherCnt != 1 {
		t.Fatalf("peerOrphanCnt[other-peer]=%d, want 1", otherCnt)
	}
}

func TestOrphanPoolQuotaKeyNormalisesToIP(t *testing.T) {
	pool := newOrphanPool(500)
	pool.perPeerLimit = 2

	var parent [32]byte
	parent[31] = 0xEE

	// Two different ip:port pairs from the same IP should share quota.
	var h1, h2, h3 [32]byte
	h1[31] = 0x01
	h2[31] = 0x02
	h3[31] = 0x03

	if added, _ := pool.Add(h1, parent, []byte{1}, "10.0.0.1:40000"); !added {
		t.Fatalf("first add should succeed")
	}
	if added, _ := pool.Add(h2, parent, []byte{2}, "10.0.0.1:40001"); !added {
		t.Fatalf("second add should succeed (same IP, different port)")
	}
	// Third from same IP must be rejected (quota = 2).
	if added, _ := pool.Add(h3, parent, []byte{3}, "10.0.0.1:40002"); added {
		t.Fatalf("third add from same IP should be rejected by per-IP quota")
	}
}

func TestPeerQuotaKeyEdgeCases(t *testing.T) {
	if got := peerQuotaKey(""); got != "" {
		t.Fatalf("peerQuotaKey(\"\") = %q, want \"\"", got)
	}
	if got := peerQuotaKey("10.0.0.1:8080"); got != "10.0.0.1" {
		t.Fatalf("peerQuotaKey(\"10.0.0.1:8080\") = %q, want \"10.0.0.1\"", got)
	}
	if got := peerQuotaKey("[::1]:9000"); got != "::1" {
		t.Fatalf("peerQuotaKey(\"[::1]:9000\") = %q, want \"::1\"", got)
	}
	if got := peerQuotaKey("[fe80::1%en0]:9000"); got != "fe80::1" {
		t.Fatalf("peerQuotaKey(\"[fe80::1%%en0]:9000\") = %q, want \"fe80::1\"", got)
	}
	if got := peerQuotaKey("fe80::1%en1"); got != "fe80::1" {
		t.Fatalf("peerQuotaKey(\"fe80::1%%en1\") = %q, want \"fe80::1\"", got)
	}
	if got := peerQuotaKey("bare-hostname"); got != "bare-hostname" {
		t.Fatalf("peerQuotaKey(\"bare-hostname\") = %q, want \"bare-hostname\"", got)
	}
}
