package p2p

import "sync"

const (
	// defaultBlockSeenCapacity is the maximum number of block hashes to
	// remember for relay deduplication.  10 000 blocks at ~10 min/block
	// covers roughly 70 days of chain history.
	defaultBlockSeenCapacity = 10_000

	// defaultTxSeenCapacity is the maximum number of transaction hashes
	// to remember.  50 000 txids covers more than a full day at peak
	// throughput and is sufficient to break inv/getdata relay loops.
	defaultTxSeenCapacity = 50_000
)

// boundedHashSet is a thread-safe bounded FIFO set of [32]byte hashes.
// When the set reaches capacity, the oldest entry is evicted to make room.
// This prevents unbounded memory growth for long-running nodes.
//
// Implementation: map for O(1) lookup + fixed-size ring buffer for FIFO
// eviction order.  All operations are O(1) amortized.
type boundedHashSet struct {
	mu   sync.RWMutex
	cap  int
	ring [][32]byte
	next int
	// items provides O(1) membership tests.
	items map[[32]byte]struct{}
}

func newBoundedHashSet(capacity int) *boundedHashSet {
	if capacity <= 0 {
		capacity = defaultTxSeenCapacity
	}
	return &boundedHashSet{
		cap:   capacity,
		ring:  make([][32]byte, capacity),
		items: make(map[[32]byte]struct{}, capacity),
	}
}

// Add inserts hash into the set.  Returns true if the hash was newly
// added, false if it was already present.  When the set is at capacity
// the oldest entry is evicted (FIFO) before the new one is stored.
func (s *boundedHashSet) Add(hash [32]byte) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.items[hash]; exists {
		return false
	}
	// Evict the oldest entry when the set is full.
	if len(s.items) >= s.cap {
		for i := 0; i < s.cap; i++ {
			idx := (s.next + i) % s.cap
			if _, exists := s.items[s.ring[idx]]; !exists {
				continue
			}
			delete(s.items, s.ring[idx])
			s.next = idx
			break
		}
	}
	s.ring[s.next] = hash
	s.items[hash] = struct{}{}
	s.next = (s.next + 1) % s.cap
	return true
}

// Has returns true if hash is in the set.
func (s *boundedHashSet) Has(hash [32]byte) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, exists := s.items[hash]
	return exists
}

// Remove deletes hash from the set. Returns true if an entry was removed.
func (s *boundedHashSet) Remove(hash [32]byte) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.items[hash]; !exists {
		return false
	}
	delete(s.items, hash)
	return true
}

// Len returns the current number of entries in the set.
func (s *boundedHashSet) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.items)
}
