package p2p

import "sync"

type hashSet struct {
	mu    sync.RWMutex
	items map[[32]byte]struct{}
}

func newHashSet() *hashSet {
	return &hashSet{
		items: make(map[[32]byte]struct{}),
	}
}

func (s *hashSet) Add(hash [32]byte) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.items[hash]; exists {
		return false
	}
	s.items[hash] = struct{}{}
	return true
}

func (s *hashSet) Has(hash [32]byte) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, exists := s.items[hash]
	return exists
}
