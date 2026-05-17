package node

func (s *SyncEngine) HeaderSyncRequest() HeaderRequest {
	if s == nil || s.chainState == nil {
		return HeaderRequest{}
	}
	view := s.chainState.view()
	if !view.hasTip {
		return HeaderRequest{Limit: s.cfg.HeaderBatchLimit}
	}
	return HeaderRequest{
		FromHash: view.tipHash,
		HasFrom:  true,
		Limit:    s.cfg.HeaderBatchLimit,
	}
}

func (s *SyncEngine) RecordBestKnownHeight(height uint64) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if height > s.bestKnownHeight {
		s.bestKnownHeight = height
	}
}

func (s *SyncEngine) BestKnownHeight() uint64 {
	if s == nil {
		return 0
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.bestKnownHeight
}

func (s *SyncEngine) LastReorgDepth() uint64 {
	if s == nil {
		return 0
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastReorgDepth
}

func (s *SyncEngine) ReorgCount() uint64 {
	if s == nil {
		return 0
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.reorgCount
}

func (s *SyncEngine) BlockApplyCounts() BlockApplyCounts {
	if s == nil {
		return BlockApplyCounts{}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.blockApply
}
