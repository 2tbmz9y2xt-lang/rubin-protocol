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

// TerminalFaulted reports whether this engine has latched the terminal storage
// persistence fault that closes admission until the node is restarted. It is the
// read-only projection of the EXISTING latch (the same one mutationAllowed fails
// closed on), for operator surfaces such as GET /health.
//
// It exposes only the boolean: the latched cause is never returned, copied or
// rendered, and the call neither installs, clears, replaces nor mutates a fault
// — a latched engine stays latched and an unlatched one stays unlatched however
// often this is called. Nil-safe like the other exported status readers: a nil
// engine reports false, never a fabricated fault.
func (s *SyncEngine) TerminalFaulted() bool {
	return s.persistenceFaulted()
}

func (s *SyncEngine) BlockApplyCounts() BlockApplyCounts {
	if s == nil {
		return BlockApplyCounts{}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.blockApply
}
