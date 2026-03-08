package node

func (s *SyncEngine) HeaderSyncRequest() HeaderRequest {
	if s == nil || s.chainState == nil {
		return HeaderRequest{}
	}
	return headerSyncRequest(s.chainState, s.cfg.HeaderBatchLimit)
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
	return s.readSyncMetric(func() uint64 {
		return s.bestKnownHeight
	})
}

func (s *SyncEngine) LastReorgDepth() uint64 {
	return s.readSyncMetric(func() uint64 {
		return s.lastReorgDepth
	})
}

func (s *SyncEngine) ReorgCount() uint64 {
	return s.readSyncMetric(func() uint64 {
		return s.reorgCount
	})
}

func (s *SyncEngine) IsInIBD(nowUnix uint64) bool {
	if s == nil || s.chainState == nil {
		return true
	}
	if !s.chainState.HasTip {
		return true
	}
	s.mu.RLock()
	tipTimestamp := s.tipTimestamp
	ibdLag := s.cfg.IBDLagSeconds
	s.mu.RUnlock()
	return isInIBDWindow(nowUnix, tipTimestamp, ibdLag)
}

func (s *SyncEngine) readSyncMetric(read func() uint64) uint64 {
	if s == nil {
		return 0
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return read()
}

func headerSyncRequest(chainState *ChainState, limit uint64) HeaderRequest {
	if chainState == nil || !chainState.HasTip {
		return HeaderRequest{Limit: limit}
	}
	return HeaderRequest{
		FromHash: chainState.TipHash,
		HasFrom:  true,
		Limit:    limit,
	}
}

func isInIBDWindow(nowUnix uint64, tipTimestamp uint64, ibdLag uint64) bool {
	if nowUnix < tipTimestamp {
		return true
	}
	return nowUnix-tipTimestamp > ibdLag
}
