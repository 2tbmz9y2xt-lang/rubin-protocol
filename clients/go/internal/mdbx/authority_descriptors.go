package mdbx

func validSelected(s *SelectedSideV1) bool {
	if s.F >= s.TipHeight || s.TipHeight > maxAuthorityHeight {
		return false
	}
	count := min(s.TipHeight-s.F, 1440)
	if s.GenerationID == 0 || !validWork(s.CumulativeChainwork) {
		return false
	}
	return all(uint64(s.RowCount) == count,
		s.LogicalBytes >= uint64(s.RowCount),
		s.LogicalBytes <= uint64(s.RowCount)*uint64(MaxBlockBytes))
}

func validSpan(s CleanupSpanV1) bool {
	if s.GenerationID == 0 {
		return false
	}
	switch s.Kind {
	case CleanupSpanGenerationV1:
		return all(s.FirstHeight == 0, s.LastHeight == 0, s.NextHeight == 0)
	case CleanupSpanBlocksV1, CleanupSpanUndoV1, CleanupSpanSideV1:
		return all(s.FirstHeight <= s.NextHeight, s.NextHeight <= s.LastHeight, s.LastHeight <= maxAuthorityHeight)
	}
	return false
}

func validCleanup(c *CleanupV1) bool {
	if len(c.Spans) < 1 {
		return false
	}
	previous := CleanupSpanKindV1(0)
	for _, span := range c.Spans {
		if !validSpan(span) || span.Kind <= previous {
			return false
		}
		previous = span.Kind
	}
	return true
}

func validReplay(v *ReplayV1) bool {
	if !validProfile(v.TargetProfile) || !validWork(v.Target.CumulativeChainwork) {
		return false
	}
	if !all(v.TargetGenerationID != 0, v.Target.TipHeight >= 1, v.Target.TipHeight <= maxAuthorityHeight) {
		return false
	}
	switch v.Cursor.Kind {
	case ReplayCursorPreGenesisV1:
		return all(v.Cursor.Height == 0, v.Cursor.BlockHash == ([32]byte{}))
	case ReplayCursorAppliedV1:
		return all(v.Cursor.Height <= v.Target.TipHeight,
			anyTrue(v.Cursor.Height != v.Target.TipHeight, v.Cursor.BlockHash == v.Target.TipHash))
	}
	return false
}

func validDetached(d *DetachedSuffixV1) bool {
	if !all(len(d.Entries) >= 1, len(d.Entries) <= 1440, int(d.EntryCount) == len(d.Entries)) {
		return false
	}
	seen, sum := map[[32]byte]bool{}, uint64(0)
	for i, entry := range d.Entries {
		if !all(entry.Height <= maxAuthorityHeight, entry.BlockBytesLen >= 1,
			entry.BlockBytesLen <= uint64(MaxBlockBytes), !seen[entry.Hash]) {
			return false
		}
		if i > 0 && !validPointStep(d.Entries[i-1].Height, entry.Height, true) {
			return false
		}
		seen[entry.Hash], sum = true, sum+entry.BlockBytesLen
	}
	first := d.Entries[0]
	return all(d.Cursor == (AuthorityPointV1{Height: first.Height, BlockHash: first.Hash}), d.LogicalBytes == sum)
}

func validDescriptors(a StorageAuthorityV1) bool {
	if a.SelectedSide != nil && !validSelected(a.SelectedSide) {
		return false
	}
	if a.DetachedSuffix != nil && !validDetached(a.DetachedSuffix) {
		return false
	}
	branch := a.ExcludedInvalidBranch
	return branch == nil || branch.FirstInvalidHeight <= maxAuthorityHeight && len(branch.ExactConsensusError) > 0
}
