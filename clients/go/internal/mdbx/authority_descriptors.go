package mdbx

func validSelectedFor(s *SelectedSideV1, tree bool) bool {
	if s.F >= s.TipHeight || s.TipHeight > maxAuthorityHeight {
		return false
	}
	// Full form row_count=min(C,1440); the sole one-slot form is C>=1440, row_count=1439 (RUBIN_MEMPOOL_POLICY.md 6.4.1.3).
	c := s.TipHeight - s.F
	if s.GenerationID == 0 || !validWork(s.CumulativeChainwork) {
		return false
	}
	return all(anyTrue(uint64(s.RowCount) == min(c, 1440), all(c >= 1440, s.RowCount == 1439)),
		s.LogicalBytes >= uint64(s.RowCount),
		s.LogicalBytes <= uint64(s.RowCount)*authorityBlockMaximum(tree))
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

func validCleanupFor(c *CleanupV1, tree bool) bool {
	if len(c.Spans) < 1 {
		return false
	}
	previous := CleanupSpanKindV1(0)
	var generation uint64
	generations := 0
	for _, span := range c.Spans {
		if !validSpan(span) || !validSpanOrder(span, previous, generation, tree) {
			return false
		}
		previous = span.Kind
		if span.Kind == CleanupSpanGenerationV1 {
			generation = span.GenerationID
			generations++
			if generations > 2 {
				return false
			}
		}
	}
	return true
}

func validReplayFor(v *ReplayV1, tree bool) bool {
	if !validProfile(v.TargetProfile) || !validWork(v.Target.CumulativeChainwork) {
		return false
	}
	if !all(v.TargetGenerationID != 0, v.Target.TipHeight >= 1, v.Target.TipHeight <= maxAuthorityHeight) {
		return false
	}
	if tree && v.Cursor == (ReplayCursorV1{}) {
		return true
	}
	switch v.Cursor.Kind {
	case ReplayCursorPreGenesisV1:
		return all(v.Cursor.Height == 0, v.Cursor.BlockHash == ([32]byte{}))
	case ReplayCursorAppliedV1:
		return all(v.Cursor.Height <= v.Target.TipHeight,
			anyTrue(v.Cursor.Height != 0, v.Cursor.BlockHash == v.Target.GenesisHash),
			anyTrue(v.Cursor.Height != v.Target.TipHeight, v.Cursor.BlockHash == v.Target.TipHash))
	}
	return false
}

func validDetachedFor(d *DetachedSuffixV1, tree bool) bool {
	if !all(len(d.Entries) >= 1, len(d.Entries) <= 1440, int(d.EntryCount) == len(d.Entries)) {
		return false
	}
	seen, sum := map[[32]byte]bool{}, uint64(0)
	for i, entry := range d.Entries {
		if !all(entry.Height <= maxAuthorityHeight, entry.BlockBytesLen >= 1,
			entry.BlockBytesLen <= authorityBlockMaximum(tree), !seen[entry.Hash]) {
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

func validDescriptors(a StorageAuthorityV1) bool { return validDescriptorsFor(a, false) }

func validDescriptorsFor(a StorageAuthorityV1, tree bool) bool {
	if a.SelectedSide != nil && !validSelectedFor(a.SelectedSide, tree) {
		return false
	}
	if a.DetachedSuffix != nil && !validDetachedFor(a.DetachedSuffix, tree) {
		return false
	}
	branch := a.ExcludedInvalidBranch
	return branch == nil || branch.FirstInvalidHeight <= maxAuthorityHeight && len(branch.ExactConsensusError) > 0
}

func authorityBlockMaximum(tree bool) uint64 {
	if tree {
		return Initial148MaxBlockBytes
	}
	return MaxBlockBytes
}

func cleanupSpanMaximum(tree bool) int {
	if tree {
		return 5
	}
	return 4
}

func validSpanOrder(span CleanupSpanV1, previous CleanupSpanKindV1, generation uint64, tree bool) bool {
	if tree && span.Kind == CleanupSpanGenerationV1 && previous == span.Kind {
		return generation != 0 && generation < span.GenerationID
	}
	return span.Kind > previous
}
