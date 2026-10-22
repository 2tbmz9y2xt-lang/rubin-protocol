package mdbx

func decodeAuthority(r *authorityReader, c *authorityDecodeControl, i *authorityInspection) (a StorageAuthorityV1) {
	a = StorageAuthorityV1{
		Version: r.tag(1), ActiveProfile: StorageProfileV1(r.tag(2)),
		B: r.u64(), U: r.u64(),
		ActiveGenerationID: r.u64(), NextGenerationID: r.u64(),
		Phase: StoragePhaseV1(r.tag(4)), Lifecycle: StorageLifecycleV1(r.tag(2)),
	}
	if !r.ok {
		return StorageAuthorityV1{}
	}
	switch a.Phase {
	case StoragePhaseNoneV1:
	case StoragePhasePruneGCV1:
		a.Cleanup = decodeCleanup(r, c, i, false)
	case StoragePhaseReplayV1:
		a.Replay = decodeReplay(r, c)
	case StoragePhaseOrdinaryApplyV1:
		a.Ordinary = decodeOrdinary(r, c, i)
	}
	return decodeOuterOptions(r, c, i, a)
}

func decodeOuterOptions(r *authorityReader, c *authorityDecodeControl, i *authorityInspection, a StorageAuthorityV1) StorageAuthorityV1 {
	if r.option() {
		c.pending = StorageProfileV1(r.tag(2))
		a.PendingTargetProfile = &c.pending
	}
	if r.option() {
		a.ExcludedInvalidBranch = decodeInvalidBranch(r, c)
	}
	if r.option() {
		a.SelectedSide = decodeSelected(r, c)
	}
	if r.option() {
		a.DetachedSuffix = decodeDetached(r, c, i)
	}
	return a
}

func decodePoint(r *authorityReader) AuthorityPointV1 {
	return AuthorityPointV1{Height: r.u64(), BlockHash: r.hash32()}
}

func decodeCleanup(r *authorityReader, c *authorityDecodeControl, i *authorityInspection, carried bool) *CleanupV1 {
	n := int(r.u8())
	if n < 1 || n > cleanupSpanMaximum(r.tree) || n*9 > r.remaining() {
		r.ok = false
		return nil
	}
	view := decodeCleanupSpans(r, c, n)
	if !r.ok {
		return nil
	}
	if i != nil {
		if carried {
			i.carried = view
		} else {
			i.phase = view
		}
	}
	return &c.cleanup
}

func decodeCleanupSpans(r *authorityReader, c *authorityDecodeControl, n int) authoritySpans {
	start := r.off
	if !r.borrowed {
		c.cleanup.Spans = make([]CleanupSpanV1, n)
	}
	for i := 0; i < n; i++ {
		var span CleanupSpanV1
		decodeSpan(r, &span)
		if !r.ok {
			return authoritySpans{}
		}
		if !r.borrowed {
			c.cleanup.Spans[i] = span
		}
	}
	return authoritySpans{encoded: r.b[start:r.off], count: n}
}

func decodeSpan(r *authorityReader, span *CleanupSpanV1) {
	span.Kind = CleanupSpanKindV1(r.tag(4))
	span.GenerationID = r.u64()
	if span.Kind == CleanupSpanGenerationV1 || !r.ok {
		return
	}
	span.FirstHeight, span.LastHeight, span.NextHeight = r.u64(), r.u64(), r.u64()
}

func decodeReplay(r *authorityReader, c *authorityDecodeControl) *ReplayV1 {
	c.replay = ReplayV1{TargetProfile: StorageProfileV1(r.tag(2)), TargetGenerationID: r.u64()}
	v := &c.replay
	v.Target = decodeRecoveryTarget(r)
	v.Cursor.Kind = ReplayCursorKindV1(r.u8())
	if v.Cursor.Kind > 2 || (!r.tree && v.Cursor.Kind == 0) {
		r.ok = false
	}
	if v.Cursor.Kind == ReplayCursorAppliedV1 {
		p := decodePoint(r)
		v.Cursor.Height, v.Cursor.BlockHash = p.Height, p.BlockHash
	}
	return v
}

func decodeRecoveryTarget(r *authorityReader) RecoveryTargetV1 {
	return RecoveryTargetV1{
		ChainID: r.hash32(), GenesisHash: r.hash32(), TipHash: r.hash32(),
		TipHeight: r.u64(), CumulativeChainwork: r.work40(),
	}
}

func decodeSelected(r *authorityReader, c *authorityDecodeControl) *SelectedSideV1 {
	c.selected = SelectedSideV1{
		GenerationID: r.u64(), F: r.u64(), TipHeight: r.u64(),
		TipHash: r.hash32(), CumulativeChainwork: r.work40(),
		RowCount: r.u16(), LogicalBytes: r.u64(),
	}
	return &c.selected
}

func decodeInvalidBranch(r *authorityReader, c *authorityDecodeControl) *InvalidBranchV1 {
	c.excluded = InvalidBranchV1{
		FirstInvalidHeight: r.u64(), FirstInvalidBlockHash: r.hash32(),
		ExactConsensusError: r.blob(),
	}
	return &c.excluded
}

func decodeDetached(r *authorityReader, c *authorityDecodeControl, i *authorityInspection) *DetachedSuffixV1 {
	n := r.count16(1440, authorityDetachedBytes)
	if !r.ok || n < 1 {
		r.ok = false
		return nil
	}
	v := &c.detached
	if i != nil {
		encoded := r.take(n * authorityDetachedBytes)
		if !r.ok {
			return nil
		}
		i.detached = authorityDetached{encoded: encoded, count: n}
	} else {
		v.Entries = make([]DetachedSuffixEntryV1, n)
		for i := range v.Entries {
			v.Entries[i] = decodeDetachedEntry(r)
		}
	}
	v.Cursor = decodePoint(r)
	v.EntryCount, v.LogicalBytes = r.u16(), r.u64()
	return v
}

func decodeDetachedEntry(r *authorityReader) DetachedSuffixEntryV1 {
	return DetachedSuffixEntryV1{Height: r.u64(), Hash: r.hash32(), BlockBytesLen: r.u64()}
}

func decodeOrdinary(r *authorityReader, c *authorityDecodeControl, i *authorityInspection) *OrdinaryApplyV1 {
	c.ordinary.Stage = OrdinaryStageV1(r.tag(4))
	v := &c.ordinary
	if r.option() {
		c.cursor = decodePoint(r)
	} else {
		v.Cursor = nil
	}
	v.Target = decodePoint(r)
	v.OldSuffix = decodePoints(r, i, true)
	v.NewSuffix = decodePoints(r, i, false)
	if r.option() {
		decodeSelected(r, c)
	} else {
		v.CapturedSelectedSide = nil
	}
	if r.option() {
		decodeCleanup(r, c, i, true)
	} else {
		v.CarriedCleanup = nil
	}
	if r.option() {
		decodeFailure(r, c)
	} else {
		v.RecordedFailure = nil
	}
	return v
}

func decodePoints(r *authorityReader, i *authorityInspection, old bool) []AuthorityPointV1 {
	n := r.count16(1440, authorityPointBytes)
	if !r.ok || n == 0 {
		return nil
	}
	if i != nil {
		encoded := r.take(n * authorityPointBytes)
		if !r.ok {
			return nil
		}
		view := authorityPoints{encoded: encoded, count: n}
		if old {
			i.old = view
		} else {
			i.new = view
		}
		return nil
	}
	points := make([]AuthorityPointV1, n)
	for i := range points {
		points[i] = decodePoint(r)
	}
	return points
}

func decodeFailure(r *authorityReader, c *authorityDecodeControl) *RecordedFailureV1 {
	c.failure.Kind = RecordedFailureKindV1(r.tag(4))
	v := &c.failure
	if r.option() {
		c.hash = r.hash32()
	} else {
		v.FailedBlockHash = nil
	}
	v.ExactResult = r.blob()
	v.Evidence = r.blob()
	return v
}
