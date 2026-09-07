package mdbx

func decodeAuthority(r *authorityReader) (a StorageAuthorityV1) {
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
		a.Cleanup = decodeCleanup(r)
	case StoragePhaseReplayV1:
		a.Replay = decodeReplay(r)
	case StoragePhaseOrdinaryApplyV1:
		a.Ordinary = decodeOrdinary(r)
	}
	decodeOuterOptions(r, &a)
	return a
}

func decodeOuterOptions(r *authorityReader, a *StorageAuthorityV1) {
	if r.option() {
		profile := StorageProfileV1(r.tag(2))
		a.PendingTargetProfile = &profile
	}
	if r.option() {
		a.ExcludedInvalidBranch = decodeInvalidBranch(r)
	}
	if r.option() {
		a.SelectedSide = decodeSelected(r)
	}
	if r.option() {
		a.DetachedSuffix = decodeDetached(r)
	}
}

func decodePoint(r *authorityReader) AuthorityPointV1 {
	return AuthorityPointV1{Height: r.u64(), BlockHash: r.hash32()}
}

func decodeCleanup(r *authorityReader) *CleanupV1 {
	n := int(r.u8())
	if n < 1 || n > 4 || n*9 > r.remaining() {
		r.ok = false
		return nil
	}
	c := &CleanupV1{Spans: make([]CleanupSpanV1, n)}
	for i := range c.Spans {
		decodeSpan(r, &c.Spans[i])
		if !r.ok {
			return nil
		}
	}
	return c
}

func decodeSpan(r *authorityReader, span *CleanupSpanV1) {
	span.Kind = CleanupSpanKindV1(r.tag(4))
	span.GenerationID = r.u64()
	if span.Kind == CleanupSpanGenerationV1 || !r.ok {
		return
	}
	span.FirstHeight, span.LastHeight, span.NextHeight = r.u64(), r.u64(), r.u64()
}

func decodeReplay(r *authorityReader) *ReplayV1 {
	v := &ReplayV1{TargetProfile: StorageProfileV1(r.tag(2)), TargetGenerationID: r.u64()}
	v.Target = decodeRecoveryTarget(r)
	v.Cursor.Kind = ReplayCursorKindV1(r.tag(2))
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

func decodeSelected(r *authorityReader) *SelectedSideV1 {
	return &SelectedSideV1{
		GenerationID: r.u64(), F: r.u64(), TipHeight: r.u64(),
		TipHash: r.hash32(), CumulativeChainwork: r.work40(),
		RowCount: r.u16(), LogicalBytes: r.u64(),
	}
}

func decodeInvalidBranch(r *authorityReader) *InvalidBranchV1 {
	return &InvalidBranchV1{
		FirstInvalidHeight: r.u64(), FirstInvalidBlockHash: r.hash32(),
		ExactConsensusError: r.blob(),
	}
}

func decodeDetached(r *authorityReader) *DetachedSuffixV1 {
	n := r.count16(1440, authorityDetachedBytes)
	if !r.ok || n < 1 {
		r.ok = false
		return nil
	}
	v := &DetachedSuffixV1{Entries: make([]DetachedSuffixEntryV1, n)}
	for i := range v.Entries {
		v.Entries[i] = DetachedSuffixEntryV1{Height: r.u64(), Hash: r.hash32(), BlockBytesLen: r.u64()}
	}
	v.Cursor = decodePoint(r)
	v.EntryCount, v.LogicalBytes = r.u16(), r.u64()
	return v
}

func decodeOrdinary(r *authorityReader) *OrdinaryApplyV1 {
	v := &OrdinaryApplyV1{Stage: OrdinaryStageV1(r.tag(4))}
	if r.option() {
		cursor := decodePoint(r)
		v.Cursor = &cursor
	}
	v.Target = decodePoint(r)
	v.OldSuffix = decodePoints(r)
	v.NewSuffix = decodePoints(r)
	if r.option() {
		v.CapturedSelectedSide = decodeSelected(r)
	}
	if r.option() {
		v.CarriedCleanup = decodeCleanup(r)
	}
	if r.option() {
		v.RecordedFailure = decodeFailure(r)
	}
	return v
}

func decodePoints(r *authorityReader) []AuthorityPointV1 {
	n := r.count16(1440, authorityPointBytes)
	if !r.ok || n == 0 {
		return nil
	}
	points := make([]AuthorityPointV1, n)
	for i := range points {
		points[i] = decodePoint(r)
	}
	return points
}

func decodeFailure(r *authorityReader) *RecordedFailureV1 {
	v := &RecordedFailureV1{Kind: RecordedFailureKindV1(r.tag(4))}
	if r.option() {
		hash := r.hash32()
		v.FailedBlockHash = &hash
	}
	v.ExactResult = r.blob()
	v.Evidence = r.blob()
	return v
}
