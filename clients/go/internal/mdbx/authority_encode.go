package mdbx

import "encoding/binary"

func appendU16(out *[]byte, n uint16) { *out = binary.BigEndian.AppendUint16(*out, n) }
func appendU32(out *[]byte, n uint32) { *out = binary.BigEndian.AppendUint32(*out, n) }
func appendU64(out *[]byte, n uint64) { *out = binary.BigEndian.AppendUint64(*out, n) }
func appendPoint(out *[]byte, p AuthorityPointV1) {
	appendU64(out, p.Height)
	*out = append(*out, p.BlockHash[:]...)
}

func appendOption(out *[]byte, present bool) {
	tag := byte(0)
	if present {
		tag = 1
	}
	*out = append(*out, tag)
}

func appendBlob(out *[]byte, b []byte) {
	appendU32(out, uint32(len(b)))
	*out = append(*out, b...)
}

func encodeAuthority(out *[]byte, a StorageAuthorityV1) {
	*out = append(*out, a.Version, byte(a.ActiveProfile))
	for _, n := range [...]uint64{a.B, a.U, a.ActiveGenerationID, a.NextGenerationID} {
		appendU64(out, n)
	}
	*out = append(*out, byte(a.Phase), byte(a.Lifecycle))
	switch a.Phase {
	case StoragePhasePruneGCV1:
		encodeCleanup(out, a.Cleanup)
	case StoragePhaseReplayV1:
		encodeReplay(out, a.Replay)
	case StoragePhaseOrdinaryApplyV1:
		encodeOrdinary(out, a.Ordinary)
	}
	encodeOuterOptions(out, a)
}

func encodeOuterOptions(out *[]byte, a StorageAuthorityV1) {
	appendOption(out, a.PendingTargetProfile != nil)
	if a.PendingTargetProfile != nil {
		*out = append(*out, byte(*a.PendingTargetProfile))
	}
	appendOption(out, a.ExcludedInvalidBranch != nil)
	if a.ExcludedInvalidBranch != nil {
		encodeInvalidBranch(out, a.ExcludedInvalidBranch)
	}
	appendOption(out, a.SelectedSide != nil)
	if a.SelectedSide != nil {
		encodeSelected(out, a.SelectedSide)
	}
	appendOption(out, a.DetachedSuffix != nil)
	if a.DetachedSuffix != nil {
		encodeDetached(out, a.DetachedSuffix)
	}
}

func encodeCleanup(out *[]byte, c *CleanupV1) {
	*out = append(*out, byte(len(c.Spans)))
	for _, span := range c.Spans {
		*out = append(*out, byte(span.Kind))
		appendU64(out, span.GenerationID)
		if span.Kind != CleanupSpanGenerationV1 {
			appendU64(out, span.FirstHeight)
			appendU64(out, span.LastHeight)
			appendU64(out, span.NextHeight)
		}
	}
}

func encodeReplay(out *[]byte, v *ReplayV1) {
	*out = append(*out, byte(v.TargetProfile))
	appendU64(out, v.TargetGenerationID)
	*out = append(*out, v.Target.ChainID[:]...)
	*out = append(*out, v.Target.GenesisHash[:]...)
	*out = append(*out, v.Target.TipHash[:]...)
	appendU64(out, v.Target.TipHeight)
	*out = append(*out, v.Target.CumulativeChainwork[:]...)
	*out = append(*out, byte(v.Cursor.Kind))
	if v.Cursor.Kind == ReplayCursorAppliedV1 {
		appendU64(out, v.Cursor.Height)
		*out = append(*out, v.Cursor.BlockHash[:]...)
	}
}

func encodeSelected(out *[]byte, v *SelectedSideV1) {
	appendU64(out, v.GenerationID)
	appendU64(out, v.F)
	appendU64(out, v.TipHeight)
	*out = append(*out, v.TipHash[:]...)
	*out = append(*out, v.CumulativeChainwork[:]...)
	appendU16(out, v.RowCount)
	appendU64(out, v.LogicalBytes)
}

func encodeInvalidBranch(out *[]byte, v *InvalidBranchV1) {
	appendU64(out, v.FirstInvalidHeight)
	*out = append(*out, v.FirstInvalidBlockHash[:]...)
	appendBlob(out, v.ExactConsensusError)
}

func encodeDetached(out *[]byte, v *DetachedSuffixV1) {
	appendU16(out, uint16(len(v.Entries)))
	for _, entry := range v.Entries {
		appendU64(out, entry.Height)
		*out = append(*out, entry.Hash[:]...)
		appendU64(out, entry.BlockBytesLen)
	}
	appendPoint(out, v.Cursor)
	appendU16(out, v.EntryCount)
	appendU64(out, v.LogicalBytes)
}

func encodeOrdinary(out *[]byte, v *OrdinaryApplyV1) {
	*out = append(*out, byte(v.Stage))
	appendOption(out, v.Cursor != nil)
	if v.Cursor != nil {
		appendPoint(out, *v.Cursor)
	}
	appendPoint(out, v.Target)
	appendPoints(out, v.OldSuffix)
	appendPoints(out, v.NewSuffix)
	appendOption(out, v.CapturedSelectedSide != nil)
	if v.CapturedSelectedSide != nil {
		encodeSelected(out, v.CapturedSelectedSide)
	}
	appendOption(out, v.CarriedCleanup != nil)
	if v.CarriedCleanup != nil {
		encodeCleanup(out, v.CarriedCleanup)
	}
	appendOption(out, v.RecordedFailure != nil)
	if v.RecordedFailure != nil {
		encodeFailure(out, v.RecordedFailure)
	}
}

func appendPoints(out *[]byte, points []AuthorityPointV1) {
	appendU16(out, uint16(len(points)))
	for _, point := range points {
		appendPoint(out, point)
	}
}

func encodeFailure(out *[]byte, v *RecordedFailureV1) {
	*out = append(*out, byte(v.Kind))
	appendOption(out, v.FailedBlockHash != nil)
	if v.FailedBlockHash != nil {
		*out = append(*out, v.FailedBlockHash[:]...)
	}
	appendBlob(out, v.ExactResult)
	appendBlob(out, v.Evidence)
}
