package mdbx

import "slices"

type (
	GenerationIDV1        = uint64
	StorageProfileV1      uint8
	StoragePhaseV1        uint8
	StorageLifecycleV1    uint8
	CleanupSpanKindV1     uint8
	ReplayCursorKindV1    uint8
	OrdinaryStageV1       uint8
	RecordedFailureKindV1 uint8
)

const (
	StorageAuthorityVersionV1                                       uint8                 = 1
	StorageProfilePrunedV1, StorageProfileArchiveV1                 StorageProfileV1      = 1, 2
	StoragePhaseNoneV1, StoragePhasePruneGCV1, StoragePhaseReplayV1 StoragePhaseV1        = 1, 2, 3
	StoragePhaseOrdinaryApplyV1                                     StoragePhaseV1        = 4
	StorageLifecycleStableV1, StorageLifecycleRecoveryRequiredV1    StorageLifecycleV1    = 1, 2
	CleanupSpanGenerationV1, CleanupSpanBlocksV1, CleanupSpanUndoV1 CleanupSpanKindV1     = 1, 2, 3
	CleanupSpanSideV1                                               CleanupSpanKindV1     = 4
	ReplayCursorPreGenesisV1, ReplayCursorAppliedV1                 ReplayCursorKindV1    = 1, 2
	OrdinaryStageDisconnectV1, OrdinaryStageConnectV1               OrdinaryStageV1       = 1, 2
	OrdinaryStageRollbackNewV1, OrdinaryStageRestoreOldV1           OrdinaryStageV1       = 3, 4
	RecordedFailureConsensusV1, RecordedFailureStoreIntegrityV1     RecordedFailureKindV1 = 1, 2
	RecordedFailureLocalInvariantV1, RecordedFailureNoncanonicalV1  RecordedFailureKindV1 = 3, 4
	maxAuthorityHeight, maxArchiveU, maxPrunedB                     uint64                = 0xffffffff, 4_294_965_856, 4_294_952_176
)

type (
	CleanupSpanV1 struct {
		Kind                                CleanupSpanKindV1
		GenerationID                        GenerationIDV1
		FirstHeight, LastHeight, NextHeight uint64
	}
	CleanupV1        struct{ Spans []CleanupSpanV1 }
	RecoveryTargetV1 struct {
		ChainID, GenesisHash, TipHash [32]byte
		TipHeight                     uint64
		CumulativeChainwork           [40]byte
	}
	ReplayCursorV1 struct {
		Kind      ReplayCursorKindV1
		Height    uint64
		BlockHash [32]byte
	}
	ReplayV1 struct {
		TargetProfile      StorageProfileV1
		TargetGenerationID GenerationIDV1
		Target             RecoveryTargetV1
		Cursor             ReplayCursorV1
	}
	AuthorityPointV1 struct {
		Height    uint64
		BlockHash [32]byte
	}
	InvalidBranchV1 struct {
		FirstInvalidHeight    uint64
		FirstInvalidBlockHash [32]byte
		ExactConsensusError   []byte
	}
	SelectedSideV1 struct {
		GenerationID        GenerationIDV1
		F, TipHeight        uint64
		TipHash             [32]byte
		CumulativeChainwork [40]byte
		RowCount            uint16
		LogicalBytes        uint64
	}
	DetachedSuffixEntryV1 struct {
		Height        uint64
		Hash          [32]byte
		BlockBytesLen uint64
	}
	DetachedSuffixV1 struct {
		Entries      []DetachedSuffixEntryV1
		Cursor       AuthorityPointV1
		EntryCount   uint16
		LogicalBytes uint64
	}
	RecordedFailureV1 struct {
		Kind                  RecordedFailureKindV1
		FailedBlockHash       *[32]byte
		ExactResult, Evidence []byte
	}
	OrdinaryApplyV1 struct {
		Stage                OrdinaryStageV1
		Cursor               *AuthorityPointV1
		Target               AuthorityPointV1
		OldSuffix, NewSuffix []AuthorityPointV1
		CapturedSelectedSide *SelectedSideV1
		CarriedCleanup       *CleanupV1
		RecordedFailure      *RecordedFailureV1
	}
	StorageAuthorityV1 struct {
		Version                              uint8
		ActiveProfile                        StorageProfileV1
		B, U                                 uint64
		ActiveGenerationID, NextGenerationID GenerationIDV1
		Phase                                StoragePhaseV1
		Lifecycle                            StorageLifecycleV1
		Cleanup                              *CleanupV1
		Replay                               *ReplayV1
		Ordinary                             *OrdinaryApplyV1
		PendingTargetProfile                 *StorageProfileV1
		ExcludedInvalidBranch                *InvalidBranchV1
		SelectedSide                         *SelectedSideV1
		DetachedSuffix                       *DetachedSuffixV1
	}
)

func all(values ...bool) bool     { return !slices.Contains(values, false) }
func anyTrue(values ...bool) bool { return slices.Contains(values, true) }
func validProfile(p StorageProfileV1) bool {
	return anyTrue(p == StorageProfilePrunedV1, p == StorageProfileArchiveV1)
}

func validWork(w [40]byte) bool {
	if !all(w[0] == 0, w[1] == 0, w[2] == 0, w[3] <= 1) {
		return false
	}
	nonzero := slices.ContainsFunc(w[4:], func(n byte) bool { return n != 0 })
	return nonzero == (w[3] == 0)
}

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

func validPoints(points []AuthorityPointV1, descending bool, seen map[[32]byte]bool) bool {
	var previous uint64
	for i, point := range points {
		if !all(point.Height <= maxAuthorityHeight, !seen[point.BlockHash]) {
			return false
		}
		if i > 0 && !validPointStep(previous, point.Height, descending) {
			return false
		}
		seen[point.BlockHash], previous = true, point.Height
	}
	return true
}

func validPointStep(previous, current uint64, descending bool) bool {
	return (descending && previous == current+1) || (!descending && current == previous+1)
}

func validFailure(f *RecordedFailureV1, newSuffix []AuthorityPointV1) bool {
	if f == nil {
		return true
	}
	if len(f.ExactResult) == 0 || len(f.Evidence) == 0 {
		return false
	}
	switch f.Kind {
	case RecordedFailureConsensusV1:
		if f.FailedBlockHash == nil {
			return true
		}
		return slices.ContainsFunc(newSuffix, func(point AuthorityPointV1) bool {
			return point.BlockHash == *f.FailedBlockHash
		})
	case RecordedFailureStoreIntegrityV1, RecordedFailureLocalInvariantV1, RecordedFailureNoncanonicalV1:
		return f.FailedBlockHash == nil
	}
	return false
}

func validStage(o *OrdinaryApplyV1) bool {
	switch o.Stage {
	case OrdinaryStageDisconnectV1:
		return validDisconnectStage(o)
	case OrdinaryStageConnectV1:
		return validConnectStage(o)
	case OrdinaryStageRollbackNewV1:
		return validRollbackNewStage(o)
	case OrdinaryStageRestoreOldV1:
		return validRestoreOldStage(o)
	}
	return false
}

func validDisconnectStage(o *OrdinaryApplyV1) bool {
	return len(o.OldSuffix) > 0 && o.RecordedFailure == nil && (o.Cursor == nil || slices.Contains(o.OldSuffix, *o.Cursor))
}

func validConnectStage(o *OrdinaryApplyV1) bool {
	return len(o.NewSuffix) > 0 && o.RecordedFailure == nil && ((o.Cursor == nil && len(o.OldSuffix) == 0) || (o.Cursor != nil && slices.Contains(o.NewSuffix, *o.Cursor)))
}

func validRollbackNewStage(o *OrdinaryApplyV1) bool {
	return len(o.NewSuffix) > 0 && o.RecordedFailure != nil && o.Cursor != nil && slices.Contains(o.NewSuffix, *o.Cursor) && (len(o.OldSuffix) > 0 || *o.Cursor != o.NewSuffix[0])
}

func validRestoreOldStage(o *OrdinaryApplyV1) bool {
	return len(o.OldSuffix) > 0 && o.RecordedFailure != nil && o.Cursor != nil && *o.Cursor != o.OldSuffix[0] && slices.Contains(o.OldSuffix, *o.Cursor)
}

func suffixF(points []AuthorityPointV1, descending bool) (uint64, bool) {
	if len(points) == 0 {
		return 0, false
	}
	point := map[bool]AuthorityPointV1{true: points[len(points)-1], false: points[0]}[descending]
	if point.Height == 0 {
		return 0, false
	}
	return point.Height - 1, true
}

func validOrdinaryTarget(o *OrdinaryApplyV1, f uint64, seen map[[32]byte]bool) bool {
	if len(o.NewSuffix) == 0 {
		if o.Target.Height != f || seen[o.Target.BlockHash] {
			return false
		}
		return o.CapturedSelectedSide == nil || validSelected(o.CapturedSelectedSide)
	}
	if o.CapturedSelectedSide == nil {
		return false
	}
	target := o.NewSuffix[len(o.NewSuffix)-1]
	side := o.CapturedSelectedSide
	if !validSelected(side) {
		return false
	}
	return all(o.Target == target, side.F == f,
		side.TipHeight == target.Height, side.TipHash == target.BlockHash)
}

func laggedPromise(height, window uint64) uint64 {
	if height < window {
		return 0
	}
	return height - window + 1
}

func validOrdinaryPromises(a StorageAuthorityV1) bool {
	height := uint64(0)
	if len(a.Ordinary.OldSuffix) > 0 {
		height = a.Ordinary.OldSuffix[0].Height
	} else {
		height = a.Ordinary.NewSuffix[0].Height - 1
	}
	return a.U == laggedPromise(height, 1440)
}

func validOrdinaryTail(a StorageAuthorityV1, f uint64, seen map[[32]byte]bool) bool {
	o := a.Ordinary
	if !validOrdinaryTarget(o, f, seen) || !validStage(o) || !validFailure(o.RecordedFailure, o.NewSuffix) {
		return false
	}
	if o.CarriedCleanup != nil && !validCleanup(o.CarriedCleanup) {
		return false
	}
	return validOrdinaryPromises(a)
}

func validOrdinary(a StorageAuthorityV1) bool {
	o := a.Ordinary
	if !all(len(o.OldSuffix) <= 1440, len(o.NewSuffix) <= 1440,
		anyTrue(len(o.OldSuffix) >= 1, len(o.NewSuffix) >= 2)) {
		return false
	}
	seen := map[[32]byte]bool{}
	if !validPoints(o.OldSuffix, true, seen) || !validPoints(o.NewSuffix, false, seen) {
		return false
	}
	oldF, oldOK := suffixF(o.OldSuffix, true)
	newF, newOK := suffixF(o.NewSuffix, false)
	if !all(anyTrue(len(o.OldSuffix) == 0, oldOK), anyTrue(len(o.NewSuffix) == 0, newOK)) {
		return false
	}
	if !anyTrue(all(oldOK, !newOK), all(!oldOK, newOK), all(oldOK, newOK, oldF == newF)) {
		return false
	}
	f := map[bool]uint64{true: oldF, false: newF}[oldOK]
	return validOrdinaryTail(a, f, seen)
}

func validProfilePromises(a StorageAuthorityV1) bool {
	if a.Version != StorageAuthorityVersionV1 {
		return false
	}
	switch a.ActiveProfile {
	case StorageProfilePrunedV1:
		if a.B == 0 {
			return a.U <= 13680
		}
		if a.B > maxPrunedB {
			return false
		}
		return a.U == a.B+13680
	case StorageProfileArchiveV1:
		return a.B == 0 && a.U <= maxArchiveU
	}
	return false
}

func validTop(a StorageAuthorityV1) bool {
	if !validProfilePromises(a) || a.ActiveGenerationID == 0 || a.ActiveGenerationID >= a.NextGenerationID {
		return false
	}
	pending := a.PendingTargetProfile != nil
	rows := map[StoragePhaseV1]bool{
		StoragePhaseNoneV1: all(a.Lifecycle == StorageLifecycleStableV1, a.Cleanup == nil, a.Replay == nil, a.Ordinary == nil, !pending),
		StoragePhasePruneGCV1: all(a.Cleanup != nil, a.Replay == nil, a.Ordinary == nil,
			anyTrue(all(a.Lifecycle == StorageLifecycleStableV1, !pending), all(a.Lifecycle == StorageLifecycleRecoveryRequiredV1, pending))),
		StoragePhaseReplayV1:        all(a.Lifecycle == StorageLifecycleRecoveryRequiredV1, a.Cleanup == nil, a.Replay != nil, a.Ordinary == nil, !pending),
		StoragePhaseOrdinaryApplyV1: all(a.Lifecycle == StorageLifecycleRecoveryRequiredV1, a.Cleanup == nil, a.Replay == nil, a.Ordinary != nil, !pending),
	}
	if !rows[a.Phase] {
		return false
	}
	if a.PendingTargetProfile != nil && !validProfile(*a.PendingTargetProfile) {
		return false
	}
	return all(
		anyTrue(a.SelectedSide == nil, a.Lifecycle == StorageLifecycleStableV1),
		anyTrue(a.DetachedSuffix == nil, all(a.Phase == StoragePhasePruneGCV1, a.Cleanup != nil)),
		anyTrue(a.SelectedSide == nil, a.DetachedSuffix == nil))
}

func validPayload(a StorageAuthorityV1) bool {
	switch a.Phase {
	case StoragePhaseNoneV1:
		return true
	case StoragePhasePruneGCV1:
		return validCleanup(a.Cleanup)
	case StoragePhaseReplayV1:
		return validReplay(a.Replay)
	case StoragePhaseOrdinaryApplyV1:
		return validOrdinary(a)
	}
	return false
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

func authorityOwners(a StorageAuthorityV1) (uint64, *CleanupV1, *SelectedSideV1) {
	replay, cleanup, side := uint64(0), a.Cleanup, a.SelectedSide
	if a.Replay != nil {
		replay = a.Replay.TargetGenerationID
	}
	if a.Ordinary != nil {
		cleanup, side = a.Ordinary.CarriedCleanup, a.Ordinary.CapturedSelectedSide
	}
	return replay, cleanup, side
}

func sideGeneration(cleanup *CleanupV1, selected *SelectedSideV1) (uint64, bool) {
	side := uint64(0)
	if selected != nil {
		side = selected.GenerationID
	}
	if cleanup != nil {
		for _, span := range cleanup.Spans {
			if span.Kind == CleanupSpanSideV1 {
				return span.GenerationID, anyTrue(side == 0, side == span.GenerationID)
			}
		}
	}
	return side, true
}

func validCleanupRelations(a StorageAuthorityV1, cleanup *CleanupV1, selected *SelectedSideV1, side uint64) (uint64, bool) {
	obsolete, first := uint64(0), uint64(0)
	if cleanup == nil {
		return obsolete, true
	}
	if selected != nil {
		first = selected.TipHeight - uint64(selected.RowCount) + 1
	}
	for _, span := range cleanup.Spans {
		owner := [5]bool{
			false,
			all(span.GenerationID != a.ActiveGenerationID, span.GenerationID != side),
			span.GenerationID == a.ActiveGenerationID, span.GenerationID == a.ActiveGenerationID,
			span.GenerationID == side,
		}[span.Kind]
		promise := [5]bool{false, true, all(a.B != 0, span.LastHeight < a.B), all(a.U != 0, span.LastHeight < a.U), anyTrue(selected == nil, span.LastHeight < first)}[span.Kind]
		if !all(owner, promise) {
			return 0, false
		}
		if span.Kind == CleanupSpanGenerationV1 {
			obsolete = span.GenerationID
		}
	}
	return obsolete, true
}

func validGenerationSequence(active, next, replay, side, obsolete uint64) bool {
	return all(anyTrue(replay == 0, replay != active), anyTrue(side == 0, side != active), anyTrue(replay == 0, replay < next), anyTrue(side == 0, side < next), anyTrue(obsolete == 0, obsolete < next))
}

func validOwners(a StorageAuthorityV1) bool {
	replay, cleanup, selected := authorityOwners(a)
	side, sidesOK := sideGeneration(cleanup, selected)
	if !sidesOK {
		return false
	}
	obsolete, cleanupOK := validCleanupRelations(a, cleanup, selected, side)
	if !cleanupOK {
		return false
	}
	return validGenerationSequence(a.ActiveGenerationID, a.NextGenerationID, replay, side, obsolete)
}

func ValidateStorageAuthorityV1(a StorageAuthorityV1) error {
	if !validTop(a) || !validPayload(a) || !validDescriptors(a) || !validOwners(a) {
		return errSchema
	}
	return nil
}
