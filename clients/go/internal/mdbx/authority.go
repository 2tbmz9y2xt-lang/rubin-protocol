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

func validPointStep(previous, current uint64, descending bool) bool {
	return (descending && previous == current+1) || (!descending && current == previous+1)
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

func validPhasePayload(a StorageAuthorityV1) bool {
	pending := a.PendingTargetProfile != nil
	switch a.Phase {
	case StoragePhaseNoneV1:
		return all(a.Lifecycle == StorageLifecycleStableV1, a.Cleanup == nil, a.Replay == nil, a.Ordinary == nil, !pending)
	case StoragePhasePruneGCV1:
		return all(a.Cleanup != nil, a.Replay == nil, a.Ordinary == nil,
			anyTrue(all(a.Lifecycle == StorageLifecycleStableV1, !pending), all(a.Lifecycle == StorageLifecycleRecoveryRequiredV1, pending))) && validCleanup(a.Cleanup)
	case StoragePhaseReplayV1:
		return all(a.Lifecycle == StorageLifecycleRecoveryRequiredV1, a.Cleanup == nil, a.Replay != nil, a.Ordinary == nil, !pending) && validReplay(a.Replay)
	case StoragePhaseOrdinaryApplyV1:
		return all(a.Lifecycle == StorageLifecycleRecoveryRequiredV1, a.Cleanup == nil, a.Replay == nil, a.Ordinary != nil, !pending) && validOrdinary(a)
	}
	return false
}

func validTop(a StorageAuthorityV1) bool {
	if !validProfilePromises(a) || a.ActiveGenerationID == 0 || a.ActiveGenerationID >= a.NextGenerationID {
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

func ValidateStorageAuthorityV1(a StorageAuthorityV1) error {
	if !validTop(a) || !validPhasePayload(a) || !validDescriptors(a) || !validOwners(a) {
		return errSchema
	}
	return nil
}
