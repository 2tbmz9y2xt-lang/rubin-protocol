package mdbx

import "slices"

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
	point := points[0]
	if descending {
		point = points[len(points)-1]
	}
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
	f := newF
	if oldOK {
		f = oldF
	}
	return validOrdinaryTail(a, f, seen)
}
