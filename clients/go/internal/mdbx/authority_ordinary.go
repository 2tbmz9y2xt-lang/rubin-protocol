package mdbx

func validPoints(points authorityPoints, descending bool, earlier authorityPoints) bool {
	var previous uint64
	for i := 0; i < points.len(); i++ {
		point := points.at(i)
		if !all(point.Height <= maxAuthorityHeight, !points.hasHash(point.BlockHash, i), !earlier.hasHash(point.BlockHash, earlier.len())) {
			return false
		}
		if i > 0 && !validPointStep(previous, point.Height, descending) {
			return false
		}
		previous = point.Height
	}
	return true
}

func validFailure(f *RecordedFailureV1, newSuffix authorityPoints) bool {
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
		return newSuffix.hasHash(*f.FailedBlockHash, newSuffix.len())
	case RecordedFailureStoreIntegrityV1, RecordedFailureLocalInvariantV1, RecordedFailureNoncanonicalV1:
		return f.FailedBlockHash == nil
	}
	return false
}

func validStage(a authorityValidation) bool {
	o := a.Ordinary
	switch o.Stage {
	case OrdinaryStageDisconnectV1:
		return validDisconnectStage(a)
	case OrdinaryStageConnectV1:
		return validConnectStage(a)
	case OrdinaryStageRollbackNewV1:
		return validRollbackNewStage(a)
	case OrdinaryStageRestoreOldV1:
		return validRestoreOldStage(a)
	}
	return false
}

func validDisconnectStage(a authorityValidation) bool {
	o := a.Ordinary
	return a.old.len() > 0 && o.RecordedFailure == nil && (o.Cursor == nil || a.old.contains(*o.Cursor))
}

func validConnectStage(a authorityValidation) bool {
	o := a.Ordinary
	return a.new.len() > 0 && o.RecordedFailure == nil && ((o.Cursor == nil && a.old.len() == 0) || (o.Cursor != nil && a.new.contains(*o.Cursor)))
}

func validRollbackNewStage(a authorityValidation) bool {
	o := a.Ordinary
	return a.new.len() > 0 && o.RecordedFailure != nil && o.Cursor != nil && a.new.contains(*o.Cursor) && (a.old.len() > 0 || *o.Cursor != a.new.at(0))
}

func validRestoreOldStage(a authorityValidation) bool {
	o := a.Ordinary
	return a.old.len() > 0 && o.RecordedFailure != nil && o.Cursor != nil && *o.Cursor != a.old.at(0) && a.old.contains(*o.Cursor)
}

func suffixF(points authorityPoints, descending bool) (uint64, bool) {
	if points.len() == 0 {
		return 0, false
	}
	point := points.at(0)
	if descending {
		point = points.at(points.len() - 1)
	}
	if point.Height == 0 {
		return 0, false
	}
	return point.Height - 1, true
}

// validOrdinaryTargetFor requires a nonempty N whose last point is the target and a captured side describing exactly N
// (RUBIN_MEMPOOL_POLICY.md 6.4.1.2, 6.4.1.7): a full capture whose rows are exactly N, or the one-slot capture of
// N[1:] plus the same-generation frozen SIDE singleton at N[0] in carried_cleanup, whose union is N of 1440.
func validOrdinaryTargetFor(a authorityValidation, f uint64, tree bool) bool {
	o := a.Ordinary
	side := o.CapturedSelectedSide
	if a.new.len() == 0 || side == nil || !validSelectedFor(side, tree) {
		return false
	}
	target := a.new.at(a.new.len() - 1)
	if !all(o.Target == target, side.F == f, side.TipHeight == target.Height, side.TipHash == target.BlockHash) {
		return false
	}
	first := side.TipHeight - uint64(side.RowCount) + 1
	if int(side.RowCount) == a.new.len() {
		return first == a.new.at(0).Height
	}
	return validCapturedUnion(a, side, first)
}

// validCapturedUnion is the captured1439+frozenSIDE1 union covering N1440; the captured row count alone never
// stands for the union's cardinality.
func validCapturedUnion(a authorityValidation, side *SelectedSideV1, first uint64) bool {
	if a.Ordinary.CarriedCleanup == nil || a.new.len() != 1440 || side.RowCount != 1439 || first != a.new.at(0).Height+1 {
		return false
	}
	frozen := CleanupSpanV1{Kind: CleanupSpanSideV1, GenerationID: side.GenerationID, FirstHeight: first - 1, LastHeight: first - 1, NextHeight: first - 1}
	return a.carried.contains(frozen)
}

func laggedPromise(height, window uint64) uint64 {
	if height < window {
		return 0
	}
	return height - window + 1
}

func validOrdinaryPromises(a authorityValidation) bool {
	height := uint64(0)
	if a.old.len() > 0 {
		height = a.old.at(0).Height
	} else {
		height = a.new.at(0).Height - 1
	}
	return a.U == laggedPromise(height, 1440)
}

func validOrdinaryTailFor(a authorityValidation, f uint64, tree bool) bool {
	o := a.Ordinary
	if !validOrdinaryTargetFor(a, f, tree) || !validStage(a) || !validFailure(o.RecordedFailure, a.new) {
		return false
	}
	if o.CarriedCleanup != nil && !validCleanupFor(a.carried, tree) {
		return false
	}
	return validOrdinaryPromises(a)
}

func validOrdinaryFor(a authorityValidation, tree bool) bool {
	if !all(a.old.len() <= 1440, a.new.len() >= 1, a.new.len() <= 1440,
		anyTrue(a.old.len() >= 1, a.new.len() >= 2)) {
		return false
	}
	if !validPoints(a.old, true, authorityPoints{}) || !validPoints(a.new, false, a.old) {
		return false
	}
	oldF, oldOK := suffixF(a.old, true)
	newF, newOK := suffixF(a.new, false)
	if !all(anyTrue(a.old.len() == 0, oldOK), anyTrue(a.new.len() == 0, newOK)) {
		return false
	}
	if !anyTrue(all(oldOK, !newOK), all(!oldOK, newOK), all(oldOK, newOK, oldF == newF)) {
		return false
	}
	f := newF
	if oldOK {
		f = oldF
	}
	return validOrdinaryTailFor(a, f, tree)
}
