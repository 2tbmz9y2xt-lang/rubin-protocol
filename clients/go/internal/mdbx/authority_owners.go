package mdbx

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

func validOwners(a StorageAuthorityV1) bool {
	replay, cleanup, selected := uint64(0), a.Cleanup, a.SelectedSide
	if a.Replay != nil {
		replay = a.Replay.TargetGenerationID
	}
	if a.Ordinary != nil {
		cleanup, selected = a.Ordinary.CarriedCleanup, a.Ordinary.CapturedSelectedSide
	}
	side, sidesOK := uint64(0), true
	if selected != nil {
		side = selected.GenerationID
	}
	if cleanup != nil {
		for _, span := range cleanup.Spans {
			if span.Kind == CleanupSpanSideV1 {
				side, sidesOK = span.GenerationID, anyTrue(side == 0, side == span.GenerationID)
				break
			}
		}
	}
	if !sidesOK || (a.Ordinary == nil && !validLiveSide(selected, cleanup)) {
		return false
	}
	obsolete, cleanupOK := validCleanupRelations(a, cleanup, selected, side)
	active, next := a.ActiveGenerationID, a.NextGenerationID
	return all(cleanupOK, anyTrue(replay == 0, replay != active), anyTrue(side == 0, side != active), anyTrue(replay == 0, replay < next), anyTrue(side == 0, side < next), anyTrue(obsolete == 0, obsolete < next))
}

// validLiveSide admits a live selected side beside a pending SIDE span only in the rolling-prepared shape: the one-slot
// descriptor and exactly SIDE(g,first-1,first-1,first-1) (RUBIN_MEMPOOL_POLICY.md 6.4.1.3). A captured ORDINARY side
// and its frozen SIDE keep the separate relation of validOrdinaryTarget. validSelected already proved first>=F+1>=1.
func validLiveSide(selected *SelectedSideV1, cleanup *CleanupV1) bool {
	if selected == nil || cleanup == nil {
		return true
	}
	first := selected.TipHeight - uint64(selected.RowCount) + 1
	for _, span := range cleanup.Spans {
		if span.Kind == CleanupSpanSideV1 {
			return all(selected.RowCount == 1439, selected.TipHeight-selected.F >= 1440,
				span == CleanupSpanV1{Kind: CleanupSpanSideV1, GenerationID: selected.GenerationID, FirstHeight: first - 1, LastHeight: first - 1, NextHeight: first - 1})
		}
	}
	return true
}
