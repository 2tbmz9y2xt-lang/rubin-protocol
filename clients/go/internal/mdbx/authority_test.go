package mdbx

import (
	"encoding/binary"
	"fmt"
	"reflect"
	"testing"
)

type authorityCase struct {
	name string
	a    StorageAuthorityV1
}
type mutationCase[T any] struct {
	name   string
	mutate func(*T)
}

func modelHash(n uint64) (hash [32]byte) { binary.BigEndian.PutUint64(hash[24:], n); return hash }
func modelWork(maximum bool) (work [40]byte) {
	work[39] = 1
	if maximum {
		work[3], work[39] = 1, 0
	}
	return work
}

func modelPoint(h, n uint64) AuthorityPointV1 { return AuthorityPointV1{h, modelHash(n)} }

func modelSide(g, f, tip uint64, rows uint16, bytes uint64) *SelectedSideV1 {
	return &SelectedSideV1{g, f, tip, modelHash(tip), modelWork(false), rows, bytes}
}

func modelBase(profile byte, b, u uint64) StorageAuthorityV1 {
	return StorageAuthorityV1{1, StorageProfileV1(profile), b, u, 1, 2, StoragePhaseV1(1), StorageLifecycleV1(1), nil, nil, nil, nil, nil, nil, nil}
}

func modelCleanup() *CleanupV1 {
	return &CleanupV1{[]CleanupSpanV1{{CleanupSpanKindV1(2), 1, 0, 0, 0}}}
}

func modelPrune(recovery bool) StorageAuthorityV1 {
	a := modelBase(1, 1, 13681)
	a.Phase, a.Cleanup = StoragePhaseV1(2), modelCleanup()
	if recovery {
		p := StorageProfileV1(2)
		a.Lifecycle, a.PendingTargetProfile = StorageLifecycleV1(2), &p
	}
	return a
}

func modelTarget() RecoveryTargetV1 {
	return RecoveryTargetV1{modelHash(11), modelHash(12), modelHash(13), 2, modelWork(false)}
}

func modelReplay(cursor byte) StorageAuthorityV1 {
	a := modelBase(1, 0, 0)
	a.NextGenerationID, a.Phase, a.Lifecycle = 3, StoragePhaseV1(3), StorageLifecycleV1(2)
	a.Replay = &ReplayV1{StorageProfileV1(2), 2, modelTarget(), ReplayCursorV1{ReplayCursorKindV1(cursor), 0, [32]byte{}}}
	if cursor == 2 {
		a.Replay.Cursor.BlockHash = a.Replay.Target.GenesisHash
	}
	return a
}

func modelFailure(kind byte) *RecordedFailureV1 {
	return &RecordedFailureV1{RecordedFailureKindV1(kind), nil, []byte{0x31}, []byte{0x41}}
}

func modelPoints(first uint64, count int, ascending bool, marker uint64) []AuthorityPointV1 {
	points := make([]AuthorityPointV1, count)
	for i := range points {
		height := first - uint64(i)
		if ascending {
			height = first + uint64(i)
		}
		points[i] = modelPoint(height, marker+uint64(i))
	}
	return points
}

func modelOrdinary(stage byte, d, c int, hOld uint64, profile byte, b, u uint64) StorageAuthorityV1 {
	a := modelBase(profile, b, u)
	a.Phase, a.Lifecycle = StoragePhaseV1(4), StorageLifecycleV1(2)
	o := &OrdinaryApplyV1{Stage: OrdinaryStageV1(stage)}
	f := hOld
	if d > 0 {
		o.OldSuffix = modelPoints(hOld, d, false, 1000)
		f = hOld - uint64(d)
	}
	if c > 0 {
		o.NewSuffix = modelPoints(f+1, c, true, 2000)
		o.Target = o.NewSuffix[len(o.NewSuffix)-1]
		o.CapturedSelectedSide = modelSide(2, f, o.Target.Height, uint16(min(c, 1440)), uint64(min(c, 1440)))
		o.CapturedSelectedSide.TipHash = o.Target.BlockHash
		a.NextGenerationID = 3
	} else {
		o.Target = modelPoint(f, 3000)
	}
	switch stage {
	case 2:
		if d > 0 {
			cursor := o.NewSuffix[0]
			o.Cursor = &cursor
		}
	case 3:
		cursor := o.NewSuffix[0]
		o.Cursor, o.RecordedFailure = &cursor, modelFailure(1)
	case 4:
		cursor := o.OldSuffix[1]
		o.Cursor, o.RecordedFailure = &cursor, modelFailure(2)
	}
	a.Ordinary = o
	return a
}

func modelDetached(count int, length uint64) *DetachedSuffixV1 {
	d := &DetachedSuffixV1{make([]DetachedSuffixEntryV1, count), AuthorityPointV1{}, uint16(count), uint64(count) * length}
	for i := range d.Entries {
		d.Entries[i] = DetachedSuffixEntryV1{uint64(count - 1 - i), modelHash(uint64(i + 1)), length}
	}
	if count > 0 {
		d.Cursor = AuthorityPointV1{d.Entries[0].Height, d.Entries[0].Hash}
	}
	return d
}

func wantModel(t *testing.T, name string, a StorageAuthorityV1, valid bool) {
	t.Helper()
	t.Run(name, func(t *testing.T) {
		err := ValidateStorageAuthorityV1(a)
		if valid && err != nil {
			t.Fatalf("valid authority rejected: %v", err)
		}
		if !valid && !exactErr(err) {
			t.Fatalf("invalid authority error = %v, want exact errSchema", err)
		}
	})
}

func exactErr(err error) bool { return err == errSchema } //nolint:errorlint // Exact sentinel identity is the contract.

func edit(a StorageAuthorityV1, f func(*StorageAuthorityV1)) StorageAuthorityV1 { f(&a); return a }

func TestStorageAuthorityV1Enums(t *testing.T) {
	for _, row := range []struct {
		name string
		got  uint8
		want uint8
	}{
		{"version", StorageAuthorityVersionV1, 1},
		{"profile pruned", uint8(StorageProfilePrunedV1), 1},
		{"profile archive", uint8(StorageProfileArchiveV1), 2},
		{"phase none", uint8(StoragePhaseNoneV1), 1},
		{"phase prune", uint8(StoragePhasePruneGCV1), 2},
		{"phase replay", uint8(StoragePhaseReplayV1), 3},
		{"phase ordinary", uint8(StoragePhaseOrdinaryApplyV1), 4},
		{"lifecycle stable", uint8(StorageLifecycleStableV1), 1},
		{"lifecycle recovery", uint8(StorageLifecycleRecoveryRequiredV1), 2},
		{"cleanup generation", uint8(CleanupSpanGenerationV1), 1},
		{"cleanup blocks", uint8(CleanupSpanBlocksV1), 2},
		{"cleanup undo", uint8(CleanupSpanUndoV1), 3},
		{"cleanup side", uint8(CleanupSpanSideV1), 4},
		{"cursor pre-genesis", uint8(ReplayCursorPreGenesisV1), 1},
		{"cursor applied", uint8(ReplayCursorAppliedV1), 2},
		{"stage disconnect", uint8(OrdinaryStageDisconnectV1), 1},
		{"stage connect", uint8(OrdinaryStageConnectV1), 2},
		{"stage rollback new", uint8(OrdinaryStageRollbackNewV1), 3},
		{"stage restore old", uint8(OrdinaryStageRestoreOldV1), 4},
		{"failure consensus", uint8(RecordedFailureConsensusV1), 1},
		{"failure store", uint8(RecordedFailureStoreIntegrityV1), 2},
		{"failure invariant", uint8(RecordedFailureLocalInvariantV1), 3},
		{"failure noncanonical", uint8(RecordedFailureNoncanonicalV1), 4},
	} {
		t.Run(row.name, func(t *testing.T) {
			if row.got != row.want {
				t.Fatalf("constant = %d, want %d", row.got, row.want)
			}
		})
	}
	for _, version := range []uint8{0, 2, 255} {
		a := modelBase(1, 0, 0)
		a.Version = version
		wantModel(t, fmt.Sprintf("version %d rejected", version), a, false)
	}
	for _, profile := range []byte{0, 3, 255} {
		wantModel(t, fmt.Sprintf("profile %d rejected", profile), modelBase(profile, 0, 0), false)
	}
}

func TestStorageAuthorityV1LegalStateMatrix(t *testing.T) {
	for phase := byte(1); phase <= 4; phase++ {
		for lifecycle := byte(1); lifecycle <= 2; lifecycle++ {
			for payload := byte(0); payload <= 3; payload++ {
				for pending := byte(0); pending <= 2; pending++ {
					a := modelBase(1, 1, 13681)
					a.Phase, a.Lifecycle = StoragePhaseV1(phase), StorageLifecycleV1(lifecycle)
					if payload == 1 {
						a.Cleanup = modelCleanup()
					}
					if payload == 2 {
						a.Replay = modelReplay(1).Replay
						a.NextGenerationID = 3
					}
					if payload == 3 {
						a.Ordinary = modelOrdinary(2, 1, 2, 15120, 1, 1, 13681).Ordinary
						a.NextGenerationID = 3
					}
					if pending != 0 {
						p := StorageProfileV1(pending)
						a.PendingTargetProfile = &p
					}
					valid := phase == 1 && lifecycle == 1 && payload == 0 && pending == 0 ||
						phase == 2 && lifecycle == 1 && payload == 1 && pending == 0 ||
						phase == 2 && lifecycle == 2 && payload == 1 && (pending == 1 || pending == 2) ||
						phase == 3 && lifecycle == 2 && payload == 2 && pending == 0 ||
						phase == 4 && lifecycle == 2 && payload == 3 && pending == 0
					wantModel(t, fmt.Sprintf("phase=%d lifecycle=%d payload=%d pending=%d", phase, lifecycle, payload, pending), a, valid)
				}
			}
		}
	}
	for _, value := range []StoragePhaseV1{0, 5, 255} {
		a := modelBase(1, 0, 0)
		a.Phase = value
		wantModel(t, fmt.Sprintf("unknown phase %d", value), a, false)
	}
	for _, value := range []StorageLifecycleV1{0, 3, 255} {
		a := modelBase(1, 0, 0)
		a.Lifecycle = value
		wantModel(t, fmt.Sprintf("unknown lifecycle %d", value), a, false)
	}
	wantModel(t, "stable selected side", edit(modelBase(1, 0, 0), func(a *StorageAuthorityV1) { a.NextGenerationID, a.SelectedSide = 3, modelSide(2, 0, 1, 1, 1) }), true)
	wantModel(t, "prune detached suffix", edit(modelPrune(false), func(a *StorageAuthorityV1) { a.DetachedSuffix = modelDetached(1, 1) }), true)
	wantModel(t, "detached without cleanup", edit(modelBase(1, 0, 0), func(a *StorageAuthorityV1) { a.DetachedSuffix = modelDetached(1, 1) }), false)
	wantModel(t, "selected and detached", edit(modelPrune(false), func(a *StorageAuthorityV1) {
		a.NextGenerationID, a.SelectedSide, a.DetachedSuffix = 3, modelSide(2, 0, 1, 1, 1), modelDetached(1, 1)
	}), false)
}

func TestStorageAuthorityV1GenerationOwners(t *testing.T) {
	wantModel(t, "generation one next two", modelBase(1, 0, 0), true)
	wantModel(t, "next generation maximum", edit(modelBase(1, 0, 0), func(a *StorageAuthorityV1) { a.ActiveGenerationID, a.NextGenerationID = ^uint64(0)-1, ^uint64(0) }), true)
	full := modelPrune(false)
	full.NextGenerationID = 4
	full.SelectedSide = modelSide(2, 1, 2, 1, 1)
	full.Cleanup.Spans = []CleanupSpanV1{
		{Kind: 1, GenerationID: 3},
		{Kind: 2, GenerationID: 1, FirstHeight: 0, LastHeight: 0, NextHeight: 0},
		{Kind: 3, GenerationID: 1, FirstHeight: 0, LastHeight: 0, NextHeight: 0},
		{Kind: 4, GenerationID: 2, FirstHeight: 0, LastHeight: 0, NextHeight: 0},
	}
	wantModel(t, "active obsolete side three ids", full, true)
	adjacent := full
	adjacent.Cleanup = &CleanupV1{Spans: []CleanupSpanV1{{Kind: 4, GenerationID: 2, FirstHeight: 1, LastHeight: 1, NextHeight: 1}}}
	wantModel(t, "SIDE cleanup adjacent boundary", adjacent, true)
	wantModel(t, "active zero", edit(modelBase(1, 0, 0), func(a *StorageAuthorityV1) { a.ActiveGenerationID = 0 }), false)
	for _, row := range []mutationCase[StorageAuthorityV1]{
		{"next zero", func(a *StorageAuthorityV1) { a.NextGenerationID = 0 }},
		{"next one", func(a *StorageAuthorityV1) { a.NextGenerationID = 1 }},
		{"next equals obsolete", func(a *StorageAuthorityV1) { a.NextGenerationID = 3 }},
		{"active reaches next", func(a *StorageAuthorityV1) {
			a.ActiveGenerationID = 4
			a.Cleanup.Spans[1].GenerationID = 4
			a.Cleanup.Spans[2].GenerationID = 4
		}},
		{"obsolete active", func(a *StorageAuthorityV1) { a.Cleanup.Spans[0].GenerationID = 1 }},
		{"obsolete side", func(a *StorageAuthorityV1) { a.Cleanup.Spans[0].GenerationID = 2 }},
		{"blocks off active", func(a *StorageAuthorityV1) { a.Cleanup.Spans[1].GenerationID = 3 }},
		{"undo off active", func(a *StorageAuthorityV1) { a.Cleanup.Spans[2].GenerationID = 3 }},
		{"side active", func(a *StorageAuthorityV1) { a.SelectedSide.GenerationID = 1; a.Cleanup.Spans[3].GenerationID = 1 }},
		{"side mismatch", func(a *StorageAuthorityV1) { a.NextGenerationID = 5; a.Cleanup.Spans[3].GenerationID = 4 }},
		{"side future", func(a *StorageAuthorityV1) { a.SelectedSide.GenerationID = 4; a.Cleanup.Spans[3].GenerationID = 4 }},
		{"side overlap", func(a *StorageAuthorityV1) { a.Cleanup.Spans[3].LastHeight = 2; a.Cleanup.Spans[3].NextHeight = 2 }},
	} {
		a := full
		a.Cleanup = &CleanupV1{Spans: append([]CleanupSpanV1(nil), full.Cleanup.Spans...)}
		side := *full.SelectedSide
		a.SelectedSide = &side
		row.mutate(&a)
		wantModel(t, row.name, a, false)
	}
	wantModel(t, "replay equals active", edit(modelReplay(1), func(a *StorageAuthorityV1) { a.Replay.TargetGenerationID = 1 }), false)
	wantModel(t, "replay future", edit(modelReplay(1), func(a *StorageAuthorityV1) { a.Replay.TargetGenerationID = 3 }), false)
}

func TestStorageAuthorityV1Cleanup(t *testing.T) {
	base := modelPrune(false)
	for _, spans := range [][]CleanupSpanV1{
		{{Kind: 2, GenerationID: 1, FirstHeight: 0, LastHeight: 0, NextHeight: 0}},
		{{Kind: 2, GenerationID: 1, FirstHeight: 0, LastHeight: 1, NextHeight: 0}},
		{{Kind: 2, GenerationID: 1, FirstHeight: 0, LastHeight: 1, NextHeight: 1}},
	} {
		a := base
		a.B = 2
		a.U = 13682
		a.Cleanup = &CleanupV1{Spans: spans}
		wantModel(t, fmt.Sprintf("progress %d-%d-%d", spans[0].FirstHeight, spans[0].NextHeight, spans[0].LastHeight), a, true)
	}
	for _, kind := range []CleanupSpanKindV1{0, 5, 255} {
		a := base
		a.Cleanup = &CleanupV1{Spans: []CleanupSpanV1{{Kind: kind, GenerationID: 1}}}
		wantModel(t, fmt.Sprintf("unknown cleanup kind %d", kind), a, false)
	}
	for _, row := range []struct {
		name  string
		spans []CleanupSpanV1
	}{
		{"cleanup empty", nil},
		{"span zero generation", []CleanupSpanV1{{Kind: 2}}},
		{"generation first nonzero", []CleanupSpanV1{{Kind: 1, GenerationID: 2, FirstHeight: 1}}},
		{"generation last nonzero", []CleanupSpanV1{{Kind: 1, GenerationID: 2, LastHeight: 1}}},
		{"generation next nonzero", []CleanupSpanV1{{Kind: 1, GenerationID: 2, NextHeight: 1}}},
		{"range first after next", []CleanupSpanV1{{Kind: 2, GenerationID: 1, FirstHeight: 1, LastHeight: 0, NextHeight: 0}}},
		{"range next after last", []CleanupSpanV1{{Kind: 2, GenerationID: 1, FirstHeight: 0, LastHeight: 0, NextHeight: 1}}},
		{"range height overflow", []CleanupSpanV1{{Kind: 4, GenerationID: 2, FirstHeight: 0x100000000, LastHeight: 0x100000000, NextHeight: 0x100000000}}},
		{"span wrong order", []CleanupSpanV1{{Kind: 3, GenerationID: 1}, {Kind: 2, GenerationID: 1}}},
		{"duplicate generation", []CleanupSpanV1{{Kind: 1, GenerationID: 2}, {Kind: 1, GenerationID: 3}}},
		{"duplicate blocks", []CleanupSpanV1{{Kind: 2, GenerationID: 1}, {Kind: 2, GenerationID: 1}}},
		{"duplicate undo", []CleanupSpanV1{{Kind: 3, GenerationID: 1}, {Kind: 3, GenerationID: 1}}},
		{"duplicate side", []CleanupSpanV1{{Kind: 4, GenerationID: 2}, {Kind: 4, GenerationID: 2}}},
	} {
		a := base
		a.NextGenerationID = 4
		a.Cleanup = &CleanupV1{Spans: row.spans}
		wantModel(t, row.name, a, false)
	}
	wantModel(t, "blocks with zero promise", edit(modelPrune(false), func(a *StorageAuthorityV1) { a.B, a.U = 0, 0 }), false)
	wantModel(t, "blocks reaches promise", edit(modelPrune(false), func(a *StorageAuthorityV1) { a.Cleanup.Spans[0].LastHeight = a.B }), false)
	wantModel(t, "undo with zero promise", edit(modelPrune(false), func(a *StorageAuthorityV1) { a.B, a.U, a.Cleanup.Spans[0].Kind = 0, 0, 3 }), false)
	wantModel(t, "undo reaches promise", edit(modelPrune(false), func(a *StorageAuthorityV1) { a.Cleanup.Spans[0].Kind, a.Cleanup.Spans[0].LastHeight = 3, a.U }), false)
	wantModel(t, "standalone SIDE cleanup maximum height without selected side", edit(modelPrune(false), func(a *StorageAuthorityV1) {
		a.NextGenerationID, a.Cleanup.Spans[0] = 3, CleanupSpanV1{Kind: 4, GenerationID: 2, FirstHeight: 0xffffffff, LastHeight: 0xffffffff, NextHeight: 0xffffffff}
	}), true)
}

func TestStorageAuthorityV1ReplayAndOwners(t *testing.T) {
	wantModel(t, "replay pre-genesis", modelReplay(1), true)
	applied := modelReplay(2)
	wantModel(t, "replay applied at height zero", applied, true)
	applied.Replay.Cursor.Height, applied.Replay.Cursor.BlockHash = 2, applied.Replay.Target.TipHash
	wantModel(t, "replay applied at target", applied, true)
	wantModel(t, "replay applied below target", edit(modelReplay(2), func(a *StorageAuthorityV1) { a.Replay.Cursor.Height, a.Replay.Cursor.BlockHash = 1, modelHash(14) }), true)
	wantModel(t, "replay target minimum height", edit(modelReplay(1), func(a *StorageAuthorityV1) { a.Replay.Target.TipHeight = 1 }), true)
	maximumWork := modelReplay(1)
	maximumWork.Replay.Target.CumulativeChainwork = modelWork(true)
	wantModel(t, "replay target chainwork 2^288", maximumWork, true)
	wantModel(t, "replay target chainwork zero", edit(modelReplay(1), func(a *StorageAuthorityV1) { a.Replay.Target.CumulativeChainwork = [40]byte{} }), false)
	tooMuchWork := maximumWork
	tooMuchWork.Replay.Target.CumulativeChainwork[39] = 1
	wantModel(t, "replay target chainwork 2^288 plus one", tooMuchWork, false)
	for _, profile := range []StorageProfileV1{1, 2} {
		a := modelReplay(1)
		a.Replay.TargetProfile = profile
		wantModel(t, fmt.Sprintf("replay target profile %d", profile), a, true)
	}
	for _, row := range []mutationCase[ReplayV1]{
		{"target profile zero", func(r *ReplayV1) { r.TargetProfile = 0 }},
		{"target profile unknown", func(r *ReplayV1) { r.TargetProfile = 3 }},
		{"target generation zero", func(r *ReplayV1) { r.TargetGenerationID = 0 }},
		{"target tip zero", func(r *ReplayV1) { r.Target.TipHeight = 0 }},
		{"target tip overflow", func(r *ReplayV1) { r.Target.TipHeight = 0x100000000 }},
		{"cursor zero", func(r *ReplayV1) { r.Cursor.Kind = 0 }},
		{"cursor unknown", func(r *ReplayV1) { r.Cursor.Kind = 3 }},
		{"pre-genesis height", func(r *ReplayV1) { r.Cursor.Height = 1 }},
		{"pre-genesis hash", func(r *ReplayV1) { r.Cursor.BlockHash = modelHash(1) }},
	} {
		a := modelReplay(1)
		row.mutate(a.Replay)
		wantModel(t, row.name, a, false)
	}
	wantModel(t, "applied genesis hash mismatch", edit(modelReplay(2), func(a *StorageAuthorityV1) { a.Replay.Cursor.BlockHash = modelHash(99) }), false)
	wantModel(t, "applied above target", edit(modelReplay(2), func(a *StorageAuthorityV1) { a.Replay.Cursor.Height = 3 }), false)
	wantModel(t, "applied target hash mismatch", edit(modelReplay(2), func(a *StorageAuthorityV1) { a.Replay.Cursor.Height, a.Replay.Cursor.BlockHash = 2, modelHash(99) }), false)
	wantModel(t, "replay target maximum height", edit(modelReplay(1), func(a *StorageAuthorityV1) { a.Replay.Target.TipHeight = 0xffffffff }), true)
}

func TestStorageAuthorityV1SelectedSide(t *testing.T) {
	for _, row := range []struct {
		name    string
		f, tip  uint64
		rows    uint16
		logical uint64
	}{
		{"C one maximum height lower bytes", 0xfffffffe, 0xffffffff, 1, 1},
		{"C one upper bytes", 0, 1, 1, 68_000_125},
		{"C 1440 lower bytes", 0, 1440, 1440, 1440},
		{"C 1440 upper bytes", 0, 1440, 1440, 97_920_180_000},
		{"C above 1440", 0, 1441, 1440, 1440},
	} {
		a := modelBase(1, 0, 0)
		a.NextGenerationID, a.SelectedSide = 3, modelSide(2, row.f, row.tip, row.rows, row.logical)
		wantModel(t, row.name, a, true)
	}
	base := modelBase(1, 0, 0)
	base.NextGenerationID, base.SelectedSide = 3, modelSide(2, 0, 2, 2, 2)
	for _, row := range []mutationCase[SelectedSideV1]{
		{"selected generation zero", func(s *SelectedSideV1) { s.GenerationID = 0 }},
		{"selected F equals tip", func(s *SelectedSideV1) { s.F = s.TipHeight; s.RowCount = 0; s.LogicalBytes = 0 }},
		{"selected F above tip", func(s *SelectedSideV1) { s.F = s.TipHeight + 1; s.RowCount = 1440; s.LogicalBytes = 1440 }},
		{"selected tip overflow", func(s *SelectedSideV1) { s.TipHeight = 0x100000000; s.RowCount = 1440; s.LogicalBytes = 1440 }},
		{"selected row count low", func(s *SelectedSideV1) { s.RowCount = 1 }},
		{"selected row count high", func(s *SelectedSideV1) { s.RowCount = 3; s.LogicalBytes = 3 }},
		{"selected logical below rows", func(s *SelectedSideV1) { s.LogicalBytes = 1 }},
		{"selected logical above product", func(s *SelectedSideV1) { s.LogicalBytes = 136000251 }},
		{"selected zero work", func(s *SelectedSideV1) { s.CumulativeChainwork = [40]byte{} }},
	} {
		a, side := base, *base.SelectedSide
		a.SelectedSide = &side
		row.mutate(a.SelectedSide)
		wantModel(t, row.name, a, false)
	}
}

func TestStorageAuthorityV1DetachedSuffix(t *testing.T) {
	for _, row := range []struct {
		name   string
		count  int
		length uint64
	}{
		{"detached one minimum", 1, 1},
		{"detached one maximum", 1, 68_000_125},
		{"detached 1440 SIDE_MAX", 1440, 68_000_125},
	} {
		a := modelPrune(false)
		a.DetachedSuffix = modelDetached(row.count, row.length)
		wantModel(t, row.name, a, true)
	}
	maximumHeight := modelPrune(false)
	maximumHeight.DetachedSuffix = modelDetached(1, 1)
	maximumHeight.DetachedSuffix.Entries[0].Height = 0xffffffff
	maximumHeight.DetachedSuffix.Cursor.Height = 0xffffffff
	wantModel(t, "detached maximum height", maximumHeight, true)
	for _, row := range []mutationCase[DetachedSuffixV1]{
		{"detached empty", func(d *DetachedSuffixV1) { d.Entries = nil; d.EntryCount = 0 }},
		{"detached 1441 entries", func(d *DetachedSuffixV1) { *d = *modelDetached(1441, 1) }},
		{"detached entry count low", func(d *DetachedSuffixV1) { d.EntryCount = 1 }},
		{"detached entry count high", func(d *DetachedSuffixV1) { d.EntryCount = 3 }},
		{"detached height overflow", func(d *DetachedSuffixV1) {
			*d = *modelDetached(1, 1)
			d.Entries[0].Height, d.Cursor.Height = 0x100000000, 0x100000000
		}},
		{"detached wrong direction", func(d *DetachedSuffixV1) { d.Entries[1].Height = 2 }},
		{"detached height gap", func(d *DetachedSuffixV1) { d.Entries[0].Height, d.Cursor.Height = 2, 2 }},
		{"detached duplicate hash", func(d *DetachedSuffixV1) { d.Entries[1].Hash = d.Entries[0].Hash }},
		{"detached zero length", func(d *DetachedSuffixV1) { d.Entries[0].BlockBytesLen, d.LogicalBytes = 0, 1 }},
		{"detached length overflow", func(d *DetachedSuffixV1) { d.Entries[0].BlockBytesLen, d.LogicalBytes = 68_000_126, 68_000_127 }},
		{"detached sum low", func(d *DetachedSuffixV1) { d.LogicalBytes = 1 }},
		{"detached sum high", func(d *DetachedSuffixV1) { d.LogicalBytes = 3 }},
		{"detached cursor height", func(d *DetachedSuffixV1) { d.Cursor.Height++ }},
		{"detached cursor hash", func(d *DetachedSuffixV1) { d.Cursor.BlockHash = modelHash(99) }},
		{"detached logical SIDE_MAX plus one", func(d *DetachedSuffixV1) {
			*d = *modelDetached(1440, 68_000_125)
			d.LogicalBytes = 97_920_180_001
		}},
	} {
		a := modelPrune(false)
		a.DetachedSuffix = modelDetached(2, 1)
		row.mutate(a.DetachedSuffix)
		wantModel(t, row.name, a, false)
	}
}

func TestStorageAuthorityV1OrdinaryStageCursor(t *testing.T) {
	change := func(a StorageAuthorityV1, edit func(*OrdinaryApplyV1)) StorageAuthorityV1 {
		edit(a.Ordinary)
		return a
	}
	point := func(p AuthorityPointV1) *AuthorityPointV1 { return &p }
	hash := func(h [32]byte) *[32]byte { return &h }
	for _, row := range []authorityCase{
		{"D1 C0 disconnect", modelOrdinary(1, 1, 0, 1, 1, 0, 0)},
		{"D1 C2 disconnect", modelOrdinary(1, 1, 2, 1, 1, 0, 0)},
		{"D1 C1 disconnect", modelOrdinary(1, 1, 1, 1, 1, 0, 0)},
		{"D0 C2 connect nil cursor H0", modelOrdinary(2, 0, 2, 0, 1, 0, 0)},
		{"D1 C2 connect", modelOrdinary(2, 1, 2, 15120, 1, 1, 13681)},
		{"rollback new", modelOrdinary(3, 1, 2, 1, 1, 0, 0)},
		{"restore old", modelOrdinary(4, 2, 2, 2, 1, 0, 0)},
		{"D2 C0 restore old", modelOrdinary(4, 2, 0, 2, 1, 0, 0)},
		{"pruned H1439", modelOrdinary(1, 1, 0, 1439, 1, 0, 0)},
		{"pruned H1440", modelOrdinary(1, 1, 0, 1440, 1, 0, 1)},
		{"pruned H15119", modelOrdinary(1, 1, 0, 15119, 1, 0, 13680)},
		{"pruned H15120", modelOrdinary(1, 1, 0, 15120, 1, 1, 13681)},
		{"pruned H max", modelOrdinary(1, 1, 0, 0xffffffff, 1, 4_294_952_176, 4_294_965_856)},
		{"archive H15120", modelOrdinary(1, 1, 0, 15120, 2, 0, 13681)},
		{"D0 C2 pruned H1439", modelOrdinary(2, 0, 2, 1439, 1, 0, 0)},
		{"D0 C2 pruned H1440", modelOrdinary(2, 0, 2, 1440, 1, 0, 1)},
		{"D0 C2 pruned H15119", modelOrdinary(2, 0, 2, 15119, 1, 0, 13680)},
		{"D0 C2 pruned H15120", modelOrdinary(2, 0, 2, 15120, 1, 1, 13681)},
		{"D1440 bound", modelOrdinary(1, 1440, 0, 2000, 1, 0, 561)},
		{"C1440 bound", modelOrdinary(2, 0, 1440, 0, 1, 0, 0)},
	} {
		wantModel(t, row.name, row.a, true)
	}
	captured := modelOrdinary(1, 1, 0, 1, 1, 0, 0)
	captured.NextGenerationID, captured.Ordinary.CapturedSelectedSide = 3, modelSide(2, 0, 1, 1, 1)
	wantModel(t, "C0 standalone captured side", captured, true)
	carried := modelOrdinary(2, 1, 2, 15120, 1, 1, 13681)
	carried.Ordinary.CarriedCleanup = modelCleanup()
	wantModel(t, "valid carried cleanup", carried, true)
	ownerCase := func(kind byte, generation, last uint64) StorageAuthorityV1 {
		a := modelOrdinary(2, 1, 2, 15120, 1, 1, 13681)
		a.NextGenerationID, a.Ordinary.CarriedCleanup = 4, modelCleanup()
		span := &a.Ordinary.CarriedCleanup.Spans[0]
		span.Kind, span.GenerationID, span.LastHeight = CleanupSpanKindV1(kind), generation, last
		return a
	}
	disconnect := modelOrdinary(1, 2, 0, 2, 1, 0, 0)
	disconnect.Ordinary.Cursor = point(disconnect.Ordinary.OldSuffix[0])
	wantModel(t, "disconnect partial cursor", disconnect, true)
	disconnect = modelOrdinary(1, 2, 0, 2, 1, 0, 0)
	disconnect.Ordinary.Cursor = point(disconnect.Ordinary.OldSuffix[1])
	wantModel(t, "disconnect exhausted cursor", disconnect, true)
	connect := modelOrdinary(2, 1, 2, 1, 1, 0, 0)
	wantModel(t, "connect partial cursor", connect, true)
	connect.Ordinary.Cursor = point(connect.Ordinary.NewSuffix[1])
	wantModel(t, "connect exhausted cursor", connect, true)
	wantModel(t, "rollback new nonterminal D0 cursor", edit(modelOrdinary(3, 0, 2, 0, 1, 0, 0), func(a *StorageAuthorityV1) { a.Ordinary.Cursor = point(a.Ordinary.NewSuffix[1]) }), true)
	for _, kind := range []byte{1, 2, 3, 4} {
		a := modelOrdinary(3, 1, 2, 1, 1, 0, 0)
		a.Ordinary.RecordedFailure = modelFailure(kind)
		wantModel(t, fmt.Sprintf("failure kind %d", kind), a, true)
	}
	wantModel(t, "consensus exact N hash", edit(modelOrdinary(3, 1, 2, 1, 1, 0, 0), func(a *StorageAuthorityV1) {
		a.Ordinary.RecordedFailure.FailedBlockHash = hash(a.Ordinary.NewSuffix[1].BlockHash)
	}), true)
	bad := []authorityCase{
		{"D0 C2 disconnect", modelOrdinary(1, 0, 2, 0, 1, 0, 0)},
		{"D0 C1 selector", modelOrdinary(2, 0, 1, 0, 1, 0, 0)},
		{"D1441 overflow", modelOrdinary(1, 1441, 0, 2000, 1, 0, 561)},
		{"C1441 overflow", modelOrdinary(2, 0, 1441, 0, 1, 0, 0)},
		{"unknown stage zero", change(modelOrdinary(1, 1, 0, 1, 1, 0, 0), func(o *OrdinaryApplyV1) { o.Stage = 0 })},
		{"unknown stage five", change(modelOrdinary(1, 1, 0, 1, 1, 0, 0), func(o *OrdinaryApplyV1) { o.Stage = 5 })},
		{"old wrong direction", change(modelOrdinary(1, 3, 0, 3, 1, 0, 0), func(o *OrdinaryApplyV1) { o.OldSuffix[1].Height = 4 })},
		{"old gap", change(modelOrdinary(1, 3, 0, 3, 1, 0, 0), func(o *OrdinaryApplyV1) { o.OldSuffix[0].Height = 4 })},
		{"new wrong direction", change(modelOrdinary(2, 0, 3, 0, 1, 0, 0), func(o *OrdinaryApplyV1) { o.NewSuffix[1].Height = 0 })},
		{"new gap", change(modelOrdinary(2, 0, 2, 0, 1, 0, 0), func(o *OrdinaryApplyV1) {
			o.NewSuffix[1].Height, o.CapturedSelectedSide.TipHeight = 3, 3
			o.Target, o.CapturedSelectedSide.RowCount, o.CapturedSelectedSide.LogicalBytes = o.NewSuffix[1], 3, 3
		})},
		{"old duplicate hash", change(modelOrdinary(1, 2, 0, 2, 1, 0, 0), func(o *OrdinaryApplyV1) { o.OldSuffix[1].BlockHash = o.OldSuffix[0].BlockHash })},
		{"new duplicate hash", change(modelOrdinary(2, 0, 2, 0, 1, 0, 0), func(o *OrdinaryApplyV1) {
			o.NewSuffix[1].BlockHash = o.NewSuffix[0].BlockHash
			o.Target.BlockHash, o.CapturedSelectedSide.TipHash = o.NewSuffix[1].BlockHash, o.NewSuffix[1].BlockHash
		})},
		{"cross-list duplicate hash", change(modelOrdinary(2, 1, 2, 1, 1, 0, 0), func(o *OrdinaryApplyV1) {
			o.NewSuffix[0].BlockHash = o.OldSuffix[0].BlockHash
			o.Cursor = point(o.NewSuffix[0])
		})},
		{"inconsistent F", change(modelOrdinary(2, 1, 2, 1, 1, 0, 0), func(o *OrdinaryApplyV1) {
			o.NewSuffix[0].Height, o.NewSuffix[1].Height, o.Target.Height, o.CapturedSelectedSide.F, o.CapturedSelectedSide.TipHeight = 2, 3, 3, 1, 3
			o.Cursor = point(o.NewSuffix[0])
		})},
		{"C positive target height", change(modelOrdinary(2, 1, 2, 1, 1, 0, 0), func(o *OrdinaryApplyV1) { o.Target.Height++ })},
		{"C positive target hash", change(modelOrdinary(2, 1, 2, 1, 1, 0, 0), func(o *OrdinaryApplyV1) { o.Target.BlockHash = modelHash(99) })},
		{"C zero target height", change(modelOrdinary(1, 1, 0, 1, 1, 0, 0), func(o *OrdinaryApplyV1) { o.Target.Height++ })},
		{"C zero target hash in old", change(modelOrdinary(1, 1, 0, 1, 1, 0, 0), func(o *OrdinaryApplyV1) { o.Target.BlockHash = o.OldSuffix[0].BlockHash })},
		{"missing captured side", change(modelOrdinary(2, 1, 2, 1, 1, 0, 0), func(o *OrdinaryApplyV1) { o.CapturedSelectedSide = nil })},
		{"captured wrong F", change(modelOrdinary(2, 1, 2, 1, 1, 0, 0), func(o *OrdinaryApplyV1) { o.CapturedSelectedSide.F++; o.CapturedSelectedSide.RowCount = 1 })},
		{"captured wrong tip height", change(modelOrdinary(2, 1, 2, 1, 1, 0, 0), func(o *OrdinaryApplyV1) {
			o.CapturedSelectedSide.TipHeight++
			o.CapturedSelectedSide.RowCount = 3
			o.CapturedSelectedSide.LogicalBytes = 3
		})},
		{"captured wrong tip hash", change(modelOrdinary(2, 1, 2, 1, 1, 0, 0), func(o *OrdinaryApplyV1) { o.CapturedSelectedSide.TipHash = modelHash(99) })},
		{"captured invalid logical bytes", change(modelOrdinary(2, 1, 2, 1, 1, 0, 0), func(o *OrdinaryApplyV1) { o.CapturedSelectedSide.LogicalBytes = 0 })},
		{"captured side generation active", change(modelOrdinary(2, 1, 2, 1, 1, 0, 0), func(o *OrdinaryApplyV1) { o.CapturedSelectedSide.GenerationID = 1 })},
		{"captured side generation next", change(modelOrdinary(2, 1, 2, 1, 1, 0, 0), func(o *OrdinaryApplyV1) { o.CapturedSelectedSide.GenerationID = 3 })},
		{"carried BLOCKS off active", ownerCase(2, 2, 0)},
		{"carried UNDO off active", ownerCase(3, 2, 0)},
		{"carried SIDE generation mismatch", ownerCase(4, 3, 0)},
		{"carried SIDE reaches captured first retained height", ownerCase(4, 2, 15120)},
		{"carried GENERATION equals captured side", ownerCase(1, 2, 0)},
		{"invalid standalone captured", change(captured, func(o *OrdinaryApplyV1) { o.CapturedSelectedSide.LogicalBytes = 0 })},
		{"disconnect foreign cursor", change(modelOrdinary(1, 1, 0, 1, 1, 0, 0), func(o *OrdinaryApplyV1) { o.Cursor = point(modelPoint(9, 9)) })},
		{"disconnect failure", change(modelOrdinary(1, 1, 0, 1, 1, 0, 0), func(o *OrdinaryApplyV1) { o.RecordedFailure = modelFailure(1) })},
		{"connect nil cursor with D", change(modelOrdinary(2, 1, 2, 1, 1, 0, 0), func(o *OrdinaryApplyV1) { o.Cursor = nil })},
		{"connect foreign cursor", change(modelOrdinary(2, 1, 2, 1, 1, 0, 0), func(o *OrdinaryApplyV1) { o.Cursor = point(modelPoint(9, 9)) })},
		{"connect failure", change(modelOrdinary(2, 1, 2, 1, 1, 0, 0), func(o *OrdinaryApplyV1) { o.RecordedFailure = modelFailure(1) })},
		{"rollback missing failure", change(modelOrdinary(3, 1, 2, 1, 1, 0, 0), func(o *OrdinaryApplyV1) { o.RecordedFailure = nil })},
		{"rollback nil cursor", change(modelOrdinary(3, 1, 2, 1, 1, 0, 0), func(o *OrdinaryApplyV1) { o.Cursor = nil })},
		{"rollback foreign cursor", change(modelOrdinary(3, 1, 2, 1, 1, 0, 0), func(o *OrdinaryApplyV1) { o.Cursor = point(modelPoint(9, 9)) })},
		{"rollback D0 terminal cursor", modelOrdinary(3, 0, 2, 0, 1, 0, 0)},
		{"restore missing failure", change(modelOrdinary(4, 2, 2, 2, 1, 0, 0), func(o *OrdinaryApplyV1) { o.RecordedFailure = nil })},
		{"restore nil cursor", change(modelOrdinary(4, 2, 2, 2, 1, 0, 0), func(o *OrdinaryApplyV1) { o.Cursor = nil })},
		{"restore foreign cursor", change(modelOrdinary(4, 2, 2, 2, 1, 0, 0), func(o *OrdinaryApplyV1) { o.Cursor = point(modelPoint(9, 9)) })},
		{"restore terminal cursor", change(modelOrdinary(4, 2, 2, 2, 1, 0, 0), func(o *OrdinaryApplyV1) { o.Cursor = point(o.OldSuffix[0]) })},
		{"failure kind zero", change(modelOrdinary(3, 1, 2, 1, 1, 0, 0), func(o *OrdinaryApplyV1) { o.RecordedFailure.Kind = 0 })},
		{"failure kind five", change(modelOrdinary(3, 1, 2, 1, 1, 0, 0), func(o *OrdinaryApplyV1) { o.RecordedFailure.Kind = 5 })},
		{"failure empty result", change(modelOrdinary(3, 1, 2, 1, 1, 0, 0), func(o *OrdinaryApplyV1) { o.RecordedFailure.ExactResult = nil })},
		{"failure empty evidence", change(modelOrdinary(3, 1, 2, 1, 1, 0, 0), func(o *OrdinaryApplyV1) { o.RecordedFailure.Evidence = []byte{} })},
		{"consensus hash outside N", change(modelOrdinary(3, 1, 2, 1, 1, 0, 0), func(o *OrdinaryApplyV1) { o.RecordedFailure.FailedBlockHash = hash(modelHash(99)) })},
		{"non-consensus hash", change(modelOrdinary(3, 1, 2, 1, 1, 0, 0), func(o *OrdinaryApplyV1) {
			o.RecordedFailure = modelFailure(2)
			o.RecordedFailure.FailedBlockHash = hash(o.NewSuffix[0].BlockHash)
		})},
		{"invalid carried cleanup", change(carried, func(o *OrdinaryApplyV1) { o.CarriedCleanup = &CleanupV1{} })},
		{"old height overflow", change(modelOrdinary(1, 1, 0, 1, 1, 0, 0), func(o *OrdinaryApplyV1) { o.OldSuffix[0].Height = 0x100000000 })},
		{"new height overflow", change(modelOrdinary(2, 0, 2, 0, 1, 0, 0), func(o *OrdinaryApplyV1) { o.NewSuffix[1].Height = 0x100000000 })},
	}
	for _, row := range bad {
		wantModel(t, row.name, row.a, false)
	}
	for _, row := range []authorityCase{
		{"H0 wrong U", modelOrdinary(2, 0, 2, 0, 1, 0, 1)},
		{"H1440 U below", modelOrdinary(1, 1, 0, 1440, 1, 0, 0)},
		{"H1440 U above", modelOrdinary(1, 1, 0, 1440, 1, 0, 2)},
		{"H15120 U below", modelOrdinary(1, 1, 0, 15120, 1, 0, 13680)},
		{"H15120 U above", modelOrdinary(1, 1, 0, 15120, 1, 2, 13682)},
		{"archive U mismatch", modelOrdinary(1, 1, 0, 15120, 2, 0, 13680)},
	} {
		wantModel(t, row.name, row.a, false)
	}
	wantModel(t, "old suffix height zero", edit(modelOrdinary(1, 1, 0, 1, 1, 0, 0), func(a *StorageAuthorityV1) {
		a.Ordinary.OldSuffix[0].Height, a.Ordinary.Target.Height = 0, ^uint64(0)
	}), false)
	newStartsAtZero := modelOrdinary(2, 1, 2, 1, 1, 0, 0)
	newStartsAtZero.Ordinary.NewSuffix[0].Height, newStartsAtZero.Ordinary.NewSuffix[1].Height = 0, 1
	newStartsAtZero.Ordinary.Target = newStartsAtZero.Ordinary.NewSuffix[1]
	newStartsAtZero.Ordinary.CapturedSelectedSide.F = 0
	newStartsAtZero.Ordinary.CapturedSelectedSide.TipHeight = 1
	newStartsAtZero.Ordinary.CapturedSelectedSide.TipHash = newStartsAtZero.Ordinary.Target.BlockHash
	newStartsAtZero.Ordinary.CapturedSelectedSide.RowCount = 1
	wantModel(t, "present new suffix starts at zero", newStartsAtZero, false)
}

func TestStorageAuthorityV1Boundaries(t *testing.T) {
	for _, row := range []authorityCase{
		{"archive zero", modelBase(2, 0, 0)},
		{"archive max U", modelBase(2, 0, 4_294_965_856)},
		{"pruned zero", modelBase(1, 0, 0)},
		{"pruned B0 max U", modelBase(1, 0, 13680)},
		{"pruned positive minimum", modelBase(1, 1, 13681)},
		{"pruned maximum", modelBase(1, 4_294_952_176, 4_294_965_856)},
	} {
		wantModel(t, row.name, row.a, true)
	}
	for _, row := range []authorityCase{
		{"archive max U plus one", modelBase(2, 0, 4_294_965_857)},
		{"archive B positive", modelBase(2, 1, 0)},
		{"pruned B max plus one", modelBase(1, 4_294_952_177, 4_294_965_857)},
		{"pruned U max plus one", modelBase(1, 4_294_952_176, 4_294_965_857)},
		{"pruned B0 U13681", modelBase(1, 0, 13681)},
		{"pruned positive U low", modelBase(1, 1, 13680)},
		{"pruned positive U high", modelBase(1, 1, 13682)},
	} {
		wantModel(t, row.name, row.a, false)
	}
	withWork := func(work [40]byte) StorageAuthorityV1 {
		a := modelBase(1, 0, 0)
		a.NextGenerationID, a.SelectedSide = 3, modelSide(2, 0, 1, 1, 1)
		a.SelectedSide.CumulativeChainwork = work
		return a
	}
	wantModel(t, "chainwork one", withWork(modelWork(false)), true)
	wantModel(t, "chainwork 2^288", withWork(modelWork(true)), true)
	badWork := [][40]byte{{}, {1}, {0, 1}, {0, 0, 1}, {3: 2, 39: 1}, {3: 1, 39: 1}}
	for i, work := range badWork {
		wantModel(t, fmt.Sprintf("invalid chainwork %d", i), withWork(work), false)
	}
	for _, row := range []struct {
		name   string
		height uint64
		error  []byte
		valid  bool
	}{
		{"invalid branch height zero", 0, []byte{1}, true},
		{"invalid branch height max", 0xffffffff, []byte{1}, true},
		{"invalid branch height overflow", 0x100000000, []byte{1}, false},
		{"invalid branch nil error", 0, nil, false},
		{"invalid branch empty error", 0, []byte{}, false},
	} {
		a := modelBase(1, 0, 0)
		a.ExcludedInvalidBranch = &InvalidBranchV1{row.height, modelHash(71), row.error}
		wantModel(t, row.name, a, row.valid)
	}
	wantModel(t, "recovery cleanup with detached", edit(modelPrune(true), func(a *StorageAuthorityV1) { a.DetachedSuffix = modelDetached(1, 1) }), true)
	for _, pending := range []StorageProfileV1{0, 3, 255} {
		a := modelPrune(true)
		*a.PendingTargetProfile = pending
		wantModel(t, fmt.Sprintf("invalid pending profile %d", pending), a, false)
	}
	wantModel(t, "otherwise valid selected in recovery", edit(modelPrune(true), func(a *StorageAuthorityV1) { a.NextGenerationID, a.SelectedSide = 3, modelSide(2, 0, 1, 1, 1) }), false)
	replayCleanup := modelReplay(1)
	replayCleanup.B, replayCleanup.U, replayCleanup.Cleanup = 1, 13681, modelCleanup()
	replayOrdinary := modelReplay(1)
	replayOrdinary.NextGenerationID, replayOrdinary.Ordinary = 4, modelOrdinary(2, 0, 2, 0, 1, 0, 0).Ordinary
	replayOrdinary.Ordinary.CapturedSelectedSide.GenerationID = 3
	replaySelected := modelReplay(1)
	replaySelected.NextGenerationID, replaySelected.SelectedSide = 4, modelSide(3, 0, 1, 1, 1)
	replayDetached := modelReplay(1)
	replayDetached.DetachedSuffix = modelDetached(1, 1)
	ordinaryCleanup := modelOrdinary(2, 0, 2, 0, 1, 0, 0)
	ordinaryCleanup.Cleanup = modelCleanup()
	ordinaryReplay := modelOrdinary(2, 0, 2, 0, 1, 0, 0)
	ordinaryReplay.NextGenerationID, ordinaryReplay.Replay = 4, modelReplay(1).Replay
	ordinaryReplay.Replay.TargetGenerationID = 3
	ordinarySelected := modelOrdinary(2, 0, 2, 0, 1, 0, 0)
	ordinarySelected.SelectedSide = modelSide(2, 0, 1, 1, 1)
	ordinaryDetached := modelOrdinary(2, 0, 2, 0, 1, 0, 0)
	ordinaryDetached.DetachedSuffix = modelDetached(1, 1)
	pruneStableReplay := edit(modelPrune(false), func(a *StorageAuthorityV1) { a.NextGenerationID, a.Replay = 3, modelReplay(1).Replay })
	pruneRecoveryReplay := edit(modelPrune(true), func(a *StorageAuthorityV1) { a.NextGenerationID, a.Replay = 3, modelReplay(1).Replay })
	ordinaryPayload := modelOrdinary(2, 0, 2, 0, 1, 0, 0).Ordinary
	pruneStableOrdinary := edit(modelPrune(false), func(a *StorageAuthorityV1) { a.NextGenerationID, a.Ordinary = 3, ordinaryPayload })
	pruneRecoveryOrdinary := edit(modelPrune(true), func(a *StorageAuthorityV1) { a.NextGenerationID, a.Ordinary = 3, ordinaryPayload })
	for _, row := range []authorityCase{
		{"replay extra cleanup", replayCleanup},
		{"replay extra ordinary", replayOrdinary},
		{"replay outer selected", replaySelected},
		{"replay outer detached", replayDetached},
		{"ordinary extra cleanup", ordinaryCleanup},
		{"ordinary extra replay", ordinaryReplay},
		{"ordinary outer selected", ordinarySelected},
		{"ordinary outer detached", ordinaryDetached},
		{"prune stable cleanup extra replay", pruneStableReplay},
		{"prune recovery cleanup extra replay", pruneRecoveryReplay},
		{"prune stable cleanup extra ordinary", pruneStableOrdinary},
		{"prune recovery cleanup extra ordinary", pruneRecoveryOrdinary},
	} {
		wantModel(t, row.name, row.a, false)
	}
}

func TestStorageAuthorityV1ErrorAndOwnership(t *testing.T) {
	deep := func() StorageAuthorityV1 {
		a := modelOrdinary(3, 1, 2, 15120, 1, 1, 13681)
		a.Ordinary.CarriedCleanup = modelCleanup()
		a.ExcludedInvalidBranch = &InvalidBranchV1{FirstInvalidHeight: 7, FirstInvalidBlockHash: modelHash(72), ExactConsensusError: []byte{1, 2, 3}}
		return a
	}
	for index, build := range []func() StorageAuthorityV1{
		func() StorageAuthorityV1 { return modelReplay(1) },                                                    // Replay
		func() StorageAuthorityV1 { return modelPrune(true) },                                                  // PRUNE_GC recovery
		func() StorageAuthorityV1 { a := modelPrune(false); a.DetachedSuffix = modelDetached(2, 1); return a }, // PRUNE_GC detached
		func() StorageAuthorityV1 {
			side := modelSide(2, 0, 1, 1, 1)
			return edit(modelBase(1, 0, 0), func(a *StorageAuthorityV1) { a.NextGenerationID, a.SelectedSide = 3, side })
		},
		deep,
	} {
		a, expected := build(), build()
		if err := ValidateStorageAuthorityV1(a); err != nil || !reflect.DeepEqual(a, expected) {
			t.Fatalf("legal image %d first validation rejected or mutated input: %v, %#v", index, err, a)
		}
		if err := ValidateStorageAuthorityV1(a); err != nil || !reflect.DeepEqual(a, expected) {
			t.Fatalf("legal image %d second validation rejected or mutated input: %v, %#v", index, err, a)
		}
	}
	invalid, expected := deep(), deep()
	invalid.ExcludedInvalidBranch.ExactConsensusError, expected.ExcludedInvalidBranch.ExactConsensusError = []byte{}, []byte{}
	if err := ValidateStorageAuthorityV1(invalid); !exactErr(err) || !reflect.DeepEqual(invalid, expected) {
		t.Fatalf("invalid nested image error or mutation = %v, %#v", err, invalid)
	}
	large := modelOrdinary(2, 0, 1440, 0, 1, 0, 0)
	for _, active := range []uint64{0, large.NextGenerationID, large.NextGenerationID + 1} {
		candidate := edit(large, func(a *StorageAuthorityV1) { a.ActiveGenerationID = active })
		var err error
		if allocations := testing.AllocsPerRun(100, func() { err = ValidateStorageAuthorityV1(candidate) }); !exactErr(err) || allocations != 0 {
			t.Fatalf("active generation %d error/allocations = %v/%v", active, err, allocations)
		}
	}
}
