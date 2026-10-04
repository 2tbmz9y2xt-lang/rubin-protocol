//go:build cgo && (darwin || linux) && (amd64 || arm64)

package consensus

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/mdbx"
)

type generationWorld struct {
	t     *testing.T
	s     *mdbx.Store
	owner *mdbx.OperationReservationOwner
	path  string
	cfg   mdbx.ConfigV1
	a     mdbx.StorageAuthorityV1
	rows  []mdbx.Mutation
}

func generationAuthority() mdbx.StorageAuthorityV1 {
	return mdbx.StorageAuthorityV1{Version: 1, ActiveProfile: 1, ActiveGenerationID: 1, NextGenerationID: 4, Phase: 2, Lifecycle: 1, Cleanup: &mdbx.CleanupV1{Spans: []mdbx.CleanupSpanV1{{Kind: 1, GenerationID: 2}}}}
}

func generationNew(t *testing.T, a mdbx.StorageAuthorityV1, rows ...mdbx.Mutation) *generationWorld {
	t.Helper()
	w := &generationWorld{t: t, path: filepath.Join(t.TempDir(), "db"), cfg: sideWorldConfig, a: a, rows: slices.Clone(rows)}
	var err error
	w.s, err = mdbx.Create(w.path, w.cfg)
	logicalMDBXAssert(t, err == nil, "generation create: %v", err)
	inspection, err := w.s.Inspect()
	logicalMDBXAssert(t, err == nil, "capture actual creation config: %v", err)
	w.cfg = inspection.Config
	t.Cleanup(func() { _ = w.s.Close() })
	w.owner, err = mdbx.NewOperationReservationOwner(154611151)
	logicalMDBXAssert(t, err == nil, "generation owner: %v", err)
	truth, stage, err := w.s.BootstrapStorageV1(1, w.owner)
	logicalMDBXAssert(t, truth == 2 && stage == 3 && err == nil, "generation bootstrap: %v/%v/%v", truth, stage, err)
	encoded, err := a.Encode()
	logicalMDBXAssert(t, err == nil, "generation authority scalar shape: %v", err)
	rows = append(slices.Clone(rows), mdbx.Mutation{DBI: logicalMDBXDBIs[0], Key: []byte{2}, BeforePresent: true, AfterKind: 2, Literal: encoded})
	logicalMDBXSeed(t, w.s, rows...)
	return w
}

func generationRow(rank uint8, key, value []byte) mdbx.Mutation {
	return mdbx.Mutation{DBI: logicalMDBXDBIs[rank], Key: key, AfterKind: 2, Literal: value}
}

func generationData(g uint64, marker byte) []mdbx.Mutation {
	var tx [32]byte
	tx[0] = marker
	key, _ := mdbx.UTXOKey(g, tx, 0)
	value, _ := (mdbx.UTXOValue{Value: uint64(marker)}).Encode()
	counter, _ := mdbx.MetaKey(0x10, g)
	return []mdbx.Mutation{generationRow(1, key, value), generationRow(0, counter, mdbx.LogicalCounterValue(9, 1))}
}

func generationProjection(g, h uint64, nonce uint64) ([32]byte, []mdbx.Mutation) {
	body := sideWorldBlock([32]byte{}, nonce)
	hash := sha3_256(body[:116])
	key, _ := mdbx.HeightKey(g, h)
	inverse, _ := mdbx.CanonicalOwnerKey(g, hash)
	return hash, []mdbx.Mutation{
		generationRow(2, key, mdbx.ChainValue(hash, [32]byte{}, sideWorldWork(1))),
		generationRow(7, inverse, mdbx.CanonicalOwnerValue(h)),
		generationRow(3, bytes.Clone(hash[:]), bytes.Clone(body[:116])),
		generationRow(4, bytes.Clone(hash[:]), body),
		generationRow(5, mdbx.UndoManifestKey(hash), mdbx.UndoManifestValue(h, [16]byte{}, 1, 0)),
	}
}

func generationCanonical(hash [32]byte, k uint64) []mdbx.Mutation {
	forward, _ := mdbx.HeightKey(1, k)
	inverse, _ := mdbx.CanonicalOwnerKey(1, hash)
	return []mdbx.Mutation{
		generationRow(2, forward, mdbx.ChainValue(hash, [32]byte{}, sideWorldWork(1))),
		generationRow(7, inverse, mdbx.CanonicalOwnerValue(k)),
	}
}

func (w *generationWorld) run(class uint8, bound uint32) selectedSideOutcome {
	w.t.Helper()
	out := CleanupGenerationMDBX(w.s, w.owner, mdbx.ObsoleteClassV1(class), bound)
	sideWantReleased(w.t, w.owner, "generation")
	return out
}

func generationClean(t *testing.T, out selectedSideOutcome, truth mdbx.CommitTruth) {
	t.Helper()
	stage, logical := mdbx.UpdateStage(3), "NEW"
	if truth == 1 {
		stage, logical = 1, "OLD"
	}
	sideWantOutcome(t, out, "", logical, truth, stage, "generation clean")
	logicalMDBXAssert(t, out.Err == nil, "generation clean error: %v", out.Err)
}

func (w *generationWorld) image(a mdbx.StorageAuthorityV1, rows ...mdbx.Mutation) {
	w.t.Helper()
	encoded, err := a.Encode()
	logicalMDBXAssert(w.t, err == nil, "expected authority: %v", err)
	rows = append(slices.Clone(rows), generationRow(0, []byte{2}, encoded))
	logicalMDBXAssert(w.t, w.s.View(func(r *mdbx.Reader) error {
		for _, row := range rows {
			value, found, err := r.Get(row.DBI, row.Key)
			if err != nil || found != (row.Literal != nil) || !bytes.Equal(value, row.Literal) {
				return errors.Join(fmt.Errorf("generation image rank%d/%x: found=%t", row.DBI.Rank, row.Key, found), err)
			}
		}
		return nil
	}) == nil, "generation image differs")
}

func generationGone(rows []mdbx.Mutation) []mdbx.Mutation {
	out := slices.Clone(rows)
	for i := range out {
		out[i].Literal = nil
	}
	return out
}

func generationTerminal(a mdbx.StorageAuthorityV1) mdbx.StorageAuthorityV1 {
	a.Phase, a.Cleanup = 1, nil
	return a
}

func TestCleanupGenerationMDBX(t *testing.T) {
	t.Run("P10-A1", func(t *testing.T) {
		a := generationAuthority()
		rows := append(generationData(2, 1), generationData(2, 2)[0])
		w := generationNew(t, a, rows...)
		generationClean(t, w.run(1, 1), 2)
		want := slices.Clone(rows)
		want[0].Literal = nil
		w.image(a, want...)
	})
	for _, name := range []string{"P10-A2", "P10-A3", "P10-A4a", "P10-A4b", "P10-A5a", "P10-A5b", "P10-A5c"} {
		t.Run(name, func(t *testing.T) {
			a := generationAuthority()
			var rows []mdbx.Mutation
			if name == "P10-A2" || name == "P10-A3" || name == "P10-A4a" || name == "P10-A4b" {
				rows = generationData(2, 1)
			}
			if name == "P10-A2" || name == "P10-A5a" {
				a.Cleanup.Spans = append(a.Cleanup.Spans, mdbx.CleanupSpanV1{Kind: 4, GenerationID: 3, FirstHeight: 5, LastHeight: 9, NextHeight: 7})
			}
			if name == "P10-A4a" || name == "P10-A4b" || name == "P10-A5c" {
				pending := mdbx.StorageProfileV1(1)
				if name == "P10-A4b" {
					pending = 2
				}
				a.Lifecycle, a.PendingTargetProfile, a.NextGenerationID = 2, &pending, ^uint64(0)
				a.ExcludedInvalidBranch = &mdbx.InvalidBranchV1{FirstInvalidHeight: 3, FirstInvalidBlockHash: [32]byte{9}, ExactConsensusError: []byte{7}}
			}
			w := generationNew(t, a, rows...)
			if len(rows) != 0 {
				generationClean(t, w.run(1, 1440), 2)
				w.image(a, generationGone(rows[:1])[0], rows[1])
			}
			generationClean(t, w.run(3, 1440), 2)
			want := generationTerminal(a)
			if name == "P10-A2" || name == "P10-A5a" {
				want = a
				want.Cleanup = &mdbx.CleanupV1{Spans: []mdbx.CleanupSpanV1{{Kind: 4, GenerationID: 3, FirstHeight: 5, LastHeight: 9, NextHeight: 7}}}
			}
			w.image(want, generationGone(rows)...)
		})
	}
	t.Run("P10-A6", func(t *testing.T) {
		t.Run("none", func(t *testing.T) { generationDisposition(t, "none") })
		for _, deferSide := range []bool{false, true} {
			t.Run(fmt.Sprintf("selected-defer%t", deferSide), func(t *testing.T) { generationSelectedKeep(t, deferSide) })
		}
	})
	t.Run("P10-A9", func(t *testing.T) {
		for _, kind := range []string{"middle", "middle-different-height", "above", "below"} {
			t.Run(kind, func(t *testing.T) { generationDisposition(t, kind) })
		}
	})
	t.Run("P10-A10", func(t *testing.T) {
		for _, kind := range []string{"BLOCKS", "BLOCKS-drained"} {
			t.Run(kind, func(t *testing.T) { generationDisposition(t, kind) })
		}
	})
	t.Run("P10-A11", func(t *testing.T) {
		a := generationAuthority()
		_, obsolete := generationProjection(2, 5, 55)
		_, active := generationProjection(1, 5, 66)
		active = append(active, generationData(1, 3)...)
		active[len(active)-1].BeforePresent = true // Bootstrap already created the active counter.
		obsolete = append(obsolete, generationData(2, 4)...)
		w := generationNew(t, a, append(slices.Clone(obsolete), active...)...)
		for _, class := range []uint8{4, 1, 3} {
			generationClean(t, w.run(class, 1440), 2)
		}
		w.image(generationTerminal(a), append(generationGone(obsolete), active...)...)
	})
	t.Run("P10-A7", func(t *testing.T) {
		a := generationAuthority()
		hash, rows := generationProjection(2, 5, 55)
		var staged []mdbx.Mutation
		for _, g := range []uint64{2, 3} {
			key, _ := mdbx.HeightKey(g, 5)
			staged = append(staged, generationRow(6, key, mdbx.ChainValue(hash, [32]byte{}, sideWorldWork(1))))
		}
		w := generationNew(t, a, append(slices.Clone(rows), staged...)...)
		generationClean(t, w.run(2, 1440), 2)
		w.image(generationTerminal(a), append(generationGone(rows), staged...)...)
	})
	t.Run("H11", func(t *testing.T) {
		a := generationAuthority()
		_, rows := generationProjection(2, 5, 55)
		_, other := generationProjection(3, 5, 66)
		other = other[2:4]
		w := generationNew(t, a, append(slices.Clone(rows), other...)...)
		generationClean(t, w.run(2, 1440), 2)
		w.image(generationTerminal(a), append(generationGone(rows), other...)...)
	})
	t.Run("H6", func(t *testing.T) {
		a := generationAuthority()
		rows := append(generationData(2, 1)[:1], generationData(2, 2)[0])
		for i := range rows {
			rows[i].Literal, _ = (mdbx.UTXOValue{CovenantData: make([]byte, 65536)}).Encode()
		}
		w := generationNew(t, a, rows...)
		generationClean(t, w.run(1, 1440), 2)
		w.image(a, generationGone(rows[:1])[0], rows[1])
		generationClean(t, w.run(1, 1440), 2)
		w.image(generationTerminal(a), generationGone(rows)...)
	})
	t.Run("P10-A8", generationConfluence)
	t.Run("H7", func(t *testing.T) {
		t.Run("excess", func(t *testing.T) {
			w, hash, family := generationFamily(t, "delete")
			var tx [32]byte
			binary.BigEndian.PutUint32(tx[28:], 414634)
			extra := generationRow(5, mdbx.UndoEntryKey(hash, tx, 405, 938, 0), family[1].Literal)
			generationSeedUndo(t, w, []mdbx.Mutation{extra})
			out := w.run(2, 1)
			sideWantOutcome(t, out, "LOCAL_RESOURCE_UNAVAILABLE(storage_capacity)", "OLD", 1, 1, "bounded raw over-count")
			logicalMDBXAssert(t, out.Err != nil && out.Err.Error() == "LOCAL_RESOURCE_UNAVAILABLE(storage_capacity): cleanup undo family exceeds native row bound", "raw family capacity refusal: %v", out.Err)
			w.image(w.a, append(slices.Clone(w.rows), extra)...)
			generationFamilyImage(t, w.s, hash, family, extra)
		})
		for _, kind := range []string{"delete", "keep", "defer"} {
			t.Run(kind, func(t *testing.T) {
				w, hash, family := generationFamily(t, kind)
				generationClean(t, w.run(2, 1), 2)
				want := generationTerminal(w.a)
				if kind == "defer" {
					want = w.a
					want.Cleanup = &mdbx.CleanupV1{Spans: slices.Clone(w.a.Cleanup.Spans[1:])}
				}
				rows := slices.Clone(w.rows)
				rows[0].Literal, rows[1].Literal = nil, nil
				if kind == "delete" {
					rows[2].Literal, rows[3].Literal, rows[4].Literal = nil, nil, nil
				}
				w.image(want, rows...)
				if kind == "delete" {
					family = nil
				}
				generationFamilyImage(t, w.s, hash, family)
			})
		}
	})
	t.Run("X1", generationRoutes)
	t.Run("API", generationAPI)
	t.Run("R6b", func(t *testing.T) {
		a := generationAuthority()
		rows := generationData(2, 1)
		w := generationNew(t, a, rows...)
		logicalMDBXAssert(t, w.owner.WithReservation(1, func() error {
			out := CleanupGenerationMDBX(w.s, w.owner, 1, 1)
			sideWantOutcome(t, out, "", "", 1, 1, "capacity API")
			logicalMDBXAssert(t, out.Err != nil && out.Err.Error() == "storage operation reservation capacity unavailable", "capacity refusal: %v", out.Err)
			w.image(a, rows...)
			return nil
		}) == nil, "outer grant")
		generationClean(t, w.run(1, 1), 2)
	})
	t.Run("remaining-width", func(t *testing.T) {
		a := generationAuthority()
		a.Cleanup.Spans = append(a.Cleanup.Spans, mdbx.CleanupSpanV1{Kind: 4, GenerationID: 3, FirstHeight: 1, LastHeight: 1441, NextHeight: 2})
		w := generationNew(t, a)
		generationClean(t, w.run(1, 1440), 2)
		want := a
		want.Cleanup = &mdbx.CleanupV1{Spans: slices.Clone(a.Cleanup.Spans[1:])}
		w.image(want)
	})
	t.Run("remaining-width-defer", func(t *testing.T) {
		a := generationAuthority()
		a.Cleanup.Spans = append(a.Cleanup.Spans, mdbx.CleanupSpanV1{Kind: 4, GenerationID: 3, FirstHeight: 1, LastHeight: 1441, NextHeight: 2})
		hash, rows := generationProjection(2, 5, 55)
		for h := uint64(2); h <= 1441; h++ {
			other := [32]byte{}
			binary.BigEndian.PutUint64(other[24:], h)
			if h == 1441 {
				other = hash
			}
			key, _ := mdbx.HeightKey(3, h)
			rows = append(rows, generationRow(6, key, mdbx.ChainValue(other, [32]byte{}, sideWorldWork(1))))
		}
		w := generationNew(t, a, rows...)
		generationClean(t, w.run(2, 1), 2)
		want := slices.Clone(rows)
		want[0].Literal, want[1].Literal, want[2].Literal, want[4].Literal = nil, nil, nil, nil
		expected := a
		expected.Cleanup = &mdbx.CleanupV1{Spans: slices.Clone(a.Cleanup.Spans[1:])}
		w.image(expected, want...)
	})
}

// One bounded window checks the complete ordered physical family, including
// every literal byte; tail supplies an excess row without copying the family.
func generationFamilyImage(t *testing.T, store *mdbx.Store, hash [32]byte, family []mdbx.Mutation, tail ...mdbx.Mutation) {
	t.Helper()
	count, expected := 0, len(family)+len(tail)
	window := make([]byte, 65536)
	err := store.View(func(r *mdbx.Reader) error {
		return r.VisitLargeImageV1(mdbx.LargeImageSelectorV1{Kind: 2, Hash: hash}, func(row mdbx.LargeImageRowV1) error {
			if count >= expected {
				return errors.New("full family has excess physical row")
			}
			var want mdbx.Mutation
			if count < len(family) {
				want = family[count]
			} else {
				want = tail[count-len(family)]
			}
			if !row.Present() || !bytes.Equal(row.Key(), want.Key) || row.Length() != uint64(len(want.Literal)) {
				return errors.New("full family presence/key/order/length differs")
			}
			for offset := 0; offset < len(want.Literal); offset += len(window) {
				n := min(len(window), len(want.Literal)-offset)
				read, err := row.ReadAt(window[:n], uint64(offset))
				if err != nil || read != n || !bytes.Equal(window[:n], want.Literal[offset:offset+n]) {
					return errors.New("full family literal bytes differ")
				}
			}
			count++
			return nil
		})
	})
	logicalMDBXAssert(t, err == nil && count == expected, "full family %d/%d: %v", count, expected, err)
}

// The full family has 414634 distinct coordinates and spent outpoints plus its
// manifest. Setup is split only into admitted writes; cleanup is one transaction.
func generationFamily(t *testing.T, kind string) (*generationWorld, [32]byte, []mdbx.Mutation) {
	a := generationAuthority()
	hash, rows := generationProjection(2, 5, 55)
	k := uint64(13691)
	if kind == "defer" {
		k = 11
	}
	if kind != "delete" {
		a.B, a.U = 10, 13690
		rows = append(rows, generationCanonical(hash, k)...)
	}
	if kind == "defer" {
		a.Cleanup.Spans = append(a.Cleanup.Spans, mdbx.CleanupSpanV1{Kind: 3, GenerationID: 1, LastHeight: 13689, NextHeight: 11})
	}
	rows[4].Literal = mdbx.UndoManifestValue(k, [16]byte{}, 406, 414634)
	w := generationNew(t, a, rows...)
	family := make([]mdbx.Mutation, 1, 414635)
	family[0] = rows[4]
	value, _ := (mdbx.UTXOValue{Value: 1}).Encode()
	for i := uint32(0); i < 414634; i++ {
		var tx [32]byte
		binary.BigEndian.PutUint32(tx[28:], i)
		family = append(family, generationRow(5, mdbx.UndoEntryKey(hash, tx, 1+i/1024, i%1024, 0), value))
	}
	for start := 1; start < len(family); start += 4096 {
		generationSeedUndo(t, w, family[start:min(start+4096, len(family))])
	}
	return w, hash, family
}

// Entry literals remain the independent expected image; only the write plan
// references temporary generation-4 sources, deleted in the same admitted batch.
func generationSeedUndo(t *testing.T, w *generationWorld, entries []mdbx.Mutation) {
	t.Helper()
	sources := make([]mdbx.Mutation, 0, len(entries))
	writes := make([]mdbx.Mutation, 0, 2*len(entries))
	for _, entry := range entries {
		key, err := mdbx.UTXOKey(4, [32]byte(entry.Key[41:73]), binary.BigEndian.Uint32(entry.Key[73:]))
		logicalMDBXAssert(t, err == nil, "temporary undo source key: %v", err)
		sources = append(sources, generationRow(1, key, entry.Literal))
		writes = append(writes,
			mdbx.Mutation{DBI: logicalMDBXDBIs[1], Key: key, BeforePresent: true, AfterKind: mdbx.AfterAbsent},
			mdbx.Mutation{DBI: logicalMDBXDBIs[5], Key: entry.Key, AfterKind: mdbx.AfterOldValueRef, RefDBI: logicalMDBXDBIs[1], RefKey: key})
	}
	logicalMDBXSeed(t, w.s, sources...)
	logicalMDBXSeed(t, w.s, writes...)
	w.image(w.a, generationGone(sources)...)
}

func generationSelected(a *mdbx.StorageAuthorityV1, hash [32]byte, body []byte) []mdbx.Mutation {
	a.SelectedSide = &mdbx.SelectedSideV1{GenerationID: 3, F: 5, TipHeight: 6, TipHash: hash, CumulativeChainwork: sideWorldWork(1), RowCount: 1, LogicalBytes: uint64(len(body))}
	key, _ := mdbx.HeightKey(3, 6)
	return []mdbx.Mutation{generationRow(6, key, mdbx.ChainValue(hash, [32]byte{}, sideWorldWork(1)))}
}

func generationRollingSelected(a *mdbx.StorageAuthorityV1, rows []mdbx.Mutation) []mdbx.Mutation {
	// The tip hash is the independently pinned big-endian height marker 1440.
	a.SelectedSide = &mdbx.SelectedSideV1{GenerationID: 3, F: 0, TipHeight: 1440, TipHash: [32]byte{30: 5, 31: 160}, CumulativeChainwork: sideWorldWork(1440), RowCount: 1439, LogicalBytes: 1439 * uint64(len(rows[3].Literal))}
	a.Cleanup.Spans = append(a.Cleanup.Spans, mdbx.CleanupSpanV1{Kind: 4, GenerationID: 3, FirstHeight: 1, LastHeight: 1, NextHeight: 1})
	for h := uint64(2); h <= 1440; h++ {
		if h == 6 {
			continue // The selected x link at j=6 was already seeded.
		}
		other := [32]byte{}
		binary.BigEndian.PutUint64(other[24:], h)
		key, _ := mdbx.HeightKey(3, h)
		rows = append(rows, generationRow(6, key, mdbx.ChainValue(other, [32]byte{}, sideWorldWork(h))))
	}
	return rows
}

// Eligible selected membership keeps by hash at j=6, independently of h=5.
func generationSelectedKeep(t *testing.T, deferSide bool) {
	a := generationAuthority()
	hash, rows := generationProjection(2, 5, 55)
	rows = append(rows, generationSelected(&a, hash, rows[3].Literal)...)
	if deferSide {
		rows = generationRollingSelected(&a, rows)
		key, _ := mdbx.HeightKey(3, 1)
		rows = append(rows, generationRow(6, key, mdbx.ChainValue(hash, [32]byte{}, sideWorldWork(1))))
	}
	w := generationNew(t, a, rows...)
	generationClean(t, w.run(2, 1), 2)
	expected, want := generationTerminal(a), slices.Clone(rows)
	if deferSide {
		expected = a
		expected.Cleanup = &mdbx.CleanupV1{Spans: slices.Clone(a.Cleanup.Spans[1:])}
	}
	want[0].Literal, want[1].Literal, want[4].Literal = nil, nil, nil
	w.image(expected, want...)
}

func generationDisposition(t *testing.T, kind string) {
	a := generationAuthority()
	h := uint64(5)
	if kind == "middle" {
		h = 11
	}
	hash, rows := generationProjection(2, h, 55)
	want := generationGone(rows)
	k := uint64(11)
	if kind == "below" || kind == "BLOCKS" || kind == "BLOCKS-drained" {
		k = 8
	}
	if kind == "above" {
		k = 13691
	}
	if kind != "none" {
		a.B, a.U = 10, 13690
		active := generationCanonical(hash, k)
		rows = append(rows, active...)
		want = append(want, active...)
		want[2].Literal = rows[2].Literal
		if k >= 10 {
			want[3].Literal = rows[3].Literal
		}
		if kind == "above" {
			rows[4].Literal = mdbx.UndoManifestValue(k, [16]byte{}, 1, 0)
			want[4].Literal = rows[4].Literal
		}
	}
	if kind == "BLOCKS" || kind == "BLOCKS-drained" {
		next := uint64(8)
		if kind == "BLOCKS-drained" {
			next = 9
		} else {
			want[3].Literal = rows[3].Literal
		}
		a.Cleanup.Spans = append(a.Cleanup.Spans, mdbx.CleanupSpanV1{Kind: 2, GenerationID: 1, FirstHeight: 0, LastHeight: 9, NextHeight: next})
	}
	w := generationNew(t, a, rows...)
	generationClean(t, w.run(2, 1440), 2)
	expected := generationTerminal(a)
	if len(a.Cleanup.Spans) > 1 {
		expected = a
		expected.Cleanup = &mdbx.CleanupV1{Spans: slices.Clone(a.Cleanup.Spans[1:])}
	}
	w.image(expected, want...)
}

func generationConfluence(t *testing.T) {
	for _, bound := range []uint32{1, 1440} {
		for class := uint8(1); class <= 4; class++ {
			t.Run(fmt.Sprintf("class%d-bound%d", class, bound), func(t *testing.T) {
				a := generationAuthority()
				_, rows := generationProjection(2, 4, 44)
				_, later := generationProjection(2, 5, 55)
				rows = append(rows, later...)
				rows = append(rows, generationData(2, 1)...)
				w := generationNew(t, a, rows...)
				for page := 0; page < 8; page++ {
					out := w.run(class, bound)
					if out.Truth == 1 {
						generationClean(t, out, 1)
						break
					}
					generationClean(t, out, 2)
				}
				w.image(generationTerminal(a), generationGone(rows)...)
				logicalMDBXAssert(t, w.s.Close() == nil, "real close")
				var err error
				w.s, err = mdbx.Open(w.path, w.cfg)
				logicalMDBXAssert(t, err == nil, "same-path Open: %v", err)
				w.image(generationTerminal(a), generationGone(rows)...)
			})
		}
	}
	for _, checkpoint := range []int{1, 2} {
		t.Run(fmt.Sprintf("same-path-after-page%d", checkpoint), func(t *testing.T) {
			a := generationAuthority()
			var rows []mdbx.Mutation
			for h := uint64(4); h <= 6; h++ {
				_, projection := generationProjection(2, h, h*11)
				rows = append(rows, projection...)
			}
			w := generationNew(t, a, rows...)
			want := slices.Clone(rows)
			for page := 0; page < checkpoint; page++ {
				generationClean(t, w.run(2, 1), 2)
				for i := page * 5; i < (page+1)*5; i++ {
					want[i].Literal = nil
				}
				w.image(a, want...)
			}
			logicalMDBXAssert(t, w.s.Close() == nil, "checkpoint real close")
			var err error
			w.s, err = mdbx.Open(w.path, w.cfg)
			logicalMDBXAssert(t, err == nil, "checkpoint same-path Open: %v", err)
			w.image(a, want...)
			out := w.run(2, 1)
			sideWantOutcome(t, out, "", "OLD", 1, 1, "checkpoint unverified refusal")
			var engine *mdbx.EngineError
			logicalMDBXAssert(t, errors.As(out.Err, &engine) && engine.Class == "InvalidInput" && engine.Operation == "get" && engine.Code == 22 && engine.Diagnostic == "canonical owner index is not verified", "checkpoint exact refusal: %v", out.Err)
			w.image(a, want...)
		})
	}
	a := generationAuthority()
	_, rows := generationProjection(2, 5, 55)
	w := generationNew(t, a, rows...)
	logicalMDBXAssert(t, w.s.Close() == nil, "close before unfinished reopen")
	var err error
	w.s, err = mdbx.Open(w.path, w.cfg)
	logicalMDBXAssert(t, err == nil, "unfinished Open: %v", err)
	out := w.run(2, 1)
	sideWantOutcome(t, out, "", "OLD", 1, 1, "R18d")
	var engine *mdbx.EngineError
	logicalMDBXAssert(t, errors.As(out.Err, &engine) && engine.Class == "InvalidInput" && engine.Operation == "get" && engine.Code == 22 && engine.Diagnostic == "canonical owner index is not verified", "R18d exact error: %v", out.Err)
	w.image(a, rows...)
}

type generationRoute struct {
	name string
	a    mdbx.StorageAuthorityV1
}

func generationRouteAuthorities() []generationRoute {
	var out []generationRoute
	for _, name := range []string{"NONE-STABLE", "NONE-RECOVERY-PRUNED", "NONE-RECOVERY-ARCHIVE", "BLOCKS", "UNDO", "SIDE", "descriptor", "REPLAY", "R17b"} {
		a := generationAuthority()
		switch name {
		case "NONE-STABLE", "NONE-RECOVERY-PRUNED", "NONE-RECOVERY-ARCHIVE":
			a.Phase, a.Cleanup = 1, nil
			if name != "NONE-STABLE" {
				pending := mdbx.StorageProfileV1(1)
				if name == "NONE-RECOVERY-ARCHIVE" {
					pending = 2
				}
				a.Lifecycle, a.PendingTargetProfile = 2, &pending
			}
		case "BLOCKS":
			a.B, a.U, a.Cleanup.Spans[0] = 10, 13690, mdbx.CleanupSpanV1{Kind: 2, GenerationID: 1, LastHeight: 9}
		case "UNDO":
			a.U, a.Cleanup.Spans[0] = 10, mdbx.CleanupSpanV1{Kind: 3, GenerationID: 1, LastHeight: 9}
		case "SIDE":
			a.Cleanup.Spans[0] = mdbx.CleanupSpanV1{Kind: 4, GenerationID: 3, FirstHeight: 5, LastHeight: 5, NextHeight: 5}
		case "descriptor":
			a.DetachedSuffix = &mdbx.DetachedSuffixV1{Entries: []mdbx.DetachedSuffixEntryV1{{Height: 5, Hash: [32]byte{9}, BlockBytesLen: 116}}, Cursor: mdbx.AuthorityPointV1{Height: 5, BlockHash: [32]byte{9}}, EntryCount: 1, LogicalBytes: 116}
		case "REPLAY":
			a.Phase, a.Lifecycle, a.Cleanup = 3, 2, nil
			a.Replay = &mdbx.ReplayV1{TargetProfile: 2, TargetGenerationID: 3, Target: mdbx.RecoveryTargetV1{TipHeight: 2, CumulativeChainwork: sideWorldWork(1)}, Cursor: mdbx.ReplayCursorV1{Kind: 1}}
		case "R17b":
			a.Phase, a.Lifecycle, a.Cleanup = 4, 2, nil
			points := []mdbx.AuthorityPointV1{{Height: 1, BlockHash: [32]byte{1}}, {Height: 2, BlockHash: [32]byte{2}}}
			a.Ordinary = &mdbx.OrdinaryApplyV1{Stage: 2, Target: points[1], NewSuffix: points, CapturedSelectedSide: &mdbx.SelectedSideV1{GenerationID: 3, TipHeight: 2, TipHash: [32]byte{2}, RowCount: 2, LogicalBytes: 232, CumulativeChainwork: sideWorldWork(1)}, CarriedCleanup: &mdbx.CleanupV1{Spans: []mdbx.CleanupSpanV1{{Kind: 1, GenerationID: 2}}}}
		}
		out = append(out, generationRoute{name, a})
	}
	return out
}

func generationRoutes(t *testing.T) {
	for _, row := range generationRouteAuthorities() {
		t.Run(row.name, func(t *testing.T) {
			rows := generationData(2, 1)
			w := generationNew(t, row.a, rows...)
			generationClean(t, w.run(1, 1), 1)
			w.image(row.a, rows...)
		})
	}
}

func generationAPI(t *testing.T) {
	a := generationAuthority()
	rows := generationData(2, 1)
	w := generationNew(t, a, rows...)
	for class := uint16(0); class <= 255; class++ {
		if class >= 1 && class <= 4 {
			continue
		}
		out := CleanupGenerationMDBX(w.s, nil, mdbx.ObsoleteClassV1(class), 1)
		sideWantOutcome(t, out, "", "", 1, 1, "invalid class before nil owner")
		logicalMDBXAssert(t, out.Err != nil && out.Err.Error() == "invalid cleanup generation page request", "invalid class exact error: %v", out.Err)
		w.image(a, rows...)
		sideWantReleased(t, w.owner, "invalid class")
	}
	for _, bound := range []uint32{0, 1441, ^uint32(0)} {
		out := CleanupGenerationMDBX(w.s, nil, 1, bound)
		sideWantOutcome(t, out, "", "", 1, 1, "invalid bound")
		logicalMDBXAssert(t, out.Err != nil && out.Err.Error() == "invalid cleanup generation page request", "invalid bound exact error: %v", out.Err)
		w.image(a, rows...)
		sideWantReleased(t, w.owner, "invalid bound")
	}
	for _, owner := range []*mdbx.OperationReservationOwner{nil, {}} {
		out := CleanupGenerationMDBX(w.s, owner, 1, 1)
		sideWantOutcome(t, out, "", "", 1, 1, "invalid owner")
		logicalMDBXAssert(t, out.Err != nil && out.Err.Error() == "invalid storage operation reservation input", "owner error: %v", out.Err)
		w.image(a, rows...)
		sideWantReleased(t, w.owner, "invalid owner")
	}
	out := CleanupGenerationMDBX(nil, nil, 0, 0)
	sideWantOutcome(t, out, "", "", 1, 1, "nil Store first")
	var engine *mdbx.EngineError
	logicalMDBXAssert(t, errors.As(out.Err, &engine) && engine.Class == "InvalidInput" && engine.Operation == "update" && engine.Code == 22 && engine.Diagnostic == "nil Store", "nil Store exact error: %v", out.Err)
	w.image(a, rows...)
}
