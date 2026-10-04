//go:build rubin_mdbx_fixture && cgo && (darwin || linux) && (amd64 || arm64)

package consensus

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/mdbx"
)

func generationRaw(t *testing.T, w *generationWorld, authority []byte, rows []mdbx.Mutation, family ...[]mdbx.Mutation) {
	t.Helper()
	_ = w.s.Close()
	reopened, err := mdbx.Open(w.path, w.cfg)
	logicalMDBXAssert(t, err == nil, "same creation path/config Open: %v", err)
	defer func() { _ = reopened.Close() }()
	rows = append(slices.Clone(rows), generationRow(0, []byte{2}, authority))
	for _, row := range rows {
		equal, err := mdbx.FixtureRawRowEqual(reopened, row.DBI.Rank, row.Key, row.Literal)
		logicalMDBXAssert(t, err == nil && equal, "raw image rank%d/%x: %v", row.DBI.Rank, row.Key, err)
	}
	if len(family) != 0 {
		generationFamilyImage(t, reopened, [32]byte(family[0][0].Key[:32]), family[0])
	}
}

func generationEncoded(t *testing.T, a mdbx.StorageAuthorityV1) []byte {
	t.Helper()
	value, err := a.Encode()
	logicalMDBXAssert(t, err == nil, "checked authority encode: %v", err)
	_, err = mdbx.DecodeStorageAuthorityV1(value)
	logicalMDBXAssert(t, err == nil, "checked authority decode: %v", err)
	return value
}

func generationEngine(t *testing.T, err error, class, op string, code int, diagnostic string) {
	t.Helper()
	var e *mdbx.EngineError
	logicalMDBXAssert(t, errors.As(err, &e) && string(e.Class) == class && e.Operation == op && e.Code == code, "engine tuple %s/%s/%d: %v", class, op, code, err)
	if diagnostic != "" {
		logicalMDBXAssert(t, e.Diagnostic == diagnostic, "engine diagnostic: %v", err)
	}
}

func generationSelected(a *mdbx.StorageAuthorityV1, hash [32]byte, body []byte) []mdbx.Mutation {
	a.SelectedSide = &mdbx.SelectedSideV1{GenerationID: 3, F: 5, TipHeight: 6, TipHash: hash, CumulativeChainwork: sideWorldWork(1), RowCount: 1, LogicalBytes: uint64(len(body))}
	key, _ := mdbx.HeightKey(3, 6)
	return []mdbx.Mutation{generationRow(6, key, mdbx.ChainValue(hash, [32]byte{}, sideWorldWork(1)))}
}

func TestCleanupGenerationMDBXNative(t *testing.T) {
	t.Run("R1b", generationAuthorityRejections)
	t.Run("R18b", generationOptionalIdentity)
	t.Run("P10-A12", func(t *testing.T) {
		generationMalformedRows(t)
		t.Run("identity", generationMalformedIdentity)
	})
	t.Run("P10-A11-pair-gap", generationPairGap)
	t.Run("H12", func(t *testing.T) { generationDamage(t, 3) })
	t.Run("P10-A13", func(t *testing.T) {
		for _, rank := range []uint8{4, 5} {
			t.Run(fmt.Sprint(rank), func(t *testing.T) { generationDamage(t, rank) })
		}
		t.Run("canonical-family", generationUndoSemantics)
		t.Run("rank-key-collision", generationRankCollision)
	})
	t.Run("X2", generationNativeFaults)
	t.Run("X3", generationNativeReservations)
	t.Run("selected-crossed", generationSelectedCrossed)
	t.Run("H10", func(t *testing.T) {
		w := generationNew(t, generationAuthority(), generationData(2, 1)...)
		var recorded, result error
		var truth mdbx.CommitTruth
		var stage mdbx.UpdateStage
		_, err := mdbx.FixtureSelectedDamage(w.s, w.owner, mdbx.SelectedDamageGetEIO, 0, []byte{2}, func() {
			_ = w.owner.WithReservation(154611151, func() error {
				truth, stage, result = w.s.Update(func(r *mdbx.Reader) (mdbx.Batch, error) {
					_, _, recorded = r.Get(logicalMDBXDBIs[0], []byte{2})
					return mdbx.Batch{Mutations: []mdbx.Mutation{{DBI: logicalMDBXDBIs[0], Key: []byte{2}, BeforePresent: true, AfterKind: 1}}}, nil
				})
				return nil
			})
		})
		logicalMDBXAssert(t, truth == 1 && stage == 1 && any(result) == any(recorded) && err == nil, "inherited ignored Reader tuple: %s/%d/%v", truth, stage, result)
		cached := CleanupGenerationMDBX(w.s, w.owner, 1, 1)
		sideWantOutcome(t, cached, "", "", 1, 1, "P10 first Reader cached tuple")
		logicalMDBXAssert(t, any(cached.Err) == any(recorded), "P10 first error changed")
		sideWantReleased(t, w.owner, "H10")
		generationRaw(t, w, generationEncoded(t, w.a), w.rows)
	})
}

func generationAuthorityRejections(t *testing.T) {
	for _, name := range []string{"version", "phase", "lifecycle", "pending", "H3-active", "H3-selected", "BLOCKS", "UNDO", "carried-BLOCKS", "carried-UNDO", "wide1441"} {
		t.Run(name, func(t *testing.T) {
			a := generationAuthority()
			_, rows := generationProjection(2, 5, 55)
			if name == "pending" {
				pending := mdbx.StorageProfileV1(1)
				a.Lifecycle, a.PendingTargetProfile = 2, &pending
			}
			if name == "H3-selected" {
				generationSelected(&a, [32]byte{7}, make([]byte, 116))
			}
			if name == "wide1441" {
				a.Cleanup.Spans = append(a.Cleanup.Spans, mdbx.CleanupSpanV1{Kind: 4, GenerationID: 3, FirstHeight: 1, LastHeight: 1441, NextHeight: 1})
			}
			if name == "BLOCKS" || name == "UNDO" {
				a.B, a.U = 10, 13690
				span := mdbx.CleanupSpanV1{Kind: 2, GenerationID: 1, LastHeight: 8}
				if name == "UNDO" {
					span.Kind, span.LastHeight = 3, 13688
				}
				a.Cleanup.Spans = append(a.Cleanup.Spans, span)
			}
			if name == "carried-BLOCKS" || name == "carried-UNDO" {
				a = generationRouteAuthorities()[8].a
				// Preserve the old-tip promise U=10 with old H=1449 and a
				// two-row captured target at 1449..1450 (F=1448).
				a.Ordinary.OldSuffix = []mdbx.AuthorityPointV1{{Height: 1449, BlockHash: [32]byte{9}}}
				a.Ordinary.NewSuffix[0].Height, a.Ordinary.NewSuffix[1].Height = 1449, 1450
				a.Ordinary.Target = a.Ordinary.NewSuffix[1]
				a.Ordinary.Cursor = &a.Ordinary.NewSuffix[0]
				a.Ordinary.CapturedSelectedSide.F, a.Ordinary.CapturedSelectedSide.TipHeight = 1448, 1450
				a.U = 10
				span := mdbx.CleanupSpanV1{Kind: 3, GenerationID: 1, LastHeight: 8}
				if name == "carried-BLOCKS" {
					// B>0 forces U=B+13680; use the matching old tip.
					a.B, a.U = 10, 13690
					a.Ordinary.OldSuffix[0].Height = 15129
					a.Ordinary.NewSuffix[0].Height, a.Ordinary.NewSuffix[1].Height = 15129, 15130
					a.Ordinary.Target, a.Ordinary.Cursor = a.Ordinary.NewSuffix[1], &a.Ordinary.NewSuffix[0]
					a.Ordinary.CapturedSelectedSide.F, a.Ordinary.CapturedSelectedSide.TipHeight = 15128, 15130
					span.Kind = 2
				}
				a.Ordinary.CarriedCleanup.Spans = append(a.Ordinary.CarriedCleanup.Spans, span)
			}
			w := generationNew(t, a, rows...)
			bad := generationEncoded(t, a)
			switch name {
			case "version":
				bad[0] = 2
			case "phase":
				bad[34] = 5
			case "lifecycle":
				bad[35] = 3
			case "pending":
				bad[47] = 3
			case "H3-active":
				binary.BigEndian.PutUint64(bad[38:46], 1)
			case "H3-selected":
				binary.BigEndian.PutUint64(bad[38:46], 3)
			}
			_, decodeErr := mdbx.DecodeStorageAuthorityV1(bad)
			shapeBad := name == "version" || name == "phase" || name == "lifecycle" || name == "pending" || name == "H3-active" || name == "H3-selected"
			logicalMDBXAssert(t, (decodeErr != nil) == shapeBad, "fixture did not encode its target shape: %s/%v", name, decodeErr)
			logicalMDBXAssert(t, mdbx.FixtureSeedRawRow(w.s, 0, []byte{2}, bad) == nil, "seed authority")
			var out selectedSideOutcome
			evidence, err := mdbx.FixtureSelectedDamage(w.s, w.owner, mdbx.SelectedDamageProbeOnly, 0, nil, func() { out = CleanupGenerationMDBX(w.s, w.owner, 2, 1440) })
			sideWantOutcome(t, out, "TERMINAL_STORE_INTEGRITY(canonical)", "OLD", 1, 1, name)
			if name == "wide1441" {
				_, native := out.Err.(*mdbx.EngineError)
				logicalMDBXAssert(t, !native && out.Err != nil && out.Err.Error() == "TERMINAL_STORE_INTEGRITY(canonical): invalid cleanup retained aggregate", "wide semantic callback error: %v", out.Err)
			} else {
				generationEngine(t, out.Err, "Integrity", "get", -30793, "invalid storage authority")
			}
			logicalMDBXAssert(t, err == nil && evidence.BeginWrite == 0 && evidence.OldGets == ([8]uint64{1}), "authority-before-data: %+v/%v", evidence, err)
			sideWantReleased(t, w.owner, name)
			generationRaw(t, w, bad, rows)
		})
	}
	// Replay+Cleanup is forbidden before encoding; the wire format has one
	// phase payload, so no persisted hybrid can isolate a replay-target guard.
	t.Run("H3-replay-target", func(t *testing.T) {
		a := generationRouteAuthorities()[7].a
		a.Cleanup = &mdbx.CleanupV1{Spans: []mdbx.CleanupSpanV1{{Kind: 1, GenerationID: a.Replay.TargetGenerationID}}}
		_, err := a.Encode()
		logicalMDBXAssert(t, err != nil, "forbidden simultaneous Replay+Cleanup encoded")
	})
}

func generationOptionalIdentity(t *testing.T) {
	for _, variant := range []string{"absent", "width", "work", "later-IO"} {
		t.Run(variant, func(t *testing.T) {
			a := generationAuthority()
			hash, rows := generationProjection(2, 5, 55)
			a.SelectedSide = &mdbx.SelectedSideV1{GenerationID: 3, F: 5, TipHeight: 7, TipHash: [32]byte{7}, CumulativeChainwork: sideWorldWork(2), RowCount: 2, LogicalBytes: 532}
			first, _ := mdbx.HeightKey(3, 6)
			last, _ := mdbx.HeightKey(3, 7)
			rows = append(rows, generationRow(6, first, mdbx.ChainValue(hash, [32]byte{}, sideWorldWork(1))))
			if variant != "absent" {
				rows = append(rows, generationRow(6, last, mdbx.ChainValue([32]byte{7}, hash, sideWorldWork(2))))
			}
			w := generationNew(t, a, rows...)
			var raw []byte
			if variant == "width" {
				raw = make([]byte, 103)
			}
			if variant == "work" {
				raw = make([]byte, 104)
			}
			if raw != nil {
				logicalMDBXAssert(t, mdbx.FixtureSeedRawRow(w.s, 6, last, raw) == nil, "seed later link")
				rows[len(rows)-1].Literal = raw
			}
			scenario := mdbx.SelectedDamageProbeOnly
			if variant == "later-IO" {
				scenario = mdbx.SelectedDamageGetEIO
			}
			var out selectedSideOutcome
			_, err := mdbx.FixtureSelectedDamage(w.s, w.owner, scenario, 6, last, func() { out = CleanupGenerationMDBX(w.s, w.owner, 2, 1) })
			if variant == "later-IO" {
				sideWantOutcome(t, out, "LOCAL_RESOURCE_UNAVAILABLE(branch_data)", "OLD", 1, 1, variant)
				generationEngine(t, out.Err, "IO", "get", 5, "")
			} else {
				sideWantOutcome(t, out, "TERMINAL_STORE_INTEGRITY(canonical)", "OLD", 1, 1, variant)
				generationEngine(t, out.Err, "Integrity", "get", -30793, "")
			}
			logicalMDBXAssert(t, err == nil, "link fixture: %v", err)
			sideWantReleased(t, w.owner, variant)
			if variant == "absent" {
				rows = append(rows, generationRow(6, last, nil))
			}
			generationRaw(t, w, generationEncoded(t, a), rows)
		})
	}
}

func generationMalformedRows(t *testing.T) {
	for _, class := range []uint8{1, 2, 3, 4} {
		for _, length := range []int{0, 1, 7, 103, 104, 105} {
			t.Run(fmt.Sprintf("class%d-width%d", class, length), func(t *testing.T) {
				a := generationAuthority()
				w := generationNew(t, a)
				rank, key := uint8(1), append(binary.BigEndian.AppendUint64(nil, 2), make([]byte, 36)...)
				switch class {
				case 2:
					rank, key = 2, logicalMDBXMust(mdbx.HeightKey(2, 5))
				case 3:
					rank, key = 0, logicalMDBXMust(mdbx.MetaKey(0x10, 2))
				case 4:
					rank, key = 7, logicalMDBXMust(mdbx.CanonicalOwnerKey(2, [32]byte{9}))
				}
				value := make([]byte, length)
				logicalMDBXAssert(t, mdbx.FixtureSeedRawRow(w.s, rank, key, value) == nil, "seed malformed generation row")
				generationClean(t, w.run(class, 1440), 2)
				generationRaw(t, w, generationEncoded(t, generationTerminal(a)), []mdbx.Mutation{generationRow(rank, key, nil)})
			})
		}
	}
}

func generationPairGap(t *testing.T) {
	for _, class := range []uint8{2, 4} {
		t.Run(fmt.Sprint(class), func(t *testing.T) {
			a := generationAuthority()
			_, rows := generationProjection(2, 5, 55)
			partner, rank := rows[1].Key, uint8(7)
			for nonce := uint64(56); partner[len(partner)-1] == 0; nonce++ {
				_, rows = generationProjection(2, 5, nonce)
				partner = rows[1].Key
			}
			if class == 4 {
				partner, rank = rows[0].Key, 2
			}
			w := generationNew(t, a, rows...)
			want := slices.Clone(rows)
			for suffix := byte(0); suffix < 3; suffix++ {
				between := bytes.Clone(partner)
				between[len(between)-1]--
				between = append(between, suffix)
				logicalMDBXAssert(t, mdbx.FixtureSeedRawRow(w.s, rank, between, []byte{0x7f}) == nil, "seed blocking extended key")
				want = append(want, generationRow(rank, between, []byte{0x7f}))
			}
			for page := 0; page < 3; page++ {
				var out selectedSideOutcome
				e, err := mdbx.FixtureSelectedDamage(w.s, w.owner, 1, 0, nil, func() { out = CleanupGenerationMDBX(w.s, w.owner, mdbx.ObsoleteClassV1(class), 1) })
				generationClean(t, out, 2)
				logicalMDBXAssert(t, err == nil && e.OldGets[3] == 0 && e.OldGets[4] == 0 && e.OldGets[5] == 0 && e.OldGets[6] == 0, "preparation reached artifact/optional health: %+v/%v", e, err)
				sideWantReleased(t, w.owner, "pair preparation")
				want[len(rows)+page].Literal = nil
				w.image(a, rows...) // Selected pair and every dependent still have their independent input bytes.
				for _, row := range want {
					equal, err := mdbx.FixtureRawRowEqual(w.s, row.DBI.Rank, row.Key, row.Literal)
					logicalMDBXAssert(t, equal && err == nil, "one strictly decreasing preparation page: %d/%x/%v", row.DBI.Rank, row.Key, err)
				}
			}
			generationClean(t, w.run(class, 1), 2)
			generationRaw(t, w, generationEncoded(t, generationTerminal(a)), generationGone(want))
		})
	}
}

func generationMalformedIdentity(t *testing.T) {
	for _, class := range []uint8{2, 4} {
		for _, name := range []string{"zero-work", "above-work", "above-height", "nondefault-work", "upper-work", "upper-height"} {
			t.Run(fmt.Sprintf("class%d/%s", class, name), func(t *testing.T) {
				a := generationAuthority()
				a.B, a.U = 10, 13690
				h := uint64(5)
				if name == "above-height" {
					h = 0x100000000
				}
				if name == "upper-height" {
					h = 0xffffffff
				}
				hash, rows := generationProjection(2, h, 55)
				rows = append(rows, generationCanonical(hash, 11)...)
				w := generationNew(t, a, rows...)
				entry := bytes.Clone(rows[0].Literal)
				var work [40]byte
				switch name {
				case "above-work":
					work[3], work[39] = 1, 1
				case "upper-work":
					work[3] = 1
				case "nondefault-work":
					work[39] = 11
				case "above-height", "upper-height":
					work[39] = 1
				}
				copy(entry[64:104], work[:])
				rows[0].Literal, rows[3].Literal = entry, []byte{0x7f}
				logicalMDBXAssert(t, mdbx.FixtureSeedRawRow(w.s, 2, rows[0].Key, entry) == nil, "seed structural identity")
				logicalMDBXAssert(t, mdbx.FixtureSeedRawRow(w.s, 4, hash[:], rows[3].Literal) == nil, "independent required body damage")
				var out selectedSideOutcome
				e, err := mdbx.FixtureSelectedDamage(w.s, w.owner, 1, 0, nil, func() { out = CleanupGenerationMDBX(w.s, w.owner, mdbx.ObsoleteClassV1(class), 1) })
				invalid := name == "zero-work" || name == "above-work" || name == "above-height"
				expected := a
				if invalid {
					generationClean(t, out, 2)
					logicalMDBXAssert(t, e.OldGets[3] == 0 && e.OldGets[4] == 0 && e.OldGets[5] == 0 && e.OldGets[6] == 0, "invalid identity reached hash-global health: %+v", e)
					rows[0].Literal, rows[1].Literal = nil, nil
					expected = generationTerminal(a)
				} else {
					sideWantOutcome(t, out, "TERMINAL_STORE_INTEGRITY(canonical)", "OLD", 1, 1, name)
					logicalMDBXAssert(t, out.Err != nil && out.Err.Error() == "TERMINAL_STORE_INTEGRITY(canonical): invalid cleanup canonical body", "valid identity did not reach required body: %v", out.Err)
				}
				logicalMDBXAssert(t, err == nil, "identity native fixture: %v", err)
				sideWantReleased(t, w.owner, name)
				generationRaw(t, w, generationEncoded(t, expected), rows)
			})
		}
	}
}

func generationRankCollision(t *testing.T) {
	var hash, orphan [32]byte
	var rows []mdbx.Mutation
	var g uint64
	for nonce := uint64(55); nonce < 311; nonce++ {
		hash, rows = generationProjection(2, 5, nonce)
		g = binary.BigEndian.Uint64(hash[:8])
		copy(orphan[:24], hash[8:])
		orphan[31] = 7
		if g > 1 && g < ^uint64(0) && bytes.Compare(hash[:], orphan[:]) < 0 {
			hash, rows = generationProjection(g, 5, nonce)
			break
		}
	}
	logicalMDBXAssert(t, g > 1 && g < ^uint64(0) && bytes.Compare(hash[:], orphan[:]) < 0, "qualify ordered collision fixture")
	a := generationAuthority()
	a.Cleanup.Spans[0].GenerationID, a.NextGenerationID = g, g+1
	key := append(bytes.Clone(hash[:]), []byte{0, 0, 0, 0, 0, 0, 0, 7}...)
	orphanKey, _ := mdbx.CanonicalOwnerKey(g, orphan)
	logicalMDBXAssert(t, bytes.Equal(key, orphanKey), "literal physical key collision across ranks")
	derived := generationRow(7, orphanKey, binary.BigEndian.AppendUint64(nil, 6))
	w := generationNew(t, a, append(slices.Clone(rows), derived)...)
	logicalMDBXAssert(t, mdbx.FixtureSeedRawRow(w.s, 5, key, []byte{0x7f}) == nil, "seed malformed undo with derived key")
	generationClean(t, w.run(4, 1), 2)
	w.image(a, append(generationGone(rows), derived)...)
	equal, err := mdbx.FixtureRawRowEqual(w.s, 5, key, nil)
	logicalMDBXAssert(t, equal && err == nil, "undo deleted while equal-key generation row remains: %v", err)
	generationClean(t, w.run(4, 1), 2)
	want := append(generationGone(rows), generationRow(7, key, nil), generationRow(5, key, nil))
	generationRaw(t, w, generationEncoded(t, generationTerminal(a)), want)
}

func generationDamage(t *testing.T, rank uint8) {
	for _, kind := range []string{"none", "canonical", "selected", "defer"} {
		t.Run(kind, func(t *testing.T) {
			a := generationAuthority()
			hash, rows := generationProjection(2, 5, 55)
			if kind == "canonical" || kind == "defer" && rank == 5 {
				k := uint64(11)
				a.B, a.U = 10, 13690
				if kind == "canonical" && rank == 5 {
					k = 13691
				}
				rows = append(rows, generationCanonical(hash, k)...)
			}
			if kind == "selected" {
				rows = append(rows, generationSelected(&a, hash, rows[3].Literal)...)
			}
			if kind == "defer" {
				if rank == 5 {
					a.Cleanup.Spans = append(a.Cleanup.Spans, mdbx.CleanupSpanV1{Kind: 3, GenerationID: 1, LastHeight: 13689, NextHeight: 11})
				} else {
					a.Cleanup.Spans = append(a.Cleanup.Spans, mdbx.CleanupSpanV1{Kind: 4, GenerationID: 3, FirstHeight: 9, LastHeight: 9, NextHeight: 9})
					key, _ := mdbx.HeightKey(3, 9)
					rows = append(rows, generationRow(6, key, mdbx.ChainValue(hash, [32]byte{}, sideWorldWork(1))))
				}
			}
			w := generationNew(t, a, rows...)
			key := bytes.Clone(hash[:])
			index := 2
			if rank == 4 {
				index = 3
			}
			if rank == 5 {
				key, index = mdbx.UndoManifestKey(hash), 4
			}
			bad := []byte{0x7f}
			if rank == 3 {
				bad = bytes.Clone(rows[2].Literal)
				bad[115] ^= 1
			}
			logicalMDBXAssert(t, mdbx.FixtureSeedRawRow(w.s, rank, key, bad) == nil, "seed damage")
			rows[index].Literal = bad
			out := w.run(2, 1)
			expected := a
			want := slices.Clone(rows)
			switch kind {
			case "canonical":
				sideWantOutcome(t, out, "TERMINAL_STORE_INTEGRITY(canonical)", "OLD", 1, 1, kind)
				logicalMDBXAssert(t, out.Err != nil, "canonical damage accepted")
			case "selected":
				if rank == 5 {
					// Selected membership owns header/body, never compact undo.
					generationClean(t, out, 2)
					expected.Cleanup, expected.Phase = nil, 1
					want[0].Literal, want[1].Literal, want[4].Literal = nil, nil, nil
				} else {
					sideWantOutcome(t, out, "LOCAL_STORE_ERROR(noncanonical)", "NOT_APPLICABLE", 2, 3, kind)
					logicalMDBXAssert(t, out.Err == nil, "complete clear failed: %v", out.Err)
					expected.SelectedSide = nil
					expected.Cleanup = &mdbx.CleanupV1{Spans: []mdbx.CleanupSpanV1{{Kind: 1, GenerationID: 2}, {Kind: 4, GenerationID: 3, FirstHeight: 6, LastHeight: 6, NextHeight: 6}}}
					want[2].Literal = nil
				}
			default:
				generationClean(t, out, 2)
				expected = generationTerminal(a)
				if kind == "defer" {
					expected = a
					expected.Cleanup = &mdbx.CleanupV1{Spans: slices.Clone(a.Cleanup.Spans[1:])}
				}
				want[0].Literal, want[1].Literal = nil, nil
				if rank != 3 {
					if kind != "defer" || rank != 5 {
						want[2].Literal = nil
					}
					if kind != "defer" {
						want[3].Literal = nil
					}
					if kind != "defer" || rank != 5 {
						want[4].Literal = nil
					}
				}
			}
			generationRaw(t, w, generationEncoded(t, expected), want)
		})
	}
}

func generationNativeFaults(t *testing.T) {
	generationNativeMatrix(t, false, func(w *generationWorld) selectedSideOutcome { return CleanupGenerationMDBX(w.s, w.owner, 1, 1) })
	for _, rank := range []uint8{6, 7} {
		t.Run(fmt.Sprintf("consulted%d", rank), func(t *testing.T) {
			a := generationAuthority()
			hash, rows := generationProjection(2, 5, 55)
			rows = append(rows, generationSelected(&a, hash, rows[3].Literal)...)
			w := generationNew(t, a, rows...)
			key, _ := mdbx.CanonicalOwnerKey(1, hash)
			if rank == 6 {
				key, _ = mdbx.HeightKey(3, 6)
			}
			var out selectedSideOutcome
			e, err := mdbx.FixtureSelectedDamage(w.s, w.owner, 9, rank, key, func() { out = CleanupGenerationMDBX(w.s, w.owner, 2, 1) })
			generationCrossed(t, out, "update:Capacity,update:IO", false)
			logicalMDBXAssert(t, err == nil && e.ReadGets != 0 && e.ProbeRan == 0 && e.ProbeDenied == e.Probes, "consulted fixture: %+v/%v", e, err)
			sideWantReleased(t, w.owner, "consulted")
			want := slices.Clone(rows)
			want[0].Literal, want[1].Literal, want[4].Literal = nil, nil, nil
			generationRaw(t, w, generationEncoded(t, generationTerminal(a)), want)
		})
	}
	t.Run("read-provenance", generationReadProvenance)
	t.Run("callback-abort", func(t *testing.T) {
		a := generationAuthority()
		a.Cleanup.Spans = append(a.Cleanup.Spans, mdbx.CleanupSpanV1{Kind: 4, GenerationID: 3, FirstHeight: 1, LastHeight: 1441, NextHeight: 1})
		w := generationNew(t, a, generationData(2, 1)...)
		var out selectedSideOutcome
		e, err := mdbx.FixtureSelectedDamage(w.s, w.owner, 11, 0, nil, func() { out = CleanupGenerationMDBX(w.s, w.owner, 1, 1) })
		sideWantOutcome(t, out, "TERMINAL_STORE_INTEGRITY(canonical)", "OLD", 1, 1, "callback refusal plus cleanup failure")
		logicalMDBXAssert(t, sideCauses(out.Err) == "-,abort:IO" && err == nil && e.BeginWrite == 0, "callback ordered causes/image: %+v/%v", out, err)
		sideWantReleased(t, w.owner, "callback-abort")
		generationRaw(t, w, generationEncoded(t, a), w.rows)
	})
}

// The finite transport matrix shares one actual consumer invocation and literal
// OLD/NEW images across X2 faults and X3 full-lane native probes.
func generationNativeMatrix(t *testing.T, reservation bool, invoke func(*generationWorld) selectedSideOutcome) {
	for _, row := range []struct {
		name     string
		scenario mdbx.SelectedDamageScenario
		truth    mdbx.CommitTruth
		stage    mdbx.UpdateStage
		result   string
		causes   string
		image    string
	}{
		{"no-work", 1, 1, 1, "", "", "old"},
		{"work", 1, 2, 3, "", "", "new"},
		{"begin-full", 2, 1, 1, "", "update:Transaction", "old"},
		{"begin-IO", 3, 1, 1, "", "update:IO", "old"},
		{"authority-IO", 4, 1, 1, "LOCAL_RESOURCE_UNAVAILABLE(storage_io)", "get:IO", "old"},
		{"native-target-capture-IO", 4, 1, 1, "LOCAL_RESOURCE_UNAVAILABLE(storage_io)", "update:IO", "old"},
		{"reader-abort", 5, 1, 1, "LOCAL_RESOURCE_UNAVAILABLE(storage_io)", "get:IO,abort:IO", "old"},
		{"delete-IO", 6, 1, 2, "LOCAL_PERSISTENCE_ERROR(precommit)", "update:IO", "old"},
		{"commit-OLD", 7, 1, 3, "TERMINAL_PERSISTENCE(old)", "update:Capacity", "old"},
		{"commit-NEW", 8, 2, 3, "TERMINAL_PERSISTENCE(new)", "update:Capacity", "new"},
		{"commit-unreadable", 9, 3, 3, "TERMINAL_PERSISTENCE(neither_or_unreadable)", "update:Capacity,update:IO", "new"},
		{"commit-third", 10, 3, 3, "TERMINAL_PERSISTENCE(neither_or_unreadable)", "update:Capacity", "third"},
		{"no-work-abort", 11, 1, 1, "LOCAL_RESOURCE_UNAVAILABLE(storage_io)", "-,abort:IO", "old"},
		{"put-IO", 12, 1, 2, "LOCAL_PERSISTENCE_ERROR(precommit)", "update:IO", "old"},
	} {
		if (row.scenario == 1) != reservation {
			continue
		}
		t.Run(row.name, func(t *testing.T) {
			a := generationAuthority()
			work := row.name != "no-work" && row.name != "no-work-abort"
			if !work {
				a = generationRouteAuthorities()[0].a
			}
			oldRows := generationData(2, 1)
			newRows := []mdbx.Mutation{generationRow(1, oldRows[0].Key, nil), oldRows[1]}
			oldAuthority, newAuthority := generationEncoded(t, a), generationEncoded(t, a)
			w := generationNew(t, a, oldRows...)
			rank, key := uint8(0), []byte{2}
			if row.name == "native-target-capture-IO" {
				rank, key = 1, oldRows[0].Key
			}
			var out selectedSideOutcome
			calls := 0
			e, err := mdbx.FixtureSelectedDamage(w.s, w.owner, row.scenario, rank, key, func() {
				calls++
				out = invoke(w)
			})
			canonical := row.truth.String()
			if row.scenario == 2 || row.scenario == 3 {
				canonical = ""
			}
			sideWantOutcome(t, out, row.result, canonical, row.truth, row.stage, row.name)
			logicalMDBXAssert(t, sideCauses(out.Err) == row.causes, "ordered raw causes: %q/%q", sideCauses(out.Err), row.causes)
			logicalMDBXAssert(t, err == nil && calls == 1 && e.ProbeRan == 0 && e.ProbeDenied == e.Probes, "native lane/fault: %+v/%v", e, err)
			if row.scenario >= 7 && row.scenario <= 10 {
				commit, direct := out.Err.(*mdbx.CommitError)
				logicalMDBXAssert(t, direct && commit.Truth == row.truth, "direct raw CommitError: %v", out.Err)
			}
			if reservation {
				probes := uint64(2)
				if work {
					probes = 4
				}
				logicalMDBXAssert(t, out.Err == nil && e.Probes == probes, "full native lane lifetime: %+v/%v", e, out.Err)
			}
			if row.name == "native-target-capture-IO" {
				generationEngine(t, out.Err, "IO", "update", 5, "")
				logicalMDBXAssert(t, e.Faults == 1 && e.Deletes == 0 && e.Commits == 0, "postcallback target capture before effects: %+v", e)
			}
			sideWantReleased(t, w.owner, row.name)
			expected, want := oldAuthority, oldRows
			if row.image != "old" {
				expected, want = newAuthority, newRows // Counter still prevents exhaustion.
			}
			if row.image == "third" {
				expected = []byte{0x7f}
			}
			generationRaw(t, w, expected, want)
		})
	}
}

func generationReadProvenance(t *testing.T) {
	for _, name := range []string{"obsolete-index", "canonical-obsolete-index", "canonical-inverse", "canonical-forward", "optional-link", "optional-header", "optional-body", "canonical-header", "canonical-body", "canonical-undo"} {
		t.Run(name, func(t *testing.T) {
			a := generationAuthority()
			hash, rows := generationProjection(2, 5, 55)
			rank, key := uint8(2), rows[0].Key
			required := name == "canonical-inverse" || name == "canonical-forward" || name == "canonical-header" || name == "canonical-body" || name == "canonical-undo"
			if required || name == "canonical-obsolete-index" {
				a.B, a.U = 10, 13690
				k := uint64(11)
				if name == "canonical-undo" {
					k = 13691
					rows[4].Literal = mdbx.UndoManifestValue(k, [16]byte{}, 1, 0)
				}
				active := generationCanonical(hash, k)
				rows = append(rows, active...)
				if name == "canonical-inverse" {
					rank, key = 7, active[1].Key
				}
				if name == "canonical-forward" {
					key = active[0].Key
				}
			} else if name != "obsolete-index" {
				rows = append(rows, generationSelected(&a, hash, rows[3].Literal)...)
			}
			switch name {
			case "optional-link":
				rank, key = 6, logicalMDBXMust(mdbx.HeightKey(3, 6))
			case "optional-header", "canonical-header":
				rank, key = 3, hash[:]
			case "optional-body", "canonical-body":
				rank, key = 4, hash[:]
			case "canonical-undo":
				rank, key = 5, rows[4].Key
			}
			w := generationNew(t, a, rows...)
			var out selectedSideOutcome
			e, err := mdbx.FixtureSelectedDamage(w.s, w.owner, 4, rank, key, func() { out = CleanupGenerationMDBX(w.s, w.owner, 2, 1) })
			result := "LOCAL_RESOURCE_UNAVAILABLE(branch_data)"
			if required {
				result = "LOCAL_RESOURCE_UNAVAILABLE(canonical_artifact_read)"
			}
			sideWantOutcome(t, out, result, "OLD", 1, 1, name)
			generationEngine(t, out.Err, "IO", "get", 5, "error 5")
			engine, direct := out.Err.(*mdbx.EngineError)
			logicalMDBXAssert(t, direct && engine != nil && engine.Cause == nil && !engine.ReopenRequired, "original direct native read error: %v", out.Err)
			logicalMDBXAssert(t, err == nil && e.Faults == 1 && e.OldAborts == 1 && e.BeginWrite == 0 && e.Deletes == 0 && e.Commits == 0 && e.Probes != 0 && e.ProbeRan == 0 && e.ProbeDenied == e.Probes, "first read failure committed: %+v/%v", e, err)
			if name == "optional-header" || name == "canonical-header" {
				logicalMDBXAssert(t, e.OldGets[3] == 1 && e.OldGets[4] == 0 && e.OldGets[5] == 0, "header failure continued health: %+v", e)
			}
			if name == "obsolete-index" || name == "canonical-obsolete-index" {
				logicalMDBXAssert(t, e.OldGets[3]+e.OldGets[4]+e.OldGets[5]+e.OldGets[6]+e.OldGets[7] == 0, "obsolete source failure consulted owners/artifacts: %+v", e)
			}
			sideWantReleased(t, w.owner, name)
			generationRaw(t, w, generationEncoded(t, a), rows)
		})
	}
}

func generationCrossed(t *testing.T, out selectedSideOutcome, causes string, drift bool) {
	t.Helper()
	sideWantOutcome(t, out, "TERMINAL_PERSISTENCE(neither_or_unreadable)", "UNKNOWN", 3, 3, "actual cleanup readback")
	commit, direct := out.Err.(*mdbx.CommitError)
	logicalMDBXAssert(t, direct && commit.Truth == 3 && sideCauses(out.Err) == causes, "direct raw CommitError: %+v/%v", out, out.Err)
	if drift {
		logicalMDBXAssert(t, commit.ReadbackCause == nil, "drift readback cause: %v", commit.ReadbackCause)
		generationEngine(t, commit.Cause, "Capacity", "update", 28, "")
	}
}

func generationNativeReservations(t *testing.T) {
	generationNativeMatrix(t, true, func(w *generationWorld) selectedSideOutcome { return CleanupGenerationMDBX(w.s, w.owner, 1, 1) })
}

func TestCleanupGenerationMDBXReadbackDrift(t *testing.T) {
	t.Run("R16b", func(t *testing.T) { generationDrift(t, "body", 4, false) })
	t.Run("H7", func(t *testing.T) {
		for _, kind := range []string{"keep", "defer"} {
			for _, entry := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s-entry%t", kind, entry), func(t *testing.T) { generationDrift(t, kind, 5, entry) })
			}
		}
	})
	t.Run("H12", func(t *testing.T) {
		for _, kind := range []string{"invalid-body", "invalid-BLOCKS", "invalid-SIDE"} {
			t.Run(kind, func(t *testing.T) { generationDrift(t, kind, 4, false) })
		}
		for _, kind := range []string{"invalid-keep", "invalid-defer"} {
			for _, entry := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s-entry%t", kind, entry), func(t *testing.T) { generationDrift(t, kind, 5, entry) })
			}
		}
	})
}

func generationDriftWorld(t *testing.T, kind string, rank uint8) (*generationWorld, [32]byte, []mdbx.Mutation) {
	var w *generationWorld
	var hash [32]byte
	var family []mdbx.Mutation
	if rank == 5 {
		familyKind := "keep"
		if kind == "defer" || kind == "invalid-defer" {
			familyKind = "defer"
		}
		w, hash, family = generationFamily(t, familyKind)
	} else {
		a := generationAuthority()
		a.B, a.U = 10, 13690
		var rows []mdbx.Mutation
		hash, rows = generationProjection(2, 5, 55)
		k := uint64(11)
		if kind == "invalid-BLOCKS" {
			k = 8
			a.Cleanup.Spans = append(a.Cleanup.Spans, mdbx.CleanupSpanV1{Kind: 2, GenerationID: 1, LastHeight: 9, NextHeight: 8})
		}
		if kind == "invalid-SIDE" {
			a.B, a.U = 0, 0
			a.Cleanup.Spans = append(a.Cleanup.Spans, mdbx.CleanupSpanV1{Kind: 4, GenerationID: 3, FirstHeight: 9, LastHeight: 9, NextHeight: 9})
			key, _ := mdbx.HeightKey(3, 9)
			rows = append(rows, generationRow(6, key, mdbx.ChainValue(hash, [32]byte{}, sideWorldWork(1))))
		} else {
			rows = append(rows, generationCanonical(hash, k)...)
		}
		w = generationNew(t, a, rows...)
	}
	if bytes.HasPrefix([]byte(kind), []byte("invalid-")) {
		// Only the obsolete parent differs. The independently named active
		// header/body, canonical proof, and deferred identity remain valid.
		bad := bytes.Clone(w.rows[0].Literal)
		bad[32] = 1
		logicalMDBXAssert(t, mdbx.FixtureSeedRawRow(w.s, 2, w.rows[0].Key, bad) == nil, "invalid own header parent")
		w.rows[0].Literal = bad
	}
	return w, hash, family
}

func generationDrift(t *testing.T, kind string, rank uint8, entry bool) {
	w, hash, family := generationDriftWorld(t, kind, rank)
	key := bytes.Clone(hash[:])
	if rank == 5 {
		key = mdbx.UndoManifestKey(hash)
		if entry {
			key = family[len(family)-1].Key
		}
	}
	var out selectedSideOutcome
	calls := 0
	drift, err := mdbx.FixtureCleanupReadbackDrift(w.s, rank, key, func() {
		calls++
		out = CleanupGenerationMDBX(w.s, w.owner, 2, 1)
	})
	// The actual tuple is asserted before drift/counters or any Store query.
	generationCrossed(t, out, "update:Capacity", true)
	value := reflect.ValueOf(w.s).Elem()
	logicalMDBXAssert(t, value.FieldByName("state").String() == "CLOSED" && value.FieldByName("env").IsNil(), "consumed Store must be CLOSED/envnil")
	logicalMDBXAssert(t, err == nil && drift == 1 && calls == 1, "fixed mode3 actual invocation: %d/%d/%v", calls, drift, err)
	sideWantReleased(t, w.owner, "readback drift")
	want := slices.Clone(w.rows)
	want[0].Literal, want[1].Literal = nil, nil
	if rank == 4 {
		want[3].Literal = []byte{0x7f}
		if kind == "body" {
			want[4].Literal = nil
		}
	} else if !entry {
		want[4].Literal = []byte{0x7f}
	}
	expected := generationTerminal(w.a)
	if len(w.a.Cleanup.Spans) > 1 {
		expected = w.a
		expected.Cleanup = &mdbx.CleanupV1{Spans: slices.Clone(w.a.Cleanup.Spans[1:])}
	}
	want = append(want, generationRow(rank, key, []byte{0x7f}))
	if rank == 5 {
		if entry {
			family[len(family)-1].Literal = []byte{0x7f}
		} else {
			family[0].Literal = []byte{0x7f}
		}
		generationRaw(t, w, generationEncoded(t, expected), want, family)
	} else {
		generationRaw(t, w, generationEncoded(t, expected), want)
	}
}

func generationUndoSemantics(t *testing.T) {
	for _, name := range []string{"height", "zero-tx", "tx-bound", "spent-bound", "missing-entry", "excess-entry", "zero-index", "index-bound", "coordinate", "outpoint", "missing-manifest"} {
		t.Run(name, func(t *testing.T) {
			a := generationAuthority()
			a.B, a.U = 10, 13690
			hash, rows := generationProjection(2, 5, 55)
			rows = append(rows, generationCanonical(hash, 13691)...)
			height, txs, spent := uint64(13691), uint32(3), uint32(1)
			txIndex := uint32(1)
			switch name {
			case "height":
				height--
			case "zero-tx":
				txs = 0
			case "tx-bound":
				txs = 1545455
			case "spent-bound":
				spent = 414635
			case "missing-entry":
				spent = 2
			case "excess-entry":
				spent = 0
			case "zero-index":
				txIndex = 0
			case "index-bound":
				txIndex = txs
			case "coordinate", "outpoint":
				spent = 2
			}
			rows[4].Literal = mdbx.UndoManifestValue(height, [16]byte{}, txs, spent)
			value, _ := (mdbx.UTXOValue{Value: 1}).Encode()
			entry := mdbx.UndoEntryKey(hash, [32]byte{1}, txIndex, 0, 0)
			rows = append(rows, generationRow(5, entry, value))
			if name == "coordinate" || name == "outpoint" {
				other, input := [32]byte{2}, uint32(0)
				if name == "outpoint" {
					other, input = [32]byte{1}, 1
				}
				rows = append(rows, generationRow(5, mdbx.UndoEntryKey(hash, other, 1, input, 0), value))
			}
			w := generationNew(t, a, rows...)
			if name == "missing-manifest" {
				logicalMDBXSeed(t, w.s, mdbx.Mutation{DBI: logicalMDBXDBIs[5], Key: rows[4].Key, BeforePresent: true, AfterKind: 1})
				rows[4].Literal = nil
			}
			out := w.run(2, 1)
			sideWantOutcome(t, out, "TERMINAL_STORE_INTEGRITY(canonical)", "OLD", 1, 1, name)
			logicalMDBXAssert(t, out.Err != nil && out.Err.Error() == "TERMINAL_STORE_INTEGRITY(canonical): invalid cleanup canonical undo", "complete family semantic refusal: %v", out.Err)
			generationRaw(t, w, generationEncoded(t, a), rows)
		})
	}
}

func generationSelectedCrossed(t *testing.T) {
	for _, scenario := range []mdbx.SelectedDamageScenario{7, 8, 9, 10} {
		t.Run(fmt.Sprint(scenario), func(t *testing.T) {
			a := generationAuthority()
			hash, rows := generationProjection(2, 5, 55)
			rows = append(rows, generationSelected(&a, hash, rows[3].Literal)...)
			w := generationNew(t, a, rows...)
			bad := bytes.Clone(rows[3].Literal)
			bad[115] ^= 1
			logicalMDBXAssert(t, mdbx.FixtureSeedRawRow(w.s, 4, hash[:], bad) == nil, "positive selected body damage")
			rows[3].Literal = bad
			var out selectedSideOutcome
			e, err := mdbx.FixtureSelectedDamage(w.s, w.owner, scenario, 0, []byte{2}, func() { out = CleanupGenerationMDBX(w.s, w.owner, 2, 1) })
			truth := mdbx.CommitTruth(3)
			if scenario == 7 {
				truth = 1
			}
			if scenario == 8 {
				truth = 2
			}
			sideWantOutcome(t, out, "LOCAL_STORE_ERROR(noncanonical)", "NOT_APPLICABLE", truth, 3, "complete selected clear exception")
			cause := "update:Capacity"
			if scenario == 9 {
				cause += ",update:IO"
			}
			commit, direct := out.Err.(*mdbx.CommitError)
			logicalMDBXAssert(t, direct && commit.Truth == truth && sideCauses(out.Err) == cause, "selected raw tuple: %v", out.Err)
			logicalMDBXAssert(t, err == nil && e.BeginWrite == 1 && e.Commits == 1 && e.BeginRead == 1 && e.ProbeDenied == e.Probes && e.ProbeRan == 0, "selected crossed native sites: %+v/%v", e, err)
			sideWantReleased(t, w.owner, "selected crossed")
			expected := generationEncoded(t, a)
			if scenario != 7 {
				a.SelectedSide = nil
				a.Cleanup = &mdbx.CleanupV1{Spans: []mdbx.CleanupSpanV1{{Kind: 1, GenerationID: 2}, {Kind: 4, GenerationID: 3, FirstHeight: 6, LastHeight: 6, NextHeight: 6}}}
				expected = generationEncoded(t, a)
				rows[2].Literal = nil
			}
			if scenario == 10 {
				expected = []byte{0x7f}
			}
			// Own generation projection/body/undo stay unchanged on every clear.
			generationRaw(t, w, expected, rows)
		})
	}
}
