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
	if reflect.ValueOf(w.s).Elem().FieldByName("state").String() != "CLOSED" {
		_ = w.s.Close()
	}
	reopened, err := mdbx.Open(w.path, w.cfg)
	logicalMDBXAssert(t, err == nil, "same creation path/config Open: %v", err)
	defer func() { _ = reopened.Close() }()
	rows = append(slices.Clone(rows), generationRow(0, []byte{2}, authority))
	for _, row := range rows {
		equal, err := mdbx.FixtureRawRowEqual(reopened, row.DBI.Rank, row.Key, row.Literal)
		logicalMDBXAssert(t, err == nil && equal, "raw image rank%d/%x: %v", row.DBI.Rank, row.Key, err)
	}
	if len(family) != 0 {
		generationFamilyImage(t, reopened, [32]byte(rows[2].Key), family[0])
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

func TestCleanupGenerationMDBXNative(t *testing.T) {
	t.Run("R1b", generationAuthorityRejections)
	t.Run("R18b", func(t *testing.T) { generationOptionalIdentity(t, "") })
	t.Run("P10-A6-optional-keep", func(t *testing.T) {
		for _, keep := range []string{"canonical-selected", "canonical-SIDE", "selected-SIDE"} {
			t.Run(keep, func(t *testing.T) { generationOptionalIdentity(t, keep) })
		}
	})
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
		t.Run("wide-raw-capacity", func(t *testing.T) {
			for _, count := range []int{1054, 1055} {
				t.Run(fmt.Sprint(count), func(t *testing.T) {
					cfg := sideWorldConfig
					cfg.PageSize = 65536
					a, hash, rows := generationBaseProjection()
					w := generationNewConfig(t, cfg, a, rows...)
					family := []mdbx.Mutation{rows[4]}
					for i := 0; i < count; i++ {
						key := make([]byte, 32700)
						copy(key, hash[:])
						key[32] = 1
						binary.BigEndian.PutUint32(key[33:37], uint32(i))
						family = append(family, generationRow(5, key, []byte{0x7f}))
						logicalMDBXAssert(t, mdbx.FixtureSeedRawRow(w.s, 5, key, []byte{0x7f}) == nil, "seed wide raw undo")
					}
					out := w.run(2, 1)
					expected, want := generationTerminal(a), generationGone(rows)
					if count == 1055 {
						sideWantOutcome(t, out, "LOCAL_RESOURCE_UNAVAILABLE(storage_capacity)", "OLD", 1, 1, "wide raw capacity")
						logicalMDBXAssert(t, out.Err != nil && out.Err.Error() == "LOCAL_RESOURCE_UNAVAILABLE(storage_capacity): cleanup undo family exceeds admitted representation capacity", "wide raw capacity error: %v", out.Err)
						expected, want = a, rows
					} else {
						generationClean(t, out, 2)
						family = nil
					}
					w.image(expected, want...)
					generationRaw(t, w, generationEncoded(t, expected), want, family)
				})
			}
		})
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
			a, _, rows := generationBaseProjection()
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
				tip, u := uint64(1449), uint64(10)
				kind := mdbx.CleanupSpanUndoV1
				if name == "carried-BLOCKS" {
					a.B, tip, u, kind = 10, 15129, 13690, mdbx.CleanupSpanBlocksV1
				}
				a.U = u
				a.Ordinary.OldSuffix = []mdbx.AuthorityPointV1{{Height: tip, BlockHash: [32]byte{9}}}
				a.Ordinary.NewSuffix[0].Height, a.Ordinary.NewSuffix[1].Height = tip, tip+1
				a.Ordinary.Target, a.Ordinary.Cursor = a.Ordinary.NewSuffix[1], &a.Ordinary.NewSuffix[0]
				a.Ordinary.CapturedSelectedSide.F, a.Ordinary.CapturedSelectedSide.TipHeight = tip-1, tip+1
				a.Ordinary.CarriedCleanup.Spans = append(a.Ordinary.CarriedCleanup.Spans, mdbx.CleanupSpanV1{Kind: kind, GenerationID: 1, LastHeight: 8})
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

func generationOptionalIdentity(t *testing.T, keep string) {
	for _, variant := range []string{"absent", "width", "work", "later-IO"} {
		t.Run(variant, func(t *testing.T) {
			a, hash, rows := generationBaseProjection()
			a.SelectedSide = &mdbx.SelectedSideV1{GenerationID: 3, F: 5, TipHeight: 7, TipHash: [32]byte{7}, CumulativeChainwork: sideWorldWork(2), RowCount: 2, LogicalBytes: 532}
			first, _ := mdbx.HeightKey(3, 6)
			last, _ := mdbx.HeightKey(3, 7)
			rows = append(rows, generationRow(6, first, mdbx.ChainValue(hash, [32]byte{}, sideWorldWork(1))))
			link := mdbx.ChainValue([32]byte{7}, hash, sideWorldWork(2))
			if keep != "" && keep != "selected-SIDE" {
				a.B, a.U = 10, 13690
				rows = append(rows, generationCanonical(hash, 11)...)
				a.Cleanup.Spans = append(a.Cleanup.Spans, mdbx.CleanupSpanV1{Kind: 3, GenerationID: 1, LastHeight: 13689, NextHeight: 11})
			}
			if keep == "canonical-SIDE" {
				a.SelectedSide = nil
				a.Cleanup.Spans = append(a.Cleanup.Spans, mdbx.CleanupSpanV1{Kind: 4, GenerationID: 3, FirstHeight: 6, LastHeight: 7, NextHeight: 6})
			}
			if keep == "selected-SIDE" {
				rows = generationRollingSelected(&a, rows)
				last, _ = mdbx.HeightKey(3, 1)
				link = mdbx.ChainValue(hash, [32]byte{}, sideWorldWork(1))
			}
			if variant != "absent" {
				rows = append(rows, generationRow(6, last, link))
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
			e, err := mdbx.FixtureSelectedDamage(w.s, w.owner, scenario, 6, last, func() { out = CleanupGenerationMDBX(w.s, w.owner, 2, 1) })
			expected := a
			if keep != "" {
				generationClean(t, out, 2)
				logicalMDBXAssert(t, e.Faults == 0, "settled keep read unnecessary link: %+v", e)
				rows[0].Literal, rows[1].Literal = nil, nil
				if keep == "selected-SIDE" {
					rows[4].Literal = nil
				}
				expected.Cleanup = &mdbx.CleanupV1{Spans: slices.Clone(a.Cleanup.Spans[1:])}
			} else if variant == "later-IO" {
				sideWantOutcome(t, out, "LOCAL_RESOURCE_UNAVAILABLE(branch_data)", "OLD", 1, 1, variant)
				generationEngine(t, out.Err, "IO", "get", 5, "")
			} else {
				sideWantOutcome(t, out, "TERMINAL_STORE_INTEGRITY(canonical)", "OLD", 1, 1, variant)
				generationEngine(t, out.Err, "Integrity", "get", -30793, "")
			}
			logicalMDBXAssert(t, (keep != "" && variant == "later-IO") == (err != nil) && (err == nil || err.Error() == "selected damage fixture site was not reached exactly as armed"), "link fixture: %v", err)
			sideWantReleased(t, w.owner, variant)
			if variant == "absent" {
				rows = append(rows, generationRow(6, last, nil))
			}
			generationRaw(t, w, generationEncoded(t, expected), rows)
		})
	}
}

func TestDrainDetachedMDBXNative(t *testing.T) {
	t.Run("P11-A1b", detachedRecordedLength)
	for _, name := range []string{"P11-A3b", "P11-A3f", "H9"} {
		t.Run(name, func(t *testing.T) { detachedRawDamage(t, name) })
	}
	for _, name := range []string{"R1c", "R8", "R9", "R9a", "R9b", "R9c", "R9d", "R9e", "R9f", "R9g", "R9h", "R9i", "R9j"} {
		t.Run(name, func(t *testing.T) { detachedAuthorityRejection(t, name) })
	}
	t.Run("R7", detachedDeniedNative)
	for _, name := range []string{"R11", "R12", "R13", "R14", "R14a"} {
		t.Run(name, func(t *testing.T) { detachedReadFailure(t, name) })
	}
	t.Run("R18a", detachedSideIdentity)
	t.Run("lowest-parent", detachedLowestParentFailure)
	t.Run("R18c", detachedExactPromises)
	t.Run("R18d", detachedOpenRefusal)
	t.Run("P11-A5", func(t *testing.T) { detachedNativeMatrix(t, false, "crossed") })
	t.Run("P11-A7", func(t *testing.T) { detachedNativeMatrix(t, true, "all") })
	t.Run("X2", func(t *testing.T) {
		detachedInvalidStage(t)
		detachedNativeMatrix(t, false, "uncrossed")
	})
	t.Run("X3", detachedGrantLifetimes)
	t.Run("R15c", detachedAbortRefusal)
	t.Run("H1", func(t *testing.T) { detachedOwnerAuthority(t, "H1") })
	t.Run("H2", func(t *testing.T) { detachedOwnerAuthority(t, "H2") })
	t.Run("H3", func(t *testing.T) { detachedOwnerAuthority(t, "H3") })
	t.Run("H4", func(t *testing.T) { detachedOwnerAuthority(t, "H4") })
	t.Run("H10", detachedIgnoredReader)
	t.Run("readback-body", detachedReadbackBody)
	t.Run("readback-owners", detachedReadbackOwners)
	t.Run("required-body-damage", detachedRequiredBodyDamage)
}

func detachedRecordedLength(t *testing.T) {
	a, rows := detachedFixture(t, 2)
	a.DetachedSuffix.Entries[0].Height, a.DetachedSuffix.Entries[1].Height = 12, 11
	a.DetachedSuffix.Cursor.Height = 12
	a.DetachedSuffix.Entries[0].BlockBytesLen, a.DetachedSuffix.Entries[1].BlockBytesLen, a.DetachedSuffix.LogicalBytes = 100, 50, 150
	// The scalar-valid lengths are not health promises; actual short remnants
	// are seeded only through the existing raw fixture.
	old := slices.Clone(rows)
	old[len(old)-1].Literal = []byte{0x99}
	w := generationNew(t, a, rows...)
	logicalMDBXAssert(t, mdbx.FixtureSeedRawRow(w.s, 4, old[len(old)-1].Key, old[len(old)-1].Literal) == nil, "seed physical short body")
	var out selectedSideOutcome
	e, err := mdbx.FixtureSelectedDamage(w.s, w.owner, 1, 0, nil, func() { out = detachedRun(t, w) })
	detachedCommitted(t, out, true)
	logicalMDBXAssert(t, err == nil && e.BeginWrite == 1 && e.ProbeRan == 0 && e.ProbeDenied == e.Probes, "recorded-length native commit: %+v/%v", e, err)
	generationRaw(t, w, generationEncoded(t, detachedAfter(a, 1, 50)), detachedGone(old))
}

func detachedRawDamage(t *testing.T, name string) {
	a, rows := detachedFixture(t, 2)
	w := generationNew(t, a, rows...)
	rank, index := uint8(4), len(rows)-1
	var value []byte
	if name == "P11-A3b" {
		rank, index, value = 3, len(rows)-2, []byte{0x03}
	} else {
		value = make([]byte, 68000126)
	}
	logicalMDBXAssert(t, mdbx.FixtureSeedRawRow(w.s, rank, rows[index].Key, value) == nil, "seed bounded malformed remnant")
	rows[index].Literal = value
	var out selectedSideOutcome
	e, err := mdbx.FixtureSelectedDamage(w.s, w.owner, 1, 0, nil, func() { out = detachedRun(t, w) })
	detachedCommitted(t, out, true)
	logicalMDBXAssert(t, err == nil && e.BeginWrite == 1 && e.Probes > 0 && e.ProbeRan == 0 && e.ProbeDenied == e.Probes, "damaged progress native/grant: %+v/%v", e, err)
	generationRaw(t, w, generationEncoded(t, detachedAfter(a, 1, 266)), detachedGone(rows))
}

func detachedMalformed(t *testing.T, a mdbx.StorageAuthorityV1, name string) []byte {
	t.Helper()
	bad := generationEncoded(t, a)
	d := a.DetachedSuffix
	start := len(bad) - (52 + 48*len(d.Entries))
	entry, cursor := start+2, start+2+48*len(d.Entries)
	switch name {
	case "R1c":
		bad[0] = 2
	case "R8":
		binary.BigEndian.PutUint64(bad[cursor:cursor+8], 11)
		copy(bad[cursor+8:cursor+40], bad[entry+56:entry+88])
	case "R9":
		binary.BigEndian.PutUint16(bad[len(bad)-10:len(bad)-8], 1)
	case "R9a":
		bad = detachedCardinalityWire(t, bad[:start], 0)
	case "R9b":
		binary.BigEndian.PutUint64(bad[entry:entry+8], 0x100000000)
		binary.BigEndian.PutUint64(bad[entry+48:entry+56], 0xffffffff)
		binary.BigEndian.PutUint64(bad[cursor:cursor+8], 0x100000000)
	case "R9c", "R9d":
		length := uint64(0)
		if name == "R9d" {
			length = 68000126
		}
		binary.BigEndian.PutUint64(bad[entry+40:entry+48], length)
		binary.BigEndian.PutUint64(bad[len(bad)-8:], length+266)
	case "R9e":
		binary.BigEndian.PutUint64(bad[entry:entry+8], 12)
		binary.BigEndian.PutUint64(bad[cursor:cursor+8], 12)
	case "R9f":
		binary.BigEndian.PutUint64(bad[entry+48:entry+56], 12)
	case "R9g":
		copy(bad[entry+56:entry+88], bad[entry+8:entry+40])
	case "R9h":
		bad = detachedCardinalityWire(t, bad[:start], 1441)
	case "R9i":
		binary.BigEndian.PutUint64(bad[len(bad)-8:], 533)
	case "R9j":
		bad = append(bytes.Clone(bad[:36]), bad[46:]...)
		bad[34] = 1
	}
	_, err := mdbx.DecodeStorageAuthorityV1(bad)
	logicalMDBXAssert(t, err != nil, "target malformed descriptor admitted: %s", name)
	return bad
}

func detachedCardinalityWire(t *testing.T, prefix []byte, count uint16) []byte {
	t.Helper()
	// Emit the complete descriptor so cardinality is the only invalid field.
	bad := append(bytes.Clone(prefix), make([]byte, 52+48*int(count))...)
	start, sum := len(prefix), uint64(0)
	binary.BigEndian.PutUint16(bad[start:start+2], count)
	for i := 0; i < int(count); i++ {
		entry := start + 2 + 48*i
		binary.BigEndian.PutUint64(bad[entry:entry+8], uint64(count)-1-uint64(i))
		binary.BigEndian.PutUint64(bad[entry+8:entry+16], uint64(i)+1)
		binary.BigEndian.PutUint64(bad[entry+40:entry+48], 266)
		logicalMDBXAssert(t, sum <= ^uint64(0)-266, "fixture logical sum overflow")
		sum += 266
	}
	cursor := start + 2 + 48*int(count)
	if count != 0 {
		copy(bad[cursor:cursor+40], bad[start+2:start+42])
	}
	binary.BigEndian.PutUint16(bad[len(bad)-10:len(bad)-8], count)
	binary.BigEndian.PutUint64(bad[len(bad)-8:], sum)
	return bad
}

func detachedAuthorityRejection(t *testing.T, name string) {
	for _, denied := range []bool{false, true} {
		t.Run(fmt.Sprintf("denied%t", denied), func(t *testing.T) {
			a, rows := detachedFixture(t, 2)
			if name == "R8" {
				a.DetachedSuffix.Entries[0].Height, a.DetachedSuffix.Entries[1].Height, a.DetachedSuffix.Cursor.Height = 12, 11, 12
			}
			bad := detachedMalformed(t, a, name)
			w := generationNew(t, a, rows...)
			logicalMDBXAssert(t, mdbx.FixtureSeedRawRow(w.s, 0, []byte{2}, bad) == nil, "seed malformed descriptor")
			var out selectedSideOutcome
			invoke := func() {
				out = DrainDetachedMDBX(w.s, w.owner)
			}
			if denied {
				original := invoke
				invoke = func() { logicalMDBXAssert(t, w.owner.WithReservation(1, func() error { original(); return nil }) == nil, "hold denied lane") }
			}
			e, err := mdbx.FixtureSelectedDamage(w.s, w.owner, 1, 0, nil, invoke)
			sideWantOutcome(t, out, "TERMINAL_STORE_INTEGRITY(canonical)", "OLD", 1, 1, name)
			generationEngine(t, out.Err, "Integrity", "get", -30793, "invalid storage authority")
			logicalMDBXAssert(t, err == nil && e.BeginWrite == 0 && e.OldGets == ([8]uint64{1}), "strict authority before capacity/data: %+v/%v", e, err)
			sideWantReleased(t, w.owner, name)
			generationRaw(t, w, bad, rows)
		})
	}
	if name == "R1c" {
		for _, cleanup := range []*mdbx.CleanupV1{nil, {}} {
			a, rows := detachedFixture(t, 2)
			invalid := a
			invalid.Cleanup = cleanup
			_, encodeErr := invalid.Encode()
			logicalMDBXAssert(t, encodeErr != nil, "suffix without nonempty Cleanup encoded")
			bad := generationEncoded(t, a)
			bad[36] = 0
			bad = append(bytes.Clone(bad[:37]), bad[46:]...)
			w := generationNew(t, a, rows...)
			logicalMDBXAssert(t, mdbx.FixtureSeedRawRow(w.s, 0, []byte{2}, bad) == nil, "seed zero cleanup")
			out := detachedRun(t, w)
			sideWantOutcome(t, out, "TERMINAL_STORE_INTEGRITY(canonical)", "OLD", 1, 1, "suffix cleanup shape")
			generationEngine(t, out.Err, "Integrity", "get", -30793, "invalid storage authority")
			generationRaw(t, w, bad, rows)
		}
	}
}

func detachedDeniedNative(t *testing.T) {
	a, rows := detachedFixture(t, 2)
	rows = rows[:len(rows)-1] // A positively missing body must not become damage.
	w := generationNew(t, a, rows...)
	var out selectedSideOutcome
	e, err := mdbx.FixtureSelectedDamage(w.s, w.owner, 1, 0, nil, func() {
		logicalMDBXAssert(t, w.owner.WithReservation(1, func() error { out = DrainDetachedMDBX(w.s, w.owner); return nil }) == nil, "deny full lane")
	})
	sideWantOutcome(t, out, "LOCAL_RESOURCE_UNAVAILABLE(storage_capacity)", "OLD", 1, 1, "capacity before missing body")
	logicalMDBXAssert(t, out.Err != nil && out.Err.Error() == "storage operation reservation capacity unavailable" && err == nil && e.BeginWrite == 0 && e.OldGets == ([8]uint64{1}), "denied control-only tuple/read counters: %+v/%v/%v", e, out.Err, err)
	sideWantReleased(t, w.owner, "denied native")
	generationRaw(t, w, generationEncoded(t, a), rows)
}

func detachedReadFailure(t *testing.T, name string) {
	for _, canonical := range []bool{false, true} {
		if (name == "R11" || name == "R12") && !canonical {
			continue
		}
		t.Run(fmt.Sprintf("canonical%t", canonical), func(t *testing.T) {
			a, rows := detachedFixture(t, 2)
			hash := a.DetachedSuffix.Entries[0].Hash
			if canonical {
				key, _ := mdbx.HeightKey(1, 19)
				inverse, _ := mdbx.CanonicalOwnerKey(1, hash)
				rows = append(rows, generationRow(2, key, mdbx.ChainValue(hash, a.DetachedSuffix.Entries[1].Hash, sideWorldWork(1))), generationRow(7, inverse, mdbx.CanonicalOwnerValue(19)))
			}
			if name == "R13" {
				rows = append(slices.Clone(rows[:5]), rows[6:]...)
			}
			if name == "R14a" && !canonical || name == "R12" || name == "R11" {
				rows[4].Literal = make([]byte, 116)
			}
			if name == "R14a" && canonical {
				// The canonical header is healthy, but the descriptor's next
				// parent identity is damaged. Required body presence still wins.
				a.DetachedSuffix.Entries[1].Hash = [32]byte{0x99}
			}
			if name == "R18a" {
				a.Cleanup.Spans = []mdbx.CleanupSpanV1{{Kind: 4, GenerationID: 3, FirstHeight: 7, LastHeight: 7, NextHeight: 7}}
			}
			w := generationNew(t, a, rows...)
			if name == "R11" {
				rows[len(rows)-2].Literal = mdbx.ChainValue([32]byte{0x99}, [32]byte{}, sideWorldWork(1))
				logicalMDBXAssert(t, mdbx.FixtureSeedRawRow(w.s, 2, rows[len(rows)-2].Key, rows[len(rows)-2].Literal) == nil, "seed actual-k canonical inconsistency")
			}
			rank, key, scenario := uint8(3), hash[:], mdbx.SelectedDamageScenario(4)
			if name == "R14" || name == "R14a" {
				rank = 4
			}
			if name == "R11" || name == "R12" || name == "R18a" {
				scenario = 1
			}
			var out selectedSideOutcome
			e, err := mdbx.FixtureSelectedDamage(w.s, w.owner, scenario, rank, key, func() { out = detachedRun(t, w) })
			result := "LOCAL_RESOURCE_UNAVAILABLE(branch_data)"
			if canonical {
				result = "LOCAL_RESOURCE_UNAVAILABLE(canonical_artifact_read)"
			}
			if scenario == 1 {
				result = "TERMINAL_STORE_INTEGRITY(canonical)"
			}
			sideWantOutcome(t, out, result, "OLD", 1, 1, name)
			logicalMDBXAssert(t, err == nil && e.BeginWrite == 0 && e.Deletes == 0, "prewrite exact preserved image: %+v/%v", e, err)
			if scenario == 4 {
				generationEngine(t, out.Err, "IO", "get", 5, "")
				engine, direct := out.Err.(*mdbx.EngineError)
				logicalMDBXAssert(t, direct && engine.Cause == nil && !engine.ReopenRequired, "direct first native cause/reopen bits changed")
				logicalMDBXAssert(t, e.Faults == 1 && sideCauses(out.Err) == "get:IO", "first native read cause: %v/%+v", out.Err, e)
			} else if name != "R12" {
				generationEngine(t, out.Err, "Integrity", "get", -30793, "")
			}
			if name == "R12" || name == "R13" || name == "R11" {
				logicalMDBXAssert(t, e.OldGets[4] == 0, "later body health ran after first header/canonical defect")
			}
			if name != "R12" {
				cached := DrainDetachedMDBX(w.s, w.owner)
				sideWantOutcome(t, cached, "", "", 1, 1, name+" cached")
				logicalMDBXAssert(t, any(cached.Err) == any(out.Err), "cached first error identity changed")
			} else {
				again := detachedRun(t, w)
				sideWantOutcome(t, again, "TERMINAL_STORE_INTEGRITY(canonical)", "OLD", 1, 1, "callback-only defect leaves owner usable")
			}
			sideWantReleased(t, w.owner, name)
			if name == "R13" {
				rows = append(rows, generationRow(4, hash[:], nil))
			}
			generationRaw(t, w, generationEncoded(t, a), rows)
		})
	}
}

func detachedExactPromises(t *testing.T) {
	for _, kind := range []uint8{2, 3} {
		for _, denied := range []bool{false, true} {
			t.Run(fmt.Sprintf("kind%d-denied%t", kind, denied), func(t *testing.T) {
				a, rows := detachedFixture(t, 2)
				a.B, a.U = 10, 13690
				last := uint64(8)
				if kind == 3 {
					last = 13688
				}
				a.Cleanup.Spans = []mdbx.CleanupSpanV1{{Kind: mdbx.CleanupSpanKindV1(kind), GenerationID: 1, LastHeight: last}}
				w := generationNew(t, a, rows...)
				var out selectedSideOutcome
				_, err := mdbx.FixtureSelectedDamage(w.s, w.owner, 1, 0, nil, func() {
					if denied {
						_ = w.owner.WithReservation(1, func() error { out = DrainDetachedMDBX(w.s, w.owner); return nil })
					} else {
						out = detachedRun(t, w)
					}
				})
				sideWantOutcome(t, out, "TERMINAL_STORE_INTEGRITY(canonical)", "OLD", 1, 1, "exact B/U promise")
				generationEngine(t, out.Err, "Integrity", "get", -30793, "invalid storage authority")
				logicalMDBXAssert(t, err == nil, "exact promise fixture: %v", err)
				sideWantReleased(t, w.owner, "exact promises")
				generationRaw(t, w, generationEncoded(t, a), rows)
			})
		}
	}
}

func detachedOpenRefusal(t *testing.T) {
	a, rows := detachedFixture(t, 2)
	w := generationNew(t, a, rows...)
	logicalMDBXAssert(t, w.s.Close() == nil, "close actual pre-state")
	var err error
	w.s, err = mdbx.Open(w.path, w.cfg)
	logicalMDBXAssert(t, err == nil, "same path/config unverified Open: %v", err)
	out := detachedRun(t, w)
	sideWantOutcome(t, out, "", "OLD", 1, 1, "unverified Open precondition")
	generationEngine(t, out.Err, "InvalidInput", "get", 22, "canonical owner index is not verified")
	w.image(a, rows...)
	// No latch: the same actual handle still supports a control-only sibling.
	logicalMDBXAssert(t, w.s.View(func(r *mdbx.Reader) error { _, err := r.ReadStorageAuthorityV1(); return err }) == nil, "unverified lookup disarmed store")
}

func detachedNativeMatrix(t *testing.T, damaged bool, filter string) {
	for _, row := range []struct {
		name                  string
		scenario              mdbx.SelectedDamageScenario
		truth                 mdbx.CommitTruth
		stage                 mdbx.UpdateStage
		result, causes, image string
	}{
		{"clean", 1, 2, 3, "", "-", "new"},
		{"begin-full", 2, 1, 1, "", "update:Transaction", "old"},
		{"begin-IO", 3, 1, 1, "", "update:IO", "old"},
		{"authority-IO", 4, 1, 1, "LOCAL_RESOURCE_UNAVAILABLE(storage_io)", "get:IO", "old"},
		{"reader-abort", 5, 1, 1, "LOCAL_RESOURCE_UNAVAILABLE(storage_io)", "get:IO,abort:IO", "old"},
		{"delete-IO", 6, 1, 2, "LOCAL_PERSISTENCE_ERROR(precommit)", "update:IO", "old"},
		{"commit-OLD", 7, 1, 3, "TERMINAL_PERSISTENCE(old)", "update:Capacity", "old"},
		{"commit-NEW", 8, 2, 3, "TERMINAL_PERSISTENCE(new)", "update:Capacity", "new"},
		{"R16c", 9, 3, 3, "TERMINAL_PERSISTENCE(neither_or_unreadable)", "update:Capacity,update:IO", "new"},
		{"commit-third", 10, 3, 3, "TERMINAL_PERSISTENCE(neither_or_unreadable)", "update:Capacity", "third"},
		{"put-IO", 12, 1, 2, "LOCAL_PERSISTENCE_ERROR(precommit)", "update:IO", "old"},
	} {
		crossed := row.scenario >= 7 && row.scenario <= 10
		if filter == "crossed" && !crossed || filter == "uncrossed" && crossed || filter == "clean" && row.scenario != 1 {
			continue
		}
		t.Run(row.name, func(t *testing.T) {
			a, rows := detachedFixture(t, 2)
			if damaged {
				rows[4].Literal = make([]byte, 116)
			}
			w := generationNew(t, a, rows...)
			var out selectedSideOutcome
			calls := 0
			e, err := mdbx.FixtureSelectedDamage(w.s, w.owner, row.scenario, 0, []byte{2}, func() {
				calls++
				out = DrainDetachedMDBX(w.s, w.owner)
			})
			result, canonical := row.result, "OLD"
			switch row.truth {
			case 2:
				canonical = "NEW"
			case 3:
				canonical = "UNKNOWN"
			}
			if damaged && row.scenario == 1 {
				result, canonical = "LOCAL_STORE_ERROR(noncanonical)", "NOT_APPLICABLE"
			}
			if row.scenario == 2 || row.scenario == 3 {
				canonical = ""
			}
			sideWantOutcome(t, out, result, canonical, row.truth, row.stage, row.name)
			logicalMDBXAssert(t, sideCauses(out.Err) == row.causes && calls == 1 && err == nil && e.ProbeRan == 0 && e.ProbeDenied == e.Probes, "raw cause/lane/native: %v/%+v/%v", out.Err, e, err)
			if row.scenario == 1 {
				logicalMDBXAssert(t, e.Probes == 4, "begin/commit/readback/OLD-abort grant: %+v", e)
			}
			if row.scenario >= 4 {
				logicalMDBXAssert(t, e.Probes > 0, "failure path did not prove full lane: %+v", e)
			}
			if row.scenario >= 7 && row.scenario <= 10 {
				commit, direct := out.Err.(*mdbx.CommitError)
				logicalMDBXAssert(t, direct && commit.Truth == row.truth, "crossed direct CommitError: %v", out.Err)
			}
			sideWantReleased(t, w.owner, row.name)
			if row.scenario != 1 {
				cached := DrainDetachedMDBX(w.s, w.owner)
				sideWantOutcome(t, cached, "", "", row.truth, 1, row.name+" cached")
				logicalMDBXAssert(t, any(cached.Err) == any(out.Err), "cached raw identity changed")
				sideWantReleased(t, w.owner, "cached")
			}
			want, authority := rows, generationEncoded(t, a)
			if row.image != "old" {
				want, authority = detachedGone(rows), generationEncoded(t, detachedAfter(a, 1, 266))
			}
			if row.image == "third" {
				authority = []byte{0x7f}
			}
			generationRaw(t, w, authority, want)
		})
	}
}

func detachedInvalidStage(t *testing.T) {
	a, rows := detachedFixture(t, 2)
	w := generationNew(t, a, rows...)
	cleanup := errors.New("cleanup")
	truth, stage, raw := mdbx.FixtureCleanupInvalidStage0(w.s, cleanup)
	for _, positive := range []bool{false, true} {
		p := &detachedDrainPlan{cleanupGenerationPlan: cleanupGenerationPlan{positive: positive}}
		out := p.project(selectedSideOutcome{Truth: truth, Stage: stage, Err: raw})
		sideWantOutcome(t, out, "TERMINAL_LOCAL_INVARIANT(evidence)", "OLD", 1, 0, "actual invalid-stage projection")
		logicalMDBXAssert(t, any(out.Err) == any(raw), "invalid-stage raw error identity changed")
	}
	cached := DrainDetachedMDBX(w.s, w.owner)
	sideWantOutcome(t, cached, "", "", 1, 1, "actual consumed invalid-stage owner")
	logicalMDBXAssert(t, any(cached.Err) == any(raw), "invalid-stage cached error changed")
	sideWantReleased(t, w.owner, "invalid-stage")
	generationRaw(t, w, generationEncoded(t, a), rows)
}

func detachedGrantLifetimes(t *testing.T) {
	detachedNativeMatrix(t, false, "clean")
	for _, route := range generationRouteAuthorities() {
		if route.name == "descriptor" {
			continue
		}
		t.Run("no-work-"+route.name, func(t *testing.T) {
			w := generationNew(t, route.a, generationData(2, 1)...)
			var out selectedSideOutcome
			e, err := mdbx.FixtureSelectedDamage(w.s, w.owner, 1, 0, nil, func() { out = DrainDetachedMDBX(w.s, w.owner) })
			generationClean(t, out, 1)
			logicalMDBXAssert(t, err == nil && e.Probes > 0 && e.ProbeRan == 0 && e.ProbeDenied == e.Probes && e.OldGets == ([8]uint64{1}), "no-work full lane/control only: %+v/%v", e, err)
			sideWantReleased(t, w.owner, route.name)
			generationRaw(t, w, generationEncoded(t, route.a), w.rows)
		})
	}
}

func detachedAbortRefusal(t *testing.T) {
	for _, defect := range []bool{false, true} {
		t.Run(fmt.Sprint(defect), func(t *testing.T) {
			a := generationAuthority()
			if defect {
				a.Cleanup.Spans = append(a.Cleanup.Spans, mdbx.CleanupSpanV1{Kind: 4, GenerationID: 3, FirstHeight: 1, LastHeight: 1441, NextHeight: 1})
			}
			w := generationNew(t, a, generationData(2, 1)...)
			var out selectedSideOutcome
			e, err := mdbx.FixtureSelectedDamage(w.s, w.owner, 11, 0, nil, func() { out = DrainDetachedMDBX(w.s, w.owner) })
			result := "LOCAL_RESOURCE_UNAVAILABLE(storage_io)"
			if defect {
				result = "TERMINAL_STORE_INTEGRITY(canonical)"
			}
			sideWantOutcome(t, out, result, "OLD", 1, 1, "callback refusal plus abort")
			logicalMDBXAssert(t, err == nil && sideCauses(out.Err) == "-,abort:IO" && e.BeginWrite == 0, "joined callback refusal: %+v/%v", out, err)
			sideWantReleased(t, w.owner, "abort refusal")
			generationRaw(t, w, generationEncoded(t, a), w.rows)
		})
	}
}

func detachedOwnerAuthority(t *testing.T, name string) {
	for _, variant := range map[string][]string{"H1": {"active-SIDE"}, "H2": {"overlap"}, "H3": {"active", "selected", "replay"}, "H4": {"duplicate-SIDE", "out-of-order"}}[name] {
		t.Run(variant, func(t *testing.T) {
			a, rows := detachedFixture(t, 2)
			if variant == "replay" {
				invalid := generationRouteAuthorities()[7].a
				invalid.Cleanup = &mdbx.CleanupV1{Spans: []mdbx.CleanupSpanV1{{Kind: 1, GenerationID: invalid.Replay.TargetGenerationID}}}
				_, err := invalid.Encode()
				logicalMDBXAssert(t, err != nil, "unrepresentable Replay+Cleanup encoded")
				return
			}
			if variant == "overlap" {
				a.DetachedSuffix = nil
				a.SelectedSide = &mdbx.SelectedSideV1{GenerationID: 3, TipHeight: 1440, TipHash: [32]byte{9}, CumulativeChainwork: sideWorldWork(1), RowCount: 1439, LogicalBytes: 1439}
			}
			if variant != "active" && variant != "selected" {
				a.Cleanup.Spans = []mdbx.CleanupSpanV1{{Kind: 4, GenerationID: 3, FirstHeight: 1, LastHeight: 1, NextHeight: 1}}
			}
			if variant == "selected" {
				a.DetachedSuffix = nil
				a.SelectedSide = &mdbx.SelectedSideV1{GenerationID: 3, TipHeight: 1, TipHash: [32]byte{9}, CumulativeChainwork: sideWorldWork(1), RowCount: 1, LogicalBytes: 266}
			}
			bad := generationEncoded(t, a)
			switch variant {
			case "active", "active-SIDE":
				binary.BigEndian.PutUint64(bad[38:46], 1)
			case "selected":
				binary.BigEndian.PutUint64(bad[38:46], 3)
			case "overlap":
				for _, offset := range []int{46, 54, 62} {
					binary.BigEndian.PutUint64(bad[offset:offset+8], 2)
				}
			case "duplicate-SIDE":
				bad[36] = 2
				bad = append(append(bytes.Clone(bad[:70]), bad[37:70]...), bad[70:]...)
			case "out-of-order":
				bad[36] = 2
				bad = append(append(bytes.Clone(bad[:70]), byte(1)), append(make([]byte, 7), append([]byte{2}, bad[70:]...)...)...)
			}
			_, decodeErr := mdbx.DecodeStorageAuthorityV1(bad)
			logicalMDBXAssert(t, decodeErr != nil, "illegal owner shape admitted: %s", variant)
			w := generationNew(t, a, rows...)
			logicalMDBXAssert(t, mdbx.FixtureSeedRawRow(w.s, 0, []byte{2}, bad) == nil, "seed owner shape")
			var out selectedSideOutcome
			e, err := mdbx.FixtureSelectedDamage(w.s, w.owner, 1, 0, nil, func() { out = detachedRun(t, w) })
			sideWantOutcome(t, out, "TERMINAL_STORE_INTEGRITY(canonical)", "OLD", 1, 1, variant)
			generationEngine(t, out.Err, "Integrity", "get", -30793, "invalid storage authority")
			logicalMDBXAssert(t, err == nil && e.OldGets == ([8]uint64{1}) && e.BeginWrite == 0, "owner shape before data: %+v/%v", e, err)
			generationRaw(t, w, bad, rows)
		})
	}
}

func detachedIgnoredReader(t *testing.T) {
	a, rows := detachedFixture(t, 2)
	w := generationNew(t, a, rows...)
	var raw, recorded error
	_, err := mdbx.FixtureSelectedDamage(w.s, w.owner, 4, 0, []byte{2}, func() {
		_ = w.owner.WithReservation(154611151, func() error {
			truth, stage, result := w.s.Update(func(r *mdbx.Reader) (mdbx.Batch, error) {
				_, _, recorded = r.Get(logicalMDBXDBIs[0], []byte{2})
				return mdbx.Batch{Mutations: []mdbx.Mutation{{DBI: logicalMDBXDBIs[0], Key: []byte{2}, BeforePresent: true, AfterKind: 1}}}, nil
			})
			raw = result
			logicalMDBXAssert(t, truth == 1 && stage == 1 && any(raw) == any(recorded), "ignored first Reader failure tuple")
			return nil
		})
	})
	logicalMDBXAssert(t, err == nil, "ignored Reader fixture: %v", err)
	cached := detachedRun(t, w)
	sideWantOutcome(t, cached, "", "", 1, 1, "ignored Reader cached")
	logicalMDBXAssert(t, any(cached.Err) == any(recorded), "cached first Reader failure replaced")
	generationRaw(t, w, generationEncoded(t, a), rows)
}

func detachedReadbackBody(t *testing.T) {
	for _, keep := range []bool{false, true} {
		t.Run(fmt.Sprint(keep), func(t *testing.T) {
			a, rows := detachedFixture(t, 2)
			hash := a.DetachedSuffix.Entries[0].Hash
			if keep {
				a.Cleanup.Spans = []mdbx.CleanupSpanV1{{Kind: 4, GenerationID: 3, FirstHeight: 7, LastHeight: 7, NextHeight: 7}}
				key, _ := mdbx.HeightKey(3, 7)
				rows = append(rows, generationRow(6, key, mdbx.ChainValue(hash, [32]byte{}, sideWorldWork(1))))
			}
			w := generationNew(t, a, rows...)
			var out selectedSideOutcome
			calls := 0
			drift, err := mdbx.FixtureCleanupReadbackDrift(w.s, 4, hash[:], func() {
				calls++
				out = DrainDetachedMDBX(w.s, w.owner)
			})
			sideWantOutcome(t, out, "TERMINAL_PERSISTENCE(neither_or_unreadable)", "UNKNOWN", 3, 3, "detached body complete image")
			logicalMDBXAssert(t, err == nil && drift == 1 && calls == 1 && sideCauses(out.Err) == "update:Capacity", "physical body image omission: %v/%d/%v", out.Err, drift, err)
			sideWantReleased(t, w.owner, "body readback")
			// The fixture's third body is deliberately neither image; metadata
			// and every other row still equal the exact new plan after real Open.
			want := slices.Clone(rows)
			want[4].Literal = nil
			want[5].Literal = []byte{0x7f}
			generationRaw(t, w, generationEncoded(t, detachedAfter(a, 1, 266)), want)
		})
	}
}

func detachedSideIdentity(t *testing.T) {
	for _, variant := range []string{"absent", "width", "work", "transient"} {
		t.Run(variant, func(t *testing.T) {
			a, rows := detachedFixture(t, 2)
			a.Cleanup.Spans = []mdbx.CleanupSpanV1{{Kind: 4, GenerationID: 3, FirstHeight: 7, LastHeight: 7, NextHeight: 7}}
			hash := a.DetachedSuffix.Entries[0].Hash
			key, _ := mdbx.HeightKey(3, 7)
			value := mdbx.ChainValue(hash, [32]byte{}, sideWorldWork(1))
			if variant != "absent" {
				rows = append(rows, generationRow(6, key, value))
			}
			w := generationNew(t, a, rows...)
			if variant == "width" || variant == "work" {
				value = make([]byte, 104)
				if variant == "width" {
					value = []byte{1}
				}
				logicalMDBXAssert(t, mdbx.FixtureSeedRawRow(w.s, 6, key, value) == nil, "seed SideLink identity")
				rows[len(rows)-1].Literal = value
			}
			scenario, result := mdbx.SelectedDamageScenario(1), "TERMINAL_STORE_INTEGRITY(canonical)"
			if variant == "transient" {
				scenario, result = 4, "LOCAL_RESOURCE_UNAVAILABLE(branch_data)"
			}
			var out selectedSideOutcome
			e, err := mdbx.FixtureSelectedDamage(w.s, w.owner, scenario, 6, key, func() { out = detachedRun(t, w) })
			sideWantOutcome(t, out, result, "OLD", 1, 1, variant)
			class, code := "Integrity", -30793
			if variant == "transient" {
				class, code = "IO", 5
			}
			generationEngine(t, out.Err, class, "get", code, "")
			logicalMDBXAssert(t, err == nil && e.BeginWrite == 0 && e.OldGets[3]+e.OldGets[4] == 0, "unknown SIDE identity reached health/mutation: %+v/%v", e, err)
			if variant == "absent" {
				rows = append(rows, generationRow(6, key, nil))
			}
			generationRaw(t, w, generationEncoded(t, a), rows)
		})
	}
}

func detachedLowestParentFailure(t *testing.T) {
	for _, variant := range []string{"absent", "work", "transient"} {
		t.Run(variant, func(t *testing.T) {
			a, rows := detachedFixture(t, 1)
			parent, inverse := rows[0], rows[1]
			if variant == "absent" {
				rows = slices.Clone(rows[2:])
			}
			w := generationNew(t, a, rows...)
			if variant == "work" {
				rows[0].Literal = mdbx.ChainValue([32]byte{0xf0}, [32]byte{}, [40]byte{})
				logicalMDBXAssert(t, mdbx.FixtureSeedRawRow(w.s, 2, parent.Key, rows[0].Literal) == nil, "seed canonical parent identity")
			}
			scenario, result := mdbx.SelectedDamageScenario(1), "TERMINAL_STORE_INTEGRITY(canonical)"
			if variant == "transient" {
				scenario, result = 4, "LOCAL_RESOURCE_UNAVAILABLE(canonical_artifact_read)"
			}
			var out selectedSideOutcome
			e, err := mdbx.FixtureSelectedDamage(w.s, w.owner, scenario, 2, parent.Key, func() { out = detachedRun(t, w) })
			sideWantOutcome(t, out, result, "OLD", 1, 1, variant)
			logicalMDBXAssert(t, err == nil && e.BeginWrite == 0 && e.OldGets[3]+e.OldGets[4] == 0, "lowest parent failure reached artifacts: %+v/%v", e, err)
			if variant == "absent" {
				rows = append(rows, generationRow(2, parent.Key, nil), generationRow(7, inverse.Key, nil))
			}
			generationRaw(t, w, generationEncoded(t, a), rows)
		})
	}
}

func detachedReadbackOwners(t *testing.T) {
	for _, kind := range []string{"no-owner", "canonical", "header", "SIDE"} {
		t.Run(kind, func(t *testing.T) {
			a, rows := detachedFixture(t, 2)
			hash := a.DetachedSuffix.Entries[0].Hash
			rank := uint8(7)
			key, _ := mdbx.CanonicalOwnerKey(1, hash)
			if kind == "canonical" || kind == "header" {
				forward, _ := mdbx.HeightKey(1, 19)
				rows = append(rows, generationRow(2, forward, mdbx.ChainValue(hash, a.DetachedSuffix.Entries[1].Hash, sideWorldWork(1))), generationRow(7, key, mdbx.CanonicalOwnerValue(19)))
				if kind == "header" {
					rank, key = 3, hash[:]
				}
			}
			if kind == "SIDE" {
				a.Cleanup.Spans = []mdbx.CleanupSpanV1{{Kind: 4, GenerationID: 3, FirstHeight: 7, LastHeight: 7, NextHeight: 7}}
				rank, key = 6, logicalMDBXMust(mdbx.HeightKey(3, 7))
				rows = append(rows, generationRow(6, key, mdbx.ChainValue(hash, [32]byte{}, sideWorldWork(1))))
			}
			w := generationNew(t, a, rows...)
			var out selectedSideOutcome
			e, err := mdbx.FixtureSelectedDamage(w.s, w.owner, 9, rank, key, func() { out = DrainDetachedMDBX(w.s, w.owner) })
			sideWantOutcome(t, out, "TERMINAL_PERSISTENCE(neither_or_unreadable)", "UNKNOWN", 3, 3, "complete owner readback")
			logicalMDBXAssert(t, err == nil && e.ReadGets > 0 && e.Faults == 1 && sideCauses(out.Err) == "update:Capacity,update:IO", "queried owner omitted from readback: %+v/%v", e, err)
			sideWantReleased(t, w.owner, kind)
			want := slices.Clone(rows)
			if kind == "no-owner" {
				want[4].Literal, want[5].Literal = nil, nil
				want = append(want, generationRow(7, key, nil))
			}
			if kind == "SIDE" {
				want[4].Literal = nil
			}
			generationRaw(t, w, generationEncoded(t, detachedAfter(a, 1, 266)), want)
		})
	}
}

func detachedRequiredBodyDamage(t *testing.T) {
	for _, variant := range []string{"absent", "parent-absent", "width", "length", "prefix", "commitment"} {
		t.Run(variant, func(t *testing.T) {
			a, rows := detachedFixture(t, 2)
			hash := a.DetachedSuffix.Entries[0].Hash
			forward, _ := mdbx.HeightKey(1, 19)
			inverse, _ := mdbx.CanonicalOwnerKey(1, hash)
			rows = append(rows, generationRow(2, forward, mdbx.ChainValue(hash, a.DetachedSuffix.Entries[1].Hash, sideWorldWork(1))), generationRow(7, inverse, mdbx.CanonicalOwnerValue(19)))
			if variant == "parent-absent" {
				a.DetachedSuffix.Entries[1].Hash = [32]byte{0x99}
			}
			missing := variant == "absent" || variant == "parent-absent"
			value := bytes.Clone(rows[5].Literal)
			switch variant {
			case "absent", "parent-absent":
				rows = append(slices.Clone(rows[:5]), rows[6:]...)
			case "prefix":
				value[108] ^= 1
			case "length", "commitment":
				value = append(value, 0)
				if variant == "commitment" {
					a.DetachedSuffix.Entries[0].BlockBytesLen, a.DetachedSuffix.LogicalBytes = 267, 533
				}
			}
			if !missing && variant != "width" {
				rows[5].Literal = value
			}
			w := generationNew(t, a, rows...)
			if variant == "width" {
				rows[5].Literal = []byte{1}
				logicalMDBXAssert(t, mdbx.FixtureSeedRawRow(w.s, 4, hash[:], rows[5].Literal) == nil, "seed required body width")
			}
			var out selectedSideOutcome
			e, err := mdbx.FixtureSelectedDamage(w.s, w.owner, 1, 0, nil, func() { out = detachedRun(t, w) })
			sideWantOutcome(t, out, "TERMINAL_STORE_INTEGRITY(canonical)", "OLD", 1, 1, "canonical required body damage")
			logicalMDBXAssert(t, out.Err != nil && out.Err.Error() == "TERMINAL_STORE_INTEGRITY(canonical): invalid cleanup canonical body" && err == nil && e.BeginWrite == 0 && e.OldGets[4] == 1, "required body defect lost priority/image: %v/%+v/%v", out.Err, e, err)
			logicalMDBXAssert(t, e.Deletes == 0 && e.Commits == 0, "required body refusal wrote native data: %+v", e)
			if missing {
				rows = append(rows, generationRow(4, hash[:], nil))
			}
			w.image(a, rows...)
			again := detachedRun(t, w)
			sideWantOutcome(t, again, "TERMINAL_STORE_INTEGRITY(canonical)", "OLD", 1, 1, "required body refusal leaves owner usable")
			logicalMDBXAssert(t, again.Err != nil && again.Err.Error() == "TERMINAL_STORE_INTEGRITY(canonical): invalid cleanup canonical body", "same-instance body refusal lost cause: %v", again.Err)
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
			a, _, rows := generationBaseProjection()
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
	w := generationNew(t, a, rows...)
	logicalMDBXAssert(t, mdbx.FixtureSeedRawRow(w.s, 7, derived.Key, derived.Literal) == nil, "seed orphan derived row")
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
	kinds := []string{"none", "canonical", "selected", "defer"}
	if rank == 3 {
		kinds = append(kinds, "selected-parent", "selected-parent-repeat", "canonical-parent", "canonical-parent-priority")
	}
	for _, kind := range kinds {
		t.Run(kind, func(t *testing.T) {
			a, hash, rows := generationBaseProjection()
			canonicalParent := kind == "canonical-parent" || kind == "canonical-parent-priority"
			if kind == "canonical" || canonicalParent || kind == "defer" && rank == 5 {
				k := uint64(11)
				a.B, a.U = 10, 13690
				if kind == "canonical" && rank == 5 {
					k = 13691
				}
				if canonicalParent {
					k = 8 // Canonical header keep alone leaves selected body membership necessary.
				}
				rows = append(rows, generationCanonical(hash, k)...)
				if kind == "canonical-parent-priority" {
					rows[5].Literal = mdbx.ChainValue(hash, [32]byte{1}, sideWorldWork(1))
				}
			}
			parentDamage := kind == "selected-parent" || kind == "selected-parent-repeat" || canonicalParent
			if kind == "selected" || parentDamage {
				rows = append(rows, generationSelected(&a, hash, rows[3].Literal)...)
			}
			if parentDamage {
				rows[len(rows)-1].Literal = mdbx.ChainValue(hash, [32]byte{1}, sideWorldWork(1))
				if kind == "selected-parent-repeat" {
					a.SelectedSide.TipHeight, a.SelectedSide.RowCount = 7, 2
					a.SelectedSide.CumulativeChainwork, a.SelectedSide.LogicalBytes = sideWorldWork(2), 2*uint64(len(rows[3].Literal))
					key, _ := mdbx.HeightKey(3, 7)
					rows = append(rows, generationRow(6, key, mdbx.ChainValue(hash, [32]byte{}, sideWorldWork(2))))
				}
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
				if !parentDamage {
					bad[115] ^= 1
				}
			}
			logicalMDBXAssert(t, mdbx.FixtureSeedRawRow(w.s, rank, key, bad) == nil, "seed damage")
			rows[index].Literal = bad
			out := w.run(2, 1)
			expected := a
			want := slices.Clone(rows)
			switch kind {
			case "canonical", "canonical-parent-priority":
				sideWantOutcome(t, out, "TERMINAL_STORE_INTEGRITY(canonical)", "OLD", 1, 1, kind)
				logicalMDBXAssert(t, out.Err != nil, "canonical damage accepted")
				if kind == "canonical-parent-priority" {
					logicalMDBXAssert(t, out.Err.Error() == "TERMINAL_STORE_INTEGRITY(canonical): invalid cleanup canonical header", "canonical parent priority: %v", out.Err)
				}
			case "selected", "selected-parent", "selected-parent-repeat", "canonical-parent":
				if rank == 5 {
					generationClean(t, out, 2)
					expected.Cleanup, expected.Phase = nil, 1
					want[0].Literal, want[1].Literal, want[4].Literal = nil, nil, nil
				} else {
					sideWantOutcome(t, out, "LOCAL_STORE_ERROR(noncanonical)", "NOT_APPLICABLE", 2, 3, kind)
					logicalMDBXAssert(t, out.Err == nil, "complete clear failed: %v", out.Err)
					expected.SelectedSide = nil
					expected.Cleanup = &mdbx.CleanupV1{Spans: []mdbx.CleanupSpanV1{{Kind: 1, GenerationID: 2}, {Kind: 4, GenerationID: 3, FirstHeight: 6, LastHeight: a.SelectedSide.TipHeight, NextHeight: 6}}}
					if kind != "canonical-parent" {
						want[2].Literal = nil
					}
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
						want[2].Literal, want[4].Literal = nil, nil
					}
					if kind != "defer" {
						want[3].Literal = nil
					}
				}
			}
			generationRaw(t, w, generationEncoded(t, expected), want)
		})
	}
}

func generationNativeFaults(t *testing.T) {
	t.Run("invalid-stage", func(t *testing.T) {
		w := generationNew(t, generationAuthority(), generationData(2, 1)...)
		cleanup := errors.New("cleanup")
		truth, stage, raw := mdbx.FixtureCleanupInvalidStage0(w.s, cleanup)
		for _, positive := range []bool{false, true} {
			out := (&cleanupGenerationPlan{positive: positive}).project(selectedSideOutcome{Truth: truth, Stage: stage, Err: raw})
			sideWantOutcome(t, out, "TERMINAL_LOCAL_INVARIANT(evidence)", "OLD", 1, 0, fmt.Sprint(positive))
			logicalMDBXAssert(t, any(out.Err) == any(raw), "invalid-stage projected error changed")
		}
		cached := CleanupGenerationMDBX(w.s, w.owner, 1, 1)
		sideWantOutcome(t, cached, "", "", 1, 1, "invalid-stage cached public call")
		logicalMDBXAssert(t, any(cached.Err) == any(raw), "invalid-stage cached error changed")
		sideWantReleased(t, w.owner, "invalid-stage")
		reopened, err := mdbx.Open(w.path, w.cfg)
		logicalMDBXAssert(t, err == nil, "consumed owner retained resources: %v", err)
		defer func() { _ = reopened.Close() }()
		for _, row := range append(slices.Clone(w.rows), generationRow(0, []byte{2}, generationEncoded(t, w.a))) {
			equal, readErr := mdbx.FixtureRawRowEqual(reopened, row.DBI.Rank, row.Key, row.Literal)
			logicalMDBXAssert(t, equal && readErr == nil, "invalid-stage OLD raw image: %v", readErr)
		}
	})
	generationNativeMatrix(t, false, func(w *generationWorld) selectedSideOutcome { return CleanupGenerationMDBX(w.s, w.owner, 1, 1) })
	for _, rank := range []uint8{6, 7} {
		t.Run(fmt.Sprintf("consulted%d", rank), func(t *testing.T) {
			a, hash, rows := generationBaseProjection()
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

func generationNativeMatrix(t *testing.T, reservation bool, invoke func(*generationWorld) selectedSideOutcome) {
	for _, row := range []struct {
		name                  string
		scenario              mdbx.SelectedDamageScenario
		truth                 mdbx.CommitTruth
		stage                 mdbx.UpdateStage
		result, causes, image string
	}{
		{"no-work", 1, 1, 1, "", "-", "old"},
		{"work", 1, 2, 3, "", "-", "new"},
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
			if row.scenario != 1 {
				cached := invoke(w)
				sideWantOutcome(t, cached, "", "", row.truth, 1, row.name+" cached no-callback")
				logicalMDBXAssert(t, any(cached.Err) == any(out.Err), "cached original native error changed: %v/%v", cached.Err, out.Err)
				sideWantReleased(t, w.owner, row.name+" cached")
			}
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
			a, hash, rows := generationBaseProjection()
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
		a, blockHash, rows := generationBaseProjection()
		a.B, a.U = 10, 13690
		hash = blockHash
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
		// Only the obsolete parent differs; active header/body, canonical proof and deferred identity remain valid.
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
	generationCrossed(t, out, "update:Capacity", true)
	value := reflect.ValueOf(w.s).Elem()
	logicalMDBXAssert(t, value.FieldByName("state").String() == "CLOSED" && value.FieldByName("env").IsNil() && value.FieldByName("writer").IsNil() && value.FieldByName("txn").IsNil() && value.FieldByName("terminalTruth").Uint() == 3, "consumed Store must be CLOSED/envnil/writernil/txnnil/UNKNOWN")
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
			a, hash, rows := generationBaseProjection()
			a.B, a.U = 10, 13690
			rows = append(rows, generationCanonical(hash, 13691)...)
			height, txs, spent := uint64(13691), uint32(3), uint32(1)
			txIndex := uint32(1)
			switch name {
			case "height":
				height--
			case "zero-tx":
				txs, spent = 0, 0
			case "tx-bound":
				txs = 1545455
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
			baseCount := len(rows)
			value, _ := (mdbx.UTXOValue{Value: 1}).Encode()
			entry := mdbx.UndoEntryKey(hash, [32]byte{1}, txIndex, 0, 0)
			if name != "zero-tx" {
				rows = append(rows, generationRow(5, entry, value))
			}
			if name == "coordinate" || name == "outpoint" {
				other, input := [32]byte{2}, uint32(0)
				if name == "outpoint" {
					other, input = [32]byte{1}, 1
				}
				rows = append(rows, generationRow(5, mdbx.UndoEntryKey(hash, other, 1, input, 0), value))
			}
			var w *generationWorld
			var families [][]mdbx.Mutation
			if name == "spent-bound" {
				var family []mdbx.Mutation
				w, hash, family = generationFamily(t, "keep")
				var tx [32]byte
				binary.BigEndian.PutUint32(tx[28:], 414634)
				extra := generationRow(5, mdbx.UndoEntryKey(hash, tx, 405, 938, 0), family[1].Literal)
				generationSeedUndo(t, w, []mdbx.Mutation{extra})
				rows = w.rows
				rows[4].Literal = mdbx.UndoManifestValue(13691, [16]byte{}, 406, 414635)
				family[0].Literal = rows[4].Literal
				logicalMDBXAssert(t, mdbx.FixtureSeedRawRow(w.s, 5, rows[4].Key, rows[4].Literal) == nil, "semantic undo manifest seed")
				families = [][]mdbx.Mutation{append(family, extra)}
			} else {
				w = generationNew(t, a, rows[:baseCount]...)
				for _, row := range rows[baseCount:] {
					logicalMDBXAssert(t, mdbx.FixtureSeedRawRow(w.s, 5, row.Key, row.Literal) == nil, "semantic undo entry seed")
				}
			}
			if name == "missing-manifest" {
				logicalMDBXSeed(t, w.s, mdbx.Mutation{DBI: logicalMDBXDBIs[5], Key: rows[4].Key, BeforePresent: true, AfterKind: 1})
				rows[4].Literal = nil
			}
			w.image(a, rows...)
			if len(families) != 0 {
				generationFamilyImage(t, w.s, hash, families[0])
			}
			out := CleanupGenerationMDBX(w.s, w.owner, 2, 1)
			sideWantOutcome(t, out, "TERMINAL_STORE_INTEGRITY(canonical)", "OLD", 1, 1, name)
			logicalMDBXAssert(t, out.Err != nil && out.Err.Error() == "TERMINAL_STORE_INTEGRITY(canonical): invalid cleanup canonical undo", "complete family semantic refusal: %v", out.Err)
			sideWantReleased(t, w.owner, name)
			generationRaw(t, w, generationEncoded(t, a), rows, families...)
		})
	}
}

func generationSelectedCrossed(t *testing.T) {
	for _, scenario := range []mdbx.SelectedDamageScenario{7, 8, 9, 10} {
		t.Run(fmt.Sprint(scenario), func(t *testing.T) {
			a, hash, rows := generationBaseProjection()
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
			generationRaw(t, w, expected, rows)
		})
	}
}
