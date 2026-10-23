//go:build rubin_mdbx_fixture && cgo && (darwin || linux) && (amd64 || arm64)

package consensus

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"reflect"
	"runtime"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/mdbx"
)

func TestBlockTreeSourceFixtureV1(t *testing.T) {
	t.Run("stored-callback", btfStored)
	t.Run("callback-cleanup", btfCallbackCleanup)
	t.Run("source-primary", btfSourcePrimary)
	t.Run("section-cleanup", btfSectionCleanup)
	t.Run("late-original", btfLateOriginal)
	t.Run("commit-readback", btfReadback)
}

func btfRequest(salt byte) blockTreeRequestV1 {
	tx := btTransaction(uint64(salt), 0, nil, [][]byte{btFrame(uint64(salt), 0, []byte{salt})}, nil, []byte{0}, nil)
	return btRequest(btBody(148, salt, [32]byte{}, tx), 6)
}

func btfEngine(t *testing.T, err error, operation string, class mdbx.EngineClass, code int, diagnostic string) *mdbx.EngineError {
	t.Helper()
	engine, ok := err.(*mdbx.EngineError)
	logicalMDBXAssert(t, ok && engine.Operation == operation && engine.Class == class && engine.Code == code && engine.Diagnostic == diagnostic && engine.Cause == nil && !engine.ReopenRequired, "engine tuple: %T %+v", err, err)
	return engine
}

func btfCached(t *testing.T, w *btWorld, previous btResult) {
	t.Helper()
	called := 0
	err := w.owner.WithOperation(mdbx.TreeOperation, func(a *mdbx.OperationAccount) error {
		truth, stage, index, err := w.s.UpdateTreeV1(a, func(*mdbx.Reader) (mdbx.TreeOperationV1, error) { called++; return mdbx.TreeOperationV1{}, nil })
		logicalMDBXAssert(t, truth == previous.truth && stage == 1 && index == -1 && reflect.ValueOf(err) == reflect.ValueOf(previous.err) && called == 0, "cached operation: %d/%d/%d/%v calls%d", truth, stage, index, err, called)
		return nil
	})
	logicalMDBXAssert(t, err == nil, "cached account: %v", err)
	viewErr := w.s.View(func(*mdbx.Reader) error { called++; return nil })
	logicalMDBXAssert(t, reflect.ValueOf(viewErr) == reflect.ValueOf(previous.err) && called == 0, "cached View changed error or ran callback: %v/%d", viewErr, called)
}

func btfStored(t *testing.T) {
	for _, variant := range []string{"absent", "malformed", "IO", "IO-abort", "valid"} {
		t.Run(variant, func(t *testing.T) {
			w := btNew(t)
			r := btfRequest(7)
			if variant == "valid" {
				witness := []byte{1, 0x7f, 0}
				witness = append(witness, btCompact(99992)...)
				witness = append(witness, make([]byte, 99992)...)
				tx := btTransaction(7, 1, nil, [][]byte{btFrame(7, 0, bytes.Repeat([]byte{7}, 65536))}, bytes.Repeat([]byte{8}, 65536), witness, bytes.Repeat([]byte{9}, 65536))
				r = btRequest(btBody(148, 7, [32]byte{}, tx), 6)
			}
			if variant != "absent" {
				w.pair(t, btMutation(3, r.Block[:], r.Raw[:148]), btMutation(4, r.Block[:], r.Raw))
			}
			if variant == "malformed" {
				logicalMDBXAssert(t, mdbx.FixtureSeedRawRow(w.s, 4, r.Block[:], []byte{0x7f}) == nil, "stored malformed fixture")
			}
			stored := bytes.Clone(r.Raw)
			r.BodyKind, r.Raw = 2, nil
			var result btResult
			var effects []blockTreeEffectV1
			run := func() { result, effects, _ = w.run(t, []blockTreeRequestV1{r}, nil) }
			if variant == "IO" || variant == "IO-abort" {
				scenario := mdbx.SelectedDamageGetEIO
				if variant == "IO-abort" {
					scenario = mdbx.SelectedDamageGetAbortEIO
				}
				evidence, err := mdbx.FixtureSelectedDamage(w.s, w.owner, scenario, 4, r.Block[:], run)
				logicalMDBXAssert(t, err == nil && evidence.Faults != 0 && evidence.Commits == 0 && evidence.Deletes == 0, "stored IO site %+v/%v", evidence, err)
				result.want(t, 1, 1, -1)
				var engine *mdbx.EngineError
				logicalMDBXAssert(t, errors.As(result.err, &engine) && engine.Operation == "get" && engine.Class == "IO" && engine.Code == 5 && engine.Diagnostic == "error 5" && engine.TreeObservation == nil, "stored IO remapped: %+v", result.err)
				if variant == "IO" {
					logicalMDBXAssert(t, result.err == engine && engine.Cause == nil, "stored IO original object wrapped or reclassified: %T %v", result.err, result.err)
				}
				btfCached(t, w, result)
				return
			}
			run()
			if variant == "valid" {
				result.want(t, 2, 3, -1)
				logicalMDBXAssert(t, result.err == nil && reflect.ValueOf(effects[0].CurrentBody).IsZero(), "stored success: %v", result.err)
				logicalMDBXAssert(t, effects[0].Primitive.Coverage.BodyKind == 2 && effects[0].Primitive.Coverage.CurrentBody == nil && effects[0].Primitive.Source.(*blockTreeSourceV1).Raw == nil, "stored body payload shape")
				w.read(t, 4, r.Block[:], stored)
				return
			}
			result.want(t, 1, 1, -1)
			message := "required block tree source is absent"
			if variant == "malformed" {
				message = "required block tree source framing differs"
			}
			btFailure(t, result.err, logicalStateFailureStoreIntegrity, message)
			logicalMDBXAssert(t, reflect.ValueOf(effects[0]).IsZero(), "failed constructor published result")
			logicalMDBXAssert(t, w.s.View(func(*mdbx.Reader) error { return nil }) == nil, "clean callback error consumed Store")
			// Actual next native operation remains legal; application integrity latch
			// and quarantine are explicitly owned by the later composer.
			w.pair(t, btMutation(6, binary.BigEndian.AppendUint64(binary.BigEndian.AppendUint64(nil, 1), 99), make([]byte, 104)))
		})
	}
}

func btfCallbackCleanup(t *testing.T) {
	for _, mode := range []uint32{0, 9, 10} {
		for _, delivery := range []string{"error", "panic", "goexit"} {
			t.Run(fmt.Sprintf("%d/%s", mode, delivery), func(t *testing.T) {
				w := btNew(t)
				var result btResult
				var primary error
				var kept *mdbx.Reader
				panicValue := new(int)
				var recovered any
				post := false
				run := func() {
					defer func() { recovered = recover() }()
					state, _, fixtureErr := mdbx.FixtureStartupCleanup(w.s, mode, false, func() {
						_ = w.owner.WithOperation(mdbx.TreeOperation, func(a *mdbx.OperationAccount) error {
							result.truth, result.stage, result.index, result.err = w.s.UpdateTreeV1(a, func(r *mdbx.Reader) (mdbx.TreeOperationV1, error) {
								kept = r
								var source blockTreeSourceV1
								_, primary = prepareBlockTreeEffectV1(&source, r, a, blockTreeRequestV1{})
								switch delivery {
								case "panic":
									panic(panicValue)
								case "goexit":
									runtime.Goexit()
								}
								return mdbx.TreeOperationV1{}, primary
							})
							return nil
						})
					})
					logicalMDBXAssert(t, fixtureErr == nil, "cleanup fixture: %v", fixtureErr)
					if mode == 0 {
						logicalMDBXAssert(t, state == "OPEN", "clean callback state %s", state)
					}
					if mode == 9 {
						logicalMDBXAssert(t, state == "CLOSED", "consumed callback state %s", state)
					}
					if mode == 10 {
						logicalMDBXAssert(t, state == "POISONEDTHREAD", "retained callback state %s", state)
					}
					post = true
				}
				if delivery == "goexit" {
					done := make(chan struct{})
					go func() { defer close(done); run() }()
					<-done
				} else {
					run()
				}
				btFailure(t, primary, logicalStateFailureLocalInvariant, "invalid block tree source request")
				_, _, expired := kept.Get(mdbx.TreeSchemaV1DBIs()[0], []byte{2})
				logicalMDBXAssert(t, expired != nil, "callback Reader/grant survived")
				btReservationsReleased(t, w.owner)
				if delivery == "panic" {
					logicalMDBXAssert(t, recovered == panicValue && !post, "panic delivery changed")
				}
				if delivery == "goexit" {
					logicalMDBXAssert(t, !post, "Goexit returned")
				}
				actualState, _, stateErr := mdbx.FixtureStartupCleanup(w.s, 0, false, func() {})
				wantState := "OPEN"
				if mode == 9 {
					wantState = "CLOSED"
				}
				if mode == 10 {
					wantState = "POISONEDTHREAD"
				}
				logicalMDBXAssert(t, stateErr == nil && actualState == wantState, "post-unwind owner state %s/%v", actualState, stateErr)
				if delivery == "error" {
					result.want(t, 1, 1, -1)
					logicalMDBXAssert(t, errors.Is(result.err, primary), "callback primary lost: %v", result.err)
					if mode == 0 {
						logicalMDBXAssert(t, result.err == primary, "clean callback wrapped primary")
					} else {
						btfCached(t, w, result)
					}
				}
				if delivery != "error" && mode != 0 {
					terminal := w.s.View(func(*mdbx.Reader) error { t.Fatal("unwind terminal View callback"); return nil })
					btfCached(t, w, btResult{truth: 1, stage: 1, index: -1, err: terminal})
				}
				if mode == 0 {
					w.pair(t, btMutation(6, binary.BigEndian.AppendUint64(binary.BigEndian.AppendUint64(nil, 1), 88), make([]byte, 104)))
				}
				if mode == 10 {
					logicalMDBXAssert(t, mdbx.FixtureStartupRelease(w.s) == nil, "release retained handle")
				}
			})
		}
	}
}

func btfSourcePrimary(t *testing.T) {
	for _, variant := range []string{"position", "sink", "wrapped-sink", "reader-direct", "reader-wrapped", "reader-caused"} {
		t.Run(variant, func(t *testing.T) {
			w := btNew(t)
			r := btfRequest(12)
			other := btfRequest(99)
			w.pair(t, btMutation(3, other.Block[:], other.Raw[:148]))
			var original, returned error
			var result btResult
			var observed []*btObserved
			run := func() {
				result, _, observed = w.run(t, []blockTreeRequestV1{r}, func(_ []blockTreeEffectV1, sources []*btObserved, _ *mdbx.TreeOperationV1) {
					sources[0].before = func(p mdbx.TreePositionV1, reader *mdbx.Reader, sink *mdbx.TreeDeltaSinkV1) error {
						switch variant {
						case "position":
							original = sources[0].source.TreeDeltaV1(255, reader, sink)
						case "sink", "wrapped-sink":
							logicalMDBXAssert(t, sink.BeginV1(sources[0].source.coverage.BlockMeta) == nil, "initial BEGIN")
							original = sources[0].source.TreeDeltaV1(p, reader, sink)
						default:
							_, _, original = reader.Get(mdbx.TreeSchemaV1DBIs()[3], other.Block[:])
						}
						returned = original
						if variant == "wrapped-sink" || variant == "reader-wrapped" {
							returned = fmt.Errorf("provider: %w", original)
						}
						if variant == "reader-caused" {
							returned = &mdbx.EngineError{Operation: "get", Class: mdbx.EngineIO, Code: 5, Diagnostic: "provider cause", Cause: original}
						}
						return returned
					}
				})
			}
			if variant == "reader-direct" || variant == "reader-wrapped" || variant == "reader-caused" {
				evidence, fixtureErr := mdbx.FixtureSelectedDamage(w.s, w.owner, mdbx.SelectedDamageGetEIO, 3, other.Block[:], run)
				logicalMDBXAssert(t, fixtureErr == nil && evidence.Faults == 1 && evidence.Commits == 0 && evidence.Deletes == 0, "Reader failure site: %+v/%v", evidence, fixtureErr)
			} else {
				run()
			}
			result.want(t, 1, 1, 0)
			logicalMDBXAssert(t, original != nil && errors.Is(result.err, original) && errors.Is(result.err, returned) && observed[0].calls == ([3]int{0, 1, 0}), "source primary identity/order: %v", result.err)
			if variant == "position" {
				btFailure(t, original, logicalStateFailureLocalInvariant, "invalid block tree source position")
			}
			if variant == "sink" || variant == "position" || variant == "reader-direct" {
				logicalMDBXAssert(t, result.err == original, "exact primary wrapped: %v", result.err)
			}
			if variant == "wrapped-sink" || variant == "reader-wrapped" || variant == "reader-caused" {
				joined, ok := result.err.(interface{ Unwrap() []error })
				logicalMDBXAssert(t, ok && len(joined.Unwrap()) == 2 && joined.Unwrap()[0] == returned && joined.Unwrap()[1] == original, "provider/sink order: %v", result.err)
			}
			w.readUnavailable(t, result)
		})
	}
}

func (w *btWorld) readUnavailable(t *testing.T, result btResult) {
	t.Helper()
	btfCached(t, w, result)
	w.reopen(t)
	btState(t, w, 1, mdbx.TreeEndpointV1{}, nil)
}

func btfLateScene(t *testing.T) (*btWorld, []blockTreeRequestV1, Outpoint) {
	t.Helper()
	w := btNew(t)
	oldTx := btTransaction(1, 0, nil, [][]byte{btFrame(9, 0, nil)}, nil, []byte{0}, nil)
	seed := btRequest(btBody(148, 1, [32]byte{}, oldTx), 3)
	seed.Generation = 2
	result, _, _ := w.run(t, []blockTreeRequestV1{seed}, nil)
	logicalMDBXAssert(t, result.err == nil, "LAG original seed: %v", result.err)
	op := Outpoint{Txid: oldTx.id}
	inert := btTransaction(2, 0, nil, nil, nil, []byte{0}, nil)
	spend := btTransaction(3, 0, []Outpoint{op}, [][]byte{btFrame(10, 0, []byte{1})}, nil, []byte{0}, nil)
	current := btfRequest(15)
	lag := btRequest(btBody(148, 2, seed.Block, inert, spend), 4)
	lag.Generation, lag.Kind = 2, 6
	return w, []blockTreeRequestV1{current, lag}, op
}

func btfSectionCleanup(t *testing.T) {
	for _, mode := range []uint32{9, 10} {
		t.Run(fmt.Sprint(mode), func(t *testing.T) {
			w := btNew(t)
			var result btResult
			var primary error
			state, _, err := mdbx.FixtureStartupCleanup(w.s, mode, false, func() {
				result, _, _ = w.run(t, []blockTreeRequestV1{btfRequest(21)}, func(_ []blockTreeEffectV1, sources []*btObserved, _ *mdbx.TreeOperationV1) {
					sources[0].before = func(_ mdbx.TreePositionV1, reader *mdbx.Reader, sink *mdbx.TreeDeltaSinkV1) error {
						primary = sources[0].source.TreeDeltaV1(255, reader, sink)
						return primary
					}
				})
			})
			logicalMDBXAssert(t, err == nil && errors.Is(result.err, primary), "section cleanup error %v/%v", result.err, err)
			result.want(t, 1, 1, 0)
			want := "CLOSED"
			if mode == 10 {
				want = "POISONEDTHREAD"
			}
			logicalMDBXAssert(t, state == want, "section cleanup state %s want %s", state, want)
			btfCached(t, w, result)
			if mode == 10 {
				logicalMDBXAssert(t, mdbx.FixtureStartupRelease(w.s) == nil, "section retained release")
			}
		})
	}
}

func btfLateOriginal(t *testing.T) {
	for _, artifact := range []string{"counter", "root", "leaf"} {
		for _, damage := range []string{"absent", "malformed"} {
			if artifact == "leaf" && damage == "absent" {
				continue
			} // public fixture has no rank8 delete; native predecessor owns this row
			t.Run(artifact+"/"+damage, func(t *testing.T) {
				w, requests, old := btfLateScene(t)
				var seedBlock [32]byte
				copy(seedBlock[:], requests[1].Raw[4:36])
				original := btfOldRows(t, w, seedBlock)
				rank := uint8(0)
				key := btMeta(0x10, 2)
				if artifact == "root" {
					key = btMeta(0x11, 2)
				}
				if artifact == "leaf" {
					rank = 8
					key = append(btUTXOKey(2, old), 0, 0)
				}
				btfDamage(t, w, rank, key, damage)
				var result btResult
				var sources []*btObserved
				evidence, fixtureErr := mdbx.FixtureSelectedDamage(w.s, w.owner, mdbx.SelectedDamagePutEIO, 0, btMeta(0x10, 1), func() { result, _, sources = w.run(t, requests, nil) })
				logicalMDBXAssert(t, fixtureErr != nil && fixtureErr.Error() == "selected damage fixture site was not reached exactly as armed" && evidence.Faults == 0 && evidence.Deletes == 0 && evidence.Commits == 0, "zero attempted writes %+v / %v", evidence, fixtureErr)
				result.want(t, 1, 1, 1)
				engine, ok := result.err.(*mdbx.EngineError)
				logicalMDBXAssert(t, ok && engine.Class == "Integrity" && engine.Operation == "update" && engine.Code == -30796 && engine.Diagnostic == "invalid tree native representation" && !engine.ReopenRequired, "original damage: %+v", result.err)
				if damage == "absent" {
					logicalMDBXAssert(t, engine.Cause == nil, "absent original cause: %v", engine.Cause)
				} else {
					logicalMDBXAssert(t, engine.Cause != nil && engine.Cause.Error() == "invalid MDBX SchemaV2 bytes", "malformed original cause: %v", engine.Cause)
				}
				observation := engine.TreeObservation
				kind := mdbx.TreeObservationAbsentV1
				if damage == "malformed" {
					kind = mdbx.TreeObservationMalformedV1
				}
				want := mdbx.TreeObservationV1{DatabaseID: [32]byte{7}, Generation: 2, Block: requests[1].Block, Height: 4, Primitive: 1, Position: 1, Rank: rank, KeyLength: uint8(len(key)), Kind: kind, OriginalImage: true, OriginalReference: true}
				copy(want.Key[:], key)
				logicalMDBXAssert(t, observation != nil && *observation == want, "copied observation: %+v want %+v", observation, want)
				logicalMDBXAssert(t, sources[0].calls == ([3]int{0, 1, 0}) && sources[1].calls == ([3]int{0, 1, 0}), "late source order: %v/%v", sources[0].calls, sources[1].calls)
				btfCached(t, w, result)
				w.reopen(t)
				btfWantOld(t, w, original, rank, key, damage)
				w.read(t, 1, btUTXOKey(2, old), btValue(btFrame(9, 0, nil), 3, true))
				w.read(t, 4, requests[0].Block[:], nil)
				btState(t, w, 1, mdbx.TreeEndpointV1{}, nil)
			})
		}
	}
	t.Run("healthy-SAME-key-arm", func(t *testing.T) {
		w, requests, _ := btfLateScene(t)
		var result btResult
		evidence, err := mdbx.FixtureSelectedDamage(w.s, w.owner, mdbx.SelectedDamagePutEIO, 0, btMeta(0x10, 1), func() { result, _, _ = w.run(t, requests, nil) })
		logicalMDBXAssert(t, err == nil && evidence.Faults == 1 && evidence.Commits == 0, "healthy same-key put arm: %+v/%v", evidence, err)
		result.want(t, 1, 2, -1)
		btfEngine(t, result.err, "update", mdbx.EngineIO, 5, "error 5")
		btfCached(t, w, result)
	})
	t.Run("first-CURRENT-stops-LAG", func(t *testing.T) {
		w, requests, _ := btfLateScene(t)
		var result btResult
		var sources []*btObserved
		var primary error
		evidence, fixtureErr := mdbx.FixtureSelectedDamage(w.s, w.owner, mdbx.SelectedDamagePutEIO, 0, btMeta(0x10, 1), func() {
			result, _, sources = w.run(t, requests, func(_ []blockTreeEffectV1, observed []*btObserved, _ *mdbx.TreeOperationV1) {
				observed[0].before = func(_ mdbx.TreePositionV1, r *mdbx.Reader, sink *mdbx.TreeDeltaSinkV1) error {
					primary = observed[0].source.TreeDeltaV1(255, r, sink)
					return primary
				}
			})
		})
		logicalMDBXAssert(t, fixtureErr != nil && fixtureErr.Error() == "selected damage fixture site was not reached exactly as armed" && evidence.Faults == 0 && evidence.Commits == 0 && evidence.Deletes == 0, "first-source zero attempts: %+v/%v", evidence, fixtureErr)
		result.want(t, 1, 1, 0)
		logicalMDBXAssert(t, result.err == primary && sources[0].calls == ([3]int{0, 1, 0}) && sources[1].calls == ([3]int{}), "first source or later LAG changed: %v calls%v/%v", result.err, sources[0].calls, sources[1].calls)
		btfCached(t, w, result)
	})
}

type btfRow struct {
	rank       uint8
	key, value []byte
}

func btfOldRows(t *testing.T, w *btWorld, seed [32]byte) []btfRow {
	t.Helper()
	var rows []btfRow
	err := w.s.View(func(r *mdbx.Reader) error {
		for _, key := range [][]byte{{0}, {1}, {2}, {3}, btMeta(0x10, 1), btMeta(0x10, 2), btMeta(0x11, 1), btMeta(0x11, 2)} {
			value, present, err := r.Get(mdbx.TreeSchemaV1DBIs()[0], key)
			if err != nil {
				return err
			}
			if present {
				rows = append(rows, btfRow{0, bytes.Clone(key), value})
			}
		}
		for _, rank := range []uint8{1, 2, 7, 8} {
			for _, g := range []uint64{1, 2} {
				page, err := r.PrefixPage(mdbx.TreeSchemaV1DBIs()[rank], binary.BigEndian.AppendUint64(nil, g), nil, 512, 1<<20)
				if err != nil {
					return err
				}
				logicalMDBXAssert(t, page.Stop == mdbx.PrefixPageExhausted, "bounded original page")
				for _, row := range page.Rows {
					rows = append(rows, btfRow{rank, row.Key, row.Value})
				}
			}
		}
		page, err := r.PrefixPage(mdbx.TreeSchemaV1DBIs()[5], seed[:], nil, 512, 1<<20)
		if err != nil {
			return err
		}
		logicalMDBXAssert(t, page.Stop == mdbx.PrefixPageExhausted, "bounded original undo page")
		for _, row := range page.Rows {
			rows = append(rows, btfRow{5, row.Key, row.Value})
		}
		for _, rank := range []uint8{3, 4} {
			value, present, err := r.Get(mdbx.TreeSchemaV1DBIs()[rank], seed[:])
			if err != nil {
				return err
			}
			logicalMDBXAssert(t, present, "original seed body/header")
			rows = append(rows, btfRow{rank, bytes.Clone(seed[:]), value})
		}
		return nil
	})
	logicalMDBXAssert(t, err == nil, "original full snapshot: %v", err)
	btfWantOld(t, w, rows, 255, nil, "unchanged")
	return rows
}

func btfWantOld(t *testing.T, w *btWorld, rows []btfRow, damagedRank uint8, damagedKey []byte, damage string) {
	t.Helper()
	var counts [9]uint64
	for _, row := range rows {
		want := row.value
		if row.rank == damagedRank && bytes.Equal(row.key, damagedKey) {
			want = []byte{0x7f}
			if damage == "absent" {
				want = nil
			}
		}
		if want != nil {
			counts[row.rank]++
		}
		equal, err := mdbx.FixtureRawRowEqual(w.s, row.rank, row.key, want)
		logicalMDBXAssert(t, err == nil && equal, "full OLD rank%d key%x drift: %v", row.rank, row.key, err)
	}
	inspection, err := w.s.Inspect()
	logicalMDBXAssert(t, err == nil && len(inspection.DBIs) == 9, "OLD inspection: %v", err)
	for _, dbi := range inspection.DBIs {
		logicalMDBXAssert(t, dbi.Entries == counts[dbi.DBI.Rank], "full OLD rank%d cardinality %d want%d", dbi.DBI.Rank, dbi.Entries, counts[dbi.DBI.Rank])
	}
}

func btfDamage(t *testing.T, w *btWorld, rank uint8, key []byte, damage string) {
	t.Helper()
	if rank == 8 {
		drifts, err := mdbx.FixtureWriteSnapshotDrift(w.s, 8, key, func() {
			w.pair(t, btMutation(6, binary.BigEndian.AppendUint64(binary.BigEndian.AppendUint64(nil, 4), 4), make([]byte, 104)))
		})
		logicalMDBXAssert(t, err == nil && drifts == 1, "persisted original node drift: %d/%v", drifts, err)
		// Remove only the harmless setup row through the actual Pair grammar.
		w.pair(t, mdbx.Mutation{DBI: mdbx.TreeSchemaV1DBIs()[6], Key: binary.BigEndian.AppendUint64(binary.BigEndian.AppendUint64(nil, 4), 4), BeforePresent: true, AfterKind: 1})
		return
	}
	if damage == "absent" {
		logicalMDBXAssert(t, mdbx.FixtureStartupDeleteRow(w.s, rank, key) == nil, "damage absence")
		return
	}
	logicalMDBXAssert(t, mdbx.FixtureSeedRawRow(w.s, rank, key, []byte{0x7f}) == nil, "damage malformed")
}

func btfReadback(t *testing.T) {
	for _, failSource := range []bool{false, true} {
		t.Run(fmt.Sprint(failSource), func(t *testing.T) {
			w := btNew(t)
			r := btfRequest(17)
			var result btResult
			var observed []*btObserved
			var sourceErr error
			evidence, err := mdbx.FixtureSelectedDamage(w.s, w.owner, mdbx.SelectedDamageCommitNew, 0, []byte{2}, func() {
				result, _, observed = w.run(t, []blockTreeRequestV1{r}, func(_ []blockTreeEffectV1, sources []*btObserved, _ *mdbx.TreeOperationV1) {
					if failSource {
						sources[0].before = func(p mdbx.TreePositionV1, reader *mdbx.Reader, sink *mdbx.TreeDeltaSinkV1) error {
							if p == 2 {
								sourceErr = sources[0].source.TreeDeltaV1(255, reader, sink)
								return sourceErr
							}
							return nil
						}
					}
				})
			})
			logicalMDBXAssert(t, err == nil && evidence.Faults == 1 && evidence.Commits == 1 && evidence.BeginRead == 1 && observed[0].calls == ([3]int{0, 1, 1}), "real readback: %+v/%v calls%v", evidence, err, observed[0].calls)
			truth := uint8(2)
			if failSource {
				truth = 3
			}
			result.want(t, truth, 3, -1)
			logicalMDBXAssert(t, result.err != nil && (!failSource || errors.Is(result.err, sourceErr)), "readback error lost: %v", result.err)
			btfCached(t, w, result)
			w.reopen(t)
			w.read(t, 4, r.Block[:], r.Raw)
			btIndexes(t, w, r, true)
		})
	}
}
