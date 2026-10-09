//go:build cgo && (darwin || linux) && (amd64 || arm64)

package mdbx

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"runtime"
	"testing"
)

// The existing independent canonical fixture writes literal key/row bytes and
// the paired owner. Expected endpoint scalars never use production encoders.
func tipRow(generation, height uint64, hash [32]byte, work [40]byte) Mutation {
	return canonicalForwardLiteral(generation, height, hash, work)
}

func tipSeed(t *testing.T, store *Store, rows ...Mutation) {
	t.Helper()
	var paired []Mutation
	for _, row := range rows {
		paired = append(paired, row, canonicalOwnerPairOf(row))
	}
	contextSort(paired)
	largeCommit(t, store, Batch{Mutations: paired})
}

func tipRead(t *testing.T, store *Store, generation uint64) *AuthorityPointV1 {
	t.Helper()
	var point *AuthorityPointV1
	mustEnvironment(t, store.View(func(reader *Reader) error {
		var err error
		point, err = reader.CanonicalTipV1(generation)
		return err
	}))
	return point
}

func tipRequirePoint(t *testing.T, point *AuthorityPointV1, height uint64, hash [32]byte) {
	t.Helper()
	if point == nil || point.Height != height || point.BlockHash != hash {
		t.Fatalf("endpoint scalar=%+v, want height%d/hash%x", point, height, hash)
	}
}

func tipError(t *testing.T, err error, operation, class string, code int, diagnostic string, reopen bool) *EngineError {
	t.Helper()
	engine, ok := directTestEngineError(err)
	if !ok || engine.Operation != operation || string(engine.Class) != class || engine.Code != code || engine.Diagnostic != diagnostic || engine.ReopenRequired != reopen {
		t.Fatalf("endpoint error=%#v, want %s/%s/%d/%q/reopen%v", err, operation, class, code, diagnostic, reopen)
	}
	return engine
}

func tipRequest(t *testing.T, reader *Reader, generation uint64, diagnostic string) {
	t.Helper()
	point, err := reader.CanonicalTipV1(generation)
	if point != nil || tipError(t, err, "prefix-page", "InvalidInput", 22, diagnostic, false).Cause != nil {
		t.Fatal("request returned point or cause")
	}
}

func tipRetired(t *testing.T, reader *Reader, cell *canonicalTipCell) {
	t.Helper()
	if reader == nil || reader.usable() || reader.tip != nil || cell != nil && *cell != (canonicalTipCell{}) {
		t.Fatal("endpoint source survived Reader expiry or operation cleanup")
	}
	failure := reader.failure
	tipRequest(t, reader, 0, "Reader is not active")
	if !sameError(reader.failure, failure) {
		t.Fatal("inactive request overwrote the first source failure")
	}
}

func tipOutcome(t *testing.T, store *Store, truth CommitTruth, stage UpdateStage, err error, wantTruth, wantStage uint8, state string) {
	t.Helper()
	if uint8(truth) != wantTruth || uint8(stage) != wantStage || string(store.state) != state || !validStoreShape(store) {
		t.Fatalf("endpoint outcome=%d/%d/%v/%s", truth, stage, err, store.state)
	}
	if state == "OPEN" {
		if store.terminal != nil || store.terminalTruth != 0 || store.txn != nil || store.env == nil || store.writer == nil {
			t.Fatal("OPEN result lost resources or acquired terminal cache")
		}
		return
	}
	if store.terminalTruth != truth || !sameError(store.terminal, err) {
		t.Fatal("terminal truth/error cache lost endpoint result")
	}
	called := false
	again, nextStage, cached := store.Update(func(*Reader) (Batch, error) { called = true; return Batch{}, nil })
	view := store.View(func(*Reader) error { called = true; return nil })
	if called || again != truth || nextStage != 1 || !sameError(cached, err) || !sameError(view, err) {
		t.Fatal("terminal next operation changed truth/error or reached a callback")
	}
}

func TestCanonicalTipV1(t *testing.T) {
	for _, row := range []struct {
		name string
		run  func(*testing.T)
	}{
		{"T01 positive empty", tipEmpty},
		{"T02 T03 T04 endpoint generations heights work", tipEndpoints},
		{"T05 T07 scalar isolation View Update", tipIsolation},
		{"T06 T10 requests and acquisition", tipRequests},
		{"T08 legacy context Large Obsolete coexist", tipCoexist},
		{"T09 constant history", tipHistory},
		{"T11 height boundary", tipHeight},
		{"T15 admission overlap precedence", tipOverlaps},
		{"T16 preflight exact source", tipPreflight},
		{"T17 direct final exact source", tipFinal},
		{"T18 callback first result", tipApplications},
	} {
		t.Run(row.name, row.run)
	}
}

func tipEmpty(t *testing.T) {
	for _, neighbors := range [][]uint64{nil, {1, 8}, {1}, {8}} {
		t.Run(fmt.Sprint(neighbors), func(t *testing.T) {
			store, _, _ := consultedStore(t)
			for i, generation := range neighbors {
				tipSeed(t, store, tipRow(generation, 37, [32]byte{byte(i + 1)}, [40]byte{39: 1}))
			}
			var saved *Reader
			mustEnvironment(t, store.View(func(reader *Reader) error {
				saved = reader
				point, err := reader.CanonicalTipV1(7)
				if point != nil || err != nil || reader.tip == nil || reader.failure != nil {
					return fmt.Errorf("positive empty shape %+v/%w", point, err)
				}
				tipRequest(t, reader, 7, "canonical tip already acquired")
				return nil
			}))
			tipRetired(t, saved, nil)
			if tipRead(t, store, 7) != nil {
				t.Fatal("fresh Reader did not prove empty")
			}
		})
	}
}

func tipEndpoints(t *testing.T) {
	for _, successor := range []bool{false, true} {
		t.Run(fmt.Sprintf("T03 selected-present/successor%v", successor), func(t *testing.T) {
			store, _, _ := consultedStore(t)
			tipSeed(t, store, tipRow(1, 99, [32]byte{0x11}, [40]byte{39: 1}), tipRow(7, 37, [32]byte{0x44}, [40]byte{39: 1}))
			if successor {
				tipSeed(t, store, tipRow(8, 99, [32]byte{0x55}, [40]byte{39: 1}))
			}
			tipRequirePoint(t, tipRead(t, store, 7), 37, [32]byte{0x44})
		})
	}
	for _, generation := range []uint64{1, 7, ^uint64(0)} {
		for _, height := range []uint64{0, 1, 37, 0xffffffff} {
			for _, work := range [][40]byte{{39: 1}, {38: 1, 39: 2}, {3: 1}} {
				t.Run(fmt.Sprintf("g%d/h%d/w%x", generation, height, work), func(t *testing.T) {
					store, _, _ := consultedStore(t)
					hash := [32]byte{0x41, byte(height), byte(generation)}
					row := tipRow(generation, height, hash, work)
					tipSeed(t, store, row)
					if height > 1 {
						tipSeed(t, store, tipRow(generation, 1, [32]byte{0x22}, [40]byte{39: 1}))
					}
					if generation != 1 {
						tipSeed(t, store, tipRow(generation-1, 99, [32]byte{0x31}, [40]byte{39: 1}))
					}
					if generation != ^uint64(0) {
						tipSeed(t, store, tipRow(generation+1, 88, [32]byte{0x32}, [40]byte{39: 1}))
					}
					tipRequirePoint(t, tipRead(t, store, generation), height, hash)
					consultedRequireImage(t, store, row.DBI, row.Key, row.Literal, true, "endpoint raw image unchanged")
				})
			}
		}
	}
	store, _, _ := consultedStore(t)
	for _, generation := range []uint64{1, 2, 7, 8, ^uint64(0) - 1, ^uint64(0)} {
		hash := [32]byte{byte(generation), byte(generation >> 56)}
		tipSeed(t, store, tipRow(generation, generation&0xff, hash, [40]byte{39: 1}))
	}
	for _, generation := range []uint64{1, 2, 7, 8, ^uint64(0) - 1, ^uint64(0)} {
		tipRequirePoint(t, tipRead(t, store, generation), generation&0xff, [32]byte{byte(generation), byte(generation >> 56)})
	}
}

func tipIsolation(t *testing.T) {
	for _, empty := range []bool{false, true} {
		store, _, _ := consultedStore(t)
		row := tipRow(7, 37, [32]byte{0x44}, [40]byte{39: 1})
		if !empty {
			tipSeed(t, store, row)
		}
		var saved *Reader
		var scalar *AuthorityPointV1
		var cell *canonicalTipCell
		target := consultedCounter(t, 900)
		truth, stage, err := store.Update(func(reader *Reader) (Batch, error) {
			saved = reader
			var getErr error
			scalar, getErr = reader.CanonicalTipV1(7)
			cell = reader.tip
			if getErr != nil {
				return Batch{}, getErr
			}
			if scalar != nil {
				scalar.Height = 1234
				scalar.BlockHash = [32]byte{0xff}
			}
			return Batch{Mutations: []Mutation{target}}, nil
		})
		tipOutcome(t, store, truth, stage, err, 2, 3, "OPEN")
		mustEnvironment(t, err)
		tipRetired(t, saved, cell)
		if empty && scalar != nil {
			t.Fatal("empty source manufactured a point")
		}
		if !empty {
			tipRequirePoint(t, scalar, 1234, [32]byte{0xff})
			tipRequirePoint(t, tipRead(t, store, 7), 37, [32]byte{0x44})
			consultedRequireImage(t, store, row.DBI, row.Key, row.Literal, true, "caller scalar cannot change source")
		}
		consultedRequireImage(t, store, target.DBI, target.Key, target.Literal, true, "unrelated effects committed")
		point := tipRead(t, store, 7)
		if point != nil {
			point.Height = 77
			tipRequirePoint(t, point, 77, [32]byte{0x44})
		}
		largeCommit(t, store, Batch{Mutations: []Mutation{consultedCounter(t, 901)}})
	}
}

func tipRequests(t *testing.T) {
	tipRequest(t, nil, 0, "Reader is not active")
	for _, empty := range []bool{false, true} {
		store, _, _ := consultedStore(t)
		if !empty {
			tipSeed(t, store, tipRow(7, 37, [32]byte{0x44}, [40]byte{39: 1}))
		}
		var saved *Reader
		truth, stage, err := store.Update(func(reader *Reader) (Batch, error) {
			saved = reader
			copyReader := newReader(reader.txn, reader.dbis)
			copyReader.self = reader
			copyReader.active.Store(true)
			tipRequest(t, copyReader, 7, "Reader is not active")
			tipRequest(t, reader, 0, "invalid prefix-page prefix")
			_, getErr := reader.CanonicalTipV1(7)
			if getErr != nil {
				return Batch{}, getErr
			}
			tipRequest(t, reader, 7, "canonical tip already acquired")
			tipRequest(t, reader, 8, "canonical tip already acquired")
			tipRequest(t, reader, 0, "invalid prefix-page prefix")
			if reader.failure != nil || !reader.usable() {
				t.Fatal("software request disarmed successful source")
			}
			return Batch{Mutations: []Mutation{consultedCounter(t, 900)}}, nil
		})
		mustEnvironment(t, err)
		tipOutcome(t, store, truth, stage, err, 2, 3, "OPEN")
		tipRetired(t, saved, nil)
		_ = tipRead(t, store, 7)
	}
	for _, request := range []uint64{0, 7, 8} {
		store, _, _ := consultedStore(t)
		var application error
		truth, stage, err := store.Update(func(reader *Reader) (Batch, error) {
			if request != 0 {
				_, application = reader.CanonicalTipV1(7)
				mustEnvironment(t, application)
			}
			_, application = reader.CanonicalTipV1(request)
			return Batch{}, application
		})
		if !sameError(err, application) {
			t.Fatal("returned request lost application identity")
		}
		tipOutcome(t, store, truth, stage, err, 1, 1, "OPEN")
		largeCommit(t, store, Batch{Mutations: []Mutation{consultedCounter(t, 900)}})
	}
}

func tipCoexist(t *testing.T) {
	for _, acquire := range []bool{false, true} {
		store, _, _ := consultedStore(t)
		window := CanonicalContextWindowV1{7, 0, 1}
		rows := contextSeed(t, store, window)
		selector := LargeImageSelectorV1{Kind: LargeImageBlockBodyV1, Hash: [32]byte{0x42}}
		tipSeed(t, store, tipRow(9, 0, [32]byte{0x31}, [40]byte{39: 1}))
		batch := Batch{Mutations: []Mutation{consultedCounter(t, 900)}, Consulted: []ConsultedRow{{DBI: canonicalForwardDBILiteral, Key: canonicalForwardKeyLiteral(8, 9)}}, ContextConsulted: &window, LargeConsulted: []LargeImageSelectorV1{selector}}
		truth, stage, err := store.Update(func(reader *Reader) (Batch, error) {
			if acquire {
				_, getErr := reader.CanonicalTipV1(7)
				if getErr != nil {
					return Batch{}, getErr
				}
			}
			page, pageErr := reader.ObsoleteGenerationPageV1(9, 2, nil, 1440)
			if pageErr != nil {
				return Batch{}, pageErr
			}
			batch.ObsoleteConsulted = []ObsoletePageWitnessV1{page.Witness}
			return batch, nil
		})
		mustEnvironment(t, err)
		tipOutcome(t, store, truth, stage, err, 2, 3, "OPEN")
		contextImages(t, store, rows)
	}
}

func tipHistory(t *testing.T) {
	for _, count := range []int{1, 257} {
		store, _, _ := consultedStore(t)
		rows := make([]Mutation, count)
		for i := range rows {
			hash := [32]byte{0x44}
			binary.BigEndian.PutUint64(hash[8:16], uint64(i))
			rows[i] = tipRow(7, uint64(i*2), hash, [40]byte{39: 1})
		}
		tipSeed(t, store, rows...)
		hash := [32]byte{0x44}
		binary.BigEndian.PutUint64(hash[8:16], uint64(count-1))
		tipRequirePoint(t, tipRead(t, store, 7), uint64((count-1)*2), hash)
	}
}

func tipHeight(t *testing.T) {
	for _, height := range []uint64{0x100000000, ^uint64(0)} {
		store, _, _ := consultedStore(t)
		tipSeed(t, store, tipRow(7, 1, [32]byte{0x11}, [40]byte{39: 1}), tipRow(7, height, [32]byte{0x22}, [40]byte{39: 1}))
		var reader *Reader
		var source error
		truth, stage, err := store.Update(func(r *Reader) (Batch, error) {
			reader = r
			point, failure := r.CanonicalTipV1(7)
			source = failure
			if point != nil {
				t.Fatal("overflow source became a scalar")
			}
			return Batch{}, nil
		})
		if tipError(t, source, "prefix-page", "Integrity", -30793, "canonical tip height outside domain", true).Cause != nil || !sameError(err, source) || !sameError(reader.failure, source) {
			t.Fatal("source height failure lost identity")
		}
		tipRetired(t, reader, nil)
		tipOutcome(t, store, truth, stage, err, 1, 1, "CLOSED")
	}
}

func tipOverlaps(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		for _, generation := range []uint64{7, 8} {
			for _, height := range []uint64{1, 37, 39} {
				for _, kind := range []string{"create", "delete", "replace"} {
					t.Run(fmt.Sprintf("g%d/h%d/%s/reverse%v", generation, height, kind, reverse), func(t *testing.T) {
						store, _, _ := consultedStore(t)
						row := tipRow(generation, height, [32]byte{0x41}, [40]byte{39: 1})
						if kind != "create" {
							tipSeed(t, store, row)
						}
						forward, owner := row, canonicalOwnerPairOf(row)
						if kind == "delete" {
							forward, owner = canonicalDelete(forward), canonicalDelete(owner)
						}
						if kind == "replace" {
							forward.Literal = bytes.Clone(forward.Literal)
							forward.Literal[63] = 0x22
							forward.BeforePresent, owner.BeforePresent = true, true
						}
						truth, stage, err := store.Update(func(r *Reader) (Batch, error) {
							_, getErr := r.CanonicalTipV1(7)
							return Batch{Mutations: []Mutation{forward, owner}, Reverse: reverse}, getErr
						})
						if generation == 7 {
							if tipError(t, err, "update", "InvalidInput", 22, "invalid Update Batch", false).Cause != nil {
								t.Fatal("overlap acquired cause")
							}
							tipOutcome(t, store, truth, stage, err, 1, 1, "OPEN")
							before := row.Literal
							if kind == "create" {
								before = nil
							}
							consultedRequireImage(t, store, row.DBI, row.Key, before, kind != "create", "overlap preserves OLD")
						} else {
							mustEnvironment(t, err)
							tipOutcome(t, store, truth, stage, err, 2, 3, "OPEN")
						}
					})
				}
			}
		}
	}
	store, _, _ := consultedStore(t)
	batch := updatePlanAuxBatch(t, 16_385)
	truth, stage, err := store.Update(func(r *Reader) (Batch, error) { _, getErr := r.CanonicalTipV1(1); return batch, getErr })
	if tipError(t, err, "update", "Capacity", -30417, "Update Batch exceeds bound", false).Cause != nil {
		t.Fatal("capacity changed cause")
	}
	tipOutcome(t, store, truth, stage, err, 1, 1, "OPEN")
	for _, variant := range []string{"invalid Batch", "legacy", "context", "Large", "Obsolete"} {
		store, _, _ := consultedStore(t)
		row := tipRow(7, 37, [32]byte{0x44}, [40]byte{39: 1})
		batch := Batch{Mutations: []Mutation{row, canonicalOwnerPairOf(row)}}
		contextSort(batch.Mutations)
		switch variant {
		case "invalid Batch":
			batch.Mutations[0].AfterKind = 99
		case "legacy":
			batch.Consulted = []ConsultedRow{{}}
		case "context":
			window := CanonicalContextWindowV1{7, 0, 10_081}
			batch.ContextConsulted = &window
		case "Large":
			batch.LargeConsulted = []LargeImageSelectorV1{{Kind: 99}}
		case "Obsolete":
			batch.ObsoleteConsulted = []ObsoletePageWitnessV1{{}}
		}
		truth, stage, result := store.Update(func(r *Reader) (Batch, error) { _, failure := r.CanonicalTipV1(7); return batch, failure })
		class, code, diagnostic := "InvalidInput", 22, "invalid Update Batch"
		if variant == "context" {
			class, code, diagnostic = "Capacity", -30417, "Update Batch exceeds bound"
		}
		tipError(t, result, "update", class, code, diagnostic, false)
		tipOutcome(t, store, truth, stage, result, 1, 1, "OPEN")
		consultedRequireImage(t, store, row.DBI, row.Key, nil, false, "earlier admission preserves absent endpoint")
	}
	store, _, _ = consultedStore(t)
	row := tipRow(7, 37, [32]byte{0x44}, [40]byte{39: 1})
	tipSeed(t, store, row)
	truth, stage, err = store.Update(func(r *Reader) (Batch, error) {
		_, failure := r.CanonicalTipV1(7)
		if failure != nil {
			return Batch{}, failure
		}
		index, indexErr := r.ObsoleteGenerationPageV1(7, 2, nil, 1)
		if indexErr != nil {
			return Batch{}, indexErr
		}
		owner, ownerErr := r.ObsoleteGenerationPageV1(7, 4, nil, 1)
		if ownerErr != nil {
			return Batch{}, ownerErr
		}
		return Batch{Mutations: []Mutation{consultedCounter(t, 900)}, ObsoleteConsulted: []ObsoletePageWitnessV1{index.Witness, owner.Witness}, ObsoleteDeletes: append(index.Rows, owner.Rows...)}, nil
	})
	tipError(t, err, "update", "InvalidInput", 22, "invalid Update Batch", false)
	tipOutcome(t, store, truth, stage, err, 1, 1, "OPEN")
	consultedRequireImage(t, store, row.DBI, row.Key, row.Literal, true, "Obsolete target overlap preserves OLD")
}

func tipDriftPlan(t *testing.T, store *Store, reader *Reader, original Mutation, kind string) {
	t.Helper()
	var rows []Mutation
	switch kind {
	case "empty-to-present":
		rows = []Mutation{original, canonicalOwnerPairOf(original)}
	case "present-to-empty":
		rows = []Mutation{canonicalDelete(original), canonicalDelete(canonicalOwnerPairOf(original))}
	case "tip-plus-two":
		row := tipRow(7, 39, [32]byte{0x55}, [40]byte{39: 1})
		rows = []Mutation{row, canonicalOwnerPairOf(row)}
	default:
		replacement := original
		replacement.Literal = bytes.Clone(original.Literal)
		var at int
		_, err := fmt.Sscan(kind, &at)
		mustEnvironment(t, err)
		replacement.Literal[at] ^= 0x01
		replacement.BeforePresent = true
		owner := canonicalOwnerPairOf(replacement)
		owner.BeforePresent = true
		rows = []Mutation{replacement, owner}
	}
	contextSort(rows)
	requireUpdateTruth(t, store.updateNative(updateNativePlan(t, rows...), nil, reader.txn), 2, true, nil, nil)
}

func tipPreflight(t *testing.T) {
	for _, kind := range []string{"empty-to-present", "present-to-empty", "tip-plus-two", "32", "63", "103"} {
		t.Run(kind, func(t *testing.T) {
			store, path, cfg := consultedStore(t)
			row := tipRow(7, 37, [32]byte{0x44}, [40]byte{39: 2})
			if kind != "empty-to-present" {
				tipSeed(t, store, row)
			}
			var reader *Reader
			var cell *canonicalTipCell
			truth, stage, err := store.Update(func(r *Reader) (Batch, error) {
				reader = r
				_, getErr := r.CanonicalTipV1(7)
				if getErr != nil {
					return Batch{}, getErr
				}
				cell = r.tip
				tipDriftPlan(t, store, r, row, kind)
				return Batch{Mutations: []Mutation{consultedCounter(t, 900)}}, nil
			})
			if tipError(t, err, "update", "StateMismatch", -30779, "OLD/write snapshot mismatch", false).Cause != nil {
				t.Fatal("preflight mismatch gained cause")
			}
			tipOutcome(t, store, truth, stage, err, 1, 1, "CLOSED")
			tipRetired(t, reader, cell)
			reopened, openErr := Open(path, cfg)
			consultedTrack(t, reopened, openErr)
			consultedRequireImage(t, reopened, readDBIsLiteral()[0], consultedCounter(t, 900).Key, nil, false, "preflight wrote no effects")
			point := tipRead(t, reopened, 7)
			switch kind {
			case "present-to-empty":
				if point != nil {
					t.Fatal("sibling deletion lost")
				}
			case "tip-plus-two":
				tipRequirePoint(t, point, 39, [32]byte{0x55})
			default:
				tipRequirePoint(t, point, 37, [32]byte{0x44})
			}
		})
	}
}

func tipFinal(t *testing.T) {
	store, _, _ := consultedStore(t)
	row := tipRow(7, 37, [32]byte{0x44}, [40]byte{39: 1})
	tipSeed(t, store, row)
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	mustEnvironment(t, store.View(func(reader *Reader) error {
		_, getErr := reader.CanonicalTipV1(7)
		if getErr != nil {
			return getErr
		}
		replacement := row
		replacement.Literal = bytes.Clone(row.Literal)
		replacement.Literal[63] = 0x55
		replacement.BeforePresent = true
		owner := canonicalOwnerPairOf(row)
		owner.BeforePresent = true
		plan := updateNativePlan(t, consultedCounter(t, 900), replacement, owner)
		outcome := store.updateNative(plan, nil, reader.txn, largeImageScope{tip: reader.tip, maxKey: 2022})
		if outcome.truth != 1 || outcome.stage != 2 || outcome.commitAttempted || outcome.secondary != nil || outcome.retainedWrite != nil || outcome.retainedRead != nil {
			t.Fatalf("final full outcome %+v", outcome)
		}
		if tipError(t, outcome.primary, "update", "StateMismatch", -30779, "final update image mismatch", false).Cause != nil {
			t.Fatal("final mismatch gained cause")
		}
		return nil
	}))
	consultedRequireImage(t, store, row.DBI, row.Key, row.Literal, true, "final abort restores original raw image")
	consultedRequireImage(t, store, readDBIsLiteral()[0], consultedCounter(t, 900).Key, nil, false, "final abort restores unrelated effects")
}

func tipApplications(t *testing.T) {
	var typedNil *CommitError
	inner := errors.New("inner")
	applications := []error{errors.New("application"), typedNil, fmt.Errorf("wrapped: %w", inner), errors.Join(inner, errors.New("second")), &EngineError{Operation: "get", Class: "IO", Code: 5, Diagnostic: "error 5", Cause: inner}}
	for i, application := range applications {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			store, _, _ := consultedStore(t)
			var reader *Reader
			var cell *canonicalTipCell
			tipSeed(t, store, tipRow(7, 37, [32]byte{0x44}, [40]byte{39: 1}))
			truth, stage, err := store.Update(func(r *Reader) (Batch, error) {
				reader = r
				_, getErr := r.CanonicalTipV1(7)
				mustEnvironment(t, getErr)
				cell = r.tip
				return Batch{}, application
			})
			if !sameError(err, application) {
				t.Fatal("application interface identity lost")
			}
			tipOutcome(t, store, truth, stage, err, 1, 1, "OPEN")
			tipRetired(t, reader, cell)
			largeCommit(t, store, Batch{Mutations: []Mutation{consultedCounter(t, 900)}})
		})
	}
	for _, acquire := range []bool{false, true} {
		store, _, _ := consultedStore(t)
		var reader *Reader
		var cell *canonicalTipCell
		tipSeed(t, store, tipRow(7, 37, [32]byte{0x44}, [40]byte{39: 1}))
		payload := &struct{ value int }{7}
		func() {
			defer func() {
				if recovered := recover(); recovered != payload {
					t.Fatalf("original callback panic %v", recovered)
				}
			}()
			_, _, _ = store.Update(func(r *Reader) (Batch, error) {
				reader = r
				if acquire {
					_, getErr := r.CanonicalTipV1(7)
					mustEnvironment(t, getErr)
					cell = r.tip
				}
				panic(payload)
			})
		}()
		tipRetired(t, reader, cell)
		if store.state != "OPEN" || store.txn != nil || !validStoreShape(store) {
			t.Fatal("panic cleanup lost Store resources")
		}
		largeCommit(t, store, Batch{Mutations: []Mutation{consultedCounter(t, 900)}})
	}
}
