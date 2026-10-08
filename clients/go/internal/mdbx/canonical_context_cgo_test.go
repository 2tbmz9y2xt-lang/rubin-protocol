//go:build cgo && (darwin || linux) && (amd64 || arm64)

package mdbx

import (
	"bytes"
	"crypto/sha3"
	"encoding/binary"
	"fmt"
	"reflect"
	"runtime"
	"sort"
	"testing"
)

// Independent physical observations; production context keys/widths are never the oracle.
func contextRows(window CanonicalContextWindowV1) []Mutation {
	rows := make([]Mutation, 0, int(window.Count)*3)
	for i := uint32(0); i < window.Count; i++ {
		header := bytes.Repeat([]byte{0x51}, 116)
		binary.BigEndian.PutUint64(header[:8], window.Generation)
		binary.BigEndian.PutUint64(header[8:16], window.FirstHeight+uint64(i))
		hash := sha3.Sum256(header)
		index := canonicalForwardLiteral(window.Generation, window.FirstHeight+uint64(i), hash, [40]byte{39: 0x41})
		rows = append(rows, index, Mutation{DBI: DBI{Name: "headers-v1", Rank: 3}, Key: bytes.Clone(hash[:]), AfterKind: AfterKind(2), Literal: header}, canonicalOwnerPairOf(index))
	}
	return rows
}

func contextSort(rows []Mutation) {
	sort.Slice(rows, func(i, j int) bool {
		return rows[i].DBI.Rank < rows[j].DBI.Rank || rows[i].DBI.Rank == rows[j].DBI.Rank && bytes.Compare(rows[i].Key, rows[j].Key) < 0
	})
}

func contextSeed(t *testing.T, store *Store, window CanonicalContextWindowV1) []Mutation {
	t.Helper()
	rows := contextRows(window)
	for start := 0; start < len(rows); start += 3000 {
		part := append([]Mutation(nil), rows[start:min(start+3000, len(rows))]...)
		contextSort(part)
		largeCommit(t, store, Batch{Mutations: part})
	}
	return rows
}

func contextImages(t *testing.T, store *Store, rows []Mutation) {
	t.Helper()
	mustEnvironment(t, store.View(func(reader *Reader) error {
		for _, row := range rows {
			got, present, err := reader.Get(row.DBI, row.Key)
			if err != nil || !present || !bytes.Equal(got, row.Literal) {
				return fmt.Errorf("complete context row rank%d key%x: %x/%v/%w", row.DBI.Rank, row.Key, got, present, err)
			}
		}
		return nil
	}))
}

func contextError(t *testing.T, err error, class string, code int, diagnostic string) {
	t.Helper()
	engine, ok := directTestEngineError(err)
	if !ok || engine == nil || engine.Operation != "update" || string(engine.Class) != class || engine.Code != code || engine.Diagnostic != diagnostic || engine.Cause != nil || engine.ReopenRequired {
		t.Fatalf("exact context error %#v, want update/%s/%d/%q/nil/false", err, class, code, diagnostic)
	}
}

func contextRefusal(t *testing.T, store *Store, batch Batch, class string, code int, diagnostic string) {
	t.Helper()
	var saved *Reader
	truth, stage, err := store.Update(func(reader *Reader) (Batch, error) {
		saved = reader
		return batch, nil
	})
	contextError(t, err, class, code, diagnostic)
	if truth != 1 || stage != 1 || string(store.state) != "OPEN" || store.env == nil || store.writer == nil || store.txn != nil || store.terminal != nil || saved == nil || saved.usable() {
		t.Fatalf("software context refusal resource tuple %d/%d/%v/%s", truth, stage, err, store.state)
	}
	consultedRequireImage(t, store, readDBIsLiteral()[0], consultedCounter(t, 900).Key, nil, false, "refusal did not write target")
}

func TestCanonicalContextWindowV1(t *testing.T) {
	for _, row := range []struct {
		name string
		run  func(*testing.T)
	}{
		{"B01 nil ordinary and reverse", contextNil},
		{"B02 B03 B04 valid finite windows", contextValid},
		{"B05 value ownership", contextOwned},
		{"B08 B09 B10 B11 scalar order and retry", contextAdmission},
		{"B12 B13 exact overlap identity", contextOverlaps},
		{"B07 B17 B18 B20 B22 complete native phases", contextPhases},
		{"B15 earlier admission", contextEarlier},
		{"descriptor API shape", contextShape},
	} {
		t.Run(row.name, row.run)
	}
}

func contextNil(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		store, _, _ := consultedStore(t)
		target := consultedCounter(t, 900)
		largeCommit(t, store, Batch{Mutations: []Mutation{target}, Reverse: reverse})
		consultedRequireImage(t, store, target.DBI, target.Key, target.Literal, true, "nil compatibility")
	}
}

func contextValid(t *testing.T) {
	for _, window := range []CanonicalContextWindowV1{{1, 0, 1}, {7, 100, 3}, {^uint64(0), 0xffffffff, 1}, {9, 1, 11}, {11, 0, 10_080}, {13, 0xfffffff0, 16}} {
		t.Run(fmt.Sprintf("g%d/h%d/n%d", window.Generation, window.FirstHeight, window.Count), func(t *testing.T) {
			store, _, _ := consultedStore(t)
			rows := contextSeed(t, store, window)
			outside := canonicalForwardLiteral(window.Generation+1, 9, [32]byte{1}, [40]byte{39: 1})
			if window.Generation == ^uint64(0) {
				outside = canonicalForwardLiteral(1, 9, [32]byte{1}, [40]byte{39: 1})
			}
			largeCommit(t, store, Batch{Mutations: []Mutation{outside, canonicalOwnerPairOf(outside)}})
			largeCommit(t, store, Batch{Mutations: []Mutation{consultedCounter(t, 900)}, ContextConsulted: &window})
			contextImages(t, store, append(rows, outside, canonicalOwnerPairOf(outside)))
		})
	}
}

func contextOwned(t *testing.T) {
	store, _, _ := consultedStore(t)
	window := CanonicalContextWindowV1{7, 100, 3}
	rows := contextSeed(t, store, window)
	plan := updateNativePlan(t, consultedCounter(t, 900))
	scope, err := updateOwnedContext(&window, plan, largeImageScope{maxKey: 2022})
	mustEnvironment(t, err)
	window = CanonicalContextWindowV1{1, 0, 1}
	if !scope.contextPresent || scope.context != (CanonicalContextWindowV1{7, 100, 3}) {
		t.Fatal("owned descriptor followed caller mutation")
	}
	mustEnvironment(t, store.View(func(reader *Reader) error {
		infrastructure, err := contextQualify(reader, plan, scope)
		if infrastructure || err != nil {
			return fmt.Errorf("owned qualification %v/%w", infrastructure, err)
		}
		requireUpdateTruth(t, store.updateNative(plan, nil, reader.txn, scope), 2, true, nil, nil)
		return nil
	}))
	contextImages(t, store, rows)
}

func contextAdmission(t *testing.T) {
	for _, row := range []struct {
		name   string
		window CanonicalContextWindowV1
		class  string
		code   int
	}{
		{"generation zero", CanonicalContextWindowV1{0, 0, 1}, "InvalidInput", 22},
		{"count zero", CanonicalContextWindowV1{1, 0, 0}, "InvalidInput", 22},
		{"height too large", CanonicalContextWindowV1{1, 0x100000000, 1}, "InvalidInput", 22},
		{"generation beats count", CanonicalContextWindowV1{0, 0, 10_081}, "InvalidInput", 22},
		{"height beats count", CanonicalContextWindowV1{1, 0x100000000, 10_081}, "InvalidInput", 22},
		{"over count", CanonicalContextWindowV1{1, 0, 10_081}, "Capacity", -30417},
		{"maximum count", CanonicalContextWindowV1{1, 0, 0xffffffff}, "Capacity", -30417},
		{"count beats overflow", CanonicalContextWindowV1{1, 0xffffffff, 10_081}, "Capacity", -30417},
		{"maximum start overflow", CanonicalContextWindowV1{1, 0xffffffff, 2}, "InvalidInput", 22},
		{"end overflow", CanonicalContextWindowV1{1, 0xfffffff0, 17}, "InvalidInput", 22},
	} {
		t.Run(row.name, func(t *testing.T) {
			store, _, _ := consultedStore(t)
			valid := CanonicalContextWindowV1{1, 0, 1}
			rows := contextSeed(t, store, valid)
			diagnostic := "invalid Update Batch"
			if row.class == "Capacity" {
				diagnostic = "Update Batch exceeds bound"
			}
			contextRefusal(t, store, Batch{Mutations: []Mutation{consultedCounter(t, 900)}, ContextConsulted: &row.window}, row.class, row.code, diagnostic)
			contextImages(t, store, rows)
			largeCommit(t, store, Batch{Mutations: []Mutation{consultedCounter(t, 900)}, ContextConsulted: &valid})
		})
	}
}

func contextOverlaps(t *testing.T) {
	for _, kind := range []string{"index target", "index legacy", "header target", "header legacy", "neighbor", "generation", "alternate header", "alternate legacy"} {
		t.Run(kind, func(t *testing.T) {
			store, _, _ := consultedStore(t)
			window := CanonicalContextWindowV1{7, 100, 3}
			rows := contextSeed(t, store, window)
			batch := Batch{Mutations: []Mutation{consultedCounter(t, 900)}, ContextConsulted: &window}
			index, header := rows[6], rows[7]
			switch kind {
			case "index target":
				batch.Mutations = append(batch.Mutations, canonicalDelete(index), canonicalDelete(rows[8]))
			case "index legacy":
				batch.Consulted = []ConsultedRow{{DBI: index.DBI, Key: index.Key}}
			case "header target":
				batch.Mutations = append(batch.Mutations, canonicalDelete(header))
			case "header legacy":
				batch.Consulted = []ConsultedRow{{DBI: header.DBI, Key: header.Key}}
			case "neighbor", "generation":
				index = canonicalForwardLiteral(7, 103, [32]byte{1}, [40]byte{})
				if kind == "generation" {
					index = canonicalForwardLiteral(8, 100, [32]byte{1}, [40]byte{})
				}
				batch.Mutations = append(batch.Mutations, index, canonicalOwnerPairOf(index))
			case "alternate header", "alternate legacy":
				header.Literal = bytes.Repeat([]byte{0x71}, 116)
				hash := sha3.Sum256(header.Literal)
				header.Key = bytes.Clone(hash[:])
				if kind == "alternate legacy" {
					batch.Consulted = []ConsultedRow{{DBI: header.DBI, Key: header.Key}}
				} else {
					batch.Mutations = append(batch.Mutations, header)
				}
			}
			contextSort(batch.Mutations)
			if kind == "neighbor" || kind == "generation" || kind == "alternate header" || kind == "alternate legacy" {
				largeCommit(t, store, batch)
			} else {
				contextRefusal(t, store, batch, "InvalidInput", 22, "invalid Update Batch")
				largeCommit(t, store, Batch{Mutations: []Mutation{consultedCounter(t, 900)}, ContextConsulted: &window})
			}
			contextImages(t, store, rows)
		})
	}
}

// Direct native plans reach final-scope disagreement that public disjointness forbids.
func contextPhases(t *testing.T) {
	for _, row := range []struct {
		name     string
		count    uint32
		position uint32
		rank     uint8
		phase    string
	}{
		{"first index byte103", 3, 0, 2, "readback"},
		{"middle index byte103", 3, 1, 2, "readback"},
		{"last index byte103", 3, 2, 2, "readback"},
		{"first header byte115", 3, 0, 3, "readback"},
		{"middle header byte115", 3, 1, 3, "readback"},
		{"last header byte115", 3, 2, 3, "readback"},
		{"old index mismatch", 3, 0, 2, "old mismatch"},
		{"old header mismatch", 3, 0, 3, "old mismatch"},
		{"retarget last index", 10_080, 10_079, 2, "readback"},
		{"retarget last header", 10_080, 10_079, 3, "readback"},
		{"prewrite equal-width index", 3, 1, 2, "prewrite"},
		{"final index", 3, 1, 2, "final"},
		{"final header", 3, 1, 3, "final"},
		{"OLD", 3, 0, 0, "old"},
		{"NEW", 3, 0, 0, "new"},
		{"neither", 3, 0, 0, "neither"},
		{"both", 3, 0, 0, "both"},
	} {
		t.Run(row.name, func(t *testing.T) {
			store, path, cfg := consultedStore(t)
			window := CanonicalContextWindowV1{9, 0, row.count}
			rows := contextSeed(t, store, window)
			plan := updateNativePlan(t, consultedCounter(t, 900))
			scope, err := updateOwnedContext(&window, plan, largeImageScope{maxKey: 2022})
			mustEnvironment(t, err)
			var outcome updateNativeOutcome
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			mustEnvironment(t, store.View(func(reader *Reader) error {
				if infrastructure, err := contextQualify(reader, plan, scope); infrastructure || err != nil {
					return fmt.Errorf("qualification %v/%w", infrastructure, err)
				}
				change := contextChange(rows, row.position, row.rank)
				if row.phase == "final" {
					change = append(append([]ownedMutation(nil), plan...), change...)
					outcome = store.updateNative(change, nil, reader.txn, scope)
					return nil
				}
				if row.phase == "new" || row.phase == "readback" {
					requireUpdateTruth(t, store.updateNative(plan, nil, reader.txn), 2, true, nil, nil)
				}
				if row.rank != 0 {
					requireUpdateTruth(t, store.updateNative(change, nil, reader.txn), 2, true, nil, nil)
				}
				if row.phase == "prewrite" {
					outcome = store.updateNative(plan, nil, reader.txn, scope)
					return nil
				}
				if row.phase == "neither" {
					third := append([]ownedMutation(nil), plan...)
					third[0].literal = bytes.Repeat([]byte{0x31}, 16)
					requireUpdateTruth(t, store.updateNative(third, nil, reader.txn), 2, true, nil, nil)
				}
				if row.phase == "both" {
					plan = nil
				}
				outcome = updateNativeReadback(store.env, store.dbis, plan, nil, reader.txn, nativeError(operationUpdate, 28), scope)
				return nil
			}))
			contextPhaseOutcome(t, store, outcome, row.phase)
			if row.phase == "final" || row.phase == "prewrite" {
				truth, stage, result := store.applyUpdateOutcome(outcome, nil, nil, false)
				if truth != 1 || stage != outcome.stage || result != store.terminal || string(store.state) != "CLOSED" || store.env != nil || store.writer != nil || store.txn != nil {
					t.Fatal("direct phase terminal resource projection")
				}
				reopened, openErr := Open(path, cfg)
				consultedTrack(t, reopened, openErr)
				if row.phase == "final" {
					contextImages(t, reopened, rows)
				}
				consultedRequireImage(t, reopened, readDBIsLiteral()[0], consultedCounter(t, 900).Key, nil, false, "phase abort target absence")
			}
		})
	}
}

func contextChange(rows []Mutation, position uint32, rank uint8) []ownedMutation {
	if rank == 0 {
		return nil
	}
	row := rows[int(position)*3+int(rank)-2]
	value := bytes.Clone(row.Literal)
	value[len(value)-1] ^= 1
	change := []ownedMutation{{dbi: row.DBI, key: row.Key, beforePresent: true, after: AfterKind(2), literal: value}}
	if rank == 2 {
		owner := rows[int(position)*3+2]
		change = append(change, ownedMutation{dbi: owner.DBI, key: owner.Key, beforePresent: true, after: AfterKind(2), literal: owner.Literal})
	}
	return change
}

func contextPhaseOutcome(t *testing.T, store *Store, outcome updateNativeOutcome, phase string) {
	t.Helper()
	if phase == "prewrite" || phase == "final" {
		diagnostic, stage := "OLD/write snapshot mismatch", UpdateStage(1)
		if phase == "final" {
			diagnostic, stage = "final update image mismatch", 2
		}
		contextError(t, outcome.primary, "StateMismatch", -30779, diagnostic)
		requireUpdateTruth(t, outcome, 1, false, outcome.primary, nil)
		if outcome.stage != stage {
			t.Fatal("phase mismatch stage", outcome.stage)
		}
		return
	}
	want := CommitTruth(3)
	if phase == "old" || phase == "both" {
		want = 1
	}
	if phase == "new" {
		want = 2
	}
	contextError(t, outcome.primary, "Capacity", 28, "error 28")
	requireUpdateTruth(t, outcome, want, true, outcome.primary, nil)
	if outcome.stage != 3 || string(store.state) != "OPEN" {
		t.Fatal("direct readback phase/resource tuple")
	}
}

func contextEarlier(t *testing.T) {
	for _, variant := range []string{"empty plan", "bad mutation", "mutation capacity", "bad legacy", "legacy capacity", "invalid Large", "Large capacity", "invalid Obsolete"} {
		t.Run(variant, func(t *testing.T) {
			store, _, _ := consultedStore(t)
			bad := CanonicalContextWindowV1{0, 0, 10_081}
			batch := Batch{Mutations: []Mutation{consultedCounter(t, 900)}, ContextConsulted: &bad}
			class, code, diagnostic := "InvalidInput", 22, "invalid Update Batch"
			switch variant {
			case "empty plan":
				batch.Mutations = nil
			case "bad mutation":
				batch.Mutations[0].AfterKind = 99
			case "mutation capacity":
				batch.Mutations = updatePlanAuxBatch(t, 16_385).Mutations
				class, code, diagnostic = "Capacity", -30417, "Update Batch exceeds bound"
			case "bad legacy":
				batch.Consulted = []ConsultedRow{{}}
			case "legacy capacity":
				batch.Consulted = consultedRows(t, 16_385)
				class, code, diagnostic = "Capacity", -30417, "Update Batch exceeds bound"
			case "invalid Large":
				batch.LargeConsulted = []LargeImageSelectorV1{{Kind: 99}}
			case "Large capacity":
				batch.LargeConsulted = make([]LargeImageSelectorV1, 2881)
				class, code, diagnostic = "Capacity", -30417, "Update Batch exceeds bound"
			case "invalid Obsolete":
				batch.ObsoleteConsulted = []ObsoletePageWitnessV1{{}}
			}
			contextRefusal(t, store, batch, class, code, diagnostic)
			largeCommit(t, store, Batch{Mutations: []Mutation{consultedCounter(t, 900)}})
		})
	}
}

func contextShape(t *testing.T) {
	typeOf := reflect.TypeFor[CanonicalContextWindowV1]()
	fields := []struct {
		name string
		typ  reflect.Type
	}{{"Generation", reflect.TypeFor[uint64]()}, {"FirstHeight", reflect.TypeFor[uint64]()}, {"Count", reflect.TypeFor[uint32]()}}
	if typeOf.NumField() != len(fields) {
		t.Fatal("descriptor field count")
	}
	for i, field := range fields {
		if typeOf.Field(i).Name != field.name || typeOf.Field(i).Type != field.typ {
			t.Fatal("descriptor API field", i)
		}
	}
	field, ok := reflect.TypeFor[Batch]().FieldByName("ContextConsulted")
	if !ok || field.Type != reflect.TypeFor[*CanonicalContextWindowV1]() {
		t.Fatal("optional Batch context field")
	}
}
