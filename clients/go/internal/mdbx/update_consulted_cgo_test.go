//go:build cgo && (darwin || linux) && (amd64 || arm64)

package mdbx

import (
	"bytes"
	"crypto/sha3"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"
)

// consultedCounter returns a fresh meta-v1 logical counter creation, the one mutation every consulted set travels with.
func consultedCounter(t *testing.T, id uint64) Mutation {
	t.Helper()
	key, err := MetaKey(0x10, id)
	mustEnvironment(t, err)
	return Mutation{DBI: readDBIsLiteral()[0], Key: key, AfterKind: AfterLiteral, Literal: LogicalCounterValue(id, id)}
}

// consultedRows returns count strictly ascending canonical-v1 rows over independent key allocations.
func consultedRows(t *testing.T, count int) []ConsultedRow {
	t.Helper()
	rows := make([]ConsultedRow, count)
	for i, mutation := range updatePlanAuxBatch(t, count).Mutations {
		rows[i] = ConsultedRow{DBI: mutation.DBI, Key: mutation.Key}
	}
	return rows
}

// consultedTrack closes store at cleanup unless a native refusal already consumed it.
func consultedTrack(t *testing.T, store *Store, err error) *Store {
	t.Helper()
	mustEnvironment(t, err)
	t.Cleanup(func() {
		if store.state == storeOPEN {
			mustEnvironment(t, store.Close())
		}
	})
	return store
}

func consultedStore(t *testing.T) (*Store, string, ConfigV1) {
	t.Helper()
	path, cfg := filepath.Join(t.TempDir(), "db"), environmentConfig()
	store, err := Create(path, cfg)
	return consultedTrack(t, store, err), path, cfg
}

// consultedReopen closes previous when a skipped subtest left it OPEN, then opens path again.
func consultedReopen(t *testing.T, previous *Store, path string, cfg ConfigV1) *Store {
	t.Helper()
	if previous.state == storeOPEN {
		mustEnvironment(t, previous.Close())
	}
	store, err := Open(path, cfg)
	return consultedTrack(t, store, err)
}

// consultedRequireCommit proves batch commits NEW and leaves the Store OPEN without terminal truth.
func consultedRequireCommit(t *testing.T, store *Store, marker string, batch Batch) {
	t.Helper()
	truth, err := store.Update(func(*Reader) (Batch, error) { return batch, nil })
	if truth != CommitTruthNew || err != nil || store.state != storeOPEN || store.terminalTruth != 0 {
		t.Fatalf("%s: %s/%v/%s", marker, truth, err, store.state)
	}
}

// consultedRequireImage proves one Get returns exactly (want, present): nil/false absent, []byte{}/true present-empty.
func consultedRequireImage(t *testing.T, store *Store, dbi DBI, key, want []byte, present bool, marker string) {
	t.Helper()
	mustEnvironment(t, store.View(func(reader *Reader) error {
		got, found, err := reader.Get(dbi, key)
		if err != nil || found != present || (got == nil) != (want == nil) || !bytes.Equal(got, want) {
			return fmt.Errorf("%s: %d bytes/nil=%v/found=%v/%w", marker, len(got), got == nil, found, err)
		}
		return nil
	}))
}

// consultedRequireOutcome proves the exact direct tuple, CommitTruthOld, an expired Reader and the Store disposition.
func consultedRequireOutcome(t *testing.T, store *Store, reader *Reader, truth CommitTruth, err error, class EngineClass, code int, diagnostic, marker string, terminal bool) {
	t.Helper()
	engine, direct := directTestEngineError(err)
	if truth != CommitTruthOld || !direct || engine.Class != class || engine.Operation != "update" || engine.Code != code ||
		engine.Diagnostic != diagnostic || engine.Cause != nil || engine.ReopenRequired || reader == nil || reader.active.Load() {
		t.Fatalf("%s: %s/%v", marker, truth, err)
	}
	closed := store.state == storeCLOSED && store.terminalTruth == CommitTruthOld && sameError(store.terminal, err) && validStoreShape(store)
	if terminal != closed || !terminal && (store.state != storeOPEN || store.terminalTruth != 0) {
		t.Fatalf("%s: %s/%v", marker, store.state, store.terminal)
	}
}

// consultedRequireRefusal proves Go admission refuses batch with an OPEN Store and unchanged caller-owned consulted rows.
func consultedRequireRefusal(t *testing.T, store *Store, marker string, class EngineClass, code int, diagnostic string, batch Batch) {
	t.Helper()
	before := fmt.Sprint(batch.Consulted)
	var reader *Reader
	truth, err := store.Update(func(observed *Reader) (Batch, error) { reader = observed; return batch, nil })
	consultedRequireOutcome(t, store, reader, truth, err, class, code, diagnostic, marker, false)
	if fmt.Sprint(batch.Consulted) != before {
		t.Fatalf("%s: caller-owned consulted rows changed", marker)
	}
}

// consultedUnit admits rows next to plan through the admission owner alone and returns the owned rows.
func consultedUnit(t *testing.T, marker string, rows []ConsultedRow, plan []ownedMutation) []ownedConsulted {
	t.Helper()
	owned, err := updateOwnedConsulted(Batch{Consulted: rows}, plan)
	if err != nil || len(owned) != len(rows) {
		t.Fatalf("%s: owned=%d err=%v", marker, len(owned), err)
	}
	for i, row := range rows {
		if owned[i].dbi != row.DBI || !bytes.Equal(owned[i].key, row.Key) || owned[i].image != (updateImage{}) {
			t.Fatalf("%s: owned row %d drifted: %+v", marker, i, owned[i])
		}
	}
	return owned
}

// consultedUnitRefusal proves the admission owner refuses rows with the exact Capacity or InvalidInput tuple.
func consultedUnitRefusal(t *testing.T, marker string, rows []ConsultedRow, plan []ownedMutation, capacity bool) {
	t.Helper()
	owned, err := updateOwnedConsulted(Batch{Consulted: rows}, plan)
	if owned != nil || err == nil {
		t.Fatalf("%s: owned=%d err=%v", marker, len(owned), err)
	}
	if capacity {
		requireEnvironmentError(t, err, EngineClass("Capacity"), operationUpdate, -30417, "Update Batch exceeds bound")
		return
	}
	requireEnvironmentError(t, err, EngineClass("InvalidInput"), operationUpdate, 22, "invalid Update Batch")
}

// consultedSeedEmptyMeta stores an empty value under meta-v1 key {2}, the only SchemaV1 key with raw minimum 0.
func consultedSeedEmptyMeta(t *testing.T, store *Store) {
	t.Helper()
	plan := []ownedMutation{{dbi: readDBIsLiteral()[0], key: []byte{2}, after: AfterLiteral, literal: []byte{}}}
	requireUpdateTruth(t, runNativeUpdate(t, store, plan), CommitTruthNew, true, nil, nil)
}

func TestUpdateConsultedImages(t *testing.T) {
	dbis := readDBIsLiteral()
	store, _, _ := consultedStore(t)
	absent, present, chain := consultedRows(t, 7)[6].Key, consultedRows(t, 8)[7].Key, ChainValue([32]byte{3}, [32]byte{4}, [40]byte{5})
	consultedSeedEmptyMeta(t, store)
	consultedRequireCommit(t, store, "images seed", Batch{Mutations: []Mutation{{DBI: dbis[2], Key: present, AfterKind: AfterLiteral, Literal: chain}}})
	t.Run("absent", func(t *testing.T) {
		counter := consultedCounter(t, 1)
		consultedRequireCommit(t, store, "absent consulted row", Batch{Mutations: []Mutation{counter}, Consulted: []ConsultedRow{{DBI: dbis[2], Key: absent}}})
		consultedRequireImage(t, store, dbis[2], absent, nil, false, "absent consulted row")
		consultedRequireImage(t, store, dbis[0], counter.Key, counter.Literal, true, "absent consulted row: mutation applied")
	})
	t.Run("present-empty", func(t *testing.T) {
		consultedRequireCommit(t, store, "present-empty consulted row", Batch{Mutations: []Mutation{consultedCounter(t, 2)}, Consulted: []ConsultedRow{{DBI: dbis[0], Key: []byte{2}}}})
		consultedRequireImage(t, store, dbis[0], []byte{2}, []byte{}, true, "present-empty consulted row")
	})
	t.Run("present-bytes", func(t *testing.T) {
		consultedRequireCommit(t, store, "present-bytes consulted row", Batch{Mutations: []Mutation{consultedCounter(t, 3)}, Consulted: []ConsultedRow{{DBI: dbis[2], Key: present}}})
		consultedRequireImage(t, store, dbis[2], present, chain, true, "present-bytes consulted row")
	})
}

func TestUpdateConsultedAdmission(t *testing.T) {
	dbis := readDBIsLiteral()
	plan := updateNativePlan(t, consultedCounter(t, 1))
	row := func(rank uint8, key []byte) ConsultedRow { return ConsultedRow{DBI: dbis[rank], Key: key} }
	image := func(width int, id uint64) []byte {
		return append(binary.BigEndian.AppendUint64(nil, id), make([]byte, width-8)...)
	}
	t.Run("invalid DBI", func(t *testing.T) {
		for _, dbi := range []DBI{{}, {Name: "utxo-v1", Rank: 2}, {Rank: 7}, {Name: "utxo-v1", Rank: 1, Flags: 1}, {Name: "UTXO-v1", Rank: 1}} {
			consultedUnitRefusal(t, fmt.Sprintf("invalid DBI %+v", dbi), []ConsultedRow{{DBI: dbi, Key: image(44, 1)}}, plan, false)
		}
	})
	t.Run("invalid key", func(t *testing.T) {
		entry, manifest := UndoEntryKey([32]byte{1}, [32]byte{2}, 0, 0, 0), UndoManifestKey([32]byte{1})
		entryTagZero, manifestTagOne := append(append([]byte(nil), entry[:32]...), append([]byte{0}, entry[33:]...)...), append(append([]byte(nil), manifest[:32]...), 1)
		for _, junk := range []ConsultedRow{
			row(1, nil), row(1, []byte{}), row(1, image(43, 1)), row(1, image(45, 1)), row(1, image(44, 0)),
			row(2, image(15, 1)), row(2, image(17, 1)), row(2, image(16, 0)), row(6, image(16, 0)),
			row(3, make([]byte, 31)), row(3, make([]byte, 33)), row(4, make([]byte, 31)), row(4, make([]byte, 33)),
			row(5, entryTagZero), row(5, manifestTagOne), row(5, entry[:76]), row(5, manifest[:32]),
			row(0, []byte{3}), row(0, []byte{0, 0}), row(0, []byte{0x10, 0, 0, 0, 0, 0, 0, 0, 0}), row(0, []byte{0x11, 0, 0, 0, 0, 0, 0, 0, 1}),
		} {
			consultedUnitRefusal(t, fmt.Sprintf("invalid key rank %d %x", junk.DBI.Rank, junk.Key), []ConsultedRow{junk}, plan, false)
		}
	})
	t.Run("duplicate", func(t *testing.T) {
		key := consultedRows(t, 1)[0].Key
		consultedUnitRefusal(t, "duplicate", []ConsultedRow{row(2, key), row(2, append([]byte(nil), key...))}, plan, false)
	})
	t.Run("descending key", func(t *testing.T) {
		consultedUnitRefusal(t, "descending key", []ConsultedRow{row(2, consultedRows(t, 2)[1].Key), row(2, consultedRows(t, 1)[0].Key)}, plan, false)
	})
	t.Run("descending rank", func(t *testing.T) {
		consultedUnitRefusal(t, "descending rank", []ConsultedRow{row(3, make([]byte, 32)), row(2, consultedRows(t, 1)[0].Key)}, plan, false)
	})
	t.Run("same key different DBI ascending", func(t *testing.T) {
		key := consultedRows(t, 1)[0].Key
		consultedUnit(t, "same key different DBI ascending", []ConsultedRow{row(2, key), row(6, key)}, plan)
	})
	t.Run("same key different DBI descending", func(t *testing.T) {
		key := consultedRows(t, 1)[0].Key
		consultedUnitRefusal(t, "same key different DBI descending", []ConsultedRow{row(6, key), row(2, key)}, plan, false)
	})
	t.Run("all widths", func(t *testing.T) {
		mutations, rows := updatePlanBatch(t).Mutations, make([]ConsultedRow, 0, 9)
		for _, i := range []int{0, 1, 2, 4, 5, 6, 7, 8, 9} {
			rows = append(rows, ConsultedRow{DBI: mutations[i].DBI, Key: mutations[i].Key})
		}
		consultedUnit(t, "all widths", rows, updateNativePlan(t, consultedCounter(t, 9)))
	})
	t.Run("overlap target", func(t *testing.T) {
		store, _, _ := consultedStore(t)
		target := ConsultedRow{DBI: plan[0].dbi, Key: append([]byte(nil), plan[0].key...)}
		consultedRequireRefusal(t, store, "overlap target", EngineClass("InvalidInput"), 22, "invalid Update Batch", Batch{Mutations: []Mutation{consultedCounter(t, 1)}, Consulted: []ConsultedRow{target}})
		consultedRequireImage(t, store, target.DBI, target.Key, nil, false, "overlap target: no native work")
	})
	t.Run("overlap reference source", func(t *testing.T) {
		store, _, _ := consultedStore(t)
		target, source := reverseKeys(t, 1, 1)
		reverseSeed(t, store, target, source, reverseValues(t)[0])
		consultedRequireRefusal(t, store, "overlap reference source", EngineClass("InvalidInput"), 22, "invalid Update Batch", Batch{Mutations: []Mutation{reverseRefRow(target, source)}, Consulted: []ConsultedRow{row(5, source)}})
		consultedRequireImage(t, store, dbis[1], target, nil, false, "overlap reference source: no native work")
	})
	t.Run("consulted without mutations", func(t *testing.T) {
		store, _, _ := consultedStore(t)
		for _, batch := range []Batch{{}, {Consulted: []ConsultedRow{}}, {Consulted: []ConsultedRow{row(2, consultedRows(t, 1)[0].Key)}}, {Reverse: true, Consulted: []ConsultedRow{row(2, consultedRows(t, 1)[0].Key)}}} {
			consultedRequireRefusal(t, store, "consulted without mutations", EngineClass("InvalidInput"), 22, "invalid Update Batch", batch)
		}
	})
	t.Run("mutation capacity wins over consulted invalid", func(t *testing.T) {
		store, _, _ := consultedStore(t)
		batch := updatePlanAuxBatch(t, 16_385)
		batch.Consulted = []ConsultedRow{{}}
		consultedRequireRefusal(t, store, "mutation capacity wins over consulted invalid", EngineClass("Capacity"), -30417, "Update Batch exceeds bound", batch)
	})
	t.Run("mutation invalid wins over consulted capacity", func(t *testing.T) {
		store, _, _ := consultedStore(t)
		batch := Batch{Mutations: []Mutation{{DBI: dbis[0], Key: []byte{2}}}, Consulted: consultedRows(t, 16_385)}
		consultedRequireRefusal(t, store, "mutation invalid wins over consulted capacity", EngineClass("InvalidInput"), 22, "invalid Update Batch", batch)
	})
}

func TestUpdateConsultedBounds(t *testing.T) {
	dbis := readDBIsLiteral()
	plan := updateNativePlan(t, consultedCounter(t, 1))
	t.Run("exact 16384 admitted", func(t *testing.T) {
		rows, total := consultedRows(t, 16_384), 0
		for _, owned := range consultedUnit(t, "exact 16384 admitted", rows, plan) {
			total += len(owned.key)
		}
		if total != 262_144 || total > 1_261_568 {
			t.Fatalf("exact 16384 admitted: cloned key bytes %d", total)
		}
		store, _, _ := consultedStore(t)
		consultedRequireCommit(t, store, "exact 16384 admitted", Batch{Mutations: []Mutation{consultedCounter(t, 1)}, Consulted: rows})
		consultedRequireImage(t, store, dbis[2], rows[16_383].Key, nil, false, "exact 16384 admitted: last row untouched")
	})
	t.Run("16385 Capacity", func(t *testing.T) {
		rows := consultedRows(t, 16_385)
		consultedUnitRefusal(t, "16385 Capacity", rows, plan, true)
		store, _, _ := consultedStore(t)
		consultedRequireRefusal(t, store, "16385 Capacity", EngineClass("Capacity"), -30417, "Update Batch exceeds bound", Batch{Mutations: []Mutation{consultedCounter(t, 1)}, Consulted: rows})
	})
	t.Run("invalid 16385th is InvalidInput", func(t *testing.T) {
		rows := consultedRows(t, 16_385)
		rows[16_384].Key = rows[16_384].Key[:15]
		consultedUnitRefusal(t, "invalid 16385th is InvalidInput", rows, plan, false)
	})
	t.Run("valid 16385th then invalid 16386th is Capacity", func(t *testing.T) {
		rows := consultedRows(t, 16_386)
		rows[16_385].Key = rows[16_385].Key[:15]
		consultedUnitRefusal(t, "valid 16385th then invalid 16386th is Capacity", rows, plan, true)
	})
	t.Run("capacity before overlap", func(t *testing.T) {
		rows := consultedRows(t, 16_385)
		overlapping := updateNativePlan(t, Mutation{DBI: dbis[2], Key: consultedRows(t, 1)[0].Key, AfterKind: AfterLiteral, Literal: ChainValue([32]byte{1}, [32]byte{2}, [40]byte{3})})
		consultedUnitRefusal(t, "capacity before overlap", rows, overlapping, true)
		consultedUnitRefusal(t, "capacity before overlap: the overlap alone", rows[:1], overlapping, false)
	})
}

// consultedBlockRow returns one ValidateRow-proven blocks-v1 row whose key depends only on index, not on length.
func consultedBlockRow(t *testing.T, index byte, length int) Mutation {
	t.Helper()
	dbi := readDBIsLiteral()[4]
	value := make([]byte, length)
	value[0] = index
	hash := sha3.Sum256(value[:116])
	mustEnvironment(t, ValidateRow(dbi, hash[:], value))
	return Mutation{DBI: dbi, Key: hash[:], AfterKind: AfterLiteral, Literal: value}
}

func TestUpdateConsultedValueBounds(t *testing.T) {
	dbis := readDBIsLiteral()
	rows := []Mutation{consultedBlockRow(t, 1, 68_000_125), consultedBlockRow(t, 2, 68_000_125), consultedBlockRow(t, 3, 18_610_901)}
	sort.Slice(rows, func(i, j int) bool { return bytes.Compare(rows[i].Key, rows[j].Key) < 0 })
	consulted := make([]ConsultedRow, len(rows))
	for i, row := range rows {
		consulted[i] = ConsultedRow{DBI: row.DBI, Key: row.Key}
	}
	store, path, cfg := consultedStore(t)
	consultedRequireCommit(t, store, "value bounds seed", Batch{Mutations: rows})
	t.Run("exact 154611151 admitted", func(t *testing.T) {
		consultedRequireCommit(t, store, "exact 154611151 admitted", Batch{Mutations: []Mutation{consultedCounter(t, 1)}, Consulted: consulted})
	})
	longer := consultedBlockRow(t, 3, 18_610_902)
	consultedRequireCommit(t, store, "value bounds one-over seed", Batch{Mutations: []Mutation{{DBI: dbis[4], Key: longer.Key, BeforePresent: true, AfterKind: AfterAbsent}}})
	consultedRequireCommit(t, store, "value bounds one-over seed", Batch{Mutations: []Mutation{longer}})
	t.Run("154611152 Capacity", func(t *testing.T) {
		var reader *Reader
		truth, err := store.Update(func(observed *Reader) (Batch, error) {
			reader = observed
			return Batch{Mutations: []Mutation{consultedCounter(t, 2)}, Consulted: consulted}, nil
		})
		consultedRequireOutcome(t, store, reader, truth, err, EngineClass("Capacity"), -30417, "Update Batch exceeds bound", "154611152 Capacity", true)
	})
	reopened := consultedReopen(t, store, path, cfg)
	for i, row := range rows {
		want := row.Literal
		if bytes.Equal(row.Key, longer.Key) {
			want = longer.Literal
		}
		consultedRequireImage(t, reopened, dbis[4], row.Key, want, true, fmt.Sprintf("154611152 Capacity: row %d intact after reopen", i))
	}
	consultedRequireImage(t, reopened, dbis[0], consultedCounter(t, 2).Key, nil, false, "154611152 Capacity: no write")
	t.Run("capacity before snapshot compare", func(t *testing.T) {
		var reader *Reader
		truth, err := reopened.Update(func(observed *Reader) (Batch, error) {
			reader = observed
			requireUpdateTruth(t, reopened.updateNative(updateNativePlan(t, consultedCounter(t, 3)), nil, observed.txn), CommitTruthNew, true, nil, nil)
			return Batch{Mutations: []Mutation{consultedCounter(t, 3)}, Consulted: consulted}, nil
		})
		consultedRequireOutcome(t, reopened, reader, truth, err, EngineClass("Capacity"), -30417, "Update Batch exceeds bound", "capacity before snapshot compare", true)
	})
	again := consultedReopen(t, reopened, path, cfg)
	t.Run("absent source before consulted capacity", func(t *testing.T) {
		target, source := reverseKeys(t, 1, 1)
		var reader *Reader
		truth, err := again.Update(func(observed *Reader) (Batch, error) {
			reader = observed
			return Batch{Mutations: []Mutation{reverseRefRow(target, source)}, Consulted: consulted}, nil
		})
		consultedRequireOutcome(t, again, reader, truth, err, EngineClass("StateMismatch"), -30779, "OLD_VALUE_REF is absent from OLD", "absent source before consulted capacity", true)
	})
}

func TestUpdateConsultedCopyIsolation(t *testing.T) {
	dbis := readDBIsLiteral()
	t.Run("owned after return", func(t *testing.T) {
		plan, rows := updateNativePlan(t, consultedCounter(t, 1)), consultedRows(t, 3)
		owned := consultedUnit(t, "owned after return", rows, plan)
		before := fmt.Sprint(owned)
		for i := range rows {
			rows[i].Key[0], rows[i].Key[15] = rows[i].Key[0]^0xff, rows[i].Key[15]^0xff
		}
		rows[0], rows[2], rows[1].DBI = rows[2], rows[0], DBI{}
		if fmt.Sprint(owned) != before {
			t.Fatalf("owned after return: owned rows drifted: %+v", owned)
		}
	})
	t.Run("aliased backing", func(t *testing.T) {
		target, source := reverseKeys(t, 1, 1)
		backing := append(append(append(make([]byte, 0, 137), target...), source...), consultedRows(t, 9)[8].Key...)
		batch := Batch{Mutations: []Mutation{reverseRefRow(backing[:44], backing[44:121])}, Consulted: []ConsultedRow{{DBI: dbis[6], Key: backing[121:137]}}}
		plan, err := updateOwnedBatch(batch)
		mustEnvironment(t, err)
		owned := consultedUnit(t, "aliased backing", batch.Consulted, plan)
		before := fmt.Sprint(plan, owned)
		for i := range backing {
			backing[i] ^= 0xff
		}
		if fmt.Sprint(plan, owned) != before {
			t.Fatal("aliased backing: owned bytes drifted")
		}
		if owned[0].dbi == plan[0].dbi && bytes.Equal(owned[0].key, plan[0].key) || owned[0].dbi == plan[0].refDBI && bytes.Equal(owned[0].key, plan[0].refKey) {
			t.Fatal("aliased backing: owned rows lost disjointness")
		}
	})
}

func TestUpdateConsultedReverse(t *testing.T) {
	dbis := readDBIsLiteral()
	key := consultedRows(t, 1)[0].Key
	rows := []ConsultedRow{{DBI: dbis[2], Key: key}, {DBI: dbis[6], Key: append([]byte(nil), key...)}}
	forward, err := updateOwnedBatch(Batch{Mutations: []Mutation{consultedCounter(t, 1)}})
	mustEnvironment(t, err)
	reverse, err := updateOwnedBatch(Batch{Reverse: true, Mutations: []Mutation{consultedCounter(t, 1)}})
	mustEnvironment(t, err)
	reverseOwned, err := updateOwnedConsulted(Batch{Reverse: true, Consulted: rows}, reverse)
	mustEnvironment(t, err)
	if !reflect.DeepEqual(reverseOwned, consultedUnit(t, "default admission", rows, forward)) {
		t.Fatalf("reverse changed consulted ownership: %+v", reverseOwned)
	}
	for _, mode := range []bool{false, true} {
		store, _, _ := consultedStore(t)
		chain := ChainValue([32]byte{5}, [32]byte{6}, [40]byte{7})
		consultedRequireCommit(t, store, "reverse seed", Batch{Mutations: []Mutation{{DBI: dbis[2], Key: key, AfterKind: AfterLiteral, Literal: chain}}})
		consultedRequireCommit(t, store, fmt.Sprintf("reverse=%v consulted commit", mode), Batch{Reverse: mode, Mutations: []Mutation{consultedCounter(t, 2)}, Consulted: rows})
		consultedRequireImage(t, store, dbis[2], key, chain, true, fmt.Sprintf("reverse=%v canonical row unchanged", mode))
		consultedRequireImage(t, store, dbis[6], key, nil, false, fmt.Sprintf("reverse=%v staged row unchanged", mode))
		consultedRequireRefusal(t, store, fmt.Sprintf("reverse=%v refuses a duplicate consulted row", mode), EngineClass("InvalidInput"), 22, "invalid Update Batch", Batch{Reverse: mode, Mutations: []Mutation{consultedCounter(t, 3)}, Consulted: []ConsultedRow{rows[0], rows[0]}})
	}
}

func TestUpdateConsultedNilEmpty(t *testing.T) {
	dbis := readDBIsLiteral()
	plan := updateNativePlan(t, consultedCounter(t, 1))
	run := func(t *testing.T, consulted []ConsultedRow) []string {
		t.Helper()
		if owned, err := updateOwnedConsulted(Batch{Consulted: consulted}, plan); owned != nil || err != nil {
			t.Fatalf("empty consulted admission: %v/%v", owned, err)
		}
		store, _, _ := consultedStore(t)
		var outcomes []string
		for _, batch := range []Batch{
			{Mutations: []Mutation{consultedCounter(t, 1)}, Consulted: consulted},
			{Mutations: []Mutation{{DBI: dbis[0], Key: []byte{2}}}, Consulted: consulted},
			{Consulted: consulted},
			{Reverse: true, Mutations: []Mutation{consultedCounter(t, 2)}, Consulted: consulted},
		} {
			truth, err := store.Update(func(*Reader) (Batch, error) { return batch, nil })
			mustEnvironment(t, store.View(func(reader *Reader) error {
				value, found, readErr := reader.Get(dbis[0], consultedCounter(t, 1).Key)
				outcomes = append(outcomes, fmt.Sprintf("%s|%v|%s|%x|%v", truth, err, store.state, value, found))
				return readErr
			}))
		}
		return outcomes
	}
	nilRun, emptyRun := run(t, nil), run(t, []ConsultedRow{})
	committed, refused := "NEW|<nil>|OPEN|00000000000000010000000000000001|true", "OLD|update: InvalidInput: code 22: invalid Update Batch|OPEN|00000000000000010000000000000001|true"
	if !reflect.DeepEqual(nilRun, emptyRun) || !reflect.DeepEqual(nilRun, []string{committed, refused, refused, committed}) {
		t.Fatalf("nil/empty consulted diverged: %q vs %q", nilRun, emptyRun)
	}
}

func TestUpdateConsultedNativeMismatch(t *testing.T) {
	dbis := readDBIsLiteral()
	key := consultedRows(t, 3)[2].Key
	before, after := ChainValue([32]byte{1}, [32]byte{2}, [40]byte{3}), ChainValue([32]byte{9}, [32]byte{10}, [40]byte{11})
	t.Run("snapshot drift", func(t *testing.T) {
		store, path, cfg := consultedStore(t)
		consultedRequireCommit(t, store, "snapshot drift seed", Batch{Mutations: []Mutation{{DBI: dbis[2], Key: key, AfterKind: AfterLiteral, Literal: before}}})
		var reader *Reader
		truth, err := store.Update(func(observed *Reader) (Batch, error) {
			reader = observed
			drift := updateNativePlan(t, Mutation{DBI: dbis[2], Key: key, BeforePresent: true, AfterKind: AfterLiteral, Literal: after})
			requireUpdateTruth(t, store.updateNative(drift, nil, observed.txn), CommitTruthNew, true, nil, nil)
			return Batch{Mutations: []Mutation{consultedCounter(t, 1)}, Consulted: []ConsultedRow{{DBI: dbis[2], Key: key}}}, nil
		})
		consultedRequireOutcome(t, store, reader, truth, err, EngineClass("StateMismatch"), -30779, "OLD/write snapshot mismatch", "snapshot drift", true)
		reopened := consultedReopen(t, store, path, cfg)
		consultedRequireImage(t, reopened, dbis[2], key, after, true, "snapshot drift: sibling commit persisted")
		consultedRequireImage(t, reopened, dbis[0], consultedCounter(t, 1).Key, nil, false, "snapshot drift: no write")
	})
	t.Run("final drift direct", func(t *testing.T) {
		store, _, _ := consultedStore(t)
		consulted := []ownedConsulted{{dbi: dbis[2], key: key}}
		mustEnvironment(t, store.View(func(reader *Reader) error {
			var err error
			consulted[0].image, err = updateNativeImage(reader.txn, store.dbis[2], key)
			return err
		}))
		if consulted[0].image != (updateImage{}) {
			t.Fatalf("final drift direct: captured %+v, want absent", consulted[0].image)
		}
		consultedRequireCommit(t, store, "final drift direct: sibling creates the row", Batch{Mutations: []Mutation{{DBI: dbis[2], Key: key, AfterKind: AfterLiteral, Literal: before}}})
		var matchErr error
		mustEnvironment(t, store.View(func(reader *Reader) error {
			matchErr = updateNativeConsultedMatch(reader.txn, store.dbis, consulted, "final update image mismatch")
			return nil
		}))
		requireEnvironmentError(t, matchErr, EngineStateMismatch, operationUpdate, -30779, "final update image mismatch")
	})
	t.Run("unreadable consulted DBI precommit", func(t *testing.T) {
		store, _, _ := consultedStore(t)
		plan, handles := updateNativePlan(t, consultedCounter(t, 1)), store.dbis
		store.dbis[2] = ^store.dbis[2]
		var outcome updateNativeOutcome
		mustEnvironment(t, store.View(func(reader *Reader) error {
			outcome = store.updateNative(plan, []ownedConsulted{{dbi: dbis[2], key: key}}, reader.txn)
			return outcome.valid()
		}))
		store.dbis = handles
		requireEngineError(t, outcome.primary, EngineLocalInvariant, operationUpdate, -30780)
		requireUpdateTruth(t, outcome, CommitTruthOld, false, outcome.primary, nil)
		consultedRequireImage(t, store, dbis[0], plan[0].key, nil, false, "unreadable consulted DBI precommit: no write")
	})
}

// consultedReadback captures rows' OLD images, commits the NEW-witness target and change, then reads back one plan.
func consultedReadback(t *testing.T, store *Store, rows []ConsultedRow, newWitness, unreadable, malformed bool, change []ownedMutation) (updateNativeOutcome, error) {
	t.Helper()
	untouched, created := updateNativePlan(t, consultedCounter(t, 31)), updateNativePlan(t, consultedCounter(t, 32))
	primary := nativeError(operationUpdate, codeENOSPC)
	var outcome updateNativeOutcome
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	mustEnvironment(t, store.View(func(reader *Reader) error {
		consulted := make([]ownedConsulted, len(rows))
		for i, row := range rows {
			image, err := updateNativeImage(reader.txn, store.dbis[row.DBI.Rank], row.Key)
			if err != nil {
				return err
			}
			consulted[i] = ownedConsulted{dbi: row.DBI, key: row.Key, image: image}
		}
		requireUpdateTruth(t, store.updateNative(created, nil, reader.txn), CommitTruthNew, true, nil, nil)
		if change != nil {
			requireUpdateTruth(t, store.updateNative(change, nil, reader.txn), CommitTruthNew, true, nil, nil)
		}
		plan, handles := untouched, store.dbis
		if newWitness {
			plan = created
		}
		if unreadable {
			handles[2] = ^handles[2]
		}
		if malformed {
			consulted[0].image = updateImage{present: true, length: 1}
		}
		outcome = updateNativeReadback(store.env, handles, plan, consulted, reader.txn, primary)
		return nil
	}))
	return outcome, primary
}

func TestUpdateConsultedReadback(t *testing.T) {
	dbis := readDBIsLiteral()
	present, absent, chain := consultedRows(t, 1)[0].Key, consultedRows(t, 2)[1].Key, ChainValue([32]byte{2}, [32]byte{3}, [40]byte{4})
	rows := []ConsultedRow{{DBI: dbis[0], Key: []byte{2}}, {DBI: dbis[2], Key: present}, {DBI: dbis[2], Key: absent}}
	deletePresent := updateNativePlan(t, Mutation{DBI: dbis[2], Key: present, BeforePresent: true, AfterKind: AfterAbsent})
	createAbsent := updateNativePlan(t, Mutation{DBI: dbis[2], Key: absent, AfterKind: AfterLiteral, Literal: chain})
	for _, row := range []struct {
		name                                         string
		metaBytes, newWitness, unreadable, malformed bool
		change                                       []ownedMutation
		truth                                        CommitTruth
		secondaryCode                                int
	}{
		{"old witness", false, false, false, false, nil, CommitTruthOld, 0},
		{"new witness", false, true, false, false, nil, CommitTruthNew, 0},
		{"consulted absent after old targets", false, false, false, false, deletePresent, CommitTruthUnknown, 0},
		{"consulted absent after new targets", false, true, false, false, deletePresent, CommitTruthUnknown, 0},
		{"present bytes became empty", true, false, false, false, []ownedMutation{{dbi: dbis[0], key: []byte{2}, beforePresent: true, after: AfterLiteral, literal: []byte{}}}, CommitTruthUnknown, 0},
		{"absent became present", false, true, false, false, createAbsent, CommitTruthUnknown, 0},
		{"unreadable consulted DBI", false, false, true, false, nil, CommitTruthUnknown, -30780},
		{"malformed consulted image", false, true, false, true, nil, CommitTruthUnknown, -30779},
	} {
		t.Run(row.name, func(t *testing.T) {
			store, _, _ := consultedStore(t)
			consultedRequireCommit(t, store, row.name+": seed", Batch{Mutations: []Mutation{{DBI: dbis[2], Key: present, AfterKind: AfterLiteral, Literal: chain}}})
			if row.metaBytes {
				consultedRequireCommit(t, store, row.name+": seed", Batch{Mutations: []Mutation{{DBI: dbis[0], Key: []byte{2}, AfterKind: AfterLiteral, Literal: admissionNone()}}})
			} else {
				consultedSeedEmptyMeta(t, store)
			}
			consulted := rows
			if row.unreadable || row.malformed {
				consulted = rows[1:2]
			}
			outcome, primary := consultedReadback(t, store, consulted, row.newWitness, row.unreadable, row.malformed, row.change)
			if row.secondaryCode == 0 {
				requireUpdateTruth(t, outcome, row.truth, true, primary, nil)
				return
			}
			if outcome.valid() != nil || outcome.truth != row.truth || !outcome.commitAttempted || !sameError(outcome.primary, primary) {
				t.Fatalf("%s: %+v", row.name, outcome)
			}
			secondary := requireEngineError(t, outcome.secondary, EngineLocalInvariant, operationUpdate, row.secondaryCode)
			if row.malformed && secondary.Diagnostic != "invalid update image shape" {
				t.Fatalf("%s: secondary %+v", row.name, secondary)
			}
		})
	}
}

func TestUpdateConsultedSourceOwnership(t *testing.T) {
	rowType, ownedType, bytesType := reflect.TypeFor[ConsultedRow](), reflect.TypeFor[ownedConsulted](), reflect.TypeFor[[]byte]()
	if rowType.NumField() != 2 || rowType.Field(0).Name != "DBI" || rowType.Field(0).Type != reflect.TypeFor[DBI]() || rowType.Field(1).Name != "Key" || rowType.Field(1).Type != bytesType ||
		ownedType.NumField() != 3 || ownedType.Field(0).Type != reflect.TypeFor[DBI]() || ownedType.Field(1).Type != bytesType || ownedType.Field(2).Type != reflect.TypeFor[updateImage]() {
		t.Fatal("consulted representation drifted")
	}
	source, err := os.ReadFile("mdbx_cgo.go")
	mustEnvironment(t, err)
	require := func(ok bool, marker string) {
		t.Helper()
		if !ok {
			t.Fatal(marker)
		}
	}
	ordered := func(body, marker string, parts ...string) {
		t.Helper()
		previous := -1
		for _, part := range parts {
			at := strings.Index(body, part)
			if at <= previous {
				t.Fatalf("%s: %q", marker, part)
			}
			previous = at
		}
	}
	require(MaxPrefixPageBytes == 154611151, "prefix-page byte bound drifted")
	require(MaxPrefixPageBytes == MaxOperationDataBytes, "prefix-page byte bound alias drifted")
	text := string(source)
	require(strings.Contains(text, "func updateNativeDeletes(txn *C.MDBX_txn, dbis [7]C.MDBX_dbi, plan []ownedMutation) error {") && strings.Contains(text, "func updateNativePuts(txn *C.MDBX_txn, dbis [7]C.MDBX_dbi, plan []ownedMutation, references []updateReference) error {"), "no-write route signatures drifted")
	for _, name := range []string{"updateNativeDeletes", "updateNativePuts"} {
		require(!strings.Contains(strings.ToLower(updateNativeBody(t, source, name)), "consulted"), "no-write route drifted: "+name)
	}
	execute := updateNativeBody(t, source, "updateNativeExecute")
	ordered(execute, "final verification order drifted", "updateNativePreflight(", "updateNativeDeletes(", "updateNativePuts(", "updateNativeVerify(", "updateNativeConsultedMatch(", "\"final update image mismatch\"", "return updateNativeCommit(")
	require(reflect.DeepEqual(updateNativeCalls(t, source, "updateNativeExecute"), map[string]int{"C.rubin_mdbx_txn_begin": 1, "nativePointerResultError": 1, "int": 1, "updateNativeRetainedWrite": 1, "updateNativeConsumed": 1, "updateNativePreflight": 1, "updateNativeAbort": 5, "updateNativeDeletes": 1, "updateNativePuts": 1, "updateNativeVerify": 1, "updateNativeConsultedMatch": 1, "updateNativeCommit": 1}), "execute call set drifted")
	preflight := updateNativeBody(t, source, "updateNativePreflight")
	ordered(preflight, "snapshot comparison order drifted", "updateNativeImages(", "updateNativeConsultedImages(", "updateNativeMatch(", "if reference.target >= 0", "return references, updateNativeConsultedMatch(")
	require(strings.Count(preflight, "\"OLD/write snapshot mismatch\"") == 3, "snapshot diagnostic drifted")
	ordered(updateNativeBody(t, source, "updateNativeReadbackTruth"), "readback fold order drifted", "updateNativeImages(", "updateNativeReadbackTargets(", "updateNativeReadbackReferences(", "updateNativeReadbackConsulted(", "if oldImage", "if newImage")
	require(strings.Contains(updateNativeBody(t, source, "updateNativeReadbackConsulted"), "oldImage, newImage = oldImage && equal, newImage && equal"), "readback fold drifted")
	for _, name := range []string{"updateNativeConsultedImages", "updateNativeConsultedMatch", "updateNativeReadbackConsulted"} {
		body := updateNativeBody(t, source, name)
		require(!strings.Contains(body, "C.GoBytes") && !strings.Contains(body, "make([]byte") && !strings.Contains(body, "append("), "borrowed consulted bytes were copied: "+name)
	}
	ordered(updateNativeBody(t, source, "updateNativeConsultedImages"), "capture charge drifted", "updateNativeImage(", "if image.present", "updateAdd(total, uint64(image.length), MaxOperationDataBytes)", "updateBoundError()", "consulted[i].image = image")
	ordered(updateNativeBody(t, source, "updateScanConsulted"), "admission order drifted", "ValidateDBI(", "validKey(", "updateKeyOrdered(", "updateAdd(*count, 1, maxUpdateConsulted)")
	ordered(updateNativeBody(t, source, "updateOwnedConsulted"), "clone order drifted", "updateScanConsulted(", "updateConsultedDisjoint(", "updateClone(")
	for _, name := range []string{"updateScanConsulted", "updateConsultedContains", "updateConsultedDisjoint", "updateOwnedConsulted"} {
		body := updateNativeBody(t, source, name)
		require(!strings.Contains(body, "C.") && !strings.Contains(body, "len(row.Key)") && !strings.Contains(body, "KeyBytes"), "admission owner drifted: "+name)
	}
	require(strings.Count(updateNativeBody(t, source, "updateOrdered"), "updateKeyOrdered(") == 1 && strings.Count(text, "bytes.Compare(previousKey, key) < 0") == 1, "second comparator appeared")
	ordered(updateNativeBody(t, source, "updatePlan"), "admission owner order drifted", "updateOwnedBatch(", "updateOwnedConsulted(")
	ordered(updateNativeBody(t, source, "Update"), "consulted transport drifted", "plan, consulted, planErr := s.updatePlan(", "s.updateNative(plan, consulted, begun.txn)", "updateAbortOld(begun.txn)")
}
