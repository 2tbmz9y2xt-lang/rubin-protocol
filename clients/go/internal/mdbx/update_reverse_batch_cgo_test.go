//go:build cgo && (darwin || linux) && (amd64 || arm64)

package mdbx

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"testing"
)

// reverseBatchKeys lays out count strictly ascending keys of one width over one backing: 44-byte utxo-v1 keys or
// 77-byte undo-v1 entry keys, each ending in its row index as the outpoint vout, so key i of either width binds key i
// of the other width through the frozen SchemaV1 offsets.
func reverseBatchKeys(count, width int) [][]byte {
	backing, keys := make([]byte, width*count), make([][]byte, count)
	for i := range keys {
		key := backing[i*width : (i+1)*width : (i+1)*width]
		if width == 44 {
			binary.BigEndian.PutUint64(key, 1)
			copy(key[8:], reverseTxid[:])
		} else {
			copy(key, reverseBlockHash[:])
			key[32] = 1
			copy(key[41:], reverseTxid[:])
		}
		binary.BigEndian.PutUint32(key[width-4:], uint32(i))
		keys[i] = key
	}
	return keys
}

func reverseBatchDeletes(dbi DBI, keys [][]byte) []Mutation {
	rows := make([]Mutation, len(keys))
	for i, key := range keys {
		rows[i] = Mutation{DBI: dbi, Key: key, BeforePresent: true, AfterKind: AfterAbsent}
	}
	return rows
}

func reverseBatchCommit(t *testing.T, store *Store, marker string, mutations ...Mutation) {
	t.Helper()
	truth, err := store.Update(func(*Reader) (Batch, error) { return Batch{Reverse: true, Mutations: mutations}, nil })
	if truth != CommitTruthNew || err != nil || store.state != storeOPEN || store.terminalTruth != 0 {
		t.Fatalf("%s: %s/%v/%s", marker, truth, err, store.state)
	}
}

// reverseBatchRequireRefusal proves the public batch is refused by admission with the exact direct tuple, leaves the
// Store OPEN, reusable and without terminal truth, expires the Reader and leaves the supplied first row's Key, Literal
// and RefKey bytes unchanged.
func reverseBatchRequireRefusal(t *testing.T, store *Store, marker string, class EngineClass, code int, diagnostic string, batch Batch) {
	t.Helper()
	row := batch.Mutations[0]
	key, literal, refKey := append([]byte(nil), row.Key...), append([]byte(nil), row.Literal...), append([]byte(nil), row.RefKey...)
	var reader *Reader
	truth, err := store.Update(func(observed *Reader) (Batch, error) { reader = observed; return batch, nil })
	engine, direct := directTestEngineError(err)
	row = batch.Mutations[0]
	if truth != CommitTruthOld || !direct || engine.Class != class || engine.Operation != "update" || engine.Code != code ||
		engine.Diagnostic != diagnostic || engine.Cause != nil || engine.ReopenRequired || reader == nil || reader.active.Load() || store.state != storeOPEN ||
		store.terminalTruth != 0 || !bytes.Equal(row.Key, key) || !bytes.Equal(row.Literal, literal) || !bytes.Equal(row.RefKey, refKey) {
		t.Fatalf("%s: %s/%v/%s", marker, truth, err, store.state)
	}
}

func reverseBatchRequireInvalid(t *testing.T, store *Store, marker string, mutations ...Mutation) {
	t.Helper()
	reverseBatchRequireRefusal(t, store, marker, EngineClass("InvalidInput"), 22, "invalid Update Batch", Batch{Reverse: true, Mutations: mutations})
}

// reverseBatchRequireInvalidRow proves true-mode admission refuses row with the exact InvalidInput tuple through
// updateOwnedBatch and charges nothing through updateScanMutation.
func reverseBatchRequireInvalidRow(t *testing.T, marker string, row Mutation) {
	t.Helper()
	requirePlanInvalid(t, Batch{Reverse: true, Mutations: []Mutation{row}}, marker)
	budget := updateBudget{reverse: true}
	if err := updateScanMutation(true, Mutation{}, row, &budget); err == nil || budget != (updateBudget{reverse: true}) {
		t.Fatalf("%s: %v/%+v", marker, err, budget)
	}
}

// reverseBatchRequireCharge runs one direct charge from budget and returns the charged budget; ok selects acceptance
// or the exact Capacity tuple.
func reverseBatchRequireCharge(t *testing.T, marker string, budget updateBudget, row Mutation, ok bool) updateBudget {
	t.Helper()
	err := updateScanMutation(true, Mutation{}, row, &budget)
	if (err == nil) != ok {
		t.Fatalf("%s: want ok=%v, got %v: %+v", marker, ok, err, budget)
	}
	if err != nil {
		requireEnvironmentError(t, err, EngineClass("Capacity"), engineOperation("update"), -30417, "Update Batch exceeds bound")
	}
	return budget
}

// reverseBatchRequireImage proves inside one View that every key holds exactly its want bytes, or that every key is
// absent when want is nil.
func reverseBatchRequireImage(t *testing.T, store *Store, dbi DBI, keys, want [][]byte, marker string) {
	t.Helper()
	mustEnvironment(t, store.View(func(reader *Reader) error {
		for i, key := range keys {
			got, found, err := reader.Get(dbi, key)
			if err != nil || found != (want != nil) || (want != nil && !bytes.Equal(got, want[i])) {
				return fmt.Errorf("%s: row %d found=%v/%w", marker, i, found, err)
			}
		}
		return nil
	}))
}

// reverseBatchRequireTerminal proves the native refusal of a reverse Batch: the exact direct StateMismatch tuple with
// CommitTruthOld, an expired Reader, and a CLOSED Store whose terminal error Update and View return without invoking
// their callbacks.
func reverseBatchRequireTerminal(t *testing.T, store *Store, reader *Reader, truth CommitTruth, err error, code int, diagnostic, marker string) {
	t.Helper()
	engine, direct := directTestEngineError(err)
	if truth != CommitTruthOld || !direct || engine.Class != EngineClass("StateMismatch") || engine.Operation != "update" || engine.Code != code ||
		engine.Diagnostic != diagnostic || engine.Cause != nil || engine.ReopenRequired || reader.active.Load() || store.state != storeCLOSED ||
		store.terminalTruth != CommitTruthOld || !sameError(store.terminal, err) || !validStoreShape(store) {
		t.Fatalf("%s: %s/%v/%s", marker, truth, err, store.state)
	}
	again, cached := store.Update(func(*Reader) (Batch, error) {
		t.Error(marker + ": callback invoked on a terminal Store")
		return Batch{}, nil
	})
	viewErr := store.View(func(*Reader) error { t.Error(marker + ": callback invoked on a terminal Store"); return nil })
	if again != CommitTruthOld || !sameError(cached, err) || !sameError(viewErr, err) {
		t.Fatalf("%s: terminal reuse %s/%v/%v", marker, again, cached, viewErr)
	}
}

func TestUpdateReverseBatchDeletePublic(t *testing.T) {
	const rows = 414_635
	dbi := readDBIsLiteral()[1]
	path, cfg := filepath.Join(t.TempDir(), "db"), environmentConfig()
	store, err := Create(path, cfg)
	mustEnvironment(t, err)
	keys := reverseBatchKeys(rows, 44)
	values, literals := make([][]byte, rows), make([]Mutation, rows)
	for i, key := range keys {
		value, encodeErr := (UTXOValue{}).Encode()
		mustEnvironment(t, encodeErr)
		values[i], literals[i] = value, Mutation{DBI: dbi, Key: key, AfterKind: AfterLiteral, Literal: value}
	}
	requireUpdateCommit(t, store, "reverse batch seed", literals...)
	deletes := reverseBatchDeletes(dbi, keys)
	reverseBatchRequireRefusal(t, store, "default batch UTXO-delete ceiling", EngineClass("Capacity"), -30417, "Update Batch exceeds bound", Batch{Mutations: deletes})
	reverseBatchRequireImage(t, store, dbi, keys, values, "default batch capacity keeps every row")
	truth, err := store.Update(func(*Reader) (Batch, error) { return Batch{Reverse: true, Mutations: deletes}, nil })
	if truth != CommitTruthNew || err != nil || store.state != storeOPEN || store.terminalTruth != 0 {
		t.Fatalf("reverse batch public delete NEW: %s/%v/%s", truth, err, store.state)
	}
	reverseBatchRequireImage(t, store, dbi, keys, nil, "reverse batch public delete removed every row")
	mustEnvironment(t, store.Close())
	store, err = Open(path, cfg)
	mustEnvironment(t, err)
	reverseBatchRequireImage(t, store, dbi, keys, nil, "reverse batch public delete survives reopen")
	mustEnvironment(t, store.Close())
}

func TestUpdateReverseBatchRestoreDeletePublic(t *testing.T) {
	const listed = 16_385
	dbis := readDBIsLiteral()
	path, cfg := filepath.Join(t.TempDir(), "db"), environmentConfig()
	store, err := Create(path, cfg)
	mustEnvironment(t, err)
	targets, sources := reverseBatchKeys(listed+1, 44), reverseBatchKeys(listed+1, 77)
	values, literals := make([][]byte, listed+1), make([]Mutation, listed+1)
	moves := reverseBatchDeletes(dbis[1], targets)
	for i := range values {
		value, encodeErr := (UTXOValue{Value: uint64(i) + 1}).Encode()
		mustEnvironment(t, encodeErr)
		values[i], literals[i] = value, Mutation{DBI: dbis[1], Key: targets[i], AfterKind: AfterLiteral, Literal: value}
		moves = append(moves, forwardRefRow(sources[i], targets[i]))
	}
	requireUpdateCommit(t, store, "reverse batch seed", literals...)
	requireUpdateCommit(t, store, "reverse batch seed", moves...)
	batch := make([]Mutation, 0, 2*listed)
	for i := range listed {
		batch = append(batch, reverseRefRow(targets[i], sources[i]))
	}
	batch = append(batch, reverseBatchDeletes(dbis[5], sources[:listed])...)
	reverseBatchCommit(t, store, "reverse batch restore-delete NEW", batch...)
	for _, reopened := range []bool{false, true} {
		if reopened {
			mustEnvironment(t, store.Close())
			store, err = Open(path, cfg)
			mustEnvironment(t, err)
		}
		marker := fmt.Sprintf("reverse batch restore-delete reopened=%v", reopened)
		reverseBatchRequireImage(t, store, dbis[1], targets[:listed], values[:listed], marker+": exact OLD source bytes")
		reverseBatchRequireImage(t, store, dbis[5], sources[:listed], nil, marker+": listed sources deleted")
		reverseBatchRequireImage(t, store, dbis[5], sources[listed:], values[listed:], marker+": unlisted sibling retained")
		reverseBatchRequireImage(t, store, dbis[1], targets[listed:], nil, marker+": unlisted target untouched")
	}
	mustEnvironment(t, store.Close())
}

func TestUpdateReverseBatchAtomicAbort(t *testing.T) {
	dbis := readDBIsLiteral()
	values := reverseValues(t)
	counter, keyErr := MetaKey(0x10, 3)
	mustEnvironment(t, keyErr)
	before, after := LogicalCounterValue(1, 1), LogicalCounterValue(2, 2)
	t.Run("existing destination after earlier effects", func(t *testing.T) {
		path, cfg := filepath.Join(t.TempDir(), "db"), environmentConfig()
		store, createErr := Create(path, cfg)
		mustEnvironment(t, createErr)
		targetA, sourceA := reverseKeys(t, 1, 1)
		targetB, sourceB := reverseKeys(t, 1, 2)
		requireUpdateCommit(t, store, "reverse batch seed", Mutation{DBI: dbis[0], Key: counter, AfterKind: AfterLiteral, Literal: before})
		reverseSeed(t, store, targetA, sourceA, values[0])
		reverseSeed(t, store, targetB, sourceB, values[1])
		requireUpdateCommit(t, store, "reverse batch seed", Mutation{DBI: dbis[1], Key: targetB, AfterKind: AfterLiteral, Literal: values[1]})
		var reader *Reader
		truth, err := store.Update(func(observed *Reader) (Batch, error) {
			reader = observed
			return Batch{Reverse: true, Mutations: []Mutation{
				{DBI: dbis[0], Key: counter, BeforePresent: true, AfterKind: AfterLiteral, Literal: after},
				reverseRefRow(targetA, sourceA),
				reverseRefRow(targetB, sourceB),
				{DBI: dbis[5], Key: sourceA, BeforePresent: true, AfterKind: AfterAbsent},
			}}, nil
		})
		reverseBatchRequireTerminal(t, store, reader, truth, err, -30799, "MDBX_KEYEXIST: Key/data pair already exists", "reverse batch atomic abort")
		reopened, openErr := Open(path, cfg)
		mustEnvironment(t, openErr)
		requireReverseValue(t, reopened, dbis[0], counter, before, "reverse batch atomic abort: counter at OLD")
		requireUpdateValue(t, reopened, dbis[1], targetA, nil, false)
		requireReverseValue(t, reopened, dbis[1], targetB, values[1], "reverse batch atomic abort: existing destination at OLD")
		requireReverseValue(t, reopened, dbis[5], sourceA, values[0], "reverse batch atomic abort: listed source at OLD")
		requireReverseValue(t, reopened, dbis[5], sourceB, values[1], "reverse batch atomic abort: unlisted source at OLD")
		mustEnvironment(t, reopened.Close())
	})
	t.Run("missing source before existing destination", func(t *testing.T) {
		path, cfg := filepath.Join(t.TempDir(), "db"), environmentConfig()
		store, createErr := Create(path, cfg)
		mustEnvironment(t, createErr)
		target, source := reverseKeys(t, 2, 3)
		requireUpdateCommit(t, store, "reverse batch seed", Mutation{DBI: dbis[1], Key: target, AfterKind: AfterLiteral, Literal: values[2]})
		var reader *Reader
		truth, err := store.Update(func(observed *Reader) (Batch, error) {
			reader = observed
			return Batch{Reverse: true, Mutations: []Mutation{reverseRefRow(target, source)}}, nil
		})
		reverseBatchRequireTerminal(t, store, reader, truth, err, -30779, "OLD_VALUE_REF is absent from OLD", "reverse batch missing source")
		reopened, openErr := Open(path, cfg)
		mustEnvironment(t, openErr)
		requireReverseValue(t, reopened, dbis[1], target, values[2], "reverse batch missing source: destination at OLD")
		requireUpdateValue(t, reopened, dbis[5], source, nil, false)
		mustEnvironment(t, reopened.Close())
	})
}

func TestUpdateReverseBatchDomain(t *testing.T) {
	dbis := readDBIsLiteral()
	values := reverseValues(t)
	target, source := reverseKeys(t, 1, 1)
	counter, keyErr := MetaKey(0x10, 1)
	mustEnvironment(t, keyErr)
	height, keyErr := HeightKey(1, 1)
	mustEnvironment(t, keyErr)
	hashKey, hashValue := updatePlanHashRow()
	manifest, manifestValue := UndoManifestKey(reverseBlockHash), UndoManifestValue(0, [16]byte{}, 0, 0)
	chain := ChainValue([32]byte{}, [32]byte{}, [40]byte{})
	literal := func(dbi DBI, key, value []byte) Mutation {
		return Mutation{DBI: dbi, Key: key, AfterKind: AfterLiteral, Literal: value}
	}
	absent := func(dbi DBI, key []byte) Mutation {
		return Mutation{DBI: dbi, Key: key, BeforePresent: true, AfterKind: AfterAbsent}
	}
	ref := func(dbi DBI, key []byte) Mutation {
		return Mutation{DBI: dbi, Key: key, AfterKind: AfterOldValueRef, RefDBI: dbis[1], RefKey: target}
	}
	replacement := func(m Mutation) Mutation { m.BeforePresent = true; return m }
	for _, cell := range []struct {
		name            string
		row             Mutation
		accept, reverse bool
		label           string
	}{
		{"meta absent", absent(dbis[0], counter), true, true, ""},
		{"meta literal", literal(dbis[0], counter, LogicalCounterValue(0, 0)), true, true, ""},
		{"meta reference", ref(dbis[0], counter), false, false, ""},
		{"utxo absent", absent(dbis[1], target), true, true, ""},
		{"utxo literal", literal(dbis[1], target, values[0]), true, false, "reverse batch rejects UTXO literal"},
		{"utxo reverse reference", reverseRefRow(target, source), true, true, ""},
		{"utxo self reference", ref(dbis[1], target), false, false, ""},
		{"canonical absent", absent(dbis[2], height), true, true, ""},
		{"canonical literal", literal(dbis[2], height, chain), true, true, ""},
		{"canonical reference", ref(dbis[2], height), false, false, ""},
		{"headers absent", absent(dbis[3], hashKey), true, true, ""},
		{"headers literal", literal(dbis[3], hashKey, hashValue), true, true, ""},
		{"headers replacement", replacement(literal(dbis[3], hashKey, hashValue)), false, false, ""},
		{"headers reference", ref(dbis[3], hashKey), false, false, ""},
		{"blocks absent", absent(dbis[4], hashKey), true, true, ""},
		{"blocks literal", literal(dbis[4], hashKey, hashValue), true, true, ""},
		{"blocks replacement", replacement(literal(dbis[4], hashKey, hashValue)), false, false, ""},
		{"blocks reference", ref(dbis[4], hashKey), false, false, ""},
		{"undo manifest absent", absent(dbis[5], manifest), true, true, ""},
		{"undo manifest literal", literal(dbis[5], manifest, manifestValue), true, false, "reverse batch rejects undo manifest literal"},
		{"undo manifest reference", ref(dbis[5], manifest), false, false, ""},
		{"undo entry absent", absent(dbis[5], source), true, true, ""},
		{"undo entry literal", literal(dbis[5], source, values[0]), false, false, ""},
		{"undo entry forward reference", forwardRefRow(source, target), true, false, "reverse batch rejects forward reference"},
		{"undo entry self reference", Mutation{DBI: dbis[5], Key: source, AfterKind: AfterOldValueRef, RefDBI: dbis[5], RefKey: source}, false, false, ""},
		{"staged absent", absent(dbis[6], height), true, true, ""},
		{"staged literal", literal(dbis[6], height, chain), true, true, ""},
		{"staged reference", ref(dbis[6], height), false, false, ""},
	} {
		var defaultPlan []ownedMutation
		for _, reverse := range []bool{false, true} {
			want, label := cell.accept, "reverse batch domain cell"
			if reverse {
				want = cell.reverse
			}
			if cell.label != "" && reverse {
				label = cell.label
			} else if cell.label != "" {
				label = "default batch domain preserved"
			}
			plan, err := updateOwnedBatch(Batch{Reverse: reverse, Mutations: []Mutation{cell.row}})
			if (err == nil) != want || (err == nil) != (len(plan) == 1) {
				t.Fatalf("%s: %s reverse=%v: %d/%v", label, cell.name, reverse, len(plan), err)
			}
			if err != nil {
				requireEnvironmentError(t, err, EngineClass("InvalidInput"), engineOperation("update"), 22, "invalid Update Batch")
			} else if !reverse {
				defaultPlan = plan
			} else if !reflect.DeepEqual(plan, defaultPlan) {
				t.Fatalf("reverse batch same owned plan in both modes: %s: %+v/%+v", cell.name, plan, defaultPlan)
			}
		}
	}
	short := func(key []byte, n int) []byte { return append([]byte(nil), key[:n]...) }
	flip := func(key []byte, at int) []byte { out := append([]byte(nil), key...); out[at] ^= 1; return out }
	tagged := func(key []byte, tag byte) []byte { out := append([]byte(nil), key...); out[32] = tag; return out }
	for _, empty := range []Batch{{Reverse: true}, {Reverse: true, Mutations: []Mutation{}}} {
		requirePlanInvalid(t, empty, "reverse batch common grammar: empty Batch accepted")
	}
	for _, row := range []struct {
		name string
		row  Mutation
	}{
		{"unknown after kind zero", Mutation{DBI: dbis[1], Key: target, BeforePresent: true}},
		{"unknown after kind four", Mutation{DBI: dbis[1], Key: target, BeforePresent: true, AfterKind: 4}},
		{"DBI name", Mutation{DBI: DBI{Name: "utxo-v2", Rank: 1}, Key: target, BeforePresent: true, AfterKind: AfterAbsent}},
		{"DBI rank", Mutation{DBI: DBI{Name: "utxo-v1", Rank: 2}, Key: target, BeforePresent: true, AfterKind: AfterAbsent}},
		{"DBI flags", Mutation{DBI: DBI{Name: "utxo-v1", Rank: 1, Flags: 1}, Key: target, BeforePresent: true, AfterKind: AfterAbsent}},
		{"key nil", absent(dbis[1], nil)},
		{"key 43 bytes", absent(dbis[1], short(target, 43))},
		{"key zero image", absent(dbis[1], append(make([]byte, 8), target[8:]...))},
		{"absent without BeforePresent", Mutation{DBI: dbis[1], Key: target, AfterKind: AfterAbsent}},
		{"absent with literal", Mutation{DBI: dbis[1], Key: target, BeforePresent: true, AfterKind: AfterAbsent, Literal: []byte{}}},
		{"absent with reference DBI", Mutation{DBI: dbis[1], Key: target, BeforePresent: true, AfterKind: AfterAbsent, RefDBI: dbis[5]}},
		{"absent with reference key", Mutation{DBI: dbis[1], Key: target, BeforePresent: true, AfterKind: AfterAbsent, RefKey: source}},
		{"literal nil", Mutation{DBI: dbis[2], Key: height, AfterKind: AfterLiteral}},
		{"literal with reference DBI", Mutation{DBI: dbis[2], Key: height, AfterKind: AfterLiteral, Literal: chain, RefDBI: dbis[1]}},
		{"literal with reference key", Mutation{DBI: dbis[2], Key: height, AfterKind: AfterLiteral, Literal: chain, RefKey: target}},
		{"reference with BeforePresent", Mutation{DBI: dbis[1], Key: target, BeforePresent: true, AfterKind: AfterOldValueRef, RefDBI: dbis[5], RefKey: source}},
		{"reference with literal", Mutation{DBI: dbis[1], Key: target, AfterKind: AfterOldValueRef, Literal: []byte{}, RefDBI: dbis[5], RefKey: source}},
		{"reference key nil", reverseRefRow(target, nil)},
		{"reference outpoint mismatch", reverseRefRow(flip(target, 8), source)},
		{"undo key 76 bytes", absent(dbis[5], short(source, 76))},
		{"undo key 78 bytes", absent(dbis[5], append(short(source, 77), 0))},
		{"undo key 77 bytes tag zero", absent(dbis[5], tagged(source, 0))},
		{"undo key 77 bytes tag two", absent(dbis[5], tagged(source, 2))},
		{"undo key 33 bytes tag one", absent(dbis[5], tagged(manifest, 1))},
	} {
		reverseBatchRequireInvalidRow(t, "reverse batch common grammar: "+row.name, row.row)
	}
	reverseBatchRequireInvalidRow(t, "reverse batch rejects UTXO literal: empty literal", literal(dbis[1], target, []byte{}))
	reverseBatchRequireInvalidRow(t, "reverse batch rejects UTXO literal: schema-invalid literal", literal(dbis[1], target, make([]byte, 19)))
	for _, rank := range []uint8{7, 255} {
		outside := Mutation{DBI: DBI{Name: "utxo-v1", Rank: rank}, BeforePresent: true, AfterKind: AfterAbsent}
		if (&updateBudget{reverse: true}).admits(outside) || !(&updateBudget{}).admits(outside) {
			t.Fatalf("reverse batch admits refuses a rank outside SchemaV1: rank %d", rank)
		}
	}
	t.Run("public", func(t *testing.T) {
		store := newUpdateStore(t)
		counterBefore, counterAfter := LogicalCounterValue(1, 1), LogicalCounterValue(2, 2)
		restoreTarget, restoreSource := reverseKeys(t, 1, 2)
		entryTarget, entrySource := reverseKeys(t, 1, 3)
		staged, stagedErr := HeightKey(1, 2)
		mustEnvironment(t, stagedErr)
		requireUpdateCommit(t, store, "reverse batch seed", literal(dbis[0], counter, counterBefore), literal(dbis[1], target, values[0]), literal(dbis[5], manifest, manifestValue))
		reverseSeed(t, store, restoreTarget, restoreSource, values[1])
		reverseSeed(t, store, entryTarget, entrySource, values[2])
		reverseBatchCommit(t, store, "reverse batch domain NEW",
			replacement(literal(dbis[0], counter, counterAfter)),
			absent(dbis[1], target), reverseRefRow(restoreTarget, restoreSource),
			literal(dbis[2], height, chain), literal(dbis[3], hashKey, hashValue), literal(dbis[4], hashKey, hashValue),
			absent(dbis[5], manifest), absent(dbis[5], entrySource), literal(dbis[6], height, chain))
		requireReverseValue(t, store, dbis[0], counter, counterAfter, "reverse batch domain NEW: counter")
		requireUpdateValue(t, store, dbis[1], target, nil, false)
		requireReverseValue(t, store, dbis[1], restoreTarget, values[1], "reverse batch domain NEW: exact OLD bytes")
		requireReverseValue(t, store, dbis[5], restoreSource, values[1], "reverse batch domain NEW: retained source")
		requireReverseValue(t, store, dbis[2], height, chain, "reverse batch domain NEW: canonical")
		requireReverseValue(t, store, dbis[3], hashKey, hashValue, "reverse batch domain NEW: header")
		requireReverseValue(t, store, dbis[4], hashKey, hashValue, "reverse batch domain NEW: block")
		requireUpdateValue(t, store, dbis[5], manifest, nil, false)
		requireUpdateValue(t, store, dbis[5], entrySource, nil, false)
		requireUpdateValue(t, store, dbis[1], entryTarget, nil, false)
		requireReverseValue(t, store, dbis[6], height, chain, "reverse batch domain NEW: staged")
		reverseBatchCommit(t, store, "reverse batch auxiliary-only NEW", literal(dbis[2], staged, chain))
		requireReverseValue(t, store, dbis[2], staged, chain, "reverse batch auxiliary-only NEW: canonical")
		freshTarget, freshSource := reverseKeys(t, 2, 4)
		otherManifest := UndoManifestKey([32]byte{0x33})
		reverseBatchRequireInvalid(t, store, "reverse batch rejects UTXO literal: public", literal(dbis[1], freshTarget, values[0]))
		requireUpdateValue(t, store, dbis[1], freshTarget, nil, false)
		reverseBatchRequireInvalid(t, store, "reverse batch rejects forward reference: public", forwardRefRow(freshSource, freshTarget))
		requireUpdateValue(t, store, dbis[5], freshSource, nil, false)
		reverseBatchRequireInvalid(t, store, "reverse batch rejects undo manifest literal: public", literal(dbis[5], otherManifest, manifestValue))
		requireUpdateValue(t, store, dbis[5], otherManifest, nil, false)
		requireUpdateCommit(t, store, "default batch domain preserved: public", literal(dbis[1], freshTarget, values[0]))
		requireUpdateCommit(t, store, "default batch domain preserved: public", absent(dbis[1], freshTarget), forwardRefRow(freshSource, freshTarget))
		requireUpdateCommit(t, store, "default batch domain preserved: public", literal(dbis[5], otherManifest, manifestValue))
		requireReverseValue(t, store, dbis[5], freshSource, values[0], "default batch domain preserved: forward reference bytes")
		mustEnvironment(t, store.Close())
	})
}

func TestUpdateReverseBatchBounds(t *testing.T) {
	dbis := readDBIsLiteral()
	target, source := reverseKeys(t, 1, 7)
	utxoDelete := Mutation{DBI: dbis[1], Key: target, BeforePresent: true, AfterKind: AfterAbsent}
	reverse := reverseRefRow(target, source)
	entryDelete := Mutation{DBI: dbis[5], Key: source, BeforePresent: true, AfterKind: AfterAbsent}
	manifestDelete := Mutation{DBI: dbis[5], Key: UndoManifestKey(reverseBlockHash), BeforePresent: true, AfterKind: AfterAbsent}
	auxRow := updatePlanAuxBatch(t, 1).Mutations[0]
	utxoLiteral := Mutation{DBI: dbis[1], Key: target, AfterKind: AfterLiteral, Literal: reverseValues(t)[0]}
	t.Run("UTXO-delete exact", func(t *testing.T) {
		batch := Batch{Reverse: true, Mutations: reverseBatchDeletes(dbis[1], reverseBatchKeys(1_545_454, 44))}
		if plan, err := updateOwnedBatch(batch); err != nil || len(plan) != 1_545_454 {
			t.Fatalf("reverse batch UTXO-delete exact: %d/%v", len(plan), err)
		}
	})
	t.Run("UTXO-delete one-over", func(t *testing.T) {
		batch := Batch{Reverse: true, Mutations: reverseBatchDeletes(dbis[1], reverseBatchKeys(1_545_455, 44))}
		plan, err := updateOwnedBatch(batch)
		if err == nil || plan != nil {
			t.Fatalf("reverse batch UTXO-delete one-over: %d/%v", len(plan), err)
		}
		requireEnvironmentError(t, err, EngineClass("Capacity"), engineOperation("update"), -30417, "Update Batch exceeds bound")
	})
	t.Run("UTXO-delete family", func(t *testing.T) {
		reverseBatchRequireCharge(t, "reverse batch UTXO-delete direct exact", updateBudget{reverse: true, utxoDeletes: 1_545_453}, utxoDelete, true)
		reverseBatchRequireCharge(t, "reverse batch UTXO-delete direct one-over", updateBudget{reverse: true, utxoDeletes: 1_545_454}, utxoDelete, false)
		reverseBatchRequireCharge(t, "reverse batch UTXO-delete overflow", updateBudget{reverse: true, utxoDeletes: ^uint64(0)}, utxoDelete, false)
		if charged := reverseBatchRequireCharge(t, "reverse batch UTXO-delete one charge", updateBudget{reverse: true}, utxoDelete, true); charged != (updateBudget{reverse: true, mutations: 1, keyBytes: 44, utxoDeletes: 1}) {
			t.Fatalf("reverse batch UTXO-delete one charge: %+v", charged)
		}
		reverseBatchRequireCharge(t, "default batch UTXO-delete ceiling", updateBudget{utxoDeletes: 414_634}, utxoDelete, false)
		reverseBatchRequireCharge(t, "default batch UTXO-delete exact", updateBudget{utxoDeletes: 414_633}, utxoDelete, true)
	})
	t.Run("reverse-reference family", func(t *testing.T) {
		bulk := reverseBulkBatch(16_385, false)
		bulk.Reverse = true
		if plan, err := updateOwnedBatch(bulk); err != nil || len(plan) != 16_385 {
			t.Fatalf("reverse batch reverse-ref family above auxiliary: %d/%v", len(plan), err)
		}
		reverseBatchRequireCharge(t, "reverse batch reverse-ref one-over", updateBudget{reverse: true, undoRefs: 414_634}, reverse, false)
		if charged := reverseBatchRequireCharge(t, "reverse batch reverse-ref exact", updateBudget{reverse: true, undoRefs: 414_633}, reverse, true); charged.undoRefs != 414_634 {
			t.Fatalf("reverse batch reverse-ref exact: %+v", charged)
		}
		reverseBatchRequireCharge(t, "reverse batch reverse-ref overflow", updateBudget{reverse: true, undoRefs: ^uint64(0)}, reverse, false)
		if charged := reverseBatchRequireCharge(t, "reverse batch reverse-ref one charge", updateBudget{reverse: true}, reverse, true); charged != (updateBudget{reverse: true, mutations: 1, keyBytes: 121, undoRefs: 1}) {
			t.Fatalf("reverse batch reverse-ref one charge: %+v", charged)
		}
		bulk = reverseBulkBatch(414_635, false)
		bulk.Reverse = true
		requirePlanCapacity(t, bulk)
		reverseBatchRequireCharge(t, "default batch reference ceiling", updateBudget{undoRefs: 414_634}, reverse, false)
	})
	t.Run("undo-entry family", func(t *testing.T) {
		bulk := Batch{Reverse: true, Mutations: reverseBatchDeletes(dbis[5], reverseBatchKeys(16_385, 77))}
		if plan, err := updateOwnedBatch(bulk); err != nil || len(plan) != 16_385 {
			t.Fatalf("reverse batch undo-entry family above auxiliary: %d/%v", len(plan), err)
		}
		reverseBatchRequireCharge(t, "reverse batch undo-entry one-over", updateBudget{reverse: true, undoEntryDeletes: 414_634}, entryDelete, false)
		if charged := reverseBatchRequireCharge(t, "reverse batch undo-entry exact", updateBudget{reverse: true, undoEntryDeletes: 414_633}, entryDelete, true); charged.undoEntryDeletes != 414_634 {
			t.Fatalf("reverse batch undo-entry exact: %+v", charged)
		}
		reverseBatchRequireCharge(t, "reverse batch undo-entry overflow", updateBudget{reverse: true, undoEntryDeletes: ^uint64(0)}, entryDelete, false)
		if charged := reverseBatchRequireCharge(t, "reverse batch undo-entry one charge", updateBudget{reverse: true}, entryDelete, true); charged != (updateBudget{reverse: true, mutations: 1, keyBytes: 77, undoEntryDeletes: 1}) {
			t.Fatalf("reverse batch undo-entry one charge: %+v", charged)
		}
		requirePlanCapacity(t, Batch{Reverse: true, Mutations: reverseBatchDeletes(dbis[5], reverseBatchKeys(414_635, 77))})
		reverseBatchRequireCharge(t, "default batch undo-entry auxiliary ceiling", updateBudget{aux: 16_384}, entryDelete, false)
		if charged := reverseBatchRequireCharge(t, "default batch undo-entry auxiliary", updateBudget{undoEntryDeletes: 414_634}, entryDelete, true); charged != (updateBudget{mutations: 1, keyBytes: 77, undoEntryDeletes: 414_634, aux: 1}) {
			t.Fatalf("default batch undo-entry auxiliary: %+v", charged)
		}
	})
	t.Run("manifest auxiliary", func(t *testing.T) {
		if charged := reverseBatchRequireCharge(t, "reverse batch manifest auxiliary", updateBudget{reverse: true, aux: 16_383, undoEntryDeletes: 414_634}, manifestDelete, true); charged != (updateBudget{reverse: true, mutations: 1, keyBytes: 33, undoEntryDeletes: 414_634, aux: 16_384}) {
			t.Fatalf("reverse batch manifest auxiliary: %+v", charged)
		}
		reverseBatchRequireCharge(t, "reverse batch manifest auxiliary one-over", updateBudget{reverse: true, aux: 16_384}, manifestDelete, false)
	})
	t.Run("key ceiling", func(t *testing.T) {
		reverseBatchRequireCharge(t, "reverse batch key mode", updateBudget{reverse: true, keyBytes: 137_676_154}, utxoDelete, true)
		if charged := reverseBatchRequireCharge(t, "reverse batch key exact", updateBudget{reverse: true, keyBytes: 151_359_076 - 44}, utxoDelete, true); charged.keyBytes != 151_359_076 {
			t.Fatalf("reverse batch key exact: %+v", charged)
		}
		reverseBatchRequireCharge(t, "reverse batch key one-over", updateBudget{reverse: true, keyBytes: 151_359_076 - 43}, utxoDelete, false)
		reverseBatchRequireCharge(t, "reverse batch key overflow", updateBudget{reverse: true, keyBytes: ^uint64(0)}, utxoDelete, false)
		reverseBatchRequireCharge(t, "reverse batch key reference charge", updateBudget{reverse: true, keyBytes: 151_359_076 - 121}, reverse, true)
		reverseBatchRequireCharge(t, "reverse batch key reference one-over", updateBudget{reverse: true, keyBytes: 151_359_076 - 120}, reverse, false)
		reverseBatchRequireCharge(t, "default batch key ceiling", updateBudget{keyBytes: 137_676_154}, utxoDelete, false)
		reverseBatchRequireCharge(t, "default batch key exact", updateBudget{keyBytes: 137_676_154 - 44}, utxoDelete, true)
	})
	t.Run("totals and auxiliary", func(t *testing.T) {
		reverseBatchRequireCharge(t, "reverse batch mutations exact", updateBudget{reverse: true, mutations: 2_391_105}, auxRow, true)
		reverseBatchRequireCharge(t, "reverse batch mutations one-over", updateBudget{reverse: true, mutations: 2_391_106}, auxRow, false)
		reverseBatchRequireCharge(t, "reverse batch mutations overflow", updateBudget{reverse: true, mutations: ^uint64(0)}, auxRow, false)
		reverseBatchRequireCharge(t, "reverse batch literals exact", updateBudget{reverse: true, literals: 155_659_727 - 104}, auxRow, true)
		reverseBatchRequireCharge(t, "reverse batch literals one-over", updateBudget{reverse: true, literals: 155_659_727 - 103}, auxRow, false)
		reverseBatchRequireCharge(t, "reverse batch literals overflow", updateBudget{reverse: true, literals: ^uint64(0)}, auxRow, false)
		reverseBatchRequireCharge(t, "reverse batch auxiliary exact", updateBudget{reverse: true, aux: 16_383}, auxRow, true)
		reverseBatchRequireCharge(t, "reverse batch auxiliary one-over", updateBudget{reverse: true, aux: 16_384}, auxRow, false)
		reverseBatchRequireCharge(t, "reverse batch auxiliary overflow", updateBudget{reverse: true, aux: ^uint64(0)}, auxRow, false)
		if charged := reverseBatchRequireCharge(t, "reverse batch auxiliary one charge", updateBudget{reverse: true}, auxRow, true); charged != (updateBudget{reverse: true, mutations: 1, keyBytes: 16, literals: 104, aux: 1}) {
			t.Fatalf("reverse batch auxiliary one charge: %+v", charged)
		}
		exhausted := updateBudget{reverse: true, utxoLiterals: 1_545_454}
		err := updateScanMutation(true, Mutation{}, utxoLiteral, &exhausted)
		if err == nil || exhausted != (updateBudget{reverse: true, utxoLiterals: 1_545_454}) {
			t.Fatalf("reverse batch UTXO literal never charged: %v/%+v", err, exhausted)
		}
		requireEnvironmentError(t, err, EngineClass("InvalidInput"), engineOperation("update"), 22, "invalid Update Batch")
		aux := updatePlanAuxBatch(t, 16_385)
		aux.Reverse = true
		requirePlanCapacity(t, aux)
	})
	t.Run("public capacity", func(t *testing.T) {
		store := newUpdateStore(t)
		aux := updatePlanAuxBatch(t, 16_385)
		reverseBatchRequireRefusal(t, store, "reverse batch public capacity", EngineClass("Capacity"), -30417, "Update Batch exceeds bound", Batch{Reverse: true, Mutations: aux.Mutations})
		requireUpdateValue(t, store, dbis[2], aux.Mutations[0].Key, nil, false)
		mustEnvironment(t, store.Close())
	})
	t.Run("envelope", func(t *testing.T) {
		if maxUpdateOutputs+maxUpdateInputs+maxUpdateInputs+maxUpdateAux != 2_391_106 || maxUpdateOutputs*44+maxUpdateInputs*121+maxUpdateInputs*77+maxUpdateAux*77 != 151_359_076 ||
			maxReverseKeyBytes != 151_359_076 || maxUpdateMutations != 2_391_106 {
			t.Fatal("reverse batch bounded envelope")
		}
	})
}

func TestUpdateReverseBatchOrder(t *testing.T) {
	dbis := readDBIsLiteral()
	target, source := reverseKeys(t, 1, 5)
	later, laterSource := reverseKeys(t, 2, 5)
	utxoLiteral := Mutation{DBI: dbis[1], Key: target, AfterKind: AfterLiteral, Literal: reverseValues(t)[0]}
	manifestLiteral := Mutation{DBI: dbis[5], Key: UndoManifestKey(reverseBlockHash), AfterKind: AfterLiteral, Literal: UndoManifestValue(0, [16]byte{}, 0, 0)}
	malformed := reverseRefRow(target, append([]byte(nil), source[:76]...))
	invalidChain := updatePlanAuxBatch(t, 1).Mutations[0]
	invalidChain.Literal = invalidChain.Literal[:103]
	exhausted := updateBudget{
		reverse: true, mutations: 2_391_106, keyBytes: 151_359_076, literals: 155_659_727,
		utxoDeletes: 1_545_454, undoRefs: 414_634, undoEntryDeletes: 414_634, utxoLiterals: 1_545_454, aux: 16_384,
	}
	requireUntouched := func(marker string, first bool, previous, row Mutation) {
		t.Helper()
		budget := exhausted
		err := updateScanMutation(first, previous, row, &budget)
		engine, direct := directTestEngineError(err)
		if !direct || engine.Class != EngineClass("InvalidInput") || budget != exhausted {
			t.Fatalf("%s: %v/%+v", marker, err, budget)
		}
		requireEnvironmentError(t, err, EngineClass("InvalidInput"), engineOperation("update"), 22, "invalid Update Batch")
	}
	requireUntouched("reverse batch restriction before charge", true, Mutation{}, utxoLiteral)
	requireUntouched("reverse batch restriction before charge: manifest literal", true, Mutation{}, manifestLiteral)
	requireUntouched("reverse batch restriction before charge: forward reference", true, Mutation{}, forwardRefRow(source, target))
	requireUntouched("reverse batch literal validation before charge", true, Mutation{}, invalidChain)
	requireUntouched("reverse batch malformed row before charge", true, Mutation{}, malformed)
	requireUntouched("reverse batch descending destination before charge", false, reverseRefRow(later, laterSource), reverseRefRow(target, source))
	requireUntouched("reverse batch duplicate destination before charge", false, reverseRefRow(target, source), reverseRefRow(target, source))
	requireUntouched("reverse batch forbidden row out of order", false, reverseRefRow(later, laterSource), utxoLiteral)
	requirePlanInvalid(t, Batch{Reverse: true, Mutations: []Mutation{reverseRefRow(target, source), reverseRefRow(target, source)}}, "reverse batch duplicate destinations accepted")
	requirePlanInvalid(t, Batch{Reverse: true, Mutations: []Mutation{reverseRefRow(later, laterSource), reverseRefRow(target, source)}}, "reverse batch descending destinations accepted")
	for _, tail := range []Mutation{malformed, manifestLiteral, utxoLiteral} {
		batch := updatePlanAuxBatch(t, 16_385)
		batch.Reverse = true
		batch.Mutations = append(batch.Mutations, tail)
		requirePlanCapacity(t, batch)
	}
	t.Run("public tails", func(t *testing.T) {
		store := newUpdateStore(t)
		prefix := updatePlanAuxBatch(t, 16_384).Mutations
		invalidStaged := Mutation{DBI: dbis[6], Key: prefix[0].Key, AfterKind: AfterLiteral, Literal: prefix[0].Literal[:103]}
		reverseBatchRequireInvalid(t, store, "reverse batch restriction before charge: public tail", append(append([]Mutation(nil), prefix...), manifestLiteral)...)
		reverseBatchRequireInvalid(t, store, "reverse batch literal validation before charge: public tail", append(append([]Mutation(nil), prefix...), invalidStaged)...)
		requireUpdateValue(t, store, dbis[2], prefix[0].Key, nil, false)
		mustEnvironment(t, store.Close())
	})
	t.Run("no partial plan", func(t *testing.T) {
		batch := Batch{Reverse: true, Mutations: []Mutation{
			{DBI: dbis[1], Key: target, BeforePresent: true, AfterKind: AfterAbsent},
			reverseRefRow(later, laterSource),
			{DBI: dbis[5], Key: source, BeforePresent: true, AfterKind: AfterAbsent},
			reverseRefRow(later, laterSource),
		}}
		plan, err := updateOwnedBatch(batch)
		if plan != nil || err == nil {
			t.Fatalf("reverse batch no partial plan: %d/%v", len(plan), err)
		}
		requireEnvironmentError(t, err, EngineClass("InvalidInput"), engineOperation("update"), 22, "invalid Update Batch")
	})
}

func TestUpdateReverseBatchOwnership(t *testing.T) {
	dbis := readDBIsLiteral()
	deleteKey, _ := reverseKeys(t, 1, 1)
	target, source := reverseKeys(t, 1, 2)
	_, entry := reverseKeys(t, 1, 3)
	auxRow := updatePlanAuxBatch(t, 1).Mutations[0]
	rows := []Mutation{
		{DBI: dbis[1], Key: append([]byte(nil), deleteKey...), BeforePresent: true, AfterKind: AfterAbsent},
		reverseRefRow(append([]byte(nil), target...), append([]byte(nil), source...)),
		{DBI: dbis[2], Key: append([]byte(nil), auxRow.Key...), AfterKind: AfterLiteral, Literal: append([]byte(nil), auxRow.Literal...)},
		{DBI: dbis[5], Key: append([]byte(nil), entry...), BeforePresent: true, AfterKind: AfterAbsent},
	}
	plan, err := updateOwnedBatch(Batch{Reverse: true, Mutations: rows})
	mustEnvironment(t, err)
	if len(plan) != 4 {
		t.Fatalf("reverse batch owned plan shape: %d", len(plan))
	}
	for i := range rows {
		rows[i].Key[8] ^= 0xff
		if rows[i].Literal != nil {
			rows[i].Literal[0] ^= 0xff
		}
		if rows[i].RefKey != nil {
			rows[i].RefKey[41] ^= 0xff
		}
	}
	if !bytes.Equal(plan[0].key, deleteKey) || !bytes.Equal(plan[1].key, target) || !bytes.Equal(plan[1].refKey, source) ||
		!bytes.Equal(plan[2].key, auxRow.Key) || !bytes.Equal(plan[2].literal, auxRow.Literal) || !bytes.Equal(plan[3].key, entry) {
		t.Fatal("reverse batch owned plan follows caller mutation")
	}
	plan[0].key[8], plan[1].key[8], plan[1].refKey[41], plan[2].key[8], plan[2].literal[0], plan[3].key[8] = 1, 1, 1, 1, 1, 1
	if rows[0].Key[8] != deleteKey[8]^0xff || rows[1].Key[8] != target[8]^0xff || rows[1].RefKey[41] != source[41]^0xff ||
		rows[2].Key[8] != auxRow.Key[8]^0xff || rows[2].Literal[0] != auxRow.Literal[0]^0xff || rows[3].Key[8] != entry[8]^0xff {
		t.Fatal("reverse batch caller input follows plan mutation")
	}
}

func TestUpdateReverseBatchCallbackPrecedence(t *testing.T) {
	dbis := readDBIsLiteral()
	values := reverseValues(t)
	target, source := reverseKeys(t, 1, 6)
	entryTarget, entry := reverseKeys(t, 1, 8)
	cause := errors.New("callback cause")
	var typedNil *EngineError
	for _, row := range []struct {
		name   string
		fail   error
		chain  error
		unwrap bool
	}{
		{"nil", nil, nil, false},
		{"direct error", cause, cause, false},
		{"wrapped direct error", fmt.Errorf("callback: %w", cause), cause, true},
		{"typed nil engine error", error(typedNil), nil, false},
		{"engine error with cause", adapterError(operationUpdate, EngineInvalidInput, codeEINVAL, "callback", cause), cause, true},
	} {
		t.Run(row.name, func(t *testing.T) {
			store := newUpdateStore(t)
			reverseSeed(t, store, target, source, values[0])
			reverseSeed(t, store, entryTarget, entry, values[1])
			batch := []Mutation{reverseRefRow(target, source), {DBI: dbis[5], Key: entry, BeforePresent: true, AfterKind: AfterAbsent}}
			var reader *Reader
			calls := 0
			truth, err := store.Update(func(observed *Reader) (Batch, error) {
				calls, reader = calls+1, observed
				return Batch{Reverse: true, Mutations: batch}, row.fail
			})
			if calls != 1 || reader.active.Load() || store.state != storeOPEN || store.terminalTruth != 0 {
				t.Fatalf("reverse batch callback precedence: %d/%s/%v/%s", calls, truth, err, store.state)
			}
			if row.fail == nil {
				if truth != CommitTruthNew || err != nil {
					t.Fatalf("reverse batch callback nil NEW: %s/%v", truth, err)
				}
				requireReverseValue(t, store, dbis[1], target, values[0], "reverse batch callback nil: exact OLD bytes")
				requireUpdateValue(t, store, dbis[5], entry, nil, false)
				mustEnvironment(t, store.Close())
				return
			}
			//nolint:errorlint // The callback contract returns the caller's exact interface value, so identity is the assertion.
			if truth != CommitTruthOld || err != row.fail || row.chain != nil && !errors.Is(err, row.chain) ||
				row.unwrap && errors.Unwrap(err) != row.chain {
				t.Fatalf("reverse batch callback precedence: %s/%v", truth, err)
			}
			requireUpdateValue(t, store, dbis[1], target, nil, false)
			requireReverseValue(t, store, dbis[5], source, values[0], "reverse batch callback error: retained source")
			requireReverseValue(t, store, dbis[5], entry, values[1], "reverse batch callback error: retained entry")
			reverseBatchCommit(t, store, "reverse batch callback error: reusable Store", batch...)
			requireReverseValue(t, store, dbis[1], target, values[0], "reverse batch callback error: exact OLD bytes")
			requireUpdateValue(t, store, dbis[5], entry, nil, false)
			mustEnvironment(t, store.Close())
		})
	}
}
