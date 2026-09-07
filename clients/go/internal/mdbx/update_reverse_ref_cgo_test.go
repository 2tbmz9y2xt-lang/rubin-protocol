//go:build cgo && (darwin || linux) && (amd64 || arm64)

package mdbx

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
)

var (
	reverseBlockHash = [32]byte{0x11}
	reverseTxid      = [32]byte{0x22}
)

// reverseLiteralKeys lays out the utxo-v1 and undo-v1 entry keys directly from the frozen SchemaV1 offsets, so the
// expected bytes never come from the admission predicate the tests drive.
func reverseLiteralKeys(imageID uint64, block, txid [32]byte, txIndex, inputIndex, vout uint32) ([]byte, []byte) {
	target, source := make([]byte, 44), make([]byte, 77)
	binary.BigEndian.PutUint64(target, imageID)
	copy(target[8:], txid[:])
	binary.BigEndian.PutUint32(target[40:], vout)
	copy(source, block[:])
	source[32] = 1
	binary.BigEndian.PutUint32(source[33:], txIndex)
	binary.BigEndian.PutUint32(source[37:], inputIndex)
	copy(source[41:], txid[:])
	binary.BigEndian.PutUint32(source[73:], vout)
	return target, source
}

func reverseKeys(t *testing.T, imageID uint64, vout uint32) ([]byte, []byte) {
	t.Helper()
	target, err := UTXOKey(imageID, reverseTxid, vout)
	mustEnvironment(t, err)
	return target, UndoEntryKey(reverseBlockHash, reverseTxid, 0, 0, vout)
}

func reverseRefRow(target, source []byte) Mutation {
	dbis := readDBIsLiteral()
	return Mutation{DBI: dbis[1], Key: target, AfterKind: AfterOldValueRef, RefDBI: dbis[5], RefKey: source}
}

func forwardRefRow(source, target []byte) Mutation {
	dbis := readDBIsLiteral()
	return Mutation{DBI: dbis[5], Key: source, AfterKind: AfterOldValueRef, RefDBI: dbis[1], RefKey: target}
}

// reverseValues returns independent UTXOValue encodings at the minimum width, at a non-default small width and at the
// maximum width.
func reverseValues(t *testing.T) [][]byte {
	t.Helper()
	encoded := make([][]byte, 0, 3)
	for _, row := range []UTXOValue{
		{},
		{Value: ^uint64(0), CovenantType: 0xffff, CovenantData: []byte{0x5a, 0x5b, 0x5c}, CreationHeight: ^uint64(0), Coinbase: true},
		{Value: 7, CovenantType: 2, CovenantData: bytes.Repeat([]byte{0x5a}, MaxCovenantBytes), CreationHeight: 9},
	} {
		value, err := row.Encode()
		mustEnvironment(t, err)
		encoded = append(encoded, value)
	}
	return encoded
}

func requireUpdateCommit(t *testing.T, store *Store, marker string, mutations ...Mutation) {
	t.Helper()
	truth, err := store.Update(func(*Reader) (Batch, error) { return Batch{Mutations: mutations}, nil })
	if truth != CommitTruthNew || err != nil || store.state != storeOPEN {
		t.Fatalf("%s: %s/%v/%s", marker, truth, err, store.state)
	}
}

func requireReverseValue(t *testing.T, store *Store, dbi DBI, key, want []byte, marker string) {
	t.Helper()
	mustEnvironment(t, store.View(func(reader *Reader) error {
		got, found, err := reader.Get(dbi, key)
		if err != nil || !found || !bytes.Equal(got, want) {
			return fmt.Errorf("%s: %d bytes/%v/%w", marker, len(got), found, err)
		}
		return nil
	}))
}

// reverseSeed writes value into the utxo row target and then moves it into the undo entry source through the existing
// forward reference, leaving target absent and source holding exactly the seeded bytes.
func reverseSeed(t *testing.T, store *Store, target, source, value []byte) {
	t.Helper()
	dbis := readDBIsLiteral()
	requireUpdateCommit(t, store, "reverse ref seed", Mutation{DBI: dbis[1], Key: target, AfterKind: AfterLiteral, Literal: value})
	requireUpdateCommit(t, store, "reverse ref seed",
		Mutation{DBI: dbis[1], Key: target, BeforePresent: true, AfterKind: AfterAbsent}, forwardRefRow(source, target))
}

func requireReversePlanRejection(t *testing.T, store *Store, marker string, mutations ...Mutation) {
	t.Helper()
	truth, err := store.Update(func(*Reader) (Batch, error) { return Batch{Mutations: mutations}, nil })
	engine, direct := directTestEngineError(err)
	if truth != CommitTruthOld || !direct || engine.Class != EngineInvalidInput || engine.Operation != string(operationUpdate) ||
		engine.Code != codeEINVAL || engine.Diagnostic != "invalid Update Batch" || engine.Cause != nil || engine.ReopenRequired ||
		store.state != storeOPEN || store.terminalTruth != 0 {
		t.Fatalf("%s: %s/%v/%s", marker, truth, err, store.state)
	}
}

func TestUpdateReverseRefTransport(t *testing.T) {
	dbis := readDBIsLiteral()
	for i, value := range reverseValues(t) {
		t.Run(fmt.Sprintf("value-%d-bytes", len(value)), func(t *testing.T) {
			path, cfg := filepath.Join(t.TempDir(), "db"), environmentConfig()
			store, err := Create(path, cfg)
			mustEnvironment(t, err)
			input := append([]byte(nil), value...)
			target, source := reverseKeys(t, uint64(i+1), uint32(i))
			reverseSeed(t, store, target, source, value)
			requireUpdateValue(t, store, dbis[1], target, nil, false)
			requireUpdateCommit(t, store, "reverse ref NEW tuple", reverseRefRow(target, source))
			for _, reopened := range []bool{false, true} {
				if reopened {
					mustEnvironment(t, store.Close())
					store, err = Open(path, cfg)
					mustEnvironment(t, err)
				}
				requireReverseValue(t, store, dbis[1], target, input, "reverse ref exact OLD bytes")
				requireReverseValue(t, store, dbis[5], source, input, "reverse ref retained source bytes")
			}
			mustEnvironment(t, store.Close())
		})
	}
	t.Run("listed source deletion and shared source", func(t *testing.T) {
		store := newUpdateStore(t)
		values := reverseValues(t)
		value, sibling := values[1], values[0]
		target, source := reverseKeys(t, 1, 1)
		siblingTarget, siblingSource := reverseKeys(t, 1, 2)
		secondTarget, _ := reverseKeys(t, 2, 2)
		reverseSeed(t, store, target, source, value)
		reverseSeed(t, store, siblingTarget, siblingSource, sibling)
		requireUpdateCommit(t, store, "reverse ref NEW tuple", reverseRefRow(target, source),
			Mutation{DBI: dbis[5], Key: source, BeforePresent: true, AfterKind: AfterAbsent})
		requireReverseValue(t, store, dbis[1], target, value, "reverse ref exact OLD bytes")
		requireUpdateValue(t, store, dbis[5], source, nil, false)
		requireReverseValue(t, store, dbis[5], siblingSource, sibling, "reverse ref unlisted sibling")
		requireUpdateCommit(t, store, "reverse ref NEW tuple", reverseRefRow(siblingTarget, siblingSource), reverseRefRow(secondTarget, siblingSource))
		requireReverseValue(t, store, dbis[1], siblingTarget, sibling, "reverse ref exact OLD bytes")
		requireReverseValue(t, store, dbis[1], secondTarget, sibling, "reverse ref exact OLD bytes")
		requireReverseValue(t, store, dbis[5], siblingSource, sibling, "reverse ref retained source bytes")
		mustEnvironment(t, store.Close())
	})
}

func TestUpdateReverseRefPayload(t *testing.T) {
	dbis := readDBIsLiteral()
	target, source := reverseKeys(t, 1, 7)
	t.Run("accepted tuples", func(t *testing.T) {
		var ones [32]byte
		for i := range ones {
			ones[i] = 0xff
		}
		for _, row := range []struct {
			name                      string
			imageID                   uint64
			block, txid               [32]byte
			txIndex, inputIndex, vout uint32
		}{
			{"image one, zero witnesses", 1, [32]byte{}, [32]byte{}, 0, 0, 0},
			{"image max, max witnesses", ^uint64(0), ones, ones, ^uint32(0), ^uint32(0), ^uint32(0)},
			{"non-default witnesses", 2, reverseBlockHash, reverseTxid, 7, 9, 3},
		} {
			literalTarget, literalSource := reverseLiteralKeys(row.imageID, row.block, row.txid, row.txIndex, row.inputIndex, row.vout)
			schemaTarget, keyErr := UTXOKey(row.imageID, row.txid, row.vout)
			mustEnvironment(t, keyErr)
			if !bytes.Equal(literalTarget, schemaTarget) ||
				!bytes.Equal(literalSource, UndoEntryKey(row.block, row.txid, row.txIndex, row.inputIndex, row.vout)) {
				t.Fatalf("reverse ref key layout: %s", row.name)
			}
			if !updateValidMutation(reverseRefRow(literalTarget, literalSource)) ||
				!updateValidMutation(forwardRefRow(literalSource, literalTarget)) {
				t.Fatalf("reverse ref accepted tuple: %s", row.name)
			}
		}
	})
	t.Run("direction product", func(t *testing.T) {
		height, keyErr := HeightKey(1, 1)
		mustEnvironment(t, keyErr)
		keys := [7][]byte{{2}, target, height, make([]byte, 32), make([]byte, 32), source, height}
		for destination := range dbis {
			for reference := range dbis {
				row := Mutation{DBI: dbis[destination], Key: keys[destination], AfterKind: AfterOldValueRef,
					RefDBI: dbis[reference], RefKey: keys[reference]}
				want := destination == 5 && reference == 1 || destination == 1 && reference == 5
				if updateValidMutation(row) != want {
					t.Fatalf("reverse ref invalid tuple: direction %d->%d", destination, reference)
				}
			}
		}
	})
	t.Run("one-dimensional witnesses", func(t *testing.T) {
		short := func(key []byte, n int) []byte { return append([]byte(nil), key[:n]...) }
		flip := func(key []byte, at int) []byte { out := append([]byte(nil), key...); out[at] ^= 1; return out }
		tagged := func(tag byte) []byte { out := append([]byte(nil), source...); out[32] = tag; return out }
		zeroImage := append(make([]byte, 8), target[8:]...)
		for _, row := range []struct {
			name     string
			mutation Mutation
		}{
			{"destination DBI name", Mutation{DBI: DBI{Name: "utxo-v2", Rank: 1}, Key: target, AfterKind: AfterOldValueRef, RefDBI: dbis[5], RefKey: source}},
			{"destination DBI flags", Mutation{DBI: DBI{Name: "utxo-v1", Rank: 1, Flags: 1}, Key: target, AfterKind: AfterOldValueRef, RefDBI: dbis[5], RefKey: source}},
			{"destination key nil", reverseRefRow(nil, source)},
			{"destination key empty", reverseRefRow([]byte{}, source)},
			{"destination key 43", reverseRefRow(short(target, 43), source)},
			{"destination key 45", reverseRefRow(append(short(target, 44), 0), source)},
			{"destination image zero", reverseRefRow(zeroImage, source)},
			{"reference DBI name", Mutation{DBI: dbis[1], Key: target, AfterKind: AfterOldValueRef, RefDBI: DBI{Name: "undo-v2", Rank: 5}, RefKey: source}},
			{"reference DBI flags", Mutation{DBI: dbis[1], Key: target, AfterKind: AfterOldValueRef, RefDBI: DBI{Name: "undo-v1", Rank: 5, Flags: 1}, RefKey: source}},
			{"source key nil", reverseRefRow(target, nil)},
			{"source key empty", reverseRefRow(target, []byte{})},
			{"source manifest", reverseRefRow(target, UndoManifestKey(reverseBlockHash))},
			{"source key 76", reverseRefRow(target, short(source, 76))},
			{"source key 78", reverseRefRow(target, append(short(source, 77), 0))},
			{"source tag zero", reverseRefRow(target, tagged(0))},
			{"source tag two", reverseRefRow(target, tagged(2))},
			{"mismatched txid", reverseRefRow(flip(target, 8), source)},
			{"mismatched vout", reverseRefRow(flip(target, 43), source)},
			{"before present", Mutation{DBI: dbis[1], Key: target, BeforePresent: true, AfterKind: AfterOldValueRef, RefDBI: dbis[5], RefKey: source}},
			{"empty literal", Mutation{DBI: dbis[1], Key: target, AfterKind: AfterOldValueRef, Literal: []byte{}, RefDBI: dbis[5], RefKey: source}},
			{"nonempty literal", Mutation{DBI: dbis[1], Key: target, AfterKind: AfterOldValueRef, Literal: []byte{0}, RefDBI: dbis[5], RefKey: source}},
			{"unknown after kind zero", Mutation{DBI: dbis[1], Key: target, AfterKind: 0, RefDBI: dbis[5], RefKey: source}},
			{"unknown after kind four", Mutation{DBI: dbis[1], Key: target, AfterKind: 4, RefDBI: dbis[5], RefKey: source}},
		} {
			keySnapshot := append([]byte(nil), row.mutation.Key...)
			refSnapshot := append([]byte(nil), row.mutation.RefKey...)
			if updateValidMutation(row.mutation) {
				t.Fatalf("reverse ref invalid tuple: %s", row.name)
			}
			if _, err := updateOwnedBatch(Batch{Mutations: []Mutation{row.mutation}}); err == nil {
				t.Fatalf("reverse ref invalid tuple: %s prepared a plan", row.name)
			}
			if !bytes.Equal(row.mutation.Key, keySnapshot) || !bytes.Equal(row.mutation.RefKey, refSnapshot) {
				t.Fatalf("reverse ref invalid tuple: %s mutated the caller keys", row.name)
			}
		}
	})
	t.Run("public rejection", func(t *testing.T) {
		store := newUpdateStore(t)
		value := reverseValues(t)[0]
		counter, keyErr := MetaKey(0x10, 3)
		mustEnvironment(t, keyErr)
		before, after := LogicalCounterValue(1, 1), LogicalCounterValue(2, 2)
		replacement := Mutation{DBI: dbis[0], Key: counter, BeforePresent: true, AfterKind: AfterLiteral, Literal: after}
		requireUpdateCommit(t, store, "reverse ref seed", Mutation{DBI: dbis[0], Key: counter, AfterKind: AfterLiteral, Literal: before})
		reverseSeed(t, store, target, source, value)
		requireReversePlanRejection(t, store, "reverse ref invalid tuple", replacement, reverseRefRow(target, UndoManifestKey(reverseBlockHash)))
		requireReversePlanRejection(t, store, "reverse ref invalid tuple", replacement,
			Mutation{DBI: dbis[1], Key: target, AfterKind: AfterOldValueRef, Literal: []byte{}, RefDBI: dbis[5], RefKey: source})
		requireReverseValue(t, store, dbis[0], counter, before, "reverse ref unchanged counter")
		requireUpdateValue(t, store, dbis[1], target, nil, false)
		requireReverseValue(t, store, dbis[5], source, value, "reverse ref retained source bytes")
		requireUpdateCommit(t, store, "reverse ref NEW tuple", reverseRefRow(target, source))
		requireReverseValue(t, store, dbis[1], target, value, "reverse ref exact OLD bytes")
		mustEnvironment(t, store.Close())
	})
}

// reverseBulkBatch builds count strictly ordered reference rows over one shared key backing; when mixed, the first half
// is reverse and the rest forward.
func reverseBulkBatch(count int, mixed bool) Batch {
	targets, sources, rows := make([]byte, 44*count), make([]byte, 77*count), make([]Mutation, count)
	reverse := count
	if mixed {
		reverse = count / 2
	}
	for i := range rows {
		target := targets[i*44 : i*44+44 : i*44+44]
		source := sources[i*77 : i*77+77 : i*77+77]
		binary.BigEndian.PutUint64(target, 1)
		copy(target[8:], reverseTxid[:])
		binary.BigEndian.PutUint32(target[40:], uint32(i))
		copy(source, reverseBlockHash[:])
		source[32] = 1
		copy(source[41:], reverseTxid[:])
		binary.BigEndian.PutUint32(source[73:], uint32(i))
		if i < reverse {
			rows[i] = reverseRefRow(target, source)
		} else {
			rows[i] = forwardRefRow(source, target)
		}
	}
	return Batch{Mutations: rows}
}

func TestUpdateReverseRefBounds(t *testing.T) {
	dbis := readDBIsLiteral()
	target, source := reverseKeys(t, 1, 7)
	reverse, forward := reverseRefRow(target, source), forwardRefRow(source, target)
	if maxUpdateInputs+maxUpdateInputs+maxUpdateOutputs+maxUpdateAux != maxUpdateMutations ||
		maxUpdateInputs*44+maxUpdateInputs*121+maxUpdateOutputs*44+maxUpdateAux*77 != maxUpdateKeyBytes {
		t.Fatal("reverse ref bounded envelope")
	}
	t.Run("direct charge", func(t *testing.T) {
		budget := updateBudget{}
		mustEnvironment(t, updateScanMutation(true, Mutation{}, reverse, &budget))
		if budget.mutations != 1 || budget.keyBytes != 121 || budget.literals != 0 {
			t.Fatalf("reverse ref key charge: %+v", budget)
		}
		for _, row := range []struct {
			name     string
			budget   updateBudget
			mutation Mutation
			ok       bool
		}{
			{"reverse ref key charge", updateBudget{keyBytes: maxUpdateKeyBytes - 121}, reverse, true},
			{"reverse ref key charge", updateBudget{keyBytes: maxUpdateKeyBytes - 120}, reverse, false},
			{"reverse ref shared count", updateBudget{undoRefs: maxUpdateInputs - 1}, reverse, true},
			{"reverse ref shared count", updateBudget{undoRefs: maxUpdateInputs}, reverse, false},
			{"reverse ref shared count", updateBudget{undoRefs: maxUpdateInputs}, forward, false},
			{"reverse ref keeps utxo deletions", updateBudget{utxoDeletes: maxUpdateInputs}, reverse, true},
			{"reverse ref keeps utxo literals", updateBudget{utxoLiterals: maxUpdateOutputs}, reverse, true},
			{"reverse ref keeps auxiliary", updateBudget{aux: maxUpdateAux}, reverse, true},
		} {
			charged := row.budget
			err := updateScanMutation(true, Mutation{}, row.mutation, &charged)
			if (err == nil) != row.ok {
				t.Fatalf("%s: want ok=%v, got %v: %+v", row.name, row.ok, err, charged)
			}
			if err != nil {
				requireEnvironmentError(t, err, EngineCapacity, operationUpdate, codeTooLarge, "Update Batch exceeds bound")
			}
		}
		for _, rank := range []uint8{0, 2, 3, 4, 6} {
			charged, row := updateBudget{undoRefs: maxUpdateInputs}, reverse
			row.DBI.Rank = rank
			if !charged.addMutation(row) || charged.undoRefs != maxUpdateInputs || charged.aux != 1 {
				t.Fatalf("reverse ref illegal destination rank %d: %+v", rank, charged)
			}
		}
	})
	t.Run("shared reference count", func(t *testing.T) {
		if _, err := updateOwnedBatch(reverseBulkBatch(int(maxUpdateAux)+1, false)); err != nil {
			t.Fatalf("reverse ref bounded plan: %v", err)
		}
		for _, mixed := range []bool{false, true} {
			if _, err := updateOwnedBatch(reverseBulkBatch(int(maxUpdateInputs), mixed)); err != nil {
				t.Fatalf("reverse ref bounded plan: mixed=%v: %v", mixed, err)
			}
			requirePlanCapacity(t, reverseBulkBatch(int(maxUpdateInputs)+1, mixed))
		}
	})
	t.Run("public capacity", func(t *testing.T) {
		store := newUpdateStore(t)
		truth, err := store.Update(func(*Reader) (Batch, error) { return reverseBulkBatch(int(maxUpdateInputs)+1, false), nil })
		engine, direct := directTestEngineError(err)
		if truth != CommitTruthOld || !direct || engine.Class != EngineCapacity || engine.Operation != string(operationUpdate) ||
			engine.Code != codeTooLarge || engine.Diagnostic != "Update Batch exceeds bound" || engine.Cause != nil ||
			engine.ReopenRequired || store.state != storeOPEN || store.terminalTruth != 0 {
			t.Fatalf("reverse ref public capacity tuple: %s/%v/%s", truth, err, store.state)
		}
		requireUpdateValue(t, store, dbis[1], target, nil, false)
		mustEnvironment(t, store.Close())
	})
}

func TestUpdateReverseRefOwnership(t *testing.T) {
	target, source := reverseKeys(t, 1, 7)
	callerTarget, callerSource := append([]byte(nil), target...), append([]byte(nil), source...)
	plan, err := updateOwnedBatch(Batch{Mutations: []Mutation{reverseRefRow(callerTarget, callerSource)}})
	mustEnvironment(t, err)
	if len(plan) != 1 || !bytes.Equal(plan[0].key, target) || !bytes.Equal(plan[0].refKey, source) {
		t.Fatal("reverse ref owned RefKey: prepared bytes")
	}
	callerTarget[8], callerSource[41] = 0xfe, 0xfe
	if !bytes.Equal(plan[0].key, target) || !bytes.Equal(plan[0].refKey, source) {
		t.Fatal("reverse ref owned RefKey")
	}
	plan[0].key[8], plan[0].refKey[41] = 0xfd, 0xfd
	if callerTarget[8] != 0xfe || callerSource[41] != 0xfe {
		t.Fatal("reverse ref owned RefKey")
	}
}

func TestUpdateReverseRefNativeMismatch(t *testing.T) {
	dbis := readDBIsLiteral()
	values := reverseValues(t)
	counter, keyErr := MetaKey(0x10, 3)
	mustEnvironment(t, keyErr)
	before, after := LogicalCounterValue(1, 1), LogicalCounterValue(2, 2)
	for _, row := range []struct {
		name        string
		code        int
		diagnostic  string
		targetValue []byte
		rows        func(target, source, second []byte) []Mutation
	}{
		{"absent source", codeProblem, "OLD_VALUE_REF is absent from OLD", nil, func(target, source, _ []byte) []Mutation {
			return []Mutation{reverseRefRow(target, source)}
		}},
		{"source scheduled for creation", codeProblem, "OLD_VALUE_REF is absent from OLD", nil, func(target, source, second []byte) []Mutation {
			return []Mutation{reverseRefRow(target, source), forwardRefRow(source, second)}
		}},
		{"existing target, equal bytes", codeKeyExist, expectedNativeDiagnostic(codeKeyExist), values[1], nil},
		{"existing target, different bytes", codeKeyExist, expectedNativeDiagnostic(codeKeyExist), values[0], nil},
	} {
		t.Run(row.name, func(t *testing.T) {
			path, cfg := filepath.Join(t.TempDir(), "db"), environmentConfig()
			store, createErr := Create(path, cfg)
			mustEnvironment(t, createErr)
			target, source := reverseKeys(t, 1, 4)
			second, _ := reverseKeys(t, 2, 4)
			requireUpdateCommit(t, store, "reverse ref seed", Mutation{DBI: dbis[0], Key: counter, AfterKind: AfterLiteral, Literal: before})
			mutations := []Mutation{{DBI: dbis[0], Key: counter, BeforePresent: true, AfterKind: AfterLiteral, Literal: after}}
			if row.rows != nil {
				requireUpdateCommit(t, store, "reverse ref seed", Mutation{DBI: dbis[1], Key: second, AfterKind: AfterLiteral, Literal: values[1]})
				mutations = append(mutations, row.rows(target, source, second)...)
			} else {
				reverseSeed(t, store, target, source, values[1])
				requireUpdateCommit(t, store, "reverse ref seed", Mutation{DBI: dbis[1], Key: target, AfterKind: AfterLiteral, Literal: row.targetValue})
				mutations = append(mutations, reverseRefRow(target, source))
			}
			var reader *Reader
			truth, err := store.Update(func(observed *Reader) (Batch, error) { reader = observed; return Batch{Mutations: mutations}, nil })
			engine, direct := directTestEngineError(err)
			if truth != CommitTruthOld || !direct || engine.Class != EngineStateMismatch || engine.Operation != string(operationUpdate) ||
				engine.Code != row.code || engine.Diagnostic != row.diagnostic || engine.Cause != nil || engine.ReopenRequired ||
				reader.active.Load() || store.state != storeCLOSED || store.terminalTruth != CommitTruthOld ||
				!sameError(store.terminal, err) || !validStoreShape(store) {
				t.Fatalf("reverse ref native tuple: %s/%v/%s", truth, err, store.state)
			}
			if again, cached := store.Update(func(*Reader) (Batch, error) {
				t.Error("reverse ref native tuple: callback invoked on a terminal Store")
				return Batch{}, nil
			}); again != CommitTruthOld || !sameError(cached, err) {
				t.Fatalf("reverse ref native tuple: terminal reuse %s/%v", again, cached)
			}
			if viewErr := store.View(func(*Reader) error {
				t.Error("reverse ref native tuple: callback invoked on a terminal Store")
				return nil
			}); !sameError(viewErr, err) {
				t.Fatalf("reverse ref native tuple: terminal reuse %v", viewErr)
			}
			var sourceValue []byte
			if row.rows == nil {
				sourceValue = values[1]
			}
			reopened, openErr := Open(path, cfg)
			mustEnvironment(t, openErr)
			requireReverseValue(t, reopened, dbis[0], counter, before, "reverse ref rolled back earlier write")
			requireUpdateValue(t, reopened, dbis[1], target, row.targetValue, row.targetValue != nil)
			requireUpdateValue(t, reopened, dbis[5], source, sourceValue, sourceValue != nil)
			mustEnvironment(t, reopened.Close())
		})
	}
}

func TestUpdateReverseRefOrder(t *testing.T) {
	dbis := readDBIsLiteral()
	values := reverseValues(t)
	target, source := reverseKeys(t, 1, 5)
	t.Run("missing source before existing target", func(t *testing.T) {
		store := newUpdateStore(t)
		requireUpdateCommit(t, store, "reverse ref seed", Mutation{DBI: dbis[1], Key: target, AfterKind: AfterLiteral, Literal: values[0]})
		truth, err := store.Update(func(*Reader) (Batch, error) { return Batch{Mutations: []Mutation{reverseRefRow(target, source)}}, nil })
		engine, direct := directTestEngineError(err)
		if truth != CommitTruthOld || !direct || engine.Code != codeProblem || engine.Diagnostic != "OLD_VALUE_REF is absent from OLD" {
			t.Fatalf("reverse ref first failure: %s/%v", truth, err)
		}
	})
	t.Run("malformed row before its own capacity charge", func(t *testing.T) {
		budget := updateBudget{undoRefs: maxUpdateInputs}
		malformed := reverseRefRow(target, append([]byte(nil), source[:76]...))
		err := updateScanMutation(true, Mutation{}, malformed, &budget)
		requireEnvironmentError(t, err, EngineInvalidInput, operationUpdate, codeEINVAL, "invalid Update Batch")
		if budget.undoRefs != maxUpdateInputs {
			t.Fatalf("reverse ref first failure: %+v", budget)
		}
	})
	t.Run("earlier capacity before a malformed tail", func(t *testing.T) {
		batch := updatePlanAuxBatch(t, int(maxUpdateAux)+1)
		batch.Mutations = append(batch.Mutations, reverseRefRow(target, append([]byte(nil), source[:76]...)))
		requirePlanCapacity(t, batch)
	})
	t.Run("duplicate and out-of-order destinations", func(t *testing.T) {
		requirePlanInvalid(t, Batch{Mutations: []Mutation{reverseRefRow(target, source), reverseRefRow(target, source)}},
			"reverse ref first failure: duplicate destination accepted")
		later, laterSource := reverseKeys(t, 2, 5)
		requirePlanInvalid(t, Batch{Mutations: []Mutation{reverseRefRow(later, laterSource), reverseRefRow(target, source)}},
			"reverse ref first failure: descending destinations accepted")
	})
}

func TestUpdateReverseRefCallbackPrecedence(t *testing.T) {
	dbis := readDBIsLiteral()
	value := reverseValues(t)[0]
	target, source := reverseKeys(t, 1, 6)
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
			reverseSeed(t, store, target, source, value)
			var reader *Reader
			calls := 0
			truth, err := store.Update(func(observed *Reader) (Batch, error) {
				calls, reader = calls+1, observed
				return Batch{Mutations: []Mutation{reverseRefRow(target, source)}}, row.fail
			})
			if calls != 1 || reader.active.Load() || store.state != storeOPEN || store.terminalTruth != 0 {
				t.Fatalf("reverse ref callback precedence: %d/%s/%v/%s", calls, truth, err, store.state)
			}
			if row.fail == nil {
				if truth != CommitTruthNew || err != nil {
					t.Fatalf("reverse ref NEW tuple: %s/%v", truth, err)
				}
				requireReverseValue(t, store, dbis[1], target, value, "reverse ref exact OLD bytes")
				mustEnvironment(t, store.Close())
				return
			}
			//nolint:errorlint // The callback contract returns the caller's exact interface value, so identity is the assertion.
			if truth != CommitTruthOld || err != row.fail || row.chain != nil && !errors.Is(err, row.chain) ||
				row.unwrap && errors.Unwrap(err) != row.chain {
				t.Fatalf("reverse ref callback precedence: %s/%v", truth, err)
			}
			requireUpdateValue(t, store, dbis[1], target, nil, false)
			requireReverseValue(t, store, dbis[5], source, value, "reverse ref retained source bytes")
			requireUpdateCommit(t, store, "reverse ref NEW tuple", reverseRefRow(target, source))
			requireReverseValue(t, store, dbis[1], target, value, "reverse ref exact OLD bytes")
			mustEnvironment(t, store.Close())
		})
	}
}
