//go:build cgo && (darwin || linux) && (amd64 || arm64)

package mdbx

import (
	"bytes"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"
)

// bootstrapEmptyCounts and bootstrapInitializedCounts are the SchemaV1 entry counts of an
// exact-empty store and of one this method has initialized.
var bootstrapEmptyCounts, bootstrapInitializedCounts = [7]uint64{2, 0, 0, 0, 0, 0, 0}, [7]uint64{4, 0, 0, 0, 0, 0, 0}

func bootstrapMetaDBI() DBI { return readDBIsLiteral()[0] }

func bootstrapOwner(t *testing.T) *OperationReservationOwner {
	t.Helper()
	return reservationOwner(t, MaxOperationDataBytes)
}

// bootstrapCounterKey is meta 0x10 || big-endian generation 1, written out independently
// of MetaKey so a constructor change cannot silently move the counter.
func bootstrapCounterKey() []byte { return []byte{0x10, 0, 0, 0, 0, 0, 0, 0, 1} }

// bootstrapImage is the exact 40-byte initial authority for profile, specified byte by
// byte here rather than by re-encoding the production constructor.
func bootstrapImage(profile byte) []byte {
	return []byte{
		1, profile, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 2, 1, 1, 0, 0, 0, 0,
	}
}

// bootstrapRefusal asserts the whole public refusal tuple: CommitTruthOld plus the exact
// direct EngineError six-tuple, so a wrapped, joined or reclassified error cannot pass.
func bootstrapRefusal(t *testing.T, marker string, truth CommitTruth, err error, class EngineClass, operation engineOperation, code int, diagnostic string, cause error, reopen bool) {
	t.Helper()
	engine, direct := directTestEngineError(err)
	if truth != CommitTruthOld || !direct || engine.Class != class || engine.Operation != string(operation) || engine.Code != code ||
		engine.Diagnostic != diagnostic || !sameError(engine.Cause, cause) || engine.ReopenRequired != reopen {
		t.Fatalf("%s: truth=%s err=%+v", marker, truth, err)
	}
}

// bootstrapNonempty asserts the exact-empty precondition refusal.
func bootstrapNonemptyRefusal(t *testing.T, marker string, truth CommitTruth, err error) {
	t.Helper()
	bootstrapRefusal(t, marker, truth, err, EngineStateMismatch, operationUpdate, codeProblem, "bootstrap requires exact-empty store", nil, false)
}

// bootstrapOpenUnchanged asserts a refusal left the Store open, reusable and free of
// terminal truth.
func bootstrapOpenUnchanged(t *testing.T, store *Store, marker string) {
	t.Helper()
	if store.state != storeOPEN || store.terminal != nil || store.terminalTruth != 0 {
		t.Fatalf("%s: %s/%v/%s", marker, store.state, store.terminal, store.terminalTruth)
	}
}

func bootstrapCounts(t *testing.T, store *Store, marker string) [7]uint64 {
	t.Helper()
	inspection, err := store.Inspect()
	if err != nil {
		t.Fatalf("%s: %v", marker, err)
	}
	var counts [7]uint64
	for rank, dbi := range inspection.DBIs {
		counts[rank] = dbi.Entries
	}
	return counts
}

func bootstrapRow(t *testing.T, store *Store, key []byte) ([]byte, bool) {
	t.Helper()
	var value []byte
	var present bool
	mustEnvironment(t, store.View(func(reader *Reader) error {
		var err error
		value, present, err = reader.Get(bootstrapMetaDBI(), key)
		return err
	}))
	return value, present
}

func bootstrapRequireRow(t *testing.T, store *Store, key, want []byte, marker string) {
	t.Helper()
	value, present := bootstrapRow(t, store, key)
	if present != (want != nil) || !bytes.Equal(value, want) {
		t.Fatalf("%s: row %x=%x/%v, want %x", marker, key, value, present, want)
	}
}

// bootstrapRequireInitialized proves the whole committed image: the two untouched
// required rows, the exact authority literal and its decoded fields, the zero counter in
// bytes and decoded entries, four metadata rows and six empty data DBIs.
func bootstrapRequireInitialized(t *testing.T, store *Store, cfg ConfigV1, profile StorageProfileV1, marker string) {
	t.Helper()
	encoded, err := cfg.Encode()
	mustEnvironment(t, err)
	bootstrapRequireRow(t, store, []byte{0}, SchemaVersionValue(), marker+": version")
	bootstrapRequireRow(t, store, []byte{1}, encoded, marker+": config")
	bootstrapRequireRow(t, store, []byte{2}, bootstrapImage(byte(profile)), marker+": authority")
	bootstrapRequireRow(t, store, bootstrapCounterKey(), make([]byte, 16), marker+": counter")
	authority, _ := bootstrapRow(t, store, []byte{2})
	decoded, decodeErr := DecodeStorageAuthorityV1(authority)
	mustEnvironment(t, decodeErr)
	if decoded != modelBase(byte(profile), 0, 0) {
		t.Fatalf("%s: authority=%+v", marker, decoded)
	}
	counter, _ := bootstrapRow(t, store, bootstrapCounterKey())
	logical, entries, counterErr := DecodeLogicalCounterValue(counter)
	mustEnvironment(t, counterErr)
	if logical != 0 || entries != 0 {
		t.Fatalf("%s: counter=%d/%d", marker, logical, entries)
	}
	if counts := bootstrapCounts(t, store, marker); counts != bootstrapInitializedCounts {
		t.Fatalf("%s: counts=%v", marker, counts)
	}
}

// bootstrapForge applies plan straight to the native writer of an open store. It is the
// only in-package route to a wrong or missing required metadata row, because Batch
// admission refuses meta keys 00 and 01 outright (updateMutableMeta).
func bootstrapForge(t *testing.T, store *Store, plan []ownedMutation) {
	t.Helper()
	requireUpdateTruth(t, runNativeUpdate(t, store, plan), CommitTruthNew, true, nil, nil)
}

// bootstrapSpareCounter is a valid extra metadata row that keeps the meta cardinality at
// two while a required row is deleted, so the census cannot preempt the metadata refusal.
func bootstrapSpareCounter() ownedMutation {
	return ownedMutation{dbi: bootstrapMetaDBI(), key: []byte{0x10, 0, 0, 0, 0, 0, 0, 0, 5}, after: AfterLiteral, literal: LogicalCounterValue(0, 0)}
}

func bootstrapReplaceMeta(key, literal []byte) ownedMutation {
	return ownedMutation{dbi: bootstrapMetaDBI(), key: key, beforePresent: true, after: AfterLiteral, literal: literal}
}

func bootstrapDeleteMeta(key []byte) ownedMutation {
	return ownedMutation{dbi: bootstrapMetaDBI(), key: key, beforePresent: true, after: AfterAbsent}
}

// bootstrapRequireTerminal proves an infrastructure failure ended the existing lifecycle:
// the Store is consumed with a shape-valid CommitTruthOld terminal that is the same object
// the call returned, and the next Update and View return it without invoking a callback.
func bootstrapRequireTerminal(t *testing.T, store *Store, err error, marker string) {
	t.Helper()
	if store.state != storeCLOSED || store.terminalTruth != CommitTruthOld || !sameError(store.terminal, err) || !validStoreShape(store) {
		t.Fatalf("%s: %s/%s/%v", marker, store.state, store.terminalTruth, store.terminal)
	}
	nextTruth, nextErr := store.Update(func(*Reader) (Batch, error) {
		t.Fatalf("%s: Update callback invoked", marker)
		return Batch{}, nil
	})
	viewErr := store.View(func(*Reader) error { t.Fatalf("%s: View callback invoked", marker); return nil })
	if nextTruth != CommitTruthOld || !sameError(nextErr, err) || !sameError(viewErr, err) || !sameError(store.Close(), err) {
		t.Fatalf("%s: cached %s/%v/%v", marker, nextTruth, nextErr, viewErr)
	}
}

func bootstrapSource(t *testing.T) []byte {
	t.Helper()
	source, err := os.ReadFile("bootstrap_cgo.go")
	mustEnvironment(t, err)
	return source
}

func TestStorageBootstrapInput(t *testing.T) {
	owner := bootstrapOwner(t)
	var absent *Store
	for _, row := range []struct {
		name       string
		store      *Store
		profile    StorageProfileV1
		owner      *OperationReservationOwner
		diagnostic string
	}{
		{"nil Store", absent, StorageProfilePrunedV1, owner, "nil Store"},
		{"nil Store before profile", absent, 0, owner, "nil Store"},
		{"nil Store before owner", absent, 0, nil, "nil Store"},
		{"profile 0", newUpdateStore(t), 0, owner, "invalid bootstrap profile"},
		{"profile 3", newUpdateStore(t), 3, owner, "invalid bootstrap profile"},
		{"profile 255", newUpdateStore(t), 255, owner, "invalid bootstrap profile"},
		{"profile before nil owner", newUpdateStore(t), 3, nil, "invalid bootstrap profile"},
		{"profile before zero owner", newUpdateStore(t), 3, &OperationReservationOwner{}, "invalid bootstrap profile"},
	} {
		t.Run(row.name, func(t *testing.T) {
			truth, err := row.store.BootstrapStorageV1(row.profile, row.owner)
			bootstrapRefusal(t, row.name, truth, err, EngineInvalidInput, operationUpdate, codeEINVAL, row.diagnostic, nil, false)
			if reservationLive(owner) != 0 {
				t.Fatalf("%s: live=%d", row.name, reservationLive(owner))
			}
			if row.store != nil {
				bootstrapOpenUnchanged(t, row.store, row.name)
				bootstrapRequireRow(t, row.store, []byte{2}, nil, row.name)
			}
		})
	}
	// A held operations lock proves the static guards invoke no Store method: reaching
	// Store.Update would return the busy tuple instead of the input refusal.
	locked := newUpdateStore(t)
	locked.operations.Lock()
	truth, err := locked.BootstrapStorageV1(3, owner)
	locked.operations.Unlock()
	bootstrapRefusal(t, "profile before Store lock", truth, err, EngineInvalidInput, operationUpdate, codeEINVAL, "invalid bootstrap profile", nil, false)
	for _, row := range []struct {
		name  string
		owner *OperationReservationOwner
	}{{"nil owner", nil}, {"zero owner", &OperationReservationOwner{}}} {
		store := newUpdateStore(t)
		truth, err = store.BootstrapStorageV1(StorageProfilePrunedV1, row.owner)
		if truth != CommitTruthOld || !sameError(err, errOperationReservationInput) {
			t.Fatalf("%s: %s/%v", row.name, truth, err)
		}
		bootstrapOpenUnchanged(t, store, row.name)
		bootstrapRequireRow(t, store, []byte{2}, nil, row.name)
	}
}

func TestStorageBootstrapImages(t *testing.T) {
	for _, profile := range []struct {
		name  string
		value StorageProfileV1
	}{{"pruned", StorageProfilePrunedV1}, {"archive", StorageProfileArchiveV1}} {
		t.Run(profile.name, func(t *testing.T) {
			store, path, cfg := consultedStore(t)
			marker, profile := profile.name, profile.value
			if counts := bootstrapCounts(t, store, marker); counts != bootstrapEmptyCounts {
				t.Fatalf("%s: pre-state counts=%v", marker, counts)
			}
			truth, err := store.BootstrapStorageV1(profile, bootstrapOwner(t))
			if truth != CommitTruthNew || err != nil {
				t.Fatalf("%s: %s/%v", marker, truth, err)
			}
			bootstrapOpenUnchanged(t, store, marker)
			bootstrapRequireInitialized(t, store, cfg, profile, marker+" commit")
			mustEnvironment(t, store.Close())
			reopened, openErr := Open(path, cfg)
			reopened = consultedTrack(t, reopened, openErr)
			bootstrapRequireInitialized(t, reopened, cfg, profile, marker+" reopen")
			// PRE_GENESIS is the absence of canonical rows plus the zero counter: no
			// genesis or index row is fabricated and no next generation is allocated.
			bootstrapRequireRow(t, reopened, []byte{0x10, 0, 0, 0, 0, 0, 0, 0, 2}, nil, marker+" next generation")
			height, heightErr := HeightKey(1, 0)
			mustEnvironment(t, heightErr)
			consultedRequireImage(t, reopened, readDBIsLiteral()[2], height, nil, false, marker+" canonical")
		})
	}
	if !bytes.Equal(bootstrapImage(1), admissionNone()) {
		t.Fatal("pruned image literal drifted from the corpus authority literal")
	}
}

func TestStorageBootstrapReservation(t *testing.T) {
	// The boundary is specified here as the literal 188, never as the production constant:
	// deriving it from bootstrapOperationBytes would move both injections with any change
	// to that constant and so would pin nothing.
	const charge, enclosing = 188, MaxOperationDataBytes - 188
	if bootstrapOperationBytes != charge {
		t.Fatalf("reservation size=%d, want %d", bootstrapOperationBytes, charge)
	}
	t.Run("exactly 188 available", func(t *testing.T) {
		store, _, cfg := consultedStore(t)
		owner := bootstrapOwner(t)
		reservationInjectLive(owner, enclosing)
		truth, err := store.BootstrapStorageV1(StorageProfilePrunedV1, owner)
		if truth != CommitTruthNew || err != nil {
			t.Fatalf("admit: %s/%v", truth, err)
		}
		if live := reservationLive(owner); live != enclosing {
			t.Fatalf("enclosing live=%d, want %d", live, enclosing)
		}
		bootstrapRequireInitialized(t, store, cfg, StorageProfilePrunedV1, "admit")
		if again := owner.WithReservation(charge, func() error { return nil }); again != nil {
			t.Fatalf("second reservation: %v", again)
		}
		if live := reservationLive(owner); live != enclosing {
			t.Fatalf("live after second reservation=%d", live)
		}
	})
	t.Run("only 187 available", func(t *testing.T) {
		store, _, cfg := consultedStore(t)
		owner := bootstrapOwner(t)
		reservationInjectLive(owner, enclosing+1)
		truth, err := store.BootstrapStorageV1(StorageProfilePrunedV1, owner)
		if truth != CommitTruthOld || !sameError(err, errOperationReservationCapacity) {
			t.Fatalf("refuse: %s/%v", truth, err)
		}
		if live := reservationLive(owner); live != enclosing+1 {
			t.Fatalf("live=%d, want %d", live, enclosing+1)
		}
		bootstrapOpenUnchanged(t, store, "refuse")
		if counts := bootstrapCounts(t, store, "refuse"); counts != bootstrapEmptyCounts {
			t.Fatalf("refuse: counts=%v", counts)
		}
		bootstrapRequireRow(t, store, []byte{2}, nil, "refuse")
		// Capacity is decided before Store.Update runs, so a busy Store cannot take
		// priority over it.
		store.operations.Lock()
		busyTruth, busyErr := store.BootstrapStorageV1(StorageProfilePrunedV1, owner)
		store.operations.Unlock()
		if busyTruth != CommitTruthOld || !sameError(busyErr, errOperationReservationCapacity) {
			t.Fatalf("capacity over busy: %s/%v", busyTruth, busyErr)
		}
		reservationInjectLive(owner, 0)
		truth, err = store.BootstrapStorageV1(StorageProfilePrunedV1, owner)
		if truth != CommitTruthNew || err != nil {
			t.Fatalf("retry: %s/%v", truth, err)
		}
		bootstrapRequireInitialized(t, store, cfg, StorageProfilePrunedV1, "retry")
		if live := reservationLive(owner); live != 0 {
			t.Fatalf("live after retry=%d", live)
		}
	})
}

func TestStorageBootstrapNonempty(t *testing.T) {
	dbis := readDBIsLiteral()
	headerKey, headerValue := updatePlanHashRow()
	var txid, block [32]byte
	txid[0], block[0] = 7, 9
	utxoValue, err := (UTXOValue{Value: 5, CovenantType: 1, CreationHeight: 3}).Encode()
	mustEnvironment(t, err)
	chain := ChainValue([32]byte{2}, [32]byte{3}, [40]byte{4})
	key := func(build func() ([]byte, error)) []byte {
		t.Helper()
		out, keyErr := build()
		mustEnvironment(t, keyErr)
		return out
	}
	utxoOne := key(func() ([]byte, error) { return UTXOKey(1, txid, 0) })
	utxoFour := key(func() ([]byte, error) { return UTXOKey(4, txid, 0) })
	for _, row := range []struct {
		name      string
		mutations []Mutation
	}{
		{"extra metadata", []Mutation{consultedCounter(t, 1)}},
		{"orphan counter", []Mutation{consultedCounter(t, 9)}},
		{"utxo row", []Mutation{{DBI: dbis[1], Key: utxoOne, AfterKind: AfterLiteral, Literal: utxoValue}}},
		{"canonical row", []Mutation{{DBI: dbis[2], Key: key(func() ([]byte, error) { return HeightKey(1, 1) }), AfterKind: AfterLiteral, Literal: chain}}},
		{"headers row", []Mutation{{DBI: dbis[3], Key: headerKey, AfterKind: AfterLiteral, Literal: headerValue}}},
		{"blocks row", []Mutation{{DBI: dbis[4], Key: headerKey, AfterKind: AfterLiteral, Literal: headerValue}}},
		{"undo row", []Mutation{{DBI: dbis[5], Key: UndoManifestKey(block), AfterKind: AfterLiteral, Literal: UndoManifestValue(4, [16]byte{1}, 2, 3)}}},
		{"staged row", []Mutation{{DBI: dbis[6], Key: key(func() ([]byte, error) { return HeightKey(1, 2) }), AfterKind: AfterLiteral, Literal: chain}}},
		{"generation four utxo", []Mutation{{DBI: dbis[1], Key: utxoFour, AfterKind: AfterLiteral, Literal: utxoValue}}},
		{"generation four canonical", []Mutation{{DBI: dbis[2], Key: key(func() ([]byte, error) { return HeightKey(4, 1) }), AfterKind: AfterLiteral, Literal: chain}}},
		{"two nonempty DBIs", []Mutation{
			{DBI: dbis[1], Key: utxoOne, AfterKind: AfterLiteral, Literal: utxoValue},
			{DBI: dbis[6], Key: key(func() ([]byte, error) { return HeightKey(1, 2) }), AfterKind: AfterLiteral, Literal: chain},
		}},
	} {
		t.Run(row.name, func(t *testing.T) {
			store, _, _ := consultedStore(t)
			requireUpdateCommit(t, store, row.name+": seed", row.mutations...)
			before := bootstrapCounts(t, store, row.name)
			owner := bootstrapOwner(t)
			truth, bootstrapErr := store.BootstrapStorageV1(StorageProfilePrunedV1, owner)
			bootstrapNonemptyRefusal(t, row.name, truth, bootstrapErr)
			bootstrapOpenUnchanged(t, store, row.name)
			if after := bootstrapCounts(t, store, row.name); after != before {
				t.Fatalf("%s: counts %v -> %v", row.name, before, after)
			}
			bootstrapRequireRow(t, store, []byte{2}, nil, row.name)
			for _, mutation := range row.mutations {
				bootstrapRequireSeeded(t, store, mutation, row.name)
			}
			if live := reservationLive(owner); live != 0 {
				t.Fatalf("%s: live=%d", row.name, live)
			}
		})
	}
	t.Run("initialized store refuses repeat", func(t *testing.T) {
		store, path, cfg := consultedStore(t)
		owner := bootstrapOwner(t)
		truth, seedErr := store.BootstrapStorageV1(StorageProfilePrunedV1, owner)
		if truth != CommitTruthNew || seedErr != nil {
			t.Fatalf("seed: %s/%v", truth, seedErr)
		}
		for _, profile := range []StorageProfileV1{StorageProfilePrunedV1, StorageProfileArchiveV1} {
			repeatTruth, repeatErr := store.BootstrapStorageV1(profile, owner)
			bootstrapNonemptyRefusal(t, "repeat", repeatTruth, repeatErr)
			bootstrapOpenUnchanged(t, store, "repeat")
			bootstrapRequireInitialized(t, store, cfg, StorageProfilePrunedV1, "repeat")
		}
		mustEnvironment(t, store.Close())
		reopened, openErr := Open(path, cfg)
		reopened = consultedTrack(t, reopened, openErr)
		repeatTruth, repeatErr := reopened.BootstrapStorageV1(StorageProfileArchiveV1, owner)
		bootstrapNonemptyRefusal(t, "reopen repeat", repeatTruth, repeatErr)
		bootstrapRequireInitialized(t, reopened, cfg, StorageProfilePrunedV1, "reopen repeat")
	})
}

// bootstrapRequireSeeded proves one seeded non-metadata row survived a refusal byte for byte.
func bootstrapRequireSeeded(t *testing.T, store *Store, mutation Mutation, marker string) {
	t.Helper()
	mustEnvironment(t, store.View(func(reader *Reader) error {
		value, present, err := reader.Get(mutation.DBI, mutation.Key)
		if err != nil || !present || !bytes.Equal(value, mutation.Literal) {
			t.Fatalf("%s: seeded row %x=%x/%v/%v", marker, mutation.Key, value, present, err)
		}
		return nil
	}))
}

func TestStorageBootstrapMetadata(t *testing.T) {
	differing := environmentConfig()
	differing.MaxReaders++
	differingBytes, err := differing.Encode()
	mustEnvironment(t, err)
	for _, row := range []struct {
		name       string
		plan       []ownedMutation
		diagnostic string
		mismatch   bool
	}{
		{"absent version row", []ownedMutation{bootstrapDeleteMeta([]byte{0}), bootstrapSpareCounter()}, "invalid bootstrap metadata 00", false},
		{"wrong version value", []ownedMutation{bootstrapReplaceMeta([]byte{0}, []byte{0, 0, 0, 2})}, "invalid bootstrap metadata 00", false},
		{"absent config row", []ownedMutation{bootstrapDeleteMeta([]byte{1}), bootstrapSpareCounter()}, "invalid bootstrap metadata 01", false},
		{"undecodable config row", []ownedMutation{bootstrapReplaceMeta([]byte{1}, make([]byte, 48))}, "invalid bootstrap metadata 01", false},
		{"valid but differing config row", []ownedMutation{bootstrapReplaceMeta([]byte{1}, differingBytes)}, "invalid bootstrap metadata 01", false},
		{"both rows invalid", []ownedMutation{bootstrapReplaceMeta([]byte{0}, []byte{0, 0, 0, 2}), bootstrapReplaceMeta([]byte{1}, make([]byte, 48))}, "invalid bootstrap metadata 00", false},
		{"count mismatch wins over metadata", []ownedMutation{bootstrapReplaceMeta([]byte{0}, []byte{0, 0, 0, 2}), bootstrapSpareCounter()}, "", true},
	} {
		t.Run(row.name, func(t *testing.T) {
			store, path, _ := consultedStore(t)
			bootstrapForge(t, store, row.plan)
			owner := bootstrapOwner(t)
			truth, bootstrapErr := store.BootstrapStorageV1(StorageProfilePrunedV1, owner)
			if live := reservationLive(owner); live != 0 {
				t.Fatalf("%s: live=%d", row.name, live)
			}
			if row.mismatch {
				bootstrapNonemptyRefusal(t, row.name, truth, bootstrapErr)
				bootstrapOpenUnchanged(t, store, row.name)
				bootstrapRequireRow(t, store, []byte{2}, nil, row.name)
				return
			}
			bootstrapRefusal(t, row.name, truth, bootstrapErr, EngineIntegrity, operationGet, codeInvalid, row.diagnostic, nil, true)
			// Recording the error on the Reader makes it infrastructure, so the existing
			// cleanup consumes the Store and every later operation returns the same object.
			bootstrapRequireTerminal(t, store, bootstrapErr, row.name)
			if row.name != "valid but differing config row" {
				return
			}
			// This row is the one whose file stays openable, so it carries the executed
			// no-initial-write proof for the whole metadata branch.
			reopened, openErr := Open(path, differing)
			reopened = consultedTrack(t, reopened, openErr)
			if counts := bootstrapCounts(t, reopened, row.name); counts != bootstrapEmptyCounts {
				t.Fatalf("%s: counts after failure=%v", row.name, counts)
			}
			bootstrapRequireRow(t, reopened, []byte{2}, nil, row.name)
			bootstrapRequireRow(t, reopened, bootstrapCounterKey(), nil, row.name)
		})
	}
}

func TestStorageBootstrapLifecycle(t *testing.T) {
	t.Run("nonempty refusal keeps the Store usable", func(t *testing.T) {
		store, _, _ := consultedStore(t)
		row := consultedCounter(t, 3)
		requireUpdateCommit(t, store, "A4 seed", row)
		owner := bootstrapOwner(t)
		truth, err := store.BootstrapStorageV1(StorageProfileArchiveV1, owner)
		bootstrapNonemptyRefusal(t, "A4", truth, err)
		bootstrapOpenUnchanged(t, store, "A4")
		bootstrapRequireSeeded(t, store, row, "A4")
		mustEnvironment(t, store.View(func(*Reader) error { return nil }))
		requireUpdateCommit(t, store, "A4 unrelated update", consultedCounter(t, 4))
		bootstrapRequireRow(t, store, []byte{2}, nil, "A4")
		if live := reservationLive(owner); live != 0 {
			t.Fatalf("A4: live=%d", live)
		}
	})
	t.Run("concurrent attempts initialize once", func(t *testing.T) {
		store, _, cfg := consultedStore(t)
		owner := bootstrapOwner(t)
		var wait sync.WaitGroup
		truths, errs := make([]CommitTruth, 4), make([]error, 4)
		wait.Add(len(truths))
		for i := range truths {
			go func() {
				defer wait.Done()
				truths[i], errs[i] = store.BootstrapStorageV1(StorageProfilePrunedV1, owner)
			}()
		}
		wait.Wait()
		committed := 0
		for i, truth := range truths {
			if truth == CommitTruthNew && errs[i] == nil {
				committed++
				continue
			}
			engine, direct := directTestEngineError(errs[i])
			busy := direct && engine.Class == EngineConcurrency && engine.Code == codeBusy && engine.Diagnostic == "store operation in progress"
			nonempty := direct && engine.Class == EngineStateMismatch && engine.Code == codeProblem && engine.Diagnostic == "bootstrap requires exact-empty store"
			if truth != CommitTruthOld || !busy && !nonempty {
				t.Fatalf("A5: %s/%v", truth, errs[i])
			}
		}
		if committed != 1 {
			t.Fatalf("A5: %d commits", committed)
		}
		bootstrapOpenUnchanged(t, store, "A5")
		bootstrapRequireInitialized(t, store, cfg, StorageProfilePrunedV1, "A5")
		if live := reservationLive(owner); live != 0 {
			t.Fatalf("A5: live=%d", live)
		}
	})
	t.Run("native census failure is recorded unchanged", func(t *testing.T) {
		store, _, _ := consultedStore(t)
		requireUpdateCommit(t, store, "R6 seed", consultedCounter(t, 6))
		store.dbis[3] = 4242 // nonzero and distinct, so validRetainedDBIs still admits the shape
		owner := bootstrapOwner(t)
		truth, err := store.BootstrapStorageV1(StorageProfilePrunedV1, owner)
		engine := requireEngineError(t, err, EngineLocalInvariant, operationInspect, codeBadDBI)
		if truth != CommitTruthOld || engine.Diagnostic != expectedNativeDiagnostic(codeBadDBI) || engine.Cause != nil || engine.ReopenRequired {
			t.Fatalf("R6: %s/%+v", truth, engine)
		}
		// The census failure wins before the cardinality predicate: the seeded store is
		// also nonempty, yet the native error is what surfaces.
		bootstrapRequireTerminal(t, store, err, "R6")
		if live := reservationLive(owner); live != 0 {
			t.Fatalf("R6: live=%d", live)
		}
	})
	t.Run("busy Store keeps its own tuple", func(t *testing.T) {
		store, _, _ := consultedStore(t)
		owner := bootstrapOwner(t)
		store.operations.Lock()
		truth, err := store.BootstrapStorageV1(StorageProfilePrunedV1, owner)
		store.operations.Unlock()
		bootstrapRefusal(t, "R7 busy", truth, err, EngineConcurrency, operationUpdate, codeBusy, "store operation in progress", nil, false)
		bootstrapOpenUnchanged(t, store, "R7 busy")
		if live := reservationLive(owner); live != 0 {
			t.Fatalf("R7 busy: live=%d", live)
		}
	})
	t.Run("cached terminal tuples are forwarded unchanged", func(t *testing.T) {
		owner := bootstrapOwner(t)
		recorded := nativeError(operationGet, codeEIO)
		store := newUpdateStore(t)
		cachedTruth, cached := store.Update(func(reader *Reader) (Batch, error) {
			reader.failure = recorded
			reader.active.Store(false)
			return updateLifecycleBatch(), nil
		})
		if cachedTruth != CommitTruthOld || !sameError(cached, recorded) || store.state != storeCLOSED {
			t.Fatalf("R7 cached OLD: %s/%v/%s", cachedTruth, cached, store.state)
		}
		truth, err := store.BootstrapStorageV1(StorageProfilePrunedV1, owner)
		if truth != CommitTruthOld || !sameError(err, recorded) {
			t.Fatalf("R7 cached OLD forward: %s/%v", truth, err)
		}
		unknown := newUpdateStore(t)
		primary, readback := nativeError(operationUpdate, codeENOSPC), nativeError(operationUpdate, codeEIO)
		projectedTruth, projected := unknown.applyUpdateOutcome(updateNativeConsumed(CommitTruthUnknown, true, primary, readback), nil, nil, false)
		if projectedTruth != CommitTruthUnknown || unknown.terminalTruth != CommitTruthUnknown {
			t.Fatalf("R7 cached UNKNOWN: %s/%s", projectedTruth, unknown.terminalTruth)
		}
		var commit *CommitError
		if !errors.As(projected, &commit) || !sameError(commit.Cause, primary) || commit.Truth != CommitTruthUnknown {
			t.Fatalf("R7 cached UNKNOWN shape: %+v", projected)
		}
		truth, err = unknown.BootstrapStorageV1(StorageProfileArchiveV1, owner)
		if truth != CommitTruthUnknown || !sameError(err, projected) {
			t.Fatalf("R7 cached UNKNOWN forward: %s/%v", truth, err)
		}
		if live := reservationLive(owner); live != 0 {
			t.Fatalf("R7: live=%d", live)
		}
	})
}

func TestStorageBootstrapComposition(t *testing.T) {
	source := bootstrapSource(t)
	t.Run("fixed builder shape", func(t *testing.T) {
		store, _, _ := consultedStore(t)
		meta := bootstrapMetaDBI()
		var batch Batch
		mustEnvironment(t, store.View(func(reader *Reader) error {
			var err error
			batch, err = bootstrapBatch(store, reader, StorageProfileArchiveV1)
			return err
		}))
		if batch.Reverse || len(batch.Mutations) != 2 || len(batch.Consulted) != 2 {
			t.Fatalf("H5: %+v", batch)
		}
		for i, want := range []Mutation{
			{DBI: meta, Key: []byte{2}, AfterKind: AfterLiteral, Literal: bootstrapImage(2)},
			{DBI: meta, Key: bootstrapCounterKey(), AfterKind: AfterLiteral, Literal: make([]byte, 16)},
		} {
			got := batch.Mutations[i]
			if got.DBI != want.DBI || !bytes.Equal(got.Key, want.Key) || got.BeforePresent || got.AfterKind != AfterLiteral ||
				!bytes.Equal(got.Literal, want.Literal) || got.RefDBI != (DBI{}) || got.RefKey != nil {
				t.Fatalf("H5: mutation %d=%+v", i, got)
			}
		}
		for i, want := range [][]byte{{0}, {1}} {
			if batch.Consulted[i].DBI != meta || !bytes.Equal(batch.Consulted[i].Key, want) {
				t.Fatalf("H5: consulted %d=%+v", i, batch.Consulted[i])
			}
		}
		if bytes.Compare(batch.Mutations[0].Key, batch.Mutations[1].Key) >= 0 || bytes.Compare(batch.Consulted[0].Key, batch.Consulted[1].Key) >= 0 {
			t.Fatal("H5: builder order is not strictly increasing")
		}
	})
	t.Run("initial encoder failure is wrapped and recorded", func(t *testing.T) {
		store := newUpdateStore(t)
		var recorded error
		truth, err := store.Update(func(reader *Reader) (Batch, error) {
			encoded, authorityErr := bootstrapAuthority(reader, 3)
			if encoded != nil {
				t.Fatal("encoder returned bytes for a refused struct")
			}
			if reader.active.Load() || !sameError(reader.failure, authorityErr) {
				t.Fatalf("encoder failure not recorded: %v/%v", reader.active.Load(), reader.failure)
			}
			recorded = authorityErr
			return Batch{}, authorityErr
		})
		bootstrapRefusal(t, "encoder", truth, err, EngineLocalInvariant, operationUpdate, codeProblem, "invalid bootstrap authority", errSchema, false)
		if !sameError(err, recorded) || store.state != storeCLOSED {
			t.Fatalf("encoder: %v/%s", err, store.state)
		}
	})
	t.Run("native outcomes project through the Store unchanged", func(t *testing.T) {
		store, _, _ := consultedStore(t)
		var batch Batch
		mustEnvironment(t, store.View(func(reader *Reader) error {
			var err error
			batch, err = bootstrapBatch(store, reader, StorageProfilePrunedV1)
			return err
		}))
		plan := updateNativePlan(t, batch.Mutations...)
		primary := nativeError(operationUpdate, codeENOSPC)
		third := []ownedMutation{{dbi: bootstrapMetaDBI(), key: plan[0].key, after: AfterLiteral, literal: bootstrapImage(2)}}
		for _, row := range []struct {
			name          string
			commit, flip  bool
			change        []ownedMutation
			truth         CommitTruth
			secondaryCode int
		}{
			{"old", false, false, nil, CommitTruthOld, 0},
			{"new", true, false, nil, CommitTruthNew, 0},
			{"neither", false, false, third, CommitTruthUnknown, 0},
			{"unreadable", false, true, nil, CommitTruthUnknown, codeBadDBI},
		} {
			t.Run(row.name, func(t *testing.T) {
				witness, _, _ := consultedStore(t)
				outcome := bootstrapReadback(t, witness, plan, row.change, primary, row.commit, row.flip)
				if outcome.truth != row.truth || !outcome.commitAttempted || !sameError(outcome.primary, primary) {
					t.Fatalf("%s: %+v", row.name, outcome)
				}
				if row.secondaryCode == 0 {
					requireUpdateTruth(t, outcome, row.truth, true, primary, nil)
				} else {
					requireEngineError(t, outcome.secondary, EngineLocalInvariant, operationUpdate, row.secondaryCode)
				}
				projected := newUpdateStore(t)
				truth, terminal := projected.applyUpdateOutcome(outcome, nil, nil, false)
				if truth != outcome.truth || projected.state != storeCLOSED || projected.terminalTruth != outcome.truth {
					t.Fatalf("%s: projection %s/%s", row.name, truth, projected.state)
				}
				again, forwarded := projected.BootstrapStorageV1(StorageProfilePrunedV1, bootstrapOwner(t))
				if again != outcome.truth || !sameError(forwarded, terminal) {
					t.Fatalf("%s: forward %s/%v", row.name, again, forwarded)
				}
			})
		}
	})
	t.Run("source ownership", func(t *testing.T) {
		// A file-scope variable would be the only place this producer could stash a Reader,
		// an Inspection or a fault hook between calls, and the declared function set is what
		// bounds it to the six contract owners plus the two row predicates.
		for _, declaration := range bootstrapFile(t, source).Decls {
			general, isGeneral := declaration.(*ast.GenDecl)
			if isGeneral && general.Tok != token.CONST {
				t.Fatalf("file-scope %s declaration: a producer with no state cannot stash a Reader, an Inspection or a hook between calls", general.Tok)
			}
		}
		var exported, declared []string
		for _, declaration := range bootstrapDecls(t, source) {
			declared = append(declared, declaration.Name.Name)
			if declaration.Name.IsExported() {
				exported = append(exported, declaration.Name.Name)
			}
			ast.Inspect(declaration, func(node ast.Node) bool {
				if ident, ok := node.(*ast.Ident); ok && (ident.Name == "validated" || ident.Name == "qualified") {
					t.Errorf("caller obligation absorbed by %q", ident.Name)
				}
				return true
			})
		}
		if strings.Join(exported, "|") != "BootstrapStorageV1" {
			t.Fatalf("exported surface=%v", exported)
		}
		if strings.Join(declared, "|") != "BootstrapStorageV1|bootstrapBatch|bootstrapInspect|bootstrapMetadata|bootstrapVersionRow|bootstrapConfigRow|bootstrapAuthority|bootstrapFailure" {
			t.Fatalf("declared owners=%v", declared)
		}
		text := string(source)
		// Everything from here to the end of this subtest is a STRUCTURAL source pin, not a
		// behavioral oracle: observing at runtime that the charge is held for the whole
		// transaction, or that reader.getMu is held across the census, needs a scheduler seam
		// or a fault hook inside the internal callback, and non_scope forbids both.
		if strings.Count(text, "s.Inspect(") != 0 || strings.Count(text, "s.inspectReadLocked(reader.txn)") != 1 || strings.Count(text, "inspectReadLocked(") != 1 {
			t.Fatal("census transaction ownership drifted")
		}
		if strings.Count(text, "reader.Get(") != 2 || strings.Count(text, "s.Update(") != 1 || strings.Count(text, "WithReservation(") != 1 {
			t.Fatal("call route drifted: exactly two required-metadata reads, one Update and one reservation")
		}
		// Those counts pin uniqueness but not nesting: charging, releasing and only then
		// updating keeps every one of them. The charge spanning the transaction is the single
		// Update call sitting inside the callback the single reservation runs.
		if reservation := bootstrapCall(bootstrapFile(t, source), "WithReservation"); reservation == nil ||
			bootstrapCall(reservation.Args[1], "Update") == nil {
			t.Fatal("Store.Update runs outside the reservation callback: the charge is not held for the transaction")
		}
		batchBody := updateNativeBody(t, source, "bootstrapBatch")
		order := []string{"bootstrapInspect(", "Entries != want", "[]byte{0x00}, []byte{0x01}", "bootstrapMetadata(", "bootstrapAuthority(", "Consulted:"}
		position := -1
		for _, step := range order {
			next := strings.Index(batchBody, step)
			if next <= position {
				t.Fatalf("bootstrapBatch order failed at %q", step)
			}
			position = next
		}
		for _, once := range []string{"[]byte{0x00}, []byte{0x01}", "bootstrapMetadata(", "bootstrapAuthority(", "LogicalCounterValue("} {
			if strings.Count(batchBody, once) != 1 {
				t.Fatalf("bootstrapBatch allocates %q more than once", once)
			}
		}
		metadataBody := updateNativeBody(t, source, "bootstrapMetadata")
		if strings.Index(metadataBody, "versionKey") >= strings.Index(metadataBody, "configKey") {
			t.Fatal("required metadata rows are not decided 00 before 01")
		}
		if strings.Count(updateNativeBody(t, source, "bootstrapInspect"), "reader.getMu.Lock()") != 1 ||
			strings.Count(updateNativeBody(t, source, "bootstrapFailure"), "reader.getMu.Lock()") != 1 ||
			strings.Count(text, "defer reader.getMu.Unlock()") != 2 {
			t.Fatal("Reader lock ownership drifted")
		}
	})
}

func bootstrapFile(t *testing.T, source []byte) *ast.File {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), "bootstrap_cgo.go", source, 0)
	mustEnvironment(t, err)
	return file
}

// bootstrapCall returns a call to name somewhere inside node, or nil when node holds none.
func bootstrapCall(node ast.Node, name string) *ast.CallExpr {
	var found *ast.CallExpr
	ast.Inspect(node, func(current ast.Node) bool {
		call, isCall := current.(*ast.CallExpr)
		if !isCall {
			return true
		}
		if selector, isSelector := call.Fun.(*ast.SelectorExpr); isSelector && selector.Sel.Name == name {
			found = call
		}
		return true
	})
	return found
}

func bootstrapDecls(t *testing.T, source []byte) []*ast.FuncDecl {
	t.Helper()
	file := bootstrapFile(t, source)
	var out []*ast.FuncDecl
	for _, declaration := range file.Decls {
		if fn, ok := declaration.(*ast.FuncDecl); ok {
			out = append(out, fn)
		}
	}
	return out
}

// bootstrapReadback reproduces the corpus readback recipe over the exact bootstrap plan:
// it captures the consulted OLD images, optionally commits the plan, and reads it back
// through a second snapshot, so OLD, NEW, neither and unreadable are engine verdicts.
func bootstrapReadback(t *testing.T, store *Store, plan, change []ownedMutation, primary error, commit, flip bool) updateNativeOutcome {
	t.Helper()
	var outcome updateNativeOutcome
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	mustEnvironment(t, store.View(func(reader *Reader) error {
		consulted := []ownedConsulted{{dbi: bootstrapMetaDBI(), key: []byte{0}}, {dbi: bootstrapMetaDBI(), key: []byte{1}}}
		if _, err := updateNativeConsultedImages(reader.txn, store.dbis, consulted); err != nil {
			return err
		}
		if commit {
			requireUpdateTruth(t, store.updateNative(plan, nil, reader.txn), CommitTruthNew, true, nil, nil)
		}
		if change != nil {
			requireUpdateTruth(t, store.updateNative(change, nil, reader.txn), CommitTruthNew, true, nil, nil)
		}
		handles := store.dbis
		if flip {
			handles[0] = ^handles[0]
		}
		outcome = updateNativeReadback(store.env, handles, plan, consulted, reader.txn, primary)
		return nil
	}))
	return outcome
}
