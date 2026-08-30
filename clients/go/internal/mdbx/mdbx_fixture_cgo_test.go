//go:build rubin_mdbx_fixture && cgo && (darwin || linux) && (amd64 || arm64)

package mdbx

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/filelock"
)

func TestFixtureModesAndFixedOperations(t *testing.T) {
	for _, tc := range []struct {
		name, diagnostic string
		mode             fixtureMode
		operation        engineOperation
	}{
		{"unexpected DBI", "SchemaV1 main cardinality mismatch", fixtureUnexpectedDBI, operationInit},
		{"third meta row", "SchemaV1 metadata cardinality mismatch", fixtureThirdMetaRow, operationInit},
		{"unnamed main row", "SchemaV1 main cardinality mismatch", fixtureUnnamedMainRow, operationOpen},
		{"wrong schema version", "invalid SchemaV1 version row", fixtureWrongSchemaVersion, operationOpen},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "db")
			var store *Store
			var err error
			if tc.mode <= fixtureThirdMetaRow {
				store, err = fixtureCreate(path, environmentConfig(), tc.mode)
			} else {
				path = closedEnvironment(t)
				store, err = fixtureOpen(path, environmentConfig(), tc.mode)
			}
			engine := requireEnvironmentError(t, err, EngineIntegrity, tc.operation, -30793, tc.diagnostic)
			fixtureOwner.Lock()
			active := fixtureOwner.active
			fixtureOwner.Unlock()
			if store != nil || active || tc.mode == fixtureWrongSchemaVersion && engine.Cause != errSchema || tc.mode != fixtureWrongSchemaVersion && engine.Cause != nil {
				t.Fatalf("fixture retained state or Cause: %v/%v/%v", store, active, engine.Cause)
			}
			requireArtifact(t, path, 0o700, false)
			for _, name := range []string{"rubin-writer.lock", "mdbx.dat", "mdbx.lck"} {
				requireArtifact(t, filepath.Join(path, name), 0o600, name == "rubin-writer.lock")
			}
			handle, result, lockErr := filelock.AcquireDirectory(path)
			if lockErr != nil || result != "" || handle == nil {
				t.Fatalf("writer retained: %q %v", result, lockErr)
			}
			mustEnvironment(t, handle.Release())
		})
	}
	for _, mode := range []fixtureMode{0, 5} {
		if err := armFixture(filepath.Join(t.TempDir(), "db"), mode); err == nil {
			t.Fatalf("invalid fixture mode %d accepted", mode)
		}
	}
	t.Run("target-bound owner", func(t *testing.T) {
		target, sibling := filepath.Join(t.TempDir(), "target"), filepath.Join(t.TempDir(), "sibling")
		mustEnvironment(t, armFixture(target, fixtureUnexpectedDBI))
		defer clearFixture()
		if armFixture(sibling, fixtureThirdMetaRow) == nil || claimFixturePath(sibling) != 0 || claimFixturePath(target) != fixtureUnexpectedDBI || claimFixturePath(target) != 0 {
			t.Fatal("fixture owner was retargeted, prematurely consumed or reused")
		}
	})
	for _, mode := range []fixtureMode{fixtureUnnamedMainRow, fixtureWrongSchemaVersion} {
		if store, err := fixtureCreate(filepath.Join(t.TempDir(), "db"), environmentConfig(), mode); store != nil || err == nil {
			t.Fatalf("Create phase accepted mode %d", mode)
		}
	}
	for _, mode := range []fixtureMode{fixtureUnexpectedDBI, fixtureThirdMetaRow} {
		if store, err := fixtureOpen(filepath.Join(t.TempDir(), "db"), environmentConfig(), mode); store != nil || err == nil {
			t.Fatalf("Open phase accepted mode %d", mode)
		}
	}
	store, copied, err := fixtureOpenReverseUTXO(filepath.Join(t.TempDir(), "db"))
	requireNoStore(t, store, err, EngineIntegrity, operationOpen, -30793, "SchemaV1 DBI flags mismatch")
	if string(copied) != string(configBytes(environmentConfig())) {
		t.Fatalf("copied metadata changed: %x", copied)
	}
	store, err = fixtureOpenStoredReadersMismatch(filepath.Join(t.TempDir(), "db"))
	effective := requireNoStore(t, store, err, EngineIntegrity, operationOpen, -30793, "effective environment mismatch")
	if effective.Cause == nil || effective.Cause.Error() != "MaxReaders: got 493, want 492" {
		t.Fatalf("effective mismatch cause=%v", effective.Cause)
	}
	path := filepath.Join(t.TempDir(), "db")
	store, err = Create(path, environmentConfig())
	mustEnvironment(t, err)
	busy, abortErr, closeErr := fixtureCloseBusy(path, store)
	requireEnvironmentError(t, busy, EngineConcurrency, operationClose, -30778, expectedNativeDiagnostic(-30778))
	if abortErr != nil || closeErr != nil || store.state != storeCLOSED {
		t.Fatalf("Close-BUSY cleanup: %v/%v/%s", abortErr, closeErr, store.state)
	}
	store, err = Create(filepath.Join(t.TempDir(), "db"), environmentConfig())
	mustEnvironment(t, err)
	if rc, cleanup := fixtureWriteOwnerMismatch(store); rc != -30416 || cleanup != nil || store.state != storeOPEN {
		t.Fatalf("owner mismatch=%d cleanup=%v state=%s", rc, cleanup, store.state)
	}
	mustEnvironment(t, store.Close())
}

func TestReaderGetNativeFixtures(t *testing.T) {
	store, err := Create(filepath.Join(t.TempDir(), "db"), environmentConfig())
	mustEnvironment(t, err)
	defer func() { _ = store.Close() }()
	dbis := readDBIsLiteral()
	emptyKey := []byte{2}
	counterKey := []byte{0x10, 0, 0, 0, 0, 0, 0, 0, 1}
	counterValue := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	blockKey := make([]byte, 32)
	blockValue := make([]byte, 68_000_125)
	blockValue[0], blockValue[len(blockValue)-1] = 0x7a, 0x5c
	if err := fixtureSeedRows(store,
		fixtureRawRow{dbi: dbis[0], key: emptyKey, value: []byte{}},
		fixtureRawRow{dbi: dbis[0], key: counterKey, value: counterValue},
		fixtureRawRow{dbi: dbis[4], key: blockKey, value: blockValue},
	); err != nil {
		t.Fatal(err)
	}
	if err := fixtureSeedRows(store, fixtureRawRow{dbi: dbis[0], key: []byte{0}, value: make([]byte, 3)}); err == nil {
		t.Fatal("fixture accepted an overbound raw row")
	}
	panicValue := &struct{ name string }{"maximum"}
	var maximum []byte
	var recovered any
	func() {
		defer func() { recovered = recover() }()
		viewErr := store.View(func(reader *Reader) error {
			value, present, getErr := reader.Get(dbis[4], blockKey)
			if getErr != nil || !present || len(value) != 68_000_125 {
				return fmt.Errorf("maximum native copy drifted: %d/%v/%w", len(value), present, getErr)
			}
			maximum = value
			panic(panicValue)
		})
		if viewErr != nil {
			t.Fatal(viewErr)
		}
	}()
	if recovered != panicValue || len(maximum) != 68_000_125 || maximum[0] != 0x7a || maximum[len(maximum)-1] != 0x5c {
		t.Fatalf("maximum panic cleanup drifted: %v/%d", recovered, len(maximum))
	}
	mustEnvironment(t, store.View(func(reader *Reader) error {
		empty, present, getErr := reader.Get(dbis[0], emptyKey)
		if getErr != nil || !present || empty == nil || len(empty) != 0 {
			return fmt.Errorf("present-empty identity drifted: %#v/%v/%w", empty, present, getErr)
		}
		first, present, getErr := reader.Get(dbis[0], counterKey)
		if getErr != nil || !present || len(first) != 16 {
			return fmt.Errorf("independent copy setup drifted: %x/%v/%w", first, present, getErr)
		}
		first[0] = 0xff
		second, present, getErr := reader.Get(dbis[0], counterKey)
		if getErr != nil || !present || len(second) != 16 || second[0] != 1 {
			return fmt.Errorf("returned bytes alias MDBX: %x/%v/%w", second, present, getErr)
		}
		absentKey := []byte{0x10, 0, 0, 0, 0, 0, 0, 0, 2}
		absent, present, getErr := reader.Get(dbis[0], absentKey)
		if getErr != nil || present || absent != nil {
			return fmt.Errorf("absence identity drifted: %#v/%v/%w", absent, present, getErr)
		}
		return nil
	}))
	inspection, err := store.Inspect()
	mustEnvironment(t, err)
	if inspection.DBIs[0].Entries != 4 || inspection.DBIs[4].Entries != 1 || inspection.ReaderTableLength == 0 {
		t.Fatalf("Inspection provenance drifted: %+v", inspection)
	}
	mustEnvironment(t, store.Close())
}
