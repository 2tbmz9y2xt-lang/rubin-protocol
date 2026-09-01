//go:build rubin_mdbx_fixture && cgo && (darwin || linux) && (amd64 || arm64)

package mdbx

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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

//nolint:errorlint // Exact callback, infrastructure and panic identities are required.
func TestReaderGetMalformedDisposition(t *testing.T) {
	dbis, key := readDBIsLiteral(), []byte{0}
	callbackErr, panicValue := errors.New("callback"), &struct{ name string }{"panic"}
	for _, mode := range []string{"ignored", "exact", "wrapped", "distinct", "panic"} {
		t.Run(mode, func(t *testing.T) {
			store, err := Create(filepath.Join(t.TempDir(), "db"), environmentConfig())
			mustEnvironment(t, err)
			mustEnvironment(t, fixtureSeedMalformedStoredWidth(store))
			var recorded, returned error
			var recovered any
			func() {
				defer func() { recovered = recover() }()
				returned = store.View(func(reader *Reader) error {
					_, _, recorded = reader.Get(dbis[0], key)
					requireEnvironmentError(t, recorded, EngineIntegrity, operationGet, codeInvalid, "stored value width outside SchemaV1 bound")
					if _, _, again := reader.Get(dbis[0], key); requireEnvironmentError(t, again, EngineInvalidInput, operationGet, codeEINVAL, "Reader is not active").Cause != nil {
						t.Fatal("failed Reader remained active")
					}
					switch mode {
					case "ignored":
						return nil
					case "exact":
						return recorded
					case "wrapped":
						return fmt.Errorf("wrapped: %w", recorded)
					case "distinct":
						return callbackErr
					default:
						panic(panicValue)
					}
				})
			}()
			if store.state != storeCLOSED || store.env != nil || store.writer != nil || store.txn != nil || store.config != (ConfigV1{}) || !sameError(store.terminal, returned) && mode != "panic" {
				t.Fatalf("post-native Get disposition drifted: %s/%v", store.state, returned)
			}
			switch mode {
			case "ignored", "exact":
				if returned != recorded {
					t.Fatalf("recorded failure identity/duplication drifted: %v", returned)
				}
			case "wrapped", "distinct":
				parts, ok := returned.(interface{ Unwrap() []error })
				if !ok || len(parts.Unwrap()) != 2 || parts.Unwrap()[1] != recorded || mode == "distinct" && parts.Unwrap()[0] != callbackErr || mode == "wrapped" && !errors.Is(parts.Unwrap()[0], recorded) {
					t.Fatalf("callback/recorded order drifted: %v", returned)
				}
			case "panic":
				if recovered != panicValue || returned != nil || store.terminal != recorded {
					t.Fatalf("panic disposition drifted: %v/%v/%v", recovered, returned, store.terminal)
				}
			}
			terminal := store.terminal
			if !sameError(store.View(func(*Reader) error { t.Fatal("closed callback invoked"); return nil }), terminal) {
				t.Fatal("closed View legality drifted")
			}
			if inspection, next := store.Inspect(); inspection != (Inspection{}) || !sameError(next, terminal) || !sameError(store.Close(), terminal) {
				t.Fatal("closed Inspect/Close legality drifted")
			}
		})
	}
}

func TestNativeUpdateFixtures(t *testing.T) {
	source, err := os.ReadFile("mdbx_cgo.go")
	mustEnvironment(t, err)
	abort, commit := updateNativeBody(t, source, "updateNativeAbort"), updateNativeBody(t, source, "updateNativeCommit")
	if !strings.Contains(abort, "if rc == codeThreadMismatch {") || !strings.Contains(abort, "updateNativeRetainedWrite(false") || strings.Count(abort, "updateNativeRetainedWrite") != 1 {
		t.Fatal("abort ownership drifted")
	}
	if !strings.Contains(commit, "case codeThreadMismatch:") || !strings.Contains(commit, "updateNativeRetainedWrite(true") || strings.Count(commit, "updateNativeRetainedWrite") != 1 || !strings.Contains(commit, "case codePanic, codeEPerm, codeBadSignature, codeEINVAL, codeBadTxn, codeProblem:\n\t\treturn updateNativeConsumed(CommitTruthOld, true, commitErr, nil)") {
		t.Fatal("commit ownership drifted")
	}
	truth := updateNativeBody(t, source, "updateNativeReadbackTruth")
	oldAt, newAt := strings.Index(truth, "if oldImage"), strings.Index(truth, "if newImage")
	if oldAt < 0 || newAt < 0 || oldAt > newAt {
		t.Fatal("readback tie-break drifted")
	}
	fixture, err := os.ReadFile("mdbx_fixture_cgo.go")
	mustEnvironment(t, err)
	post, unreadable := updateNativeBody(t, fixture, "fixtureUpdatePostCommitENOSPC"), updateNativeBody(t, fixture, "fixtureUpdatePostCommitENOSPCUnreadable")
	if strings.Count(post, "updateNativeReadback") != 1 || strings.Count(unreadable, "updateNativeReadback") != 1 {
		t.Fatal("readback truth drifted")
	}
	t.Run("wrong-thread retained write", func(t *testing.T) {
		store, err := Create(filepath.Join(t.TempDir(), "db"), environmentConfig())
		mustEnvironment(t, err)
		defer func() { mustEnvironment(t, store.Close()) }()
		outcome, release, err := fixtureUpdateWrongThread(store)
		mustEnvironment(t, err)
		defer func() { mustEnvironment(t, release()) }()
		engine := requireEngineError(t, outcome.primary, EngineLocalInvariant, operationUpdate, codeThreadMismatch)
		if engine.Diagnostic != expectedNativeDiagnostic(codeThreadMismatch) || outcome.truth != CommitTruthOld || !outcome.commitAttempted || outcome.secondary != nil || outcome.retainedWrite == nil || outcome.retainedRead != nil || outcome.valid() != nil {
			t.Fatalf("commit ownership drifted: %+v", outcome)
		}
		if locked := outcome.lockedOutcome(); !locked.poisoned || locked.err != nil {
			t.Fatalf("commit ownership drifted: %+v", locked)
		}
		both := outcome
		both.retainedRead = outcome.retainedWrite
		if both.valid() == nil {
			t.Fatal("commit ownership drifted")
		}
		wrongTruth := outcome
		wrongTruth.truth = CommitTruthNew
		if wrongTruth.valid() == nil {
			t.Fatal("commit ownership drifted")
		}
		retainedRead := updateNativeRetainedRead(outcome.primary, errors.New("cleanup"), outcome.retainedWrite)
		if retainedRead.valid() != nil {
			t.Fatalf("commit ownership drifted: %+v", retainedRead)
		}
		retainedRead.secondary = nil
		if retainedRead.valid() == nil {
			t.Fatal("commit ownership drifted")
		}
		retainedRead.secondary = errors.New("cleanup")
		retainedRead.commitAttempted = false
		if retainedRead.valid() == nil {
			t.Fatal("commit stage drifted")
		}
		committed := outcome
		committed.secondary = errors.New("cleanup")
		if committed.valid() == nil {
			t.Fatal("commit ownership drifted")
		}
	})

	t.Run("wrong-thread abort retains write", func(t *testing.T) {
		store, err := Create(filepath.Join(t.TempDir(), "db"), environmentConfig())
		mustEnvironment(t, err)
		defer func() { mustEnvironment(t, store.Close()) }()
		outcome, release, err := fixtureUpdateAbortWrongThread(store)
		mustEnvironment(t, err)
		defer func() { mustEnvironment(t, release()) }()
		primary := requireEngineError(t, outcome.primary, EngineLocalInvariant, operationUpdate, codeNotFound)
		secondary := requireEngineError(t, outcome.secondary, EngineLocalInvariant, operationAbort, codeThreadMismatch)
		if primary.Diagnostic != expectedNativeDiagnostic(codeNotFound) || secondary.Diagnostic != expectedNativeDiagnostic(codeThreadMismatch) || outcome.truth != CommitTruthOld || outcome.commitAttempted || outcome.retainedWrite == nil || outcome.retainedRead != nil || outcome.valid() != nil {
			t.Fatalf("abort ownership drifted: %+v", outcome)
		}
	})

	t.Run("break then real commit", func(t *testing.T) {
		store, err := Create(filepath.Join(t.TempDir(), "db"), environmentConfig())
		mustEnvironment(t, err)
		plan := updateNativePlan(t, updatePlanBatch(t).Mutations[8])
		outcome := fixtureUpdateResultTrue(store, plan)
		engine := requireEngineError(t, outcome.primary, EngineTransaction, operationUpdate, codeResultTrue)
		if engine.Diagnostic != expectedNativeDiagnostic(codeResultTrue) {
			t.Fatalf("RESULT_TRUE disposition drifted: %+v", engine)
		}
		if outcome.truth != CommitTruthOld || !outcome.commitAttempted || outcome.secondary != nil || outcome.retainedWrite != nil || outcome.retainedRead != nil || outcome.valid() != nil {
			t.Fatalf("RESULT_TRUE disposition drifted: %+v", outcome)
		}
		mustEnvironment(t, store.Close())
	})

	t.Run("post-commit ENOSPC OLD", func(t *testing.T) {
		store, err := Create(filepath.Join(t.TempDir(), "db"), environmentConfig())
		mustEnvironment(t, err)
		mutation := Mutation{DBI: readDBIsLiteral()[0], Key: []byte{2}, BeforePresent: true, AfterKind: planAfterLiteral, Literal: []byte{}}
		mustEnvironment(t, fixtureSeedRows(store, fixtureRawRow{dbi: mutation.DBI, key: mutation.Key, value: mutation.Literal}))
		outcome, cleanup := fixtureUpdatePostCommitENOSPC(store, updateNativePlan(t, mutation))
		mustEnvironment(t, cleanup)
		engine := requireEngineError(t, outcome.primary, EngineCapacity, operationUpdate, codeENOSPC)
		if engine.Diagnostic != expectedNativeDiagnostic(codeENOSPC) {
			t.Fatalf("readback truth drifted: %+v", engine)
		}
		if outcome.truth != CommitTruthOld || !outcome.commitAttempted || outcome.secondary != nil || outcome.retainedWrite != nil || outcome.retainedRead != nil || outcome.valid() != nil {
			t.Fatalf("readback truth drifted: %+v", outcome)
		}
		requireUpdateValue(t, store, mutation.DBI, mutation.Key, mutation.Literal, true)
		mustEnvironment(t, store.Close())
	})

	t.Run("post-commit ENOSPC unreadable", func(t *testing.T) {
		store, err := Create(filepath.Join(t.TempDir(), "db"), environmentConfig())
		mustEnvironment(t, err)
		mutation := Mutation{DBI: readDBIsLiteral()[0], Key: []byte{2}, BeforePresent: true, AfterKind: planAfterLiteral, Literal: []byte{}}
		mustEnvironment(t, fixtureSeedRows(store, fixtureRawRow{dbi: mutation.DBI, key: mutation.Key, value: mutation.Literal}))
		outcome, cleanup := fixtureUpdatePostCommitENOSPCUnreadable(store, updateNativePlan(t, mutation))
		mustEnvironment(t, cleanup)
		if outcome.truth != CommitTruthUnknown || !outcome.commitAttempted || outcome.primary == nil || outcome.secondary == nil || outcome.retainedWrite != nil || outcome.retainedRead != nil || outcome.valid() != nil {
			t.Fatalf("readback truth drifted: %+v", outcome)
		}
		_ = requireEngineError(t, outcome.primary, EngineCapacity, operationUpdate, codeENOSPC)
		mustEnvironment(t, store.Close())
	})
}

func TestNativeUpdateImageFamilies(t *testing.T) {
	for _, alias := range []bool{false, true} {
		t.Run(map[bool]string{false: "non-target reference", true: "target reference alias"}[alias], func(t *testing.T) {
			batch := updatePlanBatch(t)
			oldMeta := append([]byte(nil), batch.Mutations[1].Literal...)
			oldDelete := append([]byte(nil), batch.Mutations[3].Literal...)
			oldReference := append([]byte(nil), batch.Mutations[3].Literal...)
			oldMeta[len(oldMeta)-1], oldDelete[0], oldReference[len(oldReference)-1] = 1, 2, 3
			if alias {
				batch.Mutations[3].BeforePresent = true
				batch.Mutations[8].RefKey = append([]byte(nil), batch.Mutations[3].Key...)
				copy(batch.Mutations[8].Key[41:77], batch.Mutations[3].Key[8:44])
			}
			plan := updateNativePlan(t, batch.Mutations...)
			store, err := Create(filepath.Join(t.TempDir(), "db"), environmentConfig())
			mustEnvironment(t, err)
			rows := []fixtureRawRow{
				{dbi: batch.Mutations[1].DBI, key: batch.Mutations[1].Key, value: oldMeta},
				{dbi: batch.Mutations[2].DBI, key: batch.Mutations[2].Key, value: oldDelete},
			}
			if alias {
				rows = append(rows, fixtureRawRow{dbi: batch.Mutations[3].DBI, key: batch.Mutations[3].Key, value: oldReference})
			} else {
				rows = append(rows, fixtureRawRow{dbi: batch.Mutations[8].RefDBI, key: batch.Mutations[8].RefKey, value: oldReference})
			}
			mustEnvironment(t, fixtureSeedRows(store, rows...))
			outcome, cleanup := fixtureUpdatePostCommitENOSPC(store, plan)
			mustEnvironment(t, cleanup)
			_ = requireEngineError(t, outcome.primary, EngineCapacity, operationUpdate, codeENOSPC)
			requireUpdateTruth(t, outcome, CommitTruthNew, true, outcome.primary, nil)
			for i, mutation := range batch.Mutations {
				want, present := mutation.Literal, mutation.AfterKind != planAfterAbsent
				if mutation.AfterKind == planAfterOldValueRef {
					want = oldReference
				}
				requireUpdateValue(t, store, mutation.DBI, mutation.Key, want, present)
				if i == 8 && !alias {
					requireUpdateValue(t, store, mutation.RefDBI, mutation.RefKey, oldReference, true)
				}
			}
			mustEnvironment(t, store.Close())
		})
	}
}

func TestNativeUpdateUnknownImages(t *testing.T) {
	newPlan := func(t *testing.T, extra bool) ([]ownedMutation, []Mutation) {
		t.Helper()
		rows := []Mutation{{DBI: readDBIsLiteral()[0], Key: []byte{2}, AfterKind: planAfterLiteral, Literal: []byte{}}}
		if extra {
			key, err := MetaKey(0x10, 1)
			if err != nil {
				t.Fatal(err)
			}
			rows = append(rows, Mutation{DBI: readDBIsLiteral()[0], Key: key, AfterKind: planAfterLiteral, Literal: LogicalCounterValue(0, 0)})
		}
		return updateNativePlan(t, rows...), rows
	}
	requireUnknown := func(t *testing.T, outcome updateNativeOutcome) {
		t.Helper()
		engine := requireEngineError(t, outcome.primary, EngineCapacity, operationUpdate, codeENOSPC)
		if engine.Diagnostic != expectedNativeDiagnostic(codeENOSPC) {
			t.Fatalf("UNKNOWN primary=%+v", engine)
		}
		requireUpdateTruth(t, outcome, CommitTruthUnknown, true, outcome.primary, nil)
	}
	t.Run("third image", func(t *testing.T) {
		plan, rows := newPlan(t, false)
		store, err := Create(filepath.Join(t.TempDir(), "db"), environmentConfig())
		mustEnvironment(t, err)
		outcome, cleanup := fixtureUpdatePostCommitENOSPCThird(store, plan)
		mustEnvironment(t, cleanup)
		requireUnknown(t, outcome)
		requireUpdateValue(t, store, rows[0].DBI, rows[0].Key, []byte{0x7f}, true)
		mustEnvironment(t, store.Close())
	})
	t.Run("mixed image", func(t *testing.T) {
		plan, rows := newPlan(t, true)
		store, err := Create(filepath.Join(t.TempDir(), "db"), environmentConfig())
		mustEnvironment(t, err)
		outcome, cleanup := fixtureUpdatePostCommitENOSPCThird(store, plan)
		mustEnvironment(t, cleanup)
		requireUnknown(t, outcome)
		requireUpdateValue(t, store, rows[0].DBI, rows[0].Key, []byte{0x7f}, true)
		requireUpdateValue(t, store, rows[1].DBI, rows[1].Key, rows[1].Literal, true)
		mustEnvironment(t, store.Close())
	})
	t.Run("missing image", func(t *testing.T) {
		rows := []Mutation{{DBI: readDBIsLiteral()[0], Key: []byte{2}, BeforePresent: true, AfterKind: planAfterLiteral, Literal: []byte{}}}
		plan := updateNativePlan(t, rows...)
		store, err := Create(filepath.Join(t.TempDir(), "db"), environmentConfig())
		mustEnvironment(t, err)
		mustEnvironment(t, fixtureSeedRows(store, fixtureRawRow{dbi: rows[0].DBI, key: rows[0].Key, value: []byte{0x42}}))
		outcome, cleanup := fixtureUpdatePostCommitENOSPCMissing(store, plan)
		mustEnvironment(t, cleanup)
		requireUnknown(t, outcome)
		requireUpdateValue(t, store, rows[0].DBI, rows[0].Key, nil, false)
		mustEnvironment(t, store.Close())
	})
}
