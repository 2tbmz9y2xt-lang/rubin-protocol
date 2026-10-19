//go:build cgo && (darwin || linux) && (amd64 || arm64)

package mdbx

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sync"
	"testing"
)

func treeNativeStore(t *testing.T) (*Store, string, [32]byte) {
	t.Helper()
	path, identity := filepath.Join(t.TempDir(), "db"), [32]byte{7}
	store, err := CreateTreeV1(path, environmentConfig(), identity)
	if err != nil {
		t.Fatalf("tree families Create: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store, path, identity
}

func treeNativeError(t *testing.T, err error, op engineOperation, class EngineClass, code int, diagnostic string, cause error) {
	t.Helper()
	engine, direct := directTestEngineError(err)
	if !direct || engine.Operation != string(op) || engine.Class != class || engine.Code != code || engine.Diagnostic != diagnostic || engine.Cause != cause || engine.ReopenRequired {
		t.Fatalf("tree exact error tuple: %+v, want %s/%s/%d/%s/%v", err, op, class, code, diagnostic, cause)
	}
}

func treeNativeIntegrity(t *testing.T, err error, op engineOperation, cause error) {
	t.Helper()
	treeNativeError(t, err, op, EngineClass("Integrity"), -30796, "invalid tree native representation", cause)
}

func treeNativeZeroResources(t *testing.T, store *Store) {
	t.Helper()
	if store.format.Load() != 0 || store.databaseID != ([32]byte{}) || store.config != (ConfigV1{}) || !reflect.ValueOf(store.dbis).IsZero() || !validStoreShape(store) {
		t.Fatal("tree format/context/slot8 resource reset")
	}
}

func TestTreeNativeFactories(t *testing.T) {
	store, path, identity := treeNativeStore(t)
	want := [9]DBI{
		{Name: "meta-v1", Rank: 0},
		{Name: "utxo-v1", Rank: 1},
		{Name: "canonical-v1", Rank: 2},
		{Name: "headers-v1", Rank: 3},
		{Name: "blocks-v1", Rank: 4},
		{Name: "undo-v1", Rank: 5},
		{Name: "staged-v1", Rank: 6},
		{Name: "canonical-owner-v1", Rank: 7},
		{Name: "tree-node-v1", Rank: 8},
	}
	for _, phase := range []string{"create", "open"} {
		t.Run(phase, func(t *testing.T) {
			inspection, err := store.Inspect()
			mustEnvironment(t, err)
			for rank, row := range inspection.DBIs {
				count := uint64(0)
				if rank == 0 {
					count = 3
				}
				if row.DBI != want[rank] || row.Entries != count || row.PageSize != environmentConfig().PageSize {
					t.Fatalf("tree families: rank %d %+v", rank, row)
				}
			}
			if store.format.Load() != 3 || store.databaseID != identity || store.canonicalOwnerVerified {
				t.Fatal("tree factory immutable context or permission")
			}
			mustEnvironment(t, store.View(func(reader *Reader) error {
				for _, row := range []struct{ key, value []byte }{
					{[]byte{0}, []byte{0, 0, 0, 3}},
					{[]byte{1}, mustConfigBytes(t, environmentConfig())},
					{[]byte{3}, identity[:]},
				} {
					value, present, err := reader.Get(want[0], row.key)
					if err != nil || !present || !bytes.Equal(value, row.value) {
						t.Fatalf("tree factory controls: %x=%x/%v/%v", row.key, value, present, err)
					}
					value[0] ^= 1
				}
				got, present, err := reader.ReadTreeAuthorityV1()
				if err != nil || present || !reflect.DeepEqual(got, TreeAuthorityV1{}) || reader.failure != nil || !reader.usable() {
					t.Fatalf("tree control-only absence: %+v/%v/%v", got, present, err)
				}
				return nil
			}))
		})
		mustEnvironment(t, store.Close())
		treeNativeZeroResources(t, store)
		var err error
		store, err = OpenTreeV1(path, environmentConfig(), identity)
		mustEnvironment(t, err)
	}
	mustEnvironment(t, store.Close())
}

func mustConfigBytes(t *testing.T, cfg ConfigV1) []byte {
	t.Helper()
	encoded, err := cfg.Encode()
	mustEnvironment(t, err)
	return encoded
}

func TestTreeNativeFactoryStaticAndHistorical(t *testing.T) {
	cfg, identity := environmentConfig(), [32]byte{9}
	path := filepath.Join(t.TempDir(), "zero")
	store, err := CreateTreeV1(path, cfg, [32]byte{})
	if store != nil {
		t.Fatal("zero identity published Store")
	}
	treeNativeError(t, err, operationCreate, EngineClass("InvalidInput"), 22, "invalid tree database identity", nil)
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("zero identity allocated destination")
	}
	store, err = Create(path, cfg)
	mustEnvironment(t, err)
	if store.format.Load() != 2 || store.dbis[8] != 0 || store.databaseID != ([32]byte{}) {
		t.Fatal("historical factory context")
	}
	mustEnvironment(t, store.Close())
	unavailable, err := OpenTreeV1(path, cfg, identity)
	if unavailable != nil {
		t.Fatal("recognized historical schema published tree Store")
	}
	treeNativeError(t, err, operationOpen, EngineClass("StateMismatch"), -30779, "tree schema unavailable: recognized SchemaV2", nil)
	store, err = Open(path, cfg)
	mustEnvironment(t, err)
	mustEnvironment(t, store.Close())
	unavailable, err = OpenTreeV1(path, cfg, [32]byte{})
	if unavailable != nil {
		t.Fatal("Open zero identity published Store")
	}
	treeNativeError(t, err, operationOpen, EngineClass("InvalidInput"), 22, "invalid tree database identity", nil)
	store, treePath, id := treeNativeStore(t)
	mustEnvironment(t, store.Close())
	unavailable, err = OpenTreeV1(treePath, cfg, identity)
	if unavailable != nil {
		t.Fatal("wrong identity published Store")
	}
	treeNativeIntegrity(t, err, operationOpen, nil)
	store, err = OpenTreeV1(treePath, cfg, id)
	mustEnvironment(t, err)
	mustEnvironment(t, store.Close())
}

func TestTreeNativeTypedStaticLifetime(t *testing.T) {
	store, _, _ := treeNativeStore(t)
	var escaped *Reader
	mustEnvironment(t, store.View(func(reader *Reader) error {
		escaped = reader
		root, present, err := reader.ReadTreeRootBindingV1(0)
		if root != (RootBindingV1{}) || present {
			t.Fatal("invalid generation leaked root")
		}
		treeNativeError(t, err, operationGet, EngineClass("InvalidInput"), 22, "invalid tree generation", nil)
		for _, generation := range []uint64{1, ^uint64(0)} {
			root, present, err := reader.ReadTreeRootBindingV1(generation)
			if root != (RootBindingV1{}) || present || err != nil {
				t.Fatal("tree nonzero generation domain")
			}
		}
		valid := TreeImportReferenceV1{OriginalDatabaseID: [32]byte{1}, OriginalCurrentID: 3, OriginalLagID: 4, OriginalRole: 1}
		for name, change := range map[string]func(*TreeImportReferenceV1){
			"database zero": func(r *TreeImportReferenceV1) { r.OriginalDatabaseID = [32]byte{} },
			"current zero":  func(r *TreeImportReferenceV1) { r.OriginalCurrentID = 0 },
			"lag zero":      func(r *TreeImportReferenceV1) { r.OriginalLagID = 0 },
			"equal pair":    func(r *TreeImportReferenceV1) { r.OriginalLagID = r.OriginalCurrentID },
			"role zero":     func(r *TreeImportReferenceV1) { r.OriginalRole = 0 },
			"role three":    func(r *TreeImportReferenceV1) { r.OriginalRole = 3 },
		} {
			reference := valid
			change(&reference)
			got, err := reader.ReadTreeEvidenceV1(reference)
			if !reflect.DeepEqual(got, TreeEvidenceV1{}) {
				t.Fatalf("%s partial evidence", name)
			}
			treeNativeError(t, err, operationGet, EngineClass("InvalidInput"), 22, "invalid tree evidence reference", nil)
			if reader.failure != nil || !reader.usable() {
				t.Fatalf("%s static refusal disarmed Reader", name)
			}
			root, present, err := reader.ReadTreeRootBindingV1(1)
			if root != (RootBindingV1{}) || present || err != nil {
				t.Fatalf("%s next root absent: %+v/%v/%v", name, root, present, err)
			}
		}
		copyReader := &Reader{self: reader, txn: reader.txn, dbis: reader.dbis, format: 3, databaseID: reader.databaseID, treeConfig: reader.treeConfig}
		copyReader.active.Store(true)
		_, _, err = copyReader.ReadTreeRootBindingV1(0)
		treeNativeError(t, err, operationGet, EngineClass("InvalidInput"), 22, "Reader is not active", nil)
		var group sync.WaitGroup
		for range 8 {
			group.Go(func() {
				got, present, err := reader.ReadTreeAuthorityV1()
				if err != nil || present || !reflect.DeepEqual(got, TreeAuthorityV1{}) {
					t.Errorf("concurrent empty authority: %+v/%v/%v", got, present, err)
				}
			})
		}
		group.Wait()
		return nil
	}))
	for _, reader := range []*Reader{nil, escaped} {
		_, _, err := reader.ReadTreeRootBindingV1(0)
		treeNativeError(t, err, operationGet, EngineClass("InvalidInput"), 22, "Reader is not active", nil)
		_, err = reader.ReadTreeEvidenceV1(TreeImportReferenceV1{})
		treeNativeError(t, err, operationGet, EngineClass("InvalidInput"), 22, "Reader is not active", nil)
		_, _, err = reader.ReadTreeAuthorityV1()
		treeNativeError(t, err, operationGet, EngineClass("InvalidInput"), 22, "Reader is not active", nil)
	}
	historical, err := Create(filepath.Join(t.TempDir(), "old"), environmentConfig())
	mustEnvironment(t, err)
	defer func() { _ = historical.Close() }()
	mustEnvironment(t, historical.View(func(reader *Reader) error {
		_, _, err := reader.ReadTreeRootBindingV1(0)
		treeNativeError(t, err, operationGet, EngineClass("InvalidInput"), 22, "tree Reader required", nil)
		_, err = reader.ReadTreeEvidenceV1(TreeImportReferenceV1{})
		treeNativeError(t, err, operationGet, EngineClass("InvalidInput"), 22, "tree Reader required", nil)
		_, _, err = reader.ReadTreeAuthorityV1()
		treeNativeError(t, err, operationGet, EngineClass("InvalidInput"), 22, "tree Reader required", nil)
		if !reader.usable() || reader.failure != nil {
			t.Fatal("historical tree refusal disarmed Reader")
		}
		return nil
	}))
}

func TestTreeNativeLegacyRefusal(t *testing.T) {
	store, _, _ := treeNativeStore(t)
	before, err := store.Inspect()
	mustEnvironment(t, err)
	calls := 0
	truth, stage, err := store.Update(func(*Reader) (Batch, error) { calls++; return Batch{}, nil })
	treeNativeError(t, err, operationUpdate, EngineClass("StateMismatch"), -30779, "tree store requires typed tree operation", nil)
	if truth != CommitTruth(1) || stage != UpdateStage(1) || calls != 0 {
		t.Fatal("tree legacy operation refused after callback")
	}
	mustEnvironment(t, store.View(func(reader *Reader) error {
		_, _, err := reader.ReadTreeAuthorityV1()
		return err
	}))
	after, err := store.Inspect()
	mustEnvironment(t, err)
	if after.DBIs != before.DBIs || after.RecentTxnID != before.RecentTxnID || store.terminal != nil || store.terminalTruth != 0 {
		t.Fatal("tree legacy refusal changed rows/state")
	}
	_, _, err = store.Update(nil)
	treeNativeError(t, err, operationUpdate, EngineClass("InvalidInput"), 22, "nil Update callback", nil)
	store.operations.Lock()
	_, _, err = store.Update(func(*Reader) (Batch, error) { t.Fatal("concurrent callback"); return Batch{}, nil })
	store.operations.Unlock()
	treeNativeError(t, err, operationUpdate, EngineClass("Concurrency"), -30778, "store operation in progress", nil)
}

func TestTreeNativeViewApplicationOutcomes(t *testing.T) {
	for _, mode := range []string{"nil", "error", "panic", "Goexit"} {
		t.Run(mode, func(t *testing.T) {
			store, _, _ := treeNativeStore(t)
			application, marker := errors.New("tree application"), &struct{}{}
			var escaped *Reader
			var returned error
			var panicked any
			invoke := func() {
				defer func() { panicked = recover() }()
				returned = store.View(func(reader *Reader) error {
					escaped = reader
					_, _, err := reader.ReadTreeAuthorityV1()
					mustEnvironment(t, err)
					switch mode {
					case "error":
						return application
					case "panic":
						panic(marker)
					case "Goexit":
						runtime.Goexit()
					}
					return nil
				})
			}
			if mode == "Goexit" {
				done := make(chan struct{})
				go func() { defer close(done); invoke() }()
				<-done
			} else {
				invoke()
			}
			if (mode == "error") != (returned == application) || mode != "error" && returned != nil || mode == "panic" && panicked != marker || mode != "panic" && panicked != nil || escaped.usable() || escaped.failure != nil || store.state != storeOPEN || !validStoreShape(store) {
				t.Fatalf("tree application/resource outcome: %s/%v/%v", store.state, returned, panicked)
			}
			mustEnvironment(t, store.View(func(reader *Reader) error { _, _, err := reader.ReadTreeAuthorityV1(); return err }))
			_, err := store.Inspect()
			mustEnvironment(t, err)
		})
	}
}

func TestTreeNativeRawInputDomain(t *testing.T) {
	store, _, _ := treeNativeStore(t)
	mustEnvironment(t, store.View(func(reader *Reader) error {
		for _, dbi := range []DBI{{Name: "tree-node-v1", Rank: 7}, {Name: "other", Rank: 8}, {Name: "tree-node-v1", Rank: 8, Flags: 1}, {Rank: 9}} {
			_, present, err := reader.Get(dbi, nil)
			treeNativeError(t, err, operationGet, EngineClass("InvalidInput"), 22, "invalid SchemaV2 DBI", errSchema)
			if present {
				t.Fatal("forged descriptor present")
			}
		}
		for _, key := range [][]byte{nil, make([]byte, 45), make([]byte, 47), make([]byte, 46)} {
			_, _, err := reader.Get(DBI{Name: "tree-node-v1", Rank: 8}, key)
			treeNativeError(t, err, operationGet, EngineClass("InvalidInput"), 22, "invalid SchemaV2 key", nil)
		}
		for _, rank := range []uint8{3, 4} {
			got, err := reader.GetOptionalSide(readDBIsLiteral()[rank], make([]byte, 32))
			if !reflect.DeepEqual(got, OptionalSideValueV1{}) {
				t.Fatal("old accessor tree partial result")
			}
			treeNativeError(t, err, operationGet, EngineClass("InvalidInput"), 22, "tree Reader requires initial148 accessor", nil)
			_, err = reader.GetOptionalSide(DBI{}, nil)
			treeNativeError(t, err, operationGet, EngineClass("InvalidInput"), 22, "invalid optional-side DBI or key", nil)
		}
		if !reader.usable() || reader.failure != nil {
			t.Fatal("tree raw static refusal disarmed Reader")
		}
		return nil
	}))
}

func TestTreeNativeFormatClosure(t *testing.T) {
	store, _, identity := treeNativeStore(t)
	for _, format := range []uint32{0, 1, 4} {
		store.format.Store(format)
		_, err := store.Inspect()
		treeNativeError(t, err, operationInspect, EngineClass("LocalInvariant"), -30779, "invalid Store resource shape", nil)
		store.format.Store(3)
	}
	mustEnvironment(t, store.View(func(reader *Reader) error {
		for _, format := range []uint8{0, 1, 4} {
			reader.format = format
			_, _, err := reader.ReadTreeRootBindingV1(0)
			treeNativeError(t, err, operationGet, EngineClass("InvalidInput"), 22, "Reader is not active", nil)
			reader.format = 3
		}
		reader.databaseID = [32]byte{}
		_, _, err := reader.ReadTreeAuthorityV1()
		treeNativeError(t, err, operationGet, EngineClass("InvalidInput"), 22, "Reader is not active", nil)
		reader.databaseID = identity
		reader.treeConfig = ConfigV1{}
		_, _, err = reader.ReadTreeAuthorityV1()
		treeNativeError(t, err, operationGet, EngineClass("InvalidInput"), 22, "Reader is not active", nil)
		reader.treeConfig = environmentConfig()
		_, _, err = reader.ReadTreeAuthorityV1()
		return err
	}))
}

func TestTreeNativeIntegrityErrorDomain(t *testing.T) {
	for _, cause := range []error{nil, errSchema} {
		positive := treeIntegrity(operationGet, cause)
		treeNativeIntegrity(t, positive, operationGet, cause)
		if !validConsumedReadTerminal(positive) {
			t.Fatal("tree positive integrity terminal rejected")
		}
	}
	native := nativeError(operationGet, -30796)
	engine := requireEnvironmentError(t, native, EngineIntegrity, operationGet, -30796, expectedNativeDiagnostic(-30796))
	if !engine.ReopenRequired || !validConsumedReadTerminal(native) {
		t.Fatal("native MDBX_CORRUPTED reopen projection changed")
	}
	for name, change := range map[string]func(*EngineError){
		"operation":     func(e *EngineError) { e.Operation = "open" },
		"class":         func(e *EngineError) { e.Class = EngineIO },
		"code":          func(e *EngineError) { e.Code = -30793 },
		"diagnostic":    func(e *EngineError) { e.Diagnostic = "other" },
		"cause":         func(e *EngineError) { e.Cause = errors.New("other") },
		"wrapped cause": func(e *EngineError) { e.Cause = fmt.Errorf("wrapped: %w", errSchema) },
		"reopen":        func(e *EngineError) { e.ReopenRequired = true },
	} {
		engine, direct := directTestEngineError(treeIntegrity(operationGet, nil))
		if !direct {
			t.Fatal("tree integrity result was wrapped")
		}
		change(engine)
		if validTreeIntegrityTerminal(engine) || validConsumedReadTerminal(engine) {
			t.Fatalf("tree terminal accepted wrong %s", name)
		}
	}
}
