//go:build cgo && (darwin || linux) && (amd64 || arm64)

package mdbx

import (
	"bytes"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"testing"
)

func admissionBatch(value []byte, before bool) Batch {
	return Batch{Mutations: []Mutation{
		{DBI: DBI{Name: "meta-v1"}, Key: []byte{2}, BeforePresent: before, AfterKind: AfterLiteral, Literal: value},
		{DBI: DBI{Name: "meta-v1"}, Key: []byte{16, 0, 0, 0, 0, 0, 0, 0, 1}, BeforePresent: before, AfterKind: AfterLiteral, Literal: []byte{0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 1}},
	}}
}

func admissionImages(t *testing.T, store *Store, want Batch) {
	t.Helper()
	mustEnvironment(t, store.View(func(reader *Reader) error {
		for _, row := range want.Mutations {
			got, present, err := reader.Get(row.DBI, row.Key)
			if err != nil || !present || !bytes.Equal(got, row.Literal) {
				t.Fatalf("authority Update rejection changed rows: key=%x present=%v err=%v", row.Key, present, err)
			}
		}
		page, err := reader.PrefixPage(DBI{Name: "canonical-v1", Rank: 2}, []byte{0, 0, 0, 0, 0, 0, 0, 1}, nil, 1, 1024)
		if err != nil || len(page.Rows) != 0 {
			t.Fatalf("authority Update rejection changed rows: auxiliary count=%d err=%v", len(page.Rows), err)
		}
		return nil
	}))
}

func admissionTuple(t *testing.T, truth CommitTruth, err error, capacity bool) {
	t.Helper()
	class, code, diagnostic := "InvalidInput", 22, "invalid Update Batch"
	if capacity {
		class, code, diagnostic = "Capacity", -30417, "Update Batch exceeds bound"
	}
	e, ok := directTestEngineError(err)
	if truth.String() != "OLD" || !ok || e == nil || string(e.Class) != class || e.Operation != "update" || e.Code != code || e.Diagnostic != diagnostic || e.Cause != nil || e.ReopenRequired {
		t.Fatalf("authority Update rejection tuple: truth=%s err=%+v", truth, err)
	}
}

func TestStorageAuthorityAdmissionUpdateAccepted(t *testing.T) {
	path, cfg := filepath.Join(t.TempDir(), "db"), environmentConfig()
	store, err := Create(path, cfg)
	mustEnvironment(t, err)
	for i, value := range [][]byte{admissionNone(), codecLiteralCases(t)[6].b, admissionMaximum()} {
		batch := Batch{Mutations: admissionBatch(value, i != 0).Mutations[:1]}
		truth, err := store.Update(func(*Reader) (Batch, error) { return batch, nil })
		if truth.String() != "NEW" || err != nil {
			t.Fatalf("authority Update accepted bytes: size=%d truth=%s err=%v", len(value), truth, err)
		}
		admissionImages(t, store, batch)
		mustEnvironment(t, store.Close())
		store, err = Open(path, cfg)
		mustEnvironment(t, err)
		admissionImages(t, store, batch)
	}
	mustEnvironment(t, store.Close())
}

func TestStorageAuthorityAdmissionUpdateRejected(t *testing.T) {
	path, cfg := filepath.Join(t.TempDir(), "db"), environmentConfig()
	store, err := Create(path, cfg)
	mustEnvironment(t, err)
	old := admissionBatch(admissionNone(), false)
	truth, err := store.Update(func(*Reader) (Batch, error) { return old, nil })
	if truth.String() != "NEW" || err != nil {
		t.Fatalf("authority seed: %s/%v", truth, err)
	}
	admissionImages(t, store, old)
	bad := admissionBatch([]byte{9}, true)
	bad.Mutations[1].Literal[7] = 8
	var escaped *Reader
	truth, err = store.Update(func(r *Reader) (Batch, error) { escaped = r; return bad, nil })
	admissionTuple(t, truth, err, false)
	_, _, expired := escaped.Get(DBI{Name: "meta-v1"}, []byte{2})
	if expired == nil || store.state != storeOPEN || store.terminal != nil || store.terminalTruth != 0 {
		t.Fatal("authority rejection lifecycle changed")
	}
	admissionImages(t, store, old)
	truth, err = store.Update(func(*Reader) (Batch, error) { return admissionBatch(admissionNone(), true), nil })
	if truth.String() != "NEW" || err != nil {
		t.Fatalf("authority original Store reuse: %s/%v", truth, err)
	}
	mustEnvironment(t, store.Close())
	store, err = Open(path, cfg)
	mustEnvironment(t, err)
	admissionImages(t, store, old)
	truth, err = store.Update(func(*Reader) (Batch, error) { return admissionBatch(codecLiteralCases(t)[6].b, true), nil })
	if truth.String() != "NEW" || err != nil {
		t.Fatalf("authority rejection reuse: %s/%v", truth, err)
	}
	mustEnvironment(t, store.Close())
}

func TestStorageAuthorityAdmissionCallbackPrecedence(t *testing.T) {
	direct, cause := errors.New("direct callback"), errors.New("distinct callback cause")
	wrapped := fmt.Errorf("callback wrapper: %w", direct)
	var typedNil *EngineError
	caused := &EngineError{Class: EngineIO, Operation: "callback", Code: 71, Diagnostic: "callback-owned", Cause: cause}
	for _, row := range []struct {
		name           string
		result, unwrap error
	}{
		{"nil", nil, nil}, {"direct", direct, nil}, {"wrapped", wrapped, direct}, {"typed-nil", typedNil, nil}, {"cause-bearing", caused, cause},
	} {
		t.Run(row.name, func(t *testing.T) {
			path, cfg := filepath.Join(t.TempDir(), "db"), environmentConfig()
			store, err := Create(path, cfg)
			mustEnvironment(t, err)
			old := admissionBatch(admissionNone(), false)
			truth, err := store.Update(func(*Reader) (Batch, error) { return old, nil })
			if truth.String() != "NEW" || err != nil {
				t.Fatalf("authority seed: %s/%v", truth, err)
			}
			bad := admissionBatch([]byte{9}, true)
			bad.Mutations[1].Literal[7] = 8
			var escaped *Reader
			truth, err = store.Update(func(r *Reader) (Batch, error) { escaped = r; return bad, row.result })
			if row.result == nil {
				admissionTuple(t, truth, err, false)
			} else if truth.String() != "OLD" || !sameError(err, row.result) || !sameError(errors.Unwrap(err), row.unwrap) || !errors.Is(err, row.result) || (row.unwrap != nil && !errors.Is(err, row.unwrap)) {
				t.Fatalf("authority callback identity changed: row=%s truth=%s err=%v", row.name, truth, err)
			}
			if row.name == "typed-nil" {
				var e *EngineError
				if err == nil || reflect.TypeOf(err) != reflect.TypeFor[*EngineError]() || !errors.As(err, &e) || e != nil {
					t.Fatal("authority callback identity changed: typed-nil")
				}
			}
			if row.name == "cause-bearing" && !sameError(caused.Cause, cause) {
				t.Fatal("authority callback identity changed: cause")
			}
			_, _, expired := escaped.Get(DBI{Name: "meta-v1"}, []byte{2})
			if expired == nil || store.state != storeOPEN || store.terminal != nil || store.terminalTruth != 0 {
				t.Fatal("authority callback lifecycle changed")
			}
			admissionImages(t, store, old)
			truth, err = store.Update(func(*Reader) (Batch, error) { return admissionBatch(admissionNone(), true), nil })
			if truth.String() != "NEW" || err != nil {
				t.Fatalf("authority original Store reuse: %s/%v", truth, err)
			}
			mustEnvironment(t, store.Close())
			store, err = Open(path, cfg)
			mustEnvironment(t, err)
			admissionImages(t, store, old)
			truth, err = store.Update(func(*Reader) (Batch, error) { return admissionBatch(admissionNone(), true), nil })
			if truth.String() != "NEW" || err != nil {
				t.Fatalf("authority callback reuse: %s/%v", truth, err)
			}
			mustEnvironment(t, store.Close())
		})
	}
}

func TestStorageAuthorityAdmissionOrder(t *testing.T) {
	for _, capacity := range []bool{false, true} {
		t.Run(fmt.Sprintf("earlier-capacity-%v", capacity), func(t *testing.T) {
			path, cfg := filepath.Join(t.TempDir(), "db"), environmentConfig()
			store, err := Create(path, cfg)
			mustEnvironment(t, err)
			old := admissionBatch(admissionNone(), false)
			truth, err := store.Update(func(*Reader) (Batch, error) { return old, nil })
			if truth.String() != "NEW" || err != nil {
				t.Fatalf("authority seed: %s/%v", truth, err)
			}
			batch := Batch{Mutations: admissionBatch(make([]byte, 1_048_577), true).Mutations[:1]}
			if capacity {
				batch = updatePlanAuxBatch(t, 16_385)
				batch.Mutations = append(batch.Mutations, admissionBatch([]byte{9}, true).Mutations[0])
			}
			truth, err = store.Update(func(*Reader) (Batch, error) { return batch, nil })
			admissionTuple(t, truth, err, capacity)
			if store.state != storeOPEN || store.terminal != nil || store.terminalTruth != 0 {
				t.Fatal("authority order lifecycle changed")
			}
			admissionImages(t, store, old)
			truth, err = store.Update(func(*Reader) (Batch, error) { return admissionBatch(admissionNone(), true), nil })
			if truth.String() != "NEW" || err != nil {
				t.Fatalf("authority original Store reuse: %s/%v", truth, err)
			}
			mustEnvironment(t, store.Close())
			store, err = Open(path, cfg)
			mustEnvironment(t, err)
			admissionImages(t, store, old)
			truth, err = store.Update(func(*Reader) (Batch, error) { return admissionBatch(admissionNone(), true), nil })
			if truth.String() != "NEW" || err != nil {
				t.Fatalf("authority order reuse: %s/%v", truth, err)
			}
			mustEnvironment(t, store.Close())
		})
	}
}
