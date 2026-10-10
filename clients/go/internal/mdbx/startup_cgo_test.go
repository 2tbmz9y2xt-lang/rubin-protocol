//go:build cgo && (darwin || linux) && (amd64 || arm64)

package mdbx

import (
	"bytes"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
	"unsafe"
)

func startupOpened(t *testing.T) *Store {
	t.Helper()
	path, cfg := filepath.Join(t.TempDir(), "db"), environmentConfig()
	mustEnvironment(t, createAndClose(path, cfg))
	store, err := Open(path, cfg)
	return consultedTrack(t, store, err)
}

func startupPermission(t *testing.T, s *Store, want bool) {
	t.Helper()
	if s.canonicalOwnerVerified != want {
		t.Fatalf("native permission=%v, want %v", s.canonicalOwnerVerified, want)
	}
	mustEnvironment(t, s.View(func(r *Reader) error {
		err := r.RequireCanonicalOwnerVerificationV1()
		if want {
			if err != nil { t.Fatalf("fresh Reader permission: %v", err) }
		} else {
			requireEnvironmentError(t, err, EngineInvalidInput, operationGet, 22, "canonical owner index is not verified")
		}
		return nil
	}))
}

func TestStartupCanonicalNativeV1(t *testing.T) {
	app := errors.New("application")
	var typedNil *nilPointerError
	for _, row := range []struct {
		name string
		completion StartupCanonicalCompletionV1
		app error
		verified bool
		invariant bool
	}{
		{"0 nil", 0, nil, false, true}, {"1 nil", 1, nil, true, false},
		{"2 nil", 2, nil, false, true}, {"255 nil", 255, nil, false, true},
		{"0 error", 0, app, false, false}, {"1 error", 1, app, false, false},
		{"2 error", 2, app, false, true}, {"255 error", 255, app, false, true},
		{"0 typed nil", 0, typedNil, false, false}, {"1 typed nil", 1, typedNil, false, false},
		{"2 typed nil", 2, typedNil, false, true}, {"255 typed nil", 255, typedNil, false, true},
	} {
		t.Run(row.name, func(t *testing.T) {
			s := startupOpened(t)
			var old *Reader
			err := s.StartupVerifyCanonicalV1(func(r *Reader) (StartupCanonicalCompletionV1, error) {
				old = r
				if r.ownerVerified || r.RequireCanonicalOwnerVerificationV1() == nil { t.Fatal("checker saw future permission") }
				return row.completion, row.app
			})
			if row.invariant {
				e := requireEnvironmentError(t, err, EngineLocalInvariant, operationView, -30779, "startup canonical verification did not complete")
				if e.Cause != row.app { t.Fatal("completion error lost application identity") }
			} else if err != row.app { t.Fatalf("raw error=%v, want identical %v", err, row.app) }
			if old.usable() || old.ownerVerified || old.failure != nil || s.state != storeOPEN { t.Fatal("checker lifetime/state drifted") }
			startupPermission(t, s, row.verified)
		})
	}
	t.Run("entry refusal", func(t *testing.T) {
		var nilStore *Store
		requireEnvironmentError(t, nilStore.StartupVerifyCanonicalV1(nil), EngineInvalidInput, operationView, 22, "nil Store")
		s := startupOpened(t)
		requireEnvironmentError(t, s.StartupVerifyCanonicalV1(nil), EngineInvalidInput, operationView, 22, "nil startup canonical callback")
		startupPermission(t, s, false)
		s = newUpdateStore(t)
		called := false
		requireEnvironmentError(t, s.StartupVerifyCanonicalV1(func(*Reader) (StartupCanonicalCompletionV1, error) { called = true; return 1, nil }), EngineInvalidInput, operationView, 22, "canonical owner index is already verified")
		if called { t.Fatal("already verified ran checker") }
		startupPermission(t, s, true)
	})
	t.Run("ordinary View", func(t *testing.T) {
		s := startupOpened(t)
		mustEnvironment(t, s.View(func(*Reader) error { return nil }))
		startupPermission(t, s, false)
	})
	t.Run("lock and fresh Update", func(t *testing.T) {
		s := startupOpened(t)
		entered, finish, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
		go func() { done <- s.StartupVerifyCanonicalV1(func(*Reader) (StartupCanonicalCompletionV1, error) { close(entered); <-finish; return 1, nil }) }()
		<-entered
		if s.canonicalOwnerVerified { t.Fatal("publication before checker completes") }
		requireEnvironmentError(t, s.View(func(*Reader) error { t.Fatal("busy View callback"); return nil }), EngineConcurrency, operationView, -30778, "store operation in progress")
		_, _, err := s.Update(func(*Reader) (Batch, error) { t.Fatal("busy Update callback"); return Batch{}, nil })
		requireEnvironmentError(t, err, EngineConcurrency, operationUpdate, -30778, "store operation in progress")
		requireEnvironmentError(t, s.Close(), EngineConcurrency, operationClose, -30778, "store operation in progress")
		close(finish)
		mustEnvironment(t, <-done)
		truth, stage, err := s.Update(func(r *Reader) (Batch, error) { return Batch{}, r.RequireCanonicalOwnerVerificationV1() })
		if err != nil || truth != CommitTruthOld || stage != UpdateStagePrewrite { t.Fatalf("fresh Update=%v/%v/%v", truth, stage, err) }
	})
	for _, mode := range []string{"panic", "Goexit"} {
		t.Run(mode, func(t *testing.T) {
			s := startupOpened(t)
			finished := make(chan struct{})
			var old *Reader
			go func() {
				defer close(finished)
				defer func() { if p := recover(); mode == "panic" && p != "startup panic" { t.Errorf("panic identity=%v", p) } }()
				_ = s.StartupVerifyCanonicalV1(func(r *Reader) (StartupCanonicalCompletionV1, error) { old = r; if mode == "panic" { panic("startup panic") }; runtime.Goexit(); return 1, nil })
				t.Error("interrupted startup returned normally")
			}()
			<-finished
			if old.usable() || s.state != storeOPEN { t.Fatal("interrupted cleanup/lifetime drifted") }
			startupPermission(t, s, false)
		})
	}
}

func TestStartupCanonicalNextV1(t *testing.T) {
	for _, generation := range []uint64{1, 9, ^uint64(0)} {
		t.Run(fmt.Sprint(generation), func(t *testing.T) {
			s := newUpdateStore(t)
			hash, work := [32]byte{7}, [40]byte{39: 1}
			forward, inverse := canonicalForwardLiteral(generation, 0, hash, work), canonicalOwnerLiteral(generation, 0, hash)
			truth, _, err := s.Update(func(*Reader) (Batch, error) { return Batch{Mutations: []Mutation{forward, inverse}}, nil })
			if truth != CommitTruthNew || err != nil { t.Fatalf("seed=%v/%v", truth, err) }
			mustEnvironment(t, s.View(func(r *Reader) error {
				for _, seeded := range []Mutation{forward, inverse} {
					row, found, err := r.StartupCanonicalNextV1(seeded.DBI, generation, nil)
					if err != nil || !found || !bytes.Equal(row.Key, seeded.Key) || !bytes.Equal(row.Value, seeded.Literal) { t.Fatalf("pull=%x/%x/%v/%v", row.Key, row.Value, found, err) }
					key, value := bytes.Clone(row.Key), bytes.Clone(row.Value)
					continuation := bytes.Clone(row.Key)
					next, present, err := r.StartupCanonicalNextV1(seeded.DBI, generation, continuation)
					if err != nil || present || !reflect.DeepEqual(next, PrefixRow{}) || !bytes.Equal(continuation, key) { t.Fatalf("exclusive exhaustion=%+v/%v/%v", next, present, err) }
					row.Key[0] ^= 0xff
					if !bytes.Equal(row.Value, value) { t.Fatal("key/value copies overlap") }
					row.Value[0] ^= 0xff
					again, _, err := r.StartupCanonicalNextV1(seeded.DBI, generation, nil)
					if err != nil || !bytes.Equal(again.Key, key) || !bytes.Equal(again.Value, value) { t.Fatal("returned row aliases native storage") }
				}
				return nil
			}))
		})
	}
	t.Run("outside-generation native boundary unit", func(t *testing.T) {
		// The native-result leaf rejects current widths but must not parse the
		// structurally valid next generation's malformed semantic payload.
		for _, rank := range []uint8{2, 7} {
			prefix := canonicalForwardKeyLiteral(1, 0)[:8]
			key := canonicalForwardKeyLiteral(2, 0)
			if rank == 7 {
				key = canonicalOwnerKeyLiteral(2, [32]byte{7})
			}
			borrowed := []byte{0x91}
			row, err := prefixPageStoredRow(readDBIsLiteral()[rank], prefix, key, unsafe.Pointer(&borrowed[0]), 1)
			if err != nil || !row.outside || row.key != nil || row.value != nil || row.valueLength != 0 || borrowed[0] != 0x91 {
				t.Fatalf("foreign payload was parsed or retained: %+v/%v", row, err)
			}
		}
	})
	t.Run("input refusal", func(t *testing.T) {
		s := newUpdateStore(t)
		mustEnvironment(t, s.View(func(r *Reader) error {
			for _, row := range []struct { dbi DBI; g uint64; after []byte; diagnostic string }{
				{DBI{Name: "wrong", Rank: 2}, 1, nil, "invalid SchemaV2 DBI"},
				{DBI{Name: "headers-v1", Rank: 3}, 1, nil, "unsupported startup canonical DBI"},
				{canonicalForwardDBILiteral, 0, nil, "invalid prefix-page prefix"},
				{canonicalForwardDBILiteral, 1, []byte{}, "invalid prefix-page continuation"},
				{canonicalForwardDBILiteral, 1, canonicalForwardKeyLiteral(2, 0), "invalid prefix-page continuation"},
				{canonicalOwnerDBILiteral, 1, canonicalForwardKeyLiteral(1, 0), "invalid prefix-page continuation"},
			} {
				got, found, err := r.StartupCanonicalNextV1(row.dbi, row.g, row.after)
				requireEnvironmentError(t, err, EngineInvalidInput, operationPrefixPage, 22, row.diagnostic)
				if found || !reflect.DeepEqual(got, PrefixRow{}) || r.failure != nil || !r.usable() { t.Fatal("input refusal changed Reader or returned data") }
			}
			return nil
		}))
		var nilReader *Reader
		_, _, err := nilReader.StartupCanonicalNextV1(canonicalForwardDBILiteral, 1, nil)
		requireEnvironmentError(t, err, EngineInvalidInput, operationPrefixPage, 22, "Reader is not active")
	})
}
