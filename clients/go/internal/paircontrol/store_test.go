package paircontrol

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func await(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatal("synchronous owner did not reach/finish bounded test point")
	}
}

func directory(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	require(t, os.Chmod(dir, 0o700))
	return dir
}

func writeFixture(t *testing.T, dir string, b []byte) {
	t.Helper()
	f, err := os.OpenFile(filepath.Join(dir, "outer-control"), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	require(t, err)
	_, err = f.Write(b)
	require(t, err)
	require(t, f.Sync())
	require(t, f.Close())
	f, err = os.Open(dir)
	require(t, err)
	require(t, f.Sync())
	require(t, f.Close())
}

func existing(t *testing.T, v RecordV1) (*Store, string) {
	t.Helper()
	dir := directory(t)
	writeFixture(t, dir, fixtureBytes(v))
	s, err := OpenV1(dir, v.Identity)
	require(t, err)
	t.Cleanup(func() { require(t, s.CloseV1()) })
	return s, dir
}

func diskBytes(t *testing.T, dir string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "outer-control"))
	require(t, err)
	return b
}

func wantRecord(t *testing.T, s *Store, want RecordV1) {
	t.Helper()
	got, err := s.ObserveV1()
	require(t, err)
	if !reflect.DeepEqual(got, want) || !bytes.Equal(diskBytes(t, s.dir), fixtureBytes(want)) {
		t.Fatalf("record or actual durable bytes differ: got %+v want %+v", got, want)
	}
}

func wantLocal(t *testing.T, got ResultV1, err error, op, code string, want ResultV1) *ErrorV1 {
	t.Helper()
	var e *ErrorV1
	if got != want || !errors.As(err, &e) || e.Operation != op || e.Code != code {
		t.Fatalf("local tuple: %+v %v; want %+v %s/%s", got, err, want, op, code)
	}
	return e
}

func wantNilStore(t *testing.T, s *Store, err error, op, code string) *ErrorV1 {
	t.Helper()
	if s != nil {
		t.Fatal("failed constructor escaped a Store")
	}
	return wantLocal(t, ResultV1{}, err, op, code, ResultV1{})
}

func TestConstructorsAndReadOnly(t *testing.T) {
	dir, id := directory(t), identity()
	s, err := CreateV1(dir, id, NewInstallationProofV1{Identity: id})
	require(t, err)
	want := RecordV1{Identity: id, Selector: 1}
	wantRecord(t, s, want)
	attempt, err := s.PersistIntentV1(context.Background(), 0, replacement(), nil)
	wantLocal(t, attempt, err, "persist_intent", "refused", ResultV1{1, 0, false})
	wantRecord(t, s, want)
	r, err := s.RecoverV1()
	require(t, err)
	if r != (ResultV1{}) {
		t.Fatal("no attempt Recover minted truth")
	}
	before := diskBytes(t, dir)
	for range 2 {
		got, err := s.ObserveV1()
		require(t, err)
		got.Identity.DatabaseRoot = "/changed"
		wantRecord(t, s, want)
	}
	other, err := OpenV1(dir, id)
	wantNilStore(t, other, err, "open", "busy")
	other, err = CreateV1(dir, id, NewInstallationProofV1{Identity: id})
	wantNilStore(t, other, err, "create", "busy")
	require(t, s.CloseV1())
	require(t, s.CloseV1())
	got, err := s.ObserveV1()
	wantLocal(t, ResultV1{}, err, "observe", "closed", ResultV1{})
	if got != (RecordV1{}) {
		t.Fatal("closed Observe exposed record")
	}
	r, err = s.RecoverV1()
	wantLocal(t, r, err, "recover", "closed", ResultV1{})
	r, err = s.PersistIntentV1(context.Background(), 0, replacement(), nil)
	wantLocal(t, r, err, "persist_intent", "closed", ResultV1{})
	s, err = OpenV1(dir, id)
	require(t, err)
	wantRecord(t, s, want)
	require(t, s.CloseV1())
	if !bytes.Equal(before, diskBytes(t, dir)) {
		t.Fatal("read/open/close changed bytes")
	}
	other, err = CreateV1(dir, id, NewInstallationProofV1{Identity: id})
	wantNilStore(t, other, err, "create", "refused")
}

func TestConstructorRefusals(t *testing.T) {
	for _, name := range []string{"zero_identity", "bad_root", "zero_proof", "other_proof", "nonempty", "missing", "malformed", "other_identity", "pending", "symlink", "directory", "oversized", "wrong_mode"} {
		t.Run(name, func(t *testing.T) {
			dir, id, proof := directory(t), identity(), NewInstallationProofV1{Identity: identity()}
			creating, code := true, "refused"
			switch name {
			case "zero_identity":
				id.InstallationID = [32]byte{}
				code = "identity"
			case "bad_root":
				id.DatabaseRoot = "/db/../db"
				code = "identity"
			case "zero_proof":
				proof = NewInstallationProofV1{}
			case "other_proof":
				proof.Identity.ChainID[1] = 1
			case "nonempty":
				require(t, os.WriteFile(filepath.Join(dir, "other"), []byte{1}, 0o600))
			case "missing":
				creating, code = false, "missing"
			case "malformed":
				creating, code = false, "integrity"
				writeFixture(t, dir, []byte{1})
			case "other_identity":
				creating, code = false, "identity"
				v := selected()
				v.Identity.ChainID[1] = 1
				writeFixture(t, dir, fixtureBytes(v))
			case "pending":
				creating, code = false, "unresolved"
				require(t, os.WriteFile(filepath.Join(dir, "outer-control.pending"), nil, 0o600))
			case "symlink":
				creating, code = false, "unreadable"
				require(t, os.Symlink("missing", filepath.Join(dir, "outer-control")))
			case "directory":
				creating, code = false, "unreadable"
				require(t, os.Mkdir(filepath.Join(dir, "outer-control"), 0o700))
			case "oversized":
				creating, code = false, "integrity"
				writeFixture(t, dir, make([]byte, 16385))
			case "wrong_mode":
				code = "unreadable"
				require(t, os.Chmod(dir, 0o755))
			}
			var s *Store
			var err error
			if creating {
				s, err = CreateV1(dir, id, proof)
			} else {
				s, err = OpenV1(dir, id)
			}
			wantNilStore(t, s, err, map[bool]string{true: "create", false: "open"}[creating], code)
		})
	}
}


