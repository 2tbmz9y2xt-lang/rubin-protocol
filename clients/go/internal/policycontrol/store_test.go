package policycontrol

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"syscall"
	"testing"
	"time"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/filelock"
)

func testIdentity(b byte) Identity {
	return Identity{InstallationID: fill32(b), ChainID: fill32(b + 1), GenesisHash: fill32(b + 2), Profile: ProfileV1}
}

func storeDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "policy")
	must(t, os.Mkdir(dir, 0o700))
	must(t, os.Chmod(dir, 0o700))
	return dir
}

func mustCreate(t *testing.T, dir string, id Identity) *Store {
	t.Helper()
	s, err := Create(dir, id, NewInstallationProof{Identity: id})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func mustOpen(t *testing.T, dir string, id Identity) *Store {
	t.Helper()
	s, err := Open(dir, id)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func dirNames(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	must(t, err)
	names := []string{}
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	return names
}

func fileBytes(t *testing.T, dir string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, controlFile))
	must(t, err)
	return b
}

func mustView(t *testing.T, s *Store) View {
	t.Helper()
	v, err := s.View()
	if err != nil {
		t.Fatalf("View: %v", err)
	}
	return v
}

// A1: positive creation yields exactly the initial state and reads back.
func TestCreateNewInstallation(t *testing.T) {
	dir, id := storeDir(t), testIdentity(1)
	s := mustCreate(t, dir, id)
	want := View{Identity: id}
	if v := mustView(t, s); !reflect.DeepEqual(v, want) {
		t.Fatalf("view %+v, want %+v", v, want)
	}
	if names := dirNames(t, dir); !reflect.DeepEqual(names, []string{controlFile}) {
		t.Fatalf("directory holds %v", names)
	}
	if info, err := os.Stat(filepath.Join(dir, controlFile)); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("P mode %v err %v", info, err)
	}
	img, _ := initialImage()
	if got := fileBytes(t, dir); !bytes.Equal(got[8+96:], img[8+96:]) {
		t.Fatal("initial image differs from the independent initial shape")
	}
	must(t, s.Close())
	if v := mustView(t, mustOpen(t, dir, id)); !reflect.DeepEqual(v, want) {
		t.Fatalf("reopened view %+v", v)
	}
}

// A1, X14: Create refuses without positive proof or directory and creates nothing.
func TestCreateRefusesWithoutProofOrDirectory(t *testing.T) {
	id := testIdentity(1)
	other := testIdentity(9)
	for name, proof := range map[string]NewInstallationProof{"zero proof": {}, "other identity": {Identity: other}} {
		dir := storeDir(t)
		if s, err := Create(dir, id, proof); s != nil || !errors.Is(err, ErrRefused) {
			t.Fatalf("%s: Create err=%v", name, err)
		}
		if names := dirNames(t, dir); len(names) != 0 {
			t.Fatalf("%s: created %v", name, names)
		}
	}
	wantErr(t, ErrRefused)(Create(storeDir(t), Identity{}, NewInstallationProof{}))
	absent := filepath.Join(t.TempDir(), "absent")
	if s, err := Create(absent, id, NewInstallationProof{Identity: id}); s != nil || !errors.Is(err, ErrUnreadable) {
		t.Fatalf("absent directory: %v", err)
	}
	if _, err := os.Lstat(absent); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Create made the directory: %v", err)
	}
}

// X1: missing P without positive proof is never fresh; nothing is created.
func TestOpenMissingControl(t *testing.T) {
	id := testIdentity(1)
	absent := filepath.Join(t.TempDir(), "absent")
	if s, err := Open(absent, id); s != nil || !errors.Is(err, ErrMissingControl) {
		t.Fatalf("absent directory: %v", err)
	}
	if _, err := os.Lstat(absent); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Open made the directory: %v", err)
	}
	dir := storeDir(t)
	if s, err := Open(dir, id); s != nil || !errors.Is(err, ErrMissingControl) {
		t.Fatalf("empty directory: %v", err)
	}
	if names := dirNames(t, dir); len(names) != 0 {
		t.Fatalf("Open created %v", names)
	}
	if s, err := Create(dir, id, NewInstallationProof{Identity: id}); err != nil {
		t.Fatalf("lock was not released after missing control: %v", err)
	} else {
		_ = s.Close()
	}
}

// X2, H4: malformed, unreadable or mismatched P is an integrity error and is never reset, recreated or adopted; Create over an existing store refuses.
func TestOpenRejectsMalformedOrMismatchedControl(t *testing.T) {
	id := testIdentity(1)
	dir := storeDir(t)
	must(t, mustCreate(t, dir, id).Close())
	good := fileBytes(t, dir)
	if s, err := Create(dir, id, NewInstallationProof{Identity: id}); s != nil || !errors.Is(err, ErrRefused) {
		t.Fatalf("Create over existing store: %v", err)
	}
	foreignDir := storeDir(t)
	for _, other := range []Identity{testIdentity(7), func() Identity { o := id; o.ChainID = fill32(0x77); return o }()} {
		must(t, mustCreate(t, foreignDir, other).Close())
		foreign := fileBytes(t, foreignDir)
		_ = os.Remove(filepath.Join(foreignDir, controlFile))
		must(t, os.WriteFile(filepath.Join(dir, controlFile), foreign, 0o600))
		if s, err := Open(dir, id); s != nil || !errors.Is(err, ErrIdentityMismatch) || !errors.Is(err, ErrIntegrity) {
			t.Fatalf("foreign identity adopted: %v", err)
		}
		if !bytes.Equal(fileBytes(t, dir), foreign) {
			t.Fatal("mismatched P was rewritten")
		}
	}
	profile := bytes.Clone(good)
	profile[8+96] = 2
	for name, img := range map[string][]byte{"truncated": good[:len(good)-1], "trailing": append(bytes.Clone(good), 0), "profile": profile, "empty": {}} {
		must(t, os.WriteFile(filepath.Join(dir, controlFile), img, 0o600))
		if s, err := Open(dir, id); s != nil || !errors.Is(err, ErrIntegrity) {
			t.Fatalf("%s: Open err=%v", name, err)
		}
		if !bytes.Equal(fileBytes(t, dir), img) || !reflect.DeepEqual(dirNames(t, dir), []string{controlFile}) {
			t.Fatalf("%s: malformed P was reset or recreated", name)
		}
	}
	wantErr(t, ErrRefused)(Open(dir, Identity{}))
}

// X14, X4: the lock result decides before any read; nothing is created and no invalid result is treated as unlocked or fresh.
func TestLockAndPathResults(t *testing.T) {
	id := testIdentity(1)
	base := t.TempDir()
	regular := filepath.Join(base, "regular")
	must(t, os.WriteFile(regular, nil, 0o700))
	wide := filepath.Join(base, "wide")
	must(t, os.Mkdir(wide, 0o700))
	must(t, os.Chmod(wide, 0o755))
	target := storeDir(t)
	link := filepath.Join(base, "link")
	must(t, os.Symlink(target, link))
	for name, path := range map[string]string{"regular": regular, "mode 0755": wide, "symlink": link} {
		if s, err := Open(path, id); s != nil || !errors.Is(err, ErrUnreadable) {
			t.Fatalf("Open %s: %v", name, err)
		}
		if s, err := Create(path, id, NewInstallationProof{Identity: id}); s != nil || !errors.Is(err, ErrUnreadable) {
			t.Fatalf("Create %s: %v", name, err)
		}
	}
	if names := dirNames(t, wide); len(names) != 0 {
		t.Fatalf("created %v under a refused directory", names)
	}
	if names := dirNames(t, target); len(names) != 0 {
		t.Fatalf("created %v through a symlink", names)
	}
	for name, res := range map[string]filelock.Result{"unsupported host": filelock.ResultUnsupportedHost, "invalid": filelock.ResultInvalidOrUnopenable, "empty": ""} {
		h := hooks{acquire: func(string) (*filelock.Handle, filelock.Result, error) {
			if res == "" {
				return nil, "", nil
			}
			return nil, res, errors.New("injected")
		}}
		dir := storeDir(t)
		if s, err := start(dir, id, &NewInstallationProof{Identity: id}, h); s != nil || !errors.Is(err, ErrUnreadable) {
			t.Fatalf("create %s: %v", name, err)
		}
		if s, err := start(dir, id, nil, h); s != nil || !errors.Is(err, ErrUnreadable) {
			t.Fatalf("open %s: %v", name, err)
		}
		if names := dirNames(t, dir); len(names) != 0 {
			t.Fatalf("%s: created %v", name, names)
		}
	}
	dir := storeDir(t)
	mustCreate(t, dir, id)
	if s, err := Open(dir, id); s != nil || !errors.Is(err, ErrBusy) {
		t.Fatalf("second Open in process: %v", err)
	}
	fifoDir := storeDir(t)
	must(t, syscall.Mkfifo(filepath.Join(fifoDir, controlFile), 0o600))
	// A FIFO P refuses within a bounded deadline (a liveness bound only), first without a writer and then with a live writer that writes nothing.
	for _, live := range []bool{false, true} {
		if live {
			writer, err := os.OpenFile(filepath.Join(fifoDir, controlFile), os.O_RDWR, 0)
			must(t, err)
			t.Cleanup(func() { _ = writer.Close() })
		}
		done := make(chan error, 1)
		go func() { _, err := Open(fifoDir, id); done <- err }()
		select {
		case err := <-done:
			if !errors.Is(err, ErrUnreadable) {
				t.Fatalf("FIFO P (live writer %t): %v", live, err)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("Open waited on a FIFO P (live writer %t)", live)
		}
	}
	pdir := storeDir(t)
	must(t, os.Symlink(filepath.Join(dir, controlFile), filepath.Join(pdir, controlFile)))
	if s, err := Open(pdir, id); s != nil || !errors.Is(err, ErrUnreadable) {
		t.Fatalf("symlinked P: %v", err)
	}
}

// A1: Create reads the new image back; a readback that differs refuses.
func TestCreateReadbackRefusesTamperedImage(t *testing.T) {
	dir, id := storeDir(t), testIdentity(1)
	h := productionHooks
	h.fault = func(st stage) error {
		if st == stageRead {
			return os.WriteFile(filepath.Join(dir, controlFile), append(fileBytes(t, dir), 0), 0o600)
		}
		return nil
	}
	if s, err := start(dir, id, &NewInstallationProof{Identity: id}, h); s != nil || !errors.Is(err, ErrIntegrity) {
		t.Fatalf("tampered readback: %v", err)
	}
}
