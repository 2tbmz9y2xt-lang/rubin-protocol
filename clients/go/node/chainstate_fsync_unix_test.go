//go:build unix

package node

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// Lives in a `//go:build unix` file because os.Geteuid() is Unix-only and
// would prevent the chainstate_test.go file from compiling under
// GOOS=windows (Copilot review feedback on PR #1218).
func TestWriteFileAtomicFailsWhenParentNotWritable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: chmod-based permission check does not apply")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatalf("chmod parent read-only: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	path := filepath.Join(dir, "denied.bin")
	if err := writeFileAtomic(path, []byte("nope"), 0o600); err == nil {
		t.Fatalf("writeFileAtomic to read-only parent: expected error, got nil")
	}

	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("chmod parent restore: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(dir, atomicWriteScratchLeaf)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("fixed scratch remained after rejected write: %v", err)
	}
}

func TestWriteFileIfAbsentExactMatchResyncsMode0500WithoutReservedNames(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: chmod-based permission check does not apply")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "exact.bin")
	content := []byte("already present")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("seed destination: %v", err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatalf("chmod parent read-only: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	if err := writeFileIfAbsent(path, content); err != nil {
		t.Fatalf("exact-match write in mode-0500 parent: %v", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("chmod parent restore: %v", err)
	}
	for _, leaf := range []string{atomicWriteLockLeaf, atomicWriteScratchLeaf} {
		if _, err := os.Lstat(filepath.Join(dir, leaf)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("exact-match write created %s: %v", leaf, err)
		}
	}
}

func TestSyncDirRejectsExecuteOnlyParent(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: chmod-based permission check does not apply")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o300); err != nil {
		t.Fatalf("chmod parent execute-only: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	if err := syncDir(dir); err == nil {
		t.Fatal("syncDir on execute-only dir: expected error")
	}
}
