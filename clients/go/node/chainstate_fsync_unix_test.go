//go:build unix

package node

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestWriteFileAtomicFailsWhenParentNotWritable exercises the OpenFile
// error path of writeAndSyncTemp by chmod'ing the parent dir read-only
// before the temp file can be created. Skipped when running as root since
// root bypasses the mode check on most filesystems.
//
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

	// Tmp file must NOT remain on the filesystem either way (writeFileAtomic
	// either failed before creating it or cleaned it up via os.Remove).
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("chmod parent restore: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if strings.Contains(name, ".tmp.") {
			t.Fatalf("stale tmp file remained after open failure: %s", name)
		}
	}
}

// TestWriteAndSyncTempFailsOnUnwritableParent exercises writeAndSyncTemp's
// OpenFile error path directly, ensuring the helper is honestly testable
// without going through the full writeFileAtomic + Rename + syncDir chain.
//
// Lives in a `//go:build unix` file for the same reason as
// TestWriteFileAtomicFailsWhenParentNotWritable.
func TestWriteAndSyncTempFailsOnUnwritableParent(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: chmod-based permission check does not apply")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatalf("chmod parent read-only: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	tmpPath := filepath.Join(dir, "x.tmp.1")
	if err := writeAndSyncTemp(tmpPath, []byte("nope"), 0o600); err == nil {
		t.Fatalf("writeAndSyncTemp into read-only parent: expected error, got nil")
	}
}

// TestSyncDirIsBestEffortOnExecuteOnlyParent — exercises the Codex P2 fix
// from PR #1218. A parent directory with mode 0300 (write+execute, no read)
// permits create/rename but blocks os.Open(dir) for reading. Before the
// fix, syncDir returned EACCES after the rename had already succeeded,
// making callers treat committed state as failed. After the fix, syncDir
// silently returns nil on EACCES so the rename is reported as successful.
func TestSyncDirIsBestEffortOnExecuteOnlyParent(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: chmod-based permission check does not apply")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o300); err != nil {
		t.Fatalf("chmod parent execute-only: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	if err := syncDir(dir); err != nil {
		t.Fatalf("syncDir on execute-only dir: expected nil (best-effort), got %v", err)
	}
}
