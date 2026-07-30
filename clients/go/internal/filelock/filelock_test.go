//go:build darwin || linux

package filelock

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestAcquireContendsUntilRelease(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lock")
	holder, result, err := Acquire(path)
	if err != nil || result != "" {
		t.Fatalf("first Acquire result=%q err=%v", result, err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat lock: %v", err)
	}
	if !info.Mode().IsRegular() || info.Size() != 0 {
		t.Fatalf("lock info = mode %v size %d, want regular zero-byte file", info.Mode(), info.Size())
	}

	challenger, result, err := Acquire(path)
	if challenger != nil || result != ResultContended || err == nil {
		t.Fatalf("second Acquire handle=%v result=%q err=%v", challenger, result, err)
	}
	if err := holder.Release(); err != nil {
		t.Fatalf("release holder: %v", err)
	}

	reused, result, err := Acquire(path)
	if err != nil || result != "" {
		t.Fatalf("reused Acquire result=%q err=%v", result, err)
	}
	if err := reused.Release(); err != nil {
		t.Fatalf("release reused handle: %v", err)
	}
}

func TestAcquireRejectsUnsafeLeaves(t *testing.T) {
	cases := []struct {
		name  string
		setup func(*testing.T, string)
	}{
		{
			name: "symlink",
			setup: func(t *testing.T, path string) {
				t.Helper()
				target := path + ".target"
				if err := os.WriteFile(target, nil, 0o600); err != nil {
					t.Fatalf("write target: %v", err)
				}
				if err := os.Symlink(target, path); err != nil {
					t.Fatalf("symlink: %v", err)
				}
			},
		},
		{
			name: "dangling_symlink",
			setup: func(t *testing.T, path string) {
				t.Helper()
				if err := os.Symlink(path+".missing", path); err != nil {
					t.Fatalf("symlink: %v", err)
				}
			},
		},
		{
			name: "directory",
			setup: func(t *testing.T, path string) {
				t.Helper()
				if err := os.Mkdir(path, 0o700); err != nil {
					t.Fatalf("mkdir: %v", err)
				}
			},
		},
		{
			name: "fifo",
			setup: func(t *testing.T, path string) {
				t.Helper()
				if err := syscall.Mkfifo(path, 0o600); err != nil {
					t.Fatalf("mkfifo: %v", err)
				}
			},
		},
		{
			name: "nonzero_file",
			setup: func(t *testing.T, path string) {
				t.Helper()
				if err := os.WriteFile(path, []byte("not empty"), 0o600); err != nil {
					t.Fatalf("write lock: %v", err)
				}
			},
		},
		{
			name: "hardlink",
			setup: func(t *testing.T, path string) {
				t.Helper()
				source := path + ".source"
				if err := os.WriteFile(source, nil, 0o600); err != nil {
					t.Fatalf("write source: %v", err)
				}
				if err := os.Link(source, path); err != nil {
					t.Fatalf("link: %v", err)
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "lock")
			tc.setup(t, path)
			handle, result, err := Acquire(path)
			if handle != nil || result != ResultInvalidOrUnopenable || err == nil {
				t.Fatalf("Acquire handle=%v result=%q err=%v", handle, result, err)
			}
		})
	}
}

func TestAcquireRejectsUnreadableLeaf(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can bypass lock-file permissions")
	}
	path := filepath.Join(t.TempDir(), "lock")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("write lock: %v", err)
	}
	if err := os.Chmod(path, 0); err != nil {
		t.Fatalf("chmod lock: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o600) })
	handle, result, err := Acquire(path)
	if handle != nil || result != ResultInvalidOrUnopenable || err == nil {
		t.Fatalf("Acquire handle=%v result=%q err=%v", handle, result, err)
	}
}

// TestFileLockExternalProtocol is a test-binary-only protocol for the
// cross-client harness. Run a binary made by `go test -c` with
// RUBIN_FILELOCK_PROTOCOL_MODE=holder or challenger and -test.run set to this
// exact test. Every supplied path is absolute. The holder needs LOCK_PATH,
// READY_PATH, and RELEASE_PATH; the challenger needs LOCK_PATH and RESULT_PATH.
func TestFileLockExternalProtocol(t *testing.T) {
	mode := os.Getenv("RUBIN_FILELOCK_PROTOCOL_MODE")
	if mode == "" {
		t.Skip("external filelock protocol is not requested")
	}
	lockPath := protocolAbsolutePath(t, "RUBIN_FILELOCK_PROTOCOL_LOCK_PATH")
	switch mode {
	case "holder":
		readyPath := protocolAbsolutePath(t, "RUBIN_FILELOCK_PROTOCOL_READY_PATH")
		if protocolPathInside(filepath.Dir(lockPath), readyPath) {
			t.Fatalf("ready marker must be outside locked parent: %s", readyPath)
		}
		releasePath := protocolAbsolutePath(t, "RUBIN_FILELOCK_PROTOCOL_RELEASE_PATH")
		runProtocolHolder(t, lockPath, readyPath, releasePath)
	case "challenger":
		resultPath := protocolAbsolutePath(t, "RUBIN_FILELOCK_PROTOCOL_RESULT_PATH")
		runProtocolChallenger(t, lockPath, resultPath)
	default:
		t.Fatalf("unknown RUBIN_FILELOCK_PROTOCOL_MODE %q", mode)
	}
}

func runProtocolHolder(t *testing.T, lockPath, readyPath, releasePath string) {
	t.Helper()
	handle, result, err := Acquire(lockPath)
	if err != nil || result != "" {
		t.Fatalf("holder Acquire result=%q err=%v", result, err)
	}
	defer func() {
		if err := handle.Release(); err != nil {
			t.Errorf("holder release: %v", err)
		}
	}()
	if err := os.WriteFile(readyPath, []byte("ready\n"), 0o600); err != nil {
		t.Fatalf("write ready marker: %v", err)
	}
	waitForProtocolMarker(t, releasePath)
}

func runProtocolChallenger(t *testing.T, lockPath, resultPath string) {
	t.Helper()
	handle, result, err := Acquire(lockPath)
	outcome := "acquired"
	if err != nil {
		switch result {
		case ResultContended:
			outcome = string(ResultContended)
		case ResultInvalidOrUnopenable:
			outcome = string(ResultInvalidOrUnopenable)
		default:
			t.Fatalf("challenger Acquire result=%q err=%v", result, err)
		}
	} else if err := handle.Release(); err != nil {
		t.Fatalf("challenger release: %v", err)
	}
	if err := os.WriteFile(resultPath, []byte(outcome+"\n"), 0o600); err != nil {
		t.Fatalf("write result marker: %v", err)
	}
}

func protocolAbsolutePath(t *testing.T, name string) string {
	t.Helper()
	path := os.Getenv(name)
	if !filepath.IsAbs(path) {
		t.Fatalf("%s must be an absolute path", name)
	}
	return filepath.Clean(path)
}

func protocolPathInside(parent, path string) bool {
	rel, err := filepath.Rel(parent, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator))
}

func waitForProtocolMarker(t *testing.T, path string) {
	t.Helper()
	timeout := time.NewTimer(10 * time.Second)
	ticker := time.NewTicker(10 * time.Millisecond)
	defer timeout.Stop()
	defer ticker.Stop()
	for {
		select {
		case <-timeout.C:
			t.Fatalf("timeout waiting for release marker %s", path)
		case <-ticker.C:
			_, err := os.Stat(path)
			if err == nil {
				return
			}
			if !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("stat release marker %s: %v", path, err)
			}
		}
	}
}
