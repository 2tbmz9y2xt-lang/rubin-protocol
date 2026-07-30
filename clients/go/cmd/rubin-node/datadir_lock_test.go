//go:build darwin || linux

package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/filelock"
	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/node"
)

func TestAcquireDatadirLockReportsContentionAndReleases(t *testing.T) {
	dir := t.TempDir()
	holder, code := acquireDatadirLock(dir, &bytes.Buffer{})
	if code != 0 || holder == nil {
		t.Fatalf("first acquire code=%d holder=%v", code, holder)
	}

	var stderr bytes.Buffer
	challenger, code := acquireDatadirLock(dir, &stderr)
	if code != 2 || challenger != nil {
		t.Fatalf("second acquire code=%d holder=%v", code, challenger)
	}
	if want := "datadir is already in use by another rubin-node: " + dir; !strings.Contains(stderr.String(), want) {
		t.Fatalf("stderr=%q, want %q", stderr.String(), want)
	}
	if err := holder.Release(); err != nil {
		t.Fatalf("release holder: %v", err)
	}

	reused, code := acquireDatadirLock(dir, &bytes.Buffer{})
	if code != 0 || reused == nil {
		t.Fatalf("reused acquire code=%d holder=%v", code, reused)
	}
	if err := reused.Release(); err != nil {
		t.Fatalf("release reused holder: %v", err)
	}
}

func TestRunMutatingStartupRejectsDatadirLockBeforeBlockStore(t *testing.T) {
	cases := []struct {
		name  string
		setup func(*testing.T, string)
		want  string
	}{
		{
			name: "contended",
			setup: func(t *testing.T, dir string) {
				t.Helper()
				holder, result, err := filelock.Acquire(filepath.Join(dir, ".rubin.lock"))
				if err != nil || result != "" {
					t.Fatalf("Acquire result=%q err=%v", result, err)
				}
				t.Cleanup(func() { _ = holder.Release() })
			},
			want: "datadir is already in use by another rubin-node:",
		},
		{
			name: "invalid",
			setup: func(t *testing.T, dir string) {
				t.Helper()
				if err := os.WriteFile(filepath.Join(dir, ".rubin.lock"), []byte("not empty"), 0o600); err != nil {
					t.Fatalf("write lock: %v", err)
				}
			},
			want: "cannot open datadir lock",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			tc.setup(t, dir)
			code, stderr := runCLI("--datadir", dir)
			if code != 2 || !strings.Contains(stderr, tc.want) {
				t.Fatalf("exit=%d stderr=%q, want %q", code, stderr, tc.want)
			}
			if _, err := os.Lstat(node.BlockStorePath(dir)); !os.IsNotExist(err) {
				t.Fatalf("blockstore must not be opened or created before lock rejection: %v", err)
			}
		})
	}
}

func TestRunCreateStoreRejectsHeldLockBeforeStoreCreation(t *testing.T) {
	dir := t.TempDir()
	holder, result, err := filelock.Acquire(filepath.Join(dir, ".rubin.lock"))
	if err != nil || result != "" {
		t.Fatalf("Acquire result=%q err=%v", result, err)
	}
	t.Cleanup(func() { _ = holder.Release() })

	code, stderr := runCLI("--datadir", dir, "--create-store")
	if code != 2 || !strings.Contains(stderr, "datadir is already in use by another rubin-node:") {
		t.Fatalf("exit=%d stderr=%q", code, stderr)
	}
	for _, path := range []string{node.BlockStorePath(dir), node.ChainStatePath(dir)} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("store artifact %s exists after lock rejection: %v", path, err)
		}
	}
}

func TestRunStrictOpenMissingDatadirDoesNotCreateLock(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	rootPath := node.BlockStorePath(dir)
	_, statErr := os.Stat(rootPath)
	if statErr == nil {
		t.Fatalf("missing root unexpectedly exists: %s", rootPath)
	}
	code, stderr := runCLI("--datadir", dir)
	want := fmt.Sprintf("blockstore open failed: blockstore directory %s: %v\n", rootPath, statErr)
	if code != 2 || stderr != want {
		t.Fatalf("exit=%d stderr=%q, want %q", code, stderr, want)
	}
	if _, err := os.Lstat(dir); !os.IsNotExist(err) {
		t.Fatalf("strict open created datadir or lock: %v", err)
	}
}

func TestCreateOrOpenBlockStoreReturnsLockOnlyForMutatingStrictOpen(t *testing.T) {
	dir := preparedDatadir(t)
	chainStatePath := node.ChainStatePath(dir)

	t.Run("mutating", func(t *testing.T) {
		store, lock, code := createOrOpenBlockStore(dir, chainStatePath, false, false, &bytes.Buffer{})
		if code != 0 || store == nil || lock == nil {
			t.Fatalf("store=%v lock=%v code=%d, want store and held lock", store, lock, code)
		}
		defer func() {
			if err := lock.Release(); err != nil {
				t.Errorf("release mutating lock: %v", err)
			}
		}()

		challenger, result, err := filelock.Acquire(filepath.Join(dir, ".rubin.lock"))
		if err == nil || challenger != nil || result != filelock.ResultContended {
			if challenger != nil {
				_ = challenger.Release()
			}
			t.Fatalf("strict-open lock result=%q handle=%v err=%v, want contention", result, challenger, err)
		}
	})

	t.Run("dry_run", func(t *testing.T) {
		store, lock, code := createOrOpenBlockStore(dir, chainStatePath, false, true, &bytes.Buffer{})
		if code != 0 || store == nil || lock != nil {
			t.Fatalf("store=%v lock=%v code=%d, want store and nil lock", store, lock, code)
		}
		probe, result, err := filelock.Acquire(filepath.Join(dir, ".rubin.lock"))
		if err != nil || result != "" || probe == nil {
			t.Fatalf("dry-run must not hold lock: result=%q handle=%v err=%v", result, probe, err)
		}
		if err := probe.Release(); err != nil {
			t.Fatalf("release dry-run probe: %v", err)
		}
	})
}

func TestRunCreateStoreCreatesReusableZeroByteLock(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	if code, stderr := runCLI("--datadir", dir, "--create-store", "--mine-blocks", "1", "--mine-exit"); code != 0 {
		t.Fatalf("create exit=%d stderr=%q", code, stderr)
	}
	lockPath := filepath.Join(dir, ".rubin.lock")
	info, err := os.Stat(lockPath)
	if err != nil {
		t.Fatalf("stat lock: %v", err)
	}
	if !info.Mode().IsRegular() || info.Size() != 0 {
		t.Fatalf("lock info = mode %v size %d, want regular zero-byte file", info.Mode(), info.Size())
	}
	handle, result, err := filelock.Acquire(lockPath)
	if err != nil || result != "" {
		t.Fatalf("reacquire result=%q err=%v", result, err)
	}
	if err := handle.Release(); err != nil {
		t.Fatalf("release reacquired lock: %v", err)
	}
}

func TestRunReadOnlyModesIgnoreDatadirLock(t *testing.T) {
	cases := []struct {
		name  string
		setup func(*testing.T, string)
	}{
		{
			name: "contended",
			setup: func(t *testing.T, dir string) {
				t.Helper()
				holder, result, err := filelock.Acquire(filepath.Join(dir, ".rubin.lock"))
				if err != nil || result != "" {
					t.Fatalf("Acquire result=%q err=%v", result, err)
				}
				t.Cleanup(func() { _ = holder.Release() })
			},
		},
		{
			name: "invalid",
			setup: func(t *testing.T, dir string) {
				t.Helper()
				path := filepath.Join(dir, ".rubin.lock")
				if err := os.Remove(path); err != nil {
					t.Fatalf("remove valid lock: %v", err)
				}
				if err := os.WriteFile(path, []byte("not empty"), 0o600); err != nil {
					t.Fatalf("write invalid lock: %v", err)
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := preparedDatadir(t)
			tc.setup(t, dir)
			before := datadirSnapshot(t, dir)
			for _, args := range [][]string{
				{"--dry-run", "--datadir", dir},
				{"--legacy-exposure-scan", "--legacy-suite-id", "1", "--datadir", dir},
			} {
				var stdout, stderr bytes.Buffer
				if code := run(args, &stdout, &stderr); code != 0 {
					t.Fatalf("%v: exit=%d stderr=%q", args, code, stderr.String())
				}
			}
			assertNoFilesystemWrite(t, before, datadirSnapshot(t, dir))
		})
	}
}
