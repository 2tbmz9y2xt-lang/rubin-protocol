//go:build darwin || linux

package node

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/filelock"
)

type atomicScratchStub struct{ writeErr, syncErr, closeErr, chmodErr error }

func mustAtomic(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func requireAtomicTest(t *testing.T, ok bool, format string, args ...any) {
	t.Helper()
	if !ok {
		t.Fatalf(format, args...)
	}
}

func atomicStubOpen(stub *atomicScratchStub) func(string, int, os.FileMode) (atomicWriteScratchFile, error) {
	return func(string, int, os.FileMode) (atomicWriteScratchFile, error) { return stub, nil }
}

func (f *atomicScratchStub) Write(p []byte) (int, error) {
	if f.writeErr != nil {
		return 0, f.writeErr
	}
	return len(p), nil
}
func (f *atomicScratchStub) Sync() error             { return f.syncErr }
func (f *atomicScratchStub) Close() error            { return f.closeErr }
func (f *atomicScratchStub) Chmod(os.FileMode) error { return f.chmodErr }
func withAtomicWriteOps(t *testing.T, mutate func(*atomicWriteOps)) {
	t.Helper()
	previous, next := atomicWriteIO, atomicWriteIO
	mutate(&next)
	atomicWriteIO = next
	t.Cleanup(func() { atomicWriteIO = previous })
}

func requireAtomicWriteError(t *testing.T, err error, stage atomicWriteStage, operation atomicWriteOperation) *atomicWriteError {
	t.Helper()
	var got *atomicWriteError
	requireAtomicTest(t, err != nil && errors.As(err, &got) && got.stage == stage && got.operation == operation, "atomic error=%+v, want stage=%q operation=%q", err, stage, operation)
	return got
}

func atomicTestPath(t *testing.T, leaf string) string {
	path := filepath.Join(t.TempDir(), leaf)
	mustAtomic(t, os.MkdirAll(filepath.Dir(path), 0o700))
	return path
}

var atomicDestinationClasses = []string{"blockstore/blocks/block.bin", "blockstore/headers/header.bin", "blockstore/undo/undo.bin", "blockstore/index.json", "chainstate.json"}

func TestAtomicWriteRejectsReservedDestinationBeforeReadOrMutation(t *testing.T) {
	for _, leaf := range []string{atomicWriteLockLeaf, atomicWriteScratchLeaf} {
		t.Run(leaf, func(t *testing.T) {
			path, previousRead := atomicTestPath(t, leaf), readFileByPathFn
			var reads, opens, unlinks, syncs atomic.Int32
			readFileByPathFn = func(string, int64) ([]byte, error) { reads.Add(1); return nil, errors.New("read") }
			t.Cleanup(func() { readFileByPathFn = previousRead })
			withAtomicWriteOps(t, func(ops *atomicWriteOps) {
				ops.openScratch = func(string, int, os.FileMode) (atomicWriteScratchFile, error) {
					opens.Add(1)
					return &atomicScratchStub{}, nil
				}
				ops.unlink = func(string) error { unlinks.Add(1); return nil }
				ops.syncParent = func(string) error { syncs.Add(1); return nil }
			})
			for _, row := range []struct {
				name string
				op   atomicWriteOperation
				call func() error
			}{
				{"overwrite", atomicWriteOverwrite, func() error { return writeFileAtomic(path, []byte("p"), 0o600) }},
				{"create", atomicWriteCreateIfAbsent, func() error { return writeFileIfAbsent(path, []byte("p")) }},
			} {
				t.Run(row.name, func(t *testing.T) { requireAtomicWriteError(t, row.call(), atomicWriteBeforeNamespaceCommit, row.op) })
			}
			requireAtomicTest(t, reads.Load()+opens.Load()+unlinks.Load()+syncs.Load() == 0, "reserved destination touched helpers: read=%d open=%d unlink=%d sync=%d", reads.Load(), opens.Load(), unlinks.Load(), syncs.Load())
		})
	}
}

func TestAtomicWriteExactMatchIsLockAndScratchFreeButStrictlyResyncs(t *testing.T) {
	path := atomicTestPath(t, "block.bin")
	mustAtomic(t, os.WriteFile(path, []byte("same"), 0o600))
	mustAtomic(t, os.Chmod(path, 0o644))
	var open, unlink, sync atomic.Int32
	withAtomicWriteOps(t, func(ops *atomicWriteOps) {
		parentSync := ops.syncParent
		ops.openScratch = func(string, int, os.FileMode) (atomicWriteScratchFile, error) {
			open.Add(1)
			return &atomicScratchStub{}, nil
		}
		ops.unlink = func(string) error { unlink.Add(1); return nil }
		ops.syncParent = func(parent string) error { sync.Add(1); return parentSync(parent) }
	})
	mustAtomic(t, writeFileIfAbsent(path, []byte("same")))
	requireAtomicTest(t, open.Load()+unlink.Load() == 0 && sync.Load() == 1, "exact match write lane: open=%d unlink=%d sync=%d", open.Load(), unlink.Load(), sync.Load())
	assertNodePathMode(t, path, 0o644)
	for _, leaf := range []string{atomicWriteLockLeaf, atomicWriteScratchLeaf} {
		_, err := os.Lstat(filepath.Join(filepath.Dir(path), leaf))
		requireAtomicTest(t, errors.Is(err, os.ErrNotExist), "exact match created %s: %v", leaf, err)
	}
	syncErr := errors.New("sync existing")
	withAtomicWriteOps(t, func(ops *atomicWriteOps) { ops.syncParent = func(string) error { return syncErr } })
	got := requireAtomicWriteError(t, writeFileIfAbsent(path, []byte("same")), atomicWriteAfterNamespaceCommit, atomicWriteCreateIfAbsent)
	requireAtomicTest(t, errors.Is(got, syncErr), "exact match sync: %+v", got)
}

func TestAtomicWriteSameProcessSerializesSameAndDifferentDestinations(t *testing.T) {
	for _, paths := range [][2]string{{"one", "one"}, {"one", "two"}} {
		t.Run(paths[0]+"_"+paths[1], func(t *testing.T) {
			dir, first, second, release := t.TempDir(), make(chan struct{}), make(chan struct{}), make(chan struct{})
			var opens atomic.Int32
			withAtomicWriteOps(t, func(ops *atomicWriteOps) {
				ops.openScratch = func(string, int, os.FileMode) (atomicWriteScratchFile, error) {
					if opens.Add(1) == 1 {
						close(first)
						<-release
					} else {
						close(second)
					}
					return &atomicScratchStub{}, nil
				}
				ops.unlink, ops.rename, ops.syncParent = func(string) error { return nil }, func(string, string) error { return nil }, func(string) error { return nil }
			})
			done := make(chan error, 2)
			go func() { done <- writeFileAtomic(filepath.Join(dir, paths[0]), []byte("one"), 0o600) }()
			<-first
			go func() { done <- writeFileAtomic(filepath.Join(dir, paths[1]), []byte("two"), 0o600) }()
			select {
			case <-second:
				t.Fatal("second writer entered scratch window")
			case <-time.After(100 * time.Millisecond):
			}
			close(release)
			mustAtomic(t, <-done)
			mustAtomic(t, <-done)
		})
	}
}

func TestAtomicWriteParentAliasUsesOnePhysicalReservedLock(t *testing.T) {
	physical, alias := t.TempDir(), filepath.Join(t.TempDir(), "alias")
	mustAtomic(t, os.Symlink(physical, alias))
	holder, _, err := filelock.Acquire(filepath.Join(physical, atomicWriteLockLeaf))
	mustAtomic(t, err)
	t.Cleanup(func() { _ = holder.Release() })
	path := filepath.Join(alias, "two")
	requireAtomicTest(t, requireAtomicWriteError(t, writeFileAtomic(path, []byte("two"), 0o600), atomicWriteBeforeNamespaceCommit, atomicWriteOverwrite).primary != nil, "missing lock cause")
	_, err = os.Lstat(path)
	requireAtomicTest(t, errors.Is(err, os.ErrNotExist), "contended alias created destination: %v", err)
	mustAtomic(t, holder.Release())
	mustAtomic(t, writeFileAtomic(path, []byte("two"), 0o600))
	a, err := os.Stat(filepath.Join(physical, atomicWriteLockLeaf))
	mustAtomic(t, err)
	b, err := os.Stat(filepath.Join(alias, atomicWriteLockLeaf))
	mustAtomic(t, err)
	requireAtomicTest(t, os.SameFile(a, b), "parent aliases have different lock inodes")
}

func TestAtomicUnlinkOnlyRemovesExactLeafShapes(t *testing.T) {
	for _, row := range []struct {
		name    string
		seed    func(string) error
		refused bool
	}{
		{"missing", func(string) error { return nil }, false},
		{"regular", func(p string) error { return os.WriteFile(p, []byte("x"), 0o600) }, false},
		{"fifo", func(p string) error { return syscall.Mkfifo(p, 0o600) }, false},
		{"live_symlink", func(p string) error {
			target := filepath.Join(filepath.Dir(p), "live")
			mustAtomic(t, os.WriteFile(target, []byte("x"), 0o600))
			return os.Symlink(target, p)
		}, false},
		{"dangling_symlink", func(p string) error { return os.Symlink("missing", p) }, false},
		{"directory", func(p string) error { return os.Mkdir(p, 0o700) }, true},
	} {
		t.Run(row.name, func(t *testing.T) {
			path := atomicTestPath(t, atomicWriteScratchLeaf)
			mustAtomic(t, row.seed(path))
			err := atomicUnlink(path)
			requireAtomicTest(t, (err != nil) == row.refused, "unlink err=%v refused=%v", err, row.refused)
			if row.refused {
				info, err := os.Stat(path)
				requireAtomicTest(t, err == nil && info.IsDir(), "directory changed: %v %v", info, err)
			} else if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("scratch remains: %v", err)
			}
		})
	}
	t.Run("hardlink", func(t *testing.T) {
		dir := t.TempDir()
		live := filepath.Join(dir, "live")
		scratch := filepath.Join(dir, atomicWriteScratchLeaf)
		mustAtomic(t, os.WriteFile(live, []byte("live"), 0o600))
		mustAtomic(t, os.Link(live, scratch))
		mustAtomic(t, atomicUnlink(scratch))
		got, err := os.ReadFile(live)
		requireAtomicTest(t, err == nil && bytes.Equal(got, []byte("live")), "live=%q err=%v", got, err)
		n := osStatNlink(t, live)
		requireAtomicTest(t, n == 1, "nlink=%d", n)
	})
}

func osStatNlink(t *testing.T, path string) uint64 {
	t.Helper()
	info, err := os.Stat(path)
	mustAtomic(t, err)
	return uint64(info.Sys().(*syscall.Stat_t).Nlink)
}

func TestAtomicWriteCreatesExact0600AcrossUmasks(t *testing.T) {
	for _, mask := range []int{0, 0o22, 0o77} {
		t.Run(strconv.Itoa(mask), func(t *testing.T) {
			old := syscall.Umask(mask)
			t.Cleanup(func() { syscall.Umask(old) })
			var modes []os.FileMode
			withAtomicWriteOps(t, func(ops *atomicWriteOps) {
				rename, link := ops.rename, ops.link
				capture := func(s string) {
					info, err := os.Stat(s)
					mustAtomic(t, err)
					modes = append(modes, info.Mode().Perm())
				}
				ops.rename = func(s, d string) error { capture(s); return rename(s, d) }
				ops.link = func(s, d string) error { capture(s); return link(s, d) }
			})
			overwrite, create := atomicTestPath(t, "overwrite"), atomicTestPath(t, "create")
			mustAtomic(t, os.WriteFile(overwrite, []byte("old"), 0o600))
			mustAtomic(t, os.Chmod(overwrite, 0o644))
			mustAtomic(t, writeFileAtomic(overwrite, []byte("new"), 0o600))
			mustAtomic(t, writeFileIfAbsent(create, []byte("new")))
			for _, mode := range modes {
				requireAtomicTest(t, mode == 0o600, "scratch mode=%04o", mode)
			}
			assertNodePathMode(t, overwrite, 0o600)
			assertNodePathMode(t, create, 0o600)
		})
	}
}

type atomicPreCommitCase struct {
	name      string
	operation atomicWriteOperation
	primary   error
	preUnlink bool
	cleanup   bool
	configure func(*atomicWriteOps, error)
	resolve   bool
}

func assertAtomicPreCommit(t *testing.T, tc atomicPreCommitCase, path string) {
	t.Helper()
	unlinks, syncs := 0, 0
	withAtomicWriteOps(t, func(ops *atomicWriteOps) {
		ops.openScratch = func(string, int, os.FileMode) (atomicWriteScratchFile, error) { return &atomicScratchStub{}, nil }
		ops.unlink = func(string) error {
			unlinks++
			if tc.preUnlink && unlinks == 1 {
				return tc.primary
			}
			if tc.cleanup && unlinks == 2 {
				return syscall.EACCES
			}
			return nil
		}
		ops.syncParent = func(string) error {
			syncs++
			if tc.cleanup {
				return syscall.EIO
			}
			return nil
		}
		if tc.configure != nil {
			tc.configure(ops, tc.primary)
		}
	})
	resolve := func() error { return nil }
	if tc.resolve {
		resolve = func() error { return tc.primary }
	}
	got := requireAtomicWriteError(t, writeAtomicFile(path, []byte("p"), tc.operation, resolve), atomicWriteBeforeNamespaceCommit, tc.operation)
	requireAtomicTest(t, got.destination == path && errors.Is(got.primary, tc.primary), "destination=%q primary=%v", got.destination, got.primary)
	if tc.cleanup {
		requireAtomicTest(t, unlinks == 2 && syncs == 1 && len(got.secondary) == 2 && errors.Is(got.secondary[0], syscall.EACCES) && errors.Is(got.secondary[1], syscall.EIO), "cleanup order: unlink=%d sync=%d secondary=%v", unlinks, syncs, got.secondary)
	} else if unlinks != 1 || syncs != 0 || len(got.secondary) != 0 {
		t.Fatalf("pre-unlink order: unlink=%d sync=%d secondary=%v", unlinks, syncs, got.secondary)
	}
}

func TestAtomicWritePreCommitPrecedenceAcrossFrozenDestinations(t *testing.T) {
	cases := []atomicPreCommitCase{
		{"scratch_pre_unlink", atomicWriteOverwrite, errors.New("scratch pre-unlink"), true, false, nil, false},
		{"exclusive_open", atomicWriteOverwrite, errors.New("exclusive open"), false, true, func(o *atomicWriteOps, e error) {
			o.openScratch = func(string, int, os.FileMode) (atomicWriteScratchFile, error) { return nil, e }
		}, false},
		{"scratch_mode", atomicWriteOverwrite, errors.New("scratch mode"), false, true, func(o *atomicWriteOps, e error) { o.openScratch = atomicStubOpen(&atomicScratchStub{chmodErr: e}) }, false},
		{"write", atomicWriteOverwrite, syscall.ENOSPC, false, true, func(o *atomicWriteOps, e error) { o.openScratch = atomicStubOpen(&atomicScratchStub{writeErr: e}) }, false},
		{"file_sync", atomicWriteOverwrite, syscall.ENOSPC, false, true, func(o *atomicWriteOps, e error) { o.openScratch = atomicStubOpen(&atomicScratchStub{syncErr: e}) }, false},
		{"rename", atomicWriteOverwrite, errors.New("rename"), false, true, func(o *atomicWriteOps, e error) { o.rename = func(string, string) error { return e } }, false},
		{"link", atomicWriteCreateIfAbsent, errors.New("link"), false, true, func(o *atomicWriteOps, e error) { o.link = func(string, string) error { return e } }, false},
		{"eexist_decision", atomicWriteCreateIfAbsent, errors.New("existing mismatch"), false, true, func(o *atomicWriteOps, _ error) { o.link = func(string, string) error { return os.ErrExist } }, true},
	}
	for _, tc := range cases {
		for _, class := range atomicDestinationClasses {
			t.Run(tc.name+"/"+class, func(t *testing.T) { assertAtomicPreCommit(t, tc, atomicTestPath(t, class)) })
		}
	}
}

func TestAtomicWriteGoClosePrecedenceIsSeparate(t *testing.T) {
	tc := atomicPreCommitCase{"go_close", atomicWriteOverwrite, errors.New("close"), false, true, func(o *atomicWriteOps, e error) { o.openScratch = atomicStubOpen(&atomicScratchStub{closeErr: e}) }, false}
	for _, class := range atomicDestinationClasses {
		t.Run(class, func(t *testing.T) { assertAtomicPreCommit(t, tc, atomicTestPath(t, class)) })
	}
}

func TestAtomicWritePostCommitUnlinkThenSyncPrecedence(t *testing.T) {
	withAtomicWriteOps(t, func(ops *atomicWriteOps) {
		calls := 0
		ops.openScratch = func(string, int, os.FileMode) (atomicWriteScratchFile, error) { return &atomicScratchStub{}, nil }
		ops.unlink = func(string) error {
			calls++
			if calls == 2 {
				return syscall.EACCES
			}
			return nil
		}
		ops.rename = func(string, string) error { return nil }
		ops.syncParent = func(string) error { return syscall.EIO }
	})
	got := requireAtomicWriteError(t, writeFileAtomic(atomicTestPath(t, "destination"), []byte("p"), 0o600), atomicWriteAfterNamespaceCommit, atomicWriteOverwrite)
	requireAtomicTest(t, errors.Is(got.primary, syscall.EACCES) && len(got.secondary) == 1 && errors.Is(got.secondary[0], syscall.EIO), "postcommit precedence: %+v", got)
	var nilAtomic *atomicWriteError
	requireAtomicTest(t, nilAtomic.Error() == "" && nilAtomic.Unwrap() == nil && bytes.Contains([]byte(got.Error()), []byte("cleanup:")) && errors.Is(got, syscall.EIO), "postcommit error: %+v", got)
	release := errors.New("release")
	got = requireAtomicWriteError(t, appendAtomicWriteReleaseError(nil, false, "destination", atomicWriteOverwrite, release), atomicWriteBeforeNamespaceCommit, atomicWriteOverwrite)
	requireAtomicTest(t, errors.Is(got, release), "release error: %+v", got)
}

func TestReclaimAtomicWriteScratchUsesOnlyFiveFrozenParentsInOrder(t *testing.T) {
	dir := t.TempDir()
	root := BlockStorePath(dir)
	want := []string{dir, root, filepath.Join(root, "blocks"), filepath.Join(root, "headers"), filepath.Join(root, "undo")}
	for _, parent := range want {
		mustAtomic(t, os.MkdirAll(parent, 0o700))
		mustAtomic(t, os.WriteFile(filepath.Join(parent, atomicWriteScratchLeaf), []byte("x"), 0o600))
	}
	var unlinked, synced []string
	withAtomicWriteOps(t, func(ops *atomicWriteOps) {
		unlink, sync := ops.unlink, ops.syncParent
		ops.unlink = func(path string) error { unlinked = append(unlinked, path); return unlink(path) }
		ops.syncParent = func(path string) error { synced = append(synced, path); return sync(path) }
	})
	mustAtomic(t, ReclaimAtomicWriteScratch(dir))
	for i, parent := range want {
		requireAtomicTest(t, unlinked[i] == filepath.Join(parent, atomicWriteScratchLeaf) && synced[i] == parent, "reclaim[%d]=%q/%q", i, unlinked[i], synced[i])
	}
}
