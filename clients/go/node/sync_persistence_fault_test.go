//go:build darwin || linux

package node

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

func newPersistenceFaultEngine(t *testing.T) (*SyncEngine, *BlockStore, string) {
	t.Helper()
	dir := t.TempDir()
	store, err := CreateBlockStore(BlockStorePath(dir))
	mustAtomic(t, err)
	engine, err := NewSyncEngine(NewChainState(), store, DefaultSyncConfig(nil, devnetGenesisChainID, ChainStatePath(dir)))
	mustAtomic(t, err)
	return engine, store, dir
}

func requirePersistenceFault(t *testing.T, err error, operation atomicWriteOperation) *storagePersistenceFault {
	t.Helper()
	atomic := requireAtomicWriteError(t, err, atomicWriteAfterNamespaceCommit, operation)
	var fault *storagePersistenceFault
	requireAtomicTest(t, errors.Is(atomic.primary, os.ErrPermission) && errors.As(err, &fault) && fault != nil, "primary=%v error type=%T, want permission *storagePersistenceFault", atomic.primary, err)
	return fault
}

func awaitPersistenceResult(t *testing.T, result <-chan error, name string) error {
	t.Helper()
	select {
	case err := <-result:
		return err
	case <-time.After(time.Second):
		t.Fatalf("timed out joining %s", name)
		return nil
	}
}

func startBlockedApply(t *testing.T, engine *SyncEngine, store *BlockStore, secondScratch chan<- struct{}) (chan<- struct{}, <-chan error) {
	t.Helper()
	entered, release, result := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	withAtomicWriteOps(t, func(ops *atomicWriteOps) {
		open, link, unlink, links, opens, injected := ops.openScratch, ops.link, ops.unlink, 0, 0, false
		ops.openScratch = func(path string, flag int, mode os.FileMode) (atomicWriteScratchFile, error) {
			opens++
			if opens > 1 && secondScratch != nil {
				select {
				case secondScratch <- struct{}{}:
				default:
				}
			}
			return open(path, flag, mode)
		}
		ops.link = func(a, b string) error { links++; return link(a, b) }
		ops.unlink = func(path string) error {
			if !injected && links == 1 && filepath.Dir(path) == store.blocksDir {
				injected = true
				close(entered)
				<-release
				return os.ErrPermission
			}
			return unlink(path)
		}
	})
	go func() { _, err := engine.ApplyBlock(DevnetGenesisBlockBytes(), nil); result <- err }()
	select {
	case <-entered:
	case err := <-result:
		close(release)
		t.Fatalf("apply returned before injection: %v", err)
	case <-time.After(time.Second):
		close(release)
		t.Fatal("timed out waiting for cleanup failure")
	}
	return release, result
}

func TestSyncEnginePostCommitFailuresReloadVisibleStateWithoutCompensation(t *testing.T) {
	targets := []struct {
		name   string
		parent func(*BlockStore, string) string
	}{
		{"block", func(s *BlockStore, _ string) string { return s.blocksDir }},
		{"header", func(s *BlockStore, _ string) string { return s.headersDir }},
		{"undo", func(s *BlockStore, _ string) string { return s.undoDir }},
		{"index", func(s *BlockStore, _ string) string { return s.rootPath }},
		{"chainstate", func(_ *BlockStore, d string) string { return d }},
	}
	entries := []func(*SyncEngine, []byte, []uint64) (*ChainStateConnectSummary, error){
		(*SyncEngine).ApplyBlock,
		(*SyncEngine).ApplyBlockWithReorg,
	}
	for targetIndex, tc := range targets {
		for _, failure := range []string{"unlink", "sync"} {
			for entryIndex, entry := range entries {
				t.Run(tc.name+"/"+failure+"/"+[]string{"apply", "reorg"}[entryIndex], func(t *testing.T) {
					engine, store, dir := newPersistenceFaultEngine(t)
					engine.cfg.ChainStatePath = []string{"", engine.cfg.ChainStatePath, engine.cfg.ChainStatePath, engine.cfg.ChainStatePath, engine.cfg.ChainStatePath}[targetIndex]
					parent, failed, commits := tc.parent(store, dir), false, 0
					withAtomicWriteOps(t, func(ops *atomicWriteOps) {
						link, rename, unlink, sync := ops.link, ops.rename, ops.unlink, ops.syncParent
						ops.link = func(a, b string) error { commits++; return link(a, b) }
						ops.rename = func(a, b string) error { commits++; return rename(a, b) }
						ops.unlink = func(path string) error {
							if failure == "unlink" && !failed && commits == targetIndex+1 && filepath.Dir(path) == parent {
								failed = true
								return os.ErrPermission
							}
							return unlink(path)
						}
						ops.syncParent = func(path string) error {
							if failure == "sync" && !failed && path == parent {
								failed = true
								return os.ErrPermission
							}
							return sync(path)
						}
					})
					summary, err := entry(engine, DevnetGenesisBlockBytes(), nil)
					requireAtomicTest(t, summary == nil && failed, "summary=%+v injected=%v", summary, failed)
					fault := requirePersistenceFault(t, err, []atomicWriteOperation{atomicWriteCreateIfAbsent, atomicWriteCreateIfAbsent, atomicWriteCreateIfAbsent, atomicWriteOverwrite, atomicWriteOverwrite}[targetIndex])
					requireAtomicTest(t, fault == engine.persistenceFault && errors.Is(fault.cause, os.ErrPermission) && commits == targetIndex+1, "fault=%+v commits=%d", fault, commits)
					disk, err := OpenBlockStore(BlockStorePath(dir))
					mustAtomic(t, err)
					_, _, diskStore, err := disk.Tip()
					mustAtomic(t, err)
					_, _, cachedStore, err := store.Tip()
					requireAtomicTest(t, err == nil && diskStore == cachedStore && diskStore == (targetIndex >= 3), "store disk=%v cache=%v err=%v", diskStore, cachedStore, err)
					diskState, err := LoadChainState(ChainStatePath(dir))
					mustAtomic(t, err)
					requireAtomicTest(t, diskState.HasTip == (targetIndex == 4) && engine.chainState.view().hasTip == (targetIndex >= 3), "state disk=%v cache=%v", diskState.HasTip, engine.chainState.view().hasTip)
				})
			}
		}
	}
	var nilStore *BlockStore
	requireAtomicTest(t, nilStore.reloadFromDisk() != nil, "nil blockstore reload")
	cause, reload := errors.New("cause"), errors.New("reload")
	fault := &storagePersistenceFault{cause: cause}
	requireAtomicTest(t, fault.Error() == "storage persistence fault: cause" && errors.Is(fault, cause), "fault=%v", fault)
	fault.reloadErr = reload
	requireAtomicTest(t, fault.Error() == "storage persistence fault: cause (reload failed: reload)" && errors.Is(fault, cause), "fault=%v", fault)
	var nilFault *storagePersistenceFault
	requireAtomicTest(t, nilFault.Unwrap() == nil, "nil fault unwrap")
}

func TestSyncEnginePostCommitFaultLatchesBeforeCapturedStateReplacement(t *testing.T) {
	engine, store, _ := newPersistenceFaultEngine(t)
	release, result := startBlockedApply(t, engine, store, nil)
	engine.chainState.admissionMu.Lock()
	close(release)
	for deadline := time.Now().Add(time.Second); !engine.persistenceFaulted() && time.Now().Before(deadline); {
		time.Sleep(time.Millisecond)
	}
	if !engine.persistenceFaulted() {
		t.Error("persistence fault was not published before replacement")
	}
	engine.chainState.admissionMu.Unlock()
	requirePersistenceFault(t, awaitPersistenceResult(t, result, "failed apply"), atomicWriteCreateIfAbsent)
}

func TestSyncEngineQueuesMutatorsUntilPostCommitFaultIsPublished(t *testing.T) {
	engine, store, _ := newPersistenceFaultEngine(t)
	target, started, secondScratch, secondResult, bootstrapResult := consensus.POW_LIMIT, make(chan struct{}, 2), make(chan struct{}, 1), make(chan error, 1), make(chan error, 1)
	release, firstResult := startBlockedApply(t, engine, store, secondScratch)
	engine.cfg.Network, engine.cfg.ExpectedTarget = "regtest", &target
	block1 := buildSingleTxBlock(t, devnetGenesisBlockHash, target, 2, coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 1, 1))
	engine.persistenceFaultMu.Lock()
	start := func(call func() error, result chan<- error) { started <- struct{}{}; result <- call() }
	go start(func() error { _, err := engine.ApplyBlock(block1, nil); return err }, secondResult)
	go start(engine.BootstrapCanonicalGenesisIfEmpty, bootstrapResult)
	func() { <-started; <-started }()
	close(release)
	select {
	case <-secondScratch:
		t.Error("queued mutator reached scratch before fault publication")
	case <-time.After(100 * time.Millisecond):
	}
	engine.persistenceFaultMu.Unlock()
	requirePersistenceFault(t, awaitPersistenceResult(t, firstResult, "first apply"), atomicWriteCreateIfAbsent)
	results := [2]error{awaitPersistenceResult(t, secondResult, "second apply"), awaitPersistenceResult(t, bootstrapResult, "bootstrap")}
	requireAtomicTest(t, errors.Is(results[0], errStoragePersistenceFault) && errors.Is(results[1], errStoragePersistenceFault), "second apply=%v bootstrap=%v", results[0], results[1])
}

func TestBootstrapPostCommitFaultIsNeverRaceRecovered(t *testing.T) {
	for _, reloadFails := range []bool{false, true} {
		t.Run(map[bool]string{false: "reloads", true: "reload_fails"}[reloadFails], func(t *testing.T) {
			engine, _, dir := newPersistenceFaultEngine(t)
			failed := false
			withAtomicWriteOps(t, func(ops *atomicWriteOps) {
				sync := ops.syncParent
				ops.syncParent = func(parent string) error {
					if !failed && parent == dir {
						failed = true
						if reloadFails {
							mustAtomic(t, os.Remove(ChainStatePath(dir)))
							mustAtomic(t, os.Mkdir(ChainStatePath(dir), 0o700))
						}
						return os.ErrPermission
					}
					return sync(parent)
				}
			})
			fault, later := requirePersistenceFault(t, engine.BootstrapCanonicalGenesisIfEmpty(), atomicWriteOverwrite), engine.BootstrapCanonicalGenesisIfEmpty()
			requireAtomicTest(t, failed && fault == engine.persistenceFault && errors.Is(fault.cause, os.ErrPermission) && (fault.reloadErr != nil) == reloadFails && errors.Is(later, errStoragePersistenceFault), "fault=%+v injected=%v later=%v", fault, failed, later)
		})
	}
}

func TestSyncEnginePersistenceFaultBlocksEveryMutationEntrypoint(t *testing.T) {
	engine, store, _ := newPersistenceFaultEngine(t)
	failed := false
	withAtomicWriteOps(t, func(ops *atomicWriteOps) {
		sync := ops.syncParent
		ops.syncParent = func(parent string) error {
			if !failed && parent == store.rootPath {
				failed = true
				return os.ErrPermission
			}
			return sync(parent)
		}
	})
	_, err := engine.ApplyBlock(DevnetGenesisBlockBytes(), nil)
	requireAtomicTest(t, err != nil && failed, "expected injected post-commit fault")
	miner, err := NewMiner(engine.chainState, store, engine, DefaultMinerConfig())
	mustAtomic(t, err)
	for _, row := range []struct {
		name string
		call func() error
	}{
		{"bootstrap", engine.BootstrapCanonicalGenesisIfEmpty}, {"apply", func() error { _, e := engine.ApplyBlock([]byte{0}, nil); return e }}, {"reorg", func() error { _, e := engine.ApplyBlockWithReorg([]byte{0}, nil); return e }}, {"disconnect", func() error { _, e := engine.DisconnectTip(); return e }}, {"miner", func() error { _, e := miner.MineOne(context.Background(), nil); return e }},
	} {
		err := row.call()
		requireAtomicTest(t, errors.Is(err, errStoragePersistenceFault), "%s=%v", row.name, err)
	}
}

func TestSyncEngineRollbackAndDisconnectPostCommitFaultsDoNotCompensate(t *testing.T) {
	t.Run("rollback", func(t *testing.T) {
		engine, store, _ := newPersistenceFaultEngine(t)
		openFailed, syncFailed, commits := false, false, 0
		withAtomicWriteOps(t, func(ops *atomicWriteOps) {
			open, rename, sync := ops.openScratch, ops.rename, ops.syncParent
			ops.openScratch = func(path string, f int, m os.FileMode) (atomicWriteScratchFile, error) {
				if !openFailed && filepath.Dir(path) == store.blocksDir {
					openFailed = true
					return nil, syscall.ENOSPC
				}
				return open(path, f, m)
			}
			ops.rename = func(a, b string) error { commits++; return rename(a, b) }
			ops.syncParent = func(parent string) error {
				if !syncFailed && parent == store.rootPath {
					syncFailed = true
					return os.ErrPermission
				}
				return sync(parent)
			}
		})
		requirePersistenceFault(t, func() error { _, err := engine.ApplyBlock(DevnetGenesisBlockBytes(), nil); return err }(), atomicWriteOverwrite)
		requireAtomicTest(t, openFailed && syncFailed && commits == 1 && engine.persistenceFault != nil, "open=%v sync=%v commits=%d fault=%+v", openFailed, syncFailed, commits, engine.persistenceFault)
	})
	t.Run("disconnect", func(t *testing.T) {
		engine, store, _ := newPersistenceFaultEngine(t)
		mustAtomic(t, func() error { _, err := engine.ApplyBlock(DevnetGenesisBlockBytes(), nil); return err }())
		failed, commits := false, 0
		withAtomicWriteOps(t, func(ops *atomicWriteOps) {
			rename, sync := ops.rename, ops.syncParent
			ops.rename = func(a, b string) error { commits++; return rename(a, b) }
			ops.syncParent = func(parent string) error {
				if !failed && parent == store.rootPath {
					failed = true
					return os.ErrPermission
				}
				return sync(parent)
			}
		})
		requirePersistenceFault(t, func() error { _, err := engine.DisconnectTip(); return err }(), atomicWriteOverwrite)
		requireAtomicTest(t, failed && commits == 1 && engine.persistenceFault != nil, "failed=%v commits=%d fault=%+v", failed, commits, engine.persistenceFault)
		_, _, ok, err := store.Tip()
		requireAtomicTest(t, err == nil && !ok, "cache tip=%v err=%v", ok, err)
	})
}
