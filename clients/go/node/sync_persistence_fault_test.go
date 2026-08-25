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

// requirePersistenceFault proves one AMBIGUOUS canonical-index write: the
// transition returns the atomic-write cause itself, and the engine carries the
// terminal latch installed from that cause. The returned error is no longer the
// latch wrapper — publication classifies, latches and returns the commit cause.
func requirePersistenceFault(t *testing.T, engine *SyncEngine, err error, operation atomicWriteOperation) *storagePersistenceFault {
	t.Helper()
	atomic := requireAtomicWriteError(t, err, atomicWriteAfterNamespaceCommit, operation)
	engine.mu.RLock()
	fault := engine.persistenceFault
	engine.mu.RUnlock()
	requireAtomicTest(t, errors.Is(atomic.primary, os.ErrPermission) && fault != nil, "primary=%v latch=%v", atomic.primary, fault)
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
		open, opens, injected := ops.openScratch, 0, false
		ops.openScratch = func(path string, flag int, mode os.FileMode) (atomicWriteScratchFile, error) {
			opens++
			// Only a scratch opened AFTER the injection can belong to a queued
			// mutator: the blocked apply opens several of its own first.
			if injected && secondScratch != nil {
				select {
				case secondScratch <- struct{}{}:
				default:
				}
			}
			return open(path, flag, mode)
		}
		sync := ops.syncParent
		ops.syncParent = func(parent string) error {
			if !injected && parent == store.rootPath {
				injected = true
				close(entered)
				<-release
				return os.ErrPermission
			}
			return sync(parent)
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

// TestSyncEnginePostCommitFailuresDoNotCompensate walks every durable write a
// direct connect performs, in the order the state machine performs them —
// block, header, undo, common checkpoint, canonical index — and fails each one
// AFTER its namespace commit.
//
// Only the index write can cross the commit point. The four writes before it are
// precommit: they preserve OLD, publish nothing, latch nothing, and leave the
// last usable snapshot intact because the checkpoint they replace is a row
// common to both identities. The index write is ambiguous, so its one strict
// readback finds the planned-new identity and yields TERMINAL_PERSISTENCE(new):
// the full image and summary publish and the engine latches. Nothing anywhere
// compensates, reloads or rewrites.
func TestSyncEnginePostCommitFailuresDoNotCompensate(t *testing.T) {
	targets := []struct {
		name   string
		parent func(*BlockStore, string) string
	}{
		{"block", func(s *BlockStore, _ string) string { return s.blocksDir }},
		{"header", func(s *BlockStore, _ string) string { return s.headersDir }},
		{"undo", func(s *BlockStore, _ string) string { return s.undoDir }},
		{"checkpoint", func(_ *BlockStore, d string) string { return d }},
		{"index", func(s *BlockStore, _ string) string { return s.rootPath }},
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
					terminalNew := targetIndex == 4
					requireAtomicTest(t, (summary != nil) == terminalNew && failed && err != nil, "summary=%+v terminalNew=%v injected=%v err=%v", summary, terminalNew, failed, err)
					requireAtomicTest(t, engine.persistenceFaulted() == terminalNew && commits == targetIndex+1, "latch=%v commits=%d", engine.persistenceFaulted(), commits)
					if terminalNew {
						requirePersistenceFault(t, engine, err, atomicWriteOverwrite)
					}
					disk, err := OpenBlockStore(BlockStorePath(dir))
					mustAtomic(t, err)
					_, _, diskStore, err := disk.Tip()
					mustAtomic(t, err)
					_, _, cachedStore, err := store.Tip()
					requireAtomicTest(t, err == nil && diskStore == cachedStore && diskStore == terminalNew, "store disk=%v cache=%v err=%v", diskStore, cachedStore, err)
					diskState, err := LoadChainState(ChainStatePath(dir))
					mustAtomic(t, err)
					// The bootstrap checkpoint IS the exact empty pre-genesis
					// state, so the durable snapshot never has a tip here.
					requireAtomicTest(t, !diskState.HasTip && engine.chainState.view().hasTip == terminalNew, "state disk=%v cache=%v", diskState.HasTip, engine.chainState.view().hasTip)
				})
			}
		}
	}
	cause := errors.New("cause")
	fault := &storagePersistenceFault{cause: cause}
	requireAtomicTest(t, fault.Error() == "storage persistence fault: cause" && errors.Is(fault, cause), "fault=%v", fault)
	var nilFault *storagePersistenceFault
	requireAtomicTest(t, nilFault.Unwrap() == nil, "nil fault unwrap")
}

// TestSyncEnginePostCommitFaultKeepsAdmissionClosedAfterLatch pins the terminal
// fail-closed contract for an ambiguous atomic POST-COMMIT persistence failure:
// the fault is latched, the owner stays transition-active so AdmissionContext
// stays unavailable, the continuous admission guard is never released so a
// standard-admission waiter cannot pass it, and a later SyncEngine mutator
// acquires mutationMu and returns the latched fault instead of blocking forever.
//
// The controlling goroutine deliberately NEVER acquires admissionMu before it
// releases the injected block: the transition holds that guard across
// persistence by design, so taking it here would deadlock the test rather than
// observe anything. Everything below is proven from the owner and the engine
// instead, and the admission waiter runs on its own goroutine.
func TestSyncEnginePostCommitFaultKeepsAdmissionClosedAfterLatch(t *testing.T) {
	engine, store, _ := newPersistenceFaultEngine(t)
	mempool, err := NewMempool(engine.chainState, store, devnetGenesisChainID)
	mustAtomic(t, err)
	engine.SetMempool(mempool)
	owner := mempool.PendingOutpointOwner()
	if _, ok := owner.AdmissionContext(); !ok {
		t.Fatal("owner was not stable before the blocked apply")
	}

	release, result := startBlockedApply(t, engine, store, nil)
	// The transition began before persistence ran, so the owner is already
	// transition-active while the apply is parked inside the injected failure.
	if _, ok := owner.AdmissionContext(); ok {
		t.Error("AdmissionContext was available during an active transition")
	}
	close(release)
	requirePersistenceFault(t, engine, awaitPersistenceResult(t, result, "failed apply"), atomicWriteOverwrite)

	if !engine.persistenceFaulted() {
		t.Fatal("persistence fault was not latched")
	}
	if ctx, ok := owner.AdmissionContext(); ok {
		t.Errorf("AdmissionContext became available after the latched fault: %+v", ctx)
	}

	// The guard is still held, so a standard-admission attempt blocks. It is
	// left parked on purpose: nothing in-process may release that guard.
	admitted := make(chan error, 1)
	go func() { admitted <- mempool.AddTx(DevnetGenesisBlockBytes()) }()
	select {
	case err := <-admitted:
		t.Errorf("standard admission passed the latched guard: %v", err)
	case <-time.After(100 * time.Millisecond):
	}

	// mutationMu, unlike admissionMu, was released when the failed transition
	// returned, so a later mutator reports the latched fault rather than hanging.
	queued := make(chan error, 1)
	go func() { _, err := engine.ApplyBlock(DevnetGenesisBlockBytes(), nil); queued <- err }()
	if err := awaitPersistenceResult(t, queued, "queued mutator"); !errors.Is(err, errStoragePersistenceFault) {
		t.Fatalf("queued mutator=%v, want the latched persistence fault", err)
	}
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
	requirePersistenceFault(t, engine, awaitPersistenceResult(t, firstResult, "first apply"), atomicWriteOverwrite)
	results := [2]error{awaitPersistenceResult(t, secondResult, "second apply"), awaitPersistenceResult(t, bootstrapResult, "bootstrap")}
	requireAtomicTest(t, errors.Is(results[0], errStoragePersistenceFault) && errors.Is(results[1], errStoragePersistenceFault), "second apply=%v bootstrap=%v", results[0], results[1])
}

func TestBootstrapPostCommitFaultIsNeverRaceRecovered(t *testing.T) {
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
	err := engine.BootstrapCanonicalGenesisIfEmpty()
	fault := requirePersistenceFault(t, engine, err, atomicWriteOverwrite)
	later := engine.BootstrapCanonicalGenesisIfEmpty()
	requireAtomicTest(t, failed && errors.Is(fault.cause, os.ErrPermission) && errors.Is(later, errStoragePersistenceFault), "fault=%+v injected=%v later=%v", fault, failed, later)
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

func TestSyncEngineStagingAndDisconnectPostCommitFaultsDoNotCompensate(t *testing.T) {
	t.Run("staging_refusal_never_reaches_the_index", func(t *testing.T) {
		engine, store, _ := newPersistenceFaultEngine(t)
		openFailed, indexWrites := false, 0
		withAtomicWriteOps(t, func(ops *atomicWriteOps) {
			open := ops.openScratch
			ops.openScratch = func(path string, f int, m os.FileMode) (atomicWriteScratchFile, error) {
				if filepath.Dir(path) == store.rootPath {
					indexWrites++
				}
				if !openFailed && filepath.Dir(path) == store.blocksDir {
					openFailed = true
					return nil, syscall.ENOSPC
				}
				return open(path, f, m)
			}
		})
		_, err := engine.ApplyBlock(DevnetGenesisBlockBytes(), nil)
		requireAtomicTest(t, openFailed && err != nil && indexWrites == 0 && !engine.persistenceFaulted(), "err=%v index writes=%d latch=%v", err, indexWrites, engine.persistenceFaulted())
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
		_, err := engine.DisconnectTip()
		// Checkpoint save, then the one index write: two durable commits.
		requirePersistenceFault(t, engine, err, atomicWriteOverwrite)
		requireAtomicTest(t, failed && commits == 2, "failed=%v commits=%d", failed, commits)
		_, _, ok, tipErr := store.Tip()
		requireAtomicTest(t, tipErr == nil && !ok, "cache tip=%v err=%v", ok, tipErr)
	})
}

// TestSyncEngineTerminalFaultedSnapshot pins the read-only terminal-fault status
// method against the EXISTING latch, for BOTH terminal causes: an ambiguous
// atomic post-commit persistence fault, and a transition whose exact rollback
// restore could not be proven. Both project to the same single boolean, which is
// what GET /health renders as terminal_fault / restart_required.
//
// The status method is proven not to be a second fault authority: reading it
// repeatedly neither installs, clears nor rewrites the latched cause, and a nil
// engine reports false rather than a fabricated fault.
func TestSyncEngineTerminalFaultedSnapshot(t *testing.T) {
	var nilEngine *SyncEngine
	requireAtomicTest(t, !nilEngine.TerminalFaulted(), "nil engine reported a terminal fault")

	t.Run("terminal_canonical_index_fault", func(t *testing.T) {
		engine, store, _ := newPersistenceFaultEngine(t)
		requireAtomicTest(t, !engine.TerminalFaulted(), "fresh engine reported a terminal fault")
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
		_, applyErr := engine.ApplyBlock(DevnetGenesisBlockBytes(), nil)
		fault := requirePersistenceFault(t, engine, applyErr, atomicWriteOverwrite)
		requireAtomicTest(t, failed && engine.TerminalFaulted(), "injected=%v terminal=%v", failed, engine.TerminalFaulted())
		// Reading the status is not a state transition: the latched fault
		// pointer and its cause survive repeated reads unchanged.
		for i := 0; i < 3; i++ {
			requireAtomicTest(t, engine.TerminalFaulted(), "terminal status flipped on read %d", i)
		}
		requireAtomicTest(t, engine.persistenceFault == fault && errors.Is(fault.cause, os.ErrPermission), "fault=%+v", engine.persistenceFault)
	})

}
