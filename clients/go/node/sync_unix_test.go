//go:build unix

package node

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

// TestSyncEngineApplyBlockPutUndoFailureRollsBackCanonicalTip — Unix-
// only test for the atomic-commit rollback path when the undo write
// cannot complete. After the E.3 TOCTOU hardening PutUndo routes
// through writeAndSyncTemp + os.Link (not writeFileAtomicFn), so the
// only portable way to provoke an undo-write failure is a chmod-based
// permission error on the undo directory. Skipped under root since
// CAP_DAC bypasses the chmod check.
func TestSyncEngineApplyBlockPutUndoFailureRollsBackCanonicalTip(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: chmod-based permission check does not apply")
	}

	dir := t.TempDir()
	chainStatePath := ChainStatePath(dir)
	store, err := OpenBlockStore(BlockStorePath(dir))
	if err != nil {
		t.Fatalf("open blockstore: %v", err)
	}
	st := NewChainState()
	target := consensus.POW_LIMIT
	engine, err := NewSyncEngine(st, store, DefaultSyncConfig(&target, devnetGenesisChainID, chainStatePath))
	if err != nil {
		t.Fatalf("new sync engine: %v", err)
	}

	if err := os.Chmod(store.undoDir, 0o500); err != nil {
		t.Fatalf("chmod undo dir read-only: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(store.undoDir, 0o700) })
	undoPath := filepath.Join(store.undoDir, hex.EncodeToString(devnetGenesisBlockHash[:])+".json")

	if _, err := engine.ApplyBlock(devnetGenesisBlockBytes, nil); err == nil {
		t.Fatalf("expected apply block failure when undo write fails")
	}
	if st.HasTip {
		t.Fatalf("chainstate tip should be rolled back")
	}
	if _, _, ok, err := store.Tip(); err != nil {
		t.Fatalf("blockstore tip: %v", err)
	} else if ok {
		t.Fatalf("blockstore canonical tip should be rolled back")
	}
	if _, err := os.Stat(undoPath); !os.IsNotExist(err) {
		t.Fatalf("undo file should not exist after rollback, err=%v", err)
	}
}
