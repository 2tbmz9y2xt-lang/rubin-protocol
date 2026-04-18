//go:build unix

package node

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

// TestCommitCanonicalBlock_DoesNotAdvanceTipWhenUndoWriteFails pins the
// atomic-commit contract: if the undo write fails, the canonical tip
// must stay empty and the undo file must not exist. Block/header bytes
// persisted before the undo step remain on disk — that is safe and
// self-healing because no canonical entry references them until the tip
// advances (same orphan contract documented on
// `BlockStore::commit_canonical_block`).
//
// Unix-only because after the E.3 TOCTOU hardening PutUndo routes
// through writeAndSyncTemp + os.Link, so forcing an undo-write failure
// needs a chmod-based EACCES on the undo directory, and `os.Geteuid()`
// is not defined on Windows. Skipped under root.
func TestCommitCanonicalBlock_DoesNotAdvanceTipWhenUndoWriteFails(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: chmod-based permission check does not apply")
	}

	store := mustOpenBlockStore(t, filepath.Join(t.TempDir(), "blockstore"))
	header := testHeaderBytes(13, 13)
	hash := mustHeaderHash(t, header)
	blockBytes := []byte("blk")

	if err := os.Chmod(store.undoDir, 0o500); err != nil {
		t.Fatalf("chmod undo dir read-only: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(store.undoDir, 0o700) })
	undoPath := filepath.Join(store.undoDir, hex.EncodeToString(hash[:])+".json")

	if err := store.CommitCanonicalBlock(0, hash, header, blockBytes, &BlockUndo{}); err == nil {
		t.Fatalf("expected undo write failure")
	}
	if _, _, ok, err := store.Tip(); err != nil {
		t.Fatalf("Tip: %v", err)
	} else if ok {
		t.Fatalf("canonical tip must stay empty after undo failure")
	}
	if _, err := os.Stat(undoPath); !os.IsNotExist(err) {
		t.Fatalf("undo file must be absent after failed commit, err=%v", err)
	}
	gotBlock, err := store.GetBlockByHash(hash)
	if err != nil {
		t.Fatalf("GetBlockByHash: %v", err)
	}
	if !bytes.Equal(gotBlock, blockBytes) {
		t.Fatalf("block bytes mismatch after failed commit")
	}
}
