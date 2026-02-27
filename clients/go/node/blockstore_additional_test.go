package node

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestBlockStorePath(t *testing.T) {
	if got := BlockStorePath("x"); got != filepath.Join("x", blockStoreDirName) {
		t.Fatalf("unexpected path: %q", got)
	}
}

func TestOpenBlockStore_ErrorsWhenRootIsFile(t *testing.T) {
	dir := t.TempDir()
	rootAsFile := filepath.Join(dir, "blockstore")
	if err := os.WriteFile(rootAsFile, []byte("x"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := OpenBlockStore(rootAsFile); err == nil {
		t.Fatalf("expected error")
	}
}

func TestLoadBlockStoreIndex_Errors(t *testing.T) {
	t.Run("read_error_invalid_name", func(t *testing.T) {
		if _, err := loadBlockStoreIndex(filepath.Join(t.TempDir(), ".")); err == nil {
			t.Fatalf("expected error")
		}
	})

	t.Run("invalid_json", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "index.json")
		if err := os.WriteFile(path, []byte("{\n"), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		if _, err := loadBlockStoreIndex(path); err == nil {
			t.Fatalf("expected error")
		}
	})

	t.Run("version_mismatch", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "index.json")
		raw, _ := json.Marshal(blockStoreIndexDisk{Version: blockStoreIndexVersion + 1, Canonical: []string{}})
		raw = append(raw, '\n')
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		if _, err := loadBlockStoreIndex(path); err == nil {
			t.Fatalf("expected error")
		}
	})

	t.Run("invalid_canonical_hash", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "index.json")
		raw, _ := json.Marshal(blockStoreIndexDisk{Version: blockStoreIndexVersion, Canonical: []string{"zz"}})
		raw = append(raw, '\n')
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		if _, err := loadBlockStoreIndex(path); err == nil {
			t.Fatalf("expected error")
		}
	})
}

func TestBlockStorePutBlock_RejectsInvalidHeaderLen(t *testing.T) {
	store := mustOpenBlockStore(t, filepath.Join(t.TempDir(), "blockstore"))
	if err := store.PutBlock(0, [32]byte{}, []byte{0x01}, []byte("b")); err == nil {
		t.Fatalf("expected error")
	}
}

func TestBlockStorePutBlock_RejectsHeaderHashMismatch(t *testing.T) {
	store := mustOpenBlockStore(t, filepath.Join(t.TempDir(), "blockstore"))
	header := testHeaderBytes(1, 1)
	var wrong [32]byte
	wrong[0] = 0x01
	if err := store.PutBlock(0, wrong, header, []byte("b")); err == nil {
		t.Fatalf("expected error")
	}
}

func TestBlockStoreSetCanonicalTip_SameHashIdempotent(t *testing.T) {
	store := mustOpenBlockStore(t, filepath.Join(t.TempDir(), "blockstore"))
	payload := []byte("block-0")
	hash0, header0 := mustPutBlock(t, store, 0, 1, 11, payload)

	// Second time with same content and same height should hit the "no-op" path
	// (canonical[height] already equals hashHex).
	if err := store.PutBlock(0, hash0, header0, payload); err != nil {
		t.Fatalf("PutBlock again: %v", err)
	}
}

func TestBlockStoreRewindToHeight_Errors(t *testing.T) {
	var nilBS *BlockStore
	if err := nilBS.RewindToHeight(0); err == nil {
		t.Fatalf("expected error")
	}

	store := mustOpenBlockStore(t, filepath.Join(t.TempDir(), "blockstore"))
	if err := store.RewindToHeight(0); err != nil {
		t.Fatalf("expected ok on empty store: %v", err)
	}

	_, _ = mustPutBlock(t, store, 0, 1, 1, []byte("b0"))
	if err := store.RewindToHeight(99); err == nil {
		t.Fatalf("expected out-of-range error")
	}
}

func TestBlockStoreCanonicalHash_Errors(t *testing.T) {
	store := mustOpenBlockStore(t, filepath.Join(t.TempDir(), "blockstore"))
	if _, ok, err := store.CanonicalHash(0); err != nil || ok {
		t.Fatalf("expected ok=false no error; ok=%v err=%v", ok, err)
	}

	store.index.Canonical = []string{"zz"}
	if _, _, err := store.CanonicalHash(0); err == nil {
		t.Fatalf("expected error")
	}
}

func TestBlockStoreTip_Errors(t *testing.T) {
	store := mustOpenBlockStore(t, filepath.Join(t.TempDir(), "blockstore"))
	store.index.Canonical = []string{"zz"}
	if _, _, _, err := store.Tip(); err == nil {
		t.Fatalf("expected error")
	}
}

func TestBlockStoreGetBlockByHash_Nil(t *testing.T) {
	var bs *BlockStore
	if _, err := bs.GetBlockByHash([32]byte{}); err == nil {
		t.Fatalf("expected error")
	}
}

func TestWriteFileIfAbsent_PropagatesWriteError(t *testing.T) {
	prevRead := readFileByPathFn
	prevWrite := writeFileAtomicFn
	t.Cleanup(func() {
		readFileByPathFn = prevRead
		writeFileAtomicFn = prevWrite
	})

	readFileByPathFn = func(string) ([]byte, error) { return nil, os.ErrNotExist }
	writeFileAtomicFn = func(string, []byte, os.FileMode) error { return os.ErrPermission }

	if err := writeFileIfAbsent(filepath.Join(t.TempDir(), "x.bin"), []byte("x")); err == nil {
		t.Fatalf("expected error")
	}
}

func TestWriteFileIfAbsent_PropagatesReadAfterWriteError(t *testing.T) {
	prevRead := readFileByPathFn
	prevWrite := writeFileAtomicFn
	t.Cleanup(func() {
		readFileByPathFn = prevRead
		writeFileAtomicFn = prevWrite
	})

	reads := 0
	readFileByPathFn = func(string) ([]byte, error) {
		reads++
		if reads == 1 {
			return nil, os.ErrNotExist
		}
		return nil, os.ErrPermission
	}
	writeFileAtomicFn = func(string, []byte, os.FileMode) error { return nil }

	if err := writeFileIfAbsent(filepath.Join(t.TempDir(), "x.bin"), []byte("x")); err == nil {
		t.Fatalf("expected error")
	}
}

func TestWriteFileIfAbsent_ExistingSameContentOk(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "x.bin")
	content := []byte("same")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := writeFileIfAbsent(path, append([]byte(nil), content...)); err != nil {
		t.Fatalf("expected ok: %v", err)
	}
	// Ensure no mutation.
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !bytes.Equal(got, content) {
		t.Fatalf("content mismatch")
	}
}

func TestBlockStorePutBlock_RejectsComputedHashMismatch(t *testing.T) {
	// Coverage for consensus.BlockHash error path is hard to hit (header len checked),
	// but computedHash != blockHash is reachable by passing the wrong hash.
	store := mustOpenBlockStore(t, filepath.Join(t.TempDir(), "blockstore"))
	header := testHeaderBytes(1, 2)
	hash := mustHeaderHash(t, header)
	hash[0] ^= 0xff
	if err := store.PutBlock(0, hash, header, []byte("x")); err == nil {
		t.Fatalf("expected error")
	}
}

func TestBlockStoreGetHeaderByHash_Nil(t *testing.T) {
	var bs *BlockStore
	if _, err := bs.GetHeaderByHash([32]byte{}); err == nil {
		t.Fatalf("expected error")
	}
}

func TestBlockStorePutBlock_CallsSetCanonicalTip(t *testing.T) {
	store := mustOpenBlockStore(t, filepath.Join(t.TempDir(), "blockstore"))
	header := testHeaderBytes(9, 9)
	hash := mustHeaderHash(t, header)
	if err := store.PutBlock(0, hash, header, []byte("blk")); err != nil {
		t.Fatalf("PutBlock: %v", err)
	}
	h, ok, err := store.CanonicalHash(0)
	if err != nil {
		t.Fatalf("CanonicalHash: %v", err)
	}
	if !ok || h != hash {
		t.Fatalf("canonical mismatch")
	}
}
