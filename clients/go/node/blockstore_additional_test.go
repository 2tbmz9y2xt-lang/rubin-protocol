package node

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"math/big"
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

func TestBlockStoreStoreBlockAndChainWork(t *testing.T) {
	store := mustOpenBlockStore(t, filepath.Join(t.TempDir(), "blockstore"))
	if work, err := store.ChainWork([32]byte{}); err != nil {
		t.Fatalf("ChainWork(zero): %v", err)
	} else if work.Cmp(big.NewInt(0)) != 0 {
		t.Fatalf("zero work=%s, want 0", work)
	}

	header0 := testHeaderBytes(5, 1)
	for i := 4; i < 36; i++ {
		header0[i] = 0
	}
	hash0 := mustHeaderHash(t, header0)
	if err := store.StoreBlock(hash0, header0, []byte("blk0")); err != nil {
		t.Fatalf("StoreBlock(root): %v", err)
	}

	header1 := append([]byte(nil), testHeaderBytes(6, 2)...)
	copy(header1[4:36], hash0[:])
	hash1 := mustHeaderHash(t, header1)
	if err := store.StoreBlock(hash1, header1, []byte("blk1")); err != nil {
		t.Fatalf("StoreBlock(child): %v", err)
	}

	work0, err := store.ChainWork(hash0)
	if err != nil {
		t.Fatalf("ChainWork(root): %v", err)
	}
	work1, err := store.ChainWork(hash1)
	if err != nil {
		t.Fatalf("ChainWork(child): %v", err)
	}
	if work1.Cmp(work0) <= 0 {
		t.Fatalf("ChainWork(child)=%s, want > %s", work1, work0)
	}
}

func TestBlockStoreCanonicalIndexHelpersAndUndoErrors(t *testing.T) {
	var nilStore *BlockStore
	if _, err := nilStore.CanonicalIndexSnapshot(); err == nil {
		t.Fatalf("expected nil CanonicalIndexSnapshot error")
	}
	if err := nilStore.RestoreCanonicalIndex(nil); err == nil {
		t.Fatalf("expected nil RestoreCanonicalIndex error")
	}
	if _, err := nilStore.ChainWork([32]byte{}); err == nil {
		t.Fatalf("expected nil ChainWork error")
	}
	if err := nilStore.PutUndo([32]byte{}, &BlockUndo{}); err == nil {
		t.Fatalf("expected nil PutUndo error")
	}
	if _, err := nilStore.GetUndo([32]byte{}); err == nil {
		t.Fatalf("expected nil GetUndo error")
	}

	store := mustOpenBlockStore(t, filepath.Join(t.TempDir(), "blockstore"))
	store.index.Canonical = []string{"zz"}
	if _, err := store.CanonicalIndexSnapshot(); err == nil {
		t.Fatalf("expected invalid canonical snapshot error")
	}
	if err := store.RestoreCanonicalIndex([]string{"zz"}); err == nil {
		t.Fatalf("expected invalid canonical restore error")
	}

	if err := store.PutUndo([32]byte{0x01}, &BlockUndo{}); err != nil {
		t.Fatalf("PutUndo: %v", err)
	}
	if _, err := store.GetUndo([32]byte{0x01}); err != nil {
		t.Fatalf("GetUndo: %v", err)
	}
	if err := os.WriteFile(filepath.Join(store.undoDir, "ff.json"), []byte("{"), 0o600); err != nil {
		t.Fatalf("WriteFile(malformed undo): %v", err)
	}
	if _, err := store.GetUndo([32]byte{0xff}); err == nil {
		t.Fatalf("expected malformed undo error")
	}
}

func TestBlockStoreChainWorkParentCycle(t *testing.T) {
	store := mustOpenBlockStore(t, filepath.Join(t.TempDir(), "blockstore"))
	header := testHeaderBytes(7, 3)
	hash := mustHeaderHash(t, header)
	if err := store.StoreBlock(hash, header, []byte("blk")); err != nil {
		t.Fatalf("StoreBlock: %v", err)
	}
	headerPath := filepath.Join(store.headersDir, hex.EncodeToString(hash[:])+".bin")
	cyclicHeader := append([]byte(nil), header...)
	copy(cyclicHeader[4:36], hash[:])
	if err := os.WriteFile(headerPath, cyclicHeader, 0o600); err != nil {
		t.Fatalf("WriteFile(cyclic header): %v", err)
	}
	if _, err := store.ChainWork(hash); err == nil {
		t.Fatalf("expected parent cycle error")
	}
}

func TestBlockStoreStoreBlockAndChainWorkErrors(t *testing.T) {
	var nilStore *BlockStore
	header := testHeaderBytes(7, 7)
	hash := mustHeaderHash(t, header)
	if err := nilStore.StoreBlock(hash, header, []byte("blk")); err == nil {
		t.Fatalf("expected nil StoreBlock error")
	}
	if _, err := nilStore.ChainWork(hash); err == nil {
		t.Fatalf("expected nil ChainWork error")
	}

	store := mustOpenBlockStore(t, filepath.Join(t.TempDir(), "blockstore"))
	if _, err := store.ChainWork(hash); err == nil {
		t.Fatalf("expected missing header error")
	}

	headerPath := filepath.Join(store.headersDir, hex.EncodeToString(hash[:])+".bin")
	if err := os.WriteFile(headerPath, []byte{0x01, 0x02}, 0o600); err != nil {
		t.Fatalf("WriteFile(invalid header): %v", err)
	}
	if _, err := store.ChainWork(hash); err == nil {
		t.Fatalf("expected invalid header parse error")
	}

	cycleStore := mustOpenBlockStore(t, filepath.Join(t.TempDir(), "cycle"))
	cycleHeader := append([]byte(nil), testHeaderBytes(8, 8)...)
	cycleHash := mustHeaderHash(t, cycleHeader)
	copy(cycleHeader[4:36], cycleHash[:])
	if err := os.WriteFile(filepath.Join(cycleStore.headersDir, hex.EncodeToString(cycleHash[:])+".bin"), cycleHeader, 0o600); err != nil {
		t.Fatalf("WriteFile(cycle header): %v", err)
	}
	if _, err := cycleStore.ChainWork(cycleHash); err == nil {
		t.Fatalf("expected cycle error")
	}
}
