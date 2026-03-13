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

func TestBlockStoreSetCanonicalTip_NilBlockStore(t *testing.T) {
	var nilStore *BlockStore
	if err := nilStore.SetCanonicalTip(0, [32]byte{}); err == nil {
		t.Fatalf("expected nil blockstore error")
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

func TestCommitCanonicalBlock_DoesNotAdvanceTipWhenUndoWriteFails(t *testing.T) {
	store := mustOpenBlockStore(t, filepath.Join(t.TempDir(), "blockstore"))
	header := testHeaderBytes(13, 13)
	hash := mustHeaderHash(t, header)
	blockBytes := []byte("blk")

	prevWrite := writeFileAtomicFn
	t.Cleanup(func() { writeFileAtomicFn = prevWrite })
	undoPath := filepath.Join(store.undoDir, hex.EncodeToString(hash[:])+".json")
	writeFileAtomicFn = func(path string, data []byte, mode os.FileMode) error {
		if path == undoPath {
			return os.ErrPermission
		}
		return prevWrite(path, data, mode)
	}

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

func TestCommitCanonicalBlock_RejectsNilInputs(t *testing.T) {
	header := testHeaderBytes(14, 14)
	hash := mustHeaderHash(t, header)
	blockBytes := []byte("blk")

	var nilStore *BlockStore
	if err := nilStore.CommitCanonicalBlock(0, hash, header, blockBytes, &BlockUndo{}); err == nil {
		t.Fatalf("expected nil blockstore error")
	}

	store := mustOpenBlockStore(t, filepath.Join(t.TempDir(), "blockstore"))
	if err := store.CommitCanonicalBlock(0, hash, header, blockBytes, nil); err == nil {
		t.Fatalf("expected nil undo error")
	}
}

func TestCommitCanonicalBlock_PropagatesStoreBlockFailure(t *testing.T) {
	store := mustOpenBlockStore(t, filepath.Join(t.TempDir(), "blockstore"))
	header := testHeaderBytes(15, 15)
	hash := mustHeaderHash(t, header)
	header[0] ^= 0xff
	if err := store.CommitCanonicalBlock(0, hash, header, []byte("blk"), &BlockUndo{}); err == nil {
		t.Fatalf("expected StoreBlock failure")
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

func TestBlockStoreChainWorkCachesAndHelperCoverage(t *testing.T) {
	store := mustOpenBlockStore(t, filepath.Join(t.TempDir(), "blockstore"))

	header0 := testHeaderBytes(9, 1)
	for i := 4; i < 36; i++ {
		header0[i] = 0
	}
	hash0 := mustHeaderHash(t, header0)
	if err := store.StoreBlock(hash0, header0, []byte("blk0")); err != nil {
		t.Fatalf("StoreBlock(root): %v", err)
	}

	header1 := append([]byte(nil), testHeaderBytes(10, 2)...)
	copy(header1[4:36], hash0[:])
	hash1 := mustHeaderHash(t, header1)
	if err := store.StoreBlock(hash1, header1, []byte("blk1")); err != nil {
		t.Fatalf("StoreBlock(child): %v", err)
	}

	work1, err := store.ChainWork(hash1)
	if err != nil {
		t.Fatalf("ChainWork(initial): %v", err)
	}
	work1.Add(work1, big.NewInt(1))

	cachedAgain, err := store.ChainWork(hash1)
	if err != nil {
		t.Fatalf("ChainWork(cached): %v", err)
	}
	if cachedAgain.Cmp(work1) >= 0 {
		t.Fatalf("cached ChainWork should return an independent clone")
	}

	if _, err := buildCanonicalHeightIndex([]string{"zz", hex.EncodeToString(hash1[:])}); err == nil {
		t.Fatalf("expected invalid canonical index error")
	}

	var nilStore *BlockStore
	nilStore.rebuildCanonicalHeightIndex()
	if cloneBigInt(nil) != nil {
		t.Fatalf("cloneBigInt(nil) should be nil")
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

func TestBlockStoreChainWorkCachesCanonicalOnly(t *testing.T) {
	store := mustOpenBlockStore(t, filepath.Join(t.TempDir(), "blockstore"))

	header0 := testHeaderBytes(0x31, 1)
	for i := 4; i < 36; i++ {
		header0[i] = 0
	}
	hash0 := mustHeaderHash(t, header0)
	if err := store.PutBlock(0, hash0, header0, []byte("b0")); err != nil {
		t.Fatalf("PutBlock(root): %v", err)
	}

	header1a := append([]byte(nil), testHeaderBytes(0x32, 2)...)
	copy(header1a[4:36], hash0[:])
	hash1a := mustHeaderHash(t, header1a)
	if err := store.PutBlock(1, hash1a, header1a, []byte("b1a")); err != nil {
		t.Fatalf("PutBlock(branch a): %v", err)
	}

	header1b := append([]byte(nil), testHeaderBytes(0x33, 3)...)
	copy(header1b[4:36], hash0[:])
	hash1b := mustHeaderHash(t, header1b)
	if err := store.PutBlock(1, hash1b, header1b, []byte("b1b")); err != nil {
		t.Fatalf("PutBlock(branch b): %v", err)
	}

	if _, err := store.ChainWork(hash1a); err != nil {
		t.Fatalf("ChainWork(non-canonical branch): %v", err)
	}
	if _, err := store.ChainWork(hash1b); err != nil {
		t.Fatalf("ChainWork(canonical branch): %v", err)
	}

	store.stateMu.RLock()
	_, rootCached := store.chainWorkByHash[hash0]
	_, branchACached := store.chainWorkByHash[hash1a]
	_, branchBCached := store.chainWorkByHash[hash1b]
	store.stateMu.RUnlock()

	if !rootCached {
		t.Fatalf("expected canonical root to be cached")
	}
	if branchACached {
		t.Fatalf("non-canonical branch work must not stay cached")
	}
	if !branchBCached {
		t.Fatalf("expected canonical tip to be cached")
	}
}

func TestBlockStoreChainWorkRejectsInvalidTargetWithCachedAncestor(t *testing.T) {
	store := mustOpenBlockStore(t, filepath.Join(t.TempDir(), "blockstore"))

	header0 := testHeaderBytes(0x41, 1)
	for i := 4; i < 36; i++ {
		header0[i] = 0
	}
	hash0 := mustHeaderHash(t, header0)
	if err := store.PutBlock(0, hash0, header0, []byte("root")); err != nil {
		t.Fatalf("PutBlock(root): %v", err)
	}
	if _, err := store.ChainWork(hash0); err != nil {
		t.Fatalf("ChainWork(root): %v", err)
	}

	header1 := append([]byte(nil), testHeaderBytes(0x42, 2)...)
	copy(header1[4:36], hash0[:])
	for i := 76; i < 108; i++ {
		header1[i] = 0
	}
	hash1 := mustHeaderHash(t, header1)
	if err := store.StoreBlock(hash1, header1, []byte("bad-child")); err != nil {
		t.Fatalf("StoreBlock(child): %v", err)
	}

	if _, err := store.ChainWork(hash1); err == nil {
		t.Fatalf("expected invalid target error")
	}
}

func TestBlockStoreChainWorkRejectsInvalidTargetWithoutCachedAncestor(t *testing.T) {
	store := mustOpenBlockStore(t, filepath.Join(t.TempDir(), "blockstore"))

	header := testHeaderBytes(0x43, 3)
	for i := 4; i < 36; i++ {
		header[i] = 0
	}
	for i := 76; i < 108; i++ {
		header[i] = 0
	}
	hash := mustHeaderHash(t, header)
	if err := store.StoreBlock(hash, header, []byte("bad-root")); err != nil {
		t.Fatalf("StoreBlock(root): %v", err)
	}

	if _, err := store.ChainWork(hash); err == nil {
		t.Fatalf("expected invalid target error")
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

func TestUpdatedCanonicalHashes_CoversAllBranches(t *testing.T) {
	hash0 := [32]byte{0x01}
	hash1 := [32]byte{0x02}
	hash2 := [32]byte{0x03}
	h0 := hex.EncodeToString(hash0[:])
	h1 := hex.EncodeToString(hash1[:])
	h2 := hex.EncodeToString(hash2[:])

	if _, _, err := updatedCanonicalHashes([]string{}, 1, hash0); err == nil {
		t.Fatalf("expected height-gap error")
	}

	got, changed, err := updatedCanonicalHashes([]string{}, 0, hash0)
	if err != nil || !changed || len(got) != 1 || got[0] != h0 {
		t.Fatalf("append branch mismatch: got=%v changed=%v err=%v", got, changed, err)
	}

	got, changed, err = updatedCanonicalHashes([]string{h0, h1}, 1, hash1)
	if err != nil || changed || len(got) != 2 || got[1] != h1 {
		t.Fatalf("no-op branch mismatch: got=%v changed=%v err=%v", got, changed, err)
	}

	got, changed, err = updatedCanonicalHashes([]string{h0, h1}, 1, hash2)
	if err != nil || !changed || len(got) != 2 || got[0] != h0 || got[1] != h2 {
		t.Fatalf("replace branch mismatch: got=%v changed=%v err=%v", got, changed, err)
	}
}

func TestBlockStoreCanonicalStateHelpers(t *testing.T) {
	hash0 := [32]byte{0x11}
	hash1 := [32]byte{0x12}
	work := big.NewInt(123)

	var nilStore *BlockStore
	if got, ok := nilStore.cachedChainWork(hash0); ok || got != nil {
		t.Fatalf("nil cachedChainWork = (%v,%v), want (nil,false)", got, ok)
	}
	nilStore.storeChainWorkIfCanonical(hash0, work)
	nilStore.rebuildCanonicalHeightIndex()
	if err := nilStore.dropCanonicalStateFromLocked(0); err != nil {
		t.Fatalf("nil dropCanonicalStateFromLocked: %v", err)
	}

	store := mustOpenBlockStore(t, filepath.Join(t.TempDir(), "blockstore"))
	store.index.Canonical = []string{hex.EncodeToString(hash0[:]), hex.EncodeToString(hash1[:])}
	store.canonicalHeightByHash = map[[32]byte]uint64{hash0: 0, hash1: 1}
	store.chainWorkByHash = map[[32]byte]*big.Int{hash0: big.NewInt(10), hash1: big.NewInt(20)}

	store.storeChainWorkIfCanonical(hash0, work)
	if got, ok := store.cachedChainWork(hash0); !ok || got.Cmp(work) != 0 {
		t.Fatalf("cachedChainWork mismatch: got=%v ok=%v", got, ok)
	}
	if got, ok := store.cachedChainWork(hash1); !ok || got.Cmp(big.NewInt(20)) != 0 {
		t.Fatalf("unexpected cachedChainWork for hash1: got=%v ok=%v", got, ok)
	}
	store.storeChainWorkIfCanonical([32]byte{0xff}, big.NewInt(77))
	if _, ok := store.chainWorkByHash[[32]byte{0xff}]; ok {
		t.Fatalf("non-canonical work should not be stored")
	}
	store.storeChainWorkIfCanonical(hash0, nil)

	if err := store.dropCanonicalStateFromLocked(1); err != nil {
		t.Fatalf("dropCanonicalStateFromLocked: %v", err)
	}
	if _, ok := store.canonicalHeightByHash[hash1]; ok {
		t.Fatalf("expected hash1 to be dropped from canonical index")
	}
	if _, ok := store.chainWorkByHash[hash1]; ok {
		t.Fatalf("expected hash1 work cache to be dropped")
	}

	store.index.Canonical = []string{"zz"}
	store.rebuildCanonicalHeightIndex()
	if len(store.canonicalHeightByHash) != 1 {
		t.Fatalf("malformed rebuild should preserve old index")
	}

	store.index.Canonical = []string{hex.EncodeToString(hash0[:])}
	store.rebuildCanonicalHeightIndex()
	if len(store.canonicalHeightByHash) != 1 || store.canonicalHeightByHash[hash0] != 0 {
		t.Fatalf("rebuildCanonicalHeightIndex mismatch: %v", store.canonicalHeightByHash)
	}
	if len(store.chainWorkByHash) != 0 {
		t.Fatalf("rebuildCanonicalHeightIndex should reset chainWork cache")
	}
}

func TestBlockStoreCanonicalAndTruncateErrorBranches(t *testing.T) {
	var nilStore *BlockStore
	if _, _, err := nilStore.CanonicalHash(0); err == nil {
		t.Fatalf("expected nil CanonicalHash error")
	}
	if err := nilStore.TruncateCanonical(0); err == nil {
		t.Fatalf("expected nil TruncateCanonical error")
	}

	store := mustOpenBlockStore(t, filepath.Join(t.TempDir(), "blockstore"))
	if err := store.TruncateCanonical(1); err == nil {
		t.Fatalf("expected truncate out-of-range error")
	}

	hash := [32]byte{0x21}
	store.index.Canonical = []string{hex.EncodeToString(hash[:]), "zz"}
	store.canonicalHeightByHash = map[[32]byte]uint64{hash: 0}
	if err := store.TruncateCanonical(1); err == nil {
		t.Fatalf("expected malformed canonical truncate error")
	}
}
