package node

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

func mustOpenBlockStore(t *testing.T, path string) *BlockStore {
	t.Helper()
	store, err := OpenBlockStore(path)
	if err != nil {
		t.Fatalf("open blockstore: %v", err)
	}
	return store
}

func mustHeaderHash(t *testing.T, header []byte) [32]byte {
	t.Helper()
	hash, err := consensus.BlockHash(header)
	if err != nil {
		t.Fatalf("block hash: %v", err)
	}
	return hash
}

func mustPutBlock(t *testing.T, store *BlockStore, height uint64, seed byte, nonce uint64, payload []byte) ([32]byte, []byte) {
	t.Helper()
	header := testHeaderBytes(seed, nonce)
	hash := mustHeaderHash(t, header)
	if err := store.PutBlock(height, hash, header, payload); err != nil {
		t.Fatalf("put block height=%d: %v", height, err)
	}
	return hash, header
}

func TestBlockStorePutGetAndTip(t *testing.T) {
	store := mustOpenBlockStore(t, filepath.Join(t.TempDir(), "blockstore"))
	block0 := []byte("block-0")
	hash0, _ := mustPutBlock(t, store, 0, 1, 11, block0)

	block1 := []byte("block-1")
	hash1, header1 := mustPutBlock(t, store, 1, 2, 22, block1)

	var err error
	gotHeader1, err := store.GetHeaderByHash(hash1)
	if err != nil {
		t.Fatalf("get header by hash: %v", err)
	}
	if !bytes.Equal(gotHeader1, header1) {
		t.Fatalf("header bytes mismatch")
	}

	gotBlock1, err := store.GetBlockByHash(hash1)
	if err != nil {
		t.Fatalf("get block by hash: %v", err)
	}
	if !bytes.Equal(gotBlock1, block1) {
		t.Fatalf("block bytes mismatch")
	}

	tipHeight, tipHash, ok, err := store.Tip()
	if err != nil {
		t.Fatalf("tip: %v", err)
	}
	if !ok || tipHeight != 1 || tipHash != hash1 {
		t.Fatalf("unexpected tip: ok=%v height=%d hash=%x", ok, tipHeight, tipHash)
	}

	h0, ok, err := store.CanonicalHash(0)
	if err != nil {
		t.Fatalf("canonical hash height 0: %v", err)
	}
	if !ok || h0 != hash0 {
		t.Fatalf("canonical hash height 0 mismatch")
	}
}

func TestBlockStoreReorgAndRewindHooks(t *testing.T) {
	store := mustOpenBlockStore(t, filepath.Join(t.TempDir(), "blockstore"))
	hash0, _ := mustPutBlock(t, store, 0, 10, 1, []byte("b0"))
	_, _ = mustPutBlock(t, store, 1, 11, 2, []byte("b1a"))
	hash1b, _ := mustPutBlock(t, store, 1, 12, 3, []byte("b1b"))

	var err error
	tipHeight, tipHash, ok, err := store.Tip()
	if err != nil {
		t.Fatalf("tip after reorg: %v", err)
	}
	if !ok || tipHeight != 1 || tipHash != hash1b {
		t.Fatalf("unexpected tip after reorg: ok=%v height=%d hash=%x", ok, tipHeight, tipHash)
	}

	if err := store.RewindToHeight(0); err != nil {
		t.Fatalf("rewind to height 0: %v", err)
	}
	tipHeight, tipHash, ok, err = store.Tip()
	if err != nil {
		t.Fatalf("tip after rewind: %v", err)
	}
	if !ok || tipHeight != 0 || tipHash != hash0 {
		t.Fatalf("unexpected tip after rewind: ok=%v height=%d hash=%x", ok, tipHeight, tipHash)
	}
}

func TestBlockStoreRejectsHeightGap(t *testing.T) {
	store := mustOpenBlockStore(t, filepath.Join(t.TempDir(), "blockstore"))
	header := testHeaderBytes(3, 33)
	hash := mustHeaderHash(t, header)
	if err := store.PutBlock(2, hash, header, []byte("gapped")); err == nil {
		t.Fatalf("expected height gap error")
	}
}

func TestBlockStorePersistsIndex(t *testing.T) {
	root := filepath.Join(t.TempDir(), "blockstore")
	store := mustOpenBlockStore(t, root)
	hash, _ := mustPutBlock(t, store, 0, 7, 77, []byte("persist"))

	var err error
	reopened, err := OpenBlockStore(root)
	if err != nil {
		t.Fatalf("reopen blockstore: %v", err)
	}
	height, gotHash, ok, err := reopened.Tip()
	if err != nil {
		t.Fatalf("tip after reopen: %v", err)
	}
	if !ok || height != 0 || gotHash != hash {
		t.Fatalf("unexpected tip after reopen: ok=%v height=%d hash=%x", ok, height, gotHash)
	}
}

func TestWriteFileIfAbsentRejectsDifferentContent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x.bin")
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatalf("write old: %v", err)
	}
	if err := writeFileIfAbsent(path, []byte("new")); err == nil {
		t.Fatalf("expected error for different existing content")
	}
	if err := writeFileIfAbsent(path, []byte("old")); err != nil {
		t.Fatalf("expected ok for same existing content: %v", err)
	}
}

func TestWriteFileIfAbsentPropagatesReadError(t *testing.T) {
	prevRead := readFileByPathFn
	prevWrite := writeFileAtomicFn
	t.Cleanup(func() {
		readFileByPathFn = prevRead
		writeFileAtomicFn = prevWrite
	})

	readFileByPathFn = func(string) ([]byte, error) { return nil, errors.New("boom") }
	writeFileAtomicFn = func(string, []byte, os.FileMode) error { return nil }

	if err := writeFileIfAbsent(filepath.Join(t.TempDir(), "x.bin"), []byte("x")); err == nil {
		t.Fatalf("expected error")
	}
}

func TestWriteFileIfAbsentDetectsWrittenMismatch(t *testing.T) {
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
		return []byte("wrong"), nil
	}
	writeFileAtomicFn = func(string, []byte, os.FileMode) error { return nil }

	if err := writeFileIfAbsent(filepath.Join(t.TempDir(), "x.bin"), []byte("right")); err == nil {
		t.Fatalf("expected mismatch error")
	}
}

func TestBlockStoreTipNil(t *testing.T) {
	var bs *BlockStore
	if _, _, _, err := bs.Tip(); err == nil {
		t.Fatalf("expected error")
	}
}

func TestBlockStoreTipEmptyOK(t *testing.T) {
	store := mustOpenBlockStore(t, filepath.Join(t.TempDir(), "blockstore"))
	_, _, ok, err := store.Tip()
	if err != nil {
		t.Fatalf("tip: %v", err)
	}
	if ok {
		t.Fatalf("expected ok=false")
	}
}

func TestBlockStoreGetHeaderByHashNil(t *testing.T) {
	var bs *BlockStore
	if _, err := bs.GetHeaderByHash([32]byte{}); err == nil {
		t.Fatalf("expected error")
	}
}

func testHeaderBytes(seed byte, nonce uint64) []byte {
	header := make([]byte, consensus.BLOCK_HEADER_BYTES)
	binary.LittleEndian.PutUint32(header[0:4], 1)
	for i := 4; i < 36; i++ {
		header[i] = seed
	}
	for i := 36; i < 68; i++ {
		header[i] = seed + 1
	}
	binary.LittleEndian.PutUint64(header[68:76], 123)
	for i := 76; i < 108; i++ {
		header[i] = 0xff
	}
	binary.LittleEndian.PutUint64(header[108:116], nonce)
	return header
}
