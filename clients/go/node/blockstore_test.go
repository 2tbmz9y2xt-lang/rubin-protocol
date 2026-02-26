package node

import (
	"bytes"
	"encoding/binary"
	"path/filepath"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

func TestBlockStorePutGetAndTip(t *testing.T) {
	store, err := OpenBlockStore(filepath.Join(t.TempDir(), "blockstore"))
	if err != nil {
		t.Fatalf("open blockstore: %v", err)
	}

	header0 := testHeaderBytes(1, 11)
	hash0, err := consensus.BlockHash(header0)
	if err != nil {
		t.Fatalf("block hash 0: %v", err)
	}
	block0 := []byte("block-0")
	if err := store.PutBlock(0, hash0, header0, block0); err != nil {
		t.Fatalf("put block 0: %v", err)
	}

	header1 := testHeaderBytes(2, 22)
	hash1, err := consensus.BlockHash(header1)
	if err != nil {
		t.Fatalf("block hash 1: %v", err)
	}
	block1 := []byte("block-1")
	if err := store.PutBlock(1, hash1, header1, block1); err != nil {
		t.Fatalf("put block 1: %v", err)
	}

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
	store, err := OpenBlockStore(filepath.Join(t.TempDir(), "blockstore"))
	if err != nil {
		t.Fatalf("open blockstore: %v", err)
	}

	header0 := testHeaderBytes(10, 1)
	hash0, _ := consensus.BlockHash(header0)
	if err := store.PutBlock(0, hash0, header0, []byte("b0")); err != nil {
		t.Fatalf("put b0: %v", err)
	}

	header1a := testHeaderBytes(11, 2)
	hash1a, _ := consensus.BlockHash(header1a)
	if err := store.PutBlock(1, hash1a, header1a, []byte("b1a")); err != nil {
		t.Fatalf("put b1a: %v", err)
	}

	header1b := testHeaderBytes(12, 3)
	hash1b, _ := consensus.BlockHash(header1b)
	if err := store.PutBlock(1, hash1b, header1b, []byte("b1b")); err != nil {
		t.Fatalf("put b1b (reorg): %v", err)
	}

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
	store, err := OpenBlockStore(filepath.Join(t.TempDir(), "blockstore"))
	if err != nil {
		t.Fatalf("open blockstore: %v", err)
	}
	header := testHeaderBytes(3, 33)
	hash, _ := consensus.BlockHash(header)
	if err := store.PutBlock(2, hash, header, []byte("gapped")); err == nil {
		t.Fatalf("expected height gap error")
	}
}

func TestBlockStorePersistsIndex(t *testing.T) {
	root := filepath.Join(t.TempDir(), "blockstore")
	store, err := OpenBlockStore(root)
	if err != nil {
		t.Fatalf("open blockstore: %v", err)
	}
	header := testHeaderBytes(7, 77)
	hash, _ := consensus.BlockHash(header)
	if err := store.PutBlock(0, hash, header, []byte("persist")); err != nil {
		t.Fatalf("put block: %v", err)
	}

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
