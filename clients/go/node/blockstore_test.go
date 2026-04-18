package node

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
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
	// Only the readFileByPathFn injection is relevant after the E.3
	// TOCTOU hardening: writeFileIfAbsent no longer routes writes
	// through writeFileAtomicFn (it goes directly through
	// allocateAndWriteTemp + os.Link), so mocking writeFileAtomicFn
	// here was dead-but-harmless and has been removed.
	prevRead := readFileByPathFn
	t.Cleanup(func() {
		readFileByPathFn = prevRead
	})

	readFileByPathFn = func(string) ([]byte, error) { return nil, errors.New("boom") }

	if err := writeFileIfAbsent(filepath.Join(t.TempDir(), "x.bin"), []byte("x")); err == nil {
		t.Fatalf("expected error")
	}
}

// TestWriteFileIfAbsentDetectsWrittenMismatch was a legacy test that
// relied on writeFileAtomicFn injection to simulate a "wrong bytes hit
// the disk" scenario before the atomic-link hardening. After the E.3
// TOCTOU fix the write path uses os.Link as the atomic commit, so there
// is no longer a verify-after-write hook point. Race coverage for the
// equivalent "different content on disk" branch is now in
// TestWriteFileIfAbsent_ConcurrentDifferentContent below.

// TestWriteFileIfAbsent_Fresh exercises the happy path: destination is
// absent, writeFileIfAbsent creates it with the given bytes, and a
// subsequent call with the same bytes is a silent no-op (idempotent
// replay contract).
func TestWriteFileIfAbsent_Fresh(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "fresh.bin")
	content := []byte("hello E.3")

	if err := writeFileIfAbsent(path, content); err != nil {
		t.Fatalf("fresh write: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if !bytes.Equal(got, content) {
		t.Fatalf("content mismatch: got %q want %q", got, content)
	}
	// Idempotent replay: same bytes must succeed as a no-op.
	if err := writeFileIfAbsent(path, content); err != nil {
		t.Fatalf("idempotent replay: %v", err)
	}
}

// TestWriteFileIfAbsent_ExistingDifferentContent exercises the non-race
// detection branch: destination is already on disk with bytes that
// differ from the caller's content. writeFileIfAbsent must refuse to
// overwrite and surface an explicit error (never silently replace).
func TestWriteFileIfAbsent_ExistingDifferentContent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "occupied.bin")
	if err := os.WriteFile(path, []byte("existing bytes"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	err := writeFileIfAbsent(path, []byte("different bytes"))
	if err == nil {
		t.Fatalf("expected mismatch error, got nil")
	}
	if !strings.Contains(err.Error(), "different content") {
		t.Fatalf("expected mismatch error, got: %v", err)
	}
	// Destination bytes must not have been overwritten.
	got, _ := os.ReadFile(path)
	if string(got) != "existing bytes" {
		t.Fatalf("destination was silently overwritten: %q", got)
	}
}

// TestWriteFileIfAbsent_ConcurrentSameContent fires N goroutines at the
// same destination with identical content. Atomic os.Link ensures
// exactly one goroutine creates the file; the rest observe the EEXIST
// race branch, verify the content matches, and return nil. This is the
// dominant case during idempotent sync-engine replay, and it must NOT
// produce any errors even under heavy concurrency.
func TestWriteFileIfAbsent_ConcurrentSameContent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "shared.bin")
	content := []byte("shared payload — every goroutine writes these same bytes")

	const N = 16
	errs := make(chan error, N)
	var wg sync.WaitGroup
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- writeFileIfAbsent(path, append([]byte(nil), content...))
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		if e != nil {
			t.Fatalf("concurrent same-content write returned error: %v", e)
		}
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if !bytes.Equal(got, content) {
		t.Fatalf("content mismatch after concurrency: got %q want %q", got, content)
	}
}

// TestWriteFileIfAbsent_ConcurrentDifferentContent fires N goroutines
// at the same destination but each writes DIFFERENT bytes. Exactly one
// goroutine creates the file; the others observe the EEXIST race
// branch, read the existing bytes, see a mismatch, and error. The key
// invariant: the destination must never end up with "wrong" bytes from
// a losing goroutine — atomic link prevents that silent overwrite.
func TestWriteFileIfAbsent_ConcurrentDifferentContent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "contested.bin")

	const N = 16
	errs := make(chan error, N)
	var wg sync.WaitGroup
	for i := 0; i < N; i++ {
		id := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			unique := []byte(fmt.Sprintf("goroutine-%d-payload", id))
			errs <- writeFileIfAbsent(path, unique)
		}()
	}
	wg.Wait()
	close(errs)

	successes := 0
	for e := range errs {
		if e == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("expected exactly 1 success, got %d", successes)
	}
	// Whatever ended up on disk must be the bytes of the winning
	// goroutine — NOT truncated, NOT corrupted by a racing temp write.
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if !strings.HasPrefix(string(got), "goroutine-") || !strings.HasSuffix(string(got), "-payload") {
		t.Fatalf("destination has corrupt/unexpected bytes: %q", got)
	}
}

// Copilot P1 regression on PR #1220: a stale `<dest>.tmp.<pid>.<seq>`
// leftover from a crashed prior process (potentially hard-linked to
// a live destination inode) must NOT be reopened with O_TRUNC —
// that would truncate the destination through the shared inode.
// writeAndSyncTemp uses O_CREATE|O_EXCL (no O_TRUNC), and
// allocateAndWriteTemp retries with a fresh seq on os.ErrExist.
// Verify the retry path by pre-creating a temp at the next seq the
// allocator would produce, then confirm writeFileAtomic succeeds,
// the pre-existing stale temp is NOT truncated, and the destination
// has the expected bytes.
func TestWriteFileAtomic_SkipsStaleTempViaExclusiveCreate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "payload.bin")

	// Pre-create stale temp at the seq the next allocation would hit.
	staleSeq := nextTempSeq() + 1
	staleTmp := tempPathFor(path, os.Getpid(), staleSeq)
	staleBytes := []byte("STALE LEFTOVER - must not be truncated")
	if err := os.WriteFile(staleTmp, staleBytes, 0o600); err != nil {
		t.Fatalf("seed stale temp: %v", err)
	}

	// Counter is already at staleSeq-1 after the `nextTempSeq()+1`
	// probe above; the next nextTempSeq() call (first allocator attempt)
	// returns staleSeq and triggers the O_EXCL AlreadyExists branch.

	if err := writeFileAtomic(path, []byte("fresh bytes"), 0o600); err != nil {
		t.Fatalf("writeFileAtomic: %v", err)
	}

	// Destination has new bytes.
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read dest: %v", err)
	}
	if string(got) != "fresh bytes" {
		t.Fatalf("dest: got %q, want %q", got, "fresh bytes")
	}

	// Stale temp untouched — O_EXCL refused to reopen/truncate.
	gotStale, err := os.ReadFile(staleTmp)
	if err != nil {
		t.Fatalf("read stale after: %v", err)
	}
	if !bytes.Equal(gotStale, staleBytes) {
		t.Fatalf("stale temp was overwritten — O_EXCL retry path is broken: got %q", gotStale)
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
