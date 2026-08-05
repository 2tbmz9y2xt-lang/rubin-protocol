package node

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
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

func mustCreateBlockStore(t *testing.T, path string) *BlockStore {
	t.Helper()
	store, err := CreateBlockStore(path)
	if err != nil {
		t.Fatalf("create blockstore: %v", err)
	}
	return store
}

func assertNodePathMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("mode %s = %04o, want %04o", path, got, want)
	}
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

func TestCreateBlockStoreCreatesPrivateDirsAndFiles(t *testing.T) {
	root := filepath.Join(t.TempDir(), "blockstore")
	store := mustCreateBlockStore(t, root)

	assertNodePathMode(t, root, 0o700)
	assertNodePathMode(t, store.blocksDir, 0o700)
	assertNodePathMode(t, store.headersDir, 0o700)
	assertNodePathMode(t, store.undoDir, 0o700)

	header := testHeaderBytes(31, 31)
	hash := mustHeaderHash(t, header)
	blockBytes := []byte("private block payload")
	if err := store.CommitCanonicalBlock(0, hash, header, blockBytes, &BlockUndo{}); err != nil {
		t.Fatalf("commit canonical block: %v", err)
	}

	hashHex := hex.EncodeToString(hash[:])
	assertNodePathMode(t, filepath.Join(root, "index.json"), 0o600)
	assertNodePathMode(t, filepath.Join(store.blocksDir, hashHex+".bin"), 0o600)
	assertNodePathMode(t, filepath.Join(store.headersDir, hashHex+".bin"), 0o600)
	assertNodePathMode(t, filepath.Join(store.undoDir, hashHex+".json"), 0o600)

	reopened := mustOpenBlockStore(t, root)
	tipHeight, tipHash, ok, err := reopened.Tip()
	if err != nil {
		t.Fatalf("reopened tip: %v", err)
	}
	if !ok || tipHeight != 0 || tipHash != hash {
		t.Fatalf("reopened tip = ok=%v height=%d hash=%x, want height 0 hash %x", ok, tipHeight, tipHash, hash)
	}
}

func TestBlockStorePutGetAndTip(t *testing.T) {
	store := mustCreateBlockStore(t, filepath.Join(t.TempDir(), "blockstore"))
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
	store := mustCreateBlockStore(t, filepath.Join(t.TempDir(), "blockstore"))
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
	store := mustCreateBlockStore(t, filepath.Join(t.TempDir(), "blockstore"))
	header := testHeaderBytes(3, 33)
	hash := mustHeaderHash(t, header)
	if err := store.PutBlock(2, hash, header, []byte("gapped")); err == nil {
		t.Fatalf("expected height gap error")
	}
}

func TestBlockStorePersistsIndex(t *testing.T) {
	root := filepath.Join(t.TempDir(), "blockstore")
	store := mustCreateBlockStore(t, root)
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
	t.Cleanup(func() {
		readFileByPathFn = prevRead
	})

	readFileByPathFn = func(string, int64) ([]byte, error) { return nil, errors.New("boom") }

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

func TestWriteFileAtomic_ReclaimsFixedScratchBeforeExclusiveCreate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "payload.bin")
	scratch := filepath.Join(dir, atomicWriteScratchLeaf)
	if err := os.WriteFile(scratch, []byte("STALE LEFTOVER"), 0o600); err != nil {
		t.Fatalf("seed stale scratch: %v", err)
	}

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

	if _, err := os.Lstat(scratch); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("fixed scratch remained after commit: %v", err)
	}
}

func TestBlockStoreTipNil(t *testing.T) {
	var bs *BlockStore
	if _, _, _, err := bs.Tip(); err == nil {
		t.Fatalf("expected error")
	}
}

func TestBlockStoreTipEmptyOK(t *testing.T) {
	store := mustCreateBlockStore(t, filepath.Join(t.TempDir(), "blockstore"))
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

func putChainWorkHeader(t *testing.T, store *BlockStore, height uint64, prev [32]byte, seed byte, target [32]byte) [32]byte {
	t.Helper()
	header := testHeaderBytes(seed, uint64(seed))
	copy(header[4:36], prev[:])
	copy(header[76:108], target[:])
	hash := mustHeaderHash(t, header)
	if err := store.PutBlock(height, hash, header, []byte("chain-work-test")); err != nil {
		t.Fatalf("PutBlock(%d): %v", height, err)
	}
	return hash
}

func mustChainWorkTestChain(t *testing.T) (*BlockStore, [3][32]byte) {
	t.Helper()
	store := mustCreateBlockStore(t, filepath.Join(t.TempDir(), "blockstore"))
	var zero [32]byte
	var hashes [3][32]byte
	hashes[0] = putChainWorkHeader(t, store, 0, zero, 0x51, consensus.POW_LIMIT)
	hashes[1] = putChainWorkHeader(t, store, 1, hashes[0], 0x52, consensus.POW_LIMIT)
	hashes[2] = putChainWorkHeader(t, store, 2, hashes[1], 0x53, consensus.POW_LIMIT)
	return store, hashes
}

func mustGetChainWorkHeader(t *testing.T, store *BlockStore, hash [32]byte) []byte {
	t.Helper()
	raw, err := store.GetHeaderByHash(hash)
	if err != nil {
		t.Fatalf("GetHeaderByHash(%x): %v", hash, err)
	}
	return raw
}

func assertChainWorkLocalCorruption(t *testing.T, work *big.Int, err error) {
	t.Helper()
	if work != nil || !errors.Is(err, errBranchStoreCorrupt) {
		t.Fatalf("ChainWork=(%v,%v), want nil,errBranchStoreCorrupt", work, err)
	}
	var txErr *consensus.TxError
	if errors.As(err, &txErr) {
		t.Fatalf("local chain-work corruption leaked consensus.TxError: %v", err)
	}
}

func TestBlockStoreChainWorkCacheRows(t *testing.T) {
	want := big.NewInt(3) // POW_LIMIT contributes exactly one unit per header.
	uncached, uncachedHashes := mustChainWorkTestChain(t)
	if _, ok := uncached.cachedChainWork(uncachedHashes[2]); ok {
		t.Fatal("fresh chain-work fixture unexpectedly has a cached tip")
	}
	got, err := uncached.ChainWork(uncachedHashes[2])
	if err != nil || got.Cmp(want) != 0 {
		t.Fatalf("uncached ChainWork=(%v,%v), want %s,nil", got, err, want)
	}
	partial, partialHashes := mustChainWorkTestChain(t)
	if _, err := partial.ChainWork(partialHashes[1]); err != nil {
		t.Fatalf("ChainWork(cached ancestor): %v", err)
	}
	if err := os.WriteFile(filepath.Join(partial.headersDir, hex.EncodeToString(partialHashes[1][:])+".bin"), []byte("corrupt cached ancestor"), 0o600); err != nil {
		t.Fatalf("WriteFile(corrupt cached ancestor): %v", err)
	}
	got, err = partial.ChainWork(partialHashes[2])
	if err != nil || got.Cmp(want) != 0 {
		t.Fatalf("partial-cache ChainWork=(%v,%v), want %s,nil", got, err, want)
	}
	if err := os.WriteFile(filepath.Join(partial.headersDir, hex.EncodeToString(partialHashes[2][:])+".bin"), []byte("corrupt cached tip"), 0o600); err != nil {
		t.Fatalf("WriteFile(corrupt cached tip): %v", err)
	}
	got.SetInt64(0)
	got, err = partial.ChainWork(partialHashes[2])
	if err != nil || got.Cmp(want) != 0 {
		t.Fatalf("complete-cache ChainWork=(%v,%v), want %s,nil", got, err, want)
	}
	longStore := mustCreateBlockStore(t, filepath.Join(t.TempDir(), "long-blockstore"))
	const longCount = 33
	var longTip [32]byte
	for i := 0; i < longCount; i++ {
		longTip = putChainWorkHeader(t, longStore, uint64(i), longTip, byte(i+1), consensus.POW_LIMIT)
	}
	longGot, err := longStore.ChainWork(longTip)
	if err != nil || longGot.Cmp(big.NewInt(longCount)) != 0 {
		t.Fatalf("long uncached ChainWork=(%v,%v), want %d,nil", longGot, err, longCount)
	}
}

func TestBlockStoreChainWorkLocalCorruptionRows(t *testing.T) {
	t.Run("missing_header", func(t *testing.T) {
		store := mustCreateBlockStore(t, filepath.Join(t.TempDir(), "blockstore"))
		work, err := store.ChainWork([32]byte{0x01})
		assertChainWorkLocalCorruption(t, work, err)
	})
	t.Run("unreadable_existing_header", func(t *testing.T) {
		store := mustCreateBlockStore(t, filepath.Join(t.TempDir(), "blockstore"))
		hash := [32]byte{0x02}
		if err := os.Mkdir(filepath.Join(store.headersDir, hex.EncodeToString(hash[:])+".bin"), 0o700); err != nil {
			t.Fatalf("Mkdir(header leaf): %v", err)
		}
		work, err := store.ChainWork(hash)
		assertChainWorkLocalCorruption(t, work, err)
		if !strings.Contains(err.Error(), "cannot be read") {
			t.Fatalf("unreadable header diagnostic=%v", err)
		}
	})
	for _, tc := range []struct {
		name string
		at   int
		raw  func(t *testing.T, store *BlockStore, hashes [3][32]byte) []byte
	}{
		{"substituted_head", 2, func(t *testing.T, store *BlockStore, hashes [3][32]byte) []byte {
			return mustGetChainWorkHeader(t, store, hashes[1])
		}},
		{"substituted_middle", 1, func(t *testing.T, store *BlockStore, hashes [3][32]byte) []byte {
			return mustGetChainWorkHeader(t, store, hashes[0])
		}},
		{"short_header", 2, func(t *testing.T, _ *BlockStore, _ [3][32]byte) []byte { return []byte{0x01} }},
		{"long_header", 2, func(t *testing.T, _ *BlockStore, _ [3][32]byte) []byte {
			return make([]byte, consensus.BLOCK_HEADER_BYTES+1)
		}},
		{"dual_invalid_substitution", 2, func(t *testing.T, _ *BlockStore, _ [3][32]byte) []byte {
			raw := testHeaderBytes(0x44, 44)
			clear(raw[76:108])
			return raw
		}},
		{"identity_limited_cycle", 2, func(t *testing.T, store *BlockStore, hashes [3][32]byte) []byte {
			raw := mustGetChainWorkHeader(t, store, hashes[2])
			copy(raw[4:36], hashes[2][:])
			return raw
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, hashes := mustChainWorkTestChain(t)
			path := filepath.Join(store.headersDir, hex.EncodeToString(hashes[tc.at][:])+".bin")
			if err := os.WriteFile(path, tc.raw(t, store, hashes), 0o600); err != nil {
				t.Fatalf("WriteFile(%s): %v", tc.name, err)
			}
			work, err := store.ChainWork(hashes[2])
			assertChainWorkLocalCorruption(t, work, err)
			if tc.name == "dual_invalid_substitution" && (!strings.Contains(err.Error(), "hashes to") || strings.Contains(err.Error(), "target")) {
				t.Fatalf("dual-invalid diagnostic=%v, want identity mismatch before target ownership", err)
			}
		})
	}
	for _, tc := range []struct {
		name   string
		target [32]byte
		limit  [32]byte
	}{
		{"zero_target", [32]byte{}, consensus.POW_LIMIT},
		{"above_pow_limit", [32]byte{31: 2}, [32]byte{31: 1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			previousLimit := consensus.POW_LIMIT
			consensus.POW_LIMIT = tc.limit
			t.Cleanup(func() { consensus.POW_LIMIT = previousLimit })
			store := mustCreateBlockStore(t, filepath.Join(t.TempDir(), "blockstore"))
			var zero [32]byte
			hash := putChainWorkHeader(t, store, 0, zero, 0x61, tc.target)
			work, err := store.ChainWork(hash)
			assertChainWorkLocalCorruption(t, work, err)
		})
	}
	for invalidAt, name := range []string{"rootward", "middle", "tip"} {
		t.Run("failed_segment_does_not_publish_cache_"+name, func(t *testing.T) {
			store := mustCreateBlockStore(t, filepath.Join(t.TempDir(), "blockstore"))
			var zero [32]byte
			root := putChainWorkHeader(t, store, 0, zero, 0x71, consensus.POW_LIMIT)
			if _, err := store.ChainWork(root); err != nil {
				t.Fatalf("ChainWork(root): %v", err)
			}
			var segment [3][32]byte
			prev := root
			for i := range segment {
				target := consensus.POW_LIMIT
				if i == invalidAt {
					target = zero
				}
				segment[i] = putChainWorkHeader(t, store, uint64(i+1), prev, byte(0x72+i), target)
				prev = segment[i]
			}
			work, err := store.ChainWork(segment[2])
			assertChainWorkLocalCorruption(t, work, err)
			if _, ok := store.cachedChainWork(root); !ok {
				t.Fatal("cached ancestor disappeared after failed segment")
			}
			for _, hash := range segment {
				if _, ok := store.cachedChainWork(hash); ok {
					t.Fatalf("failed segment published cache entry for %x", hash)
				}
			}
		})
	}
}

// fresh datadir whose blockstore root does NOT exist yet.
func freshDataDir(t *testing.T) string {
	t.Helper()
	return t.TempDir()
}

// Parity matrix row 1: create with root and chainstate absent commits the tree
// plus the EXACT empty version-1 marker, and the store opens after. Rust mirror:
// `create_store_commits_exact_empty_marker`.
func TestCreateBlockStoreCommitsExactEmptyMarker(t *testing.T) {
	root := BlockStorePath(freshDataDir(t))
	store := mustCreateBlockStore(t, root)
	if got, err := store.CanonicalIndexSnapshot(); err != nil || len(got) != 0 {
		t.Fatalf("canonical snapshot = %v, %v, want empty", got, err)
	}
	for _, sub := range []string{"blocks", "headers", "undo"} {
		if info, err := os.Stat(filepath.Join(root, sub)); err != nil || !info.IsDir() {
			t.Fatalf("%s: info=%v err=%v, want directory", sub, info, err)
		}
	}
	raw, err := os.ReadFile(filepath.Join(root, "index.json")) // #nosec G304 -- test-local path.
	if err != nil {
		t.Fatalf("read marker: %v", err)
	}
	if want := "{\n  \"canonical\": [],\n  \"version\": 1\n}\n"; string(raw) != want {
		t.Fatalf("marker = %q, want %q", raw, want)
	}
	mustOpenBlockStore(t, root)
}

// Parity matrix row 2 + rejected case "create overwrites": an existing root of
// any kind is refused, and a PARTIAL root (no marker yet, i.e. a crash between
// mkdir and the commit) is adopted by neither constructor. Rust mirror:
// `create_store_rejects_existing_and_partial_root`.
func TestCreateBlockStoreRejectsExistingAndPartialRoot(t *testing.T) {
	root := BlockStorePath(freshDataDir(t))
	mustCreateBlockStore(t, root)
	seeded := filepath.Join(root, "blocks", "marker.bin")
	if err := os.WriteFile(seeded, []byte("pre-existing"), 0o600); err != nil {
		t.Fatalf("seed artifact: %v", err)
	}
	if _, err := CreateBlockStore(root); err == nil {
		t.Fatalf("second create must fail")
	}
	if _, err := os.Stat(seeded); err != nil {
		t.Fatalf("existing root must not be overwritten or reset: %v", err)
	}

	partial := BlockStorePath(freshDataDir(t))
	if err := os.Mkdir(partial, 0o700); err != nil {
		t.Fatalf("partial root: %v", err)
	}
	if _, err := CreateBlockStore(partial); err == nil {
		t.Fatalf("no resume of a partial root")
	}
	if _, err := OpenBlockStore(partial); err == nil {
		t.Fatalf("no adoption of a partial root")
	}
}

// Parity matrix rows 6-8: strict open never repairs and never creates. Rust
// mirror: `open_existing_rejects_uninitialized_tree_without_mutating`.
func TestOpenBlockStoreRejectsUninitializedTree(t *testing.T) {
	for _, tc := range []struct {
		name   string
		break_ func(t *testing.T, root string)
	}{
		{"missing_root", func(t *testing.T, root string) { mustRemoveAll(t, root) }},
		{"missing_subdir", func(t *testing.T, root string) { mustRemoveAll(t, filepath.Join(root, "undo")) }},
		{"missing_blocks", func(t *testing.T, root string) { mustRemoveAll(t, filepath.Join(root, "blocks")) }},
		{"missing_headers", func(t *testing.T, root string) { mustRemoveAll(t, filepath.Join(root, "headers")) }},
		{"missing_marker", func(t *testing.T, root string) { mustRemoveAll(t, filepath.Join(root, "index.json")) }},
		{"root_is_file", func(t *testing.T, root string) {
			mustRemoveAll(t, root)
			if err := os.WriteFile(root, []byte("x"), 0o600); err != nil {
				t.Fatalf("root as file: %v", err)
			}
		}},
		{"marker_is_directory", func(t *testing.T, root string) {
			marker := filepath.Join(root, "index.json")
			mustRemoveAll(t, marker)
			if err := os.Mkdir(marker, 0o700); err != nil {
				t.Fatalf("marker as dir: %v", err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := BlockStorePath(freshDataDir(t))
			mustCreateBlockStore(t, root)
			tc.break_(t, root)
			if _, err := OpenBlockStore(root); err == nil {
				t.Fatalf("strict open must reject")
			}
			switch tc.name {
			case "missing_root":
				if _, err := os.Stat(root); !os.IsNotExist(err) {
					t.Fatalf("strict open must not mkdir: %v", err)
				}
			case "missing_marker":
				if _, err := os.Stat(filepath.Join(root, "index.json")); !os.IsNotExist(err) {
					t.Fatalf("strict open must not synthesize a marker: %v", err)
				}
			}
		})
	}
}

func mustRemoveAll(t *testing.T, path string) {
	t.Helper()
	if err := os.RemoveAll(path); err != nil {
		t.Fatalf("remove %s: %v", path, err)
	}
}

// index_marker_validity as an executing table. Rust mirror:
// `open_existing_rejects_malformed_marker_rows` pins the same rows.
func TestOpenBlockStoreRejectsMalformedMarker(t *testing.T) {
	hash := strings.Repeat("a", 64)
	rejected := []struct{ name, body string }{
		{"empty", ""},
		{"not_an_object", "[]"},
		{"missing_version", `{"canonical":[]}`},
		{"missing_canonical", `{"version":1}`},
		{"canonical_null", `{"version":1,"canonical":null}`},
		{"unknown_field", `{"version":1,"canonical":[],"chain_id":"x"}`},
		{"duplicate_version", `{"version":1,"version":1,"canonical":[]}`},
		{"duplicate_canonical", `{"version":1,"canonical":[],"canonical":[]}`},
		{"wrong_version", `{"version":2,"canonical":[]}`},
		{"version_wrong_type", `{"version":"1","canonical":[]}`},
		{"version_non_integer", `{"version":1.0,"canonical":[]}`},
		{"canonical_wrong_type", `{"version":1,"canonical":{}}`},
		{"entry_uppercase", `{"version":1,"canonical":["` + strings.ToUpper(hash) + `"]}`},
		{"entry_short", `{"version":1,"canonical":["ab"]}`},
		{"entry_not_hex", `{"version":1,"canonical":["` + strings.Repeat("z", 64) + `"]}`},
		{"entry_wrong_type", `{"version":1,"canonical":[1]}`},
		{"trailing_value", `{"version":1,"canonical":[]} {"version":1}`},
	}
	root := BlockStorePath(freshDataDir(t))
	mustCreateBlockStore(t, root)
	marker := filepath.Join(root, "index.json")
	for _, tc := range rejected {
		if err := os.WriteFile(marker, []byte(tc.body), 0o600); err != nil {
			t.Fatalf("%s: write marker: %v", tc.name, err)
		}
		if _, err := OpenBlockStore(root); err == nil {
			t.Fatalf("marker row %s must be rejected", tc.name)
		}
	}
	// Accepted rows: the empty marker, and a well-formed lowercase entry in the
	// opposite field order (the Rust writer emits version first).
	for _, tc := range []struct {
		body string
		want int
	}{
		{`{"version":1,"canonical":[]}`, 0},
		{`{"canonical":["` + hash + `"],"version":1}`, 1},
	} {
		if err := os.WriteFile(marker, []byte(tc.body), 0o600); err != nil {
			t.Fatalf("write marker: %v", err)
		}
		store, err := OpenBlockStore(root)
		if err != nil {
			t.Fatalf("%s must be accepted: %v", tc.body, err)
		}
		if got, err := store.CanonicalIndexSnapshot(); err != nil || len(got) != tc.want {
			t.Fatalf("canonical len = %v (%v), want %d", got, err, tc.want)
		}
	}
}

// Rule 10 at the LOADER layer: a missing marker must error even though the tree
// check above it already rejects — no implicit empty index anywhere. Rust mirror:
// `open_existing_marker_loader_never_synthesizes_empty_index`.
func TestLoadBlockStoreIndexNeverSynthesizesEmptyIndex(t *testing.T) {
	root := BlockStorePath(t.TempDir())
	mustCreateBlockStore(t, root)
	marker := filepath.Join(root, "index.json")
	mustRemoveAll(t, marker)
	if _, err := loadBlockStoreIndex(marker); err == nil {
		t.Fatalf("missing marker must not decode as an empty index")
	}
}

// TestBlockStoreReadFileClassBoundsRefuseOverBound pins the bound+1 refusal
// at the two caller paths whose production bounds are cheap to stage — block
// (72MB sparse, the contract-mandated production-scale row) and header
// (117B): the typed errStoreFileTooLarge, never an absent-file default. The
// undo/index/chainstate/verify callers share the same bounded readers at
// hard-wired constants pinned by TestSafeIOClassBoundConstantsPinFrozenValues;
// their at/over verdicts run at small injectable bounds in safeio_test.go
// (RUB-1057 wave-2 de-scaling: no multi-GB or 256MB rows).
func TestBlockStoreReadFileClassBoundsRefuseOverBound(t *testing.T) {
	root := filepath.Join(t.TempDir(), "blockstore")
	store := mustCreateBlockStore(t, root)
	var hash [32]byte
	name := hex.EncodeToString(hash[:])
	createSparseFile(t, filepath.Join(root, "blocks", name+".bin"), blockFileMaxBytes+1)
	if _, err := store.GetBlockByHash(hash); !errors.Is(err, errStoreFileTooLarge) {
		t.Fatalf("block: want errStoreFileTooLarge, got %v", err)
	}
	createSparseFile(t, filepath.Join(root, "headers", name+".bin"), headerFileMaxBytes+1)
	if _, err := store.GetHeaderByHash(hash); !errors.Is(err, errStoreFileTooLarge) {
		t.Fatalf("header: want errStoreFileTooLarge, got %v", err)
	}
}

// TestBlockStoreReadFileClassBoundsAcceptAtBound: a header sized exactly at
// its class bound (116B) reads back byte-complete — the caller-level
// at-bound accept row for the one production bound that is cheap to stage
// (block's accept row reads 72MB in TestReadFileFromDirBlockClassProductionBound;
// the other classes' at/over pairs run at small injectable bounds in
// safeio_test.go, production constants pinned by
// TestSafeIOClassBoundConstantsPinFrozenValues).
func TestBlockStoreReadFileClassBoundsAcceptAtBound(t *testing.T) {
	root := filepath.Join(t.TempDir(), "blockstore")
	store := mustCreateBlockStore(t, root)
	var hash [32]byte
	name := hex.EncodeToString(hash[:])
	createSparseFile(t, filepath.Join(root, "headers", name+".bin"), headerFileMaxBytes)
	if got, err := store.GetHeaderByHash(hash); err != nil || int64(len(got)) != int64(headerFileMaxBytes) {
		t.Fatalf("header at bound: len=%d err=%v", len(got), err)
	}
}

// TestWriteFileIfAbsentVerifyReadBoundedByContentLength pins the RUB-1057
// wave-3 seam semantics on BOTH verify read sites — the fast-path probe and
// the link-EEXIST re-read: an existing destination LARGER than the content
// being written is reported as the pre-existing content-mismatch error (the
// caller-visible taxonomy is identical for every mismatch, whatever the
// existing file's size), and the read never materializes more than
// len(content) bytes, so a corrupt multi-gigabyte file at a small
// destination is never buffered whole. The recorded bound proves the seam
// passes len(content), not a coarse class constant.
func TestWriteFileIfAbsentVerifyReadBoundedByContentLength(t *testing.T) {
	content := []byte("x")
	wantErr := "file already exists with different content"
	for _, tc := range []struct {
		name   string
		eexist bool
	}{
		{"fast_path", false},
		{"link_eexist", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dst := filepath.Join(t.TempDir(), "dst.bin")
			// Far larger than len(content): a whole-file read would allocate it.
			if err := os.WriteFile(dst, bytes.Repeat([]byte{0xa5}, 4096), 0o600); err != nil {
				t.Fatalf("seed: %v", err)
			}
			prev := readFileByPathFn
			t.Cleanup(func() { readFileByPathFn = prev })
			var bounds []int64
			skipFirst := tc.eexist
			readFileByPathFn = func(path string, maxBytes int64) ([]byte, error) {
				if skipFirst {
					skipFirst = false
					return nil, os.ErrNotExist
				}
				bounds = append(bounds, maxBytes)
				got, err := readFileByPathCapped(path, maxBytes)
				if int64(len(got)) > maxBytes {
					t.Fatalf("verify read materialized %d bytes, bound %d", len(got), maxBytes)
				}
				return got, err
			}
			err := writeFileIfAbsent(dst, content)
			if err == nil || !strings.Contains(err.Error(), wantErr) {
				t.Fatalf("want content-mismatch error, got %v", err)
			}
			if errors.Is(err, errStoreFileTooLarge) {
				t.Fatalf("size refusal leaked into the caller taxonomy: %v", err)
			}
			if len(bounds) != 1 || bounds[0] != int64(len(content)) {
				t.Fatalf("verify read bounds = %v, want [%d]", bounds, len(content))
			}
		})
	}
}

// ---------------------------------------------------------------------------
// undo_envelope_v1 (RUB-1132)
// ---------------------------------------------------------------------------

const undoIntegrityFixturePath = "../../../conformance/fixtures/protocol/undo_integrity_v1.json"

type undoIntegrityVector struct {
	ID          string `json:"id"`
	BlockHash   string `json:"block_hash"`
	PayloadJSON string `json:"payload_json"`
	PayloadB64  string `json:"payload_b64"`
	Checksum    string `json:"checksum"`
	Envelope    string `json:"envelope"`
}

func loadUndoIntegrityVectors(t *testing.T) []undoIntegrityVector {
	t.Helper()
	raw, err := os.ReadFile(undoIntegrityFixturePath)
	if err != nil {
		t.Fatalf("read shared undo fixture: %v", err)
	}
	var fixture struct {
		Cases []undoIntegrityVector `json:"cases"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatalf("decode shared undo fixture: %v", err)
	}
	// An emptied or renamed fixture must fail loudly rather than let the
	// per-case loop below pass vacuously.
	if len(fixture.Cases) < 3 {
		t.Fatalf("shared undo fixture has %d cases, want at least 3", len(fixture.Cases))
	}
	return fixture.Cases
}

func mustUndoTestHash(t *testing.T, hashHex string) [32]byte {
	t.Helper()
	hash, err := parseHex32("undo test hash", hashHex)
	if err != nil {
		t.Fatalf("parse %q: %v", hashHex, err)
	}
	return hash
}

// TestUndoEnvelopeV1CrossClientVector is the Go half of the cross-client parity
// proof: every byte the Rust client must emit for the same input is pinned in
// conformance/fixtures/protocol/undo_integrity_v1.json, and this test recomputes
// all of them from the payload alone. The Rust half is
// `undo_envelope_v1_cross_client_vector`.
func TestUndoEnvelopeV1CrossClientVector(t *testing.T) {
	store := mustCreateBlockStore(t, filepath.Join(t.TempDir(), "blockstore"))
	for _, vector := range loadUndoIntegrityVectors(t) {
		t.Run(vector.ID, func(t *testing.T) {
			blockHash := mustUndoTestHash(t, vector.BlockHash)
			undo, err := unmarshalBlockUndo([]byte(vector.PayloadJSON))
			if err != nil {
				t.Fatalf("payload_json is not accepted as canonical: %v", err)
			}

			payload, err := marshalBlockUndo(undo)
			if err != nil {
				t.Fatalf("marshalBlockUndo: %v", err)
			}
			if string(payload) != vector.PayloadJSON {
				t.Fatalf("canonical payload = %q, want %q", payload, vector.PayloadJSON)
			}
			if got := base64.StdEncoding.EncodeToString(payload); got != vector.PayloadB64 {
				t.Fatalf("payload_b64 = %q, want %q", got, vector.PayloadB64)
			}
			checksum := undoEnvelopeChecksum(blockHash, payload)
			if got := hex.EncodeToString(checksum[:]); got != vector.Checksum {
				t.Fatalf("checksum = %q, want %q", got, vector.Checksum)
			}
			envelope, err := marshalUndoEnvelope(blockHash, undo)
			if err != nil {
				t.Fatalf("marshalUndoEnvelope: %v", err)
			}
			if string(envelope) != vector.Envelope {
				t.Fatalf("envelope = %q, want %q", envelope, vector.Envelope)
			}
			if !bytes.HasSuffix(envelope, []byte("\n")) || bytes.Count(envelope, []byte("\n")) != 1 {
				t.Fatalf("envelope must carry exactly one trailing LF: %q", envelope)
			}

			decoded, err := unmarshalUndoEnvelope(blockHash, []byte(vector.Envelope))
			if err != nil {
				t.Fatalf("unmarshalUndoEnvelope(pinned bytes): %v", err)
			}
			if !reflect.DeepEqual(decoded, undo) {
				t.Fatalf("round-trip undo = %+v, want %+v", decoded, undo)
			}

			// The pinned bytes must also be what the real store accepts, not
			// only what the codec accepts in isolation.
			if err := os.WriteFile(filepath.Join(store.undoDir, vector.BlockHash+".json"),
				[]byte(vector.Envelope), 0o600); err != nil {
				t.Fatalf("seed undo file: %v", err)
			}
			fromStore, err := store.GetUndo(blockHash)
			if err != nil {
				t.Fatalf("GetUndo(pinned vector): %v", err)
			}
			if !reflect.DeepEqual(fromStore, undo) {
				t.Fatalf("GetUndo = %+v, want %+v", fromStore, undo)
			}
		})
	}
}

// TestUndoEnvelopeBoundDerivation pins the mechanical derivation of the outer
// read bound. The 2 GB-scale rows themselves are not materialized — allocating
// them in a unit test is not proportionate — so the arithmetic that a maximum
// legal payload still fits inside the envelope bound is proven here instead.
func TestUndoEnvelopeBoundDerivation(t *testing.T) {
	empty, err := marshalUndoEnvelope([32]byte{}, &BlockUndo{})
	if err != nil {
		t.Fatalf("marshalUndoEnvelope: %v", err)
	}
	payload, err := marshalBlockUndo(&BlockUndo{})
	if err != nil {
		t.Fatalf("marshalBlockUndo: %v", err)
	}
	frame := len(empty) - len(base64.StdEncoding.EncodeToString(payload))
	if frame != undoEnvelopeFrameBytes {
		t.Fatalf("measured envelope frame = %d bytes, constant says %d", frame, undoEnvelopeFrameBytes)
	}

	base64Len := ((int64(undoFileMaxBytes) + 2) / 3) * 4
	if want := base64Len + int64(undoEnvelopeFrameBytes); want != int64(undoEnvelopeFileMaxBytes) {
		t.Fatalf("envelope bound = %d, derivation says %d", int64(undoEnvelopeFileMaxBytes), want)
	}
	if int64(undoEnvelopeFileMaxBytes) != 2_666_666_857 {
		t.Fatalf("envelope bound = %d, want 2666666857", int64(undoEnvelopeFileMaxBytes))
	}
	// Recorded, not incidental: unlike undoFileMaxBytes this bound is above
	// 2^31, which is why every comparison against it must widen to int64.
	if int64(undoEnvelopeFileMaxBytes) <= 1<<31 {
		t.Fatalf("envelope bound %d no longer exceeds 2^31; revisit the 32-bit note", int64(undoEnvelopeFileMaxBytes))
	}
}

// undoTestUndo is a small non-empty undo: a coinbase row plus one restored
// spend, so a corrupted payload has something to get wrong.
func undoTestUndo() *BlockUndo {
	return &BlockUndo{
		BlockHeight:              7,
		PreviousAlreadyGenerated: 1234,
		Txs: []TxUndo{
			{Spent: []SpentUndo{}},
			{Spent: []SpentUndo{{
				Outpoint: consensus.Outpoint{Txid: [32]byte{0x11}, Vout: 3},
				Entry: consensus.UtxoEntry{
					Value:             99,
					CovenantType:      consensus.COV_TYPE_P2PK,
					CovenantData:      []byte{0xaa, 0xbb},
					CreationHeight:    5,
					CreatedByCoinbase: true,
				},
			}}},
		},
	}
}

func mustMarshalUndoEnvelope(t *testing.T, blockHash [32]byte, undo *BlockUndo) string {
	t.Helper()
	raw, err := marshalUndoEnvelope(blockHash, undo)
	if err != nil {
		t.Fatalf("marshalUndoEnvelope: %v", err)
	}
	return string(raw)
}

// replaceOnce is deliberately strict: a mutation row that silently matched
// nothing would assert against an unmodified envelope and pass for the wrong
// reason.
func replaceOnce(t *testing.T, envelope, old, replacement string) string {
	t.Helper()
	if strings.Count(envelope, old) != 1 {
		t.Fatalf("mutation target %q occurs %d times, want exactly 1", old, strings.Count(envelope, old))
	}
	return strings.Replace(envelope, old, replacement, 1)
}

// TestGetUndoRejectsIntegrityFailures drives every rejected/hostile row of
// RUB-1132 through the real BlockStore.GetUndo entry point. Each row also
// re-reads the file afterwards: a rejection must never rewrite, truncate, or
// heal the record it refused.
func TestGetUndoRejectsIntegrityFailures(t *testing.T) {
	store := mustCreateBlockStore(t, filepath.Join(t.TempDir(), "blockstore"))
	blockHash := [32]byte{0x0a, 0x0b, 0x0c}
	otherHash := [32]byte{0x0d, 0x0e, 0x0f}
	undo := undoTestUndo()

	valid := mustMarshalUndoEnvelope(t, blockHash, undo)
	otherValid := mustMarshalUndoEnvelope(t, otherHash, undo)
	payload, err := marshalBlockUndo(undo)
	if err != nil {
		t.Fatalf("marshalBlockUndo: %v", err)
	}
	payloadB64 := base64.StdEncoding.EncodeToString(payload)

	// A payload that decodes but is not the canonical encoding, carrying a
	// CORRECT checksum: it can only be rejected by a payload check that runs
	// after the checksum compare.
	indented, err := json.MarshalIndent(json.RawMessage(payload), "", "  ")
	if err != nil {
		t.Fatalf("indent payload: %v", err)
	}
	envelopeOver := func(body []byte) string {
		sum := undoEnvelopeChecksum(blockHash, body)
		return fmt.Sprintf("{\"version\":1,\"block_hash\":\"%s\",\"payload_b64\":\"%s\",\"checksum\":\"%s\"}\n",
			hex.EncodeToString(blockHash[:]),
			base64.StdEncoding.EncodeToString(body),
			hex.EncodeToString(sum[:]))
	}

	legacyIndented, err := json.MarshalIndent(json.RawMessage(payload), "", "  ")
	if err != nil {
		t.Fatalf("indent legacy payload: %v", err)
	}

	for _, tc := range []struct {
		name    string
		record  string
		wantErr error  // exact error identity when the message is pinned
		wantMsg string // exact message when pinned
	}{
		{name: "legacy_indented_payload", record: string(legacyIndented) + "\n", wantErr: errUndoLegacyRecord, wantMsg: errUndoLegacyRecord.Error()},
		{name: "legacy_compact_payload", record: string(payload), wantErr: errUndoLegacyRecord, wantMsg: errUndoLegacyRecord.Error()},
		{name: "version_zero", record: replaceOnce(t, valid, `"version":1`, `"version":0`)},
		{name: "version_two", record: replaceOnce(t, valid, `"version":1`, `"version":2`)},
		{name: "version_string", record: replaceOnce(t, valid, `"version":1`, `"version":"1"`)},
		{name: "version_null", record: replaceOnce(t, valid, `"version":1`, `"version":null`)},
		{name: "version_float", record: replaceOnce(t, valid, `"version":1`, `"version":1.0`)},
		{name: "missing_checksum", record: replaceOnce(t, valid, `,"checksum":"`+valid[strings.Index(valid, `"checksum":"`)+12:strings.LastIndex(valid, `"}`)]+`"`, "")},
		{name: "unknown_field", record: replaceOnce(t, valid, `{"version":1`, `{"note":"x","version":1`)},
		{name: "duplicate_checksum_identical", record: replaceOnce(t, valid, `{"version":1`, `{"checksum":"`+strings.TrimSuffix(valid[strings.Index(valid, `"checksum":"`)+12:], "\"}\n")+`","version":1`)},
		{name: "duplicate_checksum_conflicting", record: replaceOnce(t, valid, `{"version":1`, `{"checksum":"`+strings.Repeat("00", 32)+`","version":1`)},
		{name: "duplicate_payload_conflicting", record: replaceOnce(t, valid, `{"version":1`, `{"payload_b64":"AA==","version":1`)},
		{name: "null_payload", record: replaceOnce(t, valid, `"payload_b64":"`+payloadB64+`"`, `"payload_b64":null`)},
		{name: "trailing_json_value", record: strings.TrimSuffix(valid, "\n") + "{}\n"},
		{name: "trailing_scalar", record: strings.TrimSuffix(valid, "\n") + " 1\n"},
		{name: "not_an_object", record: "[]\n"},
		{name: "not_json", record: "definitely not json\n"},
		{
			name:   "uppercase_block_hash",
			record: replaceOnce(t, valid, hex.EncodeToString(blockHash[:]), strings.ToUpper(hex.EncodeToString(blockHash[:]))),
		},
		{name: "base64_embedded_newline", record: replaceOnce(t, valid, payloadB64, payloadB64[:4]+`\n`+payloadB64[4:])},
		{name: "base64_unpadded", record: replaceOnce(t, valid, payloadB64, strings.TrimRight(payloadB64, "="))},
		{name: "base64_bad_symbol", record: replaceOnce(t, valid, payloadB64, "*"+payloadB64[1:])},
		{
			name:    "flip_one_base64_char",
			record:  replaceOnce(t, valid, payloadB64, flipBase64Symbol(payloadB64)),
			wantErr: errUndoChecksumMismatch, wantMsg: errUndoChecksumMismatch.Error(),
		},
		{
			name:    "foreign_block_hash_field",
			record:  replaceOnce(t, valid, hex.EncodeToString(blockHash[:]), hex.EncodeToString(otherHash[:])),
			wantErr: errUndoBlockHashMismatch, wantMsg: errUndoBlockHashMismatch.Error(),
		},
		{
			name:    "envelope_swapped_between_files",
			record:  otherValid,
			wantErr: errUndoBlockHashMismatch, wantMsg: errUndoBlockHashMismatch.Error(),
		},
		{
			name: "checksum_computed_for_other_block",
			record: replaceOnce(t, otherValid, hex.EncodeToString(otherHash[:]),
				hex.EncodeToString(blockHash[:])),
			wantErr: errUndoChecksumMismatch, wantMsg: errUndoChecksumMismatch.Error(),
		},
		// The two rows below carry a CORRECT checksum, so reaching a rejection
		// at all proves the payload decode runs strictly after the checksum.
		{name: "checksum_valid_over_indented_payload", record: envelopeOver(indented)},
		{name: "checksum_valid_over_null_txs", record: envelopeOver([]byte(`{"block_height":0,"previous_already_generated":0,"txs":null}`))},
		{name: "checksum_valid_over_unknown_payload_field", record: envelopeOver([]byte(`{"block_height":0,"previous_already_generated":0,"txs":[],"x":1}`))},
		{name: "checksum_valid_over_missing_payload_field", record: envelopeOver([]byte(`{"block_height":0,"txs":[]}`))},
		{name: "checksum_valid_over_duplicate_payload_field", record: envelopeOver([]byte(`{"block_height":0,"block_height":1,"previous_already_generated":0,"txs":[]}`))},
		{name: "checksum_valid_over_uppercase_txid", record: envelopeOver([]byte(`{"block_height":0,"previous_already_generated":0,"txs":[{"spent":[{"txid":"` + strings.Repeat("AB", 32) + `","vout":0,"value":0,"covenant_type":0,"covenant_data":"","creation_height":0,"created_by_coinbase":false}]}]}`))},
		{name: "checksum_valid_over_short_txid", record: envelopeOver([]byte(`{"block_height":0,"previous_already_generated":0,"txs":[{"spent":[{"txid":"aabb","vout":0,"value":0,"covenant_type":0,"covenant_data":"","creation_height":0,"created_by_coinbase":false}]}]}`))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(store.undoDir, hex.EncodeToString(blockHash[:])+".json")
			if err := os.WriteFile(path, []byte(tc.record), 0o600); err != nil {
				t.Fatalf("seed record: %v", err)
			}
			got, err := store.GetUndo(blockHash)
			if err == nil {
				t.Fatalf("GetUndo accepted %s: %+v", tc.name, got)
			}
			if got != nil {
				t.Fatalf("GetUndo returned an undo alongside its error: %+v", got)
			}
			t.Logf("rejected with: %v", err)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err = %v, want errors.Is %v", err, tc.wantErr)
				}
				if err.Error() != tc.wantMsg {
					t.Fatalf("message = %q, want exactly %q", err.Error(), tc.wantMsg)
				}
			}
			if tc.wantErr == nil && strings.HasPrefix(tc.name, "checksum_valid_over_") {
				// Payload-class failure: it must NOT be reported as a checksum
				// or hash failure, which is what proves the ordering.
				if errors.Is(err, errUndoChecksumMismatch) || errors.Is(err, errUndoBlockHashMismatch) {
					t.Fatalf("payload defect misreported as an envelope failure: %v", err)
				}
			} else if tc.wantErr == nil && !errors.Is(err, ErrUndoIntegrity) {
				t.Fatalf("err = %v, want errors.Is ErrUndoIntegrity", err)
			}

			after, readErr := os.ReadFile(path)
			if readErr != nil {
				t.Fatalf("re-read refused record: %v", readErr)
			}
			if string(after) != tc.record {
				t.Fatalf("refused record was rewritten on disk")
			}
			// PutUndo must not launder a corrupt record into a valid one.
			if err := store.PutUndo(blockHash, undo); err == nil {
				t.Fatalf("PutUndo overwrote an existing corrupt record")
			}
			healed, readErr := os.ReadFile(path)
			if readErr != nil || string(healed) != tc.record {
				t.Fatalf("PutUndo healed the corrupt record (err=%v)", readErr)
			}
		})
	}
}

// flipBase64Symbol changes one interior symbol to a different valid one, so the
// result is still canonical base64 of the same length and fails at the checksum
// rather than at the encoding check.
func flipBase64Symbol(value string) string {
	replacement := byte('A')
	if value[1] == 'A' {
		replacement = 'B'
	}
	return value[:1] + string(replacement) + value[2:]
}

// corruptStoredUndoChecksum flips one interior base64 symbol of a stored undo
// record: the file stays well-formed JSON and canonical base64, the payload
// still decodes, and only the checksum comparison can catch it. That is the
// hostile row the disconnect and reorg tests drive through their public entry
// points. Returns the corrupted bytes (so a caller can prove a refusal did not
// rewrite them) and the original bytes (so a caller can restore them and prove
// the same path accepts a valid v1 record).
func corruptStoredUndoChecksum(t *testing.T, store *BlockStore, blockHash [32]byte) (corrupt, original []byte) {
	t.Helper()
	path := filepath.Join(store.undoDir, hex.EncodeToString(blockHash[:])+".json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read stored undo: %v", err)
	}
	var envelope undoEnvelopeDisk
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatalf("stored undo is not a v1 envelope: %v", err)
	}
	corrupted := strings.Replace(string(raw), envelope.PayloadB64, flipBase64Symbol(envelope.PayloadB64), 1)
	if corrupted == string(raw) {
		t.Fatal("undo corruption was a no-op")
	}
	if err := os.WriteFile(path, []byte(corrupted), 0o600); err != nil {
		t.Fatalf("write corrupted undo: %v", err)
	}
	return []byte(corrupted), raw
}

// restoreStoredUndo puts back bytes captured by corruptStoredUndoChecksum.
func restoreStoredUndo(t *testing.T, store *BlockStore, blockHash [32]byte, original []byte) {
	t.Helper()
	path := filepath.Join(store.undoDir, hex.EncodeToString(blockHash[:])+".json")
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatalf("restore undo: %v", err)
	}
}
