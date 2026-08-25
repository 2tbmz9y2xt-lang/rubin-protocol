package node

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

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
	// RUB-1134: the marker is the frame over the UNCHANGED inner payload; the
	// literal below is the cross-client vector
	// `blockstore_index_empty_marker_payload`, so this row doubles as its
	// on-disk pin.
	want := `{"version":1,"payload_b64":"ewogICJjYW5vbmljYWwiOiBbXSwKICAidmVyc2lvbiI6IDEKfQo=",` +
		`"checksum":"7c120c21bc3ffdda6482c8d18a3c669542e89d8500928ce166700a7c7a40fe15"}` + "\n"
	if string(raw) != want {
		t.Fatalf("marker = %q, want %q", raw, want)
	}
	payload, err := openStoreEnvelope(storeEnvelopeBlockIndex, raw)
	if err != nil {
		t.Fatalf("open marker envelope: %v", err)
	}
	if wantPayload := "{\n  \"canonical\": [],\n  \"version\": 1\n}\n"; string(payload) != wantPayload {
		t.Fatalf("marker payload = %q, want %q", payload, wantPayload)
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
	// RUB-1134: every row is planted INSIDE a valid frame, so this table keeps
	// testing the inner marker schema; frame-level rejection is pinned by
	// TestBlockstoreIndexRejectsIntegrityFailures.
	writeEnvelopedMarker := func(t *testing.T, body string) {
		t.Helper()
		raw, err := marshalStoreEnvelope(storeEnvelopeBlockIndex, []byte(body))
		if err != nil {
			t.Fatalf("wrap marker: %v", err)
		}
		if err := os.WriteFile(marker, raw, 0o600); err != nil {
			t.Fatalf("write marker: %v", err)
		}
	}
	for _, tc := range rejected {
		writeEnvelopedMarker(t, tc.body)
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
		writeEnvelopedMarker(t, tc.body)
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
	if _, _, err := loadBlockStoreIndex(marker); err == nil {
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
	Note        string `json:"note"`
	BlockHash   string `json:"block_hash"`
	PayloadJSON string `json:"payload_json"`
	PayloadB64  string `json:"payload_b64"`
	Checksum    string `json:"checksum"`
	Envelope    string `json:"envelope"`
}

const undoIntegrityV2FixturePath = "../../../conformance/fixtures/protocol/undo_integrity_v2.json"

type undoIntegrityV2Fixture struct {
	ContractVersion     uint32                `json:"contract_version"`
	FixtureKind         string                `json:"fixture_kind"`
	Description         string                `json:"description"`
	ChecksumDomainASCII string                `json:"checksum_domain_ascii"`
	EnvelopeVersion     uint32                `json:"envelope_version"`
	Cases               []undoIntegrityVector `json:"cases"`
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

func loadUndoIntegrityV2Vectors(t *testing.T) []undoIntegrityVector {
	t.Helper()
	raw, err := os.ReadFile(undoIntegrityV2FixturePath)
	if err != nil {
		t.Fatalf("read shared undo v2 fixture: %v", err)
	}
	var fixture undoIntegrityV2Fixture
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&fixture); err != nil {
		t.Fatalf("decode shared undo v2 fixture: %v", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		t.Fatalf("decode shared undo v2 fixture trailing content: %v", err)
	}
	if fixture.ContractVersion != 1 || fixture.FixtureKind != "undo_integrity_v2" ||
		fixture.ChecksumDomainASCII != undoEnvelopeDomainV2 || fixture.EnvelopeVersion != undoEnvelopeVersion ||
		fixture.Description == "" {
		t.Fatalf("shared undo v2 fixture metadata = version %d kind %q domain %q envelope %d description_empty=%t",
			fixture.ContractVersion, fixture.FixtureKind, fixture.ChecksumDomainASCII,
			fixture.EnvelopeVersion, fixture.Description == "")
	}
	wantIDs := [...]string{
		"empty-undo-zero-supply",
		"u64-max-supply",
		"above-u64-supply",
		"multi-tx-one-spend",
	}
	if len(fixture.Cases) != len(wantIDs) {
		t.Fatalf("shared undo v2 fixture has %d cases, want exactly %d", len(fixture.Cases), len(wantIDs))
	}
	seenIDs := make(map[string]struct{}, len(fixture.Cases))
	seenHashes := make(map[string]struct{}, len(fixture.Cases))
	for i, vector := range fixture.Cases {
		if vector.ID != wantIDs[i] {
			t.Fatalf("shared undo v2 fixture case %d id = %q, want %q", i, vector.ID, wantIDs[i])
		}
		if _, duplicate := seenIDs[vector.ID]; duplicate {
			t.Fatalf("shared undo v2 fixture duplicate case id %q", vector.ID)
		}
		if _, duplicate := seenHashes[vector.BlockHash]; duplicate {
			t.Fatalf("shared undo v2 fixture duplicate block hash %q", vector.BlockHash)
		}
		if vector.Note == "" || vector.BlockHash == "" || vector.PayloadJSON == "" ||
			vector.PayloadB64 == "" || vector.Checksum == "" || vector.Envelope == "" {
			t.Fatalf("shared undo v2 fixture case %q has an empty required field", vector.ID)
		}
		seenIDs[vector.ID] = struct{}{}
		seenHashes[vector.BlockHash] = struct{}{}
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
			envelope, err := marshalUndoEnvelopeV1(blockHash, undo)
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

// TestUndoEnvelopeV2CrossClientVector pins exact-u128 v2 bytes through the production codec and public store paths.
func TestUndoEnvelopeV2CrossClientVector(t *testing.T) {
	vectors := loadUndoIntegrityV2Vectors(t)
	wantSupplies := [...]consensus.Uint128{
		{},
		consensus.Uint128FromU64(^uint64(0)),
		{Hi: 1},
		{Hi: ^uint64(0), Lo: ^uint64(0)},
	}
	wantTxSpentCounts := [...][]int{
		{},
		{0},
		{0},
		{0, 1},
	}
	var spentTxid [32]byte
	for i := range spentTxid {
		spentTxid[i] = 0x11
	}
	wantSpent := SpentUndo{
		Outpoint: consensus.Outpoint{Txid: spentTxid},
		Entry: consensus.UtxoEntry{
			Value:             4_999_999_000,
			CovenantType:      1,
			CovenantData:      append([]byte{0}, bytes.Repeat([]byte{0x22}, 32)...),
			CreationHeight:    1,
			CreatedByCoinbase: true,
		},
	}
	for i, vector := range vectors {
		t.Run(vector.ID, func(t *testing.T) {
			blockHash := mustUndoTestHash(t, vector.BlockHash)
			undo, err := unmarshalBlockUndoV2([]byte(vector.PayloadJSON))
			if err != nil {
				t.Fatalf("payload_json is not accepted as canonical v2: %v", err)
			}
			if undo.PreviousAlreadyGenerated != wantSupplies[i] {
				t.Fatalf("previous_already_generated = %s, want %s",
					undo.PreviousAlreadyGenerated.String(), wantSupplies[i].String())
			}
			if undo.BlockHeight != uint64(i) {
				t.Fatalf("block height = %d, want %d", undo.BlockHeight, i)
			}
			if len(undo.Txs) != len(wantTxSpentCounts[i]) {
				t.Fatalf("tx undo count = %d, want %d", len(undo.Txs), len(wantTxSpentCounts[i]))
			}
			for txIndex, wantSpentCount := range wantTxSpentCounts[i] {
				if len(undo.Txs[txIndex].Spent) != wantSpentCount {
					t.Fatalf("tx %d spent count = %d, want %d", txIndex, len(undo.Txs[txIndex].Spent), wantSpentCount)
				}
			}
			if vector.ID == "multi-tx-one-spend" && !reflect.DeepEqual(undo.Txs[1].Spent[0], wantSpent) {
				t.Fatalf("full spent entry = %+v, want %+v", undo.Txs[1].Spent[0], wantSpent)
			}
			payload, err := marshalBlockUndoV2(undo)
			if err != nil {
				t.Fatalf("marshalBlockUndoV2: %v", err)
			}
			if string(payload) != vector.PayloadJSON {
				t.Fatalf("canonical v2 payload = %q, want %q", payload, vector.PayloadJSON)
			}
			if got := base64.StdEncoding.EncodeToString(payload); got != vector.PayloadB64 {
				t.Fatalf("payload_b64 = %q, want %q", got, vector.PayloadB64)
			}
			checksum := undoEnvelopeChecksumForVersion(undoEnvelopeVersion, blockHash, payload)
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
				t.Fatalf("unmarshalUndoEnvelope(pinned v2 bytes): %v", err)
			}
			if !reflect.DeepEqual(decoded, undo) {
				t.Fatalf("round-trip undo = %+v, want %+v", decoded, undo)
			}
			readStore := mustCreateBlockStore(t, filepath.Join(t.TempDir(), "read-store"))
			readPath := filepath.Join(readStore.undoDir, vector.BlockHash+".json")
			if err := os.WriteFile(readPath, []byte(vector.Envelope), 0o600); err != nil {
				t.Fatalf("seed pinned v2 undo file: %v", err)
			}
			fromStore, err := readStore.GetUndo(blockHash)
			if err != nil {
				t.Fatalf("GetUndo(pinned v2 vector): %v", err)
			}
			if !reflect.DeepEqual(fromStore, undo) {
				t.Fatalf("GetUndo = %+v, want %+v", fromStore, undo)
			}
			writeStore := mustCreateBlockStore(t, filepath.Join(t.TempDir(), "write-store"))
			if err := writeStore.PutUndo(blockHash, undo); err != nil {
				t.Fatalf("PutUndo(absent v2 vector): %v", err)
			}
			written, err := os.ReadFile(filepath.Join(writeStore.undoDir, vector.BlockHash+".json"))
			if err != nil {
				t.Fatalf("read PutUndo v2 bytes: %v", err)
			}
			if !bytes.Equal(written, []byte(vector.Envelope)) {
				t.Fatalf("PutUndo bytes = %q, want %q", written, vector.Envelope)
			}
		})
	}
}

// TestUndoEnvelopeBoundDerivation pins the bound arithmetic. The two
// multi-gigabyte hostile rows ("maximum legal payload at the bound" and "one
// decoded byte above it") are discharged HERE, by exact derivation rather than
// by materializing ~2 GB in a unit test.
func TestUndoEnvelopeBoundDerivation(t *testing.T) {
	base64Len := func(n int64) int64 { return ((n + 2) / 3) * 4 }

	empty, err := marshalUndoEnvelope([32]byte{}, &BlockUndo{})
	if err != nil {
		t.Fatalf("marshalUndoEnvelope: %v", err)
	}
	payload, err := marshalBlockUndo(&BlockUndo{})
	if err != nil {
		t.Fatalf("marshalBlockUndo: %v", err)
	}
	// The writer's bytes must match the segment constants the reader indexes by.
	if frame := len(empty) - len(base64.StdEncoding.EncodeToString(payload)); frame != undoEnvelopeFrameBytes {
		t.Fatalf("measured envelope frame = %d bytes, constant says %d", frame, undoEnvelopeFrameBytes)
	}
	if _, _, _, err := splitUndoEnvelope(empty); err != nil {
		t.Fatalf("writer output does not satisfy the reader layout: %v", err)
	}

	// The envelope reuses the UNCHANGED undo class bound. A future edit that
	// raises it past 2^31-2 breaks readAllCapped's maxBytes+1 probe on a 32-bit
	// build, so this row exists to make that edit fail loudly here first.
	if int64(undoFileMaxBytes) != 2_000_000_000 {
		t.Fatalf("undo class bound = %d, want the unchanged 2000000000", int64(undoFileMaxBytes))
	}
	if int64(undoFileMaxBytes) > 1<<31-2 {
		t.Fatalf("undo class bound %d exceeds 2^31-2; the EOF-probe capacity argument no longer holds",
			int64(undoFileMaxBytes))
	}
	if want := int64(3 * ((undoFileMaxBytes - undoEnvelopeFrameBytes) / 4)); int64(undoPayloadMaxBytes) != want {
		t.Fatalf("payload ceiling = %d, backwards derivation says %d", int64(undoPayloadMaxBytes), want)
	}
	if int64(undoPayloadMaxBytes) != 1_499_999_856 {
		t.Fatalf("payload ceiling = %d, want 1499999856", int64(undoPayloadMaxBytes))
	}
	// The floor must precede the multiply. The naive spelling overshoots by two
	// bytes, and those two bytes are exactly the save/read asymmetry this
	// ceiling exists to close — so pin that it would in fact break.
	naive := int64(undoFileMaxBytes-undoEnvelopeFrameBytes) * 3 / 4
	if naive <= int64(undoPayloadMaxBytes) {
		t.Fatalf("naive ceiling %d no longer overshoots %d; the derivation comment is stale",
			naive, int64(undoPayloadMaxBytes))
	}
	if base64Len(naive)+int64(undoEnvelopeFrameBytes) <= int64(undoFileMaxBytes) {
		t.Fatalf("naive ceiling %d would fit after all; re-derive", naive)
	}

	// The two bound rows, arithmetically: the largest legal payload's complete
	// envelope fits, and one byte more does not.
	atBound := base64Len(int64(undoPayloadMaxBytes)) + int64(undoEnvelopeFrameBytes)
	if atBound != 1_999_999_997 || atBound > int64(undoFileMaxBytes) {
		t.Fatalf("maximum legal payload yields a %d-byte envelope, want exactly 1999999997 within the %d bound",
			atBound, int64(undoFileMaxBytes))
	}
	overBound := base64Len(int64(undoPayloadMaxBytes)+1) + int64(undoEnvelopeFrameBytes)
	if overBound <= int64(undoFileMaxBytes) {
		t.Fatalf("one byte over the payload ceiling still fits in %d bytes; the ceiling is not tight",
			overBound)
	}

	// Save/read symmetry (R3): every pinned fixture payload is far under the
	// ceiling, so the shared vector cannot be invalidated by the bound.
	for _, vector := range loadUndoIntegrityVectors(t) {
		if int64(len(vector.PayloadJSON)) > int64(undoPayloadMaxBytes) {
			t.Fatalf("fixture case %s payload is %d bytes, over the %d ceiling",
				vector.ID, len(vector.PayloadJSON), int64(undoPayloadMaxBytes))
		}
	}
}

func TestUndoEnvelopeV2RoundTripAndChecksumDomain(t *testing.T) {
	blockHash := [32]byte{0x91}
	max := consensus.Uint128{Hi: ^uint64(0), Lo: ^uint64(0)}
	undo := &BlockUndo{BlockHeight: 11, PreviousAlreadyGenerated: max, Txs: []TxUndo{}}
	raw, err := marshalUndoEnvelope(blockHash, undo)
	if err != nil {
		t.Fatalf("marshalUndoEnvelope(v2): %v", err)
	}
	version, _, payloadB64, checksumHex, err := splitUndoEnvelopeVersioned(raw)
	if err != nil {
		t.Fatalf("splitUndoEnvelopeVersioned: %v", err)
	}
	if version != undoEnvelopeVersion || !bytes.HasPrefix(raw, []byte(undoEnvelopePrefixV2)) {
		t.Fatalf("new undo is not v2: %s", raw)
	}
	payload, err := decodeCanonicalBase64(payloadB64)
	if err != nil {
		t.Fatalf("decodeCanonicalBase64: %v", err)
	}
	if !bytes.Contains(payload, []byte(`"previous_already_generated":"340282366920938463463374607431768211455"`)) {
		t.Fatalf("v2 payload supply is not canonical: %s", payload)
	}
	v1Checksum := undoEnvelopeChecksum(blockHash, payload)
	v2Checksum := undoEnvelopeChecksumForVersion(undoEnvelopeVersion, blockHash, payload)
	if v1Checksum == v2Checksum || hex.EncodeToString(v2Checksum[:]) != string(checksumHex) {
		t.Fatalf("checksum domain mismatch: v1=%x v2=%x stored=%s", v1Checksum, v2Checksum, checksumHex)
	}
	decoded, err := unmarshalUndoEnvelope(blockHash, raw)
	if err != nil {
		t.Fatalf("unmarshalUndoEnvelope(v2): %v", err)
	}
	if !reflect.DeepEqual(decoded, undo) {
		t.Fatalf("v2 round trip=%+v, want %+v", decoded, undo)
	}

	store := mustCreateBlockStore(t, filepath.Join(t.TempDir(), "blockstore"))
	if err := store.PutUndo(blockHash, undo); err != nil {
		t.Fatalf("PutUndo(v2): %v", err)
	}
	fromStore, err := store.GetUndo(blockHash)
	if err != nil {
		t.Fatalf("GetUndo(v2): %v", err)
	}
	if !reflect.DeepEqual(fromStore, undo) {
		t.Fatalf("stored v2=%+v, want %+v", fromStore, undo)
	}
}

func TestUndoEnvelopeSupplyTypesAndBoundaries(t *testing.T) {
	blockHash := [32]byte{0x92}
	for _, tc := range []struct {
		name    string
		version uint32
		payload string
		want    string
		ok      bool
		value   consensus.Uint128
	}{
		{name: "v1_u64_max", version: 1, payload: `{"block_height":0,"previous_already_generated":18446744073709551615,"txs":[]}`, ok: true, value: consensus.Uint128FromU64(^uint64(0))},
		{name: "v1_string", version: 1, payload: `{"block_height":0,"previous_already_generated":"0","txs":[]}`, want: "decode undo: envelope v1 previous_already_generated must be a nonnegative JSON integer through u64"},
		{name: "v1_negative", version: 1, payload: `{"block_height":0,"previous_already_generated":-1,"txs":[]}`, want: "decode undo: envelope v1 previous_already_generated must be a nonnegative JSON integer through u64"},
		{name: "v1_fraction", version: 1, payload: `{"block_height":0,"previous_already_generated":0.0,"txs":[]}`, want: "decode undo: envelope v1 previous_already_generated must be a nonnegative JSON integer through u64"},
		{name: "v1_overflow", version: 1, payload: `{"block_height":0,"previous_already_generated":18446744073709551616,"txs":[]}`, want: "decode undo: envelope v1 previous_already_generated must be a nonnegative JSON integer through u64"},
		{name: "v1_extreme_exponent", version: 1, payload: `{"block_height":0,"previous_already_generated":1e400,"txs":[]}`, want: "decode undo: envelope v1 previous_already_generated must be a nonnegative JSON integer through u64"},
		{name: "v2_u128_max", version: 2, payload: `{"block_height":0,"previous_already_generated":"340282366920938463463374607431768211455","txs":[]}`, ok: true, value: consensus.Uint128{Hi: ^uint64(0), Lo: ^uint64(0)}},
		{name: "v2_number", version: 2, payload: `{"block_height":0,"previous_already_generated":0,"txs":[]}`, want: "decode undo: envelope v2 previous_already_generated must be a canonical unsigned decimal string within u128"},
		{name: "v2_extreme_number", version: 2, payload: `{"block_height":0,"previous_already_generated":1e400,"txs":[]}`, want: "decode undo: envelope v2 previous_already_generated must be a canonical unsigned decimal string within u128"},
		{name: "v2_extreme_block_height", version: 2, payload: `{"block_height":1e400,"previous_already_generated":0,"txs":[]}`, want: "decode undo: envelope v2 previous_already_generated must be a canonical unsigned decimal string within u128"},
		{name: "v2_null", version: 2, payload: `{"block_height":0,"previous_already_generated":null,"txs":[]}`, want: "decode undo: envelope v2 previous_already_generated must be a canonical unsigned decimal string within u128"},
		{name: "v2_missing", version: 2, payload: `{"block_height":0,"txs":[]}`, want: "decode undo: payload is not the canonical encoding"},
		{name: "v2_leading_zero", version: 2, payload: `{"block_height":0,"previous_already_generated":"00","txs":[]}`, want: "decode undo: envelope v2 previous_already_generated must be a canonical unsigned decimal string within u128"},
		{name: "v2_escaped_zero", version: 2, payload: `{"block_height":0,"previous_already_generated":"\u0030","txs":[]}`, want: "decode undo: envelope v2 previous_already_generated must be a canonical unsigned decimal string within u128"},
		{name: "v2_overflow", version: 2, payload: `{"block_height":0,"previous_already_generated":"340282366920938463463374607431768211456","txs":[]}`, want: "decode undo: envelope v2 previous_already_generated must be a canonical unsigned decimal string within u128"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := marshalUndoEnvelopePayload(t, tc.version, blockHash, []byte(tc.payload))
			got, err := unmarshalUndoEnvelope(blockHash, raw)
			if tc.ok {
				if err != nil || got.PreviousAlreadyGenerated != tc.value {
					t.Fatalf("undo=%+v err=%v, want supply %s", got, err, tc.value.String())
				}
				return
			}
			if err == nil || err.Error() != tc.want {
				t.Fatalf("err=%v, want exactly %q", err, tc.want)
			}
			if errors.Is(err, ErrUndoIntegrity) {
				t.Fatalf("checksum-valid payload type error gained UNDO_INTEGRITY: %v", err)
			}
		})
	}
	if _, err := marshalUndoEnvelopeV1(blockHash, &BlockUndo{PreviousAlreadyGenerated: consensus.Uint128{Hi: 1}}); err == nil || err.Error() != "encode undo: envelope v1 previous_already_generated must be a nonnegative JSON integer through u64" {
		t.Fatalf("v1 encode err=%v, want exact encode-side u64 diagnostic", err)
	}
	for _, tc := range []struct {
		name    string
		payload string
	}{
		{name: "v2_duplicate_supply", payload: `{"block_height":0,"previous_already_generated":"0","previous_already_generated":"0","txs":[]}`},
		{name: "v2_trailing_json_content", payload: `{"block_height":0,"previous_already_generated":"0","txs":[]}{}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := marshalUndoEnvelopePayload(t, 2, blockHash, []byte(tc.payload))
			_, err := unmarshalUndoEnvelope(blockHash, raw)
			if err == nil || err.Error() != "decode undo: payload is not the canonical encoding" {
				t.Fatalf("err=%v, want exact canonical-payload rejection", err)
			}
			if errors.Is(err, ErrUndoIntegrity) {
				t.Fatalf("checksum-valid structural payload gained UNDO_INTEGRITY: %v", err)
			}
		})
	}

	payload := []byte(`{"block_height":0,"previous_already_generated":"0","txs":[]}`)
	raw := marshalUndoEnvelopePayload(t, 2, blockHash, payload)
	v1Sum := undoEnvelopeChecksum(blockHash, payload)
	var frame undoEnvelopeDisk
	if err := json.Unmarshal(raw, &frame); err != nil {
		t.Fatalf("decode v2 frame: %v", err)
	}
	frame.Checksum = hex.EncodeToString(v1Sum[:])
	wrongDomain, err := json.Marshal(frame)
	if err != nil {
		t.Fatalf("marshal wrong-domain frame: %v", err)
	}
	wrongDomain = append(wrongDomain, '\n')
	if _, err := unmarshalUndoEnvelope(blockHash, wrongDomain); err == nil || err.Error() != errUndoChecksumMismatch.Error() {
		t.Fatalf("wrong-domain checksum err=%v, want %q", err, errUndoChecksumMismatch.Error())
	}
}

type putUndoScratchWriteFailure struct{}

func (putUndoScratchWriteFailure) Write([]byte) (int, error) { return 0, os.ErrPermission }
func (putUndoScratchWriteFailure) Sync() error               { return nil }
func (putUndoScratchWriteFailure) Close() error              { return nil }
func (putUndoScratchWriteFailure) Chmod(os.FileMode) error   { return nil }

func TestPutUndoPreservesEquivalentExistingV1AndV2Bytes(t *testing.T) {
	store := mustCreateBlockStore(t, filepath.Join(t.TempDir(), "blockstore"))
	for _, tc := range []struct {
		name    string
		version uint32
		hash    [32]byte
		undo    *BlockUndo
	}{
		{name: "v1", version: 1, hash: [32]byte{0xa1}, undo: &BlockUndo{BlockHeight: 1, PreviousAlreadyGenerated: consensus.Uint128FromU64(7), Txs: []TxUndo{}}},
		{name: "v2", version: 2, hash: [32]byte{0xa2}, undo: &BlockUndo{BlockHeight: 2, PreviousAlreadyGenerated: consensus.Uint128{Hi: 1}, Txs: []TxUndo{}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var seeded []byte
			var err error
			if tc.version == 1 {
				seeded, err = marshalUndoEnvelopeV1(tc.hash, tc.undo)
			} else {
				seeded, err = marshalUndoEnvelope(tc.hash, tc.undo)
			}
			if err != nil {
				t.Fatalf("marshal seeded undo: %v", err)
			}
			path := filepath.Join(store.undoDir, hex.EncodeToString(tc.hash[:])+".json")
			if err := os.WriteFile(path, seeded, 0o600); err != nil {
				t.Fatalf("seed undo: %v", err)
			}
			matching := *tc.undo
			matching.Txs = nil
			for _, fault := range []string{"scratch_open", "scratch_write"} {
				t.Run(fault, func(t *testing.T) {
					previous, ops := atomicWriteIO, atomicWriteIO
					t.Cleanup(func() { atomicWriteIO = previous })
					if fault == "scratch_open" {
						ops.openScratch = func(string, int, os.FileMode) (atomicWriteScratchFile, error) { return nil, os.ErrPermission }
					} else {
						ops.openScratch = func(string, int, os.FileMode) (atomicWriteScratchFile, error) {
							return putUndoScratchWriteFailure{}, nil
						}
					}
					atomicWriteIO = ops
					if err := store.PutUndo(tc.hash, &matching); err != nil {
						t.Fatalf("PutUndo(matching): %v", err)
					}
					after, err := os.ReadFile(path)
					if err != nil || !bytes.Equal(after, seeded) {
						t.Fatalf("matching existing bytes changed: err=%v", err)
					}
				})
			}

			different := matching
			different.BlockHeight++
			if err := store.PutUndo(tc.hash, &different); err == nil {
				t.Fatal("PutUndo accepted different semantic content")
			}
			afterDifferent, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(afterDifferent, seeded) {
				t.Fatalf("different existing bytes changed: err=%v", err)
			}

			corrupt := append([]byte(nil), seeded...)
			if corrupt[len(corrupt)-4] == '0' {
				corrupt[len(corrupt)-4] = '1'
			} else {
				corrupt[len(corrupt)-4] = '0'
			}
			if err := os.WriteFile(path, corrupt, 0o600); err != nil {
				t.Fatalf("seed corrupt undo: %v", err)
			}
			if err := store.PutUndo(tc.hash, &matching); err == nil {
				t.Fatal("PutUndo accepted corrupt existing record")
			}
			afterCorrupt, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(afterCorrupt, corrupt) {
				t.Fatalf("corrupt existing bytes changed: err=%v", err)
			}
		})
	}
}

func TestPutUndoRefusesCorruptOrDifferentExistingWithoutRewrite(t *testing.T) {
	store := mustCreateBlockStore(t, filepath.Join(t.TempDir(), "blockstore"))
	hash := [32]byte{0xb3}
	path := filepath.Join(store.undoDir, hex.EncodeToString(hash[:])+".json")
	refused := []byte(`{"version":1,"version":2}` + "\n")
	if err := os.WriteFile(path, refused, 0o600); err != nil {
		t.Fatalf("seed duplicate-version undo: %v", err)
	}
	previous, ops := atomicWriteIO, atomicWriteIO
	t.Cleanup(func() { atomicWriteIO = previous })
	var writes int
	ops.openScratch = func(string, int, os.FileMode) (atomicWriteScratchFile, error) { writes++; return nil, os.ErrPermission }
	ops.link = func(string, string) error { writes++; return os.ErrPermission }
	ops.syncParent = func(string) error { writes++; return os.ErrPermission }
	atomicWriteIO = ops
	err := store.PutUndo(hash, &BlockUndo{BlockHeight: 1, Txs: []TxUndo{}})
	var atomicErr *atomicWriteError
	if !errors.Is(err, ErrUndoIntegrity) || !errors.As(err, &atomicErr) || atomicErr.stage != atomicWriteBeforeNamespaceCommit ||
		atomicErr.destination != path || atomicErr.operation != atomicWriteCreateIfAbsent ||
		atomicErr.primary == nil || atomicErr.primary.Error() != "UNDO_INTEGRITY: envelope is not the canonical encoding" || len(atomicErr.secondary) != 0 {
		t.Fatalf("PutUndo duplicate-version wrapper = %#v", atomicErr)
	}
	if writes != 0 {
		t.Fatalf("PutUndo entered write lane %d times", writes)
	}
	after, readErr := os.ReadFile(path)
	if readErr != nil || !bytes.Equal(after, refused) {
		t.Fatalf("refused existing bytes changed: err=%v", readErr)
	}
}

func marshalUndoEnvelopePayload(t *testing.T, version uint32, blockHash [32]byte, payload []byte) []byte {
	t.Helper()
	checksum := undoEnvelopeChecksumForVersion(version, blockHash, payload)
	raw, err := json.Marshal(undoEnvelopeDisk{
		Version:    version,
		BlockHash:  hex.EncodeToString(blockHash[:]),
		PayloadB64: base64.StdEncoding.EncodeToString(payload),
		Checksum:   hex.EncodeToString(checksum[:]),
	})
	if err != nil {
		t.Fatalf("marshal undo envelope: %v", err)
	}
	return append(raw, '\n')
}

// undoTestUndo is a small non-empty undo: a coinbase row plus one restored
// spend, so a corrupted payload has something to get wrong.
func undoTestUndo() *BlockUndo {
	return &BlockUndo{
		BlockHeight:              7,
		PreviousAlreadyGenerated: consensus.Uint128FromU64(1234),
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
	raw, err := marshalUndoEnvelopeV1(blockHash, undo)
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
	envelopeOverHash := func(version uint32, hash [32]byte, body []byte) string {
		sum := undoEnvelopeChecksumForVersion(version, hash, body)
		return fmt.Sprintf("{\"version\":%d,\"block_hash\":\"%s\",\"payload_b64\":\"%s\",\"checksum\":\"%s\"}\n",
			version,
			hex.EncodeToString(hash[:]),
			base64.StdEncoding.EncodeToString(body),
			hex.EncodeToString(sum[:]))
	}
	envelopeOverVersion := func(version uint32, body []byte) string {
		return envelopeOverHash(version, blockHash, body)
	}
	envelopeOver := func(body []byte) string {
		return envelopeOverVersion(undoEnvelopeVersionV1, body)
	}
	duplicateEnvelope := func(record string) string {
		return replaceOnce(t, record, `{"version":1`, `{"version":1,"version":2`)
	}

	legacyIndented, err := json.MarshalIndent(json.RawMessage(payload), "", "  ")
	if err != nil {
		t.Fatalf("indent legacy payload: %v", err)
	}
	canonicalNestedV1 := []byte(`{"block_height":0,"previous_already_generated":0,"txs":[{"spent":[{"txid":"` + strings.Repeat("11", 32) + `","vout":0,"value":0,"covenant_type":0,"covenant_data":"","creation_height":0,"created_by_coinbase":false}]}]}`)
	canonicalNestedV2 := []byte(`{"block_height":0,"previous_already_generated":"0","txs":[{"spent":[{"txid":"` + strings.Repeat("11", 32) + `","vout":0,"value":0,"covenant_type":0,"covenant_data":"","creation_height":0,"created_by_coinbase":false}]}]}`)
	canonicalPayloadError := "decode undo: payload is not the canonical encoding"
	canonicalEnvelopeError := "UNDO_INTEGRITY: envelope is not the canonical encoding"
	domainPayloadError := "decode undo: txs[0].spent[0] txid/covenant_data must be lowercase hex"

	type undoRejectCase struct {
		name    string
		record  string
		wantErr error  // exact error identity when the message is pinned
		wantMsg string // exact message when pinned
	}
	cases := []undoRejectCase{
		{name: "legacy_indented_payload", record: string(legacyIndented) + "\n", wantErr: errUndoLegacyRecord, wantMsg: errUndoLegacyRecord.Error()},
		{name: "legacy_compact_payload", record: string(payload), wantErr: errUndoLegacyRecord, wantMsg: errUndoLegacyRecord.Error()},
		{name: "version_zero", record: replaceOnce(t, valid, `"version":1`, `"version":0`), wantErr: ErrUndoIntegrity, wantMsg: "UNDO_INTEGRITY: unsupported undo envelope version 0"},
		{name: "version_two", record: replaceOnce(t, valid, `"version":1`, `"version":2`), wantErr: errUndoChecksumMismatch, wantMsg: errUndoChecksumMismatch.Error()},
		{name: "version_string", record: replaceOnce(t, valid, `"version":1`, `"version":"1"`), wantErr: ErrUndoIntegrity, wantMsg: "UNDO_INTEGRITY: undo record is not a single JSON object"},
		{name: "version_null", record: replaceOnce(t, valid, `"version":1`, `"version":null`), wantErr: errUndoLegacyRecord, wantMsg: errUndoLegacyRecord.Error()},
		{name: "version_float", record: replaceOnce(t, valid, `"version":1`, `"version":1.0`), wantErr: ErrUndoIntegrity, wantMsg: "UNDO_INTEGRITY: undo record is not a single JSON object"},
		{name: "duplicate_version_identical", record: `{"version":1,"version":1}` + "\n", wantErr: ErrUndoIntegrity, wantMsg: canonicalEnvelopeError},
		{name: "duplicate_version_supported", record: `{"version":1,"version":2}` + "\n", wantErr: ErrUndoIntegrity, wantMsg: canonicalEnvelopeError},
		{name: "duplicate_version_supported_unsupported", record: `{"version":1,"version":3}` + "\n", wantErr: ErrUndoIntegrity, wantMsg: canonicalEnvelopeError},
		{name: "duplicate_version_unsupported_supported", record: `{"version":3,"version":2}` + "\n", wantErr: ErrUndoIntegrity, wantMsg: canonicalEnvelopeError},
		{name: "duplicate_version_invalid", record: `{"version":"bad","version":null}` + "\n", wantErr: ErrUndoIntegrity, wantMsg: canonicalEnvelopeError},
		{name: "duplicate_version_boolean", record: `{"version":1,"version":true}` + "\n", wantErr: ErrUndoIntegrity, wantMsg: canonicalEnvelopeError},
		{name: "duplicate_version_fractional", record: `{"version":1,"version":1.5}` + "\n", wantErr: ErrUndoIntegrity, wantMsg: canonicalEnvelopeError},
		{name: "duplicate_version_negative", record: `{"version":-1,"version":2}` + "\n", wantErr: ErrUndoIntegrity, wantMsg: canonicalEnvelopeError},
		{name: "duplicate_version_out_of_u32", record: `{"version":4294967296,"version":1}` + "\n", wantErr: ErrUndoIntegrity, wantMsg: canonicalEnvelopeError},
		{name: "duplicate_version_huge_exponent", record: `{"version":1e400,"version":1}` + "\n", wantErr: ErrUndoIntegrity, wantMsg: canonicalEnvelopeError},
		{name: "duplicate_version_huge_exponent_reverse", record: `{"version":1,"version":1e400}` + "\n", wantErr: ErrUndoIntegrity, wantMsg: canonicalEnvelopeError},
		{name: "duplicate_version_escaped_trailing", record: `{"version":"bad","ver\u0073ion":null}{}` + "\n", wantErr: ErrUndoIntegrity, wantMsg: canonicalEnvelopeError},
		{
			name:    "duplicate_version_malformed_tail",
			record:  `{"version":1,"version":2,"x":[}` + "\n",
			wantErr: ErrUndoIntegrity, wantMsg: "UNDO_INTEGRITY: undo record is not a single JSON object",
		},
		{name: "version_case_alias_only", record: `{"Version":1}` + "\n", wantErr: errUndoLegacyRecord, wantMsg: errUndoLegacyRecord.Error()},
		{name: "version_upper_alias_only", record: `{"VERSION":1}` + "\n", wantErr: errUndoLegacyRecord, wantMsg: errUndoLegacyRecord.Error()},
		{name: "version_with_case_alias", record: `{"version":1,"Version":0}` + "\n", wantErr: ErrUndoIntegrity, wantMsg: canonicalEnvelopeError},
		{name: "version_with_bad_case_alias", record: `{"version":1,"Version":"bad"}` + "\n", wantErr: ErrUndoIntegrity, wantMsg: canonicalEnvelopeError},
		{name: "version_null_with_alias", record: `{"version":null,"Version":0}` + "\n", wantErr: ErrUndoIntegrity, wantMsg: canonicalEnvelopeError},
		{name: "version_null_with_non_ascii_near_alias", record: `{"version":null,"ver\u017fion":0}` + "\n", wantErr: errUndoLegacyRecord, wantMsg: errUndoLegacyRecord.Error()},
		{name: "version_invalid_with_alias", record: `{"version":"bad","Version":0}` + "\n", wantErr: ErrUndoIntegrity, wantMsg: canonicalEnvelopeError},
		{name: "version_unsupported_with_alias", record: `{"version":3,"Version":0}` + "\n", wantErr: ErrUndoIntegrity, wantMsg: canonicalEnvelopeError},
		{
			name:    "duplicate_version_wrong_hash",
			record:  duplicateEnvelope(replaceOnce(t, valid, hex.EncodeToString(blockHash[:]), hex.EncodeToString(otherHash[:]))),
			wantErr: ErrUndoIntegrity, wantMsg: canonicalEnvelopeError,
		},
		{
			name:    "duplicate_version_bad_base64",
			record:  duplicateEnvelope(replaceOnce(t, valid, payloadB64, "*"+payloadB64[1:])),
			wantErr: ErrUndoIntegrity, wantMsg: canonicalEnvelopeError,
		},
		{
			name:    "duplicate_version_bad_checksum",
			record:  duplicateEnvelope(replaceOnce(t, valid, valid[len(valid)-67:len(valid)-3], strings.Repeat("00", 32))),
			wantErr: ErrUndoIntegrity, wantMsg: canonicalEnvelopeError,
		},
		{
			name:    "duplicate_version_malformed_payload",
			record:  duplicateEnvelope(envelopeOver([]byte(`{`))),
			wantErr: ErrUndoIntegrity, wantMsg: canonicalEnvelopeError,
		},
		{
			name:    "not_object_array_with_duplicate_version",
			record:  `[{"version":1,"version":2}]` + "\n",
			wantErr: ErrUndoIntegrity, wantMsg: "UNDO_INTEGRITY: undo record is not a single JSON object",
		},
		{name: "missing_checksum", record: replaceOnce(t, valid, `,"checksum":"`+valid[strings.Index(valid, `"checksum":"`)+12:strings.LastIndex(valid, `"}`)]+`"`, "")},
		{name: "unknown_field", record: replaceOnce(t, valid, `{"version":1`, `{"note":"x","version":1`)},
		{name: "duplicate_checksum_identical", record: replaceOnce(t, valid, `{"version":1`, `{"checksum":"`+strings.TrimSuffix(valid[strings.Index(valid, `"checksum":"`)+12:], "\"}\n")+`","version":1`)},
		{name: "duplicate_checksum_conflicting", record: replaceOnce(t, valid, `{"version":1`, `{"checksum":"`+strings.Repeat("00", 32)+`","version":1`)},
		{name: "duplicate_payload_conflicting", record: replaceOnce(t, valid, `{"version":1`, `{"payload_b64":"AA==","version":1`)},
		{name: "null_payload", record: replaceOnce(t, valid, `"payload_b64":"`+payloadB64+`"`, `"payload_b64":null`)},
		{name: "trailing_json_value", record: strings.TrimSuffix(valid, "\n") + "{}\n", wantErr: ErrUndoIntegrity, wantMsg: canonicalEnvelopeError},
		{name: "trailing_scalar", record: strings.TrimSuffix(valid, "\n") + " 1\n", wantErr: ErrUndoIntegrity, wantMsg: canonicalEnvelopeError},
		{name: "not_an_object", record: "[]\n"},
		{name: "not_an_object_1", record: "[1]\n", wantErr: ErrUndoIntegrity, wantMsg: "UNDO_INTEGRITY: undo record is not a single JSON object"},
		{name: "not_an_object_2", record: "[2]\n", wantErr: ErrUndoIntegrity, wantMsg: "UNDO_INTEGRITY: undo record is not a single JSON object"},
		{name: "not_an_object_3", record: "[3]\n", wantErr: ErrUndoIntegrity, wantMsg: "UNDO_INTEGRITY: undo record is not a single JSON object"},
		{name: "not_an_object_null", record: "null\n", wantErr: ErrUndoIntegrity, wantMsg: "UNDO_INTEGRITY: undo record is not a single JSON object"},
		{name: "not_an_object_array_trailing", record: "[1]{}\n", wantErr: ErrUndoIntegrity, wantMsg: "UNDO_INTEGRITY: undo record is not a single JSON object"},
		{name: "not_json", record: "definitely not json\n"},
		{
			// W4 parity row: classification decodes ONE value and ignores what
			// follows, so an unversioned record with trailing garbage still
			// reports the actionable legacy message. Rust classifies identically.
			name:    "legacy_payload_with_trailing_json",
			record:  string(payload) + "{}\n",
			wantErr: errUndoLegacyRecord, wantMsg: errUndoLegacyRecord.Error(),
		},
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
			name: "foreign_block_hash_with_bad_base64",
			record: replaceOnce(t, replaceOnce(t, valid, hex.EncodeToString(blockHash[:]), hex.EncodeToString(otherHash[:])),
				payloadB64, "*"+payloadB64[1:]),
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
		// A correct checksum makes these exact errors prove payload decoding runs later.
		{name: "checksum_valid_over_indented_payload", record: envelopeOver(indented), wantMsg: canonicalPayloadError},
		{name: "checksum_valid_over_null_txs", record: envelopeOver([]byte(`{"block_height":0,"previous_already_generated":0,"txs":null}`)), wantMsg: canonicalPayloadError},
		{name: "checksum_valid_over_unknown_payload_field", record: envelopeOver([]byte(`{"block_height":0,"previous_already_generated":0,"txs":[],"x":1}`)), wantMsg: canonicalPayloadError},
		{name: "checksum_valid_over_missing_payload_field", record: envelopeOver([]byte(`{"block_height":0,"txs":[]}`)), wantMsg: canonicalPayloadError},
		{name: "checksum_valid_over_duplicate_payload_field", record: envelopeOver([]byte(`{"block_height":0,"block_height":1,"previous_already_generated":0,"txs":[]}`)), wantMsg: canonicalPayloadError},
		{name: "checksum_valid_over_nested_unknown_v1", record: envelopeOver([]byte(replaceOnce(t, string(canonicalNestedV1), `"vout":0`, `"extra":0,"vout":0`))), wantMsg: canonicalPayloadError},
		{name: "checksum_valid_over_nested_duplicate_v1", record: envelopeOver([]byte(replaceOnce(t, string(canonicalNestedV1), `"vout":0`, `"vout":0,"vout":0`))), wantMsg: canonicalPayloadError},
		{name: "checksum_valid_over_spent_null_v1", record: envelopeOver([]byte(`{"block_height":0,"previous_already_generated":0,"txs":[{"spent":null}]}`)), wantMsg: canonicalPayloadError},
		{name: "checksum_valid_over_invalid_covenant_data_v1", record: envelopeOver([]byte(replaceOnce(t, string(canonicalNestedV1), `"covenant_data":""`, `"covenant_data":"a"`))), wantMsg: domainPayloadError},
		{name: "checksum_valid_over_invalid_supply_v1", record: envelopeOver([]byte(`{"block_height":0,"previous_already_generated":"0","txs":[]}`)), wantMsg: "decode undo: envelope v1 previous_already_generated must be a nonnegative JSON integer through u64"},
		{name: "checksum_valid_over_negative_supply_v1", record: envelopeOver([]byte(`{"block_height":0,"previous_already_generated":-1,"txs":[]}`)), wantMsg: "decode undo: envelope v1 previous_already_generated must be a nonnegative JSON integer through u64"},
		{name: "checksum_valid_over_fractional_supply_v1", record: envelopeOver([]byte(`{"block_height":0,"previous_already_generated":0.0,"txs":[]}`)), wantMsg: "decode undo: envelope v1 previous_already_generated must be a nonnegative JSON integer through u64"},
		{name: "checksum_valid_over_overflow_supply_v1", record: envelopeOver([]byte(`{"block_height":0,"previous_already_generated":18446744073709551616,"txs":[]}`)), wantMsg: "decode undo: envelope v1 previous_already_generated must be a nonnegative JSON integer through u64"},
		{name: "checksum_valid_over_extreme_supply_v1", record: envelopeOver([]byte(`{"block_height":0,"previous_already_generated":1e400,"txs":[]}`)), wantMsg: "decode undo: envelope v1 previous_already_generated must be a nonnegative JSON integer through u64"},
		{name: "checksum_valid_over_mixed_unknown_invalid_supply_v1", record: envelopeOver([]byte(`{"block_height":0,"previous_already_generated":"0","txs":[],"extra":0}`)), wantMsg: canonicalPayloadError},
		{name: "checksum_valid_over_unknown_payload_field_v2", record: envelopeOverVersion(undoEnvelopeVersion, []byte(`{"block_height":0,"previous_already_generated":"0","txs":[],"x":1}`)), wantMsg: canonicalPayloadError},
		{name: "checksum_valid_over_duplicate_payload_field_v2", record: envelopeOverVersion(undoEnvelopeVersion, []byte(`{"block_height":0,"block_height":1,"previous_already_generated":"0","txs":[]}`)), wantMsg: canonicalPayloadError},
		{name: "checksum_valid_over_nested_unknown_v2", record: envelopeOverVersion(undoEnvelopeVersion, []byte(replaceOnce(t, string(canonicalNestedV2), `"vout":0`, `"extra":0,"vout":0`))), wantMsg: canonicalPayloadError},
		{name: "checksum_valid_over_nested_duplicate_v2", record: envelopeOverVersion(undoEnvelopeVersion, []byte(replaceOnce(t, string(canonicalNestedV2), `"vout":0`, `"vout":0,"vout":0`))), wantMsg: canonicalPayloadError},
		{name: "checksum_valid_over_spent_null_v2", record: envelopeOverVersion(undoEnvelopeVersion, []byte(`{"block_height":0,"previous_already_generated":"0","txs":[{"spent":null}]}`)), wantMsg: canonicalPayloadError},
		{name: "checksum_valid_over_null_block_height_v2", record: envelopeOverVersion(undoEnvelopeVersion, []byte(replaceOnce(t, string(canonicalNestedV2), `"block_height":0`, `"block_height":null`))), wantMsg: canonicalPayloadError},
		{name: "checksum_valid_over_nested_null_txid_v2", record: envelopeOverVersion(undoEnvelopeVersion, []byte(replaceOnce(t, string(canonicalNestedV2), `"txid":"`+strings.Repeat("11", 32)+`"`, `"txid":null`))), wantMsg: canonicalPayloadError},
		{name: "checksum_valid_over_nested_wrong_token_v2", record: envelopeOverVersion(undoEnvelopeVersion, []byte(replaceOnce(t, string(canonicalNestedV2), `"created_by_coinbase":false`, `"created_by_coinbase":0`))), wantMsg: canonicalPayloadError},
		{name: "checksum_valid_over_invalid_supply_nested_null_v2", record: envelopeOverVersion(undoEnvelopeVersion, []byte(replaceOnce(t, replaceOnce(t, string(canonicalNestedV2), `"previous_already_generated":"0"`, `"previous_already_generated":0`), `"txid":"`+strings.Repeat("11", 32)+`"`, `"txid":null`))), wantMsg: "decode undo: envelope v2 previous_already_generated must be a canonical unsigned decimal string within u128"},
		{name: "checksum_valid_over_invalid_covenant_data_v2", record: envelopeOverVersion(undoEnvelopeVersion, []byte(replaceOnce(t, string(canonicalNestedV2), `"covenant_data":""`, `"covenant_data":"a"`))), wantMsg: domainPayloadError},
		{name: "checksum_valid_over_invalid_supply_v2", record: envelopeOverVersion(undoEnvelopeVersion, []byte(`{"block_height":0,"previous_already_generated":0,"txs":[]}`)), wantMsg: "decode undo: envelope v2 previous_already_generated must be a canonical unsigned decimal string within u128"},
		{name: "checksum_valid_over_extreme_supply_v2", record: envelopeOverVersion(undoEnvelopeVersion, []byte(`{"block_height":0,"previous_already_generated":1e400,"txs":[]}`)), wantMsg: "decode undo: envelope v2 previous_already_generated must be a canonical unsigned decimal string within u128"},
		{name: "checksum_valid_over_extreme_block_height_invalid_supply_v2", record: envelopeOverVersion(undoEnvelopeVersion, []byte(`{"block_height":1e400,"previous_already_generated":0,"txs":[]}`)), wantMsg: "decode undo: envelope v2 previous_already_generated must be a canonical unsigned decimal string within u128"},
		{name: "checksum_valid_over_extreme_nested_scalar_invalid_supply_v2", record: envelopeOverVersion(undoEnvelopeVersion, []byte(`{"block_height":0,"previous_already_generated":0,"txs":[{"spent":[{"txid":"`+strings.Repeat("11", 32)+`","vout":4294967296,"value":0,"covenant_type":0,"covenant_data":"","creation_height":0,"created_by_coinbase":false}]}]}`)), wantMsg: "decode undo: envelope v2 previous_already_generated must be a canonical unsigned decimal string within u128"},
		{name: "checksum_valid_over_null_supply_v2", record: envelopeOverVersion(undoEnvelopeVersion, []byte(`{"block_height":0,"previous_already_generated":null,"txs":[]}`)), wantMsg: "decode undo: envelope v2 previous_already_generated must be a canonical unsigned decimal string within u128"},
		{name: "checksum_valid_over_missing_supply_v2", record: envelopeOverVersion(undoEnvelopeVersion, []byte(`{"block_height":0,"txs":[]}`)), wantMsg: canonicalPayloadError},
		{name: "checksum_valid_over_leading_zero_supply_v2", record: envelopeOverVersion(undoEnvelopeVersion, []byte(`{"block_height":0,"previous_already_generated":"00","txs":[]}`)), wantMsg: "decode undo: envelope v2 previous_already_generated must be a canonical unsigned decimal string within u128"},
		{name: "checksum_valid_over_escaped_zero_supply_v2", record: envelopeOverVersion(undoEnvelopeVersion, []byte(`{"block_height":0,"previous_already_generated":"\u0030","txs":[]}`)), wantMsg: "decode undo: envelope v2 previous_already_generated must be a canonical unsigned decimal string within u128"},
		{name: "checksum_valid_over_overflow_supply_v2", record: envelopeOverVersion(undoEnvelopeVersion, []byte(`{"block_height":0,"previous_already_generated":"340282366920938463463374607431768211456","txs":[]}`)), wantMsg: "decode undo: envelope v2 previous_already_generated must be a canonical unsigned decimal string within u128"},
		{name: "checksum_valid_over_reordered_invalid_supply_v2", record: envelopeOverVersion(undoEnvelopeVersion, []byte(`{"txs":[],"previous_already_generated":0,"block_height":0}`)), wantMsg: "decode undo: envelope v2 previous_already_generated must be a canonical unsigned decimal string within u128"},
		{name: "checksum_valid_over_indented_reordered_domain_v2", record: envelopeOverVersion(undoEnvelopeVersion, []byte("{\n  \"txs\": [{\"spent\": [{\"created_by_coinbase\": false, \"creation_height\": 0, \"covenant_data\": \"a\", \"covenant_type\": 0, \"value\": 0, \"vout\": 0, \"txid\": \""+strings.Repeat("11", 32)+"\"}]}],\n  \"previous_already_generated\": \"0\",\n  \"block_height\": 0\n}")), wantMsg: domainPayloadError},
		{name: "checksum_valid_over_indented_reordered_valid_v2", record: envelopeOverVersion(undoEnvelopeVersion, []byte("{\n  \"txs\": [],\n  \"previous_already_generated\": \"0\",\n  \"block_height\": 0\n}")), wantMsg: canonicalPayloadError},
		{name: "checksum_valid_over_mixed_duplicate_invalid_supply_v2", record: envelopeOverVersion(undoEnvelopeVersion, []byte(`{"block_height":0,"previous_already_generated":0,"previous_already_generated":0,"txs":[]}`)), wantMsg: canonicalPayloadError},
		// These two prove the decision precedes conversion: blockUndoFromDisk's
		// own message for a bad txid ("expected 32 bytes, got 2") would WIN if
		// conversion still ran first. Rust emits the identical string.
		{
			name:    "checksum_valid_over_uppercase_txid",
			record:  envelopeOver([]byte(`{"block_height":0,"previous_already_generated":0,"txs":[{"spent":[{"txid":"` + strings.Repeat("AB", 32) + `","vout":0,"value":0,"covenant_type":0,"covenant_data":"","creation_height":0,"created_by_coinbase":false}]}]}`)),
			wantMsg: domainPayloadError,
		},
		{
			name:    "checksum_valid_over_short_txid",
			record:  envelopeOver([]byte(`{"block_height":0,"previous_already_generated":0,"txs":[{"spent":[{"txid":"aabb","vout":0,"value":0,"covenant_type":0,"covenant_data":"","creation_height":0,"created_by_coinbase":false}]}]}`)),
			wantMsg: domainPayloadError,
		},
	}
	invalidNestedV2 := replaceOnce(t, string(canonicalNestedV2), `"previous_already_generated":"0"`, `"previous_already_generated":0`)
	for _, row := range []struct{ name, body string }{
		{name: "checksum_valid_over_missing_block_height_v2", body: strings.Replace(invalidNestedV2, `"block_height":0,`, "", 1)},
		{name: "checksum_valid_over_missing_txs_v2", body: `{"block_height":0,"previous_already_generated":0}`},
		{name: "checksum_valid_over_missing_spent_v2", body: `{"block_height":0,"previous_already_generated":0,"txs":[{}]}`},
		{name: "checksum_valid_over_unknown_tx_invalid_supply_v2", body: `{"block_height":0,"previous_already_generated":0,"txs":[{"spent":[],"extra":0}]}`},
		{name: "checksum_valid_over_duplicate_tx_invalid_supply_v2", body: `{"block_height":0,"previous_already_generated":0,"txs":[{"spent":[],"spent":[]}]}`},
		{name: "checksum_valid_over_nested_unknown_invalid_supply_v2", body: replaceOnce(t, invalidNestedV2, `"vout":0`, `"extra":0,"vout":0`)},
		{name: "checksum_valid_over_nested_duplicate_invalid_supply_v2", body: replaceOnce(t, invalidNestedV2, `"vout":0`, `"vout":0,"vout":0`)},
		{name: "checksum_valid_over_null_txs_invalid_supply_v2", body: `{"block_height":0,"previous_already_generated":0,"txs":null}`},
		{name: "checksum_valid_over_null_spent_invalid_supply_v2", body: `{"block_height":0,"previous_already_generated":0,"txs":[{"spent":null}]}`},
		{name: "checksum_valid_over_trailing_payload_invalid_supply_v2", body: invalidNestedV2 + `{}`},
		{name: "checksum_valid_over_wrong_txs_container_v2", body: `{"block_height":0,"previous_already_generated":0,"txs":{}}`},
		{name: "checksum_valid_over_wrong_tx_item_v2", body: `{"block_height":0,"previous_already_generated":0,"txs":[0]}`},
		{name: "checksum_valid_over_wrong_spent_container_v2", body: `{"block_height":0,"previous_already_generated":0,"txs":[{"spent":{}}]}`},
		{name: "checksum_valid_over_wrong_spent_item_v2", body: `{"block_height":0,"previous_already_generated":0,"txs":[{"spent":[0]}]}`},
	} {
		cases = append(cases, undoRejectCase{name: row.name, record: envelopeOverVersion(undoEnvelopeVersion, []byte(row.body)), wantMsg: canonicalPayloadError})
	}
	for _, field := range []struct{ name, fragment string }{
		{name: "txid", fragment: `"txid":"` + strings.Repeat("11", 32) + `",`},
		{name: "vout", fragment: `"vout":0,`},
		{name: "value", fragment: `"value":0,`},
		{name: "covenant_type", fragment: `"covenant_type":0,`},
		{name: "covenant_data", fragment: `"covenant_data":"",`},
		{name: "creation_height", fragment: `"creation_height":0,`},
		{name: "created_by_coinbase", fragment: `,"created_by_coinbase":false`},
	} {
		body := replaceOnce(t, invalidNestedV2, field.fragment, "")
		cases = append(cases, undoRejectCase{name: "checksum_valid_over_missing_spent_" + field.name + "_v2", record: envelopeOverVersion(undoEnvelopeVersion, []byte(body)), wantMsg: canonicalPayloadError})
	}
	invalidSupply := []byte(`{"block_height":0,"previous_already_generated":0,"txs":[]}`)
	foreignInvalid := envelopeOverHash(undoEnvelopeVersion, otherHash, invalidSupply)
	cases = append(cases,
		undoRejectCase{name: "foreign_hash_valid_checksum_invalid_supply_v2", record: foreignInvalid, wantErr: errUndoBlockHashMismatch, wantMsg: errUndoBlockHashMismatch.Error()},
		undoRejectCase{name: "bad_checksum_invalid_supply_v2", record: replaceOnce(t, foreignInvalid, hex.EncodeToString(otherHash[:]), hex.EncodeToString(blockHash[:])), wantErr: errUndoChecksumMismatch, wantMsg: errUndoChecksumMismatch.Error()},
	)

	for _, tc := range cases {
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
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want errors.Is %v", err, tc.wantErr)
			}
			if tc.wantMsg != "" && err.Error() != tc.wantMsg {
				t.Fatalf("message = %q, want exactly %q", err.Error(), tc.wantMsg)
			}
			if tc.wantErr == nil && strings.HasPrefix(tc.name, "checksum_valid_over_") {
				// These rows carry a CORRECT checksum, so reaching a rejection
				// at all proves the payload decode runs strictly after the
				// checksum compare. The payload-conversion class sits OUTSIDE
				// the UNDO_INTEGRITY identity by contract, so this branch
				// asserts only that the failure is not misreported as one of
				// the envelope classes.
				if errors.Is(err, ErrUndoIntegrity) {
					t.Fatalf("payload defect gained UNDO_INTEGRITY: %v", err)
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
// the same path accepts the original valid record).
func corruptStoredUndoChecksum(t *testing.T, store *BlockStore, blockHash [32]byte) (corrupt, original []byte) {
	t.Helper()
	path := filepath.Join(store.undoDir, hex.EncodeToString(blockHash[:])+".json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read stored undo: %v", err)
	}
	var envelope undoEnvelopeDisk
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatalf("stored undo is not a versioned envelope: %v", err)
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

// ---------------------------------------------------------------------------
// RUB-890: prepared canonical-index commit and strict block presence.
// The primitive is package-private and has NO production caller in this slice;
// these tests are its only drivers. Several replace package-level seams
// (writeFileAtomicFn, loadBlockStoreIndexFn, atomicWriteIO): none may call t.Parallel.
// ---------------------------------------------------------------------------

// canonicalIndexRow returns a deterministic, canonically-spelled index row.
func canonicalIndexRow(seed byte) string {
	var hash [32]byte
	hash[0] = seed
	hash[31] = seed
	return hex.EncodeToString(hash[:])
}

func canonicalIndexRowHash(t *testing.T, row string) [32]byte {
	t.Helper()
	hash, err := parseHex32("row", row)
	if err != nil {
		t.Fatalf("parseHex32(%q): %v", row, err)
	}
	return hash
}

// canonicalRAMImage is the complete published image a reader can observe. Every
// field is compared by CONTENT (reflect.DeepEqual), so a replacement that keeps
// the sizes but changes an entry is still a change.
type canonicalRAMImage struct {
	canonical []string
	heights   map[[32]byte]uint64
	indexRaw  []byte
	chainWork map[[32]byte]*big.Int
}

func captureCanonicalRAMImage(store *BlockStore) canonicalRAMImage {
	store.stateMu.RLock()
	defer store.stateMu.RUnlock()
	return canonicalRAMImage{
		canonical: append([]string(nil), store.index.Canonical...),
		heights:   maps.Clone(store.canonicalHeightByHash),
		indexRaw:  append([]byte(nil), store.indexRaw...),
		chainWork: maps.Clone(store.chainWorkByHash),
	}
}

func mustReadIndexFile(t *testing.T, store *BlockStore) []byte {
	t.Helper()
	raw, err := os.ReadFile(store.indexPath) // #nosec G304 -- test-local path.
	if err != nil {
		t.Fatalf("read index file: %v", err)
	}
	return raw
}

func withWriteFileAtomicFn(t *testing.T, fn func(string, []byte, os.FileMode) error) {
	t.Helper()
	previous := writeFileAtomicFn
	writeFileAtomicFn = fn
	t.Cleanup(func() { writeFileAtomicFn = previous })
}

// spawnReaders runs step in n goroutines until the test body returns; step
// returns false to stop its own goroutine. The cleanups are registered BEFORE
// the goroutines start and in LIFO order (close, then wait), so no failure path
// can leave a reader running past the test.
func spawnReaders(t *testing.T, n int, step func() bool) {
	t.Helper()
	var wg sync.WaitGroup
	stop := make(chan struct{})
	t.Cleanup(wg.Wait)
	t.Cleanup(func() { close(stop) })
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				if !step() {
					return
				}
			}
		}()
	}
}

func mustPrepareCanonicalIndex(t *testing.T, store *BlockStore, next []string) *preparedCanonicalIndex {
	t.Helper()
	prepared, err := prepareCanonicalIndex(store.visibleIndexBytes(), next)
	if err != nil {
		t.Fatalf("prepareCanonicalIndex(%v): %v", next, err)
	}
	return prepared
}

func mustCommitCanonicalIndex(t *testing.T, store *BlockStore, next []string) {
	t.Helper()
	prepared := mustPrepareCanonicalIndex(t, store, next)
	if got := prepared.commit(store); got.class != canonicalCommitted {
		t.Fatalf("commit(%v) = %s (%v), want COMMITTED", next, got.class, got.err)
	}
}

// assertPublishedCanonicalImage proves the prepared image is the live one in
// every place a reader can look: the index list, the height-by-hash map, the
// visible-identity bytes, the reset chain-work cache, and the disk.
func assertPublishedCanonicalImage(t *testing.T, store *BlockStore, want []string, wantRaw []byte) {
	t.Helper()
	got := captureCanonicalRAMImage(store)
	if !slices.Equal(got.canonical, want) {
		t.Fatalf("published canonical = %v, want %v", got.canonical, want)
	}
	if len(got.heights) != len(want) {
		t.Fatalf("published height map has %d entries, want %d", len(got.heights), len(want))
	}
	for height, row := range want {
		hash := canonicalIndexRowHash(t, row)
		if gotHeight, ok := got.heights[hash]; !ok || gotHeight != uint64(height) {
			t.Fatalf("height map[%x] = (%d,%v), want (%d,true)", hash, gotHeight, ok, height)
		}
	}
	if !bytes.Equal(got.indexRaw, wantRaw) {
		t.Fatalf("published visible identity is not the committed bytes")
	}
	// Every carried entry must name a row of THIS identity; whether a given row
	// was cached at all is the caller's row to assert.
	for hash := range got.chainWork {
		if _, planned := got.heights[hash]; !planned {
			t.Fatalf("published image carried chain work for %x, which this identity does not contain", hash)
		}
	}
	if disk := mustReadIndexFile(t, store); !bytes.Equal(disk, wantRaw) {
		t.Fatalf("on-disk index is not the committed bytes")
	}
}

func assertCanonicalRAMUnchanged(t *testing.T, store *BlockStore, want canonicalRAMImage, context string) {
	t.Helper()
	if got := captureCanonicalRAMImage(store); !reflect.DeepEqual(got, want) {
		t.Fatalf("%s: RAM image changed\n got=%+v\nwant=%+v", context, got, want)
	}
}

// TestPreparedCanonicalIndexAcceptedTransitions drives the accepted set through
// the primitive: the empty-store identity, genesis index, one-entry append and reorg
// replacement list, each followed by a restart that REOPENS THE COMMITTED INDEX BYTES
// (the artifacts behind the rows are the startup scan's business, not this
// primitive's). Every subtest owns its store and establishes its own precondition, so
// `-run .../genesis_index` alone proves the same thing the full run does.
func TestPreparedCanonicalIndexAcceptedTransitions(t *testing.T) {
	row0, row1, row1b := canonicalIndexRow(0x10), canonicalIndexRow(0x11), canonicalIndexRow(0x12)

	for _, tc := range []struct {
		name string
		seed []string
		next []string
	}{
		// The empty-store identity is committable, but only as a real
		// transition: preparing it against an already-empty visible index is
		// the refused no-op (RejectsInvalidNextList/no_op).
		{name: "empty_store", seed: []string{row0}, next: []string{}},
		{name: "genesis_index", next: []string{row0}},
		{name: "one_entry_append", seed: []string{row0}, next: []string{row0, row1}},
		{name: "reorg_replacement_list", seed: []string{row0, row1}, next: []string{row0, row1b}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := BlockStorePath(t.TempDir())
			store := mustCreateBlockStore(t, root)
			if tc.seed != nil {
				mustCommitCanonicalIndex(t, store, tc.seed)
			}
			// Seed the derived chain-work cache. Publication installs the image
			// built under the store lock before the write: the cached entries
			// whose hashes the PLANNED identity still contains, and nothing else.
			// Work derived under the old index for a row this identity drops must
			// not survive, because cachedChainWork answers without re-checking
			// canonical membership.
			seeded := canonicalIndexRowHash(t, row0)
			store.stateMu.Lock()
			store.chainWorkByHash[seeded] = big.NewInt(7)
			store.stateMu.Unlock()

			mustCommitCanonicalIndex(t, store, tc.next)
			store.stateMu.RLock()
			carried, present := store.chainWorkByHash[seeded]
			carriedCount := len(store.chainWorkByHash)
			store.stateMu.RUnlock()
			stillCanonical := slices.Contains(tc.next, row0)
			if present != stillCanonical || (present && carried.String() != "7") {
				t.Fatalf("seeded row carried=%v(%v) still_canonical=%v", present, carried, stillCanonical)
			}
			if carriedCount > len(tc.next) {
				t.Fatalf("carried %d entries for a %d-row identity", carriedCount, len(tc.next))
			}
			// A LITERAL fixture from the row list, never the image's own field (x == x).
			wantRaw := mustEncodeCanonicalIndex(t, tc.next)
			assertPublishedCanonicalImage(t, store, tc.next, wantRaw)

			// Restart from the committed canonical index.
			reopened := mustOpenBlockStore(t, root)
			assertPublishedCanonicalImage(t, reopened, tc.next, wantRaw)
			_, _, ok, err := reopened.Tip()
			if err != nil || ok != (len(tc.next) > 0) {
				t.Fatalf("restart tip: ok=%v err=%v", ok, err)
			}
		})
	}
}

// TestPreparedCanonicalIndexRejectsInvalidNextList: preparation validates the
// COMPLETE list with the same strictness the on-disk decode uses, before any
// image exists to commit. parseHex alone would take the uppercase row.
func TestPreparedCanonicalIndexRejectsInvalidNextList(t *testing.T) {
	store := mustCreateBlockStore(t, BlockStorePath(t.TempDir()))
	before, diskBefore := captureCanonicalRAMImage(store), mustReadIndexFile(t, store)

	// Exactly 64 characters, so a length check alone would let it through; the
	// char-class rule is what rejects the spaces. It is not an independent
	// killer — trimmed it is 62 hex characters, so parseHex32 would refuse it
	// too. uppercase_hex is the row only the case rule kills.
	padded := " " + canonicalIndexRow(0x01)[1:63] + " "
	if len(padded) != 64 {
		t.Fatalf("padded row is %d characters, want 64", len(padded))
	}

	for _, tc := range []struct {
		name string
		next []string
		// wantIs is the typed refusal, where the caller has to tell this
		// rejection from the others without matching on message text.
		wantIs error
	}{
		{name: "nil_canonical"},
		{name: "uppercase_hex", next: []string{strings.ToUpper(canonicalIndexRow(0xab))}},
		{name: "short_hex", next: []string{"00"}},
		{name: "non_hex", next: []string{strings.Repeat("z", 64)}},
		{name: "padded_hex", next: []string{padded}},
		// A repeated row would silently collapse the height-by-hash map.
		{name: "duplicate_row", next: []string{canonicalIndexRow(0x02), canonicalIndexRow(0x02)}, wantIs: errCanonicalIndexDuplicateRow},
		// The identical image: a post-commit ambiguity would classify it as
		// TERMINAL_PERSISTENCE(old) and publish nothing, while the success
		// path publishes — one transition with two different RAM outcomes. It
		// is a benign no-op, so its own sentinel keeps it apart from an
		// invalid plan.
		{name: "no_op", next: []string{}, wantIs: errCanonicalIndexNoOp},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := prepareCanonicalIndex(store.visibleIndexBytes(), tc.next)
			if err == nil {
				t.Fatalf("prepare accepted %q", tc.next)
			}
			if tc.wantIs != nil && !errors.Is(err, tc.wantIs) {
				t.Fatalf("prepare err = %v, want it to carry %v", err, tc.wantIs)
			}
		})
	}
	assertCanonicalRAMUnchanged(t, store, before, "rejected preparation")
	if !bytes.Equal(mustReadIndexFile(t, store), diskBefore) {
		t.Fatalf("rejected preparation touched the disk")
	}
}

// TestPreparedCanonicalIndexPrecommitAndStaleImageKeepExactOldState: only a failure
// the write lane PROVED did not cross the namespace commit is the frozen
// LOCAL_PERSISTENCE_ERROR(precommit) identity, and it leaves the exact old bytes
// and maps with no latch, counter or retry. A stale prepared image is a
// different, LOCAL class: nothing was even attempted, so it is not one of the
// frozen precommit triggers.
func TestPreparedCanonicalIndexPrecommitAndStaleImageKeepExactOldState(t *testing.T) {
	store := mustCreateBlockStore(t, BlockStorePath(t.TempDir()))
	row0, row1 := canonicalIndexRow(0x30), canonicalIndexRow(0x31)
	mustCommitCanonicalIndex(t, store, []string{row0})
	before, diskBefore := captureCanonicalRAMImage(store), mustReadIndexFile(t, store)

	t.Run("stale_visible_identity", func(t *testing.T) {
		// A well-formed identity this store never held: a comparison identity has
		// to DECODE (prepare refuses malformed bytes outright), so the staleness
		// under test is a different sequence, not an unreadable spelling.
		neverVisible := mustEncodeCanonicalIndex(t, []string{canonicalIndexRow(0x3f)})
		prepared, err := prepareCanonicalIndex(neverVisible, []string{row0, row1})
		if err != nil {
			t.Fatalf("prepareCanonicalIndex: %v", err)
		}
		writes := 0
		withWriteFileAtomicFn(t, func(string, []byte, os.FileMode) error { writes++; return nil })
		got := prepared.commit(store)
		if got.class != canonicalCommitStale || !errors.Is(got.err, errCanonicalIndexMoved) {
			t.Fatalf("commit = %s (%v), want the LOCAL stale class", got.class, got.err)
		}
		if writes != 0 {
			t.Fatalf("a stale prepared image reached the write lane %d times", writes)
		}
	})

	t.Run("before_namespace_commit", func(t *testing.T) {
		prepared := mustPrepareCanonicalIndex(t, store, []string{row0, row1})
		tagged := newAtomicWriteError(atomicWriteBeforeNamespaceCommit, store.indexPath, atomicWriteOverwrite, os.ErrPermission)
		withWriteFileAtomicFn(t, func(string, []byte, os.FileMode) error { return tagged })
		got := prepared.commit(store)
		if got.class != canonicalCommitPrecommit || !errors.Is(got.err, os.ErrPermission) {
			t.Fatalf("commit = %s (%v), want LOCAL_PERSISTENCE_ERROR(precommit)", got.class, got.err)
		}
	})

	assertCanonicalRAMUnchanged(t, store, before, "precommit failure")
	if !bytes.Equal(mustReadIndexFile(t, store), diskBefore) {
		t.Fatalf("precommit failure changed the on-disk index bytes")
	}
}

// TestPreparedCanonicalIndexRefusesSecondCommit: spec §6.4.1 forbids any
// rollback, retry or rewrite after a terminal persistence result. A prepared
// image whose visible identity stayed OLD would otherwise still pass its
// freshness check, so single use has to be enforced on the image itself: the
// second commit reaches no write lane at all.
func TestPreparedCanonicalIndexRefusesSecondCommit(t *testing.T) {
	store := mustCreateBlockStore(t, BlockStorePath(t.TempDir()))
	row0, row1 := canonicalIndexRow(0xc0), canonicalIndexRow(0xc1)
	mustCommitCanonicalIndex(t, store, []string{row0})
	prepared := mustPrepareCanonicalIndex(t, store, []string{row0, row1})

	writes := 0
	withWriteFileAtomicFn(t, func(path string, _ []byte, _ os.FileMode) error {
		writes++
		// TryLock, never the RLock reader: a held lock must fail this row, not hang it.
		if store.stateMu.TryLock() {
			store.stateMu.Unlock()
		} else {
			t.Error("a publication lock was held while the commit write ran")
		}
		return newAtomicWriteError(atomicWriteAfterNamespaceCommit, path, atomicWriteOverwrite, os.ErrPermission)
	})
	if got := prepared.commit(store); got.class != canonicalCommitTerminalOld {
		t.Fatalf("first commit = %s (%v), want %s", got.class, got.err, canonicalCommitTerminalOld)
	}
	before := captureCanonicalRAMImage(store)

	got := prepared.commit(store)
	if got.class != canonicalCommitStale || !errors.Is(got.err, errPreparedIndexSpent) {
		t.Fatalf("second commit = %s (%v), want the spent refusal", got.class, got.err)
	}
	if writes != 1 {
		t.Fatalf("the write lane ran %d times, want exactly one attempt", writes)
	}
	assertCanonicalRAMUnchanged(t, store, before, "second commit")
}

func TestPreparedCanonicalIndexCrossStoreCommitIsSingleUse(t *testing.T) {
	stores := []*BlockStore{mustCreateBlockStore(t, BlockStorePath(t.TempDir())), mustCreateBlockStore(t, BlockStorePath(t.TempDir()))}
	for _, store := range stores {
		if err := store.CommitCanonicalBlock(0, devnetGenesisBlockHash, devnetGenesisHeaderBytes, devnetGenesisBlockBytes, &BlockUndo{BlockHeight: 0}); err != nil {
			t.Fatalf("commit canonical block: %v", err)
		}
	}
	if !bytes.Equal(stores[0].visibleIndexBytes(), stores[1].visibleIndexBytes()) {
		t.Fatal("sibling stores do not share the prepared old image")
	}
	var writes atomic.Int32
	fault := errors.New("precommit")
	withWriteFileAtomicFn(t, func(path string, _ []byte, _ os.FileMode) error {
		writes.Add(1)
		return newAtomicWriteError(atomicWriteBeforeNamespaceCommit, path, atomicWriteOverwrite, fault)
	})
	for range 4 {
		prepared := mustPrepareCanonicalIndex(t, stores[0], []string{})
		entered, release, start := make(chan struct{}, 2), make(chan struct{}), make(chan struct{})
		var releaseOnce sync.Once
		releaseProbes := func() { releaseOnce.Do(func() { close(release) }) }
		defer releaseProbes()
		for _, store := range stores {
			probe := new(sync.Once)
			store.leafProbe = func() { probe.Do(func() { entered <- struct{}{}; <-release }) }
		}
		writes.Store(0)
		results := make(chan canonicalCommitResult, len(stores))
		receive := func(message string) canonicalCommitResult {
			select {
			case result := <-results:
				return result
			case <-time.After(time.Second):
				t.Fatal(message)
			}
			return canonicalCommitResult{}
		}
		for _, store := range stores {
			go func(store *BlockStore) { <-start; results <- prepared.commit(store) }(store)
		}
		close(start)
		select {
		case <-entered:
		case <-time.After(time.Second):
			releaseProbes()
			receive("first prepared commit did not finish")
			receive("second prepared commit did not finish")
			t.Fatal("no prepared reclassification reached its leaf probe")
		}
		select {
		case <-entered:
			releaseProbes()
			receive("first planner did not finish")
			receive("second planner did not finish")
			t.Fatal("one prepared image reached two reclassification planners")
		case loser := <-results:
			if loser.class != canonicalCommitStale || !errors.Is(loser.err, errPreparedIndexSpent) {
				releaseProbes()
				receive("claimed prepared commit did not finish")
				t.Fatalf("loser=%s err=%v", loser.class, loser.err)
			}
		case <-time.After(time.Second):
			releaseProbes()
			receive("first prepared commit did not finish")
			receive("second prepared commit did not finish")
			t.Fatal("second store did not refuse the spent image")
		}
		releaseProbes()
		winner := receive("claimed prepared commit did not finish")
		if winner.class != canonicalCommitPrecommit || !errors.Is(winner.err, fault) || writes.Load() != 1 {
			t.Fatalf("winner=%s err=%v writes=%d", winner.class, winner.err, writes.Load())
		}
	}
}

// respellCanonicalIndex wraps a HAND-WRITTEN compact spelling of one canonical
// sequence in the store envelope: field order reversed and no indentation, which
// the strict decoder accepts and encodeBlockStoreIndex never emits. It is the
// test's own oracle for "same sequence, different bytes", never produced by the code
// under test, and every user proves it differs from the canonical encoding so no row can
// pass because the two spellings collapsed. Callers pass >= 1 row: zero rows would render
// `"canonical":[""]`, an invalid single empty row, not the empty sequence.
func respellCanonicalIndex(t *testing.T, rows ...string) []byte {
	t.Helper()
	return mustMarshalStoreEnvelope(t, `{"version":1,"canonical":["`+strings.Join(rows, `","`)+`"]}`)
}

func mustMarshalStoreEnvelope(t *testing.T, payload string) []byte {
	t.Helper()
	raw, err := marshalStoreEnvelope(storeEnvelopeBlockIndex, []byte(payload))
	if err != nil {
		t.Fatalf("marshalStoreEnvelope: %v", err)
	}
	return raw
}

// withLoadBlockStoreIndexFn replaces the strict readback seam so a test can COUNT the
// reads one commit performs; it mirrors withWriteFileAtomicFn.
func withLoadBlockStoreIndexFn(t *testing.T, fn func(string) (blockStoreIndexDisk, []byte, error)) {
	t.Helper()
	previous := loadBlockStoreIndexFn
	loadBlockStoreIndexFn = fn
	t.Cleanup(func() { loadBlockStoreIndexFn = previous })
}

// countCanonicalWrites counts write attempts and reports success without touching the
// disk, for lanes that only care how many times the write lane ran.
func countCanonicalWrites(t *testing.T) *int {
	t.Helper()
	writes := 0
	withWriteFileAtomicFn(t, func(string, []byte, os.FileMode) error { writes++; return nil })
	return &writes
}

// TestPreparedCanonicalIndexSequenceIdentityPreparationAndFreshness: preparation and
// commit freshness compare the complete ordered ROW SEQUENCE of spec §6.4.1 — length and
// every row, position = height — never the bytes that spell it. So a re-spelled visible
// identity is the SAME identity, a truly moved or undecodable one is refused before the
// single-use claim and before any write, and an image with NO comparison identity still
// saves through Restore yet may never commit.
func TestPreparedCanonicalIndexSequenceIdentityPreparationAndFreshness(t *testing.T) {
	row0, row1, row2 := canonicalIndexRow(0x50), canonicalIndexRow(0x51), canonicalIndexRow(0x52)
	seedRows, nextRows := []string{row0}, []string{row0, row1}
	seed := func(t *testing.T) *BlockStore {
		t.Helper()
		store := mustCreateBlockStore(t, BlockStorePath(t.TempDir()))
		mustCommitCanonicalIndex(t, store, seedRows)
		return store
	}
	respelledSeed := respellCanonicalIndex(t, seedRows...)
	if bytes.Equal(respelledSeed, mustEncodeCanonicalIndex(t, seedRows)) {
		t.Fatal("the re-spelled fixture must differ byte for byte from the canonical encoding")
	}

	// Preparation: oldRaw state x planned next, all before any image exists.
	for _, tc := range []struct {
		name    string
		oldRaw  []byte // nil: the store's own canonical visible identity
		next    []string
		wantIs  error
		wantErr string // exact refusal text, for refusals that carry no sentinel
		wantOk  bool
	}{
		{name: "canonical_old_same_sequence_is_no_op", next: seedRows, wantIs: errCanonicalIndexNoOp},
		// Byte identity would stage this as a real transition and write.
		{name: "respelled_old_same_sequence_is_no_op", oldRaw: respelledSeed, next: seedRows, wantIs: errCanonicalIndexNoOp},
		{name: "canonical_old_different_next_builds_image", next: nextRows, wantOk: true},
		// Fail closed: an undecodable identity must not degrade into "no identity",
		// which would silently skip the no-op refusal.
		{name: "malformed_envelope_old_raw", oldRaw: []byte("bytes this store never had"), next: nextRows, wantIs: ErrStoreIntegrity},
		{name: "malformed_inner_json_old_raw", oldRaw: mustMarshalStoreEnvelope(t, `{"canonical":[`), next: nextRows},
		// STRICTNESS, not well-formedness: valid JSON in a valid envelope that a lax
		// json.Unmarshal into blockStoreIndexDisk accepts silently. The pinned text proves
		// the store's own exact-field rule refused it, wrapped as loadBlockStoreIndex wraps
		// it — one corrupt image, one error identity through prepare and reopen.
		{
			name: "extra_top_level_field_old_raw", oldRaw: mustMarshalStoreEnvelope(t, `{"version":1,"canonical":[],"extra":0}`), next: nextRows,
			wantErr: `decode blockstore index: blockstore index fields must be exactly canonical and version, got ["canonical" "extra" "version"]`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, writes := seed(t), countCanonicalWrites(t)
			oldRaw := tc.oldRaw
			if oldRaw == nil {
				oldRaw = store.visibleIndexBytes()
			}
			prepared, err := prepareCanonicalIndex(oldRaw, tc.next)
			switch {
			case tc.wantOk:
				if err != nil {
					t.Fatalf("prepare: %v", err)
				}
				// Both retained identities are compared to LITERAL sequences.
				if !slices.Equal(prepared.oldCanonical, seedRows) || !slices.Equal(prepared.index.Canonical, nextRows) {
					t.Fatalf("retained old=%v planned=%v", prepared.oldCanonical, prepared.index.Canonical)
				}
			case err == nil || prepared != nil:
				t.Fatalf("prepare accepted the refused input: %v", err)
			case tc.wantIs != nil && !errors.Is(err, tc.wantIs):
				t.Fatalf("prepare err = %v, want %v", err, tc.wantIs)
			case tc.wantErr != "" && err.Error() != tc.wantErr:
				t.Fatalf("prepare err = %q, want %q", err, tc.wantErr)
			}
			if *writes != 0 {
				t.Fatalf("preparation reached the write lane %d times", *writes)
			}
		})
	}

	setCache := func(raw []byte) func(*testing.T, *BlockStore) {
		return func(_ *testing.T, store *BlockStore) {
			store.stateMu.Lock()
			store.indexRaw = raw
			store.stateMu.Unlock()
		}
	}
	// Commit freshness: the visible identity as it stands between prepare and commit.
	for _, tc := range []struct {
		name       string
		nilOld     bool
		emptyStore bool
		cache      func(*testing.T, *BlockStore)
		wantClass  canonicalCommitClass
		wantIs     error
		wantWrites int
	}{
		// A writer that emitted a different valid spelling of the same rows leaves exactly
		// this cache; the in-tree encoder emits one spelling, so the fixture is hand-written.
		{name: "respelled_cached_identity_is_fresh", cache: setCache(respelledSeed), wantClass: canonicalCommitted, wantWrites: 1},
		// The EMPTY visible sequence is what needs the explicit no-identity guard: a nil
		// identity compares equal to an empty one, so a freshness check that only compared
		// sequences would let a Restore-shaped image commit against a fresh store.
		{name: "nil_old_identity_commit_is_refused", nilOld: true, emptyStore: true, wantClass: canonicalCommitStale, wantIs: errCanonicalIndexMoved},
		{name: "true_sequence_drift_refuses_commit", cache: func(t *testing.T, store *BlockStore) {
			// The lost-update schedule: a legacy mutator advances the visible
			// identity between prepare and commit, through its own save path.
			if err := store.SetCanonicalTip(0, canonicalIndexRowHash(t, row2)); err != nil {
				t.Fatalf("SetCanonicalTip: %v", err)
			}
		}, wantClass: canonicalCommitStale, wantIs: errCanonicalIndexMoved},
		// Empty again for the fail-closed arm: an undecodable cache decodes to NO sequence,
		// equal to the empty one, so only the explicit decode-failure refusal keeps it stale.
		{name: "undecodable_cached_identity_refuses_commit", emptyStore: true, cache: setCache([]byte("not an envelope")), wantClass: canonicalCommitStale, wantIs: errCanonicalIndexMoved},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := seed(t)
			if tc.emptyStore {
				store = mustCreateBlockStore(t, BlockStorePath(t.TempDir()))
			}
			oldRaw := store.visibleIndexBytes()
			if tc.nilOld {
				oldRaw = nil
			}
			prepared, err := prepareCanonicalIndex(oldRaw, nextRows)
			if err != nil {
				t.Fatalf("prepare: %v", err)
			}
			if tc.cache != nil {
				tc.cache(t, store)
			}
			writes := countCanonicalWrites(t)
			got := prepared.commit(store)
			if got.class != tc.wantClass || (tc.wantIs != nil && !errors.Is(got.err, tc.wantIs)) {
				t.Fatalf("commit = %s (%v), want %s (%v)", got.class, got.err, tc.wantClass, tc.wantIs)
			}
			if *writes != tc.wantWrites {
				t.Fatalf("the write lane ran %d times, want %d", *writes, tc.wantWrites)
			}
			if tc.wantClass != canonicalCommitStale {
				return
			}
			// Refused BEFORE the single-use claim, so the image stays reusable and
			// the SAME refusal comes back — never errPreparedIndexSpent.
			if prepared.spent.Load() {
				t.Fatal("a pre-claim refusal spent the image")
			}
			if again := prepared.commit(store); again.class != tc.wantClass || !errors.Is(again.err, tc.wantIs) {
				t.Fatalf("second commit = %s (%v), want the same refusal", again.class, again.err)
			}
		})
	}

	// Restore has NO comparison identity, so an identical list is not a no-op and must still
	// reach the save. The EMPTY row matters: a nil identity would compare equal to empty.
	t.Run("nil_old_identity_restore_saves_identical_sequence", func(t *testing.T) {
		for _, tc := range []struct {
			name  string
			store func(t *testing.T) *BlockStore
			rows  []string
		}{
			{name: "identical_nonempty", store: seed, rows: seedRows},
			{name: "identical_empty", store: func(t *testing.T) *BlockStore {
				return mustCreateBlockStore(t, BlockStorePath(t.TempDir()))
			}, rows: []string{}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				store, writes := tc.store(t), countCanonicalWrites(t)
				if err := store.RestoreCanonicalIndex(tc.rows); err != nil {
					t.Fatalf("RestoreCanonicalIndex(%v): %v", tc.rows, err)
				}
				if *writes != 1 {
					t.Fatalf("the write lane ran %d times, want exactly one save", *writes)
				}
			})
		}
	})

	t.Run("spent_image_refuses_second_commit", func(t *testing.T) {
		store := seed(t)
		prepared := mustPrepareCanonicalIndex(t, store, nextRows)
		writes := countCanonicalWrites(t)
		if got := prepared.commit(store); got.class != canonicalCommitted {
			t.Fatalf("first commit = %s (%v), want COMMITTED", got.class, got.err)
		}
		if got := prepared.commit(store); got.class != canonicalCommitStale || !errors.Is(got.err, errPreparedIndexSpent) {
			t.Fatalf("second commit = %s (%v), want the spent refusal", got.class, got.err)
		}
		if *writes != 1 {
			t.Fatalf("the write lane ran %d times, want exactly one attempt", *writes)
		}
	})

	t.Run("concurrent_double_commit_claims_once", func(t *testing.T) {
		store := seed(t)
		prepared := mustPrepareCanonicalIndex(t, store, nextRows)
		var writes atomic.Int32
		withWriteFileAtomicFn(t, func(string, []byte, os.FileMode) error { writes.Add(1); return nil })
		// Both goroutines park on the barrier before either may claim. Same-store commits
		// then serialize on the transition fence, so this row pins that the SECOND arrival is
		// refused as spent and only one write happens; CAS contention is the cross-store test.
		var ready sync.WaitGroup
		ready.Add(2)
		start, results := make(chan struct{}), make(chan canonicalCommitResult, 2)
		for range 2 {
			go func() { ready.Done(); <-start; results <- prepared.commit(store) }()
		}
		ready.Wait()
		close(start)
		committed, refused := 0, 0
		for range 2 {
			switch got := <-results; {
			case got.class == canonicalCommitted:
				committed++
			case got.class == canonicalCommitStale && errors.Is(got.err, errPreparedIndexSpent):
				refused++
			default:
				t.Fatalf("concurrent commit = %s (%v)", got.class, got.err)
			}
		}
		if committed != 1 || refused != 1 || writes.Load() != 1 {
			t.Fatalf("committed=%d refused=%d writes=%d, want 1/1/1", committed, refused, writes.Load())
		}
	})
}

// TestPreparedCanonicalIndexPostCommitVisibleSequenceClassify: whenever the write may
// have crossed the namespace commit — the lane said so, or it returned an error it never
// classified at all — exactly ONE strict readback classifies by the complete ordered ROW
// SEQUENCE. Two spellings of one sequence are ONE identity, so a re-spelled old or new
// image is that identity and terminal NEW caches the EXACT bytes the disk holds; a shared
// tip, a reordering, a duplicate, a prefix, an extra row, a matching length, a missing
// file and an unreadable one are each NEITHER. Neither the error text nor a stale RAM
// identity classifies, a proven pre-commit failure never reads, and every row pins single
// use: one write, one image, a spent second commit.
func TestPreparedCanonicalIndexPostCommitVisibleSequenceClassify(t *testing.T) {
	const (
		afterCommit  = ""       // the lane tagged the failure AFTER the namespace commit
		untagged     = "untag"  // an error the atomic lane never classified at all
		beforeCommit = "before" // the lane PROVED nothing crossed
		cleanWrite   = "clean"  // the write succeeded
	)
	row0, row1, row2 := canonicalIndexRow(0x40), canonicalIndexRow(0x41), canonicalIndexRow(0x42)
	row3, row4 := canonicalIndexRow(0x43), canonicalIndexRow(0x44)
	oldRows, newRows := []string{row0}, []string{row0, row1, row2}
	cause := errors.New("write-lane fault")

	canonicalNew := mustEncodeCanonicalIndex(t, newRows)
	respelledOld, respelledNew := respellCanonicalIndex(t, oldRows...), respellCanonicalIndex(t, newRows...)
	if bytes.Equal(respelledOld, mustEncodeCanonicalIndex(t, oldRows)) || bytes.Equal(respelledNew, canonicalNew) {
		t.Fatal("the re-spelled fixtures must differ byte for byte from the canonical encoding")
	}
	plant := func(raw []byte) func(*testing.T, *BlockStore) {
		return func(t *testing.T, store *BlockStore) { mustPlantIndex(t, store, raw) }
	}
	plantRows := func(rows ...string) func(*testing.T, *BlockStore) {
		return func(t *testing.T, store *BlockStore) { mustPlantIndex(t, store, mustEncodeCanonicalIndex(t, rows)) }
	}

	for _, tc := range []struct {
		name string
		// visible makes the named disk state visible from inside the write lane,
		// exactly as a crossed write would leave it. nil keeps the committed old.
		visible     func(*testing.T, *BlockStore)
		outcome     string
		wantClass   canonicalCommitClass
		wantReads   int
		wantReadErr bool
		// wantRaw non-nil means publication is expected, and it is the EXACT visible
		// identity the store must cache — a literal fixture, never the image under test.
		wantRaw []byte
		alsoIs  error
	}{
		{name: "canonical_old", outcome: afterCommit, wantClass: canonicalCommitTerminalOld, wantReads: 1},
		{name: "respelled_old", visible: plant(respelledOld), outcome: untagged, wantClass: canonicalCommitTerminalOld, wantReads: 1},
		{name: "canonical_new", visible: plant(canonicalNew), wantClass: canonicalCommitTerminalNew, wantReads: 1, wantRaw: canonicalNew},
		// Byte identity would call this NEITHER, and publishing the planned
		// encoding would leave the store naming bytes the disk does not hold.
		{name: "respelled_new", visible: plant(respelledNew), outcome: untagged, wantClass: canonicalCommitTerminalNew, wantReads: 1, wantRaw: respelledNew},
		{name: "third_sequence", visible: plantRows(row3, row4), wantClass: canonicalCommitTerminalUnknown, wantReads: 1},
		// The planned TIP with a different prefix kills tip-only identity.
		{name: "same_tip_different_prefix", visible: plantRows(row3, row1, row2), wantClass: canonicalCommitTerminalUnknown, wantReads: 1},
		// The planned rows as a SET, in another order.
		{name: "reordered_new_rows", visible: plantRows(row0, row2, row1), wantClass: canonicalCommitTerminalUnknown, wantReads: 1},
		// Decodes fine — validateBlockStoreIndex has no duplicate-row check — so only
		// sequence inequality refuses it. LONGER than the planned image on purpose: at the
		// planned length it repeats same_length_one_row_differs and a de-dup identity lives.
		{name: "duplicated_new_row", visible: plantRows(row0, row1, row1, row2), wantClass: canonicalCommitTerminalUnknown, wantReads: 1},
		{name: "strict_prefix_of_new", visible: plantRows(row0, row1), wantClass: canonicalCommitTerminalUnknown, wantReads: 1},
		{name: "new_plus_extra_row", visible: plantRows(row0, row1, row2, row3), wantClass: canonicalCommitTerminalUnknown, wantReads: 1},
		{name: "same_length_one_row_differs", visible: plantRows(row0, row1, row3), wantClass: canonicalCommitTerminalUnknown, wantReads: 1},
		{name: "empty_sequence", visible: plantRows(), wantClass: canonicalCommitTerminalUnknown, wantReads: 1},
		// A missing file is a read FAILURE, never an implicit empty identity.
		{name: "missing_file", visible: func(t *testing.T, store *BlockStore) {
			if err := os.Remove(store.indexPath); err != nil {
				t.Fatalf("remove index: %v", err)
			}
		}, outcome: untagged, wantClass: canonicalCommitTerminalUnknown, wantReads: 1, wantReadErr: true, alsoIs: os.ErrNotExist},
		// Trailing padding shifts the derived envelope layout: bytes the store
		// would refuse to reopen are no identity, however long they are.
		{
			name: "malformed_envelope", visible: plant(append(append([]byte(nil), canonicalNew...), bytes.Repeat([]byte{' '}, 4096)...)),
			wantClass: canonicalCommitTerminalUnknown, wantReads: 1, wantReadErr: true,
		},
		{name: "malformed_inner_json", visible: func(t *testing.T, store *BlockStore) {
			mustPlantIndex(t, store, mustMarshalStoreEnvelope(t, `{"canonical":[`))
		}, wantClass: canonicalCommitTerminalUnknown, wantReads: 1, wantReadErr: true},
		// A visibly NEW image behind a PROVEN pre-commit failure: nothing crossed,
		// so nothing is read or published even though a readback would say NEW.
		{name: "before_namespace_commit", visible: plant(respelledNew), outcome: beforeCommit, wantClass: canonicalCommitPrecommit},
		{name: "clean_write", outcome: cleanWrite, wantClass: canonicalCommitted, wantRaw: canonicalNew},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := mustCreateBlockStore(t, BlockStorePath(t.TempDir()))
			mustCommitCanonicalIndex(t, store, oldRows)
			prepared := mustPrepareCanonicalIndex(t, store, newRows)
			before := captureCanonicalRAMImage(store)

			writes, reads, readErr := 0, 0, error(nil)
			withLoadBlockStoreIndexFn(t, func(path string) (blockStoreIndexDisk, []byte, error) {
				reads++
				index, raw, err := loadBlockStoreIndex(path)
				readErr = err
				return index, raw, err
			})
			withWriteFileAtomicFn(t, func(path string, data []byte, perm os.FileMode) error {
				writes++
				if tc.visible != nil {
					tc.visible(t, store)
				}
				switch tc.outcome {
				case cleanWrite:
					return writeFileAtomic(path, data, perm)
				case beforeCommit:
					return newAtomicWriteError(atomicWriteBeforeNamespaceCommit, path, atomicWriteOverwrite, cause)
				case untagged:
					return cause
				default:
					return newAtomicWriteError(atomicWriteAfterNamespaceCommit, path, atomicWriteOverwrite, cause)
				}
			})

			got := prepared.commit(store)
			if got.class != tc.wantClass {
				t.Fatalf("commit = %s (%v), want %s", got.class, got.err, tc.wantClass)
			}
			if tc.outcome == cleanWrite {
				if got.err != nil {
					t.Fatalf("a committed result carries %v", got.err)
				}
			} else if !errors.Is(got.err, cause) {
				t.Fatalf("result dropped the write-lane cause: %v", got.err)
			}
			if tc.alsoIs != nil && !errors.Is(got.err, tc.alsoIs) {
				t.Fatalf("result dropped the readback failure: %v", got.err)
			}
			if (readErr != nil) != tc.wantReadErr {
				t.Fatalf("readback err = %v, want failure=%v", readErr, tc.wantReadErr)
			}
			// Both causes survive an unprovable identity: the write failure AND
			// the exact readback failure, joined.
			if readErr != nil && !errors.Is(got.err, readErr) {
				t.Fatalf("result dropped the exact readback cause %v: %v", readErr, got.err)
			}
			if writes != 1 || reads != tc.wantReads {
				t.Fatalf("writes=%d reads=%d, want 1/%d", writes, reads, tc.wantReads)
			}
			if second := prepared.commit(store); second.class != canonicalCommitStale || !errors.Is(second.err, errPreparedIndexSpent) {
				t.Fatalf("second commit = %s (%v), want the spent refusal", second.class, second.err)
			}
			if writes != 1 || reads != tc.wantReads {
				t.Fatalf("the spent second commit reached the lanes: writes=%d reads=%d", writes, reads)
			}
			if tc.wantRaw != nil {
				assertPublishedCanonicalImage(t, store, newRows, tc.wantRaw)
				return
			}
			assertCanonicalRAMUnchanged(t, store, before, tc.name)
		})
	}

	// The OLD arm needs a MULTI-ROW old identity of its own: every row above has a
	// single-row old, where "length and tip" and "the whole sequence" agree, so an old arm
	// weakened to length-plus-tip would survive the entire table. Old {row0,row1}, planned
	// {row0,row1,row2}, visible {row3,row1}: old length, old tip, different prefix.
	t.Run("old_length_and_tip_with_different_prefix", func(t *testing.T) {
		store := mustCreateBlockStore(t, BlockStorePath(t.TempDir()))
		mustCommitCanonicalIndex(t, store, []string{row0, row1})
		prepared := mustPrepareCanonicalIndex(t, store, []string{row0, row1, row2})
		before := captureCanonicalRAMImage(store)
		withWriteFileAtomicFn(t, func(path string, _ []byte, _ os.FileMode) error {
			mustPlantIndex(t, store, mustEncodeCanonicalIndex(t, []string{row3, row1}))
			return newAtomicWriteError(atomicWriteAfterNamespaceCommit, path, atomicWriteOverwrite, cause)
		})
		if got := prepared.commit(store); got.class != canonicalCommitTerminalUnknown || !errors.Is(got.err, cause) {
			t.Fatalf("commit = %s (%v), want %s carrying the write-lane cause", got.class, got.err, canonicalCommitTerminalUnknown)
		}
		assertCanonicalRAMUnchanged(t, store, before, "old length and tip with a different prefix")
	})
}

func mustEncodeCanonicalIndex(t *testing.T, canonical []string) []byte {
	t.Helper()
	raw, err := encodeBlockStoreIndex(blockStoreIndexDisk{Version: blockStoreIndexVersion, Canonical: canonical})
	if err != nil {
		t.Fatalf("encodeBlockStoreIndex: %v", err)
	}
	return raw
}

// mustPlantIndex makes raw the visible index without going through the write
// lane under test.
func mustPlantIndex(t *testing.T, store *BlockStore, raw []byte) {
	t.Helper()
	if err := os.WriteFile(store.indexPath, raw, 0o600); err != nil {
		t.Fatalf("plant index bytes: %v", err)
	}
}

// TestPreparedCanonicalIndexTerminalUnknownLeavesIdentityStale pins the
// consequence documented on classifyVisibleIndex: after a terminal result the
// cached identity may no longer describe the disk. The freshness ASSERT is not
// what stops a later write from building on it — the owning transition's latch
// is.
func TestPreparedCanonicalIndexTerminalUnknownLeavesIdentityStale(t *testing.T) {
	store := mustCreateBlockStore(t, BlockStorePath(t.TempDir()))
	row0, row1, row2 := canonicalIndexRow(0xa1), canonicalIndexRow(0xa2), canonicalIndexRow(0xa3)
	mustCommitCanonicalIndex(t, store, []string{row0})
	prepared := mustPrepareCanonicalIndex(t, store, []string{row0, row1})

	withWriteFileAtomicFn(t, func(path string, _ []byte, _ os.FileMode) error {
		mustPlantIndex(t, store, mustEncodeCanonicalIndex(t, []string{row0, row2}))
		return newAtomicWriteError(atomicWriteAfterNamespaceCommit, path, atomicWriteOverwrite, os.ErrPermission)
	})
	if got := prepared.commit(store); got.class != canonicalCommitTerminalUnknown {
		t.Fatalf("commit = %s (%v), want %s", got.class, got.err, canonicalCommitTerminalUnknown)
	}
	if bytes.Equal(store.visibleIndexBytes(), mustReadIndexFile(t, store)) {
		t.Fatalf("a third visible identity must leave the cached identity stale")
	}
}

// TestBlockStoreOpenRejectsDuplicateCanonicalRow: a repeated row collapses two
// heights into one height-by-hash entry, so the store would run with a map that
// does not describe its own list. The cross-client decoder is untouched (Rust
// still accepts it — startup divergence window, RUB-897); this is the Go-side
// guard: Open/reload reject through newBlockStore; Restore validates separately.
func TestBlockStoreOpenRejectsDuplicateCanonicalRow(t *testing.T) {
	root := BlockStorePath(t.TempDir())
	store := mustCreateBlockStore(t, root)
	row := canonicalIndexRow(0xf0)
	// The shared decoder stays untightened (Rust mirror, RUB-897): it accepts what the store refuses.
	if _, err := decodeBlockStoreIndex([]byte(`{"canonical":["` + row + `","` + row + `"],"version":1}`)); err != nil {
		t.Fatalf("decodeBlockStoreIndex must keep accepting a duplicate row: %v", err)
	}
	mustPlantIndex(t, store, mustEncodeCanonicalIndex(t, []string{row, row}))
	if _, err := OpenBlockStore(root); !errors.Is(err, errCanonicalIndexDuplicateRow) || !strings.Contains(err.Error(), store.indexPath) {
		t.Fatalf("OpenBlockStore err = %v, want the duplicate-row refusal naming %s", err, store.indexPath)
	}

	// A writer that builds its map from a caller-supplied list refuses the same list
	// before touching the file: it cannot persist what it would refuse to reopen.
	planted := mustReadIndexFile(t, store)
	if err := store.RestoreCanonicalIndex([]string{row, row}); !errors.Is(err, errCanonicalIndexDuplicateRow) || !strings.Contains(err.Error(), store.indexPath) {
		t.Fatalf("RestoreCanonicalIndex err = %v, want the duplicate-row refusal naming %s", err, store.indexPath)
	}
	if !bytes.Equal(mustReadIndexFile(t, store), planted) {
		t.Fatalf("a refused restore rewrote the canonical index")
	}
}

// TestPreparedCanonicalIndexPublishLockedAllocatesNothing measures the
// commit-to-RAM step itself, held under the same lock the commit path holds: it
// is prevalidated in-place compaction plus field assignment, with no allocation.
func TestPreparedCanonicalIndexPublishLockedAllocatesNothing(t *testing.T) {
	store := mustCreateBlockStore(t, BlockStorePath(t.TempDir()))
	prepared := mustPrepareCanonicalIndex(t, store, []string{canonicalIndexRow(0x60), canonicalIndexRow(0x61)})
	accounting := store.noncanonical.Load()
	disconnected := noncanonicalRow{hash: [32]byte{1}, blockBytes: 1, height: noncanonicalUnknownHeight}
	disconnected.setState(noncanonicalBlockArtifact, BlockArtifactValid)
	delta := &noncanonicalTransitionDelta{disconnected: []noncanonicalRow{disconnected}, usedBytes: 1, uniqueCount: 1}
	store.stateMu.Lock()
	allocs := testing.AllocsPerRun(100, func() {
		accounting.count, accounting.sortedCount, accounting.usedBytes = 0, 0, 0
		prepared.publishLocked(store, delta)
	})
	store.stateMu.Unlock()
	if allocs != 0 {
		t.Fatalf("publish allocated %v objects per run, want 0", allocs)
	}
}

// TestPreparedCanonicalIndexOldSnapshotsSurviveReplacement: publication swaps
// pointers, it never mutates the image a reader already holds.
func TestPreparedCanonicalIndexOldSnapshotsSurviveReplacement(t *testing.T) {
	store := mustCreateBlockStore(t, BlockStorePath(t.TempDir()))
	row0, row1, row2 := canonicalIndexRow(0x70), canonicalIndexRow(0x71), canonicalIndexRow(0x72)
	mustCommitCanonicalIndex(t, store, []string{row0, row1})

	snapshot, err := store.CanonicalIndexSnapshot()
	if err != nil {
		t.Fatalf("CanonicalIndexSnapshot: %v", err)
	}
	store.stateMu.RLock()
	oldHeights, oldList, oldRaw := store.canonicalHeightByHash, store.index.Canonical, store.indexRaw
	store.stateMu.RUnlock()

	mustCommitCanonicalIndex(t, store, []string{row0, row2, row1})

	if !slices.Equal(snapshot, []string{row0, row1}) {
		t.Fatalf("old snapshot mutated: %v", snapshot)
	}
	if !slices.Equal(oldList, []string{row0, row1}) {
		t.Fatalf("old index list mutated: %v", oldList)
	}
	if len(oldHeights) != 2 || oldHeights[canonicalIndexRowHash(t, row1)] != 1 {
		t.Fatalf("old height map mutated: %v", oldHeights)
	}
	if bytes.Equal(oldRaw, store.visibleIndexBytes()) {
		t.Fatalf("visible identity did not move on a real replacement")
	}
}

// TestPreparedCanonicalIndexConcurrentReadersPinOldImage: readers under
// stateMu.RLock() observe the complete old image or the complete new one — list,
// height map and visible identity always agreeing. Run under -race.
func TestPreparedCanonicalIndexConcurrentReadersPinOldImage(t *testing.T) {
	store := mustCreateBlockStore(t, BlockStorePath(t.TempDir()))
	oldHeader, newHeader := testHeaderBytes(0x80, 80), testHeaderBytes(0x81, 81)
	oldOnlyHash, newOnlyHash := mustHeaderHash(t, oldHeader), mustHeaderHash(t, newHeader)
	if err := store.StoreBlock(oldOnlyHash, oldHeader, []byte("old")); err != nil {
		t.Fatalf("store old artifact: %v", err)
	}
	if err := store.StoreBlock(newOnlyHash, newHeader, []byte("new")); err != nil {
		t.Fatalf("store new artifact: %v", err)
	}
	old, next := []string{hex.EncodeToString(oldOnlyHash[:])}, []string{hex.EncodeToString(newOnlyHash[:])}
	mustCommitCanonicalIndex(t, store, old)
	prepared := mustPrepareCanonicalIndex(t, store, next)
	// LITERAL fixtures, built before the readers start. A reader must never touch the
	// prepared image: commit may REPLACE newRaw with the bytes a terminal readback found, so
	// a goroutine reading it would race the commit — and assert x == x on the published bytes.
	oldRaw, nextRaw := mustEncodeCanonicalIndex(t, old), mustEncodeCanonicalIndex(t, next)

	spawnReaders(t, 8, func() bool {
		store.stateMu.RLock()
		canonical := append([]string(nil), store.index.Canonical...)
		_, hasOld := store.canonicalHeightByHash[oldOnlyHash]
		_, hasNew := store.canonicalHeightByHash[newOnlyHash]
		accounting := store.noncanonical.Load()
		_, oldNoncanonical := accounting.find(oldOnlyHash)
		_, newNoncanonical := accounting.find(newOnlyHash)
		raw := store.indexRaw
		store.stateMu.RUnlock()

		switch {
		case slices.Equal(canonical, old):
			if !hasOld || hasNew || oldNoncanonical || !newNoncanonical || !bytes.Equal(raw, oldRaw) {
				t.Errorf("torn old pair: canonical=(%v,%v) accounting=(%v,%v)", hasOld, hasNew, oldNoncanonical, newNoncanonical)
				return false
			}
		case slices.Equal(canonical, next):
			if hasOld || !hasNew || !oldNoncanonical || newNoncanonical || !bytes.Equal(raw, nextRaw) {
				t.Errorf("torn new pair: canonical=(%v,%v) accounting=(%v,%v)", hasOld, hasNew, oldNoncanonical, newNoncanonical)
				return false
			}
		default:
			t.Errorf("partial canonical list observed: %v", canonical)
			return false
		}
		return true
	})

	if got := prepared.commit(store); got.class != canonicalCommitted {
		t.Errorf("commit = %s (%v)", got.class, got.err)
		return
	}
	assertPublishedCanonicalImage(t, store, next, nextRaw)
}

// TestInspectBlockPresenceConcurrentWithPublication: presence classification
// reads canonical membership and the three artifact leaves, so it has to hold
// the read lock across the whole snapshot. Under -race a publication running
// concurrently with these inspections is what proves the lock is really taken.
func TestInspectBlockPresenceConcurrentWithPublication(t *testing.T) {
	fixture := newPresenceFixture(t)
	store := fixture.store
	row := hex.EncodeToString(fixture.hash[:])
	prepared := mustPrepareCanonicalIndex(t, store, []string{row})

	// Nothing is stored, so the hash is ABSENT until the publication makes it a
	// canonical member with canonical-scoped evidence, and never ABSENT after a
	// reader saw that — or the image tore. `was` is sampled BEFORE the
	// inspection; reading it after would fail a legitimately earlier ABSENT.
	var published atomic.Bool
	spawnReaders(t, 8, func() bool {
		was := published.Load()
		got := store.InspectBlockPresence(fixture.hash)
		switch {
		case got.Class == BlockPresenceLocalStoreError && got.Scope == BlockPresenceScopeCanonical:
			published.Store(true)
		case got.Class == BlockPresenceAbsent && !was:
		default:
			t.Errorf("presence during publication = %s leaves=%+v", got, got.Leaves)
			return false
		}
		return true
	})

	if got := prepared.commit(store); got.class != canonicalCommitted {
		t.Errorf("commit = %s (%v)", got.class, got.err)
		return
	}
	if got := store.InspectBlockPresence(fixture.hash); got.Class != BlockPresenceLocalStoreError || got.Scope != BlockPresenceScopeCanonical {
		t.Fatalf("presence after publication = %s leaves=%+v, want canonical-scoped store evidence", got, got.Leaves)
	}
}

// TestInspectBlockPresenceStraddledByStoreNeverShowsImpossibleState: artifact
// writers hold no store lock, so the probe lands a real StoreBlock -> PutUndo between
// two leaf reads instead of leaving that interleaving to the scheduler. BOTH interior
// boundaries are pinned, and only undo -> header -> block clears both: undo -> block
// -> header survives the first and reports the impossible {Block:absent Header:valid
// Undo:absent} at the second; forward order already fails the first with
// {Block:absent Header:valid Undo:valid}, the tuple a concurrent -race run pinned.
func TestInspectBlockPresenceStraddledByStoreNeverShowsImpossibleState(t *testing.T) {
	for _, at := range []int{2, 3} {
		t.Run(fmt.Sprintf("before_leaf_%d", at), func(t *testing.T) {
			store := mustCreateBlockStore(t, BlockStorePath(t.TempDir()))
			// Disable accounting: this test isolates the pre-accounting monotone leaf-order invariant.
			store.noncanonical.Store(nil)
			header := testHeaderBytes(0x89, 890)
			hash := mustHeaderHash(t, header)
			reads := 0
			store.leafProbe = func() {
				if reads++; reads != at {
					return
				}
				if err := store.StoreBlock(hash, header, []byte("presence-order")); err != nil {
					t.Fatalf("StoreBlock: %v", err)
				}
				if err := store.PutUndo(hash, undoTestUndo()); err != nil {
					t.Fatalf("PutUndo: %v", err)
				}
			}

			leaves := store.InspectBlockPresence(hash).Leaves
			if reads != 3 || (leaves.Header != BlockArtifactAbsent && leaves.Block == BlockArtifactAbsent) ||
				(leaves.Undo != BlockArtifactAbsent && (leaves.Header == BlockArtifactAbsent || leaves.Block == BlockArtifactAbsent)) {
				t.Fatalf("leaves %+v existed at no instant, reads=%d", leaves, reads)
			}
		})
	}
}

// failUnlinkAroundRename fails the scratch cleanup on exactly one SIDE of the
// namespace commit: the wrapped rename is what says which side the lane is on,
// so the row keeps its meaning however many times cleanup runs.
func failUnlinkAroundRename(afterRename bool, fault error) func(*testing.T, *BlockStore, *atomicWriteOps) {
	return func(_ *testing.T, _ *BlockStore, ops *atomicWriteOps) {
		rename, unlink, renamed := ops.rename, ops.unlink, false
		ops.rename = func(from, to string) error {
			err := rename(from, to)
			renamed = renamed || err == nil
			return err
		}
		ops.unlink = func(path string) error {
			if renamed == afterRename {
				return fault
			}
			return unlink(path)
		}
	}
}

// TestBlockStoreCanonicalIndexCommitFaultMatrix walks the real RUB-1084 write
// lane with one injected fault per stage. Pre-commit stages leave the exact old
// bytes and RAM; post-commit stages classify on the visible identity alone.
func TestBlockStoreCanonicalIndexCommitFaultMatrix(t *testing.T) {
	row0, row1 := canonicalIndexRow(0x90), canonicalIndexRow(0x91)
	fault := errors.New("injected stage fault")

	for _, tc := range []struct {
		name      string
		configure func(t *testing.T, store *BlockStore, ops *atomicWriteOps)
		wantClass canonicalCommitClass
		published bool
	}{
		{
			name: "temp_create",
			configure: func(_ *testing.T, _ *BlockStore, ops *atomicWriteOps) {
				ops.openScratch = func(string, int, os.FileMode) (atomicWriteScratchFile, error) { return nil, fault }
			},
			wantClass: canonicalCommitPrecommit,
		},
		{
			name: "scratch_write",
			configure: func(_ *testing.T, _ *BlockStore, ops *atomicWriteOps) {
				ops.openScratch = atomicStubOpen(&atomicScratchStub{writeErr: fault})
			},
			wantClass: canonicalCommitPrecommit,
		},
		{
			name: "file_fsync",
			configure: func(_ *testing.T, _ *BlockStore, ops *atomicWriteOps) {
				ops.openScratch = atomicStubOpen(&atomicScratchStub{syncErr: fault})
			},
			wantClass: canonicalCommitPrecommit,
		},
		{
			name: "scratch_mode",
			configure: func(_ *testing.T, _ *BlockStore, ops *atomicWriteOps) {
				ops.openScratch = atomicStubOpen(&atomicScratchStub{chmodErr: fault})
			},
			wantClass: canonicalCommitPrecommit,
		},
		{
			name: "scratch_close",
			configure: func(_ *testing.T, _ *BlockStore, ops *atomicWriteOps) {
				ops.openScratch = atomicStubOpen(&atomicScratchStub{closeErr: fault})
			},
			wantClass: canonicalCommitPrecommit,
		},
		{
			name: "rename",
			configure: func(_ *testing.T, _ *BlockStore, ops *atomicWriteOps) {
				ops.rename = func(string, string) error { return fault }
			},
			wantClass: canonicalCommitPrecommit,
		},
		{
			// The scratch reclaim that runs BEFORE the rename: nothing crossed.
			name:      "cleanup_before_rename",
			configure: failUnlinkAroundRename(false, fault),
			wantClass: canonicalCommitPrecommit,
		},
		{
			// The same cleanup seam AFTER the rename published the new bytes, so
			// the visible identity is NEW. Keyed on the observed rename, not on a
			// call ordinal, so a changed number of cleanup calls cannot silently
			// move this row to the other side of the commit point.
			name:      "cleanup_after_rename",
			configure: failUnlinkAroundRename(true, fault),
			wantClass: canonicalCommitTerminalNew,
			published: true,
		},
		{
			name: "parent_fsync",
			configure: func(_ *testing.T, _ *BlockStore, ops *atomicWriteOps) {
				ops.syncParent = func(string) error { return fault }
			},
			wantClass: canonicalCommitTerminalNew,
			published: true,
		},
		{
			// Parent fsync fails AND the committed file is gone by the time the
			// one strict readback runs: neither identity is provable.
			name: "exact_visible_reread",
			configure: func(t *testing.T, store *BlockStore, ops *atomicWriteOps) {
				ops.syncParent = func(string) error {
					if err := os.Remove(store.indexPath); err != nil && !errors.Is(err, os.ErrNotExist) {
						t.Errorf("remove index: %v", err)
					}
					return fault
				}
			},
			wantClass: canonicalCommitTerminalUnknown,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := mustCreateBlockStore(t, BlockStorePath(t.TempDir()))
			mustCommitCanonicalIndex(t, store, []string{row0})
			before, diskBefore := captureCanonicalRAMImage(store), mustReadIndexFile(t, store)
			prepared := mustPrepareCanonicalIndex(t, store, []string{row0, row1})

			withAtomicWriteOps(t, func(ops *atomicWriteOps) { tc.configure(t, store, ops) })
			got := prepared.commit(store)
			if got.class != tc.wantClass {
				t.Fatalf("commit = %s (%v), want %s", got.class, got.err, tc.wantClass)
			}
			if tc.published {
				// A LITERAL fixture: on the terminal-NEW rows the readback has already
				// replaced prepared.newRaw, so comparing against it would assert x == x.
				assertPublishedCanonicalImage(t, store, []string{row0, row1}, mustEncodeCanonicalIndex(t, []string{row0, row1}))
				return
			}
			assertCanonicalRAMUnchanged(t, store, before, tc.name)
			if tc.wantClass == canonicalCommitPrecommit && !bytes.Equal(mustReadIndexFile(t, store), diskBefore) {
				t.Fatalf("%s: a pre-commit fault changed the visible index bytes", tc.name)
			}
		})
	}
}

// TestBlockStoreIndexRawTracksVisibleBytes: the legacy mutate-then-save path
// stays on its baseline ordering, but its visible identity must remain the
// bytes on disk — including after a failed save, where the disk still holds the
// PREVIOUS image.
func TestBlockStoreIndexRawTracksVisibleBytes(t *testing.T) {
	header := testHeaderBytes(0xa0, 7)
	hash := mustHeaderHash(t, header)
	// Each subtest owns its store: sharing one would make truncate_canonical's
	// empty index the silent precondition of every step after it.
	freshStore := func(t *testing.T) *BlockStore {
		t.Helper()
		store := mustCreateBlockStore(t, BlockStorePath(t.TempDir()))
		if err := store.PutBlock(0, hash, header, []byte("block")); err != nil {
			t.Fatalf("PutBlock: %v", err)
		}
		return store
	}
	for _, step := range []struct {
		name    string
		call    func(*BlockStore) error
		wantTip bool
	}{
		{"set_canonical_tip", func(store *BlockStore) error { return store.SetCanonicalTip(0, hash) }, true},
		{"restore_canonical_index", func(store *BlockStore) error {
			return store.RestoreCanonicalIndex([]string{hex.EncodeToString(hash[:])})
		}, true},
		{"truncate_canonical", func(store *BlockStore) error { return store.TruncateCanonical(0) }, false},
		{"restore_empty_index", func(store *BlockStore) error { return store.RestoreCanonicalIndex([]string{}) }, false},
		{"restore_nil_index", func(store *BlockStore) error { return store.RestoreCanonicalIndex(nil) }, false},
	} {
		t.Run(step.name, func(t *testing.T) {
			store := freshStore(t)
			if err := step.call(store); err != nil {
				t.Fatalf("%s: %v", step.name, err)
			}
			if !bytes.Equal(store.visibleIndexBytes(), mustReadIndexFile(t, store)) {
				t.Fatalf("%s left the visible identity out of step with the disk", step.name)
			}
			// A persisted index must be a REOPENABLE index: both empty-list
			// writers fold to nil, which marshals to the null the open refuses.
			reopened, err := OpenBlockStore(store.rootPath)
			if err != nil {
				t.Fatalf("%s: reopen refused the index it just wrote: %v", step.name, err)
			}
			if _, _, ok, err := reopened.Tip(); err != nil || ok != step.wantTip {
				t.Fatalf("%s: reopened tip ok=%v err=%v, want ok=%v", step.name, ok, err, step.wantTip)
			}
		})
	}

	t.Run("restore_refuses_a_row_the_strict_open_would_refuse", func(t *testing.T) {
		// parseHex accepts spellings the on-disk decoder does not, so an
		// unrefused restore would persist an index this store cannot reopen.
		store := freshStore(t)
		disk := mustReadIndexFile(t, store)
		hashHex := hex.EncodeToString(hash[:])
		for _, row := range []string{strings.ToUpper(hashHex), " " + hashHex, hashHex + " "} {
			if err := store.RestoreCanonicalIndex([]string{row}); err == nil || !strings.Contains(err.Error(), "not 64 lowercase hex characters") {
				t.Fatalf("RestoreCanonicalIndex(%q) = %v, want the strict spelling refusal", row, err)
			}
			if _, err := OpenBlockStore(store.rootPath); err != nil || !bytes.Equal(mustReadIndexFile(t, store), disk) {
				t.Fatalf("the refused restore left an index the strict open refuses: %v", err)
			}
		}
	})

	t.Run("failed_save_keeps_the_disk_identity", func(t *testing.T) {
		store := freshStore(t)
		identityBefore, diskBefore := store.visibleIndexBytes(), mustReadIndexFile(t, store)
		withAtomicWriteOps(t, func(ops *atomicWriteOps) {
			ops.openScratch = func(string, int, os.FileMode) (atomicWriteScratchFile, error) { return nil, os.ErrPermission }
		})
		err := store.TruncateCanonical(0)
		if got := requireAtomicWriteError(t, err, atomicWriteBeforeNamespaceCommit, atomicWriteOverwrite); !errors.Is(got.primary, os.ErrPermission) {
			t.Fatalf("TruncateCanonical err = %v, want the injected pre-commit fault", err)
		}
		if !bytes.Equal(store.visibleIndexBytes(), identityBefore) || !bytes.Equal(mustReadIndexFile(t, store), diskBefore) {
			t.Fatalf("a failed save moved the visible identity off the bytes on disk")
		}
		// The documented consequence: the legacy path mutates RAM BEFORE the
		// save, so a failed save leaves bs.index leading the disk and only the
		// visible identity still describing it. A caller that derived its next
		// canonical list from RAM here would promote state the disk refused.
		store.stateMu.RLock()
		ram := append([]string(nil), store.index.Canonical...)
		store.stateMu.RUnlock()
		payload, err := openStoreEnvelope(storeEnvelopeBlockIndex, store.visibleIndexBytes())
		if err != nil {
			t.Fatalf("openStoreEnvelope(visible identity): %v", err)
		}
		visible, err := decodeBlockStoreIndex(payload)
		if err != nil {
			t.Fatalf("decodeBlockStoreIndex(visible identity): %v", err)
		}
		if slices.Equal(ram, visible.Canonical) {
			t.Fatalf("RAM %v equals the visible identity %v; the failed save left nothing to warn about", ram, visible.Canonical)
		}
	})

	// A parent-fsync fault fails the save AFTER the rename published the new
	// bytes, so the disk holds the NEW image and the visible identity must move
	// with it even though the call returned an error.
	t.Run("post_commit_save_failure_adopts_the_new_disk_identity", func(t *testing.T) {
		store := freshStore(t)
		// Start from the empty index so the save that crosses the rename
		// really writes DIFFERENT bytes: re-saving the same image would make
		// "the identity moved" unobservable.
		if err := store.TruncateCanonical(0); err != nil {
			t.Fatalf("TruncateCanonical: %v", err)
		}
		before := store.visibleIndexBytes()
		withAtomicWriteOps(t, func(ops *atomicWriteOps) {
			ops.syncParent = func(string) error { return os.ErrPermission }
		})
		err := store.SetCanonicalTip(0, hash)
		if !isAtomicWritePostCommit(err) {
			t.Fatalf("SetCanonicalTip err = %v, want a post-commit atomic write failure", err)
		}
		identity, disk := store.visibleIndexBytes(), mustReadIndexFile(t, store)
		if !bytes.Equal(identity, disk) {
			t.Fatalf("post-commit save failure left the visible identity off the bytes on disk")
		}
		if bytes.Equal(identity, before) {
			t.Fatalf("the rename crossed, so the visible identity must be the new bytes")
		}
	})
}

// TestBlockStoreOpenKeepsExactDiskIndexBytes: the visible identity is the bytes
// THEMSELVES, never a re-encoding. Two inner spellings decode to the same index,
// so an identity derived by re-encoding would claim bytes the disk does not hold.
func TestBlockStoreOpenKeepsExactDiskIndexBytes(t *testing.T) {
	root := BlockStorePath(t.TempDir())
	store := mustCreateBlockStore(t, root)
	row := canonicalIndexRow(0xd0)

	// Same rows, different inner JSON whitespace, re-enveloped.
	payload := []byte("{\n \"canonical\": [\n  \"" + row + "\"\n ],\n \"version\": 1\n}\n")
	planted, err := marshalStoreEnvelope(storeEnvelopeBlockIndex, payload)
	if err != nil {
		t.Fatalf("marshalStoreEnvelope: %v", err)
	}
	canonicalSpelling := mustEncodeCanonicalIndex(t, []string{row})
	if bytes.Equal(planted, canonicalSpelling) {
		t.Fatalf("the planted spelling must differ from the encoder's own bytes")
	}
	mustPlantIndex(t, store, planted)

	reopened := mustOpenBlockStore(t, root)
	if got := reopened.visibleIndexBytes(); !bytes.Equal(got, planted) {
		t.Fatalf("visible identity is not the bytes on disk")
	}
	if !slices.Equal(reopened.index.Canonical, []string{row}) {
		t.Fatalf("decoded canonical = %v, want the planted row", reopened.index.Canonical)
	}
}

// presenceFixture builds one store plus the artifact spellings the presence
// rows need: real block bytes whose header hashes to `hash`, that header, a
// second block's header (parses, hashes to something else), a valid hash-bound
// undo, and an undo bound to a DIFFERENT block.
type presenceFixture struct {
	store       *BlockStore
	hash        [32]byte
	blockBytes  []byte
	headerBytes []byte
	otherBlock  []byte
	otherHeader []byte
	undoBytes   []byte
	otherUndo   []byte
	variantUndo []byte
	blockPath   string
	headerPath  string
	undoPath    string
}

func newPresenceFixture(t *testing.T) *presenceFixture {
	t.Helper()
	store := mustCreateBlockStore(t, BlockStorePath(t.TempDir()))
	genesis, err := consensus.ParseBlockBytes(devnetGenesisBlockBytes)
	if err != nil {
		t.Fatalf("ParseBlockBytes(genesis): %v", err)
	}
	other, otherHeader := anotherDevnetBlock(t, consensus.POW_LIMIT)
	otherHash := mustHeaderHash(t, otherHeader)
	variant := undoTestUndo()
	variant.BlockHeight = 999
	leaf := hex.EncodeToString(devnetGenesisBlockHash[:])
	return &presenceFixture{
		store:       store,
		hash:        devnetGenesisBlockHash,
		blockBytes:  devnetGenesisBlockBytes,
		headerBytes: genesis.HeaderBytes,
		otherBlock:  other,
		otherHeader: otherHeader,
		undoBytes:   []byte(mustMarshalUndoEnvelope(t, devnetGenesisBlockHash, undoTestUndo())),
		otherUndo:   []byte(mustMarshalUndoEnvelope(t, otherHash, undoTestUndo())),
		variantUndo: []byte(mustMarshalUndoEnvelope(t, devnetGenesisBlockHash, variant)),
		blockPath:   filepath.Join(store.blocksDir, leaf+".bin"),
		headerPath:  filepath.Join(store.headersDir, leaf+".bin"),
		undoPath:    filepath.Join(store.undoDir, leaf+".json"),
	}
}

// setCanonicalMembership makes hash a canonical member (or not) without going
// through a mutator: presence classification reads membership only.
func (f *presenceFixture) setCanonicalMembership(member bool) {
	f.store.stateMu.Lock()
	defer f.store.stateMu.Unlock()
	if member {
		f.store.index.Canonical = []string{hex.EncodeToString(f.hash[:])}
		f.store.canonicalHeightByHash = map[[32]byte]uint64{f.hash: 0}
		return
	}
	f.store.index.Canonical = []string{}
	f.store.canonicalHeightByHash = map[[32]byte]uint64{}
}

func (f *presenceFixture) plant(t *testing.T, path string, content []byte) {
	t.Helper()
	if content == nil {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("remove %s: %v", path, err)
		}
		return
	}
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// artifactFingerprint proves inspection repaired, truncated or rewrote nothing.
// It digests the FULL contents: a length plus a prefix would miss a rewrite that
// keeps the size and changes the tail.
func (f *presenceFixture) artifactFingerprint(t *testing.T) string {
	t.Helper()
	out := ""
	for _, path := range []string{f.blockPath, f.headerPath, f.undoPath} {
		raw, err := os.ReadFile(path) // #nosec G304 -- test-local path.
		switch {
		case errors.Is(err, os.ErrNotExist):
			out += path + "=absent;"
		case err != nil:
			t.Fatalf("fingerprint %s: %v", path, err)
		default:
			out += fmt.Sprintf("%s=%x;", path, sha256.Sum256(raw))
		}
	}
	return out
}

// TestInspectBlockPresenceTruthTable walks the CLOSED presence table over every
// block/header/undo state combination, canonical and noncanonical, against a LITERAL
// oracle transcribed row by row from the contract's required_behavior wording — a
// canonical member is CANONICAL only for valid block + matching header + valid
// hash-bound undo and every other canonical combination is store-integrity evidence;
// a noncanonical hash is ABSENT only with all three leaves absent,
// STORED_NONCANONICAL only in the three named shapes, and LOCAL_STORE_ERROR(noncanonical)
// otherwise. Nothing here is derived from the classifier under test, header existence
// alone is never presence (C01-FORBID-PRESENCE-001), and nothing is repaired.
func TestInspectBlockPresenceTruthTable(t *testing.T) {
	// Short aliases keep each authored row on one readable line.
	const (
		aA, aV, aX       = BlockArtifactAbsent, BlockArtifactValid, BlockArtifactInvalid
		cABS, cSNC       = BlockPresenceAbsent, BlockPresenceStoredNoncanonical
		cCAN, cERR       = BlockPresenceCanonical, BlockPresenceLocalStoreError
		sCAN, sNON       = BlockPresenceScopeCanonical, BlockPresenceScopeNoncanonical
		wantCombinations = 2 * 3 * 3 * 3
	)
	table := []struct {
		member              bool
		block, header, undo BlockArtifactState
		class               BlockPresenceClass
		scope               BlockPresenceScope
	}{
		// Noncanonical.
		{false, aA, aA, aA, cABS, ""},
		{false, aA, aA, aV, cERR, sNON},
		{false, aA, aA, aX, cERR, sNON},
		{false, aA, aV, aA, cERR, sNON},
		{false, aA, aV, aV, cERR, sNON},
		{false, aA, aV, aX, cERR, sNON},
		{false, aA, aX, aA, cERR, sNON},
		{false, aA, aX, aV, cERR, sNON},
		{false, aA, aX, aX, cERR, sNON},
		{false, aV, aA, aA, cSNC, ""},
		{false, aV, aA, aV, cERR, sNON},
		{false, aV, aA, aX, cERR, sNON},
		{false, aV, aV, aA, cSNC, ""},
		{false, aV, aV, aV, cSNC, ""},
		{false, aV, aV, aX, cERR, sNON},
		{false, aV, aX, aA, cERR, sNON},
		{false, aV, aX, aV, cERR, sNON},
		{false, aV, aX, aX, cERR, sNON},
		{false, aX, aA, aA, cERR, sNON},
		{false, aX, aA, aV, cERR, sNON},
		{false, aX, aA, aX, cERR, sNON},
		{false, aX, aV, aA, cERR, sNON},
		{false, aX, aV, aV, cERR, sNON},
		{false, aX, aV, aX, cERR, sNON},
		{false, aX, aX, aA, cERR, sNON},
		{false, aX, aX, aV, cERR, sNON},
		{false, aX, aX, aX, cERR, sNON},
		// Canonical member.
		{true, aA, aA, aA, cERR, sCAN},
		{true, aA, aA, aV, cERR, sCAN},
		{true, aA, aA, aX, cERR, sCAN},
		{true, aA, aV, aA, cERR, sCAN},
		{true, aA, aV, aV, cERR, sCAN},
		{true, aA, aV, aX, cERR, sCAN},
		{true, aA, aX, aA, cERR, sCAN},
		{true, aA, aX, aV, cERR, sCAN},
		{true, aA, aX, aX, cERR, sCAN},
		{true, aV, aA, aA, cERR, sCAN},
		{true, aV, aA, aV, cERR, sCAN},
		{true, aV, aA, aX, cERR, sCAN},
		{true, aV, aV, aA, cERR, sCAN},
		{true, aV, aV, aV, cCAN, ""},
		{true, aV, aV, aX, cERR, sCAN},
		{true, aV, aX, aA, cERR, sCAN},
		{true, aV, aX, aV, cERR, sCAN},
		{true, aV, aX, aX, cERR, sCAN},
		{true, aX, aA, aA, cERR, sCAN},
		{true, aX, aA, aV, cERR, sCAN},
		{true, aX, aA, aX, cERR, sCAN},
		{true, aX, aV, aA, cERR, sCAN},
		{true, aX, aV, aV, cERR, sCAN},
		{true, aX, aV, aX, cERR, sCAN},
		{true, aX, aX, aA, cERR, sCAN},
		{true, aX, aX, aV, cERR, sCAN},
		{true, aX, aX, aX, cERR, sCAN},
	}

	if len(table) != wantCombinations {
		t.Fatalf("table has %d rows, want %d", len(table), wantCombinations)
	}
	seen := make(map[string]bool, wantCombinations)
	fixture := newPresenceFixture(t)
	// The artifact reads must run INSIDE the one presence snapshot: every leaf
	// reports the lock state it actually runs under, and the store's write
	// lock is unobtainable while the snapshot holds its RLock — so a read
	// hoisted out of the snapshot takes it and fails here.
	// An escape is reported against the ROW; the outer t would name the table.
	rowT := t
	fixture.store.leafProbe = func() {
		if fixture.store.stateMu.TryLock() {
			fixture.store.stateMu.Unlock()
			rowT.Error("leaf read ran outside the presence snapshot")
		}
	}
	for _, row := range table {
		name := fmt.Sprintf("member_%v/block_%s/header_%s/undo_%s", row.member, row.block, row.header, row.undo)
		seen[name] = true
		t.Run(name, func(t *testing.T) {
			defer func(parent *testing.T) { rowT = parent }(rowT)
			rowT = t
			leaves := BlockArtifactLeaves{Block: row.block, Header: row.header, Undo: row.undo}
			want := BlockPresence{Class: row.class, Scope: row.scope, Leaves: leaves}
			fixture.setCanonicalMembership(row.member)
			fixture.plant(t, fixture.blockPath, presenceArtifactBytes(row.block, fixture.blockBytes, fixture.otherBlock))
			fixture.plant(t, fixture.headerPath, presenceArtifactBytes(row.header, fixture.headerBytes, fixture.otherHeader))
			fixture.plant(t, fixture.undoPath, presenceArtifactBytes(row.undo, fixture.undoBytes, fixture.otherUndo))
			before := fixture.artifactFingerprint(t)

			if got := fixture.store.InspectBlockPresence(fixture.hash); got != want {
				t.Fatalf("presence = %s leaves=%+v, want %s leaves=%+v", got, got.Leaves, want, want.Leaves)
			}
			if after := fixture.artifactFingerprint(t); after != before {
				t.Fatalf("inspection rewrote an artifact")
			}
		})
	}
	states := []BlockArtifactState{BlockArtifactAbsent, BlockArtifactValid, BlockArtifactInvalid}
	for _, member := range []bool{false, true} {
		for _, block := range states {
			for _, header := range states {
				for _, undo := range states {
					name := fmt.Sprintf("member_%v/block_%s/header_%s/undo_%s", member, block, header, undo)
					if !seen[name] {
						t.Errorf("table never names %s", name)
					}
				}
			}
		}
	}
}

// presenceArtifactBytes maps a leaf state to the bytes that produce it: nil
// removes the file, valid plants the hash-bound artifact, invalid plants a
// well-formed artifact that belongs to a DIFFERENT block — the strongest
// invalid spelling, since it passes every check except identity.
func presenceArtifactBytes(state BlockArtifactState, valid, invalid []byte) []byte {
	switch state {
	case BlockArtifactValid:
		return valid
	case BlockArtifactInvalid:
		return invalid
	default:
		return nil
	}
}

// TestInspectBlockPresenceHostileArtifactSpellings pins the leaf mapping the
// truth table then generalizes: every artifact that is neither absent nor bound
// to the requested hash reads as invalid, whatever shape the corruption takes.
// A valid-but-byte-different undo is the one row that stays VALID: presence
// checks hash binding and envelope integrity, not undo semantics — and it is
// still never rewritten.
func TestInspectBlockPresenceHostileArtifactSpellings(t *testing.T) {
	fixture := newPresenceFixture(t)
	for _, tc := range []struct {
		name       string
		block      []byte
		header     []byte
		undo       []byte
		wantLeaves BlockArtifactLeaves
		wantClass  BlockPresenceClass
		wantScope  BlockPresenceScope
	}{
		{
			name: "unparseable_block", block: []byte("not a block"), header: fixture.headerBytes, undo: fixture.undoBytes,
			wantLeaves: BlockArtifactLeaves{Block: BlockArtifactInvalid, Header: BlockArtifactValid, Undo: BlockArtifactValid},
			wantClass:  BlockPresenceLocalStoreError, wantScope: BlockPresenceScopeNoncanonical,
		},
		{
			name: "truncated_block", block: fixture.blockBytes[:len(fixture.blockBytes)/2], header: fixture.headerBytes, undo: nil,
			wantLeaves: BlockArtifactLeaves{Block: BlockArtifactInvalid, Header: BlockArtifactValid, Undo: BlockArtifactAbsent},
			wantClass:  BlockPresenceLocalStoreError, wantScope: BlockPresenceScopeNoncanonical,
		},
		{
			name: "mismatched_header", block: fixture.blockBytes, header: fixture.otherHeader, undo: nil,
			wantLeaves: BlockArtifactLeaves{Block: BlockArtifactValid, Header: BlockArtifactInvalid, Undo: BlockArtifactAbsent},
			wantClass:  BlockPresenceLocalStoreError, wantScope: BlockPresenceScopeNoncanonical,
		},
		{
			name: "short_header", block: fixture.blockBytes, header: []byte{0x00}, undo: nil,
			wantLeaves: BlockArtifactLeaves{Block: BlockArtifactValid, Header: BlockArtifactInvalid, Undo: BlockArtifactAbsent},
			wantClass:  BlockPresenceLocalStoreError, wantScope: BlockPresenceScopeNoncanonical,
		},
		{
			name: "wrong_hash_bound_undo", block: fixture.blockBytes, header: fixture.headerBytes, undo: fixture.otherUndo,
			wantLeaves: BlockArtifactLeaves{Block: BlockArtifactValid, Header: BlockArtifactValid, Undo: BlockArtifactInvalid},
			wantClass:  BlockPresenceLocalStoreError, wantScope: BlockPresenceScopeNoncanonical,
		},
		{
			name: "malformed_undo", block: fixture.blockBytes, header: fixture.headerBytes, undo: []byte("{"),
			wantLeaves: BlockArtifactLeaves{Block: BlockArtifactValid, Header: BlockArtifactValid, Undo: BlockArtifactInvalid},
			wantClass:  BlockPresenceLocalStoreError, wantScope: BlockPresenceScopeNoncanonical,
		},
		{
			name: "byte_different_but_hash_bound_undo", block: fixture.blockBytes, header: fixture.headerBytes, undo: fixture.variantUndo,
			wantLeaves: BlockArtifactLeaves{Block: BlockArtifactValid, Header: BlockArtifactValid, Undo: BlockArtifactValid},
			wantClass:  BlockPresenceStoredNoncanonical,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture.setCanonicalMembership(false)
			fixture.plant(t, fixture.blockPath, tc.block)
			fixture.plant(t, fixture.headerPath, tc.header)
			fixture.plant(t, fixture.undoPath, tc.undo)
			before := fixture.artifactFingerprint(t)

			want := BlockPresence{Class: tc.wantClass, Scope: tc.wantScope, Leaves: tc.wantLeaves}
			if got := fixture.store.InspectBlockPresence(fixture.hash); got != want {
				t.Fatalf("noncanonical presence = %s leaves=%+v, want %s leaves=%+v", got, got.Leaves, want, want.Leaves)
			}
			if after := fixture.artifactFingerprint(t); after != before {
				t.Fatalf("inspection rewrote an artifact")
			}

			// The same evidence under canonical membership is store-integrity
			// evidence unless every leaf is valid.
			fixture.setCanonicalMembership(true)
			wantCanonical := BlockPresence{Class: BlockPresenceLocalStoreError, Scope: BlockPresenceScopeCanonical, Leaves: tc.wantLeaves}
			if tc.wantLeaves == (BlockArtifactLeaves{Block: BlockArtifactValid, Header: BlockArtifactValid, Undo: BlockArtifactValid}) {
				wantCanonical = BlockPresence{Class: BlockPresenceCanonical, Leaves: tc.wantLeaves}
			}
			if got := fixture.store.InspectBlockPresence(fixture.hash); got != wantCanonical {
				t.Fatalf("canonical presence = %s leaves=%+v, want %s leaves=%+v", got, got.Leaves, wantCanonical, wantCanonical.Leaves)
			}
		})
	}
}

// TestCanonicalFrozenAndLocalIdentityStrings separates the two kinds of string
// these surfaces render. FROZEN (RUB-922 C01 corpus): the four presence CLASSES, the
// scoped `LOCAL_STORE_ERROR(noncanonical)` row, and four commit identities. LOCAL:
// the canonical-scope rendering — the scope and leaves stay in the struct as the
// evidence the owning transition latches as TERMINAL_STORE_INTEGRITY(canonical), but
// the rendered identity is the bare contract class — plus the two commit classes that
// name no frozen identity at all. A zero-value presence never renders a scoped error.
func TestCanonicalFrozenAndLocalIdentityStrings(t *testing.T) {
	for _, tc := range []struct {
		presence BlockPresence
		want     string
	}{
		// Frozen corpus rows.
		{BlockPresence{Class: BlockPresenceAbsent}, "ABSENT"},
		{BlockPresence{Class: BlockPresenceStoredNoncanonical}, "STORED_NONCANONICAL"},
		{BlockPresence{Class: BlockPresenceCanonical}, "CANONICAL"},
		{BlockPresence{Class: BlockPresenceLocalStoreError, Scope: BlockPresenceScopeNoncanonical}, "LOCAL_STORE_ERROR(noncanonical)"},
		// Local renderings.
		{BlockPresence{Class: BlockPresenceLocalStoreError, Scope: BlockPresenceScopeCanonical}, "LOCAL_STORE_ERROR"},
		{BlockPresence{}, ""},
	} {
		if got := tc.presence.String(); got != tc.want {
			t.Fatalf("presence identity = %q, want %q", got, tc.want)
		}
	}

	// Every commit rendering is DISTINCT: a LOCAL class that collided with a
	// frozen one would publish a corpus identity it never earned.
	rendered := map[string]canonicalCommitClass{}
	for _, tc := range []struct {
		class canonicalCommitClass
		want  string
	}{
		{canonicalCommitPrecommit, "LOCAL_PERSISTENCE_ERROR(precommit)"},
		{canonicalCommitTerminalOld, "TERMINAL_PERSISTENCE(old)"},
		{canonicalCommitTerminalNew, "TERMINAL_PERSISTENCE(new)"},
		{canonicalCommitTerminalUnknown, "TERMINAL_PERSISTENCE(neither_or_unreadable)"},
		{canonicalCommitted, "COMMITTED"},
		{canonicalCommitStale, "STALE_PREPARED_IMAGE"},
	} {
		got := string(tc.class)
		if got != tc.want {
			t.Fatalf("commit identity = %q, want %q", got, tc.want)
		}
		if other, collides := rendered[got]; collides {
			t.Fatalf("%q renders for both %s and %s", got, other, tc.class)
		}
		rendered[got] = tc.class
	}
}

// TestInspectBlockPresenceNilStoreIsStoreError: a nil store is a programming
// error that proves nothing about any artifact, so it fails closed on the
// CANONICAL scope the owner latches and must never render the frozen
// non-latching LOCAL_STORE_ERROR(noncanonical) corpus row.
func TestInspectBlockPresenceNilStoreIsStoreError(t *testing.T) {
	var store *BlockStore
	want := BlockPresence{
		Class:  BlockPresenceLocalStoreError,
		Scope:  BlockPresenceScopeCanonical,
		Leaves: BlockArtifactLeaves{Block: BlockArtifactInvalid, Header: BlockArtifactInvalid, Undo: BlockArtifactInvalid},
	}
	if got := store.InspectBlockPresence([32]byte{}); got != want || got.String() != "LOCAL_STORE_ERROR" {
		t.Fatalf("nil-store presence = %s leaves=%+v, want %s leaves=%+v", got, got.Leaves, want, want.Leaves)
	}
}

// TestPreparedCanonicalIndexCarriesOnlyPlannedCanonicalChainWork pins the sole
// authorized extension of the prepared-commit primitive: the chain-work cache
// published with a committed image is the OLD cache intersected with the PLANNED
// canonical identity. An append keeps the whole surviving common prefix, a reorg
// drops every disconnected row, and a hash that was only ever on a side branch is
// never carried — cachedChainWork answers without re-checking membership, so an
// entry for a row this identity no longer holds would be a wrong answer.
func TestPreparedCanonicalIndexCarriesOnlyPlannedCanonicalChainWork(t *testing.T) {
	hashHex := func(h [32]byte) string { return hex.EncodeToString(h[:]) }
	newStore := func(t *testing.T) (*BlockStore, [32]byte, [32]byte, [32]byte, [32]byte) {
		t.Helper()
		store := mustCreateBlockStore(t, filepath.Join(t.TempDir(), "store"))
		genesis := mustHeaderHash(t, testHeaderBytes(0x10, 1))
		rowOne := mustHeaderHash(t, testHeaderBytes(0x11, 2))
		replacement := mustHeaderHash(t, testHeaderBytes(0x12, 3))
		sideOnly := mustHeaderHash(t, testHeaderBytes(0x13, 4))
		if err := store.RestoreCanonicalIndex([]string{hashHex(genesis), hashHex(rowOne)}); err != nil {
			t.Fatalf("RestoreCanonicalIndex: %v", err)
		}
		// Seed the cache the way a chain-work walk would: canonical rows plus one
		// entry for a hash that is only ever on a side branch.
		store.stateMu.Lock()
		store.chainWorkByHash[genesis] = big.NewInt(7)
		store.chainWorkByHash[rowOne] = big.NewInt(9)
		store.chainWorkByHash[sideOnly] = big.NewInt(11)
		store.stateMu.Unlock()
		return store, genesis, rowOne, replacement, sideOnly
	}
	carried := func(t *testing.T, store *BlockStore) map[[32]byte]string {
		t.Helper()
		store.stateMu.RLock()
		defer store.stateMu.RUnlock()
		out := make(map[[32]byte]string, len(store.chainWorkByHash))
		for hash, work := range store.chainWorkByHash {
			out[hash] = work.String()
		}
		return out
	}

	t.Run("append keeps the surviving prefix", func(t *testing.T) {
		store, genesis, rowOne, appended, sideOnly := newStore(t)
		store.stateMu.RLock()
		oldEntry := store.chainWorkByHash[genesis]
		store.stateMu.RUnlock()
		prepared := mustPrepareCanonicalIndex(t, store, []string{hashHex(genesis), hashHex(rowOne), hashHex(appended)})
		if got := prepared.commit(store); got.class != canonicalCommitted {
			t.Fatalf("commit class=%q err=%v", got.class, got.err)
		}
		// Carried by VALUE, not by pointer: mutating the entry the old cache
		// still references must not move the published one. Equal strings cannot
		// tell a clone from an alias, so the aliasing is what is asserted.
		oldEntry.SetInt64(1 << 40)
		got := carried(t, store)
		if len(got) != 2 || got[genesis] != "7" || got[rowOne] != "9" {
			t.Fatalf("carried=%v, want exactly the two canonical prefix entries", got)
		}
		if _, present := got[sideOnly]; present {
			t.Fatal("a side-only hash was carried into the planned identity")
		}
		if _, present := got[appended]; present {
			t.Fatal("an entry appeared for a row whose work was never computed")
		}
	})

	t.Run("reorg drops the disconnected row", func(t *testing.T) {
		store, genesis, rowOne, replacement, _ := newStore(t)
		prepared := mustPrepareCanonicalIndex(t, store, []string{hashHex(genesis), hashHex(replacement)})
		if got := prepared.commit(store); got.class != canonicalCommitted {
			t.Fatalf("commit class=%q err=%v", got.class, got.err)
		}
		got := carried(t, store)
		if len(got) != 1 || got[genesis] != "7" {
			t.Fatalf("carried=%v, want only the common-prefix entry", got)
		}
		if _, present := got[rowOne]; present {
			t.Fatal("work for the disconnected row survived the reorg")
		}
	})

}
