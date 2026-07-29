package node

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
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
	// Only the readFileByPathFn injection is relevant after the E.3
	// TOCTOU hardening: writeFileIfAbsent no longer routes writes
	// through writeFileAtomicFn (it goes directly through
	// allocateAndWriteTemp + os.Link), so mocking writeFileAtomicFn
	// here was dead-but-harmless and has been removed.
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
