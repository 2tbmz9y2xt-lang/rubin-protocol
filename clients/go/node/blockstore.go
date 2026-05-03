package node

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sync"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

var (
	readFileByPathFn  = readFileByPath
	writeFileAtomicFn = writeFileAtomic
)

const (
	blockStoreIndexVersion = 1
	blockStoreDirName      = "blockstore"
)

type BlockStore struct {
	stateMu sync.RWMutex

	rootPath   string
	indexPath  string
	blocksDir  string
	headersDir string
	undoDir    string
	index      blockStoreIndexDisk

	canonicalHeightByHash map[[32]byte]uint64
	chainWorkByHash       map[[32]byte]*big.Int
}

// Block/header/undo blobs are append-only. The canonical chain view is the index file,
// updated via atomic rename. Rollback paths rely on restoring that canonical index; stale
// blob files are tolerated as unreachable garbage, not live chain state.

type blockStoreIndexDisk struct {
	Canonical []string `json:"canonical"`
	Version   uint32   `json:"version"`
}

func BlockStorePath(dataDir string) string {
	return filepath.Join(dataDir, blockStoreDirName)
}

func OpenBlockStore(rootPath string) (*BlockStore, error) {
	indexPath := filepath.Join(rootPath, "index.json")
	blocksDir := filepath.Join(rootPath, "blocks")
	headersDir := filepath.Join(rootPath, "headers")
	undoDir := filepath.Join(rootPath, "undo")

	if err := os.MkdirAll(blocksDir, 0o700); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(headersDir, 0o700); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(undoDir, 0o700); err != nil {
		return nil, err
	}

	index, err := loadBlockStoreIndex(indexPath)
	if err != nil {
		return nil, err
	}
	canonicalHeightByHash, err := buildCanonicalHeightIndex(index.Canonical)
	if err != nil {
		return nil, err
	}

	bs := &BlockStore{
		rootPath:   rootPath,
		indexPath:  indexPath,
		blocksDir:  blocksDir,
		headersDir: headersDir,
		undoDir:    undoDir,
		index:      index,

		canonicalHeightByHash: canonicalHeightByHash,
		chainWorkByHash:       make(map[[32]byte]*big.Int),
	}
	return bs, nil
}

func (bs *BlockStore) PutBlock(height uint64, blockHash [32]byte, headerBytes []byte, blockBytes []byte) error {
	if err := bs.StoreBlock(blockHash, headerBytes, blockBytes); err != nil {
		return err
	}
	return bs.SetCanonicalTip(height, blockHash)
}

func (bs *BlockStore) CommitCanonicalBlock(height uint64, blockHash [32]byte, headerBytes []byte, blockBytes []byte, undo *BlockUndo) error {
	if bs == nil {
		return errors.New("nil blockstore")
	}
	if undo == nil {
		return errors.New("nil block undo")
	}
	if err := bs.StoreBlock(blockHash, headerBytes, blockBytes); err != nil {
		return err
	}
	if err := bs.PutUndo(blockHash, undo); err != nil {
		return err
	}
	return bs.SetCanonicalTip(height, blockHash)
}

func (bs *BlockStore) StoreBlock(blockHash [32]byte, headerBytes []byte, blockBytes []byte) error {
	if bs == nil {
		return errors.New("nil blockstore")
	}
	if err := validateBlockHeaderHash(headerBytes, blockHash); err != nil {
		return err
	}
	return bs.persistBlockBytes(blockHash, headerBytes, blockBytes)
}

func (bs *BlockStore) SetCanonicalTip(height uint64, blockHash [32]byte) error {
	if bs == nil {
		return errors.New("nil blockstore")
	}
	bs.stateMu.Lock()
	defer bs.stateMu.Unlock()

	hashHex := hex.EncodeToString(blockHash[:])
	currentLen := uint64(len(bs.index.Canonical))
	switch {
	case height > currentLen:
		return fmt.Errorf("height gap: got %d, expected <= %d", height, currentLen)
	case height == currentLen:
		bs.index.Canonical = append(bs.index.Canonical, hashHex)
		bs.canonicalHeightByHash[blockHash] = height
	case bs.index.Canonical[height] == hashHex:
		// No-op.
	default:
		if err := bs.dropCanonicalStateFromLocked(height); err != nil {
			return err
		}
		nextCanonical := append([]string(nil), bs.index.Canonical[:height]...)
		nextCanonical = append(nextCanonical, hashHex)
		bs.index.Canonical = nextCanonical
		bs.canonicalHeightByHash[blockHash] = height
	}
	return saveBlockStoreIndex(bs.indexPath, bs.index)
}

func (bs *BlockStore) RewindToHeight(height uint64) error {
	if bs == nil {
		return errors.New("nil blockstore")
	}
	if len(bs.index.Canonical) == 0 {
		return nil
	}
	if height >= uint64(len(bs.index.Canonical)) {
		return fmt.Errorf("rewind height out of range: %d", height)
	}
	return bs.TruncateCanonical(height + 1)
}

func (bs *BlockStore) TruncateCanonical(count uint64) error {
	if bs == nil {
		return errors.New("nil blockstore")
	}
	bs.stateMu.Lock()
	defer bs.stateMu.Unlock()
	if count > uint64(len(bs.index.Canonical)) {
		return fmt.Errorf("truncate count out of range: %d", count)
	}
	if err := bs.dropCanonicalStateFromLocked(count); err != nil {
		return err
	}
	bs.index.Canonical = append([]string(nil), bs.index.Canonical[:count]...)
	return saveBlockStoreIndex(bs.indexPath, bs.index)
}

func (bs *BlockStore) CanonicalHash(height uint64) ([32]byte, bool, error) {
	var out [32]byte
	if bs == nil {
		return out, false, errors.New("nil blockstore")
	}
	bs.stateMu.RLock()
	defer bs.stateMu.RUnlock()
	if height >= uint64(len(bs.index.Canonical)) {
		return out, false, nil
	}
	hash, err := parseHex32("canonical hash", bs.index.Canonical[height])
	if err != nil {
		return out, false, err
	}
	return hash, true, nil
}

func (bs *BlockStore) Tip() (uint64, [32]byte, bool, error) {
	var out [32]byte
	if bs == nil {
		return 0, out, false, errors.New("nil blockstore")
	}
	bs.stateMu.RLock()
	defer bs.stateMu.RUnlock()
	height, ok := canonicalTipHeight(bs.index.Canonical)
	if !ok {
		return 0, out, false, nil
	}
	hash, err := parseHex32("tip hash", bs.index.Canonical[height])
	if err != nil {
		return 0, out, false, err
	}
	return height, hash, true, nil
}

func (bs *BlockStore) CanonicalIndexSnapshot() ([]string, error) {
	if bs == nil {
		return nil, errors.New("nil blockstore")
	}
	bs.stateMu.RLock()
	defer bs.stateMu.RUnlock()
	for i, hashHex := range bs.index.Canonical {
		if _, err := parseHex32(fmt.Sprintf("canonical[%d]", i), hashHex); err != nil {
			return nil, err
		}
	}
	return append([]string(nil), bs.index.Canonical...), nil
}

func (bs *BlockStore) RestoreCanonicalIndex(canonical []string) error {
	if bs == nil {
		return errors.New("nil blockstore")
	}
	nextCanonical := append([]string(nil), canonical...)
	nextIndex, err := buildCanonicalHeightIndex(nextCanonical)
	if err != nil {
		return err
	}
	bs.stateMu.Lock()
	defer bs.stateMu.Unlock()
	bs.index.Canonical = nextCanonical
	bs.replaceCanonicalState(nextIndex)
	return saveBlockStoreIndex(bs.indexPath, bs.index)
}

func (bs *BlockStore) GetBlockByHash(blockHash [32]byte) ([]byte, error) {
	if bs == nil {
		return nil, errors.New("nil blockstore")
	}
	return readFileFromDir(bs.blocksDir, hex.EncodeToString(blockHash[:])+".bin")
}

func (bs *BlockStore) GetHeaderByHash(blockHash [32]byte) ([]byte, error) {
	if bs == nil {
		return nil, errors.New("nil blockstore")
	}
	return readFileFromDir(bs.headersDir, hex.EncodeToString(blockHash[:])+".bin")
}

func (bs *BlockStore) ChainWork(tipHash [32]byte) (*big.Int, error) {
	if bs == nil {
		return nil, errors.New("nil blockstore")
	}
	var zero [32]byte
	if tipHash == zero {
		return big.NewInt(0), nil
	}
	if cached, ok := bs.cachedChainWork(tipHash); ok {
		return cached, nil
	}

	hashes := make([][32]byte, 0, 16)
	targets := make([][32]byte, 0, 16)
	seen := make(map[[32]byte]struct{})
	current := tipHash
	for current != zero {
		if cached, ok := bs.cachedChainWork(current); ok {
			total, err := bs.accumulateChainWorkFromTargets(cached, hashes, targets)
			if err != nil {
				return nil, err
			}
			if cachedTip, ok := bs.cachedChainWork(tipHash); ok {
				return cachedTip, nil
			}
			return total, nil
		}
		if _, exists := seen[current]; exists {
			return nil, errors.New("blockstore parent cycle")
		}
		seen[current] = struct{}{}
		headerBytes, err := bs.GetHeaderByHash(current)
		if err != nil {
			return nil, err
		}
		header, err := consensus.ParseBlockHeaderBytes(headerBytes)
		if err != nil {
			return nil, err
		}
		hashes = append(hashes, current)
		targets = append(targets, header.Target)
		current = header.PrevBlockHash
	}
	total, err := consensus.ChainWorkFromTargets(targets)
	if err != nil {
		return nil, err
	}
	if _, err := bs.accumulateChainWorkFromTargets(nil, hashes, targets); err != nil {
		return nil, err
	}
	return total, nil
}

func buildCanonicalHeightIndex(canonical []string) (map[[32]byte]uint64, error) {
	out := make(map[[32]byte]uint64, len(canonical))
	for i, hashHex := range canonical {
		hash, err := parseHex32(fmt.Sprintf("canonical[%d]", i), hashHex)
		if err != nil {
			return nil, err
		}
		out[hash] = uint64(i)
	}
	return out, nil
}

func (bs *BlockStore) rebuildCanonicalHeightIndex() {
	if bs == nil {
		return
	}
	nextIndex, err := buildCanonicalHeightIndex(bs.index.Canonical)
	if err != nil {
		return
	}
	bs.replaceCanonicalState(nextIndex)
}

func (bs *BlockStore) dropCanonicalStateFromLocked(start uint64) error {
	if bs == nil || start >= uint64(len(bs.index.Canonical)) {
		return nil
	}
	nextIndex, err := buildCanonicalHeightIndex(bs.index.Canonical[:start])
	if err != nil {
		return err
	}
	bs.replaceCanonicalState(nextIndex)
	return nil
}

func (bs *BlockStore) replaceCanonicalState(nextIndex map[[32]byte]uint64) {
	if bs == nil {
		return
	}
	bs.canonicalHeightByHash = nextIndex
	bs.chainWorkByHash = make(map[[32]byte]*big.Int)
}

func (bs *BlockStore) cachedChainWork(blockHash [32]byte) (*big.Int, bool) {
	if bs == nil {
		return nil, false
	}
	bs.stateMu.RLock()
	defer bs.stateMu.RUnlock()
	cached, ok := bs.chainWorkByHash[blockHash]
	if !ok {
		return nil, false
	}
	return cloneBigInt(cached), true
}

func (bs *BlockStore) storeChainWorkIfCanonical(blockHash [32]byte, work *big.Int) {
	if bs == nil || work == nil {
		return
	}
	bs.stateMu.Lock()
	defer bs.stateMu.Unlock()
	if _, ok := bs.canonicalHeightByHash[blockHash]; !ok {
		return
	}
	bs.chainWorkByHash[blockHash] = cloneBigInt(work)
}

func (bs *BlockStore) accumulateChainWorkFromTargets(base *big.Int, hashes [][32]byte, targets [][32]byte) (*big.Int, error) {
	running := cloneBigInt(base)
	if running == nil {
		running = big.NewInt(0)
	}
	for i := len(targets) - 1; i >= 0; i-- {
		work, err := consensus.WorkFromTarget(targets[i])
		if err != nil {
			return nil, err
		}
		running.Add(running, work)
		bs.storeChainWorkIfCanonical(hashes[i], running)
	}
	return cloneBigInt(running), nil
}

func cloneBigInt(x *big.Int) *big.Int {
	if x == nil {
		return nil
	}
	return new(big.Int).Set(x)
}

func (bs *BlockStore) PutUndo(blockHash [32]byte, undo *BlockUndo) error {
	if bs == nil {
		return errors.New("nil blockstore")
	}
	raw, err := marshalBlockUndo(undo)
	if err != nil {
		return err
	}
	return writeFileIfAbsent(filepath.Join(bs.undoDir, hex.EncodeToString(blockHash[:])+".json"), raw)
}

func (bs *BlockStore) GetUndo(blockHash [32]byte) (*BlockUndo, error) {
	if bs == nil {
		return nil, errors.New("nil blockstore")
	}
	raw, err := readFileFromDir(bs.undoDir, hex.EncodeToString(blockHash[:])+".json")
	if err != nil {
		return nil, err
	}
	return unmarshalBlockUndo(raw)
}

func loadBlockStoreIndex(path string) (blockStoreIndexDisk, error) {
	raw, err := readFileByPath(path)
	if errors.Is(err, os.ErrNotExist) {
		return blockStoreIndexDisk{
			Version:   blockStoreIndexVersion,
			Canonical: []string{},
		}, nil
	}
	if err != nil {
		return blockStoreIndexDisk{}, err
	}
	var index blockStoreIndexDisk
	if err := json.Unmarshal(raw, &index); err != nil {
		return blockStoreIndexDisk{}, fmt.Errorf("decode blockstore index: %w", err)
	}
	if index.Version != blockStoreIndexVersion {
		return blockStoreIndexDisk{}, fmt.Errorf("unsupported blockstore index version: %d", index.Version)
	}
	for i, hashHex := range index.Canonical {
		if _, err := parseHex32(fmt.Sprintf("canonical[%d]", i), hashHex); err != nil {
			return blockStoreIndexDisk{}, err
		}
	}
	return index, nil
}

func saveBlockStoreIndex(path string, index blockStoreIndexDisk) error {
	raw, err := json.MarshalIndent(index, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	return writeFileAtomicFn(path, raw, 0o600)
}

func validateBlockHeaderHash(headerBytes []byte, blockHash [32]byte) error {
	if len(headerBytes) != consensus.BLOCK_HEADER_BYTES {
		return fmt.Errorf("invalid header length: %d", len(headerBytes))
	}
	computedHash, err := consensus.BlockHash(headerBytes)
	if err != nil {
		return err
	}
	if computedHash != blockHash {
		return errors.New("header hash mismatch")
	}
	return nil
}

func (bs *BlockStore) persistBlockBytes(blockHash [32]byte, headerBytes []byte, blockBytes []byte) error {
	hashHex := hex.EncodeToString(blockHash[:])
	if err := writeFileIfAbsent(filepath.Join(bs.blocksDir, hashHex+".bin"), blockBytes); err != nil {
		return err
	}
	return writeFileIfAbsent(filepath.Join(bs.headersDir, hashHex+".bin"), headerBytes)
}

func updatedCanonicalHashes(canonical []string, height uint64, blockHash [32]byte) ([]string, bool, error) {
	hashHex := hex.EncodeToString(blockHash[:])
	currentLen := uint64(len(canonical))
	switch {
	case height > currentLen:
		return nil, false, fmt.Errorf("height gap: got %d, expected <= %d", height, currentLen)
	case height == currentLen:
		return append(canonical, hashHex), true, nil
	case canonical[height] == hashHex:
		return canonical, false, nil
	default:
		nextCanonical := append([]string(nil), canonical[:height]...)
		nextCanonical = append(nextCanonical, hashHex)
		return nextCanonical, true, nil
	}
}

func canonicalTipHeight(canonical []string) (uint64, bool) {
	if len(canonical) == 0 {
		return 0, false
	}
	return uint64(len(canonical) - 1), true // #nosec G115 -- len(canonical) > 0 is checked above.
}

// writeFileIfAbsent writes content to path only if the destination is
// absent (idempotent replay: a subsequent call with matching bytes is a
// silent no-op). Hardened against the TOCTOU race audited as E.3: the
// previous implementation read then wrote, which could silently
// overwrite a file that appeared between the two syscalls. The new
// implementation writes content to a per-call-unique temp path, then
// uses os.Link for atomic create-if-absent at the syscall layer. On
// EEXIST we read the current destination and preserve the idempotent-
// same-content contract; on content mismatch we surface an explicit
// error — we never silently overwrite.
//
// Mirrors the Rust io_utils::write_file_exclusive helper's hard_link
// flow for cross-client storage parity.
//
// Threat model:
//
//	concurrent actors:  Two writers race on os.Link(tmp, path); exactly
//	                    one link succeeds. The loser sees os.ErrExist,
//	                    reads the winner's content, and returns nil if
//	                    content matches (idempotent replay) or an error
//	                    if it differs (never overwrite). Per-call
//	                    tempPathFor(path, pid, nextTempSeq()) gives
//	                    distinct temp paths so in-process goroutines
//	                    never collide.
//	process crash:      Crash between os.Link and os.Remove(tmp) leaves
//	                    a stale tmp hard-linked to the destination
//	                    inode. That is safe: writeAndSyncTemp uses
//	                    O_CREATE|O_EXCL (no O_TRUNC), so a later call
//	                    hitting the same tmp path gets os.ErrExist from
//	                    allocateAndWriteTemp and retries with a fresh
//	                    seq (16-retry budget). Startup reconcile (E.2)
//	                    sweeps orphan .tmp.* siblings. Crash before
//	                    syncDir leaves the dirent in page cache; the
//	                    fast-path on retry re-runs syncDir and
//	                    propagates its error so durability is surfaced.
//	cross-platform:     Unix (Linux, macOS): os.Link, O_EXCL, dir Sync
//	                    all semantically honored. Windows: Sync on
//	                    directories is a no-op in stdlib; Rubin does
//	                    not ship Windows as a production target.
//	                    Test surfaces that rely on os.Geteuid()/chmod
//	                    for permission-denied paths are gated behind
//	                    //go:build unix.
//	retry / exhaustion: allocateAndWriteTemp retries up to
//	                    maxTempAllocRetries (16) on os.ErrExist with a
//	                    fresh nextTempSeq. Fatal I/O surfaces
//	                    immediately. Exhaustion surfaces as an error
//	                    mentioning the destination path.
//	inode / fs-layer:   os.Link is refcount-safe: destination and tmp
//	                    share the inode; unlinking tmp drops the name
//	                    without affecting data visible through path.
//	                    O_TRUNC on a shared-inode path is intentionally
//	                    avoided everywhere in the helper stack; see
//	                    writeAndSyncTemp for the explicit O_EXCL
//	                    contract.
//	durability:         writeAndSyncTemp fsync's the temp's bytes and
//	                    inode metadata before returning. os.Link then
//	                    exposes the inode under `path`. syncDir on the
//	                    parent flushes the directory entry so the
//	                    rename/link is itself durable. Both the Ok and
//	                    EEXIST-retry branches PROPAGATE the final
//	                    syncDir error — the previous `_ = syncDir(...)`
//	                    double-swallowed EIO through syncDir's own
//	                    best-effort wrapper (Copilot P1 wave-7 on
//	                    PR #1220).
func writeFileIfAbsent(path string, content []byte) error {
	// Fast path: destination already exists. Read once and verify match
	// before attempting any writes. Same behavior as the Rust helper
	// via `write_file_exclusive` + EEXIST branch, but short-circuited
	// here to avoid a useless temp write when the file is already
	// present with the right bytes (dominant case during idempotent
	// replay on sync-engine restart).
	//
	// Copilot P1 on PR #1220: a previous call may have successfully
	// created the destination but returned an error from the final
	// syncDir step. If the caller retries, we land in this fast-path
	// and would silently report nil without ever making the directory
	// entry durable. Re-run syncDir on the idempotent match branch and
	// PROPAGATE its result — syncDir already applies the intended
	// permission policy internally (execute-only/hardened parents are
	// treated as nil return), so propagating does NOT break the
	// idempotent-replay-on-hardened-dir contract; it only surfaces
	// real durability failures (EIO / ENOENT) that would otherwise be
	// silent.
	//
	// Copilot P1 wave-7 on PR #1220: `_ = syncDir(...)` double-
	// swallowed errors — syncDir is already best-effort, so the outer
	// `_ = ...` discarded the exact failures that MUST reach the
	// caller. Propagate via `return` instead.
	if existing, err := readFileByPathFn(path); err == nil {
		if !bytes.Equal(existing, content) {
			return fmt.Errorf("file already exists with different content: %s", path)
		}
		return syncDir(filepath.Dir(path))
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	// Destination is absent at this moment. Write to a unique temp and
	// link it atomically — os.Link fails with os.ErrExist if the
	// destination appears in the meantime, so we cannot silently
	// overwrite under concurrent racing writers.
	tmpPath, err := allocateAndWriteTemp(path, content, 0o600)
	if err != nil {
		return err
	}
	linkErr := os.Link(tmpPath, path)
	// Best-effort unlink of the temp name: the link (if it succeeded) or
	// a pre-existing destination (on EEXIST) holds its own inode ref, so
	// removing the temp path never drops data. A Remove error here is a
	// leaked temp, not a correctness issue, and is intentionally ignored.
	_ = os.Remove(tmpPath)
	if linkErr != nil {
		if errors.Is(linkErr, os.ErrExist) {
			// Race: destination appeared between the fast-path read
			// and our link. Verify content matches (idempotent retry)
			// or surface the drift as an error (never overwrite).
			existing, err := readFileByPathFn(path)
			if err != nil {
				return fmt.Errorf("read existing after link EEXIST %s: %w", path, err)
			}
			if !bytes.Equal(existing, content) {
				return fmt.Errorf("file already exists with different content: %s", path)
			}
			// Propagate parent dir-sync result on the EEXIST-retry
			// branch for the same reason as the fast-path above:
			// syncDir already applies the permission policy, so
			// returning its error surfaces only real durability
			// failures.
			return syncDir(filepath.Dir(path))
		}
		return fmt.Errorf("link %s -> %s: %w", tmpPath, path, linkErr)
	}
	// The new directory entry for `path` must reach stable storage too;
	// temp's sync_all only covered the inode's data, not the dir.
	return syncDir(filepath.Dir(path))
}
