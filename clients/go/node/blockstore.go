package node

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

var (
	readFileByPathFn  = readFileByPathCapped
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
	// indexRaw is the exact visible envelope bytes of indexPath as this store
	// last read or wrote them, and is the identity a prepared commit compares
	// against. It must be the bytes THEMSELVES, never a re-encoding: two inner
	// spellings can decode to the same index, so a re-encoding would make a
	// strict readback claim an identity the disk does not hold.
	indexRaw []byte

	canonicalHeightByHash map[[32]byte]uint64
	chainWorkByHash       map[[32]byte]*big.Int

	// noncanonical is atomically published only by same-package tests; stateMu
	// protects its contents and the short-lived reservation waiters.
	noncanonical        atomic.Pointer[noncanonicalAccounting]
	noncanonicalPending map[[32]byte]chan struct{}

	// leafProbe runs via probeLeaf at the top of EACH of the three presence artifact
	// reads, so hoisting a leaf out of the read lock is observable for a store a test
	// instruments. nil in production; per store, so no two tests can share one.
	leafProbe func()
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

type blockStorePaths struct {
	root    string
	index   string
	blocks  string
	headers string
	undo    string
}

func newBlockStorePaths(rootPath string) blockStorePaths {
	return blockStorePaths{
		root:    rootPath,
		index:   filepath.Join(rootPath, "index.json"),
		blocks:  filepath.Join(rootPath, "blocks"),
		headers: filepath.Join(rootPath, "headers"),
		undo:    filepath.Join(rootPath, "undo"),
	}
}

// CreateBlockStore initializes a fresh blockstore at rootPath: the only
// constructor that writes. The root is created exclusively (an existing root of
// any kind fails; two racing creates cannot both win) and index.json is written
// LAST as the creation commit marker, so a crash before it leaves a partial root
// both constructors reject. Owns only rootPath, never chainstate.
func CreateBlockStore(rootPath string) (*BlockStore, error) {
	paths := newBlockStorePaths(rootPath)
	if err := os.Mkdir(paths.root, 0o700); err != nil {
		return nil, fmt.Errorf("create blockstore root: %w", err)
	}
	for _, dir := range []string{paths.blocks, paths.headers, paths.undo} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			return nil, fmt.Errorf("create blockstore directory: %w", err)
		}
	}
	index := blockStoreIndexDisk{Version: blockStoreIndexVersion, Canonical: []string{}}
	raw, err := writeCanonicalIndexFile(paths.index, index)
	if err != nil {
		return nil, fmt.Errorf("commit blockstore index: %w", err)
	}
	return newBlockStore(paths, index, raw)
}

// OpenBlockStore opens an already-initialized blockstore. Strict: no mkdir, no
// marker synthesis, no fallback. A missing root/subdirectory/marker, a malformed
// marker, or a resolved path of the wrong kind is an error, never a fresh empty
// store. Symlinks resolve normally; no runtime path-identity claim is made.
func OpenBlockStore(rootPath string) (*BlockStore, error) {
	paths := newBlockStorePaths(rootPath)
	if err := paths.requireInitialized(); err != nil {
		return nil, err
	}
	index, raw, err := loadBlockStoreIndex(paths.index)
	if err != nil {
		return nil, err
	}
	return newBlockStore(paths, index, raw)
}

// reloadFromDisk read-only replaces this store's visible index/cache in place.
func (bs *BlockStore) reloadFromDisk() error {
	if bs == nil {
		return errors.New("nil blockstore")
	}
	refreshed, err := OpenBlockStore(bs.rootPath)
	if err != nil {
		return err
	}
	bs.stateMu.Lock()
	defer bs.stateMu.Unlock()
	bs.index = refreshed.index
	bs.indexRaw = refreshed.indexRaw
	bs.canonicalHeightByHash = refreshed.canonicalHeightByHash
	bs.chainWorkByHash = refreshed.chainWorkByHash
	return nil
}

// requireInitialized checks the resolved filesystem kind of every path the store
// needs. Stat, not Lstat: symlinks resolve normally on open.
func (p blockStorePaths) requireInitialized() error {
	for _, dir := range []string{p.root, p.blocks, p.headers, p.undo} {
		info, err := os.Stat(dir)
		if err != nil {
			return fmt.Errorf("blockstore directory %s: %w", dir, err)
		}
		if !info.IsDir() {
			return fmt.Errorf("blockstore path is not a directory: %s", dir)
		}
	}
	info, err := os.Stat(p.index)
	if err != nil {
		return fmt.Errorf("blockstore index %s: %w", p.index, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("blockstore index is not a regular file: %s", p.index)
	}
	return nil
}

func newBlockStore(paths blockStorePaths, index blockStoreIndexDisk, indexRaw []byte) (*BlockStore, error) {
	canonicalHeightByHash, err := buildCanonicalHeightIndex(index.Canonical)
	if err != nil {
		return nil, err
	}
	if len(canonicalHeightByHash) != len(index.Canonical) {
		return nil, duplicateCanonicalRowErr(paths.index)
	}
	return &BlockStore{
		rootPath:   paths.root,
		indexPath:  paths.index,
		blocksDir:  paths.blocks,
		headersDir: paths.headers,
		undoDir:    paths.undo,
		index:      index,
		indexRaw:   indexRaw,

		canonicalHeightByHash: canonicalHeightByHash,
		chainWorkByHash:       make(map[[32]byte]*big.Int),
	}, nil
}

// PutBlock appends a canonical tip while persisting NO undo record, so a store
// written only through it is refused by the strict startup scan. Test/legacy
// convenience, no production caller; CommitCanonicalBlock is the commit path.
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
	return bs.saveCanonicalIndexLocked()
}

func (bs *BlockStore) RewindToHeight(height uint64) error {
	if bs == nil {
		return errors.New("nil blockstore")
	}
	// Read under the lock like every reader; only a precheck — TruncateCanonical
	// re-checks the range under the write lock it mutates in.
	bs.stateMu.RLock()
	length := uint64(len(bs.index.Canonical))
	bs.stateMu.RUnlock()
	if length == 0 {
		return nil
	}
	if height >= length {
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
	return bs.saveCanonicalIndexLocked()
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
	// A persisted index must be REOPENABLE: parseHex accepts uppercase and padded rows
	// the strict on-disk decoder refuses, so the spelling is proven before the lock, as
	// prepareCanonicalIndex proves it; the copy keeps an empty list non-nil for it, and
	// nil folds to that empty identity, unlike prepare — the rollback caller
	// (SyncEngine.restoreRollbackPersistentState) passes the nil CanonicalIndexSnapshot returns for an empty index.
	nextCanonical := append(make([]string, 0, len(canonical)), canonical...)
	if err := validateBlockStoreIndex(blockStoreIndexDisk{Version: blockStoreIndexVersion, Canonical: nextCanonical}); err != nil {
		return err
	}
	nextIndex, err := buildCanonicalHeightIndex(nextCanonical)
	if err != nil {
		return err
	}
	if len(nextIndex) != len(nextCanonical) {
		return duplicateCanonicalRowErr(bs.indexPath)
	}
	bs.stateMu.Lock()
	defer bs.stateMu.Unlock()
	bs.index.Canonical = nextCanonical
	bs.replaceCanonicalState(nextIndex)
	return bs.saveCanonicalIndexLocked()
}

func (bs *BlockStore) GetBlockByHash(blockHash [32]byte) ([]byte, error) {
	if bs == nil {
		return nil, errors.New("nil blockstore")
	}
	return readFileFromDir(bs.blocksDir, hex.EncodeToString(blockHash[:])+".bin", blockFileMaxBytes)
}

func (bs *BlockStore) GetHeaderByHash(blockHash [32]byte) ([]byte, error) {
	if bs == nil {
		return nil, errors.New("nil blockstore")
	}
	return readFileFromDir(bs.headersDir, hex.EncodeToString(blockHash[:])+".bin", headerFileMaxBytes)
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
		if _, exists := seen[current]; exists {
			return nil, fmt.Errorf("%w: chain-work parent cycle at %x", errBranchStoreCorrupt, current)
		}
		if cached, ok := bs.cachedChainWork(current); ok {
			return bs.chainWorkFromCachedBaseErr(tipHash, cached, hashes, targets)
		}
		seen[current] = struct{}{}
		header, err := bs.chainWorkHeader(current)
		if err != nil {
			return nil, err
		}
		hashes = append(hashes, current)
		targets = append(targets, header.Target)
		current = header.PrevBlockHash
	}
	return bs.chainWorkFromRoot(hashes, targets)
}

func (bs *BlockStore) chainWorkFromCachedBaseErr(tipHash [32]byte, cached *big.Int, hashes [][32]byte, targets [][32]byte) (*big.Int, error) {
	total, err := bs.accumulateChainWorkFromTargets(cached, hashes, targets)
	if err != nil {
		return nil, err
	}
	if cachedTip, ok := bs.cachedChainWork(tipHash); ok {
		return cachedTip, nil
	}
	return total, nil
}

func (bs *BlockStore) chainWorkFromCachedBase(tipHash [32]byte, cached *big.Int, hashes [][32]byte, targets [][32]byte) (*big.Int, error) {
	total, err := bs.accumulateChainWorkFromTargets(cached, hashes, targets)
	if err != nil {
		return nil, err
	}
	if cachedTip, ok := bs.cachedChainWork(tipHash); ok {
		return cachedTip, nil
	}
	return total, nil
}

func (bs *BlockStore) chainWorkFromRoot(hashes [][32]byte, targets [][32]byte) (*big.Int, error) {
	total, err := consensus.ChainWorkFromTargets(targets)
	if err != nil {
		return nil, fmt.Errorf("%w: chain-work targets are invalid: %v", errBranchStoreCorrupt, err) //nolint:errorlint // %v keeps local corruption out of p2p's consensus-error chain.
	}
	if _, err := bs.accumulateChainWorkFromTargets(nil, hashes, targets); err != nil {
		return nil, err
	}
	return total, nil
}

func (bs *BlockStore) chainWorkHeader(blockHash [32]byte) (consensus.BlockHeader, error) {
	headerBytes, err := bs.GetHeaderByHash(blockHash)
	if err != nil {
		return consensus.BlockHeader{}, chainWorkHeaderCorruption(blockHash, "cannot be read", err)
	}
	header, err := consensus.ParseBlockHeaderBytes(headerBytes)
	if err != nil {
		return consensus.BlockHeader{}, chainWorkHeaderCorruption(blockHash, "does not parse", err)
	}
	observedHash, err := consensus.BlockHash(headerBytes)
	if err != nil {
		return consensus.BlockHeader{}, chainWorkHeaderCorruption(blockHash, "does not hash", err)
	}
	if observedHash != blockHash {
		return consensus.BlockHeader{}, fmt.Errorf(
			"%w: stored header for %x hashes to %x",
			errBranchStoreCorrupt, blockHash, observedHash,
		)
	}
	return header, nil
}

func chainWorkHeaderCorruption(blockHash [32]byte, reason string, err error) error {
	return fmt.Errorf("%w: stored header for %x %s: %v", errBranchStoreCorrupt, blockHash, reason, err) //nolint:errorlint // %v keeps local corruption out of p2p's consensus-error chain.
}

// errCanonicalIndexDuplicateRow: a repeated hash collapses two heights into one
// height-by-hash entry, so the store would run with a map that does not describe
// its own list, and would persist an index it refuses to reopen. Refused by every
// writer that builds the map from a caller-supplied list — every constructor,
// prepare and RestoreCanonicalIndex. SetCanonicalTip mutates the live map in place
// and rests on the caller invariant alone (one canonical height per hash in any
// prev-linked chain), whose breach persists that same unreopenable index. The
// shared on-disk decoder stays deliberately untightened: decodeBlockStoreIndex is
// cross-client mirrored (Rust load_blockstore_index) and still accepts it (RUB-897).
var errCanonicalIndexDuplicateRow = errors.New("canonical index repeats a block hash")

// duplicateCanonicalRowErr is the one message shape for that refusal, so the
// store entry points cannot drift apart on how they name the offending file.
func duplicateCanonicalRowErr(indexPath string) error {
	return fmt.Errorf("canonical index %s: %w", indexPath, errCanonicalIndexDuplicateRow)
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
	pending := make([]*big.Int, len(targets))
	for i := len(targets) - 1; i >= 0; i-- {
		work, err := consensus.WorkFromTarget(targets[i])
		if err != nil {
			return nil, fmt.Errorf("%w: chain-work target for %x is invalid: %v", errBranchStoreCorrupt, hashes[i], err) //nolint:errorlint // %v keeps local corruption out of p2p's consensus-error chain.
		}
		running.Add(running, work)
		pending[i] = cloneBigInt(running)
	}
	for i := len(pending) - 1; i >= 0; i-- {
		bs.storeChainWorkIfCanonical(hashes[i], pending[i])
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
	raw, err := marshalUndoEnvelope(blockHash, undo)
	if err != nil {
		return err
	}
	path := filepath.Join(bs.undoDir, hex.EncodeToString(blockHash[:])+".json")
	// RUB-1057 write/read symmetry for the undo class: the bound rests on a
	// wire-cost derivation (>=1 mandatory signature per spent input), so this
	// guard converts any future derivation drift (a new covenant family,
	// signature aggregation) into a loud save-time error instead of a
	// next-restart refusal of the node's own undo file. RUB-1132 moves it to
	// the envelope bound so the guard still measures the bytes GetUndo reads.
	if err := checkStoreSaveBound(path, len(raw), undoFileMaxBytes); err != nil {
		return err
	}
	if err := validateAtomicWriteDestination(path, atomicWriteCreateIfAbsent); err != nil {
		return err
	}
	// An existing v1 or v2 record is accepted only after the same bounded,
	// hash-bound integrity and payload validation GetUndo performs. Semantic
	// equality preserves its exact bytes and version; corruption or a different
	// undo is never healed in place.
	resolveExisting := func() error { return bs.checkExistingUndo(path, blockHash, undo) }
	existingErr := resolveExisting()
	if existingErr == nil {
		return syncMatchingExistingFile(path)
	}
	if !errors.Is(existingErr, os.ErrNotExist) {
		return newAtomicWriteError(atomicWriteBeforeNamespaceCommit, path, atomicWriteCreateIfAbsent, existingErr)
	}
	leaf := noncanonicalReservationLeaf{
		kind:   noncanonicalUndoArtifact,
		bytes:  uint64(len(raw)),
		state:  BlockArtifactValid,
		height: undo.BlockHeight,
	}
	write := func(r *noncanonicalReservation) error {
		err := writeAtomicFile(path, raw, atomicWriteCreateIfAbsent, resolveExisting)
		if err == nil || isAtomicWritePostCommit(err) {
			r.created(leaf)
		}
		return err
	}
	return bs.reserveNoncanonicalArtifactWrite(blockHash, []noncanonicalReservationLeaf{leaf}, write)
}

func (bs *BlockStore) checkExistingUndo(path string, blockHash [32]byte, undo *BlockUndo) error {
	existingRaw, err := readFileFromDir(bs.undoDir, filepath.Base(path), undoFileMaxBytes)
	if err != nil {
		return err
	}
	existing, err := unmarshalUndoEnvelopeDisk(blockHash, existingRaw)
	if err != nil {
		return err
	}
	if !validatedBlockUndoMatches(existing, undo) {
		return errExistingContentDiffers(path)
	}
	return nil
}

func (bs *BlockStore) GetUndo(blockHash [32]byte) (*BlockUndo, error) {
	if bs == nil {
		return nil, errors.New("nil blockstore")
	}
	raw, err := readFileFromDir(bs.undoDir, hex.EncodeToString(blockHash[:])+".json", undoFileMaxBytes)
	if err != nil {
		return nil, err
	}
	// blockHash is the hash the CALLER asked for, not one read back off disk:
	// that is what makes a record moved or renamed between two undo files fail
	// instead of restoring the wrong block's UTXOs.
	return unmarshalUndoEnvelope(blockHash, raw)
}

// loadBlockStoreIndex reads the sole initialization marker. A missing marker is
// an error, never an implicit empty index (the RUB-1052/1053 strict-open
// rejection, unchanged by the envelope). Every present marker must clear the
// strict store_envelope_v1 BEFORE the inner index decode runs; envelope
// failures carry the ErrStoreIntegrity identity unwrapped, so the pinned
// messages reach callers. It returns the decoded index AND the exact visible
// bytes it validated, which become the store's visible canonical identity.
func loadBlockStoreIndex(path string) (blockStoreIndexDisk, []byte, error) {
	raw, err := readFileByPath(path)
	if err != nil {
		return blockStoreIndexDisk{}, nil, err
	}
	payload, err := openStoreEnvelope(storeEnvelopeBlockIndex, raw)
	if err != nil {
		return blockStoreIndexDisk{}, nil, err
	}
	index, err := decodeBlockStoreIndex(payload)
	if err != nil {
		return blockStoreIndexDisk{}, nil, fmt.Errorf("decode blockstore index: %w", err)
	}
	return index, raw, nil
}

// decodeBlockStoreIndex accepts exactly one JSON object with exactly one
// "version" and one "canonical" field, in either order. Duplicate/unknown/missing
// fields, a null or non-array canonical, an entry that is not 64 lowercase hex
// characters, a version other than 1, and any trailing JSON value are rejected.
// Rust mirror: load_blockstore_index in crates/rubin-node/src/blockstore.rs.
func decodeBlockStoreIndex(raw []byte) (blockStoreIndexDisk, error) {
	if err := requireExactIndexFields(raw); err != nil {
		return blockStoreIndexDisk{}, err
	}
	var index blockStoreIndexDisk
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := dec.Decode(&index); err != nil {
		return blockStoreIndexDisk{}, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return blockStoreIndexDisk{}, errors.New("unexpected trailing JSON value")
	}
	return index, validateBlockStoreIndex(index)
}

// requireExactIndexFields requires the top-level key multiset to be exactly
// {canonical, version}: struct decoding alone catches none of duplicate,
// unknown or missing fields.
func requireExactIndexFields(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if delim, ok := tok.(json.Delim); !ok || delim != '{' {
		return errors.New("blockstore index must be a JSON object")
	}
	keys, err := collectIndexFieldNames(dec)
	if err != nil {
		return err
	}
	sort.Strings(keys)
	if len(keys) != 2 || keys[0] != "canonical" || keys[1] != "version" {
		return fmt.Errorf("blockstore index fields must be exactly canonical and version, got %q", keys)
	}
	return nil
}

// collectIndexFieldNames drains the top-level object, returning its key names in
// encounter order (duplicates included, so the caller can reject them).
func collectIndexFieldNames(dec *json.Decoder) ([]string, error) {
	keys := make([]string, 0, 2)
	for dec.More() {
		key, err := dec.Token()
		if err != nil {
			return nil, err
		}
		name, _ := key.(string)
		keys = append(keys, name)
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return nil, err
		}
	}
	return keys, nil
}

func validateBlockStoreIndex(index blockStoreIndexDisk) error {
	if index.Version != blockStoreIndexVersion {
		return fmt.Errorf("unsupported blockstore index version: %d", index.Version)
	}
	// The "canonical" key is present (requireExactIndexFields), so a nil slice
	// here can only come from a JSON null.
	if index.Canonical == nil {
		return errors.New("canonical must not be null")
	}
	for i, hashHex := range index.Canonical {
		if !validCanonicalHashHex(hashHex) {
			return fmt.Errorf("canonical[%d]: not 64 lowercase hex characters: %q", i, hashHex)
		}
	}
	return nil
}

// validCanonicalHashHex: 64 lowercase hex characters (hex decoding alone would
// accept uppercase).
func validCanonicalHashHex(value string) bool {
	if len(value) != 64 {
		return false
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// encodeBlockStoreIndex produces the exact visible bytes for index. It is the
// ONE encoder behind the legacy save path and the prepared canonical commit, so
// a prepared image and a saved one can never disagree byte for byte.
func encodeBlockStoreIndex(index blockStoreIndexDisk) ([]byte, error) {
	// The empty on-disk identity is [], never the JSON null a nil slice marshals
	// to and the strict open refuses: the store must not persist an index it
	// would refuse to reopen. prepareCanonicalIndex validates BEFORE this
	// encode, so its nil-list refusal is unaffected.
	if index.Canonical == nil {
		index.Canonical = []string{}
	}
	payload, err := json.MarshalIndent(index, "", "  ")
	if err != nil {
		return nil, err
	}
	payload = append(payload, '\n')
	// The pre-envelope on-disk bytes become the exact envelope payload; the
	// inner encoding and the atomic write path are unchanged.
	return marshalStoreEnvelope(storeEnvelopeBlockIndex, payload)
}

// writeCanonicalIndexFile writes the visible index through the RUB-1084 atomic
// lane and returns the exact bytes it wrote. CONSTRUCTION ONLY: it does not publish
// indexRaw, so a LIVE store must go through saveCanonicalIndexLocked or its visible
// identity stops describing the disk; store_envelope_test.go's crash harness calls
// it directly on purpose and reopens the store afterwards.
func writeCanonicalIndexFile(path string, index blockStoreIndexDisk) ([]byte, error) {
	raw, err := encodeBlockStoreIndex(index)
	if err != nil {
		return nil, err
	}
	if err := writeFileAtomicFn(path, raw, 0o600); err != nil {
		return nil, err
	}
	return raw, nil
}

// saveCanonicalIndexLocked is the write step of the legacy mutate-then-save path: the
// caller already mutated bs.index under stateMu.Lock, so this records the bytes the
// disk holds as the new visible identity. Every caller holds stateMu across the
// mutation AND this save (RestoreCanonicalIndex proves its list before the lock), while
// a prepared commit writes OUTSIDE it, so the two paths interleave safely only under
// RUB-1202's canonical writer fence; until then the PREPARED primitive is dormant.
//
// After a PRE-commit failure the old bytes are still visible and indexRaw keeps
// naming them, while bs.index and the height map — already mutated by the caller —
// LEAD the disk: for a prepared commit the visible canonical identity is indexRaw,
// never bs.index, while the public readers (Tip, CanonicalHash,
// CanonicalIndexSnapshot) serve bs.index and so report state the disk refused. A
// POST-commit failure did rename, so the visible identity IS the new bytes even
// though the call returns an error, and indexRaw moves with it. An UNTAGGED error
// keeps the OLD identity, asymmetric to commit's "untagged takes the readback" and
// unreachable: this lane returns only stage-tagged errors.
func (bs *BlockStore) saveCanonicalIndexLocked() error {
	raw, err := encodeBlockStoreIndex(bs.index)
	if err != nil {
		return err
	}
	err = writeFileAtomicFn(bs.indexPath, raw, 0o600)
	if err == nil || isAtomicWritePostCommit(err) {
		bs.indexRaw = raw
	}
	return err
}

// VerifyGenesisAnchor enforces the RUB-1134 genesis anchor: a non-empty
// canonical index must carry the configured genesis hash at row 0, while an
// empty index skips the anchor. Failure is the distinct fail-closed
// foreign-datadir class, not an envelope-integrity failure, and satisfies
// errors.Is(err, ErrStoreIntegrity). Startup wiring (cmd/rubin-node/main.go)
// calls this BEFORE ReconcileChainStateWithBlockStore, so no replay or
// reconcile adoption ever consumes a foreign index.
func (bs *BlockStore) VerifyGenesisAnchor(genesisHash [32]byte) error {
	if bs == nil {
		return errors.New("nil blockstore")
	}
	row0, ok, err := bs.CanonicalHash(0)
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}
	if row0 != genesisHash {
		return errStoreGenesisAnchor
	}
	return nil
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

// storedBlockHeaderHash re-derives the content-addressed identity of stored
// block bytes: parse, then hash the contained header. step names the stage that
// failed and is empty on success. It is shared by replay's re-hash defense,
// startup's strict canonical-artifact check and InspectBlockPresence's block
// leaf, so none of them can disagree on what makes stored block bytes valid.
func storedBlockHeaderHash(blockBytes []byte) (blockHash [32]byte, step string, err error) {
	parsed, err := consensus.ParseBlockBytes(blockBytes)
	if err != nil {
		return blockHash, "parse block bytes", err
	}
	blockHash, err = consensus.BlockHash(parsed.HeaderBytes)
	if err != nil {
		return blockHash, "hash header", err
	}
	return blockHash, "", nil
}

func (bs *BlockStore) persistBlockBytes(blockHash [32]byte, headerBytes []byte, blockBytes []byte) error {
	hashHex := hex.EncodeToString(blockHash[:])
	blockPath := filepath.Join(bs.blocksDir, hashHex+".bin")
	headerPath := filepath.Join(bs.headersDir, hashHex+".bin")
	if bs.noncanonical.Load() == nil {
		return bs.persistUntrackedBlockBytes(blockHash, blockPath, headerPath, blockBytes, headerBytes)
	}
	return bs.persistTrackedBlockBytes(blockHash, blockPath, headerPath, blockBytes, headerBytes)
}
func (bs *BlockStore) persistUntrackedBlockBytes(hash [32]byte, blockPath, headerPath string, blockBytes, headerBytes []byte) error {
	return bs.reserveNoncanonicalArtifactWrite(hash, nil, func(*noncanonicalReservation) error {
		if err := writeFileIfAbsent(blockPath, blockBytes); err != nil {
			return err
		}
		return writeFileIfAbsent(headerPath, headerBytes)
	})
}
func (bs *BlockStore) persistTrackedBlockBytes(hash [32]byte, blockPath, headerPath string, blockBytes, headerBytes []byte) error {
	blockExists, err := preflightNoncanonicalFile(blockPath, blockBytes)
	if err != nil {
		return err
	}
	headerExists, err := preflightNoncanonicalFile(headerPath, headerBytes)
	if err != nil {
		return err
	}
	if blockExists && headerExists {
		return nil
	}
	header, err := consensus.ParseBlockHeaderBytes(headerBytes)
	if err != nil {
		return err
	}
	blockState, blockPrev := noncanonicalStoredBlockState(blockBytes, hash)
	block := noncanonicalReservationLeaf{
		kind:  noncanonicalBlockArtifact,
		bytes: uint64(len(blockBytes)),
		state: blockState,
		prev:  blockPrev,
	}
	headerLeaf := noncanonicalReservationLeaf{
		kind:  noncanonicalHeaderArtifact,
		bytes: uint64(len(headerBytes)),
		state: BlockArtifactValid,
		prev:  header.PrevBlockHash,
	}
	leaves := make([]noncanonicalReservationLeaf, 0, 2)
	if !blockExists {
		leaves = append(leaves, block)
	}
	if !headerExists {
		leaves = append(leaves, headerLeaf)
	}
	return bs.reserveNoncanonicalArtifactWrite(hash, leaves, func(r *noncanonicalReservation) error {
		return writeMissingNoncanonicalBlockFiles(r, blockPath, headerPath, blockBytes, headerBytes, block, headerLeaf, blockExists, headerExists)
	})
}
func writeMissingNoncanonicalBlockFiles(r *noncanonicalReservation, blockPath, headerPath string, blockBytes, headerBytes []byte, block, header noncanonicalReservationLeaf, blockExists, headerExists bool) error {
	if !blockExists {
		if err := writeNoncanonicalBlockArtifact(r, blockPath, blockBytes, block); err != nil {
			return err
		}
	}
	if !headerExists {
		return writeNoncanonicalBlockArtifact(r, headerPath, headerBytes, header)
	}
	return nil
}
func writeNoncanonicalBlockArtifact(r *noncanonicalReservation, path string, raw []byte, leaf noncanonicalReservationLeaf) error {
	err := writeFileIfAbsent(path, raw)
	if err == nil || isAtomicWritePostCommit(err) {
		r.created(leaf)
	}
	return err
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

// canonicalCommitClass is the outcome class of one prepared canonical-index commit.
// Exactly four values are frozen RUB-922 C01 identity strings —
// canonicalCommitPrecommit and the three canonicalCommitTerminal* — so those
// identities have one source and cannot drift from a mapping table; the other two are
// LOCAL names the owning canonical transition maps to its own result.
type canonicalCommitClass string

const (
	// canonicalCommitted is a successful durable commit. It is a LOCAL name, not a
	// frozen C01 identity: the owning canonical transition maps a committed index to
	// ACCEPTED / commit truth NEW.
	canonicalCommitted canonicalCommitClass = "COMMITTED"

	// canonicalCommitStale is the prepared image refusing to build on a visible
	// identity it never observed, or refusing a second use; err splits those.
	// errCanonicalIndexMoved attempted nothing, so the owning canonical transition maps
	// it to STALE_LOCAL_PLAN, never to the frozen precommit identity (whose
	// C01-PRENS-001 triggers are the atomic write and the precommit checkpoint writes).
	// errPreparedIndexSpent is instead a caller fence/latch violation whose commit truth
	// is whatever the FIRST attempt returned — it can follow TERMINAL_PERSISTENCE(new).
	canonicalCommitStale canonicalCommitClass = "STALE_PREPARED_IMAGE"

	canonicalCommitPrecommit       canonicalCommitClass = "LOCAL_PERSISTENCE_ERROR(precommit)"
	canonicalCommitTerminalOld     canonicalCommitClass = "TERMINAL_PERSISTENCE(old)"
	canonicalCommitTerminalNew     canonicalCommitClass = "TERMINAL_PERSISTENCE(new)"
	canonicalCommitTerminalUnknown canonicalCommitClass = "TERMINAL_PERSISTENCE(neither_or_unreadable)"
)

// canonicalCommitResult is one prepared-commit outcome: the class and the
// underlying cause for the two failure families. It carries nothing else — no
// latch, counter, lease or retry budget lives at this layer.
type canonicalCommitResult struct {
	class canonicalCommitClass
	err   error
}

// The prepared-commit refusals. Each is a typed sentinel so a consumer can tell
// a benign refusal from an invalid plan without matching on message text.
var (
	// The visible canonical identity moved between prepare and commit, so the prepared
	// image is stale and nothing is written. The owning canonical transition holds the
	// writer fence; this is the last check under it, never a substitute for it.
	errCanonicalIndexMoved = errors.New("prepared canonical index is stale: visible index bytes changed")

	// This prepared image already made its one write attempt. Spec §6.4.1 forbids any
	// rollback, retry, rewrite or heuristic classification after a terminal persistence
	// result, so a second commit is refused.
	errPreparedIndexSpent = errors.New("prepared canonical index was already committed")

	// The planned image equals the visible index bytes, so there is no
	// transition to commit — a benign no-op, not an invalid plan.
	errCanonicalIndexNoOp = errors.New("prepared canonical index is a no-op: the planned image equals the visible index bytes")
)

// preparedCanonicalIndex is one complete next canonical-index image: the exact
// bytes to commit plus every RAM object publication installs, all built BEFORE any
// write touches the filesystem. Single use, enforced on the image itself: commit
// marks it spent before the write attempt, so no result — including a terminal one
// that left the visible identity OLD and would still pass the freshness check —
// can be followed by a second write from the same image.
type preparedCanonicalIndex struct {
	oldRaw       []byte
	newRaw       []byte
	index        blockStoreIndexDisk
	heightByHash map[[32]byte]uint64
	chainWork    map[[32]byte]*big.Int
	spent        bool
}

// prepareCanonicalIndex validates the complete planned canonical list and builds the
// whole next image without touching the store or the filesystem. Validation is the
// same pair the strict on-disk read uses: validateBlockStoreIndex pins version and
// the 64-lowercase-hex row spelling (parseHex alone would accept uppercase and
// surrounding space), and buildCanonicalHeightIndex proves every row decodes to a
// hash. oldRaw is the exact visible index bytes the caller observed; commit refuses
// if the store's visible identity has moved since. A nil next list is refused exactly
// as a JSON null canonical is on disk; an empty non-nil list is the legitimate
// empty-store identity.
func prepareCanonicalIndex(oldRaw []byte, next []string) (*preparedCanonicalIndex, error) {
	// Copy so a later caller mutation cannot reach the prepared image, and keep
	// nil-ness exact: `append([]string(nil), next...)` would fold an EMPTY list
	// into nil and reject the legitimate empty-store identity.
	canonical := next
	if next != nil {
		canonical = append(make([]string, 0, len(next)), next...)
	}
	index := blockStoreIndexDisk{Version: blockStoreIndexVersion, Canonical: canonical}
	if err := validateBlockStoreIndex(index); err != nil {
		return nil, err
	}
	heightByHash, err := buildCanonicalHeightIndex(index.Canonical)
	if err != nil {
		return nil, err
	}
	if len(heightByHash) != len(index.Canonical) {
		return nil, errCanonicalIndexDuplicateRow
	}
	newRaw, err := encodeBlockStoreIndex(index)
	if err != nil {
		return nil, err
	}
	// The identical image is refused rather than staged: a post-commit
	// ambiguity would read it back as the OLD identity and publish nothing,
	// while the success path publishes — one transition with two different RAM
	// outcomes (the publication also resets the derived chain-work cache).
	if bytes.Equal(oldRaw, newRaw) {
		return nil, errCanonicalIndexNoOp
	}
	return &preparedCanonicalIndex{
		oldRaw:       append([]byte(nil), oldRaw...),
		newRaw:       newRaw,
		index:        index,
		heightByHash: heightByHash,
		chainWork:    make(map[[32]byte]*big.Int),
	}, nil
}

// commit performs the one durable canonical-index transition: single-use and
// freshness checks, the existing RUB-1084 atomic write with NO store lock held,
// exactly one strict visible readback whenever the write may have crossed the
// namespace commit, then a non-fallible publication of the prebuilt image. It
// never rolls back, retries, rewrites or repairs and latches nothing: the owning
// canonical transition consumes the returned evidence. REQUIRES the caller to hold
// the canonical writer fence (SyncEngine.mutationMu plus ChainState.admissionMu.W,
// RUB-1202): the freshness comparison is a staleness ASSERT, not mutual exclusion
// — it reads and releases the store's read lock before the write — so only that
// fence closes the check-then-act window, and under it p.spent needs no
// synchronization of its own. A nil bs is a programming error; the fence holder
// owns the receiver.
func (p *preparedCanonicalIndex) commit(bs *BlockStore) canonicalCommitResult {
	if p.spent {
		return canonicalCommitResult{class: canonicalCommitStale, err: errPreparedIndexSpent}
	}
	bs.stateMu.RLock()
	fresh := bytes.Equal(bs.indexRaw, p.oldRaw)
	bs.stateMu.RUnlock()
	if !fresh {
		return canonicalCommitResult{class: canonicalCommitStale, err: errCanonicalIndexMoved}
	}
	p.spent = true

	// No publication lock is held while waiting for or executing this write.
	err := writeFileAtomicFn(bs.indexPath, p.newRaw, 0o600)
	if err == nil {
		p.publish(bs)
		return canonicalCommitResult{class: canonicalCommitted}
	}
	// The frozen precommit identity means "no commit attempt may have crossed",
	// so only the lane's own before_namespace_commit tag may claim it. An error
	// the lane never classified is NOT proof of that, and spec §6.4.1 requires
	// one strict readback before every result persistence may have crossed —
	// so after_namespace_commit and every untagged error take the readback.
	if stage, tagged := atomicWriteStageOf(err); tagged && stage == atomicWriteBeforeNamespaceCommit {
		return canonicalCommitResult{class: canonicalCommitPrecommit, err: err}
	}
	return p.classifyVisibleIndex(bs, err)
}

// classifyVisibleIndex is the one strict readback. It classifies by the VISIBLE
// BYTES, never by the error text, and compares the complete identity: a shared tip
// or a matching hash is not one, so anything that is not exactly the old or exactly
// the new image is neither. A read failure is neither too — nothing is guessed,
// retried or rewritten. The read is BOUNDED at the longer of the two images: only those
// two byte strings can match, so anything longer is provably neither identity and is
// refused (errStoreFileTooLarge) before it is allocated on this untrusted on-disk path,
// where the planned images fix the bound. That is why it does not inherit
// loadBlockStoreIndex's deliberately unbounded read, which has no such ceiling to
// derive (RUB-1057).
//
// Byte equality is deliberately STRONGER than comparing decoded lists — two
// spellings decode alike but only one is the identity the commit planned — so do
// not "simplify" it to a decode. It also diverges deliberately from §6.4.1, which
// words the identity as the (height, block_hash) SEQUENCE: bytes can only refuse an
// image the sequence rule would accept, so the divergence runs fail-closed, and it
// is unreachable in practice because both writers encode through
// encodeBlockStoreIndex. After a terminal result the store's cached identity may no
// longer describe the disk (a third identity, or an unreadable file), and nothing
// here repairs that: commit's freshness check is a staleness ASSERT, not a guard
// against a post-terminal rewrite — the owning transition's latch is what stops the
// next write.
func (p *preparedCanonicalIndex) classifyVisibleIndex(bs *BlockStore, cause error) canonicalCommitResult {
	raw, err := readFileByPathCapped(bs.indexPath, int64(max(len(p.oldRaw), len(p.newRaw))))
	switch {
	case err != nil:
		// Both causes survive errors.Is: the write failure that sent us here
		// and the readback failure that left the identity unprovable.
		return canonicalCommitResult{class: canonicalCommitTerminalUnknown, err: errors.Join(cause, err)}
	case bytes.Equal(raw, p.oldRaw):
		return canonicalCommitResult{class: canonicalCommitTerminalOld, err: cause}
	case bytes.Equal(raw, p.newRaw):
		p.publish(bs)
		return canonicalCommitResult{class: canonicalCommitTerminalNew, err: cause}
	default:
		return canonicalCommitResult{class: canonicalCommitTerminalUnknown, err: cause}
	}
}

// publish takes the store's write lock for the one publication of this image.
func (p *preparedCanonicalIndex) publish(bs *BlockStore) {
	bs.stateMu.Lock()
	p.publishLocked(bs)
	bs.stateMu.Unlock()
}

// publishLocked installs the prebuilt image. PRECONDITION: the caller holds
// bs.stateMu.Lock(). It is split out because RUB-1202 composes this transition with
// RUB-908's prebuilt accounting-image assignment inside the SAME critical section
// (contract clause), so both become ONE complete published image and a reader under
// RLock() never observes a partial replacement.
//
// Everything assigned here was built before the write, so on the SUCCESS path there
// is no allocation, parse, callback, clone or ordinary error return between the
// durable commit and these four plain assignments — measured, not asserted. The
// post-commit-ambiguity path interposes exactly ONE strict readback first: the
// lane's durable boundary is rename plus parent fsync, but that readback decides
// the PUBLISHED image, so a parent-fsync failure over a visible new image publishes
// here as TERMINAL_PERSISTENCE(new) and the owning transition latches admission on
// the class.
//
// chainWorkByHash is REPLACED with the prepared empty map rather than carried:
// cachedChainWork serves entries without re-checking canonical membership, so work
// derived under the old index would survive a reorg as an answer for a hash this
// image no longer contains. The legacy pure-append mutator keeps its cache (only
// its reorg branch resets) — a deliberate divergence from the append path.
func (p *preparedCanonicalIndex) publishLocked(bs *BlockStore) {
	bs.index = p.index
	bs.indexRaw = p.newRaw
	bs.canonicalHeightByHash = p.heightByHash
	bs.chainWorkByHash = p.chainWork
}

// visibleIndexBytes returns a copy of the store's visible canonical identity under
// the read lock. Tests read the identity through it or under the store lock, so
// observing it can never race a concurrent publication. It is also what a next
// canonical list must be derived from, not bs.index (saveCanonicalIndexLocked
// explains why RAM can lead the disk).
func (bs *BlockStore) visibleIndexBytes() []byte {
	bs.stateMu.RLock()
	defer bs.stateMu.RUnlock()
	return append([]byte(nil), bs.indexRaw...)
}

// BlockPresenceClass is the closed set of presence classifications for a block
// hash in this store. All four CLASS strings are the contract's closed return
// set; ABSENT, STORED_NONCANONICAL, CANONICAL and LOCAL_STORE_ERROR(noncanonical)
// are the frozen RUB-922 C01 identities. The set is closed only for the current
// retain-everything profile: a retention profile that permits pruned suffix data
// adds LOCAL_RESOURCE_UNAVAILABLE(recovery_artifact) (C01-RES-RECOVERY-001),
// which arrives with RUB-908's reclaim.
type BlockPresenceClass string

const (
	BlockPresenceAbsent             BlockPresenceClass = "ABSENT"
	BlockPresenceStoredNoncanonical BlockPresenceClass = "STORED_NONCANONICAL"
	BlockPresenceCanonical          BlockPresenceClass = "CANONICAL"
	BlockPresenceLocalStoreError    BlockPresenceClass = "LOCAL_STORE_ERROR"
)

// BlockPresenceScope qualifies LOCAL_STORE_ERROR and is empty for every other class.
// Only the noncanonical spelling is a frozen corpus identity
// (LOCAL_STORE_ERROR(noncanonical)); it leaves every canonical image untouched.
// Canonical scope is LOCAL evidence: the scope and the leaves stay in the struct as
// what the owning canonical transition latches as TERMINAL_STORE_INTEGRITY(canonical),
// and the rendered identity stays the bare contract class.
type BlockPresenceScope string

const (
	BlockPresenceScopeCanonical    BlockPresenceScope = "canonical"
	BlockPresenceScopeNoncanonical BlockPresenceScope = "noncanonical"
)

// BlockArtifactState is one stored artifact's state. Valid means the artifact
// was read AND is bound to the requested hash: the block's own header re-hashes
// to it, the header hashes to it, the undo envelope carries it. Everything that
// is neither absent nor bound — corrupt, mismatched, over-bound, unreadable —
// is invalid, and none of it is ever repaired, truncated or rewritten here.
type BlockArtifactState string

const (
	BlockArtifactAbsent  BlockArtifactState = "absent"
	BlockArtifactValid   BlockArtifactState = "valid"
	BlockArtifactInvalid BlockArtifactState = "invalid"
)

// BlockArtifactLeaves is the per-artifact evidence behind one BlockPresence.
type BlockArtifactLeaves struct {
	Block  BlockArtifactState
	Header BlockArtifactState
	Undo   BlockArtifactState
}

// BlockPresence is one snapshot classification of a block hash: the class, the
// scope that qualifies a store error, and the leaf evidence behind both.
type BlockPresence struct {
	Class  BlockPresenceClass
	Scope  BlockPresenceScope
	Leaves BlockArtifactLeaves
}

// String renders the identity. Only the noncanonical store error is scoped —
// LOCAL_STORE_ERROR(noncanonical) is the frozen corpus row; a canonical-scoped store
// error renders the bare contract class and carries its scope and leaves in the
// struct instead. Nothing else renders a scope, so no class can ever print an empty
// parenthesis. It is a RENDERING, not a classification: the zero value renders ""
// (no class was assigned), and the bare LOCAL_STORE_ERROR token is the class name of
// BOTH scopes, so the consumer that must tell the latching canonical case
// (TERMINAL_STORE_INTEGRITY(canonical)) from the non-latching noncanonical corpus
// row reads Scope, never the rendered string.
func (p BlockPresence) String() string {
	if p.Class == BlockPresenceLocalStoreError && p.Scope == BlockPresenceScopeNoncanonical {
		return fmt.Sprintf("%s(%s)", p.Class, p.Scope)
	}
	return string(p.Class)
}

// InspectBlockPresence classifies blockHash against this store's canonical
// membership and its three stored artifacts. A nil receiver is a PROGRAMMING ERROR
// (consumers must not call with a nil store): it proves nothing about any artifact,
// so it fails closed with every leaf invalid on the CANONICAL scope the owner
// latches, never on the frozen non-latching corpus row LOCAL_STORE_ERROR(noncanonical);
// that value coincides with the all-invalid canonical observation by design, and the
// class set stays closed.
//
// The whole classification runs under ONE stateMu.RLock, which by contract spans the
// artifact reads as well, so canonical membership and artifact state are one snapshot
// instead of two observations a concurrent replacement could interleave. The RLock
// protects the MEMBERSHIP map; the artifact FILES have lock-free, monotone
// absent->present writers, so the leaves are read in REVERSE persistence order and
// every observed tuple is a state the store really held. RUB-908's reclaim makes
// artifacts present->absent and must re-derive that argument.
//
// The cost is real and accepted, and all of it runs under the read lock: the block
// leaf READS, fully PARSES and hashes up to consensus.MAX_BLOCK_BYTES and the undo
// leaf READS and JSON-decodes up to undoFileMaxBytes (2 GB), so a publication waits
// behind an inspection and a pending writer blocks every arriving reader. It takes no
// second lock, repairs nothing, and never treats a present header ALONE as presence.
func (bs *BlockStore) InspectBlockPresence(blockHash [32]byte) BlockPresence {
	if bs == nil {
		return BlockPresence{
			Class:  BlockPresenceLocalStoreError,
			Scope:  BlockPresenceScopeCanonical,
			Leaves: BlockArtifactLeaves{Block: BlockArtifactInvalid, Header: BlockArtifactInvalid, Undo: BlockArtifactInvalid},
		}
	}
	bs.stateMu.RLock()
	defer bs.stateMu.RUnlock()

	_, member := bs.canonicalHeightByHash[blockHash]
	// The reverse persistence order the doc argues for, in explicit statements
	// rather than composite-literal fields: undo, then header, then block.
	undo := bs.inspectUndoLeaf(blockHash)
	header := bs.inspectHeaderLeaf(blockHash)
	block := bs.inspectBlockLeaf(blockHash)
	leaves := BlockArtifactLeaves{Block: block, Header: header, Undo: undo}
	if member {
		return canonicalPresence(leaves)
	}
	return noncanonicalPresence(leaves)
}

// canonicalPresence: a canonical member is CANONICAL only with a valid block, a
// matching header and a valid hash-bound undo; EVERY other combination is
// canonical-scoped store-integrity evidence.
func canonicalPresence(leaves BlockArtifactLeaves) BlockPresence {
	complete := BlockArtifactLeaves{Block: BlockArtifactValid, Header: BlockArtifactValid, Undo: BlockArtifactValid}
	if leaves == complete {
		return BlockPresence{Class: BlockPresenceCanonical, Leaves: leaves}
	}
	return BlockPresence{Class: BlockPresenceLocalStoreError, Scope: BlockPresenceScopeCanonical, Leaves: leaves}
}

// noncanonicalPresence: nothing stored is ABSENT, the three recognized stored
// shapes are STORED_NONCANONICAL, and every other combination is a
// noncanonical-scoped store error.
func noncanonicalPresence(leaves BlockArtifactLeaves) BlockPresence {
	const (
		absent = BlockArtifactAbsent
		valid  = BlockArtifactValid
	)
	switch leaves {
	case BlockArtifactLeaves{Block: absent, Header: absent, Undo: absent}:
		return BlockPresence{Class: BlockPresenceAbsent, Leaves: leaves}
	case BlockArtifactLeaves{Block: valid, Header: absent, Undo: absent},
		BlockArtifactLeaves{Block: valid, Header: valid, Undo: absent},
		BlockArtifactLeaves{Block: valid, Header: valid, Undo: valid}:
		return BlockPresence{Class: BlockPresenceStoredNoncanonical, Leaves: leaves}
	default:
		return BlockPresence{Class: BlockPresenceLocalStoreError, Scope: BlockPresenceScopeNoncanonical, Leaves: leaves}
	}
}

func (bs *BlockStore) probeLeaf() {
	if bs.leafProbe != nil {
		bs.leafProbe()
	}
}

// inspectBlockLeaf: stored block bytes are valid only when they parse and their
// own header re-hashes to the requested hash — the same content-addressed
// identity replay's re-hash defense enforces.
func (bs *BlockStore) inspectBlockLeaf(blockHash [32]byte) BlockArtifactState {
	bs.probeLeaf()
	blockBytes, err := bs.GetBlockByHash(blockHash)
	if err != nil {
		return artifactStateFromErr(err)
	}
	// A parse/hash failure over bytes already read is computation, never
	// absence — artifactStateFromErr's os.ErrNotExist arm is unreachable here.
	observed, _, err := storedBlockHeaderHash(blockBytes)
	if err != nil || observed != blockHash {
		return BlockArtifactInvalid
	}
	return BlockArtifactValid
}

// inspectHeaderLeaf: a stored header is valid only when it hashes to the
// requested hash. Existence alone is never presence.
func (bs *BlockStore) inspectHeaderLeaf(blockHash [32]byte) BlockArtifactState {
	bs.probeLeaf()
	headerBytes, err := bs.GetHeaderByHash(blockHash)
	if err != nil {
		return artifactStateFromErr(err)
	}
	// A length/hash failure over bytes already read is computation, never absence.
	if validateBlockHeaderHash(headerBytes, blockHash) != nil {
		return BlockArtifactInvalid
	}
	return BlockArtifactValid
}

// inspectUndoLeaf: GetUndo binds the record to the hash the CALLER asked for
// (RUB-1132), so a record moved between two undo files reads as invalid.
func (bs *BlockStore) inspectUndoLeaf(blockHash [32]byte) BlockArtifactState {
	bs.probeLeaf()
	_, err := bs.GetUndo(blockHash)
	return artifactStateFromErr(err)
}

// artifactStateFromErr maps one strict artifact read to its leaf state. Only an
// absent file is absent, so a corrupt, mismatched, over-bound or unreadable
// artifact can never pass as "not there".
func artifactStateFromErr(err error) BlockArtifactState {
	switch {
	case err == nil:
		return BlockArtifactValid
	case errors.Is(err, os.ErrNotExist):
		return BlockArtifactAbsent
	default:
		return BlockArtifactInvalid
	}
}
