package node

import (
	"crypto/sha3"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

func stateToDisk(s *ChainState) (chainStateDisk, error) {
	if s == nil {
		return chainStateDisk{}, errors.New("nil chainstate")
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	utxos := make([]utxoDiskEntry, 0, len(s.Utxos))
	for op, entry := range s.Utxos {
		utxos = append(utxos, utxoDiskEntry{
			Txid:              hex.EncodeToString(op.Txid[:]),
			Vout:              op.Vout,
			Value:             entry.Value,
			CovenantType:      entry.CovenantType,
			CovenantData:      hex.EncodeToString(entry.CovenantData),
			CreationHeight:    entry.CreationHeight,
			CreatedByCoinbase: entry.CreatedByCoinbase,
		})
	}
	sort.Slice(utxos, func(i, j int) bool {
		if utxos[i].Txid != utxos[j].Txid {
			return utxos[i].Txid < utxos[j].Txid
		}
		return utxos[i].Vout < utxos[j].Vout
	})

	return chainStateDisk{
		Version:          chainStateDiskVersion,
		HasTip:           s.HasTip,
		Height:           s.Height,
		TipHash:          hex.EncodeToString(s.TipHash[:]),
		AlreadyGenerated: s.AlreadyGenerated,
		Utxos:            utxos,
	}, nil
}

func chainStateFromDisk(disk chainStateDisk) (*ChainState, error) {
	if disk.Version != chainStateDiskVersion {
		return nil, fmt.Errorf("unsupported chainstate version: %d", disk.Version)
	}

	tipHash, err := parseHex32("tip_hash", disk.TipHash)
	if err != nil {
		return nil, err
	}
	utxos := make(map[consensus.Outpoint]consensus.UtxoEntry, len(disk.Utxos))
	for _, item := range disk.Utxos {
		txid, err := parseHex32("utxo.txid", item.Txid)
		if err != nil {
			return nil, err
		}
		covData, err := parseHex("utxo.covenant_data", item.CovenantData)
		if err != nil {
			return nil, err
		}
		op := consensus.Outpoint{
			Txid: txid,
			Vout: item.Vout,
		}
		if _, exists := utxos[op]; exists {
			return nil, fmt.Errorf("duplicate utxo outpoint: %s:%d", item.Txid, item.Vout)
		}
		utxos[op] = consensus.UtxoEntry{
			Value:             item.Value,
			CovenantType:      item.CovenantType,
			CovenantData:      covData,
			CreationHeight:    item.CreationHeight,
			CreatedByCoinbase: item.CreatedByCoinbase,
		}
	}
	return &ChainState{
		HasTip:           disk.HasTip,
		Height:           disk.Height,
		TipHash:          tipHash,
		AlreadyGenerated: disk.AlreadyGenerated,
		Utxos:            utxos,
	}, nil
}
func ChainStatePath(dataDir string) string {
	return filepath.Join(dataDir, chainStateFileName)
}

func LoadChainState(path string) (*ChainState, error) {
	raw, err := readFileByPath(path)
	if errors.Is(err, os.ErrNotExist) {
		return NewChainState(), nil
	}
	if err != nil {
		return nil, err
	}
	var disk chainStateDisk
	if err := json.Unmarshal(raw, &disk); err != nil {
		return nil, fmt.Errorf("decode chainstate: %w", err)
	}
	return chainStateFromDisk(disk)
}

func (s *ChainState) Save(path string) error {
	if s == nil {
		return errors.New("nil chainstate")
	}
	disk, err := stateToDisk(s)
	if err != nil {
		return err
	}
	raw, err := json.MarshalIndent(disk, "", "  ")
	if err != nil {
		return fmt.Errorf("encode chainstate: %w", err)
	}
	raw = append(raw, '\n')
	// nosemgrep: directory permissions require execute bit for traversal; 0o600 would block directory access
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return writeFileAtomic(path, raw, 0o600)
}

func DevnetGenesisChainID() [32]byte {
	return devnetGenesisChainID
}

func DevnetGenesisBlockBytes() []byte {
	return append([]byte(nil), devnetGenesisBlockBytes...)
}

func DevnetGenesisBlockHash() [32]byte {
	return devnetGenesisBlockHash
}

// copyUtxoEntry is the canonical deep-copy helper for readonly snapshot/work-copy
// contracts in node package code. Callers should build full-set or subset copies
// from this helper rather than open-coding new UTXO copy variants.
func copyUtxoEntry(entry consensus.UtxoEntry) consensus.UtxoEntry {
	return consensus.UtxoEntry{
		Value:             entry.Value,
		CovenantType:      entry.CovenantType,
		CovenantData:      append([]byte(nil), entry.CovenantData...),
		CreationHeight:    entry.CreationHeight,
		CreatedByCoinbase: entry.CreatedByCoinbase,
	}
}

func copyUtxoSet(src map[consensus.Outpoint]consensus.UtxoEntry) map[consensus.Outpoint]consensus.UtxoEntry {
	out := make(map[consensus.Outpoint]consensus.UtxoEntry, len(src))
	for k, v := range src {
		out[k] = copyUtxoEntry(v)
	}
	return out
}

func copySelectedUtxoSet(src map[consensus.Outpoint]consensus.UtxoEntry, outpoints []consensus.Outpoint) map[consensus.Outpoint]consensus.UtxoEntry {
	out := make(map[consensus.Outpoint]consensus.UtxoEntry, countExistingUniqueOutpoints(src, outpoints))
	for _, op := range outpoints {
		if _, seen := out[op]; seen {
			continue
		}
		entry, ok := src[op]
		if !ok {
			continue
		}
		out[op] = copyUtxoEntry(entry)
	}
	return out
}

func countExistingUniqueOutpoints(src map[consensus.Outpoint]consensus.UtxoEntry, outpoints []consensus.Outpoint) int {
	if len(src) == 0 || len(outpoints) == 0 {
		return 0
	}
	seen := make(map[consensus.Outpoint]struct{}, len(outpoints))
	count := 0
	for _, op := range outpoints {
		if _, ok := seen[op]; ok {
			continue
		}
		seen[op] = struct{}{}
		if _, ok := src[op]; ok {
			count++
		}
	}
	return count
}

func decodeHexToBytesExact(value string, expectedLen int) []byte {
	raw := strings.TrimSpace(value)
	out, err := hex.DecodeString(raw)
	if err != nil {
		panic(fmt.Sprintf("invalid hex: %v", err))
	}
	if len(out) != expectedLen {
		panic(fmt.Sprintf("expected %d bytes, got %d", expectedLen, len(out)))
	}
	return out
}

func decodeHexToBytes32(value string) [32]byte {
	raw := decodeHexToBytesExact(value, 32)
	var out [32]byte
	copy(out[:], raw)
	return out
}

func deriveGenesisChainID(headerBytes, txBytes []byte) [32]byte {
	// Chain ID = SHA3-256("RUBIN-GENESIS-v1" || header || compact_size(tx_count) || tx_bytes)
	preimage := append([]byte{}, []byte(genesisMagicSeparator)...)
	preimage = append(preimage, headerBytes...)
	preimage = consensus.AppendCompactSize(preimage, 1) // tx_count = 1
	preimage = append(preimage, txBytes...)
	return sha3.Sum256(preimage)
}

func parseHex(name, value string) ([]byte, error) {
	trimmed := strings.TrimSpace(value)
	if len(trimmed)%2 != 0 {
		return nil, fmt.Errorf("%s: odd-length hex", name)
	}
	out, err := hex.DecodeString(trimmed)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return out, nil
}

func parseHex32(name, value string) ([32]byte, error) {
	var out [32]byte
	raw, err := parseHex(name, value)
	if err != nil {
		return out, err
	}
	if len(raw) != 32 {
		return out, fmt.Errorf("%s: expected 32 bytes, got %d", name, len(raw))
	}
	copy(out[:], raw)
	return out, nil
}

func nextBlockContext(s *ChainState) (uint64, *[32]byte, error) {
	if s == nil {
		return 0, nil, errors.New("nil chainstate")
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return nextBlockContextFromFields(s.HasTip, s.Height, s.TipHash)
}

func nextBlockContextFromFields(hasTip bool, height uint64, tipHash [32]byte) (uint64, *[32]byte, error) {
	if !hasTip {
		return 0, nil, nil
	}
	if height == math.MaxUint64 {
		return 0, nil, errors.New("height overflow")
	}
	nextHeight := height + 1
	prev := tipHash
	return nextHeight, &prev, nil
}

// writeFileAtomic writes data to path via a temp+rename pattern with an
// honest fsync durability contract (E.1). The actual file IO lives in
// the helpers allocateAndWriteTemp, writeAndSyncTemp, and syncDir.
//
// Sequence (any failure removes the temp file before returning):
//  1. delegate to allocateAndWriteTemp: pick a unique temp path via
//     tempPathFor+nextTempSeq and delegate to writeAndSyncTemp, which
//     opens the temp with O_CREATE|O_EXCL|O_WRONLY (NO O_TRUNC — see
//     that helper's doc for the crash-safety rationale), loops Write
//     until all bytes are persisted, Sync, Close, returns joined
//     errors. A stale-temp collision (PID + seq reuse across a crash)
//     retries up to maxTempAllocRetries with a fresh seq;
//  2. Rename temp -> destination (atomic on the same filesystem);
//  3. delegate to syncDir on the parent directory so the rename itself
//     is durable (without this the destination's bytes are on disk
//     after step 1's Sync, but the directory entry mapping `path` to
//     the new inode may still live only in the kernel page cache and
//     be lost on crash).
//
// Mirrors the Rust `clients/rust/crates/rubin-node/src/io_utils.rs`
// `write_file_atomic` for cross-client storage parity.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	tmpPath, err := allocateAndWriteTemp(path, data, mode)
	if err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	return syncDir(filepath.Dir(path))
}

// tempSeq is a process-wide monotonic counter appended to every
// temp-file name so two concurrent writers in the same process
// (goroutines, or the same goroutine retrying after a previous failed
// attempt) never collide on a shared `.tmp.<pid>` path (audit E.3).
// Without this, two goroutines writing different content to the same
// destination would silently overwrite each other's temp bytes between
// Write and Rename/Link.
//
// Scope is in-process uniqueness only. After a process crash the
// counter resets to zero, and PID reuse across processes is possible
// on long-running systems — so a fresh process CAN pick the same
// `<pid>.<seq>` prefix as a stale leftover on disk. That cross-process
// collision is handled at a different layer: `writeAndSyncTemp` opens
// the temp with O_CREATE|O_EXCL (no O_TRUNC) and returns os.ErrExist
// on collision, and `allocateAndWriteTemp` retries with a fresh seq
// up to `maxTempAllocRetries` times. tempSeq narrows the collision
// window; O_EXCL + retries close it.
//
// Note: this is a filesystem-uniqueness counter, not a cryptographic
// nonce.
var tempSeq atomic.Uint64

func nextTempSeq() uint64 {
	return tempSeq.Add(1)
}

// tempPathFor builds the companion temp path for a destination. Keeps
// pid + monotonic seq in the filename so the temp is unique across
// threads, processes, and retries. Mirrors the Rust
// `io_utils::temp_path_for` helper for cross-client parity.
func tempPathFor(path string, pid int, seq uint64) string {
	return fmt.Sprintf("%s.tmp.%d.%d", path, pid, seq)
}

// maxTempAllocRetries bounds the stale-temp collision retries in
// allocateAndWriteTemp. A collision on `<dest>.tmp.<pid>.<seq>` should
// be vanishingly rare (it requires PID reuse PLUS nextTempSeq wrapping
// back over a stale leftover from a prior process), so 16 is
// deliberately generous for the tail case while bounding pathological
// loops.
const maxTempAllocRetries = 16

// allocateAndWriteTemp picks a unique temp path for `path`, writes
// `data` to it via writeAndSyncTemp (exclusive-create + fsync), and
// returns the temp path on success. Retries up to maxTempAllocRetries
// with a fresh nextTempSeq on the rare os.ErrExist case (stale
// leftover temp after PID + seq reuse across a crash). Fatal I/O
// errors surface immediately without retry.
//
// On success the caller owns `tmpPath` and is responsible for the
// final rename/link + removing the temp name on error paths. On
// failure writeAndSyncTemp already best-effort removes the temp
// before returning.
func allocateAndWriteTemp(path string, data []byte, mode os.FileMode) (string, error) {
	pid := os.Getpid()
	var lastCollision error
	for i := 0; i < maxTempAllocRetries; i++ {
		tmpPath := tempPathFor(path, pid, nextTempSeq())
		err := writeAndSyncTemp(tmpPath, data, mode)
		if err == nil {
			return tmpPath, nil
		}
		if errors.Is(err, os.ErrExist) {
			lastCollision = fmt.Errorf("temp path already exists: %s", tmpPath)
			continue
		}
		return "", err
	}
	if lastCollision == nil {
		lastCollision = fmt.Errorf("exhausted %d retries allocating temp for %s", maxTempAllocRetries, path)
	}
	return "", lastCollision
}

// writeAndSyncTemp writes data to a fresh temp path, syncs the file's
// bytes and inode metadata to stable storage, and closes it. Opens
// with O_CREATE|O_EXCL|O_WRONLY — NO O_TRUNC — so a stale temp
// leftover from a crashed prior process that happens to be hard-linked
// to a live destination inode cannot be truncated through the shared
// inode (Copilot P1 audit on PR #1220). The caller
// (allocateAndWriteTemp) retries with a fresh seq on os.ErrExist.
//
// Write is looped until all bytes are persisted, matching Rust's
// `Write::write_all` contract: io.Writer is allowed to return a short
// write without an error, and treating that as success would let us
// sync+rename a truncated file (Copilot review feedback on PR #1218).
// A zero-byte short write is reported as io.ErrShortWrite to avoid an
// infinite loop on a well-behaved-but-stuck writer.
//
// We always run Write, Sync and Close, then combine their errors with
// errors.Join (Go 1.20+). This guarantees:
//  1. the Close error is NOT silently dropped — it surfaces in the joined
//     error and reaches the caller;
//  2. the FD is always released, even when Write or Sync fail, without
//     duplicating cleanup branches that would otherwise be unreachable
//     from a unit test (no realistic way to provoke a Write or Sync
//     failure on an already-opened regular file in CI).
//
// On any error after successful open, the temp is best-effort removed
// before returning so callers (allocateAndWriteTemp / writeFileAtomic
// / writeFileIfAbsent) do not need to clean up the error path.
func writeAndSyncTemp(tmpPath string, data []byte, mode os.FileMode) error {
	// nosemgrep: tmpPath derived from os.Getpid + atomic counter, zero external input; O_EXCL prevents overwrite
	tmp, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	var werr error
	for written := 0; written < len(data); {
		n, e := tmp.Write(data[written:])
		if e != nil {
			werr = e
			break
		}
		if n == 0 {
			werr = io.ErrShortWrite
			break
		}
		written += n
	}
	serr := tmp.Sync()
	cerr := tmp.Close()
	joined := errors.Join(werr, serr, cerr)
	if joined != nil {
		_ = os.Remove(tmpPath)
	}
	return joined
}

// syncDir opens the directory and calls Sync so any rename or unlink
// performed in it is itself durable. Unix-only: directory Sync is the
// portable way to flush the parent's directory entry on Linux/macOS;
// Windows lacks an equivalent and is not a Rubin production target.
//
// Sync and Close errors are combined via errors.Join so a Close error after
// a successful Sync still surfaces (Copilot review feedback on PR #1218,
// mirrors the writeAndSyncTemp pattern).
//
// Best-effort on permission-denied open: a parent directory with mode
// 0300 (write+execute, no read) permits create/rename but blocks
// os.Open(dir) for reading (Codex review feedback on PR #1218). The
// rename has already succeeded by the time we get here, so returning
// an error would make the caller treat committed state as failed on
// hardened directory-permission setups. Return nil instead — the
// destination bytes are already on disk via the temp file's Sync; only
// the directory-entry fsync is degraded to best-effort. Any other open
// error (ENOENT, EIO, etc) still propagates as a real anomaly.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		if errors.Is(err, fs.ErrPermission) {
			return nil
		}
		return err
	}
	serr := d.Sync()
	cerr := d.Close()
	return errors.Join(serr, cerr)
}
