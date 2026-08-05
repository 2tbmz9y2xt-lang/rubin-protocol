package node

import (
	"crypto/sha3"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/filelock"
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

// LoadChainState reads the store_envelope_v1-wrapped snapshot. An ABSENT file
// keeps the NewChainState-plus-full-replay repair path; every present file must
// clear the strict envelope BEFORE the inner chainStateDisk decode runs.
// Envelope failures carry the ErrStoreIntegrity identity and never satisfy
// fs.ErrNotExist, so a corrupt file can never ride the absent-file fallback.
func LoadChainState(path string) (*ChainState, error) {
	raw, err := readFileByPath(path)
	if errors.Is(err, os.ErrNotExist) {
		return NewChainState(), nil
	}
	if err != nil {
		return nil, err
	}
	payload, err := openStoreEnvelope(storeEnvelopeChainState, raw)
	if err != nil {
		return nil, err
	}
	var disk chainStateDisk
	if err := json.Unmarshal(payload, &disk); err != nil {
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
	payload, err := json.MarshalIndent(disk, "", "  ")
	if err != nil {
		return fmt.Errorf("encode chainstate: %w", err)
	}
	payload = append(payload, '\n')
	// The pre-envelope on-disk bytes become the exact envelope payload.
	raw, err := marshalStoreEnvelope(storeEnvelopeChainState, payload)
	if err != nil {
		return err
	}
	if err := validateAtomicWriteDestination(path, atomicWriteOverwrite); err != nil {
		return err
	}
	// nosemgrep: Semgrep_go.lang.correctness.permissions.file_permission.incorrect-default-permission
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil { // nosemgrep
		return newAtomicWriteError(atomicWriteBeforeNamespaceCommit, path, atomicWriteOverwrite, err)
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

const (
	atomicWriteLockLeaf    = ".rubin-atomic-write.lock"
	atomicWriteScratchLeaf = ".rubin-atomic-write.tmp"
)

type atomicWriteStage string

const (
	atomicWriteBeforeNamespaceCommit atomicWriteStage = "before_namespace_commit"
	atomicWriteAfterNamespaceCommit  atomicWriteStage = "after_namespace_commit"
)

type atomicWriteOperation string

const (
	atomicWriteOverwrite      atomicWriteOperation = "overwrite"
	atomicWriteCreateIfAbsent atomicWriteOperation = "create_if_absent"
)

type atomicWriteError struct {
	stage       atomicWriteStage
	destination string
	operation   atomicWriteOperation
	primary     error
	secondary   []error
}

func (e *atomicWriteError) Error() string {
	if e == nil {
		return ""
	}
	if len(e.secondary) == 0 {
		return fmt.Sprintf("atomic write %s %s for %s: %v", e.stage, e.operation, e.destination, e.primary)
	}
	return fmt.Sprintf("atomic write %s %s for %s: %v (cleanup: %v)", e.stage, e.operation, e.destination, e.primary, errors.Join(e.secondary...))
}

func (e *atomicWriteError) Unwrap() []error {
	if e == nil {
		return nil
	}
	errList := make([]error, 0, 1+len(e.secondary))
	if e.primary != nil {
		errList = append(errList, e.primary)
	}
	return append(errList, e.secondary...)
}

func newAtomicWriteError(stage atomicWriteStage, destination string, operation atomicWriteOperation, primary error, secondary ...error) *atomicWriteError {
	clean := make([]error, 0, len(secondary))
	for _, err := range secondary {
		if err != nil {
			clean = append(clean, err)
		}
	}
	return &atomicWriteError{
		stage:       stage,
		destination: destination,
		operation:   operation,
		primary:     primary,
		secondary:   clean,
	}
}

func atomicWriteStageOf(err error) (atomicWriteStage, bool) {
	var atomicErr *atomicWriteError
	if !errors.As(err, &atomicErr) {
		return "", false
	}
	return atomicErr.stage, true
}

func isAtomicWritePostCommit(err error) bool {
	stage, ok := atomicWriteStageOf(err)
	return ok && stage == atomicWriteAfterNamespaceCommit
}

type atomicWriteScratchFile interface {
	io.Writer
	Sync() error
	Close() error
	Chmod(os.FileMode) error
}

type atomicWriteOps struct {
	openScratch func(string, int, os.FileMode) (atomicWriteScratchFile, error)
	rename      func(string, string) error
	link        func(string, string) error
	unlink      func(string) error
	syncParent  func(string) error
}

var atomicWriteIO = atomicWriteOps{
	openScratch: func(path string, flag int, mode os.FileMode) (atomicWriteScratchFile, error) {
		// nosemgrep: Semgrep_go_filesystem_rule-fileread
		return os.OpenFile(path, flag, mode) // nosemgrep
	},
	rename:     os.Rename,
	link:       os.Link,
	unlink:     atomicUnlink,
	syncParent: syncDir,
}

var atomicWriteProcessMu sync.Mutex

func validateAtomicWriteDestination(path string, operation atomicWriteOperation) error {
	leaf := filepath.Base(path)
	if leaf != atomicWriteLockLeaf && leaf != atomicWriteScratchLeaf {
		return nil
	}
	return newAtomicWriteError(
		atomicWriteBeforeNamespaceCommit,
		path,
		operation,
		fmt.Errorf("reserved atomic persistence destination: %s", path),
	)
}

// writeFileAtomic replaces path from a fixed 0600 scratch in its parent.
func writeFileAtomic(path string, data []byte, _ os.FileMode) error {
	if err := validateAtomicWriteDestination(path, atomicWriteOverwrite); err != nil {
		return err
	}
	return writeAtomicFile(path, data, atomicWriteOverwrite, nil)
}

func writeAtomicFile(path string, data []byte, operation atomicWriteOperation, resolveExisting func() error) error {
	if err := validateAtomicWriteDestination(path, operation); err != nil {
		return err
	}
	parent := filepath.Dir(path)
	atomicWriteProcessMu.Lock()
	defer atomicWriteProcessMu.Unlock()

	lock, result, err := filelock.Acquire(filepath.Join(parent, atomicWriteLockLeaf))
	if err != nil {
		return newAtomicWriteError(
			atomicWriteBeforeNamespaceCommit,
			path,
			operation,
			fmt.Errorf("atomic write lock failed: %s: %s: %w", parent, result, err),
		)
	}
	committed, writeErr := writeAtomicFileLocked(path, data, operation, resolveExisting)
	if releaseErr := lock.Release(); releaseErr != nil {
		return appendAtomicWriteReleaseError(writeErr, committed, path, operation, releaseErr)
	}
	return writeErr
}

func appendAtomicWriteReleaseError(writeErr error, committed bool, path string, operation atomicWriteOperation, releaseErr error) error {
	if writeErr == nil {
		stage := atomicWriteBeforeNamespaceCommit
		if committed {
			stage = atomicWriteAfterNamespaceCommit
		}
		return newAtomicWriteError(stage, path, operation, releaseErr)
	}
	var atomicErr *atomicWriteError
	if errors.As(writeErr, &atomicErr) {
		atomicErr.secondary = append(atomicErr.secondary, releaseErr)
	}
	return writeErr
}

func writeAtomicFileLocked(path string, data []byte, operation atomicWriteOperation, resolveExisting func() error) (bool, error) {
	parent := filepath.Dir(path)
	scratch := filepath.Join(parent, atomicWriteScratchLeaf)
	if err := atomicWriteIO.unlink(scratch); err != nil {
		return false, newAtomicWriteError(atomicWriteBeforeNamespaceCommit, path, operation, err)
	}

	file, err := atomicWriteIO.openScratch(scratch, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return false, atomicWritePreCommitFailure(path, operation, parent, scratch, err)
	}
	if err := file.Chmod(0o600); err != nil {
		closeErr := file.Close()
		return false, atomicWritePreCommitFailure(path, operation, parent, scratch, err, closeErr)
	}
	writeErr, closeErr := writeAndCloseAtomicScratch(file, data)
	if writeErr != nil {
		return false, atomicWritePreCommitFailure(path, operation, parent, scratch, writeErr, closeErr)
	}
	return commitAtomicScratch(path, operation, parent, scratch, resolveExisting)
}

func commitAtomicScratch(path string, operation atomicWriteOperation, parent, scratch string, resolveExisting func() error) (bool, error) {
	switch operation {
	case atomicWriteOverwrite:
		return commitAtomicOverwrite(path, operation, parent, scratch)
	case atomicWriteCreateIfAbsent:
		return commitAtomicCreateIfAbsent(path, operation, parent, scratch, resolveExisting)
	default:
		return false, atomicWritePreCommitFailure(path, operation, parent, scratch, errors.New("unknown atomic write operation"))
	}
}

func commitAtomicOverwrite(path string, operation atomicWriteOperation, parent, scratch string) (bool, error) {
	if err := atomicWriteIO.rename(scratch, path); err != nil {
		return false, atomicWritePreCommitFailure(path, operation, parent, scratch, err)
	}
	return true, atomicWritePostCommitFailure(path, operation, parent, scratch, nil)
}

func commitAtomicCreateIfAbsent(path string, operation atomicWriteOperation, parent, scratch string, resolveExisting func() error) (bool, error) {
	if err := atomicWriteIO.link(scratch, path); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return false, atomicWritePreCommitFailure(path, operation, parent, scratch, err)
		}
		if resolveExisting == nil {
			return false, atomicWritePreCommitFailure(path, operation, parent, scratch, errors.New("missing create-if-absent destination decision"))
		}
		if decisionErr := resolveExisting(); decisionErr != nil {
			return false, atomicWritePreCommitFailure(path, operation, parent, scratch, decisionErr)
		}
	}
	return true, atomicWritePostCommitFailure(path, operation, parent, scratch, nil)
}

func writeAndCloseAtomicScratch(file atomicWriteScratchFile, data []byte) (error, error) {
	writeErr := writeAllAtomicScratch(file, data)
	var syncErr error
	if writeErr == nil {
		syncErr = file.Sync()
	}
	closeErr := file.Close()
	if writeErr != nil {
		return writeErr, firstNonNil(syncErr, closeErr)
	}
	if syncErr != nil {
		return syncErr, closeErr
	}
	return closeErr, nil
}

func writeAllAtomicScratch(file io.Writer, data []byte) error {
	for written := 0; written < len(data); {
		n, err := file.Write(data[written:])
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		written += n
	}
	return nil
}

func firstNonNil(errs ...error) error {
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}

func atomicWritePreCommitFailure(path string, operation atomicWriteOperation, parent, scratch string, primary error, priorSecondary ...error) error {
	secondary := append([]error(nil), priorSecondary...)
	if err := atomicWriteIO.unlink(scratch); err != nil {
		secondary = append(secondary, err)
	}
	if err := atomicWriteIO.syncParent(parent); err != nil {
		secondary = append(secondary, err)
	}
	return newAtomicWriteError(atomicWriteBeforeNamespaceCommit, path, operation, primary, secondary...)
}

func atomicWritePostCommitFailure(path string, operation atomicWriteOperation, parent, scratch string, primary error) error {
	secondary := make([]error, 0, 1)
	if err := atomicWriteIO.unlink(scratch); err != nil {
		if primary == nil {
			primary = err
		} else {
			secondary = append(secondary, err)
		}
	}
	if err := atomicWriteIO.syncParent(parent); err != nil {
		if primary == nil {
			primary = err
		} else {
			secondary = append(secondary, err)
		}
	}
	if primary == nil {
		return nil
	}
	return newAtomicWriteError(atomicWriteAfterNamespaceCommit, path, operation, primary, secondary...)
}

// syncDir strictly persists the parent; permission errors remain durability errors.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	return errors.Join(d.Sync(), d.Close())
}

type atomicScratchReclaimError struct {
	parent string
	cause  error
}

func (e *atomicScratchReclaimError) Error() string {
	return fmt.Sprintf("atomic scratch reclaim failed: %s: %v", e.parent, e.cause)
}

func (e *atomicScratchReclaimError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.cause
}

// ReclaimAtomicWriteScratch visits the five production parents in frozen order.
func ReclaimAtomicWriteScratch(dataDir string) error {
	root := BlockStorePath(dataDir)
	parents := []string{
		dataDir,
		root,
		filepath.Join(root, "blocks"),
		filepath.Join(root, "headers"),
		filepath.Join(root, "undo"),
	}
	for _, parent := range parents {
		if err := ReclaimAtomicWriteScratchInParent(parent); err != nil {
			return err
		}
	}
	return nil
}

// ReclaimAtomicWriteScratchInParent reclaims only the named parent's scratch.
func ReclaimAtomicWriteScratchInParent(parent string) error {
	if err := reclaimAtomicWriteScratchInParent(parent); err != nil {
		return &atomicScratchReclaimError{parent: parent, cause: err}
	}
	return nil
}

func reclaimAtomicWriteScratchInParent(parent string) (resultErr error) {
	atomicWriteProcessMu.Lock()
	defer atomicWriteProcessMu.Unlock()
	lock, result, err := filelock.Acquire(filepath.Join(parent, atomicWriteLockLeaf))
	if err != nil {
		return fmt.Errorf("atomic write lock failed: %s: %s: %w", parent, result, err)
	}
	defer func() {
		if releaseErr := lock.Release(); resultErr == nil && releaseErr != nil {
			resultErr = releaseErr
		}
	}()
	if err := atomicWriteIO.unlink(filepath.Join(parent, atomicWriteScratchLeaf)); err != nil {
		return err
	}
	if err := atomicWriteIO.syncParent(parent); err != nil {
		return err
	}
	return nil
}
