package node

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"syscall"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

const (
	noncanonicalDefaultByteLimit = uint64(8) << 30
	noncanonicalMaximumByteLimit = uint64(32) << 30
	noncanonicalHashCap          = 524288
	noncanonicalUnknownHeight    = ^uint64(0)
	noncanonicalRowWireBytes     = 98
)

var (
	closeNoncanonicalFile = (*os.File).Close
	errNoncanonicalBytes  = errors.New("LOCAL_RESOURCE_UNAVAILABLE(noncanonical_bytes)")
	errNoncanonicalCount  = errors.New("LOCAL_RESOURCE_UNAVAILABLE(noncanonical_count)")
)

type noncanonicalArtifactKind uint8

const (
	noncanonicalBlockArtifact noncanonicalArtifactKind = iota
	noncanonicalHeaderArtifact
	noncanonicalUndoArtifact
	noncanonicalStateMask    = uint16(3)
	noncanonicalReservedBase = uint16(1 << 6)
)

// noncanonicalRow is a fixed accounting image row, not durable authority.
type noncanonicalRow struct {
	hash                               [32]byte
	prev                               [32]byte
	blockBytes, headerBytes, undoBytes uint64
	height                             uint64
	flags                              uint16
}

const (
	noncanonicalRowBytes     = uint64(128)
	noncanonicalBackingBytes = uint64(noncanonicalHashCap) * noncanonicalRowBytes
)

type noncanonicalAccounting struct {
	rows                     []noncanonicalRow
	usedBytes, reservedBytes uint64
	count, sortedCount       uint32
	limit                    uint64
}
type noncanonicalAccountingSnapshot struct {
	usedBytes, reservedBytes uint64
	uniqueCount              uint32
	rows                     []noncanonicalRow
}

func normalizeNoncanonicalLimit(limit uint64) (uint64, error) {
	if limit == 0 {
		return noncanonicalDefaultByteLimit, nil
	}
	if limit < noncanonicalDefaultByteLimit || limit > noncanonicalMaximumByteLimit {
		return 0, fmt.Errorf("invalid noncanonical byte limit %d: want 0 or [%d,%d]", limit, noncanonicalDefaultByteLimit, noncanonicalMaximumByteLimit)
	}
	return limit, nil
}

func newNoncanonicalAccounting(limit uint64) (*noncanonicalAccounting, error) {
	limit, err := normalizeNoncanonicalLimit(limit)
	if err != nil {
		return nil, err
	}
	return &noncanonicalAccounting{rows: make([]noncanonicalRow, noncanonicalHashCap), limit: limit}, nil
}

func (bs *BlockStore) noncanonicalAccountingSnapshot() noncanonicalAccountingSnapshot {
	if bs == nil {
		return noncanonicalAccountingSnapshot{}
	}
	bs.stateMu.RLock()
	defer bs.stateMu.RUnlock()
	a := bs.noncanonical.Load()
	if a == nil {
		return noncanonicalAccountingSnapshot{}
	}
	return noncanonicalAccountingSnapshot{
		usedBytes: a.usedBytes, reservedBytes: a.reservedBytes, uniqueCount: a.count,
		rows: append([]noncanonicalRow(nil), a.rows[:a.count]...),
	}
}

func (bs *BlockStore) noncanonicalAccountingDigest() [32]byte {
	snapshot := bs.noncanonicalAccountingSnapshot()
	h := sha256.New()
	var header [20]byte
	binary.LittleEndian.PutUint64(header[0:8], snapshot.usedBytes)
	binary.LittleEndian.PutUint64(header[8:16], snapshot.reservedBytes)
	binary.LittleEndian.PutUint32(header[16:20], snapshot.uniqueCount)
	_, _ = h.Write(header[:])
	for _, row := range snapshot.rows {
		var raw [noncanonicalRowWireBytes]byte
		copy(raw[0:32], row.hash[:])
		copy(raw[32:64], row.prev[:])
		binary.LittleEndian.PutUint64(raw[64:72], row.blockBytes)
		binary.LittleEndian.PutUint64(raw[72:80], row.headerBytes)
		binary.LittleEndian.PutUint64(raw[80:88], row.undoBytes)
		binary.LittleEndian.PutUint64(raw[88:96], row.height)
		binary.LittleEndian.PutUint16(raw[96:98], row.flags)
		_, _ = h.Write(raw[:])
	}
	var digest [32]byte
	copy(digest[:], h.Sum(nil))
	return digest
}

func (a *noncanonicalAccounting) find(hash [32]byte) (int, bool) { return a.findPrefix(hash, a.count) }

func (a *noncanonicalAccounting) findPrefix(hash [32]byte, count uint32) (int, bool) {
	n := int(count)
	at := sort.Search(n, func(i int) bool { return bytes.Compare(a.rows[i].hash[:], hash[:]) >= 0 })
	return at, at < n && a.rows[at].hash == hash
}

func (a *noncanonicalAccounting) appendRow(hash [32]byte) (*noncanonicalRow, error) {
	if a.count >= noncanonicalHashCap {
		return nil, errNoncanonicalCount
	}
	at := int(a.count)
	a.count++
	a.rows[at] = noncanonicalRow{hash: hash, height: noncanonicalUnknownHeight}
	return &a.rows[at], nil
}

func (a *noncanonicalAccounting) insertRow(hash [32]byte, at int) (*noncanonicalRow, error) {
	if a.count >= noncanonicalHashCap {
		return nil, errNoncanonicalCount
	}
	n := int(a.count)
	copy(a.rows[at+1:n+1], a.rows[at:n])
	a.count++
	a.sortedCount = a.count
	a.rows[at] = noncanonicalRow{hash: hash, height: noncanonicalUnknownHeight}
	return &a.rows[at], nil
}

func (a *noncanonicalAccounting) rowForScan(hash [32]byte) (*noncanonicalRow, error) {
	if at, found := a.findPrefix(hash, a.sortedCount); found {
		return &a.rows[at], nil
	}
	return a.appendRow(hash)
}

func (a *noncanonicalAccounting) sortRows() {
	sort.Slice(a.rows[:a.count], func(i, j int) bool { return bytes.Compare(a.rows[i].hash[:], a.rows[j].hash[:]) < 0 })
	a.sortedCount = a.count
}

func checkedNoncanonicalAdd(left, right uint64) (uint64, bool) {
	if ^uint64(0)-left < right {
		return 0, false
	}
	return left + right, true
}

func (a *noncanonicalAccounting) canReserve(bytesToReserve uint64, addCount bool) error {
	if addCount && a.count >= noncanonicalHashCap {
		return errNoncanonicalCount
	}
	total, ok := checkedNoncanonicalAdd(a.usedBytes, a.reservedBytes)
	if !ok {
		return errNoncanonicalBytes
	}
	total, ok = checkedNoncanonicalAdd(total, bytesToReserve)
	if !ok || total > a.limit {
		return errNoncanonicalBytes
	}
	return nil
}
func artifactShift(kind noncanonicalArtifactKind) uint16 { return uint16(kind) * 2 }
func artifactReservedBit(kind noncanonicalArtifactKind) uint16 {
	return noncanonicalReservedBase << kind
}

func artifactStateBits(state BlockArtifactState) uint16 {
	switch state {
	case BlockArtifactValid:
		return 1
	case BlockArtifactInvalid:
		return 2
	default:
		return 0
	}
}

func (r *noncanonicalRow) state(kind noncanonicalArtifactKind) BlockArtifactState {
	switch (r.flags >> artifactShift(kind)) & noncanonicalStateMask {
	case 1:
		return BlockArtifactValid
	case 2:
		return BlockArtifactInvalid
	default:
		return BlockArtifactAbsent
	}
}

func (r *noncanonicalRow) setState(kind noncanonicalArtifactKind, state BlockArtifactState) {
	shift := artifactShift(kind)
	r.flags &^= noncanonicalStateMask << shift
	r.flags |= artifactStateBits(state) << shift
}

func (r *noncanonicalRow) setValidMetadata(kind noncanonicalArtifactKind, state BlockArtifactState, prev [32]byte, height uint64) {
	if state != BlockArtifactValid {
		return
	}
	switch kind {
	case noncanonicalBlockArtifact, noncanonicalHeaderArtifact:
		r.prev = prev
	case noncanonicalUndoArtifact:
		r.height = height
	}
}

func (r *noncanonicalRow) bytes(kind noncanonicalArtifactKind) *uint64 {
	switch kind {
	case noncanonicalHeaderArtifact:
		return &r.headerBytes
	case noncanonicalUndoArtifact:
		return &r.undoBytes
	default:
		return &r.blockBytes
	}
}

func (r *noncanonicalRow) hasReservation(kind noncanonicalArtifactKind) bool {
	return r.flags&artifactReservedBit(kind) != 0
}

func (r *noncanonicalRow) setReservation(kind noncanonicalArtifactKind, value uint64) {
	*r.bytes(kind) = value
	r.flags |= artifactReservedBit(kind)
}

func (r *noncanonicalRow) clearReservation(kind noncanonicalArtifactKind) uint64 {
	value := *r.bytes(kind)
	*r.bytes(kind) = 0
	r.flags &^= artifactReservedBit(kind)
	return value
}

func (r *noncanonicalRow) empty() bool {
	return r.flags&(noncanonicalStateMask<<artifactShift(noncanonicalBlockArtifact)|noncanonicalStateMask<<artifactShift(noncanonicalHeaderArtifact)|noncanonicalStateMask<<artifactShift(noncanonicalUndoArtifact)|artifactReservedBit(noncanonicalBlockArtifact)|artifactReservedBit(noncanonicalHeaderArtifact)|artifactReservedBit(noncanonicalUndoArtifact)) == 0
}

func (a *noncanonicalAccounting) remove(at int) {
	n := int(a.count)
	copy(a.rows[at:n-1], a.rows[at+1:n])
	a.count--
	a.sortedCount = a.count
	a.rows[a.count] = noncanonicalRow{}
}

func (a *noncanonicalAccounting) addScanned(hash [32]byte, kind noncanonicalArtifactKind, size uint64, state BlockArtifactState, prev [32]byte, height uint64) error {
	_, found := a.findPrefix(hash, a.sortedCount)
	if err := a.canReserve(size, !found); err != nil {
		return err
	}
	row, err := a.rowForScan(hash)
	if err != nil {
		return err
	}
	a.usedBytes += size
	*row.bytes(kind) = size
	row.setState(kind, state)
	row.setValidMetadata(kind, state, prev, height)
	return nil
}

// rebuildNoncanonicalAccounting is test-only reachability: production never calls it.
func (bs *BlockStore) rebuildNoncanonicalAccounting(limit uint64) (*noncanonicalAccounting, error) {
	if bs == nil {
		return nil, errors.New("nil blockstore")
	}
	if err := requireCompleteCanonicalPrefix(bs); err != nil {
		return nil, err
	}
	accounting, err := newNoncanonicalAccounting(limit)
	if err != nil {
		return nil, err
	}
	for _, kind := range []noncanonicalArtifactKind{noncanonicalBlockArtifact, noncanonicalHeaderArtifact, noncanonicalUndoArtifact} {
		if err := bs.scanNoncanonicalDirectory(accounting, kind); err != nil {
			return nil, err
		}
		accounting.sortRows()
	}
	return accounting, nil
}

func (bs *BlockStore) scanNoncanonicalDirectory(accounting *noncanonicalAccounting, kind noncanonicalArtifactKind) (resultErr error) {
	dir, suffix, limit := bs.noncanonicalArtifactPath(kind)
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := closeNoncanonicalFile(d); resultErr == nil && closeErr != nil {
			resultErr = closeErr
		}
	}()
	directory, err := d.Stat()
	if err != nil {
		return err
	}
	for {
		entries, readErr := d.ReadDir(1)
		if len(entries) == 1 {
			if err := bs.scanNoncanonicalEntry(accounting, kind, dir, suffix, limit, directory, entries[0]); err != nil {
				return err
			}
		}
		if errors.Is(readErr, io.EOF) {
			bs.probeLeaf()
			return stableNoncanonicalDirectory(dir, directory)
		}
		if readErr != nil {
			return readErr
		}
	}
}

func (bs *BlockStore) noncanonicalArtifactPath(kind noncanonicalArtifactKind) (string, string, int64) {
	switch kind {
	case noncanonicalHeaderArtifact:
		return bs.headersDir, ".bin", headerFileMaxBytes
	case noncanonicalUndoArtifact:
		return bs.undoDir, ".json", undoFileMaxBytes
	default:
		return bs.blocksDir, ".bin", blockFileMaxBytes
	}
}

func (bs *BlockStore) scanNoncanonicalEntry(accounting *noncanonicalAccounting, kind noncanonicalArtifactKind, dir, suffix string, limit int64, directory os.FileInfo, entry os.DirEntry) error {
	name := entry.Name()
	if name == atomicWriteLockLeaf || name == atomicWriteScratchLeaf {
		return nil
	}
	hash, err := noncanonicalArtifactHash(name, suffix)
	if err != nil {
		return err
	}
	bs.stateMu.RLock()
	_, canonical := bs.canonicalHeightByHash[hash]
	bs.stateMu.RUnlock()
	if canonical {
		return nil
	}
	entryInfo, err := entry.Info()
	if err != nil {
		return err
	}
	bs.probeLeaf()
	state, prev, height, size, err := bs.strictNoncanonicalArtifact(kind, dir, name, limit, directory, entryInfo, hash)
	if err != nil {
		return err
	}
	return accounting.addScanned(hash, kind, size, state, prev, height)
}

func noncanonicalArtifactHash(name, suffix string) ([32]byte, error) {
	if len(name) != 64+len(suffix) || name[64:] != suffix || !validCanonicalHashHex(name[:64]) {
		return [32]byte{}, fmt.Errorf("unexpected noncanonical artifact name: %q", name)
	}
	return parseHex32("noncanonical artifact hash", name[:64])
}

func (bs *BlockStore) strictNoncanonicalArtifact(kind noncanonicalArtifactKind, dir, name string, limit int64, directory, entryInfo os.FileInfo, hash [32]byte) (BlockArtifactState, [32]byte, uint64, uint64, error) {
	var zero [32]byte
	raw, size, err := bs.readNoncanonicalArtifact(dir, name, limit, directory, entryInfo)
	if err != nil {
		return BlockArtifactAbsent, zero, noncanonicalUnknownHeight, 0, fmt.Errorf("read noncanonical artifact %s: %w", name, err)
	}
	switch kind {
	case noncanonicalBlockArtifact:
		state, prev := noncanonicalStoredBlockState(raw, hash)
		return state, prev, noncanonicalUnknownHeight, size, nil
	case noncanonicalHeaderArtifact:
		if validateBlockHeaderHash(raw, hash) == nil {
			if header, err := consensus.ParseBlockHeaderBytes(raw); err == nil {
				return BlockArtifactValid, header.PrevBlockHash, noncanonicalUnknownHeight, size, nil
			}
		}
		return BlockArtifactInvalid, zero, noncanonicalUnknownHeight, size, nil
	default:
		if undo, err := unmarshalUndoEnvelope(hash, raw); err == nil {
			return BlockArtifactValid, zero, undo.BlockHeight, size, nil
		}
		return BlockArtifactInvalid, zero, noncanonicalUnknownHeight, size, nil
	}
}

func (bs *BlockStore) readNoncanonicalArtifact(dir, name string, limit int64, directory, entryInfo os.FileInfo) ([]byte, uint64, error) {
	file, before, size, err := bs.openNoncanonicalArtifact(dir, name, limit, directory, entryInfo)
	if err != nil {
		return nil, 0, err
	}
	raw, err := bs.readOpenedNoncanonicalArtifact(file, filepath.Join(dir, name), name, limit, dir, directory, before, size)
	if err != nil {
		return nil, 0, err
	}
	return raw, uint64(len(raw)), nil
}

func (bs *BlockStore) openNoncanonicalArtifact(dir, name string, limit int64, directory, entryInfo os.FileInfo) (file *os.File, before os.FileInfo, size int64, resultErr error) {
	if resultErr = stableNoncanonicalDirectory(dir, directory); resultErr != nil {
		return
	}
	path := filepath.Join(dir, name)
	if before, resultErr = os.Lstat(path); resultErr != nil {
		return
	}
	if !sameNoncanonicalArtifactSnapshot(entryInfo, before, entryInfo.Size()) {
		resultErr = errors.New("noncanonical artifact enumeration drift")
		return
	}
	bs.probeLeaf()
	if file, resultErr = openNoncanonicalArtifactFile(path); resultErr != nil {
		return
	}
	defer func() {
		if resultErr != nil {
			_ = closeNoncanonicalFile(file)
			file = nil
		}
	}()
	opened, err := file.Stat()
	if err != nil {
		resultErr = err
		return
	}
	size = opened.Size()
	if !validNoncanonicalArtifactSize(size, limit) {
		resultErr = errFileTooLarge(name, size, limit)
		return
	}
	if !sameNoncanonicalArtifactSnapshot(before, opened, size) {
		resultErr = errors.New("noncanonical artifact is not the opened regular leaf")
	}
	return
}

func openNoncanonicalArtifactFile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
}
func validNoncanonicalArtifactSize(size, limit int64) bool { return size >= 0 && size <= limit }
func (bs *BlockStore) readOpenedNoncanonicalArtifact(file *os.File, path, name string, limit int64, dir string, directory, before os.FileInfo, size int64) (raw []byte, resultErr error) {
	closed := false
	defer func() {
		if !closed {
			if closeErr := closeNoncanonicalFile(file); resultErr == nil && closeErr != nil {
				resultErr = closeErr
			}
		}
	}()
	raw, resultErr = bs.readAndVerifyNoncanonicalArtifact(file, path, name, limit, before, size)
	if resultErr != nil {
		return
	}
	resultErr = bs.closeAndCheckNoncanonicalArtifact(file, path, dir, directory, before, size)
	closed = true
	return
}

func (bs *BlockStore) readAndVerifyNoncanonicalArtifact(file *os.File, path, name string, limit int64, before os.FileInfo, size int64) ([]byte, error) {
	bs.probeLeaf()
	raw, err := readCapped(file, name, capHint(size, limit), limit)
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) != size {
		return nil, errors.New("noncanonical artifact changed while reading")
	}
	afterHandle, err := file.Stat()
	if err != nil {
		return nil, err
	}
	after, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !sameNoncanonicalArtifactSnapshot(before, afterHandle, size) || !sameNoncanonicalArtifactSnapshot(before, after, size) {
		return nil, errors.New("noncanonical artifact identity drift")
	}
	return raw, nil
}

func (bs *BlockStore) closeAndCheckNoncanonicalArtifact(file *os.File, path, dir string, directory, before os.FileInfo, size int64) error {
	if err := closeNoncanonicalFile(file); err != nil {
		return err
	}
	bs.probeLeaf()
	final, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !sameNoncanonicalArtifactSnapshot(before, final, size) {
		return errors.New("noncanonical artifact close drift")
	}
	return stableNoncanonicalDirectory(dir, directory)
}

func stableNoncanonicalDirectory(dir string, opened os.FileInfo) error {
	current, err := os.Lstat(dir)
	if err == nil && (!opened.IsDir() || !current.IsDir() || opened.Size() != current.Size() || !opened.ModTime().Equal(current.ModTime()) || !os.SameFile(opened, current)) {
		return errors.New("noncanonical artifact directory identity drift")
	}
	return err
}

func sameNoncanonicalArtifactSnapshot(before, after os.FileInfo, size int64) bool {
	return before.Mode().IsRegular() && after.Mode().IsRegular() && before.Size() == size && after.Size() == size && before.ModTime().Equal(after.ModTime()) && os.SameFile(before, after)
}

func noncanonicalStoredBlockState(raw []byte, hash [32]byte) (BlockArtifactState, [32]byte) {
	if parsed, err := consensus.ParseBlockBytes(raw); err == nil {
		if observed, err := consensus.BlockHash(parsed.HeaderBytes); err == nil && observed == hash {
			return BlockArtifactValid, parsed.Header.PrevBlockHash
		}
	}
	return BlockArtifactInvalid, [32]byte{}
}

func preflightNoncanonicalFile(path string, content []byte) (bool, error) {
	if err := validateAtomicWriteDestination(path, atomicWriteCreateIfAbsent); err != nil {
		return false, err
	}
	existing, err := readVerifyTarget(path, content)
	if err == nil {
		if !bytes.Equal(existing, content) {
			return false, newAtomicWriteError(atomicWriteBeforeNamespaceCommit, path, atomicWriteCreateIfAbsent, errExistingContentDiffers(path))
		}
		if err := syncMatchingExistingFile(path); err != nil {
			return false, err
		}
		return true, nil
	}
	if errors.Is(err, errStoreFileTooLarge) {
		return false, newAtomicWriteError(atomicWriteBeforeNamespaceCommit, path, atomicWriteCreateIfAbsent, errExistingContentDiffers(path))
	}
	if !errors.Is(err, os.ErrNotExist) {
		return false, newAtomicWriteError(atomicWriteBeforeNamespaceCommit, path, atomicWriteCreateIfAbsent, err)
	}
	return false, nil
}

type noncanonicalReservationLeaf struct {
	kind   noncanonicalArtifactKind
	bytes  uint64
	state  BlockArtifactState
	prev   [32]byte
	height uint64
}
type noncanonicalReservation struct {
	store   *BlockStore
	hash    [32]byte
	done    chan struct{}
	tracked bool
}

// reserveNoncanonicalArtifactWrite is the sole create-path reservation entry.
func (bs *BlockStore) reserveNoncanonicalArtifactWrite(hash [32]byte, leaves []noncanonicalReservationLeaf, create func(*noncanonicalReservation) error) error {
	if bs.noncanonical.Load() == nil {
		return create(&noncanonicalReservation{store: bs})
	}
	reservation, err := bs.beginNoncanonicalReservation(hash, leaves)
	if err != nil {
		return err
	}
	if !reservation.tracked {
		return create(reservation)
	}
	defer reservation.finish()
	err = create(reservation)
	reservation.releaseUncreated()
	return err
}

func (bs *BlockStore) beginNoncanonicalReservation(hash [32]byte, leaves []noncanonicalReservationLeaf) (*noncanonicalReservation, error) {
	for {
		bs.stateMu.Lock()
		reservation, wait, err := bs.lockedNoncanonicalReservation(hash, leaves)
		bs.stateMu.Unlock()
		if wait == nil {
			return reservation, err
		}
		<-wait
	}
}

func (bs *BlockStore) lockedNoncanonicalReservation(hash [32]byte, leaves []noncanonicalReservationLeaf) (*noncanonicalReservation, chan struct{}, error) {
	accounting := bs.noncanonical.Load()
	if accounting == nil {
		return &noncanonicalReservation{store: bs}, nil, nil
	}
	if _, canonical := bs.canonicalHeightByHash[hash]; canonical {
		return &noncanonicalReservation{store: bs}, nil, nil
	}
	if wait := bs.noncanonicalPending[hash]; wait != nil {
		return nil, wait, nil
	}
	reservation, err := bs.reserveLockedNoncanonicalLeaves(accounting, hash, leaves)
	return reservation, nil, err
}

func (bs *BlockStore) reserveLockedNoncanonicalLeaves(accounting *noncanonicalAccounting, hash [32]byte, leaves []noncanonicalReservationLeaf) (*noncanonicalReservation, error) {
	at, row, adding, err := accounting.reservationRow(hash, len(leaves) != 0)
	if err != nil {
		return nil, err
	}
	bytesToReserve, missing, err := noncanonicalReservationBytes(row, leaves)
	if err != nil {
		return nil, err
	}
	if !missing {
		return &noncanonicalReservation{store: bs}, nil
	}
	if err := accounting.canReserve(bytesToReserve, adding); err != nil {
		return nil, err
	}
	return bs.commitLockedNoncanonicalReservation(accounting, hash, leaves, at, row, adding, bytesToReserve)
}

func (a *noncanonicalAccounting) reservationRow(hash [32]byte, needsRow bool) (int, *noncanonicalRow, bool, error) {
	at, found := a.find(hash)
	if found {
		return at, &a.rows[at], false, nil
	}
	if needsRow && a.count >= noncanonicalHashCap {
		return at, nil, true, errNoncanonicalCount
	}
	return at, nil, true, nil
}

func noncanonicalReservationBytes(row *noncanonicalRow, leaves []noncanonicalReservationLeaf) (uint64, bool, error) {
	var bytesToReserve uint64
	missing := false
	for _, leaf := range leaves {
		if row != nil && row.state(leaf.kind) != BlockArtifactAbsent {
			continue
		}
		next, ok := checkedNoncanonicalAdd(bytesToReserve, leaf.bytes)
		if !ok {
			return 0, false, errNoncanonicalBytes
		}
		bytesToReserve, missing = next, true
	}
	return bytesToReserve, missing, nil
}

func (bs *BlockStore) commitLockedNoncanonicalReservation(accounting *noncanonicalAccounting, hash [32]byte, leaves []noncanonicalReservationLeaf, at int, row *noncanonicalRow, adding bool, bytesToReserve uint64) (*noncanonicalReservation, error) {
	if adding {
		var err error
		row, err = accounting.insertRow(hash, at)
		if err != nil {
			return nil, err
		}
	}
	for _, leaf := range leaves {
		if row.state(leaf.kind) == BlockArtifactAbsent {
			row.setReservation(leaf.kind, leaf.bytes)
		}
	}
	accounting.reservedBytes += bytesToReserve
	done := make(chan struct{})
	if bs.noncanonicalPending == nil {
		bs.noncanonicalPending = make(map[[32]byte]chan struct{})
	}
	bs.noncanonicalPending[hash] = done
	return &noncanonicalReservation{store: bs, hash: hash, done: done, tracked: true}, nil
}

func (r *noncanonicalReservation) created(leaf noncanonicalReservationLeaf) {
	if r == nil || !r.tracked {
		return
	}
	r.store.stateMu.Lock()
	defer r.store.stateMu.Unlock()
	r.createdLocked(leaf)
}

func (r *noncanonicalReservation) createdLocked(leaf noncanonicalReservationLeaf) {
	accounting := r.store.noncanonical.Load()
	if accounting == nil {
		return
	}
	at, found := accounting.find(r.hash)
	if !found {
		return
	}
	row := &accounting.rows[at]
	if !row.hasReservation(leaf.kind) {
		return
	}
	r.commitCreated(accounting, row, leaf)
}

func (r *noncanonicalReservation) commitCreated(accounting *noncanonicalAccounting, row *noncanonicalRow, leaf noncanonicalReservationLeaf) {
	reserved := row.clearReservation(leaf.kind)
	accounting.reservedBytes -= reserved
	accounting.usedBytes += reserved
	*row.bytes(leaf.kind) = reserved
	row.setState(leaf.kind, leaf.state)
	row.setValidMetadata(leaf.kind, leaf.state, leaf.prev, leaf.height)
}

func (r *noncanonicalReservation) releaseUncreated() {
	if r == nil || !r.tracked {
		return
	}
	r.store.stateMu.Lock()
	defer r.store.stateMu.Unlock()
	accounting := r.store.noncanonical.Load()
	if accounting == nil {
		return
	}
	at, found := accounting.find(r.hash)
	if !found {
		return
	}
	row := &accounting.rows[at]
	for _, kind := range []noncanonicalArtifactKind{noncanonicalBlockArtifact, noncanonicalHeaderArtifact, noncanonicalUndoArtifact} {
		if row.hasReservation(kind) {
			accounting.reservedBytes -= row.clearReservation(kind)
		}
	}
	if row.empty() {
		accounting.remove(at)
	}
}

func (r *noncanonicalReservation) finish() {
	if r == nil || !r.tracked {
		return
	}
	r.store.stateMu.Lock()
	defer r.store.stateMu.Unlock()
	delete(r.store.noncanonicalPending, r.hash)
	close(r.done)
}
