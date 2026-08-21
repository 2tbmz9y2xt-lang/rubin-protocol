package node

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"sort"

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
func (bs *BlockStore) reserveNoncanonicalArtifactWrite(hash [32]byte, leaves []noncanonicalReservationLeaf, prepare func() ([]noncanonicalReservationLeaf, error), create func(*noncanonicalReservation) error) error {
	if handled, err := bs.reserveInactiveNoncanonicalArtifactWrite(prepare, create); handled {
		return err
	}
	reservation := bs.beginNoncanonicalReservation(hash)
	if reservation.tracked {
		defer reservation.finish()
	}
	if prepare != nil {
		var err error
		leaves, err = prepare()
		if err != nil {
			return err
		}
		if len(leaves) == 0 {
			return nil
		}
	}
	if !reservation.tracked {
		return create(reservation)
	}
	if err := reservation.reserve(leaves); err != nil {
		return err
	}
	err := create(reservation)
	reservation.releaseUncreated()
	return err
}

func (bs *BlockStore) reserveInactiveNoncanonicalArtifactWrite(prepare func() ([]noncanonicalReservationLeaf, error), create func(*noncanonicalReservation) error) (bool, error) {
	if bs.noncanonical.Load() != nil {
		return false, nil
	}
	if prepare != nil {
		var err error
		leaves, err := prepare()
		if err != nil || len(leaves) == 0 {
			return true, err
		}
	}
	return true, create(&noncanonicalReservation{store: bs})
}

func (bs *BlockStore) beginNoncanonicalReservation(hash [32]byte) *noncanonicalReservation {
	for {
		bs.stateMu.Lock()
		if bs.noncanonical.Load() == nil {
			bs.stateMu.Unlock()
			return &noncanonicalReservation{store: bs}
		}
		if _, canonical := bs.canonicalHeightByHash[hash]; canonical {
			bs.stateMu.Unlock()
			return &noncanonicalReservation{store: bs}
		}
		if wait := bs.noncanonicalPending[hash]; wait != nil {
			bs.stateMu.Unlock()
			<-wait
			continue
		}
		if bs.noncanonicalPending == nil {
			bs.noncanonicalPending = make(map[[32]byte]chan struct{})
		}
		done := make(chan struct{})
		bs.noncanonicalPending[hash] = done
		bs.stateMu.Unlock()
		return &noncanonicalReservation{store: bs, hash: hash, done: done, tracked: true}
	}
}

func (r *noncanonicalReservation) reserve(leaves []noncanonicalReservationLeaf) error {
	r.store.stateMu.Lock()
	defer r.store.stateMu.Unlock()
	accounting := r.store.noncanonical.Load()
	if accounting == nil {
		return nil
	}
	if _, canonical := r.store.canonicalHeightByHash[r.hash]; canonical {
		return nil
	}
	return r.store.reserveLockedNoncanonicalLeaves(accounting, r.hash, leaves)
}

func (bs *BlockStore) reserveLockedNoncanonicalLeaves(accounting *noncanonicalAccounting, hash [32]byte, leaves []noncanonicalReservationLeaf) error {
	at, row, adding, err := accounting.reservationRow(hash, len(leaves) != 0)
	if err != nil {
		return err
	}
	bytesToReserve, missing, err := noncanonicalReservationBytes(row, leaves)
	if err != nil {
		return err
	}
	if !missing {
		return nil
	}
	if err := accounting.canReserve(bytesToReserve, adding); err != nil {
		return err
	}
	if adding {
		row, err = accounting.insertRow(hash, at)
		if err != nil {
			return err
		}
	}
	bs.commitLockedNoncanonicalReservation(accounting, row, leaves, bytesToReserve)
	return nil
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

func (bs *BlockStore) commitLockedNoncanonicalReservation(accounting *noncanonicalAccounting, row *noncanonicalRow, leaves []noncanonicalReservationLeaf, bytesToReserve uint64) {
	for _, leaf := range leaves {
		if row.state(leaf.kind) == BlockArtifactAbsent {
			row.setReservation(leaf.kind, leaf.bytes)
		}
	}
	accounting.reservedBytes += bytesToReserve
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
