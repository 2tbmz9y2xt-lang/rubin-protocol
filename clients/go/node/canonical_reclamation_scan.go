package node

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

// rebuildNoncanonicalAccounting is test-only reachability: production never calls it.
func (bs *BlockStore) rebuildNoncanonicalAccounting(limit uint64) (*noncanonicalAccounting, error) {
	if bs == nil {
		return nil, errors.New("nil blockstore")
	}
	if err := requireCompleteCanonicalPrefix(bs); err != nil {
		return nil, err
	}
	directories, err := bs.snapshotNoncanonicalDirectories()
	if err != nil {
		return nil, err
	}
	accounting, err := newNoncanonicalAccounting(limit)
	if err != nil {
		return nil, err
	}
	for _, kind := range []noncanonicalArtifactKind{noncanonicalBlockArtifact, noncanonicalHeaderArtifact, noncanonicalUndoArtifact} {
		if err := bs.scanNoncanonicalDirectory(accounting, kind, directories[kind]); err != nil {
			return nil, err
		}
		accounting.sortRows()
	}
	return accounting, nil
}

func (bs *BlockStore) snapshotNoncanonicalDirectories() ([3]os.FileInfo, error) {
	var snapshots [3]os.FileInfo
	for _, kind := range []noncanonicalArtifactKind{noncanonicalBlockArtifact, noncanonicalHeaderArtifact, noncanonicalUndoArtifact} {
		dir, _, _ := bs.noncanonicalArtifactPath(kind)
		info, err := os.Stat(dir)
		if err != nil {
			return snapshots, err
		}
		if !info.IsDir() {
			return snapshots, fmt.Errorf("noncanonical artifact directory is not a directory: %s", dir)
		}
		snapshots[kind] = info
	}
	return snapshots, nil
}

func (bs *BlockStore) scanNoncanonicalDirectory(accounting *noncanonicalAccounting, kind noncanonicalArtifactKind, fixed os.FileInfo) (resultErr error) {
	dir, suffix, limit := bs.noncanonicalArtifactPath(kind)
	d, err := openNoncanonicalDirectory(dir)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := closeNoncanonicalFile(d); resultErr == nil && closeErr != nil {
			resultErr = closeErr
		}
	}()
	directory, err := verifiedNoncanonicalDirectory(d, fixed)
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

func verifiedNoncanonicalDirectory(file *os.File, fixed os.FileInfo) (os.FileInfo, error) {
	directory, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !sameNoncanonicalDirectorySnapshot(fixed, directory) {
		return nil, errors.New("noncanonical artifact directory identity drift")
	}
	return directory, nil
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
	bs.stateMu.RLock()
	defer bs.stateMu.RUnlock()
	if _, canonical := bs.canonicalHeightByHash[hash]; canonical {
		return nil
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

func openNoncanonicalFile(path string, flags int) (*os.File, error) {
	for {
		fd, err := syscall.Open(path, flags, 0)
		if errors.Is(err, syscall.EINTR) {
			continue
		}
		if err != nil {
			return nil, &os.PathError{Op: "open", Path: path, Err: err}
		}
		if fd < 0 {
			return nil, &os.PathError{Op: "open", Path: path, Err: syscall.EINVAL}
		}
		return os.NewFile(uintptr(fd), path), nil
	}
}

func openNoncanonicalArtifactFile(path string) (*os.File, error) {
	return openNoncanonicalFile(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK)
}

func openNoncanonicalDirectory(path string) (*os.File, error) {
	return openNoncanonicalFile(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NONBLOCK|syscall.O_DIRECTORY)
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
	current, err := os.Stat(dir)
	if err == nil && !sameNoncanonicalDirectorySnapshot(opened, current) {
		return errors.New("noncanonical artifact directory identity drift")
	}
	return err
}

func sameNoncanonicalDirectorySnapshot(before, after os.FileInfo) bool {
	return before.IsDir() && after.IsDir() && before.Size() == after.Size() && before.ModTime().Equal(after.ModTime()) && os.SameFile(before, after)
}

func sameNoncanonicalArtifactSnapshot(before, after os.FileInfo, size int64) bool {
	return before.Mode().IsRegular() && after.Mode().IsRegular() && before.Size() == size && after.Size() == size && before.ModTime().Equal(after.ModTime()) && os.SameFile(before, after)
}
