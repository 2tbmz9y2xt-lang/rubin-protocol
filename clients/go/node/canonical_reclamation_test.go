package node

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

func noncanonicalTestFile(store *BlockStore, kind noncanonicalArtifactKind, hash [32]byte) string {
	dir, suffix, _ := store.noncanonicalArtifactPath(kind)
	return filepath.Join(dir, hex.EncodeToString(hash[:])+suffix)
}
func mustNoncanonical(t *testing.T, errs ...error) {
	t.Helper()
	if err := errors.Join(errs...); err != nil {
		t.Fatal(err)
	}
}
func mustNoncanonicalAtomic(t *testing.T, err error, path string) {
	var got *atomicWriteError
	if err == nil || errors.Is(err, errNoncanonicalCount) || errors.Is(err, errNoncanonicalBytes) || !errors.As(err, &got) || got.destination != path || got.stage != atomicWriteBeforeNamespaceCommit || got.operation != atomicWriteCreateIfAbsent || got.primary == nil || got.primary.Error() != errExistingContentDiffers(path).Error() || len(got.secondary) != 0 {
		t.Fatalf("atomic error=%#v", got)
	}
}
func countNoncanonicalClose(t *testing.T, target string, fault error) *int {
	t.Helper()
	closeFile, calls := closeNoncanonicalFile, 0
	closeNoncanonicalFile = func(file *os.File) error {
		if file.Name() == target {
			calls++
		}
		if err := closeFile(file); err != nil || file.Name() != target {
			return err
		}
		return fault
	}
	t.Cleanup(func() { closeNoncanonicalFile = closeFile })
	return &calls
}
func receiveNoncanonical[T any](t *testing.T, c <-chan T, message string) (value T) {
	t.Helper()
	select {
	case value = <-c:
	case <-time.After(time.Second):
		t.Fatal(message)
	}
	return
}
func installNoncanonicalAccounting(t *testing.T, store *BlockStore, limit uint64) *noncanonicalAccounting {
	t.Helper()
	accounting, err := store.rebuildNoncanonicalAccounting(limit)
	mustNoncanonical(t, err)
	store.stateMu.Lock()
	store.noncanonical.Store(accounting)
	store.noncanonicalPending = nil
	store.stateMu.Unlock()
	return accounting
}
func mustNoncanonicalRestartDigest(t *testing.T, store *BlockStore, want [32]byte) {
	t.Helper()
	reopened := mustOpenBlockStore(t, store.rootPath)
	installNoncanonicalAccounting(t, reopened, noncanonicalDefaultByteLimit)
	if got := reopened.noncanonicalAccountingDigest(); got != want {
		t.Fatalf("restart digest=%x want=%x", got, want)
	}
}

// noncanonicalTestDigest deliberately does not call production encoding.
func noncanonicalTestDigest(snapshot noncanonicalAccountingSnapshot) [32]byte {
	h := sha256.New()
	var header [20]byte
	binary.LittleEndian.PutUint64(header[:8], snapshot.usedBytes)
	binary.LittleEndian.PutUint64(header[8:16], snapshot.reservedBytes)
	binary.LittleEndian.PutUint32(header[16:20], snapshot.uniqueCount)
	_, _ = h.Write(header[:])
	for _, row := range snapshot.rows {
		var raw [98]byte
		copy(raw[:32], row.hash[:])
		copy(raw[32:64], row.prev[:])
		binary.LittleEndian.PutUint64(raw[64:72], row.blockBytes)
		binary.LittleEndian.PutUint64(raw[72:80], row.headerBytes)
		binary.LittleEndian.PutUint64(raw[80:88], row.undoBytes)
		binary.LittleEndian.PutUint64(raw[88:96], row.height)
		binary.LittleEndian.PutUint16(raw[96:98], row.flags)
		_, _ = h.Write(raw[:])
	}
	var got [32]byte
	copy(got[:], h.Sum(nil))
	return got
}
func TestNoncanonicalLimitsAndProductionDormancy(t *testing.T) {
	for _, limit := range []uint64{0, uint64(8) << 30, (uint64(8) << 30) + 1, uint64(32) << 30, (uint64(8) << 30) - 1, (uint64(32) << 30) + 1} {
		_, err := normalizeNoncanonicalLimit(limit)
		if (err == nil) != (limit == 0 || limit >= uint64(8)<<30 && limit <= uint64(32)<<30) {
			t.Fatalf("normalizeNoncanonicalLimit(%d)=%v", limit, err)
		}
	}
	if noncanonicalDefaultByteLimit != uint64(8)<<30 || noncanonicalMaximumByteLimit != uint64(32)<<30 || noncanonicalHashCap != 524288 || unsafe.Sizeof(noncanonicalRow{}) > 128 || noncanonicalBackingBytes > 64<<20 {
		t.Fatal("fixed accounting bounds drifted")
	}
	store := mustCreateBlockStore(t, filepath.Join(t.TempDir(), "store"))
	if store.noncanonical.Load() != nil {
		t.Fatal("CreateBlockStore activated accounting")
	}
	calls, wantErr := 0, errors.New("nil reservation")
	if err := store.reserveNoncanonicalArtifactWrite([32]byte{}, nil, func(*noncanonicalReservation) error { calls++; return wantErr }); !errors.Is(err, wantErr) || calls != 1 {
		t.Fatalf("nil reservation err=%v calls=%d", err, calls)
	}
	header, block := testHeaderBytes(1, 2), []byte("production write")
	hash := mustHeaderHash(t, header)
	mustNoncanonical(t, store.StoreBlock(hash, header, block))
	mustNoncanonical(t, store.PutUndo(hash, &BlockUndo{BlockHeight: 1}))
	reopened := mustOpenBlockStore(t, store.rootPath)
	if store.noncanonical.Load() != nil || reopened.noncanonical.Load() != nil {
		t.Fatal("public write or OpenBlockStore activated accounting")
	}
	mustNoncanonical(t, reopened.reloadFromDisk())
	if reopened.noncanonical.Load() != nil {
		t.Fatal("reload activated accounting")
	}
}
func TestNoncanonicalRebuildMergesArtifactPasses(t *testing.T) {
	genesis, err := consensus.ParseBlockBytes(devnetGenesisBlockBytes)
	mustNoncanonical(t, err)
	for _, kind := range []noncanonicalArtifactKind{noncanonicalBlockArtifact, noncanonicalHeaderArtifact} {
		raw := genesis.HeaderBytes
		if kind == noncanonicalBlockArtifact {
			raw = devnetGenesisBlockBytes
		}
		literal := mustCreateBlockStore(t, filepath.Join(t.TempDir(), "literal"))
		mustNoncanonical(t, os.WriteFile(noncanonicalTestFile(literal, kind, devnetGenesisBlockHash), raw, 0o600))
		installNoncanonicalAccounting(t, literal, noncanonicalDefaultByteLimit)
		mustNoncanonical(t, literal.StoreBlock(devnetGenesisBlockHash, genesis.HeaderBytes, devnetGenesisBlockBytes))
		want := noncanonicalAccountingSnapshot{usedBytes: uint64(len(devnetGenesisBlockBytes) + len(genesis.HeaderBytes)), uniqueCount: 1, rows: []noncanonicalRow{{hash: devnetGenesisBlockHash, prev: genesis.Header.PrevBlockHash, blockBytes: uint64(len(devnetGenesisBlockBytes)), headerBytes: uint64(len(genesis.HeaderBytes)), height: noncanonicalUnknownHeight, flags: 1 | 1<<2}}}
		got := literal.noncanonicalAccountingSnapshot()
		if len(got.rows) != 1 || got.usedBytes != want.usedBytes || got.reservedBytes != 0 || got.rows[0] != want.rows[0] || literal.noncanonicalAccountingDigest() != noncanonicalTestDigest(want) {
			t.Fatalf("tracked %v=%+v", kind, got)
		}
		mustNoncanonicalRestartDigest(t, literal, literal.noncanonicalAccountingDigest())
	}
	store := mustCreateBlockStore(t, filepath.Join(t.TempDir(), "store"))
	mustNoncanonical(t, store.CommitCanonicalBlock(0, devnetGenesisBlockHash, genesis.HeaderBytes, devnetGenesisBlockBytes, &BlockUndo{}))
	header, headerOnly := testHeaderBytes(9, 91), testHeaderBytes(10, 92)
	hash, headerOnlyHash, undoOnlyHash, badHeaderHash, badUndoHash := mustHeaderHash(t, header), mustHeaderHash(t, headerOnly), [32]byte{11}, [32]byte{12}, [32]byte{13}
	undo, err := marshalUndoEnvelope(hash, &BlockUndo{BlockHeight: 7})
	mustNoncanonical(t, err)
	undoOnly, err := marshalUndoEnvelope(undoOnlyHash, &BlockUndo{BlockHeight: 8})
	mustNoncanonical(t, err)
	for _, leaf := range []struct {
		kind noncanonicalArtifactKind
		hash [32]byte
		data []byte
	}{
		{noncanonicalBlockArtifact, hash, devnetGenesisBlockBytes}, {noncanonicalHeaderArtifact, hash, header}, {noncanonicalUndoArtifact, hash, undo}, {noncanonicalHeaderArtifact, headerOnlyHash, headerOnly}, {noncanonicalUndoArtifact, undoOnlyHash, undoOnly}, {noncanonicalHeaderArtifact, badHeaderHash, header}, {noncanonicalUndoArtifact, badUndoHash, []byte("corrupt undo")},
	} {
		mustNoncanonical(t, os.WriteFile(noncanonicalTestFile(store, leaf.kind, leaf.hash), leaf.data, 0o600))
	}
	for _, dir := range []string{store.blocksDir, store.headersDir, store.undoDir} {
		mustNoncanonical(t, os.WriteFile(filepath.Join(dir, atomicWriteLockLeaf), []byte("residue"), 0o600), os.WriteFile(filepath.Join(dir, atomicWriteScratchLeaf), []byte("residue"), 0o600))
	}
	parsed, _ := consensus.ParseBlockHeaderBytes(header)
	parsedOnly, _ := consensus.ParseBlockHeaderBytes(headerOnly)
	wantRows := []noncanonicalRow{
		{hash: hash, prev: parsed.PrevBlockHash, blockBytes: uint64(len(devnetGenesisBlockBytes)), headerBytes: uint64(len(header)), undoBytes: uint64(len(undo)), height: 7, flags: 2 | 1<<2 | 1<<4},
		{hash: headerOnlyHash, prev: parsedOnly.PrevBlockHash, headerBytes: uint64(len(headerOnly)), height: noncanonicalUnknownHeight, flags: 1 << 2},
		{hash: undoOnlyHash, undoBytes: uint64(len(undoOnly)), height: 8, flags: 1 << 4},
		{hash: badHeaderHash, headerBytes: uint64(len(header)), height: noncanonicalUnknownHeight, flags: 2 << 2},
		{hash: badUndoHash, undoBytes: uint64(len("corrupt undo")), height: noncanonicalUnknownHeight, flags: 2 << 4},
	}
	sort.Slice(wantRows, func(i, j int) bool { return string(wantRows[i].hash[:]) < string(wantRows[j].hash[:]) })
	want := noncanonicalAccountingSnapshot{usedBytes: uint64(len(devnetGenesisBlockBytes) + len(header)*2 + len(undo) + len(headerOnly) + len(undoOnly) + len("corrupt undo")), uniqueCount: 5, rows: wantRows}
	installNoncanonicalAccounting(t, store, noncanonicalDefaultByteLimit)
	if got := store.noncanonicalAccountingDigest(); got != noncanonicalTestDigest(want) {
		t.Fatalf("digest=%x want=%x", got, noncanonicalTestDigest(want))
	}
	mustNoncanonicalRestartDigest(t, store, store.noncanonicalAccountingDigest())
}
func TestNoncanonicalStrictRebuildRejectsLeavesAndDrift(t *testing.T) {
	for _, kind := range []string{"malformed", "suffix", "uppercase", "directory", "fifo", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			store := mustCreateBlockStore(t, filepath.Join(t.TempDir(), "store"))
			var err error
			switch kind {
			case "malformed":
				err = os.WriteFile(filepath.Join(store.blocksDir, "bad.bin"), []byte("x"), 0o600)
			case "suffix":
				err = os.WriteFile(filepath.Join(store.headersDir, hex.EncodeToString(make([]byte, 32))+".dat"), []byte("x"), 0o600)
			case "uppercase":
				err = os.WriteFile(filepath.Join(store.headersDir, strings.Repeat("A", 64)+".bin"), []byte("x"), 0o600)
			case "directory":
				err = os.Mkdir(noncanonicalTestFile(store, noncanonicalBlockArtifact, [32]byte{1}), 0o700)
			case "fifo":
				err = syscall.Mkfifo(noncanonicalTestFile(store, noncanonicalBlockArtifact, [32]byte{2}), 0o600)
			case "symlink":
				target := filepath.Join(t.TempDir(), "target")
				mustNoncanonical(t, os.WriteFile(target, []byte("x"), 0o600))
				err = os.Symlink(target, noncanonicalTestFile(store, noncanonicalBlockArtifact, [32]byte{3}))
			}
			mustNoncanonical(t, err)
			if _, err := store.rebuildNoncanonicalAccounting(noncanonicalDefaultByteLimit); err == nil {
				t.Fatal("strict rebuild accepted leaf")
			}
		})
	}
	replaceLeaf := func(store *BlockStore, path string, header []byte) {
		mustNoncanonical(t, os.Rename(path, path+".old"), os.WriteFile(path, header, 0o600), os.Remove(path+".old"), os.Chtimes(store.headersDir, time.Unix(1_000_000_000, 0), time.Unix(1_000_000_000, 0)))
	}
	for _, tc := range []struct {
		name, want string
		phase      int
		mutate     func(*BlockStore, string, []byte)
	}{
		{"empty EOF", "", 1, func(store *BlockStore, _ string, _ []byte) {
			mustNoncanonical(t, os.WriteFile(noncanonicalTestFile(store, noncanonicalBlockArtifact, [32]byte{1}), []byte("x"), 0o600))
			mustNoncanonical(t, os.Chtimes(store.blocksDir, time.Unix(1_000_000_001, 0), time.Unix(1_000_000_001, 0)))
		}}, {"enumerated inode", "", 2, replaceLeaf}, {"opened inode", "noncanonical artifact is not the opened regular leaf", 3, replaceLeaf}, {"same inode rewrite", "", 4, func(_ *BlockStore, path string, header []byte) {
			before, err := os.Lstat(path)
			mustNoncanonical(t, err)
			header = append([]byte(nil), header...)
			header[0] ^= 1
			mustNoncanonical(t, os.WriteFile(path, header, 0o600))
			mustNoncanonical(t, os.Chtimes(path, time.Unix(1_000_000_001, 0), time.Unix(1_000_000_001, 0)))
			after, err := os.Lstat(path)
			mustNoncanonical(t, err)
			if !os.SameFile(before, after) || before.Size() != after.Size() {
				t.Fatal("rewrite changed leaf identity or size")
			}
		}}, {"post-close leaf", "", 5, replaceLeaf}, {"post-close directory", "", 5, func(store *BlockStore, path string, _ []byte) {
			old := store.headersDir + ".old"
			mustNoncanonical(t, os.Rename(store.headersDir, old), os.Mkdir(store.headersDir, 0o700), os.Link(filepath.Join(old, filepath.Base(path)), path))
			store.leafProbe = func() {
				store.leafProbe = nil
				mustNoncanonical(t, os.Remove(path), os.Remove(store.headersDir), os.Rename(old, store.headersDir))
			}
		}}, {"short read", "noncanonical artifact changed while reading", 4, func(_ *BlockStore, path string, header []byte) {
			mustNoncanonical(t, os.Truncate(path, int64(len(header)-1)))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) { rejectNoncanonicalRebuildDrift(t, tc.phase, tc.mutate, tc.want) })
	}
	header := testHeaderBytes(12, 120)
	hash := mustHeaderHash(t, header)
	store := mustCreateBlockStore(t, filepath.Join(t.TempDir(), "canonical-first"))
	mustNoncanonical(t, store.SetCanonicalTip(0, hash))
	mustNoncanonical(t, os.WriteFile(filepath.Join(store.blocksDir, "bad.bin"), []byte("x"), 0o600))
	if _, err := store.rebuildNoncanonicalAccounting(noncanonicalDefaultByteLimit); !errors.Is(err, errCanonicalIndexZeroCompletePrefix) {
		t.Fatalf("canonical-first err=%v", err)
	}
}
func rejectNoncanonicalRebuildDrift(t *testing.T, phase int, mutate func(*BlockStore, string, []byte), want string) {
	t.Helper()
	store := mustCreateBlockStore(t, filepath.Join(t.TempDir(), "drift"))
	header := testHeaderBytes(12, 120)
	path := noncanonicalTestFile(store, noncanonicalHeaderArtifact, mustHeaderHash(t, header))
	mustNoncanonical(t, os.WriteFile(path, header, 0o600))
	stamp := time.Unix(1_000_000_000, 0)
	mustNoncanonical(t, os.Chtimes(path, stamp, stamp), os.Chtimes(store.blocksDir, stamp, stamp), os.Chtimes(store.headersDir, stamp, stamp))
	calls := 0
	store.leafProbe = func() {
		calls++
		if calls == phase {
			store.leafProbe = nil
			mutate(store, path, header)
		}
	}
	var closeCalls *int
	if want != "" {
		closeCalls = countNoncanonicalClose(t, path, nil)
	}
	if _, err := store.rebuildNoncanonicalAccounting(noncanonicalDefaultByteLimit); err == nil || want != "" && !strings.Contains(err.Error(), want) || closeCalls != nil && *closeCalls != 1 {
		t.Fatalf("rebuild err=%v want=%q", err, want)
	}
}
func TestNoncanonicalCloseErrors(t *testing.T) {
	for _, tc := range []struct {
		name      string
		directory bool
	}{{"leaf", false}, {"directory", true}} {
		t.Run(tc.name, func(t *testing.T) {
			store := mustCreateBlockStore(t, filepath.Join(t.TempDir(), "store"))
			header := testHeaderBytes(13, 130)
			path := noncanonicalTestFile(store, noncanonicalHeaderArtifact, mustHeaderHash(t, header))
			mustNoncanonical(t, os.WriteFile(path, header, 0o600))
			target := path
			if tc.directory {
				target = store.headersDir
			}
			fault := errors.New(tc.name)
			calls := countNoncanonicalClose(t, target, fault)
			image, err := store.rebuildNoncanonicalAccounting(noncanonicalDefaultByteLimit)
			if !errors.Is(err, fault) || image != nil || *calls != 1 {
				t.Fatalf("image=%t err=%v calls=%d", image != nil, err, *calls)
			}
		})
	}
}
func TestNoncanonicalOpenErrorCloses(t *testing.T) {
	store := mustCreateBlockStore(t, filepath.Join(t.TempDir(), "oversize"))
	path := noncanonicalTestFile(store, noncanonicalHeaderArtifact, [32]byte{1})
	mustNoncanonical(t, os.WriteFile(path, make([]byte, headerFileMaxBytes+1), 0o600))
	probes := 0
	store.leafProbe = func() { probes++ }
	calls := countNoncanonicalClose(t, path, nil)
	image, err := store.rebuildNoncanonicalAccounting(noncanonicalDefaultByteLimit)
	if !errors.Is(err, errStoreFileTooLarge) || image != nil || *calls != 1 || probes != 3 {
		t.Fatalf("image=%t err=%v calls=%d probes=%d", image != nil, err, *calls, probes)
	}
}
func withNoncanonicalFault(t *testing.T, dir string, post bool, fault error) {
	t.Helper()
	withAtomicWriteOps(t, func(ops *atomicWriteOps) {
		if post {
			sync := ops.syncParent
			ops.syncParent = func(path string) error {
				if path == dir {
					return fault
				}
				return sync(path)
			}
			return
		}
		open := ops.openScratch
		ops.openScratch = func(path string, flags int, mode os.FileMode) (atomicWriteScratchFile, error) {
			if filepath.Dir(path) == dir {
				return nil, fault
			}
			return open(path, flags, mode)
		}
	})
}
func TestNoncanonicalPartialCreateRestartsAccounting(t *testing.T) {
	fault := errors.New("injected create fault")
	for _, tc := range []struct {
		name    string
		kind    noncanonicalArtifactKind
		post    bool
		created int
		sibling bool
	}{
		{"before_block", noncanonicalBlockArtifact, false, 0, true}, {"after_block", noncanonicalBlockArtifact, true, 1, false}, {"before_header", noncanonicalHeaderArtifact, false, 1, false}, {"after_header", noncanonicalHeaderArtifact, true, 2, false}, {"before_undo", noncanonicalUndoArtifact, false, 2, false}, {"after_undo", noncanonicalUndoArtifact, true, 3, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := mustCreateBlockStore(t, filepath.Join(t.TempDir(), "store"))
			installNoncanonicalAccounting(t, store, noncanonicalDefaultByteLimit)
			header, block, undo := testHeaderBytes(15, 151), []byte("partial block"), &BlockUndo{BlockHeight: 9}
			hash := mustHeaderHash(t, header)
			rawUndo, err := marshalUndoEnvelope(hash, undo)
			mustNoncanonical(t, err)
			var before noncanonicalAccountingSnapshot
			var beforeDigest [32]byte
			if tc.sibling {
				high := [32]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
				mustNoncanonical(t, store.PutUndo(high, &BlockUndo{BlockHeight: 1}))
				before, beforeDigest = store.noncanonicalAccountingSnapshot(), store.noncanonicalAccountingDigest()
			}
			dir, _, _ := store.noncanonicalArtifactPath(tc.kind)
			withNoncanonicalFault(t, dir, tc.post, fault)
			if tc.kind == noncanonicalUndoArtifact {
				mustNoncanonical(t, store.StoreBlock(hash, header, block))
				err = store.PutUndo(hash, undo)
			} else {
				err = store.StoreBlock(hash, header, block)
			}
			if !errors.Is(err, fault) || errors.Is(err, errNoncanonicalCount) || errors.Is(err, errNoncanonicalBytes) {
				t.Fatalf("create err=%v", err)
			}
			if tc.sibling {
				got := store.noncanonicalAccountingSnapshot()
				if len(got.rows) != 1 || got.rows[0] != before.rows[0] || got.usedBytes != before.usedBytes || got.reservedBytes != 0 || got.uniqueCount != before.uniqueCount || store.noncanonicalAccountingDigest() != beforeDigest {
					t.Fatalf("rollback snapshot=%+v", got)
				}
				for _, kind := range []noncanonicalArtifactKind{noncanonicalBlockArtifact, noncanonicalHeaderArtifact} {
					if _, err := os.Lstat(noncanonicalTestFile(store, kind, hash)); !errors.Is(err, os.ErrNotExist) {
						t.Fatalf("failed %v leaf err=%v", kind, err)
					}
				}
				mustNoncanonicalRestartDigest(t, store, beforeDigest)
				return
			}
			want := []uint64{0, uint64(len(block)), uint64(len(block) + len(header)), uint64(len(block) + len(header) + len(rawUndo))}[tc.created]
			snapshot := store.noncanonicalAccountingSnapshot()
			if snapshot.usedBytes != want || snapshot.uniqueCount != uint32(min(tc.created, 1)) || store.noncanonicalAccountingDigest() != noncanonicalTestDigest(snapshot) {
				t.Fatalf("snapshot=%+v want used=%d count=%d", snapshot, want, min(tc.created, 1))
			}
			mustNoncanonicalRestartDigest(t, store, store.noncanonicalAccountingDigest())
		})
	}
}
func TestNoncanonicalQuotaAndErrorOrder(t *testing.T) {
	store := mustCreateBlockStore(t, filepath.Join(t.TempDir(), "store"))
	accounting := installNoncanonicalAccounting(t, store, noncanonicalDefaultByteLimit)
	header, block, undo := testHeaderBytes(20, 201), []byte("quota block"), &BlockUndo{BlockHeight: 10}
	hash := mustHeaderHash(t, header)
	rawUndo, err := marshalUndoEnvelope(hash, undo)
	mustNoncanonical(t, err)
	accounting.limit = uint64(len(block) + len(header) + len(rawUndo))
	mustNoncanonical(t, store.StoreBlock(hash, header, block))
	mustNoncanonical(t, store.PutUndo(hash, undo))
	if got := store.noncanonicalAccountingSnapshot(); got.usedBytes != accounting.limit || got.uniqueCount != 1 {
		t.Fatalf("exact fit=%+v", got)
	}
	nextHeader := testHeaderBytes(21, 202)
	nextHash := mustHeaderHash(t, nextHeader)
	if err := store.StoreBlock(nextHash, nextHeader, []byte("next")); !errors.Is(err, errNoncanonicalBytes) {
		t.Fatalf("byte exhaustion=%v", err)
	}
	blockPath, headerPath := noncanonicalTestFile(store, noncanonicalBlockArtifact, nextHash), noncanonicalTestFile(store, noncanonicalHeaderArtifact, nextHash)
	mustNoncanonical(t, os.WriteFile(blockPath, []byte("different"), 0o600), os.WriteFile(headerPath, []byte("also different"), 0o600))
	err = store.StoreBlock(nextHash, nextHeader, []byte("next"))
	mustNoncanonicalAtomic(t, err, blockPath)
	conflictHeader, conflictBlock := testHeaderBytes(22, 203), []byte("matching block")
	conflictHash := mustHeaderHash(t, conflictHeader)
	conflictBlockPath, conflictHeaderPath := noncanonicalTestFile(store, noncanonicalBlockArtifact, conflictHash), noncanonicalTestFile(store, noncanonicalHeaderArtifact, conflictHash)
	mustNoncanonical(t, os.WriteFile(conflictBlockPath, conflictBlock, 0o600), os.WriteFile(conflictHeaderPath, []byte("different"), 0o600))
	err = store.StoreBlock(conflictHash, conflictHeader, conflictBlock)
	mustNoncanonicalAtomic(t, err, conflictHeaderPath)
	existingUndo, err := marshalUndoEnvelope(nextHash, &BlockUndo{BlockHeight: 11})
	mustNoncanonical(t, err)
	undoPath := noncanonicalTestFile(store, noncanonicalUndoArtifact, nextHash)
	mustNoncanonical(t, os.WriteFile(undoPath, existingUndo, 0o600))
	err = store.PutUndo(nextHash, &BlockUndo{BlockHeight: 12})
	mustNoncanonicalAtomic(t, err, undoPath)
	full, err := newNoncanonicalAccounting(noncanonicalDefaultByteLimit)
	mustNoncanonical(t, err)
	full.count = 524287
	if _, err := full.appendRow([32]byte{1}); err != nil || full.count != 524288 {
		t.Fatalf("524288th row err=%v count=%d", err, full.count)
	}
	if _, err := full.appendRow([32]byte{2}); !errors.Is(err, errNoncanonicalCount) {
		t.Fatalf("524289th row err=%v", err)
	}
	if err := full.canReserve(^uint64(0), true); !errors.Is(err, errNoncanonicalCount) {
		t.Fatalf("count did not precede bytes: %v", err)
	}
	store.noncanonical.Store(full)
	fullRow, wrongHashErr := full.rows[noncanonicalHashCap-1], store.StoreBlock([32]byte{}, header, block)
	nilUndoErr := store.PutUndo([32]byte{}, nil)
	if wrongHashErr == nil || wrongHashErr.Error() != "header hash mismatch" || nilUndoErr == nil || nilUndoErr.Error() != "nil block undo" || errors.Is(wrongHashErr, errNoncanonicalCount) || errors.Is(wrongHashErr, errNoncanonicalBytes) || errors.Is(nilUndoErr, errNoncanonicalCount) || errors.Is(nilUndoErr, errNoncanonicalBytes) {
		t.Fatalf("input errs=%v,%v", wrongHashErr, nilUndoErr)
	}
	if full.count != noncanonicalHashCap || full.usedBytes != 0 || full.reservedBytes != 0 || full.rows[noncanonicalHashCap-1] != fullRow {
		t.Fatalf("input validation mutated full accounting")
	}
	for _, kind := range []noncanonicalArtifactKind{noncanonicalBlockArtifact, noncanonicalHeaderArtifact, noncanonicalUndoArtifact} {
		if _, err := os.Lstat(noncanonicalTestFile(store, kind, [32]byte{})); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("input created %v leaf err=%v", kind, err)
		}
	}
	called := false
	if err := store.reserveNoncanonicalArtifactWrite([32]byte{3}, []noncanonicalReservationLeaf{{kind: noncanonicalBlockArtifact, bytes: ^uint64(0)}, {kind: noncanonicalHeaderArtifact, bytes: 1}}, func(*noncanonicalReservation) error { called = true; return nil }); !errors.Is(err, errNoncanonicalCount) || called {
		t.Fatalf("reserve count precedence err=%v called=%t", err, called)
	}
	if err := full.addScanned([32]byte{3}, noncanonicalBlockArtifact, ^uint64(0), BlockArtifactInvalid, [32]byte{}, 0); !errors.Is(err, errNoncanonicalCount) || full.usedBytes != 0 {
		t.Fatalf("scan count precedence err=%v used=%d", err, full.usedBytes)
	}
	full.count, full.sortedCount, full.usedBytes, full.reservedBytes, full.limit = 0, 0, 0, 0, noncanonicalDefaultByteLimit
	row := full.rows[0]
	called = false
	if err := store.reserveNoncanonicalArtifactWrite([32]byte{4}, []noncanonicalReservationLeaf{{kind: noncanonicalBlockArtifact, bytes: ^uint64(0)}, {kind: noncanonicalHeaderArtifact, bytes: 1}}, func(*noncanonicalReservation) error { called = true; return nil }); !errors.Is(err, errNoncanonicalBytes) || errors.Is(err, errNoncanonicalCount) || called || full.count != 0 || full.sortedCount != 0 || full.usedBytes != 0 || full.reservedBytes != 0 || full.limit != noncanonicalDefaultByteLimit || full.rows[0] != row {
		t.Fatalf("reserve bytes err=%v used=%d reserved=%d count=%d row=%+v", err, full.usedBytes, full.reservedBytes, full.count, full.rows[0])
	}
	full.limit = 1
	mustNoncanonical(t, full.addScanned([32]byte{1}, noncanonicalBlockArtifact, 1, BlockArtifactInvalid, [32]byte{}, 0))
	row = full.rows[0]
	for _, used := range []uint64{1, ^uint64(0)} {
		full.usedBytes = used
		if err := full.addScanned([32]byte{2}, noncanonicalBlockArtifact, 1, BlockArtifactInvalid, [32]byte{}, 0); !errors.Is(err, errNoncanonicalBytes) || full.usedBytes != used || full.count != 1 || full.rows[0] != row {
			t.Fatalf("scan bytes precedence err=%v used=%d count=%d row=%+v", err, full.usedBytes, full.count, full.rows[0])
		}
	}
	if _, ok := checkedNoncanonicalAdd(^uint64(0), 1); ok {
		t.Fatal("checked add overflow accepted")
	}
}
func TestNoncanonicalReservationsCoordinateHashes(t *testing.T) {
	store := mustCreateBlockStore(t, filepath.Join(t.TempDir(), "store"))
	installNoncanonicalAccounting(t, store, noncanonicalDefaultByteLimit)
	leaf := noncanonicalReservationLeaf{kind: noncanonicalBlockArtifact, bytes: 1, state: BlockArtifactValid}
	sameLeaf := noncanonicalReservationLeaf{kind: noncanonicalHeaderArtifact, bytes: 1, state: BlockArtifactValid}
	started, release, firstDone := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	released := false
	t.Cleanup(func() {
		if !released {
			close(release)
		}
	})
	go func() {
		firstDone <- store.reserveNoncanonicalArtifactWrite([32]byte{1}, []noncanonicalReservationLeaf{leaf}, func(r *noncanonicalReservation) error { close(started); <-release; r.created(leaf); return nil })
	}()
	_ = receiveNoncanonical(t, started, "first reservation did not start")
	snapshot := store.noncanonicalAccountingSnapshot()
	if len(snapshot.rows) != 1 || snapshot.usedBytes != 0 || snapshot.reservedBytes != 1 || snapshot.uniqueCount != 1 || snapshot.rows[0].blockBytes != 1 || snapshot.rows[0].height != noncanonicalUnknownHeight || snapshot.rows[0].flags&(1<<6) == 0 {
		t.Fatalf("pending used=%d reserved=%d count=%d rows=%d", snapshot.usedBytes, snapshot.reservedBytes, snapshot.uniqueCount, len(snapshot.rows))
	}
	if got, want := store.noncanonicalAccountingDigest(), noncanonicalTestDigest(snapshot); got != want {
		t.Fatalf("pending digest=%x want=%x", got, want)
	}
	sameDone, otherDone := make(chan error, 1), make(chan error, 1)
	go func() {
		sameDone <- store.reserveNoncanonicalArtifactWrite([32]byte{1}, []noncanonicalReservationLeaf{sameLeaf}, func(r *noncanonicalReservation) error { r.created(sameLeaf); return nil })
	}()
	go func() {
		otherDone <- store.reserveNoncanonicalArtifactWrite([32]byte{}, []noncanonicalReservationLeaf{leaf}, func(r *noncanonicalReservation) error { r.created(leaf); return nil })
	}()
	mustNoncanonical(t, receiveNoncanonical(t, otherDone, "different hash serialized across I/O"))
	select {
	case err := <-sameDone:
		t.Fatalf("same hash bypassed reservation: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	released = true
	mustNoncanonical(t, receiveNoncanonical(t, firstDone, "first reservation did not finish"))
	mustNoncanonical(t, receiveNoncanonical(t, sameDone, "same hash did not resume"))
	snapshot = store.noncanonicalAccountingSnapshot()
	if len(snapshot.rows) != 2 || snapshot.usedBytes != 3 || snapshot.reservedBytes != 0 || snapshot.rows[0].hash != ([32]byte{}) || snapshot.rows[0].state(noncanonicalBlockArtifact) != BlockArtifactValid || snapshot.rows[1].hash != ([32]byte{1}) || snapshot.rows[1].state(noncanonicalBlockArtifact) != BlockArtifactValid || snapshot.rows[1].state(noncanonicalHeaderArtifact) != BlockArtifactValid {
		t.Fatalf("reservation convergence=%+v", snapshot)
	}
}
