//go:build darwin || linux

package node

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"syscall"
	"testing"
	"testing/synctest"
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

func TestNoncanonicalLimitsAndProductionActivation(t *testing.T) {
	for _, limit := range []uint64{0, uint64(8) << 30, (uint64(8) << 30) + 1, uint64(32) << 30, (uint64(8) << 30) - 1, (uint64(32) << 30) + 1} {
		_, err := normalizeNoncanonicalLimit(limit)
		if (err == nil) != (limit == 0 || limit >= uint64(8)<<30 && limit <= uint64(32)<<30) {
			t.Fatalf("normalizeNoncanonicalLimit(%d)=%v", limit, err)
		}
	}
	if noncanonicalDefaultByteLimit != uint64(8)<<30 || noncanonicalMaximumByteLimit != uint64(32)<<30 || noncanonicalHashCap != 524288 || unsafe.Sizeof(noncanonicalRow{}) > 128 || noncanonicalBackingBytes > 64<<20 {
		t.Fatal("fixed accounting bounds drifted")
	}
	accounting, err := newNoncanonicalAccounting(noncanonicalDefaultByteLimit)
	mustNoncanonical(t, err)
	actualBytes := cap(accounting.rows) * int(unsafe.Sizeof(noncanonicalRow{}))
	if len(accounting.rows) != noncanonicalHashCap || cap(accounting.rows) != noncanonicalHashCap || actualBytes > 64<<20 {
		t.Fatalf("fixed allocation rows=%d cap=%d bytes=%d", len(accounting.rows), cap(accounting.rows), actualBytes)
	}
	refusedRoot := filepath.Join(t.TempDir(), "store")
	store, err := CreateBlockStoreWithNoncanonicalLimit(refusedRoot, (uint64(32)<<30)+1)
	if err == nil || store != nil {
		t.Fatal("out-of-range create limit published a store")
	}
	if _, err := os.Stat(refusedRoot); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("refused create left a root behind: %v", err)
	}
	explicit, err := CreateBlockStoreWithNoncanonicalLimit(filepath.Join(t.TempDir(), "explicit"), noncanonicalMaximumByteLimit)
	mustNoncanonical(t, err)
	if image := explicit.noncanonical.Load(); image == nil || image.limit != noncanonicalMaximumByteLimit || image.count != 0 || image.usedBytes != 0 || image.reservedBytes != 0 {
		t.Fatalf("explicit create image=%t", image != nil)
	}
	store = mustCreateBlockStore(t, filepath.Join(t.TempDir(), "store"))
	if installed := store.noncanonical.Load(); installed == nil || installed.count != 0 || installed.usedBytes != 0 || installed.reservedBytes != 0 || installed.limit != noncanonicalDefaultByteLimit {
		t.Fatalf("CreateBlockStore did not install an empty default image: %+v", installed)
	}
	header, block := testHeaderBytes(1, 2), []byte("production write")
	hash := mustHeaderHash(t, header)
	mustNoncanonical(t, store.StoreBlock(hash, header, block))
	mustNoncanonical(t, store.PutUndo(hash, &BlockUndo{BlockHeight: 1}))
	wantDigest := store.noncanonicalAccountingDigest()
	reopened := mustOpenBlockStore(t, store.rootPath)
	if reopened.noncanonical.Load() == nil || reopened.noncanonical.Load().limit != noncanonicalDefaultByteLimit {
		t.Fatal("OpenBlockStore did not install the default accounting image")
	}
	if got := reopened.noncanonicalAccountingDigest(); got != wantDigest {
		t.Fatalf("reconstructed open digest=%x want=%x", got, wantDigest)
	}
	mustNoncanonical(t, reopened.reloadFromDisk())
	if reloaded := reopened.noncanonicalAccountingDigest(); reloaded != wantDigest {
		t.Fatalf("reload digest=%x want=%x", reloaded, wantDigest)
	}
	for _, limit := range []uint64{0, uint64(8) << 30, uint64(32) << 30} {
		explicit, err := OpenBlockStoreWithNoncanonicalLimit(store.rootPath, limit)
		if err != nil {
			t.Fatalf("OpenBlockStoreWithNoncanonicalLimit(%d): %v", limit, err)
		}
		if explicit.noncanonical.Load() == nil {
			t.Fatalf("explicit open %d published no accounting image", limit)
		}
	}
	missing := filepath.Join(t.TempDir(), "missing")
	if _, err := OpenBlockStoreWithNoncanonicalLimit(missing, (uint64(8)<<30)-1); err == nil || !strings.Contains(err.Error(), "invalid noncanonical byte limit") {
		t.Fatalf("invalid open precedence=%v", err)
	}
	if _, err := os.Lstat(missing); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("invalid open changed filesystem: %v", err)
	}
	explicit32, err := OpenBlockStoreWithNoncanonicalLimit(store.rootPath, uint64(32)<<30)
	mustNoncanonical(t, err, explicit32.reloadFromDisk())
	if got := explicit32.noncanonical.Load().limit; got != uint64(32)<<30 {
		t.Fatalf("reload limit=%d want=%d", got, uint64(32)<<30)
	}
	invalidImage, invalidDigest, invalidRaw := explicit32.noncanonical.Load(), explicit32.noncanonicalAccountingDigest(), explicit32.visibleIndexBytes()
	invalidImage.limit = 1
	if err := explicit32.reloadFromDisk(); err == nil || !strings.Contains(err.Error(), "invalid noncanonical byte limit") || explicit32.noncanonical.Load() != invalidImage || explicit32.noncanonicalAccountingDigest() != invalidDigest || !bytes.Equal(explicit32.visibleIndexBytes(), invalidRaw) {
		t.Fatalf("invalid live limit reload=%v", err)
	}
	mustNoncanonical(t, store.SetCanonicalTip(0, hash), os.Remove(noncanonicalTestFile(store, noncanonicalBlockArtifact, hash)), os.Remove(noncanonicalTestFile(store, noncanonicalUndoArtifact, hash)))
	beforeImage, beforeDigest, beforeRaw := store.noncanonical.Load(), store.noncanonicalAccountingDigest(), store.visibleIndexBytes()
	beforeHeight, beforeMember := store.canonicalHeightByHash[hash]
	if err := store.reloadFromDisk(); !errors.Is(err, errCanonicalIndexZeroCompletePrefix) {
		t.Fatalf("incomplete canonical reload error=%v", err)
	}
	canonical, err := store.CanonicalIndexSnapshot()
	mustNoncanonical(t, err)
	afterHeight, afterMember := store.canonicalHeightByHash[hash]
	if len(canonical) != 1 || canonical[0] != hex.EncodeToString(hash[:]) || beforeMember != afterMember || beforeHeight != afterHeight || store.noncanonical.Load() != beforeImage || store.noncanonicalAccountingDigest() != beforeDigest || !bytes.Equal(store.visibleIndexBytes(), beforeRaw) {
		t.Fatal("failed reload changed canonical or accounting state")
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
	hash, headerOnlyHash, undoOnlyHash, badHeaderHash, badUndoHash, emptyHeaderHash := mustHeaderHash(t, header), mustHeaderHash(t, headerOnly), [32]byte{11}, [32]byte{12}, [32]byte{13}, [32]byte{14}
	undo, err := marshalUndoEnvelope(hash, &BlockUndo{BlockHeight: 7})
	mustNoncanonical(t, err)
	undoOnly, err := marshalUndoEnvelope(undoOnlyHash, &BlockUndo{BlockHeight: 8})
	mustNoncanonical(t, err)
	for _, leaf := range []struct {
		kind noncanonicalArtifactKind
		hash [32]byte
		data []byte
	}{
		{noncanonicalBlockArtifact, hash, devnetGenesisBlockBytes}, {noncanonicalHeaderArtifact, hash, header}, {noncanonicalUndoArtifact, hash, undo}, {noncanonicalHeaderArtifact, headerOnlyHash, headerOnly}, {noncanonicalUndoArtifact, undoOnlyHash, undoOnly}, {noncanonicalHeaderArtifact, badHeaderHash, header}, {noncanonicalUndoArtifact, badUndoHash, []byte("corrupt undo")}, {noncanonicalHeaderArtifact, emptyHeaderHash, nil},
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
		{hash: emptyHeaderHash, height: noncanonicalUnknownHeight, flags: 2 << 2},
	}
	sort.Slice(wantRows, func(i, j int) bool { return string(wantRows[i].hash[:]) < string(wantRows[j].hash[:]) })
	want := noncanonicalAccountingSnapshot{usedBytes: uint64(len(devnetGenesisBlockBytes) + len(header)*2 + len(undo) + len(headerOnly) + len(undoOnly) + len("corrupt undo")), uniqueCount: 6, rows: wantRows}
	installNoncanonicalAccounting(t, store, noncanonicalDefaultByteLimit)
	if got := store.noncanonicalAccountingDigest(); got != noncanonicalTestDigest(want) {
		t.Fatalf("digest=%x want=%x", got, noncanonicalTestDigest(want))
	}
	mustNoncanonicalRestartDigest(t, store, store.noncanonicalAccountingDigest())
}

func TestNoncanonicalRebuildSkipsHashCanonicalizedAfterRead(t *testing.T) {
	store := mustCreateBlockStore(t, filepath.Join(t.TempDir(), "store"))
	header := testHeaderBytes(10, 100)
	hash := mustHeaderHash(t, header)
	mustNoncanonical(t, os.WriteFile(noncanonicalTestFile(store, noncanonicalHeaderArtifact, hash), header, 0o600))
	probes := 0
	store.leafProbe = func() {
		probes++
		if probes == 5 {
			store.leafProbe = nil
			store.stateMu.Lock()
			store.canonicalHeightByHash[hash] = 0
			store.stateMu.Unlock()
		}
	}
	image, err := store.rebuildNoncanonicalAccounting(noncanonicalDefaultByteLimit)
	if err != nil || probes != 5 || image == nil {
		t.Fatalf("image=%t probes=%d err=%v", image != nil, probes, err)
	}
	if image.usedBytes != 0 || image.count != 0 {
		t.Fatalf("used=%d count=%d", image.usedBytes, image.count)
	}
}

func TestNoncanonicalRebuildsSymlinkDirectory(t *testing.T) {
	for _, tc := range []struct {
		name           string
		retarget, fifo bool
	}{{"stable", false, false}, {"retarget directory", true, false}, {"retarget fifo", true, true}} {
		t.Run(tc.name, func(t *testing.T) {
			store := mustCreateBlockStore(t, filepath.Join(t.TempDir(), "store"))
			target, replacement := store.headersDir+".target", store.headersDir+".replacement"
			mustNoncanonical(t, os.Rename(store.headersDir, target))
			if tc.fifo {
				mustNoncanonical(t, syscall.Mkfifo(replacement, 0o600))
			} else if tc.retarget {
				mustNoncanonical(t, os.Mkdir(replacement, 0o700))
			}
			mustNoncanonical(t, os.Symlink(target, store.headersDir))
			header := testHeaderBytes(11, 110)
			hash := mustHeaderHash(t, header)
			mustNoncanonical(t, os.WriteFile(noncanonicalTestFile(store, noncanonicalHeaderArtifact, hash), header, 0o600))
			if !tc.retarget {
				reopened := mustOpenBlockStore(t, store.rootPath)
				snapshot := reopened.noncanonicalAccountingSnapshot()
				if len(snapshot.rows) != 1 || snapshot.rows[0].hash != hash || snapshot.rows[0].state(noncanonicalHeaderArtifact) != BlockArtifactValid {
					t.Fatalf("symlink directory snapshot=%+v", snapshot)
				}
				mustNoncanonicalRestartDigest(t, reopened, reopened.noncanonicalAccountingDigest())
				return
			}
			store.leafProbe = func() {
				store.leafProbe = nil
				mustNoncanonical(t, os.Remove(store.headersDir), os.Symlink(replacement, store.headersDir))
			}
			done := make(chan error, 1)
			go func() { _, err := store.rebuildNoncanonicalAccounting(noncanonicalDefaultByteLimit); done <- err }()
			if err := receiveNoncanonical(t, done, "retargeted directory rebuild did not return"); err == nil || tc.fifo && !errors.Is(err, syscall.ENOTDIR) {
				t.Fatalf("retargeted directory err=%v", err)
			}
		})
	}
}

func TestNoncanonicalStrictRebuildRejectsLeavesAndDrift(t *testing.T) {
	for _, tc := range []struct{ name, want string }{
		{"malformed", "unexpected noncanonical artifact name"},
		{"suffix", "unexpected noncanonical artifact name"},
		{"uppercase", "unexpected noncanonical artifact name"},
		{"directory", "noncanonical artifact enumeration drift"},
		{"fifo", "noncanonical artifact enumeration drift"},
		{"symlink", "read noncanonical artifact"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := mustCreateBlockStore(t, filepath.Join(t.TempDir(), "store"))
			var err error
			switch tc.name {
			case "malformed":
				err = os.WriteFile(filepath.Join(store.blocksDir, "bad.bin"), []byte("x"), 0o600)
			case "suffix":
				err = os.WriteFile(filepath.Join(store.headersDir, hex.EncodeToString(make([]byte, 32))+".bin.extra"), []byte("x"), 0o600)
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
			_, err = OpenBlockStore(store.rootPath)
			if err == nil || !strings.Contains(err.Error(), tc.want) || errors.Is(err, errNoncanonicalCount) || errors.Is(err, errNoncanonicalBytes) {
				t.Fatalf("public Open strict leaf err=%v want=%q", err, tc.want)
			}
		})
	}
	t.Run("open_skips_declared_canonical_artifact", func(t *testing.T) {
		store := mustCreateBlockStore(t, filepath.Join(t.TempDir(), "canonical-open"))
		header := testHeaderBytes(0x1f, 31)
		hash := mustHeaderHash(t, header)
		mustNoncanonical(t, store.SetCanonicalTip(0, hash), os.Mkdir(noncanonicalTestFile(store, noncanonicalBlockArtifact, hash), 0o700))
		reopened := mustOpenBlockStore(t, store.rootPath)
		if got := reopened.noncanonicalAccountingSnapshot(); got.uniqueCount != 0 || got.usedBytes != 0 {
			t.Fatalf("canonical artifact entered Open accounting: %+v", got)
		}
		if err := requireCompleteCanonicalPrefix(reopened); err == nil {
			t.Fatal("canonical completeness accepted the wrong-kind artifact")
		}
	})
	replaceLeaf := func(store *BlockStore, path string, header []byte) {
		mustNoncanonical(t, os.Rename(path, path+".old"), os.WriteFile(path, header, 0o600), os.Remove(path+".old"), os.Chtimes(store.headersDir, time.Unix(1_000_000_000, 0), time.Unix(1_000_000_000, 0)))
	}
	for _, tc := range []struct {
		name, want string
		phase      int
		mutate     func(*BlockStore, string, []byte)
	}{
		{"empty EOF", "noncanonical artifact directory identity drift", 1, func(store *BlockStore, _ string, _ []byte) {
			mustNoncanonical(t, os.WriteFile(noncanonicalTestFile(store, noncanonicalBlockArtifact, [32]byte{1}), []byte("x"), 0o600))
			mustNoncanonical(t, os.Chtimes(store.blocksDir, time.Unix(1_000_000_001, 0), time.Unix(1_000_000_001, 0)))
		}}, {"enumerated inode", "noncanonical artifact enumeration drift", 2, replaceLeaf}, {"opened inode", "noncanonical artifact is not the opened regular leaf", 3, replaceLeaf}, {"pre-open fifo", "noncanonical artifact is not the opened regular leaf", 3, func(_ *BlockStore, path string, _ []byte) {
			mustNoncanonical(t, os.Remove(path), syscall.Mkfifo(path, 0o600))
		}}, {"pre-open symlink ELOOP", "ELOOP", 3, func(_ *BlockStore, path string, _ []byte) {
			mustNoncanonical(t, os.Remove(path), os.Symlink(path+".target", path))
		}}, {"same inode rewrite", "noncanonical artifact identity drift", 4, func(_ *BlockStore, path string, header []byte) {
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
		}}, {"post-close leaf", "noncanonical artifact close drift", 5, replaceLeaf}, {"post-close directory", "noncanonical artifact directory identity drift", 5, func(store *BlockStore, path string, _ []byte) {
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

func TestNoncanonicalDisconnectRejectsStrictLeaves(t *testing.T) {
	for _, tc := range []struct {
		name, want string
		wantIs     error
	}{
		{"directory", "noncanonical artifact enumeration drift", nil},
		{"fifo", "noncanonical artifact enumeration drift", nil},
		{"symlink", "read noncanonical artifact", nil},
		{"oversize", "store file exceeds size bound", errStoreFileTooLarge},
		{"identity_drift", "store file exceeds size bound", errStoreFileTooLarge},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := mustCreateBlockStore(t, filepath.Join(t.TempDir(), "disconnect"))
			raw := testHeaderBytes(0x29, 41)
			h := mustHeaderHash(t, raw)
			mustNoncanonical(t, s.SetCanonicalTip(0, h))
			path := noncanonicalTestFile(s, noncanonicalHeaderArtifact, h)
			switch tc.name {
			case "directory":
				mustNoncanonical(t, os.Mkdir(path, 0o700))
			case "fifo":
				mustNoncanonical(t, syscall.Mkfifo(path, 0o600))
			case "symlink":
				target := filepath.Join(t.TempDir(), "target")
				mustNoncanonical(t, os.WriteFile(target, raw, 0o600), os.Symlink(target, path))
			case "oversize":
				mustNoncanonical(t, os.WriteFile(path, make([]byte, headerFileMaxBytes+1), 0o600))
			default:
				mustNoncanonical(t, os.WriteFile(path, raw, 0o600))
				s.leafProbe = func() { s.leafProbe = nil; mustNoncanonical(t, os.WriteFile(path, append(raw, 0), 0o600)) }
			}
			before, err := s.CanonicalIndexSnapshot()
			mustNoncanonical(t, err)
			digest, disk := s.noncanonicalAccountingDigest(), mustReadIndexFile(t, s)
			if err := s.TruncateCanonical(0); err == nil || !strings.Contains(err.Error(), tc.want) || tc.wantIs != nil && !errors.Is(err, tc.wantIs) || errors.Is(err, errNoncanonicalCount) || errors.Is(err, errNoncanonicalBytes) {
				t.Fatalf("disconnect strict leaf err=%v want=%q", err, tc.want)
			}
			after, err := s.CanonicalIndexSnapshot()
			mustNoncanonical(t, err)
			if !slices.Equal(after, before) || s.noncanonicalAccountingDigest() != digest || !bytes.Equal(mustReadIndexFile(t, s), disk) {
				t.Fatal("rejected disconnect mutated canonical, accounting, or disk")
			}
		})
	}
}

func rejectNoncanonicalTransition(t *testing.T, want string, amend func(*noncanonicalAccounting, [32]byte)) {
	t.Helper()
	s := mustCreateBlockStore(t, filepath.Join(t.TempDir(), "invalid-accounting"))
	h := mustHeaderHash(t, testHeaderBytes(0x2a, 42))
	mustNoncanonical(t, s.SetCanonicalTip(0, h))
	a, err := newNoncanonicalAccounting(noncanonicalDefaultByteLimit)
	mustNoncanonical(t, err)
	for i := range a.rows[:2] {
		a.rows[i] = noncanonicalRow{hash: [32]byte{byte(i + 1)}, blockBytes: 1, height: noncanonicalUnknownHeight}
		a.rows[i].setState(noncanonicalBlockArtifact, BlockArtifactValid)
	}
	a.count, a.sortedCount, a.usedBytes = 2, 2, 2
	amend(a, h)
	s.noncanonical.Store(a)
	before, err := s.CanonicalIndexSnapshot()
	mustNoncanonical(t, err)
	digest, disk := s.noncanonicalAccountingDigest(), mustReadIndexFile(t, s)
	writes := 0
	withWriteFileAtomicFn(t, func(string, []byte, os.FileMode) error { writes++; return nil })
	err = s.TruncateCanonical(0)
	after, snapshotErr := s.CanonicalIndexSnapshot()
	mustNoncanonical(t, snapshotErr)
	if err == nil || !strings.Contains(err.Error(), want) || writes != 0 {
		t.Fatalf("transition error=%v want=%q writes=%d", err, want, writes)
	}
	if s.noncanonical.Load() != a || !slices.Equal(after, before) || s.noncanonicalAccountingDigest() != digest || !bytes.Equal(mustReadIndexFile(t, s), disk) {
		t.Fatal("invalid accounting mutated canonical, accounting, or disk")
	}
}

func TestNoncanonicalTransitionValidatesAccounting(t *testing.T) {
	for _, tc := range []struct {
		name, want string
		amend      func(*noncanonicalAccounting, [32]byte)
	}{
		{"backing_shape", "image is inconsistent", func(a *noncanonicalAccounting, _ [32]byte) { a.rows, a.count, a.sortedCount = a.rows[:0], 0, 0 }},
		{"limit", "limit is inconsistent", func(a *noncanonicalAccounting, _ [32]byte) { a.limit = 1 }},
		{"used_total", "total is inconsistent", func(a *noncanonicalAccounting, _ [32]byte) { a.usedBytes-- }},
		{"unsorted", "not strictly sorted", func(a *noncanonicalAccounting, _ [32]byte) { a.rows[0], a.rows[1] = a.rows[1], a.rows[0] }},
		{"canonical_overlap", "canonical hash remained", func(a *noncanonicalAccounting, h [32]byte) {
			a.count, a.sortedCount, a.usedBytes, a.rows[0].hash = 1, 1, 1, h
		}},
		{"reservation", "image is inconsistent", func(a *noncanonicalAccounting, _ [32]byte) {
			a.reservedBytes = 1
			a.rows[0].setReservation(noncanonicalBlockArtifact, 1)
		}},
		{"row_overflow", "total overflow", func(a *noncanonicalAccounting, _ [32]byte) {
			a.count, a.sortedCount, a.usedBytes, a.rows[0].blockBytes, a.rows[0].headerBytes = 1, 1, 0, ^uint64(0), 1
		}},
		{"total_overflow", "total overflow", func(a *noncanonicalAccounting, _ [32]byte) {
			a.usedBytes, a.rows[0].blockBytes, a.rows[1].blockBytes = 0, ^uint64(0), 1
		}},
	} {
		t.Run(tc.name, func(t *testing.T) { rejectNoncanonicalTransition(t, tc.want, tc.amend) })
	}
}

func TestNoncanonicalTransitionNormalizesOverlapAndOrder(t *testing.T) {
	overlap := mustCreateBlockStore(t, filepath.Join(t.TempDir(), "overlap"))
	header := testHeaderBytes(0x2b, 43)
	hash := mustHeaderHash(t, header)
	mustNoncanonical(t, overlap.StoreBlock(hash, header, []byte("overlap")))
	overlap.index.Canonical = []string{hex.EncodeToString(hash[:])}
	overlap.indexRaw = []byte("overlap")
	prepared := mustPrepareCanonicalIndex(t, overlap, []string{})
	delta, err := overlap.prepareNoncanonicalReclassification(prepared, nil)
	if err != nil || delta.uniqueCount != 1 || len(delta.removeIndices) != 1 || len(delta.disconnected) != 1 {
		t.Fatalf("overlap delta=%+v err=%v", delta, err)
	}
	ordered := mustCreateBlockStore(t, filepath.Join(t.TempDir(), "ordered"))
	firstHeader, secondHeader := testHeaderBytes(0x2c, 44), testHeaderBytes(0x2d, 45)
	first, second := mustHeaderHash(t, firstHeader), mustHeaderHash(t, secondHeader)
	if bytes.Compare(first[:], second[:]) < 0 {
		first, second, firstHeader, secondHeader = second, first, secondHeader, firstHeader
	}
	mustNoncanonical(t, ordered.StoreBlock(first, firstHeader, []byte("first")), ordered.StoreBlock(second, secondHeader, []byte("second")))
	mustNoncanonical(t, ordered.RestoreCanonicalIndex([]string{hex.EncodeToString(first[:]), hex.EncodeToString(second[:])}), ordered.TruncateCanonical(0))
	a := ordered.noncanonical.Load()
	if a.count != 2 || bytes.Compare(a.rows[0].hash[:], a.rows[1].hash[:]) >= 0 {
		t.Fatalf("disconnected rows=%+v", a.rows[:a.count])
	}
	if _, ok := a.find(first); !ok {
		t.Fatal("sorted disconnected row is not findable")
	}
	mustNoncanonicalRestartDigest(t, ordered, ordered.noncanonicalAccountingDigest())
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
	if phase >= 3 && want != "ELOOP" {
		closeCalls = countNoncanonicalClose(t, path, nil)
	}
	done := make(chan error, 1)
	go func() { _, err := store.rebuildNoncanonicalAccounting(noncanonicalDefaultByteLimit); done <- err }()
	if err := receiveNoncanonical(t, done, "rebuild drift did not return"); err == nil || errors.Is(err, errNoncanonicalCount) || errors.Is(err, errNoncanonicalBytes) || want == "ELOOP" && !errors.Is(err, syscall.ELOOP) || want != "ELOOP" && !strings.Contains(err.Error(), want) || closeCalls != nil && *closeCalls != 1 {
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
	if errNoncanonicalCount.Error() != "LOCAL_RESOURCE_UNAVAILABLE(noncanonical_count)" || errNoncanonicalBytes.Error() != "LOCAL_RESOURCE_UNAVAILABLE(noncanonical_bytes)" {
		t.Fatal("noncanonical resource identities drifted")
	}
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
	if err := store.reserveNoncanonicalArtifactWrite([32]byte{3}, []noncanonicalReservationLeaf{{kind: noncanonicalBlockArtifact, bytes: ^uint64(0)}, {kind: noncanonicalHeaderArtifact, bytes: 1}}, nil, func(*noncanonicalReservation) error { called = true; return nil }); !errors.Is(err, errNoncanonicalCount) || called {
		t.Fatalf("reserve count precedence err=%v called=%t", err, called)
	}
	if err := full.addScanned([32]byte{3}, noncanonicalBlockArtifact, ^uint64(0), BlockArtifactInvalid, [32]byte{}, 0); !errors.Is(err, errNoncanonicalCount) || full.usedBytes != 0 {
		t.Fatalf("scan count precedence err=%v used=%d", err, full.usedBytes)
	}
	full.count, full.sortedCount, full.usedBytes, full.reservedBytes, full.limit = 0, 0, 0, 0, noncanonicalDefaultByteLimit
	row := full.rows[0]
	called = false
	if err := store.reserveNoncanonicalArtifactWrite([32]byte{4}, []noncanonicalReservationLeaf{{kind: noncanonicalBlockArtifact, bytes: ^uint64(0)}, {kind: noncanonicalHeaderArtifact, bytes: 1}}, nil, func(*noncanonicalReservation) error { called = true; return nil }); !errors.Is(err, errNoncanonicalBytes) || errors.Is(err, errNoncanonicalCount) || called || full.count != 0 || full.sortedCount != 0 || full.usedBytes != 0 || full.reservedBytes != 0 || full.limit != noncanonicalDefaultByteLimit || full.rows[0] != row {
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

func TestNoncanonicalStoreBlockConflictPrecedesConcurrentQuota(t *testing.T) {
	store := mustCreateBlockStore(t, filepath.Join(t.TempDir(), "store"))
	accounting := installNoncanonicalAccounting(t, store, noncanonicalDefaultByteLimit)
	header, first := testHeaderBytes(23, 204), []byte("first partial")
	hash := mustHeaderHash(t, header)
	blockPath := noncanonicalTestFile(store, noncanonicalBlockArtifact, hash)
	mustNoncanonical(t, os.WriteFile(blockPath, first, 0o600))
	mustNoncanonical(t, accounting.addScanned(hash, noncanonicalBlockArtifact, uint64(len(first)), BlockArtifactInvalid, [32]byte{}, noncanonicalUnknownHeight))
	accounting.limit = accounting.usedBytes
	previousRead := readFileByPathFn
	t.Cleanup(func() { readFileByPathFn = previousRead })
	sawPending := false
	readFileByPathFn = func(path string, maxBytes int64) ([]byte, error) {
		if path != blockPath {
			return previousRead(path, maxBytes)
		}
		store.stateMu.Lock()
		sawPending = store.noncanonicalPending[hash] != nil
		store.stateMu.Unlock()
		if !sawPending {
			return nil, errors.New("preflight preceded reservation")
		}
		return previousRead(path, maxBytes)
	}
	err := store.StoreBlock(hash, header, []byte("conflicting"))
	if !sawPending {
		t.Fatal("preflight preceded reservation")
	}
	mustNoncanonicalAtomic(t, err, blockPath)
}

func TestNoncanonicalReservationsCoordinateHashes(t *testing.T) {
	store := mustCreateBlockStore(t, filepath.Join(t.TempDir(), "store"))
	installNoncanonicalAccounting(t, store, noncanonicalDefaultByteLimit)
	leaf := noncanonicalReservationLeaf{kind: noncanonicalBlockArtifact, bytes: 1, state: BlockArtifactValid}
	sameLeaf := noncanonicalReservationLeaf{kind: noncanonicalHeaderArtifact, bytes: 1, state: BlockArtifactValid}
	synctest.Test(t, func(t *testing.T) {
		started, release, firstDone := make(chan struct{}), make(chan struct{}), make(chan error, 1)
		defer func() {
			select {
			case <-release:
			default:
				close(release)
			}
		}()
		go func() {
			firstDone <- store.reserveNoncanonicalArtifactWrite([32]byte{1}, []noncanonicalReservationLeaf{leaf}, nil, func(r *noncanonicalReservation) error { close(started); <-release; r.created(leaf); return nil })
		}()
		synctest.Wait()
		<-started
		snapshot := store.noncanonicalAccountingSnapshot()
		if len(snapshot.rows) != 1 || snapshot.usedBytes != 0 || snapshot.reservedBytes != 1 || snapshot.uniqueCount != 1 || snapshot.rows[0].blockBytes != 1 || snapshot.rows[0].height != noncanonicalUnknownHeight || snapshot.rows[0].flags&(1<<6) == 0 {
			t.Fatalf("pending used=%d reserved=%d count=%d rows=%d", snapshot.usedBytes, snapshot.reservedBytes, snapshot.uniqueCount, len(snapshot.rows))
		}
		if got, want := store.noncanonicalAccountingDigest(), noncanonicalTestDigest(snapshot); got != want {
			t.Fatalf("pending digest=%x want=%x", got, want)
		}
		prepared, sameDone, otherDone := make(chan struct{}), make(chan error, 1), make(chan error, 1)
		go func() {
			sameDone <- store.reserveNoncanonicalArtifactWrite([32]byte{1}, nil, func() ([]noncanonicalReservationLeaf, error) {
				close(prepared)
				return []noncanonicalReservationLeaf{sameLeaf}, nil
			}, func(r *noncanonicalReservation) error { r.created(sameLeaf); return nil })
		}()
		go func() {
			otherDone <- store.reserveNoncanonicalArtifactWrite([32]byte{}, []noncanonicalReservationLeaf{leaf}, nil, func(r *noncanonicalReservation) error { r.created(leaf); return nil })
		}()
		synctest.Wait()
		mustNoncanonical(t, <-otherDone)
		select {
		case <-prepared:
			t.Fatal("same hash preflight bypassed reservation")
		case err := <-sameDone:
			t.Fatalf("same hash bypassed reservation: %v", err)
		default:
		}
		close(release)
		synctest.Wait()
		mustNoncanonical(t, <-firstDone)
		mustNoncanonical(t, <-sameDone)
		snapshot = store.noncanonicalAccountingSnapshot()
		if len(snapshot.rows) != 2 || snapshot.usedBytes != 3 || snapshot.reservedBytes != 0 || snapshot.rows[0].hash != ([32]byte{}) || snapshot.rows[0].state(noncanonicalBlockArtifact) != BlockArtifactValid || snapshot.rows[1].hash != ([32]byte{1}) || snapshot.rows[1].state(noncanonicalBlockArtifact) != BlockArtifactValid || snapshot.rows[1].state(noncanonicalHeaderArtifact) != BlockArtifactValid {
			t.Fatalf("reservation convergence=%+v", snapshot)
		}
		before, beforeDigest, cutover := snapshot, store.noncanonicalAccountingDigest(), [32]byte{2}
		called := false
		mustNoncanonical(t, store.reserveNoncanonicalArtifactWrite(cutover, nil, func() ([]noncanonicalReservationLeaf, error) {
			store.stateMu.Lock()
			store.canonicalHeightByHash[cutover] = 0
			store.stateMu.Unlock()
			return []noncanonicalReservationLeaf{leaf}, nil
		}, func(r *noncanonicalReservation) error { called = true; r.created(leaf); return nil }))
		if got := store.noncanonicalAccountingSnapshot(); !called || len(got.rows) != len(before.rows) || got.usedBytes != before.usedBytes || got.reservedBytes != before.reservedBytes || got.uniqueCount != before.uniqueCount || store.noncanonicalAccountingDigest() != beforeDigest {
			t.Fatalf("canonical cutover charged=%+v", got)
		}
	})
}

func TestNoncanonicalCanonicalWriteFencesDisconnect(t *testing.T) {
	for _, tc := range []struct {
		name string
		kind noncanonicalArtifactKind
	}{{"block_header", noncanonicalBlockArtifact}, {"undo", noncanonicalUndoArtifact}} {
		t.Run(tc.name, func(t *testing.T) {
			store := mustCreateBlockStore(t, filepath.Join(t.TempDir(), "store"))
			header, block := testHeaderBytes(0x31, 49), append([]byte(nil), devnetGenesisBlockBytes...)
			copy(block[:consensus.BLOCK_HEADER_BYTES], header)
			hash := mustHeaderHash(t, header)
			mustNoncanonical(t, store.SetCanonicalTip(0, hash))
			var write func() error
			wantBytes := uint64(len(header) + len(block))
			if tc.kind == noncanonicalUndoArtifact {
				undo := &BlockUndo{BlockHeight: 0}
				raw, err := marshalUndoEnvelope(hash, undo)
				mustNoncanonical(t, err)
				wantBytes, write = uint64(len(raw)), func() error { return store.PutUndo(hash, undo) }
			} else {
				write = func() error { return store.StoreBlock(hash, header, block) }
			}
			synctest.Test(t, func(t *testing.T) {
				started, release, blocked := make(chan struct{}), make(chan struct{}), false
				withAtomicWriteOps(t, func(ops *atomicWriteOps) {
					open := ops.openScratch
					ops.openScratch = func(path string, flags int, mode os.FileMode) (atomicWriteScratchFile, error) {
						if !blocked {
							blocked = true
							close(started)
							<-release
						}
						return open(path, flags, mode)
					}
				})
				writeDone, disconnectDone := make(chan error, 1), make(chan error, 1)
				go func() { writeDone <- write() }()
				synctest.Wait()
				<-started
				go func() { disconnectDone <- store.TruncateCanonical(0) }()
				synctest.Wait()
				var early bool
				var disconnectErr error
				select {
				case disconnectErr = <-disconnectDone:
					early = true
				default:
				}
				close(release)
				synctest.Wait()
				writeErr := <-writeDone
				if early {
					mustNoncanonical(t, writeErr)
					t.Fatalf("disconnect bypassed canonical writer: %v", disconnectErr)
				}
				mustNoncanonical(t, writeErr, <-disconnectDone)
				snapshot := store.noncanonicalAccountingSnapshot()
				if len(snapshot.rows) != 1 || snapshot.rows[0].hash != hash || snapshot.rows[0].state(tc.kind) != BlockArtifactValid || snapshot.usedBytes != wantBytes {
					t.Fatalf("disconnected writer snapshot=%+v", snapshot)
				}
			})
		})
	}
}

func TestNoncanonicalReservationEarlyExitsFinishPending(t *testing.T) {
	store := mustCreateBlockStore(t, filepath.Join(t.TempDir(), "store"))
	accounting := installNoncanonicalAccounting(t, store, noncanonicalDefaultByteLimit)
	fault := errors.New("prepare")
	leaf := noncanonicalReservationLeaf{kind: noncanonicalBlockArtifact, bytes: 1, state: BlockArtifactValid}
	check := func(name string, hash [32]byte, exit func() ([]noncanonicalReservationLeaf, error), want error, wantCall bool) {
		t.Helper()
		before, digest, called := store.noncanonicalAccountingSnapshot(), store.noncanonicalAccountingDigest(), false
		var captured chan struct{}
		err := store.reserveNoncanonicalArtifactWrite(hash, nil, func() ([]noncanonicalReservationLeaf, error) {
			store.stateMu.Lock()
			captured = store.noncanonicalPending[hash]
			store.stateMu.Unlock()
			if captured == nil {
				t.Fatalf("%s prepare did not own pending", name)
			}
			return exit()
		}, func(*noncanonicalReservation) error { called = true; return nil })
		if want == nil && err != nil || want != nil && !errors.Is(err, want) {
			t.Fatalf("%s err=%v want=%v", name, err, want)
		}
		store.stateMu.Lock()
		pending := store.noncanonicalPending[hash]
		store.stateMu.Unlock()
		select {
		case <-captured:
		default:
			t.Fatalf("%s pending channel remained open", name)
		}
		after := store.noncanonicalAccountingSnapshot()
		if pending != nil || called != wantCall || len(after.rows) != len(before.rows) || after.usedBytes != before.usedBytes || after.reservedBytes != before.reservedBytes || after.uniqueCount != before.uniqueCount || store.noncanonicalAccountingDigest() != digest {
			t.Fatalf("%s pending=%t called=%t snapshot=%+v", name, pending != nil, called, after)
		}
	}
	check("prepare error", [32]byte{1}, func() ([]noncanonicalReservationLeaf, error) { return nil, fault }, fault, false)
	check("zero leaves", [32]byte{2}, func() ([]noncanonicalReservationLeaf, error) { return nil, nil }, nil, false)
	accounting.limit = 0
	check("quota", [32]byte{3}, func() ([]noncanonicalReservationLeaf, error) { return []noncanonicalReservationLeaf{leaf}, nil }, errNoncanonicalBytes, false)
	accounting.limit = noncanonicalDefaultByteLimit
	canonical := [32]byte{4}
	check("canonical", canonical, func() ([]noncanonicalReservationLeaf, error) {
		store.stateMu.Lock()
		store.canonicalHeightByHash[canonical] = 0
		store.stateMu.Unlock()
		return []noncanonicalReservationLeaf{leaf}, nil
	}, nil, true)
}

func TestNoncanonicalCanonicalTransitionsReclassify(t *testing.T) {
	store := mustCreateBlockStore(t, filepath.Join(t.TempDir(), "store"))
	genesis, err := consensus.ParseBlockBytes(devnetGenesisBlockBytes)
	mustNoncanonical(t, err)
	mustNoncanonical(t, store.CommitCanonicalBlock(0, devnetGenesisBlockHash, genesis.HeaderBytes, devnetGenesisBlockBytes, &BlockUndo{BlockHeight: 0}))
	header1a, header1b := testHeaderBytes(0x41, 65), testHeaderBytes(0x42, 66)
	copy(header1a[4:36], devnetGenesisBlockHash[:])
	copy(header1b[4:36], devnetGenesisBlockHash[:])
	hash1a, hash1b := mustHeaderHash(t, header1a), mustHeaderHash(t, header1b)
	blockA, blockB := append([]byte(nil), devnetGenesisBlockBytes...), append([]byte(nil), devnetGenesisBlockBytes...)
	copy(blockA[:consensus.BLOCK_HEADER_BYTES], header1a)
	copy(blockB[:consensus.BLOCK_HEADER_BYTES], header1b)

	check := func(stage string) {
		t.Helper()
		wantImage, err := store.rebuildNoncanonicalAccounting(noncanonicalDefaultByteLimit)
		mustNoncanonical(t, err)
		want := noncanonicalAccountingSnapshot{usedBytes: wantImage.usedBytes, reservedBytes: wantImage.reservedBytes, uniqueCount: wantImage.count, rows: append([]noncanonicalRow(nil), wantImage.rows[:wantImage.count]...)}
		got := store.noncanonicalAccountingSnapshot()
		if got.usedBytes != want.usedBytes || got.reservedBytes != 0 || got.uniqueCount != want.uniqueCount || len(got.rows) != len(want.rows) || store.noncanonicalAccountingDigest() != noncanonicalTestDigest(want) {
			t.Fatalf("%s: snapshot=%+v want rows=%d used=%d", stage, got, len(want.rows), want.usedBytes)
		}
		for i := range got.rows {
			if got.rows[i] != want.rows[i] {
				t.Fatalf("%s: row %d = %+v want %+v", stage, i, got.rows[i], want.rows[i])
			}
		}
		mustNoncanonicalRestartDigest(t, store, store.noncanonicalAccountingDigest())
	}

	mustNoncanonical(t, store.StoreBlock(hash1a, header1a, blockA), store.StoreBlock(hash1b, header1b, blockB))
	mustNoncanonical(t, store.PutUndo(hash1a, &BlockUndo{BlockHeight: 1}), store.PutUndo(hash1b, &BlockUndo{BlockHeight: 1}))
	check("both_forks_stored")

	oldCount := store.noncanonical.Load().count
	mustNoncanonical(t, store.SetCanonicalTip(1, hash1a))
	if tail := store.noncanonical.Load().rows[store.noncanonical.Load().count:oldCount]; len(tail) != 1 || tail[0] != (noncanonicalRow{}) {
		t.Fatalf("former active tail=%+v", tail)
	}
	check("append_canonicalizes_a")

	mustNoncanonical(t, store.SetCanonicalTip(1, hash1b))
	check("reorg_canonicalizes_b_disconnects_a")

	mustNoncanonical(t, store.RewindToHeight(0))
	check("rewind_to_genesis")

	mustNoncanonical(t, store.TruncateCanonical(0))
	check("truncate_to_empty")

	mustNoncanonical(t, store.RestoreCanonicalIndex([]string{hex.EncodeToString(devnetGenesisBlockHash[:]), hex.EncodeToString(hash1b[:])}))
	check("restore_two_rows")
	before := store.noncanonicalAccountingSnapshot()
	mustNoncanonical(t, store.SetCanonicalTip(0, devnetGenesisBlockHash))
	after := store.noncanonicalAccountingSnapshot()
	canonical, err := store.CanonicalIndexSnapshot()
	mustNoncanonical(t, err)
	if len(canonical) != 2 || after.usedBytes != before.usedBytes || after.uniqueCount != before.uniqueCount || len(after.rows) != len(before.rows) || store.noncanonicalAccountingDigest() != noncanonicalTestDigest(before) {
		t.Fatalf("no-op tip changed totals: %+v -> %+v", before, after)
	}
}

func TestNoncanonicalPreparedOutcomesPublishBothOrNeither(t *testing.T) {
	fault := errors.New("prepared write fault")
	for _, tc := range []struct {
		name      string
		wantClass canonicalCommitClass
		publish   bool
		write     func(t *testing.T, path string, data []byte, mode os.FileMode) error
	}{
		{name: "committed", wantClass: canonicalCommitted, publish: true},
		{name: "precommit", wantClass: canonicalCommitPrecommit, write: func(_ *testing.T, path string, _ []byte, _ os.FileMode) error {
			return newAtomicWriteError(atomicWriteBeforeNamespaceCommit, path, atomicWriteOverwrite, fault)
		}},
		{name: "terminal_old", wantClass: canonicalCommitTerminalOld, write: func(_ *testing.T, path string, _ []byte, _ os.FileMode) error {
			return newAtomicWriteError(atomicWriteAfterNamespaceCommit, path, atomicWriteOverwrite, fault)
		}},
		{name: "terminal_new", wantClass: canonicalCommitTerminalNew, publish: true, write: func(t *testing.T, path string, data []byte, mode os.FileMode) error {
			mustNoncanonical(t, os.WriteFile(path, data, mode))
			return newAtomicWriteError(atomicWriteAfterNamespaceCommit, path, atomicWriteOverwrite, fault)
		}},
		{name: "terminal_unknown", wantClass: canonicalCommitTerminalUnknown, write: func(t *testing.T, path string, _ []byte, mode os.FileMode) error {
			mustNoncanonical(t, os.WriteFile(path, []byte("third identity"), mode))
			return newAtomicWriteError(atomicWriteAfterNamespaceCommit, path, atomicWriteOverwrite, fault)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := mustCreateBlockStore(t, filepath.Join(t.TempDir(), "store"))
			genesis, err := consensus.ParseBlockBytes(devnetGenesisBlockBytes)
			mustNoncanonical(t, err)
			mustNoncanonical(t, store.CommitCanonicalBlock(0, devnetGenesisBlockHash, genesis.HeaderBytes, devnetGenesisBlockBytes, &BlockUndo{BlockHeight: 0}))
			headerB, headerS := testHeaderBytes(0x51, 81), testHeaderBytes(0x52, 82)
			hashB, hashS := mustHeaderHash(t, headerB), mustHeaderHash(t, headerS)
			mustNoncanonical(t, store.StoreBlock(hashB, headerB, []byte("replacement B")), store.StoreBlock(hashS, headerS, []byte("sibling S")))
			beforeAccounting := store.noncanonicalAccountingDigest()
			beforeCanonical, err := store.CanonicalIndexSnapshot()
			mustNoncanonical(t, err)
			prepared := mustPrepareCanonicalIndex(t, store, []string{hex.EncodeToString(hashB[:])})
			if tc.write != nil {
				withWriteFileAtomicFn(t, func(path string, data []byte, mode os.FileMode) error {
					return tc.write(t, path, data, mode)
				})
			}

			got := prepared.commit(store)
			if got.class != tc.wantClass {
				t.Fatalf("commit class=%s err=%v want=%s", got.class, got.err, tc.wantClass)
			}
			canonical, err := store.CanonicalIndexSnapshot()
			mustNoncanonical(t, err)
			accounting := store.noncanonical.Load()
			_, oldPresent := accounting.find(devnetGenesisBlockHash)
			_, newPresent := accounting.find(hashB)
			_, siblingPresent := accounting.find(hashS)
			if tc.publish {
				if len(canonical) != 1 || canonical[0] != hex.EncodeToString(hashB[:]) || newPresent || !oldPresent || !siblingPresent || accounting.count != 2 {
					t.Fatalf("published canonical=%v old=%v new=%v sibling=%v rows=%d", canonical, oldPresent, newPresent, siblingPresent, accounting.count)
				}
				mustNoncanonicalRestartDigest(t, store, store.noncanonicalAccountingDigest())
				return
			}
			if !slices.Equal(canonical, beforeCanonical) || oldPresent || !newPresent || !siblingPresent || store.noncanonicalAccountingDigest() != beforeAccounting {
				t.Fatalf("non-publishing outcome changed RAM: canonical=%v old=%v new=%v sibling=%v", canonical, oldPresent, newPresent, siblingPresent)
			}
		})
	}
}

func TestNoncanonicalPreparedTransitionFencesReservations(t *testing.T) {
	store := mustCreateBlockStore(t, filepath.Join(t.TempDir(), "store"))
	header := testHeaderBytes(0x61, 97)
	hash := mustHeaderHash(t, header)
	mustNoncanonical(t, store.StoreBlock(hash, header, []byte("prepared transition")))
	prepared := mustPrepareCanonicalIndex(t, store, []string{hex.EncodeToString(hash[:])})
	nextHeader := testHeaderBytes(0x62, 98)
	nextHash := mustHeaderHash(t, nextHeader)

	synctest.Test(t, func(t *testing.T) {
		write := writeFileAtomicFn
		writeStarted, releaseWrite := make(chan struct{}), make(chan struct{})
		writes := 0
		withWriteFileAtomicFn(t, func(path string, data []byte, mode os.FileMode) error {
			writes++
			if writes == 1 {
				close(writeStarted)
				<-releaseWrite
			}
			return write(path, data, mode)
		})
		commitDone := make(chan canonicalCommitResult, 1)
		go func() { commitDone <- prepared.commit(store) }()
		synctest.Wait()
		<-writeStarted
		store.stateMu.Lock()
		transitionActive := store.noncanonicalTransitionDone != nil
		store.stateMu.Unlock()
		if !transitionActive {
			t.Fatal("prepared write released its transition fence")
		}
		legacyDone := make(chan error, 1)
		go func() { legacyDone <- store.SetCanonicalTip(1, nextHash) }()

		secondPrepared := make(chan struct{})
		secondDone := make(chan error, 1)
		leaf := noncanonicalReservationLeaf{kind: noncanonicalBlockArtifact, bytes: 1, state: BlockArtifactValid}
		go func() {
			secondDone <- store.reserveNoncanonicalArtifactWrite([32]byte{9}, nil, func() ([]noncanonicalReservationLeaf, error) {
				close(secondPrepared)
				return []noncanonicalReservationLeaf{leaf}, nil
			}, func(r *noncanonicalReservation) error { r.created(leaf); return nil })
		}()
		synctest.Wait()
		select {
		case <-secondPrepared:
			t.Fatal("reservation bypassed prepared transition")
		default:
		}
		select {
		case err := <-legacyDone:
			t.Fatalf("legacy mutation bypassed prepared transition: %v", err)
		default:
		}

		close(releaseWrite)
		synctest.Wait()
		if got := <-commitDone; got.class != canonicalCommitted {
			t.Fatalf("commit=%s err=%v", got.class, got.err)
		}
		mustNoncanonical(t, <-secondDone, <-legacyDone)
		select {
		case <-secondPrepared:
		default:
			t.Fatal("reservation did not resume after prepared transition")
		}
		canonical, err := store.CanonicalIndexSnapshot()
		if err != nil || len(canonical) != 2 {
			t.Fatalf("legacy mutation did not resume on the published image: canonical=%v err=%v", canonical, err)
		}
	})
}

func TestNoncanonicalPreparedReadbackOccursOnce(t *testing.T) {
	store := mustCreateBlockStore(t, filepath.Join(t.TempDir(), "readback"))
	prepared := mustPrepareCanonicalIndex(t, store, []string{canonicalIndexRow(0x63)})
	ready := make(chan struct{})
	withWriteFileAtomicFn(t, func(path string, _ []byte, _ os.FileMode) error {
		mustNoncanonical(t, os.Remove(path), syscall.Mkfifo(path, 0o600))
		close(ready)
		return newAtomicWriteError(atomicWriteAfterNamespaceCommit, path, atomicWriteOverwrite, errors.New("post-namespace"))
	})
	wrote := make(chan error, 1)
	go func() {
		<-ready
		f, err := os.OpenFile(store.indexPath, os.O_WRONLY, 0)
		if err == nil {
			_, err = f.Write(prepared.oldRaw)
			err = errors.Join(err, f.Close())
		}
		wrote <- err
	}()
	done := make(chan canonicalCommitResult, 1)
	go func() { done <- prepared.commit(store) }()
	select {
	case got := <-done:
		mustNoncanonical(t, receiveNoncanonical(t, wrote, "FIFO writer did not finish"))
		if got.class != canonicalCommitTerminalOld {
			t.Fatalf("readback result=%s err=%v", got.class, got.err)
		}
	case <-time.After(time.Second):
		f, err := os.OpenFile(store.indexPath, os.O_RDWR, 0)
		mustNoncanonical(t, err)
		_, _ = f.Write(prepared.oldRaw)
		_ = f.Close()
		mustNoncanonical(t, receiveNoncanonical(t, wrote, "FIFO writer did not finish after recovery"))
		receiveNoncanonical(t, done, "prepared commit did not finish after recovery")
		t.Fatal("prepared commit attempted a second visible readback")
	}
}

func TestNoncanonicalLegacyFailureAndTransitionErrorOrder(t *testing.T) {
	newCanonicalStore := func(t *testing.T) *BlockStore {
		t.Helper()
		store := mustCreateBlockStore(t, filepath.Join(t.TempDir(), "store"))
		genesis, err := consensus.ParseBlockBytes(devnetGenesisBlockBytes)
		mustNoncanonical(t, err)
		mustNoncanonical(t, store.CommitCanonicalBlock(0, devnetGenesisBlockHash, genesis.HeaderBytes, devnetGenesisBlockBytes, &BlockUndo{BlockHeight: 0}))
		return store
	}
	failNextSave := func(t *testing.T, fault error) {
		t.Helper()
		write, failNext := writeFileAtomicFn, true
		withWriteFileAtomicFn(t, func(path string, data []byte, mode os.FileMode) error {
			if failNext {
				failNext = false
				return newAtomicWriteError(atomicWriteBeforeNamespaceCommit, path, atomicWriteOverwrite, fault)
			}
			return write(path, data, mode)
		})
	}
	for _, tc := range []struct {
		name    string
		restore func(*BlockStore) error
	}{
		{"set_tip", func(store *BlockStore) error { return store.SetCanonicalTip(0, devnetGenesisBlockHash) }},
		{"restore", func(store *BlockStore) error {
			return store.RestoreCanonicalIndex([]string{hex.EncodeToString(devnetGenesisBlockHash[:])})
		}},
		{"reloadFromDisk", func(store *BlockStore) error { return store.reloadFromDisk() }},
	} {
		t.Run("legacy_precommit_ram_ahead_restart_disk_truth/"+tc.name, func(t *testing.T) {
			store := newCanonicalStore(t)
			accounting := store.noncanonical.Load()
			beforeDisk, beforeRestart := mustReadIndexFile(t, store), store.noncanonicalAccountingDigest()
			fault := errors.New("legacy precommit")
			failNextSave(t, fault)
			if err := store.TruncateCanonical(0); !errors.Is(err, fault) {
				t.Fatalf("truncate error=%v", err)
			}
			canonical, err := store.CanonicalIndexSnapshot()
			mustNoncanonical(t, err)
			_, disconnected := store.noncanonical.Load().find(devnetGenesisBlockHash)
			if len(canonical) != 0 || !disconnected || !bytes.Equal(mustReadIndexFile(t, store), beforeDisk) {
				t.Fatalf("RAM/disk outcome canonical=%v disconnected=%v", canonical, disconnected)
			}
			mustNoncanonical(t, tc.restore(store))
			canonical, err = store.CanonicalIndexSnapshot()
			mustNoncanonical(t, err)
			_, disconnected = store.noncanonical.Load().find(devnetGenesisBlockHash)
			if len(canonical) != 1 || store.InspectBlockPresence(devnetGenesisBlockHash).Class != BlockPresenceCanonical || disconnected || !bytes.Equal(mustReadIndexFile(t, store), beforeDisk) || store.noncanonical.Load() != accounting {
				t.Fatalf("rollback canonical=%v disconnected=%v", canonical, disconnected)
			}
			mustNoncanonicalRestartDigest(t, store, beforeRestart)
		})
	}

	for _, tc := range []struct {
		name             string
		apply            func(*BlockStore, [32]byte) error
		wantLen          int
		wantOldDisk, row bool
	}{
		{"truncate_to_disk", func(store *BlockStore, _ [32]byte) error { return store.TruncateCanonical(1) }, 1, true, true},
		{"set_noop", func(store *BlockStore, hash [32]byte) error { return store.SetCanonicalTip(1, hash) }, 2, false, false},
		{"truncate_noop", func(store *BlockStore, _ [32]byte) error { return store.TruncateCanonical(2) }, 2, false, false},
		{"restore_noop", func(store *BlockStore, hash [32]byte) error {
			return store.RestoreCanonicalIndex([]string{hex.EncodeToString(devnetGenesisBlockHash[:]), hex.EncodeToString(hash[:])})
		}, 2, false, false},
	} {
		t.Run("legacy_append_precommit/"+tc.name, func(t *testing.T) {
			store := newCanonicalStore(t)
			beforeDisk := mustReadIndexFile(t, store)
			header, block := testHeaderBytes(0x71, 113), append([]byte(nil), devnetGenesisBlockBytes...)
			copy(header[4:36], devnetGenesisBlockHash[:])
			copy(block[:consensus.BLOCK_HEADER_BYTES], header)
			hash := mustHeaderHash(t, header)
			mustNoncanonical(t, store.StoreBlock(hash, header, block), store.PutUndo(hash, &BlockUndo{BlockHeight: 1}))
			fault := errors.New("legacy append precommit")
			failNextSave(t, fault)
			if err := store.SetCanonicalTip(1, hash); !errors.Is(err, fault) {
				t.Fatalf("append error=%v", err)
			}
			mustNoncanonical(t, tc.apply(store, hash))
			canonical, err := store.CanonicalIndexSnapshot()
			mustNoncanonical(t, err)
			_, row := store.noncanonical.Load().find(hash)
			disk := mustReadIndexFile(t, store)
			if len(canonical) != tc.wantLen || bytes.Equal(disk, beforeDisk) != tc.wantOldDisk || row != tc.row || !bytes.Equal(store.visibleIndexBytes(), disk) {
				t.Fatalf("post-noop canonical=%v old_disk=%v row=%v", canonical, bytes.Equal(disk, beforeDisk), row)
			}
			mustNoncanonicalRestartDigest(t, store, store.noncanonicalAccountingDigest())
		})
	}

	t.Run("bytes_before_mutation", func(t *testing.T) {
		store := newCanonicalStore(t)
		accounting := store.noncanonical.Load()
		row, err := accounting.insertRow([32]byte{0xff}, 0)
		mustNoncanonical(t, err)
		row.blockBytes = accounting.limit
		row.setState(noncanonicalBlockArtifact, BlockArtifactValid)
		accounting.usedBytes = accounting.limit
		beforeCanonical, err := store.CanonicalIndexSnapshot()
		mustNoncanonical(t, err)
		beforeDigest, beforeDisk := store.noncanonicalAccountingDigest(), mustReadIndexFile(t, store)
		err = store.TruncateCanonical(0)
		if !errors.Is(err, errNoncanonicalBytes) || errors.Is(err, errNoncanonicalCount) {
			t.Fatalf("truncate error=%v", err)
		}
		afterCanonical, snapshotErr := store.CanonicalIndexSnapshot()
		mustNoncanonical(t, snapshotErr)
		if !slices.Equal(afterCanonical, beforeCanonical) || store.noncanonicalAccountingDigest() != beforeDigest || !bytes.Equal(mustReadIndexFile(t, store), beforeDisk) {
			t.Fatal("byte refusal changed RAM or disk")
		}
		prepared := mustPrepareCanonicalIndex(t, store, []string{})
		writes := 0
		withWriteFileAtomicFn(t, func(string, []byte, os.FileMode) error { writes++; return nil })
		got := prepared.commit(store)
		if got.class != "" || !errors.Is(got.err, errNoncanonicalBytes) || writes != 0 {
			t.Fatalf("prepared refusal class=%q err=%v writes=%d", got.class, got.err, writes)
		}
		afterPrepared, snapshotErr := store.CanonicalIndexSnapshot()
		mustNoncanonical(t, snapshotErr)
		if !slices.Equal(afterPrepared, beforeCanonical) || store.noncanonicalAccountingDigest() != beforeDigest || !bytes.Equal(mustReadIndexFile(t, store), beforeDisk) {
			t.Fatal("prepared byte refusal changed RAM or disk")
		}
		mustNoncanonical(t, store.reloadFromDisk())
		if got := prepared.commit(store); got.class != canonicalCommitStale || !errors.Is(got.err, errPreparedIndexSpent) || writes != 0 {
			t.Fatalf("reused refused image=%s err=%v writes=%d", got.class, got.err, writes)
		}
	})

	t.Run("count_precedes_bytes", func(t *testing.T) {
		store := newCanonicalStore(t)
		accounting := store.noncanonical.Load()
		for i := 0; i < noncanonicalHashCap; i++ {
			var hash [32]byte
			binary.BigEndian.PutUint32(hash[28:], uint32(i))
			accounting.rows[i] = noncanonicalRow{hash: hash, height: noncanonicalUnknownHeight}
			accounting.rows[i].setState(noncanonicalBlockArtifact, BlockArtifactValid)
		}
		accounting.rows[0].blockBytes = accounting.limit
		accounting.count, accounting.sortedCount, accounting.usedBytes = noncanonicalHashCap, noncanonicalHashCap, accounting.limit
		err := store.TruncateCanonical(0)
		if !errors.Is(err, errNoncanonicalCount) || errors.Is(err, errNoncanonicalBytes) {
			t.Fatalf("truncate error=%v", err)
		}
		freed := mustCreateBlockStore(t, filepath.Join(t.TempDir(), "freed"))
		freed.noncanonical.Store(accounting)
		mustNoncanonical(t, freed.SetCanonicalTip(0, accounting.rows[0].hash))
		if got := freed.noncanonical.Load(); got.count != noncanonicalHashCap-1 || got.usedBytes != 0 {
			t.Fatalf("canonical removal did not free the full image: count=%d bytes=%d", got.count, got.usedBytes)
		}
	})
}

func TestNoncanonicalReloadReplacesDivergentImage(t *testing.T) {
	store := mustCreateBlockStore(t, filepath.Join(t.TempDir(), "reload-replace"))
	aHeader, cHeader := testHeaderBytes(0x64, 100), testHeaderBytes(0x65, 101)
	a, c := mustHeaderHash(t, aHeader), mustHeaderHash(t, cHeader)
	mustNoncanonical(t, store.StoreBlock(a, aHeader, []byte("A")), store.StoreBlock(c, cHeader, []byte("C")))
	bHeader := testHeaderBytes(0x66, 102)
	b := mustHeaderHash(t, bHeader)
	mustNoncanonical(t, os.Remove(noncanonicalTestFile(store, noncanonicalBlockArtifact, a)), os.Remove(noncanonicalTestFile(store, noncanonicalHeaderArtifact, a)), os.WriteFile(noncanonicalTestFile(store, noncanonicalBlockArtifact, b), []byte("B"), 0o600), os.WriteFile(noncanonicalTestFile(store, noncanonicalHeaderArtifact, b), bHeader, 0o600))
	want, err := store.reconstructNoncanonicalAccounting(noncanonicalDefaultByteLimit)
	mustNoncanonical(t, err)
	wantSnapshot := noncanonicalAccountingSnapshot{usedBytes: want.usedBytes, uniqueCount: want.count, rows: append([]noncanonicalRow(nil), want.rows[:want.count]...)}
	image := store.noncanonical.Load()
	mustNoncanonical(t, store.reloadFromDisk())
	got := store.noncanonicalAccountingSnapshot()
	if store.noncanonical.Load() != image || got.usedBytes != wantSnapshot.usedBytes || got.uniqueCount != wantSnapshot.uniqueCount || !slices.Equal(got.rows, wantSnapshot.rows) || store.noncanonicalAccountingDigest() != noncanonicalTestDigest(wantSnapshot) {
		t.Fatalf("reload image=%+v want=%+v", got, wantSnapshot)
	}
	canonical, err := store.CanonicalIndexSnapshot()
	mustNoncanonical(t, err)
	if len(canonical) != 0 || !bytes.Equal(store.visibleIndexBytes(), mustReadIndexFile(t, store)) {
		t.Fatalf("reload canonical=%v", canonical)
	}
	mustNoncanonicalRestartDigest(t, store, store.noncanonicalAccountingDigest())
}

func TestNoncanonicalReloadFailurePreservesPendingReservation(t *testing.T) {
	store := mustCreateBlockStore(t, filepath.Join(t.TempDir(), "store"))
	reopened := mustOpenBlockStore(t, store.rootPath)
	image := reopened.noncanonical.Load()
	mustNoncanonical(t, os.WriteFile(filepath.Join(reopened.blocksDir, "unexpected"), []byte("fault"), 0o600))
	canonicalBefore, err := reopened.CanonicalIndexSnapshot()
	mustNoncanonical(t, err)
	visibleBefore := reopened.visibleIndexBytes()
	row8, row9 := noncanonicalRow{hash: [32]byte{8}, blockBytes: 4, height: noncanonicalUnknownHeight}, noncanonicalRow{hash: [32]byte{9}, blockBytes: 4, height: noncanonicalUnknownHeight}
	row8.setState(noncanonicalBlockArtifact, BlockArtifactValid)
	row9.setState(noncanonicalBlockArtifact, BlockArtifactValid)
	want := noncanonicalAccountingSnapshot{usedBytes: 8, uniqueCount: 2, rows: []noncanonicalRow{row8, row9}}
	wantDigest := noncanonicalTestDigest(want)

	synctest.Test(t, func(t *testing.T) {
		leaf := noncanonicalReservationLeaf{kind: noncanonicalBlockArtifact, bytes: 4, state: BlockArtifactValid}
		firstStarted, releaseFirst := make(chan struct{}), make(chan struct{})
		firstDone := make(chan error, 1)
		go func() {
			firstDone <- reopened.reserveNoncanonicalArtifactWrite([32]byte{8}, []noncanonicalReservationLeaf{leaf}, nil, func(r *noncanonicalReservation) error {
				close(firstStarted)
				<-releaseFirst
				r.created(leaf)
				return nil
			})
		}()
		synctest.Wait()
		<-firstStarted
		if pending := reopened.noncanonicalAccountingSnapshot(); pending.reservedBytes != leaf.bytes {
			t.Fatalf("pending reserved=%d want=%d", pending.reservedBytes, leaf.bytes)
		}

		reloadDone := make(chan error, 1)
		go func() { reloadDone <- reopened.reloadFromDisk() }()
		synctest.Wait()
		reopened.stateMu.Lock()
		transitionActive := reopened.noncanonicalTransitionDone != nil
		pendingActive := reopened.noncanonicalPending[[32]byte{8}] != nil
		reopened.stateMu.Unlock()
		if !transitionActive || !pendingActive {
			t.Fatalf("reload fence=%v pending=%v", transitionActive, pendingActive)
		}

		secondPrepared := make(chan struct{})
		secondDone := make(chan error, 1)
		go func() {
			secondDone <- reopened.reserveNoncanonicalArtifactWrite([32]byte{9}, nil, func() ([]noncanonicalReservationLeaf, error) {
				close(secondPrepared)
				return []noncanonicalReservationLeaf{leaf}, nil
			}, func(r *noncanonicalReservation) error { r.created(leaf); return nil })
		}()
		synctest.Wait()
		select {
		case <-secondPrepared:
			t.Fatal("new reservation bypassed reload transition")
		default:
		}
		select {
		case err := <-reloadDone:
			t.Fatalf("reload bypassed pending reservation: %v", err)
		default:
		}

		close(releaseFirst)
		synctest.Wait()
		mustNoncanonical(t, <-firstDone, <-secondDone)
		if err := <-reloadDone; err == nil || !strings.Contains(err.Error(), "unexpected noncanonical artifact name") {
			t.Fatalf("reload error=%v", err)
		}
		got := reopened.noncanonicalAccountingSnapshot()
		canonicalAfter, err := reopened.CanonicalIndexSnapshot()
		mustNoncanonical(t, err)
		if reopened.noncanonical.Load() != image || got.usedBytes != want.usedBytes || got.reservedBytes != 0 || got.uniqueCount != want.uniqueCount || !slices.Equal(got.rows, want.rows) || reopened.noncanonicalAccountingDigest() != wantDigest || !slices.Equal(canonicalAfter, canonicalBefore) || !bytes.Equal(reopened.visibleIndexBytes(), visibleBefore) {
			t.Fatalf("failed reload state=%+v canonical=%v", got, canonicalAfter)
		}
	})
}
