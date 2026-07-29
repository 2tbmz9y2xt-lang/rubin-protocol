package node

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testReadBound = 8

// TestSafeIOClassBoundConstantsPinFrozenValues pins the three frozen
// cross-client bound values; a red row means the cross-client contract
// number drifted, not a local tuning knob. De-scaled stand-in for the
// removed at-production-bound row of the undo class: that caller shares the
// bounded reader at these hard-wired constants, and its at/over verdicts run
// at small injectable bounds in this file. The chainstate snapshot and index
// marker are deliberately absent — they grow with accumulated state, admit
// no fixed ceiling, and are owned by RUB-1062. The write-if-absent verify
// reads have no constant of their own: they are bounded by the length of the
// content being written (see readVerifyTarget).
func TestSafeIOClassBoundConstantsPinFrozenValues(t *testing.T) {
	if blockFileMaxBytes != 72_000_000 || headerFileMaxBytes != 116 ||
		undoFileMaxBytes != 2_000_000_000 {
		t.Fatalf("class bound constants drifted from the frozen cross-client table")
	}
}

// TestSafeIOGrowCapacityClampsOverflowBeforeFloor pins the guard ORDER: a
// doubling that overflows (or merely exceeds the limit) is clamped to the
// limit, never rewritten to the 512 floor — a floor-first order would return
// a capacity below the buffer's current length and make readCapped panic on
// a 32-bit build. Exercised on the helper so the row runs on 64-bit CI too.
func TestSafeIOGrowCapacityClampsOverflowBeforeFloor(t *testing.T) {
	const maxBytes = int64(1 << 20)
	limit := capHint(maxBytes, maxBytes)
	rows := []struct{ current, want int }{
		{0, 512},                 // tiny start: floor applies
		{4, 512},                 // still below the floor
		{1024, 2048},             // ordinary doubling
		{limit/2 + 1, limit},     // doubling would exceed the limit
		{limit, limit},           // already at the limit
		{math.MaxInt, limit},     // doubling overflows to negative
		{math.MaxInt / 2, limit}, // doubling lands exactly at overflow edge
		{math.MaxInt - 1, limit}, // near-ceiling overflow
	}
	for _, row := range rows {
		if got := growCapacity(row.current, maxBytes); got != row.want {
			t.Fatalf("growCapacity(%d) = %d, want %d", row.current, got, row.want)
		}
		if got := growCapacity(row.current, maxBytes); got < 0 {
			t.Fatalf("growCapacity(%d) returned negative capacity %d", row.current, got)
		}
	}
}

// TestSafeIOStoreSaveBoundRefusesOverBound pins the write/read symmetry
// guard for the undo class (the one guarded write path — block and header
// sizes are already fixed by the wire format) with small synthetic numbers:
// at bound the save proceeds, one byte over refuses with the typed class
// error and a clearly save-side message.
func TestSafeIOStoreSaveBoundRefusesOverBound(t *testing.T) {
	if err := checkStoreSaveBound("undo", testReadBound, testReadBound); err != nil {
		t.Fatalf("undo at bound: %v", err)
	}
	err := checkStoreSaveBound("undo", testReadBound+1, testReadBound)
	if !errors.Is(err, errStoreFileTooLarge) || !strings.Contains(err.Error(), "refusing to save") {
		t.Fatalf("undo over bound: want save-side errStoreFileTooLarge, got %v", err)
	}
}

// TestReadFileBoundDerivationEntrySizes pins the measured per-entry JSON
// byte cost cited by the undo bound derivation in safeio.go, encoding the
// real disk structs exactly as production does (json.MarshalIndent with
// two-space indent). The want is the marginal cost of one additional spent
// entry in its worst spendable shape. A red row means a disk-struct change
// silently shifted the derivation margin: reconcile the safeio.go comment
// and the Rust mirror bound table before re-pinning.
func TestReadFileBoundDerivationEntrySizes(t *testing.T) {
	hex64 := strings.Repeat("ab", 32)
	// CORE_VAULT max covenant_data: 32+1+1+12*32+2+1024*32 = 33_188 raw bytes.
	spent := spentUndoDisk{
		Txid: hex64, Vout: ^uint32(0), Value: ^uint64(0),
		CovenantType: 0x0101, CovenantData: strings.Repeat("cd", 33188),
		CreationHeight: ^uint64(0),
	}
	enc := func(spent []spentUndoDisk) int {
		raw, err := json.MarshalIndent(
			blockUndoDisk{Txs: []txUndoDisk{{Spent: spent}}}, "", "  ")
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		return len(raw)
	}
	if got := enc([]spentUndoDisk{spent, spent}) - enc([]spentUndoDisk{spent}); got != 66707 {
		t.Fatalf("marginal per-entry bytes = %d, want 66707", got)
	}
}

func TestReadFileFromDirRejectsTraversal(t *testing.T) {
	dir := t.TempDir()
	if _, err := readFileFromDir(dir, "../x", testReadBound); err == nil {
		t.Fatalf("expected error for traversal name")
	}
	if _, err := readFileFromDir(dir, "..", testReadBound); err == nil {
		t.Fatalf("expected error for ..")
	}
	if _, err := readFileFromDir(dir, "", testReadBound); err == nil {
		t.Fatalf("expected error for empty name")
	}
}

func TestReadFileFromDirReadsFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ok.bin")
	if err := os.WriteFile(path, []byte("hi"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	b, err := readFileFromDir(dir, "ok.bin", testReadBound)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(b) != "hi" {
		t.Fatalf("unexpected bytes: %q", string(b))
	}
}

func TestReadFileFromDirEnforcesBound(t *testing.T) {
	dir := t.TempDir()
	rows := []struct {
		name    string
		content []byte
		wantBig bool
	}{
		{"empty_ok", nil, false},
		{"at_bound_ok", bytes.Repeat([]byte{0xa5}, testReadBound), false},
		{"over_bound_refused", bytes.Repeat([]byte{0xa5}, testReadBound+1), true},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			if err := os.WriteFile(filepath.Join(dir, row.name), row.content, 0o600); err != nil {
				t.Fatalf("write: %v", err)
			}
			got, err := readFileFromDir(dir, row.name, testReadBound)
			if row.wantBig {
				if !errors.Is(err, errStoreFileTooLarge) {
					t.Fatalf("want errStoreFileTooLarge, got %v", err)
				}
				return
			}
			if err != nil || !bytes.Equal(got, row.content) {
				t.Fatalf("want %d bytes back, got len=%d err=%v", len(row.content), len(got), err)
			}
		})
	}
}

// lyingStatFile wraps a real file but reports a fixed Stat size, standing in
// for a file whose size changes between Stat and read (or a size-lying
// special file). reads counts content reads; maxRead records the largest
// read window offered (== the buffer's free capacity, exposing the growth
// pattern); statErr/readErr, when set, inject raw failures for the
// error-propagation rows.
type lyingStatFile struct {
	fs.File
	statErr error
	readErr error
	size    int64
	reads   int
	maxRead int
}

type lyingSizeInfo struct {
	fs.FileInfo
	size int64
}

func (l lyingSizeInfo) Size() int64 { return l.size }

func (l *lyingStatFile) Stat() (fs.FileInfo, error) {
	if l.statErr != nil {
		return nil, l.statErr
	}
	info, err := l.File.Stat()
	if err != nil {
		return nil, err
	}
	return lyingSizeInfo{info, l.size}, nil
}

func (l *lyingStatFile) Read(p []byte) (int, error) {
	l.reads++
	if len(p) > l.maxRead {
		l.maxRead = len(p)
	}
	if l.readErr != nil {
		return 0, l.readErr
	}
	return l.File.Read(p)
}

// TestSafeIOReadCappedGrowsGeometricallyOnStatLyingLow pins the Codex P1
// fix: a stat-lying-low race (stat says 2, the file holds 2000, bound 1500)
// is still refused at exactly the same boundary, and the buffer grows
// geometrically — the largest read window stays at one doubling step (1024
// here), never the old single maxBytes+1-sized jump (which would offer a
// 1498-byte window from the 3-byte presize).
func TestSafeIOReadCappedGrowsGeometricallyOnStatLyingLow(t *testing.T) {
	path := filepath.Join(t.TempDir(), "f.bin")
	if err := os.WriteFile(path, bytes.Repeat([]byte{0xa5}, 2000), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()
	lf := &lyingStatFile{File: f, size: 2}
	if _, err := readAllCapped(lf, "f.bin", 1500); !errors.Is(err, errStoreFileTooLarge) {
		t.Fatalf("want errStoreFileTooLarge, got %v", err)
	}
	if lf.maxRead > 1024 {
		t.Fatalf("read window %d exceeds geometric growth; bound-sized allocation spike", lf.maxRead)
	}
}

func TestSafeIOReadAllCappedPinsStatReadRace(t *testing.T) {
	path := filepath.Join(t.TempDir(), "f.bin")
	if err := os.WriteFile(path, []byte("0123456789"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	open := func(size int64) *lyingStatFile {
		t.Helper()
		f, err := os.Open(path)
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		t.Cleanup(func() { _ = f.Close() })
		return &lyingStatFile{File: f, size: size}
	}

	// An over-bound stat size is refused WITHOUT reading any content.
	overStat := open(6)
	if _, err := readAllCapped(overStat, "f.bin", 5); !errors.Is(err, errStoreFileTooLarge) {
		t.Fatalf("over-bound stat: want errStoreFileTooLarge, got %v", err)
	}
	if overStat.reads != 0 {
		t.Fatalf("content was read despite over-bound stat: %d reads", overStat.reads)
	}

	// A stat that lies LOW (file grew after Stat): the maxBytes+1 limiter
	// still refuses content past the bound instead of truncating it.
	underStat := open(2)
	if _, err := readAllCapped(underStat, "f.bin", 5); !errors.Is(err, errStoreFileTooLarge) {
		t.Fatalf("lying stat: want errStoreFileTooLarge, got %v", err)
	}
}

// createSparseFile creates a hole-only file of the nominal size (no data
// blocks written) and skips the test if the filesystem does not report the
// nominal size back.
func createSparseFile(t *testing.T, path string, size int64) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("create sparse: %v", err)
	}
	terr := f.Truncate(size)
	cerr := f.Close()
	if terr != nil || cerr != nil {
		t.Fatalf("sparse truncate/close: %v / %v", terr, cerr)
	}
	if info, err := os.Stat(path); err != nil || info.Size() != size {
		t.Skipf("sparse size not honored (err=%v)", err)
	}
}

func TestReadFileFromDirBlockClassProductionBound(t *testing.T) {
	dir := t.TempDir()
	createSparseFile(t, filepath.Join(dir, "at.bin"), blockFileMaxBytes)
	got, err := readFileFromDir(dir, "at.bin", blockFileMaxBytes)
	if err != nil || int64(len(got)) != int64(blockFileMaxBytes) {
		t.Fatalf("at-production-bound: len=%d err=%v", len(got), err)
	}
	createSparseFile(t, filepath.Join(dir, "over.bin"), blockFileMaxBytes+1)
	if _, err := readFileFromDir(dir, "over.bin", blockFileMaxBytes); !errors.Is(err, errStoreFileTooLarge) {
		t.Fatalf("over-production-bound: want errStoreFileTooLarge, got %v", err)
	}
}

// Non-regular targets keep their pre-existing OS error classes — never the
// size refusal: a directory read fails with the raw EISDIR-class error (its
// stat size ~64B passes any production bound) and a dangling symlink stays
// fs.ErrNotExist (absent-file class). Rust twin:
// `read_file_from_dir_non_regular_targets_keep_os_error_classes`.
func TestReadFileFromDirNonRegularTargetsKeepOSErrorClasses(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if _, err := readFileFromDir(dir, "sub", blockFileMaxBytes); err == nil ||
		errors.Is(err, errStoreFileTooLarge) || errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("directory: want raw read error, got %v", err)
	}
	if err := os.Symlink(filepath.Join(dir, "absent"), filepath.Join(dir, "dangling")); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	if _, err := readFileFromDir(dir, "dangling", blockFileMaxBytes); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("dangling symlink: want fs.ErrNotExist, got %v", err)
	}
}

// TestSafeIOReadAllCappedPropagatesRawErrors pins that Stat and mid-read
// failures surface as the raw error — never coerced into
// errStoreFileTooLarge, never swallowed.
func TestSafeIOReadAllCappedPropagatesRawErrors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "f.bin")
	if err := os.WriteFile(path, []byte("0123456789"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	probeErr := errors.New("probe failure")
	rows := []struct {
		name string
		mut  func(*lyingStatFile)
	}{
		{"stat_error", func(f *lyingStatFile) { f.statErr = probeErr }},
		{"read_error", func(f *lyingStatFile) { f.readErr = probeErr }},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			f, err := os.Open(path)
			if err != nil {
				t.Fatalf("open: %v", err)
			}
			defer f.Close()
			lf := &lyingStatFile{File: f, size: 4}
			row.mut(lf)
			_, err = readAllCapped(lf, "f.bin", 8)
			if !errors.Is(err, probeErr) || errors.Is(err, errStoreFileTooLarge) {
				t.Fatalf("want raw probe error, got %v", err)
			}
		})
	}
}
