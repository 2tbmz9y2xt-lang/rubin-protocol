package node

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

const testReadBound = 8

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
// special file). reads counts content reads; statErr/readErr, when set,
// inject raw failures for the error-propagation rows.
type lyingStatFile struct {
	fs.File
	statErr error
	readErr error
	size    int64
	reads   int
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
	if l.readErr != nil {
		return 0, l.readErr
	}
	return l.File.Read(p)
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
