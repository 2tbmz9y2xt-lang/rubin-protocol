package exclusionjournal

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/filelock"
)

func TestReadReleaseFileBounds(t *testing.T) {
	for _, tc := range []struct {
		name string
		size int
		want error
	}{
		{"empty", 0, ErrIntegrityV1},
		{"one-byte", 1, nil},
		{"maximum", releaseMax, nil},
		{"one-over-maximum", releaseMax + 1, ErrIntegrityV1},
		{"overlong", 2 * releaseMax, ErrIntegrityV1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), releaseFile)
			record := bytes.Repeat([]byte{0x5a}, tc.size)
			info := writeSourceEntry(t, path, record)
			f, err := os.Open(path)
			sourceMust(t, err)
			defer f.Close()

			got, id, err := readReleaseFile(f)
			sourceWantError(t, err, tc.want, "read marker file")
			if tc.want != nil {
				if got != nil || id != (filelock.IdentityV1{}) {
					t.Fatal("rejected marker returned data or an inode identity")
				}
				return
			}
			if !bytes.Equal(got, record) || id != filelock.FileIdentityV1(info) {
				t.Fatal("marker read did not return the file's bytes and inode identity")
			}
		})
	}
}

func TestReadReleaseRequiresPublishedMarker(t *testing.T) {
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	sourceMust(t, err)
	defer root.Close()
	pin, err := root.Open(".")
	sourceMust(t, err)
	defer pin.Close()
	r := &sourceRoot{Root: root, pin: pin}

	// Use identical bytes in distinct inodes so either a scratch fallback or
	// a scratch identity lookup is detectable.
	record := []byte("release intent")
	writeSourceEntry(t, filepath.Join(dir, releaseScratch), record)
	if got, id, err := readRelease(r); !errors.Is(err, os.ErrNotExist) || got != nil || id != (filelock.IdentityV1{}) {
		t.Fatalf("read with only scratch present returned %q, %v, %v; want no marker", got, id, err)
	}

	marker := writeSourceEntry(t, filepath.Join(dir, releaseFile), record)
	got, id, err := readRelease(r)
	sourceMust(t, err)
	if !bytes.Equal(got, record) || id != filelock.FileIdentityV1(marker) {
		t.Fatal("read did not bind the record to the published marker inode")
	}
}

func TestSourceReleaseRecoveryPreservesIndependentCapture(t *testing.T) {
	sourceModes(t, []string{"intent-sync", "unlink", "marker-clear"}, func(t *testing.T, fault string) {
		m, parts, size, limits := sourceSizedBundle(t)
		limits.Files, limits.Bytes = 2, 2*size
		s, o, paths, target := sourcePreparedScene(t, limits, m, parts)
		survivor := sourceForeign(m)
		other := sourcePrepare(t, o, survivor, parts)
		keepSurvivor := sourcePreservedEntry(t, filepath.Join(paths.root, other.name))

		sourceReleaseWithFault(t, o, target, fault, syscall.EIO)
		o = sourceOpen(t, sourceReopenStore(t, s, o.dir), sourceID(), limits, nil)
		sourceRead(t, o, survivor, parts)
		assertSourceReleaseCharge(t, o, survivor, 2, 2*size)

		sourceReleaseResult(t, o, nil, true, nil)
		sourceAbsent(t, paths.root, target.name, releaseDetached, releaseFile, releaseScratch)
		keepSurvivor()
		sourceRead(t, o, survivor, parts)
		assertSourceReleaseCharge(t, o, survivor, 1, size)
		sourcePrepareAndRead(t, o, sourceForeign(survivor), parts)
	})
}
