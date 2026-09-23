package node

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

var atomicWriteProductionIO = atomicWriteIO

type scratchSyncOverride struct {
	atomicWriteScratchFile
	sync func() error
}

func (f scratchSyncOverride) Sync() error { return f.sync() }

// Darwin File.Sync is F_FULLFSYNC; only TestAtomicWriteRealDurableSyncOnDarwin keeps the real syncs.
func init() {
	open := atomicWriteIO.openScratch
	atomicWriteIO.syncParent = func(string) error { return nil }
	atomicWriteIO.openScratch = func(path string, flag int, mode os.FileMode) (atomicWriteScratchFile, error) {
		file, err := open(path, flag, mode)
		if err != nil {
			return file, err
		}
		return scratchSyncOverride{file, func() error { return nil }}, nil
	}
}

func TestAtomicWriteRealDurableSyncOnDarwin(t *testing.T) {
	var fileSyncs, parentSyncs []error
	var scratchIsOSFile bool
	withAtomicWriteOps(t, func(ops *atomicWriteOps) {
		*ops = atomicWriteProductionIO
		ops.openScratch = func(path string, flag int, mode os.FileMode) (atomicWriteScratchFile, error) {
			file, err := atomicWriteProductionIO.openScratch(path, flag, mode)
			if err != nil {
				return file, err
			}
			_, scratchIsOSFile = file.(*os.File)
			return scratchSyncOverride{file, func() error {
				err := file.Sync()
				fileSyncs = append(fileSyncs, err)
				return err
			}}, nil
		}
		ops.syncParent = func(dir string) error {
			err := atomicWriteProductionIO.syncParent(dir)
			parentSyncs = append(parentSyncs, err)
			return err
		}
	})
	path, data := filepath.Join(t.TempDir(), "state.bin"), []byte("durable")
	if err := writeFileAtomic(path, data, 0o600); err != nil {
		t.Fatalf("writeFileAtomic: %v", err)
	}
	if got, err := os.ReadFile(path); err != nil || !bytes.Equal(got, data) {
		t.Fatalf("read back %q, %v; want %q", got, err, data)
	}
	if !scratchIsOSFile {
		t.Fatal("scratch file is not *os.File: the stubbed open ran")
	}
	if len(fileSyncs) == 0 || len(parentSyncs) == 0 || errors.Join(append(fileSyncs, parentSyncs...)...) != nil {
		t.Fatalf("file syncs %v, parent syncs %v; want at least one each, all nil", fileSyncs, parentSyncs)
	}
}
