//go:build darwin || linux

package node

import (
	"errors"
	"syscall"
)

// atomicUnlink removes one exact directory entry with unlink(2). It never
// follows the final component and never falls back to rmdir, so a scratch
// directory is rejected rather than removed.
func atomicUnlink(path string) error {
	err := syscall.Unlink(path)
	if errors.Is(err, syscall.ENOENT) {
		return nil
	}
	return err
}
