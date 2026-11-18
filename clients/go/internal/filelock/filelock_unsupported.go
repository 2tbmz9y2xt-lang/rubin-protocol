//go:build !darwin && !linux

package filelock

import (
	"errors"
	"os"
)

// Acquire is unavailable on hosts without the required final-component-safe
// open and advisory-lock syscalls.
func Acquire(_ string) (*Handle, Result, error) {
	return nil, ResultUnsupportedHost, errors.New("datadir writer lock is unsupported on this host")
}

// AcquireDirectory is unavailable on hosts without the required syscalls.
func AcquireDirectory(_ string) (*Handle, Result, error) {
	return nil, ResultUnsupportedHost, errors.New("datadir writer lock is unsupported on this host")
}

// IdentityV1 identifies an inode on its device.
type IdentityV1 [2]uint64

// FileIdentityV1 returns no identity when native stat is unavailable.
func FileIdentityV1(_ os.FileInfo) IdentityV1 { return IdentityV1{} }

// DirectoryIdentityV1 refuses on hosts without native directory identity.
func (*Handle) DirectoryIdentityV1() (IdentityV1, error) {
	return IdentityV1{}, errors.New("datadir writer lock is unsupported on this host")
}

func release(_ int) error {
	return nil
}
