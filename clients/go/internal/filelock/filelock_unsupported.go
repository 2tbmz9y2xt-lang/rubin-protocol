//go:build !darwin && !linux

package filelock

import "errors"

// Acquire is unavailable on hosts without the required final-component-safe
// open and advisory-lock syscalls.
func Acquire(_ string) (*Handle, Result, error) {
	return nil, ResultUnsupportedHost, errors.New("datadir writer lock is unsupported on this host")
}

// AcquireExisting is unavailable on hosts without the required syscalls.
func AcquireExisting(_ string) (*Handle, Result, error) {
	return nil, ResultUnsupportedHost, errors.New("datadir writer lock is unsupported on this host")
}

func release(_ int) error {
	return nil
}
