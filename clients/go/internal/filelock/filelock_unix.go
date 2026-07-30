//go:build darwin || linux

package filelock

import (
	"errors"
	"fmt"
	"syscall"
)

// Acquire opens path once and holds an exclusive advisory lock on its exact
// regular-file inode. Callers own a non-nil Handle until Release.
func Acquire(path string) (*Handle, Result, error) {
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0o600)
	if err != nil {
		return nil, ResultInvalidOrUnopenable, err
	}
	if err := validate(fd); err != nil {
		_ = syscall.Close(fd)
		return nil, ResultInvalidOrUnopenable, err
	}
	if err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = syscall.Close(fd)
		if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, ResultContended, err
		}
		return nil, ResultInvalidOrUnopenable, err
	}
	return &Handle{fd: fd}, "", nil
}

func validate(fd int) error {
	var stat syscall.Stat_t
	if err := syscall.Fstat(fd, &stat); err != nil {
		return err
	}
	if stat.Mode&syscall.S_IFMT != syscall.S_IFREG {
		return errors.New("datadir lock must be a regular file")
	}
	if stat.Size != 0 {
		return fmt.Errorf("datadir lock must be empty, got size %d", stat.Size)
	}
	if stat.Nlink != 1 {
		return fmt.Errorf("datadir lock must have one link, got %d", stat.Nlink)
	}
	return nil
}

func release(fd int) error {
	return syscall.Close(fd)
}
