//go:build unix

package main

import (
	"errors"
	"os"
	"syscall"
)

func openRegularFromKeyFile(path string) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, errors.New("from-key-file must be a regular file")
		}
		return nil, errors.New("read from-key-file failed")
	}
	f := os.NewFile(uintptr(fd), path)
	if f == nil {
		_ = syscall.Close(fd)
		return nil, errors.New("read from-key-file failed")
	}
	openedInfo, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, errors.New("read from-key-file failed")
	}
	if !openedInfo.Mode().IsRegular() {
		_ = f.Close()
		return nil, errors.New("from-key-file must be a regular file")
	}
	return f, nil
}
