//go:build darwin || linux

package node

import (
	"errors"
	"os"
	"syscall"
)

func requireNoncanonicalReconstructionHost() error { return nil }

func openNoncanonicalFile(path string, flags int) (*os.File, error) {
	for {
		fd, err := syscall.Open(path, flags, 0)
		if errors.Is(err, syscall.EINTR) {
			continue
		}
		if err != nil {
			return nil, &os.PathError{Op: "open", Path: path, Err: err}
		}
		if fd < 0 {
			return nil, &os.PathError{Op: "open", Path: path, Err: syscall.EINVAL}
		}
		return os.NewFile(uintptr(fd), path), nil
	}
}

func openNoncanonicalArtifactFile(path string) (*os.File, error) {
	return openNoncanonicalFile(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK)
}

func openNoncanonicalDirectory(path string) (*os.File, error) {
	return openNoncanonicalFile(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NONBLOCK|syscall.O_DIRECTORY)
}
