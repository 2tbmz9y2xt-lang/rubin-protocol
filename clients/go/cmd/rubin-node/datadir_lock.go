package main

import (
	"fmt"
	"io"
	"path/filepath"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/filelock"
)

func acquireDatadirLock(normalizedDataDir string, stderr io.Writer) (*filelock.Handle, int) {
	lockPath := filepath.Join(normalizedDataDir, ".rubin.lock")
	lock, result, err := filelock.Acquire(lockPath)
	if err == nil {
		return lock, 0
	}
	if result == filelock.ResultContended {
		_, _ = fmt.Fprintf(stderr, "datadir is already in use by another rubin-node: %s\n", normalizedDataDir)
		return nil, 2
	}
	_, _ = fmt.Fprintf(stderr, "cannot open datadir lock %s: %v\n", lockPath, err)
	return nil, 2
}
