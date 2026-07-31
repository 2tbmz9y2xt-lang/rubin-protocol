package node

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// writeFileIfAbsent keeps exact matches lock-free and sends only NotFound
// through the fixed-scratch append-only write lane.
func writeFileIfAbsent(path string, content []byte) error {
	if err := validateAtomicWriteDestination(path, atomicWriteCreateIfAbsent); err != nil {
		return err
	}
	existing, err := readVerifyTarget(path, content)
	if err == nil {
		if !bytes.Equal(existing, content) {
			return newAtomicWriteError(
				atomicWriteBeforeNamespaceCommit,
				path,
				atomicWriteCreateIfAbsent,
				errExistingContentDiffers(path),
			)
		}
		return syncMatchingExistingFile(path)
	}
	if errors.Is(err, errStoreFileTooLarge) {
		return newAtomicWriteError(
			atomicWriteBeforeNamespaceCommit,
			path,
			atomicWriteCreateIfAbsent,
			errExistingContentDiffers(path),
		)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return newAtomicWriteError(atomicWriteBeforeNamespaceCommit, path, atomicWriteCreateIfAbsent, err)
	}
	return writeFileViaTempLink(path, content)
}

// readVerifyTarget bounds reads by content length; different sizes reject.
func readVerifyTarget(path string, content []byte) ([]byte, error) {
	return readFileByPathFn(path, int64(len(content)))
}

func errExistingContentDiffers(path string) error {
	return fmt.Errorf("file already exists with different content: %s", path)
}

func writeFileViaTempLink(path string, content []byte) error {
	return writeAtomicFile(path, content, atomicWriteCreateIfAbsent, func() error {
		return handleLinkEEXIST(path, content)
	})
}

// handleLinkEEXIST decides the destination only; the scratch lane retains
// decision, scratch-unlink, then parent-sync precedence.
func handleLinkEEXIST(path string, content []byte) error {
	existing, err := readVerifyTarget(path, content)
	if errors.Is(err, errStoreFileTooLarge) {
		return errExistingContentDiffers(path)
	}
	if err != nil {
		return fmt.Errorf("read existing after link EEXIST %s: %w", path, err)
	}
	if !bytes.Equal(existing, content) {
		return errExistingContentDiffers(path)
	}
	return nil
}

func syncMatchingExistingFile(path string) error {
	if err := atomicWriteIO.syncParent(filepath.Dir(path)); err != nil {
		return newAtomicWriteError(
			atomicWriteAfterNamespaceCommit,
			path,
			atomicWriteCreateIfAbsent,
			err,
		)
	}
	return nil
}
