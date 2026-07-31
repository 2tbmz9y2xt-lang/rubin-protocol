//go:build !darwin && !linux

package node

import "errors"

func atomicUnlink(_ string) error {
	return errors.New("atomic scratch unlink is unsupported on this host")
}
