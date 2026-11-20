package exclusionjournal

import (
	"syscall"

	"golang.org/x/sys/unix"
)

func sourceSpaceUnit(stat *syscall.Statfs_t) uint64 {
	return uint64(stat.Bsize)
}

func chmodSourceInit(parent int) error {
	return unix.Fchmodat(parent, sourceInitDirectory, 0o700, unix.AT_SYMLINK_NOFOLLOW)
}

func renameSourceExclusive(parent int, from, to string) error {
	return unix.RenameatxNp(parent, from, parent, to, unix.RENAME_EXCL)
}
