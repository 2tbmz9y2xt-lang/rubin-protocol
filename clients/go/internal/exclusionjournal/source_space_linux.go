package exclusionjournal

import (
	"os"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"
)

func sourceSpaceUnit(stat *syscall.Statfs_t) uint64 {
	return uint64(max(stat.Frsize, 0))
}

// chmodSourceInit sets the mode on a pinned directory even when umask removed read access.
func chmodSourceInit(parent int) error {
	f, err := openSourceAt(parent, sourceInitDirectory, unix.O_PATH|unix.O_DIRECTORY)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := unix.Fchmodat(int(f.Fd()), "", 0o700, unix.AT_EMPTY_PATH); err != unix.EOPNOTSUPP {
		return err
	}
	return os.Chmod("/proc/self/fd/"+strconv.FormatUint(uint64(f.Fd()), 10), 0o700)
}

func renameSourceExclusive(parent int, from, to string) error {
	return unix.Renameat2(parent, from, parent, to, unix.RENAME_NOREPLACE)
}
