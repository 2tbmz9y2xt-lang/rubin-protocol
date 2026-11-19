package exclusionjournal

import "syscall"

// sourceSpaceUnit returns the native unit of the available-block count.
func sourceSpaceUnit(stat *syscall.Statfs_t) uint64 {
	return uint64(stat.Bsize)
}
