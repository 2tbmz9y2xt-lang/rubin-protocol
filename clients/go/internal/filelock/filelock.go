// Package filelock holds a process-scoped advisory lock on one regular file.
package filelock

// Result classifies a failed acquisition without exposing host-specific errno
// values to callers.
type Result string

const (
	ResultContended           Result = "contended"
	ResultInvalidOrUnopenable Result = "invalid_or_unopenable"
	ResultUnsupportedHost     Result = "unsupported_host"
)

// Handle owns an acquired lock until Release.
type Handle struct {
	fd int
}

// Release relinquishes the held lock. Releasing an already released handle is
// a no-op.
func (h *Handle) Release() error {
	if h == nil || h.fd < 0 {
		return nil
	}
	fd := h.fd
	h.fd = -1
	return release(fd)
}
