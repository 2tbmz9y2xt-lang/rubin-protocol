package node

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// writeFileIfAbsent writes content to path only if the destination is
// absent (idempotent replay: a subsequent call with matching bytes is a
// silent no-op). Hardened against the TOCTOU race audited as E.3: the
// previous implementation read then wrote, which could silently
// overwrite a file that appeared between the two syscalls. The new
// implementation writes content to a per-call-unique temp path, then
// uses os.Link for atomic create-if-absent at the syscall layer. On
// EEXIST we read the current destination and preserve the idempotent-
// same-content contract; on content mismatch we surface an explicit
// error — we never silently overwrite.
//
// Mirrors the Rust io_utils::write_file_exclusive helper's hard_link
// flow for cross-client storage parity.
//
// Threat model:
//
//	concurrent actors:  Two writers race on os.Link(tmp, path); exactly
//	                    one link succeeds. The loser sees os.ErrExist,
//	                    reads the winner's content, and returns nil if
//	                    content matches (idempotent replay) or an error
//	                    if it differs (never overwrite). Per-call
//	                    tempPathFor(path, pid, nextTempSeq()) gives
//	                    distinct temp paths so in-process goroutines
//	                    never collide.
//	process crash:      Crash between os.Link and os.Remove(tmp) leaves
//	                    a stale tmp hard-linked to the destination
//	                    inode. That is safe: writeAndSyncTemp uses
//	                    O_CREATE|O_EXCL (no O_TRUNC), so a later call
//	                    hitting the same tmp path gets os.ErrExist from
//	                    allocateAndWriteTemp and retries with a fresh
//	                    seq (16-retry budget). Startup reconcile (E.2)
//	                    sweeps orphan .tmp.* siblings. Crash before
//	                    syncDir leaves the dirent in page cache; the
//	                    fast-path on retry re-runs syncDir and
//	                    propagates its error so durability is surfaced.
//	cross-platform:     Unix (Linux, macOS): os.Link, O_EXCL, dir Sync
//	                    all semantically honored. Windows: Sync on
//	                    directories is a no-op in stdlib; Rubin does
//	                    not ship Windows as a production target.
//	                    Test surfaces that rely on os.Geteuid()/chmod
//	                    for permission-denied paths are gated behind
//	                    //go:build unix.
//	retry / exhaustion: allocateAndWriteTemp retries up to
//	                    maxTempAllocRetries (16) on os.ErrExist with a
//	                    fresh nextTempSeq. Fatal I/O surfaces
//	                    immediately. Exhaustion surfaces as an error
//	                    mentioning the destination path.
//	inode / fs-layer:   os.Link is refcount-safe: destination and tmp
//	                    share the inode; unlinking tmp drops the name
//	                    without affecting data visible through path.
//	                    O_TRUNC on a shared-inode path is intentionally
//	                    avoided everywhere in the helper stack; see
//	                    writeAndSyncTemp for the explicit O_EXCL
//	                    contract.
//	durability:         writeAndSyncTemp fsync's the temp's bytes and
//	                    inode metadata before returning. os.Link then
//	                    exposes the inode under `path`. syncDir on the
//	                    parent flushes the directory entry so the
//	                    rename/link is itself durable. Both the Ok and
//	                    EEXIST-retry branches PROPAGATE the final
//	                    syncDir error — the previous `_ = syncDir(...)`
//	                    double-swallowed EIO through syncDir's own
//	                    best-effort wrapper (Copilot P1 wave-7 on
//	                    PR #1220).
//
// writeFileIfAbsent writes content to path only if the file does not already
// exist with matching bytes. It returns an error when an existing file has
// different content (never overwrites).
//
// Fast path: destination already exists. Read once and verify match
// before attempting any writes. Same behavior as the Rust helper
// via `write_file_exclusive` + EEXIST branch, but short-circuited
// here to avoid a useless temp write when the file is already
// present with the right bytes (dominant case during idempotent
// replay on sync-engine restart).
//
// Copilot P1 on PR #1220: a previous call may have successfully
// created the destination but returned an error from the final
// syncDir step. If the caller retries, we land in this fast-path
// and would silently report nil without ever making the directory
// entry durable. Re-run syncDir on the idempotent match branch and
// PROPAGATE its result — syncDir already applies the intended
// permission policy internally (execute-only/hardened parents are
// treated as nil return), so propagating does NOT break the
// idempotent-replay-on-hardened-dir contract; it only surfaces
// real durability failures (EIO / ENOENT) that would otherwise be
// silent.
//
// Copilot P1 wave-7 on PR #1220: `_ = syncDir(...)` double-
// swallowed errors — syncDir is already best-effort, so the outer
// `_ = ...` discarded the exact failures that MUST reach the
// caller. Propagate via `return` instead.
func writeFileIfAbsent(path string, content []byte) error {
	existing, err := readFileByPathFn(path)
	if err == nil {
		return syncMatchingExistingFile(path, content, existing)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return writeFileViaTempLink(path, content)
}

// writeFileViaTempLink writes content to a temp file and atomically links it to path.
func writeFileViaTempLink(path string, content []byte) error {
	tmpPath, err := allocateAndWriteTemp(path, content, 0o600)
	if err != nil {
		return err
	}
	linkErr := os.Link(tmpPath, path)
	_ = os.Remove(tmpPath)
	if linkErr != nil {
		if errors.Is(linkErr, os.ErrExist) {
			return handleLinkEEXIST(path, content)
		}
		return fmt.Errorf("link %s -> %s: %w", tmpPath, path, linkErr)
	}
	return syncDir(filepath.Dir(path))
}

func handleLinkEEXIST(path string, content []byte) error {
	existing, err := readFileByPathFn(path)
	if err != nil {
		return fmt.Errorf("read existing after link EEXIST %s: %w", path, err)
	}
	return syncMatchingExistingFile(path, content, existing)
}

func syncMatchingExistingFile(path string, content []byte, existing []byte) error {
	if !bytes.Equal(existing, content) {
		return fmt.Errorf("file already exists with different content: %s", path)
	}
	return syncDir(filepath.Dir(path))
}
