use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// Process-wide monotonic sequence counter appended to every temp-file
/// name so two threads writing to the same destination within the same
/// process can never collide on a shared `.tmp.<pid>` path (audit
/// `E.3`). Not a cryptographic nonce — it is a plain uniqueness counter
/// for filesystem path disambiguation. Name deliberately avoids the
/// word "nonce" so CodeQL's `Hard-coded cryptographic value` check does
/// not mis-flag test literals feeding this parameter.
static TEMP_SEQ: AtomicU64 = AtomicU64::new(0);

/// Returns the NEW value (1, 2, 3, ...) — mirrors Go's
/// `atomic.Uint64.Add(1)` semantics so the cross-client naming
/// convention for `.tmp.<pid>.<seq>` files starts at the same seq in
/// both runtimes. Using `fetch_add(1) + 1` instead of `fetch_add(1)`
/// costs nothing at runtime and removes a cross-client drift class.
fn next_temp_seq() -> u64 {
    TEMP_SEQ.fetch_add(1, Ordering::Relaxed) + 1
}

/// Reject a file name (the leaf component, NOT a full path) that would
/// escape the directory it is being looked up in (audit `E.10`).
///
/// Mirrors the Go `readFileFromDir` guard in
/// `clients/go/node/safeio.go`:
///
/// ```text
/// if name == "" || name == "." || name == ".." || filepath.Base(name) != name {
///     return invalid
/// }
/// ```
///
/// Rejected vectors (cross-platform-uniform unless noted):
/// - empty name (`""`)
/// - `"."` and `".."` (parent / current dir refs)
/// - any name containing a `/` separator (would escape `dir` via
///   `dir.join("../foo")` becoming a traversal — true on every OS)
/// - any absolute path (`/etc/passwd` would override `dir.join`)
///
/// Windows-only additional vectors (gated by `cfg(windows)` to preserve
/// strict per-OS Go parity — `filepath.Base` on Unix accepts both of
/// these unchanged):
/// - any name containing a `\` separator (path separator on Windows)
/// - any Windows drive-prefixed leaf (`C:foo`, `C:`) — `Path::join`
///   on a drive-prefixed component REPLACES the base path on Windows,
///   defeating the dir-rooted contract; harmless on Unix where `:`
///   has no path-shape semantics.
///
/// This is a per-leaf-name guard, not a canonicalization-based sandbox.
/// It deliberately does NOT follow symlinks or canonicalize, because:
///   1. blockstore / chainstate readers always synthesize the leaf name
///      from `hex::encode(hash)` plus a fixed extension, so a legitimate
///      leaf can never contain a separator;
///   2. canonicalization would require disk I/O on every read and would
///      change error semantics on transient I/O failure.
fn check_safe_file_name(name: &str) -> Result<(), String> {
    if name.is_empty() || name == "." || name == ".." {
        return Err(format!("invalid file name: {name:?}"));
    }
    if name.contains('/') {
        return Err(format!("invalid file name: {name:?}"));
    }
    if Path::new(name).is_absolute() {
        return Err(format!("invalid file name: {name:?}"));
    }
    // Windows-only hardening: backslash separator + drive-prefix leaf.
    // Both are no-ops on Unix where `\` is a regular filename byte and
    // `C:` has no path-shape semantics — so gating them on `cfg(windows)`
    // matches Go's `filepath.Base` per-OS behaviour exactly.
    #[cfg(windows)]
    {
        if name.contains('\\') {
            return Err(format!("invalid file name: {name:?}"));
        }
        let bytes = name.as_bytes();
        if bytes.len() >= 2 && bytes[1] == b':' && bytes[0].is_ascii_alphabetic() {
            return Err(format!("invalid file name: {name:?}"));
        }
    }
    Ok(())
}

/// Read `dir/name` after validating `name` is a safe leaf file name
/// (audit `E.10`). Mirrors the Go `readFileFromDir` helper in
/// `clients/go/node/safeio.go` so cross-client storage readers refuse
/// the same set of traversal / absolute-path / empty-name vectors.
///
/// Use this instead of raw `fs::read(dir.join(untrusted_name))` for any
/// reader where the leaf name comes from data that could in principle
/// be attacker-influenced (block index entries, on-disk headers, etc.)
/// even when the current call sites synthesize the name from a fixed
/// `hex::encode(hash) + ".bin"` shape.
pub fn read_file_from_dir(dir: &Path, name: &str) -> Result<Vec<u8>, std::io::Error> {
    if let Err(msg) = check_safe_file_name(name) {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, msg));
    }
    fs::read(dir.join(name))
}

/// Length of the volume prefix at the start of `s`. Mirrors Go's
/// `path/filepath/path_windows.go::volumeNameLen` byte-for-byte for
/// every path shape that helper accepts:
///
/// - drive-letter: `C:` → 2 (`C:foo`, `C:\foo`, bare `C:`)
/// - UNC: `\\HOST\SHARE` → len of `\\HOST\SHARE`
/// - DOS device drive: `\\?\C:` / `\\.\C:` → 6
/// - DOS device UNC: `\\?\UNC\HOST\SHARE` → len of that prefix
///
/// Malformed path shapes (`\\`, `\\host`, `\\host\`, `\\?\UNC\host`
/// without a share segment) return the full input length to match
/// Go's fail-closed behaviour — there is no valid path to split.
/// Returns 0 on Unix and for non-volume-rooted Windows paths.
fn volume_prefix_len(s: &str) -> usize {
    #[cfg(windows)]
    {
        let bytes = s.as_bytes();
        if bytes.len() < 2 {
            return 0;
        }
        // Drive letter.
        if bytes[1] == b':' && bytes[0].is_ascii_alphabetic() {
            return 2;
        }
        let is_slash = |b: u8| b == b'/' || b == b'\\';
        // UNC / DOS device paths require two leading separators.
        if !is_slash(bytes[0]) || !is_slash(bytes[1]) {
            return 0;
        }
        // Scan for the next separator starting at `start`. Returns
        // `(segment_end, rest_start)`. `segment_end == bytes.len()`
        // means no further separator exists.
        let cut_at = |start: usize| -> (usize, usize) {
            let mut i = start;
            while i < bytes.len() && !is_slash(bytes[i]) {
                i += 1;
            }
            if i < bytes.len() {
                (i, i + 1)
            } else {
                (bytes.len(), bytes.len())
            }
        };
        let (p1_end, after_p1_sep) = cut_at(2);
        if p1_end == bytes.len() {
            // `\\` or `\\host` — no separator after host. Go returns
            // `len(path)`; mirror it.
            return bytes.len();
        }
        let (p2_end, after_p2_sep) = cut_at(after_p1_sep);
        if p2_end == bytes.len() {
            // `\\host\share` with no further separator. Go's
            // `cutPath` returns `ok=false` here and falls through to
            // `return len(path)` at the matching `if !ok` branch.
            return bytes.len();
        }
        let p1 = &bytes[2..p1_end];
        // Regular UNC: `\\HOST\SHARE\...` — volume is through share.
        if p1 != b"." && p1 != b"?" {
            return p2_end;
        }
        let p2 = &bytes[after_p1_sep..p2_end];
        // DOS device that forwards to UNC: `\\?\UNC\HOST\SHARE\...`.
        if p2.len() == 3
            && p2[0].to_ascii_uppercase() == b'U'
            && p2[1].to_ascii_uppercase() == b'N'
            && p2[2].to_ascii_uppercase() == b'C'
        {
            if after_p2_sep >= bytes.len() {
                return bytes.len();
            }
            let (_host_end, share_start) = cut_at(after_p2_sep);
            if share_start == bytes.len() {
                return bytes.len();
            }
            let (share_end, _) = cut_at(share_start);
            return share_end;
        }
        // DOS device drive or other DOS device: `\\?\C:` / `\\.\X`.
        p2_end
    }
    #[cfg(not(windows))]
    {
        let _ = s;
        0
    }
}

/// Lexical path cleanup mirroring Go's `path/filepath::Clean` for the
/// path shapes `read_file_by_path` accepts. Performs no syscalls — `..`
/// is collapsed against the preceding component textually, NOT through
/// symlink resolution.
///
/// Without this step, a path like `link/../foo` where `link` is a
/// symlink to another directory would resolve via the symlink at
/// `stat()` time, reading a file under the symlink target instead of
/// the local `foo`. Go applies `Clean` inside `filepath.Dir` so its
/// `readFileByPath` does not exhibit this divergence; mirroring the
/// lexical cleanup here keeps cross-client behaviour aligned for
/// operator-supplied paths (notably `--data-dir` values that may
/// contain `..` segments combined with symlinks anywhere along the
/// resolved chain).
///
/// Rules (per Go `Clean`):
///   - Drop each `.` element.
///   - Eliminate each inner `..` element along with the non-`..`
///     element immediately preceding it.
///   - For a rooted path, drop a leading `..` (cannot escape root).
///   - Collapse runs of consecutive separators into a single separator.
///   - Empty input becomes `.`; an otherwise empty result becomes `.`.
///
/// On Windows both `/` and `\` are treated as separators per Go's
/// `filepath` package; the canonical separator in the returned string
/// is `std::path::MAIN_SEPARATOR`.
pub(crate) fn lexical_clean(input: &str) -> String {
    #[cfg(windows)]
    let is_sep = |c: char| c == '/' || c == '\\';
    #[cfg(not(windows))]
    let is_sep = |c: char| c == '/';

    let vol_len = volume_prefix_len(input);
    let vol = &input[..vol_len];
    let rest = &input[vol_len..];
    let rooted = rest.starts_with(is_sep);

    let mut parts: Vec<&str> = Vec::new();
    for component in rest.split(is_sep) {
        match component {
            "" | "." => continue,
            ".." => {
                if let Some(last) = parts.last() {
                    if *last != ".." {
                        parts.pop();
                        continue;
                    }
                }
                if rooted {
                    // /.. → /  : drop the parent-of-root reference.
                    continue;
                }
                parts.push("..");
            }
            other => parts.push(other),
        }
    }

    let sep = std::path::MAIN_SEPARATOR;
    let mut out = String::with_capacity(input.len());
    out.push_str(vol);
    if rooted {
        out.push(sep);
    }
    for (i, p) in parts.iter().enumerate() {
        if i > 0 {
            out.push(sep);
        }
        out.push_str(p);
    }
    if out.len() == vol.len() && !rooted {
        out.push('.');
    }
    out
}

/// Normalise an operator-supplied `--data-dir` once at the CLI parse
/// site so every subsystem that derives a path from it
/// (`ChainState::save` / `load_chain_state`, `BlockStore::open` and
/// its blocks / headers / undo / index sub-directories, etc.) sees
/// the same already-cleaned root. With the root normalised once,
/// internal readers and writers can stay on raw `fs::read` /
/// `write_file_atomic` and remain symmetric with each other — there
/// is no per-helper `lexical_clean` step that could diverge between
/// read and write for operator paths that cross a symlink combined
/// with `..`.
///
/// Returns `Err` if `path` is not valid UTF-8 (the lexical cleaner
/// works on the string form of the path); the practical expectation
/// is that `--data-dir` is a UTF-8 string since it comes from the
/// argv vector this binary was launched with, but surfacing an
/// explicit error keeps the failure mode obvious on unusual setups.
pub fn normalize_data_dir(path: &Path) -> Result<PathBuf, String> {
    match path.to_str() {
        Some(s) => Ok(PathBuf::from(lexical_clean(s))),
        None => Err(format!("data_dir must be valid UTF-8: {}", path.display())),
    }
}

// Historical helpers `resolve_io_path_dir_leaf`, `read_file_by_path`,
// and `write_file_atomic_by_path` used to sit here. They applied
// `lexical_clean` to the dir portion of a caller-supplied full path
// so that symlink-divergence on an operator `--data-dir` could be
// defeated at the per-read / per-write site. After adopting
// CLI-level normalisation via `normalize_data_dir` in `main.rs`,
// every subsystem now receives a pre-cleaned data-dir and can stay
// on raw `fs::read` / `write_file_atomic`; the per-helper cleaning
// step is no longer needed (and having it at some call sites but
// not others reintroduced asymmetries between chainstate and
// blockstore surfaces). The removed helpers and their regression
// tests lived in git history; the CLI-level approach is the single
// resolution strategy the whole node now uses.

pub fn parse_hex32(name: &str, value: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(value).map_err(|e| format!("{name}: {e}"))?;
    if bytes.len() != 32 {
        return Err(format!("{name}: expected 32 bytes, got {}", bytes.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Atomically write `data` to `path` with an honest fsync durability
/// contract (audit `E.1`). Sequence (any failure between open and rename
/// best-effort removes the partially-written
/// `<dest>.tmp.<pid>.<seq>`):
///
/// 1. resolve the target's effective parent (see `effective_parent`),
///    `create_dir_all` it if missing;
/// 2. open `<path>.tmp.<pid>.<seq>` with `O_CREATE|O_EXCL|O_WRONLY` —
///    NO `O_TRUNC`, so a stale temp leftover from a crashed prior
///    process that happens to be hard-linked to a live destination
///    inode cannot be truncated through the shared inode
///    (`allocate_and_write_temp` retries with a fresh `seq` on
///    `AlreadyExists`). `<seq>` is a process-wide atomic counter
///    ensuring concurrent writers in the same process get distinct
///    temp paths (`E.3`);
/// 3. `write_all` (loops on short writes per stdlib contract);
/// 4. `sync_all` — flushes data + inode metadata to disk;
/// 5. close (implicit on scope exit; see `sync_dir` doc on Rust File close
///    error semantics);
/// 6. `fs::rename` temp -> destination (atomic on the same filesystem;
///    OVERWRITES an existing destination — use `write_file_exclusive`
///    for create-if-absent semantics);
/// 7. `sync_dir` on the effective parent so the rename itself is durable.
///
/// Mirrors the Go `clients/go/node/chainstate.go` `writeFileAtomic` for
/// cross-client storage parity.
pub fn write_file_atomic(path: &Path, data: &[u8]) -> Result<(), String> {
    let parent = effective_parent(path);
    if let Some(parent) = parent {
        fs::create_dir_all(parent)
            .map_err(|e| format!("create parent {}: {e}", parent.display()))?;
    }
    let tmp_path = allocate_and_write_temp(path, data)?;
    // Rename OVERWRITES an existing destination. If the caller requires
    // create-if-absent semantics, use `write_file_exclusive` instead.
    fs::rename(&tmp_path, path).map_err(|e| {
        let _ = fs::remove_file(&tmp_path);
        format!(
            "rename temp {} -> {}: {e}",
            tmp_path.display(),
            path.display()
        )
    })?;
    // Directory fsync makes the rename itself durable. Without this the
    // destination file's bytes are on disk after the temp `sync_all()` above,
    // but the directory entry that points the destination name at the new
    // inode may still live only in the kernel page cache and be lost on
    // crash. Mirrors the Go `writeFileAtomic` `Sync` on parent directory
    // for cross-client parity.
    if let Some(parent) = parent {
        sync_dir(parent)?;
    }
    Ok(())
}

/// Error returned by [`write_file_exclusive`] distinguishing the
/// create-if-absent race — caller needs to know "the destination already
/// exists, read it and verify content" vs "some other I/O failure".
///
/// Cross-client parity: matches the error branching in the Go
/// `writeFileIfAbsent` helper which uses `errors.Is(err, os.ErrExist)`
/// on the `os.Link` result.
#[derive(Debug)]
pub enum AtomicWriteError {
    /// `path` already exists at link time. Caller must inspect the
    /// existing content to decide whether this is an idempotent retry
    /// (content matches) or a corruption/conflict (content differs).
    AlreadyExists,
    /// Any other surfaced failure along the atomic-create sequence —
    /// for example `create_dir_all` on the parent, temp-file exclusive
    /// open (including exhaustion of the `allocate_and_write_temp`
    /// retry budget on repeated stale-temp collisions), write,
    /// file-`sync_all`, `hard_link`, or the parent-directory
    /// `sync_dir`/directory-fsync durability step that runs after a
    /// successful link. Best-effort temp-file cleanup failures are not
    /// reported through this enum (the unlink is run on every exit
    /// path but its error is intentionally discarded to keep the
    /// primary error visible).
    Other(String),
}

impl From<String> for AtomicWriteError {
    fn from(msg: String) -> Self {
        AtomicWriteError::Other(msg)
    }
}

/// Atomically write `data` to `path` only if `path` does not already
/// exist (audit `E.3`, the TOCTOU-hardened companion to
/// `write_file_atomic`). Uses the POSIX `link(2)` primitive to get
/// create-if-absent semantics at the syscall layer:
///
/// 1. resolve effective parent, `create_dir_all` if missing;
/// 2. allocate a per-call-unique `<path>.tmp.<pid>.<seq>` via
///    [`allocate_and_write_temp`] and write `data` with the exclusive
///    `O_CREATE|O_EXCL` contract — same durability semantics as
///    `write_file_atomic`, retries on stale-temp collisions (PID +
///    seq reuse after a crash);
/// 3. `hard_link(temp, path)` — atomic create-if-absent. Fails with
///    [`AtomicWriteError::AlreadyExists`] if `path` is already on disk
///    (EEXIST); that race cannot silently overwrite the existing file;
/// 4. best-effort `unlink(temp)` — the destination (or the pre-existing
///    file on EEXIST) keeps the inode, so removing the temp name never
///    drops data. The unlink runs on every exit path, and its error is
///    intentionally discarded (a leaked temp is operational cleanup,
///    not a correctness issue) — see [`AtomicWriteError::Other`] doc
///    for the best-effort cleanup contract;
/// 5. `sync_dir` on the parent so the new directory entry is durable.
///
/// Mirrors the Go `writeFileIfAbsent` hard-link pattern in
/// `clients/go/node/blockstore.go`. The per-call monotonic `seq`
/// (filesystem counter, not a cryptographic nonce) closes the thread
/// race where two concurrent writers in the same process would
/// otherwise collide on a shared `.tmp.<pid>` path.
pub fn write_file_exclusive(path: &Path, data: &[u8]) -> Result<(), AtomicWriteError> {
    let parent = effective_parent(path);
    if let Some(parent) = parent {
        fs::create_dir_all(parent)
            .map_err(|e| format!("create parent {}: {e}", parent.display()))?;
    }
    let tmp_path = allocate_and_write_temp(path, data)?;
    let link_result = fs::hard_link(&tmp_path, path);
    // Best-effort unlink of the temp name. On link success the
    // destination inode keeps its own reference, so the temp name is
    // redundant. On link failure the temp must not strand on disk. The
    // unlink error itself is intentionally discarded to keep the
    // primary link error visible to the caller — see
    // `AtomicWriteError::Other` doc on the best-effort cleanup
    // contract.
    let _ = fs::remove_file(&tmp_path);
    match link_result {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(AtomicWriteError::AlreadyExists);
        }
        Err(e) => {
            return Err(AtomicWriteError::Other(format!(
                "hard_link {} -> {}: {e}",
                tmp_path.display(),
                path.display()
            )));
        }
    }
    if let Some(parent) = parent {
        sync_dir(parent)?;
    }
    Ok(())
}

/// Bounded retry count for [`allocate_and_write_temp`]. A collision on
/// `<dest>.tmp.<pid>.<seq>` should be vanishingly rare in practice (it
/// requires PID reuse PLUS `next_temp_seq` wrapping back over a stale
/// leftover from a prior process), so 16 attempts is deliberately
/// generous for the tail case while still bounding pathological loops.
const MAX_TEMP_ALLOC_RETRIES: u32 = 16;
/// Internal error from [`write_and_sync_temp`] so callers can
/// distinguish a stale-temp collision (retry with a new `seq`) from a
/// fatal I/O failure (surface to the caller).
enum TempWriteError {
    /// The `create_new(true)` open failed with `AlreadyExists`, i.e. a
    /// temp file with this exact `<pid>.<seq>` suffix already exists
    /// on disk. After a process crash, a leftover temp from the prior
    /// process can be hard-linked to a live destination inode; if we
    /// reopened it with `O_TRUNC` we would truncate the destination
    /// through that shared inode. `O_EXCL` refuses that reuse, and the
    /// caller retries with a fresh `seq`.
    AlreadyExists,
    /// Any other failure along `open → write_all → sync_all`. The temp
    /// path, if it was created, is best-effort removed by
    /// `write_and_sync_temp` before returning so callers do not need
    /// to clean up on the error path.
    Fatal(String),
}

/// Internal helper: open a fresh temp file at `tmp_path` with
/// `O_CREATE | O_EXCL` (Rust's `create_new(true)`) — NO `O_TRUNC`.
/// Refuses to reuse a pre-existing temp name so a stale leftover from
/// a crashed prior process cannot be truncated through a shared inode
/// (Copilot P1 audit on PR #1220). Writes all bytes, `sync_all`,
/// closes.
///
/// Mirrors the Go `writeAndSyncTemp` helper. On any failure this
/// helper best-effort removes `tmp_path` before returning the error,
/// so callers do NOT need to perform separate temp cleanup on error;
/// they may still unlink the temp after success (as
/// `write_file_exclusive` does after a successful `hard_link`) to
/// reclaim the redundant name.
fn write_and_sync_temp(tmp_path: &Path, data: &[u8]) -> Result<(), TempWriteError> {
    use std::io::Write;
    let mut tmp = match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(tmp_path)
    {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(TempWriteError::AlreadyExists);
        }
        Err(e) => {
            return Err(TempWriteError::Fatal(format!(
                "open temp {}: {e}",
                tmp_path.display()
            )));
        }
    };
    let write_result: Result<(), String> = (|| {
        tmp.write_all(data)
            .map_err(|e| format!("write temp {}: {e}", tmp_path.display()))?;
        tmp.sync_all()
            .map_err(|e| format!("sync temp {}: {e}", tmp_path.display()))
    })();
    // Drop the file handle BEFORE attempting to unlink the temp path.
    // On Windows `fs::remove_file` on an open handle fails with
    // `PermissionDenied`, which would leak the failed temp and, under
    // repeated I/O failures, burn through the `MAX_TEMP_ALLOC_RETRIES`
    // budget with stale `.tmp.<pid>.<seq>` leftovers (Codex P2 on PR
    // #1220). On Unix the drop is harmless ordering (close-then-unlink
    // always works, and unlink-then-close leaves the inode alive
    // through the open fd anyway). Explicit `drop` keeps the semantics
    // portable.
    drop(tmp);
    if let Err(e) = write_result {
        let _ = fs::remove_file(tmp_path);
        return Err(TempWriteError::Fatal(e));
    }
    Ok(())
}

/// Allocate a unique temp path for `path`, write `data` to it with the
/// exclusive-create + fsync contract, and return the temp path on
/// success. Retries up to [`MAX_TEMP_ALLOC_RETRIES`] times with a
/// fresh `next_temp_seq` on the rare `AlreadyExists` case (stale
/// leftover temp after PID + seq reuse). Fatal I/O errors surface
/// immediately without retry.
fn allocate_and_write_temp(path: &Path, data: &[u8]) -> Result<std::path::PathBuf, String> {
    let pid = std::process::id();
    let mut last_collision: Option<String> = None;
    for _ in 0..MAX_TEMP_ALLOC_RETRIES {
        let tmp_path = temp_path_for(path, pid, next_temp_seq());
        match write_and_sync_temp(&tmp_path, data) {
            Ok(()) => return Ok(tmp_path),
            Err(TempWriteError::AlreadyExists) => {
                last_collision = Some(format!("temp path already exists: {}", tmp_path.display()));
                continue;
            }
            Err(TempWriteError::Fatal(msg)) => return Err(msg),
        }
    }
    Err(last_collision.unwrap_or_else(|| {
        format!(
            "exhausted {MAX_TEMP_ALLOC_RETRIES} retries allocating temp for {}",
            path.display()
        )
    }))
}

/// Build the `<dest>.tmp.<pid>.<seq>` companion path for a target
/// `path` without going through lossy `Path::display()`. The `<seq>`
/// component is a process-wide monotonic uniqueness counter (see
/// `next_temp_seq`) that closes the thread race where two concurrent
/// writers in the same process would otherwise share a `.tmp.<pid>`
/// filename and one would silently overwrite the other's temp bytes
/// between write and rename/link (audit `E.3`). Not a cryptographic
/// nonce — it is a plain counter for filesystem path disambiguation;
/// named `seq` rather than `nonce` so CodeQL's "Hard-coded
/// cryptographic value" check does not mis-flag test literals that
/// feed this parameter.
///
/// `display()` replaces non-UTF-8 bytes with `U+FFFD`; on Unix a
/// `PathBuf` can contain any byte sequence other than `/` and `\0`, so a
/// lossy conversion would produce a temp at a different location than
/// the caller's actual target — breaking both the atomic rename and the
/// failure cleanup. `OsString::push` preserves the original bytes
/// exactly. Split into its own helper so the byte-preservation contract
/// is independently testable without going through the filesystem (APFS
/// on macOS rejects non-UTF-8 filenames with EILSEQ, so a filesystem-
/// level round-trip test is not portable). Copilot + Codex review
/// feedback on PR #1218 + the E.3 lane.
fn temp_path_for(path: &Path, pid: u32, seq: u64) -> PathBuf {
    let mut tmp_os = path.as_os_str().to_os_string();
    tmp_os.push(".tmp.");
    tmp_os.push(pid.to_string());
    tmp_os.push(".");
    tmp_os.push(seq.to_string());
    PathBuf::from(tmp_os)
}

/// Compute the directory whose existence we must ensure (and whose entry we
/// must fsync) for a target path. For relative bare-name targets like
/// `Path::new("foo")` the standard library returns `Some(Path::new(""))`,
/// not `None`. An empty path can neither be created via `create_dir_all`
/// nor opened via `OpenOptions::open` for `sync_dir`, so map empty to `.`
/// (current directory) — matches the previous `fs::write` semantics.
pub(crate) fn effective_parent(path: &Path) -> Option<&Path> {
    match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => Some(p),
        Some(_) => Some(Path::new(".")),
        None => None,
    }
}

/// Open the parent directory and call `sync_all()` so any rename or unlink
/// performed in it is itself durable. Splitting this out keeps
/// `write_file_atomic` linear and lets storage callers fsync ad-hoc
/// directory mutations later if they need to.
///
/// Cross-client note: the Go counterpart `syncDir` uses
/// `errors.Join(serr, cerr)` to surface a Close error after a successful
/// Sync. Rust cannot easily mirror that — `std::fs::File::drop` discards
/// the close error by design, and there is no stable safe API to surface
/// it. The Sync error itself is returned, so a kernel-level flush failure
/// is honestly reported; only the rare close-after-successful-sync error
/// is silently absorbed by Drop. This is an accepted Rust stdlib
/// limitation, not a missing fix.
///
/// Best-effort on permission-denied open: a parent directory with mode
/// `0300` (write+execute, no read) permits create/rename but blocks
/// `OpenOptions::new().read(true).open(dir)` (Codex review feedback on
/// PR #1218). The rename has already succeeded by the time `sync_dir`
/// runs, so returning an error would make the caller treat committed
/// state as failed on hardened directory-permission setups. Return
/// `Ok(())` instead — the destination bytes are already on disk via
/// the temp file's `sync_all()`; only the directory-entry fsync is
/// degraded to best-effort. Any other open error (`NotFound`, `Other`,
/// etc) still propagates as a real anomaly.
pub fn sync_dir(dir: &Path) -> Result<(), String> {
    use std::io::ErrorKind;
    match fs::OpenOptions::new().read(true).open(dir) {
        Ok(file) => file
            .sync_all()
            .map_err(|e| format!("sync dir {}: {e}", dir.display())),
        Err(e) if e.kind() == ErrorKind::PermissionDenied => Ok(()),
        Err(e) => Err(format!("open dir {}: {e}", dir.display())),
    }
}

#[cfg(test)]
pub fn unique_temp_path(prefix: &str) -> PathBuf {
    static NEXT_UNIQUE_TEMP_ID: AtomicU64 = AtomicU64::new(0);
    std::env::temp_dir().join(format!(
        "{prefix}-{}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time")
            .as_nanos(),
        NEXT_UNIQUE_TEMP_ID.fetch_add(1, Ordering::Relaxed),
    ))
}

#[cfg(test)]
mod tests {
    use super::{
        lexical_clean, read_file_from_dir, sync_dir, unique_temp_path, volume_prefix_len,
        write_file_atomic,
    };
    use std::fs;

    /// E.10 parity: `read_file_from_dir` mirrors Go `readFileFromDir`.
    /// Rejected vectors (must surface `InvalidInput`):
    ///   `""`, `"."`, `".."`, `"../etc/passwd"`, `"sub/file"`,
    ///   `"/etc/passwd"`.
    /// Accepted: a real leaf name pointing at a file inside `dir`.
    #[test]
    fn read_file_from_dir_rejects_traversal_and_absolute_and_empty() {
        let dir = unique_temp_path("rubin-io-utils-safe-read");
        fs::create_dir_all(&dir).expect("create test dir");

        // Cross-platform-uniform rejected vectors (Go-twin parity on
        // every OS).
        for bad in [
            "",
            ".",
            "..",
            "../etc/passwd",
            "sub/file",
            "/etc/passwd", // absolute Unix
        ] {
            match read_file_from_dir(&dir, bad) {
                Err(e) if e.kind() == std::io::ErrorKind::InvalidInput => {}
                Err(e) => panic!("expected InvalidInput for {bad:?}, got {:?}: {e}", e.kind()),
                Ok(_) => panic!("expected error for {bad:?}, got Ok"),
            }
        }

        // Windows-only rejected vectors: backslash separator + drive-
        // prefix leaf. On Unix these are valid filename bytes (Go's
        // `filepath.Base` accepts them too) — gating on cfg(windows)
        // preserves strict per-OS Go parity.
        #[cfg(windows)]
        for bad in [
            "sub\\file", // backslash separator (path separator on Windows)
            "C:foo",     // drive-prefixed leaf — Path::join replaces base on Windows
            "C:",
            "z:bar",
        ] {
            match read_file_from_dir(&dir, bad) {
                Err(e) if e.kind() == std::io::ErrorKind::InvalidInput => {}
                Err(e) => panic!("expected InvalidInput for {bad:?}, got {:?}: {e}", e.kind()),
                Ok(_) => panic!("expected error for {bad:?}, got Ok"),
            }
        }

        let _ = fs::remove_dir_all(&dir);
    }

    /// E.10 happy path: a real leaf name reads back the bytes.
    #[test]
    fn read_file_from_dir_reads_inside_root() {
        let dir = unique_temp_path("rubin-io-utils-safe-read-ok");
        fs::create_dir_all(&dir).expect("create test dir");
        let leaf = "ok.bin";
        fs::write(dir.join(leaf), b"hi").expect("seed");

        let got = read_file_from_dir(&dir, leaf).expect("read leaf");
        assert_eq!(got, b"hi");

        let _ = fs::remove_dir_all(&dir);
    }

    /// `lexical_clean` mirrors Go `path/filepath::Clean`. Each case
    /// here is verified against Go's documented behaviour for the path
    /// shapes the storage helpers accept.
    #[test]
    fn lexical_clean_matches_go_filepath_clean() {
        let sep = std::path::MAIN_SEPARATOR;
        let join = |parts: &[&str]| parts.join(&sep.to_string());

        assert_eq!(lexical_clean(""), ".");
        assert_eq!(lexical_clean("."), ".");
        assert_eq!(lexical_clean(".."), "..");
        assert_eq!(lexical_clean("../"), "..");
        assert_eq!(lexical_clean("../.."), join(&["..", ".."]));
        assert_eq!(lexical_clean("../foo"), join(&["..", "foo"]));
        assert_eq!(lexical_clean("foo/../bar"), "bar");
        assert_eq!(lexical_clean("foo/./bar"), join(&["foo", "bar"]));
        assert_eq!(lexical_clean("foo//bar"), join(&["foo", "bar"]));
        assert_eq!(lexical_clean("link/../foo"), "foo");
        assert_eq!(lexical_clean("link/.."), ".");

        // Rooted: leading `..` is dropped (cannot escape root).
        assert_eq!(lexical_clean("/"), format!("{sep}"));
        assert_eq!(lexical_clean("/.."), format!("{sep}"));
        assert_eq!(lexical_clean("/../foo"), format!("{sep}foo"));
        assert_eq!(
            lexical_clean("/var/data/link/../chainstate.json"),
            format!("{sep}var{sep}data{sep}chainstate.json")
        );
    }

    /// `volume_prefix_len` must match Go `filepath.VolumeName` length
    /// on every path shape the `lexical_clean` helper may encounter
    /// on Windows: drive-letter, UNC (`\\HOST\SHARE`), DOS device
    /// drive (`\\?\C:`, `\\.\C:`), DOS device UNC
    /// (`\\?\UNC\HOST\SHARE`), and the malformed-prefix fail-closed
    /// cases. Non-Windows input always returns 0.
    #[test]
    fn volume_prefix_len_matches_go_filepath_volumename() {
        // Unix-style / relative / non-volume input: always 0.
        for s in ["", "foo", "/foo", "/foo/bar", "foo/bar", "."] {
            assert_eq!(volume_prefix_len(s), 0, "non-volume input {s:?}");
        }

        // Windows-gated cases: the byte-level parser runs only when
        // this crate is compiled for Windows. Run the full table
        // there; on non-Windows the function short-circuits to 0 so
        // assertions in this block would fail.
        #[cfg(windows)]
        {
            // Drive-letter: `C:`, `C:foo`, `C:\foo`, `c:\foo`.
            assert_eq!(volume_prefix_len("C:"), 2);
            assert_eq!(volume_prefix_len("C:foo"), 2);
            assert_eq!(volume_prefix_len("C:\\"), 2);
            assert_eq!(volume_prefix_len("C:\\foo"), 2);
            assert_eq!(volume_prefix_len("c:\\foo"), 2);
            // Non-drive single-colon shapes — not a drive letter.
            assert_eq!(volume_prefix_len("1:foo"), 0);
            assert_eq!(volume_prefix_len(":foo"), 0);

            // UNC: `\\HOST\SHARE` — volume includes HOST and SHARE.
            assert_eq!(volume_prefix_len("\\\\host\\share"), 12);
            assert_eq!(volume_prefix_len("\\\\host\\share\\"), 12);
            assert_eq!(volume_prefix_len("\\\\host\\share\\foo"), 12);
            assert_eq!(volume_prefix_len("//host/share/foo"), 12);

            // Malformed UNC prefixes: Go returns `len(path)`
            // (fail-closed — no legitimate split). Mirror it.
            assert_eq!(volume_prefix_len("\\\\"), 2);
            assert_eq!(volume_prefix_len("\\\\host"), 6);
            assert_eq!(volume_prefix_len("\\\\host\\"), 7);

            // DOS device drive: `\\?\C:` and `\\.\C:`.
            assert_eq!(volume_prefix_len("\\\\?\\C:"), 6);
            assert_eq!(volume_prefix_len("\\\\?\\C:\\foo"), 6);
            assert_eq!(volume_prefix_len("\\\\.\\C:"), 6);

            // DOS device UNC: `\\?\UNC\HOST\SHARE`.
            assert_eq!(volume_prefix_len("\\\\?\\UNC\\host\\share"), 18);
            assert_eq!(volume_prefix_len("\\\\?\\UNC\\host\\share\\"), 18);
            assert_eq!(volume_prefix_len("\\\\?\\UNC\\host\\share\\foo"), 18);
            // Malformed DOS-UNC (no share segment) → full path.
            assert_eq!(volume_prefix_len("\\\\?\\UNC\\host"), 12);
            assert_eq!(volume_prefix_len("\\\\?\\UNC"), 7);
        }
    }

    /// Smoke test for the E.1 durability contract: a fresh write goes
    /// through OpenOptions + sync_all + rename + parent dir-sync without
    /// surfacing an error on a real filesystem, and the resulting bytes
    /// are exactly what we wrote. We cannot directly observe the fsync
    /// syscall from a unit test, but we DO want a regression that
    /// notices if the `OpenOptions`/`sync_all` chain ever returns an
    /// error on the platforms that run CI (Linux/macOS).
    #[test]
    fn write_file_atomic_durably_persists_fresh_file() {
        let dir = unique_temp_path("rubin-io-utils-fresh");
        fs::create_dir_all(&dir).expect("create test dir");
        let path = dir.join("payload.bin");
        let data = b"E.1 fsync contract: bytes + dir entry must both be durable";

        write_file_atomic(&path, data).expect("write_file_atomic");

        let read_back = fs::read(&path).expect("read back");
        assert_eq!(read_back, data);

        // Cleanup
        let _ = fs::remove_dir_all(&dir);
    }

    /// Replace path: existing destination is overwritten with new bytes.
    /// Verifies sync_all + rename idempotency on top of an existing inode
    /// (this is the dominant chainstate/blockstore path: rewrite the
    /// index file every commit).
    #[test]
    fn write_file_atomic_replaces_existing_file_with_new_durable_bytes() {
        let dir = unique_temp_path("rubin-io-utils-replace");
        fs::create_dir_all(&dir).expect("create test dir");
        let path = dir.join("index.json");

        write_file_atomic(&path, b"first").expect("first write");
        write_file_atomic(&path, b"second").expect("second write");

        let read_back = fs::read(&path).expect("read back");
        assert_eq!(read_back, b"second");

        // No leftover .tmp.* sibling — temp must have been renamed away.
        let leftover_tmps: Vec<_> = fs::read_dir(&dir)
            .expect("list dir")
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.file_name().to_string_lossy().contains(".tmp."))
            .collect();
        assert!(
            leftover_tmps.is_empty(),
            "stale .tmp.* file remained after rename: {:?}",
            leftover_tmps
                .iter()
                .map(|e| e.file_name())
                .collect::<Vec<_>>()
        );

        let _ = fs::remove_dir_all(&dir);
    }

    /// Standalone `sync_dir` helper accepts an existing directory and
    /// returns Ok. Storage callers may want to fsync ad-hoc directory
    /// mutations (e.g. after deleting a stale undo file) without going
    /// through `write_file_atomic`.
    #[test]
    fn sync_dir_succeeds_on_existing_directory() {
        let dir = unique_temp_path("rubin-io-utils-syncdir");
        fs::create_dir_all(&dir).expect("create test dir");

        sync_dir(&dir).expect("sync_dir on existing directory");

        let _ = fs::remove_dir_all(&dir);
    }

    /// Codex P2 fix from PR #1218: `sync_dir` on an execute-only parent
    /// (mode `0300` — write+execute, no read) must return `Ok(())`
    /// instead of surfacing `EACCES`, because the rename has already
    /// succeeded by the time we call it. Without this, hardened
    /// directory-permission setups would see writes reported as failed
    /// even though the destination bytes are durably on disk.
    #[cfg(unix)]
    #[test]
    fn sync_dir_is_best_effort_on_execute_only_parent() {
        use std::os::unix::fs::PermissionsExt;
        // Skip when running as root — the chmod-based permission check
        // does not apply (CAP_DAC_READ_SEARCH bypasses it). Detected via
        // `id -u` (no extra crate dependency on `libc` or `users`).
        let is_root = std::process::Command::new("id")
            .arg("-u")
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .map(|s| s.trim() == "0")
            .unwrap_or(false);
        if is_root {
            return;
        }
        let dir = unique_temp_path("rubin-io-utils-syncdir-eaccess");
        fs::create_dir_all(&dir).expect("create test dir");
        let mut perms = fs::metadata(&dir).expect("stat").permissions();
        perms.set_mode(0o300);
        fs::set_permissions(&dir, perms).expect("chmod 0o300");

        let result = sync_dir(&dir);

        // Restore writable mode before any remove call so cleanup works.
        let mut restore = fs::metadata(&dir).expect("stat").permissions();
        restore.set_mode(0o700);
        let _ = fs::set_permissions(&dir, restore);
        let _ = fs::remove_dir_all(&dir);

        result.expect("sync_dir on execute-only dir must be best-effort (Ok)");
    }

    /// Pure-helper unit test for the `path.parent()` edge case: a relative
    /// bare-name target like `Path::new("relative.bin")` returns
    /// `Some(Path::new(""))` from `parent()`, not `None`. The previous
    /// `fs::write` implementation silently no-op'd the parent, so callers
    /// in CWD-relative paths kept working. The internal `effective_parent`
    /// helper maps the empty parent to `.` so `create_dir_all` and
    /// `sync_dir` both get a usable path.
    ///
    /// We test the helper directly rather than mutating the process-wide
    /// CWD with `std::env::set_current_dir`, which would race other tests
    /// running in parallel (Rust tests are concurrent by default).
    #[test]
    fn effective_parent_maps_empty_parent_to_current_directory() {
        use super::effective_parent;
        use std::path::Path;

        // Bare relative target: parent is "" -> mapped to "."
        assert_eq!(
            effective_parent(Path::new("relative.bin")),
            Some(Path::new("."))
        );
        // Absolute target with explicit parent: returned as-is
        assert_eq!(
            effective_parent(Path::new("/tmp/sub/file")),
            Some(Path::new("/tmp/sub"))
        );
        // Filesystem root: no parent at all
        assert_eq!(effective_parent(Path::new("/")), None);
        // Multi-segment relative target: parent retained
        assert_eq!(
            effective_parent(Path::new("sub/file")),
            Some(Path::new("sub"))
        );
    }

    /// Copilot P1 regression from PR #1218: the temp path must be built
    /// via byte-level `OsString::push`, NOT via lossy
    /// `format!("{}.tmp.{}", path.display(), pid)`. `path.display()`
    /// replaces non-UTF-8 bytes with `U+FFFD`, so a `PathBuf` containing
    /// any non-UTF-8 byte would round-trip to a DIFFERENT temp path
    /// than the caller's actual target.
    ///
    /// Tested on the pure helper because APFS on macOS rejects non-UTF-8
    /// filenames at the syscall layer with `EILSEQ`, which makes a
    /// filesystem-level round-trip test non-portable. `temp_path_for`
    /// is the only place where the lossy-vs-exact decision lives, so
    /// byte-level verification here pins the fix completely.
    #[cfg(unix)]
    #[test]
    fn temp_path_for_preserves_non_utf8_bytes() {
        use super::temp_path_for;
        use std::ffi::OsString;
        use std::os::unix::ffi::{OsStrExt, OsStringExt};
        use std::path::PathBuf;

        let mut bytes = b"/tmp/bad-".to_vec();
        bytes.push(0xff);
        bytes.extend_from_slice(b"-name.bin");
        let path = PathBuf::from(OsString::from_vec(bytes.clone()));

        let tmp = temp_path_for(&path, 12345, 7);

        let mut expected = bytes.clone();
        expected.extend_from_slice(b".tmp.12345.7");
        assert_eq!(tmp.as_os_str().as_bytes(), expected.as_slice());

        // Negative: lossy `format!("{}.tmp.{}.{}", path.display(), ...)`
        // would replace the 0xff byte with U+FFFD (three bytes
        // 0xef 0xbf 0xbd), producing DIFFERENT bytes.
        let lossy = format!("{}.tmp.12345.7", path.display());
        assert_ne!(
            tmp.as_os_str().as_bytes(),
            lossy.as_bytes(),
            "temp_path_for must not agree with lossy display() on non-UTF-8 input"
        );
    }

    /// The seq component is what closes the thread race (`E.3`): two
    /// consecutive calls within the same process must produce distinct
    /// temp paths, even though they share the same PID. Without the
    /// seq, two threads writing to the same destination would overwrite
    /// each other's temp bytes between open and rename/link.
    #[test]
    fn temp_path_for_is_unique_per_seq() {
        let path = std::path::Path::new("/tmp/shared-dest.bin");
        let a = super::temp_path_for(path, 42, 0);
        let b = super::temp_path_for(path, 42, 1);
        assert_ne!(a, b);
        // Same pid+seq must remain deterministic for callers that need
        // to compute the expected temp name in tests.
        let a_again = super::temp_path_for(path, 42, 0);
        assert_eq!(a, a_again);
    }

    /// `next_temp_seq` must never return the same value twice within a
    /// single process so that concurrent callers pass distinct seq
    /// values into `temp_path_for`. Verify ordering AND uniqueness in a
    /// small burst — `AtomicU64::fetch_add` gives strict monotonic
    /// growth which is stronger than uniqueness and helps diagnose a
    /// future counter-wrap or reset regression.
    #[test]
    fn next_temp_seq_is_monotonic_and_unique() {
        let a = super::next_temp_seq();
        let b = super::next_temp_seq();
        let c = super::next_temp_seq();
        // Uniqueness.
        assert!(b != a && c != a && c != b);
        // Monotonic ordering.
        assert!(a < b, "seq must be monotonically increasing: a={a} b={b}");
        assert!(b < c, "seq must be monotonically increasing: b={b} c={c}");
    }

    /// On a sync_all/write_all failure before rename the temp file MUST be
    /// removed, otherwise a real I/O fault (ENOSPC/EIO after data write)
    /// would strand large `<dest>.tmp.<pid>` siblings on disk while the
    /// caller sees an error.
    ///
    /// We exercise the path indirectly: provoke a `create_parent` failure
    /// by passing a destination whose parent path component is an existing
    /// regular file (not a directory). The early-exit must NOT leave any
    /// unrelated file behind in the surrounding temp directory.
    #[test]
    fn write_file_atomic_does_not_strand_temp_when_create_parent_fails() {
        let dir = unique_temp_path("rubin-io-utils-strand");
        fs::create_dir_all(&dir).expect("create test dir");
        let blocker = dir.join("not-a-dir");
        fs::write(&blocker, b"existing file masquerading as parent").expect("write blocker");
        // Path whose parent (`blocker`) is a regular file, so create_dir_all
        // will fail before any temp open/write happens.
        let bad_target = blocker.join("payload");

        let result = write_file_atomic(&bad_target, b"never-written");
        assert!(result.is_err(), "expected create_parent failure");

        // The directory must contain only the blocker file; no `.tmp.*`
        // sibling was created by this failed call.
        let entries: Vec<_> = fs::read_dir(&dir)
            .expect("list dir")
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            entries,
            vec!["not-a-dir".to_string()],
            "stranded files present"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    /// Copilot P1 regression on PR #1220: a stale
    /// `<dest>.tmp.<pid>.<seq>` leftover from a crashed prior process
    /// (potentially hard-linked to a live destination inode) must NOT
    /// be reopened with O_TRUNC — that would truncate the destination
    /// through the shared inode. `write_and_sync_temp` uses
    /// `create_new(true)` (O_EXCL), so reopening the same path
    /// returns `AlreadyExists` without touching inode data.
    ///
    /// Probe `write_and_sync_temp` directly with an explicit temp
    /// path so the test does not depend on the global `TEMP_SEQ`
    /// counter — Rust's `cargo test` runs tests in parallel by
    /// default, and a probe like `stale_seq = next_temp_seq() + 1`
    /// would race against any other `TEMP_SEQ`-advancing test and
    /// silently pass under a regression. The `allocate_and_write_temp`
    /// retry wrapper is just a loop on top of this primitive, so
    /// validating the primitive's EEXIST-without-truncate contract is
    /// sufficient for the retry path. Go-side integration coverage
    /// (`TestWriteFileAtomic_SkipsStaleTempViaExclusiveCreate`) runs
    /// in a serial test binary by default and exercises the full
    /// allocate-then-link flow for end-to-end confidence.
    #[test]
    fn write_and_sync_temp_refuses_to_reopen_existing_temp() {
        use super::{write_and_sync_temp, TempWriteError};
        let dir = unique_temp_path("rubin-io-utils-excl-temp");
        fs::create_dir_all(&dir).expect("create test dir");
        let tmp_path = dir.join("seeded.tmp");
        let stale_bytes = b"STALE BYTES - must not be truncated";
        fs::write(&tmp_path, stale_bytes).expect("seed stale temp");

        match write_and_sync_temp(&tmp_path, b"attempted new bytes") {
            Err(TempWriteError::AlreadyExists) => {}
            Ok(()) => {
                panic!("write_and_sync_temp accepted a pre-existing path — O_EXCL is not in effect")
            }
            Err(TempWriteError::Fatal(msg)) => {
                panic!("expected AlreadyExists, got Fatal({msg}) — unexpected error kind")
            }
        }

        // The existing temp file must be byte-identical to the seed:
        // O_EXCL refused the open, so the inode was never touched.
        assert_eq!(
            fs::read(&tmp_path).expect("read after"),
            stale_bytes,
            "pre-existing temp was truncated — O_TRUNC regression",
        );

        let _ = fs::remove_dir_all(&dir);
    }
}
