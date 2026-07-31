use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
#[cfg(test)]
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

#[path = "file_lock.rs"]
#[allow(dead_code)]
mod atomic_file_lock;

// Per-class local store read bounds (RUB-1057), enforced BEFORE the file's
// contents are allocated. Every class here holds exactly one wire item whose
// size a consensus rule already caps, so the bound is derived rather than
// invented. Artifacts that grow with chain length or UTXO-set size admit no
// such ceiling and are deliberately left UNBOUNDED: the canonical index
// marker, read through `read_file_from_dir_unbounded` below, and the
// chainstate snapshot, read through `fs::read` in
// `chainstate.rs::load_chain_state`. No fixed byte number is defensible on
// either — a settled decision rather than missing work, whose measurements
// and withdrawn alternative are recorded on `read_file_from_dir_unbounded`
// and cover both artifacts. The numbers are a cross-client contract mirrored
// byte-for-byte from Go `clients/go/node/safeio.go`; derivations and margins
// must not drift from the Go copy. The measured per-entry figure is pinned by
// `undo_entry_derivation_size` (blockstore.rs), twin of Go's
// `TestReadFileBoundDerivationEntrySizes`.
//
// - Block blobs hold exactly one wire block, capped by the P2P layer at
//   MAX_BLOCK_BYTES. Growth: none per file (fixed constant).
// - Header blobs hold exactly one wire header (BLOCK_HEADER_BYTES).
// - Undo files hold one block's spent-entry JSON. Worst legitimate case
//   (measured on this repo's pretty-JSON encoding): inputs_max =
//   MAX_BLOCK_BYTES / min-wire-per-spend (41B input + 4627B ML-DSA-87 sig,
//   ignoring the mandatory 2592B pubkey reveal and the weight cap, both of
//   which only shrink it) = 72_000_000/4_668 = 15_424 spends; worst
//   per-entry JSON = 66_707B (max spendable covenant_data is CORE_VAULT at
//   33_188B, hex-doubled) -> 15_424*66_707 ~= 1.029GB. 2_000_000_000 covers
//   that with ~1.94x margin (~3x vs the proven pubkey+sig floor of ~661MB)
//   and stays below 2^31 so the size never narrows unsafely on any build.
//   Growth: per block, not cumulative. Decoding an undo file costs roughly
//   twice the admitted on-disk bytes in peak resident memory (raw buffer plus
//   decoded structs), so this bound governs the FILE, not the decode
//   footprint. Enforced on both ends (check_store_save_bound in put_undo, the
//   bounded read in get_undo).
// The write-if-absent existing-destination verify reads have no constant of
// their own: they exist only to compare against the content being written, so
// they are bounded by that content's own length (blockstore.rs
// `write_file_if_absent`) and a larger destination is reported through the
// existing content-mismatch error rather than as a size refusal.
pub(crate) const BLOCK_FILE_MAX_BYTES: u64 = rubin_consensus::constants::MAX_BLOCK_BYTES;
pub(crate) const HEADER_FILE_MAX_BYTES: u64 = rubin_consensus::BLOCK_HEADER_BYTES as u64;
pub(crate) const UNDO_FILE_MAX_BYTES: u64 = 2_000_000_000;

/// Stable message prefix of the typed over-bound refusal; tests match on
/// ErrorKind + this prefix.
pub(crate) const STORE_FILE_TOO_LARGE_PREFIX: &str = "store file exceeds size bound";

/// Typed refusal for an over-bound store file (RUB-1057). The kind is
/// `InvalidData` — deliberately NEVER `NotFound` — so absent-file fallbacks
/// (fresh chainstate, empty block store index, write-if-absent probes) and
/// `sync_reorg::load_verified_branch_ancestor`'s NotFound-only
/// parent-not-found arm can never treat an over-bound file as absent.
/// Go twin: `errStoreFileTooLarge` in `clients/go/node/safeio.go`.
fn file_too_large_error(name: &str, observed: u64, max_bytes: u64) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        format!("{STORE_FILE_TOO_LARGE_PREFIX}: {name}: {observed} bytes observed, class bound {max_bytes}"),
    )
}

/// Write/read symmetry guard for the undo class: the node must never persist
/// an undo file it would refuse to load back. Same class as the read-side
/// refusal (shared prefix, never an absent-file class); the message is
/// clearly save-side. Block and header writes need no guard — the wire format
/// already fixes their size. Go twin: `checkStoreSaveBound` in
/// `clients/go/node/safeio.go`.
pub(crate) fn check_store_save_bound(name: &str, len: usize, max_bytes: u64) -> Result<(), String> {
    if len as u64 > max_bytes {
        return Err(format!(
            "refusing to save {name}: {len} bytes marshaled, class bound {max_bytes}: {STORE_FILE_TOO_LARGE_PREFIX}"
        ));
    }
    Ok(())
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
    //
    // Drive-prefix rejection: Go's guard is
    // `filepath.Base(name) != name`. On Windows `filepath.Base("X:foo")`
    // strips the 2-byte volume prefix and returns `"foo"` for ANY
    // byte at `name[0]` (Go matches `path[1] == ':'` unconditionally
    // in `volumeNameLen`, no ASCII-letter enforcement). So `"1:foo"`,
    // `":foo"` (2-byte, first byte is `:` — fails len>=2 + bytes[1]==':'
    // test below, `bytes[1]` is `f`), and `"_:foo"` all get rejected
    // by Go's guard. Drop the `is_ascii_alphabetic` narrowing here
    // so the Rust guard covers the same vector set.
    #[cfg(windows)]
    {
        if name.contains('\\') {
            return Err(format!("invalid file name: {name:?}"));
        }
        let bytes = name.as_bytes();
        if bytes.len() >= 2 && bytes[1] == b':' {
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
/// `max_bytes` is the caller's class bound (RUB-1057), enforced before the
/// file's contents are materialized: the OPEN handle is fstat'ed (no path
/// re-stat) and an over-bound size is refused without reading any content.
pub fn read_file_from_dir(
    dir: &Path,
    name: &str,
    max_bytes: u64,
) -> Result<Vec<u8>, std::io::Error> {
    if let Err(msg) = check_safe_file_name(name) {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, msg));
    }
    let f = fs::File::open(dir.join(name))?;
    let stat_size = f.metadata()?.len();
    read_capped(f, name, stat_size, max_bytes)
}

/// Reads `dir/name` in full with only the leaf-name guard. Its sole caller is
/// the block store index marker loader: that artifact grows with chain length
/// and admits no fixed ceiling a consensus-valid chain cannot reach, so
/// RUB-1057 deliberately leaves it UNBOUNDED.
///
/// Leaving it unbounded is a standing decision, not a gap awaiting an owner.
/// No byte ceiling is defensible on either unbounded artifact, and they grow
/// along DIFFERENT axes — this helper's marker with CHAIN LENGTH, the
/// chainstate snapshot (read via `fs::read` in `chainstate.rs`) with
/// UTXO-SET SIZE — so each would need its own number even if either were
/// defensible. (Go states this as one helper serving both artifacts; here they
/// are read by different functions, so there is no shared number at stake —
/// only the same two-axis fact.) RUB-1057 measured a 1 GB chainstate bound as
/// reachable in ~29 blocks of maximum-size CORE_VAULT outputs, and any marker
/// ceiling is only a hard cap on chain length. An incremental-decode
/// alternative to reading these whole was implemented and measured, then
/// withdrawn; do not re-derive it. It does not close the finding — an
/// oversized hostile file still kills the node — it is several times WORSE
/// than the whole-buffer path on a document holding one huge value, and its
/// equivalence to the whole-buffer decoders is only ever provable by
/// sampling. RUB-1057 is the finding of record. Go twin: `readFileByPath` in
/// `clients/go/node/safeio.go`.
pub(crate) fn read_file_from_dir_unbounded(
    dir: &Path,
    name: &str,
) -> Result<Vec<u8>, std::io::Error> {
    if let Err(msg) = check_safe_file_name(name) {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, msg));
    }
    fs::read(dir.join(name))
}

/// Bounded read of `path` routed through `read_file_from_dir` by splitting it
/// into parent dir + leaf, so the leaf-name guard applies too. Two callers
/// with different leaf provenance: the write-if-absent verify seam
/// (`blockstore.rs`), whose leaves are synthesized hex-hash names, and
/// `read_config_file_to_string`, whose leaf is an OPERATOR-CHOSEN filename —
/// that caller normalizes the path lexically first, and its doc records the
/// one verdict the split changes. Go twin: `readFileByPathCapped`.
pub(crate) fn read_file_by_path(path: &Path, max_bytes: u64) -> Result<Vec<u8>, std::io::Error> {
    let dir = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    match path.file_name().and_then(std::ffi::OsStr::to_str) {
        Some(name) => read_file_from_dir(dir, name, max_bytes),
        None => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("invalid file name: {}", path.display()),
        )),
    }
}

/// Bounds the operator-supplied genesis pack JSON (`--genesis-file`) at both
/// of its readers in `genesis.rs`: `load_genesis_config`, the one on the
/// startup path (`main.rs`), and `load_chain_id_from_genesis_file`, which has
/// no caller inside this crate and is reachable only through the `lib.rs`
/// re-export.
///
/// A legitimate pack is tiny: two 64-char hex fields (169 B), an optional
/// `rotation_descriptor` (246 B) and a couple of `suite_registry` entries come
/// to 824 B — measured on this client's `GenesisPack`, with 64-char strings
/// and 20-digit numbers.
///
/// 16 MiB is NOT derived from the schema, because the schema imposes no size
/// ceiling of its own:
///   - no string member has a schema-enforced length: `name` is only checked
///     non-empty and the hex fields are trimmed, so surrounding padding is
///     tolerated. `alg_name` is NOT a padding vector at the startup reader —
///     `normalize_suite_alg_name` requires it to `trim()` to "ML-DSA-87", so
///     it admits whitespace only — but that validation runs in
///     `load_genesis_config` alone; `load_chain_id_from_genesis_file` never
///     reaches it;
///   - `openssl_alg` is the real padding vector: a legacy alias, IGNORED
///     whenever `alg_name` is present, that still counts toward the file —
///     measured, a 16-entry pack carrying ~900 KB of it per entry is 14.4 MB
///     and IS ACCEPTED;
///   - `MAX_EXPLICIT_SUITE_REGISTRY_ITEMS` (16) is checked inside
///     `build_suite_registry_from_json`, AFTER serde has materialized the
///     whole `Vec`, so it bounds neither bytes nor allocation. BOTH readers
///     deserialize that vector, custom per-entry `Deserialize` included; what
///     `load_chain_id_from_genesis_file` skips is the cap check and the
///     per-item validation, not the allocation.
///
/// The number is therefore SET, not derived: 16 MiB sits orders of magnitude
/// above any legitimate pack (>10^4 x the 824 B above) and is the only real
/// size limit at either reader. Reachability (the RUB-1057 lesson): the file
/// is operator-authored and does not grow with chain or UTXO state, so the
/// ceiling cannot fire on honest use, while a mistakenly-pointed-at huge file
/// is refused before its contents are allocated.
///
/// The NUMBER is a cross-client contract — Go's `configFileMaxBytes`
/// (`clients/go/node/safeio.go`) is the same 16 MiB — but the two DERIVATIONS
/// differ, deliberately and on two counts: the clients parse different
/// genesis-pack schemas (Go's is four fixed hex fields including a header-bytes
/// field this client has no member for, and has no repeated member), and Go's
/// ceiling additionally covers the featurebits DEPLOYMENTS file, a Go-only
/// surface (the Rust node has no such flag; the born-bounded obligation for a
/// future port is RUB-1065). Do not harmonize the prose — only the number is
/// shared. Pinned by `config_bound_pins_derived_value`, twin of Go's
/// `TestReadFileConfigBoundPinsDerivedValue`.
pub(crate) const CONFIG_FILE_MAX_BYTES: u64 = 1 << 24;

/// Reads an operator config file as text under `CONFIG_FILE_MAX_BYTES` with
/// the typed pre-allocation refusal from RUB-1057 (`InvalidData` carrying
/// `STORE_FILE_TOO_LARGE_PREFIX`). Go twin: `ReadConfigFile` in
/// `clients/go/node/safeio.go`.
///
/// Non-UTF-8 CONTENT is refused with `InvalidData` too, preserving the
/// `fs::read_to_string` behaviour these call sites had before the bound —
/// but WITHOUT the size prefix, so the two refusal classes stay
/// distinguishable (`config_read_rejects_non_utf8_without_size_prefix`).
///
/// Path shapes whose disposition this routing changed, all measured against
/// the Go node and all now AGREEING with it — the deltas are against this
/// client's own pre-bound `fs::read_to_string`, not against Go:
///   - lexical normalization accepts paths the KERNEL would refuse, because
///     `Clean` folds `..` without checking that the component it removes is a
///     directory: `cfg.json/`, `cfg.json/.`, `cfg.json/./`, `cfg.json/.//`
///     and — the non-obvious ones — `cfg.json/../cfg.json` and
///     `cfg.json/.././cfg.json`, which traverse `..` THROUGH a regular file.
///     `read_to_string` refused all of these (ENOTDIR); Go accepts them, and
///     matching Go is the point;
///   - a FILENAME containing a non-UTF-8 byte is refused, because
///     `read_file_by_path` splits the leaf with
///     `file_name().and_then(OsStr::to_str)` and gets `None`. Go refuses it
///     too, for its own reason — `os.DirFS(..).Open` runs `fs.ValidPath`,
///     which requires `utf8.ValidString`, so it fails with `invalid argument`
///     before the syscall (measured; an absent UTF-8 leaf gives ENOENT
///     instead, which is what proves it a validity refusal). `read_to_string`
///     read such a file, so this shape moved INTO agreement with Go.
///
/// One gap is inherited from the reuse: `normalize_data_dir` passes a
/// non-UTF-8 path through UNCLEANED (its `to_str() == None` arm, pinned by
/// `normalize_data_dir_preserves_non_utf8_unix_path`). A non-UTF-8 byte in a
/// DIRECTORY component with a valid filename therefore skips normalization and
/// lets the kernel resolve `link/..` again — the class this routing closes,
/// reopened on that one input. Unreachable through the CLI, where
/// `env::args()` rejects non-UTF-8 first.
pub(crate) fn read_config_file_to_string(path: &Path) -> Result<String, std::io::Error> {
    // Normalize lexically BEFORE the bounded read splits the path, mirroring
    // Go, whose two callers both pass `filepath.Clean(path)` into
    // `ReadConfigFile` (`cmd/rubin-node/main.go`). `normalize_data_dir` is
    // that port — `lexical_clean` plus the byte-transparent pass-through for a
    // non-UTF-8 path — and `--data-dir` already gets it; the genesis file is
    // the operator path that never did.
    //
    // `lexical_clean_matches_go_filepath_clean` is a table of Rust literals
    // and never executes Go, so it pins drift from those literals, not from
    // `filepath.Clean` itself; the agreement rests on the port being written
    // against Go's documented rules and on the measured per-shape rows.
    //
    // Not cosmetic: unnormalized, `Path::parent()` leaves a `link/..` segment
    // for the KERNEL to resolve, so on `<d>/sub/link/../genesis.json` the two
    // clients read DIFFERENT FILES (measured: Go folds to `<d>/sub`, the
    // kernel follows the symlink to `<d>/other`) and two nodes given one
    // command line adopt different chain ids.
    //
    // Per-helper normalization is safe HERE in a way `normalize_data_dir`'s
    // doc warns it is not for the datadir: that warning is about a reader and
    // a writer drifting apart, and this path is READ-ONLY — nothing writes the
    // genesis pack.
    // `normalize_data_dir` is infallible today — both arms return `Ok` — so
    // this propagation is dead. Kept rather than `.expect()`ed: its signature
    // is fallible, and the alternative puts a panic on an operator-input path.
    let path = normalize_data_dir(path)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    let raw = read_file_by_path(&path, CONFIG_FILE_MAX_BYTES)?;
    String::from_utf8(raw).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "stream did not contain valid UTF-8",
        )
    })
}

/// Bounded read core (Go twin: `readAllCapped`/`readCapped`). Refuses
/// `stat_size > max_bytes` WITHOUT reading, then reads through a
/// `max_bytes+1` limiter into a buffer this function grows ITSELF, so a file
/// that grew between stat and read is still read in full when it fits, still
/// refused by the post-read length check when it does not, and never costs
/// more than `cap_hint(max_bytes, max_bytes)` of capacity.
///
/// The growth is hand-rolled rather than delegated to `read_to_end` because
/// std's amortized doubling overshoots the class bound: measured, a 2-byte
/// initial capacity reading `MAX_BLOCK_BYTES + 1` bytes ends at capacity
/// 134_217_728 == 1.86x the advertised ceiling. Go's `readCapped` never
/// exceeds `maxBytes+1`, so the overshoot was a cross-client asymmetry in
/// peak allocation. Raw read errors propagate unwrapped — never coerced into
/// the size error.
fn read_capped<R: Read>(
    r: R,
    name: &str,
    stat_size: u64,
    max_bytes: u64,
) -> Result<Vec<u8>, std::io::Error> {
    if stat_size > max_bytes {
        return Err(file_too_large_error(name, stat_size, max_bytes));
    }
    // Zero-filled so the spare capacity is safely readable as `&mut [u8]`;
    // `len == capacity` is maintained on every growth and the tail is
    // truncated at the end. Mirrors Go, whose `make` also hands back zeroed
    // memory. Saturate the limiter budget rather than +1 blindly: a wrapped
    // negative budget would report EOF immediately — a silent truncation
    // exactly where the bound is supposed to refuse.
    let mut buf = vec![0u8; cap_hint(stat_size, max_bytes)];
    let mut limited = r.take(max_bytes.saturating_add(1));
    let mut filled = 0usize;
    loop {
        if filled == buf.len() {
            let next = grow_capacity(buf.len(), max_bytes);
            if next <= buf.len() {
                break; // at the ceiling; the length check below decides
            }
            buf.reserve_exact(next - buf.len());
            buf.resize(next, 0);
        }
        let n = limited.read(&mut buf[filled..])?;
        if n == 0 {
            break;
        }
        filled += n;
    }
    buf.truncate(filled);
    if buf.len() as u64 > max_bytes {
        return Err(file_too_large_error(name, buf.len() as u64, max_bytes));
    }
    Ok(buf)
}

/// Doubles `current`, clamped to `cap_hint(max_bytes, max_bytes)` (the most
/// the limiter can ever deliver) and floored at 512 bytes, the floor itself
/// clamped to the limit so a small class never gets an oversized buffer.
/// Line-by-line twin of Go's `growCapacity` in `clients/go/node/safeio.go`;
/// the two clients' growth ceilings must stay comparable. The limit is the
/// DEFAULT and the doubling is taken only when it provably fits
/// (`current <= limit / 2`), so an overflowed product can never be observed.
fn grow_capacity(current: usize, max_bytes: u64) -> usize {
    const GROW_FLOOR: usize = 512;
    let limit = cap_hint(max_bytes, max_bytes);
    let mut next = limit;
    if current <= limit / 2 {
        next = current * 2;
    }
    if next < GROW_FLOOR {
        next = GROW_FLOOR.min(limit);
    }
    next
}

/// min(stat_size, max_bytes)+1 — the +1 gives the EOF probe room so an
/// exact-size read never reallocates — clamped to `isize::MAX` (== Go
/// `math.MaxInt` in `capHint`); the clamp is unreachable for the real class
/// bounds (all < 2^31).
fn cap_hint(stat_size: u64, max_bytes: u64) -> usize {
    let hint = stat_size.min(max_bytes).saturating_add(1);
    usize::try_from(hint.min(isize::MAX as u64)).unwrap_or(isize::MAX as usize)
}

/// Length of the volume prefix at the start of `s`. Mirrors Go
/// `internal/filepathlite/path_windows.go::volumeNameLen` byte-for-byte.
///
/// Path shapes recognised (each case mirrors Go's switch arm):
/// - drive letter: `C:` → 2 (`C:foo`, `C:\foo`, bare `C:`, `2:`
///   — Go does not enforce ASCII-letter range; we follow)
/// - no leading separator → 0 (relative / Unix-style)
/// - Local Device UNC forward: `\\.\UNC\HOST\SHARE\...` → uncLen
///   starting after the `\\.\UNC\` prefix (8 bytes)
/// - Local Device / Root Local Device: `\\.\X`, `\\?\X`, `\??\X` →
///   next segment after the 3-char prefix is part of the volume
///   (matches Go issue #64028: `Clean("\\?\c:\")` must keep trailing
///   `\` because the `c:` segment is still the volume)
/// - Two-leading-separator UNC: `\\HOST\SHARE...` → uncLen from pos 2
/// - anything else → 0
///
/// Returns 0 on non-Windows builds.
fn volume_prefix_len(s: &str) -> usize {
    #[cfg(windows)]
    {
        let bytes = s.as_bytes();
        // Drive letter — Go matches on `path[1] == ':'` without
        // enforcing that `path[0]` is a letter. Mirror that.
        if bytes.len() >= 2 && bytes[1] == b':' {
            return 2;
        }
        if bytes.is_empty() || !is_path_separator_byte(bytes[0]) {
            return 0;
        }
        // Local Device UNC forward: `\\.\UNC\...`. Go treats the
        // HOST and SHARE after `\\.\UNC\` as part of the volume.
        if path_has_prefix_fold(bytes, br"\\.\UNC") {
            return unc_len(bytes, br"\\.\UNC\".len());
        }
        // Local / Root Local Device: `\\.` / `\\?` / `\??`.
        // The next component after the 3-byte prefix is part of the
        // volume, so `\\?\C:` (6) and `\??\C:` (6) both include the
        // `C:` segment as volume. Exact match (len == 3) returns 3.
        if path_has_prefix_fold(bytes, br"\\.")
            || path_has_prefix_fold(bytes, br"\\?")
            || path_has_prefix_fold(bytes, br"\??")
        {
            if bytes.len() == 3 {
                return 3;
            }
            // Go: `_, rest, ok := cutPath(path[4:])`. Prefix + sep is
            // 4 bytes (`\\?\`, `\??\`, etc.). If `path[4:]` is empty,
            // cutPath returns ok=false and Go returns len(path).
            if 4 >= bytes.len() {
                return bytes.len();
            }
            let tail = &bytes[4..];
            match cut_first_separator(tail) {
                None => bytes.len(),
                Some((_before_end, after_start_in_tail)) => {
                    // Go: `return len(path) - len(rest) - 1`.
                    let rest_len = tail.len() - after_start_in_tail;
                    bytes.len() - rest_len - 1
                }
            }
        } else if bytes.len() >= 2 && is_path_separator_byte(bytes[1]) {
            // Two-leading-separator UNC: `\\HOST\SHARE...`.
            unc_len(bytes, 2)
        } else {
            0
        }
    }
    #[cfg(not(windows))]
    {
        let _ = s;
        0
    }
}

#[cfg(windows)]
#[inline]
fn is_path_separator_byte(c: u8) -> bool {
    c == b'/' || c == b'\\'
}

#[cfg(windows)]
#[inline]
fn ascii_upper(c: u8) -> u8 {
    if c >= b'a' && c <= b'z' {
        c - 32
    } else {
        c
    }
}

/// Mirrors Go `pathHasPrefixFold`: ignore ASCII case on non-separator
/// bytes; treat any separator in `prefix` as matching any separator
/// in `s`; require `s[len(prefix)]` to be a separator if `s` is
/// strictly longer than `prefix`.
#[cfg(windows)]
fn path_has_prefix_fold(s: &[u8], prefix: &[u8]) -> bool {
    if s.len() < prefix.len() {
        return false;
    }
    for i in 0..prefix.len() {
        if is_path_separator_byte(prefix[i]) {
            if !is_path_separator_byte(s[i]) {
                return false;
            }
        } else if ascii_upper(prefix[i]) != ascii_upper(s[i]) {
            return false;
        }
    }
    if s.len() > prefix.len() && !is_path_separator_byte(s[prefix.len()]) {
        return false;
    }
    true
}

/// Mirrors Go `uncLen`: returns the index of the second path
/// separator at or after `prefix_len`. If fewer than two separators
/// remain, returns `path.len()` (matches Go's fall-through).
#[cfg(windows)]
fn unc_len(path: &[u8], prefix_len: usize) -> usize {
    let mut count = 0usize;
    let mut i = prefix_len;
    while i < path.len() {
        if is_path_separator_byte(path[i]) {
            count += 1;
            if count == 2 {
                return i;
            }
        }
        i += 1;
    }
    path.len()
}

/// Mirrors Go `cutPath`: scan for the first separator in `tail`;
/// return `Some((before_end, after_start))` with slicing indices
/// into `tail`. `None` means no separator exists in `tail`.
#[cfg(windows)]
fn cut_first_separator(tail: &[u8]) -> Option<(usize, usize)> {
    for (i, &b) in tail.iter().enumerate() {
        if is_path_separator_byte(b) {
            return Some((i, i + 1));
        }
    }
    None
}

/// Lexical path cleanup mirroring Go's `path/filepath::Clean` for the
/// `--data-dir` path shapes `normalize_data_dir` passes in (drive,
/// UNC, Local Device, Root Local Device, POSIX absolute, and
/// relative paths with `.` / `..` segments). Performs no syscalls —
/// `..` is collapsed against the preceding component textually, NOT
/// through symlink resolution.
///
/// Reached only through `normalize_data_dir`, which has three call
/// sites: `cfg.data_dir` and `cfg.genesis_file` at the CLI parse site
/// (`main.rs`), so every subsystem deriving a path from either sees an
/// already-normalised value, and `read_config_file_to_string`, which
/// re-normalises the genesis path on every read. The genesis path is
/// therefore cleaned TWICE by design — the call is idempotent, and the
/// helper's own call is the ONLY one for direct and `lib.rs`-re-exported
/// callers that never pass through CLI parsing. Deleting either is a
/// regression; see the note at the `main.rs` site.
/// Without this step, a path like `link/../foo` where `link` is a
/// symlink to another directory would resolve via the symlink at
/// `stat()` time, reading a file under the symlink target instead
/// of the local `foo`; applying the lexical cleanup once at CLI
/// keeps cross-client behaviour aligned for operator-supplied
/// `--data-dir` values that may contain `..` segments combined with
/// symlinks anywhere along the resolved chain.
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
    let rooted = rest.chars().next().is_some_and(is_sep);

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
    // Append the `.` fallback only for the cases where Go's `Clean`
    // actually emits one:
    //   - No volume, no root, no parts: plain relative current-dir.
    //   - Drive-letter volume (e.g. `C:`) with empty rest: Go's
    //     `Clean("C:") = "C:."` (drive-relative current on that drive).
    // UNC / DOS-device volume roots (any prefix starting with two
    // path separators: `\\HOST\SHARE`, `\\?\UNC\HOST\SHARE`,
    // `\\?\C:`) must NOT receive the trailing `.` — Go returns the
    // volume unchanged there (`filepath.Clean("\\\\server\\share")` =
    // `"\\\\server\\share"`). Without this guard a UNC volume-only
    // input would be rewritten to `"\\\\server\\share."`, which is a
    // different (and invalid) path.
    let starts_with_double_sep = {
        let bytes = input.as_bytes();
        bytes.len() >= 2 && is_sep(bytes[0] as char) && is_sep(bytes[1] as char)
    };
    if out.len() == vol.len() && !rooted && !starts_with_double_sep {
        out.push('.');
    }
    // Mirror Go's `return FromSlash(out.string())` at the end of
    // Clean: on Windows every `/` is replaced with the OS
    // separator `\`. This canonicalises Windows inputs whose
    // volume prefix came in with forward slashes (e.g.
    // `//host/share/foo` → `\\host\share\foo`) and any `/` that
    // snuck through inside the vol copy. On Unix `MAIN_SEPARATOR`
    // is `/` so this pass is a no-op (we still guard it with
    // `cfg(windows)` to keep the output verbatim on non-Windows).
    #[cfg(windows)]
    {
        out = out.replace('/', "\\");
    }

    // Go `postClean` (path_windows.go:302) — protect against a
    // relative path being lexically reduced into an absolute /
    // rooted shape. Only runs when `vol_len == 0` (input had no
    // recognised volume), mirroring Go's guard
    // `if out.volLen != 0 || out.buf == nil { return }`.
    //
    // Two cases Go defends against:
    //
    // 1. First path element contains `:` before any separator —
    //    e.g. `a/../c:` lexically reduces to `c:` which Windows
    //    would interpret as a drive-relative reference. Prepend
    //    `.` + separator so the result stays relative: `.\c:`.
    //
    // 2. Output starts with `\??` (Root Local Device prefix) after
    //    lexical reduction — e.g. `\a\..\??\c:\x` reduces to
    //    `\??\c:\x`, which would be read as `c:\x` via the NT
    //    namespace. Prepend separator + `.` so the result is
    //    `\.\??\c:\x` and the `\??\` is neutralised.
    //
    // Both prepends preserve the lexical result bytes intact; they
    // only neutralise the Windows-specific interpretation. On Unix
    // these shapes are not meaningful but the prepend is still
    // harmless for the resulting string.
    #[cfg(windows)]
    {
        if vol_len == 0 && !out.is_empty() {
            let bytes = out.as_bytes();
            // Case 1: `:` in first segment before any separator.
            let mut first_segment_has_colon = false;
            for &b in bytes.iter() {
                if is_sep(b as char) {
                    break;
                }
                if b == b':' {
                    first_segment_has_colon = true;
                    break;
                }
            }
            if first_segment_has_colon {
                let mut prepended = String::with_capacity(out.len() + 2);
                prepended.push('.');
                prepended.push(sep);
                prepended.push_str(&out);
                out = prepended;
            } else if bytes.len() >= 3
                && is_sep(bytes[0] as char)
                && bytes[1] == b'?'
                && bytes[2] == b'?'
            {
                // Case 2: starts with `\??`.
                let mut prepended = String::with_capacity(out.len() + 2);
                prepended.push(sep);
                prepended.push('.');
                prepended.push_str(&out);
                out = prepended;
            }
        }
    }
    out
}

/// Normalise an operator-supplied path. THREE call sites, despite the
/// `data_dir` name:
///
///   - `--data-dir`, cleaned once at the CLI parse site so every
///     subsystem that derives a path from it (`ChainState::save` /
///     `load_chain_state`, `BlockStore::open` and its blocks /
///     headers / undo / index sub-directories, etc.) sees the same
///     already-cleaned root. With the root normalised once, internal
///     readers and writers stay on raw `fs::read` /
///     `write_file_atomic` and remain symmetric with each other —
///     no per-helper `lexical_clean` step can diverge between read
///     and write for operator paths crossing a symlink plus `..`.
///   - `--genesis-file`, at the same CLI parse site, so the path
///     `EffectiveConfig` REPORTS is the path that gets read.
///   - `--genesis-file` again, per read, inside
///     `read_config_file_to_string`.
///
/// The genesis path is deliberately cleaned TWICE. The call is
/// idempotent, and neither site subsumes the other: the CLI site is
/// what makes the reported path truthful, while the helper's own call
/// is the ONLY normalisation for direct callers and for the
/// `lib.rs`-re-exported `load_chain_id_from_genesis_file`, which never
/// passes through CLI parsing. Removing either is a regression, each
/// with its own pinning row. Neither genesis site is a datadir, and the
/// read/write asymmetry warned about above does not apply to them —
/// nothing writes that file.
///
/// If `path` is valid UTF-8, applies `lexical_clean` to its string
/// form and returns the cleaned `PathBuf`. If `path` is not valid
/// UTF-8, returns it unchanged: `lexical_clean` is string-based, and
/// preserving the original OS-native path avoids rejecting otherwise
/// valid non-UTF-8 filesystem paths on unusual setups.
pub fn normalize_data_dir(path: &Path) -> Result<PathBuf, String> {
    match path.to_str() {
        Some(s) => Ok(PathBuf::from(lexical_clean(s))),
        None => {
            // Non-UTF-8 path: `lexical_clean` is string-based and
            // cannot run on the raw bytes. Rather than hard-fail
            // startup for an otherwise valid OS-level path (on Unix
            // `PathBuf` can hold arbitrary bytes; `default_data_dir`
            // derives its path from `env::var_os("HOME")` which may
            // legitimately be non-UTF-8), pass the path through
            // unchanged. Plain `fs::read` / `fs::write` are
            // byte-transparent and worked on the pre-CLI-normalize
            // codebase for these paths, so we preserve that
            // compatibility. The cost for this edge case is that a
            // non-UTF-8 operator `--data-dir` with symlink+`..`
            // shapes bypasses the CLI-level lexical cleanup — rare
            // enough that we accept the trade-off over breaking
            // the startup path.
            Ok(path.to_path_buf())
        }
    }
}

// Historical note: `resolve_io_path_dir_leaf` and the ORIGINAL (unbounded,
// `lexical_clean`-applying) `read_file_by_path` / `write_file_atomic_by_path`
// used to sit here; CLI-level `normalize_data_dir` replaced that per-site
// cleaning strategy for the DATADIR tree and they were removed. RUB-1057
// reintroduced `read_file_by_path` above as a BOUNDED dir+leaf split reader,
// which applies no `lexical_clean` of its own. Of its two callers the
// blockstore write-if-absent verify seam passes an already-normalised
// datadir-derived path, while `read_config_file_to_string` (RUB-1069) cleans
// its operator-supplied path itself — per-site cleaning, deliberately, for
// the one read-only path that no CLI site normalises.

pub fn parse_hex32(name: &str, value: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(value).map_err(|e| format!("{name}: {e}"))?;
    if bytes.len() != 32 {
        return Err(format!("{name}: expected 32 bytes, got {}", bytes.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

pub(crate) const ATOMIC_WRITE_LOCK_LEAF: &str = ".rubin-atomic-write.lock";
pub(crate) const ATOMIC_WRITE_SCRATCH_LEAF: &str = ".rubin-atomic-write.tmp";
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AtomicWriteStage {
    BeforeNamespaceCommit,
    AfterNamespaceCommit,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AtomicWriteOperation {
    Overwrite,
    CreateIfAbsent,
}
#[derive(Clone, Debug)]
pub(crate) struct AtomicWriteError {
    pub(crate) stage: AtomicWriteStage,
    pub(crate) destination: PathBuf,
    pub(crate) operation: AtomicWriteOperation,
    pub(crate) primary: String,
    pub(crate) secondary: Vec<String>,
}
impl AtomicWriteError {
    fn new(
        stage: AtomicWriteStage,
        destination: &Path,
        operation: AtomicWriteOperation,
        primary: impl Into<String>,
    ) -> Self {
        Self {
            stage,
            destination: destination.to_path_buf(),
            operation,
            primary: primary.into(),
            secondary: Vec::new(),
        }
    }
    pub(crate) fn stage(&self) -> AtomicWriteStage {
        self.stage
    }
    fn append_secondary(&mut self, error: impl Into<String>) {
        self.secondary.push(error.into());
    }
}
impl std::fmt::Display for AtomicWriteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let stage = match self.stage {
            AtomicWriteStage::BeforeNamespaceCommit => "before_namespace_commit",
            AtomicWriteStage::AfterNamespaceCommit => "after_namespace_commit",
        };
        let operation = match self.operation {
            AtomicWriteOperation::Overwrite => "overwrite",
            AtomicWriteOperation::CreateIfAbsent => "create_if_absent",
        };
        write!(
            f,
            "{} (atomic write {stage} {operation} for {})",
            self.primary,
            self.destination.display()
        )?;
        if !self.secondary.is_empty() {
            write!(f, " (secondary: {})", self.secondary.join("; "))?;
        }
        Ok(())
    }
}
impl std::error::Error for AtomicWriteError {}
pub(crate) fn atomic_write_error_before(
    destination: &Path,
    operation: AtomicWriteOperation,
    primary: impl Into<String>,
) -> AtomicWriteError {
    AtomicWriteError::new(
        AtomicWriteStage::BeforeNamespaceCommit,
        destination,
        operation,
        primary,
    )
}
pub(crate) fn atomic_write_error_after(
    destination: &Path,
    operation: AtomicWriteOperation,
    primary: impl Into<String>,
) -> AtomicWriteError {
    AtomicWriteError::new(
        AtomicWriteStage::AfterNamespaceCommit,
        destination,
        operation,
        primary,
    )
}
pub(crate) fn is_atomic_write_post_commit(error: &AtomicWriteError) -> bool {
    error.stage() == AtomicWriteStage::AfterNamespaceCommit
}
static ATOMIC_WRITE_PROCESS_MUTEX: Mutex<()> = Mutex::new(());
#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AtomicWriteTestOp {
    PreUnlink,
    CleanupUnlink,
    ExclusiveOpen,
    Write,
    FileSync,
    Rename,
    HardLink,
    EexistDecision,
    ParentSync,
}

#[cfg(test)]
#[derive(Default)]
struct AtomicWriteTestState {
    operations: Vec<AtomicWriteTestOp>,
    failures: Vec<(AtomicWriteTestOp, usize, String)>,
}

#[cfg(test)]
thread_local! {
    static ATOMIC_WRITE_TEST_STATE: std::cell::RefCell<AtomicWriteTestState> =
        std::cell::RefCell::new(AtomicWriteTestState::default());
}

#[cfg(test)]
pub(crate) struct AtomicWriteTestScope;

#[cfg(test)]
impl AtomicWriteTestScope {
    pub(crate) fn new() -> Self {
        ATOMIC_WRITE_TEST_STATE.with(|state| *state.borrow_mut() = AtomicWriteTestState::default());
        Self
    }

    pub(crate) fn fail_at(&self, operation: AtomicWriteTestOp, occurrence: usize, error: &str) {
        ATOMIC_WRITE_TEST_STATE.with(|state| {
            state
                .borrow_mut()
                .failures
                .push((operation, occurrence, error.into()));
        });
    }

    pub(crate) fn operations(&self) -> Vec<AtomicWriteTestOp> {
        ATOMIC_WRITE_TEST_STATE.with(|state| state.borrow().operations.clone())
    }
}

#[cfg(test)]
impl Drop for AtomicWriteTestScope {
    fn drop(&mut self) {
        ATOMIC_WRITE_TEST_STATE.with(|state| *state.borrow_mut() = AtomicWriteTestState::default());
    }
}

#[cfg(test)]
fn atomic_write_test_step(operation: AtomicWriteTestOp) -> Result<(), String> {
    ATOMIC_WRITE_TEST_STATE.with(|state| {
        let mut state = state.borrow_mut();
        state.operations.push(operation);
        let occurrence = state
            .operations
            .iter()
            .filter(|&&op| op == operation)
            .count();
        match state
            .failures
            .iter()
            .position(|(expected, at, _)| *expected == operation && *at == occurrence)
        {
            Some(index) => Err(state.failures.remove(index).2),
            None => Ok(()),
        }
    })
}

pub(crate) fn validate_atomic_write_destination(
    path: &Path,
    operation: AtomicWriteOperation,
) -> Result<(), AtomicWriteError> {
    let reserved = path.file_name().is_some_and(|leaf| {
        leaf == std::ffi::OsStr::new(ATOMIC_WRITE_LOCK_LEAF)
            || leaf == std::ffi::OsStr::new(ATOMIC_WRITE_SCRATCH_LEAF)
    });
    if reserved {
        return Err(atomic_write_error_before(
            path,
            operation,
            format!(
                "reserved atomic persistence destination: {}",
                path.display()
            ),
        ));
    }
    Ok(())
}

#[cfg(test)]
pub fn write_file_atomic(path: &Path, data: &[u8]) -> Result<(), String> {
    write_file_atomic_typed(path, data).map_err(|error| error.to_string())
}

pub(crate) fn write_file_atomic_typed(path: &Path, data: &[u8]) -> Result<(), AtomicWriteError> {
    write_atomic_file(path, data, AtomicWriteOperation::Overwrite, || Ok(()))
}

pub(crate) fn write_file_create_if_absent<F>(
    path: &Path,
    data: &[u8],
    resolve_existing: F,
) -> Result<(), AtomicWriteError>
where
    F: FnOnce() -> Result<(), String>,
{
    write_atomic_file(
        path,
        data,
        AtomicWriteOperation::CreateIfAbsent,
        resolve_existing,
    )
}

fn write_atomic_file<F>(
    path: &Path,
    data: &[u8],
    operation: AtomicWriteOperation,
    resolve_existing: F,
) -> Result<(), AtomicWriteError>
where
    F: FnOnce() -> Result<(), String>,
{
    validate_atomic_write_destination(path, operation)?;
    let parent = effective_parent(path).ok_or_else(|| {
        atomic_write_error_before(path, operation, "atomic destination has no parent")
    })?;
    fs::create_dir_all(parent).map_err(|error| {
        atomic_write_error_before(
            path,
            operation,
            format!("create parent {}: {error}", parent.display()),
        )
    })?;

    let _process_guard = ATOMIC_WRITE_PROCESS_MUTEX.lock().map_err(|_| {
        atomic_write_error_before(path, operation, "atomic write process mutex is poisoned")
    })?;
    let lock_path = parent.join(ATOMIC_WRITE_LOCK_LEAF);
    let _parent_lock = atomic_file_lock::acquire(&lock_path).map_err(|error| {
        atomic_write_error_before(
            path,
            operation,
            format!(
                "atomic write lock failed: {}: {:?}: {}",
                parent.display(),
                error.class(),
                error.cause()
            ),
        )
    })?;
    write_atomic_file_locked(path, data, parent, operation, resolve_existing)
}

fn write_atomic_file_locked<F>(
    path: &Path,
    data: &[u8],
    parent: &Path,
    operation: AtomicWriteOperation,
    resolve_existing: F,
) -> Result<(), AtomicWriteError>
where
    F: FnOnce() -> Result<(), String>,
{
    let scratch = parent.join(ATOMIC_WRITE_SCRATCH_LEAF);
    if let Err(error) = pre_unlink_atomic_scratch(&scratch) {
        return Err(atomic_write_error_before(path, operation, error));
    }

    let mut file = match open_atomic_scratch(&scratch) {
        Ok(file) => file,
        Err(error) => return Err(pre_commit_failure(path, operation, parent, &scratch, error)),
    };
    let write_result: Result<(), String> = (|| {
        #[cfg(test)]
        atomic_write_test_step(AtomicWriteTestOp::Write)?;
        file.write_all(data)
            .map_err(|error| format!("write atomic scratch {}: {error}", scratch.display()))?;
        #[cfg(test)]
        atomic_write_test_step(AtomicWriteTestOp::FileSync)?;
        file.sync_all()
            .map_err(|error| format!("sync atomic scratch {}: {error}", scratch.display()))
    })();
    drop(file);
    if let Err(primary) = write_result {
        return Err(pre_commit_failure(
            path, operation, parent, &scratch, primary,
        ));
    }

    match operation {
        AtomicWriteOperation::Overwrite => {
            #[cfg(test)]
            if let Err(error) = atomic_write_test_step(AtomicWriteTestOp::Rename) {
                return Err(pre_commit_failure(path, operation, parent, &scratch, error));
            }
            if let Err(error) = fs::rename(&scratch, path) {
                return Err(pre_commit_failure(
                    path,
                    operation,
                    parent,
                    &scratch,
                    format!(
                        "rename atomic scratch {} -> {}: {error}",
                        scratch.display(),
                        path.display()
                    ),
                ));
            }
        }
        AtomicWriteOperation::CreateIfAbsent => {
            #[cfg(test)]
            if let Err(error) = atomic_write_test_step(AtomicWriteTestOp::HardLink) {
                return Err(pre_commit_failure(path, operation, parent, &scratch, error));
            }
            match fs::hard_link(&scratch, path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    #[cfg(test)]
                    if let Err(primary) = atomic_write_test_step(AtomicWriteTestOp::EexistDecision)
                    {
                        return Err(pre_commit_failure(
                            path, operation, parent, &scratch, primary,
                        ));
                    }
                    if let Err(primary) = resolve_existing() {
                        return Err(pre_commit_failure(
                            path, operation, parent, &scratch, primary,
                        ));
                    }
                }
                Err(error) => {
                    return Err(pre_commit_failure(
                        path,
                        operation,
                        parent,
                        &scratch,
                        format!(
                            "link atomic scratch {} -> {}: {error}",
                            scratch.display(),
                            path.display()
                        ),
                    ));
                }
            }
        }
    }

    post_commit_cleanup(path, operation, parent, &scratch)
}

fn pre_commit_failure(
    destination: &Path,
    operation: AtomicWriteOperation,
    parent: &Path,
    scratch: &Path,
    primary: impl Into<String>,
) -> AtomicWriteError {
    let mut error = atomic_write_error_before(destination, operation, primary);
    if let Err(cleanup) = cleanup_atomic_scratch(scratch) {
        error.append_secondary(cleanup);
    }
    if let Err(sync) = sync_atomic_parent(parent) {
        error.append_secondary(sync);
    }
    error
}

fn post_commit_cleanup(
    destination: &Path,
    operation: AtomicWriteOperation,
    parent: &Path,
    scratch: &Path,
) -> Result<(), AtomicWriteError> {
    let mut result: Option<AtomicWriteError> = None;
    if let Err(cleanup) = cleanup_atomic_scratch(scratch) {
        result = Some(atomic_write_error_after(destination, operation, cleanup));
    }
    if let Err(sync) = sync_atomic_parent(parent) {
        match result.as_mut() {
            Some(error) => error.append_secondary(sync),
            None => result = Some(atomic_write_error_after(destination, operation, sync)),
        }
    }
    result.map_or(Ok(()), Err)
}

fn open_atomic_scratch(path: &Path) -> Result<fs::File, String> {
    #[cfg(test)]
    atomic_write_test_step(AtomicWriteTestOp::ExclusiveOpen)?;
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    let file = options
        .open(path)
        .map_err(|error| format!("open atomic scratch {}: {error}", path.display()))?;
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|error| format!("chmod atomic scratch {}: {error}", path.display()))?;
    }
    Ok(file)
}

fn pre_unlink_atomic_scratch(path: &Path) -> Result<(), String> {
    #[cfg(test)]
    atomic_write_test_step(AtomicWriteTestOp::PreUnlink)?;
    unlink_atomic_scratch(path)
}

fn cleanup_atomic_scratch(path: &Path) -> Result<(), String> {
    #[cfg(test)]
    atomic_write_test_step(AtomicWriteTestOp::CleanupUnlink)?;
    unlink_atomic_scratch(path)
}

fn unlink_atomic_scratch(path: &Path) -> Result<(), String> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("unlink atomic scratch {}: {error}", path.display())),
    }
}

pub(crate) fn reclaim_atomic_write_parent(parent: &Path) -> Result<(), String> {
    let _process_guard = ATOMIC_WRITE_PROCESS_MUTEX
        .lock()
        .map_err(|_| reclaim_error(parent, "atomic write process mutex is poisoned"))?;
    let lock_path = parent.join(ATOMIC_WRITE_LOCK_LEAF);
    let _parent_lock = atomic_file_lock::acquire(&lock_path).map_err(|error| {
        reclaim_error(
            parent,
            format!(
                "atomic write lock failed: {:?}: {}",
                error.class(),
                error.cause()
            ),
        )
    })?;
    pre_unlink_atomic_scratch(&parent.join(ATOMIC_WRITE_SCRATCH_LEAF))
        .map_err(|error| reclaim_error(parent, error))?;
    sync_atomic_parent(parent).map_err(|error| reclaim_error(parent, error))
}

pub(crate) fn reclaim_atomic_write_scratch(data_dir: &Path) -> Result<(), String> {
    let blockstore = data_dir.join("blockstore");
    let parents = [
        data_dir.to_path_buf(),
        blockstore.clone(),
        blockstore.join("blocks"),
        blockstore.join("headers"),
        blockstore.join("undo"),
    ];
    for parent in parents {
        reclaim_atomic_write_parent(&parent)?;
    }
    Ok(())
}

fn reclaim_error(parent: &Path, cause: impl std::fmt::Display) -> String {
    format!(
        "atomic scratch reclaim failed: {}: {cause}",
        parent.display()
    )
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

pub fn sync_dir(dir: &Path) -> Result<(), String> {
    fs::OpenOptions::new()
        .read(true)
        .open(dir)
        .map_err(|error| format!("open dir {}: {error}", dir.display()))?
        .sync_all()
        .map_err(|error| format!("sync dir {}: {error}", dir.display()))
}

pub(crate) fn sync_atomic_parent(parent: &Path) -> Result<(), String> {
    #[cfg(test)]
    atomic_write_test_step(AtomicWriteTestOp::ParentSync)?;
    sync_dir(parent)
}

/// Create a hole-only sparse file of the nominal size (no data blocks
/// written; passes on APFS/ext4/tmpfs). Panics if the filesystem does not
/// report the nominal size back (Go's twin skips instead).
#[cfg(test)]
pub(crate) fn create_sparse_file(path: &Path, size: u64) {
    let f = fs::File::create(path).expect("create sparse");
    f.set_len(size).expect("sparse set_len");
    drop(f);
    assert_eq!(fs::metadata(path).expect("stat sparse").len(), size);
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
        create_sparse_file, lexical_clean, read_capped, read_config_file_to_string,
        read_file_from_dir, sync_dir, unique_temp_path, volume_prefix_len, write_file_atomic,
        write_file_atomic_typed, write_file_create_if_absent, AtomicWriteOperation,
        AtomicWriteStage, AtomicWriteTestOp, AtomicWriteTestScope, ATOMIC_WRITE_PROCESS_MUTEX,
        ATOMIC_WRITE_SCRATCH_LEAF, BLOCK_FILE_MAX_BYTES, CONFIG_FILE_MAX_BYTES,
        STORE_FILE_TOO_LARGE_PREFIX,
    };
    use std::fs;
    use std::io::{Cursor, Read};

    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct OperatorPathFixture {
        contract_version: u64,
        fixture_kind: String,
        description: String,
        cases: Vec<OperatorPathCase>,
    }

    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct OperatorPathCase {
        id: String,
        input: String,
        expected_unix: String,
    }

    /// Small injectable bound for the RUB-1057 corpus rows.
    const TEST_READ_BOUND: u64 = 8;

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
            match read_file_from_dir(&dir, bad, TEST_READ_BOUND) {
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
            // Go's `filepath.Base(name) != name` guard rejects ANY
            // byte at position 0 paired with `:` at position 1 —
            // Go's volumeNameLen matches `path[1] == ':'` without
            // letter enforcement. Cover the non-alphabetic vectors
            // to pin the same coverage.
            "1:foo",
            "_:foo",
            "0:",
        ] {
            match read_file_from_dir(&dir, bad, TEST_READ_BOUND) {
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

        let got = read_file_from_dir(&dir, leaf, TEST_READ_BOUND).expect("read leaf");
        assert_eq!(got, b"hi");

        let _ = fs::remove_dir_all(&dir);
    }

    /// RUB-1057 corpus: empty and at-bound files read back byte-identically;
    /// bound+1 is the typed refusal — kind `InvalidData` (never `NotFound`,
    /// so no absent-file fallback can match) + stable prefix.
    #[test]
    fn read_file_from_dir_enforces_class_bound() {
        let dir = unique_temp_path("rubin-io-bound");
        fs::create_dir_all(&dir).expect("create test dir");
        let rows: [(&str, u64, bool); 3] = [
            ("empty", 0, false),
            ("at", TEST_READ_BOUND, false),
            ("over", TEST_READ_BOUND + 1, true),
        ];
        for (name, len, over) in rows {
            fs::write(dir.join(name), vec![0xa5u8; len as usize]).expect("seed");
            match read_file_from_dir(&dir, name, TEST_READ_BOUND) {
                Ok(got) => {
                    assert!(!over, "{name}: over-bound accepted");
                    assert_eq!(got, vec![0xa5u8; len as usize]);
                }
                Err(e) => {
                    assert!(over, "{name}: unexpected error {e}");
                    assert_eq!(e.kind(), std::io::ErrorKind::InvalidData);
                    assert_ne!(e.kind(), std::io::ErrorKind::NotFound);
                    assert!(
                        e.to_string().starts_with(STORE_FILE_TOO_LARGE_PREFIX),
                        "{e}"
                    );
                }
            }
        }
        let _ = fs::remove_dir_all(&dir);
    }

    /// Pins the three frozen cross-client bound values; a red row means the
    /// cross-client contract number drifted, not a local tuning knob.
    /// De-scaled stand-in for the removed at-production-bound row of the undo
    /// class: that caller shares the bounded reader at these hard-wired
    /// constants, and its at/over verdicts run at small injectable bounds in
    /// this module. The chainstate snapshot and index marker are deliberately
    /// absent — they grow with accumulated state and admit no fixed ceiling,
    /// a standing decision recorded on `read_file_from_dir_unbounded` rather
    /// than a gap awaiting an owner. The write-if-absent verify reads have no
    /// constant of their own: they are bounded by the length of the content
    /// being written. Go twin:
    /// `TestSafeIOClassBoundConstantsPinFrozenValues`.
    #[test]
    fn class_bound_constants_pin_frozen_values() {
        assert_eq!(BLOCK_FILE_MAX_BYTES, 72_000_000);
        assert_eq!(super::HEADER_FILE_MAX_BYTES, 116);
        assert_eq!(super::UNDO_FILE_MAX_BYTES, 2_000_000_000);
    }

    /// Pins THIS client's ceiling against the agreed literal; the derivation
    /// lives on `CONFIG_FILE_MAX_BYTES`. It compares a Rust constant to a Rust
    /// literal, so it cannot observe Go and a red row does not mean "drifted
    /// from Go" — it means this client's constant moved off the agreed number.
    /// The cross-client binding is the shared literal plus the two doc blocks;
    /// Go pins its own side the same way, in
    /// `TestReadFileConfigBoundPinsDerivedValue`.
    #[test]
    fn config_bound_pins_derived_value() {
        assert_eq!(CONFIG_FILE_MAX_BYTES, 1 << 24);
    }

    /// At-bound and over-bound VERDICTS at the config helper, run against the
    /// PRODUCTION constant (not an injectable bound) so the row pins the real
    /// ceiling: at-bound read whole, one byte over refused. It observes only
    /// the final `Result`, so it does not itself prove the refusal lands
    /// BEFORE allocation — an allocate-then-refuse implementation would pass
    /// it. That ordering is enforced in `read_capped` and covered by
    /// RUB-1057's rows. Go twin: `TestReadFileConfigBoundAtAndOverBound`.
    #[test]
    fn config_read_at_and_over_bound() {
        let dir = unique_temp_path("rubin-io-utils-config-bound");
        fs::create_dir_all(&dir).expect("create test dir");

        let at = dir.join("at.json");
        create_sparse_file(&at, CONFIG_FILE_MAX_BYTES);
        let raw = read_config_file_to_string(&at).expect("at-bound config must be read whole");
        assert_eq!(raw.len() as u64, CONFIG_FILE_MAX_BYTES);

        let over = dir.join("over.json");
        create_sparse_file(&over, CONFIG_FILE_MAX_BYTES + 1);
        let err = read_config_file_to_string(&over).expect_err("over-bound config must refuse");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert!(
            err.to_string().contains(STORE_FILE_TOO_LARGE_PREFIX),
            "unexpected over-bound error: {err}"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    /// Path shapes at the config helper: every row asserts THIS client's
    /// outcome equals the Go NODE's, each Go verdict measured by driving
    /// `ReadConfigFile(filepath.Clean(path))` — the shape both Go callers use
    /// (`cmd/rubin-node/main.go`) — so the column records what an operator
    /// actually gets rather than what the bare Go helper does.
    ///
    /// The four accepting rows assert the accepted CONTENT, not merely that
    /// the read succeeded, because the last of them is about WHICH FILE is
    /// read: unnormalized, `Path::parent()` leaves `link/..` for the kernel to
    /// resolve and this client loaded a different file than Go did. The three
    /// `None` rows pin REJECTION ONLY — any `Err` satisfies them, so they do
    /// not distinguish an is-a-directory refusal from a normalization that
    /// failed outright.
    ///
    /// These measured rows are the evidence for the agreement.
    /// `lexical_clean_matches_go_filepath_clean` does NOT bind it: that test
    /// is a table of Rust literals and never executes Go.
    #[cfg(unix)]
    #[test]
    fn config_read_path_shapes_match_go_node() {
        use std::path::PathBuf;
        let dir = unique_temp_path("rubin-io-utils-config-shapes");
        fs::create_dir_all(dir.join("sub")).expect("create test dir");
        fs::create_dir_all(dir.join("other/real")).expect("create link target");
        let file = dir.join("cfg.json");
        fs::write(&file, b"{}").expect("write config");
        std::os::unix::fs::symlink(dir.join("absent"), dir.join("dangling")).expect("symlink");
        // `sub/link` -> `other/real`, so `sub/link/..` folds LEXICALLY to
        // `sub` but resolves through the KERNEL to `other`.
        fs::write(dir.join("sub/genesis.json"), b"LEXICAL").expect("write lexical");
        fs::write(dir.join("other/genesis.json"), b"KERNEL").expect("write kernel");
        std::os::unix::fs::symlink(dir.join("other/real"), dir.join("sub/link")).expect("symlink");
        let f = file.display().to_string();
        // (path, expected content when accepted) with the measured Go verdict.
        let rows: [(PathBuf, Option<&str>); 7] = [
            (file.clone(), Some("{}")),                    // Go node: ACCEPT "{}"
            (PathBuf::from(format!("{f}/")), Some("{}")),  // Go node: ACCEPT "{}"
            (PathBuf::from(format!("{f}/.")), Some("{}")), // Go node: ACCEPT "{}"
            (PathBuf::from(format!("{f}/..")), None),      // Go node: REJECT is a directory
            (dir.join("sub"), None),                       // Go node: REJECT is a directory
            (dir.join("dangling"), None),                  // Go node: REJECT no such file
            (dir.join("sub/link/../genesis.json"), Some("LEXICAL")), // Go node: ACCEPT "LEXICAL"
        ];
        for (path, want) in rows {
            assert_eq!(
                read_config_file_to_string(&path).ok().as_deref(),
                want,
                "outcome diverges from the Go node for {}",
                path.display()
            );
        }
        let _ = fs::remove_dir_all(&dir);
    }

    /// The encoding refusal must be PRESERVED, not merely kept in the same
    /// class: what an operator sees is this string interpolated into
    /// `read genesis file {path}: {e}` at both call sites, so the row pins the
    /// exact message `fs::read_to_string` produced before the bound. Asserting
    /// only the kind would let a reworded literal — including one that adopted
    /// the size prefix — pass while the behaviour changed.
    ///
    /// Cross-client: merged Go `ReadConfigFile` ACCEPTS these bytes (measured:
    /// nil error, 3 bytes) because it returns `[]byte` and leaves encoding to
    /// the caller, so the refusal lands one layer later at `json.Unmarshal`.
    /// Rust refuses at the helper, whose callers both want `String`. Both call
    /// sites end in an error — the layer differs, not the operator verdict.
    #[test]
    fn config_read_rejects_non_utf8_without_size_prefix() {
        let dir = unique_temp_path("rubin-io-utils-config-utf8");
        fs::create_dir_all(&dir).expect("create test dir");

        let path = dir.join("bad.json");
        fs::write(&path, [0xffu8, 0xfe, 0x00]).expect("write non-utf8");
        let err = read_config_file_to_string(&path).expect_err("non-utf8 config must refuse");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert_eq!(err.to_string(), "stream did not contain valid UTF-8");
        // Anchor against the reader these call sites used before the bound,
        // on the SAME file: asserting our literal against our literal could
        // not detect us drifting away from what `read_to_string` says.
        let std_err = fs::read_to_string(&path).expect_err("std must refuse too");
        assert_eq!(err.kind(), std_err.kind());
        assert_eq!(err.to_string(), std_err.to_string());

        let _ = fs::remove_dir_all(&dir);
    }

    /// Write/read symmetry guard row for the undo class (the one guarded
    /// write path — block and header sizes are already fixed by the wire
    /// format) with small synthetic numbers: at bound the save proceeds, one
    /// byte over refuses with the shared class prefix and a clearly save-side
    /// message. Go twin: `TestSafeIOStoreSaveBoundRefusesOverBound`.
    #[test]
    fn check_store_save_bound_refuses_over_bound() {
        super::check_store_save_bound("undo", TEST_READ_BOUND as usize, TEST_READ_BOUND)
            .expect("at bound");
        let err =
            super::check_store_save_bound("undo", TEST_READ_BOUND as usize + 1, TEST_READ_BOUND)
                .unwrap_err();
        assert!(
            err.starts_with("refusing to save") && err.contains(STORE_FILE_TOO_LARGE_PREFIX),
            "{err}"
        );
    }

    struct CountingReader {
        data: Cursor<Vec<u8>>,
        reads: usize,
    }
    impl Read for CountingReader {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.reads += 1;
            self.data.read(buf)
        }
    }

    /// Stat/read race pin on the testable core (Go twin:
    /// `TestSafeIOReadAllCappedPinsStatReadRace`): an over-bound stat size
    /// is refused WITHOUT reading content; a stat that lies LOW (file grew
    /// after stat) is still refused by the bound+1 limiter instead of being
    /// truncated; a stat that lies HIGH (file shrank) returns the bytes.
    #[test]
    fn read_capped_pins_stat_read_race() {
        let bytes = b"0123456789".to_vec();
        let mut r = CountingReader {
            data: Cursor::new(bytes.clone()),
            reads: 0,
        };
        let err = read_capped(&mut r, "f", 6, 5).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert_eq!(r.reads, 0, "content was read despite over-bound stat");
        let err = read_capped(Cursor::new(bytes.clone()), "f", 2, 5).unwrap_err();
        assert!(
            err.to_string().starts_with(STORE_FILE_TOO_LARGE_PREFIX),
            "{err}"
        );
        let got = read_capped(Cursor::new(b"012".to_vec()), "f", 8, 8).expect("shrank");
        assert_eq!(got, b"012");
    }

    /// Feeds `total` bytes regardless of what it claimed to Stat, recording the
    /// largest slice it was ever offered — that offered length is
    /// `capacity - filled`, so it exposes the buffer's growth profile from
    /// outside.
    struct GrowthProbeReader {
        left: usize,
        max_offer: usize,
    }
    impl Read for GrowthProbeReader {
        fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
            self.max_offer = self.max_offer.max(b.len());
            if self.left == 0 {
                return Ok(0);
            }
            let n = b.len().min(self.left);
            b[..n].fill(0xa5);
            self.left -= n;
            Ok(n)
        }
    }

    /// RUB-1057: the ACCEPTED stat/read race must stay accepted — a file that
    /// grew between stat and read but still fits the bound is returned IN
    /// FULL, exactly as Go's `readCapped` does. Turning this into a refusal
    /// would be a live cross-client divergence. The same row pins the
    /// allocation ceiling: capacity must never exceed
    /// `cap_hint(max_bytes, max_bytes)`. Under std's `read_to_end` the
    /// amortized doubling lands at 8192 for these numbers — above the 5001
    /// ceiling — so this row is falsifiable.
    #[test]
    fn read_capped_grown_file_is_returned_in_full_within_the_ceiling() {
        const MAX: u64 = 5000;
        let limit = super::cap_hint(MAX, MAX);
        let mut r = GrowthProbeReader {
            left: MAX as usize,
            max_offer: 0,
        };
        // Stat lied low (2); the reader actually yields exactly MAX bytes.
        let got =
            read_capped(&mut r, "f", 2, MAX).expect("grown-but-fitting file must be accepted");
        assert_eq!(got.len(), MAX as usize, "full bytes must be returned");
        assert!(got.iter().all(|b| *b == 0xa5), "bytes must be intact");
        assert!(
            got.capacity() <= limit,
            "capacity {} exceeds the class ceiling {limit}",
            got.capacity()
        );
    }

    /// The same race one byte over the bound is still refused with the typed
    /// error, and the buffer still never grows past the ceiling: the largest
    /// slice offered to the reader (== capacity - filled) stays within it.
    /// Under `read_to_end` the offered slices follow std's doubling and
    /// exceed the ceiling, so this row is falsifiable too.
    #[test]
    fn read_capped_over_bound_growth_stays_within_the_ceiling() {
        const MAX: u64 = 4096;
        let limit = super::cap_hint(MAX, MAX);
        let mut r = GrowthProbeReader {
            left: MAX as usize + 1,
            max_offer: 0,
        };
        let err = read_capped(&mut r, "f", 2, MAX).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert!(
            err.to_string().starts_with(STORE_FILE_TOO_LARGE_PREFIX),
            "{err}"
        );
        assert!(
            r.max_offer <= limit,
            "offered slice {} exceeds the class ceiling {limit}",
            r.max_offer
        );
    }

    /// `grow_capacity` is the line-by-line twin of Go's `growCapacity`: the
    /// limit is the default, the doubling is taken only when it fits, and the
    /// 512 floor is itself clamped so a small class (header: limit 117) never
    /// receives an oversized buffer.
    #[test]
    fn grow_capacity_mirrors_the_go_ceiling_rule() {
        const MAX: u64 = 1 << 20;
        let limit = super::cap_hint(MAX, MAX);
        assert_eq!(super::grow_capacity(0, MAX), 512);
        assert_eq!(super::grow_capacity(4, MAX), 512);
        assert_eq!(super::grow_capacity(1024, MAX), 2048);
        assert_eq!(super::grow_capacity(limit / 2 + 1, MAX), limit);
        assert_eq!(super::grow_capacity(limit, MAX), limit);
        assert_eq!(super::grow_capacity(usize::MAX, MAX), limit);
        // Small classes: the floor must never exceed the limit.
        for small in [super::HEADER_FILE_MAX_BYTES, 71, 0] {
            let small_limit = super::cap_hint(small, small);
            for current in [0, 1, small_limit] {
                assert!(
                    super::grow_capacity(current, small) <= small_limit,
                    "grow_capacity({current}, {small}) exceeds limit {small_limit}"
                );
            }
        }
    }

    /// A raw mid-read failure surfaces unwrapped — never coerced into the
    /// size error (Go twin: `TestSafeIOReadAllCappedPropagatesRawErrors`;
    /// the Go stat-error row has no core-level Rust twin because the fstat
    /// happens on a real `File` in `read_file_from_dir`).
    #[test]
    fn read_capped_propagates_raw_read_error() {
        struct FailingReader;
        impl Read for FailingReader {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("probe failure"))
            }
        }
        let err = read_capped(FailingReader, "f", 4, 8).unwrap_err();
        assert_eq!(err.to_string(), "probe failure");
        assert_ne!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    /// One at-production-bound sanity row for the block class, via sparse
    /// hole-only files (Go twin: `TestReadFileFromDirBlockClassProductionBound`).
    #[test]
    fn read_file_from_dir_block_class_production_bound() {
        let dir = unique_temp_path("rubin-io-prod-bound");
        fs::create_dir_all(&dir).expect("create test dir");
        create_sparse_file(&dir.join("at.bin"), BLOCK_FILE_MAX_BYTES);
        let got = read_file_from_dir(&dir, "at.bin", BLOCK_FILE_MAX_BYTES).expect("at bound");
        assert_eq!(got.len() as u64, BLOCK_FILE_MAX_BYTES);
        create_sparse_file(&dir.join("over.bin"), BLOCK_FILE_MAX_BYTES + 1);
        let err = read_file_from_dir(&dir, "over.bin", BLOCK_FILE_MAX_BYTES).unwrap_err();
        assert!(
            err.to_string().starts_with(STORE_FILE_TOO_LARGE_PREFIX),
            "{err}"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// `read_file_by_path` edge arms: `/` has no parent and no leaf, so the
    /// empty-parent fallback (`_ => Path::new(".")`) runs and the missing-leaf
    /// arm refuses with InvalidInput; a non-UTF-8 leaf (unix) refuses the same
    /// way. The positive bare-filename mapping (`parent() == Some("")` -> `.`)
    /// is pinned by `effective_parent_maps_empty_parent_to_current_directory`.
    #[test]
    fn read_file_by_path_refuses_rootless_and_non_utf8_leaves() {
        use std::path::Path;
        let err = super::read_file_by_path(Path::new("/"), 8).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            let raw = std::ffi::OsStr::from_bytes(b"/tmp/rubin-\xFF-leaf");
            let err = super::read_file_by_path(Path::new(raw), 8).unwrap_err();
            assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        }
    }

    /// Non-regular targets keep their pre-existing OS error classes — never
    /// the size refusal: a directory read fails with the raw is-a-directory
    /// error (its ~64B stat size passes any production bound) and a dangling
    /// symlink stays NotFound (absent-file class). Go twin:
    /// `TestReadFileFromDirNonRegularTargetsKeepOSErrorClasses`.
    #[cfg(unix)]
    #[test]
    fn read_file_from_dir_non_regular_targets_keep_os_error_classes() {
        let dir = unique_temp_path("rubin-io-nonreg");
        fs::create_dir_all(dir.join("sub")).expect("mkdir");
        let err = read_file_from_dir(&dir, "sub", BLOCK_FILE_MAX_BYTES).unwrap_err();
        assert!(
            !err.to_string().starts_with(STORE_FILE_TOO_LARGE_PREFIX)
                && err.kind() != std::io::ErrorKind::NotFound,
            "directory: {err}"
        );
        std::os::unix::fs::symlink(dir.join("absent"), dir.join("dangling")).expect("symlink");
        let err = read_file_from_dir(&dir, "dangling", BLOCK_FILE_MAX_BYTES).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
        let _ = fs::remove_dir_all(&dir);
    }

    /// `normalize_data_dir` must pass non-UTF-8 Unix paths through
    /// unchanged rather than hard-fail. On Unix `PathBuf` can hold
    /// arbitrary bytes (e.g. when `default_data_dir` derives the
    /// path from `env::var_os("HOME")` and `$HOME` is not valid
    /// UTF-8). Hard-failing here would regress startup for
    /// otherwise-valid OS-level paths that `fs::read` / `fs::write`
    /// handle correctly. The trade-off: non-UTF-8 operator
    /// `--data-dir` values bypass the lexical cleanup, which is
    /// acceptable for this rare edge case.
    #[cfg(unix)]
    #[test]
    fn normalize_data_dir_preserves_non_utf8_unix_path() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;
        use std::path::Path;

        // Bytes include a valid-looking prefix followed by an
        // invalid UTF-8 continuation byte (0xFF).
        let raw_bytes: &[u8] = b"/tmp/rubin-data-\xFFdir";
        let os_str = OsStr::from_bytes(raw_bytes);
        let input = Path::new(os_str);
        assert!(input.to_str().is_none(), "fixture must be non-UTF-8");

        let cleaned = super::normalize_data_dir(input)
            .expect("non-UTF-8 path must not hard-fail — falls through to raw");
        // Raw bytes are preserved verbatim — no `.` appending, no
        // separator rewriting, no UTF-8-lossy replacement.
        assert_eq!(cleaned.as_os_str().as_bytes(), raw_bytes);
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

    #[cfg(unix)]
    #[test]
    fn operator_path_normalization_fixture() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../../conformance/fixtures/protocol/operator_path_normalization_v1.json");
        let raw = fs::read_to_string(path).expect("read operator path fixture");
        let fixture: OperatorPathFixture = serde_json::from_str(&raw).expect("decode fixture");
        assert_eq!(fixture.contract_version, 1);
        assert_eq!(fixture.fixture_kind, "operator_path_normalization_v1");
        assert!(!fixture.description.trim().is_empty());
        #[rustfmt::skip]
        let required = [("empty", ""), ("dot", "."), ("parent", ".."), ("dot-prefix", "./name"), ("bare-name", "name"), ("repeated-separator", "a//b"), ("trailing-separator", "a/b/"), ("trailing-dot", "a/b/."), ("trailing-parent", "a/b/.."), ("mid-dot", "a/./b"), ("mid-parent", "a/x/../b"), ("absolute-root", "/"), ("rooted-parent", "/../name"), ("symlink-lexical", "sub/link/../genesis.json")];
        let mut seen = std::collections::HashSet::new();
        for case in fixture.cases {
            let (_, input) = required
                .iter()
                .find(|(id, _)| *id == case.id)
                .unwrap_or_else(|| panic!("unknown id {}", case.id));
            assert!(seen.insert(case.id.clone()), "duplicate id {}", case.id);
            assert_eq!(&case.input, input, "{} input", case.id);
            assert_eq!(
                lexical_clean(&case.input),
                case.expected_unix,
                "{}",
                case.id
            );
        }
        assert_eq!(seen.len(), required.len());
        for (id, _) in required {
            assert!(seen.contains(id), "missing id {id}");
        }
    }

    /// Windows UNC and DOS-device volume-only inputs must pass
    /// through `lexical_clean` unchanged. Go's `filepath.Clean`
    /// special-cases this: when the volume is the whole path and the
    /// input starts with two path separators (UNC / DOS device), the
    /// volume is returned as-is — NOT with a trailing `.` appended
    /// (that `.` fallback is only for no-volume empty results and for
    /// drive-letter-only inputs where Go returns `"C:."`).
    ///
    /// Without that special case a UNC volume root would be rewritten
    /// to a different (and invalid) path, e.g.
    /// `"\\\\server\\share"` → `"\\\\server\\share."`.
    #[cfg(windows)]
    #[test]
    fn lexical_clean_preserves_unc_volume_roots() {
        // Plain UNC volume root.
        assert_eq!(lexical_clean("\\\\server\\share"), "\\\\server\\share");
        // DOS-device UNC volume root.
        assert_eq!(
            lexical_clean("\\\\?\\UNC\\server\\share"),
            "\\\\?\\UNC\\server\\share"
        );
        // Drive-letter volume with empty rest still gets the `.`
        // (Go parity: `filepath.Clean("C:") = "C:."`).
        assert_eq!(lexical_clean("C:"), "C:.");
        // UNC volume root with trailing separator collapses the
        // trailing sep but keeps the volume intact.
        assert_eq!(lexical_clean("\\\\server\\share\\"), "\\\\server\\share\\");
    }

    /// `volume_prefix_len` must match Go `filepath.VolumeName` length
    /// on every path shape the `lexical_clean` helper may encounter.
    /// Reference: Go's own `volumenametests` table in
    /// `src/path/filepath/path_test.go` + `volumeNameLen` in
    /// `src/internal/filepathlite/path_windows.go`. Non-Windows input
    /// always returns 0.
    ///
    /// Case classes covered:
    /// - Drive letter (`C:`) — Go matches `path[1] == ':'` without
    ///   enforcing ASCII-letter range, so `1:`, `2:`, `:` (len<2) all
    ///   follow Go's own rule.
    /// - UNC (`\\HOST\SHARE`) — volume is through share (two seps).
    /// - Local Device UNC (`\\.\UNC\HOST\SHARE`) — case 3 in Go's
    ///   switch; UncLen-based, includes host + share.
    /// - Local / Root Local Device (`\\.\X`, `\\?\X`, `\??\X`) — next
    ///   segment after the 3-byte prefix is part of the volume. For
    ///   `\\?\UNC\host\share` this means volume = `\\?\UNC` (7), NOT
    ///   the full UNC path.
    /// - `\??\` specifically — Root Local Device; an earlier version
    ///   of this port missed it because it required two leading
    ///   separators, but Go's `pathHasPrefixFold` match works with a
    ///   single leading sep + `??`.
    /// - Malformed-prefix cases return `len(path)` (Go fail-closed).
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
            // Drive-letter family.
            assert_eq!(volume_prefix_len("C:"), 2);
            assert_eq!(volume_prefix_len("C:foo"), 2);
            assert_eq!(volume_prefix_len("C:\\"), 2);
            assert_eq!(volume_prefix_len("C:\\foo"), 2);
            assert_eq!(volume_prefix_len("c:\\foo"), 2);
            // Go matches `path[1] == ':'` without enforcing letter,
            // so `2:` IS a "drive-letter" shape per Go's own test
            // table (`{"2:", "2:"}`).
            assert_eq!(volume_prefix_len("2:"), 2);
            // One-byte / empty / no colon: 0.
            assert_eq!(volume_prefix_len(":foo"), 0);

            // Plain UNC (case 5: two leading seps + uncLen).
            assert_eq!(volume_prefix_len("\\\\host\\share"), 12);
            assert_eq!(volume_prefix_len("\\\\host\\share\\"), 12);
            assert_eq!(volume_prefix_len("\\\\host\\share\\foo"), 12);
            assert_eq!(volume_prefix_len("//host/share/foo"), 12);

            // Malformed UNC prefixes: Go returns `len(path)`.
            assert_eq!(volume_prefix_len("\\\\"), 2);
            assert_eq!(volume_prefix_len("\\\\host"), 6);
            assert_eq!(volume_prefix_len("\\\\host\\"), 7);

            // Local Device / Root Local Device (case 4): next
            // segment after the 3-byte prefix is volume.
            assert_eq!(volume_prefix_len("\\\\?\\C:"), 6);
            assert_eq!(volume_prefix_len("\\\\?\\C:\\foo"), 6);
            assert_eq!(volume_prefix_len("\\\\.\\C:"), 6);
            assert_eq!(volume_prefix_len("\\\\.\\C:\\foo"), 6);
            // Root Local Device via `\??\` — ONE leading sep + `??`.
            // Missed by the previous two-leading-separator-only
            // detector.
            assert_eq!(volume_prefix_len("\\??\\C:"), 6);
            assert_eq!(volume_prefix_len("\\??\\C:\\foo"), 6);
            assert_eq!(volume_prefix_len("\\??\\NUL"), 7);
            // Exact prefix length 3 → return 3.
            assert_eq!(volume_prefix_len("\\\\?"), 3);
            assert_eq!(volume_prefix_len("\\\\."), 3);
            assert_eq!(volume_prefix_len("\\??"), 3);
            // Empty tail after 4-byte prefix → full path length.
            assert_eq!(volume_prefix_len("\\\\?\\"), 4);
            assert_eq!(volume_prefix_len("\\??\\"), 4);

            // DOS-device UNC forward (case 3): only `\\.\UNC\` form.
            // `\\.\UNC\host\share` uses uncLen → full 18 chars.
            assert_eq!(volume_prefix_len("\\\\.\\UNC\\host\\share"), 18);
            assert_eq!(volume_prefix_len("\\\\.\\UNC\\host\\share\\foo"), 18);
            // `\\?\UNC\host\share` falls into case 4 (not case 3),
            // so volume is just `\\?\UNC` (7). This differs from the
            // previous port which incorrectly returned the full UNC
            // length here — Go's switch routes `\\?\UNC...` through
            // the Root Local Device arm, not the `\\.\UNC` arm.
            assert_eq!(volume_prefix_len("\\\\?\\UNC\\host\\share"), 7);
            assert_eq!(volume_prefix_len("\\\\?\\UNC\\host\\share\\foo"), 7);
            assert_eq!(volume_prefix_len("\\\\?\\UNC"), 7);
        }
    }

    /// `lexical_clean` must canonicalise forward slashes inside the
    /// VOLUME prefix on Windows — Go's `Clean` ends with
    /// `FromSlash(out.string())` which replaces every `/` with `\`.
    /// Inputs like `//host/share/foo` (UNC with forward slashes, a
    /// shape Windows accepts) must come out as `\\host\share\foo`,
    /// NOT `//host/share\foo` (which would mix separators and
    /// diverge from Go).
    #[cfg(windows)]
    #[test]
    fn lexical_clean_canonicalises_forward_slashes_in_volume_prefix() {
        // UNC with forward slashes in vol → backslash-canonical UNC.
        assert_eq!(lexical_clean("//host/share/foo"), "\\\\host\\share\\foo");
        // Trailing / on pure UNC vol stays a single trailing `\`.
        assert_eq!(lexical_clean("//host/share/"), "\\\\host\\share\\");
        // Mixed separators inside the path body collapse to `\`.
        assert_eq!(lexical_clean("C:/foo/bar"), "C:\\foo\\bar");
    }

    /// `lexical_clean` must apply Go's Windows `postClean` safeguard
    /// on a build targeting Windows: a relative input that lexically
    /// reduces into a path whose first segment contains `:` (e.g.
    /// `a/../C:\node` → `C:\node`) must be prepended with `.\` so the
    /// result stays relative (`.\C:\node`). Similarly, a path that
    /// lexically reduces to start with `\??` (Root Local Device
    /// prefix) must be prepended with `\.` to neutralise the NT
    /// namespace interpretation.
    ///
    /// Reference: Go `internal/filepathlite/path_windows.go::postClean`.
    /// Non-Windows builds do not run postClean — the result stays as
    /// the raw lexical reduction.
    #[cfg(windows)]
    #[test]
    fn lexical_clean_postclean_protects_against_drive_and_device_rewrites() {
        // Case 1: relative path reduces to drive-qualified shape.
        assert_eq!(lexical_clean("a/../C:\\node"), ".\\C:\\node");
        assert_eq!(lexical_clean("a\\..\\c:"), ".\\c:");
        // Case 2: relative path reduces to Root Local Device shape.
        assert_eq!(lexical_clean("\\a\\..\\??\\c:\\x"), "\\.\\??\\c:\\x");
        assert_eq!(lexical_clean("\\??\\c:\\x"), "\\??\\c:\\x"); // vol_len != 0
                                                                 // Sanity: a plain relative path with no colon / `\??` stays
                                                                 // unchanged by postClean.
        assert_eq!(lexical_clean("foo/bar"), "foo\\bar");
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

        let scope = AtomicWriteTestScope::new();
        write_file_atomic(&path, data).expect("write_file_atomic");
        assert_eq!(
            scope.operations(),
            [
                AtomicWriteTestOp::PreUnlink,
                AtomicWriteTestOp::ExclusiveOpen,
                AtomicWriteTestOp::Write,
                AtomicWriteTestOp::FileSync,
                AtomicWriteTestOp::Rename,
                AtomicWriteTestOp::CleanupUnlink,
                AtomicWriteTestOp::ParentSync,
            ]
        );

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

        assert!(
            !dir.join(ATOMIC_WRITE_SCRATCH_LEAF).exists(),
            "fixed atomic scratch remained after rename"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[rustfmt::skip]
    #[test]
    fn atomic_write_typed_failure_matrix_covers_five_destinations() {
        use AtomicWriteOperation::{CreateIfAbsent, Overwrite}; use AtomicWriteStage::{AfterNamespaceCommit, BeforeNamespaceCommit}; use AtomicWriteTestOp::*;
        let dir = unique_temp_path("rubin-atomic-typed"); fs::create_dir_all(&dir).expect("mkdir");
        let classes = [("blockstore/blocks/block.bin", CreateIfAbsent), ("blockstore/headers/header.bin", CreateIfAbsent), ("blockstore/undo/undo.bin", Overwrite), ("blockstore/index.json", Overwrite), ("chainstate.json", Overwrite)];
        let rows = [(PreUnlink, None), (ExclusiveOpen, Some([CleanupUnlink, ParentSync])), (Write, Some([CleanupUnlink, ParentSync])), (FileSync, Some([CleanupUnlink, ParentSync]))];
        let run = |path: &std::path::Path, operation, row, secondary: Option<[AtomicWriteTestOp; 2]>| {
            let scope = AtomicWriteTestScope::new(); scope.fail_at(row, 1, "primary"); if let Some(secondary) = secondary { scope.fail_at(secondary[0], 1, "cleanup"); scope.fail_at(secondary[1], 1, "parent"); } let error = match operation { Overwrite => write_file_atomic_typed(path, b"payload"), CreateIfAbsent => write_file_create_if_absent(path, b"payload", || Ok(())) }.expect_err("scripted error");
            assert_eq!((error.stage, error.destination, error.operation, error.primary), (BeforeNamespaceCommit, path.to_path_buf(), operation, "primary".into()));
            assert_eq!(error.secondary, secondary.map_or_else(Vec::new, |_| vec!["cleanup".to_string(), "parent".to_string()])); assert_eq!(scope.operations().first(), Some(&PreUnlink));
        };
        for (class, operation) in classes {
            for (row, secondary) in rows { let path = dir.join(format!("{row:?}/{class}")); run(&path, operation, row, secondary); }
            for row in match operation { Overwrite => &[Rename][..], CreateIfAbsent => &[HardLink, EexistDecision][..] } { let path = dir.join(format!("{row:?}/{class}")); if *row == EexistDecision { fs::create_dir_all(path.parent().expect("parent")).expect("mkdir parent"); fs::write(&path, b"existing").expect("seed eexist"); } run(&path, operation, *row, Some([CleanupUnlink, ParentSync])); }
            for (primary, secondary) in [(CleanupUnlink, Some(ParentSync)), (ParentSync, None)] { let path = dir.join(format!("post-{primary:?}/{class}")); let scope = AtomicWriteTestScope::new(); scope.fail_at(primary, 1, "primary"); if let Some(op) = secondary { scope.fail_at(op, 1, "secondary"); } let error = match operation { Overwrite => write_file_atomic_typed(&path, b"payload"), CreateIfAbsent => write_file_create_if_absent(&path, b"payload", || Ok(())) }.expect_err("postcommit error"); assert_eq!((error.stage, error.destination, error.operation, error.primary), (AfterNamespaceCommit, path, operation, "primary".into())); assert_eq!(error.secondary, secondary.map_or_else(Vec::new, |_| vec!["secondary".to_string()])); assert!(scope.operations().contains(&match operation { Overwrite => Rename, CreateIfAbsent => HardLink })); }
        } let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[rustfmt::skip]
    #[test]
    fn atomic_unlink_mode_and_process_serialization() {
        use super::unlink_atomic_scratch; use std::os::unix::{ffi::OsStrExt, fs::{MetadataExt, PermissionsExt, symlink}};
        struct Umask(libc::mode_t); impl Umask { fn set(mask: libc::mode_t) -> Self { Self(unsafe { libc::umask(mask) }) } } impl Drop for Umask { fn drop(&mut self) { unsafe { libc::umask(self.0); } } }
        let dir = unique_temp_path("rubin-atomic-unix"); fs::create_dir_all(&dir).expect("mkdir");
        let live = dir.join("live"); fs::write(&live, b"live").expect("live");
        for (leaf, make) in [("regular", 0), ("hardlink", 1), ("fifo", 2), ("symlink", 3), ("dangling", 4)] {
            let path = dir.join(leaf); match make { 0 => fs::write(&path, b"x").expect("regular"), 1 => fs::hard_link(&live, &path).expect("hardlink"), 2 => { let raw = std::ffi::CString::new(path.as_os_str().as_bytes()).expect("path"); assert_eq!(unsafe { libc::mkfifo(raw.as_ptr(), 0o600) }, 0); }, 3 => symlink(&live, &path).expect("symlink"), _ => symlink(dir.join("absent"), &path).expect("dangling") } unlink_atomic_scratch(&path).expect("unlink"); assert!(path.symlink_metadata().is_err()); assert_eq!(fs::read(&live).expect("live intact"), b"live");
        }
        let directory = dir.join("directory"); fs::create_dir(&directory).expect("directory"); assert!(unlink_atomic_scratch(&directory).is_err() && directory.is_dir());
        for mask in [0, 0o022, 0o077] {
            let _umask = Umask::set(mask); let scratch = dir.join(ATOMIC_WRITE_SCRATCH_LEAF); let dst = dir.join(format!("mode-{mask:o}"));
            let scope = AtomicWriteTestScope::new(); scope.fail_at(AtomicWriteTestOp::Write, 1, "write"); scope.fail_at(AtomicWriteTestOp::CleanupUnlink, 1, "keep");
            write_file_atomic_typed(&dst, b"x").expect_err("retain scratch"); assert_eq!(fs::metadata(&scratch).expect("scratch").mode() & 0o777, 0o600); drop(scope); fs::remove_file(&scratch).expect("scratch");
            write_file_atomic_typed(&dst, b"x").expect("overwrite"); assert_eq!(fs::metadata(&dst).expect("dst").permissions().mode() & 0o777, 0o600);
            let create = dir.join(format!("create-{mask:o}")); write_file_create_if_absent(&create, b"x", || Ok(())).expect("create"); assert_eq!(fs::metadata(create).expect("create").mode() & 0o777, 0o600);
        }
        let guard = ATOMIC_WRITE_PROCESS_MUTEX.lock().expect("mutex"); let barrier = std::sync::Arc::new(std::sync::Barrier::new(3)); let (tx, rx) = std::sync::mpsc::channel(); let mut threads = Vec::new();
        for (leaf, create) in [("serialized-overwrite", false), ("serialized-create", true)] {
            let (path, barrier, tx) = (dir.join(leaf), barrier.clone(), tx.clone()); threads.push(std::thread::spawn(move || { barrier.wait(); let result = if create { write_file_create_if_absent(&path, b"x", || Ok(())) } else { write_file_atomic_typed(&path, b"x") }; tx.send(result).expect("send"); }));
        }
        barrier.wait(); assert!(matches!(rx.recv_timeout(std::time::Duration::from_millis(100)), Err(std::sync::mpsc::RecvTimeoutError::Timeout))); drop(guard); for _ in 0..2 { rx.recv_timeout(std::time::Duration::from_secs(5)).expect("recv").expect("serialized write"); } for thread in threads { thread.join().expect("join"); } fs::remove_dir_all(dir).expect("cleanup");
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

    /// On a sync_all/write_all failure before rename the temp file MUST be
    /// removed, otherwise a real I/O fault (ENOSPC/EIO after data write)
    /// would strand the fixed `.rubin-atomic-write.tmp` scratch on disk while the
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

        // The directory must contain only the blocker file; no fixed
        // `.rubin-atomic-write.tmp`
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
}
