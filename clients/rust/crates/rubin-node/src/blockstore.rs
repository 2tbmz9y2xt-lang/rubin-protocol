use std::fs;
use std::path::{Path, PathBuf};

use num_bigint::BigUint;
use rubin_consensus::{
    block_hash, chain_work_from_targets, parse_block_header_bytes, BlockHeader, BLOCK_HEADER_BYTES,
};
use serde::{Deserialize, Serialize};

use crate::io_utils::{
    atomic_write_error_after, atomic_write_error_before, parse_hex32, read_file_by_path,
    read_file_from_dir, read_file_from_dir_unbounded, sync_atomic_parent,
    validate_atomic_write_destination, write_file_atomic_typed, write_file_create_if_absent,
    AtomicWriteError, AtomicWriteOperation, BLOCK_FILE_MAX_BYTES, HEADER_FILE_MAX_BYTES,
};
use crate::undo::{
    marshal_undo_envelope, unmarshal_undo_envelope, BlockUndo, UNDO_ENVELOPE_FILE_MAX_BYTES,
};
use std::ffi::OsStr;

pub const BLOCK_STORE_DIR_NAME: &str = "blockstore";
const BLOCK_STORE_INDEX_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockStore {
    root_path: PathBuf,
    index_path: PathBuf,
    blocks_dir: PathBuf,
    headers_dir: PathBuf,
    undo_dir: PathBuf,
    index: BlockStoreIndexDisk,
    /// E.7: O(1) canonical-height -> hash cache, mirror of Go's eager
    /// `buildCanonicalHeightIndex` precompute (see `clients/go/node/blockstore.go`
    /// `canonicalHeightByHash` + rebuild on `replaceCanonicalState`).
    ///
    /// Pre-decoded `[u8; 32]` for each entry in `index.canonical`, kept
    /// in lock-step on every mutation site. `canonical_hash` and `tip`
    /// read from this vector and skip the per-call hex decode of the
    /// 64-char canonical string. Eager build on `open` so lookups in
    /// startup reconcile (`truncate_incomplete_canonical_suffix`) and
    /// in the per-block `commit_canonical_block` no-op probe pay no
    /// hex-parse tax.
    canonical_hash_by_height: Vec<[u8; 32]>,
    /// Test-only: force `truncate_canonical` to return an error.
    #[cfg(test)]
    pub(crate) force_truncate_error: bool,
    /// Test-only: force `rollback_canonical` to return an error.
    #[cfg(test)]
    pub(crate) force_rollback_error: bool,
    /// Test-only: force `put_undo` to return an error. Used to exercise
    /// the crash-style atomicity contract of `commit_canonical_block`.
    #[cfg(test)]
    pub(crate) force_undo_error: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BlockStoreIndexDisk {
    version: u32,
    canonical: Vec<String>,
}

struct BlockStorePaths {
    root: PathBuf,
    index: PathBuf,
    blocks: PathBuf,
    headers: PathBuf,
    undo: PathBuf,
}

impl BlockStorePaths {
    fn new(root: PathBuf) -> Result<Self, String> {
        if root.as_os_str().is_empty() {
            return Err("blockstore root is required".to_string());
        }
        Ok(Self {
            index: root.join("index.json"),
            blocks: root.join("blocks"),
            headers: root.join("headers"),
            undo: root.join("undo"),
            root,
        })
    }

    /// Check the resolved filesystem kind of every path the store needs.
    /// `metadata`, not `symlink_metadata`: symlinks resolve normally on open.
    fn require_initialized(&self) -> Result<(), String> {
        for dir in [&self.root, &self.blocks, &self.headers, &self.undo] {
            let meta = fs::metadata(dir)
                .map_err(|e| format!("blockstore directory {}: {e}", dir.display()))?;
            if !meta.is_dir() {
                return Err(format!(
                    "blockstore path is not a directory: {}",
                    dir.display()
                ));
            }
        }
        let meta = fs::metadata(&self.index)
            .map_err(|e| format!("blockstore index {}: {e}", self.index.display()))?;
        if !meta.is_file() {
            return Err(format!(
                "blockstore index is not a regular file: {}",
                self.index.display()
            ));
        }
        Ok(())
    }
}

impl BlockStore {
    /// Initialize a fresh blockstore at `root_path`: the only constructor that
    /// writes. The root is created exclusively (an existing root of any kind
    /// fails; two racing creates cannot both win) and `index.json` is written
    /// LAST as the creation commit marker, so a crash before it leaves a partial
    /// root both constructors reject. Owns only `root_path`, never chainstate.
    /// Go mirror: `CreateBlockStore` in `clients/go/node/blockstore.go`.
    pub fn create<P: Into<PathBuf>>(root_path: P) -> Result<Self, String> {
        let paths = BlockStorePaths::new(root_path.into())?;
        fs::create_dir(&paths.root)
            .map_err(|e| format!("create blockstore root {}: {e}", paths.root.display()))?;
        for dir in [&paths.blocks, &paths.headers, &paths.undo] {
            fs::create_dir(dir)
                .map_err(|e| format!("create blockstore directory {}: {e}", dir.display()))?;
        }
        let index = BlockStoreIndexDisk {
            version: BLOCK_STORE_INDEX_VERSION,
            canonical: vec![],
        };
        save_blockstore_index(&paths.index, &index)?;
        Self::from_parts(paths, index)
    }

    /// Open an already-initialized blockstore. Strict: no mkdir, no marker
    /// synthesis, no fallback. A missing root/subdirectory/marker, a malformed
    /// marker, or a resolved path of the wrong kind is an error, never a fresh
    /// empty store. Symlinks resolve normally; no path-identity claim is made.
    /// Go mirror: `OpenBlockStore` in `clients/go/node/blockstore.go`.
    pub fn open<P: Into<PathBuf>>(root_path: P) -> Result<Self, String> {
        let paths = BlockStorePaths::new(root_path.into())?;
        paths.require_initialized()?;
        let index = load_blockstore_index(&paths.index)?;
        Self::from_parts(paths, index)
    }

    fn from_parts(paths: BlockStorePaths, index: BlockStoreIndexDisk) -> Result<Self, String> {
        let canonical_hash_by_height = build_canonical_hash_cache(&index.canonical)?;
        Ok(Self {
            root_path: paths.root,
            index_path: paths.index,
            blocks_dir: paths.blocks,
            headers_dir: paths.headers,
            undo_dir: paths.undo,
            index,
            canonical_hash_by_height,
            #[cfg(test)]
            force_truncate_error: false,
            #[cfg(test)]
            force_rollback_error: false,
            #[cfg(test)]
            force_undo_error: false,
        })
    }

    pub fn root_dir(&self) -> &Path {
        &self.root_path
    }

    pub fn put_block(
        &mut self,
        height: u64,
        block_hash_bytes: [u8; 32],
        header_bytes: &[u8],
        block_bytes: &[u8],
    ) -> Result<(), String> {
        self.persist_block_bytes(block_hash_bytes, header_bytes, block_bytes)?;
        self.set_canonical_tip(height, block_hash_bytes)
    }

    /// Atomic canonical block commit — Go parity
    /// (`clients/go/node/blockstore.go:100-114`, `CommitCanonicalBlock`:
    /// `StoreBlock` -> `PutUndo` -> `SetCanonicalTip`).
    ///
    /// Persists block bytes, header bytes, and the undo record BEFORE
    /// advancing the canonical tip. The tip update is the explicit
    /// commit point: if any earlier step (block/header/undo write) fails,
    /// the canonical tip remains at its prior height, so a crash leaves
    /// the chain with no orphaned canonical block missing its undo —
    /// which would otherwise break `disconnect_tip` on the next reorg.
    ///
    /// Compared to the previous `put_block` + separate `put_undo`
    /// sequence in `sync.rs`, this API shrinks the failure surface: the
    /// tip never advances before undo durability, so no post-hoc
    /// `truncate_canonical` rewind is needed on undo-write failure.
    /// Precommit preserves tip; postcommit may advance disk. Standalone returns the error; typed SyncEngine reloads index/cache and latches.
    ///
    /// **Orphan semantics on retry.** A failure at any step before the
    /// tip advance may leave block/header/undo files on disk without a
    /// canonical reference. These are safe and self-healing: block and
    /// header files are written via `write_file_if_absent` (idempotent
    /// no-op if the exact contents already exist on retry), and the
    /// undo file is written via `write_file_atomic`, whose tmp+rename
    /// idempotently overwrites at the same path on a subsequent retry
    /// with the same block hash. No canonical entry references these
    /// files until the tip advances, so they neither contaminate the
    /// chain nor leak unboundedly across same-hash retries.
    pub fn commit_canonical_block(
        &mut self,
        height: u64,
        block_hash_bytes: [u8; 32],
        header_bytes: &[u8],
        block_bytes: &[u8],
        undo: &BlockUndo,
    ) -> Result<(), String> {
        self.commit_canonical_block_typed(height, block_hash_bytes, header_bytes, block_bytes, undo)
            .map_err(|error| error.to_string())
    }
    pub(crate) fn commit_canonical_block_typed(
        &mut self,
        height: u64,
        block_hash_bytes: [u8; 32],
        header_bytes: &[u8],
        block_bytes: &[u8],
        undo: &BlockUndo,
    ) -> Result<(), AtomicWriteError> {
        // 0. Reject mismatched undo up front. If `undo.block_height` does
        //    not match the canonical height being committed, a later
        //    `ChainState::disconnect_block` would trip its height invariant
        //    and the tip would already have advanced — exactly the
        //    non-atomic failure mode this API is closing. Rejecting before
        //    any disk write keeps the canonical state untouched.
        if undo.block_height != height {
            return Err(atomic_write_error_before(
                &self.index_path,
                AtomicWriteOperation::Overwrite,
                format!(
                    "undo block_height mismatch: commit height={height}, undo.block_height={}",
                    undo.block_height
                ),
            ));
        }
        // 0a. Height-range + idempotent same-hash no-op guards. Semantics
        //     mirror Go's `CommitCanonicalBlock` -> `SetCanonicalTip`
        //     (`clients/go/node/blockstore.go:126-153`):
        //
        //     - `height > canonical_len` is an illegal gap; reject BEFORE
        //       any disk write so orphan block/header/undo files never
        //       accumulate in the "skipped future height" case.
        //
        //     - `height < canonical_len` with the SAME hash is an
        //       idempotent replay (crash-recovery path where
        //       `commit_canonical_block` advanced the blockstore tip
        //       but `chain_state.save` crashed; on restart
        //       `SyncEngine::apply_block` replays the already-persisted
        //       block at its original height). Replay ALWAYS calls
        //       `persist_block_bytes` for symmetric self-healing of
        //       block + header files (idempotent: `write_file_if_absent`
        //       is a no-op when the file already exists and never
        //       overwrites existing bytes; header hash is still
        //       validated against `block_hash_bytes`). Undo is
        //       conditionally back-filled via `put_undo` only when the
        //       undo file is missing on disk (pre-E.4 partial-commit
        //       case); an existing undo file is NOT rewritten. Tip /
        //       canonical index remain unchanged on both sub-paths.
        //
        //     - `height < canonical_len` with a DIFFERENT hash is a real
        //       reorg on the canonical index (same parent, different
        //       block at this height). Fall through to the normal
        //       persist -> `set_canonical_tip` path, which truncates
        //       `canonical[height..]` and pushes the new hash — matching
        //       Go. The prior block's files stay on disk as orphans (no
        //       canonical reference); this is the standard blockstore
        //       behavior for non-canonical blocks.
        //
        //     - `height == canonical_len` is the normal append.
        let current_len = self.canonical_len() as u64;
        if height > current_len {
            return Err(atomic_write_error_before(
                &self.index_path,
                AtomicWriteOperation::Overwrite,
                format!(
                    "commit_canonical_block height gap: height={height} > canonical_len={current_len}"
                ),
            ));
        }
        if height < current_len {
            let existing = self.canonical_hash(height).map_err(|error| {
                atomic_write_error_before(&self.index_path, AtomicWriteOperation::Overwrite, error)
            })?;
            if existing == Some(block_hash_bytes) {
                // Idempotent same-hash replay with symmetric healing.
                //
                //  - `persist_block_bytes` runs header validation and
                //    then writes block + header via
                //    `write_file_if_absent` (idempotent no-op if the
                //    file already exists, same pre-existing behavior
                //    as the non-atomic `put_block` path). A replay
                //    after a pre-E.4 partial-commit crash can
                //    re-create missing block/header files without
                //    clobbering existing ones.
                //
                //  - Undo is then conditionally back-filled only when
                //    absent: if the undo file is already on disk the
                //    historical bytes are NOT rewritten (matches the
                //    earlier Copilot concern that `write_file_atomic`
                //    would clobber the historical undo even on a
                //    same-hash retry); if the undo file is missing
                //    (pre-E.4 crash between block persist and undo
                //    write), `put_undo` back-fills it.
                //
                //  Canonical index / tip remain unchanged regardless.
                self.persist_block_bytes_typed(block_hash_bytes, header_bytes, block_bytes)?;
                if !self.has_undo(block_hash_bytes) {
                    self.put_undo_typed(block_hash_bytes, undo)?;
                }
                return Ok(());
            }
            // Different hash at historical height: real reorg; fall
            // through to persist + tip replace.
        }
        // 1. Persist block + header bytes (idempotent `write_file_if_absent`).
        self.persist_block_bytes_typed(block_hash_bytes, header_bytes, block_bytes)?;
        // 2. Persist undo BEFORE any tip advance. Matches Go ordering in
        //    `CommitCanonicalBlock` (StoreBlock → PutUndo → SetCanonicalTip).
        self.put_undo_typed(block_hash_bytes, undo)?;
        // 3. Advance canonical tip LAST — this is the atomic commit point.
        self.set_canonical_tip_typed(height, block_hash_bytes)
    }

    /// Cheap header consistency check — length + computed hash equals
    /// the caller-supplied hash. Called from `persist_block_bytes` as
    /// the precondition for any block/header write; every canonical
    /// entry point (`put_block`, `commit_canonical_block`,
    /// `store_block`) reaches this check through that helper, so
    /// header validation cannot drift between paths.
    fn validate_header_matches_hash(
        &self,
        header_bytes: &[u8],
        block_hash_bytes: [u8; 32],
    ) -> Result<(), String> {
        if header_bytes.len() != BLOCK_HEADER_BYTES {
            return Err(format!("invalid header length: {}", header_bytes.len()));
        }
        let computed_hash = block_hash(header_bytes).map_err(|e| e.to_string())?;
        if computed_hash != block_hash_bytes {
            return Err("header hash mismatch".to_string());
        }
        Ok(())
    }

    /// Block/header persistence shared by `put_block`,
    /// `commit_canonical_block`, and `store_block`. Validates header
    /// length + hash, then writes block and header files via
    /// `write_file_if_absent` (idempotent across retries — no-op when
    /// the file already exists; errors if existing bytes differ).
    fn persist_block_bytes(
        &self,
        block_hash_bytes: [u8; 32],
        header_bytes: &[u8],
        block_bytes: &[u8],
    ) -> Result<(), String> {
        self.persist_block_bytes_typed(block_hash_bytes, header_bytes, block_bytes)
            .map_err(|error| error.to_string())
    }
    fn persist_block_bytes_typed(
        &self,
        block_hash_bytes: [u8; 32],
        header_bytes: &[u8],
        block_bytes: &[u8],
    ) -> Result<(), AtomicWriteError> {
        let hash_hex = hex::encode(block_hash_bytes);
        let block_path = self.blocks_dir.join(format!("{hash_hex}.bin"));
        self.validate_header_matches_hash(header_bytes, block_hash_bytes)
            .map_err(|error| {
                atomic_write_error_before(&block_path, AtomicWriteOperation::CreateIfAbsent, error)
            })?;
        write_file_if_absent_typed(&block_path, block_bytes)?;
        write_file_if_absent_typed(
            &self.headers_dir.join(format!("{hash_hex}.bin")),
            header_bytes,
        )
    }

    /// Set or replace the canonical tip at `height`.
    ///
    /// Precommit restores suffix; postcommit standalone retains local state, while typed SyncEngine reloads index/cache and latches.
    pub fn set_canonical_tip(
        &mut self,
        height: u64,
        block_hash_bytes: [u8; 32],
    ) -> Result<(), String> {
        self.set_canonical_tip_typed(height, block_hash_bytes)
            .map_err(|error| error.to_string())
    }
    fn set_canonical_tip_typed(
        &mut self,
        height: u64,
        block_hash_bytes: [u8; 32],
    ) -> Result<(), AtomicWriteError> {
        let hash_hex = hex::encode(block_hash_bytes);
        let current_len = self.index.canonical.len() as u64;
        if height > current_len {
            return Err(atomic_write_error_before(
                &self.index_path,
                AtomicWriteOperation::Overwrite,
                format!("height gap: got {height}, expected <= {current_len}"),
            ));
        }
        // No-op if in-memory already holds this exact hash at this height.
        if height < current_len && self.index.canonical[height as usize] == hash_hex {
            return Ok(());
        }
        let displaced_canonical = self.index.canonical.split_off(height as usize);
        let displaced_cache = self.canonical_hash_by_height.split_off(height as usize);
        self.index.canonical.push(hash_hex);
        self.canonical_hash_by_height.push(block_hash_bytes);
        if let Err(e) = save_blockstore_index_typed(&self.index_path, &self.index) {
            if e.stage == crate::io_utils::AtomicWriteStage::BeforeNamespaceCommit {
                self.index.canonical.truncate(height as usize);
                self.index.canonical.extend(displaced_canonical);
                self.canonical_hash_by_height.truncate(height as usize);
                self.canonical_hash_by_height.extend(displaced_cache);
            }
            return Err(e);
        }
        Ok(())
    }

    /// Rewind canonical to (height + 1) entries.
    ///
    pub fn rewind_to_height(&mut self, height: u64) -> Result<(), String> {
        if self.index.canonical.is_empty() {
            return Ok(());
        }
        if height >= self.index.canonical.len() as u64 {
            return Err(format!("rewind height out of range: {height}"));
        }
        let new_len = height as usize + 1;
        match self.truncate_canonical_typed(new_len) {
            Ok(()) => Ok(()),
            Err(error) => {
                if error.stage == crate::io_utils::AtomicWriteStage::AfterNamespaceCommit {
                    self.index.canonical.truncate(new_len);
                    self.canonical_hash_by_height.truncate(new_len);
                }
                Err(error.to_string())
            }
        }
    }

    /// E.7: O(1) hot lookup served from `canonical_hash_by_height`
    /// (Go parity: `clients/go/node/blockstore.go` `CanonicalHash` reads
    /// the in-memory canonical slice that was decoded once at open).
    pub fn canonical_hash(&self, height: u64) -> Result<Option<[u8; 32]>, String> {
        if height >= self.canonical_hash_by_height.len() as u64 {
            return Ok(None);
        }
        Ok(Some(self.canonical_hash_by_height[height as usize]))
    }

    pub fn tip(&self) -> Result<Option<(u64, [u8; 32])>, String> {
        if self.canonical_hash_by_height.is_empty() {
            return Ok(None);
        }
        let height = self.canonical_hash_by_height.len() as u64 - 1;
        Ok(Some((
            height,
            self.canonical_hash_by_height[height as usize],
        )))
    }

    /// Kind-preserving sibling of [`BlockStore::get_block_by_hash`]: it returns
    /// the raw [`std::io::Error`], so a caller can tell a genuinely absent block
    /// ([`std::io::ErrorKind::NotFound`]) apart from every other read failure
    /// (permissions, a directory planted where a file belongs, EIO).
    ///
    /// `get_block_by_hash` formats that error into a `String`, which erases the
    /// kind; re-deriving the distinction by matching on the rendered text is
    /// OS-dependent and must not be used. The side-branch walk
    /// (`sync_reorg::load_verified_branch_ancestor`) needs the distinction
    /// because only `NotFound` may keep the parent-not-found / orphan-retention
    /// outcome — every other read failure is local store corruption. Go reaches
    /// the same split with `errors.Is(err, os.ErrNotExist)` in
    /// `clients/go/node/sync_reorg.go`.
    pub fn read_block_file_by_hash(
        &self,
        block_hash_bytes: [u8; 32],
    ) -> Result<Vec<u8>, std::io::Error> {
        // E.10: see `get_block_by_hash` for the safe-leaf-name rationale.
        // RUB-1057: an over-bound file is refused with `InvalidData` (never
        // `NotFound`), so on the branch ancestor walk it routes to
        // `load_verified_branch_ancestor`'s local-corruption arm
        // (`branch_store_corrupt`) and never changes a peer's disposition.
        let name = format!("{}.bin", hex::encode(block_hash_bytes));
        read_file_from_dir(&self.blocks_dir, &name, BLOCK_FILE_MAX_BYTES)
    }

    pub fn get_block_by_hash(&self, block_hash_bytes: [u8; 32]) -> Result<Vec<u8>, String> {
        // E.10: route through `read_file_from_dir` so the leaf name is
        // validated against the same traversal / absolute-path / empty-name
        // guard Go enforces in `readFileFromDir`. The synthesized
        // `<hex>.bin` cannot in practice contain a separator, but the
        // guard removes the entire class of "leaf name from on-disk
        // index drift becomes a traversal" without runtime cost.
        let name = format!("{}.bin", hex::encode(block_hash_bytes));
        self.read_block_file_by_hash(block_hash_bytes)
            .map_err(|e| format!("read block {}: {e}", self.blocks_dir.join(&name).display()))
    }

    pub fn get_header_by_hash(&self, block_hash_bytes: [u8; 32]) -> Result<Vec<u8>, String> {
        // E.10: see `get_block_by_hash` doc.
        let name = format!("{}.bin", hex::encode(block_hash_bytes));
        read_file_from_dir(&self.headers_dir, &name, HEADER_FILE_MAX_BYTES).map_err(|e| {
            format!(
                "read header {}: {e}",
                self.headers_dir.join(&name).display()
            )
        })
    }

    pub fn has_block(&self, block_hash_bytes: [u8; 32]) -> bool {
        self.headers_dir
            .join(format!("{}.bin", hex::encode(block_hash_bytes)))
            .exists()
    }

    /// Fallible header-file presence probe used by reconcile. Returns
    /// `Ok(true)` on present, `Ok(false)` only on `NotFound`, and
    /// `Err` on any other metadata error (EACCES / EIO / ENOTDIR on
    /// parent / etc.). Distinct from `has_block` — the boolean
    /// `has_block` is `Path::exists()` which conflates "missing" with
    /// metadata errors and is therefore unsafe for the
    /// reconcile-vs-truncate decision: a transient I/O failure must
    /// surface as a HARD startup error, not silently look like a
    /// "missing file → truncate canonical suffix" trigger.
    pub fn try_has_block(&self, block_hash_bytes: [u8; 32]) -> Result<bool, String> {
        try_has_file_at(
            &self
                .headers_dir
                .join(format!("{}.bin", hex::encode(block_hash_bytes))),
        )
    }

    /// Fallible block-bytes presence probe (in `blocks_dir`). Same
    /// semantics as `try_has_block`: only `NotFound` returns
    /// `Ok(false)`, every other metadata failure surfaces as `Err`.
    pub fn try_has_block_data(&self, block_hash_bytes: [u8; 32]) -> Result<bool, String> {
        try_has_file_at(
            &self
                .blocks_dir
                .join(format!("{}.bin", hex::encode(block_hash_bytes))),
        )
    }

    /// Fallible undo-file presence probe. Same semantics as
    /// `try_has_block`. Use this in `chainstate_recovery::truncate_
    /// incomplete_canonical_suffix` and any other path that must
    /// distinguish "missing" from "present but unreadable".
    pub fn try_has_undo(&self, block_hash_bytes: [u8; 32]) -> Result<bool, String> {
        try_has_file_at(
            &self
                .undo_dir
                .join(format!("{}.json", hex::encode(block_hash_bytes))),
        )
    }

    pub fn find_canonical_height(&self, block_hash_bytes: [u8; 32]) -> Result<Option<u64>, String> {
        let Some((tip_height, _)) = self.tip()? else {
            return Ok(None);
        };
        for height in (0..=tip_height).rev() {
            if self.canonical_hash(height)? == Some(block_hash_bytes) {
                return Ok(Some(height));
            }
        }
        Ok(None)
    }

    pub fn locator_hashes(&self, limit: usize) -> Result<Vec<[u8; 32]>, String> {
        let limit = if limit == 0 { 32 } else { limit };
        let Some((mut tip_height, _)) = self.tip()? else {
            return Ok(Vec::new());
        };
        let mut out = Vec::with_capacity(limit);
        let mut step = 1u64;
        let mut appended = 0usize;
        while let Some(hash) = self.canonical_hash(tip_height)? {
            out.push(hash);
            appended += 1;
            if appended >= limit || tip_height == 0 {
                break;
            }
            if appended >= 10 {
                step = step.saturating_mul(2);
            }
            if tip_height <= step {
                tip_height = 0;
            } else {
                tip_height -= step;
            }
        }
        Ok(out)
    }

    pub fn hashes_after_locators(
        &self,
        locator_hashes: &[[u8; 32]],
        stop_hash: [u8; 32],
        limit: u64,
    ) -> Result<Vec<[u8; 32]>, String> {
        let limit = if limit == 0 { 128 } else { limit };
        let Some((tip_height, _)) = self.tip()? else {
            return Ok(Vec::new());
        };
        let mut start_height = 0u64;
        for locator in locator_hashes {
            if let Some(height) = self.find_canonical_height(*locator)? {
                start_height = height.saturating_add(1);
                break;
            }
        }
        let mut out = Vec::with_capacity(limit as usize);
        for height in start_height..=tip_height {
            if out.len() as u64 >= limit {
                break;
            }
            let Some(hash) = self.canonical_hash(height)? else {
                break;
            };
            out.push(hash);
            if stop_hash != [0u8; 32] && hash == stop_hash {
                break;
            }
        }
        Ok(out)
    }

    // ----- Side-chain block storage (without canonical update) -----

    /// Store a block + header without updating the canonical index.
    /// Used for side-chain blocks that are not (yet) canonical.
    pub fn store_block(
        &self,
        block_hash_bytes: [u8; 32],
        header_bytes: &[u8],
        block_bytes: &[u8],
    ) -> Result<(), String> {
        self.store_block_typed(block_hash_bytes, header_bytes, block_bytes)
            .map_err(|error| error.to_string())
    }
    pub(crate) fn store_block_typed(
        &self,
        block_hash_bytes: [u8; 32],
        header_bytes: &[u8],
        block_bytes: &[u8],
    ) -> Result<(), AtomicWriteError> {
        // Delegate to the shared helper so header validation and
        // block/header file writes stay in one place across all
        // entry points (`put_block`, `commit_canonical_block`,
        // `store_block`).
        self.persist_block_bytes_typed(block_hash_bytes, header_bytes, block_bytes)
    }

    // ----- Chain work -----

    /// Read and verify one bounded header used by [`BlockStore::chain_work`].
    /// The parse and hash consume those exact bytes before any target or parent.
    fn chain_work_header(&self, lookup_hash: [u8; 32]) -> Result<BlockHeader, String> {
        let header_bytes = self.get_header_by_hash(lookup_hash).map_err(|err| {
            format!(
                "stored header for {} cannot be read: {err}",
                hex::encode(lookup_hash)
            )
        })?;
        let header = parse_block_header_bytes(&header_bytes).map_err(|err| {
            format!(
                "stored header for {} does not parse: {err}",
                hex::encode(lookup_hash)
            )
        })?;
        let observed_hash = block_hash(&header_bytes).map_err(|err| {
            format!(
                "stored header for {} does not hash: {err}",
                hex::encode(lookup_hash)
            )
        })?;
        if observed_hash != lookup_hash {
            return Err(format!(
                "stored header for {} hashes to {}",
                hex::encode(lookup_hash),
                hex::encode(observed_hash)
            ));
        }
        Ok(header)
    }

    /// Compute cumulative proof-of-work from genesis up to (and including)
    /// the block identified by `tip_hash`, by walking parent pointers.
    pub fn chain_work(&self, tip_hash: [u8; 32]) -> Result<BigUint, String> {
        if tip_hash == [0u8; 32] {
            return Ok(BigUint::ZERO);
        }
        let mut targets = Vec::new();
        let mut seen = std::collections::HashSet::new();
        let mut current = tip_hash;
        while current != [0u8; 32] {
            if !seen.insert(current) {
                return Err(format!(
                    "blockstore chain-work parent cycle at {}",
                    hex::encode(current)
                ));
            }
            let header = self.chain_work_header(current)?;
            targets.push(header.target);
            current = header.prev_block_hash;
        }
        chain_work_from_targets(&targets).map_err(|e| e.to_string())
    }

    // ----- Undo storage -----

    /// Persist a single undo record. Crate-private so that any in-crate
    /// canonical-commit path that needs an undo goes through
    /// `commit_canonical_block`, which enforces the
    /// `block -> header -> undo -> tip` ordering contract (see that
    /// docstring). `put_block` and `set_canonical_tip` remain `pub` for
    /// the no-undo paths (genesis / interop bootstrap, rollback, index
    /// truncate) where persisting an undo record is either unnecessary
    /// or inverted; they are NOT part of the E.4 atomicity lane.
    /// A standalone `put_undo` paired with `set_canonical_tip` in the
    /// opposite order would reintroduce the E.4 atomicity gap this task
    /// is closing.
    #[cfg(test)]
    pub(crate) fn put_undo(
        &self,
        block_hash_bytes: [u8; 32],
        undo: &BlockUndo,
    ) -> Result<(), String> {
        self.put_undo_typed(block_hash_bytes, undo)
            .map_err(|error| error.to_string())
    }
    fn put_undo_typed(
        &self,
        block_hash_bytes: [u8; 32],
        undo: &BlockUndo,
    ) -> Result<(), AtomicWriteError> {
        let path = self
            .undo_dir
            .join(format!("{}.json", hex::encode(block_hash_bytes)));
        #[cfg(test)]
        if self.force_undo_error {
            return Err(atomic_write_error_before(
                &path,
                AtomicWriteOperation::Overwrite,
                "forced undo error (test)",
            ));
        }
        let raw = marshal_undo_envelope(block_hash_bytes, undo).map_err(|error| {
            atomic_write_error_before(&path, AtomicWriteOperation::Overwrite, error)
        })?;
        // Undo files intentionally stay on the raw `write_file_atomic`
        // path (no `lexical_clean`). Writer and readers share one
        // dir-resolution strategy:
        //   - `get_undo`     → `read_file_from_dir(&self.undo_dir, ...)`
        //     (E.10 leaf-name guard on the leaf, NO `lexical_clean`
        //     on `self.undo_dir`)
        //   - `has_undo`     → `self.undo_dir.join(...).is_file()`
        //   - `try_has_undo` → `try_has_file_at(&self.undo_dir.join(...))`
        // None of them apply `lexical_clean` to `self.undo_dir`, so
        // keeping the writer on raw `write_file_atomic` means a write
        // that goes to `self.undo_dir.join(<hex>.json)` is the exact
        // same path the readers probe. The symlink-divergence
        // defense matters for the durable chainstate /
        // blockstore-index surface (startup read vs later save
        // under an operator `--data-dir` that crosses a symlink);
        // undo files are ephemeral and reorg-scoped, and keep the
        // Go-baseline symmetric raw-OS resolution so a freshly
        // written undo is always visible to the corresponding read.
        //
        // RUB-1057 write/read symmetry for the undo class: the bound rests
        // on a wire-cost derivation (>=1 mandatory signature per spent
        // input), so this guard converts any future derivation drift (a new
        // covenant family, signature aggregation) into a loud save-time
        // error instead of a next-restart refusal of the node's own undo.
        // RUB-1132 moves the guard to the envelope bound so it still measures
        // the bytes `get_undo` reads back.
        crate::io_utils::check_store_save_bound(
            &path.display().to_string(),
            raw.len(),
            UNDO_ENVELOPE_FILE_MAX_BYTES,
        )
        .map_err(|error| {
            atomic_write_error_before(&path, AtomicWriteOperation::Overwrite, error)
        })?;
        write_file_atomic_typed(&path, &raw)
    }

    pub fn get_undo(&self, block_hash_bytes: [u8; 32]) -> Result<BlockUndo, String> {
        // E.10: see `get_block_by_hash` doc.
        let name = format!("{}.json", hex::encode(block_hash_bytes));
        let raw = read_file_from_dir(&self.undo_dir, &name, UNDO_ENVELOPE_FILE_MAX_BYTES)
            .map_err(|e| format!("read undo {}: {e}", self.undo_dir.join(&name).display()))?;
        // `block_hash_bytes` is the hash the CALLER asked for, not one read back
        // off disk: that is what makes a record moved or renamed between two undo
        // files fail instead of restoring the wrong block's UTXOs. The error is
        // returned UNWRAPPED so the pinned UNDO_INTEGRITY message survives to
        // every caller boundary.
        unmarshal_undo_envelope(block_hash_bytes, &raw)
    }

    /// Cheap undo-presence check used by the same-hash replay branch
    /// of `commit_canonical_block` to verify that a canonical entry
    /// inherited from pre-E.4 disk state (or corrupted in some other
    /// way) actually has its undo file on disk before accepting the
    /// replay as a no-op. Reconcile / truncate paths use the fallible
    /// `try_has_undo` instead so EACCES / EIO surface as Err rather
    /// than silently looking like NotFound.
    fn has_undo(&self, block_hash_bytes: [u8; 32]) -> bool {
        self.undo_dir
            .join(format!("{}.json", hex::encode(block_hash_bytes)))
            .is_file()
    }

    // ----- Canonical index helpers -----

    pub fn canonical_len(&self) -> usize {
        self.index.canonical.len()
    }

    /// Returns a clone of the canonical entries from `start` to the end.
    /// Used to capture just the suffix that will be removed during a reorg
    /// (O(reorg_depth) instead of O(chain_height)).
    pub fn canonical_suffix_from(&self, start: usize) -> Vec<String> {
        if start >= self.index.canonical.len() {
            return vec![];
        }
        self.index.canonical[start..].to_vec()
    }

    /// Rollback canonical index after a partial reorg: truncate to
    /// `base_len` (removing entries added during reconnect), then
    /// re-append `suffix` (entries removed during disconnect).
    ///
    /// Atomic via out-of-place transaction: build the next index as a
    /// clone, save to disk, then commit to in-memory only on success.
    /// Precommit preserves disk and memory; postcommit may replace disk while standalone memory stays old; typed SyncEngine reloads index/cache and latches.
    pub fn rollback_canonical(
        &mut self,
        base_len: usize,
        suffix: Vec<String>,
    ) -> Result<(), String> {
        self.rollback_canonical_typed(base_len, suffix)
            .map_err(|error| error.to_string())
    }
    pub(crate) fn rollback_canonical_typed(
        &mut self,
        base_len: usize,
        suffix: Vec<String>,
    ) -> Result<(), AtomicWriteError> {
        #[cfg(test)]
        if self.force_rollback_error {
            return Err(atomic_write_error_before(
                &self.index_path,
                AtomicWriteOperation::Overwrite,
                "forced rollback error (test inject)",
            ));
        }
        // Build the target canonical once (owning only `suffix` + a
        // slice clone of `base_len` prefix entries).  No clone of the
        // entries BEYOND `base_len`.
        let clamped_base = base_len.min(self.index.canonical.len());
        let mut next_canonical = Vec::with_capacity(clamped_base + suffix.len());
        next_canonical.extend_from_slice(&self.index.canonical[..clamped_base]);
        next_canonical.extend(suffix);
        // Build the next height->hash cache BEFORE the disk write so a
        // malformed entry in `suffix` (e.g. non-hex hash string) fails
        // closed without touching disk. Precommit preserves disk/memory; postcommit may replace disk while memory stays old; typed SyncEngine reloads index/cache and latches.
        let next_cache = build_canonical_hash_cache(&next_canonical).map_err(|error| {
            atomic_write_error_before(&self.index_path, AtomicWriteOperation::Overwrite, error)
        })?;
        let view = BlockStoreIndexView {
            version: self.index.version,
            canonical: &next_canonical,
        };
        save_blockstore_index_serializable_typed(&self.index_path, &view)?;
        // Disk save succeeded — commit to in-memory (E.7 parity: mirror
        // Go's `replaceCanonicalState` rebuild after rollback).
        self.index.canonical = next_canonical;
        self.canonical_hash_by_height = next_cache;
        Ok(())
    }

    /// Truncate canonical index to exactly `new_len` entries.
    ///
    /// Precommit preserves disk/memory; postcommit may advance disk while standalone memory stays old; typed SyncEngine reloads index/cache and latches. Uses a borrowed slice view.
    pub fn truncate_canonical(&mut self, new_len: usize) -> Result<(), String> {
        self.truncate_canonical_typed(new_len)
            .map_err(|error| error.to_string())
    }
    pub(crate) fn truncate_canonical_typed(
        &mut self,
        new_len: usize,
    ) -> Result<(), AtomicWriteError> {
        #[cfg(test)]
        if self.force_truncate_error {
            return Err(atomic_write_error_before(
                &self.index_path,
                AtomicWriteOperation::Overwrite,
                "forced truncate error (test inject)",
            ));
        }
        let current_len = self.index.canonical.len();
        if new_len > current_len {
            return Err(atomic_write_error_before(
                &self.index_path,
                AtomicWriteOperation::Overwrite,
                format!("truncate_canonical new_len {new_len} > current {current_len}"),
            ));
        }
        // Fast-path: already at target length, skip the disk write.
        if new_len == current_len {
            return Ok(());
        }
        let view = BlockStoreIndexView {
            version: self.index.version,
            canonical: &self.index.canonical[..new_len],
        };
        save_blockstore_index_serializable_typed(&self.index_path, &view)?;
        // Save succeeded — now apply O(1) in-memory truncate.
        self.index.canonical.truncate(new_len);
        // E.7: keep height->hash cache coherent with the canonical
        // slice. Truncate is the only path that needs this on the
        // accepted-cases test (`canonical_hash` after `truncate_canonical(n)`
        // returns None for h >= n).
        self.canonical_hash_by_height.truncate(new_len);
        Ok(())
    }

    pub(crate) fn reload_persistence_state(&mut self) -> Result<(), String> {
        let disk = load_blockstore_index(&self.index_path)?;
        let cache = build_canonical_hash_cache(&disk.canonical)?;
        self.canonical_hash_by_height = cache;
        self.index = disk;
        Ok(())
    }
    pub(crate) fn is_index_destination(&self, path: &Path) -> bool {
        self.index_path == path
    }
}

pub fn block_store_path<P: AsRef<Path>>(data_dir: P) -> PathBuf {
    data_dir.as_ref().join(BLOCK_STORE_DIR_NAME)
}

/// E.7: build the height -> hash cache used by `canonical_hash` and
/// `tip` for O(1) hot lookups (see `BlockStore::canonical_hash_by_height`).
///
/// Mirror of Go's `buildCanonicalHeightIndex` (`clients/go/node/blockstore.go`)
/// which precomputes the inverse `hash -> height` map at open. The Rust
/// surface only needs the `height -> hash` direction for the consensus
/// hot path (sync, reconcile, devnet RPC, txpool reorg detection); a
/// failure here propagates the same `parse_hex32` error the previous
/// per-call decode would have produced, so reconcile keeps the
/// "operator must investigate corrupt index entry" semantics.
fn build_canonical_hash_cache(canonical: &[String]) -> Result<Vec<[u8; 32]>, String> {
    let mut out = Vec::with_capacity(canonical.len());
    for (i, hash_hex) in canonical.iter().enumerate() {
        // Use a constant label on the success path; allocate the
        // index-tagged label only on the error path to keep cold-start
        // / reorg cost O(N) bytes lower (one Vec allocation, no per-
        // entry String).
        let hash =
            parse_hex32("canonical", hash_hex).map_err(|e| format!("canonical[{i}]: {e}"))?;
        out.push(hash);
    }
    Ok(out)
}

/// Fallible existence probe used by the `try_has_*` family. Returns
/// `Ok(true)` if the file is present and stat'able, `Ok(false)` only
/// on `ErrorKind::NotFound`, `Err` on every other metadata failure
/// (EACCES on parent, EIO, ENOTDIR, etc.). Distinct from
/// `Path::exists()` which silently treats every metadata failure as
/// "missing" — that is unsafe for paths that gate truncate-vs-error
/// decisions in startup reconcile.
fn try_has_file_at(path: &Path) -> Result<bool, String> {
    match fs::metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(format!("stat {}: {e}", path.display())),
    }
}

fn load_blockstore_index(path: &Path) -> Result<BlockStoreIndexDisk, String> {
    // Use `read_file_from_dir(parent, file_name)` so the leaf
    // component still goes through the E.10 leaf-name guard, but
    // the dir portion is kept AS-IS (no `lexical_clean`) — that
    // way the index reads from the same physical directory the
    // block / header / undo readers + writers use when they call
    // `self.*_dir.join(...)` + raw `fs::read` / `write_file_atomic`.
    // Operator `--data-dir` is already lexically cleaned once at
    // the CLI parse site (`normalize_data_dir` in main.rs), so
    // `path.parent()` here is also pre-cleaned; there is nothing
    // to clean per-helper and no risk of split persistence between
    // the index and the block / header / undo files it references.
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let name = match path.file_name().and_then(OsStr::to_str) {
        Some(s) => s,
        None => {
            return Err(format!(
                "blockstore index path has no valid UTF-8 leaf: {}",
                path.display()
            ));
        }
    };
    // A missing marker is an error, never an implicit empty index.
    let raw = read_file_from_dir_unbounded(parent, name)
        .map_err(|e| format!("read blockstore index {}: {e}", path.display()))?;
    // `deny_unknown_fields` plus serde's duplicate/missing-field errors,
    // `from_slice`'s trailing-input rejection and the entry check below pin the
    // exact marker schema: exactly one `version` and one `canonical` field, in
    // either order. Go mirror: `decodeBlockStoreIndex` in the Go blockstore.
    let index: BlockStoreIndexDisk = serde_json::from_slice(&raw)
        .map_err(|e| format!("decode blockstore index {}: {e}", path.display()))?;
    if index.version != BLOCK_STORE_INDEX_VERSION {
        return Err(format!(
            "unsupported blockstore index version: {}",
            index.version
        ));
    }
    // Cheap string-shape check (no decode): `parse_hex32` in
    // `build_canonical_hash_cache` accepts uppercase, the marker does not.
    for (i, hash_hex) in index.canonical.iter().enumerate() {
        if !valid_canonical_hash_hex(hash_hex) {
            return Err(format!(
                "canonical[{i}]: not 64 lowercase hex characters: {hash_hex:?}"
            ));
        }
    }
    Ok(index)
}

/// The marker's exact entry shape: 64 lowercase hex characters. Shared with the
/// undo envelope (undo.rs), whose block_hash/checksum fields carry the same
/// shape — `hex::decode` alone would accept uppercase.
pub(crate) fn valid_canonical_hash_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

fn save_blockstore_index(path: &Path, index: &BlockStoreIndexDisk) -> Result<(), String> {
    save_blockstore_index_serializable(path, index)
}

/// Generic save: accepts any `Serialize` value with the same on-disk
/// shape as `BlockStoreIndexDisk`.  Lets `truncate_canonical` and
/// `rollback_canonical` pass a borrowed slice-backed view without
/// cloning all canonical strings.
fn save_blockstore_index_serializable<S: serde::Serialize + ?Sized>(
    path: &Path,
    index: &S,
) -> Result<(), String> {
    save_blockstore_index_serializable_typed(path, index).map_err(|error| error.to_string())
}
fn save_blockstore_index_typed(
    path: &Path,
    index: &BlockStoreIndexDisk,
) -> Result<(), AtomicWriteError> {
    save_blockstore_index_serializable_typed(path, index)
}
fn save_blockstore_index_serializable_typed<S: serde::Serialize + ?Sized>(
    path: &Path,
    index: &S,
) -> Result<(), AtomicWriteError> {
    let mut raw = serde_json::to_vec_pretty(index).map_err(|error| {
        atomic_write_error_before(
            path,
            AtomicWriteOperation::Overwrite,
            format!("encode blockstore index: {error}"),
        )
    })?;
    raw.push(b'\n');
    // Keep writer on raw `write_file_atomic` (no `lexical_clean`)
    // so the index file persists to the same physical directory
    // that block / header / undo writers use and that
    // `load_blockstore_index` reads back from. See the comment in
    // `load_blockstore_index` for the full blockstore-wide symmetry
    // rationale.
    write_file_atomic_typed(path, &raw)
}

/// Borrowed view of `BlockStoreIndexDisk` that serializes identically
/// but holds `&[String]` instead of owning the vector.  Used for
/// out-of-place writes (truncate/rollback) on the rare disconnect path.
#[derive(serde::Serialize)]
struct BlockStoreIndexView<'a> {
    version: u32,
    canonical: &'a [String],
}
#[cfg(test)]
fn write_file_if_absent(path: &Path, content: &[u8]) -> Result<(), String> {
    write_file_if_absent_typed(path, content).map_err(|error| error.to_string())
}
fn write_file_if_absent_typed(path: &Path, content: &[u8]) -> Result<(), AtomicWriteError> {
    let bound = content.len() as u64;
    write_file_if_absent_with_typed(path, content, move |candidate| {
        read_file_by_path(candidate, bound)
    })
}
fn existing_content_differs(path: &Path) -> String {
    format!(
        "file already exists with different content: {}",
        path.display()
    )
}
fn is_over_bound_refusal(error: &std::io::Error) -> bool {
    error.kind() == std::io::ErrorKind::InvalidData
        && error
            .to_string()
            .starts_with(crate::io_utils::STORE_FILE_TOO_LARGE_PREFIX)
}
#[cfg(test)]
fn write_file_if_absent_with(
    path: &Path,
    content: &[u8],
    read_existing: impl Fn(&Path) -> Result<Vec<u8>, std::io::Error>,
) -> Result<(), String> {
    write_file_if_absent_with_typed(path, content, read_existing).map_err(|error| error.to_string())
}
fn write_file_if_absent_with_typed(
    path: &Path,
    content: &[u8],
    read_existing: impl Fn(&Path) -> Result<Vec<u8>, std::io::Error>,
) -> Result<(), AtomicWriteError> {
    validate_atomic_write_destination(path, AtomicWriteOperation::CreateIfAbsent)?;
    match read_existing(path) {
        Ok(existing) => {
            if existing != content {
                return Err(atomic_write_error_before(
                    path,
                    AtomicWriteOperation::CreateIfAbsent,
                    existing_content_differs(path),
                ));
            }
            let parent = crate::io_utils::effective_parent(path).ok_or_else(|| {
                atomic_write_error_before(
                    path,
                    AtomicWriteOperation::CreateIfAbsent,
                    "atomic destination has no parent",
                )
            })?;
            sync_atomic_parent(parent).map_err(|error| {
                atomic_write_error_after(path, AtomicWriteOperation::CreateIfAbsent, error)
            })?;
            return Ok(());
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) if is_over_bound_refusal(&error) => {
            return Err(atomic_write_error_before(
                path,
                AtomicWriteOperation::CreateIfAbsent,
                existing_content_differs(path),
            ));
        }
        Err(error) => {
            return Err(atomic_write_error_before(
                path,
                AtomicWriteOperation::CreateIfAbsent,
                format!("read existing {}: {error}", path.display()),
            ));
        }
    }

    write_file_create_if_absent(path, content, move || {
        handle_link_eexist(path, content, read_existing)
    })
}

fn handle_link_eexist(
    path: &Path,
    content: &[u8],
    read_existing: impl Fn(&Path) -> Result<Vec<u8>, std::io::Error>,
) -> Result<(), String> {
    let existing = read_existing(path).map_err(|error| {
        if is_over_bound_refusal(&error) {
            existing_content_differs(path)
        } else {
            format!("read existing {}: {error}", path.display())
        }
    })?;
    if existing != content {
        return Err(existing_content_differs(path));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::io_utils::{
        create_sparse_file, unique_temp_path, AtomicWriteTestOp, AtomicWriteTestScope,
        ATOMIC_WRITE_LOCK_LEAF, ATOMIC_WRITE_SCRATCH_LEAF, STORE_FILE_TOO_LARGE_PREFIX,
    };
    use std::path::{Path, PathBuf};

    use rubin_consensus::{block_hash, BLOCK_HEADER_BYTES};

    use super::{
        block_store_path, read_file_by_path, write_file_if_absent, write_file_if_absent_with,
        BlockStore, BLOCK_FILE_MAX_BYTES, BLOCK_STORE_DIR_NAME, HEADER_FILE_MAX_BYTES,
    };

    /// RUB-1057: bound+1 refusal at the two caller paths whose production
    /// bounds are cheap to stage — block (72MB sparse, the contract-mandated
    /// production-scale row) and header (117B). The block row goes through
    /// `read_block_file_by_hash` so the ErrorKind pin (InvalidData, never
    /// NotFound) covers the branch ancestor walk (RUB-881): only NotFound may
    /// keep `sync_reorg::load_verified_branch_ancestor`'s parent-not-found
    /// arm. The undo/index/chainstate/verify callers share the same bounded
    /// readers at hard-wired constants pinned by
    /// `class_bound_constants_pin_frozen_values`; their at/over verdicts run
    /// at small injectable bounds in io_utils.rs (RUB-1057 wave-2
    /// de-scaling: no multi-GB or 256MB rows). Go twin:
    /// `TestBlockStoreReadFileClassBoundsRefuseOverBound`.
    #[test]
    fn read_class_bounds_refuse_over_bound_files() {
        let root = unique_temp_path("rubin-bs-bounds");
        let store = BlockStore::create(&root).expect("create");
        let hash = [0u8; 32];
        let name = hex::encode(hash);
        create_sparse_file(
            &root.join("blocks").join(format!("{name}.bin")),
            BLOCK_FILE_MAX_BYTES + 1,
        );
        let err = store.read_block_file_by_hash(hash).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert_ne!(err.kind(), std::io::ErrorKind::NotFound);
        assert!(
            err.to_string().starts_with(STORE_FILE_TOO_LARGE_PREFIX),
            "{err}"
        );
        create_sparse_file(
            &root.join("headers").join(format!("{name}.bin")),
            HEADER_FILE_MAX_BYTES + 1,
        );
        let err = store.get_header_by_hash(hash).unwrap_err();
        assert!(err.contains(STORE_FILE_TOO_LARGE_PREFIX), "{err}");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A header sized exactly at its class bound (116B) reads back
    /// byte-complete — the caller-level at-bound accept row for the one
    /// production bound that is cheap to stage (block's accept row reads
    /// 72MB in `read_file_from_dir_block_class_production_bound`; the other
    /// classes' at/over pairs run at small injectable bounds in io_utils.rs,
    /// production constants pinned by
    /// `class_bound_constants_pin_frozen_values`). Go twin:
    /// `TestBlockStoreReadFileClassBoundsAcceptAtBound`.
    #[test]
    fn read_class_bounds_accept_at_bound_files() {
        let root = unique_temp_path("rubin-bs-at-bound");
        let store = BlockStore::create(&root).expect("create");
        let hash = [0u8; 32];
        let name = hex::encode(hash);
        create_sparse_file(
            &root.join("headers").join(format!("{name}.bin")),
            HEADER_FILE_MAX_BYTES,
        );
        let got = store.get_header_by_hash(hash).expect("header at bound");
        assert_eq!(got.len() as u64, HEADER_FILE_MAX_BYTES);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// RUB-1057 wave-3 seam semantics on BOTH verify read sites — the
    /// fast-path probe and the hard_link-EEXIST re-read: an existing
    /// destination LARGER than the content being written is reported as the
    /// pre-existing content-mismatch error (identical caller-visible taxonomy
    /// for every mismatch, whatever the existing file's size), and the read
    /// never materializes more than `content.len()` bytes, so a corrupt
    /// multi-gigabyte file at a small destination is never buffered whole.
    /// The recorded bound proves the seam passes `content.len()`, not a
    /// coarse class constant. For the EEXIST arm the first probe reports
    /// NotFound so `write_file_exclusive` reaches hard_link EEXIST and
    /// performs the real second read. Go twin:
    /// `TestWriteFileIfAbsentVerifyReadBoundedByContentLength`.
    #[test]
    fn write_file_if_absent_verify_read_bounded_by_content_length() {
        for eexist in [false, true] {
            let dir = unique_temp_path("rubin-wfia-verify-bound");
            std::fs::create_dir_all(&dir).expect("mkdir");
            let dst = dir.join("dst.bin");
            // Far larger than content.len(): a whole-file read would allocate it.
            std::fs::write(&dst, [0xa5u8; 4096]).expect("seed");
            let content = b"x";
            let bounds = std::cell::RefCell::new(Vec::new());
            let skip_first = std::cell::Cell::new(eexist);
            let err = write_file_if_absent(&dst, content).unwrap_err();
            assert!(
                err.starts_with("file already exists with different content"),
                "production seam: {err}"
            );
            assert!(
                !err.contains(STORE_FILE_TOO_LARGE_PREFIX),
                "size refusal leaked into the caller taxonomy: {err}"
            );
            // Same through the injectable seam, recording the bound passed.
            let err = write_file_if_absent_with(&dst, content, |p| {
                if skip_first.replace(false) {
                    return Err(std::io::Error::from(std::io::ErrorKind::NotFound));
                }
                let bound = content.len() as u64;
                bounds.borrow_mut().push(bound);
                let got = read_file_by_path(p, bound);
                if let Ok(bytes) = &got {
                    assert!(bytes.len() as u64 <= bound, "materialized {}", bytes.len());
                }
                got
            })
            .unwrap_err();
            assert!(
                err.starts_with("file already exists with different content"),
                "injected seam (eexist={eexist}): {err}"
            );
            assert_eq!(*bounds.borrow(), vec![content.len() as u64]);
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    /// Drives every rejected/hostile row of RUB-1132 through the real
    /// `BlockStore::get_undo` entry point. Each row also re-reads the file
    /// afterwards: a rejection must never rewrite, truncate, or heal the record
    /// it refused. Go twin: `TestGetUndoRejectsIntegrityFailures`.
    #[test]
    fn get_undo_rejects_integrity_failures() {
        use crate::undo::{
            flip_base64_symbol, marshal_block_undo, marshal_undo_envelope, BlockUndo, SpentUndo,
            TxUndo, UNDO_BLOCK_HASH_MISMATCH_ERR, UNDO_CHECKSUM_MISMATCH_ERR, UNDO_LEGACY_ERR,
        };
        use rubin_consensus::{Outpoint, UtxoEntry};
        use sha3::{Digest, Sha3_256};

        let dir = unique_temp_path("rubin-undo-integrity");
        std::fs::create_dir_all(&dir).expect("mkdir");
        let store = BlockStore::create(block_store_path(&dir)).expect("create blockstore");
        let block_hash = [0x0au8; 32];
        let other_hash = [0x0du8; 32];
        let undo = BlockUndo {
            block_height: 7,
            previous_already_generated: 1234,
            txs: vec![
                TxUndo { spent: vec![] },
                TxUndo {
                    spent: vec![SpentUndo {
                        outpoint: Outpoint {
                            txid: [0x11u8; 32],
                            vout: 3,
                        },
                        entry: UtxoEntry {
                            value: 99,
                            covenant_type: 1,
                            covenant_data: vec![0xaa, 0xbb],
                            creation_height: 5,
                            created_by_coinbase: true,
                        },
                    }],
                },
            ],
        };

        let valid = String::from_utf8(marshal_undo_envelope(block_hash, &undo).expect("valid"))
            .expect("utf-8");
        let other_valid =
            String::from_utf8(marshal_undo_envelope(other_hash, &undo).expect("other"))
                .expect("utf-8");
        let payload = marshal_block_undo(&undo).expect("payload");
        let payload_b64 = crate::undo::base64_encode(&payload);
        let block_hash_hex = hex::encode(block_hash);
        let valid_json: serde_json::Value =
            serde_json::from_str(&valid).expect("valid envelope is JSON");
        let checksum_hex = valid_json["checksum"]
            .as_str()
            .expect("valid envelope has a checksum")
            .to_string();

        // Builds an envelope with a CORRECT checksum over arbitrary payload
        // bytes: reaching a rejection at all proves the payload decode runs
        // strictly after the checksum compare.
        let envelope_over = |body: &[u8]| -> String {
            let mut hasher = Sha3_256::new();
            hasher.update(b"RUBIN_BLOCK_UNDO_V1");
            hasher.update(block_hash);
            hasher.update((body.len() as u64).to_be_bytes());
            hasher.update(body);
            let checksum: [u8; 32] = hasher.finalize().into();
            format!(
                "{{\"version\":1,\"block_hash\":\"{}\",\"payload_b64\":\"{}\",\"checksum\":\"{}\"}}\n",
                block_hash_hex,
                crate::undo::base64_encode(body),
                hex::encode(checksum)
            )
        };
        let replace_once = |text: &str, old: &str, new: &str| -> String {
            assert_eq!(
                text.matches(old).count(),
                1,
                "mutation target {old:?} must occur exactly once"
            );
            text.replacen(old, new, 1)
        };

        let indented = serde_json::to_string_pretty(
            &serde_json::from_slice::<serde_json::Value>(&payload).unwrap(),
        )
        .expect("indent");

        let rows: Vec<(&str, String, Option<&str>)> = vec![
            ("legacy_indented_payload", format!("{indented}\n"), Some(UNDO_LEGACY_ERR)),
            (
                "legacy_compact_payload",
                String::from_utf8(payload.clone()).expect("utf-8"),
                Some(UNDO_LEGACY_ERR),
            ),
            ("version_zero", replace_once(&valid, "\"version\":1", "\"version\":0"), None),
            ("version_two", replace_once(&valid, "\"version\":1", "\"version\":2"), None),
            ("version_string", replace_once(&valid, "\"version\":1", "\"version\":\"1\""), None),
            ("version_null", replace_once(&valid, "\"version\":1", "\"version\":null"), None),
            ("version_float", replace_once(&valid, "\"version\":1", "\"version\":1.0"), None),
            (
                "missing_checksum",
                replace_once(&valid, &format!(",\"checksum\":\"{checksum_hex}\""), ""),
                None,
            ),
            ("unknown_field", replace_once(&valid, "{\"version\":1", "{\"note\":\"x\",\"version\":1"), None),
            (
                "duplicate_checksum_identical",
                replace_once(
                    &valid,
                    "{\"version\":1",
                    &format!("{{\"checksum\":\"{checksum_hex}\",\"version\":1"),
                ),
                None,
            ),
            (
                "duplicate_checksum_conflicting",
                replace_once(
                    &valid,
                    "{\"version\":1",
                    &format!("{{\"checksum\":\"{}\",\"version\":1", "00".repeat(32)),
                ),
                None,
            ),
            (
                "duplicate_payload_conflicting",
                replace_once(&valid, "{\"version\":1", "{\"payload_b64\":\"AA==\",\"version\":1"),
                None,
            ),
            (
                "null_payload",
                replace_once(&valid, &format!("\"payload_b64\":\"{payload_b64}\""), "\"payload_b64\":null"),
                None,
            ),
            ("trailing_json_value", format!("{}{{}}\n", valid.trim_end_matches('\n')), None),
            ("trailing_scalar", format!("{} 1\n", valid.trim_end_matches('\n')), None),
            ("not_an_object", "[]\n".to_string(), None),
            ("not_json", "definitely not json\n".to_string(), None),
            (
                "uppercase_block_hash",
                replace_once(&valid, &block_hash_hex, &block_hash_hex.to_uppercase()),
                None,
            ),
            (
                "base64_embedded_newline",
                replace_once(&valid, &payload_b64, &format!("{}\\n{}", &payload_b64[..4], &payload_b64[4..])),
                None,
            ),
            (
                "base64_unpadded",
                replace_once(&valid, &payload_b64, payload_b64.trim_end_matches('=')),
                None,
            ),
            (
                "base64_bad_symbol",
                replace_once(&valid, &payload_b64, &format!("*{}", &payload_b64[1..])),
                None,
            ),
            (
                "flip_one_base64_char",
                replace_once(&valid, &payload_b64, &flip_base64_symbol(&payload_b64)),
                Some(UNDO_CHECKSUM_MISMATCH_ERR),
            ),
            (
                "foreign_block_hash_field",
                replace_once(&valid, &block_hash_hex, &hex::encode(other_hash)),
                Some(UNDO_BLOCK_HASH_MISMATCH_ERR),
            ),
            (
                "envelope_swapped_between_files",
                other_valid.clone(),
                Some(UNDO_BLOCK_HASH_MISMATCH_ERR),
            ),
            (
                "checksum_computed_for_other_block",
                replace_once(&other_valid, &hex::encode(other_hash), &block_hash_hex),
                Some(UNDO_CHECKSUM_MISMATCH_ERR),
            ),
            ("checksum_valid_over_indented_payload", envelope_over(indented.as_bytes()), None),
            (
                "checksum_valid_over_null_txs",
                envelope_over(br#"{"block_height":0,"previous_already_generated":0,"txs":null}"#),
                None,
            ),
            (
                "checksum_valid_over_unknown_payload_field",
                envelope_over(br#"{"block_height":0,"previous_already_generated":0,"txs":[],"x":1}"#),
                None,
            ),
            (
                "checksum_valid_over_missing_payload_field",
                envelope_over(br#"{"block_height":0,"txs":[]}"#),
                None,
            ),
            (
                "checksum_valid_over_duplicate_payload_field",
                envelope_over(br#"{"block_height":0,"block_height":1,"previous_already_generated":0,"txs":[]}"#),
                None,
            ),
            (
                "checksum_valid_over_uppercase_txid",
                envelope_over(
                    format!(
                        r#"{{"block_height":0,"previous_already_generated":0,"txs":[{{"spent":[{{"txid":"{}","vout":0,"value":0,"covenant_type":0,"covenant_data":"","creation_height":0,"created_by_coinbase":false}}]}}]}}"#,
                        "AB".repeat(32)
                    )
                    .as_bytes(),
                ),
                None,
            ),
            (
                "checksum_valid_over_short_txid",
                envelope_over(
                    br#"{"block_height":0,"previous_already_generated":0,"txs":[{"spent":[{"txid":"aabb","vout":0,"value":0,"covenant_type":0,"covenant_data":"","creation_height":0,"created_by_coinbase":false}]}]}"#,
                ),
                None,
            ),
        ];

        let path = store
            .root_dir()
            .join("undo")
            .join(format!("{block_hash_hex}.json"));
        for (name, record, exact) in rows {
            std::fs::write(&path, record.as_bytes()).expect("seed record");
            let err = match store.get_undo(block_hash) {
                Ok(accepted) => panic!("get_undo accepted {name}: {accepted:?}"),
                Err(err) => err,
            };
            match exact {
                Some(want) => assert_eq!(err, want, "{name}: exact message"),
                None if name.starts_with("checksum_valid_over_") => {
                    // Payload-class failure: it must NOT be reported as a
                    // checksum or hash failure, which is what proves the order.
                    assert_ne!(err, UNDO_CHECKSUM_MISMATCH_ERR, "{name}");
                    assert_ne!(err, UNDO_BLOCK_HASH_MISMATCH_ERR, "{name}");
                }
                None => assert!(
                    err.starts_with("UNDO_INTEGRITY"),
                    "{name}: {err} lacks the cross-client prefix"
                ),
            }

            let after = std::fs::read(&path).expect("re-read refused record");
            assert_eq!(
                after,
                record.as_bytes(),
                "{name}: refused record was rewritten"
            );
        }

        // Step 8: a same-hash replay must not launder a corrupt record into a
        // valid one. Rust's back-fill branch writes only when the undo file is
        // ABSENT, so an existing corrupt record survives the replay untouched.
        // (Go reaches the same outcome through write-if-absent, which refuses
        // outright; the shared guarantee is "no silent heal", and each client
        // keeps the write behavior it already had.)
        let genesis = crate::genesis::devnet_genesis_block_bytes();
        let header = &genesis[..rubin_consensus::BLOCK_HEADER_BYTES];
        let genesis_hash = rubin_consensus::block_hash(header).expect("hash");
        let mut store = store;
        store
            .put_block(0, genesis_hash, header, &genesis)
            .expect("seed canonical entry");
        let genesis_undo_path = store
            .root_dir()
            .join("undo")
            .join(format!("{}.json", hex::encode(genesis_hash)));
        let corrupt = b"{\"version\":1,\"block_hash\":\"deadbeef\"}\n";
        std::fs::write(&genesis_undo_path, corrupt).expect("seed corrupt undo");
        let genesis_undo = BlockUndo {
            block_height: 0,
            previous_already_generated: 0,
            txs: vec![TxUndo { spent: vec![] }],
        };
        store
            .commit_canonical_block(0, genesis_hash, header, &genesis, &genesis_undo)
            .expect("same-hash replay is a no-op");
        assert_eq!(
            std::fs::read(&genesis_undo_path).expect("re-read"),
            corrupt,
            "same-hash replay healed a corrupt undo record"
        );
        assert!(
            store.get_undo(genesis_hash).is_err(),
            "the corrupt record must still be refused after the replay"
        );

        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    /// Pins the measured per-entry payload byte cost behind the undo bound
    /// derivation (io_utils.rs), measured through the production encoder
    /// (`marshal_block_undo`). A red row means a disk-struct change silently
    /// shifted the derivation margin: reconcile the io_utils.rs comment and the
    /// Go bound table before re-pinning.
    ///
    /// RUB-1132 changed the payload from indented to compact JSON, so this
    /// marginal cost dropped 66_707 -> 66_605. The io_utils.rs derivation still
    /// cites the indented figure and stays SOUND because it is now
    /// conservative: the compact payload is strictly smaller, so the same
    /// UNDO_FILE_MAX_BYTES covers strictly more spent entries than derived. The
    /// Go twin `TestReadFileBoundDerivationEntrySizes` measures
    /// `json.MarshalIndent` directly rather than the production encoder, so it
    /// still pins 66_707 — the two numbers are the two encodings of the same
    /// struct, not a cross-client divergence.
    #[test]
    fn undo_entry_derivation_size() {
        use crate::undo::{marshal_block_undo, BlockUndo, SpentUndo, TxUndo};
        use rubin_consensus::{Outpoint, UtxoEntry};
        // CORE_VAULT max covenant_data: 32+1+1+12*32+2+1024*32 = 33_188 bytes.
        let spent = SpentUndo {
            outpoint: Outpoint {
                txid: [0xab; 32],
                vout: u32::MAX,
            },
            entry: UtxoEntry {
                value: u64::MAX,
                covenant_type: 0x0101,
                covenant_data: vec![0xcd; 33_188],
                creation_height: u64::MAX,
                created_by_coinbase: false,
            },
        };
        let undo_len = |spent: Vec<SpentUndo>| -> i64 {
            let undo = BlockUndo {
                block_height: 0,
                previous_already_generated: 0,
                txs: vec![TxUndo { spent }],
            };
            marshal_block_undo(&undo).expect("marshal").len() as i64
        };
        assert_eq!(
            undo_len(vec![spent.clone(), spent.clone()]) - undo_len(vec![spent]),
            66_605
        );
    }

    /// Happy path for the E.3-hardened helper: destination absent,
    /// write_file_if_absent creates it via the atomic hard_link path,
    /// and a subsequent call with matching bytes is an idempotent
    /// no-op. Mirrors the Go `TestWriteFileIfAbsent_Fresh` for
    /// cross-client parity.
    #[rustfmt::skip]
    #[test]
    fn write_file_if_absent_fresh_then_idempotent() {
        let dir = unique_temp_path("rubin-wfia-fresh"); std::fs::create_dir_all(&dir).expect("create test dir");
        let path = dir.join("fresh.bin"); let content = b"hello E.3".to_vec();
        let fresh = AtomicWriteTestScope::new(); write_file_if_absent(&path, &content).expect("fresh write");
        assert!(fresh.operations().contains(&AtomicWriteTestOp::HardLink)); drop(fresh); assert_eq!(std::fs::read(&path).expect("read back"), content);
        // Idempotent replay: same bytes must succeed as a no-op.
        for leaf in [ATOMIC_WRITE_LOCK_LEAF, ATOMIC_WRITE_SCRATCH_LEAF] { let _ = std::fs::remove_file(dir.join(leaf)); }
        #[cfg(unix)]
        let restore_parent = {
            use std::os::unix::fs::PermissionsExt; struct Restore(std::path::PathBuf); impl Drop for Restore { fn drop(&mut self) { let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o700)); } }
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("mode");
            (unsafe { libc::geteuid() } != 0).then(|| { std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o500)).expect("readonly parent"); Restore(dir.clone()) })
        };
        let replay = AtomicWriteTestScope::new(); write_file_if_absent(&path, &content).expect("idempotent replay");
        assert_eq!(replay.operations(), [AtomicWriteTestOp::ParentSync]); assert!(!dir.join(ATOMIC_WRITE_LOCK_LEAF).exists()); assert!(!dir.join(ATOMIC_WRITE_SCRATCH_LEAF).exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt; assert_eq!(std::fs::metadata(&path).expect("mode").permissions().mode() & 0o777, 0o644); drop(restore_parent);
        }
        drop(replay);
        let reads = std::cell::Cell::new(0); for leaf in [ATOMIC_WRITE_LOCK_LEAF, ATOMIC_WRITE_SCRATCH_LEAF] {
            let reserved = dir.join(leaf); let err = write_file_if_absent_with(&reserved, b"x", |_| { reads.set(reads.get() + 1); Ok(b"x".to_vec()) }).expect_err("reserved destination");
            assert!(err.contains("reserved atomic persistence destination"));
        }
        assert_eq!(reads.get(), 0, "reserved destination validated before read");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// write_file_if_absent must refuse to overwrite an existing file
    /// with different bytes and surface an explicit error. Never
    /// silent replace — the TOCTOU-hardened helper reads the current
    /// destination on EEXIST and compares.
    #[test]
    fn write_file_if_absent_existing_different_content_is_error() {
        let dir = unique_temp_path("rubin-wfia-mismatch");
        std::fs::create_dir_all(&dir).expect("create test dir");
        let path = dir.join("occupied.bin");
        std::fs::write(&path, b"existing bytes").expect("seed");

        let err = write_file_if_absent(&path, b"different bytes").expect_err("must error");
        assert!(
            err.contains("different content"),
            "expected mismatch error, got: {err}"
        );

        // Destination bytes must not have been overwritten.
        let got = std::fs::read(&path).expect("read back");
        assert_eq!(got, b"existing bytes");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Concurrent race — identical content. Fires N threads at the
    /// same destination; exactly one creates the file via hard_link,
    /// the rest observe EEXIST, read back, match, return Ok. Dominant
    /// case during idempotent sync-engine replay — must never error
    /// under heavy concurrency. Mirrors the Go
    /// `TestWriteFileIfAbsent_ConcurrentSameContent`.
    #[test]
    fn write_file_if_absent_concurrent_same_content_all_ok() {
        let dir = unique_temp_path("rubin-wfia-concurrent-same");
        std::fs::create_dir_all(&dir).expect("create test dir");
        let path = std::sync::Arc::new(dir.join("shared.bin"));
        let content =
            std::sync::Arc::new(b"shared payload - every thread writes these same bytes".to_vec());

        const N: usize = 16;
        let mut handles = Vec::with_capacity(N);
        for _ in 0..N {
            let p = std::sync::Arc::clone(&path);
            let c = std::sync::Arc::clone(&content);
            handles.push(std::thread::spawn(move || write_file_if_absent(&p, &c)));
        }
        for h in handles {
            h.join()
                .expect("thread panic")
                .expect("same-content race must be Ok");
        }
        let got = std::fs::read(&*path).expect("read back");
        assert_eq!(&got, &*content);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Concurrent race — different content per thread. Exactly one
    /// thread wins the hard_link; the others read back the winner's
    /// bytes, observe the mismatch, and error. Critical invariant: the
    /// destination never holds "wrong" bytes from a losing thread —
    /// atomic hard_link prevents that silent overwrite that the old
    /// read-then-write_file_atomic implementation could permit under
    /// concurrent races. Mirrors the Go
    /// `TestWriteFileIfAbsent_ConcurrentDifferentContent`.
    #[test]
    fn write_file_if_absent_concurrent_different_content_exactly_one_ok() {
        let dir = unique_temp_path("rubin-wfia-concurrent-different");
        std::fs::create_dir_all(&dir).expect("create test dir");
        let path = std::sync::Arc::new(dir.join("contested.bin"));

        const N: usize = 16;
        let mut handles = Vec::with_capacity(N);
        for i in 0..N {
            let p = std::sync::Arc::clone(&path);
            handles.push(std::thread::spawn(move || {
                let unique = format!("thread-{i}-payload").into_bytes();
                write_file_if_absent(&p, &unique)
            }));
        }
        let mut successes = 0;
        for h in handles {
            if h.join().expect("thread panic").is_ok() {
                successes += 1;
            }
        }
        assert_eq!(successes, 1, "exactly one thread must win the link");

        // Whatever ended up on disk must be the bytes of the winning
        // thread — NOT truncated, NOT corrupted.
        let got = std::fs::read(&*path).expect("read back");
        let got_str = String::from_utf8(got).expect("utf8");
        assert!(
            got_str.starts_with("thread-") && got_str.ends_with("-payload"),
            "destination has corrupt bytes: {got_str}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn blockstore_open_and_reopen() {
        let dir = unique_temp_path("rubin-blockstore-test");
        std::fs::create_dir_all(&dir).expect("create test dir");
        let root = block_store_path(&dir);
        assert_eq!(
            root.file_name().and_then(|s| s.to_str()),
            Some(BLOCK_STORE_DIR_NAME)
        );

        let mut store = BlockStore::create(&root).expect("create");
        assert!(store.tip().expect("tip").is_none());
        store
            .set_canonical_tip(0, [0x11; 32])
            .expect("set canonical");
        drop(store);

        let store2 = BlockStore::open(&root).expect("reopen");
        let tip = store2.tip().expect("tip").expect("some tip");
        assert_eq!(tip.0, 0);
        assert_eq!(tip.1, [0x11; 32]);

        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn blockstore_store_block_without_canonical() {
        use crate::genesis::devnet_genesis_block_bytes;
        use rubin_consensus::{block_hash, BLOCK_HEADER_BYTES};

        let dir = unique_temp_path("rubin-blockstore-store");
        std::fs::create_dir_all(&dir).expect("create test dir");
        let root = block_store_path(&dir);
        let store = BlockStore::create(&root).expect("create");

        let genesis = devnet_genesis_block_bytes();
        let header = &genesis[..BLOCK_HEADER_BYTES];
        let hash = block_hash(header).expect("hash");

        store
            .store_block(hash, header, &genesis)
            .expect("store_block");
        assert!(store.has_block(hash));

        // store_block does NOT update canonical index.
        assert!(store.tip().expect("tip").is_none());

        let retrieved = store.get_block_by_hash(hash).expect("get");
        assert_eq!(retrieved, genesis);

        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    fn raw_chain_work_header(
        prev_hash: [u8; 32],
        target: [u8; 32],
        seed: u64,
    ) -> [u8; BLOCK_HEADER_BYTES] {
        let mut header = [0u8; BLOCK_HEADER_BYTES];
        header[..4].copy_from_slice(&1u32.to_le_bytes());
        header[4..36].copy_from_slice(&prev_hash);
        header[36..68].fill(seed as u8);
        header[68..76].copy_from_slice(&seed.to_le_bytes());
        header[76..108].copy_from_slice(&target);
        header[108..].copy_from_slice(&seed.to_le_bytes());
        header
    }

    fn write_chain_work_header(
        store: &BlockStore,
        prev_hash: [u8; 32],
        target: [u8; 32],
        seed: u64,
    ) -> ([u8; 32], [u8; BLOCK_HEADER_BYTES]) {
        let header = raw_chain_work_header(prev_hash, target, seed);
        let hash = block_hash(&header).expect("chain-work header hash");
        std::fs::write(
            store.headers_dir.join(format!("{}.bin", hex::encode(hash))),
            header,
        )
        .expect("write chain-work header");
        (hash, header)
    }

    fn chain_work_test_chain() -> (
        BlockStore,
        PathBuf,
        [[u8; 32]; 3],
        [[u8; BLOCK_HEADER_BYTES]; 3],
    ) {
        let dir = unique_temp_path("rubin-blockstore-chain-work");
        std::fs::create_dir_all(&dir).expect("create test dir");
        let store = BlockStore::create(block_store_path(&dir)).expect("create blockstore");
        let (root_hash, root_header) =
            write_chain_work_header(&store, [0u8; 32], rubin_consensus::constants::POW_LIMIT, 1);
        let (middle_hash, middle_header) =
            write_chain_work_header(&store, root_hash, rubin_consensus::constants::POW_LIMIT, 2);
        let (tip_hash, tip_header) = write_chain_work_header(
            &store,
            middle_hash,
            rubin_consensus::constants::POW_LIMIT,
            3,
        );
        (
            store,
            dir,
            [root_hash, middle_hash, tip_hash],
            [root_header, middle_header, tip_header],
        )
    }

    #[test]
    fn blockstore_chain_work_from_genesis() {
        use crate::genesis::devnet_genesis_block_bytes;
        use rubin_consensus::{block_hash, BLOCK_HEADER_BYTES};

        let dir = unique_temp_path("rubin-blockstore-cw");
        std::fs::create_dir_all(&dir).expect("create test dir");
        let root = block_store_path(&dir);
        let mut store = BlockStore::create(&root).expect("create");

        let genesis = devnet_genesis_block_bytes();
        let hash = block_hash(&genesis[..BLOCK_HEADER_BYTES]).expect("hash");
        store
            .put_block(0, hash, &genesis[..BLOCK_HEADER_BYTES], &genesis)
            .expect("put");

        let work = store.chain_work(hash).expect("chain_work");
        assert_eq!(work, num_bigint::BigUint::from(1u8));

        std::fs::remove_dir_all(root.join("headers")).expect("remove headers");
        let zero_work = store.chain_work([0u8; 32]).expect("zero");
        assert_eq!(zero_work, num_bigint::BigUint::ZERO);

        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn blockstore_chain_work_rejects_local_header_rows() {
        let (store, dir, hashes, _) = chain_work_test_chain();
        assert_eq!(
            store.chain_work(hashes[2]).expect("multi-header work"),
            num_bigint::BigUint::from(3u8)
        );
        std::fs::remove_dir_all(&dir).expect("cleanup");

        for name in [
            "missing",
            "unreadable",
            "short",
            "long",
            "substituted_head",
            "substituted_middle",
            "identity_before_target",
            "self_referential_substitution",
            "zero_target",
        ] {
            let (store, dir, hashes, headers) = chain_work_test_chain();
            let tip_path = store
                .headers_dir
                .join(format!("{}.bin", hex::encode(hashes[2])));
            let (lookup, detail) = match name {
                "missing" => {
                    std::fs::remove_file(&tip_path).expect("remove header");
                    (hashes[2], "cannot be read")
                }
                "unreadable" => {
                    std::fs::remove_file(&tip_path).expect("remove header");
                    std::fs::create_dir(&tip_path).expect("plant header directory");
                    (hashes[2], "cannot be read")
                }
                "short" => {
                    std::fs::write(&tip_path, [0u8; BLOCK_HEADER_BYTES - 1]).expect("write short");
                    (hashes[2], "does not parse")
                }
                "long" => {
                    std::fs::write(&tip_path, vec![0u8; BLOCK_HEADER_BYTES + 1])
                        .expect("write long");
                    (hashes[2], "cannot be read")
                }
                "substituted_head" => {
                    std::fs::write(&tip_path, headers[1]).expect("substitute head");
                    (hashes[2], "hashes to")
                }
                "substituted_middle" => {
                    std::fs::write(
                        store
                            .headers_dir
                            .join(format!("{}.bin", hex::encode(hashes[1]))),
                        headers[0],
                    )
                    .expect("substitute middle");
                    (hashes[2], "hashes to")
                }
                "identity_before_target" => {
                    std::fs::write(&tip_path, raw_chain_work_header(hashes[1], [0u8; 32], 4))
                        .expect("write dual-invalid header");
                    (hashes[2], "hashes to")
                }
                "self_referential_substitution" => {
                    std::fs::write(
                        &tip_path,
                        raw_chain_work_header(hashes[2], rubin_consensus::constants::POW_LIMIT, 5),
                    )
                    .expect("write self-referential header");
                    (hashes[2], "hashes to")
                }
                "zero_target" => {
                    let (hash, _) = write_chain_work_header(&store, hashes[1], [0u8; 32], 6);
                    (hash, "target is zero")
                }
                _ => unreachable!("named chain-work row"),
            };
            let err = store.chain_work(lookup).expect_err(name);
            assert!(err.contains(detail), "{name}: {err}");
            if name == "identity_before_target" {
                assert!(!err.contains("target is zero"), "identity must win: {err}");
            }
            std::fs::remove_dir_all(&dir).expect("cleanup");
        }
    }

    #[test]
    fn blockstore_undo_put_get_roundtrip() {
        use crate::undo::{BlockUndo, TxUndo};

        let dir = unique_temp_path("rubin-blockstore-undo");
        std::fs::create_dir_all(&dir).expect("create test dir");
        let root = block_store_path(&dir);
        let store = BlockStore::create(&root).expect("create");

        let undo = BlockUndo {
            block_height: 7,
            previous_already_generated: 500,
            txs: vec![TxUndo { spent: vec![] }],
        };

        let hash = [0xAB; 32];
        store.put_undo(hash, &undo).expect("put_undo");
        let loaded = store.get_undo(hash).expect("get_undo");
        assert_eq!(loaded, undo);

        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn blockstore_truncate_and_canonical_len() {
        let dir = unique_temp_path("rubin-blockstore-trunc");
        std::fs::create_dir_all(&dir).expect("create test dir");
        let root = block_store_path(&dir);
        let mut store = BlockStore::create(&root).expect("create");

        store.set_canonical_tip(0, [0x11; 32]).expect("set 0");
        store.set_canonical_tip(1, [0x22; 32]).expect("set 1");
        assert_eq!(store.canonical_len(), 2);

        store.truncate_canonical(1).expect("truncate");
        assert_eq!(store.canonical_len(), 1);
        let tip = store.tip().expect("tip").expect("some");
        assert_eq!(tip.0, 0);

        let err = store.truncate_canonical(5).unwrap_err();
        assert!(err.contains("truncate_canonical"));

        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    /// Go parity / crash-safety for Q-IMPL-RUST-STORAGE-ATOMIC-CANONICAL-COMMIT-01:
    /// `commit_canonical_block` persists block/header/undo BEFORE
    /// advancing the canonical tip. The happy-path roundtrip confirms
    /// all three pieces land and the tip moves to the new height.
    #[test]
    fn commit_canonical_block_happy_path_advances_tip_and_persists_undo() {
        use crate::genesis::devnet_genesis_block_bytes;
        use crate::undo::{BlockUndo, TxUndo};
        use rubin_consensus::{block_hash, BLOCK_HEADER_BYTES};

        let dir = unique_temp_path("rubin-blockstore-commit-happy");
        std::fs::create_dir_all(&dir).expect("create test dir");
        let root = block_store_path(&dir);
        let mut store = BlockStore::create(&root).expect("create");

        let genesis = devnet_genesis_block_bytes();
        let header = &genesis[..BLOCK_HEADER_BYTES];
        let hash = block_hash(header).expect("hash");
        let undo = BlockUndo {
            block_height: 0,
            previous_already_generated: 0,
            txs: vec![TxUndo { spent: vec![] }],
        };

        store
            .commit_canonical_block(0, hash, header, &genesis, &undo)
            .expect("commit_canonical_block");

        assert_eq!(store.canonical_len(), 1);
        let tip = store.tip().expect("tip").expect("some");
        assert_eq!(tip, (0, hash));
        assert_eq!(store.get_undo(hash).expect("get_undo"), undo);
        assert_eq!(store.get_block_by_hash(hash).expect("block"), genesis);

        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    /// Crash-style atomicity evidence for E.4: if undo persistence fails
    /// (simulated here via `force_undo_error`), the canonical tip MUST
    /// remain at its prior height. Before this change the tip was
    /// advanced by `put_block` before the undo write, so a crash at the
    /// same point would leave a canonical block with no recoverable undo.
    #[test]
    fn commit_canonical_block_leaves_tip_unchanged_when_undo_fails() {
        use crate::genesis::devnet_genesis_block_bytes;
        use crate::undo::{BlockUndo, TxUndo};
        use rubin_consensus::{block_hash, BLOCK_HEADER_BYTES};

        let dir = unique_temp_path("rubin-blockstore-commit-undo-fail");
        std::fs::create_dir_all(&dir).expect("create test dir");
        let root = block_store_path(&dir);
        let mut store = BlockStore::create(&root).expect("create");

        let genesis = devnet_genesis_block_bytes();
        let header = &genesis[..BLOCK_HEADER_BYTES];
        let hash = block_hash(header).expect("hash");
        let undo = BlockUndo {
            block_height: 0,
            previous_already_generated: 0,
            txs: vec![TxUndo { spent: vec![] }],
        };

        let canonical_len_before = store.canonical_len();
        store.force_undo_error = true;

        let err = store
            .commit_canonical_block(0, hash, header, &genesis, &undo)
            .unwrap_err();
        assert!(
            err.contains("forced undo error"),
            "expected forced undo error, got {err:?}"
        );

        // Tip MUST NOT have advanced past the prior height.
        assert_eq!(store.canonical_len(), canonical_len_before);
        assert!(store.tip().expect("tip").is_none());
        // Block AND header files landed on disk before the undo step
        // fired, which is safe because `write_file_if_absent` is
        // idempotent on retry and no canonical entry references them
        // until the tip advances. Assert both explicitly rather than
        // relying on `has_block` (which only checks the header file).
        assert_eq!(
            store.get_header_by_hash(hash).expect("get_header_by_hash"),
            header
        );
        assert_eq!(
            store.get_block_by_hash(hash).expect("get_block_by_hash"),
            genesis
        );

        // Retry contract: once the transient undo failure clears, calling
        // commit_canonical_block again with the same arguments must
        // succeed (no "already exists" error from block/header writes,
        // no stale-state corruption) and the tip must finally advance.
        store.force_undo_error = false;
        store
            .commit_canonical_block(0, hash, header, &genesis, &undo)
            .expect("retry commit_canonical_block");
        assert_eq!(store.canonical_len(), 1);
        assert_eq!(store.tip().expect("tip").expect("some"), (0, hash));
        assert_eq!(store.get_undo(hash).expect("get_undo"), undo);

        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    /// `commit_canonical_block` must reject a mismatched undo before any
    /// disk write, otherwise a later `disconnect_block` would trip its
    /// height invariant while the canonical tip has already advanced —
    /// exactly the non-atomic failure mode this API closes.
    #[test]
    fn commit_canonical_block_rejects_mismatched_undo_height() {
        use crate::genesis::devnet_genesis_block_bytes;
        use crate::undo::{BlockUndo, TxUndo};
        use rubin_consensus::{block_hash, BLOCK_HEADER_BYTES};

        let dir = unique_temp_path("rubin-blockstore-commit-undo-mismatch");
        std::fs::create_dir_all(&dir).expect("create test dir");
        let root = block_store_path(&dir);
        let mut store = BlockStore::create(&root).expect("create");

        let genesis = devnet_genesis_block_bytes();
        let header = &genesis[..BLOCK_HEADER_BYTES];
        let hash = block_hash(header).expect("hash");
        // Deliberately mismatched undo: commit height 0 but undo claims height 7.
        let bad_undo = BlockUndo {
            block_height: 7,
            previous_already_generated: 0,
            txs: vec![TxUndo { spent: vec![] }],
        };

        let err = store
            .commit_canonical_block(0, hash, header, &genesis, &bad_undo)
            .unwrap_err();
        assert!(
            err.contains("undo block_height mismatch"),
            "expected mismatch error, got {err:?}"
        );

        // Canonical state must be untouched — no files, no tip advance.
        // Check block and header files explicitly (`has_block` only
        // checks the header directory).
        assert_eq!(store.canonical_len(), 0);
        assert!(store.tip().expect("tip").is_none());
        assert!(
            store.get_header_by_hash(hash).is_err(),
            "header file must not exist before the mismatch check"
        );
        assert!(
            store.get_block_by_hash(hash).is_err(),
            "block file must not exist before the mismatch check"
        );

        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    /// Same-hash replay heals a pre-E.4 partial-commit state: a
    /// canonical entry present on disk but with its undo missing
    /// (crash between block persist and undo write on the old
    /// non-atomic path). `SyncEngine::apply_block` replays the block
    /// on restart, and the replay must back-fill the undo so recovery
    /// proceeds — not error out. If the undo IS on disk, the replay
    /// stays a no-op (doesn't rewrite historical bytes).
    #[test]
    fn commit_canonical_block_same_hash_replay_back_fills_missing_undo() {
        use crate::genesis::devnet_genesis_block_bytes;
        use crate::undo::{BlockUndo, TxUndo};
        use rubin_consensus::{block_hash, BLOCK_HEADER_BYTES};

        let dir = unique_temp_path("rubin-blockstore-replay-backfill");
        std::fs::create_dir_all(&dir).expect("create test dir");
        let root = block_store_path(&dir);
        let mut store = BlockStore::create(&root).expect("create");

        let genesis = devnet_genesis_block_bytes();
        let header = &genesis[..BLOCK_HEADER_BYTES];
        let hash = block_hash(header).expect("hash");

        // Simulate pre-E.4 partial-commit state: block + canonical tip
        // landed via the non-atomic `put_block`, but the undo file was
        // never written (crash between the two steps in the old code).
        store
            .put_block(0, hash, header, &genesis)
            .expect("put_block (seed)");
        assert_eq!(store.canonical_len(), 1);
        assert!(!store.has_undo(hash), "seeded state must have no undo");

        let undo = BlockUndo {
            block_height: 0,
            previous_already_generated: 0,
            txs: vec![TxUndo { spent: vec![] }],
        };

        // Replay the same block. Canonical entry already matches, undo
        // is missing — API must heal by writing undo and returning Ok.
        store
            .commit_canonical_block(0, hash, header, &genesis, &undo)
            .expect("same-hash replay must back-fill missing undo");

        // Canonical index unchanged; undo now present and matches.
        assert_eq!(store.canonical_len(), 1);
        assert!(
            store.has_undo(hash),
            "undo file must be written during healing"
        );
        assert_eq!(store.get_undo(hash).expect("get_undo"), undo);

        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    /// `commit_canonical_block` rejects future-height gaps BEFORE any
    /// disk write, so orphan block/header/undo files never accumulate
    /// when a caller accidentally skips a height.
    #[test]
    fn commit_canonical_block_rejects_height_gap_without_orphan_files() {
        use crate::genesis::devnet_genesis_block_bytes;
        use crate::undo::{BlockUndo, TxUndo};
        use rubin_consensus::{block_hash, BLOCK_HEADER_BYTES};

        let dir = unique_temp_path("rubin-blockstore-commit-gap");
        std::fs::create_dir_all(&dir).expect("create test dir");
        let root = block_store_path(&dir);
        let mut store = BlockStore::create(&root).expect("create");

        let genesis = devnet_genesis_block_bytes();
        let header = &genesis[..BLOCK_HEADER_BYTES];
        let hash = block_hash(header).expect("hash");
        // canonical_len starts at 0; passing height=5 is a gap.
        let undo = BlockUndo {
            block_height: 5,
            previous_already_generated: 0,
            txs: vec![TxUndo { spent: vec![] }],
        };

        let err = store
            .commit_canonical_block(5, hash, header, &genesis, &undo)
            .unwrap_err();
        assert!(
            err.contains("height gap") && err.contains("height=5"),
            "expected height-gap rejection, got {err:?}"
        );

        // No disk writes: block AND header files must NOT exist (check
        // both explicitly — `has_block` only inspects the header dir).
        assert_eq!(store.canonical_len(), 0);
        assert!(
            store.get_header_by_hash(hash).is_err(),
            "header file must not exist on height-gap rejection"
        );
        assert!(
            store.get_block_by_hash(hash).is_err(),
            "block file must not exist on height-gap rejection"
        );

        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    /// Crash-recovery path (GPT-5 review P1): after a successful
    /// `commit_canonical_block` that advanced the blockstore tip, if
    /// `chain_state.save` crashes the chain state lags the blockstore
    /// by one or more blocks. On restart `SyncEngine::apply_block`
    /// replays the already-persisted block at its original height and
    /// MUST succeed so recovery can proceed; it MUST NOT rewrite the
    /// historical undo file (`put_undo` via `write_file_atomic` would
    /// otherwise clobber the historical bytes on disk). The same-hash
    /// replay validates the header, runs the idempotent
    /// `persist_block_bytes` (no-op when block/header already exist,
    /// self-heals if missing), and only calls `put_undo` when the undo
    /// file is absent; canonical index / tip stay unchanged.
    /// This test covers the already-present-undo sub-case: byte
    /// equality before/after replay proves no rewrite happened.
    #[test]
    fn commit_canonical_block_same_hash_replay_is_idempotent_noop() {
        use crate::genesis::devnet_genesis_block_bytes;
        use crate::undo::{BlockUndo, TxUndo};
        use rubin_consensus::{block_hash, BLOCK_HEADER_BYTES};

        let dir = unique_temp_path("rubin-blockstore-same-hash-replay");
        std::fs::create_dir_all(&dir).expect("create test dir");
        let root = block_store_path(&dir);
        let mut store = BlockStore::create(&root).expect("create");

        let genesis = devnet_genesis_block_bytes();
        let header = &genesis[..BLOCK_HEADER_BYTES];
        let hash = block_hash(header).expect("hash");
        let undo = BlockUndo {
            block_height: 0,
            previous_already_generated: 0,
            txs: vec![TxUndo { spent: vec![] }],
        };

        // First commit lands normally.
        store
            .commit_canonical_block(0, hash, header, &genesis, &undo)
            .expect("first commit");
        assert_eq!(store.canonical_len(), 1);
        assert_eq!(store.tip().expect("tip").expect("some"), (0, hash));

        // Capture undo file bytes so we can assert the replay does NOT
        // rewrite them. Content comparison is more robust than mtime:
        // filesystem timestamp resolution and update semantics vary by
        // platform and may not change on a same-bytes rewrite.
        let undo_path = root
            .join("undo")
            .join(format!("{}.json", hex::encode(hash)));
        let undo_bytes_before = std::fs::read(&undo_path).expect("undo bytes before");

        // Simulate a crash-recovery replay: same hash at height 0 after
        // blockstore already advanced to canonical_len == 1. Must succeed
        // as a no-op.
        store
            .commit_canonical_block(0, hash, header, &genesis, &undo)
            .expect("replay same-hash commit must succeed");

        // Canonical index unchanged.
        assert_eq!(store.canonical_len(), 1);
        assert_eq!(store.tip().expect("tip").expect("some"), (0, hash));
        // Undo file bytes unchanged — no rewrite happened.
        let undo_bytes_after = std::fs::read(&undo_path).expect("undo bytes after");
        assert_eq!(
            undo_bytes_before, undo_bytes_after,
            "same-hash replay must not rewrite the historical undo file"
        );

        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    // ====================================================================
    // E.7 — canonical-height O(1) cache parity tests (sub-issue #1247).
    // Cache invariant: `canonical_hash_by_height[i]` is the decoded form
    // of `index.canonical[i]` for every i in 0..canonical_len, after
    // every mutation path. The lookup contract is "what's in the index
    // is also in the cache, byte-for-byte, no stale tail".
    // ====================================================================

    /// Helper: assert the cache mirrors `index.canonical` exactly.
    /// Decodes each hex string fresh so a desync (cache stale, cache
    /// short, cache long) shows up here instead of as a silent wrong
    /// answer in `canonical_hash`.
    fn assert_cache_matches_index(store: &BlockStore) {
        assert_eq!(
            store.canonical_hash_by_height.len(),
            store.index.canonical.len(),
            "cache len must equal index.canonical len",
        );
        for (i, hash_hex) in store.index.canonical.iter().enumerate() {
            let expected = crate::io_utils::parse_hex32("test", hash_hex).expect("decode");
            assert_eq!(
                store.canonical_hash_by_height[i], expected,
                "cache entry at height {i} drifted from index.canonical",
            );
        }
    }

    #[test]
    fn canonical_hash_cache_coherent_after_append_and_truncate() {
        let dir = unique_temp_path("rubin-blockstore-e7-cache-append-trunc");
        std::fs::create_dir_all(&dir).expect("create test dir");
        let root = block_store_path(&dir);
        let mut store = BlockStore::create(&root).expect("create");

        // Append three entries via the production hot path.
        store.set_canonical_tip(0, [0xA0; 32]).expect("set 0");
        store.set_canonical_tip(1, [0xA1; 32]).expect("set 1");
        store.set_canonical_tip(2, [0xA2; 32]).expect("set 2");
        assert_cache_matches_index(&store);
        assert_eq!(store.canonical_hash(0).unwrap(), Some([0xA0; 32]));
        assert_eq!(store.canonical_hash(2).unwrap(), Some([0xA2; 32]));
        assert_eq!(store.tip().unwrap(), Some((2, [0xA2; 32])));

        // Truncate to length 1 — heights >= 1 must be gone from BOTH
        // the index and the cache (rejected case: cache returns
        // Some(hash) for h beyond truncated tip).
        store.truncate_canonical(1).expect("truncate to 1");
        assert_cache_matches_index(&store);
        assert_eq!(store.canonical_hash(0).unwrap(), Some([0xA0; 32]));
        assert_eq!(store.canonical_hash(1).unwrap(), None);
        assert_eq!(store.canonical_hash(2).unwrap(), None);

        // Append at the freshly-truncated tail — new entry visible
        // without reopen (accepted case).
        store.set_canonical_tip(1, [0xB1; 32]).expect("re-set 1");
        assert_cache_matches_index(&store);
        assert_eq!(store.canonical_hash(1).unwrap(), Some([0xB1; 32]));

        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[rustfmt::skip]
    #[test]
    fn canonical_hash_cache_coherent_after_replace_at_height() {
        // set_canonical_tip(height < current_len, different hash) is
        // the reorg-replace branch (truncate-then-push). The cache
        // must follow exactly: a stale entry at the replaced height
        // is the rejected case.
        let dir = unique_temp_path("rubin-blockstore-e7-cache-replace"); std::fs::create_dir_all(&dir).expect("create test dir");
        let root = block_store_path(&dir); let mut store = BlockStore::create(&root).expect("create");

        let empty = std::fs::read(&store.index_path).expect("empty index");
        std::fs::remove_file(&store.index_path).expect("remove index"); std::fs::create_dir(&store.index_path).expect("block index");
        let err = store.set_canonical_tip(0, [0x42; 32]).unwrap_err(); assert!(err.contains("before_namespace_commit")); assert_eq!((store.canonical_len(), store.tip().unwrap()), (0, None));
        std::fs::remove_dir(&store.index_path).expect("remove blocker"); std::fs::write(&store.index_path, empty).expect("restore index");
        store.set_canonical_tip(0, [0x10; 32]).expect("set 0");
        store.set_canonical_tip(1, [0x11; 32]).expect("set 1");
        store.set_canonical_tip(2, [0x12; 32]).expect("set 2");

        // Replace at height 1 with a different hash — entries beyond
        // height 1 are dropped from both index and cache.
        store.set_canonical_tip(1, [0x99; 32]).expect("replace 1");
        assert_cache_matches_index(&store);
        assert_eq!(store.canonical_hash(0).unwrap(), Some([0x10; 32]));
        assert_eq!(store.canonical_hash(1).unwrap(), Some([0x99; 32]));
        assert_eq!(store.canonical_hash(2).unwrap(), None);

        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[rustfmt::skip]
    #[test]
    fn canonical_hash_cache_coherent_after_rewind_to_height() {
        let dir = unique_temp_path("rubin-blockstore-e7-cache-rewind"); std::fs::create_dir_all(&dir).expect("create test dir");
        let root = block_store_path(&dir); let mut store = BlockStore::create(&root).expect("create");

        store.set_canonical_tip(0, [0x21; 32]).expect("set 0");
        store.set_canonical_tip(1, [0x22; 32]).expect("set 1");
        store.set_canonical_tip(2, [0x23; 32]).expect("set 2");

        let prior = std::fs::read(&store.index_path).expect("prior index");
        std::fs::remove_file(&store.index_path).expect("remove index"); std::fs::create_dir(&store.index_path).expect("block index");
        let err = store.rewind_to_height(0).unwrap_err(); assert!(err.contains("before_namespace_commit")); assert_eq!((store.canonical_len(), store.tip().unwrap()), (3, Some((2, [0x23; 32]))));
        std::fs::remove_dir(&store.index_path).expect("remove blocker"); std::fs::write(&store.index_path, prior).expect("restore index");
        let scope = AtomicWriteTestScope::new(); scope.fail_at(AtomicWriteTestOp::CleanupUnlink, 1, "postcommit");
        assert!(store.rewind_to_height(0).is_err()); drop(scope);
        assert_cache_matches_index(&store);
        assert_eq!(store.canonical_len(), 1);
        assert_eq!(store.canonical_hash(0).unwrap(), Some([0x21; 32]));
        assert_eq!(store.canonical_hash(1).unwrap(), None);

        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn canonical_hash_cache_coherent_after_rollback_canonical() {
        let dir = unique_temp_path("rubin-blockstore-e7-cache-rollback");
        std::fs::create_dir_all(&dir).expect("create test dir");
        let root = block_store_path(&dir);
        let mut store = BlockStore::create(&root).expect("create");

        store.set_canonical_tip(0, [0x30; 32]).expect("set 0");
        store.set_canonical_tip(1, [0x31; 32]).expect("set 1");
        store.set_canonical_tip(2, [0x32; 32]).expect("set 2");

        // Reorg-style rollback: trim to base_len=1, then re-append two
        // disconnected suffix hashes.
        let suffix = vec![hex::encode([0x41u8; 32]), hex::encode([0x42u8; 32])];
        store
            .rollback_canonical(1, suffix)
            .expect("rollback_canonical");
        assert_cache_matches_index(&store);
        assert_eq!(store.canonical_len(), 3);
        assert_eq!(store.canonical_hash(0).unwrap(), Some([0x30; 32]));
        assert_eq!(store.canonical_hash(1).unwrap(), Some([0x41; 32]));
        assert_eq!(store.canonical_hash(2).unwrap(), Some([0x42; 32]));

        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn canonical_hash_cache_built_eagerly_on_cold_open() {
        // Accepted case: "Cold start with N canonical entries — cache
        // built lazy or eager — pick one and document". We chose
        // eager. After reopening, the cache must already mirror the
        // persisted index without any further write touching the
        // store, and `canonical_hash` must return the right hash with
        // zero hex parses on the read path.
        let dir = unique_temp_path("rubin-blockstore-e7-cache-cold-open");
        std::fs::create_dir_all(&dir).expect("create test dir");
        let root = block_store_path(&dir);
        let entries: Vec<[u8; 32]> = (0..16u8).map(|i| [i; 32]).collect();
        {
            let mut store = BlockStore::create(&root).expect("create");
            for (i, h) in entries.iter().enumerate() {
                store.set_canonical_tip(i as u64, *h).expect("set");
            }
        }
        // Drop the original store, reopen — cache rebuilt from disk.
        let store = BlockStore::open(&root).expect("reopen");
        assert_cache_matches_index(&store);
        for (i, h) in entries.iter().enumerate() {
            assert_eq!(store.canonical_hash(i as u64).unwrap(), Some(*h));
        }
        assert_eq!(
            store.tip().unwrap(),
            Some(((entries.len() - 1) as u64, *entries.last().unwrap()))
        );

        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    /// Fresh temp datadir whose blockstore root does NOT exist yet.
    fn fresh_datadir(prefix: &str) -> PathBuf {
        let dir = unique_temp_path(prefix);
        std::fs::create_dir_all(&dir).expect("create test dir");
        dir
    }

    /// Parity matrix row 1: create with root and chainstate absent commits the
    /// tree plus the EXACT empty version-1 marker, and the store opens after.
    #[test]
    fn create_store_commits_exact_empty_marker() {
        let dir = fresh_datadir("rubin-bs-create-marker");
        let root = block_store_path(&dir);
        let store = BlockStore::create(&root).expect("create");
        assert_eq!(store.canonical_len(), 0);
        for sub in ["blocks", "headers", "undo"] {
            assert!(root.join(sub).is_dir(), "{sub} must be a directory");
        }
        let raw = std::fs::read_to_string(root.join("index.json")).expect("marker");
        let parsed: serde_json::Value = serde_json::from_str(&raw).expect("marker json");
        assert_eq!(parsed, serde_json::json!({"version": 1, "canonical": []}));
        BlockStore::open(&root).expect("strict open of a freshly created store");
        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    /// Parity matrix row 2 + rejected case "create overwrites": an existing root
    /// of any kind is refused, and a PARTIAL root (no marker yet, i.e. a crash
    /// between mkdir and the commit) is adopted by neither constructor.
    #[test]
    fn create_store_rejects_existing_and_partial_root() {
        let dir = fresh_datadir("rubin-bs-create-existing");
        let root = block_store_path(&dir);
        BlockStore::create(&root).expect("first create");
        std::fs::write(root.join("blocks").join("marker.bin"), b"pre-existing")
            .expect("seed artifact");
        let err = BlockStore::create(&root).expect_err("second create must fail");
        assert!(err.contains("create blockstore root"), "{err}");
        assert!(
            root.join("blocks").join("marker.bin").exists(),
            "existing root must not be overwritten or reset"
        );

        let partial = block_store_path(fresh_datadir("rubin-bs-partial"));
        std::fs::create_dir(&partial).expect("partial root");
        assert!(
            BlockStore::create(&partial).is_err(),
            "no resume of a partial root"
        );
        assert!(
            BlockStore::open(&partial).is_err(),
            "no adoption of a partial root"
        );
        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    /// Parity matrix rows 6-8: strict open never repairs and never creates.
    #[test]
    fn open_existing_rejects_uninitialized_tree_without_mutating() {
        type BreakFn = fn(&Path);
        let cases: [(&str, BreakFn); 7] = [
            ("missing_root", |root| {
                std::fs::remove_dir_all(root).expect("drop root");
            }),
            ("missing_subdir", |root| {
                std::fs::remove_dir_all(root.join("undo")).expect("drop undo");
            }),
            ("missing_blocks", |root| {
                std::fs::remove_dir_all(root.join("blocks")).expect("drop blocks");
            }),
            ("missing_headers", |root| {
                std::fs::remove_dir_all(root.join("headers")).expect("drop headers");
            }),
            ("missing_marker", |root| {
                std::fs::remove_file(root.join("index.json")).expect("drop marker");
            }),
            ("root_is_file", |root| {
                std::fs::remove_dir_all(root).expect("drop root");
                std::fs::write(root, b"x").expect("root as file");
            }),
            ("marker_is_directory", |root| {
                std::fs::remove_file(root.join("index.json")).expect("drop marker");
                std::fs::create_dir(root.join("index.json")).expect("marker as dir");
            }),
        ];
        for (name, break_it) in cases {
            let dir = fresh_datadir("rubin-bs-strict-open");
            let root = block_store_path(&dir);
            BlockStore::create(&root).expect("create");
            break_it(&root);
            let err = BlockStore::open(&root).expect_err("row {name} must reject");
            assert!(!err.is_empty(), "row {name}");
            if name == "missing_root" {
                assert!(!root.exists(), "row {name}: strict open must not mkdir");
            } else if name == "missing_marker" {
                assert!(
                    !root.join("index.json").exists(),
                    "row {name}: strict open must not synthesize a marker"
                );
            }
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    /// index_marker_validity as an executing table. Every row must reject; the
    /// Go mirror `TestOpenBlockStoreRejectsMalformedMarker` pins the same rows.
    #[test]
    fn open_existing_rejects_malformed_marker_rows() {
        let hash = "a".repeat(64);
        let rows: Vec<(&str, String)> = vec![
            ("empty", String::new()),
            ("not_an_object", "[]".to_string()),
            ("missing_version", r#"{"canonical":[]}"#.to_string()),
            ("missing_canonical", r#"{"version":1}"#.to_string()),
            (
                "canonical_null",
                r#"{"version":1,"canonical":null}"#.to_string(),
            ),
            (
                "unknown_field",
                r#"{"version":1,"canonical":[],"chain_id":"x"}"#.to_string(),
            ),
            (
                "duplicate_version",
                r#"{"version":1,"version":1,"canonical":[]}"#.to_string(),
            ),
            (
                "duplicate_canonical",
                r#"{"version":1,"canonical":[],"canonical":[]}"#.to_string(),
            ),
            (
                "wrong_version",
                r#"{"version":2,"canonical":[]}"#.to_string(),
            ),
            (
                "version_wrong_type",
                r#"{"version":"1","canonical":[]}"#.to_string(),
            ),
            (
                "version_non_integer",
                r#"{"version":1.0,"canonical":[]}"#.to_string(),
            ),
            (
                "canonical_wrong_type",
                r#"{"version":1,"canonical":{}}"#.to_string(),
            ),
            (
                "entry_uppercase",
                format!(r#"{{"version":1,"canonical":["{}"]}}"#, hash.to_uppercase()),
            ),
            (
                "entry_short",
                r#"{"version":1,"canonical":["ab"]}"#.to_string(),
            ),
            (
                "entry_not_hex",
                format!(r#"{{"version":1,"canonical":["{}"]}}"#, "z".repeat(64)),
            ),
            (
                "entry_wrong_type",
                r#"{"version":1,"canonical":[1]}"#.to_string(),
            ),
            (
                "trailing_value",
                r#"{"version":1,"canonical":[]} {"version":1}"#.to_string(),
            ),
        ];
        let dir = fresh_datadir("rubin-bs-marker-rows");
        let root = block_store_path(&dir);
        BlockStore::create(&root).expect("create");
        for (name, body) in rows {
            std::fs::write(root.join("index.json"), body.as_bytes()).expect("write marker");
            assert!(
                BlockStore::open(&root).is_err(),
                "marker row {name} must be rejected"
            );
        }
        // The accepted rows: empty marker, and a well-formed lowercase entry.
        std::fs::write(root.join("index.json"), br#"{"version":1,"canonical":[]}"#)
            .expect("write marker");
        assert_eq!(
            BlockStore::open(&root)
                .expect("empty marker accepted")
                .canonical_len(),
            0
        );
        std::fs::write(
            root.join("index.json"),
            format!(r#"{{"canonical":["{hash}"],"version":1}}"#).as_bytes(),
        )
        .expect("write marker");
        assert_eq!(
            BlockStore::open(&root)
                .expect("field order is free")
                .canonical_len(),
            1
        );
        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    /// Rule 10 at the LOADER layer: a missing marker must error even though the
    /// tree check above it already rejects — no implicit empty index anywhere.
    /// Go mirror: `TestLoadBlockStoreIndexNeverSynthesizesEmptyIndex`.
    #[test]
    fn open_existing_marker_loader_never_synthesizes_empty_index() {
        let dir = fresh_datadir("rubin-bs-loader");
        let root = block_store_path(&dir);
        BlockStore::create(&root).expect("create");
        let marker = root.join("index.json");
        std::fs::remove_file(&marker).expect("drop marker");
        assert!(
            super::load_blockstore_index(&marker).is_err(),
            "missing marker must not decode as an empty index"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
