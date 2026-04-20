use std::fs;
use std::path::{Path, PathBuf};

use num_bigint::BigUint;
use rubin_consensus::{
    block_hash, fork_chainwork_from_targets, parse_block_header_bytes, BLOCK_HEADER_BYTES,
};
use serde::{Deserialize, Serialize};

use crate::io_utils::{
    parse_hex32, read_file_by_path, read_file_from_dir, write_file_atomic_by_path,
    write_file_exclusive, AtomicWriteError,
};
use crate::undo::{marshal_block_undo, unmarshal_block_undo, BlockUndo};

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
struct BlockStoreIndexDisk {
    version: u32,
    canonical: Vec<String>,
}

impl BlockStore {
    pub fn open<P: Into<PathBuf>>(root_path: P) -> Result<Self, String> {
        let root_path = root_path.into();
        if root_path.as_os_str().is_empty() {
            return Err("blockstore root is required".to_string());
        }

        let index_path = root_path.join("index.json");
        let blocks_dir = root_path.join("blocks");
        let headers_dir = root_path.join("headers");
        let undo_dir = root_path.join("undo");

        fs::create_dir_all(&blocks_dir)
            .map_err(|e| format!("create blockstore blocks {}: {e}", blocks_dir.display()))?;
        fs::create_dir_all(&headers_dir)
            .map_err(|e| format!("create blockstore headers {}: {e}", headers_dir.display()))?;
        fs::create_dir_all(&undo_dir)
            .map_err(|e| format!("create blockstore undo {}: {e}", undo_dir.display()))?;

        let index = load_blockstore_index(&index_path)?;
        let canonical_hash_by_height = build_canonical_hash_cache(&index.canonical)?;
        Ok(Self {
            root_path,
            index_path,
            blocks_dir,
            headers_dir,
            undo_dir,
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
    /// Note: a subsequent `chain_state.save` failure AFTER a successful
    /// `commit_canonical_block` still requires the caller to call
    /// `truncate_canonical(canonical_len_before)` because the tip has
    /// already advanced; that rewind is outside the atomic boundary of
    /// this API (see `sync.rs` main commit callsite).
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
        // 0. Reject mismatched undo up front. If `undo.block_height` does
        //    not match the canonical height being committed, a later
        //    `ChainState::disconnect_block` would trip its height invariant
        //    and the tip would already have advanced — exactly the
        //    non-atomic failure mode this API is closing. Rejecting before
        //    any disk write keeps the canonical state untouched.
        if undo.block_height != height {
            return Err(format!(
                "undo block_height mismatch: commit height={height}, undo.block_height={}",
                undo.block_height
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
            return Err(format!(
                "commit_canonical_block height gap: height={height} > canonical_len={current_len}"
            ));
        }
        if height < current_len {
            let existing = self.canonical_hash(height)?;
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
                self.persist_block_bytes(block_hash_bytes, header_bytes, block_bytes)?;
                if !self.has_undo(block_hash_bytes) {
                    self.put_undo(block_hash_bytes, undo)?;
                }
                return Ok(());
            }
            // Different hash at historical height: real reorg; fall
            // through to persist + tip replace.
        }
        // 1. Persist block + header bytes (idempotent `write_file_if_absent`).
        self.persist_block_bytes(block_hash_bytes, header_bytes, block_bytes)?;
        // 2. Persist undo BEFORE any tip advance. Matches Go ordering in
        //    `CommitCanonicalBlock` (StoreBlock → PutUndo → SetCanonicalTip).
        self.put_undo(block_hash_bytes, undo)?;
        // 3. Advance canonical tip LAST — this is the atomic commit point.
        self.set_canonical_tip(height, block_hash_bytes)
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
        self.validate_header_matches_hash(header_bytes, block_hash_bytes)?;
        let hash_hex = hex::encode(block_hash_bytes);
        write_file_if_absent(
            &self.blocks_dir.join(format!("{hash_hex}.bin")),
            block_bytes,
        )?;
        write_file_if_absent(
            &self.headers_dir.join(format!("{hash_hex}.bin")),
            header_bytes,
        )
    }

    /// Set or replace the canonical tip at `height`.
    ///
    /// Hot path (called per connected block via `put_block`): mutate
    /// in-memory then save; on save failure best-effort
    /// `reload_index_from_disk` to restore in-memory consistency.
    /// Avoids the O(chain_height) clone that out-of-place transactions
    /// would cost on every block.
    pub fn set_canonical_tip(
        &mut self,
        height: u64,
        block_hash_bytes: [u8; 32],
    ) -> Result<(), String> {
        let hash_hex = hex::encode(block_hash_bytes);
        let current_len = self.index.canonical.len() as u64;
        if height > current_len {
            return Err(format!(
                "height gap: got {height}, expected <= {current_len}"
            ));
        }
        // No-op if in-memory already holds this exact hash at this height.
        if height < current_len && self.index.canonical[height as usize] == hash_hex {
            return Ok(());
        }
        if height == current_len {
            self.index.canonical.push(hash_hex);
            self.canonical_hash_by_height.push(block_hash_bytes);
        } else {
            self.index.canonical.truncate(height as usize);
            self.canonical_hash_by_height.truncate(height as usize);
            self.index.canonical.push(hash_hex);
            self.canonical_hash_by_height.push(block_hash_bytes);
        }
        if let Err(e) = save_blockstore_index(&self.index_path, &self.index) {
            self.reload_index_from_disk();
            return Err(e);
        }
        Ok(())
    }

    /// Rewind canonical to (height + 1) entries.
    ///
    /// Same hot-path strategy as `set_canonical_tip`: mutate-then-save
    /// with reload on failure (avoids per-call clone of the canonical
    /// vector).
    pub fn rewind_to_height(&mut self, height: u64) -> Result<(), String> {
        if self.index.canonical.is_empty() {
            return Ok(());
        }
        if height >= self.index.canonical.len() as u64 {
            return Err(format!("rewind height out of range: {height}"));
        }
        self.index.canonical.truncate(height as usize + 1);
        self.canonical_hash_by_height.truncate(height as usize + 1);
        if let Err(e) = save_blockstore_index(&self.index_path, &self.index) {
            self.reload_index_from_disk();
            return Err(e);
        }
        Ok(())
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

    pub fn get_block_by_hash(&self, block_hash_bytes: [u8; 32]) -> Result<Vec<u8>, String> {
        // E.10: route through `read_file_from_dir` so the leaf name is
        // validated against the same traversal / absolute-path / empty-name
        // guard Go enforces in `readFileFromDir`. The synthesized
        // `<hex>.bin` cannot in practice contain a separator, but the
        // guard removes the entire class of "leaf name from on-disk
        // index drift becomes a traversal" without runtime cost.
        let name = format!("{}.bin", hex::encode(block_hash_bytes));
        read_file_from_dir(&self.blocks_dir, &name)
            .map_err(|e| format!("read block {}: {e}", self.blocks_dir.join(&name).display()))
    }

    pub fn get_header_by_hash(&self, block_hash_bytes: [u8; 32]) -> Result<Vec<u8>, String> {
        // E.10: see `get_block_by_hash` doc.
        let name = format!("{}.bin", hex::encode(block_hash_bytes));
        read_file_from_dir(&self.headers_dir, &name).map_err(|e| {
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
        // Delegate to the shared helper so header validation and
        // block/header file writes stay in one place across all
        // entry points (`put_block`, `commit_canonical_block`,
        // `store_block`).
        self.persist_block_bytes(block_hash_bytes, header_bytes, block_bytes)
    }

    // ----- Chain work -----

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
                return Err("blockstore parent cycle".into());
            }
            let header_bytes = self.get_header_by_hash(current)?;
            let header = parse_block_header_bytes(&header_bytes).map_err(|e| e.to_string())?;
            targets.push(header.target);
            current = header.prev_block_hash;
        }
        fork_chainwork_from_targets(&targets).map_err(|e| e.to_string())
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
    pub(crate) fn put_undo(
        &self,
        block_hash_bytes: [u8; 32],
        undo: &BlockUndo,
    ) -> Result<(), String> {
        #[cfg(test)]
        if self.force_undo_error {
            return Err("forced undo error (test)".to_string());
        }
        let raw = marshal_block_undo(undo)?;
        let path = self
            .undo_dir
            .join(format!("{}.json", hex::encode(block_hash_bytes)));
        write_file_atomic_by_path(&path, &raw)
    }

    pub fn get_undo(&self, block_hash_bytes: [u8; 32]) -> Result<BlockUndo, String> {
        // E.10: see `get_block_by_hash` doc.
        let name = format!("{}.json", hex::encode(block_hash_bytes));
        let raw = read_file_from_dir(&self.undo_dir, &name)
            .map_err(|e| format!("read undo {}: {e}", self.undo_dir.join(&name).display()))?;
        unmarshal_block_undo(&raw)
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
    /// A failed call leaves the in-memory canonical exactly as it was
    /// before, so callers can rely on `Err` meaning "no state change".
    pub fn rollback_canonical(
        &mut self,
        base_len: usize,
        suffix: Vec<String>,
    ) -> Result<(), String> {
        #[cfg(test)]
        if self.force_rollback_error {
            return Err("forced rollback error (test inject)".into());
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
        // closed without touching disk. Documented atomicity contract
        // ("Err means no state change") requires every fallible step to
        // run before `save_blockstore_index_serializable`.
        let next_cache = build_canonical_hash_cache(&next_canonical)?;
        let view = BlockStoreIndexView {
            version: self.index.version,
            canonical: &next_canonical,
        };
        save_blockstore_index_serializable(&self.index_path, &view)?;
        // Disk save succeeded — commit to in-memory (E.7 parity: mirror
        // Go's `replaceCanonicalState` rebuild after rollback).
        self.index.canonical = next_canonical;
        self.canonical_hash_by_height = next_cache;
        Ok(())
    }

    /// Truncate canonical index to exactly `new_len` entries.
    ///
    /// Atomic: in-memory state is updated ONLY after the disk write
    /// succeeds.  A failed call leaves the in-memory canonical exactly
    /// as it was before, so callers can rely on `Err` meaning "no
    /// state change".  Writes a borrowed slice-backed view of the
    /// target prefix instead of cloning all canonical strings.
    pub fn truncate_canonical(&mut self, new_len: usize) -> Result<(), String> {
        #[cfg(test)]
        if self.force_truncate_error {
            return Err("forced truncate error (test inject)".into());
        }
        let current_len = self.index.canonical.len();
        if new_len > current_len {
            return Err(format!(
                "truncate_canonical new_len {new_len} > current {current_len}"
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
        save_blockstore_index_serializable(&self.index_path, &view)?;
        // Save succeeded — now apply O(1) in-memory truncate.
        self.index.canonical.truncate(new_len);
        // E.7: keep height->hash cache coherent with the canonical
        // slice. Truncate is the only path that needs this on the
        // accepted-cases test (`canonical_hash` after `truncate_canonical(n)`
        // returns None for h >= n).
        self.canonical_hash_by_height.truncate(new_len);
        Ok(())
    }

    /// Reload the blockstore index from disk to restore in-memory
    /// consistency after a failed save in a hot-path mutator
    /// (`set_canonical_tip`, `rewind_to_height`).  Best-effort: if the
    /// reload itself fails the in-memory state is stale, but we have
    /// already returned the original error to the caller — the engine
    /// is in an unrecoverable state and needs repair.  Not used by
    /// `truncate_canonical` / `rollback_canonical`, which use the
    /// out-of-place transaction pattern instead.
    fn reload_index_from_disk(&mut self) {
        if let Ok(disk) = load_blockstore_index(&self.index_path) {
            // E.7: canonical hash decoding/validation happens in
            // `build_canonical_hash_cache` (not in `load_blockstore_index`).
            // If disk canonical entries are malformed, keep the prior
            // in-memory state untouched to preserve the documented
            // unrecoverable-state contract.
            if let Ok(cache) = build_canonical_hash_cache(&disk.canonical) {
                self.canonical_hash_by_height = cache;
                self.index = disk;
            }
        }
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
    // E.10: route through `read_file_by_path` so the index file read
    // gets the same leaf-name guard Go's `loadBlockStoreIndex` enforces
    // via its `readFileByPath` call. Mirrors Go cross-client.
    let raw = match read_file_by_path(path) {
        Ok(raw) => raw,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(BlockStoreIndexDisk {
                version: BLOCK_STORE_INDEX_VERSION,
                canonical: vec![],
            });
        }
        Err(e) => return Err(format!("read blockstore index {}: {e}", path.display())),
    };
    let index: BlockStoreIndexDisk = serde_json::from_slice(&raw)
        .map_err(|e| format!("decode blockstore index {}: {e}", path.display()))?;
    if index.version != BLOCK_STORE_INDEX_VERSION {
        return Err(format!(
            "unsupported blockstore index version: {}",
            index.version
        ));
    }
    // Canonical hash validation is performed in `build_canonical_hash_cache`
    // when callers (e.g. `BlockStore::open`, `reload_index_from_disk`) build
    // the height->hash cache from this index. Validating here would re-decode
    // every canonical entry on cold start (one decode in this loop, another
    // inside `build_canonical_hash_cache`); the cache build is the
    // single sanctioned `parse_hex32` site for canonical entries. Any caller
    // that consumes `index.canonical` strings without going through that
    // helper is expected to keep its own validation discipline.
    Ok(index)
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
    let mut raw =
        serde_json::to_vec_pretty(index).map_err(|e| format!("encode blockstore index: {e}"))?;
    raw.push(b'\n');
    write_file_atomic_by_path(path, &raw)
}

/// Borrowed view of `BlockStoreIndexDisk` that serializes identically
/// but holds `&[String]` instead of owning the vector.  Used for
/// out-of-place writes (truncate/rollback) on the rare disconnect path.
#[derive(serde::Serialize)]
struct BlockStoreIndexView<'a> {
    version: u32,
    canonical: &'a [String],
}

/// Write `content` to `path` only if the destination is absent
/// (idempotent replay: a subsequent call with matching bytes is a
/// silent no-op). Hardened against the TOCTOU race audited as `E.3`:
/// the previous implementation did `fs::read()` then `write_file_atomic`
/// which could silently overwrite a file that appeared between the two
/// syscalls. The new implementation keeps a read-compare fast path for
/// the idempotent-replay case (matches the Go `writeFileIfAbsent` fast
/// path) and falls through to `io_utils::write_file_exclusive` (which
/// uses `hard_link(2)` for atomic create-if-absent) only when the
/// destination is genuinely absent. On EEXIST from the race window we
/// read back the destination and preserve the idempotent-same-content
/// contract; on content mismatch we surface an explicit error.
///
/// Read-compare fast path matters for two reasons (Codex review on
/// PR #1220):
/// 1. idempotent replay during sync-engine restart is the dominant
///    caller and must not do unnecessary disk I/O;
/// 2. it keeps the "dest already has matching bytes" case working even
///    when the parent directory is temporarily unwritable (for example
///    chmod 0o500 hardening), because read does not need write
///    permission but the temp-write path does.
///
/// Mirrors the Go `writeFileIfAbsent` helper's `os.Link` flow for
/// cross-client storage parity.
///
/// # Threat model
///
/// **Concurrent actors**: Two writers race on `fs::hard_link(tmp, path)`;
/// exactly one link succeeds. The loser sees `AlreadyExists`, reads the
/// winner's content, and returns `Ok(())` on match (idempotent replay)
/// or an explicit error on drift (never overwrite). Per-call
/// `temp_path_for(path, pid, next_temp_seq())` gives distinct temp
/// paths so in-process threads never collide.
///
/// **Process crash**: A crash between `hard_link` and the best-effort
/// temp-unlink leaves a stale `<pid>.<seq>` hard-linked to the
/// destination inode. That is safe: `write_and_sync_temp` uses
/// `O_CREATE|O_EXCL` (no `O_TRUNC`), so any later call hitting the same
/// temp path returns `AlreadyExists` via `allocate_and_write_temp` and
/// retries with a fresh `seq` (16-retry budget). Startup reconcile
/// (`E.2`) sweeps orphan `.tmp.*` siblings. A crash before the final
/// `sync_dir` leaves the dirent in page cache; the fast-path on retry
/// re-runs `sync_dir` and PROPAGATES its error so the durability
/// failure is surfaced.
///
/// **Cross-platform**: Unix (Linux, macOS) is the production target:
/// `fs::hard_link`, `create_new(true)` (O_EXCL), and directory fsync
/// all honoured. Windows: directory fsync is a no-op at the stdlib
/// level; `fs::remove_file` on an open fd would fail, which is why
/// `write_and_sync_temp` explicitly `drop(fd)` before `remove_file`.
/// Rust does not ship Rubin on Windows as a production target.
///
/// **Retry / exhaustion**: `allocate_and_write_temp` retries up to
/// `MAX_TEMP_ALLOC_RETRIES` (16) on `AlreadyExists` with a fresh
/// `next_temp_seq()`. Fatal I/O surfaces immediately. Exhaustion
/// surfaces as `Err` mentioning the destination path.
///
/// **Inode / fs-layer**: `hard_link` is refcount-safe — destination
/// and temp share the inode; unlinking temp drops the name without
/// affecting bytes visible through `path`. `O_TRUNC` on any path that
/// could share an inode with a live destination is intentionally
/// avoided everywhere in the helper stack; see `write_and_sync_temp`
/// for the explicit O_EXCL contract.
///
/// **Durability**: `write_and_sync_temp` fsyncs the temp's bytes + inode
/// metadata before returning. `fs::hard_link` then exposes the inode
/// under `path`. `sync_dir` on the parent flushes the directory entry
/// so the link is itself durable. Both the `Ok` fast-path and the
/// `AlreadyExists`-retry branches PROPAGATE the final `sync_dir` error
/// — the previous `let _ = sync_dir(parent)` double-swallowed EIO
/// through `sync_dir`'s own best-effort wrapper (Copilot P1 wave-7 on
/// PR #1220).
fn write_file_if_absent(path: &Path, content: &[u8]) -> Result<(), String> {
    // Fast path: destination already on disk. Same behaviour as the Go
    // helper's `readFileByPathFn(path)` fast path — short-circuit
    // before any temp write when the file is already present with the
    // right bytes (dominant idempotent-replay case).
    //
    // Copilot P1 on PR #1220: a previous call may have successfully
    // created the destination but returned an error from the final
    // `sync_dir(parent)` step (e.g. transient EIO). If the caller
    // retries, we hit this fast-path and would silently report Ok
    // without ever making the directory entry durable. Re-run
    // `sync_dir` on the idempotent match branch and PROPAGATE its
    // result — `io_utils::sync_dir` already applies the intended
    // permission policy internally (execute-only/hardened parents
    // treated as Ok), so propagating does NOT break the
    // idempotent-replay-on-hardened-dir contract; it only surfaces
    // real durability failures (EIO / ENOENT) that would otherwise be
    // silent.
    //
    // Copilot P1 wave-7 on PR #1220: `let _ = sync_dir(parent)`
    // double-swallowed errors — `sync_dir` is already best-effort,
    // so the outer `let _` discarded the exact failures that MUST
    // reach the caller. Propagate via `?` instead.
    match fs::read(path) {
        Ok(existing) => {
            if existing != content {
                return Err(format!(
                    "file already exists with different content: {}",
                    path.display()
                ));
            }
            if let Some(parent) = crate::io_utils::effective_parent(path) {
                crate::io_utils::sync_dir(parent)?;
            }
            return Ok(());
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // Fall through to the race-hardened atomic write.
        }
        Err(e) => {
            return Err(format!("read existing {}: {e}", path.display()));
        }
    }

    match write_file_exclusive(path, content) {
        Ok(()) => Ok(()),
        Err(AtomicWriteError::AlreadyExists) => {
            // Race: destination appeared between the fast-path read
            // and our link. Verify content matches (idempotent retry)
            // or surface the drift as an error — never silently
            // overwrite, never return Ok on drift.
            let existing =
                fs::read(path).map_err(|e| format!("read existing {}: {e}", path.display()))?;
            if existing != content {
                return Err(format!(
                    "file already exists with different content: {}",
                    path.display()
                ));
            }
            // Propagate parent dir-sync result on the EEXIST-retry
            // branch for the same reason as the Ok fast-path above:
            // `sync_dir` already applies the permission policy, so
            // `?` surfaces only real durability failures.
            if let Some(parent) = crate::io_utils::effective_parent(path) {
                crate::io_utils::sync_dir(parent)?;
            }
            Ok(())
        }
        Err(AtomicWriteError::Other(msg)) => Err(msg),
    }
}

#[cfg(test)]
mod tests {
    use crate::io_utils::unique_temp_path;

    use super::{block_store_path, write_file_if_absent, BlockStore, BLOCK_STORE_DIR_NAME};

    /// Happy path for the E.3-hardened helper: destination absent,
    /// write_file_if_absent creates it via the atomic hard_link path,
    /// and a subsequent call with matching bytes is an idempotent
    /// no-op. Mirrors the Go `TestWriteFileIfAbsent_Fresh` for
    /// cross-client parity.
    #[test]
    fn write_file_if_absent_fresh_then_idempotent() {
        let dir = unique_temp_path("rubin-wfia-fresh");
        std::fs::create_dir_all(&dir).expect("create test dir");
        let path = dir.join("fresh.bin");
        let content = b"hello E.3".to_vec();

        write_file_if_absent(&path, &content).expect("fresh write");
        let got = std::fs::read(&path).expect("read back");
        assert_eq!(got, content);

        // Idempotent replay: same bytes must succeed as a no-op.
        write_file_if_absent(&path, &content).expect("idempotent replay");

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
        let root = block_store_path(&dir);
        assert_eq!(
            root.file_name().and_then(|s| s.to_str()),
            Some(BLOCK_STORE_DIR_NAME)
        );

        let mut store = BlockStore::open(&root).expect("open");
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
        let root = block_store_path(&dir);
        let store = BlockStore::open(&root).expect("open");

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

    #[test]
    fn blockstore_chain_work_from_genesis() {
        use crate::genesis::devnet_genesis_block_bytes;
        use rubin_consensus::{block_hash, BLOCK_HEADER_BYTES};

        let dir = unique_temp_path("rubin-blockstore-cw");
        let root = block_store_path(&dir);
        let mut store = BlockStore::open(&root).expect("open");

        let genesis = devnet_genesis_block_bytes();
        let hash = block_hash(&genesis[..BLOCK_HEADER_BYTES]).expect("hash");
        store
            .put_block(0, hash, &genesis[..BLOCK_HEADER_BYTES], &genesis)
            .expect("put");

        let work = store.chain_work(hash).expect("chain_work");
        assert!(work > num_bigint::BigUint::ZERO);

        let zero_work = store.chain_work([0u8; 32]).expect("zero");
        assert_eq!(zero_work, num_bigint::BigUint::ZERO);

        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn blockstore_undo_put_get_roundtrip() {
        use crate::undo::{BlockUndo, TxUndo};

        let dir = unique_temp_path("rubin-blockstore-undo");
        let root = block_store_path(&dir);
        let store = BlockStore::open(&root).expect("open");

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
        let root = block_store_path(&dir);
        let mut store = BlockStore::open(&root).expect("open");

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
        let root = block_store_path(&dir);
        let mut store = BlockStore::open(&root).expect("open");

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
        let root = block_store_path(&dir);
        let mut store = BlockStore::open(&root).expect("open");

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
        let root = block_store_path(&dir);
        let mut store = BlockStore::open(&root).expect("open");

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
        let root = block_store_path(&dir);
        let mut store = BlockStore::open(&root).expect("open");

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
        let root = block_store_path(&dir);
        let mut store = BlockStore::open(&root).expect("open");

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
        let root = block_store_path(&dir);
        let mut store = BlockStore::open(&root).expect("open");

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
        let root = block_store_path(&dir);
        let mut store = BlockStore::open(&root).expect("open");

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

    #[test]
    fn canonical_hash_cache_coherent_after_replace_at_height() {
        // set_canonical_tip(height < current_len, different hash) is
        // the reorg-replace branch (truncate-then-push). The cache
        // must follow exactly: a stale entry at the replaced height
        // is the rejected case.
        let dir = unique_temp_path("rubin-blockstore-e7-cache-replace");
        let root = block_store_path(&dir);
        let mut store = BlockStore::open(&root).expect("open");

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

    #[test]
    fn canonical_hash_cache_coherent_after_rewind_to_height() {
        let dir = unique_temp_path("rubin-blockstore-e7-cache-rewind");
        let root = block_store_path(&dir);
        let mut store = BlockStore::open(&root).expect("open");

        store.set_canonical_tip(0, [0x21; 32]).expect("set 0");
        store.set_canonical_tip(1, [0x22; 32]).expect("set 1");
        store.set_canonical_tip(2, [0x23; 32]).expect("set 2");

        store.rewind_to_height(0).expect("rewind to 0");
        assert_cache_matches_index(&store);
        assert_eq!(store.canonical_len(), 1);
        assert_eq!(store.canonical_hash(0).unwrap(), Some([0x21; 32]));
        assert_eq!(store.canonical_hash(1).unwrap(), None);

        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn canonical_hash_cache_coherent_after_rollback_canonical() {
        let dir = unique_temp_path("rubin-blockstore-e7-cache-rollback");
        let root = block_store_path(&dir);
        let mut store = BlockStore::open(&root).expect("open");

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
        let root = block_store_path(&dir);
        let entries: Vec<[u8; 32]> = (0..16u8).map(|i| [i; 32]).collect();
        {
            let mut store = BlockStore::open(&root).expect("open");
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
}
