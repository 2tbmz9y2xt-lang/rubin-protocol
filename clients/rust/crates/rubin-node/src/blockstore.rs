use std::fs;
use std::path::{Path, PathBuf};

use num_bigint::BigUint;
use rubin_consensus::{
    block_hash, fork_chainwork_from_targets, parse_block_header_bytes, BLOCK_HEADER_BYTES,
};
use serde::{Deserialize, Serialize};

use crate::io_utils::{parse_hex32, write_file_atomic};
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
        Ok(Self {
            root_path,
            index_path,
            blocks_dir,
            headers_dir,
            undo_dir,
            index,
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
        //       idempotent replay (the crash-recovery path where
        //       `commit_canonical_block` advanced the blockstore tip but
        //       `chain_state.save` crashed; on restart
        //       `SyncEngine::apply_block` replays the already-persisted
        //       block at its original height). Handle as a pure no-op:
        //       return `Ok(())` with no `persist_block_bytes`, no
        //       `put_undo`, no tip mutation. Header bytes are still
        //       validated so replay matches the append path's header/hash
        //       consistency contract.
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
                // Idempotent same-hash replay. Two sub-cases:
                //
                //  (a) Undo file already on disk — pure no-op: don't
                //      rewrite the historical undo (matches the
                //      Copilot earlier-round concern that
                //      `write_file_atomic` would clobber the historical
                //      bytes even on a same-hash retry).
                //
                //  (b) Undo file missing — pre-E.4 / partial-commit
                //      recovery case: crash between block persist and
                //      undo write left a canonical entry with no undo.
                //      Heal by writing the caller-supplied undo via
                //      `put_undo`; this is the path that made
                //      `SyncEngine::apply_block` replay able to repair
                //      the node on restart before the atomic API
                //      existed. Do NOT error here — the canonical
                //      entry is already on disk, the undo is simply
                //      being back-filled.
                self.validate_header_matches_hash(header_bytes, block_hash_bytes)?;
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
    /// the caller-supplied hash. Shared by `persist_block_bytes` (as the
    /// precondition for any disk write) and by the same-hash no-op branch
    /// of `commit_canonical_block` (so replay/no-op behavior matches the
    /// append path's validation contract even when no write happens).
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

    /// Block/header persistence shared by `put_block` and
    /// `commit_canonical_block`. Validates header length + hash, then
    /// writes block and header files via `write_file_if_absent`
    /// (idempotent across retries).
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
        } else {
            self.index.canonical.truncate(height as usize);
            self.index.canonical.push(hash_hex);
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
        if let Err(e) = save_blockstore_index(&self.index_path, &self.index) {
            self.reload_index_from_disk();
            return Err(e);
        }
        Ok(())
    }

    pub fn canonical_hash(&self, height: u64) -> Result<Option<[u8; 32]>, String> {
        if height >= self.index.canonical.len() as u64 {
            return Ok(None);
        }
        let hash = parse_hex32("canonical hash", &self.index.canonical[height as usize])?;
        Ok(Some(hash))
    }

    pub fn tip(&self) -> Result<Option<(u64, [u8; 32])>, String> {
        if self.index.canonical.is_empty() {
            return Ok(None);
        }
        let height = self.index.canonical.len() as u64 - 1;
        let hash = parse_hex32("tip hash", &self.index.canonical[height as usize])?;
        Ok(Some((height, hash)))
    }

    pub fn get_block_by_hash(&self, block_hash_bytes: [u8; 32]) -> Result<Vec<u8>, String> {
        let path = self
            .blocks_dir
            .join(format!("{}.bin", hex::encode(block_hash_bytes)));
        fs::read(&path).map_err(|e| format!("read block {}: {e}", path.display()))
    }

    pub fn get_header_by_hash(&self, block_hash_bytes: [u8; 32]) -> Result<Vec<u8>, String> {
        let path = self
            .headers_dir
            .join(format!("{}.bin", hex::encode(block_hash_bytes)));
        fs::read(&path).map_err(|e| format!("read header {}: {e}", path.display()))
    }

    pub fn has_block(&self, block_hash_bytes: [u8; 32]) -> bool {
        self.headers_dir
            .join(format!("{}.bin", hex::encode(block_hash_bytes)))
            .exists()
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
        if header_bytes.len() != BLOCK_HEADER_BYTES {
            return Err(format!("invalid header length: {}", header_bytes.len()));
        }
        let computed_hash = block_hash(header_bytes).map_err(|e| e.to_string())?;
        if computed_hash != block_hash_bytes {
            return Err("header hash mismatch".to_string());
        }
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
        write_file_atomic(&path, &raw)
    }

    pub fn get_undo(&self, block_hash_bytes: [u8; 32]) -> Result<BlockUndo, String> {
        let path = self
            .undo_dir
            .join(format!("{}.json", hex::encode(block_hash_bytes)));
        let raw = fs::read(&path).map_err(|e| format!("read undo {}: {e}", path.display()))?;
        unmarshal_block_undo(&raw)
    }

    /// Cheap undo-presence check used by the same-hash replay branch of
    /// `commit_canonical_block` to verify that a canonical entry
    /// inherited from pre-E.4 disk state (or corrupted in some other
    /// way) actually has its undo file on disk before accepting the
    /// replay as a no-op.
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
        let view = BlockStoreIndexView {
            version: self.index.version,
            canonical: &next_canonical,
        };
        save_blockstore_index_serializable(&self.index_path, &view)?;
        // Save succeeded — commit to in-memory.
        self.index.canonical = next_canonical;
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
            self.index = disk;
        }
    }
}

pub fn block_store_path<P: AsRef<Path>>(data_dir: P) -> PathBuf {
    data_dir.as_ref().join(BLOCK_STORE_DIR_NAME)
}

fn load_blockstore_index(path: &Path) -> Result<BlockStoreIndexDisk, String> {
    let raw = match fs::read(path) {
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
    for (idx, hash_hex) in index.canonical.iter().enumerate() {
        parse_hex32(&format!("canonical[{idx}]"), hash_hex)?;
    }
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
    write_file_atomic(path, &raw)
}

/// Borrowed view of `BlockStoreIndexDisk` that serializes identically
/// but holds `&[String]` instead of owning the vector.  Used for
/// out-of-place writes (truncate/rollback) on the rare disconnect path.
#[derive(serde::Serialize)]
struct BlockStoreIndexView<'a> {
    version: u32,
    canonical: &'a [String],
}

fn write_file_if_absent(path: &Path, content: &[u8]) -> Result<(), String> {
    match fs::read(path) {
        Ok(existing) => {
            if existing != content {
                return Err(format!(
                    "file already exists with different content: {}",
                    path.display()
                ));
            }
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            write_file_atomic(path, content)?;
            let existing =
                fs::read(path).map_err(|err| format!("read back {}: {err}", path.display()))?;
            if existing != content {
                return Err(format!("written content mismatch: {}", path.display()));
            }
            Ok(())
        }
        Err(e) => Err(format!("read {}: {e}", path.display())),
    }
}

#[cfg(test)]
mod tests {
    use crate::io_utils::unique_temp_path;

    use super::{block_store_path, BlockStore, BLOCK_STORE_DIR_NAME};

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
        // Block/header files land before the undo step fires, which is
        // safe because `write_file_if_absent` is idempotent on retry and
        // no canonical entry references them until the tip advances.
        assert!(store.has_block(hash));

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
        assert_eq!(store.canonical_len(), 0);
        assert!(store.tip().expect("tip").is_none());
        assert!(
            !store.has_block(hash),
            "block/header files must not be written before the mismatch check"
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

        // No disk writes: block/header/undo files must NOT exist.
        assert_eq!(store.canonical_len(), 0);
        assert!(!store.has_block(hash));

        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    /// Crash-recovery path (GPT-5 review P1): after a successful
    /// `commit_canonical_block` that advanced the blockstore tip, if
    /// `chain_state.save` crashes the chain state lags the blockstore
    /// by one or more blocks. On restart `SyncEngine::apply_block`
    /// replays the already-persisted block at its original height and
    /// MUST succeed so recovery can proceed; it MUST NOT rewrite the
    /// historical block/header/undo files because `put_undo` via
    /// `write_file_atomic` would clobber the historical undo on disk.
    /// The same-hash replay is therefore handled as a no-op: no disk
    /// writes, no tip mutation, `Ok(())` returned (header bytes are
    /// still validated for consistency with the append path).
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
}
