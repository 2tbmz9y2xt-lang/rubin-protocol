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
        )?;
        self.set_canonical_tip(height, block_hash_bytes)
    }

    /// Set or replace the canonical tip at `height`.  Atomic: in-memory
    /// canonical is updated only after the disk write succeeds, so a
    /// failed call leaves the in-memory state unchanged.
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
        // Skip the disk write if the in-memory slot already holds the
        // exact same hash.  Otherwise build the next index out-of-place.
        if height < current_len && self.index.canonical[height as usize] == hash_hex {
            return Ok(());
        }
        let mut next_index = self.index.clone();
        if height == current_len {
            next_index.canonical.push(hash_hex);
        } else {
            next_index.canonical.truncate(height as usize);
            next_index.canonical.push(hash_hex);
        }
        save_blockstore_index(&self.index_path, &next_index)?;
        self.index = next_index;
        Ok(())
    }

    /// Rewind canonical to (height + 1) entries.  Atomic: in-memory
    /// state is updated only after the disk write succeeds.
    pub fn rewind_to_height(&mut self, height: u64) -> Result<(), String> {
        if self.index.canonical.is_empty() {
            return Ok(());
        }
        if height >= self.index.canonical.len() as u64 {
            return Err(format!("rewind height out of range: {height}"));
        }
        let mut next_index = self.index.clone();
        next_index.canonical.truncate(height as usize + 1);
        save_blockstore_index(&self.index_path, &next_index)?;
        self.index = next_index;
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

    pub fn put_undo(&self, block_hash_bytes: [u8; 32], undo: &BlockUndo) -> Result<(), String> {
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
    /// Atomic: on disk-write failure the index is reloaded from disk
    /// so in-memory state stays consistent (no temp buffer needed).
    /// Restore canonical to `base_len` entries from current canonical
    /// followed by `suffix`.  Atomic: in-memory state is updated ONLY
    /// after the disk write succeeds, so a failed call leaves the
    /// in-memory canonical exactly as it was before the call (callers
    /// can rely on `Err` meaning "no state change").
    pub fn rollback_canonical(
        &mut self,
        base_len: usize,
        suffix: Vec<String>,
    ) -> Result<(), String> {
        #[cfg(test)]
        if self.force_rollback_error {
            return Err("forced rollback error (test inject)".into());
        }
        let mut next_canonical = Vec::with_capacity(base_len + suffix.len());
        next_canonical
            .extend_from_slice(&self.index.canonical[..base_len.min(self.index.canonical.len())]);
        next_canonical.extend(suffix);
        let mut next_index = self.index.clone();
        next_index.canonical = next_canonical;
        save_blockstore_index(&self.index_path, &next_index)?;
        self.index = next_index;
        Ok(())
    }

    /// Truncate canonical index to exactly `new_len` entries.
    ///
    /// Atomic: in-memory state is updated ONLY after the disk write
    /// succeeds.  A failed call leaves the in-memory canonical exactly
    /// as it was before, so callers can rely on `Err` meaning "no
    /// state change".
    pub fn truncate_canonical(&mut self, new_len: usize) -> Result<(), String> {
        #[cfg(test)]
        if self.force_truncate_error {
            return Err("forced truncate error (test inject)".into());
        }
        if new_len > self.index.canonical.len() {
            return Err(format!(
                "truncate_canonical new_len {} > current {}",
                new_len,
                self.index.canonical.len()
            ));
        }
        let mut next_index = self.index.clone();
        next_index.canonical.truncate(new_len);
        save_blockstore_index(&self.index_path, &next_index)?;
        self.index = next_index;
        Ok(())
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
    let mut raw =
        serde_json::to_vec_pretty(index).map_err(|e| format!("encode blockstore index: {e}"))?;
    raw.push(b'\n');
    write_file_atomic(path, &raw)
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
}
