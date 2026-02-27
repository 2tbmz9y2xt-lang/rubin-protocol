use std::fs;
use std::path::{Path, PathBuf};

use rubin_consensus::{block_hash, BLOCK_HEADER_BYTES};
use serde::{Deserialize, Serialize};

use crate::io_utils::{parse_hex32, write_file_atomic};

pub const BLOCK_STORE_DIR_NAME: &str = "blockstore";
const BLOCK_STORE_INDEX_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockStore {
    root_path: PathBuf,
    index_path: PathBuf,
    blocks_dir: PathBuf,
    headers_dir: PathBuf,
    index: BlockStoreIndexDisk,
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

        fs::create_dir_all(&blocks_dir)
            .map_err(|e| format!("create blockstore blocks {}: {e}", blocks_dir.display()))?;
        fs::create_dir_all(&headers_dir)
            .map_err(|e| format!("create blockstore headers {}: {e}", headers_dir.display()))?;

        let index = load_blockstore_index(&index_path)?;
        Ok(Self {
            root_path,
            index_path,
            blocks_dir,
            headers_dir,
            index,
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
        if height == current_len {
            self.index.canonical.push(hash_hex);
        } else if self.index.canonical[height as usize] != hash_hex {
            self.index.canonical.truncate(height as usize);
            self.index.canonical.push(hash_hex);
        }
        save_blockstore_index(&self.index_path, &self.index)
    }

    pub fn rewind_to_height(&mut self, height: u64) -> Result<(), String> {
        if self.index.canonical.is_empty() {
            return Ok(());
        }
        if height >= self.index.canonical.len() as u64 {
            return Err(format!("rewind height out of range: {height}"));
        }
        self.index.canonical.truncate(height as usize + 1);
        save_blockstore_index(&self.index_path, &self.index)
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
}
