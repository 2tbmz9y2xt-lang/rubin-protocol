use std::fs;
use std::path::{Path, PathBuf};

pub const BLOCK_STORE_DIR_NAME: &str = "blocks";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockStore {
    root: PathBuf,
}

impl BlockStore {
    pub fn open<P: Into<PathBuf>>(root: P) -> Result<Self, String> {
        let root = root.into();
        if root.as_os_str().is_empty() {
            return Err("blockstore root is required".to_string());
        }
        fs::create_dir_all(&root).map_err(|e| format!("create blockstore dir {}: {e}", root.display()))?;
        Ok(Self { root })
    }

    pub fn root_dir(&self) -> &Path {
        &self.root
    }
}

