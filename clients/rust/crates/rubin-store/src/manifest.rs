//! MANIFEST.json — single crash-recovery anchor for the node.
//!
//! Rules (from RUBIN_NODE_STORAGE_MODEL_v1.1.md §4.1):
//! - Update only after a block is fully applied (all DB writes committed).
//! - Writes MUST be atomic: write temp → fsync → rename.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

pub const CURRENT_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Manifest {
    pub schema_version: u32,
    pub chain_id_hex: String,
    pub tip_hash: String,
    pub tip_height: u64,
    pub tip_cumulative_work: String, // decimal string for determinism
    pub last_applied_block_hash: String,
    pub last_applied_height: u64,
}

impl Manifest {
    /// Create an initial manifest for genesis state.
    pub fn genesis(chain_id_hex: &str, genesis_hash_hex: &str, genesis_work: u128) -> Self {
        Self {
            schema_version: CURRENT_SCHEMA_VERSION,
            chain_id_hex: chain_id_hex.to_string(),
            tip_hash: genesis_hash_hex.to_string(),
            tip_height: 0,
            tip_cumulative_work: genesis_work.to_string(),
            last_applied_block_hash: genesis_hash_hex.to_string(),
            last_applied_height: 0,
        }
    }

    /// Load manifest from a JSON file.
    pub fn load(path: &Path) -> Result<Self, String> {
        let data = fs::read_to_string(path).map_err(|e| format!("read manifest: {e}"))?;
        let m: Manifest =
            serde_json::from_str(&data).map_err(|e| format!("parse manifest: {e}"))?;
        if m.schema_version > CURRENT_SCHEMA_VERSION {
            return Err(format!(
                "manifest schema_version {} is newer than supported {}",
                m.schema_version, CURRENT_SCHEMA_VERSION,
            ));
        }
        Ok(m)
    }

    /// Atomically save manifest: write to temp file → fsync → rename.
    pub fn save_atomic(&self, path: &Path) -> Result<(), String> {
        let dir = path
            .parent()
            .ok_or_else(|| "manifest path has no parent dir".to_string())?;

        // Use a unique tmp name to avoid cross-test/process collisions.
        // Uniqueness is an operational property, not a consensus one.
        let pid = std::process::id();
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let tmp_path = dir.join(format!(".MANIFEST.json.tmp.{pid}.{nanos}"));

        let json =
            serde_json::to_string_pretty(self).map_err(|e| format!("serialize manifest: {e}"))?;

        let mut f = fs::File::create(&tmp_path).map_err(|e| format!("create manifest tmp: {e}"))?;
        f.write_all(json.as_bytes())
            .map_err(|e| format!("write manifest tmp: {e}"))?;
        f.sync_all()
            .map_err(|e| format!("fsync manifest tmp: {e}"))?;
        drop(f);

        fs::rename(&tmp_path, path).map_err(|e| format!("rename manifest: {e}"))?;

        // fsync parent directory for rename durability (POSIX requirement).
        if let Ok(dir_f) = fs::File::open(dir) {
            let _ = dir_f.sync_all();
        }

        Ok(())
    }

    /// Update manifest tip fields after a block apply.
    pub fn update_tip(&mut self, block_hash_hex: &str, height: u64, cumulative_work: u128) {
        self.tip_hash = block_hash_hex.to_string();
        self.tip_height = height;
        self.tip_cumulative_work = cumulative_work.to_string();
        self.last_applied_block_hash = block_hash_hex.to_string();
        self.last_applied_height = height;
    }

    /// Return the manifest file path given a chain directory.
    pub fn path_in(chain_dir: &Path) -> PathBuf {
        chain_dir.join("MANIFEST.json")
    }

    /// Parse tip_hash hex to 32 bytes.
    pub fn tip_hash_bytes(&self) -> Result<[u8; 32], String> {
        hex_to_32(&self.tip_hash)
    }

    /// Parse tip_cumulative_work from decimal string.
    pub fn tip_cumulative_work_u128(&self) -> Result<u128, String> {
        self.tip_cumulative_work
            .parse::<u128>()
            .map_err(|e| format!("parse cumulative_work: {e}"))
    }
}

fn hex_to_32(s: &str) -> Result<[u8; 32], String> {
    let bytes = rubin_consensus::hex_decode_strict(s)?;
    if bytes.len() != 32 {
        return Err(format!("expected 32-byte hex, got {} bytes", bytes.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_manifest_roundtrip() {
        let m = Manifest::genesis("ab".repeat(32).as_str(), "cd".repeat(32).as_str(), 42);
        let dir = std::env::temp_dir();
        let path = dir.join("test_manifest.json");
        m.save_atomic(&path).unwrap();
        let loaded = Manifest::load(&path).unwrap();
        assert_eq!(m, loaded);
        let _ = std::fs::remove_file(&path);
    }
}
