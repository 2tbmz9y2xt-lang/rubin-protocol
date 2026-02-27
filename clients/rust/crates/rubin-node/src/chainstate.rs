use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

pub const CHAIN_STATE_FILE_NAME: &str = "chainstate.json";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainTip {
    pub height: u64,
    pub block_hash_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainStateData {
    pub tip: ChainTip,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainState {
    path: PathBuf,
}

impl ChainState {
    pub fn open<P: Into<PathBuf>>(path: P) -> Result<Self, String> {
        let path = path.into();
        if path.as_os_str().is_empty() {
            return Err("chainstate path is required".to_string());
        }
        Ok(Self { path })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn load_or_init(&self) -> Result<ChainStateData, String> {
        if !self.path.exists() {
            return Ok(ChainStateData {
                tip: ChainTip {
                    height: 0,
                    block_hash_hex: "00".repeat(32),
                },
            });
        }
        let raw = fs::read_to_string(&self.path).map_err(|e| format!("read chainstate {}: {e}", self.path.display()))?;
        serde_json::from_str(&raw).map_err(|e| format!("parse chainstate {}: {e}", self.path.display()))
    }

    pub fn save(&self, data: &ChainStateData) -> Result<(), String> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("create chainstate parent {}: {e}", parent.display()))?;
        }
        let raw = serde_json::to_string_pretty(data).map_err(|e| format!("encode chainstate: {e}"))?;
        fs::write(&self.path, raw).map_err(|e| format!("write chainstate {}: {e}", self.path.display()))
    }
}

#[cfg(test)]
mod tests {
    use super::{ChainState, ChainStateData, ChainTip};

    #[test]
    fn chainstate_roundtrip() {
        let dir = std::env::temp_dir().join(format!(
            "rubin-chainstate-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time")
                .as_nanos()
        ));
        let path = dir.join("chainstate.json");
        let cs = ChainState::open(&path).expect("open");

        let data = ChainStateData {
            tip: ChainTip {
                height: 42,
                block_hash_hex: "11".repeat(32),
            },
        };
        cs.save(&data).expect("save");
        let got = cs.load_or_init().expect("load");
        assert_eq!(got, data);

        std::fs::remove_dir_all(&dir).expect("cleanup");
    }
}

