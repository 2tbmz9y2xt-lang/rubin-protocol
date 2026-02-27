use std::cmp::Ordering;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use rubin_consensus::{
    block_hash, connect_block_basic_in_memory_at_height, parse_block_bytes,
    ConnectBlockBasicSummary, InMemoryChainState, Outpoint, UtxoEntry,
};
use serde::{Deserialize, Serialize};

use crate::io_utils::{parse_hex32, write_file_atomic};

pub const CHAIN_STATE_FILE_NAME: &str = "chainstate.json";
const CHAIN_STATE_DISK_VERSION: u32 = 1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainState {
    pub has_tip: bool,
    pub height: u64,
    pub tip_hash: [u8; 32],
    pub already_generated: u64,
    pub utxos: HashMap<Outpoint, UtxoEntry>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainStateConnectSummary {
    pub block_height: u64,
    pub block_hash: [u8; 32],
    pub sum_fees: u64,
    pub already_generated: u64,
    pub already_generated_n1: u64,
    pub utxo_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ChainStateDisk {
    version: u32,
    has_tip: bool,
    height: u64,
    tip_hash: String,
    already_generated: u64,
    utxos: Vec<UtxoDiskEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct UtxoDiskEntry {
    txid: String,
    vout: u32,
    value: u64,
    covenant_type: u16,
    covenant_data: String,
    creation_height: u64,
    created_by_coinbase: bool,
}

impl ChainState {
    pub fn new() -> Self {
        Self {
            has_tip: false,
            height: 0,
            tip_hash: [0u8; 32],
            already_generated: 0,
            utxos: HashMap::new(),
        }
    }

    pub fn save<P: AsRef<Path>>(&self, path: P) -> Result<(), String> {
        let path = path.as_ref();
        let disk = state_to_disk(self)?;
        let mut raw =
            serde_json::to_vec_pretty(&disk).map_err(|e| format!("encode chainstate: {e}"))?;
        raw.push(b'\n');

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("create chainstate parent {}: {e}", parent.display()))?;
        }
        write_file_atomic(path, &raw)
    }

    pub fn connect_block(
        &mut self,
        block_bytes: &[u8],
        expected_target: Option<[u8; 32]>,
        prev_timestamps: Option<&[u64]>,
        chain_id: [u8; 32],
    ) -> Result<ChainStateConnectSummary, String> {
        let (block_height, expected_prev_hash) = self.next_block_context()?;
        let mut work_state = InMemoryChainState {
            utxos: self.utxos.clone(),
            already_generated: self.already_generated,
        };

        let connect_summary: ConnectBlockBasicSummary = connect_block_basic_in_memory_at_height(
            block_bytes,
            expected_prev_hash,
            expected_target,
            block_height,
            prev_timestamps,
            &mut work_state,
            chain_id,
        )
        .map_err(|e| e.to_string())?;

        let parsed = parse_block_bytes(block_bytes).map_err(|e| e.to_string())?;
        let tip_hash = block_hash(&parsed.header_bytes).map_err(|e| e.to_string())?;

        self.has_tip = true;
        self.height = block_height;
        self.tip_hash = tip_hash;
        self.already_generated = work_state.already_generated;
        self.utxos = work_state.utxos;

        Ok(ChainStateConnectSummary {
            block_height,
            block_hash: tip_hash,
            sum_fees: connect_summary.sum_fees,
            already_generated: connect_summary.already_generated,
            already_generated_n1: connect_summary.already_generated_n1,
            utxo_count: connect_summary.utxo_count,
        })
    }

    fn next_block_context(&self) -> Result<(u64, Option<[u8; 32]>), String> {
        if !self.has_tip {
            return Ok((0, None));
        }
        if self.height == u64::MAX {
            return Err("height overflow".to_string());
        }
        Ok((self.height + 1, Some(self.tip_hash)))
    }
}

impl Default for ChainState {
    fn default() -> Self {
        Self::new()
    }
}

pub fn chain_state_path<P: AsRef<Path>>(data_dir: P) -> PathBuf {
    data_dir.as_ref().join(CHAIN_STATE_FILE_NAME)
}

pub fn load_chain_state<P: AsRef<Path>>(path: P) -> Result<ChainState, String> {
    let path = path.as_ref();
    let raw = match fs::read(path) {
        Ok(raw) => raw,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(ChainState::new()),
        Err(e) => return Err(format!("read chainstate {}: {e}", path.display())),
    };
    let disk: ChainStateDisk = serde_json::from_slice(&raw)
        .map_err(|e| format!("parse chainstate {}: {e}", path.display()))?;
    chain_state_from_disk(disk)
}

fn state_to_disk(s: &ChainState) -> Result<ChainStateDisk, String> {
    let mut utxos: Vec<UtxoDiskEntry> = s
        .utxos
        .iter()
        .map(|(op, entry)| UtxoDiskEntry {
            txid: hex::encode(op.txid),
            vout: op.vout,
            value: entry.value,
            covenant_type: entry.covenant_type,
            covenant_data: hex::encode(&entry.covenant_data),
            creation_height: entry.creation_height,
            created_by_coinbase: entry.created_by_coinbase,
        })
        .collect();
    utxos.sort_by(|a, b| match a.txid.cmp(&b.txid) {
        Ordering::Equal => a.vout.cmp(&b.vout),
        other => other,
    });

    Ok(ChainStateDisk {
        version: CHAIN_STATE_DISK_VERSION,
        has_tip: s.has_tip,
        height: s.height,
        tip_hash: hex::encode(s.tip_hash),
        already_generated: s.already_generated,
        utxos,
    })
}

fn chain_state_from_disk(disk: ChainStateDisk) -> Result<ChainState, String> {
    if disk.version != CHAIN_STATE_DISK_VERSION {
        return Err(format!("unsupported chainstate version: {}", disk.version));
    }

    let tip_hash = parse_hex32("tip_hash", &disk.tip_hash)?;
    let mut utxos = HashMap::with_capacity(disk.utxos.len());
    for item in disk.utxos {
        let txid = parse_hex32("utxo.txid", &item.txid)?;
        let covenant_data = parse_hex("utxo.covenant_data", &item.covenant_data)?;
        let outpoint = Outpoint {
            txid,
            vout: item.vout,
        };
        if utxos.contains_key(&outpoint) {
            return Err(format!(
                "duplicate utxo outpoint: {}:{}",
                item.txid, item.vout
            ));
        }
        utxos.insert(
            outpoint,
            UtxoEntry {
                value: item.value,
                covenant_type: item.covenant_type,
                covenant_data,
                creation_height: item.creation_height,
                created_by_coinbase: item.created_by_coinbase,
            },
        );
    }

    Ok(ChainState {
        has_tip: disk.has_tip,
        height: disk.height,
        tip_hash,
        already_generated: disk.already_generated,
        utxos,
    })
}

fn parse_hex(name: &str, value: &str) -> Result<Vec<u8>, String> {
    let trimmed = value.trim();
    if !trimmed.len().is_multiple_of(2) {
        return Err(format!("{name}: odd-length hex"));
    }
    hex::decode(trimmed).map_err(|e| format!("{name}: {e}"))
}

#[cfg(test)]
mod tests {
    use crate::io_utils::unique_temp_path;

    use super::{
        chain_state_path, load_chain_state, ChainState, ChainStateDisk, CHAIN_STATE_FILE_NAME,
    };
    use rubin_consensus::{Outpoint, UtxoEntry};

    #[test]
    fn chainstate_roundtrip_with_utxos() {
        let dir = unique_temp_path("rubin-chainstate-test");
        let path = chain_state_path(&dir);
        assert_eq!(
            path.file_name().and_then(|s| s.to_str()),
            Some(CHAIN_STATE_FILE_NAME)
        );

        let mut st = ChainState::new();
        st.has_tip = true;
        st.height = 42;
        st.tip_hash = [0x11; 32];
        st.already_generated = 77;
        st.utxos.insert(
            Outpoint {
                txid: [0x22; 32],
                vout: 3,
            },
            UtxoEntry {
                value: 123,
                covenant_type: 0,
                covenant_data: vec![0x01; 33],
                creation_height: 10,
                created_by_coinbase: false,
            },
        );

        st.save(&path).expect("save");
        let got = load_chain_state(&path).expect("load");
        assert_eq!(got, st);

        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn load_chainstate_rejects_wrong_version() {
        let dir = unique_temp_path("rubin-chainstate-version-test");
        let path = chain_state_path(&dir);
        std::fs::create_dir_all(&dir).expect("mkdir");

        let bad = ChainStateDisk {
            version: 999,
            has_tip: false,
            height: 0,
            tip_hash: "00".repeat(32),
            already_generated: 0,
            utxos: vec![],
        };
        let raw = serde_json::to_vec_pretty(&bad).expect("json");
        std::fs::write(&path, raw).expect("write");

        let err = load_chain_state(&path).unwrap_err();
        assert!(err.contains("unsupported chainstate version"));

        std::fs::remove_dir_all(&dir).expect("cleanup");
    }
}
