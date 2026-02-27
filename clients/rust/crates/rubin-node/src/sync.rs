use std::path::PathBuf;

use rubin_consensus::{block_hash, parse_block_bytes};

use crate::blockstore::BlockStore;
use crate::chainstate::{ChainState, ChainStateConnectSummary};

pub const DEFAULT_IBD_LAG_SECONDS: u64 = 24 * 60 * 60;
const DEFAULT_HEADER_BATCH_LIMIT: u64 = 512;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyncConfig {
    pub header_batch_limit: u64,
    pub ibd_lag_seconds: u64,
    pub expected_target: Option<[u8; 32]>,
    pub chain_id: [u8; 32],
    pub chain_state_path: Option<PathBuf>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeaderRequest {
    pub from_hash: [u8; 32],
    pub has_from: bool,
    pub limit: u64,
}

#[derive(Debug)]
pub struct SyncEngine {
    chain_state: ChainState,
    block_store: Option<BlockStore>,
    cfg: SyncConfig,
    tip_timestamp: u64,
    best_known_height: u64,
}

pub fn default_sync_config(
    expected_target: Option<[u8; 32]>,
    chain_id: [u8; 32],
    chain_state_path: Option<PathBuf>,
) -> SyncConfig {
    SyncConfig {
        header_batch_limit: DEFAULT_HEADER_BATCH_LIMIT,
        ibd_lag_seconds: DEFAULT_IBD_LAG_SECONDS,
        expected_target,
        chain_id,
        chain_state_path,
    }
}

impl SyncEngine {
    pub fn new(
        chain_state: ChainState,
        block_store: Option<BlockStore>,
        mut cfg: SyncConfig,
    ) -> Result<Self, String> {
        if cfg.header_batch_limit == 0 {
            cfg.header_batch_limit = DEFAULT_HEADER_BATCH_LIMIT;
        }
        if cfg.ibd_lag_seconds == 0 {
            cfg.ibd_lag_seconds = DEFAULT_IBD_LAG_SECONDS;
        }
        Ok(Self {
            chain_state,
            block_store,
            cfg,
            tip_timestamp: 0,
            best_known_height: 0,
        })
    }

    pub fn header_sync_request(&self) -> HeaderRequest {
        if !self.chain_state.has_tip {
            return HeaderRequest {
                from_hash: [0u8; 32],
                has_from: false,
                limit: self.cfg.header_batch_limit,
            };
        }
        HeaderRequest {
            from_hash: self.chain_state.tip_hash,
            has_from: true,
            limit: self.cfg.header_batch_limit,
        }
    }

    pub fn record_best_known_height(&mut self, height: u64) {
        if height > self.best_known_height {
            self.best_known_height = height;
        }
    }

    pub fn best_known_height(&self) -> u64 {
        self.best_known_height
    }

    pub fn is_in_ibd(&self, now_unix: u64) -> bool {
        if !self.chain_state.has_tip {
            return true;
        }
        if now_unix < self.tip_timestamp {
            return true;
        }
        now_unix - self.tip_timestamp > self.cfg.ibd_lag_seconds
    }

    pub fn apply_block(
        &mut self,
        block_bytes: &[u8],
        prev_timestamps: Option<&[u64]>,
    ) -> Result<ChainStateConnectSummary, String> {
        let parsed = parse_block_bytes(block_bytes).map_err(|e| e.to_string())?;
        let block_hash_bytes = block_hash(&parsed.header_bytes).map_err(|e| e.to_string())?;

        let snapshot = self.chain_state.clone();
        let old_tip_timestamp = self.tip_timestamp;
        let old_best_known_height = self.best_known_height;

        let summary = self.chain_state.connect_block(
            block_bytes,
            self.cfg.expected_target,
            prev_timestamps,
            self.cfg.chain_id,
        )?;

        if let Some(block_store) = self.block_store.as_mut() {
            if let Err(err) = block_store.put_block(
                summary.block_height,
                block_hash_bytes,
                &parsed.header_bytes,
                block_bytes,
            ) {
                self.chain_state = snapshot;
                self.tip_timestamp = old_tip_timestamp;
                self.best_known_height = old_best_known_height;
                return Err(err);
            }
        }

        if let Some(chain_state_path) = self.cfg.chain_state_path.as_ref() {
            if let Err(err) = self.chain_state.save(chain_state_path) {
                self.chain_state = snapshot;
                self.tip_timestamp = old_tip_timestamp;
                self.best_known_height = old_best_known_height;
                return Err(err);
            }
        }

        self.tip_timestamp = parsed.header.timestamp;
        if summary.block_height > self.best_known_height {
            self.best_known_height = summary.block_height;
        }

        Ok(summary)
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use rubin_consensus::constants::{COV_TYPE_P2PK, POW_LIMIT};
    use rubin_consensus::{Outpoint, UtxoEntry};

    use crate::blockstore::{block_store_path, BlockStore};
    use crate::chainstate::{chain_state_path, load_chain_state, ChainState};
    use crate::sync::{default_sync_config, SyncEngine};

    const VALID_BLOCK_HEX: &str = "01000000111111111111111111111111111111111111111111111111111111111111111102e66000bf8ce870908df4a8689554852ccef681ee0b5df32246162a53e36e290100000000000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff07000000000000000101000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000ffffffff00ffffffff010000000000000000020020b716a4b7f4c0fab665298ab9b8199b601ab9fa7e0a27f0713383f34cf37071a8000000000000";

    fn hex_to_bytes(hex: &str) -> Vec<u8> {
        let mut out = Vec::with_capacity(hex.len() / 2);
        let bytes = hex.as_bytes();
        let mut idx = 0;
        while idx + 1 < bytes.len() {
            let nibble = |b: u8| -> u8 {
                match b {
                    b'0'..=b'9' => b - b'0',
                    b'a'..=b'f' => b - b'a' + 10,
                    b'A'..=b'F' => b - b'A' + 10,
                    _ => panic!("invalid hex"),
                }
            };
            out.push((nibble(bytes[idx]) << 4) | nibble(bytes[idx + 1]));
            idx += 2;
        }
        out
    }

    fn tmp_dir(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "rubin-node-sync-{name}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time")
                .as_nanos()
        ))
    }

    #[test]
    fn sync_engine_ibd_logic_and_header_request() {
        let st = ChainState::new();
        let cfg = default_sync_config(None, [0u8; 32], None);
        let mut engine = SyncEngine::new(st, None, cfg).expect("new sync engine");

        let req = engine.header_sync_request();
        assert!(!req.has_from);
        assert_eq!(req.limit, 512);
        assert!(engine.is_in_ibd(1_000));

        engine.chain_state.has_tip = true;
        engine.chain_state.height = 10;
        engine.chain_state.tip_hash = [0x11; 32];
        engine.tip_timestamp = 1_000;
        engine.cfg.ibd_lag_seconds = 100;

        let req2 = engine.header_sync_request();
        assert!(req2.has_from);
        assert_eq!(req2.from_hash, [0x11; 32]);

        assert!(engine.is_in_ibd(1_200));
        assert!(!engine.is_in_ibd(1_050));
    }

    #[test]
    fn sync_engine_apply_block_persists_chainstate_and_store() {
        let dir = tmp_dir("persist");
        let chain_state_file = chain_state_path(&dir);
        let block_store_root = block_store_path(&dir);
        let store = BlockStore::open(block_store_root).expect("open blockstore");

        let st = ChainState::new();
        let cfg = default_sync_config(Some(POW_LIMIT), [0u8; 32], Some(chain_state_file.clone()));
        let mut engine = SyncEngine::new(st, Some(store), cfg).expect("new sync");

        let block = hex_to_bytes(VALID_BLOCK_HEX);
        let summary = engine.apply_block(&block, None).expect("apply block");
        assert_eq!(summary.block_height, 0);

        assert!(chain_state_file.exists());
        let loaded = load_chain_state(&chain_state_file).expect("load chainstate");
        assert!(loaded.has_tip);
        assert_eq!(loaded.height, 0);

        let tip = engine
            .block_store
            .as_ref()
            .expect("store")
            .tip()
            .expect("tip")
            .expect("some tip");
        assert_eq!(tip.0, 0);

        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn sync_engine_apply_block_no_mutation_on_failure() {
        let mut st = ChainState::new();
        st.has_tip = true;
        st.height = 5;
        st.tip_hash = [0xaa; 32];
        st.already_generated = 10;
        st.utxos.insert(
            Outpoint {
                txid: [0xbb; 32],
                vout: 0,
            },
            UtxoEntry {
                value: 1,
                covenant_type: COV_TYPE_P2PK,
                covenant_data: {
                    let mut bytes = Vec::with_capacity(33);
                    bytes.push(0x01);
                    bytes.extend_from_slice(&[0x22; 32]);
                    bytes
                },
                creation_height: 1,
                created_by_coinbase: false,
            },
        );

        let cfg = default_sync_config(None, [0u8; 32], None);
        let mut engine = SyncEngine::new(st, None, cfg).expect("new sync");
        engine.tip_timestamp = 333;
        engine.best_known_height = 777;

        let before = engine.chain_state.clone();
        let before_tip_timestamp = engine.tip_timestamp;
        let before_best_known = engine.best_known_height;

        let err = engine.apply_block(&[0x01, 0x02], None).unwrap_err();
        assert!(!err.is_empty());
        assert_eq!(engine.chain_state, before);
        assert_eq!(engine.tip_timestamp, before_tip_timestamp);
        assert_eq!(engine.best_known_height, before_best_known);
    }
}
