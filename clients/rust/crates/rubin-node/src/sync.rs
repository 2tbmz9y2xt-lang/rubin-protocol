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

    use rubin_consensus::constants::{COV_TYPE_ANCHOR, COV_TYPE_P2PK, POW_LIMIT};
    use rubin_consensus::merkle::{witness_commitment_hash, witness_merkle_root_wtxids};
    use rubin_consensus::{encode_compact_size, merkle_root_txids, parse_tx, Outpoint, UtxoEntry};

    use crate::blockstore::{block_store_path, BlockStore};
    use crate::chainstate::{chain_state_path, load_chain_state, ChainState};
    use crate::sync::{default_sync_config, SyncEngine};

    #[derive(Clone)]
    struct TestOutput {
        value: u64,
        covenant_type: u16,
        covenant_data: Vec<u8>,
    }

    fn build_block_bytes(
        prev_hash: [u8; 32],
        merkle_root: [u8; 32],
        target: [u8; 32],
        timestamp: u64,
        nonce: u64,
        txs: &[Vec<u8>],
    ) -> Vec<u8> {
        let mut header = Vec::with_capacity(84);
        header.extend_from_slice(&1u32.to_le_bytes());
        header.extend_from_slice(&prev_hash);
        header.extend_from_slice(&merkle_root);
        header.extend_from_slice(&timestamp.to_le_bytes());
        header.extend_from_slice(&target);
        header.extend_from_slice(&nonce.to_le_bytes());

        let mut block = header;
        encode_compact_size(txs.len() as u64, &mut block);
        for tx in txs {
            block.extend_from_slice(tx);
        }
        block
    }

    fn coinbase_tx_with_outputs(locktime: u32, outputs: &[TestOutput]) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&1u32.to_le_bytes());
        b.push(0x00);
        b.extend_from_slice(&0u64.to_le_bytes());
        encode_compact_size(1, &mut b);
        b.extend_from_slice(&[0u8; 32]);
        b.extend_from_slice(&u32::MAX.to_le_bytes());
        encode_compact_size(0, &mut b);
        b.extend_from_slice(&u32::MAX.to_le_bytes());
        encode_compact_size(outputs.len() as u64, &mut b);
        for out in outputs {
            b.extend_from_slice(&out.value.to_le_bytes());
            b.extend_from_slice(&out.covenant_type.to_le_bytes());
            encode_compact_size(out.covenant_data.len() as u64, &mut b);
            b.extend_from_slice(&out.covenant_data);
        }
        b.extend_from_slice(&locktime.to_le_bytes());
        encode_compact_size(0, &mut b);
        encode_compact_size(0, &mut b);
        b
    }

    fn valid_p2pk_covenant_data(seed: u8) -> Vec<u8> {
        let mut out = Vec::with_capacity(33);
        out.push(0x01);
        out.extend_from_slice(&[seed; 32]);
        out
    }

    fn coinbase_with_witness_commitment_and_p2pk_value(locktime: u32, value: u64) -> Vec<u8> {
        let wroot = witness_merkle_root_wtxids(&[[0u8; 32]]).expect("witness root");
        let commitment = witness_commitment_hash(wroot);
        coinbase_tx_with_outputs(
            locktime,
            &[
                TestOutput {
                    value,
                    covenant_type: COV_TYPE_P2PK,
                    covenant_data: valid_p2pk_covenant_data(0x42),
                },
                TestOutput {
                    value: 0,
                    covenant_type: COV_TYPE_ANCHOR,
                    covenant_data: commitment.to_vec(),
                },
            ],
        )
    }

    fn build_single_tx_block(
        prev_hash: [u8; 32],
        target: [u8; 32],
        timestamp: u64,
        coinbase_tx: &[u8],
    ) -> Vec<u8> {
        let (_, txid, _, _) = parse_tx(coinbase_tx).expect("parse coinbase");
        let root = merkle_root_txids(&[txid]).expect("merkle root");
        build_block_bytes(
            prev_hash,
            root,
            target,
            timestamp,
            7,
            &[coinbase_tx.to_vec()],
        )
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

        let coinbase = coinbase_with_witness_commitment_and_p2pk_value(0, 1);
        let block = build_single_tx_block([0x11; 32], POW_LIMIT, 12_345, &coinbase);
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
                covenant_data: valid_p2pk_covenant_data(0x22),
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
