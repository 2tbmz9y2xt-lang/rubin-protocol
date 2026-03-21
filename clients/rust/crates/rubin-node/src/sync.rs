use std::path::PathBuf;
use std::sync::Arc;

use rubin_consensus::constants::POW_LIMIT;
use rubin_consensus::{
    block_hash, parse_block_bytes, parse_block_header_bytes, CoreExtDeploymentProfiles,
};
use rubin_consensus::{RotationProvider, SuiteRegistry};

use crate::blockstore::BlockStore;
use crate::chainstate::{ChainState, ChainStateConnectSummary};
use crate::undo::build_block_undo;

pub const DEFAULT_IBD_LAG_SECONDS: u64 = 24 * 60 * 60;
const DEFAULT_HEADER_BATCH_LIMIT: u64 = 512;

#[derive(Clone, Debug)]
pub struct SyncConfig {
    pub header_batch_limit: u64,
    pub ibd_lag_seconds: u64,
    pub expected_target: Option<[u8; 32]>,
    pub chain_id: [u8; 32],
    pub chain_state_path: Option<PathBuf>,
    pub network: String,
    pub core_ext_deployments: CoreExtDeploymentProfiles,
    pub suite_context: Option<SuiteContext>,
}

#[derive(Clone)]
pub struct SuiteContext {
    pub rotation: Arc<dyn RotationProvider + Send + Sync>,
    pub registry: Arc<SuiteRegistry>,
}

impl std::fmt::Debug for SuiteContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SuiteContext")
            .field("rotation", &"<dyn RotationProvider>")
            .field("registry", &self.registry)
            .finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeaderRequest {
    pub from_hash: [u8; 32],
    pub has_from: bool,
    pub limit: u64,
}

#[derive(Debug)]
pub struct SyncEngine {
    pub(crate) chain_state: ChainState,
    pub(crate) block_store: Option<BlockStore>,
    pub(crate) cfg: SyncConfig,
    pub(crate) tip_timestamp: u64,
    pub(crate) best_known_height: u64,
}

/// Captured state for rollback on failure during reorg.
#[derive(Clone, Debug)]
pub(crate) struct SyncRollbackState {
    pub chain_state: ChainState,
    pub canonical_len: usize,
    /// Suffix of canonical entries removed during disconnect (reorg path).
    /// For rollback: truncate canonical to `canonical_len`, then re-append
    /// this suffix.  `None` for light rollback (disconnect_tip).
    /// O(reorg_depth) instead of O(chain_height).
    pub canonical_removed_suffix: Option<Vec<String>>,
    pub tip_timestamp: u64,
    pub best_known_height: u64,
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
        network: "devnet".to_string(),
        core_ext_deployments: CoreExtDeploymentProfiles::empty(),
        suite_context: None,
    }
}

impl SyncEngine {
    pub(crate) fn suite_context(&self) -> (Option<&dyn RotationProvider>, Option<&SuiteRegistry>) {
        match self.cfg.suite_context.as_ref() {
            Some(ctx) => (Some(ctx.rotation.as_ref()), Some(ctx.registry.as_ref())),
            None => (None, None),
        }
    }

    pub fn new(
        chain_state: ChainState,
        block_store: Option<BlockStore>,
        mut cfg: SyncConfig,
    ) -> Result<Self, String> {
        validate_mainnet_genesis_guard(&cfg)?;
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

    pub fn chain_state_snapshot(&self) -> ChainState {
        self.chain_state.clone()
    }

    pub fn chain_id(&self) -> [u8; 32] {
        self.cfg.chain_id
    }

    pub fn core_ext_deployments(&self) -> CoreExtDeploymentProfiles {
        self.cfg.core_ext_deployments.clone()
    }

    pub fn tip(&self) -> Result<Option<(u64, [u8; 32])>, String> {
        if let Some(block_store) = self.block_store.as_ref() {
            return block_store.tip();
        }
        if !self.chain_state.has_tip {
            return Ok(None);
        }
        Ok(Some((self.chain_state.height, self.chain_state.tip_hash)))
    }

    pub fn locator_hashes(&self, limit: usize) -> Result<Vec<[u8; 32]>, String> {
        match self.block_store.as_ref() {
            Some(block_store) => block_store.locator_hashes(limit),
            None => Ok(Vec::new()),
        }
    }

    pub fn hashes_after_locators(
        &self,
        locator_hashes: &[[u8; 32]],
        stop_hash: [u8; 32],
        limit: u64,
    ) -> Result<Vec<[u8; 32]>, String> {
        match self.block_store.as_ref() {
            Some(block_store) => {
                block_store.hashes_after_locators(locator_hashes, stop_hash, limit)
            }
            None => Ok(Vec::new()),
        }
    }

    pub fn get_block_by_hash(&self, block_hash_bytes: [u8; 32]) -> Result<Vec<u8>, String> {
        let Some(block_store) = self.block_store.as_ref() else {
            return Err("sync engine missing blockstore".to_string());
        };
        block_store.get_block_by_hash(block_hash_bytes)
    }

    pub fn has_block(&self, block_hash_bytes: [u8; 32]) -> Result<bool, String> {
        let Some(block_store) = self.block_store.as_ref() else {
            return Ok(false);
        };
        Ok(block_store.has_block(block_hash_bytes))
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
        let derived_prev_timestamps = if prev_timestamps.is_none() {
            self.prev_timestamps_for_next_block()?
        } else {
            None
        };
        let prev_timestamps = prev_timestamps.or(derived_prev_timestamps.as_deref());

        let snapshot = self.chain_state.clone();
        let old_tip_timestamp = self.tip_timestamp;
        let old_best_known_height = self.best_known_height;

        // Build undo record from the pre-mutation state.
        let next_height = if self.chain_state.has_tip {
            self.chain_state.height + 1
        } else {
            0
        };
        let undo = build_block_undo(&self.chain_state, block_bytes, next_height)?;

        let suite_context = self.cfg.suite_context.clone();
        let (rotation, registry): (Option<&dyn RotationProvider>, Option<&SuiteRegistry>) =
            match suite_context.as_ref() {
                Some(ctx) => (Some(ctx.rotation.as_ref()), Some(ctx.registry.as_ref())),
                None => (None, None),
            };
        let summary = self
            .chain_state
            .connect_block_with_core_ext_deployments_and_suite_context(
                block_bytes,
                self.cfg.expected_target,
                prev_timestamps,
                self.cfg.chain_id,
                &self.cfg.core_ext_deployments,
                rotation,
                registry,
            )?;

        let canonical_len_before = self.block_store.as_ref().map_or(0, |bs| bs.canonical_len());
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
            // Persist the undo record alongside the block.
            if let Err(err) = block_store.put_undo(block_hash_bytes, &undo) {
                // Rewind canonical to the length captured before put_block.
                let rewind_err = block_store.truncate_canonical(canonical_len_before).err();
                self.chain_state = snapshot;
                self.tip_timestamp = old_tip_timestamp;
                self.best_known_height = old_best_known_height;
                if let Some(rewind_err) = rewind_err {
                    return Err(format!(
                        "{err}; failed to rewind canonical index after undo write failure: {rewind_err}; blockstore may require repair"
                    ));
                }
                return Err(err);
            }
        }

        if let Some(chain_state_path) = self.cfg.chain_state_path.as_ref() {
            if let Err(err) = self.chain_state.save(chain_state_path) {
                // Rewind canonical index to the length captured before put_block.
                if let Some(bs) = self.block_store.as_mut() {
                    let _ = bs.truncate_canonical(canonical_len_before);
                }
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

    // ----- Rollback helpers (used by sync_disconnect / sync_reorg) -----

    /// Light rollback state — no canonical suffix (used by disconnect_tip).
    pub(crate) fn capture_rollback_state(&self) -> SyncRollbackState {
        SyncRollbackState {
            chain_state: self.chain_state.clone(),
            canonical_len: self.block_store.as_ref().map_or(0, |bs| bs.canonical_len()),
            canonical_removed_suffix: None,
            tip_timestamp: self.tip_timestamp,
            best_known_height: self.best_known_height,
        }
    }

    /// Reorg rollback state — captures only the canonical suffix that
    /// will be removed during disconnect (O(reorg_depth), not O(height)).
    pub(crate) fn capture_reorg_rollback_state(
        &self,
        common_ancestor_height: u64,
    ) -> SyncRollbackState {
        let reorg_base = (common_ancestor_height as usize).saturating_add(1);
        SyncRollbackState {
            chain_state: self.chain_state.clone(),
            canonical_len: reorg_base,
            canonical_removed_suffix: self
                .block_store
                .as_ref()
                .map(|bs| bs.canonical_suffix_from(reorg_base)),
            tip_timestamp: self.tip_timestamp,
            best_known_height: self.best_known_height,
        }
    }

    /// Rollback in-memory and persisted state to the captured snapshot.
    ///
    /// Canonical index is rolled back FIRST (IO operation).  Only after
    /// that succeeds are in-memory fields updated and chain_state saved.
    /// This ordering prevents partial mutations on IO failure.
    ///
    /// Returns an error description if persistence failed — callers
    /// should surface this as a repair hint.
    pub(crate) fn rollback_apply_block(&mut self, rb: SyncRollbackState) -> Option<String> {
        // Phase 1: canonical index rollback (IO) — fail-fast before
        // mutating any in-memory state.
        if let Some(bs) = self.block_store.as_mut() {
            let res = if let Some(suffix) = rb.canonical_removed_suffix {
                // Reorg path: truncate to base, re-append removed suffix.
                bs.rollback_canonical(rb.canonical_len, suffix)
            } else {
                // Light rollback: truncate to saved length (disconnect_tip).
                bs.truncate_canonical(rb.canonical_len)
            };
            if let Err(e) = res {
                return Some(format!("canonical rollback failed: {e}"));
            }
        }

        // Phase 2: update in-memory state and persist chain_state.
        self.chain_state = rb.chain_state;
        self.tip_timestamp = rb.tip_timestamp;
        self.best_known_height = rb.best_known_height;

        if let Some(path) = self.cfg.chain_state_path.as_ref() {
            if let Err(e) = self.chain_state.save(path) {
                return Some(format!(
                    "chain_state save on rollback failed \
                     (canonical already rolled back, may require repair): {e}"
                ));
            }
        }

        None
    }

    /// Format an error message, optionally appending rollback failure details.
    pub(crate) fn err_with_rollback(err: String, rb: Option<String>) -> String {
        match rb {
            Some(rb_err) => {
                format!("{err}; rollback failed: {rb_err}; blockstore may require repair")
            }
            None => err,
        }
    }

    pub fn prev_timestamps_for_next_block(&self) -> Result<Option<Vec<u64>>, String> {
        if !self.chain_state.has_tip {
            return Ok(None);
        }
        if self.chain_state.height == u64::MAX {
            return Err("height overflow".to_string());
        }

        let Some(block_store) = self.block_store.as_ref() else {
            return Err("sync engine missing blockstore for timestamp context".to_string());
        };

        let next_height = self.chain_state.height + 1;
        let window_len = next_height.min(11);
        let mut out = Vec::with_capacity(window_len as usize);
        for offset in 0..window_len {
            let height = next_height - 1 - offset;
            let Some(hash) = block_store.canonical_hash(height)? else {
                return Err("missing canonical header for timestamp context".to_string());
            };
            let header_bytes = block_store.get_header_by_hash(hash)?;
            let header = parse_block_header_bytes(&header_bytes).map_err(|e| e.to_string())?;
            out.push(header.timestamp);
        }
        Ok(Some(out))
    }
}

fn validate_mainnet_genesis_guard(cfg: &SyncConfig) -> Result<(), String> {
    let network = cfg.network.trim().to_ascii_lowercase();
    let network = if network.is_empty() {
        "devnet".to_string()
    } else {
        network
    };
    if network != "mainnet" {
        return Ok(());
    }
    let expected_target = cfg
        .expected_target
        .ok_or_else(|| "mainnet requires explicit expected_target".to_string())?;
    if expected_target == POW_LIMIT {
        return Err("mainnet expected_target must not equal devnet POW_LIMIT (all-ff)".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use rubin_consensus::constants::{COV_TYPE_EXT, COV_TYPE_P2PK, POW_LIMIT};
    use rubin_consensus::merkle::{witness_commitment_hash, witness_merkle_root_wtxids};
    use rubin_consensus::{
        block_hash, encode_compact_size, merkle_root_txids, parse_block_bytes, parse_tx,
        CoreExtDeploymentProfile, CoreExtDeploymentProfiles, CoreExtVerificationBinding, Outpoint,
        UtxoEntry, BLOCK_HEADER_BYTES,
    };

    use crate::blockstore::{block_store_path, BlockStore};
    use crate::chainstate::{chain_state_path, load_chain_state, ChainState};
    use crate::coinbase::{build_coinbase_tx, default_mine_address};
    use crate::genesis::{devnet_genesis_block_bytes, devnet_genesis_chain_id};
    use crate::io_utils::unique_temp_path;
    use crate::sync::{default_sync_config, SyncEngine};

    const VALID_BLOCK_HEX: &str = "01000000111111111111111111111111111111111111111111111111111111111111111102e66000bf8ce870908df4a8689554852ccef681ee0b5df32246162a53e36e290100000000000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff07000000000000000101000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000ffffffff00ffffffff010000000000000000020020b716a4b7f4c0fab665298ab9b8199b601ab9fa7e0a27f0713383f34cf37071a8000000000000";
    const CORE_EXT_NATIVE_BINDING_SPEND_TX_HEX: &str = "0100000000010000000000000001eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee000000000000000000015a0000000000000000002101111111111111111111111111111111111111111111111111111111111111111100000000010300010100";

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

    fn build_block_bytes(
        prev_hash: [u8; 32],
        merkle_root: [u8; 32],
        target: [u8; 32],
        timestamp: u64,
        txs: &[Vec<u8>],
    ) -> Vec<u8> {
        let mut header = Vec::with_capacity(BLOCK_HEADER_BYTES);
        header.extend_from_slice(&1u32.to_le_bytes());
        header.extend_from_slice(&prev_hash);
        header.extend_from_slice(&merkle_root);
        header.extend_from_slice(&timestamp.to_le_bytes());
        header.extend_from_slice(&target);
        header.extend_from_slice(&0u64.to_le_bytes());
        assert_eq!(header.len(), BLOCK_HEADER_BYTES);

        let mut block = header;
        encode_compact_size(txs.len() as u64, &mut block);
        for tx in txs {
            block.extend_from_slice(tx);
        }
        block
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
        let dir = unique_temp_path("rubin-node-sync-persist");
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

    #[test]
    fn sync_engine_mainnet_guard_requires_explicit_non_devnet_target() {
        let st = ChainState::new();

        let mut cfg = default_sync_config(None, [0u8; 32], None);
        cfg.network = "mainnet".to_string();
        let err = SyncEngine::new(st.clone(), None, cfg).unwrap_err();
        assert_eq!(err, "mainnet requires explicit expected_target");

        let mut cfg = default_sync_config(Some(POW_LIMIT), [0u8; 32], None);
        cfg.network = "mainnet".to_string();
        let err = SyncEngine::new(st.clone(), None, cfg).unwrap_err();
        assert_eq!(
            err,
            "mainnet expected_target must not equal devnet POW_LIMIT (all-ff)"
        );

        let mut target = POW_LIMIT;
        target[0] = 0x7f;
        let mut cfg = default_sync_config(Some(target), [0u8; 32], None);
        cfg.network = "mainnet".to_string();
        let engine = SyncEngine::new(st, None, cfg);
        assert!(engine.is_ok());
    }

    #[test]
    fn sync_engine_rejects_post_activation_core_ext_spend_without_pre_active_bypass() {
        let dir = unique_temp_path("rubin-node-sync-core-ext");
        let chain_state_file = chain_state_path(&dir);
        let block_store_root = block_store_path(&dir);
        let store = BlockStore::open(block_store_root).expect("open blockstore");

        let mut cfg = default_sync_config(
            Some(POW_LIMIT),
            devnet_genesis_chain_id(),
            Some(chain_state_file),
        );
        cfg.core_ext_deployments = CoreExtDeploymentProfiles {
            deployments: vec![CoreExtDeploymentProfile {
                ext_id: 1,
                activation_height: 1,
                tx_context_enabled: false,
                allowed_suite_ids: vec![3],
                verification_binding: CoreExtVerificationBinding::NativeVerifySig,
                verify_sig_ext_tx_context_fn: None,
                binding_descriptor: Vec::new(),
                ext_payload_schema: Vec::new(),
                governance_nonce: 0,
            }],
        };
        let mut engine = SyncEngine::new(ChainState::new(), Some(store), cfg).expect("new sync");
        engine
            .apply_block(&devnet_genesis_block_bytes(), None)
            .expect("apply genesis");

        engine.chain_state.utxos.insert(
            Outpoint {
                txid: [0xee; 32],
                vout: 0,
            },
            UtxoEntry {
                value: 100,
                covenant_type: COV_TYPE_EXT,
                covenant_data: vec![0x01, 0x00, 0x00],
                creation_height: 0,
                created_by_coinbase: false,
            },
        );

        let spend_tx = hex_to_bytes(CORE_EXT_NATIVE_BINDING_SPEND_TX_HEX);
        let (_, spend_txid, spend_wtxid, consumed) = parse_tx(&spend_tx).expect("parse spend");
        assert_eq!(consumed, spend_tx.len());
        let witness_root =
            witness_merkle_root_wtxids(&[[0u8; 32], spend_wtxid]).expect("witness root");
        let witness_commitment = witness_commitment_hash(witness_root);
        let coinbase =
            build_coinbase_tx(1, 0, &default_mine_address(), witness_commitment).expect("coinbase");
        let (_, coinbase_txid, _, coinbase_consumed) = parse_tx(&coinbase).expect("parse coinbase");
        assert_eq!(coinbase_consumed, coinbase.len());
        let merkle_root = merkle_root_txids(&[coinbase_txid, spend_txid]).expect("merkle root");
        let genesis = devnet_genesis_block_bytes();
        let genesis_hash = block_hash(&genesis[..BLOCK_HEADER_BYTES]).expect("genesis hash");
        let parsed_genesis = parse_block_bytes(&genesis).expect("parse genesis");
        let block = build_block_bytes(
            genesis_hash,
            merkle_root,
            POW_LIMIT,
            parsed_genesis.header.timestamp.saturating_add(1),
            &[coinbase, spend_tx],
        );

        let err = engine.apply_block(&block, None).unwrap_err();
        assert!(
            err.contains("TX_ERR_SIG_ALG_INVALID"),
            "unexpected error: {err}"
        );
    }
}
