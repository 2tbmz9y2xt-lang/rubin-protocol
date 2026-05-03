use std::time::{SystemTime, UNIX_EPOCH};

use rubin_consensus::constants::{
    MAX_BLOCK_WEIGHT, MAX_DA_BYTES_PER_BLOCK, MAX_FUTURE_DRIFT, POW_LIMIT,
};
use rubin_consensus::merkle::{witness_commitment_hash, witness_merkle_root_wtxids};
use rubin_consensus::{
    encode_compact_size, merkle_root_txids, parse_tx, pow_check, tx_weight_and_stats_public,
    CoreExtDeploymentProfiles, Tx,
};

use crate::coinbase::{
    build_coinbase_tx, default_mine_address, normalize_mine_address, parse_mine_address,
};
use crate::sync::SyncEngine;
use crate::txpool::{
    apply_policy, TxPool, TxPoolConfig, DEFAULT_MEMPOOL_MIN_FEE_RATE, DEFAULT_MIN_DA_FEE_RATE,
};

fn current_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[derive(Clone, Debug)]
pub struct MinerConfig {
    pub timestamp_source: fn() -> u64,
    pub max_tx_per_block: usize,
    pub target: [u8; 32],
    pub mine_address: Vec<u8>,
    pub policy_da_anchor_anti_abuse: bool,
    pub policy_reject_non_coinbase_anchor_outputs: bool,
    pub policy_max_da_bytes_per_block: u64,
    pub policy_da_surcharge_per_byte: u64,
    /// Stage C `current_mempool_min_fee_rate` input forwarded to the DA
    /// fee policy when `policy_da_anchor_anti_abuse` is on. Defaults to
    /// `DEFAULT_MEMPOOL_MIN_FEE_RATE` (mirrors Go's documented pattern
    /// for callers without a live rolling-floor source).
    pub policy_current_mempool_min_fee_rate: u64,
    /// Stage C `min_da_fee_rate` input forwarded to the DA fee policy
    /// when `policy_da_anchor_anti_abuse` is on. Defaults to
    /// `DEFAULT_MIN_DA_FEE_RATE`, kept separate from
    /// `DEFAULT_MEMPOOL_MIN_FEE_RATE` so a future change to the relay
    /// floor cannot silently change the DA floor.
    pub policy_min_da_fee_rate: u64,
    pub policy_reject_core_ext_pre_activation: bool,
    pub core_ext_deployments: CoreExtDeploymentProfiles,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MinedBlock {
    pub height: u64,
    pub hash: [u8; 32],
    pub timestamp: u64,
    pub nonce: u64,
    pub tx_count: usize,
}

#[derive(Clone, Debug)]
struct MinedCandidate {
    raw: Vec<u8>,
    tx: Tx,
    txid: [u8; 32],
    wtxid: [u8; 32],
    weight: u64,
}

pub struct Miner<'a> {
    sync: &'a mut SyncEngine,
    tx_pool: Option<&'a mut TxPool>,
    cfg: MinerConfig,
}

impl Default for MinerConfig {
    fn default() -> Self {
        Self {
            timestamp_source: current_unix,
            max_tx_per_block: 1024,
            target: POW_LIMIT,
            mine_address: default_mine_address(),
            policy_da_anchor_anti_abuse: true,
            policy_reject_non_coinbase_anchor_outputs: true,
            policy_max_da_bytes_per_block: MAX_DA_BYTES_PER_BLOCK / 4,
            policy_da_surcharge_per_byte: 0,
            policy_current_mempool_min_fee_rate: DEFAULT_MEMPOOL_MIN_FEE_RATE,
            policy_min_da_fee_rate: DEFAULT_MIN_DA_FEE_RATE,
            policy_reject_core_ext_pre_activation: true,
            core_ext_deployments: CoreExtDeploymentProfiles::empty(),
        }
    }
}

impl<'a> Miner<'a> {
    pub fn new(
        sync: &'a mut SyncEngine,
        tx_pool: Option<&'a mut TxPool>,
        mut cfg: MinerConfig,
    ) -> Result<Self, String> {
        cfg.mine_address = normalize_mine_address(&cfg.mine_address)?;
        if cfg.max_tx_per_block == 0 {
            cfg.max_tx_per_block = 1024;
        }
        Ok(Self { sync, tx_pool, cfg })
    }

    pub fn mine_n(&mut self, blocks: usize, txs: &[Vec<u8>]) -> Result<Vec<MinedBlock>, String> {
        let mut out = Vec::with_capacity(blocks);
        for _ in 0..blocks {
            out.push(self.mine_one(txs)?);
        }
        Ok(out)
    }

    pub fn mine_one(&mut self, txs: &[Vec<u8>]) -> Result<MinedBlock, String> {
        let next_height = if self.sync.chain_state.has_tip {
            self.sync
                .chain_state
                .height
                .checked_add(1)
                .ok_or_else(|| "height overflow".to_string())?
        } else {
            0
        };
        let prev_hash = if self.sync.chain_state.has_tip {
            self.sync.chain_state.tip_hash
        } else {
            [0u8; 32]
        };
        let remaining_weight = self.remaining_weight_budget(next_height)?;
        let candidate_txs = self.candidate_transactions(txs);
        let parsed =
            self.select_candidate_transactions(candidate_txs, next_height, remaining_weight)?;
        let witness_commitment = build_witness_commitment(&parsed)?;
        let coinbase = build_coinbase_tx(
            next_height,
            self.sync.chain_state.already_generated,
            &self.cfg.mine_address,
            witness_commitment,
        )?;
        let (_, coinbase_txid, _, consumed) = parse_tx(&coinbase).map_err(|e| e.to_string())?;
        if consumed != coinbase.len() {
            return Err("coinbase serialization is non-canonical".to_string());
        }

        let mut txids = Vec::with_capacity(1 + parsed.len());
        txids.push(coinbase_txid);
        for candidate in &parsed {
            txids.push(candidate.txid);
        }
        let merkle_root = merkle_root_txids(&txids).map_err(|e| e.to_string())?;
        let prev_timestamps = self.sync.prev_timestamps_for_next_block()?;
        let timestamp = choose_valid_timestamp(
            next_height,
            prev_timestamps.as_deref().unwrap_or(&[]),
            (self.cfg.timestamp_source)(),
        );
        let block_without_nonce =
            make_header_prefix(prev_hash, merkle_root, timestamp, self.cfg.target);
        let (header_bytes, nonce) = mine_header_nonce(&block_without_nonce, self.cfg.target)?;
        let block_bytes = assemble_block_bytes(&header_bytes, &coinbase, &parsed);
        let summary = self
            .sync
            .apply_block(&block_bytes, prev_timestamps.as_deref())?;
        self.evict_confirmed_from_pool(&parsed);
        Ok(MinedBlock {
            height: summary.block_height,
            hash: summary.block_hash,
            timestamp,
            nonce,
            tx_count: 1 + parsed.len(),
        })
    }

    fn candidate_transactions(&self, txs: &[Vec<u8>]) -> Vec<Vec<u8>> {
        let max_selected = self.cfg.max_tx_per_block.saturating_sub(1);
        if max_selected == 0 {
            return Vec::new();
        }
        if !txs.is_empty() {
            return txs.iter().take(max_selected).cloned().collect();
        }
        match self.tx_pool.as_deref() {
            Some(pool) => pool.select_transactions(max_selected, MAX_BLOCK_WEIGHT as usize),
            None => Vec::new(),
        }
    }

    fn evict_confirmed_from_pool(&mut self, parsed: &[MinedCandidate]) {
        let Some(pool) = self.tx_pool.as_deref_mut() else {
            return;
        };
        let txids: Vec<[u8; 32]> = parsed.iter().map(|candidate| candidate.txid).collect();
        pool.evict_txids(&txids);
        let block_txs: Vec<Tx> = parsed
            .iter()
            .map(|candidate| candidate.tx.clone())
            .collect();
        pool.remove_conflicting_inputs(&block_txs);
    }

    fn remaining_weight_budget(&self, next_height: u64) -> Result<u64, String> {
        let coinbase = build_coinbase_tx(
            next_height,
            self.sync.chain_state.already_generated,
            &self.cfg.mine_address,
            [0u8; 32],
        )?;
        let weight = canonical_tx_weight(&coinbase, "coinbase serialization is non-canonical")?;
        MAX_BLOCK_WEIGHT
            .checked_sub(weight)
            .ok_or_else(|| "coinbase exceeds block weight budget".to_string())
    }

    fn select_candidate_transactions(
        &self,
        candidate_txs: Vec<Vec<u8>>,
        next_height: u64,
        remaining_weight: u64,
    ) -> Result<Vec<MinedCandidate>, String> {
        let mut parsed = Vec::with_capacity(candidate_txs.len());
        let mut selected_weight = 0u64;
        let mut policy_da_included = 0u64;
        for raw in candidate_txs {
            let candidate = parse_mining_candidate(&raw)?;
            let (reject, next_da_included) =
                self.reject_candidate(&candidate.tx, next_height, policy_da_included)?;
            if reject {
                continue;
            }
            if candidate.weight > remaining_weight.saturating_sub(selected_weight) {
                continue;
            }
            selected_weight += candidate.weight;
            policy_da_included = next_da_included;
            parsed.push(candidate);
        }
        Ok(parsed)
    }

    fn reject_candidate(
        &self,
        tx: &Tx,
        next_height: u64,
        policy_da_included: u64,
    ) -> Result<(bool, u64), String> {
        let policy_cfg = TxPoolConfig {
            policy_da_surcharge_per_byte: if self.cfg.policy_da_anchor_anti_abuse {
                self.cfg.policy_da_surcharge_per_byte
            } else {
                0
            },
            policy_reject_non_coinbase_anchor_outputs: self.cfg.policy_da_anchor_anti_abuse
                && self.cfg.policy_reject_non_coinbase_anchor_outputs,
            policy_reject_core_ext_pre_activation: self.cfg.policy_reject_core_ext_pre_activation,
            policy_max_ext_payload_bytes: 0,
            core_ext_deployments: self.cfg.core_ext_deployments.clone(),
            suite_context: self.sync.cfg.suite_context.clone(),
            policy_current_mempool_min_fee_rate: if self.cfg.policy_da_anchor_anti_abuse {
                self.cfg.policy_current_mempool_min_fee_rate
            } else {
                0
            },
            policy_min_da_fee_rate: if self.cfg.policy_da_anchor_anti_abuse {
                self.cfg.policy_min_da_fee_rate
            } else {
                0
            },
        };
        if apply_policy(tx, &self.sync.chain_state.utxos, next_height, &policy_cfg).is_err() {
            return Ok((true, policy_da_included));
        }
        let (_, da_bytes, _) = tx_weight_and_stats_public(tx).map_err(|e| e.to_string())?;
        if self.cfg.policy_da_anchor_anti_abuse {
            let next_da = updated_policy_da_bytes(
                policy_da_included,
                da_bytes,
                self.cfg.policy_max_da_bytes_per_block,
            );
            if next_da.is_none() {
                return Ok((true, policy_da_included));
            }
            return Ok((false, next_da.unwrap_or(policy_da_included)));
        }
        Ok((false, policy_da_included))
    }
}

fn parse_mining_candidate(raw: &[u8]) -> Result<MinedCandidate, String> {
    let (tx, txid, wtxid, consumed) = parse_tx(raw).map_err(|e| e.to_string())?;
    if consumed != raw.len() {
        return Err("non-canonical tx bytes in miner input".to_string());
    }
    let (weight, _, _) = tx_weight_and_stats_public(&tx).map_err(|e| e.to_string())?;
    Ok(MinedCandidate {
        raw: raw.to_vec(),
        tx,
        txid,
        wtxid,
        weight,
    })
}

fn canonical_tx_weight(raw: &[u8], msg: &str) -> Result<u64, String> {
    let (tx, _, _, consumed) = parse_tx(raw).map_err(|e| e.to_string())?;
    if consumed != raw.len() {
        return Err(msg.to_string());
    }
    let (weight, _, _) = tx_weight_and_stats_public(&tx).map_err(|e| e.to_string())?;
    Ok(weight)
}

fn build_witness_commitment(parsed: &[MinedCandidate]) -> Result<[u8; 32], String> {
    let mut wtxids = Vec::with_capacity(1 + parsed.len());
    wtxids.push([0u8; 32]);
    for candidate in parsed {
        wtxids.push(candidate.wtxid);
    }
    let root = witness_merkle_root_wtxids(&wtxids).map_err(|e| e.to_string())?;
    Ok(witness_commitment_hash(root))
}

fn updated_policy_da_bytes(current: u64, da_bytes: u64, max_per_block: u64) -> Option<u64> {
    if da_bytes == 0 || max_per_block == 0 {
        return Some(current);
    }
    let next = current.checked_add(da_bytes)?;
    (next <= max_per_block).then_some(next)
}

fn choose_valid_timestamp(next_height: u64, prev_timestamps: &[u64], now: u64) -> u64 {
    if next_height == 0 || prev_timestamps.is_empty() {
        return if now == 0 { 1 } else { now };
    }
    let median = mtp_median(next_height, prev_timestamps);
    if now > median && now <= median.saturating_add(MAX_FUTURE_DRIFT) {
        return now;
    }
    median.saturating_add(1)
}

fn mtp_median(next_height: u64, prev_timestamps: &[u64]) -> u64 {
    let mut window_len = 11usize;
    if next_height < window_len as u64 {
        window_len = next_height as usize;
    }
    if prev_timestamps.len() < window_len {
        if prev_timestamps.is_empty() {
            return 0;
        }
        window_len = prev_timestamps.len();
    }
    let mut window = prev_timestamps[..window_len].to_vec();
    window.sort_unstable();
    window[(window.len() - 1) / 2]
}

fn make_header_prefix(
    prev_hash: [u8; 32],
    merkle_root: [u8; 32],
    timestamp: u64,
    target: [u8; 32],
) -> Vec<u8> {
    let mut header = Vec::with_capacity(108);
    header.extend_from_slice(&1u32.to_le_bytes());
    header.extend_from_slice(&prev_hash);
    header.extend_from_slice(&merkle_root);
    header.extend_from_slice(&timestamp.to_le_bytes());
    header.extend_from_slice(&target);
    header
}

fn mine_header_nonce(
    block_without_nonce: &[u8],
    target: [u8; 32],
) -> Result<(Vec<u8>, u64), String> {
    let mut nonce = 0u64;
    loop {
        let mut header = block_without_nonce.to_vec();
        header.extend_from_slice(&nonce.to_le_bytes());
        if pow_check(&header, target).is_ok() {
            return Ok((header, nonce));
        }
        nonce = nonce.wrapping_add(1);
        if nonce == 0 {
            return Err("exhausted nonce space without valid header".to_string());
        }
    }
}

fn assemble_block_bytes(
    header_bytes: &[u8],
    coinbase: &[u8],
    parsed: &[MinedCandidate],
) -> Vec<u8> {
    let mut block = Vec::with_capacity(
        header_bytes.len()
            + coinbase.len()
            + parsed.iter().map(|p| p.raw.len()).sum::<usize>()
            + 16,
    );
    block.extend_from_slice(header_bytes);
    encode_compact_size((1 + parsed.len()) as u64, &mut block);
    block.extend_from_slice(coinbase);
    for candidate in parsed {
        block.extend_from_slice(&candidate.raw);
    }
    block
}

pub fn parse_mine_address_arg(value: &str) -> Result<Option<Vec<u8>>, String> {
    parse_mine_address(value)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use rubin_consensus::constants::MAX_BLOCK_WEIGHT;
    use rubin_consensus::merkle::{witness_commitment_hash, witness_merkle_root_wtxids};

    use crate::{
        block_store_path, chain_state_path, default_sync_config, devnet_genesis_chain_id,
        test_helpers::signed_conflicting_p2pk_state_and_txs, BlockStore, ChainState, SyncEngine,
        TxPool,
    };

    use super::{
        assemble_block_bytes, build_witness_commitment, canonical_tx_weight,
        choose_valid_timestamp, default_mine_address, make_header_prefix, mtp_median,
        parse_mine_address_arg, parse_mining_candidate, updated_policy_da_bytes, Miner,
        MinerConfig,
    };

    fn test_sync(prefix: &str) -> (PathBuf, BlockStore, SyncEngine) {
        let dir = std::env::temp_dir().join(format!("{prefix}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("mkdir");
        let chain_state_file = chain_state_path(&dir);
        let block_store = BlockStore::open(block_store_path(&dir)).expect("blockstore");
        let chain_state = ChainState::new();
        chain_state.save(&chain_state_file).expect("save");
        let sync = SyncEngine::new(
            chain_state,
            Some(block_store.clone()),
            default_sync_config(None, devnet_genesis_chain_id(), Some(chain_state_file)),
        )
        .expect("sync");
        (dir, block_store, sync)
    }

    fn coinbase_bytes(height: u64) -> Vec<u8> {
        super::build_coinbase_tx(height, 0, &default_mine_address(), [0u8; 32]).expect("coinbase")
    }

    #[test]
    fn mine_one_from_empty_state_updates_tip() {
        let (dir, _block_store, mut sync) = test_sync("rubin-rust-miner");
        let cfg = MinerConfig {
            timestamp_source: || 1_777_000_000,
            ..MinerConfig::default()
        };
        let mut miner = Miner::new(&mut sync, None, cfg).expect("miner");

        let mined = miner.mine_one(&[]).expect("mine one");
        assert_eq!(mined.height, 0);
        assert_eq!(mined.tx_count, 1);
        let tip = miner.sync.tip().expect("tip").expect("some tip");
        assert_eq!(tip.0, 0);
        assert_eq!(tip.1, mined.hash);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn mine_n_produces_height_and_timestamp_progression() {
        let (dir, _block_store, mut sync) = test_sync("rubin-rust-miner-n");
        let cfg = MinerConfig {
            timestamp_source: || 1,
            ..MinerConfig::default()
        };
        let mut pool = TxPool::new();
        let mut miner = Miner::new(&mut sync, Some(&mut pool), cfg).expect("miner");

        let mined = miner.mine_n(3, &[]).expect("mine n");
        assert_eq!(mined.len(), 3);
        assert_eq!(mined[0].height, 0);
        assert_eq!(mined[1].height, 1);
        assert_eq!(mined[2].height, 2);
        assert!(mined[1].timestamp > mined[0].timestamp);
        assert!(mined[2].timestamp >= mined[1].timestamp);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn miner_new_normalizes_defaults() {
        let (dir, _block_store, mut sync) = test_sync("rubin-rust-miner-defaults");
        let cfg = MinerConfig {
            max_tx_per_block: 0,
            mine_address: Vec::new(),
            ..MinerConfig::default()
        };
        let miner = Miner::new(&mut sync, None, cfg).expect("miner");
        assert_eq!(miner.cfg.max_tx_per_block, 1024);
        assert_eq!(miner.cfg.mine_address, default_mine_address());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn candidate_transactions_prefers_explicit_input_and_caps_selection() {
        let (dir, _block_store, mut sync) = test_sync("rubin-rust-miner-explicit");
        let cfg = MinerConfig {
            max_tx_per_block: 2,
            ..MinerConfig::default()
        };
        let miner = Miner::new(&mut sync, None, cfg).expect("miner");
        let selected = miner.candidate_transactions(&[vec![0x01], vec![0x02], vec![0x03]]);
        assert_eq!(selected, vec![vec![0x01]]);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn candidate_transactions_falls_back_to_pool_surface() {
        let (dir, _block_store, mut sync) = test_sync("rubin-rust-miner-pool");
        let mut pool = TxPool::new();
        let cfg = MinerConfig {
            max_tx_per_block: 3,
            ..MinerConfig::default()
        };
        let miner = Miner::new(&mut sync, Some(&mut pool), cfg).expect("miner");
        let selected = miner.candidate_transactions(&[]);
        assert!(selected.is_empty());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn helper_branches_cover_timestamp_and_da_budget_edges() {
        assert_eq!(updated_policy_da_bytes(7, 0, 10), Some(7));
        assert_eq!(updated_policy_da_bytes(7, 2, 0), Some(7));
        assert_eq!(updated_policy_da_bytes(5, 6, 10), None);
        assert_eq!(updated_policy_da_bytes(u64::MAX, 1, u64::MAX), None);

        assert_eq!(choose_valid_timestamp(0, &[], 0), 1);
        assert_eq!(choose_valid_timestamp(1, &[10, 11, 12], 12), 12);
        assert_eq!(
            choose_valid_timestamp(1, &[10, 11, 12], 12 + super::MAX_FUTURE_DRIFT + 1),
            11
        );
    }

    #[test]
    fn helper_parsers_cover_noncanonical_and_address_edges() {
        let tx = coinbase_bytes(0);
        let candidate = parse_mining_candidate(&tx).expect("candidate");
        assert_eq!(candidate.raw, tx);
        assert!(candidate.weight > 0);

        let mut noncanonical = candidate.raw.clone();
        noncanonical.push(0);
        assert_eq!(
            parse_mining_candidate(&noncanonical).unwrap_err(),
            "non-canonical tx bytes in miner input"
        );
        assert_eq!(
            canonical_tx_weight(&noncanonical, "bad tx").unwrap_err(),
            "bad tx"
        );

        let default_hex = hex::encode(default_mine_address());
        assert_eq!(
            parse_mine_address_arg(&default_hex).expect("address"),
            Some(default_mine_address())
        );
        assert_eq!(parse_mine_address_arg("").expect("empty"), None);
        assert!(parse_mine_address_arg("zz").is_err());
    }

    #[test]
    fn helper_commitment_and_block_assembly_match_wire_helpers() {
        let coinbase0 = coinbase_bytes(0);
        let coinbase1 = coinbase_bytes(1);
        let first = parse_mining_candidate(&coinbase0).expect("first");
        let second = parse_mining_candidate(&coinbase1).expect("second");

        let expected_root =
            witness_merkle_root_wtxids(&[[0u8; 32], first.wtxid, second.wtxid]).expect("root");
        assert_eq!(
            build_witness_commitment(&[first.clone(), second.clone()]).expect("commitment"),
            witness_commitment_hash(expected_root)
        );

        let header = make_header_prefix([0x11; 32], [0x22; 32], 7, [0x33; 32]);
        assert_eq!(header.len(), 108);
        assert_eq!(&header[..4], &1u32.to_le_bytes());
        assert_eq!(&header[4..36], &[0x11; 32]);
        assert_eq!(&header[36..68], &[0x22; 32]);
        assert_eq!(&header[68..76], &7u64.to_le_bytes());
        assert_eq!(&header[76..108], &[0x33; 32]);

        let block = assemble_block_bytes(&header, &coinbase0, std::slice::from_ref(&second));
        let mut expected = header.clone();
        rubin_consensus::encode_compact_size(2, &mut expected);
        expected.extend_from_slice(&coinbase0);
        expected.extend_from_slice(&second.raw);
        assert_eq!(block, expected);
    }

    #[test]
    fn helper_medians_and_candidate_limits_cover_extra_branches() {
        assert_eq!(mtp_median(3, &[9, 3, 7]), 7);

        let (dir, _block_store, mut sync) = test_sync("rubin-rust-miner-one-slot");
        let cfg = MinerConfig {
            max_tx_per_block: 1,
            ..MinerConfig::default()
        };
        let miner = Miner::new(&mut sync, None, cfg).expect("miner");
        let selected = miner.candidate_transactions(&[coinbase_bytes(0)]);
        assert!(selected.is_empty());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn mine_one_rejects_explicit_noncanonical_tx_bytes() {
        let (dir, _block_store, mut sync) = test_sync("rubin-rust-miner-bad-explicit");
        let mut miner = Miner::new(&mut sync, None, MinerConfig::default()).expect("miner");
        let mut bad = coinbase_bytes(0);
        bad.push(0);
        let err = miner.mine_one(&[bad]).unwrap_err();
        assert!(
            err.contains("non-canonical tx bytes in miner input"),
            "{err}"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    fn signed_p2pk_state_and_tx(input_value: u64, output_value: u64) -> (ChainState, Vec<u8>) {
        let (state, raw, _conflict) =
            signed_conflicting_p2pk_state_and_txs(input_value, output_value, output_value - 1);
        (state, raw)
    }

    #[test]
    fn mine_one_includes_valid_explicit_tx() {
        let (dir, _block_store, mut sync) = test_sync("rubin-rust-miner-explicit-valid");
        let (state, raw) = signed_p2pk_state_and_tx(20, 10);
        sync.chain_state.utxos = state.utxos;
        let cfg = MinerConfig {
            timestamp_source: || 1_777_000_123,
            ..MinerConfig::default()
        };
        let mut miner = Miner::new(&mut sync, None, cfg).expect("miner");

        let mined = miner.mine_one(&[raw]).expect("mine one");
        assert_eq!(mined.height, 0);
        assert_eq!(mined.tx_count, 2);
        assert!(miner.sync.chain_state.has_tip);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn mine_n_evicts_confirmed_pool_transactions_between_blocks() {
        // RUB-162 Phase A migration rationale (per controller Q2 / Path A
        // approval 2026-05-03):
        //   - old assumption: signed_p2pk_state_and_tx(20, 10) → fee=10
        //     with weight ≈ 7653 admits because pre-RUB-162
        //     admit_with_metadata did not enforce the rolling fee floor.
        //   - new invariant: admit_with_metadata enforces the rolling fee
        //     floor (DEFAULT=1) via validate_fee_floor_locked.
        //   - reachability: tx is well-formed; pool.admit reaches the
        //     txpool admission path. Mine_n then confirms blocks and
        //     evicts confirmed txs from the pool.
        //   - replacement coverage: input bumped to 7700 so fee = 7700 - 10
        //     = 7690 ≥ weight (≈7653). The mine-then-evict invariant
        //     remains under test.
        let (dir, _block_store, mut sync) = test_sync("rubin-rust-miner-pool-evict");
        let (state, raw) = signed_p2pk_state_and_tx(7700, 10);
        sync.chain_state.utxos = state.utxos;

        let mut pool = TxPool::new();
        pool.admit(&raw, &sync.chain_state, None, devnet_genesis_chain_id())
            .expect("admit");

        let mined = {
            let cfg = MinerConfig {
                timestamp_source: || 1_777_000_321,
                ..MinerConfig::default()
            };
            let mut miner = Miner::new(&mut sync, Some(&mut pool), cfg).expect("miner");
            miner.mine_n(2, &[]).expect("mine n")
        };

        assert_eq!(mined.len(), 2);
        assert_eq!(mined[0].tx_count, 2);
        assert_eq!(mined[1].tx_count, 1);
        assert!(pool.is_empty());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn mine_one_evicts_conflicting_pool_transaction_for_explicit_candidate() {
        // RUB-162 Phase A migration rationale (per controller Q2 / Path A
        // approval 2026-05-03):
        //   - old assumption: signed_conflicting_p2pk_state_and_txs(20,10,9)
        //     produced two txs with fee=10/fee=11 that admitted because
        //     pre-RUB-162 admit_with_metadata did not enforce the rolling
        //     fee floor.
        //   - new invariant: admit_with_metadata enforces the rolling fee
        //     floor.
        //   - reachability: pool.admit on the conflicting_raw reaches the
        //     txpool admission path; mine_one then includes the explicit
        //     candidate which conflicts with the pool entry, evicting it.
        //   - replacement coverage: input bumped to 7700 so both txs have
        //     fees ≥ weight (~7653). The conflicting-eviction-on-explicit-
        //     candidate invariant remains under test.
        let (dir, _block_store, mut sync) = test_sync("rubin-rust-miner-explicit-conflict");
        let (state, explicit_raw, conflicting_raw) =
            signed_conflicting_p2pk_state_and_txs(7700, 10, 9);
        sync.chain_state.utxos = state.utxos.clone();

        let mut pool = TxPool::new();
        pool.admit(
            &conflicting_raw,
            &sync.chain_state,
            None,
            devnet_genesis_chain_id(),
        )
        .expect("admit conflict");

        {
            let cfg = MinerConfig {
                timestamp_source: || 1_777_000_555,
                ..MinerConfig::default()
            };
            let mut miner = Miner::new(&mut sync, Some(&mut pool), cfg).expect("miner");
            let mined = miner.mine_one(&[explicit_raw]).expect("mine explicit");
            assert_eq!(mined.tx_count, 2);
        }

        assert!(pool.is_empty());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn mine_one_rejects_height_overflow_before_assembly() {
        let (dir, _block_store, mut sync) = test_sync("rubin-rust-miner-height-overflow");
        sync.chain_state.has_tip = true;
        sync.chain_state.height = u64::MAX;
        let mut miner = Miner::new(&mut sync, None, MinerConfig::default()).expect("miner");
        let err = miner.mine_one(&[]).unwrap_err();
        assert!(err.contains("height overflow"), "{err}");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn select_candidate_transactions_covers_reject_skip_and_accept_paths() {
        let (dir, _block_store, mut sync) = test_sync("rubin-rust-miner-selection");
        let (state, raw) = signed_p2pk_state_and_tx(20, 10);
        sync.chain_state.utxos = state.utxos;
        let miner = Miner::new(&mut sync, None, MinerConfig::default()).expect("miner");

        let rejected = miner
            .select_candidate_transactions(vec![coinbase_bytes(0)], 0, MAX_BLOCK_WEIGHT)
            .expect("reject branch");
        assert!(rejected.is_empty());

        let overweight = miner
            .select_candidate_transactions(vec![raw.clone()], 0, 0)
            .expect("weight skip");
        assert!(overweight.is_empty());

        let accepted = miner
            .select_candidate_transactions(vec![raw], 0, MAX_BLOCK_WEIGHT)
            .expect("accept branch");
        assert_eq!(accepted.len(), 1);
        assert!(accepted[0].weight > 0);
        let _ = fs::remove_dir_all(&dir);
    }
}
