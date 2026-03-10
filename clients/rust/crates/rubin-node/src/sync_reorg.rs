use rubin_consensus::{
    block_hash, parse_block_bytes, parse_tx, read_compact_size_bytes,
    validate_block_basic_with_context_at_height, BLOCK_HEADER_BYTES,
};

use crate::chainstate::ChainStateConnectSummary;
use crate::sync::SyncEngine;
use crate::txpool::TxPool;

/// A block on a candidate side-chain branch, collected while walking
/// parent pointers back to a common ancestor on the canonical chain.
struct ReorgBranchBlock {
    #[allow(dead_code)]
    hash: [u8; 32],
    block_bytes: Vec<u8>,
    target: [u8; 32],
    /// Cached txids from block parse — avoids re-parsing during mempool eviction.
    txids: Vec<[u8; 32]>,
}

impl SyncEngine {
    /// Apply a block that may extend the canonical chain directly or trigger
    /// a reorg if it builds on a side chain with strictly more cumulative work.
    ///
    /// Returns the connect summary for the newly applied tip block.
    pub fn apply_block_with_reorg(
        &mut self,
        block_bytes: &[u8],
        prev_timestamps: Option<&[u64]>,
        tx_pool: Option<&mut TxPool>,
    ) -> Result<ChainStateConnectSummary, String> {
        let parsed = parse_block_bytes(block_bytes).map_err(|e| e.to_string())?;
        let bh = block_hash(&parsed.header_bytes).map_err(|e| e.to_string())?;

        // Fast path: block extends current tip or is genesis.
        if let Some(summary) = self.apply_direct_if_possible(block_bytes, prev_timestamps)? {
            if let Some(pool) = tx_pool {
                evict_confirmed_from_pool(pool, block_bytes);
            }
            return Ok(summary);
        }

        let block_store = self
            .block_store
            .as_ref()
            .ok_or("missing blockstore for side-chain block")?;

        // Store the block on the side chain (no canonical update).
        if !block_store.has_block(bh) {
            block_store.store_block(bh, &parsed.header_bytes, block_bytes)?;
        }

        // Collect branch from this block back to a common canonical ancestor.
        let (branch, common_ancestor_hash, common_ancestor_height) =
            self.collect_branch_to_canonical(bh, block_bytes)?;

        // Evaluate fork choice: switch only if candidate has strictly more work.
        let (switch, candidate_height) =
            self.should_switch_to_branch(&branch, common_ancestor_hash)?;

        if !switch {
            // Validate the block without switching chains.
            let derived_timestamps = if prev_timestamps.is_none() {
                self.prev_timestamps_for_next_block().ok().flatten()
            } else {
                None
            };
            let ts = prev_timestamps.or(derived_timestamps.as_deref());
            validate_block_basic_with_context_at_height(
                block_bytes,
                Some(parsed.header.prev_block_hash),
                self.cfg.expected_target,
                candidate_height,
                ts,
            )
            .map_err(|e| e.to_string())?;

            // Already stored above; return a synthetic summary.
            return Ok(self.synthetic_side_chain_summary(candidate_height, bh));
        }

        // Execute the reorg.
        self.apply_heavier_branch(branch, common_ancestor_height, prev_timestamps, tx_pool)
    }

    /// Fast path: apply the block directly if it extends the current tip
    /// or is the genesis block.
    fn apply_direct_if_possible(
        &mut self,
        block_bytes: &[u8],
        prev_timestamps: Option<&[u64]>,
    ) -> Result<Option<ChainStateConnectSummary>, String> {
        let parsed = parse_block_bytes(block_bytes).map_err(|e| e.to_string())?;

        if !self.chain_state.has_tip {
            // Genesis: prev_block_hash must be zero.
            if parsed.header.prev_block_hash != [0u8; 32] {
                return Err("parent block not found".into());
            }
            let summary = self.apply_block(block_bytes, prev_timestamps)?;
            return Ok(Some(summary));
        }

        if parsed.header.prev_block_hash == self.chain_state.tip_hash {
            let summary = self.apply_block(block_bytes, prev_timestamps)?;
            return Ok(Some(summary));
        }

        // Block does not extend the current tip — needs reorg evaluation.
        Ok(None)
    }

    /// Evaluate the fork choice rule: candidate branch must have strictly
    /// greater cumulative work than the current canonical chain.
    fn should_switch_to_branch(
        &self,
        branch: &[ReorgBranchBlock],
        common_ancestor_hash: [u8; 32],
    ) -> Result<(bool, u64), String> {
        let block_store = self
            .block_store
            .as_ref()
            .ok_or("sync engine has no blockstore")?;

        let current_tip_hash = self.chain_state.tip_hash;
        let current_work = block_store.chain_work(current_tip_hash)?;
        let ancestor_work = block_store.chain_work(common_ancestor_hash)?;

        let branch_targets: Vec<[u8; 32]> = branch.iter().map(|b| b.target).collect();
        let branch_work = rubin_consensus::fork_chainwork_from_targets(&branch_targets)
            .map_err(|e| e.to_string())?;

        let candidate_work = ancestor_work + branch_work;

        let ancestor_height = block_store
            .find_canonical_height(common_ancestor_hash)?
            .ok_or("common ancestor not on canonical chain")?;
        let candidate_height = ancestor_height + branch.len() as u64;

        Ok((candidate_work > current_work, candidate_height))
    }

    /// Execute the reorg: disconnect canonical blocks back to the common
    /// ancestor, then connect the heavier branch.
    fn apply_heavier_branch(
        &mut self,
        branch: Vec<ReorgBranchBlock>,
        common_ancestor_height: u64,
        prev_timestamps: Option<&[u64]>,
        tx_pool: Option<&mut TxPool>,
    ) -> Result<ChainStateConnectSummary, String> {
        let rollback = self.capture_reorg_rollback_state(common_ancestor_height);

        // Dry-run: preview the disconnect + reconnect on a cloned state.
        let disconnected_blocks =
            self.prepare_heavier_branch(&branch, common_ancestor_height, prev_timestamps)?;

        // Disconnect canonical chain back to the common ancestor.
        if let Err(err) = self.disconnect_canonical_to_ancestor(common_ancestor_height) {
            if let Some(rb_err) = self.rollback_apply_block(rollback) {
                return Err(format!(
                    "{err}; rollback failed: {rb_err}; blockstore may require repair"
                ));
            }
            return Err(err);
        }

        // Connect the heavier branch.
        let mut last_summary = None;
        for item in &branch {
            match self.apply_block(&item.block_bytes, prev_timestamps) {
                Ok(summary) => last_summary = Some(summary),
                Err(err) => {
                    if let Some(rb_err) = self.rollback_apply_block(rollback) {
                        return Err(format!(
                            "{err}; rollback failed: {rb_err}; blockstore may require repair"
                        ));
                    }
                    return Err(err);
                }
            }
        }

        // Mempool maintenance: evict txs confirmed in the winning branch,
        // then requeue txs from the disconnected blocks (those that are still
        // valid against the new chain state will be re-admitted).
        if let Some(pool) = tx_pool {
            for item in &branch {
                pool.evict_txids(&item.txids);
            }
            requeue_disconnected_transactions(pool, self, &disconnected_blocks);
        }

        last_summary.ok_or_else(|| "reorg branch was empty".into())
    }

    /// Dry-run validation: clone chain state, preview disconnect, then
    /// connect each branch block to verify the entire branch is valid.
    fn prepare_heavier_branch(
        &self,
        branch: &[ReorgBranchBlock],
        common_ancestor_height: u64,
        prev_timestamps: Option<&[u64]>,
    ) -> Result<Vec<Vec<u8>>, String> {
        let mut preview_state = self.chain_state.clone();

        let disconnected_blocks = self
            .preview_disconnect_canonical_to_ancestor(&mut preview_state, common_ancestor_height)?;

        // Connect each branch block on the preview state.
        for item in branch {
            preview_state.connect_block_with_core_ext_deployments(
                &item.block_bytes,
                self.cfg.expected_target,
                prev_timestamps,
                self.cfg.chain_id,
                &self.cfg.core_ext_deployments,
            )?;
        }

        Ok(disconnected_blocks)
    }

    /// Walk backward from the given block along parent pointers until we find
    /// a block on the canonical chain. Returns the branch blocks in
    /// ancestor-to-tip order, plus the common ancestor hash and height.
    fn collect_branch_to_canonical(
        &self,
        block_hash_bytes: [u8; 32],
        block_bytes: &[u8],
    ) -> Result<(Vec<ReorgBranchBlock>, [u8; 32], u64), String> {
        let block_store = self
            .block_store
            .as_ref()
            .ok_or("sync engine has no blockstore")?;

        let parsed = parse_block_bytes(block_bytes).map_err(|e| e.to_string())?;
        let mut branch = vec![ReorgBranchBlock {
            hash: block_hash_bytes,
            block_bytes: block_bytes.to_vec(),
            target: parsed.header.target,
            txids: parsed.txids.clone(),
        }];

        let mut parent_hash = parsed.header.prev_block_hash;

        loop {
            // Check if parent is on the canonical chain.
            if let Some(height) = block_store.find_canonical_height(parent_hash)? {
                branch.reverse();
                return Ok((branch, parent_hash, height));
            }

            // Load the parent block from the side-chain store.
            let parent_bytes = block_store
                .get_block_by_hash(parent_hash)
                .map_err(|_| "parent block not found".to_string())?;
            let parent_parsed = parse_block_bytes(&parent_bytes).map_err(|e| e.to_string())?;

            branch.push(ReorgBranchBlock {
                hash: parent_hash,
                block_bytes: parent_bytes,
                target: parent_parsed.header.target,
                txids: parent_parsed.txids.clone(),
            });

            parent_hash = parent_parsed.header.prev_block_hash;
        }
    }

    /// Create a summary for a side-chain block that was stored but did not
    /// trigger a reorg.
    fn synthetic_side_chain_summary(
        &self,
        height: u64,
        block_hash_bytes: [u8; 32],
    ) -> ChainStateConnectSummary {
        ChainStateConnectSummary {
            block_height: height,
            block_hash: block_hash_bytes,
            sum_fees: 0,
            already_generated: self.chain_state.already_generated,
            already_generated_n1: self.chain_state.already_generated,
            utxo_count: self.chain_state.utxos.len() as u64,
        }
    }
}

// ---------------------------------------------------------------------------
// Mempool helpers
// ---------------------------------------------------------------------------

/// Requeue non-coinbase transactions from disconnected blocks into the
/// mempool. Processes blocks in reverse order (oldest first) so that
/// dependency chains re-admit correctly.
fn requeue_disconnected_transactions(
    pool: &mut TxPool,
    engine: &SyncEngine,
    disconnected_blocks: &[Vec<u8>],
) {
    for block_bytes in disconnected_blocks.iter().rev() {
        let Ok(txs) = non_coinbase_tx_bytes(block_bytes) else {
            continue;
        };
        for tx_bytes in txs {
            let block_store_ref = engine.block_store.as_ref();
            let _ = pool.admit(
                &tx_bytes,
                &engine.chain_state,
                block_store_ref,
                engine.cfg.chain_id,
            );
        }
    }
}

/// Remove transactions confirmed in the given block from the mempool.
fn evict_confirmed_from_pool(pool: &mut TxPool, block_bytes: &[u8]) {
    let Ok(parsed) = parse_block_bytes(block_bytes) else {
        return;
    };
    pool.evict_txids(&parsed.txids);
}

/// Extract raw bytes for each non-coinbase transaction in a block.
/// This avoids needing a marshal_tx function — we slice directly from
/// the block bytes using parse_tx consumed lengths.
fn non_coinbase_tx_bytes(block_bytes: &[u8]) -> Result<Vec<Vec<u8>>, String> {
    if block_bytes.len() < BLOCK_HEADER_BYTES {
        return Err("block too short".into());
    }
    let after_header = &block_bytes[BLOCK_HEADER_BYTES..];
    let (tx_count, cs_size) = read_compact_size_bytes(after_header).map_err(|e| e.to_string())?;
    if tx_count <= 1 {
        return Ok(Vec::new());
    }

    let mut offset = BLOCK_HEADER_BYTES + cs_size;
    let mut txs = Vec::with_capacity((tx_count - 1) as usize);
    for i in 0..tx_count {
        let (_tx, _txid, _wtxid, consumed) =
            parse_tx(&block_bytes[offset..]).map_err(|e| e.to_string())?;
        if i > 0 {
            txs.push(block_bytes[offset..offset + consumed].to_vec());
        }
        offset += consumed;
    }
    Ok(txs)
}

#[cfg(test)]
mod tests {
    use rubin_consensus::constants::POW_LIMIT;

    use super::*;
    use crate::blockstore::{block_store_path, BlockStore};
    use crate::chainstate::{chain_state_path, ChainState};
    use crate::io_utils::unique_temp_path;
    use crate::sync::{default_sync_config, SyncEngine};
    use crate::test_helpers::{
        coinbase_only_block, coinbase_only_block_with_gen, genesis_info,
        height_one_coinbase_only_block,
    };

    #[test]
    fn non_coinbase_tx_bytes_empty_for_coinbase_only() {
        let genesis = crate::devnet_genesis_block_bytes();
        let txs = non_coinbase_tx_bytes(&genesis).expect("parse");
        assert!(txs.is_empty());
    }

    #[test]
    fn non_coinbase_tx_bytes_rejects_short_block() {
        let err = non_coinbase_tx_bytes(&[0u8; 10]).unwrap_err();
        assert!(err.contains("block too short"));
    }

    fn engine_with_store(suffix: &str) -> (SyncEngine, std::path::PathBuf) {
        let dir = unique_temp_path(suffix);
        let store = BlockStore::open(block_store_path(&dir)).expect("open blockstore");
        let cfg = default_sync_config(Some(POW_LIMIT), [0u8; 32], Some(chain_state_path(&dir)));
        let engine = SyncEngine::new(ChainState::new(), Some(store), cfg).expect("new sync");
        (engine, dir)
    }

    #[test]
    fn apply_block_with_reorg_genesis_fast_path() {
        let (mut engine, dir) = engine_with_store("rubin-reorg-gen");
        let (genesis, _, _) = genesis_info();

        let summary = engine
            .apply_block_with_reorg(&genesis, None, None)
            .expect("genesis via reorg");
        assert_eq!(summary.block_height, 0);
        assert!(engine.chain_state.has_tip);

        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn apply_block_with_reorg_tip_extension_with_pool() {
        let (mut engine, dir) = engine_with_store("rubin-reorg-tip");
        let (genesis, genesis_hash, gen_ts) = genesis_info();

        engine
            .apply_block_with_reorg(&genesis, None, None)
            .expect("genesis");

        let block1 = height_one_coinbase_only_block(genesis_hash, gen_ts + 1);
        let mut pool = TxPool::new();
        let summary = engine
            .apply_block_with_reorg(&block1, None, Some(&mut pool))
            .expect("block 1");
        assert_eq!(summary.block_height, 1);

        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn apply_block_with_reorg_non_tip_parent_without_store() {
        let cfg = default_sync_config(Some(POW_LIMIT), [0u8; 32], None);
        let mut engine = SyncEngine::new(ChainState::new(), None, cfg).expect("new");
        let (genesis, genesis_hash, gen_ts) = genesis_info();

        engine
            .apply_block_with_reorg(&genesis, None, None)
            .expect("genesis");

        // Extend tip with explicit timestamps (no blockstore for auto-derive).
        let block1 = height_one_coinbase_only_block(genesis_hash, gen_ts + 1);
        engine
            .apply_block_with_reorg(&block1, Some(&[gen_ts]), None)
            .expect("extends tip");

        // Alternate block with parent = genesis (not tip).
        // Without blockstore → error on side-chain path.
        let alt = height_one_coinbase_only_block(genesis_hash, gen_ts + 2);
        let err = engine
            .apply_block_with_reorg(&alt, Some(&[gen_ts]), None)
            .unwrap_err();
        assert!(err.contains("missing blockstore"), "got: {err}");
    }

    #[test]
    fn apply_block_with_reorg_side_chain_stored() {
        let (mut engine, dir) = engine_with_store("rubin-reorg-side");
        let (genesis, genesis_hash, gen_ts) = genesis_info();

        engine
            .apply_block_with_reorg(&genesis, None, None)
            .expect("genesis");

        let block1 = height_one_coinbase_only_block(genesis_hash, gen_ts + 1);
        engine
            .apply_block_with_reorg(&block1, None, None)
            .expect("block 1");

        // Alternate block at same height with parent = genesis.
        // Same cumulative work → no reorg (not strictly greater).
        let alt = height_one_coinbase_only_block(genesis_hash, gen_ts + 2);
        let summary = engine
            .apply_block_with_reorg(&alt, None, None)
            .expect("side chain stored");

        // Stored as side chain; canonical tip unchanged.
        assert_eq!(engine.chain_state.height, 1);
        assert_eq!(summary.block_height, 1);

        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn evict_confirmed_from_pool_no_panic() {
        let (genesis, _, _) = genesis_info();
        let mut pool = TxPool::new();
        evict_confirmed_from_pool(&mut pool, &genesis);
    }

    #[test]
    fn apply_block_with_reorg_heavier_branch_wins() {
        let (mut engine, dir) = engine_with_store("rubin-reorg-heavy");
        let (genesis, genesis_hash, gen_ts) = genesis_info();

        engine
            .apply_block_with_reorg(&genesis, None, None)
            .expect("genesis");

        // Canonical: genesis → block1
        let block1 = coinbase_only_block(1, genesis_hash, gen_ts + 1);
        engine
            .apply_block_with_reorg(&block1, None, None)
            .expect("block1 canonical");
        assert_eq!(engine.chain_state.height, 1);

        // Alt branch: genesis → block1' → block2' (longer = more work)
        let block1_alt = coinbase_only_block(1, genesis_hash, gen_ts + 2);
        let block1_alt_hash =
            rubin_consensus::block_hash(&block1_alt[..rubin_consensus::BLOCK_HEADER_BYTES])
                .expect("hash1'");

        // Pre-store block1' so collect_branch_to_canonical finds it.
        engine
            .block_store
            .as_ref()
            .unwrap()
            .store_block(
                block1_alt_hash,
                &block1_alt[..rubin_consensus::BLOCK_HEADER_BYTES],
                &block1_alt,
            )
            .expect("store block1'");

        // block1' pays subsidy(1, 0); after connecting it, already_generated = subsidy(1, 0).
        let subsidy1 = rubin_consensus::subsidy::block_subsidy(1, 0);
        let block2_alt = coinbase_only_block_with_gen(2, subsidy1, block1_alt_hash, gen_ts + 3);

        // Reorg: branch [block1', block2'] work=2 > canonical [block1] work=1.
        let mut pool = TxPool::new();
        let summary = engine
            .apply_block_with_reorg(&block2_alt, None, Some(&mut pool))
            .expect("reorg to heavier branch");

        assert_eq!(engine.chain_state.height, 2);
        assert_eq!(summary.block_height, 2);

        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn apply_block_with_reorg_rejects_non_zero_prev_genesis() {
        let (mut engine, dir) = engine_with_store("rubin-reorg-badgen");
        // Craft a block with prev_hash != [0;32] but chain has no tip.
        let bad_genesis = coinbase_only_block(0, [0xaa; 32], 1);
        let err = engine
            .apply_block_with_reorg(&bad_genesis, None, None)
            .unwrap_err();
        assert!(err.contains("parent block not found"), "got: {err}");
        std::fs::remove_dir_all(&dir).expect("cleanup");
    }
}
