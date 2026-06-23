use rubin_consensus::{
    block_hash, parse_block_bytes, parse_tx, read_compact_size_bytes,
    validate_block_basic_with_context_at_height, Outpoint, ParsedBlock, BLOCK_HEADER_BYTES,
};
use std::ops::Deref;

use crate::blockstore::BlockStore;
use crate::chainstate::{CanonicalAppliedBlock, ChainStateConnectSummary};
use crate::sync::SyncEngine;
use crate::txpool::{TxPool, TxPoolAdmitError, TxPoolAdmitErrorKind, TxSource};

pub(crate) const PARENT_BLOCK_NOT_FOUND_ERR: &str = "parent block not found";

/// Slide the MTP window forward by one block: prepend `new_ts` and keep at
/// most 11 entries.  Mirrors Go `advancePrevTimestamps`.
fn advance_prev_timestamps(prev: Option<&[u64]>, new_ts: u64) -> Vec<u64> {
    const MAX_WINDOW: usize = 11;
    let mut out = Vec::with_capacity(MAX_WINDOW);
    out.push(new_ts);
    if let Some(prev) = prev {
        for &ts in prev.iter().take(MAX_WINDOW - 1) {
            out.push(ts);
        }
    }
    out
}

/// A block on a candidate side-chain branch, collected while walking
/// parent pointers back to a common ancestor on the canonical chain.
struct ReorgBranchBlock {
    hash: [u8; 32],
    header_bytes: [u8; BLOCK_HEADER_BYTES],
    block_bytes: Vec<u8>,
    prev_hash: [u8; 32],
    target: [u8; 32],
    /// Header timestamp — used to advance the MTP sliding window during
    /// preview validation (B.9 fix).
    timestamp: u64,
    /// Cached txids from block parse — avoids re-parsing during mempool eviction.
    txids: Vec<[u8; 32]>,
}

#[derive(Clone, Debug, Default)]
pub struct TxPoolCleanupPlan {
    confirmed_txids: Vec<[u8; 32]>,
    conflicting_inputs: Vec<Outpoint>,
    requeue_block_hashes: Vec<[u8; 32]>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct TxPoolCleanupReport {
    requeue_blocks_unavailable: usize,
    requeue_blocks_invalid: usize,
    requeue_attempted: usize,
    requeue_accepted: usize,
    requeue_conflict: usize,
    requeue_rejected: usize,
    requeue_unavailable: usize,
}

impl TxPoolCleanupReport {
    pub(crate) fn requeue_failed(&self) -> usize {
        self.requeue_conflict
            .saturating_add(self.requeue_rejected)
            .saturating_add(self.requeue_unavailable)
    }

    pub(crate) fn requeue_blocks_failed(&self) -> usize {
        self.requeue_blocks_unavailable
            .saturating_add(self.requeue_blocks_invalid)
    }

    pub(crate) fn has_requeue_failures(&self) -> bool {
        self.requeue_failed() > 0 || self.requeue_blocks_failed() > 0
    }

    pub(crate) fn requeue_failure_summary(&self) -> String {
        format!(
            "requeue_attempted={} requeue_accepted={} requeue_blocks_unavailable={} requeue_blocks_invalid={} requeue_conflict={} requeue_rejected={} requeue_unavailable={}",
            self.requeue_attempted,
            self.requeue_accepted,
            self.requeue_blocks_unavailable,
            self.requeue_blocks_invalid,
            self.requeue_conflict,
            self.requeue_rejected,
            self.requeue_unavailable
        )
    }

    fn record_requeue_attempt(&mut self) {
        self.requeue_attempted = self.requeue_attempted.saturating_add(1);
    }

    fn record_requeue_accepted(&mut self) {
        self.requeue_accepted = self.requeue_accepted.saturating_add(1);
    }

    fn record_requeue_error(&mut self, err: &TxPoolAdmitError) {
        match err.kind {
            TxPoolAdmitErrorKind::Conflict => {
                self.requeue_conflict = self.requeue_conflict.saturating_add(1);
            }
            TxPoolAdmitErrorKind::Rejected => {
                self.requeue_rejected = self.requeue_rejected.saturating_add(1);
            }
            TxPoolAdmitErrorKind::Unavailable => {
                self.requeue_unavailable = self.requeue_unavailable.saturating_add(1);
            }
        }
    }
}

impl TxPoolCleanupPlan {
    pub fn is_empty(&self) -> bool {
        self.confirmed_txids.is_empty()
            && self.conflicting_inputs.is_empty()
            && self.requeue_block_hashes.is_empty()
    }

    pub fn apply(
        &self,
        pool: &mut TxPool,
        chain_state: &crate::ChainState,
        block_store: Option<&BlockStore>,
        chain_id: [u8; 32],
    ) {
        // Best-effort compatibility path. Live callers that need authoritative
        // requeue visibility must use `apply_with_report`.
        let report = self.apply_with_report(pool, chain_state, block_store, chain_id);
        if report.has_requeue_failures() {
            eprintln!(
                "mempool: requeue cleanup failed: {}",
                report.requeue_failure_summary()
            );
        }
    }

    pub(crate) fn apply_with_report(
        &self,
        pool: &mut TxPool,
        chain_state: &crate::ChainState,
        block_store: Option<&BlockStore>,
        chain_id: [u8; 32],
    ) -> TxPoolCleanupReport {
        let mut report = TxPoolCleanupReport::default();
        if !self.confirmed_txids.is_empty() {
            pool.evict_txids(&self.confirmed_txids);
        }
        if !self.conflicting_inputs.is_empty() {
            pool.remove_conflicting_outpoints(&self.conflicting_inputs);
        }
        if let Some(block_store) = block_store {
            for block_hash in self.requeue_block_hashes.iter().rev() {
                let Ok(block_bytes) = block_store.get_block_by_hash(*block_hash) else {
                    report.requeue_blocks_unavailable =
                        report.requeue_blocks_unavailable.saturating_add(1);
                    continue;
                };
                let Ok(txs) = non_coinbase_tx_bytes(&block_bytes) else {
                    report.requeue_blocks_invalid = report.requeue_blocks_invalid.saturating_add(1);
                    continue;
                };
                // Reorg requeue: route through source-aware admission so the
                // resulting `TxPoolEntry.source` records `TxSource::Reorg`,
                // matching Go `Mempool.AddReorgTx` (clients/go/node/mempool.go)
                // which delegates to `addTxWithSource(_, mempoolTxSourceReorg)`.
                // Source provenance is observability metadata only — it does
                // not affect admission validation or ordering (see
                // `compare_entries_for_mining` and the source-blind hostile
                // test `source_does_not_affect_admission_ordering` in
                // `txpool.rs`). The cleanup-only paths above
                // (`pool.evict_txids` and `pool.remove_conflicting_outpoints`)
                // intentionally remain unchanged: they remove entries from
                // existing state and must not mutate any source counter.
                for tx_bytes in txs {
                    report.record_requeue_attempt();
                    match pool.add_tx_with_source(
                        &tx_bytes,
                        chain_state,
                        Some(block_store),
                        chain_id,
                        TxSource::Reorg,
                    ) {
                        Ok(_) => report.record_requeue_accepted(),
                        Err(err) => report.record_requeue_error(&err),
                    }
                }
            }
        } else if !self.requeue_block_hashes.is_empty() {
            report.requeue_blocks_unavailable = report
                .requeue_blocks_unavailable
                .saturating_add(self.requeue_block_hashes.len());
        }
        report
    }

    pub fn merge(mut self, mut other: Self) -> Self {
        self.confirmed_txids.append(&mut other.confirmed_txids);
        self.conflicting_inputs
            .append(&mut other.conflicting_inputs);
        self.requeue_block_hashes
            .append(&mut other.requeue_block_hashes);
        self
    }

    /// Build a cleanup plan from an already-parsed block. Crate-private
    /// for the reorg pipeline and hot-path callers that already hold a
    /// `ParsedBlock` — avoids re-parsing the block bytes. External
    /// callers use the `pub` [`Self::from_block_bytes`] wrapper.
    ///
    /// The caller must guarantee `parsed` was produced from
    /// `block_bytes` (otherwise `parsed.txids` and
    /// `non_coinbase_inputs(block_bytes)` would disagree).
    pub(crate) fn from_validated_block(
        parsed: &ParsedBlock,
        block_bytes: &[u8],
    ) -> Result<Self, String> {
        Ok(Self {
            confirmed_txids: parsed.txids.clone(),
            conflicting_inputs: non_coinbase_inputs(block_bytes)?,
            ..Self::default()
        })
    }

    /// Build a cleanup plan from raw block bytes — high-level
    /// constructor intended for callers that just finished a successful
    /// `SyncEngine::apply_block` on the direct (non-reorg) path.
    ///
    /// Go parity (`clients/go/node/sync.go` calls
    /// `s.mempool.EvictConfirmedParsed(pb)` after a successful apply);
    /// in Rust the reorg path already builds this plan internally, but
    /// the direct apply path (miner loop, test harnesses) had no
    /// equivalent constructor. Usage:
    ///
    /// ```ignore
    /// TxPoolCleanupPlan::from_block_bytes(block_bytes)?
    ///     .apply(&mut pool, &chain_state, block_store, chain_id);
    /// ```
    ///
    /// Mirrors the Go post-apply cleanup shape: evict confirmed txids,
    /// drop conflicting inputs.
    ///
    /// This constructor re-parses the block. Hot-path in-crate callers
    /// that already hold a `ParsedBlock` (e.g., the reorg pipeline)
    /// use the crate-private [`Self::from_validated_block`] directly to
    /// avoid the second parse.
    pub fn from_block_bytes(block_bytes: &[u8]) -> Result<Self, String> {
        let parsed = parse_block_bytes(block_bytes).map_err(|e| e.to_string())?;
        Self::from_validated_block(&parsed, block_bytes)
    }

    #[cfg(test)]
    pub fn from_parts_for_test(
        confirmed_txids: Vec<[u8; 32]>,
        conflicting_inputs: Vec<Outpoint>,
        requeue_block_hashes: Vec<[u8; 32]>,
    ) -> Self {
        Self {
            confirmed_txids,
            conflicting_inputs,
            requeue_block_hashes,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ApplyBlockWithReorgOutcome {
    pub summary: ChainStateConnectSummary,
    pub tx_pool_cleanup: TxPoolCleanupPlan,
}

impl Deref for ApplyBlockWithReorgOutcome {
    type Target = ChainStateConnectSummary;

    fn deref(&self) -> &Self::Target {
        &self.summary
    }
}

impl SyncEngine {
    /// Apply a block that may extend the canonical chain directly or trigger
    /// a reorg if it builds on a better fork-choice branch.
    ///
    /// Returns the connect summary for the newly applied tip block.
    pub fn apply_block_with_reorg(
        &mut self,
        block_bytes: &[u8],
        prev_timestamps: Option<&[u64]>,
    ) -> Result<ApplyBlockWithReorgOutcome, String> {
        let parsed = parse_block_bytes(block_bytes).map_err(|e| e.to_string())?;
        let bh = block_hash(&parsed.header_bytes).map_err(|e| e.to_string())?;

        // Fast path: block extends current tip or is genesis.
        if let Some(summary) = self.apply_direct_if_possible(block_bytes, prev_timestamps)? {
            return Ok(ApplyBlockWithReorgOutcome {
                summary,
                tx_pool_cleanup: TxPoolCleanupPlan::from_validated_block(&parsed, block_bytes)?,
            });
        }

        let block_store = self
            .block_store
            .as_ref()
            .ok_or("missing blockstore for side-chain block")?;

        // Collect branch from this block back to a common canonical ancestor.
        // The incoming block is added directly from block_bytes (not read from
        // store), so it does not need to be persisted yet.
        let (branch, common_ancestor_hash, common_ancestor_height) =
            self.collect_branch_to_canonical(bh, block_bytes)?;

        // Evaluate fork choice: switch if the candidate has greater work, or
        // equal work with a lexicographically smaller tip hash.
        let (switch, candidate_height) =
            self.should_switch_to_branch(&branch, common_ancestor_hash)?;

        if !switch {
            // Validate the block BEFORE storing — matching Go's ordering so
            // invalid side-chain blocks never reach the blockstore (B.2 fix,
            // issue #1168).
            let candidate = branch.last().ok_or("empty side branch")?;
            let ts = self.side_branch_prev_timestamps(&branch, common_ancestor_height)?;
            validate_block_basic_with_context_at_height(
                &candidate.block_bytes,
                Some(candidate.prev_hash),
                self.cfg.expected_target,
                candidate_height,
                ts.as_deref(),
            )
            .map_err(|e| e.to_string())?;

            // Validation passed — now persist the side-chain block.
            if !block_store.has_block(candidate.hash) {
                block_store.store_block(
                    candidate.hash,
                    &candidate.header_bytes,
                    &candidate.block_bytes,
                )?;
            }

            return Ok(ApplyBlockWithReorgOutcome {
                summary: self.synthetic_side_chain_summary(candidate_height, candidate.hash),
                tx_pool_cleanup: TxPoolCleanupPlan::default(),
            });
        }

        // Execute the reorg.
        self.apply_preferred_branch(branch, common_ancestor_height)
    }

    fn side_branch_prev_timestamps(
        &self,
        branch: &[ReorgBranchBlock],
        common_ancestor_height: u64,
    ) -> Result<Option<Vec<u64>>, String> {
        if branch.is_empty() {
            return Err("empty side branch".to_string());
        }
        let next_height = common_ancestor_height
            .checked_add(1)
            .ok_or_else(|| "height overflow".to_string())?;
        let mut prev_timestamps = self.prev_timestamps_for_height(next_height)?;
        for item in &branch[..branch.len() - 1] {
            prev_timestamps = Some(advance_prev_timestamps(
                prev_timestamps.as_deref(),
                item.timestamp,
            ));
        }
        Ok(prev_timestamps)
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
                return Err(PARENT_BLOCK_NOT_FOUND_ERR.into());
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

    /// Evaluate the fork choice rule: candidate branch must have greater
    /// cumulative work, or equal work with a lexicographically smaller tip.
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
        let branch_work =
            rubin_consensus::chain_work_from_targets(&branch_targets).map_err(|e| e.to_string())?;

        let candidate_work = ancestor_work + branch_work;

        let ancestor_height = block_store
            .find_canonical_height(common_ancestor_hash)?
            .ok_or("common ancestor not on canonical chain")?;
        let candidate_height = ancestor_height + branch.len() as u64;

        let candidate_tip_hash = branch.last().ok_or("empty side branch")?.hash;
        let should_switch = match candidate_work.cmp(&current_work) {
            std::cmp::Ordering::Greater => true,
            std::cmp::Ordering::Equal => candidate_tip_hash < current_tip_hash,
            std::cmp::Ordering::Less => false,
        };

        Ok((should_switch, candidate_height))
    }

    /// Execute the reorg for the branch selected by fork choice: greater
    /// cumulative work, or equal work with a lexicographically smaller tip.
    fn apply_preferred_branch(
        &mut self,
        branch: Vec<ReorgBranchBlock>,
        common_ancestor_height: u64,
    ) -> Result<ApplyBlockWithReorgOutcome, String> {
        let rollback = self.capture_reorg_rollback_state(common_ancestor_height);

        // Dry-run: preview the disconnect + reconnect on a cloned state.
        let disconnected_blocks = self.prepare_preferred_branch(&branch, common_ancestor_height)?;
        let reorg_depth = u64::try_from(disconnected_blocks.len()).unwrap_or(u64::MAX);

        // Disconnect canonical chain back to the common ancestor.
        if let Err(err) = self.disconnect_canonical_to_ancestor(common_ancestor_height) {
            return Err(Self::err_with_rollback(
                err,
                self.rollback_apply_block(rollback),
            ));
        }

        // Connect the preferred branch.  Pass None so apply_block derives
        // fresh timestamps from the (updated) canonical index for each block,
        // instead of reusing the stale caller value (B.9 fix, issue #1166).
        let mut last_summary = None;
        let mut canonical_applied_blocks: Vec<CanonicalAppliedBlock> = Vec::new();
        for item in &branch {
            match self.apply_block(&item.block_bytes, None) {
                Ok(mut summary) => {
                    // branch is in ascending canonical (height) order, so this
                    // accumulates every newly-canonical block in canonical order.
                    // Move (not clone) the per-block entries: this throwaway
                    // summary's vec is never read again — the returned summary's
                    // vec is overwritten below.
                    canonical_applied_blocks.append(&mut summary.canonical_applied_blocks);
                    last_summary = Some(summary);
                }
                Err(err) => {
                    return Err(Self::err_with_rollback(
                        err,
                        self.rollback_apply_block(rollback),
                    ));
                }
            }
        }

        // Mempool maintenance: evict txs confirmed in the winning branch,
        // then requeue txs from the disconnected blocks (those that are still
        // valid against the new chain state will be re-admitted).
        let cleanup = TxPoolCleanupPlan {
            confirmed_txids: branch
                .iter()
                .flat_map(|item| item.txids.iter().copied())
                .collect(),
            conflicting_inputs: branch
                .iter()
                .flat_map(|item| non_coinbase_inputs(&item.block_bytes).unwrap_or_default())
                .collect(),
            requeue_block_hashes: collect_disconnected_block_hashes(&disconnected_blocks),
        };

        let mut summary = last_summary.ok_or_else(|| "reorg branch was empty".to_string())?;
        // Report every block that became canonical in this reorg (the returned
        // summary's scalar fields otherwise reflect only the new tip).
        summary.canonical_applied_blocks = canonical_applied_blocks;
        self.note_reorg(reorg_depth);
        Ok(ApplyBlockWithReorgOutcome {
            summary,
            tx_pool_cleanup: cleanup,
        })
    }

    /// Dry-run validation: clone chain state, preview disconnect, then
    /// connect each branch block to verify the entire branch is valid.
    fn prepare_preferred_branch(
        &self,
        branch: &[ReorgBranchBlock],
        common_ancestor_height: u64,
    ) -> Result<Vec<Vec<u8>>, String> {
        let mut preview_state = self.chain_state.clone();

        let disconnected_blocks = self
            .preview_disconnect_canonical_to_ancestor(&mut preview_state, common_ancestor_height)?;

        // Build a sliding MTP window: start from pre-fork timestamps, advance
        // after each block.  The blockstore index is NOT updated during preview,
        // so per-block advancement uses a sliding window instead of
        // re-deriving from the store each iteration (B.9 fix, issue #1166).
        let mut sliding_ts = self.prev_timestamps_for_height(common_ancestor_height + 1)?;
        let (rotation, registry) = self.suite_context();
        for item in branch {
            preview_state.connect_block_with_suite_context(
                &item.block_bytes,
                self.cfg.expected_target,
                sliding_ts.as_deref(),
                self.cfg.chain_id,
                rotation,
                registry,
            )?;
            sliding_ts = Some(advance_prev_timestamps(
                sliding_ts.as_deref(),
                item.timestamp,
            ));
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
            header_bytes: parsed.header_bytes,
            block_bytes: block_bytes.to_vec(),
            prev_hash: parsed.header.prev_block_hash,
            target: parsed.header.target,
            timestamp: parsed.header.timestamp,
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
                .map_err(|_| PARENT_BLOCK_NOT_FOUND_ERR.to_string())?;
            let parent_parsed = parse_block_bytes(&parent_bytes).map_err(|e| e.to_string())?;

            branch.push(ReorgBranchBlock {
                hash: parent_hash,
                header_bytes: parent_parsed.header_bytes,
                block_bytes: parent_bytes,
                prev_hash: parent_parsed.header.prev_block_hash,
                target: parent_parsed.header.target,
                timestamp: parent_parsed.header.timestamp,
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
            // Side branch stored but not switched: no block became canonical.
            canonical_applied_blocks: Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Mempool helpers
// ---------------------------------------------------------------------------

/// Track disconnected blocks by hash and re-load them from blockstore when
/// applying mempool cleanup, instead of copying every tx into the cleanup plan.
fn collect_disconnected_block_hashes(disconnected_blocks: &[Vec<u8>]) -> Vec<[u8; 32]> {
    disconnected_blocks
        .iter()
        .filter_map(|block_bytes| {
            parse_block_bytes(block_bytes)
                .ok()
                .and_then(|parsed| block_hash(&parsed.header_bytes).ok())
        })
        .collect()
}

/// Remove transactions confirmed in the given block from the mempool.
#[cfg(test)]
fn evict_confirmed_from_pool(pool: &mut TxPool, block_bytes: &[u8]) {
    let Ok(parsed) = parse_block_bytes(block_bytes) else {
        return;
    };
    pool.evict_txids(&parsed.txids);
}

fn non_coinbase_inputs(block_bytes: &[u8]) -> Result<Vec<Outpoint>, String> {
    if block_bytes.len() < BLOCK_HEADER_BYTES {
        return Err("block too short".into());
    }
    let after_header = &block_bytes[BLOCK_HEADER_BYTES..];
    let (tx_count, cs_size) = read_compact_size_bytes(after_header).map_err(|e| e.to_string())?;
    if tx_count <= 1 {
        return Ok(Vec::new());
    }

    let mut offset = BLOCK_HEADER_BYTES + cs_size;
    let mut outpoints = Vec::new();
    for i in 0..tx_count {
        let (tx, _txid, _wtxid, consumed) =
            parse_tx(&block_bytes[offset..]).map_err(|e| e.to_string())?;
        if i > 0 {
            outpoints.extend(tx.inputs.into_iter().map(|input| Outpoint {
                txid: input.prev_txid,
                vout: input.prev_vout,
            }));
        }
        offset += consumed;
    }
    Ok(outpoints)
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
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use rubin_consensus::constants::{
        MAX_FUTURE_DRIFT, ML_DSA_87_PUBKEY_BYTES, ML_DSA_87_SIG_BYTES, POW_LIMIT,
        SUITE_ID_ML_DSA_87, VERIFY_COST_ML_DSA_87,
    };
    use rubin_consensus::{
        marshal_tx, p2pk_covenant_data_for_pubkey, parse_tx, sign_transaction, Mldsa87Keypair,
        NativeSuiteSet, Outpoint, RotationProvider, SuiteParams, SuiteRegistry, Tx, TxInput,
        TxOutput, UtxoEntry,
    };

    use super::*;
    use crate::blockstore::{block_store_path, BlockStore};
    use crate::chainstate::{chain_state_path, ChainState};
    use crate::devnet_genesis_chain_id;
    use crate::io_utils::unique_temp_path;
    use crate::sync::{default_sync_config, SuiteContext, SyncEngine};
    use crate::test_helpers::{
        block_with_txs, coinbase_only_block, coinbase_only_block_with_gen, genesis_info,
        height_one_coinbase_only_block, signed_conflicting_p2pk_state_and_txs,
    };

    #[test]
    fn non_coinbase_tx_bytes_empty_for_coinbase_only() {
        let genesis = crate::devnet_genesis_block_bytes();
        let txs = non_coinbase_tx_bytes(&genesis).expect("parse");
        assert!(txs.is_empty());
    }

    /// `TxPoolCleanupPlan::from_block_bytes` is the direct-apply-path
    /// constructor introduced for Q-IMPL-NODE-CONFIRMED-TX-CLEANUP-PARITY-01.
    /// After a successful `SyncEngine::apply_block`, a direct caller
    /// (miner, test harness) can build the cleanup plan from the same
    /// block bytes and call `plan.apply(...)` to evict the now-confirmed
    /// txids from the pool. This mirrors Go's post-apply call shape
    /// `s.mempool.EvictConfirmedParsed(pb)` (clients/go/node/sync.go).
    ///
    /// The plan's `confirmed_txids` must equal the block's parsed txids
    /// (coinbase is included in `parsed.txids` just like Go passes the
    /// whole `ParsedBlock` to `EvictConfirmedParsed`; the pool's
    /// `evict_txids` is tolerant of non-member txids so the coinbase
    /// entry is a no-op when absent from the pool).
    #[test]
    fn cleanup_plan_from_block_bytes_lists_parsed_txids() {
        let genesis = crate::devnet_genesis_block_bytes();
        let parsed =
            rubin_consensus::parse_block_bytes(&genesis).expect("parse genesis for parity check");
        let plan = TxPoolCleanupPlan::from_block_bytes(&genesis).expect("from_block_bytes");
        assert_eq!(
            plan.confirmed_txids, parsed.txids,
            "confirmed_txids must mirror parsed block txids"
        );
        // Genesis is coinbase-only so there are no non-coinbase inputs to
        // drop; still, the plan is well-formed (not `is_empty`, since
        // the coinbase txid is present).
        assert!(plan.conflicting_inputs.is_empty());
        assert!(plan.requeue_block_hashes.is_empty());
    }

    #[test]
    fn cleanup_plan_from_block_bytes_rejects_short_input() {
        let err = TxPoolCleanupPlan::from_block_bytes(&[0u8; 10]).unwrap_err();
        assert!(
            !err.is_empty(),
            "short block must surface the underlying parse error"
        );
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

    fn block_header_hash(block: &[u8]) -> [u8; 32] {
        rubin_consensus::block_hash(&block[..rubin_consensus::BLOCK_HEADER_BYTES])
            .expect("block header hash")
    }

    fn timestamp_ordered_equal_work_height_one_pair(
        genesis_hash: [u8; 32],
        gen_ts: u64,
        later_tip_cmp: std::cmp::Ordering,
    ) -> (Vec<u8>, [u8; 32], Vec<u8>, [u8; 32]) {
        for earlier_delta in 1..128 {
            let earlier_ts = gen_ts + earlier_delta;
            let earlier_block = height_one_coinbase_only_block(genesis_hash, earlier_ts);
            let earlier_hash = block_header_hash(&earlier_block);
            for later_delta in (earlier_delta + 1)..128 {
                let later_block =
                    height_one_coinbase_only_block(genesis_hash, gen_ts + later_delta);
                let later_hash = block_header_hash(&later_block);
                if later_hash.cmp(&earlier_hash) == later_tip_cmp {
                    return (earlier_block, earlier_hash, later_block, later_hash);
                }
            }
        }
        panic!("could not find deterministic equal-work test pair with requested tip ordering");
    }

    struct CountingRotationProvider {
        suite_id: u8,
        spend_calls: AtomicUsize,
    }

    impl RotationProvider for CountingRotationProvider {
        fn native_create_suites(&self, _height: u64) -> NativeSuiteSet {
            NativeSuiteSet::try_new(&[SUITE_ID_ML_DSA_87, self.suite_id])
                .expect("counting rotation provider suite set must stay <= 2")
        }

        fn native_spend_suites(&self, _height: u64) -> NativeSuiteSet {
            self.spend_calls.fetch_add(1, Ordering::SeqCst);
            NativeSuiteSet::try_new(&[self.suite_id])
                .expect("counting rotation provider suite set must stay <= 2")
        }
    }

    fn suite_context(extra_suite_id: u8) -> (Arc<CountingRotationProvider>, SuiteContext) {
        let rotation = Arc::new(CountingRotationProvider {
            suite_id: extra_suite_id,
            spend_calls: AtomicUsize::new(0),
        });
        let mut suites = BTreeMap::new();
        suites.insert(
            SUITE_ID_ML_DSA_87,
            SuiteParams {
                suite_id: SUITE_ID_ML_DSA_87,
                pubkey_len: ML_DSA_87_PUBKEY_BYTES,
                sig_len: ML_DSA_87_SIG_BYTES,
                verify_cost: VERIFY_COST_ML_DSA_87,
                alg_name: "ML-DSA-87",
            },
        );
        suites.insert(
            extra_suite_id,
            SuiteParams {
                suite_id: extra_suite_id,
                pubkey_len: ML_DSA_87_PUBKEY_BYTES,
                sig_len: ML_DSA_87_SIG_BYTES,
                verify_cost: VERIFY_COST_ML_DSA_87,
                alg_name: "ML-DSA-87",
            },
        );
        let ctx = SuiteContext {
            rotation: rotation.clone(),
            registry: Arc::new(SuiteRegistry::with_suites(suites)),
        };
        (rotation, ctx)
    }

    fn rewrite_native_suite(mut raw: Vec<u8>, suite_id: u8) -> Vec<u8> {
        let (mut tx, _, _, consumed) = parse_tx(&raw).expect("parse tx");
        assert_eq!(consumed, raw.len(), "parse tx consumed full buffer");
        assert_eq!(tx.witness.len(), 1, "single witness expected");
        tx.witness[0].suite_id = suite_id;
        raw = marshal_tx(&tx).expect("marshal tx");
        raw
    }

    fn build_rotated_p2pk_tx(
        state: &ChainState,
        outpoint: Outpoint,
        keypair: &Mldsa87Keypair,
        tx_nonce: u64,
        output_value: u64,
        dest_fill: u8,
        suite_id: u8,
    ) -> Vec<u8> {
        let mut tx = Tx {
            version: rubin_consensus::constants::TX_WIRE_VERSION,
            tx_kind: 0x00,
            tx_nonce,
            inputs: vec![TxInput {
                prev_txid: outpoint.txid,
                prev_vout: outpoint.vout,
                script_sig: Vec::new(),
                sequence: 0,
            }],
            outputs: vec![TxOutput {
                value: output_value,
                covenant_type: rubin_consensus::constants::COV_TYPE_P2PK,
                covenant_data: p2pk_covenant_data_for_pubkey(&vec![dest_fill; 2592]),
            }],
            locktime: 0,
            da_commit_core: None,
            da_chunk_core: None,
            witness: Vec::new(),
            da_payload: Vec::new(),
        };
        sign_transaction(&mut tx, &state.utxos, devnet_genesis_chain_id(), keypair)
            .expect("sign tx");
        rewrite_native_suite(marshal_tx(&tx).expect("marshal tx"), suite_id)
    }

    #[test]
    fn apply_block_with_reorg_genesis_fast_path() {
        let (mut engine, dir) = engine_with_store("rubin-reorg-gen");
        let (genesis, _, _) = genesis_info();

        let summary = engine
            .apply_block_with_reorg(&genesis, None)
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
            .apply_block_with_reorg(&genesis, None)
            .expect("genesis");

        let block1 = height_one_coinbase_only_block(genesis_hash, gen_ts + 1);
        let mut pool = TxPool::new();
        let summary = engine
            .apply_block_with_reorg(&block1, None)
            .expect("block 1");
        summary.tx_pool_cleanup.apply(
            &mut pool,
            &engine.chain_state,
            engine.block_store.as_ref(),
            engine.cfg.chain_id,
        );
        assert_eq!(summary.block_height, 1);

        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn apply_block_with_reorg_tip_extension_removes_conflicting_pool_spends() {
        // RUB-162 Phase A migration rationale (per controller Q2 / Path A
        // approval 2026-05-03):
        //   - old assumption: signed_conflicting_p2pk_state_and_txs(20,10,9)
        //     produces tx with fee=10/weight≈7653 that admits because
        //     pre-RUB-162 admit_with_metadata did not enforce the rolling
        //     fee floor.
        //   - new invariant: admit_with_metadata enforces the rolling fee
        //     floor.
        //   - reachability: pool.admit reaches the txpool admission path;
        //     apply_block_with_reorg's tx_pool_cleanup then exercises the
        //     conflict-removal path on tip-extension.
        //   - replacement coverage: input bumped to 7700 so both txs have
        //     floor-compliant fees. Conflict-removal-on-tip-extension
        //     invariant remains under test.
        let (mut engine, dir) = engine_with_store("rubin-reorg-tip-conflict");
        let (genesis, genesis_hash, gen_ts) = genesis_info();
        engine
            .apply_block_with_reorg(&genesis, None)
            .expect("genesis");
        engine.cfg.chain_id = devnet_genesis_chain_id();

        let (state, admitted_raw, block_raw) = signed_conflicting_p2pk_state_and_txs(7700, 10, 9);
        engine.chain_state.utxos = state.utxos.clone();

        let mut pool = TxPool::new();
        pool.admit(
            &admitted_raw,
            &engine.chain_state,
            engine.block_store.as_ref(),
            engine.cfg.chain_id,
        )
        .expect("admit");

        let block1 = block_with_txs(1, 0, genesis_hash, gen_ts + 1, &[block_raw]);
        let outcome = engine
            .apply_block_with_reorg(&block1, None)
            .expect("block 1");
        outcome.tx_pool_cleanup.apply(
            &mut pool,
            &engine.chain_state,
            engine.block_store.as_ref(),
            engine.cfg.chain_id,
        );

        assert!(pool.is_empty());
        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn apply_block_with_reorg_non_tip_parent_without_store() {
        let cfg = default_sync_config(Some(POW_LIMIT), [0u8; 32], None);
        let mut engine = SyncEngine::new(ChainState::new(), None, cfg).expect("new");
        let (genesis, genesis_hash, gen_ts) = genesis_info();

        engine
            .apply_block_with_reorg(&genesis, None)
            .expect("genesis");

        // Extend tip with explicit timestamps (no blockstore for auto-derive).
        let block1 = height_one_coinbase_only_block(genesis_hash, gen_ts + 1);
        engine
            .apply_block_with_reorg(&block1, Some(&[gen_ts]))
            .expect("extends tip");

        // Alternate block with parent = genesis (not tip).
        // Without blockstore → error on side-chain path.
        let alt = height_one_coinbase_only_block(genesis_hash, gen_ts + 2);
        let err = engine
            .apply_block_with_reorg(&alt, Some(&[gen_ts]))
            .unwrap_err();
        assert!(err.contains("missing blockstore"), "got: {err}");
    }

    #[test]
    fn apply_block_with_reorg_switches_to_lower_tip_on_equal_work() {
        let (mut engine, dir) = engine_with_store("rubin-reorg-equal-lower");
        let (genesis, genesis_hash, gen_ts) = genesis_info();

        engine
            .apply_block_with_reorg(&genesis, None)
            .expect("genesis");

        let (higher_block, higher_hash, lower_block, lower_hash) =
            timestamp_ordered_equal_work_height_one_pair(
                genesis_hash,
                gen_ts,
                std::cmp::Ordering::Less,
            );

        engine
            .apply_block_with_reorg(&higher_block, None)
            .expect("higher-tip block first");
        assert_eq!(engine.chain_state.height, 1);
        assert_eq!(engine.chain_state.tip_hash, higher_hash);

        let summary = engine
            .apply_block_with_reorg(&lower_block, None)
            .expect("lower-tip equal-work branch");

        assert_eq!(engine.chain_state.height, 1);
        assert_eq!(summary.block_height, 1);
        assert_eq!(engine.chain_state.tip_hash, lower_hash);
        assert_eq!(engine.reorg_count(), 1);
        assert_eq!(engine.last_reorg_depth(), 1);

        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn apply_block_with_reorg_keeps_lower_tip_on_equal_work_higher_side_branch() {
        let (mut engine, dir) = engine_with_store("rubin-reorg-side");
        let (genesis, genesis_hash, gen_ts) = genesis_info();

        engine
            .apply_block_with_reorg(&genesis, None)
            .expect("genesis");

        let (lower_block, lower_hash, higher_block, _) =
            timestamp_ordered_equal_work_height_one_pair(
                genesis_hash,
                gen_ts,
                std::cmp::Ordering::Greater,
            );

        engine
            .apply_block_with_reorg(&lower_block, None)
            .expect("lower-tip block first");
        assert_eq!(engine.chain_state.height, 1);
        assert_eq!(engine.chain_state.tip_hash, lower_hash);

        let summary = engine
            .apply_block_with_reorg(&higher_block, None)
            .expect("higher-tip equal-work side branch stored");

        // Higher-tip equal-work branch is stored as side chain; canonical tip
        // remains the lower hash.
        assert_eq!(engine.chain_state.height, 1);
        assert_eq!(summary.block_height, 1);
        assert_eq!(engine.chain_state.tip_hash, lower_hash);
        assert_eq!(engine.reorg_count(), 0);
        assert_eq!(engine.last_reorg_depth(), 0);

        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn apply_block_with_reorg_keeps_tip_when_candidate_has_less_work() {
        let (mut engine, dir) = engine_with_store("rubin-reorg-less-work");
        let (genesis, genesis_hash, gen_ts) = genesis_info();

        engine
            .apply_block_with_reorg(&genesis, None)
            .expect("genesis");

        let block1 = height_one_coinbase_only_block(genesis_hash, gen_ts + 1);
        let block1_hash = block_header_hash(&block1);
        engine
            .apply_block_with_reorg(&block1, None)
            .expect("block1 canonical");

        let subsidy1 = rubin_consensus::subsidy::block_subsidy(1, 0);
        let block2 = coinbase_only_block_with_gen(2, subsidy1, block1_hash, gen_ts + 2);
        let block2_hash = block_header_hash(&block2);
        engine
            .apply_block_with_reorg(&block2, None)
            .expect("block2 canonical");
        assert_eq!(engine.chain_state.height, 2);
        assert_eq!(engine.chain_state.tip_hash, block2_hash);

        let alt = height_one_coinbase_only_block(genesis_hash, gen_ts + 3);
        let summary = engine
            .apply_block_with_reorg(&alt, None)
            .expect("lower-work side branch stored");

        assert_eq!(summary.block_height, 1);
        assert_eq!(engine.chain_state.height, 2);
        assert_eq!(engine.chain_state.tip_hash, block2_hash);
        assert_eq!(engine.reorg_count(), 0);
        assert_eq!(engine.last_reorg_depth(), 0);

        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn apply_block_with_reorg_reports_single_canonical_applied_block_on_direct_apply() {
        let (mut engine, dir) = engine_with_store("rubin-reorg-canon-direct");
        let (genesis, genesis_hash, gen_ts) = genesis_info();
        engine
            .apply_block_with_reorg(&genesis, None)
            .expect("genesis");

        let block1 = height_one_coinbase_only_block(genesis_hash, gen_ts + 1);
        let block1_hash = block_header_hash(&block1);
        let summary = engine
            .apply_block_with_reorg(&block1, None)
            .expect("block1 direct apply");

        assert_eq!(summary.canonical_applied_blocks.len(), 1);
        assert_eq!(summary.canonical_applied_blocks[0].hash, block1_hash);
        assert_eq!(summary.canonical_applied_blocks[0].hash, summary.block_hash);
        assert_eq!(summary.canonical_applied_blocks[0].block_bytes, block1);

        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn apply_block_with_reorg_reports_no_canonical_applied_blocks_on_side_branch() {
        let (mut engine, dir) = engine_with_store("rubin-reorg-canon-side");
        let (genesis, genesis_hash, gen_ts) = genesis_info();
        engine
            .apply_block_with_reorg(&genesis, None)
            .expect("genesis");

        let block1 = height_one_coinbase_only_block(genesis_hash, gen_ts + 1);
        let block1_hash = block_header_hash(&block1);
        engine
            .apply_block_with_reorg(&block1, None)
            .expect("block1 canonical");
        let subsidy1 = rubin_consensus::subsidy::block_subsidy(1, 0);
        let block2 = coinbase_only_block_with_gen(2, subsidy1, block1_hash, gen_ts + 2);
        let block2_hash = block_header_hash(&block2);
        engine
            .apply_block_with_reorg(&block2, None)
            .expect("block2 canonical");

        // Lower-work side block at height 1: stored, does not switch the tip.
        let side = height_one_coinbase_only_block(genesis_hash, gen_ts + 3);
        let summary = engine
            .apply_block_with_reorg(&side, None)
            .expect("side branch stored");

        assert!(
            summary.canonical_applied_blocks.is_empty(),
            "stored-but-not-switched side branch must report zero canonical-applied blocks"
        );
        assert_eq!(engine.chain_state.tip_hash, block2_hash);

        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn apply_block_with_reorg_reports_all_canonical_applied_blocks_in_order_on_reorg() {
        let (mut engine, dir) = engine_with_store("rubin-reorg-canon-reorg");
        let (genesis, genesis_hash, gen_ts) = genesis_info();
        engine
            .apply_block_with_reorg(&genesis, None)
            .expect("genesis");

        // Canonical: genesis -> block1 (1-block chain, work = 1).
        let block1 = coinbase_only_block(1, genesis_hash, gen_ts + 1);
        engine
            .apply_block_with_reorg(&block1, None)
            .expect("block1 canonical");

        // Heavier branch: genesis -> block1_alt -> block2_alt (work = 2).
        let block1_alt = coinbase_only_block(1, genesis_hash, gen_ts + 2);
        let block1_alt_hash = block_header_hash(&block1_alt);
        engine
            .block_store
            .as_ref()
            .unwrap()
            .store_block(
                block1_alt_hash,
                &block1_alt[..rubin_consensus::BLOCK_HEADER_BYTES],
                &block1_alt,
            )
            .expect("store block1_alt as side");

        let subsidy1 = rubin_consensus::subsidy::block_subsidy(1, 0);
        let block2_alt = coinbase_only_block_with_gen(2, subsidy1, block1_alt_hash, gen_ts + 3);
        let block2_alt_hash = block_header_hash(&block2_alt);

        let summary = engine
            .apply_block_with_reorg(&block2_alt, None)
            .expect("reorg to heavier branch");

        assert_eq!(engine.chain_state.tip_hash, block2_alt_hash);
        assert_eq!(engine.reorg_count(), 1);
        // Every block that became canonical, in ascending canonical order.
        assert_eq!(summary.canonical_applied_blocks.len(), 2);
        assert_eq!(summary.canonical_applied_blocks[0].hash, block1_alt_hash);
        assert_eq!(summary.canonical_applied_blocks[0].block_bytes, block1_alt);
        assert_eq!(summary.canonical_applied_blocks[1].hash, block2_alt_hash);
        assert_eq!(summary.canonical_applied_blocks[1].block_bytes, block2_alt);

        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn apply_block_with_reorg_uses_side_branch_timestamp_context_before_store() {
        let (mut engine, dir) = engine_with_store("rubin-reorg-side-mtp");
        let (genesis, genesis_hash, gen_ts) = genesis_info();

        engine
            .apply_block_with_reorg(&genesis, None)
            .expect("genesis");

        let block1 = height_one_coinbase_only_block(genesis_hash, gen_ts + 100);
        let block1_hash = block_header_hash(&block1);
        engine
            .apply_block_with_reorg(&block1, None)
            .expect("block1 canonical");

        let subsidy1 = rubin_consensus::subsidy::block_subsidy(1, 0);
        let block2 = coinbase_only_block_with_gen(2, subsidy1, block1_hash, gen_ts + 101);
        let block2_hash = block_header_hash(&block2);
        engine
            .apply_block_with_reorg(&block2, None)
            .expect("block2 canonical");

        let side = height_one_coinbase_only_block(genesis_hash, gen_ts + 1);
        let side_hash = block_header_hash(&side);
        let summary = engine
            .apply_block_with_reorg(&side, None)
            .expect("valid side branch must use candidate-parent MTP context");

        assert_eq!(summary.block_height, 1);
        assert_eq!(engine.chain_state.height, 2);
        assert_eq!(engine.chain_state.tip_hash, block2_hash);
        assert_eq!(engine.reorg_count(), 0);
        assert_eq!(engine.last_reorg_depth(), 0);
        assert!(
            engine.has_block(side_hash).expect("side block lookup"),
            "valid side branch must be stored after candidate-context validation"
        );

        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn apply_block_with_reorg_advances_side_branch_timestamp_context() {
        let (mut engine, dir) = engine_with_store("rubin-reorg-side-mtp-parent");
        let (genesis, genesis_hash, gen_ts) = genesis_info();

        engine
            .apply_block_with_reorg(&genesis, None)
            .expect("genesis");

        let block1 = height_one_coinbase_only_block(genesis_hash, gen_ts + 100);
        let block1_hash = block_header_hash(&block1);
        engine
            .apply_block_with_reorg(&block1, None)
            .expect("block1 canonical");

        let subsidy1 = rubin_consensus::subsidy::block_subsidy(1, 0);
        let block2 = coinbase_only_block_with_gen(2, subsidy1, block1_hash, gen_ts + 101);
        let block2_hash = block_header_hash(&block2);
        engine
            .apply_block_with_reorg(&block2, None)
            .expect("block2 canonical");

        let already_generated2 = engine.chain_state.already_generated;
        let block3 = coinbase_only_block_with_gen(3, already_generated2, block2_hash, gen_ts + 102);
        let block3_hash = block_header_hash(&block3);
        engine
            .apply_block_with_reorg(&block3, None)
            .expect("block3 canonical");

        let already_generated3 = engine.chain_state.already_generated;
        let block4 = coinbase_only_block_with_gen(4, already_generated3, block3_hash, gen_ts + 103);
        let block4_hash = block_header_hash(&block4);
        engine
            .apply_block_with_reorg(&block4, None)
            .expect("block4 canonical");

        let side1_ts = gen_ts + 200;
        let side2_ts = gen_ts.saturating_add(MAX_FUTURE_DRIFT);
        let side3_ts = gen_ts.saturating_add(MAX_FUTURE_DRIFT).saturating_add(100);
        let side1 = height_one_coinbase_only_block(genesis_hash, side1_ts);
        let side1_hash = block_header_hash(&side1);
        engine
            .apply_block_with_reorg(&side1, None)
            .expect("valid side parent must be stored");

        let side2 = coinbase_only_block_with_gen(2, subsidy1, side1_hash, side2_ts);
        let side2_hash = block_header_hash(&side2);
        engine
            .apply_block_with_reorg(&side2, None)
            .expect("valid side child must be stored");

        let subsidy2 = rubin_consensus::subsidy::block_subsidy(2, u128::from(subsidy1));
        let side_generated2 = subsidy1.saturating_add(subsidy2);
        let side3 = coinbase_only_block_with_gen(3, side_generated2, side2_hash, side3_ts);
        let side3_hash = block_header_hash(&side3);
        let summary = engine
            .apply_block_with_reorg(&side3, None)
            .expect("valid side grandchild must use advanced side-parent MTP context");

        assert_eq!(summary.block_height, 3);
        assert_eq!(engine.chain_state.height, 4);
        assert_eq!(engine.chain_state.tip_hash, block4_hash);
        assert_eq!(engine.reorg_count(), 0);
        assert!(
            engine
                .has_block(side3_hash)
                .expect("side grandchild lookup"),
            "valid side grandchild must be stored after side-parent-context validation"
        );

        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn side_branch_prev_timestamps_rejects_empty_branch() {
        let (engine, dir) = engine_with_store("rubin-reorg-side-mtp-empty");

        let err = engine.side_branch_prev_timestamps(&[], 0).unwrap_err();
        assert!(err.contains("empty side branch"), "got: {err}");

        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn apply_block_with_reorg_rejects_side_branch_timestamp_before_store() {
        let (mut engine, dir) = engine_with_store("rubin-reorg-side-mtp-reject");
        let (genesis, genesis_hash, gen_ts) = genesis_info();

        engine
            .apply_block_with_reorg(&genesis, None)
            .expect("genesis");

        let block1 = height_one_coinbase_only_block(genesis_hash, gen_ts + 100);
        let block1_hash = block_header_hash(&block1);
        engine
            .apply_block_with_reorg(&block1, None)
            .expect("block1 canonical");

        let subsidy1 = rubin_consensus::subsidy::block_subsidy(1, 0);
        let block2 = coinbase_only_block_with_gen(2, subsidy1, block1_hash, gen_ts + 101);
        let block2_hash = block_header_hash(&block2);
        engine
            .apply_block_with_reorg(&block2, None)
            .expect("block2 canonical");

        let cases = [
            (gen_ts, "BLOCK_ERR_TIMESTAMP_OLD"),
            (
                gen_ts.saturating_add(MAX_FUTURE_DRIFT).saturating_add(1),
                "BLOCK_ERR_TIMESTAMP_FUTURE",
            ),
        ];
        for (timestamp, want_code) in cases {
            let side = height_one_coinbase_only_block(genesis_hash, timestamp);
            let side_hash = block_header_hash(&side);
            let err = engine
                .apply_block_with_reorg(&side, None)
                .expect_err("timestamp-invalid side branch must reject");
            assert!(err.contains(want_code), "err={err}, want code {want_code}");
            assert_eq!(engine.chain_state.height, 2);
            assert_eq!(engine.chain_state.tip_hash, block2_hash);
            assert!(
                !engine.has_block(side_hash).expect("side block lookup"),
                "timestamp-invalid side branch must not be stored"
            );
        }

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
            .apply_block_with_reorg(&genesis, None)
            .expect("genesis");

        // Canonical: genesis → block1
        let block1 = coinbase_only_block(1, genesis_hash, gen_ts + 1);
        engine
            .apply_block_with_reorg(&block1, None)
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
            .apply_block_with_reorg(&block2_alt, None)
            .expect("reorg to heavier branch");
        summary.tx_pool_cleanup.apply(
            &mut pool,
            &engine.chain_state,
            engine.block_store.as_ref(),
            engine.cfg.chain_id,
        );

        assert_eq!(engine.chain_state.height, 2);
        assert_eq!(summary.block_height, 2);
        assert_eq!(engine.reorg_count(), 1);
        assert_eq!(engine.last_reorg_depth(), 1);

        let block2_alt_hash =
            rubin_consensus::block_hash(&block2_alt[..rubin_consensus::BLOCK_HEADER_BYTES])
                .expect("hash2'");
        let subsidy2 = rubin_consensus::subsidy::block_subsidy(2, u128::from(subsidy1));
        let block3 =
            coinbase_only_block_with_gen(3, subsidy1 + subsidy2, block2_alt_hash, gen_ts + 4);
        engine
            .apply_block_with_reorg(&block3, None)
            .expect("direct extension after reorg");
        assert_eq!(engine.reorg_count(), 1);
        assert_eq!(engine.last_reorg_depth(), 0);

        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn native_suites_cache_invalidated_on_reorg() {
        // RUB-162 Phase A migration rationale (per controller Q2 / Path A
        // approval 2026-05-03):
        //   - old assumption: UTXO value=20, tx output_value=10 → fee=10,
        //     weight ≈ 7653 admits because pre-RUB-162 admit_with_metadata
        //     did not enforce the rolling fee floor.
        //   - new invariant: admit_with_metadata enforces the rolling fee
        //     floor (DEFAULT=1) via validate_fee_floor.
        //   - reachability: tx is well-formed (signed_a/signed_b); admitted
        //     to the pool before reorg. The reorg test then exercises
        //     native suite cache invalidation when the canonical chain
        //     swaps.
        //   - replacement coverage: both UTXOs bumped from value=20 to
        //     value=20_000 so each tx fee = 20000-10 = 19990 (and
        //     20000-9 = 19991) ≥ weight (~7653) — extra headroom over
        //     the minimal floor-compliant value (~7700) to keep the
        //     rotated-suite-witness fees comfortably above the floor
        //     across both branches of the reorg path. Native-suite-
        //     cache-invalidation-on-reorg invariant remains under test.
        let (mut engine, dir) = engine_with_store("rubin-reorg-native-suite");
        let (genesis, genesis_hash, gen_ts) = genesis_info();
        engine
            .apply_block_with_reorg(&genesis, None)
            .expect("genesis");
        engine.cfg.chain_id = devnet_genesis_chain_id();

        const ROTATED_SUITE_ID: u8 = 0x42;
        let signer_a = Mldsa87Keypair::generate().expect("OpenSSL signer unavailable");
        let signer_b = Mldsa87Keypair::generate().expect("OpenSSL signer unavailable");
        let outpoint_a = Outpoint {
            txid: [0x11; 32],
            vout: 0,
        };
        let outpoint_b = Outpoint {
            txid: [0x22; 32],
            vout: 0,
        };
        let mut state = ChainState::new();
        state.utxos.insert(
            outpoint_a.clone(),
            UtxoEntry {
                value: 20_000,
                covenant_type: rubin_consensus::constants::COV_TYPE_P2PK,
                covenant_data: p2pk_covenant_data_for_pubkey(&signer_a.pubkey_bytes()),
                creation_height: 0,
                created_by_coinbase: false,
            },
        );
        state.utxos.insert(
            outpoint_b.clone(),
            UtxoEntry {
                value: 20_000,
                covenant_type: rubin_consensus::constants::COV_TYPE_P2PK,
                covenant_data: p2pk_covenant_data_for_pubkey(&signer_b.pubkey_bytes()),
                creation_height: 0,
                created_by_coinbase: false,
            },
        );

        let admitted_raw = build_rotated_p2pk_tx(
            &state,
            outpoint_a.clone(),
            &signer_a,
            7,
            10,
            0x31,
            ROTATED_SUITE_ID,
        );
        let block_raw = build_rotated_p2pk_tx(
            &state,
            outpoint_b.clone(),
            &signer_b,
            8,
            9,
            0x41,
            ROTATED_SUITE_ID,
        );
        for entry in state.utxos.values_mut() {
            entry.covenant_data[0] = ROTATED_SUITE_ID;
        }

        let (rotation, suite_ctx) = suite_context(ROTATED_SUITE_ID);
        engine.cfg.suite_context = Some(suite_ctx.clone());
        engine.chain_state.utxos = state.utxos.clone();

        let mut pool = TxPool::new_with_config(crate::txpool::TxPoolConfig {
            suite_context: Some(suite_ctx),
            ..crate::txpool::TxPoolConfig::default()
        });

        let (_, _, admitted_wtxid, admitted_len) = parse_tx(&admitted_raw).expect("parse admitted");
        assert_eq!(admitted_len, admitted_raw.len());

        let block1 = block_with_txs(
            1,
            0,
            genesis_hash,
            gen_ts + 1,
            std::slice::from_ref(&admitted_raw),
        );
        let summary_a1 = engine
            .apply_block_with_reorg(&block1, None)
            .expect("A1 canonical");
        summary_a1.tx_pool_cleanup.apply(
            &mut pool,
            &engine.chain_state,
            engine.block_store.as_ref(),
            engine.cfg.chain_id,
        );

        let block1_alt = block_with_txs(1, 0, genesis_hash, gen_ts + 2, &[block_raw]);
        let summary_b1 = engine
            .apply_block_with_reorg(&block1_alt, None)
            .expect("B1 side chain stored");
        summary_b1.tx_pool_cleanup.apply(
            &mut pool,
            &engine.chain_state,
            engine.block_store.as_ref(),
            engine.cfg.chain_id,
        );

        let block1_alt_hash =
            rubin_consensus::block_hash(&block1_alt[..rubin_consensus::BLOCK_HEADER_BYTES])
                .expect("hash B1");
        let subsidy1 = rubin_consensus::subsidy::block_subsidy(1, 0);
        let block2_alt = coinbase_only_block_with_gen(2, subsidy1, block1_alt_hash, gen_ts + 3);

        let outcome = engine
            .apply_block_with_reorg(&block2_alt, None)
            .expect("reorg to heavier branch");
        outcome.tx_pool_cleanup.apply(
            &mut pool,
            &engine.chain_state,
            engine.block_store.as_ref(),
            engine.cfg.chain_id,
        );

        assert_eq!(pool.len(), 1, "disconnected tx requeued into mempool");
        assert!(
            rotation.spend_calls.load(Ordering::SeqCst) >= 3,
            "expected native spend suites to be recomputed for canonical apply, preview replay, and mempool requeue"
        );
        assert_ne!(engine.chain_state.tip_hash, summary_a1.block_hash);
        let selected = pool.select_transactions(10, usize::MAX);
        assert_eq!(selected.len(), 1);
        let (_, _, selected_wtxid, selected_len) = parse_tx(&selected[0]).expect("parse selected");
        assert_eq!(selected_len, selected[0].len());
        assert_eq!(selected_wtxid, admitted_wtxid);

        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn apply_block_with_reorg_rejects_non_zero_prev_genesis() {
        let (mut engine, dir) = engine_with_store("rubin-reorg-badgen");
        // Craft a block with prev_hash != [0;32] but chain has no tip.
        let bad_genesis = coinbase_only_block(0, [0xaa; 32], 1);
        let err = engine
            .apply_block_with_reorg(&bad_genesis, None)
            .unwrap_err();
        assert!(err.contains(PARENT_BLOCK_NOT_FOUND_ERR), "got: {err}");
        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    /// Test: disconnect failure during reorg triggers err_with_rollback path.
    ///
    /// Making chain_state_path read-only causes `disconnect_tip -> save` to
    /// fail, while blockstore index save (separate path) still works.
    /// The rollback's Phase 2 (chain_state.save) also fails → Some(err)
    /// flows through `err_with_rollback`.
    #[test]
    fn apply_preferred_branch_disconnect_fail_rollback_cascade() {
        let (mut engine, dir) = engine_with_store("rubin-reorg-disc-fail");
        let (genesis, genesis_hash, gen_ts) = genesis_info();

        engine
            .apply_block_with_reorg(&genesis, None)
            .expect("genesis");

        let block1 = coinbase_only_block(1, genesis_hash, gen_ts + 1);
        engine
            .apply_block_with_reorg(&block1, None)
            .expect("block1");

        // Build heavier branch: block1' → block2'.
        let block1_alt = coinbase_only_block(1, genesis_hash, gen_ts + 2);
        let block1_alt_hash =
            rubin_consensus::block_hash(&block1_alt[..rubin_consensus::BLOCK_HEADER_BYTES])
                .expect("hash1'");
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

        let subsidy1 = rubin_consensus::subsidy::block_subsidy(1, 0);
        let block2_alt = coinbase_only_block_with_gen(2, subsidy1, block1_alt_hash, gen_ts + 3);

        // Make data_dir read-only so write_file_atomic cannot create the
        // temp file for chainstate.json.  Blockstore lives in a subdirectory
        // whose permissions are unaffected, so undo reads still work.
        let mut perms = std::fs::metadata(&dir).expect("dir meta").permissions();
        perms.set_readonly(true);
        std::fs::set_permissions(&dir, perms).expect("set dir ro");

        let err = engine
            .apply_block_with_reorg(&block2_alt, None)
            .unwrap_err();

        // Restore permissions for cleanup.
        let mut perms = std::fs::metadata(&dir).expect("dir meta").permissions();
        #[allow(clippy::permissions_set_readonly_false)]
        perms.set_readonly(false);
        std::fs::set_permissions(&dir, perms).expect("restore dir rw");

        // Error should mention rollback failure (chain_state save failed
        // during both disconnect and rollback Phase 2).
        assert!(
            err.contains("rollback failed") || err.contains("Permission denied"),
            "expected rollback cascade error, got: {err}"
        );

        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    /// Test: connect failure during reorg triggers err_with_rollback path.
    ///
    /// Making the undo directory read-only causes `apply_block -> put_undo`
    /// to fail after disconnect has already succeeded.  Rollback succeeds
    /// (index and chain_state paths are writable), so err_with_rollback
    /// receives `None` — the original connect error is returned unchanged.
    #[test]
    fn apply_preferred_branch_connect_fail_undo_readonly() {
        let (mut engine, dir) = engine_with_store("rubin-reorg-conn-fail");
        let (genesis, genesis_hash, gen_ts) = genesis_info();

        engine
            .apply_block_with_reorg(&genesis, None)
            .expect("genesis");

        let block1 = coinbase_only_block(1, genesis_hash, gen_ts + 1);
        engine
            .apply_block_with_reorg(&block1, None)
            .expect("block1");

        // Build heavier branch.
        let block1_alt = coinbase_only_block(1, genesis_hash, gen_ts + 2);
        let block1_alt_hash =
            rubin_consensus::block_hash(&block1_alt[..rubin_consensus::BLOCK_HEADER_BYTES])
                .expect("hash1'");
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

        let subsidy1 = rubin_consensus::subsidy::block_subsidy(1, 0);
        let block2_alt = coinbase_only_block_with_gen(2, subsidy1, block1_alt_hash, gen_ts + 3);

        // Make undo directory read-only so put_undo fails during connect.
        let undo_dir = block_store_path(&dir).join("undo");
        let mut perms = std::fs::metadata(&undo_dir)
            .expect("undo meta")
            .permissions();
        perms.set_readonly(true);
        std::fs::set_permissions(&undo_dir, perms).expect("set ro");

        let err = engine
            .apply_block_with_reorg(&block2_alt, None)
            .unwrap_err();

        // Restore permissions for cleanup.
        let mut perms = std::fs::metadata(&undo_dir)
            .expect("undo meta")
            .permissions();
        #[allow(clippy::permissions_set_readonly_false)]
        perms.set_readonly(false);
        std::fs::set_permissions(&undo_dir, perms).expect("restore rw");

        // Connect phase failed; error comes from put_undo or downstream.
        assert!(
            err.contains("undo") || err.contains("Permission denied"),
            "expected undo write error, got: {err}"
        );

        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn advance_prev_timestamps_sliding_window() {
        // Empty input → single entry.
        let got = super::advance_prev_timestamps(None, 100);
        assert_eq!(got, vec![100]);

        // Partial window (5 entries) → prepend, len=6.
        let prev = vec![90, 80, 70, 60, 50];
        let got = super::advance_prev_timestamps(Some(&prev), 100);
        assert_eq!(got, vec![100, 90, 80, 70, 60, 50]);

        // Full window (11 entries) → prepend + truncate, len=11.
        let full: Vec<u64> = (0..11).map(|i| 110 - i * 10).collect();
        let got = super::advance_prev_timestamps(Some(&full), 200);
        assert_eq!(got.len(), 11);
        assert_eq!(got[0], 200);
        assert_eq!(got[10], 20);
    }

    /// RUB-169: reorg requeue path admits transactions through the
    /// source-aware admission entry, recording `TxSource::Reorg` on the
    /// resulting `TxPoolEntry`. Mirrors Go `Mempool.AddReorgTx` →
    /// `addTxWithSource(_, mempoolTxSourceReorg)` behavior.
    ///
    /// Coverage axes (LAYER 4.4d test sufficiency):
    ///   - Reachability: builds a real reorg scenario where the heavier
    ///     branch wins, the disconnected canonical block contains a tx,
    ///     and `TxPoolCleanupPlan::apply` runs the requeue loop with
    ///     `block_store` Some.
    ///   - Mutation distinguishing: asserts the requeued entry's
    ///     `source` is `TxSource::Reorg` via `entry_source`. A parallel
    ///     control admission of the same tx via legacy `pool.admit()`
    ///     records `TxSource::Local`. A regression that wired `Local`
    ///     in `sync_reorg.rs` would yield matching sources between the
    ///     two pools and FAIL this assertion.
    ///   - Cleanup-only paths source-neutrality: separately verified by
    ///     the existing `apply_block_with_reorg_tip_extension_removes_conflicting_pool_spends`
    ///     test which exercises `evict_txids` / `remove_conflicting_outpoints`
    ///     and asserts the pool is empty (no source counter mutated).
    #[test]
    fn reorg_requeue_records_reorg_source_provenance() {
        use crate::txpool::TxSource;

        let (mut engine, dir) = engine_with_store("rubin-reorg-source-provenance");
        let (genesis, genesis_hash, gen_ts) = genesis_info();
        engine
            .apply_block_with_reorg(&genesis, None)
            .expect("genesis");
        engine.cfg.chain_id = devnet_genesis_chain_id();

        let (state, admitted_raw, _block_raw) = signed_conflicting_p2pk_state_and_txs(7700, 10, 9);
        engine.chain_state.utxos = state.utxos.clone();

        let block1 = block_with_txs(
            1,
            0,
            genesis_hash,
            gen_ts + 1,
            std::slice::from_ref(&admitted_raw),
        );
        engine
            .apply_block_with_reorg(&block1, None)
            .expect("apply block 1");
        let block1_hash =
            rubin_consensus::block_hash(&block1[..rubin_consensus::BLOCK_HEADER_BYTES])
                .expect("hash block 1");

        // Heavier alt branch: 2 blocks of work vs 1 → triggers reorg,
        // disconnects block1, requeues admitted tx via cleanup.apply.
        let block1_alt = coinbase_only_block(1, genesis_hash, gen_ts + 2);
        let block1_alt_hash =
            rubin_consensus::block_hash(&block1_alt[..rubin_consensus::BLOCK_HEADER_BYTES])
                .expect("hash block 1'");
        engine
            .block_store
            .as_ref()
            .unwrap()
            .store_block(
                block1_alt_hash,
                &block1_alt[..rubin_consensus::BLOCK_HEADER_BYTES],
                &block1_alt,
            )
            .expect("store block 1'");
        let subsidy1 = rubin_consensus::subsidy::block_subsidy(1, 0);
        let block2_alt = coinbase_only_block_with_gen(2, subsidy1, block1_alt_hash, gen_ts + 3);

        let mut pool = TxPool::new();
        let outcome = engine
            .apply_block_with_reorg(&block2_alt, None)
            .expect("reorg to heavier branch");
        let report = outcome.tx_pool_cleanup.apply_with_report(
            &mut pool,
            &engine.chain_state,
            engine.block_store.as_ref(),
            engine.cfg.chain_id,
        );
        assert_eq!(report.requeue_attempted, 1);
        assert_eq!(report.requeue_accepted, 1);
        assert_eq!(report.requeue_failed(), 0);
        assert_eq!(report.requeue_blocks_failed(), 0);
        assert_ne!(
            engine.chain_state.tip_hash, block1_hash,
            "reorg must switch tip away from block 1"
        );

        let (_, requeued_txid, _, consumed) =
            rubin_consensus::parse_tx(&admitted_raw).expect("parse admitted");
        assert_eq!(consumed, admitted_raw.len());
        assert!(
            pool.all_txids().contains(&requeued_txid),
            "requeued txid must be in pool after reorg"
        );

        // Load-bearing mutation-distinguishing assertion: source must
        // be Reorg, not Local. A regression that wired
        // `add_tx_with_source(_, TxSource::Local)` in sync_reorg would
        // FAIL this assertion.
        assert_eq!(
            pool.entry_source(&requeued_txid),
            Some(TxSource::Reorg),
            "reorg requeue must record TxSource::Reorg, not Local or any other variant"
        );

        // Control: legacy admit() of the SAME tx records Local — proves
        // the source field is observably DIFFERENT between the two
        // admission entries (so the Reorg assertion above is meaningful,
        // not trivially satisfied).
        let (mut engine2, dir2) = engine_with_store("rubin-reorg-source-control");
        engine2
            .apply_block_with_reorg(&genesis, None)
            .expect("genesis ctrl");
        engine2.cfg.chain_id = devnet_genesis_chain_id();
        engine2.chain_state.utxos = state.utxos.clone();
        let mut pool_ctrl = TxPool::new();
        pool_ctrl
            .admit(
                &admitted_raw,
                &engine2.chain_state,
                engine2.block_store.as_ref(),
                engine2.cfg.chain_id,
            )
            .expect("legacy admit ctrl");
        assert_eq!(
            pool_ctrl.entry_source(&requeued_txid),
            Some(TxSource::Local),
            "legacy admit() must record Local source (control)"
        );

        std::fs::remove_dir_all(&dir).expect("cleanup primary");
        std::fs::remove_dir_all(&dir2).expect("cleanup ctrl");
    }

    #[test]
    fn reorg_requeue_below_fee_floor_is_reported_without_pool_mutation() {
        let (mut engine, dir) = engine_with_store("rubin-reorg-requeue-below-fee-floor");
        let (genesis, genesis_hash, gen_ts) = genesis_info();
        engine
            .apply_block_with_reorg(&genesis, None)
            .expect("genesis");
        engine.cfg.chain_id = devnet_genesis_chain_id();

        let (state, low_fee_raw, _block_raw) = signed_conflicting_p2pk_state_and_txs(20, 10, 9);
        engine.chain_state.utxos = state.utxos.clone();
        let block1 = block_with_txs(
            1,
            0,
            genesis_hash,
            gen_ts + 1,
            std::slice::from_ref(&low_fee_raw),
        );
        engine
            .apply_block_with_reorg(&block1, None)
            .expect("apply block 1");

        let block1_alt = coinbase_only_block(1, genesis_hash, gen_ts + 2);
        let block1_alt_hash =
            rubin_consensus::block_hash(&block1_alt[..rubin_consensus::BLOCK_HEADER_BYTES])
                .expect("hash block 1'");
        engine
            .block_store
            .as_ref()
            .unwrap()
            .store_block(
                block1_alt_hash,
                &block1_alt[..rubin_consensus::BLOCK_HEADER_BYTES],
                &block1_alt,
            )
            .expect("store block 1'");
        let subsidy1 = rubin_consensus::subsidy::block_subsidy(1, 0);
        let block2_alt = coinbase_only_block_with_gen(2, subsidy1, block1_alt_hash, gen_ts + 3);

        let mut pool = TxPool::new();
        let outcome = engine
            .apply_block_with_reorg(&block2_alt, None)
            .expect("reorg to heavier branch");
        let report = outcome.tx_pool_cleanup.apply_with_report(
            &mut pool,
            &engine.chain_state,
            engine.block_store.as_ref(),
            engine.cfg.chain_id,
        );

        assert_eq!(report.requeue_attempted, 1);
        assert_eq!(report.requeue_accepted, 0);
        assert_eq!(report.requeue_unavailable, 1);
        assert_eq!(report.requeue_failed(), 1);
        assert_eq!(report.requeue_blocks_failed(), 0);
        assert!(
            pool.is_empty(),
            "failed below-floor requeue must not insert or index the tx as accepted"
        );
        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn reorg_requeue_duplicate_conflict_is_reported_without_replacing_entry() {
        let (mut engine, dir) = engine_with_store("rubin-reorg-requeue-duplicate-conflict");
        let (genesis, genesis_hash, gen_ts) = genesis_info();
        engine
            .apply_block_with_reorg(&genesis, None)
            .expect("genesis");
        engine.cfg.chain_id = devnet_genesis_chain_id();

        let (state, admitted_raw, _block_raw) = signed_conflicting_p2pk_state_and_txs(7700, 10, 9);
        engine.chain_state.utxos = state.utxos.clone();
        let block1 = block_with_txs(
            1,
            0,
            genesis_hash,
            gen_ts + 1,
            std::slice::from_ref(&admitted_raw),
        );
        engine
            .apply_block_with_reorg(&block1, None)
            .expect("apply block 1");

        let block1_alt = coinbase_only_block(1, genesis_hash, gen_ts + 2);
        let block1_alt_hash =
            rubin_consensus::block_hash(&block1_alt[..rubin_consensus::BLOCK_HEADER_BYTES])
                .expect("hash block 1'");
        engine
            .block_store
            .as_ref()
            .unwrap()
            .store_block(
                block1_alt_hash,
                &block1_alt[..rubin_consensus::BLOCK_HEADER_BYTES],
                &block1_alt,
            )
            .expect("store block 1'");
        let subsidy1 = rubin_consensus::subsidy::block_subsidy(1, 0);
        let block2_alt = coinbase_only_block_with_gen(2, subsidy1, block1_alt_hash, gen_ts + 3);

        let outcome = engine
            .apply_block_with_reorg(&block2_alt, None)
            .expect("reorg to heavier branch");
        let (_, requeued_txid, _, consumed) =
            rubin_consensus::parse_tx(&admitted_raw).expect("parse admitted");
        assert_eq!(consumed, admitted_raw.len());

        let mut pool = TxPool::new();
        pool.admit(
            &admitted_raw,
            &engine.chain_state,
            engine.block_store.as_ref(),
            engine.cfg.chain_id,
        )
        .expect("preload duplicate");
        assert_eq!(pool.entry_source(&requeued_txid), Some(TxSource::Local));

        let report = outcome.tx_pool_cleanup.apply_with_report(
            &mut pool,
            &engine.chain_state,
            engine.block_store.as_ref(),
            engine.cfg.chain_id,
        );

        assert_eq!(report.requeue_attempted, 1);
        assert_eq!(report.requeue_accepted, 0);
        assert_eq!(report.requeue_conflict, 1);
        assert_eq!(report.requeue_failed(), 1);
        assert_eq!(pool.len(), 1);
        assert_eq!(
            pool.entry_source(&requeued_txid),
            Some(TxSource::Local),
            "duplicate failed requeue must not replace the existing Local entry as Reorg"
        );
        std::fs::remove_dir_all(&dir).expect("cleanup");
    }
}
