use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap, HashSet};

use rubin_consensus::{
    apply_non_coinbase_tx_basic_update_with_mtp_and_core_ext_profiles_and_suite_context,
    parse_block_header_bytes, parse_core_ext_covenant_data, parse_tx, tx_weight_and_stats_public,
    CoreExtDeploymentProfiles, Outpoint, RotationProvider, SuiteRegistry,
};

use crate::sync::SuiteContext;
use crate::{BlockStore, ChainState};

const MAX_TX_POOL_TRANSACTIONS: usize = 300;

/// Default rolling mempool minimum fee rate used by callers without a live
/// rolling-floor source. Mirrors Go's `DefaultMempoolMinFeeRate` so the Rust
/// DA Stage C predicate enforces the same baseline relay floor when no live
/// mempool state is available; this is the documented Go pattern, not a
/// parallel rolling-floor invention. Live rolling-floor wiring is tracked
/// separately as the Rust standard mempool policy task.
pub const DEFAULT_MEMPOOL_MIN_FEE_RATE: u64 = 1;

/// Default spec-side DA per-byte floor used when a caller does not override
/// `policy_min_da_fee_rate`. Mirrors Go's `DefaultMinDaFeeRate`
/// (`POLICY_MEMPOOL_ADMISSION_GENESIS.md` Stage C `min_da_fee_rate`). Kept
/// as a separate constant from `DEFAULT_MEMPOOL_MIN_FEE_RATE` so a future
/// change to the relay floor cannot silently change the DA floor.
pub const DEFAULT_MIN_DA_FEE_RATE: u64 = 1;

#[derive(Debug, Clone)]
pub struct TxPoolConfig {
    pub policy_da_surcharge_per_byte: u64,
    pub policy_reject_non_coinbase_anchor_outputs: bool,
    pub policy_reject_core_ext_pre_activation: bool,
    pub policy_max_ext_payload_bytes: usize,
    pub core_ext_deployments: CoreExtDeploymentProfiles,
    pub suite_context: Option<SuiteContext>,
    /// Rolling local mempool floor used by the Stage C relay-fee term.
    /// Defaults to `DEFAULT_MEMPOOL_MIN_FEE_RATE`; a live rolling floor
    /// source is wired in when the Rust standard mempool policy ships.
    pub policy_current_mempool_min_fee_rate: u64,
    /// Spec-side DA per-byte floor (`POLICY_MEMPOOL_ADMISSION_GENESIS.md`
    /// Stage C `min_da_fee_rate`). Defaults to `DEFAULT_MIN_DA_FEE_RATE`,
    /// kept separate from `DEFAULT_MEMPOOL_MIN_FEE_RATE` so a future
    /// change to the relay floor cannot silently change the DA floor.
    /// Zero disables only the `da_fee_floor` term; the surcharge term is
    /// governed independently by `policy_da_surcharge_per_byte`.
    pub policy_min_da_fee_rate: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxPoolEntry {
    pub raw: Vec<u8>,
    pub inputs: Vec<Outpoint>,
    pub fee: u64,
    pub weight: u64,
    pub size: usize,
}

#[derive(Debug, Clone)]
pub struct TxPool {
    cfg: TxPoolConfig,
    txs: HashMap<[u8; 32], TxPoolEntry>,
    spenders: HashMap<Outpoint, [u8; 32]>,
    worst_heap: BinaryHeap<WorstEntryKey>,
    heap_seqs: HashMap<[u8; 32], u64>,
    next_heap_id: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct WorstEntryKey {
    txid: [u8; 32],
    fee: u64,
    weight: u64,
    heap_id: u64,
}

struct AdmitPriority<'a> {
    fee: u64,
    weight: u64,
    tie: &'a [u8],
}

impl Ord for WorstEntryKey {
    fn cmp(&self, other: &Self) -> Ordering {
        compare_priority_values(
            AdmitPriority {
                fee: other.fee,
                weight: other.weight,
                tie: &other.txid,
            },
            AdmitPriority {
                fee: self.fee,
                weight: self.weight,
                tie: &self.txid,
            },
        )
    }
}

impl PartialOrd for WorstEntryKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxPoolAdmitErrorKind {
    Conflict,
    Rejected,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxPoolAdmitError {
    pub kind: TxPoolAdmitErrorKind,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayTxMetadata {
    pub fee: u64,
    pub size: usize,
}

impl std::fmt::Display for TxPoolAdmitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for TxPoolAdmitError {}

impl TxPool {
    pub fn new() -> Self {
        Self::new_with_config(TxPoolConfig::default())
    }

    pub fn new_with_config(cfg: TxPoolConfig) -> Self {
        Self {
            cfg,
            txs: HashMap::new(),
            spenders: HashMap::new(),
            worst_heap: BinaryHeap::new(),
            heap_seqs: HashMap::new(),
            next_heap_id: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.txs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.txs.is_empty()
    }

    /// Returns the txids of every transaction currently in the pool.
    /// The ordering of the returned vector is not guaranteed to be stable
    /// between calls; callers that require a deterministic order must sort.
    pub fn all_txids(&self) -> Vec<[u8; 32]> {
        self.txs.keys().copied().collect()
    }

    /// Returns a defensive clone of the raw transaction bytes for a pool entry
    /// with the given txid. Returns `None` if no matching entry is present.
    pub fn tx_by_id(&self, txid: &[u8; 32]) -> Option<Vec<u8>> {
        self.txs.get(txid).map(|entry| entry.raw.clone())
    }

    /// Inject a raw entry for testing without full transaction validation.
    #[cfg(test)]
    pub fn inject_test_entry(&mut self, txid: [u8; 32], raw: Vec<u8>) {
        let size = raw.len();
        self.insert_entry(
            txid,
            TxPoolEntry {
                raw,
                inputs: Vec::new(),
                fee: 0,
                weight: size as u64,
                size,
            },
        );
    }

    /// Reports whether a transaction with the given txid is currently present
    /// in the pool.
    pub fn contains(&self, txid: &[u8; 32]) -> bool {
        self.txs.contains_key(txid)
    }

    pub fn select_transactions(&self, max_count: usize, max_bytes: usize) -> Vec<Vec<u8>> {
        if max_count == 0 || max_bytes == 0 {
            return Vec::new();
        }

        let mut entries: Vec<(&[u8; 32], &TxPoolEntry)> = self.txs.iter().collect();
        entries.sort_by(compare_entries_for_mining);

        let mut selected = Vec::with_capacity(entries.len().min(max_count));
        let mut used_bytes = 0usize;
        for entry in entries {
            if selected.len() >= max_count {
                break;
            }
            if entry.1.size > max_bytes.saturating_sub(used_bytes) {
                continue;
            }
            selected.push(entry.1.raw.clone());
            used_bytes += entry.1.size;
        }
        selected
    }

    pub fn admit(
        &mut self,
        tx_bytes: &[u8],
        chain_state: &ChainState,
        block_store: Option<&BlockStore>,
        chain_id: [u8; 32],
    ) -> Result<[u8; 32], TxPoolAdmitError> {
        self.admit_with_metadata(tx_bytes, chain_state, block_store, chain_id)
            .map(|(txid, _)| txid)
    }

    pub fn admit_with_metadata(
        &mut self,
        tx_bytes: &[u8],
        chain_state: &ChainState,
        block_store: Option<&BlockStore>,
        chain_id: [u8; 32],
    ) -> Result<([u8; 32], RelayTxMetadata), TxPoolAdmitError> {
        let (tx, txid, _wtxid, consumed) =
            parse_tx(tx_bytes).map_err(|err| rejected(format!("transaction rejected: {err}")))?;
        if consumed != tx_bytes.len() {
            return Err(rejected("transaction rejected: non-canonical tx bytes"));
        }
        if self.txs.contains_key(&txid) {
            return Err(conflict("tx already in mempool"));
        }

        let inputs: Vec<Outpoint> = tx
            .inputs
            .iter()
            .map(|input| Outpoint {
                txid: input.prev_txid,
                vout: input.prev_vout,
            })
            .collect();
        for input in &inputs {
            if let Some(existing) = self.spenders.get(input) {
                return Err(conflict(format!(
                    "mempool double-spend conflict with {}",
                    hex::encode(existing)
                )));
            }
        }

        let (weight, _, _) = tx_weight_and_stats_public(&tx)
            .map_err(|err| rejected(format!("transaction rejected: {err}")))?;

        let next_height = next_block_height(chain_state)?;
        let block_mtp = next_block_mtp(block_store, next_height)?;
        let active_profiles = self
            .cfg
            .core_ext_deployments
            .active_profiles_at_height(next_height)
            .map_err(|err| rejected(format!("transaction rejected: {err}")))?;
        let (rotation, registry): (Option<&dyn RotationProvider>, Option<&SuiteRegistry>) =
            match self.cfg.suite_context.as_ref() {
                Some(ctx) => (Some(ctx.rotation.as_ref()), Some(ctx.registry.as_ref())),
                None => (None, None),
            };
        let (_, summary) =
            apply_non_coinbase_tx_basic_update_with_mtp_and_core_ext_profiles_and_suite_context(
                &tx,
                txid,
                &chain_state.utxos,
                next_height,
                block_mtp,
                block_mtp,
                chain_id,
                &active_profiles,
                rotation,
                registry,
            )
            .map_err(|err| rejected(format!("transaction rejected: {err}")))?;
        // RUB-162 PR-1410 wave-3 drift-prevention: delegate the
        // post-consensus policy sequence (cfg-clone with cfg-zero
        // override → apply_policy → rolling-floor enforcement) to the
        // shared `apply_post_consensus_policy_with_floor` helper so
        // both `admit_with_metadata` and `relay_metadata` cannot drift
        // again (Copilot PR-1410 wave-2 Thread 4 finding). The miner
        // caller (`reject_candidate`) keeps its own policy_cfg
        // construction because it has no rolling-floor equivalent —
        // the template needs to skip a tx whenever it fails any floor
        // (Go `applyPolicyAgainstState` mempool.go:815-818).
        apply_post_consensus_policy_with_floor(
            &tx,
            &chain_state.utxos,
            next_height,
            summary.fee,
            weight,
            &self.cfg,
        )?;

        let entry = TxPoolEntry {
            raw: tx_bytes.to_vec(),
            inputs: inputs.clone(),
            fee: summary.fee,
            weight,
            size: tx_bytes.len(),
        };

        // Go-parity capacity admission (`capacityEvictionPlanLocked`,
        // clients/go/node/mempool.go:1024-1030) — runs AFTER both
        // `apply_policy` and the rolling relay-fee floor check above, so
        // sub-floor / DA-rejected transactions never reach this branch
        // and the worst-entry comparison only considers floor-compliant
        // candidates. The three distinct rejection causes are split
        // into separate error messages so callers/operators can
        // distinguish legitimate eviction-ordering rejection from
        // internal heap invariant violation:
        //   1.  `current_worst_txid()` returns a txid that does NOT
        //       resolve to a live `txs` entry → MAP-vs-HEAP corruption
        //       invariant: heap pointed at a stale txid the map no
        //       longer has. Surfaced as
        //       `"tx pool capacity invariant violated: worst_heap entry missing from txs map"`.
        //   2.  `compare_admit_priority` reports candidate is NOT
        //       strictly greater than worst → routine eviction-ordering
        //       rejection matching Go's
        //       `"mempool capacity candidate rejected by eviction ordering"`
        //       at clients/go/node/mempool.go:1028-1030 verbatim.
        //
        // The historical `current_worst_txid()` returns None production
        // error branch has been removed: it was unreachable by
        // construction in this caller. `current_worst_txid()` always
        // invokes `seed_worst_heap()`, which rebuilds `worst_heap` from
        // `self.txs` whenever the heap is empty or out of sync; we only
        // enter this block when `self.txs.len() >= MAX_TX_POOL_TRANSACTIONS > 0`.
        // After the rebuild every heap entry pairs with a fresh
        // `heap_seqs` entry, so the peek/pop loop inside
        // `current_worst_txid()` cannot exhaust the heap to None. The
        // `expect()` below documents that internal invariant; a panic
        // here would indicate a regression in `seed_worst_heap()`
        // itself.
        if self.txs.len() >= MAX_TX_POOL_TRANSACTIONS {
            let worst_txid = self.current_worst_txid().expect(
                "current_worst_txid is None only when self.txs is empty; \
                 this branch is gated on self.txs.len() >= MAX_TX_POOL_TRANSACTIONS \
                 and seed_worst_heap rebuilds worst_heap from non-empty txs",
            );
            let Some(worst_entry) = self.txs.get(&worst_txid) else {
                return Err(unavailable(
                    "tx pool capacity invariant violated: worst_heap entry missing from txs map",
                ));
            };
            if compare_admit_priority(txid, &entry, worst_txid, worst_entry) != Ordering::Greater {
                return Err(unavailable(
                    "mempool capacity candidate rejected by eviction ordering",
                ));
            }
            self.remove_entry(&worst_txid);
        }

        self.insert_entry(txid, entry);
        Ok((
            txid,
            RelayTxMetadata {
                fee: summary.fee,
                size: tx_bytes.len(),
            },
        ))
    }

    pub fn relay_metadata_for_bytes(
        &self,
        tx_bytes: &[u8],
        chain_state: &ChainState,
        block_store: Option<&BlockStore>,
        chain_id: [u8; 32],
    ) -> Result<RelayTxMetadata, TxPoolAdmitError> {
        relay_metadata(tx_bytes, chain_state, block_store, chain_id, &self.cfg)
    }

    /// Remove transactions by txid (e.g. after block confirmation).
    /// Cleans up the spender index for any removed entries.
    pub fn evict_txids(&mut self, txids: &[[u8; 32]]) {
        for txid in txids {
            self.remove_entry(txid);
        }
    }

    pub fn remove_conflicting_inputs(&mut self, txs: &[rubin_consensus::Tx]) {
        let mut outpoints = Vec::new();
        for tx in txs {
            outpoints.extend(tx.inputs.iter().map(|input| Outpoint {
                txid: input.prev_txid,
                vout: input.prev_vout,
            }));
        }
        self.remove_conflicting_outpoints(&outpoints);
    }

    pub fn remove_conflicting_outpoints(&mut self, outpoints: &[Outpoint]) {
        let mut conflicting = HashSet::new();
        for outpoint in outpoints {
            if let Some(txid) = self.spenders.get(outpoint) {
                conflicting.insert(*txid);
            }
        }
        if conflicting.is_empty() {
            return;
        }
        let txids: Vec<[u8; 32]> = conflicting.into_iter().collect();
        self.evict_txids(&txids);
    }

    fn insert_entry(&mut self, txid: [u8; 32], entry: TxPoolEntry) {
        self.next_heap_id = self.next_heap_id.saturating_add(1);
        let heap_id = self.next_heap_id;
        for input in &entry.inputs {
            self.spenders.insert(input.clone(), txid);
        }
        self.heap_seqs.insert(txid, heap_id);
        self.worst_heap.push(WorstEntryKey {
            txid,
            fee: entry.fee,
            weight: entry.weight,
            heap_id,
        });
        self.txs.insert(txid, entry);
    }

    fn remove_entry(&mut self, txid: &[u8; 32]) {
        if let Some(entry) = self.txs.remove(txid) {
            self.heap_seqs.remove(txid);
            for input in &entry.inputs {
                self.spenders.remove(input);
            }
        }
        self.compact_worst_heap_if_needed();
    }

    // PR-1410 wave-3 — the historical TxPool impl-method that performed
    // the rolling-floor check (the `_locked` suffix referred to its
    // TxPool-state lock convenience) was removed. After the wave-3
    // drift-prevention helper extraction (`apply_post_consensus_policy_with_floor`),
    // both `admit_with_metadata` and `relay_metadata` go through that
    // helper, and the free `validate_fee_floor` predicate is the single
    // source-of-truth call. The historical `_locked` suffix no longer
    // carries meaning — the predicate is stateless on the cfg field.
    // Tests call the free `validate_fee_floor` directly.

    fn seed_worst_heap(&mut self) {
        let max_stale_tail = self.txs.len().saturating_add(1);
        if self.heap_seqs.len() == self.txs.len()
            && (self.txs.is_empty() || !self.worst_heap.is_empty())
            && self.worst_heap.len() <= max_stale_tail
        {
            return;
        }
        self.rebuild_worst_heap();
    }

    fn current_worst_txid(&mut self) -> Option<[u8; 32]> {
        self.seed_worst_heap();
        loop {
            let head = self.worst_heap.peek()?;
            match self.heap_seqs.get(&head.txid) {
                Some(heap_id) if *heap_id == head.heap_id => return Some(head.txid),
                _ => {
                    self.worst_heap.pop();
                }
            }
        }
    }

    fn compact_worst_heap_if_needed(&mut self) {
        let live = self.txs.len();
        let threshold = live.saturating_mul(2);
        if self.worst_heap.len() > threshold {
            self.rebuild_worst_heap();
        }
    }

    fn rebuild_worst_heap(&mut self) {
        let mut rebuilt = BinaryHeap::with_capacity(self.txs.len());
        self.heap_seqs.clear();
        for (txid, entry) in &self.txs {
            self.next_heap_id = self.next_heap_id.saturating_add(1);
            let heap_id = self.next_heap_id;
            self.heap_seqs.insert(*txid, heap_id);
            rebuilt.push(WorstEntryKey {
                txid: *txid,
                fee: entry.fee,
                weight: entry.weight,
                heap_id,
            });
        }
        self.worst_heap = rebuilt;
    }
}

pub(crate) fn relay_metadata(
    tx_bytes: &[u8],
    chain_state: &ChainState,
    block_store: Option<&BlockStore>,
    chain_id: [u8; 32],
    cfg: &TxPoolConfig,
) -> Result<RelayTxMetadata, TxPoolAdmitError> {
    let (tx, txid, _wtxid, consumed) =
        parse_tx(tx_bytes).map_err(|err| rejected(format!("transaction rejected: {err}")))?;
    if consumed != tx_bytes.len() {
        return Err(rejected("transaction rejected: non-canonical tx bytes"));
    }

    let next_height = next_block_height(chain_state)?;
    let block_mtp = next_block_mtp(block_store, next_height)?;
    let active_profiles = cfg
        .core_ext_deployments
        .active_profiles_at_height(next_height)
        .map_err(|err| rejected(format!("transaction rejected: {err}")))?;
    let (rotation, registry): (Option<&dyn RotationProvider>, Option<&SuiteRegistry>) =
        match cfg.suite_context.as_ref() {
            Some(ctx) => (Some(ctx.rotation.as_ref()), Some(ctx.registry.as_ref())),
            None => (None, None),
        };
    let (_, summary) =
        apply_non_coinbase_tx_basic_update_with_mtp_and_core_ext_profiles_and_suite_context(
            &tx,
            txid,
            &chain_state.utxos,
            next_height,
            block_mtp,
            block_mtp,
            chain_id,
            &active_profiles,
            rotation,
            registry,
        )
        .map_err(|err| rejected(format!("transaction rejected: {err}")))?;
    // RUB-162 PR-1410 wave-3 drift-prevention: delegate the
    // post-consensus policy sequence (cfg-clone with cfg-zero override
    // → apply_policy → rolling-floor enforcement) to the shared
    // `apply_post_consensus_policy_with_floor` helper so the relay path
    // and the admit path (`admit_with_metadata`) cannot drift again.
    // Wave-2 already fixed one drift instance (relay_metadata had
    // skipped the rolling-floor check entirely while admit enforced it
    // via `validate_fee_floor`); the shared helper makes that
    // class of drift impossible by construction.
    let (weight, _, _) = tx_weight_and_stats_public(&tx)
        .map_err(|err| rejected(format!("transaction rejected: {err}")))?;
    apply_post_consensus_policy_with_floor(
        &tx,
        &chain_state.utxos,
        next_height,
        summary.fee,
        weight,
        cfg,
    )?;

    Ok(RelayTxMetadata {
        fee: summary.fee,
        size: tx_bytes.len(),
    })
}

/// Shared post-consensus policy sequence used by both
/// `TxPool::admit_with_metadata` (admit gate) and `relay_metadata`
/// (relay gate). Mirrors Go's `applyPolicyAgainstState` plus
/// `validateFeeFloorLocked` pair (clients/go/node/mempool.go:798-833
/// and mempool.go:957-967). Centralising the cfg-clone, cfg-zero
/// override, `apply_policy` invocation and rolling-floor enforcement
/// in one private helper prevents the public-gate-drift class that
/// PR #1410 wave-2 fixed once already (relay_metadata had skipped the
/// floor check while admit enforced it).
///
/// Order is mandatory and must NOT be changed without updating the
/// matching Go reference: apply_policy(cfg-zero) runs first to
/// classify DA-side rejections as Rejected (terminal), then
/// validate_fee_floor with the original cfg's
/// `policy_current_mempool_min_fee_rate` runs to classify rolling-
/// relay-floor rejections as Unavailable (transient/retryable). Both
/// public callers must use the same predicate so peer relay
/// (`tx_relay::handle_received_tx`, which gates on `relay_metadata`)
/// never propagates a tx that local `admit` would reject.
///
/// Caller responsibilities (kept out of this helper to preserve
/// existing call-site semantics):
///   - parse_tx + canonical bytes check + apply_non_coinbase_tx_basic_update
///     must complete BEFORE this helper (signature verification +
///     consensus state validation are upstream).
///   - `fee` and `weight` are extracted by the caller (admit reads
///     them at the start of the function; relay extracts weight
///     between apply_non_coinbase and this helper).
///   - The miner caller (`reject_candidate`) deliberately does NOT
///     use this helper; miner has its own policy_cfg construction
///     because it has no rolling-floor equivalent (Go
///     `applyPolicyAgainstState` mempool.go:815-818 documents this
///     same exception).
fn apply_post_consensus_policy_with_floor(
    tx: &rubin_consensus::Tx,
    utxos: &HashMap<Outpoint, rubin_consensus::UtxoEntry>,
    next_height: u64,
    fee: u64,
    weight: u64,
    cfg: &TxPoolConfig,
) -> Result<(), TxPoolAdmitError> {
    let mut policy_cfg = cfg.clone();
    policy_cfg.policy_current_mempool_min_fee_rate = 0;
    apply_policy(tx, utxos, next_height, &policy_cfg).map_err(rejected)?;
    validate_fee_floor(fee, weight, cfg.policy_current_mempool_min_fee_rate)
}

impl Default for TxPool {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for TxPoolConfig {
    fn default() -> Self {
        Self {
            policy_da_surcharge_per_byte: 0,
            policy_reject_non_coinbase_anchor_outputs: true,
            policy_reject_core_ext_pre_activation: true,
            policy_max_ext_payload_bytes: 0,
            core_ext_deployments: CoreExtDeploymentProfiles::empty(),
            suite_context: None,
            policy_current_mempool_min_fee_rate: DEFAULT_MEMPOOL_MIN_FEE_RATE,
            policy_min_da_fee_rate: DEFAULT_MIN_DA_FEE_RATE,
        }
    }
}

fn next_block_height(chain_state: &ChainState) -> Result<u64, TxPoolAdmitError> {
    if !chain_state.has_tip {
        return Ok(0);
    }
    if chain_state.height == u64::MAX {
        return Err(unavailable("height overflow"));
    }
    Ok(chain_state.height + 1)
}

fn next_block_mtp(
    block_store: Option<&BlockStore>,
    next_height: u64,
) -> Result<u64, TxPoolAdmitError> {
    let Some(block_store) = block_store else {
        return Ok(0);
    };
    if next_height == 0 {
        return Ok(0);
    }
    let mut window_len = 11u64;
    if next_height < window_len {
        window_len = next_height;
    }
    let mut out = Vec::with_capacity(window_len as usize);
    for idx in 0..window_len {
        let height = next_height - 1 - idx;
        let Some(hash) = block_store
            .canonical_hash(height)
            .map_err(|err| unavailable(err.to_string()))?
        else {
            return Err(unavailable(
                "missing canonical header for timestamp context",
            ));
        };
        let header_bytes = block_store
            .get_header_by_hash(hash)
            .map_err(|err| unavailable(err.to_string()))?;
        let header =
            parse_block_header_bytes(&header_bytes).map_err(|err| unavailable(err.to_string()))?;
        out.push(header.timestamp);
    }
    Ok(mtp_median(next_height, &out))
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

fn conflict(message: impl Into<String>) -> TxPoolAdmitError {
    TxPoolAdmitError {
        kind: TxPoolAdmitErrorKind::Conflict,
        message: message.into(),
    }
}

fn rejected(message: impl Into<String>) -> TxPoolAdmitError {
    TxPoolAdmitError {
        kind: TxPoolAdmitErrorKind::Rejected,
        message: message.into(),
    }
}

fn unavailable(message: impl Into<String>) -> TxPoolAdmitError {
    TxPoolAdmitError {
        kind: TxPoolAdmitErrorKind::Unavailable,
        message: message.into(),
    }
}

/// Returns true if `fee` is below the rolling fee floor for `weight`.
/// Mirrors Go `feeRateBelowFloor` (clients/go/node/mempool.go:1421-1434)
/// using full-precision u128 cross-multiplication (`fee < weight * floor`).
/// u128 holds any `u64 * u64` product losslessly, so the comparison is
/// well-defined at every input including `weight == u64::MAX` and
/// `floor == u64::MAX`.
///
/// Zero weight returns true: `validateFeeFloorLocked` callers treat
/// `weight == 0` as an uncomputable rate ("treat as below floor"),
/// matching Go's documented branch.
///
/// Floor argument is clamped up to `DEFAULT_MEMPOOL_MIN_FEE_RATE` if
/// smaller, mirroring Go `feeRateBelowFloor`'s in-helper clamp at
/// clients/go/node/mempool.go:1425-1427. Callers therefore always
/// receive at-least-DEFAULT enforcement even if cfg-static or
/// rolling-floor sources zero the field.
fn fee_rate_below_floor(fee: u64, weight: u64, floor: u64) -> bool {
    if weight == 0 {
        return true;
    }
    let floor = floor.max(DEFAULT_MEMPOOL_MIN_FEE_RATE);
    let required = (weight as u128) * (floor as u128);
    (fee as u128) < required
}

/// Free-function predicate enforcing the rolling-relay-floor invariant
/// shared by `admit_with_metadata` and `relay_metadata` via
/// `apply_post_consensus_policy_with_floor` so both paths use one
/// source-of-truth check. Returns `Unavailable` (transient / retryable)
/// on rolling-floor failure, mirroring Go `validateFeeFloorLocked` at
/// clients/go/node/mempool.go:957-967. The `DEFAULT_MEMPOOL_MIN_FEE_RATE`
/// clamp lives inside `fee_rate_below_floor` (Go-parity at
/// clients/go/node/mempool.go:1425-1427); the error message surfaces
/// the post-clamp value for operator clarity.
fn validate_fee_floor(fee: u64, weight: u64, cfg_floor: u64) -> Result<(), TxPoolAdmitError> {
    if fee_rate_below_floor(fee, weight, cfg_floor) {
        let surfaced_floor = cfg_floor.max(DEFAULT_MEMPOOL_MIN_FEE_RATE);
        return Err(unavailable(format!(
            "mempool fee below rolling minimum: fee={fee} weight={weight} min_fee_rate={surfaced_floor}"
        )));
    }
    Ok(())
}

pub(crate) fn apply_policy(
    tx: &rubin_consensus::Tx,
    utxos: &HashMap<Outpoint, rubin_consensus::UtxoEntry>,
    next_height: u64,
    cfg: &TxPoolConfig,
) -> Result<(), String> {
    if cfg.policy_reject_non_coinbase_anchor_outputs {
        reject_non_coinbase_anchor_outputs(tx)?;
    }
    reject_da_anchor_tx_policy(
        tx,
        utxos,
        cfg.policy_current_mempool_min_fee_rate,
        cfg.policy_min_da_fee_rate,
        cfg.policy_da_surcharge_per_byte,
    )?;
    if cfg.policy_reject_core_ext_pre_activation {
        reject_core_ext_tx_pre_activation(tx, utxos, next_height, &cfg.core_ext_deployments)?;
    }
    if cfg.policy_max_ext_payload_bytes > 0 {
        reject_core_ext_tx_oversized_payload(tx, cfg.policy_max_ext_payload_bytes)?;
    }
    Ok(())
}

/// SHOULD-level mempool policy: reject transactions with CORE_EXT outputs whose
/// ext_payload exceeds the configured maximum. This is relay policy, not consensus.
pub(crate) fn reject_core_ext_tx_oversized_payload(
    tx: &rubin_consensus::Tx,
    max_bytes: usize,
) -> Result<(), String> {
    if max_bytes == 0 {
        return Ok(());
    }
    for (i, output) in tx.outputs.iter().enumerate() {
        if output.covenant_type != rubin_consensus::constants::COV_TYPE_EXT {
            continue;
        }
        let cov = match parse_core_ext_covenant_data(&output.covenant_data) {
            Ok(c) => c,
            Err(_) => continue, // Parse failure handled by consensus validation
        };
        if cov.ext_payload.len() > max_bytes {
            return Err(format!(
                "CORE_EXT output {} ext_payload {} bytes exceeds policy limit {}",
                i,
                cov.ext_payload.len(),
                max_bytes,
            ));
        }
    }
    Ok(())
}

pub(crate) fn reject_non_coinbase_anchor_outputs(tx: &rubin_consensus::Tx) -> Result<(), String> {
    if tx
        .outputs
        .iter()
        .any(|output| output.covenant_type == rubin_consensus::constants::COV_TYPE_ANCHOR)
    {
        return Err("non-coinbase CORE_ANCHOR is non-standard (policy)".to_string());
    }
    Ok(())
}

/// Stage C DA fee policy aligned with Go's `RejectDaAnchorTxPolicy`
/// (`POLICY_MEMPOOL_ADMISSION_GENESIS.md` Stage C):
///
/// ```text
/// fee(tx)             = sum_inputs - sum_outputs
/// relay_fee_floor(tx) = weight(tx) * current_mempool_min_fee_rate
/// da_fee_floor(tx)    = da_payload_len(tx) * min_da_fee_rate
/// da_surcharge(tx)    = da_payload_len(tx) * da_surcharge_per_byte
/// da_required_fee(tx) = da_fee_floor(tx) + da_surcharge(tx)
/// required_fee(tx)    = max(relay_fee_floor(tx), da_required_fee(tx))
/// reject if fee(tx) < required_fee(tx)
/// ```
///
/// Arithmetic is checked widening; any overflow rejects fail-closed as a
/// policy error. The helper does not change consensus validity. For non-DA
/// transactions (`da_payload_len == 0`) the helper short-circuits with
/// `Ok(())` and applies no DA-specific term; relay-fee-floor enforcement
/// for non-DA transactions remains the standard mempool admission path's
/// responsibility.
///
/// Inputs:
/// - `current_mempool_min_fee_rate`: rolling local mempool floor. Callers
///   without a live rolling-floor source pass
///   `DEFAULT_MEMPOOL_MIN_FEE_RATE` (mirrors Go's documented
///   `DefaultMempoolMinFeeRate` pattern, not a parallel floor invention).
/// - `min_da_fee_rate`: spec-side DA per-byte floor (Stage C
///   `min_da_fee_rate`, default `1`).
/// - `da_surcharge_per_byte`: operator-tunable DA per-byte surcharge
///   added on top of the spec-side floor; `0` disables only the
///   surcharge term, not `da_fee_floor`.
///
/// The helper recomputes both `weight` and `da_bytes` from `tx` via
/// `tx_weight_and_stats_public`. This avoids trusting any caller-supplied
/// weight value (a stale or zero weight would otherwise silently
/// under-enforce the relay-fee half of the Stage C predicate).
pub(crate) fn reject_da_anchor_tx_policy(
    tx: &rubin_consensus::Tx,
    utxos: &HashMap<Outpoint, rubin_consensus::UtxoEntry>,
    current_mempool_min_fee_rate: u64,
    min_da_fee_rate: u64,
    da_surcharge_per_byte: u64,
) -> Result<(), String> {
    let (weight, da_bytes, _) =
        tx_weight_and_stats_public(tx).map_err(|err| format!("tx weight/stats error: {err}"))?;
    if da_bytes == 0 {
        // Non-DA transaction: the helper only enforces the DA half of the
        // Stage C admission contract. Non-DA relay-fee floor enforcement
        // is now performed by the free `validate_fee_floor` predicate
        // (defined below), invoked inside
        // `apply_post_consensus_policy_with_floor` which both
        // `TxPool::admit_with_metadata` and `relay_metadata` call AFTER
        // this helper's `apply_policy` returns Ok — mirroring Go's
        // `validateCapacityAdmissionLocked` calling `validateFeeFloorLocked`
        // at clients/go/node/mempool.go:1018-1024. Both `admit_with_metadata`
        // and `relay_metadata` zero-out the rolling floor before invoking
        // this helper so the DA-side classification is preserved without
        // double-charging the relay floor inside the DA helper. The helper
        // deliberately short-circuits here for non-DA transactions and does
        // not compute fee or apply any DA-specific term.
        return Ok(());
    }
    let relay_floor = weight.checked_mul(current_mempool_min_fee_rate).ok_or_else(|| {
        format!(
            "relay fee floor overflow (weight={weight} current_mempool_min_fee_rate={current_mempool_min_fee_rate}): u64 overflow"
        )
    })?;
    let da_floor = da_bytes.checked_mul(min_da_fee_rate).ok_or_else(|| {
        format!(
            "DA fee floor overflow (da_payload_len={da_bytes} min_da_fee_rate={min_da_fee_rate}): u64 overflow"
        )
    })?;
    let da_surcharge = da_bytes.checked_mul(da_surcharge_per_byte).ok_or_else(|| {
        format!(
            "DA surcharge overflow (da_payload_len={da_bytes} surcharge_per_byte={da_surcharge_per_byte}): u64 overflow"
        )
    })?;
    let da_required = da_floor.checked_add(da_surcharge).ok_or_else(|| {
        format!(
            "DA required fee overflow (da_fee_floor={da_floor} da_surcharge={da_surcharge}): u64 overflow"
        )
    })?;
    let required = relay_floor.max(da_required);
    if required == 0 {
        // DA tx but every Stage C rate-derived fee term is zero: the
        // relay-floor term is zero and both DA-side terms are zero.
        // Nothing to enforce; admit without fee compute.
        return Ok(());
    }
    let fee = compute_fee_no_verify(tx, utxos)
        .map_err(|err| format!("cannot compute fee for DA tx (policy): {err}"))?;
    if fee < required {
        return Err(format!(
            "DA fee below Stage C floor (fee={fee} required_fee={required} relay_fee_floor={relay_floor} da_fee_floor={da_floor} da_surcharge={da_surcharge} weight={weight} da_payload_len={da_bytes})"
        ));
    }
    Ok(())
}

pub(crate) fn compute_fee_no_verify(
    tx: &rubin_consensus::Tx,
    utxos: &HashMap<Outpoint, rubin_consensus::UtxoEntry>,
) -> Result<u64, String> {
    if tx.inputs.is_empty() {
        return Err("missing inputs".to_string());
    }
    let mut sum_in = 0u64;
    for input in &tx.inputs {
        let outpoint = Outpoint {
            txid: input.prev_txid,
            vout: input.prev_vout,
        };
        let entry = utxos
            .get(&outpoint)
            .ok_or_else(|| "missing utxo".to_string())?;
        sum_in = sum_in
            .checked_add(entry.value)
            .ok_or_else(|| "sum_in overflow".to_string())?;
    }
    let mut sum_out = 0u64;
    for output in &tx.outputs {
        sum_out = sum_out
            .checked_add(output.value)
            .ok_or_else(|| "sum_out overflow".to_string())?;
    }
    if sum_out > sum_in {
        return Err("overspend".to_string());
    }
    Ok(sum_in - sum_out)
}

pub(crate) fn reject_core_ext_tx_pre_activation(
    tx: &rubin_consensus::Tx,
    utxos: &HashMap<Outpoint, rubin_consensus::UtxoEntry>,
    height: u64,
    deployments: &CoreExtDeploymentProfiles,
) -> Result<(), String> {
    let active = deployments
        .active_profiles_at_height(height)
        .map_err(|err| err.to_string())?;
    for output in &tx.outputs {
        if output.covenant_type != rubin_consensus::constants::COV_TYPE_EXT {
            continue;
        }
        let cov =
            parse_core_ext_covenant_data(&output.covenant_data).map_err(|err| err.to_string())?;
        if !active
            .active
            .iter()
            .any(|profile| profile.ext_id == cov.ext_id)
        {
            return Err(format!("CORE_EXT output pre-ACTIVE ext_id={}", cov.ext_id));
        }
    }
    for input in &tx.inputs {
        let outpoint = Outpoint {
            txid: input.prev_txid,
            vout: input.prev_vout,
        };
        let Some(entry) = utxos.get(&outpoint) else {
            continue;
        };
        if entry.covenant_type != rubin_consensus::constants::COV_TYPE_EXT {
            continue;
        }
        let cov =
            parse_core_ext_covenant_data(&entry.covenant_data).map_err(|err| err.to_string())?;
        if !active
            .active
            .iter()
            .any(|profile| profile.ext_id == cov.ext_id)
        {
            return Err(format!("CORE_EXT spend pre-ACTIVE ext_id={}", cov.ext_id));
        }
    }
    Ok(())
}

fn compare_entries_for_mining(
    a: &(&[u8; 32], &TxPoolEntry),
    b: &(&[u8; 32], &TxPoolEntry),
) -> Ordering {
    let (a_txid, a_entry) = *a;
    let (b_txid, b_entry) = *b;
    match compare_fee_rate(a_entry, b_entry) {
        Ordering::Greater => Ordering::Less,
        Ordering::Less => Ordering::Greater,
        Ordering::Equal => match b_entry.fee.cmp(&a_entry.fee) {
            Ordering::Equal => match a_entry.weight.cmp(&b_entry.weight) {
                // Final tie-break matches Go parity
                // (`clients/go/node/mempool.go`, `sortMempoolEntries`:
                // `bytes.Compare(entries[i].txid[:], entries[j].txid[:])`)
                // and the Rust-internal `compare_priority_values` admit
                // comparator, both of which tie by TXID (lexicographic).
                // Using raw serialized bytes here (prior behavior) caused
                // deterministic ordering to drift between clients on
                // equal-fee/weight/size transaction sets.
                Ordering::Equal => a_txid.cmp(b_txid),
                other => other,
            },
            other => other,
        },
    }
}

fn compare_admit_priority(
    txid_a: [u8; 32],
    a: &TxPoolEntry,
    txid_b: [u8; 32],
    b: &TxPoolEntry,
) -> Ordering {
    compare_priority_values(
        AdmitPriority {
            fee: a.fee,
            weight: a.weight,
            tie: &txid_a,
        },
        AdmitPriority {
            fee: b.fee,
            weight: b.weight,
            tie: &txid_b,
        },
    )
}

fn compare_priority_values(a: AdmitPriority<'_>, b: AdmitPriority<'_>) -> Ordering {
    match compare_fee_rate_values(a.fee, a.weight, b.fee, b.weight) {
        Ordering::Equal => match a.fee.cmp(&b.fee) {
            Ordering::Equal => match b.weight.cmp(&a.weight) {
                Ordering::Equal => b.tie.cmp(a.tie),
                other => other,
            },
            other => other,
        },
        other => other,
    }
}

fn compare_fee_rate(a: &TxPoolEntry, b: &TxPoolEntry) -> Ordering {
    compare_fee_rate_values(a.fee, a.weight, b.fee, b.weight)
}

fn compare_fee_rate_values(fee_a: u64, weight_a: u64, fee_b: u64, weight_b: u64) -> Ordering {
    if weight_a == 0 || weight_b == 0 {
        return Ordering::Equal;
    }
    let left = u128::from(fee_a) * u128::from(weight_b);
    let right = u128::from(fee_b) * u128::from(weight_a);
    left.cmp(&right)
}

#[cfg(test)]
mod tests {
    use std::cmp::Ordering;
    use std::collections::HashMap;
    use std::fs;
    use std::path::PathBuf;

    use rubin_consensus::block::BLOCK_HEADER_BYTES;
    use rubin_consensus::constants::{
        COV_TYPE_ANCHOR, COV_TYPE_EXT, COV_TYPE_P2PK, SUITE_ID_SENTINEL, TX_WIRE_VERSION,
    };
    use rubin_consensus::{
        marshal_tx, p2pk_covenant_data_for_pubkey, parse_tx, sign_transaction,
        tx_weight_and_stats_public, CoreExtDeploymentProfile, CoreExtDeploymentProfiles,
        CoreExtVerificationBinding, DaChunkCore, Mldsa87Keypair, Outpoint, Tx, TxInput, TxOutput,
        UtxoEntry, WitnessItem,
    };

    use super::{
        compare_admit_priority, compare_entries_for_mining, compare_fee_rate, conflict, mtp_median,
        next_block_height, next_block_mtp, reject_core_ext_tx_oversized_payload,
        reject_da_anchor_tx_policy, rejected, relay_metadata, unavailable, TxPool,
        TxPoolAdmitErrorKind, TxPoolConfig, TxPoolEntry, DEFAULT_MEMPOOL_MIN_FEE_RATE,
        MAX_TX_POOL_TRANSACTIONS,
    };
    use crate::{
        block_store_path, default_sync_config, devnet_genesis_block_bytes, devnet_genesis_chain_id,
        test_helpers::signed_conflicting_p2pk_state_and_txs, BlockStore, ChainState, SyncEngine,
    };

    #[derive(serde::Deserialize)]
    struct FixtureFile<T> {
        vectors: Vec<T>,
    }

    #[derive(serde::Deserialize)]
    struct MaturityVector {
        tx_hex: String,
    }

    #[derive(Clone, serde::Deserialize)]
    struct FixtureUtxo {
        txid: String,
        vout: u32,
        value: u64,
        covenant_type: u16,
        covenant_data: String,
        creation_height: u64,
        created_by_coinbase: bool,
    }

    #[derive(Clone, serde::Deserialize)]
    struct PositiveTxVector {
        id: String,
        tx_hex: String,
        #[serde(default)]
        chain_id: Option<String>,
        height: u64,
        expect_ok: bool,
        utxos: Vec<FixtureUtxo>,
    }

    fn unique_temp_dir(prefix: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "{prefix}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time")
                .as_nanos()
        ))
    }

    fn open_block_store(prefix: &str) -> (BlockStore, PathBuf) {
        let dir = unique_temp_dir(prefix);
        fs::create_dir_all(&dir).expect("mkdir");
        let store = BlockStore::open(block_store_path(&dir)).expect("blockstore");
        (store, dir)
    }

    fn genesis_coinbase_bytes() -> Vec<u8> {
        let block = devnet_genesis_block_bytes();
        assert_eq!(
            block[BLOCK_HEADER_BYTES], 0x01,
            "expected single-tx genesis fixture"
        );
        let tx_start = BLOCK_HEADER_BYTES + 1;
        let (_tx, _txid, _wtxid, consumed) = parse_tx(&block[tx_start..]).expect("parse tx");
        block[tx_start..tx_start + consumed].to_vec()
    }

    fn maturity_fixture_tx_bytes() -> Vec<u8> {
        const DEVNET_MATURITY_FIXTURE_JSON: &str = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../../conformance/fixtures/CV-DEVNET-MATURITY.json"
        ));
        let fixture: FixtureFile<MaturityVector> =
            serde_json::from_str(DEVNET_MATURITY_FIXTURE_JSON).expect("parse fixture");
        let vector = fixture.vectors.into_iter().next().expect("fixture vector");
        hex::decode(vector.tx_hex).expect("tx hex")
    }

    fn parse_hex32_test(name: &str, value: &str) -> [u8; 32] {
        let raw = hex::decode(value).unwrap_or_else(|err| panic!("{name} hex: {err}"));
        assert_eq!(raw.len(), 32, "{name} must be 32 bytes");
        let mut out = [0u8; 32];
        out.copy_from_slice(&raw);
        out
    }

    fn fixture_utxos_to_map(items: &[FixtureUtxo]) -> HashMap<Outpoint, UtxoEntry> {
        let mut out = HashMap::with_capacity(items.len());
        for item in items {
            out.insert(
                Outpoint {
                    txid: parse_hex32_test("fixture utxo txid", &item.txid),
                    vout: item.vout,
                },
                UtxoEntry {
                    value: item.value,
                    covenant_type: item.covenant_type,
                    covenant_data: hex::decode(&item.covenant_data)
                        .expect("fixture covenant_data hex"),
                    creation_height: item.creation_height,
                    created_by_coinbase: item.created_by_coinbase,
                },
            );
        }
        out
    }

    fn positive_fixture_vector() -> PositiveTxVector {
        const UTXO_BASIC_FIXTURE_JSON: &str = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../../conformance/fixtures/CV-UTXO-BASIC.json"
        ));
        let fixture: FixtureFile<PositiveTxVector> =
            serde_json::from_str(UTXO_BASIC_FIXTURE_JSON).expect("parse positive fixture");
        fixture
            .vectors
            .into_iter()
            .find(|vector| vector.id == "CV-U-06")
            .expect("positive fixture vector")
    }

    fn fixture_chain_id(chain_id: Option<&str>) -> [u8; 32] {
        chain_id
            .map(|value| parse_hex32_test("chain_id", value))
            .unwrap_or([0u8; 32])
    }

    fn chain_state_from_positive_fixture(vector: &PositiveTxVector) -> ChainState {
        let mut state = ChainState::new();
        state.has_tip = vector.height > 0;
        state.height = vector.height.saturating_sub(1);
        state.utxos = fixture_utxos_to_map(&vector.utxos);
        state
    }

    fn empty_core_ext_covenant_data(ext_id: u16) -> Vec<u8> {
        core_ext_covenant_data_with_payload(ext_id, &[])
    }

    fn core_ext_covenant_data_with_payload(ext_id: u16, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&ext_id.to_le_bytes());
        rubin_consensus::encode_compact_size(payload.len() as u64, &mut out);
        out.extend_from_slice(payload);
        out
    }

    fn signed_p2pk_state_and_tx(
        input_value: u64,
        outputs: Vec<TxOutput>,
        tx_kind: u8,
        da_chunk_core: Option<DaChunkCore>,
        da_payload: Vec<u8>,
    ) -> (ChainState, Vec<u8>) {
        let keypair = match Mldsa87Keypair::generate() {
            Ok(value) => value,
            Err(err) => panic!("OpenSSL signer unavailable for txpool policy test: {err}"),
        };
        let pubkey = keypair.pubkey_bytes();
        let outpoint = Outpoint {
            txid: [0x11; 32],
            vout: 0,
        };
        let mut state = ChainState::new();
        state.utxos.insert(
            outpoint.clone(),
            UtxoEntry {
                value: input_value,
                covenant_type: COV_TYPE_P2PK,
                covenant_data: p2pk_covenant_data_for_pubkey(&pubkey),
                creation_height: 0,
                created_by_coinbase: false,
            },
        );

        let mut tx = Tx {
            version: TX_WIRE_VERSION,
            tx_kind,
            tx_nonce: 7,
            inputs: vec![TxInput {
                prev_txid: outpoint.txid,
                prev_vout: outpoint.vout,
                script_sig: Vec::new(),
                sequence: 0,
            }],
            outputs,
            locktime: 0,
            da_commit_core: None,
            da_chunk_core,
            witness: Vec::new(),
            da_payload,
        };
        sign_transaction(&mut tx, &state.utxos, [0u8; 32], &keypair).expect("sign tx");
        let raw = marshal_tx(&tx).expect("marshal tx");
        (state, raw)
    }

    fn core_ext_spend_state_and_tx(ext_id: u16) -> (ChainState, Vec<u8>) {
        let input = Outpoint {
            txid: [0x33; 32],
            vout: 0,
        };
        let mut state = ChainState::new();
        state.utxos.insert(
            input.clone(),
            UtxoEntry {
                value: 10,
                covenant_type: COV_TYPE_EXT,
                covenant_data: empty_core_ext_covenant_data(ext_id),
                creation_height: 0,
                created_by_coinbase: false,
            },
        );
        let tx = Tx {
            version: TX_WIRE_VERSION,
            tx_kind: 0x00,
            tx_nonce: 9,
            inputs: vec![TxInput {
                prev_txid: input.txid,
                prev_vout: input.vout,
                script_sig: Vec::new(),
                sequence: 0,
            }],
            outputs: vec![TxOutput {
                value: 9,
                covenant_type: COV_TYPE_P2PK,
                covenant_data: p2pk_covenant_data_for_pubkey(&vec![0x44; 2592]),
            }],
            locktime: 0,
            da_commit_core: None,
            da_chunk_core: None,
            witness: vec![WitnessItem {
                suite_id: SUITE_ID_SENTINEL,
                pubkey: Vec::new(),
                signature: Vec::new(),
            }],
            da_payload: Vec::new(),
        };
        let raw = marshal_tx(&tx).expect("marshal core_ext spend");
        (state, raw)
    }

    #[test]
    fn mtp_median_uses_sorted_middle_of_window() {
        let got = mtp_median(5, &[9, 3, 5, 1, 7]);
        assert_eq!(got, 5);
    }

    #[test]
    fn mtp_median_uses_available_history_when_window_is_short() {
        assert_eq!(mtp_median(3, &[9]), 9);
    }

    #[test]
    fn admit_rejects_parse_errors() {
        let mut pool = TxPool::new();
        let err = pool
            .admit(&[], &ChainState::new(), None, [0u8; 32])
            .unwrap_err();
        assert_eq!(err.kind, TxPoolAdmitErrorKind::Rejected);
        assert!(err.message.contains("transaction rejected"));
    }

    #[test]
    fn admit_rejects_sub_floor_conformance_tx_as_unavailable_with_atomicity() {
        // RUB-162 Phase A migration rationale (per controller Q2 record):
        //   - old assumption: TxPool::new() admits the canonical conformance
        //     tx; pre-RUB-162 admit_with_metadata did not enforce the rolling
        //     fee floor as a separate Unavailable classifier.
        //   - new invariant: admit_with_metadata classifies relay-floor
        //     failure as Unavailable via validate_fee_floor (mirrors
        //     Go validateFeeFloorLocked). The conformance fixture has fee=10
        //     weight=7653 (fee_rate ≈ 0.0013, far below DEFAULT=1) and the
        //     floor cannot be lowered via cfg because validate_fee_floor
        //     clamps to DEFAULT (Go parity).
        //   - why it reaches policy path: tx is well-formed; floor check is
        //     after apply_policy.
        //   - replacement coverage: this test now asserts Unavailable
        //     directly (the new correct behaviour); the floor-compliant
        //     index-population smoke equivalent lives in
        //     `rub162_admit_da_above_both_floors_admits_with_indexes`,
        //     which exercises the same `insert_entry` + `spenders` /
        //     `heap_seqs` population path under a fee-floor-compliant
        //     DA fixture. The conformance fixture itself (RUB-54 scope)
        //     is unchanged; only the in-test pool config is adapted.
        let vector = positive_fixture_vector();
        assert!(vector.expect_ok, "{} should be positive fixture", vector.id);
        let raw = hex::decode(&vector.tx_hex).expect("tx hex");
        let (_tx, _txid, _wtxid, consumed) = parse_tx(&raw).expect("parse tx");
        assert_eq!(consumed, raw.len(), "{}", vector.id);

        let state = chain_state_from_positive_fixture(&vector);
        let mut pool = TxPool::new();
        let err = pool
            .admit(
                &raw,
                &state,
                None,
                fixture_chain_id(vector.chain_id.as_deref()),
            )
            .expect_err("conformance fixture has fee_rate well below DEFAULT_MEMPOOL_MIN_FEE_RATE");
        assert_eq!(err.kind, TxPoolAdmitErrorKind::Unavailable);
        assert!(err.message.contains("mempool fee below rolling minimum"));

        // Proof assertion: pool.len(), pool.spenders.is_empty(), and
        // pool.heap_seqs.len() pin the post-Err pool state to its pre-call
        // baseline (0 / empty / 0); any partial insert by admit_with_metadata
        // would surface as a non-zero mismatch on one of these three checks.
        assert_eq!(pool.len(), 0, "no entry inserted on Unavailable");
        assert!(pool.spenders.is_empty(), "no spenders inserted on Err");
        assert_eq!(pool.heap_seqs.len(), 0, "no heap state on Err");
    }

    /// PR-1410 wave-2 migration: this test previously asserted that
    /// `relay_metadata` Ok'd the conformance fixture (fee=10 / weight≈
    /// 7653 ⇒ fee/weight ≈ 0.0013, far below DEFAULT_MEMPOOL_MIN_FEE_RATE).
    /// After the wave-2 fix `relay_metadata` enforces the same rolling
    /// floor as `admit_with_metadata`, so the conformance fixture is
    /// now sub-floor and rejects with Unavailable from the new floor
    /// check inside `relay_metadata`. The polarity-accurate name
    /// (`relay_metadata_rejects_sub_floor_conformance_tx_as_unavailable`)
    /// reflects the asserted behaviour.
    #[test]
    fn relay_metadata_rejects_sub_floor_conformance_tx_as_unavailable() {
        let vector = positive_fixture_vector();
        let raw = hex::decode(&vector.tx_hex).expect("tx hex");
        let state = chain_state_from_positive_fixture(&vector);

        let err = relay_metadata(
            &raw,
            &state,
            None,
            fixture_chain_id(vector.chain_id.as_deref()),
            &TxPoolConfig::default(),
        )
        .expect_err("conformance fixture has fee_rate well below DEFAULT_MEMPOOL_MIN_FEE_RATE");

        assert_eq!(err.kind, TxPoolAdmitErrorKind::Unavailable);
        assert!(
            err.message.contains("mempool fee below rolling minimum"),
            "expected rolling-floor message, got: {}",
            err.message
        );
    }

    #[test]
    fn new_pool_starts_empty() {
        let pool = TxPool::new();
        assert!(pool.is_empty());
        assert_eq!(pool.len(), 0);
    }

    #[test]
    fn default_impl_matches_empty_pool() {
        let pool = TxPool::default();
        assert!(pool.is_empty());
        assert_eq!(pool.len(), 0);
    }

    #[test]
    fn next_block_height_handles_tip_states() {
        assert_eq!(next_block_height(&ChainState::new()).expect("height"), 0);

        let mut state = ChainState::new();
        state.has_tip = true;
        state.height = 7;
        assert_eq!(next_block_height(&state).expect("height"), 8);

        state.height = u64::MAX;
        let err = next_block_height(&state).unwrap_err();
        assert_eq!(err.kind, TxPoolAdmitErrorKind::Unavailable);
        assert!(err.message.contains("height overflow"));
    }

    #[test]
    fn next_block_mtp_handles_missing_store_context() {
        assert_eq!(next_block_mtp(None, 0).expect("mtp"), 0);

        let (store, dir) = open_block_store("rubin-txpool-mtp");
        assert_eq!(next_block_mtp(Some(&store), 0).expect("mtp"), 0);
        let err = next_block_mtp(Some(&store), 1).unwrap_err();
        assert_eq!(err.kind, TxPoolAdmitErrorKind::Unavailable);
        assert!(err.message.contains("missing canonical header"));
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn next_block_mtp_reads_timestamp_context_from_store() {
        let (store, dir) = open_block_store("rubin-txpool-mtp-success");
        let mut engine = SyncEngine::new(
            ChainState::new(),
            Some(store.clone()),
            default_sync_config(None, devnet_genesis_chain_id(), None),
        )
        .expect("sync");
        engine
            .apply_block(&devnet_genesis_block_bytes(), None)
            .expect("apply genesis");
        let reopened = BlockStore::open(block_store_path(&dir)).expect("reopen");
        assert!(next_block_mtp(Some(&reopened), 1).expect("mtp") > 0);
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn admit_rejects_duplicate_txid() {
        let raw = genesis_coinbase_bytes();
        let (_tx, txid, _wtxid, consumed) = parse_tx(&raw).expect("parse tx");
        assert_eq!(consumed, raw.len());

        let mut pool = TxPool::new();
        pool.txs.insert(
            txid,
            TxPoolEntry {
                raw: raw.clone(),
                inputs: Vec::new(),
                fee: 0,
                weight: 0,
                size: raw.len(),
            },
        );
        let err = pool
            .admit(&raw, &ChainState::new(), None, devnet_genesis_chain_id())
            .unwrap_err();
        assert_eq!(err.kind, TxPoolAdmitErrorKind::Conflict);
        assert!(err.message.contains("already in mempool"));
    }

    #[test]
    fn admit_rejects_non_canonical_trailing_bytes() {
        let mut raw = genesis_coinbase_bytes();
        raw.push(0x00);
        let err = TxPool::new()
            .admit(&raw, &ChainState::new(), None, devnet_genesis_chain_id())
            .unwrap_err();
        assert_eq!(err.kind, TxPoolAdmitErrorKind::Rejected);
        assert!(err.message.contains("non-canonical tx bytes"));
    }

    #[test]
    fn relay_metadata_rejects_pre_activation_core_ext_outputs() {
        let (state, raw) = signed_p2pk_state_and_tx(
            10,
            vec![TxOutput {
                value: 9,
                covenant_type: COV_TYPE_EXT,
                covenant_data: empty_core_ext_covenant_data(7),
            }],
            0x00,
            None,
            Vec::new(),
        );

        let err =
            relay_metadata(&raw, &state, None, [0u8; 32], &TxPoolConfig::default()).unwrap_err();

        assert_eq!(err.kind, TxPoolAdmitErrorKind::Rejected);
        assert!(err.message.contains("CORE_EXT output pre-ACTIVE"));
    }

    #[test]
    fn admit_rejects_pool_full() {
        // RUB-162 Phase A migration rationale (per controller Path A
        // approval 2026-05-03 + RESP P1 #2 reorder fix 2026-05-03):
        //   - old assumption: input=10/output=10 → fee=0 candidate
        //     reaches the pool-full ordering check and admit returns
        //     Unavailable("tx pool full") because the pre-RUB-162
        //     admit_with_metadata had no rolling-floor classification.
        //   - new invariant: validate_fee_floor runs BEFORE the
        //     pool-full check (Go validateCapacityAdmissionLocked order
        //     at clients/go/node/mempool.go:1020-1024). Sub-floor
        //     candidates fail the floor check first.
        //   - reachability: tx is well-formed; the pool-full ordering
        //     branch is the test goal.
        //   - replacement coverage: input bumped to 7700 so fee=7690 ≥
        //     weight (~7653) ⇒ candidate passes floor and reaches the
        //     pool-full ordering check this test is asserting. A
        //     dedicated rub162_admit_full_pool_below_floor_returns_floor_
        //     error_not_pool_full test below pins the new ordering for
        //     sub-floor candidates.
        let (state, raw) = signed_p2pk_state_and_tx(
            7700,
            vec![TxOutput {
                value: 10,
                covenant_type: COV_TYPE_P2PK,
                covenant_data: p2pk_covenant_data_for_pubkey(&vec![0x55; 2592]),
            }],
            0x00,
            None,
            Vec::new(),
        );
        let (_tx, txid, _wtxid, consumed) = parse_tx(&raw).expect("parse tx");
        assert_eq!(consumed, raw.len());

        let mut pool = TxPool::new();
        for idx in 0..MAX_TX_POOL_TRANSACTIONS {
            let mut key = [0u8; 32];
            key[..8].copy_from_slice(&(idx as u64 + 1).to_le_bytes());
            if key == txid {
                key[8] = 1;
            }
            // Worst-pool entries sized to outrank candidate fee_rate so
            // pool-full ordering rejects (worst fee_rate=10 > candidate
            // fee_rate≈1.005, candidate cannot beat worst).
            pool.txs.insert(
                key,
                TxPoolEntry {
                    raw: vec![0xff],
                    inputs: Vec::new(),
                    fee: 10,
                    weight: 1,
                    size: 1,
                },
            );
        }
        let err = pool.admit(&raw, &state, None, [0u8; 32]).unwrap_err();
        assert_eq!(err.kind, TxPoolAdmitErrorKind::Unavailable);
        // PR-1410 wave-2 — error message split per Go-parity at
        // clients/go/node/mempool.go:1028-1030. Eviction-ordering
        // rejection is now distinct from internal capacity invariant
        // failure.
        assert!(
            err.message
                .contains("mempool capacity candidate rejected by eviction ordering"),
            "expected eviction-ordering message, got: {}",
            err.message
        );
    }

    /// PR-1410 wave-2 — direct `insert_entry` populates the worst_heap
    /// without going through admit_with_metadata, so this test
    /// exercises the routine eviction-ordering rejection path with a
    /// fully populated heap (not the corruption invariants). Pinning
    /// the new error-message format prevents future regressions that
    /// would collapse this case back into a generic "tx pool full"
    /// message and lose Go-parity at clients/go/node/mempool.go:1028-1030.
    #[test]
    fn rub162_admit_pool_full_eviction_ordering_message_distinct_from_invariant() {
        let (state, raw) = signed_p2pk_state_and_tx(
            7700,
            vec![TxOutput {
                value: 10,
                covenant_type: COV_TYPE_P2PK,
                covenant_data: p2pk_covenant_data_for_pubkey(&vec![0x77; 2592]),
            }],
            0x00,
            None,
            Vec::new(),
        );
        let (_tx, txid, _wtxid, consumed) = parse_tx(&raw).expect("parse tx");
        assert_eq!(consumed, raw.len());

        let mut pool = TxPool::new();
        // Populate via the production `insert_entry` path so worst_heap +
        // heap_seqs + spenders are all coherent — exercises the
        // legitimate eviction-ordering rejection branch (NOT corruption).
        for idx in 0..MAX_TX_POOL_TRANSACTIONS {
            let mut key = [0u8; 32];
            key[..8].copy_from_slice(&(idx as u64 + 1).to_le_bytes());
            if key == txid {
                key[8] = 1;
            }
            pool.insert_entry(
                key,
                TxPoolEntry {
                    raw: vec![0xff],
                    inputs: Vec::new(),
                    fee: 10,
                    weight: 1,
                    size: 1,
                },
            );
        }
        let err = pool.admit(&raw, &state, None, [0u8; 32]).unwrap_err();
        assert_eq!(err.kind, TxPoolAdmitErrorKind::Unavailable);
        assert!(
            err.message
                .contains("mempool capacity candidate rejected by eviction ordering"),
            "expected eviction-ordering message (Go-parity mempool.go:1028-1030), got: {}",
            err.message
        );
        // Pin: legitimate eviction-ordering rejection MUST NOT collapse
        // into the internal invariant-violation message.
        assert!(
            !err.message.contains("invariant violated"),
            "eviction-ordering rejection must not surface as invariant violation; got: {}",
            err.message
        );
    }

    #[test]
    fn admit_evicts_lowest_priority_when_pool_full() {
        // RUB-162 Phase A migration rationale (per controller Q2 record):
        //   - old assumption: input=10/output=8 → fee=2 with weight≈7653
        //     admits because pre-RUB-162 admit_with_metadata didn't enforce
        //     the rolling fee floor; the test exercised eviction-ordering.
        //   - new invariant: admit_with_metadata enforces the rolling fee
        //     floor (DEFAULT_MEMPOOL_MIN_FEE_RATE=1) via
        //     validate_fee_floor → Unavailable when fee/weight < 1.
        //   - why it reaches policy path: tx is well-formed; floor check
        //     is after apply_policy, before eviction.
        //   - replacement coverage: input bumped to 7661 so fee = 7661 - 8
        //     = 7653 ≥ weight (≈7653) ⇒ fee/weight ≥ 1 ⇒ passes the
        //     default floor; eviction-ordering invariant remains under test.
        //     Cfg-zero opt-out is impossible because the floor is clamped
        //     to DEFAULT inside validate_fee_floor (Go parity).
        let (state, raw) = signed_p2pk_state_and_tx(
            7661,
            vec![TxOutput {
                value: 8,
                covenant_type: COV_TYPE_P2PK,
                covenant_data: p2pk_covenant_data_for_pubkey(&vec![0x66; 2592]),
            }],
            0x00,
            None,
            Vec::new(),
        );
        let (_tx, txid, _wtxid, consumed) = parse_tx(&raw).expect("parse tx");
        assert_eq!(consumed, raw.len());

        let mut pool = TxPool::new();
        let worst = [0x11; 32];
        pool.txs.insert(
            worst,
            TxPoolEntry {
                raw: vec![0x01],
                inputs: Vec::new(),
                fee: 0,
                weight: 100,
                size: 1,
            },
        );
        for idx in 1..MAX_TX_POOL_TRANSACTIONS {
            let mut key = [0u8; 32];
            key[..8].copy_from_slice(&(idx as u64 + 1).to_le_bytes());
            if key == txid || key == worst {
                key[8] = 1;
            }
            pool.txs.insert(
                key,
                TxPoolEntry {
                    raw: vec![0xff],
                    inputs: Vec::new(),
                    fee: 1,
                    weight: 1,
                    size: 1,
                },
            );
        }

        let admitted = pool
            .admit(&raw, &state, None, [0u8; 32])
            .expect("admit should evict");
        assert_eq!(admitted, txid);
        assert_eq!(pool.txs.len(), MAX_TX_POOL_TRANSACTIONS);
        assert!(pool.txs.contains_key(&txid));
        assert!(!pool.txs.contains_key(&worst));
    }

    #[test]
    fn admit_reject_on_full_preserves_future_eviction() {
        // RUB-162 Phase A migration rationale (per controller Q2 record):
        //   - old assumption: pre-RUB-162 admit_with_metadata did not enforce
        //     the rolling fee floor; the test exercised heap-state
        //     preservation across reject + admit cycle.
        //   - new invariant: admit_with_metadata enforces the rolling fee
        //     floor via validate_fee_floor → Unavailable.
        //   - why it reaches policy path: txs are well-formed; floor check
        //     is after apply_policy.
        //   - replacement coverage: input_value bumped to make fee_rate ≥ 1
        //     so both candidates pass the floor. The "worse" candidate now
        //     has fee=7652, the "better" has fee=8000. Pool worst entry
        //     bumped to fee_rate ≈ 0.9 so worse-candidate fee_rate (~1.0)
        //     beats it but only marginally — preserves the test's intended
        //     eviction-ordering interaction. Heap-state preservation
        //     invariant (P1 #2 atomicity-related) remains under test.
        // Better candidate: fee = 20000 - 8 = 19992; weight ≈ 7653 (ML-DSA
        // witness) → fee_rate ≈ 2.61. Above floor; should beat worst pool
        // entry (fee_rate = 2.0).
        let (state_better, raw_better) = signed_p2pk_state_and_tx(
            20_000,
            vec![TxOutput {
                value: 8,
                covenant_type: COV_TYPE_P2PK,
                covenant_data: p2pk_covenant_data_for_pubkey(&vec![0x76; 2592]),
            }],
            0x00,
            None,
            Vec::new(),
        );
        // Worse candidate: fee = 7662 - 9 = 7653; weight ≈ 7653 → fee_rate
        // = 1.0. Above floor (passes validate_fee_floor) but below
        // worst pool entry's fee_rate (2.0); pool-full eviction comparator
        // rejects with Unavailable.
        let (state_worse, raw_worse) = signed_p2pk_state_and_tx(
            7_662,
            vec![TxOutput {
                value: 9,
                covenant_type: COV_TYPE_P2PK,
                covenant_data: p2pk_covenant_data_for_pubkey(&vec![0x77; 2592]),
            }],
            0x00,
            None,
            Vec::new(),
        );

        let mut pool = TxPool::new();
        let worst = [0x11; 32];
        // Worst pool entry: fee_rate = 20000/10000 = 2.0. Above the default
        // rolling floor (1) so the eviction-ordering test exercises the
        // comparator branch that compares "worse candidate at floor" vs
        // "above-floor resident worst". Inserted directly via pool.txs to
        // bypass admit_with_metadata's floor check.
        pool.txs.insert(
            worst,
            TxPoolEntry {
                raw: vec![0x01; raw_worse.len()],
                inputs: Vec::new(),
                fee: 20_000,
                weight: 10_000,
                size: raw_worse.len(),
            },
        );
        for idx in 1..MAX_TX_POOL_TRANSACTIONS {
            let mut key = [0u8; 32];
            key[..8].copy_from_slice(&(idx as u64 + 1).to_le_bytes());
            if key == worst {
                key[8] = 1;
            }
            pool.txs.insert(
                key,
                TxPoolEntry {
                    raw: vec![0xff],
                    inputs: Vec::new(),
                    fee: 3,
                    weight: 1,
                    size: 1,
                },
            );
        }

        let err = pool
            .admit(&raw_worse, &state_worse, None, [0u8; 32])
            .unwrap_err();
        assert_eq!(err.kind, TxPoolAdmitErrorKind::Unavailable);
        assert!(pool.txs.contains_key(&worst));

        let admitted = pool
            .admit(&raw_better, &state_better, None, [0u8; 32])
            .expect("admit better should still evict");
        assert_eq!(pool.txs.len(), MAX_TX_POOL_TRANSACTIONS);
        assert!(pool.txs.contains_key(&admitted));
        assert!(!pool.txs.contains_key(&worst));
    }

    #[test]
    fn admit_rejects_mempool_input_conflict() {
        let raw = maturity_fixture_tx_bytes();
        let (tx, _txid, _wtxid, consumed) = parse_tx(&raw).expect("parse tx");
        assert_eq!(consumed, raw.len());
        let first = tx.inputs.first().expect("fixture input");

        let mut pool = TxPool::new();
        pool.spenders.insert(
            rubin_consensus::Outpoint {
                txid: first.prev_txid,
                vout: first.prev_vout,
            },
            [0xabu8; 32],
        );
        let err = pool
            .admit(&raw, &ChainState::new(), None, devnet_genesis_chain_id())
            .unwrap_err();
        assert_eq!(err.kind, TxPoolAdmitErrorKind::Conflict);
        assert!(err.message.contains("double-spend conflict"));
    }

    #[test]
    fn select_transactions_orders_by_fee_rate_then_fee() {
        let mut pool = TxPool::new();
        pool.txs.insert(
            [0x11; 32],
            TxPoolEntry {
                raw: vec![0x11],
                inputs: Vec::new(),
                fee: 20,
                weight: 100,
                size: 20,
            },
        );
        pool.txs.insert(
            [0x22; 32],
            TxPoolEntry {
                raw: vec![0x22],
                inputs: Vec::new(),
                fee: 15,
                weight: 90,
                size: 10,
            },
        );
        pool.txs.insert(
            [0x33; 32],
            TxPoolEntry {
                raw: vec![0x33],
                inputs: Vec::new(),
                fee: 15,
                weight: 80,
                size: 10,
            },
        );

        let selected = pool.select_transactions(3, 40);
        assert_eq!(selected, vec![vec![0x11], vec![0x33], vec![0x22]]);
    }

    #[test]
    fn txpool_fee_rate_uses_weight_not_size() {
        let size_favored = TxPoolEntry {
            raw: vec![0x41],
            inputs: Vec::new(),
            fee: 4,
            weight: 4,
            size: 1,
        };
        let weight_favored = TxPoolEntry {
            raw: vec![0x21],
            inputs: Vec::new(),
            fee: 2,
            weight: 1,
            size: 1,
        };

        assert_eq!(
            compare_fee_rate(&size_favored, &weight_favored),
            Ordering::Less,
            "fee/weight must rank 2/1 above 4/4 even when fee/size favors 4/1",
        );
        assert_eq!(
            compare_admit_priority([0x41; 32], &size_favored, [0x21; 32], &weight_favored),
            Ordering::Less,
        );

        let size_favored_txid: [u8; 32] = [0x41; 32];
        let weight_favored_txid: [u8; 32] = [0x21; 32];
        assert_eq!(
            compare_entries_for_mining(
                &(&weight_favored_txid, &weight_favored),
                &(&size_favored_txid, &size_favored),
            ),
            Ordering::Less,
        );
    }

    #[test]
    fn select_transactions_respects_count_and_size_caps() {
        let mut pool = TxPool::new();
        pool.txs.insert(
            [0x44; 32],
            TxPoolEntry {
                raw: vec![0x44, 0x44],
                inputs: Vec::new(),
                fee: 5,
                weight: 10,
                size: 2,
            },
        );
        pool.txs.insert(
            [0x55; 32],
            TxPoolEntry {
                raw: vec![0x55, 0x55, 0x55],
                inputs: Vec::new(),
                fee: 100,
                weight: 10,
                size: 3,
            },
        );

        let selected = pool.select_transactions(1, 2);
        assert_eq!(selected, vec![vec![0x44, 0x44]]);
    }

    #[test]
    fn remove_conflicting_inputs_evicts_conflicting_mempool_entries() {
        // RUB-162 Phase A migration rationale (per controller Q2 record,
        // Path A approval 2026-05-03):
        //   - old assumption: input=20 / first_output=10 → fee=10 with
        //     weight ≈ 7653 admits because pre-RUB-162 admit_with_metadata
        //     did not enforce the rolling fee floor on non-DA txs.
        //   - new invariant: admit_with_metadata enforces the rolling fee
        //     floor (DEFAULT_MEMPOOL_MIN_FEE_RATE=1) for every admission
        //     via validate_fee_floor.
        //   - reachability: tx is well-formed (parses, basic checks pass);
        //     floor check is after apply_policy. Original test goal is to
        //     exercise remove_conflicting_inputs via a previously-admitted
        //     tx + a block tx that double-spends the same input.
        //   - replacement coverage: input bumped to 7700 so the admitted
        //     tx fee = 7700 - 10 = 7690 ≥ weight (≈7653); the block tx
        //     fee = 7700 - 9 = 7691 also above floor. Original conflict
        //     scenario preserved.
        let (state, admitted_raw, block_raw) = signed_conflicting_p2pk_state_and_txs(7700, 10, 9);
        let mut pool = TxPool::new();
        let admitted_txid = pool
            .admit(&admitted_raw, &state, None, devnet_genesis_chain_id())
            .expect("admit");
        let (block_tx, _txid, _wtxid, consumed) = parse_tx(&block_raw).expect("parse tx");
        assert_eq!(consumed, block_raw.len());

        pool.remove_conflicting_inputs(&[block_tx]);

        assert!(!pool.txs.contains_key(&admitted_txid));
        assert!(pool.is_empty());
    }

    #[test]
    fn stale_worst_heap_is_compacted_after_removals() {
        let mut pool = TxPool::new();
        for idx in 0..64u8 {
            let txid = [idx; 32];
            pool.insert_entry(
                txid,
                TxPoolEntry {
                    raw: vec![idx],
                    inputs: Vec::new(),
                    fee: idx as u64 + 1,
                    weight: idx as u64 + 1,
                    size: 1,
                },
            );
        }

        for idx in 0..63u8 {
            let txid = [idx; 32];
            pool.remove_entry(&txid);
        }

        assert_eq!(pool.txs.len(), 1);
        assert_eq!(pool.heap_seqs.len(), 1);
        assert_eq!(pool.worst_heap.len(), 1);
    }

    #[test]
    fn current_worst_txid_skips_stale_heap_tail_without_rebuild() {
        let mut pool = TxPool::new();
        for idx in 0..2u8 {
            let txid = [idx + 1; 32];
            pool.insert_entry(
                txid,
                TxPoolEntry {
                    raw: vec![idx],
                    inputs: Vec::new(),
                    fee: idx as u64 + 10,
                    weight: idx as u64 + 10,
                    size: 1,
                },
            );
        }

        pool.remove_entry(&[1; 32]);
        pool.insert_entry(
            [3; 32],
            TxPoolEntry {
                raw: vec![3],
                inputs: Vec::new(),
                fee: 30,
                weight: 30,
                size: 1,
            },
        );

        assert_eq!(pool.txs.len(), 2);
        assert_eq!(pool.heap_seqs.len(), 2);
        assert_eq!(pool.worst_heap.len(), 3);

        let next_heap_id = pool.next_heap_id;
        assert!(pool.current_worst_txid().is_some());
        assert_eq!(pool.next_heap_id, next_heap_id);
    }

    #[test]
    fn mining_sort_helpers_cover_zero_weight_and_tiebreaks() {
        let zero = TxPoolEntry {
            raw: vec![0x00],
            inputs: Vec::new(),
            fee: 10,
            weight: 0,
            size: 10,
        };
        let normal = TxPoolEntry {
            raw: vec![0x01],
            inputs: Vec::new(),
            fee: 20,
            weight: 20,
            size: 10,
        };
        assert_eq!(compare_fee_rate(&zero, &normal), Ordering::Equal);

        let high_fee = TxPoolEntry {
            raw: vec![0x03],
            inputs: Vec::new(),
            fee: 30,
            weight: 10,
            size: 10,
        };
        let low_fee = TxPoolEntry {
            raw: vec![0x02],
            inputs: Vec::new(),
            fee: 20,
            weight: 10,
            size: 10,
        };
        assert_eq!(
            compare_admit_priority([0x03; 32], &high_fee, [0x02; 32], &low_fee),
            Ordering::Greater
        );
        let high_txid: [u8; 32] = [0x03; 32];
        let low_txid: [u8; 32] = [0x02; 32];
        assert_eq!(
            compare_entries_for_mining(&(&high_txid, &high_fee), &(&low_txid, &low_fee)),
            Ordering::Less
        );

        let lighter = TxPoolEntry {
            raw: vec![0x04],
            inputs: Vec::new(),
            fee: 20,
            weight: 5,
            size: 10,
        };
        let heavier = TxPoolEntry {
            raw: vec![0x05],
            inputs: Vec::new(),
            fee: 20,
            weight: 8,
            size: 10,
        };
        let lighter_txid: [u8; 32] = [0x04; 32];
        let heavier_txid: [u8; 32] = [0x05; 32];
        assert_eq!(
            compare_entries_for_mining(&(&lighter_txid, &lighter), &(&heavier_txid, &heavier),),
            Ordering::Less
        );

        // Final tie-break is TXID (lexicographic), matching Go parity
        // (`clients/go/node/mempool.go`, `sortMempoolEntries`) and the
        // Rust admit-priority comparator. Same fee/size/weight, different
        // TXIDs — lower TXID sorts first.
        let equal_a = TxPoolEntry {
            raw: vec![0xFF],
            inputs: Vec::new(),
            fee: 20,
            weight: 10,
            size: 10,
        };
        let equal_b = TxPoolEntry {
            raw: vec![0xAA],
            inputs: Vec::new(),
            fee: 20,
            weight: 10,
            size: 10,
        };
        let lo_txid: [u8; 32] = [0x01; 32];
        let hi_txid: [u8; 32] = [0x02; 32];
        assert_eq!(
            compare_entries_for_mining(&(&lo_txid, &equal_a), &(&hi_txid, &equal_b)),
            Ordering::Less,
            "lower txid must sort first regardless of raw bytes",
        );
    }

    #[test]
    fn admit_reports_unavailable_on_height_overflow() {
        let raw = genesis_coinbase_bytes();
        let mut state = ChainState::new();
        state.has_tip = true;
        state.height = u64::MAX;

        let err = TxPool::new()
            .admit(&raw, &state, None, devnet_genesis_chain_id())
            .unwrap_err();
        assert_eq!(err.kind, TxPoolAdmitErrorKind::Unavailable);
        assert!(err.message.contains("height overflow"));
    }

    #[test]
    fn admit_reports_unavailable_when_timestamp_context_missing() {
        let raw = genesis_coinbase_bytes();
        let mut state = ChainState::new();
        state.has_tip = true;
        state.height = 0;

        let (store, dir) = open_block_store("rubin-txpool-admit-mtp");
        let err = TxPool::new()
            .admit(&raw, &state, Some(&store), devnet_genesis_chain_id())
            .unwrap_err();
        assert_eq!(err.kind, TxPoolAdmitErrorKind::Unavailable);
        assert!(err.message.contains("missing canonical header"));
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn admit_reports_unavailable_when_header_lookup_fails() {
        // RUB-162 Phase A migration rationale (per controller Path A
        // approval 2026-05-03 + RESP P1 #2 reorder fix 2026-05-03):
        //   - old assumption: positive_fixture_vector tx (fee=10/weight=
        //     7653) reaches next_block_mtp -> get_header_by_hash which
        //     fails with "read header"; pre-RUB-162 admit_with_metadata
        //     did not enforce the rolling fee floor at all.
        //   - new invariant: validate_fee_floor runs AFTER
        //     apply_policy as the post-apply Go-parity placement
        //     (mirrors clients/go/node/mempool.go:1020-1024
        //     validateCapacityAdmissionLocked called from
        //     addToMempoolLocked AFTER applyPolicyAgainstState). The
        //     conformance fixture is sub-floor so admit returns
        //     Unavailable("mempool fee below rolling minimum") AFTER
        //     apply_policy succeeds but BEFORE reaching the post-apply
        //     pool-full / capacity branches.
        //   - reachability: test's goal is the header_lookup failure
        //     path (block_store.get_header_by_hash → Err propagated
        //     as Unavailable). header_lookup happens inside
        //     next_block_mtp which runs BEFORE both apply_policy and
        //     validate_fee_floor, so floor-compliance is NOT a
        //     reachability requirement for this branch — any well-formed
        //     tx with chain_state has_tip=true / height=0 and a
        //     canonical tip whose header is missing from the
        //     block_store reaches the header_lookup branch.
        //   - replacement coverage: build a signed P2PK tx (input=7700)
        //     inline with chain_state has_tip=true / height=0; the
        //     input value is left at 7700 only for consistency with the
        //     general RUB-162 floor-compliant fixture policy across the
        //     test module (harmless here because reachability does not
        //     depend on it). The header_lookup-failure invariant remains
        //     under test.
        let (mut state, raw) = signed_p2pk_state_and_tx(
            7700,
            vec![TxOutput {
                value: 10,
                covenant_type: COV_TYPE_P2PK,
                covenant_data: p2pk_covenant_data_for_pubkey(&vec![0x99; 2592]),
            }],
            0x00,
            None,
            Vec::new(),
        );
        state.has_tip = true;
        state.height = 0;

        let (mut store, dir) = open_block_store("rubin-txpool-admit-header-read");
        store
            .set_canonical_tip(0, [0x42; 32])
            .expect("set canonical tip");

        let err = TxPool::new()
            .admit(&raw, &state, Some(&store), [0u8; 32])
            .unwrap_err();
        assert_eq!(err.kind, TxPoolAdmitErrorKind::Unavailable);
        assert!(err.message.contains("read header"));
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn admit_rejects_coinbase_semantics_as_non_coinbase() {
        let raw = genesis_coinbase_bytes();
        let err = TxPool::new()
            .admit(&raw, &ChainState::new(), None, devnet_genesis_chain_id())
            .unwrap_err();
        assert_eq!(err.kind, TxPoolAdmitErrorKind::Rejected);
        assert!(err.message.contains("transaction rejected"));
    }

    #[test]
    fn admit_rejects_non_coinbase_anchor_outputs_by_policy() {
        // RUB-162 Phase A migration rationale (per controller Path A
        // approval 2026-05-03 + RESP P1 #2 reorder fix 2026-05-03):
        //   - old assumption: input=10, sum-outputs=9 → fee=1 reaches
        //     the anchor-output policy guard which returns Rejected.
        //   - new invariant: apply_policy (which evaluates the
        //     anchor-output policy) precedes the rolling-floor check
        //     in admit_with_metadata; mirrors Go addToMempoolLocked
        //     calling applyPolicyAgainstState then
        //     validateCapacityAdmissionLocked → validateFeeFloorLocked
        //     at clients/go/node/mempool.go:798-1024.
        //   - Proof assertion: `assert_eq!(err.kind, Rejected)` plus
        //     `err.message.contains("CORE_ANCHOR")` below pin the class
        //     winner against the alternative `Unavailable("mempool fee
        //     below rolling minimum")` outcome.
        //   - reachability: tx is well-formed; the anchor-output
        //     policy guard is the test goal. fee/weight headroom is
        //     defensive (apply_policy rejects regardless), but kept
        //     for parity with the cross-pollination matrix below.
        //   - replacement coverage: input bumped to 20000 so
        //     fee = 20000 - 9 = 19991 ≥ weight ⇒ candidate passes
        //     floor (the two-output tx with anchor + p2pk has a
        //     larger weight than single-output P2PK because of the
        //     anchor covenant + p2pk witness; 20000 covers it with
        //     headroom) and reaches the anchor-output policy guard.
        let (state, raw) = signed_p2pk_state_and_tx(
            20_000,
            vec![
                TxOutput {
                    value: 0,
                    covenant_type: COV_TYPE_ANCHOR,
                    covenant_data: vec![0x99],
                },
                TxOutput {
                    value: 9,
                    covenant_type: COV_TYPE_P2PK,
                    covenant_data: p2pk_covenant_data_for_pubkey(&vec![0x22; 2592]),
                },
            ],
            0x00,
            None,
            Vec::new(),
        );
        let err = TxPool::new()
            .admit(&raw, &state, None, [0u8; 32])
            .unwrap_err();
        assert_eq!(err.kind, TxPoolAdmitErrorKind::Rejected);
        assert!(err.message.contains("CORE_ANCHOR"));
    }

    #[test]
    fn admit_rejects_da_tx_below_policy_stage_c_floor() {
        // RUB-162 Phase A migration rationale (per controller Path A
        // approval 2026-05-03 + RESP P1 #2 reorder fix 2026-05-03):
        //   - old assumption: input=10/output=9 fee=1, weight≈7653
        //     → reaches DA-helper which returns Rejected because
        //     fee < relay-floor-or-DA-required (whichever was higher).
        //   - new invariant: apply_policy (containing the DA helper
        //     with cfg-zero override) runs BEFORE
        //     validate_fee_floor. With cfg-zero the DA helper
        //     checks fee >= max(0, da_required) = da_required, leaving
        //     DA-side classification intact while the rolling relay
        //     floor is enforced separately AFTER apply_policy. To pin
        //     the DA-helper Stage C rejection path, fee must be
        //     < DA-required so apply_policy rejects with Rejected.
        //   - replacement coverage: input bumped to 8000 + fee=7991;
        //     weight≈7653; surcharge bumped to 200 so DA-required ≈
        //     da_bytes(70)*200 = 14000 > fee → DA-helper rejects with
        //     the canonical Stage C error message + named-term debug
        //     fields. The fee/weight headroom (≈1.04 ≥ default floor)
        //     is defensive — apply_policy rejects regardless, but the
        //     headroom keeps the fixture meaningful for the
        //     cross-pollination ordering matrix below. The test's
        //     purpose (verifying Stage C error message includes all
        //     named debug fields) remains under test.
        let (state, raw) = signed_p2pk_state_and_tx(
            8000,
            vec![TxOutput {
                value: 9,
                covenant_type: COV_TYPE_P2PK,
                covenant_data: p2pk_covenant_data_for_pubkey(&vec![0x23; 2592]),
            }],
            0x02,
            Some(DaChunkCore {
                da_id: [0x55; 32],
                chunk_index: 0,
                chunk_hash: [0x66; 32],
            }),
            vec![0x77; 64],
        );
        let mut pool = TxPool::new_with_config(TxPoolConfig::default());
        pool.cfg.policy_da_surcharge_per_byte = 200;
        let err = pool.admit(&raw, &state, None, [0u8; 32]).unwrap_err();
        assert_eq!(err.kind, TxPoolAdmitErrorKind::Rejected);
        assert!(
            err.message.contains("DA fee below Stage C floor"),
            "expected Stage C error, got: {}",
            err.message
        );
        assert!(
            err.message.contains("relay_fee_floor=")
                && err.message.contains("da_fee_floor=")
                && err.message.contains("da_surcharge=")
                && err.message.contains("weight=")
                && err.message.contains("da_payload_len="),
            "expected debug fields in error, got: {}",
            err.message
        );
    }

    #[test]
    fn admit_rejects_core_ext_output_pre_activation_by_policy() {
        // RUB-162 Phase A migration rationale (per controller Path A
        // approval 2026-05-03 + RESP P1 #2 reorder fix 2026-05-03):
        //   - old assumption: input=10/output=9 fee=1 reached the
        //     CORE_EXT pre-activation policy guard returning Rejected.
        //   - new invariant: apply_policy (which evaluates the
        //     CORE_EXT pre-activation policy) precedes the rolling-floor
        //     check in admit_with_metadata.
        //   - Proof assertion: `assert_eq!(err.kind, Rejected)` plus
        //     `err.message.contains("CORE_EXT output pre-ACTIVE")`
        //     below pin the class winner against the alternative
        //     `Unavailable("mempool fee below rolling minimum")`
        //     outcome.
        //   - replacement coverage: input bumped to 7700 so fee=7691
        //     ≥ weight ⇒ candidate also passes the floor (defensive,
        //     since apply_policy rejects regardless) and reaches the
        //     CORE_EXT pre-activation policy guard. The fixture is
        //     mirrored in
        //     rub162_admit_sub_floor_core_ext_classifies_as_core_ext_rejected
        //     to PIN the cross-pollination class winner.
        let (state, raw) = signed_p2pk_state_and_tx(
            7700,
            vec![TxOutput {
                value: 9,
                covenant_type: COV_TYPE_EXT,
                covenant_data: empty_core_ext_covenant_data(7),
            }],
            0x00,
            None,
            Vec::new(),
        );
        let err = TxPool::new()
            .admit(&raw, &state, None, [0u8; 32])
            .unwrap_err();
        assert_eq!(err.kind, TxPoolAdmitErrorKind::Rejected);
        assert!(err.message.contains("CORE_EXT output pre-ACTIVE"));
    }

    #[test]
    fn admit_allows_core_ext_output_when_profile_is_active() {
        // RUB-162 Phase A migration rationale (per controller Q2 record):
        //   - old assumption: input=10/output=9 → fee=1 with weight≈7533
        //     admits once core_ext profile is registered (pre-RUB-162 had no
        //     fee-floor check).
        //   - new invariant: admit_with_metadata enforces the rolling fee
        //     floor (DEFAULT_MEMPOOL_MIN_FEE_RATE=1).
        //   - why it reaches policy path: tx is well-formed; floor check is
        //     after apply_policy and after the CORE_EXT pre-activation check
        //     succeeds for the registered profile.
        //   - replacement coverage: input bumped to 7542 so fee = 7542 - 9
        //     = 7533 ≥ weight (≈7533) ⇒ fee/weight ≥ 1 ⇒ passes the
        //     default floor; the test's CORE_EXT-profile-activation
        //     invariant remains under test.
        let (state, raw) = signed_p2pk_state_and_tx(
            7_542,
            vec![TxOutput {
                value: 9,
                covenant_type: COV_TYPE_EXT,
                covenant_data: empty_core_ext_covenant_data(7),
            }],
            0x00,
            None,
            Vec::new(),
        );
        let mut pool = TxPool::new_with_config(TxPoolConfig::default());
        pool.cfg.core_ext_deployments = CoreExtDeploymentProfiles {
            deployments: vec![CoreExtDeploymentProfile {
                ext_id: 7,
                activation_height: 0,
                tx_context_enabled: false,
                allowed_suite_ids: vec![3],
                verification_binding: CoreExtVerificationBinding::VerifySigExtAccept,
                verify_sig_ext_tx_context_fn: None,
                binding_descriptor: b"accept".to_vec(),
                ext_payload_schema: b"schema".to_vec(),
                governance_nonce: 0,
            }],
        };
        let txid = pool.admit(&raw, &state, None, [0u8; 32]).expect("admit");
        assert!(pool.txs.contains_key(&txid));
    }

    #[test]
    fn admit_rejects_core_ext_spend_pre_activation_by_policy() {
        // RUB-162 Phase A migration rationale (per controller Path A
        // approval 2026-05-03 + RESP P1 #2 reorder fix 2026-05-03):
        //   - old assumption: core_ext_spend_state_and_tx helper sets
        //     UTXO value=10/output value=9 → fee=1 reaches the
        //     CORE_EXT-spend pre-activation policy guard.
        //   - new invariant: apply_policy (which evaluates the
        //     CORE_EXT spend pre-activation policy) precedes the
        //     rolling-floor check in admit_with_metadata. Headroom is
        //     defensive.
        //   - Proof assertion: `assert_eq!(err.kind, Rejected)` plus
        //     `err.message.contains("CORE_EXT spend pre-ACTIVE")`
        //     below pin the class winner against the alternative
        //     `Unavailable("mempool fee below rolling minimum")`
        //     outcome.
        //   - replacement coverage: bump UTXO value in-place to 7700
        //     (helper's UTXO value patched after construction; helper
        //     signature preserved for any future caller). fee = 7700 -
        //     9 = 7691 ≥ weight ⇒ candidate also passes the floor; the
        //     CORE_EXT-spend pre-activation guard remains the test
        //     goal.
        let (mut state, raw) = core_ext_spend_state_and_tx(9);
        for entry in state.utxos.values_mut() {
            entry.value = 7700;
        }
        let err = TxPool::new()
            .admit(&raw, &state, None, [0u8; 32])
            .unwrap_err();
        assert_eq!(err.kind, TxPoolAdmitErrorKind::Rejected);
        assert!(err.message.contains("CORE_EXT spend pre-ACTIVE"));
    }

    #[test]
    fn helper_errors_preserve_kind_and_message() {
        let conflict_err = conflict("conflict");
        assert_eq!(conflict_err.kind, TxPoolAdmitErrorKind::Conflict);
        assert_eq!(conflict_err.to_string(), "conflict");

        let rejected_err = rejected("rejected");
        assert_eq!(rejected_err.kind, TxPoolAdmitErrorKind::Rejected);
        assert_eq!(rejected_err.to_string(), "rejected");

        let unavailable_err = unavailable("unavailable");
        assert_eq!(unavailable_err.kind, TxPoolAdmitErrorKind::Unavailable);
        assert_eq!(unavailable_err.to_string(), "unavailable");
    }

    #[test]
    fn reject_oversized_payload_allows_under_limit() {
        let tx = Tx {
            version: TX_WIRE_VERSION,
            tx_kind: 0,
            tx_nonce: 1,
            inputs: vec![],
            outputs: vec![TxOutput {
                value: 1,
                covenant_type: COV_TYPE_EXT,
                covenant_data: core_ext_covenant_data_with_payload(5, &[0u8; 32]),
            }],
            locktime: 0,
            da_commit_core: None,
            da_chunk_core: None,
            witness: vec![],
            da_payload: vec![],
        };
        assert!(reject_core_ext_tx_oversized_payload(&tx, 48).is_ok());
    }

    #[test]
    fn reject_oversized_payload_allows_at_limit() {
        let tx = Tx {
            version: TX_WIRE_VERSION,
            tx_kind: 0,
            tx_nonce: 1,
            inputs: vec![],
            outputs: vec![TxOutput {
                value: 1,
                covenant_type: COV_TYPE_EXT,
                covenant_data: core_ext_covenant_data_with_payload(5, &[0u8; 48]),
            }],
            locktime: 0,
            da_commit_core: None,
            da_chunk_core: None,
            witness: vec![],
            da_payload: vec![],
        };
        assert!(reject_core_ext_tx_oversized_payload(&tx, 48).is_ok());
    }

    #[test]
    fn reject_oversized_payload_rejects_over_limit() {
        let tx = Tx {
            version: TX_WIRE_VERSION,
            tx_kind: 0,
            tx_nonce: 1,
            inputs: vec![],
            outputs: vec![TxOutput {
                value: 1,
                covenant_type: COV_TYPE_EXT,
                covenant_data: core_ext_covenant_data_with_payload(5, &[0u8; 49]),
            }],
            locktime: 0,
            da_commit_core: None,
            da_chunk_core: None,
            witness: vec![],
            da_payload: vec![],
        };
        let err = reject_core_ext_tx_oversized_payload(&tx, 48);
        assert!(err.is_err());
        assert!(err.unwrap_err().contains("exceeds policy limit"));
    }

    #[test]
    fn reject_oversized_payload_ignores_non_core_ext() {
        let tx = Tx {
            version: TX_WIRE_VERSION,
            tx_kind: 0,
            tx_nonce: 1,
            inputs: vec![],
            outputs: vec![TxOutput {
                value: 1,
                covenant_type: COV_TYPE_P2PK,
                covenant_data: vec![0u8; 100],
            }],
            locktime: 0,
            da_commit_core: None,
            da_chunk_core: None,
            witness: vec![],
            da_payload: vec![],
        };
        assert!(reject_core_ext_tx_oversized_payload(&tx, 1).is_ok());
    }

    #[test]
    fn reject_oversized_payload_zero_limit_disables() {
        let tx = Tx {
            version: TX_WIRE_VERSION,
            tx_kind: 0,
            tx_nonce: 1,
            inputs: vec![],
            outputs: vec![TxOutput {
                value: 1,
                covenant_type: COV_TYPE_EXT,
                covenant_data: core_ext_covenant_data_with_payload(5, &[0u8; 100]),
            }],
            locktime: 0,
            da_commit_core: None,
            da_chunk_core: None,
            witness: vec![],
            da_payload: vec![],
        };
        assert!(reject_core_ext_tx_oversized_payload(&tx, 0).is_ok());
    }

    #[test]
    fn reject_oversized_payload_empty_payload_allowed() {
        let tx = Tx {
            version: TX_WIRE_VERSION,
            tx_kind: 0,
            tx_nonce: 1,
            inputs: vec![],
            outputs: vec![TxOutput {
                value: 1,
                covenant_type: COV_TYPE_EXT,
                covenant_data: core_ext_covenant_data_with_payload(5, &[]),
            }],
            locktime: 0,
            da_commit_core: None,
            da_chunk_core: None,
            witness: vec![],
            da_payload: vec![],
        };
        assert!(reject_core_ext_tx_oversized_payload(&tx, 1).is_ok());
    }

    // ----- Stage C DA fee policy parity tests (Linear RUB-122) -----
    //
    // These tests pin the Stage C admission predicate
    //
    //   required_fee = max(relay_fee_floor, da_fee_floor + da_surcharge)
    //
    // bit-for-bit against the merged Go reference
    // (clients/go/node/policy_da_anchor.go::RejectDaAnchorTxPolicy) and prove
    // that prior surcharge-only behavior, zero-surcharge bypass, relay/DA
    // dominance, overflow fail-closed, and non-DA short-circuit all behave
    // identically in Rust. Tests build a real signed DA transaction, then
    // call `reject_da_anchor_tx_policy` directly with crafted rate inputs to
    // exercise both accepted and rejected cases against the actual fee
    // computed by `compute_fee_no_verify`.

    fn build_signed_da_tx_with_fee(
        fee: u64,
        da_payload: Vec<u8>,
    ) -> (ChainState, Vec<u8>, u64, u64) {
        let output_value = 100u64;
        let input_value = output_value
            .checked_add(fee)
            .expect("test fee + output_value must not overflow");
        let (state, raw) = signed_p2pk_state_and_tx(
            input_value,
            vec![TxOutput {
                value: output_value,
                covenant_type: COV_TYPE_P2PK,
                covenant_data: p2pk_covenant_data_for_pubkey(&vec![0x23; 2592]),
            }],
            0x02,
            Some(DaChunkCore {
                da_id: [0x55; 32],
                chunk_index: 0,
                chunk_hash: [0x66; 32],
            }),
            da_payload,
        );
        let (tx, _, _, _) = parse_tx(&raw).expect("parse signed DA tx");
        let (weight, da_bytes, _) =
            tx_weight_and_stats_public(&tx).expect("tx_weight_and_stats_public");
        assert!(da_bytes > 0, "test setup must produce DA tx");
        assert!(weight > 0, "test setup must produce non-zero weight");
        (state, raw, weight, da_bytes)
    }

    fn run_da_policy(
        raw: &[u8],
        state: &ChainState,
        current_min: u64,
        min_da: u64,
        surcharge: u64,
    ) -> Result<(), String> {
        let (tx, _, _, _) = parse_tx(raw).expect("parse tx");
        reject_da_anchor_tx_policy(&tx, &state.utxos, current_min, min_da, surcharge)
    }

    #[test]
    fn stage_c_da_admit_with_fee_equal_required_da_dominant() {
        // current_min=0 zeroes the relay term; min_da=1, surcharge=1 makes
        // da_required = 2 * da_bytes the dominant term. Fee = 2*da_bytes
        // exactly admits (Stage C accepts fee == required).
        let (_, _, _, da_bytes) = build_signed_da_tx_with_fee(0, vec![0x77; 64]);
        let required = da_bytes
            .checked_mul(2)
            .expect("test setup u64 mul not overflow");
        let (state, raw, weight, da_bytes2) = build_signed_da_tx_with_fee(required, vec![0x77; 64]);
        // weight/da_bytes are deterministic across reruns with the same shape.
        assert_eq!(da_bytes2, da_bytes, "DA bytes deterministic");
        assert!(weight > 0);
        run_da_policy(&raw, &state, 0, 1, 1).expect("fee == required should admit");
    }

    #[test]
    fn stage_c_da_reject_with_fee_one_below_required_da_dominant() {
        let (_, _, _, da_bytes) = build_signed_da_tx_with_fee(0, vec![0x77; 64]);
        let required = da_bytes
            .checked_mul(2)
            .expect("test setup u64 mul not overflow");
        let (state, raw, _, _) = build_signed_da_tx_with_fee(required - 1, vec![0x77; 64]);
        let err =
            run_da_policy(&raw, &state, 0, 1, 1).expect_err("fee == required - 1 must reject");
        assert!(
            err.starts_with("DA fee below Stage C floor"),
            "expected Stage C error, got: {err}"
        );
        assert!(err.contains(&format!("required_fee={required}")));
        assert!(err.contains(&format!("da_fee_floor={da_bytes}")));
        assert!(err.contains(&format!("da_surcharge={da_bytes}")));
        assert!(err.contains(&format!("da_payload_len={da_bytes}")));
    }

    #[test]
    fn stage_c_da_zero_surcharge_still_enforces_min_da_fee_rate() {
        // Surcharge-zero regression: prior surcharge-only Rust returned Ok
        // unconditionally when da_surcharge_per_byte == 0. Stage C requires
        // da_floor (= da_bytes * min_da_fee_rate) to still bind.
        let (_, _, _, da_bytes) = build_signed_da_tx_with_fee(0, vec![0x77; 64]);
        let min_da_rate = 7u64;
        let required = da_bytes
            .checked_mul(min_da_rate)
            .expect("test setup u64 mul not overflow");
        // accept at exact floor
        let (state_ok, raw_ok, _, _) = build_signed_da_tx_with_fee(required, vec![0x77; 64]);
        run_da_policy(&raw_ok, &state_ok, 0, min_da_rate, 0)
            .expect("fee == da_floor with surcharge=0 admits");
        // reject one below
        let (state_bad, raw_bad, _, _) = build_signed_da_tx_with_fee(required - 1, vec![0x77; 64]);
        let err = run_da_policy(&raw_bad, &state_bad, 0, min_da_rate, 0)
            .expect_err("fee == da_floor - 1 with surcharge=0 must reject");
        assert!(err.contains("DA fee below Stage C floor"), "got: {err}");
        assert!(err.contains("da_surcharge=0"));
    }

    #[test]
    fn stage_c_da_zero_min_rate_still_enforces_surcharge() {
        // Symmetric regression: prior Rust short-circuited when
        // da_surcharge_per_byte == 0 but did not run da_floor at all. Stage C
        // separates the two terms; zeroing min_da_fee_rate must still leave
        // surcharge enforced.
        let (_, _, _, da_bytes) = build_signed_da_tx_with_fee(0, vec![0x77; 64]);
        let surcharge_rate = 5u64;
        let required = da_bytes
            .checked_mul(surcharge_rate)
            .expect("test setup u64 mul not overflow");
        let (state_bad, raw_bad, _, _) = build_signed_da_tx_with_fee(required - 1, vec![0x77; 64]);
        let err = run_da_policy(&raw_bad, &state_bad, 0, 0, surcharge_rate)
            .expect_err("fee == surcharge - 1 with min_da_fee_rate=0 must reject");
        assert!(err.contains("DA fee below Stage C floor"), "got: {err}");
        assert!(err.contains("da_fee_floor=0"));
        assert!(err.contains(&format!("da_surcharge={required}")));
    }

    #[test]
    fn stage_c_da_relay_floor_dominates_when_higher() {
        let (_, _, weight, da_bytes) = build_signed_da_tx_with_fee(0, vec![0x77; 8]);
        // Pick current_min so weight*current_min strictly > da_bytes*1 (min_da=1, surcharge=0).
        // For typical signed P2PK + 8-byte DA payload, weight is several thousand and
        // da_bytes is small (~10), so current_min=2 makes relay dominate.
        let current_min = 2u64;
        let relay_floor = weight
            .checked_mul(current_min)
            .expect("test setup u64 mul not overflow");
        let da_required = da_bytes;
        assert!(
            relay_floor > da_required,
            "test premise: relay_floor={relay_floor} must dominate da_required={da_required}"
        );
        let (state_bad, raw_bad, _, _) =
            build_signed_da_tx_with_fee(relay_floor - 1, vec![0x77; 8]);
        let err = run_da_policy(&raw_bad, &state_bad, current_min, 1, 0)
            .expect_err("fee == relay_floor - 1 must reject when relay dominates");
        assert!(err.contains("DA fee below Stage C floor"));
        assert!(err.contains(&format!("required_fee={relay_floor}")));
        assert!(err.contains(&format!("relay_fee_floor={relay_floor}")));
        // exact-floor accept
        let (state_ok, raw_ok, _, _) = build_signed_da_tx_with_fee(relay_floor, vec![0x77; 8]);
        run_da_policy(&raw_ok, &state_ok, current_min, 1, 0).expect("fee == relay_floor admits");
    }

    #[test]
    fn stage_c_da_floor_dominates_when_higher() {
        let (_, _, weight, da_bytes) = build_signed_da_tx_with_fee(0, vec![0x77; 64]);
        // Make da_required strictly larger than relay_floor: pick min_da_rate
        // so da_bytes*min_da_rate > weight (with current_min=1, surcharge=0).
        let min_da = (weight / da_bytes) + 2;
        let da_required = da_bytes
            .checked_mul(min_da)
            .expect("test setup u64 mul not overflow");
        assert!(
            da_required > weight,
            "test premise: da_required={da_required} must dominate weight={weight}"
        );
        let (state_bad, raw_bad, _, _) =
            build_signed_da_tx_with_fee(da_required - 1, vec![0x77; 64]);
        let err = run_da_policy(&raw_bad, &state_bad, 1, min_da, 0)
            .expect_err("fee == da_required - 1 must reject when DA dominates");
        assert!(err.contains("DA fee below Stage C floor"));
        assert!(err.contains(&format!("required_fee={da_required}")));
        assert!(err.contains(&format!("da_fee_floor={da_required}")));
    }

    #[test]
    fn stage_c_da_overflow_relay_floor_rejects_fail_closed() {
        let (state, raw, weight, _) = build_signed_da_tx_with_fee(1_000_000, vec![0x77; 8]);
        let err = run_da_policy(&raw, &state, u64::MAX, 1, 1)
            .expect_err("u64::MAX * weight must overflow");
        assert!(err.starts_with("relay fee floor overflow"), "got: {err}");
        assert!(err.contains(&format!("weight={weight}")));
    }

    #[test]
    fn stage_c_da_overflow_da_floor_rejects_fail_closed() {
        let (state, raw, _, da_bytes) = build_signed_da_tx_with_fee(1_000_000, vec![0x77; 8]);
        let err = run_da_policy(&raw, &state, 1, u64::MAX, 1)
            .expect_err("u64::MAX * da_bytes must overflow");
        assert!(err.starts_with("DA fee floor overflow"), "got: {err}");
        assert!(err.contains(&format!("da_payload_len={da_bytes}")));
    }

    #[test]
    fn stage_c_da_overflow_da_surcharge_rejects_fail_closed() {
        let (state, raw, _, da_bytes) = build_signed_da_tx_with_fee(1_000_000, vec![0x77; 8]);
        let err = run_da_policy(&raw, &state, 1, 1, u64::MAX)
            .expect_err("u64::MAX * da_bytes must overflow");
        assert!(err.starts_with("DA surcharge overflow"), "got: {err}");
        assert!(err.contains(&format!("da_payload_len={da_bytes}")));
    }

    #[test]
    fn stage_c_da_overflow_da_required_addition_rejects_fail_closed() {
        // Pick min_da and surcharge each just below u64::MAX/da_bytes so each
        // mul stays in range, but their sum (da_floor + da_surcharge) overflows.
        let (_, _, _, da_bytes) = build_signed_da_tx_with_fee(0, vec![0x77; 8]);
        let half = u64::MAX / da_bytes;
        let min_da = half;
        let surcharge = half;
        // da_floor = da_bytes * half; da_surcharge = da_bytes * half.
        // Each fits. Sum = 2 * da_bytes * half ~ 2*u64::MAX/2 -> overflow on add.
        let da_floor = da_bytes
            .checked_mul(min_da)
            .expect("test premise: each mul fits");
        let da_surcharge = da_bytes
            .checked_mul(surcharge)
            .expect("test premise: each mul fits");
        assert!(
            da_floor.checked_add(da_surcharge).is_none(),
            "test premise: addition must overflow"
        );
        let (state, raw, _, _) = build_signed_da_tx_with_fee(1_000_000, vec![0x77; 8]);
        let err =
            run_da_policy(&raw, &state, 0, min_da, surcharge).expect_err("addition must overflow");
        assert!(err.starts_with("DA required fee overflow"), "got: {err}");
    }

    #[test]
    fn stage_c_non_da_tx_short_circuits_admit() {
        // Non-DA tx (tx_kind=0, no DaChunkCore, no da_payload) must be admitted
        // by reject_da_anchor_tx_policy without applying any DA term, even with
        // aggressive rate config. Non-DA relay-fee floor enforcement now lives
        // in the free validate_fee_floor predicate, invoked inside
        // apply_post_consensus_policy_with_floor (called from admit_with_metadata
        // AFTER apply_policy returns Ok) — mirroring Go's
        // validateCapacityAdmissionLocked → validateFeeFloorLocked split at
        // clients/go/node/mempool.go:1018-1024. This helper only validates the
        // DA half of the Stage C contract and intentionally short-circuits for
        // non-DA inputs.
        let (state, raw) = signed_p2pk_state_and_tx(
            10,
            vec![TxOutput {
                value: 9,
                covenant_type: COV_TYPE_P2PK,
                covenant_data: p2pk_covenant_data_for_pubkey(&vec![0x23; 2592]),
            }],
            0x00,
            None,
            Vec::new(),
        );
        run_da_policy(&raw, &state, u64::MAX, u64::MAX, u64::MAX)
            .expect("non-DA tx admits regardless of DA rate config");
    }

    #[test]
    fn stage_c_da_zero_rates_admit_without_fee_compute() {
        // DA tx with all three rates = 0: relay_floor=0, da_floor=0,
        // da_surcharge=0, required=0. Stage C admits without computing fee.
        //
        // Proof assertion: state.utxos is cleared before run_da_policy is
        // called, so compute_fee_no_verify (which dereferences each input
        // outpoint via utxos.get(...) and returns Err("missing utxo") on
        // None) would propagate that error. The test asserts run_da_policy
        // returns Ok(()), which is reachable only through the
        // `if required == 0 { return Ok(()); }` short-circuit branch in
        // reject_da_anchor_tx_policy that bypasses compute_fee_no_verify
        // entirely.
        let (mut state, raw, _, _) = build_signed_da_tx_with_fee(1_000_000, vec![0x77; 8]);
        state.utxos.clear(); // strip utxos so any fee compute would error
        run_da_policy(&raw, &state, 0, 0, 0)
            .expect("required=0 admits without compute_fee_no_verify");
    }

    // ====================================================================
    // RUB-162 Phase A regression tests — section header
    //
    // Tests in this section exercise the four Phase A invariants from
    // GitHub #1407 through the public TxPool::admit / admit_with_metadata
    // entrypoint (NOT helper-only direct calls — that was the reviewer
    // concern). Each individual test below carries its own Proof
    // assertion in the doc-comment naming the exact assertion mechanism;
    // see the `rub162_*` test functions for specifics.
    // ====================================================================

    use super::{fee_rate_below_floor, validate_fee_floor};

    /// P1 #4 fix — DA tx whose DA fee passes but rolling relay floor fails
    /// must return Unavailable from validate_fee_floor, NOT Rejected
    /// from reject_da_anchor_tx_policy. Mirrors Go applyPolicyAgainstState
    /// behaviour (clients/go/node/mempool.go:798-833): mempool admit passes
    /// currentMempoolMinFeeRate=0 to the DA helper so the relay-floor
    /// classification is owned uniformly by validateFeeFloorLocked
    /// (Unavailable, transient/retryable).
    ///
    /// Reachability: tx is well-formed (parses, basic+canonical checks pass,
    /// inputs not double-spent), DA-side floor configured to 0 so DA helper
    /// short-circuits Ok, then validate_fee_floor rejects on the
    /// rolling floor. The TxPoolConfig used has policy_min_da_fee_rate=0 and
    /// policy_da_surcharge_per_byte=0, so the DA helper's required term
    /// is 0 — the only failing path is the new validate_fee_floor.
    #[test]
    fn rub162_admit_da_below_rolling_floor_returns_unavailable_not_rejected() {
        // Build a DA tx with low fee_rate (fee=1, weight ≈ 7653 from ML-DSA
        // witness + 64-byte da_payload).
        let (state, raw, _weight, _da_bytes) = build_signed_da_tx_with_fee(1, vec![0x77; 64]);

        // cfg with relay floor = DEFAULT (1) and DA-side terms zeroed so
        // the DA helper's `required` collapses to 0 (short-circuit Ok).
        let mut pool = TxPool::new_with_config(TxPoolConfig {
            policy_current_mempool_min_fee_rate: DEFAULT_MEMPOOL_MIN_FEE_RATE,
            policy_min_da_fee_rate: 0,
            policy_da_surcharge_per_byte: 0,
            ..TxPoolConfig::default()
        });

        let err = pool
            .admit(&raw, &state, None, [0u8; 32])
            .expect_err("DA tx with fee=1, weight≈7653 must fail relay floor");
        assert_eq!(
            err.kind,
            TxPoolAdmitErrorKind::Unavailable,
            "P1 #4 fix: relay-floor failure returns Unavailable (transient/retryable), NOT Rejected (terminal)"
        );
        assert!(
            err.message.contains("mempool fee below rolling minimum"),
            "error message must come from validate_fee_floor, not DA helper; got: {}",
            err.message
        );
    }

    /// P1 #4 baseline preservation — DA tx whose DA fee fails the DA-side
    /// floor (independent of the rolling relay floor) still returns
    /// Rejected from reject_da_anchor_tx_policy. The Phase A change must
    /// NOT regress DA-floor classification.
    ///
    /// Reachability: tx is well-formed; DA-side terms force a non-zero
    /// required fee that the tx fails. apply_policy returns Err mapped
    /// to Rejected before validate_fee_floor is reached.
    #[test]
    fn rub162_admit_da_below_da_floor_returns_rejected() {
        // Per RUB-162 RESP P1 #4 ordering: apply_policy (containing the
        // DA helper with cfg-zero override) runs BEFORE
        // validate_fee_floor. To pin the DA-side rejection path,
        // build a fixture that FAILS the DA-side terms
        // (fee < da_bytes * (min_da + surcharge)). The fixture also
        // PASSES the relay floor (fee >= weight) defensively — under
        // WIP #6 ordering apply_policy rejects first regardless of
        // floor compliance, but the headroom keeps the fixture stable
        // if a future change reorders the validators again.
        let (state, raw, weight, da_bytes) = build_signed_da_tx_with_fee(8_000, vec![0x77; 64]);
        assert!(
            8_000 >= weight,
            "fee 8000 must >= weight {weight} to pass relay-floor (defensive headroom)"
        );
        // DA-required = da_bytes * (min_da + surcharge). With ~70 bytes
        // and 200+200, da_required ≈ 28000 ≫ fee=8000.
        let min_da = 200u64;
        let surcharge = 200u64;
        let required_da = da_bytes
            .checked_mul(min_da + surcharge)
            .expect("test arithmetic");
        assert!(
            8_000 < required_da,
            "fee 8000 must be below DA-required {required_da} so DA helper rejects"
        );
        let mut pool = TxPool::new_with_config(TxPoolConfig {
            policy_current_mempool_min_fee_rate: DEFAULT_MEMPOOL_MIN_FEE_RATE,
            policy_min_da_fee_rate: min_da,
            policy_da_surcharge_per_byte: surcharge,
            ..TxPoolConfig::default()
        });
        let err = pool
            .admit(&raw, &state, None, [0u8; 32])
            .expect_err("DA tx with fee below DA-required must fail DA Stage C floor");
        assert_eq!(
            err.kind,
            TxPoolAdmitErrorKind::Rejected,
            "DA-side failure must remain Rejected (terminal); preserved RUB-122 behaviour"
        );
        assert!(
            err.message.contains("DA fee below Stage C floor"),
            "error must come from DA helper, not floor check; got: {}",
            err.message
        );
    }

    /// P1 #4 happy path — DA tx that passes BOTH the DA-side floor AND
    /// the rolling relay floor admits cleanly.
    #[test]
    fn rub162_admit_da_above_both_floors_admits_with_indexes() {
        // weight ≈ 7653 from ML-DSA witness + 64-byte da_payload. Pick
        // fee that is comfortably above both floors:
        //   relay floor: weight * DEFAULT (1) ≈ 7653
        //   DA floor: da_bytes * 1 + da_bytes * 1 = 2 * da_bytes
        // Use fee = 30000 (well above both for da_bytes around 70-100).
        let (state, raw, weight, da_bytes) = build_signed_da_tx_with_fee(30_000, vec![0x77; 64]);
        assert!(
            weight <= 30_000,
            "fee must cover relay floor (weight={weight})"
        );
        assert!(
            2 * da_bytes <= 30_000,
            "fee must cover DA term ({da_bytes} bytes)"
        );

        let mut pool = TxPool::new_with_config(TxPoolConfig {
            policy_current_mempool_min_fee_rate: DEFAULT_MEMPOOL_MIN_FEE_RATE,
            policy_min_da_fee_rate: 1,
            policy_da_surcharge_per_byte: 1,
            ..TxPoolConfig::default()
        });
        let txid = pool
            .admit(&raw, &state, None, [0u8; 32])
            .expect("DA tx above both floors must admit");
        assert_eq!(pool.len(), 1);
        assert!(pool.txs.contains_key(&txid));
    }

    /// P1 #2 atomicity through public admit — Unavailable on relay-floor
    /// failure leaves all four pool indexes (txs / spenders / heap_seqs /
    /// worst_heap) unchanged AND the lazy worst_heap filter
    /// (current_worst_txid) unchanged. This proves admit_with_metadata
    /// performs the rolling-floor classification BEFORE any insert_entry
    /// call.
    ///
    /// Proof assertion: pre-populate via the production `insert_entry`
    /// path (so all four indexes plus next_heap_id receive the resident
    /// snapshot); capture every observable baseline; trigger the
    /// rolling-floor rejection through the public admit entry; assert
    /// the four index lengths + worst_heap length + next_heap_id +
    /// current_worst_txid lookup are all unchanged.
    #[test]
    fn rub162_admit_atomicity_unavailable_floor_leaves_no_partial_state() {
        let (state, raw, _weight, _da_bytes) = build_signed_da_tx_with_fee(1, vec![0x77; 64]);
        let mut pool = TxPool::new_with_config(TxPoolConfig {
            policy_current_mempool_min_fee_rate: DEFAULT_MEMPOOL_MIN_FEE_RATE,
            policy_min_da_fee_rate: 0,
            policy_da_surcharge_per_byte: 0,
            ..TxPoolConfig::default()
        });
        // Pre-populate via the production `insert_entry` path so all four
        // indexes (txs + spenders + heap_seqs + worst_heap) AND next_heap_id
        // receive the resident state — required to detect any spurious
        // mutation of cross-tx state during the failed admit.
        let resident_txid = [0xAB; 32];
        let resident_input = Outpoint {
            txid: [0x77; 32],
            vout: 0,
        };
        pool.insert_entry(
            resident_txid,
            TxPoolEntry {
                raw: vec![0x01],
                inputs: vec![resident_input.clone()],
                fee: 100,
                weight: 1,
                size: 1,
            },
        );
        let pool_len_before = pool.len();
        let spenders_before = pool.spenders.len();
        let heap_seqs_before = pool.heap_seqs.len();
        let worst_heap_before = pool.worst_heap.len();
        let next_heap_id_before = pool.next_heap_id;
        let worst_txid_before = pool.current_worst_txid();

        let err = pool
            .admit(&raw, &state, None, [0u8; 32])
            .expect_err("must fail rolling floor");
        assert_eq!(err.kind, TxPoolAdmitErrorKind::Unavailable);

        // Atomicity: every observable pool surface UNCHANGED across the
        // failed admit (txs / spenders / heap_seqs / worst_heap len +
        // next_heap_id + current_worst_txid lookup).
        assert_eq!(pool.len(), pool_len_before, "txs unchanged on Err");
        assert_eq!(
            pool.spenders.len(),
            spenders_before,
            "spenders unchanged on Err"
        );
        assert_eq!(
            pool.heap_seqs.len(),
            heap_seqs_before,
            "heap_seqs unchanged on Err"
        );
        assert_eq!(
            pool.worst_heap.len(),
            worst_heap_before,
            "worst_heap unchanged on Err (no spurious WorstEntryKey push)"
        );
        assert_eq!(
            pool.next_heap_id, next_heap_id_before,
            "next_heap_id unchanged (no partial WorstEntryKey reservation)"
        );
        assert_eq!(
            pool.current_worst_txid(),
            worst_txid_before,
            "current_worst_txid lookup unchanged (resident still observable)"
        );
        assert!(pool.txs.contains_key(&resident_txid), "resident untouched");
        assert_eq!(
            pool.spenders.get(&resident_input),
            Some(&resident_txid),
            "resident spenders entry untouched"
        );
    }

    /// P1 #3 cleanup state symmetry — `evict_txids` removes the three
    /// eager index maps that `insert_entry` adds (txs + spenders +
    /// heap_seqs). The fourth structure `worst_heap` is intentionally
    /// lazy: `remove_entry` does NOT pop the heap entry directly;
    /// instead `compact_worst_heap_if_needed` rebuilds when the heap
    /// grows past 2x the live count, and `current_worst_txid` filters
    /// stale entries via the heap_seqs lookup. The test below pins both
    /// the eager map clears AND the lazy filter (current_worst_txid is
    /// None after eviction even though the heap entry is still
    /// physically present).
    ///
    /// This is a regression guard: if a future change adds a new index
    /// (e.g. wtxids) maintained by insert_entry, evict_txids must mirror
    /// it via the same delete path; this test will then need extension
    /// rather than letting the asymmetry leak silently.
    #[test]
    fn rub162_evict_txids_clears_all_indexes_added_by_insert_entry() {
        let mut pool = TxPool::new_with_config(TxPoolConfig {
            policy_current_mempool_min_fee_rate: 0,
            ..TxPoolConfig::default()
        });
        let txid = [0xC1; 32];
        let outpoint = Outpoint {
            txid: [0xAA; 32],
            vout: 0,
        };
        // Insert via the same private path admit_with_metadata uses so
        // the test shares the production insert side.
        pool.insert_entry(
            txid,
            TxPoolEntry {
                raw: vec![0xff],
                inputs: vec![outpoint.clone()],
                fee: 100,
                weight: 1,
                size: 1,
            },
        );
        assert!(pool.txs.contains_key(&txid));
        assert_eq!(pool.spenders.get(&outpoint), Some(&txid));
        assert!(pool.heap_seqs.contains_key(&txid));

        pool.evict_txids(&[txid]);
        assert!(!pool.txs.contains_key(&txid), "txs cleared");
        assert!(!pool.spenders.contains_key(&outpoint), "spenders cleared");
        assert!(!pool.heap_seqs.contains_key(&txid), "heap_seqs cleared");
        // Lazy worst_heap behaviour: the physical heap entry MAY still
        // exist (compaction is delayed via 2x threshold), but the
        // public lookup must filter it out via the heap_seqs guard.
        assert!(
            pool.current_worst_txid().is_none(),
            "current_worst_txid hides the evicted entry via the heap_seqs guard"
        );
    }

    /// P1 #3 cleanup state symmetry — `remove_conflicting_outpoints`
    /// (the public path used by reorg/conflict cleanup) routes through
    /// `evict_txids` and clears the same indexes. The test populates a
    /// resident, builds a conflicting outpoint, and asserts symmetric
    /// removal.
    #[test]
    fn rub162_remove_conflicting_outpoints_clears_all_indexes() {
        let mut pool = TxPool::new_with_config(TxPoolConfig {
            policy_current_mempool_min_fee_rate: 0,
            ..TxPoolConfig::default()
        });
        let txid = [0xC2; 32];
        let outpoint = Outpoint {
            txid: [0xBB; 32],
            vout: 0,
        };
        pool.insert_entry(
            txid,
            TxPoolEntry {
                raw: vec![0xff],
                inputs: vec![outpoint.clone()],
                fee: 100,
                weight: 1,
                size: 1,
            },
        );

        // Conflict feed contains the resident's outpoint.
        pool.remove_conflicting_outpoints(std::slice::from_ref(&outpoint));
        assert!(
            !pool.txs.contains_key(&txid),
            "resident removed on conflict"
        );
        assert!(
            !pool.spenders.contains_key(&outpoint),
            "spenders cleared on conflict"
        );
        assert!(
            !pool.heap_seqs.contains_key(&txid),
            "heap_seqs cleared on conflict"
        );
    }

    /// P1 #4 helper unit test — `fee_rate_below_floor` is a u128 cross-mul
    /// predicate matching Go `feeRateBelowFloor`
    /// (clients/go/node/mempool.go:1421-1434), including the in-helper
    /// `floor < DefaultMempoolMinFeeRate` clamp at
    /// clients/go/node/mempool.go:1425-1427. Calling with floor=0
    /// promotes to DEFAULT_MEMPOOL_MIN_FEE_RATE
    /// before the cross-mul, so a fee=0 / weight=100 / floor=0 input
    /// rejects (required becomes 100*1=100 post-clamp, fee<100).
    ///
    /// Proof assertion: assertions below pin the documented Go branches:
    /// - weight=0 always returns true (uncomputable rate)
    /// - floor=0 + non-zero weight clamps to DEFAULT and uses required=weight*1
    /// - exact-floor (fee == weight*floor) returns false
    /// - one-below-floor returns true
    /// - u128 boundary (u64::MAX*u64::MAX) lossless
    #[test]
    fn rub162_fee_rate_below_floor_helper_branches() {
        // Zero weight: always below floor.
        assert!(fee_rate_below_floor(u64::MAX, 0, 1));
        // Zero floor: clamps to DEFAULT (1). For weight=100: required=100.
        // fee=0 < 100 → true; fee=99 < 100 → true; fee=100 == 100 → false.
        assert!(fee_rate_below_floor(0, 100, 0));
        assert!(fee_rate_below_floor(99, 100, 0));
        assert!(!fee_rate_below_floor(100, 100, 0));
        // Exact floor: not below.
        assert!(!fee_rate_below_floor(100, 100, 1));
        // One below floor.
        assert!(fee_rate_below_floor(99, 100, 1));
        // u128 boundary: required = u64::MAX * u64::MAX. Fits u128, no wrap.
        assert!(fee_rate_below_floor(u64::MAX, u64::MAX, 2));
        assert!(!fee_rate_below_floor(u64::MAX, u64::MAX, 1));
        // Concrete 7653 pin (matches the conformance fixture's weight).
        assert!(fee_rate_below_floor(10, 7653, 1));
        assert!(!fee_rate_below_floor(7653, 7653, 1));
    }

    /// P1 #4 + clamp regression — `validate_fee_floor` propagates
    /// a cfg-seeded zero into `fee_rate_below_floor`, which itself clamps
    /// to DEFAULT_MEMPOOL_MIN_FEE_RATE per Go `feeRateBelowFloor`
    /// (clients/go/node/mempool.go:1421-1434, with the in-helper clamp
    /// at lines 1425-1427). The error message surfaces the post-clamp
    /// value so operators see the actual decision basis.
    #[test]
    fn rub162_validate_fee_floor_clamps_cfg_zero_to_default() {
        // fee=0 weight=1 cfg_floor=0: helper clamps floor 0 → DEFAULT (1);
        // required = 1*1 = 1; fee<1 → reject.
        let err = validate_fee_floor(0, 1, 0)
            .expect_err("helper clamp must enforce DEFAULT even when cfg=0");
        assert_eq!(err.kind, TxPoolAdmitErrorKind::Unavailable);
        assert!(err.message.contains("min_fee_rate=1"));
        // fee=1 weight=1 cfg_floor=0: exact floor passes after clamp.
        validate_fee_floor(1, 1, 0).expect("exact floor passes");
    }

    /// PR-1410 wave-2 fix — relay_metadata must NOT be weaker than
    /// admit_with_metadata. The cfg-zero override before apply_policy
    /// (clients/go/node/mempool.go:823) preserves DA-side error class
    /// isolation, but Rust's prior implementation skipped the rolling
    /// relay floor entirely on the relay path. That created a real
    /// production divergence: `tx_relay::handle_received_tx` uses
    /// `relay_metadata` as the gate before re-announcing, so a DA tx
    /// that pays the DA-side floor but is below the rolling relay
    /// floor was propagated through the network even though
    /// `TxPool::admit` rejected the same tx. Go avoids the divergence
    /// in the full node by re-running mempool admission via
    /// `CanonicalMempoolRelayMetadata` + `CanonicalMempoolTxPool.Put`;
    /// the equivalent here is to call the same `validate_fee_floor`
    /// predicate inside `relay_metadata` after `apply_policy` succeeds
    /// (controller decision option-c per PR #1410 thread fix).
    ///
    /// Proof assertion: same DA tx, same TxPoolConfig with non-zero
    /// rolling floor + DA-side terms; admit returns Unavailable; relay
    /// metadata ALSO returns Unavailable with the same message — they
    /// must surface the same classification for the same tx so peer
    /// relay never propagates a tx the local mempool refuses to admit.
    #[test]
    fn rub162_relay_metadata_da_below_rolling_floor_returns_unavailable_matching_admit() {
        // weight ≈ 7653; DA-required = 2 * da_bytes (≈ 70 bytes ⇒ 140);
        // pick fee that beats DA-required but is well below relay floor
        // (fee=1000 < weight=7653 ⇒ relay-floor reject on both paths).
        let (state, raw, weight, da_bytes) = build_signed_da_tx_with_fee(1_000, vec![0x77; 64]);
        assert!(
            1_000 >= 2 * da_bytes,
            "test setup must let DA-required fit fee: 2*{da_bytes} <= 1000"
        );
        assert!(
            1_000 < weight,
            "test setup must put fee below relay floor: 1000 < weight={weight}"
        );
        let cfg = TxPoolConfig {
            policy_current_mempool_min_fee_rate: DEFAULT_MEMPOOL_MIN_FEE_RATE,
            policy_min_da_fee_rate: 1,
            policy_da_surcharge_per_byte: 1,
            ..TxPoolConfig::default()
        };
        // admit must reject with Unavailable from validate_fee_floor.
        let mut pool = TxPool::new_with_config(cfg.clone());
        let admit_err = pool
            .admit(&raw, &state, None, [0u8; 32])
            .expect_err("admit should reject below relay floor");
        assert_eq!(admit_err.kind, TxPoolAdmitErrorKind::Unavailable);
        assert!(admit_err
            .message
            .contains("mempool fee below rolling minimum"));
        // relay_metadata MUST also reject with Unavailable — same
        // classification as admit so peer relay does not propagate a
        // tx the local mempool refuses.
        let relay_err = relay_metadata(&raw, &state, None, [0u8; 32], &cfg)
            .expect_err("relay_metadata must reject below rolling floor (matching admit)");
        assert_eq!(relay_err.kind, TxPoolAdmitErrorKind::Unavailable);
        assert!(relay_err
            .message
            .contains("mempool fee below rolling minimum"));
    }

    /// PR-1410 wave-2 — DA tx whose DA fee fails the DA-side floor
    /// must surface as Rejected (DA helper class, terminal) from
    /// relay_metadata, NOT collapsed into the new rolling-floor
    /// Unavailable class. Preserves DA-side error class isolation
    /// while the new validate_fee_floor call sits AFTER apply_policy.
    #[test]
    fn rub162_relay_metadata_da_below_da_floor_returns_rejected_not_unavailable() {
        // weight ≈ 7653; with min_da=200 + surcharge=200 + da_bytes≈70,
        // DA-required ≈ 28000 ≫ fee=8000. The fee=8000 also passes the
        // rolling floor (fee/weight ≈ 1.04 ≥ 1) so the DA-side reject
        // is the ONLY rejection path — proves DA classification
        // survives the new floor check.
        let (state, raw, weight, da_bytes) = build_signed_da_tx_with_fee(8_000, vec![0x77; 64]);
        let min_da = 200u64;
        let surcharge = 200u64;
        let required_da = da_bytes
            .checked_mul(min_da + surcharge)
            .expect("test arithmetic");
        assert!(
            8_000 < required_da,
            "test setup must put fee below DA-required: 8000 < {required_da}"
        );
        assert!(
            8_000 >= weight,
            "test setup must put fee above rolling floor: 8000 >= weight={weight}"
        );
        let cfg = TxPoolConfig {
            policy_current_mempool_min_fee_rate: DEFAULT_MEMPOOL_MIN_FEE_RATE,
            policy_min_da_fee_rate: min_da,
            policy_da_surcharge_per_byte: surcharge,
            ..TxPoolConfig::default()
        };
        let err = relay_metadata(&raw, &state, None, [0u8; 32], &cfg)
            .expect_err("relay_metadata must reject DA tx below DA-side floor");
        assert_eq!(
            err.kind,
            TxPoolAdmitErrorKind::Rejected,
            "DA-side rejection must remain terminal Rejected, NOT new rolling-floor Unavailable; got {:?}",
            err
        );
        assert!(
            err.message.contains("DA fee below Stage C floor"),
            "error must come from DA helper, not floor check; got: {}",
            err.message
        );
    }

    /// PR-1410 wave-2 — DA tx whose fee passes BOTH floors must yield
    /// relay metadata (Ok). Smoke for the post-fix happy path.
    #[test]
    fn rub162_relay_metadata_da_above_both_floors_returns_ok() {
        // fee = 30000; DA-required = da_bytes(70)*1*2 = 140; weight≈7653,
        // fee/weight ≈ 3.92 ≥ 1. Both floors pass.
        let (state, raw, _weight, _da_bytes) = build_signed_da_tx_with_fee(30_000, vec![0x77; 64]);
        let cfg = TxPoolConfig {
            policy_current_mempool_min_fee_rate: DEFAULT_MEMPOOL_MIN_FEE_RATE,
            policy_min_da_fee_rate: 1,
            policy_da_surcharge_per_byte: 1,
            ..TxPoolConfig::default()
        };
        let meta = relay_metadata(&raw, &state, None, [0u8; 32], &cfg)
            .expect("relay_metadata should succeed when both floors pass");
        assert!(meta.fee > 0);
        assert_eq!(meta.size, raw.len());
    }

    /// P1 #2 fix — fee-floor classification runs BEFORE pool-full
    /// ordering classification (Go `validateCapacityAdmissionLocked`
    /// order at clients/go/node/mempool.go:1020-1024). A sub-floor
    /// candidate against a full pool must surface the floor error,
    /// not the pool-full error.
    ///
    /// Proof assertion: build a candidate with fee/weight far below
    /// DEFAULT_MEMPOOL_MIN_FEE_RATE, fill the pool to capacity, then
    /// call admit. Expected: TxPoolAdmitErrorKind::Unavailable with
    /// "mempool fee below rolling minimum" message (NOT "tx pool full").
    #[test]
    fn rub162_admit_full_pool_below_floor_returns_floor_error_not_pool_full() {
        // Sub-floor candidate: input=10 / output=8 → fee=2, weight≈7653.
        let (state, raw) = signed_p2pk_state_and_tx(
            10,
            vec![TxOutput {
                value: 8,
                covenant_type: COV_TYPE_P2PK,
                covenant_data: p2pk_covenant_data_for_pubkey(&vec![0x88; 2592]),
            }],
            0x00,
            None,
            Vec::new(),
        );
        let mut pool = TxPool::new();
        // Fill pool to MAX so the pool-full ordering branch IS reachable.
        for idx in 0..MAX_TX_POOL_TRANSACTIONS {
            let mut key = [0u8; 32];
            key[..8].copy_from_slice(&(idx as u64 + 1).to_le_bytes());
            pool.txs.insert(
                key,
                TxPoolEntry {
                    raw: vec![0xff],
                    inputs: Vec::new(),
                    fee: 100,
                    weight: 1,
                    size: 1,
                },
            );
        }
        let err = pool.admit(&raw, &state, None, [0u8; 32]).unwrap_err();
        assert_eq!(err.kind, TxPoolAdmitErrorKind::Unavailable);
        assert!(
            err.message.contains("mempool fee below rolling minimum"),
            "P1 #2: floor error must win over pool-full ordering; got: {}",
            err.message
        );
        // Pool unchanged (atomicity preserved through the new ordering).
        assert_eq!(pool.txs.len(), MAX_TX_POOL_TRANSACTIONS);
    }

    /// RUB-162 cross-pollination ordering PIN — a tx that is BOTH
    /// sub-floor AND fails DA-side terms must classify as Rejected
    /// (apply_policy → DA helper fires first under WIP #6 ordering),
    /// NOT Unavailable (rolling floor would fire if it ran first).
    /// Mirrors Go addToMempoolLocked at clients/go/node/mempool.go:798-1024
    /// where applyPolicyAgainstState precedes validateCapacityAdmissionLocked
    /// → validateFeeFloorLocked.
    ///
    /// Proof assertion: build a DA tx whose fee is below BOTH the rolling
    /// floor AND the DA-required floor; admit returns
    /// `TxPoolAdmitErrorKind::Rejected` with the canonical
    /// `DA fee below Stage C floor` message (not the
    /// `mempool fee below rolling minimum` message).
    #[test]
    fn rub162_admit_sub_floor_da_anchor_classifies_as_da_rejected_not_floor_unavailable() {
        // fee=10 ≪ weight (≈70 = MIN witness for DA tx) ⇒ sub-floor.
        // Default conformance da_bytes ≈ 70. DA-required = da_bytes *
        // (min_da=200 + surcharge=200) = ~28_000 ≫ fee=10 ⇒ sub-DA.
        let (state, raw, weight, da_bytes) = build_signed_da_tx_with_fee(10, vec![0x55; 64]);
        assert!(
            10 < weight,
            "test setup must put fee below relay floor: 10 < weight={weight}"
        );
        let min_da = 200u64;
        let surcharge = 200u64;
        let required_da = da_bytes
            .checked_mul(min_da + surcharge)
            .expect("test arithmetic");
        assert!(
            10 < required_da,
            "test setup must put fee below DA-required: 10 < da_required={required_da}"
        );

        let mut pool = TxPool::new_with_config(TxPoolConfig {
            policy_current_mempool_min_fee_rate: DEFAULT_MEMPOOL_MIN_FEE_RATE,
            policy_min_da_fee_rate: min_da,
            policy_da_surcharge_per_byte: surcharge,
            ..TxPoolConfig::default()
        });
        let err = pool
            .admit(&raw, &state, None, [0u8; 32])
            .expect_err("admit must reject when both sub-floor and sub-DA");
        // Cross-pollination winner: apply_policy (DA helper) → Rejected.
        assert_eq!(
            err.kind,
            TxPoolAdmitErrorKind::Rejected,
            "DA-rejection class must win when apply_policy runs before validate_fee_floor; got kind={:?} message={}",
            err.kind,
            err.message
        );
        assert!(
            err.message.contains("DA fee below Stage C floor"),
            "error must come from DA helper, not the rolling floor check; got: {}",
            err.message
        );
        // Atomicity: no partial insert on cross-pollination reject.
        assert_eq!(pool.len(), 0);
        assert!(pool.spenders.is_empty());
        assert_eq!(pool.heap_seqs.len(), 0);
    }

    /// RUB-162 cross-pollination ordering PIN — sub-floor tx with a
    /// CORE_EXT output before its profile is active. Same ordering
    /// invariant as the DA-anchor cross-pollination test above; ext-id
    /// 7 is unregistered so the pre-activation guard inside
    /// apply_policy is the relevant gate.
    ///
    /// Proof assertion: build a sub-floor P2PK→CORE_EXT tx with no
    /// matching active profile; `assert_eq!(err.kind, Rejected)` plus
    /// `err.message.contains("CORE_EXT output pre-ACTIVE")` below pin
    /// the class winner against the alternative
    /// `Unavailable("mempool fee below rolling minimum")` outcome.
    #[test]
    fn rub162_admit_sub_floor_core_ext_classifies_as_core_ext_rejected_not_floor_unavailable() {
        // input=10 / output=9 → fee=1 with weight≈7533 ⇒ sub-floor.
        // CORE_EXT output with ext_id=7 and no profile registered ⇒
        // pre-activation guard rejects.
        let (state, raw) = signed_p2pk_state_and_tx(
            10,
            vec![TxOutput {
                value: 9,
                covenant_type: COV_TYPE_EXT,
                covenant_data: empty_core_ext_covenant_data(7),
            }],
            0x00,
            None,
            Vec::new(),
        );
        let mut pool = TxPool::new();
        let err = pool
            .admit(&raw, &state, None, [0u8; 32])
            .expect_err("admit must reject when both sub-floor and pre-activation CORE_EXT");
        assert_eq!(
            err.kind,
            TxPoolAdmitErrorKind::Rejected,
            "CORE_EXT pre-activation class must win when apply_policy runs before validate_fee_floor; got kind={:?} message={}",
            err.kind,
            err.message
        );
        assert!(
            err.message.contains("CORE_EXT output pre-ACTIVE"),
            "error must come from CORE_EXT pre-activation guard, not the rolling floor check; got: {}",
            err.message
        );
        // Atomicity: no partial insert on cross-pollination reject.
        assert_eq!(pool.len(), 0);
        assert!(pool.spenders.is_empty());
        assert_eq!(pool.heap_seqs.len(), 0);
    }
}
