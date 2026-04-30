use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap, HashSet};

use rubin_consensus::{
    apply_non_coinbase_tx_basic_update_with_mtp_and_core_ext_profiles_and_suite_context,
    parse_block_header_bytes, parse_core_ext_covenant_data, parse_tx, tx_weight_and_stats_public,
    CoreExtDeploymentProfiles, Outpoint, RotationProvider, SuiteRegistry, Tx, UtxoEntry,
};

use crate::sync::SuiteContext;
use crate::{BlockStore, ChainState};

const MAX_TX_POOL_TRANSACTIONS: usize = 300;

#[derive(Debug, Clone)]
pub struct TxPoolConfig {
    pub policy_da_surcharge_per_byte: u64,
    pub policy_reject_non_coinbase_anchor_outputs: bool,
    pub policy_reject_core_ext_pre_activation: bool,
    pub policy_max_ext_payload_bytes: usize,
    pub core_ext_deployments: CoreExtDeploymentProfiles,
    pub suite_context: Option<SuiteContext>,
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

        let mut prevalidated_evict: Option<[u8; 32]> = None;
        if self.txs.len() >= MAX_TX_POOL_TRANSACTIONS {
            let Some(worst_txid) = self.current_worst_txid() else {
                return Err(unavailable("tx pool full"));
            };
            let Some(worst_entry) = self.txs.get(&worst_txid) else {
                return Err(unavailable("tx pool full"));
            };
            if let Some(candidate_fee) = estimate_tx_fee(&tx, &chain_state.utxos) {
                let candidate = TxPoolEntry {
                    raw: Vec::new(),
                    inputs: Vec::new(),
                    fee: candidate_fee,
                    weight,
                    size: tx_bytes.len(),
                };
                if compare_admit_priority(txid, &candidate, worst_txid, worst_entry)
                    != Ordering::Greater
                {
                    return Err(unavailable("tx pool full"));
                }
                prevalidated_evict = Some(worst_txid);
            }
        }

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
        apply_policy(&tx, &chain_state.utxos, next_height, &self.cfg).map_err(rejected)?;

        let entry = TxPoolEntry {
            raw: tx_bytes.to_vec(),
            inputs: inputs.clone(),
            fee: summary.fee,
            weight,
            size: tx_bytes.len(),
        };

        if self.txs.len() >= MAX_TX_POOL_TRANSACTIONS {
            let worst_txid = if let Some(worst_txid) = prevalidated_evict {
                worst_txid
            } else {
                let Some(worst_txid) = self.current_worst_txid() else {
                    return Err(unavailable("tx pool full"));
                };
                let Some(worst_entry) = self.txs.get(&worst_txid) else {
                    return Err(unavailable("tx pool full"));
                };
                if compare_admit_priority(txid, &entry, worst_txid, worst_entry)
                    != Ordering::Greater
                {
                    return Err(unavailable("tx pool full"));
                }
                worst_txid
            };
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
    apply_policy(&tx, &chain_state.utxos, next_height, cfg).map_err(rejected)?;

    Ok(RelayTxMetadata {
        fee: summary.fee,
        size: tx_bytes.len(),
    })
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

pub(crate) fn apply_policy(
    tx: &rubin_consensus::Tx,
    utxos: &HashMap<Outpoint, rubin_consensus::UtxoEntry>,
    next_height: u64,
    cfg: &TxPoolConfig,
) -> Result<(), String> {
    if cfg.policy_reject_non_coinbase_anchor_outputs {
        reject_non_coinbase_anchor_outputs(tx)?;
    }
    reject_da_anchor_tx_policy(tx, utxos, cfg.policy_da_surcharge_per_byte)?;
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

pub(crate) fn reject_da_anchor_tx_policy(
    tx: &rubin_consensus::Tx,
    utxos: &HashMap<Outpoint, rubin_consensus::UtxoEntry>,
    da_surcharge_per_byte: u64,
) -> Result<(), String> {
    let (_, da_bytes, _) = tx_weight_and_stats_public(tx).map_err(|err| err.to_string())?;
    if da_bytes == 0 || da_surcharge_per_byte == 0 {
        return Ok(());
    }
    let min_fee = da_bytes
        .checked_mul(da_surcharge_per_byte)
        .ok_or_else(|| "min fee overflow".to_string())?;
    let fee = compute_fee_no_verify(tx, utxos)?;
    if fee < min_fee {
        return Err(format!(
            "DA fee below policy minimum (fee={fee} min_fee={min_fee})"
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

fn estimate_tx_fee(tx: &Tx, utxos: &HashMap<Outpoint, UtxoEntry>) -> Option<u64> {
    let mut total_in = 0u128;
    for input in &tx.inputs {
        let entry = utxos.get(&Outpoint {
            txid: input.prev_txid,
            vout: input.prev_vout,
        })?;
        total_in = total_in.checked_add(entry.value as u128)?;
    }

    let mut total_out = 0u128;
    for output in &tx.outputs {
        total_out = total_out.checked_add(output.value as u128)?;
    }

    let fee = total_in.checked_sub(total_out)?;
    u64::try_from(fee).ok()
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
        CoreExtDeploymentProfile, CoreExtDeploymentProfiles, CoreExtVerificationBinding,
        DaChunkCore, Mldsa87Keypair, Outpoint, Tx, TxInput, TxOutput, UtxoEntry, WitnessItem,
    };

    use super::{
        compare_admit_priority, compare_entries_for_mining, compare_fee_rate, conflict, mtp_median,
        next_block_height, next_block_mtp, reject_core_ext_tx_oversized_payload, rejected,
        relay_metadata, unavailable, TxPool, TxPoolAdmitErrorKind, TxPoolConfig, TxPoolEntry,
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
    fn admit_accepts_valid_conformance_tx() {
        let vector = positive_fixture_vector();
        assert!(vector.expect_ok, "{} should be positive fixture", vector.id);
        let raw = hex::decode(&vector.tx_hex).expect("tx hex");
        let (tx, txid, _wtxid, consumed) = parse_tx(&raw).expect("parse tx");
        assert_eq!(consumed, raw.len(), "{}", vector.id);

        let state = chain_state_from_positive_fixture(&vector);
        let mut pool = TxPool::new();
        let admitted = pool
            .admit(
                &raw,
                &state,
                None,
                fixture_chain_id(vector.chain_id.as_deref()),
            )
            .expect("admit valid tx");

        assert_eq!(admitted, txid);
        assert_eq!(pool.len(), 1);
        let entry = pool.txs.get(&txid).expect("pool entry");
        assert_eq!(entry.raw, raw);
        assert_eq!(entry.inputs.len(), tx.inputs.len());
        for input in &tx.inputs {
            let outpoint = Outpoint {
                txid: input.prev_txid,
                vout: input.prev_vout,
            };
            assert_eq!(pool.spenders.get(&outpoint), Some(&txid));
        }
    }

    #[test]
    fn relay_metadata_accepts_valid_conformance_tx() {
        let vector = positive_fixture_vector();
        let raw = hex::decode(&vector.tx_hex).expect("tx hex");
        let state = chain_state_from_positive_fixture(&vector);

        let meta = relay_metadata(
            &raw,
            &state,
            None,
            fixture_chain_id(vector.chain_id.as_deref()),
            &TxPoolConfig::default(),
        )
        .expect("relay metadata");

        assert_eq!(meta.size, raw.len());
        assert!(meta.fee > 0, "relay metadata should derive non-zero fee");
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
        let (state, raw) = signed_p2pk_state_and_tx(
            10,
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
        let err = pool.admit(&raw, &state, None, [0u8; 32]).unwrap_err();
        assert_eq!(err.kind, TxPoolAdmitErrorKind::Unavailable);
        assert!(err.message.contains("tx pool full"));
    }

    #[test]
    fn admit_evicts_lowest_priority_when_pool_full() {
        let (state, raw) = signed_p2pk_state_and_tx(
            10,
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
        let (state_better, raw_better) = signed_p2pk_state_and_tx(
            10,
            vec![TxOutput {
                value: 8,
                covenant_type: COV_TYPE_P2PK,
                covenant_data: p2pk_covenant_data_for_pubkey(&vec![0x76; 2592]),
            }],
            0x00,
            None,
            Vec::new(),
        );
        let (state_worse, raw_worse) = signed_p2pk_state_and_tx(
            10,
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
        pool.txs.insert(
            worst,
            TxPoolEntry {
                raw: vec![0x01; raw_worse.len()],
                inputs: Vec::new(),
                fee: 2,
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
        let (state, admitted_raw, block_raw) = signed_conflicting_p2pk_state_and_txs(20, 10, 9);
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
        let vector = positive_fixture_vector();
        let raw = hex::decode(&vector.tx_hex).expect("tx hex");
        let mut state = chain_state_from_positive_fixture(&vector);
        state.has_tip = true;
        state.height = 0;

        let (mut store, dir) = open_block_store("rubin-txpool-admit-header-read");
        store
            .set_canonical_tip(0, [0x42; 32])
            .expect("set canonical tip");

        let err = TxPool::new()
            .admit(
                &raw,
                &state,
                Some(&store),
                fixture_chain_id(vector.chain_id.as_deref()),
            )
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
        let (state, raw) = signed_p2pk_state_and_tx(
            10,
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
    fn admit_rejects_da_tx_below_policy_surcharge_minimum() {
        let (state, raw) = signed_p2pk_state_and_tx(
            10,
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
        pool.cfg.policy_da_surcharge_per_byte = 1;
        let err = pool.admit(&raw, &state, None, [0u8; 32]).unwrap_err();
        assert_eq!(err.kind, TxPoolAdmitErrorKind::Rejected);
        assert!(err.message.contains("DA fee below policy minimum"));
    }

    #[test]
    fn admit_rejects_core_ext_output_pre_activation_by_policy() {
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
        let err = TxPool::new()
            .admit(&raw, &state, None, [0u8; 32])
            .unwrap_err();
        assert_eq!(err.kind, TxPoolAdmitErrorKind::Rejected);
        assert!(err.message.contains("CORE_EXT output pre-ACTIVE"));
    }

    #[test]
    fn admit_allows_core_ext_output_when_profile_is_active() {
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
        let (state, raw) = core_ext_spend_state_and_tx(9);
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
}
