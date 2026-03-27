use std::collections::HashMap;

use sha3::{Digest, Sha3_256};

use crate::block_basic::{
    median_time_past, parse_block_bytes, validate_block_basic_with_context_at_height,
    validate_coinbase_apply_outputs, validate_coinbase_value_bound,
};
use crate::compactsize::encode_compact_size;
use crate::constants::{COV_TYPE_ANCHOR, COV_TYPE_DA_COMMIT};
use crate::core_ext::CoreExtDeploymentProfiles;
use crate::error::{ErrorCode, TxError};
use crate::sig_queue::SigCheckQueue;
use crate::subsidy::block_subsidy;
use crate::suite_registry::{RotationProvider, SuiteRegistry};
use crate::utxo_basic::{
    apply_non_coinbase_tx_basic_update_with_mtp_and_core_ext_profiles_and_suite_context,
    apply_non_coinbase_tx_basic_update_with_mtp_and_core_ext_profiles_and_suite_context_queued_sigchecks,
    Outpoint, UtxoEntry,
};

const UTXO_SET_HASH_DST: &[u8] = b"RUBINv1-utxo-set-hash/";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InMemoryChainState {
    pub utxos: HashMap<Outpoint, UtxoEntry>,
    /// already_generated(h): subsidy-only (excluding fees).
    pub already_generated: u128,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectBlockBasicSummary {
    pub sum_fees: u64,
    pub already_generated: u128,
    pub already_generated_n1: u128,
    pub utxo_count: u64,
    /// Post-state UTXO set digest (SHA3-256) for parity checks.
    pub post_state_digest: [u8; 32],
    /// Number of queued signature-verification tasks. Zero for sequential path.
    pub sig_task_count: u64,
    /// Number of recovered worker panics. Zero on successful validation.
    pub worker_panics: u64,
}

/// ConnectBlockBasicInMemoryAtHeight connects a block against an in-memory chainstate and enforces
/// the coinbase subsidy/value bound using locally computed fees.
///
/// This intentionally does not provide any on-disk persistence.
pub fn connect_block_basic_in_memory_at_height(
    block_bytes: &[u8],
    expected_prev_hash: Option<[u8; 32]>,
    expected_target: Option<[u8; 32]>,
    block_height: u64,
    prev_timestamps: Option<&[u64]>,
    state: &mut InMemoryChainState,
    chain_id: [u8; 32],
) -> Result<ConnectBlockBasicSummary, TxError> {
    connect_block_basic_in_memory_at_height_and_core_ext_deployments(
        block_bytes,
        expected_prev_hash,
        expected_target,
        block_height,
        prev_timestamps,
        state,
        chain_id,
        &CoreExtDeploymentProfiles::empty(),
    )
}

#[allow(clippy::too_many_arguments)]
pub fn connect_block_basic_in_memory_at_height_and_core_ext_deployments(
    block_bytes: &[u8],
    expected_prev_hash: Option<[u8; 32]>,
    expected_target: Option<[u8; 32]>,
    block_height: u64,
    prev_timestamps: Option<&[u64]>,
    state: &mut InMemoryChainState,
    chain_id: [u8; 32],
    core_ext_deployments: &CoreExtDeploymentProfiles,
) -> Result<ConnectBlockBasicSummary, TxError> {
    connect_block_basic_in_memory_at_height_and_core_ext_deployments_with_suite_context(
        block_bytes,
        expected_prev_hash,
        expected_target,
        block_height,
        prev_timestamps,
        state,
        chain_id,
        core_ext_deployments,
        None,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn connect_block_basic_in_memory_at_height_and_core_ext_deployments_with_suite_context(
    block_bytes: &[u8],
    expected_prev_hash: Option<[u8; 32]>,
    expected_target: Option<[u8; 32]>,
    block_height: u64,
    prev_timestamps: Option<&[u64]>,
    state: &mut InMemoryChainState,
    chain_id: [u8; 32],
    core_ext_deployments: &CoreExtDeploymentProfiles,
    rotation: Option<&dyn RotationProvider>,
    registry: Option<&SuiteRegistry>,
) -> Result<ConnectBlockBasicSummary, TxError> {
    // Stateless checks first.
    validate_block_basic_with_context_at_height(
        block_bytes,
        expected_prev_hash,
        expected_target,
        block_height,
        prev_timestamps,
    )?;

    let pb = parse_block_bytes(block_bytes)?;
    if pb.txs.is_empty() || pb.txids.len() != pb.txs.len() {
        return Err(TxError::new(
            ErrorCode::BlockErrParse,
            "invalid parsed block",
        ));
    }

    let already_generated = state.already_generated;
    let block_mtp = median_time_past(block_height, prev_timestamps)?.unwrap_or(pb.header.timestamp);
    let core_ext_profiles = core_ext_deployments.active_profiles_at_height(block_height)?;
    let mut work_utxos = None;

    let mut sum_fees: u64 = 0;
    for i in 1..pb.txs.len() {
        let base_utxos = work_utxos.as_ref().unwrap_or(&state.utxos);
        let (next_utxos, s) =
            apply_non_coinbase_tx_basic_update_with_mtp_and_core_ext_profiles_and_suite_context(
                &pb.txs[i],
                pb.txids[i],
                base_utxos,
                block_height,
                pb.header.timestamp,
                block_mtp,
                chain_id,
                &core_ext_profiles,
                rotation,
                registry,
            )?;
        work_utxos = Some(next_utxos);
        sum_fees = sum_fees
            .checked_add(s.fee)
            .ok_or_else(|| TxError::new(ErrorCode::BlockErrParse, "sum_fees overflow"))?;
    }

    let mut work_utxos = work_utxos.unwrap_or_else(|| state.utxos.clone());

    validate_coinbase_value_bound(&pb, block_height, already_generated, sum_fees)?;
    validate_coinbase_apply_outputs(&pb.txs[0])?;

    // Add coinbase spendable outputs to UTXO set.
    let coinbase_txid = pb.txids[0];
    for (i, out) in pb.txs[0].outputs.iter().enumerate() {
        if out.covenant_type == COV_TYPE_ANCHOR || out.covenant_type == COV_TYPE_DA_COMMIT {
            continue;
        }
        work_utxos.insert(
            Outpoint {
                txid: coinbase_txid,
                vout: i as u32,
            },
            UtxoEntry {
                value: out.value,
                covenant_type: out.covenant_type,
                covenant_data: out.covenant_data.clone(),
                creation_height: block_height,
                created_by_coinbase: true,
            },
        );
    }

    let mut already_generated_n1 = already_generated;
    if block_height != 0 {
        let subsidy = block_subsidy(block_height, already_generated);
        already_generated_n1 = already_generated
            .checked_add(u128::from(subsidy))
            .ok_or_else(|| TxError::new(ErrorCode::BlockErrParse, "already_generated overflow"))?;
    }

    state.utxos = work_utxos;
    if block_height != 0 {
        state.already_generated = already_generated_n1;
    }

    let post_state_digest = utxo_set_hash(&state.utxos);

    Ok(ConnectBlockBasicSummary {
        sum_fees,
        already_generated,
        already_generated_n1,
        utxo_count: state.utxos.len() as u64,
        post_state_digest,
        sig_task_count: 0,
        worker_panics: 0,
    })
}

/// Go-style block-level deferred signature orchestration. Structural and
/// state-mutation checks stay sequential; only expensive native signature
/// verification is deferred and flushed once per block.
#[allow(clippy::too_many_arguments)]
pub fn connect_block_parallel_sig_verify(
    block_bytes: &[u8],
    expected_prev_hash: Option<[u8; 32]>,
    expected_target: Option<[u8; 32]>,
    block_height: u64,
    prev_timestamps: Option<&[u64]>,
    state: &mut InMemoryChainState,
    chain_id: [u8; 32],
    workers: usize,
) -> Result<ConnectBlockBasicSummary, TxError> {
    connect_block_parallel_sig_verify_and_core_ext_deployments(
        block_bytes,
        expected_prev_hash,
        expected_target,
        block_height,
        prev_timestamps,
        state,
        chain_id,
        &CoreExtDeploymentProfiles::empty(),
        workers,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn connect_block_parallel_sig_verify_and_core_ext_deployments(
    block_bytes: &[u8],
    expected_prev_hash: Option<[u8; 32]>,
    expected_target: Option<[u8; 32]>,
    block_height: u64,
    prev_timestamps: Option<&[u64]>,
    state: &mut InMemoryChainState,
    chain_id: [u8; 32],
    core_ext_deployments: &CoreExtDeploymentProfiles,
    workers: usize,
) -> Result<ConnectBlockBasicSummary, TxError> {
    connect_block_parallel_sig_verify_and_core_ext_deployments_with_suite_context(
        block_bytes,
        expected_prev_hash,
        expected_target,
        block_height,
        prev_timestamps,
        state,
        chain_id,
        core_ext_deployments,
        None,
        None,
        workers,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn connect_block_parallel_sig_verify_and_core_ext_deployments_with_suite_context(
    block_bytes: &[u8],
    expected_prev_hash: Option<[u8; 32]>,
    expected_target: Option<[u8; 32]>,
    block_height: u64,
    prev_timestamps: Option<&[u64]>,
    state: &mut InMemoryChainState,
    chain_id: [u8; 32],
    core_ext_deployments: &CoreExtDeploymentProfiles,
    rotation: Option<&dyn RotationProvider>,
    registry: Option<&SuiteRegistry>,
    workers: usize,
) -> Result<ConnectBlockBasicSummary, TxError> {
    validate_block_basic_with_context_at_height(
        block_bytes,
        expected_prev_hash,
        expected_target,
        block_height,
        prev_timestamps,
    )?;

    let pb = parse_block_bytes(block_bytes)?;
    if pb.txs.is_empty() || pb.txids.len() != pb.txs.len() {
        return Err(TxError::new(
            ErrorCode::BlockErrParse,
            "invalid parsed block",
        ));
    }

    let already_generated = state.already_generated;
    let block_mtp = median_time_past(block_height, prev_timestamps)?.unwrap_or(pb.header.timestamp);
    let core_ext_profiles = core_ext_deployments.active_profiles_at_height(block_height)?;
    let mut work_utxos = state.utxos.clone();
    let mut sig_queue = match registry {
        Some(registry) => SigCheckQueue::new(workers).with_registry(registry),
        None => SigCheckQueue::new(workers),
    };

    let mut sum_fees: u64 = 0;
    for i in 1..pb.txs.len() {
        let (next_utxos, summary) =
            apply_non_coinbase_tx_basic_update_with_mtp_and_core_ext_profiles_and_suite_context_queued_sigchecks(
                &pb.txs[i],
                pb.txids[i],
                &work_utxos,
                block_height,
                pb.header.timestamp,
                block_mtp,
                chain_id,
                &core_ext_profiles,
                rotation,
                registry,
                &mut sig_queue,
            )?;
        work_utxos = next_utxos;
        sum_fees = sum_fees
            .checked_add(summary.fee)
            .ok_or_else(|| TxError::new(ErrorCode::BlockErrParse, "sum_fees overflow"))?;
    }

    let sig_task_count = sig_queue.len() as u64;
    sig_queue.flush()?;

    validate_coinbase_value_bound(&pb, block_height, already_generated, sum_fees)?;
    validate_coinbase_apply_outputs(&pb.txs[0])?;

    let coinbase_txid = pb.txids[0];
    for (i, out) in pb.txs[0].outputs.iter().enumerate() {
        if out.covenant_type == COV_TYPE_ANCHOR || out.covenant_type == COV_TYPE_DA_COMMIT {
            continue;
        }
        work_utxos.insert(
            Outpoint {
                txid: coinbase_txid,
                vout: i as u32,
            },
            UtxoEntry {
                value: out.value,
                covenant_type: out.covenant_type,
                covenant_data: out.covenant_data.clone(),
                creation_height: block_height,
                created_by_coinbase: true,
            },
        );
    }

    let mut already_generated_n1 = already_generated;
    if block_height != 0 {
        let subsidy = block_subsidy(block_height, already_generated);
        already_generated_n1 = already_generated
            .checked_add(u128::from(subsidy))
            .ok_or_else(|| TxError::new(ErrorCode::BlockErrParse, "already_generated overflow"))?;
    }

    state.utxos = work_utxos;
    if block_height != 0 {
        state.already_generated = already_generated_n1;
    }

    let post_state_digest = utxo_set_hash(&state.utxos);

    Ok(ConnectBlockBasicSummary {
        sum_fees,
        already_generated,
        already_generated_n1,
        utxo_count: state.utxos.len() as u64,
        post_state_digest,
        sig_task_count,
        worker_panics: 0,
    })
}

/// utxo_set_hash computes a deterministic SHA3-256 digest over the UTXO set.
/// Must match Go consensus.UtxoSetHash and rubin-node chainstate for parity.
fn utxo_set_hash(utxos: &HashMap<Outpoint, UtxoEntry>) -> [u8; 32] {
    let mut items: Vec<([u8; 36], &UtxoEntry)> = Vec::with_capacity(utxos.len());
    for (outpoint, entry) in utxos {
        let mut key = [0u8; 36];
        key[..32].copy_from_slice(&outpoint.txid);
        key[32..].copy_from_slice(&outpoint.vout.to_le_bytes());
        items.push((key, entry));
    }
    items.sort_by(|a, b| a.0.cmp(&b.0));

    let mut buf = Vec::with_capacity(UTXO_SET_HASH_DST.len() + 8 + items.len() * 64);
    buf.extend_from_slice(UTXO_SET_HASH_DST);
    buf.extend_from_slice(&(items.len() as u64).to_le_bytes());

    for (key, entry) in items {
        buf.extend_from_slice(&key);
        buf.extend_from_slice(&entry.value.to_le_bytes());
        buf.extend_from_slice(&entry.covenant_type.to_le_bytes());
        encode_compact_size(entry.covenant_data.len() as u64, &mut buf);
        buf.extend_from_slice(&entry.covenant_data);
        buf.extend_from_slice(&entry.creation_height.to_le_bytes());
        buf.push(u8::from(entry.created_by_coinbase));
    }

    Sha3_256::digest(&buf).into()
}
