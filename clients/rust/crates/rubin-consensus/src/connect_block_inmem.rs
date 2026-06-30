use std::collections::HashMap;

use sha3::{Digest, Sha3_256};

use crate::block_basic::{
    median_time_past, parse_block_bytes, validate_coinbase_apply_outputs,
    validate_coinbase_value_bound, validate_parsed_block_basic_with_context_at_height, ParsedBlock,
};
use crate::compactsize::encode_compact_size;
use crate::constants::{COV_TYPE_ANCHOR, COV_TYPE_DA_COMMIT};
use crate::core_ext::{CoreExtDeploymentProfiles, CoreExtProfiles};
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

struct ConnectBlockContext<'a> {
    expected_prev_hash: Option<[u8; 32]>,
    expected_target: Option<[u8; 32]>,
    block_height: u64,
    prev_timestamps: Option<&'a [u64]>,
    chain_id: [u8; 32],
    core_ext_deployments: &'a CoreExtDeploymentProfiles,
    rotation: Option<&'a dyn RotationProvider>,
    registry: Option<&'a SuiteRegistry>,
}

struct PreparedConnectBlock {
    pb: ParsedBlock,
    block_height: u64,
    already_generated: u128,
    block_mtp: u64,
    core_ext_profiles: CoreExtProfiles,
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
    let ctx = ConnectBlockContext {
        expected_prev_hash,
        expected_target,
        block_height,
        prev_timestamps,
        chain_id,
        core_ext_deployments,
        rotation,
        registry,
    };
    connect_block_basic_in_memory_with_context(block_bytes, state, &ctx)
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
    let ctx = ConnectBlockContext {
        expected_prev_hash,
        expected_target,
        block_height,
        prev_timestamps,
        chain_id,
        core_ext_deployments,
        rotation,
        registry,
    };
    connect_block_parallel_sig_verify_with_context(block_bytes, state, &ctx, workers)
}

fn prepare_connect_block(
    block_bytes: &[u8],
    already_generated: u128,
    ctx: &ConnectBlockContext<'_>,
) -> Result<PreparedConnectBlock, TxError> {
    // G.9: parse once and validate against the parsed block.
    let pb = parse_block_bytes(block_bytes)?;
    validate_parsed_block_basic_with_context_at_height(
        &pb,
        ctx.expected_prev_hash,
        ctx.expected_target,
        ctx.block_height,
        ctx.prev_timestamps,
    )?;
    if pb.txs.is_empty() || pb.txids.len() != pb.txs.len() {
        return Err(TxError::new(
            ErrorCode::BlockErrParse,
            "invalid parsed block",
        ));
    }

    // 0x0102 (CORE_EXT) is unassigned with no activation path, so the retired
    // deployment set must not influence consensus/admission for ordinary
    // (e.g. P2PK) traffic. Do NOT call `active_profiles_at_height` here: it
    // validates the deployment set and would reject otherwise-valid blocks if a
    // node were started with a stale/invalid `core_ext_deployments` entry. Pass
    // empty active profiles instead, mirroring Go, which ignores the parameter.
    // The parameter is retained on the public signatures for node/CLI API
    // compatibility; full removal is tracked under CORE_EXT retirement.
    let _ = ctx.core_ext_deployments;
    Ok(PreparedConnectBlock {
        block_mtp: median_time_past(ctx.block_height, ctx.prev_timestamps)?
            .unwrap_or(pb.header.timestamp),
        core_ext_profiles: CoreExtProfiles::default(),
        pb,
        block_height: ctx.block_height,
        already_generated,
    })
}

fn connect_block_basic_in_memory_with_context(
    block_bytes: &[u8],
    state: &mut InMemoryChainState,
    ctx: &ConnectBlockContext<'_>,
) -> Result<ConnectBlockBasicSummary, TxError> {
    let prepared = prepare_connect_block(block_bytes, state.already_generated, ctx)?;
    let (work_utxos, sum_fees) = apply_non_coinbase_txs_sequential(&prepared, &state.utxos, ctx)?;
    finalize_connected_block(state, &prepared, work_utxos, sum_fees, 0)
}

fn apply_non_coinbase_txs_sequential(
    prepared: &PreparedConnectBlock,
    state_utxos: &HashMap<Outpoint, UtxoEntry>,
    ctx: &ConnectBlockContext<'_>,
) -> Result<(HashMap<Outpoint, UtxoEntry>, u64), TxError> {
    let mut work_utxos = None;
    let mut sum_fees: u64 = 0;
    for i in 1..prepared.pb.txs.len() {
        let base_utxos = work_utxos.as_ref().unwrap_or(state_utxos);
        let (next_utxos, summary) =
            apply_non_coinbase_tx_basic_update_with_mtp_and_core_ext_profiles_and_suite_context(
                &prepared.pb.txs[i],
                prepared.pb.txids[i],
                base_utxos,
                prepared.block_height,
                prepared.pb.header.timestamp,
                prepared.block_mtp,
                ctx.chain_id,
                &prepared.core_ext_profiles,
                ctx.rotation,
                ctx.registry,
            )?;
        work_utxos = Some(next_utxos);
        sum_fees = add_block_fee(sum_fees, summary.fee)?;
    }

    Ok((work_utxos.unwrap_or_else(|| state_utxos.clone()), sum_fees))
}

fn connect_block_parallel_sig_verify_with_context(
    block_bytes: &[u8],
    state: &mut InMemoryChainState,
    ctx: &ConnectBlockContext<'_>,
    workers: usize,
) -> Result<ConnectBlockBasicSummary, TxError> {
    let prepared = prepare_connect_block(block_bytes, state.already_generated, ctx)?;
    let (work_utxos, sum_fees, sig_task_count) =
        apply_non_coinbase_txs_parallel(&prepared, &state.utxos, ctx, workers)?;
    finalize_connected_block(state, &prepared, work_utxos, sum_fees, sig_task_count)
}

fn apply_non_coinbase_txs_parallel(
    prepared: &PreparedConnectBlock,
    state_utxos: &HashMap<Outpoint, UtxoEntry>,
    ctx: &ConnectBlockContext<'_>,
    workers: usize,
) -> Result<(HashMap<Outpoint, UtxoEntry>, u64, u64), TxError> {
    let mut work_utxos = state_utxos.clone();
    let mut sig_queue = match ctx.registry {
        Some(registry) => SigCheckQueue::new(workers).with_registry(registry),
        None => SigCheckQueue::new(workers),
    };

    let mut sum_fees: u64 = 0;
    for i in 1..prepared.pb.txs.len() {
        let (next_utxos, summary) =
            apply_non_coinbase_tx_basic_update_with_mtp_and_core_ext_profiles_and_suite_context_queued_sigchecks(
                &prepared.pb.txs[i],
                prepared.pb.txids[i],
                &work_utxos,
                prepared.block_height,
                prepared.pb.header.timestamp,
                prepared.block_mtp,
                ctx.chain_id,
                &prepared.core_ext_profiles,
                ctx.rotation,
                ctx.registry,
                &mut sig_queue,
            )?;
        work_utxos = next_utxos;
        sum_fees = add_block_fee(sum_fees, summary.fee)?;
    }

    let sig_task_count = sig_queue.len() as u64;
    sig_queue.flush()?;

    Ok((work_utxos, sum_fees, sig_task_count))
}

fn add_block_fee(sum_fees: u64, fee: u64) -> Result<u64, TxError> {
    sum_fees
        .checked_add(fee)
        .ok_or_else(|| TxError::new(ErrorCode::BlockErrParse, "sum_fees overflow"))
}

fn finalize_connected_block(
    state: &mut InMemoryChainState,
    prepared: &PreparedConnectBlock,
    mut work_utxos: HashMap<Outpoint, UtxoEntry>,
    sum_fees: u64,
    sig_task_count: u64,
) -> Result<ConnectBlockBasicSummary, TxError> {
    validate_coinbase_value_bound(
        &prepared.pb,
        prepared.block_height,
        prepared.already_generated,
        sum_fees,
    )?;
    validate_coinbase_apply_outputs(&prepared.pb.txs[0])?;
    add_coinbase_outputs(&mut work_utxos, prepared);
    let already_generated_n1 =
        already_generated_after_block(prepared.block_height, prepared.already_generated)?;

    state.utxos = work_utxos;
    if prepared.block_height != 0 {
        state.already_generated = already_generated_n1;
    }

    let post_state_digest = utxo_set_hash(&state.utxos);

    Ok(ConnectBlockBasicSummary {
        sum_fees,
        already_generated: prepared.already_generated,
        already_generated_n1,
        utxo_count: state.utxos.len() as u64,
        post_state_digest,
        sig_task_count,
        worker_panics: 0,
    })
}

fn add_coinbase_outputs(
    work_utxos: &mut HashMap<Outpoint, UtxoEntry>,
    prepared: &PreparedConnectBlock,
) {
    let coinbase_txid = prepared.pb.txids[0];
    for (i, out) in prepared.pb.txs[0].outputs.iter().enumerate() {
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
                creation_height: prepared.block_height,
                created_by_coinbase: true,
            },
        );
    }
}

fn already_generated_after_block(
    block_height: u64,
    already_generated: u128,
) -> Result<u128, TxError> {
    if block_height != 0 {
        let subsidy = block_subsidy(block_height, already_generated);
        return already_generated
            .checked_add(u128::from(subsidy))
            .ok_or_else(|| TxError::new(ErrorCode::BlockErrParse, "already_generated overflow"));
    }
    Ok(already_generated)
}

/// utxo_set_hash computes a deterministic SHA3-256 digest over the UTXO set.
/// Must match Go consensus.UtxoSetHash and rubin-node chainstate for parity.
pub(crate) fn utxo_set_hash(utxos: &HashMap<Outpoint, UtxoEntry>) -> [u8; 32] {
    let mut items: Vec<([u8; 36], &UtxoEntry)> = Vec::with_capacity(utxos.len());
    for (outpoint, entry) in utxos {
        let mut key = [0u8; 36];
        key[..32].copy_from_slice(&outpoint.txid);
        key[32..].copy_from_slice(&outpoint.vout.to_le_bytes());
        items.push((key, entry));
    }
    // sort_unstable_by avoids decorate/sort/undecorate copies of the
    // [u8; 36] key that sort_by_key/sort_unstable_by_key would do —
    // important on the consensus digest path with large UTXO sets.
    #[allow(clippy::unnecessary_sort_by)]
    items.sort_unstable_by(|a, b| a.0.cmp(&b.0));

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

#[cfg(test)]
#[path = "connect_block_inmem_digest_tests.rs"]
mod tests;
