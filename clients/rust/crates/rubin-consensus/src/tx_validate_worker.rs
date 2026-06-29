use crate::block_basic::ParsedBlock;
use crate::constants::{
    CORE_STEALTH_WITNESS_SLOTS, COV_TYPE_CORE_STEALTH, COV_TYPE_HTLC, COV_TYPE_MULTISIG,
    COV_TYPE_P2PK, COV_TYPE_VAULT,
};
use crate::core_ext::CoreExtProfiles;
use crate::error::{ErrorCode, TxError};
use crate::htlc::{validate_htlc_spend_q, HtlcSpendContext};
use crate::precompute::PrecomputedTxContext;
use crate::sig_cache::SigCache;
use crate::sig_queue::SigCheckQueue;
use crate::sighash::SighashV1PrehashCache;
use crate::spend_verify::{validate_p2pk_spend_q, validate_threshold_sig_spend_q};
use crate::stealth::validate_stealth_spend_q;
use crate::suite_registry::{DefaultRotationProvider, RotationProvider, SuiteRegistry};
use crate::tx::{Tx, WitnessItem};
use crate::utxo_basic::UtxoEntry;
use crate::vault::{
    parse_multisig_covenant_data, parse_vault_covenant_data_for_spend, witness_slots,
};
use crate::worker_pool::{
    run_worker_pool, WorkerCancellationToken, WorkerPoolError, WorkerPoolRunError, WorkerResult,
};

/// Outcome of validating a single non-coinbase transaction in a parallel
/// worker. Workers perform read-only checks against precomputed
/// [`PrecomputedTxContext`] and do NOT mutate UTXO or consensus state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxValidationResult {
    /// 1-based block-level index of this transaction.
    pub tx_index: usize,
    /// `true` if all input-level spend checks and signature verifications
    /// passed.
    pub valid: bool,
    /// Non-`None` if validation failed. The error is a canonical `TX_ERR_*`
    /// error suitable for deterministic error reporting.
    pub err: Option<TxError>,
    /// Number of signature verification operations executed.
    pub sig_count: usize,
    /// Transaction fee, copied from [`PrecomputedTxContext`].
    pub fee: u64,
}

struct TxLocalSpendContext<'a> {
    chain_id: [u8; 32],
    block_height: u64,
    block_mtp: u64,
    rotation: &'a dyn RotationProvider,
    registry: &'a SuiteRegistry,
}

fn pending_tx_validation_result(ptc: &PrecomputedTxContext) -> TxValidationResult {
    TxValidationResult {
        tx_index: ptc.tx_index,
        valid: false,
        err: None,
        sig_count: 0,
        fee: ptc.fee,
    }
}

fn tx_validation_error_result(ptc: &PrecomputedTxContext, err: TxError) -> TxValidationResult {
    let mut result = pending_tx_validation_result(ptc);
    result.err = Some(err);
    result
}

fn sig_queue_with_optional_cache(
    registry: &SuiteRegistry,
    sig_cache: Option<&SigCache>,
) -> SigCheckQueue {
    let sig_queue = SigCheckQueue::new(1).with_registry(registry);
    match sig_cache {
        Some(sig_cache) => sig_queue.with_cache(sig_cache.clone()),
        None => sig_queue,
    }
}

fn assigned_worker_witness(
    tx: &Tx,
    witness_cursor: usize,
    slots: usize,
    witness_end: usize,
) -> Result<&[WitnessItem], TxError> {
    let next_cursor = witness_cursor + slots;
    if next_cursor > witness_end {
        return Err(TxError::new(
            ErrorCode::TxErrParse,
            "witness underflow in worker",
        ));
    }
    Ok(&tx.witness[witness_cursor..next_cursor])
}

fn validate_worker_inputs(
    ptc: &PrecomputedTxContext,
    tx: &Tx,
    ctx: &TxLocalSpendContext<'_>,
    sighash_cache: &mut SighashV1PrehashCache<'_>,
    sig_queue: &mut SigCheckQueue,
) -> Result<usize, TxError> {
    let mut witness_cursor = ptc.witness_start;
    for (input_index, entry) in ptc.resolved_inputs.iter().enumerate() {
        let slots = witness_slots(entry.covenant_type, &entry.covenant_data)?;
        let assigned = assigned_worker_witness(tx, witness_cursor, slots, ptc.witness_end)?;

        validate_input_spend(
            entry,
            assigned,
            input_index as u32,
            entry.value,
            ctx.chain_id,
            ctx.block_height,
            ctx.block_mtp,
            sighash_cache,
            ctx.rotation,
            ctx.registry,
            Some(&mut *sig_queue),
        )?;

        witness_cursor += slots;
    }
    Ok(witness_cursor)
}

fn build_tx_local_preflight(tx: &Tx) -> Result<SighashV1PrehashCache<'_>, TxError> {
    SighashV1PrehashCache::new(tx)
}

/// Validate a single non-coinbase transaction using read-only precomputed
/// context. Iterates resolved inputs, dispatches per-covenant-type spend
/// validators, and counts signature verifications.
///
/// This function does NOT modify any UTXO set or consensus state. It is safe
/// to call concurrently from multiple threads.
///
/// Vault inputs: only the threshold signature is verified here. Full vault
/// policy (whitelist, owner lock, output rules) is enforced in the sequential
/// commit stage, which has access to block-level context.
#[allow(clippy::too_many_arguments)]
pub fn validate_tx_local(
    ptc: &PrecomputedTxContext,
    pb: &ParsedBlock,
    chain_id: [u8; 32],
    block_height: u64,
    block_mtp: u64,
    core_ext_profiles: &CoreExtProfiles,
    sig_cache: Option<&SigCache>,
) -> TxValidationResult {
    // COV_TYPE_CORE_EXT (0x0102) is UNASSIGNED and rejected by `witness_slots`
    // (TxErrCovenantTypeInvalid) before any spend dispatch, so no CORE_EXT
    // profile gating runs here. `core_ext_profiles` is retained in the public
    // signature for node/connect_block callers but carries no behavior.
    let _ = core_ext_profiles;
    let tx = &pb.txs[ptc.tx_block_idx];

    let mut sighash_cache = match build_tx_local_preflight(tx) {
        Ok(preflight) => preflight,
        Err(e) => return tx_validation_error_result(ptc, e),
    };

    let rotation = DefaultRotationProvider;
    let registry = SuiteRegistry::default_registry();
    let mut sig_queue = sig_queue_with_optional_cache(&registry, sig_cache);
    let spend_context = TxLocalSpendContext {
        chain_id,
        block_height,
        block_mtp,
        rotation: &rotation,
        registry: &registry,
    };

    let witness_cursor =
        match validate_worker_inputs(ptc, tx, &spend_context, &mut sighash_cache, &mut sig_queue) {
            Ok(witness_cursor) => witness_cursor,
            Err(e) => return tx_validation_error_result(ptc, e),
        };

    if witness_cursor != ptc.witness_end {
        return tx_validation_error_result(
            ptc,
            TxError::new(ErrorCode::TxErrParse, "witness_count mismatch"),
        );
    }

    let mut result = pending_tx_validation_result(ptc);
    result.sig_count = sig_queue.len();
    if let Err(e) = sig_queue.flush() {
        result.err = Some(e);
        return result;
    }

    result.valid = true;
    result
}

/// Dispatch a single input to the appropriate spend validator based on
/// covenant type. Mirrors the switch in
/// `apply_non_coinbase_tx_basic_update_with_mtp_and_core_ext_profiles_and_suite_context`
/// but without UTXO mutations.
#[allow(clippy::too_many_arguments)]
fn validate_input_spend(
    entry: &UtxoEntry,
    assigned: &[WitnessItem],
    input_index: u32,
    input_value: u64,
    chain_id: [u8; 32],
    block_height: u64,
    block_mtp: u64,
    sighash_cache: &mut SighashV1PrehashCache<'_>,
    rotation: &dyn RotationProvider,
    registry: &SuiteRegistry,
    sig_queue: Option<&mut SigCheckQueue>,
) -> Result<(), TxError> {
    match entry.covenant_type {
        COV_TYPE_P2PK => {
            if assigned.len() != 1 {
                return Err(TxError::new(
                    ErrorCode::TxErrParse,
                    "CORE_P2PK witness_slots must be 1",
                ));
            }
            validate_p2pk_spend_q(
                entry,
                &assigned[0],
                input_index,
                input_value,
                chain_id,
                block_height,
                sighash_cache,
                sig_queue,
                Some(rotation),
                Some(registry),
            )
        }

        COV_TYPE_MULTISIG => {
            let m = parse_multisig_covenant_data(&entry.covenant_data)?;
            validate_threshold_sig_spend_q(
                &m.keys,
                m.threshold,
                assigned,
                input_index,
                input_value,
                chain_id,
                block_height,
                "CORE_MULTISIG",
                sighash_cache,
                sig_queue,
                Some(rotation),
                Some(registry),
            )
        }

        COV_TYPE_VAULT => {
            // Vault: only verify threshold signature in the worker.
            // Full vault policy (whitelist, owner lock, output checks) is
            // enforced in the sequential commit stage.
            let v = parse_vault_covenant_data_for_spend(&entry.covenant_data)?;
            validate_threshold_sig_spend_q(
                &v.keys,
                v.threshold,
                assigned,
                input_index,
                input_value,
                chain_id,
                block_height,
                "CORE_VAULT",
                sighash_cache,
                sig_queue,
                Some(rotation),
                Some(registry),
            )
        }

        COV_TYPE_HTLC => {
            if assigned.len() != 2 {
                return Err(TxError::new(
                    ErrorCode::TxErrParse,
                    "CORE_HTLC witness_slots must be 2",
                ));
            }
            validate_htlc_spend_q(
                entry,
                &assigned[0], // path_item
                &assigned[1], // sig_item
                HtlcSpendContext {
                    input_index,
                    input_value,
                    chain_id,
                    block_height,
                    block_mtp,
                },
                sighash_cache,
                sig_queue,
                Some(rotation),
                Some(registry),
            )
        }

        COV_TYPE_CORE_STEALTH => {
            if assigned.len() != CORE_STEALTH_WITNESS_SLOTS as usize {
                return Err(TxError::new(
                    ErrorCode::TxErrParse,
                    "CORE_STEALTH witness_slots must be 1",
                ));
            }
            validate_stealth_spend_q(
                entry,
                &assigned[0],
                input_index,
                input_value,
                chain_id,
                block_height,
                sighash_cache,
                sig_queue,
                Some(rotation),
                Some(registry),
            )
        }

        _ => {
            // Other covenant types have no spend-time checks in the genesis set.
            Ok(())
        }
    }
}

/// Validate multiple transactions in parallel using the deterministic
/// [`WorkerPool`]. Returns results in submission order.
///
/// Returns a pool-level error only if the worker-pool substrate itself
/// rejects the batch before task execution starts.
#[allow(clippy::too_many_arguments)]
pub fn run_tx_validation_workers(
    token: &WorkerCancellationToken,
    max_workers: usize,
    ptcs: Vec<PrecomputedTxContext>,
    pb: &ParsedBlock,
    chain_id: [u8; 32],
    block_height: u64,
    block_mtp: u64,
    core_ext_profiles: &CoreExtProfiles,
    sig_cache: Option<SigCache>,
) -> Result<Vec<WorkerResult<TxValidationResult, TxError>>, WorkerPoolRunError> {
    let max_tasks = ptcs.len();
    if max_tasks == 0 {
        return Ok(Vec::new());
    }
    run_worker_pool(token, max_workers, max_tasks, ptcs, |_cancel, ptc| {
        let r = validate_tx_local(
            &ptc,
            pb,
            chain_id,
            block_height,
            block_mtp,
            core_ext_profiles,
            sig_cache.as_ref(),
        );
        if let Some(ref e) = r.err {
            Err(e.clone())
        } else {
            Ok(r)
        }
    })
}

/// Return the first error by transaction index from validation results, or
/// `None` if all transactions are valid. Deterministic: always selects the
/// smallest positive `tx_index` among failed results.
pub fn first_tx_error(results: &[WorkerResult<TxValidationResult, TxError>]) -> Option<TxError> {
    let mut best: Option<(usize, TxError)> = None;
    for r in results {
        let err = match &r.error {
            Some(WorkerPoolError::Task(e)) => e.clone(),
            Some(WorkerPoolError::Cancelled) => {
                TxError::new(ErrorCode::TxErrParse, "validation cancelled")
            }
            Some(WorkerPoolError::Panic(_)) => {
                TxError::new(ErrorCode::TxErrParse, "worker panicked during validation")
            }
            None => continue,
        };
        let tx_index = r.value.as_ref().map_or(0, |v| v.tx_index);
        if tx_index == 0 {
            // Defensive: if tx index is lost (0 = unset), keep the first
            // such error seen.
            if best.is_none() {
                best = Some((tx_index, err));
            }
            continue;
        }
        match &best {
            None => best = Some((tx_index, err)),
            Some((best_idx, _)) if *best_idx == 0 || tx_index < *best_idx => {
                best = Some((tx_index, err));
            }
            _ => {}
        }
    }
    best.map(|(_, e)| e)
}
