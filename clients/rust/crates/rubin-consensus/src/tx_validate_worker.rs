use crate::block_basic::ParsedBlock;
use crate::constants::{
    COV_TYPE_EXT, COV_TYPE_HTLC, COV_TYPE_MULTISIG, COV_TYPE_P2PK, COV_TYPE_STEALTH,
    COV_TYPE_VAULT, CORE_EXT_WITNESS_SLOTS, CORE_STEALTH_WITNESS_SLOTS,
};
use crate::core_ext::{
    validate_core_ext_spend_with_cache_and_suite_context, CoreExtProfiles,
};
use crate::error::{ErrorCode, TxError};
use crate::htlc::validate_htlc_spend_at_height;
use crate::precompute::PrecomputedTxContext;
use crate::sighash::SighashV1PrehashCache;
use crate::spend_verify::{validate_p2pk_spend_at_height, validate_threshold_sig_spend_at_height};
use crate::stealth::validate_stealth_spend_at_height;
use crate::suite_registry::{DefaultRotationProvider, RotationProvider, SuiteRegistry};
use crate::tx::{Tx, WitnessItem};
use crate::txcontext::{
    build_tx_context, build_tx_context_output_ext_id_cache, collect_txcontext_ext_ids,
    TxContextBundle,
};
use crate::utxo_basic::UtxoEntry;
use crate::vault::{parse_multisig_covenant_data, parse_vault_covenant_data_for_spend, witness_slots};
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
) -> TxValidationResult {
    let mut result = TxValidationResult {
        tx_index: ptc.tx_index,
        valid: false,
        err: None,
        sig_count: 0,
        fee: ptc.fee,
    };

    let tx = &pb.txs[ptc.tx_block_idx];

    // Build sighash cache for this transaction.
    let mut sighash_cache = match SighashV1PrehashCache::new(tx) {
        Ok(c) => c,
        Err(e) => {
            result.err = Some(e);
            return result;
        }
    };

    // Build TxContext if any input requires CORE_EXT context.
    let tx_context = match build_tx_context_if_needed(
        tx,
        &ptc.resolved_inputs,
        block_height,
        core_ext_profiles,
    ) {
        Ok(ctx) => ctx,
        Err(e) => {
            result.err = Some(e);
            return result;
        }
    };

    let rotation = DefaultRotationProvider;
    let registry = SuiteRegistry::default_registry();

    let mut witness_cursor = ptc.witness_start;
    for (input_index, entry) in ptc.resolved_inputs.iter().enumerate() {
        let slots = match witness_slots(entry.covenant_type, &entry.covenant_data) {
            Ok(s) => s,
            Err(e) => {
                result.err = Some(e);
                return result;
            }
        };
        if witness_cursor + slots > ptc.witness_end {
            result.err = Some(TxError::new(
                ErrorCode::TxErrParse,
                "witness underflow in worker",
            ));
            return result;
        }
        let assigned = &tx.witness[witness_cursor..witness_cursor + slots];

        if let Err(e) = validate_input_spend(
            entry,
            assigned,
            tx,
            input_index as u32,
            entry.value,
            chain_id,
            block_height,
            block_mtp,
            &mut sighash_cache,
            core_ext_profiles,
            &rotation,
            &registry,
            tx_context.as_ref(),
        ) {
            result.err = Some(e);
            return result;
        }

        // Count one sig verification per input that carries a signature.
        // Covenant types with zero witness slots or no-op validation (anchor,
        // da_commit) are excluded by the precompute stage.
        result.sig_count += 1;

        witness_cursor += slots;
    }

    if witness_cursor != ptc.witness_end {
        result.err = Some(TxError::new(
            ErrorCode::TxErrParse,
            "witness_count mismatch",
        ));
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
    tx: &Tx,
    input_index: u32,
    input_value: u64,
    chain_id: [u8; 32],
    block_height: u64,
    block_mtp: u64,
    sighash_cache: &mut SighashV1PrehashCache<'_>,
    core_ext_profiles: &CoreExtProfiles,
    rotation: &dyn RotationProvider,
    registry: &SuiteRegistry,
    tx_context: Option<&TxContextBundle>,
) -> Result<(), TxError> {
    match entry.covenant_type {
        COV_TYPE_P2PK => {
            if assigned.len() != 1 {
                return Err(TxError::new(
                    ErrorCode::TxErrParse,
                    "CORE_P2PK witness_slots must be 1",
                ));
            }
            validate_p2pk_spend_at_height(
                entry,
                &assigned[0],
                tx,
                input_index,
                input_value,
                chain_id,
                block_height,
                sighash_cache,
                Some(rotation),
                Some(registry),
            )
        }

        COV_TYPE_MULTISIG => {
            let m = parse_multisig_covenant_data(&entry.covenant_data)?;
            validate_threshold_sig_spend_at_height(
                &m.keys,
                m.threshold,
                assigned,
                tx,
                input_index,
                input_value,
                chain_id,
                block_height,
                "CORE_MULTISIG",
                sighash_cache,
                Some(rotation),
                Some(registry),
            )
        }

        COV_TYPE_VAULT => {
            // Vault: only verify threshold signature in the worker.
            // Full vault policy (whitelist, owner lock, output checks) is
            // enforced in the sequential commit stage.
            let v = parse_vault_covenant_data_for_spend(&entry.covenant_data)?;
            validate_threshold_sig_spend_at_height(
                &v.keys,
                v.threshold,
                assigned,
                tx,
                input_index,
                input_value,
                chain_id,
                block_height,
                "CORE_VAULT",
                sighash_cache,
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
            validate_htlc_spend_at_height(
                entry,
                &assigned[0], // path_item
                &assigned[1], // sig_item
                tx,
                input_index,
                input_value,
                chain_id,
                block_height,
                block_mtp,
                sighash_cache,
                Some(rotation),
                Some(registry),
            )
        }

        COV_TYPE_EXT => {
            if assigned.len() != CORE_EXT_WITNESS_SLOTS as usize {
                return Err(TxError::new(
                    ErrorCode::TxErrParse,
                    "CORE_EXT witness_slots must be 1",
                ));
            }
            validate_core_ext_spend_with_cache_and_suite_context(
                entry,
                &assigned[0],
                tx,
                input_index,
                input_value,
                chain_id,
                block_height,
                core_ext_profiles,
                Some(rotation),
                Some(registry),
                tx_context,
                sighash_cache,
            )
        }

        COV_TYPE_STEALTH => {
            if assigned.len() != CORE_STEALTH_WITNESS_SLOTS as usize {
                return Err(TxError::new(
                    ErrorCode::TxErrParse,
                    "CORE_STEALTH witness_slots must be 1",
                ));
            }
            validate_stealth_spend_at_height(
                entry,
                &assigned[0],
                tx,
                input_index,
                input_value,
                chain_id,
                block_height,
                sighash_cache,
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

/// Build [`TxContextBundle`] only when at least one resolved input requires
/// CORE_EXT context.
fn build_tx_context_if_needed(
    tx: &Tx,
    resolved_inputs: &[UtxoEntry],
    block_height: u64,
    core_ext_profiles: &CoreExtProfiles,
) -> Result<Option<TxContextBundle>, TxError> {
    let ext_ids = collect_txcontext_ext_ids(resolved_inputs, core_ext_profiles)?;
    if ext_ids.is_empty() {
        return Ok(None);
    }
    let output_ext_id_cache = build_tx_context_output_ext_id_cache(tx)?;
    build_tx_context(
        tx,
        resolved_inputs,
        Some(&output_ext_id_cache),
        block_height,
        core_ext_profiles,
    )
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
) -> Result<Vec<WorkerResult<TxValidationResult, TxError>>, WorkerPoolRunError> {
    let max_tasks = ptcs.len();
    if max_tasks == 0 {
        return Ok(Vec::new());
    }
    run_worker_pool(
        token,
        max_workers,
        max_tasks,
        ptcs,
        |_cancel, ptc| {
            let r = validate_tx_local(
                &ptc,
                pb,
                chain_id,
                block_height,
                block_mtp,
                core_ext_profiles,
            );
            if let Some(ref e) = r.err {
                Err(e.clone())
            } else {
                Ok(r)
            }
        },
    )
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
            Some(WorkerPoolError::Panic(msg)) => {
                TxError::new(ErrorCode::TxErrParse, msg.as_str())
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
