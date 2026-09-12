use std::collections::HashMap;
use std::ops::Range;

use crate::constants::{
    COINBASE_MATURITY, COV_TYPE_ANCHOR, COV_TYPE_CORE_SIMPLICITY, COV_TYPE_CORE_STEALTH,
    COV_TYPE_DA_COMMIT, COV_TYPE_HTLC, COV_TYPE_MULTISIG, COV_TYPE_P2PK, COV_TYPE_VAULT,
};
use crate::covenant_genesis::validate_tx_covenants_genesis;
use crate::error::{ErrorCode, TxError};
use crate::hash::sha3_256;
use crate::htlc::{parse_htlc_covenant_data, validate_htlc_spend_q, HtlcSpendContext};
use crate::sig_queue::SigCheckQueue;
use crate::sighash::SighashV1PrehashCache;
use crate::simplicity_covenant::reject_core_simplicity_spend;
use crate::spend_verify::{validate_p2pk_spend_q, validate_threshold_sig_spend_q};
use crate::stealth::{parse_stealth_covenant_data, validate_stealth_spend_q};
use crate::suite_registry::{RotationProvider, SuiteRegistry};
use crate::tx::{Tx, TxInput};
use crate::vault::{
    hash_in_sorted_32, output_descriptor_bytes, parse_multisig_covenant_data,
    parse_vault_covenant_data, parse_vault_covenant_data_for_spend, witness_slots,
};

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Outpoint {
    pub txid: [u8; 32],
    pub vout: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UtxoEntry {
    pub value: u64,
    pub covenant_type: u16,
    pub covenant_data: Vec<u8>,
    pub creation_height: u64,
    pub created_by_coinbase: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UtxoApplySummary {
    /// Exact u128 fee (sum_in - sum_out). Per-output and per-UTXO values
    /// remain u64, but a transaction may spend up to MAX_TX_INPUTS u64-max
    /// inputs, so the fee itself is not bounded by u64 and is never
    /// narrowed, rounded, or saturated on the way out of this struct.
    pub fee: u128,
    pub utxo_count: u64,
}

struct UtxoApplyImplContext<'a> {
    tx: &'a Tx,
    txid: [u8; 32],
    utxo_set: &'a HashMap<Outpoint, UtxoEntry>,
    height: u64,
    block_timestamp: u64,
    block_mtp: u64,
    chain_id: [u8; 32],
    rotation: Option<&'a dyn RotationProvider>,
    registry: Option<&'a SuiteRegistry>,
}

pub fn apply_non_coinbase_tx_basic_update(
    tx: &Tx,
    txid: [u8; 32],
    utxo_set: &HashMap<Outpoint, UtxoEntry>,
    height: u64,
    block_timestamp: u64,
    chain_id: [u8; 32],
) -> Result<(HashMap<Outpoint, UtxoEntry>, UtxoApplySummary), TxError> {
    apply_non_coinbase_tx_basic_update_with_mtp(
        tx,
        txid,
        utxo_set,
        height,
        block_timestamp,
        block_timestamp,
        chain_id,
    )
}

pub fn apply_non_coinbase_tx_basic_update_with_mtp(
    tx: &Tx,
    txid: [u8; 32],
    utxo_set: &HashMap<Outpoint, UtxoEntry>,
    height: u64,
    block_timestamp: u64,
    block_mtp: u64,
    chain_id: [u8; 32],
) -> Result<(HashMap<Outpoint, UtxoEntry>, UtxoApplySummary), TxError> {
    apply_non_coinbase_tx_basic_update_with_mtp_and_suite_context(
        tx,
        txid,
        utxo_set,
        height,
        block_timestamp,
        block_mtp,
        chain_id,
        None,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn apply_non_coinbase_tx_basic_update_with_mtp_and_suite_context(
    tx: &Tx,
    txid: [u8; 32],
    utxo_set: &HashMap<Outpoint, UtxoEntry>,
    height: u64,
    block_timestamp: u64,
    block_mtp: u64,
    chain_id: [u8; 32],
    rotation: Option<&dyn RotationProvider>,
    registry: Option<&SuiteRegistry>,
) -> Result<(HashMap<Outpoint, UtxoEntry>, UtxoApplySummary), TxError> {
    apply_non_coinbase_tx_basic_update_with_mtp_and_suite_context_impl(
        UtxoApplyImplContext {
            tx,
            txid,
            utxo_set,
            height,
            block_timestamp,
            block_mtp,
            chain_id,
            rotation,
            registry,
        },
        None,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn apply_non_coinbase_tx_basic_update_with_mtp_and_suite_context_queued_sigchecks(
    tx: &Tx,
    txid: [u8; 32],
    utxo_set: &HashMap<Outpoint, UtxoEntry>,
    height: u64,
    block_timestamp: u64,
    block_mtp: u64,
    chain_id: [u8; 32],
    rotation: Option<&dyn RotationProvider>,
    registry: Option<&SuiteRegistry>,
    sig_queue: &mut SigCheckQueue,
) -> Result<(HashMap<Outpoint, UtxoEntry>, UtxoApplySummary), TxError> {
    let entry_mark = sig_queue.mark();
    let result = apply_non_coinbase_tx_basic_update_with_mtp_and_suite_context_impl(
        UtxoApplyImplContext {
            tx,
            txid,
            utxo_set,
            height,
            block_timestamp,
            block_mtp,
            chain_id,
            rotation,
            registry,
        },
        Some(&mut *sig_queue),
    );
    if result.is_err() {
        sig_queue.rollback_to(entry_mark);
    }
    result
}

#[allow(clippy::too_many_arguments)]
pub fn apply_non_coinbase_tx_basic_update_with_mtp_and_suite_context_deferred_sigchecks(
    tx: &Tx,
    txid: [u8; 32],
    utxo_set: &HashMap<Outpoint, UtxoEntry>,
    height: u64,
    block_timestamp: u64,
    block_mtp: u64,
    chain_id: [u8; 32],
    rotation: Option<&dyn RotationProvider>,
    registry: Option<&SuiteRegistry>,
) -> Result<(HashMap<Outpoint, UtxoEntry>, UtxoApplySummary), TxError> {
    let mut sig_queue = SigCheckQueue::new(1);
    let queue_mark = sig_queue.mark();
    let result = apply_non_coinbase_tx_basic_update_with_mtp_and_suite_context_queued_sigchecks(
        tx,
        txid,
        utxo_set,
        height,
        block_timestamp,
        block_mtp,
        chain_id,
        rotation,
        registry,
        &mut sig_queue,
    );
    let (work, summary) = match result {
        Ok(ok) => ok,
        Err(err) => {
            sig_queue.rollback_to(queue_mark);
            return Err(err);
        }
    };
    sig_queue.flush()?;
    Ok((work, summary))
}

/// Validates the wire-level encoding that every non-coinbase input must share.
/// This preserves the sequential check order for standalone precompute.
pub(crate) fn validate_non_coinbase_input_encoding(input: &TxInput) -> Result<(), TxError> {
    if input.prev_vout == u32::MAX && input.prev_txid == [0u8; 32] {
        return Err(TxError::new(
            ErrorCode::TxErrParse,
            "coinbase prevout encoding forbidden in non-coinbase",
        ));
    }
    if !input.script_sig.is_empty() {
        return Err(TxError::new(
            ErrorCode::TxErrParse,
            "script_sig must be empty under genesis covenant set",
        ));
    }
    if input.sequence > 0x7fff_ffff {
        return Err(TxError::new(
            ErrorCode::TxErrSequenceInvalid,
            "sequence exceeds 0x7fffffff",
        ));
    }
    Ok(())
}

struct UtxoApplyState<'tx, 'queue> {
    work: HashMap<Outpoint, UtxoEntry>,
    sighash_cache: SighashV1PrehashCache<'tx>,
    sig_queue: Option<&'queue mut SigCheckQueue>,
    sum_in: u128,
    sum_in_vault: u128,
    sum_out: u128,
    vault_input_count: usize,
    creates_vault: bool,
    vault_spend: Option<VaultSpendState>,
    witness_cursor: usize,
    input_lock_ids: Vec<[u8; 32]>,
    input_cov_types: Vec<u16>,
    seen_inputs: HashMap<Outpoint, ()>,
    resolved_inputs: Vec<UtxoEntry>,
    resolved_witness_ranges: Vec<Range<usize>>,
    resolved_outpoints: Vec<Outpoint>,
}

struct VaultSpendState {
    keys: Vec<[u8; 32]>,
    threshold: u8,
    witness_range: Range<usize>,
    input_index: u32,
    input_value: u64,
    owner_lock_id: [u8; 32],
    whitelist: Vec<[u8; 32]>,
}

fn apply_non_coinbase_tx_basic_update_with_mtp_and_suite_context_impl(
    ctx: UtxoApplyImplContext<'_>,
    sig_queue: Option<&mut SigCheckQueue>,
) -> Result<(HashMap<Outpoint, UtxoEntry>, UtxoApplySummary), TxError> {
    validate_apply_inputs(&ctx)?;
    let mut state = UtxoApplyState::new(&ctx, sig_queue)?;
    state.resolve_inputs(&ctx)?;
    state.validate_spends(&ctx)?;
    state.add_outputs(&ctx)?;
    state.validate_vault_creation(&ctx)?;
    state.validate_vault_spend(&ctx)?;
    state.finish()
}

fn validate_apply_inputs(ctx: &UtxoApplyImplContext<'_>) -> Result<(), TxError> {
    let tx = ctx.tx;
    let _ = ctx.block_timestamp;
    if tx.tx_nonce == 0 {
        return Err(TxError::new(
            ErrorCode::TxErrTxNonceInvalid,
            "tx_nonce must be >= 1 for non-coinbase",
        ));
    }
    if tx.inputs.is_empty() {
        return Err(TxError::new(
            ErrorCode::TxErrParse,
            "non-coinbase must have at least one input",
        ));
    }
    validate_tx_covenants_genesis(tx, ctx.height, ctx.rotation)
}

impl<'tx, 'queue> UtxoApplyState<'tx, 'queue> {
    fn new(
        ctx: &UtxoApplyImplContext<'tx>,
        sig_queue: Option<&'queue mut SigCheckQueue>,
    ) -> Result<Self, TxError> {
        let work = ctx.utxo_set.clone();
        let sighash_cache = SighashV1PrehashCache::new(ctx.tx)?;
        Ok(Self {
            work,
            sighash_cache,
            sig_queue,
            sum_in: 0,
            sum_in_vault: 0,
            sum_out: 0,
            vault_input_count: 0,
            creates_vault: false,
            vault_spend: None,
            witness_cursor: 0,
            input_lock_ids: Vec::with_capacity(ctx.tx.inputs.len()),
            input_cov_types: Vec::with_capacity(ctx.tx.inputs.len()),
            seen_inputs: HashMap::with_capacity(ctx.tx.inputs.len()),
            resolved_inputs: Vec::with_capacity(ctx.tx.inputs.len()),
            resolved_witness_ranges: Vec::with_capacity(ctx.tx.inputs.len()),
            resolved_outpoints: Vec::with_capacity(ctx.tx.inputs.len()),
        })
    }

    fn resolve_inputs(&mut self, ctx: &UtxoApplyImplContext<'_>) -> Result<(), TxError> {
        for input in &ctx.tx.inputs {
            self.resolve_input(ctx, input)?;
        }
        if self.witness_cursor != ctx.tx.witness.len() {
            return Err(TxError::new(
                ErrorCode::TxErrParse,
                "witness_count mismatch",
            ));
        }
        Ok(())
    }

    fn resolve_input(
        &mut self,
        ctx: &UtxoApplyImplContext<'_>,
        input: &TxInput,
    ) -> Result<(), TxError> {
        validate_non_coinbase_input_encoding(input)?;
        let op = Outpoint {
            txid: input.prev_txid,
            vout: input.prev_vout,
        };
        if self.seen_inputs.contains_key(&op) {
            return Err(TxError::new(
                ErrorCode::TxErrParse,
                "duplicate input outpoint",
            ));
        }
        self.seen_inputs.insert(op.clone(), ());
        let entry = match self.work.get(&op) {
            Some(v) => v.clone(),
            None => return Err(TxError::new(ErrorCode::TxErrMissingUtxo, "utxo not found")),
        };
        validate_input_availability(&entry, ctx.height)?;
        self.validate_input_covenant(&entry)?;
        self.record_resolved_input(ctx.tx, entry, op)
    }

    fn record_resolved_input(
        &mut self,
        tx: &Tx,
        entry: UtxoEntry,
        op: Outpoint,
    ) -> Result<(), TxError> {
        let slots = witness_slots(entry.covenant_type, &entry.covenant_data)?;
        if slots == 0 {
            return Err(TxError::new(ErrorCode::TxErrParse, "invalid witness slots"));
        }
        if self.witness_cursor + slots > tx.witness.len() {
            return Err(TxError::new(ErrorCode::TxErrParse, "witness underflow"));
        }
        let assigned_range = self.witness_cursor..self.witness_cursor + slots;
        self.resolved_inputs.push(entry);
        self.resolved_witness_ranges.push(assigned_range);
        self.resolved_outpoints.push(op);
        self.witness_cursor += slots;
        Ok(())
    }

    fn validate_input_covenant(&mut self, entry: &UtxoEntry) -> Result<(), TxError> {
        if entry.covenant_type == COV_TYPE_VAULT {
            self.vault_input_count += 1;
            if self.vault_input_count > 1 {
                return Err(TxError::new(
                    ErrorCode::TxErrVaultMultiInputForbidden,
                    "multiple CORE_VAULT inputs forbidden",
                ));
            }
        }
        // Preserve the dedicated refusal before generic covenant/witness checks.
        if entry.covenant_type == COV_TYPE_CORE_SIMPLICITY {
            return Err(reject_core_simplicity_spend());
        }
        check_spend_covenant(entry.covenant_type, &entry.covenant_data)
    }

    fn validate_spends(&mut self, ctx: &UtxoApplyImplContext<'_>) -> Result<(), TxError> {
        // 0x0102 is unassigned and already rejected during input resolution.
        for (input_index, ((entry, range), op)) in self
            .resolved_inputs
            .iter()
            .zip(self.resolved_witness_ranges.iter())
            .zip(self.resolved_outpoints.iter())
            .enumerate()
        {
            validate_resolved_spend(
                ctx,
                entry,
                range,
                input_index,
                &mut self.sighash_cache,
                &mut self.sig_queue,
                &mut self.vault_spend,
            )?;
            let desc = output_descriptor_bytes(entry.covenant_type, &entry.covenant_data);
            self.input_lock_ids.push(sha3_256(&desc));
            self.input_cov_types.push(entry.covenant_type);
            self.sum_in = self
                .sum_in
                .checked_add(entry.value as u128)
                .ok_or_else(|| TxError::new(ErrorCode::TxErrParse, "u128 overflow"))?;
            if entry.covenant_type == COV_TYPE_VAULT {
                self.sum_in_vault = self
                    .sum_in_vault
                    .checked_add(entry.value as u128)
                    .ok_or_else(|| TxError::new(ErrorCode::TxErrParse, "u128 overflow"))?;
            }
            self.work.remove(op);
        }
        Ok(())
    }

    fn add_outputs(&mut self, ctx: &UtxoApplyImplContext<'_>) -> Result<(), TxError> {
        for (i, out) in ctx.tx.outputs.iter().enumerate() {
            self.sum_out = self
                .sum_out
                .checked_add(out.value as u128)
                .ok_or_else(|| TxError::new(ErrorCode::TxErrParse, "u128 overflow"))?;
            if out.covenant_type == COV_TYPE_VAULT {
                self.creates_vault = true;
            }
            if out.covenant_type == COV_TYPE_ANCHOR || out.covenant_type == COV_TYPE_DA_COMMIT {
                continue;
            }
            self.work.insert(
                Outpoint {
                    txid: ctx.txid,
                    vout: i as u32,
                },
                UtxoEntry {
                    value: out.value,
                    covenant_type: out.covenant_type,
                    covenant_data: out.covenant_data.clone(),
                    creation_height: ctx.height,
                    created_by_coinbase: false,
                },
            );
        }
        Ok(())
    }

    fn validate_vault_creation(&self, ctx: &UtxoApplyImplContext<'_>) -> Result<(), TxError> {
        // Any CORE_VAULT creation requires an owner-authorized input.
        if self.creates_vault {
            for out in &ctx.tx.outputs {
                if out.covenant_type != COV_TYPE_VAULT {
                    continue;
                }
                let v = parse_vault_covenant_data(&out.covenant_data)?;
                if !has_owner_authorized_input(
                    &self.input_lock_ids,
                    &self.input_cov_types,
                    v.owner_lock_id,
                ) {
                    return Err(TxError::new(
                        ErrorCode::TxErrVaultOwnerAuthRequired,
                        "missing owner-authorized input for CORE_VAULT creation",
                    ));
                }
            }
        }
        Ok(())
    }

    fn validate_vault_spend(&mut self, ctx: &UtxoApplyImplContext<'_>) -> Result<(), TxError> {
        if self.vault_input_count == 1 {
            let vault = self.vault_spend.take().ok_or_else(|| {
                TxError::new(
                    ErrorCode::TxErrParse,
                    "missing CORE_VAULT signature context",
                )
            })?;
            vault.validate_owner_and_sponsor(&self.input_lock_ids, &self.input_cov_types)?;
            vault.validate_no_recursion(ctx.tx)?;
            // CANONICAL §24.1 step 7 follows owner, sponsor and recursion checks.
            vault.validate_signature(
                ctx,
                &mut self.sighash_cache,
                self.sig_queue.as_deref_mut(),
            )?;
            vault.validate_destinations(ctx.tx)?;
        }
        Ok(())
    }

    fn finish(self) -> Result<(HashMap<Outpoint, UtxoEntry>, UtxoApplySummary), TxError> {
        if self.sum_out > self.sum_in {
            return Err(TxError::new(
                ErrorCode::TxErrValueConservation,
                "sum_out exceeds sum_in",
            ));
        }
        if self.vault_input_count == 1 && self.sum_out < self.sum_in_vault {
            return Err(TxError::new(
                ErrorCode::TxErrValueConservation,
                "CORE_VAULT value must not fund miner fee",
            ));
        }
        // Exact u128 fee: accepted fees above u64 are never narrowed.
        let fee = self.sum_in - self.sum_out;
        let summary = UtxoApplySummary {
            fee,
            utxo_count: self.work.len() as u64,
        };
        Ok((self.work, summary))
    }
}

fn validate_input_availability(entry: &UtxoEntry, height: u64) -> Result<(), TxError> {
    if entry.covenant_type == COV_TYPE_ANCHOR || entry.covenant_type == COV_TYPE_DA_COMMIT {
        return Err(TxError::new(
            ErrorCode::TxErrMissingUtxo,
            "attempt to spend non-spendable covenant",
        ));
    }
    // Avoid overflowing creation_height + COINBASE_MATURITY.
    if entry.created_by_coinbase
        && (height < entry.creation_height || height - entry.creation_height < COINBASE_MATURITY)
    {
        return Err(TxError::new(
            ErrorCode::TxErrCoinbaseImmature,
            "coinbase immature",
        ));
    }
    Ok(())
}

fn validate_resolved_spend(
    ctx: &UtxoApplyImplContext<'_>,
    entry: &UtxoEntry,
    range: &Range<usize>,
    input_index: usize,
    cache: &mut SighashV1PrehashCache<'_>,
    queue: &mut Option<&mut SigCheckQueue>,
    vault: &mut Option<VaultSpendState>,
) -> Result<(), TxError> {
    let assigned = &ctx.tx.witness[range.clone()];
    match entry.covenant_type {
        COV_TYPE_P2PK => apply_p2pk_spend(
            ctx,
            entry,
            assigned,
            input_index,
            cache,
            queue.as_deref_mut(),
        )?,
        COV_TYPE_MULTISIG => apply_multisig_spend(
            ctx,
            entry,
            assigned,
            input_index,
            cache,
            queue.as_deref_mut(),
        )?,
        COV_TYPE_VAULT => *vault = Some(VaultSpendState::capture(entry, range, input_index)?),
        COV_TYPE_HTLC => apply_htlc_spend(
            ctx,
            entry,
            assigned,
            input_index,
            cache,
            queue.as_deref_mut(),
        )?,
        COV_TYPE_CORE_STEALTH => apply_stealth_spend(
            ctx,
            entry,
            assigned,
            input_index,
            cache,
            queue.as_deref_mut(),
        )?,
        _ => {}
    }
    Ok(())
}

fn apply_p2pk_spend(
    ctx: &UtxoApplyImplContext<'_>,
    entry: &UtxoEntry,
    assigned: &[crate::tx::WitnessItem],
    input_index: usize,
    cache: &mut SighashV1PrehashCache<'_>,
    queue: Option<&mut SigCheckQueue>,
) -> Result<(), TxError> {
    if assigned.len() != 1 {
        return Err(TxError::new(
            ErrorCode::TxErrParse,
            "CORE_P2PK witness_slots must be 1",
        ));
    }
    validate_p2pk_spend_q(
        entry,
        &assigned[0],
        input_index as u32,
        entry.value,
        ctx.chain_id,
        ctx.height,
        cache,
        queue,
        ctx.rotation,
        ctx.registry,
    )?;
    Ok(())
}

fn apply_multisig_spend(
    ctx: &UtxoApplyImplContext<'_>,
    entry: &UtxoEntry,
    assigned: &[crate::tx::WitnessItem],
    input_index: usize,
    cache: &mut SighashV1PrehashCache<'_>,
    queue: Option<&mut SigCheckQueue>,
) -> Result<(), TxError> {
    let m = parse_multisig_covenant_data(&entry.covenant_data)?;
    validate_threshold_sig_spend_q(
        &m.keys,
        m.threshold,
        assigned,
        input_index as u32,
        entry.value,
        ctx.chain_id,
        ctx.height,
        "CORE_MULTISIG",
        cache,
        queue,
        ctx.rotation,
        ctx.registry,
    )?;
    Ok(())
}

fn apply_htlc_spend(
    ctx: &UtxoApplyImplContext<'_>,
    entry: &UtxoEntry,
    assigned: &[crate::tx::WitnessItem],
    input_index: usize,
    cache: &mut SighashV1PrehashCache<'_>,
    queue: Option<&mut SigCheckQueue>,
) -> Result<(), TxError> {
    if assigned.len() != 2 {
        return Err(TxError::new(
            ErrorCode::TxErrParse,
            "CORE_HTLC witness_slots must be 2",
        ));
    }
    validate_htlc_spend_q(
        entry,
        &assigned[0],
        &assigned[1],
        HtlcSpendContext {
            input_index: input_index as u32,
            input_value: entry.value,
            chain_id: ctx.chain_id,
            block_height: ctx.height,
            block_mtp: ctx.block_mtp,
        },
        cache,
        queue,
        ctx.rotation,
        ctx.registry,
    )?;
    Ok(())
}

fn apply_stealth_spend(
    ctx: &UtxoApplyImplContext<'_>,
    entry: &UtxoEntry,
    assigned: &[crate::tx::WitnessItem],
    input_index: usize,
    cache: &mut SighashV1PrehashCache<'_>,
    queue: Option<&mut SigCheckQueue>,
) -> Result<(), TxError> {
    if assigned.len() != 1 {
        return Err(TxError::new(
            ErrorCode::TxErrParse,
            "CORE_STEALTH witness_slots must be 1",
        ));
    }
    validate_stealth_spend_q(
        entry,
        &assigned[0],
        input_index as u32,
        entry.value,
        ctx.chain_id,
        ctx.height,
        cache,
        queue,
        ctx.rotation,
        ctx.registry,
    )?;
    Ok(())
}

impl VaultSpendState {
    fn capture(
        entry: &UtxoEntry,
        range: &Range<usize>,
        input_index: usize,
    ) -> Result<Self, TxError> {
        let v = parse_vault_covenant_data_for_spend(&entry.covenant_data)?;
        // Capture now; threshold verification remains after authorization.
        Ok(Self {
            keys: v.keys.clone(),
            threshold: v.threshold,
            witness_range: range.clone(),
            input_index: input_index as u32,
            input_value: entry.value,
            owner_lock_id: v.owner_lock_id,
            whitelist: v.whitelist,
        })
    }

    fn validate_owner_and_sponsor(&self, locks: &[[u8; 32]], types: &[u16]) -> Result<(), TxError> {
        if !has_owner_lock_input(locks, self.owner_lock_id) {
            return Err(TxError::new(
                ErrorCode::TxErrVaultOwnerAuthRequired,
                "missing owner-authorized input for CORE_VAULT spend",
            ));
        }
        if !non_vault_inputs_owned_by(locks, types, self.owner_lock_id) {
            return Err(TxError::new(
                ErrorCode::TxErrVaultFeeSponsorForbidden,
                "non-owner non-vault input forbidden in CORE_VAULT spend",
            ));
        }
        Ok(())
    }

    fn validate_no_recursion(&self, tx: &Tx) -> Result<(), TxError> {
        for out in &tx.outputs {
            if out.covenant_type == COV_TYPE_VAULT {
                return Err(TxError::new(
                    ErrorCode::TxErrVaultOutputNotWhitelisted,
                    "CORE_VAULT outputs forbidden in CORE_VAULT spend",
                ));
            }
        }
        Ok(())
    }

    fn validate_signature(
        &self,
        ctx: &UtxoApplyImplContext<'_>,
        cache: &mut SighashV1PrehashCache<'_>,
        queue: Option<&mut SigCheckQueue>,
    ) -> Result<(), TxError> {
        validate_threshold_sig_spend_q(
            &self.keys,
            self.threshold,
            &ctx.tx.witness[self.witness_range.clone()],
            self.input_index,
            self.input_value,
            ctx.chain_id,
            ctx.height,
            "CORE_VAULT",
            cache,
            queue,
            ctx.rotation,
            ctx.registry,
        )
    }

    fn validate_destinations(&self, tx: &Tx) -> Result<(), TxError> {
        for out in &tx.outputs {
            if out.covenant_type != COV_TYPE_P2PK
                && out.covenant_type != COV_TYPE_MULTISIG
                && out.covenant_type != COV_TYPE_HTLC
            {
                return Err(TxError::new(
                    ErrorCode::TxErrVaultOutputNotWhitelisted,
                    "disallowed destination covenant_type for CORE_VAULT spend",
                ));
            }
            let desc = output_descriptor_bytes(out.covenant_type, &out.covenant_data);
            let h = sha3_256(&desc);
            if !hash_in_sorted_32(&self.whitelist, &h) {
                return Err(TxError::new(
                    ErrorCode::TxErrVaultOutputNotWhitelisted,
                    "output not whitelisted for CORE_VAULT",
                ));
            }
        }
        Ok(())
    }
}
pub fn apply_non_coinbase_tx_basic(
    tx: &Tx,
    txid: [u8; 32],
    utxo_set: &HashMap<Outpoint, UtxoEntry>,
    height: u64,
    block_timestamp: u64,
    chain_id: [u8; 32],
) -> Result<UtxoApplySummary, TxError> {
    apply_non_coinbase_tx_basic_with_mtp(
        tx,
        txid,
        utxo_set,
        height,
        block_timestamp,
        block_timestamp,
        chain_id,
    )
}

pub fn apply_non_coinbase_tx_basic_with_mtp(
    tx: &Tx,
    txid: [u8; 32],
    utxo_set: &HashMap<Outpoint, UtxoEntry>,
    height: u64,
    block_timestamp: u64,
    block_mtp: u64,
    chain_id: [u8; 32],
) -> Result<UtxoApplySummary, TxError> {
    let (_work, summary) = apply_non_coinbase_tx_basic_update_with_mtp(
        tx,
        txid,
        utxo_set,
        height,
        block_timestamp,
        block_mtp,
        chain_id,
    )?;
    Ok(summary)
}

fn has_owner_authorized_input(
    input_lock_ids: &[[u8; 32]],
    input_cov_types: &[u16],
    owner_lock_id: [u8; 32],
) -> bool {
    for (lock_id, cov_type) in input_lock_ids.iter().zip(input_cov_types.iter()) {
        if *lock_id == owner_lock_id
            && (*cov_type == COV_TYPE_P2PK || *cov_type == COV_TYPE_MULTISIG)
        {
            return true;
        }
    }
    false
}

fn has_owner_lock_input(input_lock_ids: &[[u8; 32]], owner_lock_id: [u8; 32]) -> bool {
    input_lock_ids.contains(&owner_lock_id)
}

fn non_vault_inputs_owned_by(
    input_lock_ids: &[[u8; 32]],
    input_cov_types: &[u16],
    owner_lock_id: [u8; 32],
) -> bool {
    input_lock_ids
        .iter()
        .zip(input_cov_types.iter())
        .all(|(lock_id, cov_type)| *cov_type == COV_TYPE_VAULT || *lock_id == owner_lock_id)
}

#[allow(dead_code)]
fn check_spend_covenant(covenant_type: u16, covenant_data: &[u8]) -> Result<(), TxError> {
    match covenant_type {
        COV_TYPE_P2PK => Ok(()),
        COV_TYPE_CORE_STEALTH => {
            let _ = parse_stealth_covenant_data(covenant_data)?;
            Ok(())
        }
        COV_TYPE_VAULT => {
            parse_vault_covenant_data_for_spend(covenant_data)?;
            Ok(())
        }
        COV_TYPE_MULTISIG => {
            parse_multisig_covenant_data(covenant_data)?;
            Ok(())
        }
        COV_TYPE_HTLC => {
            parse_htlc_covenant_data(covenant_data)?;
            Ok(())
        }
        _ => Err(TxError::new(
            ErrorCode::TxErrCovenantTypeInvalid,
            "unsupported covenant in basic apply",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{
        COV_TYPE_CORE_EXT, LOCK_MODE_HEIGHT, MAX_STEALTH_COVENANT_DATA, SIGHASH_ALL,
        SUITE_ID_ML_DSA_87, SUITE_ID_SENTINEL,
    };
    use crate::sighash::sighash_v1_digest;
    use crate::tx::{DaCommitCore, Tx, TxInput, TxOutput, WitnessItem};
    use crate::tx_helpers::{p2pk_covenant_data_for_pubkey, sign_transaction};
    use crate::verify_sig_openssl::Mldsa87Keypair;

    // COV_TYPE_CORE_EXT (0x0102) is UNASSIGNED per CANONICAL §14 and MUST be
    // rejected as TxErrCovenantTypeInvalid at BOTH creation (genesis) and spend,
    // for ANY covenant_data (RUB-514 / RUB-585). Mirrors the Go reject behavior.
    #[test]
    fn core_ext_0x0102_unassigned_rejects_at_genesis_and_spend() {
        let keypair = Mldsa87Keypair::generate().expect("keypair");
        let pubkey = keypair.pubkey_bytes();
        assert_unassigned_core_ext_creation(&pubkey);
        assert_unassigned_core_ext_spends(&pubkey);
    }

    fn assert_unassigned_core_ext_creation(pubkey: &[u8]) {
        // Creation (genesis): a tx producing a 0x0102 output is rejected by
        // `validate_tx_covenants_genesis` before any input spend checks, so the
        // funding input does not even need a valid signature.
        let prev_txid = [0x71; 32];
        let txid = [0x72; 32];
        let chain_id = [0x73; 32];
        let funding = HashMap::from([utxo(
            prev_txid,
            100,
            COV_TYPE_P2PK,
            p2pk_covenant_data_for_pubkey(pubkey),
        )]);
        let create_tx = unsigned_tx(
            0x00,
            1,
            vec![tx_input(prev_txid)],
            vec![tx_output(90, COV_TYPE_CORE_EXT, vec![0x07, 0x00, 0x00])],
        );
        let create_err = apply_non_coinbase_tx_basic_update_with_mtp_and_suite_context(
            &create_tx, txid, &funding, 1, 0, 0, chain_id, None, None,
        )
        .expect_err("0x0102 creation must reject");
        assert_eq!(create_err.code, ErrorCode::TxErrCovenantTypeInvalid);
    }

    fn assert_unassigned_core_ext_spends(pubkey: &[u8]) {
        // Spend: a tx consuming a 0x0102 UTXO is rejected, for any covenant_data.
        // `check_spend_covenant`/`witness_slots` reject during input resolution
        // before any signature verification, so the witness contents are
        // irrelevant.
        let spend_prev = [0x81; 32];
        let spend_txid = [0x82; 32];
        let spend_chain = [0x83; 32];
        for cov_data in [vec![], vec![0x07, 0x00, 0x00], vec![0xffu8; 8]] {
            let spend_set = HashMap::from([utxo(spend_prev, 100, COV_TYPE_CORE_EXT, cov_data)]);
            let mut spend_tx = unsigned_tx(
                0x00,
                2,
                vec![tx_input(spend_prev)],
                vec![tx_output(
                    90,
                    COV_TYPE_P2PK,
                    p2pk_covenant_data_for_pubkey(pubkey),
                )],
            );
            spend_tx.witness = vec![WitnessItem {
                suite_id: SUITE_ID_ML_DSA_87,
                pubkey: pubkey.to_vec(),
                signature: vec![0u8; 1],
            }];
            let spend_err = apply_non_coinbase_tx_basic_update_with_mtp_and_suite_context(
                &spend_tx,
                spend_txid,
                &spend_set,
                1,
                0,
                0,
                spend_chain,
                None,
                None,
            )
            .expect_err("0x0102 spend must reject");
            assert_eq!(spend_err.code, ErrorCode::TxErrCovenantTypeInvalid);
        }
    }

    // RUB-591: a tx consuming a 0x0106 UTXO is rejected during input resolution
    // with the DEDICATED "spend evaluation not enabled" message — ahead of the
    // generic check_spend_covenant/witness errors — for any covenant_data.
    #[test]
    fn core_simplicity_0x0106_spend_rejects_with_dedicated_message() {
        let keypair = Mldsa87Keypair::generate().expect("keypair");
        let pubkey = keypair.pubkey_bytes();
        let spend_prev = [0x91; 32];
        let spend_txid = [0x92; 32];
        let spend_chain = [0x93; 32];
        for cov_data in [vec![], vec![0xffu8; 8]] {
            let spend_set =
                HashMap::from([utxo(spend_prev, 100, COV_TYPE_CORE_SIMPLICITY, cov_data)]);
            let mut spend_tx = unsigned_tx(
                0x00,
                2,
                vec![tx_input(spend_prev)],
                vec![tx_output(
                    90,
                    COV_TYPE_P2PK,
                    p2pk_covenant_data_for_pubkey(&pubkey),
                )],
            );
            spend_tx.witness = vec![WitnessItem {
                suite_id: SUITE_ID_ML_DSA_87,
                pubkey: pubkey.to_vec(),
                signature: vec![0u8; 1],
            }];
            let err = apply_non_coinbase_tx_basic_update_with_mtp_and_suite_context(
                &spend_tx,
                spend_txid,
                &spend_set,
                1,
                0,
                0,
                spend_chain,
                None,
                None,
            )
            .expect_err("0x0106 spend must reject");
            assert_eq!(err.code, ErrorCode::TxErrCovenantTypeInvalid);
            assert!(
                format!("{err}").contains("CORE_SIMPLICITY spend evaluation not enabled"),
                "got: {err}"
            );
        }
    }

    // A well-formed CORE_SIMPLICITY covenant blob: program_cmr[32] || state_len(0).
    fn simplicity_cov(cmr_byte: u8) -> Vec<u8> {
        let mut cov = vec![cmr_byte; 32];
        cov.push(0x00);
        cov
    }

    // RUB-505 (mirror of Go RUB-504): the §5.3 CORE_SIMPLICITY spend reject is
    // ordered at the input's wire position — an earlier-index resolution error
    // (coinbase maturity, witness underflow) wins over a later disabled-spend
    // reject, and a CORE_SIMPLICITY input wins over a later input's error.

    #[test]
    fn core_simplicity_immature_coinbase_precedes_disabled_spend() {
        let keypair = Mldsa87Keypair::generate().expect("keypair");
        let pubkey = keypair.pubkey_bytes();
        let prev = [0x67u8; 32];
        let (op, mut entry) = utxo(prev, 100, COV_TYPE_CORE_SIMPLICITY, simplicity_cov(0x67));
        entry.created_by_coinbase = true; // creation_height 0
        let set = HashMap::from([(op, entry)]);
        let tx = unsigned_tx(
            0x00,
            1,
            vec![tx_input(prev)],
            vec![tx_output(
                90,
                COV_TYPE_P2PK,
                p2pk_covenant_data_for_pubkey(&pubkey),
            )],
        );
        let err = apply_non_coinbase_tx_basic_update_with_mtp_and_suite_context(
            &tx,
            [0x68u8; 32],
            &set,
            COINBASE_MATURITY - 1,
            0,
            0,
            [0u8; 32],
            None,
            None,
        )
        .expect_err("immature coinbase precedes disabled spend");
        assert_eq!(err.code, ErrorCode::TxErrCoinbaseImmature);
    }

    #[test]
    fn core_simplicity_precedes_later_missing_utxo() {
        let keypair = Mldsa87Keypair::generate().expect("keypair");
        let pubkey = keypair.pubkey_bytes();
        let simp_prev = [0xE1u8; 32];
        let later_missing = [0xE2u8; 32];
        // Only the CORE_SIMPLICITY input is resolvable; the later input is missing.
        let set = HashMap::from([utxo(
            simp_prev,
            100,
            COV_TYPE_CORE_SIMPLICITY,
            simplicity_cov(0xE1),
        )]);
        let tx = unsigned_tx(
            0x00,
            1,
            vec![tx_input(simp_prev), tx_input(later_missing)],
            vec![tx_output(
                90,
                COV_TYPE_P2PK,
                p2pk_covenant_data_for_pubkey(&pubkey),
            )],
        );
        let err = apply_non_coinbase_tx_basic_update_with_mtp_and_suite_context(
            &tx,
            [0xE3u8; 32],
            &set,
            1,
            0,
            0,
            [0u8; 32],
            None,
            None,
        )
        .expect_err("simplicity precedes later missing utxo");
        assert_eq!(err.code, ErrorCode::TxErrCovenantTypeInvalid);
        assert!(
            format!("{err}").contains("CORE_SIMPLICITY spend evaluation not enabled"),
            "got: {err}"
        );
    }

    #[test]
    fn p2pk_witness_underflow_precedes_later_simplicity() {
        let keypair = Mldsa87Keypair::generate().expect("keypair");
        let pubkey = keypair.pubkey_bytes();
        let p2pk_prev = [0xE0u8; 32];
        let simp_prev = [0xE1u8; 32];
        let set = HashMap::from([
            utxo(
                p2pk_prev,
                100,
                COV_TYPE_P2PK,
                p2pk_covenant_data_for_pubkey(&pubkey),
            ),
            utxo(
                simp_prev,
                100,
                COV_TYPE_CORE_SIMPLICITY,
                simplicity_cov(0xE1),
            ),
        ]);
        // Empty witness => the index-0 P2PK input underflows before the later
        // CORE_SIMPLICITY input is reached.
        let tx = unsigned_tx(
            0x00,
            1,
            vec![tx_input(p2pk_prev), tx_input(simp_prev)],
            vec![tx_output(
                190,
                COV_TYPE_P2PK,
                p2pk_covenant_data_for_pubkey(&pubkey),
            )],
        );
        let err = apply_non_coinbase_tx_basic_update_with_mtp_and_suite_context(
            &tx,
            [0xE4u8; 32],
            &set,
            1,
            0,
            0,
            [0u8; 32],
            None,
            None,
        )
        .expect_err("earlier p2pk underflow precedes later simplicity");
        assert_eq!(err.code, ErrorCode::TxErrParse);
        assert!(format!("{err}").contains("witness underflow"), "got: {err}");
    }

    #[test]
    fn non_simplicity_witness_underflow_precedes_later_validation() {
        let keypair = Mldsa87Keypair::generate().expect("keypair");
        let pubkey = keypair.pubkey_bytes();
        let first_prev = [0xE7u8; 32];
        let later_prev = [0xE8u8; 32];
        let set = HashMap::from([
            utxo(
                first_prev,
                100,
                COV_TYPE_P2PK,
                p2pk_covenant_data_for_pubkey(&pubkey),
            ),
            utxo(later_prev, 100, COV_TYPE_HTLC, vec![0x01]),
        ]);
        let tx = unsigned_tx(
            0x00,
            1,
            vec![tx_input(first_prev), tx_input(later_prev)],
            vec![tx_output(
                190,
                COV_TYPE_P2PK,
                p2pk_covenant_data_for_pubkey(&pubkey),
            )],
        );
        let err = apply_non_coinbase_tx_basic_update_with_mtp_and_suite_context(
            &tx,
            [0xE9u8; 32],
            &set,
            1,
            0,
            0,
            [0u8; 32],
            None,
            None,
        )
        .expect_err("earlier witness underflow precedes later validation");
        assert_eq!(err.code, ErrorCode::TxErrParse);
        assert!(format!("{err}").contains("witness underflow"), "got: {err}");
    }

    fn tx_input(prev_txid: [u8; 32]) -> TxInput {
        TxInput {
            prev_txid,
            prev_vout: 0,
            script_sig: vec![],
            sequence: 0,
        }
    }

    fn tx_output(value: u64, covenant_type: u16, covenant_data: Vec<u8>) -> TxOutput {
        TxOutput {
            value,
            covenant_type,
            covenant_data,
        }
    }

    fn utxo(
        prev_txid: [u8; 32],
        value: u64,
        covenant_type: u16,
        covenant_data: Vec<u8>,
    ) -> (Outpoint, UtxoEntry) {
        (
            Outpoint {
                txid: prev_txid,
                vout: 0,
            },
            UtxoEntry {
                value,
                covenant_type,
                covenant_data,
                creation_height: 0,
                created_by_coinbase: false,
            },
        )
    }

    fn unsigned_tx(tx_kind: u8, tx_nonce: u64, inputs: Vec<TxInput>, outputs: Vec<TxOutput>) -> Tx {
        Tx {
            version: 1,
            tx_kind,
            tx_nonce,
            inputs,
            outputs,
            locktime: 0,
            witness: vec![],
            da_payload: vec![],
            da_commit_core: None,
            da_chunk_core: None,
        }
    }

    #[test]
    fn section16_structural_first_error_order() {
        section16_count_and_prevout_cases();
        section16_input_order_cases();
    }

    fn section16_count_and_prevout_cases() {
        let coinbase_prevout = TxInput {
            prev_txid: [0u8; 32],
            prev_vout: u32::MAX,
            script_sig: vec![],
            sequence: 0,
        };
        assert_section16_error(
            "nonce_before_input_count",
            0,
            vec![],
            ErrorCode::TxErrTxNonceInvalid,
            "tx_nonce must be >= 1 for non-coinbase",
        );
        assert_section16_error(
            "input_count_only",
            1,
            vec![],
            ErrorCode::TxErrParse,
            "non-coinbase must have at least one input",
        );
        assert_section16_error(
            "coinbase_prevout_before_script_sig",
            1,
            vec![TxInput {
                script_sig: vec![0x01],
                ..coinbase_prevout.clone()
            }],
            ErrorCode::TxErrParse,
            "coinbase prevout encoding forbidden in non-coinbase",
        );
        assert_section16_error(
            "coinbase_prevout_before_sequence",
            1,
            vec![TxInput {
                sequence: 0x8000_0000,
                ..coinbase_prevout.clone()
            }],
            ErrorCode::TxErrParse,
            "coinbase prevout encoding forbidden in non-coinbase",
        );
    }

    fn section16_input_order_cases() {
        let coinbase_prevout = TxInput {
            prev_txid: [0u8; 32],
            prev_vout: u32::MAX,
            script_sig: vec![],
            sequence: 0,
        };
        assert_section16_error(
            "input_index_order",
            1,
            vec![
                TxInput {
                    prev_txid: [0x51; 32],
                    prev_vout: 0,
                    script_sig: vec![],
                    sequence: 0x8000_0000,
                },
                coinbase_prevout.clone(),
            ],
            ErrorCode::TxErrSequenceInvalid,
            "sequence exceeds 0x7fffffff",
        );
        assert_section16_error(
            "script_sig_only",
            1,
            vec![TxInput {
                prev_txid: [0x52; 32],
                prev_vout: 0,
                script_sig: vec![0x01],
                sequence: 0,
            }],
            ErrorCode::TxErrParse,
            "script_sig must be empty under genesis covenant set",
        );
        assert_section16_error(
            "sequence_only",
            1,
            vec![TxInput {
                prev_txid: [0x53; 32],
                prev_vout: 0,
                script_sig: vec![],
                sequence: 0x8000_0000,
            }],
            ErrorCode::TxErrSequenceInvalid,
            "sequence exceeds 0x7fffffff",
        );
    }

    fn assert_section16_error(
        name: &str,
        nonce: u64,
        inputs: Vec<TxInput>,
        want: ErrorCode,
        message: &str,
    ) {
        let tx = unsigned_tx(
            0x00,
            nonce,
            inputs,
            vec![tx_output(
                1,
                COV_TYPE_P2PK,
                p2pk_covenant_data_for_pubkey(&[0x54; 32]),
            )],
        );
        let utxo_set = HashMap::from([utxo(
            [0x55; 32],
            1,
            COV_TYPE_P2PK,
            p2pk_covenant_data_for_pubkey(&[0x55; 32]),
        )]);
        let original = utxo_set.clone();
        let err = apply_non_coinbase_tx_basic_update_with_mtp_and_suite_context(
            &tx, [0x56; 32], &utxo_set, 1, 0, 0, [0u8; 32], None, None,
        )
        .expect_err(name);
        assert_eq!(err.code, want, "{name}");
        assert_eq!(err.msg, message, "{name}");
        assert_eq!(utxo_set, original, "{name}: caller UTXOs changed");
    }

    fn signed_p2pk_case() -> (Tx, HashMap<Outpoint, UtxoEntry>, [u8; 32], [u8; 32]) {
        let keypair = Mldsa87Keypair::generate().expect("keypair");
        let pubkey = keypair.pubkey_bytes();
        let prev_txid = [0x71; 32];
        let txid = [0x72; 32];
        let chain_id = [0x73; 32];
        let utxo_set = HashMap::from([(
            Outpoint {
                txid: prev_txid,
                vout: 0,
            },
            UtxoEntry {
                value: 100,
                covenant_type: COV_TYPE_P2PK,
                covenant_data: p2pk_covenant_data_for_pubkey(&pubkey),
                creation_height: 0,
                created_by_coinbase: false,
            },
        )]);
        let mut tx = Tx {
            version: 1,
            tx_kind: 0x00,
            tx_nonce: 1,
            inputs: vec![TxInput {
                prev_txid,
                prev_vout: 0,
                script_sig: vec![],
                sequence: 0,
            }],
            outputs: vec![TxOutput {
                value: 90,
                covenant_type: COV_TYPE_P2PK,
                covenant_data: p2pk_covenant_data_for_pubkey(&pubkey),
            }],
            locktime: 0,
            witness: vec![],
            da_payload: vec![],
            da_commit_core: None,
            da_chunk_core: None,
        };
        sign_transaction(&mut tx, &utxo_set, chain_id, &keypair).expect("sign");
        (tx, utxo_set, txid, chain_id)
    }

    fn signed_anchor_output_case() -> (Tx, HashMap<Outpoint, UtxoEntry>, [u8; 32], [u8; 32]) {
        let keypair = Mldsa87Keypair::generate().expect("anchor keypair");
        let pubkey = keypair.pubkey_bytes();
        let prev_txid = [0x74; 32];
        let txid = [0x75; 32];
        let chain_id = [0x76; 32];
        let utxo_set = HashMap::from([(
            Outpoint {
                txid: prev_txid,
                vout: 0,
            },
            UtxoEntry {
                value: 100,
                covenant_type: COV_TYPE_P2PK,
                covenant_data: p2pk_covenant_data_for_pubkey(&pubkey),
                creation_height: 0,
                created_by_coinbase: false,
            },
        )]);
        let mut tx = Tx {
            version: 1,
            tx_kind: 0x00,
            tx_nonce: 1,
            inputs: vec![TxInput {
                prev_txid,
                prev_vout: 0,
                script_sig: vec![],
                sequence: 0,
            }],
            outputs: vec![TxOutput {
                value: 0,
                covenant_type: COV_TYPE_ANCHOR,
                covenant_data: vec![0x41, 0x4e, 0x43, 0x48],
            }],
            locktime: 0,
            witness: vec![],
            da_payload: vec![],
            da_commit_core: None,
            da_chunk_core: None,
        };
        sign_transaction(&mut tx, &utxo_set, chain_id, &keypair).expect("sign");
        (tx, utxo_set, txid, chain_id)
    }

    fn signed_da_commit_output_case() -> (Tx, HashMap<Outpoint, UtxoEntry>, [u8; 32], [u8; 32]) {
        let keypair = Mldsa87Keypair::generate().expect("da commit keypair");
        let pubkey = keypair.pubkey_bytes();
        let prev_txid = [0x77; 32];
        let txid = [0x78; 32];
        let chain_id = [0x79; 32];
        let utxo_set = HashMap::from([utxo(
            prev_txid,
            100,
            COV_TYPE_P2PK,
            p2pk_covenant_data_for_pubkey(&pubkey),
        )]);
        let mut tx = unsigned_tx(
            0x01,
            7,
            vec![tx_input(prev_txid)],
            vec![tx_output(0, COV_TYPE_DA_COMMIT, vec![0x33; 32])],
        );
        tx.da_payload = vec![0xde, 0xad, 0xbe, 0xef];
        tx.da_commit_core = Some(DaCommitCore {
            da_id: [0x10; 32],
            chunk_count: 1,
            retl_domain_id: [0x20; 32],
            batch_number: 9,
            tx_data_root: [0x30; 32],
            state_root: [0x40; 32],
            withdrawals_root: [0x50; 32],
            batch_sig_suite: 0x00,
            batch_sig: vec![0xaa, 0xbb],
        });
        sign_transaction(&mut tx, &utxo_set, chain_id, &keypair).expect("sign");
        (tx, utxo_set, txid, chain_id)
    }

    fn sign_input_witness(
        tx: &Tx,
        input_index: u32,
        input_value: u64,
        chain_id: [u8; 32],
        keypair: &Mldsa87Keypair,
    ) -> WitnessItem {
        let digest = sighash_v1_digest(tx, input_index, input_value, chain_id).expect("digest");
        let mut signature = keypair.sign_digest32(digest).expect("sign");
        signature.push(SIGHASH_ALL);
        WitnessItem {
            suite_id: SUITE_ID_ML_DSA_87,
            pubkey: keypair.pubkey_bytes(),
            signature,
        }
    }

    fn encode_vault_covenant_data(
        owner_lock_id: [u8; 32],
        threshold: u8,
        keys: &[[u8; 32]],
        whitelist: &[[u8; 32]],
    ) -> Vec<u8> {
        let mut data = Vec::with_capacity(32 + 1 + 1 + keys.len() * 32 + 2 + whitelist.len() * 32);
        data.extend_from_slice(&owner_lock_id);
        data.push(threshold);
        data.push(keys.len() as u8);
        for key in keys {
            data.extend_from_slice(key);
        }
        data.extend_from_slice(&(whitelist.len() as u16).to_le_bytes());
        for entry in whitelist {
            data.extend_from_slice(entry);
        }
        data
    }

    fn encode_multisig_covenant_data(threshold: u8, keys: &[[u8; 32]]) -> Vec<u8> {
        let mut data = Vec::with_capacity(2 + keys.len() * 32);
        data.push(threshold);
        data.push(keys.len() as u8);
        for key in keys {
            data.extend_from_slice(key);
        }
        data
    }

    fn encode_htlc_covenant_data(
        hash: [u8; 32],
        lock_mode: u8,
        lock_value: u64,
        claim_key_id: [u8; 32],
        refund_key_id: [u8; 32],
    ) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&hash);
        data.push(lock_mode);
        data.extend_from_slice(&lock_value.to_le_bytes());
        data.extend_from_slice(&claim_key_id);
        data.extend_from_slice(&refund_key_id);
        data
    }

    fn htlc_selector_payload(preimage: &[u8]) -> Vec<u8> {
        let mut payload = Vec::with_capacity(3 + preimage.len());
        let preimage_len =
            u16::try_from(preimage.len()).expect("test htlc preimage length fits u16");
        payload.push(0x00);
        payload.extend_from_slice(&preimage_len.to_le_bytes());
        payload.extend_from_slice(preimage);
        payload
    }

    fn stealth_covenant_data_for_pubkey(pubkey: &[u8]) -> Vec<u8> {
        let mut covenant_data = vec![0u8; MAX_STEALTH_COVENANT_DATA as usize];
        let split = covenant_data.len() - 32;
        covenant_data[split..].copy_from_slice(&sha3_256(pubkey));
        covenant_data
    }

    fn signed_vault_case() -> (Tx, HashMap<Outpoint, UtxoEntry>, [u8; 32], [u8; 32]) {
        let prev_vault = [0x81; 32];
        let prev_fee = [0x82; 32];
        let txid = [0x83; 32];
        let chain_id = [0x84; 32];

        let vault_kp = Mldsa87Keypair::generate().expect("vault keypair");
        let owner_kp = Mldsa87Keypair::generate().expect("owner keypair");
        let dest_kp = Mldsa87Keypair::generate().expect("dest keypair");

        let owner_cov = p2pk_covenant_data_for_pubkey(&owner_kp.pubkey_bytes());
        let owner_lock_id = sha3_256(&output_descriptor_bytes(COV_TYPE_P2PK, &owner_cov));

        let dest_cov = p2pk_covenant_data_for_pubkey(&dest_kp.pubkey_bytes());
        let whitelist_h = sha3_256(&output_descriptor_bytes(COV_TYPE_P2PK, &dest_cov));
        let vault_key_id = sha3_256(&vault_kp.pubkey_bytes());
        let vault_cov =
            encode_vault_covenant_data(owner_lock_id, 1, &[vault_key_id], &[whitelist_h]);

        let mut tx = unsigned_tx(
            0x00,
            1,
            vec![tx_input(prev_vault), tx_input(prev_fee)],
            vec![tx_output(100, COV_TYPE_P2PK, dest_cov)],
        );
        tx.witness = vec![
            sign_input_witness(&tx, 0, 100, chain_id, &vault_kp),
            sign_input_witness(&tx, 1, 10, chain_id, &owner_kp),
        ];

        let utxo_set = HashMap::from([
            utxo(prev_vault, 100, COV_TYPE_VAULT, vault_cov),
            utxo(prev_fee, 10, COV_TYPE_P2PK, owner_cov),
        ]);

        (tx, utxo_set, txid, chain_id)
    }

    fn signed_multisig_case() -> (Tx, HashMap<Outpoint, UtxoEntry>, [u8; 32], [u8; 32]) {
        let prev_txid = [0x91; 32];
        let txid = [0x92; 32];
        let chain_id = [0x93; 32];

        let multisig_kp = Mldsa87Keypair::generate().expect("multisig keypair");
        let dest_kp = Mldsa87Keypair::generate().expect("dest keypair");

        let multisig_cov =
            encode_multisig_covenant_data(1, &[sha3_256(&multisig_kp.pubkey_bytes())]);
        let dest_cov = p2pk_covenant_data_for_pubkey(&dest_kp.pubkey_bytes());

        let mut tx = Tx {
            version: 1,
            tx_kind: 0x00,
            tx_nonce: 1,
            inputs: vec![TxInput {
                prev_txid,
                prev_vout: 0,
                script_sig: vec![],
                sequence: 0,
            }],
            outputs: vec![TxOutput {
                value: 90,
                covenant_type: COV_TYPE_P2PK,
                covenant_data: dest_cov,
            }],
            locktime: 0,
            witness: vec![],
            da_payload: vec![],
            da_commit_core: None,
            da_chunk_core: None,
        };
        tx.witness = vec![sign_input_witness(&tx, 0, 100, chain_id, &multisig_kp)];

        let utxo_set = HashMap::from([(
            Outpoint {
                txid: prev_txid,
                vout: 0,
            },
            UtxoEntry {
                value: 100,
                covenant_type: COV_TYPE_MULTISIG,
                covenant_data: multisig_cov,
                creation_height: 0,
                created_by_coinbase: false,
            },
        )]);

        (tx, utxo_set, txid, chain_id)
    }

    fn signed_htlc_case() -> (Tx, HashMap<Outpoint, UtxoEntry>, [u8; 32], [u8; 32]) {
        let prev_htlc = [0xa1; 32];
        let prev_p2pk = [0xa2; 32];
        let txid = [0xa3; 32];
        let chain_id = [0xa4; 32];

        let claim_kp = Mldsa87Keypair::generate().expect("claim keypair");
        let refund_kp = Mldsa87Keypair::generate().expect("refund keypair");
        let p2pk_kp = Mldsa87Keypair::generate().expect("p2pk keypair");
        let dest_kp = Mldsa87Keypair::generate().expect("dest keypair");

        let claim_key_id = sha3_256(&claim_kp.pubkey_bytes());
        let refund_key_id = sha3_256(&refund_kp.pubkey_bytes());
        let p2pk_cov = p2pk_covenant_data_for_pubkey(&p2pk_kp.pubkey_bytes());
        let dest_cov = p2pk_covenant_data_for_pubkey(&dest_kp.pubkey_bytes());

        let preimage = b"htlc-claim-preimage";
        let mut tx = unsigned_tx(
            0x00,
            1,
            vec![tx_input(prev_htlc), tx_input(prev_p2pk)],
            vec![tx_output(150, COV_TYPE_P2PK, dest_cov)],
        );
        tx.witness = vec![
            WitnessItem {
                suite_id: SUITE_ID_SENTINEL,
                pubkey: claim_key_id.to_vec(),
                signature: htlc_selector_payload(preimage),
            },
            sign_input_witness(&tx, 0, 100, chain_id, &claim_kp),
            sign_input_witness(&tx, 1, 70, chain_id, &p2pk_kp),
        ];

        let utxo_set = HashMap::from([
            utxo(
                prev_htlc,
                100,
                COV_TYPE_HTLC,
                encode_htlc_covenant_data(
                    sha3_256(preimage),
                    LOCK_MODE_HEIGHT,
                    1,
                    claim_key_id,
                    refund_key_id,
                ),
            ),
            utxo(prev_p2pk, 70, COV_TYPE_P2PK, p2pk_cov),
        ]);

        (tx, utxo_set, txid, chain_id)
    }

    fn signed_stealth_case() -> (Tx, HashMap<Outpoint, UtxoEntry>, [u8; 32], [u8; 32]) {
        let prev_txid = [0xb1; 32];
        let txid = [0xb2; 32];
        let chain_id = [0xb3; 32];

        let keypair = Mldsa87Keypair::generate().expect("stealth keypair");
        let output_cov = p2pk_covenant_data_for_pubkey(&keypair.pubkey_bytes());

        let mut tx = Tx {
            version: 1,
            tx_kind: 0x00,
            tx_nonce: 1,
            inputs: vec![TxInput {
                prev_txid,
                prev_vout: 0,
                script_sig: vec![],
                sequence: 0,
            }],
            outputs: vec![TxOutput {
                value: 400,
                covenant_type: COV_TYPE_P2PK,
                covenant_data: output_cov,
            }],
            locktime: 0,
            witness: vec![],
            da_payload: vec![],
            da_commit_core: None,
            da_chunk_core: None,
        };
        tx.witness = vec![sign_input_witness(&tx, 0, 500, chain_id, &keypair)];

        let utxo_set = HashMap::from([(
            Outpoint {
                txid: prev_txid,
                vout: 0,
            },
            UtxoEntry {
                value: 500,
                covenant_type: COV_TYPE_CORE_STEALTH,
                covenant_data: stealth_covenant_data_for_pubkey(&keypair.pubkey_bytes()),
                creation_height: 0,
                created_by_coinbase: false,
            },
        )]);

        (tx, utxo_set, txid, chain_id)
    }

    fn assert_apply_preserves_caller_utxos(
        tx: &Tx,
        utxo_set: &HashMap<Outpoint, UtxoEntry>,
        txid: [u8; 32],
        chain_id: [u8; 32],
    ) {
        let original = utxo_set.clone();
        let (_work, summary) = apply_non_coinbase_tx_basic_update_with_mtp_and_suite_context(
            tx, txid, utxo_set, 200, 1_000, 1_000, chain_id, None, None,
        )
        .expect("apply");
        assert!(summary.fee > 0);
        assert_eq!(utxo_set, &original, "caller utxo set mutated");
    }

    #[test]
    fn apply_non_coinbase_tx_basic_update_deferred_sigchecks_matches_sequential() {
        let (tx, utxo_set, txid, chain_id) = signed_p2pk_case();

        let sequential = apply_non_coinbase_tx_basic_update_with_mtp_and_suite_context(
            &tx, txid, &utxo_set, 1, 0, 0, chain_id, None, None,
        )
        .expect("sequential apply");

        let deferred =
            apply_non_coinbase_tx_basic_update_with_mtp_and_suite_context_deferred_sigchecks(
                &tx, txid, &utxo_set, 1, 0, 0, chain_id, None, None,
            )
            .expect("deferred apply");

        assert_eq!(deferred, sequential);
    }

    #[test]
    fn apply_non_coinbase_tx_basic_update_with_suite_context_does_not_mutate_caller_utxos() {
        let (tx, utxo_set, txid, chain_id) = signed_p2pk_case();
        assert_apply_preserves_caller_utxos(&tx, &utxo_set, txid, chain_id);
    }

    #[test]
    fn apply_non_coinbase_tx_basic_update_vault_does_not_mutate_caller_utxos() {
        let (tx, utxo_set, txid, chain_id) = signed_vault_case();
        assert_apply_preserves_caller_utxos(&tx, &utxo_set, txid, chain_id);
    }

    #[test]
    fn apply_non_coinbase_tx_basic_update_multisig_does_not_mutate_caller_utxos() {
        let (tx, utxo_set, txid, chain_id) = signed_multisig_case();
        assert_apply_preserves_caller_utxos(&tx, &utxo_set, txid, chain_id);
    }

    #[test]
    fn apply_non_coinbase_tx_basic_update_htlc_does_not_mutate_caller_utxos() {
        let (tx, utxo_set, txid, chain_id) = signed_htlc_case();
        assert_apply_preserves_caller_utxos(&tx, &utxo_set, txid, chain_id);
    }

    #[test]
    fn apply_non_coinbase_tx_basic_update_stealth_does_not_mutate_caller_utxos() {
        let (tx, utxo_set, txid, chain_id) = signed_stealth_case();
        assert_apply_preserves_caller_utxos(&tx, &utxo_set, txid, chain_id);
    }

    #[test]
    fn apply_non_coinbase_tx_basic_update_anchor_output_does_not_mutate_caller_utxos() {
        let (tx, utxo_set, txid, chain_id) = signed_anchor_output_case();
        assert_apply_preserves_caller_utxos(&tx, &utxo_set, txid, chain_id);
    }

    #[test]
    fn apply_non_coinbase_tx_basic_update_da_commit_output_does_not_mutate_caller_utxos() {
        let (tx, utxo_set, txid, chain_id) = signed_da_commit_output_case();
        assert_apply_preserves_caller_utxos(&tx, &utxo_set, txid, chain_id);
    }

    #[test]
    fn apply_non_coinbase_tx_basic_update_deferred_sigchecks_fails_closed_on_bad_signature() {
        let (mut tx, utxo_set, txid, chain_id) = signed_p2pk_case();
        tx.witness[0].signature[0] ^= 0x01;

        let err = apply_non_coinbase_tx_basic_update_with_mtp_and_suite_context_deferred_sigchecks(
            &tx, txid, &utxo_set, 1, 0, 0, chain_id, None, None,
        )
        .expect_err("bad signature must fail");

        assert_eq!(err.code, ErrorCode::TxErrSigInvalid);
    }

    #[test]
    fn apply_non_coinbase_tx_basic_update_deferred_sigchecks_rolls_back_queue_on_late_tx_error() {
        let (mut tx, utxo_set, txid, chain_id) = signed_p2pk_case();
        tx.outputs[0].value = 101;

        let err = apply_non_coinbase_tx_basic_update_with_mtp_and_suite_context_deferred_sigchecks(
            &tx, txid, &utxo_set, 1, 0, 0, chain_id, None, None,
        )
        .expect_err("late value-conservation failure must return error, not leave queued tasks");

        assert_eq!(err.code, ErrorCode::TxErrValueConservation);
    }
}
