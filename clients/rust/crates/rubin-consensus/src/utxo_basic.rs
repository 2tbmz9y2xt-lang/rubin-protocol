use std::collections::HashMap;
use std::ops::Range;

use crate::constants::{
    COINBASE_MATURITY, COV_TYPE_ANCHOR, COV_TYPE_DA_COMMIT, COV_TYPE_EXT, COV_TYPE_HTLC,
    COV_TYPE_MULTISIG, COV_TYPE_P2PK, COV_TYPE_STEALTH, COV_TYPE_VAULT,
};
use crate::core_ext::{validate_core_ext_spend_with_cache_and_suite_context_q, CoreExtProfiles};
use crate::covenant_genesis::validate_tx_covenants_genesis;
use crate::error::{ErrorCode, TxError};
use crate::hash::sha3_256;
use crate::htlc::{parse_htlc_covenant_data, validate_htlc_spend_q};
use crate::sig_queue::SigCheckQueue;
use crate::sighash::SighashV1PrehashCache;
use crate::spend_verify::{validate_p2pk_spend_q, validate_threshold_sig_spend_q};
use crate::stealth::{parse_stealth_covenant_data, validate_stealth_spend_q};
use crate::suite_registry::{RotationProvider, SuiteRegistry};
use crate::tx::Tx;
use crate::txcontext::{
    build_tx_context, build_tx_context_output_ext_id_cache, collect_txcontext_ext_ids,
};
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
    pub fee: u64,
    pub utxo_count: u64,
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
    apply_non_coinbase_tx_basic_update_with_mtp_and_core_ext_profiles(
        tx,
        txid,
        utxo_set,
        height,
        block_timestamp,
        block_mtp,
        chain_id,
        &CoreExtProfiles::empty(),
    )
}

#[allow(clippy::too_many_arguments)]
pub fn apply_non_coinbase_tx_basic_update_with_mtp_and_core_ext_profiles(
    tx: &Tx,
    txid: [u8; 32],
    utxo_set: &HashMap<Outpoint, UtxoEntry>,
    height: u64,
    block_timestamp: u64,
    block_mtp: u64,
    chain_id: [u8; 32],
    core_ext_profiles_at_height: &CoreExtProfiles,
) -> Result<(HashMap<Outpoint, UtxoEntry>, UtxoApplySummary), TxError> {
    apply_non_coinbase_tx_basic_update_with_mtp_and_core_ext_profiles_and_suite_context(
        tx,
        txid,
        utxo_set,
        height,
        block_timestamp,
        block_mtp,
        chain_id,
        core_ext_profiles_at_height,
        None,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn apply_non_coinbase_tx_basic_update_with_mtp_and_core_ext_profiles_and_suite_context(
    tx: &Tx,
    txid: [u8; 32],
    utxo_set: &HashMap<Outpoint, UtxoEntry>,
    height: u64,
    block_timestamp: u64,
    block_mtp: u64,
    chain_id: [u8; 32],
    core_ext_profiles_at_height: &CoreExtProfiles,
    rotation: Option<&dyn RotationProvider>,
    registry: Option<&SuiteRegistry>,
) -> Result<(HashMap<Outpoint, UtxoEntry>, UtxoApplySummary), TxError> {
    apply_non_coinbase_tx_basic_update_with_mtp_and_core_ext_profiles_and_suite_context_impl(
        tx,
        txid,
        utxo_set,
        height,
        block_timestamp,
        block_mtp,
        chain_id,
        core_ext_profiles_at_height,
        rotation,
        registry,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn apply_non_coinbase_tx_basic_update_with_mtp_and_core_ext_profiles_and_suite_context_deferred_sigchecks(
    tx: &Tx,
    txid: [u8; 32],
    utxo_set: &HashMap<Outpoint, UtxoEntry>,
    height: u64,
    block_timestamp: u64,
    block_mtp: u64,
    chain_id: [u8; 32],
    core_ext_profiles_at_height: &CoreExtProfiles,
    rotation: Option<&dyn RotationProvider>,
    registry: Option<&SuiteRegistry>,
) -> Result<(HashMap<Outpoint, UtxoEntry>, UtxoApplySummary), TxError> {
    let mut sig_queue = SigCheckQueue::new(1);
    let (work, summary) =
        apply_non_coinbase_tx_basic_update_with_mtp_and_core_ext_profiles_and_suite_context_impl(
            tx,
            txid,
            utxo_set,
            height,
            block_timestamp,
            block_mtp,
            chain_id,
            core_ext_profiles_at_height,
            rotation,
            registry,
            Some(&mut sig_queue),
        )?;
    sig_queue.flush()?;
    Ok((work, summary))
}

#[allow(clippy::too_many_arguments)]
fn apply_non_coinbase_tx_basic_update_with_mtp_and_core_ext_profiles_and_suite_context_impl(
    tx: &Tx,
    txid: [u8; 32],
    utxo_set: &HashMap<Outpoint, UtxoEntry>,
    height: u64,
    block_timestamp: u64,
    block_mtp: u64,
    chain_id: [u8; 32],
    core_ext_profiles_at_height: &CoreExtProfiles,
    rotation: Option<&dyn RotationProvider>,
    registry: Option<&SuiteRegistry>,
    sig_queue: Option<&mut SigCheckQueue>,
) -> Result<(HashMap<Outpoint, UtxoEntry>, UtxoApplySummary), TxError> {
    let _ = block_timestamp;
    let mut sig_queue = sig_queue;
    if tx.inputs.is_empty() {
        return Err(TxError::new(
            ErrorCode::TxErrParse,
            "non-coinbase must have at least one input",
        ));
    }
    if tx.tx_nonce == 0 {
        return Err(TxError::new(
            ErrorCode::TxErrTxNonceInvalid,
            "tx_nonce must be >= 1 for non-coinbase",
        ));
    }

    validate_tx_covenants_genesis(tx, height, rotation)?;

    let mut work = utxo_set.clone();
    let mut sighash_cache = SighashV1PrehashCache::new(tx)?;
    let mut sum_in: u128 = 0;
    let mut sum_in_vault: u128 = 0;
    let mut vault_input_count: usize = 0;
    let mut vault_whitelist: Vec<[u8; 32]> = Vec::new();
    let mut vault_owner_lock_id: [u8; 32] = [0u8; 32];
    let mut vault_sig_keys: Vec<[u8; 32]> = Vec::new();
    let mut vault_sig_threshold: u8 = 0;
    let mut vault_sig_witness_range: Option<Range<usize>> = None;
    let mut vault_sig_input_index: u32 = 0;
    let mut vault_sig_input_value: u64 = 0;
    let mut have_vault_sig: bool = false;
    let mut witness_cursor: usize = 0;
    let mut input_lock_ids: Vec<[u8; 32]> = Vec::with_capacity(tx.inputs.len());
    let mut input_cov_types: Vec<u16> = Vec::with_capacity(tx.inputs.len());
    let mut seen_inputs: HashMap<Outpoint, ()> = HashMap::with_capacity(tx.inputs.len());
    let mut resolved_inputs: Vec<UtxoEntry> = Vec::with_capacity(tx.inputs.len());
    let mut resolved_witness_ranges: Vec<Range<usize>> = Vec::with_capacity(tx.inputs.len());
    let mut resolved_outpoints: Vec<Outpoint> = Vec::with_capacity(tx.inputs.len());
    let zero_txid: [u8; 32] = [0u8; 32];

    for input in &tx.inputs {
        if !input.script_sig.is_empty() {
            return Err(TxError::new(
                ErrorCode::TxErrParse,
                "script_sig must be empty under genesis covenant set",
            ));
        }
        if input.sequence > 0x7fffffff {
            return Err(TxError::new(
                ErrorCode::TxErrSequenceInvalid,
                "sequence exceeds 0x7fffffff",
            ));
        }
        if input.prev_vout == 0xffff_ffff && input.prev_txid == zero_txid {
            return Err(TxError::new(
                ErrorCode::TxErrParse,
                "coinbase prevout encoding forbidden in non-coinbase",
            ));
        }
        let op = Outpoint {
            txid: input.prev_txid,
            vout: input.prev_vout,
        };
        if seen_inputs.contains_key(&op) {
            return Err(TxError::new(
                ErrorCode::TxErrParse,
                "duplicate input outpoint",
            ));
        }
        seen_inputs.insert(op.clone(), ());
        let entry = match work.get(&op) {
            Some(v) => v.clone(),
            None => return Err(TxError::new(ErrorCode::TxErrMissingUtxo, "utxo not found")),
        };

        if entry.covenant_type == COV_TYPE_ANCHOR || entry.covenant_type == COV_TYPE_DA_COMMIT {
            return Err(TxError::new(
                ErrorCode::TxErrMissingUtxo,
                "attempt to spend non-spendable covenant",
            ));
        }

        // Overflow-safe maturity check: avoid entry.creation_height + COINBASE_MATURITY wrapping.
        if entry.created_by_coinbase
            && (height < entry.creation_height
                || height - entry.creation_height < COINBASE_MATURITY)
        {
            return Err(TxError::new(
                ErrorCode::TxErrCoinbaseImmature,
                "coinbase immature",
            ));
        }
        if entry.covenant_type == COV_TYPE_VAULT {
            vault_input_count += 1;
            if vault_input_count > 1 {
                return Err(TxError::new(
                    ErrorCode::TxErrVaultMultiInputForbidden,
                    "multiple CORE_VAULT inputs forbidden",
                ));
            }
        }
        check_spend_covenant(entry.covenant_type, &entry.covenant_data)?;
        let slots = witness_slots(entry.covenant_type, &entry.covenant_data)?;
        if slots == 0 {
            return Err(TxError::new(ErrorCode::TxErrParse, "invalid witness slots"));
        }
        if witness_cursor + slots > tx.witness.len() {
            return Err(TxError::new(ErrorCode::TxErrParse, "witness underflow"));
        }
        let assigned_range = witness_cursor..witness_cursor + slots;
        resolved_inputs.push(entry);
        resolved_witness_ranges.push(assigned_range);
        resolved_outpoints.push(op);
        witness_cursor += slots;
    }
    if witness_cursor != tx.witness.len() {
        return Err(TxError::new(
            ErrorCode::TxErrParse,
            "witness_count mismatch",
        ));
    }

    let tx_context_ext_ids =
        collect_txcontext_ext_ids(&resolved_inputs, core_ext_profiles_at_height)?;
    let tx_context = if tx_context_ext_ids.is_empty() {
        None
    } else {
        let output_ext_id_cache = build_tx_context_output_ext_id_cache(tx)?;
        build_tx_context(
            tx,
            &resolved_inputs,
            Some(&output_ext_id_cache),
            height,
            core_ext_profiles_at_height,
        )?
    };

    for (input_index, ((entry, assigned_range), op)) in resolved_inputs
        .iter()
        .zip(resolved_witness_ranges.iter())
        .zip(resolved_outpoints.iter())
        .enumerate()
    {
        let assigned = &tx.witness[assigned_range.clone()];
        match entry.covenant_type {
            COV_TYPE_P2PK => {
                if assigned.len() != 1 {
                    return Err(TxError::new(
                        ErrorCode::TxErrParse,
                        "CORE_P2PK witness_slots must be 1",
                    ));
                }
                match sig_queue.as_mut() {
                    Some(queue) => validate_p2pk_spend_q(
                        entry,
                        &assigned[0],
                        input_index as u32,
                        entry.value,
                        chain_id,
                        height,
                        &mut sighash_cache,
                        Some(&mut **queue),
                        rotation,
                        registry,
                    )?,
                    None => validate_p2pk_spend_q(
                        entry,
                        &assigned[0],
                        input_index as u32,
                        entry.value,
                        chain_id,
                        height,
                        &mut sighash_cache,
                        None,
                        rotation,
                        registry,
                    )?,
                }
            }
            COV_TYPE_MULTISIG => {
                let m = parse_multisig_covenant_data(&entry.covenant_data)?;
                match sig_queue.as_mut() {
                    Some(queue) => validate_threshold_sig_spend_q(
                        &m.keys,
                        m.threshold,
                        assigned,
                        input_index as u32,
                        entry.value,
                        chain_id,
                        height,
                        "CORE_MULTISIG",
                        &mut sighash_cache,
                        Some(&mut **queue),
                        rotation,
                        registry,
                    )?,
                    None => validate_threshold_sig_spend_q(
                        &m.keys,
                        m.threshold,
                        assigned,
                        input_index as u32,
                        entry.value,
                        chain_id,
                        height,
                        "CORE_MULTISIG",
                        &mut sighash_cache,
                        None,
                        rotation,
                        registry,
                    )?,
                }
            }
            COV_TYPE_VAULT => {
                let v = parse_vault_covenant_data_for_spend(&entry.covenant_data)?;
                // CORE_VAULT signature threshold is checked later (CANONICAL §24.1),
                // after owner-authorization and no-fee-sponsorship checks.
                vault_sig_keys = v.keys.clone();
                vault_sig_threshold = v.threshold;
                vault_sig_witness_range = Some(assigned_range.clone());
                vault_sig_input_index = input_index as u32;
                vault_sig_input_value = entry.value;
                vault_owner_lock_id = v.owner_lock_id;
                vault_whitelist = v.whitelist;
                have_vault_sig = true;
            }
            COV_TYPE_HTLC => {
                if assigned.len() != 2 {
                    return Err(TxError::new(
                        ErrorCode::TxErrParse,
                        "CORE_HTLC witness_slots must be 2",
                    ));
                }
                match sig_queue.as_mut() {
                    Some(queue) => validate_htlc_spend_q(
                        entry,
                        &assigned[0],
                        &assigned[1],
                        input_index as u32,
                        entry.value,
                        chain_id,
                        height,
                        block_mtp,
                        &mut sighash_cache,
                        Some(&mut **queue),
                        rotation,
                        registry,
                    )?,
                    None => validate_htlc_spend_q(
                        entry,
                        &assigned[0],
                        &assigned[1],
                        input_index as u32,
                        entry.value,
                        chain_id,
                        height,
                        block_mtp,
                        &mut sighash_cache,
                        None,
                        rotation,
                        registry,
                    )?,
                }
            }
            COV_TYPE_EXT => {
                if assigned.len() != 1 {
                    return Err(TxError::new(
                        ErrorCode::TxErrParse,
                        "CORE_EXT witness_slots must be 1",
                    ));
                }
                match sig_queue.as_mut() {
                    Some(queue) => validate_core_ext_spend_with_cache_and_suite_context_q(
                        entry,
                        &assigned[0],
                        input_index as u32,
                        entry.value,
                        chain_id,
                        height,
                        core_ext_profiles_at_height,
                        rotation,
                        registry,
                        tx_context.as_ref(),
                        Some(&mut **queue),
                        &mut sighash_cache,
                    )?,
                    None => validate_core_ext_spend_with_cache_and_suite_context_q(
                        entry,
                        &assigned[0],
                        input_index as u32,
                        entry.value,
                        chain_id,
                        height,
                        core_ext_profiles_at_height,
                        rotation,
                        registry,
                        tx_context.as_ref(),
                        None,
                        &mut sighash_cache,
                    )?,
                }
            }
            COV_TYPE_STEALTH => {
                if assigned.len() != 1 {
                    return Err(TxError::new(
                        ErrorCode::TxErrParse,
                        "CORE_STEALTH witness_slots must be 1",
                    ));
                }
                match sig_queue.as_mut() {
                    Some(queue) => validate_stealth_spend_q(
                        entry,
                        &assigned[0],
                        input_index as u32,
                        entry.value,
                        chain_id,
                        height,
                        &mut sighash_cache,
                        Some(&mut **queue),
                        rotation,
                        registry,
                    )?,
                    None => validate_stealth_spend_q(
                        entry,
                        &assigned[0],
                        input_index as u32,
                        entry.value,
                        chain_id,
                        height,
                        &mut sighash_cache,
                        None,
                        rotation,
                        registry,
                    )?,
                }
            }
            _ => {}
        }

        let desc = output_descriptor_bytes(entry.covenant_type, &entry.covenant_data);
        let input_lock_id = sha3_256(&desc);
        input_lock_ids.push(input_lock_id);
        input_cov_types.push(entry.covenant_type);

        sum_in = sum_in
            .checked_add(entry.value as u128)
            .ok_or_else(|| TxError::new(ErrorCode::TxErrParse, "u128 overflow"))?;
        if entry.covenant_type == COV_TYPE_VAULT {
            sum_in_vault = sum_in_vault
                .checked_add(entry.value as u128)
                .ok_or_else(|| TxError::new(ErrorCode::TxErrParse, "u128 overflow"))?;
        }
        work.remove(op);
    }

    let mut sum_out: u128 = 0;
    let mut creates_vault = false;
    for (i, out) in tx.outputs.iter().enumerate() {
        sum_out = sum_out
            .checked_add(out.value as u128)
            .ok_or_else(|| TxError::new(ErrorCode::TxErrParse, "u128 overflow"))?;

        if out.covenant_type == COV_TYPE_VAULT {
            creates_vault = true;
        }

        if out.covenant_type == COV_TYPE_ANCHOR || out.covenant_type == COV_TYPE_DA_COMMIT {
            continue;
        }

        work.insert(
            Outpoint {
                txid,
                vout: i as u32,
            },
            UtxoEntry {
                value: out.value,
                covenant_type: out.covenant_type,
                covenant_data: out.covenant_data.clone(),
                creation_height: height,
                created_by_coinbase: false,
            },
        );
    }

    // CORE_VAULT creation rule: any tx creating CORE_VAULT outputs must include an owner-authorized input.
    if creates_vault {
        for out in &tx.outputs {
            if out.covenant_type != COV_TYPE_VAULT {
                continue;
            }
            let v = parse_vault_covenant_data(&out.covenant_data)?;
            let owner_lock_id = v.owner_lock_id;

            if !has_owner_authorized_input(&input_lock_ids, &input_cov_types, owner_lock_id) {
                return Err(TxError::new(
                    ErrorCode::TxErrVaultOwnerAuthRequired,
                    "missing owner-authorized input for CORE_VAULT creation",
                ));
            }
        }
    }

    // CORE_VAULT spend rules: safe-only model with owner binding and strict whitelist.
    if vault_input_count == 1 {
        if !have_vault_sig {
            return Err(TxError::new(
                ErrorCode::TxErrParse,
                "missing CORE_VAULT signature context",
            ));
        }
        // Owner input required.
        if !has_owner_lock_input(&input_lock_ids, vault_owner_lock_id) {
            return Err(TxError::new(
                ErrorCode::TxErrVaultOwnerAuthRequired,
                "missing owner-authorized input for CORE_VAULT spend",
            ));
        }

        // No fee sponsorship: all non-vault inputs must be owned by the same owner lock.
        if !non_vault_inputs_owned_by(&input_lock_ids, &input_cov_types, vault_owner_lock_id) {
            return Err(TxError::new(
                ErrorCode::TxErrVaultFeeSponsorForbidden,
                "non-owner non-vault input forbidden in CORE_VAULT spend",
            ));
        }

        // Circular-reference hardening: vault spends MUST NOT create new CORE_VAULT outputs.
        for out in &tx.outputs {
            if out.covenant_type == COV_TYPE_VAULT {
                return Err(TxError::new(
                    ErrorCode::TxErrVaultOutputNotWhitelisted,
                    "CORE_VAULT outputs forbidden in CORE_VAULT spend",
                ));
            }
        }

        // Signature threshold check (CANONICAL §24.1 step 7).
        let vault_sig_witness = match vault_sig_witness_range.as_ref() {
            Some(range) => &tx.witness[range.clone()],
            None => unreachable!("vault witness range must exist when have_vault_sig is true"),
        };
        match sig_queue.as_mut() {
            Some(queue) => validate_threshold_sig_spend_q(
                &vault_sig_keys,
                vault_sig_threshold,
                vault_sig_witness,
                vault_sig_input_index,
                vault_sig_input_value,
                chain_id,
                height,
                "CORE_VAULT",
                &mut sighash_cache,
                Some(&mut **queue),
                rotation,
                registry,
            )?,
            None => validate_threshold_sig_spend_q(
                &vault_sig_keys,
                vault_sig_threshold,
                vault_sig_witness,
                vault_sig_input_index,
                vault_sig_input_value,
                chain_id,
                height,
                "CORE_VAULT",
                &mut sighash_cache,
                None,
                rotation,
                registry,
            )?,
        }

        // Whitelist enforcement: all outputs must be whitelisted.
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
            if !hash_in_sorted_32(&vault_whitelist, &h) {
                return Err(TxError::new(
                    ErrorCode::TxErrVaultOutputNotWhitelisted,
                    "output not whitelisted for CORE_VAULT",
                ));
            }
        }
    }

    if sum_out > sum_in {
        return Err(TxError::new(
            ErrorCode::TxErrValueConservation,
            "sum_out exceeds sum_in",
        ));
    }
    if vault_input_count == 1 && sum_out < sum_in_vault {
        return Err(TxError::new(
            ErrorCode::TxErrValueConservation,
            "CORE_VAULT value must not fund miner fee",
        ));
    }

    let fee = u64::try_from(sum_in - sum_out)
        .map_err(|_| TxError::new(ErrorCode::TxErrParse, "u64 overflow"))?;

    let summary = UtxoApplySummary {
        fee,
        utxo_count: work.len() as u64,
    };

    Ok((work, summary))
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
    if covenant_type == COV_TYPE_P2PK {
        return Ok(());
    }
    if covenant_type == COV_TYPE_EXT {
        let _ = crate::core_ext::parse_core_ext_covenant_data(covenant_data)?;
        return Ok(());
    }
    if covenant_type == COV_TYPE_STEALTH {
        let _ = parse_stealth_covenant_data(covenant_data)?;
        return Ok(());
    }
    if covenant_type == COV_TYPE_VAULT {
        parse_vault_covenant_data_for_spend(covenant_data)?;
        return Ok(());
    }
    if covenant_type == COV_TYPE_MULTISIG {
        parse_multisig_covenant_data(covenant_data)?;
        return Ok(());
    }
    if covenant_type == COV_TYPE_HTLC {
        parse_htlc_covenant_data(covenant_data)?;
        return Ok(());
    }
    Err(TxError::new(
        ErrorCode::TxErrCovenantTypeInvalid,
        "unsupported covenant in basic apply",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compactsize::encode_compact_size;
    use crate::core_ext::{CoreExtActiveProfile, CoreExtVerificationBinding};
    use crate::tx::{Tx, TxInput, TxOutput, WitnessItem};
    use crate::tx_helpers::{p2pk_covenant_data_for_pubkey, sign_transaction};
    use crate::verify_sig_openssl::Mldsa87Keypair;
    use std::sync::{Mutex, OnceLock};

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct TxContextVerifierRecord {
        ext_id: u16,
        suite_id: u8,
        ext_payload: Vec<u8>,
        total_in: u128,
        total_out: u128,
        height: u64,
        continuing_output_count: u8,
        continuing_values: Vec<u64>,
        continuing_payload_lens: Vec<usize>,
        self_input_value: u64,
    }

    static TEST_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    static TXCTX_RECORD: OnceLock<Mutex<Option<TxContextVerifierRecord>>> = OnceLock::new();

    fn test_lock() -> &'static Mutex<()> {
        TEST_LOCK.get_or_init(|| Mutex::new(()))
    }

    fn txctx_record_slot() -> &'static Mutex<Option<TxContextVerifierRecord>> {
        TXCTX_RECORD.get_or_init(|| Mutex::new(None))
    }

    fn reset_txctx_record() {
        *txctx_record_slot().lock().expect("txctx record lock") = None;
    }

    fn take_txctx_record() -> Option<TxContextVerifierRecord> {
        txctx_record_slot()
            .lock()
            .expect("txctx record lock")
            .take()
    }

    #[allow(clippy::too_many_arguments)]
    fn recording_txcontext_verifier(
        ext_id: u16,
        suite_id: u8,
        _pubkey: &[u8],
        _signature: &[u8],
        _digest32: &[u8; 32],
        ext_payload: &[u8],
        ctx_base: &crate::txcontext::TxContextBase,
        ctx_continuing: &crate::txcontext::TxContextContinuing,
        self_input_value: u64,
    ) -> Result<bool, TxError> {
        let continuing_values = ctx_continuing
            .valid_outputs()
            .iter()
            .map(|output| output.as_ref().expect("continuing output").value)
            .collect();
        let continuing_payload_lens = ctx_continuing
            .valid_outputs()
            .iter()
            .map(|output| {
                output
                    .as_ref()
                    .expect("continuing output")
                    .ext_payload
                    .len()
            })
            .collect();
        *txctx_record_slot().lock().expect("txctx record lock") = Some(TxContextVerifierRecord {
            ext_id,
            suite_id,
            ext_payload: ext_payload.to_vec(),
            total_in: ctx_base.total_in.to_native(),
            total_out: ctx_base.total_out.to_native(),
            height: ctx_base.height,
            continuing_output_count: ctx_continuing.continuing_output_count,
            continuing_values,
            continuing_payload_lens,
            self_input_value,
        });
        Ok(true)
    }

    fn core_ext_covdata(ext_id: u16, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&ext_id.to_le_bytes());
        encode_compact_size(payload.len() as u64, &mut out);
        out.extend_from_slice(payload);
        out
    }

    fn txcontext_profiles() -> CoreExtProfiles {
        CoreExtProfiles {
            active: vec![CoreExtActiveProfile {
                ext_id: 7,
                tx_context_enabled: true,
                allowed_suite_ids: vec![0x42],
                verification_binding: CoreExtVerificationBinding::VerifySigExtAccept,
                verify_sig_ext_tx_context_fn: Some(recording_txcontext_verifier),
                binding_descriptor: b"accept".to_vec(),
                ext_payload_schema: b"schema".to_vec(),
            }],
        }
    }

    fn txcontext_input_utxos(prev_txid: [u8; 32]) -> HashMap<Outpoint, UtxoEntry> {
        HashMap::from([(
            Outpoint {
                txid: prev_txid,
                vout: 0,
            },
            UtxoEntry {
                value: 100,
                covenant_type: COV_TYPE_EXT,
                covenant_data: core_ext_covdata(7, &[0x99]),
                creation_height: 0,
                created_by_coinbase: false,
            },
        )])
    }

    #[test]
    fn apply_non_coinbase_tx_basic_update_core_ext_txcontext_step3c_dispatches_verifier() {
        let _guard = test_lock().lock().expect("test lock");
        reset_txctx_record();

        let mut chain_id = [0u8; 32];
        chain_id[0] = 0x61;
        let mut prev_txid = [0u8; 32];
        prev_txid[0] = 0xb2;
        let mut txid = [0u8; 32];
        txid[0] = 0xb5;

        let tx = Tx {
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
                covenant_type: COV_TYPE_EXT,
                covenant_data: core_ext_covdata(7, &[]),
            }],
            locktime: 0,
            witness: vec![WitnessItem {
                suite_id: 0x42,
                pubkey: vec![0x01, 0x02, 0x03],
                signature: vec![0x04, 0x01],
            }],
            da_payload: vec![],
            da_commit_core: None,
            da_chunk_core: None,
        };

        let (_work, summary) =
            apply_non_coinbase_tx_basic_update_with_mtp_and_core_ext_profiles_and_suite_context(
                &tx,
                txid,
                &txcontext_input_utxos(prev_txid),
                1,
                0,
                0,
                chain_id,
                &txcontext_profiles(),
                None,
                None,
            )
            .expect("apply txcontext tx");
        assert_eq!(summary.fee, 10);

        let record = take_txctx_record().expect("txcontext verifier call");
        assert_eq!(record.ext_id, 7);
        assert_eq!(record.suite_id, 0x42);
        assert_eq!(record.ext_payload, vec![0x99]);
        assert_eq!(record.total_in, 100);
        assert_eq!(record.total_out, 90);
        assert_eq!(record.height, 1);
        assert_eq!(record.continuing_output_count, 1);
        assert_eq!(record.continuing_values, vec![90]);
        assert_eq!(record.continuing_payload_lens, vec![0]);
        assert_eq!(record.self_input_value, 100);
    }

    #[test]
    fn apply_non_coinbase_tx_basic_update_core_ext_txcontext_malformed_output_fails_before_verifier(
    ) {
        let _guard = test_lock().lock().expect("test lock");
        reset_txctx_record();

        let mut chain_id = [0u8; 32];
        chain_id[0] = 0x62;
        let mut prev_txid = [0u8; 32];
        prev_txid[0] = 0xb3;
        let mut txid = [0u8; 32];
        txid[0] = 0xb6;

        let tx = Tx {
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
                covenant_type: COV_TYPE_EXT,
                covenant_data: vec![0x01],
            }],
            locktime: 0,
            witness: vec![WitnessItem {
                suite_id: 0x42,
                pubkey: vec![0x01, 0x02, 0x03],
                signature: vec![0x04, 0x01],
            }],
            da_payload: vec![],
            da_commit_core: None,
            da_chunk_core: None,
        };

        let err =
            apply_non_coinbase_tx_basic_update_with_mtp_and_core_ext_profiles_and_suite_context(
                &tx,
                txid,
                &txcontext_input_utxos(prev_txid),
                1,
                0,
                0,
                chain_id,
                &txcontext_profiles(),
                None,
                None,
            )
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::TxErrCovenantTypeInvalid);
        assert!(take_txctx_record().is_none());
    }

    #[test]
    fn apply_non_coinbase_tx_basic_update_core_ext_txcontext_too_many_outputs_fails_before_verifier(
    ) {
        let _guard = test_lock().lock().expect("test lock");
        reset_txctx_record();

        let mut chain_id = [0u8; 32];
        chain_id[0] = 0x63;
        let mut prev_txid = [0u8; 32];
        prev_txid[0] = 0xb4;
        let mut txid = [0u8; 32];
        txid[0] = 0xb7;

        let tx = Tx {
            version: 1,
            tx_kind: 0x00,
            tx_nonce: 1,
            inputs: vec![TxInput {
                prev_txid,
                prev_vout: 0,
                script_sig: vec![],
                sequence: 0,
            }],
            outputs: vec![
                TxOutput {
                    value: 30,
                    covenant_type: COV_TYPE_EXT,
                    covenant_data: core_ext_covdata(7, &[]),
                },
                TxOutput {
                    value: 30,
                    covenant_type: COV_TYPE_EXT,
                    covenant_data: core_ext_covdata(7, &[0x01]),
                },
                TxOutput {
                    value: 30,
                    covenant_type: COV_TYPE_EXT,
                    covenant_data: core_ext_covdata(7, &[0x02]),
                },
            ],
            locktime: 0,
            witness: vec![WitnessItem {
                suite_id: 0x42,
                pubkey: vec![0x01, 0x02, 0x03],
                signature: vec![0x04, 0x01],
            }],
            da_payload: vec![],
            da_commit_core: None,
            da_chunk_core: None,
        };

        let err =
            apply_non_coinbase_tx_basic_update_with_mtp_and_core_ext_profiles_and_suite_context(
                &tx,
                txid,
                &txcontext_input_utxos(prev_txid),
                1,
                0,
                0,
                chain_id,
                &txcontext_profiles(),
                None,
                None,
            )
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::TxErrCovenantTypeInvalid);
        assert!(take_txctx_record().is_none());
    }

    #[test]
    fn apply_non_coinbase_tx_basic_update_core_ext_txcontext_output_validation_precedes_witness_count_mismatch(
    ) {
        let _guard = test_lock().lock().expect("test lock");
        reset_txctx_record();

        let mut chain_id = [0u8; 32];
        chain_id[0] = 0x64;
        let mut prev_txid = [0u8; 32];
        prev_txid[0] = 0xb5;
        let mut txid = [0u8; 32];
        txid[0] = 0xb8;

        let tx = Tx {
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
                covenant_type: COV_TYPE_EXT,
                covenant_data: vec![0x01],
            }],
            locktime: 0,
            witness: vec![
                WitnessItem {
                    suite_id: 0x42,
                    pubkey: vec![0x01, 0x02, 0x03],
                    signature: vec![0x04, 0x01],
                },
                WitnessItem {
                    suite_id: 0x42,
                    pubkey: vec![0x09],
                    signature: vec![0x08, 0x01],
                },
            ],
            da_payload: vec![],
            da_commit_core: None,
            da_chunk_core: None,
        };

        let err =
            apply_non_coinbase_tx_basic_update_with_mtp_and_core_ext_profiles_and_suite_context(
                &tx,
                txid,
                &txcontext_input_utxos(prev_txid),
                1,
                0,
                0,
                chain_id,
                &txcontext_profiles(),
                None,
                None,
            )
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::TxErrCovenantTypeInvalid);
        assert!(take_txctx_record().is_none());
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

    #[test]
    fn apply_non_coinbase_tx_basic_update_deferred_sigchecks_matches_sequential() {
        let (tx, utxo_set, txid, chain_id) = signed_p2pk_case();

        let sequential =
            apply_non_coinbase_tx_basic_update_with_mtp_and_core_ext_profiles_and_suite_context(
                &tx,
                txid,
                &utxo_set,
                1,
                0,
                0,
                chain_id,
                &CoreExtProfiles::empty(),
                None,
                None,
            )
            .expect("sequential apply");

        let deferred = apply_non_coinbase_tx_basic_update_with_mtp_and_core_ext_profiles_and_suite_context_deferred_sigchecks(
            &tx,
            txid,
            &utxo_set,
            1,
            0,
            0,
            chain_id,
            &CoreExtProfiles::empty(),
            None,
            None,
        )
        .expect("deferred apply");

        assert_eq!(deferred, sequential);
    }

    #[test]
    fn apply_non_coinbase_tx_basic_update_deferred_sigchecks_fails_closed_on_bad_signature() {
        let (mut tx, utxo_set, txid, chain_id) = signed_p2pk_case();
        tx.witness[0].signature[0] ^= 0x01;

        let err = apply_non_coinbase_tx_basic_update_with_mtp_and_core_ext_profiles_and_suite_context_deferred_sigchecks(
            &tx,
            txid,
            &utxo_set,
            1,
            0,
            0,
            chain_id,
            &CoreExtProfiles::empty(),
            None,
            None,
        )
        .expect_err("bad signature must fail");

        assert_eq!(err.code, ErrorCode::TxErrSigInvalid);
    }
}
