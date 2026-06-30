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
use crate::tx::Tx;
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
    apply_non_coinbase_tx_basic_update_with_mtp_and_core_ext_profiles_and_suite_context(
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
pub fn apply_non_coinbase_tx_basic_update_with_mtp_and_core_ext_profiles_and_suite_context(
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
    apply_non_coinbase_tx_basic_update_with_mtp_and_core_ext_profiles_and_suite_context_impl(
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
pub(crate) fn apply_non_coinbase_tx_basic_update_with_mtp_and_core_ext_profiles_and_suite_context_queued_sigchecks(
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
    apply_non_coinbase_tx_basic_update_with_mtp_and_core_ext_profiles_and_suite_context_impl(
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
        Some(sig_queue),
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
    rotation: Option<&dyn RotationProvider>,
    registry: Option<&SuiteRegistry>,
) -> Result<(HashMap<Outpoint, UtxoEntry>, UtxoApplySummary), TxError> {
    let mut sig_queue = SigCheckQueue::new(1);
    let queue_mark = sig_queue.mark();
    let result = apply_non_coinbase_tx_basic_update_with_mtp_and_core_ext_profiles_and_suite_context_queued_sigchecks(
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

fn apply_non_coinbase_tx_basic_update_with_mtp_and_core_ext_profiles_and_suite_context_impl(
    ctx: UtxoApplyImplContext<'_>,
    sig_queue: Option<&mut SigCheckQueue>,
) -> Result<(HashMap<Outpoint, UtxoEntry>, UtxoApplySummary), TxError> {
    let UtxoApplyImplContext {
        tx,
        txid,
        utxo_set,
        height,
        block_timestamp,
        block_mtp,
        chain_id,
        rotation,
        registry,
    } = ctx;
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
        // Fail-closed: a CORE_SIMPLICITY (0x0106) spend is rejected with the
        // dedicated message ahead of the generic check_spend_covenant/witness
        // errors, matching Go's input-resolution order.
        if entry.covenant_type == COV_TYPE_CORE_SIMPLICITY {
            return Err(reject_core_simplicity_spend());
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

    // COV_TYPE_CORE_EXT (0x0102) is UNASSIGNED and already rejected by
    // `check_spend_covenant`/`witness_slots` (TxErrCovenantTypeInvalid) during
    // input resolution above, so no CORE_EXT profile gating runs here.

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
                validate_p2pk_spend_q(
                    entry,
                    &assigned[0],
                    input_index as u32,
                    entry.value,
                    chain_id,
                    height,
                    &mut sighash_cache,
                    sig_queue.as_deref_mut(),
                    rotation,
                    registry,
                )?;
            }
            COV_TYPE_MULTISIG => {
                let m = parse_multisig_covenant_data(&entry.covenant_data)?;
                validate_threshold_sig_spend_q(
                    &m.keys,
                    m.threshold,
                    assigned,
                    input_index as u32,
                    entry.value,
                    chain_id,
                    height,
                    "CORE_MULTISIG",
                    &mut sighash_cache,
                    sig_queue.as_deref_mut(),
                    rotation,
                    registry,
                )?;
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
                validate_htlc_spend_q(
                    entry,
                    &assigned[0],
                    &assigned[1],
                    HtlcSpendContext {
                        input_index: input_index as u32,
                        input_value: entry.value,
                        chain_id,
                        block_height: height,
                        block_mtp,
                    },
                    &mut sighash_cache,
                    sig_queue.as_deref_mut(),
                    rotation,
                    registry,
                )?;
            }
            COV_TYPE_CORE_STEALTH => {
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
                    chain_id,
                    height,
                    &mut sighash_cache,
                    sig_queue.as_deref_mut(),
                    rotation,
                    registry,
                )?;
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
        validate_threshold_sig_spend_q(
            &vault_sig_keys,
            vault_sig_threshold,
            vault_sig_witness,
            vault_sig_input_index,
            vault_sig_input_value,
            chain_id,
            height,
            "CORE_VAULT",
            &mut sighash_cache,
            sig_queue,
            rotation,
            registry,
        )?;

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
            p2pk_covenant_data_for_pubkey(&pubkey),
        )]);
        let create_tx = unsigned_tx(
            0x00,
            1,
            vec![tx_input(prev_txid)],
            vec![tx_output(90, COV_TYPE_CORE_EXT, vec![0x07, 0x00, 0x00])],
        );
        let create_err =
            apply_non_coinbase_tx_basic_update_with_mtp_and_core_ext_profiles_and_suite_context(
                &create_tx, txid, &funding, 1, 0, 0, chain_id, None, None,
            )
            .expect_err("0x0102 creation must reject");
        assert_eq!(create_err.code, ErrorCode::TxErrCovenantTypeInvalid);

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
                    p2pk_covenant_data_for_pubkey(&pubkey),
                )],
            );
            spend_tx.witness = vec![WitnessItem {
                suite_id: SUITE_ID_ML_DSA_87,
                pubkey: pubkey.to_vec(),
                signature: vec![0u8; 1],
            }];
            let spend_err = apply_non_coinbase_tx_basic_update_with_mtp_and_core_ext_profiles_and_suite_context(
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
            let err = apply_non_coinbase_tx_basic_update_with_mtp_and_core_ext_profiles_and_suite_context(
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
        let (_work, summary) =
            apply_non_coinbase_tx_basic_update_with_mtp_and_core_ext_profiles_and_suite_context(
                tx, txid, utxo_set, 200, 1_000, 1_000, chain_id, None, None,
            )
            .expect("apply");
        assert!(summary.fee > 0);
        assert_eq!(utxo_set, &original, "caller utxo set mutated");
    }

    #[test]
    fn apply_non_coinbase_tx_basic_update_deferred_sigchecks_matches_sequential() {
        let (tx, utxo_set, txid, chain_id) = signed_p2pk_case();

        let sequential =
            apply_non_coinbase_tx_basic_update_with_mtp_and_core_ext_profiles_and_suite_context(
                &tx, txid, &utxo_set, 1, 0, 0, chain_id, None, None,
            )
            .expect("sequential apply");

        let deferred =
            apply_non_coinbase_tx_basic_update_with_mtp_and_core_ext_profiles_and_suite_context_deferred_sigchecks(
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

        let err = apply_non_coinbase_tx_basic_update_with_mtp_and_core_ext_profiles_and_suite_context_deferred_sigchecks(
            &tx, txid, &utxo_set, 1, 0, 0, chain_id, None, None,
        )
        .expect_err("bad signature must fail");

        assert_eq!(err.code, ErrorCode::TxErrSigInvalid);
    }

    #[test]
    fn apply_non_coinbase_tx_basic_update_deferred_sigchecks_rolls_back_queue_on_late_tx_error() {
        let (mut tx, utxo_set, txid, chain_id) = signed_p2pk_case();
        tx.outputs[0].value = 101;

        let err = apply_non_coinbase_tx_basic_update_with_mtp_and_core_ext_profiles_and_suite_context_deferred_sigchecks(
            &tx, txid, &utxo_set, 1, 0, 0, chain_id, None, None,
        )
        .expect_err("late value-conservation failure must return error, not leave queued tasks");

        assert_eq!(err.code, ErrorCode::TxErrValueConservation);
    }
}
