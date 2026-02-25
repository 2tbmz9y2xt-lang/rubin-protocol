use std::collections::HashMap;

use crate::constants::{
    COINBASE_MATURITY, COV_TYPE_ANCHOR, COV_TYPE_DA_COMMIT, COV_TYPE_HTLC, COV_TYPE_MULTISIG,
    COV_TYPE_P2PK, COV_TYPE_VAULT,
};
use crate::covenant_genesis::validate_tx_covenants_genesis;
use crate::error::{ErrorCode, TxError};
use crate::hash::sha3_256;
use crate::htlc::{parse_htlc_covenant_data, validate_htlc_spend};
use crate::sighash::sighash_v1_digest;
use crate::spend_verify::{validate_p2pk_spend, validate_threshold_sig_spend};
use crate::tx::Tx;
use crate::vault::{
    hash_in_sorted_32, output_descriptor_bytes, parse_multisig_covenant_data,
    parse_vault_covenant_data, witness_slots,
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
    let _ = block_timestamp;
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

    validate_tx_covenants_genesis(tx, height)?;

    let mut work = utxo_set.clone();
    let mut sum_in: u128 = 0;
    let mut sum_in_vault: u128 = 0;
    let mut vault_input_count: usize = 0;
    let mut vault_whitelist: Vec<[u8; 32]> = Vec::new();
    let mut vault_owner_lock_id: [u8; 32] = [0u8; 32];
    let mut vault_sig_keys: Vec<[u8; 32]> = Vec::new();
    let mut vault_sig_threshold: u8 = 0;
    let mut vault_sig_witness: Vec<crate::tx::WitnessItem> = Vec::new();
    let mut vault_sig_digest: [u8; 32] = [0u8; 32];
    let mut have_vault_sig: bool = false;
    let mut witness_cursor: usize = 0;
    let mut input_lock_ids: Vec<[u8; 32]> = Vec::with_capacity(tx.inputs.len());
    let mut input_cov_types: Vec<u16> = Vec::with_capacity(tx.inputs.len());
    let mut seen_inputs: HashMap<Outpoint, ()> = HashMap::with_capacity(tx.inputs.len());
    let zero_txid: [u8; 32] = [0u8; 32];

    for (input_index, input) in tx.inputs.iter().enumerate() {
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

        if entry.created_by_coinbase && height < entry.creation_height + COINBASE_MATURITY {
            return Err(TxError::new(
                ErrorCode::TxErrCoinbaseImmature,
                "coinbase immature",
            ));
        }
        let digest = sighash_v1_digest(tx, input_index as u32, entry.value, chain_id)?;

        check_spend_covenant(entry.covenant_type, &entry.covenant_data)?;
        let slots = witness_slots(entry.covenant_type, &entry.covenant_data)?;
        if slots == 0 {
            return Err(TxError::new(ErrorCode::TxErrParse, "invalid witness slots"));
        }
        if witness_cursor + slots > tx.witness.len() {
            return Err(TxError::new(ErrorCode::TxErrParse, "witness underflow"));
        }
        let assigned = &tx.witness[witness_cursor..witness_cursor + slots];

        match entry.covenant_type {
            COV_TYPE_P2PK => {
                if slots != 1 {
                    return Err(TxError::new(
                        ErrorCode::TxErrParse,
                        "CORE_P2PK witness_slots must be 1",
                    ));
                }
                validate_p2pk_spend(&entry, &assigned[0], &digest, height)?;
            }
            COV_TYPE_MULTISIG => {
                let m = parse_multisig_covenant_data(&entry.covenant_data)?;
                validate_threshold_sig_spend(
                    &m.keys,
                    m.threshold,
                    assigned,
                    &digest,
                    height,
                    "CORE_MULTISIG",
                )?;
            }
            COV_TYPE_VAULT => {
                let v = parse_vault_covenant_data(&entry.covenant_data)?;
                // CORE_VAULT signature threshold is checked later (CANONICAL §24.1),
                // after owner-authorization and no-fee-sponsorship checks.
                vault_sig_keys = v.keys.clone();
                vault_sig_threshold = v.threshold;
                vault_sig_witness = assigned.to_vec();
                vault_sig_digest = digest;
                have_vault_sig = true;
            }
            COV_TYPE_HTLC => {
                if slots != 2 {
                    return Err(TxError::new(
                        ErrorCode::TxErrParse,
                        "CORE_HTLC witness_slots must be 2",
                    ));
                }
                validate_htlc_spend(
                    &entry,
                    &assigned[0],
                    &assigned[1],
                    &digest,
                    height,
                    block_mtp,
                )?;
            }
            _ => {}
        }
        witness_cursor += slots;

        let desc = output_descriptor_bytes(entry.covenant_type, &entry.covenant_data);
        let input_lock_id = sha3_256(&desc);
        input_lock_ids.push(input_lock_id);
        input_cov_types.push(entry.covenant_type);

        sum_in = sum_in
            .checked_add(entry.value as u128)
            .ok_or_else(|| TxError::new(ErrorCode::TxErrParse, "u128 overflow"))?;
        if entry.covenant_type == COV_TYPE_VAULT {
            vault_input_count += 1;
            if vault_input_count > 1 {
                return Err(TxError::new(
                    ErrorCode::TxErrVaultMultiInputForbidden,
                    "multiple CORE_VAULT inputs forbidden",
                ));
            }
            let v = parse_vault_covenant_data(&entry.covenant_data)?;
            vault_owner_lock_id = v.owner_lock_id;
            vault_whitelist = v.whitelist;
            sum_in_vault = sum_in_vault
                .checked_add(entry.value as u128)
                .ok_or_else(|| TxError::new(ErrorCode::TxErrParse, "u128 overflow"))?;
        }
        work.remove(&op);
    }
    if witness_cursor != tx.witness.len() {
        return Err(TxError::new(
            ErrorCode::TxErrParse,
            "witness_count mismatch",
        ));
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

            let mut has_owner_lock_id = false;
            let mut has_owner_lock_type = false;
            for i in 0..input_lock_ids.len() {
                if input_lock_ids[i] != owner_lock_id {
                    continue;
                }
                has_owner_lock_id = true;
                if input_cov_types[i] == COV_TYPE_P2PK || input_cov_types[i] == COV_TYPE_MULTISIG {
                    has_owner_lock_type = true;
                }
            }
            if !has_owner_lock_id || !has_owner_lock_type {
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
        let mut owner_auth_present = false;
        for h in &input_lock_ids {
            if *h == vault_owner_lock_id {
                owner_auth_present = true;
                break;
            }
        }
        if !owner_auth_present {
            return Err(TxError::new(
                ErrorCode::TxErrVaultOwnerAuthRequired,
                "missing owner-authorized input for CORE_VAULT spend",
            ));
        }

        // No fee sponsorship: all non-vault inputs must be owned by the same owner lock.
        for i in 0..input_cov_types.len() {
            if input_cov_types[i] == COV_TYPE_VAULT {
                continue;
            }
            if input_lock_ids[i] != vault_owner_lock_id {
                return Err(TxError::new(
                    ErrorCode::TxErrVaultFeeSponsorForbidden,
                    "non-owner non-vault input forbidden in CORE_VAULT spend",
                ));
            }
        }

        // Signature threshold check (CANONICAL §24.1 step 7).
        validate_threshold_sig_spend(
            &vault_sig_keys,
            vault_sig_threshold,
            &vault_sig_witness,
            &vault_sig_digest,
            height,
            "CORE_VAULT",
        )?;

        // Whitelist enforcement: all outputs must be whitelisted.
        for out in &tx.outputs {
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

#[allow(dead_code)]
fn check_spend_covenant(covenant_type: u16, covenant_data: &[u8]) -> Result<(), TxError> {
    if covenant_type == COV_TYPE_P2PK {
        return Ok(());
    }
    if covenant_type == COV_TYPE_VAULT {
        parse_vault_covenant_data(covenant_data)?;
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
