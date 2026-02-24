use std::collections::HashMap;

use crate::constants::{
    COINBASE_MATURITY, COV_TYPE_ANCHOR, COV_TYPE_DA_COMMIT, COV_TYPE_HTLC, COV_TYPE_MULTISIG,
    COV_TYPE_P2PK, COV_TYPE_VAULT,
};
use crate::covenant_genesis::validate_tx_covenants_genesis;
use crate::error::{ErrorCode, TxError};
use crate::hash::sha3_256;
use crate::htlc::{parse_htlc_covenant_data, validate_htlc_spend};
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
) -> Result<(HashMap<Outpoint, UtxoEntry>, UtxoApplySummary), TxError> {
    if tx.inputs.is_empty() {
        return Err(TxError::new(
            ErrorCode::TxErrParse,
            "non-coinbase must have at least one input",
        ));
    }

    validate_tx_covenants_genesis(tx, height)?;

    let mut work = utxo_set.clone();
    let mut sum_in: u128 = 0;
    let mut sum_in_vault: u128 = 0;
    let mut vault_whitelists: Vec<Vec<[u8; 32]>> = Vec::new();
    let mut has_vault_input = false;
    let mut witness_cursor: usize = 0;

    for input in &tx.inputs {
        let op = Outpoint {
            txid: input.prev_txid,
            vout: input.prev_vout,
        };
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
        if entry.covenant_type == COV_TYPE_HTLC {
            let slots = 2usize;
            if witness_cursor + slots > tx.witness.len() {
                return Err(TxError::new(
                    ErrorCode::TxErrParse,
                    "CORE_HTLC witness underflow",
                ));
            }
            validate_htlc_spend(
                &entry,
                &tx.witness[witness_cursor],
                &tx.witness[witness_cursor + 1],
                height,
                block_timestamp,
            )?;
            witness_cursor += slots;
        } else {
            check_spend_covenant(entry.covenant_type, &entry.covenant_data)?;
            let slots = witness_slots(entry.covenant_type, &entry.covenant_data);
            if slots == 0 {
                return Err(TxError::new(ErrorCode::TxErrParse, "invalid witness slots"));
            }
            if witness_cursor + slots > tx.witness.len() {
                return Err(TxError::new(ErrorCode::TxErrParse, "witness underflow"));
            }
            witness_cursor += slots;
        }

        sum_in = sum_in
            .checked_add(entry.value as u128)
            .ok_or_else(|| TxError::new(ErrorCode::TxErrParse, "u128 overflow"))?;
        if entry.covenant_type == COV_TYPE_VAULT {
            has_vault_input = true;
            let v = parse_vault_covenant_data(&entry.covenant_data)?;
            vault_whitelists.push(v.whitelist);
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
    for (i, out) in tx.outputs.iter().enumerate() {
        sum_out = sum_out
            .checked_add(out.value as u128)
            .ok_or_else(|| TxError::new(ErrorCode::TxErrParse, "u128 overflow"))?;

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
    if !vault_whitelists.is_empty() {
        for out in &tx.outputs {
            let desc = output_descriptor_bytes(out.covenant_type, &out.covenant_data);
            let h = sha3_256(&desc);
            for wl in &vault_whitelists {
                if !hash_in_sorted_32(wl, &h) {
                    return Err(TxError::new(
                        ErrorCode::TxErrCovenantTypeInvalid,
                        "output not whitelisted for CORE_VAULT",
                    ));
                }
            }
        }
    }

    if sum_out > sum_in {
        return Err(TxError::new(
            ErrorCode::TxErrValueConservation,
            "sum_out exceeds sum_in",
        ));
    }
    if has_vault_input && sum_out < sum_in_vault {
        return Err(TxError::new(
            ErrorCode::TxErrValueConservation,
            "vault inputs cannot fund miner fee",
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
) -> Result<UtxoApplySummary, TxError> {
    let (_work, summary) =
        apply_non_coinbase_tx_basic_update(tx, txid, utxo_set, height, block_timestamp)?;
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
