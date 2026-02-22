use std::collections::HashMap;

use crate::constants::{
    COINBASE_MATURITY, COV_TYPE_ANCHOR, COV_TYPE_DA_COMMIT, COV_TYPE_P2PK, COV_TYPE_TIMELOCK,
    COV_TYPE_VAULT, MAX_TIMELOCK_COVENANT_DATA,
};
use crate::covenant_genesis::validate_tx_covenants_genesis;
use crate::error::{ErrorCode, TxError};
use crate::tx::Tx;
use crate::vault::parse_vault_covenant_data;

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

pub fn apply_non_coinbase_tx_basic(
    tx: &Tx,
    txid: [u8; 32],
    utxo_set: &HashMap<Outpoint, UtxoEntry>,
    height: u64,
    block_timestamp: u64,
) -> Result<UtxoApplySummary, TxError> {
    if tx.inputs.is_empty() {
        return Err(TxError::new(
            ErrorCode::TxErrParse,
            "non-coinbase must have at least one input",
        ));
    }

    validate_tx_covenants_genesis(tx)?;

    let mut work = utxo_set.clone();
    let mut sum_in: u64 = 0;

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

        check_spend_timelock(
            entry.covenant_type,
            &entry.covenant_data,
            height,
            block_timestamp,
            entry.creation_height,
        )?;

        sum_in = sum_in
            .checked_add(entry.value)
            .ok_or_else(|| TxError::new(ErrorCode::TxErrParse, "u64 overflow"))?;
        work.remove(&op);
    }

    let mut sum_out: u64 = 0;
    for (i, out) in tx.outputs.iter().enumerate() {
        sum_out = sum_out
            .checked_add(out.value)
            .ok_or_else(|| TxError::new(ErrorCode::TxErrParse, "u64 overflow"))?;

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

    if sum_out > sum_in {
        return Err(TxError::new(
            ErrorCode::TxErrValueConservation,
            "sum_out exceeds sum_in",
        ));
    }

    Ok(UtxoApplySummary {
        fee: sum_in - sum_out,
        utxo_count: work.len() as u64,
    })
}

fn check_spend_timelock(
    covenant_type: u16,
    covenant_data: &[u8],
    height: u64,
    block_timestamp: u64,
    creation_height: u64,
) -> Result<(), TxError> {
    if covenant_type == COV_TYPE_P2PK {
        return Ok(());
    }
    if covenant_type == COV_TYPE_VAULT {
        let vault = parse_vault_covenant_data(covenant_data)?;
        // Basic apply path models owner spend-delay guard only.
        if vault.spend_delay > 0 {
            let unlock_height = creation_height
                .checked_add(vault.spend_delay)
                .ok_or_else(|| TxError::new(ErrorCode::TxErrParse, "u64 overflow"))?;
            if height < unlock_height {
                return Err(TxError::new(
                    ErrorCode::TxErrTimelockNotMet,
                    "vault spend_delay not met",
                ));
            }
        }
        return Ok(());
    }
    if covenant_type != COV_TYPE_TIMELOCK {
        return Err(TxError::new(
            ErrorCode::TxErrCovenantTypeInvalid,
            "unsupported covenant in basic apply",
        ));
    }

    if covenant_data.len() as u64 != MAX_TIMELOCK_COVENANT_DATA {
        return Err(TxError::new(
            ErrorCode::TxErrCovenantTypeInvalid,
            "invalid timelock covenant_data length",
        ));
    }

    let lock_mode = covenant_data[0];
    let mut raw = [0u8; 8];
    raw.copy_from_slice(&covenant_data[1..9]);
    let lock_value = u64::from_le_bytes(raw);
    match lock_mode {
        0x00 => {
            if height < lock_value {
                return Err(TxError::new(
                    ErrorCode::TxErrTimelockNotMet,
                    "height timelock not met",
                ));
            }
        }
        0x01 => {
            if block_timestamp < lock_value {
                return Err(TxError::new(
                    ErrorCode::TxErrTimelockNotMet,
                    "timestamp timelock not met",
                ));
            }
        }
        _ => {
            return Err(TxError::new(
                ErrorCode::TxErrCovenantTypeInvalid,
                "invalid timelock lock_mode",
            ));
        }
    }
    Ok(())
}
