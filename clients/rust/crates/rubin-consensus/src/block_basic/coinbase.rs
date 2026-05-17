use super::*;
use crate::constants::{COV_TYPE_ANCHOR, COV_TYPE_VAULT};
use crate::merkle::{witness_commitment_hash, witness_merkle_root_wtxids};
use crate::subsidy::block_subsidy;
use crate::{TxInput, TxOutput};

pub(super) fn is_coinbase_tx(tx: &Tx) -> bool {
    if !has_coinbase_tx_shape(tx) {
        return false;
    }
    let input = &tx.inputs[0];
    has_coinbase_input_shape(input)
}

fn has_coinbase_tx_shape(tx: &Tx) -> bool {
    [
        tx.tx_kind == 0x00,
        tx.tx_nonce == 0,
        tx.inputs.len() == 1,
        tx.witness.is_empty(),
        tx.da_payload.is_empty(),
    ]
    .into_iter()
    .all(core::convert::identity)
}

fn has_coinbase_input_shape(input: &TxInput) -> bool {
    [
        input.prev_txid == [0u8; 32],
        input.prev_vout == u32::MAX,
        input.script_sig.is_empty(),
        input.sequence == u32::MAX,
    ]
    .into_iter()
    .all(core::convert::identity)
}

pub(super) fn validate_coinbase_structure(
    pb: &ParsedBlock,
    block_height: u64,
) -> Result<(), TxError> {
    let coinbase = pb
        .txs
        .first()
        .ok_or_else(|| TxError::new(ErrorCode::BlockErrCoinbaseInvalid, "missing coinbase"))?;

    if !is_coinbase_tx(coinbase) {
        return Err(TxError::new(
            ErrorCode::BlockErrCoinbaseInvalid,
            "first tx is not canonical coinbase",
        ));
    }
    if coinbase.outputs.is_empty() {
        return Err(TxError::new(
            ErrorCode::BlockErrCoinbaseInvalid,
            "coinbase must have at least one output",
        ));
    }

    let expected_locktime = u32::try_from(block_height)
        .map_err(|_| TxError::new(ErrorCode::BlockErrCoinbaseInvalid, "height out of range"))?;
    if coinbase.locktime != expected_locktime {
        return Err(TxError::new(
            ErrorCode::BlockErrCoinbaseInvalid,
            "coinbase locktime must equal block height",
        ));
    }
    Ok(())
}

pub(crate) fn validate_coinbase_value_bound(
    pb: &ParsedBlock,
    block_height: u64,
    already_generated: u128,
    sum_fees: u64,
) -> Result<(), TxError> {
    if block_height == 0 {
        return Ok(());
    }
    if pb.txs.is_empty() {
        return Err(TxError::new(
            ErrorCode::BlockErrCoinbaseInvalid,
            "missing coinbase",
        ));
    }
    let coinbase = &pb.txs[0];
    let sum_coinbase = sum_coinbase_outputs(coinbase)?;
    let limit = coinbase_value_limit(block_height, already_generated, sum_fees)?;
    if sum_coinbase > limit {
        return Err(TxError::new(
            ErrorCode::BlockErrSubsidyExceeded,
            "coinbase outputs exceed subsidy+fees bound",
        ));
    }
    Ok(())
}

fn sum_coinbase_outputs(coinbase: &Tx) -> Result<u128, TxError> {
    coinbase.outputs.iter().try_fold(0u128, |sum, out| {
        sum.checked_add(out.value as u128)
            .ok_or_else(|| TxError::new(ErrorCode::BlockErrParse, "u128 overflow"))
    })
}

fn coinbase_value_limit(
    block_height: u64,
    already_generated: u128,
    sum_fees: u64,
) -> Result<u128, TxError> {
    let subsidy = block_subsidy(block_height, already_generated);
    (subsidy as u128)
        .checked_add(sum_fees as u128)
        .ok_or_else(|| TxError::new(ErrorCode::BlockErrParse, "u128 overflow"))
}

pub(crate) fn validate_coinbase_apply_outputs(coinbase: &Tx) -> Result<(), TxError> {
    for out in &coinbase.outputs {
        if out.covenant_type == COV_TYPE_VAULT {
            return Err(TxError::new(
                ErrorCode::BlockErrCoinbaseInvalid,
                "coinbase must not create CORE_VAULT outputs",
            ));
        }
    }
    Ok(())
}

pub(super) fn validate_coinbase_witness_commitment(pb: &ParsedBlock) -> Result<(), TxError> {
    let coinbase = pb
        .txs
        .first()
        .ok_or_else(|| TxError::new(ErrorCode::BlockErrCoinbaseInvalid, "missing coinbase"))?;
    if pb.wtxids.is_empty() {
        return Err(TxError::new(
            ErrorCode::BlockErrCoinbaseInvalid,
            "missing coinbase",
        ));
    }

    let wroot = witness_merkle_root_wtxids(&pb.wtxids).map_err(|_| {
        TxError::new(
            ErrorCode::BlockErrWitnessCommitment,
            "failed to compute witness merkle root",
        )
    })?;
    let expected = witness_commitment_hash(wroot);

    let matches = coinbase
        .outputs
        .iter()
        .filter(|out| is_witness_commitment_match(out, &expected))
        .take(2)
        .count();

    if matches != 1 {
        return Err(TxError::new(
            ErrorCode::BlockErrWitnessCommitment,
            "coinbase witness commitment missing or duplicated",
        ));
    }
    Ok(())
}

fn is_witness_commitment_match(out: &TxOutput, expected: &[u8; 32]) -> bool {
    out.covenant_type == COV_TYPE_ANCHOR
        && out.covenant_data.len() == 32
        && out.covenant_data.as_slice() == &expected[..]
}
