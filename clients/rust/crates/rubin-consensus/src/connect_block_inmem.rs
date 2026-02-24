use std::collections::HashMap;

use crate::block_basic::{
    parse_block_bytes, validate_block_basic_with_context_at_height, ParsedBlock,
};
use crate::constants::{COV_TYPE_ANCHOR, COV_TYPE_DA_COMMIT};
use crate::error::{ErrorCode, TxError};
use crate::subsidy::block_subsidy;
use crate::utxo_basic::{apply_non_coinbase_tx_basic_update, Outpoint, UtxoEntry};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InMemoryChainState {
    pub utxos: HashMap<Outpoint, UtxoEntry>,
    /// already_generated(h): subsidy-only (excluding fees).
    pub already_generated: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectBlockBasicSummary {
    pub sum_fees: u64,
    pub already_generated: u64,
    pub already_generated_n1: u64,
    pub utxo_count: u64,
}

fn validate_coinbase_value_bound(
    pb: &ParsedBlock,
    block_height: u64,
    already_generated: u64,
    sum_fees: u64,
) -> Result<(), TxError> {
    // Keep behavior aligned with block_basic.rs implementation.
    if pb.txs.is_empty() {
        return Err(TxError::new(
            ErrorCode::BlockErrCoinbaseInvalid,
            "missing coinbase",
        ));
    }
    if block_height == 0 {
        return Ok(());
    }

    let coinbase = &pb.txs[0];
    let mut sum_coinbase: u64 = 0;
    for out in &coinbase.outputs {
        sum_coinbase = sum_coinbase
            .checked_add(out.value)
            .ok_or_else(|| TxError::new(ErrorCode::BlockErrParse, "coinbase value overflow"))?;
    }
    let subsidy = block_subsidy(block_height, already_generated);
    let limit = subsidy
        .checked_add(sum_fees)
        .ok_or_else(|| TxError::new(ErrorCode::BlockErrParse, "subsidy+fees overflow"))?;
    if sum_coinbase > limit {
        return Err(TxError::new(
            ErrorCode::BlockErrSubsidyExceeded,
            "coinbase outputs exceed subsidy+fees bound",
        ));
    }
    Ok(())
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
) -> Result<ConnectBlockBasicSummary, TxError> {
    // Stateless checks first.
    validate_block_basic_with_context_at_height(
        block_bytes,
        expected_prev_hash,
        expected_target,
        block_height,
        prev_timestamps,
    )?;

    let pb = parse_block_bytes(block_bytes)?;
    if pb.txs.is_empty() || pb.txids.len() != pb.txs.len() {
        return Err(TxError::new(
            ErrorCode::BlockErrParse,
            "invalid parsed block",
        ));
    }

    let already_generated = state.already_generated;

    let mut sum_fees: u64 = 0;
    for i in 1..pb.txs.len() {
        let (next_utxos, s) = apply_non_coinbase_tx_basic_update(
            &pb.txs[i],
            pb.txids[i],
            &state.utxos,
            block_height,
            pb.header.timestamp,
        )?;
        state.utxos = next_utxos;
        sum_fees = sum_fees
            .checked_add(s.fee)
            .ok_or_else(|| TxError::new(ErrorCode::BlockErrParse, "sum_fees overflow"))?;
    }

    validate_coinbase_value_bound(&pb, block_height, already_generated, sum_fees)?;

    // Add coinbase spendable outputs to UTXO set.
    let coinbase_txid = pb.txids[0];
    for (i, out) in pb.txs[0].outputs.iter().enumerate() {
        if out.covenant_type == COV_TYPE_ANCHOR || out.covenant_type == COV_TYPE_DA_COMMIT {
            continue;
        }
        state.utxos.insert(
            Outpoint {
                txid: coinbase_txid,
                vout: i as u32,
            },
            UtxoEntry {
                value: out.value,
                covenant_type: out.covenant_type,
                covenant_data: out.covenant_data.clone(),
                creation_height: block_height,
                created_by_coinbase: true,
            },
        );
    }

    let mut already_generated_n1 = already_generated;
    if block_height != 0 {
        let subsidy = block_subsidy(block_height, already_generated);
        already_generated_n1 = already_generated
            .checked_add(subsidy)
            .ok_or_else(|| TxError::new(ErrorCode::BlockErrParse, "already_generated overflow"))?;
        state.already_generated = already_generated_n1;
    }

    Ok(ConnectBlockBasicSummary {
        sum_fees,
        already_generated,
        already_generated_n1,
        utxo_count: state.utxos.len() as u64,
    })
}
