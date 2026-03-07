use super::*;
use crate::covenant_genesis::validate_tx_covenants_genesis;
use std::collections::HashMap;

#[derive(Clone, Copy, Debug)]
pub(super) struct BlockTxStats {
    pub(super) sum_weight: u64,
    pub(super) sum_da: u64,
    pub(super) sum_anchor: u64,
}

pub(super) fn accumulate_block_resource_stats(pb: &ParsedBlock) -> Result<BlockTxStats, TxError> {
    let mut stats = BlockTxStats {
        sum_weight: 0,
        sum_da: 0,
        sum_anchor: 0,
    };
    for tx in &pb.txs {
        let (w, da, anchor_bytes) = tx_weight_and_stats(tx)?;
        stats.sum_weight = stats
            .sum_weight
            .checked_add(w)
            .ok_or_else(|| TxError::new(ErrorCode::TxErrParse, "u64 overflow"))?;
        stats.sum_da = stats
            .sum_da
            .checked_add(da)
            .ok_or_else(|| TxError::new(ErrorCode::TxErrParse, "u64 overflow"))?;
        stats.sum_anchor = stats
            .sum_anchor
            .checked_add(anchor_bytes)
            .ok_or_else(|| TxError::new(ErrorCode::TxErrParse, "u64 overflow"))?;
    }
    Ok(stats)
}

pub(super) fn validate_block_tx_semantics(
    pb: &ParsedBlock,
    block_height: u64,
) -> Result<(), TxError> {
    let mut seen_nonces: HashMap<u64, ()> = HashMap::with_capacity(pb.txs.len());
    for (i, tx) in pb.txs.iter().enumerate() {
        if i > 0 {
            if coinbase::is_coinbase_tx(tx) {
                return Err(TxError::new(
                    ErrorCode::BlockErrCoinbaseInvalid,
                    "coinbase-like tx found at index > 0",
                ));
            }
            if tx.inputs.is_empty() {
                return Err(TxError::new(
                    ErrorCode::TxErrParse,
                    "non-coinbase must have at least one input",
                ));
            }
            if seen_nonces.insert(tx.tx_nonce, ()).is_some() {
                return Err(TxError::new(
                    ErrorCode::TxErrNonceReplay,
                    "duplicate tx_nonce in block",
                ));
            }
        }
        validate_tx_covenants_genesis(tx, block_height)?;
    }
    Ok(())
}
