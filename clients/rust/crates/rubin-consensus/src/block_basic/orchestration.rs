use super::coinbase::validate_coinbase_witness_commitment;
use super::header::{validate_header_commitments, validate_timestamp_rules};
use super::txs::{accumulate_block_resource_stats, validate_block_tx_semantics, BlockTxStats};
use super::{
    validate_block_resource_limits, validate_da_set_integrity, BlockBasicSummary, ParsedBlock,
};
use crate::block::block_hash;
use crate::error::{ErrorCode, TxError};
use crate::suite_registry::RotationProvider;

/// G.9 / Go parity (`clients/go/consensus/block_basic.go`,
/// `validateParsedBlockBasicWithContextAtHeight`): validation logic against an
/// already-parsed block. Callers that need both the parsed block and the
/// summary parse once via `parse_block_bytes` and then call this helper,
/// instead of re-parsing in both `validate_*` and `connect_*`.
pub(crate) fn validate_parsed_block_basic_with_context_at_height(
    pb: &ParsedBlock,
    expected_prev_hash: Option<[u8; 32]>,
    expected_target: Option<[u8; 32]>,
    block_height: u64,
    prev_timestamps: Option<&[u64]>,
    rotation: Option<&dyn RotationProvider>,
) -> Result<BlockBasicSummary, TxError> {
    let stats = validate_parsed_block_basic_checks(
        pb,
        expected_prev_hash,
        expected_target,
        block_height,
        prev_timestamps,
        rotation,
    )?;
    let h = block_hash(&pb.header_bytes)
        .map_err(|_| TxError::new(ErrorCode::BlockErrParse, "failed to hash block header"))?;

    Ok(BlockBasicSummary {
        tx_count: pb.tx_count,
        sum_weight: stats.sum_weight,
        sum_da: stats.sum_da,
        block_hash: h,
    })
}

fn validate_parsed_block_basic_checks(
    pb: &ParsedBlock,
    expected_prev_hash: Option<[u8; 32]>,
    expected_target: Option<[u8; 32]>,
    block_height: u64,
    prev_timestamps: Option<&[u64]>,
    rotation: Option<&dyn RotationProvider>,
) -> Result<BlockTxStats, TxError> {
    validate_header_commitments(pb, expected_prev_hash, expected_target)
        .and_then(|_| validate_coinbase_witness_commitment(pb))
        .and_then(|_| {
            validate_timestamp_rules(pb.header.timestamp, block_height, prev_timestamps)
        })?;

    let stats = accumulate_block_resource_stats(pb)?;
    validate_block_resource_limits(stats)?;

    validate_da_set_integrity(&pb.txs)
        .and_then(|_| validate_block_tx_semantics(pb, block_height, rotation))?;

    Ok(stats)
}
