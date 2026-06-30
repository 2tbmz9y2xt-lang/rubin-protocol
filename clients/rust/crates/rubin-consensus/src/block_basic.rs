use crate::block::{BlockHeader, BLOCK_HEADER_BYTES};
use crate::constants::{MAX_ANCHOR_BYTES_PER_BLOCK, MAX_BLOCK_WEIGHT, MAX_DA_BYTES_PER_BLOCK};
use crate::error::{ErrorCode, TxError};
use crate::suite_registry::RotationProvider;
use crate::tx::Tx;

mod coinbase;
mod da_set;
mod header;
mod orchestration;
mod parser;
mod txs;
mod weight;

use self::da_set::validate_da_set_integrity;
pub(crate) use self::orchestration::validate_parsed_block_basic_with_context_at_height;
use self::parser::parse_block_bytes_impl;
use self::txs::BlockTxStats;
use self::weight::tx_weight_and_stats;

pub(crate) use self::coinbase::{validate_coinbase_apply_outputs, validate_coinbase_value_bound};
pub(crate) use self::header::median_time_past;
pub use self::weight::{tx_weight_and_stats_at_height, tx_weight_and_stats_public};

#[derive(Clone, Debug)]
pub struct ParsedBlock {
    pub header: BlockHeader,
    pub header_bytes: [u8; BLOCK_HEADER_BYTES],
    pub tx_count: u64,
    pub txs: Vec<Tx>,
    pub txids: Vec<[u8; 32]>,
    pub wtxids: Vec<[u8; 32]>,
}

#[derive(Clone, Debug)]
pub struct BlockBasicSummary {
    pub tx_count: u64,
    pub sum_weight: u64,
    pub sum_da: u64,
    pub block_hash: [u8; 32],
}

// G.9 instrumentation: per-thread counter of `parse_block_bytes`
// invocations under `#[cfg(test)]`, used by `tests/parse_dedup.rs` to
// assert the one-parse-per-apply_block invariant. Thread-local (not a
// process-global atomic) so parallel test execution cannot contaminate
// the count. Not compiled in release builds.
#[cfg(test)]
thread_local! {
    pub(crate) static PARSE_BLOCK_BYTES_CALL_COUNT: std::cell::Cell<u64> =
        const { std::cell::Cell::new(0) };
}

pub fn parse_block_bytes(block_bytes: &[u8]) -> Result<ParsedBlock, TxError> {
    #[cfg(test)]
    PARSE_BLOCK_BYTES_CALL_COUNT.with(|c| c.set(c.get() + 1));
    parse_block_bytes_impl(block_bytes)
}

pub fn validate_block_basic(
    block_bytes: &[u8],
    expected_prev_hash: Option<[u8; 32]>,
    expected_target: Option<[u8; 32]>,
) -> Result<BlockBasicSummary, TxError> {
    validate_block_basic_at_height(block_bytes, expected_prev_hash, expected_target, 0)
}

pub fn validate_block_basic_at_height(
    block_bytes: &[u8],
    expected_prev_hash: Option<[u8; 32]>,
    expected_target: Option<[u8; 32]>,
    block_height: u64,
) -> Result<BlockBasicSummary, TxError> {
    validate_block_basic_with_context_at_height(
        block_bytes,
        expected_prev_hash,
        expected_target,
        block_height,
        None,
    )
}

pub fn validate_block_basic_with_context_at_height(
    block_bytes: &[u8],
    expected_prev_hash: Option<[u8; 32]>,
    expected_target: Option<[u8; 32]>,
    block_height: u64,
    prev_timestamps: Option<&[u64]>,
) -> Result<BlockBasicSummary, TxError> {
    validate_block_basic_with_context_at_height_and_rotation(
        block_bytes,
        expected_prev_hash,
        expected_target,
        block_height,
        prev_timestamps,
        None,
    )
}

/// Rotation-aware variant of `validate_block_basic_with_context_at_height`.
/// Threads the rotation/deployment provider to genesis covenant validation so
/// an active CORE_SIMPLICITY (0x0106) deployment is accepted. Mirrors Go
/// `ValidateBlockBasicWithContextAtHeightAndRotation`.
pub fn validate_block_basic_with_context_at_height_and_rotation(
    block_bytes: &[u8],
    expected_prev_hash: Option<[u8; 32]>,
    expected_target: Option<[u8; 32]>,
    block_height: u64,
    prev_timestamps: Option<&[u64]>,
    rotation: Option<&dyn RotationProvider>,
) -> Result<BlockBasicSummary, TxError> {
    let pb = parse_block_bytes(block_bytes)?;
    validate_parsed_block_basic_with_context_at_height(
        &pb,
        expected_prev_hash,
        expected_target,
        block_height,
        prev_timestamps,
        rotation,
    )
}

pub fn validate_block_basic_with_context_and_fees_at_height(
    block_bytes: &[u8],
    expected_prev_hash: Option<[u8; 32]>,
    expected_target: Option<[u8; 32]>,
    block_height: u64,
    prev_timestamps: Option<&[u64]>,
    already_generated: u128,
    sum_fees: u64,
) -> Result<BlockBasicSummary, TxError> {
    validate_block_basic_with_context_and_fees_at_height_and_rotation(
        block_bytes,
        expected_prev_hash,
        expected_target,
        block_height,
        prev_timestamps,
        already_generated,
        sum_fees,
        None,
    )
}

/// Rotation-aware variant of `validate_block_basic_with_context_and_fees_at_height`.
/// Mirrors Go `ValidateBlockBasicWithContextAndFeesAtHeightAndRotation`.
#[allow(clippy::too_many_arguments)]
pub fn validate_block_basic_with_context_and_fees_at_height_and_rotation(
    block_bytes: &[u8],
    expected_prev_hash: Option<[u8; 32]>,
    expected_target: Option<[u8; 32]>,
    block_height: u64,
    prev_timestamps: Option<&[u64]>,
    already_generated: u128,
    sum_fees: u64,
    rotation: Option<&dyn RotationProvider>,
) -> Result<BlockBasicSummary, TxError> {
    // G.9: parse once, share `pb` between basic validation and the
    // coinbase-value-bound check, instead of parsing twice.
    let pb = parse_block_bytes(block_bytes)?;
    let s = validate_parsed_block_basic_with_context_at_height(
        &pb,
        expected_prev_hash,
        expected_target,
        block_height,
        prev_timestamps,
        rotation,
    )?;
    validate_coinbase_value_bound(&pb, block_height, already_generated, sum_fees)?;
    Ok(s)
}

fn validate_block_resource_limits(stats: BlockTxStats) -> Result<(), TxError> {
    if stats.sum_weight > MAX_BLOCK_WEIGHT {
        return Err(TxError::new(
            ErrorCode::BlockErrWeightExceeded,
            "block weight exceeded",
        ));
    }
    if stats.sum_da > MAX_DA_BYTES_PER_BLOCK {
        return Err(TxError::new(
            ErrorCode::BlockErrWeightExceeded,
            "DA bytes exceeded",
        ));
    }
    if stats.sum_anchor > MAX_ANCHOR_BYTES_PER_BLOCK {
        return Err(TxError::new(
            ErrorCode::BlockErrAnchorBytesExceeded,
            "anchor bytes exceeded",
        ));
    }
    Ok(())
}
