use crate::block::{BlockHeader, BLOCK_HEADER_BYTES};
use crate::constants::{
    COV_TYPE_DA_COMMIT, MAX_ANCHOR_BYTES_PER_BLOCK, MAX_BLOCK_WEIGHT, MAX_DA_BYTES_PER_BLOCK,
    ML_DSA_87_PUBKEY_BYTES, ML_DSA_87_SIG_BYTES, SUITE_ID_ML_DSA_87, SUITE_ID_SENTINEL,
    VERIFY_COST_ML_DSA_87, VERIFY_COST_UNKNOWN_SUITE, WITNESS_DISCOUNT_DIVISOR,
};
use crate::error::{ErrorCode, TxError};
use crate::tx::{da_core_fields_bytes, Tx};

mod coinbase;
mod da_set;
mod header;
mod orchestration;
mod parser;
mod txs;

use self::da_set::validate_da_set_integrity;
pub(crate) use self::orchestration::validate_parsed_block_basic_with_context_at_height;
use self::parser::parse_block_bytes_impl;
use self::txs::BlockTxStats;

pub(crate) use self::coinbase::{validate_coinbase_apply_outputs, validate_coinbase_value_bound};
pub(crate) use self::header::median_time_past;

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
    let pb = parse_block_bytes(block_bytes)?;
    validate_parsed_block_basic_with_context_at_height(
        &pb,
        expected_prev_hash,
        expected_target,
        block_height,
        prev_timestamps,
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
    // G.9: parse once, share `pb` between basic validation and the
    // coinbase-value-bound check, instead of parsing twice.
    let pb = parse_block_bytes(block_bytes)?;
    let s = validate_parsed_block_basic_with_context_at_height(
        &pb,
        expected_prev_hash,
        expected_target,
        block_height,
        prev_timestamps,
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

/// Shared weight-computation skeleton. `sig_cost_fn` receives each witness item
/// and returns its verification cost (same pattern as Go `txWeightComponents`).
fn tx_weight_components<F>(tx: &Tx, sig_cost_fn: F) -> Result<(u64, u64, u64), TxError>
where
    F: Fn(&crate::tx::WitnessItem) -> Result<u64, TxError>,
{
    let mut base_size: u64 = 4 + 1 + 8;
    base_size = base_size
        .checked_add(compact_size_len(tx.inputs.len() as u64))
        .ok_or_else(|| TxError::new(ErrorCode::TxErrParse, "u64 overflow"))?;
    for i in &tx.inputs {
        base_size = base_size
            .checked_add(32 + 4)
            .ok_or_else(|| TxError::new(ErrorCode::TxErrParse, "u64 overflow"))?;
        base_size = base_size
            .checked_add(compact_size_len(i.script_sig.len() as u64))
            .ok_or_else(|| TxError::new(ErrorCode::TxErrParse, "u64 overflow"))?;
        base_size = base_size
            .checked_add(i.script_sig.len() as u64)
            .ok_or_else(|| TxError::new(ErrorCode::TxErrParse, "u64 overflow"))?;
        base_size = base_size
            .checked_add(4)
            .ok_or_else(|| TxError::new(ErrorCode::TxErrParse, "u64 overflow"))?;
    }
    base_size = base_size
        .checked_add(compact_size_len(tx.outputs.len() as u64))
        .ok_or_else(|| TxError::new(ErrorCode::TxErrParse, "u64 overflow"))?;
    let mut anchor_bytes: u64 = 0;
    for o in &tx.outputs {
        base_size = base_size
            .checked_add(8 + 2)
            .ok_or_else(|| TxError::new(ErrorCode::TxErrParse, "u64 overflow"))?;
        let cov_len = o.covenant_data.len() as u64;
        base_size = base_size
            .checked_add(compact_size_len(cov_len))
            .ok_or_else(|| TxError::new(ErrorCode::TxErrParse, "u64 overflow"))?;
        base_size = base_size
            .checked_add(cov_len)
            .ok_or_else(|| TxError::new(ErrorCode::TxErrParse, "u64 overflow"))?;
        if o.covenant_type == crate::constants::COV_TYPE_ANCHOR
            || o.covenant_type == COV_TYPE_DA_COMMIT
        {
            anchor_bytes = anchor_bytes
                .checked_add(cov_len)
                .ok_or_else(|| TxError::new(ErrorCode::TxErrParse, "u64 overflow"))?;
        }
    }
    base_size = base_size
        .checked_add(4)
        .ok_or_else(|| TxError::new(ErrorCode::TxErrParse, "u64 overflow"))?;
    base_size = base_size
        .checked_add(da_core_fields_bytes(tx)?.len() as u64)
        .ok_or_else(|| TxError::new(ErrorCode::TxErrParse, "u64 overflow"))?;

    let mut witness_size: u64 = compact_size_len(tx.witness.len() as u64);
    let mut sig_cost: u64 = 0;
    for w in &tx.witness {
        witness_size = witness_size
            .checked_add(1)
            .ok_or_else(|| TxError::new(ErrorCode::TxErrParse, "u64 overflow"))?;
        witness_size = witness_size
            .checked_add(compact_size_len(w.pubkey.len() as u64))
            .ok_or_else(|| TxError::new(ErrorCode::TxErrParse, "u64 overflow"))?;
        witness_size = witness_size
            .checked_add(w.pubkey.len() as u64)
            .ok_or_else(|| TxError::new(ErrorCode::TxErrParse, "u64 overflow"))?;
        witness_size = witness_size
            .checked_add(compact_size_len(w.signature.len() as u64))
            .ok_or_else(|| TxError::new(ErrorCode::TxErrParse, "u64 overflow"))?;
        witness_size = witness_size
            .checked_add(w.signature.len() as u64)
            .ok_or_else(|| TxError::new(ErrorCode::TxErrParse, "u64 overflow"))?;

        let cost = sig_cost_fn(w)?;
        sig_cost = sig_cost
            .checked_add(cost)
            .ok_or_else(|| TxError::new(ErrorCode::TxErrParse, "u64 overflow"))?;
    }

    let da_len = tx.da_payload.len() as u64;
    let da_size = compact_size_len(da_len)
        .checked_add(da_len)
        .ok_or_else(|| TxError::new(ErrorCode::TxErrParse, "u64 overflow"))?;
    let da_bytes = if tx.tx_kind != 0x00 { da_len } else { 0 };

    let weight = WITNESS_DISCOUNT_DIVISOR
        .checked_mul(base_size)
        .and_then(|v| v.checked_add(witness_size))
        .and_then(|v| v.checked_add(da_size))
        .and_then(|v| v.checked_add(sig_cost))
        .ok_or_else(|| TxError::new(ErrorCode::TxErrParse, "u64 overflow"))?;

    Ok((weight, da_bytes, anchor_bytes))
}

/// Legacy weight with hardcoded per-suite costs.
fn tx_weight_and_stats(tx: &Tx) -> Result<(u64, u64, u64), TxError> {
    tx_weight_components(tx, |w| match w.suite_id {
        SUITE_ID_SENTINEL => Ok(0),
        SUITE_ID_ML_DSA_87 => {
            if w.pubkey.len() as u64 == ML_DSA_87_PUBKEY_BYTES
                && w.signature.len() as u64 == ML_DSA_87_SIG_BYTES + 1
            {
                Ok(VERIFY_COST_ML_DSA_87)
            } else {
                Ok(0)
            }
        }
        _ => Ok(VERIFY_COST_UNKNOWN_SUITE),
    })
}

pub fn tx_weight_and_stats_public(tx: &Tx) -> Result<(u64, u64, u64), TxError> {
    tx_weight_and_stats(tx)
}

/// Suite-aware weight calculation using registry verify costs and
/// rotation-aware native spend suites. Parity with Go
/// `TxWeightAndStatsAtHeight`. When rotation or registry is None,
/// falls back to the legacy hardcoded calculation.
pub fn tx_weight_and_stats_at_height(
    tx: &crate::tx::Tx,
    height: u64,
    rotation: Option<&dyn crate::suite_registry::RotationProvider>,
    registry: Option<&crate::suite_registry::SuiteRegistry>,
) -> Result<(u64, u64, u64), TxError> {
    let (rotation, registry) = match (rotation, registry) {
        (Some(r), Some(reg)) => (r, reg),
        _ => return tx_weight_and_stats(tx),
    };

    let native_spend = rotation.native_spend_suites(height);

    tx_weight_components(tx, |w| {
        if w.suite_id == SUITE_ID_SENTINEL {
            return Ok(0);
        }
        if native_spend.contains(w.suite_id) {
            if let Some(params) = registry.lookup(w.suite_id) {
                if w.pubkey.len() as u64 == params.pubkey_len
                    && w.signature.len() as u64 == params.sig_len + 1
                {
                    return Ok(params.verify_cost);
                }
                return Ok(0);
            }
            // In native spend set but not registered — unknown.
            return Ok(VERIFY_COST_UNKNOWN_SUITE);
        }
        // Not in native spend set — unknown suite floor.
        Ok(VERIFY_COST_UNKNOWN_SUITE)
    })
}

fn compact_size_len(n: u64) -> u64 {
    match n {
        0x00..=0xfc => 1,
        0xfd..=0xffff => 3,
        0x1_0000..=0xffff_ffff => 5,
        _ => 9,
    }
}

#[cfg(kani)]
mod verification {
    use super::compact_size_len;
    use crate::compactsize::encode_compact_size;

    #[kani::proof]
    fn verify_compact_size_len_matches_encode() {
        let n: u64 = kani::any();
        let mut buf = Vec::new();
        encode_compact_size(n, &mut buf);
        assert_eq!(compact_size_len(n), buf.len() as u64);
    }
}
