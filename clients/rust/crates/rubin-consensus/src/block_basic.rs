use crate::block::{block_hash, parse_block_header_bytes, BlockHeader, BLOCK_HEADER_BYTES};
use crate::compactsize::read_compact_size;
use crate::constants::{
    COV_TYPE_DA_COMMIT, MAX_ANCHOR_BYTES_PER_BLOCK, MAX_BLOCK_WEIGHT, MAX_DA_BATCHES_PER_BLOCK,
    MAX_DA_BYTES_PER_BLOCK, MAX_DA_CHUNK_COUNT, ML_DSA_87_PUBKEY_BYTES, ML_DSA_87_SIG_BYTES,
    SUITE_ID_ML_DSA_87, SUITE_ID_SENTINEL, VERIFY_COST_ML_DSA_87, VERIFY_COST_UNKNOWN_SUITE,
    WITNESS_DISCOUNT_DIVISOR,
};
use crate::error::{ErrorCode, TxError};
use crate::hash::sha3_256;
use crate::tx::{da_core_fields_bytes, parse_tx, Tx};
use crate::wire_read::Reader;
use std::collections::HashMap;

mod coinbase;
mod header;
mod txs;

use self::coinbase::validate_coinbase_witness_commitment;
use self::header::{validate_header_commitments, validate_timestamp_rules};
use self::txs::{accumulate_block_resource_stats, validate_block_tx_semantics, BlockTxStats};

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

#[derive(Clone, Debug)]
struct DaCommitSet {
    tx: Tx,
    chunk_count: u16,
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
    if block_bytes.len() < BLOCK_HEADER_BYTES + 1 {
        return Err(TxError::new(ErrorCode::BlockErrParse, "block too short"));
    }

    let mut header_bytes = [0u8; BLOCK_HEADER_BYTES];
    header_bytes.copy_from_slice(&block_bytes[..BLOCK_HEADER_BYTES]);
    let header = parse_block_header_bytes(&header_bytes)
        .map_err(|_| TxError::new(ErrorCode::BlockErrParse, "invalid block header"))?;

    let mut r = Reader::new(&block_bytes[BLOCK_HEADER_BYTES..]);
    let (tx_count, _) = read_compact_size(&mut r)
        .map_err(|_| TxError::new(ErrorCode::BlockErrParse, "invalid tx_count"))?;
    if tx_count == 0 {
        return Err(TxError::new(
            ErrorCode::BlockErrCoinbaseInvalid,
            "empty block tx list",
        ));
    }

    let mut txs: Vec<Tx> = Vec::new();
    let mut txids: Vec<[u8; 32]> = Vec::new();
    let mut wtxids: Vec<[u8; 32]> = Vec::new();

    for _ in 0..tx_count {
        let rem = &block_bytes[BLOCK_HEADER_BYTES + r.offset()..];
        if rem.is_empty() {
            return Err(TxError::new(
                ErrorCode::BlockErrParse,
                "unexpected EOF in tx list",
            ));
        }
        let (tx, txid, wtxid, consumed) = parse_tx(rem)?;
        if consumed == 0 {
            return Err(TxError::new(
                ErrorCode::BlockErrParse,
                "zero-length tx parse",
            ));
        }
        txs.push(tx);
        txids.push(txid);
        wtxids.push(wtxid);
        r.read_bytes(consumed)
            .map_err(|_| TxError::new(ErrorCode::BlockErrParse, "unexpected EOF in tx list"))?;
    }

    if BLOCK_HEADER_BYTES + r.offset() != block_bytes.len() {
        return Err(TxError::new(
            ErrorCode::BlockErrParse,
            "trailing bytes after tx list",
        ));
    }

    Ok(ParsedBlock {
        header,
        header_bytes,
        tx_count,
        txs,
        txids,
        wtxids,
    })
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
) -> Result<BlockBasicSummary, TxError> {
    validate_header_commitments(pb, expected_prev_hash, expected_target)?;
    validate_coinbase_witness_commitment(pb)?;
    validate_timestamp_rules(pb.header.timestamp, block_height, prev_timestamps)?;

    let stats = accumulate_block_resource_stats(pb)?;
    validate_block_resource_limits(stats)?;

    validate_da_set_integrity(&pb.txs)?;
    validate_block_tx_semantics(pb, block_height)?;

    let h = block_hash(&pb.header_bytes)
        .map_err(|_| TxError::new(ErrorCode::BlockErrParse, "failed to hash block header"))?;

    Ok(BlockBasicSummary {
        tx_count: pb.tx_count,
        sum_weight: stats.sum_weight,
        sum_da: stats.sum_da,
        block_hash: h,
    })
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

fn validate_da_set_integrity(txs: &[Tx]) -> Result<(), TxError> {
    let mut commits: HashMap<[u8; 32], DaCommitSet> = HashMap::new();
    let mut chunks: HashMap<[u8; 32], HashMap<u16, Tx>> = HashMap::new();

    for tx in txs {
        match tx.tx_kind {
            0x01 => {
                let Some(core) = tx.da_commit_core.as_ref() else {
                    return Err(TxError::new(
                        ErrorCode::TxErrParse,
                        "missing da_commit_core for tx_kind=0x01",
                    ));
                };
                if commits
                    .insert(
                        core.da_id,
                        DaCommitSet {
                            tx: tx.clone(),
                            chunk_count: core.chunk_count,
                        },
                    )
                    .is_some()
                {
                    return Err(TxError::new(
                        ErrorCode::BlockErrDaSetInvalid,
                        "duplicate DA commit for da_id",
                    ));
                }
            }
            0x02 => {
                let Some(core) = tx.da_chunk_core.as_ref() else {
                    return Err(TxError::new(
                        ErrorCode::TxErrParse,
                        "missing da_chunk_core for tx_kind=0x02",
                    ));
                };
                if sha3_256(&tx.da_payload) != core.chunk_hash {
                    return Err(TxError::new(
                        ErrorCode::BlockErrDaChunkHashInvalid,
                        "chunk_hash mismatch",
                    ));
                }
                let set = chunks.entry(core.da_id).or_default();
                if set.insert(core.chunk_index, tx.clone()).is_some() {
                    return Err(TxError::new(
                        ErrorCode::BlockErrDaSetInvalid,
                        "duplicate DA chunk index",
                    ));
                }
            }
            _ => {}
        }
    }

    validate_da_set_maps(&commits, &chunks)
}

fn da_commit_for_id<'a>(
    commits: &'a HashMap<[u8; 32], DaCommitSet>,
    da_id: &[u8; 32],
) -> Result<&'a DaCommitSet, TxError> {
    commits.get(da_id).ok_or_else(|| {
        TxError::new(
            ErrorCode::BlockErrDaSetInvalid,
            "missing DA commit for da_id",
        )
    })
}

fn da_chunk_set_for_id<'a>(
    chunks: &'a HashMap<[u8; 32], HashMap<u16, Tx>>,
    da_id: &[u8; 32],
) -> Result<&'a HashMap<u16, Tx>, TxError> {
    chunks
        .get(da_id)
        .ok_or_else(|| TxError::new(ErrorCode::BlockErrDaIncomplete, "DA commit without chunks"))
}

fn da_chunk_tx_for_index(set: &HashMap<u16, Tx>, index: u16) -> Result<&Tx, TxError> {
    set.get(&index)
        .ok_or_else(|| TxError::new(ErrorCode::BlockErrDaIncomplete, "missing DA chunk index"))
}

fn validate_da_set_maps(
    commits: &HashMap<[u8; 32], DaCommitSet>,
    chunks: &HashMap<[u8; 32], HashMap<u16, Tx>>,
) -> Result<(), TxError> {
    // Go parity (clients/go/consensus/block_basic.go, `validateDASetIntegrity`):
    // the batch-count guard runs BEFORE the sortedDAIDs loops so a block that
    // exceeds `MAX_DA_BATCHES_PER_BLOCK` surfaces as `BLOCK_ERR_DA_BATCH_EXCEEDED`,
    // not as `BLOCK_ERR_DA_SET_INVALID` / `BLOCK_ERR_DA_INCOMPLETE` from a
    // stray chunk or bad chunk_count inside the overflowing set.
    if commits.len() > MAX_DA_BATCHES_PER_BLOCK as usize {
        return Err(TxError::new(
            ErrorCode::BlockErrDaBatchExceeded,
            "too many DA commits in block",
        ));
    }

    let commit_ids = sorted_da_ids(commits);
    let chunk_ids = sorted_da_ids(chunks);

    for da_id in &chunk_ids {
        if !commits.contains_key(da_id) {
            return Err(TxError::new(
                ErrorCode::BlockErrDaSetInvalid,
                "DA chunks without DA commit",
            ));
        }
    }

    for da_id in &commit_ids {
        let commit = da_commit_for_id(commits, da_id)?;
        if commit.chunk_count == 0 || u64::from(commit.chunk_count) > MAX_DA_CHUNK_COUNT {
            return Err(TxError::new(
                ErrorCode::TxErrParse,
                "chunk_count out of range for tx_kind=0x01",
            ));
        }
        let set = da_chunk_set_for_id(chunks, da_id)?;
        if set.len() != commit.chunk_count as usize {
            return Err(TxError::new(
                ErrorCode::BlockErrDaIncomplete,
                "DA chunk count mismatch",
            ));
        }
        for i in 0..commit.chunk_count {
            let _ = da_chunk_tx_for_index(set, i)?;
        }
    }

    for da_id in &commit_ids {
        let commit = da_commit_for_id(commits, da_id)?;
        let set = da_chunk_set_for_id(chunks, da_id)?;
        let mut concat = Vec::<u8>::new();
        for i in 0..commit.chunk_count {
            let tx = da_chunk_tx_for_index(set, i)?;
            concat.extend_from_slice(&tx.da_payload);
        }
        let payload_commitment = sha3_256(&concat);

        let mut da_commit_outputs: u32 = 0;
        let mut got_commitment = [0u8; 32];
        for o in &commit.tx.outputs {
            if o.covenant_type != COV_TYPE_DA_COMMIT {
                continue;
            }
            da_commit_outputs += 1;
            // Go parity (clients/go/consensus/block_basic.go,
            // `validateDASetIntegrity` payload-commitment loop): a DA commit
            // output whose covenant payload is not exactly 32 bytes is
            // rejected as `BLOCK_ERR_DA_PAYLOAD_COMMIT_INVALID /
            // "DA commitment output has invalid length"` BEFORE the
            // missing/duplicated count check and BEFORE the commitment
            // mismatch check. Silently zero-filling `got_commitment` would
            // collapse this case into `payload commitment mismatch`, losing
            // the dedicated length-classification surface.
            if o.covenant_data.len() != 32 {
                return Err(TxError::new(
                    ErrorCode::BlockErrDaPayloadCommitInvalid,
                    "DA commitment output has invalid length",
                ));
            }
            got_commitment.copy_from_slice(&o.covenant_data);
        }
        if da_commit_outputs != 1 {
            return Err(TxError::new(
                ErrorCode::BlockErrDaPayloadCommitInvalid,
                "DA commitment output missing or duplicated",
            ));
        }
        if payload_commitment != got_commitment {
            return Err(TxError::new(
                ErrorCode::BlockErrDaPayloadCommitInvalid,
                "payload commitment mismatch",
            ));
        }
    }

    Ok(())
}

fn sorted_da_ids<T>(m: &HashMap<[u8; 32], T>) -> Vec<[u8; 32]> {
    let mut ids: Vec<[u8; 32]> = m.keys().copied().collect();
    ids.sort_unstable();
    ids
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

#[cfg(test)]
mod internal_tests {
    use super::{
        da_chunk_set_for_id, da_chunk_tx_for_index, da_commit_for_id, validate_da_set_maps,
        DaCommitSet,
    };
    use crate::constants::{COV_TYPE_DA_COMMIT, MAX_DA_BATCHES_PER_BLOCK};
    use crate::error::ErrorCode;
    use crate::tx::{Tx, TxOutput};
    use std::collections::HashMap;

    fn dummy_da_commit_tx(payload_commitment: [u8; 32]) -> Tx {
        dummy_da_commit_tx_with_covenant_data(payload_commitment.to_vec())
    }

    fn dummy_da_commit_tx_with_covenant_data(covenant_data: Vec<u8>) -> Tx {
        Tx {
            version: 1,
            tx_kind: 0x01,
            tx_nonce: 0,
            inputs: Vec::new(),
            outputs: vec![TxOutput {
                value: 0,
                covenant_type: COV_TYPE_DA_COMMIT,
                covenant_data,
            }],
            locktime: 0,
            da_commit_core: None,
            da_chunk_core: None,
            witness: Vec::new(),
            da_payload: Vec::new(),
        }
    }

    fn dummy_da_chunk_tx(payload: &[u8]) -> Tx {
        Tx {
            version: 1,
            tx_kind: 0x02,
            tx_nonce: 0,
            inputs: Vec::new(),
            outputs: Vec::new(),
            locktime: 0,
            da_commit_core: None,
            da_chunk_core: None,
            witness: Vec::new(),
            da_payload: payload.to_vec(),
        }
    }

    #[test]
    fn da_commit_for_id_missing_returns_block_err_da_set_invalid() {
        let commits: HashMap<[u8; 32], DaCommitSet> = HashMap::new();
        let err = da_commit_for_id(&commits, &[0x11; 32]).unwrap_err();
        assert_eq!(err.code, ErrorCode::BlockErrDaSetInvalid);
    }

    #[test]
    fn da_chunk_set_for_id_missing_returns_block_err_da_incomplete() {
        let chunks: HashMap<[u8; 32], HashMap<u16, Tx>> = HashMap::new();
        let err = da_chunk_set_for_id(&chunks, &[0x22; 32]).unwrap_err();
        assert_eq!(err.code, ErrorCode::BlockErrDaIncomplete);
    }

    #[test]
    fn da_chunk_tx_for_index_missing_returns_block_err_da_incomplete() {
        let set: HashMap<u16, Tx> = HashMap::new();
        let err = da_chunk_tx_for_index(&set, 0).unwrap_err();
        assert_eq!(err.code, ErrorCode::BlockErrDaIncomplete);
    }

    #[test]
    fn validate_da_set_maps_rejects_missing_chunk_index_without_panic() {
        let da_id = [0x33; 32];
        let mut commits = HashMap::new();
        commits.insert(
            da_id,
            DaCommitSet {
                tx: dummy_da_commit_tx([0x44; 32]),
                chunk_count: 2,
            },
        );

        let mut set = HashMap::new();
        set.insert(0, dummy_da_chunk_tx(b"chunk-0"));
        let mut chunks = HashMap::new();
        chunks.insert(da_id, set);

        let err = validate_da_set_maps(&commits, &chunks).unwrap_err();
        assert_eq!(err.code, ErrorCode::BlockErrDaIncomplete);
    }

    /// Go parity for G.1: a DA commit output whose covenant payload is not
    /// exactly 32 bytes is classified as
    /// `BLOCK_ERR_DA_PAYLOAD_COMMIT_INVALID / "DA commitment output has
    /// invalid length"`, not collapsed into the generic
    /// `"payload commitment mismatch"` surface.
    #[test]
    fn validate_da_set_maps_rejects_non_32_covenant_data_as_invalid_length() {
        let da_id = [0x55; 32];
        let payload = b"payload-short-covenant".to_vec();

        let mut commits = HashMap::new();
        // covenant_data deliberately 31 bytes (not 32).
        let bad_covenant: Vec<u8> = (0..31).collect();
        commits.insert(
            da_id,
            DaCommitSet {
                tx: dummy_da_commit_tx_with_covenant_data(bad_covenant),
                chunk_count: 1,
            },
        );

        let mut set = HashMap::new();
        set.insert(0, dummy_da_chunk_tx(&payload));
        let mut chunks = HashMap::new();
        chunks.insert(da_id, set);

        let err = validate_da_set_maps(&commits, &chunks).unwrap_err();
        assert_eq!(err.code, ErrorCode::BlockErrDaPayloadCommitInvalid);
        // Exact-message parity: the Go reference returns this exact string
        // (`clients/go/consensus/block_basic.go`, `validateDASetIntegrity`).
        // A substring check would mask future drift that still happens to
        // contain "invalid length".
        assert_eq!(err.msg, "DA commitment output has invalid length");
    }

    /// Go parity for G.2: the `MAX_DA_BATCHES_PER_BLOCK` guard runs BEFORE the
    /// sortedDAIDs loops, so an oversize block whose excess sets also contain
    /// structural problems (orphaned chunks, missing chunk index, chunk_count
    /// OOB) surfaces as `BLOCK_ERR_DA_BATCH_EXCEEDED` rather than the
    /// downstream `BLOCK_ERR_DA_SET_INVALID` / `BLOCK_ERR_DA_INCOMPLETE`
    /// classification of an inner set.
    #[test]
    fn validate_da_set_maps_batch_exceeded_fires_before_set_invalid() {
        let mut commits = HashMap::new();
        // `i` is u32 and we write 4 bytes of `da_id` so the counter stays
        // injective even if `MAX_DA_BATCHES_PER_BLOCK` is ever raised past
        // `u16::MAX`. `assert_eq!(commits.len(), MAX+1)` below is the
        // fail-fast guard; the wider counter keeps that guard meaningful.
        let limit: u32 = MAX_DA_BATCHES_PER_BLOCK as u32;
        for i in 0..=limit {
            // commit_count == MAX + 1 triggers the batch-exceeded guard.
            let mut da_id = [0u8; 32];
            da_id[0..4].copy_from_slice(&i.to_le_bytes());
            commits.insert(
                da_id,
                DaCommitSet {
                    tx: dummy_da_commit_tx([0xAA; 32]),
                    chunk_count: 1,
                },
            );
        }

        // Seed chunk map with an orphaned DA set (no matching commit) —
        // without the reorder, this would surface as `BlockErrDaSetInvalid`.
        let mut orphan_set = HashMap::new();
        orphan_set.insert(0, dummy_da_chunk_tx(b"orphan"));
        let mut chunks = HashMap::new();
        chunks.insert([0xFF; 32], orphan_set);

        assert_eq!(commits.len(), MAX_DA_BATCHES_PER_BLOCK as usize + 1);

        let err = validate_da_set_maps(&commits, &chunks).unwrap_err();
        assert_eq!(err.code, ErrorCode::BlockErrDaBatchExceeded);
        // Exact-message parity with Go (`clients/go/consensus/block_basic.go`,
        // `validateDASetIntegrity`): lock the full reject message, not just
        // the code, so future wording drift is caught alongside the
        // ordering invariant. Mirrors the same assertion style used by the
        // G.1 length-reject test above.
        assert_eq!(err.msg, "too many DA commits in block");
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
