use crate::block::{block_hash, parse_block_header_bytes, BlockHeader, BLOCK_HEADER_BYTES};
use crate::compactsize::read_compact_size;
use crate::constants::{
    COV_TYPE_ANCHOR, COV_TYPE_DA_COMMIT, MAX_ANCHOR_BYTES_PER_BLOCK, MAX_BLOCK_WEIGHT,
    MAX_DA_BATCHES_PER_BLOCK, MAX_DA_BYTES_PER_BLOCK, MAX_FUTURE_DRIFT, MAX_SLH_DSA_SIG_BYTES,
    ML_DSA_87_PUBKEY_BYTES, ML_DSA_87_SIG_BYTES, SLH_DSA_ACTIVATION_HEIGHT,
    SLH_DSA_SHAKE_256F_PUBKEY_BYTES, SUITE_ID_ML_DSA_87, SUITE_ID_SLH_DSA_SHAKE_256F,
    VERIFY_COST_ML_DSA_87, VERIFY_COST_SLH_DSA_SHAKE_256F, WITNESS_DISCOUNT_DIVISOR,
};
use crate::covenant_genesis::validate_tx_covenants_genesis;
use crate::error::{ErrorCode, TxError};
use crate::hash::sha3_256;
use crate::merkle::{merkle_root_txids, witness_commitment_hash, witness_merkle_root_wtxids};
use crate::pow::pow_check;
use crate::subsidy::block_subsidy;
use crate::tx::{da_core_fields_bytes, parse_tx, Tx};
use crate::wire_read::Reader;
use std::collections::HashMap;

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

pub fn parse_block_bytes(block_bytes: &[u8]) -> Result<ParsedBlock, TxError> {
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

    if let Some(prev) = expected_prev_hash {
        if pb.header.prev_block_hash != prev {
            return Err(TxError::new(
                ErrorCode::BlockErrLinkageInvalid,
                "prev_block_hash mismatch",
            ));
        }
    }

    let root = merkle_root_txids(&pb.txids)
        .map_err(|_| TxError::new(ErrorCode::BlockErrMerkleInvalid, "failed to compute merkle"))?;
    if root != pb.header.merkle_root {
        return Err(TxError::new(
            ErrorCode::BlockErrMerkleInvalid,
            "merkle_root mismatch",
        ));
    }

    pow_check(&pb.header_bytes, pb.header.target)?;

    if let Some(target) = expected_target {
        if pb.header.target != target {
            return Err(TxError::new(
                ErrorCode::BlockErrTargetInvalid,
                "target mismatch",
            ));
        }
    }

    validate_coinbase_structure(&pb, block_height)?;

    let mut sum_weight: u64 = 0;
    let mut sum_da: u64 = 0;
    let mut sum_anchor: u64 = 0;
    let mut seen_nonces: HashMap<u64, ()> = HashMap::with_capacity(pb.txs.len());
    for (i, tx) in pb.txs.iter().enumerate() {
        validate_witness_suite_activation(tx, i, block_height)?;
        if i > 0 {
            if is_coinbase_tx(tx) {
                return Err(TxError::new(
                    ErrorCode::BlockErrCoinbaseInvalid,
                    "coinbase-like tx found at index > 0",
                ));
            }
            // Non-coinbase transactions must carry at least one input.
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
        let (w, da, anchor_bytes) = tx_weight_and_stats(tx)?;
        sum_weight = sum_weight
            .checked_add(w)
            .ok_or_else(|| TxError::new(ErrorCode::TxErrParse, "u64 overflow"))?;
        sum_da = sum_da
            .checked_add(da)
            .ok_or_else(|| TxError::new(ErrorCode::TxErrParse, "u64 overflow"))?;
        sum_anchor = sum_anchor
            .checked_add(anchor_bytes)
            .ok_or_else(|| TxError::new(ErrorCode::TxErrParse, "u64 overflow"))?;
    }
    validate_coinbase_witness_commitment(&pb)?;
    validate_timestamp_rules(pb.header.timestamp, block_height, prev_timestamps)?;
    validate_da_set_integrity(&pb.txs)?;

    if sum_da > MAX_DA_BYTES_PER_BLOCK {
        return Err(TxError::new(
            ErrorCode::BlockErrWeightExceeded,
            "DA bytes exceeded",
        ));
    }
    if sum_anchor > MAX_ANCHOR_BYTES_PER_BLOCK {
        return Err(TxError::new(
            ErrorCode::BlockErrAnchorBytesExceeded,
            "anchor bytes exceeded",
        ));
    }
    if sum_weight > MAX_BLOCK_WEIGHT {
        return Err(TxError::new(
            ErrorCode::BlockErrWeightExceeded,
            "block weight exceeded",
        ));
    }

    let h = block_hash(&pb.header_bytes)
        .map_err(|_| TxError::new(ErrorCode::BlockErrParse, "failed to hash block header"))?;

    Ok(BlockBasicSummary {
        tx_count: pb.tx_count,
        sum_weight,
        sum_da,
        block_hash: h,
    })
}

pub fn validate_block_basic_with_context_and_fees_at_height(
    block_bytes: &[u8],
    expected_prev_hash: Option<[u8; 32]>,
    expected_target: Option<[u8; 32]>,
    block_height: u64,
    prev_timestamps: Option<&[u64]>,
    already_generated: u64,
    sum_fees: u64,
) -> Result<BlockBasicSummary, TxError> {
    let s = validate_block_basic_with_context_at_height(
        block_bytes,
        expected_prev_hash,
        expected_target,
        block_height,
        prev_timestamps,
    )?;
    let pb = parse_block_bytes(block_bytes)?;
    validate_coinbase_value_bound(&pb, block_height, already_generated, sum_fees)?;
    Ok(s)
}

fn is_coinbase_tx(tx: &Tx) -> bool {
    if tx.tx_kind != 0x00
        || tx.tx_nonce != 0
        || tx.inputs.len() != 1
        || !tx.witness.is_empty()
        || !tx.da_payload.is_empty()
    {
        return false;
    }
    let input = &tx.inputs[0];
    input.prev_txid == [0u8; 32]
        && input.prev_vout == u32::MAX
        && input.script_sig.is_empty()
        && input.sequence == u32::MAX
}

fn validate_coinbase_structure(pb: &ParsedBlock, block_height: u64) -> Result<(), TxError> {
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

fn validate_coinbase_value_bound(
    pb: &ParsedBlock,
    block_height: u64,
    already_generated: u64,
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

    let mut sum_coinbase: u128 = 0;
    for out in &coinbase.outputs {
        sum_coinbase = sum_coinbase
            .checked_add(out.value as u128)
            .ok_or_else(|| TxError::new(ErrorCode::BlockErrParse, "u128 overflow"))?;
    }

    let subsidy = block_subsidy(block_height, already_generated);
    let limit = (subsidy as u128)
        .checked_add(sum_fees as u128)
        .ok_or_else(|| TxError::new(ErrorCode::BlockErrParse, "u128 overflow"))?;
    if sum_coinbase > limit {
        return Err(TxError::new(
            ErrorCode::BlockErrSubsidyExceeded,
            "coinbase outputs exceed subsidy+fees bound",
        ));
    }
    Ok(())
}

fn validate_witness_suite_activation(
    tx: &Tx,
    tx_index: usize,
    block_height: u64,
) -> Result<(), TxError> {
    if tx_index == 0 {
        // Coinbase witness is structurally empty in genesis profile.
        return Ok(());
    }
    for w in &tx.witness {
        if w.suite_id == SUITE_ID_SLH_DSA_SHAKE_256F && block_height < SLH_DSA_ACTIVATION_HEIGHT {
            return Err(TxError::new(
                ErrorCode::TxErrSigAlgInvalid,
                "SLH-DSA suite inactive at this height",
            ));
        }
    }
    Ok(())
}

fn validate_coinbase_witness_commitment(pb: &ParsedBlock) -> Result<(), TxError> {
    if pb.txs.is_empty() || pb.wtxids.is_empty() {
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

    let mut matches = 0u64;
    for out in &pb.txs[0].outputs {
        if out.covenant_type != COV_TYPE_ANCHOR || out.covenant_data.len() != 32 {
            continue;
        }
        if out.covenant_data.as_slice() == &expected[..] {
            matches += 1;
        }
    }

    if matches != 1 {
        return Err(TxError::new(
            ErrorCode::BlockErrWitnessCommitment,
            "coinbase witness commitment missing or duplicated",
        ));
    }
    Ok(())
}

fn validate_timestamp_rules(
    header_timestamp: u64,
    block_height: u64,
    prev_timestamps: Option<&[u64]>,
) -> Result<(), TxError> {
    let Some(median) = median_time_past(block_height, prev_timestamps)? else {
        return Ok(());
    };
    if header_timestamp <= median {
        return Err(TxError::new(
            ErrorCode::BlockErrTimestampOld,
            "timestamp <= MTP median",
        ));
    }
    let upper_bound = median.saturating_add(MAX_FUTURE_DRIFT);
    if header_timestamp > upper_bound {
        return Err(TxError::new(
            ErrorCode::BlockErrTimestampFuture,
            "timestamp exceeds future drift",
        ));
    }
    Ok(())
}

pub(crate) fn median_time_past(
    block_height: u64,
    prev_timestamps: Option<&[u64]>,
) -> Result<Option<u64>, TxError> {
    if block_height == 0 {
        return Ok(None);
    }
    let Some(prev) = prev_timestamps else {
        return Ok(None);
    };
    if prev.is_empty() {
        return Ok(None);
    }

    let k = usize::try_from(block_height.min(11)).unwrap_or(11);
    if prev.len() < k {
        return Err(TxError::new(
            ErrorCode::BlockErrParse,
            "insufficient prev_timestamps context",
        ));
    }

    let mut window = prev[..k].to_vec();
    window.sort_unstable();
    Ok(Some(window[(window.len() - 1) / 2]))
}

#[derive(Clone)]
struct DaCommitSet {
    tx: Tx,
    chunk_count: u16,
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

    if commits.len() > MAX_DA_BATCHES_PER_BLOCK as usize {
        return Err(TxError::new(
            ErrorCode::BlockErrDaBatchExceeded,
            "too many DA commits in block",
        ));
    }

    for da_id in chunks.keys() {
        if !commits.contains_key(da_id) {
            return Err(TxError::new(
                ErrorCode::BlockErrDaSetInvalid,
                "DA chunks without DA commit",
            ));
        }
    }

    for (da_id, commit) in commits {
        let set = chunks.get(&da_id).ok_or_else(|| {
            TxError::new(ErrorCode::BlockErrDaIncomplete, "DA commit without chunks")
        })?;
        if set.len() != commit.chunk_count as usize {
            return Err(TxError::new(
                ErrorCode::BlockErrDaIncomplete,
                "DA chunk count mismatch",
            ));
        }
        let mut concat = Vec::<u8>::new();
        for i in 0..commit.chunk_count {
            let tx = set.get(&i).ok_or_else(|| {
                TxError::new(ErrorCode::BlockErrDaIncomplete, "missing DA chunk index")
            })?;
            concat.extend_from_slice(&tx.da_payload);
        }
        let payload_commitment = sha3_256(&concat);

        // CANONICAL §21.4: commit tx MUST contain exactly one CORE_DA_COMMIT output whose
        // covenant_data equals the payload commitment hash (missing/duplicate are invalid).
        let mut da_commit_outputs: u32 = 0;
        let mut got_commitment = [0u8; 32];
        for o in &commit.tx.outputs {
            if o.covenant_type != COV_TYPE_DA_COMMIT {
                continue;
            }
            da_commit_outputs += 1;
            if o.covenant_data.len() == 32 {
                got_commitment.copy_from_slice(&o.covenant_data);
            }
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

fn tx_weight_and_stats(tx: &Tx) -> Result<(u64, u64, u64), TxError> {
    let mut base_size: u64 = 4 + 1 + 8; // version + tx_kind + tx_nonce
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
        if o.covenant_type == COV_TYPE_ANCHOR || o.covenant_type == COV_TYPE_DA_COMMIT {
            anchor_bytes = anchor_bytes
                .checked_add(cov_len)
                .ok_or_else(|| TxError::new(ErrorCode::TxErrParse, "u64 overflow"))?;
        }
    }
    base_size = base_size
        .checked_add(4)
        .ok_or_else(|| TxError::new(ErrorCode::TxErrParse, "u64 overflow"))?; // locktime
    base_size = base_size
        .checked_add(da_core_fields_bytes(tx)?.len() as u64)
        .ok_or_else(|| TxError::new(ErrorCode::TxErrParse, "u64 overflow"))?;

    let mut witness_size: u64 = compact_size_len(tx.witness.len() as u64);
    let mut ml_count: u64 = 0;
    let mut slh_count: u64 = 0;
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

        match w.suite_id {
            SUITE_ID_ML_DSA_87 => {
                if w.pubkey.len() as u64 == ML_DSA_87_PUBKEY_BYTES
                    && w.signature.len() as u64 == ML_DSA_87_SIG_BYTES
                {
                    ml_count += 1;
                }
            }
            SUITE_ID_SLH_DSA_SHAKE_256F => {
                if w.pubkey.len() as u64 == SLH_DSA_SHAKE_256F_PUBKEY_BYTES
                    && !w.signature.is_empty()
                    && w.signature.len() as u64 <= MAX_SLH_DSA_SIG_BYTES
                {
                    slh_count += 1;
                }
            }
            _ => {}
        }
    }

    let da_len = tx.da_payload.len() as u64;
    let da_size = compact_size_len(da_len)
        .checked_add(da_len)
        .ok_or_else(|| TxError::new(ErrorCode::TxErrParse, "u64 overflow"))?;
    let da_bytes = if tx.tx_kind != 0x00 { da_len } else { 0 };

    let sig_cost = ml_count
        .checked_mul(VERIFY_COST_ML_DSA_87)
        .and_then(|v| v.checked_add(slh_count.checked_mul(VERIFY_COST_SLH_DSA_SHAKE_256F)?))
        .ok_or_else(|| TxError::new(ErrorCode::TxErrParse, "u64 overflow"))?;

    let weight = WITNESS_DISCOUNT_DIVISOR
        .checked_mul(base_size)
        .and_then(|v| v.checked_add(witness_size))
        .and_then(|v| v.checked_add(da_size))
        .and_then(|v| v.checked_add(sig_cost))
        .ok_or_else(|| TxError::new(ErrorCode::TxErrParse, "u64 overflow"))?;

    Ok((weight, da_bytes, anchor_bytes))
}

pub fn tx_weight_and_stats_public(tx: &Tx) -> Result<(u64, u64, u64), TxError> {
    tx_weight_and_stats(tx)
}

fn compact_size_len(n: u64) -> u64 {
    match n {
        0x00..=0xfc => 1,
        0xfd..=0xffff => 3,
        0x1_0000..=0xffff_ffff => 5,
        _ => 9,
    }
}
