use crate::block::{block_hash, parse_block_header_bytes, BlockHeader, BLOCK_HEADER_BYTES};
use crate::compactsize::read_compact_size;
use crate::constants::{
    COV_TYPE_ANCHOR, MAX_ANCHOR_BYTES_PER_BLOCK, MAX_BLOCK_WEIGHT, MAX_DA_BYTES_PER_BLOCK,
    SUITE_ID_ML_DSA_87, SUITE_ID_SLH_DSA_SHAKE_256F, VERIFY_COST_ML_DSA_87,
    VERIFY_COST_SLH_DSA_SHAKE_256F, WITNESS_DISCOUNT_DIVISOR,
};
use crate::covenant_genesis::validate_tx_covenants_genesis;
use crate::error::{ErrorCode, TxError};
use crate::merkle::merkle_root_txids;
use crate::pow::pow_check;
use crate::tx::{parse_tx, Tx};
use crate::wire_read::Reader;

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

    let mut sum_weight: u64 = 0;
    let mut sum_da: u64 = 0;
    let mut sum_anchor: u64 = 0;
    for tx in &pb.txs {
        validate_tx_covenants_genesis(tx)?;
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
        if o.covenant_type == COV_TYPE_ANCHOR {
            anchor_bytes = anchor_bytes
                .checked_add(cov_len)
                .ok_or_else(|| TxError::new(ErrorCode::TxErrParse, "u64 overflow"))?;
        }
    }
    base_size = base_size
        .checked_add(4)
        .ok_or_else(|| TxError::new(ErrorCode::TxErrParse, "u64 overflow"))?; // locktime

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
            SUITE_ID_ML_DSA_87 => ml_count += 1,
            SUITE_ID_SLH_DSA_SHAKE_256F => slh_count += 1,
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

fn compact_size_len(n: u64) -> u64 {
    match n {
        0x00..=0xfc => 1,
        0xfd..=0xffff => 3,
        0x1_0000..=0xffff_ffff => 5,
        _ => 9,
    }
}
