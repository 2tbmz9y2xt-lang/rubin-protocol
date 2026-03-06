use super::*;
use crate::merkle::merkle_root_txids;
use crate::pow::pow_check;

pub(super) fn validate_header_commitments(
    pb: &ParsedBlock,
    expected_prev_hash: Option<[u8; 32]>,
    expected_target: Option<[u8; 32]>,
) -> Result<(), TxError> {
    pow_check(&pb.header_bytes, pb.header.target)?;

    if let Some(target) = expected_target {
        if pb.header.target != target {
            return Err(TxError::new(
                ErrorCode::BlockErrTargetInvalid,
                "target mismatch",
            ));
        }
    }

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
    Ok(())
}

pub(super) fn validate_timestamp_rules(
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
    let upper_bound = median.saturating_add(crate::constants::MAX_FUTURE_DRIFT);
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
