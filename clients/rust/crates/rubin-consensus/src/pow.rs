use crate::constants::{TARGET_BLOCK_INTERVAL, WINDOW_SIZE};
use crate::error::{ErrorCode, TxError};
use crate::{block_hash, BLOCK_HEADER_BYTES};
use num_bigint::BigUint;
use num_traits::{One, Zero};

pub fn retarget_v1(
    target_old: [u8; 32],
    timestamp_first: u64,
    timestamp_last: u64,
) -> Result<[u8; 32], TxError> {
    let t_old = BigUint::from_bytes_be(&target_old);
    if t_old.is_zero() {
        return Err(TxError::new(
            ErrorCode::TxErrParse,
            "retarget: target_old is zero",
        ));
    }

    let t_actual = if timestamp_last <= timestamp_first {
        1u64
    } else {
        timestamp_last - timestamp_first
    };

    let t_expected = TARGET_BLOCK_INTERVAL
        .checked_mul(WINDOW_SIZE)
        .ok_or_else(|| TxError::new(ErrorCode::TxErrParse, "retarget: t_expected overflow"))?;
    if t_expected == 0 {
        return Err(TxError::new(
            ErrorCode::TxErrParse,
            "retarget: t_expected is zero",
        ));
    }

    // floor(target_old * T_actual / T_expected)
    let mut t_new = (&t_old * BigUint::from(t_actual)) / BigUint::from(t_expected);

    // clamp lower = max(1, floor(target_old / 4))
    let mut lower = &t_old >> 2;
    if lower < BigUint::one() {
        lower = BigUint::one();
    }
    // upper = target_old * 4
    let upper = &t_old << 2;

    if t_new < lower {
        t_new = lower;
    }
    if t_new > upper {
        t_new = upper;
    }

    biguint_to_bytes32(&t_new)
}

pub fn pow_check(header_bytes: &[u8], target: [u8; 32]) -> Result<(), TxError> {
    if header_bytes.len() != BLOCK_HEADER_BYTES {
        return Err(TxError::new(
            ErrorCode::TxErrParse,
            "pow: invalid header length",
        ));
    }
    let h = block_hash(header_bytes)?;
    if h >= target {
        return Err(TxError::new(ErrorCode::BlockErrPowInvalid, "pow invalid"));
    }
    Ok(())
}

fn biguint_to_bytes32(x: &BigUint) -> Result<[u8; 32], TxError> {
    let b = x.to_bytes_be();
    if b.len() > 32 {
        return Err(TxError::new(ErrorCode::TxErrParse, "u256: overflow"));
    }
    let mut out = [0u8; 32];
    out[32 - b.len()..].copy_from_slice(&b);
    Ok(out)
}
