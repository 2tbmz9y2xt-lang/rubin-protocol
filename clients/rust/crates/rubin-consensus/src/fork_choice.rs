use crate::constants::POW_LIMIT;
use crate::error::{ErrorCode, TxError};
use num_bigint::BigUint;
use num_traits::{One, Zero};

// fork_work_from_target computes CANONICAL §23 per-block work:
//   work = floor(2^256 / target)
//
// This is non-validation helper logic but MUST be deterministic and MUST NOT use floats.
pub fn fork_work_from_target(target: [u8; 32]) -> Result<BigUint, TxError> {
    let t = BigUint::from_bytes_be(&target);
    if t.is_zero() {
        return Err(TxError::new(ErrorCode::TxErrParse, "fork_work: target is zero"));
    }

    let pow_limit = BigUint::from_bytes_be(&POW_LIMIT);
    if t > pow_limit {
        return Err(TxError::new(
            ErrorCode::TxErrParse,
            "fork_work: target above pow_limit",
        ));
    }

    let two256: BigUint = BigUint::one() << 256usize;
    Ok(two256 / t)
}

pub fn fork_chainwork_from_targets(targets: &[[u8; 32]]) -> Result<BigUint, TxError> {
    let mut total = BigUint::zero();
    for t in targets {
        total += fork_work_from_target(*t)?;
    }
    Ok(total)
}

