use crate::constants::POW_LIMIT;
use crate::error::{ErrorCode, TxError};
use num_bigint::BigUint;
use num_traits::{One, Zero};

// work_from_target computes CANONICAL §23 per-block work:
//   work = floor(2^256 / target)
//
// This is non-validation helper logic but MUST be deterministic and MUST NOT use floats.
pub fn work_from_target(target: [u8; 32]) -> Result<BigUint, TxError> {
    let t = BigUint::from_bytes_be(&target);
    if t.is_zero() {
        return Err(TxError::new(
            ErrorCode::TxErrParse,
            "fork_work: target is zero",
        ));
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

pub fn chain_work_from_targets(targets: &[[u8; 32]]) -> Result<BigUint, TxError> {
    let mut total = BigUint::zero();
    for t in targets {
        total += work_from_target(*t)?;
    }
    Ok(total)
}

#[deprecated(note = "use work_from_target")]
pub fn fork_work_from_target(target: [u8; 32]) -> Result<BigUint, TxError> {
    work_from_target(target)
}

#[deprecated(note = "use chain_work_from_targets")]
pub fn fork_chainwork_from_targets(targets: &[[u8; 32]]) -> Result<BigUint, TxError> {
    chain_work_from_targets(targets)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn work_from_target_accepts_pow_limit_boundary() {
        let work = work_from_target(POW_LIMIT).expect("pow_limit must be accepted");
        assert_eq!(work, BigUint::one());
    }

    #[test]
    fn work_from_target_is_deterministic() {
        let target = POW_LIMIT;
        let w1 = work_from_target(target).expect("work 1");
        let w2 = work_from_target(target).expect("work 2");
        assert_eq!(w1, w2);
    }

    #[test]
    fn chain_work_from_targets_is_deterministic() {
        let targets = [POW_LIMIT, POW_LIMIT];
        let w1 = chain_work_from_targets(&targets).expect("chainwork 1");
        let w2 = chain_work_from_targets(&targets).expect("chainwork 2");
        assert_eq!(w1, w2);
    }

    #[test]
    fn work_from_target_rejects_zero_target_with_exact_error() {
        let err = work_from_target([0u8; 32]).unwrap_err();
        assert_eq!(err.code, ErrorCode::TxErrParse);
        assert_eq!(err.msg, "fork_work: target is zero");
    }

    #[test]
    fn work_from_target_accepts_one_min_target() {
        let mut target = [0u8; 32];
        target[31] = 0x01;

        let work = work_from_target(target).expect("target one must be accepted");
        let two256: BigUint = BigUint::one() << 256usize;
        assert_eq!(work, two256);
    }

    #[test]
    fn work_from_target_accepts_half_range_target() {
        let mut target = [0u8; 32];
        target[0] = 0x80;

        let work = work_from_target(target).expect("half-range target must be accepted");
        assert_eq!(work, BigUint::from(2u8));
    }

    #[test]
    fn chain_work_from_targets_sums_and_propagates_invalid_target() {
        let mut half = [0u8; 32];
        half[0] = 0x80;

        let total = chain_work_from_targets(&[POW_LIMIT, half]).expect("chainwork");
        assert_eq!(total, BigUint::from(3u8));

        let err = chain_work_from_targets(&[[0u8; 32], POW_LIMIT]).unwrap_err();
        assert_eq!(err.code, ErrorCode::TxErrParse);
        assert_eq!(err.msg, "fork_work: target is zero");
    }

    #[test]
    fn above_pow_limit_target_is_unrepresentable_with_current_pow_limit() {
        assert_eq!(POW_LIMIT, [0xffu8; 32]);
        let pow_limit = BigUint::from_bytes_be(&POW_LIMIT);
        let max_u256 = (BigUint::one() << 256usize) - BigUint::one();
        assert_eq!(pow_limit, max_u256);
    }

    #[allow(deprecated)]
    #[test]
    fn deprecated_fork_work_aliases_match_canonical_helpers() {
        let mut half = [0u8; 32];
        half[0] = 0x80;

        assert_eq!(
            fork_work_from_target(half).expect("alias work"),
            work_from_target(half).expect("canonical work")
        );

        let alias_err = fork_work_from_target([0u8; 32]).unwrap_err();
        let canonical_err = work_from_target([0u8; 32]).unwrap_err();
        assert_eq!(alias_err.code, canonical_err.code);
        assert_eq!(alias_err.msg, canonical_err.msg);

        let targets = [POW_LIMIT, half];
        assert_eq!(
            fork_chainwork_from_targets(&targets).expect("alias chainwork"),
            chain_work_from_targets(&targets).expect("canonical chainwork")
        );

        let alias_err = fork_chainwork_from_targets(&[[0u8; 32], POW_LIMIT]).unwrap_err();
        let canonical_err = chain_work_from_targets(&[[0u8; 32], POW_LIMIT]).unwrap_err();
        assert_eq!(alias_err.code, canonical_err.code);
        assert_eq!(alias_err.msg, canonical_err.msg);
    }
}
