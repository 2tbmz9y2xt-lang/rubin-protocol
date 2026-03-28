#![no_main]

use libfuzzer_sys::fuzz_target;
use num_bigint::BigUint;
use num_traits::{One, Zero};
use rubin_consensus::constants::{POW_LIMIT, TARGET_BLOCK_INTERVAL, WINDOW_SIZE};
use rubin_consensus::ErrorCode;

// Replaces Kani verify_retarget_no_panic
// (BigUint arbitrary-precision arithmetic is SAT-intractable for CBMC).
// Also asserts range and clamp invariants on every successful path.
fuzz_target!(|data: &[u8]| {
    // Need exactly 48 bytes: 32 (target_old) + 8 (ts_first) + 8 (ts_last).
    if data.len() < 48 {
        return;
    }

    let mut target_old = [0u8; 32];
    target_old.copy_from_slice(&data[..32]);

    let ts_first = u64::from_le_bytes(data[32..40].try_into().unwrap());
    let ts_last = u64::from_le_bytes(data[40..48].try_into().unwrap());

    let r1 = rubin_consensus::retarget_v1(target_old, ts_first, ts_last);
    let r2 = rubin_consensus::retarget_v1(target_old, ts_first, ts_last);

    match (&r1, &r2) {
        (Ok(a), Ok(b)) => {
            assert_eq!(a, b, "retarget_v1 non-deterministic output");
        }
        (Err(a), Err(b)) => {
            assert_eq!(a.code, b.code, "retarget_v1 error code drift");
            assert_eq!(a.msg, b.msg, "retarget_v1 error msg drift");
        }
        _ => panic!("retarget_v1 non-deterministic error/ok mismatch"),
    }

    let pow_limit = BigUint::from_bytes_be(&POW_LIMIT);
    let target_old_bi = BigUint::from_bytes_be(&target_old);
    if target_old_bi.is_zero() {
        let err = r1.expect_err("zero target_old must fail");
        assert_eq!(err.code, ErrorCode::TxErrParse);
        assert_eq!(err.msg, "retarget: target_old is zero");
        return;
    }
    if target_old_bi > pow_limit {
        let err = r1.expect_err("target_old above pow_limit must fail");
        assert_eq!(err.code, ErrorCode::TxErrParse);
        assert_eq!(err.msg, "retarget: target_old above pow_limit");
        return;
    }

    let got = r1.expect("valid target_old must retarget");
    assert_ne!(got, [0u8; 32]);

    let got_bi = BigUint::from_bytes_be(&got);
    assert!(got_bi >= BigUint::one());
    assert!(got_bi <= pow_limit);

    let t_actual = if ts_last <= ts_first {
        1u64
    } else {
        ts_last - ts_first
    };
    let t_expected = TARGET_BLOCK_INTERVAL
        .checked_mul(WINDOW_SIZE)
        .expect("canonical constants keep t_expected in range");
    let unclamped = (&target_old_bi * BigUint::from(t_actual)) / BigUint::from(t_expected);
    let mut lower = &target_old_bi >> 2;
    if lower < BigUint::one() {
        lower = BigUint::one();
    }
    let upper_unclamped = &target_old_bi << 2;
    let upper = if upper_unclamped > pow_limit {
        pow_limit.clone()
    } else {
        upper_unclamped
    };

    assert!(got_bi >= lower);
    assert!(got_bi <= upper);

    let expected = if unclamped < lower {
        lower
    } else if unclamped > upper {
        upper
    } else {
        unclamped
    };
    assert_eq!(got_bi, expected, "retarget_v1 clamp formula drift");
});
