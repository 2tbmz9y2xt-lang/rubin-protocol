#![no_main]

use libfuzzer_sys::fuzz_target;
use rubin_consensus::constants::POW_LIMIT;
use rubin_consensus::{block_hash, ErrorCode, BLOCK_HEADER_BYTES};

// Fuzz pow_check: PoW validation (header hash vs target).
// Fixed input: 80 bytes header + 32 bytes target = 112 bytes.
// Asserts range checks and strict block_hash < target semantics.
fuzz_target!(|data: &[u8]| {
    if data.len() < BLOCK_HEADER_BYTES + 32 {
        return;
    }

    let header_bytes = &data[..BLOCK_HEADER_BYTES];
    let mut target = [0u8; 32];
    target.copy_from_slice(&data[BLOCK_HEADER_BYTES..BLOCK_HEADER_BYTES + 32]);

    let r1 = rubin_consensus::pow_check(header_bytes, target);
    let r2 = rubin_consensus::pow_check(header_bytes, target);

    match (&r1, &r2) {
        (Ok(()), Ok(())) => {}
        (Err(a), Err(b)) => {
            assert_eq!(a.code, b.code, "pow_check error code drift");
            assert_eq!(a.msg, b.msg, "pow_check error msg drift");
        }
        _ => panic!("pow_check non-deterministic error/ok mismatch"),
    }

    let hash = block_hash(header_bytes).expect("fixed-size header hashes");
    if target == [0u8; 32] || target > POW_LIMIT {
        let err = r1.expect_err("out-of-range target must fail");
        assert_eq!(err.code, ErrorCode::BlockErrTargetInvalid);
        assert_eq!(err.msg, "target out of range");
    } else if hash >= target {
        let err = r1.expect_err("hash >= target must fail");
        assert_eq!(err.code, ErrorCode::BlockErrPowInvalid);
        assert_eq!(err.msg, "pow invalid");
    } else {
        r1.expect("hash < target within range must pass");
    }
});
