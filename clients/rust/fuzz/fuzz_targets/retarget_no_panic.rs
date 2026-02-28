#![no_main]

use libfuzzer_sys::fuzz_target;

// Replaces Kani verify_retarget_no_panic
// (BigUint arbitrary-precision arithmetic is SAT-intractable for CBMC).
// Also exercises private biguint_to_bytes32 on every successful path.
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
            if a != b {
                panic!("retarget_v1 non-deterministic output");
            }
        }
        (Err(_), Err(_)) => {}
        _ => panic!("retarget_v1 non-deterministic error/ok mismatch"),
    }
});
