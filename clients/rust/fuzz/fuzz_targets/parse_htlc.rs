#![no_main]

use libfuzzer_sys::fuzz_target;
use rubin_consensus::constants::{LOCK_MODE_HEIGHT, LOCK_MODE_TIMESTAMP};

// Fuzz parse_htlc_covenant_data: HTLC covenant parsing.
// Tests deterministic parsing plus post-parse covenant invariants.
fuzz_target!(|data: &[u8]| {
    let r1 = rubin_consensus::parse_htlc_covenant_data(data);
    let r2 = rubin_consensus::parse_htlc_covenant_data(data);

    match (&r1, &r2) {
        (Ok(a), Ok(b)) => {
            assert_eq!(a, b, "parse_htlc_covenant_data non-deterministic");
            assert!(matches!(a.lock_mode, LOCK_MODE_HEIGHT | LOCK_MODE_TIMESTAMP));
            assert!(a.lock_value > 0);
            assert_ne!(a.claim_key_id, a.refund_key_id);
        }
        (Err(_), Err(_)) => {}
        _ => panic!("parse_htlc_covenant_data non-deterministic error/ok mismatch"),
    }
});
