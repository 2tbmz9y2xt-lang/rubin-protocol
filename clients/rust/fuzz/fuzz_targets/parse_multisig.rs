#![no_main]

use libfuzzer_sys::fuzz_target;

// Fuzz parse_multisig_covenant_data: multisig covenant parsing.
// Covers threshold-of-n keys, sorted uniqueness checks.
fuzz_target!(|data: &[u8]| {
    let r1 = rubin_consensus::parse_multisig_covenant_data(data);
    let r2 = rubin_consensus::parse_multisig_covenant_data(data);

    match (&r1, &r2) {
        (Ok(a), Ok(b)) => {
            if a != b {
                panic!("parse_multisig_covenant_data non-deterministic");
            }
        }
        (Err(_), Err(_)) => {}
        _ => panic!("parse_multisig_covenant_data non-deterministic error/ok mismatch"),
    }
});
