#![no_main]

use libfuzzer_sys::fuzz_target;
use rubin_consensus::constants::{MAX_VAULT_KEYS, MAX_VAULT_WHITELIST_ENTRIES};

fn strictly_sorted_unique_32(xs: &[[u8; 32]]) -> bool {
    xs.windows(2).all(|w| w[0] < w[1])
}

// Fuzz parse_vault_covenant_data: vault covenant parsing.
// Covers threshold-of-n structural invariants, canonical ordering, and owner exclusion.
fuzz_target!(|data: &[u8]| {
    let r1 = rubin_consensus::parse_vault_covenant_data(data);
    let r2 = rubin_consensus::parse_vault_covenant_data(data);

    match (&r1, &r2) {
        (Ok(a), Ok(b)) => {
            assert_eq!(a, b, "parse_vault_covenant_data non-deterministic");
            assert!(a.key_count > 0 && a.key_count <= MAX_VAULT_KEYS);
            assert!(a.threshold > 0 && a.threshold <= a.key_count);
            assert_eq!(a.key_count as usize, a.keys.len());
            assert!(strictly_sorted_unique_32(&a.keys));

            assert!(a.whitelist_count > 0 && a.whitelist_count <= MAX_VAULT_WHITELIST_ENTRIES);
            assert_eq!(a.whitelist_count as usize, a.whitelist.len());
            assert!(strictly_sorted_unique_32(&a.whitelist));
            assert!(a.whitelist.iter().all(|entry| entry != &a.owner_lock_id));

            let expected_len =
                32 + 1 + 1 + a.keys.len() * 32 + 2 + a.whitelist.len() * 32;
            assert_eq!(data.len(), expected_len);
        }
        (Err(_), Err(_)) => {}
        _ => panic!("parse_vault_covenant_data non-deterministic error/ok mismatch"),
    }
});
