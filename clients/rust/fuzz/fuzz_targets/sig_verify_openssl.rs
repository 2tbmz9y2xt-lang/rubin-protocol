#![no_main]

use libfuzzer_sys::fuzz_target;

// Fuzz `verify_sig`: the OpenSSL signature verification dispatch.
//
// Parses arbitrary bytes into (suite_id, pubkey, sig, digest) and exercises
// the verify_sig path for all possible suite IDs. Since only ML-DSA-87 is
// registered, most inputs hit the unsupported-suite error path. Correct-length
// inputs for ML-DSA-87 exercise the full OpenSSL EVP_DigestVerify pipeline.
//
// Goal: exercise verify_sig dispatch, length checks, error paths, and ensure
// no panic or memory safety issue regardless of input content.
//
// Invariants checked:
// - Determinism: two calls with same input produce identical result.
// - verify_sig and verify_sig_with_registry (default) agree on known suites.
// - No panic on any input combination.
fuzz_target!(|data: &[u8]| {
    // Minimum: suite_id(1) + digest(32) + at least 1 byte each for pubkey/sig split.
    if data.len() < 35 {
        return;
    }

    let suite_id = data[0];
    let digest: [u8; 32] = data[1..33].try_into().unwrap();

    // Split remaining bytes between pubkey and sig at midpoint.
    let remaining = &data[33..];
    if remaining.is_empty() {
        return;
    }
    let mid = remaining.len() / 2;
    let pubkey = &remaining[..mid];
    let sig = &remaining[mid..];

    // Direct verify_sig call.
    let r1 = rubin_consensus::verify_sig(suite_id, pubkey, sig, digest);

    // Determinism check.
    let r2 = rubin_consensus::verify_sig(suite_id, pubkey, sig, digest);
    match (&r1, &r2) {
        (Ok(v1), Ok(v2)) => assert_eq!(v1, v2, "verify_sig non-deterministic"),
        (Err(_), Err(_)) => {} // Both error — OK.
        _ => panic!("verify_sig non-deterministic: {:?} vs {:?}", r1, r2),
    }

    // Registry dispatch with default registry.
    let registry = rubin_consensus::SuiteRegistry::default_registry();
    let r3 = rubin_consensus::verify_sig_with_registry(suite_id, pubkey, sig, digest, &registry);

    // For registered suites, results must agree.
    if registry.is_registered(suite_id) {
        match (&r1, &r3) {
            (Ok(v1), Ok(v3)) => {
                assert_eq!(v1, v3, "registry dispatch diverged for suite 0x{:02x}", suite_id);
            }
            (Err(_), Err(_)) => {} // Both error — OK (could differ in error variant).
            _ => {
                // One ok, one err: divergence only if direct returned Ok(true/false)
                // and registry returned Err or vice versa. This would be a bug.
                panic!(
                    "verify_sig vs registry diverged for suite 0x{:02x}: {:?} vs {:?}",
                    suite_id, r1, r3
                );
            }
        }
    }
});
