#![no_main]

use libfuzzer_sys::fuzz_target;

// Fuzz validate_block_basic: the primary block validator.
// Covers header parsing, tx structure, weight, merkle, witness commitment.
fuzz_target!(|data: &[u8]| {
    if data.len() < 64 {
        return;
    }

    // Split last 64 bytes as optional prev_hash and target.
    let block_end = data.len() - 64;
    let block_bytes = &data[..block_end];
    let params = &data[block_end..];

    let mut prev_hash = [0u8; 32];
    prev_hash.copy_from_slice(&params[..32]);
    let mut target = [0u8; 32];
    target.copy_from_slice(&params[32..64]);

    // Test with None options (no expected values).
    let _ = rubin_consensus::validate_block_basic(block_bytes, None, None);

    // Test with Some options (constrained validation).
    let _ = rubin_consensus::validate_block_basic(block_bytes, Some(prev_hash), Some(target));
});
