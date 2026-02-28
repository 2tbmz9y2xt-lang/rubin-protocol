#![no_main]

use libfuzzer_sys::fuzz_target;

// Fuzz pow_check: PoW validation (header hash vs target).
// Fixed input: 80 bytes header + 32 bytes target = 112 bytes.
fuzz_target!(|data: &[u8]| {
    if data.len() < 112 {
        return;
    }

    let header_bytes = &data[..80];
    let mut target = [0u8; 32];
    target.copy_from_slice(&data[80..112]);

    let _ = rubin_consensus::pow_check(header_bytes, target);
});
