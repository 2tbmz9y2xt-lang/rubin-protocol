#![no_main]

use libfuzzer_sys::fuzz_target;

// Fuzz block_subsidy: emission schedule calculation.
// Verifies no-panic, determinism, and subsidy floor invariant.
fuzz_target!(|data: &[u8]| {
    if data.len() < 16 {
        return;
    }

    let height = u64::from_le_bytes(data[..8].try_into().unwrap());
    let already_generated = u64::from_le_bytes(data[8..16].try_into().unwrap());

    let s1 = rubin_consensus::block_subsidy(height, already_generated);
    let s2 = rubin_consensus::block_subsidy(height, already_generated);

    if s1 != s2 {
        panic!("block_subsidy non-deterministic: {s1} != {s2}");
    }

    // Invariant: genesis block subsidy is always 0.
    if height == 0 && s1 != 0 {
        panic!("block_subsidy(0, _) != 0: got {s1}");
    }
});
