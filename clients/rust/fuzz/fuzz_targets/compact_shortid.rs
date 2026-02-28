#![no_main]

use libfuzzer_sys::fuzz_target;

// Fuzz compact_shortid: SipHash-2-4 based short ID for compact block relay.
// Verifies determinism: same inputs always produce same 6-byte short ID.
fuzz_target!(|data: &[u8]| {
    // Need 48 bytes: 32 (wtxid) + 8 (nonce1) + 8 (nonce2).
    if data.len() < 48 {
        return;
    }

    let mut wtxid = [0u8; 32];
    wtxid.copy_from_slice(&data[..32]);
    let nonce1 = u64::from_le_bytes(data[32..40].try_into().unwrap());
    let nonce2 = u64::from_le_bytes(data[40..48].try_into().unwrap());

    let r1 = rubin_consensus::compact_shortid(wtxid, nonce1, nonce2);
    let r2 = rubin_consensus::compact_shortid(wtxid, nonce1, nonce2);

    if r1 != r2 {
        panic!("compact_shortid non-deterministic: {r1:02x?} != {r2:02x?}");
    }
});
