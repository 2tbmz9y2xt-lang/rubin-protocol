#![no_main]
use libfuzzer_sys::fuzz_target;
use sha3::{Digest, Sha3_256};

fn sha3_256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

fuzz_target!(|data: &[u8]| {
    if data.len() > 8192 {
        return;
    }

    // Compute correct hash for payload.
    let correct_hash = sha3_256(data);

    // Correct task — must pass.
    let correct_task = rubin_consensus::DaChunkHashTask {
        tx_index: 0,
        da_payload: data.to_vec(),
        expected: correct_hash,
    };
    let r = rubin_consensus::verify_da_chunk_hashes_parallel(vec![correct_task.clone()], 1);
    assert!(r.is_ok(), "correct hash rejected: {:?}", r);

    // Mutated hash — must fail.
    let mut bad_hash = correct_hash;
    bad_hash[0] ^= 0xFF;
    let bad_task = rubin_consensus::DaChunkHashTask {
        tx_index: 0,
        da_payload: data.to_vec(),
        expected: bad_hash,
    };
    let r = rubin_consensus::verify_da_chunk_hashes_parallel(vec![bad_task], 1);
    assert!(r.is_err(), "mutated hash accepted — collision");

    // Multi-worker determinism.
    let r1 = rubin_consensus::verify_da_chunk_hashes_parallel(vec![correct_task.clone()], 2);
    let r2 = rubin_consensus::verify_da_chunk_hashes_parallel(vec![correct_task], 4);
    assert_eq!(r1.is_ok(), r2.is_ok(), "worker count affects result");
});
