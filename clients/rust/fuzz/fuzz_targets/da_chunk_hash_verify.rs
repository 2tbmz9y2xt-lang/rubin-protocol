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

    // Mutated hash — must fail regardless of worker count.
    let mut bad_hash = correct_hash;
    bad_hash[0] ^= 0xFF;
    for w in [1, 2, 4] {
        let bad_task_w = rubin_consensus::DaChunkHashTask {
            tx_index: 0,
            da_payload: data.to_vec(),
            expected: bad_hash,
        };
        let r = rubin_consensus::verify_da_chunk_hashes_parallel(vec![bad_task_w], w);
        assert!(r.is_err(), "mutated hash accepted with {} workers", w);
    }

    // Correct hash must pass regardless of worker count.
    for w in [1, 2, 4] {
        let r = rubin_consensus::verify_da_chunk_hashes_parallel(vec![correct_task.clone()], w);
        assert!(r.is_ok(), "correct hash rejected with {} workers: {:?}", w, r);
    }
});
