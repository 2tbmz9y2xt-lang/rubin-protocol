#![no_main]
use libfuzzer_sys::fuzz_target;
use sha3::{Digest, Sha3_256};

/// Mirrors rubin_consensus::hash::sha3_256 (private module).
fn sha3_256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(data);
    let r = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&r);
    out
}

fuzz_target!(|data: &[u8]| {
    if data.len() > 8192 || data.is_empty() {
        return;
    }

    // Split fuzz data into two chunks at a fuzz-derived midpoint.
    let mid = data[0] as usize % data.len();
    let chunk1 = &data[1..=mid.min(data.len() - 1)];
    let chunk2 = if mid + 1 < data.len() {
        &data[mid + 1..]
    } else {
        &[][..]
    };

    // Compute correct commitment: sha3_256(chunk1 || chunk2).
    let mut concat = Vec::with_capacity(chunk1.len() + chunk2.len());
    concat.extend_from_slice(chunk1);
    concat.extend_from_slice(chunk2);
    let correct_commit = sha3_256(&concat);

    let mut da_id = [0u8; 32];
    da_id[0] = 0x42;

    let task = rubin_consensus::DaPayloadCommitTask {
        da_id,
        chunk_count: 2,
        chunk_payloads: vec![chunk1.to_vec(), chunk2.to_vec()],
        expected_commit: correct_commit,
    };

    // Correct commitment — must pass with any worker count.
    for w in [1, 2, 4] {
        let r = rubin_consensus::verify_da_payload_commits_parallel(vec![task.clone()], w);
        assert!(
            r.is_ok(),
            "correct commit rejected with {} workers: {:?}",
            w, r
        );
    }

    // Mutated commitment — must fail.
    let mut bad_task = task.clone();
    bad_task.expected_commit[0] ^= 0xFF;
    let r = rubin_consensus::verify_da_payload_commits_parallel(vec![bad_task], 1);
    assert!(r.is_err(), "mutated commit accepted");

    // Determinism: single-chunk task with same data.
    let single_task = rubin_consensus::DaPayloadCommitTask {
        da_id,
        chunk_count: 1,
        chunk_payloads: vec![concat.clone()],
        expected_commit: correct_commit,
    };
    let r = rubin_consensus::verify_da_payload_commits_parallel(vec![single_task], 1);
    assert!(
        r.is_ok(),
        "single-chunk commit with same data rejected: {:?}",
        r
    );
});
