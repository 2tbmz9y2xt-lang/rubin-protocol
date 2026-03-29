use crate::error::ErrorCode;
use crate::tests::{
    build_block_bytes, coinbase_with_witness_commitment, da_chunk_tx, da_commit_tx,
};
use crate::{
    collect_da_chunk_hash_tasks, collect_da_payload_commit_tasks, merkle_root_txids,
    parse_block_bytes, validate_block_basic, verify_da_chunk_hashes_parallel,
    verify_da_payload_commits_parallel,
};

fn txids_for_block_txs(txs: &[Vec<u8>]) -> Vec<[u8; 32]> {
    txs.iter()
        .map(|tx| crate::parse_tx(tx).expect("parse tx").1)
        .collect()
}

#[test]
fn collect_da_chunk_hash_tasks_preserves_block_tx_order() {
    let da_id = [0x11u8; 32];
    let payload_a = b"chunk-a".to_vec();
    let payload_b = b"chunk-b".to_vec();
    let chunk_hash_a = crate::hash::sha3_256(&payload_a);
    let chunk_hash_b = crate::hash::sha3_256(&payload_b);
    let payload_commitment =
        crate::hash::sha3_256(&[payload_a.clone(), payload_b.clone()].concat());

    let coinbase = coinbase_with_witness_commitment(
        0,
        &[
            da_commit_tx(da_id, 2, payload_commitment, 1),
            da_chunk_tx(da_id, 1, chunk_hash_b, &payload_b, 2),
            da_chunk_tx(da_id, 0, chunk_hash_a, &payload_a, 3),
        ],
    );
    let txs = vec![
        coinbase,
        da_commit_tx(da_id, 2, payload_commitment, 1),
        da_chunk_tx(da_id, 1, chunk_hash_b, &payload_b, 2),
        da_chunk_tx(da_id, 0, chunk_hash_a, &payload_a, 3),
    ];
    let txids = txids_for_block_txs(&txs);
    let block = build_block_bytes(
        [0u8; 32],
        merkle_root_txids(&txids).expect("merkle root"),
        [0xff; 32],
        7,
        &txs,
    );
    let parsed = parse_block_bytes(&block).expect("parse block");

    let tasks = collect_da_chunk_hash_tasks(&parsed.txs).expect("collect chunk hash tasks");
    assert_eq!(tasks.len(), 2);
    assert_eq!(tasks[0].tx_index, 2);
    assert_eq!(tasks[0].da_payload, payload_b);
    assert_eq!(tasks[1].tx_index, 3);
    assert_eq!(tasks[1].da_payload, payload_a);
}

#[test]
fn collect_da_payload_commit_tasks_sorts_da_ids_and_orders_chunks() {
    let da_id_hi = [0x22u8; 32];
    let da_id_lo = [0x11u8; 32];

    let lo_chunk_0 = b"lo-0".to_vec();
    let lo_chunk_1 = b"lo-1".to_vec();
    let hi_chunk_0 = b"hi-0".to_vec();

    let lo_commitment = crate::hash::sha3_256(&[lo_chunk_0.clone(), lo_chunk_1.clone()].concat());
    let hi_commitment = crate::hash::sha3_256(&hi_chunk_0);

    let txs = vec![
        crate::parse_tx(&da_commit_tx(da_id_hi, 1, hi_commitment, 10))
            .expect("parse hi commit")
            .0,
        crate::parse_tx(&da_chunk_tx(
            da_id_lo,
            1,
            crate::hash::sha3_256(&lo_chunk_1),
            &lo_chunk_1,
            11,
        ))
        .expect("parse lo chunk 1")
        .0,
        crate::parse_tx(&da_chunk_tx(
            da_id_hi,
            0,
            crate::hash::sha3_256(&hi_chunk_0),
            &hi_chunk_0,
            12,
        ))
        .expect("parse hi chunk 0")
        .0,
        crate::parse_tx(&da_commit_tx(da_id_lo, 2, lo_commitment, 13))
            .expect("parse lo commit")
            .0,
        crate::parse_tx(&da_chunk_tx(
            da_id_lo,
            0,
            crate::hash::sha3_256(&lo_chunk_0),
            &lo_chunk_0,
            14,
        ))
        .expect("parse lo chunk 0")
        .0,
    ];

    let tasks = collect_da_payload_commit_tasks(&txs).expect("collect payload commit tasks");
    assert_eq!(tasks.len(), 2);
    assert_eq!(tasks[0].da_id, da_id_lo);
    assert_eq!(tasks[0].chunk_payloads, vec![lo_chunk_0, lo_chunk_1]);
    assert_eq!(tasks[1].da_id, da_id_hi);
    assert_eq!(tasks[1].chunk_payloads, vec![hi_chunk_0]);
}

#[test]
fn verify_da_chunk_hashes_parallel_matches_block_basic_error_code() {
    let da_id = [0x33u8; 32];
    let da_payload = b"bad-chunk".to_vec();
    let mut bad_chunk_hash = crate::hash::sha3_256(&da_payload);
    bad_chunk_hash[0] ^= 0x01;
    let payload_commitment = crate::hash::sha3_256(&da_payload);
    let da_commit = da_commit_tx(da_id, 1, payload_commitment, 1);
    let da_chunk = da_chunk_tx(da_id, 0, bad_chunk_hash, &da_payload, 2);
    let coinbase = coinbase_with_witness_commitment(0, &[da_commit.clone(), da_chunk.clone()]);
    let txs = vec![coinbase, da_commit, da_chunk];
    let txids = txids_for_block_txs(&txs);
    let block = build_block_bytes(
        [0u8; 32],
        merkle_root_txids(&txids).expect("merkle root"),
        [0xff; 32],
        9,
        &txs,
    );

    let block_err = validate_block_basic(&block, None, None).expect_err("bad chunk hash");
    let parsed = parse_block_bytes(&block).expect("parse block");
    let helper_err = verify_da_chunk_hashes_parallel(
        collect_da_chunk_hash_tasks(&parsed.txs).expect("collect chunk hash tasks"),
        4,
    )
    .unwrap_err();

    assert_eq!(block_err.code, ErrorCode::BlockErrDaChunkHashInvalid);
    assert_eq!(helper_err.code, block_err.code);
}

#[test]
fn verify_da_payload_commits_parallel_matches_block_basic_error_code() {
    let da_id = [0x44u8; 32];
    let da_payload = b"payload-commit".to_vec();
    let chunk_hash = crate::hash::sha3_256(&da_payload);
    let mut bad_commitment = crate::hash::sha3_256(&da_payload);
    bad_commitment[0] ^= 0x01;
    let da_commit = da_commit_tx(da_id, 1, bad_commitment, 1);
    let da_chunk = da_chunk_tx(da_id, 0, chunk_hash, &da_payload, 2);
    let coinbase = coinbase_with_witness_commitment(0, &[da_commit.clone(), da_chunk.clone()]);
    let txs = vec![coinbase, da_commit, da_chunk];
    let txids = txids_for_block_txs(&txs);
    let block = build_block_bytes(
        [0u8; 32],
        merkle_root_txids(&txids).expect("merkle root"),
        [0xff; 32],
        10,
        &txs,
    );

    let block_err = validate_block_basic(&block, None, None).expect_err("bad commitment");
    let parsed = parse_block_bytes(&block).expect("parse block");
    let helper_err = verify_da_payload_commits_parallel(
        collect_da_payload_commit_tasks(&parsed.txs).expect("collect payload commit tasks"),
        4,
    )
    .unwrap_err();

    assert_eq!(block_err.code, ErrorCode::BlockErrDaPayloadCommitInvalid);
    assert_eq!(helper_err.code, block_err.code);
}

#[test]
fn verify_da_parallel_helpers_accept_valid_multi_set_block() {
    let da_id_a = [0x55u8; 32];
    let da_id_b = [0x66u8; 32];

    let a0 = b"a-0".to_vec();
    let a1 = b"a-1".to_vec();
    let b0 = b"b-0".to_vec();

    let a_commitment = crate::hash::sha3_256(&[a0.clone(), a1.clone()].concat());
    let b_commitment = crate::hash::sha3_256(&b0);

    let txs = vec![
        coinbase_with_witness_commitment(
            0,
            &[
                da_commit_tx(da_id_b, 1, b_commitment, 1),
                da_chunk_tx(da_id_a, 1, crate::hash::sha3_256(&a1), &a1, 2),
                da_commit_tx(da_id_a, 2, a_commitment, 3),
                da_chunk_tx(da_id_b, 0, crate::hash::sha3_256(&b0), &b0, 4),
                da_chunk_tx(da_id_a, 0, crate::hash::sha3_256(&a0), &a0, 5),
            ],
        ),
        da_commit_tx(da_id_b, 1, b_commitment, 1),
        da_chunk_tx(da_id_a, 1, crate::hash::sha3_256(&a1), &a1, 2),
        da_commit_tx(da_id_a, 2, a_commitment, 3),
        da_chunk_tx(da_id_b, 0, crate::hash::sha3_256(&b0), &b0, 4),
        da_chunk_tx(da_id_a, 0, crate::hash::sha3_256(&a0), &a0, 5),
    ];
    let txids = txids_for_block_txs(&txs);
    let block = build_block_bytes(
        [0u8; 32],
        merkle_root_txids(&txids).expect("merkle root"),
        [0xff; 32],
        11,
        &txs,
    );

    validate_block_basic(&block, None, None).expect("valid DA block");
    let parsed = parse_block_bytes(&block).expect("parse valid block");

    verify_da_chunk_hashes_parallel(
        collect_da_chunk_hash_tasks(&parsed.txs).expect("collect chunk hash tasks"),
        0,
    )
    .expect("chunk hashes");
    verify_da_payload_commits_parallel(
        collect_da_payload_commit_tasks(&parsed.txs).expect("collect payload commit tasks"),
        0,
    )
    .expect("payload commitments");
}

// ---- Additional unit tests to balance Go coverage ----

#[test]
fn verify_da_chunk_hashes_empty_tasks_passes() {
    verify_da_chunk_hashes_parallel(vec![], 4).expect("empty tasks must pass");
}

#[test]
fn verify_da_payload_commits_empty_tasks_passes() {
    verify_da_payload_commits_parallel(vec![], 4).expect("empty tasks must pass");
}

#[test]
fn verify_da_chunk_hashes_single_valid_task() {
    let payload = b"single-chunk-data".to_vec();
    let expected = crate::hash::sha3_256(&payload);
    let task = crate::DaChunkHashTask {
        tx_index: 0,
        da_payload: payload,
        expected,
    };
    verify_da_chunk_hashes_parallel(vec![task], 1).expect("single valid task must pass");
}

#[test]
fn verify_da_chunk_hashes_single_invalid_task() {
    let payload = b"single-chunk-data".to_vec();
    let mut expected = crate::hash::sha3_256(&payload);
    expected[0] ^= 0xFF;
    let task = crate::DaChunkHashTask {
        tx_index: 0,
        da_payload: payload,
        expected,
    };
    let err = verify_da_chunk_hashes_parallel(vec![task], 1).unwrap_err();
    assert_eq!(err.code, ErrorCode::BlockErrDaChunkHashInvalid);
}

#[test]
fn verify_da_chunk_hashes_multi_worker_determinism() {
    let payload = b"determinism-test".to_vec();
    let expected = crate::hash::sha3_256(&payload);
    let task = crate::DaChunkHashTask {
        tx_index: 0,
        da_payload: payload,
        expected,
    };
    // Same task with different worker counts must produce same result.
    for workers in [1, 2, 4, 8] {
        verify_da_chunk_hashes_parallel(vec![task.clone()], workers)
            .unwrap_or_else(|_| panic!("failed with {} workers", workers));
    }
}

#[test]
fn verify_da_chunk_hashes_error_ordering_first_by_index() {
    let payload_ok = b"ok-payload".to_vec();
    let hash_ok = crate::hash::sha3_256(&payload_ok);

    let payload_bad = b"bad-payload".to_vec();
    let mut hash_bad = crate::hash::sha3_256(&payload_bad);
    hash_bad[0] ^= 0xFF;

    // Place bad task at index 1, good task at index 0.
    let tasks = vec![
        crate::DaChunkHashTask {
            tx_index: 0,
            da_payload: payload_ok,
            expected: hash_ok,
        },
        crate::DaChunkHashTask {
            tx_index: 1,
            da_payload: payload_bad,
            expected: hash_bad,
        },
    ];
    let err = verify_da_chunk_hashes_parallel(tasks, 2).unwrap_err();
    assert_eq!(err.code, ErrorCode::BlockErrDaChunkHashInvalid);
}

#[test]
fn verify_da_payload_commits_valid_single_chunk() {
    let chunk = b"single-commit-chunk".to_vec();
    let commitment = crate::hash::sha3_256(&chunk);
    let task = crate::DaPayloadCommitTask {
        da_id: [0x01; 32],
        chunk_count: 1,
        chunk_payloads: vec![chunk],
        expected_commit: commitment,
    };
    verify_da_payload_commits_parallel(vec![task], 1).expect("valid single chunk commit");
}

#[test]
fn verify_da_payload_commits_valid_multi_chunk() {
    let c0 = b"chunk-0".to_vec();
    let c1 = b"chunk-1".to_vec();
    let concat = [c0.clone(), c1.clone()].concat();
    let commitment = crate::hash::sha3_256(&concat);
    let task = crate::DaPayloadCommitTask {
        da_id: [0x02; 32],
        chunk_count: 2,
        chunk_payloads: vec![c0, c1],
        expected_commit: commitment,
    };
    verify_da_payload_commits_parallel(vec![task], 2).expect("valid multi-chunk commit");
}

#[test]
fn verify_da_payload_commits_invalid_commitment() {
    let chunk = b"bad-commit-chunk".to_vec();
    let mut bad_commitment = crate::hash::sha3_256(&chunk);
    bad_commitment[31] ^= 0x01;
    let task = crate::DaPayloadCommitTask {
        da_id: [0x03; 32],
        chunk_count: 1,
        chunk_payloads: vec![chunk],
        expected_commit: bad_commitment,
    };
    let err = verify_da_payload_commits_parallel(vec![task], 1).unwrap_err();
    assert_eq!(err.code, ErrorCode::BlockErrDaPayloadCommitInvalid);
}

#[test]
fn verify_da_chunk_hashes_empty_payload_valid() {
    let payload = vec![];
    let expected = crate::hash::sha3_256(&payload);
    let task = crate::DaChunkHashTask {
        tx_index: 0,
        da_payload: payload,
        expected,
    };
    verify_da_chunk_hashes_parallel(vec![task], 1).expect("empty payload with correct hash");
}

#[test]
fn verify_da_chunk_hashes_zero_workers_treated_as_sequential() {
    let payload = b"zero-workers".to_vec();
    let expected = crate::hash::sha3_256(&payload);
    let task = crate::DaChunkHashTask {
        tx_index: 0,
        da_payload: payload,
        expected,
    };
    // workers=0 should not panic and should work (fallback to sequential).
    verify_da_chunk_hashes_parallel(vec![task], 0).expect("zero workers must not panic");
}
