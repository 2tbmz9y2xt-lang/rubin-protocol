use super::*;

#[test]
fn parse_block_bytes_ok() {
    let tx = minimal_tx_bytes();
    let (_t, txid, _w, _n) = parse_tx(&tx).expect("tx");
    let root = merkle_root_txids(&[txid]).expect("root");
    let mut prev = [0u8; 32];
    prev[0] = 0x11;
    let target = [0xffu8; 32];
    let block = build_block_bytes(prev, root, target, 7, &[tx]);

    let parsed = parse_block_bytes(&block).expect("parse_block");
    assert_eq!(parsed.tx_count, 1);
    assert_eq!(parsed.txs.len(), 1);
    assert_eq!(parsed.txids.len(), 1);
}

#[test]
fn validate_block_basic_ok() {
    let tx = coinbase_with_witness_commitment(0, &[]);
    let (_t, txid, _w, _n) = parse_tx(&tx).expect("tx");
    let root = merkle_root_txids(&[txid]).expect("root");
    let mut prev = [0u8; 32];
    prev[0] = 0x22;
    let target = [0xffu8; 32];
    let block = build_block_bytes(prev, root, target, 9, &[tx]);

    let s = validate_block_basic(&block, Some(prev), Some(target)).expect("validate");
    assert_eq!(s.tx_count, 1);
}

#[test]
fn validate_block_basic_subsidy_exceeded() {
    let height = 1u64;
    let already_generated = 0u128;
    let sum_fees = 0u64;

    let subsidy = crate::subsidy::block_subsidy(height, already_generated);
    let tx = coinbase_with_witness_commitment_and_p2pk_value(height as u32, subsidy + 1, &[]);
    let (_t, txid, _w, _n) = parse_tx(&tx).expect("tx");
    let root = merkle_root_txids(&[txid]).expect("root");
    let mut prev = [0u8; 32];
    prev[0] = 0x9b;
    let target = [0xffu8; 32];
    let block = build_block_bytes(prev, root, target, 33, &[tx]);

    let err = validate_block_basic_with_context_and_fees_at_height(
        &block,
        Some(prev),
        Some(target),
        height,
        None,
        already_generated,
        sum_fees,
    )
    .unwrap_err();
    assert_eq!(err.code, ErrorCode::BlockErrSubsidyExceeded);
}

#[test]
fn validate_block_basic_subsidy_exceeded_coinbase_sum_uses_u128() {
    let height = 1u64;
    let already_generated = 0u128;
    let sum_fees = 0u64;

    let wtxids = [[0u8; 32]];
    let wroot = witness_merkle_root_wtxids(&wtxids).expect("witness merkle root");
    let commit = witness_commitment_hash(wroot);

    let tx = coinbase_tx_with_outputs(
        height as u32,
        &[
            TestOutput {
                value: u64::MAX,
                covenant_type: COV_TYPE_P2PK,
                covenant_data: valid_p2pk_covenant_data(),
            },
            TestOutput {
                value: u64::MAX,
                covenant_type: COV_TYPE_P2PK,
                covenant_data: valid_p2pk_covenant_data(),
            },
            TestOutput {
                value: 0,
                covenant_type: COV_TYPE_ANCHOR,
                covenant_data: commit.to_vec(),
            },
        ],
    );

    let (_t, txid, _w, _n) = parse_tx(&tx).expect("tx");
    let root = merkle_root_txids(&[txid]).expect("root");
    let mut prev = [0u8; 32];
    prev[0] = 0x9d;
    let target = [0xffu8; 32];
    let block = build_block_bytes(prev, root, target, 35, &[tx]);

    let err = validate_block_basic_with_context_and_fees_at_height(
        &block,
        Some(prev),
        Some(target),
        height,
        None,
        already_generated,
        sum_fees,
    )
    .unwrap_err();
    assert_eq!(err.code, ErrorCode::BlockErrSubsidyExceeded);
}

#[test]
fn validate_block_basic_subsidy_with_fees_ok() {
    let height = 1u64;
    let already_generated = 0u128;
    let sum_fees = 5u64;

    let subsidy = crate::subsidy::block_subsidy(height, already_generated);
    let tx =
        coinbase_with_witness_commitment_and_p2pk_value(height as u32, subsidy + sum_fees, &[]);
    let (_t, txid, _w, _n) = parse_tx(&tx).expect("tx");
    let root = merkle_root_txids(&[txid]).expect("root");
    let mut prev = [0u8; 32];
    prev[0] = 0x9c;
    let target = [0xffu8; 32];
    let block = build_block_bytes(prev, root, target, 34, &[tx]);

    let s = validate_block_basic_with_context_and_fees_at_height(
        &block,
        Some(prev),
        Some(target),
        height,
        None,
        already_generated,
        sum_fees,
    )
    .expect("validate");
    assert_eq!(s.tx_count, 1);
}

#[test]
fn validate_block_basic_linkage_mismatch() {
    let tx = minimal_tx_bytes();
    let (_t, txid, _w, _n) = parse_tx(&tx).expect("tx");
    let root = merkle_root_txids(&[txid]).expect("root");
    let mut prev = [0u8; 32];
    prev[0] = 0x33;
    let target = [0xffu8; 32];
    let block = build_block_bytes(prev, root, target, 11, &[tx]);
    let mut wrong_prev = [0u8; 32];
    wrong_prev[0] = 0x99;

    let err = validate_block_basic(&block, Some(wrong_prev), Some(target)).unwrap_err();
    assert_eq!(err.code, ErrorCode::BlockErrLinkageInvalid);
}

#[test]
fn validate_block_basic_merkle_mismatch() {
    let tx = minimal_tx_bytes();
    let (_t, txid, _w, _n) = parse_tx(&tx).expect("tx");
    let mut root = merkle_root_txids(&[txid]).expect("root");
    root[0] ^= 0xff;
    let mut prev = [0u8; 32];
    prev[0] = 0x44;
    let target = [0xffu8; 32];
    let block = build_block_bytes(prev, root, target, 13, &[tx]);

    let err = validate_block_basic(&block, Some(prev), Some(target)).unwrap_err();
    assert_eq!(err.code, ErrorCode::BlockErrMerkleInvalid);
}

#[test]
fn validate_block_basic_pow_invalid() {
    let tx = minimal_tx_bytes();
    let (_t, txid, _w, _n) = parse_tx(&tx).expect("tx");
    let root = merkle_root_txids(&[txid]).expect("root");
    let mut prev = [0u8; 32];
    prev[0] = 0x55;
    let mut tiny_target = [0u8; 32];
    tiny_target[31] = 0x01;
    let block = build_block_bytes(prev, root, tiny_target, 15, &[tx]);

    let err = validate_block_basic(&block, Some(prev), Some(tiny_target)).unwrap_err();
    assert_eq!(err.code, ErrorCode::BlockErrPowInvalid);
}

#[test]
fn validate_block_basic_target_range_invalid() {
    let tx = minimal_tx_bytes();
    let (_t, txid, _w, _n) = parse_tx(&tx).expect("tx");
    let root = merkle_root_txids(&[txid]).expect("root");
    let mut prev = [0u8; 32];
    prev[0] = 0x56;
    let zero_target = [0u8; 32];
    let block = build_block_bytes(prev, root, zero_target, 15, &[tx]);

    let err = validate_block_basic(&block, Some(prev), Some(zero_target)).unwrap_err();
    assert_eq!(err.code, ErrorCode::BlockErrTargetInvalid);
}

#[test]
fn validate_block_basic_target_mismatch() {
    let tx = minimal_tx_bytes();
    let (_t, txid, _w, _n) = parse_tx(&tx).expect("tx");
    let root = merkle_root_txids(&[txid]).expect("root");
    let mut prev = [0u8; 32];
    prev[0] = 0x66;
    let target = [0xffu8; 32];
    let block = build_block_bytes(prev, root, target, 17, &[tx]);
    let wrong_target = [0xeeu8; 32];

    let err = validate_block_basic(&block, Some(prev), Some(wrong_target)).unwrap_err();
    assert_eq!(err.code, ErrorCode::BlockErrTargetInvalid);
}

#[test]
fn validate_block_basic_order_pow_before_linkage_and_merkle() {
    let tx = minimal_tx_bytes();
    let (_t, txid, _w, _n) = parse_tx(&tx).expect("tx");
    let mut root = merkle_root_txids(&[txid]).expect("root");
    root[0] ^= 0xff; // force merkle mismatch
    let mut prev = [0u8; 32];
    prev[0] = 0x6a;
    let mut tiny_target = [0u8; 32];
    tiny_target[31] = 0x01; // almost surely POW-invalid
    let block = build_block_bytes(prev, root, tiny_target, 21, &[tx]);
    let mut wrong_prev = [0u8; 32];
    wrong_prev[0] = 0x6b; // force linkage mismatch

    let err = validate_block_basic(&block, Some(wrong_prev), Some(tiny_target)).unwrap_err();
    assert_eq!(err.code, ErrorCode::BlockErrPowInvalid);
}

#[test]
fn validate_block_basic_order_target_before_linkage_and_merkle() {
    let tx = minimal_tx_bytes();
    let (_t, txid, _w, _n) = parse_tx(&tx).expect("tx");
    let mut root = merkle_root_txids(&[txid]).expect("root");
    root[0] ^= 0xff; // force merkle mismatch
    let mut prev = [0u8; 32];
    prev[0] = 0x6c;
    let target = [0xffu8; 32];
    let block = build_block_bytes(prev, root, target, 23, &[tx]);
    let mut wrong_prev = [0u8; 32];
    wrong_prev[0] = 0x6d; // force linkage mismatch
    let wrong_target = [0xeeu8; 32]; // force target mismatch

    let err = validate_block_basic(&block, Some(wrong_prev), Some(wrong_target)).unwrap_err();
    assert_eq!(err.code, ErrorCode::BlockErrTargetInvalid);
}

#[test]
fn parse_block_bytes_trailing_bytes() {
    let tx = minimal_tx_bytes();
    let (_t, txid, _w, _n) = parse_tx(&tx).expect("tx");
    let root = merkle_root_txids(&[txid]).expect("root");
    let mut prev = [0u8; 32];
    prev[0] = 0x77;
    let target = [0xffu8; 32];
    let mut block = build_block_bytes(prev, root, target, 19, &[tx]);
    block.push(0x00);

    let err = parse_block_bytes(&block).unwrap_err();
    assert_eq!(err.code, ErrorCode::BlockErrParse);
}

#[test]
fn validate_block_basic_covenant_invalid() {
    let tx = coinbase_tx_with_outputs(
        0,
        &[TestOutput {
            value: 1,
            covenant_type: COV_TYPE_ANCHOR,
            covenant_data: vec![0x01],
        }],
    );
    let (_t, txid, _w, _n) = parse_tx(&tx).expect("tx");
    let root = merkle_root_txids(&[txid]).expect("root");
    let mut prev = [0u8; 32];
    prev[0] = 0x88;
    let target = [0xffu8; 32];
    let block = build_block_bytes(prev, root, target, 21, &[tx]);

    let err = validate_block_basic(&block, Some(prev), Some(target)).unwrap_err();
    assert_eq!(err.code, ErrorCode::BlockErrWitnessCommitment);
}

#[test]
fn validate_block_basic_non_coinbase_must_have_input() {
    let invalid_non_coinbase = tx_with_one_output(1, COV_TYPE_P2PK, &valid_p2pk_covenant_data());
    let coinbase = coinbase_with_witness_commitment(0, std::slice::from_ref(&invalid_non_coinbase));

    let (_t1, txid1, _w1, _n1) = parse_tx(&coinbase).expect("coinbase");
    let (_t2, txid2, _w2, _n2) = parse_tx(&invalid_non_coinbase).expect("noncoinbase");
    let root = merkle_root_txids(&[txid1, txid2]).expect("root");
    let mut prev = [0u8; 32];
    prev[0] = 0x89;
    let target = [0xffu8; 32];
    let block = build_block_bytes(prev, root, target, 23, &[coinbase, invalid_non_coinbase]);

    let err = validate_block_basic(&block, Some(prev), Some(target)).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrParse);
}

fn repeated_anchor_outputs(count: usize, payload_len: usize) -> Vec<TestOutput> {
    (0..count)
        .map(|i| TestOutput {
            value: 0,
            covenant_type: COV_TYPE_ANCHOR,
            covenant_data: vec![0x40u8.wrapping_add((i % 127) as u8); payload_len],
        })
        .collect()
}

#[test]
fn validate_block_basic_anchor_bytes_precede_nonce_replay() {
    let oversized_anchor_tx = tx_with_nonce_and_outputs(1, &repeated_anchor_outputs(3, 50_000));
    let duplicate_nonce_tx = tx_with_nonce_and_outputs(
        1,
        &[TestOutput {
            value: 1,
            covenant_type: COV_TYPE_P2PK,
            covenant_data: valid_p2pk_covenant_data(),
        }],
    );
    let coinbase = coinbase_with_witness_commitment(
        1,
        &[oversized_anchor_tx.clone(), duplicate_nonce_tx.clone()],
    );

    let (_cb, cbid, _cw, _cn) = parse_tx(&coinbase).expect("parse coinbase");
    let (_t1, tx1id, _w1, _n1) = parse_tx(&oversized_anchor_tx).expect("parse tx1");
    let (_t2, tx2id, _w2, _n2) = parse_tx(&duplicate_nonce_tx).expect("parse tx2");
    let root = merkle_root_txids(&[cbid, tx1id, tx2id]).expect("root");

    let mut prev = [0u8; 32];
    prev[0] = 0xa1;
    let target = [0xffu8; 32];
    let block = build_block_bytes(
        prev,
        root,
        target,
        41,
        &[coinbase, oversized_anchor_tx, duplicate_nonce_tx],
    );

    let err = validate_block_basic_at_height(&block, Some(prev), Some(target), 1).unwrap_err();
    assert_eq!(err.code, ErrorCode::BlockErrAnchorBytesExceeded);
}

#[test]
fn validate_block_basic_weight_precedes_nonce_replay() {
    let overweight_tx = tx_with_nonce_and_outputs(1, &repeated_anchor_outputs(1024, 17_000));
    let duplicate_nonce_tx = tx_with_nonce_and_outputs(
        1,
        &[TestOutput {
            value: 1,
            covenant_type: COV_TYPE_P2PK,
            covenant_data: valid_p2pk_covenant_data(),
        }],
    );
    let coinbase =
        coinbase_with_witness_commitment(1, &[overweight_tx.clone(), duplicate_nonce_tx.clone()]);

    let (_cb, cbid, _cw, _cn) = parse_tx(&coinbase).expect("parse coinbase");
    let (_t1, tx1id, _w1, _n1) = parse_tx(&overweight_tx).expect("parse tx1");
    let (_t2, tx2id, _w2, _n2) = parse_tx(&duplicate_nonce_tx).expect("parse tx2");
    let root = merkle_root_txids(&[cbid, tx1id, tx2id]).expect("root");

    let mut prev = [0u8; 32];
    prev[0] = 0xa2;
    let target = [0xffu8; 32];
    let block = build_block_bytes(
        prev,
        root,
        target,
        42,
        &[coinbase, overweight_tx, duplicate_nonce_tx],
    );

    let err = validate_block_basic_at_height(&block, Some(prev), Some(target), 1).unwrap_err();
    assert_eq!(err.code, ErrorCode::BlockErrWeightExceeded);
}

#[test]
fn validate_block_basic_anchor_bytes_precede_coinbase_structure() {
    let oversized_anchor_tx = tx_with_nonce_and_outputs(1, &repeated_anchor_outputs(3, 50_000));
    let coinbase = coinbase_with_witness_commitment(0, std::slice::from_ref(&oversized_anchor_tx));

    let (_cb, cbid, _cw, _cn) = parse_tx(&coinbase).expect("parse coinbase");
    let (_tx, txid, _w, _n) = parse_tx(&oversized_anchor_tx).expect("parse tx");
    let root = merkle_root_txids(&[cbid, txid]).expect("root");

    let mut prev = [0u8; 32];
    prev[0] = 0xa3;
    let target = [0xffu8; 32];
    let block = build_block_bytes(prev, root, target, 43, &[coinbase, oversized_anchor_tx]);

    let err = validate_block_basic_at_height(&block, Some(prev), Some(target), 1).unwrap_err();
    assert_eq!(err.code, ErrorCode::BlockErrAnchorBytesExceeded);
}

#[test]
fn validate_block_basic_first_tx_must_be_coinbase() {
    let tx = minimal_tx_bytes();
    let (_t, txid, _w, _n) = parse_tx(&tx).expect("tx");
    let root = merkle_root_txids(&[txid]).expect("root");
    let mut prev = [0u8; 32];
    prev[0] = 0x8a;
    let target = [0xffu8; 32];
    let block = build_block_bytes(prev, root, target, 24, &[tx]);

    let err = validate_block_basic(&block, Some(prev), Some(target)).unwrap_err();
    assert_eq!(err.code, ErrorCode::BlockErrWitnessCommitment);
}

#[test]
fn validate_block_basic_coinbase_locktime_must_match_height() {
    let height = 5u64;
    let tx = coinbase_with_witness_commitment(0, &[]);
    let (_t, txid, _w, _n) = parse_tx(&tx).expect("tx");
    let root = merkle_root_txids(&[txid]).expect("root");
    let mut prev = [0u8; 32];
    prev[0] = 0x8b;
    let target = [0xffu8; 32];
    let block = build_block_bytes(prev, root, target, 24, &[tx]);

    let err = validate_block_basic_at_height(&block, Some(prev), Some(target), height).unwrap_err();
    assert_eq!(err.code, ErrorCode::BlockErrCoinbaseInvalid);
}

#[test]
fn validate_block_basic_coinbase_like_tx_forbidden_after_index_zero() {
    let coinbase_like = coinbase_tx_with_outputs(
        0,
        &[TestOutput {
            value: 1,
            covenant_type: COV_TYPE_P2PK,
            covenant_data: valid_p2pk_covenant_data(),
        }],
    );
    let coinbase = coinbase_with_witness_commitment(0, std::slice::from_ref(&coinbase_like));

    let (_t1, txid1, _w1, _n1) = parse_tx(&coinbase).expect("coinbase");
    let (_t2, txid2, _w2, _n2) = parse_tx(&coinbase_like).expect("coinbase-like");
    let root = merkle_root_txids(&[txid1, txid2]).expect("root");
    let mut prev = [0u8; 32];
    prev[0] = 0x8c;
    let target = [0xffu8; 32];
    let block = build_block_bytes(prev, root, target, 24, &[coinbase, coinbase_like]);

    let err = validate_block_basic(&block, Some(prev), Some(target)).unwrap_err();
    assert_eq!(err.code, ErrorCode::BlockErrCoinbaseInvalid);
}

#[test]
fn validate_block_basic_witness_commitment_missing() {
    let tx = coinbase_tx_with_outputs(
        0,
        &[TestOutput {
            value: 1,
            covenant_type: COV_TYPE_P2PK,
            covenant_data: valid_p2pk_covenant_data(),
        }],
    );
    let (_t, txid, _w, _n) = parse_tx(&tx).expect("tx");
    let root = merkle_root_txids(&[txid]).expect("root");
    let mut prev = [0u8; 32];
    prev[0] = 0x90;
    let target = [0xffu8; 32];
    let block = build_block_bytes(prev, root, target, 25, &[tx]);

    let err = validate_block_basic(&block, Some(prev), Some(target)).unwrap_err();
    assert_eq!(err.code, ErrorCode::BlockErrWitnessCommitment);
}

#[test]
fn validate_block_basic_witness_commitment_duplicate() {
    let base_cb = coinbase_with_witness_commitment(0, &[]);
    let (_tx, _txid, wtxid, _n) = parse_tx(&base_cb).expect("parse base coinbase");
    let wroot = witness_merkle_root_wtxids(&[wtxid]).expect("wroot");
    let commit = witness_commitment_hash(wroot);
    let tx = coinbase_tx_with_outputs(
        0,
        &[
            TestOutput {
                value: 0,
                covenant_type: COV_TYPE_ANCHOR,
                covenant_data: commit.to_vec(),
            },
            TestOutput {
                value: 0,
                covenant_type: COV_TYPE_ANCHOR,
                covenant_data: commit.to_vec(),
            },
        ],
    );

    let (_t, txid, _w, _n) = parse_tx(&tx).expect("tx");
    let root = merkle_root_txids(&[txid]).expect("root");
    let mut prev = [0u8; 32];
    prev[0] = 0x91;
    let target = [0xffu8; 32];
    let block = build_block_bytes(prev, root, target, 27, &[tx]);

    let err = validate_block_basic(&block, Some(prev), Some(target)).unwrap_err();
    assert_eq!(err.code, ErrorCode::BlockErrWitnessCommitment);
}

#[test]
fn validate_block_basic_da_chunk_hash_mismatch() {
    let da_id = [0x51u8; 32];
    let da_payload = b"chunk payload".to_vec();
    let payload_commitment = sha3_256(&da_payload);
    let mut bad_chunk_hash = sha3_256(&da_payload);
    bad_chunk_hash[0] ^= 0x01;

    let da_commit = da_commit_tx(da_id, 1, payload_commitment, 1);
    let da_chunk = da_chunk_tx(da_id, 0, bad_chunk_hash, &da_payload, 2);
    let coinbase = coinbase_with_witness_commitment(0, &[da_commit.clone(), da_chunk.clone()]);

    let (_t1, txid1, _w1, _n1) = parse_tx(&coinbase).expect("coinbase");
    let (_t2, txid2, _w2, _n2) = parse_tx(&da_commit).expect("da_commit");
    let (_t3, txid3, _w3, _n3) = parse_tx(&da_chunk).expect("da_chunk");
    let root = merkle_root_txids(&[txid1, txid2, txid3]).expect("root");
    let mut prev = [0u8; 32];
    prev[0] = 0x93;
    let target = [0xffu8; 32];
    let block = build_block_bytes(prev, root, target, 37, &[coinbase, da_commit, da_chunk]);

    let err = validate_block_basic(&block, Some(prev), Some(target)).unwrap_err();
    assert_eq!(err.code, ErrorCode::BlockErrDaChunkHashInvalid);
}

#[test]
fn validate_block_basic_da_payload_commitment_mismatch() {
    let da_id = [0x52u8; 32];
    let da_payload = b"payload for commitment".to_vec();
    let chunk_hash = sha3_256(&da_payload);
    let payload_commitment = sha3_256(b"different payload");

    let da_commit = da_commit_tx(da_id, 1, payload_commitment, 3);
    let da_chunk = da_chunk_tx(da_id, 0, chunk_hash, &da_payload, 4);
    let coinbase = coinbase_with_witness_commitment(0, &[da_commit.clone(), da_chunk.clone()]);

    let (_t1, txid1, _w1, _n1) = parse_tx(&coinbase).expect("coinbase");
    let (_t2, txid2, _w2, _n2) = parse_tx(&da_commit).expect("da_commit");
    let (_t3, txid3, _w3, _n3) = parse_tx(&da_chunk).expect("da_chunk");
    let root = merkle_root_txids(&[txid1, txid2, txid3]).expect("root");
    let mut prev = [0u8; 32];
    prev[0] = 0x94;
    let target = [0xffu8; 32];
    let block = build_block_bytes(prev, root, target, 39, &[coinbase, da_commit, da_chunk]);

    let err = validate_block_basic(&block, Some(prev), Some(target)).unwrap_err();
    assert_eq!(err.code, ErrorCode::BlockErrDaPayloadCommitInvalid);
}

#[test]
fn validate_block_basic_da_caps_before_integrity_checks() {
    let da_id = [0x53u8; 32];
    let da_payload = vec![0x55; CHUNK_BYTES as usize];
    let payload_commitment = sha3_256(&da_payload);
    let mut bad_chunk_hash = sha3_256(&da_payload);
    bad_chunk_hash[0] ^= 0x01; // force chunk hash mismatch

    let da_commit = da_commit_tx(da_id, 1, payload_commitment, 5);
    let da_chunk = da_chunk_tx_with_anchor_outputs(
        da_id,
        0,
        bad_chunk_hash,
        &da_payload,
        6,
        3,
        MAX_ANCHOR_PAYLOAD_SIZE as usize,
    );
    let coinbase = coinbase_with_witness_commitment(0, &[da_commit.clone(), da_chunk.clone()]);

    let (_t1, txid1, _w1, _n1) = parse_tx(&coinbase).expect("coinbase");
    let (_t2, txid2, _w2, _n2) = parse_tx(&da_commit).expect("da_commit");
    let (_t3, txid3, _w3, _n3) = parse_tx(&da_chunk).expect("da_chunk");
    let root = merkle_root_txids(&[txid1, txid2, txid3]).expect("root");
    let mut prev = [0u8; 32];
    prev[0] = 0x95;
    let target = [0xffu8; 32];
    let block = build_block_bytes(prev, root, target, 41, &[coinbase, da_commit, da_chunk]);

    let err = validate_block_basic(&block, Some(prev), Some(target)).unwrap_err();
    assert_eq!(err.code, ErrorCode::BlockErrAnchorBytesExceeded);
}

#[test]
fn validate_block_basic_da_completeness_priority_over_payload_mismatch() {
    let da_incomplete = [0x54u8; 32];
    let da_payload_mismatch = [0x55u8; 32];

    // Set A: commit without chunks -> BLOCK_ERR_DA_INCOMPLETE
    let commit_incomplete = da_commit_tx(da_incomplete, 1, [0x21u8; 32], 7);

    // Set B: complete chunk set but wrong payload commitment.
    let payload = b"payload-b".to_vec();
    let bad_commitment = sha3_256(b"different-payload-b");
    let commit_mismatch = da_commit_tx(da_payload_mismatch, 1, bad_commitment, 8);
    let chunk_mismatch = da_chunk_tx(da_payload_mismatch, 0, sha3_256(&payload), &payload, 9);
    let coinbase = coinbase_with_witness_commitment(
        0,
        &[
            commit_incomplete.clone(),
            commit_mismatch.clone(),
            chunk_mismatch.clone(),
        ],
    );

    let (_t1, txid1, _w1, _n1) = parse_tx(&coinbase).expect("coinbase");
    let (_t2, txid2, _w2, _n2) = parse_tx(&commit_incomplete).expect("commit_incomplete");
    let (_t3, txid3, _w3, _n3) = parse_tx(&commit_mismatch).expect("commit_mismatch");
    let (_t4, txid4, _w4, _n4) = parse_tx(&chunk_mismatch).expect("chunk_mismatch");
    let root = merkle_root_txids(&[txid1, txid2, txid3, txid4]).expect("root");
    let mut prev = [0u8; 32];
    prev[0] = 0x96;
    let target = [0xffu8; 32];
    let block = build_block_bytes(
        prev,
        root,
        target,
        43,
        &[coinbase, commit_incomplete, commit_mismatch, chunk_mismatch],
    );

    let err = validate_block_basic(&block, Some(prev), Some(target)).unwrap_err();
    assert_eq!(err.code, ErrorCode::BlockErrDaIncomplete);
}

#[test]
fn verify_sig_rejects_wrong_mldsa_lengths_before_openssl() {
    let digest = [0u8; 32];
    let ok = crate::verify_sig_openssl::verify_sig(
        SUITE_ID_ML_DSA_87,
        &vec![0u8; (ML_DSA_87_PUBKEY_BYTES as usize) - 1],
        &vec![0u8; ML_DSA_87_SIG_BYTES as usize],
        &digest,
    )
    .expect("verify_sig should not return transport error for length mismatch");
    assert!(!ok);
}

#[test]
fn verify_sig_unsupported_suite_rejected_sig_alg_invalid() {
    let digest = [0u8; 32];
    let err = crate::verify_sig_openssl::verify_sig(0x02, &[0x01], &[0x02], &digest).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrSigAlgInvalid);
}

#[test]
fn verify_sig_parallel_mldsa_deterministic() {
    let kp = match test_mldsa87_keypair() {
        Some(v) => v,
        None => return,
    };

    let mut digest = [0u8; 32];
    digest[0] = 0x42;
    digest[31] = 0xa5;
    let mut invalid_digest = digest;
    invalid_digest[0] ^= 0x01;

    let signature = unsafe {
        let mctx = EVP_MD_CTX_new();
        assert!(!mctx.is_null(), "EVP_MD_CTX_new failed");
        assert!(
            EVP_DigestSignInit_ex(
                mctx,
                core::ptr::null_mut(),
                core::ptr::null(),
                core::ptr::null_mut(),
                core::ptr::null(),
                kp.pkey,
                core::ptr::null(),
            ) > 0,
            "EVP_DigestSignInit_ex failed"
        );
        let mut sig = vec![0u8; ML_DSA_87_SIG_BYTES as usize];
        let mut sig_len: usize = sig.len();
        assert!(
            EVP_DigestSign(
                mctx,
                sig.as_mut_ptr(),
                &mut sig_len,
                digest.as_ptr(),
                digest.len(),
            ) > 0,
            "EVP_DigestSign failed"
        );
        EVP_MD_CTX_free(mctx);
        assert_eq!(sig_len, ML_DSA_87_SIG_BYTES as usize);
        sig
    };
    let pubkey = kp.pubkey.clone();
    drop(kp);

    let workers = std::thread::available_parallelism()
        .map(|v| v.get().saturating_mul(2))
        .unwrap_or(4)
        .max(4);
    let loops_per_worker = 200usize;

    let mut handles = Vec::with_capacity(workers);
    for _ in 0..workers {
        let pubkey_local = pubkey.clone();
        let signature_local = signature.clone();
        let digest_local = digest;
        let invalid_digest_local = invalid_digest;
        handles.push(std::thread::spawn(move || {
            for _ in 0..loops_per_worker {
                let ok = crate::verify_sig_openssl::verify_sig(
                    SUITE_ID_ML_DSA_87,
                    &pubkey_local,
                    &signature_local,
                    &digest_local,
                )
                .expect("verify_sig valid path should not fail");
                assert!(ok, "verify_sig returned false for valid signature");

                let bad = crate::verify_sig_openssl::verify_sig(
                    SUITE_ID_ML_DSA_87,
                    &pubkey_local,
                    &signature_local,
                    &invalid_digest_local,
                )
                .expect("verify_sig invalid path should not fail");
                assert!(!bad, "verify_sig returned true for invalid digest");
            }
        }));
    }

    for handle in handles {
        handle.join().expect("parallel verify worker panicked");
    }
}
