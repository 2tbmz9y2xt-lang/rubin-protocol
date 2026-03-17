use super::*;

#[test]
fn parse_tx_rejects_unsupported_version() {
    let mut tx = minimal_tx_bytes();
    tx[0..4].copy_from_slice(&(TX_WIRE_VERSION + 1).to_le_bytes());

    let err = parse_tx(&tx).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrParse);
}

#[test]
fn parse_tx_minimal_txid_wtxid() {
    let tx_bytes = minimal_tx_bytes();
    let (_tx, txid, wtxid, n) = parse_tx(&tx_bytes).expect("parse");
    assert_eq!(n, tx_bytes.len());

    let want_txid = sha3_256(&tx_bytes[..core_end()]);
    assert_eq!(txid, want_txid);
    let want_wtxid = sha3_256(&tx_bytes);
    assert_eq!(wtxid, want_wtxid);
}

#[test]
fn parse_tx_nonminimal_compactsize() {
    let mut tx_bytes = minimal_tx_bytes();
    // Replace input_count=0x00 with 0xfd 0x00 0x00 (non-minimal).
    let off_input_count = 4 + 1 + 8;
    tx_bytes.splice(off_input_count..off_input_count + 1, [0xfd, 0x00, 0x00]);

    let err = parse_tx(&tx_bytes).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrParse);
}

#[test]
fn parse_tx_script_sig_len_overflow() {
    let mut b = Vec::new();
    b.extend_from_slice(&1u32.to_le_bytes());
    b.push(0x00); // tx_kind
    b.extend_from_slice(&0u64.to_le_bytes());
    b.push(0x01); // input_count
    b.extend_from_slice(&[0u8; 32]); // prev_txid
    b.extend_from_slice(&0u32.to_le_bytes()); // prev_vout
    b.push(0x21); // script_sig_len = 33 (overflow)
    b.extend_from_slice(&0u32.to_le_bytes()); // sequence
    b.push(0x00); // output_count
    b.extend_from_slice(&0u32.to_le_bytes()); // locktime
    b.push(0x00); // witness_count
    b.push(0x00); // da_payload_len

    let err = parse_tx(&b).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrParse);
}

#[test]
fn parse_tx_covenant_data_len_exceeds_cap() {
    let mut b = Vec::new();
    b.extend_from_slice(&1u32.to_le_bytes()); // version
    b.push(0x00); // tx_kind
    b.extend_from_slice(&0u64.to_le_bytes()); // tx_nonce
    crate::compactsize::encode_compact_size(0, &mut b); // input_count

    crate::compactsize::encode_compact_size(1, &mut b); // output_count
    b.extend_from_slice(&0u64.to_le_bytes()); // value
    b.extend_from_slice(&0u16.to_le_bytes()); // covenant_type
    crate::compactsize::encode_compact_size(MAX_COVENANT_DATA_PER_OUTPUT + 1, &mut b); // covenant_data_len

    b.extend_from_slice(&0u32.to_le_bytes()); // locktime
    crate::compactsize::encode_compact_size(0, &mut b); // witness_count
    crate::compactsize::encode_compact_size(0, &mut b); // da_payload_len

    let err = parse_tx(&b).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrParse);
}

#[test]
fn parse_tx_witness_count_overflow() {
    let mut tx_bytes = minimal_tx_bytes();
    // Replace witness_count=0x00 with CompactSize(1025) = 0xfd 0x01 0x04.
    let off_witness_count = core_end();
    tx_bytes.splice(off_witness_count..off_witness_count + 1, [0xfd, 0x01, 0x04]);

    let err = parse_tx(&tx_bytes).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrWitnessOverflow);
}

#[test]
fn parse_tx_witness_item_canonicalization() {
    // Start from a minimal tx and overwrite the witness section.
    let mut base = minimal_tx_bytes();
    base.truncate(core_end());

    // sentinel_noncanonical: witness_count=1, suite=0, pubkey_length=1, pubkey=0x00, sig_length=0.
    let mut tx1 = base.clone();
    tx1.push(0x01); // witness_count
    tx1.push(SUITE_ID_SENTINEL);
    tx1.push(0x01); // pubkey_length
    tx1.push(0x00); // pubkey
    tx1.push(0x00); // sig_length
    tx1.push(0x00); // da_payload_len
    let err = parse_tx(&tx1).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrParse);

    // sentinel_htlc_refund_selector_ok: suite=0x00, pubkey_length=32, sig_length=1, signature[0]=0x01.
    let mut tx1_ok_refund = base.clone();
    tx1_ok_refund.push(0x01); // witness_count
    tx1_ok_refund.push(SUITE_ID_SENTINEL);
    tx1_ok_refund.push(0x20); // pubkey_length = 32
    tx1_ok_refund.extend_from_slice(&[0u8; 32]);
    tx1_ok_refund.push(0x01); // sig_length = 1
    tx1_ok_refund.push(0x01); // refund path_id
    tx1_ok_refund.push(0x00); // da_payload_len
    parse_tx(&tx1_ok_refund).expect("refund selector should be canonical");

    // sentinel_htlc_claim_selector_ok: suite=0x00, pubkey_length=32, sig_length=19, signature=0x00||u16le(16)||preimage[16].
    let mut tx1_ok_claim = base.clone();
    tx1_ok_claim.push(0x01); // witness_count
    tx1_ok_claim.push(SUITE_ID_SENTINEL);
    tx1_ok_claim.push(0x20); // pubkey_length = 32
    tx1_ok_claim.extend_from_slice(&[0u8; 32]);
    tx1_ok_claim.push(0x13); // sig_length = 19 (1+2+16; Q-A287-03: preimage >= MIN_HTLC_PREIMAGE_BYTES=16)
    tx1_ok_claim.push(0x00); // claim path_id
    tx1_ok_claim.extend_from_slice(&[0x10u8, 0x00u8]); // preimage_len = 16 as u16le
    tx1_ok_claim.extend_from_slice(&[0x11u8; 16]); // preimage (16 bytes)
    tx1_ok_claim.push(0x00); // da_payload_len
    parse_tx(&tx1_ok_claim).expect("claim selector should be canonical");

    // sentinel_htlc_unknown_path_reject: suite=0x00, pubkey_length=32, sig_length=1, signature[0]=0x02.
    let mut tx1_bad_path = base.clone();
    tx1_bad_path.push(0x01); // witness_count
    tx1_bad_path.push(SUITE_ID_SENTINEL);
    tx1_bad_path.push(0x20); // pubkey_length = 32
    tx1_bad_path.extend_from_slice(&[0u8; 32]);
    tx1_bad_path.push(0x01); // sig_length = 1
    tx1_bad_path.push(0x02); // invalid path_id
    tx1_bad_path.push(0x00); // da_payload_len
    let err = parse_tx(&tx1_bad_path).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrParse);

    // unknown_suite: witness_count=1, suite=0x03, pubkey_length=0, sig_length=1 (sighash_type only).
    let mut tx2 = base.clone();
    tx2.push(0x01);
    tx2.push(0x03);
    tx2.push(0x00);
    tx2.push(0x01);
    tx2.push(0x01); // sighash_type
    tx2.push(0x00);
    parse_tx(&tx2).expect("unknown suite_id should be accepted at parse");

    // ml_dsa_selector_reject: suite=0x01, pubkey_length=32, sig_length=0.
    let mut tx2_bad_ml_selector = base.clone();
    tx2_bad_ml_selector.push(0x01); // witness_count
    tx2_bad_ml_selector.push(SUITE_ID_ML_DSA_87);
    tx2_bad_ml_selector.push(0x20); // pubkey_length = 32
    tx2_bad_ml_selector.extend_from_slice(&[0u8; 32]);
    tx2_bad_ml_selector.push(0x00); // sig_length = 0
    tx2_bad_ml_selector.push(0x00); // da_payload_len
    let err = parse_tx(&tx2_bad_ml_selector).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrParse);

    // ml_dsa_len_mismatch: pubkey_length=2591 (0x0A1F) and canonical sig_length.
    let mut tx3 = base.clone();
    tx3.push(0x01);
    tx3.push(SUITE_ID_ML_DSA_87);
    tx3.extend_from_slice(&[0xfd, 0x1f, 0x0a]); // pubkey_length = 2591
    tx3.extend_from_slice(&vec![0u8; 2591]);
    tx3.extend_from_slice(&[0xfd, 0x14, 0x12]); // sig_length = 4628 (ML-DSA + sighash byte)
    tx3.extend_from_slice(&vec![0u8; 4628]);
    tx3.push(0x00); // da_payload_len
    let err = parse_tx(&tx3).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrSigNoncanonical);

    // unknown_suite_sig_len_zero: parse rejects sig_len=0 for suite_id != 0x00.
    let mut tx4 = base.clone();
    tx4.push(0x01);
    tx4.push(0x02); // non-native / unknown suite
    tx4.push(0x00); // pubkey_length = 0
    tx4.push(0x00); // sig_length = 0
    tx4.push(0x00); // da_payload_len
    let err = parse_tx(&tx4).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrParse);
}

#[test]
fn parse_tx_witness_bytes_overflow() {
    let mut tx = minimal_tx_bytes();
    tx.truncate(core_end());

    tx.push(0x03); // witness_count=3
    for _ in 0..3 {
        tx.push(0x02); // unknown suite_id
        tx.push(0x40); // pubkey_length=64
        tx.extend_from_slice(&[0u8; 64]);
        tx.extend_from_slice(&[0xfd, 0xc1, 0xc2]); // sig_length=49857 (0xC2C1)
        tx.extend_from_slice(&vec![0u8; 49_857]);
    }
    tx.push(0x00); // da_payload_len

    let err = parse_tx(&tx).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrWitnessOverflow);
}

#[test]
fn parse_tx_witness_overflow_precedes_suite_canonicalization() {
    let mut tx = minimal_tx_bytes();
    tx.truncate(core_end());

    tx.push(0x01); // witness_count=1
    tx.push(0x03); // unknown suite_id (accepted by parser; overflow check fires first here)
    tx.push(0x00); // pubkey_length=0
    crate::compactsize::encode_compact_size(100_001, &mut tx); // sig_length
    tx.extend_from_slice(&vec![0u8; 100_001]);
    tx.push(0x00); // da_payload_len

    let err = parse_tx(&tx).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrWitnessOverflow);
}

#[test]
fn parse_tx_unknown_suite_id_accepted() {
    let mut tx = minimal_tx_bytes();
    tx.truncate(core_end());

    tx.push(0x01); // witness_count=1
    tx.push(0x03); // unknown suite_id
    tx.push(0x00); // pubkey_length=0
    tx.push(0x01); // sig_length=1
    tx.push(0x01); // sighash_type (informational only for unknown suites)
    tx.push(0x00); // da_payload_len

    let (t, _txid, _wtxid, _n) = parse_tx(&tx).expect("parse");
    assert_eq!(t.witness.len(), 1);
    assert_eq!(t.witness[0].suite_id, 0x03);
    assert!(t.witness[0].pubkey.is_empty());
    assert_eq!(t.witness[0].signature, vec![0x01]);
}

#[test]
fn parse_tx_da_commit_chunk_count_zero_rejected() {
    let da_id = [0x42u8; 32];
    let payload_commitment = sha3_256(b"payload");
    let tx = da_commit_tx(da_id, 0, payload_commitment, 1);

    let err = parse_tx(&tx).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrParse);
}

#[test]
fn parse_tx_da_chunk_index_out_of_range_rejected() {
    let da_id = [0x43u8; 32];
    let chunk_hash = [0x44u8; 32];
    let tx = da_chunk_tx(da_id, MAX_DA_CHUNK_COUNT as u16, chunk_hash, &[0x00], 2);

    let err = parse_tx(&tx).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrParse);
}

#[test]
fn merkle_root_single_and_two() {
    let tx1 = minimal_tx_bytes();
    let (_t1, txid1, _w1, _n1) = parse_tx(&tx1).expect("tx1");

    let root1 = merkle_root_txids(&[txid1]).expect("root1");
    let mut leaf_preimage = [0u8; 33];
    leaf_preimage[0] = 0x00;
    leaf_preimage[1..].copy_from_slice(&txid1);
    assert_eq!(root1, sha3_256(&leaf_preimage));

    let mut tx2 = minimal_tx_bytes();
    tx2[core_end() - 4] = 0x01; // locktime LSB = 1
    let (_t2, txid2, _w2, _n2) = parse_tx(&tx2).expect("tx2");

    let root2 = merkle_root_txids(&[txid1, txid2]).expect("root2");
    leaf_preimage[1..].copy_from_slice(&txid1);
    let leaf1 = sha3_256(&leaf_preimage);
    leaf_preimage[1..].copy_from_slice(&txid2);
    let leaf2 = sha3_256(&leaf_preimage);
    let mut node_preimage = [0u8; 65];
    node_preimage[0] = 0x01;
    node_preimage[1..33].copy_from_slice(&leaf1);
    node_preimage[33..].copy_from_slice(&leaf2);
    assert_eq!(root2, sha3_256(&node_preimage));
}

#[test]
fn witness_merkle_root_single_uses_zero_coinbase_id() {
    let tx1 = minimal_tx_bytes();
    let (_t1, _txid1, wtxid1, _n1) = parse_tx(&tx1).expect("tx1");

    let root = witness_merkle_root_wtxids(&[wtxid1]).expect("witness root");
    let mut leaf_preimage = [0u8; 33];
    leaf_preimage[0] = 0x02;
    // coinbase id is forced to zero for witness commitment tree
    leaf_preimage[1..].copy_from_slice(&[0u8; 32]);
    assert_eq!(root, sha3_256(&leaf_preimage));
}

#[test]
fn witness_commitment_hash_uses_prefix() {
    let mut root = [0u8; 32];
    root[31] = 0x7a;
    let got = witness_commitment_hash(root);

    let mut preimage = Vec::new();
    preimage.extend_from_slice(b"RUBIN-WITNESS/");
    preimage.extend_from_slice(&root);
    assert_eq!(got, sha3_256(&preimage));
}

#[test]
fn sighash_v1_digest_smoke() {
    let mut b = Vec::new();
    b.extend_from_slice(&1u32.to_le_bytes());
    b.push(0x00); // tx_kind
    b.extend_from_slice(&0u64.to_le_bytes());
    b.push(0x01); // input_count

    let prev_txid = [0x11u8; 32];
    b.extend_from_slice(&prev_txid);
    b.extend_from_slice(&2u32.to_le_bytes()); // prev_vout
    b.push(0x00); // script_sig_len
    b.extend_from_slice(&3u32.to_le_bytes()); // sequence

    b.push(0x00); // output_count
    b.extend_from_slice(&4u32.to_le_bytes()); // locktime
    b.push(0x00); // witness_count
    b.push(0x00); // da_payload_len

    let (tx, _txid, _wtxid, _n) = parse_tx(&b).expect("parse");

    let mut chain_id = [0u8; 32];
    chain_id[31] = 0x01;
    let digest = sighash_v1_digest(&tx, 0, 5, chain_id).expect("digest");

    let hash_of_da_core_fields = sha3_256(&[]);
    let mut prevouts = Vec::new();
    prevouts.extend_from_slice(&prev_txid);
    prevouts.extend_from_slice(&2u32.to_le_bytes());
    let hash_of_all_prevouts = sha3_256(&prevouts);
    let hash_of_all_sequences = sha3_256(&3u32.to_le_bytes());
    let hash_of_all_outputs = sha3_256(&[]);

    let mut preimage = Vec::new();
    preimage.extend_from_slice(b"RUBINv1-sighash/");
    preimage.extend_from_slice(&chain_id);
    preimage.extend_from_slice(&1u32.to_le_bytes());
    preimage.push(0x00);
    preimage.extend_from_slice(&0u64.to_le_bytes());
    preimage.extend_from_slice(&hash_of_da_core_fields);
    preimage.extend_from_slice(&hash_of_all_prevouts);
    preimage.extend_from_slice(&hash_of_all_sequences);
    preimage.extend_from_slice(&0u32.to_le_bytes());
    preimage.extend_from_slice(&prev_txid);
    preimage.extend_from_slice(&2u32.to_le_bytes());
    preimage.extend_from_slice(&5u64.to_le_bytes());
    preimage.extend_from_slice(&3u32.to_le_bytes());
    preimage.extend_from_slice(&hash_of_all_outputs);
    preimage.extend_from_slice(&4u32.to_le_bytes());
    preimage.push(SIGHASH_ALL);

    let want = sha3_256(&preimage);
    assert_eq!(digest, want);
}

#[test]
fn retarget_v1_vectors() {
    let target_old = hex32("0000000000000000000000000000000000000000000000000000000000001234");
    let t_expected = TARGET_BLOCK_INTERVAL * WINDOW_SIZE;
    let got = retarget_v1(target_old, 100, 100 + t_expected).expect("retarget");
    assert_eq!(got, target_old);

    let target_old = hex32("0000000000000000000000000000000000000000000000000000000000001000"); // 4096
    let got = retarget_v1(target_old, 200, 200).expect("retarget"); // T_actual <= 0 => 1
    let want = hex32("0000000000000000000000000000000000000000000000000000000000000400"); // 1024
    assert_eq!(got, want);

    let got = retarget_v1(target_old, 0, 10 * t_expected).expect("retarget");
    let want = hex32("0000000000000000000000000000000000000000000000000000000000004000"); // 16384
    assert_eq!(got, want);

    let got = retarget_v1(POW_LIMIT, 0, 10 * t_expected).expect("retarget");
    assert_eq!(got, POW_LIMIT);

    let target_old = hex32("0000000000000000000000000000000000000000000000000000000000001000");
    let mut window = vec![0u64; WINDOW_SIZE as usize];
    for i in 1..window.len() {
        window[i] = window[i - 1] + TARGET_BLOCK_INTERVAL;
    }
    let last = window.len() - 1;
    let prev = window[last - 1];
    window[last] = prev + 1_000_000;
    let got = retarget_v1_clamped(target_old, &window).expect("retarget clamped");
    let want = hex32("0000000000000000000000000000000000000000000000000000000000001003");
    assert_eq!(got, want);

    let err = retarget_v1_clamped(target_old, &[0u64, 120u64]).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrParse);
}

#[test]
fn pow_check_strict_less() {
    let mut header = vec![0u8; BLOCK_HEADER_BYTES];
    header[0] = 1;
    let h = block_hash(&header).expect("hash");

    // target == hash => invalid (strict less required)
    let err = pow_check(&header, h).unwrap_err();
    assert_eq!(err.code, ErrorCode::BlockErrPowInvalid);

    // target = hash + 1 => valid (unless hash is max, which is practically impossible)
    let mut bi = BigUint::from_bytes_be(&h);
    bi += BigUint::one();
    let target1 = biguint_to_bytes32(&bi);
    pow_check(&header, target1).expect("pow ok");

    let zero_target = [0u8; 32];
    let err = pow_check(&header, zero_target).unwrap_err();
    assert_eq!(err.code, ErrorCode::BlockErrTargetInvalid);
}
