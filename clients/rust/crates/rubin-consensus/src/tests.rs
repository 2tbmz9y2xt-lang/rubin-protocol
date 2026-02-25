use crate::constants::*;
use crate::error::ErrorCode;
use crate::hash::sha3_256;
use crate::merkle::{witness_commitment_hash, witness_merkle_root_wtxids};
use crate::pow::{pow_check, retarget_v1, retarget_v1_clamped};
use crate::sighash_v1_digest;
use crate::{
    apply_non_coinbase_tx_basic, apply_non_coinbase_tx_basic_with_mtp, block_hash,
    merkle_root_txids, parse_block_bytes, parse_tx, validate_block_basic,
    validate_block_basic_at_height, validate_block_basic_with_context_and_fees_at_height,
    validate_tx_covenants_genesis, Outpoint, UtxoEntry, BLOCK_HEADER_BYTES,
};
use num_bigint::BigUint;
use num_traits::One;
use std::collections::HashMap;

fn minimal_tx_bytes() -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&1u32.to_le_bytes());
    b.push(0x00); // tx_kind
    b.extend_from_slice(&0u64.to_le_bytes());
    b.push(0x00); // input_count
    b.push(0x00); // output_count
    b.extend_from_slice(&0u32.to_le_bytes()); // locktime
    b.push(0x00); // witness_count
    b.push(0x00); // da_payload_len
    b
}

fn core_end() -> usize {
    // version(4) + tx_kind(1) + tx_nonce(8) + input_count(1) + output_count(1) + locktime(4)
    4 + 1 + 8 + 1 + 1 + 4
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

    // sentinel_htlc_claim_selector_ok: suite=0x00, pubkey_length=32, sig_length=3, signature=0x00||u16le(0).
    let mut tx1_ok_claim = base.clone();
    tx1_ok_claim.push(0x01); // witness_count
    tx1_ok_claim.push(SUITE_ID_SENTINEL);
    tx1_ok_claim.push(0x20); // pubkey_length = 32
    tx1_ok_claim.extend_from_slice(&[0u8; 32]);
    tx1_ok_claim.push(0x03); // sig_length = 3
    tx1_ok_claim.extend_from_slice(&[0x00, 0x00, 0x00]); // claim path_id + preimage_len=0
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

    // unknown_suite: witness_count=1, suite=0x03, pubkey_length=0, sig_length=0.
    let mut tx2 = base.clone();
    tx2.push(0x01);
    tx2.push(0x03);
    tx2.push(0x00);
    tx2.push(0x00);
    tx2.push(0x00);
    let err = parse_tx(&tx2).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrSigAlgInvalid);

    // ml_dsa_selector_reject: suite=0x01, pubkey_length=32, sig_length=0.
    let mut tx2_bad_ml_selector = base.clone();
    tx2_bad_ml_selector.push(0x01); // witness_count
    tx2_bad_ml_selector.push(SUITE_ID_ML_DSA_87);
    tx2_bad_ml_selector.push(0x20); // pubkey_length = 32
    tx2_bad_ml_selector.extend_from_slice(&[0u8; 32]);
    tx2_bad_ml_selector.push(0x00); // sig_length = 0
    tx2_bad_ml_selector.push(0x00); // da_payload_len
    let err = parse_tx(&tx2_bad_ml_selector).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrSigNoncanonical);

    // ml_dsa_len_mismatch: pubkey_length=2591 (0x0A1F) and canonical sig_length.
    let mut tx3 = base.clone();
    tx3.push(0x01);
    tx3.push(SUITE_ID_ML_DSA_87);
    tx3.extend_from_slice(&[0xfd, 0x1f, 0x0a]); // pubkey_length = 2591
    tx3.extend_from_slice(&vec![0u8; 2591]);
    tx3.extend_from_slice(&[0xfd, 0x13, 0x12]); // sig_length = 4627
    tx3.extend_from_slice(&vec![0u8; 4627]);
    tx3.push(0x00); // da_payload_len
    let err = parse_tx(&tx3).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrSigNoncanonical);

    // slh_dsa_sig_len_zero: pubkey_length=64, sig_length=0.
    let mut tx4 = base.clone();
    tx4.push(0x01);
    tx4.push(SUITE_ID_SLH_DSA_SHAKE_256F);
    tx4.push(0x40); // pubkey_length = 64
    tx4.extend_from_slice(&[0u8; 64]);
    tx4.push(0x00); // sig_length = 0
    tx4.push(0x00); // da_payload_len
    let err = parse_tx(&tx4).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrSigNoncanonical);
}

#[test]
fn parse_tx_witness_bytes_overflow() {
    let mut tx = minimal_tx_bytes();
    tx.truncate(core_end());

    tx.push(0x03); // witness_count=3
    for _ in 0..3 {
        tx.push(SUITE_ID_SLH_DSA_SHAKE_256F);
        tx.push(0x40); // pubkey_length=64
        tx.extend_from_slice(&[0u8; 64]);
        tx.extend_from_slice(&[0xfd, 0xc0, 0xc2]); // sig_length=49856 (0xC2C0)
        tx.extend_from_slice(&vec![0u8; 49_856]);
    }
    tx.push(0x00); // da_payload_len

    let err = parse_tx(&tx).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrWitnessOverflow);
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

fn build_block_bytes(
    prev_hash: [u8; 32],
    merkle_root: [u8; 32],
    target: [u8; 32],
    nonce: u64,
    txs: &[Vec<u8>],
) -> Vec<u8> {
    assert!(!txs.is_empty());
    let mut header = Vec::with_capacity(BLOCK_HEADER_BYTES);
    header.extend_from_slice(&1u32.to_le_bytes()); // version
    header.extend_from_slice(&prev_hash);
    header.extend_from_slice(&merkle_root);
    header.extend_from_slice(&1u64.to_le_bytes()); // timestamp
    header.extend_from_slice(&target);
    header.extend_from_slice(&nonce.to_le_bytes());
    assert_eq!(header.len(), BLOCK_HEADER_BYTES);

    let mut b = header;
    crate::compactsize::encode_compact_size(txs.len() as u64, &mut b);
    for tx in txs {
        b.extend_from_slice(tx);
    }
    b
}

fn tx_with_one_output(value: u64, covenant_type: u16, covenant_data: &[u8]) -> Vec<u8> {
    tx_with_outputs(&[TestOutput {
        value,
        covenant_type,
        covenant_data: covenant_data.to_vec(),
    }])
}

#[derive(Clone)]
struct TestOutput {
    value: u64,
    covenant_type: u16,
    covenant_data: Vec<u8>,
}

fn tx_with_outputs(outputs: &[TestOutput]) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&1u32.to_le_bytes()); // version
    b.push(0x00); // tx_kind
    b.extend_from_slice(&0u64.to_le_bytes()); // tx_nonce
    crate::compactsize::encode_compact_size(0, &mut b); // input_count
    crate::compactsize::encode_compact_size(outputs.len() as u64, &mut b); // output_count
    for out in outputs {
        b.extend_from_slice(&out.value.to_le_bytes());
        b.extend_from_slice(&out.covenant_type.to_le_bytes());
        crate::compactsize::encode_compact_size(out.covenant_data.len() as u64, &mut b);
        b.extend_from_slice(&out.covenant_data);
    }
    b.extend_from_slice(&0u32.to_le_bytes()); // locktime
    crate::compactsize::encode_compact_size(0, &mut b); // witness_count
    crate::compactsize::encode_compact_size(0, &mut b); // da_payload_len
    b
}

fn coinbase_tx_with_outputs(locktime: u32, outputs: &[TestOutput]) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&1u32.to_le_bytes()); // version
    b.push(0x00); // tx_kind
    b.extend_from_slice(&0u64.to_le_bytes()); // tx_nonce
    crate::compactsize::encode_compact_size(1, &mut b); // input_count
    b.extend_from_slice(&[0u8; 32]); // prev_txid
    b.extend_from_slice(&u32::MAX.to_le_bytes()); // prev_vout
    crate::compactsize::encode_compact_size(0, &mut b); // script_sig_len
    b.extend_from_slice(&u32::MAX.to_le_bytes()); // sequence
    crate::compactsize::encode_compact_size(outputs.len() as u64, &mut b); // output_count
    for out in outputs {
        b.extend_from_slice(&out.value.to_le_bytes());
        b.extend_from_slice(&out.covenant_type.to_le_bytes());
        crate::compactsize::encode_compact_size(out.covenant_data.len() as u64, &mut b);
        b.extend_from_slice(&out.covenant_data);
    }
    b.extend_from_slice(&locktime.to_le_bytes());
    crate::compactsize::encode_compact_size(0, &mut b); // witness_count
    crate::compactsize::encode_compact_size(0, &mut b); // da_payload_len
    b
}

fn coinbase_with_witness_commitment(locktime: u32, non_coinbase_txs: &[Vec<u8>]) -> Vec<u8> {
    let mut wtxids: Vec<[u8; 32]> = Vec::with_capacity(1 + non_coinbase_txs.len());
    wtxids.push([0u8; 32]);
    for txb in non_coinbase_txs {
        let (_tx, _txid, wtxid, _n) = parse_tx(txb).expect("parse non-coinbase");
        wtxids.push(wtxid);
    }

    let wroot = witness_merkle_root_wtxids(&wtxids).expect("witness merkle root");
    let commit = witness_commitment_hash(wroot);
    coinbase_tx_with_outputs(
        locktime,
        &[TestOutput {
            value: 0,
            covenant_type: COV_TYPE_ANCHOR,
            covenant_data: commit.to_vec(),
        }],
    )
}

fn coinbase_with_witness_commitment_and_p2pk_value(
    locktime: u32,
    value: u64,
    non_coinbase_txs: &[Vec<u8>],
) -> Vec<u8> {
    let mut wtxids: Vec<[u8; 32]> = Vec::with_capacity(1 + non_coinbase_txs.len());
    wtxids.push([0u8; 32]);
    for txb in non_coinbase_txs {
        let (_tx, _txid, wtxid, _n) = parse_tx(txb).expect("parse non-coinbase");
        wtxids.push(wtxid);
    }

    let wroot = witness_merkle_root_wtxids(&wtxids).expect("witness merkle root");
    let commit = witness_commitment_hash(wroot);
    coinbase_tx_with_outputs(
        locktime,
        &[
            TestOutput {
                value,
                covenant_type: COV_TYPE_P2PK,
                covenant_data: valid_p2pk_covenant_data(),
            },
            TestOutput {
                value: 0,
                covenant_type: COV_TYPE_ANCHOR,
                covenant_data: commit.to_vec(),
            },
        ],
    )
}

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
    let already_generated = 0u64;
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
    let already_generated = 0u64;
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
    let already_generated = 0u64;
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
    assert_eq!(err.code, ErrorCode::TxErrCovenantTypeInvalid);
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
    assert_eq!(err.code, ErrorCode::BlockErrCoinbaseInvalid);
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
fn validate_block_basic_slh_inactive_at_height() {
    let prev_txid = [0xabu8; 32];
    let pubkey = vec![0u8; SLH_DSA_SHAKE_256F_PUBKEY_BYTES as usize];
    let sig = vec![0x01];
    let non_coinbase = tx_with_one_input_one_output_with_witness(
        prev_txid,
        0,
        1,
        COV_TYPE_P2PK,
        &valid_p2pk_covenant_data(),
        SUITE_ID_SLH_DSA_SHAKE_256F,
        &pubkey,
        &sig,
    );
    let coinbase = coinbase_with_witness_commitment(
        (SLH_DSA_ACTIVATION_HEIGHT - 1) as u32,
        std::slice::from_ref(&non_coinbase),
    );

    let (_t1, txid1, _w1, _n1) = parse_tx(&coinbase).expect("coinbase");
    let (_t2, txid2, _w2, _n2) = parse_tx(&non_coinbase).expect("noncoinbase");
    let root = merkle_root_txids(&[txid1, txid2]).expect("root");
    let mut prev = [0u8; 32];
    prev[0] = 0xa1;
    let target = [0xffu8; 32];
    let block = build_block_bytes(prev, root, target, 29, &[coinbase, non_coinbase]);

    let err = validate_block_basic_at_height(
        &block,
        Some(prev),
        Some(target),
        SLH_DSA_ACTIVATION_HEIGHT - 1,
    )
    .unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrSigAlgInvalid);
}

#[test]
fn validate_block_basic_slh_active_at_height() {
    let prev_txid = [0xacu8; 32];
    let pubkey = vec![0u8; SLH_DSA_SHAKE_256F_PUBKEY_BYTES as usize];
    let sig = vec![0x01];
    let non_coinbase = tx_with_one_input_one_output_with_witness(
        prev_txid,
        0,
        1,
        COV_TYPE_P2PK,
        &valid_p2pk_covenant_data(),
        SUITE_ID_SLH_DSA_SHAKE_256F,
        &pubkey,
        &sig,
    );
    let coinbase = coinbase_with_witness_commitment(
        SLH_DSA_ACTIVATION_HEIGHT as u32,
        std::slice::from_ref(&non_coinbase),
    );

    let (_t1, txid1, _w1, _n1) = parse_tx(&coinbase).expect("coinbase");
    let (_t2, txid2, _w2, _n2) = parse_tx(&non_coinbase).expect("noncoinbase");
    let root = merkle_root_txids(&[txid1, txid2]).expect("root");
    let mut prev = [0u8; 32];
    prev[0] = 0xa2;
    let target = [0xffu8; 32];
    let block = build_block_bytes(prev, root, target, 31, &[coinbase, non_coinbase]);

    validate_block_basic_at_height(&block, Some(prev), Some(target), SLH_DSA_ACTIVATION_HEIGHT)
        .expect("validate");
}

fn hex32(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    assert_eq!(s.len(), 64);
    for i in 0..32 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).expect("hex byte");
    }
    out
}

fn biguint_to_bytes32(x: &BigUint) -> [u8; 32] {
    let b = x.to_bytes_be();
    assert!(b.len() <= 32);
    let mut out = [0u8; 32];
    out[32 - b.len()..].copy_from_slice(&b);
    out
}

#[test]
fn validate_tx_covenants_genesis_p2pk_ok() {
    let mut tx = parse_tx(&minimal_tx_bytes()).expect("parse").0;
    let mut cov = vec![0u8; MAX_P2PK_COVENANT_DATA as usize];
    cov[0] = SUITE_ID_ML_DSA_87;
    tx.outputs = vec![crate::tx::TxOutput {
        value: 1,
        covenant_type: COV_TYPE_P2PK,
        covenant_data: cov,
    }];
    validate_tx_covenants_genesis(&tx, 0).expect("ok");
}

#[test]
fn validate_tx_covenants_genesis_p2pk_slh_gated_by_height() {
    let mut tx = parse_tx(&minimal_tx_bytes()).expect("parse").0;
    let mut cov = vec![0u8; MAX_P2PK_COVENANT_DATA as usize];
    cov[0] = SUITE_ID_SLH_DSA_SHAKE_256F;
    tx.outputs = vec![crate::tx::TxOutput {
        value: 1,
        covenant_type: COV_TYPE_P2PK,
        covenant_data: cov,
    }];

    let err = validate_tx_covenants_genesis(&tx, 0).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrCovenantTypeInvalid);

    validate_tx_covenants_genesis(&tx, SLH_DSA_ACTIVATION_HEIGHT).expect("ok at activation height");
}

#[test]
fn validate_tx_covenants_genesis_unassigned_0001_rejected() {
    let mut tx = parse_tx(&minimal_tx_bytes()).expect("parse").0;
    tx.outputs = vec![crate::tx::TxOutput {
        value: 1,
        covenant_type: 0x0001,
        covenant_data: vec![0x00],
    }];
    let err = validate_tx_covenants_genesis(&tx, 0).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrCovenantTypeInvalid);
}

#[test]
fn validate_tx_covenants_genesis_anchor_nonzero_value() {
    let mut tx = parse_tx(&minimal_tx_bytes()).expect("parse").0;
    tx.outputs = vec![crate::tx::TxOutput {
        value: 1,
        covenant_type: COV_TYPE_ANCHOR,
        covenant_data: vec![0x01],
    }];
    let err = validate_tx_covenants_genesis(&tx, 0).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrCovenantTypeInvalid);
}

#[test]
fn validate_tx_covenants_genesis_vault_ok() {
    let mut tx = parse_tx(&minimal_tx_bytes()).expect("parse").0;
    tx.outputs = vec![crate::tx::TxOutput {
        value: 1,
        covenant_type: COV_TYPE_VAULT,
        covenant_data: valid_vault_covenant_data_for_p2pk_output(),
    }];
    validate_tx_covenants_genesis(&tx, 0).expect("ok");
}

#[test]
fn validate_tx_covenants_genesis_vault_bad_threshold() {
    let mut tx = parse_tx(&minimal_tx_bytes()).expect("parse").0;
    tx.outputs = vec![crate::tx::TxOutput {
        value: 1,
        covenant_type: COV_TYPE_VAULT,
        covenant_data: encode_vault_covenant_data(
            [0x99u8; 32],
            3,
            &make_keys(2, 0x11),
            &make_keys(1, 0x51),
        ),
    }];
    let err = validate_tx_covenants_genesis(&tx, 0).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrVaultParamsInvalid);
}

#[test]
fn validate_tx_covenants_genesis_vault_unsorted_keys() {
    let mut keys = make_keys(2, 0x11);
    keys.swap(0, 1);
    let mut tx = parse_tx(&minimal_tx_bytes()).expect("parse").0;
    tx.outputs = vec![crate::tx::TxOutput {
        value: 1,
        covenant_type: COV_TYPE_VAULT,
        covenant_data: encode_vault_covenant_data([0x99u8; 32], 1, &keys, &make_keys(1, 0x51)),
    }];
    let err = validate_tx_covenants_genesis(&tx, 0).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrVaultKeysNotCanonical);
}

#[test]
fn validate_tx_covenants_genesis_vault_unsorted_whitelist() {
    let keys = make_keys(1, 0x11);
    let mut whitelist = make_keys(2, 0x51);
    whitelist.swap(0, 1);
    let mut tx = parse_tx(&minimal_tx_bytes()).expect("parse").0;
    tx.outputs = vec![crate::tx::TxOutput {
        value: 1,
        covenant_type: COV_TYPE_VAULT,
        covenant_data: encode_vault_covenant_data([0x99u8; 32], 1, &keys, &whitelist),
    }];
    let err = validate_tx_covenants_genesis(&tx, 0).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrVaultWhitelistNotCanonical);
}

#[test]
fn validate_tx_covenants_genesis_multisig_ok() {
    let mut tx = parse_tx(&minimal_tx_bytes()).expect("parse").0;
    tx.outputs = vec![crate::tx::TxOutput {
        value: 1,
        covenant_type: COV_TYPE_MULTISIG,
        covenant_data: encode_multisig_covenant_data(2, &make_keys(2, 0x31)),
    }];
    validate_tx_covenants_genesis(&tx, 0).expect("ok");
}

#[test]
fn validate_tx_covenants_genesis_multisig_bad_threshold() {
    let mut tx = parse_tx(&minimal_tx_bytes()).expect("parse").0;
    tx.outputs = vec![crate::tx::TxOutput {
        value: 1,
        covenant_type: COV_TYPE_MULTISIG,
        covenant_data: encode_multisig_covenant_data(3, &make_keys(2, 0x31)),
    }];
    let err = validate_tx_covenants_genesis(&tx, 0).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrCovenantTypeInvalid);
}

#[test]
fn validate_tx_covenants_genesis_multisig_unsorted_keys() {
    let mut keys = make_keys(2, 0x31);
    keys.swap(0, 1);
    let mut tx = parse_tx(&minimal_tx_bytes()).expect("parse").0;
    tx.outputs = vec![crate::tx::TxOutput {
        value: 1,
        covenant_type: COV_TYPE_MULTISIG,
        covenant_data: encode_multisig_covenant_data(1, &keys),
    }];
    let err = validate_tx_covenants_genesis(&tx, 0).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrCovenantTypeInvalid);
}

fn tx_with_one_input_one_output(
    prev_txid: [u8; 32],
    prev_vout: u32,
    out_value: u64,
    out_cov_type: u16,
    out_cov_data: &[u8],
) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&1u32.to_le_bytes());
    b.push(0x00); // tx_kind
    b.extend_from_slice(&1u64.to_le_bytes());
    crate::compactsize::encode_compact_size(1, &mut b); // input_count
    b.extend_from_slice(&prev_txid);
    b.extend_from_slice(&prev_vout.to_le_bytes());
    crate::compactsize::encode_compact_size(0, &mut b); // script_sig_len
    b.extend_from_slice(&0u32.to_le_bytes()); // sequence
    crate::compactsize::encode_compact_size(1, &mut b); // output_count
    b.extend_from_slice(&out_value.to_le_bytes());
    b.extend_from_slice(&out_cov_type.to_le_bytes());
    crate::compactsize::encode_compact_size(out_cov_data.len() as u64, &mut b);
    b.extend_from_slice(out_cov_data);
    b.extend_from_slice(&0u32.to_le_bytes()); // locktime
    crate::compactsize::encode_compact_size(1, &mut b); // witness_count
    b.push(SUITE_ID_SENTINEL);
    crate::compactsize::encode_compact_size(0, &mut b); // pubkey_length
    crate::compactsize::encode_compact_size(0, &mut b); // sig_length
    crate::compactsize::encode_compact_size(0, &mut b); // da_payload_len
    b
}

#[allow(clippy::too_many_arguments)]
fn tx_with_one_input_one_output_with_witness(
    prev_txid: [u8; 32],
    prev_vout: u32,
    out_value: u64,
    out_cov_type: u16,
    out_cov_data: &[u8],
    suite_id: u8,
    pubkey: &[u8],
    signature: &[u8],
) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&1u32.to_le_bytes());
    b.push(0x00); // tx_kind
    b.extend_from_slice(&1u64.to_le_bytes());
    crate::compactsize::encode_compact_size(1, &mut b); // input_count
    b.extend_from_slice(&prev_txid);
    b.extend_from_slice(&prev_vout.to_le_bytes());
    crate::compactsize::encode_compact_size(0, &mut b); // script_sig_len
    b.extend_from_slice(&0u32.to_le_bytes()); // sequence
    crate::compactsize::encode_compact_size(1, &mut b); // output_count
    b.extend_from_slice(&out_value.to_le_bytes());
    b.extend_from_slice(&out_cov_type.to_le_bytes());
    crate::compactsize::encode_compact_size(out_cov_data.len() as u64, &mut b);
    b.extend_from_slice(out_cov_data);
    b.extend_from_slice(&0u32.to_le_bytes()); // locktime
    crate::compactsize::encode_compact_size(1, &mut b); // witness_count
    b.push(suite_id);
    crate::compactsize::encode_compact_size(pubkey.len() as u64, &mut b);
    b.extend_from_slice(pubkey);
    crate::compactsize::encode_compact_size(signature.len() as u64, &mut b);
    b.extend_from_slice(signature);
    crate::compactsize::encode_compact_size(0, &mut b); // da_payload_len
    b
}

fn valid_p2pk_covenant_data() -> Vec<u8> {
    let mut b = vec![0u8; MAX_P2PK_COVENANT_DATA as usize];
    b[0] = SUITE_ID_ML_DSA_87;
    b
}

fn owner_p2pk_covenant_data_for_vault() -> Vec<u8> {
    let mut b = valid_p2pk_covenant_data();
    b[1] = 0x01;
    b
}

fn sentinel_witness_item() -> crate::tx::WitnessItem {
    crate::tx::WitnessItem {
        suite_id: SUITE_ID_SENTINEL,
        pubkey: vec![],
        signature: vec![],
    }
}

fn make_keys(count: usize, base: u8) -> Vec<[u8; 32]> {
    let mut keys = Vec::with_capacity(count);
    for i in 0..count {
        let mut k = [0u8; 32];
        k[0] = base + (i as u8);
        keys.push(k);
    }
    keys
}

fn encode_vault_covenant_data(
    owner_lock_id: [u8; 32],
    threshold: u8,
    keys: &[[u8; 32]],
    whitelist: &[[u8; 32]],
) -> Vec<u8> {
    let mut b = Vec::with_capacity(32 + 1 + 1 + keys.len() * 32 + 2 + whitelist.len() * 32);
    b.extend_from_slice(&owner_lock_id);
    b.push(threshold);
    b.push(keys.len() as u8);
    for k in keys {
        b.extend_from_slice(k);
    }
    b.extend_from_slice(&(whitelist.len() as u16).to_le_bytes());
    for h in whitelist {
        b.extend_from_slice(h);
    }
    b
}

fn encode_multisig_covenant_data(threshold: u8, keys: &[[u8; 32]]) -> Vec<u8> {
    let mut b = Vec::with_capacity(2 + keys.len() * 32);
    b.push(threshold);
    b.push(keys.len() as u8);
    for k in keys {
        b.extend_from_slice(k);
    }
    b
}

fn valid_vault_covenant_data_for_p2pk_output() -> Vec<u8> {
    // Destination (whitelisted) output descriptor.
    let dest = valid_p2pk_covenant_data();
    let h = sha3_256(&crate::vault::output_descriptor_bytes(COV_TYPE_P2PK, &dest));

    // Owner lock id is the hash of a (possibly different) owner output descriptor.
    let owner = owner_p2pk_covenant_data_for_vault();
    let owner_lock_id = sha3_256(&crate::vault::output_descriptor_bytes(
        COV_TYPE_P2PK,
        &owner,
    ));

    encode_vault_covenant_data(owner_lock_id, 1, &make_keys(1, 0x11), &[h])
}

fn encode_htlc_covenant_data(
    hash: [u8; 32],
    lock_mode: u8,
    lock_value: u64,
    claim_key_id: [u8; 32],
    refund_key_id: [u8; 32],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(MAX_HTLC_COVENANT_DATA as usize);
    out.extend_from_slice(&hash);
    out.push(lock_mode);
    out.extend_from_slice(&lock_value.to_le_bytes());
    out.extend_from_slice(&claim_key_id);
    out.extend_from_slice(&refund_key_id);
    out
}

#[test]
fn apply_non_coinbase_tx_basic_missing_utxo() {
    let mut prev = [0u8; 32];
    prev[0] = 0xaa;
    let tx_bytes =
        tx_with_one_input_one_output(prev, 0, 1, COV_TYPE_P2PK, &valid_p2pk_covenant_data());
    let (tx, txid, _wtxid, _n) = parse_tx(&tx_bytes).expect("parse");
    let utxos: HashMap<Outpoint, UtxoEntry> = HashMap::new();

    let err = apply_non_coinbase_tx_basic(&tx, txid, &utxos, 100, 1000).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrMissingUtxo);
}

#[test]
fn apply_non_coinbase_tx_basic_spend_anchor_rejected() {
    let mut prev = [0u8; 32];
    prev[0] = 0xab;
    let tx_bytes =
        tx_with_one_input_one_output(prev, 0, 1, COV_TYPE_P2PK, &valid_p2pk_covenant_data());
    let (tx, txid, _wtxid, _n) = parse_tx(&tx_bytes).expect("parse");

    let mut utxos: HashMap<Outpoint, UtxoEntry> = HashMap::new();
    utxos.insert(
        Outpoint {
            txid: prev,
            vout: 0,
        },
        UtxoEntry {
            value: 1,
            covenant_type: COV_TYPE_ANCHOR,
            covenant_data: vec![0x01],
            creation_height: 0,
            created_by_coinbase: false,
        },
    );

    let err = apply_non_coinbase_tx_basic(&tx, txid, &utxos, 100, 1000).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrMissingUtxo);
}

#[test]
fn apply_non_coinbase_tx_basic_zero_witness_count_rejected() {
    let mut prev = [0u8; 32];
    prev[0] = 0xac;
    let tx_bytes =
        tx_with_one_input_one_output(prev, 0, 90, COV_TYPE_P2PK, &valid_p2pk_covenant_data());
    let (mut tx, txid, _wtxid, _n) = parse_tx(&tx_bytes).expect("parse");
    tx.witness.clear();

    let mut utxos: HashMap<Outpoint, UtxoEntry> = HashMap::new();
    utxos.insert(
        Outpoint {
            txid: prev,
            vout: 0,
        },
        UtxoEntry {
            value: 100,
            covenant_type: COV_TYPE_P2PK,
            covenant_data: valid_p2pk_covenant_data(),
            creation_height: 0,
            created_by_coinbase: false,
        },
    );

    let err = apply_non_coinbase_tx_basic(&tx, txid, &utxos, 100, 1000).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrParse);
}

#[test]
fn apply_non_coinbase_tx_basic_value_conservation() {
    let mut prev = [0u8; 32];
    prev[0] = 0xae;
    let tx_bytes =
        tx_with_one_input_one_output(prev, 0, 101, COV_TYPE_P2PK, &valid_p2pk_covenant_data());
    let (tx, txid, _wtxid, _n) = parse_tx(&tx_bytes).expect("parse");

    let mut utxos: HashMap<Outpoint, UtxoEntry> = HashMap::new();
    utxos.insert(
        Outpoint {
            txid: prev,
            vout: 0,
        },
        UtxoEntry {
            value: 100,
            covenant_type: COV_TYPE_P2PK,
            covenant_data: valid_p2pk_covenant_data(),
            creation_height: 0,
            created_by_coinbase: false,
        },
    );

    let err = apply_non_coinbase_tx_basic(&tx, txid, &utxos, 200, 1000).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrValueConservation);
}

#[test]
fn apply_non_coinbase_tx_basic_ok() {
    let mut prev = [0u8; 32];
    prev[0] = 0xaf;
    let tx_bytes =
        tx_with_one_input_one_output(prev, 0, 90, COV_TYPE_P2PK, &valid_p2pk_covenant_data());
    let (tx, txid, _wtxid, _n) = parse_tx(&tx_bytes).expect("parse");

    let mut utxos: HashMap<Outpoint, UtxoEntry> = HashMap::new();
    utxos.insert(
        Outpoint {
            txid: prev,
            vout: 0,
        },
        UtxoEntry {
            value: 100,
            covenant_type: COV_TYPE_P2PK,
            covenant_data: valid_p2pk_covenant_data(),
            creation_height: 0,
            created_by_coinbase: false,
        },
    );

    let summary = apply_non_coinbase_tx_basic(&tx, txid, &utxos, 200, 1000).expect("ok");
    assert_eq!(summary.fee, 10);
    assert_eq!(summary.utxo_count, 1);
}

#[test]
fn apply_non_coinbase_tx_basic_vault_cannot_fund_fee() {
    let mut prev_vault = [0u8; 32];
    prev_vault[0] = 0xc0;
    let mut prev_fee = [0u8; 32];
    prev_fee[0] = 0xc1;
    let mut txid = [0u8; 32];
    txid[0] = 0xc2;

    let tx = crate::tx::Tx {
        version: 1,
        tx_kind: 0x00,
        tx_nonce: 1,
        inputs: vec![
            crate::tx::TxInput {
                prev_txid: prev_vault,
                prev_vout: 0,
                script_sig: vec![],
                sequence: 0,
            },
            crate::tx::TxInput {
                prev_txid: prev_fee,
                prev_vout: 0,
                script_sig: vec![],
                sequence: 0,
            },
        ],
        outputs: vec![crate::tx::TxOutput {
            value: 90,
            covenant_type: COV_TYPE_P2PK,
            covenant_data: valid_p2pk_covenant_data(),
        }],
        locktime: 0,
        da_commit_core: None,
        da_chunk_core: None,
        witness: vec![sentinel_witness_item(), sentinel_witness_item()],
        da_payload: vec![],
    };

    let mut utxos: HashMap<Outpoint, UtxoEntry> = HashMap::new();
    utxos.insert(
        Outpoint {
            txid: prev_vault,
            vout: 0,
        },
        UtxoEntry {
            value: 100,
            covenant_type: COV_TYPE_VAULT,
            covenant_data: valid_vault_covenant_data_for_p2pk_output(),
            creation_height: 0,
            created_by_coinbase: false,
        },
    );
    utxos.insert(
        Outpoint {
            txid: prev_fee,
            vout: 0,
        },
        UtxoEntry {
            value: 10,
            covenant_type: COV_TYPE_P2PK,
            covenant_data: owner_p2pk_covenant_data_for_vault(),
            creation_height: 0,
            created_by_coinbase: false,
        },
    );

    let err = apply_non_coinbase_tx_basic(&tx, txid, &utxos, 200, 1000).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrValueConservation);
}

#[test]
fn apply_non_coinbase_tx_basic_vault_preserved_with_owner_fee_input() {
    let mut prev_vault = [0u8; 32];
    prev_vault[0] = 0xd0;
    let mut prev_fee = [0u8; 32];
    prev_fee[0] = 0xd1;
    let mut txid = [0u8; 32];
    txid[0] = 0xd2;

    let tx = crate::tx::Tx {
        version: 1,
        tx_kind: 0x00,
        tx_nonce: 1,
        inputs: vec![
            crate::tx::TxInput {
                prev_txid: prev_vault,
                prev_vout: 0,
                script_sig: vec![],
                sequence: 0,
            },
            crate::tx::TxInput {
                prev_txid: prev_fee,
                prev_vout: 0,
                script_sig: vec![],
                sequence: 0,
            },
        ],
        outputs: vec![crate::tx::TxOutput {
            value: 100,
            covenant_type: COV_TYPE_P2PK,
            covenant_data: valid_p2pk_covenant_data(),
        }],
        locktime: 0,
        da_commit_core: None,
        da_chunk_core: None,
        witness: vec![sentinel_witness_item(), sentinel_witness_item()],
        da_payload: vec![],
    };

    let mut utxos: HashMap<Outpoint, UtxoEntry> = HashMap::new();
    utxos.insert(
        Outpoint {
            txid: prev_vault,
            vout: 0,
        },
        UtxoEntry {
            value: 100,
            covenant_type: COV_TYPE_VAULT,
            covenant_data: valid_vault_covenant_data_for_p2pk_output(),
            creation_height: 0,
            created_by_coinbase: false,
        },
    );
    utxos.insert(
        Outpoint {
            txid: prev_fee,
            vout: 0,
        },
        UtxoEntry {
            value: 10,
            covenant_type: COV_TYPE_P2PK,
            covenant_data: owner_p2pk_covenant_data_for_vault(),
            creation_height: 0,
            created_by_coinbase: false,
        },
    );

    let summary = apply_non_coinbase_tx_basic(&tx, txid, &utxos, 200, 1000).expect("ok");
    assert_eq!(summary.fee, 10);
}

#[test]
fn apply_non_coinbase_tx_basic_vault_allows_owner_top_up() {
    let mut prev_vault = [0u8; 32];
    prev_vault[0] = 0xd3;
    let mut prev_fee = [0u8; 32];
    prev_fee[0] = 0xd4;
    let mut txid = [0u8; 32];
    txid[0] = 0xd5;

    let tx = crate::tx::Tx {
        version: 1,
        tx_kind: 0x00,
        tx_nonce: 1,
        inputs: vec![
            crate::tx::TxInput {
                prev_txid: prev_vault,
                prev_vout: 0,
                script_sig: vec![],
                sequence: 0,
            },
            crate::tx::TxInput {
                prev_txid: prev_fee,
                prev_vout: 0,
                script_sig: vec![],
                sequence: 0,
            },
        ],
        outputs: vec![crate::tx::TxOutput {
            value: 105,
            covenant_type: COV_TYPE_P2PK,
            covenant_data: valid_p2pk_covenant_data(),
        }],
        locktime: 0,
        da_commit_core: None,
        da_chunk_core: None,
        witness: vec![sentinel_witness_item(), sentinel_witness_item()],
        da_payload: vec![],
    };

    let mut utxos: HashMap<Outpoint, UtxoEntry> = HashMap::new();
    utxos.insert(
        Outpoint {
            txid: prev_vault,
            vout: 0,
        },
        UtxoEntry {
            value: 100,
            covenant_type: COV_TYPE_VAULT,
            covenant_data: valid_vault_covenant_data_for_p2pk_output(),
            creation_height: 0,
            created_by_coinbase: false,
        },
    );
    utxos.insert(
        Outpoint {
            txid: prev_fee,
            vout: 0,
        },
        UtxoEntry {
            value: 10,
            covenant_type: COV_TYPE_P2PK,
            covenant_data: owner_p2pk_covenant_data_for_vault(),
            creation_height: 0,
            created_by_coinbase: false,
        },
    );

    let summary = apply_non_coinbase_tx_basic(&tx, txid, &utxos, 200, 1000).expect("ok");
    assert_eq!(summary.fee, 5);
}

#[test]
fn apply_non_coinbase_tx_basic_htlc_timestamp_uses_mtp() {
    let mut prev = [0u8; 32];
    prev[0] = 0xa8;
    let mut txid = [0u8; 32];
    txid[0] = 0xa9;

    let mut claim_pub = vec![0u8; SLH_DSA_SHAKE_256F_PUBKEY_BYTES as usize];
    claim_pub[0] = 0x11;
    let mut refund_pub = vec![0u8; SLH_DSA_SHAKE_256F_PUBKEY_BYTES as usize];
    refund_pub[0] = 0x22;
    let claim_key_id = sha3_256(&claim_pub);
    let refund_key_id = sha3_256(&refund_pub);

    let tx = crate::tx::Tx {
        version: 1,
        tx_kind: 0x00,
        tx_nonce: 1,
        inputs: vec![crate::tx::TxInput {
            prev_txid: prev,
            prev_vout: 0,
            script_sig: vec![],
            sequence: 0,
        }],
        outputs: vec![crate::tx::TxOutput {
            value: 90,
            covenant_type: COV_TYPE_P2PK,
            covenant_data: valid_p2pk_covenant_data(),
        }],
        locktime: 0,
        da_commit_core: None,
        da_chunk_core: None,
        witness: vec![
            crate::tx::WitnessItem {
                suite_id: SUITE_ID_SENTINEL,
                pubkey: refund_key_id.to_vec(),
                signature: vec![0x01],
            },
            crate::tx::WitnessItem {
                suite_id: SUITE_ID_SLH_DSA_SHAKE_256F,
                pubkey: refund_pub.clone(),
                signature: vec![0x01],
            },
        ],
        da_payload: vec![],
    };

    let mut utxos: HashMap<Outpoint, UtxoEntry> = HashMap::new();
    utxos.insert(
        Outpoint {
            txid: prev,
            vout: 0,
        },
        UtxoEntry {
            value: 100,
            covenant_type: COV_TYPE_HTLC,
            covenant_data: encode_htlc_covenant_data(
                sha3_256(b"htlc-hash"),
                LOCK_MODE_TIMESTAMP,
                2000,
                claim_key_id,
                refund_key_id,
            ),
            creation_height: 0,
            created_by_coinbase: false,
        },
    );

    let err = apply_non_coinbase_tx_basic_with_mtp(
        &tx,
        txid,
        &utxos,
        SLH_DSA_ACTIVATION_HEIGHT,
        3000,
        1000,
    )
    .unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrTimelockNotMet);

    let summary = apply_non_coinbase_tx_basic_with_mtp(
        &tx,
        txid,
        &utxos,
        SLH_DSA_ACTIVATION_HEIGHT,
        3000,
        3000,
    )
    .expect("ok");
    assert_eq!(summary.fee, 10);
    assert_eq!(summary.utxo_count, 1);
}

#[test]
fn apply_non_coinbase_tx_basic_vault_whitelist_rejects_output() {
    let mut prev_vault = [0u8; 32];
    prev_vault[0] = 0xe0;
    let mut prev_fee = [0u8; 32];
    prev_fee[0] = 0xe1;
    let mut txid = [0u8; 32];
    txid[0] = 0xe2;

    let mut non_whitelisted = valid_p2pk_covenant_data();
    non_whitelisted[1] = 0xff;

    let tx = crate::tx::Tx {
        version: 1,
        tx_kind: 0x00,
        tx_nonce: 1,
        inputs: vec![
            crate::tx::TxInput {
                prev_txid: prev_vault,
                prev_vout: 0,
                script_sig: vec![],
                sequence: 0,
            },
            crate::tx::TxInput {
                prev_txid: prev_fee,
                prev_vout: 0,
                script_sig: vec![],
                sequence: 0,
            },
        ],
        outputs: vec![crate::tx::TxOutput {
            value: 100,
            covenant_type: COV_TYPE_P2PK,
            covenant_data: non_whitelisted,
        }],
        locktime: 0,
        da_commit_core: None,
        da_chunk_core: None,
        witness: vec![sentinel_witness_item(), sentinel_witness_item()],
        da_payload: vec![],
    };

    let mut utxos: HashMap<Outpoint, UtxoEntry> = HashMap::new();
    utxos.insert(
        Outpoint {
            txid: prev_vault,
            vout: 0,
        },
        UtxoEntry {
            value: 100,
            covenant_type: COV_TYPE_VAULT,
            covenant_data: valid_vault_covenant_data_for_p2pk_output(),
            creation_height: 0,
            created_by_coinbase: false,
        },
    );
    utxos.insert(
        Outpoint {
            txid: prev_fee,
            vout: 0,
        },
        UtxoEntry {
            value: 10,
            covenant_type: COV_TYPE_P2PK,
            covenant_data: owner_p2pk_covenant_data_for_vault(),
            creation_height: 0,
            created_by_coinbase: false,
        },
    );

    let err = apply_non_coinbase_tx_basic(&tx, txid, &utxos, 200, 1000).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrVaultOutputNotWhitelisted);
}

#[test]
fn apply_non_coinbase_tx_basic_multisig_input_accepted() {
    let mut prev = [0u8; 32];
    prev[0] = 0xf0;
    let tx_bytes =
        tx_with_one_input_one_output(prev, 0, 90, COV_TYPE_P2PK, &valid_p2pk_covenant_data());
    let (tx, txid, _wtxid, _n) = parse_tx(&tx_bytes).expect("parse");

    let mut utxos: HashMap<Outpoint, UtxoEntry> = HashMap::new();
    utxos.insert(
        Outpoint {
            txid: prev,
            vout: 0,
        },
        UtxoEntry {
            value: 100,
            covenant_type: COV_TYPE_MULTISIG,
            covenant_data: encode_multisig_covenant_data(1, &make_keys(1, 0x31)),
            creation_height: 0,
            created_by_coinbase: false,
        },
    );

    let summary = apply_non_coinbase_tx_basic(&tx, txid, &utxos, 200, 1000).expect("ok");
    assert_eq!(summary.fee, 10);
}

#[test]
fn fork_work_vectors() {
    let ff = [0xffu8; 32];
    let w = crate::fork_work_from_target(ff).expect("work");
    assert_eq!(w, BigUint::one());

    let mut half = [0u8; 32];
    half[0] = 0x80;
    let w = crate::fork_work_from_target(half).expect("work");
    assert_eq!(w, BigUint::from(2u8));

    let mut one = [0u8; 32];
    one[31] = 0x01;
    let w = crate::fork_work_from_target(one).expect("work");
    let two256: BigUint = BigUint::one() << 256usize;
    assert_eq!(w, two256);
}
