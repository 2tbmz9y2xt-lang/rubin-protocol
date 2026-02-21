use crate::constants::*;
use crate::error::ErrorCode;
use crate::hash::sha3_256;
use crate::pow::{pow_check, retarget_v1};
use crate::sighash_v1_digest;
use crate::{block_hash, merkle_root_txids, parse_tx_v2, BLOCK_HEADER_BYTES};
use num_bigint::BigUint;
use num_traits::One;

fn minimal_tx_bytes() -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&TX_WIRE_VERSION.to_le_bytes());
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
fn parse_tx_v2_minimal_txid_wtxid() {
    let tx_bytes = minimal_tx_bytes();
    let (_tx, txid, wtxid, n) = parse_tx_v2(&tx_bytes).expect("parse");
    assert_eq!(n, tx_bytes.len());

    let want_txid = sha3_256(&tx_bytes[..core_end()]);
    assert_eq!(txid, want_txid);
    let want_wtxid = sha3_256(&tx_bytes);
    assert_eq!(wtxid, want_wtxid);
}

#[test]
fn parse_tx_v2_nonminimal_compactsize() {
    let mut tx_bytes = minimal_tx_bytes();
    // Replace input_count=0x00 with 0xfd 0x00 0x00 (non-minimal).
    let off_input_count = 4 + 1 + 8;
    tx_bytes.splice(off_input_count..off_input_count + 1, [0xfd, 0x00, 0x00]);

    let err = parse_tx_v2(&tx_bytes).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrParse);
}

#[test]
fn parse_tx_v2_script_sig_len_overflow() {
    let mut b = Vec::new();
    b.extend_from_slice(&TX_WIRE_VERSION.to_le_bytes());
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

    let err = parse_tx_v2(&b).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrParse);
}

#[test]
fn parse_tx_v2_witness_count_overflow() {
    let mut tx_bytes = minimal_tx_bytes();
    // Replace witness_count=0x00 with CompactSize(1025) = 0xfd 0x01 0x04.
    let off_witness_count = core_end();
    tx_bytes.splice(off_witness_count..off_witness_count + 1, [0xfd, 0x01, 0x04]);

    let err = parse_tx_v2(&tx_bytes).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrWitnessOverflow);
}

#[test]
fn parse_tx_v2_witness_item_canonicalization() {
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
    let err = parse_tx_v2(&tx1).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrParse);

    // unknown_suite: witness_count=1, suite=0x03, pubkey_length=0, sig_length=0.
    let mut tx2 = base.clone();
    tx2.push(0x01);
    tx2.push(0x03);
    tx2.push(0x00);
    tx2.push(0x00);
    tx2.push(0x00);
    let err = parse_tx_v2(&tx2).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrSigAlgInvalid);

    // ml_dsa_len_mismatch: pubkey_length=2591 (0x0A1F) and canonical sig_length.
    let mut tx3 = base.clone();
    tx3.push(0x01);
    tx3.push(SUITE_ID_ML_DSA_87);
    tx3.extend_from_slice(&[0xfd, 0x1f, 0x0a]); // pubkey_length = 2591
    tx3.extend_from_slice(&vec![0u8; 2591]);
    tx3.extend_from_slice(&[0xfd, 0x13, 0x12]); // sig_length = 4627
    tx3.extend_from_slice(&vec![0u8; 4627]);
    tx3.push(0x00); // da_payload_len
    let err = parse_tx_v2(&tx3).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrSigNoncanonical);

    // slh_dsa_sig_len_zero: pubkey_length=64, sig_length=0.
    let mut tx4 = base.clone();
    tx4.push(0x01);
    tx4.push(SUITE_ID_SLH_DSA_SHAKE_256F);
    tx4.push(0x40); // pubkey_length = 64
    tx4.extend_from_slice(&vec![0u8; 64]);
    tx4.push(0x00); // sig_length = 0
    tx4.push(0x00); // da_payload_len
    let err = parse_tx_v2(&tx4).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrSigNoncanonical);
}

#[test]
fn parse_tx_v2_witness_bytes_overflow() {
    let mut tx = minimal_tx_bytes();
    tx.truncate(core_end());

    tx.push(0x03); // witness_count=3
    for _ in 0..3 {
        tx.push(SUITE_ID_SLH_DSA_SHAKE_256F);
        tx.push(0x40); // pubkey_length=64
        tx.extend_from_slice(&vec![0u8; 64]);
        tx.extend_from_slice(&[0xfd, 0xc0, 0xc2]); // sig_length=49856 (0xC2C0)
        tx.extend_from_slice(&vec![0u8; 49_856]);
    }
    tx.push(0x00); // da_payload_len

    let err = parse_tx_v2(&tx).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrWitnessOverflow);
}

#[test]
fn merkle_root_single_and_two() {
    let tx1 = minimal_tx_bytes();
    let (_t1, txid1, _w1, _n1) = parse_tx_v2(&tx1).expect("tx1");

    let root1 = merkle_root_txids(&[txid1]).expect("root1");
    let mut leaf_preimage = [0u8; 33];
    leaf_preimage[0] = 0x00;
    leaf_preimage[1..].copy_from_slice(&txid1);
    assert_eq!(root1, sha3_256(&leaf_preimage));

    let mut tx2 = minimal_tx_bytes();
    tx2[core_end() - 4] = 0x01; // locktime LSB = 1
    let (_t2, txid2, _w2, _n2) = parse_tx_v2(&tx2).expect("tx2");

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
fn sighash_v1_digest_smoke() {
    let mut b = Vec::new();
    b.extend_from_slice(&TX_WIRE_VERSION.to_le_bytes());
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

    let (tx, _txid, _wtxid, _n) = parse_tx_v2(&b).expect("parse");

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
    preimage.extend_from_slice(b"RUBINv2-sighash/");
    preimage.extend_from_slice(&chain_id);
    preimage.extend_from_slice(&TX_WIRE_VERSION.to_le_bytes());
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
