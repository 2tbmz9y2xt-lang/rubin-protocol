use super::test_support::{
    encode_htlc_claim_payload, htlc_claim_fixture, htlc_spend_context, sign_witness,
    test_tx_context,
};
use super::*;
use crate::constants::{
    COV_TYPE_HTLC, LOCK_MODE_HEIGHT, MAX_HTLC_COVENANT_DATA, SUITE_ID_ML_DSA_87, SUITE_ID_SENTINEL,
};
use crate::hash::sha3_256;
use crate::htlc::validate_htlc_spend_q;
use crate::suite_registry::SuiteRegistry;
use crate::tx::WitnessItem;
use crate::utxo_basic::UtxoEntry;
use crate::verify_sig_openssl::Mldsa87Keypair;
use crate::SighashV1PrehashCache;

// HTLC Error Path Tests (11)

#[test]
fn validate_htlc_claim_payload_suite_id_mismatch_q() {
    // path_item.suite_id must be SENTINEL
    let (entry, mut path_item, sig_item, tx, ii, iv, cid, reg) = htlc_claim_fixture();
    path_item.suite_id = SUITE_ID_ML_DSA_87; // wrong: not SENTINEL
    let mut cache = SighashV1PrehashCache::new(&tx).expect("cache");
    let mut queue = SigCheckQueue::new(1).with_registry(&reg);
    let err = validate_htlc_spend_q(
        &entry,
        &path_item,
        &sig_item,
        htlc_spend_context(ii, iv, cid, 1, 0),
        &mut cache,
        Some(&mut queue),
        None,
        Some(&reg),
    )
    .expect_err("must reject non-SENTINEL selector");
    assert_eq!(err.code, ErrorCode::TxErrParse);
}

#[test]
fn validate_htlc_claim_selector_key_length_invalid_q() {
    // path_item.pubkey must be exactly 32 bytes
    let (entry, mut path_item, sig_item, tx, ii, iv, cid, reg) = htlc_claim_fixture();
    path_item.pubkey = vec![0u8; 16]; // wrong length
    let mut cache = SighashV1PrehashCache::new(&tx).expect("cache");
    let mut queue = SigCheckQueue::new(1).with_registry(&reg);
    let err = validate_htlc_spend_q(
        &entry,
        &path_item,
        &sig_item,
        htlc_spend_context(ii, iv, cid, 1, 0),
        &mut cache,
        Some(&mut queue),
        None,
        Some(&reg),
    )
    .expect_err("must reject non-32-byte selector key");
    assert_eq!(err.code, ErrorCode::TxErrParse);
}

#[test]
fn validate_htlc_claim_payload_empty_q() {
    // path_item.signature (payload) cannot be empty
    let (entry, mut path_item, sig_item, tx, ii, iv, cid, reg) = htlc_claim_fixture();
    path_item.signature = vec![]; // empty
    let mut cache = SighashV1PrehashCache::new(&tx).expect("cache");
    let mut queue = SigCheckQueue::new(1).with_registry(&reg);
    let err = validate_htlc_spend_q(
        &entry,
        &path_item,
        &sig_item,
        htlc_spend_context(ii, iv, cid, 1, 0),
        &mut cache,
        Some(&mut queue),
        None,
        Some(&reg),
    )
    .expect_err("must reject empty payload");
    assert_eq!(err.code, ErrorCode::TxErrParse);
}

#[test]
fn validate_htlc_unknown_path_byte_q() {
    // First byte of claim payload must be 0x00 (claim) or 0x01 (refund)
    let (entry, mut path_item, sig_item, tx, ii, iv, cid, reg) = htlc_claim_fixture();
    path_item.signature[0] = 0xFF; // invalid path selector
    let mut cache = SighashV1PrehashCache::new(&tx).expect("cache");
    let mut queue = SigCheckQueue::new(1).with_registry(&reg);
    let err = validate_htlc_spend_q(
        &entry,
        &path_item,
        &sig_item,
        htlc_spend_context(ii, iv, cid, 1, 0),
        &mut cache,
        Some(&mut queue),
        None,
        Some(&reg),
    )
    .expect_err("must reject unknown path byte");
    assert_eq!(err.code, ErrorCode::TxErrParse);
}

#[test]
fn validate_htlc_preimage_too_short_q() {
    // Preimage shorter than MIN_HTLC_PREIMAGE_BYTES (16)
    let claim_kp = Mldsa87Keypair::generate().expect("claim kp");
    let refund_kp = Mldsa87Keypair::generate().expect("refund kp");
    let claim_key_id = sha3_256(&claim_kp.pubkey_bytes());
    let refund_key_id = sha3_256(&refund_kp.pubkey_bytes());
    let short_preimage = b"tiny"; // 4 bytes < 16
    let mut cov = Vec::with_capacity(MAX_HTLC_COVENANT_DATA as usize);
    cov.extend_from_slice(&sha3_256(short_preimage.as_slice()));
    cov.push(LOCK_MODE_HEIGHT);
    cov.extend_from_slice(&100u64.to_le_bytes());
    cov.extend_from_slice(&claim_key_id);
    cov.extend_from_slice(&refund_key_id);
    let entry = UtxoEntry {
        value: 1000,
        covenant_type: COV_TYPE_HTLC,
        covenant_data: cov,
        creation_height: 0,
        created_by_coinbase: false,
    };
    let (tx, ii, iv, cid) = test_tx_context();
    let sig_item = sign_witness(&claim_kp, &tx, ii, iv, cid);
    let path_item = WitnessItem {
        suite_id: SUITE_ID_SENTINEL,
        pubkey: claim_key_id.to_vec(),
        signature: encode_htlc_claim_payload(short_preimage),
    };
    let reg = SuiteRegistry::default_registry();
    let mut cache = SighashV1PrehashCache::new(&tx).expect("cache");
    let mut queue = SigCheckQueue::new(1).with_registry(&reg);
    let err = validate_htlc_spend_q(
        &entry,
        &path_item,
        &sig_item,
        htlc_spend_context(ii, iv, cid, 1, 0),
        &mut cache,
        Some(&mut queue),
        None,
        Some(&reg),
    )
    .expect_err("must reject short preimage");
    assert_eq!(err.code, ErrorCode::TxErrParse);
}

#[test]
fn validate_htlc_preimage_hash_mismatch_q() {
    // Valid-length preimage that doesn't match the stored hash
    let (entry, mut path_item, sig_item, tx, ii, iv, cid, reg) = htlc_claim_fixture();
    // Replace preimage with different valid-length data
    let bad_preimage = b"wrong-preimage-1234!";
    path_item.signature = encode_htlc_claim_payload(bad_preimage);
    let mut cache = SighashV1PrehashCache::new(&tx).expect("cache");
    let mut queue = SigCheckQueue::new(1).with_registry(&reg);
    let err = validate_htlc_spend_q(
        &entry,
        &path_item,
        &sig_item,
        htlc_spend_context(ii, iv, cid, 1, 0),
        &mut cache,
        Some(&mut queue),
        None,
        Some(&reg),
    )
    .expect_err("must reject wrong preimage");
    assert_eq!(err.code, ErrorCode::TxErrSigInvalid);
}

#[test]
fn validate_htlc_claim_key_id_mismatch_q() {
    // Selector key_id doesn't match claim_key_id in covenant
    let (entry, mut path_item, sig_item, tx, ii, iv, cid, reg) = htlc_claim_fixture();
    path_item.pubkey = vec![0xAA; 32]; // wrong key_id
    let mut cache = SighashV1PrehashCache::new(&tx).expect("cache");
    let mut queue = SigCheckQueue::new(1).with_registry(&reg);
    let err = validate_htlc_spend_q(
        &entry,
        &path_item,
        &sig_item,
        htlc_spend_context(ii, iv, cid, 1, 0),
        &mut cache,
        Some(&mut queue),
        None,
        Some(&reg),
    )
    .expect_err("must reject wrong claim key_id");
    assert_eq!(err.code, ErrorCode::TxErrSigInvalid);
}

#[test]
fn validate_htlc_refund_timelock_not_met_q() {
    // Refund path with block_height below lock_value
    let claim_kp = Mldsa87Keypair::generate().expect("claim kp");
    let refund_kp = Mldsa87Keypair::generate().expect("refund kp");
    let claim_key_id = sha3_256(&claim_kp.pubkey_bytes());
    let refund_key_id = sha3_256(&refund_kp.pubkey_bytes());
    let mut cov = Vec::with_capacity(MAX_HTLC_COVENANT_DATA as usize);
    cov.extend_from_slice(&sha3_256(b"refund-preimage-test"));
    cov.push(LOCK_MODE_HEIGHT);
    cov.extend_from_slice(&500u64.to_le_bytes()); // lock at height 500
    cov.extend_from_slice(&claim_key_id);
    cov.extend_from_slice(&refund_key_id);
    let entry = UtxoEntry {
        value: 1000,
        covenant_type: COV_TYPE_HTLC,
        covenant_data: cov,
        creation_height: 0,
        created_by_coinbase: false,
    };
    let (tx, ii, iv, cid) = test_tx_context();
    let sig_item = sign_witness(&refund_kp, &tx, ii, iv, cid);
    // Refund path: path_id=0x01
    let path_item = WitnessItem {
        suite_id: SUITE_ID_SENTINEL,
        pubkey: refund_key_id.to_vec(),
        signature: vec![0x01], // refund path
    };
    let reg = SuiteRegistry::default_registry();
    let mut cache = SighashV1PrehashCache::new(&tx).expect("cache");
    let mut queue = SigCheckQueue::new(1).with_registry(&reg);
    let err = validate_htlc_spend_q(
        &entry,
        &path_item,
        &sig_item,
        htlc_spend_context(ii, iv, cid, 10, 0), // block_height below lock_value=500
        &mut cache,
        Some(&mut queue),
        None,
        Some(&reg),
    )
    .expect_err("must reject: timelock not met");
    assert_eq!(err.code, ErrorCode::TxErrTimelockNotMet);
}

#[test]
fn validate_htlc_refund_key_id_mismatch_q() {
    // Refund path with wrong selector key_id
    let claim_kp = Mldsa87Keypair::generate().expect("claim kp");
    let refund_kp = Mldsa87Keypair::generate().expect("refund kp");
    let claim_key_id = sha3_256(&claim_kp.pubkey_bytes());
    let refund_key_id = sha3_256(&refund_kp.pubkey_bytes());
    let mut cov = Vec::with_capacity(MAX_HTLC_COVENANT_DATA as usize);
    cov.extend_from_slice(&sha3_256(b"refund-key-mismatch"));
    cov.push(LOCK_MODE_HEIGHT);
    cov.extend_from_slice(&1u64.to_le_bytes());
    cov.extend_from_slice(&claim_key_id);
    cov.extend_from_slice(&refund_key_id);
    let entry = UtxoEntry {
        value: 1000,
        covenant_type: COV_TYPE_HTLC,
        covenant_data: cov,
        creation_height: 0,
        created_by_coinbase: false,
    };
    let (tx, ii, iv, cid) = test_tx_context();
    let sig_item = sign_witness(&refund_kp, &tx, ii, iv, cid);
    let path_item = WitnessItem {
        suite_id: SUITE_ID_SENTINEL,
        pubkey: vec![0xBB; 32], // wrong refund key_id
        signature: vec![0x01],
    };
    let reg = SuiteRegistry::default_registry();
    let mut cache = SighashV1PrehashCache::new(&tx).expect("cache");
    let mut queue = SigCheckQueue::new(1).with_registry(&reg);
    let err = validate_htlc_spend_q(
        &entry,
        &path_item,
        &sig_item,
        htlc_spend_context(ii, iv, cid, 100, 0),
        &mut cache,
        Some(&mut queue),
        None,
        Some(&reg),
    )
    .expect_err("must reject wrong refund key_id");
    assert_eq!(err.code, ErrorCode::TxErrSigInvalid);
}

#[test]
fn validate_htlc_claim_suite_not_native_q() {
    // sig_item with a suite_id not in native spend set
    let (entry, path_item, mut sig_item, tx, ii, iv, cid, reg) = htlc_claim_fixture();
    sig_item.suite_id = 0xFE; // unknown suite
    let mut cache = SighashV1PrehashCache::new(&tx).expect("cache");
    let mut queue = SigCheckQueue::new(1).with_registry(&reg);
    let err = validate_htlc_spend_q(
        &entry,
        &path_item,
        &sig_item,
        htlc_spend_context(ii, iv, cid, 1, 0),
        &mut cache,
        Some(&mut queue),
        None,
        Some(&reg),
    )
    .expect_err("must reject non-native suite");
    assert_eq!(err.code, ErrorCode::TxErrSigAlgInvalid);
}

#[test]
fn validate_htlc_claim_sig_non_canonical_q() {
    // sig_item with correct suite but wrong pubkey/sig lengths
    let (entry, path_item, mut sig_item, tx, ii, iv, cid, reg) = htlc_claim_fixture();
    sig_item.pubkey = vec![0u8; 10]; // wrong pubkey length (not 2592)
    let mut cache = SighashV1PrehashCache::new(&tx).expect("cache");
    let mut queue = SigCheckQueue::new(1).with_registry(&reg);
    let err = validate_htlc_spend_q(
        &entry,
        &path_item,
        &sig_item,
        htlc_spend_context(ii, iv, cid, 1, 0),
        &mut cache,
        Some(&mut queue),
        None,
        Some(&reg),
    )
    .expect_err("must reject non-canonical lengths");
    assert_eq!(err.code, ErrorCode::TxErrSigNoncanonical);
}
