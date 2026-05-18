use super::test_support::{sign_witness, test_tx_context};
use super::*;
use crate::constants::SUITE_ID_SENTINEL;
use crate::hash::sha3_256;
use crate::spend_verify::validate_threshold_sig_spend_q;
use crate::suite_registry::SuiteRegistry;
use crate::tx::WitnessItem;
use crate::verify_sig_openssl::Mldsa87Keypair;
use crate::SighashV1PrehashCache;

// Threshold Error Path Tests (5)

#[test]
fn validate_threshold_slot_count_mismatch_q() {
    // ws.len() != keys.len()
    let kp1 = Mldsa87Keypair::generate().expect("kp1");
    let key_id_1 = sha3_256(&kp1.pubkey_bytes());
    let (tx, ii, iv, cid) = test_tx_context();
    let mut cache = SighashV1PrehashCache::new(&tx).expect("cache");
    let witness = sign_witness(&kp1, &tx, ii, iv, cid);
    let reg = SuiteRegistry::default_registry();
    let mut queue = SigCheckQueue::new(1).with_registry(&reg);
    // 2 keys but only 1 witness slot
    let err = validate_threshold_sig_spend_q(
        &[key_id_1, [0xAA; 32]],
        1,
        &[witness],
        ii,
        iv,
        cid,
        0,
        "TEST",
        &mut cache,
        Some(&mut queue),
        None,
        Some(&reg),
    )
    .expect_err("must reject slot count mismatch");
    assert_eq!(err.code, ErrorCode::TxErrParse);
}

#[test]
fn validate_threshold_sentinel_with_data_q() {
    // SENTINEL witness slot with non-empty pubkey
    let kp1 = Mldsa87Keypair::generate().expect("kp1");
    let key_id_1 = sha3_256(&kp1.pubkey_bytes());
    let (tx, ii, iv, cid) = test_tx_context();
    let mut cache = SighashV1PrehashCache::new(&tx).expect("cache");
    let reg = SuiteRegistry::default_registry();
    let mut queue = SigCheckQueue::new(1).with_registry(&reg);
    let bad_sentinel = WitnessItem {
        suite_id: SUITE_ID_SENTINEL,
        pubkey: vec![0x42; 32], // SENTINEL must have empty pubkey
        signature: Vec::new(),
    };
    let err = validate_threshold_sig_spend_q(
        &[key_id_1],
        1,
        &[bad_sentinel],
        ii,
        iv,
        cid,
        0,
        "TEST",
        &mut cache,
        Some(&mut queue),
        None,
        Some(&reg),
    )
    .expect_err("must reject SENTINEL with pubkey data");
    assert_eq!(err.code, ErrorCode::TxErrParse);
}

#[test]
fn validate_threshold_invalid_suite_q() {
    // Non-SENTINEL witness with unknown suite_id
    let kp1 = Mldsa87Keypair::generate().expect("kp1");
    let key_id_1 = sha3_256(&kp1.pubkey_bytes());
    let (tx, ii, iv, cid) = test_tx_context();
    let mut cache = SighashV1PrehashCache::new(&tx).expect("cache");
    let mut witness = sign_witness(&kp1, &tx, ii, iv, cid);
    witness.suite_id = 0xFE; // unknown suite
    let reg = SuiteRegistry::default_registry();
    let mut queue = SigCheckQueue::new(1).with_registry(&reg);
    let err = validate_threshold_sig_spend_q(
        &[key_id_1],
        1,
        &[witness],
        ii,
        iv,
        cid,
        0,
        "TEST",
        &mut cache,
        Some(&mut queue),
        None,
        Some(&reg),
    )
    .expect_err("must reject unknown suite");
    assert_eq!(err.code, ErrorCode::TxErrSigAlgInvalid);
}

#[test]
fn validate_threshold_non_canonical_sig_q() {
    // Witness with correct suite but wrong pubkey length
    let kp1 = Mldsa87Keypair::generate().expect("kp1");
    let key_id_1 = sha3_256(&kp1.pubkey_bytes());
    let (tx, ii, iv, cid) = test_tx_context();
    let mut cache = SighashV1PrehashCache::new(&tx).expect("cache");
    let mut witness = sign_witness(&kp1, &tx, ii, iv, cid);
    witness.pubkey = vec![0u8; 10]; // non-canonical length
    let reg = SuiteRegistry::default_registry();
    let mut queue = SigCheckQueue::new(1).with_registry(&reg);
    let err = validate_threshold_sig_spend_q(
        &[key_id_1],
        1,
        &[witness],
        ii,
        iv,
        cid,
        0,
        "TEST",
        &mut cache,
        Some(&mut queue),
        None,
        Some(&reg),
    )
    .expect_err("must reject non-canonical lengths");
    assert_eq!(err.code, ErrorCode::TxErrSigNoncanonical);
}

#[test]
fn validate_threshold_multiple_signers_all_required_q() {
    // threshold=2 but only 1 valid signer → must fail
    let kp1 = Mldsa87Keypair::generate().expect("kp1");
    let kp2 = Mldsa87Keypair::generate().expect("kp2");
    let key_id_1 = sha3_256(&kp1.pubkey_bytes());
    let key_id_2 = sha3_256(&kp2.pubkey_bytes());
    let (tx, ii, iv, cid) = test_tx_context();
    let mut cache = SighashV1PrehashCache::new(&tx).expect("cache");
    let witness1 = sign_witness(&kp1, &tx, ii, iv, cid);
    let sentinel = WitnessItem {
        suite_id: SUITE_ID_SENTINEL,
        pubkey: Vec::new(),
        signature: Vec::new(),
    };
    let reg = SuiteRegistry::default_registry();
    let mut queue = SigCheckQueue::new(1).with_registry(&reg);
    let err = validate_threshold_sig_spend_q(
        &[key_id_1, key_id_2],
        2,                     // threshold=2
        &[witness1, sentinel], // only 1 signer
        ii,
        iv,
        cid,
        0,
        "TEST",
        &mut cache,
        Some(&mut queue),
        None,
        Some(&reg),
    )
    .expect_err("must reject: insufficient signers");
    assert_eq!(err.code, ErrorCode::TxErrSigInvalid);
    assert!(queue.is_empty(), "threshold failure must roll back queue");
}
