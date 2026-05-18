use super::test_support::{
    htlc_claim_fixture, htlc_spend_context, make_stealth_entry, sign_witness, test_tx_context,
};
use super::*;
use crate::constants::{
    COV_TYPE_CORE_STEALTH, COV_TYPE_HTLC, COV_TYPE_P2PK, LOCK_MODE_HEIGHT, MAX_HTLC_COVENANT_DATA,
    SUITE_ID_ML_DSA_87, SUITE_ID_SENTINEL,
};
use crate::hash::sha3_256;
use crate::htlc::validate_htlc_spend_q;
use crate::spend_verify::validate_p2pk_spend_q;
use crate::stealth::validate_stealth_spend_q;
use crate::suite_registry::SuiteRegistry;
use crate::tx::WitnessItem;
use crate::tx_helpers::p2pk_covenant_data_for_pubkey;
use crate::utxo_basic::UtxoEntry;
use crate::verify_sig_openssl::Mldsa87Keypair;
use crate::SighashV1PrehashCache;

// P2PK Error Path Tests (3)

#[test]
fn validate_p2pk_suite_not_in_native_q() {
    let kp = Mldsa87Keypair::generate().expect("kp");
    let pubkey = kp.pubkey_bytes();
    let entry = UtxoEntry {
        value: 100,
        covenant_type: COV_TYPE_P2PK,
        covenant_data: p2pk_covenant_data_for_pubkey(&pubkey),
        creation_height: 0,
        created_by_coinbase: false,
    };
    let (tx, ii, iv, cid) = test_tx_context();
    let mut cache = SighashV1PrehashCache::new(&tx).expect("cache");
    let mut witness = sign_witness(&kp, &tx, ii, iv, cid);
    witness.suite_id = 0xFE; // unknown suite
    let reg = SuiteRegistry::default_registry();
    let mut queue = SigCheckQueue::new(1).with_registry(&reg);
    let err = validate_p2pk_spend_q(
        &entry,
        &witness,
        ii,
        iv,
        cid,
        0,
        &mut cache,
        Some(&mut queue),
        None,
        Some(&reg),
    )
    .expect_err("must reject non-native suite");
    assert_eq!(err.code, ErrorCode::TxErrSigAlgInvalid);
}

#[test]
fn validate_p2pk_non_canonical_sig_q() {
    let kp = Mldsa87Keypair::generate().expect("kp");
    let pubkey = kp.pubkey_bytes();
    let entry = UtxoEntry {
        value: 100,
        covenant_type: COV_TYPE_P2PK,
        covenant_data: p2pk_covenant_data_for_pubkey(&pubkey),
        creation_height: 0,
        created_by_coinbase: false,
    };
    let (tx, ii, iv, cid) = test_tx_context();
    let mut cache = SighashV1PrehashCache::new(&tx).expect("cache");
    let mut witness = sign_witness(&kp, &tx, ii, iv, cid);
    witness.pubkey = vec![0u8; 10]; // non-canonical pubkey length
    let reg = SuiteRegistry::default_registry();
    let mut queue = SigCheckQueue::new(1).with_registry(&reg);
    let err = validate_p2pk_spend_q(
        &entry,
        &witness,
        ii,
        iv,
        cid,
        0,
        &mut cache,
        Some(&mut queue),
        None,
        Some(&reg),
    )
    .expect_err("must reject non-canonical");
    assert_eq!(err.code, ErrorCode::TxErrSigNoncanonical);
}

#[test]
fn validate_p2pk_covenant_data_invalid_q() {
    let kp = Mldsa87Keypair::generate().expect("kp");
    let entry = UtxoEntry {
        value: 100,
        covenant_type: COV_TYPE_P2PK,
        covenant_data: vec![0u8; 5], // wrong covenant data length
        creation_height: 0,
        created_by_coinbase: false,
    };
    let (tx, ii, iv, cid) = test_tx_context();
    let mut cache = SighashV1PrehashCache::new(&tx).expect("cache");
    let witness = sign_witness(&kp, &tx, ii, iv, cid);
    let reg = SuiteRegistry::default_registry();
    let mut queue = SigCheckQueue::new(1).with_registry(&reg);
    let err = validate_p2pk_spend_q(
        &entry,
        &witness,
        ii,
        iv,
        cid,
        0,
        &mut cache,
        Some(&mut queue),
        None,
        Some(&reg),
    )
    .expect_err("must reject invalid covenant data");
    assert_eq!(err.code, ErrorCode::TxErrCovenantTypeInvalid);
}

// Stealth Error Path Tests (4)

#[test]
fn validate_stealth_invalid_suite_q() {
    let kp = Mldsa87Keypair::generate().expect("kp");
    let one_time_key_id = sha3_256(&kp.pubkey_bytes());
    let entry = make_stealth_entry(one_time_key_id);
    let (tx, ii, iv, cid) = test_tx_context();
    let mut cache = SighashV1PrehashCache::new(&tx).expect("cache");
    let mut witness = sign_witness(&kp, &tx, ii, iv, cid);
    witness.suite_id = 0xFE; // unknown suite
    let reg = SuiteRegistry::default_registry();
    let mut queue = SigCheckQueue::new(1).with_registry(&reg);
    let err = validate_stealth_spend_q(
        &entry,
        &witness,
        ii,
        iv,
        cid,
        0,
        &mut cache,
        Some(&mut queue),
        None,
        Some(&reg),
    )
    .expect_err("must reject non-native suite");
    assert_eq!(err.code, ErrorCode::TxErrSigAlgInvalid);
}

#[test]
fn validate_stealth_bad_covenant_data_q() {
    let kp = Mldsa87Keypair::generate().expect("kp");
    let entry = UtxoEntry {
        value: 100,
        covenant_type: COV_TYPE_CORE_STEALTH,
        covenant_data: vec![0u8; 10], // wrong length (not 1600)
        creation_height: 0,
        created_by_coinbase: false,
    };
    let (tx, ii, iv, cid) = test_tx_context();
    let mut cache = SighashV1PrehashCache::new(&tx).expect("cache");
    let witness = sign_witness(&kp, &tx, ii, iv, cid);
    let reg = SuiteRegistry::default_registry();
    let mut queue = SigCheckQueue::new(1).with_registry(&reg);
    let err = validate_stealth_spend_q(
        &entry,
        &witness,
        ii,
        iv,
        cid,
        0,
        &mut cache,
        Some(&mut queue),
        None,
        Some(&reg),
    )
    .expect_err("must reject bad covenant data");
    assert_eq!(err.code, ErrorCode::TxErrCovenantTypeInvalid);
}

#[test]
fn validate_stealth_non_canonical_sig_q() {
    let kp = Mldsa87Keypair::generate().expect("kp");
    let one_time_key_id = sha3_256(&kp.pubkey_bytes());
    let entry = make_stealth_entry(one_time_key_id);
    let (tx, ii, iv, cid) = test_tx_context();
    let mut cache = SighashV1PrehashCache::new(&tx).expect("cache");
    let mut witness = sign_witness(&kp, &tx, ii, iv, cid);
    witness.pubkey = vec![0u8; 10]; // non-canonical length
    let reg = SuiteRegistry::default_registry();
    let mut queue = SigCheckQueue::new(1).with_registry(&reg);
    let err = validate_stealth_spend_q(
        &entry,
        &witness,
        ii,
        iv,
        cid,
        0,
        &mut cache,
        Some(&mut queue),
        None,
        Some(&reg),
    )
    .expect_err("must reject non-canonical");
    assert_eq!(err.code, ErrorCode::TxErrSigNoncanonical);
}

#[test]
fn validate_stealth_key_binding_mismatch_q() {
    // Valid witness but pubkey hash doesn't match one_time_key_id in covenant
    let kp = Mldsa87Keypair::generate().expect("kp");
    let wrong_key_id = [0xCC; 32]; // doesn't match sha3_256(kp.pubkey_bytes())
    let entry = make_stealth_entry(wrong_key_id);
    let (tx, ii, iv, cid) = test_tx_context();
    let mut cache = SighashV1PrehashCache::new(&tx).expect("cache");
    let witness = sign_witness(&kp, &tx, ii, iv, cid);
    let reg = SuiteRegistry::default_registry();
    let mut queue = SigCheckQueue::new(1).with_registry(&reg);
    let err = validate_stealth_spend_q(
        &entry,
        &witness,
        ii,
        iv,
        cid,
        0,
        &mut cache,
        Some(&mut queue),
        None,
        Some(&reg),
    )
    .expect_err("must reject key binding mismatch");
    assert_eq!(err.code, ErrorCode::TxErrSigInvalid);
}

// Queue Concurrency Tests (2)

#[test]
fn parallel_stress_valid_sigs_q() {
    let keypair = Mldsa87Keypair::generate().expect("keypair");
    let mut queue = SigCheckQueue::new(4);
    for i in 0..16u8 {
        let mut digest = [0u8; 32];
        digest[0] = i;
        let sig = keypair.sign_digest32(digest).expect("sign");
        queue
            .push(
                SUITE_ID_ML_DSA_87,
                &keypair.pubkey_bytes(),
                &sig,
                digest,
                TxError::new(ErrorCode::TxErrSigInvalid, "parallel"),
            )
            .expect("push");
    }
    queue.flush().expect("parallel flush must succeed");
    assert!(queue.is_empty());
}

#[test]
fn concurrent_flush_safety_q() {
    // Flush after mixed valid/invalid ensures deterministic error from first failure
    let kp_good = Mldsa87Keypair::generate().expect("good kp");
    let kp_bad = Mldsa87Keypair::generate().expect("bad kp");
    let mut queue = SigCheckQueue::new(2);
    let digest = [0x99; 32];
    let good_sig = kp_good.sign_digest32(digest).expect("sign");
    let bad_sig = kp_bad.sign_digest32(digest).expect("sign");
    // First: valid
    queue
        .push(
            SUITE_ID_ML_DSA_87,
            &kp_good.pubkey_bytes(),
            &good_sig,
            digest,
            TxError::new(ErrorCode::TxErrSigInvalid, "good"),
        )
        .expect("push good");
    // Second: invalid (signed by kp_bad, verified against kp_good's pubkey)
    queue
        .push(
            SUITE_ID_ML_DSA_87,
            &kp_good.pubkey_bytes(),
            &bad_sig,
            digest,
            TxError::new(ErrorCode::TxErrSigInvalid, "bad-cross"),
        )
        .expect("push bad");
    let err = queue.flush().expect_err("mixed flush must fail");
    assert_eq!(err.code, ErrorCode::TxErrSigInvalid);
}

// Extended error path tests (4)

#[test]
fn validate_htlc_extended_payload_validation_q() {
    // Claim payload declares preimage length but actual data doesn't match
    let (entry, mut path_item, sig_item, tx, ii, iv, cid, reg) = htlc_claim_fixture();
    // Build payload with declared length=32 but only 3 bytes of payload data total
    let mut bad_payload = vec![0x00]; // claim path
    bad_payload.extend_from_slice(&32u16.to_le_bytes()); // declares 32 bytes
                                                         // but we only have the 3-byte header, no actual preimage data → length mismatch
    path_item.signature = bad_payload;
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
    .expect_err("must reject payload length mismatch");
    assert_eq!(err.code, ErrorCode::TxErrParse);
}

#[test]
fn validate_htlc_refund_extended_safety_q() {
    // Refund path with extra bytes in payload (should be exactly 1 byte)
    let claim_kp = Mldsa87Keypair::generate().expect("claim kp");
    let refund_kp = Mldsa87Keypair::generate().expect("refund kp");
    let claim_key_id = sha3_256(&claim_kp.pubkey_bytes());
    let refund_key_id = sha3_256(&refund_kp.pubkey_bytes());
    let mut cov = Vec::with_capacity(MAX_HTLC_COVENANT_DATA as usize);
    cov.extend_from_slice(&sha3_256(b"refund-extended-test"));
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
        pubkey: refund_key_id.to_vec(),
        signature: vec![0x01, 0x00], // 2 bytes instead of 1
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
    .expect_err("must reject refund payload with extra bytes");
    assert_eq!(err.code, ErrorCode::TxErrParse);
}

#[test]
fn validate_p2pk_extended_validation_q() {
    // P2PK covenant_data has correct length but wrong suite_id byte
    let kp = Mldsa87Keypair::generate().expect("kp");
    let pubkey = kp.pubkey_bytes();
    let mut cov = p2pk_covenant_data_for_pubkey(&pubkey);
    cov[0] = 0xFE; // wrong suite_id prefix
    let entry = UtxoEntry {
        value: 100,
        covenant_type: COV_TYPE_P2PK,
        covenant_data: cov,
        creation_height: 0,
        created_by_coinbase: false,
    };
    let (tx, ii, iv, cid) = test_tx_context();
    let mut cache = SighashV1PrehashCache::new(&tx).expect("cache");
    let witness = sign_witness(&kp, &tx, ii, iv, cid);
    let reg = SuiteRegistry::default_registry();
    let mut queue = SigCheckQueue::new(1).with_registry(&reg);
    let err = validate_p2pk_spend_q(
        &entry,
        &witness,
        ii,
        iv,
        cid,
        0,
        &mut cache,
        Some(&mut queue),
        None,
        Some(&reg),
    )
    .expect_err("must reject covenant suite mismatch");
    assert_eq!(err.code, ErrorCode::TxErrCovenantTypeInvalid);
}

#[test]
fn validate_stealth_extended_safety_q() {
    // Stealth covenant data with exact right length but
    // embedded ciphertext is zeroed — key binding still must match
    let kp = Mldsa87Keypair::generate().expect("kp");
    let one_time_key_id = sha3_256(&kp.pubkey_bytes());
    let entry = make_stealth_entry(one_time_key_id);
    let (tx, ii, iv, cid) = test_tx_context();
    let mut cache = SighashV1PrehashCache::new(&tx).expect("cache");
    let witness = sign_witness(&kp, &tx, ii, iv, cid);
    let reg = SuiteRegistry::default_registry();
    let mut queue = SigCheckQueue::new(1).with_registry(&reg);
    // This should SUCCEED (key binding matches)
    validate_stealth_spend_q(
        &entry,
        &witness,
        ii,
        iv,
        cid,
        0,
        &mut cache,
        Some(&mut queue),
        None,
        Some(&reg),
    )
    .expect("stealth with zeroed ciphertext must pass validation");
    assert_eq!(queue.len(), 1);
    queue.flush().expect("flush");
}
