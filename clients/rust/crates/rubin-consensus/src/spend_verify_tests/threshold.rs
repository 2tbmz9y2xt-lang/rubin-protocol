use super::*;

// ======== Threshold Sig at Height Tests (10) ========

#[test]
fn threshold_at_height_nil_providers_falls_back() {
    // No rotation, no registry -> defaults
    let keypair = Mldsa87Keypair::generate().expect("keypair");
    let key_id = sha3_256(&keypair.pubkey_bytes());
    let (tx, input_index, input_value, chain_id) = dummy_tx_ctx();
    let w = sign_witness(&keypair, &tx, input_index, input_value, chain_id);

    let mut cache = SighashV1PrehashCache::new(&tx).expect("cache");
    let result = validate_threshold_sig_spend_at_height(
        &[key_id],
        1,
        &[w],
        &tx,
        input_index,
        input_value,
        chain_id,
        0,
        "test",
        &mut cache,
        None,
        None,
    );

    assert!(result.is_ok(), "1-of-1 valid threshold should verify");
}

#[test]
fn threshold_at_height_sentinel_passthrough() {
    // SENTINEL suite should be skipped (keyless)
    let keypair = Mldsa87Keypair::generate().expect("keypair");
    let key_id = sha3_256(&keypair.pubkey_bytes());
    let (tx, input_index, input_value, chain_id) = dummy_tx_ctx();
    let w1 = WitnessItem {
        suite_id: SUITE_ID_SENTINEL,
        pubkey: vec![],
        signature: vec![],
    };
    let w2 = sign_witness(&keypair, &tx, input_index, input_value, chain_id);

    let mut cache = SighashV1PrehashCache::new(&tx).expect("cache");
    let result = validate_threshold_sig_spend_at_height(
        &[key_id, key_id],
        1,
        &[w1, w2],
        &tx,
        input_index,
        input_value,
        chain_id,
        0,
        "test",
        &mut cache,
        None,
        None,
    );

    assert!(result.is_ok(), "sentinel should be skipped");
}

#[test]
fn threshold_at_height_non_native_suite_rejects() {
    // Suite 0xFF not in native spend set
    let key_id = [0x11; 32];
    let (tx, input_index, input_value, chain_id) = dummy_tx_ctx();
    let w = WitnessItem {
        suite_id: 0xFF,
        pubkey: vec![0x01; ML_DSA_87_PUBKEY_BYTES as usize],
        signature: vec![0x02; ML_DSA_87_SIG_BYTES as usize + 1],
    };

    let mut cache = SighashV1PrehashCache::new(&tx).expect("cache");
    let err = validate_threshold_sig_spend_at_height(
        &[key_id],
        1,
        &[w],
        &tx,
        input_index,
        input_value,
        chain_id,
        0,
        "test",
        &mut cache,
        None,
        None,
    )
    .expect_err("bad suite");

    assert_eq!(err.code, ErrorCode::TxErrSigAlgInvalid);
}

#[test]
fn threshold_at_height_slot_count_mismatch() {
    // Different number of witnesses vs keys
    let key_id = [0x11; 32];
    let (tx, input_index, input_value, chain_id) = dummy_tx_ctx();

    let mut cache = SighashV1PrehashCache::new(&tx).expect("cache");
    let err = validate_threshold_sig_spend_at_height(
        &[key_id, key_id], // 2 keys
        1,
        &[], // 0 witnesses
        &tx,
        input_index,
        input_value,
        chain_id,
        0,
        "test",
        &mut cache,
        None,
        None,
    )
    .expect_err("mismatch");

    assert_eq!(err.code, ErrorCode::TxErrParse);
}

#[test]
fn threshold_at_height_valid_sigs_meets_threshold() {
    // 1-of-2 threshold with one valid signature
    let keypair1 = Mldsa87Keypair::generate().expect("keypair1");
    let keypair2 = Mldsa87Keypair::generate().expect("keypair2");
    let key_id1 = sha3_256(&keypair1.pubkey_bytes());
    let key_id2 = sha3_256(&keypair2.pubkey_bytes());
    let (tx, input_index, input_value, chain_id) = dummy_tx_ctx();
    let w1 = sign_witness(&keypair1, &tx, input_index, input_value, chain_id);
    let w2 = WitnessItem {
        suite_id: SUITE_ID_SENTINEL,
        pubkey: vec![],
        signature: vec![],
    };

    let mut cache = SighashV1PrehashCache::new(&tx).expect("cache");
    let result = validate_threshold_sig_spend_at_height(
        &[key_id1, key_id2],
        1,
        &[w1, w2],
        &tx,
        input_index,
        input_value,
        chain_id,
        0,
        "test",
        &mut cache,
        None,
        None,
    );

    assert!(result.is_ok(), "1-of-2 with one valid should pass");
}

#[test]
fn threshold_at_height_threshold_not_met() {
    // Threshold 2 but only 1 valid signature
    let keypair1 = Mldsa87Keypair::generate().expect("keypair1");
    let keypair2 = Mldsa87Keypair::generate().expect("keypair2");
    let (tx, input_index, input_value, chain_id) = dummy_tx_ctx();
    let mut bad_sig = sign_witness(&keypair1, &tx, input_index, input_value, chain_id);
    bad_sig.signature[0] ^= 0xFF; // corrupt signature
    let w2 = sign_witness(&keypair2, &tx, input_index, input_value, chain_id);

    let key_id1 = sha3_256(&keypair1.pubkey_bytes());
    let key_id2 = sha3_256(&keypair2.pubkey_bytes());

    let mut cache = SighashV1PrehashCache::new(&tx).expect("cache");
    let err = validate_threshold_sig_spend_at_height(
        &[key_id1, key_id2],
        2,
        &[bad_sig, w2],
        &tx,
        input_index,
        input_value,
        chain_id,
        0,
        "test",
        &mut cache,
        None,
        None,
    )
    .expect_err("threshold not met");

    assert_eq!(err.code, ErrorCode::TxErrSigInvalid);
}

#[test]
fn threshold_at_height_sentinel_with_payload_rejects() {
    // SENTINEL suite with non-empty pubkey/signature
    let (tx, input_index, input_value, chain_id) = dummy_tx_ctx();
    let w = WitnessItem {
        suite_id: SUITE_ID_SENTINEL,
        pubkey: vec![0x01], // sentinel must be keyless
        signature: vec![],
    };

    let mut cache = SighashV1PrehashCache::new(&tx).expect("cache");
    let err = validate_threshold_sig_spend_at_height(
        &[[0x11; 32]],
        1,
        &[w],
        &tx,
        input_index,
        input_value,
        chain_id,
        0,
        "test",
        &mut cache,
        None,
        None,
    )
    .expect_err("sentinel payload");

    assert_eq!(err.code, ErrorCode::TxErrParse);
}

#[test]
fn threshold_at_height_wrong_lengths() {
    // Non-canonical witness item lengths
    let (tx, input_index, input_value, chain_id) = dummy_tx_ctx();
    let w = WitnessItem {
        suite_id: SUITE_ID_ML_DSA_87,
        pubkey: vec![0x01; 10], // wrong length
        signature: vec![0x02; 10],
    };

    let mut cache = SighashV1PrehashCache::new(&tx).expect("cache");
    let err = validate_threshold_sig_spend_at_height(
        &[[0x11; 32]],
        1,
        &[w],
        &tx,
        input_index,
        input_value,
        chain_id,
        0,
        "test",
        &mut cache,
        None,
        None,
    )
    .expect_err("wrong lengths");

    assert_eq!(err.code, ErrorCode::TxErrSigNoncanonical);
}

#[test]
fn threshold_at_height_not_registered() {
    // Suite not in registry
    let mut suites = BTreeMap::new();
    suites.insert(
        SUITE_ID_ML_DSA_87,
        SuiteParams {
            suite_id: SUITE_ID_ML_DSA_87,
            pubkey_len: ML_DSA_87_PUBKEY_BYTES,
            sig_len: ML_DSA_87_SIG_BYTES,
            verify_cost: 8,
            alg_name: "ML-DSA-87",
        },
    );
    let registry = SuiteRegistry::with_suites(suites);

    let (tx, input_index, input_value, chain_id) = dummy_tx_ctx();
    let w = WitnessItem {
        suite_id: 0xBB, // not in registry
        pubkey: vec![0x01; ML_DSA_87_PUBKEY_BYTES as usize],
        signature: vec![0x02; ML_DSA_87_SIG_BYTES as usize + 1],
    };

    let mut cache = SighashV1PrehashCache::new(&tx).expect("cache");
    let err = validate_threshold_sig_spend_at_height(
        &[[0x11; 32]],
        1,
        &[w],
        &tx,
        input_index,
        input_value,
        chain_id,
        0,
        "test",
        &mut cache,
        None,
        Some(&registry),
    )
    .expect_err("unregistered suite");

    assert_eq!(err.code, ErrorCode::TxErrSigAlgInvalid);
}

#[test]
fn threshold_at_height_sig_verify_error() {
    // Corrupted signature should fail verification
    let keypair = Mldsa87Keypair::generate().expect("keypair");
    let key_id = sha3_256(&keypair.pubkey_bytes());
    let (tx, input_index, input_value, chain_id) = dummy_tx_ctx();
    let mut w = sign_witness(&keypair, &tx, input_index, input_value, chain_id);
    w.signature[0] ^= 0xFF; // corrupt

    let mut cache = SighashV1PrehashCache::new(&tx).expect("cache");
    let err = validate_threshold_sig_spend_at_height(
        &[key_id],
        1,
        &[w],
        &tx,
        input_index,
        input_value,
        chain_id,
        0,
        "test",
        &mut cache,
        None,
        None,
    )
    .expect_err("bad signature");

    assert_eq!(err.code, ErrorCode::TxErrSigInvalid);
}

#[test]
fn threshold_at_height_core_multisig_suite_not_native_message_matches_go_surface() {
    let (tx, input_index, input_value, chain_id) = dummy_tx_ctx();
    let mut cache = SighashV1PrehashCache::new(&tx).expect("cache");
    let err = validate_threshold_sig_spend_at_height(
        &[[0x11; 32]],
        1,
        &[WitnessItem {
            suite_id: 0xBB,
            pubkey: vec![],
            signature: vec![],
        }],
        &tx,
        input_index,
        input_value,
        chain_id,
        0,
        "CORE_MULTISIG",
        &mut cache,
        None,
        None,
    )
    .expect_err("suite not in native spend set");
    assert_eq!(err.code, ErrorCode::TxErrSigAlgInvalid);
    assert_eq!(err.msg, "CORE_MULTISIG suite not in native spend set");
}

#[test]
fn threshold_at_height_core_vault_suite_not_registered_message_matches_go_surface() {
    let (tx, input_index, input_value, chain_id) = dummy_tx_ctx();
    let mut cache = SighashV1PrehashCache::new(&tx).expect("cache");
    let only_unregistered = TestSpendSetRotation {
        spend: NativeSuiteSet::new(&[0xBB]),
    };
    let default_registry = SuiteRegistry::default_registry();
    let err = validate_threshold_sig_spend_at_height(
        &[[0x11; 32]],
        1,
        &[WitnessItem {
            suite_id: 0xBB,
            pubkey: vec![0x01; ML_DSA_87_PUBKEY_BYTES as usize],
            signature: vec![0x02; ML_DSA_87_SIG_BYTES as usize + 1],
        }],
        &tx,
        input_index,
        input_value,
        chain_id,
        0,
        "CORE_VAULT",
        &mut cache,
        Some(&only_unregistered),
        Some(&default_registry),
    )
    .expect_err("suite not registered");
    assert_eq!(err.code, ErrorCode::TxErrSigAlgInvalid);
    assert_eq!(err.msg, "CORE_VAULT suite not registered");
}

#[test]
fn threshold_at_height_core_multisig_key_binding_message_matches_go_surface() {
    let (tx, input_index, input_value, chain_id) = dummy_tx_ctx();
    let mut cache = SighashV1PrehashCache::new(&tx).expect("cache");
    let keypair = Mldsa87Keypair::generate().expect("keypair binding");
    let witness = sign_witness(&keypair, &tx, input_index, input_value, chain_id);
    let err = validate_threshold_sig_spend_at_height(
        &[[0xEE; 32]],
        1,
        &[witness],
        &tx,
        input_index,
        input_value,
        chain_id,
        0,
        "CORE_MULTISIG",
        &mut cache,
        None,
        None,
    )
    .expect_err("key binding mismatch");
    assert_eq!(err.code, ErrorCode::TxErrSigInvalid);
    assert_eq!(err.msg, "CORE_MULTISIG key binding mismatch");
}

#[test]
fn threshold_at_height_core_vault_signature_invalid_message_matches_go_surface() {
    let (tx, input_index, input_value, chain_id) = dummy_tx_ctx();
    let mut cache = SighashV1PrehashCache::new(&tx).expect("cache");
    let keypair = Mldsa87Keypair::generate().expect("keypair invalid sig");
    let mut witness = sign_witness(&keypair, &tx, input_index, input_value, chain_id);
    witness.signature[0] ^= 0xFF;
    let key_id = sha3_256(&keypair.pubkey_bytes());
    let err = validate_threshold_sig_spend_at_height(
        &[key_id],
        1,
        &[witness],
        &tx,
        input_index,
        input_value,
        chain_id,
        0,
        "CORE_VAULT",
        &mut cache,
        None,
        None,
    )
    .expect_err("invalid signature");
    assert_eq!(err.code, ErrorCode::TxErrSigInvalid);
    assert_eq!(err.msg, "CORE_VAULT signature invalid");
}

#[test]
fn threshold_at_height_core_vault_threshold_not_met_message_matches_go_surface() {
    let (tx, input_index, input_value, chain_id) = dummy_tx_ctx();
    let mut cache = SighashV1PrehashCache::new(&tx).expect("cache");
    let err = validate_threshold_sig_spend_at_height(
        &[[0x22; 32]],
        1,
        &[WitnessItem {
            suite_id: SUITE_ID_SENTINEL,
            pubkey: vec![],
            signature: vec![],
        }],
        &tx,
        input_index,
        input_value,
        chain_id,
        0,
        "CORE_VAULT",
        &mut cache,
        None,
        None,
    )
    .expect_err("threshold not met");
    assert_eq!(err.code, ErrorCode::TxErrSigInvalid);
    assert_eq!(err.msg, "CORE_VAULT threshold not met");
}
#[test]
fn threshold_queue_flush_preserves_core_context_signature_invalid() {
    let keypair = Mldsa87Keypair::generate().expect("keypair");
    let key_id = sha3_256(&keypair.pubkey_bytes());
    let (tx, input_index, input_value, chain_id) = dummy_tx_ctx();
    let mut witness = sign_witness(&keypair, &tx, input_index, input_value, chain_id);
    witness.signature[0] ^= 0xFF;
    let mut cache = SighashV1PrehashCache::new(&tx).expect("cache");
    let registry = SuiteRegistry::default_registry();
    let mut queue = crate::sig_queue::SigCheckQueue::new(1).with_registry(&registry);
    validate_threshold_sig_spend_q(
        &[key_id],
        1,
        &[witness],
        input_index,
        input_value,
        chain_id,
        0,
        "CORE_MULTISIG",
        &mut cache,
        Some(&mut queue),
        None,
        Some(&registry),
    )
    .expect("queue path should defer signature verification");
    let err = queue
        .flush()
        .expect_err("flush must surface invalid signature");
    assert_eq!(err.code, ErrorCode::TxErrSigInvalid);
    assert_eq!(err.msg, "CORE_MULTISIG signature invalid");
}
