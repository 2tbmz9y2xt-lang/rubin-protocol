// ======== P2PK Spend at Height Tests (7) ========

#[test]
fn p2pk_at_height_nil_providers_falls_back() {
    // No rotation, no registry -> use defaults (ML-DSA-87)
    let keypair = Mldsa87Keypair::generate().expect("keypair");
    let entry = make_p2pk_entry(&keypair.pubkey_bytes());
    let (tx, input_index, input_value, chain_id) = dummy_tx_ctx();
    let w = sign_witness(&keypair, &tx, input_index, input_value, chain_id);

    let mut cache = SighashV1PrehashCache::new(&tx).expect("cache");
    let result = validate_p2pk_spend_at_height(
        &entry,
        &w,
        &tx,
        input_index,
        input_value,
        chain_id,
        0,
        &mut cache,
        None,
        None,
    );

    assert!(result.is_ok(), "default providers should verify valid P2PK");
}

#[test]
fn p2pk_at_height_suite_not_in_spend_set() {
    // Suite 0xFF not in native spend set at height
    let entry = dummy_entry();
    let (tx, input_index, input_value, chain_id) = dummy_tx_ctx();
    let w = WitnessItem {
        suite_id: 0xFF,
        pubkey: vec![0x01; ML_DSA_87_PUBKEY_BYTES as usize],
        signature: vec![0x02; ML_DSA_87_SIG_BYTES as usize + 1],
    };

    let mut cache = SighashV1PrehashCache::new(&tx).expect("cache");
    let err = validate_p2pk_spend_at_height(
        &entry,
        &w,
        &tx,
        input_index,
        input_value,
        chain_id,
        0,
        &mut cache,
        None,
        None,
    )
    .expect_err("unknown suite");

    assert_eq!(err.code, ErrorCode::TxErrSigAlgInvalid);
}

#[test]
fn p2pk_at_height_wrong_lengths() {
    // Correct suite, wrong pubkey/sig lengths
    let entry = dummy_entry();
    let (tx, input_index, input_value, chain_id) = dummy_tx_ctx();
    let w = WitnessItem {
        suite_id: SUITE_ID_ML_DSA_87,
        pubkey: vec![0x01; 10], // wrong length
        signature: vec![0x02; 10],
    };

    let mut cache = SighashV1PrehashCache::new(&tx).expect("cache");
    let err = validate_p2pk_spend_at_height(
        &entry,
        &w,
        &tx,
        input_index,
        input_value,
        chain_id,
        0,
        &mut cache,
        None,
        None,
    )
    .expect_err("wrong lengths");

    assert_eq!(err.code, ErrorCode::TxErrSigNoncanonical);
}

#[test]
fn p2pk_at_height_valid_sig_success() {
    // Full valid P2PK spend path
    let keypair = Mldsa87Keypair::generate().expect("keypair");
    let entry = make_p2pk_entry(&keypair.pubkey_bytes());
    let (tx, input_index, input_value, chain_id) = dummy_tx_ctx();
    let w = sign_witness(&keypair, &tx, input_index, input_value, chain_id);

    let mut cache = SighashV1PrehashCache::new(&tx).expect("cache");
    let result = validate_p2pk_spend_at_height(
        &entry,
        &w,
        &tx,
        input_index,
        input_value,
        chain_id,
        0,
        &mut cache,
        None,
        None,
    );

    assert!(result.is_ok(), "valid P2PK should verify");
}

#[test]
fn p2pk_at_height_bad_covenant_data() {
    // Malformed covenant_data
    let entry = UtxoEntry {
        value: 1,
        covenant_type: COV_TYPE_P2PK,
        covenant_data: vec![0x99; 10], // too short
        creation_height: 0,
        created_by_coinbase: false,
    };
    let (tx, input_index, input_value, chain_id) = dummy_tx_ctx();
    let w = WitnessItem {
        suite_id: SUITE_ID_ML_DSA_87,
        pubkey: vec![0x01; ML_DSA_87_PUBKEY_BYTES as usize],
        signature: vec![0x02; ML_DSA_87_SIG_BYTES as usize + 1],
    };

    let mut cache = SighashV1PrehashCache::new(&tx).expect("cache");
    let err = validate_p2pk_spend_at_height(
        &entry,
        &w,
        &tx,
        input_index,
        input_value,
        chain_id,
        0,
        &mut cache,
        None,
        None,
    )
    .expect_err("bad covenant");

    assert_eq!(err.code, ErrorCode::TxErrCovenantTypeInvalid);
}

#[test]
fn p2pk_at_height_suite_not_registered() {
    // Suite in spend set but not in registry
    let mut covenant_data = vec![0xAA];
    covenant_data.extend_from_slice(&[0x11; 32]);
    let entry = UtxoEntry {
        value: 1,
        covenant_type: COV_TYPE_P2PK,
        covenant_data,
        creation_height: 0,
        created_by_coinbase: false,
    };
    let (tx, input_index, input_value, chain_id) = dummy_tx_ctx();

    // Create custom registry with only SUITE_ID_ML_DSA_87
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

    let w = WitnessItem {
        suite_id: 0xAA, // suite in covenant but not registered
        pubkey: vec![0x01; ML_DSA_87_PUBKEY_BYTES as usize],
        signature: vec![0x02; ML_DSA_87_SIG_BYTES as usize + 1],
    };

    let mut cache = SighashV1PrehashCache::new(&tx).expect("cache");
    let err = validate_p2pk_spend_at_height(
        &entry,
        &w,
        &tx,
        input_index,
        input_value,
        chain_id,
        0,
        &mut cache,
        None,
        Some(&registry),
    )
    .expect_err("unregistered suite");

    assert_eq!(err.code, ErrorCode::TxErrSigAlgInvalid);
}

#[test]
fn p2pk_at_height_key_binding_mismatch() {
    // sha3(pubkey) != covenant key_id
    let keypair = Mldsa87Keypair::generate().expect("keypair");
    let mut covenant_data = vec![SUITE_ID_ML_DSA_87];
    covenant_data.extend_from_slice(&[0xFF; 32]); // wrong key_id
    let entry = UtxoEntry {
        value: 1,
        covenant_type: COV_TYPE_P2PK,
        covenant_data,
        creation_height: 0,
        created_by_coinbase: false,
    };
    let (tx, input_index, input_value, chain_id) = dummy_tx_ctx();
    let w = sign_witness(&keypair, &tx, input_index, input_value, chain_id);

    let mut cache = SighashV1PrehashCache::new(&tx).expect("cache");
    let err = validate_p2pk_spend_at_height(
        &entry,
        &w,
        &tx,
        input_index,
        input_value,
        chain_id,
        0,
        &mut cache,
        None,
        None,
    )
    .expect_err("key binding mismatch");

    assert_eq!(err.code, ErrorCode::TxErrSigInvalid);
}
