use super::*;

// ======== Key & Sig with Registry Cache Tests (5) ========

#[test]
fn verify_key_sig_registry_cache_key_mismatch() {
    // sha3(pubkey) != expected_key_id
    let keypair = Mldsa87Keypair::generate().expect("keypair");
    let wrong_key_id = [0xFF; 32];
    let (tx, input_index, input_value, chain_id) = dummy_tx_ctx();
    let w = sign_witness(&keypair, &tx, input_index, input_value, chain_id);

    let mut cache = SighashV1PrehashCache::new(&tx).expect("cache");
    let registry = SuiteRegistry::default_registry();
    let err = verify_mldsa_key_and_sig_q(
        &w,
        wrong_key_id,
        input_index,
        input_value,
        chain_id,
        &mut cache,
        &registry,
        &mut None,
        TxError::new(ErrorCode::TxErrSigInvalid, "key mismatch"),
        TxError::new(ErrorCode::TxErrSigInvalid, "sig invalid"),
    )
    .expect_err("key mismatch");

    assert_eq!(err.code, ErrorCode::TxErrSigInvalid);
}

#[test]
fn verify_key_sig_registry_cache_sig_invalid() {
    // Valid key but bad signature
    let keypair = Mldsa87Keypair::generate().expect("keypair");
    let key_id = sha3_256(&keypair.pubkey_bytes());
    let (tx, input_index, input_value, chain_id) = dummy_tx_ctx();
    let mut w = sign_witness(&keypair, &tx, input_index, input_value, chain_id);
    w.signature[0] ^= 0xFF; // corrupt signature

    let mut cache = SighashV1PrehashCache::new(&tx).expect("cache");
    let registry = SuiteRegistry::default_registry();
    let err = verify_mldsa_key_and_sig_q(
        &w,
        key_id,
        input_index,
        input_value,
        chain_id,
        &mut cache,
        &registry,
        &mut None,
        TxError::new(ErrorCode::TxErrSigInvalid, "key mismatch"),
        TxError::new(ErrorCode::TxErrSigInvalid, "sig invalid"),
    )
    .expect_err("bad sig");

    assert_eq!(err.code, ErrorCode::TxErrSigInvalid);
}

#[test]
fn verify_key_sig_registry_cache_openssl_error() {
    // Empty pubkey should trigger key binding mismatch (sha3 of empty != key_id)
    let key_id = [0x11; 32];
    let (tx, input_index, input_value, chain_id) = dummy_tx_ctx();
    let w = WitnessItem {
        suite_id: SUITE_ID_ML_DSA_87,
        pubkey: vec![],
        signature: vec![SIGHASH_ALL],
    };

    let mut cache = SighashV1PrehashCache::new(&tx).expect("cache");
    let registry = SuiteRegistry::default_registry();
    let err = verify_mldsa_key_and_sig_q(
        &w,
        key_id,
        input_index,
        input_value,
        chain_id,
        &mut cache,
        &registry,
        &mut None,
        TxError::new(ErrorCode::TxErrSigInvalid, "key mismatch"),
        TxError::new(ErrorCode::TxErrSigInvalid, "sig invalid"),
    )
    .expect_err("key binding mismatch on empty pubkey");

    // Empty pubkey SHA3 won't match [0x11; 32], so we get key mismatch error
    assert_eq!(err.code, ErrorCode::TxErrSigInvalid);
}

#[test]
fn verify_key_sig_registry_cache_bad_sighash() {
    // Invalid sighash_type byte
    let keypair = Mldsa87Keypair::generate().expect("keypair");
    let key_id = sha3_256(&keypair.pubkey_bytes());
    let (tx, input_index, input_value, chain_id) = dummy_tx_ctx();
    let mut w = sign_witness(&keypair, &tx, input_index, input_value, chain_id);
    let last_idx = w.signature.len() - 1;
    w.signature[last_idx] = 0xFF; // invalid sighash_type

    let mut cache = SighashV1PrehashCache::new(&tx).expect("cache");
    let registry = SuiteRegistry::default_registry();
    let err = verify_mldsa_key_and_sig_q(
        &w,
        key_id,
        input_index,
        input_value,
        chain_id,
        &mut cache,
        &registry,
        &mut None,
        TxError::new(ErrorCode::TxErrSigInvalid, "key mismatch"),
        TxError::new(ErrorCode::TxErrSigInvalid, "sig invalid"),
    )
    .expect_err("bad sighash");

    assert_eq!(err.code, ErrorCode::TxErrSighashTypeInvalid);
}

#[test]
fn verify_key_sig_registry_cache_success() {
    // Full valid roundtrip: correct key, valid signature
    let keypair = Mldsa87Keypair::generate().expect("keypair");
    let key_id = sha3_256(&keypair.pubkey_bytes());
    let (tx, input_index, input_value, chain_id) = dummy_tx_ctx();
    let w = sign_witness(&keypair, &tx, input_index, input_value, chain_id);

    let mut cache = SighashV1PrehashCache::new(&tx).expect("cache");
    let registry = SuiteRegistry::default_registry();
    let result = verify_mldsa_key_and_sig_q(
        &w,
        key_id,
        input_index,
        input_value,
        chain_id,
        &mut cache,
        &registry,
        &mut None,
        TxError::new(ErrorCode::TxErrSigInvalid, "key mismatch"),
        TxError::new(ErrorCode::TxErrSigInvalid, "sig invalid"),
    );

    assert!(result.is_ok(), "valid key and sig should verify");
}

#[test]
fn p2pk_suite_invalid_rejected_sig_alg_invalid() {
    let entry = dummy_entry();
    let (tx, input_index, input_value, chain_id) = dummy_tx_ctx();
    let w = WitnessItem {
        suite_id: 0x02, // non-native / unknown suite
        pubkey: vec![0x01],
        signature: vec![0x01],
    };
    let err =
        validate_p2pk_spend(&entry, &w, &tx, input_index, input_value, chain_id, 0).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrSigAlgInvalid);
}
