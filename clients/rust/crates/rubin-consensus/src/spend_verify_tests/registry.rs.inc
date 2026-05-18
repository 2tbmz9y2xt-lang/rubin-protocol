#[test]
fn extract_crypto_sig_and_sighash_rejects_missing_trailer() {
    let w = WitnessItem {
        suite_id: SUITE_ID_ML_DSA_87,
        pubkey: vec![],
        signature: vec![],
    };
    let err = extract_crypto_sig_and_sighash(&w).expect_err("missing sighash trailer");
    assert_eq!(err.code, ErrorCode::TxErrParse);
}

#[test]
fn extract_crypto_sig_and_sighash_rejects_invalid_type() {
    let w = WitnessItem {
        suite_id: SUITE_ID_ML_DSA_87,
        pubkey: vec![],
        signature: vec![0xAA, 0xFF],
    };
    let err = extract_crypto_sig_and_sighash(&w).expect_err("invalid sighash type");
    assert_eq!(err.code, ErrorCode::TxErrSighashTypeInvalid);
}

#[test]
fn extract_crypto_sig_and_sighash_preserves_crypto_sig_bytes() {
    let w = WitnessItem {
        suite_id: SUITE_ID_ML_DSA_87,
        pubkey: vec![],
        signature: vec![0xAA, 0xBB, SIGHASH_ALL],
    };
    let (crypto_sig, sighash_type) =
        extract_crypto_sig_and_sighash(&w).expect("valid trailing sighash");
    assert_eq!(crypto_sig, &[0xAA, 0xBB]);
    assert_eq!(sighash_type, SIGHASH_ALL);
}

// ======== Registry & Lookup Tests (8) ========

#[test]
fn verify_sig_with_registry_nil_uses_default_live_registry() {
    // When registry is None, verify_sig_with_registry should use the
    // canonical default live registry rather than a separate legacy path.
    let keypair = Mldsa87Keypair::generate().expect("keypair");
    let pubkey = keypair.pubkey_bytes();
    let digest = [0x42; 32];
    let sig = keypair.sign_digest32(digest).expect("sign");

    let result = crate::verify_sig_openssl::verify_sig_with_registry(
        SUITE_ID_ML_DSA_87,
        &pubkey,
        &sig,
        &digest,
        None,
    )
    .expect("verify");

    assert!(
        result,
        "valid signature should verify via default live registry"
    );
}

#[test]
fn verify_sig_with_registry_unknown_suite_returns_error() {
    // Suite 0xFF not in registry
    let registry = SuiteRegistry::default_registry();
    let pubkey = vec![0x01; ML_DSA_87_PUBKEY_BYTES as usize];
    let sig = vec![0x02; ML_DSA_87_SIG_BYTES as usize];
    let digest = [0x42; 32];

    let err = crate::verify_sig_openssl::verify_sig_with_registry(
        0xFF,
        &pubkey,
        &sig,
        &digest,
        Some(&registry),
    )
    .expect_err("unknown suite should error");

    assert_eq!(err.code, ErrorCode::TxErrSigAlgInvalid);
}

#[test]
fn verify_sig_with_registry_known_suite_wrong_lengths() {
    // Suite registered but pubkey/sig lengths mismatch
    let registry = SuiteRegistry::default_registry();
    let pubkey = vec![0x01; 10]; // wrong length
    let sig = vec![0x02; 10]; // wrong length
    let digest = [0x42; 32];

    let result = crate::verify_sig_openssl::verify_sig_with_registry(
        SUITE_ID_ML_DSA_87,
        &pubkey,
        &sig,
        &digest,
        Some(&registry),
    )
    .expect("should not error on length check");

    assert!(!result, "wrong lengths should return false, not error");
}

#[test]
fn verify_sig_with_registry_known_suite_correct_lengths() {
    // Valid suite with correct lengths passes through to OpenSSL
    let keypair = Mldsa87Keypair::generate().expect("keypair");
    let pubkey = keypair.pubkey_bytes();
    let digest = [0x42; 32];
    let sig = keypair.sign_digest32(digest).expect("sign");
    let registry = SuiteRegistry::default_registry();

    let result = crate::verify_sig_openssl::verify_sig_with_registry(
        SUITE_ID_ML_DSA_87,
        &pubkey,
        &sig,
        &digest,
        Some(&registry),
    )
    .expect("verify with registry");

    assert!(result, "valid signature with registry should verify");
}

#[test]
fn verify_sig_with_registry_custom_suite() {
    // Custom registry entry with different suite ID
    let keypair = Mldsa87Keypair::generate().expect("keypair");
    let pubkey = keypair.pubkey_bytes();
    let digest = [0x42; 32];
    let sig = keypair.sign_digest32(digest).expect("sign");

    let mut suites = BTreeMap::new();
    suites.insert(
        0x05,
        SuiteParams {
            suite_id: 0x05,
            pubkey_len: ML_DSA_87_PUBKEY_BYTES,
            sig_len: ML_DSA_87_SIG_BYTES,
            verify_cost: VERIFY_COST_ML_DSA_87,
            alg_name: "ML-DSA-87",
        },
    );
    let registry = SuiteRegistry::with_suites(suites);

    let result = crate::verify_sig_openssl::verify_sig_with_registry(
        0x05,
        &pubkey,
        &sig,
        &digest,
        Some(&registry),
    )
    .expect("verify custom suite");

    assert!(result, "custom suite entry should verify");
}

#[test]
fn verify_sig_with_registry_rejects_unsupported_binding() {
    let mut suites = BTreeMap::new();
    suites.insert(
        0x05,
        SuiteParams {
            suite_id: 0x05,
            pubkey_len: 1312,
            sig_len: 2420,
            verify_cost: 4,
            alg_name: "ML-DSA-65",
        },
    );
    let registry = SuiteRegistry::with_suites(suites);
    let pubkey = vec![0x01; 1312];
    let sig = vec![0x02; 2420];
    let digest = [0x42; 32];

    let err = crate::verify_sig_openssl::verify_sig_with_registry(
        0x05,
        &pubkey,
        &sig,
        &digest,
        Some(&registry),
    )
    .expect_err("unsupported binding should fail closed");

    assert_eq!(err.code, ErrorCode::TxErrSigAlgInvalid);
    assert!(err.msg.contains("unsupported suite verifier binding"));
}

#[test]
fn verify_sig_with_registry_consensus_init_error() {
    // Empty inputs should trigger OpenSSL parse error
    let registry = SuiteRegistry::default_registry();
    let digest = [0x42; 32];

    let result = crate::verify_sig_openssl::verify_sig_with_registry(
        SUITE_ID_ML_DSA_87,
        &[],
        &[],
        &digest,
        Some(&registry),
    );

    // Empty inputs return false, not an error (length check happens first)
    let ok = result.expect("should not error");
    assert!(!ok, "empty inputs should fail verification");
}

#[test]
fn verify_sig_with_registry_openssl_error() {
    // Corrupted signature should fail verification
    let keypair = Mldsa87Keypair::generate().expect("keypair");
    let pubkey = keypair.pubkey_bytes();
    let digest = [0x42; 32];
    let mut sig = keypair.sign_digest32(digest).expect("sign");
    sig[0] ^= 0xFF; // corrupt first byte
    let registry = SuiteRegistry::default_registry();

    let result = crate::verify_sig_openssl::verify_sig_with_registry(
        SUITE_ID_ML_DSA_87,
        &pubkey,
        &sig,
        &digest,
        Some(&registry),
    )
    .expect("verify");

    assert!(!result, "corrupted signature should not verify");
}

#[test]
fn verify_sig_with_registry_verify_returns_false() {
    // Valid signature over different digest should fail
    let keypair = Mldsa87Keypair::generate().expect("keypair");
    let pubkey = keypair.pubkey_bytes();
    let digest1 = [0x42; 32];
    let sig = keypair.sign_digest32(digest1).expect("sign");
    let mut digest2 = digest1;
    digest2[0] ^= 0xFF;
    let registry = SuiteRegistry::default_registry();

    let result = crate::verify_sig_openssl::verify_sig_with_registry(
        SUITE_ID_ML_DSA_87,
        &pubkey,
        &sig,
        &digest2,
        Some(&registry),
    )
    .expect("verify");

    assert!(!result, "signature over different digest should not verify");
}
