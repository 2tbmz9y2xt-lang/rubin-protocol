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

fn p2pk_overlap_registry() -> SuiteRegistry {
    let default = SuiteRegistry::default_registry();
    let mut suites = BTreeMap::new();
    for suite_id in [0x01, 0x02] {
        let mut params = default.lookup(0x01).expect("default suite").clone();
        params.suite_id = suite_id;
        suites.insert(suite_id, params);
    }
    SuiteRegistry::with_suites(suites)
}

#[test]
fn p2pk_suite_error_order() {
    let registry = p2pk_overlap_registry();
    let (tx, ii, iv, cid) = dummy_tx_ctx();
    for name in [
        "suite_mismatch",
        "key_binding",
        "sighash_type",
        "length_0",
        "length_1",
        "length_32",
        "length_34",
        "membership",
        "pubkey_length",
        "signature_length",
        "matching_suite",
    ] {
        let mut rotation = TestSpendSetRotation {
            spend: NativeSuiteSet::new(&[0x01, 0x02]),
        };
        let mut w = WitnessItem {
            suite_id: 0x02,
            pubkey: vec![0; 2592],
            signature: vec![0; 4628],
        };
        w.signature[4627] = 0x01;
        match name {
            "sighash_type" => w.signature[4627] = 0x04,
            "pubkey_length" => w.pubkey.truncate(2591),
            "signature_length" => {
                w.signature.remove(0);
            }
            _ => {}
        }
        let mut entry = make_p2pk_entry(&w.pubkey);
        let (mut code, mut message) = (
            "TX_ERR_SIG_ALG_INVALID",
            "CORE_P2PK covenant_data suite_id mismatch",
        );
        match name {
            "key_binding" => entry.covenant_data[1] ^= 1,
            "matching_suite" => {
                entry.covenant_data[0] = 0x02;
                entry.covenant_data[1] ^= 1;
                code = "TX_ERR_SIG_INVALID";
                message = "CORE_P2PK key binding mismatch";
            }
            "length_0" | "length_1" | "length_32" | "length_34" => {
                let length = match name {
                    "length_0" => 0,
                    "length_1" => 1,
                    "length_32" => 32,
                    _ => 34,
                };
                entry.covenant_data.resize(length, 0);
                if length == 34 {
                    entry.covenant_data[0] = w.suite_id;
                }
                code = "TX_ERR_COVENANT_TYPE_INVALID";
                message = "CORE_P2PK covenant_data invalid";
            }
            "membership" => {
                rotation.spend = NativeSuiteSet::new(&[0x01]);
                message = "CORE_P2PK suite not in native spend set";
            }
            "pubkey_length" | "signature_length" => {
                code = "TX_ERR_SIG_NONCANONICAL";
                message = "non-canonical witness item lengths";
            }
            _ => {}
        }
        let mut cache = SighashV1PrehashCache::new(&tx).expect("cache");
        let err = validate_p2pk_spend_q(
            &entry,
            &w,
            ii,
            iv,
            cid,
            1,
            &mut cache,
            None,
            Some(&rotation),
            Some(&registry),
        )
        .expect_err(name);
        assert_eq!(err.code.as_str(), code, "{name}");
        assert_eq!(err.msg, message, "{name}");
    }
}

#[test]
fn p2pk_rotation_overlap_apply_suite_mismatch() {
    let registry = p2pk_overlap_registry();
    let rotation = TestSpendSetRotation {
        spend: NativeSuiteSet::new(&[0x01, 0x02]),
    };
    let (mut tx, _, _, cid) = dummy_tx_ctx();
    tx.outputs[0].covenant_data[0] = 0x01;
    let mut w = WitnessItem {
        suite_id: 0x02,
        pubkey: vec![0; 2592],
        signature: vec![0; 4628],
    };
    w.signature[4627] = 0x01;
    let entry = make_p2pk_entry(&w.pubkey);
    tx.witness = vec![w];
    let utxos = std::collections::HashMap::from([(
        crate::utxo_basic::Outpoint {
            txid: tx.inputs[0].prev_txid,
            vout: 0,
        },
        entry,
    )]);
    let before = utxos.clone();
    let result = crate::apply_non_coinbase_tx_basic_update_with_mtp_and_suite_context(
        &tx,
        [0; 32],
        &utxos,
        1,
        0,
        0,
        cid,
        Some(&rotation),
        Some(&registry),
    );
    assert_eq!(utxos, before, "retained caller UTXOs");
    let err = result.expect_err("rotation overlap suite mismatch");
    assert_eq!(err.code.as_str(), "TX_ERR_SIG_ALG_INVALID");
    assert_eq!(err.msg, "CORE_P2PK covenant_data suite_id mismatch");
}
