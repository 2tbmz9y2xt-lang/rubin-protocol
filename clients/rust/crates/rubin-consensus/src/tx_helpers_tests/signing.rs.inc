#[test]
fn sign_transaction_populates_canonical_mldsa_witness() {
    let pubkey = test_pubkey(0x33);
    let signer = StubSigner {
        pubkey: pubkey.clone(),
        signature: test_signature(0x44),
    };
    let mut tx = test_tx();
    let chain_id = [0x55; 32];

    sign_transaction(&mut tx, &test_utxos(&pubkey), chain_id, &signer).expect("sign");

    assert_eq!(tx.witness.len(), 1);
    let item = &tx.witness[0];
    assert_eq!(item.suite_id, SUITE_ID_ML_DSA_87);
    assert_eq!(item.pubkey, pubkey);
    assert_eq!(item.signature.len(), (ML_DSA_87_SIG_BYTES + 1) as usize);
    assert_eq!(item.signature.last(), Some(&SIGHASH_ALL));

    let bytes = marshal_tx(&tx).expect("marshal signed tx");
    let (parsed, _, _, consumed) = parse_tx(&bytes).expect("parse signed tx");
    assert_eq!(consumed, bytes.len());
    assert_eq!(parsed, tx);
}

#[test]
fn sign_transaction_rejects_utxo_key_binding_mismatch() {
    let signer = StubSigner {
        pubkey: test_pubkey(0x33),
        signature: test_signature(0x44),
    };
    let mut tx = test_tx();
    let err = sign_transaction(&mut tx, &test_utxos(&test_pubkey(0x22)), [0u8; 32], &signer)
        .expect_err("key mismatch must fail");
    assert_eq!(err.code, ErrorCode::TxErrSigInvalid);
}

#[test]
fn sign_transaction_rejects_noncanonical_signer_lengths() {
    let signer = StubSigner {
        pubkey: vec![0u8; (ML_DSA_87_PUBKEY_BYTES as usize) - 1],
        signature: test_signature(0x44),
    };
    let mut tx = test_tx();
    let err = sign_transaction(&mut tx, &test_utxos(&test_pubkey(0x33)), [0u8; 32], &signer)
        .expect_err("bad pubkey len must fail");
    assert_eq!(err.code, ErrorCode::TxErrSigNoncanonical);
}

#[test]
fn sign_transaction_rejects_empty_input_list() {
    let signer = StubSigner {
        pubkey: test_pubkey(0x33),
        signature: test_signature(0x44),
    };
    let mut tx = test_tx();
    tx.inputs.clear();
    let err =
        sign_transaction(&mut tx, &HashMap::new(), [0u8; 32], &signer).expect_err("empty");
    assert_eq!(err.code, ErrorCode::TxErrParse);
}

#[test]
fn sign_transaction_rejects_missing_utxo() {
    let signer = StubSigner {
        pubkey: test_pubkey(0x33),
        signature: test_signature(0x44),
    };
    let mut tx = test_tx();
    let err =
        sign_transaction(&mut tx, &HashMap::new(), [0u8; 32], &signer).expect_err("missing");
    assert_eq!(err.code, ErrorCode::TxErrMissingUtxo);
}

#[test]
fn sign_transaction_rejects_non_p2pk_signing_entry() {
    let signer = StubSigner {
        pubkey: test_pubkey(0x33),
        signature: test_signature(0x44),
    };
    let mut tx = test_tx();
    let utxos = HashMap::from([(
        Outpoint {
            txid: [0x11; 32],
            vout: 0,
        },
        UtxoEntry {
            value: 10,
            covenant_type: 0x0104,
            covenant_data: vec![1, 1],
            creation_height: 0,
            created_by_coinbase: false,
        },
    )]);
    let err =
        sign_transaction(&mut tx, &utxos, [0u8; 32], &signer).expect_err("non-p2pk must fail");
    assert_eq!(err.code, ErrorCode::TxErrCovenantTypeInvalid);
}

#[test]
fn sign_transaction_rejects_invalid_p2pk_covenant_data() {
    let signer = StubSigner {
        pubkey: test_pubkey(0x33),
        signature: test_signature(0x44),
    };
    let mut tx = test_tx();
    let utxos = HashMap::from([(
        Outpoint {
            txid: [0x11; 32],
            vout: 0,
        },
        UtxoEntry {
            value: 10,
            covenant_type: COV_TYPE_P2PK,
            covenant_data: vec![SUITE_ID_ML_DSA_87; 32],
            creation_height: 0,
            created_by_coinbase: false,
        },
    )]);
    let err = sign_transaction(&mut tx, &utxos, [0u8; 32], &signer)
        .expect_err("invalid covenant data");
    assert_eq!(err.code, ErrorCode::TxErrCovenantTypeInvalid);
}

#[test]
fn sign_transaction_rejects_noncanonical_signature_length() {
    let pubkey = test_pubkey(0x33);
    let signer = StubSigner {
        pubkey: pubkey.clone(),
        signature: vec![0x44; (ML_DSA_87_SIG_BYTES as usize) - 1],
    };
    let mut tx = test_tx();
    let err =
        sign_transaction(&mut tx, &test_utxos(&pubkey), [0u8; 32], &signer).expect_err("sig");
    assert_eq!(err.code, ErrorCode::TxErrSigNoncanonical);
}

#[test]
fn sign_transaction_propagates_signer_errors() {
    let pubkey = test_pubkey(0x77);
    let mut tx = test_tx();
    let err = sign_transaction(&mut tx, &test_utxos(&pubkey), [0u8; 32], &ErrorSigner)
        .expect_err("signer error");
    assert_eq!(err.code, ErrorCode::TxErrSigInvalid);
}
