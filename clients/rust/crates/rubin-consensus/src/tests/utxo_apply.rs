use super::*;

#[test]
fn apply_non_coinbase_tx_basic_missing_utxo() {
    let mut prev = [0u8; 32];
    prev[0] = 0xaa;
    let tx_bytes =
        tx_with_one_input_one_output(prev, 0, 1, COV_TYPE_P2PK, &valid_p2pk_covenant_data());
    let (tx, txid, _wtxid, _n) = parse_tx(&tx_bytes).expect("parse");
    let utxos: HashMap<Outpoint, UtxoEntry> = HashMap::new();

    let err = apply_non_coinbase_tx_basic(&tx, txid, &utxos, 100, 1000, ZERO_CHAIN_ID).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrMissingUtxo);
}

#[test]
fn apply_non_coinbase_tx_basic_spend_anchor_rejected() {
    let mut prev = [0u8; 32];
    prev[0] = 0xab;
    let tx_bytes =
        tx_with_one_input_one_output(prev, 0, 1, COV_TYPE_P2PK, &valid_p2pk_covenant_data());
    let (tx, txid, _wtxid, _n) = parse_tx(&tx_bytes).expect("parse");

    let mut utxos: HashMap<Outpoint, UtxoEntry> = HashMap::new();
    utxos.insert(
        Outpoint {
            txid: prev,
            vout: 0,
        },
        UtxoEntry {
            value: 1,
            covenant_type: COV_TYPE_ANCHOR,
            covenant_data: vec![0x01],
            creation_height: 0,
            created_by_coinbase: false,
        },
    );

    let err = apply_non_coinbase_tx_basic(&tx, txid, &utxos, 100, 1000, ZERO_CHAIN_ID).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrMissingUtxo);
}

#[test]
fn apply_non_coinbase_tx_basic_zero_witness_count_rejected() {
    let mut prev = [0u8; 32];
    prev[0] = 0xac;
    let tx_bytes =
        tx_with_one_input_one_output(prev, 0, 90, COV_TYPE_P2PK, &valid_p2pk_covenant_data());
    let (mut tx, txid, _wtxid, _n) = parse_tx(&tx_bytes).expect("parse");
    tx.witness.clear();

    let mut utxos: HashMap<Outpoint, UtxoEntry> = HashMap::new();
    utxos.insert(
        Outpoint {
            txid: prev,
            vout: 0,
        },
        UtxoEntry {
            value: 100,
            covenant_type: COV_TYPE_P2PK,
            covenant_data: valid_p2pk_covenant_data(),
            creation_height: 0,
            created_by_coinbase: false,
        },
    );

    let err = apply_non_coinbase_tx_basic(&tx, txid, &utxos, 100, 1000, ZERO_CHAIN_ID).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrParse);
}

#[test]
fn apply_non_coinbase_tx_basic_unknown_covenant_spend_rejected() {
    let mut prev = [0u8; 32];
    prev[0] = 0xad;
    let tx_bytes =
        tx_with_one_input_one_output(prev, 0, 90, COV_TYPE_P2PK, &valid_p2pk_covenant_data());
    let (tx, txid, _wtxid, _n) = parse_tx(&tx_bytes).expect("parse");

    let mut utxos: HashMap<Outpoint, UtxoEntry> = HashMap::new();
    utxos.insert(
        Outpoint {
            txid: prev,
            vout: 0,
        },
        UtxoEntry {
            value: 100,
            covenant_type: 0x7777,
            covenant_data: vec![0x01],
            creation_height: 0,
            created_by_coinbase: false,
        },
    );

    let err = apply_non_coinbase_tx_basic(&tx, txid, &utxos, 100, 1000, ZERO_CHAIN_ID).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrCovenantTypeInvalid);
}

#[test]
fn apply_non_coinbase_tx_basic_value_conservation() {
    let mut prev = [0u8; 32];
    prev[0] = 0xae;
    let mut txid = [0u8; 32];
    txid[0] = 0x01;

    let kp = kp_or_skip!();
    let cov_data = p2pk_covenant_data_for_pubkey(&kp.pubkey);

    let mut tx = crate::tx::Tx {
        version: 1,
        tx_kind: 0x00,
        tx_nonce: 1,
        inputs: vec![crate::tx::TxInput {
            prev_txid: prev,
            prev_vout: 0,
            script_sig: vec![],
            sequence: 0,
        }],
        outputs: vec![crate::tx::TxOutput {
            value: 101,
            covenant_type: COV_TYPE_P2PK,
            covenant_data: cov_data.clone(),
        }],
        locktime: 0,
        da_commit_core: None,
        da_chunk_core: None,
        witness: vec![],
        da_payload: vec![],
    };
    tx.witness = vec![sign_input_witness(&tx, 0, 100, ZERO_CHAIN_ID, &kp)];

    let mut utxos: HashMap<Outpoint, UtxoEntry> = HashMap::new();
    utxos.insert(
        Outpoint {
            txid: prev,
            vout: 0,
        },
        UtxoEntry {
            value: 100,
            covenant_type: COV_TYPE_P2PK,
            covenant_data: cov_data,
            creation_height: 0,
            created_by_coinbase: false,
        },
    );

    let err = apply_non_coinbase_tx_basic(&tx, txid, &utxos, 200, 1000, ZERO_CHAIN_ID).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrValueConservation);
}

#[test]
fn connect_block_basic_in_memory_at_height_ok_computes_fees_and_updates_state() {
    let height = 1u64;
    let mut prev = [0u8; 32];
    prev[0] = 0x77;
    let target = [0xffu8; 32];

    let kp = kp_or_skip!();
    let cov_data = p2pk_covenant_data_for_pubkey(&kp.pubkey);

    let mut spend_tx = crate::tx::Tx {
        version: 1,
        tx_kind: 0x00,
        tx_nonce: 1,
        inputs: vec![crate::tx::TxInput {
            prev_txid: prev,
            prev_vout: 0,
            script_sig: vec![],
            sequence: 0,
        }],
        outputs: vec![crate::tx::TxOutput {
            value: 90,
            covenant_type: COV_TYPE_P2PK,
            covenant_data: cov_data.clone(),
        }],
        locktime: 0,
        da_commit_core: None,
        da_chunk_core: None,
        witness: vec![],
        da_payload: vec![],
    };
    let w = sign_input_witness(&spend_tx, 0, 100, ZERO_CHAIN_ID, &kp);
    spend_tx.witness = vec![w.clone()];

    let spend_bytes = tx_with_one_input_one_output_with_witness(
        prev,
        0,
        90,
        COV_TYPE_P2PK,
        &cov_data,
        w.suite_id,
        &w.pubkey,
        &w.signature,
    );
    let (_t, spend_txid, _wtxid, _n) = parse_tx(&spend_bytes).expect("parse spend tx");

    let mut state = crate::connect_block_inmem::InMemoryChainState {
        utxos: HashMap::new(),
        already_generated: 0,
    };
    state.utxos.insert(
        Outpoint {
            txid: prev,
            vout: 0,
        },
        UtxoEntry {
            value: 100,
            covenant_type: COV_TYPE_P2PK,
            covenant_data: cov_data.clone(),
            creation_height: 0,
            created_by_coinbase: false,
        },
    );

    let sum_fees = 10u64;
    let subsidy = crate::subsidy::block_subsidy(height, state.already_generated);
    let coinbase = coinbase_with_witness_commitment_and_p2pk_value(
        height as u32,
        subsidy + sum_fees,
        std::slice::from_ref(&spend_bytes),
    );
    let (_ct, coinbase_txid, _cw, _cn) = parse_tx(&coinbase).expect("parse coinbase");

    let root = merkle_root_txids(&[coinbase_txid, spend_txid]).expect("merkle root");
    let block = build_block_bytes(prev, root, target, 1, &[coinbase, spend_bytes]);

    let s = crate::connect_block_basic_in_memory_at_height(
        &block,
        Some(prev),
        Some(target),
        height,
        None,
        &mut state,
        ZERO_CHAIN_ID,
    )
    .expect("connect block");

    assert_eq!(s.sum_fees, sum_fees);
    assert_eq!(s.already_generated, 0);
    assert_eq!(s.already_generated_n1, u128::from(subsidy));
    assert_eq!(s.utxo_count, 2);
}

#[test]
fn connect_block_basic_in_memory_at_height_rejects_subsidy_exceeded() {
    let height = 1u64;
    let mut prev = [0u8; 32];
    prev[0] = 0x78;
    let target = [0xffu8; 32];

    let kp = kp_or_skip!();
    let cov_data = p2pk_covenant_data_for_pubkey(&kp.pubkey);

    let mut spend_tx = crate::tx::Tx {
        version: 1,
        tx_kind: 0x00,
        tx_nonce: 1,
        inputs: vec![crate::tx::TxInput {
            prev_txid: prev,
            prev_vout: 0,
            script_sig: vec![],
            sequence: 0,
        }],
        outputs: vec![crate::tx::TxOutput {
            value: 90,
            covenant_type: COV_TYPE_P2PK,
            covenant_data: cov_data.clone(),
        }],
        locktime: 0,
        da_commit_core: None,
        da_chunk_core: None,
        witness: vec![],
        da_payload: vec![],
    };
    let w = sign_input_witness(&spend_tx, 0, 100, ZERO_CHAIN_ID, &kp);
    spend_tx.witness = vec![w.clone()];

    let spend_bytes = tx_with_one_input_one_output_with_witness(
        prev,
        0,
        90,
        COV_TYPE_P2PK,
        &cov_data,
        w.suite_id,
        &w.pubkey,
        &w.signature,
    );
    let (_t, spend_txid, _wtxid, _n) = parse_tx(&spend_bytes).expect("parse spend tx");

    let mut state = crate::connect_block_inmem::InMemoryChainState {
        utxos: HashMap::new(),
        already_generated: 0,
    };
    state.utxos.insert(
        Outpoint {
            txid: prev,
            vout: 0,
        },
        UtxoEntry {
            value: 100,
            covenant_type: COV_TYPE_P2PK,
            covenant_data: cov_data.clone(),
            creation_height: 0,
            created_by_coinbase: false,
        },
    );

    let sum_fees = 10u64;
    let subsidy = crate::subsidy::block_subsidy(height, state.already_generated);
    let coinbase = coinbase_with_witness_commitment_and_p2pk_value(
        height as u32,
        subsidy + sum_fees + 1,
        std::slice::from_ref(&spend_bytes),
    );
    let (_ct, coinbase_txid, _cw, _cn) = parse_tx(&coinbase).expect("parse coinbase");

    let root = merkle_root_txids(&[coinbase_txid, spend_txid]).expect("merkle root");
    let block = build_block_bytes(prev, root, target, 2, &[coinbase, spend_bytes]);

    let err = crate::connect_block_basic_in_memory_at_height(
        &block,
        Some(prev),
        Some(target),
        height,
        None,
        &mut state,
        ZERO_CHAIN_ID,
    )
    .unwrap_err();
    assert_eq!(err.code, ErrorCode::BlockErrSubsidyExceeded);
}

#[test]
fn error_code_as_str_and_display() {
    assert_eq!(ErrorCode::TxErrParse.as_str(), "TX_ERR_PARSE");
    assert_eq!(
        ErrorCode::TxErrVaultOwnerAuthRequired.as_str(),
        "TX_ERR_VAULT_OWNER_AUTH_REQUIRED"
    );
    assert_eq!(
        ErrorCode::BlockErrPowInvalid.as_str(),
        "BLOCK_ERR_POW_INVALID"
    );
    assert_eq!(
        ErrorCode::BlockErrDaSetInvalid.as_str(),
        "BLOCK_ERR_DA_SET_INVALID"
    );

    let e = crate::error::TxError::new(ErrorCode::TxErrParse, "");
    assert_eq!(e.to_string(), "TX_ERR_PARSE");
    let e2 = crate::error::TxError::new(ErrorCode::TxErrParse, "bad");
    assert_eq!(e2.to_string(), "TX_ERR_PARSE: bad");
}

#[test]
fn apply_non_coinbase_tx_basic_ok() {
    let mut prev = [0u8; 32];
    prev[0] = 0xaf;
    let mut txid = [0u8; 32];
    txid[0] = 0x02;

    let kp = kp_or_skip!();
    let cov_data = p2pk_covenant_data_for_pubkey(&kp.pubkey);

    let mut tx = crate::tx::Tx {
        version: 1,
        tx_kind: 0x00,
        tx_nonce: 1,
        inputs: vec![crate::tx::TxInput {
            prev_txid: prev,
            prev_vout: 0,
            script_sig: vec![],
            sequence: 0,
        }],
        outputs: vec![crate::tx::TxOutput {
            value: 90,
            covenant_type: COV_TYPE_P2PK,
            covenant_data: cov_data.clone(),
        }],
        locktime: 0,
        da_commit_core: None,
        da_chunk_core: None,
        witness: vec![],
        da_payload: vec![],
    };
    tx.witness = vec![sign_input_witness(&tx, 0, 100, ZERO_CHAIN_ID, &kp)];

    let mut utxos: HashMap<Outpoint, UtxoEntry> = HashMap::new();
    utxos.insert(
        Outpoint {
            txid: prev,
            vout: 0,
        },
        UtxoEntry {
            value: 100,
            covenant_type: COV_TYPE_P2PK,
            covenant_data: cov_data,
            creation_height: 0,
            created_by_coinbase: false,
        },
    );

    let summary =
        apply_non_coinbase_tx_basic(&tx, txid, &utxos, 200, 1000, ZERO_CHAIN_ID).expect("ok");
    assert_eq!(summary.fee, 10);
    assert_eq!(summary.utxo_count, 1);
}

#[test]
fn apply_non_coinbase_tx_basic_vault_cannot_fund_fee() {
    let mut prev_vault = [0u8; 32];
    prev_vault[0] = 0xc0;
    let mut prev_fee = [0u8; 32];
    prev_fee[0] = 0xc1;
    let mut txid = [0u8; 32];
    txid[0] = 0xc2;

    let vault_kp = kp_or_skip!();
    let owner_kp = kp_or_skip!();
    let dest_kp = kp_or_skip!();

    let owner_cov = p2pk_covenant_data_for_pubkey(&owner_kp.pubkey);
    let owner_lock_id = sha3_256(&crate::vault::output_descriptor_bytes(
        COV_TYPE_P2PK,
        &owner_cov,
    ));

    let dest_cov = p2pk_covenant_data_for_pubkey(&dest_kp.pubkey);
    let whitelist_h = sha3_256(&crate::vault::output_descriptor_bytes(
        COV_TYPE_P2PK,
        &dest_cov,
    ));

    let vault_key_id = sha3_256(&vault_kp.pubkey);
    let vault_cov = encode_vault_covenant_data(owner_lock_id, 1, &[vault_key_id], &[whitelist_h]);

    let mut tx = crate::tx::Tx {
        version: 1,
        tx_kind: 0x00,
        tx_nonce: 1,
        inputs: vec![
            crate::tx::TxInput {
                prev_txid: prev_vault,
                prev_vout: 0,
                script_sig: vec![],
                sequence: 0,
            },
            crate::tx::TxInput {
                prev_txid: prev_fee,
                prev_vout: 0,
                script_sig: vec![],
                sequence: 0,
            },
        ],
        outputs: vec![crate::tx::TxOutput {
            value: 90,
            covenant_type: COV_TYPE_P2PK,
            covenant_data: dest_cov,
        }],
        locktime: 0,
        da_commit_core: None,
        da_chunk_core: None,
        witness: vec![],
        da_payload: vec![],
    };
    tx.witness = vec![
        sign_input_witness(&tx, 0, 100, ZERO_CHAIN_ID, &vault_kp),
        sign_input_witness(&tx, 1, 10, ZERO_CHAIN_ID, &owner_kp),
    ];

    let mut utxos: HashMap<Outpoint, UtxoEntry> = HashMap::new();
    utxos.insert(
        Outpoint {
            txid: prev_vault,
            vout: 0,
        },
        UtxoEntry {
            value: 100,
            covenant_type: COV_TYPE_VAULT,
            covenant_data: vault_cov,
            creation_height: 0,
            created_by_coinbase: false,
        },
    );
    utxos.insert(
        Outpoint {
            txid: prev_fee,
            vout: 0,
        },
        UtxoEntry {
            value: 10,
            covenant_type: COV_TYPE_P2PK,
            covenant_data: owner_cov,
            creation_height: 0,
            created_by_coinbase: false,
        },
    );

    let err = apply_non_coinbase_tx_basic(&tx, txid, &utxos, 200, 1000, ZERO_CHAIN_ID).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrValueConservation);
}

#[test]
fn apply_non_coinbase_tx_basic_vault_preserved_with_owner_fee_input() {
    let mut prev_vault = [0u8; 32];
    prev_vault[0] = 0xd0;
    let mut prev_fee = [0u8; 32];
    prev_fee[0] = 0xd1;
    let mut txid = [0u8; 32];
    txid[0] = 0xd2;

    let vault_kp = kp_or_skip!();
    let owner_kp = kp_or_skip!();
    let dest_kp = kp_or_skip!();

    let owner_cov = p2pk_covenant_data_for_pubkey(&owner_kp.pubkey);
    let owner_lock_id = sha3_256(&crate::vault::output_descriptor_bytes(
        COV_TYPE_P2PK,
        &owner_cov,
    ));

    let dest_cov = p2pk_covenant_data_for_pubkey(&dest_kp.pubkey);
    let whitelist_h = sha3_256(&crate::vault::output_descriptor_bytes(
        COV_TYPE_P2PK,
        &dest_cov,
    ));

    let vault_key_id = sha3_256(&vault_kp.pubkey);
    let vault_cov = encode_vault_covenant_data(owner_lock_id, 1, &[vault_key_id], &[whitelist_h]);

    let mut tx = crate::tx::Tx {
        version: 1,
        tx_kind: 0x00,
        tx_nonce: 1,
        inputs: vec![
            crate::tx::TxInput {
                prev_txid: prev_vault,
                prev_vout: 0,
                script_sig: vec![],
                sequence: 0,
            },
            crate::tx::TxInput {
                prev_txid: prev_fee,
                prev_vout: 0,
                script_sig: vec![],
                sequence: 0,
            },
        ],
        outputs: vec![crate::tx::TxOutput {
            value: 100,
            covenant_type: COV_TYPE_P2PK,
            covenant_data: dest_cov,
        }],
        locktime: 0,
        da_commit_core: None,
        da_chunk_core: None,
        witness: vec![],
        da_payload: vec![],
    };
    tx.witness = vec![
        sign_input_witness(&tx, 0, 100, ZERO_CHAIN_ID, &vault_kp),
        sign_input_witness(&tx, 1, 10, ZERO_CHAIN_ID, &owner_kp),
    ];

    let mut utxos: HashMap<Outpoint, UtxoEntry> = HashMap::new();
    utxos.insert(
        Outpoint {
            txid: prev_vault,
            vout: 0,
        },
        UtxoEntry {
            value: 100,
            covenant_type: COV_TYPE_VAULT,
            covenant_data: vault_cov,
            creation_height: 0,
            created_by_coinbase: false,
        },
    );
    utxos.insert(
        Outpoint {
            txid: prev_fee,
            vout: 0,
        },
        UtxoEntry {
            value: 10,
            covenant_type: COV_TYPE_P2PK,
            covenant_data: owner_cov,
            creation_height: 0,
            created_by_coinbase: false,
        },
    );

    let summary =
        apply_non_coinbase_tx_basic(&tx, txid, &utxos, 200, 1000, ZERO_CHAIN_ID).expect("ok");
    assert_eq!(summary.fee, 10);
}

#[test]
fn apply_non_coinbase_tx_basic_vault_allows_owner_top_up() {
    let mut prev_vault = [0u8; 32];
    prev_vault[0] = 0xd3;
    let mut prev_fee = [0u8; 32];
    prev_fee[0] = 0xd4;
    let mut txid = [0u8; 32];
    txid[0] = 0xd5;

    let vault_kp = kp_or_skip!();
    let owner_kp = kp_or_skip!();
    let dest_kp = kp_or_skip!();

    let owner_cov = p2pk_covenant_data_for_pubkey(&owner_kp.pubkey);
    let owner_lock_id = sha3_256(&crate::vault::output_descriptor_bytes(
        COV_TYPE_P2PK,
        &owner_cov,
    ));

    let dest_cov = p2pk_covenant_data_for_pubkey(&dest_kp.pubkey);
    let whitelist_h = sha3_256(&crate::vault::output_descriptor_bytes(
        COV_TYPE_P2PK,
        &dest_cov,
    ));

    let vault_key_id = sha3_256(&vault_kp.pubkey);
    let vault_cov = encode_vault_covenant_data(owner_lock_id, 1, &[vault_key_id], &[whitelist_h]);

    let mut tx = crate::tx::Tx {
        version: 1,
        tx_kind: 0x00,
        tx_nonce: 1,
        inputs: vec![
            crate::tx::TxInput {
                prev_txid: prev_vault,
                prev_vout: 0,
                script_sig: vec![],
                sequence: 0,
            },
            crate::tx::TxInput {
                prev_txid: prev_fee,
                prev_vout: 0,
                script_sig: vec![],
                sequence: 0,
            },
        ],
        outputs: vec![crate::tx::TxOutput {
            value: 105,
            covenant_type: COV_TYPE_P2PK,
            covenant_data: dest_cov,
        }],
        locktime: 0,
        da_commit_core: None,
        da_chunk_core: None,
        witness: vec![],
        da_payload: vec![],
    };
    tx.witness = vec![
        sign_input_witness(&tx, 0, 100, ZERO_CHAIN_ID, &vault_kp),
        sign_input_witness(&tx, 1, 10, ZERO_CHAIN_ID, &owner_kp),
    ];

    let mut utxos: HashMap<Outpoint, UtxoEntry> = HashMap::new();
    utxos.insert(
        Outpoint {
            txid: prev_vault,
            vout: 0,
        },
        UtxoEntry {
            value: 100,
            covenant_type: COV_TYPE_VAULT,
            covenant_data: vault_cov,
            creation_height: 0,
            created_by_coinbase: false,
        },
    );
    utxos.insert(
        Outpoint {
            txid: prev_fee,
            vout: 0,
        },
        UtxoEntry {
            value: 10,
            covenant_type: COV_TYPE_P2PK,
            covenant_data: owner_cov,
            creation_height: 0,
            created_by_coinbase: false,
        },
    );

    let summary =
        apply_non_coinbase_tx_basic(&tx, txid, &utxos, 200, 1000, ZERO_CHAIN_ID).expect("ok");
    assert_eq!(summary.fee, 5);
}

#[test]
fn apply_non_coinbase_tx_basic_htlc_then_p2pk_cursor_handling() {
    let mut prev_htlc = [0u8; 32];
    prev_htlc[0] = 0xb6;
    let mut prev_p2pk = [0u8; 32];
    prev_p2pk[0] = 0xb7;
    let mut txid = [0u8; 32];
    txid[0] = 0xb8;

    let claim_kp = kp_or_skip!();
    let refund_kp = kp_or_skip!();
    let p2pk_kp = kp_or_skip!();
    let dest_kp = kp_or_skip!();

    let claim_key_id = sha3_256(&claim_kp.pubkey);
    let refund_key_id = sha3_256(&refund_kp.pubkey);
    let p2pk_cov = p2pk_covenant_data_for_pubkey(&p2pk_kp.pubkey);
    let dest_cov = p2pk_covenant_data_for_pubkey(&dest_kp.pubkey);

    let preimage = b"htlc-claim-preimage";
    let mut selector_payload = Vec::with_capacity(3 + preimage.len());
    selector_payload.push(0x00);
    selector_payload.extend_from_slice(&(preimage.len() as u16).to_le_bytes());
    selector_payload.extend_from_slice(preimage);

    let mut tx = crate::tx::Tx {
        version: 1,
        tx_kind: 0x00,
        tx_nonce: 1,
        inputs: vec![
            crate::tx::TxInput {
                prev_txid: prev_htlc,
                prev_vout: 0,
                script_sig: vec![],
                sequence: 0,
            },
            crate::tx::TxInput {
                prev_txid: prev_p2pk,
                prev_vout: 0,
                script_sig: vec![],
                sequence: 0,
            },
        ],
        outputs: vec![crate::tx::TxOutput {
            value: 150,
            covenant_type: COV_TYPE_P2PK,
            covenant_data: dest_cov,
        }],
        locktime: 0,
        da_commit_core: None,
        da_chunk_core: None,
        witness: vec![],
        da_payload: vec![],
    };
    tx.witness = vec![
        crate::tx::WitnessItem {
            suite_id: SUITE_ID_SENTINEL,
            pubkey: claim_key_id.to_vec(),
            signature: selector_payload,
        },
        sign_input_witness(&tx, 0, 100, ZERO_CHAIN_ID, &claim_kp),
        sign_input_witness(&tx, 1, 70, ZERO_CHAIN_ID, &p2pk_kp),
    ];

    let mut utxos: HashMap<Outpoint, UtxoEntry> = HashMap::new();
    utxos.insert(
        Outpoint {
            txid: prev_htlc,
            vout: 0,
        },
        UtxoEntry {
            value: 100,
            covenant_type: COV_TYPE_HTLC,
            covenant_data: encode_htlc_covenant_data(
                sha3_256(preimage),
                LOCK_MODE_HEIGHT,
                1,
                claim_key_id,
                refund_key_id,
            ),
            creation_height: 0,
            created_by_coinbase: false,
        },
    );
    utxos.insert(
        Outpoint {
            txid: prev_p2pk,
            vout: 0,
        },
        UtxoEntry {
            value: 70,
            covenant_type: COV_TYPE_P2PK,
            covenant_data: p2pk_cov,
            creation_height: 0,
            created_by_coinbase: false,
        },
    );

    let summary =
        apply_non_coinbase_tx_basic(&tx, txid, &utxos, 200, 1000, ZERO_CHAIN_ID).expect("ok");
    assert_eq!(summary.fee, 20);
    assert_eq!(summary.utxo_count, 1);
}

#[test]
fn apply_non_coinbase_tx_basic_htlc_timestamp_uses_mtp() {
    let mut prev = [0u8; 32];
    prev[0] = 0xa8;
    let mut txid = [0u8; 32];
    txid[0] = 0xa9;

    let claim_kp = kp_or_skip!();
    let refund_kp = kp_or_skip!();
    let dest_kp = kp_or_skip!();

    let claim_key_id = sha3_256(&claim_kp.pubkey);
    let refund_key_id = sha3_256(&refund_kp.pubkey);
    let dest_cov = p2pk_covenant_data_for_pubkey(&dest_kp.pubkey);

    let mut tx = crate::tx::Tx {
        version: 1,
        tx_kind: 0x00,
        tx_nonce: 1,
        inputs: vec![crate::tx::TxInput {
            prev_txid: prev,
            prev_vout: 0,
            script_sig: vec![],
            sequence: 0,
        }],
        outputs: vec![crate::tx::TxOutput {
            value: 90,
            covenant_type: COV_TYPE_P2PK,
            covenant_data: dest_cov,
        }],
        locktime: 0,
        da_commit_core: None,
        da_chunk_core: None,
        witness: vec![
            crate::tx::WitnessItem {
                suite_id: SUITE_ID_SENTINEL,
                pubkey: refund_key_id.to_vec(),
                signature: vec![0x01],
            },
            sentinel_witness_item(),
        ],
        da_payload: vec![],
    };
    tx.witness[1] = sign_input_witness(&tx, 0, 100, ZERO_CHAIN_ID, &refund_kp);

    let mut utxos: HashMap<Outpoint, UtxoEntry> = HashMap::new();
    utxos.insert(
        Outpoint {
            txid: prev,
            vout: 0,
        },
        UtxoEntry {
            value: 100,
            covenant_type: COV_TYPE_HTLC,
            covenant_data: encode_htlc_covenant_data(
                sha3_256(b"htlc-hash"),
                LOCK_MODE_TIMESTAMP,
                2000,
                claim_key_id,
                refund_key_id,
            ),
            creation_height: 0,
            created_by_coinbase: false,
        },
    );

    let err = apply_non_coinbase_tx_basic_with_mtp(&tx, txid, &utxos, 0, 3000, 1000, ZERO_CHAIN_ID)
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrTimelockNotMet);

    let summary =
        apply_non_coinbase_tx_basic_with_mtp(&tx, txid, &utxos, 0, 3000, 3000, ZERO_CHAIN_ID)
            .expect("ok");
    assert_eq!(summary.fee, 10);
    assert_eq!(summary.utxo_count, 1);
}

#[test]
fn apply_non_coinbase_tx_basic_vault_whitelist_rejects_output() {
    let mut prev_vault = [0u8; 32];
    prev_vault[0] = 0xe0;
    let mut prev_fee = [0u8; 32];
    prev_fee[0] = 0xe1;
    let mut txid = [0u8; 32];
    txid[0] = 0xe2;

    let vault_kp = kp_or_skip!();
    let owner_kp = kp_or_skip!();
    let whitelisted_dest_kp = kp_or_skip!();
    let non_whitelisted_dest_kp = kp_or_skip!();

    let owner_cov = p2pk_covenant_data_for_pubkey(&owner_kp.pubkey);
    let owner_lock_id = sha3_256(&crate::vault::output_descriptor_bytes(
        COV_TYPE_P2PK,
        &owner_cov,
    ));

    let whitelisted_cov = p2pk_covenant_data_for_pubkey(&whitelisted_dest_kp.pubkey);
    let whitelist_h = sha3_256(&crate::vault::output_descriptor_bytes(
        COV_TYPE_P2PK,
        &whitelisted_cov,
    ));

    let non_whitelisted_cov = p2pk_covenant_data_for_pubkey(&non_whitelisted_dest_kp.pubkey);

    let vault_key_id = sha3_256(&vault_kp.pubkey);
    let vault_cov = encode_vault_covenant_data(owner_lock_id, 1, &[vault_key_id], &[whitelist_h]);

    let mut tx = crate::tx::Tx {
        version: 1,
        tx_kind: 0x00,
        tx_nonce: 1,
        inputs: vec![
            crate::tx::TxInput {
                prev_txid: prev_vault,
                prev_vout: 0,
                script_sig: vec![],
                sequence: 0,
            },
            crate::tx::TxInput {
                prev_txid: prev_fee,
                prev_vout: 0,
                script_sig: vec![],
                sequence: 0,
            },
        ],
        outputs: vec![crate::tx::TxOutput {
            value: 100,
            covenant_type: COV_TYPE_P2PK,
            covenant_data: non_whitelisted_cov,
        }],
        locktime: 0,
        da_commit_core: None,
        da_chunk_core: None,
        witness: vec![],
        da_payload: vec![],
    };
    tx.witness = vec![
        sign_input_witness(&tx, 0, 100, ZERO_CHAIN_ID, &vault_kp),
        sign_input_witness(&tx, 1, 10, ZERO_CHAIN_ID, &owner_kp),
    ];

    let mut utxos: HashMap<Outpoint, UtxoEntry> = HashMap::new();
    utxos.insert(
        Outpoint {
            txid: prev_vault,
            vout: 0,
        },
        UtxoEntry {
            value: 100,
            covenant_type: COV_TYPE_VAULT,
            covenant_data: vault_cov,
            creation_height: 0,
            created_by_coinbase: false,
        },
    );
    utxos.insert(
        Outpoint {
            txid: prev_fee,
            vout: 0,
        },
        UtxoEntry {
            value: 10,
            covenant_type: COV_TYPE_P2PK,
            covenant_data: owner_cov,
            creation_height: 0,
            created_by_coinbase: false,
        },
    );

    let err = apply_non_coinbase_tx_basic(&tx, txid, &utxos, 200, 1000, ZERO_CHAIN_ID).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrVaultOutputNotWhitelisted);
}

#[test]
fn apply_non_coinbase_tx_basic_vault_rejects_disallowed_destination_covenant_type_even_if_whitelisted(
) {
    let mut prev_vault = [0u8; 32];
    prev_vault[0] = 0xe4;
    let mut prev_fee = [0u8; 32];
    prev_fee[0] = 0xe5;
    let mut txid = [0u8; 32];
    txid[0] = 0xe6;

    let vault_kp = kp_or_skip!();
    let owner_kp = kp_or_skip!();

    let owner_cov = p2pk_covenant_data_for_pubkey(&owner_kp.pubkey);
    let owner_lock_id = sha3_256(&crate::vault::output_descriptor_bytes(
        COV_TYPE_P2PK,
        &owner_cov,
    ));

    // Minimal valid CORE_EXT covenant_data: ext_id:u16le(1) || ext_payload_len:CompactSize(0).
    let core_ext_cov = vec![0x01, 0x00, 0x00];
    let whitelist_h = sha3_256(&crate::vault::output_descriptor_bytes(
        COV_TYPE_EXT,
        &core_ext_cov,
    ));

    let vault_key_id = sha3_256(&vault_kp.pubkey);
    let vault_cov = encode_vault_covenant_data(owner_lock_id, 1, &[vault_key_id], &[whitelist_h]);

    let mut tx = crate::tx::Tx {
        version: 1,
        tx_kind: 0x00,
        tx_nonce: 1,
        inputs: vec![
            crate::tx::TxInput {
                prev_txid: prev_vault,
                prev_vout: 0,
                script_sig: vec![],
                sequence: 0,
            },
            crate::tx::TxInput {
                prev_txid: prev_fee,
                prev_vout: 0,
                script_sig: vec![],
                sequence: 0,
            },
        ],
        outputs: vec![crate::tx::TxOutput {
            value: 100,
            covenant_type: COV_TYPE_EXT,
            covenant_data: core_ext_cov,
        }],
        locktime: 0,
        da_commit_core: None,
        da_chunk_core: None,
        witness: vec![],
        da_payload: vec![],
    };
    tx.witness = vec![
        sign_input_witness(&tx, 0, 100, ZERO_CHAIN_ID, &vault_kp),
        sign_input_witness(&tx, 1, 10, ZERO_CHAIN_ID, &owner_kp),
    ];

    let mut utxos: HashMap<Outpoint, UtxoEntry> = HashMap::new();
    utxos.insert(
        Outpoint {
            txid: prev_vault,
            vout: 0,
        },
        UtxoEntry {
            value: 100,
            covenant_type: COV_TYPE_VAULT,
            covenant_data: vault_cov,
            creation_height: 0,
            created_by_coinbase: false,
        },
    );
    utxos.insert(
        Outpoint {
            txid: prev_fee,
            vout: 0,
        },
        UtxoEntry {
            value: 10,
            covenant_type: COV_TYPE_P2PK,
            covenant_data: owner_cov,
            creation_height: 0,
            created_by_coinbase: false,
        },
    );

    let err = apply_non_coinbase_tx_basic(&tx, txid, &utxos, 200, 1000, ZERO_CHAIN_ID).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrVaultOutputNotWhitelisted);
}

#[test]
fn apply_non_coinbase_tx_basic_vault_recursion_rejected() {
    let mut prev_vault = [0u8; 32];
    prev_vault[0] = 0xd0;
    let mut prev_fee = [0u8; 32];
    prev_fee[0] = 0xd1;
    let mut txid = [0u8; 32];
    txid[0] = 0xd2;

    let vault_kp = kp_or_skip!();
    let owner_kp = kp_or_skip!();

    let owner_cov = p2pk_covenant_data_for_pubkey(&owner_kp.pubkey);
    let owner_lock_id = sha3_256(&crate::vault::output_descriptor_bytes(
        COV_TYPE_P2PK,
        &owner_cov,
    ));

    // Minimal whitelist (unused by this test because we reject earlier on CORE_VAULT output type).
    let dummy_whitelist_h = sha3_256(b"dummy-whitelist-entry");

    let vault_key_id = sha3_256(&vault_kp.pubkey);
    let vault_cov =
        encode_vault_covenant_data(owner_lock_id, 1, &[vault_key_id], &[dummy_whitelist_h]);

    let mut tx = crate::tx::Tx {
        version: 1,
        tx_kind: 0x00,
        tx_nonce: 1,
        inputs: vec![
            crate::tx::TxInput {
                prev_txid: prev_vault,
                prev_vout: 0,
                script_sig: vec![],
                sequence: 0,
            },
            crate::tx::TxInput {
                prev_txid: prev_fee,
                prev_vout: 0,
                script_sig: vec![],
                sequence: 0,
            },
        ],
        // This output is a CORE_VAULT output and MUST be rejected for vault spends (recursion hardening).
        outputs: vec![crate::tx::TxOutput {
            value: 100,
            covenant_type: COV_TYPE_VAULT,
            covenant_data: vault_cov.clone(),
        }],
        locktime: 0,
        da_commit_core: None,
        da_chunk_core: None,
        witness: vec![],
        da_payload: vec![],
    };
    tx.witness = vec![
        sign_input_witness(&tx, 0, 100, ZERO_CHAIN_ID, &vault_kp),
        sign_input_witness(&tx, 1, 10, ZERO_CHAIN_ID, &owner_kp),
    ];

    let mut utxos: HashMap<Outpoint, UtxoEntry> = HashMap::new();
    utxos.insert(
        Outpoint {
            txid: prev_vault,
            vout: 0,
        },
        UtxoEntry {
            value: 100,
            covenant_type: COV_TYPE_VAULT,
            covenant_data: vault_cov,
            creation_height: 0,
            created_by_coinbase: false,
        },
    );
    utxos.insert(
        Outpoint {
            txid: prev_fee,
            vout: 0,
        },
        UtxoEntry {
            value: 10,
            covenant_type: COV_TYPE_P2PK,
            covenant_data: owner_cov,
            creation_height: 0,
            created_by_coinbase: false,
        },
    );

    let err = apply_non_coinbase_tx_basic(&tx, txid, &utxos, 200, 1000, ZERO_CHAIN_ID).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrVaultOutputNotWhitelisted);
}

#[test]
fn apply_non_coinbase_tx_basic_multisig_input_accepted() {
    let mut prev = [0u8; 32];
    prev[0] = 0xf0;
    let mut txid = [0u8; 32];
    txid[0] = 0xf1;

    let ms_kp = kp_or_skip!();
    let dest_kp = kp_or_skip!();

    let ms_key_id = sha3_256(&ms_kp.pubkey);
    let ms_cov = encode_multisig_covenant_data(1, &[ms_key_id]);

    let dest_cov = p2pk_covenant_data_for_pubkey(&dest_kp.pubkey);

    let mut tx = crate::tx::Tx {
        version: 1,
        tx_kind: 0x00,
        tx_nonce: 1,
        inputs: vec![crate::tx::TxInput {
            prev_txid: prev,
            prev_vout: 0,
            script_sig: vec![],
            sequence: 0,
        }],
        outputs: vec![crate::tx::TxOutput {
            value: 90,
            covenant_type: COV_TYPE_P2PK,
            covenant_data: dest_cov,
        }],
        locktime: 0,
        da_commit_core: None,
        da_chunk_core: None,
        witness: vec![],
        da_payload: vec![],
    };
    tx.witness = vec![sign_input_witness(&tx, 0, 100, ZERO_CHAIN_ID, &ms_kp)];

    let mut utxos: HashMap<Outpoint, UtxoEntry> = HashMap::new();
    utxos.insert(
        Outpoint {
            txid: prev,
            vout: 0,
        },
        UtxoEntry {
            value: 100,
            covenant_type: COV_TYPE_MULTISIG,
            covenant_data: ms_cov,
            creation_height: 0,
            created_by_coinbase: false,
        },
    );

    let summary =
        apply_non_coinbase_tx_basic(&tx, txid, &utxos, 200, 1000, ZERO_CHAIN_ID).expect("ok");
    assert_eq!(summary.fee, 10);
}

#[test]
fn fork_work_vectors() {
    let ff = [0xffu8; 32];
    let w = crate::fork_work_from_target(ff).expect("work");
    assert_eq!(w, BigUint::one());

    let mut half = [0u8; 32];
    half[0] = 0x80;
    let w = crate::fork_work_from_target(half).expect("work");
    assert_eq!(w, BigUint::from(2u8));

    let mut one = [0u8; 32];
    one[31] = 0x01;
    let w = crate::fork_work_from_target(one).expect("work");
    let two256: BigUint = BigUint::one() << 256usize;
    assert_eq!(w, two256);
}

#[test]
fn fork_work_rejects_zero_target() {
    let err = crate::fork_work_from_target([0u8; 32]).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrParse);
}

#[test]
fn fork_chainwork_from_targets_accumulates_and_propagates_error() {
    let ff = [0xffu8; 32];
    let mut half = [0u8; 32];
    half[0] = 0x80;

    let total = crate::fork_chainwork_from_targets(&[ff, half]).expect("chainwork");
    assert_eq!(total, BigUint::from(3u8));

    let err = crate::fork_chainwork_from_targets(&[[0u8; 32], ff]).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrParse);
}

#[test]
fn sentinel_keyless_enforcement() {
    use crate::spend_verify::validate_threshold_sig_spend;
    use crate::tx::WitnessItem;

    let tx = parse_tx(&minimal_tx_bytes()).expect("parse").0;

    // SENTINEL with non-empty pubkey must be rejected
    let keys = vec![[1u8; 32]];
    let ws1 = vec![WitnessItem {
        suite_id: SUITE_ID_SENTINEL,
        pubkey: vec![0x01],
        signature: vec![],
    }];
    let err = validate_threshold_sig_spend(&keys, 1, &ws1, &tx, 0, 0, ZERO_CHAIN_ID, 0, "test")
        .expect_err("should reject sentinel with pubkey");
    assert_eq!(err.code, ErrorCode::TxErrParse);

    // SENTINEL with non-empty signature must be rejected
    let ws2 = vec![WitnessItem {
        suite_id: SUITE_ID_SENTINEL,
        pubkey: vec![],
        signature: vec![0x01],
    }];
    let err = validate_threshold_sig_spend(&keys, 1, &ws2, &tx, 0, 0, ZERO_CHAIN_ID, 0, "test")
        .expect_err("should reject sentinel with signature");
    assert_eq!(err.code, ErrorCode::TxErrParse);

    // SENTINEL with both non-empty must be rejected
    let ws3 = vec![WitnessItem {
        suite_id: SUITE_ID_SENTINEL,
        pubkey: vec![0x01],
        signature: vec![0x02],
    }];
    let err = validate_threshold_sig_spend(&keys, 1, &ws3, &tx, 0, 0, ZERO_CHAIN_ID, 0, "test")
        .expect_err("should reject sentinel with pubkey+sig");
    assert_eq!(err.code, ErrorCode::TxErrParse);
}
