use super::*;

fn clone_state(
    utxos: &HashMap<Outpoint, UtxoEntry>,
    already_generated: u128,
) -> crate::InMemoryChainState {
    crate::InMemoryChainState {
        utxos: utxos.clone(),
        already_generated,
    }
}

fn err_code(err: &crate::error::TxError) -> ErrorCode {
    err.code
}

#[test]
fn integration_parity_valid_only() {
    let height = 1u64;
    let mut prev = [0u8; 32];
    prev[0] = 0x77;
    let target = [0xffu8; 32];

    let kp = kp_or_skip!();
    let cov_data = p2pk_covenant_data_for_pubkey(&kp.pubkey);
    let start_utxos = HashMap::from([(
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
    )]);

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
            covenant_data: cov_data,
        }],
        locktime: 0,
        da_commit_core: None,
        da_chunk_core: None,
        witness: vec![],
        da_payload: vec![],
    };
    spend_tx.witness = vec![sign_input_witness(&spend_tx, 0, 100, ZERO_CHAIN_ID, &kp)];
    let spend_bytes = crate::tx_helpers::marshal_tx(&spend_tx).expect("marshal spend tx");
    let (_tx, spend_txid, _wtxid, _n) = parse_tx(&spend_bytes).expect("parse spend tx");

    let subsidy = crate::subsidy::block_subsidy(height, 0);
    let coinbase = coinbase_with_witness_commitment_and_p2pk_value(
        height as u32,
        subsidy + 10,
        std::slice::from_ref(&spend_bytes),
    );
    let (_cb, coinbase_txid, _cbw, _cbn) = parse_tx(&coinbase).expect("parse coinbase");
    let root = merkle_root_txids(&[coinbase_txid, spend_txid]).expect("merkle root");
    let block = build_block_bytes(prev, root, target, 1, &[coinbase, spend_bytes]);

    let mut seq_state = clone_state(&start_utxos, 0);
    let seq_summary = crate::connect_block_basic_in_memory_at_height(
        &block,
        Some(prev),
        Some(target),
        height,
        Some(&[0]),
        &mut seq_state,
        ZERO_CHAIN_ID,
    )
    .expect("sequential connect");
    let mut par_state = clone_state(&start_utxos, 0);
    let par_summary = crate::connect_block_parallel_sig_verify(
        &block,
        Some(prev),
        Some(target),
        height,
        Some(&[0]),
        &mut par_state,
        ZERO_CHAIN_ID,
        4,
    )
    .expect("parallel connect");

    assert_eq!(seq_summary.post_state_digest, par_summary.post_state_digest);
    assert_eq!(seq_summary.sum_fees, par_summary.sum_fees);
    assert_eq!(seq_summary.utxo_count, par_summary.utxo_count);
}

#[test]
fn integration_parity_invalid_one() {
    let height = 1u64;
    let mut prev = [0u8; 32];
    prev[0] = 0x88;
    let target = [0xffu8; 32];

    let kp = kp_or_skip!();
    let cov_data = p2pk_covenant_data_for_pubkey(&kp.pubkey);
    let start_utxos = HashMap::from([(
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
    )]);

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
            covenant_data: cov_data,
        }],
        locktime: 0,
        da_commit_core: None,
        da_chunk_core: None,
        witness: vec![],
        da_payload: vec![],
    };
    let mut witness = sign_input_witness(&spend_tx, 0, 100, ZERO_CHAIN_ID, &kp);
    witness.signature[100] ^= 0xff;
    spend_tx.witness = vec![witness];
    let spend_bytes = crate::tx_helpers::marshal_tx(&spend_tx).expect("marshal spend tx");
    let (_tx, spend_txid, _wtxid, _n) = parse_tx(&spend_bytes).expect("parse spend tx");

    let subsidy = crate::subsidy::block_subsidy(height, 0);
    let coinbase = coinbase_with_witness_commitment_and_p2pk_value(
        height as u32,
        subsidy + 10,
        std::slice::from_ref(&spend_bytes),
    );
    let (_cb, coinbase_txid, _cbw, _cbn) = parse_tx(&coinbase).expect("parse coinbase");
    let root = merkle_root_txids(&[coinbase_txid, spend_txid]).expect("merkle root");
    let block = build_block_bytes(prev, root, target, 1, &[coinbase, spend_bytes]);

    let mut seq_state = clone_state(&start_utxos, 0);
    let seq_err = crate::connect_block_basic_in_memory_at_height(
        &block,
        Some(prev),
        Some(target),
        height,
        Some(&[0]),
        &mut seq_state,
        ZERO_CHAIN_ID,
    )
    .unwrap_err();
    let mut par_state = clone_state(&start_utxos, 0);
    let par_err = crate::connect_block_parallel_sig_verify(
        &block,
        Some(prev),
        Some(target),
        height,
        Some(&[0]),
        &mut par_state,
        ZERO_CHAIN_ID,
        2,
    )
    .unwrap_err();

    assert_eq!(err_code(&seq_err), err_code(&par_err));
}

#[test]
fn integration_parity_mixed() {
    let height = 1u64;
    let mut prev = [0u8; 32];
    prev[0] = 0x99;
    let target = [0xffu8; 32];

    let kp = kp_or_skip!();
    let cov_data = p2pk_covenant_data_for_pubkey(&kp.pubkey);
    let start_utxos = HashMap::from([(
        Outpoint {
            txid: prev,
            vout: 0,
        },
        UtxoEntry {
            value: 200,
            covenant_type: COV_TYPE_P2PK,
            covenant_data: cov_data.clone(),
            creation_height: 0,
            created_by_coinbase: false,
        },
    )]);

    let mut valid_spend = crate::tx::Tx {
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
            value: 190,
            covenant_type: COV_TYPE_P2PK,
            covenant_data: cov_data.clone(),
        }],
        locktime: 0,
        da_commit_core: None,
        da_chunk_core: None,
        witness: vec![],
        da_payload: vec![],
    };
    valid_spend.witness = vec![sign_input_witness(&valid_spend, 0, 200, ZERO_CHAIN_ID, &kp)];
    let valid_bytes = crate::tx_helpers::marshal_tx(&valid_spend).expect("marshal valid spend");
    let (_vtx, valid_txid, _vwtxid, _vn) = parse_tx(&valid_bytes).expect("parse valid spend");

    let mut invalid_spend = crate::tx::Tx {
        version: 1,
        tx_kind: 0x00,
        tx_nonce: 2,
        inputs: vec![crate::tx::TxInput {
            prev_txid: valid_txid,
            prev_vout: 0,
            script_sig: vec![],
            sequence: 0,
        }],
        outputs: vec![crate::tx::TxOutput {
            value: 180,
            covenant_type: COV_TYPE_P2PK,
            covenant_data: cov_data,
        }],
        locktime: 0,
        da_commit_core: None,
        da_chunk_core: None,
        witness: vec![],
        da_payload: vec![],
    };
    let mut invalid_witness = sign_input_witness(&invalid_spend, 0, 190, ZERO_CHAIN_ID, &kp);
    invalid_witness.signature[100] ^= 0xff;
    invalid_spend.witness = vec![invalid_witness];
    let invalid_bytes =
        crate::tx_helpers::marshal_tx(&invalid_spend).expect("marshal invalid spend");
    let (_itx, invalid_txid, _iwtxid, _in) = parse_tx(&invalid_bytes).expect("parse invalid spend");

    let subsidy = crate::subsidy::block_subsidy(height, 0);
    let coinbase = coinbase_with_witness_commitment_and_p2pk_value(
        height as u32,
        subsidy + 20,
        &[valid_bytes.clone(), invalid_bytes.clone()],
    );
    let (_cb, coinbase_txid, _cbw, _cbn) = parse_tx(&coinbase).expect("parse coinbase");
    let root = merkle_root_txids(&[coinbase_txid, valid_txid, invalid_txid]).expect("merkle root");
    let block = build_block_bytes(
        prev,
        root,
        target,
        1,
        &[coinbase, valid_bytes, invalid_bytes],
    );

    let mut seq_state = clone_state(&start_utxos, 0);
    let seq_err = crate::connect_block_basic_in_memory_at_height(
        &block,
        Some(prev),
        Some(target),
        height,
        Some(&[0]),
        &mut seq_state,
        ZERO_CHAIN_ID,
    )
    .unwrap_err();
    let mut par_state = clone_state(&start_utxos, 0);
    let par_err = crate::connect_block_parallel_sig_verify(
        &block,
        Some(prev),
        Some(target),
        height,
        Some(&[0]),
        &mut par_state,
        ZERO_CHAIN_ID,
        4,
    )
    .unwrap_err();

    assert_eq!(err_code(&seq_err), err_code(&par_err));
}

#[test]
fn integration_parity_multiple_valid_txs() {
    let height = 1u64;
    let mut prev = [0u8; 32];
    prev[0] = 0xaa;
    let target = [0xffu8; 32];

    let kp = kp_or_skip!();
    let cov_data = p2pk_covenant_data_for_pubkey(&kp.pubkey);
    let start_utxos = HashMap::from([(
        Outpoint {
            txid: prev,
            vout: 0,
        },
        UtxoEntry {
            value: 500,
            covenant_type: COV_TYPE_P2PK,
            covenant_data: cov_data.clone(),
            creation_height: 0,
            created_by_coinbase: false,
        },
    )]);

    let mut tx_bytes = Vec::new();
    let mut txids = Vec::new();
    let mut cur_value = 500u64;
    let mut cur_prev = prev;
    let mut sum_fees = 0u64;
    for nonce in 1..=3u64 {
        let out_value = cur_value - 10;
        let mut spend = crate::tx::Tx {
            version: 1,
            tx_kind: 0x00,
            tx_nonce: nonce,
            inputs: vec![crate::tx::TxInput {
                prev_txid: cur_prev,
                prev_vout: 0,
                script_sig: vec![],
                sequence: 0,
            }],
            outputs: vec![crate::tx::TxOutput {
                value: out_value,
                covenant_type: COV_TYPE_P2PK,
                covenant_data: cov_data.clone(),
            }],
            locktime: 0,
            da_commit_core: None,
            da_chunk_core: None,
            witness: vec![],
            da_payload: vec![],
        };
        spend.witness = vec![sign_input_witness(&spend, 0, cur_value, ZERO_CHAIN_ID, &kp)];
        let bytes = crate::tx_helpers::marshal_tx(&spend).expect("marshal chain spend");
        let (_tx, txid, _wtxid, _n) = parse_tx(&bytes).expect("parse chain spend");
        tx_bytes.push(bytes);
        txids.push(txid);
        sum_fees += 10;
        cur_value = out_value;
        cur_prev = txid;
    }

    let subsidy = crate::subsidy::block_subsidy(height, 0);
    let coinbase = coinbase_with_witness_commitment_and_p2pk_value(
        height as u32,
        subsidy + sum_fees,
        &tx_bytes,
    );
    let (_cb, coinbase_txid, _cbw, _cbn) = parse_tx(&coinbase).expect("parse coinbase");
    let mut all_txids = vec![coinbase_txid];
    all_txids.extend(txids.iter().copied());
    let root = merkle_root_txids(&all_txids).expect("merkle root");
    let mut all_bytes = vec![coinbase];
    all_bytes.extend(tx_bytes.clone());
    let block = build_block_bytes(prev, root, target, 1, &all_bytes);

    let mut seq_state = clone_state(&start_utxos, 0);
    let seq_summary = crate::connect_block_basic_in_memory_at_height(
        &block,
        Some(prev),
        Some(target),
        height,
        Some(&[0]),
        &mut seq_state,
        ZERO_CHAIN_ID,
    )
    .expect("sequential connect");
    let mut par_state = clone_state(&start_utxos, 0);
    let par_summary = crate::connect_block_parallel_sig_verify(
        &block,
        Some(prev),
        Some(target),
        height,
        Some(&[0]),
        &mut par_state,
        ZERO_CHAIN_ID,
        8,
    )
    .expect("parallel connect");

    assert_eq!(seq_summary.post_state_digest, par_summary.post_state_digest);
    assert_eq!(seq_summary.sum_fees, par_summary.sum_fees);
}
