use super::*;

fn clone_state(
    utxos: &HashMap<Outpoint, UtxoEntry>,
    already_generated: u128,
) -> crate::connect_block_inmem::InMemoryChainState {
    crate::connect_block_inmem::InMemoryChainState {
        utxos: utxos.clone(),
        already_generated,
    }
}

#[test]
fn connect_block_parallel_sig_verify_matches_sequential_for_single_p2pk_spend() {
    let height = 1u64;
    let mut prev = [0u8; 32];
    prev[0] = 0x77;
    let target = [0xffu8; 32];

    let kp = kp_or_skip!();
    let cov_data = p2pk_covenant_data_for_pubkey(&kp.pubkey);
    let prev_out = Outpoint {
        txid: prev,
        vout: 0,
    };

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
    let witness = sign_input_witness(&spend_tx, 0, 100, ZERO_CHAIN_ID, &kp);
    spend_tx.witness = vec![witness.clone()];
    let spend_bytes = tx_with_one_input_one_output_with_witness(
        prev,
        0,
        90,
        COV_TYPE_P2PK,
        &cov_data,
        witness.suite_id,
        &witness.pubkey,
        &witness.signature,
    );
    let (_tx, spend_txid, _wtxid, _n) = parse_tx(&spend_bytes).expect("parse spend tx");

    let start_utxos = HashMap::from([(
        prev_out.clone(),
        UtxoEntry {
            value: 100,
            covenant_type: COV_TYPE_P2PK,
            covenant_data: cov_data.clone(),
            creation_height: 0,
            created_by_coinbase: false,
        },
    )]);

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

    assert_eq!(par_summary.sig_task_count, 1);
    assert_eq!(par_summary.worker_panics, 0);
    assert_eq!(seq_summary.sum_fees, par_summary.sum_fees);
    assert_eq!(seq_summary.already_generated, par_summary.already_generated);
    assert_eq!(
        seq_summary.already_generated_n1,
        par_summary.already_generated_n1
    );
    assert_eq!(seq_summary.utxo_count, par_summary.utxo_count);
    assert_eq!(seq_summary.post_state_digest, par_summary.post_state_digest);
    assert_eq!(seq_state.utxos, par_state.utxos);
    assert_eq!(seq_state.already_generated, par_state.already_generated);
}

#[test]
fn connect_block_parallel_sig_verify_matches_sequential_for_multiple_inputs() {
    let height = 1u64;
    let mut prev = [0u8; 32];
    prev[0] = 0x88;
    let target = [0xffu8; 32];

    let kp = kp_or_skip!();
    let cov_data = p2pk_covenant_data_for_pubkey(&kp.pubkey);

    let mut start_utxos = HashMap::new();
    let mut inputs = Vec::new();
    let mut total_in = 0u64;
    for i in 0..4u8 {
        let mut txid = [0u8; 32];
        txid[0] = i + 1;
        start_utxos.insert(
            Outpoint { txid, vout: 0 },
            UtxoEntry {
                value: 100,
                covenant_type: COV_TYPE_P2PK,
                covenant_data: cov_data.clone(),
                creation_height: 0,
                created_by_coinbase: false,
            },
        );
        inputs.push(crate::tx::TxInput {
            prev_txid: txid,
            prev_vout: 0,
            script_sig: vec![],
            sequence: 0,
        });
        total_in += 100;
    }

    let mut spend_tx = crate::tx::Tx {
        version: 1,
        tx_kind: 0x00,
        tx_nonce: 1,
        inputs,
        outputs: vec![crate::tx::TxOutput {
            value: total_in - 10,
            covenant_type: COV_TYPE_P2PK,
            covenant_data: cov_data.clone(),
        }],
        locktime: 0,
        da_commit_core: None,
        da_chunk_core: None,
        witness: vec![],
        da_payload: vec![],
    };
    spend_tx.witness = (0..4)
        .map(|idx| sign_input_witness(&spend_tx, idx, 100, ZERO_CHAIN_ID, &kp))
        .collect();
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
        2,
    )
    .expect("parallel connect");

    assert_eq!(par_summary.sig_task_count, 4);
    assert_eq!(par_summary.worker_panics, 0);
    assert_eq!(seq_summary.sum_fees, par_summary.sum_fees);
    assert_eq!(seq_summary.utxo_count, par_summary.utxo_count);
    assert_eq!(seq_summary.post_state_digest, par_summary.post_state_digest);
    assert_eq!(seq_state.utxos, par_state.utxos);
}

#[test]
fn connect_block_parallel_sig_verify_rejects_invalid_signature_without_state_mutation() {
    let height = 1u64;
    let mut prev = [0u8; 32];
    prev[0] = 0x99;
    let target = [0xffu8; 32];

    let kp = kp_or_skip!();
    let cov_data = p2pk_covenant_data_for_pubkey(&kp.pubkey);
    let prev_out = Outpoint {
        txid: prev,
        vout: 0,
    };

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
    let mut witness = sign_input_witness(&spend_tx, 0, 100, ZERO_CHAIN_ID, &kp);
    witness.signature[100] ^= 0xff;
    spend_tx.witness = vec![witness.clone()];
    let spend_bytes = tx_with_one_input_one_output_with_witness(
        prev,
        0,
        90,
        COV_TYPE_P2PK,
        &cov_data,
        witness.suite_id,
        &witness.pubkey,
        &witness.signature,
    );
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

    let start_utxos = HashMap::from([(
        prev_out.clone(),
        UtxoEntry {
            value: 100,
            covenant_type: COV_TYPE_P2PK,
            covenant_data: cov_data.clone(),
            creation_height: 0,
            created_by_coinbase: false,
        },
    )]);
    let mut state = clone_state(&start_utxos, 0);

    let err = crate::connect_block_parallel_sig_verify(
        &block,
        Some(prev),
        Some(target),
        height,
        Some(&[0]),
        &mut state,
        ZERO_CHAIN_ID,
        2,
    )
    .unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrSigInvalid);
    assert_eq!(state.utxos, start_utxos);
    assert_eq!(state.already_generated, 0);
}

#[test]
fn connect_block_parallel_sig_verify_coinbase_only_reports_empty_sig_queue() {
    let height = 1u64;
    let mut prev = [0u8; 32];
    prev[0] = 0xaa;
    let target = [0xffu8; 32];

    let subsidy = crate::subsidy::block_subsidy(height, 0);
    let coinbase = coinbase_with_witness_commitment_and_p2pk_value(height as u32, subsidy, &[]);
    let (_cb, coinbase_txid, _cbw, _cbn) = parse_tx(&coinbase).expect("parse coinbase");
    let root = merkle_root_txids(&[coinbase_txid]).expect("merkle root");
    let block = build_block_bytes(prev, root, target, 1, &[coinbase]);

    let mut seq_state = crate::connect_block_inmem::InMemoryChainState {
        utxos: HashMap::new(),
        already_generated: 0,
    };
    let seq_summary = crate::connect_block_basic_in_memory_at_height(
        &block,
        Some(prev),
        Some(target),
        height,
        Some(&[0]),
        &mut seq_state,
        ZERO_CHAIN_ID,
    )
    .expect("sequential coinbase-only");

    let mut par_state = crate::connect_block_inmem::InMemoryChainState {
        utxos: HashMap::new(),
        already_generated: 0,
    };
    let summary = crate::connect_block_parallel_sig_verify(
        &block,
        Some(prev),
        Some(target),
        height,
        Some(&[0]),
        &mut par_state,
        ZERO_CHAIN_ID,
        1,
    )
    .expect("parallel coinbase-only");

    assert_eq!(summary.sum_fees, 0);
    assert_eq!(summary.sig_task_count, 0);
    assert_eq!(summary.worker_panics, 0);
    assert_eq!(summary.post_state_digest, seq_summary.post_state_digest);
    assert_eq!(par_state.utxos, seq_state.utxos);
}
