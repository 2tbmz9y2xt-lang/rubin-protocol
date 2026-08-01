use super::*;
use crate::output_descriptor_bytes;

fn deferred_apply(
    tx: &crate::tx::Tx,
    txid: [u8; 32],
    utxos: &HashMap<Outpoint, UtxoEntry>,
    height: u64,
) -> Result<(HashMap<Outpoint, UtxoEntry>, crate::UtxoApplySummary), crate::error::TxError> {
    crate::apply_non_coinbase_tx_basic_update_with_mtp_and_core_ext_profiles_and_suite_context_deferred_sigchecks(
        tx,
        txid,
        utxos,
        height,
        0,
        0,
        ZERO_CHAIN_ID,
        None,
        None,
    )
}

fn p2pk_input(prev_txid: [u8; 32]) -> crate::tx::TxInput {
    crate::tx::TxInput {
        prev_txid,
        prev_vout: 0,
        script_sig: vec![],
        sequence: 0,
    }
}

fn p2pk_utxo(covenant_data: Vec<u8>) -> UtxoEntry {
    UtxoEntry {
        value: 100,
        covenant_type: COV_TYPE_P2PK,
        covenant_data,
        creation_height: 0,
        created_by_coinbase: false,
    }
}

fn p2pk_tx(
    tx_nonce: u64,
    inputs: Vec<crate::tx::TxInput>,
    output_value: u64,
    covenant_data: Vec<u8>,
) -> crate::tx::Tx {
    crate::tx::Tx {
        version: 1,
        tx_kind: 0,
        tx_nonce,
        inputs,
        outputs: vec![crate::tx::TxOutput {
            value: output_value,
            covenant_type: COV_TYPE_P2PK,
            covenant_data,
        }],
        locktime: 0,
        witness: vec![],
        da_payload: vec![],
        da_commit_core: None,
        da_chunk_core: None,
    }
}

fn p2pk_sig_cache_tuple(tx: &crate::tx::Tx, input_index: usize) -> (u8, &[u8], &[u8], [u8; 32]) {
    let witness = &tx.witness[input_index];
    let (_, crypto_signature) = witness.signature.split_last().expect("sighash byte");
    let digest = crate::sighash::sighash_v1_digest(
        tx,
        u32::try_from(input_index).expect("input index fits u32"),
        100,
        ZERO_CHAIN_ID,
    )
    .expect("sighash digest");
    (witness.suite_id, &witness.pubkey, crypto_signature, digest)
}

fn core_ext_covdata(ext_id: u16, payload: &[u8]) -> Vec<u8> {
    crate::core_ext::encode_core_ext_covenant_data(ext_id, payload)
        .expect("CORE_EXT covenant_data encode")
}

fn stealth_covenant_data_for_pubkey(pubkey: &[u8]) -> Vec<u8> {
    let mut cov = vec![0u8; MAX_STEALTH_COVENANT_DATA as usize];
    let key_id = sha3_256(pubkey);
    let split = cov.len() - 32;
    cov[split..].copy_from_slice(&key_id);
    cov
}

#[test]
fn apply_non_coinbase_tx_basic_workq_multisig_branch() {
    let kp1 = kp_or_skip!();
    let kp2 = kp_or_skip!();
    let mut key_a = sha3_256(&kp1.pubkey);
    let mut key_b = sha3_256(&kp2.pubkey);
    let (mut signer_a, mut signer_b) = (&kp1, &kp2);
    if key_a > key_b {
        std::mem::swap(&mut key_a, &mut key_b);
        std::mem::swap(&mut signer_a, &mut signer_b);
    }

    let cov_data = encode_multisig_covenant_data(1, &[key_a, key_b]);
    let out_cov_data = p2pk_covenant_data_for_pubkey(&signer_a.pubkey);
    let prev_txid = [0xaau8; 32];
    let txid = [0xbbu8; 32];
    let tx = crate::tx::Tx {
        version: 1,
        tx_kind: 0x00,
        tx_nonce: 1,
        inputs: vec![crate::tx::TxInput {
            prev_txid,
            prev_vout: 0,
            script_sig: vec![],
            sequence: 0,
        }],
        outputs: vec![crate::tx::TxOutput {
            value: 900,
            covenant_type: COV_TYPE_P2PK,
            covenant_data: out_cov_data,
        }],
        locktime: 0,
        witness: vec![
            sign_input_witness(
                &crate::tx::Tx {
                    version: 1,
                    tx_kind: 0x00,
                    tx_nonce: 1,
                    inputs: vec![crate::tx::TxInput {
                        prev_txid,
                        prev_vout: 0,
                        script_sig: vec![],
                        sequence: 0,
                    }],
                    outputs: vec![crate::tx::TxOutput {
                        value: 900,
                        covenant_type: COV_TYPE_P2PK,
                        covenant_data: p2pk_covenant_data_for_pubkey(&signer_a.pubkey),
                    }],
                    locktime: 0,
                    witness: vec![],
                    da_payload: vec![],
                    da_commit_core: None,
                    da_chunk_core: None,
                },
                0,
                1000,
                ZERO_CHAIN_ID,
                signer_a,
            ),
            sentinel_witness_item(),
        ],
        da_payload: vec![],
        da_commit_core: None,
        da_chunk_core: None,
    };
    let utxos = HashMap::from([(
        Outpoint {
            txid: prev_txid,
            vout: 0,
        },
        UtxoEntry {
            value: 1000,
            covenant_type: COV_TYPE_MULTISIG,
            covenant_data: cov_data,
            creation_height: 0,
            created_by_coinbase: false,
        },
    )]);

    let (next_utxos, summary) = deferred_apply(&tx, txid, &utxos, 1).expect("multisig branch");
    assert_eq!(summary.fee, 100);
    assert_eq!(next_utxos.len(), 1);
}

#[test]
fn apply_non_coinbase_tx_basic_workq_htlc_claim_branch() {
    let claim_kp = kp_or_skip!();
    let refund_kp = kp_or_skip!();
    let claim_key_id = sha3_256(&claim_kp.pubkey);
    let refund_key_id = sha3_256(&refund_kp.pubkey);
    let preimage = b"htlc-branch-preimage";
    let prev_txid = [0xccu8; 32];
    let txid = [0xddu8; 32];
    let entry = UtxoEntry {
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
    };
    let tx = crate::tx::Tx {
        version: 1,
        tx_kind: 0x00,
        tx_nonce: 1,
        inputs: vec![crate::tx::TxInput {
            prev_txid,
            prev_vout: 0,
            script_sig: vec![],
            sequence: 0,
        }],
        outputs: vec![crate::tx::TxOutput {
            value: 90,
            covenant_type: COV_TYPE_P2PK,
            covenant_data: p2pk_covenant_data_for_pubkey(&claim_kp.pubkey),
        }],
        locktime: 0,
        witness: vec![
            crate::tx::WitnessItem {
                suite_id: SUITE_ID_SENTINEL,
                pubkey: claim_key_id.to_vec(),
                signature: {
                    let mut payload = Vec::new();
                    payload.push(0x00);
                    payload.extend_from_slice(&(preimage.len() as u16).to_le_bytes());
                    payload.extend_from_slice(preimage);
                    payload
                },
            },
            sign_input_witness(
                &crate::tx::Tx {
                    version: 1,
                    tx_kind: 0x00,
                    tx_nonce: 1,
                    inputs: vec![crate::tx::TxInput {
                        prev_txid,
                        prev_vout: 0,
                        script_sig: vec![],
                        sequence: 0,
                    }],
                    outputs: vec![crate::tx::TxOutput {
                        value: 90,
                        covenant_type: COV_TYPE_P2PK,
                        covenant_data: p2pk_covenant_data_for_pubkey(&claim_kp.pubkey),
                    }],
                    locktime: 0,
                    witness: vec![],
                    da_payload: vec![],
                    da_commit_core: None,
                    da_chunk_core: None,
                },
                0,
                entry.value,
                ZERO_CHAIN_ID,
                &claim_kp,
            ),
        ],
        da_payload: vec![],
        da_commit_core: None,
        da_chunk_core: None,
    };
    let utxos = HashMap::from([(
        Outpoint {
            txid: prev_txid,
            vout: 0,
        },
        entry.clone(),
    )]);

    let (_next_utxos, summary) = deferred_apply(&tx, txid, &utxos, 1).expect("htlc claim branch");
    assert_eq!(summary.fee, entry.value - 90);
}

#[test]
fn apply_non_coinbase_tx_basic_workq_stealth_branch() {
    let kp = kp_or_skip!();
    let cov_data = stealth_covenant_data_for_pubkey(&kp.pubkey);
    let prev_txid = [0xeeu8; 32];
    let txid = [0xffu8; 32];
    let tx = crate::tx::Tx {
        version: 1,
        tx_kind: 0x00,
        tx_nonce: 1,
        inputs: vec![crate::tx::TxInput {
            prev_txid,
            prev_vout: 0,
            script_sig: vec![],
            sequence: 0,
        }],
        outputs: vec![crate::tx::TxOutput {
            value: 400,
            covenant_type: COV_TYPE_P2PK,
            covenant_data: p2pk_covenant_data_for_pubkey(&kp.pubkey),
        }],
        locktime: 0,
        witness: vec![sign_input_witness(
            &crate::tx::Tx {
                version: 1,
                tx_kind: 0x00,
                tx_nonce: 1,
                inputs: vec![crate::tx::TxInput {
                    prev_txid,
                    prev_vout: 0,
                    script_sig: vec![],
                    sequence: 0,
                }],
                outputs: vec![crate::tx::TxOutput {
                    value: 400,
                    covenant_type: COV_TYPE_P2PK,
                    covenant_data: p2pk_covenant_data_for_pubkey(&kp.pubkey),
                }],
                locktime: 0,
                witness: vec![],
                da_payload: vec![],
                da_commit_core: None,
                da_chunk_core: None,
            },
            0,
            500,
            ZERO_CHAIN_ID,
            &kp,
        )],
        da_payload: vec![],
        da_commit_core: None,
        da_chunk_core: None,
    };
    let utxos = HashMap::from([(
        Outpoint {
            txid: prev_txid,
            vout: 0,
        },
        UtxoEntry {
            value: 500,
            covenant_type: COV_TYPE_CORE_STEALTH,
            covenant_data: cov_data,
            creation_height: 0,
            created_by_coinbase: false,
        },
    )]);

    let (next_utxos, summary) = deferred_apply(&tx, txid, &utxos, 1).expect("stealth branch");
    assert_eq!(summary.fee, 100);
    assert_eq!(next_utxos.len(), 1);
}

#[test]
fn apply_non_coinbase_tx_basic_workq_error_paths() {
    let err = deferred_apply(
        &crate::tx::Tx {
            version: 1,
            tx_kind: 0x00,
            tx_nonce: 1,
            inputs: vec![],
            outputs: vec![],
            locktime: 0,
            witness: vec![],
            da_payload: vec![],
            da_commit_core: None,
            da_chunk_core: None,
        },
        [0u8; 32],
        &HashMap::new(),
        0,
    )
    .unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrParse);

    let err = deferred_apply(
        &crate::tx::Tx {
            version: 1,
            tx_kind: 0x00,
            tx_nonce: 0,
            inputs: vec![crate::tx::TxInput {
                prev_txid: [0x01; 32],
                prev_vout: 0,
                script_sig: vec![],
                sequence: 0,
            }],
            outputs: vec![],
            locktime: 0,
            witness: vec![],
            da_payload: vec![],
            da_commit_core: None,
            da_chunk_core: None,
        },
        [0u8; 32],
        &HashMap::new(),
        0,
    )
    .unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrTxNonceInvalid);

    let kp = kp_or_skip!();
    let cov_data = p2pk_covenant_data_for_pubkey(&kp.pubkey);
    let mut missing_utxo_tx = crate::tx::Tx {
        version: 1,
        tx_kind: 0x00,
        tx_nonce: 1,
        inputs: vec![crate::tx::TxInput {
            prev_txid: [0x42; 32],
            prev_vout: 0,
            script_sig: vec![],
            sequence: 0,
        }],
        outputs: vec![crate::tx::TxOutput {
            value: 1,
            covenant_type: COV_TYPE_P2PK,
            covenant_data: cov_data.clone(),
        }],
        locktime: 0,
        witness: vec![],
        da_payload: vec![],
        da_commit_core: None,
        da_chunk_core: None,
    };
    missing_utxo_tx.witness = vec![sign_input_witness(
        &missing_utxo_tx,
        0,
        100,
        ZERO_CHAIN_ID,
        &kp,
    )];
    let err = deferred_apply(&missing_utxo_tx, [0u8; 32], &HashMap::new(), 1).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrMissingUtxo);

    let prev_txid = [0x24; 32];
    let mut duplicate_input_tx = crate::tx::Tx {
        version: 1,
        tx_kind: 0x00,
        tx_nonce: 1,
        inputs: vec![
            crate::tx::TxInput {
                prev_txid,
                prev_vout: 0,
                script_sig: vec![],
                sequence: 0,
            },
            crate::tx::TxInput {
                prev_txid,
                prev_vout: 0,
                script_sig: vec![],
                sequence: 0,
            },
        ],
        outputs: vec![crate::tx::TxOutput {
            value: 1,
            covenant_type: COV_TYPE_P2PK,
            covenant_data: cov_data.clone(),
        }],
        locktime: 0,
        witness: vec![],
        da_payload: vec![],
        da_commit_core: None,
        da_chunk_core: None,
    };
    duplicate_input_tx.witness = vec![
        sign_input_witness(&duplicate_input_tx, 0, 100, ZERO_CHAIN_ID, &kp),
        sign_input_witness(&duplicate_input_tx, 1, 100, ZERO_CHAIN_ID, &kp),
    ];
    let utxos = HashMap::from([(
        Outpoint {
            txid: prev_txid,
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
    let err = deferred_apply(&duplicate_input_tx, [0u8; 32], &utxos, 1).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrParse);

    let immature_utxos = HashMap::from([(
        Outpoint {
            txid: prev_txid,
            vout: 0,
        },
        UtxoEntry {
            value: 100,
            covenant_type: COV_TYPE_P2PK,
            covenant_data: cov_data,
            creation_height: 0,
            created_by_coinbase: true,
        },
    )]);
    let mut mature_check_tx = crate::tx::Tx {
        version: 1,
        tx_kind: 0x00,
        tx_nonce: 1,
        inputs: vec![crate::tx::TxInput {
            prev_txid,
            prev_vout: 0,
            script_sig: vec![],
            sequence: 0,
        }],
        outputs: vec![crate::tx::TxOutput {
            value: 1,
            covenant_type: COV_TYPE_P2PK,
            covenant_data: p2pk_covenant_data_for_pubkey(&kp.pubkey),
        }],
        locktime: 0,
        witness: vec![],
        da_payload: vec![],
        da_commit_core: None,
        da_chunk_core: None,
    };
    mature_check_tx.witness = vec![sign_input_witness(
        &mature_check_tx,
        0,
        100,
        ZERO_CHAIN_ID,
        &kp,
    )];
    let err = deferred_apply(&mature_check_tx, [0u8; 32], &immature_utxos, 50).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrCoinbaseImmature);
}

#[test]
fn apply_non_coinbase_tx_basic_workq_vault_spend_ok() {
    let owner_kp = kp_or_skip!();
    let vault_kp = kp_or_skip!();
    let dest_kp = kp_or_skip!();
    let owner_cov = p2pk_covenant_data_for_pubkey(&owner_kp.pubkey);
    let owner_lock_id = sha3_256(&output_descriptor_bytes(COV_TYPE_P2PK, &owner_cov));
    let dest_cov = p2pk_covenant_data_for_pubkey(&dest_kp.pubkey);
    let whitelist_h = sha3_256(&output_descriptor_bytes(COV_TYPE_P2PK, &dest_cov));
    let vault_key_id = sha3_256(&vault_kp.pubkey);
    let vault_cov = encode_vault_covenant_data(owner_lock_id, 1, &[vault_key_id], &[whitelist_h]);
    let prev_vault = [0xd1u8; 32];
    let prev_owner = [0xd2u8; 32];
    let txid = [0xd3u8; 32];
    let tx = crate::tx::Tx {
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
                prev_txid: prev_owner,
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
        witness: vec![
            sign_input_witness(
                &crate::tx::Tx {
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
                            prev_txid: prev_owner,
                            prev_vout: 0,
                            script_sig: vec![],
                            sequence: 0,
                        },
                    ],
                    outputs: vec![crate::tx::TxOutput {
                        value: 100,
                        covenant_type: COV_TYPE_P2PK,
                        covenant_data: p2pk_covenant_data_for_pubkey(&dest_kp.pubkey),
                    }],
                    locktime: 0,
                    witness: vec![],
                    da_payload: vec![],
                    da_commit_core: None,
                    da_chunk_core: None,
                },
                0,
                100,
                ZERO_CHAIN_ID,
                &vault_kp,
            ),
            sign_input_witness(
                &crate::tx::Tx {
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
                            prev_txid: prev_owner,
                            prev_vout: 0,
                            script_sig: vec![],
                            sequence: 0,
                        },
                    ],
                    outputs: vec![crate::tx::TxOutput {
                        value: 100,
                        covenant_type: COV_TYPE_P2PK,
                        covenant_data: p2pk_covenant_data_for_pubkey(&dest_kp.pubkey),
                    }],
                    locktime: 0,
                    witness: vec![],
                    da_payload: vec![],
                    da_commit_core: None,
                    da_chunk_core: None,
                },
                1,
                10,
                ZERO_CHAIN_ID,
                &owner_kp,
            ),
        ],
        da_payload: vec![],
        da_commit_core: None,
        da_chunk_core: None,
    };
    let utxos = HashMap::from([
        (
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
        ),
        (
            Outpoint {
                txid: prev_owner,
                vout: 0,
            },
            UtxoEntry {
                value: 10,
                covenant_type: COV_TYPE_P2PK,
                covenant_data: owner_cov,
                creation_height: 0,
                created_by_coinbase: false,
            },
        ),
    ]);

    let (next_utxos, summary) = deferred_apply(&tx, txid, &utxos, 200).expect("vault spend");
    assert_eq!(summary.fee, 10);
    assert_eq!(next_utxos.len(), 1);
}

#[test]
fn apply_non_coinbase_tx_basic_workq_vault_creation_ok() {
    let owner_kp = kp_or_skip!();
    let owner_cov = p2pk_covenant_data_for_pubkey(&owner_kp.pubkey);
    let owner_lock_id = sha3_256(&output_descriptor_bytes(COV_TYPE_P2PK, &owner_cov));
    let dest_kp = kp_or_skip!();
    let dest_cov = p2pk_covenant_data_for_pubkey(&dest_kp.pubkey);
    let whitelist_h = sha3_256(&output_descriptor_bytes(COV_TYPE_P2PK, &dest_cov));
    let vault_cov = encode_vault_covenant_data(owner_lock_id, 1, &[[0x11; 32]], &[whitelist_h]);
    let prev_owner = [0xc1u8; 32];
    let txid = [0xc2u8; 32];
    let mut tx = crate::tx::Tx {
        version: 1,
        tx_kind: 0x00,
        tx_nonce: 1,
        inputs: vec![crate::tx::TxInput {
            prev_txid: prev_owner,
            prev_vout: 0,
            script_sig: vec![],
            sequence: 0,
        }],
        outputs: vec![crate::tx::TxOutput {
            value: 90,
            covenant_type: COV_TYPE_VAULT,
            covenant_data: vault_cov,
        }],
        locktime: 0,
        witness: vec![],
        da_payload: vec![],
        da_commit_core: None,
        da_chunk_core: None,
    };
    tx.witness = vec![sign_input_witness(&tx, 0, 100, ZERO_CHAIN_ID, &owner_kp)];
    let utxos = HashMap::from([(
        Outpoint {
            txid: prev_owner,
            vout: 0,
        },
        UtxoEntry {
            value: 100,
            covenant_type: COV_TYPE_P2PK,
            covenant_data: owner_cov,
            creation_height: 0,
            created_by_coinbase: false,
        },
    )]);

    let (next_utxos, summary) = deferred_apply(&tx, txid, &utxos, 200).expect("vault creation");
    assert_eq!(summary.fee, 10);
    assert_eq!(next_utxos.len(), 1);
}

#[test]
fn apply_non_coinbase_tx_basic_workq_vault_error_paths() {
    let owner_kp = kp_or_skip!();
    let vault_kp = kp_or_skip!();
    let dest_kp = kp_or_skip!();
    let owner_cov = p2pk_covenant_data_for_pubkey(&owner_kp.pubkey);
    let owner_lock_id = sha3_256(&output_descriptor_bytes(COV_TYPE_P2PK, &owner_cov));
    let dest_cov = p2pk_covenant_data_for_pubkey(&dest_kp.pubkey);
    let whitelist_h = sha3_256(&output_descriptor_bytes(COV_TYPE_P2PK, &dest_cov));
    let vault_key_id = sha3_256(&vault_kp.pubkey);
    let vault_cov = encode_vault_covenant_data(owner_lock_id, 1, &[vault_key_id], &[whitelist_h]);

    let tx_base = |output: crate::tx::TxOutput| crate::tx::Tx {
        version: 1,
        tx_kind: 0x00,
        tx_nonce: 1,
        inputs: vec![
            crate::tx::TxInput {
                prev_txid: [0xe1; 32],
                prev_vout: 0,
                script_sig: vec![],
                sequence: 0,
            },
            crate::tx::TxInput {
                prev_txid: [0xe2; 32],
                prev_vout: 0,
                script_sig: vec![],
                sequence: 0,
            },
        ],
        outputs: vec![output],
        locktime: 0,
        witness: vec![],
        da_payload: vec![],
        da_commit_core: None,
        da_chunk_core: None,
    };

    let mut forbidden_output_tx = tx_base(crate::tx::TxOutput {
        value: 50,
        covenant_type: COV_TYPE_VAULT,
        covenant_data: encode_vault_covenant_data(owner_lock_id, 1, &[[0x22; 32]], &[whitelist_h]),
    });
    forbidden_output_tx.witness = vec![
        sign_input_witness(&forbidden_output_tx, 0, 100, ZERO_CHAIN_ID, &vault_kp),
        sign_input_witness(&forbidden_output_tx, 1, 10, ZERO_CHAIN_ID, &owner_kp),
    ];
    let base_utxos = HashMap::from([
        (
            Outpoint {
                txid: [0xe1; 32],
                vout: 0,
            },
            UtxoEntry {
                value: 100,
                covenant_type: COV_TYPE_VAULT,
                covenant_data: vault_cov.clone(),
                creation_height: 0,
                created_by_coinbase: false,
            },
        ),
        (
            Outpoint {
                txid: [0xe2; 32],
                vout: 0,
            },
            UtxoEntry {
                value: 10,
                covenant_type: COV_TYPE_P2PK,
                covenant_data: owner_cov.clone(),
                creation_height: 0,
                created_by_coinbase: false,
            },
        ),
    ]);
    let err = deferred_apply(&forbidden_output_tx, [0u8; 32], &base_utxos, 200).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrVaultOutputNotWhitelisted);

    let sponsor_kp = kp_or_skip!();
    let sponsor_cov = p2pk_covenant_data_for_pubkey(&sponsor_kp.pubkey);
    let mut fee_sponsor_tx = crate::tx::Tx {
        version: 1,
        tx_kind: 0x00,
        tx_nonce: 1,
        inputs: vec![
            crate::tx::TxInput {
                prev_txid: [0xf1; 32],
                prev_vout: 0,
                script_sig: vec![],
                sequence: 0,
            },
            crate::tx::TxInput {
                prev_txid: [0xf2; 32],
                prev_vout: 0,
                script_sig: vec![],
                sequence: 0,
            },
            crate::tx::TxInput {
                prev_txid: [0xf3; 32],
                prev_vout: 0,
                script_sig: vec![],
                sequence: 0,
            },
        ],
        outputs: vec![crate::tx::TxOutput {
            value: 100,
            covenant_type: COV_TYPE_P2PK,
            covenant_data: dest_cov.clone(),
        }],
        locktime: 0,
        witness: vec![],
        da_payload: vec![],
        da_commit_core: None,
        da_chunk_core: None,
    };
    fee_sponsor_tx.witness = vec![
        sign_input_witness(&fee_sponsor_tx, 0, 100, ZERO_CHAIN_ID, &vault_kp),
        sign_input_witness(&fee_sponsor_tx, 1, 10, ZERO_CHAIN_ID, &owner_kp),
        sign_input_witness(&fee_sponsor_tx, 2, 5, ZERO_CHAIN_ID, &sponsor_kp),
    ];
    let sponsor_utxos = HashMap::from([
        (
            Outpoint {
                txid: [0xf1; 32],
                vout: 0,
            },
            UtxoEntry {
                value: 100,
                covenant_type: COV_TYPE_VAULT,
                covenant_data: vault_cov.clone(),
                creation_height: 0,
                created_by_coinbase: false,
            },
        ),
        (
            Outpoint {
                txid: [0xf2; 32],
                vout: 0,
            },
            UtxoEntry {
                value: 10,
                covenant_type: COV_TYPE_P2PK,
                covenant_data: owner_cov.clone(),
                creation_height: 0,
                created_by_coinbase: false,
            },
        ),
        (
            Outpoint {
                txid: [0xf3; 32],
                vout: 0,
            },
            UtxoEntry {
                value: 5,
                covenant_type: COV_TYPE_P2PK,
                covenant_data: sponsor_cov,
                creation_height: 0,
                created_by_coinbase: false,
            },
        ),
    ]);
    let err = deferred_apply(&fee_sponsor_tx, [0u8; 32], &sponsor_utxos, 200).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrVaultFeeSponsorForbidden);

    let outsider_kp = kp_or_skip!();
    let outsider_cov = p2pk_covenant_data_for_pubkey(&outsider_kp.pubkey);
    let mut not_whitelisted_tx = tx_base(crate::tx::TxOutput {
        value: 100,
        covenant_type: COV_TYPE_P2PK,
        covenant_data: outsider_cov,
    });
    not_whitelisted_tx.witness = vec![
        sign_input_witness(&not_whitelisted_tx, 0, 100, ZERO_CHAIN_ID, &vault_kp),
        sign_input_witness(&not_whitelisted_tx, 1, 10, ZERO_CHAIN_ID, &owner_kp),
    ];
    let err = deferred_apply(&not_whitelisted_tx, [0u8; 32], &base_utxos, 200).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrVaultOutputNotWhitelisted);

    let input_kp = kp_or_skip!();
    let input_cov = p2pk_covenant_data_for_pubkey(&input_kp.pubkey);
    let fake_owner_lock_id = [0xff; 32];
    let bad_vault_cov =
        encode_vault_covenant_data(fake_owner_lock_id, 1, &[[0x11; 32]], &[whitelist_h]);
    let mut creation_missing_owner_tx = crate::tx::Tx {
        version: 1,
        tx_kind: 0x00,
        tx_nonce: 1,
        inputs: vec![crate::tx::TxInput {
            prev_txid: [0xb1; 32],
            prev_vout: 0,
            script_sig: vec![],
            sequence: 0,
        }],
        outputs: vec![crate::tx::TxOutput {
            value: 90,
            covenant_type: COV_TYPE_VAULT,
            covenant_data: bad_vault_cov,
        }],
        locktime: 0,
        witness: vec![],
        da_payload: vec![],
        da_commit_core: None,
        da_chunk_core: None,
    };
    creation_missing_owner_tx.witness = vec![sign_input_witness(
        &creation_missing_owner_tx,
        0,
        100,
        ZERO_CHAIN_ID,
        &input_kp,
    )];
    let creation_utxos = HashMap::from([(
        Outpoint {
            txid: [0xb1; 32],
            vout: 0,
        },
        UtxoEntry {
            value: 100,
            covenant_type: COV_TYPE_P2PK,
            covenant_data: input_cov,
            creation_height: 0,
            created_by_coinbase: false,
        },
    )]);
    let err =
        deferred_apply(&creation_missing_owner_tx, [0u8; 32], &creation_utxos, 200).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrVaultOwnerAuthRequired);

    // A CORE_EXT (0x0102) destination output is UNASSIGNED and rejected by the
    // genesis covenant check (TxErrCovenantTypeInvalid) BEFORE the vault output
    // whitelist check runs.
    let mut disallowed_destination_tx = tx_base(crate::tx::TxOutput {
        value: 50,
        covenant_type: COV_TYPE_CORE_EXT,
        covenant_data: core_ext_covdata(1, &[]),
    });
    disallowed_destination_tx.witness = vec![
        sign_input_witness(&disallowed_destination_tx, 0, 100, ZERO_CHAIN_ID, &vault_kp),
        sign_input_witness(&disallowed_destination_tx, 1, 10, ZERO_CHAIN_ID, &owner_kp),
    ];
    let err = deferred_apply(&disallowed_destination_tx, [0u8; 32], &base_utxos, 200).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrCovenantTypeInvalid);
}

#[test]
fn apply_non_coinbase_tx_basic_workq_core_ext_0x0102_rejects() {
    // COV_TYPE_CORE_EXT (0x0102) is UNASSIGNED: spending an input of this
    // covenant type is rejected as TxErrCovenantTypeInvalid. The CORE_EXT
    // covenant-spend runtime has been removed.
    let out_kp = kp_or_skip!();
    let out_cov = p2pk_covenant_data_for_pubkey(&out_kp.pubkey);
    let prev_txid = [0xa0; 32];
    let txid = [0xa1; 32];

    let tx = crate::tx::Tx {
        version: 1,
        tx_kind: 0x00,
        tx_nonce: 1,
        inputs: vec![crate::tx::TxInput {
            prev_txid,
            prev_vout: 0,
            script_sig: vec![],
            sequence: 0,
        }],
        outputs: vec![crate::tx::TxOutput {
            value: 90,
            covenant_type: COV_TYPE_P2PK,
            covenant_data: out_cov,
        }],
        locktime: 0,
        witness: vec![crate::tx::WitnessItem {
            suite_id: SUITE_ID_SENTINEL,
            pubkey: vec![],
            signature: vec![],
        }],
        da_payload: vec![],
        da_commit_core: None,
        da_chunk_core: None,
    };
    let ext_utxos = HashMap::from([(
        Outpoint {
            txid: prev_txid,
            vout: 0,
        },
        UtxoEntry {
            value: 100,
            covenant_type: COV_TYPE_CORE_EXT,
            // ext_id:u16le(1) || ext_payload_len:CompactSize(0)
            covenant_data: vec![0x01, 0x00, 0x00],
            creation_height: 0,
            created_by_coinbase: false,
        },
    )]);

    let err = deferred_apply(&tx, txid, &ext_utxos, 1).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrCovenantTypeInvalid);
}

#[test]
fn apply_non_coinbase_tx_basic_workq_anchor_output_skip() {
    let kp = kp_or_skip!();
    let cov_data = p2pk_covenant_data_for_pubkey(&kp.pubkey);
    let prev_txid = [0x60; 32];
    let txid = [0x61; 32];
    let mut tx = crate::tx::Tx {
        version: 1,
        tx_kind: 0x00,
        tx_nonce: 1,
        inputs: vec![crate::tx::TxInput {
            prev_txid,
            prev_vout: 0,
            script_sig: vec![],
            sequence: 0,
        }],
        outputs: vec![
            crate::tx::TxOutput {
                value: 90,
                covenant_type: COV_TYPE_P2PK,
                covenant_data: cov_data.clone(),
            },
            crate::tx::TxOutput {
                value: 0,
                covenant_type: COV_TYPE_ANCHOR,
                covenant_data: vec![0u8; 32],
            },
        ],
        locktime: 0,
        witness: vec![],
        da_payload: vec![],
        da_commit_core: None,
        da_chunk_core: None,
    };
    tx.witness = vec![sign_input_witness(&tx, 0, 100, ZERO_CHAIN_ID, &kp)];
    let utxos = HashMap::from([(
        Outpoint {
            txid: prev_txid,
            vout: 0,
        },
        UtxoEntry {
            value: 100,
            covenant_type: COV_TYPE_P2PK,
            covenant_data: cov_data,
            creation_height: 0,
            created_by_coinbase: false,
        },
    )]);

    let (next_utxos, summary) = deferred_apply(&tx, txid, &utxos, 1).expect("anchor output skip");
    assert_eq!(summary.fee, 10);
    assert_eq!(next_utxos.len(), 1);
    assert!(!next_utxos.contains_key(&Outpoint { txid, vout: 1 }));
}

#[test]
fn apply_wrapper() {
    let (tx, utxo_set, txid) = {
        let kp = kp_or_skip!();
        let cov_data = p2pk_covenant_data_for_pubkey(&kp.pubkey);
        let prev_txid = [0x70; 32];
        let mut tx = crate::tx::Tx {
            version: 1,
            tx_kind: 0x00,
            tx_nonce: 1,
            inputs: vec![crate::tx::TxInput {
                prev_txid,
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
            witness: vec![],
            da_payload: vec![],
            da_commit_core: None,
            da_chunk_core: None,
        };
        tx.witness = vec![sign_input_witness(&tx, 0, 100, ZERO_CHAIN_ID, &kp)];
        let utxos = HashMap::from([(
            Outpoint {
                txid: prev_txid,
                vout: 0,
            },
            UtxoEntry {
                value: 100,
                covenant_type: COV_TYPE_P2PK,
                covenant_data: cov_data,
                creation_height: 0,
                created_by_coinbase: false,
            },
        )]);
        (tx, utxos, [0x71; 32])
    };
    let (next_utxos, summary) = deferred_apply(&tx, txid, &utxo_set, 1).expect("wrapper success");
    assert_eq!(summary.fee, 10);
    assert_eq!(next_utxos.len(), 1);

    let err = deferred_apply(
        &crate::tx::Tx {
            version: 1,
            tx_kind: 0x00,
            tx_nonce: 1,
            inputs: vec![],
            outputs: vec![],
            locktime: 0,
            witness: vec![],
            da_payload: vec![],
            da_commit_core: None,
            da_chunk_core: None,
        },
        [0u8; 32],
        &HashMap::new(),
        0,
    )
    .unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrParse);
}

#[test]
fn apply_non_coinbase_tx_basic_workq_covenant_genesis_error() {
    let kp = kp_or_skip!();
    let cov_data = p2pk_covenant_data_for_pubkey(&kp.pubkey);
    let prev_txid = [0xcc; 32];
    let mut tx = crate::tx::Tx {
        version: 1,
        tx_kind: 0x00,
        tx_nonce: 1,
        inputs: vec![crate::tx::TxInput {
            prev_txid,
            prev_vout: 0,
            script_sig: vec![],
            sequence: 0,
        }],
        outputs: vec![crate::tx::TxOutput {
            value: 0,
            covenant_type: COV_TYPE_P2PK,
            covenant_data: cov_data.clone(),
        }],
        locktime: 0,
        witness: vec![],
        da_payload: vec![],
        da_commit_core: None,
        da_chunk_core: None,
    };
    tx.witness = vec![sign_input_witness(&tx, 0, 100, ZERO_CHAIN_ID, &kp)];
    let utxos = HashMap::from([(
        Outpoint {
            txid: prev_txid,
            vout: 0,
        },
        UtxoEntry {
            value: 100,
            covenant_type: COV_TYPE_P2PK,
            covenant_data: cov_data,
            creation_height: 0,
            created_by_coinbase: false,
        },
    )]);

    let err = deferred_apply(&tx, [0u8; 32], &utxos, 1).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrCovenantTypeInvalid);
}

#[test]
fn apply_non_coinbase_tx_basic_workq_sighash_prehash_error() {
    let kp = kp_or_skip!();
    let cov_data = p2pk_covenant_data_for_pubkey(&kp.pubkey);
    let prev_txid = [0xdd; 32];
    let mut tx = crate::tx::Tx {
        version: 1,
        tx_kind: 0x00,
        tx_nonce: 1,
        inputs: vec![crate::tx::TxInput {
            prev_txid,
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
        witness: vec![],
        da_payload: vec![],
        da_commit_core: None,
        da_chunk_core: None,
    };
    tx.witness = vec![sign_input_witness(&tx, 0, 100, ZERO_CHAIN_ID, &kp)];
    tx.tx_kind = 0x01;
    let utxos = HashMap::from([(
        Outpoint {
            txid: prev_txid,
            vout: 0,
        },
        UtxoEntry {
            value: 100,
            covenant_type: COV_TYPE_P2PK,
            covenant_data: cov_data,
            creation_height: 0,
            created_by_coinbase: false,
        },
    )]);

    let err = deferred_apply(&tx, [0u8; 32], &utxos, 1).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrParse);
}

#[test]
fn apply_non_coinbase_tx_basic_workq_check_spend_covenant_error() {
    let kp = kp_or_skip!();
    let cov_data = p2pk_covenant_data_for_pubkey(&kp.pubkey);
    let prev_txid = [0xee; 32];
    let mut tx = crate::tx::Tx {
        version: 1,
        tx_kind: 0x00,
        tx_nonce: 1,
        inputs: vec![crate::tx::TxInput {
            prev_txid,
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
        witness: vec![],
        da_payload: vec![],
        da_commit_core: None,
        da_chunk_core: None,
    };
    tx.witness = vec![sign_input_witness(&tx, 0, 100, ZERO_CHAIN_ID, &kp)];
    let utxos = HashMap::from([(
        Outpoint {
            txid: prev_txid,
            vout: 0,
        },
        UtxoEntry {
            value: 100,
            covenant_type: COV_TYPE_VAULT,
            covenant_data: vec![0xff],
            creation_height: 0,
            created_by_coinbase: false,
        },
    )]);

    let err = deferred_apply(&tx, [0u8; 32], &utxos, 1).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrVaultMalformed);
}

#[test]
fn apply_non_coinbase_tx_basic_workq_p2pk_spend_q_error() {
    let kp = kp_or_skip!();
    let cov_data = p2pk_covenant_data_for_pubkey(&kp.pubkey);
    let prev_txid = [0xff; 32];
    let tx = crate::tx::Tx {
        version: 1,
        tx_kind: 0x00,
        tx_nonce: 1,
        inputs: vec![crate::tx::TxInput {
            prev_txid,
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
        witness: vec![crate::tx::WitnessItem {
            suite_id: 0xff,
            pubkey: kp.pubkey.clone(),
            signature: vec![0u8; (ML_DSA_87_SIG_BYTES + 1) as usize],
        }],
        da_payload: vec![],
        da_commit_core: None,
        da_chunk_core: None,
    };
    let utxos = HashMap::from([(
        Outpoint {
            txid: prev_txid,
            vout: 0,
        },
        UtxoEntry {
            value: 100,
            covenant_type: COV_TYPE_P2PK,
            covenant_data: cov_data,
            creation_height: 0,
            created_by_coinbase: false,
        },
    )]);

    let err = deferred_apply(&tx, [0u8; 32], &utxos, 1).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrSigAlgInvalid);
}

#[test]
fn queued_sigchecks_transaction_entry_rollback_to_mark() {
    let kp = test_mldsa87_keypair().expect("ML-DSA-87 backend required for RUB-1096");
    let covenant_data = p2pk_covenant_data_for_pubkey(&kp.pubkey);
    let prev_txid = [0x79; 32];
    let mut late_tx = p2pk_tx(1, vec![p2pk_input(prev_txid)], 101, covenant_data.clone());
    late_tx.witness = vec![sign_input_witness(&late_tx, 0, 100, ZERO_CHAIN_ID, &kp)];
    let utxos = HashMap::from([(
        Outpoint {
            txid: prev_txid,
            vout: 0,
        },
        p2pk_utxo(covenant_data),
    )]);
    let apply = |tx: &crate::tx::Tx, queue: &mut crate::sig_queue::SigCheckQueue| {
        crate::utxo_basic::apply_non_coinbase_tx_basic_update_with_mtp_and_core_ext_profiles_and_suite_context_queued_sigchecks(
            tx, [0x7a; 32], &utxos, 1, 0, 0, ZERO_CHAIN_ID, None, None, queue,
        )
    };

    for prepopulated in [false, true] {
        let cache = crate::sig_cache::SigCache::new(1);
        let mut queue = crate::sig_queue::SigCheckQueue::new(1).with_cache(cache.clone());
        let prefix_tx = if prepopulated {
            let mut prefix_tx = late_tx.clone();
            prefix_tx.outputs[0].value = 99;
            prefix_tx.witness = vec![sign_input_witness(&prefix_tx, 0, 100, ZERO_CHAIN_ID, &kp)];
            apply(&prefix_tx, &mut queue).expect("queue valid prefix");
            Some(prefix_tx)
        } else {
            None
        };
        let entry_mark = queue.mark();
        let entry_len = queue.len();
        let before = utxos.clone();

        let mut early_tx = late_tx.clone();
        early_tx.tx_nonce = 0;
        early_tx.witness = vec![sign_input_witness(&early_tx, 0, 100, ZERO_CHAIN_ID, &kp)];
        let early_err = apply(&early_tx, &mut queue).unwrap_err();
        assert_eq!(
            early_err,
            crate::error::TxError::new(
                ErrorCode::TxErrTxNonceInvalid,
                "tx_nonce must be >= 1 for non-coinbase",
            )
        );
        assert_eq!(
            queue.mark(),
            entry_mark,
            "early rejection changed entry mark"
        );
        assert_eq!(
            queue.len(),
            entry_len,
            "early rejection left a rejected suffix"
        );
        assert_eq!(utxos, before, "caller UTXOs changed on early rejection");

        let late_err = apply(&late_tx, &mut queue).unwrap_err();
        assert_eq!(
            late_err,
            crate::error::TxError::new(ErrorCode::TxErrValueConservation, "sum_out exceeds sum_in",)
        );
        assert_eq!(
            queue.mark(),
            entry_mark,
            "late rejection changed entry mark"
        );
        assert_eq!(
            queue.len(),
            entry_len,
            "late rejection left a rejected suffix"
        );
        assert_eq!(utxos, before, "caller UTXOs changed on late rejection");
        if let Some(prefix_tx) = prefix_tx {
            queue.flush().expect("preserved prefix flushes");
            let prefix = p2pk_sig_cache_tuple(&prefix_tx, 0);
            let rejected = p2pk_sig_cache_tuple(&late_tx, 0);
            assert_eq!(cache.len(), 1);
            assert!(cache.lookup(prefix.0, prefix.1, prefix.2, prefix.3));
            assert!(!cache.lookup(rejected.0, rejected.1, rejected.2, rejected.3));
        }
    }
}

#[test]
fn queued_sigchecks_transaction_entry_success_retains_tasks() {
    let kp1 = test_mldsa87_keypair().expect("ML-DSA-87 backend required for RUB-1096");
    let kp2 = test_mldsa87_keypair().expect("ML-DSA-87 backend required for RUB-1096");
    let cov1 = p2pk_covenant_data_for_pubkey(&kp1.pubkey);
    let cov2 = p2pk_covenant_data_for_pubkey(&kp2.pubkey);
    let prev1 = [0x7b; 32];
    let prev2 = [0x7c; 32];
    let mut tx = p2pk_tx(
        1,
        vec![p2pk_input(prev1), p2pk_input(prev2)],
        199,
        cov1.clone(),
    );
    tx.witness = vec![
        sign_input_witness(&tx, 0, 100, ZERO_CHAIN_ID, &kp1),
        sign_input_witness(&tx, 1, 100, ZERO_CHAIN_ID, &kp2),
    ];
    let utxos = HashMap::from([
        (
            Outpoint {
                txid: prev1,
                vout: 0,
            },
            p2pk_utxo(cov1),
        ),
        (
            Outpoint {
                txid: prev2,
                vout: 0,
            },
            p2pk_utxo(cov2),
        ),
    ]);
    let cache = crate::sig_cache::SigCache::new(1);
    let mut queue = crate::sig_queue::SigCheckQueue::new(1).with_cache(cache.clone());
    assert!(queue.is_empty());
    crate::utxo_basic::apply_non_coinbase_tx_basic_update_with_mtp_and_core_ext_profiles_and_suite_context_queued_sigchecks(
        &tx, [0x7d; 32], &utxos, 1, 0, 0, ZERO_CHAIN_ID, None, None, &mut queue,
    )
    .expect("queue valid two-input transaction");
    assert_eq!(
        queue.len(),
        2,
        "success retains both queued signature tasks"
    );
    queue.flush().expect("flush queued signatures");
    let first = p2pk_sig_cache_tuple(&tx, 0);
    let second = p2pk_sig_cache_tuple(&tx, 1);
    assert_eq!(cache.len(), 1);
    assert!(cache.lookup(first.0, first.1, first.2, first.3));
    assert!(!cache.lookup(second.0, second.1, second.2, second.3));
}

#[test]
fn apply_non_coinbase_tx_basic_deferred_htlc_creation_first_error_order() {
    let prev_txid = [0x65u8; 32];
    let hash = [0x42u8; 32];
    let claim_key_id = [0x11u8; 32];
    let tx = crate::tx::Tx {
        version: 1,
        tx_kind: 0x00,
        tx_nonce: 1,
        inputs: vec![crate::tx::TxInput {
            prev_txid,
            prev_vout: 0,
            script_sig: vec![],
            sequence: 0,
        }],
        outputs: vec![crate::tx::TxOutput {
            value: 0,
            covenant_type: COV_TYPE_HTLC,
            covenant_data: encode_htlc_covenant_data(
                hash,
                LOCK_MODE_HEIGHT,
                1,
                claim_key_id,
                claim_key_id,
            ),
        }],
        locktime: 0,
        witness: vec![],
        da_payload: vec![],
        da_commit_core: None,
        da_chunk_core: None,
    };
    let utxos = HashMap::from([(
        Outpoint {
            txid: prev_txid,
            vout: 0,
        },
        UtxoEntry {
            value: 1,
            covenant_type: COV_TYPE_P2PK,
            covenant_data: valid_p2pk_covenant_data(),
            creation_height: 0,
            created_by_coinbase: false,
        },
    )]);
    let before = utxos.clone();
    let err = deferred_apply(&tx, [0x66u8; 32], &utxos, 1).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrParse);
    assert_eq!(err.msg, "CORE_HTLC claim/refund key_id must differ");
    assert_eq!(utxos, before, "caller UTXOs changed on deferred rejection");

    let mut queue = crate::sig_queue::SigCheckQueue::new(1);
    let queued_err = crate::utxo_basic::apply_non_coinbase_tx_basic_update_with_mtp_and_core_ext_profiles_and_suite_context_queued_sigchecks(
        &tx,
        [0x66u8; 32],
        &utxos,
        1,
        0,
        0,
        ZERO_CHAIN_ID,
        None,
        None,
        &mut queue,
    )
    .unwrap_err();
    assert_eq!(queued_err.code, ErrorCode::TxErrParse);
    assert!(queue.is_empty(), "queued rejection left signature work");
}
