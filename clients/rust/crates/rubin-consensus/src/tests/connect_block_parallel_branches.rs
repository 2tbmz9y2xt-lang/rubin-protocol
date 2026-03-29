use super::*;
use crate::output_descriptor_bytes;
use crate::{
    CoreExtActiveProfile, CoreExtProfiles, CoreExtVerificationBinding, TxContextBase,
    TxContextContinuing,
};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Mutex,
};

static CORE_EXT_TXCTX_CALLED: AtomicBool = AtomicBool::new(false);
static CORE_EXT_TXCTX_TEST_LOCK: Mutex<()> = Mutex::new(());

// Mirrors the production core-ext verifier callback signature.
#[allow(clippy::too_many_arguments)]
fn record_txctx_verifier(
    _ext_id: u16,
    _suite_id: u8,
    _pubkey: &[u8],
    _signature: &[u8],
    _digest32: &[u8; 32],
    _ext_payload: &[u8],
    _ctx_base: &TxContextBase,
    _ctx_continuing: &TxContextContinuing,
    _self_input_value: u64,
) -> Result<bool, crate::error::TxError> {
    CORE_EXT_TXCTX_CALLED.store(true, Ordering::SeqCst);
    Ok(true)
}

fn deferred_apply(
    tx: &crate::tx::Tx,
    txid: [u8; 32],
    utxos: &HashMap<Outpoint, UtxoEntry>,
    height: u64,
    profiles: &CoreExtProfiles,
) -> Result<(HashMap<Outpoint, UtxoEntry>, crate::UtxoApplySummary), crate::error::TxError> {
    crate::apply_non_coinbase_tx_basic_update_with_mtp_and_core_ext_profiles_and_suite_context_deferred_sigchecks(
        tx,
        txid,
        utxos,
        height,
        0,
        0,
        ZERO_CHAIN_ID,
        profiles,
        None,
        None,
    )
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

    let profiles = CoreExtProfiles::empty();
    let (next_utxos, summary) =
        deferred_apply(&tx, txid, &utxos, 1, &profiles).expect("multisig branch");
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

    let profiles = CoreExtProfiles::empty();
    let (_next_utxos, summary) =
        deferred_apply(&tx, txid, &utxos, 1, &profiles).expect("htlc claim branch");
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
            covenant_type: COV_TYPE_STEALTH,
            covenant_data: cov_data,
            creation_height: 0,
            created_by_coinbase: false,
        },
    )]);

    let profiles = CoreExtProfiles::empty();
    let (next_utxos, summary) =
        deferred_apply(&tx, txid, &utxos, 1, &profiles).expect("stealth branch");
    assert_eq!(summary.fee, 100);
    assert_eq!(next_utxos.len(), 1);
}

#[test]
fn apply_non_coinbase_tx_basic_workq_error_paths() {
    let profiles = CoreExtProfiles::empty();

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
        &profiles,
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
        &profiles,
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
    let err =
        deferred_apply(&missing_utxo_tx, [0u8; 32], &HashMap::new(), 1, &profiles).unwrap_err();
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
    let err = deferred_apply(&duplicate_input_tx, [0u8; 32], &utxos, 1, &profiles).unwrap_err();
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
    let err =
        deferred_apply(&mature_check_tx, [0u8; 32], &immature_utxos, 50, &profiles).unwrap_err();
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

    let profiles = CoreExtProfiles::empty();
    let (next_utxos, summary) =
        deferred_apply(&tx, txid, &utxos, 200, &profiles).expect("vault spend");
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

    let profiles = CoreExtProfiles::empty();
    let (next_utxos, summary) =
        deferred_apply(&tx, txid, &utxos, 200, &profiles).expect("vault creation");
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
    let profiles = CoreExtProfiles::empty();
    let err =
        deferred_apply(&forbidden_output_tx, [0u8; 32], &base_utxos, 200, &profiles).unwrap_err();
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
    let err =
        deferred_apply(&fee_sponsor_tx, [0u8; 32], &sponsor_utxos, 200, &profiles).unwrap_err();
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
    let err =
        deferred_apply(&not_whitelisted_tx, [0u8; 32], &base_utxos, 200, &profiles).unwrap_err();
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
    let err = deferred_apply(
        &creation_missing_owner_tx,
        [0u8; 32],
        &creation_utxos,
        200,
        &profiles,
    )
    .unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrVaultOwnerAuthRequired);

    let mut disallowed_destination_tx = tx_base(crate::tx::TxOutput {
        value: 50,
        covenant_type: COV_TYPE_EXT,
        covenant_data: core_ext_covdata(1, &[]),
    });
    disallowed_destination_tx.witness = vec![
        sign_input_witness(&disallowed_destination_tx, 0, 100, ZERO_CHAIN_ID, &vault_kp),
        sign_input_witness(&disallowed_destination_tx, 1, 10, ZERO_CHAIN_ID, &owner_kp),
    ];
    let err = deferred_apply(
        &disallowed_destination_tx,
        [0u8; 32],
        &base_utxos,
        200,
        &profiles,
    )
    .unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrVaultOutputNotWhitelisted);
}

#[test]
fn apply_non_coinbase_tx_basic_workq_core_ext_branches() {
    let _guard = CORE_EXT_TXCTX_TEST_LOCK.lock().expect("core ext test lock");
    CORE_EXT_TXCTX_CALLED.store(false, Ordering::SeqCst);
    let out_kp = kp_or_skip!();
    let out_cov = p2pk_covenant_data_for_pubkey(&out_kp.pubkey);
    let prev_txid = [0xa0; 32];
    let txid = [0xa1; 32];

    let pre_active_tx = crate::tx::Tx {
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
            covenant_data: out_cov.clone(),
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
            covenant_type: COV_TYPE_EXT,
            covenant_data: core_ext_covdata(42, &[]),
            creation_height: 0,
            created_by_coinbase: false,
        },
    )]);
    let inactive_profiles = CoreExtProfiles::empty();
    let (_next_utxos, summary) =
        deferred_apply(&pre_active_tx, txid, &ext_utxos, 1, &inactive_profiles)
            .expect("pre-active core ext");
    assert_eq!(summary.fee, 10);

    let active_disallowed_profiles = CoreExtProfiles {
        active: vec![CoreExtActiveProfile {
            ext_id: 42,
            tx_context_enabled: false,
            allowed_suite_ids: vec![0x99],
            verification_binding: CoreExtVerificationBinding::NativeVerifySig,
            verify_sig_ext_tx_context_fn: None,
            binding_descriptor: Vec::new(),
            ext_payload_schema: Vec::new(),
        }],
    };
    let disallowed_tx = crate::tx::Tx {
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
            covenant_data: out_cov.clone(),
        }],
        locktime: 0,
        witness: vec![crate::tx::WitnessItem {
            suite_id: SUITE_ID_ML_DSA_87,
            pubkey: vec![0u8; ML_DSA_87_PUBKEY_BYTES as usize],
            signature: vec![0u8; (ML_DSA_87_SIG_BYTES + 1) as usize],
        }],
        da_payload: vec![],
        da_commit_core: None,
        da_chunk_core: None,
    };
    let err = deferred_apply(
        &disallowed_tx,
        txid,
        &ext_utxos,
        1,
        &active_disallowed_profiles,
    )
    .unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrSigAlgInvalid);

    CORE_EXT_TXCTX_CALLED.store(false, Ordering::SeqCst);
    let txctx_profiles = CoreExtProfiles {
        active: vec![CoreExtActiveProfile {
            ext_id: 7,
            tx_context_enabled: true,
            allowed_suite_ids: vec![0x42],
            verification_binding: CoreExtVerificationBinding::VerifySigExtAccept,
            verify_sig_ext_tx_context_fn: Some(record_txctx_verifier),
            binding_descriptor: b"accept".to_vec(),
            ext_payload_schema: b"schema".to_vec(),
        }],
    };
    let txctx_tx = crate::tx::Tx {
        version: 1,
        tx_kind: 0x00,
        tx_nonce: 1,
        inputs: vec![crate::tx::TxInput {
            prev_txid: [0xb2; 32],
            prev_vout: 0,
            script_sig: vec![],
            sequence: 0,
        }],
        outputs: vec![crate::tx::TxOutput {
            value: 90,
            covenant_type: COV_TYPE_P2PK,
            covenant_data: out_cov.clone(),
        }],
        locktime: 0,
        witness: vec![crate::tx::WitnessItem {
            suite_id: 0x42,
            pubkey: vec![0x01, 0x02, 0x03],
            signature: vec![0x04, 0x01],
        }],
        da_payload: vec![],
        da_commit_core: None,
        da_chunk_core: None,
    };
    let txctx_utxos = HashMap::from([(
        Outpoint {
            txid: [0xb2; 32],
            vout: 0,
        },
        UtxoEntry {
            value: 100,
            covenant_type: COV_TYPE_EXT,
            covenant_data: core_ext_covdata(7, &[0x99]),
            creation_height: 0,
            created_by_coinbase: false,
        },
    )]);
    let (_next_utxos, summary) =
        deferred_apply(&txctx_tx, [0xb5; 32], &txctx_utxos, 1, &txctx_profiles)
            .expect("txcontext core ext");
    assert_eq!(summary.fee, 10);
    assert!(CORE_EXT_TXCTX_CALLED.load(Ordering::SeqCst));

    CORE_EXT_TXCTX_CALLED.store(false, Ordering::SeqCst);
    let malformed_output_tx = crate::tx::Tx {
        version: 1,
        tx_kind: 0x00,
        tx_nonce: 1,
        inputs: vec![crate::tx::TxInput {
            prev_txid: [0xb2; 32],
            prev_vout: 0,
            script_sig: vec![],
            sequence: 0,
        }],
        outputs: vec![crate::tx::TxOutput {
            value: 90,
            covenant_type: COV_TYPE_EXT,
            covenant_data: vec![0x01],
        }],
        locktime: 0,
        witness: vec![crate::tx::WitnessItem {
            suite_id: 0x42,
            pubkey: vec![0x01, 0x02, 0x03],
            signature: vec![0x04, 0x01],
        }],
        da_payload: vec![],
        da_commit_core: None,
        da_chunk_core: None,
    };
    let err = deferred_apply(
        &malformed_output_tx,
        [0xb6; 32],
        &txctx_utxos,
        1,
        &txctx_profiles,
    )
    .unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrCovenantTypeInvalid);
    assert!(!CORE_EXT_TXCTX_CALLED.load(Ordering::SeqCst));
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

    let profiles = CoreExtProfiles::empty();
    let (next_utxos, summary) =
        deferred_apply(&tx, txid, &utxos, 1, &profiles).expect("anchor output skip");
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
    let profiles = CoreExtProfiles::empty();
    let (next_utxos, summary) =
        deferred_apply(&tx, txid, &utxo_set, 1, &profiles).expect("wrapper success");
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
        &profiles,
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

    let profiles = CoreExtProfiles::empty();
    let err = deferred_apply(&tx, [0u8; 32], &utxos, 1, &profiles).unwrap_err();
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

    let profiles = CoreExtProfiles::empty();
    let err = deferred_apply(&tx, [0u8; 32], &utxos, 1, &profiles).unwrap_err();
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

    let profiles = CoreExtProfiles::empty();
    let err = deferred_apply(&tx, [0u8; 32], &utxos, 1, &profiles).unwrap_err();
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

    let profiles = CoreExtProfiles::empty();
    let err = deferred_apply(&tx, [0u8; 32], &utxos, 1, &profiles).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrSigAlgInvalid);
}
