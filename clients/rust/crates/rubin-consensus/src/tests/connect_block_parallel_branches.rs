use super::*;
use crate::output_descriptor_bytes;

pub(super) struct Rub721LaterSpend(std::cell::Cell<usize>);

impl Rub721LaterSpend {
    pub(super) fn new() -> Self {
        Self(std::cell::Cell::new(0))
    }
}

impl crate::suite_registry::RotationProvider for Rub721LaterSpend {
    fn native_create_suites(&self, _: u64) -> crate::suite_registry::NativeSuiteSet {
        crate::suite_registry::NativeSuiteSet::new(&[1])
    }

    fn native_spend_suites(&self, _: u64) -> crate::suite_registry::NativeSuiteSet {
        let call = self.0.replace(self.0.get() + 1);
        if call == 1 {
            std::panic::panic_any("RUB-721 later spend");
        }
        crate::suite_registry::NativeSuiteSet::new(&[1])
    }
}

fn deferred_apply(
    tx: &crate::tx::Tx,
    txid: [u8; 32],
    utxos: &HashMap<Outpoint, UtxoEntry>,
    height: u64,
) -> Result<(HashMap<Outpoint, UtxoEntry>, crate::UtxoApplySummary), crate::error::TxError> {
    crate::apply_non_coinbase_tx_basic_update_with_mtp_and_suite_context_deferred_sigchecks(
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

#[test]
fn rub721_transaction_order() {
    let kp = test_mldsa87_keypair().expect("RUB-721 requires native ML-DSA");
    let other = test_mldsa87_keypair().expect("RUB-721 requires native ML-DSA");
    let cov = p2pk_covenant_data_for_pubkey(&kp.pubkey);
    let vault = encode_vault_covenant_data(
        [0x44; 32],
        1,
        &[sha3_256(&kp.pubkey)],
        &[sha3_256(&output_descriptor_bytes(COV_TYPE_P2PK, &cov))],
    );
    for first_valid in [false, true] {
        for variant in 0..7 {
            let mut tx = p2pk_tx(
                1,
                vec![p2pk_input([0x81; 32]), p2pk_input([0x82; 32])],
                90,
                cov.clone(),
            );
            let mut utxos = HashMap::from([
                (
                    Outpoint {
                        txid: [0x81; 32],
                        vout: 0,
                    },
                    p2pk_utxo(cov.clone()),
                ),
                (
                    Outpoint {
                        txid: [0x82; 32],
                        vout: 0,
                    },
                    p2pk_utxo(cov.clone()),
                ),
            ]);
            if variant == 3 {
                tx.outputs[0].value = 201;
            }
            if variant == 5 {
                tx.outputs[0].covenant_type = COV_TYPE_VAULT;
                tx.outputs[0].covenant_data = vault.clone();
            }
            let first = if variant == 6 {
                tx.inputs.insert(0, p2pk_input([0x83; 32]));
                let mut entry = p2pk_utxo(vault.clone());
                entry.covenant_type = COV_TYPE_VAULT;
                utxos.insert(
                    Outpoint {
                        txid: [0x83; 32],
                        vout: 0,
                    },
                    entry,
                );
                1
            } else {
                0
            };
            tx.witness = (0..tx.inputs.len())
                .map(|index| sign_input_witness(&tx, index as u32, 100, ZERO_CHAIN_ID, &kp))
                .collect();
            if !first_valid {
                let mut wrong = tx.clone();
                wrong.tx_nonce += 10;
                tx.witness[first] =
                    sign_input_witness(&wrong, first as u32, 100, ZERO_CHAIN_ID, &kp);
            }
            let expected_later = match variant {
                0 => {
                    tx.witness[1].suite_id = 0xfe;
                    crate::error::TxError::new(
                        ErrorCode::TxErrSigAlgInvalid,
                        "CORE_P2PK suite not in native spend set",
                    )
                }
                1 => {
                    tx.witness[1].pubkey = other.pubkey.clone();
                    crate::error::TxError::new(
                        ErrorCode::TxErrSigInvalid,
                        "CORE_P2PK key binding mismatch",
                    )
                }
                2 | 6 => {
                    *tx.witness.last_mut().unwrap().signature.last_mut().unwrap() = 0;
                    crate::error::TxError::new(
                        ErrorCode::TxErrSighashTypeInvalid,
                        "invalid sighash_type",
                    )
                }
                3 => crate::error::TxError::new(
                    ErrorCode::TxErrValueConservation,
                    "sum_out exceeds sum_in",
                ),
                4 => {
                    utxos.remove(&Outpoint {
                        txid: [0x82; 32],
                        vout: 0,
                    });
                    crate::error::TxError::new(ErrorCode::TxErrMissingUtxo, "utxo not found")
                }
                _ => crate::error::TxError::new(
                    ErrorCode::TxErrVaultOwnerAuthRequired,
                    "missing owner-authorized input for CORE_VAULT creation",
                ),
            };
            let expected = if first_valid || variant >= 4 {
                expected_later
            } else {
                crate::error::TxError::new(
                    ErrorCode::TxErrSigInvalid,
                    "CORE_P2PK signature invalid",
                )
            };
            let before = utxos.clone();
            let tx_before = tx.clone();
            assert_eq!(
                deferred_apply(&tx, [0x84; 32], &utxos, 1).unwrap_err(),
                expected
            );
            let cache = crate::sig_cache::SigCache::new(16);
            let mut queue = crate::sig_queue::SigCheckQueue::new(2).with_cache(cache.clone());
            let mut prefix = p2pk_tx(19, vec![p2pk_input([0x81; 32])], 99, cov.clone());
            prefix.witness = vec![sign_input_witness(&prefix, 0, 100, ZERO_CHAIN_ID, &kp)];
            let apply = |current: &crate::tx::Tx, queue: &mut crate::sig_queue::SigCheckQueue| {
                crate::utxo_basic::apply_non_coinbase_tx_basic_update_with_mtp_and_suite_context_queued_sigchecks(
                    current, [0x84; 32], &utxos, 1, 0, 0, ZERO_CHAIN_ID, None, None, queue,
                )
            };
            apply(&prefix, &mut queue).unwrap();
            let mark = queue.mark();
            assert_eq!(
                apply(&tx, &mut queue).unwrap_err(),
                expected,
                "variant {variant}, first_valid={first_valid}"
            );
            assert_eq!(queue.mark(), mark);
            assert_eq!(queue.len(), 1);
            assert_eq!(utxos, before);
            assert_eq!(tx, tx_before);
            apply(&prefix, &mut queue).expect("next valid sibling");
            queue.flush().expect("retained prefix remains valid");
            let tuple = p2pk_sig_cache_tuple(&prefix, 0);
            assert!(cache.lookup(tuple.0, tuple.1, tuple.2, tuple.3));
        }
    }
}

#[test]
fn rub721_transaction_unwind() {
    use std::panic::{catch_unwind, AssertUnwindSafe};
    let kp = test_mldsa87_keypair().expect("RUB-721 requires native ML-DSA");
    let cov = p2pk_covenant_data_for_pubkey(&kp.pubkey);
    let utxos = HashMap::from([
        (
            Outpoint {
                txid: [0x85; 32],
                vout: 0,
            },
            p2pk_utxo(cov.clone()),
        ),
        (
            Outpoint {
                txid: [0x86; 32],
                vout: 0,
            },
            p2pk_utxo(cov.clone()),
        ),
    ]);
    let before = utxos.clone();
    for vault_output in [false, true] {
        for first_valid in [false, true] {
            let mut tx = p2pk_tx(
                1,
                vec![p2pk_input([0x85; 32]), p2pk_input([0x86; 32])],
                90,
                cov.clone(),
            );
            if vault_output {
                tx.outputs[0].covenant_type = COV_TYPE_VAULT;
                tx.outputs[0].covenant_data = encode_vault_covenant_data(
                    [0x44; 32],
                    1,
                    &[sha3_256(&kp.pubkey)],
                    &[[0x55; 32]],
                );
            }
            tx.witness = (0..2)
                .map(|index| sign_input_witness(&tx, index, 100, ZERO_CHAIN_ID, &kp))
                .collect();
            if !first_valid {
                let mut wrong = tx.clone();
                wrong.tx_nonce += 10;
                tx.witness[0] = sign_input_witness(&wrong, 0, 100, ZERO_CHAIN_ID, &kp);
            }
            let mut prefix = p2pk_tx(19, vec![p2pk_input([0x85; 32])], 99, cov.clone());
            prefix.witness = vec![sign_input_witness(&prefix, 0, 100, ZERO_CHAIN_ID, &kp)];
            let mut queue = crate::sig_queue::SigCheckQueue::new(1);
            crate::utxo_basic::apply_non_coinbase_tx_basic_update_with_mtp_and_suite_context_queued_sigchecks(
                &prefix, [0x87; 32], &utxos, 1, 0, 0, ZERO_CHAIN_ID, None, None, &mut queue,
            )
            .unwrap();
            let mark = queue.mark();
            let provider = Rub721LaterSpend::new();
            let outcome = catch_unwind(AssertUnwindSafe(|| {
                crate::utxo_basic::apply_non_coinbase_tx_basic_update_with_mtp_and_suite_context_queued_sigchecks(
                    &tx, [0x87; 32], &utxos, 1, 0, 0, ZERO_CHAIN_ID, Some(&provider), None, &mut queue,
                )
            }));
            if first_valid || vault_output {
                assert_eq!(
                    outcome.unwrap_err().downcast_ref::<&str>(),
                    Some(&"RUB-721 later spend")
                );
            } else {
                assert_eq!(
                    outcome.unwrap().unwrap_err(),
                    crate::error::TxError::new(
                        ErrorCode::TxErrSigInvalid,
                        "CORE_P2PK signature invalid"
                    )
                );
            }
            assert_eq!(queue.mark(), mark);
            assert_eq!(queue.len(), 1);
            assert_eq!(utxos, before);
            crate::utxo_basic::apply_non_coinbase_tx_basic_update_with_mtp_and_suite_context_queued_sigchecks(
                &prefix, [0x87; 32], &utxos, 1, 0, 0, ZERO_CHAIN_ID, None, None, &mut queue,
            )
            .expect("next valid sibling after unwind");
            queue
                .flush()
                .expect("retained prefix survives later unwind");
        }
    }
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
    assert_eq!(summary.fee, u128::from(entry.value - 90));
}

#[test]
fn connect_block_unknown_0x0105_refusal_preserves_state_and_nonce_prefix() {
    let kp = test_mldsa87_keypair().expect("ML-DSA-87 available");
    let cov = p2pk_covenant_data_for_pubkey(&kp.pubkey);
    let mut prefix = p2pk_tx(1, vec![p2pk_input([0xa1; 32])], 90, cov.clone());
    prefix.witness = vec![sign_input_witness(&prefix, 0, 100, ZERO_CHAIN_ID, &kp)];
    let prefix_bytes = crate::marshal_tx(&prefix).expect("marshal prefix");
    let original = crate::InMemoryChainState {
        utxos: HashMap::from([
            (
                Outpoint {
                    txid: [0xa1; 32],
                    vout: 0,
                },
                p2pk_utxo(cov.clone()),
            ),
            (
                Outpoint {
                    txid: [0xb1; 32],
                    vout: 0,
                },
                UtxoEntry {
                    value: 100,
                    covenant_type: 0x0105,
                    covenant_data: vec![0x55; 1600],
                    creation_height: 0,
                    created_by_coinbase: false,
                },
            ),
        ]),
        already_generated: 0,
    };
    for (unknown_output, nonce, expected) in [
        (false, 2, ErrorCode::TxErrCovenantTypeInvalid),
        (true, 2, ErrorCode::TxErrCovenantTypeInvalid),
        (true, 1, ErrorCode::TxErrNonceReplay),
    ] {
        let mut refused = p2pk_tx(nonce, vec![p2pk_input([0xb1; 32])], 90, cov.clone());
        if unknown_output {
            refused.inputs[0].prev_txid = [0xc1; 32];
            refused.outputs[0] = crate::TxOutput {
                value: 1,
                covenant_type: 0x0105,
                covenant_data: vec![0x55; 1600],
            };
        }
        let refused_bytes = crate::marshal_tx(&refused).expect("marshal refusal");
        let txs = vec![prefix_bytes.clone(), refused_bytes];
        let mut block_txs = vec![coinbase_with_witness_commitment(1, &txs)];
        block_txs.extend(txs);
        let txids: Vec<_> = block_txs
            .iter()
            .map(|b| parse_tx(b).expect("parse").1)
            .collect();
        let root = merkle_root_txids(&txids).expect("merkle");
        let block = build_block_bytes([0x22; 32], root, [0xff; 32], 9, &block_txs);
        for parallel in [false, true] {
            let mut state = original.clone();
            let result = if parallel {
                crate::connect_block_parallel_sig_verify(
                    &block,
                    None,
                    None,
                    1,
                    None,
                    &mut state,
                    ZERO_CHAIN_ID,
                    2,
                )
            } else {
                crate::connect_block_basic_in_memory_at_height(
                    &block,
                    None,
                    None,
                    1,
                    None,
                    &mut state,
                    ZERO_CHAIN_ID,
                )
            };
            assert_eq!(result.unwrap_err().code, expected);
            assert_eq!(state, original);
        }
        let parsed = crate::parse_block_bytes(&block).expect("parse block");
        let before_txs = parsed.txs.clone();
        let before_utxos = original.utxos.clone();
        assert_eq!(
            crate::precompute_tx_contexts(&parsed, &original.utxos, 1)
                .unwrap_err()
                .code,
            expected
        );
        assert_eq!(parsed.txs, before_txs);
        assert_eq!(original.utxos, before_utxos);
    }
    let coinbase = coinbase_with_witness_commitment(1, std::slice::from_ref(&prefix_bytes));
    let root = merkle_root_txids(&[
        parse_tx(&coinbase).expect("coinbase").1,
        parse_tx(&prefix_bytes).expect("prefix").1,
    ])
    .expect("merkle");
    let block = build_block_bytes([0x22; 32], root, [0xff; 32], 9, &[coinbase, prefix_bytes]);
    let mut sequential = original.clone();
    let summary = crate::connect_block_basic_in_memory_at_height(
        &block,
        None,
        None,
        1,
        None,
        &mut sequential,
        ZERO_CHAIN_ID,
    )
    .expect("prefix nonce remains available after refusal");
    assert_eq!(summary.sum_fees, 10);
    let mut parallel = original;
    let parallel_summary = crate::connect_block_parallel_sig_verify(
        &block,
        None,
        None,
        1,
        None,
        &mut parallel,
        ZERO_CHAIN_ID,
        2,
    )
    .expect("independent parallel block after refusal");
    assert_eq!(parallel_summary.sum_fees, 10);
    assert_eq!(parallel, sequential);
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

    let witness_count_cov = valid_p2pk_covenant_data();
    let mut witness_count_tx = p2pk_tx(
        1,
        vec![p2pk_input([0x43; 32])],
        90,
        witness_count_cov.clone(),
    );
    witness_count_tx.witness = vec![sentinel_witness_item(), sentinel_witness_item()];
    let witness_count_utxos = HashMap::from([(
        Outpoint {
            txid: [0x43; 32],
            vout: 0,
        },
        p2pk_utxo(witness_count_cov),
    )]);
    let err = deferred_apply(&witness_count_tx, [0x44; 32], &witness_count_utxos, 1)
        .expect_err("extra witness must fail");
    assert_eq!(err.code, ErrorCode::TxErrParse);
    assert_eq!(err.msg, "witness_count mismatch");

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

    let mut bad_signature_sponsor_tx = fee_sponsor_tx.clone();
    bad_signature_sponsor_tx.witness[0].signature[0] ^= 0x01;
    let err = crate::apply_non_coinbase_tx_basic_update_with_mtp_and_suite_context(
        &bad_signature_sponsor_tx,
        [0u8; 32],
        &sponsor_utxos,
        200,
        0,
        0,
        ZERO_CHAIN_ID,
        None,
        None,
    )
    .expect_err("non-owner sponsor precedes bad Vault signature");
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

    // A 0x0102 destination output is UNASSIGNED and rejected by the
    // genesis covenant check (TxErrCovenantTypeInvalid) BEFORE the vault output
    // whitelist check runs.
    let mut disallowed_destination_tx = tx_base(crate::tx::TxOutput {
        value: 50,
        covenant_type: 0x0102,
        // Opaque covenant data.
        covenant_data: vec![0x01, 0x00, 0x00],
    });
    disallowed_destination_tx.witness = vec![
        sign_input_witness(&disallowed_destination_tx, 0, 100, ZERO_CHAIN_ID, &vault_kp),
        sign_input_witness(&disallowed_destination_tx, 1, 10, ZERO_CHAIN_ID, &owner_kp),
    ];
    let err = deferred_apply(&disallowed_destination_tx, [0u8; 32], &base_utxos, 200).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrCovenantTypeInvalid);
}

#[test]
fn apply_non_coinbase_tx_basic_workq_unknown_covenant_0x0102_rejects() {
    // 0x0102 is UNASSIGNED: spending an input of this covenant type is rejected
    // as TxErrCovenantTypeInvalid.
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
            covenant_type: 0x0102,
            // Opaque covenant data.
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
fn apply_non_coinbase_tx_basic_output_group_cap_atomic() {
    use crate::suite_registry::{DefaultRotationProvider, NativeSuiteSet, RotationProvider};

    struct SimplicityActive;
    impl RotationProvider for SimplicityActive {
        fn native_create_suites(&self, h: u64) -> NativeSuiteSet {
            DefaultRotationProvider.native_create_suites(h)
        }
        fn native_spend_suites(&self, h: u64) -> NativeSuiteSet {
            DefaultRotationProvider.native_spend_suites(h)
        }
        fn simplicity_active_at_height(&self, _h: u64) -> bool {
            true
        }
    }

    let mut simplicity_covenant_data = [0x91; 32].to_vec();
    crate::compactsize::encode_compact_size(0, &mut simplicity_covenant_data);
    let simplicity_outputs = |count: usize| {
        (0..count)
            .map(|_| crate::tx::TxOutput {
                value: 1,
                covenant_type: COV_TYPE_CORE_SIMPLICITY,
                covenant_data: simplicity_covenant_data.clone(),
            })
            .collect::<Vec<_>>()
    };
    let tx_with_outputs = |prev_txid: [u8; 32], output_count: usize| crate::tx::Tx {
        version: 1,
        tx_kind: 0,
        tx_nonce: 1,
        inputs: vec![p2pk_input(prev_txid)],
        outputs: simplicity_outputs(output_count),
        locktime: 0,
        witness: vec![],
        da_payload: vec![],
        da_commit_core: None,
        da_chunk_core: None,
    };
    let p2pk_prev_txid = [0xb1; 32];
    let simplicity_prev_txid = [0xb2; 32];
    let p2pk_covenant_data = valid_p2pk_covenant_data();
    let cases = [
        (
            "P2PK input",
            tx_with_outputs(p2pk_prev_txid, SIMPLICITY_MAX_GROUP_OUTPUTS + 1),
            tx_with_outputs(p2pk_prev_txid, SIMPLICITY_MAX_GROUP_OUTPUTS),
            HashMap::from([(
                Outpoint {
                    txid: p2pk_prev_txid,
                    vout: 0,
                },
                UtxoEntry {
                    value: 100,
                    covenant_type: COV_TYPE_P2PK,
                    covenant_data: p2pk_covenant_data,
                    creation_height: 0,
                    created_by_coinbase: false,
                },
            )]),
            crate::error::TxError::new(ErrorCode::TxErrParse, "witness underflow"),
        ),
        (
            "CORE_SIMPLICITY input",
            tx_with_outputs(simplicity_prev_txid, SIMPLICITY_MAX_GROUP_OUTPUTS + 1),
            tx_with_outputs(simplicity_prev_txid, SIMPLICITY_MAX_GROUP_OUTPUTS),
            HashMap::from([(
                Outpoint {
                    txid: simplicity_prev_txid,
                    vout: 0,
                },
                UtxoEntry {
                    value: 100,
                    covenant_type: COV_TYPE_CORE_SIMPLICITY,
                    covenant_data: simplicity_covenant_data.clone(),
                    creation_height: 0,
                    created_by_coinbase: false,
                },
            )]),
            crate::error::TxError::new(
                ErrorCode::TxErrCovenantTypeInvalid,
                "CORE_SIMPLICITY spend evaluation not enabled",
            ),
        ),
    ];
    let active = SimplicityActive;
    let group_cap_error = crate::error::TxError::new(
        ErrorCode::TxErrCovenantTypeInvalid,
        "CORE_SIMPLICITY same-cmr output group exceeds limit",
    );

    for (label, over_cap, at_cap, utxos, control_error) in cases {
        let before = utxos.clone();
        let sequential =
            crate::utxo_basic::apply_non_coinbase_tx_basic_update_with_mtp_and_suite_context(
                &over_cap,
                [0xc1; 32],
                &utxos,
                1,
                0,
                0,
                ZERO_CHAIN_ID,
                Some(&active),
                None,
            );
        match sequential {
            Ok((work, summary)) => {
                panic!("{label}: expected no work or summary, got {work:?} / {summary:?}")
            }
            Err(error) => assert_eq!(error, group_cap_error, "{label}: sequential error"),
        }
        assert_eq!(utxos, before, "{label}: sequential rejection mutated UTXOs");

        assert_eq!(
            crate::utxo_basic::apply_non_coinbase_tx_basic_update_with_mtp_and_suite_context(
                &at_cap,
                [0xc2; 32],
                &utxos,
                1,
                0,
                0,
                ZERO_CHAIN_ID,
                Some(&active),
                None,
            )
            .unwrap_err(),
            control_error,
            "{label}: exactly-at-cap control must reach input validation",
        );

        let mut queue = crate::sig_queue::SigCheckQueue::new(1);
        let empty_mark = queue.mark();
        queue
            .push(
                SUITE_ID_ML_DSA_87,
                &[0x11],
                &[0x22],
                [0x33; 32],
                crate::error::TxError::new(ErrorCode::TxErrSigInvalid, "dummy prefix task"),
            )
            .expect("seed deterministic queued prefix");
        let prefix_mark = queue.mark();
        let prefix_len = queue.len();
        let prefix_debug = format!("{queue:?}");
        assert_eq!(prefix_len, 1, "{label}: queued prefix was not seeded");
        match crate::utxo_basic::apply_non_coinbase_tx_basic_update_with_mtp_and_suite_context_queued_sigchecks(
            &over_cap,
            [0xc3; 32],
            &utxos,
            1,
            0,
            0,
            ZERO_CHAIN_ID,
            Some(&active),
            None,
            &mut queue,
        ) {
            Ok((work, summary)) => {
                panic!("{label}: expected no queued work or summary, got {work:?} / {summary:?}")
            }
            Err(error) => assert_eq!(error, group_cap_error, "{label}: queued error"),
        }
        assert_eq!(utxos, before, "{label}: queued rejection mutated UTXOs");
        assert_eq!(queue.mark(), prefix_mark, "{label}: queue mark changed");
        assert_eq!(queue.len(), prefix_len, "{label}: queue length changed");
        assert_eq!(
            format!("{queue:?}"),
            prefix_debug,
            "{label}: queue state changed"
        );
        assert!(!queue.is_empty(), "{label}: queued prefix was cleared");
        queue.rollback_to(empty_mark);
        assert_eq!(queue.mark(), empty_mark, "{label}: queue cleanup mark");
        assert!(queue.is_empty(), "{label}: queue cleanup failed");
    }
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
        crate::utxo_basic::apply_non_coinbase_tx_basic_update_with_mtp_and_suite_context_queued_sigchecks(
            tx, [0x7a; 32], &utxos, 1, 0, 0, ZERO_CHAIN_ID, None, None, queue,
        )
    };

    for prepopulated in [false, true] {
        let cache = crate::sig_cache::SigCache::new(2);
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
            assert_eq!(cache.len(), 2);
            assert!(cache.lookup(prefix.0, prefix.1, prefix.2, prefix.3));
            assert!(cache.lookup(rejected.0, rejected.1, rejected.2, rejected.3));
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
    crate::utxo_basic::apply_non_coinbase_tx_basic_update_with_mtp_and_suite_context_queued_sigchecks(
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
fn queued_sigchecks_transaction_entry_unbound_registry_rollback() {
    let kp = test_mldsa87_keypair().expect("ML-DSA-87 backend required for RUB-1096");
    let covenant_data = p2pk_covenant_data_for_pubkey(&kp.pubkey);
    let prev_txid = [0x7e; 32];
    let mut late_tx = p2pk_tx(1, vec![p2pk_input(prev_txid)], 101, covenant_data.clone());
    late_tx.witness = vec![sign_input_witness(&late_tx, 0, 100, ZERO_CHAIN_ID, &kp)];
    let mut valid_tx = late_tx.clone();
    valid_tx.outputs[0].value = 99;
    valid_tx.witness = vec![sign_input_witness(&valid_tx, 0, 100, ZERO_CHAIN_ID, &kp)];
    let utxos = HashMap::from([(
        Outpoint {
            txid: prev_txid,
            vout: 0,
        },
        p2pk_utxo(covenant_data),
    )]);

    let registry_a = crate::SuiteRegistry::default_registry();
    let ml_dsa_87 = registry_a
        .lookup(SUITE_ID_ML_DSA_87)
        .expect("default ML-DSA-87 suite")
        .clone();
    let registry_b = crate::SuiteRegistry::with_suites(std::collections::BTreeMap::from([
        (SUITE_ID_ML_DSA_87, ml_dsa_87.clone()),
        (
            0x02,
            crate::suite_registry::SuiteParams {
                suite_id: 0x02,
                ..ml_dsa_87
            },
        ),
    ]));
    let apply = |tx: &crate::tx::Tx,
                 registry: &crate::SuiteRegistry,
                 queue: &mut crate::sig_queue::SigCheckQueue| {
        crate::utxo_basic::apply_non_coinbase_tx_basic_update_with_mtp_and_suite_context_queued_sigchecks(
            tx,
            [0x7f; 32],
            &utxos,
            1,
            0,
            0,
            ZERO_CHAIN_ID,
            None,
            Some(registry),
            queue,
        )
    };
    let value_error =
        crate::error::TxError::new(ErrorCode::TxErrValueConservation, "sum_out exceeds sum_in");
    let mismatch_error = crate::error::TxError::new(
        ErrorCode::TxErrSigAlgInvalid,
        "SigCheckQueue registry mismatch",
    );

    let mut unbound_queue = crate::sig_queue::SigCheckQueue::new(1);
    assert_eq!(
        apply(&late_tx, &registry_a, &mut unbound_queue).unwrap_err(),
        value_error.clone()
    );
    let reused_result =
        apply(&valid_tx, &registry_b, &mut unbound_queue).expect("registry B after rollback");
    unbound_queue.flush().expect("flush registry-B task");
    let mut fresh_b_queue = crate::sig_queue::SigCheckQueue::new(1);
    let fresh_result = apply(&valid_tx, &registry_b, &mut fresh_b_queue).expect("fresh registry B");
    fresh_b_queue.flush().expect("flush fresh registry-B task");
    assert_eq!(reused_result, fresh_result);
    assert_eq!(
        apply(&valid_tx, &registry_a, &mut unbound_queue).unwrap_err(),
        mismatch_error.clone()
    );

    let mut bound_queue = crate::sig_queue::SigCheckQueue::new(1).with_registry(&registry_a);
    assert_eq!(
        apply(&late_tx, &registry_a, &mut bound_queue).unwrap_err(),
        value_error
    );
    assert_eq!(
        apply(&valid_tx, &registry_b, &mut bound_queue).unwrap_err(),
        mismatch_error
    );
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
    let queued_err = crate::utxo_basic::apply_non_coinbase_tx_basic_update_with_mtp_and_suite_context_queued_sigchecks(
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
