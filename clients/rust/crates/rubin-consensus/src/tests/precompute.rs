use std::collections::HashMap;

use crate::block::{BlockHeader, BLOCK_HEADER_BYTES};
use crate::block_basic::ParsedBlock;
use crate::constants::*;
use crate::hash::sha3_256;
use crate::precompute::precompute_tx_contexts;
use crate::tx::{Tx, TxInput, TxOutput, WitnessItem};
use crate::utxo_basic::{Outpoint, UtxoEntry};

fn valid_p2pk_covenant_data() -> Vec<u8> {
    vec![0u8; 32] // key-id placeholder
}

fn dummy_witness() -> WitnessItem {
    WitnessItem {
        suite_id: SUITE_ID_ML_DSA_87,
        pubkey: vec![0u8; ML_DSA_87_PUBKEY_BYTES as usize],
        signature: vec![0u8; (ML_DSA_87_SIG_BYTES + 1) as usize],
    }
}

fn make_parsed_block(coinbase: Tx, txs: Vec<Tx>) -> ParsedBlock {
    let mut all_txs = Vec::with_capacity(1 + txs.len());
    all_txs.push(coinbase);
    all_txs.extend(txs);

    let txids: Vec<[u8; 32]> = (0..all_txs.len()).map(|i| sha3_256(&[i as u8])).collect();
    let wtxids = txids.clone();

    ParsedBlock {
        header: BlockHeader {
            version: 1,
            prev_block_hash: [0u8; 32],
            merkle_root: [0u8; 32],
            timestamp: 0,
            target: [0u8; 32],
            nonce: 0,
        },
        header_bytes: [0u8; BLOCK_HEADER_BYTES],
        tx_count: all_txs.len() as u64,
        txs: all_txs,
        txids,
        wtxids,
    }
}

fn simple_coinbase() -> Tx {
    Tx {
        version: 1,
        tx_kind: 0x00,
        tx_nonce: 0,
        inputs: vec![TxInput {
            prev_txid: [0u8; 32],
            prev_vout: 0xffff_ffff,
            script_sig: Vec::new(),
            sequence: 0,
        }],
        outputs: vec![TxOutput {
            value: 50_000_000,
            covenant_type: COV_TYPE_P2PK,
            covenant_data: valid_p2pk_covenant_data(),
        }],
        locktime: 0,
        da_commit_core: None,
        da_chunk_core: None,
        witness: Vec::new(),
        da_payload: Vec::new(),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Basic behavior
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn precompute_coinbase_only_block() {
    let pb = make_parsed_block(simple_coinbase(), vec![]);
    let utxos = HashMap::new();
    let results = precompute_tx_contexts(&pb, &utxos, 100).unwrap();
    assert!(results.is_empty());
}

#[test]
fn precompute_nil_block() {
    let pb = ParsedBlock {
        header: BlockHeader {
            version: 1,
            prev_block_hash: [0u8; 32],
            merkle_root: [0u8; 32],
            timestamp: 0,
            target: [0u8; 32],
            nonce: 0,
        },
        header_bytes: [0u8; BLOCK_HEADER_BYTES],
        tx_count: 0,
        txs: vec![],
        txids: vec![],
        wtxids: vec![],
    };
    let err = precompute_tx_contexts(&pb, &HashMap::new(), 0);
    assert!(err.is_err());
}

#[test]
fn precompute_single_p2pk() {
    let cov_data = valid_p2pk_covenant_data();
    let prev_txid = sha3_256(b"prev-tx-for-precompute");
    let op = Outpoint {
        txid: prev_txid,
        vout: 0,
    };
    let utxos = HashMap::from([(
        op.clone(),
        UtxoEntry {
            value: 1000,
            covenant_type: COV_TYPE_P2PK,
            covenant_data: cov_data.clone(),
            creation_height: 0,
            created_by_coinbase: false,
        },
    )]);

    let tx = Tx {
        version: 1,
        tx_kind: 0x00,
        tx_nonce: 1,
        inputs: vec![TxInput {
            prev_txid,
            prev_vout: 0,
            script_sig: Vec::new(),
            sequence: 0,
        }],
        outputs: vec![TxOutput {
            value: 900,
            covenant_type: COV_TYPE_P2PK,
            covenant_data: cov_data,
        }],
        locktime: 0,
        da_commit_core: None,
        da_chunk_core: None,
        witness: vec![dummy_witness()],
        da_payload: Vec::new(),
    };

    let pb = make_parsed_block(simple_coinbase(), vec![tx]);
    let results = precompute_tx_contexts(&pb, &utxos, 100).unwrap();
    assert_eq!(results.len(), 1);

    let ctx = &results[0];
    assert_eq!(ctx.tx_index, 1);
    assert_eq!(ctx.resolved_inputs.len(), 1);
    assert_eq!(ctx.resolved_inputs[0].value, 1000);
    assert_eq!(ctx.witness_start, 0);
    assert_eq!(ctx.witness_end, 1);
    assert_eq!(ctx.fee, 100);
    assert_eq!(ctx.input_outpoints, vec![op]);
}

#[test]
fn precompute_witness_cursor_parity() {
    let cov_data = valid_p2pk_covenant_data();
    let prev0 = sha3_256(b"utxo-0");
    let prev1 = sha3_256(b"utxo-1");

    let utxos = HashMap::from([
        (
            Outpoint {
                txid: prev0,
                vout: 0,
            },
            UtxoEntry {
                value: 500,
                covenant_type: COV_TYPE_P2PK,
                covenant_data: cov_data.clone(),
                creation_height: 0,
                created_by_coinbase: false,
            },
        ),
        (
            Outpoint {
                txid: prev1,
                vout: 0,
            },
            UtxoEntry {
                value: 500,
                covenant_type: COV_TYPE_P2PK,
                covenant_data: cov_data.clone(),
                creation_height: 0,
                created_by_coinbase: false,
            },
        ),
    ]);

    let tx0 = Tx {
        version: 1,
        tx_kind: 0x00,
        tx_nonce: 1,
        inputs: vec![TxInput {
            prev_txid: prev0,
            prev_vout: 0,
            script_sig: Vec::new(),
            sequence: 0,
        }],
        outputs: vec![TxOutput {
            value: 400,
            covenant_type: COV_TYPE_P2PK,
            covenant_data: cov_data.clone(),
        }],
        locktime: 0,
        da_commit_core: None,
        da_chunk_core: None,
        witness: vec![dummy_witness()],
        da_payload: Vec::new(),
    };
    let tx1 = Tx {
        version: 1,
        tx_kind: 0x00,
        tx_nonce: 2,
        inputs: vec![TxInput {
            prev_txid: prev1,
            prev_vout: 0,
            script_sig: Vec::new(),
            sequence: 0,
        }],
        outputs: vec![TxOutput {
            value: 400,
            covenant_type: COV_TYPE_P2PK,
            covenant_data: cov_data,
        }],
        locktime: 0,
        da_commit_core: None,
        da_chunk_core: None,
        witness: vec![dummy_witness()],
        da_payload: Vec::new(),
    };

    let pb = make_parsed_block(simple_coinbase(), vec![tx0, tx1]);
    let results = precompute_tx_contexts(&pb, &utxos, 100).unwrap();
    assert_eq!(results.len(), 2);

    // Per-tx cursor reset: both [0,1)
    assert_eq!(results[0].witness_start, 0);
    assert_eq!(results[0].witness_end, 1);
    assert_eq!(results[1].witness_start, 0);
    assert_eq!(results[1].witness_end, 1);
    assert_eq!(results[0].fee, 100);
    assert_eq!(results[1].fee, 100);
}

#[test]
fn precompute_same_block_parent_child() {
    let cov_data = valid_p2pk_covenant_data();
    let prev_txid = sha3_256(b"genesis-utxo");

    let utxos = HashMap::from([(
        Outpoint {
            txid: prev_txid,
            vout: 0,
        },
        UtxoEntry {
            value: 1000,
            covenant_type: COV_TYPE_P2PK,
            covenant_data: cov_data.clone(),
            creation_height: 0,
            created_by_coinbase: false,
        },
    )]);

    let tx0 = Tx {
        version: 1,
        tx_kind: 0x00,
        tx_nonce: 1,
        inputs: vec![TxInput {
            prev_txid,
            prev_vout: 0,
            script_sig: Vec::new(),
            sequence: 0,
        }],
        outputs: vec![TxOutput {
            value: 900,
            covenant_type: COV_TYPE_P2PK,
            covenant_data: cov_data.clone(),
        }],
        locktime: 0,
        da_commit_core: None,
        da_chunk_core: None,
        witness: vec![dummy_witness()],
        da_payload: Vec::new(),
    };

    // tx1 spends tx0's output. tx0 is at block index 1 → txid = sha3(byte(1))
    let tx0_txid = sha3_256(&[1u8]);
    let tx1 = Tx {
        version: 1,
        tx_kind: 0x00,
        tx_nonce: 2,
        inputs: vec![TxInput {
            prev_txid: tx0_txid,
            prev_vout: 0,
            script_sig: Vec::new(),
            sequence: 0,
        }],
        outputs: vec![TxOutput {
            value: 800,
            covenant_type: COV_TYPE_P2PK,
            covenant_data: cov_data,
        }],
        locktime: 0,
        da_commit_core: None,
        da_chunk_core: None,
        witness: vec![dummy_witness()],
        da_payload: Vec::new(),
    };

    let pb = make_parsed_block(simple_coinbase(), vec![tx0, tx1]);
    let results = precompute_tx_contexts(&pb, &utxos, 100).unwrap();
    assert_eq!(results.len(), 2);
    assert_eq!(results[1].resolved_inputs[0].value, 900);
    assert_eq!(results[1].fee, 100);
}

// ─────────────────────────────────────────────────────────────────────────────
// Error paths
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn precompute_missing_utxo() {
    let prev_txid = sha3_256(b"nonexistent");
    let tx = Tx {
        version: 1,
        tx_kind: 0x00,
        tx_nonce: 1,
        inputs: vec![TxInput {
            prev_txid,
            prev_vout: 0,
            script_sig: Vec::new(),
            sequence: 0,
        }],
        outputs: vec![TxOutput {
            value: 100,
            covenant_type: COV_TYPE_P2PK,
            covenant_data: valid_p2pk_covenant_data(),
        }],
        locktime: 0,
        da_commit_core: None,
        da_chunk_core: None,
        witness: vec![dummy_witness()],
        da_payload: Vec::new(),
    };
    let pb = make_parsed_block(simple_coinbase(), vec![tx]);
    let err = precompute_tx_contexts(&pb, &HashMap::new(), 100).unwrap_err();
    assert_eq!(err.code.as_str(), "TX_ERR_MISSING_UTXO");
}

#[test]
fn precompute_duplicate_input() {
    let cov_data = valid_p2pk_covenant_data();
    let prev_txid = sha3_256(b"dup-input");
    let utxos = HashMap::from([(
        Outpoint {
            txid: prev_txid,
            vout: 0,
        },
        UtxoEntry {
            value: 1000,
            covenant_type: COV_TYPE_P2PK,
            covenant_data: cov_data.clone(),
            creation_height: 0,
            created_by_coinbase: false,
        },
    )]);

    let tx = Tx {
        version: 1,
        tx_kind: 0x00,
        tx_nonce: 1,
        inputs: vec![
            TxInput {
                prev_txid,
                prev_vout: 0,
                script_sig: Vec::new(),
                sequence: 0,
            },
            TxInput {
                prev_txid,
                prev_vout: 0,
                script_sig: Vec::new(),
                sequence: 0,
            },
        ],
        outputs: vec![TxOutput {
            value: 100,
            covenant_type: COV_TYPE_P2PK,
            covenant_data: cov_data,
        }],
        locktime: 0,
        da_commit_core: None,
        da_chunk_core: None,
        witness: vec![dummy_witness(), dummy_witness()],
        da_payload: Vec::new(),
    };
    let pb = make_parsed_block(simple_coinbase(), vec![tx]);
    let err = precompute_tx_contexts(&pb, &utxos, 100).unwrap_err();
    assert_eq!(err.code.as_str(), "TX_ERR_PARSE");
}

#[test]
fn precompute_witness_underflow() {
    let cov_data = valid_p2pk_covenant_data();
    let prev_txid = sha3_256(b"witness-underflow");
    let utxos = HashMap::from([(
        Outpoint {
            txid: prev_txid,
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

    let tx = Tx {
        version: 1,
        tx_kind: 0x00,
        tx_nonce: 1,
        inputs: vec![TxInput {
            prev_txid,
            prev_vout: 0,
            script_sig: Vec::new(),
            sequence: 0,
        }],
        outputs: vec![TxOutput {
            value: 400,
            covenant_type: COV_TYPE_P2PK,
            covenant_data: cov_data,
        }],
        locktime: 0,
        da_commit_core: None,
        da_chunk_core: None,
        witness: vec![], // empty!
        da_payload: Vec::new(),
    };
    let pb = make_parsed_block(simple_coinbase(), vec![tx]);
    let err = precompute_tx_contexts(&pb, &utxos, 100).unwrap_err();
    assert_eq!(err.code.as_str(), "TX_ERR_PARSE");
}

#[test]
fn precompute_witness_count_mismatch() {
    let cov_data = valid_p2pk_covenant_data();
    let prev_txid = sha3_256(b"witness-overflow");
    let utxos = HashMap::from([(
        Outpoint {
            txid: prev_txid,
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

    let tx = Tx {
        version: 1,
        tx_kind: 0x00,
        tx_nonce: 1,
        inputs: vec![TxInput {
            prev_txid,
            prev_vout: 0,
            script_sig: Vec::new(),
            sequence: 0,
        }],
        outputs: vec![TxOutput {
            value: 400,
            covenant_type: COV_TYPE_P2PK,
            covenant_data: cov_data,
        }],
        locktime: 0,
        da_commit_core: None,
        da_chunk_core: None,
        witness: vec![dummy_witness(), dummy_witness()], // extra
        da_payload: Vec::new(),
    };
    let pb = make_parsed_block(simple_coinbase(), vec![tx]);
    let err = precompute_tx_contexts(&pb, &utxos, 100).unwrap_err();
    assert_eq!(err.code.as_str(), "TX_ERR_PARSE");
}

#[test]
fn precompute_outputs_exceed_inputs() {
    let cov_data = valid_p2pk_covenant_data();
    let prev_txid = sha3_256(b"value-overflow");
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

    let tx = Tx {
        version: 1,
        tx_kind: 0x00,
        tx_nonce: 1,
        inputs: vec![TxInput {
            prev_txid,
            prev_vout: 0,
            script_sig: Vec::new(),
            sequence: 0,
        }],
        outputs: vec![TxOutput {
            value: 200,
            covenant_type: COV_TYPE_P2PK,
            covenant_data: cov_data,
        }],
        locktime: 0,
        da_commit_core: None,
        da_chunk_core: None,
        witness: vec![dummy_witness()],
        da_payload: Vec::new(),
    };
    let pb = make_parsed_block(simple_coinbase(), vec![tx]);
    let err = precompute_tx_contexts(&pb, &utxos, 100).unwrap_err();
    assert_eq!(err.code.as_str(), "TX_ERR_VALUE_CONSERVATION");
}

#[test]
fn precompute_non_spendable_covenant() {
    let prev_txid = sha3_256(b"anchor-spend");
    let utxos = HashMap::from([(
        Outpoint {
            txid: prev_txid,
            vout: 0,
        },
        UtxoEntry {
            value: 100,
            covenant_type: COV_TYPE_ANCHOR,
            covenant_data: Vec::new(),
            creation_height: 0,
            created_by_coinbase: false,
        },
    )]);

    let tx = Tx {
        version: 1,
        tx_kind: 0x00,
        tx_nonce: 1,
        inputs: vec![TxInput {
            prev_txid,
            prev_vout: 0,
            script_sig: Vec::new(),
            sequence: 0,
        }],
        outputs: vec![TxOutput {
            value: 50,
            covenant_type: COV_TYPE_P2PK,
            covenant_data: valid_p2pk_covenant_data(),
        }],
        locktime: 0,
        da_commit_core: None,
        da_chunk_core: None,
        witness: vec![dummy_witness()],
        da_payload: Vec::new(),
    };
    let pb = make_parsed_block(simple_coinbase(), vec![tx]);
    let err = precompute_tx_contexts(&pb, &utxos, 100).unwrap_err();
    assert_eq!(err.code.as_str(), "TX_ERR_MISSING_UTXO");
}

#[test]
fn precompute_coinbase_prevout_forbidden() {
    let tx = Tx {
        version: 1,
        tx_kind: 0x00,
        tx_nonce: 1,
        inputs: vec![TxInput {
            prev_txid: [0u8; 32],
            prev_vout: 0xffff_ffff,
            script_sig: Vec::new(),
            sequence: 0,
        }],
        outputs: vec![TxOutput {
            value: 50,
            covenant_type: COV_TYPE_P2PK,
            covenant_data: valid_p2pk_covenant_data(),
        }],
        locktime: 0,
        da_commit_core: None,
        da_chunk_core: None,
        witness: vec![dummy_witness()],
        da_payload: Vec::new(),
    };
    let pb = make_parsed_block(simple_coinbase(), vec![tx]);
    let err = precompute_tx_contexts(&pb, &HashMap::new(), 100).unwrap_err();
    assert_eq!(err.code.as_str(), "TX_ERR_PARSE");
}

#[test]
fn precompute_no_inputs() {
    let tx = Tx {
        version: 1,
        tx_kind: 0x00,
        tx_nonce: 1,
        inputs: vec![],
        outputs: vec![TxOutput {
            value: 50,
            covenant_type: COV_TYPE_P2PK,
            covenant_data: valid_p2pk_covenant_data(),
        }],
        locktime: 0,
        da_commit_core: None,
        da_chunk_core: None,
        witness: vec![],
        da_payload: Vec::new(),
    };
    let pb = make_parsed_block(simple_coinbase(), vec![tx]);
    let err = precompute_tx_contexts(&pb, &HashMap::new(), 100).unwrap_err();
    assert_eq!(err.code.as_str(), "TX_ERR_PARSE");
}

#[test]
fn precompute_snapshot_not_mutated() {
    let cov_data = valid_p2pk_covenant_data();
    let prev_txid = sha3_256(b"snapshot-immutable");
    let op = Outpoint {
        txid: prev_txid,
        vout: 0,
    };
    let utxos = HashMap::from([(
        op.clone(),
        UtxoEntry {
            value: 1000,
            covenant_type: COV_TYPE_P2PK,
            covenant_data: cov_data.clone(),
            creation_height: 0,
            created_by_coinbase: false,
        },
    )]);

    let tx = Tx {
        version: 1,
        tx_kind: 0x00,
        tx_nonce: 1,
        inputs: vec![TxInput {
            prev_txid,
            prev_vout: 0,
            script_sig: Vec::new(),
            sequence: 0,
        }],
        outputs: vec![TxOutput {
            value: 900,
            covenant_type: COV_TYPE_P2PK,
            covenant_data: cov_data,
        }],
        locktime: 0,
        da_commit_core: None,
        da_chunk_core: None,
        witness: vec![dummy_witness()],
        da_payload: Vec::new(),
    };
    let pb = make_parsed_block(simple_coinbase(), vec![tx]);
    precompute_tx_contexts(&pb, &utxos, 100).unwrap();

    // Original snapshot must still have the UTXO.
    assert!(utxos.contains_key(&op));
    assert_eq!(utxos.len(), 1);
}

// ─────────────────────────────────────────────────────────────────────────────
// Hardening guard tests (#897)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn precompute_txids_txs_length_mismatch() {
    let cov_data = valid_p2pk_covenant_data();
    let prev_txid = sha3_256(b"txid-len-mismatch");
    let op = Outpoint {
        txid: prev_txid,
        vout: 0,
    };
    let mut utxos = HashMap::new();
    utxos.insert(
        op.clone(),
        UtxoEntry {
            value: 1000,
            covenant_type: COV_TYPE_P2PK,
            covenant_data: cov_data.clone(),
            creation_height: 0,
            created_by_coinbase: false,
        },
    );

    let tx = Tx {
        version: 1,
        tx_kind: 0x00,
        tx_nonce: 1,
        inputs: vec![TxInput {
            prev_txid,
            prev_vout: 0,
            script_sig: vec![],
            sequence: 0,
        }],
        outputs: vec![TxOutput {
            value: 900,
            covenant_type: COV_TYPE_P2PK,
            covenant_data: cov_data,
        }],
        locktime: 0,
        da_commit_core: None,
        da_chunk_core: None,
        witness: vec![dummy_witness()],
        da_payload: Vec::new(),
    };

    // Build a ParsedBlock with mismatched txids length.
    let mut pb = make_parsed_block(simple_coinbase(), vec![tx]);
    pb.txids.pop(); // Now txids.len() < txs.len()

    let err = precompute_tx_contexts(&pb, &utxos, 100).unwrap_err();
    assert!(
        err.msg.contains("txids/txs length mismatch"),
        "unexpected error: {}",
        err.msg
    );
}

#[test]
fn precompute_immature_coinbase_spend_rejected() {
    let cov_data = valid_p2pk_covenant_data();
    let prev_txid = sha3_256(b"coinbase-immature");
    let op = Outpoint {
        txid: prev_txid,
        vout: 0,
    };
    let mut utxos = HashMap::new();
    utxos.insert(
        op.clone(),
        UtxoEntry {
            value: 1000,
            covenant_type: COV_TYPE_P2PK,
            covenant_data: cov_data.clone(),
            creation_height: 50, // created at height 50
            created_by_coinbase: true,
        },
    );

    let tx = Tx {
        version: 1,
        tx_kind: 0x00,
        tx_nonce: 1,
        inputs: vec![TxInput {
            prev_txid,
            prev_vout: 0,
            script_sig: vec![],
            sequence: 0,
        }],
        outputs: vec![TxOutput {
            value: 900,
            covenant_type: COV_TYPE_P2PK,
            covenant_data: cov_data,
        }],
        locktime: 0,
        da_commit_core: None,
        da_chunk_core: None,
        witness: vec![dummy_witness()],
        da_payload: Vec::new(),
    };

    let pb = make_parsed_block(simple_coinbase(), vec![tx]);

    // Block height 100: maturity gap = 100 - 50 = 50 < COINBASE_MATURITY (100).
    let err = precompute_tx_contexts(&pb, &utxos, 100).unwrap_err();
    assert!(
        err.msg.contains("coinbase immature"),
        "unexpected error: {}",
        err.msg
    );
    assert_eq!(err.code, crate::error::ErrorCode::TxErrCoinbaseImmature);
}

#[test]
fn precompute_mature_coinbase_spend_accepted() {
    let cov_data = valid_p2pk_covenant_data();
    let prev_txid = sha3_256(b"coinbase-mature");
    let op = Outpoint {
        txid: prev_txid,
        vout: 0,
    };
    let mut utxos = HashMap::new();
    utxos.insert(
        op.clone(),
        UtxoEntry {
            value: 1000,
            covenant_type: COV_TYPE_P2PK,
            covenant_data: cov_data.clone(),
            creation_height: 50,
            created_by_coinbase: true,
        },
    );

    let tx = Tx {
        version: 1,
        tx_kind: 0x00,
        tx_nonce: 1,
        inputs: vec![TxInput {
            prev_txid,
            prev_vout: 0,
            script_sig: vec![],
            sequence: 0,
        }],
        outputs: vec![TxOutput {
            value: 900,
            covenant_type: COV_TYPE_P2PK,
            covenant_data: cov_data,
        }],
        locktime: 0,
        da_commit_core: None,
        da_chunk_core: None,
        witness: vec![dummy_witness()],
        da_payload: Vec::new(),
    };

    let pb = make_parsed_block(simple_coinbase(), vec![tx]);

    // Block height 150: maturity gap = 150 - 50 = 100 == COINBASE_MATURITY. Should pass.
    precompute_tx_contexts(&pb, &utxos, 150).unwrap();
}
