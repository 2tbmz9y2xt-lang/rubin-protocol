use std::collections::HashMap;

use crate::block::{BlockHeader, BLOCK_HEADER_BYTES};
use crate::block_basic::ParsedBlock;
use crate::constants::*;
use crate::core_ext::CoreExtProfiles;
use crate::error::ErrorCode;
use crate::hash::sha3_256;
use crate::precompute::{precompute_tx_contexts, PrecomputedTxContext};
use crate::tx::{Tx, TxInput, TxOutput, WitnessItem};
use crate::tx_validate_worker::{
    first_tx_error, run_tx_validation_workers, validate_tx_local, TxValidationResult,
};
use crate::utxo_basic::{Outpoint, UtxoEntry};
use crate::worker_pool::{WorkerCancellationToken, WorkerPoolError, WorkerResult};

fn valid_p2pk_covenant_data() -> Vec<u8> {
    vec![0u8; 32]
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

fn simple_p2pk_tx(prev_txid_seed: u8) -> Tx {
    let mut prev_txid = [0u8; 32];
    prev_txid[0] = prev_txid_seed;
    Tx {
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
            value: 90,
            covenant_type: COV_TYPE_P2PK,
            covenant_data: valid_p2pk_covenant_data(),
        }],
        locktime: 0,
        da_commit_core: None,
        da_chunk_core: None,
        witness: vec![dummy_witness()],
        da_payload: Vec::new(),
    }
}

fn make_utxo_snapshot_for_tx(
    tx: &Tx,
    value: u64,
) -> HashMap<Outpoint, UtxoEntry> {
    let mut snap = HashMap::new();
    for input in &tx.inputs {
        snap.insert(
            Outpoint {
                txid: input.prev_txid,
                vout: input.prev_vout,
            },
            UtxoEntry {
                value,
                covenant_type: COV_TYPE_P2PK,
                covenant_data: valid_p2pk_covenant_data(),
                creation_height: 1,
                created_by_coinbase: false,
            },
        );
    }
    snap
}

/// Helper: precompute + validate for a single-tx block.
fn precompute_single_tx(
    tx: Tx,
    input_value: u64,
    block_height: u64,
) -> (ParsedBlock, Vec<PrecomputedTxContext>, HashMap<Outpoint, UtxoEntry>) {
    let snapshot = make_utxo_snapshot_for_tx(&tx, input_value);
    let pb = make_parsed_block(simple_coinbase(), vec![tx]);
    let ptcs = precompute_tx_contexts(&pb, &snapshot, block_height).unwrap();
    (pb, ptcs, snapshot)
}

// ─────────────────────────────────────────────────────────────────────────────
// validate_tx_local
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn validate_tx_local_witness_underflow() {
    let tx = simple_p2pk_tx(0x42);
    let (pb, mut ptcs, _snap) = precompute_single_tx(tx, 100, 100);

    // Corrupt witness_end so the worker sees fewer witness items than needed.
    ptcs[0].witness_end = ptcs[0].witness_start;

    let profiles = CoreExtProfiles::empty();
    let r = validate_tx_local(&ptcs[0], &pb, [0u8; 32], 100, 0, &profiles);
    assert!(!r.valid);
    assert!(r.err.is_some());
    let err = r.err.unwrap();
    assert_eq!(err.code, ErrorCode::TxErrParse);
    assert!(err.msg.contains("witness underflow"));
}

#[test]
fn validate_tx_local_witness_count_mismatch() {
    // Create a tx with an extra witness item that won't be consumed.
    let mut tx = simple_p2pk_tx(0x42);
    tx.witness.push(dummy_witness()); // extra witness
    let (pb, ptcs, _snap) = precompute_single_tx(tx, 100, 100);

    let profiles = CoreExtProfiles::empty();
    let r = validate_tx_local(&ptcs[0], &pb, [0u8; 32], 100, 0, &profiles);
    assert!(!r.valid);
    assert!(r.err.is_some());
    let err = r.err.unwrap();
    assert_eq!(err.code, ErrorCode::TxErrParse);
    assert!(err.msg.contains("witness_count mismatch"));
}

#[test]
fn validate_tx_local_fee_and_index_preserved() {
    let tx = simple_p2pk_tx(0x42);
    let (pb, ptcs, _snap) = precompute_single_tx(tx, 100, 100);

    let profiles = CoreExtProfiles::empty();
    let r = validate_tx_local(&ptcs[0], &pb, [0u8; 32], 100, 0, &profiles);
    // Note: this test will likely fail at signature verification (dummy witness
    // won't pass ML-DSA verify) — we're testing that fee/index are set correctly
    // before any validation error is returned.
    assert_eq!(r.tx_index, ptcs[0].tx_index);
    assert_eq!(r.fee, ptcs[0].fee);
}

#[test]
fn validate_tx_local_default_covenant_passthrough() {
    // COV_TYPE_ANCHOR has no spend-time checks — the default match arm returns Ok(()).
    // However, ANCHOR is non-spendable and filtered by precompute. Test with a
    // synthetic PrecomputedTxContext that has no resolved inputs (empty block body
    // after coinbase).
    let pb = make_parsed_block(simple_coinbase(), vec![simple_p2pk_tx(0x42)]);
    let ptc = PrecomputedTxContext {
        tx_index: 1,
        tx_block_idx: 1,
        txid: [0u8; 32],
        resolved_inputs: vec![], // no inputs → zero iterations
        witness_start: 0,
        witness_end: 0,
        input_outpoints: vec![],
        fee: 0,
    };
    let profiles = CoreExtProfiles::empty();
    let r = validate_tx_local(&ptc, &pb, [0u8; 32], 100, 0, &profiles);
    assert!(r.valid);
    assert!(r.err.is_none());
}

// ─────────────────────────────────────────────────────────────────────────────
// run_tx_validation_workers
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn run_tx_validation_workers_empty() {
    let token = WorkerCancellationToken::new();
    let profiles = CoreExtProfiles::empty();
    let pb = make_parsed_block(simple_coinbase(), vec![]);
    let results =
        run_tx_validation_workers(&token, 4, vec![], &pb, [0u8; 32], 1, 0, &profiles).unwrap();
    assert!(results.is_empty());
}

#[test]
fn run_tx_validation_workers_cancelled_token() {
    let tx = simple_p2pk_tx(0x42);
    let (pb, ptcs, _snap) = precompute_single_tx(tx, 100, 100);

    let token = WorkerCancellationToken::new();
    token.cancel(); // pre-cancel

    let profiles = CoreExtProfiles::empty();
    let results =
        run_tx_validation_workers(&token, 2, ptcs, &pb, [0u8; 32], 100, 0, &profiles).unwrap();
    assert_eq!(results.len(), 1);
    assert!(results[0].error.is_some());
    match &results[0].error {
        Some(WorkerPoolError::Cancelled) => {}
        other => panic!("expected Cancelled, got {:?}", other),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// first_tx_error
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn first_tx_error_all_valid() {
    let results: Vec<WorkerResult<TxValidationResult, _>> = vec![
        WorkerResult {
            value: Some(TxValidationResult {
                tx_index: 1,
                valid: true,
                err: None,
                sig_count: 1,
                fee: 10,
            }),
            error: None,
        },
        WorkerResult {
            value: Some(TxValidationResult {
                tx_index: 2,
                valid: true,
                err: None,
                sig_count: 1,
                fee: 20,
            }),
            error: None,
        },
    ];
    assert!(first_tx_error(&results).is_none());
}

#[test]
fn first_tx_error_nil() {
    let results: Vec<WorkerResult<TxValidationResult, _>> = vec![];
    assert!(first_tx_error(&results).is_none());
}

#[test]
fn first_tx_error_picks_smallest_tx_index() {
    use crate::error::TxError;

    let err3 = TxError::new(ErrorCode::TxErrParse, "tx3");
    let err1 = TxError::new(ErrorCode::TxErrMissingUtxo, "tx1");

    let results: Vec<WorkerResult<TxValidationResult, _>> = vec![
        WorkerResult {
            value: Some(TxValidationResult {
                tx_index: 3,
                valid: false,
                err: Some(err3.clone()),
                sig_count: 0,
                fee: 0,
            }),
            error: Some(WorkerPoolError::Task(err3)),
        },
        WorkerResult {
            value: Some(TxValidationResult {
                tx_index: 2,
                valid: true,
                err: None,
                sig_count: 1,
                fee: 10,
            }),
            error: None,
        },
        WorkerResult {
            value: Some(TxValidationResult {
                tx_index: 1,
                valid: false,
                err: Some(err1.clone()),
                sig_count: 0,
                fee: 0,
            }),
            error: Some(WorkerPoolError::Task(err1.clone())),
        },
    ];

    let got = first_tx_error(&results);
    assert!(got.is_some());
    let got = got.unwrap();
    assert_eq!(got.code, ErrorCode::TxErrMissingUtxo);
    assert!(got.msg.contains("tx1"));
}

#[test]
fn first_tx_error_fallback_when_tx_index_zero() {
    use crate::error::TxError;

    let err_a = TxError::new(ErrorCode::TxErrParse, "missing index A");
    let err_b = TxError::new(ErrorCode::TxErrParse, "missing index B");

    // Both errors have tx_index=0 (unset). First encountered should be kept.
    let results: Vec<WorkerResult<TxValidationResult, _>> = vec![
        WorkerResult {
            value: Some(TxValidationResult {
                tx_index: 0,
                valid: false,
                err: Some(err_a.clone()),
                sig_count: 0,
                fee: 0,
            }),
            error: Some(WorkerPoolError::Task(err_a.clone())),
        },
        WorkerResult {
            value: Some(TxValidationResult {
                tx_index: 0,
                valid: false,
                err: Some(err_b.clone()),
                sig_count: 0,
                fee: 0,
            }),
            error: Some(WorkerPoolError::Task(err_b)),
        },
    ];

    let got = first_tx_error(&results).unwrap();
    assert!(got.msg.contains("missing index A"));
}
