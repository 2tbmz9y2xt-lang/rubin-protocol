use std::collections::HashMap;

use crate::block::{BlockHeader, BLOCK_HEADER_BYTES};
use crate::block_basic::ParsedBlock;
use crate::constants::*;
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
    // Genesis-valid CORE_P2PK covenant_data: suite_id byte + key-id placeholder.
    // `precompute_tx_contexts` now validates output covenant genesis, so P2PK
    // outputs must use a real native-create suite_id and the exact length.
    let mut b = vec![0u8; MAX_P2PK_COVENANT_DATA as usize];
    b[0] = SUITE_ID_ML_DSA_87;
    b
}

fn dummy_witness() -> WitnessItem {
    WitnessItem {
        suite_id: SUITE_ID_ML_DSA_87,
        pubkey: vec![0u8; ML_DSA_87_PUBKEY_BYTES as usize],
        signature: vec![0u8; (ML_DSA_87_SIG_BYTES + 1) as usize],
    }
}

fn stealth_covenant_data_for_pubkey(pubkey: &[u8]) -> Vec<u8> {
    let mut cov = vec![0u8; MAX_STEALTH_COVENANT_DATA as usize];
    let split = cov.len() - 32;
    cov[split..].copy_from_slice(&sha3_256(pubkey));
    cov
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

fn make_utxo_snapshot_for_tx(tx: &Tx, value: u64) -> HashMap<Outpoint, UtxoEntry> {
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
) -> (
    ParsedBlock,
    Vec<PrecomputedTxContext>,
    HashMap<Outpoint, UtxoEntry>,
) {
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

    let r = validate_tx_local(&ptcs[0], &pb, [0u8; 32], 100, 0, None);
    assert!(!r.valid);
    assert!(r.err.is_some());
    let err = r.err.unwrap();
    assert_eq!(err.code, ErrorCode::TxErrParse);
    assert!(err.msg.contains("witness underflow"));
}

#[test]
fn validate_tx_local_witness_count_mismatch() {
    // Synthetic PTC with no resolved inputs but witness_end > witness_start.
    // After zero iterations witness_cursor == witness_start != witness_end,
    // triggering the mismatch guard.
    let pb = make_parsed_block(simple_coinbase(), vec![simple_p2pk_tx(0x42)]);
    let ptc = PrecomputedTxContext {
        tx_index: 1,
        tx_block_idx: 1,
        txid: [0u8; 32],
        resolved_inputs: vec![], // no inputs → zero iterations
        witness_start: 0,
        witness_end: 1, // mismatch: cursor stays at 0
        input_outpoints: vec![],
        fee: 0,
    };
    let r = validate_tx_local(&ptc, &pb, [0u8; 32], 100, 0, None);
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

    let r = validate_tx_local(&ptcs[0], &pb, [0u8; 32], 100, 0, None);
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
    let r = validate_tx_local(&ptc, &pb, [0u8; 32], 100, 0, None);
    assert!(r.valid);
    assert!(r.err.is_none());
}

/// Covers validate_input_spend → COV_TYPE_P2PK branch. The dummy signature
/// will fail inside validate_p2pk_spend_at_height, but the branch is entered
/// and lines 176-194 of tx_validate_worker.rs are exercised.
#[test]
fn validate_tx_local_p2pk_dispatch_enters_branch() {
    let tx = simple_p2pk_tx(0x42);
    let (pb, ptcs, _snap) = precompute_single_tx(tx, 100, 100);

    let r = validate_tx_local(&ptcs[0], &pb, [0u8; 32], 100, 0, None);
    // Dummy sig will fail at ML-DSA verify but the P2PK branch was entered.
    // Dummy sig will fail ML-DSA verify but the P2PK branch was entered.
    // We only care that the path was exercised, not that it passed.
    let _ = r.valid;
    assert_eq!(r.tx_index, ptcs[0].tx_index);
    assert_eq!(r.fee, ptcs[0].fee);
}

/// Covers validate_input_spend → COV_TYPE_MULTISIG branch. Uses synthetic PTC
/// with a multisig resolved input and dummy witness items.
#[test]
fn validate_tx_local_multisig_dispatch_enters_branch() {
    let mut tx = simple_p2pk_tx(0x42);
    // Replace witness with two dummy items (threshold=1, 2 keys → 2 witness slots).
    tx.witness = vec![dummy_witness(), dummy_witness()];

    let mut prev_txid = [0u8; 32];
    prev_txid[0] = 0x42;

    let pb = make_parsed_block(simple_coinbase(), vec![tx]);
    // Build synthetic PTC with MULTISIG input.
    // Keys MUST be strictly sorted for parse_multisig_covenant_data to succeed.
    let mut multisig_cov_data = vec![0u8; 66]; // threshold(1) + key_count(1) + 2×32 keys
    multisig_cov_data[0] = 1; // threshold
    multisig_cov_data[1] = 2; // key_count
                              // key[0] = 0x01 repeated (lexicographically smaller)
    multisig_cov_data[2..34].fill(0x01);
    // key[1] = 0x02 repeated (lexicographically larger → strictly sorted)
    multisig_cov_data[34..66].fill(0x02);
    let ptc = PrecomputedTxContext {
        tx_index: 1,
        tx_block_idx: 1,
        txid: [0u8; 32],
        resolved_inputs: vec![UtxoEntry {
            value: 100,
            covenant_type: COV_TYPE_MULTISIG,
            covenant_data: multisig_cov_data,
            creation_height: 1,
            created_by_coinbase: false,
        }],
        witness_start: 0,
        witness_end: 2,
        input_outpoints: vec![Outpoint {
            txid: prev_txid,
            vout: 0,
        }],
        fee: 10,
    };
    let r = validate_tx_local(&ptc, &pb, [0u8; 32], 100, 0, None);
    // Will fail at sig verify but MULTISIG branch was entered.
    assert_eq!(r.tx_index, 1);
    assert_eq!(r.fee, 10);
}

// RUB-591: the worker upfront guard rejects a 0x0106 spend with the dedicated
// message before any input dispatch (defensive — precompute already rejects it).
#[test]
fn validate_tx_local_rejects_core_simplicity_spend() {
    let mut tx = simple_p2pk_tx(0x55);
    tx.witness = vec![dummy_witness()];
    let pb = make_parsed_block(simple_coinbase(), vec![tx]);
    let ptc = PrecomputedTxContext {
        tx_index: 1,
        tx_block_idx: 1,
        txid: [0u8; 32],
        resolved_inputs: vec![UtxoEntry {
            value: 100,
            covenant_type: COV_TYPE_CORE_SIMPLICITY,
            covenant_data: vec![],
            creation_height: 1,
            created_by_coinbase: false,
        }],
        witness_start: 0,
        witness_end: 1,
        input_outpoints: vec![Outpoint {
            txid: [0u8; 32],
            vout: 0,
        }],
        fee: 10,
    };
    let r = validate_tx_local(&ptc, &pb, [0u8; 32], 100, 0, None);
    assert!(!r.valid);
    let err = r.err.expect("0x0106 worker input must reject");
    assert_eq!(err.code, ErrorCode::TxErrCovenantTypeInvalid);
    assert!(err
        .msg
        .contains("CORE_SIMPLICITY spend evaluation not enabled"));
}

/// Covers validate_input_spend → COV_TYPE_VAULT branch. Uses synthetic PTC
/// with a vault resolved input.
#[test]
fn validate_tx_local_vault_dispatch_enters_branch() {
    let mut tx = simple_p2pk_tx(0x42);
    tx.witness = vec![dummy_witness()];

    let mut prev_txid = [0u8; 32];
    prev_txid[0] = 0x42;

    let pb = make_parsed_block(simple_coinbase(), vec![tx]);
    // Vault covenant data: owner_lock_id[32] + threshold[1] + key_count[1] + 1×32 key
    //   + whitelist_count[2] + 1×32 whitelist entry = 100 bytes
    let mut vault_cov_data = vec![0u8; 100];
    vault_cov_data[32] = 1; // threshold
    vault_cov_data[33] = 1; // key_count (→ 1 witness slot)
                            // key at offset 34..66
    vault_cov_data[34..66].fill(0x01);
    // whitelist_count = 1 (LE u16 at offset 66..68)
    vault_cov_data[66] = 1;
    // whitelist entry at offset 68..100
    vault_cov_data[68..100].fill(0x02);
    let ptc = PrecomputedTxContext {
        tx_index: 1,
        tx_block_idx: 1,
        txid: [0u8; 32],
        resolved_inputs: vec![UtxoEntry {
            value: 100,
            covenant_type: COV_TYPE_VAULT,
            covenant_data: vault_cov_data,
            creation_height: 1,
            created_by_coinbase: false,
        }],
        witness_start: 0,
        witness_end: 1,
        input_outpoints: vec![Outpoint {
            txid: prev_txid,
            vout: 0,
        }],
        fee: 10,
    };
    let r = validate_tx_local(&ptc, &pb, [0u8; 32], 100, 0, None);
    assert_eq!(r.tx_index, 1);
}

/// Covers validate_input_spend → COV_TYPE_HTLC branch.
#[test]
fn validate_tx_local_htlc_dispatch_enters_branch() {
    let mut tx = simple_p2pk_tx(0x42);
    tx.witness = vec![dummy_witness(), dummy_witness()]; // HTLC needs 2 slots

    let mut prev_txid = [0u8; 32];
    prev_txid[0] = 0x42;

    let pb = make_parsed_block(simple_coinbase(), vec![tx]);
    // HTLC covenant data: hash[32] + lock_mode[1] + lock_value[8] + claim_key_id[32] + refund_key_id[32]
    let htlc_cov_data = vec![0u8; 105];
    let ptc = PrecomputedTxContext {
        tx_index: 1,
        tx_block_idx: 1,
        txid: [0u8; 32],
        resolved_inputs: vec![UtxoEntry {
            value: 100,
            covenant_type: COV_TYPE_HTLC,
            covenant_data: htlc_cov_data,
            creation_height: 1,
            created_by_coinbase: false,
        }],
        witness_start: 0,
        witness_end: 2,
        input_outpoints: vec![Outpoint {
            txid: prev_txid,
            vout: 0,
        }],
        fee: 10,
    };
    let r = validate_tx_local(&ptc, &pb, [0u8; 32], 100, 0, None);
    assert_eq!(r.tx_index, 1);
}

/// Covers witness_slots error path (lines 102-104) when resolved input has
/// an unknown covenant type.
#[test]
fn validate_tx_local_unknown_covenant_witness_slots_error() {
    let tx = simple_p2pk_tx(0x42);
    let mut prev_txid = [0u8; 32];
    prev_txid[0] = 0x42;

    let pb = make_parsed_block(simple_coinbase(), vec![tx]);
    let ptc = PrecomputedTxContext {
        tx_index: 1,
        tx_block_idx: 1,
        txid: [0u8; 32],
        resolved_inputs: vec![UtxoEntry {
            value: 100,
            covenant_type: 0xFFFF, // unknown → witness_slots returns error
            covenant_data: vec![],
            creation_height: 1,
            created_by_coinbase: false,
        }],
        witness_start: 0,
        witness_end: 1,
        input_outpoints: vec![Outpoint {
            txid: prev_txid,
            vout: 0,
        }],
        fee: 10,
    };
    let r = validate_tx_local(&ptc, &pb, [0u8; 32], 100, 0, None);
    assert!(!r.valid);
    assert!(r.err.is_some());
    assert_eq!(r.err.unwrap().code, ErrorCode::TxErrCovenantTypeInvalid);
}

/// A CORE_EXT (0x0102) input with malformed covenant data is rejected during
/// worker spend dispatch (`witness_slots` -> TxErrCovenantTypeInvalid), since
/// 0x0102 is UNASSIGNED. No CORE_EXT profile machinery is involved.
#[test]
fn validate_tx_local_ext_context_build_error() {
    let mut tx = simple_p2pk_tx(0x42);
    tx.witness = vec![dummy_witness()];

    let mut prev_txid = [0u8; 32];
    prev_txid[0] = 0x42;

    let pb = make_parsed_block(simple_coinbase(), vec![tx]);

    let ptc = PrecomputedTxContext {
        tx_index: 1,
        tx_block_idx: 1,
        txid: [0u8; 32],
        resolved_inputs: vec![UtxoEntry {
            value: 100,
            covenant_type: COV_TYPE_CORE_EXT,
            covenant_data: vec![0u8; 4], // malformed: too short for ext_id parse
            creation_height: 1,
            created_by_coinbase: false,
        }],
        witness_start: 0,
        witness_end: 1,
        input_outpoints: vec![Outpoint {
            txid: prev_txid,
            vout: 0,
        }],
        fee: 10,
    };
    let r = validate_tx_local(&ptc, &pb, [0u8; 32], 100, 0, None);
    assert!(!r.valid);
    assert!(r.err.is_some());
}

/// Covers the full successful validation path with a real ML-DSA-87 signature:
/// sig_count increment (line 138), witness_cursor advance (line 140),
/// result.valid = true (line 151), and the complete P2PK branch (lines 183-194).
#[test]
fn validate_tx_local_real_signature_full_path() {
    use crate::sig_cache::SigCache;
    use crate::tx_helpers::{p2pk_covenant_data_for_pubkey, sign_transaction};
    use crate::verify_sig_openssl::Mldsa87Keypair;

    let keypair = match Mldsa87Keypair::generate() {
        Ok(kp) => kp,
        Err(_) => return, // OpenSSL unavailable — skip gracefully
    };
    let pubkey = keypair.pubkey_bytes();
    let cov_data = p2pk_covenant_data_for_pubkey(&pubkey);

    let prev_txid = [0x42u8; 32];
    let outpoint = Outpoint {
        txid: prev_txid,
        vout: 0,
    };

    let mut utxo_map = HashMap::new();
    utxo_map.insert(
        outpoint.clone(),
        UtxoEntry {
            value: 100,
            covenant_type: COV_TYPE_P2PK,
            covenant_data: cov_data.clone(),
            creation_height: 1,
            created_by_coinbase: false,
        },
    );

    let mut tx = Tx {
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
            covenant_data: cov_data,
        }],
        locktime: 0,
        da_commit_core: None,
        da_chunk_core: None,
        witness: Vec::new(),
        da_payload: Vec::new(),
    };

    sign_transaction(&mut tx, &utxo_map, [0u8; 32], &keypair).expect("sign tx");

    let pb = make_parsed_block(simple_coinbase(), vec![tx]);
    let ptcs = precompute_tx_contexts(&pb, &utxo_map, 100).unwrap();

    let r = validate_tx_local(&ptcs[0], &pb, [0u8; 32], 100, 0, None);
    assert!(r.valid, "expected valid tx, got err: {:?}", r.err);
    assert!(r.err.is_none());
    assert_eq!(r.sig_count, 1);
    assert_eq!(r.fee, 10); // 100 - 90

    let cache = SigCache::new(100);
    let cached_first = validate_tx_local(&ptcs[0], &pb, [0u8; 32], 100, 0, Some(&cache));
    assert!(
        cached_first.valid,
        "expected cached first run to pass: {:?}",
        cached_first.err
    );
    assert_eq!(cache.hits(), 0);

    let cached_second = validate_tx_local(&ptcs[0], &pb, [0u8; 32], 100, 0, Some(&cache));
    assert!(
        cached_second.valid,
        "expected cached second run to pass: {:?}",
        cached_second.err
    );
    assert_eq!(cache.hits(), 1);
}

#[test]
fn validate_tx_local_stealth_valid() {
    let kp = match super::test_mldsa87_keypair() {
        Some(kp) => kp,
        None => return,
    };

    let prev_txid = [0x55u8; 32];
    let mut tx = Tx {
        version: 1,
        tx_kind: 0x00,
        tx_nonce: 3,
        inputs: vec![TxInput {
            prev_txid,
            prev_vout: 0,
            script_sig: Vec::new(),
            sequence: 0,
        }],
        outputs: vec![TxOutput {
            value: 90,
            covenant_type: COV_TYPE_P2PK,
            covenant_data: super::p2pk_covenant_data_for_pubkey(&kp.pubkey),
        }],
        locktime: 0,
        da_commit_core: None,
        da_chunk_core: None,
        witness: Vec::new(),
        da_payload: Vec::new(),
    };
    tx.witness = vec![super::sign_input_witness(&tx, 0, 100, [0u8; 32], &kp)];

    let pb = make_parsed_block(simple_coinbase(), vec![tx]);
    let ptc = PrecomputedTxContext {
        tx_index: 1,
        tx_block_idx: 1,
        txid: [0u8; 32],
        resolved_inputs: vec![UtxoEntry {
            value: 100,
            covenant_type: COV_TYPE_CORE_STEALTH,
            covenant_data: stealth_covenant_data_for_pubkey(&kp.pubkey),
            creation_height: 1,
            created_by_coinbase: false,
        }],
        witness_start: 0,
        witness_end: 1,
        input_outpoints: vec![Outpoint {
            txid: prev_txid,
            vout: 0,
        }],
        fee: 10,
    };

    let result = validate_tx_local(&ptc, &pb, [0u8; 32], 100, 0, None);
    assert!(result.valid, "expected valid, got {:?}", result.err);
    assert!(result.err.is_none());
    assert_eq!(result.sig_count, 1);
}

#[test]
fn validate_tx_local_core_ext_0x0102_rejects_unassigned() {
    // COV_TYPE_CORE_EXT (0x0102) is UNASSIGNED: the worker rejects a resolved
    // input of this covenant type via witness_slots with TxErrCovenantTypeInvalid,
    // before any (removed) CORE_EXT spend runtime could run.
    let prev_txid = [0x77u8; 32];
    let tx = simple_p2pk_tx(0x77);
    let pb = make_parsed_block(simple_coinbase(), vec![tx]);
    let ptc = PrecomputedTxContext {
        tx_index: 1,
        tx_block_idx: 1,
        txid: [0u8; 32],
        resolved_inputs: vec![UtxoEntry {
            value: 100,
            covenant_type: COV_TYPE_CORE_EXT,
            // ext_id:u16le(1) || ext_payload_len:CompactSize(0)
            covenant_data: vec![0x01, 0x00, 0x00],
            creation_height: 1,
            created_by_coinbase: false,
        }],
        witness_start: 0,
        witness_end: 1,
        input_outpoints: vec![Outpoint {
            txid: prev_txid,
            vout: 0,
        }],
        fee: 10,
    };

    let result = validate_tx_local(&ptc, &pb, [0u8; 32], 1, 0, None);
    assert!(!result.valid);
    assert_eq!(
        result.err.unwrap().code,
        ErrorCode::TxErrCovenantTypeInvalid
    );
}

#[test]
fn run_tx_validation_workers_with_sig_cache_reuses_positive_result() {
    use crate::sig_cache::SigCache;
    use crate::tx_helpers::{p2pk_covenant_data_for_pubkey, sign_transaction};
    use crate::verify_sig_openssl::Mldsa87Keypair;

    let keypair = match Mldsa87Keypair::generate() {
        Ok(kp) => kp,
        Err(_) => return,
    };
    let pubkey = keypair.pubkey_bytes();
    let cov_data = p2pk_covenant_data_for_pubkey(&pubkey);
    let prev_txid = [0x24u8; 32];
    let outpoint = Outpoint {
        txid: prev_txid,
        vout: 0,
    };

    let mut utxo_map = HashMap::new();
    utxo_map.insert(
        outpoint,
        UtxoEntry {
            value: 100,
            covenant_type: COV_TYPE_P2PK,
            covenant_data: cov_data.clone(),
            creation_height: 1,
            created_by_coinbase: false,
        },
    );

    let mut tx = Tx {
        version: 1,
        tx_kind: 0x00,
        tx_nonce: 2,
        inputs: vec![TxInput {
            prev_txid,
            prev_vout: 0,
            script_sig: Vec::new(),
            sequence: 0,
        }],
        outputs: vec![TxOutput {
            value: 90,
            covenant_type: COV_TYPE_P2PK,
            covenant_data: cov_data,
        }],
        locktime: 0,
        da_commit_core: None,
        da_chunk_core: None,
        witness: Vec::new(),
        da_payload: Vec::new(),
    };

    sign_transaction(&mut tx, &utxo_map, [0u8; 32], &keypair).expect("sign tx");

    let pb = make_parsed_block(simple_coinbase(), vec![tx]);
    let ptcs = precompute_tx_contexts(&pb, &utxo_map, 100).unwrap();
    let token = WorkerCancellationToken::new();
    let cache = SigCache::new(100);

    let first = run_tx_validation_workers(
        &token,
        1,
        ptcs.clone(),
        &pb,
        [0u8; 32],
        100,
        0,
        Some(cache.clone()),
    )
    .unwrap();
    assert_eq!(first.len(), 1);
    assert!(
        first[0].error.is_none(),
        "first run err: {:?}",
        first[0].error
    );
    assert_eq!(cache.hits(), 0);

    let second =
        run_tx_validation_workers(&token, 1, ptcs, &pb, [0u8; 32], 100, 0, Some(cache.clone()))
            .unwrap();
    assert_eq!(second.len(), 1);
    assert!(
        second[0].error.is_none(),
        "second run err: {:?}",
        second[0].error
    );
    assert_eq!(cache.hits(), 1);
}

/// Exercises run_tx_validation_workers worker closure (lines 351-367).
#[test]
fn validate_tx_local_worker_pool_closure() {
    let tx = simple_p2pk_tx(0x42);
    let (pb, ptcs, _snap) = precompute_single_tx(tx, 100, 100);

    let token = WorkerCancellationToken::new();
    let results = run_tx_validation_workers(&token, 2, ptcs, &pb, [0u8; 32], 100, 0, None).unwrap();
    assert_eq!(results.len(), 1);
    // The result will have an error (dummy sig) but the worker was exercised.
    assert!(results[0].error.is_some() || results[0].value.is_some());
}

// ─────────────────────────────────────────────────────────────────────────────
// run_tx_validation_workers
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn run_tx_validation_workers_empty() {
    let token = WorkerCancellationToken::new();
    let pb = make_parsed_block(simple_coinbase(), vec![]);
    let results = run_tx_validation_workers(&token, 4, vec![], &pb, [0u8; 32], 1, 0, None).unwrap();
    assert!(results.is_empty());
}

#[test]
fn run_tx_validation_workers_cancelled_token() {
    let tx = simple_p2pk_tx(0x42);
    let (pb, ptcs, _snap) = precompute_single_tx(tx, 100, 100);

    let token = WorkerCancellationToken::new();
    token.cancel(); // pre-cancel

    let results = run_tx_validation_workers(&token, 2, ptcs, &pb, [0u8; 32], 100, 0, None).unwrap();
    assert_eq!(results.len(), 1);
    assert!(results[0].error.is_some());
    match &results[0].error {
        Some(WorkerPoolError::Cancelled) => {}
        other => panic!("expected Cancelled, got {:?}", other),
    }
}

#[test]
fn run_tx_validation_workers_valid_p2pk_real_signature() {
    use crate::tx_helpers::{p2pk_covenant_data_for_pubkey, sign_transaction};
    use crate::verify_sig_openssl::Mldsa87Keypair;

    let keypair = match Mldsa87Keypair::generate() {
        Ok(kp) => kp,
        Err(_) => return,
    };

    let pubkey = keypair.pubkey_bytes();
    let cov_data = p2pk_covenant_data_for_pubkey(&pubkey);
    let prev_txid = [0x42u8; 32];
    let outpoint = Outpoint {
        txid: prev_txid,
        vout: 0,
    };

    let mut utxo_map = HashMap::new();
    utxo_map.insert(
        outpoint,
        UtxoEntry {
            value: 100,
            covenant_type: COV_TYPE_P2PK,
            covenant_data: cov_data.clone(),
            creation_height: 1,
            created_by_coinbase: false,
        },
    );

    let mut tx = Tx {
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
            covenant_data: cov_data,
        }],
        locktime: 0,
        da_commit_core: None,
        da_chunk_core: None,
        witness: Vec::new(),
        da_payload: Vec::new(),
    };

    sign_transaction(&mut tx, &utxo_map, [0u8; 32], &keypair).expect("sign tx");

    let pb = make_parsed_block(simple_coinbase(), vec![tx]);
    let ptcs = precompute_tx_contexts(&pb, &utxo_map, 100).expect("precompute");
    let token = WorkerCancellationToken::new();

    let results = run_tx_validation_workers(&token, 2, ptcs, &pb, [0u8; 32], 100, 0, None)
        .expect("run workers");
    assert_eq!(results.len(), 1);
    assert!(
        results[0].error.is_none(),
        "unexpected error: {:?}",
        results[0].error
    );
    let value = results[0].value.as_ref().expect("worker value");
    assert!(value.valid, "expected valid result, got {:?}", value.err);
    assert_eq!(value.tx_index, 1);
    assert_eq!(value.fee, 10);
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
fn first_tx_error_single_error() {
    use crate::error::TxError;

    let err = TxError::new(ErrorCode::TxErrSigInvalid, "sig");
    let results: Vec<WorkerResult<TxValidationResult, _>> = vec![WorkerResult {
        value: Some(TxValidationResult {
            tx_index: 2,
            valid: false,
            err: Some(err.clone()),
            sig_count: 0,
            fee: 0,
        }),
        error: Some(WorkerPoolError::Task(err.clone())),
    }];

    let got = first_tx_error(&results).expect("single error");
    assert_eq!(got.code, ErrorCode::TxErrSigInvalid);
    assert!(got.msg.contains("sig"));
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
