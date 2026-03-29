use super::*;

use crate::connect_block_inmem::InMemoryChainState;
use crate::hash::sha3_256;

// ───────────────────────────────────────────────────────────────────
// Helpers
// ───────────────────────────────────────────────────────────────────

/// Coinbase with a vault output + anchor witness commitment.
/// Go parity: coinbaseWithWitnessCommitmentAndVaultOutputAtHeight.
fn coinbase_with_witness_commitment_and_vault_output(
    locktime: u32,
    value: u64,
    vault_data: &[u8],
    non_coinbase_txs: &[Vec<u8>],
) -> Vec<u8> {
    let mut wtxids: Vec<[u8; 32]> = Vec::with_capacity(1 + non_coinbase_txs.len());
    wtxids.push([0u8; 32]); // coinbase wtxid placeholder
    for txb in non_coinbase_txs {
        let (_tx, _txid, wtxid, _n) = parse_tx(txb).expect("parse non-coinbase for witness root");
        wtxids.push(wtxid);
    }

    let wroot = crate::merkle::witness_merkle_root_wtxids(&wtxids).expect("witness merkle root");
    let commit = crate::merkle::witness_commitment_hash(wroot);
    coinbase_tx_with_outputs(
        locktime,
        &[
            TestOutput {
                value,
                covenant_type: COV_TYPE_VAULT,
                covenant_data: vault_data.to_vec(),
            },
            TestOutput {
                value: 0,
                covenant_type: COV_TYPE_ANCHOR,
                covenant_data: commit.to_vec(),
            },
        ],
    )
}

// ───────────────────────────────────────────────────────────────────
// Tests
// ───────────────────────────────────────────────────────────────────

/// Go parity: TestConnectBlockBasicInMemoryAtHeight_OK_ComputesFeesAndUpdatesState
///
/// Spend a single P2PK UTXO (100 → 90, fee=10). Verify:
///   - sum_fees == 10
///   - already_generated == 0 (pre-block)
///   - already_generated_n1 == subsidy
///   - utxo_count == 2 (spend output + coinbase p2pk; anchor excluded)
///   - state.already_generated advanced to subsidy
#[test]
fn connect_block_ok_computes_fees_and_updates_state() {
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

    // Build spend tx: 1 input (prev:0, value 100) → 1 output (90, P2PK).
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

    let mut state = InMemoryChainState {
        utxos: HashMap::from([(
            prev_out,
            UtxoEntry {
                value: 100,
                covenant_type: COV_TYPE_P2PK,
                covenant_data: cov_data.clone(),
                creation_height: 0,
                created_by_coinbase: false,
            },
        )]),
        already_generated: 0,
    };

    let sum_fees = 10u64;
    let subsidy = crate::subsidy::block_subsidy(height, state.already_generated);
    let coinbase = coinbase_with_witness_commitment_and_p2pk_value(
        height as u32,
        subsidy + sum_fees,
        std::slice::from_ref(&spend_bytes),
    );
    let (_cb, coinbase_txid, _cbw, _cbn) = parse_tx(&coinbase).expect("parse coinbase");

    let root = merkle_root_txids(&[coinbase_txid, spend_txid]).expect("merkle root");
    let block = build_block_bytes(prev, root, target, 1, &[coinbase, spend_bytes]);

    // prev_timestamps: minimal slice to exercise MTP branch (k = min(11, height) = 1).
    let s = crate::connect_block_basic_in_memory_at_height(
        &block,
        Some(prev),
        Some(target),
        height,
        Some(&[0]),
        &mut state,
        ZERO_CHAIN_ID,
    )
    .expect("connect_block_basic_in_memory_at_height");

    assert_eq!(s.sum_fees, sum_fees, "sum_fees mismatch");
    assert_eq!(
        s.already_generated, 0,
        "already_generated should be 0 (pre-block)"
    );
    assert_eq!(
        s.already_generated_n1,
        u128::from(subsidy),
        "already_generated_n1 mismatch"
    );
    // spend output + coinbase p2pk output (anchor not added to UTXO set).
    assert_eq!(s.utxo_count, 2, "utxo_count mismatch");
    assert_eq!(
        state.already_generated,
        u128::from(subsidy),
        "state.already_generated not advanced"
    );

    // Per-element UTXO verification: covenant_type, value, created_by_coinbase for each entry.
    let spend_entry = state
        .utxos
        .get(&Outpoint {
            txid: spend_txid,
            vout: 0,
        })
        .expect("spend output missing from UTXO set");
    assert_eq!(
        spend_entry.covenant_type, COV_TYPE_P2PK,
        "spend output covenant_type mismatch"
    );
    assert_eq!(spend_entry.value, 90, "spend output value mismatch");
    assert!(
        !spend_entry.created_by_coinbase,
        "spend output created_by_coinbase should be false"
    );

    let cb_entry = state
        .utxos
        .get(&Outpoint {
            txid: coinbase_txid,
            vout: 0,
        })
        .expect("coinbase output missing from UTXO set");
    assert_eq!(
        cb_entry.covenant_type, COV_TYPE_P2PK,
        "coinbase output covenant_type mismatch"
    );
    assert_eq!(
        cb_entry.value,
        subsidy + sum_fees,
        "coinbase output value mismatch"
    );
    assert!(
        cb_entry.created_by_coinbase,
        "coinbase output created_by_coinbase should be true"
    );
}

/// Go parity: TestConnectBlockBasicInMemoryAtHeight_NilState
///
/// Go passes nil state → BLOCK_ERR_PARSE. Rust's type system prevents nil references.
/// Equivalent coverage: empty block bytes → parse failure.
#[test]
fn connect_block_empty_block_bytes_returns_error() {
    let mut state = InMemoryChainState {
        utxos: HashMap::new(),
        already_generated: 0,
    };

    let err = crate::connect_block_basic_in_memory_at_height(
        &[],
        None,
        None,
        0,
        None,
        &mut state,
        ZERO_CHAIN_ID,
    )
    .unwrap_err();

    assert_eq!(
        err.code,
        ErrorCode::BlockErrParse,
        "expected BlockErrParse for empty bytes"
    );
}

/// Go parity: TestParseAndValidateBlockBasicWithContextAtHeight_ReturnsParsedBlock
///
/// Go tests internal parseAndValidateBlockBasicWithContextAtHeight. Rust equivalent:
/// connect a valid coinbase-only block at height 0 and verify the summary matches
/// expectations (exercises parse + validate + connect path).
#[test]
fn connect_block_coinbase_only_at_height0_succeeds() {
    let height = 0u64;
    let mut prev = [0u8; 32];
    prev[0] = 0x41;
    let target = [0xffu8; 32];

    let coinbase = coinbase_with_witness_commitment(height as u32, &[]);
    let (_cb, cb_txid, _cbw, _cbn) = parse_tx(&coinbase).expect("parse coinbase");
    let root = merkle_root_txids(&[cb_txid]).expect("merkle root");
    let block = build_block_bytes(prev, root, target, 5, &[coinbase]);

    let mut state = InMemoryChainState {
        utxos: HashMap::new(),
        already_generated: 0,
    };

    let s = crate::connect_block_basic_in_memory_at_height(
        &block,
        Some(prev),
        Some(target),
        height,
        None,
        &mut state,
        ZERO_CHAIN_ID,
    )
    .expect("connect_block at height 0 with coinbase-only");

    assert_eq!(s.sum_fees, 0);
    // At height 0, already_generated must not advance.
    assert_eq!(s.already_generated, 0);
    assert_eq!(s.already_generated_n1, 0);
    // Coinbase has only anchor output (value=0, COV_TYPE_ANCHOR) which is NOT added to UTXO set.
    assert_eq!(s.utxo_count, 0);
}

/// Go parity: TestConnectBlockBasicInMemoryAtHeight_Height0_DoesNotAdvanceAlreadyGenerated
///
/// At height 0, already_generated stays at its initial value (no subsidy emission).
#[test]
fn connect_block_height0_does_not_advance_already_generated() {
    let height = 0u64;
    let mut prev = [0u8; 32];
    prev[0] = 0x12;
    let target = [0xffu8; 32];

    let coinbase = coinbase_with_witness_commitment_and_p2pk_value(height as u32, 1, &[]);
    let (_cb, cb_txid, _cbw, _cbn) = parse_tx(&coinbase).expect("parse coinbase");
    let root = merkle_root_txids(&[cb_txid]).expect("merkle root");
    let block = build_block_bytes(prev, root, target, 4, &[coinbase]);

    let mut state = InMemoryChainState {
        utxos: HashMap::new(),
        already_generated: 123,
    };

    let s = crate::connect_block_basic_in_memory_at_height(
        &block,
        Some(prev),
        Some(target),
        height,
        None,
        &mut state,
        ZERO_CHAIN_ID,
    )
    .expect("connect_block at height 0");

    assert_eq!(s.sum_fees, 0, "sum_fees should be 0 at height 0");
    assert_eq!(
        s.already_generated, 123,
        "already_generated should not change at height 0"
    );
    assert_eq!(
        s.already_generated_n1, 123,
        "already_generated_n1 should not change at height 0"
    );
    assert_eq!(
        state.already_generated, 123,
        "state.already_generated must not advance at height 0"
    );
    // 1 spendable output (p2pk with value=1); anchor excluded.
    assert_eq!(s.utxo_count, 1);
}

/// Go parity: TestConnectBlockBasicInMemoryAtHeight_RejectsSubsidyExceeded
///
/// Coinbase claims subsidy + fees + 1 → BLOCK_ERR_SUBSIDY_EXCEEDED.
#[test]
fn connect_block_rejects_subsidy_exceeded() {
    let height = 1u64;
    let mut prev = [0u8; 32];
    prev[0] = 0x78;
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

    let mut state = InMemoryChainState {
        utxos: HashMap::from([(
            prev_out,
            UtxoEntry {
                value: 100,
                covenant_type: COV_TYPE_P2PK,
                covenant_data: cov_data.clone(),
                creation_height: 0,
                created_by_coinbase: false,
            },
        )]),
        already_generated: 0,
    };

    let sum_fees = 10u64;
    let subsidy = crate::subsidy::block_subsidy(height, state.already_generated);
    // Overvalue: subsidy + fees + 1.
    let coinbase = coinbase_with_witness_commitment_and_p2pk_value(
        height as u32,
        subsidy + sum_fees + 1,
        std::slice::from_ref(&spend_bytes),
    );
    let (_cb, coinbase_txid, _cbw, _cbn) = parse_tx(&coinbase).expect("parse coinbase");
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

    assert_eq!(
        err.code,
        ErrorCode::BlockErrSubsidyExceeded,
        "expected BlockErrSubsidyExceeded"
    );
}

/// Go parity: TestConnectBlockBasicInMemoryAtHeight_RejectsCoinbaseVaultOutput
///
/// Coinbase with vault output → BLOCK_ERR_COINBASE_INVALID.
/// Verifies state is not mutated on rejected block.
#[test]
fn connect_block_rejects_coinbase_vault_output() {
    let height = 1u64;
    let mut prev = [0u8; 32];
    prev[0] = 0xb1;
    let target = [0xffu8; 32];

    let coinbase = coinbase_with_witness_commitment_and_vault_output(
        height as u32,
        1,
        &valid_vault_covenant_data_for_p2pk_output(),
        &[],
    );
    let (_cb, cb_txid, _cbw, _cbn) = parse_tx(&coinbase).expect("parse coinbase");
    let root = merkle_root_txids(&[cb_txid]).expect("merkle root");
    let block = build_block_bytes(prev, root, target, 51, &[coinbase]);

    let mut state = InMemoryChainState {
        utxos: HashMap::new(),
        already_generated: 0,
    };

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

    assert_eq!(
        err.code,
        ErrorCode::BlockErrCoinbaseInvalid,
        "expected BlockErrCoinbaseInvalid for vault in coinbase"
    );
    assert!(
        state.utxos.is_empty(),
        "state mutated on coinbase vault reject: utxos={}",
        state.utxos.len()
    );
    assert_eq!(
        state.already_generated, 0,
        "already_generated mutated on coinbase vault reject"
    );
}

/// Go parity: TestConnectBlockBasicInMemoryAtHeight_CoinbaseVaultRejectDoesNotMutateAppliedSpends
///
/// Block with valid spend tx + invalid coinbase (vault output) → BLOCK_ERR_COINBASE_INVALID.
/// Critical atomicity test: the spend's UTXO removal must be rolled back — original
/// UTXO must remain intact in state.
#[test]
fn connect_block_coinbase_vault_reject_does_not_mutate_applied_spends() {
    let height = 1u64;
    let mut prev = [0u8; 32];
    prev[0] = 0xb2;
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

    let coinbase = coinbase_with_witness_commitment_and_vault_output(
        height as u32,
        1,
        &valid_vault_covenant_data_for_p2pk_output(),
        std::slice::from_ref(&spend_bytes),
    );
    let (_cb, cb_txid, _cbw, _cbn) = parse_tx(&coinbase).expect("parse coinbase");
    let root = merkle_root_txids(&[cb_txid, spend_txid]).expect("merkle root");
    let block = build_block_bytes(prev, root, target, 52, &[coinbase, spend_bytes]);

    let mut state = InMemoryChainState {
        utxos: HashMap::from([(
            prev_out.clone(),
            UtxoEntry {
                value: 100,
                covenant_type: COV_TYPE_P2PK,
                covenant_data: cov_data.clone(),
                creation_height: 0,
                created_by_coinbase: false,
            },
        )]),
        already_generated: 0,
    };

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

    assert_eq!(
        err.code,
        ErrorCode::BlockErrCoinbaseInvalid,
        "expected BlockErrCoinbaseInvalid"
    );
    // Atomicity: original UTXO must still be present.
    assert_eq!(
        state.utxos.len(),
        1,
        "state.utxos len changed on rejected block"
    );
    let entry = state
        .utxos
        .get(&prev_out)
        .expect("original UTXO removed on rejected block");
    assert_eq!(entry.value, 100, "original UTXO value mutated");
    assert_eq!(
        entry.covenant_type, COV_TYPE_P2PK,
        "original UTXO covenant_type mutated"
    );
    assert!(
        !entry.created_by_coinbase,
        "original UTXO created_by_coinbase mutated"
    );
    assert_eq!(
        state.already_generated, 0,
        "already_generated mutated on rejected block"
    );
}

/// DeepSeek finding 1: non-zero-value anchor output in coinbase is rejected by consensus.
///
/// CORE_ANCHOR outputs must have value=0 (covenant_genesis.rs). Connect_block must
/// enforce this invariant end-to-end. Also verifies state is not mutated on rejection.
#[test]
fn connect_block_rejects_nonzero_anchor_in_coinbase() {
    let height = 1u64;
    let mut prev = [0u8; 32];
    prev[0] = 0xc1;
    let target = [0xffu8; 32];

    // Build coinbase with non-zero anchor: P2PK(1) + Anchor(value=5, commit).
    let wtxids: Vec<[u8; 32]> = vec![[0u8; 32]];
    let wroot = crate::merkle::witness_merkle_root_wtxids(&wtxids).expect("witness merkle root");
    let commit = crate::merkle::witness_commitment_hash(wroot);

    let coinbase = coinbase_tx_with_outputs(
        height as u32,
        &[
            TestOutput {
                value: 1,
                covenant_type: COV_TYPE_P2PK,
                covenant_data: valid_p2pk_covenant_data(),
            },
            TestOutput {
                value: 5, // non-zero anchor — protocol violation
                covenant_type: COV_TYPE_ANCHOR,
                covenant_data: commit.to_vec(),
            },
        ],
    );
    let (_cb, cb_txid, _cbw, _cbn) = parse_tx(&coinbase).expect("parse coinbase");
    let root = merkle_root_txids(&[cb_txid]).expect("merkle root");
    let block = build_block_bytes(prev, root, target, 60, &[coinbase]);

    let mut state = InMemoryChainState {
        utxos: HashMap::new(),
        already_generated: 0,
    };

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

    assert_eq!(
        err.code,
        ErrorCode::TxErrCovenantTypeInvalid,
        "non-zero anchor must be rejected"
    );
    assert!(
        state.utxos.is_empty(),
        "state mutated on rejected block with non-zero anchor"
    );
}

/// DeepSeek finding 2: non-coinbase tx creating a vault output must be accepted.
///
/// P2PK input (100) → Vault output (90), fee = 10. Vault's owner_lock_id
/// matches the P2PK input's lock_id, satisfying CORE_VAULT creation rules.
/// Verifies vault output ends up in UTXO set.
#[test]
fn connect_block_non_coinbase_vault_output_accepted() {
    let height = 1u64;
    let mut prev = [0u8; 32];
    prev[0] = 0xc2;
    let target = [0xffu8; 32];

    let kp = kp_or_skip!();
    let cov_data = p2pk_covenant_data_for_pubkey(&kp.pubkey);
    let prev_out = Outpoint {
        txid: prev,
        vout: 0,
    };

    // Compute the P2PK input's lock_id to use as vault owner_lock_id.
    let input_lock_id = sha3_256(&crate::vault::output_descriptor_bytes(
        COV_TYPE_P2PK,
        &cov_data,
    ));

    // Build valid vault covenant data with owner_lock_id matching the P2PK input.
    let dest_descriptor =
        crate::vault::output_descriptor_bytes(COV_TYPE_P2PK, &valid_p2pk_covenant_data());
    let dest_hash = sha3_256(&dest_descriptor);
    let vault_cov_data =
        encode_vault_covenant_data(input_lock_id, 1, &make_keys(1, 0x22), &[dest_hash]);

    // Spend tx: P2PK(100) → Vault(90), fee = 10.
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
            covenant_type: COV_TYPE_VAULT,
            covenant_data: vault_cov_data.clone(),
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
        COV_TYPE_VAULT,
        &vault_cov_data,
        witness.suite_id,
        &witness.pubkey,
        &witness.signature,
    );
    let (_tx, spend_txid, _wtxid, _n) = parse_tx(&spend_bytes).expect("parse spend tx");

    let mut state = InMemoryChainState {
        utxos: HashMap::from([(
            prev_out,
            UtxoEntry {
                value: 100,
                covenant_type: COV_TYPE_P2PK,
                covenant_data: cov_data.clone(),
                creation_height: 0,
                created_by_coinbase: false,
            },
        )]),
        already_generated: 0,
    };

    let sum_fees = 10u64;
    let subsidy = crate::subsidy::block_subsidy(height, state.already_generated);
    let coinbase = coinbase_with_witness_commitment_and_p2pk_value(
        height as u32,
        subsidy + sum_fees,
        std::slice::from_ref(&spend_bytes),
    );
    let (_cb, coinbase_txid, _cbw, _cbn) = parse_tx(&coinbase).expect("parse coinbase");
    let root = merkle_root_txids(&[coinbase_txid, spend_txid]).expect("merkle root");
    let block = build_block_bytes(prev, root, target, 61, &[coinbase, spend_bytes]);

    let s = crate::connect_block_basic_in_memory_at_height(
        &block,
        Some(prev),
        Some(target),
        height,
        Some(&[0]),
        &mut state,
        ZERO_CHAIN_ID,
    )
    .expect("connect_block with vault output in non-coinbase tx");

    assert_eq!(s.sum_fees, sum_fees);
    // 2 UTXO entries: vault output (90) + coinbase P2PK output.
    assert_eq!(s.utxo_count, 2, "vault output must be in UTXO set");

    // Verify vault output is actually present.
    let mut found_vault = false;
    for entry in state.utxos.values() {
        if entry.covenant_type == COV_TYPE_VAULT {
            assert_eq!(entry.value, 90, "vault UTXO value mismatch");
            assert_eq!(
                entry.covenant_data, vault_cov_data,
                "vault UTXO covenant_data mismatch"
            );
            found_vault = true;
        }
    }
    assert!(found_vault, "vault output not found in UTXO set");
}
