//! Deterministic fuzz-style tests for validate_tx_covenants_genesis.
//! Mirrors Go FuzzValidateTxCovenantsGenesis.
//!
//! Invariant: no panic on any parsed Tx + block_height; deterministic results.

use rubin_consensus::constants::{
    COV_TYPE_ANCHOR, COV_TYPE_DA_COMMIT, COV_TYPE_EXT, COV_TYPE_HTLC, COV_TYPE_MULTISIG,
    COV_TYPE_P2PK, COV_TYPE_RESERVED_FUTURE, COV_TYPE_STEALTH, COV_TYPE_VAULT,
    MAX_P2PK_COVENANT_DATA, SUITE_ID_ML_DSA_87,
};
use rubin_consensus::{parse_tx, validate_tx_covenants_genesis, Tx, TxInput, TxOutput};

// =============================================================
// Malformed tx bytes → parse_tx fails, never reaches genesis
// =============================================================

#[test]
fn cov_genesis_empty_tx_bytes() {
    assert!(parse_tx(&[]).is_err());
}

#[test]
fn cov_genesis_all_zeros() {
    let _ = parse_tx(&[0u8; 128]);
}

#[test]
fn cov_genesis_all_ff() {
    let _ = parse_tx(&[0xFF; 128]);
}

#[test]
fn cov_genesis_incremental_lengths_no_panic() {
    for len in 0..=200 {
        let _ = parse_tx(&vec![0x55u8; len]);
    }
}

// =============================================================
// Synthetic Tx with various covenant types — no panic
// =============================================================

fn make_tx_with_outputs(outputs: Vec<TxOutput>) -> Tx {
    Tx {
        version: 1,
        tx_kind: 0x00,
        tx_nonce: 0,
        locktime: 0,
        inputs: vec![TxInput {
            prev_txid: [0x55u8; 32],
            prev_vout: 0,
            script_sig: vec![],
            sequence: 0xFFFFFFFF,
        }],
        outputs,
        witness: vec![],
        da_commit_core: None,
        da_chunk_core: None,
        da_payload: vec![],
    }
}

fn valid_p2pk_covenant_data() -> Vec<u8> {
    let mut cov = vec![0u8; MAX_P2PK_COVENANT_DATA as usize];
    cov[0] = SUITE_ID_ML_DSA_87;
    cov
}

#[test]
fn cov_genesis_empty_outputs() {
    let tx = make_tx_with_outputs(vec![]);
    let r = validate_tx_covenants_genesis(&tx, 1, None);
    assert!(r.is_ok());
}

#[test]
fn cov_genesis_p2pk_valid_suite() {
    let tx = make_tx_with_outputs(vec![TxOutput {
        value: 100,
        covenant_type: COV_TYPE_P2PK,
        covenant_data: valid_p2pk_covenant_data(),
    }]);
    assert!(validate_tx_covenants_genesis(&tx, 1, None).is_ok());
}

#[test]
fn cov_genesis_p2pk_zero_value_rejected() {
    let tx = make_tx_with_outputs(vec![TxOutput {
        value: 0,
        covenant_type: COV_TYPE_P2PK,
        covenant_data: valid_p2pk_covenant_data(),
    }]);
    assert!(validate_tx_covenants_genesis(&tx, 1, None).is_err());
}

#[test]
fn cov_genesis_p2pk_wrong_data_len() {
    let cov_data = vec![SUITE_ID_ML_DSA_87; 100]; // wrong length
    let tx = make_tx_with_outputs(vec![TxOutput {
        value: 100,
        covenant_type: COV_TYPE_P2PK,
        covenant_data: cov_data,
    }]);
    assert!(validate_tx_covenants_genesis(&tx, 1, None).is_err());
}

#[test]
fn cov_genesis_p2pk_invalid_suite() {
    let mut cov_data = vec![0u8; MAX_P2PK_COVENANT_DATA as usize];
    cov_data[0] = 0xFF; // invalid suite_id
    let tx = make_tx_with_outputs(vec![TxOutput {
        value: 100,
        covenant_type: COV_TYPE_P2PK,
        covenant_data: cov_data,
    }]);
    assert!(validate_tx_covenants_genesis(&tx, 1, None).is_err());
}

#[test]
fn cov_genesis_anchor_valid() {
    let tx = make_tx_with_outputs(vec![TxOutput {
        value: 0,
        covenant_type: COV_TYPE_ANCHOR,
        covenant_data: vec![0x42; 32],
    }]);
    assert!(validate_tx_covenants_genesis(&tx, 1, None).is_ok());
}

#[test]
fn cov_genesis_anchor_nonzero_value() {
    let tx = make_tx_with_outputs(vec![TxOutput {
        value: 1,
        covenant_type: COV_TYPE_ANCHOR,
        covenant_data: vec![0x42; 32],
    }]);
    assert!(validate_tx_covenants_genesis(&tx, 1, None).is_err());
}

#[test]
fn cov_genesis_anchor_empty_data() {
    let tx = make_tx_with_outputs(vec![TxOutput {
        value: 0,
        covenant_type: COV_TYPE_ANCHOR,
        covenant_data: vec![],
    }]);
    assert!(validate_tx_covenants_genesis(&tx, 1, None).is_err());
}

#[test]
fn cov_genesis_unknown_type_rejected() {
    let tx = make_tx_with_outputs(vec![TxOutput {
        value: 100,
        covenant_type: 0xFFFF,
        covenant_data: vec![0x00; 10],
    }]);
    assert!(validate_tx_covenants_genesis(&tx, 1, None).is_err());
}

#[test]
fn cov_genesis_reserved_future_rejected() {
    let tx = make_tx_with_outputs(vec![TxOutput {
        value: 100,
        covenant_type: COV_TYPE_RESERVED_FUTURE,
        covenant_data: vec![0x00; 10],
    }]);
    assert!(validate_tx_covenants_genesis(&tx, 1, None).is_err());
}

#[test]
fn cov_genesis_da_commit_valid() {
    let mut tx = make_tx_with_outputs(vec![TxOutput {
        value: 0,
        covenant_type: COV_TYPE_DA_COMMIT,
        covenant_data: vec![0x42; 32],
    }]);
    tx.tx_kind = 0x01;
    assert!(validate_tx_covenants_genesis(&tx, 1, None).is_ok());
}

#[test]
fn cov_genesis_da_commit_wrong_tx_kind() {
    let tx = make_tx_with_outputs(vec![TxOutput {
        value: 0,
        covenant_type: COV_TYPE_DA_COMMIT,
        covenant_data: vec![0x42; 32],
    }]);
    assert!(validate_tx_covenants_genesis(&tx, 1, None).is_err());
}

#[test]
fn cov_genesis_da_commit_wrong_data_len() {
    let mut tx = make_tx_with_outputs(vec![TxOutput {
        value: 0,
        covenant_type: COV_TYPE_DA_COMMIT,
        covenant_data: vec![0x42; 31],
    }]);
    tx.tx_kind = 0x01;
    assert!(validate_tx_covenants_genesis(&tx, 1, None).is_err());
}

// =============================================================
// Determinism
// =============================================================

#[test]
fn cov_genesis_deterministic() {
    let tx = make_tx_with_outputs(vec![TxOutput {
        value: 100,
        covenant_type: COV_TYPE_P2PK,
        covenant_data: valid_p2pk_covenant_data(),
    }]);
    let r1 = validate_tx_covenants_genesis(&tx, 1, None);
    let r2 = validate_tx_covenants_genesis(&tx, 1, None);
    assert_eq!(r1.is_ok(), r2.is_ok());
}

#[test]
fn cov_genesis_deterministic_error() {
    let tx = make_tx_with_outputs(vec![TxOutput {
        value: 100,
        covenant_type: 0xFFFF,
        covenant_data: vec![],
    }]);
    let r1 = validate_tx_covenants_genesis(&tx, 1, None);
    let r2 = validate_tx_covenants_genesis(&tx, 1, None);
    assert!(r1.is_err());
    assert!(r2.is_err());
}

// =============================================================
// Height boundary — no panic
// =============================================================

#[test]
fn cov_genesis_height_zero() {
    let tx = make_tx_with_outputs(vec![]);
    let _ = validate_tx_covenants_genesis(&tx, 0, None);
}

#[test]
fn cov_genesis_height_max() {
    let tx = make_tx_with_outputs(vec![]);
    let _ = validate_tx_covenants_genesis(&tx, u64::MAX, None);
}

// =============================================================
// Multiple outputs mixed — no panic
// =============================================================

#[test]
fn cov_genesis_mixed_outputs_no_panic() {
    let tx = make_tx_with_outputs(vec![
        TxOutput {
            value: 100,
            covenant_type: COV_TYPE_P2PK,
            covenant_data: valid_p2pk_covenant_data(),
        },
        TxOutput {
            value: 0,
            covenant_type: COV_TYPE_ANCHOR,
            covenant_data: vec![0x42; 32],
        },
    ]);
    assert!(validate_tx_covenants_genesis(&tx, 1, None).is_ok());
}

#[test]
fn cov_genesis_all_known_types_no_panic() {
    for cov_type in [
        COV_TYPE_P2PK,
        COV_TYPE_ANCHOR,
        COV_TYPE_EXT,
        COV_TYPE_HTLC,
        COV_TYPE_VAULT,
        COV_TYPE_MULTISIG,
        COV_TYPE_STEALTH,
        COV_TYPE_DA_COMMIT,
        COV_TYPE_RESERVED_FUTURE,
        0xFFFF,
    ] {
        let tx = make_tx_with_outputs(vec![TxOutput {
            value: 1,
            covenant_type: cov_type,
            covenant_data: vec![0x42; 64],
        }]);
        let _ = validate_tx_covenants_genesis(&tx, 1, None);
    }
}
