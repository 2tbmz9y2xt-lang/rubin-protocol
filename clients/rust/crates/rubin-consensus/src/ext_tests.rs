use std::collections::HashMap;

use crate::apply_non_coinbase_tx_basic_with_mtp;
use crate::apply_non_coinbase_tx_basic_with_mtp_and_profiles;
use crate::constants::{
    CORE_EXT_WITNESS_SLOTS, COV_TYPE_EXT, COV_TYPE_P2PK, SUITE_ID_ML_DSA_87, SUITE_ID_SENTINEL,
    VERIFY_COST_UNKNOWN_SUITE,
};
use crate::covenant_genesis::validate_tx_covenants_genesis;
use crate::encode_compact_size;
use crate::error::ErrorCode;
use crate::ext::parse_core_ext_covenant_data;
use crate::tx::{Tx, TxInput, TxOutput, WitnessItem};
use crate::tx_weight_and_stats_public;
use crate::{CoreExtProfile, Outpoint, UtxoEntry};

fn encode_core_ext_covenant_data(ext_id: u16, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&ext_id.to_le_bytes());
    encode_compact_size(payload.len() as u64, &mut out);
    out.extend_from_slice(payload);
    out
}

fn valid_p2pk_covenant_data() -> Vec<u8> {
    let mut out = Vec::with_capacity(33);
    out.push(SUITE_ID_ML_DSA_87);
    out.extend_from_slice(&[0x11u8; 32]);
    out
}

#[test]
fn parse_core_ext_covenant_data_valid_and_malformed() {
    let good = encode_core_ext_covenant_data(0x0011, &[0xaa, 0xbb, 0xcc]);
    let ext = parse_core_ext_covenant_data(&good).expect("valid CORE_EXT covenant_data");
    assert_eq!(ext.ext_id, 0x0011);
    assert_eq!(ext.ext_payload, vec![0xaa, 0xbb, 0xcc]);

    let bad = &good[..good.len() - 1];
    let err = parse_core_ext_covenant_data(bad).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrCovenantTypeInvalid);
}

#[test]
fn witness_slots_core_ext_fixed() {
    let slots = crate::witness_slots(COV_TYPE_EXT, &[]).expect("CORE_EXT witness slots");
    assert_eq!(slots, CORE_EXT_WITNESS_SLOTS);
}

#[test]
fn validate_tx_covenants_genesis_core_ext() {
    let mut tx = Tx {
        version: 1,
        tx_kind: 0x00,
        tx_nonce: 1,
        inputs: Vec::new(),
        outputs: vec![TxOutput {
            value: 1,
            covenant_type: COV_TYPE_EXT,
            covenant_data: encode_core_ext_covenant_data(0x1234, &[0x01]),
        }],
        locktime: 0,
        da_commit_core: None,
        da_chunk_core: None,
        witness: Vec::new(),
        da_payload: Vec::new(),
    };
    validate_tx_covenants_genesis(&tx, 0).expect("valid CORE_EXT output");

    tx.outputs[0].value = 0;
    let err = validate_tx_covenants_genesis(&tx, 0).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrCovenantTypeInvalid);
}

#[test]
fn apply_non_coinbase_core_ext_preactivation_sentinel_rule() {
    let prev_txid = [0x42u8; 32];
    let txid = [0x43u8; 32];
    let ext_cov_data = encode_core_ext_covenant_data(0x0077, &[0x10, 0x20]);

    let base_tx = Tx {
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
        witness: vec![WitnessItem {
            suite_id: SUITE_ID_SENTINEL,
            pubkey: Vec::new(),
            signature: Vec::new(),
        }],
        da_payload: Vec::new(),
    };

    let mut utxos = HashMap::new();
    utxos.insert(
        Outpoint {
            txid: prev_txid,
            vout: 0,
        },
        UtxoEntry {
            value: 100,
            covenant_type: COV_TYPE_EXT,
            covenant_data: ext_cov_data,
            creation_height: 0,
            created_by_coinbase: false,
        },
    );

    let summary =
        apply_non_coinbase_tx_basic_with_mtp(&base_tx, txid, &utxos, 100, 1000, 1000, [0u8; 32])
            .expect("sentinel pre-activation spend must pass");
    assert_eq!(summary.fee, 10);

    let mut non_sentinel_tx = base_tx.clone();
    non_sentinel_tx.witness = vec![WitnessItem {
        suite_id: SUITE_ID_ML_DSA_87,
        pubkey: Vec::new(),
        signature: Vec::new(),
    }];
    let err = apply_non_coinbase_tx_basic_with_mtp(
        &non_sentinel_tx,
        txid,
        &utxos,
        100,
        1000,
        1000,
        [0u8; 32],
    )
    .unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrParse);
}

#[test]
fn apply_non_coinbase_core_ext_active_profile_enforces_allowed_suites() {
    let prev_txid = [0x51u8; 32];
    let txid = [0x52u8; 32];
    let ext_cov_data = encode_core_ext_covenant_data(0x0077, &[0xaa]);

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
            value: 90,
            covenant_type: COV_TYPE_P2PK,
            covenant_data: valid_p2pk_covenant_data(),
        }],
        locktime: 0,
        da_commit_core: None,
        da_chunk_core: None,
        witness: vec![WitnessItem {
            suite_id: 0x03,
            pubkey: Vec::new(),
            signature: Vec::new(),
        }],
        da_payload: Vec::new(),
    };

    let mut utxos = HashMap::new();
    utxos.insert(
        Outpoint {
            txid: prev_txid,
            vout: 0,
        },
        UtxoEntry {
            value: 100,
            covenant_type: COV_TYPE_EXT,
            covenant_data: ext_cov_data,
            creation_height: 0,
            created_by_coinbase: false,
        },
    );

    let profiles = vec![CoreExtProfile {
        ext_id: 0x0077,
        activation_height: 1_000,
        allowed_suite_ids: vec![SUITE_ID_ML_DSA_87],
    }];

    let err = apply_non_coinbase_tx_basic_with_mtp_and_profiles(
        &tx,
        txid,
        &utxos,
        1_000,
        1000,
        1000,
        [0u8; 32],
        Some(&profiles),
    )
    .unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrSigAlgInvalid);
}

#[test]
fn tx_weight_unknown_suite_conservative_sig_cost() {
    let tx = Tx {
        version: 1,
        tx_kind: 0x00,
        tx_nonce: 1,
        inputs: Vec::new(),
        outputs: vec![TxOutput {
            value: 1,
            covenant_type: COV_TYPE_P2PK,
            covenant_data: valid_p2pk_covenant_data(),
        }],
        locktime: 0,
        da_commit_core: None,
        da_chunk_core: None,
        witness: vec![WitnessItem {
            suite_id: 0x7f,
            pubkey: vec![0x01],
            signature: vec![0x02],
        }],
        da_payload: Vec::new(),
    };
    let (weight, _, _) = tx_weight_and_stats_public(&tx).expect("weight");
    assert!(weight >= VERIFY_COST_UNKNOWN_SUITE);
}
