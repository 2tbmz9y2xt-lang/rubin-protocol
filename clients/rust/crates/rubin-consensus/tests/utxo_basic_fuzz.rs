//! Deterministic fuzz-style tests for utxo_basic: apply_non_coinbase_tx_basic,
//! apply_non_coinbase_tx_basic_with_mtp. Mirrors Go FuzzApplyNonCoinbaseTxBasic,
//! FuzzUtxoApplyNonCoinbase.
//!
//! Invariant: no panic on any parsed-tx + UTXO set combination; deterministic results.

use rubin_consensus::{
    apply_non_coinbase_tx_basic, apply_non_coinbase_tx_basic_with_mtp,
    p2pk_covenant_data_for_pubkey, parse_tx, Outpoint, UtxoEntry,
};
use std::collections::HashMap;

const COV_TYPE_P2PK: u16 = 0x0000;

fn dummy_pubkey() -> Vec<u8> {
    vec![0x42u8; 2592] // ML-DSA-87 pubkey size
}

fn dummy_p2pk_cov_data() -> Vec<u8> {
    p2pk_covenant_data_for_pubkey(&dummy_pubkey())
}

fn make_utxo_set_for_tx_inputs(
    tx_bytes: &[u8],
) -> Option<(rubin_consensus::Tx, [u8; 32], HashMap<Outpoint, UtxoEntry>)> {
    let (tx, txid, _wtxid, _consumed) = match parse_tx(tx_bytes) {
        Ok(v) => v,
        Err(_) => return None,
    };
    if tx.inputs.is_empty() {
        return None;
    }

    let mut utxos = HashMap::new();
    for inp in &tx.inputs {
        utxos.insert(
            Outpoint {
                txid: inp.prev_txid,
                vout: inp.prev_vout,
            },
            UtxoEntry {
                value: 1_000_000,
                covenant_type: COV_TYPE_P2PK,
                covenant_data: dummy_p2pk_cov_data(),
                creation_height: 1,
                created_by_coinbase: false,
            },
        );
    }
    Some((tx, txid, utxos))
}

// =============================================================
// apply_non_coinbase_tx_basic — malformed tx bytes → no panic
// =============================================================

#[test]
fn utxo_apply_empty_tx_bytes() {
    // parse_tx fails, so we never reach apply — but no panic
    assert!(parse_tx(&[]).is_err());
}

#[test]
fn utxo_apply_all_zeros() {
    let _ = parse_tx(&[0u8; 128]);
}

#[test]
fn utxo_apply_all_ff() {
    let _ = parse_tx(&[0xFF; 128]);
}

#[test]
fn utxo_apply_incremental_lengths_no_panic() {
    for len in 0..=200 {
        let _ = parse_tx(&vec![0x55u8; len]);
    }
}

// =============================================================
// apply with synthetic UTXO set — no panic, deterministic
// =============================================================

#[test]
fn utxo_apply_missing_input_in_utxo_set() {
    // Construct a minimal tx that parses, but provide empty UTXO set
    let tx_bytes = minimal_tx_bytes();
    let (tx, txid, _wtxid, _consumed) = parse_tx(&tx_bytes).expect("minimal_tx_bytes must parse");
    let empty_utxos = HashMap::new();
    let chain_id = [0u8; 32];
    // Should error (missing UTXO), not panic
    let _ = apply_non_coinbase_tx_basic(&tx, txid, &empty_utxos, 1, 1000, chain_id);
}

#[test]
fn utxo_apply_with_matched_utxos_no_panic() {
    let tx_bytes = minimal_tx_bytes();
    let (tx, txid, utxos) =
        make_utxo_set_for_tx_inputs(&tx_bytes).expect("minimal_tx_bytes must parse with UTXOs");
    let chain_id = [0u8; 32];
    let r1 = apply_non_coinbase_tx_basic(&tx, txid, &utxos, 1, 1000, chain_id);
    let r2 = apply_non_coinbase_tx_basic(&tx, txid, &utxos, 1, 1000, chain_id);
    assert_eq!(r1.is_ok(), r2.is_ok());
}

#[test]
fn utxo_apply_with_mtp_no_panic() {
    let tx_bytes = minimal_tx_bytes();
    let (tx, txid, utxos) =
        make_utxo_set_for_tx_inputs(&tx_bytes).expect("minimal_tx_bytes must parse with UTXOs");
    let chain_id = [0u8; 32];
    let _ = apply_non_coinbase_tx_basic_with_mtp(&tx, txid, &utxos, 1, 1000, 900, chain_id);
}

#[test]
fn utxo_apply_height_zero() {
    let tx_bytes = minimal_tx_bytes();
    let (tx, txid, utxos) =
        make_utxo_set_for_tx_inputs(&tx_bytes).expect("minimal_tx_bytes must parse with UTXOs");
    let chain_id = [0u8; 32];
    let _ = apply_non_coinbase_tx_basic(&tx, txid, &utxos, 0, 0, chain_id);
}

#[test]
fn utxo_apply_height_max() {
    let tx_bytes = minimal_tx_bytes();
    let (tx, txid, utxos) =
        make_utxo_set_for_tx_inputs(&tx_bytes).expect("minimal_tx_bytes must parse with UTXOs");
    let chain_id = [0u8; 32];
    let _ = apply_non_coinbase_tx_basic(&tx, txid, &utxos, u64::MAX, u64::MAX, chain_id);
}

#[test]
fn utxo_apply_deterministic() {
    let tx_bytes = minimal_tx_bytes();
    let (tx, txid, utxos) =
        make_utxo_set_for_tx_inputs(&tx_bytes).expect("minimal_tx_bytes must parse with UTXOs");
    let chain_id = [0u8; 32];
    let r1 = apply_non_coinbase_tx_basic_with_mtp(&tx, txid, &utxos, 100, 1000, 900, chain_id);
    let r2 = apply_non_coinbase_tx_basic_with_mtp(&tx, txid, &utxos, 100, 1000, 900, chain_id);
    match (r1, r2) {
        (Ok(s1), Ok(s2)) => {
            assert_eq!(s1.fee, s2.fee);
        }
        (Err(_), Err(_)) => {} // both error — ok
        _ => panic!("non-deterministic result"),
    }
}

// =============================================================
// Synthetic valid tx with P2PK covenant: parse round-trip
// =============================================================

#[test]
fn utxo_apply_various_chain_ids() {
    let tx_bytes = minimal_tx_bytes();
    let (tx, txid, utxos) =
        make_utxo_set_for_tx_inputs(&tx_bytes).expect("minimal_tx_bytes must parse with UTXOs");
    // Different chain IDs should not panic
    for byte in [0x00, 0x01, 0xFF] {
        let chain_id = [byte; 32];
        let _ = apply_non_coinbase_tx_basic(&tx, txid, &utxos, 1, 1000, chain_id);
    }
}

// =============================================================
// Helper: construct minimal valid tx bytes
// =============================================================

fn minimal_tx_bytes() -> Vec<u8> {
    // Minimal standard tx: version=1, kind=0, 1 input, 1 P2PK output.
    // Wire format: version(u32) | tx_kind(u8) | tx_nonce(u64) | input_count(cs)
    //   | [prev_txid(32) + prev_vout(u32) + script_sig_len(cs) + script_sig + sequence(u32)] ...
    //   | output_count(cs) | [value(u64) + cov_type(u16) + cov_data_len(cs) + cov_data] ...
    //   | locktime(u32) | witness_count(cs) | [suite(u8) + pk_len(cs) + pk + sig_len(cs) + sig] ...
    //   | da_payload_len(cs) | da_payload
    let mut buf = Vec::new();

    // version: u32 LE — MUST be TX_WIRE_VERSION (1)
    buf.extend_from_slice(&1u32.to_le_bytes());
    // tx_kind: u8
    buf.push(0x00);
    // tx_nonce: u64 LE
    buf.extend_from_slice(&0u64.to_le_bytes());

    // input_count: compact_size = 1
    buf.push(0x01);
    // input[0]:
    //   prev_txid: 32 bytes
    buf.extend_from_slice(&[0x55u8; 32]);
    //   prev_vout: u32 LE
    buf.extend_from_slice(&0u32.to_le_bytes());
    //   script_sig_len: compact_size = 0
    buf.push(0x00);
    //   sequence: u32 LE
    buf.extend_from_slice(&0xFFFFFFFFu32.to_le_bytes());

    // output_count: compact_size = 1
    buf.push(0x01);
    // output[0]:
    //   value: u64 LE
    buf.extend_from_slice(&100u64.to_le_bytes());
    //   covenant_type: u16 LE
    buf.extend_from_slice(&COV_TYPE_P2PK.to_le_bytes());
    //   covenant_data_len: compact_size + data
    let cov_data = dummy_p2pk_cov_data();
    rubin_consensus::encode_compact_size(cov_data.len() as u64, &mut buf);
    buf.extend_from_slice(&cov_data);

    // locktime: u32 LE
    buf.extend_from_slice(&0u32.to_le_bytes());

    // witness_count: compact_size = 0 (no witnesses)
    buf.push(0x00);

    // da_payload_len: compact_size = 0
    buf.push(0x00);

    buf
}
