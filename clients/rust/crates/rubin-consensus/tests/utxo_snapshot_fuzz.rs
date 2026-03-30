//! Deterministic direct tests for utxo_snapshot: UtxoSnapshot, utxo_snapshot_shard.
//! Mirrors Go TestUtxoSnapshot_* + shard distribution tests.
//!
//! Invariant: no panic; deterministic; immutability; shard bounds.

use rubin_consensus::{utxo_snapshot_shard, Outpoint, UtxoEntry, UtxoSnapshot};
use std::collections::HashMap;

fn test_outpoint(txid_byte: u8, vout: u32) -> Outpoint {
    let mut txid = [0u8; 32];
    txid[0] = txid_byte;
    Outpoint { txid, vout }
}

fn test_entry(value: u64) -> UtxoEntry {
    UtxoEntry {
        value,
        covenant_type: 0,
        covenant_data: Vec::new(),
        creation_height: 0,
        created_by_coinbase: false,
    }
}

// =============================================================
// UtxoSnapshot — construction and lookup
// =============================================================

#[test]
fn snapshot_none_is_empty() {
    let snap = UtxoSnapshot::new(None);
    assert_eq!(snap.count(), 0);
    assert!(snap.get(&test_outpoint(0xAA, 0)).is_none());
    assert!(!snap.contains(&test_outpoint(0xAA, 0)));
}

#[test]
fn snapshot_empty_map() {
    let utxos = HashMap::new();
    let snap = UtxoSnapshot::new(Some(&utxos));
    assert_eq!(snap.count(), 0);
}

#[test]
fn snapshot_single_entry() {
    let mut utxos = HashMap::new();
    utxos.insert(test_outpoint(0x01, 0), test_entry(1000));
    let snap = UtxoSnapshot::new(Some(&utxos));
    assert_eq!(snap.count(), 1);
    assert_eq!(snap.get(&test_outpoint(0x01, 0)).unwrap().value, 1000);
    assert!(snap.contains(&test_outpoint(0x01, 0)));
    assert!(!snap.contains(&test_outpoint(0x02, 0)));
}

#[test]
fn snapshot_multiple_entries() {
    let mut utxos = HashMap::new();
    for i in 0..10u8 {
        utxos.insert(test_outpoint(i, i as u32), test_entry(i as u64 * 100));
    }
    let snap = UtxoSnapshot::new(Some(&utxos));
    assert_eq!(snap.count(), 10);
    for i in 0..10u8 {
        let entry = snap.get(&test_outpoint(i, i as u32)).unwrap();
        assert_eq!(entry.value, i as u64 * 100);
    }
}

// =============================================================
// Immutability after creation
// =============================================================

#[test]
fn snapshot_immutable_after_creation() {
    let mut utxos = HashMap::new();
    utxos.insert(test_outpoint(0xAA, 0), test_entry(1000));
    utxos.insert(test_outpoint(0xBB, 0), test_entry(2000));
    let snap = UtxoSnapshot::new(Some(&utxos));

    // Mutate source
    utxos.remove(&test_outpoint(0xAA, 0));
    utxos.insert(test_outpoint(0xFF, 0), test_entry(9999));

    // Snapshot unchanged
    assert_eq!(snap.count(), 2);
    assert_eq!(snap.get(&test_outpoint(0xAA, 0)).unwrap().value, 1000);
    assert!(!snap.contains(&test_outpoint(0xFF, 0)));
}

// =============================================================
// resolve_inputs
// =============================================================

#[test]
fn snapshot_resolve_inputs_all_found() {
    let mut utxos = HashMap::new();
    utxos.insert(test_outpoint(0xAA, 0), test_entry(1000));
    utxos.insert(test_outpoint(0xBB, 1), test_entry(2000));
    let snap = UtxoSnapshot::new(Some(&utxos));

    let tx = rubin_consensus::Tx {
        version: 1,
        tx_kind: 0,
        tx_nonce: 1,
        inputs: vec![
            rubin_consensus::TxInput {
                prev_txid: test_outpoint(0xAA, 0).txid,
                prev_vout: 0,
                script_sig: vec![],
                sequence: 0,
            },
            rubin_consensus::TxInput {
                prev_txid: test_outpoint(0xBB, 1).txid,
                prev_vout: 1,
                script_sig: vec![],
                sequence: 0,
            },
        ],
        outputs: vec![],
        locktime: 0,
        da_commit_core: None,
        da_chunk_core: None,
        witness: vec![],
        da_payload: vec![],
    };

    let entries = snap.resolve_inputs(&tx).unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].value, 1000);
    assert_eq!(entries[1].value, 2000);
}

#[test]
fn snapshot_resolve_inputs_missing() {
    let utxos = HashMap::new();
    let snap = UtxoSnapshot::new(Some(&utxos));

    let tx = rubin_consensus::Tx {
        version: 1,
        tx_kind: 0,
        tx_nonce: 1,
        inputs: vec![rubin_consensus::TxInput {
            prev_txid: test_outpoint(0xFF, 0).txid,
            prev_vout: 0,
            script_sig: vec![],
            sequence: 0,
        }],
        outputs: vec![],
        locktime: 0,
        da_commit_core: None,
        da_chunk_core: None,
        witness: vec![],
        da_payload: vec![],
    };

    let err = snap.resolve_inputs(&tx).unwrap_err();
    assert!(err.to_string().contains("missing UTXO") || err.code.as_str() == "TX_ERR_MISSING_UTXO");
}

#[test]
fn snapshot_resolve_inputs_empty() {
    let snap = UtxoSnapshot::new(Some(&HashMap::new()));
    let tx = rubin_consensus::Tx {
        version: 1,
        tx_kind: 0,
        tx_nonce: 1,
        inputs: vec![],
        outputs: vec![],
        locktime: 0,
        da_commit_core: None,
        da_chunk_core: None,
        witness: vec![],
        da_payload: vec![],
    };
    let entries = snap.resolve_inputs(&tx).unwrap();
    assert!(entries.is_empty());
}

// =============================================================
// for_each
// =============================================================

#[test]
fn snapshot_for_each_visits_all() {
    let mut utxos = HashMap::new();
    for i in 0..5u8 {
        utxos.insert(test_outpoint(i, 0), test_entry(i as u64 * 100));
    }
    let snap = UtxoSnapshot::new(Some(&utxos));

    let mut total_value = 0u64;
    let mut count = 0usize;
    snap.for_each(|_, entry| {
        total_value += entry.value;
        count += 1;
    });
    assert_eq!(count, 5);
    assert_eq!(total_value, 0 + 100 + 200 + 300 + 400);
}

// =============================================================
// utxo_snapshot_shard — bounds and determinism
// =============================================================

#[test]
fn shard_zero_shards_returns_zero() {
    assert_eq!(utxo_snapshot_shard(&test_outpoint(0xAA, 0), 0), 0);
}

#[test]
fn shard_one_shard_returns_zero() {
    assert_eq!(utxo_snapshot_shard(&test_outpoint(0xAA, 0), 1), 0);
}

#[test]
fn shard_result_within_bounds() {
    for i in 0..=255u8 {
        let op = test_outpoint(i, i as u32);
        for num_shards in [2, 3, 4, 7, 8, 16, 31, 32, 64, 128, 256] {
            let shard = utxo_snapshot_shard(&op, num_shards);
            assert!(
                shard < num_shards,
                "shard={shard} >= num_shards={num_shards}"
            );
        }
    }
}

#[test]
fn shard_deterministic() {
    let op = test_outpoint(0xAB, 3);
    let s1 = utxo_snapshot_shard(&op, 8);
    let s2 = utxo_snapshot_shard(&op, 8);
    assert_eq!(s1, s2);
}

#[test]
fn shard_same_txid_different_vout_same_shard() {
    for vout in 0..100u32 {
        assert_eq!(
            utxo_snapshot_shard(&test_outpoint(0xAA, 0), 8),
            utxo_snapshot_shard(&test_outpoint(0xAA, vout), 8),
        );
    }
}

#[test]
fn shard_distribution_nontrivial() {
    let num_shards = 4;
    let mut counts = [0usize; 4];
    for i in 0..=255u8 {
        let mut txid = [0u8; 32];
        txid[0] = i;
        txid[1] = i.wrapping_mul(7);
        txid[2] = i.wrapping_mul(13);
        txid[3] = i.wrapping_mul(31);
        let shard = utxo_snapshot_shard(&Outpoint { txid, vout: 0 }, num_shards);
        counts[shard] += 1;
    }
    // Every shard must get at least some entries
    assert!(counts.iter().all(|c| *c > 0), "distribution: {counts:?}");
}

// =============================================================
// Concurrent reads stability (single-threaded determinism proxy)
// =============================================================

#[test]
fn snapshot_repeated_reads_stable() {
    let mut utxos = HashMap::new();
    for i in 0..50u8 {
        utxos.insert(test_outpoint(i, 0), test_entry(i as u64 * 10));
    }
    let snap = UtxoSnapshot::new(Some(&utxos));

    for _ in 0..100 {
        for i in 0..50u8 {
            let entry = snap.get(&test_outpoint(i, 0)).unwrap();
            assert_eq!(entry.value, i as u64 * 10);
        }
    }
}

// =============================================================
// Default trait
// =============================================================

#[test]
fn snapshot_default_is_empty() {
    let snap = UtxoSnapshot::default();
    assert_eq!(snap.count(), 0);
}
