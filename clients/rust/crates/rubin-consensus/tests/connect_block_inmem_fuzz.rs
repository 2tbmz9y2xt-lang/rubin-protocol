//! Deterministic fuzz-style tests for connect_block_basic_in_memory_at_height.
//! Mirrors Go FuzzConnectBlockInMemory.
//!
//! Invariant: no panic on any block_bytes + chain state; deterministic results.

use rubin_consensus::{
    connect_block_basic_in_memory_at_height, InMemoryChainState, Outpoint, UtxoEntry,
};
use std::collections::HashMap;

fn empty_state() -> InMemoryChainState {
    InMemoryChainState {
        utxos: HashMap::new(),
        already_generated: 0,
    }
}

// =============================================================
// Empty / minimal inputs — no panic
// =============================================================

#[test]
fn connect_empty_block_bytes() {
    let mut state = empty_state();
    let chain_id = [0u8; 32];
    let result =
        connect_block_basic_in_memory_at_height(&[], None, None, 1, None, &mut state, chain_id);
    assert!(result.is_err());
}

#[test]
fn connect_one_byte() {
    let mut state = empty_state();
    let chain_id = [0u8; 32];
    let result =
        connect_block_basic_in_memory_at_height(&[0x00], None, None, 1, None, &mut state, chain_id);
    assert!(result.is_err());
}

#[test]
fn connect_all_zeros_256() {
    let mut state = empty_state();
    let chain_id = [0u8; 32];
    let result = connect_block_basic_in_memory_at_height(
        &[0u8; 256],
        None,
        None,
        1,
        None,
        &mut state,
        chain_id,
    );
    // Should error (bad block structure), not panic
    assert!(result.is_err());
}

#[test]
fn connect_all_ff_256() {
    let mut state = empty_state();
    let chain_id = [0u8; 32];
    let _ = connect_block_basic_in_memory_at_height(
        &[0xFF; 256],
        None,
        None,
        1,
        None,
        &mut state,
        chain_id,
    );
}

// =============================================================
// With constraints — no panic
// =============================================================

#[test]
fn connect_with_prev_hash_constraint() {
    let mut state = empty_state();
    let chain_id = [0u8; 32];
    let prev_hash = [0x01u8; 32];
    let _ = connect_block_basic_in_memory_at_height(
        &[0u8; 256],
        Some(prev_hash),
        None,
        1,
        None,
        &mut state,
        chain_id,
    );
}

#[test]
fn connect_with_target_constraint() {
    let mut state = empty_state();
    let chain_id = [0u8; 32];
    let target = [0xFF; 32];
    let _ = connect_block_basic_in_memory_at_height(
        &[0u8; 256],
        None,
        Some(target),
        1,
        None,
        &mut state,
        chain_id,
    );
}

#[test]
fn connect_with_both_constraints() {
    let mut state = empty_state();
    let chain_id = [0u8; 32];
    let prev_hash = [0xAA; 32];
    let target = [0xFF; 32];
    let _ = connect_block_basic_in_memory_at_height(
        &[0u8; 256],
        Some(prev_hash),
        Some(target),
        1,
        None,
        &mut state,
        chain_id,
    );
}

// =============================================================
// Height boundaries — no panic
// =============================================================

#[test]
fn connect_height_zero() {
    let mut state = empty_state();
    let chain_id = [0u8; 32];
    let _ = connect_block_basic_in_memory_at_height(
        &[0u8; 256],
        None,
        None,
        0,
        None,
        &mut state,
        chain_id,
    );
}

#[test]
fn connect_height_max() {
    let mut state = empty_state();
    let chain_id = [0u8; 32];
    let _ = connect_block_basic_in_memory_at_height(
        &[0u8; 256],
        None,
        None,
        u64::MAX,
        None,
        &mut state,
        chain_id,
    );
}

// =============================================================
// With prev_timestamps — no panic
// =============================================================

#[test]
fn connect_with_prev_timestamps() {
    let mut state = empty_state();
    let chain_id = [0u8; 32];
    let timestamps = [100u64, 200, 300, 400, 500, 600, 700, 800, 900, 1000, 1100];
    let _ = connect_block_basic_in_memory_at_height(
        &[0u8; 256],
        None,
        None,
        12,
        Some(&timestamps),
        &mut state,
        chain_id,
    );
}

#[test]
fn connect_with_empty_timestamps() {
    let mut state = empty_state();
    let chain_id = [0u8; 32];
    let _ = connect_block_basic_in_memory_at_height(
        &[0u8; 256],
        None,
        None,
        1,
        Some(&[]),
        &mut state,
        chain_id,
    );
}

// =============================================================
// Non-empty chainstate — no panic
// =============================================================

#[test]
fn connect_with_existing_utxos() {
    let mut utxos = HashMap::new();
    utxos.insert(
        Outpoint {
            txid: [0x01; 32],
            vout: 0,
        },
        UtxoEntry {
            value: 50_000_000,
            covenant_type: 0x0000,
            covenant_data: vec![0x01; 33],
            creation_height: 1,
            created_by_coinbase: true,
        },
    );
    let mut state = InMemoryChainState {
        utxos,
        already_generated: 50_000_000,
    };
    let chain_id = [0u8; 32];
    let _ = connect_block_basic_in_memory_at_height(
        &[0u8; 256],
        None,
        None,
        2,
        None,
        &mut state,
        chain_id,
    );
}

// =============================================================
// Determinism: same input → same error
// =============================================================

#[test]
fn connect_deterministic_error() {
    let buf = [0x42u8; 512];
    let chain_id = [0u8; 32];

    let mut state1 = empty_state();
    let r1 =
        connect_block_basic_in_memory_at_height(&buf, None, None, 1, None, &mut state1, chain_id);

    let mut state2 = empty_state();
    let r2 =
        connect_block_basic_in_memory_at_height(&buf, None, None, 1, None, &mut state2, chain_id);

    assert_eq!(r1.is_ok(), r2.is_ok());
    if let (Err(e1), Err(e2)) = (&r1, &r2) {
        assert_eq!(e1.code, e2.code);
    }
}

// =============================================================
// Incremental lengths — no panic
// =============================================================

#[test]
fn connect_incremental_lengths_no_panic() {
    let chain_id = [0u8; 32];
    for len in 0..=300 {
        let mut state = empty_state();
        let buf = vec![0u8; len];
        let _ = connect_block_basic_in_memory_at_height(
            &buf, None, None, 1, None, &mut state, chain_id,
        );
    }
}

// =============================================================
// Various chain_id values — no panic
// =============================================================

#[test]
fn connect_various_chain_ids() {
    for byte in [0x00u8, 0x01, 0x42, 0xFF] {
        let mut state = empty_state();
        let chain_id = [byte; 32];
        let _ = connect_block_basic_in_memory_at_height(
            &[0u8; 256],
            None,
            None,
            1,
            None,
            &mut state,
            chain_id,
        );
    }
}

// =============================================================
// State not mutated on error
// =============================================================

#[test]
fn connect_error_preserves_state() {
    let mut state = empty_state();
    state.already_generated = 12345;
    let chain_id = [0u8; 32];

    let result = connect_block_basic_in_memory_at_height(
        &[0u8; 10], // too short → error
        None, None, 1, None, &mut state, chain_id,
    );

    assert!(result.is_err());
    // State should not be modified on parse error
    assert_eq!(state.already_generated, 12345);
    assert!(state.utxos.is_empty());
}
