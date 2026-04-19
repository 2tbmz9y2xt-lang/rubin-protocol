//! G.9 / sub-issue #1248: assert that the Rust consensus path parses each
//! block exactly ONCE per `apply_block`-style call (`connect_block_*`),
//! mirroring the Go single-parse pattern in
//! `clients/go/consensus/connect_block_inmem.go` (`parseAndValidateBlockBasicWithContextAtHeight`).
//!
//! Uses the test-only `PARSE_BLOCK_BYTES_CALL_COUNT` counter in
//! `block_basic.rs`. The counter is `thread_local!`, so each test runs
//! against its own isolated counter — no cross-test contamination under
//! `cargo test`'s default parallel runner. Tests still snapshot the
//! counter at entry and assert the delta (rather than asserting an
//! absolute value) so any ambient parse calls earlier in the same
//! thread (e.g. from helper fixtures) do not affect the assertion.

use super::*;

use crate::block_basic::PARSE_BLOCK_BYTES_CALL_COUNT;
use crate::connect_block_inmem::InMemoryChainState;

fn parse_count() -> u64 {
    PARSE_BLOCK_BYTES_CALL_COUNT.with(|c| c.get())
}

/// Build the same coinbase-only block used by
/// `connect_block_coinbase_only_at_height0_succeeds` so we have a
/// happy-path block whose parse cost we can measure.
fn happy_path_block_bytes() -> (Vec<u8>, [u8; 32], [u8; 32]) {
    let prev = [0u8; 32];
    let target = [0xffu8; 32];
    let coinbase = coinbase_with_witness_commitment(0, &[]);
    let (_cb, coinbase_txid, _cbw, _cbn) = parse_tx(&coinbase).expect("parse coinbase");
    let root = merkle_root_txids(&[coinbase_txid]).expect("merkle root");
    let block = build_block_bytes(prev, root, target, 1, &[coinbase]);
    (block, prev, target)
}

/// G.9 happy path: `connect_block_basic_in_memory_at_height` parses the
/// block exactly once, even though it internally still validates basic
/// rules (which used to call `parse_block_bytes` a second time).
#[test]
fn connect_block_basic_in_memory_parses_once_on_happy_path() {
    let (block, prev, target) = happy_path_block_bytes();
    let mut state = InMemoryChainState {
        utxos: HashMap::new(),
        already_generated: 0,
    };

    let before = parse_count();
    let _summary = crate::connect_block_basic_in_memory_at_height(
        &block,
        Some(prev),
        Some(target),
        0,
        None,
        &mut state,
        ZERO_CHAIN_ID,
    )
    .expect("connect_block_basic_in_memory_at_height happy path");
    let delta = parse_count() - before;

    assert_eq!(
        delta, 1,
        "G.9: connect_block_basic_in_memory_at_height must parse the block \
         exactly once per apply_block (observed {delta})"
    );
}

/// G.9 error path: a connect call that fails inside basic validation must
/// NOT have parsed the block twice. With the dedup in place the parse
/// count is exactly 1 (parse, then validate-on-parsed fails); before the
/// fix it was 1 (validate failed before the second parse) — but the
/// stricter property the slice-protocol locks is "≤ 1 parse on the error
/// path", which we still want to assert as a regression guard.
#[test]
fn connect_block_basic_in_memory_does_not_double_parse_on_validation_error() {
    let (block, _prev, target) = happy_path_block_bytes();
    let mut state = InMemoryChainState {
        utxos: HashMap::new(),
        already_generated: 0,
    };

    // Force a stateless-validation rejection: pass a wrong expected_prev_hash
    // so validate_header_commitments fails after parse, before connect's
    // tx-application loop.
    let wrong_prev = [0xAAu8; 32];

    let before = parse_count();
    let err = crate::connect_block_basic_in_memory_at_height(
        &block,
        Some(wrong_prev),
        Some(target),
        0,
        None,
        &mut state,
        ZERO_CHAIN_ID,
    )
    .expect_err("expected stateless validation to reject wrong prev_hash");
    let delta = parse_count() - before;

    // Must be a header / commitment class rejection, not a parse failure
    // (a parse failure would short-circuit at the very first parse and
    // hide a regression where a second parse was added later).
    assert_ne!(
        err.code,
        ErrorCode::BlockErrParse,
        "G.9 setup error: expected non-parse rejection, got BlockErrParse: {err:?}"
    );
    assert!(
        delta <= 1,
        "G.9: connect_block_basic_in_memory_at_height parsed the block \
         {delta} times on the error path; must be ≤ 1"
    );
}

/// G.9 reorg/disconnect path: applying the same block again (e.g. after a
/// reorg revert) must still parse exactly once per call, with no leaked
/// parsed state across calls.
#[test]
fn connect_block_basic_in_memory_parses_once_on_reapply() {
    let (block, prev, target) = happy_path_block_bytes();
    let mut state1 = InMemoryChainState {
        utxos: HashMap::new(),
        already_generated: 0,
    };
    let mut state2 = InMemoryChainState {
        utxos: HashMap::new(),
        already_generated: 0,
    };

    let before = parse_count();
    let _ = crate::connect_block_basic_in_memory_at_height(
        &block,
        Some(prev),
        Some(target),
        0,
        None,
        &mut state1,
        ZERO_CHAIN_ID,
    )
    .expect("first apply");
    let _ = crate::connect_block_basic_in_memory_at_height(
        &block,
        Some(prev),
        Some(target),
        0,
        None,
        &mut state2,
        ZERO_CHAIN_ID,
    )
    .expect("second apply (reapply / reorg)");
    let delta = parse_count() - before;

    assert_eq!(
        delta, 2,
        "G.9: two consecutive connect_block calls must parse exactly twice \
         total (1 parse per apply_block); observed {delta}"
    );
}

/// G.9 fees variant: `validate_block_basic_with_context_and_fees_at_height`
/// used to call `validate_block_basic_with_context_at_height` (1 parse)
/// and then `parse_block_bytes` again (2nd parse) before checking the
/// coinbase value bound. After the fix it parses exactly once.
#[test]
fn validate_block_basic_with_context_and_fees_at_height_parses_once() {
    let (block, prev, target) = happy_path_block_bytes();

    let before = parse_count();
    let _ = crate::validate_block_basic_with_context_and_fees_at_height(
        &block,
        Some(prev),
        Some(target),
        0,
        None,
        0,
        0,
    )
    .expect("validate_block_basic_with_context_and_fees_at_height happy path");
    let delta = parse_count() - before;

    assert_eq!(
        delta, 1,
        "G.9: validate_block_basic_with_context_and_fees_at_height must parse \
         the block exactly once (observed {delta})"
    );
}
