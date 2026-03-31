#![allow(dead_code)]

#[path = "../benches/bench_support.rs"]
mod bench_support;

use std::path::PathBuf;

use rubin_node::{devnet_genesis_chain_id, TxPool};

fn runtime_perf_guardrail_doc_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../../evidence/runtime-perf/RUST_RUNTIME_PERF_GUARDRAILS.md")
}

#[test]
fn runtime_baseline_txpool_fixture_stays_parity_safe() {
    let (state, raw) = bench_support::fresh_txpool_fixture();
    let state_before = state.clone();

    let mut pool = TxPool::new();
    let txid = pool
        .admit(&raw, &state, None, devnet_genesis_chain_id())
        .expect("admit fixture tx");
    let meta = pool
        .relay_metadata_for_bytes(&raw, &state, None, devnet_genesis_chain_id())
        .expect("relay metadata for fixture tx");

    assert_eq!(meta.size, raw.len());
    assert!(
        meta.fee > 0,
        "fixture relay metadata should keep a non-zero fee"
    );
    assert_eq!(pool.len(), 1, "benchmark fixture must stay admissible");
    assert_ne!(txid, [0u8; 32], "admitted txid should not be zeroed");
    assert_eq!(
        state, state_before,
        "runtime baseline txpool fixture must not mutate caller chainstate"
    );
}

#[test]
fn runtime_baseline_undo_fixture_round_trips_prev_state() {
    let fixture = bench_support::large_block_undo_fixture();
    let expected_digest = fixture.prev_state.state_digest();
    let mut restored = fixture.connected_state.clone();

    restored
        .disconnect_block(&fixture.block_bytes, &fixture.undo)
        .expect("disconnect benchmark fixture");

    assert_eq!(
        restored, fixture.prev_state,
        "disconnect benchmark fixture must restore the exact previous state"
    );
    assert_eq!(
        restored.state_digest(),
        expected_digest,
        "disconnect benchmark fixture must preserve the canonical state digest"
    );
}

#[test]
fn runtime_perf_guardrail_doc_matches_bench_contract() {
    let doc = std::fs::read_to_string(runtime_perf_guardrail_doc_path())
        .expect("read runtime perf guardrail doc");

    assert!(
        doc.contains(bench_support::RUNTIME_BASELINE_BENCH_COMMAND),
        "guardrail doc must pin the canonical Rust runtime baseline command"
    );
    for target in bench_support::RUNTIME_BASELINE_EVIDENCE_TARGETS {
        assert!(
            doc.contains(target),
            "guardrail doc must mention benchmark target {target}"
        );
    }
}
