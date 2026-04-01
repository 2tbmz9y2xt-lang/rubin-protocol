# Rust Runtime Perf Guardrails

Task: `Q-PERF-RUST-PARITY-GUARDRAILS-01`

Issue: `rubin-protocol#1050`

Scope: Rust-only runtime/perf guardrails for future perf PRs. No spec change,
no Go drift, no CI rewrite in this lane.

## Canonical benchmark command

```bash
cargo bench --manifest-path clients/rust/Cargo.toml -p rubin-node --bench runtime_baseline -- --noplot --sample-size 10 --measurement-time 2
```

## Required evidence targets

Every future Rust perf PR touching the `rubin-node` runtime hot paths must
report before/after numbers for the affected subset of these stable targets:

- `rubin_node_txpool/admit`
- `rubin_node_txpool/relay_metadata`
- `rubin_node_chainstate_clone`
- `rubin_node_sync_chain_state_snapshot`
- `rubin_node_sync/apply_genesis`
- `rubin_node_sync/disconnect_tip_after_genesis`
- `rubin_node_undo/build_large_block`
- `rubin_node_undo/disconnect_large_block`
- `rubin_node_miner_mine_one`

## Parity-safe guardrail

Perf PRs are not allowed to trade away validation/runtime correctness.
Before merge, the PR must show:

- targeted regression tests for the Rust runtime path it touched;
- evidence that the benchmark fixture still exercises a parity-safe path;
- measured deltas for the affected stable benchmark IDs;
- an explicit negative-result note instead of speculative code churn when the
  numbers do not justify an optimization.

## Current fixture-backed guardrails

- txpool fixture remains admissible and relay-metadata-safe without mutating the
  caller chainstate;
- large undo fixture still disconnects back to the exact previous chainstate;
- this document is kept in sync with the benchmark contract by a Rust test.
