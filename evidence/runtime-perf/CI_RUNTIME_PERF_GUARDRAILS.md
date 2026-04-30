# CI Runtime Perf Guardrails

Task: `Q-PERF-CI-GUARDRAILS-01`

Issue: `rubin-protocol#1053`

Scope: expose non-blocking runtime benchmark visibility for the current Go/Rust
hot paths and publish base-vs-head deltas as CI artifacts.

## Current contract

The CI lane must:

- run on pull requests that touch `clients/go/node/**`,
  `clients/rust/crates/rubin-node/**`, or the runtime perf guardrail tooling;
- benchmark the selected Go and Rust runtime hot paths on the same runner for
  both PR base and PR head;
- upload raw artifacts plus parsed metrics;
- write a markdown summary into `GITHUB_STEP_SUMMARY`;
- stay informational only while the baseline stabilizes.

## Selected benchmark set

Go:

- `BenchmarkMempoolAddTx`
- `BenchmarkMempoolRelayMetadata`
- `BenchmarkMinerBuildContext`
- `BenchmarkCloneChainState`
- `BenchmarkCopyUtxoSet`
- `BenchmarkConnectBlockWithCoreExtProfilesAndSuiteContext`
- `BenchmarkConnectBlockParallelSigsWithSuiteContext`

Rust:

- `rubin_node_txpool/admit`
- `rubin_node_txpool/relay_metadata`
- `rubin_node_chainstate_clone`
- `rubin_node_sync_chain_state_snapshot`
- `rubin_node_sync/apply_genesis`
- `rubin_node_sync/disconnect_tip_after_genesis`
- `rubin_node_undo/build_large_block`
- `rubin_node_undo/disconnect_large_block`
- `rubin_node_miner_mine_one`

## Future soft-threshold path

This lane is intentionally non-blocking for now. The next hardening step, if
the project wants it later, is:

1. require several stable runs on `main`;
2. pick only the low-noise subset of benchmarks;
3. define soft thresholds per benchmark family;
4. keep threshold breaches advisory first, not merge-blocking.

## Mainline trend capture

`Q-PERF-MAINLINE-TREND-CAPTURE-01` adds reconstructable trend artifacts for
future low-noise calibration:

- `artifacts/runtime-perf/trend.json`
- `artifacts/runtime-perf/trend.md`

The schema and selected low-noise candidate list are documented in:

- `evidence/runtime-perf/MAINLINE_TREND_CAPTURE.md`

This does not change the current policy: runtime-perf remains informational only
and does not define hard regression thresholds.
