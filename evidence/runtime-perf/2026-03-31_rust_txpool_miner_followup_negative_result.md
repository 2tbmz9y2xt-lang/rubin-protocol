# Rust Txpool/Miner Follow-up Negative Result

Task: `Q-PERF-RUST-TXPOOL-MINER-FOLLOWUP-01`

Issue: `rubin-protocol#1049`

Baseline: `origin/main@98fc219f695c12975cd36aeaef8f425ca7c4b27d`

## Verdict

`not justified by numbers`

The current runtime baseline does not show an isolated dominant hotspot inside
the allowed `txpool.rs` / `miner.rs` scope that would justify a separate code
optimization slice right now.

## Benchmark Command

```bash
cd /Users/gpt/Documents/rubin-protocol/clients/rust
cargo bench -p rubin-node --bench runtime_baseline -- --noplot --sample-size 10 --measurement-time 2
```

## Observed Results

- `txpool/admit`: `139.64-143.24 µs`
- `relay_metadata`: `139.47-142.01 µs`
- `chainstate_clone`: `6.89-7.05 µs`
- `sync/apply_genesis`: `687.05-844.54 µs`
- `sync/disconnect_tip_after_genesis`: `407.99-448.10 µs`
- `miner_mine_one`: `867.20-969.29 µs`

## Decision

`miner_mine_one` is still dominated mostly by out-of-scope sync/apply work.
Within the allowed `txpool.rs` / `miner.rs` scope, the benchmark evidence does
not currently justify a new optimization patch.

This slice should remain evidence-only until a future baseline isolates a real
`txpool` or `miner` hotspot inside scope.
