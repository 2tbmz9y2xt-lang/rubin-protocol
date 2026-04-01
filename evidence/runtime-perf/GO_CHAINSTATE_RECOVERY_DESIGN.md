# Go Chainstate Recovery Design Note

Task: `Q-PERF-GO-RECOVERY-DESIGN-01`

Issue: `rubin-protocol#1052`

Scope: measure the current Go chainstate recovery costs and document the next
storage/recovery direction without changing consensus semantics.

## Canonical measurement command

```bash
scripts/benchmarks/run_go_chainstate_recovery_bench.sh
```

Raw output:

- [`go-chainstate-recovery/raw.txt`](./go-chainstate-recovery/raw.txt)
- [`go-chainstate-recovery/parsed.json`](./go-chainstate-recovery/parsed.json)

## Current measurements

Environment from the raw run:

- host: Apple M4 Max
- `go test ./node -run "^$" -bench "^(BenchmarkChainStateSave|BenchmarkChainStateLoad|BenchmarkReconcileChainState)$" -benchmem -count=1`

Measured points:

| Target | ns/op | B/op | allocs/op |
|--------|------:|-----:|----------:|
| `BenchmarkChainStateSave/utxos_4096` | `4,925,552` | `5,267,255` | `16,423` |
| `BenchmarkChainStateSave/utxos_8192` | `10,201,125` | `10,294,602` | `32,805` |
| `BenchmarkChainStateLoad/utxos_4096` | `5,530,935` | `3,769,672` | `16,435` |
| `BenchmarkChainStateLoad/utxos_8192` | `11,587,776` | `7,997,119` | `32,838` |
| `BenchmarkReconcileChainState/noop_tip_32_blocks` | `1,163,321` | `160,487` | `1,488` |
| `BenchmarkReconcileChainState/replay_32_blocks` | `5,192,942` | `1,010,021` | `7,685` |

## What the numbers mean

- current JSON snapshot save/load cost scales close to linearly with UTXO count;
- moving from `4096` to `8192` UTXOs roughly doubles both CPU time and allocation
  pressure for `Save` and `Load`;
- a `32`-block canonical replay gap already costs about the same wall-clock time
  as saving or loading a `4096`-UTXO snapshot;
- the current model is safe and simple, but it pays twice:
  - full JSON snapshot cost on persistence/reload;
  - linear replay cost when the persisted snapshot lags the canonical tip.

## Recommended next direction

Recommended storage/recovery model:

1. keep consensus state semantics unchanged;
2. keep the current JSON snapshot reader as a legacy fallback during migration;
3. add a binary snapshot format for the hot recovery path;
4. append a compact canonical journal after each accepted block;
5. on startup/recovery:
   - load the newest binary snapshot;
   - replay the journal suffix;
   - fall back to full canonical replay only when the snapshot/journal pair is
     missing or invalid.

## Why this direction

Pros:

- lowers startup/recovery latency without changing block validation rules;
- reduces JSON marshal/unmarshal cost on the hot recovery path;
- keeps replay bounded to the journal suffix instead of the full missing tip gap;
- preserves fail-closed recovery because canonical replay still exists as the
  final fallback path.

Costs:

- more code in storage/recovery plumbing;
- new on-disk format versioning and migration logic;
- extra CI/test surface for snapshot/journal compatibility;
- more recovery-path invariants to keep in Go/Rust parity review.

## Explicit non-goals for the next lane

- no consensus rule change;
- no wire-format change;
- no storage migration in the same PR that introduces the design note;
- no claim that the binary snapshot path is ready before dedicated recovery
  validation and rollback tests exist.
