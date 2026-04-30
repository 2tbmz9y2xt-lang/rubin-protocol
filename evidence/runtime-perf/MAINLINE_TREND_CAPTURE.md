# Mainline Runtime Perf Trend Capture

Task: `Q-PERF-MAINLINE-TREND-CAPTURE-01`

Issue: `rubin-protocol#1362`

Linear mirror: `RUB-131`

Scope: preserve reconstructable mainline and nightly benchmark artifacts so
future advisory performance thresholds can be based on observed trend data, not
single-run guesses.

## Contract

Trend capture is informational only. It does not introduce merge-blocking
performance gates, hard thresholds, runtime optimizations, or benchmark rewrites.

Artifacts are built by:

- `scripts/runtime_perf/build_runtime_perf_trend.py`

The script reads existing metric JSON files when present:

- `go_metrics.json`
- `rust_metrics.json`
- `combined_load_metrics.json`

Missing metric files are recorded in `source_runs[*].missing_suites` and do not
become a regression decision.

Metric JSON files that exist but do not contain any collectable metric rows are
recorded in `source_runs[*].invalid_suites` and are not listed in
`suites_present`.

## Artifact Retention

The runtime-perf and combined-load workflows upload trend artifacts with
`retention-days: 90`.

Workflow artifacts keep the raw benchmark outputs and parsed JSON metrics needed
to reconstruct trend rows by run id, attempt, workflow, ref, SHA, and event.

## Trend Schema

`trend.json` has `schema_version: 1` and includes:

- `source_runs`: artifact directory plus GitHub run metadata.
- `source_runs[*].missing_suites`: metric JSON files that were absent.
- `source_runs[*].invalid_suites`: metric JSON files that were present but did
  not contain collectable metric rows.
- `low_noise_benchmark_candidates`: the documented candidate set for future
  low-noise analysis.
- `required_trend_fields`: `sample_count`, `median`, `p90`, `variance`,
  `samples`.
- `suites`: benchmark metrics grouped by suite, benchmark, and metric name.

Each metric row preserves raw `samples` so median, p90, and variance can be
recomputed later.

For a single run, `median` and `p90` equal the only sample and `variance` is
`0.0`. That is artifact capture only, not threshold calibration.

## Selected Low-Noise Candidates

These are candidate benchmark families for future trend analysis. They are not
thresholds and are not yet calibrated regression gates.

Go:

- `BenchmarkMempoolAddTx` / `ns_per_op`: in-memory standard mempool admission.
- `BenchmarkMempoolRelayMetadata` / `ns_per_op`: in-memory relay metadata.
- `BenchmarkCloneChainState` / `ns_per_op`: deterministic chain-state clone.

Rust:

- `rubin_node_txpool/admit` / `ns_per_op`: in-memory txpool admission.
- `rubin_node_txpool/relay_metadata` / `ns_per_op`: in-memory relay metadata.
- `rubin_node_chainstate_clone` / `ns_per_op`: deterministic chain-state clone.

Combined load:

- `BenchmarkValidateBlockBasicCombinedLoad` / `ns_per_op`: existing documented
  mixed-load nightly benchmark.

## Workflow Surfaces

`.github/workflows/runtime-perf-guardrails.yml` now also runs on pushes to
`main` so mainline runtime-perf artifacts are captured after merges. Pull
request runtime-perf remains informational and does not compare against hard
thresholds.

`.github/workflows/combined-load-nightly.yml` continues its nightly/manual
combined-load benchmark and adds `trend.json` / `trend.md` to the same artifact
bundle.

## Future Threshold Path

A future advisory threshold task must consume multiple retained mainline/nightly
artifacts and justify each selected benchmark with observed median, p90,
variance, and sample count. This PR intentionally does not choose those
thresholds.
