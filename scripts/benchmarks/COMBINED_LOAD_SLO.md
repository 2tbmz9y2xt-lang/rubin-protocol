# Combined-Load Benchmark (Unknown Suite + DA) SLO

Purpose: provide a repeatable benchmark/evidence lane for mixed load:

- non-native witness processing (`suite_id=0x02`, unknown suite),
- DA-filled block parsing/validation (`tx_kind=0x01/0x02` with chunk payloads),
- block-basic validation path as implemented in Go consensus.

## Scenario

Benchmark target:

- `BenchmarkValidateBlockBasicCombinedLoad`

Default profile (configurable via environment variables):

- `RUBIN_COMBINED_LOAD_UNKNOWN_SUITE_TXS=8`
- `RUBIN_COMBINED_LOAD_DA_CHUNKS=32`
- `RUBIN_COMBINED_LOAD_CHUNK_BYTES=65536`
- `RUBIN_COMBINED_LOAD_UNKNOWN_SUITE_SIG_BYTES=49856`

## Metrics

Collected from Go benchmark output:

- `ns/op`
- `B/op`
- `allocs/op`

SLO thresholds are stored in:

- `scripts/benchmarks/combined_load_slo.json`

The SLO is advisory. A threshold breach is emitted as `status: "warn"` in the
parsed JSON and workflow summary, but it must not fail the nightly workflow.
Missing benchmark data is emitted as `status: "no_data"` instead of being
classified as a regression.

Current threshold calibration remains intentionally broad. The nightly workflow
preserves `trend.json` / `trend.md` so a later task can tighten thresholds from
retained multi-run median, p90, and variance data.

## Evidence Lane

Nightly/manual workflow:

- `.github/workflows/combined-load-nightly.yml`

Artifacts:

- `combined_load_benchmark.txt`
- `combined_load_metrics.json`
- `combined_load_summary.md`

These artifacts MUST be kept with workflow run metadata for audit evidence.
