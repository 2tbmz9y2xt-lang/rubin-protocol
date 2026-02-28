# Combined-Load Benchmark (SLH + DA) SLO

Purpose: provide a repeatable benchmark/evidence lane for mixed load:

- SLH-heavy witness processing (`SUITE_ID_SLH_DSA_SHAKE_256F`),
- DA-filled block parsing/validation (`tx_kind=0x01/0x02` with chunk payloads),
- block-basic validation path as implemented in Go consensus.

## Scenario

Benchmark target:

- `BenchmarkValidateBlockBasicCombinedLoad`

Default profile (configurable via environment variables):

- `RUBIN_COMBINED_LOAD_SLH_TXS=8`
- `RUBIN_COMBINED_LOAD_DA_CHUNKS=32`
- `RUBIN_COMBINED_LOAD_CHUNK_BYTES=65536`
- `RUBIN_COMBINED_LOAD_SLH_SIG_BYTES=49856`

## Metrics

Collected from Go benchmark output:

- `ns/op`
- `B/op`
- `allocs/op`

SLO thresholds are stored in:

- `scripts/benchmarks/combined_load_slo.json`

## Evidence Lane

Nightly/manual workflow:

- `.github/workflows/combined-load-nightly.yml`

Artifacts:

- `combined_load_benchmark.txt`
- `combined_load_metrics.json`

Both artifacts MUST be kept with workflow run metadata for audit evidence.
