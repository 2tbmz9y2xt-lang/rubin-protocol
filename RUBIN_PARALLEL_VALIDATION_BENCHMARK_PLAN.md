# RUBIN Parallel Validation — Benchmark Plan

## Goal

Measure practical performance gain while preserving deterministic correctness.

## Workload Classes

1. signature-heavy
2. UTXO-heavy
3. covenant-heavy
4. DA-heavy
5. mixed realistic
6. adversarial flood

## Hardware Profiles

- 4 core / 16 GB
- 8 core / 32 GB
- 16 core / 64 GB
- 32 core / 128 GB

## Required Artifacts

- `benchmark_results.json`
- `benchmark_summary.md`
- `benchmark_env.json`

## Required Metrics

- throughput (`tx/s`)
- block validation latency
- signature verification throughput
- UTXO lookup latency
- CPU and memory envelope
- commit stage latency

## Merge Gate Thresholds

- 1-worker mode regression <= 5%
- positive gain on 8-core mixed workload
- positive gain on 16-core signature-heavy workload
- deterministic replay equality remains 100%

## Reporting Rules

- separate cold-cache and warm-cache runs;
- pin dataset IDs and git SHA;
- record runtime flags and worker count in `benchmark_env.json`.
