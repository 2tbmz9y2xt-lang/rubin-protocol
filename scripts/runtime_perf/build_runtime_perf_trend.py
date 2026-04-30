#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import math
import statistics
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

LOW_NOISE_CANDIDATES = [
    {
        "suite": "go",
        "benchmark": "BenchmarkMempoolAddTx",
        "metric": "ns_per_op",
        "reason": "in-memory standard mempool admission path",
    },
    {
        "suite": "go",
        "benchmark": "BenchmarkMempoolRelayMetadata",
        "metric": "ns_per_op",
        "reason": "in-memory relay metadata path",
    },
    {
        "suite": "go",
        "benchmark": "BenchmarkCloneChainState",
        "metric": "ns_per_op",
        "reason": "deterministic chain-state clone path",
    },
    {
        "suite": "rust",
        "benchmark": "rubin_node_txpool/admit",
        "metric": "ns_per_op",
        "reason": "in-memory Rust txpool admission path",
    },
    {
        "suite": "rust",
        "benchmark": "rubin_node_txpool/relay_metadata",
        "metric": "ns_per_op",
        "reason": "in-memory Rust relay metadata path",
    },
    {
        "suite": "rust",
        "benchmark": "rubin_node_chainstate_clone",
        "metric": "ns_per_op",
        "reason": "deterministic Rust chain-state clone path",
    },
    {
        "suite": "combined_load",
        "benchmark": "BenchmarkValidateBlockBasicCombinedLoad",
        "metric": "ns_per_op",
        "reason": "single documented mixed-load benchmark with existing nightly artifact lane",
    },
]

METRIC_FILES = {
    "go": "go_metrics.json",
    "rust": "rust_metrics.json",
    "combined_load": "combined_load_metrics.json",
}

DEFAULT_METRICS = {
    "go": ["ns_per_op", "b_per_op", "allocs_per_op"],
    "rust": ["ns_per_op"],
    "combined_load": ["ns_per_op", "b_per_op", "allocs_per_op"],
}


def utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def load_json(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8", errors="strict"))


def percentile_nearest_rank(values: list[float], percentile: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    rank = max(1, math.ceil((percentile / 100.0) * len(ordered)))
    return ordered[min(rank - 1, len(ordered) - 1)]


def summarize_values(samples: list[dict[str, Any]]) -> dict[str, Any]:
    values = [float(sample["value"]) for sample in samples]
    return {
        "sample_count": len(values),
        "median": statistics.median(values) if values else None,
        "p90": percentile_nearest_rank(values, 90.0),
        "variance": statistics.pvariance(values) if len(values) > 1 else 0.0 if values else None,
        "samples": samples,
    }


def run_metadata(args: argparse.Namespace, run_dir: Path) -> dict[str, str | None]:
    return {
        "artifact_dir": str(run_dir),
        "run_id": args.run_id,
        "run_attempt": args.run_attempt,
        "run_number": args.run_number,
        "sha": args.sha,
        "ref": args.ref,
        "event_name": args.event_name,
        "workflow": args.workflow,
        "generated_at": args.generated_at,
    }


def collect_go_or_rust(
    suite: str,
    payload: dict[str, Any],
    metadata: dict[str, str | None],
    trend: dict[str, dict[str, dict[str, list[dict[str, Any]]]]],
) -> None:
    metrics = payload.get("metrics")
    if not isinstance(metrics, dict):
        return
    for benchmark, metric_values in metrics.items():
        if not isinstance(metric_values, dict):
            continue
        for metric_name in DEFAULT_METRICS[suite]:
            value = metric_values.get(metric_name)
            if value is None:
                continue
            trend.setdefault(suite, {}).setdefault(benchmark, {}).setdefault(metric_name, []).append(
                {"value": float(value), **metadata}
            )


def collect_combined_load(
    payload: dict[str, Any],
    metadata: dict[str, str | None],
    trend: dict[str, dict[str, dict[str, list[dict[str, Any]]]]],
) -> None:
    benchmark = payload.get("benchmark")
    if not isinstance(benchmark, str) or not benchmark:
        return
    for metric_name in DEFAULT_METRICS["combined_load"]:
        value = payload.get(metric_name)
        if value is None:
            continue
        trend.setdefault("combined_load", {}).setdefault(benchmark, {}).setdefault(metric_name, []).append(
            {"value": float(value), **metadata}
        )


def build_trend(args: argparse.Namespace) -> dict[str, Any]:
    trend_samples: dict[str, dict[str, dict[str, list[dict[str, Any]]]]] = {}
    source_runs: list[dict[str, Any]] = []

    for run_dir_arg in args.run_dir:
        run_dir = Path(run_dir_arg)
        metadata = run_metadata(args, run_dir)
        suites_present: list[str] = []
        missing_suites: list[str] = []

        for suite, filename in METRIC_FILES.items():
            path = run_dir / filename
            try:
                payload = load_json(path)
            except json.JSONDecodeError as exc:
                raise SystemExit(f"ERROR: malformed metric JSON: {path}: {exc}") from exc
            if payload is None:
                missing_suites.append(suite)
                continue
            suites_present.append(suite)
            if suite in {"go", "rust"}:
                collect_go_or_rust(suite, payload, metadata, trend_samples)
            elif suite == "combined_load":
                collect_combined_load(payload, metadata, trend_samples)

        source_runs.append(
            {
                **metadata,
                "suites_present": suites_present,
                "missing_suites": missing_suites,
            }
        )

    suites: dict[str, dict[str, dict[str, Any]]] = {}
    for suite, benchmarks in sorted(trend_samples.items()):
        suites[suite] = {}
        for benchmark, metrics in sorted(benchmarks.items()):
            suites[suite][benchmark] = {
                metric_name: summarize_values(samples)
                for metric_name, samples in sorted(metrics.items())
            }

    return {
        "schema_version": 1,
        "generated_at": args.generated_at,
        "source_runs": source_runs,
        "required_trend_fields": ["sample_count", "median", "p90", "variance", "samples"],
        "low_noise_benchmark_candidates": LOW_NOISE_CANDIDATES,
        "threshold_policy": "informational_only_no_thresholds",
        "suites": suites,
    }


def render_summary(doc: dict[str, Any]) -> str:
    lines = [
        "# Runtime Perf Trend Capture",
        "",
        "This artifact is informational and does not define regression thresholds.",
        "",
        f"- schema_version: `{doc['schema_version']}`",
        f"- generated_at: `{doc['generated_at']}`",
        f"- source_runs: `{len(doc['source_runs'])}`",
        "- required trend fields: `sample_count`, `median`, `p90`, `variance`, `samples`",
        "",
        "## Low-noise benchmark candidates",
        "",
    ]
    for candidate in doc["low_noise_benchmark_candidates"]:
        lines.append(
            f"- `{candidate['suite']}` / `{candidate['benchmark']}` / `{candidate['metric']}`: {candidate['reason']}"
        )
    lines.extend(["", "## Captured metrics", ""])
    suites = doc["suites"]
    if not suites:
        lines.extend(["No metrics were parsed. Missing suites are recorded in `source_runs`.", ""])
    for suite, benchmarks in suites.items():
        lines.extend([f"### {suite}", ""])
        for benchmark, metrics in benchmarks.items():
            for metric_name, summary in metrics.items():
                lines.append(
                    f"- `{benchmark}` `{metric_name}`: samples={summary['sample_count']} "
                    f"median={summary['median']} p90={summary['p90']} variance={summary['variance']}"
                )
        lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Build reconstructable runtime perf trend artifacts.")
    parser.add_argument("--run-dir", action="append", required=True, help="Artifact directory containing metric JSON files.")
    parser.add_argument("--output", required=True, help="Path to write trend JSON.")
    parser.add_argument("--summary", required=True, help="Path to write markdown summary.")
    parser.add_argument("--run-id", default=None)
    parser.add_argument("--run-attempt", default=None)
    parser.add_argument("--run-number", default=None)
    parser.add_argument("--sha", default=None)
    parser.add_argument("--ref", default=None)
    parser.add_argument("--event-name", default=None)
    parser.add_argument("--workflow", default=None)
    parser.add_argument("--generated-at", default=utc_now())
    args = parser.parse_args()

    doc = build_trend(args)
    output_path = Path(args.output)
    summary_path = Path(args.summary)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    summary_path.write_text(render_summary(doc), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
