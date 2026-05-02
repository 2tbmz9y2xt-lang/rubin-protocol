#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any


BENCH_LINE_RE = re.compile(
    r"^(?P<name>BenchmarkValidateBlockBasicCombinedLoad(?:-\d+)?)\s+"
    r"(?P<n>\d+)\s+"
    r"(?P<ns>[\d.]+)\s+ns/op\s+"
    r"(?:(?P<mbps>[\d.]+)\s+MB/s\s+)?"
    r"(?P<bop>[\d.]+)\s+B/op\s+"
    r"(?P<allocs>[\d.]+)\s+allocs/op$"
)


METRIC_CHECKS = [
    ("ns_per_op", "max_ns_per_op"),
    ("b_per_op", "max_b_per_op"),
    ("allocs_per_op", "max_allocs_per_op"),
]


def parse_metric(raw: str) -> float:
    return float(raw.strip())


def load_slo(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8", errors="strict"))
    if not isinstance(payload, dict):
        raise ValueError(f"SLO JSON root is {type(payload).__name__}, expected object")
    for key in ["benchmark", "max_ns_per_op", "max_b_per_op", "max_allocs_per_op"]:
        if key not in payload:
            raise ValueError(f"SLO missing required key {key!r}")
    return payload


def no_data_result(slo: dict[str, Any] | None, reason: str) -> dict[str, Any]:
    return {
        "benchmark": slo.get("benchmark") if slo else None,
        "iterations": None,
        "ns_per_op": None,
        "mb_per_s": None,
        "b_per_op": None,
        "allocs_per_op": None,
        "slo": slo,
        "status": "no_data",
        "violations": [],
        "reason": reason,
        "advisory": True,
    }


def parse_benchmark(lines: list[str], slo: dict[str, Any]) -> dict[str, Any]:
    match = None
    for line in lines:
        parsed = BENCH_LINE_RE.match(line.strip())
        if parsed:
            match = parsed
            break
    if match is None:
        return no_data_result(slo, "benchmark line for BenchmarkValidateBlockBasicCombinedLoad not found")

    benchmark_name = match.group("name").split("-")[0]
    result: dict[str, Any] = {
        "benchmark": benchmark_name,
        "iterations": int(match.group("n")),
        "ns_per_op": parse_metric(match.group("ns")),
        "mb_per_s": parse_metric(match.group("mbps")) if match.group("mbps") else None,
        "b_per_op": parse_metric(match.group("bop")),
        "allocs_per_op": parse_metric(match.group("allocs")),
        "slo": slo,
        "status": "pass",
        "violations": [],
        "reason": "combined-load benchmark is within advisory SLO",
        "advisory": True,
    }

    if benchmark_name != slo.get("benchmark"):
        return no_data_result(
            slo,
            f"benchmark mismatch: got {benchmark_name!r}, expected {slo.get('benchmark')!r}",
        )

    for metric_key, limit_key in METRIC_CHECKS:
        limit = float(slo[limit_key])
        value = float(result[metric_key])
        if value > limit:
            result["status"] = "warn"
            result["violations"].append(f"{metric_key}={value} exceeds {limit_key}={limit}")
    if result["status"] == "warn":
        result["reason"] = "combined-load benchmark exceeded advisory SLO; workflow remains non-blocking"
    return result


def render_summary(result: dict[str, Any]) -> str:
    lines = [
        "# Combined-Load Advisory SLO",
        "",
        f"Status: `{result['status']}`.",
        "",
        "This check is advisory only. `warn` and `no_data` do not fail the workflow.",
        "",
        f"- benchmark: `{result.get('benchmark')}`",
        f"- ns_per_op: `{result.get('ns_per_op')}`",
        f"- b_per_op: `{result.get('b_per_op')}`",
        f"- allocs_per_op: `{result.get('allocs_per_op')}`",
        f"- reason: {result.get('reason')}",
        "",
    ]
    violations = result.get("violations") or []
    if violations:
        lines.extend(["## Advisory violations", ""])
        lines.extend(f"- {violation}" for violation in violations)
        lines.append("")
    return "\n".join(lines)


def write_outputs(output_path: Path, summary_path: Path | None, result: dict[str, Any]) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if summary_path is not None:
        summary_path.parent.mkdir(parents=True, exist_ok=True)
        summary_path.write_text(render_summary(result), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Parse Go benchmark output and emit advisory combined-load SLO status.")
    parser.add_argument("--input", required=True, help="Path to go test benchmark stdout file.")
    parser.add_argument("--slo", required=True, help="Path to JSON SLO config.")
    parser.add_argument("--output", required=True, help="Path to write parsed JSON metrics.")
    parser.add_argument("--summary", help="Optional path to write markdown advisory summary.")
    args = parser.parse_args()

    input_path = Path(args.input)
    slo_path = Path(args.slo)
    output_path = Path(args.output)
    summary_path = Path(args.summary) if args.summary else None

    if not slo_path.exists():
        print(f"ERROR: SLO file not found: {slo_path}", file=sys.stderr)
        return 1
    try:
        slo = load_slo(slo_path)
    except (json.JSONDecodeError, ValueError) as exc:
        print(f"ERROR: invalid SLO file {slo_path}: {exc}", file=sys.stderr)
        return 1

    if not input_path.exists():
        result = no_data_result(slo, f"benchmark output not found: {input_path}")
        write_outputs(output_path, summary_path, result)
        print("WARN: combined-load benchmark data unavailable; wrote no_data advisory result.")
        return 0

    lines = input_path.read_text(encoding="utf-8", errors="strict").splitlines()
    result = parse_benchmark(lines, slo)
    write_outputs(output_path, summary_path, result)

    if result["status"] == "pass":
        print("OK: combined-load benchmark parsed and within advisory SLO.")
    elif result["status"] == "warn":
        print("WARN: combined-load advisory SLO exceeded; workflow remains non-blocking.", file=sys.stderr)
        for violation in result["violations"]:
            print(f" - {violation}", file=sys.stderr)
    else:
        print("WARN: combined-load benchmark data unavailable; wrote no_data advisory result.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
