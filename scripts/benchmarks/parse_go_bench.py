#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path


BENCH_LINE_RE = re.compile(
    r"^(?P<name>BenchmarkValidateBlockBasicCombinedLoad(?:-\d+)?)\s+"
    r"(?P<n>\d+)\s+"
    r"(?P<ns>[\d.]+)\s+ns/op\s+"
    r"(?:(?P<mbps>[\d.]+)\s+MB/s\s+)?"
    r"(?P<bop>[\d.]+)\s+B/op\s+"
    r"(?P<allocs>[\d.]+)\s+allocs/op$"
)


def parse_metric(raw: str) -> float:
    return float(raw.strip())


def main() -> int:
    parser = argparse.ArgumentParser(description="Parse Go benchmark output and enforce SLO.")
    parser.add_argument("--input", required=True, help="Path to go test benchmark stdout file.")
    parser.add_argument("--slo", required=True, help="Path to JSON SLO config.")
    parser.add_argument("--output", required=True, help="Path to write parsed JSON metrics.")
    args = parser.parse_args()

    input_path = Path(args.input)
    slo_path = Path(args.slo)
    output_path = Path(args.output)

    if not input_path.exists():
        print(f"ERROR: benchmark output not found: {input_path}", file=sys.stderr)
        return 1
    if not slo_path.exists():
        print(f"ERROR: SLO file not found: {slo_path}", file=sys.stderr)
        return 1

    lines = input_path.read_text(encoding="utf-8", errors="strict").splitlines()
    match = None
    for line in lines:
        m = BENCH_LINE_RE.match(line.strip())
        if m:
            match = m
            break
    if match is None:
        print("ERROR: benchmark line for BenchmarkValidateBlockBasicCombinedLoad not found", file=sys.stderr)
        return 1

    slo = json.loads(slo_path.read_text(encoding="utf-8", errors="strict"))
    benchmark_name = match.group("name").split("-")[0]
    result = {
        "benchmark": benchmark_name,
        "iterations": int(match.group("n")),
        "ns_per_op": parse_metric(match.group("ns")),
        "mb_per_s": parse_metric(match.group("mbps")) if match.group("mbps") else None,
        "b_per_op": parse_metric(match.group("bop")),
        "allocs_per_op": parse_metric(match.group("allocs")),
        "slo": slo,
        "status": "pass",
        "violations": [],
    }

    if benchmark_name != slo.get("benchmark"):
        result["status"] = "fail"
        result["violations"].append(
            f"benchmark mismatch: got {benchmark_name!r}, expected {slo.get('benchmark')!r}"
        )

    checks = [
        ("ns_per_op", "max_ns_per_op"),
        ("b_per_op", "max_b_per_op"),
        ("allocs_per_op", "max_allocs_per_op"),
    ]
    for metric_key, limit_key in checks:
        limit = float(slo[limit_key])
        value = float(result[metric_key])
        if value > limit:
            result["status"] = "fail"
            result["violations"].append(
                f"{metric_key}={value} exceeds {limit_key}={limit}"
            )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")

    if result["status"] != "pass":
        print("ERROR: combined-load SLO failed", file=sys.stderr)
        for violation in result["violations"]:
            print(f" - {violation}", file=sys.stderr)
        return 1

    print("OK: combined-load benchmark parsed and within SLO.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
