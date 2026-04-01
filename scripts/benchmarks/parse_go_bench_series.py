#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path


BENCH_LINE_RE = re.compile(
    r"^(?P<name>Benchmark[^\s]+(?:/[^\s]+)?(?:-\d+)?)\s+"
    r"(?P<n>\d+)\s+"
    r"(?P<ns>[\d.]+)\s+ns/op\s+"
    r"(?:(?P<mbps>[\d.]+)\s+MB/s\s+)?"
    r"(?P<bop>[\d.]+)\s+B/op\s+"
    r"(?P<allocs>[\d.]+)\s+allocs/op$"
)


def parse_float(raw: str) -> float:
    return float(raw.strip())


def main() -> int:
    parser = argparse.ArgumentParser(description="Parse a series of Go benchmark lines into JSON.")
    parser.add_argument("--input", required=True, help="Path to go test benchmark stdout file.")
    parser.add_argument("--output", required=True, help="Path to write parsed JSON metrics.")
    args = parser.parse_args()

    input_path = Path(args.input)
    output_path = Path(args.output)
    lines = input_path.read_text(encoding="utf-8", errors="strict").splitlines()

    benchmarks: list[dict[str, object]] = []
    for line in lines:
        match = BENCH_LINE_RE.match(line.strip())
        if not match:
            continue
        full_name = match.group("name")
        logical_name = full_name.rsplit("-", 1)[0]
        benchmarks.append(
            {
                "benchmark": logical_name,
                "iterations": int(match.group("n")),
                "ns_per_op": parse_float(match.group("ns")),
                "mb_per_s": parse_float(match.group("mbps")) if match.group("mbps") else None,
                "b_per_op": parse_float(match.group("bop")),
                "allocs_per_op": parse_float(match.group("allocs")),
            }
        )

    if not benchmarks:
        raise SystemExit("ERROR: no benchmark lines found in input")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps({"benchmarks": benchmarks}, indent=2) + "\n", encoding="utf-8")
    print(f"OK: wrote {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
