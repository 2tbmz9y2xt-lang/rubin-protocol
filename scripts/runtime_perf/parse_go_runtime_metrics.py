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


def main() -> int:
    parser = argparse.ArgumentParser(description="Parse Go runtime benchmark output.")
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    input_path = Path(args.input)
    output_path = Path(args.output)
    metrics: dict[str, dict[str, float | int]] = {}
    for line in input_path.read_text(encoding="utf-8", errors="strict").splitlines():
        match = BENCH_LINE_RE.match(line.strip())
        if not match:
            continue
        name = match.group("name").rsplit("-", 1)[0]
        metrics[name] = {
            "iterations": int(match.group("n")),
            "ns_per_op": float(match.group("ns")),
            "mb_per_s": float(match.group("mbps")) if match.group("mbps") else None,
            "b_per_op": float(match.group("bop")),
            "allocs_per_op": float(match.group("allocs")),
        }

    if not metrics:
        raise SystemExit("ERROR: no Go runtime benchmark lines found")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps({"suite": "go", "metrics": metrics}, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
