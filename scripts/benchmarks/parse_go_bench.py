#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import math
import re
import sys
from pathlib import Path
from typing import Any


CORE_METRIC_PATTERNS = {
    "ns_per_op": re.compile(r"(?<!\S)(?P<value>\S+)\s+ns/op\b"),
    "mb_per_s": re.compile(r"(?<!\S)(?P<value>\S+)\s+MB/s\b"),
    "b_per_op": re.compile(r"(?<!\S)(?P<value>\S+)\s+B/op\b"),
    "allocs_per_op": re.compile(r"(?<!\S)(?P<value>\S+)\s+allocs/op\b"),
}


METRIC_CHECKS = [
    ("ns_per_op", "max_ns_per_op"),
    ("b_per_op", "max_b_per_op"),
    ("allocs_per_op", "max_allocs_per_op"),
]


def parse_finite_number(raw: Any, label: str, *, allow_zero: bool) -> float:
    if isinstance(raw, bool) or raw is None:
        raise ValueError(f"{label} is not numeric: {raw!r}")
    try:
        value = float(raw)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{label} has invalid numeric token {raw!r}") from exc
    if not math.isfinite(value):
        raise ValueError(f"{label} has non-finite numeric token {raw!r}")
    if value < 0 or (value == 0 and not allow_zero):
        bound = "non-negative" if allow_zero else "positive"
        raise ValueError(f"{label} must be {bound}: {raw!r}")
    return value


def parse_metric(raw: str) -> float:
    return parse_finite_number(raw.strip(), "metric", allow_zero=True)


def strip_go_benchmark_suffix(name: str) -> str:
    parts = name.rsplit("-", 1)
    if len(parts) == 2 and parts[1].isdigit():
        return parts[0]
    return name


def parse_benchmark_line(line: str, benchmark: str) -> tuple[dict[str, Any] | None, str | None]:
    prefix = re.match(
        rf"^(?P<name>{re.escape(benchmark)}(?:-\d+)?)\s+(?P<n>\d+)\s+(?P<metrics>.*)$",
        line.strip(),
    )
    if prefix is None:
        return None, None
    metrics = prefix.group("metrics")
    parsed: dict[str, Any] = {
        "benchmark": strip_go_benchmark_suffix(prefix.group("name")),
        "iterations": int(prefix.group("n")),
    }
    missing: list[str] = []
    for key, pattern in CORE_METRIC_PATTERNS.items():
        match = pattern.search(metrics)
        if match is None:
            if key == "mb_per_s":
                parsed[key] = None
                continue
            missing.append(key)
            continue
        try:
            parsed[key] = parse_metric(match.group("value"))
        except ValueError as exc:
            return None, f"benchmark line for {benchmark} has malformed {key}: {exc}"
    if missing:
        return None, f"benchmark line for {benchmark} missing required metric(s): {', '.join(missing)}"
    return parsed, None


def load_slo(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8", errors="strict"))
    if not isinstance(payload, dict):
        raise ValueError(f"SLO JSON root is {type(payload).__name__}, expected object")
    for key in ["benchmark", "max_ns_per_op", "max_b_per_op", "max_allocs_per_op"]:
        if key not in payload:
            raise ValueError(f"SLO missing required key {key!r}")
    for _, limit_key in METRIC_CHECKS:
        payload[limit_key] = parse_finite_number(payload[limit_key], f"SLO {limit_key}", allow_zero=False)
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
    benchmark = str(slo["benchmark"])
    parsed = None
    parse_issue = None
    for line in lines:
        parsed, parse_issue = parse_benchmark_line(line, benchmark)
        if parse_issue is not None:
            break
        if parsed is not None:
            break
    if parsed is None:
        return no_data_result(slo, parse_issue or f"benchmark line for {benchmark} not found")

    result: dict[str, Any] = {
        "benchmark": parsed["benchmark"],
        "iterations": parsed["iterations"],
        "ns_per_op": parsed["ns_per_op"],
        "mb_per_s": parsed["mb_per_s"],
        "b_per_op": parsed["b_per_op"],
        "allocs_per_op": parsed["allocs_per_op"],
        "slo": slo,
        "status": "pass",
        "violations": [],
        "reason": "combined-load benchmark is within advisory SLO",
        "advisory": True,
    }

    if result["benchmark"] != slo.get("benchmark"):
        return no_data_result(
            slo,
            f"benchmark mismatch: got {result['benchmark']!r}, expected {slo.get('benchmark')!r}",
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
