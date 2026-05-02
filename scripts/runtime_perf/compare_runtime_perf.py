#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

ADVISORY_THRESHOLDS: list[dict[str, Any]] = [
    {
        "suite": "go",
        "benchmark": "BenchmarkMempoolAddTx",
        "metric": "ns_per_op",
        "max_regression_pct": 20.0,
        "reason": "selected low-noise in-memory Go mempool admission candidate from mainline trend capture",
    },
    {
        "suite": "go",
        "benchmark": "BenchmarkMempoolRelayMetadata",
        "metric": "ns_per_op",
        "max_regression_pct": 20.0,
        "reason": "selected low-noise in-memory Go relay metadata candidate from mainline trend capture",
    },
    {
        "suite": "go",
        "benchmark": "BenchmarkCloneChainState",
        "metric": "ns_per_op",
        "max_regression_pct": 25.0,
        "reason": "selected deterministic Go chain-state clone candidate from mainline trend capture",
    },
    {
        "suite": "rust",
        "benchmark": "rubin_node_txpool/admit",
        "metric": "ns_per_op",
        "max_regression_pct": 20.0,
        "reason": "selected low-noise Rust txpool admission candidate from mainline trend capture",
    },
    {
        "suite": "rust",
        "benchmark": "rubin_node_txpool/relay_metadata",
        "metric": "ns_per_op",
        "max_regression_pct": 20.0,
        "reason": "selected low-noise Rust relay metadata candidate from mainline trend capture",
    },
    {
        "suite": "rust",
        "benchmark": "rubin_node_chainstate_clone",
        "metric": "ns_per_op",
        "max_regression_pct": 25.0,
        "reason": "selected deterministic Rust chain-state clone candidate from mainline trend capture",
    },
]

METRIC_FILES = {
    "go": "go_metrics.json",
    "rust": "rust_metrics.json",
}

ROW_FIELDS = {
    "go": ["ns_per_op", "b_per_op", "allocs_per_op"],
    "rust": ["ns_per_op"],
}

THRESHOLD_INDEX = {
    (item["suite"], item["benchmark"], item["metric"]): item
    for item in ADVISORY_THRESHOLDS
}


def load_json(path: Path) -> tuple[dict[str, Any] | None, str | None]:
    if not path.exists():
        return None, f"missing artifact: {path}"
    try:
        payload = json.loads(path.read_text(encoding="utf-8", errors="strict"))
    except json.JSONDecodeError as exc:
        return None, f"malformed JSON in {path}: {exc}"
    if not isinstance(payload, dict):
        return None, f"JSON root in {path} is {type(payload).__name__}, expected object"
    return payload, None


def load_exit_code(path: Path) -> int | None:
    if not path.exists():
        return None
    return int(path.read_text(encoding="utf-8", errors="strict").strip())


def pct_delta(base: float, head: float) -> float | None:
    if base == 0:
        return None
    return ((head - base) / base) * 100.0


def metrics_from_payload(suite: str, payload: dict[str, Any] | None) -> dict[str, dict[str, Any]]:
    if payload is None:
        return {}
    if suite in {"go", "rust"}:
        metrics = payload.get("metrics")
        return metrics if isinstance(metrics, dict) else {}
    return {}


def classify_delta(
    *,
    suite: str,
    benchmark: str,
    metric: str,
    base_value: Any,
    head_value: Any,
    threshold: dict[str, Any] | None,
    base_issue: str | None,
    head_issue: str | None,
) -> dict[str, Any]:
    if threshold is None:
        return {
            "status": "unselected",
            "reason": "benchmark metric is outside the selected low-noise advisory threshold set",
        }
    entry = {
        "suite": suite,
        "benchmark": benchmark,
        "metric": metric,
        "baseline": base_value,
        "observed": head_value,
        "delta_pct": None,
        "threshold_pct": threshold["max_regression_pct"],
        "status": "no_data",
        "reason": threshold["reason"],
    }
    if base_issue or head_issue:
        entry["reason"] = "; ".join(issue for issue in [base_issue, head_issue] if issue)
        return entry
    if base_value is None or head_value is None:
        entry["reason"] = "baseline or observed metric missing; no advisory decision"
        return entry
    delta = pct_delta(float(base_value), float(head_value))
    entry["delta_pct"] = delta
    if delta is None:
        entry["reason"] = "baseline metric is zero; percent delta unavailable"
        return entry
    if delta > float(threshold["max_regression_pct"]):
        entry["status"] = "warn"
        entry["reason"] = (
            f"observed regression {delta:+.2f}% exceeds advisory threshold "
            f"{float(threshold['max_regression_pct']):.2f}%"
        )
    else:
        entry["status"] = "pass"
        entry["reason"] = (
            f"observed delta {delta:+.2f}% is within advisory threshold "
            f"{float(threshold['max_regression_pct']):.2f}%"
        )
    return entry


def build_rows(
    suite: str,
    base_metrics: dict[str, dict[str, Any]],
    head_metrics: dict[str, dict[str, Any]],
    fields: list[str],
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for name in sorted(set(base_metrics) | set(head_metrics)):
        base = base_metrics.get(name)
        head = head_metrics.get(name)
        row: dict[str, Any] = {"suite": suite, "name": name, "base": base, "head": head, "deltas": {}, "advisory": {}}
        if base and head:
            for field in fields:
                if field in base and field in head:
                    row["deltas"][field] = pct_delta(float(base[field]), float(head[field]))
        for field in fields:
            threshold = THRESHOLD_INDEX.get((suite, name, field))
            row["advisory"][field] = classify_delta(
                suite=suite,
                benchmark=name,
                metric=field,
                base_value=base.get(field) if base else None,
                head_value=head.get(field) if head else None,
                threshold=threshold,
                base_issue=None,
                head_issue=None,
            )
        rows.append(row)
    return rows


def build_advisory_decisions(
    metric_sets: dict[str, tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]], str | None, str | None]]
) -> list[dict[str, Any]]:
    decisions: list[dict[str, Any]] = []
    for threshold in ADVISORY_THRESHOLDS:
        suite = threshold["suite"]
        benchmark = threshold["benchmark"]
        metric = threshold["metric"]
        base_metrics, head_metrics, base_issue, head_issue = metric_sets.get(suite, ({}, {}, "missing suite", "missing suite"))
        base = base_metrics.get(benchmark, {})
        head = head_metrics.get(benchmark, {})
        decisions.append(
            classify_delta(
                suite=suite,
                benchmark=benchmark,
                metric=metric,
                base_value=base.get(metric),
                head_value=head.get(metric),
                threshold=threshold,
                base_issue=base_issue if not base_metrics else None,
                head_issue=head_issue if not head_metrics else None,
            )
        )
    return decisions


def advisory_status(decisions: list[dict[str, Any]]) -> str:
    statuses = [decision["status"] for decision in decisions]
    if "warn" in statuses:
        return "warn"
    if "no_data" in statuses:
        return "no_data"
    return "pass"


def render_value(value: Any) -> str:
    if value is None:
        return "n/a"
    if isinstance(value, float):
        return f"{value:.0f}"
    return str(value)


def render_table(title: str, rows: list[dict[str, Any]]) -> list[str]:
    lines = [f"### {title}", "", "| Benchmark | Base ns/op | Head ns/op | Delta | Advisory |", "|---|---:|---:|---:|---|"]
    for row in rows:
        base = row["base"]
        head = row["head"]
        if not base or not head:
            lines.append(
                f"| `{row['name']}` | {'missing' if not base else render_value(base.get('ns_per_op'))} | "
                f"{'missing' if not head else render_value(head.get('ns_per_op'))} | n/a | no_data |"
            )
            continue
        delta = row["deltas"].get("ns_per_op")
        delta_str = "n/a" if delta is None else f"{delta:+.2f}%"
        advisory = row["advisory"].get("ns_per_op", {"status": "unselected"})["status"]
        lines.append(
            f"| `{row['name']}` | {render_value(base.get('ns_per_op'))} | "
            f"{render_value(head.get('ns_per_op'))} | {delta_str} | {advisory} |"
        )
    lines.append("")
    return lines


def render_advisory_summary(decisions: list[dict[str, Any]]) -> list[str]:
    lines = [
        "## Advisory regression detection",
        "",
        f"Overall advisory status: `{advisory_status(decisions)}`.",
        "",
        "This status is informational only. Threshold WARN does not fail this workflow.",
        "",
        "| Suite | Benchmark | Metric | Baseline | Observed | Delta | Threshold | Status | Reason |",
        "|---|---|---|---:|---:|---:|---:|---|---|",
    ]
    for item in decisions:
        delta = item.get("delta_pct")
        delta_str = "n/a" if delta is None else f"{float(delta):+.2f}%"
        threshold = item.get("threshold_pct")
        threshold_str = "n/a" if threshold is None else f"{float(threshold):.2f}%"
        lines.append(
            f"| `{item['suite']}` | `{item['benchmark']}` | `{item['metric']}` | "
            f"{render_value(item.get('baseline'))} | {render_value(item.get('observed'))} | "
            f"{delta_str} | {threshold_str} | `{item['status']}` | {item['reason']} |"
        )
    lines.append("")
    return lines


def main() -> int:
    parser = argparse.ArgumentParser(description="Compare base/head runtime perf artifacts.")
    parser.add_argument("--base-dir", required=True)
    parser.add_argument("--head-dir", required=True)
    parser.add_argument("--summary", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    base_dir = Path(args.base_dir)
    head_dir = Path(args.head_dir)
    summary_path = Path(args.summary)
    output_path = Path(args.output)

    loaded: dict[str, tuple[dict[str, Any] | None, str | None, dict[str, Any] | None, str | None]] = {}
    input_issues: list[str] = []
    for suite, filename in METRIC_FILES.items():
        base_payload, base_issue = load_json(base_dir / filename)
        head_payload, head_issue = load_json(head_dir / filename)
        loaded[suite] = (base_payload, base_issue, head_payload, head_issue)
        input_issues.extend(issue for issue in [base_issue, head_issue] if issue)

    base_rc = load_exit_code(base_dir / "exit_code.txt")
    head_rc = load_exit_code(head_dir / "exit_code.txt")

    metric_sets: dict[str, tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]], str | None, str | None]] = {}
    suite_rows: dict[str, list[dict[str, Any]]] = {}
    for suite, (base_payload, base_issue, head_payload, head_issue) in loaded.items():
        base_metrics = metrics_from_payload(suite, base_payload)
        head_metrics = metrics_from_payload(suite, head_payload)
        metric_sets[suite] = (base_metrics, head_metrics, base_issue, head_issue)
        suite_rows[suite] = build_rows(suite, base_metrics, head_metrics, ROW_FIELDS[suite])

    advisory = build_advisory_decisions(metric_sets)

    summary_lines = [
        "# Runtime Perf Guardrails",
        "",
        "Non-blocking benchmark visibility for the selected Go/Rust runtime hot paths.",
        "",
        f"- base suite exit code: `{base_rc}`",
        f"- head suite exit code: `{head_rc}`",
        "",
    ]

    summary_lines.extend(render_advisory_summary(advisory))

    for suite, title in [("go", "Go"), ("rust", "Rust")]:
        rows = suite_rows[suite]
        if rows:
            summary_lines.extend(render_table(title, rows))
        else:
            summary_lines.extend([f"### {title}", "", f"{title} metrics missing in either base or head artifact.", ""])

    summary_lines.extend(
        [
            "## Threshold policy",
            "",
            "- this lane is informational only;",
            "- advisory threshold warnings must not block merge;",
            "- missing or malformed benchmark data is reported as `no_data`, not as a regression;",
            "- thresholds apply only to selected low-noise candidates documented in trend-capture evidence.",
            "",
        ]
    )

    result = {
        "base_exit_code": base_rc,
        "head_exit_code": head_rc,
        "input_issues": input_issues,
        "advisory_status": advisory_status(advisory),
        "advisory_thresholds": ADVISORY_THRESHOLDS,
        "advisory": advisory,
        "go": suite_rows["go"] or None,
        "rust": suite_rows["rust"] or None,
    }

    summary_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.write_text("\n".join(summary_lines), encoding="utf-8")
    output_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
