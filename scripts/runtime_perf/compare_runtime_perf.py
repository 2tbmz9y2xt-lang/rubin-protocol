#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import math
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


def validate_threshold_registry() -> None:
    unknown_suites = sorted({item["suite"] for item in ADVISORY_THRESHOLDS} - set(METRIC_FILES))
    if unknown_suites:
        joined = ", ".join(unknown_suites)
        raise ValueError(f"advisory threshold suite(s) not configured in METRIC_FILES: {joined}")


def coerce_metric(value: Any) -> tuple[float | None, str | None]:
    if isinstance(value, bool) or value is None:
        return None, f"non-numeric metric value: {value!r}"
    try:
        metric = float(value)
    except (TypeError, ValueError):
        return None, f"non-numeric metric value: {value!r}"
    if not math.isfinite(metric):
        return None, f"non-finite metric value: {value!r}"
    if metric < 0:
        return None, f"negative metric value: {value!r}"
    return metric, None


def json_safe_value(value: Any) -> Any:
    if isinstance(value, float) and not math.isfinite(value):
        return None
    if isinstance(value, dict):
        return {key: json_safe_value(item) for key, item in value.items()}
    if isinstance(value, list):
        return [json_safe_value(item) for item in value]
    return value


def load_json(path: Path) -> tuple[dict[str, Any] | None, str | None]:
    if not path.exists():
        return None, f"missing artifact: {path}"
    try:
        raw = path.read_text(encoding="utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        return None, f"invalid UTF-8 in {path}: {exc}"
    except OSError as exc:
        return None, f"cannot read artifact {path}: {exc}"
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        return None, f"malformed JSON in {path}: {exc}"
    if not isinstance(payload, dict):
        return None, f"JSON root in {path} is {type(payload).__name__}, expected object"
    return payload, None


def load_exit_code(path: Path) -> tuple[int | None, str | None]:
    if not path.exists():
        return None, None
    try:
        raw = path.read_text(encoding="utf-8", errors="strict").strip()
    except UnicodeDecodeError as exc:
        return None, f"invalid UTF-8 in {path}: {exc}"
    except OSError as exc:
        return None, f"cannot read exit code artifact {path}: {exc}"
    try:
        return int(raw), None
    except ValueError:
        return None, f"malformed exit code in {path}: {raw!r}"


def pct_delta(base: float, head: float) -> float | None:
    if base == 0:
        return None
    return ((head - base) / base) * 100.0


def missing_from_payload(suite: str, payload: dict[str, Any] | None) -> tuple[list[str], str | None]:
    if payload is None:
        return [], None
    raw_missing = payload.get("missing", [])
    if raw_missing is None:
        return [], None
    if not isinstance(raw_missing, list):
        return [], f"{suite} metrics artifact field 'missing' is {type(raw_missing).__name__}, expected list"
    missing: list[str] = []
    for item in raw_missing:
        if not isinstance(item, str):
            return [], f"{suite} metrics artifact field 'missing' contains {type(item).__name__}, expected string"
        missing.append(item)
    return sorted(set(missing)), None


def metrics_from_payload(
    suite: str,
    payload: dict[str, Any] | None,
) -> tuple[dict[str, dict[str, Any]], str | None, dict[str, str], list[str]]:
    if payload is None:
        return {}, None, {}, []
    if suite in {"go", "rust"}:
        metrics = payload.get("metrics")
        if not isinstance(metrics, dict):
            issue = f"{suite} metrics artifact missing object field 'metrics'"
            return {}, issue, {}, [issue]
        normalized: dict[str, dict[str, Any]] = {}
        entry_issues: dict[str, str] = {}
        input_issues: list[str] = []
        for benchmark, metric_values in metrics.items():
            if not isinstance(metric_values, dict):
                issue = f"{suite} metrics entry for {benchmark} is {type(metric_values).__name__}, expected object"
                entry_issues[benchmark] = issue
                input_issues.append(issue)
                continue
            normalized[benchmark] = metric_values
        return normalized, None, entry_issues, input_issues
    issue = f"unknown metrics suite: {suite}"
    return {}, issue, {}, [issue]


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
        "baseline": json_safe_value(base_value),
        "observed": json_safe_value(head_value),
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
    base_float, base_float_issue = coerce_metric(base_value)
    head_float, head_float_issue = coerce_metric(head_value)
    if base_float_issue or head_float_issue:
        entry["reason"] = "baseline or observed metric is non-numeric: " + "; ".join(
            issue for issue in [base_float_issue, head_float_issue] if issue
        )
        return entry
    delta = pct_delta(base_float, head_float)
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
    base_suite_issue: str | None,
    head_suite_issue: str | None,
    base_entry_issues: dict[str, str],
    head_entry_issues: dict[str, str],
    extra_names: list[str] | None = None,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    row_names = set(base_metrics) | set(head_metrics) | set(base_entry_issues) | set(head_entry_issues) | set(extra_names or [])
    for name in sorted(row_names):
        base = base_metrics.get(name)
        head = head_metrics.get(name)
        row: dict[str, Any] = {
            "suite": suite,
            "name": name,
            "base": json_safe_value(base),
            "head": json_safe_value(head),
            "deltas": {},
            "advisory": {},
        }
        if base and head:
            for field in fields:
                if field in base and field in head:
                    base_float, base_float_issue = coerce_metric(base[field])
                    head_float, head_float_issue = coerce_metric(head[field])
                    if base_float_issue is None and head_float_issue is None:
                        row["deltas"][field] = pct_delta(base_float, head_float)
        for field in fields:
            threshold = THRESHOLD_INDEX.get((suite, name, field))
            row["advisory"][field] = classify_delta(
                suite=suite,
                benchmark=name,
                metric=field,
                base_value=base.get(field) if base else None,
                head_value=head.get(field) if head else None,
                threshold=threshold,
                base_issue=base_suite_issue or base_entry_issues.get(name),
                head_issue=head_suite_issue or head_entry_issues.get(name),
            )
        rows.append(row)
    return rows


def build_advisory_decisions(
    metric_sets: dict[
        str,
        tuple[
            dict[str, dict[str, Any]],
            dict[str, dict[str, Any]],
            str | None,
            str | None,
            dict[str, str],
            dict[str, str],
        ],
    ]
) -> list[dict[str, Any]]:
    decisions: list[dict[str, Any]] = []
    for threshold in ADVISORY_THRESHOLDS:
        suite = threshold["suite"]
        benchmark = threshold["benchmark"]
        metric = threshold["metric"]
        base_metrics, head_metrics, base_suite_issue, head_suite_issue, base_entry_issues, head_entry_issues = metric_sets.get(
            suite,
            ({}, {}, "missing suite", "missing suite", {}, {}),
        )
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
                base_issue=base_suite_issue or base_entry_issues.get(benchmark),
                head_issue=head_suite_issue or head_entry_issues.get(benchmark),
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


def render_markdown_cell(value: Any, limit: int = 240) -> str:
    text = render_value(value).replace("\r", " ").replace("\n", " ").replace("|", "\\|")
    if len(text) > limit:
        return text[: limit - 3] + "..."
    return text


def render_table(title: str, rows: list[dict[str, Any]]) -> list[str]:
    lines = [f"### {title}", "", "| Benchmark | Base ns/op | Head ns/op | Delta | Advisory |", "|---|---:|---:|---:|---|"]
    for row in rows:
        base = row["base"]
        head = row["head"]
        advisory = row["advisory"].get("ns_per_op", {"status": "unselected"})["status"]
        if not base or not head:
            lines.append(
                f"| `{row['name']}` | {'missing' if not base else render_value(base.get('ns_per_op'))} | "
                f"{'missing' if not head else render_value(head.get('ns_per_op'))} | n/a | {advisory} |"
            )
            continue
        delta = row["deltas"].get("ns_per_op")
        delta_str = "n/a" if delta is None else f"{delta:+.2f}%"
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
            f"{delta_str} | {threshold_str} | `{item['status']}` | {render_markdown_cell(item['reason'])} |"
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
    validate_threshold_registry()

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

    base_rc, base_rc_issue = load_exit_code(base_dir / "exit_code.txt")
    head_rc, head_rc_issue = load_exit_code(head_dir / "exit_code.txt")
    input_issues.extend(issue for issue in [base_rc_issue, head_rc_issue] if issue)

    metric_sets: dict[
        str,
        tuple[
            dict[str, dict[str, Any]],
            dict[str, dict[str, Any]],
            str | None,
            str | None,
            dict[str, str],
            dict[str, str],
        ],
    ] = {}
    suite_rows: dict[str, list[dict[str, Any]]] = {}
    missing_by_suite: dict[str, dict[str, list[str]]] = {}
    for suite, (base_payload, base_issue, head_payload, head_issue) in loaded.items():
        base_metrics, base_suite_issue, base_entry_issues, base_shape_issues = metrics_from_payload(suite, base_payload)
        head_metrics, head_suite_issue, head_entry_issues, head_shape_issues = metrics_from_payload(suite, head_payload)
        base_missing, base_missing_issue = missing_from_payload(suite, base_payload)
        head_missing, head_missing_issue = missing_from_payload(suite, head_payload)
        base_data_issue = base_issue or base_suite_issue
        head_data_issue = head_issue or head_suite_issue
        input_issues.extend(base_shape_issues)
        input_issues.extend(head_shape_issues)
        input_issues.extend(issue for issue in [base_missing_issue, head_missing_issue] if issue)
        missing_by_suite[suite] = {"base": base_missing, "head": head_missing}
        metric_sets[suite] = (
            base_metrics,
            head_metrics,
            base_data_issue,
            head_data_issue,
            base_entry_issues,
            head_entry_issues,
        )
        suite_rows[suite] = build_rows(
            suite,
            base_metrics,
            head_metrics,
            ROW_FIELDS[suite],
            base_data_issue,
            head_data_issue,
            base_entry_issues,
            head_entry_issues,
            sorted(set(base_missing) | set(head_missing)),
        )

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
            summary_lines.extend([f"### {title}", "", f"{title} metrics unavailable or empty in either base or head artifact.", ""])

    summary_lines.extend(
        [
            "## Threshold policy",
            "",
            "- this lane is informational only;",
            "- advisory threshold warnings must not block merge;",
            "- missing or malformed benchmark data is reported as `no_data`, not as a regression;",
            "- thresholds apply only to selected low-noise `ns_per_op` candidates documented in trend-capture evidence;",
            "- byte and allocation metrics remain reported but unthresholded in this advisory slice.",
            "",
        ]
    )

    result = {
        "base_exit_code": base_rc,
        "head_exit_code": head_rc,
        "input_issues": input_issues,
        "advisory_status": advisory_status(advisory),
        "advisory_thresholds": [dict(item) for item in ADVISORY_THRESHOLDS],
        "advisory": advisory,
        "missing": missing_by_suite,
        "go": suite_rows["go"],
        "rust": suite_rows["rust"],
    }

    summary_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.write_text("\n".join(summary_lines), encoding="utf-8")
    output_path.write_text(json.dumps(result, allow_nan=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
