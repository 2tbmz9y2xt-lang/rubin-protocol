#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path


def load_json(path: Path) -> dict | None:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8", errors="strict"))


def load_exit_code(path: Path) -> int | None:
    if not path.exists():
        return None
    return int(path.read_text(encoding="utf-8", errors="strict").strip())


def pct_delta(base: float, head: float) -> float | None:
    if base == 0:
        return None
    return ((head - base) / base) * 100.0


def build_rows(base_metrics: dict[str, dict], head_metrics: dict[str, dict], fields: list[str]) -> list[dict]:
    rows: list[dict] = []
    for name in sorted(set(base_metrics) | set(head_metrics)):
        base = base_metrics.get(name)
        head = head_metrics.get(name)
        row = {"name": name, "base": base, "head": head, "deltas": {}}
        if base and head:
            for field in fields:
                if field in base and field in head:
                    row["deltas"][field] = pct_delta(float(base[field]), float(head[field]))
        rows.append(row)
    return rows


def render_table(title: str, rows: list[dict], fields: list[str]) -> list[str]:
    lines = [f"### {title}", "", "| Benchmark | Base ns/op | Head ns/op | Δ ns/op |", "|---|---:|---:|---:|"]
    for row in rows:
        base = row["base"]
        head = row["head"]
        if not base or not head:
            lines.append(f"| `{row['name']}` | {'missing' if not base else base.get('ns_per_op', 'n/a')} | {'missing' if not head else head.get('ns_per_op', 'n/a')} | n/a |")
            continue
        delta = row["deltas"].get("ns_per_op")
        delta_str = "n/a" if delta is None else f"{delta:+.2f}%"
        lines.append(
            f"| `{row['name']}` | {base['ns_per_op']:.0f} | {head['ns_per_op']:.0f} | {delta_str} |"
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

    base_go = load_json(base_dir / "go_metrics.json")
    head_go = load_json(head_dir / "go_metrics.json")
    base_rust = load_json(base_dir / "rust_metrics.json")
    head_rust = load_json(head_dir / "rust_metrics.json")
    base_rc = load_exit_code(base_dir / "exit_code.txt")
    head_rc = load_exit_code(head_dir / "exit_code.txt")

    summary_lines = [
        "# Runtime Perf Guardrails",
        "",
        "Non-blocking benchmark visibility for the selected Go/Rust runtime hot paths.",
        "",
        f"- base suite exit code: `{base_rc}`",
        f"- head suite exit code: `{head_rc}`",
        "",
    ]

    result = {
        "base_exit_code": base_rc,
        "head_exit_code": head_rc,
        "go": None,
        "rust": None,
    }

    if base_go and head_go:
        go_rows = build_rows(base_go["metrics"], head_go["metrics"], ["ns_per_op", "b_per_op", "allocs_per_op"])
        summary_lines.extend(render_table("Go", go_rows, ["ns_per_op", "b_per_op", "allocs_per_op"]))
        result["go"] = go_rows
    else:
        summary_lines.extend(["### Go", "", "Go metrics missing in either base or head artifact.", ""])

    if base_rust and head_rust:
        rust_rows = build_rows(base_rust["metrics"], head_rust["metrics"], ["ns_per_op"])
        summary_lines.extend(render_table("Rust", rust_rows, ["ns_per_op"]))
        missing = sorted(set(base_rust.get("missing", [])) | set(head_rust.get("missing", [])))
        if missing:
            summary_lines.extend(["Missing rust targets:", ""])
            for name in missing:
                summary_lines.append(f"- `{name}`")
            summary_lines.append("")
        result["rust"] = rust_rows
    else:
        summary_lines.extend(["### Rust", "", "Rust metrics missing in either base or head artifact.", ""])

    summary_lines.extend(
        [
            "## Threshold policy",
            "",
            "- this lane is informational only;",
            "- it must not block merge while the baseline is still stabilizing;",
            "- follow-up perf slices can promote specific stable deltas into soft thresholds later.",
            "",
        ]
    )

    summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.write_text("\n".join(summary_lines), encoding="utf-8")
    output_path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
