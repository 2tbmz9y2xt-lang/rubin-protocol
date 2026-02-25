#!/usr/bin/env python3
from __future__ import annotations

import argparse
import importlib.util
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURES_DIR = REPO_ROOT / "conformance" / "fixtures"
RUNNER_PATH = REPO_ROOT / "conformance" / "runner" / "run_cv_bundle.py"
OUT_PATH = REPO_ROOT / "conformance" / "MATRIX.md"
EXPECTED_GATES = frozenset(
    {
        "CV-BLOCK-BASIC",
        "CV-COMPACT",
        "CV-COVENANT-GENESIS",
        "CV-DA-INTEGRITY",
        "CV-DETERMINISM",
        "CV-FORK-CHOICE",
        "CV-HTLC",
        "CV-HTLC-ORDERING",
        "CV-MERKLE",
        "CV-OUTPUT-DESCRIPTOR",
        "CV-PARSE",
        "CV-POW",
        "CV-REPLAY",
        "CV-SIG",
        "CV-SIGHASH",
        "CV-SUBSIDY",
        "CV-TIMESTAMP",
        "CV-UTXO-BASIC",
        "CV-VALIDATION-ORDER",
        "CV-VAULT",
        "CV-VAULT-POLICY",
        "CV-WEIGHT",
    }
)


@dataclass(frozen=True)
class GateRow:
    gate: str
    vectors: int
    ops: tuple[str, ...]
    local_ops: tuple[str, ...]
    executable_ops: tuple[str, ...]


def load_local_ops() -> set[str]:
    spec = importlib.util.spec_from_file_location("rubin_run_cv_bundle", str(RUNNER_PATH))
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load runner module: {RUNNER_PATH}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[attr-defined]
    local_ops = getattr(mod, "LOCAL_OPS", None)
    if not isinstance(local_ops, set) or not all(isinstance(x, str) for x in local_ops):
        raise RuntimeError("runner LOCAL_OPS missing/invalid")
    return set(local_ops)


def iter_fixtures() -> Iterable[Path]:
    if not FIXTURES_DIR.exists():
        raise RuntimeError(f"missing fixtures dir: {FIXTURES_DIR}")
    return sorted(FIXTURES_DIR.glob("CV-*.json"))


def validate_fixture_schema(data: Any, path: Path) -> tuple[str, list[dict[str, Any]]]:
    if not isinstance(data, dict):
        raise RuntimeError(f"fixture root must be object: {path}")

    missing = [field for field in ("gate", "vectors") if field not in data]
    if missing:
        missing_str = ", ".join(missing)
        raise RuntimeError(f"fixture missing required field(s): {missing_str}: {path}")

    gate = data["gate"]
    vectors = data["vectors"]
    if not isinstance(gate, str) or not gate.strip():
        raise RuntimeError(f"fixture field gate must be non-empty string: {path}")
    if not isinstance(vectors, list):
        raise RuntimeError(f"fixture field vectors must be an array: {path}")

    for idx, vector in enumerate(vectors):
        if not isinstance(vector, dict):
            raise RuntimeError(f"fixture vector[{idx}] must be object: {path}")
        op = vector.get("op")
        if not isinstance(op, str) or not op.strip():
            vid = vector.get("id", f"#{idx}")
            raise RuntimeError(f"fixture vector missing required op: {path} ({vid})")

    return gate.strip(), vectors


def load_gate_rows(local_ops: set[str]) -> list[GateRow]:
    rows: list[GateRow] = []
    seen_gates: set[str] = set()
    for p in iter_fixtures():
        data = json.loads(p.read_text(encoding="utf-8", errors="strict"))
        gate, vectors = validate_fixture_schema(data, p)
        if gate in seen_gates:
            raise RuntimeError(f"duplicate fixture gate: {gate}: {p}")
        seen_gates.add(gate)
        ops = tuple(sorted({v["op"].strip() for v in vectors}))

        local = tuple(sorted([o for o in ops if o in local_ops]))
        executable = tuple(sorted([o for o in ops if o not in local_ops]))
        rows.append(
            GateRow(
                gate=gate,
                vectors=len(vectors),
                ops=ops,
                local_ops=local,
                executable_ops=executable,
            )
        )
    rows.sort(key=lambda r: r.gate)
    return rows


def validate_expected_gates(rows: list[GateRow]) -> None:
    actual_gates = {row.gate for row in rows}
    missing = sorted(EXPECTED_GATES - actual_gates)
    unexpected = sorted(actual_gates - EXPECTED_GATES)

    if not missing and not unexpected:
        return

    problems: list[str] = []
    if missing:
        problems.append(f"missing fixtures for gates: {', '.join(missing)}")
    if unexpected:
        problems.append(f"unexpected gates in fixtures: {', '.join(unexpected)}")
    raise RuntimeError(f"fixture completeness check failed: {'; '.join(problems)}")


def render(rows: list[GateRow], local_ops: set[str]) -> str:
    total_vectors = sum(r.vectors for r in rows)
    total_gates = len(rows)
    all_ops = sorted({o for r in rows for o in r.ops})
    all_exec_ops = sorted({o for r in rows for o in r.executable_ops})
    all_local_ops = sorted({o for r in rows for o in r.local_ops})

    def fmt_ops(items: Iterable[str]) -> str:
        return ", ".join(items) if items else "-"

    lines: list[str] = []
    lines.append("# Conformance Matrix (generated)")
    lines.append("")
    lines.append("Generated by `tools/gen_conformance_matrix.py`.")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(f"- Gates: **{total_gates}**")
    lines.append(f"- Vectors: **{total_vectors}**")
    lines.append(f"- Unique ops: **{len(all_ops)}**")
    lines.append(f"- Executable ops (Go↔Rust parity): **{len(all_exec_ops)}**")
    lines.append(f"- Local-only ops (runner-defined): **{len(all_local_ops)}**")
    lines.append("")
    lines.append("## Gates")
    lines.append("")
    lines.append("| Gate | Vectors | Ops | Executable ops | Local-only ops |")
    lines.append("| --- | ---: | --- | --- | --- |")
    for r in rows:
        lines.append(
            f"| `{r.gate}` | {r.vectors} | {fmt_ops(r.ops)} | {fmt_ops(r.executable_ops)} | {fmt_ops(r.local_ops)} |"
        )
    lines.append("")
    lines.append("## Local-only ops (runner)")
    lines.append("")
    for op in sorted(local_ops):
        lines.append(f"- `{op}`")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="fail if conformance/MATRIX.md is out of date")
    args = ap.parse_args()

    local_ops = load_local_ops()
    rows = load_gate_rows(local_ops)
    validate_expected_gates(rows)
    content = render(rows, local_ops)

    if args.check:
        if not OUT_PATH.exists():
            print(f"ERROR: missing {OUT_PATH}")
            return 1
        cur = OUT_PATH.read_text(encoding="utf-8", errors="strict")
        if cur != content:
            print("ERROR: conformance/MATRIX.md is out of date (run tools/gen_conformance_matrix.py)")
            return 1
        print("OK: conformance/MATRIX.md is up to date")
        return 0

    OUT_PATH.write_text(content, encoding="utf-8")
    print(f"WROTE: {OUT_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
