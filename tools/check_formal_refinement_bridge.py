#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from pathlib import Path


def fail(msg: str) -> int:
    print(f"ERROR: {msg}", file=sys.stderr)
    return 1


def parse_executable_ops(matrix_text: str) -> set[str]:
    ops: set[str] = set()
    for line in matrix_text.splitlines():
        if not line.startswith("| `CV-"):
            continue
        cols = [c.strip() for c in line.split("|")]
        if len(cols) < 6:
            continue
        executable_col = cols[4]
        if executable_col == "-" or not executable_col:
            continue
        for item in executable_col.split(","):
            op = item.strip()
            if op:
                ops.add(op)
    return ops


def parse_fixture_gates(fixtures_dir: Path) -> dict[str, set[str]]:
    gate_ops: dict[str, set[str]] = {}
    for fixture in sorted(fixtures_dir.glob("CV-*.json")):
        doc = json.loads(fixture.read_text(encoding="utf-8"))
        gate = doc.get("gate")
        vectors = doc.get("vectors", [])
        if not isinstance(gate, str) or not isinstance(vectors, list):
            continue
        ops = gate_ops.setdefault(gate, set())
        for row in vectors:
            if isinstance(row, dict) and isinstance(row.get("op"), str):
                ops.add(row["op"])
    return gate_ops


def theorem_exists(repo_root: Path, theorem_name: str) -> bool:
    short_name = theorem_name.split(".")[-1]
    for p in (repo_root / "rubin-formal" / "RubinFormal").glob("*.lean"):
        txt = p.read_text(encoding="utf-8")
        if f"theorem {short_name}" in txt:
            return True
    return False


def main() -> int:
    repo_root = Path(__file__).resolve().parents[1]
    bridge_path = repo_root / "rubin-formal" / "refinement_bridge.json"
    matrix_path = repo_root / "conformance" / "MATRIX.md"
    fixtures_dir = repo_root / "conformance" / "fixtures"

    if not bridge_path.exists():
        return fail("rubin-formal/refinement_bridge.json not found")
    if not matrix_path.exists():
        return fail("conformance/MATRIX.md not found")
    if not fixtures_dir.exists():
        return fail("conformance/fixtures directory not found")

    bridge = json.loads(bridge_path.read_text(encoding="utf-8"))
    rows = bridge.get("critical_ops")
    if not isinstance(rows, list) or len(rows) == 0:
        return fail("refinement_bridge.json: critical_ops[] must be non-empty")

    matrix_text = matrix_path.read_text(encoding="utf-8")
    executable_ops = parse_executable_ops(matrix_text)
    gate_ops = parse_fixture_gates(fixtures_dir)

    bad = False
    for idx, row in enumerate(rows):
        if not isinstance(row, dict):
            print(f"ERROR: critical_ops[{idx}] must be object", file=sys.stderr)
            bad = True
            continue
        op = row.get("op")
        gate = row.get("gate")
        theorem = row.get("model_theorem")
        lean_file = row.get("lean_file")

        if not isinstance(op, str) or not op:
            print(f"ERROR: critical_ops[{idx}] missing op", file=sys.stderr)
            bad = True
            continue
        if op not in executable_ops:
            print(f"ERROR: op `{op}` is not executable in conformance/MATRIX.md", file=sys.stderr)
            bad = True

        if not isinstance(gate, str) or gate not in gate_ops:
            print(f"ERROR: gate `{gate}` not found in fixtures", file=sys.stderr)
            bad = True
        elif op not in gate_ops[gate]:
            print(f"ERROR: op `{op}` is not present in fixture gate `{gate}`", file=sys.stderr)
            bad = True

        if not isinstance(theorem, str) or not theorem:
            print(f"ERROR: missing model_theorem for op `{op}`", file=sys.stderr)
            bad = True
        elif not theorem_exists(repo_root, theorem):
            print(f"ERROR: theorem `{theorem}` not found in rubin-formal Lean files", file=sys.stderr)
            bad = True

        if not isinstance(lean_file, str) or not (repo_root / lean_file).exists():
            print(f"ERROR: lean_file missing for op `{op}`: {lean_file}", file=sys.stderr)
            bad = True

    if bad:
        return 1

    print(f"OK: formal refinement bridge valid ({len(rows)} critical ops mapped).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
