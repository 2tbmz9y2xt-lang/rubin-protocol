#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from pathlib import Path

from check_formal_coverage import (
    ALLOWED_PROOF_TRUST,
    declared_lean_theorems,
    declared_lean_theorems_in_text,
    has_canonical_import,
    validate_source_rebind,
)


ALLOWED_EVIDENCE_LEVEL = {
    "machine_checked_universal",
    "machine_checked_assumption_backed",
    "machine_checked_behavioral",
    "machine_checked_contract",
}
FORMAL_SKIP_GATE_PREFIXES = ("CV-PV-",)
FORBIDDEN_SCOPE_MARKERS = ("universal", "for all", "all inputs", "all byte strings", "not bounded", "not-bounded")
TRACE_SOURCE_FILE = "rubin-formal/RubinFormal/Refinement/GoTraceV1.lean"


def valid_non_empty_string_list(value: object) -> bool:
    return isinstance(value, list) and bool(value) and all(isinstance(item, str) and item for item in value)


def valid_string_list(value: object) -> bool:
    return isinstance(value, list) and all(isinstance(item, str) and item for item in value)


def states_bounded_scope(value: object) -> bool:
    if not isinstance(value, str):
        return False
    lowered = value.lower()
    if any(marker in lowered for marker in FORBIDDEN_SCOPE_MARKERS):
        return False
    words = set(lowered.replace("-", " ").split())
    return "bounded" in words and "unbounded" not in words


def trace_ids_for_op(trace_text: str, op: str) -> set[str]:
    list_name_by_op = {
        "parse_tx": "parseOuts",
        "sighash_v1": "sighashOuts",
        "retarget_v1": "powOuts",
        "utxo_apply_basic": "utxoBasicOuts",
    }
    list_name = list_name_by_op.get(op)
    if list_name is None:
        return set()
    marker = f"def {list_name} : List "
    start = trace_text.find(marker)
    if start == -1:
        return set()
    block_start = trace_text.find("[", start)
    block_end = trace_text.find("\n]", block_start)
    if block_start == -1 or block_end == -1:
        return set()
    block = trace_text[block_start:block_end]
    ids: set[str] = set()
    for item in block.split("},"):
        if op == "retarget_v1" and 'op := "retarget_v1"' not in item:
            continue
        marker = 'id := "'
        id_start = item.find(marker)
        if id_start == -1:
            continue
        id_start += len(marker)
        id_end = item.find('"', id_start)
        if id_end != -1:
            ids.add(item[id_start:id_end])
    return ids


def gate_to_camel(gate: str) -> str:
    if not gate.startswith("CV-"):
        raise ValueError(f"invalid gate name: {gate}")
    return "".join(part.lower().capitalize() for part in gate[3:].split("-") if part)


def has_lean_replay_evidence(repo_root: Path, gate: str) -> bool:
    if any(gate.startswith(prefix) for prefix in FORMAL_SKIP_GATE_PREFIXES):
        return False
    conformance_dir = repo_root / "rubin-formal" / "RubinFormal" / "Conformance"
    index_path = conformance_dir / "Index.lean"
    if not index_path.exists():
        return False
    camel = gate_to_camel(gate)
    vectors_file = conformance_dir / f"CV{camel}Vectors.lean"
    replay_file = conformance_dir / f"CV{camel}Replay.lean"
    index_text = index_path.read_text(encoding="utf-8")
    return (
        vectors_file.exists()
        and replay_file.exists()
        and has_canonical_import(index_text, f"import RubinFormal.Conformance.CV{camel}Vectors")
        and has_canonical_import(index_text, f"import RubinFormal.Conformance.CV{camel}Replay")
    )


def fail(msg: str) -> int:
    print(f"ERROR: {msg}", file=sys.stderr)
    return 1


def theorem_declared_in_file(path: Path, theorem: str) -> bool:
    return theorem in declared_lean_theorems_in_text(path.read_text(encoding="utf-8"))


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
    if "package_maturity" in bridge:
        return fail("package_maturity belongs only in rubin-formal/proof_coverage.json")
    source_rebind_errors = validate_source_rebind(bridge)
    if source_rebind_errors:
        for err in source_rebind_errors:
            print(f"ERROR: {err}", file=sys.stderr)
        return 1

    rows = bridge.get("critical_ops")
    if not isinstance(rows, list) or len(rows) == 0:
        return fail("refinement_bridge.json: critical_ops[] must be non-empty")

    matrix_text = matrix_path.read_text(encoding="utf-8")
    executable_ops = parse_executable_ops(matrix_text)
    gate_ops = parse_fixture_gates(fixtures_dir)
    declared_theorems = declared_lean_theorems(repo_root / "rubin-formal" / "RubinFormal")
    trace_path = repo_root / TRACE_SOURCE_FILE
    if not trace_path.exists():
        return fail("rubin-formal/RubinFormal/Refinement/GoTraceV1.lean not found")
    trace_text = trace_path.read_text(encoding="utf-8")

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
        evidence_level = row.get("evidence_level")
        proof_trust = row.get("proof_trust")
        traced_vector_ids = row.get("traced_vector_ids")
        trace_source_file = row.get("trace_source_file")
        scope = row.get("contract_scope")
        limitations = row.get("limitations")

        if not isinstance(op, str) or not op:
            print(f"ERROR: critical_ops[{idx}] missing op", file=sys.stderr)
            bad = True
            continue
        if not isinstance(theorem, str) or not theorem:
            print(f"ERROR: missing model_theorem for op `{op}`", file=sys.stderr)
            bad = True
        elif theorem not in declared_theorems:
            print(f"ERROR: theorem `{theorem}` not found in rubin-formal Lean files", file=sys.stderr)
            bad = True

        lean_path = repo_root / lean_file if isinstance(lean_file, str) else None
        if lean_path is None or not lean_path.exists():
            print(f"ERROR: lean_file missing for op `{op}`: {lean_file}", file=sys.stderr)
            bad = True
        elif isinstance(theorem, str) and theorem and not theorem_declared_in_file(lean_path, theorem):
            print(f"ERROR: theorem `{theorem}` is not declared in lean_file `{lean_file}`", file=sys.stderr)
            bad = True

        if evidence_level not in ALLOWED_EVIDENCE_LEVEL:
            print(
                f"ERROR: invalid evidence_level for op `{op}`: {evidence_level}; "
                f"expected one of {sorted(ALLOWED_EVIDENCE_LEVEL)}",
                file=sys.stderr,
            )
            bad = True
            continue
        if proof_trust not in ALLOWED_PROOF_TRUST:
            print(
                f"ERROR: invalid proof_trust for op `{op}`: {proof_trust}; expected one of {sorted(ALLOWED_PROOF_TRUST)}",
                file=sys.stderr,
            )
            bad = True

        if not isinstance(scope, str) or not scope:
            print(f"ERROR: contract_scope for op `{op}` must be a non-empty string", file=sys.stderr)
            bad = True
        if not valid_string_list(limitations):
            print(f"ERROR: limitations[] for op `{op}` must be a string list", file=sys.stderr)
            bad = True

        if evidence_level == "machine_checked_contract":
            if op not in executable_ops:
                print(f"ERROR: contract op `{op}` is not executable in conformance/MATRIX.md", file=sys.stderr)
                bad = True
            if not isinstance(gate, str) or gate not in gate_ops:
                print(f"ERROR: contract gate `{gate}` not found in fixtures", file=sys.stderr)
                bad = True
            elif op not in gate_ops[gate]:
                print(f"ERROR: contract op `{op}` is not present in fixture gate `{gate}`", file=sys.stderr)
                bad = True
            elif not has_lean_replay_evidence(repo_root, gate):
                print(f"ERROR: contract gate `{gate}` lacks imported Lean replay evidence", file=sys.stderr)
                bad = True
            if not states_bounded_scope(scope):
                print(f"ERROR: contract_scope for contract op `{op}` must state the bounded claim", file=sys.stderr)
                bad = True
            if not valid_non_empty_string_list(limitations):
                print(f"ERROR: contract limitations[] for op `{op}` must be non-empty", file=sys.stderr)
                bad = True
        elif evidence_level == "machine_checked_universal":
            if "universal" not in scope.lower():
                print(f"ERROR: universal contract_scope for op `{op}` must state its universal ceiling", file=sys.stderr)
                bad = True
        elif evidence_level == "machine_checked_assumption_backed":
            assumption_text = f"{scope} {' '.join(limitations) if isinstance(limitations, list) else ''}".lower()
            if not any(marker in assumption_text for marker in ("assumption", "depends", "collision", "reduction")):
                print(f"ERROR: assumption-backed op `{op}` must name its assumption/reduction ceiling", file=sys.stderr)
                bad = True
            if not valid_non_empty_string_list(limitations):
                print(f"ERROR: assumption-backed limitations[] for op `{op}` must be non-empty", file=sys.stderr)
                bad = True
        elif evidence_level == "machine_checked_behavioral":
            if "behavioral" not in scope.lower():
                print(f"ERROR: behavioral contract_scope for op `{op}` must state its behavioral ceiling", file=sys.stderr)
                bad = True
            if not valid_non_empty_string_list(limitations):
                print(f"ERROR: behavioral limitations[] for op `{op}` must be non-empty", file=sys.stderr)
                bad = True

        claims_trace_evidence = trace_source_file is not None or traced_vector_ids is not None
        if claims_trace_evidence:
            if evidence_level != "machine_checked_contract":
                print(f"ERROR: trace-backed op `{op}` must use machine_checked_contract evidence", file=sys.stderr)
                bad = True
            if trace_source_file != TRACE_SOURCE_FILE:
                print(
                    f"ERROR: trace_source_file for op `{op}` must be `{TRACE_SOURCE_FILE}`, got {trace_source_file}",
                    file=sys.stderr,
                )
                bad = True
            if not valid_non_empty_string_list(traced_vector_ids):
                print(f"ERROR: traced_vector_ids[] for op `{op}` must be a non-empty string list", file=sys.stderr)
                bad = True
            else:
                expected_trace_ids = trace_ids_for_op(trace_text, op)
                actual_trace_ids = set(traced_vector_ids)
                if not expected_trace_ids:
                    print(f"ERROR: no imported trace rows found for trace-backed op `{op}`", file=sys.stderr)
                    bad = True
                elif actual_trace_ids != expected_trace_ids:
                    print(
                        f"ERROR: traced_vector_ids[] for op `{op}` drift: expected {sorted(expected_trace_ids)}, "
                        f"got {sorted(actual_trace_ids)}",
                        file=sys.stderr,
                    )
                    bad = True
        elif "traced_vector_ids" in row or "trace_source_file" in row:
            print(f"ERROR: incomplete trace evidence fields for op `{op}`", file=sys.stderr)
            bad = True

    if bad:
        return 1

    print(f"OK: formal refinement bridge valid ({len(rows)} critical ops mapped).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
