#!/usr/bin/env python3
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

from check_formal_coverage import (
    ALLOWED_PROOF_TRUST,
    blank_lean_comments_and_strings,
    declared_lean_theorems,
    declared_lean_theorems_in_text,
    has_canonical_import,
    validate_active_path_manifest,
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
REQUIRED_TRACE_OPS = frozenset({"parse_tx", "sighash_v1", "retarget_v1", "utxo_apply_basic"})
TRACE_LIST_NAME_BY_OP = {
    "parse_tx": "parseOuts",
    "sighash_v1": "sighashOuts",
    "retarget_v1": "powOuts",
    "utxo_apply_basic": "utxoBasicOuts",
}


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


def _trace_list_block(live_text: str, list_name: str) -> tuple[int, int] | None:
    definition_re = re.compile(
        rf"^\s*def\s+{re.escape(list_name)}\s*:\s*List\b", re.MULTILINE
    )
    definitions = list(definition_re.finditer(live_text))
    if len(definitions) != 1:
        return None
    assignment = live_text.find(":=", definitions[0].end())
    if assignment == -1:
        return None
    opening = live_text.find("[", assignment + 2)
    if opening == -1:
        return None
    depth = 0
    for index in range(opening, len(live_text)):
        if live_text[index] == "[":
            depth += 1
        elif live_text[index] == "]":
            depth -= 1
            if depth == 0:
                return opening, index + 1
            if depth < 0:
                return None
    return None


def _trace_record_ranges(live_text: str, block_start: int, block_end: int) -> list[tuple[int, int]] | None:
    records: list[tuple[int, int]] = []
    depth = 0
    record_start: int | None = None
    for index in range(block_start + 1, block_end - 1):
        if live_text[index] == "{":
            if depth == 0:
                record_start = index
            depth += 1
        elif live_text[index] == "}":
            depth -= 1
            if depth < 0:
                return None
            if depth == 0 and record_start is not None:
                records.append((record_start, index + 1))
                record_start = None
    return records if depth == 0 else None


def _ordinary_string_value(source: str, start: int, end: int) -> str | None:
    if start >= end or source[start] != '"':
        return None
    value: list[str] = []
    index = start + 1
    while index < end:
        ch = source[index]
        if ch == "\\" and index + 1 < end:
            value.append(source[index + 1])
            index += 2
            continue
        if ch == '"':
            return "".join(value)
        value.append(ch)
        index += 1
    return None


def _live_string_field(source: str, live_text: str, start: int, end: int, field: str) -> str | None:
    match = re.search(rf"\b{re.escape(field)}\s*:=", live_text[start:end])
    if match is None:
        return None
    value_start = start + match.end()
    while value_start < end and source[value_start].isspace():
        value_start += 1
    return _ordinary_string_value(source, value_start, end)


def trace_ids_for_op(trace_text: str, op: str) -> set[str] | None:
    list_name = TRACE_LIST_NAME_BY_OP.get(op)
    if list_name is None:
        return set()
    live_text = blank_lean_comments_and_strings(trace_text)
    block = _trace_list_block(live_text, list_name)
    if block is None:
        return None
    records = _trace_record_ranges(live_text, *block)
    if records is None:
        return None
    ids: set[str] = set()
    for record_start, record_end in records:
        identifier = _live_string_field(trace_text, live_text, record_start, record_end, "id")
        if identifier is None:
            return None
        if op == "retarget_v1":
            record_op = _live_string_field(trace_text, live_text, record_start, record_end, "op")
            if record_op is None:
                return None
            if record_op != "retarget_v1":
                continue
        ids.add(identifier)
    return ids


def trace_binding_errors(
    op: str, evidence_level: object, trace_source_file: object, traced_vector_ids: object, trace_text: str
) -> list[str]:
    required = op in REQUIRED_TRACE_OPS
    declared = trace_source_file is not None or traced_vector_ids is not None
    if not required and not declared:
        return []
    errors: list[str] = []
    if required and not declared:
        return [f"required trace evidence missing for op `{op}`"]
    if evidence_level != "machine_checked_contract":
        errors.append(f"trace-backed op `{op}` must use machine_checked_contract evidence")
    if trace_source_file != TRACE_SOURCE_FILE:
        errors.append(f"trace_source_file for op `{op}` must be `{TRACE_SOURCE_FILE}`, got {trace_source_file}")
    if not valid_non_empty_string_list(traced_vector_ids):
        errors.append(f"traced_vector_ids[] for op `{op}` must be a non-empty string list")
    else:
        actual = set(traced_vector_ids)
        list_name = TRACE_LIST_NAME_BY_OP.get(op)
        if list_name is None:
            errors.append(f"no trace list mapping registered for trace-backed op `{op}`")
            return errors
        expected = trace_ids_for_op(trace_text, op)
        if expected is None:
            errors.append(f"trace list `{list_name}` must have exactly one live definition with extractable rows")
        elif not expected:
            errors.append(f"no imported trace rows found for trace-backed op `{op}`")
        elif actual != expected:
            errors.append(f"traced_vector_ids[] for op `{op}` drift: expected {sorted(expected)}, got {sorted(actual)}")
    return errors

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
    source_rebind_errors.extend(validate_active_path_manifest(repo_root, bridge))
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
    seen_ops: set[str] = set()
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
        seen_ops.add(op)
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

        for error in trace_binding_errors(op, evidence_level, trace_source_file, traced_vector_ids, trace_text):
            print(f"ERROR: {error}", file=sys.stderr)
            bad = True

    for op in sorted(REQUIRED_TRACE_OPS - seen_ops):
        print(f"ERROR: required trace op missing from refinement_bridge.json: `{op}`", file=sys.stderr)
        bad = True

    if bad:
        return 1

    print(f"OK: formal refinement bridge valid ({len(rows)} critical ops mapped).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
