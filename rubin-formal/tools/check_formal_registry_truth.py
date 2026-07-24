#!/usr/bin/env python3
from __future__ import annotations

import json
import re
import subprocess
import sys
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Optional, Tuple


REPO_PREFIX = "rubin-formal/"
PROOF_TRUST_KERNEL = "kernel_checked"
PROOF_TRUST_COMPILER = "compiler_trusted"
ALLOWED_PROOF_TRUST = {PROOF_TRUST_KERNEL, PROOF_TRUST_COMPILER}
# proof_trust distinguishes only compiler/evaluator closure: ordinary Lean
# foundations such as propext, Quot.sound, and Classical.choice remain possible.
COMPILER_TRUST_AXIOM = "Lean.ofReduceBool"
ALLOWED_AXIOMS = {
    "propext",
    "Quot.sound",
    "Classical.choice",
    COMPILER_TRUST_AXIOM,
}

# Intentionally narrow shared-op parity scope after Q-FORMAL-REGISTRY-EVIDENCE-LEVEL-ALIGN-01.
# `sighash_v1`, `retarget_v1`, and `fork_choice_select` remain honest supplemental bridge lanes whose
# bridge evidence level is narrower than the broader section row on purpose. `weight_accounting`
# remains subject to row-presence and evidence-level parity, but intentionally retains bounded
# compiler-trusted CV support in its bridge lane while its proof_coverage universal row contains only
# kernel-checked claim-bearing theorems.
SHARED_OP_PARITY = {
    "da_set_integrity": "da_set_integrity",
    "weight_accounting": "weight_accounting",
}
EXPECTED_COVERAGE_TRUST = (32, 520, 505, 15, 52, 49)
EXPECTED_UNIVERSAL_TRUST = (24, 480, 12, 43, 40)
EXPECTED_KERNEL_THEOREM_COMPLEMENT = (468, 456)
EXPECTED_BRIDGE_TRUST = (12, 165, 162, 9, 21, 21)
EXPECTED_UNAFFECTED_UNIVERSAL = {
    "block_timestamp_rules",
    "consensus_constants_witness_lengths_pre_rotation",
    "consensus_error_codes",
    "parallel_validation_equivalence",
    "replay_domain_checks",
    "spend_gate_bridge",
    "create_side_live_gate",
    "feature_activation_fsm",
    "transaction_identifiers",
    "transaction_wire",
    "value_conservation",
    "weight_accounting",
}
EXPECTED_AFFECTED_BRIDGE_REFS = {
    "da_set_integrity": 1,
    "fork_choice_select": 2,
    "native_rotation": 1,
    "native_suite_rotation": 2,
    "parse_tx": 1,
    "retarget_v1": 9,
    "sighash_v1": 3,
    "utxo_apply_basic": 1,
    "weight_accounting": 1,
}

DECL_KINDS = ("theorem", "lemma", "def", "abbrev")
TheoremRef = Tuple[str, Optional[str]]

NAMESPACE_RE = re.compile(r"^\s*namespace\s+([A-Za-z0-9_'.]+)\s*$")
SECTION_RE = re.compile(r"^\s*section(?:\s+([A-Za-z0-9_'.]+))?\s*$")
END_RE = re.compile(r"^\s*end(?:\s+([A-Za-z0-9_'.]+))?\s*$")
IMPORT_RE = re.compile(r"^\s*import\s+([A-Za-z][A-Za-z0-9_']*(?:\.[A-Za-z][A-Za-z0-9_']*)*)\s*$", re.MULTILINE)
DECLARATION_RE = re.compile(
    r"^\s*(?:@\[[^\]]+\]\s*)*"
    r"(?P<modifiers>(?:(?:private|protected|noncomputable|unsafe|partial)\s+)*)"
    r"(?:theorem|lemma|def|abbrev)\s+"
    r"(?P<name>[A-Za-z0-9_'?!]+(?:\.[A-Za-z0-9_'?!]+)*)"
    r"(?:\.\{[^}]+\})?"
    r"(?=\s|$|[:({\[])"
)


@dataclass(frozen=True)
class ScopeFrame:
    kind: str
    label: Optional[str]
    parts: tuple[str, ...]


def fail(msg: str) -> int:
    print(f"ERROR: {msg}", file=sys.stderr)
    return 1


def _scan_lean(text: str, *, blank_strings: bool) -> str:
    out: list[str] = []
    i = 0
    while i < len(text):
        start, keep = i, None
        if text[i] == "r":
            quote = i + 1
            while quote < len(text) and text[quote] == "#": quote += 1
            if quote < len(text) and text[quote] == '"':
                end = text.find('"' + "#" * (quote - i - 1), quote + 1)
                i = len(text) if end < 0 else end + quote - i
                keep = not blank_strings
        if keep is None and text[i] == '"':
            i += 1
            while i < len(text) and text[i] != '"': i += 2 if text[i] == "\\" else 1
            i += i < len(text)
            keep = not blank_strings
        if keep is None and text.startswith("--", i):
            end = text.find("\n", i)
            i = len(text) if end < 0 else end
            keep = False
        if keep is None and text.startswith("/-", i):
            depth = 1
            i += 2
            while i < len(text) and depth:
                if text.startswith("/-", i):
                    depth, i = depth + 1, i + 2
                elif text.startswith("-/", i):
                    depth, i = depth - 1, i + 2
                else: i += 1
            keep = False
        if keep is None:
            out.append(text[i]); i += 1
        elif keep:
            out.extend(text[start:i])
        else:
            out.extend("\n" if ch == "\n" else " " for ch in text[start:i])
    return "".join(out)


def strip_lean_comments(text: str) -> str:
    """Blank Lean comments while preserving quoted strings and line positions."""
    return _scan_lean(text, blank_strings=False)


def blank_lean_comments_and_strings(text: str) -> str:
    """Blank Lean comments and quoted/raw strings while preserving line positions."""
    return _scan_lean(text, blank_strings=True)


def source_import_reachability(repo_root: Path) -> tuple[set[Path], list[str]]:
    root = repo_root / "RubinFormal.lean"
    if not root.exists():
        return set(), ["formal root source missing: RubinFormal.lean"]

    reachable: set[Path] = set()
    errors: list[str] = []
    pending = [root]
    while pending:
        path = pending.pop()
        resolved = path.resolve()
        if resolved in reachable:
            continue
        reachable.add(resolved)
        for module in IMPORT_RE.findall(blank_lean_comments_and_strings(path.read_text(encoding="utf-8"))):
            if module == "RubinFormal":
                imported = root
            elif module.startswith("RubinFormal."):
                imported = repo_root / f"{module.replace('.', '/')}.lean"
            else:
                continue
            if not imported.exists():
                errors.append(f"root import missing source: {module} ({rel_repo_path(repo_root, imported)})")
            else:
                pending.append(imported)
    return reachable, sorted(set(errors))


def _current_namespace_parts(stack: list[ScopeFrame]) -> list[str]:
    parts: list[str] = []
    for frame in stack:
        if frame.kind == "namespace":
            parts.extend(frame.parts)
    return parts


def _qualify_decl_name(local_name: str, namespace_parts: list[str]) -> str:
    if local_name.startswith("_root_."):
        return local_name[len("_root_.") :]
    if namespace_parts:
        return ".".join([*namespace_parts, local_name])
    return local_name


def _pop_scope(stack: list[ScopeFrame], label: Optional[str]) -> None:
    if not stack:
        return
    if label is None:
        stack.pop()
        return
    for idx in range(len(stack) - 1, -1, -1):
        if stack[idx].label == label:
            del stack[idx:]
            return
    stack.pop()


def extract_declared_names(text: str) -> set[str]:
    stripped = strip_lean_comments(text)
    stack: list[ScopeFrame] = []
    names: set[str] = set()

    for line in stripped.splitlines():
        if match := NAMESPACE_RE.match(line):
            label = match.group(1)
            parts = tuple(part for part in label.split(".") if part)
            stack.append(ScopeFrame("namespace", label, parts))
            continue
        if match := SECTION_RE.match(line):
            stack.append(ScopeFrame("section", match.group(1), ()))
            continue
        if match := END_RE.match(line):
            _pop_scope(stack, match.group(1))
            continue
        if match := DECLARATION_RE.match(line):
            if "private" in match.group("modifiers").split():
                continue
            names.add(_qualify_decl_name(match.group("name"), _current_namespace_parts(stack)))

    return names


def rel_repo_path(repo_root: Path, path: Path) -> str:
    return str(path.resolve().relative_to(repo_root.resolve()))


def lean_repo_path(repo_root: Path, rel_path: str) -> Path:
    if not rel_path.startswith(REPO_PREFIX):
        raise ValueError(
            f"non-canonical path in registry: {rel_path!r} "
            f"(must start with {REPO_PREFIX!r})"
        )
    source_root = (repo_root / "RubinFormal").resolve()
    candidate = repo_root / rel_path[len(REPO_PREFIX) :]
    if not candidate.resolve().is_relative_to(source_root):
        raise ValueError(
            f"registered file escapes RubinFormal source root: {rel_path}"
        )
    return candidate


def try_lean_repo_path(repo_root: Path, rel_path: str) -> Optional[Path]:
    try:
        return lean_repo_path(repo_root, rel_path)
    except ValueError:
        return None


def olean_path(repo_root: Path, rel_path: str) -> Path:
    if not rel_path.startswith(REPO_PREFIX):
        raise ValueError(
            f"non-canonical path in registry: {rel_path!r} "
            f"(must start with {REPO_PREFIX!r})"
        )
    normalized = rel_path[len(REPO_PREFIX) :]
    if not normalized.startswith("RubinFormal/") or not normalized.endswith(".lean"):
        raise ValueError(f"registered file is outside RubinFormal build graph surface: {rel_path}")
    source_path = lean_repo_path(repo_root, rel_path)
    source_root = (repo_root / "RubinFormal").resolve()
    source_suffix = source_path.resolve().relative_to(source_root).with_suffix(".olean")
    build_root = repo_root / ".lake" / "build" / "lib" / "RubinFormal"
    candidate = build_root / source_suffix
    if not candidate.resolve().is_relative_to(build_root.resolve()):
        raise ValueError(
            f"derived olean path escapes RubinFormal build root: {rel_path}"
        )
    return candidate


def coverage_paths(row: dict) -> set[str]:
    refs: set[str] = set()
    row_file = row.get("file")
    if isinstance(row_file, str):
        refs.add(row_file)
    theorem_files = row.get("theorem_files", {})
    if isinstance(theorem_files, dict):
        for path in theorem_files.values():
            if isinstance(path, str):
                refs.add(path)
    return refs


def bridge_paths(row: dict) -> set[str]:
    refs: set[str] = set()
    for key in ("lean_file",):
        path = row.get(key)
        if isinstance(path, str):
            refs.add(path)
    theorem_files = row.get("supporting_theorem_files", {})
    if isinstance(theorem_files, dict):
        for path in theorem_files.values():
            if isinstance(path, str):
                refs.add(path)
    return refs


def iter_registry_paths(coverage: dict, bridge: dict) -> set[str]:
    refs: set[str] = set()
    for row in coverage.get("coverage", []):
        if isinstance(row, dict):
            refs.update(coverage_paths(row))
    for row in bridge.get("critical_ops", []):
        if isinstance(row, dict):
            refs.update(bridge_paths(row))
    return refs


def coverage_theorems(row: dict) -> list[TheoremRef]:
    refs: list[TheoremRef] = []
    theorem_files = row.get("theorem_files", {})
    theorem_map = theorem_files if isinstance(theorem_files, dict) else {}
    for theorem in row.get("theorems", []):
        if isinstance(theorem, str):
            refs.append((theorem, theorem_map.get(theorem)))
    return refs


def coverage_theorem_file_paths(coverage: dict) -> dict[str, set[str]]:
    paths: dict[str, set[str]] = {}
    for row in coverage.get("coverage", []):
        if not isinstance(row, dict):
            continue
        theorem_files = row.get("theorem_files", {})
        if not isinstance(theorem_files, dict):
            continue
        for theorem in row.get("theorems", []):
            path = theorem_files.get(theorem) if isinstance(theorem, str) else None
            if isinstance(path, str):
                paths.setdefault(theorem, set()).add(path)
    return paths


def bridge_supporting_theorem_bindings(
    row: dict, coverage_paths: dict[str, set[str]]
) -> tuple[dict[str, str], list[str]]:
    op = row.get("op", "<unknown>")
    supporting = {theorem for theorem in row.get("supporting_theorems", []) if isinstance(theorem, str)}
    direct = row.get("supporting_theorem_files", {})
    if not isinstance(direct, dict):
        return {}, [f"refinement_bridge `{op}` supporting_theorem_files must be an object"]
    errors: list[str] = []
    for theorem in direct:
        if not isinstance(theorem, str) or theorem not in supporting:
            errors.append(f"refinement_bridge `{op}` has unexpected supporting theorem binding `{theorem}`")
    bindings: dict[str, str] = {}
    for theorem in supporting:
        covered = coverage_paths.get(theorem, set())
        explicit = direct.get(theorem)
        if len(covered) > 1:
            errors.append(
                f"refinement_bridge `{op}` supporting theorem `{theorem}` has conflicting proof_coverage bindings: {sorted(covered)}"
            )
            continue
        if covered:
            path = next(iter(covered))
            if explicit is not None:
                errors.append(
                    f"refinement_bridge `{op}` supporting theorem `{theorem}` has direct binding but "
                    f"proof_coverage already binds it to `{path}`"
                )
                continue
            bindings[theorem] = path
        elif explicit is not None and not isinstance(explicit, str):
            errors.append(f"refinement_bridge `{op}` supporting theorem `{theorem}` has non-string file binding")
        elif isinstance(explicit, str):
            bindings[theorem] = explicit
        else:
            errors.append(f"refinement_bridge `{op}` supporting theorem `{theorem}` has no exact Lean-file binding")
    return bindings, errors


def bridge_theorems(row: dict, supporting_bindings: Optional[dict[str, str]] = None) -> list[TheoremRef]:
    refs: list[TheoremRef] = []
    lean_file = row.get("lean_file") if isinstance(row.get("lean_file"), str) else None
    model_theorem = row.get("model_theorem")
    if isinstance(model_theorem, str):
        refs.append((model_theorem, lean_file))
    for theorem in row.get("supporting_theorems", []):
        if isinstance(theorem, str):
            refs.append((theorem, supporting_bindings.get(theorem) if supporting_bindings else None))
    return refs


def iter_registered_theorems_with_binding_errors(
    coverage: dict, bridge: dict
) -> tuple[list[TheoremRef], list[TheoremRef], list[str]]:
    coverage_refs: list[TheoremRef] = []
    bridge_refs: list[TheoremRef] = []
    for row in coverage.get("coverage", []):
        if isinstance(row, dict):
            coverage_refs.extend(coverage_theorems(row))
    binding_errors: list[str] = []
    coverage_paths = coverage_theorem_file_paths(coverage)
    for row in bridge.get("critical_ops", []):
        if isinstance(row, dict):
            bindings, errors = bridge_supporting_theorem_bindings(row, coverage_paths)
            bridge_refs.extend(bridge_theorems(row, bindings))
            binding_errors.extend(errors)
    return coverage_refs, bridge_refs, binding_errors


def iter_registered_theorems(
    coverage: dict, bridge: dict
) -> tuple[list[TheoremRef], list[TheoremRef]]:
    """Return registered theorem references using the historical public shape."""
    coverage_refs, bridge_refs, _ = iter_registered_theorems_with_binding_errors(coverage, bridge)
    return coverage_refs, bridge_refs


def validate_registered_paths(repo_root: Path, registered_paths: set[str]) -> list[str]:
    errors: list[str] = []
    existing_paths: list[tuple[str, Path]] = []
    for declared_path in sorted(registered_paths):
        abs_path = try_lean_repo_path(repo_root, declared_path)
        if abs_path is None:
            errors.append(f"unsupported non-repo path in registry: {declared_path}")
            continue
        if not abs_path.exists():
            errors.append(f"referenced Lean file does not exist: {declared_path}")
            continue
        existing_paths.append((declared_path, abs_path))

    reachable, reachability_errors = source_import_reachability(repo_root) if existing_paths else (set(), [])
    errors.extend(reachability_errors)
    for declared_path, abs_path in existing_paths:
        if abs_path.resolve() not in reachable:
            errors.append(
                "registered Lean file is not reachable from RubinFormal.lean source imports: "
                f"{declared_path}"
            )
            continue
        try:
            built = olean_path(repo_root, declared_path)
        except ValueError as exc:
            errors.append(str(exc))
            continue
        if not built.exists():
            errors.append(
                "registered Lean file is outside the default build graph or failed to build: "
                f"{declared_path} (missing {rel_repo_path(repo_root, built)})"
            )
    return errors


def theorem_lookup_error(label: str, theorem: str, declared_path: Optional[str]) -> str:
    if label == "proof_coverage" and declared_path:
        return f"proof_coverage theorem `{theorem}` not found in declared file `{declared_path}`"
    location = declared_path if declared_path else "RubinFormal/"
    return f"{label} theorem `{theorem}` not found in `{location}`"


def validate_single_theorem_ref(
    theorem: str,
    declared_path: Optional[str],
    theorem_exists_in_file,
    theorem_exists_anywhere,
    *,
    label: str,
    allow_global_fallback: bool,
) -> Optional[str]:
    if label == "proof_coverage" and not declared_path:
        return f"proof_coverage theorem `{theorem}` has no exact theorem_files mapping"
    if declared_path:
        declared_result = theorem_exists_in_file(theorem, declared_path)
        if declared_result is None or declared_result:
            return None
    if theorem_exists_anywhere(theorem) and (allow_global_fallback or not declared_path):
        return None
    return theorem_lookup_error(label, theorem, declared_path)


def validate_theorem_refs(
    refs: list[TheoremRef],
    theorem_exists_in_file,
    theorem_exists_anywhere,
    *,
    label: str,
    allow_global_fallback: bool,
) -> list[str]:
    errors: list[str] = []
    for theorem, declared_path in refs:
        error = validate_single_theorem_ref(
            theorem,
            declared_path,
            theorem_exists_in_file,
            theorem_exists_anywhere,
            label=label,
            allow_global_fallback=allow_global_fallback,
        )
        if error is not None:
            errors.append(error)
    return errors


def indexed_rows(rows: list[dict], key: str) -> dict[str, dict]:
    return {
        row[key]: row
        for row in rows
        if isinstance(row, dict) and isinstance(row.get(key), str)
    }


def validate_shared_op_parity(
    coverage_rows: dict[str, dict], bridge_rows: dict[str, dict]
) -> list[str]:
    errors: list[str] = []
    for op, section_key in SHARED_OP_PARITY.items():
        bridge_row = bridge_rows.get(op)
        coverage_row = coverage_rows.get(section_key)
        if bridge_row is None:
            errors.append(f"shared-op parity row missing in refinement_bridge.json: {op}")
            continue
        if coverage_row is None:
            errors.append(f"shared-op parity row missing in proof_coverage.json: {section_key}")
            continue
        for field, label in (("evidence_level", "evidence level"), ("proof_trust", "proof trust")):
            if op == "weight_accounting" and field == "proof_trust":
                # RUB-1037 preserves this intentional mixed evidence lane.
                continue
            if bridge_row.get(field) != coverage_row.get(field):
                errors.append(
                    f"shared-op {label} drift for {op}: refinement_bridge={bridge_row.get(field)} vs "
                    f"proof_coverage[{section_key}]={coverage_row.get(field)}"
                )
    return errors


def parse_axiom_output(output: str, expected: list[str]) -> tuple[dict[str, str], list[str]]:
    trust: dict[str, str] = {}
    cursor = 0
    for theorem in expected:
        while cursor < len(output) and output[cursor].isspace():
            cursor += 1
        no_axioms = f"'{theorem}' does not depend on any axioms"
        if output.startswith(no_axioms, cursor):
            trust[theorem] = PROOF_TRUST_KERNEL
            cursor += len(no_axioms)
            continue
        header = f"'{theorem}' depends on axioms: ["
        if not output.startswith(header, cursor):
            return {}, [f"unparseable #print axioms output for `{theorem}`"]
        start = cursor + len(header)
        end = output.find("]", start)
        if end == -1:
            return {}, [f"unterminated #print axioms output for `{theorem}`"]
        axioms = [name.strip() for name in output[start:end].split(",") if name.strip()]
        unknown_axioms = sorted(set(axioms) - ALLOWED_AXIOMS)
        if unknown_axioms:
            return {}, [
                f"unexpected axiom(s) for `{theorem}`: {', '.join(unknown_axioms)}"
            ]
        trust[theorem] = PROOF_TRUST_COMPILER if COMPILER_TRUST_AXIOM in axioms else PROOF_TRUST_KERNEL
        cursor = end + 1
    if output[cursor:].strip():
        return {}, ["unexpected trailing output from #print axioms"]
    return trust, []


def classify_registered_theorems(repo_root: Path, refs: list[TheoremRef]) -> tuple[dict[str, str], list[str]]:
    theorems = sorted({theorem for theorem, _ in refs})
    if not theorems:
        return {}, []
    source = "\n".join([
        "import RubinFormal",
        "import RubinFormal.ErrorPriority",
        *(f"#print axioms {theorem}" for theorem in theorems),
        "",
    ])
    try:
        result = subprocess.run(
            ["lake", "env", "lean", "--stdin", "--root=."],
            cwd=repo_root,
            input=source,
            text=True,
            capture_output=True,
            check=False,
        )
    except OSError as exc:
        return {}, [f"cannot run lake env lean for proof trust: {exc}"]
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        return {}, [f"lake env lean #print axioms failed ({result.returncode}): {detail}"]
    return parse_axiom_output(result.stdout, theorems)


def _row_theorems(row: dict, extractor) -> list[str]:
    return [theorem for theorem, _ in extractor(row)]


def _trust_facts(rows: list[dict], extractor, theorem_trust: dict[str, str]) -> tuple[int, int, int, int, int, int]:
    row_refs = [_row_theorems(row, extractor) for row in rows]
    refs = [theorem for names in row_refs for theorem in names]
    compiler_refs = [theorem for theorem in refs if theorem_trust[theorem] == PROOF_TRUST_COMPILER]
    compiler_rows = sum(any(theorem_trust[theorem] == PROOF_TRUST_COMPILER for theorem in names) for names in row_refs)
    return len(rows), len(refs), len(set(refs)), compiler_rows, len(compiler_refs), len(set(compiler_refs))


def validate_compiled_proof_trust(coverage: dict, bridge: dict, theorem_trust: dict[str, str]) -> list[str]:
    errors: list[str] = []
    coverage_rows = [row for row in coverage.get("coverage", []) if isinstance(row, dict)]
    bridge_rows = [row for row in bridge.get("critical_ops", []) if isinstance(row, dict)]
    for label, rows, extractor, id_field in (
        ("proof_coverage", coverage_rows, coverage_theorems, "section_key"),
        ("refinement_bridge", bridge_rows, bridge_theorems, "op"),
    ):
        for row in rows:
            names = _row_theorems(row, extractor)
            missing = [name for name in names if name not in theorem_trust]
            identity = row.get(id_field)
            if missing:
                errors.append(f"{label} `{identity}` has unclassified theorem refs: {sorted(set(missing))}")
                continue
            expected = PROOF_TRUST_COMPILER if any(theorem_trust[name] == PROOF_TRUST_COMPILER for name in names) else PROOF_TRUST_KERNEL
            actual = row.get("proof_trust")
            if actual not in ALLOWED_PROOF_TRUST:
                errors.append(f"{label} `{identity}` has invalid proof_trust: {actual}")
            elif actual != expected:
                errors.append(f"{label} `{identity}` proof_trust drift: expected {expected}, got {actual}")
    if errors:
        return errors

    coverage_facts = _trust_facts(coverage_rows, coverage_theorems, theorem_trust)
    if coverage_facts != EXPECTED_COVERAGE_TRUST:
        errors.append(f"coverage compiled-trust facts drift: expected {EXPECTED_COVERAGE_TRUST}, got {coverage_facts}")
    universal_rows = [row for row in coverage_rows if row.get("evidence_level") == "machine_checked_universal"]
    universal_facts = _trust_facts(universal_rows, coverage_theorems, theorem_trust)
    universal_expected = (universal_facts[0], universal_facts[1], universal_facts[3], universal_facts[4], universal_facts[5])
    if universal_expected != EXPECTED_UNIVERSAL_TRUST:
        errors.append(f"universal compiled-trust facts drift: expected {EXPECTED_UNIVERSAL_TRUST}, got {universal_expected}")
    unaffected = {
        row.get("section_key") for row in universal_rows
        if all(theorem_trust[name] == PROOF_TRUST_KERNEL for name in _row_theorems(row, coverage_theorems))
    }
    if unaffected != EXPECTED_UNAFFECTED_UNIVERSAL:
        errors.append(f"unaffected universal rows drift: expected {sorted(EXPECTED_UNAFFECTED_UNIVERSAL)}, got {sorted(unaffected)}")
    coverage_refs = [theorem for row in coverage_rows for theorem in _row_theorems(row, coverage_theorems)]
    kernel_refs = [theorem for theorem in coverage_refs if theorem_trust[theorem] == PROOF_TRUST_KERNEL]
    kernel_facts = (len(kernel_refs), len(set(kernel_refs)))
    if kernel_facts != EXPECTED_KERNEL_THEOREM_COMPLEMENT:
        errors.append(f"kernel theorem-level complement drift: expected {EXPECTED_KERNEL_THEOREM_COMPLEMENT}, got {kernel_facts}")
    bridge_facts = _trust_facts(bridge_rows, bridge_theorems, theorem_trust)
    if bridge_facts != EXPECTED_BRIDGE_TRUST:
        errors.append(f"bridge compiled-trust facts drift: expected {EXPECTED_BRIDGE_TRUST}, got {bridge_facts}")
    affected_bridge_refs = {
        row.get("op"): sum(theorem_trust[name] == PROOF_TRUST_COMPILER for name in _row_theorems(row, bridge_theorems))
        for row in bridge_rows
    }
    affected_bridge_refs = {op: count for op, count in affected_bridge_refs.items() if count}
    if affected_bridge_refs != EXPECTED_AFFECTED_BRIDGE_REFS:
        errors.append(f"affected bridge theorem refs drift: expected {EXPECTED_AFFECTED_BRIDGE_REFS}, got {affected_bridge_refs}")
    return errors


def load_registry_inputs(repo_root: Path) -> tuple[dict, dict, list[Path]]:
    coverage_path = repo_root / "proof_coverage.json"
    bridge_path = repo_root / "refinement_bridge.json"
    if not coverage_path.exists():
        raise FileNotFoundError("proof_coverage.json not found")
    if not bridge_path.exists():
        raise FileNotFoundError("refinement_bridge.json not found")
    def load_json(path: Path) -> dict:
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            raise ValueError(f"{path.name}: invalid JSON") from None
        except UnicodeDecodeError:
            raise ValueError(f"{path.name}: invalid UTF-8") from None

    coverage = load_json(coverage_path)
    bridge = load_json(bridge_path)
    lean_files = sorted((repo_root / "RubinFormal").rglob("*.lean"))
    if not lean_files:
        raise FileNotFoundError("no Lean files found under RubinFormal/")
    return coverage, bridge, lean_files


def theorem_lookups(repo_root: Path, lean_files: list[Path]):
    @lru_cache(maxsize=None)
    def file_text(path: Path) -> str:
        return path.read_text(encoding="utf-8")

    @lru_cache(maxsize=None)
    def declared_names(path: Path) -> frozenset[str]:
        return frozenset(extract_declared_names(file_text(path)))

    @lru_cache(maxsize=None)
    def theorem_exists_anywhere(qualified: str) -> bool:
        return any(qualified in declared_names(path) for path in lean_files)

    @lru_cache(maxsize=None)
    def theorem_exists_in_file(qualified: str, rel_path: str) -> Optional[bool]:
        abs_path = try_lean_repo_path(repo_root, rel_path)
        if abs_path is None:
            return None
        if not abs_path.exists():
            return False
        return qualified in declared_names(abs_path)

    return theorem_exists_anywhere, theorem_exists_in_file


def collect_registry_errors(
    repo_root: Path,
    coverage: dict,
    bridge: dict,
    theorem_exists_anywhere,
    theorem_exists_in_file,
) -> tuple[set[str], list[TheoremRef], list[TheoremRef], list[str]]:
    registered_paths = iter_registry_paths(coverage, bridge)
    coverage_theorem_refs, bridge_theorem_refs, binding_errors = iter_registered_theorems_with_binding_errors(
        coverage, bridge
    )
    coverage_rows = indexed_rows(coverage.get("coverage", []), "section_key")
    bridge_rows = indexed_rows(bridge.get("critical_ops", []), "op")
    errors = []
    if coverage.get("source_rebind") != bridge.get("source_rebind"):
        errors.append("source_rebind manifest drift between proof_coverage.json and refinement_bridge.json")
    errors.extend(binding_errors)
    errors.extend(validate_registered_paths(repo_root, registered_paths))
    errors.extend(
        validate_theorem_refs(
            coverage_theorem_refs,
            theorem_exists_in_file,
            theorem_exists_anywhere,
            label="proof_coverage",
            allow_global_fallback=False,
        )
    )
    errors.extend(
        validate_theorem_refs(
            bridge_theorem_refs,
            theorem_exists_in_file,
            theorem_exists_anywhere,
            label="refinement_bridge",
            allow_global_fallback=False,
        )
    )
    errors.extend(validate_shared_op_parity(coverage_rows, bridge_rows))
    return registered_paths, coverage_theorem_refs, bridge_theorem_refs, errors


def main() -> int:
    repo_root = Path(__file__).resolve().parents[1]
    try:
        coverage, bridge, lean_files = load_registry_inputs(repo_root)
    except (FileNotFoundError, ValueError) as exc:
        return fail(str(exc))

    theorem_exists_anywhere, theorem_exists_in_file = theorem_lookups(repo_root, lean_files)
    registered_paths, coverage_theorem_refs, bridge_theorem_refs, errors = collect_registry_errors(
        repo_root, coverage, bridge, theorem_exists_anywhere, theorem_exists_in_file
    )
    if errors:
        for msg in errors:
            print(f"ERROR: {msg}", file=sys.stderr)
        return 1

    theorem_trust, trust_errors = classify_registered_theorems(
        repo_root, coverage_theorem_refs + bridge_theorem_refs
    )
    errors = trust_errors or validate_compiled_proof_trust(coverage, bridge, theorem_trust)
    if errors:
        for msg in errors:
            print(f"ERROR: {msg}", file=sys.stderr)
        return 1

    print(
        "OK: formal registry truth passed "
        f"({len(registered_paths)} registered Lean files reachable, "
        f"{len(coverage_theorem_refs)} proof_coverage theorem refs, "
        f"{len(bridge_theorem_refs)} refinement_bridge theorem refs, "
        f"{len(SHARED_OP_PARITY)} shared-op parity rows)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
