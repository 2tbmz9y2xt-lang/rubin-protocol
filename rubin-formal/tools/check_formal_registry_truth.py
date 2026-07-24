#!/usr/bin/env python3
from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Optional, Tuple


REPO_PREFIX = "rubin-formal/"

# Intentionally narrow shared-op parity scope after Q-FORMAL-REGISTRY-EVIDENCE-LEVEL-ALIGN-01.
# `retarget_v1` and `fork_choice_select` remain honest supplemental bridge lanes whose
# bridge evidence level is narrower than the broader section row on purpose.
SHARED_OP_PARITY = {
    "sighash_v1": "sighash_v1",
    "da_set_integrity": "da_set_integrity",
    "weight_accounting": "weight_accounting",
}

DECL_KINDS = ("theorem", "lemma", "def", "abbrev")
TheoremRef = Tuple[str, Optional[str]]

NAMESPACE_RE = re.compile(r"^\s*namespace\s+([A-Za-z0-9_'.]+)\s*$")
SECTION_RE = re.compile(r"^\s*section(?:\s+([A-Za-z0-9_'.]+))?\s*$")
END_RE = re.compile(r"^\s*end(?:\s+([A-Za-z0-9_'.]+))?\s*$")
DECLARATION_RE = re.compile(
    r"^\s*(?:@\[[^\]]+\]\s*)*"
    r"(?:(?:private|protected|noncomputable|unsafe|partial)\s+)*"
    r"(?:theorem|lemma|def|abbrev)\s+"
    r"([A-Za-z0-9_'?!]+(?:\.[A-Za-z0-9_'?!]+)*)"
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


def _consume_string(text: str, i: int, out: list[str]) -> int:
    out.append(text[i])
    i += 1
    while i < len(text):
        ch = text[i]
        out.append(ch)
        if ch == "\\" and i + 1 < len(text):
            out.append(text[i + 1])
            i += 2
            continue
        i += 1
        if ch == "\"":
            break
    return i


def _consume_line_comment(text: str, i: int, out: list[str]) -> int:
    while i < len(text) and text[i] != "\n":
        out.append(" ")
        i += 1
    if i < len(text):
        out.append("\n")
        i += 1
    return i


def _comment_pair_delta(text: str, i: int) -> int:
    nxt = text[i + 1] if i + 1 < len(text) else ""
    if text[i] == "/" and nxt == "-":
        return 1
    if text[i] == "-" and nxt == "/":
        return -1
    return 0


def _consume_block_comment(text: str, i: int, out: list[str]) -> int:
    depth = 1
    while i < len(text) and depth > 0:
        delta = _comment_pair_delta(text, i)
        if delta:
            out.extend((" ", " "))
            depth += delta
            i += 2
            continue
        out.append("\n" if text[i] == "\n" else " ")
        i += 1
    return i


def strip_lean_comments(text: str) -> str:
    out: list[str] = []
    i = 0

    while i < len(text):
        ch = text[i]
        nxt = text[i + 1] if i + 1 < len(text) else ""

        if ch == "\"":
            i = _consume_string(text, i, out)
            continue
        if ch == "-" and nxt == "-":
            out.extend((" ", " "))
            i = _consume_line_comment(text, i + 2, out)
            continue
        if ch == "/" and nxt == "-":
            out.extend((" ", " "))
            i = _consume_block_comment(text, i + 2, out)
            continue

        out.append(ch)
        i += 1

    return "".join(out)


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
            names.add(_qualify_decl_name(match.group(1), _current_namespace_parts(stack)))

    return names


def rel_repo_path(repo_root: Path, path: Path) -> str:
    return str(path.resolve().relative_to(repo_root.resolve()))


def lean_repo_path(repo_root: Path, rel_path: str) -> Path:
    if rel_path.startswith(REPO_PREFIX):
        return repo_root / rel_path[len(REPO_PREFIX) :]
    raise ValueError(
        f"non-canonical path in registry: {rel_path!r} "
        f"(must start with {REPO_PREFIX!r})"
    )


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
    suffix = normalized[: -len(".lean")]
    return repo_root / ".lake" / "build" / "lib" / f"{suffix}.olean"


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
    for key in ("lean_file", "theorem_file"):
        path = row.get(key)
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


def bridge_theorems(row: dict) -> list[TheoremRef]:
    refs: list[TheoremRef] = []
    lean_file = row.get("lean_file") if isinstance(row.get("lean_file"), str) else None
    theorem_file = row.get("theorem_file") if isinstance(row.get("theorem_file"), str) else None
    model_theorem = row.get("model_theorem")
    if isinstance(model_theorem, str):
        refs.append((model_theorem, lean_file))
    for theorem in row.get("supporting_theorems", []):
        if isinstance(theorem, str):
            refs.append((theorem, theorem_file))
    return refs


def iter_registered_theorems(
    coverage: dict, bridge: dict
) -> tuple[list[TheoremRef], list[TheoremRef]]:
    coverage_refs: list[TheoremRef] = []
    bridge_refs: list[TheoremRef] = []
    for row in coverage.get("coverage", []):
        if isinstance(row, dict):
            coverage_refs.extend(coverage_theorems(row))
    for row in bridge.get("critical_ops", []):
        if isinstance(row, dict):
            bridge_refs.extend(bridge_theorems(row))
    return coverage_refs, bridge_refs


def validate_registered_paths(repo_root: Path, registered_paths: set[str]) -> list[str]:
    errors: list[str] = []
    for declared_path in sorted(registered_paths):
        abs_path = try_lean_repo_path(repo_root, declared_path)
        if abs_path is None:
            errors.append(f"unsupported non-repo path in registry: {declared_path}")
            continue
        if not abs_path.exists():
            errors.append(f"referenced Lean file does not exist: {declared_path}")
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
        if bridge_row.get("evidence_level") != coverage_row.get("evidence_level"):
            errors.append(
                f"shared-op evidence level drift for {op}: "
                f"refinement_bridge={bridge_row.get('evidence_level')} vs "
                f"proof_coverage[{section_key}]={coverage_row.get('evidence_level')}"
            )
    return errors


def load_registry_inputs(repo_root: Path) -> tuple[dict, dict, list[Path]]:
    coverage_path = repo_root / "proof_coverage.json"
    bridge_path = repo_root / "refinement_bridge.json"
    if not coverage_path.exists():
        raise FileNotFoundError("proof_coverage.json not found")
    if not bridge_path.exists():
        raise FileNotFoundError("refinement_bridge.json not found")
    coverage = json.loads(coverage_path.read_text(encoding="utf-8"))
    bridge = json.loads(bridge_path.read_text(encoding="utf-8"))
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
    coverage_theorem_refs, bridge_theorem_refs = iter_registered_theorems(coverage, bridge)
    coverage_rows = indexed_rows(coverage.get("coverage", []), "section_key")
    bridge_rows = indexed_rows(bridge.get("critical_ops", []), "op")
    errors = []
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
            allow_global_fallback=True,
        )
    )
    errors.extend(validate_shared_op_parity(coverage_rows, bridge_rows))
    return registered_paths, coverage_theorem_refs, bridge_theorem_refs, errors


def main() -> int:
    repo_root = Path(__file__).resolve().parents[1]
    try:
        coverage, bridge, lean_files = load_registry_inputs(repo_root)
    except FileNotFoundError as exc:
        return fail(str(exc))

    theorem_exists_anywhere, theorem_exists_in_file = theorem_lookups(repo_root, lean_files)
    registered_paths, coverage_theorem_refs, bridge_theorem_refs, errors = collect_registry_errors(
        repo_root, coverage, bridge, theorem_exists_anywhere, theorem_exists_in_file
    )
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
