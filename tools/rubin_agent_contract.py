#!/usr/bin/env python3
from __future__ import annotations

import json
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any


SCRIPT_DIR = Path(__file__).resolve().parent
SCHEMA_PATH = SCRIPT_DIR / "agent_templates" / "q_manifest.schema.json"

OWNER_AREAS = (
    "consensus",
    "node",
    "p2p",
    "storage",
    "rpc",
    "ci",
    "formal",
    "docs",
    "tooling",
)

CANONICAL_INVARIANTS = (
    "scope",
    "state_ownership",
    "lock_io",
    "failure_atomicity",
    "go_rust_parity",
    "caller_fuzz_test_sweep",
    "test_stability",
)

RUNTIME_SENSITIVE_TOKENS = (
    "p2p",
    "sync",
    "rpc",
    "miner",
    "reconnect",
)

PRODUCTION_SUFFIXES = {".go", ".rs", ".lean"}
COMMENT_PREFIXES = ("//", "#", "/*", "*", "--")

DIFF_HEADER_RE = re.compile(r"^diff --git a/(.+) b/(.+)$")
HUNK_HEADER_RE = re.compile(
    r"^@@ -(?P<old_start>\d+)(?:,(?P<old_count>\d+))? "
    r"\+(?P<new_start>\d+)(?:,(?P<new_count>\d+))? @@"
)


class ContractError(RuntimeError):
    """Base error for local coder-agent contracts."""


class GitCommandError(ContractError):
    """Raised when a required git command fails."""


class ManifestValidationError(ContractError):
    """Raised when a manifest or schema is invalid."""

    def __init__(self, errors: list[str]):
        self.errors = errors
        message = "manifest validation failed:\n- " + "\n- ".join(errors)
        super().__init__(message)


@dataclass(frozen=True)
class AddedLine:
    number: int
    text: str


@dataclass
class FilePatch:
    path: str
    added_lines: list[AddedLine] = field(default_factory=list)
    added_count: int = 0
    deleted_count: int = 0


def normalize_rel_path(path: str) -> str:
    normalized = path.replace("\\", "/")
    if normalized.startswith("./"):
        return normalized[2:]
    return normalized


def resolve_manifest_path(path_arg: str | Path) -> Path:
    path = Path(path_arg).expanduser()
    if path.is_absolute():
        return path
    cwd_candidate = Path.cwd() / path
    if cwd_candidate.exists():
        return cwd_candidate.resolve()
    return path.resolve()


def discover_repo_root(manifest_path: Path) -> Path:
    result = subprocess.run(
        ["git", "-C", str(manifest_path.parent), "rev-parse", "--show-toplevel"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or "git rev-parse failed"
        raise GitCommandError(
            f"unable to discover repo root for manifest {manifest_path}: {detail}"
        )
    return Path(result.stdout.strip()).resolve()


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ManifestValidationError([f"{path}: file not found"]) from exc
    except json.JSONDecodeError as exc:
        raise ManifestValidationError(
            [f"{path}: invalid json at line {exc.lineno} column {exc.colno}: {exc.msg}"]
        ) from exc


def _validate_instance(instance: Any, schema: dict[str, Any], pointer: str = "$") -> list[str]:
    errors: list[str] = []
    schema_type = schema.get("type")

    if schema_type == "object":
        if not isinstance(instance, dict):
            return [f"{pointer}: expected object"]
        required = schema.get("required", [])
        for key in required:
            if key not in instance:
                errors.append(f"{pointer}: missing required property {key!r}")
        properties = schema.get("properties", {})
        if schema.get("additionalProperties") is False:
            extras = sorted(set(instance.keys()) - set(properties.keys()))
            for key in extras:
                errors.append(f"{pointer}: unexpected property {key!r}")
        for key, value in instance.items():
            prop_schema = properties.get(key)
            if prop_schema is not None:
                errors.extend(_validate_instance(value, prop_schema, f"{pointer}.{key}"))
        return errors

    if schema_type == "array":
        if not isinstance(instance, list):
            return [f"{pointer}: expected array"]
        min_items = schema.get("minItems")
        if min_items is not None and len(instance) < min_items:
            errors.append(f"{pointer}: expected at least {min_items} item(s)")
        if schema.get("uniqueItems"):
            try:
                normalized = [json.dumps(item, sort_keys=True) for item in instance]
            except TypeError:
                normalized = [repr(item) for item in instance]
            if len(normalized) != len(set(normalized)):
                errors.append(f"{pointer}: array items must be unique")
        item_schema = schema.get("items")
        if item_schema is not None:
            for idx, item in enumerate(instance):
                errors.extend(_validate_instance(item, item_schema, f"{pointer}[{idx}]"))
        return errors

    if schema_type == "string":
        if not isinstance(instance, str):
            return [f"{pointer}: expected string"]
        min_length = schema.get("minLength")
        if min_length is not None and len(instance) < min_length:
            errors.append(f"{pointer}: expected string length >= {min_length}")
        enum = schema.get("enum")
        if enum is not None and instance not in enum:
            errors.append(f"{pointer}: expected one of {enum!r}")
        pattern = schema.get("pattern")
        if pattern is not None and re.fullmatch(pattern, instance) is None:
            errors.append(f"{pointer}: value does not match pattern {pattern!r}")
        return errors

    if schema_type == "integer":
        if not isinstance(instance, int) or isinstance(instance, bool):
            return [f"{pointer}: expected integer"]
        minimum = schema.get("minimum")
        if minimum is not None and instance < minimum:
            errors.append(f"{pointer}: expected integer >= {minimum}")
        return errors

    return errors


def validate_manifest_document(document: dict[str, Any]) -> dict[str, Any]:
    schema = load_json(SCHEMA_PATH)
    errors = _validate_instance(document, schema)

    if "required_invariants" in document:
        observed = document["required_invariants"]
        if isinstance(observed, list):
            missing = sorted(set(CANONICAL_INVARIANTS) - set(observed))
            extras = sorted(set(observed) - set(CANONICAL_INVARIANTS))
            if missing:
                errors.append(
                    "$.required_invariants: missing canonical invariant(s): "
                    + ", ".join(missing)
                )
            if extras:
                errors.append(
                    "$.required_invariants: unsupported invariant(s): "
                    + ", ".join(extras)
                )

    if (
        isinstance(document.get("target_production_loc"), int)
        and isinstance(document.get("hard_production_loc"), int)
        and document["target_production_loc"] > document["hard_production_loc"]
    ):
        errors.append(
            "$.target_production_loc: target_production_loc must be <= hard_production_loc"
        )

    if errors:
        raise ManifestValidationError(errors)
    return document


def load_manifest(path_arg: str | Path) -> tuple[Path, Path, dict[str, Any]]:
    manifest_path = resolve_manifest_path(path_arg)
    repo_root = discover_repo_root(manifest_path)
    document = load_json(manifest_path)
    manifest = validate_manifest_document(document)
    return manifest_path, repo_root, manifest


def run_git(repo_root: Path, args: list[str]) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo_root), *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "git command failed"
        raise GitCommandError(f"git {' '.join(args)} failed: {detail}")
    return result.stdout


def default_diff_range(repo_root: Path) -> str:
    run_git(repo_root, ["rev-parse", "--verify", "origin/main"])
    merge_base = run_git(repo_root, ["merge-base", "origin/main", "HEAD"]).strip()
    if not merge_base:
        raise GitCommandError("git merge-base origin/main HEAD returned empty output")
    return merge_base


def resolve_diff_range(repo_root: Path, diff_range: str | None) -> str:
    if diff_range:
        return diff_range
    return default_diff_range(repo_root)


def list_changed_files(repo_root: Path, diff_range: str) -> list[str]:
    output = run_git(repo_root, ["diff", "--name-only", diff_range, "--"])
    changed = {normalize_rel_path(line) for line in output.splitlines() if line.strip()}
    changed.update(list_untracked_files(repo_root))
    return sorted(changed)


def list_untracked_files(repo_root: Path) -> list[str]:
    output = run_git(repo_root, ["ls-files", "--others", "--exclude-standard"])
    return [normalize_rel_path(line) for line in output.splitlines() if line.strip()]


def parse_diff_patches(repo_root: Path, diff_range: str) -> dict[str, FilePatch]:
    output = run_git(repo_root, ["diff", "--find-renames", "--unified=0", diff_range, "--"])
    patches: dict[str, FilePatch] = {}
    current: FilePatch | None = None
    new_line = 0
    old_line = 0
    in_hunk = False

    for line in output.splitlines():
        match = DIFF_HEADER_RE.match(line)
        if match:
            path = normalize_rel_path(match.group(2))
            current = patches.setdefault(path, FilePatch(path=path))
            in_hunk = False
            continue

        if current is None:
            continue

        if line.startswith("+++ "):
            dst = line[4:].strip()
            if dst != "/dev/null":
                path = normalize_rel_path(dst.removeprefix("b/"))
                if path != current.path:
                    current = patches.setdefault(path, FilePatch(path=path))
            continue

        hunk = HUNK_HEADER_RE.match(line)
        if hunk:
            old_line = int(hunk.group("old_start"))
            new_line = int(hunk.group("new_start"))
            in_hunk = True
            continue

        if not in_hunk:
            continue

        if line.startswith("+") and not line.startswith("+++"):
            current.added_count += 1
            current.added_lines.append(AddedLine(number=new_line, text=line[1:]))
            new_line += 1
            continue

        if line.startswith("-") and not line.startswith("---"):
            current.deleted_count += 1
            old_line += 1
            continue

        if line.startswith(" "):
            old_line += 1
            new_line += 1

    for rel_path in list_untracked_files(repo_root):
        path = repo_root / rel_path
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        added_lines = [
            AddedLine(number=idx, text=line)
            for idx, line in enumerate(text.splitlines(), start=1)
        ]
        patch = patches.setdefault(rel_path, FilePatch(path=rel_path))
        patch.added_lines.extend(added_lines)
        patch.added_count += len(added_lines)

    return patches


def path_matches_glob(rel_path: str, pattern: str) -> bool:
    rel = PurePosixPath(normalize_rel_path(rel_path))
    normalized_pattern = normalize_rel_path(pattern)
    return rel.match(normalized_pattern) or rel.as_posix() == normalized_pattern


def matches_any_glob(rel_path: str, patterns: list[str]) -> bool:
    return any(path_matches_glob(rel_path, pattern) for pattern in patterns)


def is_test_file(rel_path: str) -> bool:
    pure = PurePosixPath(normalize_rel_path(rel_path))
    if pure.name.endswith("_test.go"):
        return True
    return any(part in {"tests", "benches", "fuzz"} for part in pure.parts)


def is_production_loc_file(rel_path: str) -> bool:
    pure = PurePosixPath(normalize_rel_path(rel_path))
    if pure.suffix not in PRODUCTION_SUFFIXES:
        return False
    return not is_test_file(rel_path)


def is_runtime_sensitive_path(rel_path: str) -> bool:
    pure = PurePosixPath(normalize_rel_path(rel_path))
    lower_parts = [part.lower() for part in pure.parts]
    return any(
        token in part
        for token in RUNTIME_SENSITIVE_TOKENS
        for part in lower_parts
    )


def count_production_loc(patches: dict[str, FilePatch]) -> int:
    total = 0
    for rel_path, patch in patches.items():
        if is_production_loc_file(rel_path):
            total += patch.added_count + patch.deleted_count
    return total


def is_comment_line(text: str) -> bool:
    stripped = text.lstrip()
    return any(stripped.startswith(prefix) for prefix in COMMENT_PREFIXES)


def read_worktree_text(repo_root: Path, rel_path: str) -> str:
    return (repo_root / rel_path).read_text(encoding="utf-8")


def find_drop_block_ranges(text: str) -> list[tuple[int, int]]:
    lines = text.splitlines()
    ranges: list[tuple[int, int]] = []
    tracking = False
    started = False
    start_line = 0
    brace_depth = 0

    for idx, line in enumerate(lines, start=1):
        if not tracking and "Drop for" in line:
            tracking = True

        if not tracking:
            continue

        open_braces = line.count("{")
        close_braces = line.count("}")

        if not started and open_braces:
            started = True
            start_line = idx
            brace_depth += open_braces - close_braces
            if brace_depth <= 0:
                ranges.append((start_line, idx))
                tracking = False
                started = False
                brace_depth = 0
            continue

        if started:
            brace_depth += open_braces - close_braces
            if brace_depth <= 0:
                ranges.append((start_line, idx))
                tracking = False
                started = False
                brace_depth = 0

    return ranges


def line_in_ranges(line_number: int, ranges: list[tuple[int, int]]) -> bool:
    return any(start <= line_number <= end for start, end in ranges)
