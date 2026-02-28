#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path


DATE_HDR_RE = re.compile(r"(?m)^##\s+\d{4}-\d{2}-\d{2}\b")


@dataclass(frozen=True)
class IdLoc:
    value: str
    path: Path


def load_json(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8", errors="strict"))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate conformance gate/vector IDs and changelog presence."
    )
    parser.add_argument(
        "--code-root",
        default=".",
        help="Path to code repository root (default: .)",
    )
    parser.add_argument(
        "--spec-root",
        default="",
        help=(
            "Optional path to spec directory containing SPEC_CHANGELOG.md. "
            "If omitted, auto-detection checks code-root/spec and sibling rubin-spec* repos."
        ),
    )
    return parser.parse_args()


def detect_spec_roots(code_root: Path, explicit_spec_root: str) -> list[Path]:
    candidates: list[Path] = []
    if explicit_spec_root:
        candidates.append(Path(explicit_spec_root))
    env_raw = os.environ.get("RUBIN_SPEC_ROOT", "")
    if env_raw:
        candidates.append(Path(env_raw))
    candidates.extend(
        [
            code_root / "spec",
            code_root.parent / "rubin-spec-private" / "spec",
            code_root.parent / "rubin-spec" / "spec",
        ]
    )

    unique: list[Path] = []
    seen: set[Path] = set()
    for candidate in candidates:
        resolved = candidate.expanduser().resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        unique.append(resolved)
    return unique


def changelog_candidates(spec_roots: list[Path]) -> list[Path]:
    out: list[Path] = []
    for root in spec_roots:
        out.append(root / "SPEC_CHANGELOG.md")
        out.append(root / "CHANGES.md")
    return out


def pick_changelog(candidates: list[Path]) -> Path | None:
    for p in candidates:
        if p.exists():
            return p
    return None


def validate_changelog(path: Path) -> list[str]:
    problems: list[str] = []
    text = path.read_text(encoding="utf-8", errors="strict")

    if not text.lstrip().startswith("#"):
        problems.append("changelog: missing top-level markdown header (# ...)")

    if "NON-CONSENSUS" not in text:
        problems.append("changelog: must include 'NON-CONSENSUS' marker")

    if not DATE_HDR_RE.search(text):
        problems.append("changelog: must contain at least one dated section header: '## YYYY-MM-DD'")

    return problems


def main() -> int:
    args = parse_args()
    code_root = Path(args.code_root).expanduser().resolve()
    fixtures_dir = code_root / "conformance" / "fixtures"
    spec_roots = detect_spec_roots(code_root, args.spec_root)
    candidates = changelog_candidates(spec_roots)

    if not fixtures_dir.exists():
        print("ERROR: conformance/fixtures directory not found", file=sys.stderr)
        return 2

    fixture_paths = sorted(fixtures_dir.glob("*.json"))
    if not fixture_paths:
        print("ERROR: no conformance fixtures found in conformance/fixtures/*.json", file=sys.stderr)
        return 2

    failed = False

    gate_seen: dict[str, IdLoc] = {}
    vector_seen: dict[str, IdLoc] = {}

    for path in fixture_paths:
        try:
            data = load_json(path)
        except Exception as e:
            print(f"ERROR: cannot parse json: {path}: {e}", file=sys.stderr)
            failed = True
            continue

        if not isinstance(data, dict):
            print(f"ERROR: fixture root must be object: {path}", file=sys.stderr)
            failed = True
            continue

        gate = data.get("gate")
        if not isinstance(gate, str) or gate.strip() == "":
            print(f"ERROR: missing/invalid 'gate' string in {path}", file=sys.stderr)
            failed = True
            continue

        expected_gate = path.stem
        if gate != expected_gate:
            print(
                f"ERROR: gate must match filename stem in {path}: gate={gate!r} expected={expected_gate!r}",
                file=sys.stderr,
            )
            failed = True

        if gate in gate_seen:
            prev = gate_seen[gate]
            print(
                f"ERROR: duplicate gate id {gate!r} in {path} (already in {prev.path})",
                file=sys.stderr,
            )
            failed = True
        else:
            gate_seen[gate] = IdLoc(gate, path)

        vectors = data.get("vectors")
        if not isinstance(vectors, list):
            print(f"ERROR: missing/invalid 'vectors' array in {path}", file=sys.stderr)
            failed = True
            continue

        local_vectors: set[str] = set()
        for i, v in enumerate(vectors):
            if not isinstance(v, dict):
                print(f"ERROR: vectors[{i}] must be object in {path}", file=sys.stderr)
                failed = True
                continue

            vid = v.get("id")
            if not isinstance(vid, str) or vid.strip() == "":
                print(f"ERROR: vectors[{i}].id must be non-empty string in {path}", file=sys.stderr)
                failed = True
                continue

            if vid in local_vectors:
                print(f"ERROR: duplicate vector id {vid!r} within {path}", file=sys.stderr)
                failed = True
            else:
                local_vectors.add(vid)

            if vid in vector_seen:
                prev = vector_seen[vid]
                print(
                    f"ERROR: duplicate vector id {vid!r} in {path} (already in {prev.path})",
                    file=sys.stderr,
                )
                failed = True
            else:
                vector_seen[vid] = IdLoc(vid, path)

    changelog = pick_changelog(candidates)
    if not changelog:
        print(
            "ERROR: missing spec changelog file (expected SPEC_CHANGELOG.md/CHANGES.md under configured spec roots)",
            file=sys.stderr,
        )
        print(
            f"       searched roots: {', '.join(str(p) for p in spec_roots)}",
            file=sys.stderr,
        )
        failed = True
    else:
        problems = validate_changelog(changelog)
        for p in problems:
            print(f"ERROR: {p} ({changelog})", file=sys.stderr)
        if problems:
            failed = True

    if failed:
        return 1

    print(
        f"OK: conformance IDs are unique (gates={len(gate_seen)} vectors={len(vector_seen)}), changelog present."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
