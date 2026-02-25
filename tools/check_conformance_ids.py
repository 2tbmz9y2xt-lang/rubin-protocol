#!/usr/bin/env python3
from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(".")
FIXTURES_DIR = ROOT / "conformance" / "fixtures"

CHANGELOG_CANDIDATES = [
    ROOT / "spec" / "SPEC_CHANGELOG.md",
    ROOT / "spec" / "CHANGES.md",
]

DATE_HDR_RE = re.compile(r"(?m)^##\s+\d{4}-\d{2}-\d{2}\b")


@dataclass(frozen=True)
class IdLoc:
    value: str
    path: Path


def load_json(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8", errors="strict"))


def pick_changelog() -> Path | None:
    for p in CHANGELOG_CANDIDATES:
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
    if not FIXTURES_DIR.exists():
        print("ERROR: conformance/fixtures directory not found", file=sys.stderr)
        return 2

    fixture_paths = sorted(FIXTURES_DIR.glob("*.json"))
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

    changelog = pick_changelog()
    if not changelog:
        print(
            "ERROR: missing spec changelog file (expected spec/SPEC_CHANGELOG.md or spec/CHANGES.md)",
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

