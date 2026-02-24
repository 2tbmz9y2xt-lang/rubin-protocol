#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from pathlib import Path


ALLOWED_STATUS = {"proved", "stated", "deferred"}
ALLOWED_PROOF_LEVEL = {"toy-model", "spec-model", "byte-model", "refinement"}


def fail(msg: str) -> int:
    print(f"ERROR: {msg}", file=sys.stderr)
    return 1


def main() -> int:
    repo_root = Path(__file__).resolve().parents[1]
    section_hashes_path = repo_root / "spec" / "SECTION_HASHES.json"
    coverage_path = repo_root / "rubin-formal" / "proof_coverage.json"

    if not section_hashes_path.exists():
        return fail("spec/SECTION_HASHES.json not found")
    if not coverage_path.exists():
        return fail("rubin-formal/proof_coverage.json not found")

    section_hashes = json.loads(section_hashes_path.read_text(encoding="utf-8"))
    coverage = json.loads(coverage_path.read_text(encoding="utf-8"))

    proof_level = coverage.get("proof_level")
    if proof_level not in ALLOWED_PROOF_LEVEL:
        return fail(
            f"invalid or missing proof_level in rubin-formal/proof_coverage.json: {proof_level}; "
            f"expected one of {sorted(ALLOWED_PROOF_LEVEL)}"
        )

    claims = coverage.get("claims")
    if not isinstance(claims, dict):
        return fail("missing claims{} in rubin-formal/proof_coverage.json (required to prevent overclaim)")
    allowed_claims = claims.get("allowed")
    forbidden_claims = claims.get("forbidden")
    if not isinstance(allowed_claims, list) or len(allowed_claims) == 0:
        return fail("claims.allowed[] must be a non-empty list in rubin-formal/proof_coverage.json")
    if not isinstance(forbidden_claims, list) or len(forbidden_claims) == 0:
        return fail("claims.forbidden[] must be a non-empty list in rubin-formal/proof_coverage.json")

    expected_keys = set(section_hashes.get("section_headings", {}).keys())
    rows = coverage.get("coverage")
    if not isinstance(rows, list):
        return fail("coverage[]. list is missing in proof_coverage.json")

    seen_keys: set[str] = set()
    bad = False
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            print(f"ERROR: coverage[{index}] is not an object", file=sys.stderr)
            bad = True
            continue

        key = row.get("section_key")
        status = row.get("status")
        theorems = row.get("theorems", [])
        file_path = row.get("file")

        if key not in expected_keys:
            print(f"ERROR: unknown section_key in coverage[{index}]: {key}", file=sys.stderr)
            bad = True
            continue
        if key in seen_keys:
            print(f"ERROR: duplicate section_key in coverage: {key}", file=sys.stderr)
            bad = True
        seen_keys.add(key)

        if status not in ALLOWED_STATUS:
            print(
                f"ERROR: invalid status for {key}: {status}; expected one of {sorted(ALLOWED_STATUS)}",
                file=sys.stderr,
            )
            bad = True

        if status in {"proved", "stated"}:
            if not isinstance(theorems, list) or len(theorems) == 0:
                print(f"ERROR: {key} has status={status} but empty theorems[]", file=sys.stderr)
                bad = True

        if not isinstance(file_path, str) or not file_path:
            print(f"ERROR: {key} has missing file path", file=sys.stderr)
            bad = True
        else:
            abs_file = repo_root / file_path
            if not abs_file.exists():
                print(f"ERROR: coverage file does not exist for {key}: {file_path}", file=sys.stderr)
                bad = True

    missing = sorted(expected_keys - seen_keys)
    if missing:
        print("ERROR: missing section keys in proof coverage:", file=sys.stderr)
        for key in missing:
            print(f"  - {key}", file=sys.stderr)
        bad = True

    if bad:
        return 1

    print(
        f"OK: formal coverage baseline is consistent "
        f"({len(seen_keys)} sections from spec/SECTION_HASHES.json), proof_level={proof_level}."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
