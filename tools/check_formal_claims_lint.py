#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from pathlib import Path


ALLOWED_CLAIM_LEVEL = {"toy", "byte", "refined"}
PROOF_TO_CLAIM = {
    "toy-model": "toy",
    "spec-model": "toy",
    "byte-model": "byte",
    "refinement": "refined",
}
GUARD_HINTS = ("not ok", "forbidden", "запрещ", "claims.forbidden")


def fail(msg: str) -> int:
    print(f"ERROR: {msg}", file=sys.stderr)
    return 1


def is_guarded(lines: list[str], i: int) -> bool:
    start = max(0, i - 5)
    context = " ".join(lines[start : i + 1]).lower()
    return any(h in context for h in GUARD_HINTS)


def main() -> int:
    repo_root = Path(__file__).resolve().parents[1]
    coverage_path = repo_root / "rubin-formal" / "proof_coverage.json"
    if not coverage_path.exists():
        return fail("rubin-formal/proof_coverage.json not found")

    doc = json.loads(coverage_path.read_text(encoding="utf-8"))
    proof_level = doc.get("proof_level")
    claim_level = doc.get("claim_level")
    claims = doc.get("claims", {})
    forbidden = claims.get("forbidden")

    if claim_level not in ALLOWED_CLAIM_LEVEL:
        return fail(f"invalid claim_level={claim_level}; expected one of {sorted(ALLOWED_CLAIM_LEVEL)}")
    expected_claim = PROOF_TO_CLAIM.get(proof_level)
    if expected_claim is None:
        return fail(f"unsupported proof_level={proof_level} for claim consistency check")
    if claim_level != expected_claim:
        return fail(
            f"claim_level/proof_level mismatch: proof_level={proof_level} requires claim_level={expected_claim}, got {claim_level}"
        )

    if not isinstance(forbidden, list) or len(forbidden) == 0:
        return fail("claims.forbidden[] must be a non-empty list")

    doc_paths = [
        repo_root / "README.md",
        repo_root / "SPEC_LOCATION.md",
        repo_root / "rubin-formal" / "README.md",
        repo_root / "rubin-formal" / "PROOF_COVERAGE.md",
    ]
    for p in doc_paths:
        if not p.exists():
            return fail(f"doc for claims lint not found: {p.relative_to(repo_root)}")

    if claim_level == "toy":
        missing_toy_markers = []
        for p in doc_paths:
            txt = p.read_text(encoding="utf-8").lower()
            if "toy-model" not in txt:
                missing_toy_markers.append(str(p.relative_to(repo_root)))
        if missing_toy_markers:
            return fail(f"claim_level=toy requires toy-model marker in docs: {missing_toy_markers}")

    bad = False
    for p in doc_paths:
        lines = p.read_text(encoding="utf-8").splitlines()
        for i, line in enumerate(lines):
            low = line.lower()
            for phrase in forbidden:
                if not isinstance(phrase, str) or not phrase:
                    continue
                if phrase.lower() in low and not is_guarded(lines, i):
                    print(
                        f"ERROR: unguarded forbidden claim phrase in {p.relative_to(repo_root)}:{i+1}: {phrase}",
                        file=sys.stderr,
                    )
                    bad = True

    if bad:
        return 1

    print(f"OK: formal claims lint passed (claim_level={claim_level}, proof_level={proof_level}).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
