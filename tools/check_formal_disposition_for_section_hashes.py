#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path


def _sha3_256_hex_lf_normalized(b: bytes) -> str:
    b = b.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    return hashlib.sha3_256(b).hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser(
        description=(
            "Merge gate: when spec/SECTION_HASHES.json changes, formal disposition must be updated "
            "(rubin-formal proof_coverage.json must carry matching spec_section_hashes_sha3_256)."
        )
    )
    ap.add_argument(
        "--spec-root",
        required=True,
        help="Path to rubin-spec-private checkout root (must contain spec/SECTION_HASHES.json).",
    )
    ap.add_argument(
        "--formal-root",
        required=True,
        help="Path to rubin-formal checkout root (must contain proof_coverage.json).",
    )
    args = ap.parse_args()

    spec_hashes = Path(args.spec_root) / "spec" / "SECTION_HASHES.json"
    formal_cov = Path(args.formal_root) / "proof_coverage.json"

    if not spec_hashes.exists():
        print(f"ERROR: missing spec SECTION_HASHES: {spec_hashes}", file=sys.stderr)
        return 2
    if not formal_cov.exists():
        print(f"ERROR: missing formal proof coverage: {formal_cov}", file=sys.stderr)
        return 2

    got = _sha3_256_hex_lf_normalized(spec_hashes.read_bytes())

    data = json.loads(formal_cov.read_text(encoding="utf-8"))
    exp = data.get("spec_section_hashes_sha3_256")
    if not isinstance(exp, str) or not exp.strip():
        print("FAIL: formal proof_coverage.json missing spec_section_hashes_sha3_256", file=sys.stderr)
        return 1

    if exp != got:
        print("FAIL: formal disposition out of date for spec/SECTION_HASHES.json", file=sys.stderr)
        print(f"  expected(formal): {exp}", file=sys.stderr)
        print(f"  got(spec):        {got}", file=sys.stderr)
        print(
            "  fix: update rubin-formal/proof_coverage.json field spec_section_hashes_sha3_256 "
            "to match the current spec SECTION_HASHES.json",
            file=sys.stderr,
        )
        return 1

    print("OK: formal disposition matches spec SECTION_HASHES.json (sha3-256).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

