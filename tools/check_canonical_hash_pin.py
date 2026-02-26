#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Check pinned sha256 for spec/RUBIN_L1_CANONICAL.md",
    )
    parser.add_argument(
        "--spec",
        default="spec/RUBIN_L1_CANONICAL.md",
        help="path to canonical spec file (repo-relative)",
    )
    parser.add_argument(
        "--pin",
        default="spec/RUBIN_L1_CANONICAL_SHA256.txt",
        help="path to pinned sha256 file (repo-relative)",
    )
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parents[1]
    spec_path = (repo_root / args.spec).resolve()
    pin_path = (repo_root / args.pin).resolve()

    if not spec_path.exists():
        print(f"ERROR: spec file not found: {spec_path}", file=sys.stderr)
        return 2
    if not pin_path.exists():
        print(f"ERROR: pin file not found: {pin_path}", file=sys.stderr)
        return 2

    expected = pin_path.read_text(encoding="utf-8").strip().lower()
    if len(expected) != 64 or any(ch not in "0123456789abcdef" for ch in expected):
        print(f"ERROR: invalid sha256 in pin file: {pin_path}", file=sys.stderr)
        return 2

    actual = file_sha256(spec_path)
    if actual != expected:
        print("FAIL: canonical hash pin mismatch", file=sys.stderr)
        print(f"  spec:     {spec_path}", file=sys.stderr)
        print(f"  pin_file: {pin_path}", file=sys.stderr)
        print(f"  expected: {expected}", file=sys.stderr)
        print(f"  actual:   {actual}", file=sys.stderr)
        return 1

    print(f"OK: canonical hash pin matches ({actual})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
