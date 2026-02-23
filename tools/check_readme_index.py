#!/usr/bin/env python3
from __future__ import annotations

import sys
from pathlib import Path


REQUIRED_FILES = [
    "./RUBIN_L1_CANONICAL.md",
    "./RUBIN_COMPACT_BLOCKS.md",
    "./RUBIN_NETWORK_PARAMS.md",
    "./RUBIN_L1_P2P_AUX.md",
    "./RUBIN_SLH_FALLBACK_PLAYBOOK.md",
    "./SECTION_HASHES.json",
]

REQUIRED_PHRASES = [
    "Consensus source-of-truth: RUBIN_L1_CANONICAL.md",
    "Precedence (normative):",
    "Document Precedence",
    "RUBIN_L1_CANONICAL.md",
    "RUBIN_COMPACT_BLOCKS.md",
    "RUBIN_NETWORK_PARAMS.md",
    "SECTION_HASHES.json pins",
]


def main() -> int:
    repo_root = Path(".")
    readme = repo_root / "spec" / "README.md"
    if not readme.exists():
        print("ERROR: spec/README.md not found", file=sys.stderr)
        return 2

    text = readme.read_text(encoding="utf-8", errors="strict")

    missing_files = [f for f in REQUIRED_FILES if f not in text]
    missing_phrases = [p for p in REQUIRED_PHRASES if p not in text]

    if missing_files:
        print("ERROR: README.md is missing references to files:", file=sys.stderr)
        for f in missing_files:
            print(f"  - {f}", file=sys.stderr)

    if missing_phrases:
        print("ERROR: README.md is missing required phrases/sections:", file=sys.stderr)
        for p in missing_phrases:
            print(f"  - {p}", file=sys.stderr)

    if missing_files or missing_phrases:
        return 1

    print("OK: README index/precedence looks consistent.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
