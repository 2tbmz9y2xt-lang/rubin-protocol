#!/usr/bin/env python3
from __future__ import annotations

# Thin wrapper: unified bundle runner now executes CV-BLOCK via apply-block.

import subprocess
import sys
from pathlib import Path


def main() -> int:
    repo_root = Path(__file__).resolve().parents[2]
    p = subprocess.run(
        [sys.executable, "conformance/runner/run_cv_bundle.py", "--only-gates", "CV-BLOCK"],
        cwd=str(repo_root),
    )
    return p.returncode


if __name__ == "__main__":
    raise SystemExit(main())
