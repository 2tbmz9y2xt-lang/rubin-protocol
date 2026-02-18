#!/usr/bin/env python3
from __future__ import annotations

# Thin wrapper: unified bundle runner executes CV-UTXO via run_utxo() (implemented).
# Previous placeholder calling run_unimplemented() was stale — ApplyTx/UTXO are
# fully implemented in Go (consensus/tx.go:815) and Rust (rubin-consensus/src/lib.rs:900).

import subprocess
import sys
from pathlib import Path


def main() -> int:
    repo_root = Path(__file__).resolve().parents[2]
    p = subprocess.run(
        [sys.executable, "conformance/runner/run_cv_bundle.py"],
        cwd=str(repo_root),
    )
    return p.returncode


if __name__ == "__main__":
    raise SystemExit(main())
