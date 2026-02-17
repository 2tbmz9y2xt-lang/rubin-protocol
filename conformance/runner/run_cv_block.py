#!/usr/bin/env python3
from __future__ import annotations

from run_cv_unimplemented import run_unimplemented


def main() -> int:
    return run_unimplemented(
        "CV-BLOCK",
        "block validation/reorg/UTXO pipeline currently not exposed via CLI in this phase",
    )


if __name__ == "__main__":
    raise SystemExit(main())
