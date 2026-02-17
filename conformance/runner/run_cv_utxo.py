#!/usr/bin/env python3
from __future__ import annotations

from run_cv_unimplemented import run_unimplemented


def main() -> int:
    return run_unimplemented(
        "CV-UTXO",
        "UTXO set and spend checks require ApplyTx/UTXO-layer in node runtime",
    )


if __name__ == "__main__":
    raise SystemExit(main())
