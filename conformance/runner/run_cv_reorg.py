#!/usr/bin/env python3
from __future__ import annotations

from run_cv_unimplemented import run_unimplemented


def main() -> int:
    return run_unimplemented(
        "CV-REORG",
        "reorg/fork-selection engine is not yet wired as CLI contract for conformance vectors",
    )


if __name__ == "__main__":
    raise SystemExit(main())
