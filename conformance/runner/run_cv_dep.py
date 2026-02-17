#!/usr/bin/env python3
from __future__ import annotations

from run_cv_unimplemented import run_unimplemented


def main() -> int:
    return run_unimplemented(
        "CV-DEP",
        "version bits activation transitions are not yet exposed as executable node API",
    )


if __name__ == "__main__":
    raise SystemExit(main())
