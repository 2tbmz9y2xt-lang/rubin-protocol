#!/usr/bin/env python3
from __future__ import annotations

from run_cv_unimplemented import run_unimplemented


def main() -> int:
    return run_unimplemented(
        "CV-BIND",
        "bind semantics require full witness-authorization checks exposed in node CLI",
    )


if __name__ == "__main__":
    raise SystemExit(main())
