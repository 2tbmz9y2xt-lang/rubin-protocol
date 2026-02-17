#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from run_cv_common import build_clients, load_yaml, run


def expected_vec_ok(v: Any) -> tuple[bool, str]:
    if not isinstance(v, dict):
        return False, "invalid vector entry (not a mapping)"
    if not isinstance(v.get("encoding_hex"), str) or v["encoding_hex"] == "":
        return False, "missing encoding_hex"
    if not isinstance(v.get("value"), int):
        return False, "missing value"
    return True, ""


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run CV-COMPACTSIZE conformance vectors against Rust + Go clients."
    )
    parser.add_argument(
        "--fixture",
        default=None,
        help="Path to CV-COMPACTSIZE.yml (default: repo/conformance/fixtures/CV-COMPACTSIZE.yml)",
    )
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parents[2]
    fixture_path = (
        Path(args.fixture).resolve()
        if args.fixture
        else repo_root / "conformance" / "fixtures" / "CV-COMPACTSIZE.yml"
    )
    fixture = load_yaml(fixture_path)
    if "gate" in fixture and fixture.get("gate") != "CV-COMPACTSIZE":
        print(f"invalid gate in fixture: {fixture_path}")
        return 1
    if "gate" not in fixture and str(fixture.get("id", "")) != "CV-COMPACTSIZE":
        print(f"fixture does not target CV-COMPACTSIZE: {fixture_path}")
        return 1

    vectors = fixture.get("vectors")
    if not isinstance(vectors, list) or not vectors:
        print(f"fixture has no vectors: {fixture_path}")
        return 1

    clients = build_clients(repo_root)

    failures: list[str] = []
    executed = 0

    for v in vectors:
        ok, reason = expected_vec_ok(v)
        test_id = str(v.get("name", "<missing name>"))
        if not ok:
            failures.append(f"{test_id}: {reason}")
            continue
        expected = str(v["value"])
        encoded = str(v["encoding_hex"]).replace(" ", "")
        cmd = ["compactsize", "--encoded-hex", encoded]

        out_r, err_r, rc_r = run(clients["rust"], cmd)
        if rc_r != 0:
            failures.append(
                f"{test_id}: rust failed (exit={rc_r}): {err_r}"
            )
            continue

        out_g, err_g, rc_g = run(clients["go"], cmd)
        if rc_g != 0:
            failures.append(
                f"{test_id}: go failed (exit={rc_g}): {err_g}"
            )
            continue

        executed += 1
        if out_r != expected:
            failures.append(
                f"{test_id}: rust compactsize mismatch: got={out_r} expected={expected}"
            )
        if out_g != expected:
            failures.append(
                f"{test_id}: go compactsize mismatch: got={out_g} expected={expected}"
            )
        if out_r != out_g:
            failures.append(
                f"{test_id}: cross-client mismatch: rust={out_r} go={out_g}"
            )

    if failures:
        print("CV-COMPACTSIZE: FAIL")
        for f in failures:
            print(f"- {f}")
        return 1

    print(f"CV-COMPACTSIZE: PASS ({executed} checks)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
