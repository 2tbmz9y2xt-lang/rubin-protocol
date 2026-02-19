#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path
import tempfile

from run_cv_common import build_clients, make_parse_tx_bytes, parse_int, run, load_yaml


def check_expected_error(stderr: str, expected_error: str, test_id: str, failures: list[str]) -> bool:
    if expected_error in stderr:
        return True
    failures.append(
        f"{test_id}: expected_error={expected_error}; got stderr={stderr or '<empty>'}"
    )
    return False


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run CV-PARSE conformance vectors against Rust + Go clients."
    )
    parser.add_argument(
        "--fixture",
        default=None,
        help="Path to CV-PARSE.yml (default: repo/conformance/fixtures/CV-PARSE.yml)",
    )
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parents[2]
    fixture_path = (
        Path(args.fixture).resolve()
        if args.fixture
        else repo_root / "conformance" / "fixtures" / "CV-PARSE.yml"
    )
    fixture = load_yaml(fixture_path)
    if fixture.get("gate") != "CV-PARSE":
        print(f"invalid gate in fixture: {fixture_path}")
        return 1

    tests = fixture.get("tests")
    if not isinstance(tests, list) or not tests:
        print(f"fixture has no tests: {fixture_path}")
        return 1

    clients = build_clients(repo_root)
    failures: list[str] = []
    executed = 0

    tmp = tempfile.TemporaryDirectory(prefix="rubin-cv-txhex-")
    tx_dir = Path(tmp.name)

    for t in tests:
        if not isinstance(t, dict):
            failures.append("invalid test entry (not a mapping)")
            continue
        test_id = str(t.get("id", "<missing id>"))
        ctx = t.get("context")
        if not isinstance(ctx, dict):
            failures.append(f"{test_id}: missing/invalid context")
            continue

        tx_hex = make_parse_tx_bytes(ctx)
        tx_path = tx_dir / f"{test_id}.txhex"
        tx_path.write_text(tx_hex.strip() + "\n", encoding="utf-8")
        cmd = ["parse", "--tx-hex-file", str(tx_path)]

        max_witness_size = ctx.get("max_witness_size_per_tx")
        if max_witness_size is not None:
            try:
                cmd.extend(["--max-witness-bytes", str(parse_int(max_witness_size))])
            except (TypeError, ValueError) as e:
                failures.append(f"{test_id}: invalid max_witness_size_per_tx: {e}")
                continue

        out_r, err_r, rc_r = run(clients["rust"], cmd)
        out_g, err_g, rc_g = run(clients["go"], cmd)
        expected_error = t.get("expected_error")
        expected_code = t.get("expected_code")

        if expected_error:
            if not isinstance(expected_error, str):
                failures.append(f"{test_id}: expected_error must be string")
                continue
            executed += 1
            if rc_r == 0:
                failures.append(f"{test_id}: rust should fail with {expected_error}")
            if rc_g == 0:
                failures.append(f"{test_id}: go should fail with {expected_error}")
            if rc_r != 0 and rc_g != 0:
                check_expected_error(err_r, expected_error, test_id, failures)
                check_expected_error(err_g, expected_error, test_id, failures)
            if rc_r != rc_g:
                failures.append(
                    f"{test_id}: cross-client result mismatch: rust_rc={rc_r} go_rc={rc_g}"
                )
            continue

        if expected_code != "PASS":
            failures.append(f"{test_id}: unsupported expectation {expected_code}")
            continue

        if rc_r != 0:
            failures.append(f"{test_id}: rust parse failed: {err_r}")
        if rc_g != 0:
            failures.append(f"{test_id}: go parse failed: {err_g}")
        if rc_r == 0 and rc_g == 0:
            if out_r != "OK":
                failures.append(f"{test_id}: rust parse output mismatch: got={out_r}")
            if out_g != "OK":
                failures.append(f"{test_id}: go parse output mismatch: got={out_g}")
            if out_r != out_g:
                failures.append(
                    f"{test_id}: cross-client parse output mismatch: rust={out_r} go={out_g}"
                )
            executed += 1

    if failures:
        print("CV-PARSE: FAIL")
        for f in failures:
            print(f"- {f}")
        return 1

    print(f"CV-PARSE: PASS ({executed} checks)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
