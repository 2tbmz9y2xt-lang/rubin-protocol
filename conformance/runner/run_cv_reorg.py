#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path

from run_cv_common import build_clients, extract_error_token, load_yaml, parse_int, run


def expected_token(test_id: str, expected_outcome: str, ctx: dict[str, object]) -> str:
    norm = expected_outcome.strip().lower()
    if test_id == "REORG-01" or "smaller lexicographic tip" in norm:
        a = parse_int(ctx.get("fork_a_work", 0))
        b = parse_int(ctx.get("fork_b_work", 0))
        tip_a = str(ctx.get("tip_hash_a", ""))
        tip_b = str(ctx.get("tip_hash_b", ""))
        if a > b:
            return "SELECT_FORK_A"
        if b > a:
            return "SELECT_FORK_B"
        return "SELECT_FORK_A" if tip_a <= tip_b else "SELECT_FORK_B"
    if "select fork b" in norm:
        return "SELECT_FORK_B"
    if "select fork a" in norm:
        return "SELECT_FORK_A"
    if "rollback stale branch" in norm or "select candidate branch" in norm:
        return "SELECT_CANDIDATE_ROLLBACK_STALE"
    if "s_101 identical" in norm:
        return "DETERMINISTIC_UTXO_STATE"
    if "tx index 2 successfully spends" in norm or "order is canonical and deterministic" in norm:
        return "DETERMINISTIC_TX_ORDER"
    if "deterministic" in norm or "canonical" in norm:
        return "DETERMINISTIC_BRANCH_SWITCH"
    raise ValueError(f"unsupported expected_outcome mapping: {expected_outcome}")


def run_reorg(clients: dict[str, object], ctx: dict[str, object]) -> tuple[tuple[str, str, int], tuple[str, str, int]]:
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as f:
        json.dump(ctx, f)
        path = f.name
    try:
        rust = run(clients["rust"], ["reorg", "--context-json", path])
        go = run(clients["go"], ["reorg", "--context-json", path])
        return rust, go
    finally:
        Path(path).unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(description="Run CV-REORG conformance vectors against Rust + Go clients.")
    parser.add_argument(
        "--fixture",
        default=None,
        help="Path to CV-REORG.yml (default: repo/conformance/fixtures/CV-REORG.yml)",
    )
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parents[2]
    fixture_path = (
        Path(args.fixture).resolve()
        if args.fixture
        else repo_root / "conformance" / "fixtures" / "CV-REORG.yml"
    )
    fixture = load_yaml(fixture_path)
    if fixture.get("gate") != "CV-REORG":
        print(f"invalid gate in fixture: {fixture_path}")
        return 1

    tests = fixture.get("tests")
    if not isinstance(tests, list) or not tests:
        print(f"fixture has no tests: {fixture_path}")
        return 1

    clients = build_clients(repo_root)
    failures: list[str] = []
    executed = 0

    for test in tests:
        if not isinstance(test, dict):
            failures.append("invalid test entry (not a mapping)")
            continue
        test_id = str(test.get("id", "<missing id>"))
        ctx = test.get("context")
        if not isinstance(ctx, dict):
            failures.append(f"{test_id}: missing context")
            continue
        outcome = str(test.get("expected_outcome", "")).strip()
        if not outcome:
            failures.append(f"{test_id}: missing expected_outcome")
            continue

        try:
            want = expected_token(test_id, outcome, ctx)
        except Exception as e:
            failures.append(f"{test_id}: {e}")
            continue

        (out_r, err_r, rc_r), (out_g, err_g, rc_g) = run_reorg(clients, ctx)
        executed += 1

        if rc_r != 0:
            failures.append(f"{test_id}: rust reorg failed: {extract_error_token(err_r)} ({err_r})")
            continue
        if rc_g != 0:
            failures.append(f"{test_id}: go reorg failed: {extract_error_token(err_g)} ({err_g})")
            continue

        got_r = out_r.strip()
        got_g = out_g.strip()
        if got_r != want:
            failures.append(f"{test_id}: rust expected {want}, got {got_r}")
        if got_g != want:
            failures.append(f"{test_id}: go expected {want}, got {got_g}")
        if got_r != got_g:
            failures.append(f"{test_id}: cross-client output mismatch rust={got_r} go={got_g}")

    if failures:
        print("CV-REORG: FAIL")
        for f in failures:
            print(f"- {f}")
        return 1

    print(f"CV-REORG: PASS ({executed} checks)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
