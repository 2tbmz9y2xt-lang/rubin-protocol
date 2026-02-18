#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path

from run_cv_common import (
    build_clients,
    build_tx_hex,
    extract_error_token,
    load_yaml,
    parse_int,
    run,
)

CORE_P2PK = 0x0000

SUITE_ID_ML_DSA = 0x01
SUITE_ID_SLH_DSA = 0x02

ML_DSA_PUBKEY_BYTES = 2592
ML_DSA_SIG_BYTES = 4627
SLH_DSA_PUBKEY_BYTES = 64


def suite_bytes(suite_id: int) -> tuple[bytes, bytes]:
    if suite_id == SUITE_ID_ML_DSA:
        return bytes([0x11]) * ML_DSA_PUBKEY_BYTES, bytes([0x22]) * ML_DSA_SIG_BYTES
    if suite_id == SUITE_ID_SLH_DSA:
        return bytes([0x33]) * SLH_DSA_PUBKEY_BYTES, b"\x44"
    return bytes([0x55]) * 32, bytes([0x66]) * 64


def parse_suite_id(raw: object) -> int:
    return parse_int(raw)


def deployment_state(ctx: dict[str, object]) -> str:
    profile = ctx.get("chain_profile")
    if isinstance(profile, dict):
        state = str(profile.get("deployment_state", "")).strip().upper()
        if state:
            return state
    deployment = ctx.get("deployment")
    if isinstance(deployment, dict):
        signal = deployment.get("signal_count_in_window")
        threshold = deployment.get("threshold")
        if signal is not None and threshold is not None:
            try:
                if parse_int(signal) >= parse_int(threshold):
                    return "LOCKED_IN"
            except Exception:
                pass
            return "FAILED"
    return ""


def suite_id_02_active(state: str) -> bool:
    return state in {"ACTIVE", "LOCKED_IN"}


def make_verify_tx_for_suite(suite_id: int) -> tuple[str, bytes]:
    pubkey, sig = suite_bytes(suite_id)
    key_id = hashlib.sha3_256(pubkey).digest()
    prevout_data = bytes([suite_id & 0xFF]) + key_id
    tx_hex = build_tx_hex(
        version=1,
        tx_nonce=1,
        inputs=[
            {
                "prev_txid": bytes(32),
                "prev_vout": 0,
                "script_sig": b"",
                "sequence": 1,
            }
        ],
        outputs=[{"value": 1, "covenant_type": CORE_P2PK, "covenant_data": bytes([SUITE_ID_ML_DSA]) + bytes(32)}],
        locktime=0,
        witnesses=[{"suite_id": suite_id, "pubkey": pubkey, "sig": sig}],
    )
    return tx_hex, prevout_data


def main() -> int:
    parser = argparse.ArgumentParser(description="Run CV-DEP conformance vectors against Rust + Go clients.")
    parser.add_argument(
        "--fixture",
        default=None,
        help="Path to CV-DEP.yml (default: repo/conformance/fixtures/CV-DEP.yml)",
    )
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parents[2]
    fixture_path = (
        Path(args.fixture).resolve()
        if args.fixture
        else repo_root / "conformance" / "fixtures" / "CV-DEP.yml"
    )
    fixture = load_yaml(fixture_path)
    if fixture.get("gate") != "CV-DEP":
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

        expected_error = str(test.get("expected_error", "")).strip().upper()
        expected_code = str(test.get("expected_code", "")).strip().upper()
        expected_deployment_state = str(test.get("expected_deployment_state", "")).strip().upper()
        expected_outcome = str(test.get("expected_outcome", "")).strip().upper()

        if expected_deployment_state or expected_outcome:
            executed += 1
            state = deployment_state(ctx)
            expected_state = expected_deployment_state or expected_outcome
            if state != expected_state:
                failures.append(f"{test_id}: expected deployment_state={expected_state}, got={state or '<empty>'}")
            continue

        tx_ctx = ctx.get("tx")
        if not isinstance(tx_ctx, dict):
            failures.append(f"{test_id}: missing tx context")
            continue
        suite_raw = tx_ctx.get("suite_id", tx_ctx.get("suite_id_hex", "0x01"))
        try:
            suite_id = parse_suite_id(suite_raw)
        except Exception as e:
            failures.append(f"{test_id}: invalid suite_id: {e}")
            continue

        try:
            tx_hex, prevout_data = make_verify_tx_for_suite(suite_id)
        except Exception as e:
            failures.append(f"{test_id}: failed to synthesize verify tx: {e}")
            continue

        state = deployment_state(ctx)
        cmd = [
            "verify",
            "--tx-hex",
            tx_hex,
            "--input-index",
            "0",
            "--input-value",
            "100",
            "--prevout-covenant-type",
            str(CORE_P2PK),
            "--prevout-covenant-data-hex",
            prevout_data.hex(),
            "--chain-id-hex",
            "00" * 32,
            "--chain-height",
            "10",
            "--chain-timestamp",
            "0",
        ]
        if suite_id_02_active(state):
            cmd.append("--suite-id-02-active")

        out_r, err_r, rc_r = run(clients["rust"], cmd)
        out_g, err_g, rc_g = run(clients["go"], cmd)
        tok_r = extract_error_token(err_r)
        tok_g = extract_error_token(err_g)
        executed += 1

        if expected_error:
            if rc_r == 0:
                failures.append(f"{test_id}: rust expected {expected_error}, got OK")
            elif tok_r != expected_error:
                failures.append(f"{test_id}: rust expected {expected_error}, got={tok_r} ({err_r})")

            if rc_g == 0:
                failures.append(f"{test_id}: go expected {expected_error}, got OK")
            elif tok_g != expected_error:
                failures.append(f"{test_id}: go expected {expected_error}, got={tok_g} ({err_g})")

            if rc_r != rc_g:
                failures.append(f"{test_id}: cross-client rc mismatch rust={rc_r} go={rc_g}")
            continue

        if expected_code == "PASS":
            # For dev providers signatures are intentionally invalid, so PASS here means
            # "deployment gate passed": no TX_ERR_DEPLOYMENT_INACTIVE at this stage.
            if tok_r == "TX_ERR_DEPLOYMENT_INACTIVE":
                failures.append(f"{test_id}: rust unexpectedly reported deployment inactive")
            if tok_g == "TX_ERR_DEPLOYMENT_INACTIVE":
                failures.append(f"{test_id}: go unexpectedly reported deployment inactive")

            if rc_r == 0 and out_r != "OK":
                failures.append(f"{test_id}: rust expected OK output on success, got={out_r}")
            if rc_g == 0 and out_g != "OK":
                failures.append(f"{test_id}: go expected OK output on success, got={out_g}")

            if rc_r != rc_g:
                failures.append(f"{test_id}: cross-client rc mismatch rust={rc_r} go={rc_g}")
            if rc_r != 0 and tok_r != tok_g:
                failures.append(f"{test_id}: cross-client error token mismatch rust={tok_r} go={tok_g}")
            continue

        failures.append(f"{test_id}: missing expected_code/expected_error")

    if failures:
        print("CV-DEP: FAIL")
        for f in failures:
            print(f"- {f}")
        return 1

    print(f"CV-DEP: PASS ({executed} checks)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
