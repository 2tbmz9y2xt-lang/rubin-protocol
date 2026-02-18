#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import tempfile
from pathlib import Path

from run_cv_common import (
    build_clients,
    build_tx_hex,
    extract_error_token,
    load_yaml,
    parse_hex,
    parse_int,
    run,
)

CORE_P2PK = 0x0000
CORE_TIMELOCK_V1 = 0x0001
CORE_ANCHOR = 0x0002
SUITE_ID_SENTINEL = 0x00


def parse_txid_32(value: object) -> bytes:
    if not isinstance(value, str):
        return bytes(32)
    if ".." in value:
        return bytes(32)
    hex_only = re.sub(r"[^0-9a-fA-F]", "", value)
    if not hex_only:
        return bytes(32)
    raw = parse_hex(hex_only)
    if len(raw) > 32:
        return raw[:32]
    if len(raw) < 32:
        return raw.rjust(32, b"\x00")
    return raw


def timelock_data(lock_value: int = 0) -> bytes:
    return bytes([0x00]) + int(lock_value).to_bytes(8, "little", signed=False)


def run_apply_utxo(clients: dict[str, object], ctx: dict[str, object]) -> tuple[tuple[str, str, int], tuple[str, str, int]]:
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as f:
        json.dump(ctx, f)
        path = f.name
    try:
        rust = run(clients["rust"], ["apply-utxo", "--context-json", path])
        go = run(clients["go"], ["apply-utxo", "--context-json", path])
        return rust, go
    finally:
        Path(path).unlink(missing_ok=True)


def build_context_for_test(test_id: str, ctx: dict[str, object]) -> dict[str, object]:
    case_name = str(ctx.get("case", "")).strip().upper()

    if test_id == "UTXO-01":
        prev = ctx.get("tx_input_prevout")
        if not isinstance(prev, dict):
            raise ValueError("missing tx_input_prevout")
        tx_hex = build_tx_hex(
            version=1,
            tx_nonce=1,
            inputs=[
                {
                    "prev_txid": parse_txid_32(prev.get("txid")),
                    "prev_vout": parse_int(prev.get("vout", 0)),
                    "script_sig": b"",
                    "sequence": 1,
                }
            ],
            outputs=[{"value": 1, "covenant_type": CORE_P2PK, "covenant_data": bytes([0x01]) + bytes(32)}],
            locktime=0,
            witnesses=[{"suite_id": SUITE_ID_SENTINEL, "pubkey": b"", "sig": b""}],
        )
        return {
            "chain_id_hex": "00" * 32,
            "chain_height": 10,
            "chain_timestamp": 0,
            "suite_id_02_active": False,
            "tx_hex": tx_hex,
            "utxo_set": [],
        }

    if test_id == "UTXO-02":
        tx_inputs = ctx.get("tx_inputs")
        if not isinstance(tx_inputs, list) or len(tx_inputs) < 2:
            raise ValueError("missing tx_inputs")
        inputs = []
        witnesses = []
        for item in tx_inputs:
            if not isinstance(item, dict):
                raise ValueError("invalid tx_inputs item")
            prev = item.get("prevout")
            if not isinstance(prev, dict):
                raise ValueError("invalid prevout")
            inputs.append(
                {
                    "prev_txid": parse_txid_32(prev.get("txid")),
                    "prev_vout": parse_int(prev.get("vout", 0)),
                    "script_sig": b"",
                    "sequence": 1,
                }
            )
            witnesses.append({"suite_id": SUITE_ID_SENTINEL, "pubkey": b"", "sig": b""})
        tx_hex = build_tx_hex(
            version=1,
            tx_nonce=1,
            inputs=inputs,
            outputs=[{"value": 1, "covenant_type": CORE_P2PK, "covenant_data": bytes([0x01]) + bytes(32)}],
            locktime=0,
            witnesses=witnesses,
        )
        pre = ctx.get("preblock_utxo")
        if not isinstance(pre, dict):
            raise ValueError("missing preblock_utxo")
        utxo_entry = {
            "txid": parse_txid_32(pre.get("txid")).hex(),
            "vout": parse_int(pre.get("vout", 0)),
            "value": parse_int(pre.get("value", 0)),
            "covenant_type": CORE_TIMELOCK_V1,
            "covenant_data": timelock_data(0).hex(),
            "creation_height": 0,
            "created_by_coinbase": False,
        }
        return {
            "chain_id_hex": "00" * 32,
            "chain_height": 10,
            "chain_timestamp": 0,
            "suite_id_02_active": False,
            "tx_hex": tx_hex,
            "utxo_set": [utxo_entry],
        }

    if test_id == "UTXO-03":
        sum_inputs = parse_int(ctx.get("sum_inputs", 0))
        sum_outputs = parse_int(ctx.get("sum_outputs", 0))
        prev_txid = bytes([0xAB]) * 32
        tx_hex = build_tx_hex(
            version=1,
            tx_nonce=1,
            inputs=[
                {
                    "prev_txid": prev_txid,
                    "prev_vout": 0,
                    "script_sig": b"",
                    "sequence": 1,
                }
            ],
            outputs=[{"value": sum_outputs, "covenant_type": CORE_P2PK, "covenant_data": bytes([0x01]) + bytes(32)}],
            locktime=0,
            witnesses=[{"suite_id": SUITE_ID_SENTINEL, "pubkey": b"", "sig": b""}],
        )
        utxo_entry = {
            "txid": prev_txid.hex(),
            "vout": 0,
            "value": sum_inputs,
            "covenant_type": CORE_TIMELOCK_V1,
            "covenant_data": timelock_data(0).hex(),
            "creation_height": 0,
            "created_by_coinbase": False,
        }
        return {
            "chain_id_hex": "00" * 32,
            "chain_height": 10,
            "chain_timestamp": 0,
            "suite_id_02_active": False,
            "tx_hex": tx_hex,
            "utxo_set": [utxo_entry],
        }

    if test_id == "UTXO-04" or case_name == "TX_NONCE_INVALID":
        prev_txid = bytes([0xC1]) * 32
        tx_hex = build_tx_hex(
            version=1,
            tx_nonce=0,
            inputs=[
                {
                    "prev_txid": prev_txid,
                    "prev_vout": 0,
                    "script_sig": b"",
                    "sequence": 1,
                }
            ],
            outputs=[{"value": 1, "covenant_type": CORE_P2PK, "covenant_data": bytes([0x01]) + bytes(32)}],
            locktime=0,
            witnesses=[{"suite_id": SUITE_ID_SENTINEL, "pubkey": b"", "sig": b""}],
        )
        utxo_entry = {
            "txid": prev_txid.hex(),
            "vout": 0,
            "value": 2,
            "covenant_type": CORE_TIMELOCK_V1,
            "covenant_data": timelock_data(0).hex(),
            "creation_height": 0,
            "created_by_coinbase": False,
        }
        return {
            "chain_id_hex": "00" * 32,
            "chain_height": 10,
            "chain_timestamp": 0,
            "suite_id_02_active": False,
            "tx_hex": tx_hex,
            "utxo_set": [utxo_entry],
        }

    if test_id == "UTXO-05" or case_name == "SEQUENCE_INVALID":
        prev_txid = bytes([0xC2]) * 32
        tx_hex = build_tx_hex(
            version=1,
            tx_nonce=1,
            inputs=[
                {
                    "prev_txid": prev_txid,
                    "prev_vout": 0,
                    "script_sig": b"",
                    "sequence": 0xFFFF_FFFF,
                }
            ],
            outputs=[{"value": 1, "covenant_type": CORE_P2PK, "covenant_data": bytes([0x01]) + bytes(32)}],
            locktime=0,
            witnesses=[{"suite_id": SUITE_ID_SENTINEL, "pubkey": b"", "sig": b""}],
        )
        utxo_entry = {
            "txid": prev_txid.hex(),
            "vout": 0,
            "value": 2,
            "covenant_type": CORE_TIMELOCK_V1,
            "covenant_data": timelock_data(0).hex(),
            "creation_height": 0,
            "created_by_coinbase": False,
        }
        return {
            "chain_id_hex": "00" * 32,
            "chain_height": 10,
            "chain_timestamp": 0,
            "suite_id_02_active": False,
            "tx_hex": tx_hex,
            "utxo_set": [utxo_entry],
        }

    if test_id == "UTXO-06" or case_name == "ANCHOR_NONZERO_VALUE":
        prev_txid = bytes([0xC3]) * 32
        tx_hex = build_tx_hex(
            version=1,
            tx_nonce=1,
            inputs=[
                {
                    "prev_txid": prev_txid,
                    "prev_vout": 0,
                    "script_sig": b"",
                    "sequence": 1,
                }
            ],
            outputs=[{"value": 1, "covenant_type": CORE_ANCHOR, "covenant_data": b"\xAA"}],
            locktime=0,
            witnesses=[{"suite_id": SUITE_ID_SENTINEL, "pubkey": b"", "sig": b""}],
        )
        utxo_entry = {
            "txid": prev_txid.hex(),
            "vout": 0,
            "value": 2,
            "covenant_type": CORE_TIMELOCK_V1,
            "covenant_data": timelock_data(0).hex(),
            "creation_height": 0,
            "created_by_coinbase": False,
        }
        return {
            "chain_id_hex": "00" * 32,
            "chain_height": 10,
            "chain_timestamp": 0,
            "suite_id_02_active": False,
            "tx_hex": tx_hex,
            "utxo_set": [utxo_entry],
        }

    if test_id == "UTXO-07" or case_name == "COVENANT_UNKNOWN_TYPE":
        unknown_type = parse_int(ctx.get("unknown_covenant_type", 0x0200))
        prev_txid = bytes([0xC4]) * 32
        tx_hex = build_tx_hex(
            version=1,
            tx_nonce=1,
            inputs=[
                {
                    "prev_txid": prev_txid,
                    "prev_vout": 0,
                    "script_sig": b"",
                    "sequence": 1,
                }
            ],
            outputs=[{"value": 1, "covenant_type": unknown_type, "covenant_data": b"\x01"}],
            locktime=0,
            witnesses=[{"suite_id": SUITE_ID_SENTINEL, "pubkey": b"", "sig": b""}],
        )
        utxo_entry = {
            "txid": prev_txid.hex(),
            "vout": 0,
            "value": 2,
            "covenant_type": CORE_TIMELOCK_V1,
            "covenant_data": timelock_data(0).hex(),
            "creation_height": 0,
            "created_by_coinbase": False,
        }
        return {
            "chain_id_hex": "00" * 32,
            "chain_height": 10,
            "chain_timestamp": 0,
            "suite_id_02_active": False,
            "tx_hex": tx_hex,
            "utxo_set": [utxo_entry],
        }

    if test_id == "UTXO-08" or case_name == "COINBASE_IMMATURE":
        prev_txid = bytes([0xC5]) * 32
        chain_height = parse_int(ctx.get("chain_height", 50))
        creation_height = parse_int(ctx.get("creation_height", 1))
        tx_hex = build_tx_hex(
            version=1,
            tx_nonce=1,
            inputs=[
                {
                    "prev_txid": prev_txid,
                    "prev_vout": 0,
                    "script_sig": b"",
                    "sequence": 1,
                }
            ],
            outputs=[{"value": 1, "covenant_type": CORE_P2PK, "covenant_data": bytes([0x01]) + bytes(32)}],
            locktime=0,
            witnesses=[{"suite_id": SUITE_ID_SENTINEL, "pubkey": b"", "sig": b""}],
        )
        utxo_entry = {
            "txid": prev_txid.hex(),
            "vout": 0,
            "value": 2,
            "covenant_type": CORE_TIMELOCK_V1,
            "covenant_data": timelock_data(0).hex(),
            "creation_height": creation_height,
            "created_by_coinbase": True,
        }
        return {
            "chain_id_hex": "00" * 32,
            "chain_height": chain_height,
            "chain_timestamp": 0,
            "suite_id_02_active": False,
            "tx_hex": tx_hex,
            "utxo_set": [utxo_entry],
        }

    raise ValueError(f"unsupported UTXO test id: {test_id}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Run CV-UTXO conformance vectors against Rust + Go clients.")
    parser.add_argument(
        "--fixture",
        default=None,
        help="Path to CV-UTXO.yml (default: repo/conformance/fixtures/CV-UTXO.yml)",
    )
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parents[2]
    fixture_path = (
        Path(args.fixture).resolve()
        if args.fixture
        else repo_root / "conformance" / "fixtures" / "CV-UTXO.yml"
    )
    fixture = load_yaml(fixture_path)
    if fixture.get("gate") != "CV-UTXO":
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
        if not expected_error and not expected_code:
            failures.append(f"{test_id}: missing expected_error/expected_code")
            continue

        try:
            context_json = build_context_for_test(test_id, ctx)
        except Exception as e:
            failures.append(f"{test_id}: failed to build apply-utxo context: {e}")
            continue

        (out_r, err_r, rc_r), (out_g, err_g, rc_g) = run_apply_utxo(clients, context_json)
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
            if rc_r != 0:
                failures.append(f"{test_id}: rust expected PASS, got={tok_r}")
            if rc_g != 0:
                failures.append(f"{test_id}: go expected PASS, got={tok_g}")
            if rc_r == 0 and out_r != "OK":
                failures.append(f"{test_id}: rust expected OK, got={out_r}")
            if rc_g == 0 and out_g != "OK":
                failures.append(f"{test_id}: go expected OK, got={out_g}")
            if rc_r != rc_g:
                failures.append(f"{test_id}: cross-client rc mismatch rust={rc_r} go={rc_g}")
            continue

        failures.append(f"{test_id}: unsupported expected_code={expected_code}")

    if failures:
        print("CV-UTXO: FAIL")
        for f in failures:
            print(f"- {f}")
        return 1

    print(f"CV-UTXO: PASS ({executed} checks)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
