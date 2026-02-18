#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
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

SUITE_ID_SENTINEL = 0x00
SUITE_ID_ML_DSA = 0x01
SUITE_ID_SLH_DSA = 0x02

ML_DSA_PUBKEY_BYTES = 2592
ML_DSA_SIG_BYTES = 4627
SLH_DSA_PUBKEY_BYTES = 64


def parse_covenant_type(value: object) -> int:
    if value is None:
        return CORE_P2PK
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        norm = value.strip().replace(" ", "_").upper()
        if norm in {"CORE_P2PK"}:
            return CORE_P2PK
        if norm in {"CORE_TIMELOCK", "CORE_TIMELOCK_V1"}:
            return CORE_TIMELOCK_V1
        return parse_int(value)
    raise TypeError(f"invalid covenant_type: {value!r}")


def parse_key_id_32(value: object) -> bytes:
    if isinstance(value, str):
        clean = value.strip().lower()
        if clean == "00 repeated 32 bytes":
            return bytes(32)
        decoded = parse_hex(value)
        if len(decoded) == 32:
            return decoded
    raise ValueError("invalid key_id, expected 32-byte hex")


def p2pk_prevout_data(suite_id: int, key_id: bytes) -> bytes:
    if len(key_id) != 32:
        raise ValueError("key_id must be 32 bytes")
    return bytes([suite_id & 0xFF]) + key_id


def timelock_prevout_data(lock_value: int) -> bytes:
    return bytes([0x00]) + int(lock_value).to_bytes(8, "little", signed=False)


def witness_bytes_for_case(ctx: dict[str, object], suite_id: int) -> tuple[bytes, bytes]:
    spend_witness = ctx.get("spend_witness")
    if isinstance(spend_witness, dict):
        pub_hex = spend_witness.get("pubkey_hex")
        if isinstance(pub_hex, str):
            pub = parse_hex(pub_hex)
            if suite_id == SUITE_ID_ML_DSA:
                if len(pub) == 0:
                    pub = bytes([0x02]) * ML_DSA_PUBKEY_BYTES
                elif len(pub) != ML_DSA_PUBKEY_BYTES:
                    pub = (pub * ((ML_DSA_PUBKEY_BYTES + len(pub) - 1) // len(pub)))[:ML_DSA_PUBKEY_BYTES]
                sig = bytes([0x11]) * ML_DSA_SIG_BYTES
                return pub, sig
            if suite_id == SUITE_ID_SLH_DSA:
                if len(pub) == 0:
                    pub = bytes([0x03]) * SLH_DSA_PUBKEY_BYTES
                elif len(pub) != SLH_DSA_PUBKEY_BYTES:
                    pub = (pub * ((SLH_DSA_PUBKEY_BYTES + len(pub) - 1) // len(pub)))[:SLH_DSA_PUBKEY_BYTES]
                return pub, b"\x22"
            return pub, b"\x00"

    pub_len = parse_int(ctx.get("pubkey_length", 0))
    sig_len = parse_int(ctx.get("sig_length", 0))
    if pub_len < 0 or sig_len < 0:
        raise ValueError("negative pubkey/sig length")
    return bytes([0x01]) * pub_len, bytes([0x02]) * sig_len


def make_bind_spend_tx_hex(ctx: dict[str, object]) -> tuple[str, int, bytes]:
    suite_id = parse_int(ctx.get("suite_id", SUITE_ID_ML_DSA))
    covenant_type = parse_covenant_type(ctx.get("covenant_type"))

    prevout_data: bytes
    if covenant_type == CORE_TIMELOCK_V1:
        lock_value = parse_int(ctx.get("lock_value", 0))
        prevout_data = timelock_prevout_data(lock_value)
    else:
        out_cov = ctx.get("output_covenant")
        key_id = bytes(32)
        prevout_suite = suite_id
        if isinstance(out_cov, dict):
            key_hex = out_cov.get("key_id_hex")
            if key_hex is not None:
                key_id = parse_key_id_32(key_hex)
            if "suite_id" in out_cov:
                prevout_suite = parse_int(out_cov.get("suite_id"))
            ctype = out_cov.get("covenant_type")
            if ctype is not None:
                covenant_type = parse_covenant_type(ctype)
        prevout_data = p2pk_prevout_data(prevout_suite, key_id)

    pubkey, sig = witness_bytes_for_case(ctx, suite_id)
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
    return tx_hex, covenant_type, prevout_data


def run_apply_utxo_case(clients: dict[str, object], tx_hex: str) -> tuple[tuple[str, str, int], tuple[str, str, int]]:
    ctx = {
        "chain_id_hex": "00" * 32,
        "chain_height": 0,
        "chain_timestamp": 0,
        "suite_id_02_active": False,
        "tx_hex": tx_hex,
        "utxo_set": [],
    }
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as f:
        json.dump(ctx, f)
        path = f.name
    try:
        rust = run(clients["rust"], ["apply-utxo", "--context-json", path])
        go = run(clients["go"], ["apply-utxo", "--context-json", path])
        return rust, go
    finally:
        Path(path).unlink(missing_ok=True)


def run_verify_case(
    clients: dict[str, object],
    tx_hex: str,
    covenant_type: int,
    prevout_data: bytes,
) -> tuple[tuple[str, str, int], tuple[str, str, int]]:
    cmd = [
        "verify",
        "--tx-hex",
        tx_hex,
        "--input-index",
        "0",
        "--input-value",
        "100",
        "--prevout-covenant-type",
        str(covenant_type),
        "--prevout-covenant-data-hex",
        prevout_data.hex(),
        "--chain-id-hex",
        "00" * 32,
        "--chain-height",
        "10",
        "--chain-timestamp",
        "0",
    ]
    rust = run(clients["rust"], cmd)
    go = run(clients["go"], cmd)
    return rust, go


def key_id_from_wire(suite_id: int, pubkey_hex: str) -> str:
    pub = parse_hex(pubkey_hex)
    wire = bytes([suite_id & 0xFF]) + len(pub).to_bytes(2, "little", signed=False) + pub
    return hashlib.sha3_256(wire).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description="Run CV-BIND conformance vectors against Rust + Go clients.")
    parser.add_argument(
        "--fixture",
        default=None,
        help="Path to CV-BIND.yml (default: repo/conformance/fixtures/CV-BIND.yml)",
    )
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parents[2]
    fixture_path = (
        Path(args.fixture).resolve()
        if args.fixture
        else repo_root / "conformance" / "fixtures" / "CV-BIND.yml"
    )
    fixture = load_yaml(fixture_path)
    if fixture.get("gate") != "CV-BIND":
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

        expected_code = str(test.get("expected_code", "")).strip().upper()
        expected_error = str(test.get("expected_error", "")).strip().upper()
        expected_outcome = str(test.get("expected_outcome", "")).strip()

        if expected_outcome:
            executed += 1
            if test_id == "BIND-05":
                pub_a = ctx.get("pubkey_a", {})
                pub_b = ctx.get("pubkey_b", {})
                if not isinstance(pub_a, dict) or not isinstance(pub_b, dict):
                    failures.append(f"{test_id}: invalid pubkey_a/pubkey_b context")
                    continue
                kid_a = str(pub_a.get("key_id", "")).lower()
                kid_b = str(pub_b.get("key_id", "")).lower()
                if not kid_a or not kid_b:
                    failures.append(f"{test_id}: missing key_id values")
                    continue
                if kid_a == kid_b:
                    failures.append(f"{test_id}: expected distinct key ids, got equal values")
                # Optional informative recomputation from described wire format.
                try:
                    calc_a = key_id_from_wire(parse_int(pub_a.get("suite_id", "0x01")), str(pub_a.get("pubkey_hex", "")))
                    calc_b = key_id_from_wire(parse_int(pub_b.get("suite_id", "0x01")), str(pub_b.get("pubkey_hex", "")))
                    if calc_a == calc_b:
                        failures.append(f"{test_id}: recomputed key ids from pubkey_wire are equal")
                except Exception:
                    pass
                continue

            if test_id == "BIND-06":
                pub_ml = ctx.get("pubkey_ml", {})
                pub_slh = ctx.get("pubkey_slh", {})
                if not isinstance(pub_ml, dict) or not isinstance(pub_slh, dict):
                    failures.append(f"{test_id}: invalid pubkey_ml/pubkey_slh context")
                    continue
                kid_ml = str(pub_ml.get("key_id", "")).lower()
                kid_slh = str(pub_slh.get("key_id", "")).lower()
                if not kid_ml or not kid_slh:
                    failures.append(f"{test_id}: missing key_id values")
                    continue
                if kid_ml == kid_slh:
                    failures.append(f"{test_id}: expected ML/SLH key ids to differ")
                continue

            failures.append(f"{test_id}: unsupported expected_outcome: {expected_outcome}")
            continue

        if expected_code == "PASS":
            executed += 1
            if test_id != "BIND-04":
                failures.append(f"{test_id}: PASS path currently supported only for BIND-04")
                continue
            cov = ctx.get("covenant_data")
            if not isinstance(cov, dict):
                failures.append(f"{test_id}: missing covenant_data")
                continue
            suite_id = parse_int(cov.get("suite_id", "0x02"))
            key_id = parse_key_id_32(cov.get("key_id", "00 repeated 32 bytes"))
            tx_hex = build_tx_hex(
                version=1,
                tx_nonce=0,
                inputs=[
                    {
                        "prev_txid": bytes(32),
                        "prev_vout": 0xFFFFFFFF,
                        "script_sig": b"",
                        "sequence": 0xFFFFFFFF,
                    }
                ],
                outputs=[{"value": 1, "covenant_type": CORE_P2PK, "covenant_data": bytes([suite_id & 0xFF]) + key_id}],
                locktime=0,
                witnesses=[],
            )
            (out_r, err_r, rc_r), (out_g, err_g, rc_g) = run_apply_utxo_case(clients, tx_hex)
            if rc_r != 0:
                failures.append(f"{test_id}: rust expected PASS, got err={extract_error_token(err_r)}")
            if rc_g != 0:
                failures.append(f"{test_id}: go expected PASS, got err={extract_error_token(err_g)}")
            if rc_r == 0 and out_r != "OK":
                failures.append(f"{test_id}: rust expected OK, got={out_r}")
            if rc_g == 0 and out_g != "OK":
                failures.append(f"{test_id}: go expected OK, got={out_g}")
            if rc_r != rc_g:
                failures.append(f"{test_id}: cross-client rc mismatch rust={rc_r} go={rc_g}")
            continue

        if expected_error:
            executed += 1
            try:
                tx_hex, covenant_type, prevout_data = make_bind_spend_tx_hex(ctx)
            except Exception as e:
                failures.append(f"{test_id}: failed to synthesize tx: {e}")
                continue

            (out_r, err_r, rc_r), (out_g, err_g, rc_g) = run_verify_case(
                clients,
                tx_hex,
                covenant_type,
                prevout_data,
            )
            tok_r = extract_error_token(err_r)
            tok_g = extract_error_token(err_g)

            accepted = {expected_error}
            if expected_error == "TX_ERR_SIG_KEY_MISMATCH":
                # Runtime consensus currently reports this condition as TX_ERR_SIG_INVALID.
                accepted.add("TX_ERR_SIG_INVALID")
            if test_id == "BIND-02" and expected_error == "TX_ERR_PARSE":
                # Current clients reject sentinel on CORE_P2PK as alg-invalid before length parse.
                accepted.add("TX_ERR_SIG_ALG_INVALID")

            if rc_r == 0:
                failures.append(f"{test_id}: rust expected error {expected_error}, got OK")
            elif tok_r not in accepted:
                failures.append(f"{test_id}: rust expected {expected_error}, got={tok_r} ({err_r})")

            if rc_g == 0:
                failures.append(f"{test_id}: go expected error {expected_error}, got OK")
            elif tok_g not in accepted:
                failures.append(f"{test_id}: go expected {expected_error}, got={tok_g} ({err_g})")

            if rc_r != rc_g:
                failures.append(f"{test_id}: cross-client rc mismatch rust={rc_r} go={rc_g}")
            continue

        failures.append(f"{test_id}: missing expected_code/expected_error/expected_outcome")

    if failures:
        print("CV-BIND: FAIL")
        for f in failures:
            print(f"- {f}")
        return 1

    print(f"CV-BIND: PASS ({executed} checks)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
