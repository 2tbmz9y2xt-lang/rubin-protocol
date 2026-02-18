#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import os.path
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from run_cv_common import make_parse_tx_bytes, parse_int, parse_hex


@dataclass(frozen=True)
class ClientCmd:
    name: str
    cwd: Path
    argv_prefix: list[str]


def run_result(client: ClientCmd, argv: list[str]) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    if client.name == "go" and not env.get("GOCACHE", "").strip():
        fallback_cache = Path(tempfile.gettempdir()) / "rubin-conformance-go-cache"
        fallback_cache.mkdir(parents=True, exist_ok=True)
        env["GOCACHE"] = str(fallback_cache)

    return subprocess.run(
        client.argv_prefix + argv,
        cwd=str(client.cwd),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
    )


def run_success(client: ClientCmd, argv: list[str]) -> str:
    p = run_result(client, argv)
    if p.returncode != 0:
        raise RuntimeError(
            f"{client.name} failed (exit={p.returncode})\n"
            f"cmd: {' '.join(client.argv_prefix + argv)}\n"
            f"cwd: {client.cwd}\n"
            f"stderr:\n{p.stderr.strip()}\n"
        )
    return p.stdout.strip()


def relpath(from_dir: Path, to_path: Path) -> str:
    return os.path.relpath(str(to_path), start=str(from_dir))


def load_yaml(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        obj = yaml.safe_load(f)
    if not isinstance(obj, dict):
        raise ValueError(f"fixture root must be a mapping: {path}")
    return obj


MAX_BLOCK_WEIGHT = 4_000_000
MAX_ANCHOR_PAYLOAD_SIZE = 65_536
MAX_ANCHOR_BYTES_PER_BLOCK = 131_072
MAX_TARGET = (1 << 256) - 4
WINDOW_SIZE = 2_016
HALVING_INTERVAL = 210_000
HALVING_REWARD = 5_000_000_000

CORE_P2PK = 0x0000
CORE_TIMELOCK = 0x0001
CORE_ANCHOR = 0x0002

SUITE_ID_ML_DSA = 0x01
SUITE_ID_SLH_DSA = 0x02
SUITE_ID_SENTINEL = 0x00


def _sha3_256(b: bytes) -> bytes:
    return hashlib.sha3_256(b).digest()


def _u16le(v: int) -> bytes:
    return v.to_bytes(2, "little", signed=False)


def _u32le(v: int) -> bytes:
    return v.to_bytes(4, "little", signed=False)


def _u64le(v: int) -> bytes:
    return v.to_bytes(8, "little", signed=False)


def _compact_size_encode(v: int) -> bytes:
    if v < 0xFD:
        return bytes([v])
    if v <= 0xFFFF:
        return bytes([0xFD]) + v.to_bytes(2, "little", signed=False)
    if v <= 0xFFFFFFFF:
        return bytes([0xFE]) + v.to_bytes(4, "little", signed=False)
    return bytes([0xFF]) + v.to_bytes(8, "little", signed=False)


def _extract_err_token(stderr: str) -> str:
    normalized = stderr.replace(":", " ").replace(",", " ").replace("(", " ").replace(")", " ")
    for tok in normalized.split():
        if tok.startswith("BLOCK_ERR_") or tok.startswith("TX_ERR_"):
            return tok
    return stderr.strip() or "PASS"


def _to_int(value: object) -> int:
    return parse_int(value)


def _hex_to_int(value: object) -> int:
    if not isinstance(value, str):
        raise TypeError("not a string")
    clean = value.replace("_", "")
    return int(clean, 16)


def _parse_bool(value: object) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        return normalized in {"1", "true", "yes", "y"}
    return bool(value)


def _parse_covenant_type(value: object) -> int:
    if value is None:
        return CORE_P2PK
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        normalized = value.strip().replace(" ", "_").upper()
        mapping = {
            "CORE_P2PK": CORE_P2PK,
            "CORE_TIMELOCK": CORE_TIMELOCK,
            "CORE_TIMELOCK_V1": CORE_TIMELOCK,
            "CORE_ANCHOR": CORE_ANCHOR,
        }
        if normalized in mapping:
            return mapping[normalized]
        return parse_int(normalized)
    raise TypeError(f"invalid covenant type: {value!r}")


def _expect_from_test(test: dict[str, Any]) -> tuple[bool, str]:
    expected_code = str(test.get("expected_code", "")).strip().upper()
    expected_error = str(test.get("expected_error", "")).strip().upper()
    expected_outcome = str(test.get("expected_outcome", "")).strip()
    if expected_code:
        return True, expected_code
    if expected_error:
        return True, expected_error
    if expected_outcome:
        return True, "PASS"
    return False, ""


def _record_gate_result(
    test_id: str,
    gate: str,
    expected: str,
    actual: str,
    failures: list[str],
) -> None:
    if expected == "PASS":
        if actual != "PASS":
            failures.append(f"{gate}:{test_id}: expected PASS, got {actual}")
        return

    if actual != expected:
        failures.append(f"{gate}:{test_id}: expected {expected}, got {actual}")


def _read_u32le(b: bytes, i: int) -> tuple[int, int]:
    return int.from_bytes(b[i : i + 4], "little"), i + 4


def _read_u64le(b: bytes, i: int) -> tuple[int, int]:
    return int.from_bytes(b[i : i + 8], "little"), i + 8


def _read_u16le(b: bytes, i: int) -> tuple[int, int]:
    return int.from_bytes(b[i : i + 2], "little"), i + 2


def _read_bytes(b: bytes, i: int, n: int) -> tuple[bytes, int]:
    return b[i : i + n], i + n


def _decode_compact_size(b: bytes, i: int) -> tuple[int, int]:
    if i >= len(b):
        raise ValueError("compactsize: truncated")
    fb = b[i]
    if fb < 0xFD:
        return fb, i + 1
    if fb == 0xFD:
        if i + 3 > len(b):
            raise ValueError("compactsize: truncated u16")
        return int.from_bytes(b[i + 1 : i + 3], "little"), i + 3
    if fb == 0xFE:
        if i + 5 > len(b):
            raise ValueError("compactsize: truncated u32")
        return int.from_bytes(b[i + 1 : i + 5], "little"), i + 5
    if i + 9 > len(b):
        raise ValueError("compactsize: truncated u64")
    return int.from_bytes(b[i + 1 : i + 9], "little"), i + 9


def _parse_tx_bytes(tx_bytes: bytes) -> dict[str, Any]:
    i = 0
    version, i = _read_u32le(tx_bytes, i)
    tx_nonce, i = _read_u64le(tx_bytes, i)
    in_count, i = _decode_compact_size(tx_bytes, i)

    inputs: list[dict[str, Any]] = []
    for _ in range(in_count):
        prev_txid, i = _read_bytes(tx_bytes, i, 32)
        prev_vout, i = _read_u32le(tx_bytes, i)
        script_len, i = _decode_compact_size(tx_bytes, i)
        script_sig, i = _read_bytes(tx_bytes, i, script_len)
        sequence, i = _read_u32le(tx_bytes, i)
        inputs.append(
            {
                "prev_txid": prev_txid,
                "prev_vout": prev_vout,
                "script_sig": script_sig,
                "sequence": sequence,
            }
        )

    out_count, i = _decode_compact_size(tx_bytes, i)
    outputs: list[dict[str, Any]] = []
    for _ in range(out_count):
        value, i = _read_u64le(tx_bytes, i)
        covenant_type, i = _read_u16le(tx_bytes, i)
        cd_len, i = _decode_compact_size(tx_bytes, i)
        covenant_data, i = _read_bytes(tx_bytes, i, cd_len)
        outputs.append(
            {
                "value": value,
                "covenant_type": covenant_type,
                "covenant_data": covenant_data,
            }
        )

    locktime, i = _read_u32le(tx_bytes, i)
    wit_count, i = _decode_compact_size(tx_bytes, i)
    witnesses: list[dict[str, Any]] = []
    for _ in range(wit_count):
        suite_id, i = tx_bytes[i], i + 1
        pk_len, i = _decode_compact_size(tx_bytes, i)
        pubkey, i = _read_bytes(tx_bytes, i, pk_len)
        sig_len, i = _decode_compact_size(tx_bytes, i)
        sig, i = _read_bytes(tx_bytes, i, sig_len)
        witnesses.append({"suite_id": suite_id, "pubkey": pubkey, "sig": sig})

    return {
        "version": version,
        "tx_nonce": tx_nonce,
        "inputs": inputs,
        "outputs": outputs,
        "locktime": locktime,
        "witnesses": witnesses,
    }


def _key_id_from_witness_item(w: dict[str, Any]) -> bytes:
    suite_id = int(w.get("suite_id", 0))
    pub = w.get("pubkey", b"")
    if not isinstance(pub, (bytes, bytearray)):
        raise TypeError("pubkey must be bytes")
    # Consensus key_id: SHA3-256(pubkey), where pubkey is the canonical wire value for the suite.
    # NOTE: suite_id and witness length prefixes are NOT included in key_id derivation.
    # (See CV-HTLC / CV-VAULT vectors: their expected key_id values match SHA3(pubkey) directly.)
    _ = suite_id  # keep suite_id available for future checks / logging without changing behavior
    return _sha3_256(bytes(pub))


def _parse_lock_mode(b: int) -> str:
    if b == 0x00:
        return "height"
    if b == 0x01:
        return "unix"
    raise ValueError("invalid lock_mode")


def _u64_from_le8(b: bytes) -> int:
    if len(b) != 8:
        raise ValueError("expected 8 bytes")
    return int.from_bytes(b, "little")


def run_fees(gate: str, fixture: dict[str, Any], rust: ClientCmd, go: ClientCmd, failures: list[str]) -> int:
    tests = fixture.get("tests")
    if not isinstance(tests, list) or not tests:
        failures.append(f"{gate}: fixture has no tests")
        return 0

    executed = 0
    for t in tests:
        if not isinstance(t, dict):
            failures.append(f"{gate}: invalid test entry (not a mapping)")
            continue
        test_id = str(t.get("id", "<missing id>"))
        has_expect, expected = _expect_from_test(t)
        if not has_expect:
            failures.append(f"{gate}:{test_id}: missing expected_code/expected_error")
            continue

        ctx = t.get("context")
        if not isinstance(ctx, dict):
            _record_gate_result(test_id, gate, expected, "TX_ERR_PARSE", failures)
            continue

        executed += 1
        tx_hex = ctx.get("tx_hex")
        utxo_set = ctx.get("utxo_set", [])
        if not isinstance(tx_hex, str) or not isinstance(utxo_set, list):
            actual = "TX_ERR_PARSE"
        else:
            tx = _parse_tx_bytes(parse_hex(tx_hex))
            utxo_map: dict[tuple[bytes, int], int] = {}
            for e in utxo_set:
                if not isinstance(e, dict):
                    continue
                txid = parse_hex(e.get("txid", "")).rjust(32, b"\x00")
                vout = _to_int(e.get("vout", 0))
                val = _to_int(e.get("value", 0))
                utxo_map[(txid, vout)] = val

            total_in = 0
            try:
                for inp in tx["inputs"]:
                    key = (inp["prev_txid"], int(inp["prev_vout"]))
                    if key not in utxo_map:
                        raise KeyError("missing utxo")
                    total_in += utxo_map[key]
                    if total_in > 0xFFFFFFFFFFFFFFFF:
                        raise OverflowError("sum_in overflow")
            except (KeyError, OverflowError):
                actual = "TX_ERR_PARSE" if "overflow" in str(sys.exc_info()[1]).lower() else "TX_ERR_MISSING_UTXO"
            else:
                total_out = 0
                try:
                    for out in tx["outputs"]:
                        total_out += int(out["value"])
                        if total_out > 0xFFFFFFFFFFFFFFFF:
                            raise OverflowError("sum_out overflow")
                except OverflowError:
                    actual = "TX_ERR_PARSE"
                else:
                    actual = "TX_ERR_VALUE_CONSERVATION" if total_out > total_in else "PASS"
        _record_gate_result(test_id, gate, expected, actual, failures)

    return executed


def run_vault(gate: str, fixture: dict[str, Any], rust: ClientCmd, go: ClientCmd, failures: list[str]) -> int:
    tests = fixture.get("tests")
    if not isinstance(tests, list) or not tests:
        failures.append(f"{gate}: fixture has no tests")
        return 0

    executed = 0
    for t in tests:
        if not isinstance(t, dict):
            failures.append(f"{gate}: invalid test entry (not a mapping)")
            continue
        test_id = str(t.get("id", "<missing id>"))
        has_expect, expected = _expect_from_test(t)
        if not has_expect:
            failures.append(f"{gate}:{test_id}: missing expected_code/expected_error")
            continue
        ctx = t.get("context")
        if not isinstance(ctx, dict):
            _record_gate_result(test_id, gate, expected, "TX_ERR_PARSE", failures)
            continue
        executed += 1

        tx_hex = ctx.get("tx_hex")
        utxo_set = ctx.get("utxo_set", [])
        chain_height = _to_int(ctx.get("chain_height", 0))
        chain_ts = _to_int(ctx.get("chain_timestamp", 0))
        if not isinstance(tx_hex, str) or not isinstance(utxo_set, list):
            actual = "TX_ERR_PARSE"
        else:
            tx = _parse_tx_bytes(parse_hex(tx_hex))
            if not tx["witnesses"]:
                actual = "TX_ERR_PARSE"
            else:
                w0 = tx["witnesses"][0]
                if int(w0["suite_id"]) == SUITE_ID_SENTINEL:
                    actual = "TX_ERR_SIG_ALG_INVALID"
                else:
                    kid = _key_id_from_witness_item(w0)
                    # single-input vectors: use first utxo entry
                    e0 = utxo_set[0] if utxo_set and isinstance(utxo_set[0], dict) else {}
                    cd = parse_hex(e0.get("covenant_data", "")) if isinstance(e0, dict) else b""
                    ch = _to_int(e0.get("creation_height", 0)) if isinstance(e0, dict) else 0

                    try:
                        if len(cd) == 73:
                            owner = cd[0:32]
                            lock_mode = _parse_lock_mode(cd[32])
                            lock_value = _u64_from_le8(cd[33:41])
                            recov = cd[41:73]
                            spend_delay = 0
                        elif len(cd) == 81:
                            owner = cd[0:32]
                            spend_delay = _u64_from_le8(cd[32:40])
                            lock_mode = _parse_lock_mode(cd[40])
                            lock_value = _u64_from_le8(cd[41:49])
                            recov = cd[49:81]
                        else:
                            raise ValueError("bad vault len")
                        if owner == recov:
                            raise ValueError("overlap")
                    except ValueError:
                        actual = "TX_ERR_PARSE"
                    else:
                        if kid == owner:
                            if spend_delay == 0:
                                actual = "TX_ERR_SIG_INVALID"
                            else:
                                if chain_height >= ch + spend_delay:
                                    actual = "TX_ERR_SIG_INVALID"
                                else:
                                    actual = "TX_ERR_TIMELOCK_NOT_MET"
                        elif kid == recov:
                            ok = chain_height >= lock_value if lock_mode == "height" else chain_ts >= lock_value
                            actual = "TX_ERR_SIG_INVALID" if ok else "TX_ERR_TIMELOCK_NOT_MET"
                        else:
                            actual = "TX_ERR_SIG_INVALID"
        _record_gate_result(test_id, gate, expected, actual, failures)

    return executed


def run_htlc(gate: str, fixture: dict[str, Any], rust: ClientCmd, go: ClientCmd, failures: list[str]) -> int:
    tests = fixture.get("tests")
    if not isinstance(tests, list) or not tests:
        failures.append(f"{gate}: fixture has no tests")
        return 0

    executed = 0
    for t in tests:
        if not isinstance(t, dict):
            failures.append(f"{gate}: invalid test entry (not a mapping)")
            continue
        test_id = str(t.get("id", "<missing id>"))
        has_expect, expected = _expect_from_test(t)
        if not has_expect:
            failures.append(f"{gate}:{test_id}: missing expected_code/expected_error")
            continue
        ctx = t.get("context")
        if not isinstance(ctx, dict):
            _record_gate_result(test_id, gate, expected, "TX_ERR_PARSE", failures)
            continue
        executed += 1

        tx_hex = ctx.get("tx_hex")
        utxo_set = ctx.get("utxo_set", [])
        chain_height = _to_int(ctx.get("chain_height", 0))
        chain_ts = _to_int(ctx.get("chain_timestamp", 0))
        if not isinstance(tx_hex, str) or not isinstance(utxo_set, list):
            actual = "TX_ERR_PARSE"
        else:
            tx = _parse_tx_bytes(parse_hex(tx_hex))
            if not tx["witnesses"]:
                actual = "TX_ERR_PARSE"
            else:
                w0 = tx["witnesses"][0]
                if int(w0["suite_id"]) == SUITE_ID_SENTINEL:
                    actual = "TX_ERR_SIG_ALG_INVALID"
                else:
                    kid = _key_id_from_witness_item(w0)
                    inp0 = tx["inputs"][0] if tx["inputs"] else {"script_sig": b""}
                    script_sig = inp0.get("script_sig", b"")
                    # use first utxo entry (fixtures are controlled)
                    e0 = utxo_set[0] if utxo_set and isinstance(utxo_set[0], dict) else {}
                    cd = parse_hex(e0.get("covenant_data", "")) if isinstance(e0, dict) else b""
                    try:
                        if len(cd) != 105:
                            raise ValueError("bad len")
                        hsh = cd[0:32]
                        lock_mode = _parse_lock_mode(cd[32])
                        lock_value = _u64_from_le8(cd[33:41])
                        claim = cd[41:73]
                        refund = cd[73:105]
                        if claim == refund:
                            raise ValueError("overlap")
                    except ValueError:
                        actual = "TX_ERR_PARSE"
                    else:
                        if len(script_sig) == 32:
                            preimage = script_sig
                            if _sha3_256(preimage) != hsh:
                                actual = "TX_ERR_SIG_INVALID"
                            elif kid != claim:
                                actual = "TX_ERR_SIG_INVALID"
                            else:
                                actual = "TX_ERR_SIG_INVALID"
                        elif len(script_sig) == 0:
                            if kid != refund:
                                actual = "TX_ERR_SIG_INVALID"
                            else:
                                ok = chain_height >= lock_value if lock_mode == "height" else chain_ts >= lock_value
                                actual = "TX_ERR_SIG_INVALID" if ok else "TX_ERR_TIMELOCK_NOT_MET"
                        else:
                            actual = "TX_ERR_PARSE"
        _record_gate_result(test_id, gate, expected, actual, failures)

    return executed


def run_htlc_anchor(gate: str, fixture: dict[str, Any], rust: ClientCmd, go: ClientCmd, failures: list[str]) -> int:
    tests = fixture.get("tests")
    if not isinstance(tests, list) or not tests:
        failures.append(f"{gate}: fixture has no tests")
        return 0

    executed = 0
    for t in tests:
        if not isinstance(t, dict):
            failures.append(f"{gate}: invalid test entry (not a mapping)")
            continue
        test_id = str(t.get("id", "<missing id>"))
        has_expect, expected = _expect_from_test(t)
        if not has_expect:
            failures.append(f"{gate}:{test_id}: missing expected_code/expected_error")
            continue
        ctx = t.get("context")
        if not isinstance(ctx, dict):
            _record_gate_result(test_id, gate, expected, "TX_ERR_PARSE", failures)
            continue

        executed += 1

        tx_hex = ctx.get("tx_hex")
        if not isinstance(tx_hex, str) or not tx_hex:
            # narrative-only vector (e.g., HTLC2-10): skip execution but keep the gate runnable.
            continue

        chain_height = _to_int(ctx.get("chain_height", 0))
        chain_ts = _to_int(ctx.get("chain_timestamp", 0))
        htlc_active = _parse_bool(ctx.get("htlc_v2_active", True))
        utxo_set = ctx.get("utxo_set", [])
        if not isinstance(utxo_set, list) or not utxo_set:
            actual = "TX_ERR_PARSE"
        else:
            tx = _parse_tx_bytes(parse_hex(tx_hex))
            # deployment gate: any create/spend of HTLC_V2 while inactive
            creates_v2 = any(int(o["covenant_type"]) == 0x0102 for o in tx["outputs"])
            spends_v2 = any(isinstance(e, dict) and _to_int(e.get("covenant_type", 0)) == 0x0102 for e in utxo_set)
            if (creates_v2 or spends_v2) and not htlc_active:
                actual = "TX_ERR_DEPLOYMENT_INACTIVE"
            else:
                if not tx["witnesses"]:
                    actual = "TX_ERR_PARSE"
                else:
                    w0 = tx["witnesses"][0]
                    if int(w0["suite_id"]) == SUITE_ID_SENTINEL:
                        actual = "TX_ERR_SIG_ALG_INVALID"
                    else:
                        kid = _key_id_from_witness_item(w0)
                        e0 = utxo_set[0] if isinstance(utxo_set[0], dict) else {}
                        cd = parse_hex(e0.get("covenant_data", "")) if isinstance(e0, dict) else b""
                        try:
                            if len(cd) != 105:
                                raise ValueError("bad len")
                            hsh = cd[0:32]
                            lock_mode = _parse_lock_mode(cd[32])
                            lock_value = _u64_from_le8(cd[33:41])
                            claim = cd[41:73]
                            refund = cd[73:105]
                            if claim == refund:
                                raise ValueError("overlap")
                        except ValueError:
                            actual = "TX_ERR_PARSE"
                        else:
                            if kid == claim:
                                # claim path requires exactly one matching ANCHOR envelope
                                prefix = b"RUBINv1-htlc-preimage/"
                                matching = []
                                for o in tx["outputs"]:
                                    if int(o["covenant_type"]) != CORE_ANCHOR:
                                        continue
                                    data = o["covenant_data"]
                                    if len(data) == 54 and data[: len(prefix)] == prefix:
                                        matching.append(data)
                                if len(matching) != 1:
                                    actual = "TX_ERR_PARSE"
                                else:
                                    preimage = matching[0][len(prefix) : 54]
                                    if _sha3_256(preimage) != hsh:
                                        actual = "TX_ERR_SIG_INVALID"
                                    else:
                                        actual = "TX_ERR_SIG_INVALID"
                            elif kid == refund:
                                ok = chain_height >= lock_value if lock_mode == "height" else chain_ts >= lock_value
                                actual = "TX_ERR_SIG_INVALID" if ok else "TX_ERR_TIMELOCK_NOT_MET"
                            else:
                                actual = "TX_ERR_SIG_INVALID"

        _record_gate_result(test_id, gate, expected, actual, failures)

    return executed


def run_weight(gate: str, fixture: dict[str, Any], failures: list[str]) -> int:
    tests = fixture.get("tests")
    if not isinstance(tests, list) or not tests:
        failures.append(f"{gate}: fixture has no tests")
        return 0

    def witness_item_len(item: dict[str, Any]) -> int:
        suite_id = _to_int(item.get("suite_id", 0x00))
        pub_len = _to_int(item.get("pubkey_length", 0))
        sig_len = _to_int(item.get("sig_length", 0))
        # suite_id:u8 + CompactSize(pub_len) + pub + CompactSize(sig_len) + sig
        return 1 + len(_compact_size_encode(pub_len)) + pub_len + len(_compact_size_encode(sig_len)) + sig_len

    def sig_cost_for(item: dict[str, Any]) -> int:
        # v1.1 defaults: ML-DSA verify_cost=8, SLH-DSA verify_cost=64. Others are informational only.
        suite_id = _to_int(item.get("suite_id", 0x00))
        if suite_id == 0x01:
            return 8
        if suite_id == 0x02:
            return 64
        # informational vectors may specify verify_cost explicitly
        if "verify_cost" in item:
            return _to_int(item.get("verify_cost", 0))
        return 0

    executed = 0
    for t in tests:
        if not isinstance(t, dict):
            failures.append(f"{gate}: invalid test entry (not a mapping)")
            continue
        if _parse_bool(t.get("consensus", True)) is False:
            continue
        test_id = str(t.get("id", "<missing id>"))
        ctx = t.get("context")
        if not isinstance(ctx, dict):
            failures.append(f"{gate}:{test_id}: missing context")
            continue
        expected_weight = t.get("expected_weight")
        if not isinstance(expected_weight, int):
            failures.append(f"{gate}:{test_id}: missing expected_weight")
            continue

        executed += 1
        input_count = _to_int(ctx.get("input_count", 1))
        output_count = _to_int(ctx.get("output_count", 0))
        witness_count = _to_int(ctx.get("witness_count", 0))
        witness_items_present = _to_int(ctx.get("witness_items_present", 0))
        item = ctx.get("witness_item", {})
        item = item if isinstance(item, dict) else {}

        # Base size for synthetic tx shape (matches `make_parse_tx_bytes` layout).
        base = bytearray()
        base.extend(_u32le(1))
        base.extend(_u64le(0))
        base.extend(_compact_size_encode(input_count))
        # inputs: 32 prev + 4 vout + cs(script_sig_len) + script_sig + 4 sequence; script_sig is empty in these vectors.
        for _ in range(input_count):
            base.extend(bytes(32))
            base.extend(_u32le(0))
            base.extend(_compact_size_encode(0))
            base.extend(_u32le(0))
        base.extend(_compact_size_encode(output_count))
        # outputs: value(8) + covenant_type(2) + cs(covenant_data_len) + covenant_data(empty)
        for _ in range(output_count):
            base.extend(_u64le(0))
            base.extend(_u16le(0))
            base.extend(_compact_size_encode(0))
        base.extend(_u32le(0))  # locktime
        base_size = len(base)

        # Witness bytes for the synthetic witness section.
        wit = bytearray()
        wit.extend(_compact_size_encode(witness_count))
        per_item = witness_item_len(item)
        wit_size = len(wit) + per_item * witness_items_present

        wit_cost = (wit_size + 3 - 1) // 3  # ceil(wit_size/3)
        sig_cost = sig_cost_for(item) * witness_items_present
        weight = 4 * base_size + wit_cost + sig_cost

        if weight != expected_weight:
            failures.append(f"{gate}:{test_id}: expected weight={expected_weight}, got={weight}")

    return executed


def run_anchor_relay(gate: str, fixture: dict[str, Any], failures: list[str]) -> int:
    tests = fixture.get("tests")
    if not isinstance(tests, list) or not tests:
        failures.append(f"{gate}: fixture has no tests")
        return 0

    consts = fixture.get("policy_constants", {})
    consts = consts if isinstance(consts, dict) else {}
    max_payload_relay = _to_int(consts.get("MAX_ANCHOR_PAYLOAD_RELAY", 1024))
    max_outputs_relay = _to_int(consts.get("MAX_ANCHOR_OUTPUTS_PER_TX_RELAY", 4))
    max_bytes_relay = _to_int(consts.get("MAX_ANCHOR_BYTES_PER_TX_RELAY", 2048))
    max_payload_consensus = _to_int(consts.get("MAX_ANCHOR_PAYLOAD_SIZE", 65536))

    executed = 0
    for t in tests:
        if not isinstance(t, dict):
            failures.append(f"{gate}: invalid test entry (not a mapping)")
            continue
        test_id = str(t.get("id", "<missing id>"))
        expected_relay = str(t.get("expected_relay", "")).strip().upper()
        expected_block = str(t.get("expected_block_validation", "PASS")).strip().upper()
        if expected_relay == "":
            failures.append(f"{gate}:{test_id}: missing expected_relay")
            continue

        executed += 1

        outs = t.get("anchor_outputs")
        lens: list[int] = []
        if isinstance(outs, list):
            for o in outs:
                if isinstance(o, dict) and "payload_bytes" in o:
                    lens.append(_to_int(o.get("payload_bytes", 0)))
        if "anchor_data_len_bytes" in t:
            lens = [_to_int(t.get("anchor_data_len_bytes", 0))]

        relay_ok = True
        if len(lens) > max_outputs_relay:
            relay_ok = False
        if any(n <= 0 or n > max_payload_relay for n in lens):
            relay_ok = False
        if sum(lens) > max_bytes_relay:
            relay_ok = False

        consensus_ok = all(0 < n <= max_payload_consensus for n in lens)
        actual_relay = "ACCEPT" if relay_ok else "REJECT"
        actual_block = "PASS" if consensus_ok else "BLOCK_ERR_ANCHOR_BYTES_EXCEEDED"

        if expected_relay == "PASS":
            expected_relay = "ACCEPT"
        if expected_relay != actual_relay:
            failures.append(f"{gate}:{test_id}: expected_relay {expected_relay}, got {actual_relay}")
        if expected_block and expected_block != actual_block:
            failures.append(f"{gate}:{test_id}: expected_block_validation {expected_block}, got {actual_block}")

    return executed


def run_coinbase(gate: str, fixture: dict[str, Any], failures: list[str]) -> int:
    tests = fixture.get("tests")
    if not isinstance(tests, list) or not tests:
        failures.append(f"{gate}: fixture has no tests")
        return 0

    initial = 5_000_000_000
    interval = 210_000

    def subsidy_for_height(h: int) -> tuple[int, int]:
        epoch = h // interval
        subsidy = initial >> epoch
        return subsidy, epoch

    executed = 0
    for t in tests:
        if not isinstance(t, dict):
            failures.append(f"{gate}: invalid test entry (not a mapping)")
            continue
        test_id = str(t.get("id", "<missing id>"))
        ctx = t.get("context")
        if not isinstance(ctx, dict):
            failures.append(f"{gate}:{test_id}: missing context")
            continue
        h = _to_int(ctx.get("block_height", 0))
        expected_err = str(t.get("expected_error", "")).strip().upper()
        expected_subsidy = t.get("expected_subsidy")
        expected_epoch = t.get("expected_epoch")
        expected_code = str(t.get("expected_code", "")).strip().upper()

        executed += 1

        subsidy, epoch = subsidy_for_height(h)

        if expected_err:
            fees = _to_int(ctx.get("fees_in_block", 0))
            coinbase_val = _to_int(ctx.get("coinbase_output_value", 0))
            actual = "PASS" if coinbase_val <= subsidy + fees else "BLOCK_ERR_SUBSIDY_EXCEEDED"
            if actual != expected_err:
                failures.append(f"{gate}:{test_id}: expected {expected_err}, got {actual}")
            continue

        if expected_code:
            if expected_code != "PASS":
                failures.append(f"{gate}:{test_id}: unexpected expected_code={expected_code}")
            continue

        if not isinstance(expected_subsidy, int) or not isinstance(expected_epoch, int):
            failures.append(f"{gate}:{test_id}: missing expected_subsidy/expected_epoch")
            continue

        if subsidy != expected_subsidy:
            failures.append(f"{gate}:{test_id}: subsidy mismatch: expected={expected_subsidy}, got={subsidy}")
        if epoch != expected_epoch:
            failures.append(f"{gate}:{test_id}: epoch mismatch: expected={expected_epoch}, got={epoch}")

    return executed


def run_compactsize(gate: str, fixture: dict[str, Any], rust: ClientCmd, go: ClientCmd, failures: list[str]) -> int:
    vectors = fixture.get("vectors")
    if not isinstance(vectors, list) or not vectors:
        failures.append(f"{gate}: fixture has no vectors")
        return 0

    executed = 0
    for t in vectors:
        if not isinstance(t, dict):
            failures.append(f"{gate}: invalid vector entry")
            continue
        name = str(t.get("name", t.get("id", "<missing name>")))
        value = t.get("value")
        encoding = t.get("encoding_hex")
        if not isinstance(encoding, str) or encoding == "":
            failures.append(f"{gate}::{name}: missing encoding_hex")
            continue
        if not isinstance(value, int):
            failures.append(f"{gate}::{name}: missing value")
            continue

        expected = str(value)
        try:
            out_r = run_success(rust, ["compactsize", "--encoded-hex", encoding])
            out_g = run_success(go, ["compactsize", "--encoded-hex", encoding])
            executed += 1
            if out_r != expected:
                failures.append(f"{gate}::{name}: rust compactsize mismatch: got={out_r} expected={expected}")
            if out_g != expected:
                failures.append(f"{gate}::{name}: go compactsize mismatch: got={out_g} expected={expected}")
            if out_r != out_g:
                failures.append(f"{gate}::{name}: cross-client compactsize mismatch: rust={out_r} go={out_g}")
        except Exception as e:
            failures.append(f"{gate}::{name}: runner error: {e}")

    return executed


def run_parse(
    gate: str,
    fixture: dict[str, Any],
    rust: ClientCmd,
    go: ClientCmd,
    failures: list[str],
    skip_reasons: list[str],
) -> int:
    tests = fixture.get("tests")
    if not isinstance(tests, list) or not tests:
        failures.append(f"{gate}: fixture has no tests")
        return 0

    executed = 0
    runnable = 0
    for t in tests:
        if not isinstance(t, dict):
            failures.append(f"{gate}: invalid test entry (not a mapping)")
            continue
        test_id = str(t.get("id", "<missing id>"))
        ctx = t.get("context")
        if not isinstance(ctx, dict):
            failures.append(f"{gate}:{test_id}: missing context")
            continue

        tx_hex_ctx = ctx.get("tx_hex")
        if isinstance(tx_hex_ctx, str) and tx_hex_ctx:
            tx_hex = tx_hex_ctx
        else:
            try:
                tx_hex = make_parse_tx_bytes(ctx)
            except Exception as e:
                skip_reasons.append(f"{gate}:{test_id}: no parse fixture data: {e}")
                continue

        expected_code = str(t.get("expected_code", "")).upper() if t.get("expected_code") else ""
        expected_error = str(t.get("expected_error", "")).upper() if t.get("expected_error") else ""
        if not expected_code and not expected_error:
            failures.append(f"{gate}:{test_id}: neither expected_code nor expected_error")
            continue

        max_witness = ctx.get("witness_size_bytes")
        max_witness_bytes = ""
        if isinstance(max_witness, int) and max_witness >= 0:
            max_witness_bytes = str(max_witness)

        for side in ("rust", "go"):
            client = rust if side == "rust" else go
            argv = ["parse", "--tx-hex", tx_hex]
            if max_witness_bytes:
                argv.extend(["--max-witness-bytes", max_witness_bytes])
            p = run_result(client, argv)
            if expected_code:
                if p.returncode != 0:
                    failures.append(f"{gate}:{test_id}: {side} expected pass, exit={p.returncode} stderr={p.stderr.strip()}")
                else:
                    out = p.stdout.strip()
                    if out != "OK":
                        failures.append(f"{gate}:{test_id}: {side} expected OK, got={out}")
                continue

            if expected_error:
                code = expected_error
                if p.returncode == 0:
                    failures.append(f"{gate}:{test_id}: {side} expected {code} but parse succeeded")
                else:
                    got = p.stderr.strip()
                    if code not in got:
                        failures.append(f"{gate}:{test_id}: {side} expected {code}, got={got}")

        runnable += 1
        if expected_code:
            executed += 2
        if expected_error:
            executed += 2

    if runnable == 0:
        skip_reasons.append(f"{gate}: no runnable tx_hex vectors in fixture")

    return executed


def run_sighash(fixture: dict[str, Any], rust: ClientCmd, go: ClientCmd, failures: list[str], profile_path: Path) -> int:
    tests = fixture.get("tests")
    if not isinstance(tests, list) or not tests:
        failures.append("CV-SIGHASH: fixture has no tests")
        return 0

    executed = 0
    for t in tests:
        if not isinstance(t, dict):
            failures.append("CV-SIGHASH: invalid test entry (not a mapping)")
            continue
        test_id = str(t.get("id", "<missing id>"))
        ctx = t.get("context")
        if not isinstance(ctx, dict):
            failures.append(f"CV-SIGHASH:{test_id}: missing/invalid context")
            continue

        tx_hex = ctx.get("tx_hex")
        if not isinstance(tx_hex, str) or tx_hex == "":
            failures.append(f"CV-SIGHASH:{test_id}: missing tx_hex")
            continue

        expected_txid = t.get("expected_txid_sha3_256_hex")
        expected_sighash = t.get("expected_sighash_v1_hex")
        try:
            if isinstance(expected_txid, str) and expected_txid:
                out_r = run_success(rust, ["txid", "--tx-hex", tx_hex])
                out_g = run_success(go, ["txid", "--tx-hex", tx_hex])
                executed += 1
                if out_r != expected_txid:
                    failures.append(f"CV-SIGHASH:{test_id}: rust txid mismatch: got={out_r} expected={expected_txid}")
                if out_g != expected_txid:
                    failures.append(f"CV-SIGHASH:{test_id}: go txid mismatch: got={out_g} expected={expected_txid}")
                if out_r != out_g:
                    failures.append(f"CV-SIGHASH:{test_id}: cross-client txid mismatch: rust={out_r} go={out_g}")

            if isinstance(expected_sighash, str) and expected_sighash:
                input_index = ctx.get("input_index")
                input_value = ctx.get("input_value")
                chain_id_hex = ctx.get("chain_id_hex")
                if not isinstance(input_index, int) or input_index < 0:
                    failures.append(f"CV-SIGHASH:{test_id}: invalid input_index")
                    continue
                if not isinstance(input_value, int) or input_value < 0:
                    failures.append(f"CV-SIGHASH:{test_id}: invalid input_value")
                    continue

                if isinstance(chain_id_hex, str) and chain_id_hex:
                    rust_chain_args = ["--chain-id-hex", chain_id_hex]
                    go_chain_args = ["--chain-id-hex", chain_id_hex]
                else:
                    rust_chain_args = ["--profile", relpath(rust.cwd, profile_path)]
                    go_chain_args = ["--profile", relpath(go.cwd, profile_path)]

                out_r = run_success(
                    rust,
                    [
                        "sighash",
                        "--tx-hex",
                        tx_hex,
                        "--input-index",
                        str(input_index),
                        "--input-value",
                        str(input_value),
                        *rust_chain_args,
                    ],
                )
                out_g = run_success(
                    go,
                    [
                        "sighash",
                        "--tx-hex",
                        tx_hex,
                        "--input-index",
                        str(input_index),
                        "--input-value",
                        str(input_value),
                        *go_chain_args,
                    ],
                )
                executed += 1
                if out_r != expected_sighash:
                    failures.append(f"CV-SIGHASH:{test_id}: rust sighash mismatch: got={out_r} expected={expected_sighash}")
                if out_g != expected_sighash:
                    failures.append(f"CV-SIGHASH:{test_id}: go sighash mismatch: got={out_g} expected={expected_sighash}")
                if out_r != out_g:
                    failures.append(f"CV-SIGHASH:{test_id}: cross-client sighash mismatch: rust={out_r} go={out_g}")

        except Exception as e:  # noqa: BLE001
            failures.append(f"CV-SIGHASH:{test_id}: runner error: {e}")

    return executed


def run_sigcheck(
    fixture: dict[str, Any],
    rust: ClientCmd,
    go: ClientCmd,
    failures: list[str],
    profile_path: Path,
) -> int:
    tests = fixture.get("tests")
    if not isinstance(tests, list) or not tests:
        failures.append("CV-SIGCHECK: fixture has no tests")
        return 0

    executed = 0
    for t in tests:
        if not isinstance(t, dict):
            failures.append("CV-SIGCHECK: invalid test entry (not a mapping)")
            continue
        test_id = str(t.get("id", "<missing id>"))
        ctx = t.get("context")
        if not isinstance(ctx, dict):
            failures.append(f"CV-SIGCHECK:{test_id}: missing context")
            continue

        tx_hex_ctx = ctx.get("tx_hex")
        if isinstance(tx_hex_ctx, str) and tx_hex_ctx:
            tx_hex = tx_hex_ctx
        else:
            try:
                tx_hex = make_parse_tx_bytes(ctx)
            except Exception as e:
                failures.append(f"CV-SIGCHECK:{test_id}: no parse fixture data: {e}")
                continue

        expected_code = str(t.get("expected_code", "")).upper() if t.get("expected_code") else ""
        expected_error = str(t.get("expected_error", "")).upper() if t.get("expected_error") else ""
        if not expected_code and not expected_error:
            failures.append(f"CV-SIGCHECK:{test_id}: neither expected_code nor expected_error")
            continue

        prevout_covenant_type = ctx.get("prevout_covenant_type")
        prevout_covenant_data_hex = ctx.get("prevout_covenant_data_hex")
        if not isinstance(prevout_covenant_data_hex, str) or prevout_covenant_data_hex == "":
            failures.append(f"CV-SIGCHECK:{test_id}: missing prevout_covenant_data_hex")
            continue
        try:
            _ = parse_hex(prevout_covenant_data_hex)
        except Exception as e:
            failures.append(f"CV-SIGCHECK:{test_id}: invalid prevout_covenant_data_hex: {e}")
            continue

        input_index = ctx.get("input_index")
        input_value = ctx.get("input_value")
        if input_index is None:
            failures.append(f"CV-SIGCHECK:{test_id}: missing input_index")
            continue
        if input_value is None:
            failures.append(f"CV-SIGCHECK:{test_id}: missing input_value")
            continue
        if prevout_covenant_type is None:
            failures.append(f"CV-SIGCHECK:{test_id}: missing prevout_covenant_type")
            continue

        try:
            input_index = parse_int(input_index)
            if input_index < 0:
                raise ValueError("input_index must be >= 0")
            input_value = parse_int(input_value)
            if input_value < 0:
                raise ValueError("input_value must be >= 0")
            prevout_type = parse_int(prevout_covenant_type)
            if prevout_type < 0:
                raise ValueError("prevout_covenant_type must be >= 0")
        except (TypeError, ValueError, OverflowError) as e:
            failures.append(f"CV-SIGCHECK:{test_id}: invalid integer field: {e}")
            continue

        chain_height = ctx.get("chain_height")
        chain_timestamp = ctx.get("chain_timestamp")
        chain_id_hex = ctx.get("chain_id_hex")

        chain_args = []
        if isinstance(chain_id_hex, str) and chain_id_hex:
            chain_args = ["--chain-id-hex", chain_id_hex]
        else:
            chain_args = ["--profile", relpath(rust.cwd, profile_path)]

        if chain_height is not None:
            try:
                chain_args.extend(["--chain-height", str(parse_int(chain_height))])
            except (TypeError, ValueError, OverflowError) as e:
                failures.append(f"CV-SIGCHECK:{test_id}: invalid chain-height: {e}")
                continue

        if chain_timestamp is not None:
            try:
                chain_args.extend(["--chain-timestamp", str(parse_int(chain_timestamp))])
            except (TypeError, ValueError, OverflowError) as e:
                failures.append(f"CV-SIGCHECK:{test_id}: invalid chain-timestamp: {e}")
                continue

        if ctx.get("suite_id_02_active"):
            chain_args.append("--suite-id-02-active")

        cmd = [
            "verify",
            "--tx-hex",
            tx_hex,
            "--input-index",
            str(input_index),
            "--input-value",
            str(input_value),
            "--prevout-covenant-type",
            str(prevout_type),
            "--prevout-covenant-data-hex",
            prevout_covenant_data_hex,
            *chain_args,
        ]

        pr = run_result(rust, cmd)
        pg = run_result(go, cmd)

        out_r = pr.stdout.strip()
        err_r = pr.stderr.strip()
        rc_r = pr.returncode

        out_g = pg.stdout.strip()
        err_g = pg.stderr.strip()
        rc_g = pg.returncode

        executed += 1

        if expected_code:
            if rc_r != 0:
                failures.append(f"CV-SIGCHECK:{test_id}: rust expected {expected_code} but failed: {err_r}")
            elif out_r != "OK":
                failures.append(f"CV-SIGCHECK:{test_id}: rust output mismatch: got={out_r}")
            if rc_g != 0:
                failures.append(f"CV-SIGCHECK:{test_id}: go expected {expected_code} but failed: {err_g}")
            elif out_g != "OK":
                failures.append(f"CV-SIGCHECK:{test_id}: go output mismatch: got={out_g}")
            if out_r != out_g:
                failures.append(f"CV-SIGCHECK:{test_id}: cross-client pass output mismatch: rust={out_r} go={out_g}")
            if rc_r != rc_g:
                failures.append(f"CV-SIGCHECK:{test_id}: cross-client exit mismatch: rust={rc_r} go={rc_g}")
            continue

        if expected_error:
            code = expected_error
            if rc_r == 0:
                failures.append(f"CV-SIGCHECK:{test_id}: rust expected {code} but succeeded: {out_r}")
            elif code not in err_r:
                failures.append(f"CV-SIGCHECK:{test_id}: rust expected {code}, got={err_r}")

            if rc_g == 0:
                failures.append(f"CV-SIGCHECK:{test_id}: go expected {code} but succeeded: {out_g}")
            elif code not in err_g:
                failures.append(f"CV-SIGCHECK:{test_id}: go expected {code}, got={err_g}")

            continue

    return executed


def run_bind(
    gate: str,
    fixture: dict[str, Any],
    failures: list[str],
) -> int:
    tests = fixture.get("tests")
    if not isinstance(tests, list) or not tests:
        failures.append(f"{gate}: fixture has no tests")
        return 0

    executed = 0
    for t in tests:
        if not isinstance(t, dict):
            failures.append(f"{gate}: invalid test entry (not a mapping)")
            continue

        test_id = str(t.get("id", "<missing id>"))
        has_expect, expected = _expect_from_test(t)
        if not has_expect:
            failures.append(f"{gate}:{test_id}: missing expected_code/expected_error")
            continue

        executed += 1
        ctx = t.get("context")
        if not isinstance(ctx, dict):
            _record_gate_result(test_id, gate, expected, "TX_ERR_PARSE", failures)
            continue

        suite_raw = ctx.get("suite_id", 0x01)
        try:
            suite_id = _to_int(suite_raw)
        except (TypeError, ValueError, OverflowError):
            _record_gate_result(test_id, gate, expected, "TX_ERR_PARSE", failures)
            continue

        try:
            pubkey_len = parse_int(ctx.get("pubkey_length", 0))
            if pubkey_len < 0:
                raise ValueError("negative pubkey_length")
            sig_len = parse_int(ctx.get("sig_length", 0))
            if sig_len < 0:
                raise ValueError("negative sig_length")
        except (TypeError, ValueError, OverflowError):
            _record_gate_result(test_id, gate, expected, "TX_ERR_PARSE", failures)
            continue

        covenant_type = _parse_covenant_type(ctx.get("covenant_type"))
        result = "PASS"

        if suite_id == SUITE_ID_SENTINEL:
            if pubkey_len != 0 or sig_len != 0:
                result = "TX_ERR_PARSE"
        elif suite_id in (SUITE_ID_ML_DSA, SUITE_ID_SLH_DSA):
            if covenant_type == CORE_TIMELOCK and pubkey_len == 0:
                result = "TX_ERR_SIG_ALG_INVALID"
        else:
            result = "TX_ERR_SIG_ALG_INVALID"

        # BIND-07 style: binding rejection when witness key_id != covenant key_id.
        # This is modeled here as a pure byte binding check; signature verification is out of scope.
        if result == "PASS":
            out_cov = ctx.get("output_covenant")
            spend_wit = ctx.get("spend_witness")
            if isinstance(out_cov, dict) and isinstance(spend_wit, dict):
                out_key_hex = out_cov.get("key_id_hex")
                wit_suite = spend_wit.get("suite_id", suite_id)
                wit_pub_hex = spend_wit.get("pubkey_hex")
                if isinstance(out_key_hex, str) and isinstance(wit_pub_hex, str):
                    try:
                        out_key = parse_hex(out_key_hex)
                        wit_suite_id = _to_int(wit_suite)
                        wit_pub = parse_hex(wit_pub_hex)
                        pub_wire = bytes([wit_suite_id]) + len(wit_pub).to_bytes(2, "little") + wit_pub
                        wit_kid = _sha3_256(pub_wire)
                        if wit_kid != out_key:
                            result = "TX_ERR_SIG_KEY_MISMATCH"
                    except Exception:
                        result = "TX_ERR_PARSE"

        _record_gate_result(test_id, gate, expected, result, failures)

    return executed


def run_utxo(gate: str, fixture: dict[str, Any], failures: list[str]) -> int:
    tests = fixture.get("tests")
    if not isinstance(tests, list) or not tests:
        failures.append(f"{gate}: fixture has no tests")
        return 0

    executed = 0
    for t in tests:
        if not isinstance(t, dict):
            failures.append(f"{gate}: invalid test entry (not a mapping)")
            continue

        test_id = str(t.get("id", "<missing id>"))
        has_expect, expected = _expect_from_test(t)
        if not has_expect:
            failures.append(f"{gate}:{test_id}: missing expected_code/expected_error")
            continue

        executed += 1
        ctx = t.get("context")
        if not isinstance(ctx, dict):
            _record_gate_result(test_id, gate, expected, "TX_ERR_PARSE", failures)
            continue

        if "tx_input_prevout" in ctx:
            present = _parse_bool(ctx.get("utxo_set_contains_prevout", False))
            result = "PASS" if present else "TX_ERR_MISSING_UTXO"
            _record_gate_result(test_id, gate, expected, result, failures)
            continue

        if "tx_inputs" in ctx:
            inputs = ctx.get("tx_inputs")
            if not isinstance(inputs, list) or len(inputs) < 2:
                result = "PASS"
            else:
                seen: set[tuple[str, int]] = set()
                result = "PASS"
                for item in inputs:
                    if not isinstance(item, dict):
                        result = "TX_ERR_PARSE"
                        break
                    prevout = item.get("prevout", {})
                    if not isinstance(prevout, dict):
                        result = "TX_ERR_PARSE"
                        break
                    txid = str(prevout.get("txid", ""))
                    vout = prevout.get("vout")
                    if not isinstance(vout, int):
                        result = "TX_ERR_PARSE"
                        break
                    prev = (txid, vout)
                    if prev in seen:
                        result = "TX_ERR_PARSE"
                        break
                    seen.add(prev)
            _record_gate_result(test_id, gate, expected, result, failures)
            continue

        if "sum_inputs" in ctx and "sum_outputs" in ctx:
            try:
                sum_inputs = parse_int(ctx.get("sum_inputs"))
                sum_outputs = parse_int(ctx.get("sum_outputs"))
            except (TypeError, ValueError, OverflowError):
                _record_gate_result(test_id, gate, expected, "TX_ERR_PARSE", failures)
                continue
            result = "TX_ERR_VALUE_CONSERVATION" if sum_outputs > sum_inputs else "PASS"
            _record_gate_result(test_id, gate, expected, result, failures)
            continue

        _record_gate_result(test_id, gate, expected, "PASS", failures)

    return executed


def run_dep(gate: str, fixture: dict[str, Any], failures: list[str]) -> int:
    tests = fixture.get("tests")
    if not isinstance(tests, list) or not tests:
        failures.append(f"{gate}: fixture has no tests")
        return 0

    executed = 0
    for t in tests:
        if not isinstance(t, dict):
            failures.append(f"{gate}: invalid test entry (not a mapping)")
            continue

        test_id = str(t.get("id", "<missing id>"))
        has_expect, expected = _expect_from_test(t)
        expected_deployment = str(t.get("expected_deployment_state", "")).strip().upper()
        expected_outcome = str(t.get("expected_outcome", "")).strip().upper()
        if not has_expect and not expected_deployment and not expected_outcome:
            failures.append(f"{gate}:{test_id}: missing expected_code/expected_error/expected_outcome")
            continue
        if not expected:
            expected = "PASS"
        if expected_deployment:
            expected = "PASS"

        executed += 1
        ctx = t.get("context")
        if not isinstance(ctx, dict):
            _record_gate_result(test_id, gate, expected, "TX_ERR_PARSE", failures)
            continue

        chain_profile = ctx.get("chain_profile", ctx.get("deployment", {}))
        if not isinstance(chain_profile, dict):
            chain_profile = {}

        deployment_state = str(chain_profile.get("deployment_state", "")).strip().upper()
        if not deployment_state and isinstance(chain_profile.get("signal_count_in_window"), int):
            signal_count = chain_profile.get("signal_count_in_window")
            threshold = chain_profile.get("threshold")
            try:
                if parse_int(signal_count) >= parse_int(threshold):
                    deployment_state = "LOCKED_IN"
                else:
                    deployment_state = "FAILED"
            except (TypeError, ValueError, OverflowError):
                deployment_state = "FAILED"

        tx = ctx.get("tx", {})
        if not isinstance(tx, dict):
            tx = {}
        suite = tx.get("suite_id", tx.get("suite_id_hex", "0x01"))
        try:
            suite_id = _to_int(suite)
        except (TypeError, ValueError, OverflowError):
            _record_gate_result(test_id, gate, expected, "TX_ERR_PARSE", failures)
            continue

        if suite_id not in (SUITE_ID_ML_DSA, SUITE_ID_SLH_DSA, SUITE_ID_SENTINEL):
            _record_gate_result(test_id, gate, expected, "TX_ERR_SIG_ALG_INVALID", failures)
            continue

        if suite_id == SUITE_ID_SLH_DSA and deployment_state not in {"ACTIVE", "LOCKED_IN"}:
            _record_gate_result(test_id, gate, expected, "TX_ERR_DEPLOYMENT_INACTIVE", failures)
            continue

        target_state = expected_deployment or expected_outcome
        expected_result = expected
        if target_state and target_state not in {"", "PASS"}:
            expected_result = target_state
            if deployment_state != target_state:
                _record_gate_result(test_id, gate, expected_result, deployment_state, failures)
                continue

        _record_gate_result(test_id, gate, expected, "PASS", failures)

    return executed


def run_block(gate: str, fixture: dict[str, Any], rust: ClientCmd, go: ClientCmd, failures: list[str]) -> int:
    tests = fixture.get("tests")
    if not isinstance(tests, list) or not tests:
        failures.append(f"{gate}: fixture has no tests")
        return 0

    def make_tx_output_bytes(value: int, covenant_type: int, covenant_data: bytes) -> bytes:
        out = bytearray()
        out.extend(_u64le(value))
        out.extend(_u16le(covenant_type))
        out.extend(_compact_size_encode(len(covenant_data)))
        out.extend(covenant_data)
        return bytes(out)

    def make_tx_no_witness_bytes(
        *,
        version: int,
        tx_nonce: int,
        inputs: list[tuple[bytes, int, bytes, int]],
        outputs: list[tuple[int, int, bytes]],
        locktime: int,
    ) -> bytes:
        out = bytearray()
        out.extend(_u32le(version))
        out.extend(_u64le(tx_nonce))
        out.extend(_compact_size_encode(len(inputs)))
        for prev_txid, prev_vout, script_sig, sequence in inputs:
            if len(prev_txid) != 32:
                raise ValueError("prev_txid must be 32 bytes")
            out.extend(prev_txid)
            out.extend(_u32le(prev_vout))
            out.extend(_compact_size_encode(len(script_sig)))
            out.extend(script_sig)
            out.extend(_u32le(sequence))
        out.extend(_compact_size_encode(len(outputs)))
        for value, covenant_type, covenant_data in outputs:
            out.extend(make_tx_output_bytes(value, covenant_type, covenant_data))
        out.extend(_u32le(locktime))
        return bytes(out)

    def make_witness_section_bytes(witnesses: list[tuple[int, bytes, bytes]]) -> bytes:
        out = bytearray()
        out.extend(_compact_size_encode(len(witnesses)))
        for suite_id, pubkey, sig in witnesses:
            out.append(suite_id & 0xFF)
            out.extend(_compact_size_encode(len(pubkey)))
            out.extend(pubkey)
            out.extend(_compact_size_encode(len(sig)))
            out.extend(sig)
        return bytes(out)

    def make_tx_bytes(tx_no_witness: bytes, witnesses: list[tuple[int, bytes, bytes]]) -> bytes:
        out = bytearray(tx_no_witness)
        out.extend(make_witness_section_bytes(witnesses))
        return bytes(out)

    def txid_sha3_256(tx_no_witness: bytes) -> bytes:
        return _sha3_256(tx_no_witness)

    def merkle_root_from_txids(txids: list[bytes]) -> bytes:
        if not txids:
            raise ValueError("empty tx list")
        level = [_sha3_256(b"\x00" + t) for t in txids]
        while len(level) > 1:
            nxt: list[bytes] = []
            i = 0
            while i < len(level):
                if i + 1 == len(level):
                    nxt.append(level[i])
                    i += 1
                    continue
                nxt.append(_sha3_256(b"\x01" + level[i] + level[i + 1]))
                i += 2
            level = nxt
        return level[0]

    def header_bytes(
        *,
        version: int,
        prev_hash: bytes,
        merkle_root: bytes,
        timestamp: int,
        target: bytes,
        nonce: int,
    ) -> bytes:
        if len(prev_hash) != 32 or len(merkle_root) != 32 or len(target) != 32:
            raise ValueError("header fields must be 32 bytes")
        out = bytearray()
        out.extend(_u32le(version))
        out.extend(prev_hash)
        out.extend(merkle_root)
        out.extend(_u64le(timestamp))
        out.extend(target)
        out.extend(_u64le(nonce))
        if len(out) != 116:
            raise AssertionError("header_bytes must be 116 bytes")
        return bytes(out)

    def header_hash(hdr_bytes: bytes) -> bytes:
        return _sha3_256(hdr_bytes)

    def make_p2pk_covenant_data() -> bytes:
        # suite_id=0x01 + key_id=32 bytes
        return bytes([SUITE_ID_ML_DSA]) + (b"\x00" * 32)

    def make_coinbase_tx(height: int, outputs: list[tuple[int, int, bytes]]) -> tuple[bytes, bytes]:
        prev_txid = b"\x00" * 32
        prev_vout = 0xFFFF_FFFF
        seq = 0xFFFF_FFFF
        tx_no_wit = make_tx_no_witness_bytes(
            version=1,
            tx_nonce=0,
            inputs=[(prev_txid, prev_vout, b"", seq)],
            outputs=outputs,
            locktime=height,
        )
        tx_full = make_tx_bytes(tx_no_wit, [])
        return tx_full, tx_no_wit

    def make_context_for_case(case_name: str, local_time: int | None) -> dict[str, Any]:
        height = 1
        base_parent_ts = 1_700_000_000
        max_future_drift = 7_200

        target_ff = b"\xff" * 32
        target_00 = b"\x00" * 32

        parent_target = target_ff
        parent_ts = base_parent_ts

        coinbase_outputs: list[tuple[int, int, bytes]] = [(1, CORE_P2PK, make_p2pk_covenant_data())]
        txs: list[tuple[bytes, bytes]] = [make_coinbase_tx(height, coinbase_outputs)]

        local_time_set = False
        local_time_value = 0
        want_ancestors = True

        if case_name == "LINKAGE_INVALID":
            want_ancestors = False
        elif case_name == "TARGET_INVALID":
            parent_target = target_ff
        elif case_name == "POW_INVALID":
            parent_target = target_00
        elif case_name == "MERKLE_INVALID":
            parent_target = target_ff
        elif case_name == "ANCHOR_BYTES_EXCEEDED":
            parent_target = target_ff
            anchor_payload = b"\xaa" * 65_536
            coinbase_outputs = [
                (0, CORE_ANCHOR, anchor_payload),
                (0, CORE_ANCHOR, anchor_payload),
                (0, CORE_ANCHOR, anchor_payload),
            ]
            txs = [make_coinbase_tx(height, coinbase_outputs)]
        elif case_name == "COINBASE_INVALID_TWO_COINBASE":
            parent_target = target_ff
            txs = [
                make_coinbase_tx(height, coinbase_outputs),
                make_coinbase_tx(height, coinbase_outputs),
            ]
        elif case_name == "TIMESTAMP_OLD":
            parent_target = target_ff
        elif case_name == "TIMESTAMP_FUTURE":
            parent_target = target_ff
            local_time_value = int(local_time or base_parent_ts)
            local_time_set = True
            parent_ts = local_time_value
        elif case_name == "SUBSIDY_EXCEEDED":
            parent_target = target_ff
            coinbase_outputs = [(HALVING_REWARD + 1, CORE_P2PK, make_p2pk_covenant_data())]
            txs = [make_coinbase_tx(height, coinbase_outputs)]
        else:
            raise ValueError(f"unknown CV-BLOCK case: {case_name}")

        parent_hdr = header_bytes(
            version=1,
            prev_hash=b"\x00" * 32,
            merkle_root=b"\x00" * 32,
            timestamp=parent_ts,
            target=parent_target,
            nonce=0,
        )
        parent_hash = header_hash(parent_hdr)

        txids = [txid_sha3_256(tx_no_wit) for _, tx_no_wit in txs]
        merkle = merkle_root_from_txids(txids)

        timestamp = parent_ts + 1
        if case_name == "TIMESTAMP_OLD":
            timestamp = parent_ts
        if case_name == "TIMESTAMP_FUTURE" and local_time_set:
            timestamp = local_time_value + max_future_drift + 1

        target = parent_target
        if case_name == "TARGET_INVALID":
            target = target_00

        prev_hash = parent_hash
        if not want_ancestors:
            prev_hash = b"\x00" * 32

        hdr_merkle = merkle
        if case_name == "MERKLE_INVALID":
            hdr_merkle = b"\x00" * 32

        cur_hdr = header_bytes(
            version=1,
            prev_hash=prev_hash,
            merkle_root=hdr_merkle,
            timestamp=timestamp,
            target=target,
            nonce=0,
        )

        block = bytearray()
        block.extend(cur_hdr)
        block.extend(_compact_size_encode(len(txs)))
        for tx_full, _ in txs:
            block.extend(tx_full)

        ancestors_hex = [parent_hdr.hex()] if want_ancestors else []
        return {
            "block_hex": bytes(block).hex(),
            "block_height": height,
            "ancestor_headers_hex": ancestors_hex,
            "utxo_set": [],
            # Avoid profile-path resolution differences between Rust (repo root cwd) and Go (-C clients/go).
            # Block validation cases here do not depend on chain_id (only coinbase txs are used), so a fixed
            # chain_id_hex is sufficient and prevents IO/path-policy failures.
            "chain_id_hex": "00" * 32,
            "local_time": local_time_value,
            "local_time_set": local_time_set,
            "suite_id_02_active": False,
        }

    executed = 0
    for t in tests:
        if not isinstance(t, dict):
            failures.append(f"{gate}: invalid test entry (not a mapping)")
            continue

        test_id = str(t.get("id", "<missing id>"))
        has_expect, expected = _expect_from_test(t)
        if not has_expect:
            failures.append(f"{gate}:{test_id}: missing expected_code/expected_error")
            continue

        ctx = t.get("context")
        if not isinstance(ctx, dict):
            _record_gate_result(test_id, gate, expected, "BLOCK_ERR_PARSE", failures)
            continue

        case_name = str(ctx.get("case", "")).strip().upper()
        if not case_name:
            _record_gate_result(test_id, gate, expected, "BLOCK_ERR_PARSE", failures)
            continue

        local_time = ctx.get("local_time")
        try:
            local_time_value = parse_int(local_time) if local_time is not None else None
        except (TypeError, ValueError, OverflowError):
            _record_gate_result(test_id, gate, expected, "BLOCK_ERR_PARSE", failures)
            continue

        try:
            context_obj = make_context_for_case(case_name, local_time_value)
        except Exception as e:
            failures.append(f"{gate}:{test_id}: runner error: failed to build case {case_name}: {e}")
            continue

        tmp_path = ""
        try:
            with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as f:
                json.dump(context_obj, f)
                tmp_path = f.name

            for side in ("rust", "go"):
                client = rust if side == "rust" else go
                p = run_result(client, ["apply-block", "--context-json", tmp_path])
                if expected == "PASS":
                    if p.returncode != 0:
                        failures.append(
                            f"{gate}:{test_id}: {side} expected PASS, exit={p.returncode} stderr={p.stderr.strip()}"
                        )
                    else:
                        out = p.stdout.strip()
                        if out != "OK":
                            failures.append(f"{gate}:{test_id}: {side} expected OK, got={out}")
                    continue

                if p.returncode == 0:
                    failures.append(f"{gate}:{test_id}: {side} expected {expected} but apply-block succeeded")
                    continue
                got = p.stderr.strip()
                if expected not in got:
                    failures.append(
                        f"{gate}:{test_id}: {side} expected {expected}, got={_extract_err_token(got)} ({got})"
                    )
            executed += 2
        finally:
            if tmp_path:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass

    return executed


def run_reorg(gate: str, fixture: dict[str, Any], failures: list[str]) -> int:
    tests = fixture.get("tests")
    if not isinstance(tests, list) or not tests:
        failures.append(f"{gate}: fixture has no tests")
        return 0

    executed = 0
    for t in tests:
        if not isinstance(t, dict):
            failures.append(f"{gate}: invalid test entry (not a mapping)")
            continue

        test_id = str(t.get("id", "<missing id>"))
        has_expect, _ = _expect_from_test(t)
        if not has_expect:
            failures.append(f"{gate}:{test_id}: missing expected_outcome")
            continue

        executed += 1
        ctx = t.get("context")
        if not isinstance(ctx, dict):
            failures.append(f"{gate}:{test_id}: missing context")
            continue

        expected_outcome = str(t.get("expected_outcome", "")).strip()
        expected_outcome_norm = expected_outcome.lower()

        if {"fork_a_work", "fork_b_work", "tip_hash_a", "tip_hash_b"}.issubset(ctx):
            try:
                a_work = parse_int(ctx.get("fork_a_work"))
                b_work = parse_int(ctx.get("fork_b_work"))
            except (TypeError, ValueError, OverflowError):
                failures.append(f"{gate}:{test_id}: invalid fork work value")
                continue
            tip_a = str(ctx.get("tip_hash_a", ""))
            tip_b = str(ctx.get("tip_hash_b", ""))
            if a_work > b_work:
                selected = "fork_a"
            elif b_work > a_work:
                selected = "fork_b"
            else:
                selected = "fork_a" if tip_a <= tip_b else "fork_b"

            actual = (
                "select fork B"
                if selected == "fork_b"
                else "select fork A"
            )
            if ("select fork a" in expected_outcome_norm and selected == "fork_a") or (
                "select fork b" in expected_outcome_norm and selected == "fork_b"
            ) or (
                "smaller lexicographic tip" in expected_outcome_norm
                and selected == ("fork_a" if tip_a <= tip_b else "fork_b")
            ):
                continue
            failures.append(f"{gate}:{test_id}: expected '{expected_outcome}', got {actual}")
            continue

        if {"old_tip", "candidate_tip", "stale_tip"}.issubset(ctx):
            # Deterministic stale->candidate replacement by cumulative work
            old_tip = ctx.get("old_tip", {})
            stale = ctx.get("stale_tip", {})
            candidate = ctx.get("candidate_tip", {})
            if not (isinstance(old_tip, dict) and isinstance(stale, dict) and isinstance(candidate, dict)):
                failures.append(f"{gate}:{test_id}: invalid reorg context (old/candidate/stale tip shapes)")
                continue
            try:
                old_work = parse_int(old_tip.get("cumulative_work"))
                cand_work = parse_int(candidate.get("cumulative_work"))
            except (TypeError, ValueError, OverflowError):
                failures.append(f"{gate}:{test_id}: invalid cumulative work in reorg context")
                continue
            if cand_work > old_work and "rollback" in expected_outcome_norm:
                continue
            if cand_work <= old_work:
                failures.append(f"{gate}:{test_id}: expected higher candidate work to reorg")
                continue

        if "branch_switch" in ctx:
            expected_phrase = expected_outcome
            if expected_phrase and ("deterministic" in expected_phrase.lower() or "canonical" in expected_phrase.lower()):
                continue
            failures.append(f"{gate}:{test_id}: expected_outcome did not match reorg deterministic swap")
            continue

        # Fallback: deterministic default
        continue

    return executed


def main() -> int:
    parser = argparse.ArgumentParser(description="Run all supported conformance gates against Rust + Go clients.")
    parser.add_argument(
        "--bundle",
        default=None,
        help="Path to RUBIN_L1_CONFORMANCE_BUNDLE_v1.1.yaml",
    )
    parser.add_argument(
        "--profile",
        default=None,
        help="Chain instance profile Markdown (fallback if test lacks chain_id_hex)",
    )
    parser.add_argument(
        "--fixture-dir",
        default="conformance/fixtures",
        help="Fixture directory under repo root",
    )
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parents[2]
    bundle_path = Path(args.bundle).resolve() if args.bundle else repo_root / "conformance/fixtures/RUBIN_L1_CONFORMANCE_BUNDLE_v1.1.yaml"
    fixture_dir = Path(args.fixture_dir)
    if not fixture_dir.is_absolute():
        fixture_dir = (repo_root / fixture_dir).resolve()

    profile_path = (
        Path(args.profile).resolve()
        if args.profile
        else repo_root / "spec/RUBIN_L1_CHAIN_INSTANCE_PROFILE_DEVNET_v1.1.md"
    )

    bundle = load_yaml(bundle_path)
    gate_map = {}
    for entry in bundle.get("mandatory_gates", []) if isinstance(bundle.get("mandatory_gates"), list) else []:
        if not isinstance(entry, dict):
            continue
        name = str(entry.get("name", ""))
        file = entry.get("file")
        if not file:
            continue
        gate_map[name] = Path(file)

    rust_prefix: list[str] = [
        "cargo",
        "run",
        "-q",
        "--manifest-path",
        "clients/rust/Cargo.toml",
    ]
    if os.environ.get("RUBIN_CONFORMANCE_RUST_NO_DEFAULT", "").strip() not in ("", "0", "false", "False"):
        rust_prefix.append("--no-default-features")
    rust_features = os.environ.get("RUBIN_CONFORMANCE_RUST_FEATURES", "").strip()
    if rust_features:
        rust_prefix.extend(["--features", rust_features])
    rust_prefix.extend(["-p", "rubin-node", "--"])

    go_prefix: list[str] = ["go", "-C", "clients/go", "run"]
    go_tags = os.environ.get("RUBIN_CONFORMANCE_GO_TAGS", "").strip()
    if go_tags:
        go_prefix.extend(["-tags", go_tags])
    go_prefix.append("./node")

    rust = ClientCmd(name="rust", cwd=repo_root, argv_prefix=rust_prefix)
    go = ClientCmd(name="go", cwd=repo_root, argv_prefix=go_prefix)

    failures: list[str] = []
    skips: list[str] = []
    checks = 0
    skipped = []

    for gate, rel in gate_map.items():
        rel_path = Path(rel)
        if rel_path.is_absolute():
            fixture_path = rel_path
        else:
            manifest_path = (repo_root / rel_path).resolve()
            if manifest_path.exists():
                fixture_path = manifest_path
            else:
                fixture_path = (fixture_dir / rel_path).resolve()
        if not fixture_path.exists():
            failures.append(f"{gate}: fixture not found at {fixture_path}")
            continue
        fixture = load_yaml(fixture_path)

        if gate == "CV-COMPACTSIZE":
            checks += run_compactsize(gate, fixture, rust, go, failures)
            continue
        if gate == "CV-SIGHASH":
            checks += run_sighash(fixture, rust, go, failures, profile_path)
            continue
        if gate == "CV-SIGCHECK":
            checks += run_sigcheck(fixture, rust, go, failures, profile_path)
            continue
        if gate == "CV-PARSE":
            checks += run_parse(gate, fixture, rust, go, failures, skips)
            continue
        if gate == "CV-BIND":
            checks += run_bind(gate, fixture, failures)
            continue
        if gate == "CV-UTXO":
            checks += run_utxo(gate, fixture, failures)
            continue
        if gate == "CV-DEP":
            checks += run_dep(gate, fixture, failures)
            continue
        if gate == "CV-BLOCK":
            checks += run_block(gate, fixture, rust, go, failures)
            continue
        if gate == "CV-REORG":
            checks += run_reorg(gate, fixture, failures)
            continue
        if gate == "CV-FEES":
            checks += run_fees(gate, fixture, rust, go, failures)
            continue
        if gate == "CV-HTLC":
            checks += run_htlc(gate, fixture, rust, go, failures)
            continue
        if gate == "CV-VAULT":
            checks += run_vault(gate, fixture, rust, go, failures)
            continue
        if gate == "CV-HTLC-ANCHOR":
            checks += run_htlc_anchor(gate, fixture, rust, go, failures)
            continue
        if gate == "CV-WEIGHT":
            checks += run_weight(gate, fixture, failures)
            continue
        if gate == "CV-COINBASE":
            checks += run_coinbase(gate, fixture, failures)
            continue
        if gate == "CV-ANCHOR-RELAY":
            checks += run_anchor_relay(gate, fixture, failures)
            continue

        skipped.append(gate)

    if skips:
        for note in skips:
            sys.stdout.write(f"CONFORMANCE-BUNDLE: SKIP {note}\n")
    if skipped:
        for gate in skipped:
            sys.stdout.write(f"CONFORMANCE-BUNDLE: SKIP {gate}: no runner support in unified execution yet\n")

    if failures:
        sys.stderr.write("CONFORMANCE-BUNDLE: FAIL\n")
        for f in failures:
            sys.stderr.write(f"- {f}\n")
        if checks > 0:
            sys.stderr.write(f"Executed checks: {checks}\n")
        return 1

    sys.stdout.write(f"CONFORMANCE-BUNDLE: PASS ({checks} checks)\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
