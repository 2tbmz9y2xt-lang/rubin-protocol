#!/usr/bin/env python3

import argparse
import json
import os
import pathlib
import subprocess
import sys
from typing import Any, Dict, List, Tuple


REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
FIXTURES_DIR = REPO_ROOT / "conformance" / "fixtures"
BIN_DIR = REPO_ROOT / "conformance" / "bin"


COMPACT_DEFAULTS: Dict[str, int] = {
    "DA_ORPHAN_TTL_BLOCKS": 3,
    "DA_ORPHAN_POOL_PER_PEER_MAX": 4 * 1024 * 1024,
    "DA_ORPHAN_POOL_PER_DA_ID_MAX": 8 * 1024 * 1024,
    "DA_ORPHAN_POOL_SIZE": 64 * 1024 * 1024,
    "MAX_DA_BYTES_PER_BLOCK": 32_000_000,
    "CHUNK_BYTES": 524_288,
    "PREFETCH_BYTES_PER_SEC": 4_000_000,
    "PREFETCH_GLOBAL_BPS": 32_000_000,
}


LOCAL_OPS = {
    "compact_collision_fallback",
    "compact_witness_roundtrip",
    "compact_batch_verify",
    "compact_prefill_roundtrip",
    "compact_state_machine",
    "compact_orphan_limits",
    "compact_orphan_storm",
    "compact_chunk_count_cap",
    "compact_sendcmpct_modes",
    "compact_peer_quality",
    "compact_prefetch_caps",
    "compact_telemetry_rate",
    "compact_telemetry_fields",
    "compact_grace_period",
    "nonce_replay_intrablock",
    "timestamp_bounds",
    "fork_work",
    "fork_choice_select",
    "determinism_order",
    "validation_order",
}


def run(cmd: List[str], cwd: pathlib.Path) -> None:
    p = subprocess.run(cmd, cwd=str(cwd), stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if p.returncode != 0:
        out = p.stdout.decode("utf-8", errors="replace")
        raise RuntimeError(f"command failed: {' '.join(cmd)}\n{out}")


def build_tools() -> Tuple[pathlib.Path, pathlib.Path]:
    BIN_DIR.mkdir(parents=True, exist_ok=True)

    go_cli = BIN_DIR / "go-consensus-cli"
    run(
        ["go", "build", "-o", str(go_cli), "./cmd/rubin-consensus-cli"],
        cwd=REPO_ROOT / "clients" / "go",
    )

    run(
        ["cargo", "build", "-p", "rubin-consensus-cli"],
        cwd=REPO_ROOT / "clients" / "rust",
    )
    rust_cli = REPO_ROOT / "clients" / "rust" / "target" / "debug" / "rubin-consensus-cli"
    if sys.platform.startswith("win"):
        rust_cli = rust_cli.with_suffix(".exe")

    if not rust_cli.exists():
        raise RuntimeError(f"missing rust cli binary: {rust_cli}")

    return go_cli, rust_cli


def call_tool(tool_path: pathlib.Path, req: Dict[str, Any]) -> Dict[str, Any]:
    p = subprocess.run(
        [str(tool_path)],
        input=(json.dumps(req) + "\n").encode("utf-8"),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=dict(os.environ),
    )
    if p.returncode != 0:
        stderr = p.stderr.decode("utf-8", errors="replace")
        raise RuntimeError(f"tool failed: {tool_path} rc={p.returncode} stderr={stderr}")
    out = p.stdout.decode("utf-8", errors="replace")
    try:
        return json.loads(out)
    except json.JSONDecodeError as e:
        raise RuntimeError(f"tool returned non-json: {tool_path}\n{out}\n{e}")


def load_fixtures() -> List[Dict[str, Any]]:
    fixtures = []
    for p in sorted(FIXTURES_DIR.glob("CV-*.json")):
        fixtures.append(json.loads(p.read_text(encoding="utf-8")))
    return fixtures


def as_sorted_ints(values: Any) -> List[int]:
    if not isinstance(values, list):
        return []
    out: List[int] = []
    for v in values:
        out.append(int(v))
    return sorted(out)


def check_expect(problems: List[str], prefix: str, got: Any, expected: Any, field: str) -> None:
    if expected != got:
        problems.append(f"{prefix}: {field} expected={expected} got={got}")


def parse_hex_uint(value: Any) -> int:
    if isinstance(value, int):
        return value
    if not isinstance(value, str):
        raise ValueError("expected integer or hex string")
    text = value.strip().lower()
    if text.startswith("0x"):
        text = text[2:]
    if text == "":
        return 0
    return int(text, 16)


def parse_hex_bytes(value: Any) -> bytes:
    if not isinstance(value, str):
        raise ValueError("expected hex string")
    text = value.strip().lower()
    if text.startswith("0x"):
        text = text[2:]
    if len(text) % 2 == 1:
        text = "0" + text
    return bytes.fromhex(text)


def materialize_tx_hex(v: Dict[str, Any]) -> str:
    tx_hex = v.get("tx_hex")
    if isinstance(tx_hex, str) and tx_hex.strip() != "":
        return tx_hex.strip()

    parts = v.get("tx_hex_parts")
    if not isinstance(parts, list) or len(parts) == 0:
        raise ValueError("missing tx_hex (or tx_hex_parts)")

    out: List[str] = []
    for p in parts:
        if isinstance(p, str):
            out.append(p.strip())
            continue
        if isinstance(p, dict):
            repeat_byte = p.get("repeat_byte")
            count = p.get("count")
            if not isinstance(repeat_byte, str) or not isinstance(count, int):
                raise ValueError("tx_hex_parts dict must have repeat_byte (string) and count (int)")
            b = repeat_byte.strip().lower()
            if b.startswith("0x"):
                b = b[2:]
            if len(b) != 2:
                raise ValueError("repeat_byte must be exactly 1 byte hex (2 chars)")
            int(b, 16)  # validate
            if count < 0:
                raise ValueError("repeat_byte count must be non-negative")
            out.append(b * count)
            continue
        raise ValueError("tx_hex_parts entries must be strings or dict repeat blocks")

    return "".join(out)


def validate_local_vector(gate: str, v: Dict[str, Any]) -> List[str]:
    op = v.get("op")
    vid = v.get("id", "?")
    prefix = f"{gate}/{vid}"
    problems: List[str] = []

    if op == "compact_collision_fallback":
        missing = as_sorted_ints(v.get("missing_indices", []))
        getblocktxn_ok = bool(v.get("getblocktxn_ok", True))
        request_getblocktxn = len(missing) > 0
        request_full_block = request_getblocktxn and not getblocktxn_ok
        penalize_peer = False

        if "expect_request_getblocktxn" in v:
            check_expect(
                problems,
                prefix,
                request_getblocktxn,
                bool(v["expect_request_getblocktxn"]),
                "request_getblocktxn",
            )
        if "expect_request_full_block" in v:
            check_expect(
                problems,
                prefix,
                request_full_block,
                bool(v["expect_request_full_block"]),
                "request_full_block",
            )
        if "expect_penalize_peer" in v:
            check_expect(
                problems,
                prefix,
                penalize_peer,
                bool(v["expect_penalize_peer"]),
                "penalize_peer",
            )
        return problems

    if op == "compact_witness_roundtrip":
        suite_id = int(v.get("suite_id", 0x01))
        pub_len = int(v.get("pubkey_length", 0))
        sig_len = int(v.get("sig_length", 0))

        def enc_compact_size(n: int) -> bytes:
            if n < 0xFD:
                return bytes([n])
            if n <= 0xFFFF:
                return bytes([0xFD, n & 0xFF, (n >> 8) & 0xFF])
            if n <= 0xFFFFFFFF:
                return bytes(
                    [
                        0xFE,
                        n & 0xFF,
                        (n >> 8) & 0xFF,
                        (n >> 16) & 0xFF,
                        (n >> 24) & 0xFF,
                    ]
                )
            out = [0xFF]
            for i in range(8):
                out.append((n >> (8 * i)) & 0xFF)
            return bytes(out)

        wire = bytearray()
        wire.append(suite_id & 0xFF)
        wire.extend(enc_compact_size(pub_len))
        wire.extend(bytes([0x11]) * pub_len)
        wire.extend(enc_compact_size(sig_len))
        wire.extend(bytes([0x22]) * sig_len)

        # Decode immediately and compare structural equality (round-trip).
        off = 0

        def dec_compact_size(buf: bytes, o: int) -> Tuple[int, int]:
            pfx = buf[o]
            if pfx < 0xFD:
                return pfx, o + 1
            if pfx == 0xFD:
                return (buf[o + 1] | (buf[o + 2] << 8)), o + 3
            if pfx == 0xFE:
                return (
                    buf[o + 1]
                    | (buf[o + 2] << 8)
                    | (buf[o + 3] << 16)
                    | (buf[o + 4] << 24),
                    o + 5,
                )
            n = 0
            for i in range(8):
                n |= buf[o + 1 + i] << (8 * i)
            return n, o + 9

        suite2 = wire[off]
        off += 1
        pub2, off = dec_compact_size(wire, off)
        pub_bytes = wire[off : off + pub2]
        off += pub2
        sig2, off = dec_compact_size(wire, off)
        sig_bytes = wire[off : off + sig2]
        off += sig2
        roundtrip_ok = (
            suite2 == suite_id
            and pub2 == pub_len
            and sig2 == sig_len
            and len(pub_bytes) == pub_len
            and len(sig_bytes) == sig_len
            and off == len(wire)
        )

        if "expect_roundtrip_ok" in v:
            check_expect(
                problems,
                prefix,
                roundtrip_ok,
                bool(v["expect_roundtrip_ok"]),
                "roundtrip_ok",
            )
        if "expect_wire_bytes" in v:
            check_expect(problems, prefix, len(wire), int(v["expect_wire_bytes"]), "wire_bytes")
        return problems

    if op == "compact_batch_verify":
        batch_size = int(v.get("batch_size", 64))
        invalid = as_sorted_ints(v.get("invalid_indices", []))
        for idx in invalid:
            if idx < 0 or idx >= batch_size:
                problems.append(f"{prefix}: invalid index out of range ({idx}) for batch_size={batch_size}")
                return problems

        batch_ok = len(invalid) == 0
        fallback_used = not batch_ok

        if "expect_batch_ok" in v:
            check_expect(problems, prefix, batch_ok, bool(v["expect_batch_ok"]), "batch_ok")
        if "expect_fallback" in v:
            check_expect(problems, prefix, fallback_used, bool(v["expect_fallback"]), "fallback")
        if "expect_invalid_indices" in v:
            check_expect(
                problems,
                prefix,
                invalid,
                as_sorted_ints(v["expect_invalid_indices"]),
                "invalid_indices",
            )
        return problems

    if op == "compact_prefill_roundtrip":
        tx_count = int(v["tx_count"])
        prefilled = set(as_sorted_ints(v.get("prefilled_indices", [])))
        mempool = set(as_sorted_ints(v.get("mempool_indices", [])))
        blocktxn = as_sorted_ints(v.get("blocktxn_indices", []))

        all_indices = set(range(tx_count))
        shortid_indices = sorted(all_indices - prefilled)
        missing = sorted([i for i in shortid_indices if i not in mempool])
        request_getblocktxn = len(missing) > 0

        reconstructed = False
        if not request_getblocktxn:
            reconstructed = True
        elif blocktxn == missing:
            reconstructed = True

        request_full_block = request_getblocktxn and not reconstructed

        if "expect_missing_indices" in v:
            check_expect(
                problems,
                prefix,
                missing,
                as_sorted_ints(v["expect_missing_indices"]),
                "missing_indices",
            )
        if "expect_reconstructed" in v:
            check_expect(problems, prefix, reconstructed, bool(v["expect_reconstructed"]), "reconstructed")
        if "expect_request_full_block" in v:
            check_expect(
                problems,
                prefix,
                request_full_block,
                bool(v["expect_request_full_block"]),
                "request_full_block",
            )
        return problems

    if op == "compact_state_machine":
        chunk_count = int(v["chunk_count"])
        ttl_cfg = int(v.get("ttl_blocks", COMPACT_DEFAULTS["DA_ORPHAN_TTL_BLOCKS"]))
        chunks = set(as_sorted_ints(v.get("initial_chunks", [])))
        commit_seen = bool(v.get("initial_commit_seen", False))
        state = "C" if (commit_seen and len(chunks) == chunk_count) else ("B" if commit_seen else "A")
        pinned = state == "C"
        ttl = ttl_cfg if state in ("A", "B") else 0
        ttl_reset_count = 0
        evicted = False
        checkblock_results: List[bool] = []

        for e in v.get("events", []):
            et = e.get("type")
            if et == "chunk":
                idx = int(e.get("index", -1))
                if 0 <= idx < chunk_count and state != "EVICTED":
                    chunks.add(idx)
                if commit_seen and len(chunks) == chunk_count:
                    state = "C"
                    pinned = True
            elif et == "commit":
                if state != "EVICTED":
                    if state == "A":
                        ttl = ttl_cfg
                        ttl_reset_count += 1
                    commit_seen = True
                    if len(chunks) == chunk_count:
                        state = "C"
                        pinned = True
                    else:
                        state = "B"
                        pinned = False
            elif et == "tick":
                if state in ("A", "B"):
                    ttl -= int(e.get("blocks", 1))
                    if ttl <= 0:
                        state = "EVICTED"
                        evicted = True
                        commit_seen = False
                        chunks.clear()
                        pinned = False
                        ttl = 0
            elif et == "checkblock":
                checkblock_results.append(commit_seen and len(chunks) == chunk_count)
            else:
                problems.append(f"{prefix}: unknown state-machine event type={et}")
                return problems

        if "expect_final_state" in v:
            check_expect(problems, prefix, state, v["expect_final_state"], "final_state")
        if "expect_evicted" in v:
            check_expect(problems, prefix, evicted, bool(v["expect_evicted"]), "evicted")
        if "expect_pinned" in v:
            check_expect(problems, prefix, pinned, bool(v["expect_pinned"]), "pinned")
        if "expect_ttl" in v:
            check_expect(problems, prefix, ttl, int(v["expect_ttl"]), "ttl")
        if "expect_ttl_reset_count" in v:
            check_expect(problems, prefix, ttl_reset_count, int(v["expect_ttl_reset_count"]), "ttl_reset_count")
        if "expect_checkblock_results" in v:
            expected = [bool(x) for x in v["expect_checkblock_results"]]
            check_expect(problems, prefix, checkblock_results, expected, "checkblock_results")
        return problems

    if op == "compact_orphan_limits":
        per_peer_limit = int(v.get("per_peer_limit", COMPACT_DEFAULTS["DA_ORPHAN_POOL_PER_PEER_MAX"]))
        per_da_id_limit = int(v.get("per_da_id_limit", COMPACT_DEFAULTS["DA_ORPHAN_POOL_PER_DA_ID_MAX"]))
        global_limit = int(v.get("global_limit", COMPACT_DEFAULTS["DA_ORPHAN_POOL_SIZE"]))
        current_peer = int(v.get("current_peer_bytes", 0))
        current_da_id = int(v.get("current_da_id_bytes", 0))
        current_global = int(v.get("current_global_bytes", 0))
        incoming = int(v.get("incoming_chunk_bytes", 0))

        admit = (
            current_peer + incoming <= per_peer_limit
            and current_da_id + incoming <= per_da_id_limit
            and current_global + incoming <= global_limit
        )
        if "expect_admit" in v:
            check_expect(problems, prefix, admit, bool(v["expect_admit"]), "admit")
        return problems

    if op == "compact_orphan_storm":
        global_limit = int(v.get("global_limit", COMPACT_DEFAULTS["DA_ORPHAN_POOL_SIZE"]))
        current_global = int(v.get("current_global_bytes", 0))
        incoming_chunk = int(v.get("incoming_chunk_bytes", 0))
        incoming_has_commit = bool(v.get("incoming_has_commit", False))
        storm_trigger_pct = float(v.get("storm_trigger_pct", 90.0))
        recovery_success_rate = float(v.get("recovery_success_rate", 100.0))
        observation_minutes = int(v.get("observation_minutes", 0))

        fill_pct = 0.0 if global_limit <= 0 else (100.0 * current_global / global_limit)
        storm_mode = fill_pct > storm_trigger_pct
        rollback = recovery_success_rate < 95.0 and observation_minutes >= 10

        admit = current_global + incoming_chunk <= global_limit
        if storm_mode and not incoming_has_commit:
            admit = False

        if "expect_fill_pct" in v:
            expected = float(v["expect_fill_pct"])
            if abs(fill_pct - expected) > 1e-9:
                problems.append(f"{prefix}: fill_pct expected={expected} got={fill_pct}")
        if "expect_storm_mode" in v:
            check_expect(problems, prefix, storm_mode, bool(v["expect_storm_mode"]), "storm_mode")
        if "expect_admit" in v:
            check_expect(problems, prefix, admit, bool(v["expect_admit"]), "admit")
        if "expect_rollback" in v:
            check_expect(problems, prefix, rollback, bool(v["expect_rollback"]), "rollback")
        return problems

    if op == "compact_chunk_count_cap":
        max_count = int(
            v.get(
                "max_da_chunk_count",
                COMPACT_DEFAULTS["MAX_DA_BYTES_PER_BLOCK"] // COMPACT_DEFAULTS["CHUNK_BYTES"],
            )
        )
        chunk_count = int(v.get("chunk_count", 0))
        ok = 0 <= chunk_count <= max_count
        expected_ok = bool(v.get("expect_ok", True))
        check_expect(problems, prefix, ok, expected_ok, "ok")
        if not ok and "expect_err" in v:
            check_expect(problems, prefix, "TX_ERR_PARSE", v["expect_err"], "err")
        return problems

    if op == "compact_sendcmpct_modes":
        def compute_mode(payload: Dict[str, Any]) -> int:
            in_ibd = bool(payload.get("in_ibd", False))
            warmup_done = bool(payload.get("warmup_done", False))
            miss_rate_pct = float(payload.get("miss_rate_pct", 0.0))
            miss_blocks = int(payload.get("miss_rate_blocks", 0))

            if in_ibd:
                return 0
            if miss_rate_pct > 10.0 and miss_blocks >= 5:
                return 0
            if warmup_done and miss_rate_pct <= 0.5:
                return 2
            if warmup_done:
                return 1
            return 0

        if isinstance(v.get("phases"), list):
            phases = v["phases"]
            modes = [compute_mode(p if isinstance(p, dict) else {}) for p in phases]
            if "expect_modes" in v:
                check_expect(
                    problems,
                    prefix,
                    modes,
                    [int(x) for x in v["expect_modes"]],
                    "modes",
                )
        else:
            mode = compute_mode(v)
            if "expect_mode" in v:
                check_expect(problems, prefix, mode, int(v["expect_mode"]), "mode")
        return problems

    if op == "compact_peer_quality":
        score = int(v.get("start_score", 50))
        grace = bool(v.get("grace_period_active", False))
        events = v.get("events", [])
        deltas = {
            "reconstruct_no_getblocktxn": 2,
            "getblocktxn_first_try": 1,
            "prefetch_completed": 1,
            "incomplete_set": -5,
            "getblocktxn_required": -3,
            "full_block_required": -10,
            "prefetch_cap_exceeded": -2,
        }

        for ev in events:
            if ev not in deltas:
                problems.append(f"{prefix}: unknown peer-quality event={ev}")
                return problems
            delta = deltas[ev]
            if grace and delta < 0:
                delta = int(delta / 2)  # penalty halved, rounded toward zero
            score = max(0, min(100, score + delta))

        elapsed_blocks = int(v.get("elapsed_blocks", 0))
        for _ in range(elapsed_blocks // 144):
            if score > 50:
                score -= 1
            elif score < 50:
                score += 1

        if score >= 75:
            mode = 2
        elif score >= 40:
            mode = 1
        else:
            mode = 0

        if "expect_score" in v:
            check_expect(problems, prefix, score, int(v["expect_score"]), "score")
        if "expect_mode" in v:
            check_expect(problems, prefix, mode, int(v["expect_mode"]), "mode")
        return problems

    if op == "compact_prefetch_caps":
        per_peer_bps = int(v.get("per_peer_bps", COMPACT_DEFAULTS["PREFETCH_BYTES_PER_SEC"]))
        global_bps = int(v.get("global_bps", COMPACT_DEFAULTS["PREFETCH_GLOBAL_BPS"]))
        streams = [int(x) for x in v.get("peer_streams_bps", [])]
        if not streams:
            per_peer = int(v.get("peer_stream_bps", 0))
            active = int(v.get("active_sets", 1))
            streams = [per_peer for _ in range(active)]

        peer_exceeded = any(s > per_peer_bps for s in streams)
        global_exceeded = sum(streams) > global_bps
        quality_penalty = peer_exceeded or global_exceeded
        disconnect = False

        if "expect_peer_exceeded" in v:
            check_expect(problems, prefix, peer_exceeded, bool(v["expect_peer_exceeded"]), "peer_exceeded")
        if "expect_global_exceeded" in v:
            check_expect(
                problems,
                prefix,
                global_exceeded,
                bool(v["expect_global_exceeded"]),
                "global_exceeded",
            )
        if "expect_quality_penalty" in v:
            check_expect(
                problems,
                prefix,
                quality_penalty,
                bool(v["expect_quality_penalty"]),
                "quality_penalty",
            )
        if "expect_disconnect" in v:
            check_expect(problems, prefix, disconnect, bool(v["expect_disconnect"]), "disconnect")
        return problems

    if op == "compact_telemetry_rate":
        completed = int(v.get("completed_sets", 0))
        total = int(v.get("total_sets", 0))
        if total < 0 or completed < 0 or completed > total:
            problems.append(f"{prefix}: invalid completed/total values")
            return problems
        rate = 1.0 if total == 0 else (completed / total)
        if "expect_rate" in v:
            expected = float(v["expect_rate"])
            if abs(rate - expected) > 1e-9:
                problems.append(f"{prefix}: rate expected={expected} got={rate}")
        return problems

    if op == "compact_telemetry_fields":
        telemetry = v.get("telemetry", {})
        if not isinstance(telemetry, dict):
            problems.append(f"{prefix}: telemetry must be object")
            return problems
        required = [
            "shortid_collision_count",
            "shortid_collision_blocks",
            "shortid_collision_peers",
            "da_mempool_fill_pct",
            "orphan_pool_fill_pct",
            "miss_rate_bytes_L1",
            "miss_rate_bytes_DA",
            "partial_set_count",
            "partial_set_age_p95",
            "recovery_success_rate",
            "prefetch_latency_ms",
            "peer_quality_score",
        ]
        missing = sorted([k for k in required if k not in telemetry])
        if "expect_missing_fields" in v:
            check_expect(
                problems,
                prefix,
                missing,
                sorted([str(x) for x in v["expect_missing_fields"]]),
                "missing_fields",
            )
        if "expect_ok" in v:
            check_expect(problems, prefix, len(missing) == 0, bool(v["expect_ok"]), "ok")
        return problems

    if op == "compact_grace_period":
        grace_period_blocks = int(v.get("grace_period_blocks", 1440))
        elapsed_blocks = int(v.get("elapsed_blocks", 0))
        grace_active = elapsed_blocks < grace_period_blocks
        score = int(v.get("start_score", 50))
        events = [str(e) for e in v.get("events", [])]
        deltas = {
            "reconstruct_no_getblocktxn": 2,
            "getblocktxn_first_try": 1,
            "prefetch_completed": 1,
            "incomplete_set": -5,
            "getblocktxn_required": -3,
            "full_block_required": -10,
            "prefetch_cap_exceeded": -2,
        }
        for ev in events:
            if ev not in deltas:
                problems.append(f"{prefix}: unknown grace event={ev}")
                return problems
            delta = deltas[ev]
            if grace_active and delta < 0:
                delta = int(delta / 2)
            score = max(0, min(100, score + delta))
        disconnect = (score < 5) and (not grace_active)
        if "expect_grace_active" in v:
            check_expect(problems, prefix, grace_active, bool(v["expect_grace_active"]), "grace_active")
        if "expect_score" in v:
            check_expect(problems, prefix, score, int(v["expect_score"]), "score")
        if "expect_disconnect" in v:
            check_expect(problems, prefix, disconnect, bool(v["expect_disconnect"]), "disconnect")
        if "expect_ok" in v:
            check_expect(problems, prefix, True, bool(v["expect_ok"]), "ok")
        return problems

    if op == "nonce_replay_intrablock":
        nonces = [int(x) for x in v.get("nonces", [])]
        seen = set()
        duplicates: List[int] = []
        for nonce in nonces:
            if nonce in seen:
                duplicates.append(nonce)
            else:
                seen.add(nonce)
        replay = len(duplicates) > 0
        ok = not replay
        err = "TX_ERR_NONCE_REPLAY" if replay else None
        if "expect_duplicates" in v:
            check_expect(
                problems,
                prefix,
                sorted(duplicates),
                sorted([int(x) for x in v["expect_duplicates"]]),
                "duplicates",
            )
        if "expect_ok" in v:
            check_expect(problems, prefix, ok, bool(v["expect_ok"]), "ok")
        if "expect_err" in v:
            check_expect(problems, prefix, err, v["expect_err"], "err")
        return problems

    if op == "timestamp_bounds":
        timestamp = int(v.get("timestamp", 0))
        mtp = int(v.get("mtp", 0))
        max_future_drift = int(v.get("max_future_drift", 7_200))
        ok = True
        err = None
        if timestamp <= mtp:
            ok = False
            err = "BLOCK_ERR_TIMESTAMP_OLD"
        elif timestamp > mtp + max_future_drift:
            ok = False
            err = "BLOCK_ERR_TIMESTAMP_FUTURE"
        if "expect_ok" in v:
            check_expect(problems, prefix, ok, bool(v["expect_ok"]), "ok")
        if "expect_err" in v:
            check_expect(problems, prefix, err, v["expect_err"], "err")
        return problems

    if op == "fork_work":
        target = parse_hex_uint(v.get("target"))
        if target <= 0:
            problems.append(f"{prefix}: target must be > 0")
            return problems
        work = (1 << 256) // target
        work_hex = hex(work)
        if "expect_work" in v:
            expected_work = hex(parse_hex_uint(v["expect_work"]))
            check_expect(problems, prefix, work_hex, expected_work, "work")
        if "expect_ok" in v:
            check_expect(problems, prefix, True, bool(v["expect_ok"]), "ok")
        return problems

    if op == "fork_choice_select":
        chains = v.get("chains", [])
        if not isinstance(chains, list) or len(chains) == 0:
            problems.append(f"{prefix}: chains must be non-empty array")
            return problems

        best_id = None
        best_work = -1
        best_tip = None
        for chain in chains:
            if not isinstance(chain, dict):
                problems.append(f"{prefix}: chain entry must be object")
                return problems
            cid = str(chain.get("id"))
            tip_hash = parse_hex_bytes(chain.get("tip_hash", ""))
            targets = chain.get("targets", [])
            if not isinstance(targets, list) or len(targets) == 0:
                problems.append(f"{prefix}: chain {cid} targets must be non-empty array")
                return problems
            total_work = 0
            for t in targets:
                target = parse_hex_uint(t)
                if target <= 0:
                    problems.append(f"{prefix}: chain {cid} has non-positive target")
                    return problems
                total_work += (1 << 256) // target

            if (total_work > best_work) or (
                total_work == best_work and (best_tip is None or tip_hash < best_tip)
            ):
                best_work = total_work
                best_tip = tip_hash
                best_id = cid

        if "expect_winner" in v:
            check_expect(problems, prefix, best_id, str(v["expect_winner"]), "winner")
        if "expect_chainwork" in v:
            expected_work = parse_hex_uint(v["expect_chainwork"])
            check_expect(problems, prefix, best_work, expected_work, "chainwork")
        if "expect_ok" in v:
            check_expect(problems, prefix, True, bool(v["expect_ok"]), "ok")
        return problems

    if op == "determinism_order":
        keys = v.get("keys", [])
        if not isinstance(keys, list):
            problems.append(f"{prefix}: keys must be array")
            return problems

        def key_bytes(item: Any) -> bytes:
            if isinstance(item, str):
                stripped = item.strip().lower()
                if stripped.startswith("0x"):
                    return parse_hex_bytes(stripped)
                return item.encode("utf-8")
            return str(item).encode("utf-8")

        sorted_keys = sorted(keys, key=lambda x: key_bytes(x))
        if "expect_sorted_keys" in v:
            check_expect(problems, prefix, sorted_keys, v["expect_sorted_keys"], "sorted_keys")
        if "expect_ok" in v:
            check_expect(problems, prefix, True, bool(v["expect_ok"]), "ok")
        return problems

    if op == "validation_order":
        checks = v.get("checks", [])
        if not isinstance(checks, list) or len(checks) == 0:
            problems.append(f"{prefix}: checks must be non-empty array")
            return problems
        first_err = None
        evaluated: List[str] = []
        for check in checks:
            if not isinstance(check, dict):
                problems.append(f"{prefix}: check entry must be object")
                return problems
            name = str(check.get("name", ""))
            evaluated.append(name)
            if bool(check.get("fails", False)):
                first_err = check.get("err")
                break
        if "expect_first_err" in v:
            check_expect(problems, prefix, first_err, v["expect_first_err"], "first_err")
        if "expect_evaluated" in v:
            check_expect(problems, prefix, evaluated, v["expect_evaluated"], "evaluated")
        if "expect_ok" in v:
            expected_ok = bool(v["expect_ok"])
            check_expect(problems, prefix, first_err is None, expected_ok, "ok")
        return problems

    problems.append(f"{prefix}: unknown local op {op}")
    return problems


def validate_vector(
    gate: str,
    v: Dict[str, Any],
    go_cli: pathlib.Path,
    rust_cli: pathlib.Path,
) -> List[str]:
    op = v.get("op")
    if not op:
        return [f"{gate}/{v.get('id','?')}: missing op"]

    if op in LOCAL_OPS:
        return validate_local_vector(gate, v)

    try:
        tx_hex = materialize_tx_hex(v)
    except Exception:
        tx_hex = ""

    req: Dict[str, Any] = {"op": op}
    if op == "parse_tx":
        if tx_hex == "":
            return [f"{gate}/{v.get('id','?')}: missing tx_hex"]
        req["tx_hex"] = tx_hex
    elif op == "merkle_root":
        req["txids"] = v["txids"]
    elif op == "sighash_v1":
        if tx_hex == "":
            return [f"{gate}/{v.get('id','?')}: missing tx_hex"]
        req["tx_hex"] = tx_hex
        req["chain_id"] = v["chain_id"]
        req["input_index"] = v["input_index"]
        req["input_value"] = v["input_value"]
    elif op == "block_hash":
        req["header_hex"] = v["header_hex"]
    elif op == "pow_check":
        req["header_hex"] = v["header_hex"]
        req["target_hex"] = v["target_hex"]
    elif op == "retarget_v1":
        req["target_old"] = v["target_old"]
        req["timestamp_first"] = v["timestamp_first"]
        req["timestamp_last"] = v["timestamp_last"]
        if isinstance(v.get("window_timestamps"), list):
            req["window_timestamps"] = [int(x) for x in v["window_timestamps"]]
        elif isinstance(v.get("window_pattern"), dict):
            p = v["window_pattern"]
            mode = str(p.get("mode", ""))
            if mode == "step_with_last_jump":
                window_size = int(p.get("window_size", 10_080))
                start = int(p.get("start", 0))
                step = int(p.get("step", 120))
                last_jump = int(p.get("last_jump", 0))
                if window_size < 2:
                    return [f"{gate}/{v.get('id','?')}: window_pattern.window_size must be >= 2"]
                if step < 0 or last_jump < 0:
                    return [f"{gate}/{v.get('id','?')}: window_pattern step/jump must be non-negative"]
                ts = [start]
                for _ in range(1, window_size):
                    ts.append(ts[-1] + step)
                if last_jump > 0:
                    ts[-1] = ts[-2] + last_jump
                req["window_timestamps"] = ts
            else:
                return [f"{gate}/{v.get('id','?')}: unknown window_pattern.mode={mode}"]
    elif op == "block_basic_check":
        req["block_hex"] = v["block_hex"]
        if "height" in v:
            req["height"] = int(v["height"])
        if isinstance(v.get("prev_timestamps"), list):
            req["prev_timestamps"] = [int(x) for x in v["prev_timestamps"]]
        if "expected_prev_hash" in v:
            req["expected_prev_hash"] = v["expected_prev_hash"]
        if "expected_target" in v:
            req["expected_target"] = v["expected_target"]
    elif op == "block_basic_check_with_fees":
        req["block_hex"] = v["block_hex"]
        req["height"] = int(v["height"])
        if isinstance(v.get("prev_timestamps"), list):
            req["prev_timestamps"] = [int(x) for x in v["prev_timestamps"]]
        if "expected_prev_hash" in v:
            req["expected_prev_hash"] = v["expected_prev_hash"]
        if "expected_target" in v:
            req["expected_target"] = v["expected_target"]
        req["already_generated"] = int(v.get("already_generated", 0))
        req["sum_fees"] = int(v.get("sum_fees", 0))
    elif op == "covenant_genesis_check":
        if tx_hex == "":
            return [f"{gate}/{v.get('id','?')}: missing tx_hex"]
        req["tx_hex"] = tx_hex
    elif op == "utxo_apply_basic":
        if tx_hex == "":
            return [f"{gate}/{v.get('id','?')}: missing tx_hex"]
        req["tx_hex"] = tx_hex
        req["utxos"] = v["utxos"]
        req["height"] = v["height"]
        req["block_timestamp"] = v["block_timestamp"]
    elif op == "compact_shortid":
        req["wtxid"] = v["wtxid"]
        req["nonce1"] = v["nonce1"]
        req["nonce2"] = v["nonce2"]
    elif op == "output_descriptor_bytes":
        cov_type = v["input"]["covenant_type"]
        if isinstance(cov_type, str):
            cov_type = int(cov_type, 0)
        req["covenant_type"] = cov_type
        req["covenant_data_hex"] = v["input"]["covenant_data_hex"]
    elif op == "output_descriptor_hash":
        cov_type = v["input"]["covenant_type"]
        if isinstance(cov_type, str):
            cov_type = int(cov_type, 0)
        req["covenant_type"] = cov_type
        req["covenant_data_hex"] = v["input"]["covenant_data_hex"]
    else:
        return [f"{gate}/{v.get('id','?')}: unknown op {op}"]

    go_resp = call_tool(go_cli, req)
    rust_resp = call_tool(rust_cli, req)

    problems: List[str] = []
    vid = v.get("id", "?")

    if bool(go_resp.get("ok")) != bool(rust_resp.get("ok")):
        problems.append(f"{gate}/{vid}: go ok={go_resp.get('ok')} rust ok={rust_resp.get('ok')}")
        return problems

    expected_ok = bool(v.get("expect_ok", True))
    if expected_ok != bool(go_resp.get("ok")):
        problems.append(f"{gate}/{vid}: expect_ok={expected_ok} got_ok={go_resp.get('ok')}")
        return problems

    if not go_resp.get("ok"):
        ge = go_resp.get("err")
        re = rust_resp.get("err")
        if ge != re:
            problems.append(f"{gate}/{vid}: err mismatch go={ge} rust={re}")
        if "expect_err" in v and ge != v["expect_err"]:
            problems.append(f"{gate}/{vid}: expect_err={v['expect_err']} got_err={ge}")
        return problems

    # ok=true
    if op == "parse_tx":
        for k in ["txid", "wtxid"]:
            if go_resp.get(k) != rust_resp.get(k):
                problems.append(
                    f"{gate}/{vid}: {k} mismatch go={go_resp.get(k)} rust={rust_resp.get(k)}"
                )
        if go_resp.get("consumed") != rust_resp.get("consumed"):
            problems.append(
                f"{gate}/{vid}: consumed mismatch go={go_resp.get('consumed')} rust={rust_resp.get('consumed')}"
            )
        if "expect_txid" in v and go_resp.get("txid") != v["expect_txid"]:
            problems.append(f"{gate}/{vid}: expect_txid mismatch")
        if "expect_wtxid" in v and go_resp.get("wtxid") != v["expect_wtxid"]:
            problems.append(f"{gate}/{vid}: expect_wtxid mismatch")
        if "expect_consumed" in v and go_resp.get("consumed") != v["expect_consumed"]:
            problems.append(f"{gate}/{vid}: expect_consumed mismatch")
    elif op == "merkle_root":
        if go_resp.get("merkle_root") != rust_resp.get("merkle_root"):
            problems.append(
                f"{gate}/{vid}: merkle_root mismatch go={go_resp.get('merkle_root')} rust={rust_resp.get('merkle_root')}"
            )
        if "expect_merkle_root" in v and go_resp.get("merkle_root") != v["expect_merkle_root"]:
            problems.append(f"{gate}/{vid}: expect_merkle_root mismatch")
        if "expect_not_merkle_root" in v and go_resp.get("merkle_root") == v["expect_not_merkle_root"]:
            problems.append(f"{gate}/{vid}: expect_not_merkle_root violated")
    elif op == "sighash_v1":
        if go_resp.get("digest") != rust_resp.get("digest"):
            problems.append(
                f"{gate}/{vid}: digest mismatch go={go_resp.get('digest')} rust={rust_resp.get('digest')}"
            )
        if "expect_digest" in v and go_resp.get("digest") != v["expect_digest"]:
            problems.append(f"{gate}/{vid}: expect_digest mismatch")
    elif op == "block_hash":
        if go_resp.get("block_hash") != rust_resp.get("block_hash"):
            problems.append(
                f"{gate}/{vid}: block_hash mismatch go={go_resp.get('block_hash')} rust={rust_resp.get('block_hash')}"
            )
        if "expect_block_hash" in v and go_resp.get("block_hash") != v["expect_block_hash"]:
            problems.append(f"{gate}/{vid}: expect_block_hash mismatch")
    elif op == "retarget_v1":
        if go_resp.get("target_new") != rust_resp.get("target_new"):
            problems.append(
                f"{gate}/{vid}: target_new mismatch go={go_resp.get('target_new')} rust={rust_resp.get('target_new')}"
            )
        if "expect_target_new" in v and go_resp.get("target_new") != v["expect_target_new"]:
            problems.append(f"{gate}/{vid}: expect_target_new mismatch")
    elif op == "pow_check":
        # ok/err parity is already checked above.
        pass
    elif op == "block_basic_check":
        if go_resp.get("block_hash") != rust_resp.get("block_hash"):
            problems.append(
                f"{gate}/{vid}: block_hash mismatch go={go_resp.get('block_hash')} rust={rust_resp.get('block_hash')}"
            )
        if "expect_block_hash" in v and go_resp.get("block_hash") != v["expect_block_hash"]:
            problems.append(f"{gate}/{vid}: expect_block_hash mismatch")
    elif op == "covenant_genesis_check":
        # ok/err parity is already checked above.
        pass
    elif op == "utxo_apply_basic":
        for k in ["fee", "utxo_count"]:
            if go_resp.get(k) != rust_resp.get(k):
                problems.append(
                    f"{gate}/{vid}: {k} mismatch go={go_resp.get(k)} rust={rust_resp.get(k)}"
                )
        if "expect_fee" in v and go_resp.get("fee") != v["expect_fee"]:
            problems.append(f"{gate}/{vid}: expect_fee mismatch")
        if "expect_utxo_count" in v and go_resp.get("utxo_count") != v["expect_utxo_count"]:
            problems.append(f"{gate}/{vid}: expect_utxo_count mismatch")
    elif op == "compact_shortid":
        go_sid = go_resp.get("short_id") or go_resp.get("digest")
        rust_sid = rust_resp.get("short_id") or rust_resp.get("digest")
        if go_sid != rust_sid:
            problems.append(
                f"{gate}/{vid}: short_id mismatch go={go_sid} rust={rust_sid}"
            )
        if "expect_short_id" in v and go_sid != v["expect_short_id"]:
            problems.append(f"{gate}/{vid}: expect_short_id mismatch")
    elif op == "output_descriptor_bytes":
        go_desc = go_resp.get("descriptor_hex") or go_resp.get("digest")
        rust_desc = rust_resp.get("descriptor_hex") or rust_resp.get("digest")
        if go_desc != rust_desc:
            problems.append(
                f"{gate}/{vid}: descriptor_hex mismatch go={go_desc} rust={rust_desc}"
            )
        if "expected_hex" in v and go_desc != v["expected_hex"]:
            problems.append(f"{gate}/{vid}: expected_hex mismatch")
    elif op == "output_descriptor_hash":
        go_hash = go_resp.get("digest")
        rust_hash = rust_resp.get("digest")
        if go_hash != rust_hash:
            problems.append(
                f"{gate}/{vid}: digest mismatch go={go_hash} rust={rust_hash}"
            )
        if "expected_hash" in v and go_hash != v["expected_hash"]:
            problems.append(f"{gate}/{vid}: expected_hash mismatch")

    return problems


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--only-gates", nargs="*", default=None)
    ap.add_argument("--list-gates", action="store_true")
    args = ap.parse_args()

    fixtures = load_fixtures()
    gates = [f["gate"] for f in fixtures]
    if args.list_gates:
        for g in gates:
            print(g)
        return 0

    only = set(args.only_gates or [])
    if only:
        fixtures = [f for f in fixtures if f["gate"] in only]

    go_cli, rust_cli = build_tools()

    total = 0
    problems: List[str] = []
    for f in fixtures:
        gate = f["gate"]
        vectors = f.get("vectors", [])
        for v in vectors:
            total += 1
            problems.extend(validate_vector(gate, v, go_cli, rust_cli))

    if problems:
        for p in problems:
            print("FAIL", p)
        print(f"FAILED: {len(problems)} problems across {total} vectors")
        return 1

    print(f"PASS: {total} vectors")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
