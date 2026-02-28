#!/usr/bin/env python3

import argparse
from fractions import Fraction
import json
import os
import pathlib
import subprocess
import sys
from typing import Any, Dict, List, Optional, Set, Tuple


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
    op.strip()
    for op in os.getenv("RUBIN_CONFORMANCE_LOCAL_OPS", "").split(",")
    if op.strip()
}


def run(cmd: List[str], cwd: pathlib.Path) -> None:
    p = subprocess.run(cmd, cwd=str(cwd), stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if p.returncode != 0:
        out = p.stdout.decode("utf-8", errors="replace")
        raise RuntimeError(f"command failed: {' '.join(cmd)}\n{out}")


def build_tools() -> Tuple[pathlib.Path, pathlib.Path]:
    BIN_DIR.mkdir(parents=True, exist_ok=True)

    go_cli = BIN_DIR / "go-consensus-cli"
    if sys.platform.startswith("win"):
        go_cli = go_cli.with_suffix(".exe")
    run(
        ["go", "build", "-o", str(go_cli), "./cmd/rubin-consensus-cli"],
        cwd=REPO_ROOT / "clients" / "go",
    )
    if not go_cli.exists():
        raise RuntimeError(f"missing go cli binary: {go_cli}")

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


def as_int(x: Any) -> int:
    if x is None:
        return 0
    try:
        return int(x)
    except (ValueError, TypeError):
        return 0


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


def materialize_tx_hex(
    v: Dict[str, Any],
    vectors_by_id: Optional[Dict[str, Dict[str, Any]]] = None,
    seen_ids: Optional[Set[str]] = None,
) -> str:
    tx_hex = v.get("tx_hex")
    if isinstance(tx_hex, str) and tx_hex.strip() != "":
        return tx_hex.strip()

    tx_hex_from = v.get("tx_hex_from")
    if isinstance(tx_hex_from, str) and tx_hex_from.strip() != "":
        if vectors_by_id is None:
            raise ValueError("tx_hex_from requires vectors_by_id context")
        ref_id = tx_hex_from.strip()
        ref = vectors_by_id.get(ref_id)
        if not isinstance(ref, dict):
            raise ValueError(f"tx_hex_from reference not found: {ref_id}")
        seen = set(seen_ids or set())
        if ref_id in seen:
            raise ValueError(f"tx_hex_from recursion detected at {ref_id}")
        seen.add(ref_id)
        base_hex = materialize_tx_hex(ref, vectors_by_id=vectors_by_id, seen_ids=seen)
        base = bytearray(bytes.fromhex(base_hex))
        muts = v.get("tx_hex_mutations", [])
        if muts is None:
            muts = []
        if not isinstance(muts, list):
            raise ValueError("tx_hex_mutations must be a list")
        for m in muts:
            if not isinstance(m, dict):
                raise ValueError("tx_hex_mutations entries must be objects")
            offset = m.get("offset")
            b = m.get("byte")
            if not isinstance(offset, int):
                raise ValueError("tx_hex_mutations.offset must be int")
            if not isinstance(b, str):
                raise ValueError("tx_hex_mutations.byte must be hex string")
            hb = b.strip().lower()
            if hb.startswith("0x"):
                hb = hb[2:]
            if len(hb) != 2:
                raise ValueError("tx_hex_mutations.byte must encode exactly one byte")
            if offset < 0 or offset >= len(base):
                raise ValueError(
                    f"tx_hex_mutations.offset out of range: {offset} (len={len(base)})"
                )
            base[offset] = int(hb, 16)
        return base.hex()

    parts = v.get("tx_hex_parts")
    if not isinstance(parts, list) or len(parts) == 0:
        raise ValueError("missing tx_hex (or tx_hex_parts or tx_hex_from)")

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

    if op == "compact_eviction_tiebreak":
        entries = v.get("entries", [])
        if not isinstance(entries, list) or len(entries) == 0:
            problems.append(f"{prefix}: entries must be non-empty array")
            return problems

        normalized: List[Tuple[str, Fraction, int]] = []
        for entry in entries:
            if not isinstance(entry, dict):
                problems.append(f"{prefix}: entry must be object")
                return problems
            da_id = str(entry.get("da_id", ""))
            fee = int(entry.get("fee", 0))
            wire_bytes = int(entry.get("wire_bytes", 0))
            received_time = int(entry.get("received_time", 0))
            if da_id == "" or wire_bytes <= 0:
                problems.append(f"{prefix}: invalid da_id/wire_bytes")
                return problems
            normalized.append((da_id, Fraction(fee, wire_bytes), received_time))

        order = [x[0] for x in sorted(normalized, key=lambda x: (x[1], x[2], x[0]))]
        if "expect_evict_order" in v:
            check_expect(
                problems,
                prefix,
                order,
                [str(x) for x in v["expect_evict_order"]],
                "evict_order",
            )
        if "expect_ok" in v:
            check_expect(problems, prefix, True, bool(v["expect_ok"]), "ok")
        return problems

    if op == "compact_a_to_b_retention":
        chunk_count = int(v.get("chunk_count", 0))
        initial_chunks = sorted(set(as_sorted_ints(v.get("initial_chunks", []))))
        commit_arrives = bool(v.get("commit_arrives", True))
        if chunk_count <= 0:
            problems.append(f"{prefix}: chunk_count must be > 0")
            return problems

        retained_chunks = list(initial_chunks)
        missing_chunks = [i for i in range(chunk_count) if i not in set(retained_chunks)]
        state = "A"
        if commit_arrives:
            state = "C" if len(missing_chunks) == 0 else "B"
        prefetch_targets = missing_chunks if state == "B" else []
        discarded_chunks: List[int] = []

        if "expect_state" in v:
            check_expect(problems, prefix, state, str(v["expect_state"]), "state")
        if "expect_retained_chunks" in v:
            check_expect(
                problems,
                prefix,
                retained_chunks,
                sorted(set(as_sorted_ints(v["expect_retained_chunks"]))),
                "retained_chunks",
            )
        if "expect_missing_chunks" in v:
            check_expect(
                problems,
                prefix,
                missing_chunks,
                sorted(set(as_sorted_ints(v["expect_missing_chunks"]))),
                "missing_chunks",
            )
        if "expect_prefetch_targets" in v:
            check_expect(
                problems,
                prefix,
                prefetch_targets,
                sorted(set(as_sorted_ints(v["expect_prefetch_targets"]))),
                "prefetch_targets",
            )
        if "expect_discarded_chunks" in v:
            check_expect(
                problems,
                prefix,
                discarded_chunks,
                sorted(set(as_sorted_ints(v["expect_discarded_chunks"]))),
                "discarded_chunks",
            )
        if "expect_ok" in v:
            check_expect(problems, prefix, True, bool(v["expect_ok"]), "ok")
        return problems

    if op == "compact_duplicate_commit":
        target_da_id = str(v.get("da_id", ""))
        commits = v.get("commits", [])
        if not isinstance(commits, list) or len(commits) == 0:
            problems.append(f"{prefix}: commits must be non-empty array")
            return problems

        first_seen_peer = None
        duplicates_dropped = 0
        penalized_peers: List[str] = []
        for c in commits:
            if not isinstance(c, dict):
                problems.append(f"{prefix}: commit entry must be object")
                return problems
            da_id = str(c.get("da_id", ""))
            peer = str(c.get("peer", ""))
            if da_id == "" or peer == "":
                problems.append(f"{prefix}: invalid duplicate-commit entry")
                return problems
            if target_da_id == "":
                target_da_id = da_id
            if da_id != target_da_id:
                continue
            if first_seen_peer is None:
                first_seen_peer = peer
            else:
                duplicates_dropped += 1
                penalized_peers.append(peer)

        replaced = False
        if "expect_retained_peer" in v:
            check_expect(problems, prefix, first_seen_peer, str(v["expect_retained_peer"]), "retained_peer")
        if "expect_duplicates_dropped" in v:
            check_expect(
                problems,
                prefix,
                duplicates_dropped,
                int(v["expect_duplicates_dropped"]),
                "duplicates_dropped",
            )
        if "expect_penalized_peers" in v:
            check_expect(
                problems,
                prefix,
                sorted(penalized_peers),
                sorted([str(x) for x in v["expect_penalized_peers"]]),
                "penalized_peers",
            )
        if "expect_replaced" in v:
            check_expect(problems, prefix, replaced, bool(v["expect_replaced"]), "replaced")
        if "expect_ok" in v:
            check_expect(problems, prefix, True, bool(v["expect_ok"]), "ok")
        return problems

    if op == "compact_total_fee":
        commit_fee = int(v.get("commit_fee", 0))
        chunk_fees = [int(x) for x in v.get("chunk_fees", [])]
        total_fee = commit_fee + sum(chunk_fees)
        if "expect_total_fee" in v:
            check_expect(problems, prefix, total_fee, int(v["expect_total_fee"]), "total_fee")
        if "expect_ok" in v:
            check_expect(problems, prefix, True, bool(v["expect_ok"]), "ok")
        return problems

    if op == "compact_pinned_accounting":
        current_payload = int(v.get("current_pinned_payload_bytes", 0))
        incoming_payload = int(v.get("incoming_payload_bytes", 0))
        commit_overhead = int(v.get("incoming_commit_overhead_bytes", 0))
        cap = int(v.get("cap_bytes", 96_000_000))

        counted_bytes = current_payload + incoming_payload
        admit = counted_bytes <= cap
        ignored_overhead = commit_overhead

        if "expect_counted_bytes" in v:
            check_expect(problems, prefix, counted_bytes, int(v["expect_counted_bytes"]), "counted_bytes")
        if "expect_admit" in v:
            check_expect(problems, prefix, admit, bool(v["expect_admit"]), "admit")
        if "expect_ignored_overhead_bytes" in v:
            check_expect(
                problems,
                prefix,
                ignored_overhead,
                int(v["expect_ignored_overhead_bytes"]),
                "ignored_overhead_bytes",
            )
        if "expect_ok" in v:
            check_expect(problems, prefix, True, bool(v["expect_ok"]), "ok")
        return problems

    if op == "compact_storm_commit_bearing":
        contains_commit = bool(v.get("contains_commit", False))
        contains_chunk_for_known_commit = bool(v.get("contains_chunk_for_known_commit", False))
        contains_block_with_commit = bool(v.get("contains_block_with_commit", False))
        fill_pct = float(v.get("orphan_pool_fill_pct", 0.0))
        trigger_pct = float(v.get("storm_trigger_pct", 90.0))

        commit_bearing = (
            contains_commit or contains_chunk_for_known_commit or contains_block_with_commit
        )
        storm_mode = fill_pct > trigger_pct
        prioritize = (not storm_mode) or commit_bearing
        admit = True
        if storm_mode and not commit_bearing:
            admit = False

        if "expect_storm_mode" in v:
            check_expect(problems, prefix, storm_mode, bool(v["expect_storm_mode"]), "storm_mode")
        if "expect_commit_bearing" in v:
            check_expect(
                problems,
                prefix,
                commit_bearing,
                bool(v["expect_commit_bearing"]),
                "commit_bearing",
            )
        if "expect_prioritize" in v:
            check_expect(problems, prefix, prioritize, bool(v["expect_prioritize"]), "prioritize")
        if "expect_admit" in v:
            check_expect(problems, prefix, admit, bool(v["expect_admit"]), "admit")
        if "expect_ok" in v:
            check_expect(problems, prefix, True, bool(v["expect_ok"]), "ok")
        return problems

    if op == "vault_policy_rules":
        owner_lock_id = str(v.get("owner_lock_id", "owner"))
        vault_input_count = int(v.get("vault_input_count", 0))
        non_vault_lock_ids = [str(x) for x in v.get("non_vault_lock_ids", [])]
        has_owner_auth = bool(v.get("has_owner_auth", owner_lock_id in non_vault_lock_ids))
        sum_out = int(v.get("sum_out", 0))
        sum_in_vault = int(v.get("sum_in_vault", 0))
        slots = int(v.get("slots", 0))
        key_count = int(v.get("key_count", 0))
        sig_threshold_ok = bool(v.get("sig_threshold_ok", True))

        sentinel_suite_id = int(v.get("sentinel_suite_id", 0))
        sentinel_pubkey_len = int(v.get("sentinel_pubkey_len", 0))
        sentinel_sig_len = int(v.get("sentinel_sig_len", 0))
        sentinel_verify_called = bool(v.get("sentinel_verify_called", False))
        sentinel_ok = (
            sentinel_suite_id == 0
            and sentinel_pubkey_len == 0
            and sentinel_sig_len == 0
            and not sentinel_verify_called
        )

        whitelist = [str(x) for x in v.get("whitelist", [])]
        whitelist_ok = whitelist == sorted(whitelist) and len(set(whitelist)) == len(whitelist)

        checks = {
            "multi_vault": (
                vault_input_count <= 1,
                "TX_ERR_VAULT_MULTI_INPUT_FORBIDDEN",
            ),
            "owner_auth": (
                has_owner_auth,
                "TX_ERR_VAULT_OWNER_AUTH_REQUIRED",
            ),
            "fee_sponsor": (
                all(lock_id == owner_lock_id for lock_id in non_vault_lock_ids),
                "TX_ERR_VAULT_FEE_SPONSOR_FORBIDDEN",
            ),
            "witness_slots": (
                slots == key_count,
                "TX_ERR_PARSE",
            ),
            "sentinel": (
                sentinel_ok,
                "TX_ERR_PARSE",
            ),
            "sig_threshold": (
                sig_threshold_ok,
                "TX_ERR_SIG_INVALID",
            ),
            "whitelist": (
                whitelist_ok,
                "TX_ERR_VAULT_WHITELIST_NOT_CANONICAL",
            ),
            "value": (
                sum_out >= sum_in_vault,
                "TX_ERR_VALUE_CONSERVATION",
            ),
        }

        validation_order = [str(x) for x in v.get("validation_order", [
            "multi_vault",
            "owner_auth",
            "fee_sponsor",
            "witness_slots",
            "sentinel",
            "sig_threshold",
            "whitelist",
            "value",
        ])]

        err = None
        for rule in validation_order:
            if rule not in checks:
                problems.append(f"{prefix}: unknown vault validation rule={rule}")
                return problems
            ok, code = checks[rule]
            if not ok:
                err = code
                break
        ok = err is None

        if "expect_ok" in v:
            check_expect(problems, prefix, ok, bool(v["expect_ok"]), "ok")
        if "expect_err" in v:
            check_expect(problems, prefix, err, str(v["expect_err"]), "err")
        return problems

    if op == "htlc_ordering_policy":
        path = str(v.get("path", "claim")).lower()
        structural_ok = bool(v.get("structural_ok", True))
        locktime_ok = bool(v.get("locktime_ok", True))
        suite_id = int(v.get("suite_id", 1))
        block_height = int(v.get("block_height", 0))
        activation_height = int(v.get("slh_activation_height", 1_000_000))
        lengths_ok = bool(v.get("lengths_ok", True))
        key_binding_ok = bool(v.get("key_binding_ok", True))
        preimage_ok = bool(v.get("preimage_ok", True))
        verify_ok = bool(v.get("verify_ok", True))

        verify_called = False
        err = None
        if not structural_ok:
            err = "TX_ERR_PARSE"
        elif path == "refund" and not locktime_ok:
            err = "TX_ERR_TIMELOCK_NOT_MET"
        elif suite_id not in (1, 2):
            err = "TX_ERR_SIG_ALG_INVALID"
        elif suite_id == 2 and block_height < activation_height:
            err = "TX_ERR_SIG_ALG_INVALID"
        elif not lengths_ok:
            err = "TX_ERR_SIG_NONCANONICAL"
        elif not key_binding_ok:
            err = "TX_ERR_SIG_INVALID"
        elif path == "claim" and not preimage_ok:
            err = "TX_ERR_SIG_INVALID"
        else:
            verify_called = True
            if not verify_ok:
                err = "TX_ERR_SIG_INVALID"

        ok = err is None
        if "expect_ok" in v:
            check_expect(problems, prefix, ok, bool(v["expect_ok"]), "ok")
        if "expect_err" in v:
            check_expect(problems, prefix, err, str(v["expect_err"]), "err")
        if "expect_verify_called" in v:
            check_expect(
                problems,
                prefix,
                verify_called,
                bool(v["expect_verify_called"]),
                "verify_called",
            )
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
    vectors_by_id: Dict[str, Dict[str, Any]],
) -> List[str]:
    op = v.get("op")
    if not op:
        return [f"{gate}/{v.get('id','?')}: missing op"]

    if op in LOCAL_OPS:
        return validate_local_vector(gate, v)

    try:
        tx_hex = materialize_tx_hex(v, vectors_by_id=vectors_by_id)
    except Exception:
        tx_hex = ""

    req: Dict[str, Any] = {"op": op}

    def include_block_context(*, require_height: bool) -> None:
        if require_height:
            req["height"] = int(v["height"])
        elif "height" in v:
            req["height"] = int(v["height"])
        if isinstance(v.get("prev_timestamps"), list):
            req["prev_timestamps"] = [int(x) for x in v["prev_timestamps"]]
        if "expected_prev_hash" in v:
            req["expected_prev_hash"] = v["expected_prev_hash"]
        if "expected_target" in v:
            req["expected_target"] = v["expected_target"]

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
    elif op == "tx_weight_and_stats":
        if tx_hex == "":
            return [f"{gate}/{v.get('id','?')}: missing tx_hex"]
        req["tx_hex"] = tx_hex
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
        include_block_context(require_height=False)
    elif op == "block_basic_check_with_fees":
        req["block_hex"] = v["block_hex"]
        include_block_context(require_height=True)
        req["already_generated"] = int(v.get("already_generated", 0))
        req["sum_fees"] = int(v.get("sum_fees", 0))
    elif op == "connect_block_basic":
        req["block_hex"] = v["block_hex"]
        include_block_context(require_height=True)
        req["already_generated"] = int(v.get("already_generated", 0))
        req["utxos"] = v.get("utxos", [])
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
        if "block_mtp" in v:
            req["block_mtp"] = int(v["block_mtp"])
    elif op == "fork_work":
        req["target"] = v["target"]
    elif op == "fork_choice_select":
        req["chains"] = v["chains"]
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
    elif op == "witness_merkle_root":
        req["wtxids"] = v["wtxids"]
    elif op.startswith("compact_") and op != "compact_shortid":
        for key, value in v.items():
            if key in ("id", "op") or key.startswith("expect_"):
                continue
            req[key] = value
    elif op == "nonce_replay_intrablock":
        req["nonces"] = [int(x) for x in v.get("nonces", [])]
    elif op == "timestamp_bounds":
        req["mtp"] = int(v.get("mtp", 0))
        req["timestamp"] = int(v.get("timestamp", 0))
        req["max_future_drift"] = int(v.get("max_future_drift", 7_200))
    elif op == "determinism_order":
        req["keys"] = v.get("keys", [])
    elif op == "validation_order":
        req["checks"] = v.get("checks", [])
    elif op == "htlc_ordering_policy":
        req["path"] = str(v.get("path", "claim"))
        req["structural_ok"] = bool(v.get("structural_ok", True))
        req["locktime_ok"] = bool(v.get("locktime_ok", True))
        req["suite_id"] = int(v.get("suite_id", 1))
        req["height"] = int(v.get("block_height", 0))
        req["slh_activation_height"] = int(v.get("slh_activation_height", 1_000_000))
        req["key_binding_ok"] = bool(v.get("key_binding_ok", True))
        req["preimage_ok"] = bool(v.get("preimage_ok", True))
        req["verify_ok"] = bool(v.get("verify_ok", True))
    elif op == "vault_policy_rules":
        req["owner_lock_id"] = str(v.get("owner_lock_id", "owner"))
        req["vault_input_count"] = int(v.get("vault_input_count", 0))
        req["non_vault_lock_ids"] = [str(x) for x in v.get("non_vault_lock_ids", [])]
        if "has_owner_auth" in v:
            req["has_owner_auth"] = bool(v["has_owner_auth"])
        req["sum_out"] = int(v.get("sum_out", 0))
        req["sum_in_vault"] = int(v.get("sum_in_vault", 0))
        req["slots"] = int(v.get("slots", 0))
        req["key_count"] = int(v.get("key_count", 0))
        req["sig_threshold_ok"] = bool(v.get("sig_threshold_ok", True))
        req["sentinel_suite_id"] = int(v.get("sentinel_suite_id", 0))
        req["sentinel_pubkey_len"] = int(v.get("sentinel_pubkey_len", 0))
        req["sentinel_sig_len"] = int(v.get("sentinel_sig_len", 0))
        req["sentinel_verify_called"] = bool(v.get("sentinel_verify_called", False))
        req["whitelist"] = [str(x) for x in v.get("whitelist", [])]
        if "validation_order" in v and isinstance(v["validation_order"], list):
            req["validation_order"] = [str(x) for x in v["validation_order"]]
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
    elif op == "witness_merkle_root":
        if go_resp.get("witness_merkle_root") != rust_resp.get("witness_merkle_root"):
            problems.append(
                f"{gate}/{vid}: witness_merkle_root mismatch go={go_resp.get('witness_merkle_root')} rust={rust_resp.get('witness_merkle_root')}"
            )
        if "expect_witness_merkle_root" in v and go_resp.get("witness_merkle_root") != v["expect_witness_merkle_root"]:
            problems.append(f"{gate}/{vid}: expect_witness_merkle_root mismatch")
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
    elif op == "block_basic_check_with_fees":
        if go_resp.get("block_hash") != rust_resp.get("block_hash"):
            problems.append(
                f"{gate}/{vid}: block_hash mismatch go={go_resp.get('block_hash')} rust={rust_resp.get('block_hash')}"
            )
        if "expect_block_hash" in v and go_resp.get("block_hash") != v["expect_block_hash"]:
            problems.append(f"{gate}/{vid}: expect_block_hash mismatch")
    elif op == "connect_block_basic":
        for k in ["sum_fees", "utxo_count", "already_generated", "already_generated_n1"]:
            gv = as_int(go_resp.get(k))
            rv = as_int(rust_resp.get(k))
            if gv != rv:
                problems.append(f"{gate}/{vid}: {k} mismatch go={gv} rust={rv}")

        if "expect_sum_fees" in v and as_int(go_resp.get("sum_fees")) != int(v["expect_sum_fees"]):
            problems.append(f"{gate}/{vid}: expect_sum_fees mismatch")
        if "expect_utxo_count" in v and as_int(go_resp.get("utxo_count")) != int(v["expect_utxo_count"]):
            problems.append(f"{gate}/{vid}: expect_utxo_count mismatch")
        if "expect_already_generated" in v and as_int(go_resp.get("already_generated")) != int(v["expect_already_generated"]):
            problems.append(f"{gate}/{vid}: expect_already_generated mismatch")
        if "expect_already_generated_n1" in v and as_int(go_resp.get("already_generated_n1")) != int(v["expect_already_generated_n1"]):
            problems.append(f"{gate}/{vid}: expect_already_generated_n1 mismatch")
    elif op == "covenant_genesis_check":
        # ok/err parity is already checked above.
        pass
    elif op == "utxo_apply_basic":
        for k in ["fee", "utxo_count"]:
            gv = as_int(go_resp.get(k))
            rv = as_int(rust_resp.get(k))
            if gv != rv:
                problems.append(
                    f"{gate}/{vid}: {k} mismatch go={gv} rust={rv}"
                )
        if "expect_fee" in v and as_int(go_resp.get("fee")) != int(v["expect_fee"]):
            problems.append(f"{gate}/{vid}: expect_fee mismatch")
        if "expect_utxo_count" in v and as_int(go_resp.get("utxo_count")) != int(v["expect_utxo_count"]):
            problems.append(f"{gate}/{vid}: expect_utxo_count mismatch")
    elif op == "fork_work":
        if go_resp.get("work") != rust_resp.get("work"):
            problems.append(f"{gate}/{vid}: work mismatch go={go_resp.get('work')} rust={rust_resp.get('work')}")
        if "expect_work" in v and go_resp.get("work") != v["expect_work"]:
            problems.append(f"{gate}/{vid}: expect_work mismatch")
    elif op == "fork_choice_select":
        if go_resp.get("winner") != rust_resp.get("winner"):
            problems.append(
                f"{gate}/{vid}: winner mismatch go={go_resp.get('winner')} rust={rust_resp.get('winner')}"
            )
        if "expect_winner" in v and go_resp.get("winner") != v["expect_winner"]:
            problems.append(f"{gate}/{vid}: expect_winner mismatch")
        if go_resp.get("chainwork") != rust_resp.get("chainwork"):
            problems.append(
                f"{gate}/{vid}: chainwork mismatch go={go_resp.get('chainwork')} rust={rust_resp.get('chainwork')}"
            )
        if "expect_chainwork" in v and go_resp.get("chainwork") != v["expect_chainwork"]:
            problems.append(f"{gate}/{vid}: expect_chainwork mismatch")
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
    elif op == "tx_weight_and_stats":
        for k in ["weight", "da_bytes", "anchor_bytes"]:
            if go_resp.get(k) != rust_resp.get(k):
                problems.append(
                    f"{gate}/{vid}: {k} mismatch go={go_resp.get(k)} rust={rust_resp.get(k)}"
                )
        if "expect_weight" in v and go_resp.get("weight") != v["expect_weight"]:
            problems.append(f"{gate}/{vid}: expect_weight mismatch")
        if "expect_da_bytes" in v and go_resp.get("da_bytes") != v["expect_da_bytes"]:
            problems.append(f"{gate}/{vid}: expect_da_bytes mismatch")
        if "expect_anchor_bytes" in v and go_resp.get("anchor_bytes") != v["expect_anchor_bytes"]:
            problems.append(f"{gate}/{vid}: expect_anchor_bytes mismatch")
    elif op.startswith("compact_") and op != "compact_shortid":
        def normalize_compact_response(resp: Dict[str, Any]) -> Dict[str, Any]:
            normalized = dict(resp or {})
            bool_fields = {
                "request_getblocktxn",
                "request_full_block",
                "penalize_peer",
                "roundtrip_ok",
                "batch_ok",
                "fallback",
                "reconstructed",
                "evicted",
                "pinned",
                "admit",
                "storm_mode",
                "rollback",
                "peer_exceeded",
                "global_exceeded",
                "quality_penalty",
                "disconnect",
                "replaced",
                "commit_bearing",
                "prioritize",
            }
            int_fields = {
                "wire_bytes",
                "ttl",
                "ttl_reset_count",
                "mode",
                "score",
                "duplicates_dropped",
                "total_fee",
                "counted_bytes",
                "ignored_overhead_bytes",
            }
            float_fields = {"fill_pct", "rate"}
            list_fields = {
                "invalid_indices",
                "missing_indices",
                "checkblock_results",
                "missing_fields",
                "evict_order",
                "retained_chunks",
                "prefetch_targets",
                "discarded_chunks",
                "penalized_peers",
            }
            str_fields = {"state", "retained_peer"}

            for key in bool_fields:
                normalized.setdefault(key, False)
            for key in int_fields:
                normalized.setdefault(key, 0)
            for key in float_fields:
                normalized.setdefault(key, 0.0)
            for key in list_fields:
                normalized.setdefault(key, [])
            for key in str_fields:
                normalized.setdefault(key, "")
            return normalized

        go_resp = normalize_compact_response(go_resp)
        rust_resp = normalize_compact_response(rust_resp)

        field_map = {
            "compact_collision_fallback": ["request_getblocktxn", "request_full_block", "penalize_peer"],
            "compact_witness_roundtrip": ["roundtrip_ok", "wire_bytes"],
            "compact_batch_verify": ["batch_ok", "fallback", "invalid_indices"],
            "compact_prefill_roundtrip": ["missing_indices", "reconstructed", "request_full_block"],
            "compact_state_machine": [
                "state",
                "evicted",
                "pinned",
                "ttl",
                "ttl_reset_count",
                "checkblock_results",
            ],
            "compact_orphan_limits": ["admit"],
            "compact_orphan_storm": ["fill_pct", "storm_mode", "admit", "rollback"],
            "compact_sendcmpct_modes": ["invalid_indices", "mode"],
            "compact_peer_quality": ["score", "mode"],
            "compact_prefetch_caps": ["peer_exceeded", "global_exceeded", "quality_penalty", "disconnect"],
            "compact_telemetry_rate": ["rate"],
            "compact_telemetry_fields": ["missing_fields"],
            "compact_grace_period": ["storm_mode", "score", "disconnect"],
            "compact_eviction_tiebreak": ["evict_order"],
            "compact_a_to_b_retention": [
                "state",
                "retained_chunks",
                "missing_indices",
                "prefetch_targets",
                "discarded_chunks",
            ],
            "compact_duplicate_commit": [
                "retained_peer",
                "duplicates_dropped",
                "penalized_peers",
                "replaced",
            ],
            "compact_total_fee": ["total_fee"],
            "compact_pinned_accounting": ["counted_bytes", "admit", "ignored_overhead_bytes"],
            "compact_storm_commit_bearing": ["storm_mode", "commit_bearing", "prioritize", "admit"],
        }
        for key in field_map.get(op, []):
            if go_resp.get(key) != rust_resp.get(key):
                problems.append(
                    f"{gate}/{vid}: {key} mismatch go={go_resp.get(key)} rust={rust_resp.get(key)}"
                )

        if "expect_request_getblocktxn" in v and go_resp.get("request_getblocktxn") != bool(v["expect_request_getblocktxn"]):
            problems.append(f"{gate}/{vid}: expect_request_getblocktxn mismatch")
        if "expect_request_full_block" in v and go_resp.get("request_full_block") != bool(v["expect_request_full_block"]):
            problems.append(f"{gate}/{vid}: expect_request_full_block mismatch")
        if "expect_penalize_peer" in v and go_resp.get("penalize_peer") != bool(v["expect_penalize_peer"]):
            problems.append(f"{gate}/{vid}: expect_penalize_peer mismatch")
        if "expect_roundtrip_ok" in v and go_resp.get("roundtrip_ok") != bool(v["expect_roundtrip_ok"]):
            problems.append(f"{gate}/{vid}: expect_roundtrip_ok mismatch")
        if "expect_wire_bytes" in v and int(go_resp.get("wire_bytes", -1)) != int(v["expect_wire_bytes"]):
            problems.append(f"{gate}/{vid}: expect_wire_bytes mismatch")
        if "expect_batch_ok" in v and go_resp.get("batch_ok") != bool(v["expect_batch_ok"]):
            problems.append(f"{gate}/{vid}: expect_batch_ok mismatch")
        if "expect_fallback" in v and go_resp.get("fallback") != bool(v["expect_fallback"]):
            problems.append(f"{gate}/{vid}: expect_fallback mismatch")
        if "expect_invalid_indices" in v:
            if sorted([int(x) for x in (go_resp.get("invalid_indices") or [])]) != sorted([int(x) for x in v["expect_invalid_indices"]]):
                problems.append(f"{gate}/{vid}: expect_invalid_indices mismatch")
        if "expect_missing_indices" in v:
            if sorted([int(x) for x in (go_resp.get("missing_indices") or [])]) != sorted([int(x) for x in v["expect_missing_indices"]]):
                problems.append(f"{gate}/{vid}: expect_missing_indices mismatch")
        if "expect_reconstructed" in v and go_resp.get("reconstructed") != bool(v["expect_reconstructed"]):
            problems.append(f"{gate}/{vid}: expect_reconstructed mismatch")
        if "expect_final_state" in v and go_resp.get("state") != v["expect_final_state"]:
            problems.append(f"{gate}/{vid}: expect_final_state mismatch")
        if "expect_state" in v and go_resp.get("state") != v["expect_state"]:
            problems.append(f"{gate}/{vid}: expect_state mismatch")
        if "expect_evicted" in v and go_resp.get("evicted") != bool(v["expect_evicted"]):
            problems.append(f"{gate}/{vid}: expect_evicted mismatch")
        if "expect_pinned" in v and go_resp.get("pinned") != bool(v["expect_pinned"]):
            problems.append(f"{gate}/{vid}: expect_pinned mismatch")
        if "expect_ttl" in v and int(go_resp.get("ttl", -1)) != int(v["expect_ttl"]):
            problems.append(f"{gate}/{vid}: expect_ttl mismatch")
        if "expect_ttl_reset_count" in v and int(go_resp.get("ttl_reset_count", -1)) != int(v["expect_ttl_reset_count"]):
            problems.append(f"{gate}/{vid}: expect_ttl_reset_count mismatch")
        if "expect_checkblock_results" in v and list(go_resp.get("checkblock_results") or []) != [bool(x) for x in v["expect_checkblock_results"]]:
            problems.append(f"{gate}/{vid}: expect_checkblock_results mismatch")
        if "expect_admit" in v and go_resp.get("admit") != bool(v["expect_admit"]):
            problems.append(f"{gate}/{vid}: expect_admit mismatch")
        if "expect_fill_pct" in v:
            if abs(float(go_resp.get("fill_pct", 0.0)) - float(v["expect_fill_pct"])) > 1e-9:
                problems.append(f"{gate}/{vid}: expect_fill_pct mismatch")
        if "expect_storm_mode" in v and go_resp.get("storm_mode") != bool(v["expect_storm_mode"]):
            problems.append(f"{gate}/{vid}: expect_storm_mode mismatch")
        if "expect_rollback" in v and go_resp.get("rollback") != bool(v["expect_rollback"]):
            problems.append(f"{gate}/{vid}: expect_rollback mismatch")
        if "expect_modes" in v and list(go_resp.get("invalid_indices") or []) != [int(x) for x in v["expect_modes"]]:
            problems.append(f"{gate}/{vid}: expect_modes mismatch")
        if "expect_mode" in v and int(go_resp.get("mode", -1)) != int(v["expect_mode"]):
            problems.append(f"{gate}/{vid}: expect_mode mismatch")
        if "expect_score" in v and int(go_resp.get("score", -1)) != int(v["expect_score"]):
            problems.append(f"{gate}/{vid}: expect_score mismatch")
        if "expect_peer_exceeded" in v and go_resp.get("peer_exceeded") != bool(v["expect_peer_exceeded"]):
            problems.append(f"{gate}/{vid}: expect_peer_exceeded mismatch")
        if "expect_global_exceeded" in v and go_resp.get("global_exceeded") != bool(v["expect_global_exceeded"]):
            problems.append(f"{gate}/{vid}: expect_global_exceeded mismatch")
        if "expect_quality_penalty" in v and go_resp.get("quality_penalty") != bool(v["expect_quality_penalty"]):
            problems.append(f"{gate}/{vid}: expect_quality_penalty mismatch")
        if "expect_disconnect" in v and go_resp.get("disconnect") != bool(v["expect_disconnect"]):
            problems.append(f"{gate}/{vid}: expect_disconnect mismatch")
        if "expect_rate" in v:
            if abs(float(go_resp.get("rate", 0.0)) - float(v["expect_rate"])) > 1e-9:
                problems.append(f"{gate}/{vid}: expect_rate mismatch")
        if "expect_missing_fields" in v:
            if sorted([str(x) for x in (go_resp.get("missing_fields") or [])]) != sorted([str(x) for x in v["expect_missing_fields"]]):
                problems.append(f"{gate}/{vid}: expect_missing_fields mismatch")
        if "expect_grace_active" in v and go_resp.get("storm_mode") != bool(v["expect_grace_active"]):
            problems.append(f"{gate}/{vid}: expect_grace_active mismatch")
        if "expect_evict_order" in v and list(go_resp.get("evict_order") or []) != [str(x) for x in v["expect_evict_order"]]:
            problems.append(f"{gate}/{vid}: expect_evict_order mismatch")
        if "expect_retained_chunks" in v:
            if sorted([int(x) for x in (go_resp.get("retained_chunks") or [])]) != sorted([int(x) for x in v["expect_retained_chunks"]]):
                problems.append(f"{gate}/{vid}: expect_retained_chunks mismatch")
        if "expect_prefetch_targets" in v:
            if sorted([int(x) for x in (go_resp.get("prefetch_targets") or [])]) != sorted([int(x) for x in v["expect_prefetch_targets"]]):
                problems.append(f"{gate}/{vid}: expect_prefetch_targets mismatch")
        if "expect_discarded_chunks" in v:
            if sorted([int(x) for x in (go_resp.get("discarded_chunks") or [])]) != sorted([int(x) for x in v["expect_discarded_chunks"]]):
                problems.append(f"{gate}/{vid}: expect_discarded_chunks mismatch")
        if "expect_retained_peer" in v and go_resp.get("retained_peer") != str(v["expect_retained_peer"]):
            problems.append(f"{gate}/{vid}: expect_retained_peer mismatch")
        if "expect_duplicates_dropped" in v and int(go_resp.get("duplicates_dropped", -1)) != int(v["expect_duplicates_dropped"]):
            problems.append(f"{gate}/{vid}: expect_duplicates_dropped mismatch")
        if "expect_penalized_peers" in v:
            if sorted([str(x) for x in (go_resp.get("penalized_peers") or [])]) != sorted([str(x) for x in v["expect_penalized_peers"]]):
                problems.append(f"{gate}/{vid}: expect_penalized_peers mismatch")
        if "expect_replaced" in v and go_resp.get("replaced") != bool(v["expect_replaced"]):
            problems.append(f"{gate}/{vid}: expect_replaced mismatch")
        if "expect_total_fee" in v and int(go_resp.get("total_fee", -1)) != int(v["expect_total_fee"]):
            problems.append(f"{gate}/{vid}: expect_total_fee mismatch")
        if "expect_counted_bytes" in v and int(go_resp.get("counted_bytes", -1)) != int(v["expect_counted_bytes"]):
            problems.append(f"{gate}/{vid}: expect_counted_bytes mismatch")
        if "expect_ignored_overhead_bytes" in v and int(go_resp.get("ignored_overhead_bytes", -1)) != int(v["expect_ignored_overhead_bytes"]):
            problems.append(f"{gate}/{vid}: expect_ignored_overhead_bytes mismatch")
        if "expect_commit_bearing" in v and go_resp.get("commit_bearing") != bool(v["expect_commit_bearing"]):
            problems.append(f"{gate}/{vid}: expect_commit_bearing mismatch")
        if "expect_prioritize" in v and go_resp.get("prioritize") != bool(v["expect_prioritize"]):
            problems.append(f"{gate}/{vid}: expect_prioritize mismatch")
    elif op == "nonce_replay_intrablock":
        go_dup = sorted([int(x) for x in (go_resp.get("duplicates") or [])])
        rust_dup = sorted([int(x) for x in (rust_resp.get("duplicates") or [])])
        if go_dup != rust_dup:
            problems.append(f"{gate}/{vid}: duplicates mismatch go={go_dup} rust={rust_dup}")
        if "expect_duplicates" in v:
            exp_dup = sorted([int(x) for x in v["expect_duplicates"]])
            if go_dup != exp_dup:
                problems.append(f"{gate}/{vid}: expect_duplicates mismatch")
    elif op == "timestamp_bounds":
        # ok/err parity is already checked above.
        pass
    elif op == "determinism_order":
        go_sorted = go_resp.get("sorted_keys") or []
        rust_sorted = rust_resp.get("sorted_keys") or []
        if go_sorted != rust_sorted:
            problems.append(
                f"{gate}/{vid}: sorted_keys mismatch go={go_sorted} rust={rust_sorted}"
            )
        if "expect_sorted_keys" in v and go_sorted != v["expect_sorted_keys"]:
            problems.append(f"{gate}/{vid}: expect_sorted_keys mismatch")
    elif op == "validation_order":
        go_first = go_resp.get("first_err")
        rust_first = rust_resp.get("first_err")
        if go_first != rust_first:
            problems.append(
                f"{gate}/{vid}: first_err mismatch go={go_first} rust={rust_first}"
            )
        go_eval = go_resp.get("evaluated") or []
        rust_eval = rust_resp.get("evaluated") or []
        if go_eval != rust_eval:
            problems.append(
                f"{gate}/{vid}: evaluated mismatch go={go_eval} rust={rust_eval}"
            )
        if "expect_first_err" in v and go_first != v["expect_first_err"]:
            problems.append(f"{gate}/{vid}: expect_first_err mismatch")
        if "expect_evaluated" in v and go_eval != v["expect_evaluated"]:
            problems.append(f"{gate}/{vid}: expect_evaluated mismatch")
    elif op == "htlc_ordering_policy":
        go_called = bool(go_resp.get("verify_called", False))
        rust_called = bool(rust_resp.get("verify_called", False))
        if go_called != rust_called:
            problems.append(
                f"{gate}/{vid}: verify_called mismatch go={go_called} rust={rust_called}"
            )
        if "expect_verify_called" in v and go_called != bool(v["expect_verify_called"]):
            problems.append(f"{gate}/{vid}: expect_verify_called mismatch")
    elif op == "vault_policy_rules":
        # ok/err parity is already checked above.
        pass

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
            vectors_by_id = {str(x.get("id", "")): x for x in vectors if isinstance(x, dict)}
            problems.extend(validate_vector(gate, v, go_cli, rust_cli, vectors_by_id))

    if problems:
        for p in problems:
            print("FAIL", p)
        print(f"FAILED: {len(problems)} problems across {total} vectors")
        return 1

    print(f"PASS: {total} vectors")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
