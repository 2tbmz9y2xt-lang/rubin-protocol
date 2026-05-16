#!/usr/bin/env python3
# ruff: noqa: E302,E305,E401,E701
from __future__ import annotations
import argparse, json, math, os, re, sys, tempfile
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path
from typing import Any
SCHEMA_VERSION = "rubin-mixed-client-devnet-soak-report-v2"; MAX_JSON_BYTES = 1_000_000  # noqa: E702
HEX32 = re.compile(r"[0-9a-f]{64}"); HEX_BYTES = re.compile(r"(?:[0-9a-f]{2})+"); ENDPOINT = re.compile(r"([0-9A-Za-z._-]+):([0-9]{1,5})")  # noqa: E702
METRICS = ("rubin_node_reorg_total", "rubin_node_last_reorg_depth"); NUM = r"[0-9]+(?:\.0*)?(?:[eE][+]?\d+)?"; METRIC_LINE = re.compile(rf"^({'|'.join(METRICS)})\s+({NUM})(?:\s+({NUM}))?\s*$"); NO_DUPES = lambda pairs: dict(pairs) if len({k for k, _ in pairs}) == len(pairs) else (_ for _ in ()).throw(ValueError("duplicate_json_key")); BAD_MARKER = lambda value: any(k == "schema_marker" or k.startswith("failure_") or BAD_MARKER(v) for k, v in value.items()) if isinstance(value, dict) else any(BAD_MARKER(v) for v in value) if isinstance(value, list) else False  # noqa: E702, E731
SAFE_REASON = re.compile(r"[a-z0-9_:-]{1,160}"); CLAIM_REASON_TOKENS = {"ready", "pass", "parity", "converge", "convergence", "reorg", "restart", "metric", "fail", "no_data", "not_applicable", "helper_only"}  # noqa: E702
PATH_FIELD_NAMES = {"marker_path", "get_tx_path", "tx_status_path", "block_path", "mine_next_path", "tip_path", "go_tip_block", "rust_tip_block", "binary"}
PATH_FIELD_DOTTED_NAMES = {
    "observations.pre_partition.common_go_block", "observations.pre_partition.common_go_mine", "observations.pre_partition.common_rust_block", "observations.pre_partition.common_rust_tip", "observations.pre_partition.go_peer_snapshot", "observations.pre_partition.rust_peer_snapshot",
    "observations.partition.go_peer_snapshot", "observations.partition.rust_peer_snapshot", "observations.fork.go_block", "observations.fork.go_mine", "observations.fork.go_peer_snapshot", "observations.fork.go_tip", "observations.fork.rust_block_1", "observations.fork.rust_block_2", "observations.fork.rust_mine_1", "observations.fork.rust_mine_2", "observations.fork.rust_peer_snapshot", "observations.fork.rust_tip",
    "observations.heal.go_peer_snapshot", "observations.heal.rust_peer_snapshot", "observations.reorg.go_reorg_parent_block", "observations.reorg.go_tip", "observations.reorg.go_tip_block", "observations.reorg.rust_tip", "observations.reorg.rust_tip_block",
}
TX_OBJECT_KEYS = {
    "go_submit": {"get_tx_path", "rpc_endpoint", "tx_hex", "tx_status_path", "txid"},
    "rust_submit": {"get_tx_path", "rpc_endpoint", "tx_hex", "tx_status_path", "txid"},
    "go_accept": {"get_tx_path", "raw_hex", "rpc_endpoint", "tx_status_path", "txid"},
    "rust_accept": {"get_tx_path", "raw_hex", "rpc_endpoint", "tx_status_path", "txid"},
    "go_mine": {"block_hash", "block_path", "class", "height", "mine_next_path", "mined_by", "raw_hex", "rpc_endpoint", "tx_count", "txid"},
    "rust_mine": {"block_hash", "block_path", "class", "height", "mine_next_path", "mined_by", "raw_hex", "rpc_endpoint", "tx_count", "txid"},
    "go_converge": {"block_hash", "block_path", "class", "converged_at", "height", "raw_hex", "rpc_endpoint", "tip_path", "txid"},
    "rust_converge": {"block_hash", "block_path", "class", "converged_at", "height", "raw_hex", "rpc_endpoint", "tip_path", "txid"},
}
SECTIONS = {
    "mesh": ("mesh_report", "mixed_client_mesh", ["nodes", "peer_connectivity", "final_verification", "legacy_schema_compatibility.marker_path", "raw_samples.propagation", "raw_samples.convergence"]),
    "go_to_rust_accept": ("go_submit_rust_accept_report", "mixed_client_go_submit_rust_accept", ["go_submit", "rust_accept", "tx_path", "raw_samples.propagation"]),
    "go_to_rust_mine_converge": ("go_submit_rust_mine_go_converge_report", "mixed_client_go_submit_rust_mine_go_converge", ["go_submit", "rust_accept", "rust_mine", "go_converge", "tx_path", "raw_samples.propagation", "raw_samples.convergence"]),
    "rust_to_go_mine_converge": ("rust_submit_go_mine_rust_converge_report", "mixed_client_rust_submit_go_mine_rust_converge", ["rust_submit", "go_accept", "go_mine", "rust_converge", "tx_path", "raw_samples.propagation", "raw_samples.convergence"]),
    "rust_restart": ("rust_restart_report", "mixed_client_rust_restart", ["restart.stopped_node", "rust_restart.old_pid", "rust_restart.new_pid", "rust_restart.old_pid_stopped", "rust_restart.same_datadir", "rust_restart.peer_reconnect_observed", "rust_restart.go_target_height", "rust_restart.catch_up_height"]),
    "partition_heal_reorg": ("partition_heal_reorg_report", "mixed_client_partition_heal_reorg", ["proof.partition_changed_peer_state", "proof.fork_diverged", "proof.heal_restored_peer_state", "proof.reorg_converged", "proof.process_identity_rechecked_after_heal", "proof.go_reorg_metrics", "observations.reorg"]),
}
def is_hex32(value: Any) -> bool: return isinstance(value, str) and bool(HEX32.fullmatch(value))  # noqa: E704
def hex_bytes(value: Any) -> bool: return isinstance(value, str) and bool(HEX_BYTES.fullmatch(value))  # noqa: E704
def jint(value: Any, minimum: int = 1) -> bool: return isinstance(value, int) and not isinstance(value, bool) and minimum <= value <= 1_000_000_000  # noqa: E704
def section(name: str, status: str, reason: str | None = None, **kw: Any) -> dict[str, Any]:
    out = {"status": status, "claim_type": kw.pop("claim_type", "status_evidence")}
    if reason:
        out["reason"] = reason
    for key, value in kw.items():
        if value is not None and value != []:
            out[key] = str(value) if isinstance(value, Path) else value
    return out
def load(path: Path) -> tuple[Any | None, str | None]:
    try:
        with path.open("rb") as src: raw = src.read(MAX_JSON_BYTES + 1)
        if len(raw) > MAX_JSON_BYTES: return None, "json_too_large"  # noqa: E701
        return json.loads(raw.decode("utf-8"), object_pairs_hook=NO_DUPES, parse_constant=lambda c: (_ for _ in ()).throw(ValueError(f"non_finite_json_constant:{c}"))), None
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
        text = str(exc)
        return None, text if text.startswith(("non_finite_json_constant:", "duplicate_json_key")) else f"malformed_json:{exc.__class__.__name__}"
def regular_path(raw_path: str, reason: str) -> tuple[Path, str | None]: raw = Path(os.path.expanduser(raw_path)); canon = Path(os.path.realpath(raw)); return (canon, None) if raw.is_file() and not raw.is_symlink() else (canon, reason)  # noqa: E704, E702
def get(data: Any, dotted: str) -> tuple[Any, bool]:
    cur = data
    for part in dotted.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None, False
        cur = cur[part]
    return cur, True
def source_object_error(obj: Any, label: str) -> str | None:
    keys = TX_OBJECT_KEYS[label]
    if not isinstance(obj, dict) or set(obj) != keys:
        return f"{label}_source_fields_invalid"
    if not isinstance(obj.get("rpc_endpoint"), str) or not obj["rpc_endpoint"]:
        return f"{label}_source_fields_invalid"
    if not isinstance(obj.get("txid"), str) or not obj["txid"]:
        return f"{label}_source_fields_invalid"
    if any(not isinstance(obj.get(k), str) or not obj[k] for k in keys & PATH_FIELD_NAMES):
        return f"{label}_source_fields_invalid"
    if any(k in keys and not hex_bytes(obj.get(k)) for k in ("tx_hex", "raw_hex")) or ("tx_count" in keys and not jint(obj.get("tx_count"), 2)):
        return f"{label}_source_fields_invalid"
    return None
def nonfinite(value: Any, label: str = "root") -> str | None:
    if isinstance(value, dict):
        for key, item in value.items():
            if bad := nonfinite(item, f"{label}.{key}"):
                return bad
    if isinstance(value, list):
        for idx, item in enumerate(value):
            if bad := nonfinite(item, f"{label}[{idx}]"):
                return bad
    return f"non_finite_numeric_value:{label}" if isinstance(value, float) and not math.isfinite(value) else None
def scenario_reject(scenario: Any) -> str | None:
    text = str(scenario or "")
    if "schema_marker" in text or "helper" in text:
        return "helper_only_artifact_not_full_mixed_client"
    if text.startswith(("go_binary_soak", "rust_skeleton")) or "single_client" in text:
        return "same_client_artifact_presented_as_mixed_client"
    return None
def nodes(data: dict[str, Any], require_alive: bool = True, require_backing: bool = True) -> tuple[dict[str, dict[str, Any]] | None, str | None]:
    raw = data.get("nodes")
    if not isinstance(raw, list) or len(raw) != 2 or not all(isinstance(n, dict) for n in raw):
        return None, "process_identity_missing_or_invalid"
    by_name = {n.get("name"): n for n in raw if isinstance(n.get("name"), str)}
    if set(by_name) != {"node-go", "node-rust"}:
        return None, "wrong_role_identity"
    out: dict[str, dict[str, Any]] = {}
    for name, impl in (("node-go", "go"), ("node-rust", "rust")):
        node = by_name[name]
        if node.get("implementation") != impl or not jint(node.get("pid")) or (node.get("process_alive") is not True if require_alive else ("process_alive" in node and node.get("process_alive") is not True)):
            return None, "wrong_role_identity"
        if (not all(isinstance((v := node.get(k)), str) and (m := ENDPOINT.fullmatch(v)) is not None and 1 <= int(m.group(2)) <= 65535 for k in ("rpc_endpoint", "p2p_endpoint"))) or any(k in node and node.get(k) is not True for k in ("rpc_endpoint_process_backed", "p2p_endpoint_process_backed")) or (require_backing and (node.get("rpc_endpoint_process_backed") is not True or node.get("p2p_endpoint_process_backed") is not True)):
            return None, "process_identity_missing_or_invalid"
        out[impl] = node
    if out["go"]["pid"] == out["rust"]["pid"] or len({out[i][k] for i in ("go", "rust") for k in ("rpc_endpoint", "p2p_endpoint")}) != 4:
        return None, "process_identity_missing_or_invalid"
    return out, None
def validate_mesh(data: dict[str, Any]) -> str | None:
    _, bad = nodes(data)
    if bad:
        return bad
    peer, final = data.get("peer_connectivity"), data.get("final_verification")
    if not isinstance(peer, dict) or any(peer.get(k) is not True for k in ("go_to_rust", "rust_to_go", "bidirectional_observed")):
        return "peer_connectivity_invalid"
    return validate_samples(data, None, None, "") if isinstance(final, dict) and final.get("producer_side") is True else "final_verification_invalid"
def validate_samples(data: dict[str, Any], prop_dir: str | None, conv_dir: str | None, txid: str, height: int | None = None, block_hash: str | None = None) -> str | None:
    raw = data.get("raw_samples")
    if not isinstance(raw, dict) or set(raw) != {"schema_version", "semantics", "propagation", "convergence"} or raw.get("schema_version") != "rubin-devnet-process-soak-raw-samples-v1" or raw.get("semantics") != "raw samples only; no SLO threshold or pass claim":
        return "raw_samples_invalid"
    for name, direction in (("propagation", prop_dir), ("convergence", conv_dir)):
        bucket = raw.get(name)
        samples = bucket.get("samples") if isinstance(bucket, dict) else None
        if not isinstance(bucket, dict) or set(bucket) != {"classification", "path_direction", "reason", "samples", "unit"} or bucket.get("unit") != "seconds" or bucket.get("path_direction") != direction or not isinstance(samples, list):
            return f"{name}_samples_invalid"
        if direction is None:
            if bucket.get("classification") != "not_requested" or bucket.get("reason") != f"{name}_sample_not_requested_by_scenario" or samples:
                return f"{name}_samples_unrequested_observed"
            continue
        if bucket.get("classification") != "observed" or bucket.get("reason") is not None or len(samples) != 1:
            return f"{name}_samples_missing"
        sample = samples[0]
        src, dst = direction.split("->")
        keys = {"classification", "elapsed", "path_direction", "source", "target", "tx_id", "unit"} | ({"block_hash", "height"} if name == "convergence" else set())
        if not isinstance(sample, dict) or set(sample) != keys or sample.get("classification") != "observed" or sample.get("path_direction") != direction or sample.get("source") != f"node-{src}" or sample.get("target") != f"node-{dst}" or sample.get("tx_id") != txid or sample.get("unit") != "seconds":
            return f"{name}_sample_identity_invalid"
        elapsed = sample.get("elapsed")
        if not isinstance(elapsed, (int, float)) or isinstance(elapsed, bool):
            return f"{name}_sample_elapsed_invalid"
        if isinstance(elapsed, float) and not math.isfinite(elapsed):
            return f"non_finite_{name}_sample:0"
        if elapsed < 0 or elapsed > 1_000_000_000:
            return f"{name}_sample_elapsed_out_of_range"
        if name == "convergence" and (not jint(sample.get("height")) or sample.get("height") != height or sample.get("block_hash") != block_hash):
            return "convergence_sample_identity_mismatch"
    return None
def validate_tx(data: dict[str, Any], converge: bool, rust_submit: bool) -> str | None:
    by_impl, bad = nodes(data)
    if bad or by_impl is None:
        return bad
    tx_path = data.get("tx_path")
    if not isinstance(tx_path, dict) or set(tx_path) != {"submitted_at", "observed_at", "tx_id"} or not is_hex32(tx_path.get("tx_id")):
        return "tx_path_invalid"
    txid = tx_path["tx_id"]
    submit, accept, mine, conv, src, dst, prop, conv_dir, submit_impl, accept_impl, mine_impl, conv_impl = ("rust_submit", "go_accept", "go_mine", "rust_converge", "node-rust", "node-go", "rust->go", "go->rust", "rust", "go", "go", "rust") if rust_submit else ("go_submit", "rust_accept", "rust_mine", "go_converge", "node-go", "node-rust", "go->rust", "rust->go", "go", "rust", "rust", "go")
    if tx_path.get("submitted_at") != src or tx_path.get("observed_at") != [dst]:
        return "tx_path_direction_invalid"
    for label, impl in ((submit, submit_impl), (accept, accept_impl)):
        if bad := source_object_error(data.get(label), label):
            return bad
        if data[label].get("txid") != txid:
            return f"{label}_txid_mismatch"
        if data[label].get("rpc_endpoint") != by_impl[impl]["rpc_endpoint"]:
            return f"{label}_rpc_endpoint_mismatch"
    submitted_hex = data[submit]["tx_hex"]
    if data[accept]["raw_hex"] != submitted_hex:
        return f"{accept}_raw_hex_mismatch"
    if not converge: return validate_samples(data, prop, None, txid)  # noqa: E701
    mined, seen = data.get(mine), data.get(conv)
    if (bad := source_object_error(mined, mine)) or (bad := source_object_error(seen, conv)): return bad  # noqa: E701
    if not isinstance(mined, dict) or not isinstance(seen, dict): return "convergence_identity_mismatch"  # noqa: E701
    if mined.get("raw_hex") != submitted_hex or seen.get("raw_hex") != submitted_hex:
        return "convergence_identity_mismatch"
    if mined.get("txid") != txid or seen.get("txid") != txid or any(obj.get("rpc_endpoint") != by_impl[impl]["rpc_endpoint"] for obj, impl in ((mined, mine_impl), (seen, conv_impl))) or mined.get("class") != "mined_included" or mined.get("mined_by") != f"node-{mine_impl}" or seen.get("class") != "canonical_block_found" or seen.get("converged_at") != f"node-{conv_impl}": return "convergence_identity_mismatch"  # noqa: E701
    if mined.get("height") != seen.get("height") or mined.get("block_hash") != seen.get("block_hash") or not jint(mined.get("height")) or not jint(seen.get("height")) or not is_hex32(mined.get("block_hash")): return "convergence_identity_mismatch"  # noqa: E701
    return validate_samples(data, prop, conv_dir, txid, mined["height"], mined["block_hash"])
def restart_contradiction(data: dict[str, Any]) -> str | None:
    if not isinstance(data.get("restart"), dict) or data["restart"].get("stopped_node") != "node-rust":
        return "wrong_role_identity"
    by_impl, bad = nodes(data, require_alive=False)
    rr = data.get("rust_restart")
    if not isinstance(rr, dict):
        return "restart_source_binding_contradiction:malformed_source_fields" if "rust_restart" in data else bad
    if any(k in rr and not isinstance(rr.get(k), bool) for k in ("old_pid_stopped", "same_datadir", "peer_reconnect_observed")) or any(k in rr and not jint(rr.get(k)) for k in ("old_pid", "new_pid", "go_target_height", "catch_up_height")):
        return "restart_source_binding_contradiction:malformed_source_fields"
    if rr.get("old_pid_stopped") is False:
        return "restart_source_binding_contradiction:old_pid_stopped_false"
    if rr.get("same_datadir") is False:
        return "restart_source_binding_contradiction:same_datadir_false"
    if rr.get("peer_reconnect_observed") is False:
        return "restart_source_binding_contradiction:peer_reconnect_not_observed"
    if bad or by_impl is None:
        return bad or "process_identity_missing_or_invalid"
    old_pid, new_pid = rr.get("old_pid"), rr.get("new_pid")
    if jint(old_pid) and old_pid in {by_impl["go"]["pid"], by_impl["rust"]["pid"]}:
        return "restart_source_binding_contradiction:old_pid_aliases_live_node"
    if jint(new_pid) and new_pid != by_impl["rust"]["pid"]:
        return "restart_source_binding_contradiction:new_pid_not_final_rust_pid"
    restart = data["restart"]
    if any(k in restart and not jint(restart.get(k)) for k in ("pre_restart_height", "catch_up_height")):
        return "restart_source_binding_contradiction:malformed_source_fields"
    for key in ("pre_restart_height", "catch_up_height"):
        if key in restart and (key not in rr or rr.get(key) != restart[key]):
            return f"restart_source_binding_contradiction:{key}_mismatch"
    if "pre_restart_height" in restart and "catch_up_height" in restart and restart["catch_up_height"] < restart["pre_restart_height"]:
        return "restart_source_binding_contradiction:catch_up_height_below_pre_restart"
    target, caught, pre = rr.get("go_target_height"), rr.get("catch_up_height"), rr.get("pre_restart_height", restart.get("pre_restart_height"))
    if pre is not None and (not jint(pre) or not jint(target) or target <= pre):
        return "restart_source_binding_contradiction:target_height_not_advanced"
    if jint(target) and jint(caught):
        if caught < target:
            return "restart_source_binding_contradiction:catch_up_height_below_target"
        if caught != target:
            return "restart_source_binding_contradiction:catch_up_height_not_target"
    go_tip, catch_tip = rr.get("go_target_tip"), rr.get("catch_up_tip")
    if go_tip is not None and not is_hex32(go_tip):
        return "restart_source_binding_contradiction:go_target_tip_invalid"
    if catch_tip is not None and not is_hex32(catch_tip):
        return "restart_source_binding_contradiction:catch_up_tip_invalid"
    if is_hex32(go_tip) and is_hex32(catch_tip) and go_tip != catch_tip:
        return "restart_source_binding_contradiction:tip_hash_mismatch"
    return None
def partition_contradiction(data: dict[str, Any]) -> str | None:
    _, bad = nodes(data, require_alive=False, require_backing=False)
    proof = data.get("proof")
    if not isinstance(proof, dict):
        return "partition_reorg_source_binding_contradiction:malformed_proof_fields" if "proof" in data else bad
    if any(k in proof and not isinstance(proof.get(k), bool) for k in ("partition_changed_peer_state", "fork_diverged", "heal_restored_peer_state", "reorg_converged", "process_identity_rechecked_after_heal")) or ("go_reorg_metrics" in proof and (not isinstance(proof.get("go_reorg_metrics"), dict) or any(not jint(proof["go_reorg_metrics"].get(m)) for m in METRICS))):
        return "partition_reorg_source_binding_contradiction:malformed_proof_fields"
    for key, reason in (("partition_changed_peer_state", "partition_no_peer_state_change"), ("fork_diverged", "partition_no_fork_divergence"), ("heal_restored_peer_state", "partition_heal_not_restored"), ("reorg_converged", "partition_reorg_not_converged"), ("process_identity_rechecked_after_heal", "partition_process_identity_not_rechecked_after_heal")):
        if proof.get(key) is False:
            return f"partition_reorg_source_binding_contradiction:{reason}"
    go_fork, rust_win = proof.get("go_partition_tip"), proof.get("rust_winning_tip")
    if (go_fork is not None or rust_win is not None) and not (isinstance(go_fork, dict) and isinstance(rust_win, dict)):
        return "partition_reorg_source_binding_contradiction:malformed_tip_fields"
    if isinstance(go_fork, dict) and isinstance(rust_win, dict) and (not jint(go_fork.get("height")) or not jint(rust_win.get("height")) or not is_hex32(go_fork.get("hash")) or not is_hex32(rust_win.get("hash")) or go_fork.get("hash") == rust_win.get("hash")):
        return "partition_reorg_source_binding_contradiction:fork_tip_not_diverged"
    if any(a in proof and b in proof and proof[a] != proof[b] for a, b in (("final_go_tip", "go_tip"), ("final_rust_tip", "rust_tip"))):
        return "partition_reorg_source_binding_contradiction:tip_alias_mismatch"
    go_tip = proof["final_go_tip"] if "final_go_tip" in proof else proof.get("go_tip")
    rust_tip = proof["final_rust_tip"] if "final_rust_tip" in proof else proof.get("rust_tip")
    if (go_tip is not None or rust_tip is not None) and not (isinstance(go_tip, dict) and isinstance(rust_tip, dict)):
        return "partition_reorg_source_binding_contradiction:malformed_tip_fields"
    if isinstance(go_tip, dict) and isinstance(rust_tip, dict):
        if not jint(go_tip.get("height")) or not jint(rust_tip.get("height")) or not is_hex32(go_tip.get("hash")) or not is_hex32(rust_tip.get("hash")):
            return "partition_reorg_source_binding_contradiction:block_hash_malformed"
        if jint(go_tip.get("height")) and jint(rust_tip.get("height")) and go_tip.get("height") != rust_tip.get("height"):
            return "partition_reorg_source_binding_contradiction:final_height_mismatch"
        if is_hex32(go_tip.get("hash")) and is_hex32(rust_tip.get("hash")) and go_tip.get("hash") != rust_tip.get("hash"):
            return "partition_reorg_source_binding_contradiction:final_tip_hash_mismatch"
        if isinstance(go_fork, dict) and isinstance(rust_win, dict) and (go_tip != rust_win or rust_tip != rust_win): return "partition_reorg_source_binding_contradiction:final_tip_not_winning_tip"  # noqa: E701
    return bad
def build_section(name: str, attr: str, scenario: str, fields: list[str], args: argparse.Namespace) -> dict[str, Any]:
    raw_path = getattr(args, attr)
    if not raw_path:
        return section(name, "no_data", f"{name}_artifact_missing", source_fields=fields)
    path, path_err = regular_path(raw_path, "source_artifact_not_regular")
    if path_err:
        return section(name, "fail", path_err, source_artifact_path=path, source_fields=fields)
    data, err = load(path)
    if err or not isinstance(data, dict):
        return section(name, "fail", err or "root_not_object", source_artifact_path=path)
    try: bad, bad_marker = nonfinite(data), BAD_MARKER(data)
    except RecursionError: return section(name, "fail", "malformed_json:RecursionError", source_artifact_path=path)  # noqa: E701
    if bad:
        return section(name, "fail", bad, source_artifact_path=path, scenario=data.get("scenario"))
    got = data.get("scenario")
    if got != scenario:
        helper = scenario_reject(got)
        return section(name, "helper_only" if helper and helper.startswith("helper") else "fail", helper or "unsupported_scenario", source_artifact_path=path, scenario=got, source_fields=fields)
    if data.get("verdict") != "PASS" or bad_marker:
        return section(name, "fail", "source_verdict_not_pass" if data.get("verdict") != "PASS" else "pass_artifact_contains_failure_fields", source_artifact_path=path, scenario=got)
    missing = [f for f in fields if not get(data, f)[1]]
    malformed = "legacy_schema_compatibility.marker_path" if name == "mesh" and get(data, "legacy_schema_compatibility.marker_path")[1] and (not isinstance((m := get(data, "legacy_schema_compatibility.marker_path")[0]), str) or not m or regular_path(str(Path(os.path.expanduser(m)) if Path(os.path.expanduser(m)).is_absolute() else path.parent / m), "legacy_schema_marker_not_regular")[1]) else "observations.reorg" if name == "partition_heal_reorg" and get(data, "observations.reorg")[1] and not isinstance(get(data, "observations.reorg")[0], dict) else None
    if malformed:
        return section(name, "fail", "malformed_source_fields:" + malformed, source_artifact_path=path, scenario=got)
    if name in {"rust_restart", "partition_heal_reorg"}:
        bad = restart_contradiction(data) if name == "rust_restart" else partition_contradiction(data)
        if bad:
            return section(name, "fail", bad, source_artifact_path=path, scenario=got)
        base = "restart_source_binding_unproven" if name == "rust_restart" else "partition_reorg_source_binding_unproven"
        reason = base if not missing else f"{base}:missing_source_fields:{','.join(missing)}"
        return section(name, "no_data", reason, source_artifact_path=path, scenario=got, source_fields=fields, claim_type="structural_only", evidence_class="structural_only", behavior_evidence=False)
    if missing:
        return section(name, "fail", "missing_source_fields:" + ",".join(missing), source_artifact_path=path, scenario=got)
    bad = validate_mesh(data) if name == "mesh" else validate_tx(data, "converge" in name, name.startswith("rust_to_go"))
    if bad:
        return section(name, "fail", bad, source_artifact_path=path, scenario=got)
    return section(name, "no_data", "source_contract_validation_unavailable", source_artifact_path=path, scenario=got, source_fields=fields, claim_type="structural_only", evidence_class="structural_only", behavior_evidence=False)
def parse_metrics(path: Path) -> tuple[dict[str, int] | None, str | None]:
    try:
        with path.open("rb") as src: raw = src.read(MAX_JSON_BYTES + 1)
        if len(raw) > MAX_JSON_BYTES: return None, "metrics_too_large"  # noqa: E701
        text = raw.decode("utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        return None, f"read_failed:{exc.__class__.__name__}"
    try:
        found: dict[str, int] = {}
        if text.lstrip().startswith("{"):
            obj = json.loads(text, object_pairs_hook=NO_DUPES, parse_float=Decimal, parse_int=Decimal, parse_constant=lambda c: (_ for _ in ()).throw(ValueError(f"non_finite_json_constant:{c}")))
            if not isinstance(obj, dict):
                return None, "metrics_malformed"
            if nonfinite(obj) or any(key not in METRICS for key in obj):
                return None, "metrics_malformed"
            for metric in METRICS:
                if metric not in obj: return None, "metrics_missing_or_zero"  # noqa: E701
                if isinstance((v := obj.get(metric)), bool) or not isinstance(v, Decimal) or not v.is_finite() or v <= 0 or v > Decimal(1_000_000_000) or v != v.to_integral_value():
                    return None, "metric_value_invalid"
                found[metric] = int(v)
        else:
            for raw_line in text.splitlines():
                if not (line := raw_line.strip()): continue  # noqa: E701
                head = re.match(r"[A-Za-z_:][A-Za-z0-9_:]*", line); metric = head.group(0) if head else ""; m = METRIC_LINE.fullmatch(line) if metric in METRICS else None  # noqa: E702
                if metric in METRICS and not m: return None, "metrics_malformed"  # noqa: E701
                if m:
                    value = float(m.group(2))
                    if metric in found or not math.isfinite(value) or value <= 0 or value > 1_000_000_000 or int(value) != value: return None, "metrics_duplicate" if metric in found else "metric_value_invalid"  # noqa: E701
                    found[metric] = int(value)
    except (json.JSONDecodeError, TypeError, ValueError, RecursionError) as exc:
        return None, str(exc) if str(exc).startswith("duplicate_json_key") else "metrics_malformed"
    return (found, None) if all(found.get(m, 0) > 0 for m in METRICS) else (None, "metrics_missing_or_zero")
def no_data_source_reason_error(value: Any) -> str | None:
    if not isinstance(value, str) or not value:
        return "rust_reorg_metrics_no_data_reason_invalid"
    lowered = value.lower()
    if any(re.search(rf"(?<![a-z0-9]){re.escape(token).replace('_', '[_-]?')}(?![a-z0-9])", lowered) for token in CLAIM_REASON_TOKENS):
        return "rust_reorg_metrics_no_data_reason_reserved"
    return None if SAFE_REASON.fullmatch(value) else "rust_reorg_metrics_no_data_reason_invalid"
def metric_section(args: argparse.Namespace) -> dict[str, Any]:
    if args.rust_reorg_metrics_no_data:
        if bad := no_data_source_reason_error(args.rust_reorg_metrics_no_data):
            return section("reorg_metrics", "fail", bad, claim_type="metric_evidence")
        return section("reorg_metrics", "no_data", "rust_reorg_metrics_no_data", source_reason=args.rust_reorg_metrics_no_data, claim_type="metric_evidence")
    if not args.rust_reorg_metrics:
        return section("reorg_metrics", "no_data", "rust_reorg_metrics_missing", claim_type="metric_evidence")
    path, path_err = regular_path(args.rust_reorg_metrics, "metrics_not_regular")
    metrics, err = (None, path_err) if path_err else parse_metrics(path)
    return section("reorg_metrics", "fail", err, source_artifact_path=path, claim_type="metric_evidence") if err else section("reorg_metrics", "no_data", "metric_source_binding_unavailable", source_artifact_path=path, source_fields=sorted(METRICS), claim_type="metric_evidence", metric_values=metrics)
def raw_samples_section(sections: dict[str, dict[str, Any]]) -> dict[str, Any]: return section("raw_samples", "fail", "source_sample_section_failed") if any(sections[name]["status"] in {"fail", "helper_only"} for name in ("go_to_rust_accept", "go_to_rust_mine_converge", "rust_to_go_mine_converge")) else section("raw_samples", "no_data", "source_contract_validation_unavailable", source_fields=["raw_samples.propagation", "raw_samples.convergence"], claim_type="sample_evidence")  # noqa: E704
def claim_tokens_in_text(value: Any) -> set[str]:
    if not isinstance(value, str):
        return set()
    lowered = value.lower()
    return {token for token in CLAIM_REASON_TOKENS if re.search(rf"(?<![a-z0-9]){re.escape(token).replace('_', '[_-]?')}(?![a-z0-9])", lowered)}
def inventory(sections: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    out = []
    for name, sec in sections.items():
        tokens = {sec["status"]}
        tokens |= {"converge", "convergence"} if "converge" in name else set()
        tokens |= {"reorg"} if "reorg" in name else set()
        tokens |= {"restart"} if "restart" in name else set()
        tokens |= {"metric"} if "metric" in name else set()
        tokens |= {"not_applicable"} if name == "deferred_related" else set()
        tokens |= claim_tokens_in_text(sec.get("reason")) | claim_tokens_in_text(sec.get("source_reason"))
        out.extend({"token": t, "section": name, "source_artifact_path": sec.get("source_artifact_path"), "source_fields": sec.get("source_fields", []), "claim_type": sec.get("claim_type", "status_evidence")} for t in sorted(tokens))
    return out
def generate(args: argparse.Namespace) -> tuple[dict[str, Any], int]:
    sections = {name: build_section(name, attr, scenario, fields, args) for name, (attr, scenario, fields) in SECTIONS.items()}
    sections["reorg_metrics"] = metric_section(args)
    sections["raw_samples"] = raw_samples_section(sections)
    sections["deferred_related"] = section("deferred_related", "not_applicable", "deferred_by_rub_227", claim_type="deferred_related_work")
    statuses = {s["status"] for s in sections.values()}
    verdict = "FAIL" if statuses & {"fail", "helper_only"} else "NO_DATA" if "no_data" in statuses else "PASS"
    inputs = {k: (v if k.endswith("_no_data") else str(Path(os.path.realpath(Path(os.path.expanduser(v)))))) for k, v in vars(args).items() if k != "output" and v}
    report = {"schema_version": SCHEMA_VERSION, "verdict": verdict, "generated_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "inputs": inputs, "sections": sections, "claim_inventory": inventory(sections), "non_goals": ["PR-1 report consumer only; no runtime, producer, live scenario, client, schema, or CI changes.", "Restart/reorg behavior evidence remains blocked on RUB-240 source-bound producer sidecars.", "RUB-227 orphan metrics remain deferred/not_applicable."]}
    return report, 1 if verdict == "FAIL" else 0
def write_atomic(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            out.write(json.dumps(data, indent=2, sort_keys=True) + "\n")
        os.replace(tmp, path)
    except OSError:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
def path_field_targets(value: Any, base: Path) -> list[Path]:
    out: list[Path] = []; stack: list[tuple[Any, str]] = [(value, "")]  # noqa: E702
    def add_path(text: str) -> None:
        raw = (_ for _ in ()).throw(ValueError("path_field_contains_nul")) if "\x00" in text else Path(os.path.expanduser(text)); out.append(Path(os.path.realpath(raw if raw.is_absolute() else base / raw)))  # noqa: E702
    while stack:
        item, prefix = stack.pop()
        if isinstance(item, dict):
            for key, child in item.items():
                dotted = f"{prefix}.{key}" if prefix else key; is_path = key in PATH_FIELD_NAMES or (key.endswith("_path") and key != "tx_path") or dotted in PATH_FIELD_DOTTED_NAMES  # noqa: E702
                if is_path and not isinstance(child, str): raise ValueError("path_field_not_string")  # noqa: E701
                if is_path: add_path(child)  # noqa: E701
                else: stack.append((child, dotted))  # noqa: E701
        elif isinstance(item, list):
            if prefix.endswith("command_argv"):
                for child in item:
                    if isinstance(child, str):
                        for text in (child, child.split("=", 1)[1] if "=" in child else ""):
                            if text and (text.startswith(("~", "/", ".")) or os.sep in text): add_path(text)  # noqa: E701
            stack.extend((child, prefix) for child in item)
    return out
def same_path(left: Path, right: Path) -> bool:
    if left == right: return True  # noqa: E701
    try: return os.path.samefile(left, right)  # noqa: E701
    except (OSError, ValueError): return sys.platform == "darwin" and str(left).lower() == str(right).lower()  # noqa: E701
def scan_source_data(path: Path) -> dict[str, Any] | None:
    data, err = load(path)
    return data if err is None and isinstance(data, dict) else None
def output_overwrites_input(args: argparse.Namespace, out_path: Path) -> str | None:
    for key, value in vars(args).items():
        if key == "output" or key.endswith("_no_data") or not value:
            continue
        source_path = Path(os.path.realpath(Path(os.path.expanduser(value))))
        if same_path(source_path, out_path):
            return "output_overwrites_input"
        if not source_path.is_file():
            continue
        data = scan_source_data(source_path)
        if data is None:
            if key == "rust_reorg_metrics":
                continue
            _, err = load(source_path)
            return f"output_scan_failed:{err or 'source_not_object'}"
        try: targets = path_field_targets(data, source_path.parent)
        except ValueError as exc: return f"output_scan_failed:{exc}"  # noqa: E701
        if any(same_path(target, out_path) for target in targets):
            return "output_overwrites_input"
    return None
def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate fail-closed mixed-client devnet soak report v2.")
    for opt, dest in (("--mesh-report", "mesh_report"), ("--go-submit-rust-accept-report", "go_submit_rust_accept_report"), ("--go-submit-rust-mine-go-converge-report", "go_submit_rust_mine_go_converge_report"), ("--rust-submit-go-mine-rust-converge-report", "rust_submit_go_mine_rust_converge_report"), ("--rust-restart-report", "rust_restart_report"), ("--partition-heal-reorg-report", "partition_heal_reorg_report")):
        parser.add_argument(opt, dest=dest)
    metrics = parser.add_mutually_exclusive_group()
    metrics.add_argument("--rust-reorg-metrics")
    metrics.add_argument("--rust-reorg-metrics-no-data")
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    out_path = Path(os.path.realpath(Path(os.path.expanduser(args.output))))
    overwrite_reason = output_overwrites_input(args, out_path)
    if overwrite_reason:
        return print(f"FAIL: {overwrite_reason}", file=sys.stderr) or 1
    report, rc = generate(args)
    try:
        write_atomic(out_path, report)
    except OSError as exc:
        print(f"FAIL: output_write_failed:{exc.__class__.__name__}: {exc}", file=sys.stderr)
        return 1
    if rc:
        print("FAIL: " + "; ".join(f"{k}:{v.get('reason', v['status'])}" for k, v in report["sections"].items() if v["status"] in {"fail", "helper_only"}), file=sys.stderr)
    else:
        print(f"{report['verdict']}: wrote {args.output}")
    return rc
if __name__ == "__main__":
    raise SystemExit(main())
