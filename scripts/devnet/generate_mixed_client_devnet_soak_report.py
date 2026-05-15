#!/usr/bin/env python3
# ruff: noqa: E302,E305,E401,E701
from __future__ import annotations
import argparse, json, math, os, re, sys, tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
SCHEMA_VERSION = "rubin-mixed-client-devnet-soak-report-v2"; MAX_JSON_BYTES = 1_000_000  # noqa: E702
HEX32 = re.compile(r"[0-9a-f]{64}"); ENDPOINT = re.compile(r"([^\s:/]+):([0-9]+)")  # noqa: E702
METRICS = ("rubin_node_reorg_total", "rubin_node_last_reorg_depth"); NO_DUPES = lambda pairs: dict(pairs) if len({k for k, _ in pairs}) == len(pairs) else (_ for _ in ()).throw(ValueError("duplicate_json_key")); BAD_MARKER = lambda value: any(k == "schema_marker" or k.startswith("failure_") or BAD_MARKER(v) for k, v in value.items()) if isinstance(value, dict) else any(BAD_MARKER(v) for v in value) if isinstance(value, list) else False  # noqa: E702, E731
SECTIONS = {
    "mesh": ("mesh_report", "mixed_client_mesh", ["nodes", "peer_connectivity", "final_verification", "legacy_schema_compatibility.marker_path", "raw_samples.propagation", "raw_samples.convergence"]),
    "go_to_rust_accept": ("go_submit_rust_accept_report", "mixed_client_go_submit_rust_accept", ["go_submit", "rust_accept", "tx_path", "raw_samples.propagation"]),
    "go_to_rust_mine_converge": ("go_submit_rust_mine_go_converge_report", "mixed_client_go_submit_rust_mine_go_converge", ["go_submit", "rust_accept", "rust_mine", "go_converge", "tx_path", "raw_samples.propagation", "raw_samples.convergence"]),
    "rust_to_go_mine_converge": ("rust_submit_go_mine_rust_converge_report", "mixed_client_rust_submit_go_mine_rust_converge", ["rust_submit", "go_accept", "go_mine", "rust_converge", "tx_path", "raw_samples.propagation", "raw_samples.convergence"]),
    "rust_restart": ("rust_restart_report", "mixed_client_rust_restart", ["restart.stopped_node", "rust_restart.old_pid", "rust_restart.new_pid", "rust_restart.old_pid_stopped", "rust_restart.same_datadir", "rust_restart.peer_reconnect_observed", "rust_restart.go_target_height", "rust_restart.catch_up_height"]),
    "partition_heal_reorg": ("partition_heal_reorg_report", "mixed_client_partition_heal_reorg", ["proof.partition_changed_peer_state", "proof.fork_diverged", "proof.heal_restored_peer_state", "proof.reorg_converged", "proof.process_identity_rechecked_after_heal", "proof.go_reorg_metrics", "observations.reorg"]),
}
def is_hex32(value: Any) -> bool: return isinstance(value, str) and bool(HEX32.fullmatch(value))  # noqa: E704
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
        if path.stat().st_size > MAX_JSON_BYTES:
            return None, "json_too_large"
        raw = path.read_bytes()
        return json.loads(raw.decode("utf-8"), object_pairs_hook=NO_DUPES, parse_constant=lambda c: (_ for _ in ()).throw(ValueError(f"non_finite_json_constant:{c}"))), None
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
        text = str(exc)
        return None, text if text.startswith(("non_finite_json_constant:", "duplicate_json_key")) else f"malformed_json:{exc.__class__.__name__}"
def regular_path(raw_path: str, reason: str) -> tuple[Path, str | None]: raw = Path(raw_path).expanduser(); canon = Path(os.path.realpath(raw)); return (canon, None) if raw.is_file() and not raw.is_symlink() else (canon, reason)  # noqa: E704, E702
def get(data: Any, dotted: str) -> tuple[Any, bool]:
    cur = data
    for part in dotted.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None, False
        cur = cur[part]
    return cur, True
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
def nodes(data: dict[str, Any], require_alive: bool = True) -> tuple[dict[str, dict[str, Any]] | None, str | None]:
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
        if not all(isinstance((v := node.get(k)), str) and (m := ENDPOINT.fullmatch(v)) is not None and 1 <= int(m.group(2)) <= 65535 for k in ("rpc_endpoint", "p2p_endpoint")):
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
        if not isinstance(elapsed, (int, float)) or isinstance(elapsed, bool) or elapsed < 0 or elapsed > 1_000_000_000 or (isinstance(elapsed, float) and not math.isfinite(elapsed)):
            return f"non_finite_{name}_sample:0"
        if name == "convergence" and (not jint(sample.get("height")) or sample.get("height") != height or sample.get("block_hash") != block_hash):
            return "convergence_sample_identity_mismatch"
    return None
def validate_tx(data: dict[str, Any], converge: bool, rust_submit: bool) -> str | None:
    _, bad = nodes(data)
    if bad:
        return bad
    tx_path = data.get("tx_path")
    if not isinstance(tx_path, dict) or set(tx_path) != {"submitted_at", "observed_at", "tx_id"} or not is_hex32(tx_path.get("tx_id")):
        return "tx_path_invalid"
    txid = tx_path["tx_id"]
    submit, accept, mine, conv, src, dst, prop, conv_dir = ("rust_submit", "go_accept", "go_mine", "rust_converge", "node-rust", "node-go", "rust->go", "go->rust") if rust_submit else ("go_submit", "rust_accept", "rust_mine", "go_converge", "node-go", "node-rust", "go->rust", "rust->go")
    if tx_path.get("submitted_at") != src or tx_path.get("observed_at") != [dst]:
        return "tx_path_direction_invalid"
    for label in (submit, accept):
        if not isinstance(data.get(label), dict) or set(data[label]) != {"txid"} or data[label].get("txid") != txid:
            return f"{label}_txid_mismatch"
    if not converge: return validate_samples(data, prop, None, txid)  # noqa: E701
    mined, seen = data.get(mine), data.get(conv)
    if not isinstance(mined, dict) or not isinstance(seen, dict) or set(mined) != {"txid", "height", "block_hash"} or set(seen) != {"txid", "height", "block_hash"} or mined.get("txid") != txid or seen.get("txid") != txid: return "convergence_identity_mismatch"  # noqa: E701
    if mined.get("height") != seen.get("height") or mined.get("block_hash") != seen.get("block_hash") or not jint(mined.get("height")) or not jint(seen.get("height")) or not is_hex32(mined.get("block_hash")): return "convergence_identity_mismatch"  # noqa: E701
    return validate_samples(data, prop, conv_dir, txid, mined["height"], mined["block_hash"])
def restart_contradiction(data: dict[str, Any]) -> str | None:
    if not isinstance(data.get("restart"), dict) or data["restart"].get("stopped_node") != "node-rust":
        return "wrong_role_identity"
    rr = data.get("rust_restart")
    if not isinstance(rr, dict):
        return "restart_source_binding_contradiction:malformed_source_fields" if "rust_restart" in data else None
    if any(k in rr and not isinstance(rr.get(k), bool) for k in ("old_pid_stopped", "same_datadir", "peer_reconnect_observed")) or any(k in rr and not jint(rr.get(k)) for k in ("old_pid", "new_pid", "go_target_height", "catch_up_height")):
        return "restart_source_binding_contradiction:malformed_source_fields"
    if rr.get("old_pid_stopped") is False:
        return "restart_source_binding_contradiction:old_pid_stopped_false"
    if rr.get("same_datadir") is False:
        return "restart_source_binding_contradiction:same_datadir_false"
    if rr.get("peer_reconnect_observed") is False:
        return "restart_source_binding_contradiction:peer_reconnect_not_observed"
    by_impl, bad = nodes(data, require_alive=False)
    if bad or by_impl is None:
        return bad or "process_identity_missing_or_invalid"
    old_pid, new_pid = rr.get("old_pid"), rr.get("new_pid")
    if jint(old_pid) and old_pid in {by_impl["go"]["pid"], by_impl["rust"]["pid"]}:
        return "restart_source_binding_contradiction:old_pid_aliases_live_node"
    if jint(new_pid) and new_pid != by_impl["rust"]["pid"]:
        return "restart_source_binding_contradiction:new_pid_not_final_rust_pid"
    target, caught, pre = rr.get("go_target_height"), rr.get("catch_up_height"), rr.get("pre_restart_height", data.get("restart", {}).get("pre_restart_height"))
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
    proof = data.get("proof")
    if not isinstance(proof, dict):
        return "partition_reorg_source_binding_contradiction:malformed_proof_fields" if "proof" in data else None
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
    _, bad = nodes(data, require_alive=False)
    return bad
def build_section(name: str, attr: str, scenario: str, fields: list[str], args: argparse.Namespace) -> tuple[dict[str, Any], dict[str, Any] | None]:
    raw_path = getattr(args, attr)
    if not raw_path:
        return section(name, "no_data", f"{name}_artifact_missing", source_fields=fields), None
    path, path_err = regular_path(raw_path, "source_artifact_not_regular")
    if path_err:
        return section(name, "fail", path_err, source_artifact_path=path, source_fields=fields), None
    data, err = load(path)
    if err or not isinstance(data, dict):
        return section(name, "fail", err or "root_not_object", source_artifact_path=path), None
    try: bad, bad_marker = nonfinite(data), BAD_MARKER(data)
    except RecursionError: return section(name, "fail", "malformed_json:RecursionError", source_artifact_path=path), data  # noqa: E701
    if bad:
        return section(name, "fail", bad, source_artifact_path=path, scenario=data.get("scenario")), data
    got = data.get("scenario")
    if got != scenario:
        helper = scenario_reject(got)
        return section(name, "helper_only" if helper and helper.startswith("helper") else "fail", helper or "unsupported_scenario", source_artifact_path=path, scenario=got, source_fields=fields), data
    if data.get("verdict") != "PASS" or bad_marker:
        return section(name, "fail", "source_verdict_not_pass" if data.get("verdict") != "PASS" else "pass_artifact_contains_failure_fields", source_artifact_path=path, scenario=got), data
    missing = [f for f in fields if not get(data, f)[1]]
    malformed = "legacy_schema_compatibility.marker_path" if name == "mesh" and get(data, "legacy_schema_compatibility.marker_path")[1] and (not isinstance(get(data, "legacy_schema_compatibility.marker_path")[0], str) or not get(data, "legacy_schema_compatibility.marker_path")[0] or regular_path(get(data, "legacy_schema_compatibility.marker_path")[0], "legacy_schema_marker_not_regular")[1]) else "observations.reorg" if name == "partition_heal_reorg" and get(data, "observations.reorg")[1] and not isinstance(get(data, "observations.reorg")[0], dict) else None
    if malformed:
        return section(name, "fail", "malformed_source_fields:" + malformed, source_artifact_path=path, scenario=got), data
    if name in {"rust_restart", "partition_heal_reorg"}:
        bad = restart_contradiction(data) if name == "rust_restart" else partition_contradiction(data)
        if bad:
            return section(name, "fail", bad, source_artifact_path=path, scenario=got), data
        base = "restart_source_binding_unproven" if name == "rust_restart" else "partition_reorg_source_binding_unproven"
        reason = base if not missing else f"{base}:missing_source_fields:{','.join(missing)}"
        return section(name, "no_data", reason, source_artifact_path=path, scenario=got, source_fields=fields, claim_type="structural_only", evidence_class="structural_only", behavior_evidence=False), data
    if missing:
        return section(name, "fail", "missing_source_fields:" + ",".join(missing), source_artifact_path=path, scenario=got), data
    bad = validate_mesh(data) if name == "mesh" else validate_tx(data, "converge" in name, name.startswith("rust_to_go"))
    if bad:
        return section(name, "fail", bad, source_artifact_path=path, scenario=got), data
    return section(name, "no_data", "source_contract_validation_unavailable", source_artifact_path=path, scenario=got, source_fields=fields, claim_type="structural_only", evidence_class="structural_only", behavior_evidence=False), data
def parse_metrics(path: Path) -> tuple[dict[str, int] | None, str | None]:
    try:
        if path.stat().st_size > MAX_JSON_BYTES:
            return None, "metrics_too_large"
        raw = path.read_bytes()
        text = raw.decode("utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        return None, f"read_failed:{exc.__class__.__name__}"
    try:
        found: dict[str, int] = {}
        if text.lstrip().startswith("{"):
            obj = json.loads(text, object_pairs_hook=NO_DUPES, parse_constant=lambda c: (_ for _ in ()).throw(ValueError(f"non_finite_json_constant:{c}")))
            if not isinstance(obj, dict):
                return None, "metrics_malformed"
            for metric in METRICS:
                if isinstance((v := obj.get(metric)), bool) or not isinstance(v, (int, float)) or (isinstance(v, float) and not math.isfinite(v)) or v <= 0 or v > 1_000_000_000 or int(v) != v:
                    return None, "metric_value_invalid"
                found[metric] = int(v)
        else:
            for line in text.splitlines():
                parts = line.split()
                if parts and parts[0].split("{", 1)[0] in METRICS and (len(parts) not in {2, 3} or "{" in parts[0] or (len(parts) == 3 and not re.fullmatch(r"[0-9]+(?:\.0*)?(?:[eE][+]?\d+)?", parts[2]))):
                    return None, "metrics_malformed"
                if len(parts) in {2, 3} and (metric := parts[0].split("{", 1)[0]) in METRICS:
                    if metric in found or not re.fullmatch(r"[0-9]+(?:\.0*)?(?:[eE][+]?\d+)?", parts[1]) or not math.isfinite(float(parts[1])) or float(parts[1]) <= 0 or float(parts[1]) > 1_000_000_000 or int(float(parts[1])) != float(parts[1]):
                        return None, "metrics_duplicate" if metric in found else "metric_value_invalid"
                    found[metric] = int(float(parts[1]))
    except (json.JSONDecodeError, TypeError, ValueError, RecursionError) as exc:
        return None, str(exc) if str(exc).startswith("duplicate_json_key") else "metrics_malformed"
    return (found, None) if all(found.get(m, 0) > 0 for m in METRICS) else (None, "metrics_missing_or_zero")
def metric_section(args: argparse.Namespace) -> dict[str, Any]:
    if args.rust_reorg_metrics_no_data:
        return section("reorg_metrics", "no_data", "rust_reorg_metrics_no_data", source_reason=args.rust_reorg_metrics_no_data, claim_type="metric_evidence")
    if not args.rust_reorg_metrics:
        return section("reorg_metrics", "no_data", "rust_reorg_metrics_missing", claim_type="metric_evidence")
    path, path_err = regular_path(args.rust_reorg_metrics, "metrics_not_regular")
    metrics, err = (None, path_err) if path_err else parse_metrics(path)
    return section("reorg_metrics", "fail", err, source_artifact_path=path, claim_type="metric_evidence") if err else section("reorg_metrics", "no_data", "metric_source_binding_unavailable", source_artifact_path=path, source_fields=sorted(METRICS), claim_type="metric_evidence", metric_values=metrics)
def raw_samples_section(sections: dict[str, dict[str, Any]]) -> dict[str, Any]: return section("raw_samples", "fail", "source_sample_section_failed") if any(sections[name]["status"] in {"fail", "helper_only"} for name in ("go_to_rust_accept", "go_to_rust_mine_converge", "rust_to_go_mine_converge")) else section("raw_samples", "no_data", "source_contract_validation_unavailable", source_fields=["raw_samples.propagation", "raw_samples.convergence"], claim_type="sample_evidence")  # noqa: E704
def inventory(sections: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    out = []
    for name, sec in sections.items():
        tokens = {sec["status"]}
        tokens |= {"converge", "convergence"} if "converge" in name else set()
        tokens |= {"reorg"} if "reorg" in name else set()
        tokens |= {"restart"} if "restart" in name else set()
        tokens |= {"metric"} if "metric" in name else set()
        tokens |= {"not_applicable"} if name == "deferred_related" else set()
        out.extend({"token": t, "section": name, "source_artifact_path": sec.get("source_artifact_path"), "source_fields": sec.get("source_fields", []), "claim_type": sec.get("claim_type", "status_evidence")} for t in sorted(tokens))
    return out
def generate(args: argparse.Namespace) -> tuple[dict[str, Any], int]:
    sections = {name: build_section(name, attr, scenario, fields, args)[0] for name, (attr, scenario, fields) in SECTIONS.items()}
    sections["reorg_metrics"] = metric_section(args)
    sections["raw_samples"] = raw_samples_section(sections)
    sections["deferred_related"] = section("deferred_related", "not_applicable", "deferred_by_rub_227", claim_type="deferred_related_work")
    statuses = {s["status"] for s in sections.values()}
    verdict = "FAIL" if statuses & {"fail", "helper_only"} else "NO_DATA" if "no_data" in statuses else "PASS"
    inputs = {k: (v if k.endswith("_no_data") else str(Path(os.path.realpath(Path(v).expanduser())))) for k, v in vars(args).items() if k != "output" and v is not None}
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
def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate fail-closed mixed-client devnet soak report v2.")
    for opt, dest in (("--mesh-report", "mesh_report"), ("--go-submit-rust-accept-report", "go_submit_rust_accept_report"), ("--go-submit-rust-mine-go-converge-report", "go_submit_rust_mine_go_converge_report"), ("--rust-submit-go-mine-rust-converge-report", "rust_submit_go_mine_rust_converge_report"), ("--rust-restart-report", "rust_restart_report"), ("--partition-heal-reorg-report", "partition_heal_reorg_report")):
        parser.add_argument(opt, dest=dest)
    metrics = parser.add_mutually_exclusive_group()
    metrics.add_argument("--rust-reorg-metrics")
    metrics.add_argument("--rust-reorg-metrics-no-data")
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    out_path = Path(os.path.realpath(Path(args.output).expanduser()))
    if any(v and not k.endswith("_no_data") and (Path(os.path.realpath(Path(v).expanduser())) == out_path or (not regular_path(v, "nonregular")[1] and isinstance((d := load(Path(os.path.realpath(Path(v).expanduser())))[0]), dict) and isinstance((m := get(d, "legacy_schema_compatibility.marker_path")[0]), str) and Path(os.path.realpath(Path(m).expanduser())) == out_path)) for k, v in vars(args).items() if k != "output"):
        return print("FAIL: output_overwrites_input", file=sys.stderr) or 1
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
