#!/usr/bin/env python3
# ruff: noqa: E302,E305,E401,E701
from __future__ import annotations
import argparse, json, math, os, re, shlex, subprocess, sys, tempfile  # nosec B404
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path
from typing import Any
SCHEMA_VERSION = "rubin-mixed-client-devnet-soak-report-v2"; MAX_JSON_BYTES = 1_000_000; MAX_PARSER_OUTPUT_BYTES = 100_000; MAX_TX_HEX_CHARS = 20_000  # noqa: E702
REPO_ROOT = Path(__file__).resolve().parents[2]; DEV_ENV = REPO_ROOT / "scripts" / "dev-env.sh"; GO_MODULE_ROOT = REPO_ROOT / "clients" / "go"  # noqa: E702
HEX32 = re.compile(r"[0-9a-f]{64}"); HEX_BYTES = re.compile(r"(?:[0-9a-f]{2})+"); ENDPOINT = re.compile(r"([0-9A-Za-z._-]+):([0-9]{1,5})")  # noqa: E702
BLOCK_REASON_PREFIX = "RUBIN_BLOCK_CHECK_REASON:"
METRICS = ("rubin_node_reorg_total", "rubin_node_last_reorg_depth"); NUM = r"[0-9]+(?:\.0*)?(?:[eE][+]?\d+)?"; METRIC_LINE = re.compile(rf"^({'|'.join(METRICS)})\s+({NUM})(?:\s+({NUM}))?\s*$"); STRICT_METRIC_LINE = re.compile(rf"^({'|'.join(METRICS)})\s+([0-9]+)(?:\.0*)?\s*$"); NO_DUPES = lambda pairs: dict(pairs) if len({k for k, _ in pairs}) == len(pairs) else (_ for _ in ()).throw(ValueError("duplicate_json_key")); BAD_MARKER = lambda value: any(k == "schema_marker" or k.startswith("failure_") or BAD_MARKER(v) for k, v in value.items()) if isinstance(value, dict) else any(BAD_MARKER(v) for v in value) if isinstance(value, list) else False  # noqa: E702, E731
SAFE_REASON = re.compile(r"[a-z0-9_:-]{1,160}"); CLAIM_REASON_TOKENS = {"ready", "pass", "parity", "converge", "convergence", "reorg", "restart", "metric", "fail", "no_data", "not_applicable", "helper_only"}  # noqa: E702
PATH_FIELD_NAMES = {"marker_path", "get_tx_path", "tx_status_path", "block_path", "mine_next_path", "tip_path", "go_tip_block", "rust_tip_block", "binary", "datadir"}; DIRECTORY_PATH_FIELD_NAMES = {"datadir"}  # noqa: E702
PATH_FIELD_DOTTED_NAMES = {
    "observations.pre_partition.common_go_block", "observations.pre_partition.common_go_mine", "observations.pre_partition.common_rust_block", "observations.pre_partition.common_rust_tip", "observations.pre_partition.go_peer_snapshot", "observations.pre_partition.rust_peer_snapshot",
    "observations.partition.go_peer_snapshot", "observations.partition.rust_peer_snapshot", "observations.fork.go_block", "observations.fork.go_mine", "observations.fork.go_peer_snapshot", "observations.fork.go_tip", "observations.fork.rust_block_1", "observations.fork.rust_block_2", "observations.fork.rust_mine_1", "observations.fork.rust_mine_2", "observations.fork.rust_peer_snapshot", "observations.fork.rust_tip",
    "observations.heal.go_peer_snapshot", "observations.heal.rust_peer_snapshot", "observations.reorg.go_metrics", "observations.reorg.go_reorg_parent_block", "observations.reorg.go_tip", "observations.reorg.go_tip_block", "observations.reorg.rust_tip", "observations.reorg.rust_tip_block",
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
RESTART_OBJECT_KEYS = {"catch_up_has_tip", "catch_up_height", "catch_up_tip", "catch_up_tip_path", "datadir", "go_target_has_tip", "go_target_height", "go_target_mine_next_path", "go_target_tip", "go_target_tip_path", "go_target_tx_count", "new_command_argv", "new_p2p_endpoint", "new_pid", "new_rpc_endpoint", "new_started_at", "old_command_argv", "old_p2p_endpoint", "old_pid", "old_pid_stopped", "old_rpc_endpoint", "old_started_at", "peer_reconnect_observed", "pre_restart_has_tip", "pre_restart_height", "pre_restart_tip", "pre_restart_tip_path", "same_datadir"}
RESTART_SUMMARY_KEYS = {"catch_up_height", "pre_restart_height", "stopped_node"}
RESTART_SOURCE_FIELDS = ["run_id", "restart.stopped_node", "restart.pre_restart_height", "restart.catch_up_height"] + [f"rust_restart.{key}" for key in sorted(RESTART_OBJECT_KEYS)]
RESTART_TOP_KEYS = {"artifact_created_at_utc", "artifact_root", "final_verification", "legacy_schema_compatibility", "nodes", "peer_connectivity", "raw_samples", "restart", "run_id", "rust_restart", "scenario", "verdict"}
RESTART_FINAL_KEYS = {"peer_snapshots_rechecked", "process_identity_rechecked", "producer_side", "rust_outbound_link_rechecked", "rust_outbound_local_addr", "rust_outbound_pid", "rust_outbound_remote_addr"}
RESTART_LINK_KEYS = {"go_peer_snapshot_expected_addr", "rust_outbound_local_addr", "rust_outbound_pid", "rust_outbound_remote_addr", "rust_peer_snapshot_expected_addr"}
RESTART_PEER_KEYS = {"bidirectional_observed", "counterpart_links", "go_peer_snapshot", "go_to_rust", "rust_peer_snapshot", "rust_to_go"}
RESTART_MARKER_SCHEMA_VERSION = "rubin-mixed-client-devnet-evidence-v1"; RESTART_MARKER_PARTICIPANT_KEYS = {"endpoint", "implementation", "name", "started_at"}  # noqa: E702
RESTART_SNAPSHOT_KEYS = {"count", "peers"}; RESTART_PEER_ENTRY_KEYS = {"addr", "handshake_complete"}  # noqa: E702
NODE_OBJECT_KEYS = {"binary", "command", "command_argv", "implementation", "name", "p2p_endpoint", "pid", "process_alive", "process_comm", "rpc_endpoint", "started_at"}
NODE_BACKING_KEYS = {"p2p_endpoint_process_backed", "rpc_endpoint_process_backed"}
PARTITION_NODE_KEYS = {"implementation", "name", "p2p_endpoint", "pid", "rpc_endpoint", "started_at"}
PARTITION_TOP_KEYS = {"artifact_created_at_utc", "artifact_root", "final_verification", "legacy_schema_compatibility", "nodes", "observations", "peer_connectivity", "proof", "raw_samples", "run_id", "scenario", "verdict"}
PARTITION_LEGACY_PURPOSE = "schema-valid legacy artifact only; not the partition/heal/reorg report verdict"
PARTITION_LEGACY_REASON = "existing mixed_client_evidence_v1 PASS requires tx_path; partition/heal/reorg PASS lives in this report"
PARTITION_SOURCE_FIELDS = [
    "run_id", "artifact_created_at_utc",
    "proof.partition_proxy_endpoint", "proof.pre_partition_go_peer_addr", "proof.heal_go_peer_addr",
    "proof.partition_changed_peer_state", "proof.fork_diverged", "proof.heal_restored_peer_state", "proof.reorg_converged", "proof.process_identity_rechecked_after_heal", "proof.go_reorg_metrics",
    "proof.go_partition_tip", "proof.rust_winning_tip", "proof.final_go_tip", "proof.final_rust_tip",
    "observations.pre_partition.common_go_block", "observations.pre_partition.common_go_mine", "observations.pre_partition.common_rust_block", "observations.pre_partition.common_rust_tip", "observations.pre_partition.go_peer_snapshot", "observations.pre_partition.rust_peer_snapshot",
    "observations.partition.go_peer_snapshot", "observations.partition.rust_peer_snapshot",
    "observations.fork.go_block", "observations.fork.go_mine", "observations.fork.go_peer_snapshot", "observations.fork.go_tip", "observations.fork.rust_block_1", "observations.fork.rust_block_2", "observations.fork.rust_mine_1", "observations.fork.rust_mine_2", "observations.fork.rust_peer_snapshot", "observations.fork.rust_tip",
    "observations.heal.go_peer_snapshot", "observations.heal.rust_peer_snapshot",
    "observations.reorg.go_metrics", "observations.reorg.go_reorg_parent_block", "observations.reorg.go_tip", "observations.reorg.go_tip_block", "observations.reorg.rust_tip", "observations.reorg.rust_tip_block",
]
PARTITION_PASS_CONTRACT_FIELDS = ["legacy_schema_compatibility.marker_path", "nodes", "raw_samples.propagation", "raw_samples.convergence"]
SECTIONS = {
    "mesh": ("mesh_report", "mixed_client_mesh", ["nodes", "peer_connectivity", "final_verification", "legacy_schema_compatibility.marker_path", "raw_samples.propagation", "raw_samples.convergence"]),
    "go_to_rust_accept": ("go_submit_rust_accept_report", "mixed_client_go_submit_rust_accept", ["go_submit", "rust_accept", "tx_path", "raw_samples.propagation"]),
    "go_to_rust_mine_converge": ("go_submit_rust_mine_go_converge_report", "mixed_client_go_submit_rust_mine_go_converge", ["go_submit", "rust_accept", "rust_mine", "go_converge", "tx_path", "raw_samples.propagation", "raw_samples.convergence"]),
    "rust_to_go_mine_converge": ("rust_submit_go_mine_rust_converge_report", "mixed_client_rust_submit_go_mine_rust_converge", ["rust_submit", "go_accept", "go_mine", "rust_converge", "tx_path", "raw_samples.propagation", "raw_samples.convergence"]),
    "rust_restart": ("rust_restart_report", "mixed_client_rust_restart", RESTART_SOURCE_FIELDS),
    "partition_heal_reorg": ("partition_heal_reorg_report", "mixed_client_partition_heal_reorg", PARTITION_SOURCE_FIELDS),
}
SOURCE_BASE_TOP_KEYS = {"artifact_root", "final_verification", "legacy_schema_compatibility", "nodes", "peer_connectivity", "raw_samples", "scenario", "verdict"}
SOURCE_TOP_KEYS = {
    "mesh": SOURCE_BASE_TOP_KEYS,
    "go_to_rust_accept": SOURCE_BASE_TOP_KEYS | {"go_submit", "rust_accept", "tx_path"},
    "go_to_rust_mine_converge": SOURCE_BASE_TOP_KEYS | {"go_submit", "go_converge", "rust_accept", "rust_mine", "tx_path"},
    "rust_to_go_mine_converge": SOURCE_BASE_TOP_KEYS | {"go_accept", "go_mine", "rust_converge", "rust_submit", "tx_path"},
}
SOURCE_PEER_KEYS = {"bidirectional_observed", "counterpart_links", "go_peer_snapshot", "go_to_rust", "rust_peer_snapshot", "rust_to_go"}
SOURCE_LINK_KEYS = {"go_peer_snapshot_expected_addr", "rust_outbound_local_addr", "rust_outbound_pid", "rust_outbound_remote_addr", "rust_peer_snapshot_expected_addr"}
SOURCE_LEGACY_PURPOSE = "schema-valid legacy artifact only; not the mesh report verdict"
SOURCE_LEGACY_REASON = "existing mixed_client_evidence_v1 PASS requires tx_path; mesh process/connectivity PASS lives in this report"
SOURCE_LEGACY_REASONS = {SOURCE_LEGACY_REASON, "existing mixed_client_evidence_v1 PASS requires tx_path"}
SOURCE_MESH_MARKER_KEYS = {"evidence_type", "failure_reason", "participants", "scenario", "schema_version", "verdict"}
SOURCE_TX_MARKER_KEYS = {"evidence_type", "participants", "scenario", "schema_version", "tx_path", "verdict"}
BLOCK_INCLUSION_GO = r'''
package main
import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)
const reasonPrefix = "RUBIN_BLOCK_CHECK_REASON:"
type blockResp struct { Hash string `json:"hash"`; Height uint64 `json:"height"`; Canonical bool `json:"canonical"`; BlockHex string `json:"block_hex"` }
type request struct { Block blockResp `json:"block"`; TxHex string `json:"tx_hex"`; Txid string `json:"txid"`; Height uint64 `json:"height"`; Hash string `json:"hash"`; TxCount uint64 `json:"tx_count"` }
func die(reason string, detail any) {
	text := fmt.Sprint(detail)
	if strings.HasPrefix(text, reasonPrefix) { text = "detail:" + text }
	fmt.Fprintln(os.Stderr, reasonPrefix + reason)
	fmt.Fprintln(os.Stderr, text)
	os.Exit(1)
}
func main() {
	var req request
	if err := json.NewDecoder(os.Stdin).Decode(&req); err != nil { die("convergence_block_parser_malformed_input", err) }
	if req.Block.Height != req.Height || strings.ToLower(req.Block.Hash) != strings.ToLower(req.Hash) || !req.Block.Canonical { die("convergence_block_sidecar_mismatch", "block response height/hash/canonical mismatch") }
	txBytes, err := hex.DecodeString(strings.TrimSpace(req.TxHex)); if err != nil { die("convergence_tx_hex_parse_failed", err) }
	_, wantTxid, wantWtxid, consumed, err := consensus.ParseTx(txBytes); if err != nil || consumed != len(txBytes) { die("convergence_tx_hex_parse_failed", "parse tx_hex failed") }
	if hex.EncodeToString(wantTxid[:]) != strings.ToLower(req.Txid) { die("convergence_tx_hex_txid_mismatch", "tx_hex txid mismatch") }
	blockBytes, err := hex.DecodeString(strings.TrimSpace(req.Block.BlockHex)); if err != nil { die("convergence_block_hex_parse_failed", err) }
	pb, err := consensus.ParseBlockBytes(blockBytes); if err != nil { die("convergence_block_hex_parse_failed", err) }
	gotHash, err := consensus.BlockHash(pb.HeaderBytes); if err != nil || hex.EncodeToString(gotHash[:]) != strings.ToLower(req.Hash) { die("convergence_block_hash_mismatch", "parsed block hash mismatch") }
	if pb.TxCount != req.TxCount { die("convergence_block_tx_count_mismatch", "parsed block tx_count mismatch") }
	if _, err := consensus.ValidateBlockBasicAtHeight(blockBytes, nil, nil, req.Height); err != nil { die("convergence_block_basic_validation_failed", err) }
	for i, got := range pb.Txids { if i > 0 && got == wantTxid && pb.Wtxids[i] == wantWtxid { return } }
	die("convergence_block_missing_submitted_txid", "submitted txid/wtxid missing from parsed block")
}
'''
_BLOCK_HELPER_DIR: tempfile.TemporaryDirectory[str] | None = None
_BLOCK_HELPER_BIN: Path | None = None
_BLOCK_HELPER_ERR: str | None = None
def is_hex32(value: Any) -> bool: return isinstance(value, str) and bool(HEX32.fullmatch(value))  # noqa: E704
def hex_bytes(value: Any) -> bool: return isinstance(value, str) and bool(HEX_BYTES.fullmatch(value))  # noqa: E704
def jint(value: Any, minimum: int = 0) -> bool: return isinstance(value, int) and not isinstance(value, bool) and minimum <= value <= 1_000_000_000  # noqa: E704
def ju64(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 18_446_744_073_709_551_615
def endpoint(value: Any) -> bool:
    return isinstance(value, str) and (m := ENDPOINT.fullmatch(value)) is not None and 1 <= int(m.group(2)) <= 65535
def utc_z(value: Any) -> bool:
    if not isinstance(value, str) or len(value) != 20 or value[-1] != "Z":
        return False
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").strftime("%Y-%m-%dT%H:%M:%SZ") == value
    except ValueError:
        return False
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
def regular_abs_path(raw_path: str, reason: str) -> tuple[Path, str | None]:
    raw = Path(os.path.expanduser(raw_path)); canon = Path(os.path.realpath(raw))  # noqa: E702
    return (canon, None) if raw.is_absolute() and raw.is_file() and not raw.is_symlink() else (canon, reason)
def safe_abs_path(value: Any) -> Path | None:
    if not isinstance(value, str) or value.strip() != value or not value or value[0] in "'\"" or value[-1] in "'\"" or "\0" in value or any(ord(c) < 32 for c in value):
        return None
    raw = Path(value)
    if not raw.is_absolute():
        return None
    try:
        return Path(os.path.realpath(raw))
    except (OSError, ValueError):
        return None
def str_list(value: Any) -> bool: return isinstance(value, list) and all(isinstance(item, str) for item in value)  # noqa: E704
def command_bound_to_argv(node: dict[str, Any]) -> bool:
    argv, command = node.get("command_argv"), node.get("command")
    if not str_list(argv) or not isinstance(command, str) or not command:
        return False
    try:
        return shlex.split(command) == argv
    except ValueError:
        return False
def same_arg_path(left: str, right: str) -> bool:
    try:
        return Path(os.path.realpath(os.path.expanduser(left))) == Path(os.path.realpath(os.path.expanduser(right)))
    except (OSError, ValueError):
        return False
def argv_eq(actual: Any, expected: Any, path_indexes: set[int]) -> bool:
    return str_list(actual) and str_list(expected) and len(actual) == len(expected) and all(same_arg_path(actual[i], expected[i]) if i in path_indexes else actual[i] == expected[i] for i in range(len(expected)))
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
    expected_node_keys = NODE_OBJECT_KEYS | NODE_BACKING_KEYS if require_backing else PARTITION_NODE_KEYS
    allowed_node_key_sets = {frozenset(expected_node_keys)} if require_alive else {frozenset(expected_node_keys), frozenset(expected_node_keys - {"process_alive"})}
    if not require_backing:
        full_keys = NODE_OBJECT_KEYS | NODE_BACKING_KEYS
        allowed_node_key_sets |= {frozenset(full_keys), frozenset(full_keys - {"process_alive"})}
    for name, impl in (("node-go", "go"), ("node-rust", "rust")):
        node = by_name[name]
        if frozenset(node) not in allowed_node_key_sets:
            return None, "process_identity_missing_or_invalid"
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
def source_peer_final_error(data: dict[str, Any]) -> str | None:
    by_impl, node_bad = nodes(data)
    if node_bad or by_impl is None:
        return node_bad
    peer, final = data.get("peer_connectivity"), data.get("final_verification")
    if not isinstance(peer, dict) or set(peer) != SOURCE_PEER_KEYS or any(peer.get(k) is not True for k in ("go_to_rust", "rust_to_go", "bidirectional_observed")):
        return "peer_connectivity_invalid"
    links = peer.get("counterpart_links")
    if not isinstance(links, dict) or set(links) != SOURCE_LINK_KEYS:
        return "peer_connectivity_invalid"
    if not all(endpoint(links.get(k)) for k in ("go_peer_snapshot_expected_addr", "rust_peer_snapshot_expected_addr", "rust_outbound_local_addr", "rust_outbound_remote_addr")):
        return "peer_connectivity_invalid"
    go_expected, rust_expected = links["go_peer_snapshot_expected_addr"], links["rust_peer_snapshot_expected_addr"]
    if rust_expected != by_impl["go"]["p2p_endpoint"] or links.get("rust_outbound_remote_addr") != rust_expected or links.get("rust_outbound_local_addr") != go_expected or links.get("rust_outbound_pid") != by_impl["rust"]["pid"]:
        return "peer_connectivity_invalid"
    if go_expected in {rust_expected, by_impl["rust"]["p2p_endpoint"], by_impl["go"]["rpc_endpoint"], by_impl["rust"]["rpc_endpoint"]}:
        return "peer_connectivity_invalid"
    for snapshot_name, expected in (("go_peer_snapshot", go_expected), ("rust_peer_snapshot", rust_expected)):
        snapshot = peer.get(snapshot_name)
        peers = snapshot.get("peers") if isinstance(snapshot, dict) else None
        if not isinstance(snapshot, dict) or set(snapshot) != RESTART_SNAPSHOT_KEYS or not isinstance(peers, list) or not jint(snapshot.get("count")) or len(peers) != snapshot["count"]:
            return "peer_connectivity_invalid"
        if len(peers) != 1 or any(not isinstance(item, dict) or set(item) != RESTART_PEER_ENTRY_KEYS or item.get("addr") != expected or item.get("handshake_complete") is not True for item in peers):
            return "peer_connectivity_invalid"
    if not isinstance(final, dict) or set(final) != RESTART_FINAL_KEYS or any(final.get(k) is not True for k in ("producer_side", "process_identity_rechecked", "rust_outbound_link_rechecked", "peer_snapshots_rechecked")):
        return "final_verification_invalid"
    return None if final.get("rust_outbound_pid") == by_impl["rust"]["pid"] and final.get("rust_outbound_local_addr") == go_expected and final.get("rust_outbound_remote_addr") == rust_expected else "final_verification_invalid"
def marker_participants_bound(marker: dict[str, Any], by_impl: dict[str, dict[str, Any]]) -> bool:
    participants = marker.get("participants")
    if not isinstance(participants, list) or len(participants) != 2 or any(not isinstance(p, dict) or set(p) != RESTART_MARKER_PARTICIPANT_KEYS or not all(isinstance(p.get(k), str) for k in RESTART_MARKER_PARTICIPANT_KEYS) for p in participants):
        return False
    expected = sorted((node["name"], impl, node["rpc_endpoint"], node["started_at"]) for impl, node in by_impl.items())
    return sorted((p["name"], p["implementation"], p["endpoint"], p["started_at"]) for p in participants) == expected
def source_node_identity_error(by_impl: dict[str, dict[str, Any]], root: Path) -> str | None:
    for impl, expected_name, expected_comm in (("go", "node-go", "rubin-node-go"), ("rust", "node-rust", "rubin-node-rust")):
        node = by_impl[impl]
        if node.get("name") != expected_name or node.get("process_comm") != expected_comm or not jint(node.get("pid"), 1) or not utc_z(node.get("started_at")) or not command_bound_to_argv(node):
            return "process_identity_missing_or_invalid"
        binary = safe_abs_path(node.get("binary"))
        if binary is None or binary.name != expected_comm or not binary.is_file() or not os.access(binary, os.X_OK):
            return "process_identity_missing_or_invalid"
        try:
            binary.relative_to(root)
        except ValueError:
            return "process_identity_missing_or_invalid"
        expected_argv = [str(binary), "--network", "devnet", "--datadir", str(root / f"node-{impl}"), "--bind", "127.0.0.1:0", "--rpc-bind", "127.0.0.1:0"] + (["--peer", by_impl["go"]["p2p_endpoint"]] if impl == "rust" else [])
        if not argv_eq(node.get("command_argv"), expected_argv, {0, 4}):
            return "process_identity_missing_or_invalid"
    return None
def source_report_contract_error(name: str, data: dict[str, Any], path: Path) -> str | None:
    if set(data) != SOURCE_TOP_KEYS[name]:
        return f"{name}_top_level_fields_invalid"
    root = safe_abs_path(data.get("artifact_root"))
    if root is None or not root.is_dir():
        return f"{name}_artifact_root_invalid"
    try:
        Path(os.path.realpath(path)).relative_to(root)
    except ValueError:
        return f"{name}_artifact_root_invalid"
    if bad := source_peer_final_error(data):
        return bad
    legacy = data.get("legacy_schema_compatibility")
    marker_raw = legacy.get("marker_path") if isinstance(legacy, dict) else None
    if not isinstance(legacy, dict) or set(legacy) != {"authoritative", "marker_path", "purpose", "reason"} or legacy.get("authoritative") is not False or not isinstance(marker_raw, str) or not marker_raw:
        return f"{name}_legacy_marker_invalid"
    if legacy.get("purpose") != SOURCE_LEGACY_PURPOSE or legacy.get("reason") not in SOURCE_LEGACY_REASONS:
        return f"{name}_legacy_marker_invalid"
    marker_path = str(Path(os.path.expanduser(marker_raw)) if Path(os.path.expanduser(marker_raw)).is_absolute() else path.parent / marker_raw)
    marker_canon, marker_err = regular_path(marker_path, "legacy_schema_marker_not_regular")
    try:
        marker_canon.relative_to(root)
    except ValueError:
        marker_err = marker_err or "legacy_schema_marker_not_bound"
    marker = None
    if marker_err is None:
        marker, marker_err = load(marker_canon)
    by_impl, node_bad = nodes(data)
    if marker_err or not isinstance(marker, dict):
        return f"{name}_legacy_marker_invalid"
    if node_bad or by_impl is None:
        return node_bad
    if bad := source_node_identity_error(by_impl, root):
        return bad
    marker_keys = SOURCE_MESH_MARKER_KEYS if name == "mesh" else SOURCE_TX_MARKER_KEYS
    if set(marker) != marker_keys:
        return f"{name}_legacy_marker_invalid"
    if not marker_participants_bound(marker, by_impl):
        return f"{name}_legacy_marker_invalid"
    if marker.get("schema_version") != RESTART_MARKER_SCHEMA_VERSION or marker.get("scenario") != "mixed_client_mesh_schema_marker" or marker.get("evidence_type") != "mixed_client_process_soak":
        return f"{name}_legacy_marker_invalid"
    if name == "mesh":
        return None if marker.get("verdict") == "FAIL" and isinstance(marker.get("failure_reason"), str) and marker["failure_reason"] else f"{name}_legacy_marker_invalid"
    return None if marker.get("verdict") == "PASS" and marker.get("tx_path") == data.get("tx_path") else f"{name}_legacy_marker_invalid"
def source_artifact(path_value: Any, root: Path, reason: str) -> tuple[Path | None, str | None]:
    p, err = regular_abs_path(path_value, reason) if isinstance(path_value, str) else (None, reason)
    if err or p is None:
        return None, reason
    try:
        p.relative_to(root)
    except ValueError:
        return None, reason
    return p, None
def source_load_json(path_value: Any, root: Path, reason: str) -> tuple[dict[str, Any] | None, Path | None, str | None]:
    p, err = source_artifact(path_value, root, reason)
    data, load_err = (None, err) if err else load(p)  # type: ignore[arg-type]
    return (data, p, None) if load_err is None and isinstance(data, dict) else (None, p, reason)
def source_load_json_detailed(path_value: Any, root: Path, path_reason: str, nonobject_reason: str) -> tuple[dict[str, Any] | None, Path | None, str | None]:
    p, err = source_artifact(path_value, root, path_reason)
    if err or p is None:
        return None, p, path_reason
    data, load_err = load(p)
    if load_err:
        return None, p, load_err
    return (data, p, None) if isinstance(data, dict) else (None, p, nonobject_reason)
def tx_capture_sidecar_error(label: str, obj: dict[str, Any], impl: str, endpoint: str, root: Path, txid: str, txhex: str) -> tuple[list[Path], str | None]:
    status, status_path, err = source_load_json(obj.get("tx_status_path"), root, f"{label}_sidecar_invalid")
    got, get_path, get_err = source_load_json(obj.get("get_tx_path"), root, f"{label}_sidecar_invalid")
    if err or get_err or status is None or got is None or status_path is None or get_path is None:
        return [], f"{label}_sidecar_invalid"
    if set(status) != {"implementation", "request_path", "rpc_endpoint", "status", "txid"} or status.get("implementation") != impl or status.get("rpc_endpoint") != endpoint or status.get("request_path") != f"/tx_status?txid={txid}" or status.get("status") != "pending" or status.get("txid") != txid:
        return [], f"{label}_sidecar_invalid"
    if set(got) != {"found", "implementation", "raw_hex", "request_path", "rpc_endpoint", "txid"} or got.get("implementation") != impl or got.get("rpc_endpoint") != endpoint or got.get("request_path") != f"/get_tx?txid={txid}" or got.get("found") is not True or got.get("txid") != txid or got.get("raw_hex") != txhex:
        return [], f"{label}_sidecar_invalid"
    return [status_path, get_path], None
def consensus_cli(request_obj: dict[str, Any], reason_prefix: str) -> tuple[dict[str, Any] | None, str | None]:
    if not DEV_ENV.is_file() or not GO_MODULE_ROOT.is_dir():
        return None, f"{reason_prefix}_parser_unavailable"
    try:
        proc = subprocess.run(  # nosec B603
            [str(DEV_ENV), "--", "go", "-C", str(GO_MODULE_ROOT), "run", "./cmd/rubin-consensus-cli"],
            check=False,
            env={**os.environ, "RUBIN_OPENSSL_SKIP_FIPS_GUARD": "1"},
            input=json.dumps(request_obj) + "\n",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=60,
        )
    except subprocess.TimeoutExpired:
        return None, f"{reason_prefix}_parser_timeout"
    except OSError:
        return None, f"{reason_prefix}_parser_unavailable"
    stdout, stderr = proc.stdout or "", proc.stderr or ""
    if len(stdout) > MAX_PARSER_OUTPUT_BYTES or len(stderr) > MAX_PARSER_OUTPUT_BYTES:
        return None, f"{reason_prefix}_parser_output_too_large"
    if proc.returncode != 0:
        return None, f"{reason_prefix}_parser_failed"
    try:
        parsed = json.loads(stdout)
    except (json.JSONDecodeError, UnicodeDecodeError, RecursionError, ValueError):
        return None, f"{reason_prefix}_parser_malformed_output"
    return (parsed, None) if isinstance(parsed, dict) else (None, f"{reason_prefix}_parser_malformed_output")
def tx_hex_txid_error(txhex: Any, txid: str) -> str | None:
    if not isinstance(txhex, str) or not (2 <= len(txhex) <= MAX_TX_HEX_CHARS) or len(txhex) % 2 != 0 or not HEX_BYTES.fullmatch(txhex):
        return "tx_hex_malformed_or_unbounded"
    parsed, err = consensus_cli({"op": "parse_tx", "tx_hex": txhex}, "tx")
    if err or parsed is None:
        return err
    if parsed.get("ok") is not True:
        return "tx_parser_failed"
    if parsed.get("txid") != txid:
        return "tx_hex_txid_mismatch"
    return None if parsed.get("consumed") == len(txhex) // 2 else "tx_parser_consumed_mismatch"
def block_helper_binary() -> tuple[Path | None, str | None]:
    global _BLOCK_HELPER_BIN, _BLOCK_HELPER_DIR, _BLOCK_HELPER_ERR
    if not DEV_ENV.is_file() or not GO_MODULE_ROOT.is_dir():
        return None, "convergence_block_tooling_unavailable"
    if _BLOCK_HELPER_BIN is not None and _BLOCK_HELPER_BIN.is_file():
        return _BLOCK_HELPER_BIN, None
    if _BLOCK_HELPER_ERR is not None:
        return None, _BLOCK_HELPER_ERR
    try:
        tmp = tempfile.TemporaryDirectory(prefix="rubin-block-check-")
        helper = Path(tmp.name) / "main.go"; binary = Path(tmp.name) / "rubin-block-check"  # noqa: E702
        helper.write_text(BLOCK_INCLUSION_GO, encoding="utf-8")
        proc = subprocess.run(  # nosec B603
            [str(DEV_ENV), "--", "go", "-C", str(GO_MODULE_ROOT), "build", "-o", str(binary), str(helper)],
            check=False,
            env={**os.environ, "RUBIN_OPENSSL_SKIP_FIPS_GUARD": "1"},
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=60,
        )
    except subprocess.TimeoutExpired:
        _BLOCK_HELPER_ERR = "convergence_block_tooling_timeout"
        return None, _BLOCK_HELPER_ERR
    except OSError:
        _BLOCK_HELPER_ERR = "convergence_block_tooling_unavailable"
        return None, _BLOCK_HELPER_ERR
    output = f"{proc.stdout or ''}\n{proc.stderr or ''}"
    if len(output) > MAX_PARSER_OUTPUT_BYTES:
        _BLOCK_HELPER_ERR = "convergence_block_tooling_output_too_large"
        return None, _BLOCK_HELPER_ERR
    if proc.returncode != 0:
        _BLOCK_HELPER_ERR = "convergence_block_tooling_build_failed"
        return None, _BLOCK_HELPER_ERR
    _BLOCK_HELPER_DIR = tmp; _BLOCK_HELPER_BIN = binary  # noqa: E702
    return _BLOCK_HELPER_BIN, None
def block_inclusion_error(block: dict[str, Any], txhex: str, txid: str, height: int, block_hash: str, tx_count: int) -> str | None:
    binary, build_err = block_helper_binary()
    if build_err or binary is None:
        return build_err or "convergence_block_tooling_unavailable"
    try:
        proc = subprocess.run(  # nosec B603
            [str(binary)],
            check=False,
            env={**os.environ, "RUBIN_OPENSSL_SKIP_FIPS_GUARD": "1"},
            input=json.dumps({"block": block, "tx_hex": txhex, "txid": txid, "height": height, "hash": block_hash, "tx_count": tx_count}) + "\n",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=60,
        )
    except subprocess.TimeoutExpired:
        return "convergence_block_parser_timeout"
    except OSError:
        return "convergence_block_tooling_unavailable"
    output = f"{proc.stdout or ''}\n{proc.stderr or ''}"
    if len(output) > MAX_PARSER_OUTPUT_BYTES:
        return "convergence_block_parser_output_too_large"
    if proc.returncode == 0:
        return None
    for line in output.splitlines():
        if line.startswith(BLOCK_REASON_PREFIX):
            reason = line[len(BLOCK_REASON_PREFIX):]
            return reason if SAFE_REASON.fullmatch(reason) else "convergence_block_parser_malformed_output"
    return "convergence_block_parser_failed"
def tx_converge_sidecar_error(mine: dict[str, Any], seen: dict[str, Any], mine_impl: str, seen_impl: str, by_impl: dict[str, dict[str, Any]], root: Path, txid: str, txhex: str) -> tuple[list[Path], str | None]:
    reason = "convergence_sidecar_invalid"
    mine_next, mine_next_path, err = source_load_json_detailed(mine.get("mine_next_path"), root, "convergence_sidecar_path_invalid", "convergence_sidecar_nonobject")
    mine_block, mine_block_path, block_err = source_load_json_detailed(mine.get("block_path"), root, "convergence_sidecar_path_invalid", "convergence_sidecar_nonobject")
    seen_tip, seen_tip_path, tip_err = source_load_json_detailed(seen.get("tip_path"), root, "convergence_sidecar_path_invalid", "convergence_sidecar_nonobject")
    seen_block, seen_block_path, seen_block_err = source_load_json_detailed(seen.get("block_path"), root, "convergence_sidecar_path_invalid", "convergence_sidecar_nonobject")
    for load_err in (err, block_err, tip_err, seen_block_err):
        if load_err:
            return [], load_err
    paths = [p for p in (mine_next_path, mine_block_path, seen_tip_path, seen_block_path) if p is not None]
    if len(paths) != 4 or len(set(paths)) != 4 or mine_next is None or mine_block is None or seen_tip is None or seen_block is None:
        return [], "convergence_sidecar_paths_not_distinct"
    height, block_hash, tx_count = mine.get("height"), mine.get("block_hash"), mine.get("tx_count")
    if not jint(height) or not is_hex32(block_hash) or not jint(tx_count, 2):
        return [], reason
    if set(mine_next) != {"block_hash", "height", "implementation", "mined", "nonce", "request_path", "rpc_endpoint", "timestamp", "tx_count"} or mine_next.get("implementation") != mine_impl or mine_next.get("rpc_endpoint") != by_impl[mine_impl]["rpc_endpoint"] or mine_next.get("request_path") != "/mine_next" or mine_next.get("mined") is not True or not jint(mine_next.get("height")) or mine_next.get("height") != height or mine_next.get("block_hash") != block_hash or not jint(mine_next.get("tx_count"), 2) or mine_next.get("tx_count") != tx_count or not ju64(mine_next.get("nonce")) or not ju64(mine_next.get("timestamp")):
        return [], reason
    block_keys = {"block_hex", "canonical", "hash", "height", "implementation", "request_path", "rpc_endpoint"}
    for block, impl, endpoint in ((mine_block, mine_impl, by_impl[mine_impl]["rpc_endpoint"]), (seen_block, seen_impl, by_impl[seen_impl]["rpc_endpoint"])):
        if set(block) != block_keys or block.get("implementation") != impl or block.get("rpc_endpoint") != endpoint or block.get("request_path") != f"/get_block?height={height}" or block.get("canonical") is not True or not jint(block.get("height")) or block.get("height") != height or block.get("hash") != block_hash or not hex_bytes(block.get("block_hex")):
            return [], reason
        if err := block_inclusion_error(block, txhex, txid, height, block_hash, tx_count):
            return [], err
    if set(seen_tip) != {"best_known_height", "has_tip", "height", "implementation", "in_ibd", "request_path", "rpc_endpoint", "tip_hash"} or seen_tip.get("implementation") != seen_impl or seen_tip.get("rpc_endpoint") != by_impl[seen_impl]["rpc_endpoint"] or seen_tip.get("request_path") != "/get_tip" or seen_tip.get("has_tip") is not True or not jint(seen_tip.get("height")) or seen_tip.get("height") != height or seen_tip.get("tip_hash") != block_hash or not jint(seen_tip.get("best_known_height")) or seen_tip["best_known_height"] < height or not isinstance(seen_tip.get("in_ibd"), bool):
        return [], reason
    return paths, None
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
def validate_tx_source_sidecars(data: dict[str, Any], converge: bool, rust_submit: bool, root: Path) -> str | None:
    by_impl, bad = nodes(data)
    if bad or by_impl is None:
        return bad
    txid = data["tx_path"]["tx_id"]
    submit, accept, mine, conv, submit_impl, accept_impl, mine_impl, conv_impl = ("rust_submit", "go_accept", "go_mine", "rust_converge", "rust", "go", "go", "rust") if rust_submit else ("go_submit", "rust_accept", "rust_mine", "go_converge", "go", "rust", "rust", "go")
    txhex = data[submit]["tx_hex"]
    if err := tx_hex_txid_error(txhex, txid):
        return err
    paths: list[Path] = []
    for label, impl in ((submit, submit_impl), (accept, accept_impl)):
        new_paths, err = tx_capture_sidecar_error(label, data[label], impl, by_impl[impl]["rpc_endpoint"], root, txid, txhex)
        if err:
            return err
        paths.extend(new_paths)
    if converge:
        new_paths, err = tx_converge_sidecar_error(data[mine], data[conv], mine_impl, conv_impl, by_impl, root, txid, txhex)
        if err:
            return err
        paths.extend(new_paths)
    return None if len(paths) == len(set(paths)) else "tx_sidecar_paths_not_distinct"
def restart_height_tip_contradiction(rr: dict[str, Any], restart: dict[str, Any] | None) -> str | None:
    pre = rr.get("pre_restart_height", restart.get("pre_restart_height") if isinstance(restart, dict) else None)
    target, caught = rr.get("go_target_height"), rr.get("catch_up_height", restart.get("catch_up_height") if isinstance(restart, dict) else None)
    if pre is not None and target is not None and (not jint(pre) or not jint(target) or target <= pre):
        return "restart_source_binding_contradiction:target_height_not_advanced"
    if target is not None and caught is not None:
        if not jint(target) or not jint(caught):
            return "restart_source_binding_contradiction:malformed_source_fields"
        if caught < target:
            return "restart_source_binding_contradiction:catch_up_height_below_target"
        if caught != target:
            return "restart_source_binding_contradiction:catch_up_height_not_target"
    present_tips = [rr[key] for key in ("pre_restart_tip", "go_target_tip", "catch_up_tip") if key in rr]
    if any(not is_hex32(tip) for tip in present_tips):
        return "restart_source_binding_contradiction:tip_hash_invalid"
    if "go_target_tip" in rr and "catch_up_tip" in rr and rr.get("go_target_tip") != rr.get("catch_up_tip"):
        return "restart_source_binding_contradiction:tip_hash_mismatch"
    return None
def restart_contradiction(data: dict[str, Any]) -> str | None:
    restart = data.get("restart")
    if not isinstance(restart, dict):
        return "wrong_role_identity"
    if set(restart) != RESTART_SUMMARY_KEYS:
        return "restart_source_binding_contradiction:malformed_source_fields"
    if restart.get("stopped_node") != "node-rust":
        return "wrong_role_identity"
    by_impl, bad = nodes(data, require_alive=False)
    rr = data.get("rust_restart")
    if not isinstance(rr, dict):
        return "restart_source_binding_contradiction:malformed_source_fields" if "rust_restart" in data else bad
    if set(rr) != RESTART_OBJECT_KEYS:
        return "restart_source_binding_contradiction:malformed_source_fields"
    if any(not isinstance(rr.get(k), bool) for k in ("old_pid_stopped", "same_datadir", "peer_reconnect_observed", "pre_restart_has_tip", "go_target_has_tip", "catch_up_has_tip")) or any(not jint(rr.get(k), 1) for k in ("old_pid", "new_pid", "go_target_tx_count")) or any(not jint(rr.get(k)) for k in ("pre_restart_height", "go_target_height", "catch_up_height")):
        return "restart_source_binding_contradiction:malformed_source_fields"
    if rr.get("old_pid_stopped") is False:
        return "restart_source_binding_contradiction:old_pid_stopped_false"
    if rr.get("same_datadir") is False:
        return "restart_source_binding_contradiction:same_datadir_false"
    if rr.get("peer_reconnect_observed") is False:
        return "restart_source_binding_contradiction:peer_reconnect_not_observed"
    if rr.get("pre_restart_has_tip") is not True or rr.get("go_target_has_tip") is not True or rr.get("catch_up_has_tip") is not True:
        return "restart_source_binding_contradiction:tip_flags_not_true"
    if not endpoint(rr.get("old_rpc_endpoint")) or not endpoint(rr.get("old_p2p_endpoint")) or not endpoint(rr.get("new_rpc_endpoint")) or not endpoint(rr.get("new_p2p_endpoint")) or not utc_z(rr.get("old_started_at")) or not utc_z(rr.get("new_started_at")) or not str_list(rr.get("old_command_argv")) or not str_list(rr.get("new_command_argv")):
        return "restart_source_binding_contradiction:malformed_source_fields"
    if bad or by_impl is None:
        return bad or "process_identity_missing_or_invalid"
    old_pid, new_pid = rr.get("old_pid"), rr.get("new_pid")
    if old_pid == new_pid:
        return "restart_source_binding_contradiction:old_pid_aliases_live_node"
    if jint(old_pid) and old_pid in {by_impl["go"]["pid"], by_impl["rust"]["pid"]}:
        return "restart_source_binding_contradiction:old_pid_aliases_live_node"
    if jint(new_pid) and new_pid != by_impl["rust"]["pid"]:
        return "restart_source_binding_contradiction:new_pid_not_final_rust_pid"
    if rr.get("new_rpc_endpoint") != by_impl["rust"]["rpc_endpoint"] or rr.get("new_p2p_endpoint") != by_impl["rust"]["p2p_endpoint"] or rr.get("new_started_at") != by_impl["rust"].get("started_at"):
        return "restart_source_binding_contradiction:new_process_identity_mismatch"
    if any(k in restart and not jint(restart.get(k)) for k in ("pre_restart_height", "catch_up_height")):
        return "restart_source_binding_contradiction:malformed_source_fields"
    for key in ("pre_restart_height", "catch_up_height"):
        if key in restart and (key not in rr or rr.get(key) != restart[key]):
            return f"restart_source_binding_contradiction:{key}_mismatch"
    if "pre_restart_height" in restart and "catch_up_height" in restart and restart["catch_up_height"] < restart["pre_restart_height"]:
        return "restart_source_binding_contradiction:catch_up_height_below_pre_restart"
    if bad := restart_height_tip_contradiction(rr, restart):
        return bad
    return None
def restart_present_contradiction(data: dict[str, Any]) -> str | None:
    restart, rr = data.get("restart"), data.get("rust_restart")
    if bad := restart_identity_binding_error(data):
        return bad
    if "restart" in data and not isinstance(restart, dict):
        return "restart_source_binding_contradiction:malformed_source_fields"
    if isinstance(restart, dict):
        if any(k not in RESTART_SUMMARY_KEYS for k in restart):
            return "restart_source_binding_contradiction:malformed_source_fields"
        if "stopped_node" in restart and restart.get("stopped_node") != "node-rust":
            return "wrong_role_identity"
        if any(k in restart and not jint(restart.get(k)) for k in ("pre_restart_height", "catch_up_height")):
            return "restart_source_binding_contradiction:malformed_source_fields"
    if not isinstance(rr, dict):
        return None
    if any(k not in RESTART_OBJECT_KEYS for k in rr):
        return "restart_source_binding_contradiction:malformed_source_fields"
    bools = ("old_pid_stopped", "same_datadir", "peer_reconnect_observed", "pre_restart_has_tip", "go_target_has_tip", "catch_up_has_tip")
    if any(k in rr and not isinstance(rr.get(k), bool) for k in bools) or any(k in rr and not jint(rr.get(k), 1) for k in ("old_pid", "new_pid", "go_target_tx_count")) or any(k in rr and not jint(rr.get(k)) for k in ("pre_restart_height", "go_target_height", "catch_up_height")):
        return "restart_source_binding_contradiction:malformed_source_fields"
    if rr.get("old_pid_stopped") is False:
        return "restart_source_binding_contradiction:old_pid_stopped_false"
    if rr.get("same_datadir") is False:
        return "restart_source_binding_contradiction:same_datadir_false"
    if rr.get("peer_reconnect_observed") is False:
        return "restart_source_binding_contradiction:peer_reconnect_not_observed"
    if any(k in rr and rr.get(k) is not True for k in ("pre_restart_has_tip", "go_target_has_tip", "catch_up_has_tip")):
        return "restart_source_binding_contradiction:tip_flags_not_true"
    if any(k in rr and not endpoint(rr.get(k)) for k in ("old_rpc_endpoint", "old_p2p_endpoint", "new_rpc_endpoint", "new_p2p_endpoint")) or any(k in rr and not utc_z(rr.get(k)) for k in ("old_started_at", "new_started_at")) or any(k in rr and not str_list(rr.get(k)) for k in ("old_command_argv", "new_command_argv")):
        return "restart_source_binding_contradiction:malformed_source_fields"
    by_impl, bad = nodes(data, require_alive=False)
    if bad or by_impl is None:
        return None
    old_pid, new_pid = rr.get("old_pid"), rr.get("new_pid")
    if jint(old_pid) and (old_pid == new_pid or old_pid in {by_impl["go"]["pid"], by_impl["rust"]["pid"]}):
        return "restart_source_binding_contradiction:old_pid_aliases_live_node"
    if jint(new_pid) and new_pid != by_impl["rust"]["pid"]:
        return "restart_source_binding_contradiction:new_pid_not_final_rust_pid"
    for key in ("pre_restart_height", "catch_up_height"):
        if isinstance(restart, dict) and key in restart and key in rr and rr.get(key) != restart[key]:
            return f"restart_source_binding_contradiction:{key}_mismatch"
    if isinstance(restart, dict) and "pre_restart_height" in restart and "catch_up_height" in restart and restart["catch_up_height"] < restart["pre_restart_height"]:
        return "restart_source_binding_contradiction:catch_up_height_below_pre_restart"
    return restart_height_tip_contradiction(rr, restart if isinstance(restart, dict) else None)
def restart_identity_binding_error(data: dict[str, Any]) -> str | None:
    root = None
    if "artifact_root" in data:
        root_raw = data.get("artifact_root")
        if not isinstance(root_raw, str):
            return "restart_source_binding_contradiction:artifact_root_invalid"
        root = safe_abs_path(root_raw)
        if root is None or not root.is_dir():
            return "restart_source_binding_contradiction:artifact_root_invalid"
    if "run_id" in data:
        run_id = data.get("run_id")
        if not isinstance(run_id, str) or run_id.strip() != run_id or not run_id or (root is not None and run_id != root.name):
            return "restart_source_binding_contradiction:run_identity_invalid"
    if "artifact_created_at_utc" in data and not utc_z(data.get("artifact_created_at_utc")):
        return "restart_source_binding_contradiction:run_identity_invalid"
    rr = data.get("rust_restart")
    if isinstance(rr, dict) and "datadir" in rr:
        if root is None:
            return "restart_source_binding_contradiction:artifact_root_invalid"
        datadir_raw = rr.get("datadir")
        datadir = safe_abs_path(datadir_raw)
        root_datadir = root / "node-rust"
        if not isinstance(datadir_raw, str) or Path(os.path.expanduser(datadir_raw)).name != "node-rust" or datadir != root_datadir or not root_datadir.is_dir() or root_datadir.is_symlink():
            return "restart_source_binding_contradiction:datadir_not_bound"
    return None
def restart_peer_snapshot_error(peer: dict[str, Any], field: str, expected_addr: Any) -> str | None:
    snap = peer.get(field)
    entries = snap.get("peers") if isinstance(snap, dict) else None
    if not isinstance(snap, dict) or set(snap) != RESTART_SNAPSHOT_KEYS or not jint(snap.get("count"), 1) or snap.get("count") != 1 or not isinstance(entries, list) or len(entries) != 1:
        return "restart_source_binding_contradiction:peer_connectivity_invalid"
    entry = entries[0]
    if not isinstance(entry, dict) or set(entry) != RESTART_PEER_ENTRY_KEYS or entry.get("addr") != expected_addr or entry.get("handshake_complete") is not True:
        return "restart_source_binding_contradiction:peer_connectivity_invalid"
    return None
def restart_pass_contract_error(data: dict[str, Any], path: Path) -> str | None:
    if set(data) != RESTART_TOP_KEYS:
        return "restart_source_binding_contradiction:top_level_fields_invalid"
    root_raw = data.get("artifact_root")
    if not isinstance(root_raw, str):
        return "restart_source_binding_contradiction:artifact_root_invalid"
    root = safe_abs_path(root_raw)
    if root is None or not root.is_dir():
        return "restart_source_binding_contradiction:artifact_root_invalid"
    try:
        Path(os.path.realpath(path)).relative_to(root)
    except ValueError:
        return "restart_source_binding_contradiction:report_outside_artifact_root"
    legacy = data.get("legacy_schema_compatibility")
    if not isinstance(legacy, dict) or set(legacy) != {"authoritative", "marker_path", "purpose", "reason"} or legacy.get("authoritative") is not False:
        return "restart_source_binding_contradiction:legacy_marker_invalid"
    if legacy.get("purpose") != "schema-valid legacy artifact only; not the Rust restart report verdict" or legacy.get("reason") != "existing mixed_client_evidence_v1 PASS requires tx_path; Rust restart PASS lives in this report":
        return "restart_source_binding_contradiction:legacy_marker_invalid"
    marker_path_raw = legacy.get("marker_path")
    if not isinstance(marker_path_raw, str):
        return "restart_source_binding_contradiction:legacy_marker_invalid"
    marker_path, marker_err = regular_abs_path(marker_path_raw, "restart_source_binding_contradiction:legacy_marker_invalid")
    if marker_err:
        return marker_err
    try:
        marker_path.relative_to(root)
    except ValueError:
        return "restart_source_binding_contradiction:legacy_marker_invalid"
    marker, marker_load_err = load(marker_path)
    if marker_load_err or not isinstance(marker, dict) or set(marker) != {"evidence_type", "failure_reason", "participants", "restart", "scenario", "schema_version", "verdict"}:
        return "restart_source_binding_contradiction:legacy_marker_invalid"
    if marker.get("schema_version") != RESTART_MARKER_SCHEMA_VERSION or marker.get("scenario") != "mixed_client_mesh_schema_marker" or marker.get("evidence_type") != "mixed_client_process_soak" or marker.get("verdict") != "FAIL" or marker.get("restart") != data.get("restart") or not isinstance(marker.get("failure_reason"), str) or not marker["failure_reason"]:
        return "restart_source_binding_contradiction:legacy_marker_invalid"
    by_impl, bad = nodes(data, require_alive=True)
    if bad or by_impl is None:
        return bad or "process_identity_missing_or_invalid"
    for impl, expected_name, expected_comm in (("go", "node-go", "rubin-node-go"), ("rust", "node-rust", "rubin-node-rust")):
        node = by_impl[impl]
        if node.get("name") != expected_name or node.get("process_comm") != expected_comm or not utc_z(node.get("started_at")) or not command_bound_to_argv(node):
            return "restart_source_binding_contradiction:node_identity_invalid"
        binary = safe_abs_path(node.get("binary"))
        if binary is None or binary.name != expected_comm or not binary.is_file() or not os.access(binary, os.X_OK):
            return "restart_source_binding_contradiction:node_identity_invalid"
        try:
            binary.relative_to(root)
        except ValueError:
            return "restart_source_binding_contradiction:node_identity_invalid"
        expected_argv = [str(binary), "--network", "devnet", "--datadir", str(root / f"node-{impl}"), "--bind", "127.0.0.1:0", "--rpc-bind", "127.0.0.1:0"] + (["--peer", by_impl["go"]["p2p_endpoint"]] if impl == "rust" else [])
        if not argv_eq(node.get("command_argv"), expected_argv, {0, 4}):
            return "restart_source_binding_contradiction:node_identity_invalid"
    if not marker_participants_bound(marker, by_impl):
        return "restart_source_binding_contradiction:legacy_marker_invalid"
    peer = data.get("peer_connectivity")
    links = peer.get("counterpart_links") if isinstance(peer, dict) else None
    if not isinstance(peer, dict) or set(peer) != RESTART_PEER_KEYS or any(peer.get(k) is not True for k in ("go_to_rust", "rust_to_go", "bidirectional_observed")) or not isinstance(links, dict) or set(links) != RESTART_LINK_KEYS:
        return "restart_source_binding_contradiction:peer_connectivity_invalid"
    go_expected, rust_expected = links.get("go_peer_snapshot_expected_addr"), links.get("rust_peer_snapshot_expected_addr")
    if (
        not endpoint(go_expected)
        or not endpoint(rust_expected)
        or links.get("rust_outbound_local_addr") != go_expected
        or links.get("rust_outbound_remote_addr") != rust_expected
        or rust_expected != by_impl["go"]["p2p_endpoint"]
        or links.get("rust_outbound_pid") != by_impl["rust"]["pid"]
        or go_expected in {rust_expected, by_impl["rust"]["p2p_endpoint"], by_impl["go"]["rpc_endpoint"], by_impl["rust"]["rpc_endpoint"]}
    ):
        return "restart_source_binding_contradiction:peer_connectivity_invalid"
    if bad := (restart_peer_snapshot_error(peer, "go_peer_snapshot", go_expected) or restart_peer_snapshot_error(peer, "rust_peer_snapshot", rust_expected)):
        return bad
    final = data.get("final_verification")
    if not isinstance(final, dict) or set(final) != RESTART_FINAL_KEYS or any(final.get(k) is not True for k in ("producer_side", "process_identity_rechecked", "rust_outbound_link_rechecked", "peer_snapshots_rechecked")):
        return "restart_source_binding_contradiction:final_verification_invalid"
    if final.get("rust_outbound_pid") != by_impl["rust"]["pid"] or final.get("rust_outbound_local_addr") != go_expected or final.get("rust_outbound_remote_addr") != rust_expected:
        return "restart_source_binding_contradiction:final_verification_invalid"
    return validate_samples(data, None, None, "")
def restart_sidecar_error(data: dict[str, Any], path: Path) -> str | None:
    rr = data["rust_restart"]
    by_impl, _ = nodes(data, require_alive=False)
    root_raw = data.get("artifact_root")
    if by_impl is None or not isinstance(root_raw, str):
        return "restart_source_binding_contradiction:artifact_root_invalid"
    root = safe_abs_path(root_raw)
    if root is None or not root.is_dir():
        return "restart_source_binding_contradiction:artifact_root_invalid"
    if bad := restart_identity_binding_error(data):
        return bad
    expected_old_argv = [by_impl["rust"].get("binary"), "--network", "devnet", "--datadir", str(root / "node-rust"), "--bind", "127.0.0.1:0", "--rpc-bind", "127.0.0.1:0", "--peer", by_impl["go"]["p2p_endpoint"]]
    if not argv_eq(rr.get("old_command_argv"), expected_old_argv, {0, 4}) or not argv_eq(rr.get("new_command_argv"), by_impl["rust"].get("command_argv"), {0, 4}):
        return "restart_source_binding_contradiction:argv_mismatch"
    try:
        Path(os.path.realpath(path)).relative_to(root)
    except ValueError:
        return "restart_source_binding_contradiction:report_outside_artifact_root"
    def artifact(field: str, reason: str) -> tuple[Path | None, str | None]:
        if not isinstance(rr.get(field), str):
            return None, reason
        p, err = regular_abs_path(str(rr[field]), reason)
        if err:
            return None, err
        try:
            p.relative_to(root)
        except ValueError:
            return None, reason
        return p, None
    def tip(field: str, impl: str, endpoint: Any, height: Any, tip_hash: Any, reason: str) -> str | None:
        p, err = artifact(field, reason)
        sidecar, load_err = (None, err) if err else load(p)  # type: ignore[arg-type]
        if load_err or not isinstance(sidecar, dict):
            return reason
        keys = {"best_known_height", "has_tip", "height", "implementation", "in_ibd", "request_path", "rpc_endpoint", "tip_hash"}
        if set(sidecar) != keys or sidecar.get("implementation") != impl or sidecar.get("rpc_endpoint") != endpoint or sidecar.get("request_path") != "/get_tip":
            return reason
        sidecar_height = sidecar.get("height")
        if sidecar.get("has_tip") is not True or not jint(sidecar_height) or sidecar_height != height or sidecar.get("tip_hash") != tip_hash:
            return reason
        if not jint(sidecar.get("best_known_height")) or sidecar["best_known_height"] < sidecar_height or not isinstance(sidecar.get("in_ibd"), bool):
            return reason
        return None
    checks = (
        ("pre_restart_tip_path", "rust", rr.get("old_rpc_endpoint"), rr.get("pre_restart_height"), rr.get("pre_restart_tip"), "restart_source_binding_contradiction:pre_restart_tip_sidecar_invalid"),
        ("go_target_tip_path", "go", by_impl["go"]["rpc_endpoint"], rr.get("go_target_height"), rr.get("go_target_tip"), "restart_source_binding_contradiction:go_target_tip_sidecar_invalid"),
        ("catch_up_tip_path", "rust", by_impl["rust"]["rpc_endpoint"], rr.get("catch_up_height"), rr.get("catch_up_tip"), "restart_source_binding_contradiction:catch_up_tip_sidecar_invalid"),
    )
    for check in checks:
        if err := tip(*check):
            return err
    p, err = artifact("go_target_mine_next_path", "restart_source_binding_contradiction:go_target_mine_next_invalid")
    mine, load_err = (None, err) if err else load(p)  # type: ignore[arg-type]
    if load_err or not isinstance(mine, dict):
        return "restart_source_binding_contradiction:go_target_mine_next_invalid"
    keys = {"block_hash", "height", "implementation", "mined", "nonce", "request_path", "rpc_endpoint", "timestamp", "tx_count"}
    if set(mine) != keys or mine.get("implementation") != "go" or mine.get("rpc_endpoint") != by_impl["go"]["rpc_endpoint"] or mine.get("request_path") != "/mine_next":
        return "restart_source_binding_contradiction:go_target_mine_next_invalid"
    mine_height = mine.get("height")
    mine_tx_count = mine.get("tx_count")
    if (
        mine.get("mined") is not True
        or not jint(mine_height)
        or not jint(mine_tx_count, 1)
        or mine_height != rr.get("go_target_height")
        or mine.get("block_hash") != rr.get("go_target_tip")
        or mine_tx_count != rr.get("go_target_tx_count")
    ):
        return "restart_source_binding_contradiction:go_target_mine_next_invalid"
    if not ju64(mine.get("nonce")) or not ju64(mine.get("timestamp")):
        return "restart_source_binding_contradiction:go_target_mine_next_invalid"
    return None
def partition_contradiction(data: dict[str, Any]) -> str | None:
    _, bad = nodes(data, require_alive=False, require_backing=False)
    proof = data.get("proof")
    if not isinstance(proof, dict):
        return "partition_reorg_source_binding_contradiction:malformed_proof_fields" if "proof" in data else bad
    if any(k in proof and not isinstance(proof.get(k), bool) for k in ("partition_changed_peer_state", "fork_diverged", "heal_restored_peer_state", "reorg_converged", "process_identity_rechecked_after_heal")) or ("go_reorg_metrics" in proof and (not isinstance(proof.get("go_reorg_metrics"), dict) or any(not jint(proof["go_reorg_metrics"].get(m), 1) for m in METRICS))):
        return "partition_reorg_source_binding_contradiction:malformed_proof_fields"
    if any(k in proof and not endpoint(proof.get(k)) for k in ("partition_proxy_endpoint", "pre_partition_go_peer_addr", "heal_go_peer_addr")):
        return "partition_reorg_source_binding_contradiction:malformed_proof_fields"
    for key, reason in (("partition_changed_peer_state", "partition_no_peer_state_change"), ("fork_diverged", "partition_no_fork_divergence"), ("heal_restored_peer_state", "partition_heal_not_restored"), ("reorg_converged", "partition_reorg_not_converged"), ("process_identity_rechecked_after_heal", "partition_process_identity_not_rechecked_after_heal")):
        if proof.get(key) is False:
            return f"partition_reorg_source_binding_contradiction:{reason}"
    go_fork, rust_win = proof.get("go_partition_tip"), proof.get("rust_winning_tip")
    if (go_fork is not None or rust_win is not None) and not (isinstance(go_fork, dict) and isinstance(rust_win, dict)):
        return "partition_reorg_source_binding_contradiction:malformed_tip_fields"
    if isinstance(go_fork, dict) and isinstance(rust_win, dict) and (not jint(go_fork.get("height")) or not jint(rust_win.get("height")) or not is_hex32(go_fork.get("hash")) or not is_hex32(rust_win.get("hash")) or go_fork.get("hash") == rust_win.get("hash") or rust_win.get("height") <= go_fork.get("height")):
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
def partition_node_identity_error(by_impl: dict[str, dict[str, Any]], root: Path, partition_proxy: str) -> str | None:
    if not endpoint(partition_proxy):
        return "partition_reorg_source_binding_contradiction:node_identity_invalid"
    if partition_proxy in {node.get(field) for node in by_impl.values() for field in ("rpc_endpoint", "p2p_endpoint")}:
        return "partition_reorg_source_binding_contradiction:node_identity_invalid"
    for impl, expected_name, expected_comm, extra in (("go", "node-go", "rubin-node-go", []), ("rust", "node-rust", "rubin-node-rust", ["--peer", partition_proxy])):
        node = by_impl[impl]
        if node.get("name") != expected_name or node.get("process_comm") != expected_comm or not utc_z(node.get("started_at")) or not command_bound_to_argv(node):
            return "partition_reorg_source_binding_contradiction:node_identity_invalid"
        binary = safe_abs_path(node.get("binary"))
        if binary is None or binary.name != expected_comm or not binary.is_file() or not os.access(binary, os.X_OK):
            return "partition_reorg_source_binding_contradiction:node_identity_invalid"
        try:
            binary.relative_to(root)
        except ValueError:
            return "partition_reorg_source_binding_contradiction:node_identity_invalid"
        expected_argv = [str(binary), "--network", "devnet", "--datadir", str(root / f"node-{impl}"), "--bind", "127.0.0.1:0", "--rpc-bind", "127.0.0.1:0"] + extra
        if not argv_eq(node.get("command_argv"), expected_argv, {0, 4}):
            return "partition_reorg_source_binding_contradiction:node_identity_invalid"
    return None
def partition_pass_contract_error(data: dict[str, Any], path: Path) -> str | None:
    if set(data) != PARTITION_TOP_KEYS:
        return "partition_reorg_source_binding_contradiction:top_level_fields_invalid"
    root = safe_abs_path(data.get("artifact_root"))
    if root is None or not root.is_dir() or root.is_symlink():
        return "partition_reorg_source_binding_contradiction:artifact_root_invalid"
    try:
        Path(os.path.realpath(path)).relative_to(root)
    except ValueError:
        return "partition_reorg_source_binding_contradiction:report_outside_artifact_root"
    legacy = data.get("legacy_schema_compatibility")
    if not isinstance(legacy, dict) or set(legacy) != {"authoritative", "marker_path", "purpose", "reason"} or legacy.get("authoritative") is not False:
        return "partition_reorg_source_binding_contradiction:legacy_marker_invalid"
    if legacy.get("purpose") != PARTITION_LEGACY_PURPOSE or legacy.get("reason") != PARTITION_LEGACY_REASON:
        return "partition_reorg_source_binding_contradiction:legacy_marker_invalid"
    marker_raw = legacy.get("marker_path")
    if not isinstance(marker_raw, str) or not marker_raw:
        return "partition_reorg_source_binding_contradiction:legacy_marker_invalid"
    marker_path, marker_err = regular_abs_path(marker_raw, "partition_reorg_source_binding_contradiction:legacy_marker_invalid")
    if marker_err:
        return marker_err
    try:
        marker_path.relative_to(root)
    except ValueError:
        return "partition_reorg_source_binding_contradiction:legacy_marker_invalid"
    marker, marker_load_err = load(marker_path)
    if marker_load_err or not isinstance(marker, dict) or marker.get("schema_version") != RESTART_MARKER_SCHEMA_VERSION or marker.get("scenario") != "mixed_client_mesh_schema_marker" or marker.get("evidence_type") != "mixed_client_process_soak" or marker.get("verdict") != "FAIL":
        return "partition_reorg_source_binding_contradiction:legacy_marker_invalid"
    _, node_bad = nodes(data, require_alive=True, require_backing=True)
    if node_bad:
        return node_bad
    sample_bad = validate_samples(data, None, None, "")
    return f"partition_reorg_source_binding_contradiction:{sample_bad}" if sample_bad else None
def partition_load_sidecar(path: Path, reason: str) -> tuple[dict[str, Any] | None, str | None]:
    data, err = load(path)
    return (data, None) if err is None and isinstance(data, dict) else (None, reason)
def partition_peer_sidecar(path: Path, expected: str | None, connected: bool) -> str | None:
    data, err = partition_load_sidecar(path, "partition_reorg_source_binding_contradiction:peer_snapshot_invalid")
    if err or data is None:
        return err
    peers = data.get("peers")
    if set(data) != RESTART_SNAPSHOT_KEYS or not isinstance(data.get("count"), int) or isinstance(data.get("count"), bool) or not isinstance(peers, list) or data["count"] != len(peers):
        return "partition_reorg_source_binding_contradiction:peer_snapshot_invalid"
    if any(not isinstance(peer, dict) or set(peer) != {"addr", "handshake_complete"} or not endpoint(peer.get("addr")) or not isinstance(peer.get("handshake_complete"), bool) for peer in peers) or len({peer.get("addr") for peer in peers}) != len(peers):
        return "partition_reorg_source_binding_contradiction:peer_snapshot_invalid"
    complete = [peer["addr"] for peer in peers if peer.get("handshake_complete") is True]
    if connected:
        return None if expected and complete == [expected] and len(peers) == 1 else "partition_reorg_source_binding_contradiction:peer_snapshot_invalid"
    return None if expected is None and complete == [] and len(peers) == 0 else "partition_reorg_source_binding_contradiction:peer_snapshot_invalid"
def partition_tip_sidecar(path: Path, impl: str, rpc: str, height: int, block_hash: str) -> str | None:
    data, err = partition_load_sidecar(path, "partition_reorg_source_binding_contradiction:tip_sidecar_invalid")
    if err or data is None:
        return err
    keys = {"best_known_height", "has_tip", "height", "implementation", "in_ibd", "request_path", "rpc_endpoint", "tip_hash"}
    if set(data) != keys or data.get("implementation") != impl or data.get("rpc_endpoint") != rpc or data.get("request_path") != "/get_tip":
        return "partition_reorg_source_binding_contradiction:tip_sidecar_invalid"
    if data.get("has_tip") is not True or not jint(data.get("height")) or data["height"] != height or data.get("tip_hash") != block_hash or not jint(data.get("best_known_height")) or data["best_known_height"] < height or not isinstance(data.get("in_ibd"), bool):
        return "partition_reorg_source_binding_contradiction:tip_sidecar_invalid"
    return None
def partition_block_sidecar(path: Path, impl: str, rpc: str, height: int, block_hash: str, expected_prev_hash: str | None = None) -> str | None:
    data, err = partition_load_sidecar(path, "partition_reorg_source_binding_contradiction:block_sidecar_invalid")
    if err or data is None:
        return err
    keys = {"block_hex", "canonical", "hash", "height", "implementation", "request_path", "rpc_endpoint"}
    if set(data) != keys or data.get("implementation") != impl or data.get("rpc_endpoint") != rpc or data.get("request_path") != f"/get_block?height={height}":
        return "partition_reorg_source_binding_contradiction:block_sidecar_invalid"
    if data.get("canonical") is not True or not jint(data.get("height")) or data.get("height") != height or data.get("hash") != block_hash or not hex_bytes(data.get("block_hex")):
        return "partition_reorg_source_binding_contradiction:block_sidecar_invalid"
    if err := partition_block_payload_error(data["block_hex"], height, block_hash, expected_prev_hash):
        return err
    return None
def partition_block_payload_error(block_hex: str, height: int, block_hash: str, expected_prev_hash: str | None = None) -> str | None:
    if not DEV_ENV.is_file() or not GO_MODULE_ROOT.is_dir():
        return "partition_reorg_source_binding_contradiction:block_parser_unavailable"
    request_obj = {"op": "block_basic_check", "block_hex": block_hex, "height": height}
    if expected_prev_hash is not None:
        request_obj["expected_prev_hash"] = expected_prev_hash
    request = json.dumps(request_obj) + "\n"
    try:
        # Fixed repo-local argv with no shell; report-controlled block bytes are passed on stdin.
        proc = subprocess.run(  # nosec B603
            [str(DEV_ENV), "--", "go", "-C", str(GO_MODULE_ROOT), "run", "./cmd/rubin-consensus-cli"],
            check=False,
            env={**os.environ, "RUBIN_OPENSSL_SKIP_FIPS_GUARD": "1"},
            input=request,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=60,
        )
    except subprocess.TimeoutExpired:
        return "partition_reorg_source_binding_contradiction:block_parser_timeout"
    except OSError:
        return "partition_reorg_source_binding_contradiction:block_parser_unavailable"
    stdout, stderr = proc.stdout or "", proc.stderr or ""
    if len(stdout) > MAX_PARSER_OUTPUT_BYTES or len(stderr) > MAX_PARSER_OUTPUT_BYTES:
        return "partition_reorg_source_binding_contradiction:block_parser_output_too_large"
    if proc.returncode != 0:
        return "partition_reorg_source_binding_contradiction:block_parser_failed"
    try:
        parsed = json.loads(stdout)
    except (json.JSONDecodeError, UnicodeDecodeError, RecursionError, ValueError):
        return "partition_reorg_source_binding_contradiction:block_parser_malformed_output"
    if not isinstance(parsed, dict):
        return "partition_reorg_source_binding_contradiction:block_parser_malformed_output"
    if parsed.get("ok") is not True:
        return "partition_reorg_source_binding_contradiction:block_payload_invalid"
    if parsed.get("block_hash") != block_hash:
        return "partition_reorg_source_binding_contradiction:block_hash_mismatch"
    return None
def partition_mine_sidecar(path: Path, impl: str, rpc: str, minimum: int = 1) -> tuple[dict[str, Any] | None, str | None]:
    data, err = partition_load_sidecar(path, "partition_reorg_source_binding_contradiction:mine_sidecar_invalid")
    if err or data is None:
        return None, err
    keys = {"block_hash", "height", "implementation", "mined", "nonce", "request_path", "rpc_endpoint", "timestamp", "tx_count"}
    if set(data) != keys or data.get("implementation") != impl or data.get("rpc_endpoint") != rpc or data.get("request_path") != "/mine_next":
        return None, "partition_reorg_source_binding_contradiction:mine_sidecar_invalid"
    if data.get("mined") is not True or not jint(data.get("height"), minimum) or not is_hex32(data.get("block_hash")) or not jint(data.get("tx_count"), 1) or not ju64(data.get("nonce")) or not ju64(data.get("timestamp")):
        return None, "partition_reorg_source_binding_contradiction:mine_sidecar_invalid"
    return data, None
def partition_obs_paths(data: dict[str, Any], root: Path) -> tuple[dict[str, Path] | None, str | None]:
    paths: dict[str, Path] = {}
    for dotted in PATH_FIELD_DOTTED_NAMES:
        value, present = get(data, dotted)
        if not present:
            return None, "partition_reorg_source_binding_contradiction:malformed_source_fields"
        sidecar, err = regular_abs_path(value, "partition_reorg_source_binding_contradiction:sidecar_invalid") if isinstance(value, str) else (None, "partition_reorg_source_binding_contradiction:sidecar_invalid")
        if err or sidecar is None:
            return None, err or "partition_reorg_source_binding_contradiction:sidecar_invalid"
        try:
            sidecar.relative_to(root)
        except ValueError:
            return None, "partition_reorg_source_binding_contradiction:sidecar_outside_artifact_root"
        paths[dotted.removeprefix("observations.")] = sidecar
    if len(set(paths.values())) != len(paths):
        return None, "partition_reorg_source_binding_contradiction:sidecar_paths_not_distinct"
    return paths, None
def partition_sidecar_error(data: dict[str, Any], path: Path) -> str | None:
    root_raw = data.get("artifact_root")
    root = safe_abs_path(root_raw)
    if root is None or not root.is_dir() or root.is_symlink():
        return "partition_reorg_source_binding_contradiction:artifact_root_invalid"
    if data.get("run_id") != root.name or not utc_z(data.get("artifact_created_at_utc")):
        return "partition_reorg_source_binding_contradiction:run_identity_invalid"
    try:
        path.relative_to(root)
    except ValueError:
        return "partition_reorg_source_binding_contradiction:report_outside_artifact_root"
    by_impl, bad = nodes(data, require_alive=False, require_backing=True)
    if bad:
        return bad
    proof = data["proof"]
    expected_proof_keys = {"final_go_tip", "final_rust_tip", "fork_diverged", "go_partition_tip", "go_reorg_metrics", "heal_go_peer_addr", "heal_restored_peer_state", "partition_changed_peer_state", "partition_proxy_endpoint", "pre_partition_go_peer_addr", "process_identity_rechecked_after_heal", "reorg_converged", "rust_winning_tip"}
    if set(proof) != expected_proof_keys:
        return "partition_reorg_source_binding_contradiction:malformed_proof_fields"
    if proof.get("partition_proxy_endpoint") in {proof.get("pre_partition_go_peer_addr"), proof.get("heal_go_peer_addr")}:
        return "partition_reorg_source_binding_contradiction:node_identity_invalid"
    if bad := partition_node_identity_error(by_impl, root, proof.get("partition_proxy_endpoint")):
        return bad
    proof_metrics = proof.get("go_reorg_metrics")
    if not isinstance(proof_metrics, dict) or set(proof_metrics) != set(METRICS) or any(not jint(proof_metrics.get(metric), 1) for metric in METRICS):
        return "partition_reorg_source_binding_contradiction:malformed_proof_fields"
    final = data.get("final_verification")
    if not isinstance(final, dict) or set(final) != RESTART_FINAL_KEYS or final.get("producer_side") is not True or final.get("process_identity_rechecked") is not True or final.get("peer_snapshots_rechecked") is not True or final.get("rust_outbound_link_rechecked") is not False or final.get("rust_outbound_local_addr") is not None or final.get("rust_outbound_remote_addr") is not None or final.get("rust_outbound_pid") is not None:
        return "partition_reorg_source_binding_contradiction:final_verification_invalid"
    connectivity = data.get("peer_connectivity")
    if not isinstance(connectivity, dict) or set(connectivity) != RESTART_PEER_KEYS or any(connectivity.get(key) is not False for key in ("go_to_rust", "rust_to_go", "bidirectional_observed")) or not isinstance(connectivity.get("counterpart_links"), dict) or set(connectivity["counterpart_links"]) != RESTART_LINK_KEYS or any(connectivity["counterpart_links"].get(key) is not None for key in RESTART_LINK_KEYS):
        return "partition_reorg_source_binding_contradiction:peer_connectivity_overclaim"
    for field in ("go_peer_snapshot", "rust_peer_snapshot"):
        snap = connectivity.get(field)
        if not isinstance(snap, dict) or set(snap) != RESTART_SNAPSHOT_KEYS or not jint(snap.get("count")) or snap.get("count") != 0 or snap.get("peers") != []:
            return "partition_reorg_source_binding_contradiction:peer_connectivity_invalid"
    paths, err = partition_obs_paths(data, root)
    if err or paths is None:
        return err or "partition_reorg_source_binding_contradiction:sidecar_invalid"
    source_metrics, metrics_err = parse_metrics(paths["reorg.go_metrics"], strict_prometheus=True)
    if metrics_err or source_metrics is None:
        return f"partition_reorg_source_binding_contradiction:{metrics_err or 'metrics_invalid'}"
    if source_metrics != proof_metrics:
        return "partition_reorg_source_binding_contradiction:reorg_metrics_mismatch"
    go_fork, rust_win, final_go, final_rust = proof["go_partition_tip"], proof["rust_winning_tip"], proof["final_go_tip"], proof["final_rust_tip"]
    go_rpc, rust_rpc = by_impl["go"]["rpc_endpoint"], by_impl["rust"]["rpc_endpoint"]
    peer_checks = (
        ("pre_partition.rust_peer_snapshot", proof["partition_proxy_endpoint"], True), ("pre_partition.go_peer_snapshot", proof["pre_partition_go_peer_addr"], True),
        ("partition.rust_peer_snapshot", None, False), ("partition.go_peer_snapshot", None, False), ("fork.rust_peer_snapshot", None, False), ("fork.go_peer_snapshot", None, False),
        ("heal.rust_peer_snapshot", proof["partition_proxy_endpoint"], True), ("heal.go_peer_snapshot", proof["heal_go_peer_addr"], True),
    )
    for key, expected, connected in peer_checks:
        if err := partition_peer_sidecar(paths[key], expected, connected):
            return err
    common, err = partition_mine_sidecar(paths["pre_partition.common_go_mine"], "go", go_rpc)
    if err or common is None:
        return err
    if common.get("height") != go_fork["height"] - 1:
        return "partition_reorg_source_binding_contradiction:common_parent_invalid"
    sidecar_checks = (
        partition_block_sidecar(paths["pre_partition.common_go_block"], "go", go_rpc, common["height"], common["block_hash"]),
        partition_tip_sidecar(paths["pre_partition.common_rust_tip"], "rust", rust_rpc, common["height"], common["block_hash"]),
        partition_block_sidecar(paths["pre_partition.common_rust_block"], "rust", rust_rpc, common["height"], common["block_hash"]),
        partition_tip_sidecar(paths["fork.go_tip"], "go", go_rpc, go_fork["height"], go_fork["hash"]),
        partition_block_sidecar(paths["fork.go_block"], "go", go_rpc, go_fork["height"], go_fork["hash"], common["block_hash"]),
        partition_tip_sidecar(paths["fork.rust_tip"], "rust", rust_rpc, rust_win["height"], rust_win["hash"]),
        partition_tip_sidecar(paths["reorg.go_tip"], "go", go_rpc, final_go["height"], final_go["hash"]),
        partition_tip_sidecar(paths["reorg.rust_tip"], "rust", rust_rpc, final_rust["height"], final_rust["hash"]),
    )
    if bad := next((item for item in sidecar_checks if item), None):
        return bad
    go_mine, err = partition_mine_sidecar(paths["fork.go_mine"], "go", go_rpc)
    if err or go_mine is None:
        return err
    if go_mine.get("height") != go_fork["height"] or go_mine.get("block_hash") != go_fork["hash"]:
        return "partition_reorg_source_binding_contradiction:mine_sidecar_invalid"
    rust_mine_1, err = partition_mine_sidecar(paths["fork.rust_mine_1"], "rust", rust_rpc)
    if err or rust_mine_1 is None:
        return err
    if rust_mine_1.get("height") != go_fork["height"] or rust_mine_1.get("block_hash") == go_fork["hash"]:
        return "partition_reorg_source_binding_contradiction:fork_tip_not_diverged"
    if err := partition_block_sidecar(paths["fork.rust_block_1"], "rust", rust_rpc, rust_mine_1["height"], rust_mine_1["block_hash"], common["block_hash"]):
        return err
    if err := partition_block_sidecar(paths["reorg.go_reorg_parent_block"], "go", go_rpc, rust_mine_1["height"], rust_mine_1["block_hash"], common["block_hash"]):
        return err
    rust_mine_2, err = partition_mine_sidecar(paths["fork.rust_mine_2"], "rust", rust_rpc)
    if err or rust_mine_2 is None:
        return err
    if rust_mine_2.get("height") != rust_win["height"] or rust_mine_2.get("block_hash") != rust_win["hash"]:
        return "partition_reorg_source_binding_contradiction:mine_sidecar_invalid"
    if rust_mine_2["height"] != rust_mine_1["height"] + 1:
        return "partition_reorg_source_binding_contradiction:rust_winning_branch_not_contiguous"
    final_block_checks = (
        partition_block_sidecar(paths["fork.rust_block_2"], "rust", rust_rpc, rust_win["height"], rust_win["hash"], rust_mine_1["block_hash"]),
        partition_block_sidecar(paths["reorg.go_tip_block"], "go", go_rpc, final_go["height"], final_go["hash"], rust_mine_1["block_hash"]),
        partition_block_sidecar(paths["reorg.rust_tip_block"], "rust", rust_rpc, final_rust["height"], final_rust["hash"], rust_mine_1["block_hash"]),
    )
    if bad := next((item for item in final_block_checks if item), None):
        return bad
    return None
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
        base = "restart_source_binding_unproven" if name == "rust_restart" else "partition_reorg_source_binding_unproven"
        reason = base if not missing else f"{base}:missing_source_fields:{','.join(missing)}"
        if name == "rust_restart":
            if "rust_restart" in data and not isinstance(data.get("rust_restart"), dict):
                return section(name, "fail", restart_contradiction(data) or "restart_source_binding_contradiction:malformed_source_fields", source_artifact_path=path, scenario=got)
            if missing:
                _, node_bad = nodes(data, require_alive=False)
                if node_bad:
                    return section(name, "fail", node_bad, source_artifact_path=path, scenario=got)
                if bad := restart_present_contradiction(data):
                    return section(name, "fail", bad, source_artifact_path=path, scenario=got)
                return section(name, "no_data", reason, source_artifact_path=path, scenario=got, source_fields=fields, claim_type="structural_only", evidence_class="structural_only", behavior_evidence=False)
            if bad := (restart_contradiction(data) or restart_pass_contract_error(data, path)):
                return section(name, "fail", bad, source_artifact_path=path, scenario=got)
            if bad := restart_sidecar_error(data, path):
                return section(name, "fail", bad, source_artifact_path=path, scenario=got)
            return section(name, "pass", None, source_artifact_path=path, scenario=got, source_fields=fields, claim_type="behavior_evidence", evidence_class="behavior_evidence", behavior_evidence=True)
        bad = partition_contradiction(data)
        if bad:
            return section(name, "fail", bad, source_artifact_path=path, scenario=got)
        if missing:
            return section(name, "no_data", reason, source_artifact_path=path, scenario=got, source_fields=fields, claim_type="structural_only", evidence_class="structural_only", behavior_evidence=False)
        if bad := partition_pass_contract_error(data, path):
            return section(name, "fail", bad, source_artifact_path=path, scenario=got)
        if bad := partition_sidecar_error(data, path):
            return section(name, "fail", bad, source_artifact_path=path, scenario=got)
        return section(name, "pass", None, source_artifact_path=path, scenario=got, source_fields=fields + PARTITION_PASS_CONTRACT_FIELDS, claim_type="behavior_evidence", evidence_class="behavior_evidence", behavior_evidence=True)
    if missing:
        return section(name, "fail", "missing_source_fields:" + ",".join(missing), source_artifact_path=path, scenario=got)
    if name in SOURCE_TOP_KEYS:
        if bad := source_report_contract_error(name, data, path):
            return section(name, "fail", bad, source_artifact_path=path, scenario=got)
    bad = validate_mesh(data) if name == "mesh" else validate_tx(data, "converge" in name, name.startswith("rust_to_go"))
    if bad:
        return section(name, "fail", bad, source_artifact_path=path, scenario=got)
    if name != "mesh" and name in SOURCE_TOP_KEYS:
        root = safe_abs_path(data.get("artifact_root"))
        if root is None:
            return section(name, "fail", f"{name}_artifact_root_invalid", source_artifact_path=path, scenario=got)
        if bad := validate_tx_source_sidecars(data, "converge" in name, name.startswith("rust_to_go"), root):
            return section(name, "fail", bad, source_artifact_path=path, scenario=got)
    return section(name, "pass", None, source_artifact_path=path, scenario=got, source_fields=fields, claim_type="source_report_evidence", evidence_class="source_report_evidence", behavior_evidence=False)
def parse_metrics(path: Path, strict_prometheus: bool = False) -> tuple[dict[str, int] | None, str | None]:
    try:
        with path.open("rb") as src: raw = src.read(MAX_JSON_BYTES + 1)
        if len(raw) > MAX_JSON_BYTES: return None, "metrics_too_large"  # noqa: E701
        text = raw.decode("utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        return None, f"read_failed:{exc.__class__.__name__}"
    try:
        found: dict[str, int] = {}
        if text.lstrip().startswith("{"):
            if strict_prometheus:
                return None, "metrics_malformed"
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
                head = re.match(r"[A-Za-z_:][A-Za-z0-9_:]*", line); metric = head.group(0) if head else ""; m = (STRICT_METRIC_LINE if strict_prometheus else METRIC_LINE).fullmatch(line) if metric in METRICS else None  # noqa: E702
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
def metric_section(args: argparse.Namespace, sections: dict[str, dict[str, Any]]) -> dict[str, Any]:
    if args.rust_reorg_metrics_no_data:
        if bad := no_data_source_reason_error(args.rust_reorg_metrics_no_data):
            return section("reorg_metrics", "fail", bad, claim_type="metric_evidence")
        return section("reorg_metrics", "no_data", "rust_reorg_metrics_no_data", source_reason=args.rust_reorg_metrics_no_data, claim_type="metric_evidence")
    if not args.rust_reorg_metrics:
        return section("reorg_metrics", "no_data", "rust_reorg_metrics_missing", claim_type="metric_evidence")
    path, path_err = regular_path(args.rust_reorg_metrics, "metrics_not_regular")
    metrics, err = (None, path_err) if path_err else parse_metrics(path)
    if err:
        return section("reorg_metrics", "fail", err, source_artifact_path=path, claim_type="metric_evidence")
    partition = sections.get("partition_heal_reorg", {})
    binding_reason = "metric_source_binding_unavailable"
    if partition.get("status") == "pass" and isinstance(partition.get("source_artifact_path"), str):
        partition_path, partition_err = regular_abs_path(partition["source_artifact_path"], "partition_source_not_regular")
        pdata, perr = load(partition_path) if partition_err is None else (None, partition_err)
        metric_value, present = get(pdata, "observations.reorg.go_metrics") if perr is None and isinstance(pdata, dict) else (None, False)
        metric_path, metric_err = regular_abs_path(metric_value, "metrics_not_regular") if present and isinstance(metric_value, str) else (None, "metrics_not_regular")
        binding_reason = "metric_source_binding_path_mismatch" if metric_err is None and metric_path != path else binding_reason
        if metric_err is None and metric_path == path:
            return section("reorg_metrics", "pass", None, source_artifact_path=path, source_fields=sorted(METRICS), claim_type="metric_evidence", evidence_class="metric_evidence", behavior_evidence=False, metric_values=metrics)
    if binding_reason == "metric_source_binding_path_mismatch":
        return section("reorg_metrics", "no_data", binding_reason, source_artifact_path=path, expected_source_artifact_path=metric_path, source_fields=sorted(METRICS), claim_type="metric_evidence", metric_values=metrics)
    return section("reorg_metrics", "no_data", binding_reason, source_artifact_path=path, source_fields=sorted(METRICS), claim_type="metric_evidence", metric_values=metrics)
def raw_sample_observed(path_value: Any, fields: tuple[str, ...]) -> bool:
    path, err = regular_abs_path(path_value, "raw_samples_source_not_regular") if isinstance(path_value, str) else (None, "raw_samples_source_not_regular")
    data, load_err = load(path) if err is None and path is not None else (None, err)
    if load_err or not isinstance(data, dict):
        return False
    for field in fields:
        value, present = get(data, field)
        samples = value.get("samples") if isinstance(value, dict) else None
        if not present or not isinstance(samples, list) or not samples or any(not isinstance(item, dict) for item in samples):
            return False
    return True
def raw_samples_section(sections: dict[str, dict[str, Any]]) -> dict[str, Any]:
    tx_requirements = {
        "go_to_rust_accept": ("raw_samples.propagation",),
        "go_to_rust_mine_converge": ("raw_samples.propagation", "raw_samples.convergence"),
        "rust_to_go_mine_converge": ("raw_samples.propagation", "raw_samples.convergence"),
    }
    tx_names = tuple(tx_requirements)
    if any(sections[name]["status"] in {"fail", "helper_only"} for name in tx_names):
        return section("raw_samples", "fail", "source_sample_section_failed")
    if all(sections[name]["status"] == "pass" for name in tx_names):
        if not all(raw_sample_observed(sections[name].get("source_artifact_path"), tx_requirements[name]) for name in tx_names):
            return section("raw_samples", "no_data", "raw_samples_source_observation_unavailable", source_fields=["raw_samples.propagation", "raw_samples.convergence"], claim_type="raw_samples", evidence_class="raw_samples", slo_claim=False)
        return section("raw_samples", "pass", None, source_fields=["raw_samples.propagation", "raw_samples.convergence"], claim_type="raw_samples", evidence_class="raw_samples", slo_claim=False)
    return section("raw_samples", "no_data", "source_contract_validation_unavailable", source_fields=["raw_samples.propagation", "raw_samples.convergence"], claim_type="raw_samples", evidence_class="raw_samples", slo_claim=False)
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
    sections["reorg_metrics"] = metric_section(args, sections)
    sections["raw_samples"] = raw_samples_section(sections)
    sections["deferred_related"] = section("deferred_related", "not_applicable", "deferred_by_rub_227", claim_type="deferred_related_work")
    statuses = {s["status"] for s in sections.values()}
    verdict = "FAIL" if statuses & {"fail", "helper_only"} else "NO_DATA" if "no_data" in statuses else "PASS"
    inputs = {k: (v if k.endswith("_no_data") else str(Path(os.path.realpath(Path(os.path.expanduser(v)))))) for k, v in vars(args).items() if k != "output" and v}
    non_goals = ["No runtime/client/schema/CI changes are claimed by this aggregate report.", "RUB-227 orphan metrics remain deferred/not_applicable."]
    if sections["partition_heal_reorg"].get("behavior_evidence") is not True:
        non_goals.append("Partition/heal/reorg behavior evidence requires source-bound producer sidecars before classification.")
    report = {"schema_version": SCHEMA_VERSION, "verdict": verdict, "generated_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "inputs": inputs, "sections": sections, "claim_inventory": inventory(sections), "non_goals": non_goals}
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
def path_field_targets(value: Any, base: Path) -> list[tuple[Path, bool]]:
    out: list[tuple[Path, bool]] = []; stack: list[tuple[Any, str]] = [(value, "")]  # noqa: E702
    def add_path(text: str, directory: bool = False) -> None:
        raw = (_ for _ in ()).throw(ValueError("path_field_contains_nul")) if "\x00" in text else Path(os.path.expanduser(text)); out.append((Path(os.path.realpath(raw if raw.is_absolute() else base / raw)), directory))  # noqa: E702
    while stack:
        item, prefix = stack.pop()
        if isinstance(item, dict):
            for key, child in item.items():
                dotted = f"{prefix}.{key}" if prefix else key; is_path = key in PATH_FIELD_NAMES or (key.endswith("_path") and key != "tx_path") or dotted in PATH_FIELD_DOTTED_NAMES  # noqa: E702
                if is_path and not isinstance(child, str): raise ValueError("path_field_not_string")  # noqa: E701
                if is_path: add_path(child, key in DIRECTORY_PATH_FIELD_NAMES)  # noqa: E701
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
def path_contains(parent: Path, child: Path) -> bool:
    try:
        child.relative_to(parent)
        return True
    except ValueError:
        return sys.platform == "darwin" and str(child).lower().startswith(str(parent).rstrip(os.sep).lower() + os.sep)
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
        if any(same_path(target, out_path) or (is_dir and path_contains(target, out_path)) for target, is_dir in targets):
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
