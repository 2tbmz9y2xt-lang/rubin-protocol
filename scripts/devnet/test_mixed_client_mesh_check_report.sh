#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
HARNESS="${REPO_ROOT}/scripts/devnet-mixed-client-mesh.sh"
DEV_ENV="${REPO_ROOT}/scripts/dev-env.sh"
VALIDATOR="${REPO_ROOT}/scripts/devnet/validate_mixed_client_evidence.py"
GENERATOR="${REPO_ROOT}/scripts/devnet/generate_mixed_client_devnet_soak_report.py"
GO_MODULE_ROOT="${REPO_ROOT}/clients/go"
MESH_TIMEOUT=1
export GO_MODULE_ROOT
export MESH_TIMEOUT

command -v python3 >/dev/null 2>&1 || { echo "python3 is required" >&2; exit 1; }
[[ -x "${HARNESS}" ]] || { echo "mixed-client mesh harness missing or non-executable: ${HARNESS}" >&2; exit 1; }
[[ -x "${DEV_ENV}" ]] || { echo "dev-env wrapper missing or non-executable: ${DEV_ENV}" >&2; exit 1; }
[[ -r "${VALIDATOR}" ]] || { echo "validator unreadable: ${VALIDATOR}" >&2; exit 1; }
[[ -r "${GENERATOR}" ]] || { echo "generator unreadable: ${GENERATOR}" >&2; exit 1; }

TMP_PARENT="$(cd -- "${TMPDIR:-/tmp}" && pwd -P)" || { echo "test TMPDIR parent is not usable: ${TMPDIR:-/tmp}" >&2; exit 1; }
TMP_ROOT="$(mktemp -d "${TMP_PARENT%/}/rubin-mesh-check-report.XXXXXX")"
cleanup() {
  rm -rf -- "${TMP_ROOT}"
}
trap cleanup EXIT

require_contains() {
  local output="$1" needle="$2" label="$3"
  if [[ "${output}" != *"${needle}"* ]]; then
    echo "FAIL: ${label} missing expected text: ${needle}" >&2
    echo "actual output:" >&2
    printf '%s\n' "${output}" >&2
    exit 1
  fi
}

expect_pass_contains() {
  local label="$1" needle="$2" output
  shift 2
  if ! output="$("$@" 2>&1)"; then
    echo "FAIL: ${label} should pass" >&2
    echo "actual output:" >&2
    printf '%s\n' "${output}" >&2
    exit 1
  fi
  require_contains "${output}" "${needle}" "${label}"
}

expect_fail_contains() {
  local label="$1" needle="$2" output
  shift 2
  if output="$("$@" 2>&1)"; then
    echo "FAIL: ${label} should fail" >&2
    echo "actual output:" >&2
    printf '%s\n' "${output}" >&2
    exit 1
  fi
  require_contains "${output}" "${needle}" "${label}"
}

expect_fail_token() {
  local label="$1" expected_token="$2" output token
  shift 2
  if output="$("$@" 2>&1)"; then
    echo "FAIL: ${label} should fail" >&2
    echo "actual output:" >&2
    printf '%s\n' "${output}" >&2
    exit 1
  fi
  token="$(printf '%s\n' "${output}" | tx_report_reason_token)"
  if [[ "${token}" != "${expected_token}" ]]; then
    echo "FAIL: ${label} produced token ${token}, want ${expected_token}" >&2
    echo "actual output:" >&2
    printf '%s\n' "${output}" >&2
    exit 1
  fi
}

expect_fail_check_token() {
  local label="$1" expected_token="$2" output token
  shift 2
  if output="$("$@" 2>&1)"; then
    echo "FAIL: ${label} should fail" >&2
    echo "actual output:" >&2
    printf '%s\n' "${output}" >&2
    exit 1
  fi
  token="$(printf '%s\n' "${output}" | check_report_reason_token)"
  if [[ "${token}" != "${expected_token}" ]]; then
    echo "FAIL: ${label} produced token ${token}, want ${expected_token}" >&2
    echo "actual output:" >&2
    printf '%s\n' "${output}" >&2
    exit 1
  fi
}

expect_generator_fail_contains() {
  local label="$1" needle="$2" output_path output
  shift 2
  output_path="${TMP_ROOT}/generator-negative.json"
  if output="$(python3 "${GENERATOR}" "$@" --output "${output_path}" 2>&1)"; then
    echo "FAIL: ${label} should fail" >&2
    echo "actual output:" >&2
    printf '%s\n' "${output}" >&2
    exit 1
  fi
  require_contains "${output}" "${needle}" "${label}"
}

extract_check_report() {
  python3 - "${HARNESS}" "${CHECK_REPORT_LIB}" <<'PY'
from pathlib import Path
import sys

src, dst = map(Path, sys.argv[1:3])
lines = src.read_text(encoding="utf-8").splitlines()
start = next(i for i, line in enumerate(lines) if line.startswith("check_report()"))
end = next(i for i, line in enumerate(lines[start:], start) if line.startswith('[[ "${MESH_TIMEOUT}"'))
token_start = next(i for i, line in enumerate(lines) if line.startswith("check_report_reason_token()"))
token_end = next(i for i, line in enumerate(lines[token_start:], token_start) if line.startswith("combined_report_reason_token()"))
capture_start = next(i for i, line in enumerate(lines) if line.startswith("rpc_json()"))
capture_end = next(i for i, line in enumerate(lines[capture_start:], capture_start) if line.startswith("pid_comm()"))
tx_capture_start = next(i for i, line in enumerate(lines) if line.startswith("tx_capture_reason()"))
tx_capture_end = next(i for i, line in enumerate(lines[tx_capture_start:], tx_capture_start) if line.startswith("tx_sidecar_reason()"))
tx_prepare_reason_start = next(i for i, line in enumerate(lines) if line.startswith("rust_restart_prepare_reason()"))
tx_prepare_reason_end = next(i for i, line in enumerate(lines[tx_prepare_reason_start:], tx_prepare_reason_start) if line.startswith("parse_txid()"))
block_reason_start = next(i for i, line in enumerate(lines) if line.startswith("block_inclusion_failure_reason()"))
block_reason_end = next(i for i, line in enumerate(lines[block_reason_start:], block_reason_start) if line.startswith("verify_block_inclusion()"))
mine_reason_start = next(i for i, line in enumerate(lines) if line.startswith("mine_next_http_error_reason()"))
mine_reason_end = next(i for i, line in enumerate(lines[mine_reason_start:], mine_reason_start) if line.startswith("rust_mine_including_tx()"))
rust_mine_start = next(i for i, line in enumerate(lines) if line.startswith("rust_mine_including_tx()"))
rust_mine_end = next(i for i, line in enumerate(lines[rust_mine_start:], rust_mine_start) if line.startswith("tip_matches()"))
Path(dst).write_text("\n".join(lines[start:end] + [""] + lines[token_start:token_end] + [""] + lines[capture_start:capture_end] + [""] + lines[tx_capture_start:tx_capture_end] + [""] + lines[tx_prepare_reason_start:tx_prepare_reason_end] + [""] + lines[block_reason_start:block_reason_end] + [""] + lines[mine_reason_start:mine_reason_end] + [""] + lines[rust_mine_start:rust_mine_end]) + "\n", encoding="utf-8")
PY
}

extract_prepare_tx_chainstate() {
  python3 - "${HARNESS}" "${PREPARE_TX_CHAINSTATE_LIB}" <<'PY'
from pathlib import Path
import sys

src, dst = map(Path, sys.argv[1:3])
lines = src.read_text(encoding="utf-8").splitlines()
start = next(i for i, line in enumerate(lines) if line.startswith("prepare_tx_chainstate()"))
end = next(i for i, line in enumerate(lines[start:], start) if line.startswith("parse_txid()"))
Path(dst).write_text("\n".join(lines[start:end]) + "\n", encoding="utf-8")
PY
}

check_prepare_tx_chainstate_cleanup() {
  local probe="${TMP_ROOT}/prepare-tx-chainstate-cleanup.sh" probe_root="${TMP_ROOT}/prepare-tx-chainstate-cleanup"
  mkdir -p -- "${probe_root}"
  cat >"${probe}" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

source "$1"
probe_root="$2"
KEYGEN_JSON="${probe_root}/keygen.json"
KEYGEN_GO="${probe_root}/keygen.go"
GO_MODULE_ROOT="${probe_root}/go"
DEV_ENV="${probe_root}/dev-env.sh"
GO_NODE_BIN="${probe_root}/rubin-node"
GO_DIR="${probe_root}/go-node"
RUST_DIR="${probe_root}/rust-node"
MINE_LOG="${probe_root}/mine-go.log"
TMPDIR="${probe_root}/tmp"
TX_REASON=""
TX_FROM_KEY_DIR=""
TX_FROM_KEY_FILE=""
TX_TO_KEY=""
mkdir -p -- "${TMPDIR}" "${GO_MODULE_ROOT}" "${GO_DIR}" "${RUST_DIR}"

build_go_txgen() { :; }
write_keygen() { :; }
disable_xtrace_for_secret() { return 1; }
restore_xtrace_after_secret() { :; }
make_tx_secret_dir() {
  mkdir -p -- "${probe_root}/secret"
  printf '%s\n' "${probe_root}/secret"
}
cleanup_tx_from_key_file() { :; }
bounded_mesh() {
  printf '{"malformed":true}\n'
  printf 'keygen stderr\n' >&2
}
parse_keygen_material() { return 9; }
keygen_material_reason() { printf '%s\n' go_submit_keygen_material_malformed; }

set +e
prepare_tx_chainstate
rc=$?
set -e
[[ ${rc} -ne 0 ]] || { echo "FAIL: prepare_tx_chainstate should fail on malformed keygen material" >&2; exit 1; }
[[ "${TX_REASON}" == "go_submit_keygen_material_malformed" ]] || { echo "FAIL: unexpected TX_REASON: ${TX_REASON}" >&2; exit 1; }
[[ ! -e "${KEYGEN_JSON}.raw" ]] || { echo "FAIL: keygen raw sidecar survived failure" >&2; exit 1; }
[[ ! -e "${KEYGEN_JSON}.stderr" ]] || { echo "FAIL: keygen stderr sidecar survived failure" >&2; exit 1; }
SH
  bash "${probe}" "${PREPARE_TX_CHAINSTATE_LIB}" "${probe_root}"
}

write_reports() {
  python3 - "${TMP_ROOT}" <<'PY'
from pathlib import Path
import hashlib
import json
import stat
import sys

root = Path(sys.argv[1])
artifact_root = root / "artifact-root"
artifact_root.mkdir()
(artifact_root / "node-go").mkdir()
(artifact_root / "node-rust").mkdir()
go_bin = artifact_root / "rubin-node-go"
rust_bin = artifact_root / "rubin-node-rust"
for path in (go_bin, rust_bin):
    path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)

def compact_size(n: int) -> bytes:
    if n < 0xfd:
        return bytes([n])
    if n <= 0xffff:
        return b"\xfd" + n.to_bytes(2, "little")
    if n <= 0xffffffff:
        return b"\xfe" + n.to_bytes(4, "little")
    return b"\xff" + n.to_bytes(8, "little")

def sha3(data: bytes) -> bytes:
    return hashlib.sha3_256(data).digest()

def read_compact_size(buf: bytes, off: int) -> tuple[int, int]:
    first = buf[off]
    if first < 0xfd:
        return first, off + 1
    if first == 0xfd:
        return int.from_bytes(buf[off + 1:off + 3], "little"), off + 3
    if first == 0xfe:
        return int.from_bytes(buf[off + 1:off + 5], "little"), off + 5
    return int.from_bytes(buf[off + 1:off + 9], "little"), off + 9

def txid_kind0(txb: bytes) -> bytes:
    off = 0
    off += 4  # version
    tx_kind = txb[off]
    off += 1
    if tx_kind != 0:
        raise ValueError("synthetic test only supports tx_kind=0")
    off += 8  # nonce
    n_inputs, off = read_compact_size(txb, off)
    for _ in range(n_inputs):
        off += 32 + 4
        script_len, off = read_compact_size(txb, off)
        off += script_len + 4
    n_outputs, off = read_compact_size(txb, off)
    for _ in range(n_outputs):
        off += 8 + 2
        covenant_len, off = read_compact_size(txb, off)
        off += covenant_len
    off += 4  # locktime
    return sha3(txb[:off])

def build_synthetic_submitted_tx() -> bytes:
    return b"".join([
        (1).to_bytes(4, "little"),
        b"\x00",
        (7).to_bytes(8, "little"),
        compact_size(1),
        b"\x11" * 32,
        (0).to_bytes(4, "little"),
        compact_size(0),
        (0).to_bytes(4, "little"),
        compact_size(1),
        (0).to_bytes(8, "little"),
        (0x0002).to_bytes(2, "little"),
        compact_size(1),
        b"\x42",
        (0).to_bytes(4, "little"),
        compact_size(0),
        compact_size(0),
    ])

tx_bytes = build_synthetic_submitted_tx()
tx_hex = tx_bytes.hex()
txid = txid_kind0(tx_bytes).hex()
go_rpc = "127.0.0.1:51001"
go_p2p = "127.0.0.1:51002"
rust_rpc = "127.0.0.1:51003"
rust_p2p = "127.0.0.1:51004"
rust_outbound = "127.0.0.1:51005"
go_started = "2026-05-12T10:00:00Z"
rust_started = "2026-05-12T10:00:01Z"

def dump(path: Path, data: object) -> None:
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")

def node(impl: str) -> dict:
    is_go = impl == "go"
    name = "node-go" if is_go else "node-rust"
    binary = go_bin if is_go else rust_bin
    argv = [
        str(binary),
        "--network",
        "devnet",
        "--datadir",
        str(artifact_root / name),
        "--bind",
        "127.0.0.1:0",
        "--rpc-bind",
        "127.0.0.1:0",
    ]
    if not is_go:
        argv.extend(["--peer", go_p2p])
    return {
        "binary": str(binary),
        "command": " ".join(argv),
        "command_argv": argv,
        "implementation": impl,
        "name": name,
        "p2p_endpoint": go_p2p if is_go else rust_p2p,
        "p2p_endpoint_process_backed": True,
        "pid": 41001 if is_go else 41002,
        "process_alive": True,
        "process_comm": "rubin-node-go" if is_go else "rubin-node-rust",
        "rpc_endpoint": go_rpc if is_go else rust_rpc,
        "rpc_endpoint_process_backed": True,
        "started_at": go_started if is_go else rust_started,
    }

nodes = [node("go"), node("rust")]
connectivity = {
    "bidirectional_observed": True,
    "counterpart_links": {
        "go_peer_snapshot_expected_addr": rust_outbound,
        "rust_outbound_local_addr": rust_outbound,
        "rust_outbound_pid": 41002,
        "rust_outbound_remote_addr": go_p2p,
        "rust_peer_snapshot_expected_addr": go_p2p,
    },
    "go_peer_snapshot": {"count": 1, "peers": [{"addr": rust_outbound, "handshake_complete": True}]},
    "go_to_rust": True,
    "rust_peer_snapshot": {"count": 1, "peers": [{"addr": go_p2p, "handshake_complete": True}]},
    "rust_to_go": True,
}
final_verification = {
    "peer_snapshots_rechecked": True,
    "process_identity_rechecked": True,
    "producer_side": True,
    "rust_outbound_link_rechecked": True,
    "rust_outbound_local_addr": rust_outbound,
    "rust_outbound_pid": 41002,
    "rust_outbound_remote_addr": go_p2p,
}


def raw_samples(prop_direction=None, prop_elapsed=2, conv_direction=None, conv_elapsed=3):
    def bucket(direction, elapsed, sample_kind):
        if direction is None:
            return {
                "classification": "not_requested",
                "path_direction": None,
                "reason": f"{sample_kind}_sample_not_requested_by_scenario",
                "samples": [],
                "unit": "seconds",
            }
        source_impl, target_impl = direction.split("->")
        sample = {
            "classification": "observed",
            "elapsed": elapsed,
            "path_direction": direction,
            "source": f"node-{source_impl}",
            "target": f"node-{target_impl}",
            "tx_id": txid,
            "unit": "seconds",
        }
        if sample_kind == "convergence":
            sample.update({"block_hash": block_hash, "height": height})
        return {
            "classification": "observed",
            "path_direction": direction,
            "reason": None,
            "samples": [sample],
            "unit": "seconds",
        }
    return {
        "schema_version": "rubin-devnet-process-soak-raw-samples-v1",
        "semantics": "raw samples only; no SLO threshold or pass claim",
        "propagation": bucket(prop_direction, prop_elapsed, "propagation"),
        "convergence": bucket(conv_direction, conv_elapsed, "convergence"),
    }


mesh_marker = artifact_root / "mesh-marker.json"
dump(mesh_marker, {
    "evidence_type": "mixed_client_process_soak",
    "failure_reason": "schema v1 PASS requires tx_path; mesh PASS lives in sibling report",
    "participants": [
        {"endpoint": go_rpc, "implementation": "go", "name": "node-go", "started_at": go_started},
        {"endpoint": rust_rpc, "implementation": "rust", "name": "node-rust", "started_at": rust_started},
    ],
    "scenario": "mixed_client_mesh_schema_marker",
    "schema_version": "rubin-mixed-client-devnet-evidence-v1",
    "verdict": "FAIL",
})
mesh_report = {
    "artifact_root": str(artifact_root),
    "final_verification": final_verification,
    "legacy_schema_compatibility": {
        "authoritative": False,
        "marker_path": str(mesh_marker),
        "purpose": "schema-valid legacy artifact only; not the mesh report verdict",
        "reason": "existing mixed_client_evidence_v1 PASS requires tx_path",
    },
    "nodes": nodes,
    "peer_connectivity": connectivity,
    "raw_samples": raw_samples(),
    "scenario": "mixed_client_mesh",
    "verdict": "PASS",
}
dump(root / "mesh-report.json", mesh_report)

restart_marker = artifact_root / "restart-marker.json"
restart = {
    "catch_up_height": 8,
    "pre_restart_height": 7,
    "stopped_node": "node-rust",
}
restart_info = {
    "catch_up_has_tip": True,
    "catch_up_height": 8,
    "catch_up_tip": "bb" * 32,
    "catch_up_tip_path": str(artifact_root / "rust-catch-up-tip.json"),
    "datadir": str(artifact_root / "node-rust"),
    "go_target_has_tip": True,
    "go_target_height": 8,
    "go_target_mine_next_path": str(artifact_root / "go-restart-mine-next.json"),
    "go_target_tip": "bb" * 32,
    "go_target_tip_path": str(artifact_root / "go-restart-target-tip.json"),
    "go_target_tx_count": 1,
    "new_command_argv": node("rust")["command_argv"],
    "new_p2p_endpoint": rust_p2p,
    "new_pid": 41002,
    "new_rpc_endpoint": rust_rpc,
    "new_started_at": rust_started,
    "old_command_argv": node("rust")["command_argv"],
    "old_p2p_endpoint": "127.0.0.1:51031",
    "old_pid": 41020,
    "old_pid_stopped": True,
    "old_rpc_endpoint": "127.0.0.1:51030",
    "old_started_at": "2026-05-12T09:59:58Z",
    "peer_reconnect_observed": True,
    "pre_restart_has_tip": True,
    "pre_restart_height": 7,
    "pre_restart_tip": "aa" * 32,
    "pre_restart_tip_path": str(artifact_root / "rust-pre-restart-tip.json"),
    "same_datadir": True,
}
dump(artifact_root / "rust-pre-restart-tip.json", {"best_known_height": 7, "has_tip": True, "height": 7, "implementation": "rust", "in_ibd": False, "request_path": "/get_tip", "rpc_endpoint": "127.0.0.1:51030", "tip_hash": "aa" * 32})
dump(artifact_root / "go-restart-mine-next.json", {"block_hash": "bb" * 32, "height": 8, "implementation": "go", "mined": True, "nonce": 1777000001, "request_path": "/mine_next", "rpc_endpoint": go_rpc, "timestamp": 1777000000, "tx_count": 1})
dump(artifact_root / "go-restart-target-tip.json", {"best_known_height": 8, "has_tip": True, "height": 8, "implementation": "go", "in_ibd": False, "request_path": "/get_tip", "rpc_endpoint": go_rpc, "tip_hash": "bb" * 32})
dump(artifact_root / "rust-catch-up-tip.json", {"best_known_height": 8, "has_tip": True, "height": 8, "implementation": "rust", "in_ibd": False, "request_path": "/get_tip", "rpc_endpoint": rust_rpc, "tip_hash": "bb" * 32})
dump(restart_marker, {
    "evidence_type": "mixed_client_process_soak",
    "failure_reason": "schema v1 PASS requires tx_path; restart PASS lives in sibling report",
    "participants": [
        {"endpoint": go_rpc, "implementation": "go", "name": "node-go", "started_at": go_started},
        {"endpoint": rust_rpc, "implementation": "rust", "name": "node-rust", "started_at": rust_started},
    ],
    "restart": restart,
    "scenario": "mixed_client_mesh_schema_marker",
    "schema_version": "rubin-mixed-client-devnet-evidence-v1",
    "verdict": "FAIL",
})
restart_report = {
    **mesh_report,
    "artifact_created_at_utc": "2026-05-12T10:00:02Z",
    "legacy_schema_compatibility": {
        "authoritative": False,
        "marker_path": str(restart_marker),
        "purpose": "schema-valid legacy artifact only; not the Rust restart report verdict",
        "reason": "existing mixed_client_evidence_v1 PASS requires tx_path; Rust restart PASS lives in this report",
    },
    "restart": restart,
    "run_id": artifact_root.name,
    "rust_restart": restart_info,
    "scenario": "mixed_client_rust_restart",
}
dump(root / "restart-report.json", restart_report)

tx_marker = artifact_root / "tx-marker.json"
tx_path = {"observed_at": ["node-rust"], "submitted_at": "node-go", "tx_id": txid}
dump(tx_marker, {
    "evidence_type": "mixed_client_process_soak",
    "participants": [
        {"endpoint": go_rpc, "implementation": "go", "name": "node-go", "started_at": go_started},
        {"endpoint": rust_rpc, "implementation": "rust", "name": "node-rust", "started_at": rust_started},
    ],
    "scenario": "mixed_client_mesh_schema_marker",
    "schema_version": "rubin-mixed-client-devnet-evidence-v1",
    "tx_path": tx_path,
    "verdict": "PASS",
})
for impl, endpoint, prefix in (("go", go_rpc, "go"), ("rust", rust_rpc, "rust")):
    status_path = artifact_root / f"{prefix}-tx-status.json"
    get_path = artifact_root / f"{prefix}-get-tx.json"
    dump(status_path, {
        "implementation": impl,
        "request_path": f"/tx_status?txid={txid}",
        "rpc_endpoint": endpoint,
        "status": "pending",
        "txid": txid,
    })
    dump(get_path, {
        "found": True,
        "implementation": impl,
        "raw_hex": tx_hex,
        "request_path": f"/get_tx?txid={txid}",
        "rpc_endpoint": endpoint,
        "txid": txid,
    })
for impl, endpoint, prefix in (("rust", rust_rpc, "rust-submit"), ("go", go_rpc, "go-accept")):
    dump(artifact_root / f"{prefix}-tx-status.json", {
        "implementation": impl,
        "request_path": f"/tx_status?txid={txid}",
        "rpc_endpoint": endpoint,
        "status": "pending",
        "txid": txid,
    })
    dump(artifact_root / f"{prefix}-get-tx.json", {
        "found": True,
        "implementation": impl,
        "raw_hex": tx_hex,
        "request_path": f"/get_tx?txid={txid}",
        "rpc_endpoint": endpoint,
        "txid": txid,
    })
height = 102
tx_count = 2

def merkle(ids: list[bytes], leaf_tag: int, node_tag: int) -> bytes:
    level = [sha3(bytes([leaf_tag]) + item) for item in ids]
    while len(level) > 1:
        next_level = []
        i = 0
        while i < len(level):
            if i == len(level) - 1:
                next_level.append(level[i])
                i += 1
            else:
                next_level.append(sha3(bytes([node_tag]) + level[i] + level[i + 1]))
                i += 2
        level = next_level
    return level[0]

def coinbase_with_witness_commitment(block_height: int, non_coinbase_txs: list[bytes]) -> tuple[bytes, bytes, bytes]:
    wtxids = [bytes(32)] + [sha3(txb) for txb in non_coinbase_txs]
    witness_root = merkle(wtxids, 0x02, 0x03)
    commitment = sha3(b"RUBIN-WITNESS/" + witness_root)
    core = b"".join([
        (1).to_bytes(4, "little"),
        b"\x00",
        (0).to_bytes(8, "little"),
        compact_size(1),
        bytes(32),
        (0xffffffff).to_bytes(4, "little"),
        compact_size(0),
        (0xffffffff).to_bytes(4, "little"),
        compact_size(1),
        (0).to_bytes(8, "little"),
        (0x0002).to_bytes(2, "little"),
        compact_size(len(commitment)),
        commitment,
        block_height.to_bytes(4, "little"),
    ])
    full = core + compact_size(0) + compact_size(0)
    return full, sha3(core), sha3(full)

def build_basic_block(non_coinbase_hex: str, block_height: int, prev_hash=None) -> tuple[str, str]:
    non_coinbase = bytes.fromhex(non_coinbase_hex)
    non_coinbase_txid = txid_kind0(non_coinbase)
    if non_coinbase_hex == tx_hex and non_coinbase_txid.hex() != txid:
        raise ValueError("synthetic txid fixture drift")
    coinbase, coinbase_txid, _ = coinbase_with_witness_commitment(block_height, [non_coinbase])
    txids = [coinbase_txid, non_coinbase_txid]
    merkle_root = merkle(txids, 0x00, 0x01)
    header = b"".join([
        (1).to_bytes(4, "little"),
        bytes(32) if prev_hash is None else bytes.fromhex(prev_hash),
        merkle_root,
        (1).to_bytes(8, "little"),
        b"\xff" * 32,
        (1).to_bytes(8, "little"),
    ])
    block = header + compact_size(2) + coinbase + non_coinbase
    return block.hex(), sha3(header).hex()

def corrupt_merkle_block(block_hex_value: str) -> tuple[str, str]:
    block = bytearray.fromhex(block_hex_value)
    block[4 + 32] ^= 0x01
    return bytes(block).hex(), sha3(bytes(block[:116])).hex()

def block_sidecar(impl: str, endpoint: str, block_hex_value: str, block_hash_value: str, sidecar_height: int = height) -> dict:
    return {"block_hex": block_hex_value, "canonical": True, "hash": block_hash_value, "height": sidecar_height, "implementation": impl, "request_path": f"/get_block?height={sidecar_height}", "rpc_endpoint": endpoint}
def tip_sidecar(impl: str, endpoint: str, block_hash_value: str, sidecar_height: int) -> dict:
    return {"best_known_height": sidecar_height, "has_tip": True, "height": sidecar_height, "implementation": impl, "in_ibd": False, "request_path": "/get_tip", "rpc_endpoint": endpoint, "tip_hash": block_hash_value}
def mine_sidecar(impl: str, endpoint: str, block_hash_value: str, sidecar_height: int, count: int = tx_count) -> dict:
    return {"block_hash": block_hash_value, "height": sidecar_height, "implementation": impl, "mined": True, "nonce": 0, "request_path": "/mine_next", "rpc_endpoint": endpoint, "timestamp": 1, "tx_count": count}
def peer_snapshot(addr):
    peers = [] if addr is None else [{"addr": addr, "handshake_complete": True}]
    return {"count": len(peers), "peers": peers}

common_height = height - 1
rust_win_height = height + 1
common_block_hex, common_hash = build_basic_block(tx_hex, common_height)
block_hex, block_hash = build_basic_block(tx_hex, height, common_hash)
mutated_tx = bytearray.fromhex(tx_hex)
mutated_tx[5] ^= 0x01
missing_tx_block_hex, missing_tx_hash = build_basic_block(mutated_tx.hex(), height)
partition_rust_block_1_hex, partition_rust_block_1_hash = build_basic_block(mutated_tx.hex(), height, common_hash)
rust_win_block_hex, rust_win_hash = build_basic_block(mutated_tx.hex(), rust_win_height, partition_rust_block_1_hash)
disconnected_go_block_hex, disconnected_go_hash = build_basic_block(tx_hex, height)
corrupt_block_hex, corrupt_block_hash = corrupt_merkle_block(block_hex)

dump(artifact_root / "rust-mined-block.json", block_sidecar("rust", rust_rpc, block_hex, block_hash))
dump(artifact_root / "go-converged-block.json", block_sidecar("go", go_rpc, block_hex, block_hash))
dump(artifact_root / "go-converged-wrong-source-block.json", block_sidecar("rust", rust_rpc, block_hex, block_hash))
dump(artifact_root / "go-converged-malformed-block.json", {"block_hex": "00", "canonical": True, "hash": block_hash, "height": height, "implementation": "go", "request_path": f"/get_block?height={height}", "rpc_endpoint": go_rpc})
dump(artifact_root / "rust-missing-tx-block.json", block_sidecar("rust", rust_rpc, missing_tx_block_hex, missing_tx_hash))
dump(artifact_root / "go-converged-missing-tx-block.json", block_sidecar("go", go_rpc, missing_tx_block_hex, missing_tx_hash))
dump(artifact_root / "rust-corrupt-merkle-block.json", block_sidecar("rust", rust_rpc, corrupt_block_hex, corrupt_block_hash))
dump(artifact_root / "go-corrupt-merkle-block.json", block_sidecar("go", go_rpc, corrupt_block_hex, corrupt_block_hash))
dump(artifact_root / "go-mined-block.json", block_sidecar("go", go_rpc, block_hex, block_hash))
dump(artifact_root / "rust-converged-block.json", block_sidecar("rust", rust_rpc, block_hex, block_hash))
dump(artifact_root / "rust-converged-wrong-source-block.json", block_sidecar("go", go_rpc, block_hex, block_hash))
dump(artifact_root / "rust-converged-malformed-block.json", {"block_hex": "00", "canonical": True, "hash": block_hash, "height": height, "implementation": "rust", "request_path": f"/get_block?height={height}", "rpc_endpoint": rust_rpc})
dump(artifact_root / "go-missing-tx-block.json", block_sidecar("go", go_rpc, missing_tx_block_hex, missing_tx_hash))
dump(artifact_root / "rust-converged-missing-tx-block.json", block_sidecar("rust", rust_rpc, missing_tx_block_hex, missing_tx_hash))
dump(artifact_root / "rust-mine-next.json", {"block_hash": block_hash, "height": height, "implementation": "rust", "mined": True, "nonce": 0, "request_path": "/mine_next", "rpc_endpoint": rust_rpc, "timestamp": 1, "tx_count": tx_count})
dump(artifact_root / "rust-missing-tx-mine-next.json", {"block_hash": missing_tx_hash, "height": height, "implementation": "rust", "mined": True, "nonce": 0, "request_path": "/mine_next", "rpc_endpoint": rust_rpc, "timestamp": 1, "tx_count": tx_count})
dump(artifact_root / "rust-corrupt-merkle-mine-next.json", {"block_hash": corrupt_block_hash, "height": height, "implementation": "rust", "mined": True, "nonce": 0, "request_path": "/mine_next", "rpc_endpoint": rust_rpc, "timestamp": 1, "tx_count": tx_count})
dump(artifact_root / "rust-tx-count-mismatch-mine-next.json", {"block_hash": block_hash, "height": height, "implementation": "rust", "mined": True, "nonce": 0, "request_path": "/mine_next", "rpc_endpoint": rust_rpc, "timestamp": 1, "tx_count": 3})
dump(artifact_root / "go-mine-next.json", {"block_hash": block_hash, "height": height, "implementation": "go", "mined": True, "nonce": 0, "request_path": "/mine_next", "rpc_endpoint": go_rpc, "timestamp": 1, "tx_count": tx_count})
dump(artifact_root / "go-missing-tx-mine-next.json", {"block_hash": missing_tx_hash, "height": height, "implementation": "go", "mined": True, "nonce": 0, "request_path": "/mine_next", "rpc_endpoint": go_rpc, "timestamp": 1, "tx_count": tx_count})
dump(artifact_root / "go-converge-tip.json", {"best_known_height": height, "has_tip": True, "height": height, "implementation": "go", "in_ibd": False, "request_path": "/get_tip", "rpc_endpoint": go_rpc, "tip_hash": block_hash})
dump(artifact_root / "go-missing-tx-tip.json", {"best_known_height": height, "has_tip": True, "height": height, "implementation": "go", "in_ibd": False, "request_path": "/get_tip", "rpc_endpoint": go_rpc, "tip_hash": missing_tx_hash})
dump(artifact_root / "go-corrupt-merkle-tip.json", {"best_known_height": height, "has_tip": True, "height": height, "implementation": "go", "in_ibd": False, "request_path": "/get_tip", "rpc_endpoint": go_rpc, "tip_hash": corrupt_block_hash})
dump(artifact_root / "rust-converge-tip.json", {"best_known_height": height, "has_tip": True, "height": height, "implementation": "rust", "in_ibd": False, "request_path": "/get_tip", "rpc_endpoint": rust_rpc, "tip_hash": block_hash})
dump(artifact_root / "rust-missing-tx-tip.json", {"best_known_height": height, "has_tip": True, "height": height, "implementation": "rust", "in_ibd": False, "request_path": "/get_tip", "rpc_endpoint": rust_rpc, "tip_hash": missing_tx_hash})
partition_proxy = "127.0.0.1:53010"
partition_go_peer = "127.0.0.1:53011"
partition_nodes = json.loads(json.dumps(nodes))
partition_nodes[1]["command_argv"][-1] = partition_proxy
partition_nodes[1]["command"] = " ".join(partition_nodes[1]["command_argv"])
partition_peer_connectivity = {"bidirectional_observed": False, "counterpart_links": {"go_peer_snapshot_expected_addr": None, "rust_outbound_local_addr": None, "rust_outbound_pid": None, "rust_outbound_remote_addr": None, "rust_peer_snapshot_expected_addr": None}, "go_peer_snapshot": {"count": 0, "peers": []}, "go_to_rust": False, "rust_peer_snapshot": {"count": 0, "peers": []}, "rust_to_go": False}
partition_final = {"peer_snapshots_rechecked": True, "process_identity_rechecked": True, "producer_side": True, "rust_outbound_link_rechecked": False, "rust_outbound_local_addr": None, "rust_outbound_pid": None, "rust_outbound_remote_addr": None}
dump(artifact_root / "partition-common-go-mine.json", mine_sidecar("go", go_rpc, common_hash, common_height))
dump(artifact_root / "partition-common-go-block.json", block_sidecar("go", go_rpc, common_block_hex, common_hash, common_height))
dump(artifact_root / "partition-common-rust-tip.json", tip_sidecar("rust", rust_rpc, common_hash, common_height))
dump(artifact_root / "partition-common-rust-block.json", block_sidecar("rust", rust_rpc, common_block_hex, common_hash, common_height))
dump(artifact_root / "partition-go-mine.json", mine_sidecar("go", go_rpc, block_hash, height))
dump(artifact_root / "partition-go-tip.json", tip_sidecar("go", go_rpc, block_hash, height))
dump(artifact_root / "partition-go-block.json", block_sidecar("go", go_rpc, block_hex, block_hash))
dump(artifact_root / "partition-rust-mine-1.json", mine_sidecar("rust", rust_rpc, partition_rust_block_1_hash, height))
dump(artifact_root / "partition-rust-block-1.json", block_sidecar("rust", rust_rpc, partition_rust_block_1_hex, partition_rust_block_1_hash))
dump(artifact_root / "partition-rust-same-fork-mine.json", mine_sidecar("rust", rust_rpc, block_hash, height))
dump(artifact_root / "partition-rust-same-fork-block.json", block_sidecar("rust", rust_rpc, block_hex, block_hash))
dump(artifact_root / "partition-rust-mine-2.json", mine_sidecar("rust", rust_rpc, rust_win_hash, rust_win_height))
dump(artifact_root / "partition-rust-tip.json", tip_sidecar("rust", rust_rpc, rust_win_hash, rust_win_height))
dump(artifact_root / "partition-rust-block-2.json", block_sidecar("rust", rust_rpc, rust_win_block_hex, rust_win_hash, rust_win_height))
dump(artifact_root / "partition-final-go-tip.json", tip_sidecar("go", go_rpc, rust_win_hash, rust_win_height))
dump(artifact_root / "partition-final-rust-tip.json", tip_sidecar("rust", rust_rpc, rust_win_hash, rust_win_height))
dump(artifact_root / "partition-go-reorg-parent-block.json", block_sidecar("go", go_rpc, partition_rust_block_1_hex, partition_rust_block_1_hash))
dump(artifact_root / "partition-go-losing-reorg-parent-block.json", block_sidecar("go", go_rpc, block_hex, block_hash))
dump(artifact_root / "partition-go-reorg-parent-forged-block.json", block_sidecar("go", go_rpc, block_hex, partition_rust_block_1_hash))
dump(artifact_root / "partition-go-disconnected-mine.json", mine_sidecar("go", go_rpc, disconnected_go_hash, height))
dump(artifact_root / "partition-go-disconnected-tip.json", tip_sidecar("go", go_rpc, disconnected_go_hash, height))
dump(artifact_root / "partition-go-disconnected-block.json", block_sidecar("go", go_rpc, disconnected_go_block_hex, disconnected_go_hash))
dump(artifact_root / "partition-final-go-block.json", block_sidecar("go", go_rpc, rust_win_block_hex, rust_win_hash, rust_win_height))
dump(artifact_root / "partition-final-rust-block.json", block_sidecar("rust", rust_rpc, rust_win_block_hex, rust_win_hash, rust_win_height))
(artifact_root / "partition-go-metrics.prom").write_text("rubin_node_reorg_total 1\nrubin_node_last_reorg_depth 1\n", encoding="utf-8")
(artifact_root / "partition-go-metrics-timestamp.prom").write_text("rubin_node_reorg_total 1 123\nrubin_node_last_reorg_depth 1 123\n", encoding="utf-8")
for name, addr in (("partition-pre-rust-peers.json", partition_proxy), ("partition-pre-go-peers.json", partition_go_peer), ("partition-drop-rust-peers.json", None), ("partition-drop-go-peers.json", None), ("partition-fork-rust-peers.json", None), ("partition-fork-go-peers.json", None), ("partition-heal-rust-peers.json", partition_proxy), ("partition-heal-go-peers.json", partition_go_peer)):
    dump(artifact_root / name, peer_snapshot(addr))
bad_peer_snapshot = peer_snapshot(partition_proxy); bad_peer_snapshot["count"] = True; dump(artifact_root / "partition-pre-rust-peers-bool-count.json", bad_peer_snapshot)
partition_observations = {"pre_partition": {"common_go_block": str(artifact_root / "partition-common-go-block.json"), "common_go_mine": str(artifact_root / "partition-common-go-mine.json"), "common_rust_block": str(artifact_root / "partition-common-rust-block.json"), "common_rust_tip": str(artifact_root / "partition-common-rust-tip.json"), "go_peer_snapshot": str(artifact_root / "partition-pre-go-peers.json"), "rust_peer_snapshot": str(artifact_root / "partition-pre-rust-peers.json")}, "partition": {"go_peer_snapshot": str(artifact_root / "partition-drop-go-peers.json"), "rust_peer_snapshot": str(artifact_root / "partition-drop-rust-peers.json")}, "fork": {"go_block": str(artifact_root / "partition-go-block.json"), "go_mine": str(artifact_root / "partition-go-mine.json"), "go_peer_snapshot": str(artifact_root / "partition-fork-go-peers.json"), "go_tip": str(artifact_root / "partition-go-tip.json"), "rust_block_1": str(artifact_root / "partition-rust-block-1.json"), "rust_block_2": str(artifact_root / "partition-rust-block-2.json"), "rust_mine_1": str(artifact_root / "partition-rust-mine-1.json"), "rust_mine_2": str(artifact_root / "partition-rust-mine-2.json"), "rust_peer_snapshot": str(artifact_root / "partition-fork-rust-peers.json"), "rust_tip": str(artifact_root / "partition-rust-tip.json")}, "heal": {"go_peer_snapshot": str(artifact_root / "partition-heal-go-peers.json"), "rust_peer_snapshot": str(artifact_root / "partition-heal-rust-peers.json")}, "reorg": {"go_metrics": str(artifact_root / "partition-go-metrics.prom"), "go_reorg_parent_block": str(artifact_root / "partition-go-reorg-parent-block.json"), "go_tip": str(artifact_root / "partition-final-go-tip.json"), "go_tip_block": str(artifact_root / "partition-final-go-block.json"), "rust_tip": str(artifact_root / "partition-final-rust-tip.json"), "rust_tip_block": str(artifact_root / "partition-final-rust-block.json")}}
partition_report = {**mesh_report, "artifact_created_at_utc": "2026-05-12T10:00:02Z", "final_verification": partition_final, "legacy_schema_compatibility": {**mesh_report["legacy_schema_compatibility"], "marker_path": str(mesh_marker)}, "nodes": partition_nodes, "observations": partition_observations, "peer_connectivity": partition_peer_connectivity, "proof": {"final_go_tip": {"height": rust_win_height, "hash": rust_win_hash}, "final_rust_tip": {"height": rust_win_height, "hash": rust_win_hash}, "fork_diverged": True, "go_partition_tip": {"height": height, "hash": block_hash}, "go_reorg_metrics": {"rubin_node_last_reorg_depth": 1, "rubin_node_reorg_total": 1}, "heal_go_peer_addr": partition_go_peer, "heal_restored_peer_state": True, "partition_changed_peer_state": True, "partition_proxy_endpoint": partition_proxy, "pre_partition_go_peer_addr": partition_go_peer, "process_identity_rechecked_after_heal": True, "reorg_converged": True, "rust_winning_tip": {"height": rust_win_height, "hash": rust_win_hash}}, "run_id": artifact_root.name, "scenario": "mixed_client_partition_heal_reorg"}
dump(root / "partition-report.json", partition_report)
bad_partition = json.loads(json.dumps(partition_report)); bad_partition["observations"]["reorg"]["go_reorg_parent_block"] = str(artifact_root / "partition-go-losing-reorg-parent-block.json"); dump(root / "partition-losing-parent-report.json", bad_partition)
bad_partition = json.loads(json.dumps(partition_report)); bad_partition["observations"]["reorg"]["go_reorg_parent_block"] = str(artifact_root / "partition-go-reorg-parent-forged-block.json"); dump(root / "partition-forged-parent-payload-report.json", bad_partition)
bad_partition = json.loads(json.dumps(partition_report)); bad_partition["proof"]["rust_winning_tip"] = {"height": height, "hash": missing_tx_hash}; bad_partition["proof"]["final_go_tip"] = {"height": height, "hash": missing_tx_hash}; bad_partition["proof"]["final_rust_tip"] = {"height": height, "hash": missing_tx_hash}; dump(root / "partition-same-height-winner-report.json", bad_partition)
bad_partition = json.loads(json.dumps(partition_report)); bad_partition["peer_connectivity"]["bidirectional_observed"] = True; dump(root / "partition-peer-connectivity-overclaim-report.json", bad_partition)
bad_partition = json.loads(json.dumps(partition_report)); bad_partition["peer_connectivity"]["go_peer_snapshot"]["count"] = False; dump(artifact_root / "partition-peer-connectivity-bool-count-report.json", bad_partition)
bad_partition = json.loads(json.dumps(partition_report)); bad_partition["final_verification"]["rust_outbound_link_rechecked"] = True; dump(root / "partition-final-verification-overclaim-report.json", bad_partition)
bad_partition = json.loads(json.dumps(partition_report)); bad_partition["nodes"][0]["rpc_endpoint_process_backed"] = False; dump(artifact_root / "partition-unbacked-node-report.json", bad_partition)
bad_partition = json.loads(json.dumps(partition_report)); bad_partition["nodes"][1]["command_argv"][-1] = go_p2p; bad_partition["nodes"][1]["command"] = " ".join(bad_partition["nodes"][1]["command_argv"]); dump(artifact_root / "partition-rust-peer-argv-mismatch-report.json", bad_partition)
bad_partition = json.loads(json.dumps(partition_report)); bad_partition["proof"]["go_partition_tip"] = {"height": height, "hash": disconnected_go_hash}; bad_partition["observations"]["fork"]["go_mine"] = str(artifact_root / "partition-go-disconnected-mine.json"); bad_partition["observations"]["fork"]["go_tip"] = str(artifact_root / "partition-go-disconnected-tip.json"); bad_partition["observations"]["fork"]["go_block"] = str(artifact_root / "partition-go-disconnected-block.json"); dump(root / "partition-disconnected-go-fork-report.json", bad_partition)
bad_partition = json.loads(json.dumps(partition_report)); bad_partition["observations"]["fork"]["rust_mine_1"] = str(artifact_root / "partition-rust-same-fork-mine.json"); bad_partition["observations"]["fork"]["rust_block_1"] = str(artifact_root / "partition-rust-same-fork-block.json"); dump(root / "partition-same-first-rust-fork-report.json", bad_partition)
bad_partition = json.loads(json.dumps(partition_report)); bad_partition["proof"]["go_reorg_metrics"]["rubin_node_reorg_total"] = 2; dump(artifact_root / "partition-forged-metrics-report.json", bad_partition)
bad_partition = json.loads(json.dumps(partition_report)); bad_partition["observations"]["pre_partition"]["rust_peer_snapshot"] = str(artifact_root / "partition-pre-rust-peers-bool-count.json"); dump(artifact_root / "partition-peer-sidecar-bool-count-report.json", bad_partition)
bad_partition = json.loads(json.dumps(partition_report)); bad_partition["observations"]["reorg"]["go_metrics"] = str(artifact_root / "partition-go-metrics-timestamp.prom"); dump(artifact_root / "partition-metrics-timestamp-report.json", bad_partition)
tx_report = {
    **mesh_report,
    "go_submit": {
        "get_tx_path": str(artifact_root / "go-get-tx.json"),
        "rpc_endpoint": go_rpc,
        "tx_hex": tx_hex,
        "tx_status_path": str(artifact_root / "go-tx-status.json"),
        "txid": txid,
    },
    "legacy_schema_compatibility": {**mesh_report["legacy_schema_compatibility"], "marker_path": str(tx_marker)},
    "raw_samples": raw_samples(prop_direction="go->rust", prop_elapsed=2),
    "rust_accept": {
        "get_tx_path": str(artifact_root / "rust-get-tx.json"),
        "raw_hex": tx_hex,
        "rpc_endpoint": rust_rpc,
        "tx_status_path": str(artifact_root / "rust-tx-status.json"),
        "txid": txid,
    },
    "scenario": "mixed_client_go_submit_rust_accept",
    "tx_path": tx_path,
}
dump(root / "tx-report.json", tx_report)
converge_report = {
    **tx_report,
    "go_converge": {
        "block_hash": block_hash,
        "block_path": str(artifact_root / "go-converged-block.json"),
        "class": "canonical_block_found",
        "converged_at": "node-go",
        "height": height,
        "raw_hex": tx_hex,
        "rpc_endpoint": go_rpc,
        "tip_path": str(artifact_root / "go-converge-tip.json"),
        "txid": txid,
    },
    "raw_samples": raw_samples(prop_direction="go->rust", prop_elapsed=2, conv_direction="rust->go", conv_elapsed=4),
    "rust_mine": {
        "block_hash": block_hash,
        "block_path": str(artifact_root / "rust-mined-block.json"),
        "class": "mined_included",
        "height": height,
        "mine_next_path": str(artifact_root / "rust-mine-next.json"),
        "mined_by": "node-rust",
        "raw_hex": tx_hex,
        "rpc_endpoint": rust_rpc,
        "tx_count": tx_count,
        "txid": txid,
    },
    "scenario": "mixed_client_go_submit_rust_mine_go_converge",
}
dump(root / "converge-report.json", converge_report)
rust_tx_marker = artifact_root / "rust-submit-tx-marker.json"
rust_tx_path = {"observed_at": ["node-go"], "submitted_at": "node-rust", "tx_id": txid}
dump(rust_tx_marker, {
    "evidence_type": "mixed_client_process_soak",
    "participants": [
        {"endpoint": go_rpc, "implementation": "go", "name": "node-go", "started_at": go_started},
        {"endpoint": rust_rpc, "implementation": "rust", "name": "node-rust", "started_at": rust_started},
    ],
    "scenario": "mixed_client_mesh_schema_marker",
    "schema_version": "rubin-mixed-client-devnet-evidence-v1",
    "tx_path": rust_tx_path,
    "verdict": "PASS",
})
rust_converge_report = {
    **mesh_report,
    "go_accept": {
        "get_tx_path": str(artifact_root / "go-accept-get-tx.json"),
        "raw_hex": tx_hex,
        "rpc_endpoint": go_rpc,
        "tx_status_path": str(artifact_root / "go-accept-tx-status.json"),
        "txid": txid,
    },
    "go_mine": {
        "block_hash": block_hash,
        "block_path": str(artifact_root / "go-mined-block.json"),
        "class": "mined_included",
        "height": height,
        "mine_next_path": str(artifact_root / "go-mine-next.json"),
        "mined_by": "node-go",
        "raw_hex": tx_hex,
        "rpc_endpoint": go_rpc,
        "tx_count": tx_count,
        "txid": txid,
    },
    "legacy_schema_compatibility": {**mesh_report["legacy_schema_compatibility"], "marker_path": str(rust_tx_marker)},
    "raw_samples": raw_samples(prop_direction="rust->go", prop_elapsed=2, conv_direction="go->rust", conv_elapsed=4),
    "rust_converge": {
        "block_hash": block_hash,
        "block_path": str(artifact_root / "rust-converged-block.json"),
        "class": "canonical_block_found",
        "converged_at": "node-rust",
        "height": height,
        "raw_hex": tx_hex,
        "rpc_endpoint": rust_rpc,
        "tip_path": str(artifact_root / "rust-converge-tip.json"),
        "txid": txid,
    },
    "rust_submit": {
        "get_tx_path": str(artifact_root / "rust-submit-get-tx.json"),
        "rpc_endpoint": rust_rpc,
        "tx_hex": tx_hex,
        "tx_status_path": str(artifact_root / "rust-submit-tx-status.json"),
        "txid": txid,
    },
    "scenario": "mixed_client_rust_submit_go_mine_rust_converge",
    "tx_path": rust_tx_path,
}
dump(root / "rust-submit-go-mine-report.json", rust_converge_report)
bad_tx_samples = json.loads(json.dumps(tx_report))
bad_tx_samples["raw_samples"]["propagation"]["samples"] = []
dump(root / "tx-missing-propagation-samples.json", bad_tx_samples)
bad_tx_samples = json.loads(json.dumps(tx_report))
bad_tx_samples["raw_samples"]["propagation"]["samples"][0]["elapsed"] = "__NONFINITE_ELAPSED__"
nonfinite_json = json.dumps(bad_tx_samples, indent=2, sort_keys=True).replace('"__NONFINITE_ELAPSED__"', '1e309', 1) + "\n"
(root / "tx-nonfinite-propagation-sample.json").write_text(nonfinite_json, encoding="utf-8")
bad_tx_samples = json.loads(json.dumps(tx_report))
bad_tx_samples["raw_samples"]["propagation"]["samples"][0]["elapsed"] = 10 ** 400
dump(root / "tx-huge-int-propagation-sample.json", bad_tx_samples)
bad_tx_samples = json.loads(json.dumps(tx_report))
bad_tx_samples["raw_samples"]["propagation"]["p90_seconds"] = 2
dump(root / "tx-slo-claim-sample.json", bad_tx_samples)
bad_converge_samples = json.loads(json.dumps(converge_report))
bad_converge_samples["raw_samples"]["convergence"]["samples"] = []
dump(root / "converge-missing-convergence-samples.json", bad_converge_samples)
bad_converge_samples = json.loads(json.dumps(converge_report))
bad_converge_samples["raw_samples"]["convergence"]["samples"][0]["height"] = True
dump(root / "converge-bool-height-sample.json", bad_converge_samples)
bad_converge_samples = json.loads(json.dumps(converge_report))
bad_converge_samples["raw_samples"]["convergence"]["samples"][0]["height"] = 1.0
dump(root / "converge-float-height-sample.json", bad_converge_samples)
bad_converge_samples = json.loads(json.dumps(converge_report))
bad_converge_samples["raw_samples"]["convergence"]["samples"][0]["block_hash"] = block_hash.upper()
dump(root / "converge-uppercase-block-hash-sample.json", bad_converge_samples)
bad_mesh_samples = json.loads(json.dumps(mesh_report))
bad_mesh_samples["raw_samples"]["propagation"]["reason"] = "p90_seconds_slo_passed"
dump(root / "mesh-bad-propagation-not-requested-reason.json", bad_mesh_samples)
bad_mesh_samples = json.loads(json.dumps(mesh_report))
bad_mesh_samples["raw_samples"]["convergence"]["reason"] = "latency_threshold_passed"
dump(root / "mesh-bad-convergence-not-requested-reason.json", bad_mesh_samples)
bad_restart = json.loads(json.dumps(restart_report))
del bad_restart["restart"]
dump(root / "restart-missing-restart-object.json", bad_restart)
bad_restart = json.loads(json.dumps(restart_report))
del bad_restart["rust_restart"]
dump(root / "restart-missing-process-object.json", bad_restart)
bad_restart = json.loads(json.dumps(restart_report))
bad_restart["rust_restart"]["old_pid"] = bad_restart["rust_restart"]["new_pid"]
dump(root / "restart-same-pid.json", bad_restart)
bad_restart = json.loads(json.dumps(restart_report))
bad_restart["rust_restart"]["old_pid"] = bad_restart["nodes"][0]["pid"]
dump(root / "restart-old-pid-alias-go.json", bad_restart)
bad_restart = json.loads(json.dumps(restart_report))
bad_restart["rust_restart"]["old_pid_stopped"] = False
dump(root / "restart-old-pid-not-stopped.json", bad_restart)
bad_restart = json.loads(json.dumps(restart_report))
bad_restart["rust_restart"]["peer_reconnect_observed"] = False
dump(root / "restart-no-peer-reconnect.json", bad_restart)
bad_restart = json.loads(json.dumps(restart_report))
bad_restart["rust_restart"]["same_datadir"] = False
dump(root / "restart-same-datadir-false.json", bad_restart)
bad_restart = json.loads(json.dumps(restart_report))
bad_restart["rust_restart"]["datadir"] = str(artifact_root / "node-rust-other")
dump(root / "restart-datadir-mismatch.json", bad_restart)
(artifact_root / "node-rust-link").symlink_to(artifact_root / "node-rust", target_is_directory=True)
bad_restart = json.loads(json.dumps(restart_report))
bad_restart["rust_restart"]["datadir"] = str(artifact_root / "node-rust-link")
dump(root / "restart-datadir-symlink.json", bad_restart)
bad_restart = json.loads(json.dumps(restart_report))
bad_restart["rust_restart"]["datadir"] = "node-rust"
dump(root / "restart-datadir-relative.json", bad_restart)
bad_restart = json.loads(json.dumps(restart_report))
bad_restart["nodes"][0]["unexpected_evidence"] = "must not pass"
dump(root / "restart-node-extra-field.json", bad_restart)
bad_restart = json.loads(json.dumps(restart_report))
bad_restart["run_id"] = ""
dump(root / "restart-stale-run-id.json", bad_restart)
bad_restart = json.loads(json.dumps(restart_report))
bad_restart["run_id"] = "stale-but-nonempty"
dump(root / "restart-stale-run-id-mismatch.json", bad_restart)
bad_restart = json.loads(json.dumps(restart_report))
bad_restart["artifact_created_at_utc"] = ""
dump(root / "restart-stale-artifact-created-at.json", bad_restart)
bad_restart = json.loads(json.dumps(restart_report))
bad_restart["restart"]["catch_up_height"] = 6
bad_restart["rust_restart"]["catch_up_height"] = 6
below_pre_restart_marker = artifact_root / "restart-below-pre-restart-marker.json"
dump(below_pre_restart_marker, {
    "evidence_type": "mixed_client_process_soak",
    "failure_reason": "schema v1 PASS requires tx_path; restart PASS lives in sibling report",
    "participants": [
        {"endpoint": go_rpc, "implementation": "go", "name": "node-go", "started_at": go_started},
        {"endpoint": rust_rpc, "implementation": "rust", "name": "node-rust", "started_at": rust_started},
    ],
    "restart": bad_restart["restart"],
    "scenario": "mixed_client_mesh_schema_marker",
    "schema_version": "rubin-mixed-client-devnet-evidence-v1",
    "verdict": "FAIL",
})
bad_restart["legacy_schema_compatibility"]["marker_path"] = str(below_pre_restart_marker)
dump(root / "restart-catch-up-below-pre-restart.json", bad_restart)
bad_restart = json.loads(json.dumps(restart_report))
bad_restart["restart"]["catch_up_height"] = 7
bad_restart["rust_restart"]["catch_up_height"] = 7
stale_restart_marker = artifact_root / "restart-stale-marker.json"
dump(stale_restart_marker, {
    "evidence_type": "mixed_client_process_soak",
    "failure_reason": "schema v1 PASS requires tx_path; restart PASS lives in sibling report",
    "participants": [
        {"endpoint": go_rpc, "implementation": "go", "name": "node-go", "started_at": go_started},
        {"endpoint": rust_rpc, "implementation": "rust", "name": "node-rust", "started_at": rust_started},
    ],
    "restart": bad_restart["restart"],
    "scenario": "mixed_client_mesh_schema_marker",
    "schema_version": "rubin-mixed-client-devnet-evidence-v1",
    "verdict": "FAIL",
})
bad_restart["legacy_schema_compatibility"]["marker_path"] = str(stale_restart_marker)
dump(root / "restart-stale-catch-up.json", bad_restart)
bad_restart = json.loads(json.dumps(restart_report))
bad_restart["legacy_schema_compatibility"]["marker_path"] = str(mesh_marker)
dump(root / "restart-legacy-marker-mismatch.json", bad_restart)
bad_restart = json.loads(json.dumps(restart_report))
bad_restart["rust_restart"]["new_pid"] = 41099
dump(root / "restart-new-pid-not-final.json", bad_restart)
bad_restart = json.loads(json.dumps(restart_report))
bad_restart["rust_restart"]["pre_restart_has_tip"] = False
bad_restart["rust_restart"]["pre_restart_tip"] = None
dump(root / "restart-pre-tip-absent.json", bad_restart)
bad_restart = json.loads(json.dumps(restart_report))
bad_restart["rust_restart"]["catch_up_has_tip"] = False
bad_restart["rust_restart"]["catch_up_tip"] = None
dump(root / "restart-catch-up-tip-absent.json", bad_restart)
bad_restart = json.loads(json.dumps(restart_report))
bad_restart["rust_restart"]["go_target_height"] = 7
dump(root / "restart-go-target-not-advanced.json", bad_restart)
bad_restart = json.loads(json.dumps(restart_report))
bad_restart["rust_restart"]["pre_restart_height"] = "7"
dump(root / "restart-pre-restart-height-string.json", bad_restart)
bad_restart = json.loads(json.dumps(restart_report))
bad_restart["rust_restart"]["go_target_height"] = "8"
dump(root / "restart-go-target-height-string.json", bad_restart)
bad_restart = json.loads(json.dumps(restart_report))
bad_restart["rust_restart"]["catch_up_height"] = "8"
dump(root / "restart-catch-up-height-string.json", bad_restart)
bad_restart = json.loads(json.dumps(restart_report))
bad_restart["rust_restart"]["pre_restart_height"] = True
dump(root / "restart-pre-restart-height-bool.json", bad_restart)
bad_restart = json.loads(json.dumps(restart_report))
bad_restart["rust_restart"]["go_target_height"] = True
dump(root / "restart-go-target-height-bool.json", bad_restart)
bad_restart = json.loads(json.dumps(restart_report))
bad_restart["rust_restart"]["catch_up_height"] = True
dump(root / "restart-catch-up-height-bool.json", bad_restart)
bad_restart = json.loads(json.dumps(restart_report))
bad_restart["rust_restart"]["catch_up_tip"] = "cc" * 32
dump(root / "restart-catch-up-tip-mismatch.json", bad_restart)
bad_restart = json.loads(json.dumps(restart_report))
bad_restart["legacy_schema_compatibility"]["purpose"] = "schema-valid legacy artifact only; not the mesh report verdict"
bad_restart["legacy_schema_compatibility"]["reason"] = "existing mixed_client_evidence_v1 PASS requires tx_path; RUB-21 mesh-only PASS lives in this report"
dump(root / "restart-stale-legacy-text.json", bad_restart)
bad_sidecar = {"best_known_height": 7, "has_tip": True, "height": 7.0, "implementation": "rust", "in_ibd": False, "request_path": "/get_tip", "rpc_endpoint": rust_rpc, "tip_hash": "aa" * 32}
dump(artifact_root / "rust-pre-restart-tip-float-height.json", bad_sidecar)
bad_restart = json.loads(json.dumps(restart_report))
bad_restart["rust_restart"]["pre_restart_tip_path"] = str(artifact_root / "rust-pre-restart-tip-float-height.json")
dump(root / "restart-pre-tip-sidecar-float-height.json", bad_restart)
bad_sidecar = {"best_known_height": 8, "has_tip": True, "height": 8.0, "implementation": "rust", "in_ibd": False, "request_path": "/get_tip", "rpc_endpoint": rust_rpc, "tip_hash": "bb" * 32}
dump(artifact_root / "rust-catch-up-tip-float-height.json", bad_sidecar)
bad_restart = json.loads(json.dumps(restart_report))
bad_restart["rust_restart"]["catch_up_tip_path"] = str(artifact_root / "rust-catch-up-tip-float-height.json")
dump(root / "restart-catch-up-tip-sidecar-float-height.json", bad_restart)
bad_sidecar = {"best_known_height": 0, "has_tip": True, "height": 7, "implementation": "rust", "in_ibd": False, "request_path": "/get_tip", "rpc_endpoint": rust_rpc, "tip_hash": "aa" * 32}
dump(artifact_root / "rust-pre-restart-tip-low-best-known.json", bad_sidecar)
bad_restart = json.loads(json.dumps(restart_report))
bad_restart["rust_restart"]["pre_restart_tip_path"] = str(artifact_root / "rust-pre-restart-tip-low-best-known.json")
dump(root / "restart-pre-tip-sidecar-low-best-known.json", bad_restart)
bad_sidecar = {"best_known_height": 0, "has_tip": True, "height": 8, "implementation": "go", "in_ibd": False, "request_path": "/get_tip", "rpc_endpoint": go_rpc, "tip_hash": "bb" * 32}
dump(artifact_root / "go-restart-target-tip-low-best-known.json", bad_sidecar)
bad_restart = json.loads(json.dumps(restart_report))
bad_restart["rust_restart"]["go_target_tip_path"] = str(artifact_root / "go-restart-target-tip-low-best-known.json")
dump(root / "restart-go-target-tip-sidecar-low-best-known.json", bad_restart)
bad_sidecar = {"best_known_height": 0, "has_tip": True, "height": 8, "implementation": "rust", "in_ibd": False, "request_path": "/get_tip", "rpc_endpoint": rust_rpc, "tip_hash": "bb" * 32}
dump(artifact_root / "rust-catch-up-tip-low-best-known.json", bad_sidecar)
bad_restart = json.loads(json.dumps(restart_report))
bad_restart["rust_restart"]["catch_up_tip_path"] = str(artifact_root / "rust-catch-up-tip-low-best-known.json")
dump(root / "restart-catch-up-tip-sidecar-low-best-known.json", bad_restart)
bad_sidecar = {"best_known_height": 8, "has_tip": True, "height": 8.0, "implementation": "go", "in_ibd": False, "request_path": "/get_tip", "rpc_endpoint": go_rpc, "tip_hash": "bb" * 32}
dump(artifact_root / "go-restart-target-tip-float-height.json", bad_sidecar)
bad_restart = json.loads(json.dumps(restart_report))
bad_restart["rust_restart"]["go_target_tip_path"] = str(artifact_root / "go-restart-target-tip-float-height.json")
dump(root / "restart-go-target-tip-float-height.json", bad_restart)
bad_mine_next = {"block_hash": "bb" * 32, "height": 8, "implementation": "go", "mined": True, "nonce": 0, "request_path": "/mine_next", "rpc_endpoint": go_rpc, "timestamp": 1, "tx_count": True}
dump(artifact_root / "go-restart-mine-next-bool-tx-count.json", bad_mine_next)
bad_restart = json.loads(json.dumps(restart_report))
bad_restart["rust_restart"]["go_target_mine_next_path"] = str(artifact_root / "go-restart-mine-next-bool-tx-count.json")
dump(root / "restart-go-target-mine-bool-tx-count.json", bad_restart)
bad_rust_converge = json.loads(json.dumps(rust_converge_report))
bad_rust_converge["rust_converge"]["txid"] = "11" * 32
dump(root / "rust-submit-go-mine-wrong-txid.json", bad_rust_converge)
bad_rust_converge = json.loads(json.dumps(rust_converge_report))
bad_rust_converge["go_mine"]["class"] = "accepted_only"
dump(root / "rust-submit-go-mine-bad-go-class.json", bad_rust_converge)
bad_rust_converge = json.loads(json.dumps(rust_converge_report))
bad_rust_converge["rust_converge"]["class"] = "accepted_only"
dump(root / "rust-submit-go-mine-bad-rust-converge-class.json", bad_rust_converge)
bad_rust_converge = json.loads(json.dumps(rust_converge_report))
bad_rust_converge["rust_converge"]["block_path"] = str(artifact_root / "go-mined-block.json")
dump(root / "rust-submit-go-mine-duplicate-sidecar-path.json", bad_rust_converge)
bad_rust_converge = json.loads(json.dumps(rust_converge_report))
bad_rust_converge["rust_converge"]["block_path"] = str(artifact_root / "rust-converged-wrong-source-block.json")
dump(root / "rust-submit-go-mine-wrong-sidecar-source.json", bad_rust_converge)
bad_rust_converge = json.loads(json.dumps(rust_converge_report))
bad_rust_converge["rust_converge"]["block_path"] = str(artifact_root / "rust-converged-malformed-block.json")
dump(root / "rust-submit-go-mine-malformed-block.json", bad_rust_converge)
bad_rust_converge = json.loads(json.dumps(rust_converge_report))
bad_rust_converge["go_mine"]["block_hash"] = missing_tx_hash
bad_rust_converge["go_mine"]["block_path"] = str(artifact_root / "go-missing-tx-block.json")
bad_rust_converge["go_mine"]["mine_next_path"] = str(artifact_root / "go-missing-tx-mine-next.json")
bad_rust_converge["rust_converge"]["block_hash"] = missing_tx_hash
bad_rust_converge["rust_converge"]["block_path"] = str(artifact_root / "rust-converged-missing-tx-block.json")
bad_rust_converge["rust_converge"]["tip_path"] = str(artifact_root / "rust-missing-tx-tip.json")
dump(root / "rust-submit-go-mine-missing-tx-block.json", bad_rust_converge)
bad_converge = json.loads(json.dumps(converge_report))
bad_converge["go_converge"]["txid"] = "11" * 32
dump(root / "converge-wrong-txid.json", bad_converge)
bad_converge = json.loads(json.dumps(converge_report))
bad_converge["rust_mine"]["class"] = "accepted_only"
dump(root / "converge-bad-rust-class.json", bad_converge)
bad_converge = json.loads(json.dumps(converge_report))
bad_converge["go_converge"]["block_path"] = str(artifact_root / "rust-mined-block.json")
dump(root / "converge-duplicate-sidecar-path.json", bad_converge)
bad_converge = json.loads(json.dumps(converge_report))
bad_converge["go_converge"]["block_path"] = str(artifact_root / "go-converged-wrong-source-block.json")
dump(root / "converge-wrong-sidecar-source.json", bad_converge)
bad_converge = json.loads(json.dumps(converge_report))
bad_converge["go_converge"]["block_path"] = str(artifact_root / "go-converged-malformed-block.json")
dump(root / "converge-malformed-block.json", bad_converge)
bad_converge = json.loads(json.dumps(converge_report))
bad_converge["rust_mine"]["block_hash"] = missing_tx_hash
bad_converge["rust_mine"]["block_path"] = str(artifact_root / "rust-missing-tx-block.json")
bad_converge["rust_mine"]["mine_next_path"] = str(artifact_root / "rust-missing-tx-mine-next.json")
bad_converge["go_converge"]["block_hash"] = missing_tx_hash
bad_converge["go_converge"]["block_path"] = str(artifact_root / "go-converged-missing-tx-block.json")
bad_converge["go_converge"]["tip_path"] = str(artifact_root / "go-missing-tx-tip.json")
dump(root / "converge-missing-tx-block.json", bad_converge)
bad_converge = json.loads(json.dumps(converge_report))
bad_converge["rust_mine"]["block_hash"] = corrupt_block_hash
bad_converge["rust_mine"]["block_path"] = str(artifact_root / "rust-corrupt-merkle-block.json")
bad_converge["rust_mine"]["mine_next_path"] = str(artifact_root / "rust-corrupt-merkle-mine-next.json")
bad_converge["go_converge"]["block_hash"] = corrupt_block_hash
bad_converge["go_converge"]["block_path"] = str(artifact_root / "go-corrupt-merkle-block.json")
bad_converge["go_converge"]["tip_path"] = str(artifact_root / "go-corrupt-merkle-tip.json")
dump(root / "converge-bad-merkle-block.json", bad_converge)
bad_converge = json.loads(json.dumps(converge_report))
bad_converge["rust_mine"]["tx_count"] = 3
bad_converge["rust_mine"]["mine_next_path"] = str(artifact_root / "rust-tx-count-mismatch-mine-next.json")
dump(root / "converge-tx-count-mismatch.json", bad_converge)
(root / "empty.json").write_text("", encoding="utf-8")
(root / "malformed.json").write_text("[", encoding="utf-8")
with (root / "oversized.json").open("wb") as f:
    f.write(b" " * 1_000_001)
print(root / "mesh-report.json")
print(root / "tx-report.json")
print(root / "converge-report.json")
print(root / "rust-submit-go-mine-report.json")
print(root / "tx-missing-propagation-samples.json")
print(root / "tx-nonfinite-propagation-sample.json")
print(root / "tx-slo-claim-sample.json")
print(root / "converge-missing-convergence-samples.json")
print(root / "mesh-bad-propagation-not-requested-reason.json")
print(root / "mesh-bad-convergence-not-requested-reason.json")
print(root / "rust-submit-go-mine-wrong-txid.json")
print(root / "rust-submit-go-mine-bad-go-class.json")
print(root / "rust-submit-go-mine-bad-rust-converge-class.json")
print(root / "rust-submit-go-mine-duplicate-sidecar-path.json")
print(root / "rust-submit-go-mine-wrong-sidecar-source.json")
print(root / "rust-submit-go-mine-malformed-block.json")
print(root / "rust-submit-go-mine-missing-tx-block.json")
print(root / "converge-wrong-txid.json")
print(root / "converge-bad-rust-class.json")
print(root / "converge-duplicate-sidecar-path.json")
print(root / "converge-wrong-sidecar-source.json")
print(root / "converge-malformed-block.json")
print(root / "converge-missing-tx-block.json")
print(root / "converge-bad-merkle-block.json")
print(root / "converge-tx-count-mismatch.json")
print(root / "restart-report.json")
print(root / "restart-missing-restart-object.json")
print(root / "restart-missing-process-object.json")
print(root / "restart-same-pid.json")
print(root / "restart-old-pid-not-stopped.json")
print(root / "restart-no-peer-reconnect.json")
print(root / "restart-same-datadir-false.json")
print(root / "restart-datadir-mismatch.json")
print(root / "restart-stale-run-id.json")
print(root / "restart-catch-up-below-pre-restart.json")
print(root / "restart-stale-catch-up.json")
print(root / "restart-legacy-marker-mismatch.json")
print(root / "restart-new-pid-not-final.json")
print(root / "restart-pre-tip-absent.json")
print(root / "restart-catch-up-tip-absent.json")
print(root / "restart-go-target-not-advanced.json")
print(root / "restart-pre-restart-height-string.json")
print(root / "restart-go-target-height-string.json")
print(root / "restart-catch-up-height-string.json")
print(root / "restart-pre-restart-height-bool.json")
print(root / "restart-go-target-height-bool.json")
print(root / "restart-catch-up-height-bool.json")
print(root / "restart-catch-up-tip-mismatch.json")
print(root / "restart-stale-legacy-text.json")
print(root / "restart-pre-tip-sidecar-float-height.json")
print(root / "restart-catch-up-tip-sidecar-float-height.json")
print(root / "restart-go-target-tip-float-height.json")
print(root / "restart-go-target-mine-bool-tx-count.json")
print(root / "restart-old-pid-alias-go.json")
print(root / "restart-pre-tip-sidecar-low-best-known.json")
print(root / "restart-go-target-tip-sidecar-low-best-known.json")
print(root / "restart-catch-up-tip-sidecar-low-best-known.json")
print(root / "restart-stale-artifact-created-at.json")
print(root / "restart-stale-run-id-mismatch.json")
print(root / "partition-report.json")
print(root / "partition-losing-parent-report.json")
print(root / "partition-forged-parent-payload-report.json")
print(root / "partition-same-height-winner-report.json")
print(root / "partition-peer-connectivity-overclaim-report.json")
print(artifact_root / "partition-peer-connectivity-bool-count-report.json")
print(root / "partition-final-verification-overclaim-report.json")
print(artifact_root / "partition-unbacked-node-report.json")
print(artifact_root / "partition-rust-peer-argv-mismatch-report.json")
print(root / "partition-disconnected-go-fork-report.json")
print(root / "partition-same-first-rust-fork-report.json")
print(artifact_root / "partition-forged-metrics-report.json")
print(artifact_root / "partition-peer-sidecar-bool-count-report.json")
print(artifact_root / "partition-metrics-timestamp-report.json")
PY
}

CHECK_REPORT_LIB="${TMP_ROOT}/check-report-lib.sh"
PREPARE_TX_CHAINSTATE_LIB="${TMP_ROOT}/prepare-tx-chainstate-lib.sh"
extract_check_report
extract_prepare_tx_chainstate
check_prepare_tx_chainstate_cleanup
# shellcheck source=/dev/null
source "${CHECK_REPORT_LIB}"
[[ "$(tx_path_prepare_reason go_submit_chainstate_prepare_failed 1)" == "go_submit_chainstate_prepare_failed" ]] || { echo "FAIL: go-submit prep reason should remain go_submit scoped" >&2; exit 1; }
[[ "$(tx_path_prepare_reason go_submit_chainstate_prepare_failed 2)" == "go_submit_chainstate_prepare_failed" ]] || { echo "FAIL: go-submit converge prep reason should remain go_submit scoped" >&2; exit 1; }
[[ "$(tx_path_prepare_reason go_submit_chainstate_prepare_failed 3)" == "rust_submit_chainstate_prepare_failed" ]] || { echo "FAIL: rust-submit prep fallback reason was not remapped" >&2; exit 1; }
[[ "$(tx_path_prepare_reason go_submit_mine_timeout 3)" == "rust_submit_mine_timeout" ]] || { echo "FAIL: rust-submit mining prep timeout reason was not remapped" >&2; exit 1; }
[[ "$(tx_path_prepare_reason tx_chainstate_unrelated 3)" == "tx_chainstate_unrelated" ]] || { echo "FAIL: non-go-submit prep reason should remain unchanged" >&2; exit 1; }
[[ "$(rust_restart_prepare_reason go_submit_keygen_failed)" == "rust_restart_keygen_failed" ]] || { echo "FAIL: rust restart keygen prep reason was not remapped" >&2; exit 1; }
[[ "$(rust_restart_prepare_reason go_submit_mine_timeout)" == "rust_restart_chainstate_mine_timeout" ]] || { echo "FAIL: rust restart mine prep reason was not remapped" >&2; exit 1; }
[[ "$(rust_restart_prepare_reason go_submit_chainstate_copy_failed)" == "rust_restart_chainstate_copy_failed" ]] || { echo "FAIL: rust restart copy prep reason was not remapped" >&2; exit 1; }
[[ "$(rust_restart_prepare_reason "")" == "rust_restart_chainstate_prepare_failed" ]] || { echo "FAIL: rust restart empty prep reason fallback was not remapped" >&2; exit 1; }
REPORT_LIST="${TMP_ROOT}/reports.txt"
write_reports >"${REPORT_LIST}"
MESH_REPORT="$(sed -n '1p' "${REPORT_LIST}")"
TX_REPORT="$(sed -n '2p' "${REPORT_LIST}")"
CONVERGE_REPORT="$(sed -n '3p' "${REPORT_LIST}")"
RUST_SUBMIT_GO_MINE_REPORT="$(sed -n '4p' "${REPORT_LIST}")"
TX_MISSING_PROPAGATION_SAMPLE_REPORT="$(sed -n '5p' "${REPORT_LIST}")"
TX_NONFINITE_PROPAGATION_SAMPLE_REPORT="$(sed -n '6p' "${REPORT_LIST}")"
TX_SLO_CLAIM_SAMPLE_REPORT="$(sed -n '7p' "${REPORT_LIST}")"
CONVERGE_MISSING_CONVERGENCE_SAMPLE_REPORT="$(sed -n '8p' "${REPORT_LIST}")"
MESH_BAD_PROPAGATION_REASON_REPORT="$(sed -n '9p' "${REPORT_LIST}")"
MESH_BAD_CONVERGENCE_REASON_REPORT="$(sed -n '10p' "${REPORT_LIST}")"
RUST_SUBMIT_GO_MINE_WRONG_TXID_REPORT="$(sed -n '11p' "${REPORT_LIST}")"
RUST_SUBMIT_GO_MINE_BAD_GO_CLASS_REPORT="$(sed -n '12p' "${REPORT_LIST}")"
RUST_SUBMIT_GO_MINE_BAD_RUST_CONVERGE_CLASS_REPORT="$(sed -n '13p' "${REPORT_LIST}")"
RUST_SUBMIT_GO_MINE_DUPLICATE_SIDECAR_REPORT="$(sed -n '14p' "${REPORT_LIST}")"
RUST_SUBMIT_GO_MINE_WRONG_SIDECAR_SOURCE_REPORT="$(sed -n '15p' "${REPORT_LIST}")"
RUST_SUBMIT_GO_MINE_MALFORMED_BLOCK_REPORT="$(sed -n '16p' "${REPORT_LIST}")"
RUST_SUBMIT_GO_MINE_MISSING_TX_BLOCK_REPORT="$(sed -n '17p' "${REPORT_LIST}")"
CONVERGE_WRONG_TXID_REPORT="$(sed -n '18p' "${REPORT_LIST}")"
CONVERGE_BAD_RUST_CLASS_REPORT="$(sed -n '19p' "${REPORT_LIST}")"
CONVERGE_DUPLICATE_SIDECAR_REPORT="$(sed -n '20p' "${REPORT_LIST}")"
CONVERGE_WRONG_SIDECAR_SOURCE_REPORT="$(sed -n '21p' "${REPORT_LIST}")"
CONVERGE_MALFORMED_BLOCK_REPORT="$(sed -n '22p' "${REPORT_LIST}")"
CONVERGE_MISSING_TX_BLOCK_REPORT="$(sed -n '23p' "${REPORT_LIST}")"
CONVERGE_BAD_MERKLE_BLOCK_REPORT="$(sed -n '24p' "${REPORT_LIST}")"
CONVERGE_TX_COUNT_MISMATCH_REPORT="$(sed -n '25p' "${REPORT_LIST}")"
RESTART_REPORT="$(sed -n '26p' "${REPORT_LIST}")"
RESTART_MISSING_RESTART_REPORT="$(sed -n '27p' "${REPORT_LIST}")"
RESTART_MISSING_PROCESS_REPORT="$(sed -n '28p' "${REPORT_LIST}")"
RESTART_SAME_PID_REPORT="$(sed -n '29p' "${REPORT_LIST}")"
RESTART_OLD_PID_NOT_STOPPED_REPORT="$(sed -n '30p' "${REPORT_LIST}")"
RESTART_NO_PEER_RECONNECT_REPORT="$(sed -n '31p' "${REPORT_LIST}")"
RESTART_SAME_DATADIR_FALSE_REPORT="$(sed -n '32p' "${REPORT_LIST}")"
RESTART_DATADIR_MISMATCH_REPORT="$(sed -n '33p' "${REPORT_LIST}")"
RESTART_STALE_RUN_ID_REPORT="$(sed -n '34p' "${REPORT_LIST}")"
RESTART_CATCH_UP_BELOW_PRE_RESTART_REPORT="$(sed -n '35p' "${REPORT_LIST}")"
RESTART_STALE_CATCH_UP_REPORT="$(sed -n '36p' "${REPORT_LIST}")"
RESTART_LEGACY_MARKER_MISMATCH_REPORT="$(sed -n '37p' "${REPORT_LIST}")"
RESTART_NEW_PID_NOT_FINAL_REPORT="$(sed -n '38p' "${REPORT_LIST}")"
RESTART_PRE_TIP_ABSENT_REPORT="$(sed -n '39p' "${REPORT_LIST}")"
RESTART_CATCH_UP_TIP_ABSENT_REPORT="$(sed -n '40p' "${REPORT_LIST}")"
RESTART_GO_TARGET_NOT_ADVANCED_REPORT="$(sed -n '41p' "${REPORT_LIST}")"
RESTART_PRE_RESTART_HEIGHT_STRING_REPORT="$(sed -n '42p' "${REPORT_LIST}")"
RESTART_GO_TARGET_HEIGHT_STRING_REPORT="$(sed -n '43p' "${REPORT_LIST}")"
RESTART_CATCH_UP_HEIGHT_STRING_REPORT="$(sed -n '44p' "${REPORT_LIST}")"
RESTART_PRE_RESTART_HEIGHT_BOOL_REPORT="$(sed -n '45p' "${REPORT_LIST}")"
RESTART_GO_TARGET_HEIGHT_BOOL_REPORT="$(sed -n '46p' "${REPORT_LIST}")"
RESTART_CATCH_UP_HEIGHT_BOOL_REPORT="$(sed -n '47p' "${REPORT_LIST}")"
RESTART_CATCH_UP_TIP_MISMATCH_REPORT="$(sed -n '48p' "${REPORT_LIST}")"
RESTART_STALE_LEGACY_TEXT_REPORT="$(sed -n '49p' "${REPORT_LIST}")"
RESTART_PRE_TIP_SIDECAR_FLOAT_HEIGHT_REPORT="$(sed -n '50p' "${REPORT_LIST}")"
RESTART_CATCH_UP_TIP_SIDECAR_FLOAT_HEIGHT_REPORT="$(sed -n '51p' "${REPORT_LIST}")"
RESTART_GO_TARGET_TIP_FLOAT_HEIGHT_REPORT="$(sed -n '52p' "${REPORT_LIST}")"
RESTART_GO_TARGET_MINE_BOOL_TX_COUNT_REPORT="$(sed -n '53p' "${REPORT_LIST}")"
RESTART_OLD_PID_ALIAS_GO_REPORT="$(sed -n '54p' "${REPORT_LIST}")"
RESTART_PRE_TIP_SIDECAR_LOW_BEST_KNOWN_REPORT="$(sed -n '55p' "${REPORT_LIST}")"
RESTART_GO_TARGET_TIP_SIDECAR_LOW_BEST_KNOWN_REPORT="$(sed -n '56p' "${REPORT_LIST}")"
RESTART_CATCH_UP_TIP_SIDECAR_LOW_BEST_KNOWN_REPORT="$(sed -n '57p' "${REPORT_LIST}")"
RESTART_STALE_ARTIFACT_TIME_REPORT="$(sed -n '58p' "${REPORT_LIST}")"
RESTART_STALE_RUN_ID_MISMATCH_REPORT="$(sed -n '59p' "${REPORT_LIST}")"
PARTITION_REPORT="$(sed -n '60p' "${REPORT_LIST}")"
PARTITION_LOSING_PARENT_REPORT="$(sed -n '61p' "${REPORT_LIST}")"
PARTITION_FORGED_PARENT_PAYLOAD_REPORT="$(sed -n '62p' "${REPORT_LIST}")"
PARTITION_SAME_HEIGHT_WINNER_REPORT="$(sed -n '63p' "${REPORT_LIST}")"
PARTITION_PEER_CONNECTIVITY_OVERCLAIM_REPORT="$(sed -n '64p' "${REPORT_LIST}")"
PARTITION_PEER_CONNECTIVITY_BOOL_COUNT_REPORT="$(sed -n '65p' "${REPORT_LIST}")"
PARTITION_FINAL_VERIFICATION_OVERCLAIM_REPORT="$(sed -n '66p' "${REPORT_LIST}")"
PARTITION_UNBACKED_NODE_REPORT="$(sed -n '67p' "${REPORT_LIST}")"
PARTITION_RUST_PEER_ARGV_MISMATCH_REPORT="$(sed -n '68p' "${REPORT_LIST}")"
PARTITION_DISCONNECTED_GO_FORK_REPORT="$(sed -n '69p' "${REPORT_LIST}")"
PARTITION_SAME_FIRST_RUST_FORK_REPORT="$(sed -n '70p' "${REPORT_LIST}")"
PARTITION_FORGED_METRICS_REPORT="$(sed -n '71p' "${REPORT_LIST}")"
PARTITION_PEER_SIDECAR_BOOL_COUNT_REPORT="$(sed -n '72p' "${REPORT_LIST}")"
PARTITION_METRICS_TIMESTAMP_REPORT="$(sed -n '73p' "${REPORT_LIST}")"
TX_HUGE_INT_PROPAGATION_SAMPLE_REPORT="${TMP_ROOT}/tx-huge-int-propagation-sample.json"
CONVERGE_BOOL_HEIGHT_SAMPLE_REPORT="${TMP_ROOT}/converge-bool-height-sample.json"
CONVERGE_FLOAT_HEIGHT_SAMPLE_REPORT="${TMP_ROOT}/converge-float-height-sample.json"
CONVERGE_UPPERCASE_BLOCK_HASH_SAMPLE_REPORT="${TMP_ROOT}/converge-uppercase-block-hash-sample.json"
[[ -f "${TX_HUGE_INT_PROPAGATION_SAMPLE_REPORT}" && -f "${CONVERGE_BOOL_HEIGHT_SAMPLE_REPORT}" && -f "${CONVERGE_FLOAT_HEIGHT_SAMPLE_REPORT}" && -f "${CONVERGE_UPPERCASE_BLOCK_HASH_SAMPLE_REPORT}" ]] || { echo "failed to build raw sample regression reports" >&2; exit 1; }
[[ -n "${MESH_REPORT}" && -n "${TX_REPORT}" && -n "${CONVERGE_REPORT}" && -n "${RUST_SUBMIT_GO_MINE_REPORT}" && -n "${TX_MISSING_PROPAGATION_SAMPLE_REPORT}" && -n "${TX_NONFINITE_PROPAGATION_SAMPLE_REPORT}" && -n "${TX_SLO_CLAIM_SAMPLE_REPORT}" && -n "${CONVERGE_MISSING_CONVERGENCE_SAMPLE_REPORT}" && -n "${MESH_BAD_PROPAGATION_REASON_REPORT}" && -n "${MESH_BAD_CONVERGENCE_REASON_REPORT}" && -n "${RUST_SUBMIT_GO_MINE_WRONG_TXID_REPORT}" && -n "${RUST_SUBMIT_GO_MINE_BAD_GO_CLASS_REPORT}" && -n "${RUST_SUBMIT_GO_MINE_BAD_RUST_CONVERGE_CLASS_REPORT}" && -n "${RUST_SUBMIT_GO_MINE_DUPLICATE_SIDECAR_REPORT}" && -n "${RUST_SUBMIT_GO_MINE_WRONG_SIDECAR_SOURCE_REPORT}" && -n "${RUST_SUBMIT_GO_MINE_MALFORMED_BLOCK_REPORT}" && -n "${RUST_SUBMIT_GO_MINE_MISSING_TX_BLOCK_REPORT}" && -n "${CONVERGE_WRONG_TXID_REPORT}" && -n "${CONVERGE_BAD_RUST_CLASS_REPORT}" && -n "${CONVERGE_DUPLICATE_SIDECAR_REPORT}" && -n "${CONVERGE_WRONG_SIDECAR_SOURCE_REPORT}" && -n "${CONVERGE_MALFORMED_BLOCK_REPORT}" && -n "${CONVERGE_MISSING_TX_BLOCK_REPORT}" && -n "${CONVERGE_BAD_MERKLE_BLOCK_REPORT}" && -n "${CONVERGE_TX_COUNT_MISMATCH_REPORT}" ]] || { echo "failed to build synthetic reports" >&2; exit 1; }
[[ -n "${RESTART_REPORT}" && -n "${RESTART_MISSING_RESTART_REPORT}" && -n "${RESTART_MISSING_PROCESS_REPORT}" && -n "${RESTART_SAME_PID_REPORT}" && -n "${RESTART_OLD_PID_NOT_STOPPED_REPORT}" && -n "${RESTART_NO_PEER_RECONNECT_REPORT}" && -n "${RESTART_SAME_DATADIR_FALSE_REPORT}" && -n "${RESTART_DATADIR_MISMATCH_REPORT}" && -n "${RESTART_STALE_RUN_ID_REPORT}" && -n "${RESTART_CATCH_UP_BELOW_PRE_RESTART_REPORT}" && -n "${RESTART_STALE_CATCH_UP_REPORT}" && -n "${RESTART_LEGACY_MARKER_MISMATCH_REPORT}" && -n "${RESTART_NEW_PID_NOT_FINAL_REPORT}" && -n "${RESTART_PRE_TIP_ABSENT_REPORT}" && -n "${RESTART_CATCH_UP_TIP_ABSENT_REPORT}" && -n "${RESTART_GO_TARGET_NOT_ADVANCED_REPORT}" && -n "${RESTART_PRE_RESTART_HEIGHT_STRING_REPORT}" && -n "${RESTART_GO_TARGET_HEIGHT_STRING_REPORT}" && -n "${RESTART_CATCH_UP_HEIGHT_STRING_REPORT}" && -n "${RESTART_PRE_RESTART_HEIGHT_BOOL_REPORT}" && -n "${RESTART_GO_TARGET_HEIGHT_BOOL_REPORT}" && -n "${RESTART_CATCH_UP_HEIGHT_BOOL_REPORT}" && -n "${RESTART_CATCH_UP_TIP_MISMATCH_REPORT}" && -n "${RESTART_STALE_LEGACY_TEXT_REPORT}" && -n "${RESTART_PRE_TIP_SIDECAR_FLOAT_HEIGHT_REPORT}" && -n "${RESTART_CATCH_UP_TIP_SIDECAR_FLOAT_HEIGHT_REPORT}" && -n "${RESTART_GO_TARGET_TIP_FLOAT_HEIGHT_REPORT}" && -n "${RESTART_GO_TARGET_MINE_BOOL_TX_COUNT_REPORT}" && -n "${RESTART_OLD_PID_ALIAS_GO_REPORT}" && -n "${RESTART_PRE_TIP_SIDECAR_LOW_BEST_KNOWN_REPORT}" && -n "${RESTART_GO_TARGET_TIP_SIDECAR_LOW_BEST_KNOWN_REPORT}" && -n "${RESTART_CATCH_UP_TIP_SIDECAR_LOW_BEST_KNOWN_REPORT}" && -n "${RESTART_STALE_ARTIFACT_TIME_REPORT}" && -n "${RESTART_STALE_RUN_ID_MISMATCH_REPORT}" ]] || { echo "failed to build synthetic restart reports" >&2; exit 1; }
[[ -n "${PARTITION_REPORT}" && -n "${PARTITION_LOSING_PARENT_REPORT}" && -n "${PARTITION_FORGED_PARENT_PAYLOAD_REPORT}" && -n "${PARTITION_SAME_HEIGHT_WINNER_REPORT}" && -n "${PARTITION_PEER_CONNECTIVITY_OVERCLAIM_REPORT}" && -n "${PARTITION_PEER_CONNECTIVITY_BOOL_COUNT_REPORT}" && -n "${PARTITION_FINAL_VERIFICATION_OVERCLAIM_REPORT}" && -n "${PARTITION_UNBACKED_NODE_REPORT}" && -n "${PARTITION_RUST_PEER_ARGV_MISMATCH_REPORT}" && -n "${PARTITION_DISCONNECTED_GO_FORK_REPORT}" && -n "${PARTITION_SAME_FIRST_RUST_FORK_REPORT}" && -n "${PARTITION_FORGED_METRICS_REPORT}" && -n "${PARTITION_PEER_SIDECAR_BOOL_COUNT_REPORT}" && -n "${PARTITION_METRICS_TIMESTAMP_REPORT}" ]] || { echo "failed to build synthetic partition reports" >&2; exit 1; }

expect_pass_contains "public mesh check-report" "PASS: mixed_client_mesh report structurally accepted" "${HARNESS}" --check-report "${MESH_REPORT}"
expect_pass_contains "rust restart check-report" "PASS: mixed_client_rust_restart report structurally accepted" "${HARNESS}" --rust-restart --check-report "${RESTART_REPORT}"
expect_pass_contains "partition check-report" "PASS: mixed_client_partition_heal_reorg report structurally accepted" "${HARNESS}" --partition-heal-reorg --check-report "${PARTITION_REPORT}"
expect_fail_contains "partition rejects losing fork as reorg parent" "observations.reorg.go_reorg_parent_block does not match expected block" "${HARNESS}" --partition-heal-reorg --check-report "${PARTITION_LOSING_PARENT_REPORT}"
expect_fail_contains "partition rejects forged parent block payload" "observations.reorg.go_reorg_parent_block parsed block hash mismatch" "${HARNESS}" --partition-heal-reorg --check-report "${PARTITION_FORGED_PARENT_PAYLOAD_REPORT}"
expect_fail_contains "partition rejects same-height winning fork" "partition fork tips do not prove Rust winning branch" "${HARNESS}" --partition-heal-reorg --check-report "${PARTITION_SAME_HEIGHT_WINNER_REPORT}"
expect_fail_contains "partition rejects peer_connectivity overclaim" "partition peer_connectivity overclaims direct link" "${HARNESS}" --partition-heal-reorg --check-report "${PARTITION_PEER_CONNECTIVITY_OVERCLAIM_REPORT}"
expect_fail_contains "partition rejects peer_connectivity bool count" "partition peer_connectivity.go_peer_snapshot must be empty" "${HARNESS}" --partition-heal-reorg --check-report "${PARTITION_PEER_CONNECTIVITY_BOOL_COUNT_REPORT}"
expect_generator_fail_contains "partition generator rejects peer_connectivity bool count" "peer_connectivity_invalid" --partition-heal-reorg-report "${PARTITION_PEER_CONNECTIVITY_BOOL_COUNT_REPORT}"
expect_fail_contains "partition rejects final_verification overclaim" "partition final verification is incomplete" "${HARNESS}" --partition-heal-reorg --check-report "${PARTITION_FINAL_VERIFICATION_OVERCLAIM_REPORT}"
expect_generator_fail_contains "partition generator rejects unbacked node evidence" "process_identity_missing_or_invalid" --partition-heal-reorg-report "${PARTITION_UNBACKED_NODE_REPORT}"
expect_fail_contains "partition rejects rust peer argv mismatch" "node command_argv does not match exact launched argv" "${HARNESS}" --partition-heal-reorg --check-report "${PARTITION_RUST_PEER_ARGV_MISMATCH_REPORT}"
expect_generator_fail_contains "partition generator rejects rust peer argv mismatch" "node_identity_invalid" --partition-heal-reorg-report "${PARTITION_RUST_PEER_ARGV_MISMATCH_REPORT}"
expect_fail_contains "partition rejects disconnected fork parent" "observations.fork.go_block block payload check failed" "${HARNESS}" --partition-heal-reorg --check-report "${PARTITION_DISCONNECTED_GO_FORK_REPORT}"
expect_fail_contains "partition rejects non-divergent rust fork" "rust fork first mine did not diverge from go fork" "${HARNESS}" --partition-heal-reorg --check-report "${PARTITION_SAME_FIRST_RUST_FORK_REPORT}"
expect_fail_contains "partition rejects forged reorg metrics" "partition go reorg metrics do not match source sidecar" "${HARNESS}" --partition-heal-reorg --check-report "${PARTITION_FORGED_METRICS_REPORT}"
expect_generator_fail_contains "partition generator rejects forged reorg metrics" "reorg_metrics_mismatch" --partition-heal-reorg-report "${PARTITION_FORGED_METRICS_REPORT}"
expect_fail_contains "partition rejects bool peer sidecar count" "observations.pre_partition.rust_peer_snapshot peer snapshot malformed" "${HARNESS}" --partition-heal-reorg --check-report "${PARTITION_PEER_SIDECAR_BOOL_COUNT_REPORT}"
expect_generator_fail_contains "partition generator rejects bool peer sidecar count" "peer_snapshot_invalid" --partition-heal-reorg-report "${PARTITION_PEER_SIDECAR_BOOL_COUNT_REPORT}"
expect_fail_contains "partition rejects timestamped reorg metrics" "observations.reorg.go_metrics malformed metric line" "${HARNESS}" --partition-heal-reorg --check-report "${PARTITION_METRICS_TIMESTAMP_REPORT}"
expect_generator_fail_contains "partition generator rejects timestamped metrics sidecar" "metrics_malformed" --partition-heal-reorg-report "${PARTITION_METRICS_TIMESTAMP_REPORT}"
expect_fail_contains "public restart check-report" "public restart check-report is unsupported" "${HARNESS}" --check-report "${RESTART_REPORT}"
expect_fail_contains "restart live check-report unsupported" "--rust-restart --check-report-live is unsupported" "${HARNESS}" --rust-restart --check-report-live "${RESTART_REPORT}"
expect_fail_contains "restart mode rejects mesh artifact" "rust restart validation requires a mixed_client_rust_restart report" "${HARNESS}" --rust-restart --check-report "${MESH_REPORT}"
expect_fail_contains "restart rejects missing restart object" "report top-level keys mismatch" "${HARNESS}" --rust-restart --check-report "${RESTART_MISSING_RESTART_REPORT}"
expect_fail_contains "restart rejects missing process object" "report top-level keys mismatch" "${HARNESS}" --rust-restart --check-report "${RESTART_MISSING_PROCESS_REPORT}"
expect_fail_contains "restart rejects same pid reuse" "rust_restart reused the stopped pid" "${HARNESS}" --rust-restart --check-report "${RESTART_SAME_PID_REPORT}"
expect_fail_contains "restart rejects old pid aliasing go" "rust_restart.old_pid aliases a final live node pid" "${HARNESS}" --rust-restart --check-report "${RESTART_OLD_PID_ALIAS_GO_REPORT}"
expect_fail_contains "restart rejects old pid not stopped" "rust_restart does not prove old process stopped" "${HARNESS}" --rust-restart --check-report "${RESTART_OLD_PID_NOT_STOPPED_REPORT}"
expect_fail_contains "restart rejects missing peer reconnect" "rust_restart peer reconnect was not observed" "${HARNESS}" --rust-restart --check-report "${RESTART_NO_PEER_RECONNECT_REPORT}"
expect_fail_contains "restart rejects same_datadir false" "rust_restart does not prove same datadir restart" "${HARNESS}" --rust-restart --check-report "${RESTART_SAME_DATADIR_FALSE_REPORT}"
expect_fail_contains "restart rejects datadir mismatch" "rust_restart datadir is not bound to artifact root" "${HARNESS}" --rust-restart --check-report "${RESTART_DATADIR_MISMATCH_REPORT}"
expect_fail_contains "restart rejects stale run identity" "restart report run_id missing" "${HARNESS}" --rust-restart --check-report "${RESTART_STALE_RUN_ID_REPORT}"
expect_fail_contains "restart rejects stale artifact timestamp" "restart report artifact_created_at_utc invalid" "${HARNESS}" --rust-restart --check-report "${RESTART_STALE_ARTIFACT_TIME_REPORT}"
expect_fail_contains "restart rejects stale run id mismatch" "restart report run_id mismatch" "${HARNESS}" --rust-restart --check-report "${RESTART_STALE_RUN_ID_MISMATCH_REPORT}"
expect_fail_contains "restart rejects catch-up below pre-restart" "below pre_restart_height" "${HARNESS}" --rust-restart --check-report "${RESTART_CATCH_UP_BELOW_PRE_RESTART_REPORT}"
expect_fail_contains "restart rejects stale catch-up" "rust_restart catch-up height does not match go target" "${HARNESS}" --rust-restart --check-report "${RESTART_STALE_CATCH_UP_REPORT}"
expect_fail_contains "restart rejects legacy marker mismatch" "legacy marker restart object is not bound to report restart object" "${HARNESS}" --rust-restart --check-report "${RESTART_LEGACY_MARKER_MISMATCH_REPORT}"
expect_fail_contains "restart rejects new pid not final rust process" "rust_restart.new_pid is not the final rust node pid" "${HARNESS}" --rust-restart --check-report "${RESTART_NEW_PID_NOT_FINAL_REPORT}"
expect_fail_contains "restart rejects missing pre-restart tip" "rust_restart pre-restart tip is not proven" "${HARNESS}" --rust-restart --check-report "${RESTART_PRE_TIP_ABSENT_REPORT}"
expect_fail_contains "restart rejects missing catch-up tip" "rust_restart catch-up tip is not proven" "${HARNESS}" --rust-restart --check-report "${RESTART_CATCH_UP_TIP_ABSENT_REPORT}"
expect_fail_contains "restart rejects non-advanced go target" "rust_restart go target did not advance beyond pre-restart tip" "${HARNESS}" --rust-restart --check-report "${RESTART_GO_TARGET_NOT_ADVANCED_REPORT}"
expect_fail_contains "restart rejects catch-up tip mismatch" "rust_restart catch-up tip does not match go target" "${HARNESS}" --rust-restart --check-report "${RESTART_CATCH_UP_TIP_MISMATCH_REPORT}"
expect_fail_contains "restart rejects stale legacy text" "legacy_schema_compatibility restart purpose mismatch" "${HARNESS}" --rust-restart --check-report "${RESTART_STALE_LEGACY_TEXT_REPORT}"
expect_fail_contains "restart rejects float pre-restart sidecar height" "rust_restart.pre_restart_tip_path.height is not an integer" "${HARNESS}" --rust-restart --check-report "${RESTART_PRE_TIP_SIDECAR_FLOAT_HEIGHT_REPORT}"
expect_fail_contains "restart rejects float catch-up sidecar height" "rust_restart.catch_up_tip_path.height is not an integer" "${HARNESS}" --rust-restart --check-report "${RESTART_CATCH_UP_TIP_SIDECAR_FLOAT_HEIGHT_REPORT}"
expect_fail_contains "restart rejects float go target sidecar height" "rust_restart.go_target_tip_path.height is not an integer" "${HARNESS}" --rust-restart --check-report "${RESTART_GO_TARGET_TIP_FLOAT_HEIGHT_REPORT}"
expect_fail_contains "restart rejects string pre-restart height" "rust_restart.pre_restart_height is not an integer" "${HARNESS}" --rust-restart --check-report "${RESTART_PRE_RESTART_HEIGHT_STRING_REPORT}"
expect_fail_contains "restart rejects string go target height" "rust_restart.go_target_height is not an integer" "${HARNESS}" --rust-restart --check-report "${RESTART_GO_TARGET_HEIGHT_STRING_REPORT}"
expect_fail_contains "restart rejects string catch-up height" "rust_restart.catch_up_height is not an integer" "${HARNESS}" --rust-restart --check-report "${RESTART_CATCH_UP_HEIGHT_STRING_REPORT}"
expect_fail_contains "restart rejects bool pre-restart height" "rust_restart.pre_restart_height is not an integer" "${HARNESS}" --rust-restart --check-report "${RESTART_PRE_RESTART_HEIGHT_BOOL_REPORT}"
expect_fail_contains "restart rejects bool go target height" "rust_restart.go_target_height is not an integer" "${HARNESS}" --rust-restart --check-report "${RESTART_GO_TARGET_HEIGHT_BOOL_REPORT}"
expect_fail_contains "restart rejects bool catch-up height" "rust_restart.catch_up_height is not an integer" "${HARNESS}" --rust-restart --check-report "${RESTART_CATCH_UP_HEIGHT_BOOL_REPORT}"
expect_fail_contains "restart rejects bool go target mine tx_count" "rust_restart.go_target_mine_next_path.tx_count is not an integer" "${HARNESS}" --rust-restart --check-report "${RESTART_GO_TARGET_MINE_BOOL_TX_COUNT_REPORT}"
expect_fail_contains "restart rejects low pre-restart sidecar best-known height" "rust_restart.pre_restart_tip_path.best_known_height below height" "${HARNESS}" --rust-restart --check-report "${RESTART_PRE_TIP_SIDECAR_LOW_BEST_KNOWN_REPORT}"
expect_fail_contains "restart rejects low go target sidecar best-known height" "rust_restart.go_target_tip_path.best_known_height below height" "${HARNESS}" --rust-restart --check-report "${RESTART_GO_TARGET_TIP_SIDECAR_LOW_BEST_KNOWN_REPORT}"
expect_fail_contains "restart rejects low catch-up sidecar best-known height" "rust_restart.catch_up_tip_path.best_known_height below height" "${HARNESS}" --rust-restart --check-report "${RESTART_CATCH_UP_TIP_SIDECAR_LOW_BEST_KNOWN_REPORT}"
expect_fail_check_token "token maps restart mode mismatch" "rust_restart_scenario_required" check_report "${MESH_REPORT}" offline rust-restart
expect_fail_check_token "token maps public restart report" "public_restart_check_report_unsupported" check_report "${RESTART_REPORT}" offline public
expect_fail_check_token "token maps restart same pid" "rust_restart_same_pid" check_report "${RESTART_SAME_PID_REPORT}" offline rust-restart
expect_fail_check_token "token maps restart old pid alias" "rust_restart_old_pid_aliases_final_node" check_report "${RESTART_OLD_PID_ALIAS_GO_REPORT}" offline rust-restart
expect_fail_check_token "token maps restart old pid not stopped" "rust_restart_old_process_not_stopped" check_report "${RESTART_OLD_PID_NOT_STOPPED_REPORT}" offline rust-restart
expect_fail_check_token "token maps restart missing peer reconnect" "rust_restart_peer_reconnect_missing" check_report "${RESTART_NO_PEER_RECONNECT_REPORT}" offline rust-restart
expect_fail_check_token "token maps restart same_datadir false" "rust_restart_datadir_mismatch" check_report "${RESTART_SAME_DATADIR_FALSE_REPORT}" offline rust-restart
expect_fail_check_token "token maps restart datadir mismatch" "rust_restart_datadir_not_bound" check_report "${RESTART_DATADIR_MISMATCH_REPORT}" offline rust-restart
expect_fail_check_token "token maps restart datadir symlink" "rust_restart_datadir_not_bound" check_report "${TMP_ROOT}/restart-datadir-symlink.json" offline rust-restart
expect_fail_check_token "token maps restart relative datadir" "rust_restart_datadir_not_bound" check_report "${TMP_ROOT}/restart-datadir-relative.json" offline rust-restart
expect_fail_check_token "token maps restart node extra field" "process_identity_invalid" check_report "${TMP_ROOT}/restart-node-extra-field.json" offline rust-restart
expect_fail_check_token "token maps restart stale run identity" "rust_restart_run_id_missing" check_report "${RESTART_STALE_RUN_ID_REPORT}" offline rust-restart
expect_fail_check_token "token maps restart stale artifact timestamp" "rust_restart_artifact_created_at_invalid" check_report "${RESTART_STALE_ARTIFACT_TIME_REPORT}" offline rust-restart
expect_fail_check_token "token maps restart stale run id mismatch" "rust_restart_run_id_mismatch" check_report "${RESTART_STALE_RUN_ID_MISMATCH_REPORT}" offline rust-restart
expect_fail_check_token "token maps restart catch-up below pre-restart" "rust_restart_catch_up_below_pre_restart" check_report "${RESTART_CATCH_UP_BELOW_PRE_RESTART_REPORT}" offline rust-restart
expect_fail_check_token "token maps restart stale catch-up" "rust_restart_catch_up_height_not_go_target" check_report "${RESTART_STALE_CATCH_UP_REPORT}" offline rust-restart
expect_fail_check_token "token maps restart pre-restart height invalid" "rust_restart_pre_restart_height_invalid" check_report "${RESTART_PRE_RESTART_HEIGHT_STRING_REPORT}" offline rust-restart
expect_fail_check_token "token maps restart go target height invalid" "rust_restart_go_target_height_invalid" check_report "${RESTART_GO_TARGET_HEIGHT_STRING_REPORT}" offline rust-restart
expect_fail_check_token "token maps restart catch-up height invalid" "rust_restart_catch_up_height_invalid" check_report "${RESTART_CATCH_UP_HEIGHT_STRING_REPORT}" offline rust-restart
expect_fail_check_token "token maps restart pre-restart bool invalid" "rust_restart_pre_restart_height_invalid" check_report "${RESTART_PRE_RESTART_HEIGHT_BOOL_REPORT}" offline rust-restart
expect_fail_check_token "token maps restart go target bool invalid" "rust_restart_go_target_height_invalid" check_report "${RESTART_GO_TARGET_HEIGHT_BOOL_REPORT}" offline rust-restart
expect_fail_check_token "token maps restart catch-up bool invalid" "rust_restart_catch_up_height_invalid" check_report "${RESTART_CATCH_UP_HEIGHT_BOOL_REPORT}" offline rust-restart
expect_fail_check_token "token maps restart pre tip absent" "rust_restart_pre_tip_not_proven" check_report "${RESTART_PRE_TIP_ABSENT_REPORT}" offline rust-restart
expect_fail_check_token "token maps restart catch-up tip absent" "rust_restart_catch_up_tip_not_proven" check_report "${RESTART_CATCH_UP_TIP_ABSENT_REPORT}" offline rust-restart
expect_fail_check_token "token maps restart pre sidecar invalid" "rust_restart_pre_restart_tip_sidecar_invalid" check_report "${RESTART_PRE_TIP_SIDECAR_FLOAT_HEIGHT_REPORT}" offline rust-restart
expect_fail_check_token "token maps restart catch-up sidecar invalid" "rust_restart_catch_up_tip_sidecar_invalid" check_report "${RESTART_CATCH_UP_TIP_SIDECAR_FLOAT_HEIGHT_REPORT}" offline rust-restart
expect_fail_check_token "token maps restart go target sidecar invalid" "rust_restart_go_target_tip_sidecar_invalid" check_report "${RESTART_GO_TARGET_TIP_FLOAT_HEIGHT_REPORT}" offline rust-restart
expect_fail_check_token "token maps restart go target mine sidecar invalid" "rust_restart_go_target_mine_next_invalid" check_report "${RESTART_GO_TARGET_MINE_BOOL_TX_COUNT_REPORT}" offline rust-restart
expect_fail_check_token "token maps restart pre sidecar low best-known" "rust_restart_pre_restart_tip_sidecar_invalid" check_report "${RESTART_PRE_TIP_SIDECAR_LOW_BEST_KNOWN_REPORT}" offline rust-restart
expect_fail_check_token "token maps restart go target sidecar low best-known" "rust_restart_go_target_tip_sidecar_invalid" check_report "${RESTART_GO_TARGET_TIP_SIDECAR_LOW_BEST_KNOWN_REPORT}" offline rust-restart
expect_fail_check_token "token maps restart catch-up sidecar low best-known" "rust_restart_catch_up_tip_sidecar_invalid" check_report "${RESTART_CATCH_UP_TIP_SIDECAR_LOW_BEST_KNOWN_REPORT}" offline rust-restart
expect_fail_check_token "token maps restart go target not advanced" "rust_restart_go_target_not_advanced" check_report "${RESTART_GO_TARGET_NOT_ADVANCED_REPORT}" offline rust-restart
expect_fail_check_token "token maps restart catch-up tip mismatch" "rust_restart_catch_up_tip_not_go_target" check_report "${RESTART_CATCH_UP_TIP_MISMATCH_REPORT}" offline rust-restart
expect_fail_contains "public rejects propagation not-requested reason drift" "raw_samples.propagation must be not_requested with canonical reason" "${HARNESS}" --check-report "${MESH_BAD_PROPAGATION_REASON_REPORT}"
expect_fail_contains "public rejects convergence not-requested reason drift" "raw_samples.convergence must be not_requested with canonical reason" "${HARNESS}" --check-report "${MESH_BAD_CONVERGENCE_REASON_REPORT}"
expect_fail_contains "public tx check-report" "public tx-path check-report is unsupported" "${HARNESS}" --check-report "${TX_REPORT}"
expect_fail_contains "public converge check-report" "public tx-path check-report is unsupported" "${HARNESS}" --check-report "${CONVERGE_REPORT}"
expect_fail_contains "public rust-submit converge check-report" "public tx-path check-report is unsupported" "${HARNESS}" --check-report "${RUST_SUBMIT_GO_MINE_REPORT}"
expect_fail_contains "public tx check-report-live" "public tx-path check-report-live is unsupported" "${HARNESS}" --check-report-live "${TX_REPORT}"
expect_fail_contains "combined tx flag and check-report" "tx-path modes cannot be combined" "${HARNESS}" --go-submit-rust-accept --check-report "${TX_REPORT}"
expect_fail_contains "combined tx-path flags reject" "tx-path modes are mutually exclusive" "${HARNESS}" --go-submit-rust-accept --go-submit-rust-mine-go-converge
expect_fail_contains "combined rust-submit tx-path flags reject" "tx-path modes are mutually exclusive" "${HARNESS}" --go-submit-rust-accept --rust-submit-go-mine-rust-converge

expect_pass_contains "producer tx internal check" "PASS: mixed_client_go_submit_rust_accept report structurally accepted" check_report "${TX_REPORT}" offline producer-tx
expect_pass_contains "producer converge internal check" "PASS: mixed_client_go_submit_rust_mine_go_converge report structurally accepted" check_report "${CONVERGE_REPORT}" offline producer-tx
expect_pass_contains "producer rust-submit converge internal check" "PASS: mixed_client_rust_submit_go_mine_rust_converge report structurally accepted" check_report "${RUST_SUBMIT_GO_MINE_REPORT}" offline producer-tx
expect_fail_contains "producer rejects mesh report" "producer tx validation requires a mixed-client tx-path report" check_report "${MESH_REPORT}" offline producer-tx
expect_fail_contains "producer rejects missing propagation sample" "raw_samples.propagation requires one observed sample" check_report "${TX_MISSING_PROPAGATION_SAMPLE_REPORT}" offline producer-tx
expect_fail_contains "producer rejects non-finite propagation sample" "raw_samples.propagation.samples[0].elapsed is not finite" check_report "${TX_NONFINITE_PROPAGATION_SAMPLE_REPORT}" offline producer-tx
expect_fail_contains "producer rejects huge integer propagation sample" "raw_samples.propagation.samples[0].elapsed is not finite" check_report "${TX_HUGE_INT_PROPAGATION_SAMPLE_REPORT}" offline producer-tx
expect_fail_contains "producer rejects sample SLO claim" "raw_samples.propagation keys mismatch" check_report "${TX_SLO_CLAIM_SAMPLE_REPORT}" offline producer-tx
expect_fail_contains "producer rejects missing convergence sample" "raw_samples.convergence requires one observed sample" check_report "${CONVERGE_MISSING_CONVERGENCE_SAMPLE_REPORT}" offline producer-tx
expect_fail_contains "producer rejects bool convergence height" "raw_samples.convergence.samples[0].height is not an integer" check_report "${CONVERGE_BOOL_HEIGHT_SAMPLE_REPORT}" offline producer-tx
expect_fail_contains "producer rejects float convergence height" "raw_samples.convergence.samples[0].height is not an integer" check_report "${CONVERGE_FLOAT_HEIGHT_SAMPLE_REPORT}" offline producer-tx
expect_fail_contains "producer rejects uppercase convergence block hash" "raw_samples.convergence.samples[0].block_hash is not lowercase 32-byte hex" check_report "${CONVERGE_UPPERCASE_BLOCK_HASH_SAMPLE_REPORT}" offline producer-tx
expect_fail_contains "producer rejects converged txid drift" "mined/converged tx identity differs from submitted tx" check_report "${CONVERGE_WRONG_TXID_REPORT}" offline producer-tx
expect_fail_contains "producer rejects rust-submit converged txid drift" "mined/converged tx identity differs from submitted tx" check_report "${RUST_SUBMIT_GO_MINE_WRONG_TXID_REPORT}" offline producer-tx
expect_fail_contains "producer rejects reused converge sidecar path" "converge sidecar paths are not pairwise distinct" check_report "${CONVERGE_DUPLICATE_SIDECAR_REPORT}" offline producer-tx
expect_fail_contains "producer rejects reused rust-submit converge sidecar path" "converge sidecar paths are not pairwise distinct" check_report "${RUST_SUBMIT_GO_MINE_DUPLICATE_SIDECAR_REPORT}" offline producer-tx
expect_fail_contains "producer rejects wrong-source converge block" "go_converge.block_path sidecar identity mismatch" check_report "${CONVERGE_WRONG_SIDECAR_SOURCE_REPORT}" offline producer-tx
expect_fail_contains "producer rejects wrong-source rust converge block" "rust_converge.block_path sidecar identity mismatch" check_report "${RUST_SUBMIT_GO_MINE_WRONG_SIDECAR_SOURCE_REPORT}" offline producer-tx
expect_fail_contains "producer rejects malformed converge block" "go_converge.block_path inclusion check failed" check_report "${CONVERGE_MALFORMED_BLOCK_REPORT}" offline producer-tx
expect_fail_contains "producer rejects malformed rust converge block" "rust_converge.block_path inclusion check failed" check_report "${RUST_SUBMIT_GO_MINE_MALFORMED_BLOCK_REPORT}" offline producer-tx
expect_fail_contains "producer rejects converge block missing tx" "submitted txid missing from parsed block txids" check_report "${CONVERGE_MISSING_TX_BLOCK_REPORT}" offline producer-tx
expect_fail_contains "producer rejects rust-submit converge block missing tx" "submitted txid missing from parsed block txids" check_report "${RUST_SUBMIT_GO_MINE_MISSING_TX_BLOCK_REPORT}" offline producer-tx
expect_fail_contains "producer rejects uncommitted converge block tx list" "basic block validation failed" check_report "${CONVERGE_BAD_MERKLE_BLOCK_REPORT}" offline producer-tx
expect_fail_contains "producer rejects converge block tx_count mismatch" "parsed block tx_count mismatch" check_report "${CONVERGE_TX_COUNT_MISMATCH_REPORT}" offline producer-tx
expect_fail_token "token maps converge class drift" "rust_mine_class_invalid" check_report "${CONVERGE_BAD_RUST_CLASS_REPORT}" offline producer-tx
expect_fail_token "token maps go mine class drift" "go_mine_class_invalid" check_report "${RUST_SUBMIT_GO_MINE_BAD_GO_CLASS_REPORT}" offline producer-tx
expect_fail_token "token maps rust converge class drift" "rust_converge_class_invalid" check_report "${RUST_SUBMIT_GO_MINE_BAD_RUST_CONVERGE_CLASS_REPORT}" offline producer-tx
expect_fail_token "token maps reused converge sidecar path" "converge_sidecar_paths_not_distinct" check_report "${CONVERGE_DUPLICATE_SIDECAR_REPORT}" offline producer-tx
expect_fail_token "token maps reused rust-submit converge sidecar path" "converge_sidecar_paths_not_distinct" check_report "${RUST_SUBMIT_GO_MINE_DUPLICATE_SIDECAR_REPORT}" offline producer-tx
expect_fail_token "token maps propagation sample failures" "propagation_samples_invalid" check_report "${TX_MISSING_PROPAGATION_SAMPLE_REPORT}" offline producer-tx
expect_fail_token "token maps convergence sample failures" "convergence_samples_invalid" check_report "${CONVERGE_MISSING_CONVERGENCE_SAMPLE_REPORT}" offline producer-tx
expect_fail_token "token maps wrong-source converge sidecar" "converge_sidecar_identity_mismatch" check_report "${CONVERGE_WRONG_SIDECAR_SOURCE_REPORT}" offline producer-tx
expect_fail_token "token maps wrong-source rust converge sidecar" "converge_sidecar_identity_mismatch" check_report "${RUST_SUBMIT_GO_MINE_WRONG_SIDECAR_SOURCE_REPORT}" offline producer-tx
expect_fail_token "token maps malformed parsed block" "block_hex_parse_failed" check_report "${CONVERGE_MALFORMED_BLOCK_REPORT}" offline producer-tx
expect_fail_token "token maps malformed rust parsed block" "block_hex_parse_failed" check_report "${RUST_SUBMIT_GO_MINE_MALFORMED_BLOCK_REPORT}" offline producer-tx
expect_fail_token "token maps parsed block tx omission" "block_missing_submitted_txid" check_report "${CONVERGE_MISSING_TX_BLOCK_REPORT}" offline producer-tx
expect_fail_token "token maps rust-submit parsed block tx omission" "block_missing_submitted_txid" check_report "${RUST_SUBMIT_GO_MINE_MISSING_TX_BLOCK_REPORT}" offline producer-tx
expect_fail_token "token maps uncommitted block tx list" "block_basic_validation_failed" check_report "${CONVERGE_BAD_MERKLE_BLOCK_REPORT}" offline producer-tx
expect_fail_token "token maps block tx_count mismatch" "block_tx_count_mismatch" check_report "${CONVERGE_TX_COUNT_MISMATCH_REPORT}" offline producer-tx
[[ "$(block_inclusion_failure_reason rust_mine "parse block_hex failed: short block")" == "rust_mine_block_hex_parse_failed" ]] || { echo "FAIL: rust mine parse failure reason collapsed" >&2; exit 1; }
[[ "$(block_inclusion_failure_reason rust_mine "parsed block hash mismatch")" == "rust_mine_block_hash_mismatch" ]] || { echo "FAIL: rust mine hash mismatch reason collapsed" >&2; exit 1; }
[[ "$(block_inclusion_failure_reason rust_mine "basic block validation failed: BLOCK_ERR_MERKLE_INVALID")" == "rust_mine_block_basic_validation_failed" ]] || { echo "FAIL: rust mine basic block failure reason collapsed" >&2; exit 1; }
[[ "$(block_inclusion_failure_reason go_converge "parsed block tx_count mismatch")" == "go_converge_block_tx_count_mismatch" ]] || { echo "FAIL: go converge tx_count mismatch reason collapsed" >&2; exit 1; }
[[ "$(block_inclusion_failure_reason go_converge "submitted txid missing from parsed block txids")" == "go_converge_block_missing_submitted_txid" ]] || { echo "FAIL: go converge missing-tx reason collapsed" >&2; exit 1; }
[[ "$(block_inclusion_failure_reason go_converge "block response height/hash/canonical mismatch")" == "go_converge_block_sidecar_mismatch" ]] || { echo "FAIL: go converge sidecar mismatch reason collapsed" >&2; exit 1; }
printf '{"mined":false,"error":"live mining unavailable"}\n' >"${TMP_ROOT}/mine-live-unavailable.json"
printf '{"mined":false,"error":"sync engine unavailable"}\n' >"${TMP_ROOT}/mine-sync-unavailable.json"
printf '{"mined":false,"error":"tx pool unavailable"}\n' >"${TMP_ROOT}/mine-pool-unavailable.json"
printf '{"mined":false,"error":"template rejected"}\n' >"${TMP_ROOT}/mine-rejected.json"
[[ "$(mine_next_http_error_reason "${TMP_ROOT}/mine-live-unavailable.json")" == "rust_mine_live_mining_unavailable" ]] || { echo "FAIL: live mining error reason collapsed" >&2; exit 1; }
[[ "$(mine_next_http_error_reason "${TMP_ROOT}/mine-sync-unavailable.json")" == "rust_mine_sync_unavailable" ]] || { echo "FAIL: sync unavailable error reason collapsed" >&2; exit 1; }
[[ "$(mine_next_http_error_reason "${TMP_ROOT}/mine-pool-unavailable.json")" == "rust_mine_tx_pool_unavailable" ]] || { echo "FAIL: tx pool unavailable error reason collapsed" >&2; exit 1; }
[[ "$(mine_next_http_error_reason "${TMP_ROOT}/mine-rejected.json")" == "rust_mine_rejected" ]] || { echo "FAIL: miner rejection error reason collapsed" >&2; exit 1; }
[[ "$(mine_next_http_error_reason "${TMP_ROOT}/mine-pool-unavailable.json" go_mine)" == "go_mine_tx_pool_unavailable" ]] || { echo "FAIL: go mine tx pool unavailable error reason collapsed" >&2; exit 1; }
rpc_json() {
  [[ "$1" == "POST" && "$3" == "/mine_next" ]] || return 1
  printf '{"mined":false,"error":"tx pool unavailable"}\n'
  return 22
}
export RUST_RPC_ADDR="127.0.0.1:59999"
RUST_MINE_JSON="${TMP_ROOT}/mine-next-sidecar.json"
TX_REASON=""
if rust_mine_including_tx; then
  echo "FAIL: rust_mine_including_tx should fail on /mine_next HTTP error" >&2
  exit 1
fi
[[ "${TX_REASON}" == "rust_mine_tx_pool_unavailable" ]] || { echo "FAIL: mine_next HTTP body did not map through raw sidecar to TX_REASON: ${TX_REASON}" >&2; exit 1; }
[[ ! -e "${RUST_MINE_JSON}.raw" ]] || { echo "FAIL: mine_next HTTP raw body was not cleaned up" >&2; exit 1; }
export GO_RPC_ADDR="127.0.0.1:59998"
GO_MINE_JSON="${TMP_ROOT}/go-mine-next-sidecar.json"
TX_REASON=""
if go_mine_including_tx; then
  echo "FAIL: go_mine_including_tx should fail on /mine_next HTTP error" >&2
  exit 1
fi
[[ "${TX_REASON}" == "go_mine_tx_pool_unavailable" ]] || { echo "FAIL: go mine_next HTTP body did not map through raw sidecar to TX_REASON: ${TX_REASON}" >&2; exit 1; }
[[ ! -e "${GO_MINE_JSON}.raw" ]] || { echo "FAIL: go mine_next HTTP raw body was not cleaned up" >&2; exit 1; }

expect_fail_contains "non-regular report" "report is not a regular file" "${HARNESS}" --check-report "${TMP_ROOT}"
expect_fail_contains "empty report" "report is empty" "${HARNESS}" --check-report "${TMP_ROOT}/empty.json"
expect_fail_contains "malformed report" "report malformed JSON" "${HARNESS}" --check-report "${TMP_ROOT}/malformed.json"
expect_fail_contains "oversized report" "report is too large" "${HARNESS}" --check-report "${TMP_ROOT}/oversized.json"

printf 'PASS: mixed-client mesh check-report public/internal boundaries are covered\n'
