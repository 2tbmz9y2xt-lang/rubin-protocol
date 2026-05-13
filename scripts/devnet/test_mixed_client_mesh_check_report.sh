#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
HARNESS="${REPO_ROOT}/scripts/devnet-mixed-client-mesh.sh"
DEV_ENV="${REPO_ROOT}/scripts/dev-env.sh"
VALIDATOR="${REPO_ROOT}/scripts/devnet/validate_mixed_client_evidence.py"
GO_MODULE_ROOT="${REPO_ROOT}/clients/go"
MESH_TIMEOUT=1
export GO_MODULE_ROOT
export MESH_TIMEOUT

command -v python3 >/dev/null 2>&1 || { echo "python3 is required" >&2; exit 1; }
[[ -x "${HARNESS}" ]] || { echo "mixed-client mesh harness missing or non-executable: ${HARNESS}" >&2; exit 1; }
[[ -x "${DEV_ENV}" ]] || { echo "dev-env wrapper missing or non-executable: ${DEV_ENV}" >&2; exit 1; }
[[ -r "${VALIDATOR}" ]] || { echo "validator unreadable: ${VALIDATOR}" >&2; exit 1; }

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

extract_check_report() {
  python3 - "${HARNESS}" "${CHECK_REPORT_LIB}" <<'PY'
from pathlib import Path
import sys

src, dst = map(Path, sys.argv[1:3])
lines = src.read_text(encoding="utf-8").splitlines()
start = next(i for i, line in enumerate(lines) if line.startswith("check_report()"))
end = next(i for i, line in enumerate(lines[start:], start) if line.startswith('[[ "${MESH_TIMEOUT}"'))
token_start = next(i for i, line in enumerate(lines) if line.startswith("tx_report_reason_token()"))
token_end = next(i for i, line in enumerate(lines[token_start:], token_start) if line.startswith("combined_report_reason_token()"))
Path(dst).write_text("\n".join(lines[start:end] + [""] + lines[token_start:token_end]) + "\n", encoding="utf-8")
PY
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

tx_hex = "010000000001000000000000000001010000000000000000016954e89e15c3eef53f39d5e758fd47dfc84f15f042cd83edc0c93723e93b7d0a83000a00000000000000b3ec7cf4503854f1f691ffb3c0bde5e22af4705161edb20ede25a62e3209a716b3ec7cf4503854f1f691ffb3c0bde5e22af4705161edb20ede25a62e3209a716000000000000"
txid = "d379ae84430d5296e97a71ba8e6996d869b8c6e85b13b51ab0d8ee23455057e1"
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
    "scenario": "mixed_client_mesh",
    "verdict": "PASS",
}
dump(root / "mesh-report.json", mesh_report)

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
height = 102
tx_count = 2
header = b"\x00" * 116
block_hash = hashlib.sha3_256(header).hexdigest()
block_hex = header.hex() + "02" + tx_hex + tx_hex
mutated_tx = bytearray.fromhex(tx_hex)
mutated_tx[5] ^= 0x01
missing_tx_block_hex = header.hex() + "02" + mutated_tx.hex() + mutated_tx.hex()
dump(artifact_root / "rust-mined-block.json", {"block_hex": block_hex, "canonical": True, "hash": block_hash, "height": height, "implementation": "rust", "request_path": f"/get_block?height={height}", "rpc_endpoint": rust_rpc})
dump(artifact_root / "go-converged-block.json", {"block_hex": block_hex, "canonical": True, "hash": block_hash, "height": height, "implementation": "go", "request_path": f"/get_block?height={height}", "rpc_endpoint": go_rpc})
dump(artifact_root / "go-converged-wrong-source-block.json", {"block_hex": block_hex, "canonical": True, "hash": block_hash, "height": height, "implementation": "rust", "request_path": f"/get_block?height={height}", "rpc_endpoint": rust_rpc})
dump(artifact_root / "go-converged-malformed-block.json", {"block_hex": "00", "canonical": True, "hash": block_hash, "height": height, "implementation": "go", "request_path": f"/get_block?height={height}", "rpc_endpoint": go_rpc})
dump(artifact_root / "go-converged-missing-tx-block.json", {"block_hex": missing_tx_block_hex, "canonical": True, "hash": block_hash, "height": height, "implementation": "go", "request_path": f"/get_block?height={height}", "rpc_endpoint": go_rpc})
dump(artifact_root / "rust-mine-next.json", {"block_hash": block_hash, "height": height, "implementation": "rust", "mined": True, "nonce": 0, "request_path": "/mine_next", "rpc_endpoint": rust_rpc, "timestamp": 1, "tx_count": tx_count})
dump(artifact_root / "go-converge-tip.json", {"best_known_height": height, "has_tip": True, "height": height, "implementation": "go", "in_ibd": False, "request_path": "/get_tip", "rpc_endpoint": go_rpc, "tip_hash": block_hash})
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
bad_converge["go_converge"]["block_path"] = str(artifact_root / "go-converged-missing-tx-block.json")
dump(root / "converge-missing-tx-block.json", bad_converge)
(root / "empty.json").write_text("", encoding="utf-8")
(root / "malformed.json").write_text("[", encoding="utf-8")
with (root / "oversized.json").open("wb") as f:
    f.write(b" " * 1_000_001)
print(root / "mesh-report.json")
print(root / "tx-report.json")
print(root / "converge-report.json")
print(root / "converge-wrong-txid.json")
print(root / "converge-bad-rust-class.json")
print(root / "converge-duplicate-sidecar-path.json")
print(root / "converge-wrong-sidecar-source.json")
print(root / "converge-malformed-block.json")
print(root / "converge-missing-tx-block.json")
PY
}

CHECK_REPORT_LIB="${TMP_ROOT}/check-report-lib.sh"
extract_check_report
# shellcheck source=/dev/null
source "${CHECK_REPORT_LIB}"
REPORT_LIST="${TMP_ROOT}/reports.txt"
write_reports >"${REPORT_LIST}"
MESH_REPORT="$(sed -n '1p' "${REPORT_LIST}")"
TX_REPORT="$(sed -n '2p' "${REPORT_LIST}")"
CONVERGE_REPORT="$(sed -n '3p' "${REPORT_LIST}")"
CONVERGE_WRONG_TXID_REPORT="$(sed -n '4p' "${REPORT_LIST}")"
CONVERGE_BAD_RUST_CLASS_REPORT="$(sed -n '5p' "${REPORT_LIST}")"
CONVERGE_DUPLICATE_SIDECAR_REPORT="$(sed -n '6p' "${REPORT_LIST}")"
CONVERGE_WRONG_SIDECAR_SOURCE_REPORT="$(sed -n '7p' "${REPORT_LIST}")"
CONVERGE_MALFORMED_BLOCK_REPORT="$(sed -n '8p' "${REPORT_LIST}")"
CONVERGE_MISSING_TX_BLOCK_REPORT="$(sed -n '9p' "${REPORT_LIST}")"
[[ -n "${MESH_REPORT}" && -n "${TX_REPORT}" && -n "${CONVERGE_REPORT}" && -n "${CONVERGE_WRONG_TXID_REPORT}" && -n "${CONVERGE_BAD_RUST_CLASS_REPORT}" && -n "${CONVERGE_DUPLICATE_SIDECAR_REPORT}" && -n "${CONVERGE_WRONG_SIDECAR_SOURCE_REPORT}" && -n "${CONVERGE_MALFORMED_BLOCK_REPORT}" && -n "${CONVERGE_MISSING_TX_BLOCK_REPORT}" ]] || { echo "failed to build synthetic reports" >&2; exit 1; }

expect_pass_contains "public mesh check-report" "PASS: mixed_client_mesh report structurally accepted" "${HARNESS}" --check-report "${MESH_REPORT}"
expect_fail_contains "public tx check-report" "public tx-path check-report is unsupported" "${HARNESS}" --check-report "${TX_REPORT}"
expect_fail_contains "public converge check-report" "public tx-path check-report is unsupported" "${HARNESS}" --check-report "${CONVERGE_REPORT}"
expect_fail_contains "public tx check-report-live" "public tx-path check-report-live is unsupported" "${HARNESS}" --check-report-live "${TX_REPORT}"
expect_fail_contains "combined tx flag and check-report" "tx-path modes cannot be combined" "${HARNESS}" --go-submit-rust-accept --check-report "${TX_REPORT}"
expect_fail_contains "combined tx-path flags reject" "tx-path modes are mutually exclusive" "${HARNESS}" --go-submit-rust-accept --go-submit-rust-mine-go-converge

expect_pass_contains "producer tx internal check" "PASS: mixed_client_go_submit_rust_accept report structurally accepted" check_report "${TX_REPORT}" offline producer-tx
expect_pass_contains "producer converge internal check" "PASS: mixed_client_go_submit_rust_mine_go_converge report structurally accepted" check_report "${CONVERGE_REPORT}" offline producer-tx
expect_fail_contains "producer rejects mesh report" "producer tx validation requires a mixed-client tx-path report" check_report "${MESH_REPORT}" offline producer-tx
expect_fail_contains "producer rejects converged txid drift" "mined/converged tx identity differs from submitted tx" check_report "${CONVERGE_WRONG_TXID_REPORT}" offline producer-tx
expect_fail_contains "producer rejects reused converge sidecar path" "converge sidecar paths are not pairwise distinct" check_report "${CONVERGE_DUPLICATE_SIDECAR_REPORT}" offline producer-tx
expect_fail_contains "producer rejects wrong-source converge block" "go_converge.block_path sidecar identity mismatch" check_report "${CONVERGE_WRONG_SIDECAR_SOURCE_REPORT}" offline producer-tx
expect_fail_contains "producer rejects malformed converge block" "go_converge.block_path inclusion check failed" check_report "${CONVERGE_MALFORMED_BLOCK_REPORT}" offline producer-tx
expect_fail_contains "producer rejects converge block missing tx" "submitted txid missing from parsed block txids" check_report "${CONVERGE_MISSING_TX_BLOCK_REPORT}" offline producer-tx
expect_fail_token "token maps converge class drift" "rust_mine_class_invalid" check_report "${CONVERGE_BAD_RUST_CLASS_REPORT}" offline producer-tx
expect_fail_token "token maps reused converge sidecar path" "converge_sidecar_paths_not_distinct" check_report "${CONVERGE_DUPLICATE_SIDECAR_REPORT}" offline producer-tx
expect_fail_token "token maps wrong-source converge sidecar" "converge_sidecar_identity_mismatch" check_report "${CONVERGE_WRONG_SIDECAR_SOURCE_REPORT}" offline producer-tx
expect_fail_token "token maps malformed parsed block" "block_hex_parse_failed" check_report "${CONVERGE_MALFORMED_BLOCK_REPORT}" offline producer-tx
expect_fail_token "token maps parsed block tx omission" "block_missing_submitted_txid" check_report "${CONVERGE_MISSING_TX_BLOCK_REPORT}" offline producer-tx

expect_fail_contains "non-regular report" "report is not a regular file" "${HARNESS}" --check-report "${TMP_ROOT}"
expect_fail_contains "empty report" "report is empty" "${HARNESS}" --check-report "${TMP_ROOT}/empty.json"
expect_fail_contains "malformed report" "report malformed JSON" "${HARNESS}" --check-report "${TMP_ROOT}/malformed.json"
expect_fail_contains "oversized report" "report is too large" "${HARNESS}" --check-report "${TMP_ROOT}/oversized.json"

printf 'PASS: mixed-client mesh check-report public/internal boundaries are covered\n'
