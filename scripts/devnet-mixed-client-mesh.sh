#!/usr/bin/env bash
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEV_ENV="${REPO_ROOT}/scripts/dev-env.sh"
GO_MODULE_ROOT="${REPO_ROOT}/clients/go"
RUST_WORKSPACE_ROOT="${REPO_ROOT}/clients/rust"
HELPER="${REPO_ROOT}/scripts/devnet-process-common.sh"
VALIDATOR="${REPO_ROOT}/scripts/devnet/validate_mixed_client_evidence.py"
CHECK_REPORT="" CHECK_REPORT_MODE=0 MESH_TIMEOUT="${MESH_TIMEOUT:-90}"
usage() { echo "usage: $0 [--check-report PATH]" >&2; }
while (($#)); do
  case "$1" in
    --check-report)
      [[ $# -ge 2 ]] || { usage; exit 2; }
      CHECK_REPORT_MODE=1
      CHECK_REPORT="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage
      exit 2
      ;;
  esac
done
need_tool() { command -v -- "$1" >/dev/null 2>&1 || { echo "$1 is required for mixed-client mesh evidence" >&2; exit 1; }; }
check_report() { local report="${1:-}" mode="${2:-offline}"
  [[ -n "${report}" ]] || { echo "FAIL: report path is required" >&2; return 1; }
  python3 - "${report}" "${DEV_ENV}" "${VALIDATOR}" "${mode}" <<'PY'
import datetime as dt, json, os, subprocess, sys, urllib.request
from pathlib import Path
path = Path(sys.argv[1])
live = sys.argv[4] == "live"
def fail(message: str) -> None: print(f"FAIL: {message}", file=sys.stderr); sys.exit(1)
def req(ok: bool, message: str) -> None:
    if not ok: fail(message)
def run(argv: list[str]) -> str:
    try:
        p = subprocess.run(argv, check=False, text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=5)
    except (OSError, subprocess.TimeoutExpired) as exc:
        fail(f"live check failed for {argv[0]}: {exc}")
    req(p.returncode == 0 and p.stdout.strip(), f"live check failed: {' '.join(argv)}")
    return p.stdout.strip().splitlines()[0]
def checked_path(label: str, value: object) -> Path:
    req(isinstance(value, str) and value.strip() == value and value and value[0] not in "'\"" and value[-1] not in "'\"", f"{label} is not an unquoted path string")
    p = Path(value)
    req(p.is_absolute(), f"{label} is not absolute")
    return p
def ep(value: object) -> bool:
    if not isinstance(value, str): return False
    host, sep, port = value.partition(":")
    return sep == ":" and host == "127.0.0.1" and ":" not in port and port.isascii() and port.isdigit() and 1 <= int(port) <= 65535
def nonempty_str(value: object) -> bool: return isinstance(value, str) and bool(value.strip())
def ps_comm(pid: int) -> str: return os.path.basename(run(["ps", "-ww", "-p", str(pid), "-o", "comm="]))
def lsof_lines(pid: int, state: str) -> list[str]:
    p = subprocess.run(["lsof", "-nP", "-a", "-p", str(pid), "-iTCP", f"-sTCP:{state}", "-Fn"], check=False, text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=5)
    return [line[1:] for line in p.stdout.splitlines() if line.startswith("n")]
def owns_listen(pid: int, endpoint: str) -> bool: return endpoint in lsof_lines(pid, "LISTEN")
def peers(addr: str) -> dict:
    try:
        with urllib.request.urlopen(f"http://{addr}/peers", timeout=5) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except Exception as exc:
        fail(f"live peer snapshot failed for {addr}: {exc}")
    return data if isinstance(data, dict) else {}
def snapshot_norm(snapshot: object) -> list[tuple[str, bool]]:
    count = snapshot.get("count") if isinstance(snapshot, dict) else None
    peers = snapshot.get("peers") if isinstance(snapshot, dict) else None
    req(isinstance(count, int) and not isinstance(count, bool) and isinstance(peers, list) and count == len(peers), "peer snapshot count/peers are invalid")
    norm = sorted((p.get("addr"), p.get("handshake_complete")) for p in peers if isinstance(p, dict) and ep(p.get("addr")) and isinstance(p.get("handshake_complete"), bool))
    req(len(norm) == len(peers) and len({addr for addr, _ in norm}) == len(norm), "peer snapshot entries are malformed or duplicated")
    return norm
def ts(value: object) -> bool:
    if not isinstance(value, str) or len(value) != 20 or value[-1] != "Z": return False
    try:
        return dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").strftime("%Y-%m-%dT%H:%M:%SZ") == value
    except ValueError:
        return False
try:
    with path.open(encoding="utf-8") as f:
        data = json.load(f)
except OSError as exc:
    fail(f"cannot read report: {exc}")
except json.JSONDecodeError as exc:
    fail(f"malformed JSON report: {exc}")
req(isinstance(data, dict), "report root is not an object")
req(data.get("scenario") == "mixed_client_mesh", f"scenario is not mixed_client_mesh: {data.get('scenario')!r}")
req(data.get("verdict") == "PASS", f"report verdict is not PASS: {data.get('verdict')!r}")
req("failure_reason" not in data and "schema_marker" not in data, "PASS report must not carry failure/schema-marker verdict fields")
artifact_root = checked_path("artifact_root", data.get("artifact_root")).resolve()
legacy_schema = data.get("legacy_schema_compatibility")
req(isinstance(legacy_schema, dict) and legacy_schema.get("authoritative") is False and "verdict" not in legacy_schema and nonempty_str(legacy_schema.get("marker_path")), "legacy_schema_compatibility missing marker_path")
marker_path = checked_path("legacy_schema_compatibility.marker_path", legacy_schema.get("marker_path")).resolve()
try: marker_path.relative_to(artifact_root)
except ValueError: fail("legacy marker is outside artifact_root")
req(marker_path.is_file() and marker_path.stat().st_size > 0, "legacy marker is missing, unreadable, or empty")
try:
    with marker_path.open(encoding="utf-8") as f: marker = json.load(f)
except (OSError, json.JSONDecodeError) as exc:
    fail(f"legacy marker is not readable JSON: {exc}")
req(isinstance(marker, dict) and marker.get("scenario") == "mixed_client_mesh_schema_marker" and marker.get("verdict") == "FAIL" and marker.get("evidence_type") == "mixed_client_process_soak", "legacy marker has wrong non-authoritative FAIL shape")
try: validator = subprocess.run([sys.argv[2], "--", "python3", sys.argv[3], str(marker_path)], check=False, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
except (OSError, subprocess.TimeoutExpired) as exc: fail(f"legacy marker schema validation failed: {exc}")
req(validator.returncode == 0, "legacy marker schema validation failed: " + ((validator.stderr or validator.stdout).strip().splitlines() or ["validator returned nonzero"])[0])
nodes = data.get("nodes")
req(isinstance(nodes, list) and len(nodes) == 2 and all(isinstance(n, dict) for n in nodes), "PASS report requires exactly two node records")
expected = {"go": ("node-go", "rubin-node-go"), "rust": ("node-rust", "rubin-node-rust")}
for node in nodes:
    impl = node.get("implementation")
    name = node.get("name")
    req(isinstance(impl, str) and impl in expected, f"node has invalid implementation: {impl!r}")
    expected_name, expected_bin = expected[impl]
    req(name == expected_name, f"{impl} node has invalid name: {name!r}")
    command, binary, command_argv = node.get("command"), node.get("binary"), node.get("command_argv")
    binary_path = checked_path(f"{name}.binary", binary).resolve()
    try: binary_path.relative_to(artifact_root)
    except ValueError: fail(f"{name} binary is outside artifact_root")
    req(node.get("process_comm") == expected_bin, f"{name} process_comm does not prove {impl} identity")
    req(nonempty_str(command) and isinstance(command_argv, list) and all(isinstance(arg, str) for arg in command_argv) and command_argv and Path(command_argv[0]).is_absolute() and Path(command_argv[0]).resolve() == binary_path and binary_path.name == expected_bin and binary_path.is_file() and os.access(binary_path, os.X_OK), f"{name} command/binary is not bound to executable {expected_bin}")
    req(ep(node.get("rpc_endpoint")) and ep(node.get("p2p_endpoint")) and ts(node.get("started_at")), f"{name} has malformed endpoint or timestamp")
    req(isinstance(node.get("pid"), int) and not isinstance(node.get("pid"), bool) and node["pid"] > 0, f"{name} pid is not a positive integer")
    if live: req(ps_comm(node["pid"]) == expected_bin, f"{name} live process identity does not match report"); req(owns_listen(node["pid"], node["rpc_endpoint"]) and owns_listen(node["pid"], node["p2p_endpoint"]), f"{name} live listeners are not pid-owned")
    for field in ("process_alive", "rpc_endpoint_process_backed", "p2p_endpoint_process_backed"):
        req(node.get(field) is True, f"{name} does not prove {field}")
impls = {n["implementation"] for n in nodes}
req(impls == {"go", "rust"}, f"PASS report requires one go and one rust node, got {sorted(impls)}")
nodes_by_impl = {node["implementation"]: node for node in nodes}
req(nodes_by_impl["go"]["pid"] != nodes_by_impl["rust"]["pid"], "go/rust process evidence uses the same pid")
req(nodes_by_impl["go"]["binary"] != nodes_by_impl["rust"]["binary"] and nodes_by_impl["go"]["command"] != nodes_by_impl["rust"]["command"] and nodes_by_impl["go"].get("command_argv") != nodes_by_impl["rust"].get("command_argv"), "go/rust process evidence is not implementation-distinct")
connectivity = data.get("peer_connectivity")
req(isinstance(connectivity, dict), "PASS report missing peer_connectivity object")
req(all(connectivity.get(f) is True for f in ("go_to_rust", "rust_to_go", "bidirectional_observed")), "peer_connectivity booleans are not all true")
links = connectivity.get("counterpart_links")
req(isinstance(links, dict), "PASS report missing counterpart_links")
go_expected = links.get("go_peer_snapshot_expected_addr")
rust_expected = links.get("rust_peer_snapshot_expected_addr")
req(all(ep(links.get(f)) for f in ("go_peer_snapshot_expected_addr", "rust_peer_snapshot_expected_addr", "rust_outbound_local_addr", "rust_outbound_remote_addr")), "counterpart link endpoint is malformed")
req(rust_expected == nodes_by_impl["go"]["p2p_endpoint"] and links.get("rust_outbound_remote_addr") == rust_expected and links.get("rust_outbound_local_addr") == go_expected and links.get("rust_outbound_pid") == nodes_by_impl["rust"]["pid"], "peer evidence is not bound to expected counterpart endpoints")
req(isinstance(go_expected, str) and go_expected not in {rust_expected, nodes_by_impl["rust"]["p2p_endpoint"], nodes_by_impl["go"]["rpc_endpoint"], nodes_by_impl["rust"]["rpc_endpoint"]}, "go peer evidence is not a rust outbound peer address")
if live: req(f"{go_expected}->{rust_expected}" in lsof_lines(nodes_by_impl["rust"]["pid"], "ESTABLISHED"), "rust outbound TCP link is not live and rust-owned")
final = data.get("final_verification")
req(isinstance(final, dict) and all(final.get(f) is True for f in ("producer_side", "process_identity_rechecked", "rust_outbound_link_rechecked", "peer_snapshots_rechecked")), "PASS report missing producer-side final verification")
req(final.get("rust_outbound_pid") == nodes_by_impl["rust"]["pid"] and final.get("rust_outbound_local_addr") == go_expected and final.get("rust_outbound_remote_addr") == rust_expected, "final verification is not bound to peer evidence")
for field, expected_addr in (("go_peer_snapshot", go_expected), ("rust_peer_snapshot", rust_expected)):
    stored = snapshot_norm(connectivity.get(field))
    req((expected_addr, True) in stored, f"{field} missing expected completed peer")
    if live: fresh = snapshot_norm(peers(nodes_by_impl["go" if field.startswith("go_") else "rust"]["rpc_endpoint"])); req(stored == fresh, f"{field} differs from live exact peer set")
print(f"PASS: mixed-client mesh report accepted {path}")
PY
}
if [[ "${CHECK_REPORT_MODE}" == "1" ]]; then need_tool python3; check_report "${CHECK_REPORT}" offline; exit 0; fi
need_tool python3
[[ -x "${DEV_ENV}" ]] || { echo "dev-env wrapper missing or non-executable: ${DEV_ENV}" >&2; exit 1; }
[[ -r "${VALIDATOR}" ]] || { echo "validator unreadable: ${VALIDATOR}" >&2; exit 1; }
# shellcheck source=scripts/devnet-process-common.sh disable=SC1091
source "${HELPER}"
rubin_process_init mixed-client-mesh
GO_NODE_BIN="${RUBIN_PROCESS_ARTIFACT_ROOT}/rubin-node-go"
RUST_NODE_BIN="${RUBIN_PROCESS_ARTIFACT_ROOT}/rubin-node-rust"
GO_DIR="${RUBIN_PROCESS_ARTIFACT_ROOT}/node-go"
RUST_DIR="${RUBIN_PROCESS_ARTIFACT_ROOT}/node-rust"
GO_LOG="node-go.log"
RUST_LOG="node-rust.log"
REPORT_JSON="${RUBIN_PROCESS_ARTIFACT_ROOT}/mixed-client-mesh-report.json"
LEGACY_SCHEMA_MARKER_JSON="${RUBIN_PROCESS_ARTIFACT_ROOT}/mixed-client-mesh-legacy-schema-marker.json"
GO_PEERS_JSON="${RUBIN_PROCESS_ARTIFACT_ROOT}/go-peers.json"
RUST_PEERS_JSON="${RUBIN_PROCESS_ARTIFACT_ROOT}/rust-peers.json"
GO_PID="" RUST_PID="" GO_RPC_ADDR="" RUST_RPC_ADDR="" GO_P2P_ADDR="" RUST_P2P_ADDR="" GO_STARTED_AT_UTC="" RUST_STARTED_AT_UTC=""
GO_COMM="" RUST_COMM="" RUST_TO_GO_LOCAL_ADDR="" GO_CMD="" RUST_CMD="" GO_ARGV_JSON="" RUST_ARGV_JSON=""
FINAL_PROCESS_IDENTITY_RECHECKED="" FINAL_RUST_OUTBOUND_LINK_RECHECKED="" FINAL_PEER_SNAPSHOTS_RECHECKED=""
mkdir -p -- "${GO_DIR}" "${RUST_DIR}"
run_fips_preflight_before_captured_dev_env() { [[ "${RUBIN_OPENSSL_FIPS_MODE:-off}" != "only" || "${RUBIN_OPENSSL_SKIP_FIPS_GUARD:-0}" == "1" ]] && return 0; echo "Running FIPS-only preflight before captured dev-env command streams" >&2; "${DEV_ENV}" -- "${REPO_ROOT}/scripts/crypto/openssl/fips-preflight.sh" >&2; }
run_validator() { RUBIN_OPENSSL_SKIP_FIPS_GUARD=1 "${DEV_ENV}" -- python3 "${VALIDATOR}" "$@"; }
argv_cmd() { local out="" arg q; for arg; do printf -v q "%q" "$arg"; out+="${out:+ }${q}"; done; printf '%s\n' "${out}"; }; argv_json() { python3 -c 'import json,sys; print(json.dumps(sys.argv[1:]))' "$@"; }
rpc_json() {
  local method="$1" addr="$2" path="$3"
  python3 - "${method}" "${addr}" "${path}" <<'PY'
import socket, sys, urllib.error, urllib.request
method, addr, path = sys.argv[1:4]
req = urllib.request.Request(f"http://{addr}{path}", method=method)
try:
    with urllib.request.urlopen(req, timeout=5) as resp: print(resp.read().decode("utf-8"), end="")
except urllib.error.HTTPError as exc:
    print(exc.read().decode("utf-8"), end="")
    sys.exit(22)
except (urllib.error.URLError, TimeoutError, socket.timeout) as exc:
    print(f"request failed: {getattr(exc, 'reason', exc)}", end="")
    sys.exit(1)
PY
}
pid_comm() {
  local pid="$1" comm
  comm="$(ps -ww -p "${pid}" -o comm= 2>/dev/null | sed -n '1p')" || return 1; [[ -n "${comm}" ]] || return 1; basename -- "${comm}"
}
pid_listens_on() {
  local pid="$1" endpoint="$2" out status=0
  out="$(lsof -nP -a -p "${pid}" -iTCP -sTCP:LISTEN -Fn 2>&1)" || status=$?
  grep -F -x -q -- "n${endpoint}" <<<"${out}" && return 0
  (( status == 0 || ${#out} == 0 )) || return 2
  return 1
}
p2p_addr_for_pid() {
  local pid="$1" rpc_addr="$2" timeout="$3"
  python3 - "${pid}" "${rpc_addr}" "${timeout}" <<'PY'
import re, subprocess, sys, time
pid, rpc_addr, timeout = sys.argv[1], sys.argv[2], int(sys.argv[3])
deadline = time.time() + timeout
while time.time() < deadline:
    proc = subprocess.run(["lsof", "-nP", "-a", "-p", pid, "-iTCP", "-sTCP:LISTEN", "-Fn"], text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    addrs = sorted({line[1:].strip() for line in proc.stdout.splitlines() if line.startswith("n") and line[1:].strip() != rpc_addr and re.fullmatch(r"127\.0\.0\.1:[0-9]+", line[1:].strip())})
    if len(addrs) == 1: print(addrs[0]); sys.exit(0)
    if len(addrs) > 1: sys.exit(f"ambiguous p2p listen addresses for pid={pid}: {addrs}")
    time.sleep(1)
sys.exit(f"timeout resolving p2p listen address for pid={pid}")
PY
}
extract_log_addr() {
  local log_file="$1" prefix="$2" path addr
  path="$(_rubin_process_resolve_log "${log_file}")" || return 1
  addr="$(sed -n "s/.*${prefix}//p" "${path}" | tail -n 1 | tr -d '[:space:]')" || return 1
  [[ "${addr}" == 127.0.0.1:* ]] || return 1
  printf '%s\n' "${addr}"
}
build_go_node() { echo "Building Go rubin-node binary" >&2; "${DEV_ENV}" -- go -C "${GO_MODULE_ROOT}" build -o "${GO_NODE_BIN}" ./cmd/rubin-node || return 1; [[ -x "${GO_NODE_BIN}" ]]; }
build_rust_node() {
  local host_triple cargo_target_dir cargo_log cargo_bin
  echo "Building Rust rubin-node binary" >&2
  run_fips_preflight_before_captured_dev_env
  host_triple="$(RUBIN_OPENSSL_SKIP_FIPS_GUARD=1 "${DEV_ENV}" -- rustc -vV | awk '/^host:/ {print $2}')" || return 1
  [[ -n "${host_triple}" ]] || return 1
  cargo_target_dir="${RUBIN_PROCESS_ARTIFACT_ROOT}/cargo-target"
  cargo_log="${RUBIN_PROCESS_ARTIFACT_ROOT}/cargo-build.jsonl"
  RUBIN_OPENSSL_SKIP_FIPS_GUARD=1 "${DEV_ENV}" -- cargo build --manifest-path "${RUST_WORKSPACE_ROOT}/Cargo.toml" --release --locked -p rubin-node --target "${host_triple}" --target-dir "${cargo_target_dir}" --message-format=json-render-diagnostics >"${cargo_log}" || return 1
  cargo_bin="$(python3 - "${cargo_log}" <<'PY'
import json, sys
selected = None
with open(sys.argv[1], encoding="utf-8") as f:
    for line_no, raw in enumerate(f, 1):
        line = raw.strip()
        if not line: continue
        if not line.startswith("{"): sys.exit(f"cargo build log contamination: {line[:160]!r}")
        try: ev = json.loads(line)
        except json.JSONDecodeError as exc: sys.exit(f"malformed cargo JSON at line {line_no}: {exc.msg}")
        if ev.get("reason") != "compiler-artifact": continue
        target = ev.get("target") or {}
        if target.get("name") == "rubin-node" and "bin" in (target.get("kind") or []) and ev.get("executable"): selected = ev["executable"]
if selected is None: sys.exit("no rubin-node executable artifact in cargo JSON stream")
print(selected)
PY
)" || return 1
  [[ -x "${cargo_bin}" ]] || return 1
  cp -- "${cargo_bin}" "${RUST_NODE_BIN}" || return 1
  [[ -x "${RUST_NODE_BIN}" ]]
}
write_outputs() {
  local verdict="$1" reason="${2:-}"
  export REPORT_JSON LEGACY_SCHEMA_MARKER_JSON verdict reason GO_PID RUST_PID GO_RPC_ADDR RUST_RPC_ADDR \
    GO_P2P_ADDR RUST_P2P_ADDR GO_STARTED_AT_UTC RUST_STARTED_AT_UTC GO_COMM RUST_COMM \
    GO_NODE_BIN RUST_NODE_BIN GO_CMD RUST_CMD GO_ARGV_JSON RUST_ARGV_JSON GO_PEERS_JSON RUST_PEERS_JSON \
    GO_PROCESS_ALIVE RUST_PROCESS_ALIVE GO_RPC_PROCESS_BACKED RUST_RPC_PROCESS_BACKED GO_P2P_PROCESS_BACKED RUST_P2P_PROCESS_BACKED \
    RUST_TO_GO_LOCAL_ADDR FINAL_PROCESS_IDENTITY_RECHECKED FINAL_RUST_OUTBOUND_LINK_RECHECKED FINAL_PEER_SNAPSHOTS_RECHECKED \
    RUBIN_PROCESS_ARTIFACT_ROOT
  python3 - <<'PY'
import json, os
e = os.environ
verdict = e["verdict"]
reason = (e.get("reason") or "").strip()
def read_json(path: str) -> dict:
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return {"count": 0, "peers": []}
nodes = []
for impl, name, pid_key, rpc_key, p2p_key, started_key, comm_key, bin_key, cmd_key, argv_key in (
    ("go", "node-go", "GO_PID", "GO_RPC_ADDR", "GO_P2P_ADDR", "GO_STARTED_AT_UTC", "GO_COMM", "GO_NODE_BIN", "GO_CMD", "GO_ARGV_JSON"),
    ("rust", "node-rust", "RUST_PID", "RUST_RPC_ADDR", "RUST_P2P_ADDR", "RUST_STARTED_AT_UTC", "RUST_COMM", "RUST_NODE_BIN", "RUST_CMD", "RUST_ARGV_JSON"),
):
    pid_raw = (e.get(pid_key) or "").strip()
    prefix = impl.upper()
    node = {
        "name": name,
        "implementation": impl,
        "pid": int(pid_raw) if pid_raw.isdigit() else None,
        "command": e.get(cmd_key) or "",
        "command_argv": json.loads(e.get(argv_key) or "[]"),
        "binary": e.get(bin_key) or "",
        "rpc_endpoint": e.get(rpc_key) or None,
        "p2p_endpoint": e.get(p2p_key) or None,
        "started_at": e.get(started_key) or None,
        "process_comm": e.get(comm_key) or None,
        "process_alive": verdict == "PASS" and e.get(f"{prefix}_PROCESS_ALIVE") == "true",
        "rpc_endpoint_process_backed": verdict == "PASS" and e.get(f"{prefix}_RPC_PROCESS_BACKED") == "true",
        "p2p_endpoint_process_backed": verdict == "PASS" and e.get(f"{prefix}_P2P_PROCESS_BACKED") == "true",
    }
    nodes.append(node)
go_snapshot, rust_snapshot = read_json(e["GO_PEERS_JSON"]), read_json(e["RUST_PEERS_JSON"])
report = {
    "scenario": "mixed_client_mesh",
    "verdict": verdict,
    "artifact_root": e["RUBIN_PROCESS_ARTIFACT_ROOT"],
    "nodes": nodes,
    "peer_connectivity": {
        "go_to_rust": verdict == "PASS",
        "rust_to_go": verdict == "PASS",
        "bidirectional_observed": verdict == "PASS",
        "counterpart_links": {"go_peer_snapshot_expected_addr": e.get("RUST_TO_GO_LOCAL_ADDR") or None, "rust_peer_snapshot_expected_addr": e.get("GO_P2P_ADDR") or None, "rust_outbound_local_addr": e.get("RUST_TO_GO_LOCAL_ADDR") or None, "rust_outbound_remote_addr": e.get("GO_P2P_ADDR") or None, "rust_outbound_pid": int(e["RUST_PID"]) if e.get("RUST_PID", "").isdigit() else None},
        "go_peer_snapshot": go_snapshot,
        "rust_peer_snapshot": rust_snapshot,
    },
    "final_verification": {"producer_side": verdict == "PASS", "process_identity_rechecked": e.get("FINAL_PROCESS_IDENTITY_RECHECKED") == "true", "rust_outbound_link_rechecked": e.get("FINAL_RUST_OUTBOUND_LINK_RECHECKED") == "true", "peer_snapshots_rechecked": e.get("FINAL_PEER_SNAPSHOTS_RECHECKED") == "true", "rust_outbound_pid": int(e["RUST_PID"]) if e.get("RUST_PID", "").isdigit() else None, "rust_outbound_local_addr": e.get("RUST_TO_GO_LOCAL_ADDR") or None, "rust_outbound_remote_addr": e.get("GO_P2P_ADDR") or None},
    "legacy_schema_compatibility": {
        "authoritative": False,
        "marker_path": e["LEGACY_SCHEMA_MARKER_JSON"],
        "purpose": "schema-valid legacy artifact only; not the mesh report verdict",
        "reason": "existing mixed_client_evidence_v1 PASS requires tx_path; RUB-21 mesh-only PASS lives in this report",
    },
}
if verdict != "PASS":
    report["failure_reason"] = reason or "mixed-client mesh did not produce PASS evidence"
with open(e["REPORT_JSON"], "w", encoding="utf-8") as f:
    json.dump(report, f, indent=2, sort_keys=True)
    f.write("\n")
legacy_marker_reason = reason if verdict != "PASS" and reason else (
    "mixed-client mesh process/connectivity PASS is recorded in sibling report; "
    "existing schema v1 PASS requires tx_path proof owned by RUB-22/RUB-23"
)
legacy_schema_marker = {
    "schema_version": "rubin-mixed-client-devnet-evidence-v1",
    "evidence_type": "mixed_client_process_soak",
    "scenario": "mixed_client_mesh_schema_marker",
    "verdict": "FAIL",
    "failure_reason": legacy_marker_reason,
    "participants": [
        {"name": "node-go", "implementation": "go", **({"endpoint": e["GO_RPC_ADDR"], "started_at": e["GO_STARTED_AT_UTC"]} if e.get("GO_RPC_ADDR") and e.get("GO_STARTED_AT_UTC") else {})},
        {"name": "node-rust", "implementation": "rust", **({"endpoint": e["RUST_RPC_ADDR"], "started_at": e["RUST_STARTED_AT_UTC"]} if e.get("RUST_RPC_ADDR") and e.get("RUST_STARTED_AT_UTC") else {})},
    ],
}
with open(e["LEGACY_SCHEMA_MARKER_JSON"], "w", encoding="utf-8") as f:
    json.dump(legacy_schema_marker, f, indent=2, sort_keys=True)
    f.write("\n")
PY
}
finish_no_data() { local reason="$1"; write_outputs "NO_DATA" "${reason}"; run_validator "${LEGACY_SCHEMA_MARKER_JSON}" >&2; echo "NO_DATA: ${reason}; report=${REPORT_JSON} legacy_schema_marker=${LEGACY_SCHEMA_MARKER_JSON}" >&2; exit 1; }
wait_peer_snapshot() {
  local label="$1" addr="$2" out="$3" timeout="$4" expected="$5" deadline tmp
  deadline=$((SECONDS + timeout))
  tmp="${out}.tmp"
  while (( SECONDS < deadline )); do
    if rpc_json GET "${addr}" /peers >"${tmp}" 2>/dev/null \
      && python3 - "${tmp}" "${expected}" <<'PY' >/dev/null 2>&1
import json, sys
with open(sys.argv[1], encoding="utf-8") as f:
    data = json.load(f)
expected, peers, count = sys.argv[2], data.get("peers"), data.get("count")
def ep(v): return isinstance(v, str) and v.count(":") == 1 and v.startswith("127.0.0.1:") and v.rsplit(":", 1)[-1].isdigit() and 1 <= int(v.rsplit(":", 1)[-1]) <= 65535
ok = isinstance(count, int) and not isinstance(count, bool) and isinstance(peers, list) and count == len(peers) and all(isinstance(p, dict) and ep(p.get("addr")) and isinstance(p.get("handshake_complete"), bool) for p in peers) and len({p.get("addr") for p in peers}) == len(peers) and any(p.get("addr") == expected and p.get("handshake_complete") is True for p in peers)
sys.exit(0 if ok else 1)
PY
    then
      mv -- "${tmp}" "${out}"
      return 0
    fi
    sleep 1
  done
  rm -f -- "${tmp}"
  echo "timeout waiting for ${label} /peers completed handshake" >&2
  return 1
}
wait_rust_to_go_link() {
  local missing="$1" ambiguous="$2" deadline out status
  deadline=$((SECONDS + MESH_TIMEOUT))
  while (( SECONDS < deadline )); do
    status=0; out="$(lsof -nP -a -p "${RUST_PID}" -iTCP -sTCP:ESTABLISHED -Fn 2>/dev/null | REMOTE_ADDR="${GO_P2P_ADDR}" perl -ne 'BEGIN{$r=$ENV{REMOTE_ADDR}} chomp; s/^n// or next; print "$1\n" if /^(127[.]0[.]0[.]1:[0-9]+)->\Q$r\E$/' | sort -u)" || status=$?
    (( status == 0 || ${#out} == 0 )) || finish_no_data "${missing}"
    [[ "${out}" != *$'\n'* ]] || finish_no_data "${ambiguous}"; [[ -z "${out}" ]] || { RUST_TO_GO_LOCAL_ADDR="${out}"; return 0; }
    sleep 1
  done; finish_no_data "${missing}"
}
verify_process_identity() {
  local label="$1" impl="$2" pid="$3" rpc_addr="$4" p2p_addr="$5" expected_comm="$6" comm
  rubin_process_is_alive "${pid}" || { echo "${label} pid is not alive: ${pid}" >&2; return 1; }
  comm="$(pid_comm "${pid}")" || { echo "${label} process comm unavailable: ${pid}" >&2; return 1; }
  [[ "${comm}" == "${expected_comm}" ]] || { echo "${label} process comm=${comm}, want ${expected_comm}" >&2; return 1; }
  pid_listens_on "${pid}" "${rpc_addr}" || { echo "${label} rpc endpoint is not process-backed: ${rpc_addr}" >&2; return 1; }
  pid_listens_on "${pid}" "${p2p_addr}" || { echo "${label} p2p endpoint is not process-backed: ${p2p_addr}" >&2; return 1; }
  case "${impl}" in
    go) GO_COMM="${comm}"; GO_PROCESS_ALIVE=true; GO_RPC_PROCESS_BACKED=true; GO_P2P_PROCESS_BACKED=true ;;
    rust) RUST_COMM="${comm}"; RUST_PROCESS_ALIVE=true; RUST_RPC_PROCESS_BACKED=true; RUST_P2P_PROCESS_BACKED=true ;;
    *) return 1 ;;
  esac
}
start_rust_node() {
  local -a argv=("${RUST_NODE_BIN}" --network devnet --datadir "${RUST_DIR}" --bind 127.0.0.1:0 --rpc-bind 127.0.0.1:0 --peer "${GO_P2P_ADDR}")
  RUST_CMD="$(argv_cmd "${argv[@]}")"; RUST_ARGV_JSON="$(argv_json "${argv[@]}")"
  rubin_process_start "${RUST_LOG}" "${argv[@]}" || return 1
  RUST_PID="${RUBIN_PROCESS_LAST_PID}"
  rubin_process_wait_for_log "${RUST_LOG}" "p2p: listening=" 60 "${RUST_PID}" || return 1
  rubin_process_wait_for_log "${RUST_LOG}" "rpc: listening=" 60 "${RUST_PID}" || return 1
  RUST_P2P_ADDR="$(extract_log_addr "${RUST_LOG}" "p2p: listening=")" || return 1
  RUST_RPC_ADDR="$(rubin_process_extract_rpc_addr "${RUST_LOG}")" || return 1
  rubin_process_wait_for_rpc_ready "${RUST_RPC_ADDR}" 30 || return 1
  RUST_STARTED_AT_UTC="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
start_go_node() {
  local -a argv=("${GO_NODE_BIN}" --network devnet --datadir "${GO_DIR}" --bind 127.0.0.1:0 --rpc-bind 127.0.0.1:0)
  GO_CMD="$(argv_cmd "${argv[@]}")"; GO_ARGV_JSON="$(argv_json "${argv[@]}")"
  rubin_process_start "${GO_LOG}" "${argv[@]}" || return 1
  GO_PID="${RUBIN_PROCESS_LAST_PID}"
  rubin_process_wait_for_log "${GO_LOG}" "rpc: listening=" 60 "${GO_PID}" || return 1
  GO_RPC_ADDR="$(rubin_process_extract_rpc_addr "${GO_LOG}")" || return 1
  GO_P2P_ADDR="$(p2p_addr_for_pid "${GO_PID}" "${GO_RPC_ADDR}" 30)" || return 1
  rubin_process_wait_for_rpc_ready "${GO_RPC_ADDR}" 30 || return 1
  GO_STARTED_AT_UTC="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
[[ "${MESH_TIMEOUT}" =~ ^[0-9]{1,3}$ ]] || { echo "MESH_TIMEOUT must be an integer in [1, 600]" >&2; exit 2; }
MESH_TIMEOUT="$((10#${MESH_TIMEOUT}))"; (( MESH_TIMEOUT >= 1 && MESH_TIMEOUT <= 600 )) || { echo "MESH_TIMEOUT must be an integer in [1, 600]" >&2; exit 2; }
command -v lsof >/dev/null 2>&1 || finish_no_data "lsof_unavailable"; command -v perl >/dev/null 2>&1 || finish_no_data "perl_unavailable"
build_go_node || finish_no_data "go_build_failed"
build_rust_node || finish_no_data "rust_build_failed"
start_go_node || finish_no_data "go_process_not_ready"
verify_process_identity node-go go "${GO_PID}" "${GO_RPC_ADDR}" "${GO_P2P_ADDR}" rubin-node-go || finish_no_data "go_process_identity_unverified"
start_rust_node || finish_no_data "rust_process_not_ready"
verify_process_identity node-rust rust "${RUST_PID}" "${RUST_RPC_ADDR}" "${RUST_P2P_ADDR}" rubin-node-rust || finish_no_data "rust_process_identity_unverified"
wait_peer_snapshot node-rust "${RUST_RPC_ADDR}" "${RUST_PEERS_JSON}" "${MESH_TIMEOUT}" "${GO_P2P_ADDR}" || finish_no_data "rust_peer_snapshot_missing_go_endpoint"
wait_rust_to_go_link rust_to_go_tcp_link_missing rust_to_go_tcp_link_ambiguous
wait_peer_snapshot node-go "${GO_RPC_ADDR}" "${GO_PEERS_JSON}" "${MESH_TIMEOUT}" "${RUST_TO_GO_LOCAL_ADDR}" || finish_no_data "go_peer_snapshot_missing_rust_endpoint"
verify_process_identity node-go-final go "${GO_PID}" "${GO_RPC_ADDR}" "${GO_P2P_ADDR}" rubin-node-go || finish_no_data "go_final_process_identity_unverified"
verify_process_identity node-rust-final rust "${RUST_PID}" "${RUST_RPC_ADDR}" "${RUST_P2P_ADDR}" rubin-node-rust || finish_no_data "rust_final_process_identity_unverified"
FINAL_PROCESS_IDENTITY_RECHECKED=true
wait_rust_to_go_link rust_final_to_go_tcp_link_missing rust_final_to_go_tcp_link_ambiguous
FINAL_RUST_OUTBOUND_LINK_RECHECKED=true
wait_peer_snapshot node-rust-final "${RUST_RPC_ADDR}" "${RUST_PEERS_JSON}" "${MESH_TIMEOUT}" "${GO_P2P_ADDR}" || finish_no_data "rust_final_peer_snapshot_missing_go_endpoint"
wait_peer_snapshot node-go-final "${GO_RPC_ADDR}" "${GO_PEERS_JSON}" "${MESH_TIMEOUT}" "${RUST_TO_GO_LOCAL_ADDR}" || finish_no_data "go_final_peer_snapshot_missing_rust_endpoint"
FINAL_PEER_SNAPSHOTS_RECHECKED=true
PASS_REPORT_JSON="${REPORT_JSON}.pass.tmp"; FINAL_REPORT_JSON="${REPORT_JSON}"; REPORT_JSON="${PASS_REPORT_JSON}"
write_outputs "PASS"; REPORT_JSON="${FINAL_REPORT_JSON}"
if run_validator "${LEGACY_SCHEMA_MARKER_JSON}" >&2 && check_report "${PASS_REPORT_JSON}" live >&2; then
  mv -- "${PASS_REPORT_JSON}" "${REPORT_JSON}"
else
  rm -f -- "${PASS_REPORT_JSON}"; finish_no_data "pass_report_validation_failed"
fi
[[ "${RUBIN_PROCESS_KEEP_ARTIFACTS}" == "1" ]] && echo "PASS: mixed-client mesh connected go_pid=${GO_PID} rust_pid=${RUST_PID}; report=${REPORT_JSON} legacy_schema_marker=${LEGACY_SCHEMA_MARKER_JSON}" || echo "PASS: mixed-client mesh connected go_pid=${GO_PID} rust_pid=${RUST_PID}; set KEEP_TMP=1 to retain report"
