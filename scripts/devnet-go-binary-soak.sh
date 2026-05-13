#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEV_ENV="${REPO_ROOT}/scripts/dev-env.sh"
GO_MODULE_ROOT="${REPO_ROOT}/clients/go"
RUST_MODULE_ROOT="${REPO_ROOT}/clients/rust"
HELPER="${REPO_ROOT}/scripts/devnet-process-common.sh"
TARGET_HEIGHT=120 WITH_RESTART=0 MIXED_PARTITION_HEAL=0 MIXED_PARTITION_HEAL_REORG=0

usage() { echo "usage: $0 [--target-height N] [--with-restart] [--mixed-client-partition-heal] [--mixed-client-partition-heal-reorg]" >&2; }
while (($#)); do
  case "$1" in
    --target-height)
      [[ $# -ge 2 ]] || { usage; exit 2; }
      TARGET_HEIGHT="$2"
      shift 2
      ;;
    --with-restart)
      WITH_RESTART=1
      shift
      ;;
    --mixed-client-partition-heal)
      MIXED_PARTITION_HEAL=1
      shift
      ;;
    --mixed-client-partition-heal-reorg)
      MIXED_PARTITION_HEAL_REORG=1
      shift
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
(( MIXED_PARTITION_HEAL + MIXED_PARTITION_HEAL_REORG <= 1 )) || { usage; exit 2; }
for tool in python3 perl lsof; do
  command -v "${tool}" >/dev/null 2>&1 || {
    echo "${tool} is required for Go binary soak evidence" >&2
    exit 1
  }
done
# Runtime txgen needs base height >=100; bound height to keep the soak finite.
TARGET_HEIGHT="$(python3 -c 'import sys; s=sys.argv[1]; n=int(s) if s.isdecimal() else -1; 101 <= n <= 10000 or sys.exit(2); print(n)' "${TARGET_HEIGHT}")" || { echo "--target-height must be an integer in [101, 10000]" >&2; exit 2; }
# shellcheck source=scripts/devnet-process-common.sh disable=SC1091
source "${HELPER}"
rubin_process_init go-binary-soak
NODE_BIN="${RUBIN_PROCESS_ARTIFACT_ROOT}/rubin-node-go"
RUST_NODE_BIN="${RUBIN_PROCESS_ARTIFACT_ROOT}/rubin-node-rust"
TXGEN_BIN="${RUBIN_PROCESS_ARTIFACT_ROOT}/rubin-txgen"
KEYGEN_GO="${RUBIN_PROCESS_ARTIFACT_ROOT}/keygen.go"
KEYGEN_JSON="${RUBIN_PROCESS_ARTIFACT_ROOT}/keygen.json"
TCP_PROXY_PY="${RUBIN_PROCESS_ARTIFACT_ROOT}/tcp_proxy.py"
REPORT_JSON="${RUBIN_PROCESS_ARTIFACT_ROOT}/go-binary-soak-report.json"
PARTITION_REPORT_JSON="${RUBIN_PROCESS_ARTIFACT_ROOT}/mixed-client-partition-heal-report.json"
PARTITION_REORG_REPORT_JSON="${RUBIN_PROCESS_ARTIFACT_ROOT}/mixed-client-partition-heal-reorg-report.json"
PARTITION_REORG_BLOCK_CHECK_GO="${RUBIN_PROCESS_ARTIFACT_ROOT}/partition-reorg-block-check.go"
BASE_HEIGHT=$((TARGET_HEIGHT - 1))
BASE_MINE_BLOCKS=$((BASE_HEIGHT + 1))
A_DIR="${RUBIN_PROCESS_ARTIFACT_ROOT}/node-a"
B_DIR="${RUBIN_PROCESS_ARTIFACT_ROOT}/node-b"
C_DIR="${RUBIN_PROCESS_ARTIFACT_ROOT}/node-c"
A_LOG="node-a.log" B_LOG="node-b.log" C_LOG="node-c.log"
B_PROXY_LOG="node-b-proxy.log" C_PROXY_LOG="node-c-proxy.log"
B_RESTART_LOG="node-b-restart.log"
MINE_LOG="${RUBIN_PROCESS_ARTIFACT_ROOT}/mine-base.log"
RUBIN_PROCESS_LOGS+=("${MINE_LOG}")
PRE_RESTART_B_HEIGHT="" PRE_RESTART_B_TIP=""
PRE_RESTART_B_RPC_ADDR="" PRE_RESTART_B_P2P_ADDR=""
PRE_RESTART_B_PID=""
POST_RESTART_B_RPC_ADDR="" POST_RESTART_B_P2P_ADDR=""
POST_RESTART_B_PID=""
POST_RESTART_CATCHUP_HEIGHT=""
POST_RESTART_CATCHUP_TIP=""
POST_RESTART_CATCHUP_PEERS="0"
POST_RESTART_MINE_HEIGHT=""
POST_RESTART_MINE_HASH=""
POST_RESTART_MINE_TX_COUNT="0"
POST_RESTART_ACCEPTED_PEER=""
INCLUSION_PROOF_NODE="node-a"
B_PROXY_TARGET="${RUBIN_PROCESS_ARTIFACT_ROOT}/node-b-proxy-target"
C_PROXY_TARGET="${RUBIN_PROCESS_ARTIFACT_ROOT}/node-c-proxy-target"
rpc_json() {
  local method="$1" addr="$2" path="$3" body="${4:-}"
  python3 - "${method}" "${addr}" "${path}" "${body}" <<'PY'
import socket, sys, urllib.error, urllib.request
method, addr, path, body = sys.argv[1:5]
data = body.encode() if body else None
req = urllib.request.Request(f"http://{addr}{path}", data=data, method=method)
if body:
    req.add_header("Content-Type", "application/json")
try:
    with urllib.request.urlopen(req, timeout=5) as resp:
        print(resp.read().decode("utf-8"), end="")
except urllib.error.HTTPError as exc:
    print(exc.read().decode("utf-8"), end=""); sys.exit(22)
except (urllib.error.URLError, TimeoutError, socket.timeout) as exc:
    print(f"request failed: {getattr(exc, 'reason', exc)}", end=""); sys.exit(1)
PY
}
tip_tsv() {
  rpc_json GET "$1" /get_tip | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["height"], d["tip_hash"], sep="\t")'
}
metric_value() {
  rpc_json GET "$1" /metrics | awk -v name="$2" '$1 == name {print int($2); found=1} END {exit !found}'
}
wait_height() {
  local addr="$1" want="$2" timeout="$3" height hash
  local deadline=$((SECONDS + timeout))
  while ((SECONDS < deadline)); do
    if IFS=$'\t' read -r height hash < <(tip_tsv "${addr}" 2>/dev/null) && [[ "${height}" == "${want}" && -n "${hash}" ]]; then
      return 0
    fi
    sleep 1
  done
  echo "timeout waiting for ${addr} height=${want}" >&2
  return 1
}
wait_peers() {
  local addr="$1" want="$2" timeout="$3" value
  local deadline=$((SECONDS + timeout))
  while ((SECONDS < deadline)); do
    if value="$(metric_value "${addr}" rubin_node_peer_count 2>/dev/null)" && [[ "${value}" =~ ^[0-9]+$ && "${value}" -ge "${want}" ]]; then
      printf '%s\n' "${value}"
      return 0
    fi
    sleep 1
  done
  echo "timeout waiting for ${addr} peer_count>=${want}" >&2
  return 1
}
block_matches_hash_canonical() {
  local block_json="$1" expected_hash="$2"
  printf '%s' "${block_json}" | python3 -c 'import json,sys; d=json.load(sys.stdin); expected=sys.argv[1].lower(); actual=(d.get("hash") or d.get("block_hash") or "").lower(); canonical=d.get("canonical"); (actual == expected and canonical is True) or sys.exit("expected_hash=%s actual_hash=%s actual_canonical=%r" % (expected, actual or "<missing>", canonical))' "${expected_hash}"
}
describe_block_json() { local block_json="$1"; printf '%s' "${block_json}" | python3 -c 'import json,sys; d=json.load(sys.stdin); actual=d.get("hash") or d.get("block_hash") or "<missing>"; print("reported_hash=%s reported_canonical=%r" % (actual, d.get("canonical")))'; }
stop_registered_pid() {
  local managed_pid="${1:-}" rc=0 kept=() pid
  [[ -n "${managed_pid}" ]] || return 1
  rubin_process_stop_pid "${managed_pid}" || rc=$?
  for pid in "${RUBIN_PROCESS_PIDS[@]}"; do
    [[ "${pid}" == "${managed_pid}" ]] || kept+=("${pid}")
  done
  if ((${#kept[@]})); then
    RUBIN_PROCESS_PIDS=("${kept[@]}")
  else
    RUBIN_PROCESS_PIDS=()
  fi
  for pid in "${RUBIN_PROCESS_PIDS[@]}"; do
    [[ "${pid}" != "${managed_pid}" ]] || {
      echo "stale managed pid remained registered after stop: ${managed_pid}" >&2
      return 1
    }
  done
  return "${rc}"
}
write_tcp_proxy() {
  cat >"${TCP_PROXY_PY}" <<'PY'
import socket, sys, threading
target_file = sys.argv[1]; listener = socket.socket(); listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); listener.bind(("127.0.0.1", 0)); listener.listen()
print(f"proxy: listening={listener.getsockname()[0]}:{listener.getsockname()[1]}", flush=True)
def pump(src, dst):
    try:
        data = src.recv(65536)
        while data: dst.sendall(data); data = src.recv(65536)
    except OSError:
        pass
    for sock in (src, dst):
        try: sock.close()
        except OSError: pass
while True:
    client, _ = listener.accept()
    try:
        host, port = open(target_file, encoding="utf-8").read().strip().rsplit(":", 1)
        if host != "127.0.0.1": raise ValueError("proxy target must be loopback")
        upstream = socket.create_connection((host, int(port)), timeout=5)
        upstream.settimeout(None)
    except Exception:
        client.close(); continue
    for src, dst in ((client, upstream), (upstream, client)):
        threading.Thread(target=pump, args=(src, dst), daemon=True).start()
PY
}
write_partition_tcp_proxy() {
  cat >"${TCP_PROXY_PY}" <<'PY'
import socket, sys, threading, time
target_file = sys.argv[1]
listener = socket.socket()
listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listener.bind(("127.0.0.1", 0))
listener.listen()
print(f"proxy: listening={listener.getsockname()[0]}:{listener.getsockname()[1]}", flush=True)
active = set()
lock = threading.Lock()
last_target = None
def close_sock(sock):
    try: sock.shutdown(socket.SHUT_RDWR)
    except OSError: pass
    try: sock.close()
    except OSError: pass
def close_active():
    with lock:
        socks = list(active)
        active.clear()
    for sock in socks:
        close_sock(sock)
def read_target():
    try:
        return open(target_file, encoding="utf-8").read().strip()
    except OSError:
        return "drop"
def watch_target():
    global last_target
    while True:
        current = read_target()
        if last_target is None:
            last_target = current
        elif current != last_target:
            last_target = current
            close_active()
        time.sleep(0.2)
def pump(src, dst):
    try:
        src.settimeout(0.5)
        while True:
            try:
                data = src.recv(65536)
            except socket.timeout:
                continue
            if not data:
                break
            dst.sendall(data)
    except OSError:
        pass
    for sock in (src, dst):
        close_sock(sock)
        with lock:
            active.discard(sock)
threading.Thread(target=watch_target, daemon=True).start()
while True:
    client, _ = listener.accept()
    try:
        target = read_target()
        if target == "drop": raise ValueError("proxy target is drop")
        host, port = target.rsplit(":", 1)
        if host != "127.0.0.1": raise ValueError("proxy target must be loopback")
        upstream = socket.create_connection((host, int(port)), timeout=5)
        upstream.settimeout(None)
    except Exception:
        client.close(); continue
    with lock:
        active.add(client)
        active.add(upstream)
    for src, dst in ((client, upstream), (upstream, client)):
        threading.Thread(target=pump, args=(src, dst), daemon=True).start()
PY
}
PROXY_PID=""
PROXY_ADDR=""
start_proxy() {
  local log_file="$1" target_file="$2"
  PROXY_PID="" PROXY_ADDR=""
  rubin_process_start "${log_file}" python3 -u "${TCP_PROXY_PY}" "${target_file}"
  PROXY_PID="${RUBIN_PROCESS_LAST_PID}"
  rubin_process_wait_for_log "${log_file}" "proxy: listening=" 30 "${PROXY_PID}" || { stop_registered_pid "${PROXY_PID}" || true; PROXY_PID=""; return 1; }
  PROXY_ADDR="$(sed -n 's/.*proxy: listening=//p' "${RUBIN_PROCESS_ARTIFACT_ROOT}/${log_file}" | tail -n 1 | tr -d '[:space:]')"
  [[ -n "${PROXY_ADDR}" ]] || { echo "missing proxy listening banner in ${log_file}" >&2; stop_registered_pid "${PROXY_PID}" || true; PROXY_PID=""; return 1; }
  [[ "${PROXY_ADDR}" == 127.0.0.1:* ]] || { echo "proxy must listen on 127.0.0.1, got ${PROXY_ADDR}" >&2; stop_registered_pid "${PROXY_PID}" || true; PROXY_PID=""; return 1; }
}
STARTED_PID=""
STARTED_RPC=""
STARTED_P2P=""
p2p_addr_for_pid() {
  local pid="$1" rpc_addr="$2" timeout="$3"
  command -v lsof >/dev/null 2>&1 || { echo "lsof is required to resolve p2p :0 bind address" >&2; return 1; }
  python3 - "${pid}" "${rpc_addr}" "${timeout}" <<'PY'
import re, subprocess, sys, time
pid, rpc_addr, timeout = sys.argv[1], sys.argv[2], int(sys.argv[3]); deadline = time.time() + timeout
while time.time() < deadline:
    proc = subprocess.run(["lsof", "-nP", "-a", "-p", pid, "-iTCP", "-sTCP:LISTEN", "-Fn"], text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    addrs = sorted({line[1:].strip() for line in proc.stdout.splitlines() if line.startswith("n") and line[1:].strip() != rpc_addr and re.fullmatch(r"127\.0\.0\.1:[0-9]+", line[1:].strip())})
    if len(addrs) == 1:
        print(addrs[0]); sys.exit(0)
    if len(addrs) > 1:
        sys.exit(f"ambiguous p2p listen addresses for pid={pid}: {addrs}")
    time.sleep(1)
sys.exit(f"timeout resolving p2p listen address for pid={pid}")
PY
}
partition_no_data() {
  local reason="${1:-unknown}"
  echo "NO_DATA: reason=${reason}; report=${PARTITION_REPORT_JSON}" >&2
  return 1
}
build_rust_node_for_partition() {
  local host_triple cargo_target_dir cargo_log cargo_bin rc
  echo "Building Rust rubin-node binary"
  host_triple="$(RUBIN_OPENSSL_SKIP_FIPS_GUARD=1 "${DEV_ENV}" -- rustc -vV | awk '/^host:/ {print $2}')" || return 1
  [[ -n "${host_triple}" ]] || { echo "could not derive host target triple from rustc -vV output" >&2; return 1; }
  cargo_target_dir="${RUBIN_PROCESS_ARTIFACT_ROOT}/cargo-target"
  cargo_log="${RUBIN_PROCESS_ARTIFACT_ROOT}/partition-cargo-build.jsonl"
  RUBIN_OPENSSL_SKIP_FIPS_GUARD=1 "${DEV_ENV}" -- cargo build --manifest-path "${RUST_MODULE_ROOT}/Cargo.toml" --release --locked -p rubin-node --target "${host_triple}" --target-dir "${cargo_target_dir}" --message-format=json-render-diagnostics >"${cargo_log}" || return 1
  cargo_bin="$(python3 - "${cargo_log}" <<'PY'
import json, sys
selected = None
with open(sys.argv[1], encoding="utf-8") as f:
    for raw in f:
        line = raw.strip()
        if not line:
            continue
        if not line.startswith("{"):
            sys.exit(2)
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            sys.exit(2)
        if ev.get("reason") != "compiler-artifact":
            continue
        target = ev.get("target") or {}
        if target.get("name") == "rubin-node" and "bin" in (target.get("kind") or []) and ev.get("executable"):
            selected = ev["executable"]
if selected is None:
    sys.exit(3)
print(selected)
PY
  )" || { rc=$?; [[ ${rc} -eq 2 ]] && echo "cargo build log parser failed: malformed JSON stream ${cargo_log}" >&2 || echo "cargo build log parser failed: rubin-node executable artifact missing in ${cargo_log}" >&2; return 1; }
  [[ -x "${cargo_bin}" ]] || { echo "cargo-reported executable is not executable: ${cargo_bin}" >&2; return 1; }
  cp -- "${cargo_bin}" "${RUST_NODE_BIN}"
  [[ -x "${RUST_NODE_BIN}" ]] || { echo "Rust rubin-node binary is missing after build" >&2; return 1; }
}
pid_listens_on() {
  local pid="$1" endpoint="$2" out status=0
  out="$(lsof -nP -a -p "${pid}" -iTCP -sTCP:LISTEN -Fn 2>/dev/null)" || status=$?
  (( status == 0 )) || return 1
  grep -F -x -q -- "n${endpoint}" <<<"${out}"
}
start_partition_go_node() {
  local log_file="partition-node-go.log" args
  GO_PARTITION_PID="" GO_PARTITION_RPC="" GO_PARTITION_P2P="" GO_PARTITION_STARTED=""
  args=(--network devnet --datadir "${RUBIN_PROCESS_ARTIFACT_ROOT}/partition-node-go" --bind 127.0.0.1:0 --rpc-bind 127.0.0.1:0)
  [[ -z "${PARTITION_GO_MINE_ADDRESS_HEX:-}" ]] || args+=(--mine-address "${PARTITION_GO_MINE_ADDRESS_HEX}")
  rubin_process_start "${log_file}" "${NODE_BIN}" "${args[@]}" || return 1
  GO_PARTITION_PID="${RUBIN_PROCESS_LAST_PID}"
  rubin_process_wait_for_log "${log_file}" "rpc: listening=" 60 "${GO_PARTITION_PID}" || return 1
  GO_PARTITION_RPC="$(rubin_process_extract_rpc_addr "${log_file}")" || return 1
  GO_PARTITION_P2P="$(p2p_addr_for_pid "${GO_PARTITION_PID}" "${GO_PARTITION_RPC}" 30)" || return 1
  rubin_process_wait_for_rpc_ready "${GO_PARTITION_RPC}" 30 || return 1
  GO_PARTITION_STARTED="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
start_partition_rust_node() {
  local log_file="partition-node-rust.log" peer_addr="$1" args
  RUST_PARTITION_PID="" RUST_PARTITION_RPC="" RUST_PARTITION_P2P="" RUST_PARTITION_STARTED=""
  args=(--network devnet --datadir "${RUBIN_PROCESS_ARTIFACT_ROOT}/partition-node-rust" --bind 127.0.0.1:0 --rpc-bind 127.0.0.1:0 --peer "${peer_addr}")
  [[ -z "${PARTITION_RUST_MINE_ADDRESS_HEX:-}" ]] || args+=(--mine-address "${PARTITION_RUST_MINE_ADDRESS_HEX}")
  rubin_process_start "${log_file}" "${RUST_NODE_BIN}" "${args[@]}" || return 1
  RUST_PARTITION_PID="${RUBIN_PROCESS_LAST_PID}"
  rubin_process_wait_for_log "${log_file}" "rpc: listening=" 60 "${RUST_PARTITION_PID}" || return 1
  RUST_PARTITION_RPC="$(rubin_process_extract_rpc_addr "${log_file}")" || return 1
  RUST_PARTITION_P2P="$(p2p_addr_for_pid "${RUST_PARTITION_PID}" "${RUST_PARTITION_RPC}" 30)" || return 1
  rubin_process_wait_for_rpc_ready "${RUST_PARTITION_RPC}" 30 || return 1
  RUST_PARTITION_STARTED="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
verify_partition_process_identity() {
  local label="$1" pid="$2" rpc_addr="$3" p2p_addr="$4" expected_executable="$5" expected_realpath
  rubin_process_is_alive "${pid}" || { echo "${label} pid is not alive: ${pid}" >&2; return 1; }
  expected_realpath="$(_rubin_process_executable_realpath "${expected_executable}")" || { echo "${label} expected executable is not verifiable: ${expected_executable}" >&2; return 1; }
  _rubin_process_started_exec_matches "${pid}" "${expected_realpath}" || { echo "${label} executable identity mismatch: ${pid}" >&2; return 1; }
  pid_listens_on "${pid}" "${rpc_addr}" || { echo "${label} rpc endpoint is not pid-owned: ${rpc_addr}" >&2; return 1; }
  pid_listens_on "${pid}" "${p2p_addr}" || { echo "${label} p2p endpoint is not pid-owned: ${p2p_addr}" >&2; return 1; }
}
capture_peer_snapshot() {
  local impl="$1" rpc_addr="$2" phase="$3" out="$4" tmp raw rc=0
  tmp="${out}.tmp"
  raw="${out}.raw"
  PEER_SNAPSHOT_REASON=""
  rm -f -- "${out}" "${tmp}" "${raw}"
  rpc_json GET "${rpc_addr}" /peers >"${raw}" || rc=$?
  if (( rc != 0 )); then
    [[ "${rc}" == "22" ]] && PEER_SNAPSHOT_REASON="http_error" || PEER_SNAPSHOT_REASON="rpc_failed"
    rm -f -- "${raw}" "${tmp}"
    return 2
  fi
  python3 - "${impl}" "${rpc_addr}" "${phase}" "${raw}" "${tmp}" <<'PY' || rc=$?
import json, sys, time
impl, rpc_addr, phase, raw_path, out_path = sys.argv[1:6]

def fail(reason, detail):
    print(f"{reason}: {detail}", file=sys.stderr)
    codes = {
        "json_malformed": 2,
        "shape_mismatch": 3,
        "write_failed": 4,
    }
    sys.exit(codes.get(reason, 5))

try:
    with open(raw_path, encoding="utf-8") as f:
        data = json.load(f)
except (OSError, UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
    fail("json_malformed", exc)

if not isinstance(data, dict):
    fail("shape_mismatch", "peer response root is not an object")
allowed_response_keys = {"count", "peers"}
if set(data) != allowed_response_keys:
    fail("shape_mismatch", f"peer response keys mismatch: {sorted(data)}")
peers = data.get("peers")
count = data.get("count")
if not isinstance(count, int) or isinstance(count, bool) or not isinstance(peers, list) or count != len(peers):
    fail("shape_mismatch", "peer response count/peers shape mismatch")
allowed_peer_keys = {
    "addr",
    "ban_score",
    "best_height",
    "da_mempool_size",
    "handshake_complete",
    "last_error",
    "protocol_version",
    "pruned_below_height",
    "tx_relay",
}
for peer in peers:
    if not isinstance(peer, dict):
        fail("shape_mismatch", "peer response entry is not an object")
    if set(peer) != allowed_peer_keys:
        fail("shape_mismatch", f"peer entry keys mismatch: {sorted(peer)}")
    if not isinstance(peer["addr"], str) or not isinstance(peer["last_error"], str):
        fail("shape_mismatch", "peer response string field mismatch")
    for key in ("ban_score", "best_height", "da_mempool_size", "protocol_version", "pruned_below_height"):
        value = peer[key]
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            fail("shape_mismatch", f"peer response integer field mismatch: {key}")
    if not isinstance(peer["handshake_complete"], bool) or not isinstance(peer["tx_relay"], bool):
        fail("shape_mismatch", "peer response boolean field mismatch")
out = {
    "captured_at_unix_ns": time.time_ns(),
    "implementation": impl,
    "phase": phase,
    "request_path": "/peers",
    "rpc_endpoint": rpc_addr,
    "response": data,
}
try:
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2, sort_keys=True)
        f.write("\n")
except OSError as exc:
    fail("write_failed", exc)
PY
  if (( rc != 0 )); then
    case "${rc}" in
      2) PEER_SNAPSHOT_REASON="json_malformed" ;;
      3) PEER_SNAPSHOT_REASON="shape_mismatch" ;;
      4) PEER_SNAPSHOT_REASON="write_failed" ;;
      *) PEER_SNAPSHOT_REASON="parser_failed" ;;
    esac
    rm -f -- "${raw}" "${tmp}" "${out}"
    return 2
  fi
  mv -- "${tmp}" "${out}" || { PEER_SNAPSHOT_REASON="publish_failed"; rm -f -- "${raw}" "${tmp}" "${out}"; return 2; }
  rm -f -- "${raw}"
}
peer_snapshot_has_complete() {
  local snapshot="$1" expected_addr="$2"
  python3 - "${snapshot}" "${expected_addr}" <<'PY'
import json, sys
try:
    with open(sys.argv[1], encoding="utf-8") as f:
        data = json.load(f)
except (OSError, UnicodeDecodeError, json.JSONDecodeError, RecursionError):
    sys.exit(2)
expected = sys.argv[2]
resp = data.get("response") if isinstance(data, dict) else None
peers = resp.get("peers") if isinstance(resp, dict) else None
if not isinstance(peers, list):
    sys.exit(2)
sys.exit(0 if any(isinstance(p, dict) and p.get("addr") == expected and p.get("handshake_complete") is True for p in peers) else 1)
PY
}
peer_snapshot_no_data_reason() {
  local label="$1" reason="${PEER_SNAPSHOT_REASON:-peer_snapshot_failed}"
  label="${label//-/_}"
  printf '%s_peer_snapshot_%s\n' "${label}" "${reason}"
}
wait_peer_present() {
  local label="$1" impl="$2" rpc_addr="$3" expected_addr="$4" out="$5" timeout="$6" deadline rc
  deadline=$((SECONDS + timeout))
  while (( SECONDS < deadline )); do
    if capture_peer_snapshot "${impl}" "${rpc_addr}" "${label}" "${out}"; then
      rc=0
      peer_snapshot_has_complete "${out}" "${expected_addr}" || rc=$?
      (( rc == 0 )) && return 0
      (( rc == 2 )) && { PEER_SNAPSHOT_REASON="sidecar_malformed"; echo "invalid ${label} peer snapshot: ${out}" >&2; return 2; }
    else
      rc=$?
      (( rc == 2 )) || PEER_SNAPSHOT_REASON="snapshot_failed"
      echo "${label} peer snapshot failed: reason=${PEER_SNAPSHOT_REASON:-peer_snapshot_failed}" >&2
      return 2
    fi
    sleep 1
  done
  echo "timeout waiting for ${label} peer ${expected_addr}" >&2
  return 1
}
wait_peer_absent() {
  local label="$1" impl="$2" rpc_addr="$3" expected_addr="$4" out="$5" timeout="$6" deadline rc
  deadline=$((SECONDS + timeout))
  while (( SECONDS < deadline )); do
    if capture_peer_snapshot "${impl}" "${rpc_addr}" "${label}" "${out}"; then
      rc=0
      peer_snapshot_has_complete "${out}" "${expected_addr}" || rc=$?
      [[ "${rc}" == "1" ]] && return 0
      (( rc == 0 )) || { PEER_SNAPSHOT_REASON="sidecar_malformed"; echo "invalid ${label} peer snapshot: ${out}" >&2; return 2; }
    else
      rc=$?
      (( rc == 2 )) || PEER_SNAPSHOT_REASON="snapshot_failed"
      echo "${label} peer snapshot failed: reason=${PEER_SNAPSHOT_REASON:-peer_snapshot_failed}" >&2
      return 2
    fi
    sleep 1
  done
  echo "timeout waiting for ${label} peer ${expected_addr} to disappear" >&2
  return 1
}
require_peer_present() {
  local missing_reason="$1" label="$2" rc=0
  shift 2
  wait_peer_present "${label}" "$@" || rc=$?
  (( rc == 0 )) && return 0
  (( rc == 2 )) && partition_no_data "$(peer_snapshot_no_data_reason "${label}")"
  partition_no_data "${missing_reason}"
}
require_peer_absent() {
  local unchanged_reason="$1" label="$2" rc=0
  shift 2
  wait_peer_absent "${label}" "$@" || rc=$?
  (( rc == 0 )) && return 0
  (( rc == 2 )) && partition_no_data "$(peer_snapshot_no_data_reason "${label}")"
  partition_no_data "${unchanged_reason}"
}
established_local_to_remote() {
  local pid="$1" remote="$2" raw err status=0
  command -v lsof >/dev/null 2>&1 || return 3
  err="${RUBIN_PROCESS_ARTIFACT_ROOT}/lsof-established-${pid}.err"
  rm -f -- "${err}"
  raw="$(lsof -nP -a -p "${pid}" -iTCP -sTCP:ESTABLISHED -Fn 2>"${err}")" || status=$?
  if (( status != 0 )); then
    [[ -z "${raw}" && ! -s "${err}" ]] || { rm -f -- "${err}"; return 3; }
    rm -f -- "${err}"
    return 1
  fi
  rm -f -- "${err}"
  LSOF_RAW="${raw}" python3 - "${remote}" <<'PY'
import os, re, sys
remote = sys.argv[1]
locals_ = []
for raw in os.environ.get("LSOF_RAW", "").splitlines():
    raw = raw.strip()
    if not raw.startswith("n"):
        continue
    value = raw[1:]
    m = re.fullmatch(r"(127[.]0[.]0[.]1:[0-9]+)->(127[.]0[.]0[.]1:[0-9]+)", value)
    if m and m.group(2) == remote:
        locals_.append(m.group(1))
locals_ = sorted(set(locals_))
if len(locals_) == 1:
    print(locals_[0])
    sys.exit(0)
if len(locals_) == 0:
    sys.exit(1)
sys.exit(2)
PY
}
wait_established_local_to_remote() {
  local label="$1" pid="$2" remote="$3" timeout="$4" deadline out rc
  deadline=$((SECONDS + timeout))
  while (( SECONDS < deadline )); do
    rc=0
    out="$(established_local_to_remote "${pid}" "${remote}")" || rc=$?
    (( rc == 0 )) && { printf '%s\n' "${out}"; return 0; }
    (( rc == 2 )) && { echo "ambiguous ${label} established link to ${remote}" >&2; return 1; }
    (( rc == 3 )) && { echo "lsof failed while checking ${label} established link to ${remote}" >&2; return 1; }
    sleep 1
  done
  echo "timeout waiting for ${label} established link to ${remote}" >&2
  return 1
}
wait_no_established_to_remote() {
  local label="$1" pid="$2" remote="$3" timeout="$4" deadline rc
  deadline=$((SECONDS + timeout))
  while (( SECONDS < deadline )); do
    rc=0
    established_local_to_remote "${pid}" "${remote}" >/dev/null || rc=$?
    if [[ "${rc:-1}" == "1" ]]; then
      return 0
    fi
    (( rc == 2 )) && { echo "ambiguous ${label} established link to ${remote}" >&2; return 1; }
    (( rc == 3 )) && { echo "lsof failed while checking ${label} established link to ${remote}" >&2; return 1; }
    rc=0
    sleep 1
  done
  echo "timeout waiting for ${label} established link to ${remote} to close" >&2
  return 1
}
write_partition_report() {
  local tmp="${PARTITION_REPORT_JSON}.tmp"
  export PARTITION_REPORT_JSON PARTITION_REPORT_TMP GO_PARTITION_PID GO_PARTITION_RPC GO_PARTITION_P2P GO_PARTITION_STARTED RUST_PARTITION_PID RUST_PARTITION_RPC RUST_PARTITION_P2P RUST_PARTITION_STARTED PROXY_PID PROXY_ADDR GO_PROXY_LOCAL_PRE GO_PROXY_LOCAL_HEAL PRE_RUST_PEERS PRE_GO_PEERS PARTITION_RUST_PEERS PARTITION_GO_PEERS HEAL_RUST_PEERS HEAL_GO_PEERS
  PARTITION_REPORT_TMP="${tmp}"
  rm -f -- "${tmp}"
  python3 - <<'PY' || { rm -f -- "${tmp}"; return 1; }
import json, os
e = os.environ
report = {
    "scenario": "mixed_client_partition_heal_peer_state",
    "verdict": "PASS",
    "nodes": [
        {"name": "node-go", "implementation": "go", "pid": int(e["GO_PARTITION_PID"]), "rpc_endpoint": e["GO_PARTITION_RPC"], "p2p_endpoint": e["GO_PARTITION_P2P"], "started_at": e["GO_PARTITION_STARTED"]},
        {"name": "node-rust", "implementation": "rust", "pid": int(e["RUST_PARTITION_PID"]), "rpc_endpoint": e["RUST_PARTITION_RPC"], "p2p_endpoint": e["RUST_PARTITION_P2P"], "started_at": e["RUST_PARTITION_STARTED"]},
    ],
    "control": {"mode": "active_drop_tcp_proxy_with_live_peer_state", "source": "node-rust", "target": "node-go", "proxy_pid": int(e["PROXY_PID"]), "proxy_addr": e["PROXY_ADDR"]},
    "proof": {
        "partition_changed_peer_state": True,
        "heal_restored_peer_state": True,
        "proxy_target_file_only_is_insufficient": True,
        "process_identity_rechecked_after_heal": True,
        "source_expected_peer_addr": e["PROXY_ADDR"],
        "target_pre_partition_peer_addr": e["GO_PROXY_LOCAL_PRE"],
        "target_heal_peer_addr": e["GO_PROXY_LOCAL_HEAL"],
    },
    "observations": {
        "pre_partition": {"rust_peer_snapshot": e["PRE_RUST_PEERS"], "go_peer_snapshot": e["PRE_GO_PEERS"]},
        "partition": {"rust_peer_snapshot": e["PARTITION_RUST_PEERS"], "go_peer_snapshot": e["PARTITION_GO_PEERS"]},
        "heal": {"rust_peer_snapshot": e["HEAL_RUST_PEERS"], "go_peer_snapshot": e["HEAL_GO_PEERS"]},
    },
    "non_goals": ["no reorg proof", "no schema/report validator change", "no Go/Rust runtime change"],
}
with open(e["PARTITION_REPORT_TMP"], "w", encoding="utf-8") as f:
    json.dump(report, f, indent=2, sort_keys=True)
    f.write("\n")
PY
  mv -- "${tmp}" "${PARTITION_REPORT_JSON}" || { rm -f -- "${tmp}"; return 1; }
}
partition_reorg_no_data() {
  local reason="${1:-unknown}"
  echo "NO_DATA: reason=${reason}; report=${PARTITION_REORG_REPORT_JSON}" >&2
  return 1
}
require_reorg_peer_present() {
  local missing_reason="$1" label="$2" rc=0
  shift 2
  wait_peer_present "${label}" "$@" || rc=$?
  (( rc == 0 )) && return 0
  (( rc == 2 )) && partition_reorg_no_data "$(peer_snapshot_no_data_reason "${label}")"
  partition_reorg_no_data "${missing_reason}"
}
require_reorg_peer_absent() {
  local unchanged_reason="$1" label="$2" rc=0
  shift 2
  wait_peer_absent "${label}" "$@" || rc=$?
  (( rc == 0 )) && return 0
  (( rc == 2 )) && partition_reorg_no_data "$(peer_snapshot_no_data_reason "${label}")"
  partition_reorg_no_data "${unchanged_reason}"
}
capture_reorg_rpc_sidecar() {
  local impl="$1" method="$2" rpc_addr="$3" path="$4" phase="$5" out="$6" body="${7:-}" tmp raw rc=0
  REORG_CAPTURE_REASON=""
  tmp="${out}.tmp"
  raw="${out}.raw"
  rm -f -- "${out}" "${tmp}" "${raw}"
  rpc_json "${method}" "${rpc_addr}" "${path}" "${body}" >"${raw}" || rc=$?
  if (( rc != 0 )); then
    [[ "${rc}" == "22" ]] && REORG_CAPTURE_REASON="${phase}_http_error" || REORG_CAPTURE_REASON="${phase}_rpc_failed"
    echo "${phase} ${method} ${path} failed via ${impl} rpc=${rpc_addr}: $(cat "${raw}" 2>/dev/null || true)" >&2
    rm -f -- "${raw}" "${tmp}" "${out}"
    return 2
  fi
  python3 - "${impl}" "${method}" "${rpc_addr}" "${path}" "${phase}" "${raw}" "${tmp}" <<'PY' || rc=$?
import json
import os
import sys
import time

impl, method, rpc_addr, path, phase, raw_path, out_path = sys.argv[1:8]

def fail(reason, detail):
    print(f"{reason}: {detail}", file=sys.stderr)
    codes = {
        "read_failed": 3,
        "size_mismatch": 4,
        "json_malformed": 5,
        "shape_mismatch": 6,
        "write_failed": 7,
    }
    sys.exit(codes.get(reason, 8))

try:
    size = os.path.getsize(raw_path)
except OSError as exc:
    fail("read_failed", exc)
if size <= 0 or size > 1048576:
    fail("size_mismatch", f"raw response size={size}")
try:
    with open(raw_path, encoding="utf-8") as f:
        data = json.load(f)
except (OSError, UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
    fail("json_malformed", exc)
if not isinstance(data, dict):
    fail("shape_mismatch", "response root is not an object")
sidecar = {
    "captured_at_unix_ns": time.time_ns(),
    "implementation": impl,
    "method": method,
    "phase": phase,
    "request_path": path,
    "response": data,
    "rpc_endpoint": rpc_addr,
}
try:
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(sidecar, f, indent=2, sort_keys=True)
        f.write("\n")
except OSError as exc:
    fail("write_failed", exc)
PY
  if (( rc != 0 )); then
    case "${rc}" in
      3) REORG_CAPTURE_REASON="${phase}_sidecar_read_failed" ;;
      4) REORG_CAPTURE_REASON="${phase}_sidecar_size_mismatch" ;;
      5) REORG_CAPTURE_REASON="${phase}_sidecar_json_malformed" ;;
      6) REORG_CAPTURE_REASON="${phase}_sidecar_shape_mismatch" ;;
      7) REORG_CAPTURE_REASON="${phase}_sidecar_write_failed" ;;
      *) REORG_CAPTURE_REASON="${phase}_sidecar_parser_failed" ;;
    esac
    rm -f -- "${raw}" "${tmp}" "${out}"
    return 2
  fi
  mv -- "${tmp}" "${out}" || { REORG_CAPTURE_REASON="${phase}_sidecar_publish_failed"; rm -f -- "${raw}" "${tmp}" "${out}"; return 2; }
  rm -f -- "${raw}"
}
reorg_mine_tsv() {
  python3 - "$1" <<'PY'
import json
import re
import sys

try:
    with open(sys.argv[1], encoding="utf-8") as f:
        data = json.load(f)
except (OSError, UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
    sys.exit(f"mine sidecar malformed: {exc}")
if not isinstance(data, dict) or set(data) != {"captured_at_unix_ns", "implementation", "method", "phase", "request_path", "response", "rpc_endpoint"}:
    sys.exit("mine sidecar shape mismatch")
if data.get("method") != "POST" or data.get("request_path") != "/mine_next":
    sys.exit("mine sidecar route mismatch")
resp = data.get("response")
if not isinstance(resp, dict) or set(resp) != {"block_hash", "height", "mined", "nonce", "timestamp", "tx_count"}:
    sys.exit("mine response shape mismatch")
height, block_hash, tx_count = resp.get("height"), resp.get("block_hash"), resp.get("tx_count")
if resp.get("mined") is not True:
    sys.exit("mine response did not mine")
if not isinstance(height, int) or isinstance(height, bool) or height < 1:
    sys.exit("mine height mismatch")
if not isinstance(block_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", block_hash):
    sys.exit("mine block hash mismatch")
if not isinstance(tx_count, int) or isinstance(tx_count, bool) or tx_count < 1:
    sys.exit("mine tx_count mismatch")
print(height, block_hash, tx_count, sep="\t")
PY
}
reorg_tip_tsv() {
  python3 - "$1" <<'PY'
import json
import re
import sys

try:
    with open(sys.argv[1], encoding="utf-8") as f:
        data = json.load(f)
except (OSError, UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
    sys.exit(f"tip sidecar malformed: {exc}")
if not isinstance(data, dict) or set(data) != {"captured_at_unix_ns", "implementation", "method", "phase", "request_path", "response", "rpc_endpoint"}:
    sys.exit("tip sidecar shape mismatch")
if data.get("method") != "GET" or data.get("request_path") != "/get_tip":
    sys.exit("tip sidecar route mismatch")
resp = data.get("response")
if not isinstance(resp, dict) or set(resp) != {"best_known_height", "has_tip", "height", "in_ibd", "tip_hash"}:
    sys.exit("tip response shape mismatch")
height, tip_hash = resp.get("height"), resp.get("tip_hash")
if resp.get("has_tip") is not True:
    sys.exit("tip response has no tip")
if not isinstance(height, int) or isinstance(height, bool) or height < 1:
    sys.exit("tip height mismatch")
if not isinstance(tip_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", tip_hash):
    sys.exit("tip hash mismatch")
print(height, tip_hash, sep="\t")
PY
}
write_partition_reorg_block_check_go() {
  cat >"${PARTITION_REORG_BLOCK_CHECK_GO}" <<'EOF'
package main
import (
  "encoding/hex"
  "flag"
  "fmt"
  "os"
  "strings"
  "github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)
func die(format string, args ...any) {
  fmt.Fprintf(os.Stderr, format+"\n", args...)
  os.Exit(1)
}
func main() {
  blockHexPath := flag.String("block-hex-file", "", "file containing block_hex")
  wantHash := flag.String("hash", "", "expected block hash")
  flag.Parse()
  if *blockHexPath == "" || *wantHash == "" {
    die("missing required flags")
  }
  rawHex, err := os.ReadFile(*blockHexPath)
  if err != nil {
    die("read block_hex: %v", err)
  }
  blockHex := strings.TrimSpace(string(rawHex))
  blockBytes, err := hex.DecodeString(blockHex)
  if err != nil {
    die("decode block_hex: %v", err)
  }
  pb, err := consensus.ParseBlockBytes(blockBytes)
  if err != nil {
    die("parse block_hex failed: %v", err)
  }
  got, err := consensus.BlockHash(pb.HeaderBytes)
  if err != nil {
    die("hash block header failed: %v", err)
  }
  gotHex := hex.EncodeToString(got[:])
  if gotHex != *wantHash {
    die("parsed block hash mismatch: got=%s want=%s", gotHex, *wantHash)
  }
}
EOF
}
reorg_block_failure_reason() {
  local phase="$1" output="$2"
  case "${output}" in
    *"sidecar malformed:"*) printf '%s\n' "${phase}_block_sidecar_malformed" ;;
    *"sidecar shape mismatch"*) printf '%s\n' "${phase}_block_sidecar_shape_mismatch" ;;
    *"sidecar route mismatch"*) printf '%s\n' "${phase}_block_sidecar_route_mismatch" ;;
    *"block response shape mismatch"*) printf '%s\n' "${phase}_block_response_shape_mismatch" ;;
    *"block response height/hash/canonical mismatch"*) printf '%s\n' "${phase}_block_response_mismatch" ;;
    *"block_hex shape mismatch"*) printf '%s\n' "${phase}_block_hex_shape_mismatch" ;;
    *"write block_hex failed"*) printf '%s\n' "${phase}_block_hex_write_failed" ;;
    *"read block_hex:"*) printf '%s\n' "${phase}_block_hex_read_failed" ;;
    *"decode block_hex:"*) printf '%s\n' "${phase}_block_hex_decode_failed" ;;
    *"parse block_hex failed:"*) printf '%s\n' "${phase}_block_hex_parse_failed" ;;
    *"hash block header failed:"*) printf '%s\n' "${phase}_block_hash_failed" ;;
    *"parsed block hash mismatch:"*) printf '%s\n' "${phase}_block_hash_mismatch" ;;
    *) printf '%s\n' "${phase}_block_check_failed" ;;
  esac
}
reorg_block_matches() {
  local phase="$1" path="$2" height="$3" block_hash="$4" block_hex_file output
  block_hex_file="${path}.block_hex"
  rm -f -- "${block_hex_file}"
  output="$(python3 - "${path}" "${height}" "${block_hash}" "${block_hex_file}" <<'PY'
import json
import re
import sys

path, height_raw, want_hash, block_hex_path = sys.argv[1:5]
try:
    want_height = int(height_raw)
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
except (OSError, ValueError, UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
    sys.exit(f"block sidecar malformed: {exc}")
if not isinstance(data, dict) or set(data) != {"captured_at_unix_ns", "implementation", "method", "phase", "request_path", "response", "rpc_endpoint"}:
    sys.exit("block sidecar shape mismatch")
if data.get("method") != "GET" or data.get("request_path") != f"/get_block?height={want_height}":
    sys.exit("block sidecar route mismatch")
resp = data.get("response")
if not isinstance(resp, dict) or set(resp) != {"block_hex", "canonical", "hash", "height"}:
    sys.exit("block response shape mismatch")
block_hex = resp.get("block_hex")
if resp.get("height") != want_height or resp.get("canonical") is not True or resp.get("hash") != want_hash:
    sys.exit("block response height/hash/canonical mismatch")
if not isinstance(block_hex, str) or not block_hex or len(block_hex) % 2 != 0 or not re.fullmatch(r"[0-9a-f]+", block_hex):
    sys.exit("block_hex shape mismatch")
try:
    with open(block_hex_path, "w", encoding="utf-8") as f:
        f.write(block_hex)
        f.write("\n")
except OSError as exc:
    sys.exit(f"write block_hex failed: {exc}")
PY
  )" || {
    REORG_STEP_REASON="$(reorg_block_failure_reason "${phase}" "${output}")"
    rm -f -- "${block_hex_file}"
    printf '%s\n' "${output}" >&2
    return 1
  }
  [[ -s "${PARTITION_REORG_BLOCK_CHECK_GO}" ]] || write_partition_reorg_block_check_go
  output="$(RUBIN_OPENSSL_SKIP_FIPS_GUARD=1 "${DEV_ENV}" -- go -C "${GO_MODULE_ROOT}" run "${PARTITION_REORG_BLOCK_CHECK_GO}" --block-hex-file "${block_hex_file}" --hash "${block_hash}" 2>&1)" || {
    REORG_STEP_REASON="$(reorg_block_failure_reason "${phase}" "${output}")"
    rm -f -- "${block_hex_file}"
    printf '%s\n' "${output}" >&2
    return 1
  }
  rm -f -- "${block_hex_file}"
}
mine_reorg_block() {
  local impl="$1" rpc_addr="$2" phase="$3" out="$4"
  REORG_STEP_REASON=""
  capture_reorg_rpc_sidecar "${impl}" POST "${rpc_addr}" /mine_next "${phase}" "${out}" '{}' || { REORG_STEP_REASON="${REORG_CAPTURE_REASON:-${phase}_capture_failed}"; return 1; }
  reorg_mine_tsv "${out}" || { REORG_STEP_REASON="${phase}_mine_sidecar_malformed"; return 1; }
}
capture_reorg_block() {
  local impl="$1" rpc_addr="$2" phase="$3" height="$4" block_hash="$5" out="$6"
  REORG_STEP_REASON=""
  capture_reorg_rpc_sidecar "${impl}" GET "${rpc_addr}" "/get_block?height=${height}" "${phase}" "${out}" || { REORG_STEP_REASON="${REORG_CAPTURE_REASON:-${phase}_capture_failed}"; return 1; }
  reorg_block_matches "${phase}" "${out}" "${height}" "${block_hash}" || { REORG_STEP_REASON="${REORG_STEP_REASON:-${phase}_block_check_failed}"; return 1; }
}
wait_reorg_tip_matches() {
  local impl="$1" rpc_addr="$2" phase="$3" out="$4" want_height="$5" want_hash="$6" timeout="$7" deadline tmp parsed height tip_hash
  REORG_STEP_REASON=""
  deadline=$((SECONDS + timeout))
  tmp="${out}.candidate"
  rm -f -- "${out}" "${tmp}"
  while (( SECONDS < deadline )); do
    if capture_reorg_rpc_sidecar "${impl}" GET "${rpc_addr}" /get_tip "${phase}" "${tmp}"; then
      parsed="$(reorg_tip_tsv "${tmp}")" || { REORG_STEP_REASON="${phase}_tip_sidecar_malformed"; rm -f -- "${tmp}"; return 2; }
      IFS=$'\t' read -r height tip_hash <<<"${parsed}" || { REORG_STEP_REASON="${phase}_tip_sidecar_malformed"; rm -f -- "${tmp}"; return 2; }
      if [[ "${height}" == "${want_height}" && "${tip_hash}" == "${want_hash}" ]]; then
        mv -- "${tmp}" "${out}" || { REORG_STEP_REASON="${phase}_tip_publish_failed"; rm -f -- "${tmp}" "${out}"; return 2; }
        return 0
      fi
    else
      REORG_STEP_REASON="${REORG_CAPTURE_REASON:-${phase}_capture_failed}"
      rm -f -- "${tmp}"
      return 2
    fi
    sleep 1
  done
  rm -f -- "${tmp}"
  return 1
}
require_reorg_tip_matches() {
  local timeout_reason="$1" malformed_reason="$2" rc=0
  shift 2
  wait_reorg_tip_matches "$@" || rc=$?
  (( rc == 0 )) && return 0
  (( rc == 2 )) && partition_reorg_no_data "${REORG_STEP_REASON:-${malformed_reason}}"
  partition_reorg_no_data "${timeout_reason}"
}
write_partition_reorg_report() {
  local tmp="${PARTITION_REORG_REPORT_JSON}.tmp"
  export PARTITION_REORG_REPORT_JSON PARTITION_REORG_REPORT_TMP GO_PARTITION_PID GO_PARTITION_RPC GO_PARTITION_P2P GO_PARTITION_STARTED RUST_PARTITION_PID RUST_PARTITION_RPC RUST_PARTITION_P2P RUST_PARTITION_STARTED PROXY_PID PROXY_ADDR GO_PROXY_LOCAL_PRE GO_PROXY_LOCAL_HEAL PRE_RUST_PEERS PRE_GO_PEERS PARTITION_RUST_PEERS PARTITION_GO_PEERS FORK_RUST_PEERS FORK_GO_PEERS HEAL_RUST_PEERS HEAL_GO_PEERS COMMON_HEIGHT COMMON_HASH COMMON_TX_COUNT GO_FORK_HEIGHT GO_FORK_HASH GO_FORK_TX_COUNT RUST_FORK1_HEIGHT RUST_FORK1_HASH RUST_FORK1_TX_COUNT RUST_FORK2_HEIGHT RUST_FORK2_HASH RUST_FORK2_TX_COUNT GO_REORG_TOTAL GO_LAST_REORG_DEPTH COMMON_GO_MINE COMMON_RUST_TIP COMMON_GO_BLOCK COMMON_RUST_BLOCK GO_FORK_MINE GO_FORK_TIP GO_FORK_BLOCK RUST_FORK1_MINE RUST_FORK2_MINE RUST_FORK_TIP RUST_FORK1_BLOCK RUST_FORK2_BLOCK FINAL_GO_TIP FINAL_RUST_TIP FINAL_GO_REORG_BLOCK FINAL_GO_TIP_BLOCK FINAL_RUST_TIP_BLOCK
  PARTITION_REORG_REPORT_TMP="${tmp}"
  rm -f -- "${tmp}"
  python3 - <<'PY' || { rm -f -- "${tmp}"; return 1; }
import json
import os

e = os.environ
report = {
    "scenario": "mixed_client_partition_heal_reorg",
    "verdict": "PASS",
    "nodes": [
        {"name": "node-go", "implementation": "go", "pid": int(e["GO_PARTITION_PID"]), "rpc_endpoint": e["GO_PARTITION_RPC"], "p2p_endpoint": e["GO_PARTITION_P2P"], "started_at": e["GO_PARTITION_STARTED"]},
        {"name": "node-rust", "implementation": "rust", "pid": int(e["RUST_PARTITION_PID"]), "rpc_endpoint": e["RUST_PARTITION_RPC"], "p2p_endpoint": e["RUST_PARTITION_P2P"], "started_at": e["RUST_PARTITION_STARTED"]},
    ],
    "control": {"mode": "active_drop_tcp_proxy_with_live_peer_state_and_reorg", "source": "node-rust", "target": "node-go", "proxy_pid": int(e["PROXY_PID"]), "proxy_addr": e["PROXY_ADDR"]},
    "proof": {
        "common_height": int(e["COMMON_HEIGHT"]),
        "common_hash": e["COMMON_HASH"],
        "partition_changed_peer_state": True,
        "fork_diverged": True,
        "heal_restored_peer_state": True,
        "reorg_converged": True,
        "go_partition_tip": {"height": int(e["GO_FORK_HEIGHT"]), "hash": e["GO_FORK_HASH"]},
        "rust_winning_tip": {"height": int(e["RUST_FORK2_HEIGHT"]), "hash": e["RUST_FORK2_HASH"]},
        "go_reorg_parent_after_heal": {"height": int(e["RUST_FORK1_HEIGHT"]), "hash": e["RUST_FORK1_HASH"]},
        "mined_tx_counts": {"common": int(e["COMMON_TX_COUNT"]), "go_fork": int(e["GO_FORK_TX_COUNT"]), "rust_fork_1": int(e["RUST_FORK1_TX_COUNT"]), "rust_fork_2": int(e["RUST_FORK2_TX_COUNT"])},
        "go_reorg_metrics": {"rubin_node_reorg_total": int(e["GO_REORG_TOTAL"]), "rubin_node_last_reorg_depth": int(e["GO_LAST_REORG_DEPTH"])},
        "process_identity_rechecked_after_heal": True,
        "source_expected_peer_addr": e["PROXY_ADDR"],
        "target_pre_partition_peer_addr": e["GO_PROXY_LOCAL_PRE"],
        "target_heal_peer_addr": e["GO_PROXY_LOCAL_HEAL"],
    },
    "observations": {
        "pre_partition": {"rust_peer_snapshot": e["PRE_RUST_PEERS"], "go_peer_snapshot": e["PRE_GO_PEERS"], "common_go_mine": e["COMMON_GO_MINE"], "common_rust_tip": e["COMMON_RUST_TIP"], "common_go_block": e["COMMON_GO_BLOCK"], "common_rust_block": e["COMMON_RUST_BLOCK"]},
        "partition": {"rust_peer_snapshot": e["PARTITION_RUST_PEERS"], "go_peer_snapshot": e["PARTITION_GO_PEERS"]},
        "fork": {"rust_peer_snapshot": e["FORK_RUST_PEERS"], "go_peer_snapshot": e["FORK_GO_PEERS"], "go_mine": e["GO_FORK_MINE"], "go_tip": e["GO_FORK_TIP"], "go_block": e["GO_FORK_BLOCK"], "rust_mine_1": e["RUST_FORK1_MINE"], "rust_mine_2": e["RUST_FORK2_MINE"], "rust_tip": e["RUST_FORK_TIP"], "rust_block_1": e["RUST_FORK1_BLOCK"], "rust_block_2": e["RUST_FORK2_BLOCK"]},
        "heal": {"rust_peer_snapshot": e["HEAL_RUST_PEERS"], "go_peer_snapshot": e["HEAL_GO_PEERS"]},
        "reorg": {"go_tip": e["FINAL_GO_TIP"], "rust_tip": e["FINAL_RUST_TIP"], "go_reorg_parent_block": e["FINAL_GO_REORG_BLOCK"], "go_tip_block": e["FINAL_GO_TIP_BLOCK"], "rust_tip_block": e["FINAL_RUST_TIP_BLOCK"]},
    },
    "non_goals": ["no reorg algorithm/runtime change", "no P2P protocol change", "no tx-path proof beyond setup evidence"],
}
if set(report) != {"control", "nodes", "non_goals", "observations", "proof", "scenario", "verdict"}:
    raise SystemExit("report top-level key mismatch")
expected_proof_keys = {
    "common_hash",
    "common_height",
    "fork_diverged",
    "go_partition_tip",
    "go_reorg_metrics",
    "go_reorg_parent_after_heal",
    "heal_restored_peer_state",
    "mined_tx_counts",
    "partition_changed_peer_state",
    "process_identity_rechecked_after_heal",
    "reorg_converged",
    "rust_winning_tip",
    "source_expected_peer_addr",
    "target_heal_peer_addr",
    "target_pre_partition_peer_addr",
}
if set(report["proof"]) != expected_proof_keys:
    raise SystemExit("report proof key mismatch")
if report["verdict"] != "PASS" or "failure_phase" in report or "failure_reason" in report:
    raise SystemExit("report verdict/failure field mismatch")
if report["proof"]["go_partition_tip"]["hash"] == report["proof"]["rust_winning_tip"]["hash"]:
    raise SystemExit("report does not prove divergent fork")
if report["proof"]["go_reorg_metrics"]["rubin_node_reorg_total"] < 1 or report["proof"]["go_reorg_metrics"]["rubin_node_last_reorg_depth"] < 1:
    raise SystemExit("report does not prove Go reorg metric increment")
with open(e["PARTITION_REORG_REPORT_TMP"], "w", encoding="utf-8") as f:
    json.dump(report, f, indent=2, sort_keys=True)
    f.write("\n")
PY
  mv -- "${tmp}" "${PARTITION_REORG_REPORT_JSON}" || { rm -f -- "${tmp}"; return 1; }
}
run_mixed_partition_heal() {
  local proxy_target="${RUBIN_PROCESS_ARTIFACT_ROOT}/partition-proxy-target.txt"
  PRE_RUST_PEERS="${RUBIN_PROCESS_ARTIFACT_ROOT}/pre-rust-peers.json"
  PRE_GO_PEERS="${RUBIN_PROCESS_ARTIFACT_ROOT}/pre-go-peers.json"
  PARTITION_RUST_PEERS="${RUBIN_PROCESS_ARTIFACT_ROOT}/partition-rust-peers.json"
  PARTITION_GO_PEERS="${RUBIN_PROCESS_ARTIFACT_ROOT}/partition-go-peers.json"
  HEAL_RUST_PEERS="${RUBIN_PROCESS_ARTIFACT_ROOT}/heal-rust-peers.json"
  HEAL_GO_PEERS="${RUBIN_PROCESS_ARTIFACT_ROOT}/heal-go-peers.json"
  echo "Building Go/Rust rubin-node binaries for live partition/heal proof"
  "${DEV_ENV}" -- go -C "${GO_MODULE_ROOT}" build -o "${NODE_BIN}" ./cmd/rubin-node || partition_no_data go_build_failed
  build_rust_node_for_partition || partition_no_data rust_build_failed
  write_partition_tcp_proxy
  start_partition_go_node || partition_no_data go_process_not_ready
  verify_partition_process_identity node-go "${GO_PARTITION_PID}" "${GO_PARTITION_RPC}" "${GO_PARTITION_P2P}" "${NODE_BIN}" || partition_no_data go_process_identity_unverified
  printf '%s\n' "${GO_PARTITION_P2P}" >"${proxy_target}"
  start_proxy "partition-proxy.log" "${proxy_target}" || partition_no_data proxy_not_ready
  start_partition_rust_node "${PROXY_ADDR}" || partition_no_data rust_process_not_ready
  verify_partition_process_identity node-rust "${RUST_PARTITION_PID}" "${RUST_PARTITION_RPC}" "${RUST_PARTITION_P2P}" "${RUST_NODE_BIN}" || partition_no_data rust_process_identity_unverified
  require_peer_present pre_partition_source_peer_missing pre-rust rust "${RUST_PARTITION_RPC}" "${PROXY_ADDR}" "${PRE_RUST_PEERS}" 90
  GO_PROXY_LOCAL_PRE="$(wait_established_local_to_remote proxy-pre "${PROXY_PID}" "${GO_PARTITION_P2P}" 30)" || partition_no_data pre_partition_proxy_target_link_missing
  require_peer_present pre_partition_target_peer_missing pre-go go "${GO_PARTITION_RPC}" "${GO_PROXY_LOCAL_PRE}" "${PRE_GO_PEERS}" 30
  printf 'drop\n' >"${proxy_target}"
  require_peer_absent partition_source_peer_unchanged partition-rust rust "${RUST_PARTITION_RPC}" "${PROXY_ADDR}" "${PARTITION_RUST_PEERS}" 90
  require_peer_absent partition_target_peer_unchanged partition-go go "${GO_PARTITION_RPC}" "${GO_PROXY_LOCAL_PRE}" "${PARTITION_GO_PEERS}" 30
  wait_no_established_to_remote rust-partition "${RUST_PARTITION_PID}" "${PROXY_ADDR}" 30 || partition_no_data partition_source_tcp_link_unchanged
  wait_no_established_to_remote proxy-partition "${PROXY_PID}" "${GO_PARTITION_P2P}" 30 || partition_no_data partition_proxy_target_link_unchanged
  printf '%s\n' "${GO_PARTITION_P2P}" >"${proxy_target}"
  require_peer_present heal_source_peer_missing heal-rust rust "${RUST_PARTITION_RPC}" "${PROXY_ADDR}" "${HEAL_RUST_PEERS}" 120
  GO_PROXY_LOCAL_HEAL="$(wait_established_local_to_remote proxy-heal "${PROXY_PID}" "${GO_PARTITION_P2P}" 60)" || partition_no_data heal_proxy_target_link_missing
  require_peer_present heal_target_peer_missing heal-go go "${GO_PARTITION_RPC}" "${GO_PROXY_LOCAL_HEAL}" "${HEAL_GO_PEERS}" 60
  verify_partition_process_identity node-go-final "${GO_PARTITION_PID}" "${GO_PARTITION_RPC}" "${GO_PARTITION_P2P}" "${NODE_BIN}" || partition_no_data go_final_process_identity_unverified
  verify_partition_process_identity node-rust-final "${RUST_PARTITION_PID}" "${RUST_PARTITION_RPC}" "${RUST_PARTITION_P2P}" "${RUST_NODE_BIN}" || partition_no_data rust_final_process_identity_unverified
  write_partition_report || partition_no_data report_write_failed
  if [[ "${RUBIN_PROCESS_KEEP_ARTIFACTS}" == "1" ]]; then
    echo "PASS: mixed-client partition/heal changed and restored live peer state; report=${PARTITION_REPORT_JSON}"
  else
    echo "PASS: mixed-client partition/heal changed and restored live peer state; set KEEP_TMP=1 to retain report"
  fi
}
run_mixed_partition_heal_reorg() {
  local proxy_target="${RUBIN_PROCESS_ARTIFACT_ROOT}/partition-reorg-proxy-target.txt" parsed expected_fork_height expected_winning_height
  PARTITION_GO_MINE_ADDRESS_HEX="1111111111111111111111111111111111111111111111111111111111111111"
  PARTITION_RUST_MINE_ADDRESS_HEX="2222222222222222222222222222222222222222222222222222222222222222"
  PRE_RUST_PEERS="${RUBIN_PROCESS_ARTIFACT_ROOT}/reorg-pre-rust-peers.json"
  PRE_GO_PEERS="${RUBIN_PROCESS_ARTIFACT_ROOT}/reorg-pre-go-peers.json"
  PARTITION_RUST_PEERS="${RUBIN_PROCESS_ARTIFACT_ROOT}/reorg-partition-rust-peers.json"
  PARTITION_GO_PEERS="${RUBIN_PROCESS_ARTIFACT_ROOT}/reorg-partition-go-peers.json"
  FORK_RUST_PEERS="${RUBIN_PROCESS_ARTIFACT_ROOT}/reorg-fork-rust-peers.json"
  FORK_GO_PEERS="${RUBIN_PROCESS_ARTIFACT_ROOT}/reorg-fork-go-peers.json"
  HEAL_RUST_PEERS="${RUBIN_PROCESS_ARTIFACT_ROOT}/reorg-heal-rust-peers.json"
  HEAL_GO_PEERS="${RUBIN_PROCESS_ARTIFACT_ROOT}/reorg-heal-go-peers.json"
  COMMON_GO_MINE="${RUBIN_PROCESS_ARTIFACT_ROOT}/reorg-common-go-mine.json"
  COMMON_RUST_TIP="${RUBIN_PROCESS_ARTIFACT_ROOT}/reorg-common-rust-tip.json"
  COMMON_GO_BLOCK="${RUBIN_PROCESS_ARTIFACT_ROOT}/reorg-common-go-block.json"
  COMMON_RUST_BLOCK="${RUBIN_PROCESS_ARTIFACT_ROOT}/reorg-common-rust-block.json"
  GO_FORK_MINE="${RUBIN_PROCESS_ARTIFACT_ROOT}/reorg-go-fork-mine.json"
  GO_FORK_TIP="${RUBIN_PROCESS_ARTIFACT_ROOT}/reorg-go-fork-tip.json"
  GO_FORK_BLOCK="${RUBIN_PROCESS_ARTIFACT_ROOT}/reorg-go-fork-block.json"
  RUST_FORK1_MINE="${RUBIN_PROCESS_ARTIFACT_ROOT}/reorg-rust-fork1-mine.json"
  RUST_FORK2_MINE="${RUBIN_PROCESS_ARTIFACT_ROOT}/reorg-rust-fork2-mine.json"
  RUST_FORK_TIP="${RUBIN_PROCESS_ARTIFACT_ROOT}/reorg-rust-fork-tip.json"
  RUST_FORK1_BLOCK="${RUBIN_PROCESS_ARTIFACT_ROOT}/reorg-rust-fork1-block.json"
  RUST_FORK2_BLOCK="${RUBIN_PROCESS_ARTIFACT_ROOT}/reorg-rust-fork2-block.json"
  FINAL_GO_TIP="${RUBIN_PROCESS_ARTIFACT_ROOT}/reorg-final-go-tip.json"
  FINAL_RUST_TIP="${RUBIN_PROCESS_ARTIFACT_ROOT}/reorg-final-rust-tip.json"
  FINAL_GO_REORG_BLOCK="${RUBIN_PROCESS_ARTIFACT_ROOT}/reorg-final-go-reorg-parent-block.json"
  FINAL_GO_TIP_BLOCK="${RUBIN_PROCESS_ARTIFACT_ROOT}/reorg-final-go-tip-block.json"
  FINAL_RUST_TIP_BLOCK="${RUBIN_PROCESS_ARTIFACT_ROOT}/reorg-final-rust-tip-block.json"
  echo "Building Go/Rust rubin-node binaries for live partition/heal reorg proof"
  "${DEV_ENV}" -- go -C "${GO_MODULE_ROOT}" build -o "${NODE_BIN}" ./cmd/rubin-node || partition_reorg_no_data go_build_failed
  build_rust_node_for_partition || partition_reorg_no_data rust_build_failed
  write_partition_tcp_proxy
  start_partition_go_node || partition_reorg_no_data go_process_not_ready
  verify_partition_process_identity node-go "${GO_PARTITION_PID}" "${GO_PARTITION_RPC}" "${GO_PARTITION_P2P}" "${NODE_BIN}" || partition_reorg_no_data go_process_identity_unverified
  printf '%s\n' "${GO_PARTITION_P2P}" >"${proxy_target}"
  start_proxy "partition-reorg-proxy.log" "${proxy_target}" || partition_reorg_no_data proxy_not_ready
  start_partition_rust_node "${PROXY_ADDR}" || partition_reorg_no_data rust_process_not_ready
  verify_partition_process_identity node-rust "${RUST_PARTITION_PID}" "${RUST_PARTITION_RPC}" "${RUST_PARTITION_P2P}" "${RUST_NODE_BIN}" || partition_reorg_no_data rust_process_identity_unverified
  require_reorg_peer_present pre_partition_source_peer_missing pre-rust rust "${RUST_PARTITION_RPC}" "${PROXY_ADDR}" "${PRE_RUST_PEERS}" 90
  GO_PROXY_LOCAL_PRE="$(wait_established_local_to_remote proxy-pre "${PROXY_PID}" "${GO_PARTITION_P2P}" 30)" || partition_reorg_no_data pre_partition_proxy_target_link_missing
  require_reorg_peer_present pre_partition_target_peer_missing pre-go go "${GO_PARTITION_RPC}" "${GO_PROXY_LOCAL_PRE}" "${PRE_GO_PEERS}" 30

  parsed="$(mine_reorg_block go "${GO_PARTITION_RPC}" common-go-mine "${COMMON_GO_MINE}")" || partition_reorg_no_data "${REORG_STEP_REASON:-common_go_mine_failed}"
  IFS=$'\t' read -r COMMON_HEIGHT COMMON_HASH COMMON_TX_COUNT <<<"${parsed}" || partition_reorg_no_data common_go_mine_malformed
  require_reorg_tip_matches common_rust_converge_timeout common_rust_tip_malformed rust "${RUST_PARTITION_RPC}" common-rust-tip "${COMMON_RUST_TIP}" "${COMMON_HEIGHT}" "${COMMON_HASH}" 120
  capture_reorg_block go "${GO_PARTITION_RPC}" common-go-block "${COMMON_HEIGHT}" "${COMMON_HASH}" "${COMMON_GO_BLOCK}" || partition_reorg_no_data "${REORG_STEP_REASON:-common_go_block_missing}"
  capture_reorg_block rust "${RUST_PARTITION_RPC}" common-rust-block "${COMMON_HEIGHT}" "${COMMON_HASH}" "${COMMON_RUST_BLOCK}" || partition_reorg_no_data "${REORG_STEP_REASON:-common_rust_block_missing}"

  printf 'drop\n' >"${proxy_target}"
  require_reorg_peer_absent partition_source_peer_unchanged partition-rust rust "${RUST_PARTITION_RPC}" "${PROXY_ADDR}" "${PARTITION_RUST_PEERS}" 90
  require_reorg_peer_absent partition_target_peer_unchanged partition-go go "${GO_PARTITION_RPC}" "${GO_PROXY_LOCAL_PRE}" "${PARTITION_GO_PEERS}" 30
  wait_no_established_to_remote rust-partition "${RUST_PARTITION_PID}" "${PROXY_ADDR}" 30 || partition_reorg_no_data partition_source_tcp_link_unchanged
  wait_no_established_to_remote proxy-partition "${PROXY_PID}" "${GO_PARTITION_P2P}" 30 || partition_reorg_no_data partition_proxy_target_link_unchanged

  expected_fork_height=$((COMMON_HEIGHT + 1))
  parsed="$(mine_reorg_block go "${GO_PARTITION_RPC}" partition-go-fork-mine "${GO_FORK_MINE}")" || partition_reorg_no_data "${REORG_STEP_REASON:-go_fork_mine_failed}"
  IFS=$'\t' read -r GO_FORK_HEIGHT GO_FORK_HASH GO_FORK_TX_COUNT <<<"${parsed}" || partition_reorg_no_data go_fork_mine_malformed
  (( GO_FORK_HEIGHT == expected_fork_height )) || partition_reorg_no_data go_fork_height_unexpected
  require_reorg_tip_matches go_fork_tip_timeout go_fork_tip_malformed go "${GO_PARTITION_RPC}" partition-go-fork-tip "${GO_FORK_TIP}" "${GO_FORK_HEIGHT}" "${GO_FORK_HASH}" 30
  capture_reorg_block go "${GO_PARTITION_RPC}" partition-go-fork-block "${GO_FORK_HEIGHT}" "${GO_FORK_HASH}" "${GO_FORK_BLOCK}" || partition_reorg_no_data "${REORG_STEP_REASON:-go_fork_block_missing}"

  parsed="$(mine_reorg_block rust "${RUST_PARTITION_RPC}" partition-rust-fork1-mine "${RUST_FORK1_MINE}")" || partition_reorg_no_data "${REORG_STEP_REASON:-rust_fork1_mine_failed}"
  IFS=$'\t' read -r RUST_FORK1_HEIGHT RUST_FORK1_HASH RUST_FORK1_TX_COUNT <<<"${parsed}" || partition_reorg_no_data rust_fork1_mine_malformed
  (( RUST_FORK1_HEIGHT == expected_fork_height )) || partition_reorg_no_data rust_fork1_height_unexpected
  [[ "${RUST_FORK1_HASH}" != "${GO_FORK_HASH}" ]] || partition_reorg_no_data fork_hash_not_divergent
  expected_winning_height=$((COMMON_HEIGHT + 2))
  parsed="$(mine_reorg_block rust "${RUST_PARTITION_RPC}" partition-rust-fork2-mine "${RUST_FORK2_MINE}")" || partition_reorg_no_data "${REORG_STEP_REASON:-rust_fork2_mine_failed}"
  IFS=$'\t' read -r RUST_FORK2_HEIGHT RUST_FORK2_HASH RUST_FORK2_TX_COUNT <<<"${parsed}" || partition_reorg_no_data rust_fork2_mine_malformed
  (( RUST_FORK2_HEIGHT == expected_winning_height )) || partition_reorg_no_data rust_fork2_height_unexpected
  require_reorg_tip_matches rust_fork_tip_timeout rust_fork_tip_malformed rust "${RUST_PARTITION_RPC}" partition-rust-fork-tip "${RUST_FORK_TIP}" "${RUST_FORK2_HEIGHT}" "${RUST_FORK2_HASH}" 30
  capture_reorg_block rust "${RUST_PARTITION_RPC}" partition-rust-fork1-block "${RUST_FORK1_HEIGHT}" "${RUST_FORK1_HASH}" "${RUST_FORK1_BLOCK}" || partition_reorg_no_data "${REORG_STEP_REASON:-rust_fork1_block_missing}"
  capture_reorg_block rust "${RUST_PARTITION_RPC}" partition-rust-fork2-block "${RUST_FORK2_HEIGHT}" "${RUST_FORK2_HASH}" "${RUST_FORK2_BLOCK}" || partition_reorg_no_data "${REORG_STEP_REASON:-rust_fork2_block_missing}"
  require_reorg_peer_absent fork_source_peer_unchanged fork-rust rust "${RUST_PARTITION_RPC}" "${PROXY_ADDR}" "${FORK_RUST_PEERS}" 5
  require_reorg_peer_absent fork_target_peer_unchanged fork-go go "${GO_PARTITION_RPC}" "${GO_PROXY_LOCAL_PRE}" "${FORK_GO_PEERS}" 5

  printf '%s\n' "${GO_PARTITION_P2P}" >"${proxy_target}"
  require_reorg_peer_present heal_source_peer_missing heal-rust rust "${RUST_PARTITION_RPC}" "${PROXY_ADDR}" "${HEAL_RUST_PEERS}" 120
  GO_PROXY_LOCAL_HEAL="$(wait_established_local_to_remote proxy-heal "${PROXY_PID}" "${GO_PARTITION_P2P}" 60)" || partition_reorg_no_data heal_proxy_target_link_missing
  require_reorg_peer_present heal_target_peer_missing heal-go go "${GO_PARTITION_RPC}" "${GO_PROXY_LOCAL_HEAL}" "${HEAL_GO_PEERS}" 60

  require_reorg_tip_matches go_reorg_converge_timeout go_reorg_tip_malformed go "${GO_PARTITION_RPC}" final-go-tip "${FINAL_GO_TIP}" "${RUST_FORK2_HEIGHT}" "${RUST_FORK2_HASH}" 180
  require_reorg_tip_matches rust_final_tip_timeout rust_final_tip_malformed rust "${RUST_PARTITION_RPC}" final-rust-tip "${FINAL_RUST_TIP}" "${RUST_FORK2_HEIGHT}" "${RUST_FORK2_HASH}" 30
  capture_reorg_block go "${GO_PARTITION_RPC}" final-go-reorg-parent-block "${RUST_FORK1_HEIGHT}" "${RUST_FORK1_HASH}" "${FINAL_GO_REORG_BLOCK}" || partition_reorg_no_data "${REORG_STEP_REASON:-go_reorg_parent_block_missing}"
  capture_reorg_block go "${GO_PARTITION_RPC}" final-go-tip-block "${RUST_FORK2_HEIGHT}" "${RUST_FORK2_HASH}" "${FINAL_GO_TIP_BLOCK}" || partition_reorg_no_data "${REORG_STEP_REASON:-go_reorg_tip_block_missing}"
  capture_reorg_block rust "${RUST_PARTITION_RPC}" final-rust-tip-block "${RUST_FORK2_HEIGHT}" "${RUST_FORK2_HASH}" "${FINAL_RUST_TIP_BLOCK}" || partition_reorg_no_data "${REORG_STEP_REASON:-rust_final_tip_block_missing}"
  GO_REORG_TOTAL="$(metric_value "${GO_PARTITION_RPC}" rubin_node_reorg_total)" || partition_reorg_no_data go_reorg_metric_missing
  GO_LAST_REORG_DEPTH="$(metric_value "${GO_PARTITION_RPC}" rubin_node_last_reorg_depth)" || partition_reorg_no_data go_reorg_depth_metric_missing
  (( GO_REORG_TOTAL >= 1 )) || partition_reorg_no_data go_reorg_metric_not_incremented
  (( GO_LAST_REORG_DEPTH >= 1 )) || partition_reorg_no_data go_reorg_depth_not_recorded
  verify_partition_process_identity node-go-final "${GO_PARTITION_PID}" "${GO_PARTITION_RPC}" "${GO_PARTITION_P2P}" "${NODE_BIN}" || partition_reorg_no_data go_final_process_identity_unverified
  verify_partition_process_identity node-rust-final "${RUST_PARTITION_PID}" "${RUST_PARTITION_RPC}" "${RUST_PARTITION_P2P}" "${RUST_NODE_BIN}" || partition_reorg_no_data rust_final_process_identity_unverified
  write_partition_reorg_report || partition_reorg_no_data report_write_failed
  if [[ "${RUBIN_PROCESS_KEEP_ARTIFACTS}" == "1" ]]; then
    echo "PASS: mixed-client partition/heal produced live reorg convergence; report=${PARTITION_REORG_REPORT_JSON}"
  else
    echo "PASS: mixed-client partition/heal produced live reorg convergence; set KEEP_TMP=1 to retain report"
  fi
}
start_node_ready() {
  local label="$1" log_file="$2" datadir="$3" peers="${4:-}" args
  args=(--datadir "${datadir}" --bind 127.0.0.1:0 --rpc-bind 127.0.0.1:0 --mine-address "${MINE_ADDRESS_HEX}")
  [[ -z "${peers}" ]] || args+=(--peers "${peers}")
  STARTED_PID="" STARTED_RPC="" STARTED_P2P=""
  if ! rubin_process_start "${log_file}" "${NODE_BIN}" "${args[@]}"; then
    echo "${label} start failed" >&2
    [[ -z "${RUBIN_PROCESS_LAST_PID}" ]] || stop_registered_pid "${RUBIN_PROCESS_LAST_PID}" || true
    return 1
  fi
  STARTED_PID="${RUBIN_PROCESS_LAST_PID}"
  if ! rubin_process_wait_for_log "${log_file}" "rpc: listening=" 30 "${STARTED_PID}"; then
    echo "${label} did not become ready" >&2
    stop_registered_pid "${STARTED_PID}" || true
    STARTED_PID=""
    return 1
  fi
  STARTED_RPC="$(rubin_process_extract_rpc_addr "${log_file}")" || { stop_registered_pid "${STARTED_PID}" || true; return 1; }
  STARTED_P2P="$(p2p_addr_for_pid "${STARTED_PID}" "${STARTED_RPC}" 30)" || { stop_registered_pid "${STARTED_PID}" || true; return 1; }
}
start_soak_cluster() {
  A_PID="" B_PID="" C_PID="" A_RPC_ADDR="" B_RPC_ADDR="" C_RPC_ADDR=""
  start_node_ready node-b "${B_LOG}" "${B_DIR}" || return 1
  B_PID="${STARTED_PID}" B_RPC_ADDR="${STARTED_RPC}" B_P2P_ADDR="${STARTED_P2P}"
  printf '%s\n' "${B_P2P_ADDR}" >"${B_PROXY_TARGET}"
  start_proxy "${B_PROXY_LOG}" "${B_PROXY_TARGET}"
  B_PROXY_ADDR="${PROXY_ADDR}"
  start_node_ready node-c "${C_LOG}" "${C_DIR}" || return 1
  C_PID="${STARTED_PID}" C_RPC_ADDR="${STARTED_RPC}" C_P2P_ADDR="${STARTED_P2P}"
  printf '%s\n' "${C_P2P_ADDR}" >"${C_PROXY_TARGET}"
  start_proxy "${C_PROXY_LOG}" "${C_PROXY_TARGET}"
  C_PROXY_ADDR="${PROXY_ADDR}"
  start_node_ready node-a "${A_LOG}" "${A_DIR}" "${B_PROXY_ADDR},${C_PROXY_ADDR}" || return 1
  A_PID="${STARTED_PID}" A_RPC_ADDR="${STARTED_RPC}" A_P2P_ADDR="${STARTED_P2P}"
  rubin_process_wait_for_rpc_ready "${A_RPC_ADDR}" 30
  rubin_process_wait_for_rpc_ready "${B_RPC_ADDR}" 30
  rubin_process_wait_for_rpc_ready "${C_RPC_ADDR}" 30
}
restart_node_b() {
  start_node_ready "node-b restart" "${B_RESTART_LOG}" "${B_DIR}" "${A_P2P_ADDR}" || return 1
  B_PID="${STARTED_PID}" B_RPC_ADDR="${STARTED_RPC}" B_P2P_ADDR="${STARTED_P2P}"
  printf '%s\n' "${B_P2P_ADDR}" >"${B_PROXY_TARGET}"
  POST_RESTART_B_PID="${B_PID}"
  POST_RESTART_B_RPC_ADDR="${B_RPC_ADDR}" POST_RESTART_B_P2P_ADDR="${B_P2P_ADDR}"
}
write_keygen() {
  cat >"${KEYGEN_GO}" <<'EOF'
package main
import ("encoding/hex"; "encoding/json"; "os"; "github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus")
func main() {
  from, err := consensus.NewMLDSA87Keypair(); if err != nil { panic(err) }; defer from.Close()
  to, err := consensus.NewMLDSA87Keypair(); if err != nil { panic(err) }; defer to.Close()
  der, err := from.PrivateKeyDER(); if err != nil { panic(err) }
  out := map[string]string{
    "from_der_hex": hex.EncodeToString(der),
    "mine_address_hex": hex.EncodeToString(consensus.P2PKCovenantDataForPubkey(from.PubkeyBytes())),
    "to_address_hex": hex.EncodeToString(consensus.P2PKCovenantDataForPubkey(to.PubkeyBytes())),
  }
  if err := json.NewEncoder(os.Stdout).Encode(out); err != nil { panic(err) }
}
EOF
}
if (( MIXED_PARTITION_HEAL == 1 )); then
  run_mixed_partition_heal
  exit 0
fi
if (( MIXED_PARTITION_HEAL_REORG == 1 )); then
  run_mixed_partition_heal_reorg
  exit 0
fi
echo "Building Go rubin-node and rubin-txgen"
"${DEV_ENV}" -- go -C "${GO_MODULE_ROOT}" build -o "${NODE_BIN}" ./cmd/rubin-node
"${DEV_ENV}" -- go -C "${GO_MODULE_ROOT}" build -o "${TXGEN_BIN}" ./cmd/rubin-txgen
write_keygen
write_tcp_proxy
"${DEV_ENV}" -- go -C "${GO_MODULE_ROOT}" run "${KEYGEN_GO}" >"${KEYGEN_JSON}"
FROM_DER_HEX="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["from_der_hex"])' "${KEYGEN_JSON}")"
MINE_ADDRESS_HEX="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["mine_address_hex"])' "${KEYGEN_JSON}")"
TO_ADDRESS_HEX="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["to_address_hex"])' "${KEYGEN_JSON}")"
mkdir -p "${A_DIR}" "${B_DIR}" "${C_DIR}"
echo "Mining mature Go chain to height ${BASE_HEIGHT}"
"${NODE_BIN}" --datadir "${A_DIR}" --mine-address "${MINE_ADDRESS_HEX}" --mine-blocks "${BASE_MINE_BLOCKS}" --mine-exit >"${MINE_LOG}" 2>&1
cp -R "${A_DIR}/." "${B_DIR}/"
cp -R "${A_DIR}/." "${C_DIR}/"
echo "Starting three Go rubin-node processes"
start_soak_cluster
for addr in "${A_RPC_ADDR}" "${B_RPC_ADDR}" "${C_RPC_ADDR}"; do wait_height "${addr}" "${BASE_HEIGHT}" 30; done
if (( WITH_RESTART == 1 )); then
  IFS=$'\t' read -r PRE_RESTART_B_HEIGHT PRE_RESTART_B_TIP < <(tip_tsv "${B_RPC_ADDR}")
  PRE_RESTART_B_RPC_ADDR="${B_RPC_ADDR}" PRE_RESTART_B_P2P_ADDR="${B_P2P_ADDR}"
  PRE_RESTART_B_PID="${B_PID}"
  echo "Stopping node-b pid=${B_PID} at deterministic restart checkpoint height ${PRE_RESTART_B_HEIGHT}"
  stop_registered_pid "${B_PID}"
fi
echo "Submitting tx through Go RPC and mining it through /mine_next"
TX_HEX="$("${TXGEN_BIN}" --datadir "${A_DIR}" --from-key "${FROM_DER_HEX}" --to-key "${TO_ADDRESS_HEX}" --amount 1 --fee 1 --submit-to "${A_RPC_ADDR}")"
if ! MEMPOOL_JSON="$(rpc_json GET "${A_RPC_ADDR}" /get_mempool)"; then echo "get_mempool request failed: ${MEMPOOL_JSON}" >&2; exit 1; fi
TX_ID="$(printf '%s' "${MEMPOOL_JSON}" | python3 -c 'import json,sys; d=json.load(sys.stdin); (d.get("count") == 1 and d.get("txids")) or sys.exit("expected mempool count=1; mempool_json="+json.dumps(d, sort_keys=True)); print(d["txids"][0])')"
if ! MINE_JSON="$(rpc_json POST "${A_RPC_ADDR}" /mine_next '{}')"; then echo "mine_next request failed: ${MINE_JSON}" >&2; exit 1; fi
IFS=$'\t' read -r FINAL_HEIGHT FINAL_HASH TX_COUNT < <(printf '%s' "${MINE_JSON}" | python3 -c 'import json,sys; d=json.load(sys.stdin); (d.get("mined") is True) or sys.exit("mine_next failed: "+str(d.get("error","missing mined result"))); print(d["height"], d["block_hash"], d["tx_count"], sep="\t")')
[[ "${FINAL_HEIGHT}" == "${TARGET_HEIGHT}" && "${TX_COUNT}" -ge 2 ]] || {
  echo "unexpected mine_next result height=${FINAL_HEIGHT} tx_count=${TX_COUNT}" >&2
  exit 1
}
wait_height "${A_RPC_ADDR}" "${TARGET_HEIGHT}" 30
if (( WITH_RESTART == 1 )); then
  echo "Restarting node-b from disk-backed datadir ${B_DIR}"
  restart_node_b
  rubin_process_wait_for_rpc_ready "${B_RPC_ADDR}" 30
  wait_height "${B_RPC_ADDR}" "${TARGET_HEIGHT}" 60
  IFS=$'\t' read -r POST_RESTART_CATCHUP_HEIGHT POST_RESTART_CATCHUP_TIP < <(tip_tsv "${B_RPC_ADDR}")
  if ! POST_RESTART_CATCHUP_PEERS="$(wait_peers "${B_RPC_ADDR}" 1 30)"; then
    echo "failed post-restart node-b peer wait addr=${B_RPC_ADDR} want=1 timeout=30" >&2
    exit 1
  fi
  echo "Mining one additional block after restart through restarted node-b"
  if ! POST_RESTART_MINE_JSON="$(rpc_json POST "${B_RPC_ADDR}" /mine_next '{}')"; then echo "post-restart mine_next request failed: ${POST_RESTART_MINE_JSON}" >&2; exit 1; fi
  IFS=$'\t' read -r POST_RESTART_MINE_HEIGHT POST_RESTART_MINE_HASH POST_RESTART_MINE_TX_COUNT < <(printf '%s' "${POST_RESTART_MINE_JSON}" | python3 -c 'import json,sys; d=json.load(sys.stdin); (d.get("mined") is True) or sys.exit("post-restart mine_next failed: "+str(d.get("error","missing mined result"))); print(d["height"], d["block_hash"], d["tx_count"], sep="\t")')
  POST_RESTART_TARGET_HEIGHT=$((TARGET_HEIGHT + 1))
  [[ "${POST_RESTART_MINE_HEIGHT}" == "${POST_RESTART_TARGET_HEIGHT}" && "${POST_RESTART_MINE_TX_COUNT}" -ge 1 ]] || {
    echo "unexpected post-restart mine_next result height=${POST_RESTART_MINE_HEIGHT} tx_count=${POST_RESTART_MINE_TX_COUNT}" >&2
    exit 1
  }
  wait_height "${A_RPC_ADDR}" "${POST_RESTART_TARGET_HEIGHT}" 90
  wait_height "${B_RPC_ADDR}" "${POST_RESTART_TARGET_HEIGHT}" 60
  if ! POST_RESTART_B_BLOCK_JSON="$(rpc_json GET "${B_RPC_ADDR}" "/get_block?height=${POST_RESTART_TARGET_HEIGHT}")"; then
    echo "post-restart restarted node-b get_block failed addr=${B_RPC_ADDR} height=${POST_RESTART_TARGET_HEIGHT}: ${POST_RESTART_B_BLOCK_JSON}" >&2
    exit 1
  fi
  block_matches_hash_canonical "${POST_RESTART_B_BLOCK_JSON}" "${POST_RESTART_MINE_HASH}" || {
    echo "post-restart block was not adopted by restarted node-b at height=${POST_RESTART_TARGET_HEIGHT} expected_hash=${POST_RESTART_MINE_HASH} $(describe_block_json "${POST_RESTART_B_BLOCK_JSON}")" >&2
    exit 1
  }
  if ! POST_RESTART_A_BLOCK_JSON="$(rpc_json GET "${A_RPC_ADDR}" "/get_block?height=${POST_RESTART_TARGET_HEIGHT}")"; then
    echo "post-restart node-a get_block failed addr=${A_RPC_ADDR} height=${POST_RESTART_TARGET_HEIGHT}: ${POST_RESTART_A_BLOCK_JSON}" >&2
    exit 1
  fi
  block_matches_hash_canonical "${POST_RESTART_A_BLOCK_JSON}" "${POST_RESTART_MINE_HASH}" || {
    echo "post-restart block was not adopted by node-a at height=${POST_RESTART_TARGET_HEIGHT} expected_hash=${POST_RESTART_MINE_HASH} $(describe_block_json "${POST_RESTART_A_BLOCK_JSON}")" >&2
    exit 1
  }
  POST_RESTART_ACCEPTED_PEER="node-a"
  INCLUSION_PROOF_NODE="node-b"
fi
IFS=$'\t' read -r A_HEIGHT A_TIP < <(tip_tsv "${A_RPC_ADDR}")
IFS=$'\t' read -r B_HEIGHT B_TIP < <(tip_tsv "${B_RPC_ADDR}")
IFS=$'\t' read -r C_HEIGHT C_TIP < <(tip_tsv "${C_RPC_ADDR}")
if ! A_PEERS="$(wait_peers "${A_RPC_ADDR}" 2 30)"; then
  echo "failed node-a peer wait addr=${A_RPC_ADDR} want=2 timeout=30" >&2
  exit 1
fi
if ! B_PEERS="$(wait_peers "${B_RPC_ADDR}" 1 30)"; then
  echo "failed node-b peer wait addr=${B_RPC_ADDR} want=1 timeout=30" >&2
  exit 1
fi
if ! C_PEERS="$(wait_peers "${C_RPC_ADDR}" 1 30)"; then
  echo "failed node-c peer wait addr=${C_RPC_ADDR} want=1 timeout=30" >&2
  exit 1
fi
if (( WITH_RESTART == 1 )); then
  [[ "${POST_RESTART_ACCEPTED_PEER}" == "node-a" ]] || {
    echo "unexpected post-restart adoption marker=${POST_RESTART_ACCEPTED_PEER}" >&2
    exit 1
  }
  if ! POST_RESTART_A_BLOCK_JSON="$(rpc_json GET "${A_RPC_ADDR}" "/get_block?height=${POST_RESTART_MINE_HEIGHT}")"; then
    echo "post-restart adoption marker node-a get_block failed addr=${A_RPC_ADDR} height=${POST_RESTART_MINE_HEIGHT}: ${POST_RESTART_A_BLOCK_JSON}" >&2
    exit 1
  fi
  block_matches_hash_canonical "${POST_RESTART_A_BLOCK_JSON}" "${POST_RESTART_MINE_HASH}" || {
    echo "post-restart adoption marker node-a mismatch height=${POST_RESTART_MINE_HEIGHT} expected_hash=${POST_RESTART_MINE_HASH} $(describe_block_json "${POST_RESTART_A_BLOCK_JSON}")" >&2
    exit 1
  }
  [[ "${A_HEIGHT}" == "${POST_RESTART_MINE_HEIGHT}" && "${A_TIP}" == "${POST_RESTART_MINE_HASH}" && "${B_HEIGHT}" == "${POST_RESTART_MINE_HEIGHT}" && "${B_TIP}" == "${POST_RESTART_MINE_HASH}" && (("${C_HEIGHT}" == "${BASE_HEIGHT}" && -n "${C_TIP}") || ("${C_HEIGHT}" == "${TARGET_HEIGHT}" && "${C_TIP}" == "${FINAL_HASH}") || ("${C_HEIGHT}" == "${POST_RESTART_MINE_HEIGHT}" && "${C_TIP}" == "${POST_RESTART_MINE_HASH}")) && "${A_PEERS}" -ge 2 && "${B_PEERS}" -ge 1 && "${C_PEERS}" -ge 1 ]] || {
    echo "unexpected restart checkpoint/connectivity post_restart=${POST_RESTART_MINE_HASH} b_height=${B_HEIGHT} c_height=${C_HEIGHT} peers=${A_PEERS}/${B_PEERS}/${C_PEERS}" >&2
    exit 1
  }
else
  [[ "${A_HEIGHT}" == "${TARGET_HEIGHT}" && "${A_TIP}" == "${FINAL_HASH}" ]] || {
    echo "unexpected node-a checkpoint final=${FINAL_HASH} a_height=${A_HEIGHT} a_tip=${A_TIP}" >&2
    exit 1
  }
  [[ (("${B_HEIGHT}" == "${BASE_HEIGHT}" && -n "${B_TIP}") || ("${B_HEIGHT}" == "${TARGET_HEIGHT}" && "${B_TIP}" == "${FINAL_HASH}")) && (("${C_HEIGHT}" == "${BASE_HEIGHT}" && -n "${C_TIP}") || ("${C_HEIGHT}" == "${TARGET_HEIGHT}" && "${C_TIP}" == "${FINAL_HASH}")) && "${A_PEERS}" -ge 2 && "${B_PEERS}" -ge 1 && "${C_PEERS}" -ge 1 ]] || {
    echo "unexpected peer checkpoint/connectivity final=${FINAL_HASH} b_height=${B_HEIGHT} c_height=${C_HEIGHT} peers=${A_PEERS}/${B_PEERS}/${C_PEERS}" >&2
    exit 1
  }
fi
if (( WITH_RESTART == 1 )); then
  if ! BLOCK_JSON="$(rpc_json GET "${B_RPC_ADDR}" "/get_block?height=${TARGET_HEIGHT}")"; then
    echo "restart target block get_block failed addr=${B_RPC_ADDR} height=${TARGET_HEIGHT}: ${BLOCK_JSON}" >&2
    exit 1
  fi
  if ! POST_RESTART_BLOCK_JSON="$(rpc_json GET "${B_RPC_ADDR}" "/get_block?height=${POST_RESTART_MINE_HEIGHT}")"; then
    echo "restart post-restart block get_block failed addr=${B_RPC_ADDR} height=${POST_RESTART_MINE_HEIGHT}: ${POST_RESTART_BLOCK_JSON}" >&2
    exit 1
  fi
  block_matches_hash_canonical "${BLOCK_JSON}" "${FINAL_HASH}" || { echo "restart target block mismatch expected_hash=${FINAL_HASH} $(describe_block_json "${BLOCK_JSON}")" >&2; exit 1; }
  block_matches_hash_canonical "${POST_RESTART_BLOCK_JSON}" "${POST_RESTART_MINE_HASH}" || { echo "restart post-restart block mismatch expected_hash=${POST_RESTART_MINE_HASH} $(describe_block_json "${POST_RESTART_BLOCK_JSON}")" >&2; exit 1; }
else
  if ! BLOCK_JSON="$(rpc_json GET "${A_RPC_ADDR}" "/get_block?height=${TARGET_HEIGHT}")"; then
    echo "target block get_block failed addr=${A_RPC_ADDR} height=${TARGET_HEIGHT}: ${BLOCK_JSON}" >&2
    exit 1
  fi
fi
printf '%s' "${BLOCK_JSON}" | python3 -c 'import json,sys; d=json.load(sys.stdin); sys.argv[1].lower() in d.get("block_hex", "").lower() or sys.exit("submitted tx bytes missing from target block")' "${TX_HEX}"
if (( WITH_RESTART == 1 )); then
  printf '%s' "${POST_RESTART_BLOCK_JSON}" | python3 -c 'import json,sys; d=json.load(sys.stdin); h=d.get("block_hex",""); (isinstance(h, str) and len(h) > 0) or sys.exit("post-restart block visibility check failed")'
fi
export REPORT_JSON TARGET_HEIGHT BASE_HEIGHT A_HEIGHT B_HEIGHT C_HEIGHT A_TIP B_TIP C_TIP A_PID B_PID C_PID A_RPC_ADDR B_RPC_ADDR C_RPC_ADDR A_P2P_ADDR B_P2P_ADDR C_P2P_ADDR A_PEERS B_PEERS C_PEERS TX_ID FINAL_HASH TX_COUNT WITH_RESTART PRE_RESTART_B_HEIGHT PRE_RESTART_B_TIP PRE_RESTART_B_RPC_ADDR PRE_RESTART_B_P2P_ADDR PRE_RESTART_B_PID POST_RESTART_B_RPC_ADDR POST_RESTART_B_P2P_ADDR POST_RESTART_B_PID POST_RESTART_CATCHUP_HEIGHT POST_RESTART_CATCHUP_TIP POST_RESTART_CATCHUP_PEERS POST_RESTART_MINE_HEIGHT POST_RESTART_MINE_HASH POST_RESTART_MINE_TX_COUNT POST_RESTART_ACCEPTED_PEER INCLUSION_PROOF_NODE
python3 - <<'PY'
import json, os
e = os.environ
i = lambda key: int(e[key])
participants = [{"name": f"node-{n.lower()}", "pid": i(f"{n}_PID"), "rpc": e[f"{n}_RPC_ADDR"], "p2p": e[f"{n}_P2P_ADDR"], "checkpoint_height": i(f"{n}_HEIGHT"), "tip_hash": e[f"{n}_TIP"], "peer_count": i(f"{n}_PEERS")} for n in ("A", "B", "C")]
restart_enabled = e["WITH_RESTART"] == "1"
report = {
    "scenario": "go_binary_soak_restart" if restart_enabled else "go_binary_soak_skeleton",
    "target_height": i("TARGET_HEIGHT"),
    "base_height": i("BASE_HEIGHT"),
    "participants": participants,
    "tx": {"id": e["TX_ID"], "submission": "rpc:/submit_tx", "inclusion_proof_node": e["INCLUSION_PROOF_NODE"], "inclusion_height": i("TARGET_HEIGHT")},
    "final": {
        "height": i("POST_RESTART_MINE_HEIGHT" if restart_enabled else "TARGET_HEIGHT"),
        "tip_hash": e["POST_RESTART_MINE_HASH"] if restart_enabled else e["FINAL_HASH"],
        "tx_count": i("POST_RESTART_MINE_TX_COUNT" if restart_enabled else "TX_COUNT"),
    },
    "verdict": "PASS",
}
if restart_enabled:
    report["restart"] = {
        "enabled": True,
        "stopped_node": "node-b",
        "checkpoint_before_stop": {"height": i("PRE_RESTART_B_HEIGHT"), "tip_hash": e["PRE_RESTART_B_TIP"], "rpc": e["PRE_RESTART_B_RPC_ADDR"], "p2p": e["PRE_RESTART_B_P2P_ADDR"], "pid": i("PRE_RESTART_B_PID")},
        "state_after_catchup": {"height": i("POST_RESTART_CATCHUP_HEIGHT"), "tip_hash": e["POST_RESTART_CATCHUP_TIP"], "rpc": e["POST_RESTART_B_RPC_ADDR"], "p2p": e["POST_RESTART_B_P2P_ADDR"], "pid": i("POST_RESTART_B_PID"), "peer_count": i("POST_RESTART_CATCHUP_PEERS")},
        "post_restart_live_action": {"action": "mine_next", "height": i("POST_RESTART_MINE_HEIGHT"), "block_hash": e["POST_RESTART_MINE_HASH"], "tx_count": i("POST_RESTART_MINE_TX_COUNT"), "accepted_by_peer": e["POST_RESTART_ACCEPTED_PEER"]},
    }
else:
    report["restart"] = {"enabled": False}
with open(e["REPORT_JSON"], "w", encoding="utf-8") as f:
    json.dump(report, f, indent=2, sort_keys=True)
    f.write("\n")
PY
if (( WITH_RESTART == 1 )); then
  PASS_SUMMARY="PASS: Go binary soak mined tx at height ${TARGET_HEIGHT} and post-restart block at height ${POST_RESTART_MINE_HEIGHT} (tx=${TX_ID}, restart=1)"
else
  PASS_SUMMARY="PASS: Go binary soak reached height ${TARGET_HEIGHT} with tx ${TX_ID} (restart=0)"
fi
if [[ "${RUBIN_PROCESS_KEEP_ARTIFACTS}" == "1" ]]; then
  echo "${PASS_SUMMARY}; report=${REPORT_JSON}"
else
  echo "${PASS_SUMMARY}; set KEEP_TMP=1 to retain report"
fi
