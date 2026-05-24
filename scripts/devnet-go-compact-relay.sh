#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEV_ENV="${REPO_ROOT}/scripts/dev-env.sh"
GO_MODULE_ROOT="${REPO_ROOT}/clients/go"
HELPER="${REPO_ROOT}/scripts/devnet-process-common.sh"
: "${KEEP_TMP:=1}"
: "${COMPACT_RELAY_IO_TIMEOUT_SECONDS:=5}"
export KEEP_TMP
for tool in python3 perl lsof; do
  command -v "${tool}" >/dev/null 2>&1 || { echo "${tool} is required for Go compact relay devnet evidence" >&2; exit 1; }
done
# shellcheck source=scripts/devnet-process-common.sh disable=SC1091
source "${HELPER}"
COMPACT_RELAY_IO_TIMEOUT_SECONDS="$(_rubin_process_uint_decimal COMPACT_RELAY_IO_TIMEOUT_SECONDS "${COMPACT_RELAY_IO_TIMEOUT_SECONDS}")"
rubin_process_init go-compact-relay
NODE_BIN="${RUBIN_PROCESS_ARTIFACT_ROOT}/rubin-node-go"
PROXY_PY="${RUBIN_PROCESS_ARTIFACT_ROOT}/capture_proxy.py"
PROXY_READY="${RUBIN_PROCESS_ARTIFACT_ROOT}/proxy.ready"
PROXY_EVENTS="${RUBIN_PROCESS_ARTIFACT_ROOT}/sendcmpct-events.jsonl"
COMPACT_TEST_JSONL="${RUBIN_PROCESS_ARTIFACT_ROOT}/compact-path-go-test.jsonl"
COMPACT_EVIDENCE_JSON="${RUBIN_PROCESS_ARTIFACT_ROOT}/compact-path-evidence.json"
REPORT_JSON="${RUBIN_PROCESS_ARTIFACT_ROOT}/go-compact-relay-report.json"
A_DIR="${RUBIN_PROCESS_ARTIFACT_ROOT}/node-a"
B_DIR="${RUBIN_PROCESS_ARTIFACT_ROOT}/node-b"
A_LOG="node-a.log"
B_LOG="node-b.log"
PROXY_LOG="proxy.log"
wait_peers_ready() {
  local label="$1" addr="$2" deadline=$((SECONDS + 30)) count="0"
  while (( SECONDS < deadline )); do
    if count="$(python3 - "${addr}" "${COMPACT_RELAY_IO_TIMEOUT_SECONDS}" <<'PY' 2>/dev/null
import json, sys, urllib.request
with urllib.request.urlopen(f"http://{sys.argv[1]}/peers", timeout=int(sys.argv[2])) as resp:
    data = json.load(resp)
print(sum(1 for p in (data.get("peers") or []) if p.get("handshake_complete") is True))
PY
    )" && [[ "${count}" =~ ^[0-9]+$ && "${count}" -ge 1 ]]; then
      printf '%s\n' "${count}"
      return 0
    fi
    sleep 1
  done
  echo "timeout waiting for ${label} handshake peers addr=${addr} actual=${count}" >&2
  return 1
}
p2p_addr_for_pid() {
  python3 - "$1" "$2" <<'PY'
import re, subprocess, sys, time
pid, rpc_addr = sys.argv[1:3]
deadline = time.time() + 30
while time.time() < deadline:
    proc = subprocess.run(["lsof", "-nP", "-a", "-p", pid, "-iTCP", "-sTCP:LISTEN", "-Fn"], text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False)
    addrs = sorted({line[1:].strip() for line in proc.stdout.splitlines() if line.startswith("n") and line[1:].strip() != rpc_addr and re.fullmatch(r"127\.0\.0\.1:[0-9]+", line[1:].strip())})
    if len(addrs) == 1:
        print(addrs[0])
        sys.exit(0)
    if len(addrs) > 1:
        raise SystemExit(f"ambiguous p2p listen addresses for pid={pid}: {addrs}")
    time.sleep(1)
raise SystemExit(f"timeout resolving p2p listen address for pid={pid}")
PY
}
write_proxy() {
  cat >"${PROXY_PY}" <<'PY'
import json, socket, struct, sys, threading, time
target, ready_path, events_path, io_timeout = sys.argv[1:5]
target_host, target_port = target.rsplit(":", 1)
magic = None
lock = threading.Lock()
def recv_exact(sock, size):
    chunks = []
    got = 0
    while got < size:
        chunk = sock.recv(size - got)
        if not chunk:
            raise EOFError
        chunks.append(chunk)
        got += len(chunk)
    return b"".join(chunks)
def record(direction, command, payload):
    if command != "sendcmpct":
        return
    event = {"direction": direction, "command": command, "size": len(payload)}
    if len(payload) == 9:
        event["mode"] = payload[0]
        event["version"] = int.from_bytes(payload[1:9], "little")
    with lock, open(events_path, "a", encoding="utf-8") as out:
        out.write(json.dumps(event, sort_keys=True) + "\n")
def pump(direction, src, dst):
    global magic
    try:
        while True:
            header = recv_exact(src, 24)
            with lock:
                if magic is None:
                    magic = header[:4]
                elif header[:4] != magic:
                    raise SystemExit(f"{direction}: bad magic")
            command = header[4:16].rstrip(b"\x00").decode("ascii", "strict")
            size = struct.unpack("<I", header[16:20])[0]
            payload = recv_exact(src, size) if size else b""
            record(direction, command, payload)
            dst.sendall(header + payload)
    except (EOFError, OSError):
        try:
            dst.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        dst.close()
with socket.create_server(("127.0.0.1", 0)) as listener:
    addr = listener.getsockname()
    with open(ready_path, "w", encoding="utf-8") as ready:
        ready.write(f"{addr[0]}:{addr[1]}\n")
    print(f"proxy: listening={addr[0]}:{addr[1]}", flush=True)
    client, _ = listener.accept()
    with client, socket.create_connection((target_host, int(target_port)), timeout=int(io_timeout)) as server:
        server.settimeout(None)
        threads = [
            threading.Thread(target=pump, args=("a_to_b", client, server), daemon=True),
            threading.Thread(target=pump, args=("b_to_a", server, client), daemon=True),
        ]
        for thread in threads:
            thread.start()
        while any(thread.is_alive() for thread in threads):
            time.sleep(0.1)
PY
}
start_node() {
  local label="$1" log_file="$2" datadir="$3" peers="${4:-}"
  if [[ -z "${peers}" ]]; then
    rubin_process_start "${log_file}" "${NODE_BIN}" --datadir "${datadir}" --bind 127.0.0.1:0 --rpc-bind 127.0.0.1:0 \
      || { printf 'failed to start %s log_file=%s\n' "${label}" "${log_file}" >&2; return 1; }
  else
    rubin_process_start "${log_file}" "${NODE_BIN}" --datadir "${datadir}" --bind 127.0.0.1:0 --rpc-bind 127.0.0.1:0 --peers "${peers}" \
      || { printf 'failed to start %s log_file=%s\n' "${label}" "${log_file}" >&2; return 1; }
  fi
  STARTED_PID="${RUBIN_PROCESS_LAST_PID}"
  rubin_process_wait_for_log "${log_file}" "rpc: listening=" 30 "${STARTED_PID}" \
    || { printf 'failed waiting for %s rpc listen log_file=%s pid=%s\n' "${label}" "${log_file}" "${STARTED_PID}" >&2; return 1; }
  STARTED_RPC="$(rubin_process_extract_rpc_addr "${log_file}")"
  STARTED_P2P="$(p2p_addr_for_pid "${STARTED_PID}" "${STARTED_RPC}")" \
    || { printf 'failed resolving %s p2p address pid=%s rpc=%s\n' "${label}" "${STARTED_PID}" "${STARTED_RPC}" >&2; return 1; }
  rubin_process_wait_for_rpc_ready "${STARTED_RPC}" 30 \
    || { printf 'failed waiting for %s rpc ready addr=%s\n' "${label}" "${STARTED_RPC}" >&2; return 1; }
}
wait_sendcmpct_exchange() {
  local deadline=$((SECONDS + 30))
  while (( SECONDS < deadline )); do
    if [[ -s "${PROXY_EVENTS}" ]] && python3 - "${PROXY_EVENTS}" <<'PY'
import json, sys
seen = {}
with open(sys.argv[1], encoding="utf-8") as fh:
    for line in fh:
        event = json.loads(line)
        if event.get("command") == "sendcmpct" and event.get("mode") == 0 and event.get("version") == 1:
            seen[event.get("direction")] = event
missing = {"a_to_b", "b_to_a"} - set(seen)
if missing:
    raise SystemExit("missing sendcmpct directions: " + ",".join(sorted(missing)))
PY
    then
      return 0
    fi
    sleep 1
  done
  echo "timeout waiting for bidirectional sendcmpct events in ${PROXY_EVENTS}" >&2
  return 1
}
run_fips_preflight_before_captured_dev_env() {
  if [[ "${RUBIN_OPENSSL_FIPS_MODE:-off}" != "only" || "${RUBIN_OPENSSL_SKIP_FIPS_GUARD:-0}" == "1" ]]; then
    return 0
  fi
  echo "Running FIPS-only preflight before captured dev-env command streams" >&2
  "${DEV_ENV}" -- "${REPO_ROOT}/scripts/crypto/openssl/fips-preflight.sh" >&2
}
run_compact_path_evidence() {
  local test_name="TestCompactProcessEvidenceSummaryMarkers"
  local -a compact_test_cmd=(/usr/bin/env RUBIN_OPENSSL_SKIP_FIPS_GUARD=1 "${DEV_ENV}" -- go -C "${GO_MODULE_ROOT}" test ./node/p2p -run "^${test_name}$" -count=1 -json)
  run_fips_preflight_before_captured_dev_env
  "${compact_test_cmd[@]}" >"${COMPACT_TEST_JSONL}" || {
    echo "compact path evidence test failed; jsonl=${COMPACT_TEST_JSONL}" >&2
    return 1
  }
  export COMPACT_EVIDENCE_JSON COMPACT_TEST_JSONL DEV_ENV GO_MODULE_ROOT
  python3 - "${test_name}" <<'PY'
import json, os, sys
test_name = sys.argv[1]
jsonl_path = os.environ["COMPACT_TEST_JSONL"]
test_passed = False
package_passed = False
with open(jsonl_path, encoding="utf-8") as fh:
    for line_no, line in enumerate(fh, 1):
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError as exc:
            raise SystemExit(f"malformed compact evidence JSONL at line {line_no}: {exc}") from None
        if event.get("Test") == test_name and event.get("Action") == "pass":
            test_passed = True
        if event.get("Package", "").endswith("/clients/go/node/p2p") and event.get("Action") == "pass" and "Test" not in event:
            package_passed = True
if not test_passed or not package_passed:
    raise SystemExit(f"missing compact evidence PASS test_passed={test_passed} package_passed={package_passed}")
evidence = {
    "compact_attempted": True,
    "compact_reconstructed": True,
    "fallback_used": False,
    "disabled_receive_rejected": True,
    "evidence_scope": "go_test_wrapper_not_live_devnet",
    "source": {
        "kind": "go_test_wrapper",
        "package": "./node/p2p",
        "test": test_name,
        "jsonl": jsonl_path,
        "argv": [
            "/usr/bin/env",
            "RUBIN_OPENSSL_SKIP_FIPS_GUARD=1",
            os.environ["DEV_ENV"],
            "--",
            "go",
            "-C",
            os.environ["GO_MODULE_ROOT"],
            "test",
            "./node/p2p",
            "-run",
            f"^{test_name}$",
            "-count=1",
            "-json",
        ],
    },
}
with open(os.environ["COMPACT_EVIDENCE_JSON"], "w", encoding="utf-8") as out:
    json.dump(evidence, out, indent=2, sort_keys=True)
    out.write("\n")
PY
}
write_report() {
  export REPORT_JSON RUBIN_PROCESS_ARTIFACT_ROOT NODE_BIN A_PID B_PID A_RPC_ADDR B_RPC_ADDR A_P2P_ADDR B_P2P_ADDR PROXY_ADDR PROXY_EVENTS COMPACT_EVIDENCE_JSON A_PEERS B_PEERS A_LOG B_LOG
  python3 - <<'PY'
import json, os
def load_json(path, label):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except OSError as exc:
        raise SystemExit(f"read {label}: {exc}") from None
    except json.JSONDecodeError as exc:
        raise SystemExit(f"malformed {label}: {exc}") from None
def load_jsonl(path, label):
    events = []
    try:
        with open(path, encoding="utf-8") as fh:
            for line_no, line in enumerate(fh, 1):
                if not line.strip():
                    continue
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError as exc:
                    raise SystemExit(f"malformed {label} at line {line_no}: {exc}") from None
    except OSError as exc:
        raise SystemExit(f"read {label}: {exc}") from None
    return events
events = load_jsonl(os.environ["PROXY_EVENTS"], "sendcmpct JSONL")
compact_evidence = load_json(os.environ["COMPACT_EVIDENCE_JSON"], "compact evidence JSON")
for key, want in (("compact_attempted", True), ("compact_reconstructed", True), ("fallback_used", False)):
    if compact_evidence.get(key) is not want:
        raise SystemExit(f"compact evidence {key}={compact_evidence.get(key)!r}, want {want!r}")
root, node_bin = os.environ["RUBIN_PROCESS_ARTIFACT_ROOT"], os.environ["NODE_BIN"]
report = {
    "scenario": "go_two_node_compact_sendcmpct_process",
    "verdict": "PASS",
    "go_test_compact_evidence": compact_evidence,
    "participants": [
        {k: v for k, v in (("name", "node-a"), ("implementation", "go"), ("pid", int(os.environ["A_PID"])), ("binary", node_bin), ("rpc", os.environ["A_RPC_ADDR"]), ("p2p", os.environ["A_P2P_ADDR"]), ("log", os.path.join(root, os.environ["A_LOG"])), ("handshake_peers", int(os.environ["A_PEERS"])))},
        {k: v for k, v in (("name", "node-b"), ("implementation", "go"), ("pid", int(os.environ["B_PID"])), ("binary", node_bin), ("rpc", os.environ["B_RPC_ADDR"]), ("p2p", os.environ["B_P2P_ADDR"]), ("log", os.path.join(root, os.environ["B_LOG"])), ("handshake_peers", int(os.environ["B_PEERS"])))},
    ],
    "proxy": {"addr": os.environ["PROXY_ADDR"], "target": os.environ["B_P2P_ADDR"]},
    "sendcmpct": [{"direction": e["direction"], "mode": e["mode"], "version": e["version"], "size": e["size"]} for e in events],
    "out_of_scope": ["live_devnet_cmpctblock_reconstruction", "production_compact_receive_enablement", "full_block_regression_closeout", "da_relay", "rust", "final_devnet_readiness"],
}
dirs = {e["direction"] for e in events if e.get("command") == "sendcmpct" and e.get("mode") == 0 and e.get("version") == 1}
if dirs != {"a_to_b", "b_to_a"}:
    raise SystemExit(f"missing bidirectional sendcmpct evidence: {sorted(dirs)}")
with open(os.environ["REPORT_JSON"], "w", encoding="utf-8") as out:
    json.dump(report, out, indent=2, sort_keys=True)
    out.write("\n")
PY
}
echo "Building Go rubin-node"
"${DEV_ENV}" -- go -C "${GO_MODULE_ROOT}" build -o "${NODE_BIN}" ./cmd/rubin-node
write_proxy
mkdir -p "${A_DIR}" "${B_DIR}"
start_node node-b "${B_LOG}" "${B_DIR}"
B_PID="${STARTED_PID}"
B_RPC_ADDR="${STARTED_RPC}"
B_P2P_ADDR="${STARTED_P2P}"
rubin_process_start "${PROXY_LOG}" python3 -u "${PROXY_PY}" "${B_P2P_ADDR}" "${PROXY_READY}" "${PROXY_EVENTS}" "${COMPACT_RELAY_IO_TIMEOUT_SECONDS}"
PROXY_PID="${RUBIN_PROCESS_LAST_PID}"
rubin_process_wait_for_log "${PROXY_LOG}" "proxy: listening=" 30 "${PROXY_PID}"
PROXY_ADDR="$(tr -d '[:space:]' <"${PROXY_READY}")"
start_node node-a "${A_LOG}" "${A_DIR}" "${PROXY_ADDR}"
A_PID="${STARTED_PID}"
A_RPC_ADDR="${STARTED_RPC}"
A_P2P_ADDR="${STARTED_P2P}"
A_PEERS="$(wait_peers_ready node-a "${A_RPC_ADDR}")"
B_PEERS="$(wait_peers_ready node-b "${B_RPC_ADDR}")"
wait_sendcmpct_exchange
run_compact_path_evidence
write_report
echo "PASS: Go compact relay sendcmpct observed; cmpctblock path verified by Go test wrapper; report=${REPORT_JSON}"
