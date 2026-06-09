#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEV_ENV="${REPO_ROOT}/scripts/dev-env.sh"
RUST_ROOT="${REPO_ROOT}/clients/rust"
HELPER="${REPO_ROOT}/scripts/devnet-process-common.sh"
unset REPORT_JSON
: "${KEEP_TMP:=1}"
: "${COMPACT_RELAY_IO_TIMEOUT_SECONDS:=5}"
usage() { echo "usage: $0" >&2; }
while (($#)); do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    *) usage; exit 2 ;;
  esac
done
# Rust compact relay process smoke (RUB-408 bring-up, RUB-441 PASS conversion).
# Mirror of the Go compact relay smoke (scripts/devnet-go-compact-relay.sh):
# bring up two Rust devnet nodes with a transparent Python capture proxy between
# them, prove a real two-node handshake, observe the bidirectional sendcmpct
# capability advertisement (mode=0, version=1) on the wire (RUB-441 adds the
# Rust node's sendcmpct advertisement, mirroring Go advertiseLocalCompactMode),
# exercise the live block announce -> receive/apply -> tip convergence path, and
# evidence the cmpctblock reconstruct/apply path with a Rust test wrapper. Like
# the Go smoke, live cmpctblock reconstruction and production compact-receive
# enablement are out of scope; the announce path stays on the full-block path.
emit_report() {
  local verdict="$1" reason="${2:-}"
  if [[ -n "${REPORT_JSON:-}" ]]; then
    python3 - "${REPORT_JSON}" "${verdict}" "${reason}" "${RUBIN_PROCESS_ARTIFACT_ROOT:-}" "${NODE_BIN:-}" "${A_PID:-}" "${A_RPC:-}" "${A_P2P:-}" "${A_PEERS:-}" "${B_PID:-}" "${B_RPC:-}" "${B_P2P:-}" "${B_PEERS:-}" <<'PY'
import json, sys
path, verdict, reason, root, binary, a_pid, a_rpc, a_p2p, a_peers, b_pid, b_rpc, b_p2p, b_peers = sys.argv[1:14]
data = {"scenario": "rust_two_node_compact_sendcmpct_process", "verdict": verdict}
if reason: data["failure_reason"] = reason
if root: data["artifact_root"] = root
participants = []
for name, pid, rpc, p2p, peers in (("node-a", a_pid, a_rpc, a_p2p, a_peers), ("node-b", b_pid, b_rpc, b_p2p, b_peers)):
    if pid:
        item = {"name": name, "implementation": "rust", "pid": int(pid), "binary": binary, "rpc": rpc or None, "p2p": p2p or None, "log": f"{root}/{name}.log" if root else None}
        if peers: item["handshake_peers"] = int(peers)
        participants.append(item)
if participants: data["participants"] = participants
with open(path, "w", encoding="utf-8") as f:
    json.dump(data, f, indent=2, sort_keys=True); f.write("\n")
PY
    echo "${verdict}: reason=${reason}; report=${REPORT_JSON}" >&2
  else
    echo "${verdict}: reason=${reason}" >&2
  fi
}
emit_no_data() { emit_report NO_DATA "$1"; exit 1; }
emit_fail() { emit_report FAIL "$1"; exit 1; }

for tool in python3 perl git; do
  command -v "${tool}" >/dev/null 2>&1 || { echo "${tool} is required for Rust compact relay devnet evidence" >&2; exit 1; }
done
[[ -x "${DEV_ENV}" ]] || { echo "dev-env wrapper missing or non-executable: ${DEV_ENV}" >&2; exit 1; }
# shellcheck source=scripts/devnet-process-common.sh disable=SC1091
source "${HELPER}"
COMPACT_RELAY_IO_TIMEOUT_SECONDS="$(_rubin_process_uint_decimal COMPACT_RELAY_IO_TIMEOUT_SECONDS "${COMPACT_RELAY_IO_TIMEOUT_SECONDS}")"
export KEEP_TMP
rubin_process_init rust-compact-relay
NODE_BIN="${RUBIN_PROCESS_ARTIFACT_ROOT}/rubin-node-rust"
PROXY_PY="${RUBIN_PROCESS_ARTIFACT_ROOT}/capture_proxy.py"
PROXY_READY="${RUBIN_PROCESS_ARTIFACT_ROOT}/proxy.ready"
PROXY_EVENTS="${RUBIN_PROCESS_ARTIFACT_ROOT}/sendcmpct-events.jsonl"
COMPACT_TEST_LOG="${RUBIN_PROCESS_ARTIFACT_ROOT}/compact-path-rust-test.log"
COMPACT_EVIDENCE_JSON="${RUBIN_PROCESS_ARTIFACT_ROOT}/compact-path-evidence.json"
REPORT_JSON="${RUBIN_PROCESS_ARTIFACT_ROOT}/rust-compact-relay-report.json"
A_DIR="${RUBIN_PROCESS_ARTIFACT_ROOT}/node-a"
B_DIR="${RUBIN_PROCESS_ARTIFACT_ROOT}/node-b"
CARGO_TARGET="${RUBIN_PROCESS_ARTIFACT_ROOT}/cargo-target"
build_node() {
  local host bin
  host="$("${DEV_ENV}" -- rustc -vV | awk '/^host:/ {print $2}')"
  [[ -n "${host}" ]] || { echo "could not derive host target triple" >&2; return 1; }
  "${DEV_ENV}" -- cargo build --manifest-path "${RUST_ROOT}/Cargo.toml" \
    --release --locked -p rubin-node --target "${host}" --target-dir "${CARGO_TARGET}" \
    >/dev/null
  bin="${CARGO_TARGET}/${host}/release/rubin-node"
  cp -- "${bin}" "${NODE_BIN}"
  [[ -x "${NODE_BIN}" ]] || { echo "built Rust node is not executable: ${NODE_BIN}" >&2; return 1; }
}
# Transparent p2p capture proxy (identical framing parser to the Go compact
# smoke): forwards bytes between node-a and node-b and records sendcmpct frames
# (mode = payload[0], version = payload[1:9] LE) to a JSONL events file.
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
rpc_json() {
  local method="$1" addr="$2" path="$3" body="${4:-}"
  python3 - "${method}" "${addr}" "${path}" "${body}" "${COMPACT_RELAY_IO_TIMEOUT_SECONDS}" <<'PY'
import socket, sys, urllib.error, urllib.request
method, addr, path, body, raw_timeout = sys.argv[1:6]
timeout = int(raw_timeout)
data = body.encode() if body else None
req = urllib.request.Request(f"http://{addr}{path}", data=data, method=method)
if body:
    req.add_header("Content-Type", "application/json")
try:
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        print(resp.read().decode("utf-8"), end="")
except urllib.error.HTTPError as exc:
    print(exc.read().decode("utf-8"), end="")
    sys.exit(22)
except (urllib.error.URLError, TimeoutError, socket.timeout) as exc:
    print(f"request failed timeout={timeout}: {getattr(exc, 'reason', exc)}", end="")
    sys.exit(1)
PY
}
tip_tsv() {
  rpc_json GET "$1" /get_tip | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["height"], d["tip_hash"], sep="\t")'
}
wait_tip_exact() {
  local label="$1" addr="$2" want_height="$3" want_hash="$4" timeout="$5"
  local deadline=$((SECONDS + timeout)) height hash last_height="<none>" last_hash="<none>"
  while (( SECONDS < deadline )); do
    if IFS=$'\t' read -r height hash < <(tip_tsv "${addr}" 2>/dev/null); then
      last_height="${height}"; last_hash="${hash}"
      [[ "${height}" == "${want_height}" && "${hash}" == "${want_hash}" ]] && return 0
    fi
    sleep 1
  done
  echo "timeout waiting for ${label} tip addr=${addr} expected=${want_height}/${want_hash} actual=${last_height}/${last_hash}" >&2
  return 1
}
mine_next_tsv() {
  local addr="$1" response
  response="$(rpc_json POST "${addr}" /mine_next '{}')" || return 1
  printf '%s' "${response}" | python3 -c 'import json,sys; d=json.load(sys.stdin); sys.exit("mine_next failed: " + str(d.get("error", d))) if d.get("mined") is not True else print(d["height"], d["block_hash"], d["tx_count"], sep="\t")'
}
wait_peers_ready() {
  local label="$1" addr="$2" deadline=$((SECONDS + 30)) count="0"
  while (( SECONDS < deadline )); do
    if count="$(rpc_json GET "${addr}" /peers 2>/dev/null | python3 -c 'import json,sys; d=json.load(sys.stdin); print(sum(1 for p in (d.get("peers") or []) if p.get("handshake_complete") is True))')" &&
      [[ "${count}" =~ ^[0-9]+$ && "${count}" -ge 1 ]]; then
      printf '%s\n' "${count}"
      return 0
    fi
    sleep 1
  done
  echo "timeout waiting for ${label} handshake peers addr=${addr} actual=${count}" >&2
  return 1
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
# Compact reconstruct/apply evidence via a Rust test wrapper (mirror of the Go
# smoke's TestCompactProcessEvidenceSummaryMarkers wrapper; the live cmpctblock
# reconstruction path is unit-tested, not driven over the devnet wire).
run_compact_path_evidence() {
  local -a tests=(
    compact_reconstruct_go_parity_matrix
    getblocktxn_serves_announced_block_in_request_order
    getblocktxn_rejects_disabled_duplicate_and_unannounced
  )
  local -a filters=() name
  for name in "${tests[@]}"; do filters+=("p2p_runtime::tests::${name}"); done
  if ! "${DEV_ENV}" -- cargo test --manifest-path "${RUST_ROOT}/Cargo.toml" -p rubin-node --lib \
      --target-dir "${CARGO_TARGET}" -- --exact "${filters[@]}" >"${COMPACT_TEST_LOG}" 2>&1; then
    echo "compact path evidence test failed; log=${COMPACT_TEST_LOG}" >&2
    return 1
  fi
  COMPACT_EVIDENCE_JSON="${COMPACT_EVIDENCE_JSON}" COMPACT_TEST_LOG="${COMPACT_TEST_LOG}" \
    EXPECTED_TESTS="${#tests[@]}" TEST_NAMES="${tests[*]}" python3 <<'PY'
import json, os, re
log_path = os.environ["COMPACT_TEST_LOG"]
expected = int(os.environ["EXPECTED_TESTS"])
names = os.environ["TEST_NAMES"].split()
text = open(log_path, encoding="utf-8").read()
m = re.search(r"test result: ok\. (\d+) passed; (\d+) failed", text)
if not m:
    raise SystemExit("no passing test-result summary in compact evidence log")
passed, failed = int(m.group(1)), int(m.group(2))
if failed != 0 or passed < expected:
    raise SystemExit(f"compact evidence wrapper: passed={passed} failed={failed} expected>={expected}")
for name in names:
    if f"test p2p_runtime::tests::{name} ... ok" not in text:
        raise SystemExit(f"compact evidence missing PASS marker for {name}")
evidence = {
    "compact_attempted": True,
    "compact_reconstructed": True,
    "fallback_used": False,
    "disabled_receive_rejected": True,
    "evidence_scope": "rust_test_wrapper_not_live_devnet",
    "source": {"kind": "rust_test_wrapper", "package": "rubin-node", "tests": names, "log": log_path},
}
with open(os.environ["COMPACT_EVIDENCE_JSON"], "w", encoding="utf-8") as out:
    json.dump(evidence, out, indent=2, sort_keys=True)
    out.write("\n")
PY
}
start_node() {
  local label="$1" log="$2" datadir="$3" peers="${4:-}"
  local cmd=("${NODE_BIN}" --network devnet --datadir "${datadir}" --bind 127.0.0.1:0 --rpc-bind 127.0.0.1:0)
  STARTED_PID=""; STARTED_RPC=""; STARTED_P2P=""
  [[ -z "${peers}" ]] || cmd+=(--peers "${peers}")
  rubin_process_start "${log}" "${cmd[@]}" || { echo "failed to start ${label}" >&2; return 1; }
  STARTED_PID="${RUBIN_PROCESS_LAST_PID}"
  rubin_process_wait_for_log "${log}" "rpc: listening=" 60 "${STARTED_PID}" || return 1
  STARTED_RPC="$(rubin_process_extract_rpc_addr "${log}")" || return 1
  _rubin_process_loopback_endpoint "${STARTED_RPC}" || { echo "failed resolving ${label} rpc address" >&2; return 1; }
  rubin_process_wait_for_log "${log}" "p2p: listening=" 60 "${STARTED_PID}" || return 1
  STARTED_P2P="$(sed -n 's/.*p2p: listening=//p' "$(_rubin_process_resolve_log "${log}")" | tail -n 1 | tr -d '[:space:]')" || return 1
  _rubin_process_loopback_endpoint "${STARTED_P2P}" || { echo "failed resolving ${label} p2p address" >&2; return 1; }
  rubin_process_wait_for_rpc_ready "${STARTED_RPC}" 30 || return 1
}
write_pass_report() {
  export REPORT_JSON RUBIN_PROCESS_ARTIFACT_ROOT NODE_BIN A_DIR B_DIR A_PID B_PID A_RPC B_RPC A_P2P B_P2P A_PEERS B_PEERS \
    PROXY_ADDR PROXY_EVENTS COMPACT_EVIDENCE_JSON \
    BASE_HEIGHT BASE_HASH RELAY_HEIGHT RELAY_HASH RELAY_TX_COUNT \
    A_FINAL_HEIGHT A_FINAL_HASH B_FINAL_HEIGHT B_FINAL_HASH \
    SOURCE_COMMIT SOURCE_BRANCH SOURCE_REMOTE SCRIPT_PATH CLEANUP_STOPPED
  python3 - <<'PY'
import json, os
e = os.environ
i = lambda key: int(e[key])
def load_json(path, label):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"{label}: {exc}") from None
def load_jsonl(path, label):
    events = []
    with open(path, encoding="utf-8") as fh:
        for line_no, line in enumerate(fh, 1):
            if not line.strip():
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise SystemExit(f"malformed {label} at line {line_no}: {exc}") from None
    return events
sendcmpct = load_jsonl(e["PROXY_EVENTS"], "sendcmpct JSONL")
compact_evidence = load_json(e["COMPACT_EVIDENCE_JSON"], "compact evidence JSON")
report = {
    "scenario": "rust_two_node_compact_sendcmpct_process",
    "verdict": "PASS",
    "source": {
        "repo": e["SOURCE_REMOTE"],
        "branch": e["SOURCE_BRANCH"],
        "commit_sha": e["SOURCE_COMMIT"],
        "script": e["SCRIPT_PATH"],
        "artifact_root": e["RUBIN_PROCESS_ARTIFACT_ROOT"],
        "node_version": {"binary": e["NODE_BIN"], "source_commit": e["SOURCE_COMMIT"]},
    },
    "participants": [
        {"name": "node-a", "implementation": "rust", "pid": i("A_PID"), "binary": e["NODE_BIN"], "rpc": e["A_RPC"], "p2p": e["A_P2P"], "datadir": e["A_DIR"], "handshake_peers": i("A_PEERS")},
        {"name": "node-b", "implementation": "rust", "pid": i("B_PID"), "binary": e["NODE_BIN"], "rpc": e["B_RPC"], "p2p": e["B_P2P"], "datadir": e["B_DIR"], "handshake_peers": i("B_PEERS")},
    ],
    "proxy": {"addr": e["PROXY_ADDR"], "target": e["B_P2P"]},
    "compact_evidence": {
        "handshake": {"node_a_peers": i("A_PEERS"), "node_b_peers": i("B_PEERS")},
        "compact_capability_advertisement": {
            "transport": "captured on the wire by the proxy between node-a and node-b",
            "sendcmpct": [{"direction": s.get("direction"), "mode": s.get("mode"), "version": s.get("version"), "size": s.get("size")} for s in sendcmpct],
        },
        "announcement_receive_apply": {
            "live_block_relay": {"mined_by": "node-a", "height": i("RELAY_HEIGHT"), "block_hash": e["RELAY_HASH"], "tx_count": i("RELAY_TX_COUNT"), "applied_by": "node-b", "path": "full-block announce (compact mode 0); INV -> getdata -> block -> apply"},
            "cmpctblock_reconstruct_apply": compact_evidence,
        },
        "tip_convergence": {"node_a": {"height": i("A_FINAL_HEIGHT"), "tip_hash": e["A_FINAL_HASH"]}, "node_b": {"height": i("B_FINAL_HEIGHT"), "tip_hash": e["B_FINAL_HASH"]}},
    },
    "cleanup": {"nodes_stopped": e["CLEANUP_STOPPED"] == "true", "artifact_root_policy": "KEEP_TMP honored by rubin_process_cleanup"},
    "out_of_scope": ["live_devnet_cmpctblock_reconstruction", "production_compact_receive_enablement", "compact_block_announcement_send_path", "da_relay", "go", "final_devnet_readiness"],
}
if report["participants"][0]["datadir"] == report["participants"][1]["datadir"] or report["participants"][0]["pid"] == report["participants"][1]["pid"]:
    raise SystemExit("participants are not distinct")
dirs = {s["direction"] for s in sendcmpct if s.get("command") == "sendcmpct" and s.get("mode") == 0 and s.get("version") == 1}
if dirs != {"a_to_b", "b_to_a"}:
    raise SystemExit(f"missing bidirectional sendcmpct evidence: {sorted(dirs)}")
for key, want in (("compact_attempted", True), ("compact_reconstructed", True), ("fallback_used", False), ("disabled_receive_rejected", True)):
    if compact_evidence.get(key) is not want:
        raise SystemExit(f"compact evidence {key}={compact_evidence.get(key)!r}, want {want!r}")
tips = report["compact_evidence"]["tip_convergence"]
if tips["node_a"] != tips["node_b"]:
    raise SystemExit("tip convergence proof missing")
if tips["node_a"]["tip_hash"] != e["RELAY_HASH"]:
    raise SystemExit("converged tip is not the relayed block")
if not report["cleanup"]["nodes_stopped"]:
    raise SystemExit("cleanup proof missing")
with open(e["REPORT_JSON"], "w", encoding="utf-8") as fh:
    json.dump(report, fh, indent=2, sort_keys=True)
    fh.write("\n")
PY
}
SOURCE_COMMIT="$(git -C "${REPO_ROOT}" rev-parse HEAD)"
SOURCE_BRANCH="$(git -C "${REPO_ROOT}" rev-parse --abbrev-ref HEAD)"
SOURCE_REMOTE="$(git -C "${REPO_ROOT}" remote get-url origin 2>/dev/null || echo rubin-protocol)"
SCRIPT_PATH="scripts/devnet-rust-compact-relay.sh"
echo "Building Rust rubin-node"
build_node || emit_no_data node_build_failed
write_proxy
mkdir -p "${A_DIR}" "${B_DIR}" || emit_no_data artifact_setup_failed
if ! start_node node-b node-b.log "${B_DIR}"; then
  B_PID="${STARTED_PID:-}"; B_RPC="${STARTED_RPC:-}"; B_P2P="${STARTED_P2P:-}"
  emit_no_data node_b_start_failed
fi
B_PID="${STARTED_PID}"; B_RPC="${STARTED_RPC}"; B_P2P="${STARTED_P2P}"
rubin_process_start proxy.log python3 -u "${PROXY_PY}" "${B_P2P}" "${PROXY_READY}" "${PROXY_EVENTS}" "${COMPACT_RELAY_IO_TIMEOUT_SECONDS}" || emit_no_data proxy_start_failed
PROXY_PID="${RUBIN_PROCESS_LAST_PID}"
rubin_process_wait_for_log proxy.log "proxy: listening=" 30 "${PROXY_PID}" || emit_no_data proxy_listen_missing
PROXY_ADDR="$(tr -d '[:space:]' <"${PROXY_READY}")"
if ! start_node node-a node-a.log "${A_DIR}" "${PROXY_ADDR}"; then
  A_PID="${STARTED_PID:-}"; A_RPC="${STARTED_RPC:-}"; A_P2P="${STARTED_P2P:-}"
  emit_no_data node_a_start_failed
fi
A_PID="${STARTED_PID}"; A_RPC="${STARTED_RPC}"; A_P2P="${STARTED_P2P}"
A_PEERS="$(wait_peers_ready node-a "${A_RPC}")" || emit_no_data node_a_handshake_missing
B_PEERS="$(wait_peers_ready node-b "${B_RPC}")" || emit_no_data node_b_handshake_missing
echo "Phase 1: bidirectional sendcmpct capability advertisement (mode=0, version=1)"
wait_sendcmpct_exchange || emit_fail sendcmpct_exchange_missing
echo "Phase 2: live block announce -> receive/apply -> tip convergence"
IFS=$'\t' read -r BASE_HEIGHT BASE_HASH < <(tip_tsv "${A_RPC}") || emit_fail node_a_base_tip_unavailable
IFS=$'\t' read -r RELAY_HEIGHT RELAY_HASH RELAY_TX_COUNT < <(mine_next_tsv "${A_RPC}") || emit_fail block_mine_failed
wait_tip_exact node-b "${B_RPC}" "${RELAY_HEIGHT}" "${RELAY_HASH}" 60 || emit_fail block_relay_apply_missing
echo "Phase 3: compact reconstruct/apply evidence (Rust test wrapper)"
run_compact_path_evidence || emit_fail compact_path_evidence_failed
echo "Phase 4: final tip convergence"
IFS=$'\t' read -r A_FINAL_HEIGHT A_FINAL_HASH < <(tip_tsv "${A_RPC}") || emit_fail node_a_final_tip_unavailable
IFS=$'\t' read -r B_FINAL_HEIGHT B_FINAL_HASH < <(tip_tsv "${B_RPC}") || emit_fail node_b_final_tip_unavailable
[[ "${A_FINAL_HEIGHT}" == "${B_FINAL_HEIGHT}" && "${A_FINAL_HASH}" == "${B_FINAL_HASH}" && "${A_FINAL_HASH}" == "${RELAY_HASH}" ]] || emit_fail final_convergence_mismatch
echo "Phase 5: cleanup (stop nodes + proxy before writing the PASS report)"
CLEANUP_STOPPED=false
if rubin_process_stop_all && ! rubin_process_is_alive "${A_PID}" && ! rubin_process_is_alive "${B_PID}" && ! rubin_process_is_alive "${PROXY_PID}"; then
  CLEANUP_STOPPED=true
fi
[[ "${CLEANUP_STOPPED}" == "true" ]] || emit_fail node_cleanup_incomplete
write_pass_report || emit_fail pass_report_write_failed
echo "PASS: Rust compact relay process smoke completed; report=${REPORT_JSON}"
