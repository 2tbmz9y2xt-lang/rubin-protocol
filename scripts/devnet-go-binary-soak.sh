#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEV_ENV="${REPO_ROOT}/scripts/dev-env.sh"
GO_MODULE_ROOT="${REPO_ROOT}/clients/go"
HELPER="${REPO_ROOT}/scripts/devnet-process-common.sh"
TARGET_HEIGHT=120
WITH_RESTART=0

usage() { echo "usage: $0 [--target-height N] [--with-restart]" >&2; }
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
# Runtime txgen needs base height >=100; bound height to keep the soak finite.
TARGET_HEIGHT="$(python3 -c 'import sys; s=sys.argv[1]; n=int(s) if s.isdecimal() else -1; 101 <= n <= 10000 or sys.exit(2); print(n)' "${TARGET_HEIGHT}")" || { echo "--target-height must be an integer in [101, 10000]" >&2; exit 2; }
# shellcheck source=scripts/devnet-process-common.sh disable=SC1091
source "${HELPER}"
rubin_process_init go-binary-soak
NODE_BIN="${RUBIN_PROCESS_ARTIFACT_ROOT}/rubin-node-go"
TXGEN_BIN="${RUBIN_PROCESS_ARTIFACT_ROOT}/rubin-txgen"
KEYGEN_GO="${RUBIN_PROCESS_ARTIFACT_ROOT}/keygen.go"
KEYGEN_JSON="${RUBIN_PROCESS_ARTIFACT_ROOT}/keygen.json"
TCP_PROXY_PY="${RUBIN_PROCESS_ARTIFACT_ROOT}/tcp_proxy.py"
REPORT_JSON="${RUBIN_PROCESS_ARTIFACT_ROOT}/go-binary-soak-report.json"
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
PRE_RESTART_B_HEIGHT=""
PRE_RESTART_B_TIP=""
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
  printf '%s' "${block_json}" | python3 -c 'import json,sys; d=json.load(sys.stdin); expected=sys.argv[1].lower(); actual=(d.get("hash") or d.get("block_hash") or "").lower(); actual == expected or sys.exit(1); d.get("canonical") is True or sys.exit(2)' "${expected_hash}"
}
write_tcp_proxy() {
  cat >"${TCP_PROXY_PY}" <<'PY'
import socket, sys, threading
target_file = sys.argv[1]; listener = socket.socket(); listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); listener.bind(("127.0.0.1", 0)); listener.listen()
print(f"proxy: listening={listener.getsockname()[0]}:{listener.getsockname()[1]}", flush=True)
def pump(src, dst):
    try:
        while data := src.recv(65536):
            dst.sendall(data)
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
    except Exception:
        client.close(); continue
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
  rubin_process_wait_for_log "${log_file}" "proxy: listening=" 30 "${PROXY_PID}"
  PROXY_ADDR="$(sed -n 's/.*proxy: listening=//p' "${RUBIN_PROCESS_ARTIFACT_ROOT}/${log_file}" | tail -n 1 | tr -d '[:space:]')"
  [[ -n "${PROXY_ADDR}" ]] || { echo "missing proxy listening banner in ${log_file}" >&2; return 1; }
  [[ "${PROXY_ADDR}" == 127.0.0.1:* ]] || { echo "proxy must listen on 127.0.0.1, got ${PROXY_ADDR}" >&2; return 1; }
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
start_node_ready() {
  local label="$1" log_file="$2" datadir="$3" peers="${4:-}" args
  args=(--datadir "${datadir}" --bind 127.0.0.1:0 --rpc-bind 127.0.0.1:0 --mine-address "${MINE_ADDRESS_HEX}")
  [[ -z "${peers}" ]] || args+=(--peers "${peers}")
  STARTED_PID="" STARTED_RPC="" STARTED_P2P=""
  if ! rubin_process_start "${log_file}" "${NODE_BIN}" "${args[@]}"; then
    echo "${label} start failed" >&2
    [[ -z "${RUBIN_PROCESS_LAST_PID}" ]] || rubin_process_stop_pid "${RUBIN_PROCESS_LAST_PID}" || true
    return 1
  fi
  STARTED_PID="${RUBIN_PROCESS_LAST_PID}"
  if ! rubin_process_wait_for_log "${log_file}" "rpc: listening=" 30 "${STARTED_PID}"; then
    echo "${label} did not become ready" >&2
    rubin_process_stop_pid "${STARTED_PID}" || true
    STARTED_PID=""
    return 1
  fi
  STARTED_RPC="$(rubin_process_extract_rpc_addr "${log_file}")" || { rubin_process_stop_pid "${STARTED_PID}" || true; return 1; }
  STARTED_P2P="$(p2p_addr_for_pid "${STARTED_PID}" "${STARTED_RPC}" 30)" || { rubin_process_stop_pid "${STARTED_PID}" || true; return 1; }
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
  rubin_process_stop_pid "${B_PID}"
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
  POST_RESTART_CATCHUP_PEERS="$(wait_peers "${B_RPC_ADDR}" 1 30)"
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
  POST_RESTART_B_BLOCK_JSON="$(rpc_json GET "${B_RPC_ADDR}" "/get_block?height=${POST_RESTART_TARGET_HEIGHT}")"
  block_matches_hash_canonical "${POST_RESTART_B_BLOCK_JSON}" "${POST_RESTART_MINE_HASH}" || {
    echo "post-restart block was not adopted by restarted node-b at height=${POST_RESTART_TARGET_HEIGHT} hash=${POST_RESTART_MINE_HASH}" >&2
    exit 1
  }
  POST_RESTART_A_BLOCK_JSON="$(rpc_json GET "${A_RPC_ADDR}" "/get_block?height=${POST_RESTART_TARGET_HEIGHT}")"
  block_matches_hash_canonical "${POST_RESTART_A_BLOCK_JSON}" "${POST_RESTART_MINE_HASH}" || {
    echo "post-restart block was not adopted by node-a at height=${POST_RESTART_TARGET_HEIGHT} hash=${POST_RESTART_MINE_HASH}" >&2
    exit 1
  }
  POST_RESTART_ACCEPTED_PEER="node-a"
  INCLUSION_PROOF_NODE="node-b"
fi
IFS=$'\t' read -r A_HEIGHT A_TIP < <(tip_tsv "${A_RPC_ADDR}")
IFS=$'\t' read -r B_HEIGHT B_TIP < <(tip_tsv "${B_RPC_ADDR}")
IFS=$'\t' read -r C_HEIGHT C_TIP < <(tip_tsv "${C_RPC_ADDR}")
A_PEERS="$(wait_peers "${A_RPC_ADDR}" 2 30)"
B_PEERS="$(wait_peers "${B_RPC_ADDR}" 1 30)" C_PEERS="$(wait_peers "${C_RPC_ADDR}" 1 30)"
if (( WITH_RESTART == 1 )); then
  [[ "${POST_RESTART_ACCEPTED_PEER}" == "node-a" ]] || {
    echo "unexpected post-restart adoption marker=${POST_RESTART_ACCEPTED_PEER}" >&2
    exit 1
  }
  POST_RESTART_A_BLOCK_JSON="$(rpc_json GET "${A_RPC_ADDR}" "/get_block?height=${POST_RESTART_MINE_HEIGHT}")"
  block_matches_hash_canonical "${POST_RESTART_A_BLOCK_JSON}" "${POST_RESTART_MINE_HASH}" || {
    echo "post-restart adoption marker node-a mismatch height=${A_HEIGHT} tip=${A_TIP}" >&2
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
  BLOCK_JSON="$(rpc_json GET "${B_RPC_ADDR}" "/get_block?height=${TARGET_HEIGHT}")"
  POST_RESTART_BLOCK_JSON="$(rpc_json GET "${B_RPC_ADDR}" "/get_block?height=${POST_RESTART_MINE_HEIGHT}")"
  block_matches_hash_canonical "${BLOCK_JSON}" "${FINAL_HASH}" || { echo "restart target block mismatch canonical/hash expected=${FINAL_HASH}" >&2; exit 1; }
  block_matches_hash_canonical "${POST_RESTART_BLOCK_JSON}" "${POST_RESTART_MINE_HASH}" || { echo "restart post-restart block mismatch canonical/hash expected=${POST_RESTART_MINE_HASH}" >&2; exit 1; }
else
  BLOCK_JSON="$(rpc_json GET "${A_RPC_ADDR}" "/get_block?height=${TARGET_HEIGHT}")"
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
