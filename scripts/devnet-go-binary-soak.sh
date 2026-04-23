#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEV_ENV="${REPO_ROOT}/scripts/dev-env.sh"
GO_MODULE_ROOT="${REPO_ROOT}/clients/go"
HELPER="${REPO_ROOT}/scripts/devnet-process-common.sh"
TARGET_HEIGHT=120
WITH_RESTART=0
CLUSTER_START_ATTEMPTS=5
NODE_RESTART_ATTEMPTS=5

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
REPORT_JSON="${RUBIN_PROCESS_ARTIFACT_ROOT}/go-binary-soak-report.json"
BASE_HEIGHT=$((TARGET_HEIGHT - 1))
BASE_MINE_BLOCKS=$((BASE_HEIGHT + 1))
A_DIR="${RUBIN_PROCESS_ARTIFACT_ROOT}/node-a"
B_DIR="${RUBIN_PROCESS_ARTIFACT_ROOT}/node-b"
C_DIR="${RUBIN_PROCESS_ARTIFACT_ROOT}/node-c"
A_LOG="node-a.log" B_LOG="node-b.log" C_LOG="node-c.log"
B_RESTART_LOG="node-b-restart.log"
MINE_LOG="${RUBIN_PROCESS_ARTIFACT_ROOT}/mine-base.log"
RUBIN_PROCESS_LOGS+=("${MINE_LOG}")
PRE_RESTART_B_HEIGHT=""
PRE_RESTART_B_TIP=""
PRE_RESTART_B_RPC_ADDR=""
PRE_RESTART_B_PID=""
POST_RESTART_B_RPC_ADDR=""
POST_RESTART_B_PID=""
POST_RESTART_CATCHUP_HEIGHT=""
POST_RESTART_CATCHUP_TIP=""
POST_RESTART_CATCHUP_PEERS="0"
POST_RESTART_MINE_HEIGHT=""
POST_RESTART_MINE_HASH=""
POST_RESTART_MINE_TX_COUNT="0"
POST_RESTART_ACCEPTED_PEER=""
INCLUSION_PROOF_NODE="node-a"
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
allocate_loopback_addr() {
  python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(f"127.0.0.1:{s.getsockname()[1]}"); s.close()'
}
unregister_managed_pid() {
  local stale_pid="${1:-}" kept=() pid
  [[ -n "${stale_pid}" ]] || return 1
  for pid in "${RUBIN_PROCESS_PIDS[@]}"; do
    [[ "${pid}" == "${stale_pid}" ]] || kept+=("${pid}")
  done
  RUBIN_PROCESS_PIDS=("${kept[@]}")
}
stop_managed_pid() {
  local managed_pid="${1:-}"
  [[ -n "${managed_pid}" ]] || return 1
  rubin_process_stop_pid "${managed_pid}"
  unregister_managed_pid "${managed_pid}"
}
stop_cluster_attempt() {
  local managed_pid
  for managed_pid in "${C_PID:-}" "${B_PID:-}" "${A_PID:-}"; do
    [[ -z "${managed_pid}" ]] || stop_managed_pid "${managed_pid}" || true
  done
  A_PID="" B_PID="" C_PID=""
}
start_soak_cluster() {
  local attempt
  attempt=1
  while (( attempt <= CLUSTER_START_ATTEMPTS )); do
    A_PID="" B_PID="" C_PID="" A_RPC_ADDR="" B_RPC_ADDR="" C_RPC_ADDR=""
    A_P2P_ADDR="$(allocate_loopback_addr)" || return 1
    B_P2P_ADDR="$(allocate_loopback_addr)" || return 1
    C_P2P_ADDR="$(allocate_loopback_addr)" || return 1
    if ! rubin_process_start "${A_LOG}" "${NODE_BIN}" --datadir "${A_DIR}" --bind "${A_P2P_ADDR}" --rpc-bind 127.0.0.1:0 --peers "${B_P2P_ADDR},${C_P2P_ADDR}" --mine-address "${MINE_ADDRESS_HEX}"; then
      echo "node-a start attempt ${attempt} failed; retrying with fresh loopback ports" >&2
      stop_cluster_attempt
      ((attempt++))
      continue
    fi
    A_PID="${RUBIN_PROCESS_LAST_PID}"
    if ! rubin_process_wait_for_log "${A_LOG}" "rpc: listening=" 30 "${A_PID}"; then
      echo "node-a did not become ready on attempt ${attempt}; retrying with fresh loopback ports" >&2
      stop_cluster_attempt
      ((attempt++))
      continue
    fi
    A_RPC_ADDR="$(rubin_process_extract_rpc_addr "${A_LOG}")" || { stop_cluster_attempt; return 1; }
    if ! rubin_process_start "${B_LOG}" "${NODE_BIN}" --datadir "${B_DIR}" --bind "${B_P2P_ADDR}" --rpc-bind 127.0.0.1:0 --peers "${A_P2P_ADDR}" --mine-address "${MINE_ADDRESS_HEX}"; then
      echo "node-b start attempt ${attempt} failed; retrying with fresh loopback ports" >&2
      stop_cluster_attempt
      ((attempt++))
      continue
    fi
    B_PID="${RUBIN_PROCESS_LAST_PID}"
    if ! rubin_process_wait_for_log "${B_LOG}" "rpc: listening=" 30 "${B_PID}"; then
      echo "node-b did not become ready on attempt ${attempt}; retrying with fresh loopback ports" >&2
      stop_cluster_attempt
      ((attempt++))
      continue
    fi
    B_RPC_ADDR="$(rubin_process_extract_rpc_addr "${B_LOG}")" || { stop_cluster_attempt; return 1; }
    if ! rubin_process_start "${C_LOG}" "${NODE_BIN}" --datadir "${C_DIR}" --bind "${C_P2P_ADDR}" --rpc-bind 127.0.0.1:0 --peers "${A_P2P_ADDR}" --mine-address "${MINE_ADDRESS_HEX}"; then
      echo "node-c start attempt ${attempt} failed; retrying with fresh loopback ports" >&2
      stop_cluster_attempt
      ((attempt++))
      continue
    fi
    C_PID="${RUBIN_PROCESS_LAST_PID}"
    if ! rubin_process_wait_for_log "${C_LOG}" "rpc: listening=" 30 "${C_PID}"; then
      echo "node-c did not become ready on attempt ${attempt}; retrying with fresh loopback ports" >&2
      stop_cluster_attempt
      ((attempt++))
      continue
    fi
    C_RPC_ADDR="$(rubin_process_extract_rpc_addr "${C_LOG}")" || { stop_cluster_attempt; return 1; }
    if rubin_process_wait_for_rpc_ready "${A_RPC_ADDR}" 30 && rubin_process_wait_for_rpc_ready "${B_RPC_ADDR}" 30 && rubin_process_wait_for_rpc_ready "${C_RPC_ADDR}" 30; then
      return 0
    fi
    echo "cluster RPC readiness failed on attempt ${attempt}; retrying with fresh loopback ports" >&2
    stop_cluster_attempt
    ((attempt++))
  done
  echo "failed to start three-node cluster after ${CLUSTER_START_ATTEMPTS} attempts" >&2
  return 1
}
restart_node_b() {
  local attempt
  attempt=1
  while (( attempt <= NODE_RESTART_ATTEMPTS )); do
    if (( attempt > 1 )); then
      B_P2P_ADDR="$(allocate_loopback_addr)" || return 1
    fi
    if ! rubin_process_start "${B_RESTART_LOG}" "${NODE_BIN}" --datadir "${B_DIR}" --bind "${B_P2P_ADDR}" --rpc-bind 127.0.0.1:0 --peers "${A_P2P_ADDR}" --mine-address "${MINE_ADDRESS_HEX}"; then
      echo "node-b restart attempt ${attempt} failed; retrying with fresh loopback port" >&2
      [[ -z "${RUBIN_PROCESS_LAST_PID}" ]] || stop_managed_pid "${RUBIN_PROCESS_LAST_PID}" || true
      ((attempt++))
      continue
    fi
    B_PID="${RUBIN_PROCESS_LAST_PID}"
    if rubin_process_wait_for_log "${B_RESTART_LOG}" "rpc: listening=" 30 "${B_PID}"; then
      B_RPC_ADDR="$(rubin_process_extract_rpc_addr "${B_RESTART_LOG}")" || return 1
      POST_RESTART_B_PID="${B_PID}"
      POST_RESTART_B_RPC_ADDR="${B_RPC_ADDR}"
      return 0
    fi
    echo "node-b restart did not become ready on attempt ${attempt}; retrying with fresh loopback port" >&2
    stop_managed_pid "${B_PID}" || true
    B_PID=""
    ((attempt++))
  done
  echo "failed to restart node-b after ${NODE_RESTART_ATTEMPTS} attempts" >&2
  return 1
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
  PRE_RESTART_B_RPC_ADDR="${B_RPC_ADDR}"
  PRE_RESTART_B_PID="${B_PID}"
  echo "Stopping node-b pid=${B_PID} at deterministic restart checkpoint height ${PRE_RESTART_B_HEIGHT}"
  stop_managed_pid "${B_PID}"
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
export REPORT_JSON TARGET_HEIGHT BASE_HEIGHT A_HEIGHT B_HEIGHT C_HEIGHT A_TIP B_TIP C_TIP A_PID B_PID C_PID A_RPC_ADDR B_RPC_ADDR C_RPC_ADDR A_PEERS B_PEERS C_PEERS TX_ID FINAL_HASH TX_COUNT WITH_RESTART PRE_RESTART_B_HEIGHT PRE_RESTART_B_TIP PRE_RESTART_B_RPC_ADDR PRE_RESTART_B_PID POST_RESTART_B_RPC_ADDR POST_RESTART_B_PID POST_RESTART_CATCHUP_HEIGHT POST_RESTART_CATCHUP_TIP POST_RESTART_CATCHUP_PEERS POST_RESTART_MINE_HEIGHT POST_RESTART_MINE_HASH POST_RESTART_MINE_TX_COUNT POST_RESTART_ACCEPTED_PEER INCLUSION_PROOF_NODE
python3 - <<'PY'
import json, os
participants = []
for node in ("A", "B", "C"):
    participants.append({"name": f"node-{node.lower()}", "pid": int(os.environ[f"{node}_PID"]), "rpc": os.environ[f"{node}_RPC_ADDR"], "checkpoint_height": int(os.environ[f"{node}_HEIGHT"]), "tip_hash": os.environ[f"{node}_TIP"], "peer_count": int(os.environ[f"{node}_PEERS"])})
restart_enabled = os.environ["WITH_RESTART"] == "1"
report = {
    "scenario": "go_binary_soak_restart" if restart_enabled else "go_binary_soak_skeleton",
    "target_height": int(os.environ["TARGET_HEIGHT"]),
    "base_height": int(os.environ["BASE_HEIGHT"]),
    "participants": participants,
    "tx": {
        "id": os.environ["TX_ID"],
        "submission": "rpc:/submit_tx",
        "inclusion_proof_node": os.environ["INCLUSION_PROOF_NODE"],
        "inclusion_height": int(os.environ["TARGET_HEIGHT"]),
    },
    "final": {
        "height": int(os.environ["POST_RESTART_MINE_HEIGHT"] if restart_enabled else os.environ["TARGET_HEIGHT"]),
        "tip_hash": os.environ["POST_RESTART_MINE_HASH"] if restart_enabled else os.environ["FINAL_HASH"],
        "tx_count": int(os.environ["POST_RESTART_MINE_TX_COUNT"] if restart_enabled else os.environ["TX_COUNT"]),
    },
    "verdict": "PASS",
}
if restart_enabled:
    report["restart"] = {
        "enabled": True,
        "stopped_node": "node-b",
        "checkpoint_before_stop": {
            "height": int(os.environ["PRE_RESTART_B_HEIGHT"]),
            "tip_hash": os.environ["PRE_RESTART_B_TIP"],
            "rpc": os.environ["PRE_RESTART_B_RPC_ADDR"],
            "pid": int(os.environ["PRE_RESTART_B_PID"]),
        },
        "state_after_catchup": {
            "height": int(os.environ["POST_RESTART_CATCHUP_HEIGHT"]),
            "tip_hash": os.environ["POST_RESTART_CATCHUP_TIP"],
            "rpc": os.environ["POST_RESTART_B_RPC_ADDR"],
            "pid": int(os.environ["POST_RESTART_B_PID"]),
            "peer_count": int(os.environ["POST_RESTART_CATCHUP_PEERS"]),
        },
        "post_restart_live_action": {
            "action": "mine_next",
            "height": int(os.environ["POST_RESTART_MINE_HEIGHT"]),
            "block_hash": os.environ["POST_RESTART_MINE_HASH"],
            "tx_count": int(os.environ["POST_RESTART_MINE_TX_COUNT"]),
            "accepted_by_peer": os.environ["POST_RESTART_ACCEPTED_PEER"],
        },
    }
else:
    report["restart"] = {"enabled": False}
with open(os.environ["REPORT_JSON"], "w", encoding="utf-8") as f:
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
