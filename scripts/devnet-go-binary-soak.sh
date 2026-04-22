#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEV_ENV="${REPO_ROOT}/scripts/dev-env.sh"
GO_MODULE_ROOT="${REPO_ROOT}/clients/go"
HELPER="${REPO_ROOT}/scripts/devnet-process-common.sh"
TARGET_HEIGHT=120

usage() { echo "usage: $0 [--target-height N]" >&2; }
while (($#)); do
  case "$1" in
    --target-height)
      [[ $# -ge 2 ]] || { usage; exit 2; }
      TARGET_HEIGHT="$2"
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
MINE_LOG="${RUBIN_PROCESS_ARTIFACT_ROOT}/mine-base.log"
RUBIN_PROCESS_LOGS+=("${MINE_LOG}")
rpc_json() {
  local method="$1" addr="$2" path="$3" body="${4:-}"
  python3 - "${method}" "${addr}" "${path}" "${body}" <<'PY'
import sys, urllib.error, urllib.request
method, addr, path, body = sys.argv[1:5]
data = body.encode() if body else None
req = urllib.request.Request(f"http://{addr}{path}", data=data, method=method)
if body:
    req.add_header("Content-Type", "application/json")
try:
    resp = urllib.request.urlopen(req, timeout=5)
except urllib.error.HTTPError as exc:
    print(exc.read().decode("utf-8"), end=""); sys.exit(22)
except (urllib.error.URLError, TimeoutError) as exc:
    print(f"request failed: {getattr(exc, 'reason', exc)}", end=""); sys.exit(1)
with resp:
    print(resp.read().decode("utf-8"), end="")
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
A_PID=""
for _ in 1 2 3; do
  A_P2P_ADDR="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(f"127.0.0.1:{s.getsockname()[1]}"); s.close()')"
  if rubin_process_start "${A_LOG}" "${NODE_BIN}" --datadir "${A_DIR}" --bind "${A_P2P_ADDR}" --rpc-bind 127.0.0.1:0 --mine-address "${MINE_ADDRESS_HEX}" && rubin_process_wait_for_log "${A_LOG}" "rpc: listening=" 30 "${RUBIN_PROCESS_LAST_PID}"; then A_PID="${RUBIN_PROCESS_LAST_PID}"; A_RPC_ADDR="$(rubin_process_extract_rpc_addr "${A_LOG}")"; break; fi
  [[ -z "${RUBIN_PROCESS_LAST_PID}" ]] || rubin_process_stop_pid "${RUBIN_PROCESS_LAST_PID}" || true
done
[[ -n "${A_PID}" ]] || { echo "failed to start node-a after retrying loopback bind ports" >&2; exit 1; }
rubin_process_start "${B_LOG}" "${NODE_BIN}" --datadir "${B_DIR}" --bind 127.0.0.1:0 --rpc-bind 127.0.0.1:0 --peers "${A_P2P_ADDR}" --mine-address "${MINE_ADDRESS_HEX}"
B_PID="${RUBIN_PROCESS_LAST_PID}"
rubin_process_start "${C_LOG}" "${NODE_BIN}" --datadir "${C_DIR}" --bind 127.0.0.1:0 --rpc-bind 127.0.0.1:0 --peers "${A_P2P_ADDR}" --mine-address "${MINE_ADDRESS_HEX}"
C_PID="${RUBIN_PROCESS_LAST_PID}"
rubin_process_wait_for_log "${B_LOG}" "rpc: listening=" 30 "${B_PID}"
B_RPC_ADDR="$(rubin_process_extract_rpc_addr "${B_LOG}")"
rubin_process_wait_for_log "${C_LOG}" "rpc: listening=" 30 "${C_PID}"
C_RPC_ADDR="$(rubin_process_extract_rpc_addr "${C_LOG}")"
for addr in "${A_RPC_ADDR}" "${B_RPC_ADDR}" "${C_RPC_ADDR}"; do rubin_process_wait_for_rpc_ready "${addr}" 30; done
for addr in "${A_RPC_ADDR}" "${B_RPC_ADDR}" "${C_RPC_ADDR}"; do wait_height "${addr}" "${BASE_HEIGHT}" 30; done
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
IFS=$'\t' read -r A_HEIGHT A_TIP < <(tip_tsv "${A_RPC_ADDR}")
IFS=$'\t' read -r B_HEIGHT B_TIP < <(tip_tsv "${B_RPC_ADDR}")
IFS=$'\t' read -r C_HEIGHT C_TIP < <(tip_tsv "${C_RPC_ADDR}")
A_PEERS="$(wait_peers "${A_RPC_ADDR}" 2 30)" B_PEERS="$(wait_peers "${B_RPC_ADDR}" 1 30)" C_PEERS="$(wait_peers "${C_RPC_ADDR}" 1 30)"
[[ "${A_HEIGHT}" == "${TARGET_HEIGHT}" && "${A_TIP}" == "${FINAL_HASH}" ]] || {
  echo "unexpected node-a checkpoint final=${FINAL_HASH} a_height=${A_HEIGHT} a_tip=${A_TIP}" >&2
  exit 1
}
[[ (("${B_HEIGHT}" == "${BASE_HEIGHT}" && -n "${B_TIP}") || ("${B_HEIGHT}" == "${TARGET_HEIGHT}" && "${B_TIP}" == "${FINAL_HASH}")) && (("${C_HEIGHT}" == "${BASE_HEIGHT}" && -n "${C_TIP}") || ("${C_HEIGHT}" == "${TARGET_HEIGHT}" && "${C_TIP}" == "${FINAL_HASH}")) && "${A_PEERS}" -ge 2 && "${B_PEERS}" -ge 1 && "${C_PEERS}" -ge 1 ]] || {
  echo "unexpected peer checkpoint/connectivity final=${FINAL_HASH} b_height=${B_HEIGHT} c_height=${C_HEIGHT} peers=${A_PEERS}/${B_PEERS}/${C_PEERS}" >&2
  exit 1
}
BLOCK_JSON="$(rpc_json GET "${A_RPC_ADDR}" "/get_block?height=${TARGET_HEIGHT}")"
printf '%s' "${BLOCK_JSON}" | python3 -c 'import json,sys; d=json.load(sys.stdin); sys.argv[1].lower() in d.get("block_hex", "").lower() or sys.exit("submitted tx bytes missing from target block")' "${TX_HEX}"
export REPORT_JSON TARGET_HEIGHT BASE_HEIGHT A_HEIGHT B_HEIGHT C_HEIGHT A_TIP B_TIP C_TIP A_PID B_PID C_PID A_RPC_ADDR B_RPC_ADDR C_RPC_ADDR A_PEERS B_PEERS C_PEERS TX_ID FINAL_HASH TX_COUNT
python3 - <<'PY'
import json, os
participants = []
for node in ("A", "B", "C"):
    participants.append({"name": f"node-{node.lower()}", "pid": int(os.environ[f"{node}_PID"]), "rpc": os.environ[f"{node}_RPC_ADDR"], "checkpoint_height": int(os.environ[f"{node}_HEIGHT"]), "tip_hash": os.environ[f"{node}_TIP"], "peer_count": int(os.environ[f"{node}_PEERS"])})
report = {"scenario": "go_binary_soak_skeleton", "target_height": int(os.environ["TARGET_HEIGHT"]), "base_height": int(os.environ["BASE_HEIGHT"]), "participants": participants, "tx": {"id": os.environ["TX_ID"], "submission": "rpc:/submit_tx"}, "final": {"height": int(os.environ["TARGET_HEIGHT"]), "tip_hash": os.environ["FINAL_HASH"], "tx_count": int(os.environ["TX_COUNT"])}, "verdict": "PASS"}
with open(os.environ["REPORT_JSON"], "w", encoding="utf-8") as f:
    json.dump(report, f, indent=2, sort_keys=True)
    f.write("\n")
PY
if [[ "${RUBIN_PROCESS_KEEP_ARTIFACTS}" == "1" ]]; then echo "PASS: Go binary soak reached height ${TARGET_HEIGHT} with tx ${TX_ID}; report=${REPORT_JSON}"; else echo "PASS: Go binary soak reached height ${TARGET_HEIGHT} with tx ${TX_ID}; set KEEP_TMP=1 to retain report"; fi
