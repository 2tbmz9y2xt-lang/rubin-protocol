#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEV_ENV="${REPO_ROOT}/scripts/dev-env.sh"
GO_MODULE_ROOT="${REPO_ROOT}/clients/go"
HELPER="${REPO_ROOT}/scripts/devnet-process-common.sh"
TARGET_HEIGHT=120

usage() {
  echo "usage: $0 [--target-height N]" >&2
}

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

[[ "${TARGET_HEIGHT}" =~ ^[0-9]+$ && "${TARGET_HEIGHT}" -ge 102 ]] || {
  echo "--target-height must be an integer >= 102" >&2
  exit 2
}

# shellcheck source=scripts/devnet-process-common.sh disable=SC1091
source "${HELPER}"
rubin_process_init go-binary-soak

NODE_BIN="${RUBIN_PROCESS_ARTIFACT_ROOT}/rubin-node-go"
TXGEN_BIN="${RUBIN_PROCESS_ARTIFACT_ROOT}/rubin-txgen"
KEYGEN_GO="${RUBIN_PROCESS_ARTIFACT_ROOT}/keygen.go"
KEYGEN_JSON="${RUBIN_PROCESS_ARTIFACT_ROOT}/keygen.json"
REPORT_JSON="${RUBIN_PROCESS_ARTIFACT_ROOT}/go-binary-soak-report.json"
BASE_HEIGHT=$((TARGET_HEIGHT - 1))
BASE_MINE_BLOCKS="${TARGET_HEIGHT}"
A_DIR="${RUBIN_PROCESS_ARTIFACT_ROOT}/node-a"
B_DIR="${RUBIN_PROCESS_ARTIFACT_ROOT}/node-b"
C_DIR="${RUBIN_PROCESS_ARTIFACT_ROOT}/node-c"
A_LOG="node-a.log"
B_LOG="node-b.log"
C_LOG="node-c.log"
MINE_LOG="${RUBIN_PROCESS_ARTIFACT_ROOT}/mine-base.log"
A_P2P_ADDR="127.0.0.1:$((29110 + ($$ % 1000)))"

rpc_json() {
  local method="$1" addr="$2" path="$3" body="${4:-}"
  python3 - "${method}" "${addr}" "${path}" "${body}" <<'PY'
import json, sys, urllib.request
method, addr, path, body = sys.argv[1:5]
data = body.encode() if body else None
req = urllib.request.Request(f"http://{addr}{path}", data=data, method=method)
if body:
    req.add_header("Content-Type", "application/json")
with urllib.request.urlopen(req, timeout=5) as resp:
    print(resp.read().decode("utf-8"), end="")
PY
}

json_key() {
  python3 -c 'import json,sys; d=json.load(sys.stdin)
for p in sys.argv[1].split("."): d=d[p]
print(d)' "$1"
}

tip_tsv() {
  rpc_json GET "$1" /get_tip | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["height"], d["tip_hash"], sep="\t")'
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
rubin_process_start "${A_LOG}" "${NODE_BIN}" --datadir "${A_DIR}" --bind "${A_P2P_ADDR}" --rpc-bind 127.0.0.1:0 --mine-address "${MINE_ADDRESS_HEX}"
A_PID="${RUBIN_PROCESS_LAST_PID}"
rubin_process_start "${B_LOG}" "${NODE_BIN}" --datadir "${B_DIR}" --bind 127.0.0.1:0 --rpc-bind 127.0.0.1:0 --peers "${A_P2P_ADDR}" --mine-address "${MINE_ADDRESS_HEX}"
B_PID="${RUBIN_PROCESS_LAST_PID}"
rubin_process_start "${C_LOG}" "${NODE_BIN}" --datadir "${C_DIR}" --bind 127.0.0.1:0 --rpc-bind 127.0.0.1:0 --peers "${A_P2P_ADDR}" --mine-address "${MINE_ADDRESS_HEX}"
C_PID="${RUBIN_PROCESS_LAST_PID}"

rubin_process_wait_for_log "${A_LOG}" "rpc: listening=" 30 "${A_PID}"
A_RPC_ADDR="$(rubin_process_extract_rpc_addr "${A_LOG}")"
rubin_process_wait_for_log "${B_LOG}" "rpc: listening=" 30 "${B_PID}"
B_RPC_ADDR="$(rubin_process_extract_rpc_addr "${B_LOG}")"
rubin_process_wait_for_log "${C_LOG}" "rpc: listening=" 30 "${C_PID}"
C_RPC_ADDR="$(rubin_process_extract_rpc_addr "${C_LOG}")"
rubin_process_wait_for_rpc_ready "${A_RPC_ADDR}" 30
rubin_process_wait_for_rpc_ready "${B_RPC_ADDR}" 30
rubin_process_wait_for_rpc_ready "${C_RPC_ADDR}" 30
wait_height "${A_RPC_ADDR}" "${BASE_HEIGHT}" 30
wait_height "${B_RPC_ADDR}" "${BASE_HEIGHT}" 30
wait_height "${C_RPC_ADDR}" "${BASE_HEIGHT}" 30

echo "Submitting tx through Go RPC and mining it through /mine_next"
TX_HEX="$("${TXGEN_BIN}" --datadir "${A_DIR}" --from-key "${FROM_DER_HEX}" --to-key "${TO_ADDRESS_HEX}" --amount 1 --fee 1 --submit-to "${A_RPC_ADDR}")"
MEMPOOL_JSON="$(rpc_json GET "${A_RPC_ADDR}" /get_mempool)"
TX_ID="$(printf '%s' "${MEMPOOL_JSON}" | python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["count"] == 1; print(d["txids"][0])')"
MINE_JSON="$(rpc_json POST "${A_RPC_ADDR}" /mine_next '{}')"
FINAL_HEIGHT="$(printf '%s' "${MINE_JSON}" | json_key height)"
FINAL_HASH="$(printf '%s' "${MINE_JSON}" | json_key block_hash)"
TX_COUNT="$(printf '%s' "${MINE_JSON}" | json_key tx_count)"
[[ "${FINAL_HEIGHT}" == "${TARGET_HEIGHT}" && "${TX_COUNT}" -ge 2 ]] || {
  echo "unexpected mine_next result height=${FINAL_HEIGHT} tx_count=${TX_COUNT}" >&2
  exit 1
}
wait_height "${A_RPC_ADDR}" "${TARGET_HEIGHT}" 30
IFS=$'\t' read -r A_HEIGHT A_TIP < <(tip_tsv "${A_RPC_ADDR}")
IFS=$'\t' read -r B_HEIGHT B_TIP < <(tip_tsv "${B_RPC_ADDR}")
IFS=$'\t' read -r C_HEIGHT C_TIP < <(tip_tsv "${C_RPC_ADDR}")
[[ "${A_HEIGHT}" == "${TARGET_HEIGHT}" && "${A_TIP}" == "${FINAL_HASH}" ]] || {
  echo "unexpected node-a checkpoint final=${FINAL_HASH} a_height=${A_HEIGHT} a_tip=${A_TIP}" >&2
  exit 1
}
[[ ("${B_HEIGHT}" == "${BASE_HEIGHT}" && -n "${B_TIP}") || ("${B_HEIGHT}" == "${TARGET_HEIGHT}" && "${B_TIP}" == "${FINAL_HASH}") ]] || {
  echo "unexpected node-b checkpoint final=${FINAL_HASH} b_height=${B_HEIGHT} b_tip=${B_TIP}" >&2
  exit 1
}
[[ ("${C_HEIGHT}" == "${BASE_HEIGHT}" && -n "${C_TIP}") || ("${C_HEIGHT}" == "${TARGET_HEIGHT}" && "${C_TIP}" == "${FINAL_HASH}") ]] || {
  echo "unexpected node-c checkpoint final=${FINAL_HASH} c_height=${C_HEIGHT} c_tip=${C_TIP}" >&2
  exit 1
}
BLOCK_JSON="$(rpc_json GET "${A_RPC_ADDR}" "/get_block?height=${TARGET_HEIGHT}")"
printf '%s' "${BLOCK_JSON}" | python3 -c 'import json,sys; d=json.load(sys.stdin); assert sys.argv[1].lower() in d["block_hex"].lower()' "${TX_HEX}"

export REPORT_JSON TARGET_HEIGHT BASE_HEIGHT A_HEIGHT B_HEIGHT C_HEIGHT A_TIP B_TIP C_TIP A_PID B_PID C_PID A_RPC_ADDR B_RPC_ADDR C_RPC_ADDR TX_ID FINAL_HASH TX_COUNT
python3 - <<'PY'
import json, os
report = {
  "scenario": "go_binary_soak_skeleton",
  "target_height": int(os.environ["TARGET_HEIGHT"]),
  "base_height": int(os.environ["BASE_HEIGHT"]),
  "participants": [
    {"name": "node-a", "pid": int(os.environ["A_PID"]), "rpc": os.environ["A_RPC_ADDR"], "checkpoint_height": int(os.environ["A_HEIGHT"]), "tip_hash": os.environ["A_TIP"]},
    {"name": "node-b", "pid": int(os.environ["B_PID"]), "rpc": os.environ["B_RPC_ADDR"], "checkpoint_height": int(os.environ["B_HEIGHT"]), "tip_hash": os.environ["B_TIP"]},
    {"name": "node-c", "pid": int(os.environ["C_PID"]), "rpc": os.environ["C_RPC_ADDR"], "checkpoint_height": int(os.environ["C_HEIGHT"]), "tip_hash": os.environ["C_TIP"]},
  ],
  "tx": {"id": os.environ["TX_ID"], "submission": "rpc:/submit_tx"},
  "final": {"height": int(os.environ["TARGET_HEIGHT"]), "tip_hash": os.environ["FINAL_HASH"], "tx_count": int(os.environ["TX_COUNT"])},
  "verdict": "PASS",
}
with open(os.environ["REPORT_JSON"], "w", encoding="utf-8") as f:
    json.dump(report, f, indent=2, sort_keys=True)
    f.write("\n")
PY
echo "PASS: Go binary soak reached height ${TARGET_HEIGHT} with tx ${TX_ID}; report=${REPORT_JSON}"
