#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEV_ENV="${REPO_ROOT}/scripts/dev-env.sh"
GO_MODULE_ROOT="${REPO_ROOT}/clients/go"
RUST_MODULE_ROOT="${REPO_ROOT}/clients/rust"
TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/rubin-devnet-rpc-parity.XXXXXX")"
GO_NODE_BIN="${TMP_ROOT}/rubin-node-go"
GO_TXGEN_BIN="${TMP_ROOT}/rubin-txgen"
RUST_NODE_BIN="${TMP_ROOT}/rubin-node-rust"
KEEP_TMP="${KEEP_TMP:-0}"

GO_DATA_DIR="${TMP_ROOT}/go-node"
RUST_DATA_DIR="${TMP_ROOT}/rust-node"
GO_LOG="${TMP_ROOT}/go-node.log"
RUST_LOG="${TMP_ROOT}/rust-node.log"
MINE_LOG="${TMP_ROOT}/mine.log"
KEYGEN_GO="${TMP_ROOT}/key_material.go"
KEYGEN_JSON="${TMP_ROOT}/key_material.json"

GO_RPC_ADDR="${GO_RPC_ADDR:-127.0.0.1:19112}"
RUST_RPC_ADDR="${RUST_RPC_ADDR:-127.0.0.1:19113}"

PIDS=()

cleanup() {
  local status=$?
  for pid in "${PIDS[@]:-}"; do
    if kill -0 "${pid}" >/dev/null 2>&1; then
      kill "${pid}" >/dev/null 2>&1 || true
      wait "${pid}" >/dev/null 2>&1 || true
    fi
  done
  if [[ ${status} -ne 0 ]]; then
    echo "FAIL: artifacts preserved at ${TMP_ROOT}" >&2
    for log in "${MINE_LOG}" "${GO_LOG}" "${RUST_LOG}"; do
      if [[ -f "${log}" ]]; then
        echo "----- $(basename "${log}") -----" >&2
        tail -n 80 "${log}" >&2 || true
      fi
    done
    exit "${status}"
  fi
  if [[ "${KEEP_TMP}" == "1" ]]; then
    echo "OK: artifacts preserved at ${TMP_ROOT}"
    exit 0
  fi
  rm -rf "${TMP_ROOT}"
}

trap cleanup EXIT

start_bg() {
  local log_file="$1"
  shift
  "$@" >"${log_file}" 2>&1 &
  PIDS+=("$!")
}

wait_for_rpc_height() {
  local rpc_addr="$1"
  local timeout="$2"
  local deadline=$((SECONDS + timeout))
  while (( SECONDS < deadline )); do
    if python3 - "${rpc_addr}" 2>/dev/null <<'PY'
import json
import sys
import urllib.request

rpc_addr = sys.argv[1]
with urllib.request.urlopen(f"http://{rpc_addr}/get_tip", timeout=2) as resp:
    if resp.status != 200:
        raise SystemExit(1)
    data = json.load(resp)
if data.get("has_tip") and isinstance(data.get("height"), int):
    raise SystemExit(0)
raise SystemExit(1)
PY
    then
      return 0
    fi
    sleep 1
  done
  echo "timeout waiting for /get_tip on ${rpc_addr}" >&2
  return 1
}

read_tip_tsv() {
  local rpc_addr="$1"
  python3 - "${rpc_addr}" <<'PY'
import json
import sys
import urllib.request

rpc_addr = sys.argv[1]
with urllib.request.urlopen(f"http://{rpc_addr}/get_tip", timeout=2) as resp:
    data = json.load(resp)
print(data["height"], data["tip_hash"], sep="\t")
PY
}

check_metrics() {
  local rpc_addr="$1"
  python3 - "${rpc_addr}" <<'PY'
import re
import sys
import urllib.request

rpc_addr = sys.argv[1]
expected = {
    "rubin_node_tip_height",
    "rubin_node_best_known_height",
    "rubin_node_in_ibd",
    "rubin_node_peer_count",
    "rubin_node_mempool_txs",
    "rubin_node_rpc_requests_total",
    "rubin_node_submit_tx_total",
}
with urllib.request.urlopen(f"http://{rpc_addr}/metrics", timeout=2) as resp:
    if resp.status != 200:
        raise SystemExit(1)
    body = resp.read().decode("utf-8")
names = set()
for line in body.splitlines():
    line = line.strip()
    if not line or line.startswith("#"):
        continue
    name = re.split(r"[{ ]", line, maxsplit=1)[0]
    names.add(name)
missing = sorted(expected - names)
if missing:
    raise SystemExit(f"missing metrics for {rpc_addr}: {', '.join(missing)}")
if 'rubin_node_mempool_txs 1' not in body:
    raise SystemExit(f"mempool metric did not reach 1 for {rpc_addr}")
if 'rubin_node_submit_tx_total{result=\"accepted\"} 1' not in body:
    raise SystemExit(f"accepted submit counter missing for {rpc_addr}")
PY
}

echo "Building Go binaries"
"${DEV_ENV}" -- go -C "${GO_MODULE_ROOT}" build -o "${GO_NODE_BIN}" ./cmd/rubin-node
"${DEV_ENV}" -- go -C "${GO_MODULE_ROOT}" build -o "${GO_TXGEN_BIN}" ./cmd/rubin-txgen

echo "Building Rust binary"
"${DEV_ENV}" -- bash -lc "cd '${RUST_MODULE_ROOT}' && cargo build -p rubin-node >/dev/null"
cp "${RUST_MODULE_ROOT}/target/debug/rubin-node" "${RUST_NODE_BIN}"

cat >"${KEYGEN_GO}" <<'EOF'
package main

import (
	"encoding/hex"
	"encoding/json"
	"os"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

type payload struct {
	FromDERHex     string `json:"from_der_hex"`
	MineAddressHex string `json:"mine_address_hex"`
	ToAddressHex   string `json:"to_address_hex"`
}

func main() {
	fromKP, err := consensus.NewMLDSA87Keypair()
	if err != nil {
		panic(err)
	}
	defer fromKP.Close()
	toKP, err := consensus.NewMLDSA87Keypair()
	if err != nil {
		panic(err)
	}
	defer toKP.Close()
	fromDER, err := fromKP.PrivateKeyDER()
	if err != nil {
		panic(err)
	}
	out := payload{
		FromDERHex:     hex.EncodeToString(fromDER),
		MineAddressHex: hex.EncodeToString(consensus.P2PKCovenantDataForPubkey(fromKP.PubkeyBytes())),
		ToAddressHex:   hex.EncodeToString(consensus.P2PKCovenantDataForPubkey(toKP.PubkeyBytes())),
	}
	if err := json.NewEncoder(os.Stdout).Encode(out); err != nil {
		panic(err)
	}
}
EOF

echo "Generating temporary devnet key material"
"${DEV_ENV}" -- go -C "${GO_MODULE_ROOT}" run "${KEYGEN_GO}" >"${KEYGEN_JSON}"

FROM_DER_HEX="$(python3 - "${KEYGEN_JSON}" <<'PY'
import json, sys
print(json.load(open(sys.argv[1]))["from_der_hex"])
PY
)"
MINE_ADDRESS_HEX="$(python3 - "${KEYGEN_JSON}" <<'PY'
import json, sys
print(json.load(open(sys.argv[1]))["mine_address_hex"])
PY
)"
TO_ADDRESS_HEX="$(python3 - "${KEYGEN_JSON}" <<'PY'
import json, sys
print(json.load(open(sys.argv[1]))["to_address_hex"])
PY
)"

mkdir -p "${GO_DATA_DIR}" "${RUST_DATA_DIR}"

echo "Mining mature chainstate with Go node"
"${GO_NODE_BIN}" --datadir "${GO_DATA_DIR}" --mine-address "${MINE_ADDRESS_HEX}" --mine-blocks 101 --mine-exit >"${MINE_LOG}" 2>&1
cp -R "${GO_DATA_DIR}/." "${RUST_DATA_DIR}/"

echo "Starting Go RPC node at ${GO_RPC_ADDR}"
start_bg "${GO_LOG}" "${GO_NODE_BIN}" --datadir "${GO_DATA_DIR}" --rpc-bind "${GO_RPC_ADDR}"
echo "Starting Rust RPC node at ${RUST_RPC_ADDR}"
start_bg "${RUST_LOG}" "${RUST_NODE_BIN}" --datadir "${RUST_DATA_DIR}" --rpc-bind "${RUST_RPC_ADDR}"

wait_for_rpc_height "${GO_RPC_ADDR}" 30
wait_for_rpc_height "${RUST_RPC_ADDR}" 30

IFS=$'\t' read -r GO_HEIGHT GO_HASH < <(read_tip_tsv "${GO_RPC_ADDR}")
IFS=$'\t' read -r RUST_HEIGHT RUST_HASH < <(read_tip_tsv "${RUST_RPC_ADDR}")
if [[ "${GO_HEIGHT}" != "${RUST_HEIGHT}" || "${GO_HASH}" != "${RUST_HASH}" ]]; then
  echo "tip mismatch: go=${GO_HEIGHT}:${GO_HASH} rust=${RUST_HEIGHT}:${RUST_HASH}" >&2
  exit 1
fi

echo "Submitting deterministic tx against Go RPC"
GO_TX_HEX="$("${GO_TXGEN_BIN}" \
  --datadir "${GO_DATA_DIR}" \
  --from-key "${FROM_DER_HEX}" \
  --to-key "${TO_ADDRESS_HEX}" \
  --amount 1 \
  --fee 1 \
  --submit-to "${GO_RPC_ADDR}")"

echo "Submitting deterministic tx against Rust RPC"
RUST_TX_HEX="$("${GO_TXGEN_BIN}" \
  --datadir "${GO_DATA_DIR}" \
  --from-key "${FROM_DER_HEX}" \
  --to-key "${TO_ADDRESS_HEX}" \
  --amount 1 \
  --fee 1 \
  --submit-to "${RUST_RPC_ADDR}")"

check_metrics "${GO_RPC_ADDR}"
check_metrics "${RUST_RPC_ADDR}"

echo "PASS: Go/Rust devnet RPC parity smoke matched tip ${GO_HEIGHT}:${GO_HASH} and accepted tx via both clients"
