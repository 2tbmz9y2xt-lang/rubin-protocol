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
GO_DONOR_LOG="${TMP_ROOT}/go-donor.log"
RUST_LOG="${TMP_ROOT}/rust-node.log"
MINE_LOG="${TMP_ROOT}/mine.log"
KEYGEN_GO="${TMP_ROOT}/key_material.go"
KEYGEN_JSON="${TMP_ROOT}/key_material.json"

GO_RPC_BIND="${GO_RPC_ADDR:-127.0.0.1:0}"
RUST_RPC_ADDR="${RUST_RPC_ADDR:-127.0.0.1:0}"
DETERMINISTIC_TX_FEE=10000
RPC_REQUEST_TIMEOUT_SECONDS="${RPC_REQUEST_TIMEOUT_SECONDS:-10}"

PIDS=()

fail() { echo "FAIL: $*" >&2; exit 1; }

child_pending() {
  local active
  active="$(builtin jobs -pr && builtin jobs -ps)" || fail "could not read background jobs"
  [[ $'\n'"${active}"$'\n' == *$'\n'"$1"$'\n'* ]]
}

wait_bg_exit() {
  local pid="$1" deadline=$((SECONDS + $2))
  while child_pending "${pid}"; do
    (( SECONDS < deadline )) || return 1
    sleep 0.1
  done
  return 0
}

stop_bg() {
  local index="$1" pid="${PIDS[$1]}" rc=1
  if child_pending "${pid}" && kill "${pid}"; then
    if wait_bg_exit "${pid}" 30; then
      rc=0
    elif child_pending "${pid}"; then
      kill -KILL "${pid}" && wait_bg_exit "${pid}" 2 || return 1
    fi
  elif child_pending "${pid}"; then
    return 1
  fi
  wait "${pid}" || rc=1
  child_pending "${pid}" && return 1
  unset 'PIDS[index]'
  return "${rc}"
}

cleanup() {
  local status=$? index
  for index in "${!PIDS[@]}"; do stop_bg "${index}" >/dev/null 2>&1 || true; done
  if [[ ${status} -ne 0 ]]; then
    echo "FAIL: artifacts preserved at ${TMP_ROOT}" >&2
    for log in "${MINE_LOG}" "${GO_DONOR_LOG}" "${GO_LOG}" "${RUST_LOG}"; do
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

wait_for_log() {
  local file="$1"
  local pattern="$2"
  local timeout="$3"
  local deadline=$((SECONDS + timeout))
  while (( SECONDS < deadline )); do
    if [[ -f "${file}" ]] && grep -q "${pattern}" "${file}"; then
      return 0
    fi
    sleep 1
  done
  echo "timeout waiting for ${pattern} in ${file}" >&2
  return 1
}

extract_rpc_addr() {
  local file="$1"
  local addr
  addr="$(awk -F= '/rpc: listening=/{print $2}' "${file}" | tail -n 1 | tr -d '[:space:]')"
  if [[ -z "${addr}" ]]; then
    echo "missing rpc listening banner in ${file}" >&2
    return 1
  fi
  printf '%s\n' "${addr}"
}

observe_pair() {
  python3 - "${RPC_REQUEST_TIMEOUT_SECONDS}" "$@" <<'PY'
import http.client
import json
import re
import signal
import sys
import time
from contextlib import closing

request_timeout, go, rust, *pinned_hash = sys.argv[1:]
def expired(*_):
    raise TimeoutError
def invalid_constant(token):
    raise ValueError(token)
signal.signal(signal.SIGALRM, expired)

def rpc(addr, route, deadline):
    try:
        timeout = min(float(request_timeout), deadline - time.monotonic())
        if not timeout > 0:
            return {}
        try:
            signal.setitimer(signal.ITIMER_REAL, timeout)
            with closing(http.client.HTTPConnection(addr, timeout=timeout)) as conn:
                conn.request("GET", route)
                with conn.getresponse() as response:
                    data = json.load(response, parse_constant=invalid_constant) if response.status == 200 else None
                    return data if isinstance(data, dict) else {}
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
    except (OSError, ValueError, RecursionError, http.client.HTTPException):
        return {}

def tip(addr, deadline):
    data = rpc(addr, "/get_tip", deadline)
    height, digest = data.get("height"), data.get("tip_hash")
    if data.get("has_tip") is True and type(height) is int and isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest):
        return height, digest

def mismatch(go_tip, rust_tip):
    raise SystemExit(f"tip mismatch: go={go_tip[0]}:{go_tip[1]} rust={rust_tip[0]}:{rust_tip[1]}")

def wait_tip(addr, expected=None):
    deadline, last = time.monotonic() + 30, None
    while time.monotonic() < deadline:
        sample = tip(addr, deadline)
        if time.monotonic() >= deadline:
            break
        if sample is not None:
            last = sample
            if (sample[0] == 101 if expected is None else sample == expected):
                return sample
        time.sleep(max(0, min(1, deadline - time.monotonic())))
    if last is not None and expected is not None:
        mismatch(expected, last)
    raise SystemExit(f"timeout waiting for /get_tip on {addr} after 30s (request_timeout={request_timeout}s)")

if not pinned_hash:
    donor = wait_tip(go)
    wait_tip(rust, donor)
    print(donor[1])
else:
    deadline = time.monotonic() + 30
    go_tip, rust_tip = tip(go, deadline), tip(rust, deadline)
    if go_tip is None or rust_tip is None or time.monotonic() >= deadline:
        raise SystemExit("unusable /get_tip response after Go reopen")
    if go_tip != rust_tip:
        mismatch(go_tip, rust_tip)
    if go_tip != (101, pinned_hash[0]):
        raise SystemExit(f"tip changed after Go reopen: expected=101:{pinned_hash[0]} observed={go_tip[0]}:{go_tip[1]}")
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        snapshots = [rpc(addr, "/peers", deadline) for addr in (go, rust)]
        if time.monotonic() < deadline and all(type(d.get("count")) is int and d["count"] == 0 and d.get("peers") == [] for d in snapshots):
            print(*go_tip, sep="\t")
            break
        time.sleep(max(0, min(1, deadline - time.monotonic())))
    else:
        raise SystemExit(f"timeout waiting for /peers isolation on {go} and {rust}")
PY
}

check_metrics() {
  local rpc_addr="$1"
  python3 - "${rpc_addr}" "${RPC_REQUEST_TIMEOUT_SECONDS}" <<'PY'
import re
import sys
import urllib.request

rpc_addr = sys.argv[1]
request_timeout = float(sys.argv[2])
expected = {
    "rubin_node_tip_height",
    "rubin_node_best_known_height",
    "rubin_node_in_ibd",
    "rubin_node_peer_count",
    "rubin_node_mempool_txs",
    "rubin_node_rpc_requests_total",
    "rubin_node_submit_tx_total",
}
try:
    with urllib.request.urlopen(f"http://{rpc_addr}/metrics", timeout=request_timeout) as resp:
        if resp.status != 200:
            raise SystemExit(f"/metrics returned status={resp.status} for {rpc_addr} with request_timeout={request_timeout}s")
        body = resp.read().decode("utf-8")
except Exception as exc:
    raise SystemExit(f"/metrics request failed for {rpc_addr} with request_timeout={request_timeout}s: {exc}")
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
"${GO_NODE_BIN}" --create-store --datadir "${GO_DATA_DIR}" --mine-address "${MINE_ADDRESS_HEX}" --mine-blocks 101 --mine-exit >"${MINE_LOG}" 2>&1

python3 -c 'import os, sys; sys.exit(bool(os.listdir(sys.argv[1])))' "${RUST_DATA_DIR}" 2>/dev/null || fail "Rust exact-empty preflight failed for ${RUST_DATA_DIR}"
echo "Starting Rust RPC node at ${RUST_RPC_ADDR}"
start_bg "${RUST_LOG}" "${RUST_NODE_BIN}" --create-store --datadir "${RUST_DATA_DIR}" --bind "127.0.0.1:0" --rpc-bind "${RUST_RPC_ADDR}"
wait_for_log "${RUST_LOG}" "rpc: listening=" 30
RUST_RPC_ADDR="$(extract_rpc_addr "${RUST_LOG}")"
RUST_P2P_ADDR="$(awk '/^p2p: listening=/ { sub(/^p2p: listening=/, ""); addr=$0; n++ } END { if (n == 1) print addr }' "${RUST_LOG}")"
[[ "${RUST_P2P_ADDR}" =~ ^127\.0\.0\.1:([1-9][0-9]{0,4})$ ]] &&
  (( BASH_REMATCH[1] <= 65535 )) || fail "missing or invalid Rust P2P listening banner in ${RUST_LOG}"

start_bg "${GO_DONOR_LOG}" "${GO_NODE_BIN}" --datadir "${GO_DATA_DIR}" --bind "127.0.0.1:0" --rpc-bind "${GO_RPC_BIND}" --peer "${RUST_P2P_ADDR}"
wait_for_log "${GO_DONOR_LOG}" "rpc: listening=" 30
DONOR_RPC_ADDR="$(extract_rpc_addr "${GO_DONOR_LOG}")"
DONOR_HASH="$(observe_pair "${DONOR_RPC_ADDR}" "${RUST_RPC_ADDR}")"
stop_bg 1 || fail "could not stop and reap Go donor"

echo "Starting Go RPC node at ${GO_RPC_BIND}"
start_bg "${GO_LOG}" "${GO_NODE_BIN}" --datadir "${GO_DATA_DIR}" --bind "127.0.0.1:0" --rpc-bind "${GO_RPC_BIND}"
wait_for_log "${GO_LOG}" "rpc: listening=" 30
GO_RPC_ADDR="$(extract_rpc_addr "${GO_LOG}")"
TIP="$(observe_pair "${GO_RPC_ADDR}" "${RUST_RPC_ADDR}" "${DONOR_HASH}")"
IFS=$'\t' read -r GO_HEIGHT GO_HASH <<<"${TIP}"

echo "Submitting deterministic tx against Go RPC"
GO_TX_HEX="$("${GO_TXGEN_BIN}" \
  --datadir "${GO_DATA_DIR}" \
  --from-key "${FROM_DER_HEX}" \
  --to-key "${TO_ADDRESS_HEX}" \
  --amount 1 \
  --fee "${DETERMINISTIC_TX_FEE}" \
  --submit-to "${GO_RPC_ADDR}")"
if [[ -z "${GO_TX_HEX}" ]]; then
  echo "go txgen produced empty tx hex" >&2
  exit 1
fi

echo "Submitting deterministic tx against Rust RPC"
RUST_TX_HEX="$("${GO_TXGEN_BIN}" \
  --datadir "${GO_DATA_DIR}" \
  --from-key "${FROM_DER_HEX}" \
  --to-key "${TO_ADDRESS_HEX}" \
  --amount 1 \
  --fee "${DETERMINISTIC_TX_FEE}" \
  --submit-to "${RUST_RPC_ADDR}")"
if [[ -z "${RUST_TX_HEX}" ]]; then
  echo "rust txgen produced empty tx hex" >&2
  exit 1
fi

check_metrics "${GO_RPC_ADDR}"
check_metrics "${RUST_RPC_ADDR}"

echo "PASS: Go/Rust devnet RPC parity smoke matched tip ${GO_HEIGHT}:${GO_HASH} and accepted tx via both clients"
