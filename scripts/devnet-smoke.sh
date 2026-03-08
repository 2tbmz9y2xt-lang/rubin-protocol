#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEV_ENV="${REPO_ROOT}/scripts/dev-env.sh"
GO_MODULE_ROOT="${REPO_ROOT}/clients/go"
TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/rubin-devnet-smoke.XXXXXX")"
BIN="${TMP_ROOT}/rubin-node"
GO_BUILD_CACHE="${TMP_ROOT}/go-build"
KEEP_TMP="${KEEP_TMP:-0}"

NODE_A_DIR="${TMP_ROOT}/node-a"
NODE_B_DIR="${TMP_ROOT}/node-b"
NODE_C_DIR="${TMP_ROOT}/node-c"

NODE_A_RPC_ADDR="${NODE_A_RPC_ADDR:-127.0.0.1:0}"
NODE_B_RPC_ADDR="${NODE_B_RPC_ADDR:-127.0.0.1:0}"
NODE_C_RPC_ADDR="${NODE_C_RPC_ADDR:-127.0.0.1:0}"

NODE_A_LOG="${TMP_ROOT}/node-a.log"
NODE_B_LOG="${TMP_ROOT}/node-b.log"
NODE_C_LOG="${TMP_ROOT}/node-c.log"
NODE_A_INSPECT="${TMP_ROOT}/node-a.inspect.log"
NODE_B_INSPECT="${TMP_ROOT}/node-b.inspect.log"
NODE_C_INSPECT="${TMP_ROOT}/node-c.inspect.log"

PIDS=()
LAST_PID=""

cleanup() {
  local status=$?
  for pid in "${PIDS[@]:-}"; do
    if kill -0 "${pid}" >/dev/null 2>&1; then
      kill "${pid}" >/dev/null 2>&1 || true
      wait "${pid}" >/dev/null 2>&1 || true
    fi
  done
  if [[ ${status} -ne 0 ]]; then
    echo "FAIL: logs preserved at ${TMP_ROOT}" >&2
    for log in "${NODE_A_LOG}" "${NODE_B_LOG}" "${NODE_C_LOG}"; do
      if [[ -f "${log}" ]]; then
        echo "----- $(basename "${log}") -----" >&2
        tail -n 40 "${log}" >&2 || true
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

wait_for_log() {
  local file="$1"
  local pattern="$2"
  local timeout="$3"
  local pid="${4:-}"
  local deadline=$((SECONDS + timeout))
  while (( SECONDS < deadline )); do
    if [[ -f "${file}" ]] && grep -q "${pattern}" "${file}"; then
      return 0
    fi
    if [[ -n "${pid}" ]] && ! kill -0 "${pid}" >/dev/null 2>&1; then
      echo "process ${pid} exited before ${pattern} appeared in ${file}" >&2
      return 1
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

wait_for_height() {
  local datadir="$1"
  local want_height="$2"
  local timeout="$3"
  local deadline=$((SECONDS + timeout))
  while (( SECONDS < deadline )); do
    if python3 - "${datadir}" "${want_height}" <<'PY'
import json
import pathlib
import sys

datadir = pathlib.Path(sys.argv[1])
want_height = int(sys.argv[2])
path = datadir / "chainstate.json"
if not path.exists():
    raise SystemExit(1)
data = json.loads(path.read_text())
if data.get("has_tip") and data.get("height") == want_height:
    raise SystemExit(0)
raise SystemExit(1)
PY
    then
      return 0
    fi
    sleep 1
  done
  echo "timeout waiting for height=${want_height} in ${datadir}" >&2
  return 1
}

wait_for_rpc_ready() {
  local rpc_addr="$1"
  local timeout="$2"
  local deadline=$((SECONDS + timeout))
  while (( SECONDS < deadline )); do
    if python3 - "${rpc_addr}" <<'PY'
import json
import sys
import urllib.request

rpc_addr = sys.argv[1]
with urllib.request.urlopen(f"http://{rpc_addr}/get_tip", timeout=2) as resp:
    if resp.status != 200:
        raise SystemExit(1)
    json.loads(resp.read().decode("utf-8"))
raise SystemExit(0)
PY
    then
      return 0
    fi
    sleep 1
  done
  echo "timeout waiting for RPC readiness at ${rpc_addr}" >&2
  return 1
}

wait_for_rpc_height() {
  local rpc_addr="$1"
  local want_height="$2"
  local timeout="$3"
  local deadline=$((SECONDS + timeout))
  while (( SECONDS < deadline )); do
    if python3 - "${rpc_addr}" "${want_height}" <<'PY'
import json
import sys
import urllib.request

rpc_addr = sys.argv[1]
want_height = int(sys.argv[2])
with urllib.request.urlopen(f"http://{rpc_addr}/get_tip", timeout=2) as resp:
    if resp.status != 200:
        raise SystemExit(1)
    data = json.loads(resp.read().decode("utf-8"))
if data.get("has_tip") and data.get("height") == want_height:
    raise SystemExit(0)
raise SystemExit(1)
PY
    then
      return 0
    fi
    sleep 1
  done
  echo "timeout waiting for RPC height=${want_height} at ${rpc_addr}" >&2
  return 1
}

read_state_tsv() {
  local datadir="$1"
  python3 - "${datadir}" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1]) / "chainstate.json"
data = json.loads(path.read_text())
print(
    data["height"],
    data["tip_hash"],
    len(data["utxos"]),
    data["already_generated"],
    "true" if data["has_tip"] else "false",
    sep="\t",
)
PY
}

inspect_node() {
  local name="$1"
  local datadir="$2"
  local inspect_log="$3"

  "${BIN}" --dry-run --datadir "${datadir}" >"${inspect_log}" 2>&1

  local height tip utxos already_generated has_tip
  IFS=$'\t' read -r height tip utxos already_generated has_tip < <(read_state_tsv "${datadir}")
  local chainstate_sha
  chainstate_sha="$(shasum -a 256 "${datadir}/chainstate.json" | awk '{print $1}')"

  echo "SUMMARY ${name} has_tip=${has_tip} height=${height} tip=${tip} utxos=${utxos} already_generated=${already_generated} chainstate_sha256=${chainstate_sha}"
  grep -E '^(chainstate:|blockstore:)' "${inspect_log}"
}

start_node() {
  local log_file="$1"
  shift
  "${BIN}" "$@" >"${log_file}" 2>&1 &
  LAST_PID="$!"
  PIDS+=("${LAST_PID}")
}

echo "Building rubin-node binary into ${BIN}"
mkdir -p "${GO_BUILD_CACHE}"
GOCACHE="${GO_BUILD_CACHE}" "${DEV_ENV}" -- go -C "${GO_MODULE_ROOT}" build -o "${BIN}" ./cmd/rubin-node

mkdir -p "${NODE_A_DIR}" "${NODE_B_DIR}" "${NODE_C_DIR}"

NODE_A_PORT="$((29110 + ($$ % 1000)))"
NODE_A_ADDR="127.0.0.1:${NODE_A_PORT}"

echo "Starting node A at ${NODE_A_ADDR}"
start_node "${NODE_A_LOG}" --datadir "${NODE_A_DIR}" --bind "${NODE_A_ADDR}" --rpc-bind "${NODE_A_RPC_ADDR}" --mine-blocks 10
NODE_A_PID="${LAST_PID}"
wait_for_log "${NODE_A_LOG}" "rpc: listening=" 30 "${NODE_A_PID}"
NODE_A_RPC_ADDR="$(extract_rpc_addr "${NODE_A_LOG}")"
wait_for_log "${NODE_A_LOG}" "rubin-node skeleton running" 30 "${NODE_A_PID}"
wait_for_rpc_ready "${NODE_A_RPC_ADDR}" 30

MINED_LINES="$(grep -c '^mined:' "${NODE_A_LOG}" || true)"
if [[ "${MINED_LINES}" != "10" ]]; then
  echo "node A mined lines=${MINED_LINES}, want 10" >&2
  exit 1
fi

IFS=$'\t' read -r NODE_A_HEIGHT _ _ _ NODE_A_HAS_TIP < <(read_state_tsv "${NODE_A_DIR}")
if [[ "${NODE_A_HAS_TIP}" != "true" ]]; then
  echo "node A has no tip after mining" >&2
  exit 1
fi

echo "Starting node B"
start_node "${NODE_B_LOG}" --datadir "${NODE_B_DIR}" --bind "127.0.0.1:0" --rpc-bind "${NODE_B_RPC_ADDR}" --peers "${NODE_A_ADDR}"
NODE_B_PID="${LAST_PID}"
echo "Starting node C"
start_node "${NODE_C_LOG}" --datadir "${NODE_C_DIR}" --bind "127.0.0.1:0" --rpc-bind "${NODE_C_RPC_ADDR}" --peers "${NODE_A_ADDR}"
NODE_C_PID="${LAST_PID}"

wait_for_log "${NODE_B_LOG}" "rpc: listening=" 30 "${NODE_B_PID}"
NODE_B_RPC_ADDR="$(extract_rpc_addr "${NODE_B_LOG}")"
wait_for_log "${NODE_C_LOG}" "rpc: listening=" 30 "${NODE_C_PID}"
NODE_C_RPC_ADDR="$(extract_rpc_addr "${NODE_C_LOG}")"
wait_for_log "${NODE_B_LOG}" "rubin-node skeleton running" 30 "${NODE_B_PID}"
wait_for_log "${NODE_C_LOG}" "rubin-node skeleton running" 30 "${NODE_C_PID}"
wait_for_rpc_ready "${NODE_B_RPC_ADDR}" 30
wait_for_rpc_ready "${NODE_C_RPC_ADDR}" 30
wait_for_height "${NODE_B_DIR}" "${NODE_A_HEIGHT}" 30
wait_for_height "${NODE_C_DIR}" "${NODE_A_HEIGHT}" 30
wait_for_rpc_height "${NODE_A_RPC_ADDR}" "${NODE_A_HEIGHT}" 30
wait_for_rpc_height "${NODE_B_RPC_ADDR}" "${NODE_A_HEIGHT}" 30
wait_for_rpc_height "${NODE_C_RPC_ADDR}" "${NODE_A_HEIGHT}" 30

inspect_node "node-a" "${NODE_A_DIR}" "${NODE_A_INSPECT}"
inspect_node "node-b" "${NODE_B_DIR}" "${NODE_B_INSPECT}"
inspect_node "node-c" "${NODE_C_DIR}" "${NODE_C_INSPECT}"

A_SHA="$(shasum -a 256 "${NODE_A_DIR}/chainstate.json" | awk '{print $1}')"
B_SHA="$(shasum -a 256 "${NODE_B_DIR}/chainstate.json" | awk '{print $1}')"
C_SHA="$(shasum -a 256 "${NODE_C_DIR}/chainstate.json" | awk '{print $1}')"

if [[ "${A_SHA}" != "${B_SHA}" || "${A_SHA}" != "${C_SHA}" ]]; then
  echo "chainstate mismatch: A=${A_SHA} B=${B_SHA} C=${C_SHA}" >&2
  exit 1
fi

echo "PASS: 3-process devnet smoke sync converged with identical chainstate digest ${A_SHA}"
