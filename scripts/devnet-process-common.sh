#!/usr/bin/env bash

# Shared fail-closed process helpers for devnet evidence scripts.
# Source this file from scenario scripts, then call rubin_process_init.

RUBIN_PROCESS_ARTIFACT_ROOT="${RUBIN_PROCESS_ARTIFACT_ROOT:-}"
RUBIN_PROCESS_KEEP_ARTIFACTS="${RUBIN_PROCESS_KEEP_ARTIFACTS:-${KEEP_TMP:-0}}"
RUBIN_PROCESS_STOP_GRACE_SECONDS="${RUBIN_PROCESS_STOP_GRACE_SECONDS:-5}"
RUBIN_PROCESS_PIDS=()
RUBIN_PROCESS_LOGS=()
RUBIN_PROCESS_LAST_PID=""

rubin_process_init() {
  local prefix="${1:-rubin-devnet-process}"

  if [[ -z "${RUBIN_PROCESS_ARTIFACT_ROOT}" ]]; then
    RUBIN_PROCESS_ARTIFACT_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/${prefix}.XXXXXX")"
  else
    mkdir -p "${RUBIN_PROCESS_ARTIFACT_ROOT}"
  fi

  RUBIN_PROCESS_PIDS=()
  RUBIN_PROCESS_LOGS=()
  RUBIN_PROCESS_LAST_PID=""
  trap rubin_process_exit_trap EXIT
}

rubin_process_register_log() {
  local log_file="$1"
  RUBIN_PROCESS_LOGS+=("${log_file}")
}

rubin_process_start() {
  local log_file="$1"
  shift

  mkdir -p "$(dirname "${log_file}")"
  rubin_process_register_log "${log_file}"
  "$@" >"${log_file}" 2>&1 &
  RUBIN_PROCESS_LAST_PID="$!"
  RUBIN_PROCESS_PIDS+=("${RUBIN_PROCESS_LAST_PID}")
}

rubin_process_is_alive() {
  local pid="$1"
  kill -0 "${pid}" >/dev/null 2>&1
}

rubin_process_stop_pid() {
  local pid="$1"

  if rubin_process_is_alive "${pid}"; then
    kill "${pid}" >/dev/null 2>&1 || true
    local deadline=$((SECONDS + RUBIN_PROCESS_STOP_GRACE_SECONDS))
    while rubin_process_is_alive "${pid}" && (( SECONDS < deadline )); do
      sleep 1
    done
  fi
  if rubin_process_is_alive "${pid}"; then
    kill -KILL "${pid}" >/dev/null 2>&1 || true
  fi
  wait "${pid}" >/dev/null 2>&1 || true
}

rubin_process_stop_all() {
  local pid
  for pid in "${RUBIN_PROCESS_PIDS[@]:-}"; do
    rubin_process_stop_pid "${pid}"
  done
}

rubin_process_wait_for_log() {
  local file="$1"
  local pattern="$2"
  local timeout="$3"
  local pid="${4:-}"
  local deadline=$((SECONDS + timeout))

  while (( SECONDS < deadline )); do
    if [[ -f "${file}" ]] && grep -q "${pattern}" "${file}"; then
      return 0
    fi
    if [[ -n "${pid}" ]] && ! rubin_process_is_alive "${pid}"; then
      echo "process ${pid} exited before ${pattern} appeared in ${file}" >&2
      return 1
    fi
    sleep 1
  done

  echo "timeout waiting for ${pattern} in ${file}" >&2
  return 1
}

rubin_process_extract_rpc_addr() {
  local file="$1"
  local addr

  addr="$(awk -F= '/rpc: listening=/{print $2}' "${file}" | tail -n 1 | tr -d '[:space:]')"
  if [[ -z "${addr}" ]]; then
    echo "missing rpc listening banner in ${file}" >&2
    return 1
  fi
  printf '%s\n' "${addr}"
}

rubin_process_wait_for_rpc_ready() {
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
    json.load(resp)
PY
    then
      return 0
    fi
    sleep 1
  done

  echo "timeout waiting for /get_tip on ${rpc_addr}" >&2
  return 1
}

rubin_process_dump_artifacts() {
  local log_file

  echo "FAIL: artifacts preserved at ${RUBIN_PROCESS_ARTIFACT_ROOT}" >&2
  for log_file in "${RUBIN_PROCESS_LOGS[@]:-}"; do
    if [[ -f "${log_file}" ]]; then
      echo "----- $(basename "${log_file}") -----" >&2
      tail -n 80 "${log_file}" >&2 || true
    fi
  done
}

rubin_process_cleanup() {
  local status="$1"

  rubin_process_stop_all
  if [[ "${status}" != "0" ]]; then
    rubin_process_dump_artifacts
    return "${status}"
  fi
  if [[ "${RUBIN_PROCESS_KEEP_ARTIFACTS}" == "1" ]]; then
    echo "OK: artifacts preserved at ${RUBIN_PROCESS_ARTIFACT_ROOT}"
    return 0
  fi
  rm -rf "${RUBIN_PROCESS_ARTIFACT_ROOT}"
}

rubin_process_exit_trap() {
  local status=$?
  rubin_process_cleanup "${status}"
  exit "${status}"
}

rubin_process_self_test() {
  set -euo pipefail

  rubin_process_init "rubin-devnet-process-selftest"
  local log_file="${RUBIN_PROCESS_ARTIFACT_ROOT}/selftest.log"
  local pid
  rubin_process_start "${log_file}" bash -c 'trap "exit 0" TERM; echo "rpc: listening=127.0.0.1:12345"; while :; do sleep 1; done'
  pid="${RUBIN_PROCESS_LAST_PID}"
  rubin_process_wait_for_log "${log_file}" "rpc: listening=" 5 "${pid}"

  local addr
  addr="$(rubin_process_extract_rpc_addr "${log_file}")"
  if [[ "${addr}" != "127.0.0.1:12345" ]]; then
    echo "unexpected rpc addr: ${addr}" >&2
    return 1
  fi

  rubin_process_stop_pid "${pid}"
  echo "PASS: devnet process common self-test"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  case "${1:-}" in
    --self-test)
      rubin_process_self_test
      ;;
    *)
      echo "usage: $0 --self-test" >&2
      exit 2
      ;;
  esac
fi
