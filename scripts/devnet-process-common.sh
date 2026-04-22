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
  local safe_prefix="${prefix//\//_}"
  safe_prefix="${safe_prefix//\\/_}"
  local artifact_parent="${RUBIN_PROCESS_ARTIFACT_ROOT:-${TMPDIR:-/tmp}}"

  if [[ -z "${safe_prefix}" || "${safe_prefix}" == "." || "${safe_prefix}" == ".." ]]; then
    safe_prefix="rubin-devnet-process"
  fi
  if [[ -z "${artifact_parent}" || "${artifact_parent}" == "/" || "${artifact_parent}" == "." ]]; then
    echo "unsafe artifact parent: ${artifact_parent:-<empty>}" >&2
    return 1
  fi

  mkdir -p "${artifact_parent}"
  if ! RUBIN_PROCESS_ARTIFACT_ROOT="$(mktemp -d "${artifact_parent%/}/${safe_prefix}.XXXXXX")"; then
    echo "failed to create artifact root under ${artifact_parent}" >&2
    return 1
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
  local needle="$2"
  local timeout="$3"
  local pid="${4:-}"
  local deadline=$((SECONDS + timeout))

  while (( SECONDS < deadline )); do
    if [[ -f "${file}" ]] && grep -F -q -- "${needle}" "${file}"; then
      return 0
    fi
    if [[ -n "${pid}" ]] && ! rubin_process_is_alive "${pid}"; then
      echo "process ${pid} exited before ${needle} appeared in ${file}" >&2
      return 1
    fi
    sleep 1
  done

  echo "timeout waiting for ${needle} in ${file}" >&2
  return 1
}

rubin_process_extract_rpc_addr() {
  local file="$1"
  local addr

  if [[ ! -r "${file}" ]]; then
    echo "rpc log file is missing or unreadable: ${file}" >&2
    return 1
  fi
  if ! addr="$(awk -F= '/rpc: listening=/{print $2}' "${file}" | tail -n 1 | tr -d '[:space:]')"; then
    echo "failed to extract rpc listening banner from ${file}" >&2
    return 1
  fi
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

  if ! command -v python3 >/dev/null 2>&1; then
    echo "python3 is required to poll /get_tip" >&2
    return 1
  fi

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
  if [[ -z "${RUBIN_PROCESS_ARTIFACT_ROOT}" ||
        "${RUBIN_PROCESS_ARTIFACT_ROOT}" == "/" ||
        "${RUBIN_PROCESS_ARTIFACT_ROOT}" == "." ]]; then
    echo "refusing to remove unsafe artifact root: ${RUBIN_PROCESS_ARTIFACT_ROOT:-<empty>}" >&2
    return 1
  fi
  rm -rf -- "${RUBIN_PROCESS_ARTIFACT_ROOT}"
}

rubin_process_exit_trap() {
  local status=$?
  local cleanup_status=0
  rubin_process_cleanup "${status}" || cleanup_status=$?
  if [[ "${status}" != "0" ]]; then
    exit "${status}"
  fi
  exit "${cleanup_status}"
}

rubin_process_self_test() {
  set -euo pipefail

  local parent_root
  parent_root="$(mktemp -d "${TMPDIR:-/tmp}/rubin-devnet-process-parent.XXXXXX")"
  RUBIN_PROCESS_ARTIFACT_ROOT="${parent_root}"
  rubin_process_init "unsafe/prefix"
  if [[ "${RUBIN_PROCESS_ARTIFACT_ROOT}" == "${parent_root}" ||
        "${RUBIN_PROCESS_ARTIFACT_ROOT}" != "${parent_root}/"* ]]; then
    echo "custom artifact parent was not isolated: ${RUBIN_PROCESS_ARTIFACT_ROOT}" >&2
    return 1
  fi
  rubin_process_cleanup 0
  trap - EXIT
  if [[ ! -d "${parent_root}" ]]; then
    echo "custom artifact parent was removed: ${parent_root}" >&2
    return 1
  fi
  rm -rf -- "${parent_root}"
  RUBIN_PROCESS_ARTIFACT_ROOT=""

  local parent_file
  parent_file="$(mktemp "${TMPDIR:-/tmp}/rubin-devnet-process-parent-file.XXXXXX")"
  RUBIN_PROCESS_ARTIFACT_ROOT="${parent_file}"
  if rubin_process_init "bad-parent" 2>"${parent_file}.err"; then
    echo "artifact root creation unexpectedly succeeded under file parent" >&2
    return 1
  fi
  rm -f -- "${parent_file}" "${parent_file}.err"
  RUBIN_PROCESS_ARTIFACT_ROOT=""

  if bash -c 'source "$1"; rubin_process_init trap-fail; RUBIN_PROCESS_ARTIFACT_ROOT=/; exit 0' bash "${BASH_SOURCE[0]}" >/dev/null 2>&1; then
    echo "exit trap ignored cleanup failure" >&2
    return 1
  fi

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
