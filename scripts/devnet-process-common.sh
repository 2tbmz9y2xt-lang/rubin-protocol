#!/usr/bin/env bash

# Shared fail-closed process helpers for devnet evidence scripts.
# Source this file, then call rubin_process_init before using helpers.

RUBIN_PROCESS_ARTIFACT_ROOT="${RUBIN_PROCESS_ARTIFACT_ROOT:-}"
RUBIN_PROCESS_ARTIFACT_PARENT="${RUBIN_PROCESS_ARTIFACT_PARENT:-}"
RUBIN_PROCESS_KEEP_ARTIFACTS="${RUBIN_PROCESS_KEEP_ARTIFACTS:-${KEEP_TMP:-0}}"
RUBIN_PROCESS_STOP_GRACE_SECONDS="${RUBIN_PROCESS_STOP_GRACE_SECONDS:-5}"
RUBIN_PROCESS_PIDS=()
RUBIN_PROCESS_LOGS=()
RUBIN_PROCESS_LAST_PID=""
_RUBIN_PROCESS_CREATED_PARENT=""

_rubin_process_error() { echo "$*" >&2; }

_rubin_process_uint() {
  [[ "${2:-}" =~ ^[0-9]+$ ]] || { _rubin_process_error "$1 must be a non-negative integer: ${2:-<empty>}"; return 1; }
}

_rubin_process_pid() { [[ "${1:-}" =~ ^[1-9][0-9]*$ ]]; }

_rubin_process_has_parent_ref() { case "/${1:-}/" in *"/../"*) return 0 ;; *) return 1 ;; esac; }

_rubin_process_require_init() {
  [[ -n "${RUBIN_PROCESS_ARTIFACT_ROOT}" && -d "${RUBIN_PROCESS_ARTIFACT_ROOT}" ]] || { _rubin_process_error "rubin_process_init must run before process helpers"; return 1; }
}

_rubin_process_resolve_log() {
  local log_file="${1:-}"
  _rubin_process_require_init || return 1
  [[ -n "${log_file}" ]] || { _rubin_process_error "log path must not be empty"; return 1; }
  [[ "${log_file}" == /* ]] || log_file="${RUBIN_PROCESS_ARTIFACT_ROOT}/${log_file}"
  ! _rubin_process_has_parent_ref "${log_file}" || { _rubin_process_error "log path must not contain '..': ${log_file}"; return 1; }
  case "${log_file}" in
    "${RUBIN_PROCESS_ARTIFACT_ROOT}"/*) printf '%s\n' "${log_file}" ;;
    *) _rubin_process_error "log path must stay under artifact root: ${log_file}"; return 1 ;;
  esac
}

rubin_process_init() {
  local prefix="${1:-rubin-devnet-process}"
  local safe_prefix="${prefix//[^[:alnum:]._-]/_}"
  local parent="${RUBIN_PROCESS_ARTIFACT_PARENT:-${RUBIN_PROCESS_ARTIFACT_ROOT:-${TMPDIR:-/tmp}}}"

  [[ -z "$(trap -p EXIT || true)" ]] || {
    _rubin_process_error "refusing to overwrite existing EXIT trap"
    return 1
  }
  [[ -n "${safe_prefix}" && "${safe_prefix}" != "." && "${safe_prefix}" != ".." ]] || safe_prefix="rubin-devnet-process"
  [[ "${parent}" == /* && "${parent}" != "/" && "${parent}" != "." && "${parent}" != ".." ]] && ! _rubin_process_has_parent_ref "${parent}" || {
    _rubin_process_error "unsafe artifact parent: ${parent:-<empty>}"
    return 1
  }
  _rubin_process_uint "RUBIN_PROCESS_STOP_GRACE_SECONDS" "${RUBIN_PROCESS_STOP_GRACE_SECONDS}" || return 1
  mkdir -p "${parent}" || { _rubin_process_error "failed to create artifact parent: ${parent}"; return 1; }

  _RUBIN_PROCESS_CREATED_PARENT="${parent%/}"
  if ! RUBIN_PROCESS_ARTIFACT_ROOT="$(mktemp -d "${_RUBIN_PROCESS_CREATED_PARENT}/${safe_prefix}.XXXXXX")"; then
    RUBIN_PROCESS_ARTIFACT_ROOT=""
    _rubin_process_error "failed to create artifact root under ${_RUBIN_PROCESS_CREATED_PARENT}"
    return 1
  fi
  [[ -d "${RUBIN_PROCESS_ARTIFACT_ROOT}" ]] || {
    _rubin_process_error "artifact root is not a directory: ${RUBIN_PROCESS_ARTIFACT_ROOT}"
    RUBIN_PROCESS_ARTIFACT_ROOT=""
    return 1
  }
  RUBIN_PROCESS_PIDS=()
  RUBIN_PROCESS_LOGS=()
  RUBIN_PROCESS_LAST_PID=""
  trap rubin_process_exit_trap EXIT
}

rubin_process_is_alive() {
  _rubin_process_pid "${1:-}" || return 1
  kill -0 "$1" >/dev/null 2>&1
}

rubin_process_start() {
  local log_file log_dir started_pid
  (( $# >= 2 )) || { _rubin_process_error "rubin_process_start requires a log path and command"; return 1; }
  log_file="$(_rubin_process_resolve_log "$1")" || return 1
  shift
  log_dir="$(dirname "${log_file}")"
  mkdir -p "${log_dir}" || { _rubin_process_error "failed to create log directory: ${log_dir}"; return 1; }

  RUBIN_PROCESS_LAST_PID=""
  "$@" >"${log_file}" 2>&1 &
  started_pid="$!"
  sleep 0.2
  if ! rubin_process_is_alive "${started_pid}"; then
    wait "${started_pid}" >/dev/null 2>&1 || true
    _rubin_process_error "background command exited before registration: ${log_file}"
    return 1
  fi
  RUBIN_PROCESS_LAST_PID="${started_pid}"
  RUBIN_PROCESS_PIDS+=("${started_pid}")
  RUBIN_PROCESS_LOGS+=("${log_file}")
}

rubin_process_stop_pid() {
  local pid="${1:-}" deadline
  _rubin_process_pid "${pid}" || return 1
  if rubin_process_is_alive "${pid}"; then
    kill "${pid}" >/dev/null 2>&1 || true
    _rubin_process_uint "RUBIN_PROCESS_STOP_GRACE_SECONDS" "${RUBIN_PROCESS_STOP_GRACE_SECONDS}" || return 1
    deadline=$((SECONDS + RUBIN_PROCESS_STOP_GRACE_SECONDS))
    while rubin_process_is_alive "${pid}" && (( SECONDS < deadline )); do sleep 1; done
  fi
  rubin_process_is_alive "${pid}" && kill -KILL "${pid}" >/dev/null 2>&1 || true
  wait "${pid}" >/dev/null 2>&1 || true
}

rubin_process_stop_all() {
  local i
  for ((i=${#RUBIN_PROCESS_PIDS[@]} - 1; i >= 0; i--)); do
    rubin_process_stop_pid "${RUBIN_PROCESS_PIDS[$i]}" || return 1
  done
}

rubin_process_wait_for_log() {
  local file="${1:-}" needle="${2:-}" timeout="${3:-}" pid="${4:-}" deadline
  [[ -n "${file}" && -n "${needle}" ]] || { _rubin_process_error "rubin_process_wait_for_log requires file, needle, timeout"; return 1; }
  file="$(_rubin_process_resolve_log "${file}")" || return 1
  _rubin_process_uint "timeout" "${timeout}" || return 1
  deadline=$((SECONDS + timeout))
  while (( SECONDS < deadline )); do
    [[ -f "${file}" ]] && grep -F -q -- "${needle}" "${file}" && return 0
    if [[ -n "${pid}" ]] && ! rubin_process_is_alive "${pid}"; then
      _rubin_process_error "process ${pid} exited before ${needle} appeared in ${file}"
      return 1
    fi
    sleep 1
  done
  _rubin_process_error "timeout waiting for ${needle} in ${file}"
  return 1
}

rubin_process_extract_rpc_addr() {
  local file="${1:-}" addr
  file="$(_rubin_process_resolve_log "${file}")" || return 1
  [[ -r "${file}" ]] || { _rubin_process_error "rpc log file is missing or unreadable: ${file:-<empty>}"; return 1; }
  if ! addr="$(sed -n 's/.*rpc: listening=//p' "${file}" | tail -n 1 | tr -d '[:space:]')"; then
    _rubin_process_error "failed to extract rpc listening banner from ${file}"
    return 1
  fi
  [[ -n "${addr}" ]] || { _rubin_process_error "missing rpc listening banner in ${file}"; return 1; }
  printf '%s\n' "${addr}"
}

rubin_process_wait_for_rpc_ready() {
  local rpc_addr="${1:-}" timeout="${2:-}" deadline
  [[ -n "${rpc_addr}" && "${rpc_addr}" != *[[:space:]/]* ]] || { _rubin_process_error "invalid rpc address: ${rpc_addr:-<empty>}"; return 1; }
  _rubin_process_uint "timeout" "${timeout}" || return 1
  command -v python3 >/dev/null 2>&1 || { _rubin_process_error "python3 is required to poll /get_tip"; return 1; }
  deadline=$((SECONDS + timeout))
  while (( SECONDS < deadline )); do
    if python3 -c 'import json,sys,urllib.request as u; r=u.urlopen(f"http://{sys.argv[1]}/get_tip", timeout=2); json.load(r); sys.exit(0 if r.status == 200 else 1)' "${rpc_addr}" 2>/dev/null; then
      return 0
    fi
    sleep 1
  done
  _rubin_process_error "timeout waiting for /get_tip on ${rpc_addr}"
  return 1
}

rubin_process_dump_artifacts() {
  local log_file
  _rubin_process_error "FAIL: artifacts preserved at ${RUBIN_PROCESS_ARTIFACT_ROOT:-<unset>}"
  for log_file in "${RUBIN_PROCESS_LOGS[@]:-}"; do
    [[ -f "${log_file}" ]] || continue
    _rubin_process_error "----- $(basename "${log_file}") -----"
    tail -n 80 "${log_file}" >&2 || true
  done
}

rubin_process_cleanup() {
  local status="${1:-0}" cleanup_status=0
  _rubin_process_uint "status" "${status}" || return 1
  rubin_process_stop_all || cleanup_status=$?
  if [[ "${status}" != "0" ]]; then rubin_process_dump_artifacts; return "${status}"; fi
  [[ "${RUBIN_PROCESS_KEEP_ARTIFACTS}" == "1" ]] && {
    echo "OK: artifacts preserved at ${RUBIN_PROCESS_ARTIFACT_ROOT}"
    return "${cleanup_status}"
  }
  [[ -n "${_RUBIN_PROCESS_CREATED_PARENT}" && -n "${RUBIN_PROCESS_ARTIFACT_ROOT}" ]] && ! _rubin_process_has_parent_ref "${RUBIN_PROCESS_ARTIFACT_ROOT}" || {
    _rubin_process_error "refusing cleanup without initialized artifact paths or with parent traversal"
    return 1
  }
  case "${RUBIN_PROCESS_ARTIFACT_ROOT}" in
    "${_RUBIN_PROCESS_CREATED_PARENT}"/*) ;;
    *) _rubin_process_error "refusing to remove unsafe artifact root: ${RUBIN_PROCESS_ARTIFACT_ROOT}"; return 1 ;;
  esac
  rm -rf -- "${RUBIN_PROCESS_ARTIFACT_ROOT}" || cleanup_status=$?
  return "${cleanup_status}"
}

rubin_process_exit_trap() {
  local status=$? cleanup_status=0
  rubin_process_cleanup "${status}" || cleanup_status=$?
  [[ "${status}" != "0" ]] && exit "${status}"
  exit "${cleanup_status}"
}
