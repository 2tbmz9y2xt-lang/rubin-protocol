#!/usr/bin/env bash

# Shared fail-closed process helpers for devnet evidence scripts.
# Source this file, then call rubin_process_init before using helpers.

: "${RUBIN_PROCESS_ARTIFACT_ROOT:=}"
: "${RUBIN_PROCESS_ARTIFACT_PARENT:=}"
: "${RUBIN_PROCESS_KEEP_ARTIFACTS:=${KEEP_TMP:-0}}"
: "${RUBIN_PROCESS_STOP_GRACE_SECONDS:=5}"
_rubin_process_existing_exit_trap="$(trap -p EXIT || true)"
if [[ "${_rubin_process_existing_exit_trap}" == *"rubin_process_exit_trap"* ]]; then
  echo "refusing to re-source devnet process helper after rubin_process_init" >&2
  unset _rubin_process_existing_exit_trap
  if ! return 1 2>/dev/null; then
    # shellcheck disable=SC2317 # reachable only when the helper is executed instead of sourced.
    exit 1
  fi
fi
unset _rubin_process_existing_exit_trap
RUBIN_PROCESS_PIDS=()
RUBIN_PROCESS_STARTED_PIDS=()
RUBIN_PROCESS_STARTED_EXEC_REALPATHS=()
RUBIN_PROCESS_LOGS=()
RUBIN_PROCESS_LAST_PID=""
RUBIN_PROCESS_TOPOLOGY_NAMES=()
RUBIN_PROCESS_TOPOLOGY_IMPLS=()
RUBIN_PROCESS_TOPOLOGY_PIDS=()
RUBIN_PROCESS_TOPOLOGY_ENDPOINTS=()
RUBIN_PROCESS_TOPOLOGY_EXEC_REALPATHS=()
RUBIN_PROCESS_PROXY_SOURCES=()
RUBIN_PROCESS_PROXY_TARGETS=()
RUBIN_PROCESS_PROXY_ADDRS=()
RUBIN_PROCESS_PROXY_TARGET_FILES=()
_RUBIN_PROCESS_CREATED_PARENT=""
_RUBIN_PROCESS_CREATED_ROOT=""
_RUBIN_PROCESS_CREATED_ROOT_REAL=""
_RUBIN_PROCESS_STOP_GRACE_SECONDS_DECIMAL=""

_rubin_process_error() { printf '%s\n' "$*" >&2; }

_rubin_process_uint() {
  [[ "${2:-}" =~ ^[0-9]+$ ]] || { _rubin_process_error "$1 must be a non-negative integer: ${2:-<empty>}"; return 1; }
}

_rubin_process_uint_decimal() {
  local value max=2147483647
  _rubin_process_uint "$1" "$2" || return 1
  value="$2"
  while [[ "${#value}" -gt 1 && "${value:0:1}" == "0" ]]; do value="${value:1}"; done
  if (( ${#value} > ${#max} )) || { (( ${#value} == ${#max} )) && (( 10#${value} > max )); }; then
    _rubin_process_error "$1 is too large: $2"
    return 1
  fi
  printf '%s\n' "$((10#${value}))"
}

_rubin_process_pid() { [[ "${1:-}" =~ ^[1-9][0-9]*$ ]]; }
_rubin_process_name() { [[ "${1:-}" =~ ^node-[a-z0-9][a-z0-9-]{0,30}$ ]]; }
_rubin_process_implementation() { [[ "${1:-}" == "go" || "${1:-}" == "rust" ]]; }
_rubin_process_loopback_endpoint() {
  local endpoint="${1:-}" host port port_dec
  [[ "${endpoint}" == 127.0.0.1:* ]] || return 1
  host="${endpoint%:*}"
  port="${endpoint##*:}"
  [[ "${host}" == "127.0.0.1" && "${port}" =~ ^[0-9]+$ ]] || return 1
  port_dec="$(_rubin_process_uint_decimal port "${port}" 2>/dev/null)" || return 1
  (( port_dec >= 1 && port_dec <= 65535 ))
}

_rubin_process_has_parent_ref() { case "/${1:-}/" in *"/../"*) return 0 ;; *) return 1 ;; esac; }

_rubin_process_physical_dir() {
  local dir="${1:-}"
  [[ -n "${dir}" && -d "${dir}" ]] || { _rubin_process_error "directory does not exist: ${dir:-<empty>}"; return 1; }
  (cd "${dir}" && pwd -P) || { _rubin_process_error "failed to resolve directory: ${dir}"; return 1; }
}

_rubin_process_require_init() {
  [[ -n "${RUBIN_PROCESS_ARTIFACT_ROOT}" && -d "${RUBIN_PROCESS_ARTIFACT_ROOT}" ]] || { _rubin_process_error "rubin_process_init must run before process helpers"; return 1; }
  [[ -n "${_RUBIN_PROCESS_CREATED_ROOT}" && "${RUBIN_PROCESS_ARTIFACT_ROOT}" == "${_RUBIN_PROCESS_CREATED_ROOT}" ]] || { _rubin_process_error "rubin_process_init must complete successfully before process helpers"; return 1; }
  [[ -n "${_RUBIN_PROCESS_CREATED_ROOT_REAL}" && "$(_rubin_process_physical_dir "${RUBIN_PROCESS_ARTIFACT_ROOT}")" == "${_RUBIN_PROCESS_CREATED_ROOT_REAL}" ]] || { _rubin_process_error "artifact root no longer resolves to the helper-created directory: ${RUBIN_PROCESS_ARTIFACT_ROOT}"; return 1; }
  [[ ! -L "${RUBIN_PROCESS_ARTIFACT_ROOT}" ]] || { _rubin_process_error "artifact root must not be a symlink: ${RUBIN_PROCESS_ARTIFACT_ROOT}"; return 1; }
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

_rubin_process_reject_symlink_components() {
  local path="${1:-}" relative current component old_ifs
  case "${path}" in
    "${RUBIN_PROCESS_ARTIFACT_ROOT}") return 0 ;;
    "${RUBIN_PROCESS_ARTIFACT_ROOT}"/*) relative="${path#"${RUBIN_PROCESS_ARTIFACT_ROOT}"/}" ;;
    *) _rubin_process_error "path must stay under artifact root: ${path}"; return 1 ;;
  esac

  current="${RUBIN_PROCESS_ARTIFACT_ROOT}"
  old_ifs="${IFS}"
  IFS="/"
  read -r -a components <<< "${relative}"
  IFS="${old_ifs}"
  for component in "${components[@]}"; do
    [[ -n "${component}" && "${component}" != "." ]] || continue
    current="${current}/${component}"
    [[ ! -L "${current}" ]] || { _rubin_process_error "path component must not be a symlink: ${current}"; return 1; }
  done
}

_rubin_process_require_artifact_parent() {
  local file="${1:-}" dir root_real dir_real
  _rubin_process_require_init || return 1
  _rubin_process_reject_symlink_components "${file}" || return 1
  dir="$(dirname "${file}")"
  [[ -d "${dir}" ]] || return 0
  root_real="$(_rubin_process_physical_dir "${RUBIN_PROCESS_ARTIFACT_ROOT}")" || return 1
  dir_real="$(_rubin_process_physical_dir "${dir}")" || return 1
  case "${dir_real}" in
    "${root_real}"|"${root_real}"/*) ;;
    *) _rubin_process_error "log directory must stay under artifact root: ${dir}"; return 1 ;;
  esac
}

_rubin_process_clear_state() {
  trap - EXIT
  RUBIN_PROCESS_PIDS=()
  RUBIN_PROCESS_STARTED_PIDS=()
  RUBIN_PROCESS_STARTED_EXEC_REALPATHS=()
  RUBIN_PROCESS_LOGS=()
  RUBIN_PROCESS_LAST_PID=""
  RUBIN_PROCESS_TOPOLOGY_NAMES=()
  RUBIN_PROCESS_TOPOLOGY_IMPLS=()
  RUBIN_PROCESS_TOPOLOGY_PIDS=()
  RUBIN_PROCESS_TOPOLOGY_ENDPOINTS=()
  RUBIN_PROCESS_TOPOLOGY_EXEC_REALPATHS=()
  RUBIN_PROCESS_PROXY_SOURCES=()
  RUBIN_PROCESS_PROXY_TARGETS=()
  RUBIN_PROCESS_PROXY_ADDRS=()
  RUBIN_PROCESS_PROXY_TARGET_FILES=()
  RUBIN_PROCESS_ARTIFACT_ROOT=""
  _RUBIN_PROCESS_CREATED_PARENT=""
  _RUBIN_PROCESS_CREATED_ROOT=""
  _RUBIN_PROCESS_CREATED_ROOT_REAL=""
}

_rubin_process_mkdir_under_artifact_root() {
  local dir="${1:-}" relative current component old_ifs
  case "${dir}" in
    "${RUBIN_PROCESS_ARTIFACT_ROOT}") return 0 ;;
    "${RUBIN_PROCESS_ARTIFACT_ROOT}"/*) relative="${dir#"${RUBIN_PROCESS_ARTIFACT_ROOT}"/}" ;;
    *) _rubin_process_error "directory must stay under artifact root: ${dir}"; return 1 ;;
  esac

  current="${RUBIN_PROCESS_ARTIFACT_ROOT}"
  old_ifs="${IFS}"
  IFS="/"
  read -r -a components <<< "${relative}"
  IFS="${old_ifs}"
  for component in "${components[@]}"; do
    [[ -n "${component}" && "${component}" != "." ]] || continue
    current="${current}/${component}"
    [[ ! -L "${current}" ]] || { _rubin_process_error "directory component must not be a symlink: ${current}"; return 1; }
    [[ ! -e "${current}" || -d "${current}" ]] || { _rubin_process_error "directory component is not a directory: ${current}"; return 1; }
    [[ -d "${current}" ]] || mkdir "${current}" || { _rubin_process_error "failed to create log directory: ${current}"; return 1; }
  done
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
  if [[ "${parent}" != /* || "${parent}" == "/" || "${parent}" == "." || "${parent}" == ".." ]] || _rubin_process_has_parent_ref "${parent}"; then
    _rubin_process_error "unsafe artifact parent: ${parent:-<empty>}"
    return 1
  fi
  _RUBIN_PROCESS_STOP_GRACE_SECONDS_DECIMAL="$(_rubin_process_uint_decimal "RUBIN_PROCESS_STOP_GRACE_SECONDS" "${RUBIN_PROCESS_STOP_GRACE_SECONDS}")" || return 1
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
  _RUBIN_PROCESS_CREATED_ROOT="${RUBIN_PROCESS_ARTIFACT_ROOT}"
  _RUBIN_PROCESS_CREATED_ROOT_REAL="$(_rubin_process_physical_dir "${RUBIN_PROCESS_ARTIFACT_ROOT}")" || {
    RUBIN_PROCESS_ARTIFACT_ROOT=""
    return 1
  }
  RUBIN_PROCESS_PIDS=()
  RUBIN_PROCESS_STARTED_PIDS=()
  RUBIN_PROCESS_STARTED_EXEC_REALPATHS=()
  RUBIN_PROCESS_LOGS=()
  RUBIN_PROCESS_LAST_PID=""
  RUBIN_PROCESS_TOPOLOGY_NAMES=()
  RUBIN_PROCESS_TOPOLOGY_IMPLS=()
  RUBIN_PROCESS_TOPOLOGY_PIDS=()
  RUBIN_PROCESS_TOPOLOGY_ENDPOINTS=()
  RUBIN_PROCESS_TOPOLOGY_EXEC_REALPATHS=()
  RUBIN_PROCESS_PROXY_SOURCES=()
  RUBIN_PROCESS_PROXY_TARGETS=()
  RUBIN_PROCESS_PROXY_ADDRS=()
  RUBIN_PROCESS_PROXY_TARGET_FILES=()
  trap rubin_process_exit_trap EXIT
}

rubin_process_is_alive() {
  _rubin_process_pid "${1:-}" || return 1
  kill -0 "$1" >/dev/null 2>&1
}

rubin_process_start() {
  local log_file log_dir launch_exec_realpath launch_status started_pid
  (( $# >= 2 )) || { _rubin_process_error "rubin_process_start requires a log path and command"; return 1; }
  log_file="$(_rubin_process_resolve_log "$1")" || return 1
  shift
  log_dir="$(dirname "${log_file}")"
  _rubin_process_mkdir_under_artifact_root "${log_dir}" || return 1
  _rubin_process_require_artifact_parent "${log_file}" || return 1
  command -v perl >/dev/null 2>&1 || { _rubin_process_error "perl is required to launch managed process groups"; return 1; }
  launch_exec_realpath="$(_rubin_process_executable_realpath "$1")" || { _rubin_process_error "failed to resolve executable identity for $1"; return 1; }

  RUBIN_PROCESS_LAST_PID=""
  perl -e 'setpgrp(0, 0) or die "setpgrp failed: $!"; exec { $ARGV[0] } @ARGV or die "exec failed: $!"' -- "$@" >"${log_file}" 2>&1 &
  launch_status=$?
  if (( launch_status != 0 )); then
    _rubin_process_error "failed to launch background command for ${log_file}"
    return "${launch_status}"
  fi
  started_pid="$!"
  _rubin_process_pid "${started_pid}" || { _rubin_process_error "failed to capture background pid for ${log_file}"; return 1; }
  sleep 0.2
  if ! rubin_process_is_alive "${started_pid}"; then
    kill -- "-${started_pid}" >/dev/null 2>&1 || true
    wait "${started_pid}" >/dev/null 2>&1 || true
    _rubin_process_error "background command exited before registration: ${log_file}"
    return 1
  fi
  # shellcheck disable=SC2034 # caller scripts read this state after sourcing.
  RUBIN_PROCESS_LAST_PID="${started_pid}"
  RUBIN_PROCESS_PIDS+=("${started_pid}")
  RUBIN_PROCESS_STARTED_PIDS+=("${started_pid}")
  RUBIN_PROCESS_STARTED_EXEC_REALPATHS+=("${launch_exec_realpath}")
  RUBIN_PROCESS_LOGS+=("${log_file}")
  disown "${started_pid}" 2>/dev/null || true
}

_rubin_process_node_index() {
  local name="${1:-}" i
  for ((i=0; i<${#RUBIN_PROCESS_TOPOLOGY_NAMES[@]}; i++)); do
    [[ "${RUBIN_PROCESS_TOPOLOGY_NAMES[$i]}" == "${name}" ]] || continue
    printf '%s\n' "${i}"
    return 0
  done
  return 1
}

_rubin_process_link_index() {
  local source="${1:-}" target="${2:-}" i
  for ((i=0; i<${#RUBIN_PROCESS_PROXY_SOURCES[@]}; i++)); do
    [[ "${RUBIN_PROCESS_PROXY_SOURCES[$i]}" == "${source}" && "${RUBIN_PROCESS_PROXY_TARGETS[$i]}" == "${target}" ]] || continue
    printf '%s\n' "${i}"
    return 0
  done
  return 1
}

_rubin_process_managed_pid() {
  local pid="${1:-}" current
  for current in "${RUBIN_PROCESS_PIDS[@]}"; do
    [[ "${current}" == "${pid}" ]] && return 0
  done
  return 1
}

_rubin_process_executable_realpath() {
  local executable="${1:-}" resolved
  [[ -n "${executable}" ]] || return 1
  if [[ "${executable}" == */* ]]; then
    resolved="${executable}"
  else
    resolved="$(command -v -- "${executable}" 2>/dev/null)" || return 1
  fi
  [[ -n "${resolved}" && -f "${resolved}" && -x "${resolved}" ]] || return 1
  perl -MCwd=realpath -e 'my $p = realpath($ARGV[0]); defined $p && -f $p && -x $p or exit 1; print "$p\n";' "${resolved}"
}

_rubin_process_started_exec_realpath() {
  local pid="${1:-}" i
  _rubin_process_pid "${pid}" || return 1
  for ((i=${#RUBIN_PROCESS_STARTED_PIDS[@]} - 1; i >= 0; i--)); do
    [[ "${RUBIN_PROCESS_STARTED_PIDS[$i]}" == "${pid}" ]] || continue
    printf '%s\n' "${RUBIN_PROCESS_STARTED_EXEC_REALPATHS[$i]}"
    return 0
  done
  return 1
}

_rubin_process_started_exec_matches() {
  local pid="${1:-}" expected_exec="${2:-}" started_exec
  [[ -n "${expected_exec}" ]] || return 1
  started_exec="$(_rubin_process_started_exec_realpath "${pid}")" || return 1
  [[ "${started_exec}" == "${expected_exec}" ]]
}

_rubin_process_pid_comm() {
  local pid="${1:-}" comm
  comm="$(ps -p "${pid}" -o comm= 2>/dev/null | awk 'NR==1 {print $1}')" || return 1
  [[ -n "${comm}" ]] || return 1
  basename "${comm}"
}

_rubin_process_runtime_comm_matches() {
  local implementation="${1:-}" comm="${2:-}"
  case "${implementation}:${comm}" in
    go:rubin-node-go|rust:rubin-node-rust) return 0 ;;
    *) return 1 ;;
  esac
}

_rubin_process_pid_listens_on() {
  local pid="${1:-}" endpoint="${2:-}"
  command -v lsof >/dev/null 2>&1 || { _rubin_process_error "lsof is required to prove process-backed endpoint"; return 1; }
  lsof -nP -a -p "${pid}" -iTCP -sTCP:LISTEN -Fn 2>/dev/null | grep -F -x -q -- "n${endpoint}"
}

rubin_process_register_topology_node() {
  local name="${1:-}" implementation="${2:-}" pid="${3:-}" endpoint="${4:-}" expected_executable="${5:-}" comm expected_exec started_exec
  _rubin_process_require_init || return 1
  _rubin_process_name "${name}" || { _rubin_process_error "NO_DATA: reason=invalid_node_name node=${name:-<empty>}"; return 1; }
  _rubin_process_implementation "${implementation}" || { _rubin_process_error "NO_DATA: reason=invalid_implementation node=${name} implementation=${implementation:-<empty>}"; return 1; }
  if ! _rubin_process_pid "${pid}" || ! rubin_process_is_alive "${pid}"; then
    _rubin_process_error "NO_DATA: reason=dead_node_pid node=${name} pid=${pid:-<empty>}"
    return 1
  fi
  _rubin_process_managed_pid "${pid}" || { _rubin_process_error "NO_DATA: reason=unmanaged_node_pid node=${name} pid=${pid}"; return 1; }
  _rubin_process_loopback_endpoint "${endpoint}" || { _rubin_process_error "NO_DATA: reason=invalid_node_endpoint node=${name} endpoint=${endpoint:-<empty>}"; return 1; }
  _rubin_process_pid_listens_on "${pid}" "${endpoint}" || { _rubin_process_error "NO_DATA: reason=node_endpoint_not_process_backed node=${name} pid=${pid} endpoint=${endpoint}"; return 1; }
  comm="$(_rubin_process_pid_comm "${pid}")" || { _rubin_process_error "NO_DATA: reason=process_identity_unverified node=${name} pid=${pid}"; return 1; }
  _rubin_process_runtime_comm_matches "${implementation}" "${comm}" || { _rubin_process_error "NO_DATA: reason=process_identity_unverified node=${name} implementation=${implementation} pid=${pid} comm=${comm}"; return 1; }
  [[ -n "${expected_executable}" ]] || { _rubin_process_error "NO_DATA: reason=missing_expected_executable node=${name} implementation=${implementation} pid=${pid}"; return 1; }
  expected_exec="$(_rubin_process_executable_realpath "${expected_executable}")" || { _rubin_process_error "NO_DATA: reason=expected_executable_unverified node=${name} implementation=${implementation} pid=${pid}"; return 1; }
  started_exec="$(_rubin_process_started_exec_realpath "${pid}")" || { _rubin_process_error "NO_DATA: reason=process_identity_unverified node=${name} implementation=${implementation} pid=${pid}"; return 1; }
  [[ "${started_exec}" == "${expected_exec}" ]] || { _rubin_process_error "NO_DATA: reason=process_identity_unverified node=${name} implementation=${implementation} pid=${pid}"; return 1; }
  ! _rubin_process_node_index "${name}" >/dev/null || { _rubin_process_error "NO_DATA: reason=duplicate_node node=${name}"; return 1; }
  RUBIN_PROCESS_TOPOLOGY_NAMES+=("${name}")
  RUBIN_PROCESS_TOPOLOGY_IMPLS+=("${implementation}")
  RUBIN_PROCESS_TOPOLOGY_PIDS+=("${pid}")
  RUBIN_PROCESS_TOPOLOGY_ENDPOINTS+=("${endpoint}")
  RUBIN_PROCESS_TOPOLOGY_EXEC_REALPATHS+=("${expected_exec}")
}

rubin_process_register_proxy_link() {
  local source="${1:-}" target="${2:-}" proxy_addr="${3:-}" target_file="${4:-}" target_i target_endpoint
  _rubin_process_require_init || return 1
  _rubin_process_node_index "${source}" >/dev/null || { _rubin_process_error "NO_DATA: reason=unknown_source source=${source:-<empty>}"; return 1; }
  target_i="$(_rubin_process_node_index "${target}")" || { _rubin_process_error "NO_DATA: reason=unknown_target target=${target:-<empty>}"; return 1; }
  [[ "${source}" != "${target}" ]] || { _rubin_process_error "NO_DATA: reason=same_node source=${source} target=${target}"; return 1; }
  _rubin_process_loopback_endpoint "${proxy_addr}" || { _rubin_process_error "NO_DATA: reason=invalid_proxy_endpoint proxy=${proxy_addr:-<empty>}"; return 1; }
  _rubin_process_require_artifact_parent "${target_file}" || return 1
  target_endpoint="${RUBIN_PROCESS_TOPOLOGY_ENDPOINTS[$target_i]}"
  [[ -r "${target_file}" && "$(tr -d '[:space:]' <"${target_file}")" == "${target_endpoint}" ]] || { _rubin_process_error "NO_DATA: reason=missing_proxy_target source=${source} target=${target}"; return 1; }
  RUBIN_PROCESS_PROXY_SOURCES+=("${source}")
  RUBIN_PROCESS_PROXY_TARGETS+=("${target}")
  RUBIN_PROCESS_PROXY_ADDRS+=("${proxy_addr}")
  RUBIN_PROCESS_PROXY_TARGET_FILES+=("${target_file}")
}

rubin_process_probe_endpoint() {
  local endpoint="${1:-}" timeout="${2:-1}" rc=0
  _rubin_process_loopback_endpoint "${endpoint}" || { _rubin_process_error "NO_DATA: reason=invalid_probe_endpoint endpoint=${endpoint:-<empty>}"; return 1; }
  command -v python3 >/dev/null 2>&1 || { _rubin_process_error "NO_DATA: reason=python3_unavailable endpoint=${endpoint}"; return 1; }
  python3 - "${timeout}" <<'PY' >/dev/null 2>&1 || { _rubin_process_error "NO_DATA: reason=invalid_probe_timeout endpoint=${endpoint}"; return 1; }
import math, sys
try:
    value = float(sys.argv[1])
except (OverflowError, ValueError):
    sys.exit(1)
sys.exit(0 if math.isfinite(value) and value > 0 else 1)
PY
  python3 - "${endpoint}" "${timeout}" <<'PY' || rc=$?
import socket, sys
endpoint, timeout = sys.argv[1], float(sys.argv[2])
host, port = endpoint.rsplit(":", 1)
try:
    sock = socket.create_connection((host, int(port)), timeout=timeout)
    sock.settimeout(timeout)
    data = sock.recv(1)
    sock.close()
    sys.exit(0 if data else 1)
except socket.timeout:
    sys.exit(2)
except OSError:
    sys.exit(1)
PY
  case "${rc}" in
    0) return 0 ;;
    2) _rubin_process_error "NO_DATA: reason=probe_timeout endpoint=${endpoint}"; return 1 ;;
    *) _rubin_process_error "NO_DATA: reason=probe_disconnected endpoint=${endpoint}"; return 1 ;;
  esac
}

_rubin_process_node_is_fresh() {
  local index="${1:-}" pid endpoint expected_exec
  pid="${RUBIN_PROCESS_TOPOLOGY_PIDS[$index]}"
  endpoint="${RUBIN_PROCESS_TOPOLOGY_ENDPOINTS[$index]}"
  expected_exec="${RUBIN_PROCESS_TOPOLOGY_EXEC_REALPATHS[$index]:-}"
  rubin_process_is_alive "${pid}" && _rubin_process_started_exec_matches "${pid}" "${expected_exec}" && _rubin_process_pid_listens_on "${pid}" "${endpoint}"
}

_rubin_process_control_pair() {
  local action="${1:-}" source="${2:-}" target="${3:-}" source_i target_i link_i target_file target_endpoint current_target
  _rubin_process_require_init || return 1
  source_i="$(_rubin_process_node_index "${source}")" || { _rubin_process_error "NO_DATA: phase=${action} reason=unknown_source source=${source:-<empty>} target=${target:-<empty>}"; return 1; }
  [[ "${source}" != "${target}" ]] || { _rubin_process_error "NO_DATA: phase=${action} reason=same_node source=${source} target=${target}"; return 1; }
  ((${#RUBIN_PROCESS_TOPOLOGY_NAMES[@]} >= 2)) || { _rubin_process_error "NO_DATA: phase=${action} reason=single_node_topology source=${source} target=${target}"; return 1; }
  target_i="$(_rubin_process_node_index "${target}")" || { _rubin_process_error "NO_DATA: phase=${action} reason=unknown_target source=${source} target=${target:-<empty>}"; return 1; }
  [[ "${RUBIN_PROCESS_TOPOLOGY_IMPLS[$source_i]}" != "${RUBIN_PROCESS_TOPOLOGY_IMPLS[$target_i]}" ]] || { _rubin_process_error "NO_DATA: phase=${action} reason=same_client_topology source=${source} target=${target}"; return 1; }
  if ! _rubin_process_node_is_fresh "${source_i}" || ! _rubin_process_node_is_fresh "${target_i}"; then
    _rubin_process_error "NO_DATA: phase=${action} reason=stale_topology source=${source} target=${target}"
    return 1
  fi
  link_i="$(_rubin_process_link_index "${source}" "${target}")" || { _rubin_process_error "NO_DATA: phase=${action} reason=missing_proxy_link source=${source} target=${target}"; return 1; }
  target_file="${RUBIN_PROCESS_PROXY_TARGET_FILES[$link_i]}"
  target_endpoint="${RUBIN_PROCESS_TOPOLOGY_ENDPOINTS[$target_i]}"
  _rubin_process_require_artifact_parent "${target_file}" || return 1
  [[ -r "${target_file}" ]] || { _rubin_process_error "NO_DATA: phase=${action} reason=missing_proxy_target source=${source} target=${target}"; return 1; }
  current_target="$(tr -d '[:space:]' <"${target_file}")"
  [[ "${action}" != "partition" || "${current_target}" != "drop" ]] || { _rubin_process_error "NO_DATA: phase=partition reason=no_effect source=${source} target=${target}"; return 1; }
  [[ "${action}" != "heal" || "${current_target}" != "${target_endpoint}" ]] || { _rubin_process_error "NO_DATA: phase=heal reason=no_effect source=${source} target=${target}"; return 1; }
  _rubin_process_error "NO_DATA: phase=${action} reason=runtime_edge_verifier_required source=${source} target=${target}"
  return 1
}

rubin_process_partition_pair() { _rubin_process_control_pair partition "$@"; }
rubin_process_heal_pair() { _rubin_process_control_pair heal "$@"; }

rubin_process_stop_pid() {
  local pid="${1:-}" grace_seconds deadline
  _rubin_process_pid "${pid}" || return 1
  grace_seconds="${_RUBIN_PROCESS_STOP_GRACE_SECONDS_DECIMAL:-}"
  [[ -n "${grace_seconds}" ]] || grace_seconds="$(_rubin_process_uint_decimal "RUBIN_PROCESS_STOP_GRACE_SECONDS" "${RUBIN_PROCESS_STOP_GRACE_SECONDS}")" || return 1
  if rubin_process_is_alive "${pid}"; then
    kill -- "-${pid}" >/dev/null 2>&1 || kill "${pid}" >/dev/null 2>&1 || true
    deadline=$((SECONDS + grace_seconds))
    while rubin_process_is_alive "${pid}" && (( SECONDS < deadline )); do sleep 1; done
  fi
  if rubin_process_is_alive "${pid}"; then
    kill -KILL -- "-${pid}" >/dev/null 2>&1 || kill -KILL "${pid}" >/dev/null 2>&1 || true
  fi
  wait "${pid}" >/dev/null 2>&1 || true
}

rubin_process_stop_all() {
  local i rc status=0
  for ((i=${#RUBIN_PROCESS_PIDS[@]} - 1; i >= 0; i--)); do
    rc=0
    rubin_process_stop_pid "${RUBIN_PROCESS_PIDS[$i]}" || rc=$?
    (( rc == 0 )) || { (( status == 0 )) && status="${rc}"; }
  done
  return "${status}"
}

rubin_process_wait_for_log() {
  local file="${1:-}" needle="${2:-}" timeout="${3:-}" pid="${4:-}" timeout_seconds deadline
  [[ -n "${file}" && -n "${needle}" && -n "${timeout}" ]] || { _rubin_process_error "rubin_process_wait_for_log requires file, needle, timeout"; return 1; }
  file="$(_rubin_process_resolve_log "${file}")" || return 1
  _rubin_process_require_artifact_parent "${file}" || return 1
  timeout_seconds="$(_rubin_process_uint_decimal "timeout" "${timeout}")" || return 1
  [[ -z "${pid}" ]] || _rubin_process_pid "${pid}" || { _rubin_process_error "invalid pid: ${pid}"; return 1; }
  deadline=$((SECONDS + timeout_seconds))
  while (( SECONDS < deadline )); do
    if [[ -f "${file}" ]]; then
      _rubin_process_require_artifact_parent "${file}" || return 1
      grep -F -q -- "${needle}" "${file}" && return 0
    fi
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
  _rubin_process_require_artifact_parent "${file}" || return 1
  [[ -r "${file}" ]] || { _rubin_process_error "rpc log file is missing or unreadable: ${file:-<empty>}"; return 1; }
  if ! addr="$(sed -n 's/.*rpc: listening=//p' "${file}" | tail -n 1 | tr -d '[:space:]')"; then
    _rubin_process_error "failed to extract rpc listening banner from ${file}"
    return 1
  fi
  [[ -n "${addr}" ]] || { _rubin_process_error "missing rpc listening banner in ${file}"; return 1; }
  printf '%s\n' "${addr}"
}

rubin_process_wait_for_rpc_ready() {
  local rpc_addr="${1:-}" timeout="${2:-}" timeout_seconds deadline
  [[ -n "${rpc_addr}" && -n "${timeout}" ]] || { _rubin_process_error "rubin_process_wait_for_rpc_ready requires rpc address and timeout"; return 1; }
  [[ "${rpc_addr}" != *[[:space:]/]* ]] || { _rubin_process_error "invalid rpc address: ${rpc_addr:-<empty>}"; return 1; }
  timeout_seconds="$(_rubin_process_uint_decimal "timeout" "${timeout}")" || return 1
  command -v python3 >/dev/null 2>&1 || { _rubin_process_error "python3 is required to poll /get_tip"; return 1; }
  deadline=$((SECONDS + timeout_seconds))
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
  ((${#RUBIN_PROCESS_LOGS[@]} > 0)) || return 0
  for log_file in "${RUBIN_PROCESS_LOGS[@]}"; do
    _rubin_process_require_artifact_parent "${log_file}" || { _rubin_process_error "skipping unsafe log file: ${log_file}"; continue; }
    [[ -f "${log_file}" ]] || continue
    _rubin_process_error "----- $(basename "${log_file}") -----"
    tail -n 80 "${log_file}" >&2 || true
  done
}

rubin_process_cleanup() {
  local status="${1:-0}" cleanup_status=0
  _rubin_process_uint "status" "${status}" || return 1
  if [[ -z "${RUBIN_PROCESS_ARTIFACT_ROOT}" && -z "${_RUBIN_PROCESS_CREATED_ROOT}" && ${#RUBIN_PROCESS_PIDS[@]} -eq 0 ]]; then
    _rubin_process_clear_state
    return 0
  fi
  rubin_process_stop_all || cleanup_status=$?
  if [[ "${status}" != "0" ]]; then
    rubin_process_dump_artifacts
    _rubin_process_clear_state
    return "${status}"
  fi
  [[ "${RUBIN_PROCESS_KEEP_ARTIFACTS}" == "1" ]] && {
    echo "OK: artifacts preserved at ${RUBIN_PROCESS_ARTIFACT_ROOT}"
    _rubin_process_clear_state
    return "${cleanup_status}"
  }
  if [[ -z "${_RUBIN_PROCESS_CREATED_PARENT}" || -z "${_RUBIN_PROCESS_CREATED_ROOT}" || -z "${_RUBIN_PROCESS_CREATED_ROOT_REAL}" || -z "${RUBIN_PROCESS_ARTIFACT_ROOT}" ]] || _rubin_process_has_parent_ref "${RUBIN_PROCESS_ARTIFACT_ROOT}"; then
    _rubin_process_error "refusing cleanup without initialized artifact paths or with parent traversal"
    return 1
  fi
  _rubin_process_require_init || return 1
  [[ "${RUBIN_PROCESS_ARTIFACT_ROOT}" == "${_RUBIN_PROCESS_CREATED_ROOT}" ]] || {
    _rubin_process_error "refusing to remove artifact root not created by rubin_process_init: ${RUBIN_PROCESS_ARTIFACT_ROOT}"
    return 1
  }
  case "${RUBIN_PROCESS_ARTIFACT_ROOT}" in
    "${_RUBIN_PROCESS_CREATED_PARENT}"/*) ;;
    *) _rubin_process_error "refusing to remove unsafe artifact root: ${RUBIN_PROCESS_ARTIFACT_ROOT}"; return 1 ;;
  esac
  rm -rf -- "${_RUBIN_PROCESS_CREATED_ROOT_REAL}" || cleanup_status=$?
  _rubin_process_clear_state
  return "${cleanup_status}"
}

rubin_process_exit_trap() {
  local status=$? cleanup_status=0
  rubin_process_cleanup "${status}" || cleanup_status=$?
  [[ "${status}" != "0" ]] && exit "${status}"
  exit "${cleanup_status}"
}
