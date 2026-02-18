#!/usr/bin/env bash
set -euo pipefail

# Run the security triage checks used by the automation with hardened env defaults.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

date_utc() {
  date -u +%Y-%m-%dT%H:%M:%SZ
}

log() {
  printf '[%s] %s\n' "$(date_utc)" "$*"
}

tool_version() {
  local cmd="$1"
  shift || true
  if command -v "${cmd}" >/dev/null 2>&1; then
    "$@" 2>&1 | head -n 1 | tr -d '\n'
  else
    echo "not-found"
  fi
}

command_has_output() {
  local pattern="$1"
  local file="$2"
  local grep_opts="-E"
  grep "${grep_opts}" -q "${pattern}" "${file}"
}

gosec_output_has_issues() {
  local file="$1"

  if ! [[ -f "${file}" ]]; then
    return 1
  fi

  if command -v jq >/dev/null 2>&1; then
    local issues_len golang_len
    issues_len="$(jq -r '.Issues | length // 0' "${file}")"
    golang_len="$(jq -r '.["Golang errors"] | length // 0' "${file}")"
    [[ "${issues_len}" != "0" || "${golang_len}" != "0" ]]
  else
    # Fallback: tolerate no jq.
    ! command_has_output '"Issues":[[:space:]]*\\[\\]' "${file}" && return 1
    ! command_has_output '"Golang errors":[[:space:]]*{}' "${file}" && return 1
    return 0
  fi
}

run_gosec_scan() {
  local out_file="$1"
  set +e
  (
    cd "${ROOT}/clients/go"
    gosec -fmt=json -exclude-dir=vendor -out="${out_file}" ./...
  )
  local rc=$?
  set -e
  return "${rc}"
}

git_safe() {
  git -c core.hooksPath=/dev/null -C "${ROOT}" "$@"
}

worktree_status_snapshot() {
  if ! command -v git >/dev/null 2>&1; then
    return 0
  fi
  if ! git_safe rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    return 0
  fi
  git_safe status --porcelain=1 --untracked-files=all || true
}

enforce_clean_tree_gate() {
  local before="$1"
  local after="$2"
  local gate_enabled="${RUBIN_ENFORCE_CLEAN_TREE:-1}"

  if [[ "${gate_enabled}" != "1" ]]; then
    log "clean-tree gate disabled: RUBIN_ENFORCE_CLEAN_TREE=${gate_enabled}"
    return 0
  fi

  if [[ "${before}" != "${after}" ]]; then
    log "clean-tree gate FAILED: worktree changed during run"
    printf '%s\n' "--- status(before) ---"
    printf '%s\n' "${before}"
    printf '%s\n' "--- status(after) ---"
    printf '%s\n' "${after}"
    return 1
  fi

  log "clean-tree gate passed"
}

log "repo-security-triage start"
log "tool versions: semgrep=$(tool_version semgrep semgrep --version) gosec=$(tool_version gosec gosec -version)"
WORKTREE_STATUS_BEFORE="$(worktree_status_snapshot)"

# Artifacts: external by default. Repository paths require explicit opt-in.
RUBIN_ALLOW_REPO_ARTIFACTS="${RUBIN_ALLOW_REPO_ARTIFACTS:-0}"
RUBIN_ARTIFACT_DIR="${RUBIN_TRIAGE_ARTIFACT_DIR:-${RUBIN_ARTIFACT_DIR:-}}"
if [[ "${RUBIN_ALLOW_REPO_ARTIFACTS}" == "1" ]]; then
  SEM_GREP_OUT_DEFAULT="${ROOT}/clients/go/semgrep_output.json"
  GOSEC_OUT_DEFAULT="${ROOT}/clients/go/gosec_output.json"
  CARGO_AUDIT_OUT_DEFAULT="${ROOT}/clients/rust/cargo_audit.json"
  log "artifact mode: repository (RUBIN_ALLOW_REPO_ARTIFACTS=1)"
else
  if [[ -z "${RUBIN_ARTIFACT_DIR}" ]]; then
    RUBIN_ARTIFACT_DIR="/tmp/repo-security-triage-$(date -u +%Y%m%dT%H%M%SZ)"
  fi
  mkdir -p "${RUBIN_ARTIFACT_DIR}"
  SEM_GREP_OUT_DEFAULT="${RUBIN_ARTIFACT_DIR}/semgrep_output.json"
  GOSEC_OUT_DEFAULT="${RUBIN_ARTIFACT_DIR}/gosec_output.json"
  CARGO_AUDIT_OUT_DEFAULT="${RUBIN_ARTIFACT_DIR}/cargo_audit.json"
  log "artifact mode: external dir=${RUBIN_ARTIFACT_DIR}"
fi
SEM_GREP_OUT="${RUBIN_SEMGREP_OUT:-${SEM_GREP_OUT_DEFAULT}}"
GOSEC_OUT="${RUBIN_GOSEC_OUT:-${GOSEC_OUT_DEFAULT}}"
CARGO_AUDIT_OUT="${RUBIN_CARGO_AUDIT_OUT:-${CARGO_AUDIT_OUT_DEFAULT}}"
mkdir -p "$(dirname "${SEM_GREP_OUT}")" "$(dirname "${GOSEC_OUT}")" "$(dirname "${CARGO_AUDIT_OUT}")"
log "artifact outputs: semgrep=${SEM_GREP_OUT} gosec=${GOSEC_OUT} cargo-audit=${CARGO_AUDIT_OUT}"

# Semgrep: explicit CA bundle for macOS/OpenSSL edge cases.
# Semgrep writes user logs/settings under ~/.semgrep by default, which can be outside
# the sandbox writable roots. Force it into /tmp so semgrep can start reliably.
XDG_CONFIG_HOME_DIR="${XDG_CONFIG_HOME:-/tmp/xdg_config_repo_security_triage}"
mkdir -p "${XDG_CONFIG_HOME_DIR}"
export XDG_CONFIG_HOME="${XDG_CONFIG_HOME_DIR}"
SEMGREP_DATA_DIR="${XDG_CONFIG_HOME_DIR}/.semgrep"
mkdir -p "${SEMGREP_DATA_DIR}"
export SEMGREP_LOG_FILE="${SEMGREP_LOG_FILE:-${SEMGREP_DATA_DIR}/semgrep.log}"
export SEMGREP_SETTINGS_FILE="${SEMGREP_SETTINGS_FILE:-${SEMGREP_DATA_DIR}/settings.yml}"

SSL_CERT_PATH="${SSL_CERT_FILE:-/opt/homebrew/etc/ca-certificates/cert.pem}"
if [[ ! -f "${SSL_CERT_PATH}" ]]; then
  if [[ -f /etc/ssl/cert.pem ]]; then
    SSL_CERT_PATH="/etc/ssl/cert.pem"
  fi
fi
export SSL_CERT_FILE="${SSL_CERT_PATH}"
log "semgrep: SSL_CERT_FILE=${SSL_CERT_FILE}"
log "semgrep: XDG_CONFIG_HOME=${XDG_CONFIG_HOME} SEMGREP_LOG_FILE=${SEMGREP_LOG_FILE}"

# Gosec: writable cache and stable module mode for local scans.
GOSEC_GOCACHE="${GOCACHE:-/tmp/gocache_repo_security_triage}"
mkdir -p "${GOSEC_GOCACHE}"
export GOCACHE="${GOSEC_GOCACHE}"
export GOSUMDB="${GOSUMDB:-off}"
GOSEC_MAX_ATTEMPTS="${GOSEC_MAX_ATTEMPTS:-2}"
GOSEC_RETRY_DELAY="${GOSEC_RETRY_DELAY:-2}"

# Cargo-audit: avoid lock contention in shared ~/.cargo advisory db cache.
CARGO_HOME_DIR="${CARGO_HOME:-/tmp/cargo_home_repo_security_triage}"
mkdir -p "${CARGO_HOME_DIR}"
export CARGO_HOME="${CARGO_HOME_DIR}"

log "running semgrep"
(
  cd "${ROOT}"
  semgrep \
    --json \
    --config p/owasp-top-ten \
    --config p/cwe-top-25 \
    --config p/ci \
    --config p/rust \
    --config p/golang \
    . >"${SEM_GREP_OUT}"
)
SEM_SEMGRP_RC=$?
log "semgrep rc=${SEM_SEMGRP_RC} output=${SEM_GREP_OUT}"

log "running gosec"
GOSEC_RC=0
for attempt in $(seq 1 "${GOSEC_MAX_ATTEMPTS}"); do
  log "running gosec attempt ${attempt}/${GOSEC_MAX_ATTEMPTS}"
  run_gosec_scan "${GOSEC_OUT}"
  GOSEC_RC=$?
  if [[ "${GOSEC_RC}" == "0" ]] && ! gosec_output_has_issues "${GOSEC_OUT}"; then
    log "gosec success on attempt ${attempt}"
    break
  fi
  if [[ "${attempt}" -lt "${GOSEC_MAX_ATTEMPTS}" ]]; then
    log "gosec unstable on attempt ${attempt}; retrying in ${GOSEC_RETRY_DELAY}s"
    sleep "${GOSEC_RETRY_DELAY}"
  else
    log "gosec failed after ${GOSEC_MAX_ATTEMPTS} attempts"
    GOSEC_RC=1
  fi
done
log "gosec rc=${GOSEC_RC} output=${GOSEC_OUT}"

log "running cargo audit"
(
  cd "${ROOT}/clients/rust"
  cargo audit --json >"${CARGO_AUDIT_OUT}"
)
CARGO_RC=$?
log "cargo-audit rc=${CARGO_RC} output=${CARGO_AUDIT_OUT}"

WORKTREE_STATUS_AFTER="$(worktree_status_snapshot)"
enforce_clean_tree_gate "${WORKTREE_STATUS_BEFORE}" "${WORKTREE_STATUS_AFTER}"

log "repo-security-triage done: semgrep=${SEM_SEMGRP_RC} gosec=${GOSEC_RC} cargo-audit=${CARGO_RC}"
