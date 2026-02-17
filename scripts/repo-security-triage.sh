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

log "repo-security-triage start"
log "tool versions: semgrep=$(tool_version semgrep semgrep --version) gosec=$(tool_version gosec gosec -version)"

# Semgrep: explicit CA bundle for macOS/OpenSSL edge cases.
SEM_GREP_OUT="${ROOT}/clients/go/semgrep_output.json"
SSL_CERT_PATH="${SSL_CERT_FILE:-/opt/homebrew/etc/ca-certificates/cert.pem}"
if [[ ! -f "${SSL_CERT_PATH}" ]]; then
  if [[ -f /etc/ssl/cert.pem ]]; then
    SSL_CERT_PATH="/etc/ssl/cert.pem"
  fi
fi
export SSL_CERT_FILE="${SSL_CERT_PATH}"
log "semgrep: SSL_CERT_FILE=${SSL_CERT_FILE}"

# Gosec: writable cache and stable module mode for local scans.
GOSEC_GOCACHE="${GOCACHE:-/tmp/gocache_repo_security_triage}"
mkdir -p "${GOSEC_GOCACHE}"
export GOCACHE="${GOSEC_GOCACHE}"
export GOSUMDB="${GOSUMDB:-off}"
GOSEC_OUT="${ROOT}/clients/go/gosec_output.json"
GOSEC_MAX_ATTEMPTS="${GOSEC_MAX_ATTEMPTS:-2}"
GOSEC_RETRY_DELAY="${GOSEC_RETRY_DELAY:-2}"

# Cargo-audit: avoid lock contention in shared ~/.cargo advisory db cache.
CARGO_HOME_DIR="${CARGO_HOME:-/tmp/cargo_home_repo_security_triage}"
mkdir -p "${CARGO_HOME_DIR}"
export CARGO_HOME="${CARGO_HOME_DIR}"
CARGO_AUDIT_OUT="${ROOT}/clients/rust/cargo_audit.json"

log "running semgrep"
semgrep \
  --json \
  --config p/owasp-top-ten \
  --config p/cwe-top-25 \
  --config p/ci \
  --config p/rust \
  --config p/golang \
  . >"${SEM_GREP_OUT}"
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

log "repo-security-triage done: semgrep=${SEM_SEMGRP_RC} gosec=${GOSEC_RC} cargo-audit=${CARGO_RC}"
