#!/usr/bin/env bash
# test_rust_skeleton_fixtures.sh — RUB-27 fixture accept/reject test.
#
# Wires the committed Rust skeleton fixtures as test consumers, proving
# the RUB-27 acceptance criterion "RUB-24 schema validator accepts the
# valid skeleton artifact and rejects helper-only artifact" via the
# committed validator (scripts/devnet/validate_mixed_client_evidence.py).
#
# Without this script the two committed fixtures would have no in-repo
# consumer; the harness only validates its own runtime-emitted artifact,
# not the committed fixture pair. This script anchors the acceptance
# claim to a reproducible exit-code + cross-field-message contract.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DEV_ENV="${REPO_ROOT}/scripts/dev-env.sh"
VALIDATOR="${REPO_ROOT}/scripts/devnet/validate_mixed_client_evidence.py"
VALID_FIXTURE="${REPO_ROOT}/scripts/devnet/testdata/rust_skeleton_fail_evidence_valid.json"
REJECTED_FIXTURE="${REPO_ROOT}/scripts/devnet/testdata/rust_skeleton_helper_only_rejected.json"

command -v python3 >/dev/null 2>&1 || { echo "python3 is required" >&2; exit 1; }
[[ -x "${DEV_ENV}" ]] || { echo "dev-env wrapper missing or non-executable: ${DEV_ENV}" >&2; exit 1; }
[[ -r "${VALIDATOR}" ]] || { echo "validator unreadable: ${VALIDATOR}" >&2; exit 1; }
[[ -r "${VALID_FIXTURE}" ]] || { echo "valid fixture unreadable: ${VALID_FIXTURE}" >&2; exit 1; }
[[ -r "${REJECTED_FIXTURE}" ]] || { echo "rejected fixture unreadable: ${REJECTED_FIXTURE}" >&2; exit 1; }

run_fips_preflight_before_captured_dev_env() {
  if [[ "${RUBIN_OPENSSL_FIPS_MODE:-off}" != "only" ]]; then
    return 0
  fi
  if [[ "${RUBIN_OPENSSL_SKIP_FIPS_GUARD:-0}" == "1" ]]; then
    return 0
  fi

  echo "Running FIPS-only preflight before captured dev-env validator streams" >&2
  "${DEV_ENV}" -- "${REPO_ROOT}/scripts/crypto/openssl/fips-preflight.sh" >&2
}

run_validator() {
  RUBIN_OPENSSL_SKIP_FIPS_GUARD=1 "${DEV_ENV}" -- python3 "${VALIDATOR}" "$@"
}

run_fips_preflight_before_captured_dev_env

# Acceptance leg 1: validator MUST accept the well-formed FAIL skeleton.
echo "test_rust_skeleton_fixtures: valid fixture must validate"
if ! run_validator "${VALID_FIXTURE}"; then
  echo "FAIL: validator rejected the valid skeleton fixture" >&2
  exit 1
fi

# Acceptance leg 2: validator MUST reject the helper-only shape and
# surface the three expected cross-field rejections (missing 2nd
# participant, missing go counterpart impl, tx_path required for PASS).
# Pinning to specific cross-field messages — not just non-zero exit —
# anchors the acceptance to the rejection class, not to a generic
# schema-shape failure that some future schema relaxation could mask.
echo "test_rust_skeleton_fixtures: helper-only fixture must be rejected"
# Single validator invocation captures both stderr+stdout and exit code
# (P2 finding from PR #1510 review): the previous double-invocation
# could mask a behavior change between runs. The if/else form keeps
# `set -e` armed for everything else and binds REJECTED_RC to the
# exact exit code of the captured invocation.
if REJECTED_OUTPUT="$(run_validator "${REJECTED_FIXTURE}" 2>&1)"; then
  REJECTED_RC=0
else
  REJECTED_RC=$?
fi
if [[ "${REJECTED_RC}" == "0" ]]; then
  echo "FAIL: validator accepted the helper-only fixture (expected rejection)" >&2
  echo "actual output:" >&2
  printf '%s\n' "${REJECTED_OUTPUT}" >&2
  exit 1
fi

for needle in \
  "requires at least 2 participants" \
  "at least one implementation=go and one implementation=rust" \
  "tx_path: required for evidence_type=mixed_client_process_soak with verdict=PASS"; do
  if [[ "${REJECTED_OUTPUT}" != *"${needle}"* ]]; then
    echo "FAIL: helper-only rejection missing expected cross-field message: ${needle}" >&2
    echo "actual output:" >&2
    printf '%s\n' "${REJECTED_OUTPUT}" >&2
    exit 1
  fi
done

echo "PASS: rust skeleton fixtures accept/reject pair confirmed"
