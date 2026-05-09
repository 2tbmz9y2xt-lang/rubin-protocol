#!/usr/bin/env bash
# test_rust_skeleton_fixtures.sh — RUB-27 fixtures plus RUB-25 gate tests.
#
# Wires the committed Rust skeleton fixtures to the RUB-24 validator
# and exercises the RUB-25 mixed-client process evidence gate through
# fixture-driven pass/fail boundaries.
#
# This does not prove live Go/Rust runtime behavior; it anchors schema
# and shell-gate acceptance claims to reproducible fixture exit codes.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DEV_ENV="${REPO_ROOT}/scripts/dev-env.sh"
VALIDATOR="${REPO_ROOT}/scripts/devnet/validate_mixed_client_evidence.py"
GATE_SCRIPT="${REPO_ROOT}/scripts/devnet-rust-binary-soak.sh"
VALID_FIXTURE="${REPO_ROOT}/scripts/devnet/testdata/rust_skeleton_fail_evidence_valid.json"
REJECTED_FIXTURE="${REPO_ROOT}/scripts/devnet/testdata/rust_skeleton_helper_only_rejected.json"
VALID_MIXED_FIXTURE="${REPO_ROOT}/scripts/devnet/testdata/valid_process_mixed.json"

command -v python3 >/dev/null 2>&1 || { echo "python3 is required" >&2; exit 1; }
[[ -x "${DEV_ENV}" ]] || { echo "dev-env wrapper missing or non-executable: ${DEV_ENV}" >&2; exit 1; }
[[ -r "${VALIDATOR}" ]] || { echo "validator unreadable: ${VALIDATOR}" >&2; exit 1; }
[[ -x "${GATE_SCRIPT}" ]] || { echo "gate script missing or non-executable: ${GATE_SCRIPT}" >&2; exit 1; }
[[ -r "${VALID_FIXTURE}" ]] || { echo "valid fixture unreadable: ${VALID_FIXTURE}" >&2; exit 1; }
[[ -r "${REJECTED_FIXTURE}" ]] || { echo "rejected fixture unreadable: ${REJECTED_FIXTURE}" >&2; exit 1; }
[[ -r "${VALID_MIXED_FIXTURE}" ]] || { echo "valid mixed fixture unreadable: ${VALID_MIXED_FIXTURE}" >&2; exit 1; }

TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/rubin-rust-skeleton-fixtures.XXXXXX")"
cleanup() {
  rm -rf -- "${TMP_ROOT}"
}
trap cleanup EXIT

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

run_gate() {
  "${GATE_SCRIPT}" --check-evidence "$@"
}

require_output_contains() {
  local output="$1" needle="$2" label="$3"
  if [[ "${output}" != *"${needle}"* ]]; then
    echo "FAIL: ${label} missing expected text: ${needle}" >&2
    echo "actual output:" >&2
    printf '%s\n' "${output}" >&2
    exit 1
  fi
}

expect_gate_pass() {
  local fixture="$1" label="$2" output
  if ! output="$(run_gate "${fixture}" 2>&1)"; then
    echo "FAIL: ${label} should pass mixed-client gate" >&2
    echo "actual output:" >&2
    printf '%s\n' "${output}" >&2
    exit 1
  fi
  require_output_contains "${output}" "PASS: mixed-client process evidence gate accepted ${fixture}" "${label}"
}

expect_gate_fail() {
  local fixture="$1" label="$2" needle="$3" output
  if output="$(run_gate "${fixture}" 2>&1)"; then
    echo "FAIL: ${label} should fail mixed-client gate" >&2
    echo "actual output:" >&2
    printf '%s\n' "${output}" >&2
    exit 1
  fi
  require_output_contains "${output}" "${needle}" "${label}"
}

write_same_client_fixture() {
  local path="$1"
  cat >"${path}" <<'JSON'
{
  "schema_version": "rubin-mixed-client-devnet-evidence-v1",
  "evidence_type": "mixed_client_process_soak",
  "scenario": "same_client_selected_path_with_unselected_rust",
  "verdict": "PASS",
  "participants": [
    {
      "name": "node-go-a",
      "implementation": "go",
      "endpoint": "127.0.0.1:41001",
      "started_at": "2026-05-09T10:00:00Z"
    },
    {
      "name": "node-go-b",
      "implementation": "go",
      "endpoint": "127.0.0.1:41002",
      "started_at": "2026-05-09T10:00:01Z"
    },
    {
      "name": "node-rust",
      "implementation": "rust",
      "endpoint": "127.0.0.1:41003",
      "started_at": "2026-05-09T10:00:02Z"
    }
  ],
  "tx_path": {
    "submitted_at": "node-go-a",
    "observed_at": ["node-go-b"],
    "tx_id": "5555555555555555555555555555555555555555555555555555555555555555"
  }
}
JSON
}

write_stdout_contaminated_fixture() {
  local path="$1"
  {
    printf '%s\n' "dev-env banner on stdout"
    cat "${VALID_MIXED_FIXTURE}"
  } >"${path}"
}

write_unselected_helper_fixture() {
  local path="$1"
  cat >"${path}" <<'JSON'
{
  "schema_version": "rubin-mixed-client-devnet-evidence-v1",
  "evidence_type": "mixed_client_process_soak",
  "scenario": "selected_mixed_with_unselected_helper",
  "verdict": "PASS",
  "participants": [
    {"name": "node-go", "implementation": "go", "endpoint": "127.0.0.1:41001", "started_at": "2026-05-09T10:00:00Z"},
    {"name": "node-rust", "implementation": "rust", "endpoint": "127.0.0.1:41002", "started_at": "2026-05-09T10:00:01Z"},
    {"name": "node-rust-helper", "implementation": "rust"}
  ],
  "tx_path": {"submitted_at": "node-go", "observed_at": ["node-rust"], "tx_id": "6666666666666666666666666666666666666666666666666666666666666666"}
}
JSON
}

write_repair2_fixtures() {
  local selected_dup="$1" unselected_dup="$2" pass_failure_reason="$3"
  python3 - "${VALID_MIXED_FIXTURE}" "${selected_dup}" "${unselected_dup}" "${pass_failure_reason}" <<'PY'
import copy, json, sys

src, selected_dup, unselected_dup, pass_failure_reason = sys.argv[1:5]
with open(src, encoding="utf-8") as f:
    base = json.load(f)
selected = copy.deepcopy(base)
selected["participants"][1]["endpoint"] = selected["participants"][0]["endpoint"]
unselected = copy.deepcopy(base)
unselected["participants"].append({
    "name": "node-go-shadow",
    "implementation": "go",
    "endpoint": base["participants"][0]["endpoint"],
    "started_at": "2026-05-09T10:00:02Z",
})
contradictory = copy.deepcopy(base)
contradictory["failure_reason"] = "no data should not pass"
for path, data in (
    (selected_dup, selected),
    (unselected_dup, unselected),
    (pass_failure_reason, contradictory),
):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=True)
        f.write("\n")
PY
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

echo "test_rust_skeleton_fixtures: mixed-client gate must pass valid process fixture"
expect_gate_pass "${VALID_MIXED_FIXTURE}" "valid mixed process fixture"

SPACE_DIR="${TMP_ROOT}/path with spaces [rubin]"
mkdir -p -- "${SPACE_DIR}"
SPACE_FIXTURE="${SPACE_DIR}/valid mixed process.json"
cp "${VALID_MIXED_FIXTURE}" "${SPACE_FIXTURE}"
expect_gate_pass "${SPACE_FIXTURE}" "valid mixed process fixture path with spaces"

echo "test_rust_skeleton_fixtures: mixed-client gate must fail closed on boundary fixtures"
MISSING_FIXTURE="${TMP_ROOT}/missing-mixed.json"
EMPTY_FIXTURE="${TMP_ROOT}/empty-mixed.json"
WRONG_ROOT_FIXTURE="${TMP_ROOT}/wrong-root-mixed.json"
MALFORMED_FIXTURE="${TMP_ROOT}/malformed-mixed.json"
STDOUT_CONTAMINATED_FIXTURE="${TMP_ROOT}/stdout-contaminated-mixed.json"
SAME_CLIENT_FIXTURE="${TMP_ROOT}/same-client-mixed.json"
UNSELECTED_HELPER_FIXTURE="${TMP_ROOT}/unselected-helper-mixed.json"
SELECTED_DUP_ENDPOINT_FIXTURE="${TMP_ROOT}/selected-duplicate-endpoint-mixed.json"
UNSELECTED_DUP_ENDPOINT_FIXTURE="${TMP_ROOT}/unselected-duplicate-endpoint-mixed.json"
PASS_FAILURE_REASON_FIXTURE="${TMP_ROOT}/pass-failure-reason-mixed.json"
touch "${EMPTY_FIXTURE}"
printf '%s\n' '[]' >"${WRONG_ROOT_FIXTURE}"
printf '%s\n' '{"schema_version":"rubin-mixed-client-devnet-evidence-v1"}' '{"extra":"ndjson"}' >"${MALFORMED_FIXTURE}"
write_stdout_contaminated_fixture "${STDOUT_CONTAMINATED_FIXTURE}"
write_same_client_fixture "${SAME_CLIENT_FIXTURE}"
write_unselected_helper_fixture "${UNSELECTED_HELPER_FIXTURE}"
write_repair2_fixtures "${SELECTED_DUP_ENDPOINT_FIXTURE}" "${UNSELECTED_DUP_ENDPOINT_FIXTURE}" "${PASS_FAILURE_REASON_FIXTURE}"

expect_gate_fail "${MISSING_FIXTURE}" "missing artifact" "artifact not found or not a regular file"
expect_gate_fail "" "empty --check-evidence argument" "artifact path is required"
expect_gate_fail "${EMPTY_FIXTURE}" "empty artifact" "artifact empty"
expect_gate_fail "${MALFORMED_FIXTURE}" "malformed artifact" "validator rejected artifact"
expect_gate_fail "${WRONG_ROOT_FIXTURE}" "wrong root artifact" "validator rejected artifact"
expect_gate_fail "${STDOUT_CONTAMINATED_FIXTURE}" "stdout-contaminated artifact" "validator rejected artifact"
expect_gate_fail "${REJECTED_FIXTURE}" "helper-only artifact" "validator rejected artifact"
expect_gate_fail "${VALID_FIXTURE}" "no-data/failure artifact" "verdict is not PASS"
expect_gate_fail "${SAME_CLIENT_FIXTURE}" "same-client selected path" "requires observer implementation to differ"
expect_gate_fail "${UNSELECTED_HELPER_FIXTURE}" "unselected helper-only participant" "participant lacks real process evidence"
expect_gate_fail "${SELECTED_DUP_ENDPOINT_FIXTURE}" "selected duplicate endpoint" "duplicate participant endpoint"
expect_gate_fail "${UNSELECTED_DUP_ENDPOINT_FIXTURE}" "unselected duplicate endpoint" "duplicate participant endpoint"
expect_gate_fail "${PASS_FAILURE_REASON_FIXTURE}" "PASS with failure_reason" "failure_reason is not allowed"

echo "PASS: rust skeleton fixtures and mixed-client gate boundaries confirmed"
