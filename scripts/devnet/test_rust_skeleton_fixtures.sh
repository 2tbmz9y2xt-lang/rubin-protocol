#!/usr/bin/env bash
# test_rust_skeleton_fixtures.sh — RUB-27 helper marker plus RUB-25 gate tests.
#
# Wires the committed Rust helper/advisory marker fixtures to the RUB-24
# validator and exercises the RUB-25 mixed-client process evidence gate
# through fixture-driven pass/fail boundaries.
#
# This does not prove live Go/Rust runtime behavior; it anchors schema,
# label-boundary, and shell-gate acceptance claims to reproducible
# fixture exit codes.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DEV_ENV="${REPO_ROOT}/scripts/dev-env.sh"
VALIDATOR="${REPO_ROOT}/scripts/devnet/validate_mixed_client_evidence.py"
GATE_SCRIPT="${REPO_ROOT}/scripts/devnet-rust-binary-soak.sh"
HELPER_MARKER_FIXTURE="${REPO_ROOT}/scripts/devnet/testdata/rust_helper_advisory_non_process_marker.json"
HELPER_FAILED_MARKER_FIXTURE="${REPO_ROOT}/scripts/devnet/testdata/rust_helper_advisory_failed_launch_marker.json"
REJECTED_FIXTURE="${REPO_ROOT}/scripts/devnet/testdata/rust_skeleton_helper_only_rejected.json"
VALID_MIXED_FIXTURE="${REPO_ROOT}/scripts/devnet/testdata/valid_process_mixed.json"

command -v python3 >/dev/null 2>&1 || { echo "python3 is required" >&2; exit 1; }
[[ -x "${DEV_ENV}" ]] || { echo "dev-env wrapper missing or non-executable: ${DEV_ENV}" >&2; exit 1; }
[[ -r "${VALIDATOR}" ]] || { echo "validator unreadable: ${VALIDATOR}" >&2; exit 1; }
[[ -x "${GATE_SCRIPT}" ]] || { echo "gate script missing or non-executable: ${GATE_SCRIPT}" >&2; exit 1; }
[[ -r "${HELPER_MARKER_FIXTURE}" ]] || { echo "helper marker fixture unreadable: ${HELPER_MARKER_FIXTURE}" >&2; exit 1; }
[[ -r "${HELPER_FAILED_MARKER_FIXTURE}" ]] || { echo "failed helper marker fixture unreadable: ${HELPER_FAILED_MARKER_FIXTURE}" >&2; exit 1; }
[[ -r "${REJECTED_FIXTURE}" ]] || { echo "rejected fixture unreadable: ${REJECTED_FIXTURE}" >&2; exit 1; }
[[ -r "${VALID_MIXED_FIXTURE}" ]] || { echo "valid mixed fixture unreadable: ${VALID_MIXED_FIXTURE}" >&2; exit 1; }

TMP_PARENT_RAW="${TMPDIR:-/tmp}"
TMP_PARENT="$(cd -- "${TMP_PARENT_RAW}" && pwd -P)" || { echo "failed to canonicalize TMPDIR=${TMP_PARENT_RAW}" >&2; exit 1; }
TMP_ROOT="$(mktemp -d "${TMP_PARENT%/}/rubin-rust-skeleton-fixtures.XXXXXX")" || { echo "failed to create fixture temp dir under ${TMP_PARENT}" >&2; exit 1; }
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

assert_helper_marker_labels() {
  local fixture="$1"
  python3 - "${fixture}" <<'PY'
import json
import sys

path = sys.argv[1]
with open(path, encoding="utf-8") as f:
    data = json.load(f)

errors = []
if data.get("scenario") != "rust_helper_advisory_non_process_marker":
    errors.append(f"scenario is not helper/advisory/non-process: {data.get('scenario')!r}")
if data.get("verdict") != "FAIL":
    errors.append(f"helper marker verdict must be FAIL: {data.get('verdict')!r}")
reason = data.get("failure_reason")
required = ["helper-only/advisory", "non-process", "full mixed-client process", "RUB-21", "RUB-22", "RUB-23"]
if not isinstance(reason, str) or any(token not in reason for token in required):
    errors.append(f"failure_reason does not pin helper/process boundary: {reason!r}")
if data.get("evidence_type") != "mixed_client_process_soak":
    errors.append("schema marker must keep the RUB-24 process enum so the validator can check its shape")
if errors:
    for err in errors:
        print(f"FAIL: {err}", file=sys.stderr)
    sys.exit(1)
PY
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

# Acceptance leg 1: validator MUST accept the well-formed helper/advisory
# FAIL schema marker, and label checks MUST pin it as non-process.
echo "test_rust_skeleton_fixtures: helper/advisory marker must validate and stay labeled"
assert_helper_marker_labels "${HELPER_MARKER_FIXTURE}"
if ! run_validator "${HELPER_MARKER_FIXTURE}"; then
  echo "FAIL: validator rejected the helper/advisory schema marker" >&2
  exit 1
fi
assert_helper_marker_labels "${HELPER_FAILED_MARKER_FIXTURE}"
if ! run_validator "${HELPER_FAILED_MARKER_FIXTURE}"; then
  echo "FAIL: validator rejected the failed helper/advisory schema marker" >&2
  exit 1
fi

# Acceptance leg 2: validator MUST reject an actual helper-only label as
# outside the mixed_client_process_soak process schema. This pins the
# process/helper class boundary at the schema floor instead of relying on
# later cross-field failures under a stale process label.
echo "test_rust_skeleton_fixtures: helper-only label must be rejected"
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
  "evidence_type:" \
  "helper_only_advisory_non_process"; do
  if [[ "${REJECTED_OUTPUT}" != *"${needle}"* ]]; then
    echo "FAIL: helper-only rejection missing expected stable schema-boundary marker: ${needle}" >&2
    echo "actual output:" >&2
    printf '%s\n' "${REJECTED_OUTPUT}" >&2
    exit 1
  fi
done

echo "test_rust_skeleton_fixtures: mixed-client gate must pass valid process fixture"
expect_gate_pass "${VALID_MIXED_FIXTURE}" "valid mixed process fixture"
(cd "${REPO_ROOT}" && expect_gate_pass "./scripts/devnet/testdata/valid_process_mixed.json" "valid mixed process fixture with ./ spelling")

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
expect_gate_fail "${REJECTED_FIXTURE}" "helper-only label artifact" "validator rejected artifact"
expect_gate_fail "${HELPER_MARKER_FIXTURE}" "helper/advisory schema marker" "verdict is not PASS"
expect_gate_fail "${SAME_CLIENT_FIXTURE}" "same-client selected path" "requires observer implementation to differ"
expect_gate_fail "${UNSELECTED_HELPER_FIXTURE}" "unselected helper-only participant" "participant lacks real process evidence"
expect_gate_fail "${SELECTED_DUP_ENDPOINT_FIXTURE}" "selected duplicate endpoint" "duplicate participant endpoint"
expect_gate_fail "${UNSELECTED_DUP_ENDPOINT_FIXTURE}" "unselected duplicate endpoint" "duplicate participant endpoint"
expect_gate_fail "${PASS_FAILURE_REASON_FIXTURE}" "PASS with failure_reason" "failure_reason is not allowed"

echo "PASS: rust helper/advisory marker and mixed-client gate boundaries confirmed"
