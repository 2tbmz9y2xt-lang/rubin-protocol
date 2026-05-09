#!/usr/bin/env bash
# devnet-rust-binary-soak.sh — RUB-27 process-soak skeleton harness.
#
# Launches a real `rubin-node` Rust binary as a process, records honest
# process-level evidence (mixed_client_evidence_v1 conformant), and fails
# closed if the binary cannot be built or launched.
#
# Skeleton scope (RUB-27): Rust-only process launch. The emitted evidence
# is intentionally `verdict=FAIL` because a single-Rust skeleton has no
# cross-implementation tx_path proof — that proof is owned by RUB-21,
# RUB-22, RUB-23. The Go participant in the artifact is a declared
# placeholder (name + implementation only) so the schema cross-field
# gate (mixed_client_process_soak requires both go and rust impls and
# at least 2 participants) accepts the artifact; downstream issues
# replace the placeholder with a real-launched Go participant plus a
# tx_path PASS section.
#
# Hostile-case enforcement (RUB-27 enumeration → enforcement layer):
#   * missing Rust binary           → cargo build fails → exit non-zero, no artifact
#   * binary exits immediately      → rubin_process_start detects exit-before-registration
#   * pid recorded but already dead → wait_for_log checks rubin_process_is_alive per iteration
#   * stdout/stderr in JSON parse   → evidence built via python json.dump, never via shell jq
#   * helper artifact labeled real  → evidence emitter only fills endpoint/started_at on real launch
#   * timeout returns pass          → wait_for_* non-zero on timeout, harness exits non-zero
#   * wrong implementation identity → hardcoded "rust" string in evidence emitter
#   * schema misses command/pid     → command/pid live in custom REPORT (out-of-band of schema)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEV_ENV="${REPO_ROOT}/scripts/dev-env.sh"
RUST_WORKSPACE_ROOT="${REPO_ROOT}/clients/rust"
HELPER="${REPO_ROOT}/scripts/devnet-process-common.sh"
VALIDATOR="${REPO_ROOT}/scripts/devnet/validate_mixed_client_evidence.py"

usage() { echo "usage: $0" >&2; }
case "${1:-}" in
  -h|--help)
    usage
    exit 0
    ;;
  "")
    ;;
  *)
    usage
    exit 2
    ;;
esac

for tool in python3 perl; do
  command -v "${tool}" >/dev/null 2>&1 || {
    echo "${tool} is required for Rust binary soak skeleton" >&2
    exit 1
  }
done
[[ -r "${VALIDATOR}" ]] || { echo "validator unreadable: ${VALIDATOR}" >&2; exit 1; }
[[ -x "${DEV_ENV}" ]] || { echo "dev-env wrapper missing or non-executable: ${DEV_ENV}" >&2; exit 1; }

# shellcheck source=scripts/devnet-process-common.sh disable=SC1091
source "${HELPER}"
rubin_process_init rust-binary-soak

NODE_BIN="${RUBIN_PROCESS_ARTIFACT_ROOT}/rubin-node-rust"
DATA_DIR="${RUBIN_PROCESS_ARTIFACT_ROOT}/node-rust"
LOG_FILE="node-rust.log"
REPORT_JSON="${RUBIN_PROCESS_ARTIFACT_ROOT}/rust-binary-soak-report.json"
EVIDENCE_JSON="${RUBIN_PROCESS_ARTIFACT_ROOT}/rust-binary-soak-evidence.json"
mkdir -p "${DATA_DIR}"

# Build the Rust binary via the project dev-env wrapper. cargo failure
# exits non-zero before any artifact is emitted, satisfying the
# "missing Rust binary" hostile case.
echo "Building Rust rubin-node binary"
"${DEV_ENV}" -- cargo build \
  --manifest-path "${RUST_WORKSPACE_ROOT}/Cargo.toml" \
  --release --locked -p rubin-node
CARGO_TARGET_BIN="${RUST_WORKSPACE_ROOT}/target/release/rubin-node"
[[ -x "${CARGO_TARGET_BIN}" ]] || {
  echo "cargo build did not produce executable: ${CARGO_TARGET_BIN}" >&2
  exit 1
}
cp "${CARGO_TARGET_BIN}" "${NODE_BIN}"
[[ -x "${NODE_BIN}" ]] || {
  echo "rust binary copy is not executable: ${NODE_BIN}" >&2
  exit 1
}

# UTC-Z seconds-only canonical format per RUB-208 / PR-C policy
# enforced by the schema regex on participants[].started_at. Captured
# inside attempt_skeleton_launch AFTER the rpc-listening banner is
# observed (P1 finding from PR #1510 review): on slow starts or banner
# timeouts a pre-launch capture would have stamped evidence with a time
# earlier than the actual observed start. The empty default here means
# evidence carries no started_at on launch failure paths, which is
# honest — we never observed a started state.
STARTED_AT_UTC=""

LAUNCH_FAILURE_REASON=""
RPC_ADDR=""
NODE_PID=""

# Single-purpose function so set -e stays on for the rest of the script
# while each helper failure routes into LAUNCH_FAILURE_REASON. Bash
# leaves set -e disarmed for commands followed by `||`, so the
# `cmd || { reason=...; return 1; }` form here does not abort the script
# on a single helper failure — the calling `if` block decides next steps.
attempt_skeleton_launch() {
  rubin_process_start "${LOG_FILE}" "${NODE_BIN}" \
    --network devnet --datadir "${DATA_DIR}" \
    --bind 127.0.0.1:0 --rpc-bind 127.0.0.1:0 \
    || { LAUNCH_FAILURE_REASON="rubin_process_start did not register a Rust skeleton process"; return 1; }
  NODE_PID="${RUBIN_PROCESS_LAST_PID:-}"
  [[ -n "${NODE_PID}" ]] \
    || { LAUNCH_FAILURE_REASON="rubin_process_start did not capture a pid"; return 1; }
  rubin_process_wait_for_log "${LOG_FILE}" "rpc: listening=" 60 "${NODE_PID}" \
    || { LAUNCH_FAILURE_REASON="rust skeleton did not emit rpc-listening banner within 60s"; return 1; }
  # Stamped here, immediately after the rpc-listening banner is observed,
  # so participants[].started_at reflects an observed start time rather
  # than a pre-launch wall-clock guess.
  STARTED_AT_UTC="$(python3 -c 'import datetime; print(datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))')"
  RPC_ADDR="$(rubin_process_extract_rpc_addr "${LOG_FILE}")" \
    || { LAUNCH_FAILURE_REASON="failed to extract rpc-listening address from log"; return 1; }
  [[ -n "${RPC_ADDR}" ]] \
    || { LAUNCH_FAILURE_REASON="rpc-listening banner missing address payload"; return 1; }
  rubin_process_wait_for_rpc_ready "${RPC_ADDR}" 30 \
    || { LAUNCH_FAILURE_REASON="rust skeleton /get_tip RPC was not reachable within 30s"; return 1; }
  rubin_process_is_alive "${NODE_PID}" \
    || { LAUNCH_FAILURE_REASON="rust skeleton process pid=${NODE_PID} exited after RPC probe"; return 1; }
  return 0
}

LAUNCH_STATUS="failed"
if attempt_skeleton_launch; then
  LAUNCH_STATUS="success"
fi

export EVIDENCE_JSON REPORT_JSON LAUNCH_STATUS LAUNCH_FAILURE_REASON \
       RPC_ADDR STARTED_AT_UTC NODE_BIN NODE_PID LOG_FILE DATA_DIR
python3 - <<'PY'
import json
import os

e = os.environ
status = e["LAUNCH_STATUS"]

if status == "success":
    failure_reason = (
        "rust-only skeleton run; cross-implementation tx_path proof is "
        "RUB-21/22/23"
    )
    rust_participant = {
        "name": "node-rust",
        "implementation": "rust",
        "endpoint": e["RPC_ADDR"],
        "started_at": e["STARTED_AT_UTC"],
    }
else:
    failure_reason = (
        e["LAUNCH_FAILURE_REASON"]
        or "rust skeleton launch failed without a specific reason"
    )
    # Honest evidence: on launch failure no real endpoint/started_at
    # was observed, so the rust participant carries name+implementation
    # only. The schema-required cross-impl participant pair is satisfied
    # by the declared go placeholder below.
    rust_participant = {"name": "node-rust", "implementation": "rust"}

evidence = {
    "schema_version": "rubin-mixed-client-devnet-evidence-v1",
    "evidence_type": "mixed_client_process_soak",
    "scenario": "rust_binary_soak_skeleton",
    "verdict": "FAIL",
    "failure_reason": failure_reason,
    "participants": [
        rust_participant,
        # Declared Go placeholder. RUB-21/22/23 replace this with a
        # real-launched Go participant plus a tx_path PASS section.
        {"name": "node-go", "implementation": "go"},
    ],
}
with open(e["EVIDENCE_JSON"], "w", encoding="utf-8") as f:
    json.dump(evidence, f, indent=2, sort_keys=True)
    f.write("\n")

# Out-of-band custom report: carries command path / pid that the
# committed mixed_client_evidence_v1 schema does not model. Not
# validated by validate_mixed_client_evidence.py — this report is
# operator-facing audit material, kept in a sibling file so the
# schema-validated artifact stays minimal.
#
# pid / rpc_endpoint / started_at_utc are recorded whenever they were
# observed during the launch attempt, regardless of final launch_status
# (P2 finding from PR #1510 review): a launch that registers a pid and
# emits the rpc-listening banner before a later readiness check fails
# previously dropped both fields, hiding identity that operators need
# for failure forensics. The pid_observed / rpc_observed / started_observed
# flags carry the boolean "did we ever see this during the attempt".
node_pid_raw = (e.get("NODE_PID") or "").strip()
rpc_addr_raw = (e.get("RPC_ADDR") or "").strip()
started_at_raw = (e.get("STARTED_AT_UTC") or "").strip()
report = {
    "scenario": "rust_binary_soak_skeleton",
    "implementation": "rust",
    "command_path": e["NODE_BIN"],
    "data_dir": e["DATA_DIR"],
    "log_file": e["LOG_FILE"],
    "launch_status": status,
    "pid": int(node_pid_raw) if node_pid_raw else None,
    "pid_observed": bool(node_pid_raw),
    "rpc_endpoint": rpc_addr_raw or None,
    "rpc_observed": bool(rpc_addr_raw),
    "started_at_utc": started_at_raw or None,
    "started_observed": bool(started_at_raw),
    "failure_reason": e["LAUNCH_FAILURE_REASON"] if status == "failed" else None,
    "follow_ups": [
        "RUB-21 owns cross-implementation tx_path PASS evidence",
        "RUB-22/23 own end-to-end tx propagation",
        "RUB-25 owns CI fail-closed gate integration",
    ],
}
with open(e["REPORT_JSON"], "w", encoding="utf-8") as f:
    json.dump(report, f, indent=2, sort_keys=True)
    f.write("\n")
PY

# RUB-24 schema validator is the canonical gate: must accept the
# skeleton artifact (well-formed shape) regardless of LAUNCH_STATUS.
# A validator rejection here is a real bug in this harness, not a
# launch-time symptom — let `set -e` propagate the non-zero exit.
echo "Validating emitted evidence via RUB-24 schema validator"
python3 "${VALIDATOR}" "${EVIDENCE_JSON}"

if [[ "${LAUNCH_STATUS}" == "success" ]]; then
  PASS_SUMMARY="SKELETON: rust binary soak launched pid=${NODE_PID} rpc=${RPC_ADDR} (verdict=FAIL/skeleton-only; cross-impl tx_path is RUB-21/22/23)"
  if [[ "${RUBIN_PROCESS_KEEP_ARTIFACTS}" == "1" ]]; then
    echo "${PASS_SUMMARY}; report=${REPORT_JSON} evidence=${EVIDENCE_JSON}"
  else
    echo "${PASS_SUMMARY}; set KEEP_TMP=1 to retain artifacts"
  fi
  exit 0
else
  FAIL_SUMMARY="FAIL: rust skeleton launch failed: ${LAUNCH_FAILURE_REASON}"
  echo "${FAIL_SUMMARY}; report=${REPORT_JSON} evidence=${EVIDENCE_JSON}" >&2
  exit 1
fi
