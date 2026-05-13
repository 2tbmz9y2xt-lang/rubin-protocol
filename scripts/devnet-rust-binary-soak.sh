#!/usr/bin/env bash
# devnet-rust-binary-soak.sh — RUB-27 Rust helper/advisory launch harness.
#
# Launches a real `rubin-node` Rust binary as a process, records honest
# helper-only/advisory non-process evidence, and fails closed if the
# binary cannot be built or launched.
#
# Skeleton scope (RUB-27): Rust-only process launch. The emitted
# mixed_client_evidence_v1 artifact is a non-authoritative FAIL schema
# marker labeled by scenario/failure_reason as helper-only/advisory and
# non-process. It is intentionally NOT full mixed-client process-soak
# evidence: a single-Rust helper run has no cross-implementation tx_path
# proof, and that full process proof is owned by RUB-21, RUB-22, and
# RUB-23. The Go participant in the marker is a declared placeholder
# (name + implementation only) so the RUB-24 schema shape can still be
# validated, while the RUB-25 PASS gate rejects it.
#
# Hostile-case enforcement (RUB-27 enumeration → enforcement layer):
#   * missing Rust binary           → cargo build fails → exit non-zero before any
#                                     evidence/report JSON is written; the artifact
#                                     root may still exist for forensics via the
#                                     EXIT trap (rubin_process_init creates it
#                                     up-front) — the failure signal is the
#                                     non-zero exit and absence of the JSONs,
#                                     not absence of the directory itself
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

CHECK_EVIDENCE="" CHECK_EVIDENCE_MODE=0

usage() { echo "usage: $0 [--check-evidence PATH]" >&2; }
while (($#)); do
  case "$1" in
    --check-evidence)
      [[ $# -ge 2 ]] || { usage; exit 2; }
      CHECK_EVIDENCE_MODE=1
      CHECK_EVIDENCE="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage
      exit 2
      ;;
  esac
done

command -v python3 >/dev/null 2>&1 || {
  echo "python3 is required for Rust helper/advisory launch marker" >&2
  exit 1
}
[[ -r "${VALIDATOR}" ]] || { echo "validator unreadable: ${VALIDATOR}" >&2; exit 1; }
[[ -x "${DEV_ENV}" ]] || { echo "dev-env wrapper missing or non-executable: ${DEV_ENV}" >&2; exit 1; }

run_fips_preflight_before_captured_dev_env() {
  if [[ "${RUBIN_OPENSSL_FIPS_MODE:-off}" != "only" ]]; then
    return 0
  fi
  if [[ "${RUBIN_OPENSSL_SKIP_FIPS_GUARD:-0}" == "1" ]]; then
    return 0
  fi

  echo "Running FIPS-only preflight before captured dev-env command streams" >&2
  "${DEV_ENV}" -- "${REPO_ROOT}/scripts/crypto/openssl/fips-preflight.sh" >&2
}

run_validator() {
  RUBIN_OPENSSL_SKIP_FIPS_GUARD=1 "${DEV_ENV}" -- python3 "${VALIDATOR}" "$@"
}

mixed_gate_fail() {
  echo "FAIL: mixed-client process evidence gate: $*" >&2
  return 1
}

print_prefixed_file() {
  local label="$1" path="$2"
  [[ -s "${path}" ]] || return 0
  echo "${label}:" >&2
  sed 's/^/  /' "${path}" >&2
}

check_mixed_client_pass_evidence() {
  local artifact="${1:-}" validator_stdout="" validator_stderr=""
  local gate_error tmp_parent

  [[ -n "${artifact}" ]] || mixed_gate_fail "artifact path is required" || return 1
  [[ -f "${artifact}" ]] || mixed_gate_fail "artifact not found or not a regular file: ${artifact}" || return 1
  [[ -r "${artifact}" ]] || mixed_gate_fail "artifact unreadable: ${artifact}" || return 1
  [[ -s "${artifact}" ]] || mixed_gate_fail "artifact empty: ${artifact}" || return 1

  run_fips_preflight_before_captured_dev_env

  tmp_parent="${TMPDIR:-/tmp}"
  tmp_parent="$(cd -- "${tmp_parent}" && pwd -P)" || return 1
  validator_stdout="$(mktemp "${tmp_parent%/}/rubin-mixed-validator-stdout.XXXXXX")" || return 1
  validator_stderr="$(mktemp "${tmp_parent%/}/rubin-mixed-validator-stderr.XXXXXX")" || {
    rm -f -- "${validator_stdout}"
    return 1
  }

  if ! run_validator "${artifact}" >"${validator_stdout}" 2>"${validator_stderr}"; then
    echo "FAIL: mixed-client process evidence gate validator rejected artifact: ${artifact}" >&2
    print_prefixed_file "validator stdout" "${validator_stdout}"
    print_prefixed_file "validator stderr" "${validator_stderr}"
    rm -f -- "${validator_stdout}" "${validator_stderr}"
    return 1
  fi

  if ! python3 - "${validator_stdout}" "${artifact}" <<'PY'
import sys; from pathlib import Path
actual = Path(sys.argv[1]).read_text(encoding="utf-8")
artifact = sys.argv[2]
sys.exit(0 if actual in {f"PASS: {artifact}\n", f"PASS: {Path(artifact)}\n"} else 1)
PY
  then
    echo "FAIL: mixed-client process evidence gate validator stdout contaminated for: ${artifact}" >&2
    echo "expected stdout: PASS: ${artifact} (or validator Path spelling)" >&2
    print_prefixed_file "actual stdout" "${validator_stdout}"
    print_prefixed_file "validator stderr" "${validator_stderr}"
    rm -f -- "${validator_stdout}" "${validator_stderr}"
    return 1
  fi

  print_prefixed_file "validator stderr" "${validator_stderr}"
  rm -f -- "${validator_stdout}" "${validator_stderr}"

  if ! gate_error="$(python3 - "${artifact}" 2>&1 <<'PY'
import json
import sys

path = sys.argv[1]
with open(path, encoding="utf-8") as f:
    data = json.load(f)


def fail(message: str) -> None:
    print(message, file=sys.stderr)
    sys.exit(1)


if data.get("evidence_type") != "mixed_client_process_soak":
    fail(
        "evidence_type is not mixed_client_process_soak: "
        f"{data.get('evidence_type')!r}"
    )
if data.get("verdict") != "PASS":
    fail(
        "verdict is not PASS; mixed-client process gate rejects "
        f"{data.get('verdict')!r} evidence"
    )
if "failure_reason" in data:
    fail("failure_reason is not allowed on PASS mixed-client process evidence")

participants = data.get("participants")
tx_path = data.get("tx_path")
if not isinstance(participants, list) or not isinstance(tx_path, dict):
    fail("schema floor unexpectedly allowed missing participants or tx_path")

by_name = {p["name"]: p for p in participants}
submitted_at = tx_path.get("submitted_at")
observed_at = tx_path.get("observed_at")
if not isinstance(submitted_at, str) or not isinstance(observed_at, list):
    fail("schema floor unexpectedly allowed malformed tx_path references")

missing_process_fields = []
for participant in participants:
    missing = [
        field for field in ("endpoint", "started_at") if not participant.get(field)
    ]
    if missing:
        missing_process_fields.append(
            f"{participant['name']} missing {','.join(missing)}"
        )

if missing_process_fields:
    fail(
        "participant lacks real process evidence: "
        + "; ".join(missing_process_fields)
    )

endpoint_owner = {}
for participant in participants:
    endpoint = participant["endpoint"]
    previous = endpoint_owner.setdefault(endpoint, participant["name"])
    if previous != participant["name"]:
        fail(
            "duplicate participant endpoint in PASS mixed-client process evidence: "
            f"{endpoint!r} used by {previous!r} and {participant['name']!r}"
        )

referenced = [submitted_at, *observed_at]
for name in referenced:
    participant = by_name.get(name)
    if participant is None:
        fail(f"tx_path references undeclared participant: {name!r}")

impls = {by_name[name]["implementation"] for name in referenced}
if not {"go", "rust"} <= impls:
    fail(
        "tx_path does not reference both Go and Rust process participants; "
        f"referenced implementations={sorted(impls)}"
    )
PY
)"; then
    echo "FAIL: mixed-client process evidence gate rejected artifact: ${artifact}" >&2
    printf '%s\n' "${gate_error}" >&2
    return 1
  fi

  echo "PASS: mixed-client process evidence gate accepted ${artifact}"
}

if [[ "${CHECK_EVIDENCE_MODE}" == "1" ]]; then
  check_mixed_client_pass_evidence "${CHECK_EVIDENCE}"
  exit 0
fi

command -v perl >/dev/null 2>&1 || {
  echo "perl is required for Rust helper/advisory launch marker" >&2
  exit 1
}

# shellcheck source=scripts/devnet-process-common.sh disable=SC1091
source "${HELPER}"
rubin_process_init rust-helper-advisory

NODE_BIN="${RUBIN_PROCESS_ARTIFACT_ROOT}/rubin-node-rust"
DATA_DIR="${RUBIN_PROCESS_ARTIFACT_ROOT}/node-rust"
LOG_FILE="node-rust.log"
REPORT_JSON="${RUBIN_PROCESS_ARTIFACT_ROOT}/rust-helper-advisory-report.json"
EVIDENCE_JSON="${RUBIN_PROCESS_ARTIFACT_ROOT}/rust-helper-advisory-schema-marker.json"
mkdir -p "${DATA_DIR}"

# Build the Rust binary via the project dev-env wrapper. cargo failure
# exits non-zero before any artifact is emitted, satisfying the
# "missing Rust binary" hostile case.
echo "Building Rust rubin-node binary"
# The produced binary path is derived from Cargo's authoritative build
# output (machine-readable JSON event stream) instead of being guessed
# from a host-layout assumption. Cargo emits one `compiler-artifact`
# event per artifact; we select the one whose `target.name == "rubin-node"`
# AND `target.kind` includes `"bin"` AND `executable` is non-null, then
# take its `executable` path. That path is correct under every cargo
# axis that affects placement: `--target-dir`, `CARGO_TARGET_DIR`,
# `.cargo/config.toml build.target-dir`, `--target <triple>`,
# `CARGO_BUILD_TARGET`, `.cargo/config.toml build.target`,
# `--profile <name>`, and `--out-dir <dir>` (PR #1510 wave-3 codex
# finding: previously pinned `${target-dir}/release/rubin-node` lookup
# missed `target/<triple>/release/` placement when a target triple was
# in effect). We still pass `--target-dir` so the artifact root (and
# its EXIT-trap-managed cleanup) owns the build cache; cargo's metadata
# is what actually tells the harness where the binary landed.
# Side-effect: each invocation gets its own mktemp'd cargo-target/, so
# nothing reuses a shared cache — fine for a helper/advisory launch marker whose job
# is to prove a real-process launch end-to-end on every run.
CARGO_TARGET_DIR_LOCAL="${RUBIN_PROCESS_ARTIFACT_ROOT}/cargo-target"
CARGO_BUILD_LOG="${RUBIN_PROCESS_ARTIFACT_ROOT}/cargo-build.jsonl"
run_fips_preflight_before_captured_dev_env

# Force the host triple as the build target (PR #1510 wave-N+1 codex
# finding "Force host target before executing rubin-node"): without an
# explicit --target, cargo inherits CARGO_BUILD_TARGET / `build.target`
# / .cargo/config.toml `[build] target=`. A non-host configured default
# yields a cross-compiled binary; the cargo-metadata path resolution
# below still picks the right path, but `rubin_process_start` then
# fails at runtime with `exec format error` because the harness exec's
# the artifact directly. Pinning --target to rustc's reported host
# triple defeats every config/env axis that could redirect to a
# non-host triple. Cargo CLI precedence: explicit --target overrides
# CARGO_BUILD_TARGET env and .cargo/config.toml `build.target`.
HOST_TRIPLE="$(RUBIN_OPENSSL_SKIP_FIPS_GUARD=1 "${DEV_ENV}" -- rustc -vV | awk '/^host:/ {print $2}')"
[[ -n "${HOST_TRIPLE}" ]] || {
  echo "could not derive host target triple from rustc -vV output" >&2
  exit 1
}
RUBIN_OPENSSL_SKIP_FIPS_GUARD=1 "${DEV_ENV}" -- cargo build \
  --manifest-path "${RUST_WORKSPACE_ROOT}/Cargo.toml" \
  --release --locked -p rubin-node \
  --target "${HOST_TRIPLE}" \
  --target-dir "${CARGO_TARGET_DIR_LOCAL}" \
  --message-format=json-render-diagnostics >"${CARGO_BUILD_LOG}"

# Fail-closed JSONL parser. Cargo's --message-format=json-render-diagnostics
# routes machine-readable JSON events to stdout (one event per line) and
# human-rendered diagnostics to stderr; this stdout stream therefore
# MUST be pure JSON. The parser exits non-zero on three classes of bad
# input (PR #1510 wave-N+1 copilot P1 finding: previous "fail-closed"
# label sat on a fail-OPEN body that silently `continue`d on contamination):
#   (a) any non-empty line whose first byte isn't '{' (wrapper banner,
#       dev-env preamble, environment-injected message) — fail-closed;
#   (b) any line that starts with '{' but JSON-decodes with an error
#       (truncated stream, encoding corruption) — fail-closed;
#   (c) the whole stream contains zero compiler-artifact events
#       matching target.name=rubin-node + kind=bin + non-null executable
#       (cargo skipped the build, or toolchain changed event semantics)
#       — fail-closed via final exit 1.
# Empty lines are tolerated as a defensive compatibility hedge; valid
# JSON events with reason != compiler-artifact (e.g., compiler-message,
# build-script-executed, build-finished) are correctly skipped — they
# are part of cargo's normal stream, not contamination.
CARGO_TARGET_BIN="$(python3 - "${CARGO_BUILD_LOG}" <<'PY'
import json
import sys

log_path = sys.argv[1]
selected = None
with open(log_path, encoding="utf-8") as f:
    for raw in f:
        line = raw.strip()
        if not line:
            continue
        if not line.startswith("{"):
            sys.stderr.write(
                f"cargo build log contamination: non-JSON line: {line[:160]!r}\n"
            )
            sys.exit(1)
        try:
            ev = json.loads(line)
        except json.JSONDecodeError as exc:
            sys.stderr.write(
                f"cargo build log JSON parse error: {exc}: {line[:160]!r}\n"
            )
            sys.exit(1)
        if ev.get("reason") != "compiler-artifact":
            continue
        target = ev.get("target") or {}
        if target.get("name") != "rubin-node":
            continue
        kinds = target.get("kind") or []
        if "bin" not in kinds:
            continue
        executable = ev.get("executable")
        if not executable:
            continue
        # Don't break: take the LAST matching event so a release
        # rebuild's final link wins over any earlier deps-only emission.
        selected = executable
if selected is None:
    sys.exit(1)
print(selected)
PY
)" || {
  echo "cargo build log parser failed (no rubin-node bin executable artifact, or contamination); raw log: ${CARGO_BUILD_LOG}" >&2
  exit 1
}
[[ -x "${CARGO_TARGET_BIN}" ]] || {
  echo "cargo-reported executable is not executable: ${CARGO_TARGET_BIN}" >&2
  exit 1
}
cp "${CARGO_TARGET_BIN}" "${NODE_BIN}"
[[ -x "${NODE_BIN}" ]] || {
  echo "rust binary copy is not executable: ${NODE_BIN}" >&2
  exit 1
}

# UTC-Z seconds-only canonical format per RUB-208 / PR-C policy
# enforced by the schema regex on participants[].started_at. Captured
# inside attempt_helper_launch AFTER the rpc-listening banner is
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
attempt_helper_launch() {
  rubin_process_start "${LOG_FILE}" "${NODE_BIN}" \
    --network devnet --datadir "${DATA_DIR}" \
    --bind 127.0.0.1:0 --rpc-bind 127.0.0.1:0 \
    || { LAUNCH_FAILURE_REASON="rubin_process_start did not register a Rust helper/advisory process"; return 1; }
  NODE_PID="${RUBIN_PROCESS_LAST_PID:-}"
  [[ -n "${NODE_PID}" ]] \
    || { LAUNCH_FAILURE_REASON="rubin_process_start did not capture a pid"; return 1; }
  rubin_process_wait_for_log "${LOG_FILE}" "rpc: listening=" 60 "${NODE_PID}" \
    || { LAUNCH_FAILURE_REASON="Rust helper/advisory launch did not emit rpc-listening banner within 60s"; return 1; }
  # Stamped here, immediately after the rpc-listening banner is observed,
  # so participants[].started_at reflects an observed start time rather
  # than a pre-launch wall-clock guess.
  STARTED_AT_UTC="$(python3 -c 'import datetime; print(datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))')"
  RPC_ADDR="$(rubin_process_extract_rpc_addr "${LOG_FILE}")" \
    || { LAUNCH_FAILURE_REASON="failed to extract rpc-listening address from log"; return 1; }
  [[ -n "${RPC_ADDR}" ]] \
    || { LAUNCH_FAILURE_REASON="rpc-listening banner missing address payload"; return 1; }
  rubin_process_wait_for_rpc_ready "${RPC_ADDR}" 30 \
    || { LAUNCH_FAILURE_REASON="Rust helper/advisory /get_tip RPC was not reachable within 30s"; return 1; }
  rubin_process_is_alive "${NODE_PID}" \
    || { LAUNCH_FAILURE_REASON="Rust helper/advisory process pid=${NODE_PID} exited after RPC probe"; return 1; }
  return 0
}

LAUNCH_STATUS="failed"
if attempt_helper_launch; then
  LAUNCH_STATUS="success"
fi

export EVIDENCE_JSON REPORT_JSON LAUNCH_STATUS LAUNCH_FAILURE_REASON \
       RPC_ADDR STARTED_AT_UTC NODE_BIN NODE_PID LOG_FILE DATA_DIR \
       RUBIN_PROCESS_ARTIFACT_ROOT
python3 - <<'PY'
import json
import os

e = os.environ
status = e["LAUNCH_STATUS"]
launch_failure_raw = (e.get("LAUNCH_FAILURE_REASON") or "").strip()
helper_boundary = (
    "helper-only/advisory non-process Rust launch marker; full "
    "mixed-client process tx_path proof is RUB-21/RUB-22/RUB-23"
)

# Compute one effective_failure_reason and use it in BOTH evidence and
# report (PR #1510 wave-N+1 copilot P2 finding: previously evidence had
# an older fallback while report passed
# LAUNCH_FAILURE_REASON through unchanged, so a failed-path with empty
# env var produced an empty/None report.failure_reason while evidence
# had explicit text). Single computed value eliminates the asymmetry.
if status == "success":
    effective_failure_reason = helper_boundary
elif launch_failure_raw:
    effective_failure_reason = f"{helper_boundary}; launch_failure={launch_failure_raw}"
else:
    effective_failure_reason = f"{helper_boundary}; launch_failure=unspecified"

if status == "success":
    rust_participant = {
        "name": "node-rust",
        "implementation": "rust",
        "endpoint": e["RPC_ADDR"],
        "started_at": e["STARTED_AT_UTC"],
    }
else:
    # Honest evidence: on launch failure no real endpoint/started_at
    # was observed, so the rust participant carries name+implementation
    # only. The schema-required cross-impl participant pair is satisfied
    # by the declared go placeholder below.
    rust_participant = {"name": "node-rust", "implementation": "rust"}

evidence = {
    "schema_version": "rubin-mixed-client-devnet-evidence-v1",
    "evidence_type": "mixed_client_process_soak",
    "scenario": "rust_helper_advisory_non_process_marker",
    "verdict": "FAIL",
    "failure_reason": effective_failure_reason,
    "participants": [
        rust_participant,
        # Declared Go placeholder. RUB-21/RUB-22/RUB-23 replace this
        # marker with a real-launched Go participant plus a tx_path PASS
        # process-soak artifact.
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
# (PR #1510 wave-1 copilot P2 finding): a launch that registers a pid
# and emits the rpc-listening banner before a later readiness check
# fails previously dropped both fields, hiding identity that operators
# need for failure forensics. The pid_observed / rpc_observed /
# started_observed booleans carry "did we ever see this".
#
# log_path is the absolute resolved location of the harness log,
# alongside artifact_root, so an operator reading this report from
# outside the harness CWD (tarball, archived report, ticket attachment)
# can still resolve and tail the log file without re-deriving the
# artifact-root prefix (PR #1510 wave-N+1 controller-isolated reviewer
# P2 finding: report was carrying log_file relative-only).
node_pid_raw = (e.get("NODE_PID") or "").strip()
rpc_addr_raw = (e.get("RPC_ADDR") or "").strip()
started_at_raw = (e.get("STARTED_AT_UTC") or "").strip()
artifact_root = e["RUBIN_PROCESS_ARTIFACT_ROOT"]
log_file_relative = e["LOG_FILE"]
log_path_absolute = os.path.join(artifact_root, log_file_relative)
report = {
    "scenario": "rust_helper_advisory_non_process",
    "evidence_class": "helper_only_advisory_non_process",
    "claim_boundary": "does_not_prove_mixed_client_process_soak",
    "implementation": "rust",
    "command_path": e["NODE_BIN"],
    "data_dir": e["DATA_DIR"],
    "artifact_root": artifact_root,
    "log_file": log_file_relative,
    "log_path": log_path_absolute,
    "launch_status": status,
    "pid": int(node_pid_raw) if node_pid_raw else None,
    "pid_observed": bool(node_pid_raw),
    "rpc_endpoint": rpc_addr_raw or None,
    "rpc_observed": bool(rpc_addr_raw),
    "started_at_utc": started_at_raw or None,
    "started_observed": bool(started_at_raw),
    "failure_reason": effective_failure_reason,
    "follow_ups": [
        "RUB-21 owns full mixed-client process tx_path PASS evidence",
        "RUB-22/RUB-23 own end-to-end mixed-client tx propagation",
        "RUB-25 owns CI fail-closed process evidence gate integration",
    ],
}
with open(e["REPORT_JSON"], "w", encoding="utf-8") as f:
    json.dump(report, f, indent=2, sort_keys=True)
    f.write("\n")
PY

# RUB-24 schema validator is used here only for the non-authoritative
# helper/advisory FAIL marker shape. The marker must validate as a
# well-formed FAIL object, while RUB-25's PASS gate still rejects it as
# not full mixed-client process soak evidence.
echo "Validating helper/advisory schema marker via RUB-24 schema validator"
run_validator "${EVIDENCE_JSON}"

if [[ "${LAUNCH_STATUS}" == "success" ]]; then
  PASS_SUMMARY="HELPER_ONLY_ADVISORY: rust binary launch observed pid=${NODE_PID} rpc=${RPC_ADDR} (non-process marker; full mixed-client tx_path proof is RUB-21/RUB-22/RUB-23)"
  if [[ "${RUBIN_PROCESS_KEEP_ARTIFACTS}" == "1" ]]; then
    echo "${PASS_SUMMARY}; report=${REPORT_JSON} evidence=${EVIDENCE_JSON}"
  else
    echo "${PASS_SUMMARY}; set KEEP_TMP=1 to retain artifacts"
  fi
  exit 0
else
  FAILURE_REASON_FOR_SUMMARY="${LAUNCH_FAILURE_REASON}"
  if [[ -z "${FAILURE_REASON_FOR_SUMMARY//[[:space:]]/}" ]]; then
    FAILURE_REASON_FOR_SUMMARY="launch_failure=unspecified"
  else
    FAILURE_REASON_FOR_SUMMARY="launch_failure=${FAILURE_REASON_FOR_SUMMARY}"
  fi
  FAIL_SUMMARY="FAIL: helper-only/advisory non-process Rust launch marker; full mixed-client process tx_path proof is RUB-21/RUB-22/RUB-23; ${FAILURE_REASON_FOR_SUMMARY}"
  echo "${FAIL_SUMMARY}; report=${REPORT_JSON} evidence=${EVIDENCE_JSON}" >&2
  exit 1
fi
