#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEV_ENV="${REPO_ROOT}/scripts/dev-env.sh"
COMPACT_SCRIPT="${REPO_ROOT}/scripts/devnet-rust-compact-relay.sh"
DA_SCRIPT="${REPO_ROOT}/scripts/devnet-rust-da-relay.sh"
ENV_BIN="/usr/bin/env"
SCRIPT_PATH="scripts/devnet-rust-compact-da-soak.sh"
: "${KEEP_TMP:=1}"
export KEEP_TMP
SELF_TEST=0
usage() { echo "usage: $0 [--self-test]" >&2; }
while (($#)); do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    --self-test) SELF_TEST=1; shift ;;
    *) usage; exit 2 ;;
  esac
done
# Combined Rust compact+DA process soak: orchestrate the merged compact (RUB-441)
# and DA (RUB-443) relay process smokes as children, capture each source-bound
# child report, verify the child node pids exited (anti-stale), and aggregate
# into a fail-closed combined report. Combined PASS requires both children PASS;
# both now reach PASS, so the combined soak produces verdict=PASS with both child
# verdicts and artifact paths bound to the repo/branch/commit. This harness adds
# no runtime/parser/provider/miner behavior — it only reuses already-merged
# children. `--self-test` exercises the fail-closed aggregation with synthetic
# child reports (compact!=PASS and da!=PASS both yield combined NO_DATA) without
# spawning nodes.

# Aggregate two child reports into the combined report. Reads COMPACT_REPORT,
# DA_REPORT, COMPACT_CLEANUP, DA_CLEANUP, REPORT_JSON, ARTIFACT_ROOT and the
# SOURCE_* binding from the environment; writes the combined report and returns
# 0 only when both children are PASS (fail-closed).
aggregate_and_write() {
  python3 - <<'PY'
import json, os, sys
def load(path, label):
    with open(path, encoding="utf-8") as fh:
        try:
            return json.load(fh)
        except json.JSONDecodeError as exc:
            raise SystemExit(f"malformed {label}: {exc}") from None
def node_binary(report):
    for p in report.get("participants") or []:
        if isinstance(p, dict) and isinstance(p.get("binary"), str) and p["binary"].strip():
            return p["binary"]
    return None
e = os.environ
compact = load(e["COMPACT_REPORT"], "compact report")
da = load(e["DA_REPORT"], "DA report")
cv, dv = compact.get("verdict"), da.get("verdict")
combined = "PASS" if cv == "PASS" and dv == "PASS" else "NO_DATA"
report = {
    "scenario": "rust_compact_da_combined_soak",
    "verdict": combined,
    "combined_verdict": combined,
    "compact_verdict": cv,
    "da_verdict": dv,
    "source": {
        "repo": e["SOURCE_REMOTE"],
        "branch": e["SOURCE_BRANCH"],
        "commit_sha": e["SOURCE_COMMIT"],
        "script": e["SCRIPT_PATH"],
        "artifact_root": e["ARTIFACT_ROOT"],
        "node_version": {
            "compact_binary": node_binary(compact),
            "da_binary": node_binary(da),
            "source_commit": e["SOURCE_COMMIT"],
        },
    },
    "artifact_paths": {
        "compact_report": e["COMPACT_REPORT"],
        "da_report": e["DA_REPORT"],
        "combined_report": e["REPORT_JSON"],
    },
    "prerequisites": {
        "compact_smoke": "RUB-441 devnet-rust-compact-relay.sh (PASS)",
        "da_smoke": "RUB-443 devnet-rust-da-relay.sh (PASS)",
    },
    "compact": {"verdict": cv, "failure_reason": compact.get("failure_reason"), "report": e["COMPACT_REPORT"], "cleanup": json.loads(e["COMPACT_CLEANUP"])},
    "da": {"verdict": dv, "failure_reason": da.get("failure_reason"), "report": e["DA_REPORT"], "cleanup": json.loads(e["DA_CLEANUP"])},
    "source_of_truth_summary": [
        "Compact relay is relay-only; DA txs enter a block only through the complete-set provider group, never as flat candidates.",
        "Combined PASS requires both child smokes PASS; this harness adds no runtime/parser/provider/miner behavior.",
    ],
    "out_of_scope": ["production_runtime_change", "new_p2p_handler_behavior", "new_miner_behavior", "go", "mixed_client", "final_devnet_readiness"],
}
if combined != "PASS":
    report["failure_reason"] = "child_smokes_not_pass"
with open(e["REPORT_JSON"], "w", encoding="utf-8") as f:
    json.dump(report, f, indent=2, sort_keys=True)
    f.write("\n")
print(f"{combined}: compact={cv} da={dv}; report={e['REPORT_JSON']}", file=sys.stderr)
raise SystemExit(0 if combined == "PASS" else 1)
PY
}

# Fail-closed aggregation self-test: synthesize child reports with controlled
# verdicts and assert the combined verdict + exit status without spawning nodes.
run_self_test() {
  command -v python3 >/dev/null 2>&1 || { echo "python3 is required for --self-test" >&2; return 1; }
  local td; td="$(mktemp -d "${TMPDIR:-/tmp}/rust-compact-da-soak-selftest.XXXXXX")"
  # shellcheck disable=SC2317
  trap 'rm -rf -- "${td}"' RETURN
  local synth_cleanup='{"cleanup_verified": true, "label": "x", "participant_pids": [1]}'
  _synth_report() {
    python3 - "$1" "$2" <<'PY'
import json, sys
path, verdict = sys.argv[1:3]
data = {"scenario": "x", "verdict": verdict, "participants": [{"name": "node-a", "pid": 1, "binary": "/tmp/rubin-node-rust"}]}
if verdict != "PASS":
    data["failure_reason"] = "synthetic"
with open(path, "w", encoding="utf-8") as f:
    json.dump(data, f)
PY
  }
  local rc combined fail=0 cv dv want_combined want_rc scenario
  for scenario in "PASS:PASS:PASS:0" "NO_DATA:PASS:NO_DATA:1" "PASS:FAIL:NO_DATA:1" "FAIL:FAIL:NO_DATA:1"; do
    IFS=':' read -r cv dv want_combined want_rc <<<"${scenario}"
    _synth_report "${td}/compact.json" "${cv}"
    _synth_report "${td}/da.json" "${dv}"
    rc=0
    COMPACT_REPORT="${td}/compact.json" DA_REPORT="${td}/da.json" \
      COMPACT_CLEANUP="${synth_cleanup}" DA_CLEANUP="${synth_cleanup}" \
      REPORT_JSON="${td}/combined.json" ARTIFACT_ROOT="${td}" \
      SOURCE_REMOTE="self-test" SOURCE_BRANCH="self-test" SOURCE_COMMIT="0" SCRIPT_PATH="${SCRIPT_PATH}" \
      aggregate_and_write >/dev/null 2>&1 || rc=$?
    combined="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["combined_verdict"])' "${td}/combined.json")"
    if [[ "${combined}" != "${want_combined}" || "${rc}" != "${want_rc}" ]]; then
      echo "self-test FAIL: compact=${cv} da=${dv} -> combined=${combined}/rc=${rc}, want ${want_combined}/${want_rc}" >&2
      fail=1
    fi
  done
  [[ "${fail}" == "0" ]] || return 1
  echo "PASS: compact+DA soak fail-closed aggregation self-test (combined NO_DATA when either child != PASS)"
}

if [[ "${SELF_TEST}" == "1" ]]; then
  run_self_test
  exit $?
fi

for tool in python3 perl ps git; do
  command -v "${tool}" >/dev/null 2>&1 || { echo "${tool} is required for Rust compact+DA soak evidence" >&2; exit 1; }
done
for path in "${DEV_ENV}" "${COMPACT_SCRIPT}" "${DA_SCRIPT}" "${ENV_BIN}"; do
  [[ -x "${path}" ]] || { echo "missing or non-executable: ${path}" >&2; exit 1; }
done

SOURCE_COMMIT="$(git -C "${REPO_ROOT}" rev-parse HEAD)"
SOURCE_BRANCH="$(git -C "${REPO_ROOT}" rev-parse --abbrev-ref HEAD)"
SOURCE_REMOTE="$(git -C "${REPO_ROOT}" remote get-url origin 2>/dev/null || echo rubin-protocol)"
export SOURCE_COMMIT SOURCE_BRANCH SOURCE_REMOTE SCRIPT_PATH

artifact_parent="${RUBIN_PROCESS_ARTIFACT_PARENT:-${TMPDIR:-/tmp}}"
case "${artifact_parent}" in /*) ;; *) echo "unsafe artifact parent: ${artifact_parent:-<empty>}" >&2; exit 1 ;; esac
case "/${artifact_parent}/" in *"/../"*) echo "unsafe artifact parent contains '..': ${artifact_parent}" >&2; exit 1 ;; esac
mkdir -p "${artifact_parent}"
ARTIFACT_PARENT_REAL="$(cd "${artifact_parent}" && pwd -P)"
ARTIFACT_ROOT="$(mktemp -d "${artifact_parent%/}/rust-compact-da-soak.XXXXXX")"
ARTIFACT_ROOT_REAL="$(cd "${ARTIFACT_ROOT}" && pwd -P)"
REPORT_JSON="${ARTIFACT_ROOT}/rust-compact-da-soak-report.json"
COMPACT_LOG="${ARTIFACT_ROOT}/compact-relay.log"
DA_LOG="${ARTIFACT_ROOT}/da-relay.log"
# Export the child-result holders up front (empty) so a fail-closed exit before
# both children complete can still emit the consistent source-bound schema with
# null child fields.
export ARTIFACT_ROOT REPORT_JSON
export COMPACT_REPORT="" DA_REPORT="" COMPACT_CLEANUP="" DA_CLEANUP=""
# Preserve artifacts on any non-zero (fail-closed) exit or KEEP_TMP=1, keep the real
# exit status independent of cleanup, and refuse to delete anything outside the
# artifact parent (realpath prefix guard) — mirror of the Go soak cleanup.
cleanup_artifact_root() {
  local status=$? cleanup_status=0
  if [[ "${status}" == "0" && "${KEEP_TMP}" != "1" ]]; then
    if [[ -z "${ARTIFACT_ROOT_REAL}" || "${ARTIFACT_ROOT_REAL}" == "/" ]]; then
      echo "refusing cleanup without initialized artifact root" >&2; cleanup_status=1
    else
      case "${ARTIFACT_ROOT_REAL}" in
        "${ARTIFACT_PARENT_REAL}"/rust-compact-da-soak.*) rm -rf -- "${ARTIFACT_ROOT_REAL}" || cleanup_status=$? ;;
        *) echo "refusing cleanup outside artifact parent: ${ARTIFACT_ROOT_REAL}" >&2; cleanup_status=1 ;;
      esac
    fi
  fi
  [[ "${status}" != "0" ]] && exit "${status}"
  exit "${cleanup_status}"
}
trap cleanup_artifact_root EXIT

extract_report_path() {
  python3 - "$1" "${ARTIFACT_ROOT}" <<'PY'
import re, sys
from pathlib import Path
log_path, artifact_root = sys.argv[1:3]
root = Path(artifact_root).resolve()
report = None
with open(log_path, encoding="utf-8") as fh:
    for line in fh:
        m = re.search(r"report=(.+?)\s*$", line)
        if m: report = m.group(1)
if report is None: raise SystemExit(f"missing report= marker in {log_path}")
path = Path(report).resolve()
try: path.relative_to(root)
except ValueError: raise SystemExit(f"report path escapes artifact root: {path}") from None
if not path.is_file(): raise SystemExit(f"report path is not a regular file: {path}")
print(path)
PY
}

# Children emit a source-bound PASS report (RUB-441/RUB-443) and exit 0 on PASS;
# capture the report path regardless of exit code so a non-PASS child still
# aggregates into a fail-closed combined verdict. A child that emits no report at
# all is a hard harness failure.
run_child_soak() {
  local label="$1" script="$2" log="$3"
  echo "Running ${label} soak" >&2
  "${ENV_BIN}" KEEP_TMP=1 RUBIN_PROCESS_KEEP_ARTIFACTS=1 RUBIN_PROCESS_ARTIFACT_PARENT="${ARTIFACT_ROOT}" "${script}" >"${log}" 2>&1 || true
  extract_report_path "${log}" || { echo "${label} soak produced no report; log=${log}" >&2; tail -n 80 "${log}" >&2 || true; return 1; }
}

assert_participant_pids_exited() {
  python3 - "$1" "$2" <<'PY'
import json, os, subprocess, sys
label, report_path = sys.argv[1:3]
with open(report_path, encoding="utf-8") as fh: report = json.load(fh)
participants = report.get("participants")
if not isinstance(participants, list) or not participants:
    raise SystemExit(f"{label}: missing participant pid evidence")
checks = []
for p in participants:
    if not isinstance(p, dict): raise SystemExit(f"{label}: invalid participant entry: {p!r}")
    pid = p.get("pid")
    if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
        raise SystemExit(f"{label}: invalid participant pid: {pid!r}")
    binary = p.get("binary")
    if not isinstance(binary, str) or not binary.strip():
        raise SystemExit(f"{label}: invalid participant binary for pid {pid}: {binary!r}")
    checks.append((pid, os.path.basename(os.path.realpath(binary))))
for pid, expected in checks:
    try: os.kill(pid, 0)
    except ProcessLookupError: continue
    except PermissionError: raise SystemExit(f"{label}: participant pid not inspectable: {pid}") from None
    proc = subprocess.run(["ps", "-p", str(pid), "-o", "comm="], check=False, text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    actual = os.path.basename(os.path.realpath(proc.stdout.strip())) if proc.returncode == 0 and proc.stdout.strip() else ""
    if expected and actual and actual != expected: continue
    raise SystemExit(f"{label}: participant pid still alive after child cleanup: {pid}")
print(json.dumps({"label": label, "participant_pids": [pid for pid, _ in checks], "cleanup_verified": True}, sort_keys=True))
PY
}

# Fail-closed combined report for an early exit (child missing report / stale
# pids). Emits the SAME source-bound schema as the aggregated path so downstream
# evidence consumers always see source + artifact_paths + the *_verdict fields;
# unavailable child fields are null.
emit_combined_unavailable() {
  local reason="$1"
  COMBINED_FAIL_REASON="${reason}" python3 - <<'PY'
import json, os
e = os.environ
def opt(key):
    val = e.get(key, "")
    return val or None
def child_verdict(key):
    # Derive the child verdict from its report when the path is available and
    # readable; null only when the child produced no readable report.
    path = e.get(key, "")
    if not path:
        return None
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh).get("verdict")
    except (OSError, json.JSONDecodeError):
        return None
report = {
    "scenario": "rust_compact_da_combined_soak",
    "verdict": "NO_DATA",
    "combined_verdict": "NO_DATA",
    "compact_verdict": child_verdict("COMPACT_REPORT"),
    "da_verdict": child_verdict("DA_REPORT"),
    "failure_reason": e["COMBINED_FAIL_REASON"],
    "source": {
        "repo": e.get("SOURCE_REMOTE"),
        "branch": e.get("SOURCE_BRANCH"),
        "commit_sha": e.get("SOURCE_COMMIT"),
        "script": e.get("SCRIPT_PATH"),
        "artifact_root": e.get("ARTIFACT_ROOT"),
        "node_version": {"compact_binary": None, "da_binary": None, "source_commit": e.get("SOURCE_COMMIT")},
    },
    "artifact_paths": {
        "compact_report": opt("COMPACT_REPORT"),
        "da_report": opt("DA_REPORT"),
        "combined_report": e["REPORT_JSON"],
    },
}
with open(e["REPORT_JSON"], "w", encoding="utf-8") as f:
    json.dump(report, f, indent=2, sort_keys=True); f.write("\n")
PY
  echo "NO_DATA: reason=${reason}; report=${REPORT_JSON}" >&2
  exit 1
}

COMPACT_REPORT="$(run_child_soak compact "${COMPACT_SCRIPT}" "${COMPACT_LOG}")" || emit_combined_unavailable compact_child_no_report
COMPACT_CLEANUP="$(assert_participant_pids_exited compact "${COMPACT_REPORT}")" || emit_combined_unavailable compact_child_stale_pids
DA_REPORT="$(run_child_soak da "${DA_SCRIPT}" "${DA_LOG}")" || emit_combined_unavailable da_child_no_report
DA_CLEANUP="$(assert_participant_pids_exited da "${DA_REPORT}")" || emit_combined_unavailable da_child_stale_pids

export COMPACT_REPORT DA_REPORT COMPACT_CLEANUP DA_CLEANUP
aggregate_and_write
