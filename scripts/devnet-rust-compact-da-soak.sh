#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEV_ENV="${REPO_ROOT}/scripts/dev-env.sh"
COMPACT_SCRIPT="${REPO_ROOT}/scripts/devnet-rust-compact-relay.sh"
DA_SCRIPT="${REPO_ROOT}/scripts/devnet-rust-da-relay.sh"
ENV_BIN="/usr/bin/env"
: "${KEEP_TMP:=1}"
export KEEP_TMP
usage() { echo "usage: $0" >&2; }
while (($#)); do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    *) usage; exit 2 ;;
  esac
done
# Combined Rust compact+DA process soak: orchestrate the merged compact (RUB-408)
# and DA (RUB-409) relay process smokes as children, capture each source-bound child
# report, verify the child node pids exited (anti-stale), and aggregate into a
# fail-closed combined report. Combined PASS requires both children PASS; today both
# fail-close to NO_DATA (compact advertisement + DA signed-tx-generator runtime gaps),
# so the combined verdict is NO_DATA carrying both child reasons. This harness adds no
# runtime/parser/provider/miner behavior — it only reuses already-merged children.

for tool in python3 perl ps; do
  command -v "${tool}" >/dev/null 2>&1 || { echo "${tool} is required for Rust compact+DA soak evidence" >&2; exit 1; }
done
for path in "${DEV_ENV}" "${COMPACT_SCRIPT}" "${DA_SCRIPT}" "${ENV_BIN}"; do
  [[ -x "${path}" ]] || { echo "missing or non-executable: ${path}" >&2; exit 1; }
done

artifact_parent="${RUBIN_PROCESS_ARTIFACT_PARENT:-${TMPDIR:-/tmp}}"
case "${artifact_parent}" in /*) ;; *) echo "unsafe artifact parent: ${artifact_parent:-<empty>}" >&2; exit 1 ;; esac
case "/${artifact_parent}/" in *"/../"*) echo "unsafe artifact parent contains '..': ${artifact_parent}" >&2; exit 1 ;; esac
mkdir -p "${artifact_parent}"
ARTIFACT_ROOT="$(mktemp -d "${artifact_parent%/}/rust-compact-da-soak.XXXXXX")"
REPORT_JSON="${ARTIFACT_ROOT}/rust-compact-da-soak-report.json"
COMPACT_LOG="${ARTIFACT_ROOT}/compact-relay.log"
DA_LOG="${ARTIFACT_ROOT}/da-relay.log"
cleanup() { [[ "${KEEP_TMP}" == "1" ]] || rm -rf -- "${ARTIFACT_ROOT}"; }
trap cleanup EXIT

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

# Rust child smokes fail-close to NO_DATA (exit 1) until their runtime gap closes;
# capture the source-bound report regardless of exit code and let the aggregation
# read the verdict. A child that emits no report at all is a hard harness failure.
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

emit_combined_unavailable() {
  local reason="$1"
  python3 - "${REPORT_JSON}" "${reason}" "${ARTIFACT_ROOT}" <<'PY'
import json, sys
path, reason, root = sys.argv[1:4]
with open(path, "w", encoding="utf-8") as f:
    json.dump({"scenario": "rust_compact_da_combined_soak", "verdict": "NO_DATA", "failure_reason": reason, "artifact_root": root}, f, indent=2, sort_keys=True); f.write("\n")
PY
  echo "NO_DATA: reason=${reason}; report=${REPORT_JSON}" >&2
  exit 1
}

COMPACT_REPORT="$(run_child_soak compact "${COMPACT_SCRIPT}" "${COMPACT_LOG}")" || emit_combined_unavailable compact_child_no_report
COMPACT_CLEANUP="$(assert_participant_pids_exited compact "${COMPACT_REPORT}")" || emit_combined_unavailable compact_child_stale_pids
DA_REPORT="$(run_child_soak da "${DA_SCRIPT}" "${DA_LOG}")" || emit_combined_unavailable da_child_no_report
DA_CLEANUP="$(assert_participant_pids_exited da "${DA_REPORT}")" || emit_combined_unavailable da_child_stale_pids

export REPORT_JSON ARTIFACT_ROOT COMPACT_REPORT DA_REPORT COMPACT_CLEANUP DA_CLEANUP
python3 - <<'PY'
import json, os, sys
def load(path, label):
    with open(path, encoding="utf-8") as fh:
        try: return json.load(fh)
        except json.JSONDecodeError as exc: raise SystemExit(f"malformed {label}: {exc}") from None
compact = load(os.environ["COMPACT_REPORT"], "compact report")
da = load(os.environ["DA_REPORT"], "DA report")
cv, dv = compact.get("verdict"), da.get("verdict")
combined = "PASS" if cv == "PASS" and dv == "PASS" else "NO_DATA"
report = {
    "scenario": "rust_compact_da_combined_soak",
    "verdict": combined,
    "artifact_root": os.environ["ARTIFACT_ROOT"],
    "prerequisites": {
        "compact_smoke": "RUB-408 devnet-rust-compact-relay.sh (Done)",
        "da_smoke": "RUB-409 devnet-rust-da-relay.sh (Done)",
    },
    "compact": {"verdict": cv, "failure_reason": compact.get("failure_reason"), "report": os.environ["COMPACT_REPORT"], "cleanup": json.loads(os.environ["COMPACT_CLEANUP"])},
    "da": {"verdict": dv, "failure_reason": da.get("failure_reason"), "report": os.environ["DA_REPORT"], "cleanup": json.loads(os.environ["DA_CLEANUP"])},
    "source_of_truth_summary": [
        "Compact relay is relay-only; DA txs enter a block only through the complete-set provider group, never as flat candidates.",
        "Combined PASS requires both child smokes PASS; this harness adds no runtime/parser/provider/miner behavior.",
    ],
}
if combined != "PASS":
    report["failure_reason"] = "child_smokes_not_pass"
with open(os.environ["REPORT_JSON"], "w", encoding="utf-8") as f:
    json.dump(report, f, indent=2, sort_keys=True); f.write("\n")
print(f"{combined}: compact={cv} da={dv}; report={os.environ['REPORT_JSON']}", file=sys.stderr)
raise SystemExit(0 if combined == "PASS" else 1)
PY
