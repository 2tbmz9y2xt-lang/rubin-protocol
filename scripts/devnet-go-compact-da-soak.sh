#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEV_ENV="${REPO_ROOT}/scripts/dev-env.sh"
GO_MODULE_ROOT="${REPO_ROOT}/clients/go"
COMPACT_SCRIPT="${REPO_ROOT}/scripts/devnet-go-compact-relay.sh"
DA_SCRIPT="${REPO_ROOT}/scripts/devnet-go-da-relay.sh"
ENV_BIN="/usr/bin/env"
: "${KEEP_TMP:=1}"
export KEEP_TMP

for tool in python3 git perl lsof ps; do
  command -v "${tool}" >/dev/null 2>&1 || { echo "${tool} is required for Go compact+DA soak evidence" >&2; exit 1; }
done

require_file() {
  local label="$1" path="$2"
  [[ -f "${path}" ]] || { echo "missing ${label}: ${path}" >&2; exit 1; }
}

require_executable() {
  local label="$1" path="$2"
  require_file "${label}" "${path}"
  [[ -x "${path}" ]] || { echo "${label} is not executable: ${path}" >&2; exit 1; }
}

resolve_spec_root() {
  local candidate
  if [[ -n "${RUBIN_SPEC_ROOT:-}" ]]; then
    printf '%s\n' "${RUBIN_SPEC_ROOT}"
    return 0
  fi
  for candidate in "${REPO_ROOT}/../rubin-spec-private/spec" "${REPO_ROOT}/../rubin-spec/spec"; do
    if [[ -f "${candidate}/RUBIN_COMPACT_BLOCKS.md" && -f "${candidate}/RUBIN_L1_P2P_AUX.md" ]]; then
      printf '%s\n' "${candidate}"
      return 0
    fi
  done
  echo "RUBIN_SPEC_ROOT is required when no sibling rubin-spec-private/spec or rubin-spec/spec checkout is available" >&2
  return 1
}

require_executable compact-script "${COMPACT_SCRIPT}"
require_executable da-script "${DA_SCRIPT}"
require_executable dev-env "${DEV_ENV}"
require_executable env "${ENV_BIN}"
SPEC_ROOT="$(resolve_spec_root)"
[[ -d "${SPEC_ROOT}" ]] || { echo "missing spec root: ${SPEC_ROOT}" >&2; exit 1; }
SPEC_ROOT="$(cd "${SPEC_ROOT}" && pwd -P)"
require_file compact-spec "${SPEC_ROOT}/RUBIN_COMPACT_BLOCKS.md"
require_file p2p-aux-spec "${SPEC_ROOT}/RUBIN_L1_P2P_AUX.md"

artifact_parent="${RUBIN_PROCESS_ARTIFACT_PARENT:-${TMPDIR:-/tmp}}"
case "${artifact_parent}" in
  /*) ;;
  *) echo "unsafe artifact parent: ${artifact_parent:-<empty>}" >&2; exit 1 ;;
esac
case "/${artifact_parent}/" in
  *"/../"*) echo "unsafe artifact parent contains '..': ${artifact_parent}" >&2; exit 1 ;;
esac
mkdir -p "${artifact_parent}"
ARTIFACT_PARENT_REAL="$(cd "${artifact_parent}" && pwd -P)"
ARTIFACT_ROOT="$(mktemp -d "${artifact_parent%/}/go-compact-da-soak.XXXXXX")"
ARTIFACT_ROOT_REAL="$(cd "${ARTIFACT_ROOT}" && pwd -P)"
REPORT_JSON="${ARTIFACT_ROOT}/go-compact-da-soak-report.json"
COMPACT_LOG="${ARTIFACT_ROOT}/compact-relay.log"
DA_LOG="${ARTIFACT_ROOT}/da-relay.log"
FALLBACK_JSONL="${ARTIFACT_ROOT}/compact-fallback-go-test.jsonl"
FALLBACK_EVIDENCE_JSON="${ARTIFACT_ROOT}/compact-fallback-evidence.json"

cleanup_artifact_root() {
  local status=$? cleanup_status=0
  if [[ "${status}" == "0" && "${KEEP_TMP}" != "1" ]]; then
    if [[ -z "${ARTIFACT_ROOT_REAL}" || "${ARTIFACT_ROOT_REAL}" == "/" ]]; then
      echo "refusing cleanup without initialized artifact root" >&2
      cleanup_status=1
    else
      case "${ARTIFACT_ROOT_REAL}" in
        "${ARTIFACT_PARENT_REAL}"/go-compact-da-soak.*) rm -rf -- "${ARTIFACT_ROOT_REAL}" || cleanup_status=$? ;;
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
import os
import re
import sys
from pathlib import Path

log_path, artifact_root = sys.argv[1:3]
root = Path(artifact_root).resolve()
report = None
with open(log_path, encoding="utf-8") as fh:
    for line in fh:
        match = re.search(r"report=(.+?)\s*$", line)
        if match:
            report = match.group(1)
if report is None:
    raise SystemExit(f"missing report= marker in {log_path}")
path = Path(report).resolve()
try:
    path.relative_to(root)
except ValueError:
    raise SystemExit(f"report path escapes artifact root: {path}") from None
if not path.is_file():
    raise SystemExit(f"report path is not a regular file: {path}")
print(path)
PY
}

run_child_soak() {
  local label="$1" script="$2" log="$3"
  local -a child_cmd=("${ENV_BIN}" KEEP_TMP=1 RUBIN_PROCESS_KEEP_ARTIFACTS=1 RUBIN_PROCESS_ARTIFACT_PARENT="${ARTIFACT_ROOT}" "${script}")
  echo "Running ${label} soak" >&2
  if ! "${child_cmd[@]}" >"${log}" 2>&1; then
    echo "${label} soak failed; log=${log}" >&2
    tail -n 80 "${log}" >&2 || true
    return 1
  fi
  extract_report_path "${log}"
}

assert_participant_pids_exited() {
  python3 - "$1" "$2" <<'PY'
import json
import os
import subprocess
import sys

label, report_path = sys.argv[1:3]
with open(report_path, encoding="utf-8") as fh:
    report = json.load(fh)
participants = report.get("participants")
if not isinstance(participants, list) or not participants:
    raise SystemExit(f"{label}: missing participant pid evidence")
checks = []
for participant in participants:
    if not isinstance(participant, dict):
        raise SystemExit(f"{label}: invalid participant entry: {participant!r}")
    pid = participant.get("pid")
    if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
        raise SystemExit(f"{label}: invalid participant pid: {pid!r}")
    binary = participant.get("binary")
    if not isinstance(binary, str) or not binary.strip():
        raise SystemExit(f"{label}: invalid participant binary for pid {pid}: {binary!r}")
    expected = os.path.basename(os.path.realpath(binary))
    checks.append((pid, expected))
for pid, expected in checks:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        continue
    except PermissionError:
        raise SystemExit(f"{label}: participant pid still exists but is not inspectable: {pid}") from None
    proc = subprocess.run(["ps", "-p", str(pid), "-o", "comm="], check=False, text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    actual = os.path.basename(os.path.realpath(proc.stdout.strip())) if proc.returncode == 0 and proc.stdout.strip() else ""
    if expected and actual and actual != expected:
        continue
    raise SystemExit(f"{label}: participant pid still alive after child cleanup: {pid}")
print(json.dumps({"label": label, "participant_pids": [pid for pid, _ in checks], "cleanup_verified": True}, sort_keys=True))
PY
}

run_fallback_evidence() {
  local test_name="TestCompactFlowHardeningMatrix"
  local -a cmd=(/usr/bin/env RUBIN_OPENSSL_SKIP_FIPS_GUARD=1 "${DEV_ENV}" -- go -C "${GO_MODULE_ROOT}" test ./node/p2p -run "^${test_name}$" -count=1 -json)
  run_fips_preflight_before_captured_dev_env
  "${cmd[@]}" >"${FALLBACK_JSONL}" || {
    echo "compact fallback evidence test failed; jsonl=${FALLBACK_JSONL}" >&2
    return 1
  }
  export FALLBACK_JSONL FALLBACK_EVIDENCE_JSON DEV_ENV GO_MODULE_ROOT
  python3 - "${test_name}" <<'PY'
import json
import os
import sys

test_name = sys.argv[1]
jsonl_path = os.environ["FALLBACK_JSONL"]
test_passed = False
package_passed = False
with open(jsonl_path, encoding="utf-8") as fh:
    for line_no, line in enumerate(fh, 1):
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError as exc:
            raise SystemExit(f"malformed fallback JSONL at line {line_no}: {exc}") from None
        if event.get("Test") == test_name and event.get("Action") == "pass":
            test_passed = True
        if event.get("Package", "").endswith("/clients/go/node/p2p") and event.get("Action") == "pass" and "Test" not in event:
            package_passed = True
if not test_passed or not package_passed:
    raise SystemExit(f"missing fallback evidence PASS test_passed={test_passed} package_passed={package_passed}")
evidence = {
    "full_block_fallback_available": True,
    "evidence_scope": "go_test_wrapper_not_live_devnet",
    "source": {
        "kind": "go_test_wrapper",
        "package": "./node/p2p",
        "test": test_name,
        "jsonl": jsonl_path,
        "argv": [
            "/usr/bin/env",
            "RUBIN_OPENSSL_SKIP_FIPS_GUARD=1",
            os.environ["DEV_ENV"],
            "--",
            "go",
            "-C",
            os.environ["GO_MODULE_ROOT"],
            "test",
            "./node/p2p",
            "-run",
            f"^{test_name}$",
            "-count=1",
            "-json",
        ],
    },
}
with open(os.environ["FALLBACK_EVIDENCE_JSON"], "w", encoding="utf-8") as out:
    json.dump(evidence, out, indent=2, sort_keys=True)
    out.write("\n")
PY
}

run_fips_preflight_before_captured_dev_env() {
  if [[ "${RUBIN_OPENSSL_FIPS_MODE:-off}" != "only" || "${RUBIN_OPENSSL_SKIP_FIPS_GUARD:-0}" == "1" ]]; then
    return 0
  fi
  echo "Running FIPS-only preflight before captured dev-env command streams" >&2
  "${DEV_ENV}" -- "${REPO_ROOT}/scripts/crypto/openssl/fips-preflight.sh" >&2
}

normalize_spec_remote() {
  python3 - "$1" <<'PY'
import re
import sys

remote = sys.argv[1]
patterns = (
    r"^https://github\.com/(?P<slug>2tbmz9y2xt-lang/rubin-spec)(?:\.git)?$",
    r"^git@github\.com:(?P<slug>2tbmz9y2xt-lang/rubin-spec)(?:\.git)?$",
)
for pattern in patterns:
    match = re.fullmatch(pattern, remote)
    if match:
        print(match.group("slug"))
        raise SystemExit(0)
raise SystemExit(f"unexpected spec origin remote: {remote or '<none>'}")
PY
}

assert_spec_files_tracked_clean() {
  local file
  for file in spec/RUBIN_COMPACT_BLOCKS.md spec/RUBIN_L1_P2P_AUX.md; do
    git -C "${SPEC_REPO_ROOT}" ls-files --error-unmatch "${file}" >/dev/null \
      || { echo "spec file is not tracked: ${file}" >&2; exit 1; }
    git -C "${SPEC_REPO_ROOT}" cat-file -e "HEAD:${file}" \
      || { echo "spec file is not present at HEAD: ${file}" >&2; exit 1; }
  done
  git -C "${SPEC_REPO_ROOT}" diff --quiet -- spec/RUBIN_COMPACT_BLOCKS.md spec/RUBIN_L1_P2P_AUX.md \
    || { echo "spec files have unstaged changes" >&2; exit 1; }
  git -C "${SPEC_REPO_ROOT}" diff --cached --quiet -- spec/RUBIN_COMPACT_BLOCKS.md spec/RUBIN_L1_P2P_AUX.md \
    || { echo "spec files have staged changes" >&2; exit 1; }
}

SPEC_REPO_ROOT="$(cd "${SPEC_ROOT}/.." && pwd -P)"
SPEC_COMMIT="$(git -C "${SPEC_REPO_ROOT}" rev-parse HEAD)"
SPEC_REMOTE="$(git -C "${SPEC_REPO_ROOT}" remote get-url origin 2>/dev/null || true)"
SPEC_REPO="$(normalize_spec_remote "${SPEC_REMOTE}")"
assert_spec_files_tracked_clean

COMPACT_REPORT="$(run_child_soak compact "${COMPACT_SCRIPT}" "${COMPACT_LOG}")"
COMPACT_CLEANUP_JSON="$(assert_participant_pids_exited compact "${COMPACT_REPORT}")"
DA_REPORT="$(run_child_soak da "${DA_SCRIPT}" "${DA_LOG}")"
DA_CLEANUP_JSON="$(assert_participant_pids_exited da "${DA_REPORT}")"
run_fallback_evidence

export REPORT_JSON ARTIFACT_ROOT COMPACT_REPORT DA_REPORT FALLBACK_EVIDENCE_JSON COMPACT_CLEANUP_JSON DA_CLEANUP_JSON SPEC_ROOT SPEC_COMMIT SPEC_REMOTE SPEC_REPO COMPACT_LOG DA_LOG FALLBACK_JSONL
python3 - <<'PY'
import json
import os

def load(path, label):
    with open(path, encoding="utf-8") as fh:
        try:
            return json.load(fh)
        except json.JSONDecodeError as exc:
            raise SystemExit(f"malformed {label}: {exc}") from None

compact = load(os.environ["COMPACT_REPORT"], "compact report")
da = load(os.environ["DA_REPORT"], "DA report")
fallback = load(os.environ["FALLBACK_EVIDENCE_JSON"], "fallback evidence")
compact_cleanup = json.loads(os.environ["COMPACT_CLEANUP_JSON"])
da_cleanup = json.loads(os.environ["DA_CLEANUP_JSON"])

if compact.get("verdict") != "PASS":
    raise SystemExit("compact child report is not PASS")
if da.get("verdict") != "PASS":
    raise SystemExit("DA child report is not PASS")
compact_evidence = compact.get("go_test_compact_evidence") or {}
for key, want in (("compact_attempted", True), ("compact_reconstructed", True), ("fallback_used", False)):
    if compact_evidence.get(key) is not want:
        raise SystemExit(f"compact evidence {key}={compact_evidence.get(key)!r}, want {want!r}")
directions = {
    event.get("direction")
    for event in compact.get("sendcmpct", [])
    if event.get("mode") == 0 and event.get("version") == 1
}
if directions != {"a_to_b", "b_to_a"}:
    raise SystemExit(f"missing bidirectional sendcmpct directions: {sorted(directions)}")
da_evidence = da.get("da_relay_evidence") or {}
complete = da_evidence.get("complete_set_mined") or {}
if complete.get("tx_count") != 4:
    raise SystemExit(f"DA complete-set tx_count={complete.get('tx_count')!r}, want 4")
duplicate = da_evidence.get("duplicate_commit_first_seen_no_replacement") or {}
if not duplicate.get("duplicate_txid"):
    raise SystemExit("DA duplicate first-seen evidence missing duplicate_txid")
if fallback.get("full_block_fallback_available") is not True:
    raise SystemExit("compact full-block fallback evidence missing")

report = {
    "scenario": "go_compact_da_combined_soak",
    "verdict": "PASS",
    "source_of_truth_summary": [
        "RUBIN_L1_P2P_AUX defines compact relay wire commands and points relay semantics to RUBIN_COMPACT_BLOCKS.",
        "RUBIN_COMPACT_BLOCKS defines compact relay as relay-only; it must not redefine canonical block validity.",
        "RUBIN_COMPACT_BLOCKS sendcmpct mode 0 is full-block-only, while modes 1 and 2 enable compact receive/push behavior.",
        "RUBIN_COMPACT_BLOCKS DA state C COMPLETE_SET is the only DA set state eligible for candidate-block inclusion.",
        "RUBIN_COMPACT_BLOCKS cache-miss handling preserves getblocktxn first and full-block fallback after reconstruction failure.",
    ],
    "spec": {
        "repo": os.environ["SPEC_REPO"],
        "commit": os.environ["SPEC_COMMIT"],
        "remote": os.environ["SPEC_REMOTE"],
        "root": os.environ["SPEC_ROOT"],
        "files": ["RUBIN_L1_P2P_AUX.md", "RUBIN_COMPACT_BLOCKS.md"],
    },
    "compact": {
        "report": os.environ["COMPACT_REPORT"],
        "log": os.environ["COMPACT_LOG"],
        "sendcmpct_directions": sorted(directions),
        "compact_reconstructed": True,
        "compact_reconstruction_fallback_used": False,
    },
    "da": {
        "report": os.environ["DA_REPORT"],
        "log": os.environ["DA_LOG"],
        "complete_set_mined": complete,
        "duplicate_commit_first_seen_no_replacement": duplicate,
    },
    "fallback": {
        "full_block_fallback_available": True,
        "evidence": fallback,
    },
    "cleanup": {
        "scope": "participant_pids_from_child_reports",
        "compact": compact_cleanup,
        "da": da_cleanup,
    },
    "timeouts": {
        "compact_relay_io_timeout_seconds": os.environ.get("COMPACT_RELAY_IO_TIMEOUT_SECONDS", "5"),
        "go_da_relay_rpc_timeout_seconds": os.environ.get("RUBIN_GO_DA_RELAY_RPC_TIMEOUT_SECONDS", "5"),
    },
    "deterministic_markers": {
        "compact_path_exercised": True,
        "da_path_exercised": True,
        "full_block_fallback_available": True,
        "timeout_paths_bounded_by_child_scripts": True,
        "participant_pid_cleanup_verified": True,
    },
    "out_of_scope": [
        "production_runtime_change",
        "new_p2p_handler_behavior",
        "new_miner_behavior",
        "new_mempool_behavior",
        "rust",
        "mixed_client",
        "parent_RUB_224_closeout",
        "final_devnet_readiness",
    ],
}
with open(os.environ["REPORT_JSON"], "w", encoding="utf-8") as out:
    json.dump(report, out, indent=2, sort_keys=True)
    out.write("\n")
PY

if [[ "${KEEP_TMP}" == "1" ]]; then
  echo "PASS: Go compact+DA combined soak evidence completed; report=${REPORT_JSON}"
else
  echo "PASS: Go compact+DA combined soak evidence completed; report_removed_on_exit=true"
fi
