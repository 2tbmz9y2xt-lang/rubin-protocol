#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SOAK_SCRIPT="${REPO_ROOT}/scripts/devnet-go-compact-da-soak.sh"
SYSTEM_ENV="/usr/bin/env"

command -v python3 >/dev/null 2>&1 || { echo "python3 is required" >&2; exit 1; }
[[ -r "${SOAK_SCRIPT}" ]] || { echo "soak script unreadable: ${SOAK_SCRIPT}" >&2; exit 1; }
[[ -x "${SYSTEM_ENV}" ]] || { echo "system env is not executable: ${SYSTEM_ENV}" >&2; exit 1; }

TMP_PARENT="$(cd -- "${TMPDIR:-/tmp}" && pwd -P)" || { echo "failed to canonicalize TMPDIR=${TMPDIR:-/tmp}" >&2; exit 1; }
TMP_ROOT="$(mktemp -d "${TMP_PARENT%/}/rubin-compact-da-env.XXXXXX")" || { echo "mktemp failed" >&2; exit 1; }
cleanup() {
  rm -rf -- "${TMP_ROOT}"
}
trap cleanup EXIT

FAKE_BIN="${TMP_ROOT}/bin"
mkdir -p "${FAKE_BIN}"
cat >"${FAKE_BIN}/env" <<'SH'
#!/usr/bin/env sh
exit 0
SH
chmod +x "${FAKE_BIN}/env"

PATH="${FAKE_BIN}:${PATH}"
RESOLVED_ENV="$(command -v env)"
[[ "${RESOLVED_ENV}" == "${FAKE_BIN}/env" ]] || { echo "test setup failed: env did not resolve to fake env" >&2; exit 1; }

python3 - "${SOAK_SCRIPT}" "${SYSTEM_ENV}" <<'PY'
import re
import sys
from pathlib import Path

script_path = Path(sys.argv[1])
system_env = sys.argv[2]
text = script_path.read_text(encoding="utf-8")

if f'ENV_BIN="{system_env}"' not in text:
    raise SystemExit(f"missing pinned ENV_BIN={system_env}")

child_cmd_pattern = re.compile(
    r'local -a child_cmd=\("\$\{ENV_BIN\}" KEEP_TMP=1 '
    r'RUBIN_PROCESS_KEEP_ARTIFACTS=1 '
    r'RUBIN_PROCESS_ARTIFACT_PARENT="\$\{ARTIFACT_ROOT\}" '
    r'"\$\{script\}"\)'
)
if not child_cmd_pattern.search(text):
    raise SystemExit("missing child_cmd invocation through pinned ENV_BIN")

for line_no, line in enumerate(text.splitlines(), 1):
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        continue
    if "KEEP_TMP=1" not in line or "RUBIN_PROCESS_KEEP_ARTIFACTS=1" not in line:
        continue
    if re.search(r'(^|[^\w/.-])env\s+KEEP_TMP=1\s+RUBIN_PROCESS_KEEP_ARTIFACTS=1', line):
        raise SystemExit(f"bare env child invocation at line {line_no}: {line}")

if '"${child_cmd[@]}"' not in text:
    raise SystemExit("child command array is not executed")
PY

echo "PASS: compact+DA soak child env resolution is pinned against PATH shadowing"
