#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'
HARNESS="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/scripts/devnet-rust-compact-relay.sh"
TMP_PARENT="$(cd -- "${TMPDIR:-/tmp}" && pwd -P)"
TMP_ROOT="$(mktemp -d "${TMP_PARENT}/rubin-rust-compact-deps.XXXXXX")"
trap 'rm -rf -- "${TMP_ROOT}"' EXIT
FAKE_BIN="${TMP_ROOT}/bin"
mkdir -p "${FAKE_BIN}" && cat >"${FAKE_BIN}/gh" <<'SH'
#!/usr/bin/env sh
case "${RUBIN_FAKE_GH_MODE:-not_done}" in
  malformed) printf 'true\n' ;;
  *) printf 'false\tfalse\n' ;;
esac
SH
chmod +x "${FAKE_BIN}/gh"
LEAK_PATH="${TMP_ROOT}/must-not-exist.json"
if output="$(REPORT_JSON="${LEAK_PATH}" RUBIN_PROCESS_ARTIFACT_ROOT="${TMP_ROOT}/bad" PATH="${FAKE_BIN}:${PATH}" "${HARNESS}" --dependency-preflight-only 2>&1)"; then
  echo "FAIL: dependency preflight should fail closed" >&2; echo "${output}" >&2; exit 1
fi
[[ ! -e "${LEAK_PATH}" ]] || { echo "FAIL: dependency preflight wrote inherited REPORT_JSON" >&2; exit 1; }
[[ "${output}" == *"NO_DATA: reason=dependency_1855_not_done"* ]] || {
  echo "FAIL: dependency preflight produced unexpected output" >&2; echo "${output}" >&2; exit 1
}
if output="$(RUBIN_FAKE_GH_MODE=malformed PATH="${FAKE_BIN}:${PATH}" "${HARNESS}" --dependency-preflight-only 2>&1)"; then
  echo "FAIL: malformed gh output should fail closed" >&2; echo "${output}" >&2; exit 1
fi
[[ "${output}" == *"NO_DATA: reason=dependency_1855_gh_output_malformed"* ]] || {
  echo "FAIL: malformed gh output produced unexpected output" >&2; echo "${output}" >&2; exit 1
}
echo "PASS: Rust compact relay dependency preflight fails closed with NO_DATA"
