#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
HARNESS="${REPO_ROOT}/scripts/devnet-mixed-client-mesh.sh"

command -v python3 >/dev/null 2>&1 || { echo "python3 is required" >&2; exit 1; }
[[ -x "${HARNESS}" ]] || { echo "mixed-client mesh harness missing or non-executable: ${HARNESS}" >&2; exit 1; }

TMP_PARENT="$(cd -- "${TMPDIR:-/tmp}" && pwd -P)" || { echo "test TMPDIR parent is not usable: ${TMPDIR:-/tmp}" >&2; exit 1; }
TMP_ROOT="$(mktemp -d "${TMP_PARENT%/}/rubin-mesh-keygen-material.XXXXXX")"
cleanup() {
  rm -rf -- "${TMP_ROOT}"
}
trap cleanup EXIT

HELPER_LIB="${TMP_ROOT}/keygen-material-lib.sh"
python3 - "${HARNESS}" "${HELPER_LIB}" <<'PY'
from pathlib import Path
import sys

src, dst = map(Path, sys.argv[1:3])
lines = src.read_text(encoding="utf-8").splitlines()
start = next(i for i, line in enumerate(lines) if line.startswith("keygen_material_reason()"))
end = next(i for i, line in enumerate(lines[start:], start) if line.startswith("prepare_tx_chainstate()"))
dst.write_text("\n".join(lines[start:end]) + "\n", encoding="utf-8")
PY
# shellcheck source=/dev/null
source "${HELPER_LIB}"

addr_a="01$(printf '%*s' 64 '' | tr ' ' 'a')"
addr_b="01$(printf '%*s' 64 '' | tr ' ' 'b')"
addr_bad_suite="02$(printf '%*s' 64 '' | tr ' ' 'c')"
addr_a_upper="$(printf '%s' "${addr_a}" | tr '[:lower:]' '[:upper:]')"
TX_FROM_KEY_DIR="${TMP_ROOT}/secret"
mkdir "${TX_FROM_KEY_DIR}"
chmod 700 "${TX_FROM_KEY_DIR}"
key_file="${TX_FROM_KEY_DIR}/from-key.hex"
printf 'abcd\n' >"${key_file}"
chmod 600 "${key_file}"
expected_key_file="$(python3 -c 'from pathlib import Path; import sys; print(Path(sys.argv[1]).resolve())' "${key_file}")"

material_json() {
  python3 - "$1" "$2" "$3" "$4" <<'PY'
import json
import sys

private_key_file, from_addr, to_addr, mine_addr = sys.argv[1:5]
print(json.dumps({
    "from_address_hex": from_addr,
    "mine_address_hex": mine_addr,
    "private_key_file": private_key_file,
    "to_address_hex": to_addr,
}))
PY
}

expect_reason() {
  local label="$1" expected="$2" raw="$3" output rc reason
  set +e
  output="$(parse_keygen_material "${raw}" 2>&1)"
  rc=$?
  set -e
  if (( rc == 0 )); then
    echo "FAIL: ${label} should fail" >&2
    printf '%s\n' "${output}" >&2
    exit 1
  fi
  reason="$(keygen_material_reason "${rc}")"
  if [[ "${reason}" != "${expected}" ]]; then
    echo "FAIL: ${label} reason=${reason}, want ${expected}" >&2
    exit 1
  fi
  [[ ! -e "${TX_FROM_KEY_DIR}/keygen-public.json" ]] || { echo "FAIL: ${label} left raw keygen material temp file" >&2; exit 1; }
}

good_json="$(material_json "${key_file}" "${addr_a}" "${addr_b}" "${addr_a}")"
good_output="$(parse_keygen_material "${good_json}")" || { echo "FAIL: valid keygen material rejected" >&2; exit 1; }
[[ "$(printf '%s\n' "${good_output}" | sed -n '$=')" == "3" ]] || { echo "FAIL: valid keygen material did not emit 3 fields" >&2; exit 1; }
[[ "$(printf '%s\n' "${good_output}" | sed -n '1p')" == "${expected_key_file}" ]] || { echo "FAIL: private key file output mismatch" >&2; exit 1; }
[[ "$(printf '%s\n' "${good_output}" | sed -n '2p')" == "${addr_b}" ]] || { echo "FAIL: to address output mismatch" >&2; exit 1; }
[[ "$(printf '%s\n' "${good_output}" | sed -n '3p')" == "${addr_a}" ]] || { echo "FAIL: mine address output mismatch" >&2; exit 1; }

mkdir "${TMP_ROOT}/relative tmp"
canonical_relative_tmp="$(cd "${TMP_ROOT}" && tx_secret_tmp_parent "relative tmp")" || { echo "FAIL: relative TMPDIR parent rejected" >&2; exit 1; }
[[ "${canonical_relative_tmp}" == "$(cd "${TMP_ROOT}/relative tmp" && pwd -P)" && "${canonical_relative_tmp}" == /* ]] || { echo "FAIL: relative TMPDIR parent was not canonicalized" >&2; exit 1; }
relative_secret="$(cd "${TMP_ROOT}" && make_tx_secret_dir "relative tmp")" || { echo "FAIL: relative TMPDIR secret dir creation failed" >&2; exit 1; }
case "${relative_secret}" in
  "${canonical_relative_tmp}"/rubin-txgen-from-key.*) ;;
  *) echo "FAIL: relative TMPDIR secret dir was not created under canonical parent: ${relative_secret}" >&2; exit 1 ;;
esac
relative_key_file="${relative_secret}/from-key.hex"
printf 'abcd\n' >"${relative_key_file}"
chmod 600 "${relative_key_file}"
TX_FROM_KEY_DIR="${relative_secret}"
relative_good_json="$(material_json "${relative_key_file}" "${addr_a}" "${addr_b}" "${addr_a}")"
relative_good_output="$(parse_keygen_material "${relative_good_json}")" || { echo "FAIL: canonicalized relative TMPDIR keygen material rejected" >&2; exit 1; }
[[ "$(printf '%s\n' "${relative_good_output}" | sed -n '1p')" == "${relative_key_file}" ]] || { echo "FAIL: relative TMPDIR private key output mismatch" >&2; exit 1; }
TX_FROM_KEY_DIR="${TMP_ROOT}/secret"

expect_reason "malformed json" go_submit_keygen_material_malformed_json "{"
expect_reason "wrong root" go_submit_keygen_material_root_invalid "[]"
expect_reason "extra key" go_submit_keygen_material_keys_mismatch "$(python3 - "${key_file}" "${addr_a}" "${addr_b}" <<'PY'
import json
import sys
print(json.dumps({"private_key_file": sys.argv[1], "from_address_hex": sys.argv[2], "to_address_hex": sys.argv[3], "mine_address_hex": sys.argv[2], "private_key_hex": "secret"}))
PY
)"
expect_reason "outside key path" go_submit_keygen_private_path_mismatch "$(material_json "${TMP_ROOT}/outside.hex" "${addr_a}" "${addr_b}" "${addr_a}")"
chmod 644 "${key_file}"
expect_reason "loose key mode" go_submit_keygen_private_file_mode_invalid "${good_json}"
chmod 200 "${key_file}"
expect_reason "unreadable key mode" go_submit_keygen_private_file_mode_invalid "${good_json}"
chmod 600 "${key_file}"
expect_reason "bad address" go_submit_keygen_address_malformed "$(material_json "${key_file}" "${addr_a_upper}" "${addr_b}" "${addr_a}")"
expect_reason "bad suite" go_submit_keygen_address_malformed "$(material_json "${key_file}" "${addr_bad_suite}" "${addr_b}" "${addr_bad_suite}")"
expect_reason "from mine mismatch" go_submit_keygen_from_mine_mismatch "$(material_json "${key_file}" "${addr_a}" "${addr_b}" "${addr_b}")"
expect_reason "to matches from" go_submit_keygen_to_matches_from "$(material_json "${key_file}" "${addr_a}" "${addr_a}" "${addr_a}")"

printf 'PASS: mixed-client mesh keygen material guard is covered\n'
