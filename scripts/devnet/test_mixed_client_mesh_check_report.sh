#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
HARNESS="${REPO_ROOT}/scripts/devnet-mixed-client-mesh.sh"
DEV_ENV="${REPO_ROOT}/scripts/dev-env.sh"
VALIDATOR="${REPO_ROOT}/scripts/devnet/validate_mixed_client_evidence.py"
GENERATOR="${REPO_ROOT}/scripts/devnet/generate_mixed_client_devnet_soak_report.py"
GO_MODULE_ROOT="${REPO_ROOT}/clients/go"
MESH_TIMEOUT=2
export GO_MODULE_ROOT
export MESH_TIMEOUT

command -v python3 >/dev/null 2>&1 || { echo "python3 is required" >&2; exit 1; }
[[ -x "${HARNESS}" ]] || { echo "mixed-client mesh harness missing or non-executable: ${HARNESS}" >&2; exit 1; }
[[ -x "${DEV_ENV}" ]] || { echo "dev-env wrapper missing or non-executable: ${DEV_ENV}" >&2; exit 1; }
[[ -r "${VALIDATOR}" ]] || { echo "validator unreadable: ${VALIDATOR}" >&2; exit 1; }
[[ -r "${GENERATOR}" ]] || { echo "generator unreadable: ${GENERATOR}" >&2; exit 1; }

TMP_PARENT="$(cd -- "${TMPDIR:-/tmp}" && pwd -P)" || { echo "test TMPDIR parent is not usable: ${TMPDIR:-/tmp}" >&2; exit 1; }
TMP_ROOT="$(mktemp -d "${TMP_PARENT%/}/rubin-mesh-check-report.XXXXXX")"
cleanup() {
  rm -rf -- "${TMP_ROOT}"
}
trap cleanup EXIT

require_contains() {
  local output="$1" needle="$2" label="$3"
  if [[ "${output}" != *"${needle}"* ]]; then
    echo "FAIL: ${label} missing expected text: ${needle}" >&2
    echo "actual output:" >&2
    printf '%s\n' "${output}" >&2
    exit 1
  fi
}

expect_pass_contains() {
  local label="$1" needle="$2" output
  shift 2
  if ! output="$("$@" 2>&1)"; then
    echo "FAIL: ${label} should pass" >&2
    echo "actual output:" >&2
    printf '%s\n' "${output}" >&2
    exit 1
  fi
  require_contains "${output}" "${needle}" "${label}"
}

expect_fail_contains() {
  local label="$1" needle="$2" output
  shift 2
  if output="$("$@" 2>&1)"; then
    echo "FAIL: ${label} should fail" >&2
    echo "actual output:" >&2
    printf '%s\n' "${output}" >&2
    exit 1
  fi
  require_contains "${output}" "${needle}" "${label}"
}

expect_fail_token() {
  local label="$1" expected_token="$2" output token
  shift 2
  if output="$("$@" 2>&1)"; then
    echo "FAIL: ${label} should fail" >&2
    echo "actual output:" >&2
    printf '%s\n' "${output}" >&2
    exit 1
  fi
  token="$(printf '%s\n' "${output}" | tx_report_reason_token)"
  if [[ "${token}" != "${expected_token}" ]]; then
    echo "FAIL: ${label} produced token ${token}, want ${expected_token}" >&2
    echo "actual output:" >&2
    printf '%s\n' "${output}" >&2
    exit 1
  fi
}

expect_fail_check_token() {
  local label="$1" expected_token="$2" output token
  shift 2
  if output="$("$@" 2>&1)"; then
    echo "FAIL: ${label} should fail" >&2
    echo "actual output:" >&2
    printf '%s\n' "${output}" >&2
    exit 1
  fi
  token="$(printf '%s\n' "${output}" | check_report_reason_token)"
  if [[ "${token}" != "${expected_token}" ]]; then
    echo "FAIL: ${label} produced token ${token}, want ${expected_token}" >&2
    echo "actual output:" >&2
    printf '%s\n' "${output}" >&2
    exit 1
  fi
}

expect_generator_fail_contains() {
  local label="$1" needle="$2" output_path output
  shift 2
  output_path="${TMP_ROOT}/generator-negative.json"
  if output="$(python3 "${GENERATOR}" "$@" --output "${output_path}" 2>&1)"; then
    echo "FAIL: ${label} should fail" >&2
    echo "actual output:" >&2
    printf '%s\n' "${output}" >&2
    exit 1
  fi
  require_contains "${output}" "${needle}" "${label}"
}

extract_check_report() {
  python3 - "${HARNESS}" "${CHECK_REPORT_LIB}" <<'PY'
from pathlib import Path
import sys

src, dst = map(Path, sys.argv[1:3])
lines = src.read_text(encoding="utf-8").splitlines()
start = next(i for i, line in enumerate(lines) if line.startswith("check_report()"))
end = next(i for i, line in enumerate(lines[start:], start) if line.startswith('[[ "${MESH_TIMEOUT}"'))
token_start = next(i for i, line in enumerate(lines) if line.startswith("check_report_reason_token()"))
token_end = next(i for i, line in enumerate(lines[token_start:], token_start) if line.startswith("rpc_json()"))
capture_start = next(i for i, line in enumerate(lines) if line.startswith("rpc_json()"))
capture_end = next(i for i, line in enumerate(lines[capture_start:], capture_start) if line.startswith("pid_comm()"))
tx_capture_start = next(i for i, line in enumerate(lines) if line.startswith("tx_capture_reason()"))
tx_capture_end = next(i for i, line in enumerate(lines[tx_capture_start:], tx_capture_start) if line.startswith("tx_sidecar_reason()"))
tx_prepare_reason_start = next(i for i, line in enumerate(lines) if line.startswith("rust_restart_prepare_reason()"))
tx_prepare_reason_end = next(i for i, line in enumerate(lines[tx_prepare_reason_start:], tx_prepare_reason_start) if line.startswith("parse_txid()"))
block_reason_start = next(i for i, line in enumerate(lines) if line.startswith("block_inclusion_failure_reason()"))
block_reason_end = next(i for i, line in enumerate(lines[block_reason_start:], block_reason_start) if line.startswith("verify_block_inclusion()"))
mine_reason_start = next(i for i, line in enumerate(lines) if line.startswith("mine_next_http_error_reason()"))
mine_reason_end = next(i for i, line in enumerate(lines[mine_reason_start:], mine_reason_start) if line.startswith("rust_mine_including_tx()"))
rust_mine_start = next(i for i, line in enumerate(lines) if line.startswith("rust_mine_including_tx()"))
rust_mine_end = next(i for i, line in enumerate(lines[rust_mine_start:], rust_mine_start) if line.startswith("tip_matches()"))
Path(dst).write_text("\n".join(lines[start:end] + [""] + lines[token_start:token_end] + [""] + lines[capture_start:capture_end] + [""] + lines[tx_capture_start:tx_capture_end] + [""] + lines[tx_prepare_reason_start:tx_prepare_reason_end] + [""] + lines[block_reason_start:block_reason_end] + [""] + lines[mine_reason_start:mine_reason_end] + [""] + lines[rust_mine_start:rust_mine_end]) + "\n", encoding="utf-8")
PY
}

extract_prepare_tx_chainstate() {
  python3 - "${HARNESS}" "${PREPARE_TX_CHAINSTATE_LIB}" <<'PY'
from pathlib import Path
import sys

src, dst = map(Path, sys.argv[1:3])
lines = src.read_text(encoding="utf-8").splitlines()
start = next(i for i, line in enumerate(lines) if line.startswith("prepare_tx_chainstate()"))
end = next(i for i, line in enumerate(lines[start:], start) if line.startswith("parse_txid()"))
Path(dst).write_text("\n".join(lines[start:end]) + "\n", encoding="utf-8")
PY
}

extract_slices() {
  python3 - "${HARNESS}" "$@" <<'PY'
from pathlib import Path
import sys

lines = Path(sys.argv[1]).read_text(encoding="utf-8").splitlines()
dst, out = Path(sys.argv[2]), []
for first, stop in zip(sys.argv[3::2], sys.argv[4::2]):
    start = next(i for i, line in enumerate(lines) if line.startswith(first))
    end = next(i for i, line in enumerate(lines[start:], start) if line.startswith(stop))
    out += lines[start:end] + [""]
dst.write_text("\n".join(out) + "\n", encoding="utf-8")
PY
}

check_prepare_tx_chainstate_leaves_rust_empty() {
  local probe="${TMP_ROOT}/prepare-tx-chainstate-empty.sh" probe_root="${TMP_ROOT}/prepare-tx-chainstate-empty"
  mkdir -p -- "${probe_root}"
  cat >"${probe}" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
source "$1"
probe_root="$2"
KEYGEN_JSON="${probe_root}/keygen.json"; KEYGEN_GO="${probe_root}/keygen.go"; GO_MODULE_ROOT="${probe_root}/go"; DEV_ENV="${probe_root}/dev-env.sh"
GO_NODE_BIN="${probe_root}/rubin-node"; GO_DIR="${probe_root}/go-node"; RUST_DIR="${probe_root}/rust-node"; MINE_LOG="${probe_root}/mine-go.log"; TMPDIR="${probe_root}/tmp"
TX_REASON=""; TX_FROM_KEY_DIR=""; TX_FROM_KEY_FILE=""; TX_TO_KEY=""; GO_STORE_READY=0; RUST_STORE_READY=0
mkdir -p -- "${TMPDIR}" "${GO_MODULE_ROOT}" "${GO_DIR}" "${RUST_DIR}"
build_go_txgen() { :; }
write_keygen() { :; }
disable_xtrace_for_secret() { return 1; }
restore_xtrace_after_secret() { :; }
make_tx_secret_dir() { mkdir -p -- "${probe_root}/secret"; printf '%s\n' "${probe_root}/secret"; }
cleanup_tx_from_key_file() { :; }
_rubin_process_resolve_log() { printf '%s\n' "$1"; }
bounded_mesh() {
  local arg
  for arg; do [[ "${arg}" == --mine-blocks ]] && { printf 'store\n' >"${GO_DIR}/chainstate"; printf 'mined\n'; return 0; }; done
  printf '{}\n'
}
parse_keygen_material() { printf '%s\n%s\n%s\n' "${probe_root}/secret/from-key.hex" "01$(printf 'b%.0s' {1..64})" "01$(printf 'a%.0s' {1..64})"; }
prepare_tx_chainstate || { echo "FAIL: prepare_tx_chainstate failed: ${TX_REASON}" >&2; exit 1; }
[[ "${GO_STORE_READY}" == 1 && "${RUST_STORE_READY}" == 0 ]] || { echo "FAIL: store flags go=${GO_STORE_READY} rust=${RUST_STORE_READY}" >&2; exit 1; }
[[ -f "${GO_DIR}/chainstate" ]] || { echo "FAIL: Go store was not created by the mining run" >&2; exit 1; }
find -H "${RUST_DIR}" -mindepth 1 -maxdepth 1 -exec false {} + || { echo "FAIL: Rust datadir is not empty after prepare_tx_chainstate" >&2; exit 1; }
SH
  bash "${probe}" "${PREPARE_TX_CHAINSTATE_LIB}" "${probe_root}"
}

check_rust_datadir_guard() {
  local probe="${TMP_ROOT}/rust-datadir-guard.sh" probe_root="${TMP_ROOT}/rust-datadir-guard" lib="${TMP_ROOT}/rust-datadir-guard-lib.sh"
  mkdir -p -- "${probe_root}"
  extract_slices "${lib}" "require_rust_datadir_exact_empty()" "start_rust_node()"
  cat >"${probe}" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
source "$1"
probe_root="$2"
RUST_NODE_BIN="${probe_root}/rubin-node-rust"; GO_P2P_ADDR="127.0.0.1:51002"; SPAWNED="${probe_root}/spawned-argv"
argv_cmd() { :; }
argv_json() { :; }
rubin_process_start() { shift; printf '%s\n' "$@" >"${SPAWNED}"; return 1; }
expect_refused() {
  RUST_DIR="$1"; RUST_STORE_READY=0; RUST_EXACT_EMPTY_BEFORE_FIRST_START=false; rm -f -- "${SPAWNED}"
  if start_rust_node_with_log node-rust.log; then echo "FAIL: start accepted ${RUST_DIR}" >&2; exit 1; fi
  [[ "${START_REASON}" == rust_datadir_not_exact_empty ]] || { echo "FAIL: start reason ${START_REASON} for ${RUST_DIR}" >&2; exit 1; }
  [[ ! -e "${SPAWNED}" && "${RUST_STORE_READY}" == 0 ]] || { echo "FAIL: Rust process spawned on ${RUST_DIR}" >&2; exit 1; }
  [[ "${RUST_EXACT_EMPTY_BEFORE_FIRST_START}" == false ]] || { echo "FAIL: refused start set rust_exact_empty_before_first_start ${RUST_EXACT_EMPTY_BEFORE_FIRST_START} for ${RUST_DIR}" >&2; exit 1; }
}
mkdir -p -- "${probe_root}/file" "${probe_root}/dot" "${probe_root}/newline" "${probe_root}/empty"
printf 'x\n' >"${probe_root}/file/CURRENT"; printf 'x\n' >"${probe_root}/dot/.lock"; printf 'x\n' >"${probe_root}/newline/"$'\n'
ln -s -- "${probe_root}/file" "${probe_root}/link-to-file-dir"; printf 'x\n' >"${probe_root}/regular"
expect_refused "${probe_root}/file"
expect_refused "${probe_root}/dot"
expect_refused "${probe_root}/newline"
expect_refused "${probe_root}/link-to-file-dir"
expect_refused "${probe_root}/regular"
expect_refused "${probe_root}/missing"
RUST_DIR="${probe_root}/empty"; RUST_STORE_READY=0; RUST_EXACT_EMPTY_BEFORE_FIRST_START=false; rm -f -- "${SPAWNED}"
if start_rust_node_with_log node-rust.log; then echo "FAIL: stub launch should fail" >&2; exit 1; fi
[[ "${START_REASON}" == rust_launch_failed && "${RUST_STORE_READY}" == 1 ]] || { echo "FAIL: empty datadir start reason ${START_REASON}" >&2; exit 1; }
[[ "${RUST_EXACT_EMPTY_BEFORE_FIRST_START}" == true ]] || { echo "FAIL: empty datadir start set rust_exact_empty_before_first_start ${RUST_EXACT_EMPTY_BEFORE_FIRST_START}" >&2; exit 1; }
[[ "$(tail -n 1 "${SPAWNED}")" == --create-store ]] || { echo "FAIL: first Rust start lacks --create-store" >&2; exit 1; }
printf 'x\n' >"${probe_root}/empty/CURRENT"; rm -f -- "${SPAWNED}"
if start_rust_node_with_log node-rust-restart.log; then echo "FAIL: stub relaunch should fail" >&2; exit 1; fi
[[ "${START_REASON}" == rust_launch_failed && "${RUST_EXACT_EMPTY_BEFORE_FIRST_START}" == true ]] || { echo "FAIL: reopen start reason ${START_REASON}, rust_exact_empty_before_first_start ${RUST_EXACT_EMPTY_BEFORE_FIRST_START}" >&2; exit 1; }
! grep -Fxq -- --create-store "${SPAWNED}" || { echo "FAIL: Rust reopen carries --create-store" >&2; exit 1; }
SH
  bash "${probe}" "${lib}" "${probe_root}"
}

check_txgen_datadir_guard() {
  local probe="${TMP_ROOT}/txgen-datadir-guard.sh" probe_root="${TMP_ROOT}/txgen-datadir-guard" lib="${TMP_ROOT}/txgen-datadir-guard-lib.sh"
  mkdir -p -- "${probe_root}/go-node" "${probe_root}/rust-node"
  ln -s -- "${probe_root}/rust-node" "${probe_root}/rust-alias"
  extract_slices "${lib}" "txgen_datadir_guard()" "wait_rust_accept()"
  cat >"${probe}" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
source "$1"
probe_root="$2"
GO_DIR="${probe_root}/go-node"; RUST_DIR="${probe_root}/rust-node"; GO_RPC_ADDR="127.0.0.1:51001"; RUST_RPC_ADDR="127.0.0.1:51003"
TXGEN_BIN="${probe_root}/rubin-txgen"; SPAWNED="${probe_root}/txgen-argv"; DETERMINISTIC_TX_FEE=1; TX_TO_KEY=to
TX_FROM_KEY_FILE="${probe_root}/from-key.hex"; printf 'k\n' >"${TX_FROM_KEY_FILE}"
printf '#!/bin/sh\nprintf "%%s\\n" "$@" >"%s"\nexit 1\n' "${SPAWNED}" >"${TXGEN_BIN}"; chmod +x "${TXGEN_BIN}"
bounded_mesh() { "$@"; }
cleanup_tx_from_key_file() { :; }
TX_REASON=""
if submit_rust_tx; then echo "FAIL: stub txgen should fail" >&2; exit 1; fi
[[ "${TX_REASON}" == rust_submit_txgen_failed ]] || { echo "FAIL: submit_rust_tx reason ${TX_REASON}" >&2; exit 1; }
python3 - "${SPAWNED}" "${GO_DIR}" "${RUST_RPC_ADDR}" <<'PY'
import sys
argv = open(sys.argv[1], encoding="utf-8").read().splitlines()
if argv[argv.index("--datadir") + 1] != sys.argv[2] or argv[argv.index("--submit-to") + 1] != sys.argv[3]:
    sys.exit(f"submit_rust_tx txgen argv {argv}")
PY
expect_guard_refused() {
  TX_REASON=""
  if txgen_datadir_guard "${TXGEN_BIN}" "$@" --submit-to "${GO_RPC_ADDR}"; then echo "FAIL: guard accepted $*" >&2; exit 1; fi
  [[ "${TX_REASON}" == cross_client_datadir_argv ]] || { echo "FAIL: guard reason ${TX_REASON} for $*" >&2; exit 1; }
}
expect_guard_refused --datadir "${RUST_DIR}"
expect_guard_refused --datadir "${probe_root}/rust-alias"
expect_guard_refused --datadir "${probe_root}/missing"
expect_guard_refused --datadir ""
expect_guard_refused
TX_REASON=""; txgen_datadir_guard "${TXGEN_BIN}" --datadir "${GO_DIR}" || { echo "FAIL: guard refused the Go datadir" >&2; exit 1; }
GO_DIR="${probe_root}/rust-alias"; rm -f -- "${SPAWNED}"; TX_REASON=""
if submit_go_tx; then echo "FAIL: submit_go_tx accepted the Rust datadir" >&2; exit 1; fi
[[ "${TX_REASON}" == cross_client_datadir_argv && ! -e "${SPAWNED}" ]] || { echo "FAIL: submit_go_tx reason ${TX_REASON} or txgen spawned" >&2; exit 1; }
rm -f -- "${SPAWNED}"; TX_REASON=""
if submit_rust_tx; then echo "FAIL: submit_rust_tx accepted the Rust datadir" >&2; exit 1; fi
[[ "${TX_REASON}" == cross_client_datadir_argv && ! -e "${SPAWNED}" ]] || { echo "FAIL: submit_rust_tx reason ${TX_REASON} or txgen spawned" >&2; exit 1; }
SH
  bash "${probe}" "${lib}" "${probe_root}"
}

check_initial_convergence_wait() {
  local probe="${TMP_ROOT}/initial-convergence.sh" probe_root="${TMP_ROOT}/initial-convergence" lib="${TMP_ROOT}/initial-convergence-lib.sh"
  mkdir -p -- "${probe_root}"
  extract_slices "${lib}" "tx_capture_reason()" "tx_sidecar_reason()" "tip_matches()" "wait_go_converge_to_rust_mined_block()" "parse_restart_tip_sidecar()" "rust_restart_start_reason()" "partition_capture_tip()" "capture_go_reorg_metrics()"
  cat >"${probe}" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
source "$1"
probe_root="$2"
MESH_TIMEOUT=2; GO_RPC_ADDR="127.0.0.1:51001"; RUST_RPC_ADDR="127.0.0.1:51003"; TX_PATH_MODE=0; RUST_RESTART_MODE=0; PARTITION_HEAL_REORG_MODE=0
INITIAL_GO_TIP_JSON="${probe_root}/go-tip.json"; INITIAL_RUST_TIP_JSON="${probe_root}/rust-tip.json"
RUST_CAPTURE_FAILS=0
capture_rpc_sidecar() {
  printf '%s\n' "$4" >>"${probe_root}/captures-$1"
  [[ "$1" == go ]] && { cp -- "${GO_TIP_INPUT}" "$5"; return; }
  (( $(wc -l <"${probe_root}/captures-rust") > RUST_CAPTURE_FAILS )) || return 1
  cp -- "${RUST_TIP_INPUT}" "$5"
}
tip() { printf '{"best_known_height":%s,"has_tip":%s,"height":%s,"in_ibd":false,"tip_hash":%s}\n' "$2" "$3" "$2" "$4" >"${probe_root}/$1.json"; printf '%s\n' "${probe_root}/$1.json"; }
aa="\"$(printf 'a%.0s' {1..64})\""; bb="\"$(printf 'b%.0s' {1..64})\""
go101="$(tip go101 101 true "${aa}")"; rust101="$(tip rust101 101 true "${aa}")"; rust100="$(tip rust100 100 true "${bb}")"; rust101b="$(tip rust101b 101 true "${bb}")"
absent="$(tip absent null false null)"; rust_zero="$(tip rustzero 0 true "${aa}")"
printf '{"has_tip":false,"tip_hash":null}\n' >"${probe_root}/absent-no-height.json"
expect_match() {
  GO_TIP_INPUT="$1"; RUST_TIP_INPUT="$2"; rm -f -- "${INITIAL_GO_TIP_JSON}" "${INITIAL_RUST_TIP_JSON}"
  wait_initial_convergence || { echo "FAIL: initial convergence rejected $1 $2: ${PARTITION_REASON}" >&2; exit 1; }
  cmp -s -- "$1" "${INITIAL_GO_TIP_JSON}" || { echo "FAIL: initial Go tip capture is not the accepted answer" >&2; exit 1; }
  cmp -s -- "$2" "${INITIAL_RUST_TIP_JSON}" || { echo "FAIL: initial Rust tip capture is not the accepted answer" >&2; exit 1; }
}
expect_reason() {
  GO_TIP_INPUT="$2"; RUST_TIP_INPUT="$3"
  if wait_initial_convergence; then echo "FAIL: initial convergence accepted $2 $3" >&2; exit 1; fi
  [[ "${PARTITION_REASON}" == "$1" ]] || { echo "FAIL: initial convergence reason ${PARTITION_REASON}, want $1" >&2; exit 1; }
}
TX_PATH_MODE=3
expect_match "${go101}" "${rust101}"
MESH_TIMEOUT=1 expect_reason initial_convergence_timeout "${go101}" "${rust100}"
expect_reason initial_convergence_timeout "${go101}" "${rust101b}"
expect_reason initial_convergence_go_tip_tip_absent "${absent}" "${absent}"
rm -f -- "${probe_root}/captures-go" "${probe_root}/captures-rust"; RUST_CAPTURE_FAILS=1
MESH_TIMEOUT=3 expect_match "${go101}" "${rust101}"
[[ "$(wc -l <"${probe_root}/captures-go")" -eq 1 && "$(wc -l <"${probe_root}/captures-rust")" -eq 2 ]] || { echo "FAIL: Go tip captures $(wc -l <"${probe_root}/captures-go"), Rust tip captures $(wc -l <"${probe_root}/captures-rust"), want 1 and 2" >&2; exit 1; }
RUST_CAPTURE_FAILS=1000
expect_reason initial_convergence_timeout "${go101}" "${rust101}"
RUST_CAPTURE_FAILS=0
TX_PATH_MODE=0
expect_match "${absent}" "${absent}"
expect_reason initial_convergence_timeout "${absent}" "${rust_zero}"
expect_reason initial_convergence_timeout "${go101}" "${absent}"
expect_reason initial_convergence_timeout "${absent}" "${probe_root}/absent-no-height.json"
SH
  bash "${probe}" "${lib}" "${probe_root}"
}

check_store_neutrality_producer_reasons() {
  local probe="${TMP_ROOT}/sn-producer.sh" probe_root="${TMP_ROOT}/sn-producer" lib="${TMP_ROOT}/sn-producer-lib.sh" main="${TMP_ROOT}/sn-producer-main.sh"
  mkdir -p -- "${probe_root}/cap" "${probe_root}/out"
  extract_slices "${lib}" "sidecar_derivations_py()" '[[ "${MESH_TIMEOUT}"' "chain_mode()" "capture_go_reorg_metrics()"
  extract_slices "${main}" "write_store_neutrality_sidecar ||" "if (( PARTITION_HEAL_REORG_MODE == 1 )); then"
  python3 - "${probe_root}" <<'PY'
import hashlib, json, sys
root = sys.argv[1]
for name, size in (("116", 116), ("148", 148)):
    header = bytes(range(size))
    for impl in ("go", "rust"):
        json.dump({"block_hex": (header + bytes(8)).hex(), "hash": hashlib.sha3_256(header).hexdigest()}, open(f"{root}/block-{name}-{impl}.json", "w"))
h116, h148 = bytes(range(116)), bytes(range(148))
for impl, block_hex, block_hash in (("go", h116 + bytes(8), hashlib.sha3_256(h116).hexdigest()), ("rust", h148 + bytes(8), hashlib.sha3_256(h148).hexdigest())):
    json.dump({"block_hex": block_hex.hex(), "hash": block_hash}, open(f"{root}/block-differ-{impl}.json", "w"))
    json.dump({"block_hex": (h148 + bytes(8)).hex(), "hash": hashlib.sha3_256(h116).hexdigest() if impl == "go" else "ff" * 32}, open(f"{root}/block-nomatch-{impl}.json", "w"))
ident = {"network": "devnet", "chain_id_hex": "dd" * 32, "genesis_hash_hex": "ee" * 32}
json.dump({**ident, "peer_count": 3}, open(f"{root}/ident.json", "w"))
block = json.load(open(f"{root}/block-116-go.json"))
for name, base in (("ident", ident), ("block", block)):
    for key in base:
        json.dump({k: v for k, v in base.items() if k != key}, open(f"{root}/bad-{name}-no-{key}.json", "w"))
        json.dump({**base, key: None}, open(f"{root}/bad-{name}-null-{key}.json", "w"))
        json.dump({**base, key: 7}, open(f"{root}/bad-{name}-number-{key}.json", "w"))
json.dump({"best_known_height": 101, "has_tip": True, "height": 101, "in_ibd": False, "tip_hash": "c1" * 32}, open(f"{root}/tip-go.json", "w"))
json.dump({"best_known_height": 102, "has_tip": False, "height": 102, "in_ibd": True, "tip_hash": "c2" * 32}, open(f"{root}/tip-rust.json", "w"))
for impl in ("go", "rust"):
    json.dump({"best_known_height": 0, "has_tip": False, "height": None, "in_ibd": False, "tip_hash": None}, open(f"{root}/tip-absent-{impl}.json", "w"))
for impl in ("go", "rust", "txgen"):
    open(f"{root}/bin-{impl}", "w").write(f"{impl} binary\n")
json.dump([], open(f"{root}/array.json", "w"))
PY
  cat >"${probe}" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
source "$1"
main="$2"; p="$3"
TX_PATH_MODE=3; RUST_RESTART_MODE=0; PARTITION_HEAL_REORG_MODE=0; GO_RPC_ADDR="127.0.0.1:51001"; RUST_RPC_ADDR="127.0.0.1:51003"; REPO_ROOT="${p}"
GO_NODE_BIN="${p}/bin-go"; RUST_NODE_BIN="${p}/bin-rust"; TXGEN_BIN="${p}/bin-txgen"; GO_DIR="${p}/node-go"; RUST_DIR="${p}/node-rust"; RUST_EXACT_EMPTY_BEFORE_FIRST_START=true
CHAIN_IDENTITY_JSON="${p}/cap/ident.json"; GENESIS_GO_BLOCK_JSON="${p}/cap/go.json"; GENESIS_RUST_BLOCK_JSON="${p}/cap/rust.json"; INITIAL_GO_TIP_JSON="${p}/tip-go.json"; INITIAL_RUST_TIP_JSON="${p}/tip-rust.json"
STORE_NEUTRALITY_JSON="${p}/out/sidecar.json"; BLOCKS=116; FAIL_CAPTURE=""; BAD_CAPTURE=""; BAD_SRC=""; FAIL_GIT=""; GIT_HEAD=0123456789abcdef0123456789abcdef01234567; GIT_STATUS=""
capture_rpc_sidecar() {
  local src="${p}/block-${BLOCKS}-$1.json"
  printf '%s\n' "$1 $4" >>"${p}/captures.log"
  [[ "$1 $4" == "${FAIL_CAPTURE}" ]] && return 1
  [[ "$4" == /chain_identity ]] && src="${p}/ident.json"
  [[ "$1 $4" == "${BAD_CAPTURE}" ]] && src="${BAD_SRC}"
  cp -- "${src}" "$5"
}
git() {
  [[ "$3" == "${FAIL_GIT}" ]] && return 128
  case "$*" in
    "-C ${p} rev-parse HEAD") printf '%s\n' "${GIT_HEAD}" ;;
    "-C ${p} status --porcelain -- clients") printf '%s' "${GIT_STATUS}" ;;
    *) return 99 ;;
  esac
}
finish_no_data() { printf '%s\n' "$1"; exit 0; }
expect_end() {
  local got
  rm -f -- "${p}/captures.log"
  got="$(source "${main}"; printf 'completed\n')"
  [[ "${got}" == "$1" ]] || { echo "FAIL: sidecar producer ended with ${got}, want $1" >&2; exit 1; }
}
expect_sidecar() {
  python3 - "${STORE_NEUTRALITY_JSON}" "${p}" "${GIT_HEAD}" "$1" "$2" "$3" "${INITIAL_GO_TIP_JSON}" "${INITIAL_RUST_TIP_JSON}" <<'PY' || { echo "FAIL: sidecar members or capture requests differ from the producer inputs, clients_tree_clean $1, rust_exact_empty_before_first_start $2, mode $3" >&2; exit 1; }
import hashlib, json, sys
out, p, head, clean, empty, mode, go_tip_path, rust_tip_path = sys.argv[1:9]
chain = mode == "chain"
def load(path): return json.load(open(path, encoding="utf-8"))
def sha(name): return hashlib.sha256(open(f"{p}/{name}", "rb").read()).hexdigest()
ident, go_tip, rust_tip = load(f"{p}/ident.json"), load(go_tip_path), load(rust_tip_path)
want = {
    "evidence_domain": "pre_switch_store_neutrality", "protocol_commit": head, "clients_tree_clean": clean == "true",
    "binaries": {"go_node_sha256": sha("bin-go"), "rust_node_sha256": sha("bin-rust"), "txgen_sha256": sha("bin-txgen") if chain else None},
    "chain_identity": {key: ident[key] for key in ("network", "chain_id_hex", "genesis_hash_hex")},
    "genesis": {"go_hash": load(f"{p}/block-differ-go.json")["hash"], "rust_hash": load(f"{p}/block-differ-rust.json")["hash"], "go_block_path": f"{p}/cap/go.json", "rust_block_path": f"{p}/cap/rust.json"} if chain else None,
    "header_bytes": {"go": 116, "rust": 148} if chain else None,
    "datadirs": {"go": f"{p}/node-go", "rust": f"{p}/node-rust", "rust_exact_empty_before_first_start": empty == "true"},
    "initial_convergence": {"go_has_tip": go_tip["has_tip"], "rust_has_tip": rust_tip["has_tip"], "height": go_tip["height"], "go_tip_hash": go_tip["tip_hash"], "rust_tip_hash": rust_tip["tip_hash"], "go_tip_path": go_tip_path, "rust_tip_path": rust_tip_path},
}
captures = ["go /chain_identity"] + (["go /get_block?height=0", "rust /get_block?height=0"] if chain else [])
sys.exit(load(out) != want or open(f"{p}/captures.log", encoding="utf-8").read().splitlines() != captures)
PY
}
expect_heights() { python3 -c 'import json, sys; sys.exit(json.load(open(sys.argv[1]))["header_bytes"] != {"go": int(sys.argv[2]), "rust": int(sys.argv[3])})' "${STORE_NEUTRALITY_JSON}" "$1" "$2" || { echo "FAIL: sidecar header_bytes is not go $1 rust $2" >&2; exit 1; }; }
BLOCKS=148 expect_end completed; expect_heights 148 148
BLOCKS=nomatch expect_end completed; expect_heights 116 0
BLOCKS=differ expect_end completed; expect_sidecar true true chain
BLOCKS=differ GIT_STATUS=" M clients/go/node/miner.go" RUST_EXACT_EMPTY_BEFORE_FIRST_START=false expect_end completed; expect_sidecar false false chain
expect_end completed; expect_heights 116 116
bad_captures=0
for bad in "${p}"/bad-ident-*.json; do BAD_CAPTURE="go /chain_identity" BAD_SRC="${bad}" expect_end store_neutrality_chain_identity_capture_failed; bad_captures=$((bad_captures + 1)); done
for bad in "${p}"/bad-block-*.json; do
  for capture in "go /get_block?height=0" "rust /get_block?height=0"; do BAD_CAPTURE="${capture}" BAD_SRC="${bad}" expect_end store_neutrality_genesis_capture_failed; bad_captures=$((bad_captures + 1)); done
done
(( bad_captures == 21 )) || { echo "FAIL: producer member cases ran ${bad_captures}, want 21" >&2; exit 1; }
FAIL_CAPTURE="go /chain_identity" expect_end store_neutrality_chain_identity_capture_failed
BAD_CAPTURE="go /chain_identity" BAD_SRC="${p}/array.json" expect_end store_neutrality_chain_identity_capture_failed
FAIL_CAPTURE="go /get_block?height=0" expect_end store_neutrality_genesis_capture_failed
FAIL_CAPTURE="rust /get_block?height=0" expect_end store_neutrality_genesis_capture_failed
BAD_CAPTURE="rust /get_block?height=0" BAD_SRC="${p}/array.json" expect_end store_neutrality_genesis_capture_failed
FAIL_GIT=rev-parse expect_end store_neutrality_commit_unavailable
FAIL_GIT=status expect_end store_neutrality_commit_unavailable
TXGEN_BIN="${p}/missing" expect_end store_neutrality_binary_hash_failed
STORE_NEUTRALITY_JSON="${p}/missing/sidecar.json" expect_end store_neutrality_sidecar_write_failed
INITIAL_GO_TIP_JSON="${p}/array.json" expect_end store_neutrality_sidecar_write_failed
INITIAL_RUST_TIP_JSON="${p}/missing-tip.json" expect_end store_neutrality_sidecar_write_failed
rm -f -- "${GENESIS_GO_BLOCK_JSON}" "${GENESIS_RUST_BLOCK_JSON}"
(
  TX_PATH_MODE=0; TXGEN_BIN="${p}/missing"; INITIAL_GO_TIP_JSON="${p}/tip-absent-go.json"; INITIAL_RUST_TIP_JSON="${p}/tip-absent-rust.json"
  expect_end completed; expect_sidecar true true default
)
SH
  bash "${probe}" "${lib}" "${main}" "${probe_root}"
}

extract_proxy_go_local_addr() {
  python3 - "${HARNESS}" "${PROXY_GO_LOCAL_ADDR_LIB}" <<'PY'
from pathlib import Path
import sys

src, dst = map(Path, sys.argv[1:3])
lines = src.read_text(encoding="utf-8").splitlines()
start = next(i for i, line in enumerate(lines) if line.startswith("proxy_go_local_addr()"))
end = next(i for i, line in enumerate(lines[start:], start) if line.startswith("wait_peer_snapshot_state()"))
Path(dst).write_text("\n".join(lines[start:end]) + "\n", encoding="utf-8")
PY
}

extract_wait_peer_snapshot() {
  python3 - "${HARNESS}" "${WAIT_PEER_SNAPSHOT_LIB}" <<'PY'
from pathlib import Path
import sys

src, dst = map(Path, sys.argv[1:3])
lines = src.read_text(encoding="utf-8").splitlines()
start = next(i for i, line in enumerate(lines) if line.startswith("wait_peer_snapshot()"))
end = next(i for i, line in enumerate(lines[start:], start) if line.startswith("wait_rust_to_go_link()"))
Path(dst).write_text("\n".join(lines[start:end]) + "\n", encoding="utf-8")
PY
}

extract_capture_go_reorg_metrics() {
  python3 - "${HARNESS}" "${CAPTURE_GO_REORG_METRICS_LIB}" <<'PY'
from pathlib import Path
import sys

src, dst = map(Path, sys.argv[1:3])
lines = src.read_text(encoding="utf-8").splitlines()
start = next(i for i, line in enumerate(lines) if line.startswith("capture_go_reorg_metrics()"))
end = next(i for i, line in enumerate(lines[start:], start) if line.startswith("run_partition_heal_reorg_scenario()"))
Path(dst).write_text("\n".join(lines[start:end]) + "\n", encoding="utf-8")
PY
}

extract_wait_peer_snapshot_state() {
  python3 - "${HARNESS}" "${WAIT_PEER_SNAPSHOT_STATE_LIB}" <<'PY'
from pathlib import Path
import sys

src, dst = map(Path, sys.argv[1:3])
lines = src.read_text(encoding="utf-8").splitlines()
start = next(i for i, line in enumerate(lines) if line.startswith("wait_peer_snapshot_state()"))
end = next(i for i, line in enumerate(lines[start:], start) if line.startswith("parse_partition_mine_result()"))
Path(dst).write_text("\n".join(lines[start:end]) + "\n", encoding="utf-8")
PY
}

check_proxy_go_local_addr_reason() {
  local probe="${TMP_ROOT}/proxy-go-local-addr-probe.sh"
  cat >"${probe}" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
source "$1"
RUBIN_PROCESS_ARTIFACT_ROOT="$2"
MESH_TIMEOUT=2
PARTITION_PROXY_PID=123
GO_P2P_ADDR="127.0.0.1:51002"
PARTITION_REASON=""
bounded() { return 142; }
if proxy_go_local_addr partition_pre_proxy_to_go_missing partition_pre_proxy_to_go_ambiguous; then
  echo "FAIL: proxy_go_local_addr should fail on lsof timeout" >&2
  exit 1
fi
[[ "${PARTITION_REASON}" == "lsof_timeout" ]] || { echo "FAIL: proxy_go_local_addr lost parent-visible reason: ${PARTITION_REASON}" >&2; exit 1; }
SH
  bash "${probe}" "${PROXY_GO_LOCAL_ADDR_LIB}" "${TMP_ROOT}"
}

check_wait_peer_snapshot_normalizes() {
  local probe="${TMP_ROOT}/wait-peer-snapshot-probe.sh"
  cat >"${probe}" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
source "$1"
probe_root="$2"
MESH_TIMEOUT=2
RPC_JSON_INPUT=""
rpc_json() { cat -- "${RPC_JSON_INPUT}"; }
write_json() { printf '%s\n' "$2" >"$1"; }
rich="${probe_root}/peer-rich.json"; extra="${probe_root}/peer-secret.json"; out="${probe_root}/peer-out-public.json"
write_json "${rich}" '{"count":1,"peers":[{"addr":"127.0.0.1:51001","handshake_complete":true,"ban_score":0,"last_error":"","protocol_version":1,"best_height":7,"tx_relay":true,"pruned_below_height":0,"da_mempool_size":0}]}'
write_json "${extra}" '{"count":1,"peers":[{"addr":"127.0.0.1:51001","handshake_complete":true,"secret":"x"}]}'
RPC_JSON_INPUT="${rich}"
PEER_SNAPSHOT_REASON=""
wait_peer_snapshot node-go "${RPC_JSON_INPUT}" "${out}" 2 "127.0.0.1:51001" || { echo "FAIL: rich wait_peer_snapshot rejected: ${PEER_SNAPSHOT_REASON}" >&2; exit 1; }
python3 - "${out}" <<'PY'
import json, sys
data = json.load(open(sys.argv[1], encoding="utf-8"))
if data != {"count": 1, "peers": [{"addr": "127.0.0.1:51001", "handshake_complete": True}]}:
    sys.exit(1)
PY
RPC_JSON_INPUT="${extra}"
PEER_SNAPSHOT_REASON=""
if wait_peer_snapshot node-go "${RPC_JSON_INPUT}" "${out}" 2 "127.0.0.1:51001"; then
  echo "FAIL: wait_peer_snapshot accepted secret peer metadata" >&2
  exit 1
fi
[[ "${PEER_SNAPSHOT_REASON}" == "peer_snapshot_invalid_shape" ]] || { echo "FAIL: wait_peer_snapshot reason ${PEER_SNAPSHOT_REASON}" >&2; exit 1; }
SH
  bash "${probe}" "${WAIT_PEER_SNAPSHOT_LIB}" "${TMP_ROOT}"
}

check_capture_go_reorg_metrics_reason() {
  local probe="${TMP_ROOT}/capture-go-reorg-metrics-probe.sh"
  cat >"${probe}" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
source "$1"
probe_root="$2"
GO_RPC_ADDR="127.0.0.1:51001"
PARTITION_GO_METRICS_PROM="${probe_root}/captured.prom"
PARTITION_GO_METRICS_PARSED=""
PARTITION_REASON=""
METRICS_INPUT=""
rpc_json() { cat -- "${METRICS_INPUT}"; }
write_case() {
  local path="$1"
  shift
  printf '%s\n' "$@" >"${path}"
}
expect_metrics_pass() {
  METRICS_INPUT="$1"
  PARTITION_REASON=""
  PARTITION_GO_METRICS_PARSED=""
  capture_go_reorg_metrics || { echo "FAIL: metrics parser rejected valid input: ${PARTITION_REASON}" >&2; exit 1; }
  [[ "${PARTITION_GO_METRICS_PARSED}" == "$2" ]] || { echo "FAIL: metrics parser returned ${PARTITION_GO_METRICS_PARSED}" >&2; exit 1; }
}
expect_metrics_reason() {
  local expected="$2"
  METRICS_INPUT="$1"
  PARTITION_REASON=""
  PARTITION_GO_METRICS_PARSED=""
  if capture_go_reorg_metrics; then
    echo "FAIL: metrics parser accepted invalid input ${METRICS_INPUT}" >&2
    exit 1
  fi
  [[ "${PARTITION_REASON}" == "${expected}" ]] || { echo "FAIL: metrics parser reason ${PARTITION_REASON}, want ${expected}" >&2; exit 1; }
}
valid="${probe_root}/valid.prom"; depth_zero="${probe_root}/depth-zero.prom"; timestamp="${probe_root}/timestamp.prom"; json="${probe_root}/metrics.json"; zero="${probe_root}/zero.prom"; zero_depth_zero="${probe_root}/zero-depth-zero.prom"; zero_depth_one="${probe_root}/zero-depth-one.prom"; duplicate="${probe_root}/duplicate.prom"
write_case "${valid}" "rubin_node_reorg_total 2" "rubin_node_last_reorg_depth 3"
write_case "${depth_zero}" "rubin_node_reorg_total 1" "rubin_node_last_reorg_depth 0"
write_case "${timestamp}" "rubin_node_reorg_total 2 123" "rubin_node_last_reorg_depth 3"
write_case "${json}" '{"rubin_node_reorg_total": 2, "rubin_node_last_reorg_depth": 3}'
write_case "${zero}" "rubin_node_reorg_total 0" "rubin_node_last_reorg_depth 3"
write_case "${zero_depth_zero}" "rubin_node_reorg_total 0" "rubin_node_last_reorg_depth 0"; write_case "${zero_depth_one}" "rubin_node_reorg_total 0" "rubin_node_last_reorg_depth 1"
write_case "${duplicate}" "rubin_node_reorg_total 2" "rubin_node_reorg_total 3" "rubin_node_last_reorg_depth 3"
expect_metrics_pass "${valid}" $'2\t3'; expect_metrics_pass "${depth_zero}" $'1\t0'
expect_metrics_reason "${timestamp}" partition_go_metrics_malformed
expect_metrics_reason "${json}" partition_go_metrics_malformed
expect_metrics_reason "${zero}" partition_go_metrics_missing_or_zero
expect_metrics_reason "${zero_depth_zero}" partition_go_metrics_missing_or_zero; expect_metrics_reason "${zero_depth_one}" partition_go_metrics_missing_or_zero
expect_metrics_reason "${duplicate}" partition_go_metrics_duplicate
SH
  bash "${probe}" "${CAPTURE_GO_REORG_METRICS_LIB}" "${TMP_ROOT}"
}

check_wait_peer_snapshot_state_reason() {
  local probe="${TMP_ROOT}/wait-peer-snapshot-state-probe.sh"
  cat >"${probe}" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
source "$1"
probe_root="$2"
MESH_TIMEOUT=2
RPC_JSON_INPUT=""
rpc_json() { cat -- "${RPC_JSON_INPUT}"; }
write_json() { printf '%s\n' "$2" >"$1"; }
valid="${probe_root}/peer-valid.json"; rich="${probe_root}/peer-rich.json"; overlong="${probe_root}/peer-overlong-port.json"; extra="${probe_root}/peer-extra-field.json"; out="${probe_root}/peer-out.json"
write_json "${valid}" '{"count":1,"peers":[{"addr":"127.0.0.1:51001","handshake_complete":true}]}'
write_json "${rich}" '{"count":1,"peers":[{"addr":"127.0.0.1:51001","handshake_complete":true,"ban_score":0,"last_error":"","protocol_version":1,"best_height":7,"tx_relay":true,"pruned_below_height":0,"da_mempool_size":0}]}'
write_json "${overlong}" '{"count":1,"peers":[{"addr":"127.0.0.1:123456","handshake_complete":true}]}'
write_json "${extra}" '{"count":1,"peers":[{"addr":"127.0.0.1:51001","handshake_complete":true,"secret":"x"}]}'
RPC_JSON_INPUT="${valid}"
PEER_SNAPSHOT_REASON=""
wait_peer_snapshot_state node-rust "${RPC_JSON_INPUT}" "${out}" 2 "127.0.0.1:51001" connected || { echo "FAIL: valid peer snapshot rejected: ${PEER_SNAPSHOT_REASON}" >&2; exit 1; }
RPC_JSON_INPUT="${rich}"
PEER_SNAPSHOT_REASON=""
wait_peer_snapshot_state node-rust "${RPC_JSON_INPUT}" "${out}" 2 "127.0.0.1:51001" connected || { echo "FAIL: rich peer snapshot rejected: ${PEER_SNAPSHOT_REASON}" >&2; exit 1; }
python3 - "${out}" <<'PY'
import json, sys
data = json.load(open(sys.argv[1], encoding="utf-8"))
if data != {"count": 1, "peers": [{"addr": "127.0.0.1:51001", "handshake_complete": True}]}:
    sys.exit(1)
PY
for invalid in "${overlong}" "${extra}"; do
  RPC_JSON_INPUT="${invalid}"
  PEER_SNAPSHOT_REASON=""
  if wait_peer_snapshot_state node-rust "${RPC_JSON_INPUT}" "${out}" 2 "127.0.0.1:51001" connected; then
    echo "FAIL: invalid peer snapshot accepted: ${invalid}" >&2
    exit 1
  fi
  [[ "${PEER_SNAPSHOT_REASON}" == "peer_snapshot_invalid_shape" ]] || { echo "FAIL: peer snapshot reason ${PEER_SNAPSHOT_REASON}" >&2; exit 1; }
done
SH
  bash "${probe}" "${WAIT_PEER_SNAPSHOT_STATE_LIB}" "${TMP_ROOT}"
}

check_prepare_tx_chainstate_cleanup() {
  local probe="${TMP_ROOT}/prepare-tx-chainstate-cleanup.sh" probe_root="${TMP_ROOT}/prepare-tx-chainstate-cleanup"
  mkdir -p -- "${probe_root}"
  cat >"${probe}" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

source "$1"
probe_root="$2"
KEYGEN_JSON="${probe_root}/keygen.json"
KEYGEN_GO="${probe_root}/keygen.go"
GO_MODULE_ROOT="${probe_root}/go"
DEV_ENV="${probe_root}/dev-env.sh"
GO_NODE_BIN="${probe_root}/rubin-node"
GO_DIR="${probe_root}/go-node"
RUST_DIR="${probe_root}/rust-node"
MINE_LOG="${probe_root}/mine-go.log"
TMPDIR="${probe_root}/tmp"
TX_REASON=""
TX_FROM_KEY_DIR=""
TX_FROM_KEY_FILE=""
TX_TO_KEY=""
mkdir -p -- "${TMPDIR}" "${GO_MODULE_ROOT}" "${GO_DIR}" "${RUST_DIR}"

build_go_txgen() { :; }
write_keygen() { :; }
disable_xtrace_for_secret() { return 1; }
restore_xtrace_after_secret() { :; }
make_tx_secret_dir() {
  mkdir -p -- "${probe_root}/secret"
  printf '%s\n' "${probe_root}/secret"
}
cleanup_tx_from_key_file() { :; }
bounded_mesh() {
  printf '{"malformed":true}\n'
  printf 'keygen stderr\n' >&2
}
parse_keygen_material() { return 9; }
keygen_material_reason() { printf '%s\n' go_submit_keygen_material_malformed; }

set +e
prepare_tx_chainstate
rc=$?
set -e
[[ ${rc} -ne 0 ]] || { echo "FAIL: prepare_tx_chainstate should fail on malformed keygen material" >&2; exit 1; }
[[ "${TX_REASON}" == "go_submit_keygen_material_malformed" ]] || { echo "FAIL: unexpected TX_REASON: ${TX_REASON}" >&2; exit 1; }
[[ ! -e "${KEYGEN_JSON}.raw" ]] || { echo "FAIL: keygen raw sidecar survived failure" >&2; exit 1; }
[[ ! -e "${KEYGEN_JSON}.stderr" ]] || { echo "FAIL: keygen stderr sidecar survived failure" >&2; exit 1; }
SH
  bash "${probe}" "${PREPARE_TX_CHAINSTATE_LIB}" "${probe_root}"
}

write_reports() {
  python3 - "${TMP_ROOT}" <<'PY'
from pathlib import Path
import hashlib
import json
import stat
import sys

root = Path(sys.argv[1])
artifact_root = root / "artifact-root"
artifact_root.mkdir()
(artifact_root / "node-go").mkdir()
(artifact_root / "node-rust").mkdir()
go_bin = artifact_root / "rubin-node-go"
rust_bin = artifact_root / "rubin-node-rust"
for path in (go_bin, rust_bin):
    path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)

def compact_size(n: int) -> bytes:
    if n < 0xfd:
        return bytes([n])
    if n <= 0xffff:
        return b"\xfd" + n.to_bytes(2, "little")
    if n <= 0xffffffff:
        return b"\xfe" + n.to_bytes(4, "little")
    return b"\xff" + n.to_bytes(8, "little")

def sha3(data: bytes) -> bytes:
    return hashlib.sha3_256(data).digest()

def read_compact_size(buf: bytes, off: int) -> tuple[int, int]:
    first = buf[off]
    if first < 0xfd:
        return first, off + 1
    if first == 0xfd:
        return int.from_bytes(buf[off + 1:off + 3], "little"), off + 3
    if first == 0xfe:
        return int.from_bytes(buf[off + 1:off + 5], "little"), off + 5
    return int.from_bytes(buf[off + 1:off + 9], "little"), off + 9

def txid_kind0(txb: bytes) -> bytes:
    off = 0
    off += 4  # version
    tx_kind = txb[off]
    off += 1
    if tx_kind != 0:
        raise ValueError("synthetic test only supports tx_kind=0")
    off += 8  # nonce
    n_inputs, off = read_compact_size(txb, off)
    for _ in range(n_inputs):
        off += 32 + 4
        script_len, off = read_compact_size(txb, off)
        off += script_len + 4
    n_outputs, off = read_compact_size(txb, off)
    for _ in range(n_outputs):
        off += 8 + 2
        covenant_len, off = read_compact_size(txb, off)
        off += covenant_len
    off += 4  # locktime
    return sha3(txb[:off])

def build_synthetic_submitted_tx() -> bytes:
    return b"".join([
        (1).to_bytes(4, "little"),
        b"\x00",
        (7).to_bytes(8, "little"),
        compact_size(1),
        b"\x11" * 32,
        (0).to_bytes(4, "little"),
        compact_size(0),
        (0).to_bytes(4, "little"),
        compact_size(1),
        (0).to_bytes(8, "little"),
        (0x0002).to_bytes(2, "little"),
        compact_size(1),
        b"\x42",
        (0).to_bytes(4, "little"),
        compact_size(0),
        compact_size(0),
    ])

tx_bytes = build_synthetic_submitted_tx()
tx_hex = tx_bytes.hex()
txid = txid_kind0(tx_bytes).hex()
go_rpc = "127.0.0.1:51001"
go_p2p = "127.0.0.1:51002"
rust_rpc = "127.0.0.1:51003"
rust_p2p = "127.0.0.1:51004"
rust_outbound = "127.0.0.1:51005"
go_started = "2026-05-12T10:00:00Z"
rust_started = "2026-05-12T10:00:01Z"

def dump(path: Path, data: object) -> None:
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")

def node(impl: str, create_store: bool) -> dict:
    is_go = impl == "go"
    name = "node-go" if is_go else "node-rust"
    binary = go_bin if is_go else rust_bin
    argv = [
        str(binary),
        "--network",
        "devnet",
        "--datadir",
        str(artifact_root / name),
        "--bind",
        "127.0.0.1:0",
        "--rpc-bind",
        "127.0.0.1:0",
    ]
    if not is_go:
        argv.extend(["--peer", go_p2p])
    if create_store:
        argv.append("--create-store")
    return {
        "binary": str(binary),
        "command": " ".join(argv),
        "command_argv": argv,
        "implementation": impl,
        "name": name,
        "p2p_endpoint": go_p2p if is_go else rust_p2p,
        "p2p_endpoint_process_backed": True,
        "pid": 41001 if is_go else 41002,
        "process_alive": True,
        "process_comm": "rubin-node-go" if is_go else "rubin-node-rust",
        "rpc_endpoint": go_rpc if is_go else rust_rpc,
        "rpc_endpoint_process_backed": True,
        "started_at": go_started if is_go else rust_started,
    }

nodes = [node("go", True), node("rust", True)]
connectivity = {
    "bidirectional_observed": True,
    "counterpart_links": {
        "go_peer_snapshot_expected_addr": rust_outbound,
        "rust_outbound_local_addr": rust_outbound,
        "rust_outbound_pid": 41002,
        "rust_outbound_remote_addr": go_p2p,
        "rust_peer_snapshot_expected_addr": go_p2p,
    },
    "go_peer_snapshot": {"count": 1, "peers": [{"addr": rust_outbound, "handshake_complete": True}]},
    "go_to_rust": True,
    "rust_peer_snapshot": {"count": 1, "peers": [{"addr": go_p2p, "handshake_complete": True}]},
    "rust_to_go": True,
}
final_verification = {
    "peer_snapshots_rechecked": True,
    "process_identity_rechecked": True,
    "producer_side": True,
    "rust_outbound_link_rechecked": True,
    "rust_outbound_local_addr": rust_outbound,
    "rust_outbound_pid": 41002,
    "rust_outbound_remote_addr": go_p2p,
}


def raw_samples(prop_direction=None, prop_elapsed=2, conv_direction=None, conv_elapsed=3):
    def bucket(direction, elapsed, sample_kind):
        if direction is None:
            return {
                "classification": "not_requested",
                "path_direction": None,
                "reason": f"{sample_kind}_sample_not_requested_by_scenario",
                "samples": [],
                "unit": "seconds",
            }
        source_impl, target_impl = direction.split("->")
        sample = {
            "classification": "observed",
            "elapsed": elapsed,
            "path_direction": direction,
            "source": f"node-{source_impl}",
            "target": f"node-{target_impl}",
            "tx_id": txid,
            "unit": "seconds",
        }
        if sample_kind == "convergence":
            sample.update({"block_hash": block_hash, "height": height})
        return {
            "classification": "observed",
            "path_direction": direction,
            "reason": None,
            "samples": [sample],
            "unit": "seconds",
        }
    return {
        "schema_version": "rubin-devnet-process-soak-raw-samples-v1",
        "semantics": "raw samples only; no SLO threshold or pass claim",
        "propagation": bucket(prop_direction, prop_elapsed, "propagation"),
        "convergence": bucket(conv_direction, conv_elapsed, "convergence"),
    }


mesh_marker = artifact_root / "mesh-marker.json"
dump(mesh_marker, {
    "evidence_type": "mixed_client_process_soak",
    "failure_reason": "schema v1 PASS requires tx_path; mesh PASS lives in sibling report",
    "participants": [
        {"endpoint": go_rpc, "implementation": "go", "name": "node-go", "started_at": go_started},
        {"endpoint": rust_rpc, "implementation": "rust", "name": "node-rust", "started_at": rust_started},
    ],
    "scenario": "mixed_client_mesh_schema_marker",
    "schema_version": "rubin-mixed-client-devnet-evidence-v1",
    "verdict": "FAIL",
})
mesh_report = {
    "artifact_root": str(artifact_root),
    "final_verification": final_verification,
    "legacy_schema_compatibility": {
        "authoritative": False,
        "marker_path": str(mesh_marker),
        "purpose": "schema-valid legacy artifact only; not the mesh report verdict",
        "reason": "existing mixed_client_evidence_v1 PASS requires tx_path",
    },
    "nodes": nodes,
    "peer_connectivity": connectivity,
    "raw_samples": raw_samples(),
    "scenario": "mixed_client_mesh",
    "verdict": "PASS",
}
dump(root / "mesh-report.json", mesh_report)

restart_marker = artifact_root / "restart-marker.json"
restart = {
    "catch_up_height": 108,
    "pre_restart_height": 107,
    "stopped_node": "node-rust",
}
restart_info = {
    "catch_up_has_tip": True,
    "catch_up_height": 108,
    "catch_up_tip": "bb" * 32,
    "catch_up_tip_path": str(artifact_root / "rust-catch-up-tip.json"),
    "datadir": str(artifact_root / "node-rust"),
    "go_target_has_tip": True,
    "go_target_height": 108,
    "go_target_mine_next_path": str(artifact_root / "go-restart-mine-next.json"),
    "go_target_tip": "bb" * 32,
    "go_target_tip_path": str(artifact_root / "go-restart-target-tip.json"),
    "go_target_tx_count": 1,
    "new_command_argv": node("rust", False)["command_argv"],
    "new_p2p_endpoint": rust_p2p,
    "new_pid": 41002,
    "new_rpc_endpoint": rust_rpc,
    "new_started_at": rust_started,
    "old_command_argv": node("rust", True)["command_argv"],
    "old_p2p_endpoint": "127.0.0.1:51031",
    "old_pid": 41020,
    "old_pid_stopped": True,
    "old_rpc_endpoint": "127.0.0.1:51030",
    "old_started_at": "2026-05-12T09:59:58Z",
    "peer_reconnect_observed": True,
    "pre_restart_has_tip": True,
    "pre_restart_height": 107,
    "pre_restart_tip": "aa" * 32,
    "pre_restart_tip_path": str(artifact_root / "rust-pre-restart-tip.json"),
    "same_datadir": True,
}
dump(artifact_root / "rust-pre-restart-tip.json", {"best_known_height": 107, "has_tip": True, "height": 107, "implementation": "rust", "in_ibd": False, "request_path": "/get_tip", "rpc_endpoint": "127.0.0.1:51030", "tip_hash": "aa" * 32})
dump(artifact_root / "go-restart-mine-next.json", {"block_hash": "bb" * 32, "height": 108, "implementation": "go", "mined": True, "nonce": 1777000001, "request_path": "/mine_next", "rpc_endpoint": go_rpc, "timestamp": 1777000000, "tx_count": 1, "commit_state": "committed"})
dump(artifact_root / "go-restart-target-tip.json", {"best_known_height": 108, "has_tip": True, "height": 108, "implementation": "go", "in_ibd": False, "request_path": "/get_tip", "rpc_endpoint": go_rpc, "tip_hash": "bb" * 32})
dump(artifact_root / "rust-catch-up-tip.json", {"best_known_height": 108, "has_tip": True, "height": 108, "implementation": "rust", "in_ibd": False, "request_path": "/get_tip", "rpc_endpoint": rust_rpc, "tip_hash": "bb" * 32})
dump(restart_marker, {
    "evidence_type": "mixed_client_process_soak",
    "failure_reason": "schema v1 PASS requires tx_path; restart PASS lives in sibling report",
    "participants": [
        {"endpoint": go_rpc, "implementation": "go", "name": "node-go", "started_at": go_started},
        {"endpoint": rust_rpc, "implementation": "rust", "name": "node-rust", "started_at": rust_started},
    ],
    "restart": restart,
    "scenario": "mixed_client_mesh_schema_marker",
    "schema_version": "rubin-mixed-client-devnet-evidence-v1",
    "verdict": "FAIL",
})
restart_report = {
    **mesh_report,
    "artifact_created_at_utc": "2026-05-12T10:00:02Z",
    "legacy_schema_compatibility": {
        "authoritative": False,
        "marker_path": str(restart_marker),
        "purpose": "schema-valid legacy artifact only; not the Rust restart report verdict",
        "reason": "existing mixed_client_evidence_v1 PASS requires tx_path; Rust restart PASS lives in this report",
    },
    "nodes": [node("go", False), node("rust", False)],
    "restart": restart,
    "run_id": artifact_root.name,
    "rust_restart": restart_info,
    "scenario": "mixed_client_rust_restart",
}
dump(root / "restart-report.json", restart_report)

tx_marker = artifact_root / "tx-marker.json"
tx_path = {"observed_at": ["node-rust"], "submitted_at": "node-go", "tx_id": txid}
dump(tx_marker, {
    "evidence_type": "mixed_client_process_soak",
    "participants": [
        {"endpoint": go_rpc, "implementation": "go", "name": "node-go", "started_at": go_started},
        {"endpoint": rust_rpc, "implementation": "rust", "name": "node-rust", "started_at": rust_started},
    ],
    "scenario": "mixed_client_mesh_schema_marker",
    "schema_version": "rubin-mixed-client-devnet-evidence-v1",
    "tx_path": tx_path,
    "verdict": "PASS",
})
for impl, endpoint, prefix in (("go", go_rpc, "go"), ("rust", rust_rpc, "rust")):
    status_path = artifact_root / f"{prefix}-tx-status.json"
    get_path = artifact_root / f"{prefix}-get-tx.json"
    dump(status_path, {
        "implementation": impl,
        "request_path": f"/tx_status?txid={txid}",
        "rpc_endpoint": endpoint,
        "status": "pending",
        "txid": txid,
    })
    dump(get_path, {
        "found": True,
        "implementation": impl,
        "raw_hex": tx_hex,
        "request_path": f"/get_tx?txid={txid}",
        "rpc_endpoint": endpoint,
        "txid": txid,
    })
for impl, endpoint, prefix in (("rust", rust_rpc, "rust-submit"), ("go", go_rpc, "go-accept")):
    dump(artifact_root / f"{prefix}-tx-status.json", {
        "implementation": impl,
        "request_path": f"/tx_status?txid={txid}",
        "rpc_endpoint": endpoint,
        "status": "pending",
        "txid": txid,
    })
    dump(artifact_root / f"{prefix}-get-tx.json", {
        "found": True,
        "implementation": impl,
        "raw_hex": tx_hex,
        "request_path": f"/get_tx?txid={txid}",
        "rpc_endpoint": endpoint,
        "txid": txid,
    })
height = 103
tx_count = 2

def merkle(ids: list[bytes], leaf_tag: int, node_tag: int) -> bytes:
    level = [sha3(bytes([leaf_tag]) + item) for item in ids]
    while len(level) > 1:
        next_level = []
        i = 0
        while i < len(level):
            if i == len(level) - 1:
                next_level.append(level[i])
                i += 1
            else:
                next_level.append(sha3(bytes([node_tag]) + level[i] + level[i + 1]))
                i += 2
        level = next_level
    return level[0]

def coinbase_with_witness_commitment(block_height: int, non_coinbase_txs: list[bytes]) -> tuple[bytes, bytes, bytes]:
    wtxids = [bytes(32)] + [sha3(txb) for txb in non_coinbase_txs]
    witness_root = merkle(wtxids, 0x02, 0x03)
    commitment = sha3(b"RUBIN-WITNESS/" + witness_root)
    core = b"".join([
        (1).to_bytes(4, "little"),
        b"\x00",
        (0).to_bytes(8, "little"),
        compact_size(1),
        bytes(32),
        (0xffffffff).to_bytes(4, "little"),
        compact_size(0),
        (0xffffffff).to_bytes(4, "little"),
        compact_size(1),
        (0).to_bytes(8, "little"),
        (0x0002).to_bytes(2, "little"),
        compact_size(len(commitment)),
        commitment,
        block_height.to_bytes(4, "little"),
    ])
    full = core + compact_size(0) + compact_size(0)
    return full, sha3(core), sha3(full)

def build_basic_block(non_coinbase_hex: str, block_height: int, prev_hash=None) -> tuple[str, str]:
    non_coinbase = bytes.fromhex(non_coinbase_hex)
    non_coinbase_txid = txid_kind0(non_coinbase)
    if non_coinbase_hex == tx_hex and non_coinbase_txid.hex() != txid:
        raise ValueError("synthetic txid fixture drift")
    coinbase, coinbase_txid, _ = coinbase_with_witness_commitment(block_height, [non_coinbase])
    txids = [coinbase_txid, non_coinbase_txid]
    merkle_root = merkle(txids, 0x00, 0x01)
    header = b"".join([
        (1).to_bytes(4, "little"),
        bytes(32) if prev_hash is None else bytes.fromhex(prev_hash),
        merkle_root,
        (1).to_bytes(8, "little"),
        b"\xff" * 32,
        (1).to_bytes(8, "little"),
    ])
    block = header + compact_size(2) + coinbase + non_coinbase
    return block.hex(), sha3(header).hex()

def corrupt_merkle_block(block_hex_value: str) -> tuple[str, str]:
    block = bytearray.fromhex(block_hex_value)
    block[4 + 32] ^= 0x01
    return bytes(block).hex(), sha3(bytes(block[:116])).hex()

def block_sidecar(impl: str, endpoint: str, block_hex_value: str, block_hash_value: str, sidecar_height: int = height) -> dict:
    return {"block_hex": block_hex_value, "canonical": True, "hash": block_hash_value, "height": sidecar_height, "implementation": impl, "request_path": f"/get_block?height={sidecar_height}", "rpc_endpoint": endpoint}
def tip_sidecar(impl: str, endpoint: str, block_hash_value: str, sidecar_height: int) -> dict:
    return {"best_known_height": sidecar_height, "has_tip": True, "height": sidecar_height, "implementation": impl, "in_ibd": False, "request_path": "/get_tip", "rpc_endpoint": endpoint, "tip_hash": block_hash_value}
def mine_sidecar(impl: str, endpoint: str, block_hash_value: str, sidecar_height: int, count: int = tx_count) -> dict:
    return {"block_hash": block_hash_value, "height": sidecar_height, "implementation": impl, "mined": True, "nonce": 0, "request_path": "/mine_next", "rpc_endpoint": endpoint, "timestamp": 1, "tx_count": count, **({"commit_state": "committed"} if impl == "go" else {})}
def peer_snapshot(addr):
    peers = [] if addr is None else [{"addr": addr, "handshake_complete": True}]
    return {"count": len(peers), "peers": peers}

common_height = height - 1
rust_win_height = height + 1
common_block_hex, common_hash = build_basic_block(tx_hex, common_height)
block_hex, block_hash = build_basic_block(tx_hex, height, common_hash)
mutated_tx = bytearray.fromhex(tx_hex)
mutated_tx[5] ^= 0x01
missing_tx_block_hex, missing_tx_hash = build_basic_block(mutated_tx.hex(), height)
partition_rust_block_1_hex, partition_rust_block_1_hash = build_basic_block(mutated_tx.hex(), height, common_hash)
rust_win_block_hex, rust_win_hash = build_basic_block(mutated_tx.hex(), rust_win_height, partition_rust_block_1_hash)
rust_skip_height = height + 3
rust_skip_block_hex, rust_skip_hash = build_basic_block(mutated_tx.hex(), rust_skip_height, partition_rust_block_1_hash)
disconnected_go_block_hex, disconnected_go_hash = build_basic_block(tx_hex, height)
corrupt_block_hex, corrupt_block_hash = corrupt_merkle_block(block_hex)

dump(artifact_root / "rust-mined-block.json", block_sidecar("rust", rust_rpc, block_hex, block_hash))
dump(artifact_root / "go-converged-block.json", block_sidecar("go", go_rpc, block_hex, block_hash))
dump(artifact_root / "go-converged-wrong-source-block.json", block_sidecar("rust", rust_rpc, block_hex, block_hash))
dump(artifact_root / "go-converged-malformed-block.json", {"block_hex": "00", "canonical": True, "hash": block_hash, "height": height, "implementation": "go", "request_path": f"/get_block?height={height}", "rpc_endpoint": go_rpc})
dump(artifact_root / "rust-missing-tx-block.json", block_sidecar("rust", rust_rpc, missing_tx_block_hex, missing_tx_hash))
dump(artifact_root / "go-converged-missing-tx-block.json", block_sidecar("go", go_rpc, missing_tx_block_hex, missing_tx_hash))
dump(artifact_root / "rust-corrupt-merkle-block.json", block_sidecar("rust", rust_rpc, corrupt_block_hex, corrupt_block_hash))
dump(artifact_root / "go-corrupt-merkle-block.json", block_sidecar("go", go_rpc, corrupt_block_hex, corrupt_block_hash))
dump(artifact_root / "go-mined-block.json", block_sidecar("go", go_rpc, block_hex, block_hash))
dump(artifact_root / "rust-converged-block.json", block_sidecar("rust", rust_rpc, block_hex, block_hash))
dump(artifact_root / "rust-converged-wrong-source-block.json", block_sidecar("go", go_rpc, block_hex, block_hash))
dump(artifact_root / "rust-converged-malformed-block.json", {"block_hex": "00", "canonical": True, "hash": block_hash, "height": height, "implementation": "rust", "request_path": f"/get_block?height={height}", "rpc_endpoint": rust_rpc})
dump(artifact_root / "go-missing-tx-block.json", block_sidecar("go", go_rpc, missing_tx_block_hex, missing_tx_hash))
dump(artifact_root / "rust-converged-missing-tx-block.json", block_sidecar("rust", rust_rpc, missing_tx_block_hex, missing_tx_hash))
dump(artifact_root / "rust-mine-next.json", {"block_hash": block_hash, "height": height, "implementation": "rust", "mined": True, "nonce": 0, "request_path": "/mine_next", "rpc_endpoint": rust_rpc, "timestamp": 1, "tx_count": tx_count})
dump(artifact_root / "rust-missing-tx-mine-next.json", {"block_hash": missing_tx_hash, "height": height, "implementation": "rust", "mined": True, "nonce": 0, "request_path": "/mine_next", "rpc_endpoint": rust_rpc, "timestamp": 1, "tx_count": tx_count})
dump(artifact_root / "rust-corrupt-merkle-mine-next.json", {"block_hash": corrupt_block_hash, "height": height, "implementation": "rust", "mined": True, "nonce": 0, "request_path": "/mine_next", "rpc_endpoint": rust_rpc, "timestamp": 1, "tx_count": tx_count})
dump(artifact_root / "rust-tx-count-mismatch-mine-next.json", {"block_hash": block_hash, "height": height, "implementation": "rust", "mined": True, "nonce": 0, "request_path": "/mine_next", "rpc_endpoint": rust_rpc, "timestamp": 1, "tx_count": 3})
dump(artifact_root / "go-mine-next.json", {"block_hash": block_hash, "height": height, "implementation": "go", "mined": True, "nonce": 0, "request_path": "/mine_next", "rpc_endpoint": go_rpc, "timestamp": 1, "tx_count": tx_count, "commit_state": "committed"})
dump(artifact_root / "go-missing-tx-mine-next.json", {"block_hash": missing_tx_hash, "height": height, "implementation": "go", "mined": True, "nonce": 0, "request_path": "/mine_next", "rpc_endpoint": go_rpc, "timestamp": 1, "tx_count": tx_count, "commit_state": "committed"})
dump(artifact_root / "go-converge-tip.json", {"best_known_height": height, "has_tip": True, "height": height, "implementation": "go", "in_ibd": False, "request_path": "/get_tip", "rpc_endpoint": go_rpc, "tip_hash": block_hash})
dump(artifact_root / "go-missing-tx-tip.json", {"best_known_height": height, "has_tip": True, "height": height, "implementation": "go", "in_ibd": False, "request_path": "/get_tip", "rpc_endpoint": go_rpc, "tip_hash": missing_tx_hash})
dump(artifact_root / "go-corrupt-merkle-tip.json", {"best_known_height": height, "has_tip": True, "height": height, "implementation": "go", "in_ibd": False, "request_path": "/get_tip", "rpc_endpoint": go_rpc, "tip_hash": corrupt_block_hash})
dump(artifact_root / "rust-converge-tip.json", {"best_known_height": height, "has_tip": True, "height": height, "implementation": "rust", "in_ibd": False, "request_path": "/get_tip", "rpc_endpoint": rust_rpc, "tip_hash": block_hash})
dump(artifact_root / "rust-missing-tx-tip.json", {"best_known_height": height, "has_tip": True, "height": height, "implementation": "rust", "in_ibd": False, "request_path": "/get_tip", "rpc_endpoint": rust_rpc, "tip_hash": missing_tx_hash})
partition_proxy = "127.0.0.1:53010"
partition_go_peer = "127.0.0.1:53011"
partition_nodes = [node("go", False), node("rust", True)]
partition_nodes[1]["command_argv"][-2] = partition_proxy
partition_nodes[1]["command"] = " ".join(partition_nodes[1]["command_argv"])
partition_peer_connectivity = {"bidirectional_observed": False, "counterpart_links": {"go_peer_snapshot_expected_addr": None, "rust_outbound_local_addr": None, "rust_outbound_pid": None, "rust_outbound_remote_addr": None, "rust_peer_snapshot_expected_addr": None}, "go_peer_snapshot": {"count": 0, "peers": []}, "go_to_rust": False, "rust_peer_snapshot": {"count": 0, "peers": []}, "rust_to_go": False}
partition_final = {"peer_snapshots_rechecked": True, "process_identity_rechecked": True, "producer_side": True, "rust_outbound_link_rechecked": False, "rust_outbound_local_addr": None, "rust_outbound_pid": None, "rust_outbound_remote_addr": None}
dump(artifact_root / "partition-common-go-mine.json", mine_sidecar("go", go_rpc, common_hash, common_height))
dump(artifact_root / "partition-common-go-block.json", block_sidecar("go", go_rpc, common_block_hex, common_hash, common_height))
dump(artifact_root / "partition-common-rust-tip.json", tip_sidecar("rust", rust_rpc, common_hash, common_height))
dump(artifact_root / "partition-common-rust-block.json", block_sidecar("rust", rust_rpc, common_block_hex, common_hash, common_height))
dump(artifact_root / "partition-go-mine.json", mine_sidecar("go", go_rpc, block_hash, height))
dump(artifact_root / "partition-go-tip.json", tip_sidecar("go", go_rpc, block_hash, height))
dump(artifact_root / "partition-go-block.json", block_sidecar("go", go_rpc, block_hex, block_hash))
dump(artifact_root / "partition-rust-mine-1.json", mine_sidecar("rust", rust_rpc, partition_rust_block_1_hash, height))
dump(artifact_root / "partition-rust-block-1.json", block_sidecar("rust", rust_rpc, partition_rust_block_1_hex, partition_rust_block_1_hash))
dump(artifact_root / "partition-rust-same-fork-mine.json", mine_sidecar("rust", rust_rpc, block_hash, height))
dump(artifact_root / "partition-rust-same-fork-block.json", block_sidecar("rust", rust_rpc, block_hex, block_hash))
dump(artifact_root / "partition-rust-mine-2.json", mine_sidecar("rust", rust_rpc, rust_win_hash, rust_win_height))
dump(artifact_root / "partition-rust-tip.json", tip_sidecar("rust", rust_rpc, rust_win_hash, rust_win_height))
dump(artifact_root / "partition-rust-block-2.json", block_sidecar("rust", rust_rpc, rust_win_block_hex, rust_win_hash, rust_win_height))
dump(artifact_root / "partition-rust-skip-mine.json", mine_sidecar("rust", rust_rpc, rust_skip_hash, rust_skip_height))
dump(artifact_root / "partition-rust-skip-tip.json", tip_sidecar("rust", rust_rpc, rust_skip_hash, rust_skip_height))
dump(artifact_root / "partition-rust-skip-block.json", block_sidecar("rust", rust_rpc, rust_skip_block_hex, rust_skip_hash, rust_skip_height))
dump(artifact_root / "partition-final-go-skip-tip.json", tip_sidecar("go", go_rpc, rust_skip_hash, rust_skip_height))
dump(artifact_root / "partition-final-rust-skip-tip.json", tip_sidecar("rust", rust_rpc, rust_skip_hash, rust_skip_height))
dump(artifact_root / "partition-final-go-skip-block.json", block_sidecar("go", go_rpc, rust_skip_block_hex, rust_skip_hash, rust_skip_height))
dump(artifact_root / "partition-final-rust-skip-block.json", block_sidecar("rust", rust_rpc, rust_skip_block_hex, rust_skip_hash, rust_skip_height))
dump(artifact_root / "partition-final-go-tip.json", tip_sidecar("go", go_rpc, rust_win_hash, rust_win_height))
dump(artifact_root / "partition-final-rust-tip.json", tip_sidecar("rust", rust_rpc, rust_win_hash, rust_win_height))
dump(artifact_root / "partition-go-reorg-parent-block.json", block_sidecar("go", go_rpc, partition_rust_block_1_hex, partition_rust_block_1_hash))
dump(artifact_root / "partition-go-losing-reorg-parent-block.json", block_sidecar("go", go_rpc, block_hex, block_hash))
dump(artifact_root / "partition-go-reorg-parent-forged-block.json", block_sidecar("go", go_rpc, block_hex, partition_rust_block_1_hash))
dump(artifact_root / "partition-go-disconnected-mine.json", mine_sidecar("go", go_rpc, disconnected_go_hash, height))
dump(artifact_root / "partition-go-disconnected-tip.json", tip_sidecar("go", go_rpc, disconnected_go_hash, height))
dump(artifact_root / "partition-go-disconnected-block.json", block_sidecar("go", go_rpc, disconnected_go_block_hex, disconnected_go_hash))
dump(artifact_root / "partition-final-go-block.json", block_sidecar("go", go_rpc, rust_win_block_hex, rust_win_hash, rust_win_height))
dump(artifact_root / "partition-final-rust-block.json", block_sidecar("rust", rust_rpc, rust_win_block_hex, rust_win_hash, rust_win_height))
(artifact_root / "partition-go-metrics.prom").write_text("rubin_node_reorg_total 1\nrubin_node_last_reorg_depth 0\n", encoding="utf-8")
(artifact_root / "partition-go-metrics-depth-1.prom").write_text("rubin_node_reorg_total 1\nrubin_node_last_reorg_depth 1\n", encoding="utf-8")
(artifact_root / "partition-go-metrics-timestamp.prom").write_text("rubin_node_reorg_total 1 123\nrubin_node_last_reorg_depth 1 123\n", encoding="utf-8")
(artifact_root / "partition-go-metrics.json").write_text(json.dumps({"rubin_node_reorg_total": 1, "rubin_node_last_reorg_depth": 1}) + "\n", encoding="utf-8")
for name, addr in (("partition-pre-rust-peers.json", partition_proxy), ("partition-pre-go-peers.json", partition_go_peer), ("partition-drop-rust-peers.json", None), ("partition-drop-go-peers.json", None), ("partition-fork-rust-peers.json", None), ("partition-fork-go-peers.json", None), ("partition-heal-rust-peers.json", partition_proxy), ("partition-heal-go-peers.json", partition_go_peer)):
    dump(artifact_root / name, peer_snapshot(addr))
dump(artifact_root / "partition-direct-pre-rust-peers.json", peer_snapshot(go_p2p))
dump(artifact_root / "partition-direct-heal-rust-peers.json", peer_snapshot(go_p2p))
bad_peer_snapshot = peer_snapshot(partition_proxy); bad_peer_snapshot["count"] = True; dump(artifact_root / "partition-pre-rust-peers-bool-count.json", bad_peer_snapshot)
bad_peer_snapshot = peer_snapshot(partition_proxy); bad_peer_snapshot["peers"][0]["secret"] = "x"; dump(artifact_root / "partition-pre-rust-peers-extra-field.json", bad_peer_snapshot)
bad_tip = tip_sidecar("rust", rust_rpc, rust_win_hash, rust_win_height); bad_tip["height"] = float(rust_win_height); dump(artifact_root / "partition-rust-tip-float-height.json", bad_tip)
bad_tip = tip_sidecar("go", go_rpc, rust_win_hash, rust_win_height); bad_tip["in_ibd"] = "false"; dump(artifact_root / "partition-final-go-tip-string-ibd.json", bad_tip)
bad_mine = mine_sidecar("rust", rust_rpc, rust_win_hash, rust_win_height); bad_mine["nonce"] = "0"; dump(artifact_root / "partition-rust-mine-string-nonce.json", bad_mine)
bad_mine = mine_sidecar("rust", rust_rpc, rust_win_hash, rust_win_height); bad_mine["timestamp"] = "1"; dump(artifact_root / "partition-rust-mine-string-timestamp.json", bad_mine)
partition_observations = {"pre_partition": {"common_go_block": str(artifact_root / "partition-common-go-block.json"), "common_go_mine": str(artifact_root / "partition-common-go-mine.json"), "common_rust_block": str(artifact_root / "partition-common-rust-block.json"), "common_rust_tip": str(artifact_root / "partition-common-rust-tip.json"), "go_peer_snapshot": str(artifact_root / "partition-pre-go-peers.json"), "rust_peer_snapshot": str(artifact_root / "partition-pre-rust-peers.json")}, "partition": {"go_peer_snapshot": str(artifact_root / "partition-drop-go-peers.json"), "rust_peer_snapshot": str(artifact_root / "partition-drop-rust-peers.json")}, "fork": {"go_block": str(artifact_root / "partition-go-block.json"), "go_mine": str(artifact_root / "partition-go-mine.json"), "go_peer_snapshot": str(artifact_root / "partition-fork-go-peers.json"), "go_tip": str(artifact_root / "partition-go-tip.json"), "rust_block_1": str(artifact_root / "partition-rust-block-1.json"), "rust_block_2": str(artifact_root / "partition-rust-block-2.json"), "rust_mine_1": str(artifact_root / "partition-rust-mine-1.json"), "rust_mine_2": str(artifact_root / "partition-rust-mine-2.json"), "rust_peer_snapshot": str(artifact_root / "partition-fork-rust-peers.json"), "rust_tip": str(artifact_root / "partition-rust-tip.json")}, "heal": {"go_peer_snapshot": str(artifact_root / "partition-heal-go-peers.json"), "rust_peer_snapshot": str(artifact_root / "partition-heal-rust-peers.json")}, "reorg": {"go_metrics": str(artifact_root / "partition-go-metrics.prom"), "go_reorg_parent_block": str(artifact_root / "partition-go-reorg-parent-block.json"), "go_tip": str(artifact_root / "partition-final-go-tip.json"), "go_tip_block": str(artifact_root / "partition-final-go-block.json"), "rust_tip": str(artifact_root / "partition-final-rust-tip.json"), "rust_tip_block": str(artifact_root / "partition-final-rust-block.json")}}
partition_legacy = {"authoritative": False, "marker_path": str(mesh_marker), "purpose": "schema-valid legacy artifact only; not the partition/heal/reorg report verdict", "reason": "existing mixed_client_evidence_v1 PASS requires tx_path; partition/heal/reorg PASS lives in this report"}
partition_report = {**mesh_report, "artifact_created_at_utc": "2026-05-12T10:00:02Z", "final_verification": partition_final, "legacy_schema_compatibility": partition_legacy, "nodes": partition_nodes, "observations": partition_observations, "peer_connectivity": partition_peer_connectivity, "proof": {"final_go_tip": {"height": rust_win_height, "hash": rust_win_hash}, "final_rust_tip": {"height": rust_win_height, "hash": rust_win_hash}, "fork_diverged": True, "go_partition_tip": {"height": height, "hash": block_hash}, "go_reorg_metrics": {"rubin_node_last_reorg_depth": 0, "rubin_node_reorg_total": 1}, "heal_go_peer_addr": partition_go_peer, "heal_restored_peer_state": True, "partition_changed_peer_state": True, "partition_proxy_endpoint": partition_proxy, "pre_partition_go_peer_addr": partition_go_peer, "process_identity_rechecked_after_heal": True, "reorg_converged": True, "rust_winning_tip": {"height": rust_win_height, "hash": rust_win_hash}}, "run_id": artifact_root.name, "scenario": "mixed_client_partition_heal_reorg"}
dump(root / "partition-report.json", partition_report)
positive_partition = json.loads(json.dumps(partition_report)); positive_partition["proof"]["go_reorg_metrics"]["rubin_node_last_reorg_depth"] = 1; positive_partition["observations"]["reorg"]["go_metrics"] = str(artifact_root / "partition-go-metrics-depth-1.prom"); dump(artifact_root / "partition-positive-depth-report.json", positive_partition)
for depth in (0, 1):
    metrics_path = artifact_root / f"partition-zero-total-depth-{depth}.prom"; metrics_path.write_text(f"rubin_node_reorg_total 0\nrubin_node_last_reorg_depth {depth}\n", encoding="utf-8")
    bad_partition = json.loads(json.dumps(positive_partition if depth else partition_report)); bad_partition["proof"]["go_reorg_metrics"]["rubin_node_reorg_total"] = 0; bad_partition["observations"]["reorg"]["go_metrics"] = str(metrics_path); dump(artifact_root / f"partition-zero-total-depth-{depth}-report.json", bad_partition)
bad_partition = json.loads(json.dumps(partition_report)); del bad_partition["raw_samples"]; dump(artifact_root / "partition-missing-raw-samples-report.json", bad_partition)
bad_partition = json.loads(json.dumps(partition_report)); del bad_partition["nodes"][0]["process_alive"]; dump(artifact_root / "partition-missing-process-alive-report.json", bad_partition)
bad_partition = json.loads(json.dumps(partition_report)); bad_partition["unexpected_pass_evidence"] = True; dump(artifact_root / "partition-extra-top-level-report.json", bad_partition)
bad_partition = json.loads(json.dumps(partition_report)); bad_partition["legacy_schema_compatibility"]["purpose"] = "schema-valid legacy artifact only; not the mesh report verdict"; dump(artifact_root / "partition-stale-legacy-purpose-report.json", bad_partition)
bad_partition = json.loads(json.dumps(partition_report)); bad_partition["legacy_schema_compatibility"]["unexpected"] = True; dump(artifact_root / "partition-extra-legacy-key-report.json", bad_partition)
bad_partition = json.loads(json.dumps(partition_report)); bad_partition["observations"]["reorg"]["go_reorg_parent_block"] = str(artifact_root / "partition-go-losing-reorg-parent-block.json"); dump(root / "partition-losing-parent-report.json", bad_partition)
bad_partition = json.loads(json.dumps(partition_report)); bad_partition["observations"]["reorg"]["go_reorg_parent_block"] = str(artifact_root / "partition-go-reorg-parent-forged-block.json"); dump(root / "partition-forged-parent-payload-report.json", bad_partition)
bad_partition = json.loads(json.dumps(partition_report)); bad_partition["proof"]["rust_winning_tip"] = {"height": height, "hash": missing_tx_hash}; bad_partition["proof"]["final_go_tip"] = {"height": height, "hash": missing_tx_hash}; bad_partition["proof"]["final_rust_tip"] = {"height": height, "hash": missing_tx_hash}; dump(root / "partition-same-height-winner-report.json", bad_partition)
bad_partition = json.loads(json.dumps(partition_report)); bad_partition["peer_connectivity"]["bidirectional_observed"] = True; dump(root / "partition-peer-connectivity-overclaim-report.json", bad_partition)
bad_partition = json.loads(json.dumps(partition_report)); bad_partition["peer_connectivity"]["go_peer_snapshot"]["count"] = False; dump(artifact_root / "partition-peer-connectivity-bool-count-report.json", bad_partition)
bad_partition = json.loads(json.dumps(partition_report)); bad_partition["final_verification"]["rust_outbound_link_rechecked"] = True; dump(root / "partition-final-verification-overclaim-report.json", bad_partition)
bad_partition = json.loads(json.dumps(partition_report)); bad_partition["nodes"][0]["rpc_endpoint_process_backed"] = False; dump(artifact_root / "partition-unbacked-node-report.json", bad_partition)
bad_partition = json.loads(json.dumps(partition_report)); bad_partition["nodes"][1]["command_argv"][-2] = go_p2p; bad_partition["nodes"][1]["command"] = " ".join(bad_partition["nodes"][1]["command_argv"]); dump(artifact_root / "partition-rust-peer-argv-mismatch-report.json", bad_partition)
bad_partition = json.loads(json.dumps(partition_report)); bad_partition["proof"]["partition_proxy_endpoint"] = go_p2p; bad_partition["nodes"][1]["command_argv"][-2] = go_p2p; bad_partition["nodes"][1]["command"] = " ".join(bad_partition["nodes"][1]["command_argv"]); bad_partition["observations"]["pre_partition"]["rust_peer_snapshot"] = str(artifact_root / "partition-direct-pre-rust-peers.json"); bad_partition["observations"]["heal"]["rust_peer_snapshot"] = str(artifact_root / "partition-direct-heal-rust-peers.json"); dump(artifact_root / "partition-direct-proxy-report.json", bad_partition)
bad_partition = json.loads(json.dumps(partition_report)); bad_partition["proof"]["go_partition_tip"] = {"height": height, "hash": disconnected_go_hash}; bad_partition["observations"]["fork"]["go_mine"] = str(artifact_root / "partition-go-disconnected-mine.json"); bad_partition["observations"]["fork"]["go_tip"] = str(artifact_root / "partition-go-disconnected-tip.json"); bad_partition["observations"]["fork"]["go_block"] = str(artifact_root / "partition-go-disconnected-block.json"); dump(root / "partition-disconnected-go-fork-report.json", bad_partition)
bad_partition = json.loads(json.dumps(partition_report)); bad_partition["observations"]["fork"]["rust_mine_1"] = str(artifact_root / "partition-rust-same-fork-mine.json"); bad_partition["observations"]["fork"]["rust_block_1"] = str(artifact_root / "partition-rust-same-fork-block.json"); dump(root / "partition-same-first-rust-fork-report.json", bad_partition)
bad_partition = json.loads(json.dumps(partition_report)); bad_partition["proof"]["rust_winning_tip"] = {"height": rust_skip_height, "hash": rust_skip_hash}; bad_partition["proof"]["final_go_tip"] = {"height": rust_skip_height, "hash": rust_skip_hash}; bad_partition["proof"]["final_rust_tip"] = {"height": rust_skip_height, "hash": rust_skip_hash}; bad_partition["observations"]["fork"]["rust_mine_2"] = str(artifact_root / "partition-rust-skip-mine.json"); bad_partition["observations"]["fork"]["rust_tip"] = str(artifact_root / "partition-rust-skip-tip.json"); bad_partition["observations"]["fork"]["rust_block_2"] = str(artifact_root / "partition-rust-skip-block.json"); bad_partition["observations"]["reorg"]["go_tip"] = str(artifact_root / "partition-final-go-skip-tip.json"); bad_partition["observations"]["reorg"]["rust_tip"] = str(artifact_root / "partition-final-rust-skip-tip.json"); bad_partition["observations"]["reorg"]["go_tip_block"] = str(artifact_root / "partition-final-go-skip-block.json"); bad_partition["observations"]["reorg"]["rust_tip_block"] = str(artifact_root / "partition-final-rust-skip-block.json"); dump(artifact_root / "partition-skip-height-rust-winner-report.json", bad_partition)
bad_partition = json.loads(json.dumps(partition_report)); bad_partition["proof"]["go_reorg_metrics"]["rubin_node_reorg_total"] = 2; dump(artifact_root / "partition-forged-metrics-report.json", bad_partition)
bad_partition = json.loads(json.dumps(partition_report)); bad_partition["observations"]["pre_partition"]["rust_peer_snapshot"] = str(artifact_root / "partition-pre-rust-peers-bool-count.json"); dump(artifact_root / "partition-peer-sidecar-bool-count-report.json", bad_partition)
bad_partition = json.loads(json.dumps(partition_report)); bad_partition["observations"]["pre_partition"]["rust_peer_snapshot"] = str(artifact_root / "partition-pre-rust-peers-extra-field.json"); dump(artifact_root / "partition-peer-sidecar-extra-field-report.json", bad_partition)
bad_partition = json.loads(json.dumps(partition_report)); bad_partition["observations"]["fork"]["rust_tip"] = str(artifact_root / "partition-rust-tip-float-height.json"); dump(artifact_root / "partition-rust-tip-float-height-report.json", bad_partition)
bad_partition = json.loads(json.dumps(partition_report)); bad_partition["observations"]["reorg"]["go_tip"] = str(artifact_root / "partition-final-go-tip-string-ibd.json"); dump(artifact_root / "partition-go-tip-string-ibd-report.json", bad_partition)
bad_partition = json.loads(json.dumps(partition_report)); bad_partition["observations"]["fork"]["rust_mine_2"] = str(artifact_root / "partition-rust-mine-string-nonce.json"); dump(artifact_root / "partition-rust-mine-string-nonce-report.json", bad_partition)
bad_partition = json.loads(json.dumps(partition_report)); bad_partition["observations"]["fork"]["rust_mine_2"] = str(artifact_root / "partition-rust-mine-string-timestamp.json"); dump(artifact_root / "partition-rust-mine-string-timestamp-report.json", bad_partition)
bad_partition = json.loads(json.dumps(partition_report)); bad_partition["observations"]["reorg"]["go_metrics"] = str(artifact_root / "partition-go-metrics-timestamp.prom"); dump(artifact_root / "partition-metrics-timestamp-report.json", bad_partition)
bad_partition = json.loads(json.dumps(partition_report)); bad_partition["observations"]["reorg"]["go_metrics"] = str(artifact_root / "partition-go-metrics.json"); dump(artifact_root / "partition-metrics-json-report.json", bad_partition)
tx_report = {
    **mesh_report,
    "nodes": [node("go", False), node("rust", True)],
    "go_submit": {
        "get_tx_path": str(artifact_root / "go-get-tx.json"),
        "rpc_endpoint": go_rpc,
        "tx_hex": tx_hex,
        "tx_status_path": str(artifact_root / "go-tx-status.json"),
        "txid": txid,
    },
    "legacy_schema_compatibility": {**mesh_report["legacy_schema_compatibility"], "marker_path": str(tx_marker)},
    "raw_samples": raw_samples(prop_direction="go->rust", prop_elapsed=2),
    "rust_accept": {
        "get_tx_path": str(artifact_root / "rust-get-tx.json"),
        "raw_hex": tx_hex,
        "rpc_endpoint": rust_rpc,
        "tx_status_path": str(artifact_root / "rust-tx-status.json"),
        "txid": txid,
    },
    "scenario": "mixed_client_go_submit_rust_accept",
    "tx_path": tx_path,
}
dump(root / "tx-report.json", tx_report)
dump(root / "tx-rust-without-create-report.json", {**tx_report, "nodes": [node("go", False), node("rust", False)]})
dump(root / "tx-go-with-create-report.json", {**tx_report, "nodes": [node("go", True), node("rust", True)]})
dump(root / "mesh-rust-without-create-report.json", {**mesh_report, "nodes": [node("go", True), node("rust", False)]})
dump(root / "restart-old-without-create-report.json", {**restart_report, "rust_restart": {**restart_info, "old_command_argv": node("rust", False)["command_argv"]}})
dump(root / "restart-new-with-create-report.json", {**restart_report, "nodes": [node("go", False), node("rust", True)], "rust_restart": {**restart_info, "new_command_argv": node("rust", True)["command_argv"]}})
bad_partition = json.loads(json.dumps(partition_report)); del bad_partition["nodes"][1]["command_argv"][-1]; bad_partition["nodes"][1]["command"] = " ".join(bad_partition["nodes"][1]["command_argv"]); dump(root / "partition-rust-without-create-report.json", bad_partition)
converge_report = {
    **tx_report,
    "go_converge": {
        "block_hash": block_hash,
        "block_path": str(artifact_root / "go-converged-block.json"),
        "class": "canonical_block_found",
        "converged_at": "node-go",
        "height": height,
        "raw_hex": tx_hex,
        "rpc_endpoint": go_rpc,
        "tip_path": str(artifact_root / "go-converge-tip.json"),
        "txid": txid,
    },
    "raw_samples": raw_samples(prop_direction="go->rust", prop_elapsed=2, conv_direction="rust->go", conv_elapsed=4),
    "rust_mine": {
        "block_hash": block_hash,
        "block_path": str(artifact_root / "rust-mined-block.json"),
        "class": "mined_included",
        "height": height,
        "mine_next_path": str(artifact_root / "rust-mine-next.json"),
        "mined_by": "node-rust",
        "raw_hex": tx_hex,
        "rpc_endpoint": rust_rpc,
        "tx_count": tx_count,
        "txid": txid,
    },
    "scenario": "mixed_client_go_submit_rust_mine_go_converge",
}
dump(root / "converge-report.json", converge_report)
rust_tx_marker = artifact_root / "rust-submit-tx-marker.json"
rust_tx_path = {"observed_at": ["node-go"], "submitted_at": "node-rust", "tx_id": txid}
dump(rust_tx_marker, {
    "evidence_type": "mixed_client_process_soak",
    "participants": [
        {"endpoint": go_rpc, "implementation": "go", "name": "node-go", "started_at": go_started},
        {"endpoint": rust_rpc, "implementation": "rust", "name": "node-rust", "started_at": rust_started},
    ],
    "scenario": "mixed_client_mesh_schema_marker",
    "schema_version": "rubin-mixed-client-devnet-evidence-v1",
    "tx_path": rust_tx_path,
    "verdict": "PASS",
})
rust_converge_report = {
    **mesh_report,
    "nodes": [node("go", False), node("rust", True)],
    "go_accept": {
        "get_tx_path": str(artifact_root / "go-accept-get-tx.json"),
        "raw_hex": tx_hex,
        "rpc_endpoint": go_rpc,
        "tx_status_path": str(artifact_root / "go-accept-tx-status.json"),
        "txid": txid,
    },
    "go_mine": {
        "block_hash": block_hash,
        "block_path": str(artifact_root / "go-mined-block.json"),
        "class": "mined_included",
        "height": height,
        "mine_next_path": str(artifact_root / "go-mine-next.json"),
        "mined_by": "node-go",
        "raw_hex": tx_hex,
        "rpc_endpoint": go_rpc,
        "tx_count": tx_count,
        "txid": txid,
    },
    "legacy_schema_compatibility": {**mesh_report["legacy_schema_compatibility"], "marker_path": str(rust_tx_marker)},
    "raw_samples": raw_samples(prop_direction="rust->go", prop_elapsed=2, conv_direction="go->rust", conv_elapsed=4),
    "rust_converge": {
        "block_hash": block_hash,
        "block_path": str(artifact_root / "rust-converged-block.json"),
        "class": "canonical_block_found",
        "converged_at": "node-rust",
        "height": height,
        "raw_hex": tx_hex,
        "rpc_endpoint": rust_rpc,
        "tip_path": str(artifact_root / "rust-converge-tip.json"),
        "txid": txid,
    },
    "rust_submit": {
        "get_tx_path": str(artifact_root / "rust-submit-get-tx.json"),
        "rpc_endpoint": rust_rpc,
        "tx_hex": tx_hex,
        "tx_status_path": str(artifact_root / "rust-submit-tx-status.json"),
        "txid": txid,
    },
    "scenario": "mixed_client_rust_submit_go_mine_rust_converge",
    "tx_path": rust_tx_path,
}
dump(root / "rust-submit-go-mine-report.json", rust_converge_report)
bad_tx_samples = json.loads(json.dumps(tx_report))
bad_tx_samples["raw_samples"]["propagation"]["samples"] = []
dump(root / "tx-missing-propagation-samples.json", bad_tx_samples)
bad_tx_samples = json.loads(json.dumps(tx_report))
bad_tx_samples["raw_samples"]["propagation"]["samples"][0]["elapsed"] = "__NONFINITE_ELAPSED__"
nonfinite_json = json.dumps(bad_tx_samples, indent=2, sort_keys=True).replace('"__NONFINITE_ELAPSED__"', '1e309', 1) + "\n"
(root / "tx-nonfinite-propagation-sample.json").write_text(nonfinite_json, encoding="utf-8")
bad_tx_samples = json.loads(json.dumps(tx_report))
bad_tx_samples["raw_samples"]["propagation"]["samples"][0]["elapsed"] = 10 ** 400
dump(root / "tx-huge-int-propagation-sample.json", bad_tx_samples)
bad_tx_samples = json.loads(json.dumps(tx_report))
bad_tx_samples["raw_samples"]["propagation"]["p90_seconds"] = 2
dump(root / "tx-slo-claim-sample.json", bad_tx_samples)
bad_converge_samples = json.loads(json.dumps(converge_report))
bad_converge_samples["raw_samples"]["convergence"]["samples"] = []
dump(root / "converge-missing-convergence-samples.json", bad_converge_samples)
bad_converge_samples = json.loads(json.dumps(converge_report))
bad_converge_samples["raw_samples"]["convergence"]["samples"][0]["height"] = True
dump(root / "converge-bool-height-sample.json", bad_converge_samples)
bad_converge_samples = json.loads(json.dumps(converge_report))
bad_converge_samples["raw_samples"]["convergence"]["samples"][0]["height"] = 1.0
dump(root / "converge-float-height-sample.json", bad_converge_samples)
bad_converge_samples = json.loads(json.dumps(converge_report))
bad_converge_samples["raw_samples"]["convergence"]["samples"][0]["block_hash"] = block_hash.upper()
dump(root / "converge-uppercase-block-hash-sample.json", bad_converge_samples)
bad_mesh_samples = json.loads(json.dumps(mesh_report))
bad_mesh_samples["raw_samples"]["propagation"]["reason"] = "p90_seconds_slo_passed"
dump(root / "mesh-bad-propagation-not-requested-reason.json", bad_mesh_samples)
bad_mesh_samples = json.loads(json.dumps(mesh_report))
bad_mesh_samples["raw_samples"]["convergence"]["reason"] = "latency_threshold_passed"
dump(root / "mesh-bad-convergence-not-requested-reason.json", bad_mesh_samples)
bad_restart = json.loads(json.dumps(restart_report))
del bad_restart["restart"]
dump(root / "restart-missing-restart-object.json", bad_restart)
bad_restart = json.loads(json.dumps(restart_report))
del bad_restart["rust_restart"]
dump(root / "restart-missing-process-object.json", bad_restart)
bad_restart = json.loads(json.dumps(restart_report))
bad_restart["rust_restart"]["old_pid"] = bad_restart["rust_restart"]["new_pid"]
dump(root / "restart-same-pid.json", bad_restart)
bad_restart = json.loads(json.dumps(restart_report))
bad_restart["rust_restart"]["old_pid"] = bad_restart["nodes"][0]["pid"]
dump(root / "restart-old-pid-alias-go.json", bad_restart)
bad_restart = json.loads(json.dumps(restart_report))
bad_restart["rust_restart"]["old_pid_stopped"] = False
dump(root / "restart-old-pid-not-stopped.json", bad_restart)
bad_restart = json.loads(json.dumps(restart_report))
bad_restart["rust_restart"]["peer_reconnect_observed"] = False
dump(root / "restart-no-peer-reconnect.json", bad_restart)
bad_restart = json.loads(json.dumps(restart_report))
bad_restart["rust_restart"]["same_datadir"] = False
dump(root / "restart-same-datadir-false.json", bad_restart)
bad_restart = json.loads(json.dumps(restart_report))
bad_restart["rust_restart"]["datadir"] = str(artifact_root / "node-rust-other")
dump(root / "restart-datadir-mismatch.json", bad_restart)
(artifact_root / "node-rust-link").symlink_to(artifact_root / "node-rust", target_is_directory=True)
bad_restart = json.loads(json.dumps(restart_report))
bad_restart["rust_restart"]["datadir"] = str(artifact_root / "node-rust-link")
dump(root / "restart-datadir-symlink.json", bad_restart)
bad_restart = json.loads(json.dumps(restart_report))
bad_restart["rust_restart"]["datadir"] = "node-rust"
dump(root / "restart-datadir-relative.json", bad_restart)
bad_restart = json.loads(json.dumps(restart_report))
bad_restart["nodes"][0]["unexpected_evidence"] = "must not pass"
dump(root / "restart-node-extra-field.json", bad_restart)
bad_restart = json.loads(json.dumps(restart_report))
bad_restart["run_id"] = ""
dump(root / "restart-stale-run-id.json", bad_restart)
bad_restart = json.loads(json.dumps(restart_report))
bad_restart["run_id"] = "stale-but-nonempty"
dump(root / "restart-stale-run-id-mismatch.json", bad_restart)
bad_restart = json.loads(json.dumps(restart_report))
bad_restart["artifact_created_at_utc"] = ""
dump(root / "restart-stale-artifact-created-at.json", bad_restart)
bad_restart = json.loads(json.dumps(restart_report))
bad_restart["restart"]["catch_up_height"] = 106
bad_restart["rust_restart"]["catch_up_height"] = 106
below_pre_restart_marker = artifact_root / "restart-below-pre-restart-marker.json"
dump(below_pre_restart_marker, {
    "evidence_type": "mixed_client_process_soak",
    "failure_reason": "schema v1 PASS requires tx_path; restart PASS lives in sibling report",
    "participants": [
        {"endpoint": go_rpc, "implementation": "go", "name": "node-go", "started_at": go_started},
        {"endpoint": rust_rpc, "implementation": "rust", "name": "node-rust", "started_at": rust_started},
    ],
    "restart": bad_restart["restart"],
    "scenario": "mixed_client_mesh_schema_marker",
    "schema_version": "rubin-mixed-client-devnet-evidence-v1",
    "verdict": "FAIL",
})
bad_restart["legacy_schema_compatibility"]["marker_path"] = str(below_pre_restart_marker)
dump(root / "restart-catch-up-below-pre-restart.json", bad_restart)
bad_restart = json.loads(json.dumps(restart_report))
bad_restart["restart"]["catch_up_height"] = 107
bad_restart["rust_restart"]["catch_up_height"] = 107
stale_restart_marker = artifact_root / "restart-stale-marker.json"
dump(stale_restart_marker, {
    "evidence_type": "mixed_client_process_soak",
    "failure_reason": "schema v1 PASS requires tx_path; restart PASS lives in sibling report",
    "participants": [
        {"endpoint": go_rpc, "implementation": "go", "name": "node-go", "started_at": go_started},
        {"endpoint": rust_rpc, "implementation": "rust", "name": "node-rust", "started_at": rust_started},
    ],
    "restart": bad_restart["restart"],
    "scenario": "mixed_client_mesh_schema_marker",
    "schema_version": "rubin-mixed-client-devnet-evidence-v1",
    "verdict": "FAIL",
})
bad_restart["legacy_schema_compatibility"]["marker_path"] = str(stale_restart_marker)
dump(root / "restart-stale-catch-up.json", bad_restart)
bad_restart = json.loads(json.dumps(restart_report))
bad_restart["legacy_schema_compatibility"]["marker_path"] = str(mesh_marker)
dump(root / "restart-legacy-marker-mismatch.json", bad_restart)
bad_restart = json.loads(json.dumps(restart_report))
bad_restart["rust_restart"]["new_pid"] = 41099
dump(root / "restart-new-pid-not-final.json", bad_restart)
bad_restart = json.loads(json.dumps(restart_report))
bad_restart["rust_restart"]["pre_restart_has_tip"] = False
bad_restart["rust_restart"]["pre_restart_tip"] = None
dump(root / "restart-pre-tip-absent.json", bad_restart)
bad_restart = json.loads(json.dumps(restart_report))
bad_restart["rust_restart"]["catch_up_has_tip"] = False
bad_restart["rust_restart"]["catch_up_tip"] = None
dump(root / "restart-catch-up-tip-absent.json", bad_restart)
bad_restart = json.loads(json.dumps(restart_report))
bad_restart["rust_restart"]["go_target_height"] = 7
dump(root / "restart-go-target-not-advanced.json", bad_restart)
bad_restart = json.loads(json.dumps(restart_report))
bad_restart["rust_restart"]["pre_restart_height"] = "107"
dump(root / "restart-pre-restart-height-string.json", bad_restart)
bad_restart = json.loads(json.dumps(restart_report))
bad_restart["rust_restart"]["go_target_height"] = "108"
dump(root / "restart-go-target-height-string.json", bad_restart)
bad_restart = json.loads(json.dumps(restart_report))
bad_restart["rust_restart"]["catch_up_height"] = "108"
dump(root / "restart-catch-up-height-string.json", bad_restart)
bad_restart = json.loads(json.dumps(restart_report))
bad_restart["rust_restart"]["pre_restart_height"] = True
dump(root / "restart-pre-restart-height-bool.json", bad_restart)
bad_restart = json.loads(json.dumps(restart_report))
bad_restart["rust_restart"]["go_target_height"] = True
dump(root / "restart-go-target-height-bool.json", bad_restart)
bad_restart = json.loads(json.dumps(restart_report))
bad_restart["rust_restart"]["catch_up_height"] = True
dump(root / "restart-catch-up-height-bool.json", bad_restart)
bad_restart = json.loads(json.dumps(restart_report))
bad_restart["rust_restart"]["catch_up_tip"] = "cc" * 32
dump(root / "restart-catch-up-tip-mismatch.json", bad_restart)
bad_restart = json.loads(json.dumps(restart_report))
bad_restart["legacy_schema_compatibility"]["purpose"] = "schema-valid legacy artifact only; not the mesh report verdict"
bad_restart["legacy_schema_compatibility"]["reason"] = "existing mixed_client_evidence_v1 PASS requires tx_path; RUB-21 mesh-only PASS lives in this report"
dump(root / "restart-stale-legacy-text.json", bad_restart)
bad_sidecar = {"best_known_height": 107, "has_tip": True, "height": 107.0, "implementation": "rust", "in_ibd": False, "request_path": "/get_tip", "rpc_endpoint": rust_rpc, "tip_hash": "aa" * 32}
dump(artifact_root / "rust-pre-restart-tip-float-height.json", bad_sidecar)
bad_restart = json.loads(json.dumps(restart_report))
bad_restart["rust_restart"]["pre_restart_tip_path"] = str(artifact_root / "rust-pre-restart-tip-float-height.json")
dump(root / "restart-pre-tip-sidecar-float-height.json", bad_restart)
bad_sidecar = {"best_known_height": 108, "has_tip": True, "height": 108.0, "implementation": "rust", "in_ibd": False, "request_path": "/get_tip", "rpc_endpoint": rust_rpc, "tip_hash": "bb" * 32}
dump(artifact_root / "rust-catch-up-tip-float-height.json", bad_sidecar)
bad_restart = json.loads(json.dumps(restart_report))
bad_restart["rust_restart"]["catch_up_tip_path"] = str(artifact_root / "rust-catch-up-tip-float-height.json")
dump(root / "restart-catch-up-tip-sidecar-float-height.json", bad_restart)
bad_sidecar = {"best_known_height": 0, "has_tip": True, "height": 107, "implementation": "rust", "in_ibd": False, "request_path": "/get_tip", "rpc_endpoint": rust_rpc, "tip_hash": "aa" * 32}
dump(artifact_root / "rust-pre-restart-tip-low-best-known.json", bad_sidecar)
bad_restart = json.loads(json.dumps(restart_report))
bad_restart["rust_restart"]["pre_restart_tip_path"] = str(artifact_root / "rust-pre-restart-tip-low-best-known.json")
dump(root / "restart-pre-tip-sidecar-low-best-known.json", bad_restart)
bad_sidecar = {"best_known_height": 0, "has_tip": True, "height": 108, "implementation": "go", "in_ibd": False, "request_path": "/get_tip", "rpc_endpoint": go_rpc, "tip_hash": "bb" * 32}
dump(artifact_root / "go-restart-target-tip-low-best-known.json", bad_sidecar)
bad_restart = json.loads(json.dumps(restart_report))
bad_restart["rust_restart"]["go_target_tip_path"] = str(artifact_root / "go-restart-target-tip-low-best-known.json")
dump(root / "restart-go-target-tip-sidecar-low-best-known.json", bad_restart)
bad_sidecar = {"best_known_height": 0, "has_tip": True, "height": 108, "implementation": "rust", "in_ibd": False, "request_path": "/get_tip", "rpc_endpoint": rust_rpc, "tip_hash": "bb" * 32}
dump(artifact_root / "rust-catch-up-tip-low-best-known.json", bad_sidecar)
bad_restart = json.loads(json.dumps(restart_report))
bad_restart["rust_restart"]["catch_up_tip_path"] = str(artifact_root / "rust-catch-up-tip-low-best-known.json")
dump(root / "restart-catch-up-tip-sidecar-low-best-known.json", bad_restart)
bad_sidecar = {"best_known_height": 108, "has_tip": True, "height": 108.0, "implementation": "go", "in_ibd": False, "request_path": "/get_tip", "rpc_endpoint": go_rpc, "tip_hash": "bb" * 32}
dump(artifact_root / "go-restart-target-tip-float-height.json", bad_sidecar)
bad_restart = json.loads(json.dumps(restart_report))
bad_restart["rust_restart"]["go_target_tip_path"] = str(artifact_root / "go-restart-target-tip-float-height.json")
dump(root / "restart-go-target-tip-float-height.json", bad_restart)
bad_mine_next = {"block_hash": "bb" * 32, "height": 108, "implementation": "go", "mined": True, "nonce": 0, "request_path": "/mine_next", "rpc_endpoint": go_rpc, "timestamp": 1, "tx_count": True, "commit_state": "committed"}
dump(artifact_root / "go-restart-mine-next-bool-tx-count.json", bad_mine_next)
bad_restart = json.loads(json.dumps(restart_report))
bad_restart["rust_restart"]["go_target_mine_next_path"] = str(artifact_root / "go-restart-mine-next-bool-tx-count.json")
dump(root / "restart-go-target-mine-bool-tx-count.json", bad_restart)
bad_rust_converge = json.loads(json.dumps(rust_converge_report))
bad_rust_converge["rust_converge"]["txid"] = "11" * 32
dump(root / "rust-submit-go-mine-wrong-txid.json", bad_rust_converge)
bad_rust_converge = json.loads(json.dumps(rust_converge_report))
bad_rust_converge["go_mine"]["class"] = "accepted_only"
dump(root / "rust-submit-go-mine-bad-go-class.json", bad_rust_converge)
bad_rust_converge = json.loads(json.dumps(rust_converge_report))
bad_rust_converge["rust_converge"]["class"] = "accepted_only"
dump(root / "rust-submit-go-mine-bad-rust-converge-class.json", bad_rust_converge)
bad_rust_converge = json.loads(json.dumps(rust_converge_report))
bad_rust_converge["rust_converge"]["block_path"] = str(artifact_root / "go-mined-block.json")
dump(root / "rust-submit-go-mine-duplicate-sidecar-path.json", bad_rust_converge)
bad_rust_converge = json.loads(json.dumps(rust_converge_report))
bad_rust_converge["rust_converge"]["block_path"] = str(artifact_root / "rust-converged-wrong-source-block.json")
dump(root / "rust-submit-go-mine-wrong-sidecar-source.json", bad_rust_converge)
bad_rust_converge = json.loads(json.dumps(rust_converge_report))
bad_rust_converge["rust_converge"]["block_path"] = str(artifact_root / "rust-converged-malformed-block.json")
dump(root / "rust-submit-go-mine-malformed-block.json", bad_rust_converge)
bad_rust_converge = json.loads(json.dumps(rust_converge_report))
bad_rust_converge["go_mine"]["block_hash"] = missing_tx_hash
bad_rust_converge["go_mine"]["block_path"] = str(artifact_root / "go-missing-tx-block.json")
bad_rust_converge["go_mine"]["mine_next_path"] = str(artifact_root / "go-missing-tx-mine-next.json")
bad_rust_converge["rust_converge"]["block_hash"] = missing_tx_hash
bad_rust_converge["rust_converge"]["block_path"] = str(artifact_root / "rust-converged-missing-tx-block.json")
bad_rust_converge["rust_converge"]["tip_path"] = str(artifact_root / "rust-missing-tx-tip.json")
dump(root / "rust-submit-go-mine-missing-tx-block.json", bad_rust_converge)
bad_converge = json.loads(json.dumps(converge_report))
bad_converge["go_converge"]["txid"] = "11" * 32
dump(root / "converge-wrong-txid.json", bad_converge)
bad_converge = json.loads(json.dumps(converge_report))
bad_converge["rust_mine"]["class"] = "accepted_only"
dump(root / "converge-bad-rust-class.json", bad_converge)
bad_converge = json.loads(json.dumps(converge_report))
bad_converge["go_converge"]["block_path"] = str(artifact_root / "rust-mined-block.json")
dump(root / "converge-duplicate-sidecar-path.json", bad_converge)
bad_converge = json.loads(json.dumps(converge_report))
bad_converge["go_converge"]["block_path"] = str(artifact_root / "go-converged-wrong-source-block.json")
dump(root / "converge-wrong-sidecar-source.json", bad_converge)
bad_converge = json.loads(json.dumps(converge_report))
bad_converge["go_converge"]["block_path"] = str(artifact_root / "go-converged-malformed-block.json")
dump(root / "converge-malformed-block.json", bad_converge)
bad_converge = json.loads(json.dumps(converge_report))
bad_converge["rust_mine"]["block_hash"] = missing_tx_hash
bad_converge["rust_mine"]["block_path"] = str(artifact_root / "rust-missing-tx-block.json")
bad_converge["rust_mine"]["mine_next_path"] = str(artifact_root / "rust-missing-tx-mine-next.json")
bad_converge["go_converge"]["block_hash"] = missing_tx_hash
bad_converge["go_converge"]["block_path"] = str(artifact_root / "go-converged-missing-tx-block.json")
bad_converge["go_converge"]["tip_path"] = str(artifact_root / "go-missing-tx-tip.json")
dump(root / "converge-missing-tx-block.json", bad_converge)
bad_converge = json.loads(json.dumps(converge_report))
bad_converge["rust_mine"]["block_hash"] = corrupt_block_hash
bad_converge["rust_mine"]["block_path"] = str(artifact_root / "rust-corrupt-merkle-block.json")
bad_converge["rust_mine"]["mine_next_path"] = str(artifact_root / "rust-corrupt-merkle-mine-next.json")
bad_converge["go_converge"]["block_hash"] = corrupt_block_hash
bad_converge["go_converge"]["block_path"] = str(artifact_root / "go-corrupt-merkle-block.json")
bad_converge["go_converge"]["tip_path"] = str(artifact_root / "go-corrupt-merkle-tip.json")
dump(root / "converge-bad-merkle-block.json", bad_converge)
bad_converge = json.loads(json.dumps(converge_report))
bad_converge["rust_mine"]["tx_count"] = 3
bad_converge["rust_mine"]["mine_next_path"] = str(artifact_root / "rust-tx-count-mismatch-mine-next.json")
dump(root / "converge-tx-count-mismatch.json", bad_converge)
(root / "empty.json").write_text("", encoding="utf-8")
(root / "malformed.json").write_text("[", encoding="utf-8")
with (root / "oversized.json").open("wb") as f:
    f.write(b" " * 1_000_001)
mine_next_cases = (
    ("partition-go", "partition-common-go-mine.json", partition_report, ("observations", "pre_partition", "common_go_mine"), ("no-commit", "not-committed")),
    ("partition-rust", "partition-rust-mine-1.json", partition_report, ("observations", "fork", "rust_mine_1"), ("commit", "go-impl")),
    ("restart-go", "go-restart-mine-next.json", restart_report, ("rust_restart", "go_target_mine_next_path"), ("no-commit", "not-committed")),
    ("converge-rust", "rust-mine-next.json", converge_report, ("rust_mine", "mine_next_path"), ("commit", "go-impl")),
    ("rust-conv-go", "go-mine-next.json", rust_converge_report, ("go_mine", "mine_next_path"), ("no-commit", "not-committed")),
)
mine_next_edits = {
    "no-commit": lambda d: d.pop("commit_state"),
    "not-committed": lambda d: d.__setitem__("commit_state", "not_committed"),
    "commit": lambda d: d.__setitem__("commit_state", "committed"),
    "go-impl": lambda d: d.__setitem__("implementation", "go"),
}
for site, sidecar_name, base_report, field, variants in mine_next_cases:
    for variant in variants:
        sidecar = json.loads((artifact_root / sidecar_name).read_text(encoding="utf-8"))
        mine_next_edits[variant](sidecar)
        sidecar_path = artifact_root / f"mine-next-{site}-{variant}-sidecar.json"
        dump(sidecar_path, sidecar)
        bad = json.loads(json.dumps(base_report))
        target = bad
        for key in field[:-1]:
            target = target[key]
        target[field[-1]] = str(sidecar_path)
        dump(artifact_root / f"mine-next-{site}-{variant}.json", bad)
import shutil
SN_NAME = "mixed-client-mesh-store-neutrality.json"
SCENARIO_ROOTS = {"mixed_client_mesh": "mesh", "mixed_client_go_submit_rust_accept": "tx-accept", "mixed_client_go_submit_rust_mine_go_converge": "tx-converge", "mixed_client_rust_submit_go_mine_rust_converge": "rust-submit", "mixed_client_rust_restart": "restart", "mixed_client_partition_heal_reorg": "partition"}
old_root = str(artifact_root)
for report_path in sorted(root.rglob("*.json")):
    try:
        report_text = report_path.read_text(encoding="utf-8")
        report_obj = json.loads(report_text)
    except (UnicodeDecodeError, ValueError):
        continue
    if isinstance(report_obj, dict) and report_obj.get("artifact_root") == old_root and report_obj.get("scenario") in SCENARIO_ROOTS:
        mode_root = root / SCENARIO_ROOTS[report_obj["scenario"]] / "artifact-root"
        report_path.write_text(report_text.replace(old_root, str(mode_root)), encoding="utf-8")
genesis_header = (1).to_bytes(4, "little") + bytes(64) + (1).to_bytes(8, "little") + b"\xff" * 32 + (0).to_bytes(8, "little")
genesis_hex, genesis_hash = (genesis_header + bytes(40)).hex(), sha3(genesis_header).hex()
long_header = genesis_header + b"\x07" * 32
long_genesis_hex, long_genesis_hash = (long_header + bytes(8)).hex(), sha3(long_header).hex()
conv_hash = "cc" * 32
def sn_tip(impl: str, endpoint: str, chain: bool, tip_height: int = 101, tip_hash: str = conv_hash) -> dict:
    if not chain:
        return {"best_known_height": 0, "has_tip": False, "height": None, "implementation": impl, "in_ibd": True, "request_path": "/get_tip", "rpc_endpoint": endpoint, "tip_hash": None}
    return tip_sidecar(impl, endpoint, tip_hash, tip_height)
def write_store_neutrality(mode_root: Path, scenario: str) -> None:
    chain = scenario != "mixed_client_mesh"
    rust_endpoint = "127.0.0.1:51030" if scenario == "mixed_client_rust_restart" else rust_rpc
    (mode_root / "rubin-txgen").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    dump(mode_root / "initial-convergence-go-tip.json", sn_tip("go", go_rpc, chain))
    dump(mode_root / "initial-convergence-rust-tip.json", sn_tip("rust", rust_endpoint, chain))
    genesis = heights = None
    if chain:
        dump(mode_root / "genesis-go-block.json", {**block_sidecar("go", go_rpc, genesis_hex, genesis_hash, 0)})
        dump(mode_root / "genesis-rust-block.json", {**block_sidecar("rust", rust_endpoint, genesis_hex, genesis_hash, 0)})
        genesis = {"go_hash": genesis_hash, "rust_hash": genesis_hash, "go_block_path": str(mode_root / "genesis-go-block.json"), "rust_block_path": str(mode_root / "genesis-rust-block.json")}
        heights = {"go": 116, "rust": 116}
    dump(mode_root / SN_NAME, {
        "evidence_domain": "pre_switch_store_neutrality",
        "protocol_commit": "ab" * 20,
        "clients_tree_clean": True,
        "binaries": {"go_node_sha256": hashlib.sha256((mode_root / "rubin-node-go").read_bytes()).hexdigest(), "rust_node_sha256": hashlib.sha256((mode_root / "rubin-node-rust").read_bytes()).hexdigest(), "txgen_sha256": hashlib.sha256((mode_root / "rubin-txgen").read_bytes()).hexdigest() if chain else None},
        "chain_identity": {"network": "devnet", "chain_id_hex": "dd" * 32, "genesis_hash_hex": genesis_hash},
        "genesis": genesis,
        "header_bytes": heights,
        "datadirs": {"go": str(mode_root / "node-go"), "rust": str(mode_root / "node-rust"), "rust_exact_empty_before_first_start": True},
        "initial_convergence": {"go_has_tip": chain, "rust_has_tip": chain, "height": 101 if chain else None, "go_tip_hash": conv_hash if chain else None, "rust_tip_hash": conv_hash if chain else None, "go_tip_path": str(mode_root / "initial-convergence-go-tip.json"), "rust_tip_path": str(mode_root / "initial-convergence-rust-tip.json")},
    })
for scenario, name in SCENARIO_ROOTS.items():
    shutil.copytree(artifact_root, root / name / "artifact-root", symlinks=True)
    write_store_neutrality(root / name / "artifact-root", scenario)
SN_DELETE = object()
SN_BASE_REPORTS = {"mesh": root / "mesh-report.json", "tx-accept": root / "tx-report.json", "restart": root / "restart-report.json", "partition": root / "partition-report.json"}
def sn_variant(name: str, base: str, edit, report_edit=None) -> None:
    base_root = root / base / "artifact-root"
    var_root = root / f"sn-{name}" / "artifact-root"
    shutil.copytree(base_root, var_root, symlinks=True)
    report = json.loads(SN_BASE_REPORTS[base].read_text(encoding="utf-8").replace(str(base_root), str(var_root)))
    if report_edit is not None:
        report_edit(report)
    sidecar = json.loads((var_root / SN_NAME).read_text(encoding="utf-8").replace(str(base_root), str(var_root)))
    if edit(sidecar, var_root) is SN_DELETE:
        (var_root / SN_NAME).unlink()
    else:
        dump(var_root / SN_NAME, sidecar)
    dump(root / f"sn-{name}-report.json", report)
def sn_edit_file(var_root: Path, file_name: str, **changes) -> None:
    data = json.loads((var_root / file_name).read_text(encoding="utf-8"))
    data.update(changes)
    dump(var_root / file_name, data)
def sn_set_height(sidecar: dict, var_root: Path, value: int) -> None:
    sidecar["initial_convergence"]["height"] = value
    for file_name in ("initial-convergence-go-tip.json", "initial-convergence-rust-tip.json"):
        sn_edit_file(var_root, file_name, height=value, best_known_height=value)
def sn_long_genesis(sidecar: dict, var_root: Path) -> None:
    for impl in ("go", "rust"):
        sn_edit_file(var_root, f"genesis-{impl}-block.json", block_hex=long_genesis_hex, hash=long_genesis_hash)
    sidecar["genesis"].update({"go_hash": long_genesis_hash, "rust_hash": long_genesis_hash})
    sidecar["chain_identity"]["genesis_hash_hex"] = long_genesis_hash
    sidecar["header_bytes"] = {"go": 148, "rust": 148}
def sn_drop_rust_create(report: dict) -> None:
    rust_node = next(node_obj for node_obj in report["nodes"] if node_obj["implementation"] == "rust")
    rust_node["command_argv"] = [arg for arg in rust_node["command_argv"] if arg != "--create-store"]
    rust_node["command"] = " ".join(rust_node["command_argv"])
sn_variant("grammar-differs", "tx-accept", lambda s, r: s["header_bytes"].update(rust=148))
sn_variant("grammar-outside", "tx-accept", lambda s, r: s["header_bytes"].update(go=120, rust=120))
sn_variant("grammar-no-match", "tx-accept", lambda s, r: sn_edit_file(r, "genesis-rust-block.json", block_hex="00" + genesis_hex[2:]))
sn_variant("grammar-derived-differs", "tx-accept", lambda s, r: (sn_long_genesis(s, r), s["header_bytes"].update(go=116, rust=116)))
sn_variant("long-header", "tx-accept", sn_long_genesis)
sn_variant("genesis-identity", "tx-accept", lambda s, r: s["chain_identity"].update(genesis_hash_hex="ee" * 32))
sn_variant("genesis-block-hash", "tx-accept", lambda s, r: sn_edit_file(r, "genesis-go-block.json", hash="ee" * 32))
sn_variant("argv-and-extra-key", "tx-accept", lambda s, r: s.update(node_rust_datadir_sha256="00" * 32), sn_drop_rust_create)
sn_variant("genesis-and-grammar", "tx-accept", lambda s, r: (s["chain_identity"].update(genesis_hash_hex="ee" * 32), s["header_bytes"].update(rust=148)))
sn_variant("binary-and-genesis", "tx-accept", lambda s, r: (s["binaries"].update(go_node_sha256="00" * 32), s["chain_identity"].update(genesis_hash_hex="ee" * 32)))
sn_variant("grammar-and-convergence", "tx-accept", lambda s, r: (s["header_bytes"].update(rust=148), s["initial_convergence"].update(rust_tip_hash="ee" * 32), sn_edit_file(r, "initial-convergence-rust-tip.json", tip_hash="ee" * 32)))
sn_variant("genesis-and-block-file", "tx-accept", lambda s, r: (s["chain_identity"].update(genesis_hash_hex="ee" * 32), sn_edit_file(r, "genesis-go-block.json", implementation="rust")))
sn_variant("tip-endpoint", "tx-accept", lambda s, r: sn_edit_file(r, "initial-convergence-rust-tip.json", rpc_endpoint=go_rpc))
sn_variant("missing", "tx-accept", lambda s, r: SN_DELETE)
sn_variant("mesh-genesis", "mesh", lambda s, r: s.update(genesis={"go_hash": genesis_hash, "rust_hash": genesis_hash, "go_block_path": str(r / "node-go"), "rust_block_path": str(r / "node-rust")}))
sn_variant("mesh-txgen", "mesh", lambda s, r: s["binaries"].update(txgen_sha256=hashlib.sha256((r / "rubin-txgen").read_bytes()).hexdigest()))
sn_variant("mesh-tip-present", "mesh", lambda s, r: sn_edit_file(r, "initial-convergence-rust-tip.json", has_tip=True, height=0, tip_hash=conv_hash))
sn_variant("restart-below", "restart", lambda s, r: sn_set_height(s, r, 108))
sn_variant("restart-new-endpoint", "restart", lambda s, r: sn_edit_file(r, "initial-convergence-rust-tip.json", rpc_endpoint=rust_rpc))
sn_variant("restart-at-pre-restart", "restart", lambda s, r: sn_set_height(s, r, 107))
sn_variant("partition-not-above", "partition", lambda s, r: sn_set_height(s, r, common_height))
import os
def sn_drop_file_key(var_root: Path, file_name: str, key: str) -> None:
    data = json.loads((var_root / file_name).read_text(encoding="utf-8"))
    data.pop(key)
    dump(var_root / file_name, data)
def sn_outside(var_root: Path, file_name: str) -> str:
    shutil.copy(var_root / file_name, var_root.parent / file_name)
    return str(var_root.parent / file_name)
def sn_conv_hash(sidecar: dict, var_root: Path, value: str) -> None:
    sidecar["initial_convergence"].update(go_tip_hash=value, rust_tip_hash=value)
    for file_name in ("initial-convergence-go-tip.json", "initial-convergence-rust-tip.json"):
        sn_edit_file(var_root, file_name, tip_hash=value)
SN_MODES = {"mesh": "public", "tx-accept": "tx", "restart": "rust-restart"}
SN_ALL, SN_CHAIN = ("mesh", "tx-accept", "restart"), ("tx-accept", "restart")
SN_I, SN_G, SN_H = "store_neutrality_sidecar_invalid", "store_neutrality_genesis_mismatch", "store_neutrality_header_grammar_mismatch"
GO_TIP, GO_BLOCK, RUST_BLOCK = "initial-convergence-go-tip.json", "genesis-go-block.json", "genesis-rust-block.json"
GO_TIP_PATH, GO_BLOCK_PATH, GO_BLOCK_BAD = "initial_convergence.go_tip_path", "genesis.go_block_path", "genesis.go_block_path is not"
GO_TIP_KEYS, GO_TIP_IDENT, GO_BLOCK_KEYS, GO_BLOCK_IDENT = GO_TIP_PATH + " keys mismatch", GO_TIP_PATH + " sidecar identity mismatch", GO_BLOCK_PATH + " keys mismatch", GO_BLOCK_PATH + " sidecar identity mismatch"
SN_CASES = (
    (SN_ALL, "top-missing", SN_I, "sidecar keys mismatch", lambda s, r: s.pop("datadirs")),
    (SN_ALL, "top-extra", SN_I, "sidecar keys mismatch", lambda s, r: s.update(node_rust_datadir_sha256="00" * 32)),
    (SN_ALL, "domain", SN_I, "evidence_domain mismatch", lambda s, r: s.update(evidence_domain="post_switch_store_neutrality")),
    (SN_ALL, "commit-upper", SN_I, "protocol_commit is not 40 lowercase hex", lambda s, r: s.update(protocol_commit="AB" * 20)),
    (SN_ALL, "commit-short", SN_I, "protocol_commit is not 40 lowercase hex", lambda s, r: s.update(protocol_commit="ab" * 19 + "a")),
    (SN_ALL, "commit-long", SN_I, "protocol_commit is not 40 lowercase hex", lambda s, r: s.update(protocol_commit="ab" * 20 + "a")),
    (SN_ALL, "tree-dirty", SN_I, "clients_tree_clean is not true", lambda s, r: s.update(clients_tree_clean=False)),
    (SN_ALL, "tree-one", SN_I, "clients_tree_clean is not true", lambda s, r: s.update(clients_tree_clean=1)),
    (SN_ALL, "binaries-extra", SN_I, "binaries keys mismatch", lambda s, r: s["binaries"].update(extra_sha256="00" * 32)),
    (SN_ALL, "binaries-missing", SN_I, "binaries keys mismatch", lambda s, r: s["binaries"].pop("txgen_sha256")),
    (SN_ALL, "go-node-hash", SN_I, "binaries.go_node_sha256 does not match", lambda s, r: s["binaries"].update(go_node_sha256="00" * 32)),
    (SN_ALL, "rust-node-hash", SN_I, "binaries.rust_node_sha256 does not match", lambda s, r: s["binaries"].update(rust_node_sha256="00" * 32)),
    (SN_ALL, "ident-extra", SN_I, "chain_identity malformed", lambda s, r: s["chain_identity"].update(extra="x")),
    (SN_ALL, "ident-missing", SN_I, "chain_identity malformed", lambda s, r: s["chain_identity"].pop("network")),
    (SN_ALL, "network-empty", SN_I, "chain_identity malformed", lambda s, r: s["chain_identity"].update(network="")),
    (SN_ALL, "network-number", SN_I, "chain_identity malformed", lambda s, r: s["chain_identity"].update(network=5)),
    (SN_ALL, "chain-id-upper", SN_I, "chain_identity malformed", lambda s, r: s["chain_identity"].update(chain_id_hex="DD" * 32)),
    (SN_ALL, "ident-genesis-short", SN_I, "chain_identity malformed", lambda s, r: s["chain_identity"].update(genesis_hash_hex=genesis_hash[:62])),
    (SN_ALL, "datadirs-extra", SN_I, "datadirs mismatch", lambda s, r: s["datadirs"].update(extra=str(r))),
    (SN_ALL, "datadirs-missing", SN_I, "datadirs mismatch", lambda s, r: s["datadirs"].pop("rust_exact_empty_before_first_start")),
    (SN_ALL, "go-datadir", SN_I, "datadirs mismatch", lambda s, r: s["datadirs"].update(go=str(r / "node-rust"))),
    (SN_ALL, "rust-datadir", SN_I, "datadirs mismatch", lambda s, r: s["datadirs"].update(rust=str(r / "node-go"))),
    (SN_ALL, "rust-not-empty", SN_I, "datadirs mismatch", lambda s, r: s["datadirs"].update(rust_exact_empty_before_first_start=False)),
    (SN_ALL, "conv-extra", SN_I, "initial_convergence keys mismatch", lambda s, r: s["initial_convergence"].update(extra=None)),
    (SN_ALL, "conv-missing", SN_I, "initial_convergence keys mismatch", lambda s, r: s["initial_convergence"].pop("go_tip_path")),
    (SN_ALL, "tip-relative", SN_I, GO_TIP_PATH + " is not absolute", lambda s, r: s["initial_convergence"].update(go_tip_path=os.path.relpath(r / GO_TIP))),
    (SN_ALL, "tip-outside", SN_I, GO_TIP_PATH + " is outside artifact_root", lambda s, r: s["initial_convergence"].update(go_tip_path=sn_outside(r, GO_TIP))),
    (SN_ALL, "tip-directory", SN_I, GO_TIP_PATH + " file is missing", lambda s, r: s["initial_convergence"].update(go_tip_path=str(r / "node-go"))),
    (SN_ALL, "tip-array", SN_I, GO_TIP_PATH + " root is not an object", lambda s, r: dump(r / GO_TIP, [1])),
    (SN_ALL, "tip-extra", SN_I, GO_TIP_KEYS, lambda s, r: sn_edit_file(r, GO_TIP, extra=1)),
    (SN_ALL, "tip-missing", SN_I, GO_TIP_KEYS, lambda s, r: sn_drop_file_key(r, GO_TIP, "in_ibd")),
    (SN_ALL, "tip-impl", SN_I, GO_TIP_IDENT, lambda s, r: sn_edit_file(r, GO_TIP, implementation="rust")),
    (SN_ALL, "tip-request", SN_I, GO_TIP_IDENT, lambda s, r: sn_edit_file(r, GO_TIP, request_path="/get_block?height=0")),
    (SN_ALL, "tip-endpoint", SN_I, GO_TIP_IDENT, lambda s, r: sn_edit_file(r, GO_TIP, rpc_endpoint=rust_rpc)),
    (("mesh",), "go-has-tip", SN_I, "initial_convergence does not prove two absent tips", lambda s, r: s["initial_convergence"].update(go_has_tip=True)),
    (("mesh",), "rust-has-tip", SN_I, "initial_convergence does not prove two absent tips", lambda s, r: s["initial_convergence"].update(rust_has_tip=True)),
    (("mesh",), "height-zero", SN_I, "initial_convergence does not prove two absent tips", lambda s, r: s["initial_convergence"].update(height=0)),
    (("mesh",), "go-tip-hash", SN_I, "initial_convergence does not prove two absent tips", lambda s, r: s["initial_convergence"].update(go_tip_hash=conv_hash)),
    (("mesh",), "rust-tip-hash", SN_I, "initial_convergence does not prove two absent tips", lambda s, r: s["initial_convergence"].update(rust_tip_hash=conv_hash)),
    (("mesh",), "header-bytes", SN_I, "genesis and header_bytes are not null", lambda s, r: s.update(header_bytes={"go": 116, "rust": 116})),
    (("mesh",), "tip-has-tip", SN_I, "initial_convergence.go_tip_path does not report an absent tip", lambda s, r: sn_edit_file(r, GO_TIP, has_tip=True)),
    (("mesh",), "tip-height", SN_I, "initial_convergence.go_tip_path does not report an absent tip", lambda s, r: sn_edit_file(r, GO_TIP, height=0)),
    (("mesh",), "tip-hash", SN_I, "initial_convergence.go_tip_path does not report an absent tip", lambda s, r: sn_edit_file(r, GO_TIP, tip_hash=conv_hash)),
    (SN_CHAIN, "txgen-hash", SN_I, "binaries.txgen_sha256 does not match", lambda s, r: s["binaries"].update(txgen_sha256="00" * 32)),
    (SN_CHAIN, "txgen-null", SN_I, "binaries.txgen_sha256 does not match", lambda s, r: s["binaries"].update(txgen_sha256=None)),
    (SN_CHAIN, "txgen-unreadable", SN_I, "binaries.txgen_sha256 does not match", lambda s, r: ((r / "rubin-txgen").unlink(), s["binaries"].update(txgen_sha256=None))),
    (SN_CHAIN, "go-has-tip-false", SN_I, "initial_convergence does not prove equal tips", lambda s, r: s["initial_convergence"].update(go_has_tip=False)),
    (SN_CHAIN, "rust-has-tip-false", SN_I, "initial_convergence does not prove equal tips", lambda s, r: s["initial_convergence"].update(rust_has_tip=False)),
    (SN_CHAIN, "height-100", SN_I, "initial_convergence does not prove equal tips", lambda s, r: sn_set_height(s, r, 100)),
    (SN_CHAIN, "height-string", SN_I, "initial_convergence does not prove equal tips", lambda s, r: s["initial_convergence"].update(height="101")),
    (SN_CHAIN, "conv-hash-upper", SN_I, "initial_convergence does not prove equal tips", lambda s, r: sn_conv_hash(s, r, "CC" * 32)),
    (SN_CHAIN, "conv-hash-differs", SN_I, "initial_convergence does not prove equal tips", lambda s, r: (s["initial_convergence"].update(rust_tip_hash="ee" * 32), sn_edit_file(r, "initial-convergence-rust-tip.json", tip_hash="ee" * 32))),
    (SN_CHAIN, "tip-has-tip-false", SN_I, GO_TIP_PATH + " does not match expected tip", lambda s, r: sn_edit_file(r, GO_TIP, has_tip=False)),
    (SN_CHAIN, "tip-height", SN_I, GO_TIP_PATH + " does not match expected tip", lambda s, r: sn_edit_file(r, GO_TIP, height=102, best_known_height=102)),
    (SN_CHAIN, "tip-hash", SN_I, GO_TIP_PATH + " does not match expected tip", lambda s, r: sn_edit_file(r, GO_TIP, tip_hash="ee" * 32)),
    (SN_CHAIN, "genesis-list", SN_I, "genesis malformed", lambda s, r: s.update(genesis=[])),
    (SN_CHAIN, "genesis-extra", SN_I, "genesis malformed", lambda s, r: s["genesis"].update(extra=None)),
    (SN_CHAIN, "genesis-missing", SN_I, "genesis malformed", lambda s, r: s["genesis"].pop("rust_block_path")),
    (SN_CHAIN, "genesis-go-upper", SN_I, "genesis malformed", lambda s, r: s["genesis"].update(go_hash=genesis_hash.upper())),
    (SN_CHAIN, "genesis-rust-upper", SN_I, "genesis malformed", lambda s, r: s["genesis"].update(rust_hash=genesis_hash.upper())),
    (SN_CHAIN, "genesis-rust-differs", SN_G, "go_hash, rust_hash and chain_identity.genesis_hash_hex are not all equal", lambda s, r: (s["genesis"].update(rust_hash="ee" * 32), sn_edit_file(r, RUST_BLOCK, hash="ee" * 32))),
    (SN_CHAIN, "block-relative", SN_I, GO_BLOCK_PATH + " is not absolute", lambda s, r: s["genesis"].update(go_block_path=os.path.relpath(r / GO_BLOCK))),
    (SN_CHAIN, "block-outside", SN_I, GO_BLOCK_PATH + " is outside artifact_root", lambda s, r: s["genesis"].update(go_block_path=sn_outside(r, GO_BLOCK))),
    (SN_CHAIN, "block-directory", SN_I, GO_BLOCK_PATH + " file is missing", lambda s, r: s["genesis"].update(go_block_path=str(r / "node-go"))),
    (SN_CHAIN, "block-array", SN_I, GO_BLOCK_PATH + " root is not an object", lambda s, r: dump(r / GO_BLOCK, [1])),
    (SN_CHAIN, "block-extra", SN_I, GO_BLOCK_KEYS, lambda s, r: sn_edit_file(r, GO_BLOCK, extra=1)),
    (SN_CHAIN, "block-missing", SN_I, GO_BLOCK_KEYS, lambda s, r: sn_drop_file_key(r, GO_BLOCK, "canonical")),
    (SN_CHAIN, "block-impl", SN_I, "genesis.rust_block_path sidecar identity mismatch", lambda s, r: sn_edit_file(r, RUST_BLOCK, implementation="go")),
    (SN_CHAIN, "block-request", SN_I, GO_BLOCK_IDENT, lambda s, r: sn_edit_file(r, GO_BLOCK, request_path="/get_block?height=1")),
    (SN_CHAIN, "block-height-one", SN_I, GO_BLOCK_BAD + " the go genesis block capture", lambda s, r: sn_edit_file(r, GO_BLOCK, height=1)),
    (SN_CHAIN, "block-height-false", SN_I, GO_BLOCK_BAD + " the go genesis block capture", lambda s, r: sn_edit_file(r, GO_BLOCK, height=False)),
    (SN_CHAIN, "block-not-canonical", SN_I, GO_BLOCK_BAD + " the go genesis block capture", lambda s, r: sn_edit_file(r, GO_BLOCK, canonical=False)),
    (SN_CHAIN, "block-canonical-one", SN_I, GO_BLOCK_BAD + " the go genesis block capture", lambda s, r: sn_edit_file(r, GO_BLOCK, canonical=1)),
    (SN_CHAIN, "block-hex-empty", SN_I, GO_BLOCK_BAD + " the go genesis block capture", lambda s, r: sn_edit_file(r, GO_BLOCK, block_hex="")),
    (SN_CHAIN, "block-hex-upper", SN_I, GO_BLOCK_BAD + " the go genesis block capture", lambda s, r: sn_edit_file(r, GO_BLOCK, block_hex=genesis_hex.upper())),
    (SN_CHAIN, "block-hex-odd", SN_I, GO_BLOCK_BAD + " the go genesis block capture", lambda s, r: sn_edit_file(r, GO_BLOCK, block_hex=genesis_hex + "0")),
    (SN_CHAIN, "block-hex-number", SN_I, GO_BLOCK_BAD + " the go genesis block capture", lambda s, r: sn_edit_file(r, GO_BLOCK, block_hex=5)),
    (SN_CHAIN, "block-endpoint", SN_I, GO_BLOCK_IDENT, lambda s, r: sn_edit_file(r, GO_BLOCK, rpc_endpoint=rust_rpc)),
    (("restart",), "rust-block-new-endpoint", SN_I, "genesis.rust_block_path sidecar identity mismatch", lambda s, r: sn_edit_file(r, RUST_BLOCK, rpc_endpoint=rust_rpc)),
    (SN_CHAIN, "rust-block-hash", SN_G, "genesis.rust_block_path hash differs from genesis.rust_hash", lambda s, r: sn_edit_file(r, RUST_BLOCK, hash="ee" * 32)),
    (SN_CHAIN, "header-list", SN_I, "header_bytes malformed", lambda s, r: s.update(header_bytes=[116, 116])),
    (SN_CHAIN, "header-extra", SN_I, "header_bytes malformed", lambda s, r: s["header_bytes"].update(extra=116)),
    (SN_CHAIN, "header-missing", SN_I, "header_bytes malformed", lambda s, r: s["header_bytes"].pop("rust")),
    (SN_CHAIN, "header-string", SN_I, "header_bytes malformed", lambda s, r: s["header_bytes"].update(go="116")),
    (SN_CHAIN, "header-bool", SN_I, "header_bytes malformed", lambda s, r: s["header_bytes"].update(go=True)),
    (SN_CHAIN, "header-float", SN_I, "header_bytes malformed", lambda s, r: s["header_bytes"].update(go=116.0, rust=116.0)),
    (SN_CHAIN, "header-rust-outside", SN_H, "header_bytes.rust is not 116 or 148", lambda s, r: s["header_bytes"].update(rust=120)),
)
with (root / "sn-cases.tsv").open("w", encoding="utf-8") as cases:
    for columns, case_name, token, needle, edit in SN_CASES:
        for column in columns:
            sn_variant(f"{column}-{case_name}", column, edit)
            cases.write(f"{SN_MODES[column]}\t{column}-{case_name}\t{token}\t{needle}\n")
artifact_root = root / "partition" / "artifact-root"
print(root / "mesh-report.json")
print(root / "tx-report.json")
print(root / "converge-report.json")
print(root / "rust-submit-go-mine-report.json")
print(root / "tx-missing-propagation-samples.json")
print(root / "tx-nonfinite-propagation-sample.json")
print(root / "tx-slo-claim-sample.json")
print(root / "converge-missing-convergence-samples.json")
print(root / "mesh-bad-propagation-not-requested-reason.json")
print(root / "mesh-bad-convergence-not-requested-reason.json")
print(root / "rust-submit-go-mine-wrong-txid.json")
print(root / "rust-submit-go-mine-bad-go-class.json")
print(root / "rust-submit-go-mine-bad-rust-converge-class.json")
print(root / "rust-submit-go-mine-duplicate-sidecar-path.json")
print(root / "rust-submit-go-mine-wrong-sidecar-source.json")
print(root / "rust-submit-go-mine-malformed-block.json")
print(root / "rust-submit-go-mine-missing-tx-block.json")
print(root / "converge-wrong-txid.json")
print(root / "converge-bad-rust-class.json")
print(root / "converge-duplicate-sidecar-path.json")
print(root / "converge-wrong-sidecar-source.json")
print(root / "converge-malformed-block.json")
print(root / "converge-missing-tx-block.json")
print(root / "converge-bad-merkle-block.json")
print(root / "converge-tx-count-mismatch.json")
print(root / "restart-report.json")
print(root / "restart-missing-restart-object.json")
print(root / "restart-missing-process-object.json")
print(root / "restart-same-pid.json")
print(root / "restart-old-pid-not-stopped.json")
print(root / "restart-no-peer-reconnect.json")
print(root / "restart-same-datadir-false.json")
print(root / "restart-datadir-mismatch.json")
print(root / "restart-stale-run-id.json")
print(root / "restart-catch-up-below-pre-restart.json")
print(root / "restart-stale-catch-up.json")
print(root / "restart-legacy-marker-mismatch.json")
print(root / "restart-new-pid-not-final.json")
print(root / "restart-pre-tip-absent.json")
print(root / "restart-catch-up-tip-absent.json")
print(root / "restart-go-target-not-advanced.json")
print(root / "restart-pre-restart-height-string.json")
print(root / "restart-go-target-height-string.json")
print(root / "restart-catch-up-height-string.json")
print(root / "restart-pre-restart-height-bool.json")
print(root / "restart-go-target-height-bool.json")
print(root / "restart-catch-up-height-bool.json")
print(root / "restart-catch-up-tip-mismatch.json")
print(root / "restart-stale-legacy-text.json")
print(root / "restart-pre-tip-sidecar-float-height.json")
print(root / "restart-catch-up-tip-sidecar-float-height.json")
print(root / "restart-go-target-tip-float-height.json")
print(root / "restart-go-target-mine-bool-tx-count.json")
print(root / "restart-old-pid-alias-go.json")
print(root / "restart-pre-tip-sidecar-low-best-known.json")
print(root / "restart-go-target-tip-sidecar-low-best-known.json")
print(root / "restart-catch-up-tip-sidecar-low-best-known.json")
print(root / "restart-stale-artifact-created-at.json")
print(root / "restart-stale-run-id-mismatch.json")
print(root / "partition-report.json")
print(artifact_root / "partition-missing-raw-samples-report.json")
print(artifact_root / "partition-missing-process-alive-report.json")
print(artifact_root / "partition-extra-top-level-report.json")
print(artifact_root / "partition-stale-legacy-purpose-report.json")
print(artifact_root / "partition-extra-legacy-key-report.json")
print(root / "partition-losing-parent-report.json")
print(root / "partition-forged-parent-payload-report.json")
print(root / "partition-same-height-winner-report.json")
print(root / "partition-peer-connectivity-overclaim-report.json")
print(artifact_root / "partition-peer-connectivity-bool-count-report.json")
print(root / "partition-final-verification-overclaim-report.json")
print(artifact_root / "partition-unbacked-node-report.json")
print(artifact_root / "partition-rust-peer-argv-mismatch-report.json")
print(artifact_root / "partition-direct-proxy-report.json")
print(root / "partition-disconnected-go-fork-report.json")
print(root / "partition-same-first-rust-fork-report.json")
print(artifact_root / "partition-skip-height-rust-winner-report.json")
print(artifact_root / "partition-forged-metrics-report.json")
print(artifact_root / "partition-peer-sidecar-bool-count-report.json")
print(artifact_root / "partition-peer-sidecar-extra-field-report.json")
print(artifact_root / "partition-rust-tip-float-height-report.json")
print(artifact_root / "partition-go-tip-string-ibd-report.json")
print(artifact_root / "partition-rust-mine-string-nonce-report.json")
print(artifact_root / "partition-rust-mine-string-timestamp-report.json")
print(artifact_root / "partition-metrics-timestamp-report.json")
print(artifact_root / "partition-metrics-json-report.json"); print(artifact_root / "partition-positive-depth-report.json")
print(artifact_root / "partition-zero-total-depth-0-report.json")
print(artifact_root / "partition-zero-total-depth-1-report.json")
PY
}

CHECK_REPORT_LIB="${TMP_ROOT}/check-report-lib.sh"
PREPARE_TX_CHAINSTATE_LIB="${TMP_ROOT}/prepare-tx-chainstate-lib.sh"
PROXY_GO_LOCAL_ADDR_LIB="${TMP_ROOT}/proxy-go-local-addr-lib.sh"
WAIT_PEER_SNAPSHOT_LIB="${TMP_ROOT}/wait-peer-snapshot-lib.sh"
CAPTURE_GO_REORG_METRICS_LIB="${TMP_ROOT}/capture-go-reorg-metrics-lib.sh"
WAIT_PEER_SNAPSHOT_STATE_LIB="${TMP_ROOT}/wait-peer-snapshot-state-lib.sh"
extract_check_report
extract_prepare_tx_chainstate
extract_proxy_go_local_addr
extract_wait_peer_snapshot
extract_capture_go_reorg_metrics
extract_wait_peer_snapshot_state
check_prepare_tx_chainstate_cleanup
check_prepare_tx_chainstate_leaves_rust_empty
check_rust_datadir_guard
check_txgen_datadir_guard
check_initial_convergence_wait
check_store_neutrality_producer_reasons
check_proxy_go_local_addr_reason
check_wait_peer_snapshot_normalizes
check_capture_go_reorg_metrics_reason
check_wait_peer_snapshot_state_reason
# shellcheck source=/dev/null
source "${CHECK_REPORT_LIB}"
[[ "$(tx_path_prepare_reason go_submit_chainstate_prepare_failed 1)" == "go_submit_chainstate_prepare_failed" ]] || { echo "FAIL: go-submit prep reason should remain go_submit scoped" >&2; exit 1; }
[[ "$(tx_path_prepare_reason go_submit_chainstate_prepare_failed 2)" == "go_submit_chainstate_prepare_failed" ]] || { echo "FAIL: go-submit converge prep reason should remain go_submit scoped" >&2; exit 1; }
[[ "$(tx_path_prepare_reason go_submit_chainstate_prepare_failed 3)" == "rust_submit_chainstate_prepare_failed" ]] || { echo "FAIL: rust-submit prep fallback reason was not remapped" >&2; exit 1; }
[[ "$(tx_path_prepare_reason go_submit_mine_timeout 3)" == "rust_submit_mine_timeout" ]] || { echo "FAIL: rust-submit mining prep timeout reason was not remapped" >&2; exit 1; }
[[ "$(tx_path_prepare_reason tx_chainstate_unrelated 3)" == "tx_chainstate_unrelated" ]] || { echo "FAIL: non-go-submit prep reason should remain unchanged" >&2; exit 1; }
[[ "$(rust_restart_prepare_reason go_submit_keygen_failed)" == "rust_restart_keygen_failed" ]] || { echo "FAIL: rust restart keygen prep reason was not remapped" >&2; exit 1; }
[[ "$(rust_restart_prepare_reason go_submit_mine_timeout)" == "rust_restart_chainstate_mine_timeout" ]] || { echo "FAIL: rust restart mine prep reason was not remapped" >&2; exit 1; }
[[ "$(rust_restart_prepare_reason "")" == "rust_restart_chainstate_prepare_failed" ]] || { echo "FAIL: rust restart empty prep reason fallback was not remapped" >&2; exit 1; }
REPORT_LIST="${TMP_ROOT}/reports.txt"
write_reports >"${REPORT_LIST}"
MESH_REPORT="$(sed -n '1p' "${REPORT_LIST}")"
TX_REPORT="$(sed -n '2p' "${REPORT_LIST}")"
CONVERGE_REPORT="$(sed -n '3p' "${REPORT_LIST}")"
RUST_SUBMIT_GO_MINE_REPORT="$(sed -n '4p' "${REPORT_LIST}")"
TX_MISSING_PROPAGATION_SAMPLE_REPORT="$(sed -n '5p' "${REPORT_LIST}")"
TX_NONFINITE_PROPAGATION_SAMPLE_REPORT="$(sed -n '6p' "${REPORT_LIST}")"
TX_SLO_CLAIM_SAMPLE_REPORT="$(sed -n '7p' "${REPORT_LIST}")"
CONVERGE_MISSING_CONVERGENCE_SAMPLE_REPORT="$(sed -n '8p' "${REPORT_LIST}")"
MESH_BAD_PROPAGATION_REASON_REPORT="$(sed -n '9p' "${REPORT_LIST}")"
MESH_BAD_CONVERGENCE_REASON_REPORT="$(sed -n '10p' "${REPORT_LIST}")"
RUST_SUBMIT_GO_MINE_WRONG_TXID_REPORT="$(sed -n '11p' "${REPORT_LIST}")"
RUST_SUBMIT_GO_MINE_BAD_GO_CLASS_REPORT="$(sed -n '12p' "${REPORT_LIST}")"
RUST_SUBMIT_GO_MINE_BAD_RUST_CONVERGE_CLASS_REPORT="$(sed -n '13p' "${REPORT_LIST}")"
RUST_SUBMIT_GO_MINE_DUPLICATE_SIDECAR_REPORT="$(sed -n '14p' "${REPORT_LIST}")"
RUST_SUBMIT_GO_MINE_WRONG_SIDECAR_SOURCE_REPORT="$(sed -n '15p' "${REPORT_LIST}")"
RUST_SUBMIT_GO_MINE_MALFORMED_BLOCK_REPORT="$(sed -n '16p' "${REPORT_LIST}")"
RUST_SUBMIT_GO_MINE_MISSING_TX_BLOCK_REPORT="$(sed -n '17p' "${REPORT_LIST}")"
CONVERGE_WRONG_TXID_REPORT="$(sed -n '18p' "${REPORT_LIST}")"
CONVERGE_BAD_RUST_CLASS_REPORT="$(sed -n '19p' "${REPORT_LIST}")"
CONVERGE_DUPLICATE_SIDECAR_REPORT="$(sed -n '20p' "${REPORT_LIST}")"
CONVERGE_WRONG_SIDECAR_SOURCE_REPORT="$(sed -n '21p' "${REPORT_LIST}")"
CONVERGE_MALFORMED_BLOCK_REPORT="$(sed -n '22p' "${REPORT_LIST}")"
CONVERGE_MISSING_TX_BLOCK_REPORT="$(sed -n '23p' "${REPORT_LIST}")"
CONVERGE_BAD_MERKLE_BLOCK_REPORT="$(sed -n '24p' "${REPORT_LIST}")"
CONVERGE_TX_COUNT_MISMATCH_REPORT="$(sed -n '25p' "${REPORT_LIST}")"
RESTART_REPORT="$(sed -n '26p' "${REPORT_LIST}")"
RESTART_MISSING_RESTART_REPORT="$(sed -n '27p' "${REPORT_LIST}")"
RESTART_MISSING_PROCESS_REPORT="$(sed -n '28p' "${REPORT_LIST}")"
RESTART_SAME_PID_REPORT="$(sed -n '29p' "${REPORT_LIST}")"
RESTART_OLD_PID_NOT_STOPPED_REPORT="$(sed -n '30p' "${REPORT_LIST}")"
RESTART_NO_PEER_RECONNECT_REPORT="$(sed -n '31p' "${REPORT_LIST}")"
RESTART_SAME_DATADIR_FALSE_REPORT="$(sed -n '32p' "${REPORT_LIST}")"
RESTART_DATADIR_MISMATCH_REPORT="$(sed -n '33p' "${REPORT_LIST}")"
RESTART_STALE_RUN_ID_REPORT="$(sed -n '34p' "${REPORT_LIST}")"
RESTART_CATCH_UP_BELOW_PRE_RESTART_REPORT="$(sed -n '35p' "${REPORT_LIST}")"
RESTART_STALE_CATCH_UP_REPORT="$(sed -n '36p' "${REPORT_LIST}")"
RESTART_LEGACY_MARKER_MISMATCH_REPORT="$(sed -n '37p' "${REPORT_LIST}")"
RESTART_NEW_PID_NOT_FINAL_REPORT="$(sed -n '38p' "${REPORT_LIST}")"
RESTART_PRE_TIP_ABSENT_REPORT="$(sed -n '39p' "${REPORT_LIST}")"
RESTART_CATCH_UP_TIP_ABSENT_REPORT="$(sed -n '40p' "${REPORT_LIST}")"
RESTART_GO_TARGET_NOT_ADVANCED_REPORT="$(sed -n '41p' "${REPORT_LIST}")"
RESTART_PRE_RESTART_HEIGHT_STRING_REPORT="$(sed -n '42p' "${REPORT_LIST}")"
RESTART_GO_TARGET_HEIGHT_STRING_REPORT="$(sed -n '43p' "${REPORT_LIST}")"
RESTART_CATCH_UP_HEIGHT_STRING_REPORT="$(sed -n '44p' "${REPORT_LIST}")"
RESTART_PRE_RESTART_HEIGHT_BOOL_REPORT="$(sed -n '45p' "${REPORT_LIST}")"
RESTART_GO_TARGET_HEIGHT_BOOL_REPORT="$(sed -n '46p' "${REPORT_LIST}")"
RESTART_CATCH_UP_HEIGHT_BOOL_REPORT="$(sed -n '47p' "${REPORT_LIST}")"
RESTART_CATCH_UP_TIP_MISMATCH_REPORT="$(sed -n '48p' "${REPORT_LIST}")"
RESTART_STALE_LEGACY_TEXT_REPORT="$(sed -n '49p' "${REPORT_LIST}")"
RESTART_PRE_TIP_SIDECAR_FLOAT_HEIGHT_REPORT="$(sed -n '50p' "${REPORT_LIST}")"
RESTART_CATCH_UP_TIP_SIDECAR_FLOAT_HEIGHT_REPORT="$(sed -n '51p' "${REPORT_LIST}")"
RESTART_GO_TARGET_TIP_FLOAT_HEIGHT_REPORT="$(sed -n '52p' "${REPORT_LIST}")"
RESTART_GO_TARGET_MINE_BOOL_TX_COUNT_REPORT="$(sed -n '53p' "${REPORT_LIST}")"
RESTART_OLD_PID_ALIAS_GO_REPORT="$(sed -n '54p' "${REPORT_LIST}")"
RESTART_PRE_TIP_SIDECAR_LOW_BEST_KNOWN_REPORT="$(sed -n '55p' "${REPORT_LIST}")"
RESTART_GO_TARGET_TIP_SIDECAR_LOW_BEST_KNOWN_REPORT="$(sed -n '56p' "${REPORT_LIST}")"
RESTART_CATCH_UP_TIP_SIDECAR_LOW_BEST_KNOWN_REPORT="$(sed -n '57p' "${REPORT_LIST}")"
RESTART_STALE_ARTIFACT_TIME_REPORT="$(sed -n '58p' "${REPORT_LIST}")"
RESTART_STALE_RUN_ID_MISMATCH_REPORT="$(sed -n '59p' "${REPORT_LIST}")"
PARTITION_REPORT="$(sed -n '60p' "${REPORT_LIST}")"
PARTITION_MISSING_RAW_SAMPLES_REPORT="$(sed -n '61p' "${REPORT_LIST}")"
PARTITION_MISSING_PROCESS_ALIVE_REPORT="$(sed -n '62p' "${REPORT_LIST}")"
PARTITION_EXTRA_TOP_LEVEL_REPORT="$(sed -n '63p' "${REPORT_LIST}")"
PARTITION_STALE_LEGACY_PURPOSE_REPORT="$(sed -n '64p' "${REPORT_LIST}")"
PARTITION_EXTRA_LEGACY_KEY_REPORT="$(sed -n '65p' "${REPORT_LIST}")"
PARTITION_LOSING_PARENT_REPORT="$(sed -n '66p' "${REPORT_LIST}")"
PARTITION_FORGED_PARENT_PAYLOAD_REPORT="$(sed -n '67p' "${REPORT_LIST}")"
PARTITION_SAME_HEIGHT_WINNER_REPORT="$(sed -n '68p' "${REPORT_LIST}")"
PARTITION_PEER_CONNECTIVITY_OVERCLAIM_REPORT="$(sed -n '69p' "${REPORT_LIST}")"
PARTITION_PEER_CONNECTIVITY_BOOL_COUNT_REPORT="$(sed -n '70p' "${REPORT_LIST}")"
PARTITION_FINAL_VERIFICATION_OVERCLAIM_REPORT="$(sed -n '71p' "${REPORT_LIST}")"
PARTITION_UNBACKED_NODE_REPORT="$(sed -n '72p' "${REPORT_LIST}")"
PARTITION_RUST_PEER_ARGV_MISMATCH_REPORT="$(sed -n '73p' "${REPORT_LIST}")"
PARTITION_DIRECT_PROXY_REPORT="$(sed -n '74p' "${REPORT_LIST}")"
PARTITION_DISCONNECTED_GO_FORK_REPORT="$(sed -n '75p' "${REPORT_LIST}")"
PARTITION_SAME_FIRST_RUST_FORK_REPORT="$(sed -n '76p' "${REPORT_LIST}")"
PARTITION_SKIP_HEIGHT_RUST_WINNER_REPORT="$(sed -n '77p' "${REPORT_LIST}")"
PARTITION_FORGED_METRICS_REPORT="$(sed -n '78p' "${REPORT_LIST}")"
PARTITION_PEER_SIDECAR_BOOL_COUNT_REPORT="$(sed -n '79p' "${REPORT_LIST}")"
PARTITION_PEER_SIDECAR_EXTRA_FIELD_REPORT="$(sed -n '80p' "${REPORT_LIST}")"
PARTITION_RUST_TIP_FLOAT_HEIGHT_REPORT="$(sed -n '81p' "${REPORT_LIST}")"
PARTITION_GO_TIP_STRING_IBD_REPORT="$(sed -n '82p' "${REPORT_LIST}")"
PARTITION_RUST_MINE_STRING_NONCE_REPORT="$(sed -n '83p' "${REPORT_LIST}")"
PARTITION_RUST_MINE_STRING_TIMESTAMP_REPORT="$(sed -n '84p' "${REPORT_LIST}")"
PARTITION_METRICS_TIMESTAMP_REPORT="$(sed -n '85p' "${REPORT_LIST}")"
PARTITION_METRICS_JSON_REPORT="$(sed -n '86p' "${REPORT_LIST}")"
PARTITION_POSITIVE_DEPTH_REPORT="$(sed -n '87p' "${REPORT_LIST}")"
PARTITION_ZERO_TOTAL_DEPTH_0_REPORT="$(sed -n '88p' "${REPORT_LIST}")"
PARTITION_ZERO_TOTAL_DEPTH_1_REPORT="$(sed -n '89p' "${REPORT_LIST}")"
TX_HUGE_INT_PROPAGATION_SAMPLE_REPORT="${TMP_ROOT}/tx-huge-int-propagation-sample.json"
CONVERGE_BOOL_HEIGHT_SAMPLE_REPORT="${TMP_ROOT}/converge-bool-height-sample.json"
CONVERGE_FLOAT_HEIGHT_SAMPLE_REPORT="${TMP_ROOT}/converge-float-height-sample.json"
CONVERGE_UPPERCASE_BLOCK_HASH_SAMPLE_REPORT="${TMP_ROOT}/converge-uppercase-block-hash-sample.json"
[[ -f "${TX_HUGE_INT_PROPAGATION_SAMPLE_REPORT}" && -f "${CONVERGE_BOOL_HEIGHT_SAMPLE_REPORT}" && -f "${CONVERGE_FLOAT_HEIGHT_SAMPLE_REPORT}" && -f "${CONVERGE_UPPERCASE_BLOCK_HASH_SAMPLE_REPORT}" ]] || { echo "failed to build raw sample regression reports" >&2; exit 1; }
[[ -n "${MESH_REPORT}" && -n "${TX_REPORT}" && -n "${CONVERGE_REPORT}" && -n "${RUST_SUBMIT_GO_MINE_REPORT}" && -n "${TX_MISSING_PROPAGATION_SAMPLE_REPORT}" && -n "${TX_NONFINITE_PROPAGATION_SAMPLE_REPORT}" && -n "${TX_SLO_CLAIM_SAMPLE_REPORT}" && -n "${CONVERGE_MISSING_CONVERGENCE_SAMPLE_REPORT}" && -n "${MESH_BAD_PROPAGATION_REASON_REPORT}" && -n "${MESH_BAD_CONVERGENCE_REASON_REPORT}" && -n "${RUST_SUBMIT_GO_MINE_WRONG_TXID_REPORT}" && -n "${RUST_SUBMIT_GO_MINE_BAD_GO_CLASS_REPORT}" && -n "${RUST_SUBMIT_GO_MINE_BAD_RUST_CONVERGE_CLASS_REPORT}" && -n "${RUST_SUBMIT_GO_MINE_DUPLICATE_SIDECAR_REPORT}" && -n "${RUST_SUBMIT_GO_MINE_WRONG_SIDECAR_SOURCE_REPORT}" && -n "${RUST_SUBMIT_GO_MINE_MALFORMED_BLOCK_REPORT}" && -n "${RUST_SUBMIT_GO_MINE_MISSING_TX_BLOCK_REPORT}" && -n "${CONVERGE_WRONG_TXID_REPORT}" && -n "${CONVERGE_BAD_RUST_CLASS_REPORT}" && -n "${CONVERGE_DUPLICATE_SIDECAR_REPORT}" && -n "${CONVERGE_WRONG_SIDECAR_SOURCE_REPORT}" && -n "${CONVERGE_MALFORMED_BLOCK_REPORT}" && -n "${CONVERGE_MISSING_TX_BLOCK_REPORT}" && -n "${CONVERGE_BAD_MERKLE_BLOCK_REPORT}" && -n "${CONVERGE_TX_COUNT_MISMATCH_REPORT}" ]] || { echo "failed to build synthetic reports" >&2; exit 1; }
[[ -n "${RESTART_REPORT}" && -n "${RESTART_MISSING_RESTART_REPORT}" && -n "${RESTART_MISSING_PROCESS_REPORT}" && -n "${RESTART_SAME_PID_REPORT}" && -n "${RESTART_OLD_PID_NOT_STOPPED_REPORT}" && -n "${RESTART_NO_PEER_RECONNECT_REPORT}" && -n "${RESTART_SAME_DATADIR_FALSE_REPORT}" && -n "${RESTART_DATADIR_MISMATCH_REPORT}" && -n "${RESTART_STALE_RUN_ID_REPORT}" && -n "${RESTART_CATCH_UP_BELOW_PRE_RESTART_REPORT}" && -n "${RESTART_STALE_CATCH_UP_REPORT}" && -n "${RESTART_LEGACY_MARKER_MISMATCH_REPORT}" && -n "${RESTART_NEW_PID_NOT_FINAL_REPORT}" && -n "${RESTART_PRE_TIP_ABSENT_REPORT}" && -n "${RESTART_CATCH_UP_TIP_ABSENT_REPORT}" && -n "${RESTART_GO_TARGET_NOT_ADVANCED_REPORT}" && -n "${RESTART_PRE_RESTART_HEIGHT_STRING_REPORT}" && -n "${RESTART_GO_TARGET_HEIGHT_STRING_REPORT}" && -n "${RESTART_CATCH_UP_HEIGHT_STRING_REPORT}" && -n "${RESTART_PRE_RESTART_HEIGHT_BOOL_REPORT}" && -n "${RESTART_GO_TARGET_HEIGHT_BOOL_REPORT}" && -n "${RESTART_CATCH_UP_HEIGHT_BOOL_REPORT}" && -n "${RESTART_CATCH_UP_TIP_MISMATCH_REPORT}" && -n "${RESTART_STALE_LEGACY_TEXT_REPORT}" && -n "${RESTART_PRE_TIP_SIDECAR_FLOAT_HEIGHT_REPORT}" && -n "${RESTART_CATCH_UP_TIP_SIDECAR_FLOAT_HEIGHT_REPORT}" && -n "${RESTART_GO_TARGET_TIP_FLOAT_HEIGHT_REPORT}" && -n "${RESTART_GO_TARGET_MINE_BOOL_TX_COUNT_REPORT}" && -n "${RESTART_OLD_PID_ALIAS_GO_REPORT}" && -n "${RESTART_PRE_TIP_SIDECAR_LOW_BEST_KNOWN_REPORT}" && -n "${RESTART_GO_TARGET_TIP_SIDECAR_LOW_BEST_KNOWN_REPORT}" && -n "${RESTART_CATCH_UP_TIP_SIDECAR_LOW_BEST_KNOWN_REPORT}" && -n "${RESTART_STALE_ARTIFACT_TIME_REPORT}" && -n "${RESTART_STALE_RUN_ID_MISMATCH_REPORT}" ]] || { echo "failed to build synthetic restart reports" >&2; exit 1; }
[[ -n "${PARTITION_REPORT}" && -n "${PARTITION_MISSING_RAW_SAMPLES_REPORT}" && -n "${PARTITION_MISSING_PROCESS_ALIVE_REPORT}" && -n "${PARTITION_EXTRA_TOP_LEVEL_REPORT}" && -n "${PARTITION_STALE_LEGACY_PURPOSE_REPORT}" && -n "${PARTITION_EXTRA_LEGACY_KEY_REPORT}" && -n "${PARTITION_LOSING_PARENT_REPORT}" && -n "${PARTITION_FORGED_PARENT_PAYLOAD_REPORT}" && -n "${PARTITION_SAME_HEIGHT_WINNER_REPORT}" && -n "${PARTITION_PEER_CONNECTIVITY_OVERCLAIM_REPORT}" && -n "${PARTITION_PEER_CONNECTIVITY_BOOL_COUNT_REPORT}" && -n "${PARTITION_FINAL_VERIFICATION_OVERCLAIM_REPORT}" && -n "${PARTITION_UNBACKED_NODE_REPORT}" && -n "${PARTITION_RUST_PEER_ARGV_MISMATCH_REPORT}" && -n "${PARTITION_DIRECT_PROXY_REPORT}" && -n "${PARTITION_DISCONNECTED_GO_FORK_REPORT}" && -n "${PARTITION_SAME_FIRST_RUST_FORK_REPORT}" && -n "${PARTITION_SKIP_HEIGHT_RUST_WINNER_REPORT}" && -n "${PARTITION_FORGED_METRICS_REPORT}" && -n "${PARTITION_PEER_SIDECAR_BOOL_COUNT_REPORT}" && -n "${PARTITION_PEER_SIDECAR_EXTRA_FIELD_REPORT}" && -n "${PARTITION_RUST_TIP_FLOAT_HEIGHT_REPORT}" && -n "${PARTITION_GO_TIP_STRING_IBD_REPORT}" && -n "${PARTITION_RUST_MINE_STRING_NONCE_REPORT}" && -n "${PARTITION_RUST_MINE_STRING_TIMESTAMP_REPORT}" && -n "${PARTITION_METRICS_TIMESTAMP_REPORT}" && -n "${PARTITION_METRICS_JSON_REPORT}" ]] || { echo "failed to build synthetic partition reports" >&2; exit 1; }

for bad_fee in 0 abc 100000001; do
  if DETERMINISTIC_TX_FEE="${bad_fee}" "${HARNESS}" --partition-heal-reorg >/dev/null 2>"${TMP_ROOT}/bad-fee.err"; then
    echo "partition mode accepted invalid DETERMINISTIC_TX_FEE=${bad_fee}" >&2
    exit 1
  fi
  grep -Fq "DETERMINISTIC_TX_FEE must be a positive integer <= 100000000" "${TMP_ROOT}/bad-fee.err" || { cat "${TMP_ROOT}/bad-fee.err" >&2; exit 1; }
done

expect_pass_contains "public mesh check-report" "PASS: mixed_client_mesh report structurally accepted" "${HARNESS}" --check-report "${MESH_REPORT}"
expect_pass_contains "rust restart check-report" "PASS: mixed_client_rust_restart report structurally accepted" "${HARNESS}" --rust-restart --check-report "${RESTART_REPORT}"
expect_pass_contains "partition check-report" "PASS: mixed_client_partition_heal_reorg report structurally accepted" "${HARNESS}" --partition-heal-reorg --check-report "${PARTITION_REPORT}"
expect_pass_contains "partition positive-depth check-report" "PASS: mixed_client_partition_heal_reorg report structurally accepted" "${HARNESS}" --partition-heal-reorg --check-report "${PARTITION_POSITIVE_DEPTH_REPORT}"
expect_fail_contains "partition rejects zero total at depth zero" "proof.go_reorg_metrics.rubin_node_reorg_total is below 1" "${HARNESS}" --partition-heal-reorg --check-report "${PARTITION_ZERO_TOTAL_DEPTH_0_REPORT}"; expect_fail_contains "partition rejects zero total at depth one" "proof.go_reorg_metrics.rubin_node_reorg_total is below 1" "${HARNESS}" --partition-heal-reorg --check-report "${PARTITION_ZERO_TOTAL_DEPTH_1_REPORT}"
expect_fail_contains "partition rejects missing raw samples" "report top-level keys mismatch" "${HARNESS}" --partition-heal-reorg --check-report "${PARTITION_MISSING_RAW_SAMPLES_REPORT}"
expect_generator_fail_contains "partition generator rejects missing raw samples" "top_level_fields_invalid" --partition-heal-reorg-report "${PARTITION_MISSING_RAW_SAMPLES_REPORT}"
expect_fail_contains "partition rejects missing process_alive" "go node keys mismatch" "${HARNESS}" --partition-heal-reorg --check-report "${PARTITION_MISSING_PROCESS_ALIVE_REPORT}"
expect_generator_fail_contains "partition generator rejects missing process_alive" "process_identity_missing_or_invalid" --partition-heal-reorg-report "${PARTITION_MISSING_PROCESS_ALIVE_REPORT}"
expect_fail_contains "partition rejects extra top-level evidence" "report top-level keys mismatch" "${HARNESS}" --partition-heal-reorg --check-report "${PARTITION_EXTRA_TOP_LEVEL_REPORT}"
expect_generator_fail_contains "partition generator rejects extra top-level evidence" "top_level_fields_invalid" --partition-heal-reorg-report "${PARTITION_EXTRA_TOP_LEVEL_REPORT}"
expect_fail_contains "partition rejects stale legacy purpose" "legacy_schema_compatibility partition purpose mismatch" "${HARNESS}" --partition-heal-reorg --check-report "${PARTITION_STALE_LEGACY_PURPOSE_REPORT}"
expect_generator_fail_contains "partition generator rejects stale legacy purpose" "legacy_marker_invalid" --partition-heal-reorg-report "${PARTITION_STALE_LEGACY_PURPOSE_REPORT}"
expect_fail_contains "partition rejects extra legacy key" "legacy_schema_compatibility missing marker_path" "${HARNESS}" --partition-heal-reorg --check-report "${PARTITION_EXTRA_LEGACY_KEY_REPORT}"
expect_generator_fail_contains "partition generator rejects extra legacy key" "legacy_marker_invalid" --partition-heal-reorg-report "${PARTITION_EXTRA_LEGACY_KEY_REPORT}"
expect_fail_contains "partition rejects losing fork as reorg parent" "observations.reorg.go_reorg_parent_block does not match expected block" "${HARNESS}" --partition-heal-reorg --check-report "${PARTITION_LOSING_PARENT_REPORT}"
expect_fail_contains "partition rejects forged parent block payload" "observations.reorg.go_reorg_parent_block parsed block hash mismatch" "${HARNESS}" --partition-heal-reorg --check-report "${PARTITION_FORGED_PARENT_PAYLOAD_REPORT}"
expect_fail_contains "partition rejects same-height winning fork" "partition fork tips do not prove Rust winning branch" "${HARNESS}" --partition-heal-reorg --check-report "${PARTITION_SAME_HEIGHT_WINNER_REPORT}"
expect_fail_contains "partition rejects peer_connectivity overclaim" "partition peer_connectivity overclaims direct link" "${HARNESS}" --partition-heal-reorg --check-report "${PARTITION_PEER_CONNECTIVITY_OVERCLAIM_REPORT}"
expect_fail_contains "partition rejects peer_connectivity bool count" "partition peer_connectivity.go_peer_snapshot must be empty" "${HARNESS}" --partition-heal-reorg --check-report "${PARTITION_PEER_CONNECTIVITY_BOOL_COUNT_REPORT}"
expect_generator_fail_contains "partition generator rejects peer_connectivity bool count" "peer_connectivity_invalid" --partition-heal-reorg-report "${PARTITION_PEER_CONNECTIVITY_BOOL_COUNT_REPORT}"
expect_fail_contains "partition rejects final_verification overclaim" "partition final verification is incomplete" "${HARNESS}" --partition-heal-reorg --check-report "${PARTITION_FINAL_VERIFICATION_OVERCLAIM_REPORT}"
expect_generator_fail_contains "partition generator rejects unbacked node evidence" "process_identity_missing_or_invalid" --partition-heal-reorg-report "${PARTITION_UNBACKED_NODE_REPORT}"
expect_fail_contains "partition rejects rust peer argv mismatch" "node command_argv does not match exact launched argv" "${HARNESS}" --partition-heal-reorg --check-report "${PARTITION_RUST_PEER_ARGV_MISMATCH_REPORT}"
expect_generator_fail_contains "partition generator rejects rust peer argv mismatch" "node_identity_invalid" --partition-heal-reorg-report "${PARTITION_RUST_PEER_ARGV_MISMATCH_REPORT}"
expect_fail_contains "partition rejects direct proxy self-validation" "partition proxy endpoint is not proxy-only" "${HARNESS}" --partition-heal-reorg --check-report "${PARTITION_DIRECT_PROXY_REPORT}"
expect_generator_fail_contains "partition generator rejects direct proxy self-validation" "node_identity_invalid" --partition-heal-reorg-report "${PARTITION_DIRECT_PROXY_REPORT}"
expect_fail_contains "partition rejects disconnected fork parent" "observations.fork.go_block block payload check failed" "${HARNESS}" --partition-heal-reorg --check-report "${PARTITION_DISCONNECTED_GO_FORK_REPORT}"
expect_fail_contains "partition rejects non-divergent rust fork" "rust fork first mine did not diverge from go fork" "${HARNESS}" --partition-heal-reorg --check-report "${PARTITION_SAME_FIRST_RUST_FORK_REPORT}"
expect_fail_contains "partition rejects skipped-height rust winner" "rust winning branch is not contiguous" "${HARNESS}" --partition-heal-reorg --check-report "${PARTITION_SKIP_HEIGHT_RUST_WINNER_REPORT}"
expect_generator_fail_contains "partition generator rejects skipped-height rust winner" "rust_winning_branch_not_contiguous" --partition-heal-reorg-report "${PARTITION_SKIP_HEIGHT_RUST_WINNER_REPORT}"
expect_fail_contains "partition rejects forged reorg metrics" "partition go reorg metrics do not match source sidecar" "${HARNESS}" --partition-heal-reorg --check-report "${PARTITION_FORGED_METRICS_REPORT}"
expect_generator_fail_contains "partition generator rejects forged reorg metrics" "reorg_metrics_mismatch" --partition-heal-reorg-report "${PARTITION_FORGED_METRICS_REPORT}"
expect_fail_contains "partition rejects bool peer sidecar count" "observations.pre_partition.rust_peer_snapshot peer snapshot malformed" "${HARNESS}" --partition-heal-reorg --check-report "${PARTITION_PEER_SIDECAR_BOOL_COUNT_REPORT}"
expect_generator_fail_contains "partition generator rejects bool peer sidecar count" "peer_snapshot_invalid" --partition-heal-reorg-report "${PARTITION_PEER_SIDECAR_BOOL_COUNT_REPORT}"
expect_fail_contains "partition rejects peer sidecar extra field" "observations.pre_partition.rust_peer_snapshot peer entries malformed" "${HARNESS}" --partition-heal-reorg --check-report "${PARTITION_PEER_SIDECAR_EXTRA_FIELD_REPORT}"
expect_generator_fail_contains "partition generator rejects peer sidecar extra field" "peer_snapshot_invalid" --partition-heal-reorg-report "${PARTITION_PEER_SIDECAR_EXTRA_FIELD_REPORT}"
expect_fail_contains "partition rejects float rust tip sidecar height" "observations.fork.rust_tip does not match expected tip" "${HARNESS}" --partition-heal-reorg --check-report "${PARTITION_RUST_TIP_FLOAT_HEIGHT_REPORT}"
expect_generator_fail_contains "partition generator rejects float rust tip sidecar height" "tip_sidecar_invalid" --partition-heal-reorg-report "${PARTITION_RUST_TIP_FLOAT_HEIGHT_REPORT}"
expect_fail_contains "partition rejects string go tip in_ibd" "observations.reorg.go_tip does not match expected tip" "${HARNESS}" --partition-heal-reorg --check-report "${PARTITION_GO_TIP_STRING_IBD_REPORT}"
expect_generator_fail_contains "partition generator rejects string go tip in_ibd" "tip_sidecar_invalid" --partition-heal-reorg-report "${PARTITION_GO_TIP_STRING_IBD_REPORT}"
expect_fail_contains "partition rejects string rust mine nonce" "observations.fork.rust_mine_2 malformed mine result" "${HARNESS}" --partition-heal-reorg --check-report "${PARTITION_RUST_MINE_STRING_NONCE_REPORT}"
expect_generator_fail_contains "partition generator rejects string rust mine nonce" "mine_sidecar_invalid" --partition-heal-reorg-report "${PARTITION_RUST_MINE_STRING_NONCE_REPORT}"
expect_fail_contains "partition rejects string rust mine timestamp" "observations.fork.rust_mine_2 malformed mine result" "${HARNESS}" --partition-heal-reorg --check-report "${PARTITION_RUST_MINE_STRING_TIMESTAMP_REPORT}"
expect_generator_fail_contains "partition generator rejects string rust mine timestamp" "mine_sidecar_invalid" --partition-heal-reorg-report "${PARTITION_RUST_MINE_STRING_TIMESTAMP_REPORT}"
expect_fail_contains "partition rejects timestamped reorg metrics" "observations.reorg.go_metrics malformed metric line" "${HARNESS}" --partition-heal-reorg --check-report "${PARTITION_METRICS_TIMESTAMP_REPORT}"
expect_generator_fail_contains "partition generator rejects timestamped metrics sidecar" "metrics_malformed" --partition-heal-reorg-report "${PARTITION_METRICS_TIMESTAMP_REPORT}"
expect_fail_contains "partition rejects JSON reorg metrics" "observations.reorg.go_metrics malformed metric line" "${HARNESS}" --partition-heal-reorg --check-report "${PARTITION_METRICS_JSON_REPORT}"
expect_generator_fail_contains "partition generator rejects JSON metrics sidecar" "metrics_malformed" --partition-heal-reorg-report "${PARTITION_METRICS_JSON_REPORT}"
expect_fail_contains "public restart check-report" "public restart check-report is unsupported" "${HARNESS}" --check-report "${RESTART_REPORT}"
expect_fail_contains "restart live check-report unsupported" "--rust-restart --check-report-live is unsupported" "${HARNESS}" --rust-restart --check-report-live "${RESTART_REPORT}"
expect_fail_contains "restart mode rejects mesh artifact" "rust restart validation requires a mixed_client_rust_restart report" "${HARNESS}" --rust-restart --check-report "${MESH_REPORT}"
expect_fail_contains "restart rejects missing restart object" "report top-level keys mismatch" "${HARNESS}" --rust-restart --check-report "${RESTART_MISSING_RESTART_REPORT}"
expect_fail_contains "restart rejects missing process object" "report top-level keys mismatch" "${HARNESS}" --rust-restart --check-report "${RESTART_MISSING_PROCESS_REPORT}"
expect_fail_contains "restart rejects same pid reuse" "rust_restart reused the stopped pid" "${HARNESS}" --rust-restart --check-report "${RESTART_SAME_PID_REPORT}"
expect_fail_contains "restart rejects old pid aliasing go" "rust_restart.old_pid aliases a final live node pid" "${HARNESS}" --rust-restart --check-report "${RESTART_OLD_PID_ALIAS_GO_REPORT}"
expect_fail_contains "restart rejects old pid not stopped" "rust_restart does not prove old process stopped" "${HARNESS}" --rust-restart --check-report "${RESTART_OLD_PID_NOT_STOPPED_REPORT}"
expect_fail_contains "restart rejects missing peer reconnect" "rust_restart peer reconnect was not observed" "${HARNESS}" --rust-restart --check-report "${RESTART_NO_PEER_RECONNECT_REPORT}"
expect_fail_contains "restart rejects same_datadir false" "rust_restart does not prove same datadir restart" "${HARNESS}" --rust-restart --check-report "${RESTART_SAME_DATADIR_FALSE_REPORT}"
expect_fail_contains "restart rejects datadir mismatch" "rust_restart datadir is not bound to artifact root" "${HARNESS}" --rust-restart --check-report "${RESTART_DATADIR_MISMATCH_REPORT}"
expect_fail_contains "restart rejects stale run identity" "restart report run_id missing" "${HARNESS}" --rust-restart --check-report "${RESTART_STALE_RUN_ID_REPORT}"
expect_fail_contains "restart rejects stale artifact timestamp" "restart report artifact_created_at_utc invalid" "${HARNESS}" --rust-restart --check-report "${RESTART_STALE_ARTIFACT_TIME_REPORT}"
expect_fail_contains "restart rejects stale run id mismatch" "restart report run_id mismatch" "${HARNESS}" --rust-restart --check-report "${RESTART_STALE_RUN_ID_MISMATCH_REPORT}"
expect_fail_contains "restart rejects catch-up below pre-restart" "below pre_restart_height" "${HARNESS}" --rust-restart --check-report "${RESTART_CATCH_UP_BELOW_PRE_RESTART_REPORT}"
expect_fail_contains "restart rejects stale catch-up" "rust_restart catch-up height does not match go target" "${HARNESS}" --rust-restart --check-report "${RESTART_STALE_CATCH_UP_REPORT}"
expect_fail_contains "restart rejects legacy marker mismatch" "legacy marker restart object is not bound to report restart object" "${HARNESS}" --rust-restart --check-report "${RESTART_LEGACY_MARKER_MISMATCH_REPORT}"
expect_fail_contains "restart rejects new pid not final rust process" "rust_restart.new_pid is not the final rust node pid" "${HARNESS}" --rust-restart --check-report "${RESTART_NEW_PID_NOT_FINAL_REPORT}"
expect_fail_contains "restart rejects missing pre-restart tip" "rust_restart pre-restart tip is not proven" "${HARNESS}" --rust-restart --check-report "${RESTART_PRE_TIP_ABSENT_REPORT}"
expect_fail_contains "restart rejects missing catch-up tip" "rust_restart catch-up tip is not proven" "${HARNESS}" --rust-restart --check-report "${RESTART_CATCH_UP_TIP_ABSENT_REPORT}"
expect_fail_contains "restart rejects non-advanced go target" "rust_restart go target did not advance beyond pre-restart tip" "${HARNESS}" --rust-restart --check-report "${RESTART_GO_TARGET_NOT_ADVANCED_REPORT}"
expect_fail_contains "restart rejects catch-up tip mismatch" "rust_restart catch-up tip does not match go target" "${HARNESS}" --rust-restart --check-report "${RESTART_CATCH_UP_TIP_MISMATCH_REPORT}"
expect_fail_contains "restart rejects stale legacy text" "legacy_schema_compatibility restart purpose mismatch" "${HARNESS}" --rust-restart --check-report "${RESTART_STALE_LEGACY_TEXT_REPORT}"
expect_fail_contains "restart rejects float pre-restart sidecar height" "rust_restart.pre_restart_tip_path.height is not an integer" "${HARNESS}" --rust-restart --check-report "${RESTART_PRE_TIP_SIDECAR_FLOAT_HEIGHT_REPORT}"
expect_fail_contains "restart rejects float catch-up sidecar height" "rust_restart.catch_up_tip_path.height is not an integer" "${HARNESS}" --rust-restart --check-report "${RESTART_CATCH_UP_TIP_SIDECAR_FLOAT_HEIGHT_REPORT}"
expect_fail_contains "restart rejects float go target sidecar height" "rust_restart.go_target_tip_path.height is not an integer" "${HARNESS}" --rust-restart --check-report "${RESTART_GO_TARGET_TIP_FLOAT_HEIGHT_REPORT}"
expect_fail_contains "restart rejects string pre-restart height" "rust_restart.pre_restart_height is not an integer" "${HARNESS}" --rust-restart --check-report "${RESTART_PRE_RESTART_HEIGHT_STRING_REPORT}"
expect_fail_contains "restart rejects string go target height" "rust_restart.go_target_height is not an integer" "${HARNESS}" --rust-restart --check-report "${RESTART_GO_TARGET_HEIGHT_STRING_REPORT}"
expect_fail_contains "restart rejects string catch-up height" "rust_restart.catch_up_height is not an integer" "${HARNESS}" --rust-restart --check-report "${RESTART_CATCH_UP_HEIGHT_STRING_REPORT}"
expect_fail_contains "restart rejects bool pre-restart height" "rust_restart.pre_restart_height is not an integer" "${HARNESS}" --rust-restart --check-report "${RESTART_PRE_RESTART_HEIGHT_BOOL_REPORT}"
expect_fail_contains "restart rejects bool go target height" "rust_restart.go_target_height is not an integer" "${HARNESS}" --rust-restart --check-report "${RESTART_GO_TARGET_HEIGHT_BOOL_REPORT}"
expect_fail_contains "restart rejects bool catch-up height" "rust_restart.catch_up_height is not an integer" "${HARNESS}" --rust-restart --check-report "${RESTART_CATCH_UP_HEIGHT_BOOL_REPORT}"
expect_fail_contains "restart rejects bool go target mine tx_count" "rust_restart.go_target_mine_next_path.tx_count is not an integer" "${HARNESS}" --rust-restart --check-report "${RESTART_GO_TARGET_MINE_BOOL_TX_COUNT_REPORT}"
expect_fail_contains "restart rejects low pre-restart sidecar best-known height" "rust_restart.pre_restart_tip_path.best_known_height below height" "${HARNESS}" --rust-restart --check-report "${RESTART_PRE_TIP_SIDECAR_LOW_BEST_KNOWN_REPORT}"
expect_fail_contains "restart rejects low go target sidecar best-known height" "rust_restart.go_target_tip_path.best_known_height below height" "${HARNESS}" --rust-restart --check-report "${RESTART_GO_TARGET_TIP_SIDECAR_LOW_BEST_KNOWN_REPORT}"
expect_fail_contains "restart rejects low catch-up sidecar best-known height" "rust_restart.catch_up_tip_path.best_known_height below height" "${HARNESS}" --rust-restart --check-report "${RESTART_CATCH_UP_TIP_SIDECAR_LOW_BEST_KNOWN_REPORT}"
expect_fail_check_token "token maps restart mode mismatch" "rust_restart_scenario_required" check_report "${MESH_REPORT}" offline rust-restart
expect_fail_check_token "token maps public restart report" "public_restart_check_report_unsupported" check_report "${RESTART_REPORT}" offline public
expect_fail_check_token "token maps restart same pid" "rust_restart_same_pid" check_report "${RESTART_SAME_PID_REPORT}" offline rust-restart
expect_fail_check_token "token maps restart old pid alias" "rust_restart_old_pid_aliases_final_node" check_report "${RESTART_OLD_PID_ALIAS_GO_REPORT}" offline rust-restart
expect_fail_check_token "token maps restart old pid not stopped" "rust_restart_old_process_not_stopped" check_report "${RESTART_OLD_PID_NOT_STOPPED_REPORT}" offline rust-restart
expect_fail_check_token "token maps restart missing peer reconnect" "rust_restart_peer_reconnect_missing" check_report "${RESTART_NO_PEER_RECONNECT_REPORT}" offline rust-restart
expect_fail_check_token "token maps restart same_datadir false" "rust_restart_datadir_mismatch" check_report "${RESTART_SAME_DATADIR_FALSE_REPORT}" offline rust-restart
expect_fail_check_token "token maps restart datadir mismatch" "rust_restart_datadir_not_bound" check_report "${RESTART_DATADIR_MISMATCH_REPORT}" offline rust-restart
expect_fail_check_token "token maps restart datadir symlink" "rust_restart_datadir_not_bound" check_report "${TMP_ROOT}/restart-datadir-symlink.json" offline rust-restart
expect_fail_check_token "token maps restart relative datadir" "rust_restart_datadir_not_bound" check_report "${TMP_ROOT}/restart-datadir-relative.json" offline rust-restart
expect_fail_check_token "token maps restart node extra field" "process_identity_invalid" check_report "${TMP_ROOT}/restart-node-extra-field.json" offline rust-restart
expect_fail_check_token "token maps restart stale run identity" "rust_restart_run_id_missing" check_report "${RESTART_STALE_RUN_ID_REPORT}" offline rust-restart
expect_fail_check_token "token maps restart stale artifact timestamp" "rust_restart_artifact_created_at_invalid" check_report "${RESTART_STALE_ARTIFACT_TIME_REPORT}" offline rust-restart
expect_fail_check_token "token maps restart stale run id mismatch" "rust_restart_run_id_mismatch" check_report "${RESTART_STALE_RUN_ID_MISMATCH_REPORT}" offline rust-restart
expect_fail_check_token "token maps restart catch-up below pre-restart" "rust_restart_catch_up_below_pre_restart" check_report "${RESTART_CATCH_UP_BELOW_PRE_RESTART_REPORT}" offline rust-restart
expect_fail_check_token "token maps restart stale catch-up" "rust_restart_catch_up_height_not_go_target" check_report "${RESTART_STALE_CATCH_UP_REPORT}" offline rust-restart
expect_fail_check_token "token maps restart pre-restart height invalid" "rust_restart_pre_restart_height_invalid" check_report "${RESTART_PRE_RESTART_HEIGHT_STRING_REPORT}" offline rust-restart
expect_fail_check_token "token maps restart go target height invalid" "rust_restart_go_target_height_invalid" check_report "${RESTART_GO_TARGET_HEIGHT_STRING_REPORT}" offline rust-restart
expect_fail_check_token "token maps restart catch-up height invalid" "rust_restart_catch_up_height_invalid" check_report "${RESTART_CATCH_UP_HEIGHT_STRING_REPORT}" offline rust-restart
expect_fail_check_token "token maps restart pre-restart bool invalid" "rust_restart_pre_restart_height_invalid" check_report "${RESTART_PRE_RESTART_HEIGHT_BOOL_REPORT}" offline rust-restart
expect_fail_check_token "token maps restart go target bool invalid" "rust_restart_go_target_height_invalid" check_report "${RESTART_GO_TARGET_HEIGHT_BOOL_REPORT}" offline rust-restart
expect_fail_check_token "token maps restart catch-up bool invalid" "rust_restart_catch_up_height_invalid" check_report "${RESTART_CATCH_UP_HEIGHT_BOOL_REPORT}" offline rust-restart
expect_fail_check_token "token maps restart pre tip absent" "rust_restart_pre_tip_not_proven" check_report "${RESTART_PRE_TIP_ABSENT_REPORT}" offline rust-restart
expect_fail_check_token "token maps restart catch-up tip absent" "rust_restart_catch_up_tip_not_proven" check_report "${RESTART_CATCH_UP_TIP_ABSENT_REPORT}" offline rust-restart
expect_fail_check_token "token maps restart pre sidecar invalid" "rust_restart_pre_restart_tip_sidecar_invalid" check_report "${RESTART_PRE_TIP_SIDECAR_FLOAT_HEIGHT_REPORT}" offline rust-restart
expect_fail_check_token "token maps restart catch-up sidecar invalid" "rust_restart_catch_up_tip_sidecar_invalid" check_report "${RESTART_CATCH_UP_TIP_SIDECAR_FLOAT_HEIGHT_REPORT}" offline rust-restart
expect_fail_check_token "token maps restart go target sidecar invalid" "rust_restart_go_target_tip_sidecar_invalid" check_report "${RESTART_GO_TARGET_TIP_FLOAT_HEIGHT_REPORT}" offline rust-restart
expect_fail_check_token "token maps restart go target mine sidecar invalid" "rust_restart_go_target_mine_next_invalid" check_report "${RESTART_GO_TARGET_MINE_BOOL_TX_COUNT_REPORT}" offline rust-restart
expect_fail_check_token "token maps restart pre sidecar low best-known" "rust_restart_pre_restart_tip_sidecar_invalid" check_report "${RESTART_PRE_TIP_SIDECAR_LOW_BEST_KNOWN_REPORT}" offline rust-restart
expect_fail_check_token "token maps restart go target sidecar low best-known" "rust_restart_go_target_tip_sidecar_invalid" check_report "${RESTART_GO_TARGET_TIP_SIDECAR_LOW_BEST_KNOWN_REPORT}" offline rust-restart
expect_fail_check_token "token maps restart catch-up sidecar low best-known" "rust_restart_catch_up_tip_sidecar_invalid" check_report "${RESTART_CATCH_UP_TIP_SIDECAR_LOW_BEST_KNOWN_REPORT}" offline rust-restart
expect_fail_check_token "token maps restart go target not advanced" "rust_restart_go_target_not_advanced" check_report "${RESTART_GO_TARGET_NOT_ADVANCED_REPORT}" offline rust-restart
expect_fail_check_token "token maps restart catch-up tip mismatch" "rust_restart_catch_up_tip_not_go_target" check_report "${RESTART_CATCH_UP_TIP_MISMATCH_REPORT}" offline rust-restart
expect_fail_contains "public rejects propagation not-requested reason drift" "raw_samples.propagation must be not_requested with canonical reason" "${HARNESS}" --check-report "${MESH_BAD_PROPAGATION_REASON_REPORT}"
expect_fail_contains "public rejects convergence not-requested reason drift" "raw_samples.convergence must be not_requested with canonical reason" "${HARNESS}" --check-report "${MESH_BAD_CONVERGENCE_REASON_REPORT}"
expect_fail_contains "public tx check-report" "public tx-path check-report is unsupported" "${HARNESS}" --check-report "${TX_REPORT}"
expect_fail_contains "public converge check-report" "public tx-path check-report is unsupported" "${HARNESS}" --check-report "${CONVERGE_REPORT}"
expect_fail_contains "public rust-submit converge check-report" "public tx-path check-report is unsupported" "${HARNESS}" --check-report "${RUST_SUBMIT_GO_MINE_REPORT}"
expect_fail_contains "public tx check-report-live" "public tx-path check-report-live is unsupported" "${HARNESS}" --check-report-live "${TX_REPORT}"
expect_fail_contains "combined tx flag and check-report" "tx-path modes cannot be combined" "${HARNESS}" --go-submit-rust-accept --check-report "${TX_REPORT}"
expect_fail_contains "combined tx-path flags reject" "tx-path modes are mutually exclusive" "${HARNESS}" --go-submit-rust-accept --go-submit-rust-mine-go-converge
expect_fail_contains "combined rust-submit tx-path flags reject" "tx-path modes are mutually exclusive" "${HARNESS}" --go-submit-rust-accept --rust-submit-go-mine-rust-converge

expect_pass_contains "producer tx internal check" "PASS: mixed_client_go_submit_rust_accept report structurally accepted" check_report "${TX_REPORT}" offline producer-tx
expect_pass_contains "producer converge internal check" "PASS: mixed_client_go_submit_rust_mine_go_converge report structurally accepted" check_report "${CONVERGE_REPORT}" offline producer-tx
expect_pass_contains "producer rust-submit converge internal check" "PASS: mixed_client_rust_submit_go_mine_rust_converge report structurally accepted" check_report "${RUST_SUBMIT_GO_MINE_REPORT}" offline producer-tx
for variant in no-commit not-committed; do
  expect_fail_contains "partition go mine_next ${variant}" "observations.pre_partition.common_go_mine keys mismatch" "${HARNESS}" --partition-heal-reorg --check-report "${TMP_ROOT}/partition/artifact-root/mine-next-partition-go-${variant}.json"
  expect_generator_fail_contains "partition generator go mine_next ${variant}" "partition_reorg_source_binding_contradiction:mine_sidecar_invalid" --partition-heal-reorg-report "${TMP_ROOT}/partition/artifact-root/mine-next-partition-go-${variant}.json"
  expect_fail_contains "restart go target mine_next ${variant}" "rust_restart.go_target_mine_next_path keys mismatch" "${HARNESS}" --rust-restart --check-report "${TMP_ROOT}/restart/artifact-root/mine-next-restart-go-${variant}.json"
  expect_generator_fail_contains "restart generator go target mine_next ${variant}" "restart_source_binding_contradiction:go_target_mine_next_invalid" --rust-restart-report "${TMP_ROOT}/restart/artifact-root/mine-next-restart-go-${variant}.json"
  expect_fail_contains "rust-submit go mine_next ${variant}" "go_mine.mine_next keys mismatch" check_report "${TMP_ROOT}/rust-submit/artifact-root/mine-next-rust-conv-go-${variant}.json" offline producer-tx
  expect_generator_fail_contains "rust-submit generator go mine_next ${variant}" "convergence_sidecar_invalid" --rust-submit-go-mine-rust-converge-report "${TMP_ROOT}/rust-submit/artifact-root/mine-next-rust-conv-go-${variant}.json"
done
expect_fail_contains "partition rust mine_next with commit_state" "observations.fork.rust_mine_1 keys mismatch" "${HARNESS}" --partition-heal-reorg --check-report "${TMP_ROOT}/partition/artifact-root/mine-next-partition-rust-commit.json"
expect_generator_fail_contains "partition generator rust mine_next with commit_state" "partition_reorg_source_binding_contradiction:mine_sidecar_invalid" --partition-heal-reorg-report "${TMP_ROOT}/partition/artifact-root/mine-next-partition-rust-commit.json"
expect_fail_contains "converge rust mine_next with commit_state" "rust_mine.mine_next keys mismatch" check_report "${TMP_ROOT}/tx-converge/artifact-root/mine-next-converge-rust-commit.json" offline producer-tx
expect_generator_fail_contains "converge generator rust mine_next with commit_state" "convergence_sidecar_invalid" --go-submit-rust-mine-go-converge-report "${TMP_ROOT}/tx-converge/artifact-root/mine-next-converge-rust-commit.json"
expect_fail_contains "partition rust mine_next named go" "observations.fork.rust_mine_1 sidecar identity mismatch" "${HARNESS}" --partition-heal-reorg --check-report "${TMP_ROOT}/partition/artifact-root/mine-next-partition-rust-go-impl.json"
expect_fail_contains "converge rust mine_next named go" "rust_mine mine_next sidecar identity mismatch" check_report "${TMP_ROOT}/tx-converge/artifact-root/mine-next-converge-rust-go-impl.json" offline producer-tx
expect_fail_contains "producer rejects mesh report" "producer tx validation requires a mixed-client tx-path report" check_report "${MESH_REPORT}" offline producer-tx
expect_fail_contains "producer rejects missing propagation sample" "raw_samples.propagation requires one observed sample" check_report "${TX_MISSING_PROPAGATION_SAMPLE_REPORT}" offline producer-tx
expect_fail_contains "producer rejects non-finite propagation sample" "raw_samples.propagation.samples[0].elapsed is not finite" check_report "${TX_NONFINITE_PROPAGATION_SAMPLE_REPORT}" offline producer-tx
expect_fail_contains "producer rejects huge integer propagation sample" "raw_samples.propagation.samples[0].elapsed is not finite" check_report "${TX_HUGE_INT_PROPAGATION_SAMPLE_REPORT}" offline producer-tx
expect_fail_contains "producer rejects sample SLO claim" "raw_samples.propagation keys mismatch" check_report "${TX_SLO_CLAIM_SAMPLE_REPORT}" offline producer-tx
expect_fail_contains "producer rejects missing convergence sample" "raw_samples.convergence requires one observed sample" check_report "${CONVERGE_MISSING_CONVERGENCE_SAMPLE_REPORT}" offline producer-tx
expect_fail_contains "producer rejects bool convergence height" "raw_samples.convergence.samples[0].height is not an integer" check_report "${CONVERGE_BOOL_HEIGHT_SAMPLE_REPORT}" offline producer-tx
expect_fail_contains "producer rejects float convergence height" "raw_samples.convergence.samples[0].height is not an integer" check_report "${CONVERGE_FLOAT_HEIGHT_SAMPLE_REPORT}" offline producer-tx
expect_fail_contains "producer rejects uppercase convergence block hash" "raw_samples.convergence.samples[0].block_hash is not lowercase 32-byte hex" check_report "${CONVERGE_UPPERCASE_BLOCK_HASH_SAMPLE_REPORT}" offline producer-tx
expect_fail_contains "producer rejects converged txid drift" "mined/converged tx identity differs from submitted tx" check_report "${CONVERGE_WRONG_TXID_REPORT}" offline producer-tx
expect_fail_contains "producer rejects rust-submit converged txid drift" "mined/converged tx identity differs from submitted tx" check_report "${RUST_SUBMIT_GO_MINE_WRONG_TXID_REPORT}" offline producer-tx
expect_fail_contains "producer rejects reused converge sidecar path" "converge sidecar paths are not pairwise distinct" check_report "${CONVERGE_DUPLICATE_SIDECAR_REPORT}" offline producer-tx
expect_fail_contains "producer rejects reused rust-submit converge sidecar path" "converge sidecar paths are not pairwise distinct" check_report "${RUST_SUBMIT_GO_MINE_DUPLICATE_SIDECAR_REPORT}" offline producer-tx
expect_fail_contains "producer rejects wrong-source converge block" "go_converge.block_path sidecar identity mismatch" check_report "${CONVERGE_WRONG_SIDECAR_SOURCE_REPORT}" offline producer-tx
expect_fail_contains "producer rejects wrong-source rust converge block" "rust_converge.block_path sidecar identity mismatch" check_report "${RUST_SUBMIT_GO_MINE_WRONG_SIDECAR_SOURCE_REPORT}" offline producer-tx
expect_fail_contains "producer rejects malformed converge block" "go_converge.block_path inclusion check failed" check_report "${CONVERGE_MALFORMED_BLOCK_REPORT}" offline producer-tx
expect_fail_contains "producer rejects malformed rust converge block" "rust_converge.block_path inclusion check failed" check_report "${RUST_SUBMIT_GO_MINE_MALFORMED_BLOCK_REPORT}" offline producer-tx
expect_fail_contains "producer rejects converge block missing tx" "submitted txid missing from parsed block txids" check_report "${CONVERGE_MISSING_TX_BLOCK_REPORT}" offline producer-tx
expect_fail_contains "producer rejects rust-submit converge block missing tx" "submitted txid missing from parsed block txids" check_report "${RUST_SUBMIT_GO_MINE_MISSING_TX_BLOCK_REPORT}" offline producer-tx
expect_fail_contains "producer rejects uncommitted converge block tx list" "basic block validation failed" check_report "${CONVERGE_BAD_MERKLE_BLOCK_REPORT}" offline producer-tx
expect_fail_contains "producer rejects converge block tx_count mismatch" "parsed block tx_count mismatch" check_report "${CONVERGE_TX_COUNT_MISMATCH_REPORT}" offline producer-tx
expect_fail_token "token maps converge class drift" "rust_mine_class_invalid" check_report "${CONVERGE_BAD_RUST_CLASS_REPORT}" offline producer-tx
expect_fail_token "token maps go mine class drift" "go_mine_class_invalid" check_report "${RUST_SUBMIT_GO_MINE_BAD_GO_CLASS_REPORT}" offline producer-tx
expect_fail_token "token maps rust converge class drift" "rust_converge_class_invalid" check_report "${RUST_SUBMIT_GO_MINE_BAD_RUST_CONVERGE_CLASS_REPORT}" offline producer-tx
expect_fail_token "token maps reused converge sidecar path" "converge_sidecar_paths_not_distinct" check_report "${CONVERGE_DUPLICATE_SIDECAR_REPORT}" offline producer-tx
expect_fail_token "token maps reused rust-submit converge sidecar path" "converge_sidecar_paths_not_distinct" check_report "${RUST_SUBMIT_GO_MINE_DUPLICATE_SIDECAR_REPORT}" offline producer-tx
expect_fail_token "token maps propagation sample failures" "propagation_samples_invalid" check_report "${TX_MISSING_PROPAGATION_SAMPLE_REPORT}" offline producer-tx
expect_fail_token "token maps convergence sample failures" "convergence_samples_invalid" check_report "${CONVERGE_MISSING_CONVERGENCE_SAMPLE_REPORT}" offline producer-tx
expect_fail_token "token maps wrong-source converge sidecar" "converge_sidecar_identity_mismatch" check_report "${CONVERGE_WRONG_SIDECAR_SOURCE_REPORT}" offline producer-tx
expect_fail_token "token maps wrong-source rust converge sidecar" "converge_sidecar_identity_mismatch" check_report "${RUST_SUBMIT_GO_MINE_WRONG_SIDECAR_SOURCE_REPORT}" offline producer-tx
expect_fail_token "token maps malformed parsed block" "block_hex_parse_failed" check_report "${CONVERGE_MALFORMED_BLOCK_REPORT}" offline producer-tx
expect_fail_token "token maps malformed rust parsed block" "block_hex_parse_failed" check_report "${RUST_SUBMIT_GO_MINE_MALFORMED_BLOCK_REPORT}" offline producer-tx
expect_fail_token "token maps parsed block tx omission" "block_missing_submitted_txid" check_report "${CONVERGE_MISSING_TX_BLOCK_REPORT}" offline producer-tx
expect_fail_token "token maps rust-submit parsed block tx omission" "block_missing_submitted_txid" check_report "${RUST_SUBMIT_GO_MINE_MISSING_TX_BLOCK_REPORT}" offline producer-tx
expect_fail_token "token maps uncommitted block tx list" "block_basic_validation_failed" check_report "${CONVERGE_BAD_MERKLE_BLOCK_REPORT}" offline producer-tx
expect_fail_token "token maps block tx_count mismatch" "block_tx_count_mismatch" check_report "${CONVERGE_TX_COUNT_MISMATCH_REPORT}" offline producer-tx
[[ "$(block_inclusion_failure_reason rust_mine "parse block_hex failed: short block")" == "rust_mine_block_hex_parse_failed" ]] || { echo "FAIL: rust mine parse failure reason collapsed" >&2; exit 1; }
[[ "$(block_inclusion_failure_reason rust_mine "parsed block hash mismatch")" == "rust_mine_block_hash_mismatch" ]] || { echo "FAIL: rust mine hash mismatch reason collapsed" >&2; exit 1; }
[[ "$(block_inclusion_failure_reason rust_mine "basic block validation failed: BLOCK_ERR_MERKLE_INVALID")" == "rust_mine_block_basic_validation_failed" ]] || { echo "FAIL: rust mine basic block failure reason collapsed" >&2; exit 1; }
[[ "$(block_inclusion_failure_reason go_converge "parsed block tx_count mismatch")" == "go_converge_block_tx_count_mismatch" ]] || { echo "FAIL: go converge tx_count mismatch reason collapsed" >&2; exit 1; }
[[ "$(block_inclusion_failure_reason go_converge "submitted txid missing from parsed block txids")" == "go_converge_block_missing_submitted_txid" ]] || { echo "FAIL: go converge missing-tx reason collapsed" >&2; exit 1; }
[[ "$(block_inclusion_failure_reason go_converge "block response height/hash/canonical mismatch")" == "go_converge_block_sidecar_mismatch" ]] || { echo "FAIL: go converge sidecar mismatch reason collapsed" >&2; exit 1; }
printf '{"mined":false,"error":"live mining unavailable"}\n' >"${TMP_ROOT}/mine-live-unavailable.json"
printf '{"mined":false,"error":"sync engine unavailable"}\n' >"${TMP_ROOT}/mine-sync-unavailable.json"
printf '{"mined":false,"error":"tx pool unavailable"}\n' >"${TMP_ROOT}/mine-pool-unavailable.json"
printf '{"mined":false,"error":"template rejected"}\n' >"${TMP_ROOT}/mine-rejected.json"
[[ "$(mine_next_http_error_reason "${TMP_ROOT}/mine-live-unavailable.json")" == "rust_mine_live_mining_unavailable" ]] || { echo "FAIL: live mining error reason collapsed" >&2; exit 1; }
[[ "$(mine_next_http_error_reason "${TMP_ROOT}/mine-sync-unavailable.json")" == "rust_mine_sync_unavailable" ]] || { echo "FAIL: sync unavailable error reason collapsed" >&2; exit 1; }
[[ "$(mine_next_http_error_reason "${TMP_ROOT}/mine-pool-unavailable.json")" == "rust_mine_tx_pool_unavailable" ]] || { echo "FAIL: tx pool unavailable error reason collapsed" >&2; exit 1; }
[[ "$(mine_next_http_error_reason "${TMP_ROOT}/mine-rejected.json")" == "rust_mine_rejected" ]] || { echo "FAIL: miner rejection error reason collapsed" >&2; exit 1; }
[[ "$(mine_next_http_error_reason "${TMP_ROOT}/mine-pool-unavailable.json" go_mine)" == "go_mine_tx_pool_unavailable" ]] || { echo "FAIL: go mine tx pool unavailable error reason collapsed" >&2; exit 1; }
rpc_json() {
  [[ "$1" == "POST" && "$3" == "/mine_next" ]] || return 1
  printf '{"mined":false,"error":"tx pool unavailable"}\n'
  return 22
}
export RUST_RPC_ADDR="127.0.0.1:59999"
RUST_MINE_JSON="${TMP_ROOT}/mine-next-sidecar.json"
TX_REASON=""
if rust_mine_including_tx; then
  echo "FAIL: rust_mine_including_tx should fail on /mine_next HTTP error" >&2
  exit 1
fi
[[ "${TX_REASON}" == "rust_mine_tx_pool_unavailable" ]] || { echo "FAIL: mine_next HTTP body did not map through raw sidecar to TX_REASON: ${TX_REASON}" >&2; exit 1; }
[[ ! -e "${RUST_MINE_JSON}.raw" ]] || { echo "FAIL: mine_next HTTP raw body was not cleaned up" >&2; exit 1; }
export GO_RPC_ADDR="127.0.0.1:59998"
GO_MINE_JSON="${TMP_ROOT}/go-mine-next-sidecar.json"
TX_REASON=""
if go_mine_including_tx; then
  echo "FAIL: go_mine_including_tx should fail on /mine_next HTTP error" >&2
  exit 1
fi
[[ "${TX_REASON}" == "go_mine_tx_pool_unavailable" ]] || { echo "FAIL: go mine_next HTTP body did not map through raw sidecar to TX_REASON: ${TX_REASON}" >&2; exit 1; }
[[ ! -e "${GO_MINE_JSON}.raw" ]] || { echo "FAIL: go mine_next HTTP raw body was not cleaned up" >&2; exit 1; }

expect_fail_contains "non-regular report" "report is not a regular file" "${HARNESS}" --check-report "${TMP_ROOT}"
expect_fail_contains "empty report" "report is empty" "${HARNESS}" --check-report "${TMP_ROOT}/empty.json"
expect_fail_contains "malformed report" "report malformed JSON" "${HARNESS}" --check-report "${TMP_ROOT}/malformed.json"
expect_fail_contains "oversized report" "report is too large" "${HARNESS}" --check-report "${TMP_ROOT}/oversized.json"

expect_fail_contains "tx report Rust argv without --create-store" "node command_argv does not match exact launched argv" check_report "${TMP_ROOT}/tx-rust-without-create-report.json" offline producer-tx
expect_fail_contains "tx report Go argv with --create-store" "node command_argv does not match exact launched argv" check_report "${TMP_ROOT}/tx-go-with-create-report.json" offline producer-tx
expect_fail_contains "mesh report Rust argv without --create-store" "node command_argv does not match exact launched argv" "${HARNESS}" --check-report "${TMP_ROOT}/mesh-rust-without-create-report.json"
expect_fail_contains "restart old Rust argv without --create-store" "rust_restart old argv mismatch" "${HARNESS}" --rust-restart --check-report "${TMP_ROOT}/restart-old-without-create-report.json"
expect_fail_contains "restart new Rust argv with --create-store" "node command_argv does not match exact launched argv" "${HARNESS}" --rust-restart --check-report "${TMP_ROOT}/restart-new-with-create-report.json"
expect_fail_contains "partition Rust argv without --create-store" "node command_argv does not match exact launched argv" "${HARNESS}" --partition-heal-reorg --check-report "${TMP_ROOT}/partition-rust-without-create-report.json"
sn_check() {
  local label="$1" token="$2" needle="$3" mode="$4" name="$5"
  case "${mode}" in
    tx) expect_fail_contains "${label}" "FAIL: ${token}: ${needle}" check_report "${TMP_ROOT}/sn-${name}-report.json" offline producer-tx
        expect_fail_token "${label} token" "${token}" check_report "${TMP_ROOT}/sn-${name}-report.json" offline producer-tx ;;
    *) expect_fail_contains "${label}" "FAIL: ${token}: ${needle}" check_report "${TMP_ROOT}/sn-${name}-report.json" offline "${mode}"
       expect_fail_check_token "${label} token" "${token}" check_report "${TMP_ROOT}/sn-${name}-report.json" offline "${mode}" ;;
  esac
}
SN_INVALID=store_neutrality_sidecar_invalid; SN_GENESIS=store_neutrality_genesis_mismatch; SN_GRAMMAR=store_neutrality_header_grammar_mismatch
sn_check "sidecar header lengths differ" "${SN_GRAMMAR}" "header_bytes.go differs from header_bytes.rust" tx grammar-differs
sn_check "sidecar header length outside the two grammars" "${SN_GRAMMAR}" "header_bytes.go is not 116 or 148" tx grammar-outside
sn_check "sidecar genesis block with no matching header length" "${SN_GRAMMAR}" "header_bytes.rust is not the unique header length" tx grammar-no-match
sn_check "sidecar recorded length differs from derived length" "${SN_GRAMMAR}" "header_bytes.go is not the unique header length" tx grammar-derived-differs
expect_pass_contains "sidecar 148-byte header derivation" "PASS: mixed_client_go_submit_rust_accept report structurally accepted" check_report "${TMP_ROOT}/sn-long-header-report.json" offline producer-tx
sn_check "sidecar genesis identity mismatch" "${SN_GENESIS}" "go_hash, rust_hash and chain_identity.genesis_hash_hex are not all equal" tx genesis-identity
sn_check "sidecar genesis block hash mismatch" "${SN_GENESIS}" "genesis.go_block_path hash differs" tx genesis-block-hash
expect_fail_contains "argv defect before sidecar extra key" "node command_argv does not match exact launched argv" check_report "${TMP_ROOT}/sn-argv-and-extra-key-report.json" offline producer-tx
expect_fail_check_token "argv defect before sidecar extra key token" argv_mismatch check_report "${TMP_ROOT}/sn-argv-and-extra-key-report.json" offline producer-tx
sn_check "genesis identity before header grammar" "${SN_GENESIS}" "go_hash, rust_hash and chain_identity.genesis_hash_hex are not all equal" tx genesis-and-grammar
sn_check "binaries before genesis identity" "${SN_INVALID}" "binaries.go_node_sha256 does not match" tx binary-and-genesis
sn_check "initial convergence before header grammar" "${SN_INVALID}" "initial_convergence does not prove equal tips" tx grammar-and-convergence
sn_check "genesis block file before genesis identity" "${SN_INVALID}" "genesis.go_block_path sidecar identity mismatch" tx genesis-and-block-file
sn_check "sidecar rust tip endpoint" "${SN_INVALID}" "initial_convergence.rust_tip_path sidecar identity mismatch" tx tip-endpoint
sn_check "sidecar missing" "${SN_INVALID}" "store-neutrality sidecar file is missing" tx missing
sn_check "default sidecar with genesis" "${SN_INVALID}" "genesis and header_bytes are not null" public mesh-genesis
sn_check "default sidecar with txgen hash" "${SN_INVALID}" "binaries.txgen_sha256 is not null" public mesh-txgen
sn_check "default sidecar with a present tip" "${SN_INVALID}" "initial_convergence.rust_tip_path does not report an absent tip" public mesh-tip-present
sn_check "restart pre-restart height below initial convergence" "${SN_INVALID}" "rust_restart.pre_restart_height is below initial_convergence.height" rust-restart restart-below
sn_check "restart initial rust tip from the restarted endpoint" "${SN_INVALID}" "initial_convergence.rust_tip_path sidecar identity mismatch" rust-restart restart-new-endpoint
sn_check "partition common block not above initial convergence" "${SN_INVALID}" "partition common block height is not above initial_convergence.height" partition-heal-reorg partition-not-above
expect_pass_contains "restart initial convergence at the pre-restart height" "PASS: mixed_client_rust_restart report structurally accepted" check_report "${TMP_ROOT}/sn-restart-at-pre-restart-report.json" offline rust-restart
sn_cases=0
while IFS=$'\t' read -r sn_mode sn_name sn_token sn_needle; do
  sn_check "sidecar ${sn_name}" "${sn_token}" "${sn_needle}" "${sn_mode}" "${sn_name}"
  sn_cases=$((sn_cases + 1))
done < "${TMP_ROOT}/sn-cases.tsv"
(( sn_cases == 198 )) || { echo "FAIL: sidecar case table ran ${sn_cases} rows, want 198" >&2; exit 1; }
sn_output="$(check_report "${TMP_ROOT}/sn-tx-accept-top-extra-report.json" offline producer-tx 2>&1)" && { echo "FAIL: sidecar extra key report should fail" >&2; exit 1; }
[[ "$(combined_report_reason_token <<<"${sn_output}")" == store_neutrality_sidecar_invalid ]] || { echo "FAIL: combined token for sidecar keys mismatch: $(combined_report_reason_token <<<"${sn_output}")" >&2; exit 1; }
printf 'PASS: mixed-client mesh check-report public/internal boundaries are covered\n'
