#!/usr/bin/env bash
# RUB-1078: cross-client datadir writer-lock evidence.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEV_ENV="${REPO_ROOT}/scripts/dev-env.sh"
MODE="${1:-}"
[[ $# == 1 && ( "${MODE}" == datadir || "${MODE}" == atomic-parent ) ]] || {
  printf 'usage: %s {datadir|atomic-parent}\n' "${0##*/}" >&2
  exit 2
}
for tool in cmp cp grep ln mkfifo python3 tr; do
  command -v "${tool}" >/dev/null 2>&1 || { printf 'missing required tool: %s\n' "${tool}" >&2; exit 1; }
done

# shellcheck source=scripts/devnet-process-common.sh
source "${REPO_ROOT}/scripts/devnet-process-common.sh"
rubin_process_init rubin-storage-lock-parity
ART="${RUBIN_PROCESS_ARTIFACT_ROOT}"
RESTORE_MODE_DIR=""
storage_lock_exit_trap() {
  local status=$? cleanup_status=0
  [[ -z "${RESTORE_MODE_DIR}" ]] || chmod 0700 "${RESTORE_MODE_DIR}" 2>/dev/null || true
  rubin_process_cleanup "${status}" || cleanup_status=$?
  (( status != 0 )) && exit "${status}"
  exit "${cleanup_status}"
}
trap storage_lock_exit_trap EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
node_bin() {
  case "$1" in
    go) printf '%s\n' "${GO_NODE}" ;;
    rust) printf '%s\n' "${RUST_NODE}" ;;
    *) fail "unknown implementation: $1" ;;
  esac
}

# Sorted recursive lstat inventory: path, kind, regular SHA-256 or symlink
# target, size, mode, device/inode/link count and mtime. atime/ctime are absent.
snapshot_datadir() {
  python3 - "$1" <<'PY'
import hashlib
import os
import stat
import sys

root = os.path.abspath(sys.argv[1])
if not os.path.isdir(root):
    raise SystemExit(f"snapshot root is not a directory: {root}")
def digest(path):
    value = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            value.update(chunk)
    return value.hexdigest()
def row(path):
    st = os.lstat(path)
    if stat.S_ISREG(st.st_mode):
        payload = "sha256:" + digest(path)
    elif stat.S_ISLNK(st.st_mode):
        payload = "target:" + os.readlink(path)
    else:
        payload = "-"
    return "\t".join((os.path.relpath(path, root), stat.filemode(st.st_mode)[0], payload,
        str(st.st_size), format(stat.S_IMODE(st.st_mode), "04o"), str(st.st_dev),
        str(st.st_ino), str(st.st_nlink), str(st.st_mtime_ns)))
rows, pending = [], [root]
while pending:
    path = pending.pop()
    st = os.lstat(path)
    rows.append(row(path))
    if stat.S_ISDIR(st.st_mode):
        with os.scandir(path) as directory:
            pending.extend(sorted((entry.path for entry in directory), key=os.fsencode))
sys.stdout.write("\n".join(sorted(rows)) + "\n")
PY
}
take_snapshot() { snapshot_datadir "$2" >"$3" || fail "$1: snapshot failed for $2"; }
assert_same_snapshot() { cmp -s "$2" "$3" || fail "$1: datadir snapshot changed (before=$2 after=$3)"; }
assert_same_atomic_semantic_snapshot() {
  python3 - "$2" "$3" <<'PY' || fail "$1: authoritative snapshot changed (before=$2 after=$3)"
import sys

def semantic_rows(path):
    rows = set()
    with open(path, encoding="utf-8") as source:
        for raw in source:
            fields = raw.rstrip("\n").split("\t")
            if len(fields) != 9:
                raise SystemExit(f"malformed snapshot row in {path}: {raw!r}")
            rows.add(tuple(fields[index] for index in (0, 1, 2, 3, 4, 7)))
    return rows

before, after = semantic_rows(sys.argv[1]), semantic_rows(sys.argv[2])
if before != after:
    raise SystemExit("semantic snapshot rows differ")
PY
}
assert_exact_file() {
  local expected="${ART}/markers/$1.expected"
  printf '%s\n' "$3" >"${expected}"
  cmp -s "${expected}" "$2" || fail "$1: unexpected file content: $2"
}
assert_absent() { [[ ! -e "$2" && ! -L "$2" ]] || fail "$1: unexpected artifact exists: $2"; }

mkdir -p "${ART}/markers" "${ART}/fixtures"
GO_NODE="${ART}/rubin-node-go"
RUST_NODE="${ART}/rubin-node-rust"
GO_LOCK_TEST="${ART}/go-filelock.test"
RUST_LOCK_TEST="${ART}/rust-filelock.test"
BASH_BIN="${BASH}"
[[ "${BASH_BIN}" == /* && -x "${BASH_BIN}" ]] || fail 'current Bash binary is not absolute and executable'

echo 'Building Go node and test-only filelock protocol from this checkout'
"${DEV_ENV}" -- go -C "${REPO_ROOT}/clients/go" build -o "${GO_NODE}" ./cmd/rubin-node
"${DEV_ENV}" -- go -C "${REPO_ROOT}/clients/go" test -c -o "${GO_LOCK_TEST}" ./internal/filelock
rust_artifact() {
  python3 - "$1" "$2" <<'PY'
import json
import sys

path, want_test = sys.argv[1], sys.argv[2] == "test"
found = None
try:
    with open(path, encoding="utf-8") as source:
        lines = list(source)
except (OSError, UnicodeError) as exc:
    raise SystemExit(f"cannot read Cargo JSONL: {exc}")
for line_number, raw in enumerate(lines, 1):
        try:
            event = json.loads(raw)
        except (json.JSONDecodeError, RecursionError) as exc:
            raise SystemExit(f"malformed Cargo JSONL at line {line_number}: {exc}")
        if not isinstance(event, dict):
            raise SystemExit(f"Cargo JSONL event at line {line_number} is not an object")
        target = event.get("target", {})
        profile = event.get("profile", {})
        if not isinstance(target, dict) or not isinstance(profile, dict):
            raise SystemExit(f"Cargo JSONL event at line {line_number} has invalid target/profile")
        kind, is_test, executable = target.get("kind", []), profile.get("test"), event.get("executable")
        if not isinstance(kind, list) or any(not isinstance(value, str) for value in kind):
            raise SystemExit(f"Cargo JSONL event at line {line_number} has invalid target.kind")
        if is_test is not None and not isinstance(is_test, bool):
            raise SystemExit(f"Cargo JSONL event at line {line_number} has invalid profile.test")
        if executable is not None and not isinstance(executable, str):
            raise SystemExit(f"Cargo JSONL event at line {line_number} has invalid executable")
        if (event.get("reason") == "compiler-artifact" and target.get("name") == "rubin-node"
                and "bin" in kind and bool(is_test) == want_test and executable):
            found = executable
if found is None:
    raise SystemExit("no rubin-node binary artifact")
print(found)
PY
}
echo 'Building Rust node and test-only filelock protocol from this checkout'
RUST_BUILD_LOG="${ART}/rust-node-build.jsonl"
"${DEV_ENV}" -- cargo build --manifest-path "${REPO_ROOT}/clients/rust/Cargo.toml" -p rubin-node \
  --message-format=json-render-diagnostics >"${RUST_BUILD_LOG}"
RUST_NODE_SOURCE="$(rust_artifact "${RUST_BUILD_LOG}" node)" || fail 'cargo did not report the Rust node binary'
[[ -x "${RUST_NODE_SOURCE}" ]] || fail "cargo-reported Rust node is not executable: ${RUST_NODE_SOURCE}"
cp -- "${RUST_NODE_SOURCE}" "${RUST_NODE}"
RUST_TEST_LOG="${ART}/rust-filelock-test-build.jsonl"
"${DEV_ENV}" -- cargo test --manifest-path "${REPO_ROOT}/clients/rust/Cargo.toml" -p rubin-node --no-run \
  --message-format=json-render-diagnostics >"${RUST_TEST_LOG}"
RUST_TEST_SOURCE="$(rust_artifact "${RUST_TEST_LOG}" test)" || fail 'cargo did not report the Rust filelock test binary'
[[ -x "${RUST_TEST_SOURCE}" ]] || fail "cargo-reported Rust test binary is not executable: ${RUST_TEST_SOURCE}"
cp -- "${RUST_TEST_SOURCE}" "${RUST_LOCK_TEST}"

wait_managed_exit() {
  local marker="$1" label="$2" pid="$3"
  local line="" extra=""
  rubin_process_wait_for_log "${marker}" 'exit=' 30 "${pid}" || fail "${label}: process did not publish an exit marker"
  {
    IFS= read -r line || fail "${label}: malformed exit marker"
    if IFS= read -r extra || [[ -n "${extra}" ]]; then
      fail "${label}: malformed exit marker"
    fi
  } <"${marker}"
  case "${line}" in
    exit=0) return 0 ;;
    exit=2) return 2 ;;
    *) fail "${label}: invalid exit marker ${line}" ;;
  esac
}
HOLDER_PID=""
HOLDER_RELEASE=""
HOLDER_STATUS=""
start_holder() {
  local impl="$1" label="$2" lock="$3" log="${ART}/${2}.${1}.holder.log" ready="${ART}/markers/${2}.${1}.ready" status="${ART}/markers/${2}.${1}.holder.status"
  HOLDER_RELEASE="${ART}/markers/${label}.${impl}.release"
  # shellcheck disable=SC2016 # The wrapper owns these positional parameters.
  case "${impl}" in
    go) rubin_process_start "${log}" "${BASH_BIN}" -c '
set -euo pipefail
status="$1"
shift
rc=0
"$@" || rc=$?
printf "exit=%s\n" "${rc}" >"${status}.tmp.$$"
mv -f -- "${status}.tmp.$$" "${status}"
exit "${rc}"
' rubin-holder-status "${status}" env RUBIN_FILELOCK_PROTOCOL_MODE=holder \
      RUBIN_FILELOCK_PROTOCOL_LOCK_PATH="${lock}" RUBIN_FILELOCK_PROTOCOL_READY_PATH="${ready}" \
      RUBIN_FILELOCK_PROTOCOL_RELEASE_PATH="${HOLDER_RELEASE}" "${GO_LOCK_TEST}" \
      -test.run '^TestFileLockExternalProtocol$' -test.count=1 ;;
    rust) rubin_process_start "${log}" "${BASH_BIN}" -c '
set -euo pipefail
status="$1"
shift
rc=0
"$@" || rc=$?
printf "exit=%s\n" "${rc}" >"${status}.tmp.$$"
mv -f -- "${status}.tmp.$$" "${status}"
exit "${rc}"
' rubin-holder-status "${status}" env RUBIN_FILE_LOCK_PROTOCOL_MODE=holder \
      RUBIN_FILE_LOCK_PROTOCOL_LOCK_PATH="${lock}" RUBIN_FILE_LOCK_PROTOCOL_READY_PATH="${ready}" \
      RUBIN_FILE_LOCK_PROTOCOL_RELEASE_PATH="${HOLDER_RELEASE}" "${RUST_LOCK_TEST}" \
      file_lock::tests::external_file_lock_protocol --exact --nocapture ;;
    *) fail "${label}: unknown holder ${impl}" ;;
  esac || fail "${label}: ${impl} holder start"
  HOLDER_PID="${RUBIN_PROCESS_LAST_PID}"
  HOLDER_STATUS="${status}"
  rubin_process_wait_for_log "${ready}" ready 15 "${HOLDER_PID}" || fail "${label}: holder did not publish ready marker"
  assert_exact_file "${label}.${impl}.ready" "${ready}" ready
}
release_holder() {
  local rc=0
  printf 'release\n' >"${HOLDER_RELEASE}"
  wait_managed_exit "${HOLDER_STATUS}" "$1: holder release" "${HOLDER_PID}" || rc=$?
  (( rc == 0 )) || fail "$1: holder release exited ${rc}"
}
crash_holder() {
  rubin_process_stop_pid "${HOLDER_PID}" || fail "$1: holder stop failed"
  rubin_process_is_alive "${HOLDER_PID}" && fail "$1: holder survived stop"
  return 0
}
protocol_challenger() {
  local impl="$1" label="$2" lock="$3" want="$4" result="${ART}/markers/${2}.${1}.result" rc=0 got
  case "${impl}" in
    go) env RUBIN_FILELOCK_PROTOCOL_MODE=challenger RUBIN_FILELOCK_PROTOCOL_LOCK_PATH="${lock}" \
      RUBIN_FILELOCK_PROTOCOL_RESULT_PATH="${result}" "${GO_LOCK_TEST}" -test.run '^TestFileLockExternalProtocol$' \
      -test.count=1 >"${ART}/${label}.${impl}.stdout" 2>"${ART}/${label}.${impl}.stderr" || rc=$? ;;
    rust) env RUBIN_FILE_LOCK_PROTOCOL_MODE=challenger RUBIN_FILE_LOCK_PROTOCOL_LOCK_PATH="${lock}" \
      RUBIN_FILE_LOCK_PROTOCOL_RESULT_PATH="${result}" "${RUST_LOCK_TEST}" file_lock::tests::external_file_lock_protocol \
      --exact --nocapture >"${ART}/${label}.${impl}.stdout" 2>"${ART}/${label}.${impl}.stderr" || rc=$? ;;
    *) fail "${label}: unknown challenger ${impl}" ;;
  esac
  (( rc == 0 )) || fail "${label}: ${impl} protocol exited ${rc}"
  [[ -f "${result}" ]] || fail "${label}: ${impl} did not write a result marker"
  got="$(tr -d '[:space:]' <"${result}")"
  [[ "${got}" == "${want}" ]] || fail "${label}: ${impl} result=${got:-<empty>} want=${want}"
}
assert_contention() {
  local holder="$1" challenger="$2" label="$3" dir="${ART}/fixtures/${3}"
  mkdir -p "${dir}"
  start_holder "${holder}" "${label}" "${dir}/.rubin.lock"
  protocol_challenger "${challenger}" "${label}.challenger" "${dir}/.rubin.lock" contended
  release_holder "${label}"
}
assert_alias_contention() {
  local holder="$1" challenger="$2" label="$3" target="${ART}/fixtures/${3}-target" alias="${ART}/fixtures/${3}-alias"
  mkdir -p "${target}"
  ln -s "${target}" "${alias}"
  start_holder "${holder}" "${label}" "${target}/.rubin.lock"
  protocol_challenger "${challenger}" "${label}.challenger" "${alias}/.rubin.lock" contended
  release_holder "${label}"
}
assert_invalid() {
  protocol_challenger go "$1" "$2" invalid_or_unopenable
  protocol_challenger rust "$1" "$2" invalid_or_unopenable
}

echo 'Checking test-only same-client and cross-client lock contention'
assert_contention go go same-go
assert_contention rust rust same-rust
assert_contention go rust go-holds-rust-protocol
assert_contention rust go rust-holds-go-protocol
REACQUIRE_DIR="${ART}/fixtures/reacquire"
mkdir -p "${REACQUIRE_DIR}"
start_holder go release-reacquire "${REACQUIRE_DIR}/.rubin.lock"
release_holder release-reacquire
[[ -f "${REACQUIRE_DIR}/.rubin.lock" && ! -s "${REACQUIRE_DIR}/.rubin.lock" ]] || fail 'released lock is not persistent and empty'
protocol_challenger rust release-reacquire.reopen "${REACQUIRE_DIR}/.rubin.lock" acquired
CRASH_DIR="${ART}/fixtures/crash-reacquire"
mkdir -p "${CRASH_DIR}"
start_holder rust crash-reacquire "${CRASH_DIR}/.rubin.lock"
crash_holder crash-reacquire
protocol_challenger go crash-reacquire.reopen "${CRASH_DIR}/.rubin.lock" acquired
assert_alias_contention go rust parent-alias-go-rust
assert_alias_contention rust go parent-alias-rust-go
DISTINCT_A="${ART}/fixtures/distinct-a"
DISTINCT_B="${ART}/fixtures/distinct-b"
mkdir -p "${DISTINCT_A}" "${DISTINCT_B}"
start_holder go distinct-roots "${DISTINCT_A}/.rubin.lock"
protocol_challenger rust distinct-roots.challenger "${DISTINCT_B}/.rubin.lock" acquired
release_holder distinct-roots

echo 'Checking unsafe lock leaves, permission denial, and strict missing parents'
INVALID_DIR="${ART}/fixtures/invalid-leaves"
mkdir -p "${INVALID_DIR}"
: >"${INVALID_DIR}/target"
ln -s "${INVALID_DIR}/target" "${INVALID_DIR}/symlink"
ln -s "${INVALID_DIR}/missing-target" "${INVALID_DIR}/dangling-symlink"
mkdir "${INVALID_DIR}/directory"
mkfifo "${INVALID_DIR}/fifo"
printf x >"${INVALID_DIR}/nonempty"
: >"${INVALID_DIR}/hardlink-source"
ln "${INVALID_DIR}/hardlink-source" "${INVALID_DIR}/hardlink"
for leaf in symlink dangling-symlink directory fifo nonempty hardlink; do assert_invalid "invalid-${leaf}" "${INVALID_DIR}/${leaf}"; done
(( EUID != 0 )) || fail 'permission-denial leaf is mandatory but cannot be exercised as uid 0 without a portable unprivileged runner'
RESTORE_MODE_DIR="${INVALID_DIR}/no-access"
mkdir "${RESTORE_MODE_DIR}"
chmod 000 "${RESTORE_MODE_DIR}"
assert_invalid invalid-permission "${RESTORE_MODE_DIR}/.rubin.lock"
chmod 0700 "${RESTORE_MODE_DIR}"
RESTORE_MODE_DIR=""
MISSING_PARENT="${ART}/fixtures/missing-parent/child"
assert_invalid missing-parent "${MISSING_PARENT}/.rubin.lock"
[[ ! -e "${ART}/fixtures/missing-parent" ]] || fail 'strict missing lock parent was created'

LIVE_PID=""
LIVE_RPC=""
start_live() {
  local impl="$1" datadir="$2" label="$3" create="${4:-}" bin rpc log="${ART}/${3}.${1}.live.log"
  bin="$(node_bin "${impl}")"
  if [[ "${create}" == create ]]; then
    rubin_process_start "${log}" "${bin}" --network devnet --datadir "${datadir}" --create-store --mine-blocks 1 --bind 127.0.0.1:0 --rpc-bind 127.0.0.1:0
  else
    rubin_process_start "${log}" "${bin}" --network devnet --datadir "${datadir}" --bind 127.0.0.1:0 --rpc-bind 127.0.0.1:0
  fi || fail "${label}: ${impl} live start"
  LIVE_PID="${RUBIN_PROCESS_LAST_PID}"
  rubin_process_wait_for_log "${log}" 'rpc: listening=' 30 "${LIVE_PID}" || fail "${label}: RPC banner"
  rpc="$(rubin_process_extract_rpc_addr "${log}")" || fail "${label}: RPC address"
  rubin_process_wait_for_rpc_ready "${rpc}" 30 || fail "${label}: RPC readiness"
  LIVE_RPC="${rpc}"
}
stop_live() {
  rubin_process_stop_pid "${LIVE_PID}" || fail "$1: live stop failed"
  rubin_process_is_alive "${LIVE_PID}" && fail "$1: live node survived stop"
  return 0
}
initialize_store() {
  start_live "$1" "$2" "$3" create
  stop_live "$3"
  [[ -f "$2/.rubin.lock" && ! -s "$2/.rubin.lock" ]] || fail "$3: initialized store has no valid persistent lock"
}
assert_fresh_create_reclaims_datadir_scratch() {
  local impl="$1" label="fresh-create-${1}" datadir="${ART}/fixtures/fresh-create-${1}"
  mkdir -p "${datadir}"
  printf 'stale datadir scratch\n' >"${datadir}/${ATOMIC_SCRATCH_LEAF}"
  initialize_store "${impl}" "${datadir}" "${label}"
  assert_absent "${label}: stale datadir scratch" "${datadir}/${ATOMIC_SCRATCH_LEAF}"
  assert_store_readable "${label}" "${datadir}"
}
RUN_RC=0
RUN_OUT=""
RUN_ERR=""
run_node() {
  local impl="$1" label="$2"
  shift 2
  RUN_OUT="${ART}/${label}.${impl}.stdout"
  RUN_ERR="${ART}/${label}.${impl}.stderr"
  RUN_RC=0
  "$(node_bin "${impl}")" "$@" >"${RUN_OUT}" 2>"${RUN_ERR}" || RUN_RC=$?
}
assert_contention_error() { assert_exact_file "$1" "${RUN_ERR}" "datadir is already in use by another rubin-node: $2"; }
assert_live_cross_contention() {
  local holder="$1" challenger="$2" label="$3" datadir="${ART}/fixtures/${3}" before="${ART}/${3}.before" after="${ART}/${3}.after"
  initialize_store "${holder}" "${datadir}" "${label}.init"
  start_live "${holder}" "${datadir}" "${label}.holder"
  take_snapshot "${label}.before" "${datadir}" "${before}"
  run_node "${challenger}" "${label}.challenger" --network devnet --datadir "${datadir}" --mine-blocks 1 --mine-exit --bind 127.0.0.1:0 --rpc-bind 127.0.0.1:0
  [[ "${RUN_RC}" == 2 ]] || fail "${label}: contender exit=${RUN_RC}, want=2"
  assert_contention_error "${label}.challenger.contention" "${datadir}"
  take_snapshot "${label}.after" "${datadir}" "${after}"
  assert_same_snapshot "${label}: contender changed held datadir" "${before}" "${after}"
  stop_live "${label}.holder"
}
assert_create_path_contention() {
  local holder="$1" challenger="$2" label="$3" datadir="${ART}/fixtures/${3}"
  mkdir -p "${datadir}"
  start_holder "${holder}" "${label}" "${datadir}/.rubin.lock"
  run_node "${challenger}" "${label}.challenger" --network devnet --datadir "${datadir}" --create-store --mine-blocks 1 --mine-exit
  [[ "${RUN_RC}" == 2 ]] || fail "${label}: create contender exit=${RUN_RC}, want=2"
  assert_contention_error "${label}.challenger.contention" "${datadir}"
  assert_absent "${label}" "${datadir}/blockstore"
  assert_absent "${label}" "${datadir}/chainstate.json"
  release_holder "${label}"
}

RACE_PID=""; RACE_ERR=""; RACE_STATUS=""
start_race_node() {
  local impl="$1" label="$2" datadir="$3" gate="$4" bin ready out err log status
  bin="$(node_bin "${impl}")"
  [[ "${bin}" == /* && -x "${bin}" ]] || fail "${label}: ${impl} race binary is not absolute and executable"
  ready="${ART}/markers/${label}.${impl}.race.ready"
  out="${ART}/${label}.${impl}.race.stdout"
  err="${ART}/${label}.${impl}.race.stderr"
  log="${ART}/${label}.${impl}.race.log"
  status="${ART}/markers/${label}.${impl}.race.status"
  # shellcheck disable=SC2016 # The wrapper owns these positional parameters.
  rubin_process_start "${log}" "${BASH_BIN}" -c '
set -euo pipefail
ready="$1"; gate="$2"; out="$3"; err="$4"; status="$5"
shift 5
[[ -p "${gate}" ]] || exit 2
printf "ready\n" >"${ready}"
IFS= read -r token <"${gate}"
[[ "${token}" == release ]] || exit 2
rc=0
"$@" >"${out}" 2>"${err}" || rc=$?
printf "exit=%s\n" "${rc}" >"${status}.tmp.$$"
mv -f -- "${status}.tmp.$$" "${status}"
exit "${rc}"
' rubin-race-gate "${ready}" "${gate}" "${out}" "${err}" "${status}" "${bin}" --network devnet --datadir "${datadir}" --create-store --mine-blocks 1 --mine-exit ||
    fail "${label}: ${impl} race start"
  RACE_PID="${RUBIN_PROCESS_LAST_PID}"
  RACE_ERR="${err}"
  RACE_STATUS="${status}"
  rubin_process_wait_for_log "${ready}" ready 15 "${RACE_PID}" || fail "${label}: ${impl} race process did not reach barrier"
  assert_exact_file "${label}.${impl}.race.ready" "${ready}" ready
}
release_race_barrier() {
  local a="$1" b="$2" apid bpid arc=0 brc=0
  printf 'release\n' >"${a}" & apid=$!
  printf 'release\n' >"${b}" & bpid=$!
  wait "${apid}" || arc=$?
  wait "${bpid}" || brc=$?
  (( arc == 0 && brc == 0 )) || fail "create race barrier release failed (first=${arc} second=${brc})"
}
assert_store_readable() {
  local label="$1" datadir="$2" impl
  [[ -d "${datadir}/blockstore" && -f "${datadir}/chainstate.json" && -f "${datadir}/.rubin.lock" && ! -s "${datadir}/.rubin.lock" ]] ||
    fail "${label}: winner did not leave one readable store, chainstate, and persistent lock"
  for impl in go rust; do
    run_node "${impl}" "${label}.${impl}.read" --network devnet --datadir "${datadir}" --dry-run
    [[ "${RUN_RC}" == 0 && ! -s "${RUN_ERR}" ]] || fail "${label}: ${impl} cannot read winning store (exit=${RUN_RC})"
    grep -F -q 'blockstore:' "${RUN_OUT}" || fail "${label}: ${impl} read produced no blockstore observation"
  done
}
post_winner_create_refusal() {
  run_node "$1" "$2.$1.post-create" --network devnet --datadir "$3" --create-store --mine-blocks 1 --mine-exit
  [[ "${RUN_RC}" == 2 ]] || fail "$2: $1 post-winner create exit=${RUN_RC}, want=2"
  assert_exact_file "$2.$1.post-create.root-exists" "${RUN_ERR}" "blockstore create failed: blockstore root already exists: $3/blockstore"
}
assert_create_race() {
  local first="$1" second="$2" label="$3" datadir="${ART}/fixtures/${3}" first_gate second_gate first_pid second_pid first_err second_err first_status second_status first_rc=0 second_rc=0 winner loser loser_err actual before after
  assert_absent "${label}: initial datadir" "${datadir}"
  first_gate="${ART}/markers/${label}.${first}.gate"
  second_gate="${ART}/markers/${label}.${second}.gate"
  mkfifo "${first_gate}" "${second_gate}" || fail "${label}: cannot create FIFO race barrier"
  start_race_node "${first}" "${label}" "${datadir}" "${first_gate}"
  first_pid="${RACE_PID}"; first_err="${RACE_ERR}"; first_status="${RACE_STATUS}"
  start_race_node "${second}" "${label}" "${datadir}" "${second_gate}"
  second_pid="${RACE_PID}"; second_err="${RACE_ERR}"; second_status="${RACE_STATUS}"
  release_race_barrier "${first_gate}" "${second_gate}"
  wait_managed_exit "${first_status}" "${label}: ${first} race" "${first_pid}" || first_rc=$?
  wait_managed_exit "${second_status}" "${label}: ${second} race" "${second_pid}" || second_rc=$?
  printf '%s\n' "${first_rc}" >"${ART}/${label}.${first}.race.exit"
  printf '%s\n' "${second_rc}" >"${ART}/${label}.${second}.race.exit"
  if (( first_rc == 0 && second_rc == 2 )); then winner="${first}"; loser="${second}"; loser_err="${second_err}";
  elif (( first_rc == 2 && second_rc == 0 )); then winner="${second}"; loser="${first}"; loser_err="${first_err}";
  else fail "${label}: race exits must be exactly one 0 and one 2 (first=${first_rc} second=${second_rc})"; fi
  printf '%s\n' "${winner}" >"${ART}/${label}.winner"
  actual="$(<"${loser_err}")"
  case "${actual}" in
    "datadir is already in use by another rubin-node: ${datadir}") assert_exact_file "${label}.${loser}.race.contention" "${loser_err}" "${actual}" ;;
    "blockstore create failed: blockstore root already exists: ${datadir}/blockstore") assert_exact_file "${label}.${loser}.race.root-exists" "${loser_err}" "${actual}" ;;
    *) fail "${label}: ${loser} race loser emitted no contract-legal refusal" ;;
  esac
  before="${ART}/${label}.post.before"; after="${ART}/${label}.post.after"
  take_snapshot "${label}.post.before" "${datadir}" "${before}"
  post_winner_create_refusal go "${label}" "${datadir}"
  post_winner_create_refusal rust "${label}" "${datadir}"
  take_snapshot "${label}.post.after" "${datadir}" "${after}"
  assert_same_snapshot "${label}: post-winner create mutated store" "${before}" "${after}"
  assert_store_readable "${label}" "${datadir}"
}
assert_reader() {
  local reader="$1" mode="$2" label="$3" datadir="$4" holder="${5:-}" before="${ART}/${3}.${1}.before" after="${ART}/${3}.${1}.after" needle
  take_snapshot "${label}.${reader}.before" "${datadir}" "${before}"
  [[ -z "${holder}" ]] || rubin_process_is_alive "${holder}" || fail "${label}: holder died before ${reader} ${mode}"
  case "${mode}" in
    dry-run) run_node "${reader}" "${label}" --network devnet --datadir "${datadir}" --dry-run; needle='"data_dir"' ;;
    legacy) run_node "${reader}" "${label}" --network devnet --datadir "${datadir}" --legacy-exposure-scan --legacy-suite-id 1; needle='"report_version"' ;;
    *) fail "${label}: unknown read-only mode ${mode}" ;;
  esac
  [[ -z "${holder}" ]] || rubin_process_is_alive "${holder}" || fail "${label}: holder died after ${reader} ${mode}"
  [[ "${RUN_RC}" == 0 && ! -s "${RUN_ERR}" ]] || fail "${label}: ${reader} ${mode} failed (exit=${RUN_RC})"
  grep -F -q "${needle}" "${RUN_OUT}" || fail "${label}: ${reader} ${mode} output missing ${needle}"
  take_snapshot "${label}.${reader}.after" "${datadir}" "${after}"
  assert_same_snapshot "${label}: ${reader} ${mode} mutated datadir" "${before}" "${after}"
}
assert_readers_with_holder() {
  local holder="$1" label="$2" datadir="${ART}/fixtures/${2}" mode reader
  initialize_store "${holder}" "${datadir}" "${label}.init"
  start_live "${holder}" "${datadir}" "${label}.holder"
  for mode in dry-run legacy; do for reader in go rust; do assert_reader "${reader}" "${mode}" "${label}.${reader}-${mode}" "${datadir}" "${LIVE_PID}"; done; done
  stop_live "${label}.holder"
}
assert_readers_without_lock() {
  local label=readonly-no-lock datadir="${ART}/fixtures/readonly-no-lock" lock="${ART}/fixtures/readonly-no-lock/.rubin.lock" mode reader
  initialize_store go "${datadir}" "${label}.init"
  [[ -f "${lock}" && ! -s "${lock}" ]] || fail "${label}: prepared store has no removable lock"
  rm -f -- "${lock}"
  assert_absent "${label}: pre-reader lock" "${lock}"
  for mode in dry-run legacy; do for reader in go rust; do assert_reader "${reader}" "${mode}" "${label}.${reader}-${mode}" "${datadir}"; done; done
  assert_absent "${label}: readers created a lock" "${lock}"
}

ATOMIC_LOCK_LEAF='.rubin-atomic-write.lock'
ATOMIC_SCRATCH_LEAF='.rubin-atomic-write.tmp'
ATOMIC_PARENTS=()
set_atomic_parents() {
  local datadir="$1" leaf
  ATOMIC_PARENTS=("${datadir}")
  for leaf in blockstore blockstore/blocks blockstore/headers blockstore/undo; do
    ATOMIC_PARENTS+=("${datadir}/${leaf}")
  done
}
assert_atomic_reserved_state() {
  local label="$1" want_scratch="$2" want_lock="$3" parent scratch_count=0 lock_count=0
  for parent in "${ATOMIC_PARENTS[@]}"; do
    [[ -d "${parent}" ]] || fail "${label}: fixed atomic parent is absent: ${parent}"
    if [[ -e "${parent}/${ATOMIC_SCRATCH_LEAF}" || -L "${parent}/${ATOMIC_SCRATCH_LEAF}" ]]; then (( scratch_count += 1 )); fi
    if [[ -e "${parent}/${ATOMIC_LOCK_LEAF}" || -L "${parent}/${ATOMIC_LOCK_LEAF}" ]]; then (( lock_count += 1 )); fi
  done
  [[ "${scratch_count}" == "${want_scratch}" ]] || fail "${label}: atomic scratch count=${scratch_count}, want=${want_scratch} across five fixed parents"
  [[ "${lock_count}" == "${want_lock}" ]] || fail "${label}: atomic lock count=${lock_count}, want=${want_lock} across five fixed parents"
}
canonical_live_block_path() {
  python3 - "$1/blockstore/index.json" "$1/blockstore/blocks" <<'PY'
import base64, binascii, json, pathlib, sys
def require(condition, message):
    if not condition:
        raise SystemExit(message)
# RUB-1134: unwrap the store_envelope_v1 frame (the node verifies the
# domain-tagged checksum on open); every malformed shape stays a deterministic
# SystemExit rather than a traceback.
try:
    envelope = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
    require(isinstance(envelope, dict), "canonical block index envelope is not an object")
    require(envelope.get("version") == 1, "canonical block index envelope is not version 1")
    require(isinstance(envelope.get("payload_b64"), str), "canonical block index envelope has no payload")
    index = json.loads(base64.b64decode(envelope["payload_b64"], validate=True))
except (OSError, UnicodeError, json.JSONDecodeError, RecursionError, binascii.Error, ValueError) as exc:
    raise SystemExit(f"cannot read canonical block index: {exc}")
require(isinstance(index, dict), "canonical block index root is not an object")
canonical = index.get("canonical")
require(isinstance(canonical, list) and canonical, "canonical block index has no live block")
block_hash = canonical[-1]
require(isinstance(block_hash, str) and len(block_hash) == 64 and all(ch in "0123456789abcdef" for ch in block_hash), "canonical block index has an invalid final hash")
path = pathlib.Path(sys.argv[2]) / f"{block_hash}.bin"
require(path.is_file(), f"canonical block destination is absent: {path}")
print(path)
PY
}
seed_atomic_residues() {
  local label="$1" datadir="$2" live_block="$3" parent
  set_atomic_parents "${datadir}"
  [[ -f "${live_block}" ]] || fail "${label}: live block for hardlink residue is absent"
  for parent in "${ATOMIC_PARENTS[@]}"; do
    assert_absent "${label}: preseed scratch" "${parent}/${ATOMIC_SCRATCH_LEAF}"
    rm -f -- "${parent}/${ATOMIC_LOCK_LEAF}" || fail "${label}: cannot remove exact test lock leaf"
    assert_absent "${label}: cleared lock" "${parent}/${ATOMIC_LOCK_LEAF}"
  done
  ln -- "${live_block}" "${ATOMIC_PARENTS[0]}/${ATOMIC_SCRATCH_LEAF}" || fail "${label}: root hardlink residue"
  [[ "${live_block}" -ef "${ATOMIC_PARENTS[0]}/${ATOMIC_SCRATCH_LEAF}" ]] ||
    fail "${label}: root scratch is not a hardlink to the live destination"
  for parent in "${ATOMIC_PARENTS[@]:1}"; do
    printf '%s\n' "${label}: residue" >"${parent}/${ATOMIC_SCRATCH_LEAF}"
  done
  assert_atomic_reserved_state "${label}: seeded exact residues" 5 0
}
RPC_RESULT=""
rpc_result() {
  local label="$1" rpc="$2" method="$3" route="$4"
  RPC_RESULT="${ART}/${label}.${route#/}.json"
  python3 - "${rpc}" "${method}" "${route}" >"${RPC_RESULT}" <<'PY'
import json, socket, sys, time, urllib.error, urllib.request
started, method, route = time.monotonic(), sys.argv[2], sys.argv[3]
data = b"{}" if method == "POST" else None
request = urllib.request.Request(f"http://{sys.argv[1]}{route}", data=data, method=method)
if data is not None:
    request.add_header("Content-Type", "application/json")
try:
    with urllib.request.urlopen(request, timeout=10) as response:
        status, raw = response.status, response.read()
except urllib.error.HTTPError as exc:
    status, raw = exc.code, exc.read()
except (urllib.error.URLError, socket.timeout, TimeoutError, OSError) as exc:
    raise SystemExit(f"HTTP transport failed for {route}: {exc}")
try:
    text = raw.decode("utf-8")
except UnicodeError as exc:
    raise SystemExit(f"HTTP body for {route} is not UTF-8: {exc}")
try:
    body = json.loads(text)
except (json.JSONDecodeError, RecursionError) as exc:
    raise SystemExit(f"HTTP body for {route} is malformed JSON: {exc}")
print(json.dumps({"body": body, "elapsed_ms": int((time.monotonic() - started) * 1000), "status": status}, sort_keys=True))
PY
}
validate_atomic_rpc() {
  local label="$1" mode="$2" result="$3" arg1="${4:-}" arg2="${5:-}" output="${6:-/dev/null}"
  python3 - "${mode}" "${result}" "${arg1}" "${arg2}" >"${output}" <<'PY' || fail "${label}: ${mode} RPC contract"
import json, pathlib, re, sys
def require(condition, message):
    if not condition:
        raise SystemExit(message)
def load(path, label):
    try:
        value = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise SystemExit(f"{label} is unreadable: {exc}")
    require(isinstance(value, dict), f"{label} root is not an object")
    return value
mode, record = sys.argv[1], load(sys.argv[2], f"{sys.argv[1]} response")
require(set(record) == {"body", "elapsed_ms", "status"}, f"{mode} transport keys changed")
require(type(record["elapsed_ms"]) is int and 0 <= record["elapsed_ms"] <= 10000, f"{mode} response was not bounded")
body = record["body"]
if mode == "tip":
    require(record["status"] == 200 and isinstance(body, dict) and set(body) == {"has_tip", "height", "tip_hash", "best_known_height", "in_ibd"}, "tip HTTP disposition/root/keys changed")
    require(body["has_tip"] is True and type(body["height"]) is int and body["height"] >= 0, "tip has invalid has_tip/height")
    tip_hash = body["tip_hash"]
    require(isinstance(tip_hash, str) and len(tip_hash) == 64 and all(ch in "0123456789abcdef" for ch in tip_hash), "tip has invalid tip_hash")
    print(json.dumps({key: body[key] for key in ("has_tip", "height", "tip_hash")}, sort_keys=True))
elif mode == "refusal":
    require(record["status"] == 422 and isinstance(body, dict) and set(body) == {"mined", "error"} and body["mined"] is False, "refusal HTTP disposition/root/keys changed")
    error = body["error"]
    markers = ("atomic write lock failed", sys.argv[3], "before_namespace_commit", "create_if_absent")
    require(isinstance(error, str) and all(marker in error for marker in markers), "atomic refusal is missing stable markers")
    require(re.search(re.escape(sys.argv[3]) + r"/[^/\s]+\.bin(?:\b|:)", error), "atomic refusal has no .bin child destination")
    require(re.search(r"(contend|would[ _-]?block|temporar(?:ily)? unavailable|resource busy)", error, re.I), "atomic refusal has no contention class")
    require("datadir is already in use" not in error and "persistence fault" not in error, "atomic writer took the wrong refusal path")
elif mode == "success":
    before, after = load(sys.argv[3], "pre-refusal tip"), load(sys.argv[4], "post-retry tip")
    keys = {"mined", "height", "block_hash", "timestamp", "nonce", "tx_count"}
    require(record["status"] == 200 and isinstance(body, dict) and set(body) == keys, "retry success HTTP disposition/root/keys changed")
    require(body["mined"] is True and all(type(body[key]) is int for key in ("height", "timestamp", "nonce", "tx_count")), "retry success types changed")
    require(isinstance(body["block_hash"], str) and len(body["block_hash"]) == 64 and all(ch in "0123456789abcdef" for ch in body["block_hash"]), "retry block_hash type changed")
    require(set(before) == {"has_tip", "height", "tip_hash"} and set(after) == set(before), "tip projection keys changed")
    require(before["has_tip"] is True and after["has_tip"] is True, "tip projection has no tip")
    require(body["height"] == before["height"] + 1 and after["height"] == body["height"] and after["tip_hash"] == body["block_hash"], "retry is not exactly one bound transition")
else:
    raise SystemExit(f"unknown validator mode: {mode}")
PY
}
tip_projection() {
  rpc_result "$1" "$2" GET /get_tip || fail "$1: get_tip request"
  validate_atomic_rpc "$1" tip "${RPC_RESULT}" "" "" "$3"
}
assert_atomic_writer_contention() {
  local holder="$1" writer="$2" label="$3" route="$4" physical="${ART}/fixtures/${3}-physical" alias="" before="${ART}/${3}.before" after="${ART}/${3}.after" pre_tip="${ART}/${3}.tip.before" refused_tip="${ART}/${3}.tip.refused" success_tip="${ART}/${3}.tip.success" holder_parent writer_parent
  local datadir="${physical}"
  mkdir -p "${physical}"
  case "${route}" in
    direct) ;;
    alias)
      alias="${ART}/fixtures/${3}-alias"
      ln -s "${physical}" "${alias}" || fail "${label}: cannot create stable datadir alias"
      datadir="${alias}"
      ;;
    *) fail "${label}: unknown atomic writer route ${route}" ;;
  esac
  initialize_store "${writer}" "${datadir}" "${label}.init"
  start_live "${writer}" "${datadir}" "${label}.writer"
  holder_parent="${physical}/blockstore/blocks"
  writer_parent="${datadir}/blockstore/blocks"
  [[ "${holder_parent}" == /* && "${writer_parent}" == /* ]] || fail "${label}: atomic lock paths must be absolute"
  start_holder "${holder}" "${label}.atomic-holder" "${holder_parent}/${ATOMIC_LOCK_LEAF}"
  tip_projection "${label}.pre-refusal" "${LIVE_RPC}" "${pre_tip}"
  take_snapshot "${label}.before" "${physical}" "${before}"
  rpc_result "${label}.refusal" "${LIVE_RPC}" POST /mine_next || fail "${label}: refused mine_next request"
  validate_atomic_rpc "${label}" refusal "${RPC_RESULT}" "${writer_parent}"
  rubin_process_is_alive "${LIVE_PID}" || fail "${label}: ordinary writer did not survive pre-commit refusal"
  take_snapshot "${label}.after" "${physical}" "${after}"
  assert_same_atomic_semantic_snapshot "${label}: same-parent different-destination writer mutated state" "${before}" "${after}"
  tip_projection "${label}.post-refusal" "${LIVE_RPC}" "${refused_tip}"
  cmp -s "${pre_tip}" "${refused_tip}" || fail "${label}: tip changed across refused mine_next"
  release_holder "${label}.atomic-holder"
  rpc_result "${label}.retry" "${LIVE_RPC}" POST /mine_next || fail "${label}: retry mine_next request"
  local retry_result="${RPC_RESULT}"
  tip_projection "${label}.post-retry" "${LIVE_RPC}" "${success_tip}"
  validate_atomic_rpc "${label}" success "${retry_result}" "${pre_tip}" "${success_tip}"
  stop_live "${label}.writer"
}
assert_atomic_reclaim() {
  local seed_impl="$1" reclaim_impl="$2" label="$3" datadir="${ART}/fixtures/${3}" live_block backup mode reader
  initialize_store "${seed_impl}" "${datadir}" "${label}.init"
  live_block="$(canonical_live_block_path "${datadir}")" || fail "${label}: canonical live block lookup"
  backup="${ART}/${label}.live-block.before"
  cp -- "${live_block}" "${backup}" || fail "${label}: capture live block before hardlink residue"
  seed_atomic_residues "${label}" "${datadir}" "${live_block}"
  for mode in dry-run legacy; do for reader in go rust; do
    assert_reader "${reader}" "${mode}" "${label}.${reader}-${mode}" "${datadir}"
    assert_atomic_reserved_state "${label}: ${reader} ${mode} changed a reserved leaf" 5 0
  done; done
  start_live "${reclaim_impl}" "${datadir}" "${label}.reclaim"
  assert_atomic_reserved_state "${label}: mutating startup did not reclaim five exact residues" 0 5
  cmp -s "${backup}" "${live_block}" || fail "${label}: unlinking hardlink scratch changed live destination bytes"
  stop_live "${label}.reclaim"
}
run_atomic_parent() {
  assert_fresh_create_reclaims_datadir_scratch go
  assert_fresh_create_reclaims_datadir_scratch rust
  assert_atomic_writer_contention go rust atomic-go-holder-rust-writer direct
  assert_atomic_writer_contention rust go atomic-rust-holder-go-writer direct
  assert_atomic_writer_contention go rust atomic-go-holder-rust-writer-alias alias
  assert_atomic_writer_contention rust go atomic-rust-holder-go-writer-alias alias
  assert_atomic_reclaim go rust atomic-reclaim-go-rust
  assert_atomic_reclaim rust go atomic-reclaim-rust-go
}

if [[ "${MODE}" == atomic-parent ]]; then
  run_atomic_parent
  echo 'PASS: storage lock parity (atomic-parent)'
  exit 0
fi

echo 'Checking create-path lock acquisition before store creation'
assert_create_path_contention go rust create-lock-go-holds-rust
assert_create_path_contention rust go create-lock-rust-holds-go
echo 'Checking real Go-holds-Rust and Rust-holds-Go datadir contention'
assert_live_cross_contention go rust live-go-holds-rust
assert_live_cross_contention rust go live-rust-holds-go
echo 'Checking concurrent create/store losers and read-only modes'
assert_create_race go rust create-race-go-rust
assert_create_race rust go create-race-rust-go
assert_readers_with_holder go readonly-go-holder
assert_readers_with_holder rust readonly-rust-holder
assert_readers_without_lock
echo 'PASS: storage lock parity (datadir)'
