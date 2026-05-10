#!/usr/bin/env bash
set -euo pipefail

HELPER="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/scripts/devnet-process-common.sh"
# shellcheck source=scripts/devnet-process-common.sh disable=SC1091
source "${HELPER}"

command -v lsof >/dev/null 2>&1 || { printf 'FAIL: NO_DATA reason=lsof_unavailable fixture=partition_control\n' >&2; exit 1; }

# Fixture-only internal _rubin_process_* calls seed hostile states unreachable through public APIs.
require_contains() {
  local haystack="$1" needle="$2" label="$3"
  [[ "${haystack}" == *"${needle}"* ]] || { printf 'missing %s in %s: %s\n' "${needle}" "${label}" "${haystack}" >&2; return 1; }
}

expect_fail_contains() {
  local label="$1" needle="$2"
  shift 2
  local output output_file="${PARENT}/expect-fail-output.txt"
  if "$@" >"${output_file}" 2>&1; then
    printf 'expected failure for %s\n' "${label}" >&2
    return 1
  fi
  output="$(<"${output_file}")"
  require_contains "${output}" "${needle}" "${label}"
}

expect_fail_with_path_contains() {
  local label="$1" needle="$2" path="$3" old_path rc
  shift 3
  old_path="${PATH}"
  PATH="${path}"
  if expect_fail_contains "${label}" "${needle}" "$@"; then rc=0; else rc=$?; fi
  PATH="${old_path}"
  return "${rc}"
}

write_server() {
  cat >"$1" <<'PY'
import socket, sys, threading, time
mode = sys.argv[1]
listener = socket.socket()
listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listener.bind(("127.0.0.1", 0))
listener.listen()
print(f"server: listening={listener.getsockname()[0]}:{listener.getsockname()[1]}", flush=True)
def handle(conn):
    try:
        if mode == "send":
            conn.sendall(b"ok")
        else:
            time.sleep(3)
    except OSError:
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass
while True:
    conn, _ = listener.accept()
    threading.Thread(target=handle, args=(conn,), daemon=True).start()
PY
}

write_runtime_stub() {
  mkdir -p "$(dirname "$1")"
  cat >"$1" <<'SH'
#!/usr/bin/env sh
exit 99
SH
  chmod +x "$1"
}

server_addr() { sed -n 's/.*server: listening=//p' "$1" | tail -n 1 | tr -d '[:space:]'; }

start_server() {
  local label="$1" mode="$2" log_file
  log_file="${label}.log"
  rubin_process_start "${log_file}" python3 -u "${SERVER_PY}" "${mode}"
  rubin_process_wait_for_log "${log_file}" "server: listening=" 10 "${RUBIN_PROCESS_LAST_PID}"
  SERVER_PID="${RUBIN_PROCESS_LAST_PID}"
  SERVER_ENDPOINT="$(server_addr "${RUBIN_PROCESS_ARTIFACT_ROOT}/${log_file}")"
}

start_spoof_server() {
  local label="$1" runtime_name="$2" log_file spoof_bin
  log_file="${label}.log"
  spoof_bin="${RUBIN_PROCESS_ARTIFACT_ROOT}/${runtime_name}"
  SPOOF_EXECUTABLE="${spoof_bin}"
  cat >"${spoof_bin}" <<'PL'
#!/usr/bin/env perl
use strict; use warnings;
use IO::Socket::INET;
$0 =~ s{.*/}{}; $| = 1;
my $listener = IO::Socket::INET->new(LocalAddr => "127.0.0.1", LocalPort => 0, Listen => 5, ReuseAddr => 1, Proto => "tcp") or die "listen failed: $!";
print "server: listening=127.0.0.1:" . $listener->sockport() . "\n";
while (1) {
  my $client = $listener->accept();
  next unless $client; print {$client} "ok"; close $client;
}
PL
  chmod +x "${spoof_bin}"
  rubin_process_start "${log_file}" "${spoof_bin}"
  rubin_process_wait_for_log "${log_file}" "server: listening=" 10 "${RUBIN_PROCESS_LAST_PID}"
  SERVER_PID="${RUBIN_PROCESS_LAST_PID}"
  SERVER_ENDPOINT="$(server_addr "${RUBIN_PROCESS_ARTIFACT_ROOT}/${log_file}")"
}

seed_nodes() {
  RUBIN_PROCESS_TOPOLOGY_NAMES=(node-go node-rust)
  RUBIN_PROCESS_TOPOLOGY_IMPLS=("${1:-go}" "${2:-rust}")
  RUBIN_PROCESS_TOPOLOGY_PIDS=("${GO_PID}" "${RUST_PID}")
  RUBIN_PROCESS_TOPOLOGY_ENDPOINTS=("${GO_ENDPOINT}" "${RUST_ENDPOINT}")
  RUBIN_PROCESS_TOPOLOGY_EXEC_REALPATHS=("$(_rubin_process_started_exec_realpath "${GO_PID}")" "$(_rubin_process_started_exec_realpath "${RUST_PID}")")
}

seed_link() {
  RUBIN_PROCESS_PROXY_SOURCES=(node-go)
  RUBIN_PROCESS_PROXY_TARGETS=(node-rust)
  RUBIN_PROCESS_PROXY_ADDRS=("127.0.0.1:1")
  RUBIN_PROCESS_PROXY_TARGET_FILES=("$1")
}

PARENT="$(mktemp -d "${TMPDIR:-/tmp}/rubin partition fail closed.XXXXXX")"
cleanup_fixture() {
  local status=$?
  rubin_process_cleanup "${status}" || true
  [[ "${status}" != "0" || ! -d "${PARENT}" ]] || rmdir "${PARENT}" || true
  exit "${status}"
}
RUBIN_PROCESS_ARTIFACT_PARENT="${PARENT}"
expect_fail_contains "proxy before init" "rubin_process_init must run" rubin_process_register_proxy_link node-go node-rust 127.0.0.1:1 "${PARENT}/missing-target"
expect_fail_contains "control before init" "rubin_process_init must run" rubin_process_partition_pair node-go node-rust
rubin_process_init partition-control-fail-closed
trap cleanup_fixture EXIT

SERVER_PY="${RUBIN_PROCESS_ARTIFACT_ROOT}/helper server.py"
EXPECTED_GO_BIN="${RUBIN_PROCESS_ARTIFACT_ROOT}/expected/rubin-node-go"
NO_TOOLS_DIR="${RUBIN_PROCESS_ARTIFACT_ROOT}/no-tools"
TARGET_FILE="${RUBIN_PROCESS_ARTIFACT_ROOT}/proxy target.txt"
MISSING_TARGET="${RUBIN_PROCESS_ARTIFACT_ROOT}/missing target.txt"
write_server "${SERVER_PY}"
write_runtime_stub "${EXPECTED_GO_BIN}"
mkdir "${NO_TOOLS_DIR}"

SERVER_PID="" SERVER_ENDPOINT="" SPOOF_EXECUTABLE=""
start_server go-helper send; GO_PID="${SERVER_PID}" GO_ENDPOINT="${SERVER_ENDPOINT}"
START_FAILURE_LOG="${RUBIN_PROCESS_ARTIFACT_ROOT}/start failure.txt"
if rubin_process_start missing-command.log "${RUBIN_PROCESS_ARTIFACT_ROOT}/missing-command" 2>"${START_FAILURE_LOG}"; then
  echo "expected start failure for missing command" >&2
  exit 1
fi
require_contains "$(cat "${START_FAILURE_LOG}")" "failed to resolve executable identity" "start clears stale last pid"
[[ -z "${RUBIN_PROCESS_LAST_PID}" ]] || { echo "failed start left stale RUBIN_PROCESS_LAST_PID=${RUBIN_PROCESS_LAST_PID}" >&2; exit 1; }
start_server rust-helper send; RUST_PID="${SERVER_PID}" RUST_ENDPOINT="${SERVER_ENDPOINT}"
start_server silent-helper silent; SILENT_ENDPOINT="${SERVER_ENDPOINT}"
start_spoof_server basename-spoof rubin-node-go; SPOOF_GO_PID="${SERVER_PID}" SPOOF_GO_ENDPOINT="${SERVER_ENDPOINT}"
SPOOF_GO_COMM="$(_rubin_process_pid_comm "${SPOOF_GO_PID}")" || { echo "failed to read spoof process comm" >&2; exit 1; }; [[ "${SPOOF_GO_COMM}" == "rubin-node-go" ]] || { echo "spoof fixture did not expose rubin-node-go comm: ${SPOOF_GO_COMM}" >&2; exit 1; }
expect_fail_with_path_contains "lsof unavailable registration" "reason=lsof_unavailable" "${NO_TOOLS_DIR}" rubin_process_register_topology_node node-go go "${GO_PID}" "${GO_ENDPOINT}" "${EXPECTED_GO_BIN}"
expect_fail_contains "fake go identity" "reason=process_identity_unverified" rubin_process_register_topology_node node-go go "${GO_PID}" "${GO_ENDPOINT}"
expect_fail_contains "basename spoof missing expected executable" "reason=missing_expected_executable" rubin_process_register_topology_node node-spoof go "${SPOOF_GO_PID}" "${SPOOF_GO_ENDPOINT}"
expect_fail_contains "basename spoof arbitrary expected executable" "reason=runtime_identity_verifier_required" rubin_process_register_topology_node node-spoof go "${SPOOF_GO_PID}" "${SPOOF_GO_ENDPOINT}" "${SPOOF_EXECUTABLE}"
expect_fail_contains "basename spoof identity mismatch" "reason=runtime_identity_verifier_required" rubin_process_register_topology_node node-spoof go "${SPOOF_GO_PID}" "${SPOOF_GO_ENDPOINT}" "${EXPECTED_GO_BIN}"
((${#RUBIN_PROCESS_TOPOLOGY_NAMES[@]} == 0)) || { echo "fake process was registered as topology" >&2; exit 1; }
expect_fail_contains "socket timeout" "reason=probe_timeout" rubin_process_probe_endpoint "${SILENT_ENDPOINT}" 1
expect_fail_contains "invalid probe timeout" "reason=invalid_probe_timeout" rubin_process_probe_endpoint "${GO_ENDPOINT}" not-a-float
expect_fail_contains "unknown source" "reason=unknown_source" rubin_process_partition_pair node-missing node-rust

RUBIN_PROCESS_TOPOLOGY_NAMES=(node-go)
RUBIN_PROCESS_TOPOLOGY_IMPLS=(go)
RUBIN_PROCESS_TOPOLOGY_PIDS=("${GO_PID}")
RUBIN_PROCESS_TOPOLOGY_ENDPOINTS=("${GO_ENDPOINT}")
RUBIN_PROCESS_TOPOLOGY_EXEC_REALPATHS=("$(_rubin_process_started_exec_realpath "${GO_PID}")")
expect_fail_contains "same node" "reason=same_node" rubin_process_partition_pair node-go node-go
expect_fail_contains "single node" "reason=single_node_topology" rubin_process_partition_pair node-go node-rust

seed_nodes go go
expect_fail_contains "same client" "reason=same_client_topology" rubin_process_partition_pair node-go node-rust

seed_nodes
expect_fail_with_path_contains "lsof unavailable control" "reason=lsof_unavailable" "${NO_TOOLS_DIR}" rubin_process_partition_pair node-go node-rust
seed_link "${MISSING_TARGET}"
expect_fail_contains "missing proxy target" "reason=missing_proxy_target" rubin_process_partition_pair node-go node-rust

printf 'drop\n' >"${TARGET_FILE}"
seed_link "${TARGET_FILE}"
expect_fail_contains "partition no effect" "reason=no_effect" rubin_process_partition_pair node-go node-rust
printf '%s\n' "${RUST_ENDPOINT}" >"${TARGET_FILE}"
expect_fail_contains "heal no effect" "reason=no_effect" rubin_process_heal_pair node-go node-rust
expect_fail_contains "runtime verifier required" "reason=runtime_edge_verifier_required" rubin_process_partition_pair node-go node-rust

rubin_process_stop_pid "${RUST_PID}" || true
printf '%s\n' "${RUST_ENDPOINT}" >"${TARGET_FILE}"
expect_fail_contains "stale topology" "reason=stale_topology" rubin_process_partition_pair node-go node-rust

rubin_process_cleanup 0
rm -f "${PARENT}/expect-fail-output.txt"; rmdir "${PARENT}"
printf 'PASS: partition control helpers fail closed without live runtime proof\n'
