#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEV_ENV="${REPO_ROOT}/scripts/dev-env.sh"
RUST_ROOT="${REPO_ROOT}/clients/rust"
HELPER="${REPO_ROOT}/scripts/devnet-process-common.sh"
unset REPORT_JSON
: "${KEEP_TMP:=1}"
: "${DA_RELAY_IO_TIMEOUT_SECONDS:=5}"
usage() { echo "usage: $0" >&2; }
while (($#)); do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    *) usage; exit 2 ;;
  esac
done
# Narrow DA-only Rust process smoke: bring up two Rust devnet nodes (DA relay is
# default-on for devnet), prove a real two-node handshake, then emit a source-bound
# PASS/FAIL/NO_DATA report. The runtime relay->complete-set-provider->miner path is
# wired (RUB-440 inbound staging, RUB-389 provider, RUB-435 consume, RUB-387 flat
# exclusion), but this harness has no signed DA commit/chunk tx source: the Rust node
# mines to a public key and exposes no key persistence across the keygen->mine->sign
# process boundary, so a follow-up in-process DA-tx generator is required before the
# relay->complete-set->mine scenario can be driven to PASS. PASS would assert the
# complete set mined (tx_count==4: commit+chunk0+chunk1, duplicate omitted) and tip
# convergence; FAIL would be that invariant disproven once a tx source exists.
emit_report() {
  local verdict="$1" reason="${2:-}"
  if [[ -n "${REPORT_JSON:-}" ]]; then
    python3 - "${REPORT_JSON}" "${verdict}" "${reason}" "${RUBIN_PROCESS_ARTIFACT_ROOT:-}" "${NODE_BIN:-}" "${A_PID:-}" "${A_RPC:-}" "${A_P2P:-}" "${A_PEERS:-}" "${B_PID:-}" "${B_RPC:-}" "${B_P2P:-}" "${B_PEERS:-}" <<'PY'
import json, sys
path, verdict, reason, root, binary, a_pid, a_rpc, a_p2p, a_peers, b_pid, b_rpc, b_p2p, b_peers = sys.argv[1:14]
data = {"scenario": "rust_two_node_da_relay_process", "verdict": verdict}
if reason: data["failure_reason"] = reason
if root: data["artifact_root"] = root
participants = []
for name, pid, rpc, p2p, peers in (("node-a", a_pid, a_rpc, a_p2p, a_peers), ("node-b", b_pid, b_rpc, b_p2p, b_peers)):
    if pid:
        item = {"name": name, "implementation": "rust", "pid": int(pid), "binary": binary, "rpc": rpc or None, "p2p": p2p or None, "log": f"{root}/{name}.log" if root else None}
        if peers: item["handshake_peers"] = int(peers)
        participants.append(item)
if participants: data["participants"] = participants
with open(path, "w", encoding="utf-8") as f:
    json.dump(data, f, indent=2, sort_keys=True); f.write("\n")
PY
    echo "${verdict}: reason=${reason}; report=${REPORT_JSON}" >&2
  else
    echo "${verdict}: reason=${reason}" >&2
  fi
}
emit_no_data() { emit_report NO_DATA "$1"; exit 1; }

for tool in python3 perl lsof; do
  command -v "${tool}" >/dev/null 2>&1 || { echo "${tool} is required for Rust DA relay devnet evidence" >&2; exit 1; }
done
[[ -x "${DEV_ENV}" ]] || { echo "dev-env wrapper missing or non-executable: ${DEV_ENV}" >&2; exit 1; }
# shellcheck source=scripts/devnet-process-common.sh disable=SC1091
source "${HELPER}"
DA_RELAY_IO_TIMEOUT_SECONDS="$(_rubin_process_uint_decimal DA_RELAY_IO_TIMEOUT_SECONDS "${DA_RELAY_IO_TIMEOUT_SECONDS}")"
export KEEP_TMP
rubin_process_init rust-da-relay
NODE_BIN="${RUBIN_PROCESS_ARTIFACT_ROOT}/rubin-node-rust"
REPORT_JSON="${RUBIN_PROCESS_ARTIFACT_ROOT}/rust-da-relay-report.json"
A_DIR="${RUBIN_PROCESS_ARTIFACT_ROOT}/node-a"
B_DIR="${RUBIN_PROCESS_ARTIFACT_ROOT}/node-b"
build_node() {
  local host bin
  host="$("${DEV_ENV}" -- rustc -vV | awk '/^host:/ {print $2}')"
  [[ -n "${host}" ]] || { echo "could not derive host target triple" >&2; return 1; }
  "${DEV_ENV}" -- cargo build --manifest-path "${RUST_ROOT}/Cargo.toml" \
    --release --locked -p rubin-node --target "${host}" --target-dir "${RUBIN_PROCESS_ARTIFACT_ROOT}/cargo-target" \
    >/dev/null
  bin="${RUBIN_PROCESS_ARTIFACT_ROOT}/cargo-target/${host}/release/rubin-node"
  cp -- "${bin}" "${NODE_BIN}"
  [[ -x "${NODE_BIN}" ]] || { echo "built Rust node is not executable: ${NODE_BIN}" >&2; return 1; }
}
start_node() {
  local label="$1" log="$2" datadir="$3" peers="${4:-}"
  local cmd=("${NODE_BIN}" --network devnet --datadir "${datadir}" --bind 127.0.0.1:0 --rpc-bind 127.0.0.1:0)
  STARTED_PID=""; STARTED_RPC=""; STARTED_P2P=""
  [[ -z "${peers}" ]] || cmd+=(--peers "${peers}")
  rubin_process_start "${log}" "${cmd[@]}" || { echo "failed to start ${label}" >&2; return 1; }
  STARTED_PID="${RUBIN_PROCESS_LAST_PID}"
  rubin_process_wait_for_log "${log}" "rpc: listening=" 60 "${STARTED_PID}" || return 1
  STARTED_RPC="$(rubin_process_extract_rpc_addr "${log}")" || return 1
  _rubin_process_loopback_endpoint "${STARTED_RPC}" || { echo "failed resolving ${label} rpc address" >&2; return 1; }
  rubin_process_wait_for_log "${log}" "p2p: listening=" 60 "${STARTED_PID}" || return 1
  STARTED_P2P="$(sed -n 's/.*p2p: listening=//p' "$(_rubin_process_resolve_log "${log}")" | tail -n 1 | tr -d '[:space:]')" || return 1
  _rubin_process_loopback_endpoint "${STARTED_P2P}" || { echo "failed resolving ${label} p2p address" >&2; return 1; }
  rubin_process_wait_for_rpc_ready "${STARTED_RPC}" 30 || return 1
}
wait_peers_ready() {
  local label="$1" addr="$2" deadline=$((SECONDS + 30)) count="0"
  while (( SECONDS < deadline )); do
    if count="$(python3 - "${addr}" "${DA_RELAY_IO_TIMEOUT_SECONDS}" <<'PY' 2>/dev/null
import json, sys, urllib.request
with urllib.request.urlopen(f"http://{sys.argv[1]}/peers", timeout=int(sys.argv[2])) as resp:
    data = json.load(resp)
print(sum(1 for p in (data.get("peers") or []) if p.get("handshake_complete") is True))
PY
    )" && [[ "${count}" =~ ^[0-9]+$ && "${count}" -ge 1 ]]; then
      printf '%s\n' "${count}"
      return 0
    fi
    sleep 1
  done
  echo "timeout waiting for ${label} handshake peers addr=${addr} actual=${count}" >&2
  return 1
}
echo "Building Rust rubin-node"
build_node
mkdir -p "${A_DIR}" "${B_DIR}"
if ! start_node node-b node-b.log "${B_DIR}"; then
  B_PID="${STARTED_PID:-}"; B_RPC="${STARTED_RPC:-}"; B_P2P="${STARTED_P2P:-}"
  emit_no_data node_b_start_failed
fi
B_PID="${STARTED_PID}"; B_RPC="${STARTED_RPC}"; B_P2P="${STARTED_P2P}"
if ! start_node node-a node-a.log "${A_DIR}" "${B_P2P}"; then
  A_PID="${STARTED_PID:-}"; A_RPC="${STARTED_RPC:-}"; A_P2P="${STARTED_P2P:-}"
  emit_no_data node_a_start_failed
fi
A_PID="${STARTED_PID}"; A_RPC="${STARTED_RPC}"; A_P2P="${STARTED_P2P}"
A_PEERS="$(wait_peers_ready node-a "${A_RPC}")" || emit_no_data node_a_handshake_missing
B_PEERS="$(wait_peers_ready node-b "${B_RPC}")" || emit_no_data node_b_handshake_missing
emit_no_data rust_da_signed_tx_source_unavailable
