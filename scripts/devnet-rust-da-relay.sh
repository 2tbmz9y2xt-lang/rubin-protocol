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
# exclusion). RUB-442 adds the in-process signed DA tx source (rust-da-txgen):
# because the Rust node mines to a public key and exposes no key persistence
# across the keygen->mine->sign process boundary, the generator does keygen + mine
# + sign in one process and emits a complete signed DA set (commit + chunk0 +
# chunk1, plus the duplicate commit) that passes Rust canonical tx admission. This
# harness now generates that set to prove the source exists, then emits NO_DATA:
# driving the relay->complete-set->mine scenario to PASS (assert the complete set
# mined with tx_count==4 and tip convergence) is the follow-up RUB-443.
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

for tool in python3 perl; do
  command -v "${tool}" >/dev/null 2>&1 || { echo "${tool} is required for Rust DA relay devnet evidence" >&2; exit 1; }
done
[[ -x "${DEV_ENV}" ]] || { echo "dev-env wrapper missing or non-executable: ${DEV_ENV}" >&2; exit 1; }
# shellcheck source=scripts/devnet-process-common.sh disable=SC1091
source "${HELPER}"
DA_RELAY_IO_TIMEOUT_SECONDS="$(_rubin_process_uint_decimal DA_RELAY_IO_TIMEOUT_SECONDS "${DA_RELAY_IO_TIMEOUT_SECONDS}")"
export KEEP_TMP
rubin_process_init rust-da-relay
NODE_BIN="${RUBIN_PROCESS_ARTIFACT_ROOT}/rubin-node-rust"
DATXGEN_BIN="${RUBIN_PROCESS_ARTIFACT_ROOT}/rust-da-txgen"
DA_DATADIR="${RUBIN_PROCESS_ARTIFACT_ROOT}/da-txgen-datadir"
DA_TX_JSON="${RUBIN_PROCESS_ARTIFACT_ROOT}/rust-da-txs.json"
DA_TX_ERR="${RUBIN_PROCESS_ARTIFACT_ROOT}/rust-da-txgen.err"
REPORT_JSON="${RUBIN_PROCESS_ARTIFACT_ROOT}/rust-da-relay-report.json"
A_DIR="${RUBIN_PROCESS_ARTIFACT_ROOT}/node-a"
B_DIR="${RUBIN_PROCESS_ARTIFACT_ROOT}/node-b"
build_node() {
  local host bin datxgen
  host="$("${DEV_ENV}" -- rustc -vV | awk '/^host:/ {print $2}')"
  [[ -n "${host}" ]] || { echo "could not derive host target triple" >&2; return 1; }
  # `-p rubin-node` builds every target of the package, including the
  # rust-da-txgen binary used by generate_da_set below.
  "${DEV_ENV}" -- cargo build --manifest-path "${RUST_ROOT}/Cargo.toml" \
    --release --locked -p rubin-node --target "${host}" --target-dir "${RUBIN_PROCESS_ARTIFACT_ROOT}/cargo-target" \
    >/dev/null
  bin="${RUBIN_PROCESS_ARTIFACT_ROOT}/cargo-target/${host}/release/rubin-node"
  cp -- "${bin}" "${NODE_BIN}"
  [[ -x "${NODE_BIN}" ]] || { echo "built Rust node is not executable: ${NODE_BIN}" >&2; return 1; }
  datxgen="${RUBIN_PROCESS_ARTIFACT_ROOT}/cargo-target/${host}/release/rust-da-txgen"
  cp -- "${datxgen}" "${DATXGEN_BIN}"
  [[ -x "${DATXGEN_BIN}" ]] || { echo "built Rust DA tx generator is not executable: ${DATXGEN_BIN}" >&2; return 1; }
}
# RUB-442: produce a complete signed DA set (commit + two chunks + duplicate
# commit) with the in-process keygen+mine+sign generator and assert it is
# well-formed (valid hex, distinct 64-hex txids). The generator self-checks each
# tx against Rust canonical tx admission and exits non-zero on failure.
generate_da_set() {
  mkdir -p "${DA_DATADIR}" || { echo "da-txgen datadir setup failed" >&2; return 1; }
  if ! "${DATXGEN_BIN}" "${DA_DATADIR}" >"${DA_TX_JSON}" 2>"${DA_TX_ERR}"; then
    echo "rust-da-txgen failed: $(tail -n 1 "${DA_TX_ERR}" 2>/dev/null)" >&2
    return 1
  fi
  python3 - "${DA_TX_JSON}" <<'PY'
import json, re, sys
with open(sys.argv[1], encoding="utf-8") as fh:
    data = json.load(fh)
if not isinstance(data, dict):
    raise SystemExit("DA tx JSON is not an object")
required = ("chunk0", "commit", "duplicate_commit", "chunk1")
txids = set()
for key in required:
    entry = data.get(key)
    if not isinstance(entry, dict):
        raise SystemExit(f"missing or malformed entry for {key}")
    tx_hex = entry.get("hex")
    txid = entry.get("txid")
    if not (isinstance(tx_hex, str) and re.fullmatch(r"[0-9a-f]+", tx_hex) and len(tx_hex) % 2 == 0):
        raise SystemExit(f"malformed hex for {key}")
    if not (isinstance(txid, str) and re.fullmatch(r"[0-9a-f]{64}", txid)):
        raise SystemExit(f"malformed txid for {key}")
    txids.add(txid)
if len(txids) != len(required):
    raise SystemExit("DA set txids are not distinct")
print("rust-da-txgen DA set: " + ", ".join(f"{k}={data[k]['txid'][:12]}" for k in required), file=sys.stderr)
PY
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
build_node || emit_no_data node_build_failed
mkdir -p "${A_DIR}" "${B_DIR}" || emit_no_data artifact_setup_failed
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
echo "Generating signed Rust DA set (in-process keygen+mine+sign)"
generate_da_set || emit_no_data rust_da_signed_tx_source_generation_failed
# Source proven: a complete admissible signed DA set now exists. Driving the
# relay->complete-set->mine scenario to PASS is the follow-up RUB-443.
emit_no_data rust_da_relay_complete_set_mine_pending
