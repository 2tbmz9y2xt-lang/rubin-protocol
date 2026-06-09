#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEV_ENV="${REPO_ROOT}/scripts/dev-env.sh"
RUST_ROOT="${REPO_ROOT}/clients/rust"
HELPER="${REPO_ROOT}/scripts/devnet-process-common.sh"
unset REPORT_JSON
BASE_HEIGHT=105
# rust-da-txgen mines N blocks from genesis (heights 0..N-1), so reaching a
# tip of BASE_HEIGHT requires BASE_HEIGHT+1 mined blocks.
BASE_BLOCKS=$((BASE_HEIGHT + 1))
INCOMPLETE_HEIGHT=$((BASE_HEIGHT + 1))
: "${KEEP_TMP:=1}"
: "${DA_RELAY_IO_TIMEOUT_SECONDS:=5}"
usage() { echo "usage: $0" >&2; }
while (($#)); do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    *) usage; exit 2 ;;
  esac
done
# Rust DA relay process smoke (RUB-409 bring-up, RUB-442 signed tx source,
# RUB-443 PASS conversion). Mirror of the Go DA relay smoke
# (scripts/devnet-go-da-relay.sh): mine a mature base chain via the in-process
# rust-da-txgen generator (keygen + mine + sign in one process; the keypair
# never leaves it), copy the datadir to both nodes, start two Rust devnet
# nodes, prove a real two-node handshake, then drive the signed DA set through
# relay -> complete-set-provider -> miner: an incomplete set (lone chunk0) and
# a staged commit must NOT be mined (tx_count==1), the complete set must be
# mined (tx_count==4: coinbase + commit + chunk0 + chunk1, duplicate commit
# omitted), one post-complete block must stay DA-free (no duplicate-set mine,
# no orphan leak into a block), and both nodes must converge on the same tip.
# Emits a source-bound PASS/FAIL/NO_DATA report.
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
emit_fail() { emit_report FAIL "$1"; exit 1; }

for tool in python3 perl git; do
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
  # rust-da-txgen generator/blockcheck binary used below.
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
# commit) with the in-process keygen+mine+sign generator, mining the mature
# base chain directly into node-a's datadir (the generator self-checks each tx
# against Rust canonical tx admission and exits non-zero on failure), and
# assert the emitted JSON is well-formed (valid hex, distinct 64-hex txids).
generate_da_set() {
  mkdir -p "${A_DIR}" || { echo "da-txgen datadir setup failed" >&2; return 1; }
  if ! "${DATXGEN_BIN}" "${A_DIR}" "${BASE_BLOCKS}" >"${DA_TX_JSON}" 2>"${DA_TX_ERR}"; then
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
json_field() { python3 -c $'import json,sys\nwith open(sys.argv[1], encoding="utf-8") as fh:\n    d=json.load(fh)\nv=d[sys.argv[2]][sys.argv[3]]\nif not isinstance(v,str) or not v:\n    raise SystemExit("missing JSON field")\nprint(v)' "$1" "$2" "$3"; }
rpc_json() {
  local method="$1" addr="$2" path="$3" body="${4:-}"
  python3 - "${method}" "${addr}" "${path}" "${body}" "${DA_RELAY_IO_TIMEOUT_SECONDS}" <<'PY'
import socket, sys, urllib.error, urllib.request
method, addr, path, body, raw_timeout = sys.argv[1:6]
timeout = int(raw_timeout)
data = body.encode() if body else None
req = urllib.request.Request(f"http://{addr}{path}", data=data, method=method)
if body:
    req.add_header("Content-Type", "application/json")
try:
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        print(resp.read().decode("utf-8"), end="")
except urllib.error.HTTPError as exc:
    print(exc.read().decode("utf-8"), end="")
    sys.exit(22)
except (urllib.error.URLError, TimeoutError, socket.timeout) as exc:
    print(f"request failed timeout={timeout}: {getattr(exc, 'reason', exc)}", end="")
    sys.exit(1)
PY
}
tip_tsv() {
  rpc_json GET "$1" /get_tip | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["height"], d["tip_hash"], sep="\t")'
}
wait_tip_exact() {
  local label="$1" addr="$2" want_height="$3" want_hash="$4" timeout="$5"
  local deadline=$((SECONDS + timeout)) height hash last_height="<none>" last_hash="<none>"
  while (( SECONDS < deadline )); do
    if IFS=$'\t' read -r height hash < <(tip_tsv "${addr}" 2>/dev/null); then
      last_height="${height}"
      last_hash="${hash}"
      [[ "${height}" == "${want_height}" && "${hash}" == "${want_hash}" ]] && return 0
    fi
    sleep 1
  done
  echo "timeout waiting for ${label} tip addr=${addr} expected_height=${want_height} expected_hash=${want_hash} actual_height=${last_height} actual_hash=${last_hash}" >&2
  return 1
}
wait_peers_ready() {
  local label="$1" addr="$2" deadline=$((SECONDS + 30)) count="0"
  while (( SECONDS < deadline )); do
    if count="$(rpc_json GET "${addr}" /peers 2>/dev/null | python3 -c 'import json,sys; d=json.load(sys.stdin); print(sum(1 for p in (d.get("peers") or []) if p.get("handshake_complete") is True))')" &&
      [[ "${count}" =~ ^[0-9]+$ && "${count}" -ge 1 ]]; then
      printf '%s\n' "${count}"
      return 0
    fi
    sleep 1
  done
  echo "timeout waiting for ${label} handshake peers addr=${addr} actual=${count}" >&2
  return 1
}
wait_mempool_contains() {
  local label="$1" addr="$2" txid="$3" deadline=$((SECONDS + 30)) last="<none>"
  while (( SECONDS < deadline )); do
    if last="$(rpc_json GET "${addr}" /get_mempool 2>/dev/null)" &&
      printf '%s' "${last}" | python3 -c 'import json,sys; want=sys.argv[1]; d=json.load(sys.stdin); sys.exit(0 if want in (d.get("txids") or []) else 1)' "${txid}"; then
      return 0
    fi
    sleep 1
  done
  echo "timeout waiting for ${label} mempool tx addr=${addr} txid=${txid} last=${last}" >&2
  return 1
}
submit_tx_hex() {
  local addr="$1" tx_hex="$2" body response
  body="$(python3 - "${tx_hex}" <<'PY'
import json, re, sys
tx_hex = sys.argv[1]
if not re.fullmatch(r"[0-9a-f]+", tx_hex) or len(tx_hex) % 2 != 0 or len(tx_hex) > 20000:
    raise SystemExit("tx_hex is malformed or unbounded")
print(json.dumps({"tx_hex": tx_hex}, separators=(",", ":")))
PY
)" || return 1
  response="$(rpc_json POST "${addr}" /submit_tx "${body}")" || { echo "submit failed: ${response}" >&2; return 1; }
  printf '%s' "${response}" | python3 -c 'import json,re,sys; d=json.load(sys.stdin); txid=d.get("txid"); sys.exit(0 if d.get("accepted") is True and isinstance(txid, str) and re.fullmatch(r"[0-9a-f]{64}", txid) else 1)'
}
mine_next_tsv() {
  local addr="$1" response
  response="$(rpc_json POST "${addr}" /mine_next '{}')" || return 1
  printf '%s' "${response}" | python3 -c 'import json,sys; d=json.load(sys.stdin); sys.exit("mine_next failed: " + str(d.get("error", d))) if d.get("mined") is not True else print(d["height"], d["block_hash"], d["tx_count"], sep="\t")'
}
block_hex() { rpc_json GET "$1" "/get_block?height=$2" | python3 -c 'import json,sys; d=json.load(sys.stdin); print((d.get("block_hex") or "").lower())'; }
assert_block_txids() { "${DATXGEN_BIN}" blockcheck "$@"; }
STARTED_PID=""; STARTED_RPC=""; STARTED_P2P=""
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
write_pass_report() {
  export REPORT_JSON NODE_BIN DATXGEN_BIN A_DIR B_DIR A_PID B_PID A_RPC B_RPC A_P2P B_P2P A_PEERS B_PEERS \
    CHUNK0_TXID COMMIT_TXID DUP_TXID CHUNK1_TXID DA_ID \
    INCOMPLETE_MINE_HEIGHT INCOMPLETE_MINE_HASH INCOMPLETE_TX_COUNT \
    STAGED_MINE_HEIGHT STAGED_MINE_HASH STAGED_TX_COUNT \
    COMPLETE_MINE_HEIGHT COMPLETE_MINE_HASH COMPLETE_TX_COUNT \
    POST_MINE_HEIGHT POST_MINE_HASH POST_TX_COUNT \
    A_FINAL_HEIGHT A_FINAL_HASH B_FINAL_HEIGHT B_FINAL_HASH \
    SOURCE_COMMIT SOURCE_BRANCH SOURCE_REMOTE SCRIPT_PATH RUBIN_PROCESS_ARTIFACT_ROOT CLEANUP_NODES_STOPPED
  python3 - <<'PY'
import json, os
e = os.environ
i = lambda key: int(e[key])
report = {
    "scenario": "rust_two_node_da_relay_process",
    "verdict": "PASS",
    "source": {
        "repo": e["SOURCE_REMOTE"],
        "branch": e["SOURCE_BRANCH"],
        "commit_sha": e["SOURCE_COMMIT"],
        "script": e["SCRIPT_PATH"],
        "artifact_root": e["RUBIN_PROCESS_ARTIFACT_ROOT"],
        "node_version": {"binary": e["NODE_BIN"], "source_commit": e["SOURCE_COMMIT"]},
        "tx_generator": {"binary": e["DATXGEN_BIN"], "kind": "in_process_keygen_mine_sign", "source_commit": e["SOURCE_COMMIT"]},
    },
    "participants": [
        {"name": "node-a", "implementation": "rust", "pid": i("A_PID"), "binary": e["NODE_BIN"], "rpc": e["A_RPC"], "p2p": e["A_P2P"], "datadir": e["A_DIR"], "handshake_peers": i("A_PEERS")},
        {"name": "node-b", "implementation": "rust", "pid": i("B_PID"), "binary": e["NODE_BIN"], "rpc": e["B_RPC"], "p2p": e["B_P2P"], "datadir": e["B_DIR"], "handshake_peers": i("B_PEERS")},
    ],
    "da_relay_evidence": {
        "da_id": e["DA_ID"],
        "submitter_to_peer_relay": {"submitted_to": "node-b", "observed_in_mempool": "node-a", "admitted_txids": {"commit": e["COMMIT_TXID"], "chunk0": e["CHUNK0_TXID"], "chunk1": e["CHUNK1_TXID"], "duplicate_commit": e["DUP_TXID"]}},
        "incomplete_set_not_mined": {"mined_by": "node-a", "height": i("INCOMPLETE_MINE_HEIGHT"), "block_hash": e["INCOMPLETE_MINE_HASH"], "tx_count": i("INCOMPLETE_TX_COUNT"), "omitted_chunk_txid": e["CHUNK0_TXID"]},
        "staged_commit_not_mined_until_complete": {"mined_by": "node-a", "height": i("STAGED_MINE_HEIGHT"), "block_hash": e["STAGED_MINE_HASH"], "tx_count": i("STAGED_TX_COUNT"), "omitted_commit_txid": e["COMMIT_TXID"]},
        "complete_set_mined": {"mined_by": "node-a", "height": i("COMPLETE_MINE_HEIGHT"), "block_hash": e["COMPLETE_MINE_HASH"], "tx_count": i("COMPLETE_TX_COUNT"), "included_commit_txid": e["COMMIT_TXID"], "included_chunk_txids": [e["CHUNK0_TXID"], e["CHUNK1_TXID"]], "provider_miner_path": "relay complete set entered the block only via the complete-da-set provider (flat DA candidates are excluded by the miner)"},
        "duplicate_commit_first_seen_no_replacement": {"duplicate_txid": e["DUP_TXID"], "evidence": "duplicate txid omitted from parsed complete block and from the post-complete block"},
        "post_complete_block_da_free": {"mined_by": "node-a", "height": i("POST_MINE_HEIGHT"), "block_hash": e["POST_MINE_HASH"], "tx_count": i("POST_TX_COUNT"), "evidence": "no DA tx (including the duplicate commit) leaked into the next block after the complete set was consumed"},
        "tip_convergence": {"node_a": {"height": i("A_FINAL_HEIGHT"), "tip_hash": e["A_FINAL_HASH"]}, "node_b": {"height": i("B_FINAL_HEIGHT"), "tip_hash": e["B_FINAL_HASH"]}},
    },
    "happy_path_expectations": {
        "expected_da_commit_count": 1,
        "expected_da_chunk_count": 2,
        "expected_complete_da_set": True,
        "expected_duplicate_da_set": False,
        "expected_orphan_leak": False,
    },
    "cleanup": {"nodes_stopped": e["CLEANUP_NODES_STOPPED"] == "true", "artifact_root_policy": "KEEP_TMP honored by rubin_process_cleanup"},
}
if report["participants"][0]["datadir"] == report["participants"][1]["datadir"] or report["participants"][0]["pid"] == report["participants"][1]["pid"]: raise SystemExit("participants are not distinct")
if report["da_relay_evidence"]["incomplete_set_not_mined"]["tx_count"] != 1: raise SystemExit("incomplete set was mined or tx_count proof missing")
if report["da_relay_evidence"]["staged_commit_not_mined_until_complete"]["tx_count"] != 1: raise SystemExit("staged commit set was mined or tx_count proof missing")
if report["da_relay_evidence"]["complete_set_mined"]["tx_count"] != 4: raise SystemExit("complete DA set tx_count proof missing")
if report["da_relay_evidence"]["post_complete_block_da_free"]["tx_count"] != 1: raise SystemExit("post-complete block is not DA-free")
tips = report["da_relay_evidence"]["tip_convergence"]
if tips["node_a"] != tips["node_b"]: raise SystemExit("tip convergence proof missing")
if not report["cleanup"]["nodes_stopped"]: raise SystemExit("cleanup proof missing")
with open(e["REPORT_JSON"], "w", encoding="utf-8") as fh:
    json.dump(report, fh, indent=2, sort_keys=True)
    fh.write("\n")
PY
}
SOURCE_COMMIT="$(git -C "${REPO_ROOT}" rev-parse HEAD)"
SOURCE_BRANCH="$(git -C "${REPO_ROOT}" rev-parse --abbrev-ref HEAD)"
SOURCE_REMOTE="$(git -C "${REPO_ROOT}" remote get-url origin 2>/dev/null || echo rubin-protocol)"
SCRIPT_PATH="scripts/devnet-rust-da-relay.sh"
echo "Building Rust rubin-node + rust-da-txgen"
build_node || emit_no_data node_build_failed
echo "Generating signed Rust DA set (in-process keygen+mine+sign) into node-a datadir"
generate_da_set || emit_no_data rust_da_signed_tx_source_generation_failed
CHUNK0_HEX="$(json_field "${DA_TX_JSON}" chunk0 hex)"
CHUNK0_TXID="$(json_field "${DA_TX_JSON}" chunk0 txid)"
COMMIT_HEX="$(json_field "${DA_TX_JSON}" commit hex)"
COMMIT_TXID="$(json_field "${DA_TX_JSON}" commit txid)"
DUP_HEX="$(json_field "${DA_TX_JSON}" duplicate_commit hex)"
DUP_TXID="$(json_field "${DA_TX_JSON}" duplicate_commit txid)"
CHUNK1_HEX="$(json_field "${DA_TX_JSON}" chunk1 hex)"
CHUNK1_TXID="$(json_field "${DA_TX_JSON}" chunk1 txid)"
DA_ID="$(python3 -c $'import json,sys\nwith open(sys.argv[1], encoding="utf-8") as fh:\n    d=json.load(fh)\nv=d["da_id"]\nif not isinstance(v,str) or not v:\n    raise SystemExit("missing da_id")\nprint(v)' "${DA_TX_JSON}")"
mkdir -p "${B_DIR}" || emit_no_data artifact_setup_failed
cp -R "${A_DIR}/." "${B_DIR}/" || emit_no_data datadir_copy_failed
[[ -d "${A_DIR}" && -d "${B_DIR}" && "${A_DIR}" != "${B_DIR}" && ! -L "${A_DIR}" && ! -L "${B_DIR}" ]] || { echo "node datadirs must be distinct non-symlink directories" >&2; exit 1; }
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
IFS=$'\t' read -r BASE_TIP_HEIGHT BASE_HASH < <(tip_tsv "${A_RPC}") || emit_no_data node_a_tip_unavailable
[[ "${BASE_TIP_HEIGHT}" == "${BASE_HEIGHT}" ]] || emit_no_data base_chain_height_mismatch
wait_tip_exact node-b "${B_RPC}" "${BASE_HEIGHT}" "${BASE_HASH}" 30 || emit_no_data node_b_base_tip_mismatch
echo "Phase 1: lone chunk0 must not be mined"
submit_tx_hex "${B_RPC}" "${CHUNK0_HEX}" >/dev/null || emit_fail chunk0_submit_rejected
wait_mempool_contains node-a "${A_RPC}" "${CHUNK0_TXID}" || emit_fail chunk0_relay_missing
IFS=$'\t' read -r INCOMPLETE_MINE_HEIGHT INCOMPLETE_MINE_HASH INCOMPLETE_TX_COUNT < <(mine_next_tsv "${A_RPC}") || emit_fail incomplete_mine_failed
[[ "${INCOMPLETE_MINE_HEIGHT}" == "${INCOMPLETE_HEIGHT}" && "${INCOMPLETE_TX_COUNT}" == "1" ]] || emit_fail incomplete_set_mined_unexpectedly
wait_tip_exact node-b "${B_RPC}" "${INCOMPLETE_HEIGHT}" "${INCOMPLETE_MINE_HASH}" 60 || emit_fail incomplete_block_propagation_missing
INCOMPLETE_BLOCK_HEX="$(block_hex "${A_RPC}" "${INCOMPLETE_HEIGHT}")"
assert_block_txids "${INCOMPLETE_BLOCK_HEX}" "${INCOMPLETE_MINE_HASH}" "1" "-" "${CHUNK0_TXID}" || emit_fail incomplete_block_txid_assertion_failed
echo "Phase 2: staged commit (missing chunk1) must not be mined"
submit_tx_hex "${B_RPC}" "${COMMIT_HEX}" >/dev/null || emit_fail commit_submit_rejected
wait_mempool_contains node-a "${A_RPC}" "${COMMIT_TXID}" || emit_fail commit_relay_missing
IFS=$'\t' read -r STAGED_MINE_HEIGHT STAGED_MINE_HASH STAGED_TX_COUNT < <(mine_next_tsv "${A_RPC}") || emit_fail staged_mine_failed
[[ "${STAGED_MINE_HEIGHT}" == "$((INCOMPLETE_HEIGHT + 1))" && "${STAGED_TX_COUNT}" == "1" ]] || emit_fail staged_set_mined_unexpectedly
wait_tip_exact node-b "${B_RPC}" "${STAGED_MINE_HEIGHT}" "${STAGED_MINE_HASH}" 60 || emit_fail staged_block_propagation_missing
STAGED_BLOCK_HEX="$(block_hex "${A_RPC}" "${STAGED_MINE_HEIGHT}")"
assert_block_txids "${STAGED_BLOCK_HEX}" "${STAGED_MINE_HASH}" "1" "-" "${CHUNK0_TXID},${COMMIT_TXID}" || emit_fail staged_block_txid_assertion_failed
echo "Phase 3: complete set (commit + chunk0 + chunk1) must be mined, duplicate omitted"
submit_tx_hex "${B_RPC}" "${DUP_HEX}" >/dev/null || emit_fail duplicate_submit_rejected
wait_mempool_contains node-a "${A_RPC}" "${DUP_TXID}" || emit_fail duplicate_relay_missing
submit_tx_hex "${B_RPC}" "${CHUNK1_HEX}" >/dev/null || emit_fail chunk1_submit_rejected
wait_mempool_contains node-a "${A_RPC}" "${CHUNK1_TXID}" || emit_fail chunk1_relay_missing
COMPLETE_FOUND=0
for _ in 1 2 3 4 5; do
  IFS=$'\t' read -r COMPLETE_MINE_HEIGHT COMPLETE_MINE_HASH COMPLETE_TX_COUNT < <(mine_next_tsv "${A_RPC}") || emit_fail complete_mine_failed
  wait_tip_exact node-b "${B_RPC}" "${COMPLETE_MINE_HEIGHT}" "${COMPLETE_MINE_HASH}" 60 || emit_fail complete_block_propagation_missing
  COMPLETE_BLOCK_HEX="$(block_hex "${A_RPC}" "${COMPLETE_MINE_HEIGHT}")"
  assert_block_txids "${COMPLETE_BLOCK_HEX}" "${COMPLETE_MINE_HASH}" "4" "${COMMIT_TXID},${CHUNK0_TXID},${CHUNK1_TXID}" "${DUP_TXID}" 2>/dev/null && { COMPLETE_FOUND=1; break; }
done
[[ "${COMPLETE_FOUND}" == "1" ]] || emit_fail complete_set_not_mined
echo "Phase 4: post-complete block must stay DA-free (duplicate set not mined, no orphan leak)"
IFS=$'\t' read -r POST_MINE_HEIGHT POST_MINE_HASH POST_TX_COUNT < <(mine_next_tsv "${A_RPC}") || emit_fail post_complete_mine_failed
[[ "${POST_TX_COUNT}" == "1" ]] || emit_fail post_complete_block_not_da_free
wait_tip_exact node-b "${B_RPC}" "${POST_MINE_HEIGHT}" "${POST_MINE_HASH}" 60 || emit_fail post_complete_block_propagation_missing
POST_BLOCK_HEX="$(block_hex "${A_RPC}" "${POST_MINE_HEIGHT}")"
assert_block_txids "${POST_BLOCK_HEX}" "${POST_MINE_HASH}" "1" "-" "${DUP_TXID},${COMMIT_TXID},${CHUNK0_TXID},${CHUNK1_TXID}" || emit_fail post_complete_block_txid_assertion_failed
echo "Phase 5: final tip convergence"
IFS=$'\t' read -r A_FINAL_HEIGHT A_FINAL_HASH < <(tip_tsv "${A_RPC}") || emit_fail node_a_final_tip_unavailable
IFS=$'\t' read -r B_FINAL_HEIGHT B_FINAL_HASH < <(tip_tsv "${B_RPC}") || emit_fail node_b_final_tip_unavailable
[[ "${A_FINAL_HEIGHT}" == "${B_FINAL_HEIGHT}" && "${A_FINAL_HASH}" == "${B_FINAL_HASH}" && "${A_FINAL_HASH}" == "${POST_MINE_HASH}" ]] || emit_fail final_convergence_mismatch
echo "Phase 6: cleanup (stop both nodes before writing the PASS report)"
CLEANUP_NODES_STOPPED=false
if rubin_process_stop_all && ! rubin_process_is_alive "${A_PID}" && ! rubin_process_is_alive "${B_PID}"; then
  CLEANUP_NODES_STOPPED=true
fi
[[ "${CLEANUP_NODES_STOPPED}" == "true" ]] || emit_fail node_cleanup_incomplete
write_pass_report || emit_fail pass_report_write_failed
echo "PASS: Rust DA relay process smoke completed; report=${REPORT_JSON}"
