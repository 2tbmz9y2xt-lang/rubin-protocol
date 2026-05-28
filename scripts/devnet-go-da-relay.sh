#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEV_ENV="${REPO_ROOT}/scripts/dev-env.sh"
GO_MODULE_ROOT="${REPO_ROOT}/clients/go"
HELPER="${REPO_ROOT}/scripts/devnet-process-common.sh"
BASE_HEIGHT=105
INCOMPLETE_HEIGHT=$((BASE_HEIGHT + 1))
: "${KEEP_TMP:=1}"
: "${RUBIN_GO_DA_RELAY_RPC_TIMEOUT_SECONDS:=5}"
export KEEP_TMP

for tool in python3 perl lsof; do command -v "${tool}" >/dev/null 2>&1 || { echo "${tool} is required for Go DA relay devnet evidence" >&2; exit 1; }; done
python3 -c $'import math,sys\nraw=sys.argv[1]\ntry:\n    value=float(raw)\nexcept ValueError:\n    raise SystemExit(f"invalid RUBIN_GO_DA_RELAY_RPC_TIMEOUT_SECONDS={raw!r}")\nif not math.isfinite(value) or value <= 0 or value > 300:\n    raise SystemExit(f"RUBIN_GO_DA_RELAY_RPC_TIMEOUT_SECONDS out of range: {raw!r}")' "${RUBIN_GO_DA_RELAY_RPC_TIMEOUT_SECONDS}"

# shellcheck source=scripts/devnet-process-common.sh disable=SC1091
source "${HELPER}"
rubin_process_init go-da-relay

NODE_BIN="${RUBIN_PROCESS_ARTIFACT_ROOT}/rubin-node-go"
KEYGEN_GO="${RUBIN_PROCESS_ARTIFACT_ROOT}/keygen.go"
KEYGEN_JSON="${RUBIN_PROCESS_ARTIFACT_ROOT}/keygen.json"
DATXGEN_GO="${RUBIN_PROCESS_ARTIFACT_ROOT}/da_txgen.go"
DA_TX_JSON="${RUBIN_PROCESS_ARTIFACT_ROOT}/da-txs.json"
SECRET_DIR=""; FROM_KEY_FILE=""
REPORT_JSON="${RUBIN_PROCESS_ARTIFACT_ROOT}/go-da-relay-report.json"
MINE_LOG="${RUBIN_PROCESS_ARTIFACT_ROOT}/mine-base.log"
A_DIR="${RUBIN_PROCESS_ARTIFACT_ROOT}/node-a"
B_DIR="${RUBIN_PROCESS_ARTIFACT_ROOT}/node-b"
A_LOG="node-a.log"
B_LOG="node-b.log"
RUBIN_PROCESS_LOGS+=("${MINE_LOG}")

cleanup_from_key_file() { local rc=0; [[ -z "${FROM_KEY_FILE:-}" ]] || rm -f -- "${FROM_KEY_FILE}" || rc=$?; [[ -z "${SECRET_DIR:-}" ]] || rmdir -- "${SECRET_DIR}" || rc=$?; FROM_KEY_FILE=""; SECRET_DIR=""; return "${rc}"; }

go_da_relay_exit_trap() {
  local status=$? cleanup_status=0
  cleanup_from_key_file || cleanup_status=$?
  rubin_process_cleanup "${status}" || cleanup_status=$?
  [[ "${status}" != "0" ]] && exit "${status}"
  exit "${cleanup_status}"
}
trap go_da_relay_exit_trap EXIT
SECRET_PARENT="$(cd -- "${TMPDIR:-/tmp}" && pwd -P)"
[[ "${SECRET_PARENT}" == /* ]] || { echo "unsafe secret temp parent: ${SECRET_PARENT}" >&2; exit 1; }
SECRET_DIR="$(mktemp -d "${SECRET_PARENT}/go-da-relay-key.XXXXXX")"
chmod 700 "${SECRET_DIR}" && FROM_KEY_FILE="${SECRET_DIR}/from-key.hex"

rpc_json() {
  local method="$1" addr="$2" path="$3" body="${4:-}"
  python3 - "${method}" "${addr}" "${path}" "${body}" "${RUBIN_GO_DA_RELAY_RPC_TIMEOUT_SECONDS}" <<'PY'
import math, socket, sys, urllib.error, urllib.request
method, addr, path, body, raw_timeout = sys.argv[1:6]
timeout = float(raw_timeout)
if not math.isfinite(timeout) or timeout <= 0 or timeout > 300:
    raise SystemExit(f"invalid rpc timeout: {raw_timeout!r}")
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

wait_ready() {
  local label="$1" addr="$2" deadline=$((SECONDS + 30))
  while (( SECONDS < deadline )); do
    if rpc_json GET "${addr}" /ready 2>/dev/null | python3 -c 'import json,sys; d=json.load(sys.stdin); sys.exit(0 if d.get("ready") is True else 1)' >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "timeout waiting for ${label} /ready=true addr=${addr}" >&2
  return 1
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

block_hex() {
  rpc_json GET "$1" "/get_block?height=$2" | python3 -c 'import json,sys; d=json.load(sys.stdin); print((d.get("block_hex") or "").lower())'
}

assert_block_omits() { local block="$1" tx_hex="$2" label="$3"; [[ "${block}" != *"${tx_hex}"* ]] || { echo "expected ${label} block to omit tx" >&2; return 1; }; }

p2p_addr_for_pid() {
  python3 - "$1" "$2" <<'PY'
import re, subprocess, sys, time
pid, rpc_addr = sys.argv[1:3]
deadline = time.time() + 30
while time.time() < deadline:
    proc = subprocess.run(["lsof", "-nP", "-a", "-p", pid, "-iTCP", "-sTCP:LISTEN", "-Fn"], text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False)
    addrs = sorted({line[1:].strip() for line in proc.stdout.splitlines() if line.startswith("n") and line[1:].strip() != rpc_addr and re.fullmatch(r"127\.0\.0\.1:[0-9]+", line[1:].strip())})
    if len(addrs) == 1:
        print(addrs[0])
        sys.exit(0)
    if len(addrs) > 1:
        raise SystemExit(f"ambiguous p2p listen addresses for pid={pid}: {addrs}")
    time.sleep(1)
raise SystemExit(f"timeout resolving p2p listen address for pid={pid}")
PY
}

STARTED_PID=""; STARTED_RPC=""; STARTED_P2P=""
start_node_ready() {
  local label="$1" log_file="$2" datadir="$3" peers="${4:-}" args
  args=(--datadir "${datadir}" --bind 127.0.0.1:0 --rpc-bind 127.0.0.1:0 --mine-address "${MINE_ADDRESS_HEX}")
  [[ -z "${peers}" ]] || args+=(--peers "${peers}")
  rubin_process_start "${log_file}" "${NODE_BIN}" "${args[@]}" || { echo "${label} start failed" >&2; return 1; }
  STARTED_PID="${RUBIN_PROCESS_LAST_PID}"
  rubin_process_wait_for_log "${log_file}" "rpc: listening=" 30 "${STARTED_PID}" || return 1
  STARTED_RPC="$(rubin_process_extract_rpc_addr "${log_file}")" || return 1
  _rubin_process_pid_listens_on "${STARTED_PID}" "${STARTED_RPC}" || return 1
  STARTED_P2P="$(p2p_addr_for_pid "${STARTED_PID}" "${STARTED_RPC}")" || return 1
  wait_ready "${label}" "${STARTED_RPC}"
}

write_keygen() {
  cat >"${KEYGEN_GO}" <<'GO'
package main
import (
	"encoding/hex"
	"encoding/json"
	"os"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)
func main() {
	if len(os.Args) != 2 { panic("usage: keygen <from-key-file>") }
	key, err := consensus.NewMLDSA87Keypair(); if err != nil { panic(err) }
	defer key.Close()
	der, err := key.PrivateKeyDER(); if err != nil { panic(err) }
	if err := os.WriteFile(os.Args[1], []byte(hex.EncodeToString(der)), 0o600); err != nil { panic(err) }
	out := map[string]string{"mine_address_hex": hex.EncodeToString(consensus.P2PKCovenantDataForPubkey(key.PubkeyBytes()))}
	if err := json.NewEncoder(os.Stdout).Encode(out); err != nil { panic(err) }
}
GO
}

write_da_txgen() {
  cat >"${DATXGEN_GO}" <<'GO'
package main
import (
	"bytes"
	"crypto/sha3"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"os"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/node"
)
type spendable struct { op consensus.Outpoint; entry consensus.UtxoEntry }
func main() {
	if len(os.Args) != 3 { panic("usage: da-txgen <datadir> <from-key-file>") }
	derHex, err := os.ReadFile(os.Args[2]); if err != nil { panic(err) }
	der, err := hex.DecodeString(string(bytes.TrimSpace(derHex))); if err != nil { panic(err) }
	key, err := consensus.NewMLDSA87KeypairFromDER(der); if err != nil { panic(err) }
	defer key.Close()
	st, err := node.LoadChainState(node.ChainStatePath(node.NormalizeDataDir(os.Args[1]))); if err != nil { panic(err) }
	nextHeight := st.Height + 1
	addr := consensus.P2PKCovenantDataForPubkey(key.PubkeyBytes())
	coins := selectCoins(st, addr, nextHeight, 4)
	payload0 := []byte("rubin-da-relay-process-smoke-0")
	payload1 := []byte("rubin-da-relay-process-smoke-1")
	payload := append(append([]byte(nil), payload0...), payload1...)
	replacement := []byte("rubin-da-relay-replacement")
	daID := sha3.Sum256([]byte("rubin-da-relay-process-smoke-da-id"))
	chunk0 := signDAChunk(st, key, coins[0].op, daID, 3201, 0, payload0)
	commit := signDACommit(st, key, coins[1].op, daID, 3202, payload, 2)
	duplicate := signDACommit(st, key, coins[2].op, daID, 3203, replacement, 2)
	chunk1 := signDAChunk(st, key, coins[3].op, daID, 3204, 1, payload1)
	out := map[string]map[string]string{"chunk0": txJSON(chunk0), "commit": txJSON(commit), "duplicate_commit": txJSON(duplicate), "chunk1": txJSON(chunk1)}
	if err := json.NewEncoder(os.Stdout).Encode(out); err != nil { panic(err) }
}
func selectCoins(st *node.ChainState, addr []byte, nextHeight uint64, count int) []spendable {
	var coins []spendable
	for op, entry := range st.Utxos {
		if !entry.CreatedByCoinbase || entry.CovenantType != consensus.COV_TYPE_P2PK || !bytes.Equal(entry.CovenantData, addr) {
			continue
		}
		if entry.CreationHeight > math.MaxUint64-consensus.COINBASE_MATURITY || nextHeight < entry.CreationHeight+consensus.COINBASE_MATURITY {
			continue
		}
		coins = append(coins, spendable{op: op, entry: entry})
		if len(coins) == count { return coins }
	}
	if len(coins) < count { panic(fmt.Errorf("need %d mature coinbases, have %d", count, len(coins))) }
	return coins
}
func signDACommit(st *node.ChainState, key *consensus.MLDSA87Keypair, op consensus.Outpoint, daID [32]byte, nonce uint64, payload []byte, chunkCount uint16) []byte {
	commitment := sha3.Sum256(payload)
	tx := &consensus.Tx{Version: 1, TxKind: 0x01, TxNonce: nonce, Inputs: []consensus.TxInput{{PrevTxid: op.Txid, PrevVout: op.Vout}}, Outputs: []consensus.TxOutput{{CovenantType: consensus.COV_TYPE_DA_COMMIT, CovenantData: commitment[:]}}, DaCommitCore: &consensus.DaCommitCore{DaID: daID, ChunkCount: chunkCount, BatchNumber: 1}, DaPayload: []byte{0xa1}}
	return signMarshalCheck(st, key, tx)
}
func signDAChunk(st *node.ChainState, key *consensus.MLDSA87Keypair, op consensus.Outpoint, daID [32]byte, nonce uint64, index uint16, payload []byte) []byte {
	hash := sha3.Sum256(payload)
	tx := &consensus.Tx{Version: 1, TxKind: 0x02, TxNonce: nonce, Inputs: []consensus.TxInput{{PrevTxid: op.Txid, PrevVout: op.Vout}}, DaChunkCore: &consensus.DaChunkCore{DaID: daID, ChunkIndex: index, ChunkHash: hash}, DaPayload: append([]byte(nil), payload...)}
	return signMarshalCheck(st, key, tx)
}
func signMarshalCheck(st *node.ChainState, key *consensus.MLDSA87Keypair, tx *consensus.Tx) []byte {
	if err := consensus.SignTransaction(tx, st.Utxos, node.DevnetGenesisChainID(), key); err != nil { panic(err) }
	raw, err := consensus.MarshalTx(tx); if err != nil { panic(err) }
	if _, err := consensus.CheckTransaction(raw, st.Utxos, st.Height+1, 0, node.DevnetGenesisChainID()); err != nil { panic(err) }
	return raw
}
func txJSON(raw []byte) map[string]string {
	_, txid, _, consumed, err := consensus.ParseTx(raw)
	if err != nil || consumed != len(raw) { panic("generated non-canonical tx") }
	return map[string]string{"hex": hex.EncodeToString(raw), "txid": hex.EncodeToString(txid[:])}
}
GO
}

json_field() { python3 -c $'import json,sys\nd=json.load(open(sys.argv[1], encoding="utf-8"))\nv=d[sys.argv[2]][sys.argv[3]]\nif not isinstance(v,str) or not v:\n    raise SystemExit("missing JSON field")\nprint(v)' "$1" "$2" "$3"; }

write_report() {
  export REPORT_JSON NODE_BIN A_DIR B_DIR A_PID B_PID A_RPC_ADDR B_RPC_ADDR A_P2P_ADDR B_P2P_ADDR A_PEERS B_PEERS CHUNK0_TXID COMMIT_TXID DUP_TXID CHUNK1_TXID INCOMPLETE_MINE_HEIGHT INCOMPLETE_MINE_HASH INCOMPLETE_TX_COUNT STAGED_MINE_HEIGHT STAGED_MINE_HASH STAGED_TX_COUNT COMPLETE_MINE_HEIGHT COMPLETE_MINE_HASH COMPLETE_TX_COUNT A_FINAL_HEIGHT A_FINAL_HASH B_FINAL_HEIGHT B_FINAL_HASH
  python3 - <<'PY'
import json, os
e = os.environ
i = lambda key: int(e[key])
report = {
    "scenario": "go_two_node_da_relay_process_smoke",
    "verdict": "PASS",
    "participants": [
        {"name": "node-a", "implementation": "go", "pid": i("A_PID"), "binary": e["NODE_BIN"], "rpc": e["A_RPC_ADDR"], "p2p": e["A_P2P_ADDR"], "datadir": e["A_DIR"], "handshake_peers": i("A_PEERS")},
        {"name": "node-b", "implementation": "go", "pid": i("B_PID"), "binary": e["NODE_BIN"], "rpc": e["B_RPC_ADDR"], "p2p": e["B_P2P_ADDR"], "datadir": e["B_DIR"], "handshake_peers": i("B_PEERS")},
    ],
    "da_relay_evidence": {
        "submitter_to_peer_relay": {"submitted_to": "node-b", "observed_in_mempool": "node-a"},
        "incomplete_set_not_mined": {"mined_by": "node-a", "height": i("INCOMPLETE_MINE_HEIGHT"), "block_hash": e["INCOMPLETE_MINE_HASH"], "tx_count": i("INCOMPLETE_TX_COUNT"), "omitted_chunk_txid": e["CHUNK0_TXID"]},
        "staged_commit_not_mined_until_complete": {"mined_by": "node-a", "height": i("STAGED_MINE_HEIGHT"), "block_hash": e["STAGED_MINE_HASH"], "tx_count": i("STAGED_TX_COUNT"), "omitted_commit_txid": e["COMMIT_TXID"]},
        "complete_set_mined": {"mined_by": "node-a", "height": i("COMPLETE_MINE_HEIGHT"), "block_hash": e["COMPLETE_MINE_HASH"], "tx_count": i("COMPLETE_TX_COUNT"), "included_commit_txid": e["COMMIT_TXID"], "included_chunk_txids": [e["CHUNK0_TXID"], e["CHUNK1_TXID"]]},
        "duplicate_commit_first_seen_no_replacement": {"duplicate_txid": e["DUP_TXID"], "evidence": "duplicate tx hex omitted from complete block"},
    },
    "tx_generator": {"kind": "temporary_go_helper", "evidence_scope": "signed_tx_generation_only_not_runtime_proof"},
    "out_of_scope": ["rust", "mixed_client", "production_runtime_change", "final_devnet_readiness"],
}
if report["participants"][0]["datadir"] == report["participants"][1]["datadir"] or report["participants"][0]["pid"] == report["participants"][1]["pid"]: raise SystemExit("participants are not distinct")
if report["da_relay_evidence"]["incomplete_set_not_mined"]["tx_count"] != 1: raise SystemExit("incomplete set was mined or tx_count proof missing")
if report["da_relay_evidence"]["staged_commit_not_mined_until_complete"]["tx_count"] != 1: raise SystemExit("staged commit set was mined or tx_count proof missing")
if report["da_relay_evidence"]["complete_set_mined"]["tx_count"] != 4: raise SystemExit("complete DA set tx_count proof missing")
with open(e["REPORT_JSON"], "w", encoding="utf-8") as fh:
    json.dump(report, fh, indent=2, sort_keys=True)
    fh.write("\n")
PY
}

echo "Building Go rubin-node"
"${DEV_ENV}" -- go -C "${GO_MODULE_ROOT}" build -o "${NODE_BIN}" ./cmd/rubin-node
write_keygen
RUBIN_OPENSSL_SKIP_FIPS_GUARD=1 "${DEV_ENV}" -- go -C "${GO_MODULE_ROOT}" run "${KEYGEN_GO}" "${FROM_KEY_FILE}" >"${KEYGEN_JSON}"
MINE_ADDRESS_HEX="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["mine_address_hex"])' "${KEYGEN_JSON}")"

mkdir -p "${A_DIR}" "${B_DIR}"
echo "Mining mature Go chain to height ${BASE_HEIGHT}"
"${NODE_BIN}" --datadir "${A_DIR}" --mine-address "${MINE_ADDRESS_HEX}" --mine-blocks "${BASE_HEIGHT}" --mine-exit >"${MINE_LOG}" 2>&1
write_da_txgen
RUBIN_OPENSSL_SKIP_FIPS_GUARD=1 "${DEV_ENV}" -- go -C "${GO_MODULE_ROOT}" run "${DATXGEN_GO}" "${A_DIR}" "${FROM_KEY_FILE}" >"${DA_TX_JSON}"
cleanup_from_key_file
CHUNK0_HEX="$(json_field "${DA_TX_JSON}" chunk0 hex)"
CHUNK0_TXID="$(json_field "${DA_TX_JSON}" chunk0 txid)"
COMMIT_HEX="$(json_field "${DA_TX_JSON}" commit hex)"
COMMIT_TXID="$(json_field "${DA_TX_JSON}" commit txid)"
DUP_HEX="$(json_field "${DA_TX_JSON}" duplicate_commit hex)"
DUP_TXID="$(json_field "${DA_TX_JSON}" duplicate_commit txid)"
CHUNK1_HEX="$(json_field "${DA_TX_JSON}" chunk1 hex)"
CHUNK1_TXID="$(json_field "${DA_TX_JSON}" chunk1 txid)"

cp -R "${A_DIR}/." "${B_DIR}/"
[[ -d "${A_DIR}" && -d "${B_DIR}" && "${A_DIR}" != "${B_DIR}" && ! -L "${A_DIR}" && ! -L "${B_DIR}" ]] || { echo "node datadirs must be distinct non-symlink directories" >&2; exit 1; }
start_node_ready node-b "${B_LOG}" "${B_DIR}"
B_PID="${STARTED_PID}"
B_RPC_ADDR="${STARTED_RPC}"
B_P2P_ADDR="${STARTED_P2P}"
start_node_ready node-a "${A_LOG}" "${A_DIR}" "${B_P2P_ADDR}"
A_PID="${STARTED_PID}"
A_RPC_ADDR="${STARTED_RPC}"
A_P2P_ADDR="${STARTED_P2P}"
A_PEERS="$(wait_peers_ready node-a "${A_RPC_ADDR}")"
B_PEERS="$(wait_peers_ready node-b "${B_RPC_ADDR}")"
IFS=$'\t' read -r _ BASE_HASH < <(tip_tsv "${A_RPC_ADDR}")
wait_tip_exact node-b "${B_RPC_ADDR}" "${BASE_HEIGHT}" "${BASE_HASH}" 30

submit_tx_hex "${B_RPC_ADDR}" "${CHUNK0_HEX}" >/dev/null
wait_mempool_contains node-a "${A_RPC_ADDR}" "${CHUNK0_TXID}"
IFS=$'\t' read -r INCOMPLETE_MINE_HEIGHT INCOMPLETE_MINE_HASH INCOMPLETE_TX_COUNT < <(mine_next_tsv "${A_RPC_ADDR}")
[[ "${INCOMPLETE_MINE_HEIGHT}" == "${INCOMPLETE_HEIGHT}" && "${INCOMPLETE_TX_COUNT}" == "1" ]] || {
  echo "incomplete DA set mined unexpectedly height=${INCOMPLETE_MINE_HEIGHT} tx_count=${INCOMPLETE_TX_COUNT}" >&2
  exit 1
}
wait_tip_exact node-b "${B_RPC_ADDR}" "${INCOMPLETE_HEIGHT}" "${INCOMPLETE_MINE_HASH}" 60
INCOMPLETE_BLOCK_HEX="$(block_hex "${A_RPC_ADDR}" "${INCOMPLETE_HEIGHT}")"
assert_block_omits "${INCOMPLETE_BLOCK_HEX}" "${CHUNK0_HEX}" "incomplete"

submit_tx_hex "${B_RPC_ADDR}" "${COMMIT_HEX}" >/dev/null
wait_mempool_contains node-a "${A_RPC_ADDR}" "${COMMIT_TXID}"
IFS=$'\t' read -r STAGED_MINE_HEIGHT STAGED_MINE_HASH STAGED_TX_COUNT < <(mine_next_tsv "${A_RPC_ADDR}")
[[ "${STAGED_MINE_HEIGHT}" == "$((INCOMPLETE_HEIGHT + 1))" && "${STAGED_TX_COUNT}" == "1" ]] || { echo "staged DA set mined unexpectedly height=${STAGED_MINE_HEIGHT} tx_count=${STAGED_TX_COUNT}" >&2; exit 1; }
wait_tip_exact node-b "${B_RPC_ADDR}" "${STAGED_MINE_HEIGHT}" "${STAGED_MINE_HASH}" 60
STAGED_BLOCK_HEX="$(block_hex "${A_RPC_ADDR}" "${STAGED_MINE_HEIGHT}")"
[[ "${STAGED_BLOCK_HEX}" != *"${CHUNK0_HEX}"* && "${STAGED_BLOCK_HEX}" != *"${COMMIT_HEX}"* ]] || { echo "expected staged block to omit incomplete DA txs" >&2; exit 1; }
submit_tx_hex "${B_RPC_ADDR}" "${DUP_HEX}" >/dev/null
wait_mempool_contains node-a "${A_RPC_ADDR}" "${DUP_TXID}"
submit_tx_hex "${B_RPC_ADDR}" "${CHUNK1_HEX}" >/dev/null
wait_mempool_contains node-a "${A_RPC_ADDR}" "${CHUNK1_TXID}"
COMPLETE_FOUND=0
for _ in 1 2 3 4 5; do
  IFS=$'\t' read -r COMPLETE_MINE_HEIGHT COMPLETE_MINE_HASH COMPLETE_TX_COUNT < <(mine_next_tsv "${A_RPC_ADDR}")
  wait_tip_exact node-b "${B_RPC_ADDR}" "${COMPLETE_MINE_HEIGHT}" "${COMPLETE_MINE_HASH}" 60
  COMPLETE_BLOCK_HEX="$(block_hex "${A_RPC_ADDR}" "${COMPLETE_MINE_HEIGHT}")"
  [[ "${COMPLETE_TX_COUNT}" == "4" && "${COMPLETE_BLOCK_HEX}" == *"${COMMIT_HEX}"* && "${COMPLETE_BLOCK_HEX}" == *"${CHUNK0_HEX}"* && "${COMPLETE_BLOCK_HEX}" == *"${CHUNK1_HEX}"* && "${COMPLETE_BLOCK_HEX}" != *"${DUP_HEX}"* ]] && { COMPLETE_FOUND=1; break; }
done
[[ "${COMPLETE_FOUND}" == "1" ]] || { echo "complete DA set not mined by receiver node-a" >&2; exit 1; }
IFS=$'\t' read -r A_FINAL_HEIGHT A_FINAL_HASH < <(tip_tsv "${A_RPC_ADDR}")
IFS=$'\t' read -r B_FINAL_HEIGHT B_FINAL_HASH < <(tip_tsv "${B_RPC_ADDR}")
[[ "${A_FINAL_HEIGHT}" == "${B_FINAL_HEIGHT}" && "${A_FINAL_HASH}" == "${B_FINAL_HASH}" && "${A_FINAL_HASH}" == "${COMPLETE_MINE_HASH}" ]] || {
  echo "final convergence mismatch node-a=${A_FINAL_HEIGHT}/${A_FINAL_HASH} node-b=${B_FINAL_HEIGHT}/${B_FINAL_HASH}" >&2
  exit 1
}

write_report
echo "PASS: Go DA relay process smoke completed; report=${REPORT_JSON}"
