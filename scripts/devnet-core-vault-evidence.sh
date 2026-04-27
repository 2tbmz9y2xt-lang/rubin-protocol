#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEV_ENV="${REPO_ROOT}/scripts/dev-env.sh"
GO_MODULE_ROOT="${REPO_ROOT}/clients/go"
HELPER="${REPO_ROOT}/scripts/devnet-process-common.sh"
FIXTURE_PATH="${CORE_VAULT_FIXTURE_PATH:-${REPO_ROOT}/conformance/fixtures/devnet/devnet-vault-create-01.json}"
VECTOR_ID="${CORE_VAULT_VECTOR_ID:-DEVNET-VAULT-CREATE-01}"
DEVNET_CHAIN_ID="88f8a9acdeeb902e27aa2fdcb8c46ecf818bf68dec5273ec1bcc5084e2333103"
: "${KEEP_TMP:=1}"
export KEEP_TMP
export RUBIN_PROCESS_ARTIFACT_PARENT="${CORE_VAULT_ARTIFACT_PARENT:-${TMPDIR:-/tmp}/rubin-core-vault-evidence}"

for tool in python3 perl; do
  command -v "${tool}" >/dev/null 2>&1 || { echo "${tool} is required for CORE_VAULT evidence" >&2; exit 1; }
done

# shellcheck source=scripts/devnet-process-common.sh disable=SC1091
source "${HELPER}"
rubin_process_init core-vault-evidence

NODE_BIN="${RUBIN_PROCESS_ARTIFACT_ROOT}/rubin-node-go"
SEED_GO="${RUBIN_PROCESS_ARTIFACT_ROOT}/seed_core_vault.go"
REPORT_JSON="${RUBIN_PROCESS_ARTIFACT_ROOT}/core-vault-evidence-report.json"
NODE_DIR="${RUBIN_PROCESS_ARTIFACT_ROOT}/node-a"
NODE_LOG="node-a.log"
NODE_PID=""
NODE_RPC_ADDR=""
CHAIN_IDENTITY_JSON="{}"
SUBMIT_JSON=""
SUBMITTED_TXID=""
MINE_JSON=""
MINED_HEIGHT=""
MINED_HASH=""
BLOCK_JSON=""
PHASE="init"

write_report() {
  local status="$1" reason="$2"
  python3 - "${REPORT_JSON}" "${status}" "${PHASE}" "${reason}" "${FIXTURE_PATH}" "${VECTOR_ID}" \
    "${RUBIN_PROCESS_ARTIFACT_ROOT}" "${NODE_PID}" "${NODE_RPC_ADDR}" "${NODE_DIR}" \
    "${CHAIN_IDENTITY_JSON}" "${SUBMIT_JSON}" "${DEVNET_CHAIN_ID}" "${SUBMITTED_TXID}" \
    "${MINE_JSON}" "${MINED_HEIGHT}" "${MINED_HASH}" "${BLOCK_JSON}" <<'PY' || true
import json, sys
(
    path,
    status,
    phase,
    reason,
    fixture,
    vector,
    root,
    pid,
    rpc,
    datadir,
    identity_raw,
    submit_raw,
    devnet_chain_id,
    submitted_txid,
    mine_raw,
    mined_height,
    mined_hash,
    block_raw,
) = sys.argv[1:19]
def load(raw):
    try: return json.loads(raw) if raw else None
    except Exception: return {"raw": raw}
participants = []
if pid and rpc:
    participants.append({"name":"node-a","pid":int(pid),"rpc":rpc,"datadir":datadir,"chain_identity":load(identity_raw)})
verdict = "PASS" if status == "PASS" else "FAIL"
report = {
    "scenario":"CORE_VAULT", "status":status,
    "canonical_input":{"artifact":fixture,"vector_id":vector},
    "canonical_input_chain_id":devnet_chain_id,
    "live_devnet_chain_id":devnet_chain_id, "artifact_root":root,
    "participants":participants, "submitted_txid":submitted_txid or None,
    "mined_height":int(mined_height) if mined_height else None,
    "mined_hash":mined_hash or None,
    "inclusion_node":"node-a" if status == "PASS" else None,
    "inclusion_proven":status == "PASS",
    "live_submit_response":load(submit_raw),
    "live_mine_response":load(mine_raw),
    "live_block_response":load(block_raw),
    "verdict":verdict,
    "phase":phase,
}
if status != "PASS":
    report["failure_phase"] = phase
    report["failure_reason"] = reason
with open(path, "w", encoding="utf-8") as fh:
    json.dump(report, fh, indent=2, sort_keys=True); fh.write("\n")
PY
}

fail() { local status="$1" reason="$2"; write_report "${status}" "${reason}"; echo "${reason}" >&2; exit 1; }

rpc_json() {
  local method="$1" addr="$2" path="$3" body="${4:-}"
  python3 - "${method}" "${addr}" "${path}" "${body}" <<'PY'
import socket, sys, urllib.error, urllib.request
method, addr, path, body = sys.argv[1:5]
req = urllib.request.Request(f"http://{addr}{path}", data=(body.encode() if body else None), method=method)
if body: req.add_header("Content-Type", "application/json")
try:
    with urllib.request.urlopen(req, timeout=5) as resp: print(resp.read().decode(), end="")
except urllib.error.HTTPError as exc:
    print(exc.read().decode(), end=""); sys.exit(22)
except (urllib.error.URLError, TimeoutError, socket.timeout) as exc:
    print(f"request failed: {getattr(exc, 'reason', exc)}", end=""); sys.exit(1)
PY
}

wait_ready_true() {
  local addr="$1" deadline=$((SECONDS + 30)) body
  while ((SECONDS < deadline)); do
    if body="$(rpc_json GET "${addr}" /ready 2>/dev/null)" &&
      printf '%s' "${body}" | python3 -c 'import json,sys; sys.exit(0 if json.load(sys.stdin).get("ready") is True else 1)' 2>/dev/null; then
      return 0
    fi
    sleep 1
  done
  return 1
}

write_seed_go() {
  cat >"${SEED_GO}" <<'GO'
package main
import (
	"encoding/hex"; "encoding/json"; "flag"; "os"
	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/node"
)
type fixture struct{ Vectors []struct{ ID string `json:"id"`; ExpectOK bool `json:"expect_ok"`; ExpectErr string `json:"expect_err"`; TxHex string `json:"tx_hex"`; Utxos []struct{ Txid string `json:"txid"`; Vout uint32 `json:"vout"`; Value uint64 `json:"value"`; CovenantType uint16 `json:"covenant_type"`; CovenantData string `json:"covenant_data"`; CreationHeight uint64 `json:"creation_height"`; CreatedByCoinbase bool `json:"created_by_coinbase"` } `json:"utxos"` } `json:"vectors"` }
func main() {
	datadir, fixturePath, vectorID := flag.String("datadir", "", ""), flag.String("fixture", "", ""), flag.String("vector-id", "", "")
	flag.Parse(); raw, err := os.ReadFile(*fixturePath); if err != nil { panic(err) }
	var fx fixture; if err := json.Unmarshal(raw, &fx); err != nil { panic(err) }
	idx := -1; for i := range fx.Vectors { if fx.Vectors[i].ID == *vectorID { idx = i; break } }
	if idx < 0 { panic("CORE_VAULT vector not found") }
	v := fx.Vectors[idx]
	if *datadir == "" || !v.ExpectOK || v.ExpectErr != "" || v.TxHex == "" || len(v.Utxos) == 0 { panic("CORE_VAULT vector is not an expect_ok tx with utxo context") }
	st := node.NewChainState(); store, err := node.OpenBlockStore(node.BlockStorePath(*datadir)); if err != nil { panic(err) }
	engine, err := node.NewSyncEngine(st, store, node.DefaultSyncConfig(nil, node.DevnetGenesisChainID(), node.ChainStatePath(*datadir))); if err != nil { panic(err) }
	if _, err := engine.ApplyBlock(node.DevnetGenesisBlockBytes(), nil); err != nil { panic(err) }
	for _, u := range v.Utxos { txidBytes, err := hex.DecodeString(u.Txid); if err != nil || len(txidBytes) != 32 { panic("invalid fixture txid") }; cov, err := hex.DecodeString(u.CovenantData); if err != nil { panic("invalid fixture covenant_data") }; var txid [32]byte; copy(txid[:], txidBytes); st.Utxos[consensus.Outpoint{Txid: txid, Vout: u.Vout}] = consensus.UtxoEntry{Value: u.Value, CovenantType: u.CovenantType, CovenantData: cov, CreationHeight: u.CreationHeight, CreatedByCoinbase: u.CreatedByCoinbase} }
	if err := st.Save(node.ChainStatePath(*datadir)); err != nil { panic(err) }
}
GO
}

PHASE="fixture_preflight"
[[ -f "${FIXTURE_PATH}" ]] || fail FAIL_MISSING_CANONICAL_INPUT "canonical CORE_VAULT fixture missing: ${FIXTURE_PATH}"
TX_HEX="$(python3 - "${FIXTURE_PATH}" "${VECTOR_ID}" "${DEVNET_CHAIN_ID}" <<'PY'
import json, sys
root = json.load(open(sys.argv[1], encoding="utf-8"))
vector_id = sys.argv[2]
devnet_chain_id = sys.argv[3]
match = [v for v in root.get("vectors", []) if v.get("id") == vector_id]
if len(match) != 1: raise SystemExit("vector count mismatch")
v = match[0]
if v.get("expect_ok") is not True or v.get("expect_err") or not v.get("tx_hex") or not v.get("utxos"): raise SystemExit("bad vector")
if v.get("chain_id_hex") != devnet_chain_id: raise SystemExit("vector chain_id_hex is not canonical devnet chain_id")
bytes.fromhex(v["tx_hex"])
for u in v["utxos"]: bytes.fromhex(u["txid"]); bytes.fromhex(u["covenant_data"])
print(v["tx_hex"])
PY
)" || fail FAIL_MISSING_CANONICAL_INPUT "canonical CORE_VAULT vector ${VECTOR_ID} is missing or unusable"

PHASE="build"
echo "Building Go rubin-node"
"${DEV_ENV}" -- go -C "${GO_MODULE_ROOT}" build -o "${NODE_BIN}" ./cmd/rubin-node || fail FAIL_LOCAL_HARNESS "rubin-node build failed"
write_seed_go
mkdir -p "${NODE_DIR}" || fail FAIL_LOCAL_HARNESS "failed to create node datadir"
PHASE="seed_fixture_context"
"${DEV_ENV}" -- go -C "${GO_MODULE_ROOT}" run "${SEED_GO}" --datadir "${NODE_DIR}" --fixture "${FIXTURE_PATH}" --vector-id "${VECTOR_ID}" || fail FAIL_LOCAL_HARNESS "failed to seed canonical CORE_VAULT fixture context"

PHASE="start_live_node"
echo "Starting Go rubin-node with canonical CORE_VAULT fixture context"
rubin_process_start "${NODE_LOG}" "${NODE_BIN}" --datadir "${NODE_DIR}" --bind 127.0.0.1:0 --rpc-bind 127.0.0.1:0 || fail FAIL_LOCAL_HARNESS "rubin-node start failed"
NODE_PID="${RUBIN_PROCESS_LAST_PID}"
rubin_process_wait_for_log "${NODE_LOG}" "rpc: listening=" 30 "${NODE_PID}" || fail FAIL_LOCAL_HARNESS "rubin-node did not expose RPC"
NODE_RPC_ADDR="$(rubin_process_extract_rpc_addr "${NODE_LOG}")" || fail FAIL_LOCAL_HARNESS "failed to extract node RPC address"
rubin_process_wait_for_rpc_ready "${NODE_RPC_ADDR}" 30 || fail FAIL_LOCAL_HARNESS "node RPC did not answer /get_tip"
wait_ready_true "${NODE_RPC_ADDR}" || fail FAIL_LOCAL_HARNESS "node /ready did not report ready=true"
CHAIN_IDENTITY_JSON="$(rpc_json GET "${NODE_RPC_ADDR}" /chain_identity)" || fail FAIL_LOCAL_HARNESS "chain_identity query failed"

PHASE="submit_live_rpc"
echo "Submitting canonical CORE_VAULT tx through live /submit_tx"
SUBMIT_BODY="$(python3 -c 'import json,sys; print(json.dumps({"tx_hex": sys.argv[1]}))' "${TX_HEX}")"
SUBMIT_JSON="$(rpc_json POST "${NODE_RPC_ADDR}" /submit_tx "${SUBMIT_BODY}")" || fail FAIL_SUBMIT "submit_tx request failed: ${SUBMIT_JSON}"
SUBMITTED_TXID="$(python3 - "${SUBMIT_JSON}" <<'PY'
import json, sys
d = json.loads(sys.argv[1])
if d.get("accepted") is not True or not d.get("txid"):
    raise SystemExit(f"submit_tx did not accept CORE_VAULT tx: {d}")
print(d["txid"])
PY
)" || fail FAIL_SUBMIT "submit_tx did not accept CORE_VAULT tx: ${SUBMIT_JSON}"

PHASE="mine_live_rpc"
echo "Mining submitted CORE_VAULT tx through live /mine_next"
MINE_JSON="$(rpc_json POST "${NODE_RPC_ADDR}" /mine_next "{}")" || fail FAIL_MINE "mine_next request failed: ${MINE_JSON}"
MINE_PARSED="$(python3 - "${MINE_JSON}" <<'PY'
import json, sys
d = json.loads(sys.argv[1])
if d.get("mined") is not True or d.get("height") is None or not d.get("block_hash"):
    raise SystemExit(f"mine_next did not mine a block: {d}")
print(d["height"], d["block_hash"])
PY
)" || fail FAIL_MINE "mine_next did not mine a block: ${MINE_JSON}"
read -r MINED_HEIGHT MINED_HASH <<<"${MINE_PARSED}"

PHASE="query_inclusion"
BLOCK_JSON="$(rpc_json GET "${NODE_RPC_ADDR}" "/get_block?height=${MINED_HEIGHT}")" || fail FAIL_INCLUSION "get_block failed at height ${MINED_HEIGHT}: ${BLOCK_JSON}"
python3 - "${BLOCK_JSON}" "${MINED_HEIGHT}" "${MINED_HASH}" "${TX_HEX}" <<'PY' || fail FAIL_INCLUSION "mined block does not prove CORE_VAULT inclusion"
import json, sys
d = json.loads(sys.argv[1])
want_height = int(sys.argv[2])
want_hash = sys.argv[3].lower()
tx_hex = sys.argv[4].lower()
if d.get("height") != want_height:
    raise SystemExit(f"height mismatch: {d.get('height')} != {want_height}")
if str(d.get("hash", "")).lower() != want_hash:
    raise SystemExit(f"hash mismatch: {d.get('hash')} != {want_hash}")
if d.get("canonical") is not True:
    raise SystemExit("block is not canonical")
if tx_hex not in str(d.get("block_hex", "")).lower():
    raise SystemExit("submitted CORE_VAULT tx bytes missing from mined block")
PY

PHASE="pass"
write_report PASS ""
echo "PASS: CORE_VAULT live evidence submit->mine->query succeeded; report=${REPORT_JSON}"
