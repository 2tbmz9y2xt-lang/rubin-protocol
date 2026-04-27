#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEV_ENV="${REPO_ROOT}/scripts/dev-env.sh"
GO_MODULE_ROOT="${REPO_ROOT}/clients/go"
HELPER="${REPO_ROOT}/scripts/devnet-process-common.sh"
FIXTURE_PATH="${CORE_VAULT_FIXTURE_PATH:-${REPO_ROOT}/conformance/fixtures/CV-VAULT.json}"
VECTOR_ID="${CORE_VAULT_VECTOR_ID:-VAULT-CREATE-02}"
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
VECTOR_JSON="${RUBIN_PROCESS_ARTIFACT_ROOT}/core-vault-vector.json"
SEED_JSON="${RUBIN_PROCESS_ARTIFACT_ROOT}/seed-core-vault.json"
REPORT_JSON="${RUBIN_PROCESS_ARTIFACT_ROOT}/core-vault-evidence-report.json"
NODE_DIR="${RUBIN_PROCESS_ARTIFACT_ROOT}/node-a"
NODE_LOG="node-a.log"
NODE_PID=""
NODE_RPC_ADDR=""
TX_HEX=""
MINE_ADDRESS_HEX=""
SUBMITTED_TXID=""
MINED_HEIGHT=""
MINED_HASH=""
TX_COUNT=""
CHAIN_IDENTITY_JSON="{}"
SUBMIT_JSON=""
CURRENT_PHASE="init"

write_fail_report() {
  local reason="$1"
  python3 - "${REPORT_JSON}" "${reason}" "${CURRENT_PHASE}" "${FIXTURE_PATH}" "${VECTOR_ID}" "${RUBIN_PROCESS_ARTIFACT_ROOT}" \
    "${NODE_PID}" "${NODE_RPC_ADDR}" "${NODE_DIR}" "${CHAIN_IDENTITY_JSON}" "${SUBMIT_JSON}" <<'PY' || true
import json, sys
path, reason, phase, fixture, vector_id, artifact_root, pid, rpc, datadir, identity_raw, submit_raw = sys.argv[1:12]
participants = []
if pid and rpc:
    try:
        chain_identity = json.loads(identity_raw)
    except Exception:
        chain_identity = {"raw": identity_raw}
    participants.append({
        "name": "node-a",
        "pid": int(pid),
        "rpc": rpc,
        "datadir": datadir,
        "chain_identity": chain_identity,
    })
try:
    live_submit_response = json.loads(submit_raw) if submit_raw else None
except Exception:
    live_submit_response = {"raw": submit_raw}
report = {
    "scenario": "CORE_VAULT",
    "status": "BLOCKED_BY_1312",
    "canonical_input": {"artifact": fixture, "vector_id": vector_id},
    "canonical_input_chain_id": "zero_chain_id_fixture_signature",
    "live_devnet_chain_id": "88f8a9acdeeb902e27aa2fdcb8c46ecf818bf68dec5273ec1bcc5084e2333103",
    "artifact_root": artifact_root,
    "participants": participants,
    "submitted_txid": None,
    "mined_height": None,
    "mined_hash": None,
    "inclusion_node": None,
    "inclusion_proven": False,
    "expected_current_live_submit_error": "TX_ERR_SIG_INVALID",
    "live_submit_response": live_submit_response,
    "verdict": "FAIL",
    "failure_phase": phase,
    "failure_reason": reason,
}
with open(path, "w", encoding="utf-8") as fh:
    json.dump(report, fh, indent=2, sort_keys=True)
    fh.write("\n")
PY
}

fail() {
  local reason="$1"
  write_fail_report "${reason}"
  echo "${reason}" >&2
  exit 1
}

rpc_json() {
  local method="$1" addr="$2" path="$3" body="${4:-}"
  python3 - "${method}" "${addr}" "${path}" "${body}" <<'PY'
import socket, sys, urllib.error, urllib.request
method, addr, path, body = sys.argv[1:5]
data = body.encode() if body else None
req = urllib.request.Request(f"http://{addr}{path}", data=data, method=method)
if body:
    req.add_header("Content-Type", "application/json")
try:
    with urllib.request.urlopen(req, timeout=5) as resp:
        print(resp.read().decode("utf-8"), end="")
except urllib.error.HTTPError as exc:
    print(exc.read().decode("utf-8"), end=""); sys.exit(22)
except (urllib.error.URLError, TimeoutError, socket.timeout) as exc:
    print(f"request failed: {getattr(exc, 'reason', exc)}", end=""); sys.exit(1)
PY
}

wait_ready_true() {
  local addr="$1" timeout="$2" body
  local deadline=$((SECONDS + timeout))
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
  cat >"${SEED_GO}" <<'EOF'
package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/node"
)

type fixture struct {
	Vectors []vector `json:"vectors"`
}
type vector struct {
	ID       string        `json:"id"`
	ExpectOK bool          `json:"expect_ok"`
	ExpectErr string       `json:"expect_err"`
	TxHex    string        `json:"tx_hex"`
	Utxos    []fixtureUTXO `json:"utxos"`
}
type fixtureUTXO struct {
	Txid              string `json:"txid"`
	Vout              uint32 `json:"vout"`
	Value             uint64 `json:"value"`
	CovenantType      uint16 `json:"covenant_type"`
	CovenantData      string `json:"covenant_data"`
	CreationHeight    uint64 `json:"creation_height"`
	CreatedByCoinbase bool   `json:"created_by_coinbase"`
}

func main() {
	datadir := flag.String("datadir", "", "node datadir")
	fixturePath := flag.String("fixture", "", "CV-VAULT fixture")
	vectorID := flag.String("vector-id", "", "vector id")
	flag.Parse()
	if *datadir == "" || *fixturePath == "" || *vectorID == "" {
		panic("datadir, fixture, and vector-id are required")
	}
	raw, err := os.ReadFile(*fixturePath)
	if err != nil {
		panic(err)
	}
	var fx fixture
	if err := json.Unmarshal(raw, &fx); err != nil {
		panic(err)
	}
	var selected *vector
	for i := range fx.Vectors {
		if fx.Vectors[i].ID == *vectorID {
			selected = &fx.Vectors[i]
			break
		}
	}
	if selected == nil {
		panic("CORE_VAULT vector not found")
	}
	if !selected.ExpectOK || selected.ExpectErr != "" || selected.TxHex == "" || len(selected.Utxos) == 0 {
		panic("CORE_VAULT vector is not an expect_ok tx with utxo context")
	}
	st := node.NewChainState()
	store, err := node.OpenBlockStore(node.BlockStorePath(*datadir))
	if err != nil {
		panic(err)
	}
	engine, err := node.NewSyncEngine(st, store, node.DefaultSyncConfig(nil, node.DevnetGenesisChainID(), node.ChainStatePath(*datadir)))
	if err != nil {
		panic(err)
	}
	if _, err := engine.ApplyBlock(node.DevnetGenesisBlockBytes(), nil); err != nil {
		panic(err)
	}
	for _, u := range selected.Utxos {
		txidBytes, err := hex.DecodeString(u.Txid)
		if err != nil || len(txidBytes) != 32 {
			panic(fmt.Sprintf("invalid fixture txid for %s:%d", u.Txid, u.Vout))
		}
		var txid [32]byte
		copy(txid[:], txidBytes)
		cov, err := hex.DecodeString(u.CovenantData)
		if err != nil {
			panic(fmt.Sprintf("invalid fixture covenant_data for %s:%d", u.Txid, u.Vout))
		}
		st.Utxos[consensus.Outpoint{Txid: txid, Vout: u.Vout}] = consensus.UtxoEntry{
			Value:             u.Value,
			CovenantType:      u.CovenantType,
			CovenantData:      cov,
			CreationHeight:    u.CreationHeight,
			CreatedByCoinbase: u.CreatedByCoinbase,
		}
	}
	if err := st.Save(node.ChainStatePath(*datadir)); err != nil {
		panic(err)
	}
	out := map[string]any{"vector_id": selected.ID, "height": st.Height, "tip_hash": fmt.Sprintf("%x", st.TipHash[:]), "utxo_count": len(st.Utxos)}
	if err := json.NewEncoder(os.Stdout).Encode(out); err != nil {
		panic(err)
	}
}
EOF
}

CURRENT_PHASE="fixture_preflight"
[[ -f "${FIXTURE_PATH}" ]] || fail "canonical CORE_VAULT fixture missing: ${FIXTURE_PATH}"
python3 - "${FIXTURE_PATH}" "${VECTOR_ID}" "${VECTOR_JSON}" <<'PY' || fail "canonical CORE_VAULT vector ${VECTOR_ID} is missing or unusable"
import json, sys
fixture, vector_id, out = sys.argv[1:4]
root = json.load(open(fixture, encoding="utf-8"))
matches = [v for v in root.get("vectors", []) if v.get("id") == vector_id]
if len(matches) != 1:
    raise SystemExit(f"expected exactly one {vector_id}, got {len(matches)}")
v = matches[0]
if v.get("expect_ok") is not True or v.get("expect_err") or not v.get("tx_hex") or not v.get("utxos"):
    raise SystemExit("vector must be expect_ok with tx_hex and utxos")
bytes.fromhex(v["tx_hex"])
for u in v["utxos"]:
    bytes.fromhex(u["txid"]); bytes.fromhex(u["covenant_data"])
with open(out, "w", encoding="utf-8") as fh:
    json.dump(v, fh, indent=2, sort_keys=True)
    fh.write("\n")
PY
TX_HEX="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["tx_hex"])' "${VECTOR_JSON}")"
MINE_ADDRESS_HEX="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["utxos"][0]["covenant_data"])' "${VECTOR_JSON}")"

CURRENT_PHASE="build"
echo "Building Go rubin-node"
"${DEV_ENV}" -- go -C "${GO_MODULE_ROOT}" build -o "${NODE_BIN}" ./cmd/rubin-node || fail "rubin-node build failed"
write_seed_go
mkdir -p "${NODE_DIR}" || fail "failed to create node datadir"
CURRENT_PHASE="seed_fixture_context"
"${DEV_ENV}" -- go -C "${GO_MODULE_ROOT}" run "${SEED_GO}" --datadir "${NODE_DIR}" --fixture "${FIXTURE_PATH}" --vector-id "${VECTOR_ID}" >"${SEED_JSON}" ||
  fail "failed to seed canonical CORE_VAULT fixture context"

CURRENT_PHASE="start_live_node"
echo "Starting Go rubin-node with canonical CORE_VAULT fixture context"
rubin_process_start "${NODE_LOG}" "${NODE_BIN}" --datadir "${NODE_DIR}" --bind 127.0.0.1:0 --rpc-bind 127.0.0.1:0 --mine-address "${MINE_ADDRESS_HEX}" ||
  fail "rubin-node start failed"
NODE_PID="${RUBIN_PROCESS_LAST_PID}"
rubin_process_wait_for_log "${NODE_LOG}" "rpc: listening=" 30 "${NODE_PID}" || fail "rubin-node did not expose RPC"
NODE_RPC_ADDR="$(rubin_process_extract_rpc_addr "${NODE_LOG}")" || fail "failed to extract node RPC address"
rubin_process_wait_for_rpc_ready "${NODE_RPC_ADDR}" 30 || fail "node RPC did not answer /get_tip"
wait_ready_true "${NODE_RPC_ADDR}" 30 || fail "node /ready did not report ready=true"
CHAIN_IDENTITY_JSON="$(rpc_json GET "${NODE_RPC_ADDR}" /chain_identity)" || fail "chain_identity query failed"

CURRENT_PHASE="submit_live_rpc"
echo "Submitting canonical CORE_VAULT tx through live /submit_tx"
SUBMIT_BODY="$(python3 -c 'import json,sys; print(json.dumps({"tx_hex": sys.argv[1]}))' "${TX_HEX}")"
SUBMIT_JSON="$(rpc_json POST "${NODE_RPC_ADDR}" /submit_tx "${SUBMIT_BODY}")" ||
  fail "submit_tx request failed: ${SUBMIT_JSON}"
SUBMITTED_TXID="$(printf '%s' "${SUBMIT_JSON}" | python3 -c 'import json,sys; d=json.load(sys.stdin); (d.get("accepted") is True and d.get("txid")) or sys.exit("submit_tx did not accept: "+json.dumps(d, sort_keys=True)); print(d["txid"])')" ||
  fail "submit_tx response did not prove acceptance"
MEMPOOL_JSON="$(rpc_json GET "${NODE_RPC_ADDR}" /get_mempool)" || fail "get_mempool request failed"
python3 -c 'import json,sys; d=json.load(sys.stdin); txid=sys.argv[1]; txid in d.get("txids", []) or sys.exit(json.dumps(d, sort_keys=True))' \
  "${SUBMITTED_TXID}" <<<"${MEMPOOL_JSON}" || fail "submitted txid missing from live mempool"

CURRENT_PHASE="mine_live_rpc"
echo "Mining CORE_VAULT tx through live /mine_next"
MINE_JSON="$(rpc_json POST "${NODE_RPC_ADDR}" /mine_next '{}')" || fail "mine_next request failed: ${MINE_JSON}"
IFS=$'\t' read -r MINED_HEIGHT MINED_HASH TX_COUNT < <(printf '%s' "${MINE_JSON}" | python3 -c 'import json,sys; d=json.load(sys.stdin); (d.get("mined") is True) or sys.exit("mine_next failed: "+json.dumps(d, sort_keys=True)); print(d["height"], d["block_hash"], d["tx_count"], sep="\t")') ||
  fail "mine_next response did not prove mined block"
[[ "${TX_COUNT}" =~ ^[0-9]+$ && "${TX_COUNT}" -ge 2 ]] || fail "mined block tx_count=${TX_COUNT}, expected at least coinbase plus CORE_VAULT tx"
TIP_JSON="$(rpc_json GET "${NODE_RPC_ADDR}" /get_tip)" || fail "get_tip request failed after mine"
python3 -c 'import json,sys; d=json.load(sys.stdin); ok=(str(d.get("height")) == sys.argv[1] and str(d.get("tip_hash", "")).lower() == sys.argv[2].lower()); ok or sys.exit(json.dumps(d, sort_keys=True))' \
  "${MINED_HEIGHT}" "${MINED_HASH}" <<<"${TIP_JSON}" || fail "live tip does not match mined CORE_VAULT block"

CURRENT_PHASE="query_live_inclusion"
echo "Querying mined block through live /get_block"
BLOCK_JSON="$(rpc_json GET "${NODE_RPC_ADDR}" "/get_block?height=${MINED_HEIGHT}")" ||
  fail "get_block request failed for mined height ${MINED_HEIGHT}: ${BLOCK_JSON}"
python3 -c 'import json,sys; d=json.load(sys.stdin); expected=sys.argv[1].lower(); tx_hex=sys.argv[2].lower(); actual=(d.get("hash") or d.get("block_hash") or "").lower(); ok=(actual == expected and d.get("canonical") is True and tx_hex in d.get("block_hex", "").lower()); ok or sys.exit(json.dumps({"expected_hash": expected, "actual_hash": actual, "canonical": d.get("canonical")}, sort_keys=True))' \
  "${MINED_HASH}" "${TX_HEX}" <<<"${BLOCK_JSON}" || fail "live get_block did not prove CORE_VAULT inclusion"

CURRENT_PHASE="write_pass_report"
python3 - "${REPORT_JSON}" "${FIXTURE_PATH}" "${VECTOR_ID}" "${NODE_PID}" "${NODE_RPC_ADDR}" "${NODE_DIR}" "${CHAIN_IDENTITY_JSON}" "${SUBMITTED_TXID}" "${MINED_HEIGHT}" "${MINED_HASH}" "${TX_COUNT}" <<'PY' ||
import json, sys
path, fixture, vector_id, pid, rpc, datadir, identity_raw, txid, height, block_hash, tx_count = sys.argv[1:12]
participant = {
    "name": "node-a",
    "pid": int(pid),
    "rpc": rpc,
    "datadir": datadir,
    "chain_identity": json.loads(identity_raw),
}
report = {
    "scenario": "CORE_VAULT",
    "canonical_input": {"artifact": fixture, "vector_id": vector_id},
    "participants": [participant],
    "submitted_txid": txid,
    "mined_height": int(height),
    "mined_hash": block_hash,
    "inclusion_node": "node-a",
    "inclusion_proven": True,
    "verdict": "PASS",
    "failure_reason": None,
    "proof": {
        "submit": "live_rpc:/submit_tx",
        "mine": "live_rpc:/mine_next",
        "query": "live_rpc:/get_block",
        "tx_count": int(tx_count),
    },
}
names = {p["name"] for p in report["participants"]}
if report["inclusion_node"] not in names or not report["inclusion_proven"] or report["verdict"] != "PASS":
    raise SystemExit("internal report consistency failure")
with open(path, "w", encoding="utf-8") as fh:
    json.dump(report, fh, indent=2, sort_keys=True)
    fh.write("\n")
PY
  fail "failed to write PASS report"

echo "PASS: CORE_VAULT tx ${SUBMITTED_TXID} mined at height ${MINED_HEIGHT} hash ${MINED_HASH}; report=${REPORT_JSON}"
