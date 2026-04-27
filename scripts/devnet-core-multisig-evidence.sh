#!/usr/bin/env bash
set -euo pipefail

# Live Go devnet operator evidence for the canonical CORE_MULTISIG 1-of-1
# spend artifact. The script seeds a fresh devnet chainstate with the
# fixture's UTXO context, launches rubin-node, and proves submit -> mine ->
# get_block inclusion through live RPC.
#
# Reporting contract:
#   - JSON report is mandatory on every post-init PASS/FAIL path.
#   - Pre-init missing-tool failures (python3/perl) emit FAIL_HARNESS_PRE_INIT
#     on stderr only, with non-zero exit, before the runtime artifact contract
#     begins.
#   - Report-writer failures surface FAIL_REPORT_WRITE_FAILED on stderr
#     alongside the original failure reason and the non-zero exit; they are
#     never silently swallowed.

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEV_ENV="${REPO_ROOT}/scripts/dev-env.sh"
GO_MODULE_ROOT="${REPO_ROOT}/clients/go"
HELPER="${REPO_ROOT}/scripts/devnet-process-common.sh"
CANONICAL_FIXTURE_PATH="${REPO_ROOT}/conformance/fixtures/devnet/devnet-multisig-spend-01.json"
CANONICAL_VECTOR_ID="DEVNET-MULTISIG-SPEND-01"
REQUESTED_FIXTURE_PATH="${CORE_MULTISIG_FIXTURE_PATH:-${CANONICAL_FIXTURE_PATH}}"
REQUESTED_VECTOR_ID="${CORE_MULTISIG_VECTOR_ID:-${CANONICAL_VECTOR_ID}}"
FIXTURE_PATH="${CANONICAL_FIXTURE_PATH}"
VECTOR_ID="${CANONICAL_VECTOR_ID}"
DEVNET_CHAIN_ID="88f8a9acdeeb902e27aa2fdcb8c46ecf818bf68dec5273ec1bcc5084e2333103"
RPC_TIMEOUT_SECONDS=30
: "${KEEP_TMP:=1}"
export KEEP_TMP
export RUBIN_PROCESS_ARTIFACT_PARENT="${CORE_MULTISIG_ARTIFACT_PARENT:-${TMPDIR:-/tmp}/rubin-core-multisig-evidence}"

# Pre-init tool availability checks. These run BEFORE rubin_process_init,
# so the runtime artifact contract has not yet begun (no artifact_root, no
# JSON report can be written). Missing python3/perl is a harness-environment
# failure surfaced on stderr with a non-zero exit; FAIL JSON reports become
# mandatory only after rubin_process_init succeeds.
for tool in python3 perl; do
  command -v "${tool}" >/dev/null 2>&1 || {
    echo "FAIL_HARNESS_PRE_INIT: ${tool} is required for CORE_MULTISIG evidence; runtime artifact contract has not started yet" >&2
    exit 1
  }
done

# shellcheck source=scripts/devnet-process-common.sh disable=SC1091
source "${HELPER}"
rubin_process_init core-multisig-evidence

NODE_BIN="${RUBIN_PROCESS_ARTIFACT_ROOT}/rubin-node-go"
SEED_GO="${RUBIN_PROCESS_ARTIFACT_ROOT}/seed_core_multisig.go"
REPORT_JSON="${RUBIN_PROCESS_ARTIFACT_ROOT}/core-multisig-evidence-report.json"
SEED_STDERR="${RUBIN_PROCESS_ARTIFACT_ROOT}/seed-stderr.log"
TX_HEX_FILE="${RUBIN_PROCESS_ARTIFACT_ROOT}/submitted-tx.hex"
SUBMIT_BODY_JSON="${RUBIN_PROCESS_ARTIFACT_ROOT}/submit-body.json"
MINE_BODY_JSON="${RUBIN_PROCESS_ARTIFACT_ROOT}/mine-body.json"
BLOCK_RESPONSE_JSON="${RUBIN_PROCESS_ARTIFACT_ROOT}/get-block-response.json"
NODE_DIR="${RUBIN_PROCESS_ARTIFACT_ROOT}/node-a"
NODE_LOG="node-a.log"
NODE_PID=""
NODE_RPC_ADDR=""
CHAIN_IDENTITY_JSON=""
SUBMIT_JSON=""
SUBMITTED_TXID=""
MINE_JSON=""
MINED_HEIGHT=""
MINED_HASH=""
FIXTURE_CHAIN_ID=""
LIVE_CHAIN_ID=""
PHASE="init"

write_report() {
  # Always returns the underlying python writer's exit code. Callers MUST
  # treat a non-zero return as a real artifact-emission failure, regardless
  # of the requested status (PASS or FAIL).
  local status="$1" reason="$2"
  python3 - "${REPORT_JSON}" "${status}" "${PHASE}" "${reason}" "${FIXTURE_PATH}" "${VECTOR_ID}" \
    "${RUBIN_PROCESS_ARTIFACT_ROOT}" "${NODE_PID}" "${NODE_RPC_ADDR}" "${NODE_DIR}" "${CHAIN_IDENTITY_JSON}" \
    "${SUBMIT_JSON}" "${MINE_JSON}" "${BLOCK_RESPONSE_JSON}" "${DEVNET_CHAIN_ID}" "${FIXTURE_CHAIN_ID}" "${LIVE_CHAIN_ID}" \
    "${SUBMITTED_TXID}" "${MINED_HEIGHT}" "${MINED_HASH}" <<'PY'
import json
import sys

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
    identity,
    submit,
    mine,
    block_path,
    expected_chain_id,
    fixture_chain_id,
    live_chain_id,
    txid,
    height,
    block_hash,
) = sys.argv[1:21]


def load(raw):
    try:
        return json.loads(raw) if raw else None
    except Exception:
        return {"raw": raw}


def load_file(p):
    try:
        with open(p, encoding="utf-8") as fh:
            return json.load(fh)
    except FileNotFoundError:
        return None
    except Exception as exc:
        return {"raw_error": str(exc)}


participants = []
# Include the node-a participant whenever pid is known, even if rpc address
# could not be observed yet. This keeps pid/datadir visible in the report on
# partial-start failures (e.g. start_live_node failing after process spawn but
# before /chain_identity), without inventing rpc/chain_identity values that
# were never observed.
if pid:
    participants.append({
        "name": "node-a",
        "pid": int(pid),
        "rpc": rpc or None,
        "datadir": datadir or None,
        "chain_identity": load(identity) if identity else None,
    })

report = {
    "scenario": "CORE_MULTISIG",
    "status": status,
    "canonical_input": {"artifact": fixture, "vector_id": vector},
    "canonical_input_chain_id": fixture_chain_id or None,
    "expected_devnet_chain_id": expected_chain_id,
    "live_devnet_chain_id": live_chain_id or None,
    "artifact_root": root,
    "participants": participants,
    "submitted_txid": txid or None,
    "mined_height": int(height) if height else None,
    "mined_hash": block_hash or None,
    "inclusion_node": "node-a" if status == "PASS" else None,
    "inclusion_proven": status == "PASS",
    "live_submit_response": load(submit),
    "live_mine_response": load(mine),
    "live_block_response": load_file(block_path),
    "verdict": "PASS" if status == "PASS" else "FAIL",
}
if status != "PASS":
    report["failure_phase"] = phase
    report["failure_reason"] = reason

with open(path, "w", encoding="utf-8") as fh:
    json.dump(report, fh, indent=2, sort_keys=True)
    fh.write("\n")
PY
}

fail() {
  # FAIL artifact emission is mandatory once rubin_process_init succeeds.
  # write_report failures are not silently swallowed: a secondary stderr
  # line names the report path, the original failure reason is still
  # printed, and the script exits 1.
  local status="$1" reason="$2" rc=0
  if [[ -n "${RUBIN_PROCESS_ARTIFACT_ROOT:-}" ]]; then
    write_report "${status}" "${reason}" || rc=$?
    if (( rc != 0 )); then
      echo "FAIL_REPORT_WRITE_FAILED: report writer exit=${rc} path=${REPORT_JSON} primary_status=${status} primary_phase=${PHASE}" >&2
    fi
  else
    echo "FAIL_PRE_INIT: artifact root not initialized; no JSON report written" >&2
  fi
  echo "${reason}" >&2
  exit 1
}

rpc_json() {
  local method="$1" addr="$2" path="$3" body_file="${4:-}"
  python3 - "${method}" "${addr}" "${path}" "${body_file}" "${RPC_TIMEOUT_SECONDS}" <<'PY'
import socket
import sys
import urllib.error
import urllib.request

method, addr, path, body_file, timeout_s = sys.argv[1:6]
body = None
if body_file:
    with open(body_file, "rb") as fh:
        body = fh.read()
req = urllib.request.Request(f"http://{addr}{path}", data=body, method=method)
if body is not None:
    req.add_header("Content-Type", "application/json")
try:
    with urllib.request.urlopen(req, timeout=float(timeout_s)) as resp:
        print(resp.read().decode(), end="")
except urllib.error.HTTPError as exc:
    print(exc.read().decode(), end="")
    sys.exit(22)
except (urllib.error.URLError, TimeoutError, socket.timeout) as exc:
    print(f"request failed: {getattr(exc, 'reason', exc)}", end="")
    sys.exit(1)
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
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/node"
)

type fixtureUTXO struct {
	Txid              string `json:"txid"`
	Vout              uint32 `json:"vout"`
	Value             uint64 `json:"value"`
	CovenantType      uint16 `json:"covenant_type"`
	CovenantData      string `json:"covenant_data"`
	CreationHeight    uint64 `json:"creation_height"`
	CreatedByCoinbase bool   `json:"created_by_coinbase"`
}

type fixtureVector struct {
	ID         string        `json:"id"`
	ExpectOK   bool          `json:"expect_ok"`
	ExpectErr  string        `json:"expect_err"`
	ChainIDHex string        `json:"chain_id_hex"`
	TxHex      string        `json:"tx_hex"`
	Utxos      []fixtureUTXO `json:"utxos"`
}

type fixtureFile struct {
	Vectors []fixtureVector `json:"vectors"`
}

func die(v any) {
	fmt.Fprintln(os.Stderr, v)
	os.Exit(2)
}

func main() {
	datadir := flag.String("datadir", "", "")
	fixturePath := flag.String("fixture", "", "")
	vectorID := flag.String("vector-id", "", "")
	chainID := flag.String("chain-id", "", "")
	flag.Parse()

	raw, err := os.ReadFile(*fixturePath)
	if err != nil {
		die(fmt.Sprintf("read fixture: %v", err))
	}
	var fx fixtureFile
	if err := json.Unmarshal(raw, &fx); err != nil {
		die(fmt.Sprintf("parse fixture JSON: %v", err))
	}
	idx := -1
	for i := range fx.Vectors {
		if fx.Vectors[i].ID == *vectorID {
			if idx >= 0 {
				die("duplicate CORE_MULTISIG vector id")
			}
			idx = i
		}
	}
	if idx < 0 {
		die("CORE_MULTISIG vector not found")
	}
	v := fx.Vectors[idx]
	if *datadir == "" || !v.ExpectOK || v.ExpectErr != "" || v.TxHex == "" || len(v.Utxos) == 0 {
		die("CORE_MULTISIG fixture contract mismatch")
	}
	if v.ChainIDHex != *chainID {
		die(fmt.Sprintf("chain_id_hex actual=%s expected=%s", v.ChainIDHex, *chainID))
	}
	if _, err := hex.DecodeString(v.TxHex); err != nil {
		die(fmt.Sprintf("invalid tx_hex: %v", err))
	}

	st := node.NewChainState()
	store, err := node.OpenBlockStore(node.BlockStorePath(*datadir))
	if err != nil {
		die(err)
	}
	engine, err := node.NewSyncEngine(st, store, node.DefaultSyncConfig(nil, node.DevnetGenesisChainID(), node.ChainStatePath(*datadir)))
	if err != nil {
		die(err)
	}
	if _, err := engine.ApplyBlock(node.DevnetGenesisBlockBytes(), nil); err != nil {
		die(err)
	}
	for _, u := range v.Utxos {
		txidBytes, err := hex.DecodeString(u.Txid)
		if err != nil || len(txidBytes) != 32 {
			die("invalid fixture txid")
		}
		cov, err := hex.DecodeString(u.CovenantData)
		if err != nil {
			die(fmt.Sprintf("invalid fixture covenant_data: %v", err))
		}
		var txid [32]byte
		copy(txid[:], txidBytes)
		st.Utxos[consensus.Outpoint{Txid: txid, Vout: u.Vout}] = consensus.UtxoEntry{
			Value:             u.Value,
			CovenantType:      u.CovenantType,
			CovenantData:      cov,
			CreationHeight:    u.CreationHeight,
			CreatedByCoinbase: u.CreatedByCoinbase,
		}
	}
	if err := st.Save(node.ChainStatePath(*datadir)); err != nil {
		die(err)
	}
	fmt.Println(v.ChainIDHex)
	fmt.Println(v.TxHex)
}
GO
}

PHASE="fixture_preflight"
[[ -f "${CANONICAL_FIXTURE_PATH}" ]] || fail FAIL_INPUT "canonical devnet CORE_MULTISIG fixture missing: ${CANONICAL_FIXTURE_PATH}"
CANONICAL_FIXTURE_REAL="$(python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "${CANONICAL_FIXTURE_PATH}")" || \
  fail FAIL_INPUT "failed to resolve canonical CORE_MULTISIG fixture realpath: ${CANONICAL_FIXTURE_PATH}"
FIXTURE_REAL="$(python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "${REQUESTED_FIXTURE_PATH}")" || \
  fail FAIL_INPUT "failed to resolve requested CORE_MULTISIG fixture realpath: ${REQUESTED_FIXTURE_PATH}"
[[ "${FIXTURE_REAL}" == "${CANONICAL_FIXTURE_REAL}" ]] || fail FAIL_INPUT "non-canonical CORE_MULTISIG fixture rejected: actual=${FIXTURE_REAL} expected=${CANONICAL_FIXTURE_REAL}"
[[ "${REQUESTED_VECTOR_ID}" == "${CANONICAL_VECTOR_ID}" ]] || fail FAIL_INPUT "non-canonical CORE_MULTISIG vector rejected: actual=${REQUESTED_VECTOR_ID} expected=${CANONICAL_VECTOR_ID}"
write_seed_go || fail FAIL_LOCAL_HARNESS "failed to write seed program"
mkdir -p "${NODE_DIR}" || fail FAIL_LOCAL_HARNESS "failed to create node datadir"

PHASE="seed_fixture_context"
if ! SEED_OUT="$("${DEV_ENV}" -- go -C "${GO_MODULE_ROOT}" run "${SEED_GO}" \
  --datadir "${NODE_DIR}" \
  --fixture "${FIXTURE_PATH}" \
  --vector-id "${VECTOR_ID}" \
  --chain-id "${DEVNET_CHAIN_ID}" 2>"${SEED_STDERR}")"; then
  fail FAIL_INPUT "fixture validation/seed failed: stdout=${SEED_OUT}; stderr=$(cat "${SEED_STDERR}" 2>/dev/null || true)"
fi
FIXTURE_CHAIN_ID="${SEED_OUT%%$'\n'*}"
TX_HEX="${SEED_OUT#*$'\n'}"
[[ "${TX_HEX}" != "${SEED_OUT}" && "${TX_HEX}" != *$'\n'* && -n "${FIXTURE_CHAIN_ID}" && -n "${TX_HEX}" ]] || \
  fail FAIL_INPUT "fixture validation emitted unexpected stdout shape: ${SEED_OUT}"
printf '%s' "${TX_HEX}" >"${TX_HEX_FILE}" || fail FAIL_INPUT "failed to persist submitted tx_hex"

PHASE="build"
echo "Building Go rubin-node"
"${DEV_ENV}" -- go -C "${GO_MODULE_ROOT}" build -o "${NODE_BIN}" ./cmd/rubin-node || fail FAIL_LOCAL_HARNESS "rubin-node build failed"

PHASE="start_live_node"
echo "Starting Go rubin-node with canonical devnet CORE_MULTISIG fixture context"
rubin_process_start "${NODE_LOG}" "${NODE_BIN}" --network devnet --datadir "${NODE_DIR}" --bind 127.0.0.1:0 --rpc-bind 127.0.0.1:0 || \
  fail FAIL_LOCAL_HARNESS "rubin-node start failed"
NODE_PID="${RUBIN_PROCESS_LAST_PID}"
rubin_process_wait_for_log "${NODE_LOG}" "rpc: listening=" 30 "${NODE_PID}" || fail FAIL_LOCAL_HARNESS "rubin-node did not expose RPC"
NODE_RPC_ADDR="$(rubin_process_extract_rpc_addr "${NODE_LOG}")" || fail FAIL_LOCAL_HARNESS "failed to extract node RPC address"
rubin_process_wait_for_rpc_ready "${NODE_RPC_ADDR}" 30 || fail FAIL_LOCAL_HARNESS "node RPC did not answer /get_tip"
wait_ready_true "${NODE_RPC_ADDR}" || fail FAIL_LOCAL_HARNESS "node /ready did not report ready=true"
CHAIN_IDENTITY_JSON="$(rpc_json GET "${NODE_RPC_ADDR}" /chain_identity)" || fail FAIL_LOCAL_HARNESS "chain_identity query failed"
LIVE_CHAIN_ID="$(printf '%s' "${CHAIN_IDENTITY_JSON}" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("chain_id_hex",""))')" || \
  fail FAIL_LOCAL_HARNESS "chain_identity parse failed: ${CHAIN_IDENTITY_JSON}"
[[ "${LIVE_CHAIN_ID}" == "${DEVNET_CHAIN_ID}" ]] || \
  fail FAIL_LOCAL_HARNESS "live node chain_id mismatch: actual=${LIVE_CHAIN_ID} expected=${DEVNET_CHAIN_ID}"

PHASE="submit_live_rpc"
echo "Submitting canonical devnet CORE_MULTISIG tx through live /submit_tx"
printf '{"tx_hex":"%s"}' "${TX_HEX}" >"${SUBMIT_BODY_JSON}" || fail FAIL_SUBMIT "failed to persist submit body"
SUBMIT_JSON="$(rpc_json POST "${NODE_RPC_ADDR}" /submit_tx "${SUBMIT_BODY_JSON}")" || fail FAIL_SUBMIT "submit_tx request failed: ${SUBMIT_JSON}"
SUBMITTED_TXID="$(python3 - "${SUBMIT_JSON}" 2>&1 <<'PY'
import json
import sys

d = json.loads(sys.argv[1])
if d.get("accepted") is not True or not d.get("txid"):
    raise SystemExit(f"accepted/txid mismatch: {d}")
print(d["txid"])
PY
)" || fail FAIL_SUBMIT "submit_tx did not return accepted=true and txid: ${SUBMITTED_TXID}; response=${SUBMIT_JSON}"

PHASE="mine_live_rpc"
echo "Mining submitted CORE_MULTISIG tx through live /mine_next"
printf '{}' >"${MINE_BODY_JSON}" || fail FAIL_MINE "failed to persist mine body"
MINE_JSON="$(rpc_json POST "${NODE_RPC_ADDR}" /mine_next "${MINE_BODY_JSON}")" || fail FAIL_MINE "mine_next request failed: ${MINE_JSON}"
MINE_PARSED="$(python3 - "${MINE_JSON}" 2>&1 <<'PY'
import json
import sys

d = json.loads(sys.argv[1])
if d.get("mined") is not True or d.get("height") is None or not d.get("block_hash"):
    raise SystemExit(f"mined/height/hash mismatch: {d}")
print(d["height"], d["block_hash"])
PY
)" || fail FAIL_MINE "mine_next did not return mined height/hash: ${MINE_PARSED}; response=${MINE_JSON}"
read -r MINED_HEIGHT MINED_HASH <<<"${MINE_PARSED}"

PHASE="query_inclusion"
BLOCK_JSON="$(rpc_json GET "${NODE_RPC_ADDR}" "/get_block?height=${MINED_HEIGHT}")" || fail FAIL_INCLUSION "get_block failed at height ${MINED_HEIGHT}: ${BLOCK_JSON}"
printf '%s' "${BLOCK_JSON}" >"${BLOCK_RESPONSE_JSON}" || fail FAIL_INCLUSION "failed to persist get_block response"
BLOCK_CHECK="$(python3 - "${BLOCK_RESPONSE_JSON}" "${TX_HEX_FILE}" "${MINED_HEIGHT}" "${MINED_HASH}" 2>&1 <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as fh:
    d = json.load(fh)
with open(sys.argv[2], encoding="utf-8") as fh:
    tx_hex = fh.read().strip().lower()
want_height = int(sys.argv[3])
want_hash = sys.argv[4].lower()
actual_height = d.get("height")
actual_hash = str(d.get("hash", "")).lower()
canonical = d.get("canonical")
block_hex = str(d.get("block_hex", "")).lower()
if actual_height != want_height:
    raise SystemExit(f"height actual={actual_height} expected={want_height}")
if actual_hash != want_hash:
    raise SystemExit(f"hash actual={actual_hash} expected={want_hash}")
if canonical is not True:
    raise SystemExit(f"canonical actual={canonical} expected=True")
if tx_hex not in block_hex:
    raise SystemExit("submitted tx_hex missing from live block_hex")
PY
)" || fail FAIL_INCLUSION "get_block inclusion check failed: ${BLOCK_CHECK}; response_file=${BLOCK_RESPONSE_JSON}"

PHASE="pass"
# PASS-side writer/validation failures route through the same
# FAIL_REPORT_WRITE_FAILED stderr marker that fail() emits, so the
# report-writer failure class is closed across both PASS and FAIL paths.
pass_rc=0
write_report PASS "" || pass_rc=$?
if (( pass_rc != 0 )); then
  echo "FAIL_REPORT_WRITE_FAILED: report writer exit=${pass_rc} path=${REPORT_JSON} primary_status=PASS primary_phase=${PHASE}" >&2
  exit "${pass_rc}"
fi
pass_rc=0
python3 -m json.tool "${REPORT_JSON}" >/dev/null || pass_rc=$?
if (( pass_rc != 0 )); then
  echo "FAIL_REPORT_WRITE_FAILED: report json validation exit=${pass_rc} path=${REPORT_JSON} primary_status=PASS primary_phase=${PHASE}" >&2
  exit "${pass_rc}"
fi
echo "PASS: CORE_MULTISIG live evidence submit->mine->query succeeded; report=${REPORT_JSON}"
