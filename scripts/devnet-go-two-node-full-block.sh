#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEV_ENV="${REPO_ROOT}/scripts/dev-env.sh"
GO_MODULE_ROOT="${REPO_ROOT}/clients/go"
HELPER="${REPO_ROOT}/scripts/devnet-process-common.sh"
BASE_HEIGHT=101
TARGET_A_HEIGHT=$((BASE_HEIGHT + 1))
TARGET_B_HEIGHT=$((BASE_HEIGHT + 2))
: "${KEEP_TMP:=1}"
: "${RUBIN_GO_TWO_NODE_RPC_TIMEOUT_SECONDS:=5}"
export KEEP_TMP

prepend_path_if_exists_once() {
  local dir="$1"
  [[ -d "${dir}" ]] || return 0
  case ":${PATH}:" in
    *":${dir}:"*) ;;
    *) PATH="${dir}:${PATH}" ;;
  esac
}

configure_openssl_runtime_env() {
  if [[ -n "${RUBIN_OPENSSL_PREFIX:-}" ]]; then
    [[ -x "${RUBIN_OPENSSL_PREFIX}/bin/openssl" ]] || {
      echo "RUBIN_OPENSSL_PREFIX is set but missing bin/openssl: ${RUBIN_OPENSSL_PREFIX}" >&2
      return 1
    }
    prepend_path_if_exists_once "${RUBIN_OPENSSL_PREFIX}/bin"
    export OPENSSL_DIR="${RUBIN_OPENSSL_PREFIX}"
    if [[ -d "${RUBIN_OPENSSL_PREFIX}/lib/ossl-modules" ]]; then
      export OPENSSL_MODULES="${RUBIN_OPENSSL_PREFIX}/lib/ossl-modules"
    elif [[ -d "${RUBIN_OPENSSL_PREFIX}/lib64/ossl-modules" ]]; then
      export OPENSSL_MODULES="${RUBIN_OPENSSL_PREFIX}/lib64/ossl-modules"
    fi
  fi
  [[ -z "${RUBIN_OPENSSL_MODULES:-}" ]] || export OPENSSL_MODULES="${RUBIN_OPENSSL_MODULES}"
  [[ -z "${RUBIN_OPENSSL_CONF:-}" ]] || export OPENSSL_CONF="${RUBIN_OPENSSL_CONF}"
  if [[ "${RUBIN_OPENSSL_FIPS_MODE:-off}" == "only" && -n "${OPENSSL_DIR:-}" ]]; then
    if [[ -z "${OPENSSL_CONF:-}" && -f "${OPENSSL_DIR}/ssl/openssl-fips.cnf" ]]; then
      export OPENSSL_CONF="${OPENSSL_DIR}/ssl/openssl-fips.cnf"
    fi
    if [[ -z "${OPENSSL_MODULES:-}" && -d "${OPENSSL_DIR}/lib/ossl-modules" ]]; then
      export OPENSSL_MODULES="${OPENSSL_DIR}/lib/ossl-modules"
    elif [[ -z "${OPENSSL_MODULES:-}" && -d "${OPENSSL_DIR}/lib64/ossl-modules" ]]; then
      export OPENSSL_MODULES="${OPENSSL_DIR}/lib64/ossl-modules"
    fi
  fi
  export PATH
}
configure_openssl_runtime_env

for tool in python3 perl lsof; do
  command -v "${tool}" >/dev/null 2>&1 || {
    echo "${tool} is required for Go two-node full-block devnet evidence" >&2
    exit 1
  }
done

# shellcheck source=scripts/devnet-process-common.sh disable=SC1091
source "${HELPER}"
rubin_process_init go-two-node-full-block

NODE_BIN="${RUBIN_PROCESS_ARTIFACT_ROOT}/rubin-node-go"
TXGEN_BIN="${RUBIN_PROCESS_ARTIFACT_ROOT}/rubin-txgen"
CONSENSUS_CLI_BIN="${RUBIN_PROCESS_ARTIFACT_ROOT}/rubin-consensus-cli-go"
KEYGEN_GO="${RUBIN_PROCESS_ARTIFACT_ROOT}/keygen.go"
KEYGEN_JSON="${RUBIN_PROCESS_ARTIFACT_ROOT}/keygen.json"
FROM_KEY_FILE="${RUBIN_PROCESS_ARTIFACT_ROOT}/from-key.hex"
REPORT_JSON="${RUBIN_PROCESS_ARTIFACT_ROOT}/go-two-node-full-block-report.json"
MINE_LOG="${RUBIN_PROCESS_ARTIFACT_ROOT}/mine-base.log"
A_DIR="${RUBIN_PROCESS_ARTIFACT_ROOT}/node-a"
B_DIR="${RUBIN_PROCESS_ARTIFACT_ROOT}/node-b"
A_LOG="node-a.log"
B_LOG="node-b.log"
RUBIN_PROCESS_LOGS+=("${MINE_LOG}")

cleanup_from_key_file() {
  [[ -n "${FROM_KEY_FILE:-}" ]] || return 0
  rm -f -- "${FROM_KEY_FILE}"
}

go_two_node_exit_trap() {
  local status=$? cleanup_status=0
  cleanup_from_key_file || cleanup_status=$?
  rubin_process_cleanup "${status}" || cleanup_status=$?
  [[ "${status}" != "0" ]] && exit "${status}"
  exit "${cleanup_status}"
}
trap go_two_node_exit_trap EXIT

rpc_json() {
  local method="$1" addr="$2" path="$3" body="${4:-}"
  python3 - "${method}" "${addr}" "${path}" "${body}" "${RUBIN_GO_TWO_NODE_RPC_TIMEOUT_SECONDS}" <<'PY'
import socket
import sys
import urllib.error
import urllib.request

method, addr, path, body, timeout_raw = sys.argv[1:6]
try:
    request_timeout = float(timeout_raw)
except ValueError:
    raise SystemExit(f"invalid RUBIN_GO_TWO_NODE_RPC_TIMEOUT_SECONDS={timeout_raw!r}")
if request_timeout <= 0 or request_timeout > 300:
    raise SystemExit(f"RUBIN_GO_TWO_NODE_RPC_TIMEOUT_SECONDS out of range: {timeout_raw!r}")
data = body.encode() if body else None
req = urllib.request.Request(f"http://{addr}{path}", data=data, method=method)
if body:
    req.add_header("Content-Type", "application/json")
try:
    with urllib.request.urlopen(req, timeout=request_timeout) as resp:
        print(resp.read().decode("utf-8"), end="")
except urllib.error.HTTPError as exc:
    print(exc.read().decode("utf-8"), end="")
    sys.exit(22)
except (urllib.error.URLError, TimeoutError, socket.timeout) as exc:
    print(f"request failed timeout={request_timeout}: {getattr(exc, 'reason', exc)}", end="")
    sys.exit(1)
PY
}

ready_true() {
  rpc_json GET "$1" /ready | python3 -c 'import json,sys; d=json.load(sys.stdin); sys.exit(0 if d.get("ready") is True else 1)'
}

wait_ready() {
  local label="$1" addr="$2" timeout="$3" deadline
  deadline=$((SECONDS + timeout))
  while (( SECONDS < deadline )); do
    if ready_true "${addr}" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "timeout waiting for ${label} /ready=true addr=${addr} timeout=${timeout}" >&2
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
      if [[ "${height}" == "${want_height}" && "${hash}" == "${want_hash}" ]]; then
        return 0
      fi
    fi
    sleep 1
  done
  echo "timeout waiting for ${label} tip addr=${addr} expected_height=${want_height} expected_hash=${want_hash} actual_height=${last_height} actual_hash=${last_hash} timeout=${timeout}" >&2
  return 1
}

wait_height_any_hash() {
  local label="$1" addr="$2" want_height="$3" timeout="$4"
  local deadline=$((SECONDS + timeout)) height hash last_height="<none>" last_hash="<none>"
  while (( SECONDS < deadline )); do
    if IFS=$'\t' read -r height hash < <(tip_tsv "${addr}" 2>/dev/null); then
      last_height="${height}"
      last_hash="${hash}"
      if [[ "${height}" == "${want_height}" && -n "${hash}" ]]; then
        printf '%s\t%s\n' "${height}" "${hash}"
        return 0
      fi
    fi
    sleep 1
  done
  echo "timeout waiting for ${label} height addr=${addr} expected_height=${want_height} actual_height=${last_height} actual_hash=${last_hash} timeout=${timeout}" >&2
  return 1
}

peer_count_ready() {
  rpc_json GET "$1" /peers | python3 -c 'import json,sys; d=json.load(sys.stdin); peers=d.get("peers") or []; ok=sum(1 for p in peers if p.get("handshake_complete") is True); print(ok)'
}

wait_peers_ready() {
  local label="$1" addr="$2" want="$3" timeout="$4"
  local deadline=$((SECONDS + timeout)) count="0"
  while (( SECONDS < deadline )); do
    if count="$(peer_count_ready "${addr}" 2>/dev/null)" && [[ "${count}" =~ ^[0-9]+$ && "${count}" -ge "${want}" ]]; then
      printf '%s\n' "${count}"
      return 0
    fi
    sleep 1
  done
  echo "timeout waiting for ${label} handshake peers addr=${addr} expected_min=${want} actual=${count} timeout=${timeout}" >&2
  return 1
}

wait_mempool_contains() {
  local label="$1" addr="$2" txid="$3" timeout="$4"
  local deadline=$((SECONDS + timeout)) last="<none>"
  while (( SECONDS < deadline )); do
    if last="$(rpc_json GET "${addr}" /get_mempool 2>/dev/null)" && printf '%s' "${last}" | python3 -c '
import json
import sys
want = sys.argv[1]
d = json.load(sys.stdin)
sys.exit(0 if want in (d.get("txids") or []) else 1)
' "${txid}"
    then
      return 0
    fi
    sleep 1
  done
  echo "timeout waiting for ${label} mempool tx addr=${addr} txid=${txid} last_mempool=${last} timeout=${timeout}" >&2
  return 1
}

block_json_matches() {
  local block_json="$1" expected_height="$2" expected_hash="$3"
  printf '%s' "${block_json}" | python3 -c '
import json
import sys

d = json.load(sys.stdin)
expected_height = int(sys.argv[1])
expected_hash = sys.argv[2].lower()
actual_hash = (d.get("hash") or d.get("block_hash") or "").lower()
actual_height = d.get("height")
canonical = d.get("canonical")
missing_hash = "<missing>"
if actual_height != expected_height or actual_hash != expected_hash or canonical is not True:
    raise SystemExit(
        f"expected_height={expected_height} actual_height={actual_height} "
        f"expected_hash={expected_hash} actual_hash={actual_hash or missing_hash} "
        f"actual_canonical={canonical!r}"
    )
' "${expected_height}" "${expected_hash}"
}

block_contains_hex() {
  local block_json="$1" tx_hex="$2" label="$3"
  printf '%s' "${block_json}" | python3 -c '
import json
import sys

d = json.load(sys.stdin)
needle = sys.argv[1].lower()
label = sys.argv[2]
haystack = (d.get("block_hex") or "").lower()
if needle not in haystack:
    raise SystemExit(f"submitted tx bytes missing from {label} block_hex")
' "${tx_hex}" "${label}"
}

chain_identity_tsv() {
  rpc_json GET "$1" /chain_identity | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["network"], d["chain_id_hex"], d["genesis_hash_hex"], sep="\t")'
}

mempool_min_fee_rate() {
  local addr="$1" body
  body="$(rpc_json GET "${addr}" /metrics)" || return 1
  printf '%s' "${body}" | python3 -c '
import re
import sys

metric = "rubin_node_mempool_min_fee_rate"
found = None
for raw in sys.stdin.read().splitlines():
    line = raw.strip()
    if not line or line.startswith("#"):
        continue
    fields = line.split()
    if fields[0] != metric:
        continue
    if found is not None:
        raise SystemExit(f"duplicate {metric} metric")
    if len(fields) != 2 or not re.fullmatch(r"[0-9]+", fields[1]):
        raise SystemExit(f"malformed {metric} metric line: {raw!r}")
    found = int(fields[1])
if found is None:
    raise SystemExit(f"missing {metric} metric")
if found < 1:
    found = 1
if found > 2**64 - 1:
    raise SystemExit(f"{metric} overflows uint64: {found}")
print(found)
'
}

generate_tx_hex() {
  local fee="$1" tx_hex
  tx_hex="$("${TXGEN_BIN}" --datadir "${A_DIR}" --from-key-file "${FROM_KEY_FILE}" --to-key "${TO_ADDRESS_HEX}" --amount 1 --fee "${fee}")" || return 1
  [[ "${tx_hex}" =~ ^[0-9a-f]+$ && ${#tx_hex} -le 20000 && $(( ${#tx_hex} % 2 )) -eq 0 ]] || {
    echo "txgen emitted malformed or unbounded tx_hex length=${#tx_hex}" >&2
    return 1
  }
  printf '%s\n' "${tx_hex}"
}

tx_weight_stats_tsv() {
  local tx_hex="$1"
  python3 - "${CONSENSUS_CLI_BIN}" "${tx_hex}" <<'PY'
import json
import re
import subprocess
import sys

cli, tx_hex = sys.argv[1:3]
if not re.fullmatch(r"[0-9a-f]+", tx_hex) or len(tx_hex) % 2 != 0 or len(tx_hex) > 20_000:
    raise SystemExit("tx_hex is malformed or unbounded")
req = json.dumps({"op": "tx_weight_and_stats", "tx_hex": tx_hex}) + "\n"
try:
    proc = subprocess.run(
        [cli],
        input=req,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=30,
        check=False,
    )
except subprocess.TimeoutExpired:
    raise SystemExit("tx weight helper timed out")
except OSError as exc:
    raise SystemExit(f"tx weight helper unavailable: {exc}")
if len(proc.stdout or "") > 100_000 or len(proc.stderr or "") > 100_000:
    raise SystemExit("tx weight helper output too large")
if proc.returncode != 0:
    raise SystemExit(f"tx weight helper failed rc={proc.returncode}: {(proc.stderr or '').strip()}")
try:
    data = json.loads(proc.stdout)
except (json.JSONDecodeError, UnicodeDecodeError, RecursionError) as exc:
    raise SystemExit(f"tx weight helper emitted malformed JSON: {exc}")
if not isinstance(data, dict) or data.get("ok") is not True:
    raise SystemExit(f"tx weight helper rejected tx: {data!r}")
vals = []
for name in ("weight", "da_bytes", "anchor_bytes"):
    value = data.get(name)
    if not isinstance(value, int) or value < 0 or value > 2**64 - 1:
        raise SystemExit(f"tx weight helper returned invalid {name}: {value!r}")
    vals.append(value)
if vals[0] == 0:
    raise SystemExit("tx weight helper returned zero weight")
print(*vals, sep="\t")
PY
}

required_fee_for_weight() {
  python3 - "$1" "$2" <<'PY'
import sys

weight = int(sys.argv[1])
fee_rate = int(sys.argv[2])
if weight <= 0 or fee_rate <= 0:
    raise SystemExit(f"invalid weight/fee_rate: weight={weight} fee_rate={fee_rate}")
max_u64 = 2**64 - 1
if weight > max_u64 or fee_rate > max_u64 or weight > max_u64 // fee_rate:
    raise SystemExit(f"required fee overflow: weight={weight} fee_rate={fee_rate}")
print(weight * fee_rate)
PY
}

derive_policy_valid_tx() {
  local attempt current_fee tx_hex stats required_fee
  TX_MIN_FEE_RATE="$(mempool_min_fee_rate "${A_RPC_ADDR}")" || return 1
  current_fee="${TX_MIN_FEE_RATE}"
  for attempt in 1 2 3 4 5; do
    tx_hex="$(generate_tx_hex "${current_fee}")" || return 1
    stats="$(tx_weight_stats_tsv "${tx_hex}")" || return 1
    IFS=$'\t' read -r TX_WEIGHT TX_DA_BYTES TX_ANCHOR_BYTES <<<"${stats}"
    required_fee="$(required_fee_for_weight "${TX_WEIGHT}" "${TX_MIN_FEE_RATE}")" || return 1
    if [[ "${current_fee}" == "${required_fee}" ]]; then
      TX_HEX="${tx_hex}"
      TX_FEE="${current_fee}"
      TX_REQUIRED_FEE="${required_fee}"
      return 0
    fi
    current_fee="${required_fee}"
  done
  echo "fee calculation did not converge after ${attempt} attempts min_fee_rate=${TX_MIN_FEE_RATE} last_fee=${current_fee} last_weight=${TX_WEIGHT:-<none>}" >&2
  return 1
}

submit_tx_hex() {
  local tx_hex="$1" body response
  body="$(python3 - "${tx_hex}" <<'PY'
import json
import re
import sys

tx_hex = sys.argv[1]
if not re.fullmatch(r"[0-9a-f]+", tx_hex) or len(tx_hex) % 2 != 0 or len(tx_hex) > 20_000:
    raise SystemExit("tx_hex is malformed or unbounded")
print(json.dumps({"tx_hex": tx_hex}, separators=(",", ":")))
PY
)" || return 1
  response="$(rpc_json POST "${A_RPC_ADDR}" /submit_tx "${body}")" || {
    echo "submit failed: ${response}" >&2
    return 1
  }
  printf '%s' "${response}" | python3 -c '
import json
import re
import sys

d = json.load(sys.stdin)
txid = d.get("txid")
if d.get("accepted") is not True or not isinstance(txid, str) or not re.fullmatch(r"[0-9a-f]{64}", txid):
    raise SystemExit("submit_tx did not return accepted txid: " + json.dumps(d, sort_keys=True))
print(txid)
'
}

assert_same_identity() {
  local a="$1" b="$2" a_id b_id
  a_id="$(chain_identity_tsv "${a}")"
  b_id="$(chain_identity_tsv "${b}")"
  [[ "${a_id}" == "${b_id}" ]] || {
    echo "chain identity mismatch node-a=${a_id} node-b=${b_id}" >&2
    return 1
  }
}

assert_distinct_datadirs() {
  python3 - "${A_DIR}" "${B_DIR}" <<'PY'
import os
import sys

a, b = sys.argv[1:3]
for label, path in (("node-a", a), ("node-b", b)):
    if not os.path.isdir(path):
        raise SystemExit(f"{label} datadir missing: {path}")
    if os.path.islink(path):
        raise SystemExit(f"{label} datadir must not be symlink: {path}")
if os.path.samefile(a, b):
    raise SystemExit(f"node datadirs must be distinct: {a} and {b}")
for rel in ("chainstate.json", "blocks"):
    pa = os.path.join(a, rel)
    pb = os.path.join(b, rel)
    if os.path.exists(pa) and os.path.exists(pb) and os.path.samefile(pa, pb):
        raise SystemExit(f"node storage path must not be shared: {pa} and {pb}")
PY
}

p2p_addr_for_pid() {
  local pid="$1" rpc_addr="$2" timeout="$3"
  python3 - "${pid}" "${rpc_addr}" "${timeout}" <<'PY'
import re
import subprocess
import sys
import time

pid, rpc_addr, timeout = sys.argv[1], sys.argv[2], int(sys.argv[3])
deadline = time.time() + timeout
while time.time() < deadline:
    proc = subprocess.run(
        ["lsof", "-nP", "-a", "-p", pid, "-iTCP", "-sTCP:LISTEN", "-Fn"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    addrs = sorted({
        line[1:].strip()
        for line in proc.stdout.splitlines()
        if line.startswith("n")
        and line[1:].strip() != rpc_addr
        and re.fullmatch(r"127\.0\.0\.1:[0-9]+", line[1:].strip())
    })
    if len(addrs) == 1:
        print(addrs[0])
        sys.exit(0)
    if len(addrs) > 1:
        raise SystemExit(f"ambiguous p2p listen addresses for pid={pid}: {addrs}")
    time.sleep(1)
raise SystemExit(f"timeout resolving p2p listen address for pid={pid}")
PY
}

STARTED_PID=""
STARTED_RPC=""
STARTED_P2P=""
start_node_ready() {
  local label="$1" log_file="$2" datadir="$3" peers="${4:-}" args
  args=(--datadir "${datadir}" --bind 127.0.0.1:0 --rpc-bind 127.0.0.1:0 --mine-address "${MINE_ADDRESS_HEX}")
  [[ -z "${peers}" ]] || args+=(--peers "${peers}")
  STARTED_PID=""
  STARTED_RPC=""
  STARTED_P2P=""
  if ! rubin_process_start "${log_file}" "${NODE_BIN}" "${args[@]}"; then
    echo "${label} start failed" >&2
    [[ -z "${RUBIN_PROCESS_LAST_PID}" ]] || rubin_process_stop_pid "${RUBIN_PROCESS_LAST_PID}" || true
    return 1
  fi
  STARTED_PID="${RUBIN_PROCESS_LAST_PID}"
  rubin_process_wait_for_log "${log_file}" "rpc: listening=" 30 "${STARTED_PID}" || {
    echo "${label} did not print rpc listening banner" >&2
    rubin_process_stop_pid "${STARTED_PID}" || true
    return 1
  }
  STARTED_RPC="$(rubin_process_extract_rpc_addr "${log_file}")" || {
    rubin_process_stop_pid "${STARTED_PID}" || true
    return 1
  }
  STARTED_P2P="$(p2p_addr_for_pid "${STARTED_PID}" "${STARTED_RPC}" 30)" || {
    rubin_process_stop_pid "${STARTED_PID}" || true
    return 1
  }
  wait_ready "${label}" "${STARTED_RPC}" 30
}

write_keygen() {
  cat >"${KEYGEN_GO}" <<'GO'
package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

func main() {
	if len(os.Args) != 2 {
		panic("usage: keygen <from-key-file>")
	}
	from, err := consensus.NewMLDSA87Keypair()
	if err != nil {
		panic(err)
	}
	defer from.Close()
	to, err := consensus.NewMLDSA87Keypair()
	if err != nil {
		panic(err)
	}
	defer to.Close()
	der, err := from.PrivateKeyDER()
	if err != nil {
		panic(err)
	}
	if err := os.WriteFile(os.Args[1], []byte(hex.EncodeToString(der)), 0o600); err != nil {
		panic(fmt.Errorf("write from key file: %w", err))
	}
	out := map[string]string{
		"mine_address_hex": hex.EncodeToString(consensus.P2PKCovenantDataForPubkey(from.PubkeyBytes())),
		"to_address_hex":   hex.EncodeToString(consensus.P2PKCovenantDataForPubkey(to.PubkeyBytes())),
	}
	if err := json.NewEncoder(os.Stdout).Encode(out); err != nil {
		panic(err)
	}
}
GO
}

write_report() {
  export REPORT_JSON A_DIR B_DIR A_PID B_PID A_RPC_ADDR B_RPC_ADDR A_P2P_ADDR B_P2P_ADDR A_PEERS B_PEERS TX_ID TX_HEX \
    TX_FEE TX_WEIGHT TX_MIN_FEE_RATE TX_REQUIRED_FEE TX_DA_BYTES TX_ANCHOR_BYTES \
    BASE_HEIGHT BASE_HASH A_MINE_HEIGHT A_MINE_HASH A_MINE_TX_COUNT B_AFTER_A_HEIGHT B_AFTER_A_HASH \
    B_MINE_HEIGHT B_MINE_HASH B_MINE_TX_COUNT A_FINAL_HEIGHT A_FINAL_HASH B_FINAL_HEIGHT B_FINAL_HASH
  python3 - <<'PY'
import json
import os
import sys

e = os.environ
i = lambda key: int(e[key])
participants = [
    {
        "name": "node-a",
        "pid": i("A_PID"),
        "rpc": e["A_RPC_ADDR"],
        "p2p": e["A_P2P_ADDR"],
        "datadir": e["A_DIR"],
        "base_height": i("BASE_HEIGHT"),
        "base_hash": e["BASE_HASH"],
        "final_height": i("A_FINAL_HEIGHT"),
        "final_hash": e["A_FINAL_HASH"],
        "handshake_peers": i("A_PEERS"),
    },
    {
        "name": "node-b",
        "pid": i("B_PID"),
        "rpc": e["B_RPC_ADDR"],
        "p2p": e["B_P2P_ADDR"],
        "datadir": e["B_DIR"],
        "base_height": i("BASE_HEIGHT"),
        "base_hash": e["BASE_HASH"],
        "final_height": i("B_FINAL_HEIGHT"),
        "final_hash": e["B_FINAL_HASH"],
        "handshake_peers": i("B_PEERS"),
    },
]
report = {
    "scenario": "go_two_node_full_block_process",
    "verdict": "PASS",
    "participants": participants,
    "tx": {
        "id": e["TX_ID"],
        "fee": i("TX_FEE"),
        "weight": i("TX_WEIGHT"),
        "min_fee_rate": i("TX_MIN_FEE_RATE"),
        "required_fee": i("TX_REQUIRED_FEE"),
        "da_bytes": i("TX_DA_BYTES"),
        "anchor_bytes": i("TX_ANCHOR_BYTES"),
        "submission": "node-a rpc:/submit_tx",
        "observed_in_node_b_mempool_before_mine": True,
        "included_by": "node-a",
        "included_height": i("A_MINE_HEIGHT"),
        "included_block_hash": e["A_MINE_HASH"],
    },
    "events": [
        {
            "actor": "node-a",
            "action": "mine_next",
            "height": i("A_MINE_HEIGHT"),
            "block_hash": e["A_MINE_HASH"],
            "tx_count": i("A_MINE_TX_COUNT"),
            "accepted_by": "node-b",
            "node_b_height_after": i("B_AFTER_A_HEIGHT"),
            "node_b_hash_after": e["B_AFTER_A_HASH"],
        },
        {
            "actor": "node-b",
            "action": "mine_next",
            "height": i("B_MINE_HEIGHT"),
            "block_hash": e["B_MINE_HASH"],
            "tx_count": i("B_MINE_TX_COUNT"),
            "accepted_by": "node-a",
        },
    ],
    "final": {
        "participants": ["node-a", "node-b"],
        "height": i("A_FINAL_HEIGHT"),
        "hash": e["A_FINAL_HASH"],
    },
    "out_of_scope": ["compact_relay", "da_relay", "rust", "mixed_client"],
}
participant_names = {p["name"] for p in participants}
if participant_names != {"node-a", "node-b"}:
    raise SystemExit(f"bad participants: {sorted(participant_names)}")
if set(report["final"]["participants"]) != participant_names:
    raise SystemExit("final participants do not match participants table")
for event in report["events"]:
    if event["actor"] not in participant_names or event["accepted_by"] not in participant_names:
        raise SystemExit(f"event references unknown participant: {event}")
if participants[0]["datadir"] == participants[1]["datadir"]:
    raise SystemExit("participants share datadir in report")
if participants[0]["final_height"] != participants[1]["final_height"]:
    raise SystemExit("participant final heights differ")
if participants[0]["final_hash"] != participants[1]["final_hash"]:
    raise SystemExit("participant final hashes differ")
if report["final"]["height"] != participants[0]["final_height"] or report["final"]["hash"] != participants[0]["final_hash"]:
    raise SystemExit("final summary does not match participant rows")
text = json.dumps(report, sort_keys=True)
for forbidden in ("compact relay ready", "da relay ready", "da readiness", "compact readiness"):
    if forbidden in text.lower():
        raise SystemExit(f"forbidden readiness claim in report: {forbidden}")
with open(e["REPORT_JSON"], "w", encoding="utf-8") as f:
    json.dump(report, f, indent=2, sort_keys=True)
    f.write("\n")
PY
}

echo "Building Go rubin-node and rubin-txgen"
"${DEV_ENV}" -- go -C "${GO_MODULE_ROOT}" build -o "${NODE_BIN}" ./cmd/rubin-node
"${DEV_ENV}" -- go -C "${GO_MODULE_ROOT}" build -o "${TXGEN_BIN}" ./cmd/rubin-txgen
"${DEV_ENV}" -- go -C "${GO_MODULE_ROOT}" build -o "${CONSENSUS_CLI_BIN}" ./cmd/rubin-consensus-cli
write_keygen
RUBIN_OPENSSL_SKIP_FIPS_GUARD=1 "${DEV_ENV}" -- go -C "${GO_MODULE_ROOT}" run "${KEYGEN_GO}" "${FROM_KEY_FILE}" >"${KEYGEN_JSON}"
MINE_ADDRESS_HEX="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["mine_address_hex"])' "${KEYGEN_JSON}")"
TO_ADDRESS_HEX="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["to_address_hex"])' "${KEYGEN_JSON}")"

mkdir -p "${A_DIR}" "${B_DIR}"
echo "Mining mature Go chain to height ${BASE_HEIGHT}"
"${NODE_BIN}" --datadir "${A_DIR}" --mine-address "${MINE_ADDRESS_HEX}" --mine-blocks "${BASE_HEIGHT}" --mine-exit >"${MINE_LOG}" 2>&1
cp -R "${A_DIR}/." "${B_DIR}/"
assert_distinct_datadirs

start_node_ready node-b "${B_LOG}" "${B_DIR}"
B_PID="${STARTED_PID}"
B_RPC_ADDR="${STARTED_RPC}"
B_P2P_ADDR="${STARTED_P2P}"
start_node_ready node-a "${A_LOG}" "${A_DIR}" "${B_P2P_ADDR}"
A_PID="${STARTED_PID}"
A_RPC_ADDR="${STARTED_RPC}"
A_P2P_ADDR="${STARTED_P2P}"

assert_same_identity "${A_RPC_ADDR}" "${B_RPC_ADDR}"
A_PEERS="$(wait_peers_ready node-a "${A_RPC_ADDR}" 1 30)"
B_PEERS="$(wait_peers_ready node-b "${B_RPC_ADDR}" 1 30)"
IFS=$'\t' read -r _ BASE_HASH < <(wait_height_any_hash "node-a base" "${A_RPC_ADDR}" "${BASE_HEIGHT}" 30)
wait_tip_exact node-b "${B_RPC_ADDR}" "${BASE_HEIGHT}" "${BASE_HASH}" 30

derive_policy_valid_tx
cleanup_from_key_file
TX_ID="$(submit_tx_hex "${TX_HEX}")"
A_MEMPOOL_JSON="$(rpc_json GET "${A_RPC_ADDR}" /get_mempool)"
printf '%s' "${A_MEMPOOL_JSON}" | python3 -c '
import json
import sys

want = sys.argv[1]
d = json.load(sys.stdin)
txids = d.get("txids") or []
if d.get("count") != 1 or len(txids) != 1 or txids[0] != want:
    raise SystemExit("expected node-a mempool count=1 after submit, got " + json.dumps(d, sort_keys=True))
' "${TX_ID}"
wait_mempool_contains node-b "${B_RPC_ADDR}" "${TX_ID}" 30

A_MINE_JSON="$(rpc_json POST "${A_RPC_ADDR}" /mine_next '{}')"
IFS=$'\t' read -r A_MINE_HEIGHT A_MINE_HASH A_MINE_TX_COUNT < <(printf '%s' "${A_MINE_JSON}" | python3 -c '
import json
import sys

d = json.load(sys.stdin)
if d.get("mined") is not True:
    raise SystemExit("node-a mine_next failed: " + str(d.get("error", d)))
print(d["height"], d["block_hash"], d["tx_count"], sep="\t")
')
[[ "${A_MINE_HEIGHT}" == "${TARGET_A_HEIGHT}" && "${A_MINE_TX_COUNT}" -ge 2 ]] || {
  echo "unexpected node-a mine result expected_height=${TARGET_A_HEIGHT} actual_height=${A_MINE_HEIGHT} tx_count=${A_MINE_TX_COUNT} hash=${A_MINE_HASH}" >&2
  exit 1
}
wait_tip_exact node-a "${A_RPC_ADDR}" "${TARGET_A_HEIGHT}" "${A_MINE_HASH}" 30
wait_tip_exact node-b "${B_RPC_ADDR}" "${TARGET_A_HEIGHT}" "${A_MINE_HASH}" 60
IFS=$'\t' read -r B_AFTER_A_HEIGHT B_AFTER_A_HASH < <(tip_tsv "${B_RPC_ADDR}")
B_TARGET_BLOCK_JSON="$(rpc_json GET "${B_RPC_ADDR}" "/get_block?height=${TARGET_A_HEIGHT}")"
block_json_matches "${B_TARGET_BLOCK_JSON}" "${TARGET_A_HEIGHT}" "${A_MINE_HASH}"
block_contains_hex "${B_TARGET_BLOCK_JSON}" "${TX_HEX}" "node-b adopted node-a-mined"

B_MINE_JSON="$(rpc_json POST "${B_RPC_ADDR}" /mine_next '{}')"
IFS=$'\t' read -r B_MINE_HEIGHT B_MINE_HASH B_MINE_TX_COUNT < <(printf '%s' "${B_MINE_JSON}" | python3 -c '
import json
import sys

d = json.load(sys.stdin)
if d.get("mined") is not True:
    raise SystemExit("node-b mine_next failed: " + str(d.get("error", d)))
print(d["height"], d["block_hash"], d["tx_count"], sep="\t")
')
[[ "${B_MINE_HEIGHT}" == "${TARGET_B_HEIGHT}" && "${B_MINE_TX_COUNT}" -ge 1 ]] || {
  echo "unexpected node-b mine result expected_height=${TARGET_B_HEIGHT} actual_height=${B_MINE_HEIGHT} tx_count=${B_MINE_TX_COUNT} hash=${B_MINE_HASH}" >&2
  exit 1
}
wait_tip_exact node-b "${B_RPC_ADDR}" "${TARGET_B_HEIGHT}" "${B_MINE_HASH}" 30
wait_tip_exact node-a "${A_RPC_ADDR}" "${TARGET_B_HEIGHT}" "${B_MINE_HASH}" 60
A_FINAL_BLOCK_JSON="$(rpc_json GET "${A_RPC_ADDR}" "/get_block?height=${TARGET_B_HEIGHT}")"
B_FINAL_BLOCK_JSON="$(rpc_json GET "${B_RPC_ADDR}" "/get_block?height=${TARGET_B_HEIGHT}")"
block_json_matches "${A_FINAL_BLOCK_JSON}" "${TARGET_B_HEIGHT}" "${B_MINE_HASH}"
block_json_matches "${B_FINAL_BLOCK_JSON}" "${TARGET_B_HEIGHT}" "${B_MINE_HASH}"
IFS=$'\t' read -r A_FINAL_HEIGHT A_FINAL_HASH < <(tip_tsv "${A_RPC_ADDR}")
IFS=$'\t' read -r B_FINAL_HEIGHT B_FINAL_HASH < <(tip_tsv "${B_RPC_ADDR}")
[[ "${A_FINAL_HEIGHT}" == "${B_FINAL_HEIGHT}" && "${A_FINAL_HASH}" == "${B_FINAL_HASH}" && "${A_FINAL_HASH}" == "${B_MINE_HASH}" ]] || {
  echo "final convergence mismatch node-a_height=${A_FINAL_HEIGHT} node-a_hash=${A_FINAL_HASH} node-b_height=${B_FINAL_HEIGHT} node-b_hash=${B_FINAL_HASH} expected_hash=${B_MINE_HASH}" >&2
  exit 1
}

write_report
echo "PASS: Go two-node full-block process smoke reached height ${A_FINAL_HEIGHT} hash ${A_FINAL_HASH}; report=${REPORT_JSON}"
