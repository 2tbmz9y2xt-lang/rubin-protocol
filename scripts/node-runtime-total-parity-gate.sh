#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEV_ENV="${REPO_ROOT}/scripts/dev-env.sh"
GO_MODULE_ROOT="${REPO_ROOT}/clients/go"
RUST_MODULE_ROOT="${REPO_ROOT}/clients/rust"
REPORT_PATH="${REPORT_PATH:-/tmp/node-runtime-total-parity-report.json}"
PV_REPORT_PATH="${PV_REPORT_PATH:-/tmp/pv-soak-total-parity-report.json}"

run_stage() {
  local label="$1"
  shift
  echo "[node-runtime-total-parity] ${label}"
  "$@"
}

run_stage "Stage 1/5: live Go↔Rust devnet RPC parity smoke" \
  "${REPO_ROOT}/scripts/devnet-rpc-parity-smoke.sh"

run_stage "Stage 2/5: live Go↔Rust P2P interop coverage" \
  "${DEV_ENV}" -- bash -lc "cd '${GO_MODULE_ROOT}' && RUBIN_P2P_INTEROP=1 go test ./node/p2p -run '^TestRustInterop_(GoDialRustServerHandshake|RustClientDialGoServerHandshake|RustServerPingGoClientPong|RustClientReceivesTxFromGo|RustClientSyncsFiveBlocksFromGo)$' -count=1"

run_stage "Stage 3/5: Go relay + txpool lifecycle parity checks" \
  "${DEV_ENV}" -- bash -lc "cd '${GO_MODULE_ROOT}' && go test ./node/p2p -run '^(TestAnnounceTx|TestAnnounceTxMetadataError)$' -count=1 && go test ./node -run '^TestApplyBlockWithReorgRequeuesDisconnectedTransactionsIntoMempool$' -count=1"

run_stage "Stage 4/5: Rust relay + txpool lifecycle parity checks" \
  "${DEV_ENV}" -- bash -lc "cd '${RUST_MODULE_ROOT}' && cargo test -p rubin-node handle_received_tx_with_valid_fixture_stores_and_relays -- --test-threads=1 && cargo test -p rubin-node announce_tx_uses_real_metadata_for_relay_pool_priority -- --test-threads=1 && cargo test -p rubin-node apply_block_with_reorg_tip_extension_with_pool -- --test-threads=1 && cargo test -p rubin-node apply_block_with_reorg_tip_extension_removes_conflicting_pool_spends -- --test-threads=1"

run_stage "Stage 5/5: PV/shadow parity soak gate" \
  "${REPO_ROOT}/scripts/pv-soak-ci-gate.sh" --report "${PV_REPORT_PATH}"

HEAD_SHA="$(git -C "${REPO_ROOT}" rev-parse HEAD)"
TIMESTAMP_UTC="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

python3 - <<'PY' "${REPORT_PATH}" "${PV_REPORT_PATH}" "${HEAD_SHA}" "${TIMESTAMP_UTC}"
import json
import pathlib
import sys

report_path = pathlib.Path(sys.argv[1])
pv_report_path = pathlib.Path(sys.argv[2])
head_sha = sys.argv[3]
timestamp_utc = sys.argv[4]

pv_report = {}
if pv_report_path.exists():
    pv_report = json.loads(pv_report_path.read_text())

report = {
    "schema_version": 1,
    "gate": "node-runtime-total-parity",
    "verdict": "PASS",
    "head_sha": head_sha,
    "timestamp_utc": timestamp_utc,
    "stages": [
        {
            "name": "live_devnet_rpc_smoke",
            "command": "./scripts/devnet-rpc-parity-smoke.sh",
        },
        {
            "name": "live_go_rust_p2p_interop",
            "command": "RUBIN_P2P_INTEROP=1 go test ./node/p2p -run ^TestRustInterop_(GoDialRustServerHandshake|RustClientDialGoServerHandshake|RustServerPingGoClientPong|RustClientReceivesTxFromGo|RustClientSyncsFiveBlocksFromGo)$ -count=1",
        },
        {
            "name": "go_relay_and_txpool_lifecycle",
            "command": "go test ./node/p2p -run ^(TestAnnounceTx|TestAnnounceTxMetadataError)$ -count=1 && go test ./node -run ^TestApplyBlockWithReorgRequeuesDisconnectedTransactionsIntoMempool$ -count=1",
        },
        {
            "name": "rust_relay_and_txpool_lifecycle",
            "command": "cargo test -p rubin-node handle_received_tx_with_valid_fixture_stores_and_relays -- --test-threads=1 && cargo test -p rubin-node announce_tx_uses_real_metadata_for_relay_pool_priority -- --test-threads=1 && cargo test -p rubin-node apply_block_with_reorg_tip_extension_with_pool -- --test-threads=1 && cargo test -p rubin-node apply_block_with_reorg_tip_extension_removes_conflicting_pool_spends -- --test-threads=1",
        },
        {
            "name": "pv_shadow_soak_gate",
            "command": f"./scripts/pv-soak-ci-gate.sh --report {pv_report_path}",
            "report": pv_report,
        },
    ],
}

report_path.write_text(json.dumps(report, indent=2) + "\n")
print(f"[node-runtime-total-parity] Report written to {report_path}")
print(f"[node-runtime-total-parity] Verdict: {report['verdict']}")
PY

echo "[node-runtime-total-parity] PASS"
