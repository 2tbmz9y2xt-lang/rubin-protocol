#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEV_ENV="${REPO_ROOT}/scripts/dev-env.sh"
RUST_MODULE_ROOT="${REPO_ROOT}/clients/rust"
REPORT_PATH="${REPORT_PATH:-/tmp/rust-consensus-total-parity-report.json}"

run_stage() {
  local label="$1"
  shift
  echo "[rust-consensus-total-parity] ${label}"
  "$@"
}

run_stage "Stage 1/5: Rust sequential-vs-parallel connect_block parity tests" \
  "${DEV_ENV}" -- bash -lc "cd '${RUST_MODULE_ROOT}' && cargo test -p rubin-consensus connect_block_parallel -- --test-threads=1"

run_stage "Stage 2/5: Rust snapshot/precompute parity tests" \
  "${DEV_ENV}" -- bash -lc "cd '${RUST_MODULE_ROOT}' && cargo test -p rubin-consensus utxo_snapshot_sequential_parallel_parity -- --test-threads=1 && cargo test -p rubin-consensus precompute_witness_cursor_parity -- --test-threads=1"

run_stage "Stage 3/5: Rust parallel DA parity tests" \
  "${DEV_ENV}" -- bash -lc "cd '${RUST_MODULE_ROOT}' && cargo test -p rubin-consensus da_verify_parallel -- --test-threads=1"

run_stage "Stage 4/5: Rust signature-cache parity tests" \
  "${DEV_ENV}" -- bash -lc "cd '${RUST_MODULE_ROOT}' && cargo test -p rubin-consensus run_tx_validation_workers_with_sig_cache_reuses_positive_result -- --test-threads=1"

run_stage "Stage 5/5: Go↔Rust conformance bundle parity checks" \
  "${DEV_ENV}" -- python3 "${REPO_ROOT}/conformance/runner/run_cv_bundle.py"

HEAD_SHA="$(git -C "${REPO_ROOT}" rev-parse HEAD)"
TIMESTAMP_UTC="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

python3 - <<'PY' "${REPORT_PATH}" "${HEAD_SHA}" "${TIMESTAMP_UTC}"
import json
import pathlib
import sys

report_path = pathlib.Path(sys.argv[1])
head_sha = sys.argv[2]
timestamp_utc = sys.argv[3]

report = {
    "schema_version": 1,
    "gate": "rust-consensus-total-parity",
    "verdict": "PASS",
    "head_sha": head_sha,
    "timestamp_utc": timestamp_utc,
    "stages": [
        {
            "name": "rust_seq_vs_parallel_connect_block",
            "command": "cargo test -p rubin-consensus connect_block_parallel -- --test-threads=1",
        },
        {
            "name": "rust_snapshot_and_precompute_parity",
            "command": "cargo test -p rubin-consensus utxo_snapshot_sequential_parallel_parity -- --test-threads=1 && cargo test -p rubin-consensus precompute_witness_cursor_parity -- --test-threads=1",
        },
        {
            "name": "rust_parallel_da_parity",
            "command": "cargo test -p rubin-consensus da_verify_parallel -- --test-threads=1",
        },
        {
            "name": "rust_sig_cache_parity",
            "command": "cargo test -p rubin-consensus run_tx_validation_workers_with_sig_cache_reuses_positive_result -- --test-threads=1",
        },
        {
            "name": "go_rust_conformance_bundle",
            "command": "python3 conformance/runner/run_cv_bundle.py",
        },
    ],
}

report_path.write_text(json.dumps(report, indent=2) + "\n")
print(f"[rust-consensus-total-parity] Report written to {report_path}")
print(f"[rust-consensus-total-parity] Verdict: {report['verdict']}")
PY

echo "[rust-consensus-total-parity] PASS"
