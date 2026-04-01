#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT=""
OUT_DIR=""
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo-root)
      REPO_ROOT="$2"
      shift 2
      ;;
    --output-dir)
      OUT_DIR="$2"
      shift 2
      ;;
    *)
      echo "unknown arg: $1" >&2
      exit 2
      ;;
  esac
done

if [[ -z "$REPO_ROOT" || -z "$OUT_DIR" ]]; then
  echo "usage: $0 --repo-root <repo-root> --output-dir <out-dir>" >&2
  exit 2
fi

mkdir -p "$OUT_DIR"

GO_OUT="$OUT_DIR/go_runtime_raw.txt"
GO_JSON="$OUT_DIR/go_metrics.json"
RUST_JSON="$OUT_DIR/rust_metrics.json"

pushd "$REPO_ROOT" >/dev/null

go_bench_regex='^(BenchmarkMempoolAddTx|BenchmarkMempoolRelayMetadata|BenchmarkMinerBuildContext|BenchmarkCloneChainState|BenchmarkCopyUtxoSet|BenchmarkConnectBlockWithCoreExtProfilesAndSuiteContext|BenchmarkConnectBlockParallelSigsWithSuiteContext)$'

set +e
(cd clients/go && go test ./node -run '^$' -bench "$go_bench_regex" -benchmem -count=1) | tee "$GO_OUT"
go_status=${PIPESTATUS[0]}
set -e
if [[ $go_status -eq 0 ]]; then
  python3 "$SCRIPT_DIR/parse_go_runtime_metrics.py" --input "$GO_OUT" --output "$GO_JSON"
fi

for path in \
  clients/rust/target/criterion/rubin_node_txpool \
  clients/rust/target/criterion/rubin_node_chainstate_clone \
  clients/rust/target/criterion/rubin_node_sync_chain_state_snapshot \
  clients/rust/target/criterion/rubin_node_sync \
  clients/rust/target/criterion/rubin_node_undo \
  clients/rust/target/criterion/rubin_node_miner_mine_one
do
  rm -rf "$path"
done

set +e
(cd clients/rust && cargo bench -p rubin-node --bench runtime_baseline -- --noplot --sample-size 10 --measurement-time 1)
rust_status=$?
set -e
if [[ $rust_status -eq 0 ]]; then
  python3 "$SCRIPT_DIR/parse_rust_runtime_metrics.py" \
    --criterion-root "$REPO_ROOT/clients/rust/target/criterion" \
    --output "$RUST_JSON"
fi

popd >/dev/null

exit_code=0
if [[ $go_status -ne 0 ]]; then
  exit_code=$((exit_code | 1))
fi
if [[ $rust_status -ne 0 ]]; then
  exit_code=$((exit_code | 2))
fi

exit "$exit_code"
