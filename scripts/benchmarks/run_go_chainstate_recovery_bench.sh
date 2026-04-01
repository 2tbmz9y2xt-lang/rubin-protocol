#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT_DIR="${1:-$REPO_ROOT/evidence/runtime-perf/go-chainstate-recovery}"

mkdir -p "$OUT_DIR"
RAW_OUT="$OUT_DIR/raw.txt"
JSON_OUT="$OUT_DIR/parsed.json"

cd "$REPO_ROOT"

scripts/dev-env.sh -- bash -lc '
  set -euo pipefail
  cd clients/go
  go test ./node \
    -run "^$" \
    -bench "^(BenchmarkChainStateSave|BenchmarkChainStateLoad|BenchmarkReconcileChainState)$" \
    -benchmem \
    -count=1
' | tee "$RAW_OUT"

python3 scripts/benchmarks/parse_go_bench_series.py --input "$RAW_OUT" --output "$JSON_OUT"

echo "Wrote:"
echo "  $RAW_OUT"
echo "  $JSON_OUT"
