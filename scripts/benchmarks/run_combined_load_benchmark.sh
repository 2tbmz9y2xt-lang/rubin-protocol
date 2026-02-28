#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT_DIR="${1:-$ROOT_DIR/artifacts/combined-load}"

mkdir -p "$OUT_DIR"

RAW_OUT="$OUT_DIR/combined_load_benchmark.txt"
JSON_OUT="$OUT_DIR/combined_load_metrics.json"
SLO_FILE="$ROOT_DIR/scripts/benchmarks/combined_load_slo.json"

BENCH_ITERS="${RUBIN_COMBINED_LOAD_BENCH_ITERS:-1}"

echo "[combined-load] running Go benchmark (iters=${BENCH_ITERS}x)"

"$ROOT_DIR/scripts/dev-env.sh" -- bash -lc "
  cd '$ROOT_DIR/clients/go'
  go test ./consensus \
    -run '^$' \
    -bench '^BenchmarkValidateBlockBasicCombinedLoad$' \
    -benchmem \
    -count=1 \
    -benchtime='${BENCH_ITERS}x'
" | tee "$RAW_OUT"

python3 "$ROOT_DIR/scripts/benchmarks/parse_go_bench.py" \
  --input "$RAW_OUT" \
  --slo "$SLO_FILE" \
  --output "$JSON_OUT"

echo "[combined-load] artifacts:"
echo "  - $RAW_OUT"
echo "  - $JSON_OUT"
